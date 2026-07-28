/*
 * ───────────────────────────────────────────────────────────────────────────
 * Privateer — Transparency Excerpt (server)
 *
 * This file is published from Privateer's otherwise-closed server so anyone can
 * verify our core privacy claim: the server stores and forwards CIPHERTEXT
 * ONLY, never user plaintext, and routes AI inference exclusively to
 * Zero-Data-Retention providers.
 *
 * It is an EXCERPT, not a runnable build. Imports of modules that are NOT part
 * of this transparency repo (e.g. billing/pricing, entitlement/quota, S3/object
 * storage, email, rate limiting, Redis, Sentry wiring, logging) are left in
 * place so the code reads truthfully, but those modules are intentionally
 * omitted — they only ever see ciphertext, account IDs, and metadata, so they
 * add nothing to the privacy audit. Some such logic is stubbed inline with a
 * clearly marked "TRANSPARENCY REPO OMISSION" note.
 *
 * No secrets or credentials appear here; `process.env.*` reads reference public
 * variable NAMES only (documented in .env.example). See docs/E2EE_ARCHITECTURE.md.
 * ───────────────────────────────────────────────────────────────────────────
 */

'use strict';

/**
 * Harbor orchestrator — SEV-SNP attestation minting.
 *
 * Runs ON the confidential VM (privileged host side), NOT inside a tenant. Given
 * a tenant daemon's relay identity key and a server freshness nonce, it produces
 * a fresh AMD SEV-SNP attestation report bound to both, and (optionally) a CoCo
 * Trustee verdict on the AMD VCEK certificate chain.
 *
 * CROSS-COMPONENT CONTRACT (must stay in lockstep with the CLIENT verifier
 * client/services/harborAttestation.ts, which independently re-checks these bytes):
 *   - report_data[0:32]  = SHA-256( DER-SPKI(terminalPub) )   ← key binding
 *   - report_data[32:64] = the 32-byte server nonce           ← anti-replay freshness
 *   - MEASUREMENT (report offset 0x90, 48 bytes)              ← launch measurement
 * The client pins the SAME 12-byte X25519 SPKI prefix and offset 0x50 for
 * report_data. If the enclave ever binds a different key type, BOTH sides change
 * together. server/test/harborOrchestratorAttest.test.js pins the prefix here
 * against Node's canonical `spki` DER export.
 *
 * Why the host mints (not the tenant): configfs-tsm (/sys/kernel/config/tsm/report)
 * is a host-privileged kernel interface; a rootless tenant container cannot reach
 * it, and we deliberately do NOT bind it in (that would weaken §0.6 isolation). The
 * SEV-SNP report attests the whole CVM; report_data binds it to one tenant's key.
 *
 * This ports server/scripts/harborMintReport.sh (the Step-0 spike, proven on real
 * GCP SEV-SNP silicon) into Node so the orchestrator can mint on demand. The mint
 * function is injectable so tests exercise the wiring without configfs/hardware.
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileP = promisify(execFile);

// X25519 SubjectPublicKeyInfo DER prefix for a raw 32-byte key:
//   SEQUENCE(42){ SEQUENCE(5){ OID 1.3.101.110 } BIT STRING(33){ 00 || key } }
// Prepending this to the raw key and hashing reproduces
// sha256(publicKey.export({ type:'spki', format:'der' })). This is byte-identical
// to client/services/harborAttestation.ts X25519_SPKI_PREFIX — keep in lockstep.
const X25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

const REPORT_DATA_LEN = 64;
const NONCE_LEN = 32;

function badInput(msg) {
  const err = new Error(msg);
  err.status = 400;
  err.code = 'HARBOR_ATTEST_BAD_INPUT';
  return err;
}

/**
 * The fingerprint the enclave binds for a raw X25519 public key: sha256 over its
 * DER SPKI encoding. Returns a 32-byte Buffer. Throws HARBOR_ATTEST_BAD_INPUT if
 * `terminalPubB64` is not a base64 raw 32-byte X25519 key.
 */
function terminalKeyFingerprint(terminalPubB64) {
  let raw;
  try {
    raw = Buffer.from(String(terminalPubB64 || ''), 'base64');
  } catch {
    throw badInput('terminalPub is not valid base64');
  }
  if (raw.length !== 32) {
    throw badInput(`terminalPub must decode to 32 raw bytes (got ${raw.length})`);
  }
  const spki = Buffer.concat([X25519_SPKI_PREFIX, raw]);
  return crypto.createHash('sha256').update(spki).digest();
}

/**
 * Build the 64-byte SEV-SNP report_data: sha256(SPKI(terminalPub)) ‖ nonce.
 * `nonceHex` is the server's freshness nonce (64 hex chars = 32 bytes).
 */
function buildReportData(terminalPubB64, nonceHex) {
  const fp = terminalKeyFingerprint(terminalPubB64); // 32 bytes (validates key)
  const nonce = Buffer.from(String(nonceHex || ''), 'hex');
  if (nonce.length !== NONCE_LEN) {
    throw badInput(`nonce must be ${NONCE_LEN} bytes (${NONCE_LEN * 2} hex chars), got ${nonce.length}`);
  }
  return Buffer.concat([fp, nonce], REPORT_DATA_LEN);
}

/**
 * Mint a fresh SEV-SNP report via configfs-tsm — the Node port of
 * harborMintReport.sh. `reportData` is the 64-byte inblob. Returns the raw report
 * Buffer (the outblob). Throws HARBOR_TSM_UNAVAILABLE (503) when configfs-tsm is
 * absent (e.g. a non-CVM/dev host) so the caller fail-closes rather than faking.
 *
 * configfs leaf dirs are created/removed with mkdir/rmdir (NOT rm -rf). The leaf
 * name is per-call unique so concurrent mints don't collide.
 */
let mintCounter = 0;
function mintReport({ reportData, tsmReportDir = '/sys/kernel/config/tsm/report' }) {
  if (!Buffer.isBuffer(reportData) || reportData.length !== REPORT_DATA_LEN) {
    throw badInput(`reportData must be a ${REPORT_DATA_LEN}-byte Buffer`);
  }
  if (!fs.existsSync(tsmReportDir)) {
    const err = new Error(
      `[harbor:orch] configfs-tsm not available at ${tsmReportDir} — this host is not a ` +
      'SEV-SNP CVM (or the sev-guest module / configfs mount is missing).'
    );
    err.status = 503;
    err.code = 'HARBOR_TSM_UNAVAILABLE';
    throw err;
  }

  // eslint-disable-next-line no-plusplus
  const leaf = path.join(tsmReportDir, `r${process.pid}-${mintCounter++}`);
  try {
    fs.rmdirSync(leaf); // clear any stale leaf from a prior crash (ignore if absent)
  } catch { /* not present — fine */ }

  fs.mkdirSync(leaf); // configfs materializes inblob/outblob on mkdir
  try {
    fs.writeFileSync(path.join(leaf, 'inblob'), reportData);
    return fs.readFileSync(path.join(leaf, 'outblob'));
  } finally {
    try { fs.rmdirSync(leaf); } catch { /* best-effort cleanup */ }
  }
}

/**
 * Mint a report by shelling out to the privileged helper (harborMint.js) instead of
 * touching configfs-tsm in-process. This is how the ROOTLESS orchestrator mints:
 * configfs-tsm is root-only, so the helper (root, via a locked-down sudoers rule) is
 * the one privileged step. `helper` is an ABSOLUTE path from config (HARBOR_MINT_HELPER)
 * and must be root-owned + not writable by the orchestrator user (else the NOPASSWD sudo
 * rule is a root escalation). `exec` is injectable for tests. Async so a mint never
 * blocks the event loop for other tenants. Returns the raw report Buffer; fail-closed to
 * HARBOR_TSM_UNAVAILABLE on any error (missing sudo/helper, bad output, mint failure).
 */
async function mintReportViaHelper({ reportData, helper, sudo = true, nodeBin = 'node', exec = execFileP, logger = console }) {
  if (!Buffer.isBuffer(reportData) || reportData.length !== REPORT_DATA_LEN) {
    throw badInput(`reportData must be a ${REPORT_DATA_LEN}-byte Buffer`);
  }
  if (!helper) {
    const err = new Error('mint helper not configured (HARBOR_MINT_HELPER)');
    err.status = 500;
    err.code = 'HARBOR_MINT_NO_HELPER';
    throw err;
  }
  const hex = reportData.toString('hex');
  const cmd = sudo ? 'sudo' : nodeBin;
  const argv = sudo ? ['-n', nodeBin, helper, hex] : [helper, hex];
  try {
    const { stdout } = await exec(cmd, argv, { timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
    const buf = Buffer.from(String(stdout).trim(), 'base64');
    if (buf.length < OFF_SIGNATURE) {
      throw new Error(`helper returned ${buf.length} bytes (not a report)`);
    }
    return buf;
  } catch (err) {
    logger.error(`[harbor:orch] mint helper failed (${err.message})`);
    const e = new Error(`SEV-SNP mint via helper failed: ${err.message}`);
    e.status = 503;
    e.code = 'HARBOR_TSM_UNAVAILABLE';
    throw e;
  }
}

// ── AMD chain verification (`chainVerified`) ─────────────────────────────────
//
// DECISION (2026-07-20): Harbor SELF-VERIFIES the AMD chain rather than deploying a
// CoCo Trustee. The client's trust model only needs one boolean from us — "is this a
// genuine AMD-signed SEV-SNP report" — and Step 0 already PROVED we can produce it
// ourselves (`snpguest verify attestation` → "VEK signed the Attestation Report!" on
// real GCP silicon). A full Trustee (KBS+AS+RVPS+policy) is built for the secret-
// brokering flow we do not use, so it would be a whole extra service to run and
// secure for a verdict we can compute locally. The Trustee path is KEPT as an option
// (set HARBOR_TRUSTEE_URL) but is no longer required.
//
// WHAT `chainVerified` ACTUALLY ASSERTS (be precise — the client renders this as a
// user-facing trust claim, and §5 forbids overstating it):
//   ✓ the report is signed by the VCEK (a chip+TCB-specific key)
//   ✓ the VCEK cert chains to AMD's ASK, and the ASK to the ARK root
//   ✓ the ARK matches our pinned fingerprint — IF one is configured (see amdArkSha256;
//     unpinned, the root of trust degrades to "TLS to kdsintf.amd.com")
//   ✓ the reported TCB meets our configured floor — IF one is configured (see minTcb;
//     unset, a host on DOWNGRADED/vulnerable firmware still verifies, because AMD
//     issues a perfectly valid VCEK for an old TCB)
// It does NOT assert anything about which workload is running — that is the
// MEASUREMENT, checked separately by the client.
//
// Two implementations, tried in order:
//   1. snpguest (PREFERRED) — the exact recipe validated in Step 0. Delegates cert
//      fetching + chain math to AMD's own tooling.
//   2. native Node fallback — fetches VCEK + ARK/ASK from AMD's KDS and does the cert
//      chain + ECDSA-P384 report-signature check with node:crypto, for hosts without
//      snpguest installed.
// Everything is FAIL-CLOSED: any missing tool, failed fetch, bad signature, or thrown
// error yields `false`, and the client then shows `failed`/`chain-unverified`. We never
// return true on "couldn't check".

const AMD_KDS_BASE = 'https://kdsintf.amd.com/vcek/v1';

// SEV-SNP ATTESTATION_REPORT offsets used for signature verification.
const OFF_REPORT_DATA = 0x50;   // 64-byte report_data (fp‖nonce) — the key/nonce binding
const OFF_REPORTED_TCB = 0x180; // 8-byte TCB_VERSION
const OFF_CHIP_ID = 0x1a0;      // 64-byte unique chip id
const OFF_SIGNATURE = 0x2a0;    // signature block; everything BEFORE it is signed
const ECDSA_FIELD = 0x48;       // 72-byte r/s fields (P-384 uses the low 48, little-endian)
const P384_LEN = 48;

/** Map a snpguest processor name to the KDS product path segment. */
function kdsProduct(processor) {
  const p = String(processor || 'milan').toLowerCase();
  return p.charAt(0).toUpperCase() + p.slice(1); // milan → Milan, genoa → Genoa
}

/**
 * Parse the fields needed to verify a report's signature. TCB_VERSION is a little-
 * endian u64: byte0=bootloader, byte1=tee, bytes2-5 reserved, byte6=snp, byte7=microcode.
 */
function parseSnpReport(reportBuf) {
  const buf = Buffer.from(reportBuf);
  if (buf.length < OFF_SIGNATURE + ECDSA_FIELD * 2) {
    throw badInput(`report too short to carry a signature (${buf.length} bytes)`);
  }
  const tcbRaw = buf.subarray(OFF_REPORTED_TCB, OFF_REPORTED_TCB + 8);
  // r and s are stored little-endian in 72-byte fields; reverse the low 48 to big-endian.
  const rBE = Buffer.from(buf.subarray(OFF_SIGNATURE, OFF_SIGNATURE + P384_LEN)).reverse();
  const sBE = Buffer.from(buf.subarray(OFF_SIGNATURE + ECDSA_FIELD, OFF_SIGNATURE + ECDSA_FIELD + P384_LEN)).reverse();
  return {
    signedBody: buf.subarray(0, OFF_SIGNATURE), // exactly what the VCEK signed
    sigP1363: Buffer.concat([rBE, sBE]),        // IEEE-P1363 r‖s, what node:crypto wants
    reportData: Buffer.from(buf.subarray(OFF_REPORT_DATA, OFF_REPORT_DATA + REPORT_DATA_LEN)), // fp‖nonce binding
    chipIdHex: buf.subarray(OFF_CHIP_ID, OFF_CHIP_ID + 64).toString('hex'),
    tcb: { bl: tcbRaw[0], tee: tcbRaw[1], snp: tcbRaw[6], ucode: tcbRaw[7] },
  };
}

/** The AMD KDS URL that serves the VCEK for this exact chip + TCB. */
function kdsVcekUrl(processor, chipIdHex, tcb) {
  return `${AMD_KDS_BASE}/${kdsProduct(processor)}/${chipIdHex}` +
    `?blSPL=${tcb.bl}&teeSPL=${tcb.tee}&snpSPL=${tcb.snp}&ucodeSPL=${tcb.ucode}`;
}

/**
 * Verify the report body was signed by `vcekPublicKey` (ECDSA P-384 over SHA-384).
 * Pure — unit-tested against a synthetic report signed with a generated P-384 key,
 * which is what pins the r/s little-endian handling and the 0x2A0 signed-length.
 */
function verifyReportSignature({ signedBody, sigP1363, vcekPublicKey }) {
  try {
    return crypto.verify(
      'sha384',
      signedBody,
      { key: vcekPublicKey, dsaEncoding: 'ieee-p1363' },
      sigP1363
    );
  } catch {
    return false;
  }
}

/** Split a PEM bundle (AMD's cert_chain is ASK then ARK) into X509Certificate objects. */
function parsePemChain(pem) {
  const blocks = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  return blocks.map((b) => new crypto.X509Certificate(b));
}

/**
 * Check the fetched ARK against a pinned SHA-256 of its DER.
 *
 * WHY THIS EXISTS: `ark.verify(ark.publicKey)` only proves the cert is self-signed,
 * which ANY self-signed cert is. Both the VCEK and the ASK/ARK bundle come from
 * kdsintf.amd.com in the same flow, so without a pin the entire root of trust is
 * "we reached AMD over TLS with Node's CA store" — one bad CA or one MITM and the
 * whole chain validates against an attacker's root. Pinning the ARK is what makes
 * the chain mean what the comment above says it means.
 *
 * Returns 'ok' | 'mismatch' | 'unpinned'. `mismatch` is FAIL-CLOSED at the caller.
 * `unpinned` is permitted (and logged loudly) so this is deployable before someone
 * reads the real fingerprint off AMD's published root — see the go-live gate in
 * docs/HARBOR_HOSTED_RUNTIME.md. We deliberately do NOT ship a guessed constant:
 * a wrong pin here either breaks all attestation or, worse, pins an attacker's root.
 */
function checkArkPin(ark, pinnedSha256, logger = console) {
  if (!pinnedSha256) {
    logger.warn(
      '[harbor:orch] AMD ARK is NOT pinned (HARBOR_AMD_ARK_SHA256 unset) — chain root of ' +
      'trust is TLS to kdsintf.amd.com only. Pin before go-live.'
    );
    return 'unpinned';
  }
  const actual = crypto.createHash('sha256').update(ark.raw).digest('hex').toLowerCase();
  // Accept the shapes people paste: bare hex, "sha256:<hex>", and colon/space-grouped
  // ("AB:CD:.."). Strip the algorithm prefix FIRST — its letters are themselves valid
  // hex, so a blanket non-hex strip would silently fold "sha256:" into the digest and
  // turn a correct pin into a mismatch.
  const expected = String(pinnedSha256).trim().toLowerCase()
    .replace(/^sha-?256[:=]/, '')
    .replace(/[\s:]/g, '');
  if (actual !== expected) {
    logger.error(
      `[harbor:orch] AMD ARK FINGERPRINT MISMATCH — expected ${pinnedSha256}, got ${actual}. ` +
      'Refusing to verify (possible MITM or wrong processor generation).'
    );
    return 'mismatch';
  }
  return 'ok';
}

/**
 * Enforce a minimum TCB (anti-rollback). AMD issues a valid VCEK for whatever TCB the
 * host reports, INCLUDING an old one with known vulnerabilities — signature validity
 * alone says nothing about firmware freshness. `minTcb` is a partial
 * { bl, tee, snp, ucode }; only the components present are compared.
 *
 * Returns 'ok' | 'below-floor' | 'unset'. Unset is permitted + logged: the correct
 * floor is hardware- and fleet-specific (read it off the CVM during Step 1.0 HW
 * acceptance), and inventing one here would be a fabricated security constant.
 */
function checkTcbFloor(tcb, minTcb, logger = console) {
  if (!minTcb || typeof minTcb !== 'object' || Object.keys(minTcb).length === 0) {
    logger.warn(
      '[harbor:orch] No minimum TCB configured (HARBOR_MIN_TCB unset) — a host on ' +
      'DOWNGRADED firmware will still report chainVerified=true. Set before go-live.'
    );
    return 'unset';
  }
  for (const part of ['bl', 'tee', 'snp', 'ucode']) {
    const floor = minTcb[part];
    if (floor === undefined || floor === null) continue;
    if (Number(tcb[part]) < Number(floor)) {
      logger.error(
        `[harbor:orch] TCB ROLLBACK: reported ${part}=${tcb[part]} is below the configured ` +
        `floor ${floor} — chainVerified=false.`
      );
      return 'below-floor';
    }
  }
  return 'ok';
}

/**
 * The key/nonce binding check, done in Node against a SIGNATURE-VERIFIED report.
 * `reportData` is the 64-byte report_data parsed from the report; `expectedReportDataHex`
 * is fp‖nonce (128 hex chars). Returns true when no binding was requested (null) or it
 * matches exactly; false (fail-closed) on any mismatch, wrong length, or parse error.
 * This is the guarantee snpguest's `-r` was meant to give but can't for binary data.
 */
function checkReportDataBinding(reportData, expectedReportDataHex, logger = console) {
  if (expectedReportDataHex == null) return true;
  try {
    const want = Buffer.from(String(expectedReportDataHex), 'hex');
    if (
      want.length !== REPORT_DATA_LEN ||
      !Buffer.isBuffer(reportData) || reportData.length !== REPORT_DATA_LEN ||
      !crypto.timingSafeEqual(reportData, want)
    ) {
      logger.error(
        '[harbor:orch] report_data binding MISMATCH — the report is not bound to the ' +
        'expected terminal key + nonce. chainVerified=false.'
      );
      return false;
    }
    return true;
  } catch (err) {
    logger.error(`[harbor:orch] report_data binding check errored (${err.message}) — chainVerified=false.`);
    return false;
  }
}

// ── cert chain relayed to the client (GO-LIVE GATE 1) ────────────────────────
//
// The client re-verifies the AMD chain ITSELF against an ARK pinned in its binary
// (client/services/harborChainVerify.ts), so it does not have to trust our
// `chainVerified` boolean. For that it needs the raw certificates. We fetch the
// SAME VCEK (by chip+TCB) + ASK/ARK the native verifier uses and hand them over as
// base64 DER. This is data the client will re-derive trust from — we do NOT need to
// have verified it ourselves for it to be useful, but we fetch it from AMD's KDS
// over TLS all the same. Cached: a VCEK is stable per (chip, TCB) and the cert_chain
// per processor generation, so we avoid re-hitting the KDS on every attestation.
const CHAIN_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6h
const vcekCache = new Map();   // key: `${processor}:${chipId}:${bl}.${tee}.${snp}.${ucode}` → { der(base64), at }
const chainCache = new Map();  // key: processor → { ask, ark (base64), at }

function cacheGet(map, key) {
  const hit = map.get(key);
  if (hit && Date.now() - hit.at < CHAIN_CACHE_TTL_MS) return hit;
  if (hit) map.delete(key);
  return null;
}

/**
 * Fetch { vcek, ask, ark } (each base64 DER) for a report so the CLIENT can run its
 * own VCEK←ASK←ARK verification. Returns null (never throws) if the KDS is
 * unreachable or the chain is malformed — the client then falls back to the server
 * `chainVerified` boolean and shows a weaker posture, rather than the app erroring.
 */
async function fetchCertChain({ reportBuf, processor = 'milan', fetchAmd = fetch, logger = console }) {
  try {
    const { chipIdHex, tcb } = parseSnpReport(reportBuf);
    const proc = String(processor || 'milan').toLowerCase();
    const vcekKey = `${proc}:${chipIdHex}:${tcb.bl}.${tcb.tee}.${tcb.snp}.${tcb.ucode}`;

    let vcekB64 = cacheGet(vcekCache, vcekKey)?.der || null;
    if (!vcekB64) {
      const res = await fetchAmd(kdsVcekUrl(proc, chipIdHex, tcb));
      if (!res || !res.ok) { logger.warn('[harbor:orch] KDS VCEK fetch failed — no client cert chain'); return null; }
      vcekB64 = Buffer.from(await res.arrayBuffer()).toString('base64');
      vcekCache.set(vcekKey, { der: vcekB64, at: Date.now() });
    }

    let chain = cacheGet(chainCache, proc);
    if (!chain) {
      const res = await fetchAmd(`${AMD_KDS_BASE}/${kdsProduct(proc)}/cert_chain`);
      if (!res || !res.ok) { logger.warn('[harbor:orch] KDS cert_chain fetch failed — no client cert chain'); return null; }
      const certs = parsePemChain(await res.text()); // [ASK, ARK]
      if (!certs[0] || !certs[1]) { logger.warn('[harbor:orch] KDS cert_chain missing ASK/ARK'); return null; }
      chain = {
        ask: Buffer.from(certs[0].raw).toString('base64'),
        ark: Buffer.from(certs[1].raw).toString('base64'),
        at: Date.now(),
      };
      chainCache.set(proc, chain);
    }

    // `processor` tells the client which pinned ARK to select; it is only a HINT —
    // the client's ARK pin is the real anchor, so a lie here just yields a pin
    // mismatch (or unpinned-processor), never a trusted forged root.
    return { vcek: vcekB64, ask: chain.ask, ark: chain.ark, processor: proc };
  } catch (err) {
    logger.warn(`[harbor:orch] fetchCertChain failed (${err.message}) — no client cert chain`);
    return null;
  }
}

/**
 * Native fallback: fetch the VCEK + AMD root chain from the KDS and verify
 * VCEK ← ASK ← ARK, then that the VCEK signed this report.
 *
 * `fetchAmd(url)` is injectable (returns { ok, text(), arrayBuffer() }) so tests run
 * offline. NOTE: this path has NOT yet been cross-checked against snpguest on real
 * silicon — that is part of the Step 1.0 HW acceptance. Prefer snpguest where present.
 */
async function verifyChainNative({
  reportBuf,
  processor = 'milan',
  fetchAmd = fetch,
  arkSha256 = null,
  minTcb = null,
  expectedReportDataHex = null,
  logger = console,
}) {
  try {
    const { signedBody, sigP1363, reportData, chipIdHex, tcb } = parseSnpReport(reportBuf);

    // Key/nonce binding: the report_data (fp‖nonce) must be exactly what we asked the
    // enclave to bind. Without this, native returns true for ANY genuinely-AMD-signed
    // report regardless of which terminal key it carries — the leniency the HW cross-
    // check surfaced. Short-circuits before any network work.
    if (!checkReportDataBinding(reportData, expectedReportDataHex, logger)) return false;

    // Anti-rollback BEFORE any network work — a below-floor TCB is a definitive no.
    if (checkTcbFloor(tcb, minTcb, logger) === 'below-floor') return false;

    const [vcekRes, chainRes] = await Promise.all([
      fetchAmd(kdsVcekUrl(processor, chipIdHex, tcb)),
      fetchAmd(`${AMD_KDS_BASE}/${kdsProduct(processor)}/cert_chain`),
    ]);
    if (!vcekRes || !vcekRes.ok || !chainRes || !chainRes.ok) {
      logger.warn('[harbor:orch] AMD KDS fetch failed — chainVerified=false');
      return false;
    }

    const vcek = new crypto.X509Certificate(Buffer.from(await vcekRes.arrayBuffer()));
    const chain = parsePemChain(await chainRes.text());
    const ask = chain[0];
    const ark = chain[1];
    if (!ask || !ark) {
      logger.warn('[harbor:orch] AMD cert_chain did not yield ASK+ARK — chainVerified=false');
      return false;
    }

    // The ARK must be AMD's, not merely self-consistent. Fail-closed on a mismatch.
    if (checkArkPin(ark, arkSha256, logger) === 'mismatch') return false;

    // VCEK ← ASK ← ARK, and ARK is self-signed (AMD's root of trust).
    if (!vcek.verify(ask.publicKey) || !ask.verify(ark.publicKey) || !ark.verify(ark.publicKey)) {
      logger.error('[harbor:orch] AMD certificate chain did NOT validate — chainVerified=false');
      return false;
    }

    const sigOk = verifyReportSignature({ signedBody, sigP1363, vcekPublicKey: vcek.publicKey });
    if (!sigOk) logger.error('[harbor:orch] VCEK did NOT sign this report — chainVerified=false');
    return sigOk;
  } catch (err) {
    logger.warn(`[harbor:orch] native chain verify failed (${err.message}) — chainVerified=false`);
    return false;
  }
}

/**
 * Preferred path: shell out to snpguest — the exact Step-0-validated recipe
 * (fetch ca → fetch vcek → verify attestation). This verifies ONLY the AMD cert
 * chain + report signature; it does NOT check the report_data key/nonce binding.
 *
 * WHY NO `-r` BINDING HERE (learned on real 0.10.0 silicon during HW acceptance):
 * snpguest's `--report-data` neither hex-decodes its argument nor accepts our binary
 * fp‖nonce — 0.10.0 wants a 64-CHARACTER value and compares its raw ASCII bytes
 * (its own --help even mislabels this as "128 chars"). It is unusable for a binary
 * report_data. So we do the binding in Node instead (checkReportDataBinding), against
 * the very bytes snpguest proves are signed — an equivalent guarantee without the
 * version-fragile flag. The caller (verifyChainAuto) enforces it.
 */
async function verifyChainSnpguest({
  reportBuf,
  snpguestBin = 'snpguest',
  processor = 'milan',
  minTcb = null,
  logger = console,
}) {
  // ASYNC, not execFileSync: three subprocess calls that each fetch from AMD's KDS,
  // at up to 60s apiece, would otherwise stall the orchestrator's event loop for
  // every other tenant's start/suspend/attest while one attestation runs.
  const opts = { timeout: 60000 };
  try {
    await execFileP(snpguestBin, ['--version'], opts);
  } catch {
    return null; // not installed — signal "no verdict", caller falls back
  }

  // snpguest verifies SIGNATURES, not firmware freshness — it will happily validate a
  // report from a rolled-back TCB. Enforce our floor on both paths, not just native.
  try {
    if (checkTcbFloor(parseSnpReport(reportBuf).tcb, minTcb, logger) === 'below-floor') return false;
  } catch (err) {
    logger.error(`[harbor:orch] could not parse report for the TCB floor check (${err.message})`);
    return false;
  }

  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'harbor-snpverify-'));
  const certDir = path.join(dir, 'certs');
  const reportPath = path.join(dir, 'report.bin');
  try {
    await fsp.mkdir(certDir);
    await fsp.writeFile(reportPath, Buffer.from(reportBuf));
    await execFileP(snpguestBin, ['fetch', 'ca', 'pem', certDir, processor], opts);
    await execFileP(snpguestBin, ['fetch', 'vcek', 'pem', certDir, reportPath, '-p', processor], opts);

    const args = ['verify', 'attestation', certDir, reportPath, '-p', processor];
    await execFileP(snpguestBin, args, opts); // non-zero exit rejects (chain + signature)
    return true;
  } catch (err) {
    logger.error(`[harbor:orch] snpguest chain verify failed — chainVerified=false (${err.message})`);
    return false;
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => { /* best effort */ });
  }
}

/**
 * Optional CoCo Trustee path — kept for operators who already run one (or who later
 * want the KBS secret-brokering flow). Used only when HARBOR_TRUSTEE_URL is set.
 */
async function verifyChain({ reportBuf, trusteeUrl }) {
  if (!trusteeUrl) return false;
  try {
    const res = await fetch(`${trusteeUrl.replace(/\/$/, '')}/attest/sev-snp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ report: Buffer.from(reportBuf).toString('base64') }),
    });
    if (!res.ok) return false;
    const out = await res.json().catch(() => ({}));
    // Accept a couple of common verdict shapes; treat anything else as unverified.
    return out.chainVerified === true || out.verified === true || out.allow === true;
  } catch {
    return false;
  }
}

/**
 * Dispatcher used by tenants.attest: Trustee if one is configured, else self-verify
 * (snpguest, falling back to native). Fail-closed at every branch.
 */
async function verifyChainAuto({ reportBuf, config = {}, expectedReportDataHex = null, logger = console }) {
  if (config.trusteeUrl) {
    return verifyChain({ reportBuf, trusteeUrl: config.trusteeUrl });
  }
  const viaSnpguest = await verifyChainSnpguest({
    reportBuf,
    snpguestBin: config.snpguestBin,
    processor: config.snpProcessor,
    minTcb: config.minTcb,
    logger,
  });
  if (viaSnpguest !== null) {
    // snpguest verified the chain + signature. It cannot check the report_data binding
    // (see verifyChainSnpguest), so we enforce it here in Node against the now-signature-
    // verified report. chainVerified = genuine chain AND bound to our key + nonce.
    if (!viaSnpguest) return false;
    let reportData;
    try { ({ reportData } = parseSnpReport(reportBuf)); } catch { return false; }
    return checkReportDataBinding(reportData, expectedReportDataHex, logger);
  }

  logger.warn('[harbor:orch] snpguest not installed — falling back to native AMD chain verify.');
  return verifyChainNative({
    reportBuf,
    processor: config.snpProcessor,
    arkSha256: config.amdArkSha256,
    minTcb: config.minTcb,
    expectedReportDataHex,
    logger,
  });
}

module.exports = {
  X25519_SPKI_PREFIX,
  terminalKeyFingerprint,
  buildReportData,
  mintReport,
  mintReportViaHelper,
  fetchCertChain,
  verifyChain,
  verifyChainAuto,
  verifyChainSnpguest,
  verifyChainNative,
  verifyReportSignature,
  checkArkPin,
  checkTcbFloor,
  checkReportDataBinding,
  parseSnpReport,
  kdsVcekUrl,
  kdsProduct,
  REPORT_DATA_LEN,
  NONCE_LEN,
  OFF_SIGNATURE,
};
