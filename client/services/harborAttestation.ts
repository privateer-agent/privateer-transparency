/**
 * Harbor attestation — client-side verification of a hosted (Harbor) agent's
 * confidential-VM enclave. Step 3 of the Harbor plan (docs/HARBOR_STEP1_PLAN.md,
 * docs/HARBOR_HOSTED_RUNTIME.md).
 *
 * A Harbor agent runs `privateer-agent` inside an AMD SEV-SNP confidential VM. The
 * enclave mints a fresh SEV-SNP attestation report and packs, into
 * `report_data[0:32]`, the SHA-256 of the DER SubjectPublicKeyInfo of the daemon's
 * identity key (`terminalPub`) — the SAME key the app pins/drives over the relay.
 * The report's `MEASUREMENT` (offset 0x90, 48 bytes) is the launch measurement of
 * our reproducible image, whose expected value the server serves as
 * `HostedAgent.measurement`.
 *
 * The client independently checks, all FAIL-CLOSED (an explicit mismatch is `failed`,
 * possible MITM/replay; "couldn't check" — report absent, no reference — is `unverified`):
 *   1. KEY BINDING — the attested key equals the terminalPub of the terminal
 *      actually terminating our driven relay session.
 *   2. MEASUREMENT — the report's measurement equals the published reference.
 *   3. FRESHNESS — the report's `report_data[32:64]` equals the freshness nonce the
 *      server issued for THIS attestation request (anti-replay). The enclave binds it
 *      alongside the key; the server both mints and returns it, so the client can audit
 *      the nonce half of report_data itself rather than trusting the server for freshness.
 *   4. CHAIN (GATE 1, harborChainVerify.ts) — the AMD certificate chain and the report
 *      signature, verified HERE from the raw VCEK+ASK+ARK the server relays, rooted in
 *      an ARK PINNED in this binary. On NATIVE this is REQUIRED for `attested`: we do NOT
 *      fall back to the server's `chainVerified` boolean to reach a green posture. If the
 *      certs are absent (stub / KDS unreachable) the posture is `unverified`, never
 *      `attested` — otherwise a server could omit the certs, assert `chainVerified:true`,
 *      and forge the bytes 1–3 read (all values IT supplies) to fake a green shield.
 *
 * WHY (4) MATTERS: without it the report bytes are unauthenticated — anything able to
 * shape our JSON response could emit a buffer carrying any key fingerprint and any
 * measurement, set `chainVerified: true`, and obtain `attested`. Checks 1–3 are sound
 * against a third party who cannot alter server responses but VACUOUS against a
 * malicious or compromised server — precisely the party attestation exists to
 * constrain. Verifying the VCEK signature (report[0:0x2A0], ECDSA P-384) up a chain to
 * a pinned ARK is what authenticates the bytes 1–3 read.
 *
 * ⚠ NATIVE-ONLY MEANING: (4) is a real guarantee only where the store-signed binary is
 * outside server control (native). On WEB the server ships this very file, so a hostile
 * server would edit the verifier itself — `verifyHarborAttestation({platform:'web'})`
 * therefore NEVER returns `attested`, capping at `unverified`. The required `platform`
 * input is what makes the trust environment an explicit, fail-closed decision.
 *
 * Pure by design (no network) so it is unit-testable against synthetic reports —
 * see server/test/harborAttestation.test.js, which also pins the X25519-SPKI prefix
 * below against Node's canonical `publicKey.export({type:'spki',format:'der'})`.
 */

import { sha256 } from '@noble/hashes/sha256';
import { fromBase64 } from './cryptoService';
import { verifyReportChain, type ChainVerifyResult } from './harborChainVerify';

// SEV-SNP ATTESTATION_REPORT field offsets (bytes). report_data is 64 bytes at
// 0x50; MEASUREMENT is 48 bytes at 0x90; the signature block is at 0x2A0 and a
// genuine report is 0x4A0 (1184) bytes.
const OFF_REPORT_DATA = 0x50;
const OFF_NONCE = 0x70;        // report_data[32:64] — the server freshness nonce
const OFF_MEASUREMENT = 0x90;
const LEN_MEASUREMENT = 48;
const OFF_SIGNATURE = 0x2a0;
const REPORT_LEN = 0x4a0;

// Require a FULL-LENGTH report, not merely one long enough to hold the two fields
// we read (0xC0). Rationale: at 0xC0 the buffer cannot even contain the signature
// block at 0x2A0, so accepting it meant accepting objects that are structurally not
// attestation reports at all — a 192-byte forgery with the right 32 bytes at 0x50
// and 48 at 0x90 verified as `attested`.
//
// This is a structural precondition for the real check, not the check itself: it
// guarantees the buffer we hand to harborChainVerify actually contains a signature
// block at 0x2A0. The authentication is Gate 1 (verifyReportChain) — the VCEK
// signature over report[0:0x2A0] up a chain to our pinned ARK — which a length pad
// alone cannot satisfy. Without certs relayed we fall back to the server boolean and
// this length check is the only structural guard, so keep it strict.
const REPORT_MIN_LEN = REPORT_LEN;

// X25519 SubjectPublicKeyInfo DER prefix for a raw 32-byte key:
//   SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.110 } BIT STRING(33) { 00 || key } }
// Prepending this to the raw key and hashing reproduces
// sha256(publicKey.export({ type: 'spki', format: 'der' })) for an X25519 key —
// the exact fingerprint the enclave binds (see server/scripts/harborAttestSpike.js
// and pi-privacy's Tinfoil SEV-SNP parse). terminalPub is an X25519 key (32 raw
// bytes, base64) — see terminalTrustService.ts. If the enclave ever binds a
// different key type, this prefix + that contract must change in lockstep.
const X25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

export type HarborPosture = 'attested' | 'unverified' | 'failed';

// The report + server-side verdicts the proxy returns (GET /api/harbor/:id/attestation).
// Raw AMD certificates the server relays so the client can re-verify the chain
// itself (Gate 1). base64 DER. Absent on stub / when the KDS was unreachable.
export interface HarborCertChain {
  vcek: string;                        // leaf: chip+TCB VCEK (base64 DER)
  ask: string;                         // intermediate: AMD SEV signing key (base64 DER)
  ark: string;                         // root: AMD SEV root key (base64 DER)
  processor?: string;                  // 'milan' | … — selects the client's pinned ARK
}

export interface HarborAttestationReport {
  reportB64: string;                   // raw SEV-SNP report bytes, base64
  chainVerified: boolean;              // server/Trustee AMD VCEK-chain verdict
  certChain?: HarborCertChain | null;  // raw certs for the client's OWN chain verify
  measurement: string | null;          // published reference (hex), from HostedAgent
  terminalPub: string | null;          // key the server recorded for this agent
  nonce: string | null;                // freshness nonce echoed into the report
  verifiedAt: string | null;
}

export interface HarborVerifyInput {
  report: HarborAttestationReport;
  // The key of the terminal we are ACTUALLY driving (from the live relay session).
  // Falls back to the server-recorded key for an informational (not-driving) check.
  expectedTerminalPub: string | null;
  // Where this verifier is running — REQUIRED, and it gates whether `attested` is even
  // reachable, so the caller must declare it (fail-closed by construction):
  //   'native' — store-signed binary outside server control. `attested` requires the app
  //              to have verified the AMD chain ITSELF (clientChainVerified === true).
  //   'web'    — the server SHIPS this verifier, so no self-verification is trustworthy;
  //              `attested` is NEVER returned (capped at `unverified`).
  // Pass `Platform.OS === 'web' ? 'web' : 'native'`.
  platform: 'native' | 'web';
}

export interface HarborAttestationResult {
  posture: HarborPosture;
  keyMatched: boolean;
  measurementMatched: boolean | null;  // null = no reference to compare against
  nonceMatched: boolean | null;        // null = no nonce reference to compare against
  chainVerified: boolean;              // the server's relayed AMD-chain verdict
  // The client's OWN AMD chain verdict (Gate 1), computed here from the relayed
  // certs against an ARK PINNED in this binary — no trust in the server boolean.
  //   true  = we independently verified VCEK←ASK←ARK(pinned) + report signature
  //   false = the relayed certs do NOT verify (posture → failed)
  //   null  = no certs relayed, so we could not check (fell back to `chainVerified`)
  clientChainVerified: boolean | null;
  clientChainReason: string | null;    // machine hint from the client chain verifier
  attestedKeyFp: string | null;        // report_data[0:32], hex
  expectedKeyFp: string | null;        // sha256(spki(expectedTerminalPub)), hex
  measurement: string | null;          // report MEASUREMENT, hex
  reason: string | null;               // machine hint when not `attested`
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/**
 * The fingerprint the enclave binds for a raw X25519 public key: sha256 over its
 * DER SPKI encoding. Exported for the test's contract check.
 */
export function terminalKeyFingerprint(terminalPubB64: string): string | null {
  let raw: Uint8Array;
  try {
    raw = fromBase64(terminalPubB64);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null; // not a raw X25519 key → can't wrap deterministically
  const spki = new Uint8Array(X25519_SPKI_PREFIX.length + 32);
  spki.set(X25519_SPKI_PREFIX, 0);
  spki.set(raw, X25519_SPKI_PREFIX.length);
  return toHex(sha256(spki));
}

/**
 * Verify a Harbor attestation. Pure. Fail-closed: any explicit mismatch (key,
 * measurement, or chain) yields `failed`; inability to check yields `unverified`;
 * only all-green yields `attested`.
 */
export function verifyHarborAttestation({ report, expectedTerminalPub, platform }: HarborVerifyInput): HarborAttestationResult {
  const base: HarborAttestationResult = {
    posture: 'unverified',
    keyMatched: false,
    measurementMatched: null,
    nonceMatched: null,
    chainVerified: !!report.chainVerified,
    clientChainVerified: null,
    clientChainReason: null,
    attestedKeyFp: null,
    expectedKeyFp: null,
    measurement: null,
    reason: null,
  };

  // Parse the raw report.
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(report.reportB64 || '');
  } catch {
    return { ...base, reason: 'report-undecodable' };
  }
  if (bytes.length < REPORT_MIN_LEN) {
    return { ...base, reason: 'report-too-short' };
  }
  const attestedKeyFp = toHex(bytes.subarray(OFF_REPORT_DATA, OFF_REPORT_DATA + 32));
  const attestedNonce = toHex(bytes.subarray(OFF_NONCE, OFF_NONCE + 32));
  const measurement = toHex(bytes.subarray(OFF_MEASUREMENT, OFF_MEASUREMENT + LEN_MEASUREMENT));

  // GATE 1 — verify the AMD chain OURSELVES from the relayed certs, so `attested`
  // no longer rests on the server's `chainVerified` boolean. When certs are present
  // this verdict is authoritative: true supersedes the server boolean, false is a
  // hard fail (a server relaying certs that don't verify is exactly the attack this
  // closes). When absent (stub / KDS down) we leave it null and fall back below.
  // NOTE: only meaningful on native — on web the server ships this verifier, so a
  // hostile server edits it; callers weight the badge by Platform accordingly.
  let clientChain: ChainVerifyResult | null = null;
  const cc = report.certChain;
  if (cc && cc.vcek && cc.ask && cc.ark) {
    try {
      clientChain = verifyReportChain({
        reportBytes: bytes,
        vcekDer: fromBase64(cc.vcek),
        askDer: fromBase64(cc.ask),
        arkDer: fromBase64(cc.ark),
        processor: cc.processor,
      });
    } catch (err) {
      clientChain = { ok: false, reason: `certchain-decode:${(err as Error)?.message || 'bad'}` };
    }
  }
  const clientChainVerified = clientChain ? clientChain.ok : null;
  const clientChainReason = clientChain ? clientChain.reason : null;

  // Key binding — against the LIVE terminal key when driving.
  const expectedKeyFp = expectedTerminalPub ? terminalKeyFingerprint(expectedTerminalPub) : null;
  const keyMatched = !!expectedKeyFp && attestedKeyFp === expectedKeyFp;

  // Measurement — only decidable when we hold a reference.
  const ref = report.measurement ? report.measurement.toLowerCase() : null;
  const measurementMatched = ref ? measurement === ref : null;

  // Freshness — the nonce the server issued for THIS request must be echoed into
  // report_data[32:64]. Only decidable when the server returned the nonce it minted.
  const refNonce = report.nonce ? report.nonce.toLowerCase() : null;
  const nonceMatched = refNonce ? attestedNonce === refNonce : null;

  const result: HarborAttestationResult = {
    ...base,
    keyMatched,
    measurementMatched,
    nonceMatched,
    clientChainVerified,
    clientChainReason,
    attestedKeyFp,
    expectedKeyFp,
    measurement,
  };

  // FAIL-CLOSED: an explicit contradiction is danger, not "meh".
  if (expectedKeyFp && !keyMatched) return { ...result, posture: 'failed', reason: 'key-mismatch' };
  if (measurementMatched === false) return { ...result, posture: 'failed', reason: 'measurement-mismatch' };
  if (nonceMatched === false) return { ...result, posture: 'failed', reason: 'nonce-mismatch' };
  // Relayed certs that don't chain to our pinned ARK are the strongest failure —
  // surface the verifier's specific reason (e.g. ark-pin-mismatch) over a generic one.
  if (clientChainVerified === false) {
    return { ...result, posture: 'failed', reason: clientChainReason || 'client-chain-unverified' };
  }

  // GATE 1 ENFORCEMENT — `attested` requires the APP ITSELF to have verified the AMD
  // chain. We deliberately do NOT fall back to the server's `chainVerified` boolean here:
  // a malicious server could otherwise omit `certChain`, set `chainVerified:true`, and
  // forge report bytes so the key/measurement/nonce (all values IT supplies) match — the
  // exact bypass Gate 1 exists to close. So:
  //   • web  → the verifier is server-shipped, so no self-check is trustworthy → never attested.
  //   • native + no client-verified chain (certs absent / KDS down) → `unverified`, not green.
  if (platform === 'web') {
    return { ...result, posture: 'unverified', reason: 'web-verifier-server-shipped' };
  }
  if (clientChainVerified !== true) {
    return { ...result, posture: 'unverified', reason: 'no-client-chain' };
  }

  // Chain is app-verified. Remaining "couldn't fully confirm" gates (no live key to bind,
  // or no published measurement reference yet) still hold it below `attested`.
  if (!expectedKeyFp) return { ...result, posture: 'unverified', reason: 'no-terminal-key' };
  if (measurementMatched === null) return { ...result, posture: 'unverified', reason: 'no-reference-measurement' };

  return { ...result, posture: 'attested', reason: null };
}
