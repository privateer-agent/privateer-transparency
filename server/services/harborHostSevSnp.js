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

/**
 * Harbor SEV-SNP host backend — the real (non-stub) compute backend.
 *
 * Talks to the per-host orchestrator running inside each Harbor confidential VM
 * (plan Phase 1). Selected via `HARBOR_HOST_BACKEND=sevsnp`. It is NOT usable
 * until (a) the measured Harbor image + SEV-SNP CVM fleet exist, and (b)
 * `HARBOR_HOST_CONTROL_URL` (+ optional `HARBOR_HOST_CONTROL_TOKEN`) point at a
 * running orchestrator. Until then any call fails 503 with a clear message — this
 * module encodes the control contract so the real wiring is fill-in-the-blanks.
 *
 * The orchestrator's job per host CVM, given a boot payload from `start`:
 *   1. Allocate an isolated tenant slot (Linux namespace / cgroup / container).
 *   2. Seed `$PRIVATEER_HOME`: write `credentials.json` (the minted pair) 0600,
 *      `account-trust.json` = `{ accountSignPub }`, and `routines/relay-id` = the
 *      given `termId` (so the daemon registers under the id the server recorded —
 *      see the CONTRACT note in harborProvisionService).
 *   3. Set env `HARBOR_HOSTED=1`, `PRIVATEER_SERVER_URL=<our server>`, then launch
 *      `node bin/privateer-daemon.mjs run` in that slot (outbound-only).
 *   4. Return `{ hostId, region, measurement }` where `measurement` is the attested
 *      image measurement the app verifies (Phase 3).
 * `suspend` stops the tenant's daemon process (freeing the slot); `stop` tears the
 * tenant down entirely.
 *
 * `attest` asks the orchestrator for a FRESH SEV-SNP report from the running
 * tenant's enclave, bound to `nonce` and to the daemon's `terminalPub`
 * (report_data[0:32] = sha256(DER(terminalPub SPKI))). The orchestrator validates
 * the AMD VCEK chain and returns that verdict as `chainVerified` (the "client trusts
 * the server for the chain" decision — the client then independently binds the key +
 * measurement; see client/services/harborAttestation.ts).
 *
 * HOW the chain is validated (decided 2026-07-20, see harborOrchestrator/attest.js):
 * the orchestrator SELF-VERIFIES via `snpguest`, falling back to a native node:crypto
 * implementation. A CoCo Trustee is an OPTIONAL path, used only when HARBOR_TRUSTEE_URL
 * is set — it is built for a secret-brokering flow Harbor does not currently use.
 *
 * ⚠ This comment previously said "Until a Trustee is wired the orchestrator returns
 * chainVerified: false." That was stale and it misled a later design doc into treating
 * a Trustee as a prerequisite for attestation. It is not, and never was after
 * 2026-07-20. Verification is still FAIL-CLOSED at every branch — a missing tool,
 * failed fetch, bad signature, or unmet report_data binding all yield false — so the
 * client still refuses to trust an unverified chain.
 */

const logger = require('../utils/logger');

const CONTROL_URL = process.env.HARBOR_HOST_CONTROL_URL || null;
const CONTROL_TOKEN = process.env.HARBOR_HOST_CONTROL_TOKEN || null;
// Cap the host-orchestrator round-trip. Attest is called inside a ~12s retry loop
// (harborProvisionService.attest), so keep a single hop well under that.
const CONTROL_TIMEOUT_MS = Number(process.env.HARBOR_HOST_CONTROL_TIMEOUT_MS) || 30000;

function assertConfigured() {
  if (!CONTROL_URL) {
    const err = new Error(
      '[harbor:sevsnp] HARBOR_HOST_CONTROL_URL is not set — the confidential-VM host ' +
      'orchestrator is not deployed yet (plan Phase 0/1).'
    );
    err.status = 503;
    err.code = 'HARBOR_HOST_UNAVAILABLE';
    throw err;
  }
}

async function control(path, body) {
  assertConfigured();
  // Time-box the host round-trip so a slow/unresponsive orchestrator can't hang the
  // request thread (and the client's wake/drive spinner) indefinitely.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CONTROL_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${CONTROL_URL}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(CONTROL_TOKEN ? { authorization: `Bearer ${CONTROL_TOKEN}` } : {}),
      },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
  } catch (e) {
    const err = new Error(
      `[harbor:sevsnp] host control ${path} → ${e && e.name === 'AbortError' ? `timed out after ${CONTROL_TIMEOUT_MS}ms` : String(e && e.message || e)}`
    );
    err.status = 504;
    err.code = 'HARBOR_HOST_UNAVAILABLE';
    throw err;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    // Preserve the orchestrator's structured error (status + code) across this boundary.
    // Without this, callers like harborProvisionService.attest() — whose boot-race retry
    // loop keys off err.code === 'HARBOR_ATTEST_NO_KEY' — see a statusless Error, skip the
    // retry, and surface the race as an opaque 500 instead of self-healing.
    let parsed = null;
    try { parsed = JSON.parse(text); } catch { /* non-JSON body */ }
    const err = new Error(`[harbor:sevsnp] host control ${path} → ${res.status} ${text.slice(0, 200)}`);
    err.status = res.status;
    if (parsed && parsed.code) err.code = parsed.code;
    throw err;
  }
  return res.json().catch(() => ({}));
}

const sevsnpBackend = {
  name: 'sevsnp',

  async start({ userId, agentId, termId, credentials, accountSignPub, routines, webAccess }) {
    logger.info(`[harbor:sevsnp] start tenant user=${userId} agent=${agentId} term=${termId} routines=${(routines || []).length} web=${webAccess === false ? 'off' : 'on'}`);
    const out = await control('/tenants/start', { userId, agentId, termId, credentials, accountSignPub, routines, webAccess });
    return {
      hostId: out.hostId || null,
      region: out.region || null,
      measurement: out.measurement || null,
    };
  },

  async suspend({ userId, agentId }) {
    await control('/tenants/suspend', { userId, agentId });
  },

  async stop({ userId, agentId }) {
    await control('/tenants/stop', { userId, agentId });
  },

  async attest({ userId, agentId, termId, nonce }) {
    logger.info(`[harbor:sevsnp] attest tenant user=${userId} agent=${agentId} term=${termId}`);
    const out = await control('/tenants/attest', { userId, agentId, termId, nonce });
    return {
      reportB64: out.report || out.reportB64 || null,
      chainVerified: out.chainVerified === true,
      terminalPub: out.terminalPub || null,
      // Raw VCEK+ASK+ARK (base64 DER) for the client's own Gate-1 chain verification.
      certChain: out.certChain || null,
    };
  },
};

module.exports = sevsnpBackend;
