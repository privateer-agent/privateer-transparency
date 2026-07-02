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
 * Cargo share-snapshot payload validation (pure — unit-testable without the
 * route's import graph). Used by POST /api/share finalize for
 * sourceType === 'cargo'.
 *
 * Sizes are ciphertext lengths: cargo artifacts are capped at 512KB plaintext
 * client-side; the base64 {iv,ct} JSON lands around 700KB, so the content cap
 * leaves headroom without letting finalize be abused as blob storage.
 */

const MAX_CARGO_CONTENT_CT = 1_500_000;
const MAX_CARGO_META_CT = 8_192;

/**
 * @param {{encryptedMeta?: unknown, encryptedContent?: unknown}|null} cargo
 * @returns {{status: number, message: string}|null} error to send, or null when valid
 */
function validateCargoPayload(cargo) {
  if (!cargo || typeof cargo.encryptedMeta !== 'string' || typeof cargo.encryptedContent !== 'string') {
    return { status: 400, message: 'cargo.encryptedMeta and cargo.encryptedContent are required' };
  }
  if (cargo.encryptedContent.length > MAX_CARGO_CONTENT_CT || cargo.encryptedMeta.length > MAX_CARGO_META_CT) {
    return { status: 413, message: 'Artifact is too large to share.' };
  }
  return null;
}

module.exports = { validateCargoPayload, MAX_CARGO_CONTENT_CT, MAX_CARGO_META_CT };
