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
 * Base58 (Bitcoin alphabet) — the canonical display form for a Solana address.
 *
 * Lifted verbatim out of routes/auth.js so the wallet signature verifiers can
 * share it (services/walletVerifiers.js) instead of keeping a second copy in
 * step. Behaviour is unchanged, including the 32-byte assumption in `decode`:
 * the BigInt is padded back out to 64 hex chars, which is what makes a pubkey
 * with leading zero bytes round-trip.
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Decode a base58 string to a 32-byte Buffer. Throws on an invalid character. */
function base58Decode(str) {
  let result = BigInt(0);
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base58 character: ${char}`);
    result = result * BigInt(58) + BigInt(idx);
  }
  const hex = result.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

/**
 * Encode a 32-byte buffer as base58 (the canonical Solana address form).
 * Leading zero bytes map to leading '1's, per the base58 spec.
 */
function base58Encode(buf) {
  let result = '';
  let value = BigInt('0x' + buf.toString('hex'));
  while (value > BigInt(0)) {
    const rem = value % BigInt(58);
    value = value / BigInt(58);
    result = BASE58_ALPHABET[Number(rem)] + result;
  }
  for (const byte of buf) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result;
}

module.exports = { base58Decode, base58Encode, BASE58_ALPHABET };
