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

const mongoose = require('mongoose');

/**
 * Cargo — a saved, runnable HTML artifact (the "builds" from the code-preview
 * feature). Nautical name for Privateer's take on Claude-style artifacts.
 *
 * All content is encrypted client-side (AES-256-GCM) before it reaches here;
 * the server stores and returns ciphertext only and never decrypts. A merged
 * artifact is small (client caps it at 512 KB), so the HTML lives inline in
 * `encryptedContent` — no S3 blob, unlike ProjectFile.
 */
const cargoSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    storageType: {
      type: String,
      enum: ['cloud', 'local'],
      default: 'cloud'
    },
    // E2EE: encrypted runnable HTML document. { iv, ct } JSON string → HTML.
    encryptedContent: {
      type: String,
      required: true
    },
    // E2EE: encrypted metadata JSON { iv, ct } → { title, langs }.
    encryptedMetadata: {
      type: String,
      required: true
    },
    // Byte length of the ciphertext content, for storage accounting.
    fileSize: {
      type: Number,
      default: 0
    }
  },
  {
    timestamps: true
  }
);

cargoSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('Cargo', cargoSchema);
