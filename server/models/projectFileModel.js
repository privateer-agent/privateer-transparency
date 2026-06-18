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
 * ProjectFile — an encrypted file attached to a project.
 *
 * All content (binary and metadata) is encrypted client-side (AES-256-GCM) before
 * being sent here. The server stores and returns ciphertext only — it never decrypts.
 *
 * For text/code files, encryptedTextContent holds the extracted UTF-8 text so the
 * client can inject it into the system prompt without re-downloading the full binary.
 * PDFs and images have null encryptedTextContent; the client fetches the binary at
 * inference time and sends it inline.
 */
const projectFileSchema = new mongoose.Schema(
  {
    projectId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      required: true,
      index: true
    },
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
    // S3 key for the encrypted binary (cloud only).
    s3Key: {
      type: String,
      default: null
    },
    // E2EE: encrypted file metadata JSON { iv, ct } → { filename, mimeType, size, fileType: 'text'|'pdf'|'image' }
    encryptedMetadata: {
      type: String,
      required: true
    },
    // E2EE: encrypted UTF-8 text content for text/code files. Null for PDFs and images.
    // { iv, ct } → raw text string
    encryptedTextContent: {
      type: String,
      default: null
    },
    fileSize: {
      type: Number,
      default: 0
    },
    // Client-controlled ordering within the project file list.
    ordering: {
      type: Number,
      default: 0
    }
  },
  {
    timestamps: true
  }
);

projectFileSchema.index({ projectId: 1, userId: 1 });
projectFileSchema.index({ projectId: 1, ordering: 1 });

module.exports = mongoose.model('ProjectFile', projectFileSchema);
