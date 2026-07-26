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
 * Standalone audio clips generated in the Audio studio (text-to-speech).
 *
 * Every other Library row is derived from an attachment embedded on a chat
 * message. A studio clip has no conversation, and `Message` has no
 * `fileAttachments` schema path — so the "synthesize a standalone Message"
 * trick `POST /api/library/videos` uses is unavailable here. This collection is
 * the clip's only home.
 *
 * Invariant: exactly one home per clip. Cloud backend → a row here plus an S3
 * object. Local backend → an on-device index entry plus an encrypted local
 * file, and nothing reaches this collection at all (CLAUDE.md §2). Never both.
 * That is what keeps the `GET /files` merge dedup-free and the delete
 * fall-through in libraryDeletion unambiguous.
 *
 * E2EE (CLAUDE.md §5): the server stores ciphertext and opaque handles only.
 * The filename, the prompt that produced the clip, the voice and the model id
 * all live inside `encryptedMetadata`, which the client seals before upload.
 */
const libraryAudioSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },

    // Stable handle: the S3 key under user_uploads/<userId>/ written by
    // POST /api/chat/upload-file. Named `storageRef` rather than `s3Key`
    // (which libraryVideoModel uses) because every file-shaped path in the
    // codebase — shapeFile, signFileRow, deleteFile, LibraryFolderItem.ref,
    // folders bulk-delete — already keys on `storageRef`. Matching it is what
    // lets those be reused verbatim instead of forked.
    storageRef: { type: String, required: true },
    // 'local' never reaches this collection; the enum makes that structural.
    storageType: { type: String, enum: ['cloud'], default: 'cloud' },

    // Encrypted JSON: { filename, mimeType, size, source, voice, ttsModelId,
    // prompt, durationMs }. A superset of the { filename, mimeType, size }
    // shape chatService writes for chat file attachments, so any client that
    // can decrypt one can decrypt the other.
    encryptedMetadata: { type: String, default: null },
    encIv: { type: String, default: null }, // IV for the binary, not the metadata

    fileSize: { type: Number, default: null },     // plaintext byte length
    // Ciphertext byte length — what was actually charged against the storage
    // cap, so the delete refund is exact. (The chat-attachment path reads a
    // field that doesn't exist and under-refunds by the AES-GCM overhead.)
    encryptedSize: { type: Number, default: null },

    // Provenance. 'tts' = generated in the Audio studio. 'upload' is reserved
    // for a future chatless audio import; audio that arrives via a chat keeps
    // living in Chat.messages[].fileAttachments[] and is shaped with
    // source: 'chat'.
    source: { type: String, enum: ['tts', 'upload'], default: 'tts', index: true },

    // Render hint only — not content, not identifying.
    durationMs: { type: Number, default: null },

    // Hard delete is the intended path (there's no chat history to preserve).
    // Kept so a future trash feature needs no migration.
    deleted: { type: Boolean, default: false },
  },
  { timestamps: true }
);

libraryAudioSchema.index({ userId: 1, deleted: 1, createdAt: -1 });
// Makes POST /api/library/audio idempotent: a client retry after a network
// blip upserts the same row instead of duplicating it.
libraryAudioSchema.index({ userId: 1, storageRef: 1 }, { unique: true });

// E2EE fence, mirroring chatModel's. Mongoose would drop these keys anyway
// since they aren't in the schema — the fence exists so a later "let's just
// add a title field" change trips a reviewer rather than silently persisting
// the prompt text or the user's chosen voice in plaintext.
const PLAINTEXT_KEYS = [
  'filename', 'fileName', 'mimeType', 'prompt', 'text', 'voice', 'ttsModelId', 'title',
];

libraryAudioSchema.pre('save', function (next) {
  for (const key of PLAINTEXT_KEYS) this.set(key, undefined);
  next();
});

function fenceUpdatePlaintext(next) {
  const update = this.getUpdate?.();
  if (!update) return next();
  const strip = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    for (const key of PLAINTEXT_KEYS) delete obj[key];
  };
  strip(update);
  strip(update.$set);
  strip(update.$setOnInsert);
  next();
}
libraryAudioSchema.pre('findOneAndUpdate', fenceUpdatePlaintext);
libraryAudioSchema.pre('updateOne', fenceUpdatePlaintext);
libraryAudioSchema.pre('updateMany', fenceUpdatePlaintext);

module.exports = mongoose.model('LibraryAudio', libraryAudioSchema);
