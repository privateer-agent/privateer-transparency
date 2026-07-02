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
 * ShareSnapshot — a public, read-only, point-in-time copy of a chat, graph, or
 * cargo artifact.
 *
 * E2EE is preserved: at share time the client re-encrypts the conversation
 * under a fresh 32-byte *share key* (separate from the account master key) and
 * uploads only the ciphertext here. The share key never reaches the server —
 * it lives in the share URL's #fragment, which browsers never transmit. So the
 * server stores ciphertext only, exactly as with normal chats, yet anyone with
 * the full link can decrypt the snapshot locally.
 *
 * `wrappedShareKey` is the share key wrapped under the owner's master key, kept
 * so the owner can re-open/update an existing snapshot without minting a new
 * link. It is owner-only and is NEVER returned by the public GET route.
 *
 * Snapshots are frozen: new messages in the source chat do not appear until the
 * owner re-shares (which overwrites this document in place, keyed by token).
 */

// Re-encrypted media reference. `s3Key` lives under `shares/<token>/` and the
// bytes are AES-256-GCM ciphertext under the share key; `encIv` is that IV.
const assetRefSchema = new mongoose.Schema(
  {
    kind: { type: String, enum: ['image', 'video'], required: true },
    s3Key: { type: String, required: true },
    encIv: { type: String, required: true },
    mimeType: { type: String, default: null },
    fileName: { type: String, default: null },
    width: { type: Number, default: null },
    height: { type: Number, default: null },
    durationMs: { type: Number, default: null },
  },
  { _id: false }
);

// Document attachment (pdf/audio/docx/csv/code). Unlike images/videos, document
// bytes are not durably stored, so a share carries metadata only — rendered as a
// non-downloadable chip. The filename is encrypted under the share key.
const fileRefSchema = new mongoose.Schema(
  {
    type: { type: String, default: 'file' },
    encryptedFileName: { type: String, default: null },
    mimeType: { type: String, default: null },
  },
  { _id: false }
);

const shareSnapshotSchema = new mongoose.Schema(
  {
    // Public URL identifier (crypto.randomBytes(16).toString('base64url')).
    token: { type: String, required: true, unique: true, index: true },

    ownerUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },

    sourceType: { type: String, enum: ['chat', 'graph', 'cargo'], required: true },
    // Where the original chat/graph lives. `cloud` sources exist in our DB (and
    // ownership is verified against it); `local` sources live only on the user's
    // device — the owner uploads their own re-encrypted snapshot, so there is no
    // server-side record to verify against.
    sourceBackend: { type: String, enum: ['cloud', 'local'], default: 'cloud' },
    // Original Chat / ChatGraph id — lets the owner find an existing share to
    // re-copy/update or to show "already shared" state. Unique per owner+source.
    // Stored as a string so it covers both cloud ObjectId hex (24 chars) and
    // local on-device ids (32 hex chars, which are NOT valid ObjectIds).
    sourceId: { type: String, required: true, index: true },

    // Share key wrapped under the owner master key. Owner-only, never public.
    wrappedShareKey: { type: String, required: true },

    // {iv,ct} JSON under the share key.
    encryptedTitle: { type: String, default: null },

    // Linear-chat snapshot: ordered message list.
    messages: [
      {
        role: { type: String, enum: ['user', 'assistant', 'system'], required: true },
        encryptedContent: { type: String, default: null },
        encryptedSources: { type: String, default: null },
        attachments: { type: [assetRefSchema], default: [] },
        files: { type: [fileRefSchema], default: [] },
      },
    ],

    // Graph snapshot: nodes + edges. `clientNodeId` is a stable id used to wire
    // edges within the snapshot (decoupled from server ObjectIds).
    nodes: [
      {
        clientNodeId: { type: String, required: true },
        type: { type: String, enum: ['entry', 'standard', 'note', 'file'], default: 'standard' },
        encryptedPrompt: { type: String, default: null },
        encryptedAiResponse: { type: String, default: null },
        encryptedNoteBody: { type: String, default: null },
        position: { x: { type: Number, default: 0 }, y: { type: Number, default: 0 } },
        attachments: { type: [assetRefSchema], default: [] },
        files: { type: [fileRefSchema], default: [] },
      },
    ],
    edges: [
      {
        sourceNodeId: { type: String, required: true },
        targetNodeId: { type: String, required: true },
        edgeType: { type: String, default: 'directional' },
      },
    ],
    entryNodeIds: { type: [String], default: [] },

    // Cargo snapshot: one inline artifact, re-encrypted under the share key.
    // encryptedMeta is {iv,ct} of JSON {title, kind} — the artifact kind stays
    // inside the ciphertext so the server remains kind-blind.
    cargo: {
      type: new mongoose.Schema(
        {
          encryptedMeta: { type: String, required: true },
          encryptedContent: { type: String, required: true },
        },
        { _id: false }
      ),
      default: null,
    },

    viewCount: { type: Number, default: 0 },
    revokedAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null }, // reserved; no UI in v1
  },
  { timestamps: true }
);

// One live share per (owner, source). Re-sharing overwrites in place.
shareSnapshotSchema.index({ ownerUserId: 1, sourceId: 1 }, { unique: true });

shareSnapshotSchema.methods.isViewable = function () {
  if (this.revokedAt) return false;
  if (this.expiresAt && this.expiresAt.getTime() <= Date.now()) return false;
  return true;
};

module.exports = mongoose.model('ShareSnapshot', shareSnapshotSchema);
