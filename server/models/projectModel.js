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
 * Project model — a named container for related chats with persistent AI instructions.
 *
 * All user content (name, instructions) is encrypted client-side (AES-256-GCM) before
 * being sent here. The server stores and returns ciphertext only — it never decrypts.
 */
const projectSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    // E2EE: encrypted project name. JSON string: { "iv": "<base64>", "ct": "<base64>" }
    encryptedName: {
      type: String,
      required: true
    },
    // E2EE: encrypted project instructions (system prompt for all chats in this project).
    // JSON string: { "iv": "<base64>", "ct": "<base64>" }
    encryptedInstructions: {
      type: String,
      default: null
    },
    isActive: {
      type: Boolean,
      default: true
    },
    lastActivity: {
      type: Date,
      default: Date.now,
      index: true
    },
    totalChats: {
      type: Number,
      default: 0,
      min: 0
    },
    iconType: {
      type: String,
      default: null
    },
    iconValue: {
      type: String,
      default: null
    },
    iconColor: {
      type: String,
      default: null
    },
    // Pinned projects are surfaced in the side-navigation drawer regardless of
    // recency. No user content — a plain boolean, safe to store unencrypted.
    pinned: {
      type: Boolean,
      default: false
    },
    metadata: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
      default: () => new Map()
    }
  },
  {
    timestamps: true
  }
);

projectSchema.index({ userId: 1, lastActivity: -1 });
projectSchema.index({ userId: 1, isActive: 1 });

// Create a new project
projectSchema.statics.createProject = async function(userId, data) {
  const { encryptedName, encryptedInstructions, iconType, iconValue, iconColor } = data;
  return this.create({
    userId,
    encryptedName,
    encryptedInstructions: encryptedInstructions || null,
    iconType: iconType || null,
    iconValue: iconValue || null,
    iconColor: iconColor || null,
    lastActivity: new Date()
  });
};

// Get all active projects for a user (ordered by most recent activity)
projectSchema.statics.getUserProjects = async function(userId) {
  if (!userId) return [];
  return this.find({ userId, isActive: true })
    .sort({ lastActivity: -1 })
    .select('encryptedName encryptedInstructions iconType iconValue iconColor pinned totalChats lastActivity createdAt')
    .lean();
};

module.exports = mongoose.model('Project', projectSchema);
