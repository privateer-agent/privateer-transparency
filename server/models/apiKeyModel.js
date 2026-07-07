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
const crypto = require('crypto');

// Developer API keys ("sk-priv-…") for the OpenAI-compatible /v1 surface.
//
// Same trust model as refreshTokenModel: the raw key is shown to the developer
// exactly ONCE at creation; we persist only its SHA-256 hash plus a short
// display suffix (keyLast4) so the UI can render "sk-priv-…a1b2" without ever
// holding the secret. A key authorizes inference against its owner's account —
// billed to their shared credit balance, bounded by their tier caps (see
// middleware/apiKeyAuth.js). Keys live until revoked (no TTL).
const KEY_PREFIX = 'sk-priv-';

const apiKeySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    // SHA-256 hex of the raw key. The raw secret is never stored.
    keyHash: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    // Last 4 chars of the raw key, for display only ("sk-priv-…a1b2").
    keyLast4: {
      type: String,
      required: true
    },
    // Optional user-supplied label ("prod backend", "laptop", …).
    name: {
      type: String,
      trim: true,
      maxlength: 100,
      default: null
    },
    lastUsedAt: {
      type: Date,
      default: null
    },
    revokedAt: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);

// Newest-first listing per owner.
apiKeySchema.index({ userId: 1, createdAt: -1 });

apiKeySchema.statics.KEY_PREFIX = KEY_PREFIX;

// Generate a cryptographically secure raw key. Shown once; never persisted raw.
apiKeySchema.statics.generateRawKey = function () {
  return `${KEY_PREFIX}${crypto.randomBytes(32).toString('hex')}`;
};

// Hash a raw key for storage / lookup.
apiKeySchema.statics.hashKey = function (rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
};

// Resolve a raw key to its live (non-revoked) record, or null.
apiKeySchema.statics.findValidByRaw = async function (rawKey) {
  if (typeof rawKey !== 'string' || !rawKey.startsWith(KEY_PREFIX)) return null;
  const keyHash = this.hashKey(rawKey);
  return this.findOne({ keyHash, revokedAt: null });
};

const ApiKey = mongoose.model('ApiKey', apiKeySchema);

module.exports = ApiKey;
