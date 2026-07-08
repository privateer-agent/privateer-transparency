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

// Cloud "outbox" for unattended CLI results (completed routines, finished agent
// tasks) so the app can catch up when it reopens, without push notifications.
//
// Store-and-forward mailbox, NOT an archive: the CLI seals a small summary to
// the account's outbox public key (X25519 sealed box; see outboxSeal on the
// client/CLI) and POSTs the ciphertext here. The server stores opaque blobs
// only — it can never read the content. A key-holding client fetches on open,
// decrypts locally, then acks (which deletes). The full transcript stays on the
// terminal; this only carries a capped summary.
//
// Everything content-shaped — routine/task name, prompt, result text, error
// tails, and the incidental identifiers (paths, cwd, hostnames, command lines,
// tool args) that leak project/client names — lives INSIDE `sealed`. The
// plaintext fields below are only what the server needs to route, quota, and
// expire.
const outboxItemSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    // X25519 sealed box, base64. Wire format: epk(32) ‖ iv(12) ‖ ct‖tag.
    // The server never decrypts this.
    sealed: {
      type: String,
      required: true
    },
    // Decoded ciphertext size in bytes — kept in the clear for quota/enforcement.
    size: {
      type: Number,
      required: true,
      min: 0
    },
    // Hard TTL backstop. Items are normally removed on ack; this guarantees the
    // mailbox never accumulates if a device never comes back.
    expiresAt: {
      type: Date,
      required: true
    }
  },
  { timestamps: true }
);

// Fetch-on-open: newest unacked items for a user.
outboxItemSchema.index({ userId: 1, createdAt: -1 });
// TTL index: auto-purge at expiresAt (30-day backstop set by the route).
outboxItemSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OutboxItem = mongoose.model('OutboxItem', outboxItemSchema);

module.exports = OutboxItem;
