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
 * Cloud outbox — store-and-forward mailbox for unattended CLI results.
 *
 * A running `privateer-agent` terminal seals a small summary of a completed
 * routine / finished agent task to the account's outbox public key and POSTs
 * the ciphertext here. A key-holding client (app/web) fetches on open, decrypts
 * locally, then acks (delete). The server only ever handles opaque blobs.
 *
 *   POST /api/outbox/pubkey  (authed) → publish the account outbox public key.
 *                                       Write-once: immutable after first set.
 *   GET  /api/outbox/pubkey  (authed) → the caller's outbox public key (terminals
 *                                       read this to know what to seal to).
 *   POST /api/outbox         (authed, rate-limited) → enqueue one sealed item.
 *   GET  /api/outbox         (authed) → the caller's pending items, newest first.
 *   POST /api/outbox/ack     (authed) → delete acked items by id.
 *
 * Terminals hold NO account key material, so they can only write. The immutable
 * pubkey guarantees a compromised terminal can't substitute a key it controls;
 * clients additionally verify the published key matches their locally-derived
 * one before trusting the outbox.
 */
const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const logger = require('../utils/logger');
const Sentry = require('@sentry/node');
const User = require('../models/userModel');
const OutboxItem = require('../models/outboxItemModel');
const { authenticate } = require('../middleware/auth');
const { outboxPostLimiter } = require('../middleware/rateLimiter');

// A sealed item is epk(32)+iv(12)+tag(16) overhead over a summary capped at
// ~64KiB plaintext. Cap the base64 payload generously above that; the mailbox
// carries summaries, not transcripts.
const MAX_SEALED_B64_LEN = 128 * 1024;
// How many items one fetch returns. Fetch-on-open catch-up, not history.
const MAX_FETCH = 100;
// Hard TTL backstop; items are normally removed on ack.
const TTL_MS = 30 * 24 * 60 * 60 * 1000;

// Validate a base64 string, optionally pinning the decoded byte length.
function decodeBase64(value, expectedBytes = null) {
  if (typeof value !== 'string' || value.length === 0) return null;
  let buf;
  try {
    buf = Buffer.from(value, 'base64');
  } catch {
    return null;
  }
  if (buf.length === 0) return null;
  // Buffer.from is lenient (drops invalid chars); re-encode and compare to
  // reject malformed input rather than silently storing a truncated blob.
  if (buf.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) return null;
  if (expectedBytes !== null && buf.length !== expectedBytes) return null;
  return buf;
}

// ---------------------------------------------------------------------------
// Outbox public key
// ---------------------------------------------------------------------------

router.get('/pubkey', authenticate, async (req, res) => {
  res.json({ outboxPublicKey: req.user.outboxPublicKey || null });
});

router.post('/pubkey', authenticate, async (req, res) => {
  try {
    const { outboxPublicKey } = req.body || {};
    if (!decodeBase64(outboxPublicKey, 32)) {
      return res.status(400).json({ message: 'outboxPublicKey must be base64 of 32 bytes', code: 'BAD_OUTBOX_KEY' });
    }

    // Write-once. Only set when currently unset — a compromised terminal must
    // never be able to overwrite the account's outbox key with its own.
    const updated = await User.findOneAndUpdate(
      { _id: req.user._id, $or: [{ outboxPublicKey: { $in: [null, ''] } }, { outboxPublicKey: { $exists: false } }] },
      { $set: { outboxPublicKey } },
      { new: true }
    ).select('outboxPublicKey');

    if (updated) {
      return res.json({ outboxPublicKey: updated.outboxPublicKey, created: true });
    }

    // Already set. Idempotent if it matches; a conflict otherwise (someone else
    // — possibly a hostile terminal — got there first; the client surfaces this).
    const current = await User.findById(req.user._id).select('outboxPublicKey');
    if (current && current.outboxPublicKey === outboxPublicKey) {
      return res.json({ outboxPublicKey: current.outboxPublicKey, created: false });
    }
    return res.status(409).json({
      message: 'A different outbox public key is already published for this account',
      code: 'OUTBOX_KEY_CONFLICT',
    });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'outbox_pubkey_set' } });
    logger.error('Outbox pubkey set error:', error);
    res.status(500).json({ message: 'Error publishing outbox key' });
  }
});

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

router.post('/', authenticate, outboxPostLimiter, async (req, res) => {
  try {
    const { sealed } = req.body || {};
    if (typeof sealed !== 'string' || sealed.length === 0) {
      return res.status(400).json({ message: 'sealed is required (base64)', code: 'NO_SEALED' });
    }
    if (sealed.length > MAX_SEALED_B64_LEN) {
      return res.status(413).json({ message: 'Sealed item too large', code: 'OUTBOX_TOO_LARGE' });
    }
    const buf = decodeBase64(sealed);
    if (!buf) {
      return res.status(400).json({ message: 'sealed must be valid base64', code: 'BAD_SEALED' });
    }

    const item = await OutboxItem.create({
      userId: req.user._id,
      sealed,
      size: buf.length,
      expiresAt: new Date(Date.now() + TTL_MS),
    });

    res.status(201).json({ id: item._id, createdAt: item.createdAt });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'outbox_post' } });
    logger.error('Outbox post error:', error);
    res.status(500).json({ message: 'Error enqueueing outbox item' });
  }
});

router.get('/', authenticate, async (req, res) => {
  try {
    const items = await OutboxItem.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(MAX_FETCH)
      .select('sealed createdAt')
      .lean();

    res.json({
      items: items.map((it) => ({ id: it._id, sealed: it.sealed, createdAt: it.createdAt })),
    });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'outbox_list' } });
    logger.error('Outbox list error:', error);
    res.status(500).json({ message: 'Error fetching outbox' });
  }
});

router.post('/ack', authenticate, async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
    const valid = ids.filter((id) => mongoose.Types.ObjectId.isValid(id)).slice(0, MAX_FETCH);
    if (valid.length === 0) {
      return res.status(400).json({ message: 'ids must be a non-empty array of item ids', code: 'NO_IDS' });
    }
    // Scoped to userId so one user can never delete another's items.
    const result = await OutboxItem.deleteMany({ userId: req.user._id, _id: { $in: valid } });
    res.json({ deleted: result.deletedCount || 0 });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'outbox_ack' } });
    logger.error('Outbox ack error:', error);
    res.status(500).json({ message: 'Error acking outbox items' });
  }
});

module.exports = router;
