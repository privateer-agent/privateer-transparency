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
 * Developer API-key management (JWT-authed — the app manages the user's own keys).
 *
 *   POST   /api/keys        — mint a key; raw sk-priv-… returned ONCE.
 *                              Body: { name, expiration, creditLimitUsd, limitReset }
 *                              — all optional, so an older client still mints
 *                              a never-expiring, unlimited key.
 *   GET    /api/keys        — list the caller's keys (never the raw secret)
 *   DELETE /api/keys/:id    — revoke a key
 *
 * The raw key is shown a single time at creation; only its SHA-256 hash and a
 * 4-char display suffix are stored (see models/apiKeyModel.js). The keys
 * themselves authenticate the OpenAI-compatible /v1 surface.
 */
const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');
const ApiKey = require('../models/apiKeyModel');
const { authenticate } = require('../middleware/auth');
const apiKeyUsage = require('../services/apiKeyUsage');

// Expiration choices, as durations from the moment of creation. An enum rather
// than a client-sent date so the server owns the clock and a key can't be
// minted already expired or a century out.
const DAY = 86400000;
const EXPIRATIONS = {
  none: null,
  '1d': DAY,
  '7d': 7 * DAY,
  '30d': 30 * DAY,
  '90d': 90 * DAY,
  '1y': 365 * DAY,
};
// Ceiling on a per-key limit: far above any real use, low enough that a typo'd
// extra zero is refused rather than stored as "effectively unlimited".
const MAX_CREDIT_LIMIT_USD = 100000;

function badRequest(res, message, code) {
  return res.status(400).json({ message, code });
}

router.use(authenticate);

// Shape a key doc for the client — never includes the raw secret or hash.
function publicKey(doc) {
  const reset = doc.limitReset || null;
  const nextReset = doc.creditLimitUsd != null ? apiKeyUsage.nextReset(reset) : null;
  return {
    id: String(doc._id),
    name: doc.name || null,
    keyLast4: doc.keyLast4,
    createdAt: doc.createdAt,
    lastUsedAt: doc.lastUsedAt || null,
    revokedAt: doc.revokedAt || null,
    expiresAt: doc.expiresAt || null,
    creditLimitUsd: doc.creditLimitUsd ?? null,
    limitReset: reset,
    // Spend in the CURRENT window (0 once it has rolled), not the stored
    // counter, which only restarts on the next charge.
    usageUsd: Math.round(apiKeyUsage.currentUsageUsd(doc) * 10000) / 10000,
    nextResetAt: nextReset,
  };
}

// POST /api/keys — create. Returns the raw key exactly once.
router.post('/', async (req, res) => {
  try {
    const rawName = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const name = rawName ? rawName.slice(0, 100) : null;

    const expiration = req.body?.expiration ?? 'none';
    if (!Object.prototype.hasOwnProperty.call(EXPIRATIONS, expiration)) {
      return badRequest(res, 'Unknown expiration', 'INVALID_EXPIRATION');
    }
    const expiresAt = EXPIRATIONS[expiration] == null ? null : new Date(Date.now() + EXPIRATIONS[expiration]);

    let creditLimitUsd = req.body?.creditLimitUsd ?? null;
    if (creditLimitUsd !== null) {
      creditLimitUsd = Number(creditLimitUsd);
      if (!Number.isFinite(creditLimitUsd) || creditLimitUsd <= 0 || creditLimitUsd > MAX_CREDIT_LIMIT_USD) {
        return badRequest(res, 'Credit limit must be between $0.01 and $100,000', 'INVALID_CREDIT_LIMIT');
      }
      creditLimitUsd = Math.round(creditLimitUsd * 100) / 100;
      if (creditLimitUsd <= 0) {
        return badRequest(res, 'Credit limit must be between $0.01 and $100,000', 'INVALID_CREDIT_LIMIT');
      }
    }

    // A reset only means something on a limited key; on an unlimited one it is
    // dropped rather than refused, matching the form, which greys it out.
    let limitReset = req.body?.limitReset ?? null;
    if (limitReset !== null && !apiKeyUsage.LIMIT_RESETS.includes(limitReset)) {
      return badRequest(res, 'Unknown limit reset', 'INVALID_LIMIT_RESET');
    }
    if (creditLimitUsd === null) limitReset = null;

    const rawKey = ApiKey.generateRawKey();
    const doc = await ApiKey.create({
      userId: req.user._id,
      keyHash: ApiKey.hashKey(rawKey),
      keyLast4: rawKey.slice(-4),
      name,
      expiresAt,
      creditLimitUsd,
      limitReset,
    });

    // `key` is present ONLY on this create response — it is never retrievable again.
    return res.status(201).json({ ...publicKey(doc), key: rawKey });
  } catch (err) {
    logger.error('POST /api/keys failed:', err.message);
    return res.status(500).json({ message: 'Failed to create API key' });
  }
});

// GET /api/keys — list the caller's keys (newest first).
router.get('/', async (req, res) => {
  try {
    const docs = await ApiKey.find({ userId: req.user._id }).sort({ createdAt: -1 }).lean();
    // .lean() docs lack virtuals; publicKey reads only plain fields, so it's fine.
    return res.json({ keys: docs.map(publicKey) });
  } catch (err) {
    logger.error('GET /api/keys failed:', err.message);
    return res.status(500).json({ message: 'Failed to list API keys' });
  }
});

// DELETE /api/keys/:id — revoke (scoped to the caller).
router.delete('/:id', async (req, res) => {
  try {
    const doc = await ApiKey.findOne({ _id: req.params.id, userId: req.user._id });
    if (!doc) {
      return res.status(404).json({ message: 'API key not found' });
    }
    if (!doc.revokedAt) {
      doc.revokedAt = new Date();
      await doc.save();
    }
    return res.json(publicKey(doc));
  } catch (err) {
    // Bad ObjectId etc. — treat as not found rather than 500.
    if (err.name === 'CastError') {
      return res.status(404).json({ message: 'API key not found' });
    }
    logger.error('DELETE /api/keys failed:', err.message);
    return res.status(500).json({ message: 'Failed to revoke API key' });
  }
});

module.exports = router;
