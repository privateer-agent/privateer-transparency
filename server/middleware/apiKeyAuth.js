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

const User = require('../models/userModel');
const ApiKey = require('../models/apiKeyModel');
const logger = require('../utils/logger');

// OpenAI-shaped auth failure so the standard OpenAI SDKs surface a clean error.
function unauthorized(res, message) {
  return res.status(401).json({
    error: {
      message,
      type: 'invalid_request_error',
      code: 'invalid_api_key'
    }
  });
}

/**
 * Authenticate a developer request by its "sk-priv-…" API key.
 *
 * Parallels middleware/auth.js `authenticate` but keyed off an API key instead
 * of a JWT. On success attaches req.user (same shape as JWT auth), req.userId,
 * and req.apiKeyId. A key authorizes inference against its owner's account, so
 * everything downstream (entitlement, billing) keys off req.userId exactly as
 * the JWT path does.
 */
async function authenticateApiKey(req, res, next) {
  const header = req.headers.authorization || '';
  const rawKey = header.startsWith('Bearer ') ? header.slice(7).trim() : null;

  if (!rawKey || !rawKey.startsWith(ApiKey.KEY_PREFIX)) {
    return unauthorized(res, 'Missing or malformed API key. Provide it as: Authorization: Bearer sk-priv-…');
  }

  try {
    const keyDoc = await ApiKey.findValidByRaw(rawKey);
    if (!keyDoc) {
      return unauthorized(res, 'Invalid or revoked API key.');
    }

    const user = await User.findById(keyDoc.userId).select(
      '-password -passwordResetToken -passwordResetExpires -emailVerificationToken -emailVerificationExpires'
    );
    if (!user) {
      return unauthorized(res, 'Invalid or revoked API key.');
    }
    if (user.accountStatus === 'deleted' || user.accountStatus === 'grace_period') {
      return unauthorized(res, 'The account for this API key is not active.');
    }

    req.user = user;
    req.userId = user._id;
    req.apiKeyId = keyDoc._id;

    // Best-effort "last used" stamp — never block or fail the request on it.
    ApiKey.updateOne({ _id: keyDoc._id }, { lastUsedAt: new Date() }).catch(() => {});

    next();
  } catch (err) {
    logger.error('API key authentication error:', err.message);
    return unauthorized(res, 'Could not verify API key.');
  }
}

module.exports = { authenticateApiKey };
