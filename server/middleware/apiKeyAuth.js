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
const analyticsService = require('../services/analyticsService');
const apiKeyUsage = require('../services/apiKeyUsage');

// OpenAI-shaped auth failure so the standard OpenAI SDKs surface a clean error.
function unauthorized(res, message, code = 'invalid_api_key') {
  return res.status(401).json({
    error: {
      message,
      type: 'invalid_request_error',
      code
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
    // Its own code: "expired" tells a developer to mint a new key, where
    // "invalid" sends them looking for a typo.
    if (apiKeyUsage.isExpired(keyDoc)) {
      return unauthorized(res, 'This API key has expired.', 'expired_api_key');
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
    // The doc rides the request so the per-key credit gate (checkBalance) can
    // read the limit without a second lookup.
    req.apiKey = keyDoc;

    // Best-effort "last used" stamp — never block or fail the request on it.
    // findOneAndUpdate rather than updateOne so the pre-image comes back in the
    // same round trip: a null → set transition is the first request this key
    // has ever served, which is the developer-activation signal (keys created
    // and actually used, as opposed to keys created).
    ApiKey.findOneAndUpdate({ _id: keyDoc._id }, { lastUsedAt: new Date() }, { new: false })
      .then((prev) => { if (prev && !prev.lastUsedAt) analyticsService.track('first_api_key_used'); })
      .catch(() => {});

    // Everything downstream bills inside this key's context, which is how a
    // charge made five modules away is counted against the key's credit limit
    // (services/apiKeyUsage.js explains why this is not a parameter).
    apiKeyUsage.runWithKey({ apiKeyId: keyDoc._id, userId: user._id }, next);
  } catch (err) {
    logger.error('API key authentication error:', err.message);
    return unauthorized(res, 'Could not verify API key.');
  }
}

/**
 * Re-enter the key's billing context after middleware that resumes on another
 * async context (multer/busboy resumes on the socket's). Place it right after.
 */
function rebindApiKeyContext(req, _res, next) {
  if (!req.apiKeyId) return next();
  apiKeyUsage.runWithKey({ apiKeyId: req.apiKeyId, userId: req.userId }, next);
}

module.exports = { authenticateApiKey, rebindApiKeyContext };
