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
const UserSession = require('../models/userSessionModel');
const { verifyAccessToken } = require('../services/tokenService');

/**
 * Verify the Bearer token, check jti revocation, and attach req.user + req.jti.
 * Returns 401 if missing/invalid, 403 if revoked.
 */
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const decoded = verifyAccessToken(token);

    // jti revocation check (same predicate as isRevoked; keeps the row so we can
    // tag which client minted the session — see req.sessionClient below).
    const session = await UserSession.findIfLive(decoded.jti);
    if (!session) {
      return res.status(401).json({ message: 'Session has been revoked', code: 'SESSION_REVOKED' });
    }

    const user = await User.findById(decoded.sub).select(
      '-password -passwordResetToken -passwordResetExpires -emailVerificationToken -emailVerificationExpires'
    );
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    if (user.accountStatus === 'deleted') {
      return res.status(401).json({ message: 'Account has been deleted' });
    }

    if (user.accountStatus === 'grace_period') {
      // Allow only the cancel-deletion endpoint for grace_period accounts
      const isCancelPath = req.path === '/auth/account/cancel-deletion' ||
        req.originalUrl === '/auth/account/cancel-deletion';
      if (!isCancelPath) {
        return res.status(403).json({ message: 'Account pending deletion', code: 'ACCOUNT_PENDING_DELETION' });
      }
    }

    req.user = user;
    req.jti = decoded.jti;
    req.authMethod = decoded.authMethod;
    // Which surface minted this session ('mobile' | 'web' | 'desktop' | 'cli';
    // undefined on legacy rows / older app builds). Routes shared by more than one
    // surface use it to attribute usage — the sealed relay is one route serving both
    // the app and a linked terminal, so it cannot infer the caller from the path the
    // way agentInference/v1/appTools do.
    req.sessionClient = session.client;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ message: 'Invalid token' });
  }
}

/**
 * Same as authenticate but non-blocking — continues without user if no/bad token.
 */
async function lightAuthenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return next();

  try {
    const decoded = verifyAccessToken(token);
    const session = await UserSession.findIfLive(decoded.jti);
    if (!session) return next();

    const user = await User.findById(decoded.sub);
    // Match authenticate()'s account-status gating: a deleted or pending-
    // deletion account is not a live identity, so leave req.user unset and let
    // the route proceed as anonymous rather than acting on a half-deleted user.
    if (user && user.accountStatus !== 'deleted' && user.accountStatus !== 'grace_period') {
      req.user = user;
      req.jti = decoded.jti;
      req.authMethod = decoded.authMethod;
      req.sessionClient = session.client;
    }
  } catch (_) {
    // Invalid token — continue without user
  }
  next();
}

/**
 * authenticate + admin role check.
 */
async function authenticateAdmin(req, res, next) {
  await authenticate(req, res, async () => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized' });
    }
    next();
  });
}

module.exports = { authenticate, lightAuthenticate, authenticateAdmin };
