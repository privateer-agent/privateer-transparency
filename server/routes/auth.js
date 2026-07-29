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

const express = require('express');
const mongoose = require('mongoose');
const logger = require('../utils/logger');
const router = express.Router();
const { base58Decode } = require('../utils/base58');
const {
  parseWalletIdentity,
  verifyWalletSignature,
  isSupportedNamespace,
  InvalidWalletIdentityError,
} = require('../services/walletVerifiers');
const User = require('../models/userModel');
const UserAuthMethod = require('../models/userAuthMethodModel');
const UserSession = require('../models/userSessionModel');
const RefreshToken = require('../models/refreshTokenModel');
const EmailService = require('../services/emailService');
const tokenService = require('../services/tokenService');
const analyticsService = require('../services/analyticsService');
const redis = require('../services/redisClient');
const relayHub = require('../services/relayHub');
const { signalRevokedTerminals, signalAllTerminals } = require('../services/sessionRevocation');
const { authenticate } = require('../middleware/auth');
const { sessionDeviceMeta } = require('../utils/sessionDeviceMeta');
const { loginRateLimiter, registerRateLimiter, nonceLimiter, walletVerifyLimiter, resendVerificationLimiter, resetLimit, deviceApproveLimiter, sessionSpawnLimiter } = require('../middleware/rateLimiter');

// Max concurrent live child (per-terminal) sessions a single machine login may
// spawn. Bounds credential amplification: even with a leaked credential set, a
// refresh token can't be turned into an unbounded fleet of billable sessions.
const MAX_CHILD_SESSIONS_PER_FAMILY = Number(process.env.MAX_CHILD_SESSIONS_PER_FAMILY) || 16;
// How long a terminal child may be offline before GET /auth/sessions prunes it.
// Must sit comfortably above the relay's 60s presence TTL + 3s auto-reconnect so
// a transient disconnect (lid close, wifi blip) is never mistaken for a close.
const TERMINAL_PRUNE_GRACE_MS = Number(process.env.TERMINAL_PRUNE_GRACE_MS) || 3 * 60 * 1000;
const { validateEmail, validatePassword } = require('../services/validation');
const Sentry = require('@sentry/node');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sanitizeUser(user) {
  return {
    id: user._id,
    email: user.email,
    profileImage: user.profileImage,
    solanaPublicKey: user.solanaPublicKey || null,
    // Chain-scoped identity, so the UI can label the account with the chain it
    // actually belongs to. Falls back to the legacy field for accounts created
    // before multi-chain sign-in — without it an EVM user reads as having no
    // wallet at all, since solanaPublicKey is null for them.
    walletAddress: user.walletAddress || user.solanaPublicKey || null,
    walletChain: user.walletChain || (user.solanaPublicKey ? 'solana' : null),
    kekSource: user.kekSource || null,
    outboxPublicKey: user.outboxPublicKey || null,
  };
}

function buildVaultPayload(user) {
  if (!user.wrappedMasterKey) return { vault: null };
  return {
    vault: {
      wrappedMasterKey: user.wrappedMasterKey,
      kekSource: user.kekSource,
      kdfSalt: user.kdfSalt || null,
      kdfParams: user.kdfParams || null,
      // Which chain to re-derive the KEK with — the client picks both the
      // wallet provider and the vault message from this. Absent on
      // pre-multi-chain accounts, where falling back to Solana is correct by
      // construction. (kekMessageVersion is deliberately NOT sent: the message
      // follows from the chain, and a second source of truth for the same fact
      // is how the two drift apart.)
      walletChain: user.walletChain || (user.solanaPublicKey ? 'solana' : null),
    },
  };
}

// Argon2id parameter floor. Aligned with OWASP password-storage guidance:
// m >= 64 MiB, t >= 3, p >= 1. Reject anything weaker so a malicious or
// outdated client can't downgrade a new vault's offline-brute-force cost.
const MIN_ARGON2ID_M = 65536;   // 64 MiB
const MIN_ARGON2ID_T = 3;
const MIN_ARGON2ID_P = 1;

function validateKdfParams(params) {
  if (!params || typeof params !== 'object') return false;
  if (params.algorithm !== 'argon2id') return false;
  if (!Number.isInteger(params.m) || params.m < MIN_ARGON2ID_M || params.m > 1048576) return false;
  if (!Number.isInteger(params.t) || params.t < MIN_ARGON2ID_T || params.t > 10) return false;
  if (!Number.isInteger(params.p) || params.p < MIN_ARGON2ID_P || params.p > 8) return false;
  return true;
}

function validateBase64(value, expectedBytes = null) {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    const buf = Buffer.from(value, 'base64');
    if (expectedBytes !== null && buf.length !== expectedBytes) return false;
    return buf.length > 0;
  } catch {
    return false;
  }
}

// Canonical wallet sign-in message format. Mirrors what walletAuthService
// constructs on the client. The exact line set is part of the auth protocol:
// any signed message that doesn't match this shape (or whose Wallet/Nonce
// values disagree with the request) is rejected, so a signature obtained in a
// different context (a different domain, a different app, no Wallet: line)
// cannot be replayed to authenticate here. The Wallet: line carries the pubkey
// as base58 (current clients, the form users recognize) or 64-char hex (legacy
// clients); both are normalized to lowercase hex before the binding check.
const CANONICAL_BRAND_NAME = 'Privateer';
const CANONICAL_BRAND_DOMAIN = 'privateer.pro';
// Issued: must be within NONCE_TTL_SECS of "now" to bound replay if the
// nonce TTL is ever extended without the binding tightening up.
const MAX_AUTH_MESSAGE_SKEW_SECS = 10 * 60;

function parseCanonicalAuthMessage(text) {
  if (typeof text !== 'string') return null;
  const lines = text.split('\n');

  // Two shapes, distinguished by an optional `Chain:` line in position 3:
  //
  //   5 lines, no Chain  → Solana. The original format, pinned forever so
  //                        existing accounts and older clients keep verifying.
  //   6 lines with Chain → every other namespace, explicitly scoped.
  //
  // A Solana signature therefore can't be replayed as an eip155 one (or vice
  // versa): the bytes the wallet signed differ.
  const hasChainLine = lines.length === 6;
  if (lines.length !== 5 && !hasChainLine) return null;

  const m0 = lines[0].match(/^Sign in to (.+)$/);
  const m1 = lines[1].match(/^Domain: (.+)$/);
  const m2 = lines[2].match(/^Wallet: (0x[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[1-9A-HJ-NP-Za-km-z]{32,44})$/);
  const mc = hasChainLine ? lines[3].match(/^Chain: ([a-z0-9]{3,16})$/) : null;
  const m3 = lines[hasChainLine ? 4 : 3].match(/^Nonce: ([0-9a-fA-F]+)$/);
  const m4 = lines[hasChainLine ? 5 : 4].match(/^Issued: (.+)$/);
  if (!m0 || !m1 || !m2 || !m3 || !m4) return null;
  if (hasChainLine && !mc) return null;

  // Normalize the Wallet: token to lowercase unprefixed hex, matching
  // walletVerifiers' `identity.hex`, so the binding check below is one
  // comparison regardless of chain. EVM addresses arrive 0x-prefixed and
  // checksummed; Solana arrives base58 (current clients) or hex (legacy ones).
  const walletToken = m2[1];
  let walletHex;
  if (/^0x[0-9a-fA-F]{40}$/.test(walletToken)) {
    walletHex = walletToken.slice(2).toLowerCase();
  } else if (/^[0-9a-fA-F]{64}$/.test(walletToken)) {
    walletHex = walletToken.toLowerCase();
  } else {
    try {
      walletHex = base58Decode(walletToken).toString('hex');
    } catch {
      return null;
    }
    if (walletHex.length !== 64) return null;
  }

  const issuedMs = Date.parse(m4[1]);
  if (Number.isNaN(issuedMs)) return null;

  return {
    name:   m0[1],
    domain: m1[1],
    wallet: walletHex,
    chain:  hasChainLine ? mc[1] : 'solana',
    nonce:  m3[1],
    issuedMs,
  };
}

// ---------------------------------------------------------------------------
// Email / Password — Registration
// ---------------------------------------------------------------------------

router.post('/register', registerRateLimiter, async (req, res) => {
  try {
    const { email, password, wrappedMasterKey, kdfSalt, kdfParams } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: req.t('errors.emailPasswordRequired') });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: req.t('errors.invalidEmail') });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ message: req.t('errors.passwordTooShort') });
    }

    if (!validateBase64(wrappedMasterKey)) {
      return res.status(400).json({ message: 'wrappedMasterKey is required (base64)' });
    }
    if (!validateBase64(kdfSalt, 16)) {
      return res.status(400).json({ message: 'kdfSalt is required (base64-encoded 16 bytes)' });
    }
    if (!validateKdfParams(kdfParams)) {
      return res.status(400).json({ message: 'kdfParams must be { algorithm: "argon2id", m, t, p }' });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ message: req.t('errors.accountExists') });
    }

    const verificationToken = EmailService.generateVerificationToken();

    // Create the User and its auth-method row atomically. Without a transaction
    // a failure on UserAuthMethod.create (e.g. a stale auth-method row left over
    // from a manually-deleted User) leaves a dangling orphan User behind.
    const session = await mongoose.startSession();
    let user;
    try {
      await session.withTransaction(async () => {
        const [created] = await User.create([{
          email: email.toLowerCase(),
          password,
          isEmailVerified: false,
          emailVerificationToken: verificationToken,
          emailVerificationExpires: Date.now() + 24 * 60 * 60 * 1000,
          wrappedMasterKey,
          kekSource: 'password',
          kdfSalt,
          kdfParams,
          emailLocale: req.language || 'en',
        }], { session });
        user = created;

        await UserAuthMethod.create(
          [{ userId: user._id, method: 'email', externalId: user.email }],
          { session }
        );
      });
    } finally {
      session.endSession();
    }

    analyticsService.track('signup', {
      method: req.body.fromGuest === true ? 'guest_convert' : 'email'
    });

    try {
      await EmailService.sendVerificationEmail(user, req.language);
    } catch (emailError) {
      Sentry.captureException(emailError, { level: 'warning', tags: { op: 'auth_send_verification_email' } });
      logger.error('Failed to send verification email:', emailError);
    }

    res.status(201).json({
      message: 'Registration successful. Please check your email to verify your account.',
      requiresVerification: true,
      email: user.email
    });
  } catch (error) {
    logger.error('Registration error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ message: req.t('errors.accountExists') });
    }
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(e => e.message);
      return res.status(400).json({ message: errors.join(', ') });
    }
    Sentry.captureException(error, { tags: { op: 'auth_register' } });
    res.status(500).json({ message: 'Error creating account' });
  }
});

// ---------------------------------------------------------------------------
// Email / Password — Login
// ---------------------------------------------------------------------------

router.post('/login', loginRateLimiter, async (req, res) => {
  try {
    const { email, password, recover } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: req.t('errors.emailPasswordRequired') });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.password) {
      return res.status(401).json({ message: req.t('errors.invalidCredentials') });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: req.t('errors.invalidCredentials') });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: req.t('errors.verifyEmailFirst'),
        requiresVerification: true,
        email: user.email
      });
    }

    if (user.accountStatus === 'grace_period') {
      // Recovery path for the 30-day deletion grace period. delete-request
      // revoked every session AND refresh token, so the standalone
      // /account/cancel-deletion (which needs a still-valid refresh token) can
      // never succeed from a client that already tore down its tokens. A fresh
      // password login IS a full re-auth, so honor it as the recovery gesture:
      // the client re-issues the login with `recover: true` after the user
      // confirms the "account scheduled for deletion — recover?" prompt.
      // Without the flag we still surface the prompt rather than silently
      // reviving an account the user may have meant to leave deleting.
      if (recover !== true) {
        return res.status(403).json({
          message: req.t('errors.accountScheduledDeletion'),
          code: 'ACCOUNT_PENDING_DELETION'
        });
      }
      user.accountStatus = 'active';
      user.deletionRequestedAt = undefined;
      user.hardDeleteAt = undefined;
      await user.save();
    }

    await UserAuthMethod.findOneAndUpdate(
      { userId: user._id, method: 'email' },
      { lastUsedAt: new Date() },
      { upsert: true, setDefaultsOnInsert: true, new: true }
    ).catch(() => null);

    await resetLimit(`login:${req.ip}:${email.toLowerCase()}`);

    // Tag the session with the surface that signed in (mobile / web / desktop)
    // so the linked-device list can name it. Cosmetic only — see
    // utils/sessionDeviceMeta.
    const { accessToken, refreshToken } = await tokenService.issueTokenPair(
      user._id,
      'email',
      sessionDeviceMeta(req),
    );

    res.json({
      accessToken,
      refreshToken,
      user: sanitizeUser(user),
      ...buildVaultPayload(user),
    });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_login' } });
    logger.error('Login error:', error);
    res.status(500).json({ message: 'Error signing in' });
  }
});

// ---------------------------------------------------------------------------
// Token Refresh
// ---------------------------------------------------------------------------

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    const tokens = await tokenService.rotateRefreshToken(refreshToken);
    res.json(tokens);
  } catch (error) {
    if (error.code === 'TOKEN_REUSE') {
      Sentry.captureMessage('refresh_token_reuse_detected', {
        level: 'warning',
        tags: { op: 'auth_refresh_reuse' },
      });
      return res.status(401).json({ message: 'Session invalidated due to token reuse', code: 'TOKEN_REUSE' });
    }
    res.status(401).json({ message: req.t('errors.invalidRefreshToken') });
  }
});

/**
 * POST /auth/session/spawn
 * Mints a NEW, independent CLI session (its own familyId + refresh-token
 * lineage) from a machine login's refresh token, WITHOUT rotating that parent
 * token. Each running terminal calls this once at startup so it rotates its own
 * token in isolation — many terminals on one machine no longer share (and fight
 * over) a single rotating refresh token. Children surface in GET /auth/sessions
 * and are individually revocable; revoking the parent device cascades to them.
 *
 * Security (hardened): this is NOT unauthenticated. The caller must present BOTH
 *   (a) a valid (non-revoked, non-expired) parent refresh token in the body, AND
 *   (b) a real, RS256-signed access token for the SAME account as a Bearer header
 *       (allowed to be expired — the refresh token is the liveness proof; the
 *       signed access JWT is a possession proof that raises the bar above
 *       "refresh token alone").
 * Plus: per-IP rate limit and a hard per-family cap on concurrent live children
 * so a leaked credential set can't be amplified into an unbounded billable fleet.
 */
router.post('/session/spawn', sessionSpawnLimiter, async (req, res) => {
  try {
    const { refreshToken, deviceLabel } = req.body || {};
    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    // Possession proof: a real signed access token (expiry not enforced here).
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    if (!bearer) {
      return res.status(401).json({ message: 'Authorization required', code: 'AUTH_REQUIRED' });
    }
    let claims;
    try {
      claims = tokenService.verifyAccessTokenAllowExpired(bearer);
    } catch (_) {
      return res.status(401).json({ message: req.t('errors.invalidToken') || 'Invalid token', code: 'INVALID_TOKEN' });
    }

    const parent = await RefreshToken.findValid(refreshToken);
    if (!parent) {
      return res.status(401).json({ message: req.t('errors.invalidRefreshToken'), code: 'INVALID_TOKEN' });
    }
    // The access JWT and the refresh token must belong to the same account.
    if (!claims?.sub || parent.userId.toString() !== claims.sub.toString()) {
      return res.status(403).json({ message: 'Token mismatch', code: 'TOKEN_MISMATCH' });
    }

    // A child can't itself parent more children — root the lineage at the device.
    const parentFamilyId = parent.parentFamilyId || parent.familyId || parent.jti;

    // Anti-amplification: cap concurrent live children per machine login. Count
    // DISTINCT child familyIds (a child rotating its access token creates extra
    // UserSession rows under the same familyId — those must not inflate the count).
    const liveChildFamilies = await UserSession.distinct('familyId', {
      userId: parent.userId,
      parentFamilyId,
      revokedAt: null,
      expiresAt: { $gt: new Date() },
    });
    if (liveChildFamilies.length >= MAX_CHILD_SESSIONS_PER_FAMILY) {
      return res.status(429).json({
        message: 'Too many active terminals for this device. Sign one out and try again.',
        code: 'CHILD_SESSION_CAP',
      });
    }

    const label = typeof deviceLabel === 'string' && deviceLabel.trim()
      ? deviceLabel.trim().slice(0, 100)
      : (parent.deviceLabel || undefined);

    const { accessToken, refreshToken: childRefresh } = await tokenService.issueTokenPair(
      parent.userId,
      parent.authMethod,
      { client: 'cli', deviceLabel: label, parentFamilyId }
    );

    // Sliding renewal: the parent token is validated here but never rotated, so
    // its expiry would otherwise be frozen at login time and an actively-used
    // machine login would still die REFRESH_TTL_DAYS after /login. Push it a
    // full TTL window out from now instead; idle machines still age out.
    // Best-effort — the spawn already succeeded on a token valid right now.
    try {
      await tokenService.slideRefreshTokenExpiry(parent);
    } catch (renewErr) {
      logger.warn('Session spawn: sliding renewal failed (non-fatal):', renewErr);
    }

    res.json({ accessToken, refreshToken: childRefresh });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_session_spawn' } });
    logger.error('Session spawn error:', error);
    res.status(500).json({ message: 'Error creating session' });
  }
});

/**
 * DELETE /auth/session/current
 * Revokes the CALLER's own session lineage (the familyId behind the presented
 * access token) — access tokens and refresh token, cascading to any children.
 * This is the counterpart to /session/spawn: a terminal calls it on exit so its
 * per-terminal child session disappears from Linked Devices immediately instead
 * of lingering until the access-token rows expire. Self-scoped by design — it
 * can only ever revoke the session that authenticates the request.
 */
router.delete('/session/current', authenticate, async (req, res) => {
  try {
    const own = await UserSession.findOne({ userId: req.user._id, jti: req.jti }).lean();
    if (own?.familyId) {
      await tokenService.revokeSessionFamily(req.user._id, own.familyId);
    } else {
      // Legacy session without a familyId — revoke just this access jti.
      await UserSession.updateOne(
        { userId: req.user._id, jti: req.jti, revokedAt: null },
        { $set: { revokedAt: new Date() } }
      );
    }
    res.json({ message: 'Session revoked' });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_session_self_revoke' } });
    logger.error('Self session revoke error:', error);
    res.status(500).json({ message: 'Error revoking session' });
  }
});

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

router.post('/logout', authenticate, async (req, res) => {
  try {
    await tokenService.revokeAllUserSessions(req.user._id);
    // Logout revokes every session for the account (all devices + terminals), so
    // sign out any live terminals promptly too instead of leaving them to die on
    // the ≤25s heartbeat. Best-effort (see DELETE /sessions/:id).
    void signalAllTerminals(req.user._id).catch((err) => {
      logger.warn('Relay session_revoked broadcast (logout) failed:', err?.message || err);
    });
    res.json({ message: req.t('success.signedOut') });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_logout' } });
    logger.error('Logout error:', error);
    res.status(500).json({ message: 'Error signing out' });
  }
});

// ---------------------------------------------------------------------------
// Session registry (linked devices)
// ---------------------------------------------------------------------------

/**
 * GET /auth/sessions
 * Lists the user's active sessions, one row per device (grouped by familyId;
 * legacy rows without one are listed individually). Powers the app's
 * "Linked terminals" screen and is the device directory future remote-access
 * will pick from. The caller's own session is flagged `current`.
 */
router.get('/sessions', authenticate, async (req, res) => {
  try {
    const now = new Date();
    const rows = await UserSession.find({
      userId: req.user._id,
      revokedAt: null,
      expiresAt: { $gt: now },
      // Per-terminal child sessions ARE included now (security: they must be
      // visible and individually revocable, not invisible long-lived credentials).
      // They carry parentFamilyId so the app can nest them under their device; a
      // child whose access tokens have all expired drops off here automatically,
      // and revoking the parent cascades to any it can't see.
    }).sort({ createdAt: -1 }).lean();

    // Collapse a device's many access-token rows into a single entry.
    const byDevice = new Map();
    let currentKey = null;
    for (const row of rows) {
      const key = row.familyId || row.jti;
      if (row.jti === req.jti) currentKey = key;
      const existing = byDevice.get(key);
      if (!existing) {
        byDevice.set(key, {
          id: key,
          client: row.client || 'app',
          deviceLabel: row.deviceLabel || null,
          authMethod: row.authMethod,
          // Per-terminal child session → the parent device's familyId it belongs
          // to (null for top-level devices). Lets the app nest terminals under
          // their machine login; each is still independently revocable by `id`.
          parentId: row.parentFamilyId || null,
          isChild: !!row.parentFamilyId,
          createdAt: row.createdAt,   // first seen (oldest, since we overwrite downward)
          lastSeenAt: row.createdAt,  // most recent (first row wins — sorted desc)
        });
      } else {
        // rows are newest-first, so later iterations are older → push createdAt back
        existing.createdAt = row.createdAt;
      }
    }

    const ids = Array.from(byDevice.keys());
    // Which of these devices currently has a live agent on the relay (so the
    // app can show "online" + enable remote-access). Ephemeral, Redis-backed.
    // last-seen is the durable companion: it lets us prune terminal children
    // that closed a while ago without racing the relay's 3s auto-reconnect.
    const [online, lastSeen] = await Promise.all([
      relayHub.onlineMap(ids),
      relayHub.lastSeenMap(ids),
    ]);

    // Auto-prune dead terminal children. A per-terminal child that used
    // remote-access (has a last-seen), is offline now, and hasn't been seen for
    // longer than the grace window is a closed terminal — delete its lineage so
    // the list reflects reality. Constraints that keep this safe:
    //   • children only (never a device/parent) and never the caller's own session
    //   • DELETE via tokenService.deleteSessionFamily, never revoke — a revoked
    //     token replayed by a still-alive agent would trip reuse-detection and
    //     revoke the WHOLE account; a deleted one just makes it re-spawn a child.
    //   • requires a last-seen: a child that never came online (remote-access off)
    //     has no liveness signal and is left alone (it ages out via token TTL).
    //   • grace ≫ the 60s presence TTL + 3s reconnect, so blips never prune.
    const nowMs = Date.now();
    const prune = Array.from(byDevice.values()).filter((s) =>
      s.isChild &&
      s.client === 'cli' &&
      s.id !== currentKey &&
      !online[s.id] &&
      lastSeen[s.id] != null &&
      nowMs - lastSeen[s.id] > TERMINAL_PRUNE_GRACE_MS,
    );
    for (const s of prune) {
      byDevice.delete(s.id);
      // Best-effort; the list already reflects the prune, and a stale row just
      // reappears on the next poll if the delete somehow failed.
      tokenService.deleteSessionFamily(req.user._id, s.id)
        .then(() => relayHub.clearLastSeen(s.id))
        .catch((err) => logger.warn('Terminal auto-prune failed (non-fatal):', err?.message || err));
    }

    const sessions = Array.from(byDevice.values()).map((s) => ({
      ...s,
      current: s.id === currentKey,
      online: !!online[s.id],
    }));

    res.json({ sessions });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_sessions_list' } });
    logger.error('Sessions list error:', error);
    res.status(500).json({ message: 'Error loading sessions' });
  }
});

/**
 * DELETE /auth/sessions/:id
 * Revokes one device lineage (id = familyId). Scoped to the caller's userId so
 * no one can revoke another user's session. Falls back to a single jti for
 * legacy rows that predate familyId.
 */
router.delete('/sessions/:id', authenticate, async (req, res) => {
  try {
    const id = req.params.id;
    const revoked = await tokenService.revokeSessionFamily(req.user._id, id);

    if (revoked === 0) {
      // Legacy session without a familyId — revoke the single access jti.
      const result = await UserSession.updateOne(
        { userId: req.user._id, jti: id, revokedAt: null },
        { $set: { revokedAt: new Date() } }
      );
      if (!result.matchedCount) {
        return res.status(404).json({ message: 'Session not found' });
      }
    }

    // Promptly sign out any live terminals on this lineage. The relay heartbeat
    // already terminates a revoked socket within ≤25s (relaySessionLive), but
    // that's a silent transport drop; pushing a `session_revoked` frame lets the
    // agent tear down cleanly right now — clear its local credentials, drop
    // remote access, and tell the user — instead of lingering with a dead token.
    // Best-effort only: never let a relay hiccup fail the revoke the DB already did.
    void signalRevokedTerminals(req.user._id, id).catch((err) => {
      logger.warn('Relay session_revoked push failed:', err?.message || err);
    });

    res.json({ message: 'Session revoked' });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_sessions_revoke' } });
    logger.error('Session revoke error:', error);
    res.status(500).json({ message: 'Error revoking session' });
  }
});

/**
 * PATCH /auth/sessions/:id
 * Renames one device lineage (id = familyId) — sets its human-friendly
 * deviceLabel. Scoped to the caller's userId. Lets a user tell apart multiple
 * terminals running on the same machine. Falls back to a single jti for legacy
 * rows that predate familyId.
 */
router.patch('/sessions/:id', authenticate, async (req, res) => {
  try {
    const id = req.params.id;
    const raw = req.body?.deviceLabel;
    if (typeof raw !== 'string' || !raw.trim()) {
      return res.status(400).json({ message: 'deviceLabel is required' });
    }
    // Cap matches the device-flow label limit (deviceAuth.js).
    const deviceLabel = raw.trim().slice(0, 100);

    const renamed = await tokenService.renameSessionFamily(req.user._id, id, deviceLabel);

    if (renamed === 0) {
      // Legacy session without a familyId — rename the single access jti.
      const result = await UserSession.updateOne(
        { userId: req.user._id, jti: id, revokedAt: null },
        { $set: { deviceLabel } }
      );
      if (!result.matchedCount) {
        return res.status(404).json({ message: 'Session not found' });
      }
    }

    res.json({ message: 'Session renamed', deviceLabel });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_sessions_rename' } });
    logger.error('Session rename error:', error);
    res.status(500).json({ message: 'Error renaming session' });
  }
});

// ---------------------------------------------------------------------------
// Email Verification
// ---------------------------------------------------------------------------

router.post('/verify-email', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Look up by token alone (ignore expiry) so this route is idempotent: a
    // repeat verify — Safari refresh, re-tapping the email link, or a client
    // double-fire on remount — lands on the already-verified success path below
    // instead of a false "Invalid or expired". The token is kept after a
    // successful verify (rather than cleared) precisely so the repeat resolves.
    const user = await User.findOne({ emailVerificationToken: token });
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    // Duplicate request on an already-consumed token → idempotent success.
    if (user.isEmailVerified) {
      return res.json({ message: 'Email verified successfully' });
    }

    // First-time verification still honors the 24h expiry window.
    const expiresAt = user.emailVerificationExpires ? user.emailVerificationExpires.getTime() : 0;
    if (expiresAt <= Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired verification token' });
    }

    user.isEmailVerified = true;
    user.emailVerificationExpires = undefined;
    // Keep emailVerificationToken so repeat requests resolve to the idempotent
    // success path above. Once isEmailVerified is true the token grants nothing;
    // resend-verification overwrites it with a fresh value when needed.
    await user.save();

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_verify_email' } });
    logger.error('Email verification error:', error);
    res.status(500).json({ message: 'Error verifying email' });
  }
});

router.post('/resend-verification', resendVerificationLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email?.toLowerCase() });

    if (!user || user.isEmailVerified) {
      return res.json({ message: 'If that email is registered and unverified, a link has been sent.' });
    }

    const verificationToken = EmailService.generateVerificationToken();
    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    await EmailService.sendVerificationEmail(user, req.language);

    res.json({ message: 'If that email is registered and unverified, a link has been sent.' });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_resend_verification' } });
    logger.error('Error resending verification:', error);
    res.status(500).json({ message: 'Error sending verification email' });
  }
});

// ---------------------------------------------------------------------------
// Password Change (authenticated re-wrap of master key)
// ---------------------------------------------------------------------------

/**
 * POST /auth/change-password
 *
 * Atomically updates the account password and the wrapped master key. The
 * client unwraps the master key with the old password's KEK locally, derives
 * a new KEK from the new password (with a fresh salt), re-wraps the master
 * key, and submits both halves here. The server never sees either KEK.
 *
 * Body: {
 *   currentPassword: string,
 *   newPassword:     string,
 *   wrappedMasterKey: string (base64),
 *   kdfSalt:         string (base64, 16 bytes),
 *   kdfParams:       { algorithm: 'argon2id', m, t, p }
 * }
 */
router.post('/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword, wrappedMasterKey, kdfSalt, kdfParams } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'currentPassword and newPassword are required' });
    }
    if (!validatePassword(newPassword)) {
      return res.status(400).json({ message: 'New password must be at least 8 characters' });
    }
    if (!validateBase64(wrappedMasterKey)) {
      return res.status(400).json({ message: 'wrappedMasterKey is required (base64)' });
    }
    if (!validateBase64(kdfSalt, 16)) {
      return res.status(400).json({ message: 'kdfSalt is required (base64-encoded 16 bytes)' });
    }
    if (!validateKdfParams(kdfParams)) {
      return res.status(400).json({ message: 'kdfParams must be { algorithm: "argon2id", m, t, p }' });
    }

    const user = await User.findById(req.user._id);
    if (!user || !user.password) {
      return res.status(400).json({ message: 'Password change is not available for this account' });
    }
    if (user.kekSource !== 'password') {
      return res.status(400).json({ message: 'Password change is only available for password-based accounts' });
    }

    const ok = await user.comparePassword(currentPassword);
    if (!ok) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    user.password = newPassword;
    user.wrappedMasterKey = wrappedMasterKey;
    user.kdfSalt = kdfSalt;
    user.kdfParams = kdfParams;
    await user.save();

    await tokenService.revokeAllUserSessions(user._id);
    // Password change revoked every session (a re-wrap under the new KEK); sign out
    // all live terminals promptly too. Best-effort (see DELETE handler).
    void signalAllTerminals(user._id).catch((err) => {
      logger.warn('Relay session_revoked broadcast (password) failed:', err?.message || err);
    });

    res.json({ message: 'Password changed. Please sign in again.' });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_change_password' } });
    logger.error('Change password error:', error);
    res.status(500).json({ message: 'Error changing password' });
  }
});

// ---------------------------------------------------------------------------
// Current User
// ---------------------------------------------------------------------------

router.get('/me', authenticate, async (req, res) => {
  res.json({ user: sanitizeUser(req.user), ...buildVaultPayload(req.user) });
});

// ---------------------------------------------------------------------------
// Account Deletion
// ---------------------------------------------------------------------------

router.post('/account/delete-request', authenticate, async (req, res) => {
  try {
    const user = req.user;
    user.accountStatus = 'grace_period';
    user.deletionRequestedAt = new Date();
    user.hardDeleteAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await user.save();

    await tokenService.revokeAllUserSessions(user._id);
    // Every session is gone — promptly sign out all live terminals too, rather
    // than let them dead-end on their next call. Best-effort (see DELETE handler).
    void signalAllTerminals(user._id).catch((err) => {
      logger.warn('Relay session_revoked broadcast (delete) failed:', err?.message || err);
    });

    if (user.email) {
      try {
        await EmailService.sendAccountDeletionConfirmation(user, req.language);
      } catch (_) { /* non-fatal */ }
    }

    res.json({
      message: 'Your account is scheduled for deletion in 30 days. You can recover it by signing in before then.',
      hardDeleteAt: user.hardDeleteAt
    });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_account_delete_request' } });
    logger.error('Account deletion error:', error);
    res.status(500).json({ message: 'Error processing deletion request' });
  }
});

router.post('/account/cancel-deletion', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token required to recover account' });
    }

    const tokenDoc = await require('../models/refreshTokenModel').findValid(refreshToken);
    if (!tokenDoc) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    const user = await User.findById(tokenDoc.userId);
    if (!user || user.accountStatus !== 'grace_period') {
      return res.status(400).json({ message: 'Account is not pending deletion' });
    }

    user.accountStatus = 'active';
    user.deletionRequestedAt = undefined;
    user.hardDeleteAt = undefined;
    await user.save();

    const { accessToken, refreshToken: newRefreshToken } = await tokenService.issueTokenPair(
      user._id,
      tokenDoc.authMethod,
      sessionDeviceMeta(req),
    );

    res.json({ message: 'Account recovery successful', accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'auth_account_cancel_deletion' } });
    logger.error('Cancel deletion error:', error);
    res.status(500).json({ message: 'Error recovering account' });
  }
});

// ---------------------------------------------------------------------------
// Solana Wallet Auth
// ---------------------------------------------------------------------------

const NONCE_TTL_SECS = 5 * 60;

router.post('/wallet/nonce', nonceLimiter, async (req, res) => {
  try {
    const crypto = require('crypto');
    const nonce   = crypto.randomBytes(32).toString('hex');
    const nonceId = crypto.randomBytes(16).toString('hex');

    await redis.set(`nonce:${nonceId}`, nonce, 'EX', NONCE_TTL_SECS);

    res.json({ nonce, nonceId });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'wallet_nonce' } });
    logger.error('Wallet nonce error:', error);
    res.status(500).json({ message: 'Error generating nonce' });
  }
});

router.post('/wallet/verify', walletVerifyLimiter, async (req, res) => {
  try {
    const { walletPublicKey, signature, signedMessage, nonceId } = req.body;
    // Absent `chain` means a client that predates multi-chain sign-in, which
    // could only ever have been Solana.
    const chain = req.body.chain || 'solana';

    if (!walletPublicKey || !signature || !signedMessage || !nonceId) {
      return res.status(400).json({ message: 'walletPublicKey, signature, signedMessage, and nonceId are required' });
    }

    if (!isSupportedNamespace(chain)) {
      return res.status(400).json({ message: `Unsupported wallet chain: ${chain}`, code: 'UNSUPPORTED_CHAIN' });
    }

    const storedNonce = await redis.getdel(`nonce:${nonceId}`);

    if (!storedNonce) {
      return res.status(401).json({ message: 'Nonce expired or not found. Please request a new one.' });
    }

    // Identity parsing and signature verification are per-chain and live in
    // services/walletVerifiers. This route stays chain-independent: nonce,
    // message binding, account lookup, session issuance.
    let identity;
    try {
      identity = parseWalletIdentity(chain, walletPublicKey);
    } catch (err) {
      if (err instanceof InvalidWalletIdentityError) {
        return res.status(400).json({ message: err.message });
      }
      throw err;
    }

    const msgBuf = Buffer.from(signedMessage, 'hex');
    const parsed = parseCanonicalAuthMessage(msgBuf.toString('utf8'));
    if (!parsed) {
      return res.status(401).json({ message: 'Signed message format is invalid' });
    }

    // Lowercase hex is the form the signature-binding check and the vault KEK
    // message use (neither is displayed). The stored identity is the canonical
    // address instead — base58 on Solana, EIP-55 on EVM — because that's what
    // users see in their wallet and explorers, and what any on-chain or billing
    // surface needs.
    const pubKeyHex = identity.hex;
    const canonicalAddress = identity.canonical;
    if (
      parsed.name !== CANONICAL_BRAND_NAME ||
      parsed.domain !== CANONICAL_BRAND_DOMAIN ||
      parsed.wallet !== pubKeyHex.toLowerCase() ||
      // The chain the message was scoped to must be the chain we're verifying
      // under, or a signature could be lifted from one namespace to another.
      parsed.chain !== chain ||
      parsed.nonce !== storedNonce ||
      Math.abs(Date.now() - parsed.issuedMs) > MAX_AUTH_MESSAGE_SKEW_SECS * 1000
    ) {
      return res.status(401).json({ message: 'Signed message does not match expected context' });
    }

    const sigBuf = Buffer.from(signature, 'hex');

    const valid = verifyWalletSignature({
      namespace: identity.namespace,
      identity,
      message: msgBuf,
      signature: sigBuf,
    });

    if (!valid) {
      return res.status(401).json({ message: 'Invalid signature' });
    }

    // Lookup is chain-scoped. Solana additionally falls back to (and keeps
    // writing) the legacy `solanaPublicKey` field: every wallet account created
    // before multi-chain sign-in is keyed on it alone, and dual-writing means a
    // rollback to the previous server can't strand accounts made in between.
    let user = chain === 'solana'
      ? await User.findOne({ $or: [
          { solanaPublicKey: canonicalAddress },
          { walletChain: 'solana', walletAddress: canonicalAddress },
        ] })
      : await User.findOne({ walletChain: chain, walletAddress: canonicalAddress });

    if (!user) {
      user = await User.create({
        ...(chain === 'solana' ? { solanaPublicKey: canonicalAddress } : {}),
        walletChain: chain,
        walletAddress: canonicalAddress,
        username: `wallet_${canonicalAddress.slice(0, 8)}`,
        isEmailVerified: false,
        accountStatus: 'active'
      });
      analyticsService.track('signup', { method: 'wallet', chain });
    } else if (!user.walletChain) {
      // Backfill on touch: a pre-multi-chain account gets its chain-scoped
      // identity the first time it signs in, so no migration script is needed.
      user.walletChain = 'solana';
      user.walletAddress = user.solanaPublicKey;
      await user.save();
    }

    if (user.accountStatus === 'grace_period') {
      // Recovery path for the 30-day deletion grace period (mirrors /auth/login):
      // a fresh, valid wallet signature IS a full re-auth, so honor `recover:
      // true` — sent by the client after the user confirms the "scheduled for
      // deletion — recover?" prompt — as the recovery gesture. Without the flag
      // we surface the prompt rather than silently reviving the account. This is
      // the only workable recovery: delete-request revoked every session and
      // refresh token, so the token-based /account/cancel-deletion can't run.
      if (req.body.recover !== true) {
        return res.status(403).json({
          message: 'This account is scheduled for deletion. Recover it?',
          code: 'ACCOUNT_PENDING_DELETION'
        });
      }
      user.accountStatus = 'active';
      user.deletionRequestedAt = undefined;
      user.hardDeleteAt = undefined;
      await user.save();
    }

    await UserAuthMethod.findOneAndUpdate(
      { userId: user._id, method: 'wallet' },
      // Solana keeps the bare address it has always stored; other chains are
      // namespace-prefixed so the (method, externalId) unique index can't
      // collide across chains and the row says what it is.
      { externalId: chain === 'solana' ? canonicalAddress : `${chain}:${canonicalAddress}`, lastUsedAt: new Date() },
      { upsert: true }
    );

    const { accessToken, refreshToken } = await tokenService.issueTokenPair(
      user._id,
      'wallet',
      sessionDeviceMeta(req),
    );

    res.json({
      accessToken,
      refreshToken,
      user: sanitizeUser(user),
      ...buildVaultPayload(user),
      needsMasterKeySetup: !user.wrappedMasterKey,
    });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'wallet_verify' } });
    logger.error('Wallet verify error:', error);
    res.status(500).json({ message: 'Wallet sign-in failed. Please try again.' });
  }
});

/**
 * POST /auth/wallet/master-key
 *
 * One-time setup of the wrapped master key for a wallet account. Called
 * immediately after the first /wallet/verify when the response indicated
 * needsMasterKeySetup. Idempotent: re-submitting the same wrappedMasterKey
 * returns 200; submitting a different one returns 409.
 *
 * Body: { wrappedMasterKey: string (base64) }
 */
router.post('/wallet/master-key', authenticate, async (req, res) => {
  try {
    const { wrappedMasterKey } = req.body;

    if (!validateBase64(wrappedMasterKey)) {
      return res.status(400).json({ message: 'wrappedMasterKey is required (base64)' });
    }

    if (req.authMethod !== 'wallet') {
      return res.status(403).json({ message: 'Only wallet sessions can set a wallet master key' });
    }

    // Atomic conditional update: only set when no master key is already
    // recorded. Two concurrent setup calls can no longer both win the race
    // (the second's $in match fails and we either confirm idempotency or
    // reject as a conflict).
    //
    // The vault-message version follows the account's chain: Solana enrolled at
    // v2 before chains existed and stays there forever, everything else at v3.
    // Derived from the stored chain rather than anything the client sends —
    // a client that could choose its own version could pin a new account to a
    // message its wallet can't reproduce.
    const walletChain = req.user.walletChain || 'solana';
    const kekMessageVersion = walletChain === 'solana' ? 2 : 3;

    const updated = await User.findOneAndUpdate(
      { _id: req.user._id, $or: [{ wrappedMasterKey: { $in: [null, ''] } }, { wrappedMasterKey: { $exists: false } }] },
      { $set: { wrappedMasterKey, kekSource: 'wallet', kekMessageVersion } },
      { new: true }
    );

    if (updated) {
      return res.json({ success: true });
    }

    // No document matched — a key was already set. Idempotent for the same
    // wrapped blob, 409 otherwise.
    const current = await User.findById(req.user._id).select('wrappedMasterKey');
    if (current && current.wrappedMasterKey === wrappedMasterKey) {
      return res.json({ success: true });
    }
    return res.status(409).json({
      message: 'A wrapped master key is already set for this account.',
      code: 'MASTER_KEY_ALREADY_SET'
    });
  } catch (error) {
    Sentry.captureException(error, { tags: { op: 'wallet_master_key_setup' } });
    logger.error('Wallet master-key error:', error);
    res.status(500).json({ message: 'Failed to register master key' });
  }
});

module.exports = router;
