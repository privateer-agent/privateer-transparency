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
 * Pending Reply Store — Redis-backed, opt-in, short-TTL hold for an AI reply
 * whose client vanished mid-stream.
 *
 * WHAT THIS IS (and the honest E2EE posture):
 * Normally the server is a blind SSE proxy for chat: plaintext transits during
 * inference but is NEVER buffered or written to Mongo/S3 (docs/E2EE_ARCHITECTURE.md).
 * This module is the ONE opt-in exception. When a user has explicitly enabled
 * "Finish replies in the cloud" AND the app disconnects before the reply lands
 * (backgrounded then killed, network drop), the server stashes the already-
 * generated plaintext reply here so the app can pick it up on reopen, encrypt it
 * client-side, and persist it. Without this, that reply is simply lost (the model
 * call still ran and was billed — see chatController.streamMessage).
 *
 * Bounds that keep this honest:
 *   - OFF by default; only reached when the request carries holdReplyInCloud.
 *   - Only written when the client actually disconnected (clientGone) — a reply
 *     delivered normally is never buffered.
 *   - EPHEMERAL: Redis only, never Mongo/S3. Auto-expires via TTL (default 1h),
 *     and is deleted the instant the client acks pickup (dropReply).
 *   - Tenant-scoped key `<userId>:<pendingMessageId>` — never id alone — so two
 *     accounts can't collide (mirrors deepResearchJobStore).
 * This does NOT change the on-device model: the durable copy is still the
 * client-encrypted assistant turn. This is a brief plaintext hold, by consent.
 */

const redis = require('./redisClient');
const logger = require('../utils/logger');

// Default 1 hour. Kept deliberately short — this is plaintext at rest in
// Privateer-operated Redis, so the window is the exposure. Overridable per-env.
const PENDING_REPLY_TTL_MS = parseInt(
  process.env.PENDING_REPLY_TTL_MS || String(60 * 60 * 1000),
  10
);

const routeKey = (userId, pendingMessageId) => `${String(userId)}:${pendingMessageId}`;
const replyKey = (userId, pendingMessageId) => `pendingReply:${routeKey(userId, pendingMessageId)}`;

/**
 * Stash a completed (or partial) reply for a disconnected client. `payload`
 * is the minimal set the client needs to reconstruct + encrypt the assistant
 * turn: { status, response, modelUsed, tokensUsed, sources?, webSearchUsed?,
 * truncated?, createdAt }. Best-effort — a Redis failure must not break the
 * (already-finished) request, so we swallow and log.
 */
async function stashReply(userId, pendingMessageId, payload) {
  if (!userId || !pendingMessageId) return false;
  try {
    await redis.set(
      replyKey(userId, pendingMessageId),
      JSON.stringify(payload),
      'PX',
      PENDING_REPLY_TTL_MS
    );
    return true;
  } catch (err) {
    logger.warn('[pendingReplyStore] stash failed:', err.message);
    return false;
  }
}

/**
 * Read a held reply, scoped to its owner. Returns null if absent/expired.
 */
async function getReply(userId, pendingMessageId) {
  if (!userId || !pendingMessageId) return null;
  try {
    const raw = await redis.get(replyKey(userId, pendingMessageId));
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (err) {
    logger.warn('[pendingReplyStore] get failed:', err.message);
    return null;
  }
}

/**
 * Delete a held reply (client ack after it has encrypted + persisted the turn).
 * Idempotent; TTL is the backstop if this never runs.
 */
async function dropReply(userId, pendingMessageId) {
  if (!userId || !pendingMessageId) return;
  try {
    await redis.del(replyKey(userId, pendingMessageId));
  } catch (err) {
    logger.warn('[pendingReplyStore] drop failed:', err.message);
  }
}

module.exports = {
  stashReply,
  getReply,
  dropReply,
  _internal: { routeKey, replyKey, PENDING_REPLY_TTL_MS },
};
