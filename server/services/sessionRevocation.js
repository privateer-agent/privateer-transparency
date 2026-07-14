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
 * sessionRevocation — push a `session_revoked` relay frame to a user's live
 * terminals when their account sessions are revoked server-side.
 *
 * The relay heartbeat already terminates a revoked socket within ≤25s
 * (relaySessionLive → ws.terminate), but that's a silent transport drop. These
 * helpers send an explicit `{ type: 'session_revoked' }` frame so a running
 * privateer-agent tears down cleanly the moment you revoke it — clears its local
 * machine login, drops remote access, and tells the user to run /signin — instead
 * of lingering with a dead token until its next server call.
 *
 * Both are BEST-EFFORT: callers fire-and-forget (`void fn().catch(...)`) so a
 * relay hiccup can never undo the DB revoke that already succeeded.
 */

const relayHub = require('./relayHub');
const UserSession = require('../models/userSessionModel');

async function pushTo(uid, terminals) {
  await Promise.all(
    terminals.map((t) =>
      relayHub.publishDown(relayHub.routeKey(uid, t.termId), { type: 'session_revoked' }),
    ),
  );
}

/**
 * One device lineage was revoked (DELETE /auth/sessions/:id, id = familyId).
 * Signals the device's own live terminal(s) plus any child terminals spawned
 * from it. A live terminal's relay registry records its OWN session familyId
 * (the child's, when spawned), so we match against the device familyId AND the
 * familyIds of its children.
 */
async function signalRevokedTerminals(userId, familyId) {
  const uid = userId.toString();
  const childFamilies = await UserSession.distinct('familyId', {
    userId,
    parentFamilyId: familyId,
  });
  const affected = new Set([familyId, ...childFamilies.filter(Boolean)]);
  const terminals = await relayHub.listTerminals(uid);
  await pushTo(uid, terminals.filter((t) => t.familyId && affected.has(t.familyId)));
}

/**
 * Every session for the user was revoked (change-password, account deletion —
 * both call revokeAllUserSessions). Signals all of the user's live terminals.
 */
async function signalAllTerminals(userId) {
  const uid = userId.toString();
  const terminals = await relayHub.listTerminals(uid);
  await pushTo(uid, terminals);
}

module.exports = { signalRevokedTerminals, signalAllTerminals };
