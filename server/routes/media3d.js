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
 * 3D mesh generation for the app's 3D studio screen (`/api/media3d/*`).
 *
 *   GET  /api/media3d/capabilities   — what this account can generate, and for how much
 *   POST /api/media3d/models         — submit an async image-to-mesh job
 *   GET  /api/media3d/models/:jobId  — poll it; delivers the bytes once, inline
 *
 * The mount point is `/api/media3d` and not `/api/media` because that one is
 * already the image router (plus its `/api/images` legacy alias), whose params
 * would decide what `/models` means before this file got a look at it.
 *
 * WHY THIS EXISTS RATHER THAN POINTING THE APP AT `/api/agent/media/*`. The
 * handlers are literally the same functions — this file adds no behaviour — but
 * the two routers differ in the two things a router is for:
 *
 *   - CONCURRENCY. The agent pool ('agentjobs') exists so that a user driving
 *     several linked terminals doesn't serialize through the app's chat slots
 *     (see routes/agentMedia's header). Sending app traffic into it would undo
 *     exactly that: a mesh started in the studio would take a slot away from the
 *     terminal the same person has open. The app uses the app's pool, which is
 *     what `requireConcurrencySlot()` with no arguments means.
 *   - BILLING ORIGIN. `req.mediaOrigin` tags the usage row and the job record so
 *     studio spend reports as app spend. Without it every mesh made in the app
 *     would be filed under the terminal.
 *
 * Deliberately NOT here:
 *   - `requireCloudBackend()`. The mesh is returned inline and nothing is stored
 *     server-side, so a local-backend account can generate one and keep it on
 *     device — the same reasoning that keeps it off the agent routes.
 */
const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { checkCreditBalance } = require('../middleware/checkBalance');
const { requireDailyCap, requireConcurrencySlot, requireFeature } = require('../middleware/entitlement');
const {
  handleAgentModelSubmit,
  handleAgentModelStatus,
  handleAgentMediaCapabilities,
} = require('../services/agentMediaHandler');

router.use(authenticate);
router.use((req, res, next) => {
  req.userId = req.user._id;
  // Read by agentMediaHandler.mediaOrigin and stamped onto the job row, so the
  // poll that settles the charge bills this as app spend even though it is the
  // agent handler doing the work.
  req.mediaOrigin = 'app';
  next();
});

// The studio reads this before it can render anything: whether fal is configured
// at all, whether this account's ZDR setting blocks it, the legal options, and
// the exact price of every combination of them. Cheap and read-only — no gate.
router.get('/capabilities', handleAgentMediaCapabilities);

// The credit floor is the cheapest legal generation (Geometry, no surcharges)
// rather than a round number, so an account holding exactly enough for the call
// it is about to make isn't refused by the gate in front of it — the handler
// prices the real request and refuses on that.
router.post(
  '/models',
  requireFeature('modelGen'),
  requireDailyCap('modelGen'),
  checkCreditBalance(0.22),
  requireConcurrencySlot(),
  handleAgentModelSubmit
);

// Polling holds no slot and burns no cap: the job is already running upstream
// and the studio polls it for a minute or more. Charging a slot per poll would
// let one pending mesh lock the account out of its own chat.
router.get('/models/:jobId', handleAgentModelStatus);

module.exports = router;
