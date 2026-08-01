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
const logger = require('../utils/logger');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { requireFeature, requireCreate } = require('../middleware/entitlement');
const harbor = require('../services/harborProvisionService');
const HostedAgent = require('../models/hostedAgentModel');

// Harbor — hosted-agent control plane (Navigator+ feature). Gates:
//   requireFeature('hostedAgent')  → min tier standard (Navigator)
//   requireCreate('hostedAgent')   → per-tier count (maxHostedAgents)
// The actual compute runs on our confidential-VM host backend (see
// harborProvisionService); these routes are the app-facing control surface.

function fail(res, err, op) {
  if (err && err.status) {
    return res.status(err.status).json({ success: false, code: err.code, message: err.message });
  }
  logger.error(`[harbor] ${op} error:`, err);
  return res.status(500).json({ success: false, message: 'Harbor request failed.' });
}

// GET /api/harbor — list this account's hosted agents.
router.get('/', authenticate, async (req, res) => {
  try {
    res.json({ success: true, agents: await harbor.list(req.user._id) });
  } catch (err) { fail(res, err, 'list'); }
});

// POST /api/harbor — enable a new hosted agent (allocate a slot; suspended,
// ready to wake). Body: { accountSignPub?, label? }.
router.post('/', authenticate, requireFeature('hostedAgent'), requireCreate('hostedAgent'), async (req, res) => {
  try {
    const { accountSignPub, label } = req.body || {};
    const agent = await harbor.enable(req.user._id, {
      accountSignPub: typeof accountSignPub === 'string' ? accountSignPub.slice(0, 128) : null,
      label: typeof label === 'string' ? label.slice(0, 80) : null,
    });
    res.status(201).json({ success: true, agent });
  } catch (err) { fail(res, err, 'enable'); }
});

// POST /api/harbor/agent/schedule — the daemon reports its earliest upcoming
// routine fire time so the scheduler can wake it while suspended. Called by the
// daemon itself (its account child-session JWT); scoped to its own agent by
// termId. `nextRoutineAt: null` clears the marker (no routines pending).
// Declared before the /:agentId routes so 'agent' isn't taken as an agentId.
router.post('/agent/schedule', authenticate, async (req, res) => {
  try {
    const { termId, nextRoutineAt, suspended } = req.body || {};
    if (!termId || typeof termId !== 'string') {
      return res.status(400).json({ success: false, message: 'termId required' });
    }
    let when = null;
    if (nextRoutineAt != null) {
      const d = new Date(nextRoutineAt);
      if (isNaN(d.getTime())) {
        return res.status(400).json({ success: false, message: 'invalid nextRoutineAt' });
      }
      when = d;
    }
    const set = { nextRoutineAt: when, lastActiveAt: new Date() };
    // The daemon reports `suspended: true` as it idle-exits, so the sweeper knows
    // to wake it again for `nextRoutineAt`. (A running agent omits the flag.)
    if (suspended === true) set.status = 'suspended';
    const updated = await HostedAgent.findOneAndUpdate(
      { userId: req.user._id, termId },
      { $set: set },
      { new: true }
    );
    if (!updated) return res.status(404).json({ success: false, code: 'HARBOR_NOT_FOUND' });
    res.json({ success: true });
  } catch (err) { fail(res, err, 'schedule'); }
});

// POST /api/harbor/:agentId/wake — wake on demand (Drive).
router.post('/:agentId/wake', authenticate, async (req, res) => {
  try {
    res.json({ success: true, agent: await harbor.wake(req.user._id, req.params.agentId) });
  } catch (err) { fail(res, err, 'wake'); }
});

// GET /api/harbor/:agentId/attestation — fetch a fresh SEV-SNP attestation report
// for a running hosted agent, plus the trusted reference values the client checks
// against (published measurement + recorded terminalPub) and the server's AMD-chain
// verdict. The client binds the key + measurement itself, fail-closed (Step 3). On
// the stub backend this returns 503 HARBOR_ATTESTATION_UNAVAILABLE by design.
router.get('/:agentId/attestation', authenticate, async (req, res) => {
  try {
    res.json({ success: true, attestation: await harbor.attest(req.user._id, req.params.agentId) });
  } catch (err) { fail(res, err, 'attest'); }
});

// GET /api/harbor/:agentId/routines — the durable routine definitions for a hosted
// agent. These are the source of truth (re-seeded into the enclave on each wake), NOT
// the ephemeral routines.json inside the wiped tenant home.
router.get('/:agentId/routines', authenticate, async (req, res) => {
  try {
    res.json({ success: true, routines: await harbor.listRoutines(req.user._id, req.params.agentId) });
  } catch (err) { fail(res, err, 'routines-list'); }
});

// PUT /api/harbor/:agentId/routines — replace the agent's routines. Body: { routines: [
//   { name, cron|at, prompt, model?, delivery?, tools?, enabled? }, … ] }. Persists them
// and re-seeds a fresh wake so the daemon picks them up and reports its next fire time
// (bootstrapping the wake scheduler even from a suspended state).
router.put('/:agentId/routines', authenticate, async (req, res) => {
  try {
    const routines = Array.isArray(req.body && req.body.routines) ? req.body.routines : null;
    if (!routines) return res.status(400).json({ success: false, message: 'routines array required' });
    res.json({ success: true, agent: await harbor.setRoutines(req.user._id, req.params.agentId, routines) });
  } catch (err) { fail(res, err, 'routines-set'); }
});

// PATCH /api/harbor/:agentId — update the agent's own settings.
// Body: { label?, webAccess?, mediaAccess? }. `webAccess` governs whether the daemon
// gets web_search/web_fetch (served by our /api/rag/* with the agent's own credential,
// so no provider key reaches the tenant — but the derived query does leave the enclave).
// `mediaAccess` governs the media-generation tools (real spend + prompt/input egress out
// of the enclave), off by default. Both land in the tenant env, which is read only at
// container start, so flipping either on a running agent restarts it; see
// harborProvisionService.updateAgent.
router.patch('/:agentId', authenticate, async (req, res) => {
  try {
    const { label, webAccess, mediaAccess } = req.body || {};
    if (webAccess !== undefined && typeof webAccess !== 'boolean') {
      return res.status(400).json({ success: false, message: 'webAccess must be a boolean' });
    }
    if (mediaAccess !== undefined && typeof mediaAccess !== 'boolean') {
      return res.status(400).json({ success: false, message: 'mediaAccess must be a boolean' });
    }
    if (label !== undefined && typeof label !== 'string') {
      return res.status(400).json({ success: false, message: 'label must be a string' });
    }
    const agent = await harbor.updateAgent(req.user._id, req.params.agentId, { label, webAccess, mediaAccess });
    res.json({ success: true, agent });
  } catch (err) { fail(res, err, 'update'); }
});

// POST /api/harbor/:agentId/suspend — suspend a running agent.
router.post('/:agentId/suspend', authenticate, async (req, res) => {
  try {
    res.json({ success: true, agent: await harbor.suspend(req.user._id, req.params.agentId) });
  } catch (err) { fail(res, err, 'suspend'); }
});

// DELETE /api/harbor/:agentId — disable (tear down + free the slot).
router.delete('/:agentId', authenticate, async (req, res) => {
  try {
    await harbor.disable(req.user._id, req.params.agentId);
    res.json({ success: true });
  } catch (err) { fail(res, err, 'disable'); }
});

module.exports = router;
