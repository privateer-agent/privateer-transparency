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
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const { requireStorage } = require('../middleware/entitlement');
const {
  createCargo,
  listCargo,
  getCargo,
  updateCargo,
  deleteCargo,
  createCargoVersion,
  listCargoVersions,
  getCargoVersion
} = require('../controllers/cargoController');

// All Cargo routes require auth and are scoped to the caller's userId.
router.use(authenticate);
router.use((req, res, next) => { req.userId = req.user._id; next(); });

// requireStorage() checks byte headroom from Content-Length — generic, no new
// entitlement `kind` needed. Add a 'cargo' kind to entitlementService only if a
// per-count cap is later wanted.
router.post('/', requireStorage(), createCargo);
router.get('/', listCargo);
router.get('/:cargoId', getCargo);
router.patch('/:cargoId', requireStorage(), updateCargo);
router.delete('/:cargoId', deleteCargo);

// Version history (checkpoints). Snapshots are full encrypted copies, retained
// as a per-artifact ring buffer (cargoController.MAX_VERSIONS). Restore is
// client-orchestrated (snapshot-current → PATCH the artifact), so no restore
// route is needed here.
router.post('/:cargoId/versions', requireStorage(), createCargoVersion);
router.get('/:cargoId/versions', listCargoVersions);
router.get('/:cargoId/versions/:versionId', getCargoVersion);

module.exports = router;
