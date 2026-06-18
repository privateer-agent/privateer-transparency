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
const { requireCreate, requireStorage, requireCloudBackend } = require('../middleware/entitlement');
const {
  createProject,
  getProjects,
  getProject,
  updateProject,
  deleteProject,
  getProjectChats
} = require('../controllers/projectController');
const {
  uploadFile,
  listFiles,
  getFileContent,
  deleteFile
} = require('../controllers/projectFilesController');

router.use(authenticate);

router.post('/', requireCreate('project'), createProject);
router.get('/', getProjects);
router.get('/:projectId', getProject);
router.patch('/:projectId', updateProject);
router.delete('/:projectId', deleteProject);
router.get('/:projectId/chats', getProjectChats);

// Project files (E2EE — server stores ciphertext only).
// File-count cap + cumulative storage cap are enforced before upload.
router.post('/:projectId/files', requireCloudBackend(), requireCreate('projectFile', 'projectId'), requireStorage(), uploadFile);
router.get('/:projectId/files', listFiles);
router.get('/:projectId/files/:fileId/content', getFileContent);
router.delete('/:projectId/files/:fileId', deleteFile);

module.exports = router;
