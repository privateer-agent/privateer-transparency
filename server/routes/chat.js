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
const {
  sendMessage,
  streamMessage,
  startDeepResearch,
  streamDeepResearch,
  getDeepResearch,
  cancelDeepResearch,
  ackDeepResearch,
  startBuild,
  streamBuild,
  getBuild,
  cancelBuild,
  ackBuild,
  planNodes,
  compactContext,
  getTokenStatus,
  uploadImage,
  uploadFile,
  generateImage,
  editImage,
  analyzeImage,
  generateOrEditImage,
  resolveImageGenModelId,
  generateVideo,
  getVideoStatus,
  updateVideoAttachmentMetadata,
  updateVideoAttachmentStorageRef,
  uploadGeneratedVideo,
} = require('../controllers/chatController');
const { analyzeIntent, chargeIntentAnalysis } = require('../services/intentService');
const { uploadImageWithThumb, handleUploadError, uploadFileSingle, handleFileUploadError } = require('../services/ImageUpload');
const { authenticate } = require('../middleware/auth');
const { checkCreditBalance } = require('../middleware/checkBalance');
const { requireDailyCap, requireFeature, requireStorage, requireCloudBackend, requireConcurrencySlot } = require('../middleware/entitlement');
const { limitTextInput } = require('../middleware/inputLimits');

// Apply authentication to all chat routes; bridge req.userId for chatController compat
router.use(authenticate);
router.use((req, res, next) => { req.userId = req.user._id; next(); });

// Send message — minimum $0.05 balance required so a near-empty wallet can't
// kick off a large completion. Actual cost is deducted post-call (still cheap
// per request; the floor caps worst-case leak per attempt).
router.post('/message', limitTextInput, requireDailyCap('message'), checkCreditBalance(0.05), requireConcurrencySlot(), sendMessage);

// Stream message — same gating as /message; delivers tokens via SSE.
router.post('/stream', limitTextInput, requireDailyCap('message'), checkCreditBalance(0.05), requireConcurrencySlot(), streamMessage);

// Deep Research — detached background job. `start` validates + kicks off a run
// and returns a jobId immediately; progress is consumed over the reconnectable
// SSE stream. Cancellation + client-ack (delete) are idempotent. Daily cap and
// per-user concurrency are enforced inside the controller/job store (the run
// holds a DR-specific slot for its whole lifetime, unlike requireConcurrencySlot
// which releases at request end). Same $0.05 balance floor as chat.
router.post('/deep-research', limitTextInput, checkCreditBalance(0.05), startDeepResearch);
router.get('/deep-research/:jobId/stream', streamDeepResearch);
router.get('/deep-research/:jobId', getDeepResearch);
router.post('/deep-research/:jobId/cancel', cancelDeepResearch);
router.delete('/deep-research/:jobId', ackDeepResearch);

// Build/Cargo — detached background job, same shape as Deep Research: a large
// artifact can take minutes and must survive a dropped socket / app
// backgrounding. Daily cap + per-user concurrency are enforced inside the
// controller/job store (the run holds a build slot for its whole lifetime).
router.post('/build', limitTextInput, checkCreditBalance(0.05), startBuild);
router.get('/build/:jobId/stream', streamBuild);
router.get('/build/:jobId', getBuild);
router.post('/build/:jobId/cancel', cancelBuild);
router.delete('/build/:jobId', ackBuild);

// Plan multi-node fan-out (graph). Cheap planner call (no concurrency slot,
// minimal balance floor); the actual node generations each go through /stream.
router.post('/plan', limitTextInput, checkCreditBalance(0), planNodes);

// Compact a chat/project into background context for a different conversation
// (context pills). Same cheap-utility gating as /plan: no daily message cap and
// no concurrency slot, since this fires on a drag rather than on a send — it
// must not consume the user's message quota.
router.post('/compact', limitTextInput, checkCreditBalance(0), compactContext);

// Generate or edit image based on intent
router.post('/generate-or-edit-image', limitTextInput, requireCloudBackend(), requireDailyCap('imageGen'), checkCreditBalance(0), requireConcurrencySlot(), async (req, res) => {
  try {
    const { prompt, imageAttachments = [] } = req.body;
    const userId = req.userId;

    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ message: req.t('errors.validPromptRequired') });
    }

    const hasImageAttachments = imageAttachments && imageAttachments.length > 0;
    const intentAnalysis = await analyzeIntent(prompt, hasImageAttachments);
    await chargeIntentAnalysis(userId, intentAnalysis);

    const imageGenModelId = await resolveImageGenModelId(userId, req.body.imageGenModelId || null);
    const result = await generateOrEditImage(
      prompt,
      imageAttachments,
      intentAnalysis.intent,
      userId,
      req,
      imageGenModelId
    );

    res.json({
      success: true,
      responseText: result.responseText,
      generatedImages: result.generatedImages,
      tokensUsed: result.tokensUsed,
      intent: intentAnalysis.intent
    });
  } catch (error) {
    logger.error('Generate or edit image error:', error);
    res.status(500).json({ message: req.t('errors.imageGenError'), error: error.message });
  }
});

// Get user's credit balance and usage stats
router.get('/token-status', getTokenStatus);

// Upload image with optional analysis
router.post('/upload-image',
  requireCloudBackend(),
  requireStorage(),
  checkCreditBalance(0),
  uploadImageWithThumb,
  handleUploadError,
  uploadImage
);

// Upload a client-encrypted file attachment (pdf/docx/csv/code/audio) to S3.
// Server stores ciphertext only — never plaintext file bytes (E2EE).
router.post('/upload-file',
  requireCloudBackend(),
  requireStorage(),
  checkCreditBalance(0),
  uploadFileSingle,
  handleFileUploadError,
  uploadFile
);

// Generate image from text prompt
router.post('/generate-image', limitTextInput, requireCloudBackend(), requireDailyCap('imageGen'), requireStorage(() => 0), checkCreditBalance(0), requireConcurrencySlot(), generateImage);

// Edit an existing image via AI — returns raw buffer (client encrypts + uploads)
router.post('/edit-image', limitTextInput, requireCloudBackend(), requireDailyCap('imageGen'), requireStorage(() => 0), checkCreditBalance(0), requireConcurrencySlot(), editImage);

// Analyze an existing image — vision feature, gated to Sailor and up.
router.post('/analyze-image', requireFeature('vision'), checkCreditBalance(0), analyzeImage);

// Video generation — async job submission + status polling.
// Gated to Sailor (basic) and up; pass-tier promotion via top-up also unlocks it.
// Local-storage accounts are allowed here: the controller already branches on
// UserStoragePrefs and returns the raw bytes inline so the client can writeLocal()
// without anything plaintext ever resting on the server. Stay-connected only —
// closing the app mid-poll drops the job.
router.post('/generate-video', limitTextInput, requireFeature('videoGen'), requireDailyCap('imageGen'), checkCreditBalance(0), requireConcurrencySlot(), generateVideo);
router.get('/video-status/:jobId', getVideoStatus);
// Upload client-encrypted ciphertext of a completed AI video (cloud backend).
// Server stores ciphertext only — never plaintext video bytes (E2EE).
router.post('/upload-video', requireCloudBackend(), checkCreditBalance(0), uploadGeneratedVideo);
// Store client-side encrypted metadata for a completed video attachment
router.patch('/video-attachment/:jobId/metadata', updateVideoAttachmentMetadata);
// Record a local-storage fileId after the client writes the video to disk
router.patch('/video-attachment/:jobId/storage-ref', updateVideoAttachmentStorageRef);

// Health check
router.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'chat', timestamp: new Date().toISOString() });
});

module.exports = router;
