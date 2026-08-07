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
 * Public, OpenAI-compatible developer API.
 *
 *   Base URL:  https://api.privateer.pro/v1
 *   Auth:      Authorization: Bearer sk-priv-…   (developer API keys)
 *
 *   POST /v1/chat/completions       — billed chat inference (OpenAI wire format)
 *   GET  /v1/models                 — OpenAI-shaped model list
 *   POST /v1/images/generations     — image generation (OpenAI Images shape)
 *   POST /v1/videos                 — submit an async video job (Privateer ext.)
 *   GET  /v1/videos/:id             — poll a video job; returns a signed URL
 *   POST /v1/audio/transcriptions   — speech-to-text (OpenAI shape, multipart)
 *   POST /v1/audio/speech           — text-to-speech (OpenAI shape, audio bytes)
 *
 * sk-priv-… keys instead of the app JWT; downstream model resolution, ZDR,
 * entitlement, and billing are the same account path the app uses. Inference is
 * a stateless in-memory pass-through — only billing metadata is persisted (plus,
 * for async video, a small job record). NOT E2EE.
 */
const express = require('express');
const multer = require('multer');
const router = express.Router();
const logger = require('../utils/logger');
const { authenticateApiKey } = require('../middleware/apiKeyAuth');
const { apiRateLimiter } = require('../middleware/rateLimiter');
const { checkCreditBalance } = require('../middleware/checkBalance');
const { requireDailyCap, requireConcurrencySlot, requireFeature } = require('../middleware/entitlement');
const { handleChatCompletion } = require('../services/openaiProxyHandler');
const { handleImageGeneration, handleVideoSubmit, handleVideoStatus } = require('../services/openaiMediaHandler');
const audioService = require('../services/audioService');
// The non-ZDR media gate, shared with the app and agent paths — /audio/sfx is
// the only /v1 audio route that needs it.
const { assertMediaModelAllowed, resolveAllowNonZdrMedia } = require('../controllers/chatController');
const billingService = require('../services/billingService');
const { listEnabledModels } = require('../services/inferenceService');

// Developer /v1 turns get their own concurrency pool ('apikey'), separate from
// the app's chat slots and the Agent CLI's 'agentjobs' pool.
const API_CONCURRENCY_CAP = Number(process.env.API_CONCURRENCY_CAP) || 8;

// In-memory multipart parsing for OpenAI-style audio uploads (bounded).
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

function oaError(res, status, message, code = 'INVALID_REQUEST') {
  return res.status(status).json({ error: { message, type: 'invalid_request_error', code } });
}

router.use(authenticateApiKey);

// ── Chat ──────────────────────────────────────────────────────────────────────
router.post(
  '/chat/completions',
  apiRateLimiter,
  requireDailyCap('message'),
  checkCreditBalance(0.05),
  requireConcurrencySlot({ keyPrefix: 'apikey', cap: API_CONCURRENCY_CAP }),
  (req, res) => handleChatCompletion(req, res, { kind: 'api' })
);

// ── Models ──────────────────────────────────────────────────────────────────
router.get('/models', apiRateLimiter, async (_req, res) => {
  try {
    const configs = await listEnabledModels();
    const data = configs.map((c) => ({ id: c.modelId, object: 'model', owned_by: 'privateer' }));
    res.json({ object: 'list', data });
  } catch (err) {
    logger.error('GET /v1/models failed:', err.message);
    res.status(500).json({ error: { message: 'Failed to fetch model list', type: 'server_error', code: 'models_unavailable' } });
  }
});

// ── Images ────────────────────────────────────────────────────────────────────
router.post(
  '/images/generations',
  apiRateLimiter,
  requireDailyCap('imageGen'),
  checkCreditBalance(0.01),
  requireConcurrencySlot({ keyPrefix: 'apikey', cap: API_CONCURRENCY_CAP }),
  handleImageGeneration
);

// ── Video (async submit → poll) ────────────────────────────────────────────────
router.post(
  '/videos',
  apiRateLimiter,
  requireFeature('videoGen'),
  requireDailyCap('imageGen'),
  checkCreditBalance(0.05),
  requireConcurrencySlot({ keyPrefix: 'apikey', cap: API_CONCURRENCY_CAP }),
  handleVideoSubmit
);
router.get('/videos/:id', apiRateLimiter, handleVideoStatus);

// ── Audio: speech-to-text (multipart `file`, or JSON audioBase64) ──────────────
router.post(
  '/audio/transcriptions',
  apiRateLimiter,
  requireDailyCap('message'),
  checkCreditBalance(0.01),
  requireConcurrencySlot({ keyPrefix: 'apikey', cap: API_CONCURRENCY_CAP }),
  upload.single('file'),
  async (req, res) => {
    try {
      let audioBase64, format;
      if (req.file) {
        audioBase64 = req.file.buffer.toString('base64');
        format = (req.file.originalname || '').split('.').pop() || 'm4a';
      } else if (typeof req.body?.audioBase64 === 'string') {
        audioBase64 = req.body.audioBase64;
        format = req.body.format;
      }
      if (!audioBase64) return oaError(res, 400, 'An audio `file` is required.', 'AUDIO_REQUIRED');

      const requireZdr = await audioService.resolveRequireZdr(req.userId, req.body?.requireZdr);
      const { text } = await audioService.transcribe({
        userId: req.userId, audioBase64, format, language: req.body?.language, modelId: req.body?.model, requireZdr,
        billingMarkup: billingService.apiMarkupFactor(), origin: 'api',
      });
      return res.json({ text });
    } catch (err) {
      return sendMediaError(res, err, 'audio_transcriptions');
    }
  }
);

// ── Audio: text-to-speech (returns raw audio bytes) ───────────────────────────
router.post(
  '/audio/speech',
  apiRateLimiter,
  requireDailyCap('message'),
  checkCreditBalance(0.01),
  requireConcurrencySlot({ keyPrefix: 'apikey', cap: API_CONCURRENCY_CAP }),
  async (req, res) => {
  try {
    const body = req.body || {};
    const text = typeof body.input === 'string' ? body.input : body.text;
    if (!text || typeof text !== 'string' || !text.trim()) return oaError(res, 400, '`input` text is required.', 'TEXT_REQUIRED');

    // mp3 by default, like OpenAI's own /v1/audio/speech, and pcm when asked
    // for. Models that can't do mp3 (Gemini TTS) are overridden inside
    // audioService.resolveResponseFormat and come back as WAV, so an
    // unsupported combination downgrades the container instead of 400ing.
    const format = body.response_format === 'pcm' ? 'pcm' : 'mp3';
    const requireZdr = await audioService.resolveRequireZdr(req.userId, body.requireZdr);
    const { buffer, mimeType } = await audioService.synthesizeSpeech({
      userId: req.userId, text, voice: body.voice, format, modelId: body.model, requireZdr,
      billingMarkup: billingService.apiMarkupFactor(), origin: 'api',
    });
    res.setHeader('Content-Type', mimeType || 'audio/mpeg');
    res.setHeader('Content-Length', buffer.length);
    return res.send(buffer);
  } catch (err) {
    return sendMediaError(res, err, 'audio_speech');
  }
});

// ── Audio: sound effects (returns raw audio bytes) ────────────────────────────
//
// Shaped like /audio/speech — bytes back, not JSON — because the caller wants a
// file, and OpenAI's own audio endpoints set that precedent.
//
// The one difference worth knowing about: this is the only /v1 audio route
// behind the non-ZDR media gate. Sound effects run on fal, which has no
// zero-data-retention endpoint, so a key whose account requires ZDR gets a 403
// `ZDR_MEDIA_BLOCKED` until non-ZDR media generation is enabled. That is the
// same rule the app enforces (CLAUDE.md §5) — not an API-only restriction — and
// it is deliberately NOT the exemption music takes.
router.post(
  '/audio/sfx',
  apiRateLimiter,
  requireDailyCap('sfxGen'),
  // Fixed price per call, so the gate can be exact rather than the bare $0.01
  // floor the speech route uses.
  (req, res, next) => {
    let estimate;
    try {
      estimate = audioService.sfxChargeEstimateUsd(audioService.resolveSfxModel(req.body?.model));
    } catch (err) {
      return sendMediaError(res, err, 'audio_sfx');
    }
    return checkCreditBalance(estimate)(req, res, next);
  },
  requireConcurrencySlot({ keyPrefix: 'apikey', cap: API_CONCURRENCY_CAP }),
  async (req, res) => {
    try {
      const body = req.body || {};
      const prompt = typeof body.input === 'string' ? body.input : body.prompt;
      if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
        return oaError(res, 400, '`input` text is required.', 'PROMPT_REQUIRED');
      }

      const modelId = audioService.resolveSfxModel(body.model);
      const requireZdr = await audioService.resolveRequireZdr(req.userId, body.requireZdr);
      const allowNonZdrMedia = await resolveAllowNonZdrMedia(req.userId, body.allowNonZdrMedia);
      await assertMediaModelAllowed({ userId: req.userId, modelId, requireZdr, allowNonZdrMedia });

      const { buffer, mimeType, durationSeconds } = await audioService.generateSfx({
        userId: req.userId, prompt, modelId, duration: body.duration,
        billingMarkup: billingService.apiMarkupFactor(), origin: 'api',
      });
      res.setHeader('Content-Type', mimeType || 'audio/mpeg');
      res.setHeader('Content-Length', buffer.length);
      // The rendered length, so a caller that clamped its request can tell
      // without decoding the file.
      res.setHeader('X-Privateer-Duration-Seconds', String(durationSeconds));
      return res.send(buffer);
    } catch (err) {
      return sendMediaError(res, err, 'audio_sfx');
    }
  });

function sendMediaError(res, err, op) {
  // ZDR_MEDIA_BLOCKED already carries statusCode 403 from assertMediaModelAllowed,
  // so it flows through as a 403 with its own actionable message rather than
  // being flattened into a 500.
  const status = err.statusCode || (err.code === 'INSUFFICIENT_FUNDS' ? 402 : err.code === 'ZDR_KEY_UNAVAILABLE' ? 503 : 500);
  const code = err.code || 'INFERENCE_ERROR';
  if (status >= 500) logger.error(`[v1 ${op}]`, err.message, err.upstreamStatus || '', err.upstreamDetail || '');
  if (res.headersSent) return;
  // Fold the upstream detail into the client-facing message so a 502 is
  // actionable (e.g. which audio format / voice the backend rejected).
  const message = err.upstreamDetail ? `${err.message} (upstream ${err.upstreamStatus || ''}: ${err.upstreamDetail})` : err.message;
  return res.status(status).json({ error: { message, type: 'invalid_request_error', code } });
}

module.exports = router;
