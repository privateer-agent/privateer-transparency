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
 * Media handlers for the developer /v1 API: image generation and async video.
 *
 * Same trust model as the chat proxy (openaiProxyHandler): auth-agnostic (reads
 * req.userId/req.body), non-E2EE, stateless except billing metadata + (for
 * video) a small job record so status polls resolve by id. Reuses the app's
 * inference/billing/reservation services and the S3 helpers.
 */
const crypto = require('crypto');
const logger = require('../utils/logger');
const Sentry = require('@sentry/node');
const inferenceService = require('./inferenceService');
const billingService = require('./billingService');
const reservationService = require('./reservationService');
const { uploadToS3, generateSignedUrl } = require('./cloud-services');
const { resolveImageGenModelId, resolveRequireZdr, isImageFallbackEligibleError, IMAGE_GEN_FALLBACK_MODEL } = require('../controllers/chatController');
const ApiMediaJob = require('../models/apiMediaJobModel');
const ApiMediaArtifact = require('../models/apiMediaArtifactModel');

const VIDEO_URL_TTL_SEC = Number(process.env.API_VIDEO_URL_TTL_SEC) || 3600;
const IMAGE_URL_TTL_SEC = Number(process.env.API_IMAGE_URL_TTL_SEC) || 3600;
const VIDEO_JOB_TTL_MS = (Number(process.env.API_VIDEO_JOB_TTL_HOURS) || 24) * 3600 * 1000;
// How long uploaded /v1 media artifacts live in S3 before the sweep deletes
// them (services/apiMediaCleanup.js). Signed URLs are far shorter-lived.
const MEDIA_RETENTION_MS = (Number(process.env.API_MEDIA_RETENTION_HOURS) || 24) * 3600 * 1000;

// ── Cost calculation ─────────────────────────────────────────────────────────
//
// TRANSPARENCY REPO OMISSION — proprietary billing logic, intentionally redacted.
//
// Our video markup factor (applied to the provider-reported render cost) is part
// of Privateer's CLOSED codebase and is NOT published here. Image billing lives
// in inferenceService.calcImageGenCost (also omitted). Billing operates purely on
// provider cost, token counts, and model IDs — it never sees user prompts or
// generated media — so it adds nothing to the privacy audit. The helper below is
// stubbed to preserve call-site readability.

function videoChargeUsd(/* providerCostUsd */) {
  return 0; // omitted: provider cost × markup
}

// ── Media helpers ────────────────────────────────────────────────────────────

// Record an uploaded S3 object for later cleanup. Best-effort — a tracking-row
// failure must not fail the media response (worst case: the object lingers).
async function trackArtifact(userId, up, kind) {
  try {
    await ApiMediaArtifact.create({
      userId, s3Key: up.s3Key, bucketType: 'ai_generated', kind,
      fileSize: up.fileSize || 0, expiresAt: new Date(Date.now() + MEDIA_RETENTION_MS),
    });
  } catch (err) {
    logger.warn('[v1 media] failed to record artifact for cleanup', up?.s3Key, err.message);
  }
}

function extForMime(mimeType) {
  const m = (mimeType || '').toLowerCase();
  if (m.includes('png')) return 'png';
  if (m.includes('jpeg') || m.includes('jpg')) return 'jpg';
  if (m.includes('webp')) return 'webp';
  if (m.includes('gif')) return 'gif';
  if (m.includes('mp4')) return 'mp4';
  if (m.includes('webm')) return 'webm';
  return 'bin';
}

function oaError(res, status, message, code = 'INVALID_REQUEST') {
  return res.status(status).json({ error: { message, type: 'invalid_request_error', code } });
}

// POST /v1/images/generations — OpenAI Images shape.
// { model, prompt, n, size, aspect_ratio, response_format, requireZdr }
async function handleImageGeneration(req, res) {
  const userId = req.userId;
  const body = req.body || {};
  const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';
  if (!prompt) return oaError(res, 400, 'prompt is required');

  const n = Math.min(Math.max(1, parseInt(body.n, 10) || 1), 4);
  const responseFormat = body.response_format === 'url' ? 'url' : 'b64_json';

  try {
    let modelId = await resolveImageGenModelId(userId, body.model);
    const requireZdr = await resolveRequireZdr(userId, body.requireZdr);

    const options = { modelId, requireZdr };
    if (typeof body.size === 'string' && body.size) options.imageSize = body.size;
    if (typeof body.aspect_ratio === 'string' && body.aspect_ratio) options.aspectRatio = body.aspect_ratio;

    // Affordability: the checkCreditBalance gate only guarantees a small floor,
    // but we may generate up to n images (billed per image). Pre-check the full
    // n-image cost so a near-empty account can't over-generate before running dry.
    const estimate = await inferenceService.calcImageGenCost(modelId, n);
    const estimateBilled = billingService.apiBilledCost({ providerCostUsd: estimate.providerCostUsd, costUsd: estimate.costUsd });
    const bal = await billingService.checkBalance(userId, estimateBilled);
    if (bal.status === 'blocked') {
      return res.status(402).json({ error: { message: 'Insufficient balance for this image request.', type: 'invalid_request_error', code: 'INSUFFICIENT_FUNDS' } });
    }

    const data = [];
    for (let i = 0; i < n; i++) {
      let result;
      try {
        result = await inferenceService.generateImage(prompt, options);
      } catch (genErr) {
        // The account's chosen/default image model may be unroutable — e.g. an
        // OpenAI image model OpenRouter can't serve for image output, which
        // surfaces as PROVIDER_UNAVAILABLE / a "modalities" 404. Fall back once
        // to the known-good default image model, mirroring the app's chat image
        // path (chatController), so a stock `images.generate` doesn't hard-fail.
        if (isImageFallbackEligibleError(genErr) && modelId !== IMAGE_GEN_FALLBACK_MODEL) {
          logger.debug(`[v1 images] ${modelId} failed (${genErr.code || genErr.message?.slice(0, 80)}) — falling back to ${IMAGE_GEN_FALLBACK_MODEL}`);
          modelId = IMAGE_GEN_FALLBACK_MODEL;
          options.modelId = modelId;
          result = await inferenceService.generateImage(prompt, options);
        } else {
          throw genErr;
        }
      }
      const img = result?.images?.[0];
      if (!img?.buffer) {
        const e = new Error('image generation returned no image');
        e.statusCode = 502; e.code = 'IMAGE_GEN_FAILED';
        throw e;
      }

      // Bill each produced image immediately so partial output is never free.
      // Flat API rate (not the app's image markup).
      const { providerCostUsd, costUsd } = await inferenceService.calcImageGenCost(modelId, 1);
      const billedUsd = billingService.apiBilledCost({ providerCostUsd, costUsd });
      await billingService.chargeUsd(userId, billedUsd, {
        model: modelId, tokensPrompt: 0, tokensCompletion: 0, providerCostUsd, kind: 'imageGen',
      });

      if (responseFormat === 'url') {
        const up = await uploadToS3(
          { buffer: img.buffer, mimetype: img.mimeType, originalname: `image.${extForMime(img.mimeType)}`, size: img.buffer.length },
          'ai_generated', String(userId), 'api/images/'
        );
        await trackArtifact(userId, up, 'image');
        const url = await generateSignedUrl(up.s3Key, 'ai_generated', IMAGE_URL_TTL_SEC);
        data.push({ url });
      } else {
        data.push({ b64_json: img.buffer.toString('base64') });
      }
    }

    return res.json({ created: Math.floor(Date.now() / 1000), data });
  } catch (err) {
    return sendError(res, err, 'image_generation');
  }
}

// POST /v1/videos — submit an async video job.
// { model, prompt, seconds, size, generate_audio, requireZdr }
async function handleVideoSubmit(req, res) {
  const userId = req.userId;
  const body = req.body || {};
  const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';
  if (!prompt) return oaError(res, 400, 'prompt is required');

  try {
    const modelId = (typeof body.model === 'string' && body.model.includes('/')) ? body.model : undefined;
    const requireZdr = await resolveRequireZdr(userId, body.requireZdr);
    const durationSec = Number(body.seconds || body.duration) || undefined;
    const resolution = body.size || body.resolution;
    const generateAudio = body.generate_audio === true || body.generateAudio === true;

    const submit = await inferenceService.submitVideoGeneration(prompt, {
      modelId, duration: durationSec, resolution, generate_audio: generateAudio, requireZdr,
    });
    const { jobId, status, usedZdrKey } = submit;
    const refKey = `video:${jobId}`;

    // Hold the estimated cost now; settle against the provider's actual usage on
    // completion. If the caller can't cover the estimate, fail before we track.
    const estimate = reservationService.estimateVideoCostUsd({ modelId, durationSec, resolution, generateAudio, markup: billingService.apiMarkupFactor() });
    try {
      await reservationService.reserveUsd(userId, estimate.chargeUsd, {
        kind: 'videoGen', refKey, meta: { modelId, source: 'api' }, estimatorVersion: estimate.estimatorVersion,
      });
    } catch (e) {
      if (e?.code === 'INSUFFICIENT_FUNDS') {
        return res.status(402).json({ error: { message: 'Insufficient balance to reserve this video job.', type: 'invalid_request_error', code: 'INSUFFICIENT_FUNDS' } });
      }
      throw e;
    }

    await ApiMediaJob.create({
      userId, jobId, kind: 'video', model: modelId || null, usedZdrKey: !!usedZdrKey,
      status: status === 'completed' ? 'processing' : 'queued',
      reservationRefKey: refKey, expiresAt: new Date(Date.now() + VIDEO_JOB_TTL_MS),
    });

    return res.status(202).json({ id: jobId, object: 'video.job', status: 'queued', created: Math.floor(Date.now() / 1000) });
  } catch (err) {
    return sendError(res, err, 'video_submit');
  }
}

// GET /v1/videos/:id — poll status; on completion returns a short-lived URL.
async function handleVideoStatus(req, res) {
  const userId = req.userId;
  const jobId = req.params.id;

  try {
    const job = await ApiMediaJob.findOne({ jobId, userId });
    if (!job) return oaError(res, 404, 'No such video job.', 'not_found');

    if (job.status === 'completed' && job.s3Key) {
      const url = await generateSignedUrl(job.s3Key, 'ai_generated', VIDEO_URL_TTL_SEC);
      return res.json({ id: jobId, object: 'video.job', status: 'completed', url, expires_at: Math.floor(Date.now() / 1000) + VIDEO_URL_TTL_SEC });
    }
    if (job.status === 'failed') {
      return res.json({ id: jobId, object: 'video.job', status: 'failed', error: { message: job.error || 'Video generation failed.' } });
    }

    const poll = await inferenceService.pollVideoGeneration(jobId, { useZdrKey: job.usedZdrKey });
    const status = String(poll?.status || '').toLowerCase();

    if (status === 'completed' && Array.isArray(poll.unsigned_urls) && poll.unsigned_urls[0]) {
      // Atomically claim the completion so concurrent polls settle billing once.
      const claimed = await ApiMediaJob.findOneAndUpdate(
        { jobId, userId, status: { $in: ['queued', 'processing'] } },
        { status: 'processing' },
        { new: true }
      );
      const { buffer, mimeType } = await inferenceService.downloadVideoBuffer(poll.unsigned_urls[0], { useZdrKey: job.usedZdrKey });
      const up = await uploadToS3(
        { buffer, mimetype: mimeType || 'video/mp4', originalname: `video.${extForMime(mimeType || 'video/mp4')}`, size: buffer.length },
        'ai_generated', String(userId), 'api/videos/'
      );

      if (claimed) {
        // Settle billing from the provider's reported cost (fallback flat).
        const providerCostUsd = Number(poll?.usage?.cost ?? poll?.usage?.total_cost) || 0.5;
        const chargeUsd = videoChargeUsd(providerCostUsd);
        try {
          await reservationService.settleReservation(job.reservationRefKey, chargeUsd, { providerCostUsd, model: job.model || 'video-generation', kind: 'videoGen' });
        } catch (e) {
          if (e?.code === 'RESERVATION_NOT_FOUND') {
            await billingService.chargeUsd(userId, chargeUsd, { model: job.model || 'video-generation', providerCostUsd, kind: 'videoGen' }).catch(() => {});
          } else {
            logger.warn('[v1 video] settle failed', e.message);
          }
        }
      }

      await ApiMediaJob.updateOne({ jobId, userId }, { status: 'completed', s3Key: up.s3Key, mimeType: mimeType || 'video/mp4' });
      await trackArtifact(userId, up, 'video');
      const url = await generateSignedUrl(up.s3Key, 'ai_generated', VIDEO_URL_TTL_SEC);
      return res.json({ id: jobId, object: 'video.job', status: 'completed', url, expires_at: Math.floor(Date.now() / 1000) + VIDEO_URL_TTL_SEC });
    }

    if (status === 'failed' || poll?.error || poll?.failure_reason) {
      const message = poll?.error?.message || poll?.message || poll?.failure_reason || 'Video generation failed.';
      await reservationService.releaseReservation(job.reservationRefKey, 'video-failed').catch(() => {});
      await ApiMediaJob.updateOne({ jobId, userId }, { status: 'failed', error: String(message).slice(0, 500) });
      return res.json({ id: jobId, object: 'video.job', status: 'failed', error: { message } });
    }

    // Still running.
    if (job.status === 'queued') await ApiMediaJob.updateOne({ jobId, userId }, { status: 'processing' });
    return res.json({ id: jobId, object: 'video.job', status: 'processing' });
  } catch (err) {
    return sendError(res, err, 'video_status');
  }
}

function sendError(res, err, op) {
  const status = err.statusCode || 500;
  const code = err.code || 'INFERENCE_ERROR';
  if (status >= 500) {
    Sentry.captureException(err, { tags: { op } });
    logger.error(`[v1 ${op}]`, err.message);
  }
  if (res.headersSent) return;
  return res.status(status).json({ error: { message: err.message, type: 'invalid_request_error', code } });
}

module.exports = { handleImageGeneration, handleVideoSubmit, handleVideoStatus };
