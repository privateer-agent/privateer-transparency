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
 * Media handlers for the developer /v1 API: image generation, async video, and
 * async 3D meshes.
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
const {
  resolveImageGenModelId, resolveRequireZdr, isImageFallbackEligibleError, IMAGE_GEN_FALLBACK_MODEL,
  resolveAllowNonZdrMedia, assertMediaModelAllowed,
} = require('../controllers/chatController');
const falService = require('./falService');
const {
  DEFAULT_3D_MODEL, resolve3dModel, fal3dModel, normalize3dOptions, fal3dCostUsd,
  buildFal3dInput, fal3dOutputUrl, fal3dMime,
} = require('../data/fal3dModels');
const ApiMediaJob = require('../models/apiMediaJobModel');
const ApiMediaArtifact = require('../models/apiMediaArtifactModel');

const VIDEO_URL_TTL_SEC = Number(process.env.API_VIDEO_URL_TTL_SEC) || 3600;
const IMAGE_URL_TTL_SEC = Number(process.env.API_IMAGE_URL_TTL_SEC) || 3600;
const MODEL3D_URL_TTL_SEC = Number(process.env.API_MODEL3D_URL_TTL_SEC) || 3600;
const VIDEO_JOB_TTL_MS = (Number(process.env.API_VIDEO_JOB_TTL_HOURS) || 24) * 3600 * 1000;
const MODEL3D_JOB_TTL_MS = (Number(process.env.API_MODEL3D_JOB_TTL_HOURS) || 24) * 3600 * 1000;

// Input bounds for a mesh job. Meshes take PICTURES, so unlike every other /v1
// media route this one accepts caller-supplied binary — bounded individually and
// in total, because the global express.json cap would otherwise reject the whole
// request with a message about JSON size rather than about images.
const MAX_3D_VIEWS = 4;
const MAX_3D_INPUT_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_3D_INPUT_TOTAL_BYTES = 12 * 1024 * 1024;
// Measured against the live endpoint: a textured mesh at the provider's default
// face count is ~64 MB. Held in memory once on the way to S3.
const MAX_MESH_BYTES = Number(process.env.FAL_MAX_MESH_BYTES) || 128 * 1024 * 1024;
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
        model: modelId, tokensPrompt: 0, tokensCompletion: 0, providerCostUsd, kind: 'imageGen', origin: 'api',
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
          await reservationService.settleReservation(job.reservationRefKey, chargeUsd, { providerCostUsd, model: job.model || 'video-generation', kind: 'videoGen', origin: 'api' });
        } catch (e) {
          if (e?.code === 'RESERVATION_NOT_FOUND') {
            await billingService.chargeUsd(userId, chargeUsd, { model: job.model || 'video-generation', providerCostUsd, kind: 'videoGen', origin: 'api' }).catch(() => {});
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

// ── 3D meshes (async submit → poll) ──────────────────────────────────────────
//
// The developer-API twin of the agent's /api/agent/media/models. Two differences
// from that path, both deliberate:
//
//   - the finished mesh is uploaded to S3 and handed back as a short-lived
//     signed URL, rather than returned inline as base64. That is the /v1 trade
//     everywhere (see the module header): writing a user's generated file to our
//     bucket is right for a developer API and wrong for the agent, whose whole
//     posture is that content stays on the user's machine.
//   - billing is the flat API rate (apiBilledCost), not the app's per-modality
//     mesh markup — same rule image and video already follow here.
//
// The catalog, the ZDR gate and the fal queue transport are shared with the
// agent path; only the delivery and the markup differ.

/**
 * Decode one caller-supplied reference view.
 *
 * Accepts raw base64, a `data:` URI, or `{ data, mimeType }`. It does NOT accept
 * an http(s) URL, and that is a security decision rather than an omission: a
 * server-side fetch of a caller-controlled URL is an SSRF primitive, and this
 * endpoint is reachable with nothing but an API key. Callers send bytes.
 */
function input3dImage(entry, index) {
  const raw = typeof entry === 'string' ? entry : (entry?.data ?? entry?.b64_json ?? entry?.image);
  if (typeof raw !== 'string' || !raw) {
    throw Object.assign(new Error(`images[${index}] must be base64 image data or a data: URI`), {
      statusCode: 400, code: 'IMAGE_DATA_REQUIRED',
    });
  }
  if (/^https?:\/\//i.test(raw)) {
    throw Object.assign(
      new Error(`images[${index}] must be base64 data, not a URL — this endpoint does not fetch remote images.`),
      { statusCode: 400, code: 'IMAGE_URL_UNSUPPORTED' }
    );
  }
  // A data: URI carries its own mime type; trust that over a caller-declared one.
  const dataUri = /^data:([^;,]+);base64,(.*)$/is.exec(raw);
  const mimeType = dataUri ? dataUri[1] : (entry?.mimeType || entry?.mime_type || 'image/png');
  const b64 = dataUri ? dataUri[2] : raw;

  const buffer = Buffer.from(b64, 'base64');
  if (buffer.length === 0) {
    throw Object.assign(new Error(`images[${index}] is not valid base64`), { statusCode: 400, code: 'IMAGE_DATA_INVALID' });
  }
  if (buffer.length > MAX_3D_INPUT_IMAGE_BYTES) {
    throw Object.assign(
      new Error(`images[${index}] is ${(buffer.length / 1048576).toFixed(1)} MB — the limit is ${MAX_3D_INPUT_IMAGE_BYTES / 1048576} MB`),
      { statusCode: 413, code: 'IMAGE_TOO_LARGE' }
    );
  }
  return { data: buffer.toString('base64'), mimeType, bytes: buffer.length };
}

// POST /v1/models3d — submit an async image-to-mesh job.
// { image | images[], model, format, generate_type, polygon_type, face_count, pbr, requireZdr }
async function handleModel3dSubmit(req, res) {
  const userId = req.userId;
  const body = req.body || {};

  try {
    if (!falService.isConfigured()) {
      return oaError(res, 503, '3D generation is not available on this deployment.', 'MODEL_3D_UNAVAILABLE');
    }

    const raw = Array.isArray(body.images) ? body.images : (body.image ? [body.image] : []);
    if (raw.length === 0) {
      return oaError(res, 400, 'image (or images[]) is required — 3D generation is image-to-mesh.', 'IMAGE_REQUIRED');
    }
    if (raw.length > MAX_3D_VIEWS) {
      return oaError(res, 400, `At most ${MAX_3D_VIEWS} views per request (front, back, left, right).`, 'TOO_MANY_INPUT_IMAGES');
    }
    const images = raw.map(input3dImage);
    const totalBytes = images.reduce((sum, img) => sum + img.bytes, 0);
    if (totalBytes > MAX_3D_INPUT_TOTAL_BYTES) {
      return oaError(
        res, 413,
        `The reference views total ${(totalBytes / 1048576).toFixed(1)} MB — the limit for one request is ${MAX_3D_INPUT_TOTAL_BYTES / 1048576} MB.`,
        'IMAGES_TOO_LARGE'
      );
    }

    const modelId = resolve3dModel(typeof body.model === 'string' ? body.model : null);
    // The same non-ZDR media gate the app and agent paths use. fal has no ZDR
    // endpoint, so a key belonging to a ZDR-required account is refused here
    // unless that account has opted into non-ZDR media.
    const requireZdr = await resolveRequireZdr(userId, body.requireZdr);
    const allowNonZdrMedia = await resolveAllowNonZdrMedia(userId, undefined);
    await assertMediaModelAllowed({ userId, modelId, requireZdr, allowNonZdrMedia });

    // Snake_case is the /v1 house style; camelCase is accepted alongside it so a
    // caller moving between the agent tool and this endpoint isn't tripped up.
    const normalized = normalize3dOptions(modelId, {
      generateType: body.generate_type ?? body.generateType,
      polygonType: body.polygon_type ?? body.polygonType,
      faceCount: body.face_count ?? body.faceCount,
      format: body.format,
      pbr: body.pbr === true || body.enable_pbr === true,
      extraViewCount: images.length - 1,
    });

    const providerCostUsd = fal3dCostUsd(modelId, normalized);
    // Flat developer-API rate, not the app's mesh markup — see the cost note at
    // the top of this file.
    const chargeUsd = billingService.apiBilledCost({ providerCostUsd });

    // Reserve BEFORE submitting, and note that this deliberately does NOT copy
    // the video path above, which submits first and reserves against the id the
    // provider returns. Video can get away with it because its cost is only
    // known after the fact; a mesh's is known exactly here, so reserving first
    // means an account that cannot cover the job never reaches the provider. The
    // other order bills us for a generation we then refuse to sell, and leaves
    // it running with no job row and no reservation to unwind.
    const refKey = `model3d:${userId}:${Date.now()}:${crypto.randomBytes(5).toString('hex')}`;
    try {
      await reservationService.reserveUsd(userId, chargeUsd, {
        kind: 'modelGen', refKey, meta: { modelId, ...normalized, views: images.length, source: 'api' },
      });
    } catch (e) {
      if (e?.code === 'INSUFFICIENT_FUNDS') {
        return res.status(402).json({
          error: {
            message: `Insufficient balance to reserve this 3D job (about $${chargeUsd.toFixed(2)}).`,
            type: 'invalid_request_error', code: 'INSUFFICIENT_FUNDS',
          },
        });
      }
      throw e;
    }

    let submit;
    try {
      submit = await falService.submitQueued(modelId, buildFal3dInput(modelId, { images, normalized }));
    } catch (submitErr) {
      await reservationService.releaseReservation(refKey, 'model3d-submit-failed').catch(() => {});
      throw submitErr;
    }

    await ApiMediaJob.create({
      userId, jobId: submit.requestId, kind: 'model3d', model: modelId,
      status: 'queued', reservationRefKey: refKey,
      format: normalized.format, mimeType: fal3dMime(normalized.format),
      chargeUsd, providerCostUsd,
      expiresAt: new Date(Date.now() + MODEL3D_JOB_TTL_MS),
    });

    return res.status(202).json({
      id: submit.requestId,
      object: 'model3d.job',
      status: 'queued',
      model: modelId,
      format: normalized.format,
      estimated_cost_usd: chargeUsd,
      created: Math.floor(Date.now() / 1000),
    });
  } catch (err) {
    return sendError(res, err, 'model3d_submit');
  }
}

// GET /v1/models3d/:id — poll status; on completion returns a short-lived URL.
async function handleModel3dStatus(req, res) {
  const userId = req.userId;
  const jobId = req.params.id;

  try {
    const job = await ApiMediaJob.findOne({ jobId, userId, kind: 'model3d' });
    if (!job) return oaError(res, 404, 'No such 3D job.', 'not_found');

    // Unlike the agent path, a completed job is re-servable: the mesh is in our
    // bucket until the retention sweep takes it, so a second poll mints a fresh
    // signed URL rather than reporting the bytes already gone.
    if (job.status === 'completed' && job.s3Key) {
      const url = await generateSignedUrl(job.s3Key, 'ai_generated', MODEL3D_URL_TTL_SEC);
      return res.json({
        id: jobId, object: 'model3d.job', status: 'completed', model: job.model,
        format: job.format, url, expires_at: Math.floor(Date.now() / 1000) + MODEL3D_URL_TTL_SEC,
      });
    }
    if (job.status === 'failed') {
      return res.json({ id: jobId, object: 'model3d.job', status: 'failed', error: { message: job.error || '3D generation failed.' } });
    }

    const poll = await falService.pollQueued(job.model, jobId);

    if (poll.status === 'completed') {
      // Claim the completion atomically so concurrent polls settle billing once.
      const claimed = await ApiMediaJob.findOneAndUpdate(
        { jobId, userId, status: { $in: ['queued', 'processing'] } },
        { status: 'processing' },
        { new: true }
      );

      const requested = job.format || fal3dModel(job.model)?.formats?.[0] || 'glb';
      const picked = fal3dOutputUrl(job.model, poll.result, requested);
      if (!picked) {
        await reservationService.releaseReservation(job.reservationRefKey, 'model3d-empty').catch(() => {});
        await ApiMediaJob.updateOne({ jobId, userId }, { status: 'failed', error: 'The 3D model returned no mesh.' });
        return res.json({ id: jobId, object: 'model3d.job', status: 'failed', error: { message: 'The 3D model returned no mesh.' } });
      }

      // The container decides the mime type, never the CDN — fal serves OBJ as
      // text/plain, and that label would follow the object into S3 and out to
      // the caller, who picks a file extension from it.
      const mimeType = fal3dMime(picked.format);
      let buffer;
      try {
        ({ buffer } = await falService.fetchOutput(picked.url, { maxBytes: MAX_MESH_BYTES, defaultMimeType: mimeType }));
      } catch (downloadErr) {
        logger.error('[v1 model3d] provider download failed', downloadErr.message);
        await reservationService.releaseReservation(job.reservationRefKey, 'model3d-download-failed').catch(() => {});
        const message = downloadErr?.code === 'FAL_OUTPUT_TOO_LARGE'
          ? `The generated mesh is larger than this endpoint will return (${(downloadErr.bytes / 1048576).toFixed(0)} MB). Set face_count to bound it.`
          : 'Downloading the mesh from the provider failed.';
        await ApiMediaJob.updateOne({ jobId, userId }, { status: 'failed', error: message });
        return res.json({ id: jobId, object: 'model3d.job', status: 'failed', error: { message } });
      }

      const up = await uploadToS3(
        { buffer, mimetype: mimeType, originalname: `model.${picked.format}`, size: buffer.length },
        'ai_generated', String(userId), 'api/models3d/'
      );

      if (claimed) {
        // Settle at the figure reserved. fal reports no per-request cost, so
        // this is not a reconciliation — the number was computed at submit from
        // the request options and carried on the job row.
        const settleUsd = Number(job.chargeUsd);
        try {
          if (Number.isFinite(settleUsd) && settleUsd > 0) {
            await reservationService.settleReservation(job.reservationRefKey, settleUsd, {
              providerCostUsd: Number(job.providerCostUsd) || 0, model: job.model, kind: 'modelGen', origin: 'api',
            });
          } else {
            await reservationService.releaseReservation(job.reservationRefKey, 'model3d-no-charge');
          }
        } catch (e) {
          if (e?.code === 'RESERVATION_NOT_FOUND' && Number.isFinite(settleUsd) && settleUsd > 0) {
            await billingService.chargeUsd(userId, settleUsd, {
              model: job.model, providerCostUsd: Number(job.providerCostUsd) || 0, kind: 'modelGen', origin: 'api',
            }).catch(() => {});
          } else {
            logger.warn('[v1 model3d] settle failed', e.message);
          }
        }
      }

      await ApiMediaJob.updateOne({ jobId, userId }, {
        status: 'completed', s3Key: up.s3Key, mimeType, format: picked.format,
      });
      await trackArtifact(userId, up, 'model3d');
      const url = await generateSignedUrl(up.s3Key, 'ai_generated', MODEL3D_URL_TTL_SEC);
      return res.json({
        id: jobId, object: 'model3d.job', status: 'completed', model: job.model,
        format: picked.format, url, expires_at: Math.floor(Date.now() / 1000) + MODEL3D_URL_TTL_SEC,
      });
    }

    if (poll.status === 'failed') {
      await reservationService.releaseReservation(job.reservationRefKey, 'model3d-failed').catch(() => {});
      await ApiMediaJob.updateOne({ jobId, userId }, { status: 'failed', error: String(poll.message || '').slice(0, 500) });
      return res.json({ id: jobId, object: 'model3d.job', status: 'failed', error: { message: poll.message || '3D generation failed.' } });
    }

    if (job.status === 'queued' && poll.status === 'processing') {
      await ApiMediaJob.updateOne({ jobId, userId }, { status: 'processing' });
    }
    return res.json({ id: jobId, object: 'model3d.job', status: poll.status === 'queued' ? 'queued' : 'processing' });
  } catch (err) {
    // A job fal has forgotten will never resolve — stop the caller polling it.
    if (err?.code === 'FAL_JOB_NOT_FOUND') {
      const job = await ApiMediaJob.findOne({ jobId, userId, kind: 'model3d' }).catch(() => null);
      await reservationService.releaseReservation(job?.reservationRefKey, 'model3d-vanished').catch(() => {});
      await ApiMediaJob.updateOne({ jobId, userId }, { status: 'failed', error: 'The provider no longer has this job.' }).catch(() => {});
      return oaError(res, 404, 'The provider no longer has this job.', 'not_found');
    }
    return sendError(res, err, 'model3d_status');
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

module.exports = {
  handleImageGeneration,
  handleVideoSubmit,
  handleVideoStatus,
  handleModel3dSubmit,
  handleModel3dStatus,
  // Exported for test/v1Model3d.test.js — pure input decoding, asserted without
  // touching fal, S3 or Mongo.
  input3dImage,
  MAX_3D_VIEWS,
  MAX_3D_INPUT_TOTAL_BYTES,
};
