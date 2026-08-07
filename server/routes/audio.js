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
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');
const logger = require('../utils/logger');
const Sentry = require('../instrument');
const { authenticate } = require('../middleware/auth');
const audioService = require('../services/audioService');
const { assertFeatureAllowed, EntitlementError, sendEntitlementError } = require('../services/entitlementService');
const { requireDailyCap } = require('../middleware/entitlement');
const { checkCreditBalance } = require('../middleware/checkBalance');
// The non-ZDR media gate lives in chatController alongside the image/video
// paths it was written for; /sfx is the fourth caller (agentMediaHandler
// imports it the same way).
const { assertMediaModelAllowed, resolveAllowNonZdrMedia } = require('../controllers/chatController');
// Speech is the fifth caller of that gate — fal's voices have no ZDR endpoint
// either, so they are gated like any other non-ZDR media model (see ttsZdrBlocked).
const { isFalAudioModel } = require('../data/falModels');
// The voice picker's audition clips: identical for every account, so they are
// synthesized once and cached globally rather than re-bought on every tap.
const voicePreviewStore = require('../services/voicePreviewStore');
const { t, SUPPORTED } = require('../i18n');

const router = express.Router();

/**
 * Narrow a client-supplied language tag to a catalog we actually ship.
 *
 * The preview sample is the one string on this router the client chooses the
 * *language* of but not the *text* of, so the tag is treated as untrusted input:
 * region stripped (`es-MX` → `es`), matched against SUPPORTED, and anything else
 * dropped so the caller falls back to the request's own language. Returns null
 * when there's no match — never the raw tag, which would land in a cache key.
 */
function normalizeSampleLocale(tag) {
  if (!tag || typeof tag !== 'string') return null;
  const base = tag.trim().toLowerCase().split(/[-_]/)[0];
  return SUPPORTED.includes(base) ? base : null;
}

// Voice chat (STT + TTS) is a paid-tier feature — gate every audio call on the
// 'voice' entitlement. Returns true if it already sent a 403 so the caller can
// bail. The provider/billing logic lives in services/audioService.js (shared
// with the developer /v1 audio endpoints).
async function voiceGateBlocked(req, res) {
  try {
    await assertFeatureAllowed(req.user._id, 'voice');
    return false;
  } catch (err) {
    if (err instanceof EntitlementError) {
      const sent = sendEntitlementError(res, err);
      if (sent) return true;
    }
    throw err;
  }
}

/**
 * Map a fal failure onto the surface's own error code.
 *
 * fal now serves three of this file's four generation routes, and each one has
 * its own vocabulary the client already branches on (SFX_*, MUSIC_*, TTS_*).
 * Rather than teach every client three new provider-shaped codes, translate
 * here: an unset key, a rejected key, our own balance running dry and fal
 * throttling us are all *our* outage, and the user gets one "try again shortly".
 * The distinction survives in the log and in Sentry, because the remediations
 * are completely different.
 *
 * Returns null when the error isn't fal's, so the caller falls through to its
 * own handling. (/sfx keeps its longer inline version — it is the route the
 * enforcement test reads.)
 *
 * @returns {{ status: number, code: string } | null}
 */
function falErrorFor(err, { op, unavailable, timeout, failed }) {
  const code = err?.code;
  if (code === 'FAL_UNCONFIGURED' || code === 'FAL_AUTH'
    || code === 'FAL_BALANCE_EXHAUSTED' || code === 'FAL_RATE_LIMITED') {
    if (code === 'FAL_BALANCE_EXHAUSTED') {
      // Loud, and captured: this one silently disables the feature for every
      // user at once, and nothing else in the system will notice.
      Sentry.captureException(err, { level: 'error', tags: { op, reason: 'fal_balance' } });
      logger.error(`[${op}] fal balance exhausted — this feature is down until it is topped up`);
    }
    return { status: 503, code: unavailable };
  }
  if (code === 'FAL_TIMEOUT') return { status: 504, code: timeout };
  if (code === 'FAL_FAILED' || code === 'FAL_BAD_OUTPUT' || code === 'FAL_OUTPUT_TOO_LARGE'
    || code === 'FAL_MODEL_UNSUPPORTED') {
    return { status: 502, code: failed };
  }
  return null;
}

/**
 * The non-ZDR gate for speech, and the reason it exists.
 *
 * Every voice this server offered until now was ZDR or ran in a confidential
 * enclave — `server.js` filters the tts/stt catalogs on `hasZdrCoverage`, and
 * the Voice card's shield says as much. fal's voices (ElevenLabs, Kokoro,
 * Orpheus) are the first that are neither, so they are gated exactly the way a
 * non-ZDR image or video model is: a default account (Require ZDR on, non-ZDR
 * media off) cannot use one, and gets the same 403 with the same code, pointing
 * at the same setting. The picker hides them under those settings too — this is
 * the server-side half, so a tampered client gains nothing.
 *
 * A ZDR/TEE model short-circuits before any of this, so the confidential default
 * path is untouched: no extra pref reads, no behaviour change.
 *
 * @returns true when it has already sent a 403 and the caller should bail.
 */
async function ttsZdrBlocked(req, res, modelId) {
  if (!isFalAudioModel(modelId)) return false;
  try {
    const userId = req.user._id;
    const requireZdr = await audioService.resolveRequireZdr(userId, req.body?.requireZdr);
    const allowNonZdrMedia = await resolveAllowNonZdrMedia(userId, req.body?.allowNonZdrMedia);
    await assertMediaModelAllowed({ userId, modelId, requireZdr, allowNonZdrMedia });
    return false;
  } catch (err) {
    if (err?.code === 'ZDR_MEDIA_BLOCKED') {
      res.status(403).json({ message: err.message, code: 'ZDR_MEDIA_BLOCKED', modelId });
      return true;
    }
    throw err;
  }
}

// ── POST /api/audio/transcribe ────────────────────────────────────────────────
// body: { audioBase64, format, language?, sttModelId?, requireZdr? }  →  { text }
router.post('/transcribe', authenticate, async (req, res) => {
  try {
    if (await voiceGateBlocked(req, res)) return;
    const { audioBase64, format, language, sttModelId } = req.body || {};
    const requireZdr = await audioService.resolveRequireZdr(req.user._id, req.body?.requireZdr);
    const { text } = await audioService.transcribe({
      userId: req.user._id, audioBase64, format, language, modelId: sttModelId, requireZdr,
    });
    return res.json({ text });
  } catch (err) {
    if (err?.code === 'AUDIO_REQUIRED') return res.status(400).json({ message: req.t('errors.audioRequired') });
    if (err?.code === 'STT_FAILED') return res.status(502).json({ message: req.t('errors.transcriptionFailed'), code: 'STT_FAILED' });
    if (err?.code === 'ZDR_KEY_UNAVAILABLE') return res.status(503).json({ message: req.t('errors.zdrKeyUnavailable'), code: 'ZDR_KEY_UNAVAILABLE' });
    if (err?.code === 'INSUFFICIENT_FUNDS') return res.status(402).json({ message: req.t('errors.insufficientBalance'), code: 'INSUFFICIENT_FUNDS' });
    Sentry.captureException(err, { tags: { op: 'audio_transcribe' } });
    logger.error('[audio/transcribe]', err);
    return res.status(500).json({ message: req.t('errors.transcriptionFailed') });
  }
});

// ── POST /api/audio/speech ────────────────────────────────────────────────────
// body: { text, ttsModelId?, voice?, format?, requireZdr? }  →  { audioBase64, mimeType }
router.post('/speech', authenticate, async (req, res) => {
  try {
    if (await voiceGateBlocked(req, res)) return;
    const { text, ttsModelId, voice, format } = req.body || {};
    if (await ttsZdrBlocked(req, res, ttsModelId)) return;
    const requireZdr = await audioService.resolveRequireZdr(req.user._id, req.body?.requireZdr);
    const { buffer, mimeType } = await audioService.synthesizeSpeech({
      userId: req.user._id, text, voice, format, modelId: ttsModelId, requireZdr,
    });
    return res.json({ audioBase64: buffer.toString('base64'), mimeType });
  } catch (err) {
    if (err?.code === 'TEXT_REQUIRED') return res.status(400).json({ message: req.t('errors.textRequired') });
    if (err?.code === 'TTS_FAILED') return res.status(502).json({ message: req.t('errors.ttsFailed'), code: 'TTS_FAILED' });
    if (err?.code === 'ZDR_KEY_UNAVAILABLE') return res.status(503).json({ message: req.t('errors.zdrKeyUnavailable'), code: 'ZDR_KEY_UNAVAILABLE' });
    // A voice that doesn't belong to the chosen model. Its own 400 rather than a
    // generic failure: the fix is picking a voice, not retrying.
    if (err?.code === 'VOICE_UNSUPPORTED') return res.status(400).json({ message: req.t('errors.ttsFailed'), code: 'VOICE_UNSUPPORTED' });
    const falErr = falErrorFor(err, {
      op: 'audio_speech', unavailable: 'TTS_UNAVAILABLE', timeout: 'TTS_TIMEOUT', failed: 'TTS_FAILED',
    });
    if (falErr) return res.status(falErr.status).json({ message: req.t('errors.ttsFailed'), code: falErr.code });
    Sentry.captureException(err, { tags: { op: 'audio_speech' } });
    logger.error('[audio/speech]', err);
    return res.status(500).json({ message: req.t('errors.ttsFailed') });
  }
});

// ── POST /api/audio/speech/stream ─────────────────────────────────────────────
// body: { text, ttsModelId?, voice?, requireZdr? }  →  audio/mpeg byte stream
//
// Same synthesis as /speech, but the bytes are piped through as the provider
// emits them instead of being buffered into a base64 JSON field. That buffering
// is worth ~1s per spoken sentence on a provider that streams (Deepgram Aura-2
// returns its first byte in ~0.5s regardless of input length), which is the
// difference between a conversation and a walkie-talkie.
//
// It only pays off on providers that stream. Some — including the current
// confidential-compute default, tinfoil/qwen3-tts — synthesize the whole clip
// before sending anything, and there this endpoint is simply equivalent to the
// buffered one. Nothing breaks; there's just nothing to gain.
//
// A 409 here means "this model can't stream", not "something failed" — the
// client is expected to fall back to /speech rather than show an error.
router.post('/speech/stream', authenticate, async (req, res) => {
  let stream;
  try {
    if (await voiceGateBlocked(req, res)) return;
    const { text, ttsModelId, voice } = req.body || {};
    if (await ttsZdrBlocked(req, res, ttsModelId)) return;
    const requireZdr = await audioService.resolveRequireZdr(req.user._id, req.body?.requireZdr);
    stream = await audioService.synthesizeSpeechStream({
      userId: req.user._id, text, voice, modelId: ttsModelId, requireZdr,
    });
  } catch (err) {
    if (err?.code === 'TEXT_REQUIRED') return res.status(400).json({ message: req.t('errors.textRequired') });
    if (err?.code === 'TTS_STREAM_UNSUPPORTED') return res.status(409).json({ code: 'TTS_STREAM_UNSUPPORTED' });
    if (err?.code === 'TTS_FAILED') return res.status(502).json({ message: req.t('errors.ttsFailed'), code: 'TTS_FAILED' });
    if (err?.code === 'ZDR_KEY_UNAVAILABLE') return res.status(503).json({ message: req.t('errors.zdrKeyUnavailable'), code: 'ZDR_KEY_UNAVAILABLE' });
    Sentry.captureException(err, { tags: { op: 'audio_speech_stream' } });
    logger.error('[audio/speech/stream]', err);
    return res.status(500).json({ message: req.t('errors.ttsFailed') });
  }

  // Headers go out before the first byte so the client can start decoding
  // immediately; nothing below may switch to a JSON error response.
  res.setHeader('Content-Type', stream.mimeType);
  res.setHeader('Cache-Control', 'no-store');
  // Chunked, and explicitly un-buffered by any intermediary — a proxy that
  // accumulates the body would silently undo the entire point of this route.
  res.setHeader('X-Accel-Buffering', 'no');

  try {
    const body = stream.response.body;
    if (!body) throw new Error('provider returned no body');
    // Node's Readable.fromWeb bridges undici's WHATWG stream to the Express
    // response, and pipeline() propagates client disconnects upstream so an
    // abandoned reply stops costing money mid-sentence.
    await pipeline(Readable.fromWeb(body), res);
  } catch (err) {
    // Mid-stream failure: the status line is long gone, so the only honest
    // thing left is to end the response and let the client's decoder see a
    // truncated clip.
    logger.error('[audio/speech/stream] mid-stream', err?.message || err);
    Sentry.captureException(err, { level: 'warning', tags: { op: 'audio_speech_stream_pipe' } });
    try { res.end(); } catch { /* already destroyed */ }
  } finally {
    // Bill what the provider actually generated, whether or not the client
    // stayed to listen — the cost was incurred either way.
    stream.settle();
  }
});

// ── POST /api/audio/voice-preview ─────────────────────────────────────────────
// body: { ttsModelId, voice, locale? }  →  { audioBase64, mimeType, cached }
//
// The audition clip behind the ▶ button in the voice picker, served from a
// GLOBAL cache: synthesized once for a given (model, voice, locale) and then
// replayed for every account, forever, free. Previously every tap was a fresh
// paid synthesis, so answering "which of these 90 voices do I want?" cost 90
// TTS calls — per user, every time.
//
// NOTE WHAT IS NOT IN THE BODY: the text. It cannot be, and that is the whole
// design. A cache shared across accounts may only ever hold content that is the
// same for everyone, so the sentence comes from this server's own i18n catalog
// (`audio.voicePreviewSample`) and the client sends nothing but a locale. That
// makes the cached clip an app asset we happen to mint lazily rather than a
// cross-account store of user text — see the header of services/voicePreviewStore.js
// before touching this. Free text belongs on /speech, which caches nothing.
//
// Both gates run before the cache read, not after: a preview is exactly as
// entitlement- and ZDR-gated as the synthesis it stands in for, and a cache hit
// must not become a way around either.
router.post('/voice-preview', authenticate, async (req, res) => {
  try {
    if (await voiceGateBlocked(req, res)) return;
    const { ttsModelId, voice, locale } = req.body || {};
    if (await ttsZdrBlocked(req, res, ttsModelId)) return;

    // Resolve to exactly what synthesis will run. The cache keys on the resolved
    // values, not the requested ones, or `voice: undefined` and the model's own
    // default voice would mint two entries holding the identical clip.
    const model = audioService.resolveAudioModel(ttsModelId, audioService.DEFAULT_TTS_MODEL);
    const wireVoice = audioService.resolveVoice(voice, model);
    const format = audioService.resolveResponseFormat(model, undefined);
    const lang = normalizeSampleLocale(locale) || normalizeSampleLocale(req.language) || 'en';
    const text = t('audio.voicePreviewSample', lang);

    const { base64, mimeType, cached } = await voicePreviewStore.getOrSynthesize(
      { model, voice: wireVoice, format, text, lang },
      async () => {
        const requireZdr = await audioService.resolveRequireZdr(req.user._id, req.body?.requireZdr);
        // Charged like any other synthesis — someone has to pay the provider the
        // first time. Everyone after them rides the cache for nothing.
        return audioService.synthesizeSpeech({
          userId: req.user._id, text, voice: wireVoice, modelId: model, requireZdr,
        });
      },
    );
    return res.json({ audioBase64: base64, mimeType, cached });
  } catch (err) {
    if (err?.code === 'TTS_FAILED') return res.status(502).json({ message: req.t('errors.ttsFailed'), code: 'TTS_FAILED' });
    if (err?.code === 'ZDR_KEY_UNAVAILABLE') return res.status(503).json({ message: req.t('errors.zdrKeyUnavailable'), code: 'ZDR_KEY_UNAVAILABLE' });
    if (err?.code === 'VOICE_UNSUPPORTED') return res.status(400).json({ message: req.t('errors.ttsFailed'), code: 'VOICE_UNSUPPORTED' });
    const falErr = falErrorFor(err, {
      op: 'audio_voice_preview', unavailable: 'TTS_UNAVAILABLE', timeout: 'TTS_TIMEOUT', failed: 'TTS_FAILED',
    });
    if (falErr) return res.status(falErr.status).json({ message: req.t('errors.ttsFailed'), code: falErr.code });
    Sentry.captureException(err, { tags: { op: 'audio_voice_preview' } });
    logger.error('[audio/voice-preview]', err);
    return res.status(500).json({ message: req.t('errors.ttsFailed') });
  }
});

// ── POST /api/audio/music ─────────────────────────────────────────────────────
// body: { prompt, musicModelId? }  →  { audioBase64, mimeType, model }
//
// Fixed-price per call ($0.04 clip / $0.08 song before markup), which is what
// the extra middleware is for: TTS is fractions of a cent and needs neither a
// daily cap nor a balance pre-check, music needs both.
//
// No ZDR gate. That is a deliberate exception, not an omission — see the
// carve-out comment on audioService.generateMusic. Neither Lyria SKU has a ZDR
// endpoint and no confidential-compute music model exists, so gating this the
// way image/video generation is gated would mean nobody can make music without
// first flipping a privacy pref. The prompt is instead sent unattributed, and
// the client states that plainly before the user generates.
//
// Balance is checked against the *resolved* model rather than a flat estimate,
// so a clip isn't blocked by the price of a full song.
const musicBalanceGate = (req, res, next) => {
  let estimate;
  try {
    // Length is part of the price now that the catalog includes models fal
    // meters by the minute, so the gate is given the same duration the
    // generation will use rather than a flat per-model figure.
    estimate = audioService.musicChargeEstimateUsd(
      audioService.resolveMusicModel(req.body?.musicModelId),
      req.body?.duration,
    );
  } catch (err) {
    if (err?.code === 'MUSIC_MODEL_UNSUPPORTED') {
      return res.status(400).json({ message: req.t('errors.musicModelUnsupported'), code: 'MUSIC_MODEL_UNSUPPORTED' });
    }
    return next(err);
  }
  return checkCreditBalance(estimate)(req, res, next);
};

router.post('/music', authenticate, requireDailyCap('musicGen'), musicBalanceGate, async (req, res) => {
  try {
    const { prompt, musicModelId, duration } = req.body || {};
    const { buffer, mimeType, model, durationSeconds } = await audioService.generateMusic({
      userId: req.user._id, prompt, modelId: musicModelId, duration,
    });
    // `durationSeconds` is present only for the models that take a length —
    // a Lyria SKU *is* its length, so there is nothing to report back.
    return res.json({ audioBase64: buffer.toString('base64'), mimeType, model, ...(durationSeconds ? { durationSeconds } : {}) });
  } catch (err) {
    if (err?.code === 'PROMPT_REQUIRED') return res.status(400).json({ message: req.t('errors.promptRequired'), code: 'PROMPT_REQUIRED' });
    if (err?.code === 'MUSIC_MODEL_UNSUPPORTED') return res.status(400).json({ message: req.t('errors.musicModelUnsupported'), code: 'MUSIC_MODEL_UNSUPPORTED' });
    if (err?.code === 'MUSIC_TIMEOUT') return res.status(504).json({ message: req.t('errors.musicTimeout'), code: 'MUSIC_TIMEOUT' });
    if (err?.code === 'MUSIC_EMPTY') return res.status(502).json({ message: req.t('errors.musicEmpty'), code: 'MUSIC_EMPTY' });
    if (err?.code === 'MUSIC_FAILED') return res.status(502).json({ message: req.t('errors.musicFailed'), code: 'MUSIC_FAILED' });
    if (err?.code === 'INSUFFICIENT_FUNDS') return res.status(402).json({ message: req.t('errors.insufficientBalance'), code: 'INSUFFICIENT_FUNDS' });
    // The music catalog spans two providers now, so a fal outage has to speak
    // the same MUSIC_* vocabulary the OpenRouter path does.
    const falErr = falErrorFor(err, {
      op: 'audio_music', unavailable: 'MUSIC_FAILED', timeout: 'MUSIC_TIMEOUT', failed: 'MUSIC_FAILED',
    });
    if (falErr) {
      return res.status(falErr.status).json({
        message: req.t(falErr.code === 'MUSIC_TIMEOUT' ? 'errors.musicTimeout' : 'errors.musicFailed'),
        code: falErr.code,
      });
    }
    Sentry.captureException(err, { tags: { op: 'audio_music' } });
    logger.error('[audio/music]', err);
    return res.status(500).json({ message: req.t('errors.musicFailed') });
  }
});

// ── POST /api/audio/sfx ───────────────────────────────────────────────────────
// body: { prompt, sfxModelId?, duration?, requireZdr?, allowNonZdrMedia? }
//   →  { audioBase64, mimeType, model, durationSeconds }
//
// Same fixed-price shape as /music, and deliberately NOT the same privacy
// shape. Music skips assertMediaModelAllowed because no music model anywhere in
// the catalog has a ZDR endpoint, so gating it would hand every default account
// an empty picker. Sound effects have no such excuse — fal is simply a non-ZDR
// provider, which is the exact situation assertMediaModelAllowed exists for. So
// this route gates like image and video generation do: a ZDR account (the
// default) gets a 403 ZDR_MEDIA_BLOCKED until it opts in via allowNonZdrMedia.
//
// The gate runs before the balance check on purpose. A blocked user must not
// have their balance probed for a call that was never going to happen, and the
// 403 is the more useful error to surface first.
const sfxBalanceGate = (req, res, next) => {
  let estimate;
  try {
    const sfxModel = audioService.resolveSfxModel(req.body?.sfxModelId);
    // Same reason as the music gate: one of the effect models is billed by the
    // second, so the estimate has to know how long the effect will be.
    estimate = audioService.sfxChargeEstimateUsd(
      sfxModel,
      audioService.resolveSfxDuration(req.body?.duration, sfxModel),
    );
  } catch (err) {
    if (err?.code === 'SFX_MODEL_UNSUPPORTED') {
      return res.status(400).json({ message: req.t('errors.sfxModelUnsupported'), code: 'SFX_MODEL_UNSUPPORTED' });
    }
    return next(err);
  }
  return checkCreditBalance(estimate)(req, res, next);
};

router.post('/sfx', authenticate, requireDailyCap('sfxGen'), sfxBalanceGate, async (req, res) => {
  try {
    const { prompt, sfxModelId, duration } = req.body || {};
    const userId = req.user._id;
    const modelId = audioService.resolveSfxModel(sfxModelId);

    const requireZdr = await audioService.resolveRequireZdr(userId, req.body?.requireZdr);
    const allowNonZdrMedia = await resolveAllowNonZdrMedia(userId, req.body?.allowNonZdrMedia);
    await assertMediaModelAllowed({ userId, modelId, requireZdr, allowNonZdrMedia });

    const { buffer, mimeType, model, durationSeconds } = await audioService.generateSfx({
      userId, prompt, modelId, duration,
    });
    return res.json({ audioBase64: buffer.toString('base64'), mimeType, model, durationSeconds });
  } catch (err) {
    if (err?.code === 'PROMPT_REQUIRED') return res.status(400).json({ message: req.t('errors.promptRequired'), code: 'PROMPT_REQUIRED' });
    if (err?.code === 'SFX_MODEL_UNSUPPORTED') return res.status(400).json({ message: req.t('errors.sfxModelUnsupported'), code: 'SFX_MODEL_UNSUPPORTED' });
    if (err?.code === 'ZDR_MEDIA_BLOCKED') return res.status(403).json({ message: err.message, code: 'ZDR_MEDIA_BLOCKED', modelId: err.modelId });
    // fal being unreachable, unconfigured or rate-limiting us is our outage, not
    // the user's bad prompt — 503 so the client can say "try again" rather than
    // "that didn't work".
    // All four are our problem, not the user's — an unset key, a rejected key,
    // our own fal balance running dry, or fal throttling us. The user sees one
    // "try again shortly"; the distinction lives in the log and in Sentry,
    // because the remediations are completely different.
    if (err?.code === 'FAL_UNCONFIGURED' || err?.code === 'FAL_AUTH'
      || err?.code === 'FAL_BALANCE_EXHAUSTED' || err?.code === 'FAL_RATE_LIMITED') {
      if (err.code === 'FAL_BALANCE_EXHAUSTED') {
        // Loud, and captured: this one silently disables the whole feature for
        // every user at once, and nothing else in the system will notice.
        Sentry.captureException(err, { level: 'error', tags: { op: 'audio_sfx', reason: 'fal_balance' } });
        logger.error('[audio/sfx] fal balance exhausted — sound effects are down until it is topped up');
      }
      return res.status(503).json({ message: req.t('errors.sfxUnavailable'), code: 'SFX_UNAVAILABLE' });
    }
    if (err?.code === 'FAL_TIMEOUT') return res.status(504).json({ message: req.t('errors.sfxTimeout'), code: 'SFX_TIMEOUT' });
    if (err?.code === 'SFX_EMPTY') return res.status(502).json({ message: req.t('errors.sfxEmpty'), code: 'SFX_EMPTY' });
    if (err?.code === 'FAL_FAILED' || err?.code === 'FAL_BAD_OUTPUT' || err?.code === 'FAL_OUTPUT_TOO_LARGE') {
      return res.status(502).json({ message: req.t('errors.sfxFailed'), code: 'SFX_FAILED' });
    }
    if (err?.code === 'INSUFFICIENT_FUNDS') return res.status(402).json({ message: req.t('errors.insufficientBalance'), code: 'INSUFFICIENT_FUNDS' });
    Sentry.captureException(err, { tags: { op: 'audio_sfx' } });
    logger.error('[audio/sfx]', err);
    return res.status(500).json({ message: req.t('errors.sfxFailed') });
  }
});

module.exports = router;
