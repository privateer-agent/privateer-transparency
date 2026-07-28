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

const router = express.Router();

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
    const requireZdr = await audioService.resolveRequireZdr(req.user._id, req.body?.requireZdr);
    const { buffer, mimeType } = await audioService.synthesizeSpeech({
      userId: req.user._id, text, voice, format, modelId: ttsModelId, requireZdr,
    });
    return res.json({ audioBase64: buffer.toString('base64'), mimeType });
  } catch (err) {
    if (err?.code === 'TEXT_REQUIRED') return res.status(400).json({ message: req.t('errors.textRequired') });
    if (err?.code === 'TTS_FAILED') return res.status(502).json({ message: req.t('errors.ttsFailed'), code: 'TTS_FAILED' });
    if (err?.code === 'ZDR_KEY_UNAVAILABLE') return res.status(503).json({ message: req.t('errors.zdrKeyUnavailable'), code: 'ZDR_KEY_UNAVAILABLE' });
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
    estimate = audioService.musicChargeEstimateUsd(audioService.resolveMusicModel(req.body?.musicModelId));
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
    const { prompt, musicModelId } = req.body || {};
    const { buffer, mimeType, model } = await audioService.generateMusic({
      userId: req.user._id, prompt, modelId: musicModelId,
    });
    return res.json({ audioBase64: buffer.toString('base64'), mimeType, model });
  } catch (err) {
    if (err?.code === 'PROMPT_REQUIRED') return res.status(400).json({ message: req.t('errors.promptRequired'), code: 'PROMPT_REQUIRED' });
    if (err?.code === 'MUSIC_MODEL_UNSUPPORTED') return res.status(400).json({ message: req.t('errors.musicModelUnsupported'), code: 'MUSIC_MODEL_UNSUPPORTED' });
    if (err?.code === 'MUSIC_TIMEOUT') return res.status(504).json({ message: req.t('errors.musicTimeout'), code: 'MUSIC_TIMEOUT' });
    if (err?.code === 'MUSIC_EMPTY') return res.status(502).json({ message: req.t('errors.musicEmpty'), code: 'MUSIC_EMPTY' });
    if (err?.code === 'MUSIC_FAILED') return res.status(502).json({ message: req.t('errors.musicFailed'), code: 'MUSIC_FAILED' });
    if (err?.code === 'INSUFFICIENT_FUNDS') return res.status(402).json({ message: req.t('errors.insufficientBalance'), code: 'INSUFFICIENT_FUNDS' });
    Sentry.captureException(err, { tags: { op: 'audio_music' } });
    logger.error('[audio/music]', err);
    return res.status(500).json({ message: req.t('errors.musicFailed') });
  }
});

module.exports = router;
