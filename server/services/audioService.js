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
 * Shared speech-to-text / text-to-speech logic.
 *
 * Extracted from routes/audio.js so both the app voice path and the developer
 * /v1 audio endpoints (routes/v1.js) go through one provider-branched
 * implementation: NEAR AI / Tinfoil confidential enclaves, else OpenRouter's
 * dedicated /audio/transcriptions and /audio/speech endpoints. Billing is done
 * here (kinds 'stt' / 'tts'); callers just shape the HTTP response.
 *
 * E2EE note (CLAUDE.md §5): recorded audio (STT) and reply text (TTS) transit
 * to the provider exactly like chat inference — forwarded, never persisted.
 */
const logger = require('../utils/logger');
const Sentry = require('../instrument');
const billingService = require('./billingService');
const inferenceService = require('./inferenceService');
const nearAiService = require('./nearAiService');
const tinfoilService = require('./tinfoilService');
const UserStoragePrefs = require('../models/userStoragePrefsModel');

const OPENROUTER_BASE = process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1';

const DEFAULT_STT_MODEL = process.env.DEFAULT_STT_MODEL || 'openai/whisper-1';
const DEFAULT_TTS_MODEL = process.env.DEFAULT_TTS_MODEL || 'google/gemini-3.1-flash-tts-preview';
const DEFAULT_TTS_VOICE = process.env.DEFAULT_TTS_VOICE || 'Zephyr';

// Audio carries user content, so it obeys ZDR like chat. Request wins; else pref.
async function resolveRequireZdr(userId, requested) {
  if (typeof requested === 'boolean') return requested;
  try {
    const prefs = await UserStoragePrefs.findOne({ userId }).lean();
    if (prefs && prefs.requireZdr === false) return false;
  } catch (_) { /* non-fatal */ }
  return true;
}

// ── Cost calculation ─────────────────────────────────────────────────────────
//
// TRANSPARENCY REPO OMISSION — proprietary billing logic, intentionally redacted.
//
// Audio billing (our markup factor applied to the provider-reported cost) is
// part of Privateer's CLOSED codebase and is NOT published here. Per our policy
// we open the "plaintext trust boundary" only; billing operates on provider
// cost, token/second counts, and model IDs — it never sees, stores, or transmits
// user audio or text — so it adds nothing to the privacy audit. The helpers
// below are stubbed to preserve call-site readability.

async function chargeAudio(/* userId, providerCostUsd, { model, kind } */) {
  /* omitted: provider cost × markup, closed billing logic */
}

async function fetchGenerationCost(/* generationId, useZdrKey */) {
  return null; // omitted: provider-cost lookup
}

// ── Audio containers ─────────────────────────────────────────────────────────

// Prepend a canonical 44-byte RIFF/WAVE header to raw little-endian PCM.
function pcmToWav(pcm, sampleRate, channels, bitsPerSample) {
  const blockAlign = channels * (bitsPerSample / 8);
  const byteRate = sampleRate * blockAlign;
  const header = Buffer.alloc(44);
  header.write('RIFF', 0);
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write('WAVE', 8);
  header.write('fmt ', 12);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(channels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(byteRate, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bitsPerSample, 34);
  header.write('data', 36);
  header.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([header, pcm]);
}

/**
 * Transcribe audio → { text, model }. Bills 'stt'. Throws {statusCode,code} on
 * bad input / provider failure / ZDR-key / insufficient funds.
 */
async function transcribe({ userId, audioBase64, format, language, modelId, requireZdr = true, billingMarkup }) {
  if (!audioBase64 || typeof audioBase64 !== 'string') {
    throw Object.assign(new Error('audio is required'), { statusCode: 400, code: 'AUDIO_REQUIRED' });
  }
  const model = (typeof modelId === 'string' && modelId.includes('/')) ? modelId : DEFAULT_STT_MODEL;

  if (nearAiService.isNearModel(model)) {
    const { text, providerCostUsd } = await nearAiService.transcribe({ audioBase64, format, language, modelId: model });
    await chargeAudio(userId, providerCostUsd, { model, kind: 'stt', markup: billingMarkup });
    return { text, model };
  }
  if (tinfoilService.isTinfoilModel(model)) {
    const { text, providerCostUsd } = await tinfoilService.transcribe({ audioBase64, format, language, modelId: model });
    await chargeAudio(userId, providerCostUsd, { model, kind: 'stt', markup: billingMarkup });
    return { text, model };
  }

  const body = { model, input_audio: { data: audioBase64, format: format || 'm4a' }, temperature: 0, ...(language ? { language } : {}) };
  const r = await fetch(`${OPENROUTER_BASE}/audio/transcriptions`, {
    method: 'POST',
    headers: { ...inferenceService.orHeaders(requireZdr), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const errText = await r.text().catch(() => '');
    logger.error('[audioService.transcribe] OpenRouter error', r.status, errText);
    throw Object.assign(new Error('transcription failed'), { statusCode: 502, code: 'STT_FAILED' });
  }
  const data = await r.json();
  const text = typeof data?.text === 'string' ? data.text : '';
  let costUsd = Number(data?.usage?.cost);
  if (!Number.isFinite(costUsd) || costUsd <= 0) {
    costUsd = await fetchGenerationCost(r.headers.get('x-generation-id'), requireZdr);
  }
  await chargeAudio(userId, costUsd, { model, kind: 'stt', markup: billingMarkup });
  return { text, model };
}

/**
 * Synthesize speech → { buffer, mimeType, model }. Bills 'tts' in the
 * background. Throws {statusCode,code} on bad input / provider failure.
 */
async function synthesizeSpeech({ userId, text, voice, format, modelId, requireZdr = true, billingMarkup }) {
  if (!text || typeof text !== 'string' || !text.trim()) {
    throw Object.assign(new Error('text is required'), { statusCode: 400, code: 'TEXT_REQUIRED' });
  }
  const model = (typeof modelId === 'string' && modelId.includes('/')) ? modelId : DEFAULT_TTS_MODEL;
  const responseFormat = format === 'pcm' ? 'pcm' : 'mp3';

  let r;
  let tinfoilCostUsd = null;
  if (tinfoilService.isTinfoilModel(model)) {
    const out = await tinfoilService.speechRequest({ text: text.slice(0, 8000), voice, responseFormat, modelId: model });
    r = out.response;
    tinfoilCostUsd = out.providerCostUsd;
  } else {
    r = await fetch(`${OPENROUTER_BASE}/audio/speech`, {
      method: 'POST',
      headers: { ...inferenceService.orHeaders(requireZdr), 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, input: text.slice(0, 8000), voice: voice || DEFAULT_TTS_VOICE, response_format: responseFormat }),
    });
  }
  if (!r.ok) {
    const errText = await r.text().catch(() => '');
    logger.error('[audioService.speech] OpenRouter error', r.status, errText);
    throw Object.assign(new Error('speech synthesis failed'), { statusCode: 502, code: 'TTS_FAILED' });
  }

  const generationId = r.headers.get('x-generation-id');
  let buffer = Buffer.from(await r.arrayBuffer());
  const upstreamType = (r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  let mimeType;
  if (upstreamType.includes('mpeg') || upstreamType.includes('mp3')) {
    mimeType = 'audio/mpeg';
  } else if (upstreamType.includes('wav') || upstreamType.includes('wave')) {
    mimeType = 'audio/wav';
  } else if (upstreamType.startsWith('audio/') && !upstreamType.includes('pcm') && !upstreamType.includes('l16') && !upstreamType.includes('basic')) {
    mimeType = upstreamType;
  } else {
    logger.warn('[audioService.speech] wrapping raw PCM from', model, '→', upstreamType || '(none)', `${buffer.byteLength}B`);
    buffer = pcmToWav(buffer, 24000, 1, 16);
    mimeType = 'audio/wav';
  }

  if (tinfoilCostUsd !== null) {
    chargeAudio(userId, tinfoilCostUsd, { model, kind: 'tts', markup: billingMarkup }).catch(() => {});
  } else {
    fetchGenerationCost(generationId, requireZdr)
      .then(cost => chargeAudio(userId, cost, { model, kind: 'tts', markup: billingMarkup }))
      .catch(() => {});
  }
  return { buffer, mimeType, model };
}

module.exports = {
  transcribe,
  synthesizeSpeech,
  resolveRequireZdr,
  pcmToWav,
  DEFAULT_STT_MODEL,
  DEFAULT_TTS_MODEL,
  DEFAULT_TTS_VOICE,
};
