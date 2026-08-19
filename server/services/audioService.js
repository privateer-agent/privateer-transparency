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
 * Shared speech-to-text / text-to-speech / music / sound-effect logic.
 *
 * Extracted from routes/audio.js so both the app voice path and the developer
 * /v1 audio endpoints (routes/v1.js) go through one provider-branched
 * implementation: NEAR AI / Tinfoil confidential enclaves, else OpenRouter's
 * dedicated /audio/transcriptions and /audio/speech endpoints, plus fal for the
 * one thing neither can do (see generateSfx). Billing is done here (kinds
 * 'stt' / 'tts' / 'musicGen' / 'sfxGen'); callers just shape the HTTP response.
 *
 * E2EE note (CLAUDE.md §5): recorded audio (STT) and reply text (TTS) transit
 * to the provider exactly like chat inference — forwarded, never persisted.
 * Music generation carries a wider, deliberate carve-out — see generateMusic.
 * Sound effects deliberately do NOT reuse that carve-out: they sit behind the
 * ordinary non-ZDR media gate, enforced by the route — see generateSfx.
 */
const logger = require('../utils/logger');
const Sentry = require('../instrument');
const billingService = require('./billingService');
const inferenceService = require('./inferenceService');
const nearAiService = require('./nearAiService');
const tinfoilService = require('./tinfoilService');
const falService = require('./falService');
const {
  isFalAudioModel, falAudioModel, falModelIdsFor, falResolveVoice,
  falAudioCostUsd, falClampDuration, buildFalInput, falOutputUrl, falAudioMime,
} = require('../data/falModels');
const {
  ttsFloorUsd, sttFloorUsd, TTS_USD_PER_CHAR, STT_USD_PER_MINUTE,
} = require('../data/openrouterAudioModels');
const { tinfoilVoicesFor } = require('../data/tinfoilModels');
const UserStoragePrefs = require('../models/userStoragePrefsModel');

const OPENROUTER_BASE = process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1';

// Whisper Large v3 *turbo*, not `openai/whisper-1`: only the Large v3 family has
// a ZDR endpoint. requireZdr defaults ON, which puts the request on the ZDR key,
// and that key 404s whisper-1 with "No endpoints available matching your
// guardrail restrictions and data policy" (measured 2026-07-27).
//
// Turbo over plain v3 because transcription sits directly in the voice loop's
// critical path and the two are otherwise interchangeable: same family, same
// ZDR posture, same transcript on our test clip — but 342ms vs 1453ms measured
// 2026-07-28. Over a second of every spoken turn, for free.
//
// NOT `tinfoil/whisper-large-v3-turbo`, and it's the one audio default that
// isn't confidential compute, so the reason is worth pinning down. It is the
// same Whisper weights in an enclave, and on latency it would be affordable —
// benched 2026-07-29 over 13 alternating runs on one 10s clip, transcripts
// identical word-for-word every time, median 511ms vs 313ms. Cost is what rules
// it out: Tinfoil prices transcription at a flat $0.01/request (requestPrice in
// their catalog) against OpenRouter's metered $0.04/audio-minute, i.e. $0.00011
// for that same clip — ~90x, breaking even only past ~15 minutes of audio in a
// single call. Every dictation press and every spoken turn goes through this
// pref (client transcribeRecording), so the enclave would cost a cent a tap.
// The enclave model stays a one-tap choice instead: it leads the Recommended
// STT list in ModelPickerSheet. Revisit if Tinfoil ever meters STT by duration.
const DEFAULT_STT_MODEL = process.env.DEFAULT_STT_MODEL || 'openai/whisper-large-v3-turbo';
// Default to a confidential-compute voice: Qwen3 TTS runs in a Tinfoil enclave
// (AMD SEV-SNP + confidential GPU) with a fetchable attestation, so spoken text
// is processed somewhere the operator can't read into — a strictly stronger
// guarantee than contractual ZDR, and it satisfies the requireZdr gate on its
// own. (Voxtral TTS was the default and was cheaper; it now returns speech that
// isn't the submitted text — see RETIRED_AUDIO_MODELS.)
const DEFAULT_TTS_MODEL = process.env.DEFAULT_TTS_MODEL || 'tinfoil/qwen3-tts';
// Fallback for models whose voice set we don't enumerate (Gemini et al.).
// Tinfoil models never use this — see resolveVoice.
const DEFAULT_TTS_VOICE = process.env.DEFAULT_TTS_VOICE || 'Zephyr';

// The input cap every speech backend has always been given, named now that a
// second one reads it (the fal path bills on exactly these characters, so the
// number the user is charged for and the number we send have to be the same
// expression).
const TTS_INPUT_MAX = 8000;

// A fal speech job is a synchronous round trip plus a CDN fetch, on models that
// synthesize a paragraph in a few seconds. Shorter than the SFX bound because
// speech is usually in front of someone waiting to hear it.
const FAL_TTS_TIMEOUT_MS = Number(process.env.FAL_TTS_TIMEOUT_MS) || 60_000;

// OpenAI-compatible clients always send an OpenAI voice name (`alloy`, `nova`,
// …), which no backend we route to accepts. Gemini's are named differently
// (`Zephyr`, `Puck`, …) and passing `alloy` to it 502s, so map the OpenAI names
// to their nearest Gemini equivalent and let a stock OpenAI SDK call work.
// Unknown / already-Gemini voice names pass through untouched; empty → default
// voice. (The Tinfoil default is handled ahead of this — see resolveVoice.)
const OPENAI_TO_GEMINI_VOICE = {
  alloy: 'Zephyr', echo: 'Charon', fable: 'Puck', onyx: 'Orus',
  nova: 'Aoede', shimmer: 'Leda', ash: 'Enceladus', ballad: 'Algieba',
  coral: 'Kore', sage: 'Iapetus', verse: 'Fenrir',
};

// Resolve the wire voice for a given model. Voice names are strictly per-model
// family, so this must never hand one family's name to another.
//
// Tinfoil is handled first and separately: its /v1/audio/speech *requires* a
// voice and rejects anything outside that model's own preset speakers, so both
// the Gemini mapping below and a bare passthrough 400 there. Fall back to the
// model's own first speaker rather than the global Gemini default.
function resolveVoice(voice, model) {
  // fal's voice models are the same story as Tinfoil's, one provider along:
  // each endpoint accepts only its own speakers (Kokoro's `af_bella`,
  // ElevenLabs' `Rachel`, Orpheus' `tara`), and the table in data/falModels.js
  // is the only place those sets exist.
  if (isFalAudioModel(model)) return falResolveVoice(model, voice) || '';
  if (tinfoilService.isTinfoilModel(model)) {
    const presets = tinfoilVoicesFor(model);
    if (voice && presets.includes(voice)) return voice;
    return presets[0] || '';
  }
  if (typeof model === 'string' && model.startsWith('openai/')) return voice || 'alloy';
  if (!voice || typeof voice !== 'string') return DEFAULT_TTS_VOICE;
  return OPENAI_TO_GEMINI_VOICE[voice.toLowerCase()] || voice;
}

/**
 * Speech models we no longer serve → what to run instead.
 *
 * Both entries are ids users already have persisted in
 * UserStoragePrefs.preferredTtsModelId / preferredSttModelId (they were our own
 * defaults), so dropping them from the picker isn't enough — the stored pref
 * has to heal on the request path too, the same way RETIRED_MODEL_ALIASES heals
 * a retired chat slug in inferenceService.resolveModelId.
 */
const RETIRED_AUDIO_MODELS = {
  // Broken upstream, not delisted: /v1/audio/speech accepts the request, bills,
  // and returns a well-formed 24 kHz mono MP3 — but the speech is not the text
  // we sent. Measured 2026-07-27, "The quick brown fox jumps over the lazy dog."
  // came back as 8.3s that transcribes to "Thank you." (neutral_female), and
  // similar babble for casual_male / cheerful_female / de_male, for wav as well
  // as mp3, and at every candidate sample-rate reinterpretation of the raw PCM
  // — so it is the model, not a container mislabel. qwen3-tts, same host, same
  // request shape, returns the sentence verbatim. Drop this line if Tinfoil
  // fixes it (and re-list the model in data/tinfoilModels.js).
  'tinfoil/voxtral-tts': 'tinfoil/qwen3-tts',
  // No ZDR endpoint, so it 404s under the default requireZdr — see
  // DEFAULT_STT_MODEL. Same model family, so the replacement is a strict
  // upgrade rather than a change of behaviour.
  'openai/whisper-1': 'openai/whisper-large-v3',
};

/** Resolve the model to actually call: caller's id if usable, else the default, retired ids healed. */
function resolveAudioModel(requested, fallbackModel) {
  const requestedId = (typeof requested === 'string' && requested.includes('/')) ? requested : fallbackModel;
  const replacement = RETIRED_AUDIO_MODELS[requestedId];
  if (!replacement) return requestedId;
  logger.info('[audioService] retired model', requestedId, '→', replacement);
  return replacement;
}

// TTS models whose /audio/speech accepts nothing but raw PCM. Gemini 400s on
// anything else ('Gemini TTS only supports response_format="pcm". Got "mp3".'),
// so honouring a caller's mp3 request there means failing the whole call. We
// ask for pcm instead and hand back the WAV we wrap it into below — a container
// every client can play, just not the one they named.
const PCM_ONLY_TTS_MODEL = /gemini[\w.-]*-tts/i;

function resolveResponseFormat(model, requested) {
  if (PCM_ONLY_TTS_MODEL.test(model)) return 'pcm';
  return requested === 'pcm' ? 'pcm' : 'mp3';
}

/**
 * Sample rate + channel count for a raw-PCM response, read off the content-type
 * parameters (Gemini sends `audio/pcm;rate=24000;channels=1`). Guessing these
 * wrong doesn't fail loudly — it plays back at the wrong speed — so parse when
 * the provider says, and fall back to the 24 kHz mono every speech model we've
 * seen emits.
 */
function parsePcmParams(contentType) {
  const rate = Number(/(?:^|;)\s*rate=(\d+)/i.exec(contentType || '')?.[1]);
  const channels = Number(/(?:^|;)\s*channels=(\d+)/i.exec(contentType || '')?.[1]);
  return {
    sampleRate: Number.isFinite(rate) && rate > 0 ? rate : 24000,
    channels: Number.isFinite(channels) && channels > 0 ? channels : 1,
  };
}

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

// ── fal generations ──────────────────────────────────────────────────────────

/**
 * Run one fal audio generation and hand back finished bytes.
 *
 * Shared by all three fal surfaces (speech, music, effects) because the shape is
 * identical and the differences are all in the table: build the request from
 * data/falModels.js, run it, pull the output URL out of wherever that endpoint
 * puts it, and fetch the bytes **in this process**. The last step is not an
 * optimisation to skip — fal's output URL is public and unauthenticated for as
 * long as it lives, so it must die here rather than travel to a client (see the
 * falService header).
 *
 * `emptyCode` is the caller's own "a 200 with no audio" code. That case is
 * almost always the safety checker declining a prompt, and each surface has copy
 * for it; a shared code would make all three say "the network failed".
 */
async function runFalAudio(modelId, { prompt, voice, seconds, lyrics, instrumental, promptMax, timeoutMs, emptyCode }) {
  const input = buildFalInput(modelId, { prompt, voice, seconds, lyrics, instrumental, promptMax });
  const result = await falService.run(modelId, input, { timeoutMs });
  const url = falOutputUrl(modelId, result);
  if (!url) {
    throw Object.assign(new Error('no audio was returned'), { statusCode: 502, code: emptyCode });
  }
  const { buffer, mimeType } = await falService.fetchOutput(url, { timeoutMs });
  // Not the CDN's word for it. Some endpoints serve audio as
  // application/octet-stream, and that label reaches the client, which picks a
  // file extension from it — see falAudioMime.
  return { buffer, mimeType: falAudioMime(modelId, url, mimeType) };
}

/**
 * Transcribe audio → { text, model }. Bills 'stt'. Throws {statusCode,code} on
 * bad input / provider failure / ZDR-key / insufficient funds.
 */
async function transcribe({ userId, audioBase64, format, language, modelId, requireZdr = true, billingMarkup, origin = 'app' }) {
  if (!audioBase64 || typeof audioBase64 !== 'string') {
    throw Object.assign(new Error('audio is required'), { statusCode: 400, code: 'AUDIO_REQUIRED' });
  }
  const model = resolveAudioModel(modelId, DEFAULT_STT_MODEL);

  if (nearAiService.isNearModel(model)) {
    const { text, providerCostUsd } = await nearAiService.transcribe({ audioBase64, format, language, modelId: model });
    await chargeAudio(userId, providerCostUsd, { model, kind: 'stt', markup: billingMarkup, origin });
    return { text, model };
  }
  if (tinfoilService.isTinfoilModel(model)) {
    const { text, providerCostUsd } = await tinfoilService.transcribe({ audioBase64, format, language, modelId: model });
    await chargeAudio(userId, providerCostUsd, { model, kind: 'stt', markup: billingMarkup, origin });
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
    // Surface a short upstream detail so an opaque 502 is diagnosable by callers
    // (bad audio format vs. model/endpoint unavailable) instead of a bare string.
    throw Object.assign(new Error('transcription failed'), {
      statusCode: 502, code: 'STT_FAILED', upstreamStatus: r.status, upstreamDetail: errText.slice(0, 300),
    });
  }
  const data = await r.json();
  const text = typeof data?.text === 'string' ? data.text : '';
  const settleArgs = {
    userId, generationId: r.headers.get('x-generation-id'), requireZdr,
    model, kind: 'stt', markup: billingMarkup, origin,
    // Bounded from below — see estimateAudioSecondsFromBase64. Only consulted
    // if the provider never tells us what the call actually cost.
    fallbackSeconds: estimateAudioSecondsFromBase64(audioBase64, format),
  };
  const inlineCostUsd = Number(data?.usage?.cost);
  if (Number.isFinite(inlineCostUsd) && inlineCostUsd > 0) {
    // The usual case: the cost came back with the transcript, so there is
    // nothing to poll and nothing to wait for. Kept inline so an exhausted
    // balance still surfaces as a 402 the way it always has.
    await settleOpenRouterAudioCharge({ ...settleArgs, inlineCostUsd });
  } else {
    // No inline cost — settling now means polling the generation record, which
    // can take seconds. That wait belongs nowhere near a voice turn, so it moves
    // to the background. The charge (and the alert if it can't be priced) still
    // happens; only the 402 is traded away, and the drained balance blocks the
    // NEXT request at the route gate.
    settleOpenRouterAudioCharge(settleArgs).catch(() => { /* alerted inside */ });
  }
  return { text, model };
}

/**
 * Synthesize speech → { buffer, mimeType, model }. Bills 'tts' in the
 * background. Throws {statusCode,code} on bad input / provider failure.
 */
async function synthesizeSpeech({ userId, text, voice, format, modelId, requireZdr = true, billingMarkup, origin = 'app' }) {
  if (!text || typeof text !== 'string' || !text.trim()) {
    throw Object.assign(new Error('text is required'), { statusCode: 400, code: 'TEXT_REQUIRED' });
  }
  const model = resolveAudioModel(modelId, DEFAULT_TTS_MODEL);
  const responseFormat = resolveResponseFormat(model, format);
  const wireVoice = resolveVoice(voice, model);
  const input = text.slice(0, TTS_INPUT_MAX);

  // fal voices. Not an /audio/speech backend at all — a job that answers with a
  // URL — so this returns finished bytes here rather than joining the
  // Response-shaped path below. Callers MUST have cleared assertMediaModelAllowed
  // first: fal has no ZDR endpoint, and speech is gated exactly like image and
  // video generation (see data/falModels.js). This function doesn't gate itself,
  // for the same reason generateSfx doesn't — the gate needs the request's
  // requireZdr/allowNonZdrMedia, which is route-shaped.
  if (isFalAudioModel(model)) {
    const { buffer, mimeType } = await runFalAudio(model, {
      prompt: input, voice: wireVoice, promptMax: TTS_INPUT_MAX,
      timeoutMs: FAL_TTS_TIMEOUT_MS, emptyCode: 'TTS_FAILED',
    });
    // Billed on characters submitted, which is exactly what fal meters — so
    // unlike the OpenRouter path there is nothing to look up afterwards.
    chargeAudio(userId, falAudioCostUsd(model, { chars: input.length }), {
      model, kind: 'tts', markup: billingMarkup, origin,
    }).catch(() => {});
    return { buffer, mimeType, model };
  }

  let r;
  let tinfoilCostUsd = null;
  if (tinfoilService.isTinfoilModel(model)) {
    const out = await tinfoilService.speechRequest({ text: input, voice: wireVoice, responseFormat, modelId: model });
    r = out.response;
    tinfoilCostUsd = out.providerCostUsd;
  } else {
    r = await fetch(`${OPENROUTER_BASE}/audio/speech`, {
      method: 'POST',
      headers: { ...inferenceService.orHeaders(requireZdr), 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, input, voice: wireVoice, response_format: responseFormat }),
    });
  }
  if (!r.ok) {
    const errText = await r.text().catch(() => '');
    logger.error('[audioService.speech] OpenRouter error', r.status, errText);
    // Surface a short upstream detail so an opaque 502 is diagnosable by callers
    // (which model/voice/format the backend rejected) instead of a bare string.
    throw Object.assign(new Error('speech synthesis failed'), {
      statusCode: 502, code: 'TTS_FAILED', upstreamStatus: r.status, upstreamDetail: errText.slice(0, 300),
    });
  }

  const generationId = r.headers.get('x-generation-id');
  let buffer = Buffer.from(await r.arrayBuffer());
  const contentType = r.headers.get('content-type') || '';
  const upstreamType = contentType.split(';')[0].trim().toLowerCase();
  let mimeType;
  if (upstreamType.includes('mpeg') || upstreamType.includes('mp3')) {
    mimeType = 'audio/mpeg';
  } else if (upstreamType.includes('wav') || upstreamType.includes('wave')) {
    mimeType = 'audio/wav';
  } else if (upstreamType.startsWith('audio/') && !upstreamType.includes('pcm') && !upstreamType.includes('l16') && !upstreamType.includes('basic')) {
    mimeType = upstreamType;
  } else {
    // Expected for the pcm-only models, not an anomaly — the wrap is what makes
    // their output playable. Logged at debug there, warn for anything else.
    const { sampleRate, channels } = parsePcmParams(contentType);
    const log = responseFormat === 'pcm' ? logger.debug : logger.warn;
    log('[audioService.speech] wrapping raw PCM from', model, '→', upstreamType || '(none)',
      `${sampleRate}Hz ${channels}ch ${buffer.byteLength}B`);
    buffer = pcmToWav(buffer, sampleRate, channels, 16);
    mimeType = 'audio/wav';
  }

  if (tinfoilCostUsd !== null) {
    chargeAudio(userId, tinfoilCostUsd, { model, kind: 'tts', markup: billingMarkup, origin }).catch(() => {});
  } else {
    settleOpenRouterAudioCharge({
      userId, generationId, requireZdr, model, kind: 'tts',
      markup: billingMarkup, origin, fallbackChars: input.length,
    }).catch(() => { /* alerted inside */ });
  }
  return { buffer, mimeType, model };
}

/**
 * Same synthesis, but hand back the provider's response unread so the caller can
 * pipe bytes through as they arrive → { response, mimeType, model, generationId,
 * settle }. Throws {statusCode,code} exactly like synthesizeSpeech.
 *
 * Why a second entry point rather than a flag: `synthesizeSpeech` is defined by
 * what it does *after* the response — buffers it, wraps raw PCM into a WAV
 * container, and returns finished bytes. None of that is possible on a stream.
 * The PCM wrap in particular needs the total length for the RIFF header, which
 * is unknown until the last byte, so this path serves mp3 only and refuses
 * pcm-only models (the caller falls back to the buffered endpoint).
 *
 * Billing can't be settled inline either — the cost lands on the generation
 * record after the stream ends — so the caller invokes `settle()` once it has
 * finished piping.
 */
async function synthesizeSpeechStream({ userId, text, voice, format, modelId, requireZdr = true, billingMarkup, origin = 'app' }) {
  if (!text || typeof text !== 'string' || !text.trim()) {
    throw Object.assign(new Error('text is required'), { statusCode: 400, code: 'TEXT_REQUIRED' });
  }
  const model = resolveAudioModel(modelId, DEFAULT_TTS_MODEL);
  // Same "not a failure, just not streamable" answer for the fal voices: fal
  // renders the whole clip and answers with a URL, so there is no byte stream to
  // pipe. The client falls back to the buffered endpoint.
  if (PCM_ONLY_TTS_MODEL.test(model) || isFalAudioModel(model)) {
    // Not a failure — just not streamable. A distinct code so the client falls
    // back to the buffered endpoint instead of surfacing an error.
    throw Object.assign(new Error('model cannot stream'), { statusCode: 409, code: 'TTS_STREAM_UNSUPPORTED' });
  }
  const responseFormat = resolveResponseFormat(model, format);
  const wireVoice = resolveVoice(voice, model);
  // Named rather than sliced twice inline: this is also what the fallback price
  // is metered on when the generation record never arrives (see settle below),
  // and billing the pre-truncation length would overcharge.
  const wireText = text.slice(0, 8000);

  let r;
  let tinfoilCostUsd = null;
  if (tinfoilService.isTinfoilModel(model)) {
    const out = await tinfoilService.speechRequest({ text: wireText, voice: wireVoice, responseFormat, modelId: model });
    r = out.response;
    tinfoilCostUsd = out.providerCostUsd;
  } else {
    r = await fetch(`${OPENROUTER_BASE}/audio/speech`, {
      method: 'POST',
      headers: { ...inferenceService.orHeaders(requireZdr), 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, input: wireText, voice: wireVoice, response_format: responseFormat }),
    });
  }
  if (!r.ok) {
    const errText = await r.text().catch(() => '');
    logger.error('[audioService.speechStream] provider error', r.status, errText);
    throw Object.assign(new Error('speech synthesis failed'), {
      statusCode: 502, code: 'TTS_FAILED', upstreamStatus: r.status, upstreamDetail: errText.slice(0, 300),
    });
  }

  const upstreamType = (r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  // A provider that answered with PCM despite an mp3 request can't be streamed
  // either — the client has no container to open. Rare, but it would otherwise
  // send unplayable bytes and look like a decode bug.
  if (!upstreamType.includes('mpeg') && !upstreamType.includes('mp3')) {
    throw Object.assign(new Error('unstreamable content type'), {
      statusCode: 409, code: 'TTS_STREAM_UNSUPPORTED', upstreamDetail: upstreamType,
    });
  }

  const generationId = r.headers.get('x-generation-id');
  const settle = () => {
    if (tinfoilCostUsd !== null) {
      chargeAudio(userId, tinfoilCostUsd, { model, kind: 'tts', markup: billingMarkup, origin }).catch(() => {});
      return;
    }
    settleOpenRouterAudioCharge({
      userId, generationId, requireZdr, model, kind: 'tts',
      markup: billingMarkup, origin, fallbackChars: wireText.length,
    }).catch(() => { /* alerted inside */ });
  };

  return { response: r, mimeType: 'audio/mpeg', model, generationId, settle };
}

// ── Music generation (Lyria) ─────────────────────────────────────────────────
//
// Not a /audio/speech call. Lyria is exposed as a chat-completions model that
// emits an audio part, and it *requires* `stream: true` — a non-streaming
// request 400s with "Audio output requires stream: true". The audio still
// arrives in one burst (~10s, a handful of chunks), so this buffers the whole
// clip and hands the caller finished bytes rather than proxying a stream the
// client has no way to play progressively.
//
// PRIVACY — deliberate carve-out (CLAUDE.md §5). Neither Lyria SKU has a Zero
// Data Retention endpoint, and there is no confidential-compute music model to
// fall back to: the entire OpenRouter catalog offers exactly two audio *output*
// generators, both of them these. So unlike every other media generation path,
// this one does NOT sit behind assertMediaModelAllowed / allowNonZdrMedia —
// music is offered to every user, ZDR preference or not. What we do instead is
// send it unattributed: no `user` field, no account id, no chat id, no
// conversation history. The prompt reaches the provider with nothing tying it
// to a Privateer account beyond our own API key. That is a real mitigation and
// a partial one — it does not make the prompt private, and the UI says so at
// the point of generation. Do not soften that copy, and do not quietly reuse
// this exemption for another model.
const MUSIC_MODELS = {
  'google/lyria-3-clip-preview': { approxCostUsd: 0.04 },  // 30s clip
  'google/lyria-3-pro-preview':  { approxCostUsd: 0.08 },  // full song
  // Everything fal hosts for music, priced from data/falModels.js so there is
  // one table of fal prices rather than two that can disagree. These are ALSO
  // non-ZDR — adding them widens the choice inside the carve-out, it does not
  // narrow the carve-out. If a zero-retention music model ever ships anywhere,
  // that is the moment to collapse this back into the ordinary media gate.
  ...Object.fromEntries(falModelIdsFor('audioGen').map(id => [id, { approxCostUsd: falAudioModel(id).typicalUsd }])),
};
// Env-overridable like the TTS/STT defaults, but validated against the table
// above: an override outside it would otherwise be returned unchecked by
// resolveMusicModel and then priced off a missing row.
const FALLBACK_MUSIC_MODEL = 'google/lyria-3-clip-preview';
const DEFAULT_MUSIC_MODEL = Object.hasOwn(MUSIC_MODELS, process.env.DEFAULT_MUSIC_MODEL || '')
  ? process.env.DEFAULT_MUSIC_MODEL
  : FALLBACK_MUSIC_MODEL;

// A description of the music, not a document. The context window is a million
// tokens, but nothing about this model rewards a long prompt — the cap exists
// so a paste-bomb can't inflate a fixed-price call into a slow one.
const MUSIC_PROMPT_MAX = 2000;

// Generous: a full song takes longer than a clip, and the whole payload lands
// in one burst near the end, so a tight bound would abort a request that was
// about to succeed.
const MUSIC_TIMEOUT_MS = Number(process.env.MUSIC_TIMEOUT_MS) || 240_000;

/**
 * Resolve + validate the music model. An allowlist rather than a passthrough:
 * `output_modalities=audio` also returns the conversational `openai/gpt-audio*`
 * models, which answer in speech instead of generating music. Letting one
 * through would bill a real call for something the user can't use.
 */
function resolveMusicModel(modelId) {
  if (!modelId) return DEFAULT_MUSIC_MODEL;
  // hasOwn, not truthiness: `MUSIC_MODELS['constructor']` is truthy off the
  // prototype, which would wave an unusable model through to a confusing 502
  // instead of the 400 this is here to produce.
  if (Object.hasOwn(MUSIC_MODELS, modelId)) return modelId;
  throw Object.assign(
    new Error(`${modelId} is not a music generation model`),
    { statusCode: 400, code: 'MUSIC_MODEL_UNSUPPORTED', modelId }
  );
}

/**
 * Provider-side price of one generation, before markup.
 *
 * `duration` matters only for the fal models billed by length (ElevenLabs by the
 * minute, CassetteAI by the minute); a Lyria SKU and a flat-priced fal model
 * ignore it, which is why it's optional rather than required.
 */
function musicCostEstimateUsd(modelId, duration) {
  if (isFalAudioModel(modelId)) {
    return falAudioCostUsd(modelId, { seconds: falClampDuration(modelId, duration) ?? 0 });
  }
  return MUSIC_MODELS[modelId]?.approxCostUsd ?? MUSIC_MODELS[FALLBACK_MUSIC_MODEL].approxCostUsd;
}

/**
 * What the user is actually charged for one generation. Music is fixed-price
 * per call, so unlike chat/image the balance gate can be exact instead of the
 * bare $0.01 minimum — a user with $0.05 shouldn't start a $0.10 generation.
 * With a length-priced model that exactness now depends on the requested
 * duration, so the gate has to be given the same one the generation will use.
 */
function musicChargeEstimateUsd(modelId, duration) {
  return musicCostEstimateUsd(modelId, duration) * MARKUP;
}

/**
 * Generate music from a text prompt → { buffer, mimeType, model, costUsd }.
 * Bills 'musicGen'. Throws {statusCode,code} on bad input / provider failure.
 */
async function generateMusic({ userId, prompt, modelId, duration, lyrics, instrumental = true, billingMarkup, origin = 'app' }) {
  if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
    throw Object.assign(new Error('prompt is required'), { statusCode: 400, code: 'PROMPT_REQUIRED' });
  }
  const model = resolveMusicModel(modelId);

  // fal's music models. Same carve-out, same posture: falService.run sends no
  // user field, no account id and no history either, so the prompt reaches the
  // provider attributable to our API key and nothing finer — and fal is asked to
  // store neither the request nor the output (X-Fal-Store-IO, see falService).
  // Unlike Lyria, most of these take a length, so the price follows it.
  if (isFalAudioModel(model)) {
    const seconds = falClampDuration(model, duration);
    const { buffer, mimeType } = await runFalAudio(model, {
      prompt, seconds, lyrics, instrumental, promptMax: MUSIC_PROMPT_MAX,
      timeoutMs: MUSIC_TIMEOUT_MS, emptyCode: 'MUSIC_EMPTY',
    });
    const costUsd = falAudioCostUsd(model, { seconds: seconds ?? 0 });
    // Billed after the fact and never fatal, as on the Lyria path below: fal has
    // charged us and the user has the track, so a billing hiccup must not
    // withhold it. The route's balance gate is what stops an empty wallet.
    try {
      await chargeAudio(userId, costUsd, { model, kind: 'musicGen', markup: billingMarkup, origin });
    } catch (err) {
      Sentry.captureException(err, { level: 'warning', tags: { op: 'audio_charge_musicGen' } });
    }
    return { buffer, mimeType, model, costUsd, durationSeconds: seconds };
  }

  // Exactly the body the endpoint accepts. Note what is absent: no `user`
  // field. OpenRouter forwards it to the provider as an end-user identifier,
  // which is the one thing that would make a retained prompt attributable.
  const body = {
    model,
    messages: [{ role: 'user', content: prompt.trim().slice(0, MUSIC_PROMPT_MAX) }],
    modalities: ['text', 'audio'],
    stream: true,
  };

  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), MUSIC_TIMEOUT_MS);
  try {
    let r;
    try {
      r = await fetch(`${OPENROUTER_BASE}/chat/completions`, {
        method: 'POST',
        // Standard key, always. Neither SKU has a ZDR endpoint, so the ZDR
        // account 404s them — the same rule resolveUseZdrKey applies to any
        // non-ZDR media model.
        headers: { ...inferenceService.orHeaders(false), 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: abort.signal,
      });
    } catch (fetchErr) {
      if (fetchErr?.name === 'AbortError') {
        throw Object.assign(new Error(`music generation timed out after ${MUSIC_TIMEOUT_MS}ms`), {
          statusCode: 504, code: 'MUSIC_TIMEOUT', timedOut: true,
        });
      }
      throw fetchErr;
    }

    if (!r.ok) {
      const errText = await r.text().catch(() => '');
      logger.error('[audioService.generateMusic] OpenRouter error', r.status, errText);
      throw Object.assign(new Error('music generation failed'), {
        statusCode: 502, code: 'MUSIC_FAILED', upstreamStatus: r.status, upstreamDetail: errText.slice(0, 300),
      });
    }

    const { audioParts, costUsd } = await readMusicStream(r);

    if (audioParts.length === 0) {
      // A 200 with no audio part means the model answered in text — the usual
      // cause is a prompt it declined. Distinct code so the client can say so
      // instead of blaming the network.
      throw Object.assign(new Error('no audio was returned'), { statusCode: 502, code: 'MUSIC_EMPTY' });
    }

    // Every response observed so far chunks the *text* of one base64 stream, so
    // joining then decoding once is correct. Guard the other encoding anyway:
    // '=' padding on a non-final part means the parts are independently
    // encoded, and joining the text would leave padding mid-stream and corrupt
    // the file. Decode those separately instead.
    const paddedMidStream = audioParts.slice(0, -1).some(p => p.includes('='));
    const buffer = paddedMidStream
      ? Buffer.concat(audioParts.map(p => Buffer.from(p, 'base64')))
      : Buffer.from(audioParts.join(''), 'base64');

    // `delta.audio.format` comes back null, so the container is asserted, not
    // read. Verified MP3 (ID3 tag or a bare MPEG frame sync). Log rather than
    // throw if that ever changes — handing back playable-looking bytes the user
    // paid for beats failing the request outright.
    const isMp3 = buffer.length > 3
      && (buffer.toString('ascii', 0, 3) === 'ID3' || (buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0));
    if (!isMp3) {
      logger.warn('[audioService.generateMusic] unexpected container from', model,
        '— first bytes', buffer.subarray(0, 4).toString('hex'), `${buffer.byteLength}B`);
    }

    // Billed after the fact and never fatal: the bytes exist and the provider
    // has already charged us, so a billing hiccup must not withhold the clip.
    // The route's checkCreditBalance gate is what actually keeps a user from
    // generating with an empty wallet.
    if (costUsd === null) {
      // The fallback is a price hardcoded in MUSIC_MODELS, so a silent slide
      // into it would bill a stale number indefinitely if OpenRouter ever
      // changes what Lyria costs. Make that visible rather than quiet.
      logger.warn('[audioService.generateMusic] no inline usage.cost from', model,
        '— billing the table price', musicCostEstimateUsd(model));
    }
    try {
      await chargeAudio(userId, costUsd ?? musicCostEstimateUsd(model), {
        model, kind: 'musicGen', markup: billingMarkup, origin,
      });
    } catch (err) {
      Sentry.captureException(err, { level: 'warning', tags: { op: 'audio_charge_musicGen' } });
    }

    return { buffer, mimeType: 'audio/mpeg', model, costUsd };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Consume the SSE body, collecting base64 audio segments and the inline cost.
 *
 * Unlike TTS there is no fetchGenerationCost round-trip to fall back on: the
 * final chunk carries `usage.cost` directly.
 */
async function readMusicStream(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const audioParts = [];
  let costUsd = null;
  // Decoded chunks that do not yet complete a line. Held as an ARRAY and joined
  // only when a newline actually arrives, because the audio is delivered as ONE
  // `data:` line several megabytes long: a full song is ~4.8MB of base64 spread
  // over ~400 network chunks with no newline among them. Appending each chunk to
  // a growing string re-copies the whole accumulated line every time, which is
  // quadratic in the payload — measured at ~0.8-3.5s of FULLY BLOCKED event loop
  // for one Lyria 3 Pro clip on a fast laptop, and several times that on the
  // production instance's half core. Nothing else on the server runs during it.
  // Joining once instead keeps it flat (~20ms) regardless of how the stream is
  // chunked. Do not "simplify" this back to `buf += chunk`.
  let pending = [];

  /** Handle one complete line. Returns true when the stream is done. */
  const takeLine = (raw) => {
    const line = raw.trim();
    // Skips blank lines, `event:` lines and OpenRouter's `: PROCESSING`
    // keepalive comments in one condition.
    if (!line.startsWith('data:')) return false;
    const payload = line.slice(5).trim();
    if (payload === '[DONE]') return true;
    let chunk;
    try { chunk = JSON.parse(payload); } catch { return false; }
    const data = chunk?.choices?.[0]?.delta?.audio?.data;
    if (typeof data === 'string' && data) audioParts.push(data);
    const cost = Number(chunk?.usage?.cost);
    if (Number.isFinite(cost) && cost > 0) costUsd = cost;
    return false;
  };

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    const text = decoder.decode(value, { stream: true });
    // The common case for this endpoint: mid-way through the one huge audio
    // line, so there is nothing to parse and nothing to copy.
    if (text.indexOf('\n') === -1) { pending.push(text); continue; }

    let buf = pending.length ? pending.join('') + text : text;
    pending = [];
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (takeLine(line)) return { audioParts, costUsd };
    }
    if (buf) pending.push(buf);
  }

  // A final line the stream never terminated with a newline. SSE normally does,
  // and `[DONE]` returns above, so this is a guard rather than the usual path.
  if (pending.length) takeLine(pending.join(''));
  return { audioParts, costUsd };
}

// ── Sound-effect generation (fal / Stable Audio 3 Small SFX) ─────────────────
//
// The one path in this file that leaves both OpenRouter and our TEE providers:
// neither has an SFX model at all (see the falService header). Everything below
// is shaped after generateMusic — fixed price per call, whole clip buffered,
// bytes handed back for the client to encrypt — with one deliberate difference.
//
// PRIVACY — NOT a carve-out, and it must stay that way. Music is exempt from
// assertMediaModelAllowed because gating it would leave a default account with
// an empty picker and no alternative anywhere in the catalog (CLAUDE.md §5).
// SFX is not in that position: a user who wants zero-retention audio can simply
// not generate sound effects, exactly as they can decline any other non-ZDR
// media model. So SFX goes through the ordinary gate, and the route — not this
// function — is where that gate lives, mirroring image and video generation.
// Do not reuse music's exemption here, and do not add a privacy note in its
// place: the gate is the disclosure, and a note beside it would imply the gate
// is insufficient.
// Every sound-effect model we serve, priced from the one fal table (see
// data/falModels.js). fal returns no inline cost with the response — unlike
// OpenRouter, which hands back usage.cost — so that table is what we actually
// bill against and it can only be kept honest by reconciling against the fal
// invoice. If fal repriced and nobody updated it, we would bill the stale number
// forever and silently, which is exactly the failure generateMusic logs a
// warning about. There is no runtime signal to warn on here, so the check is
// manual — and now covers three models rather than one.
//
// `approxCostUsd` is the *typical* generation (a 5-second effect), which is what
// the balance gate needs; the charge is computed from the actual length for the
// models fal meters by the second.
const SFX_MODELS = Object.fromEntries(
  falModelIdsFor('sfxGen').map(id => [id, { approxCostUsd: falAudioModel(id).typicalUsd }])
);
const FALLBACK_SFX_MODEL = 'fal-ai/stable-audio-3/small/sfx/text-to-audio';
const DEFAULT_SFX_MODEL = Object.hasOwn(SFX_MODELS, process.env.DEFAULT_SFX_MODEL || '')
  ? process.env.DEFAULT_SFX_MODEL
  : FALLBACK_SFX_MODEL;

// A description of one sound, not a scene. Shorter than MUSIC_PROMPT_MAX
// because the model is 459M parameters and a paragraph makes its output worse,
// not longer — the cap is a nudge as much as a guard.
const SFX_PROMPT_MAX = 500;

// What the model will actually render, in seconds. The ceiling is the model's
// own; the floor is where a request stops being worth a round trip.
const SFX_MIN_DURATION = 1;
const SFX_MAX_DURATION = 30;
const SFX_DEFAULT_DURATION = 5;

// Generation is a few seconds on this model. The bound is loose enough to
// absorb a cold start without being loose enough to hold a request open past
// the point the user has given up.
const SFX_TIMEOUT_MS = Number(process.env.SFX_TIMEOUT_MS) || 90_000;

/** Resolve + validate the SFX model against the allowlist. */
function resolveSfxModel(modelId) {
  if (!modelId) return DEFAULT_SFX_MODEL;
  // hasOwn, not truthiness — same prototype-key trap resolveMusicModel documents.
  if (Object.hasOwn(SFX_MODELS, modelId)) return modelId;
  throw Object.assign(
    new Error(`${modelId} is not a sound-effect model`),
    { statusCode: 400, code: 'SFX_MODEL_UNSUPPORTED', modelId }
  );
}

/**
 * Clamp a requested duration into what the chosen model will render.
 *
 * Bounds are per model now (data/falModels.js) rather than global, so the model
 * id is part of the question — though every effect model we offer happens to
 * agree on 1-30s, which is why the exported SFX_MIN/MAX/DEFAULT constants the
 * client mirrors are still meaningful.
 *
 * "Unspecified" is checked before the numeric coercion, not after: `Number(null)`
 * and `Number('')` are both 0, which is finite, so a caller that omitted the
 * field by sending null would fall through the clamp and get a 1-second effect
 * instead of the default. Absent means default; present-but-out-of-range means
 * clamp. Those are different answers and the coercion erases the difference.
 * (falClampDuration is where that rule now lives — it is the same rule.)
 */
function resolveSfxDuration(duration, modelId = DEFAULT_SFX_MODEL) {
  return falClampDuration(modelId, duration) ?? SFX_DEFAULT_DURATION;
}

/**
 * Provider-side price of one generation, before markup. `seconds` is only read
 * by the models fal meters by length (ElevenLabs); it falls back to that model's
 * default duration, which is what the balance gate wants.
 */
function sfxCostEstimateUsd(modelId, seconds) {
  if (isFalAudioModel(modelId)) return falAudioCostUsd(modelId, { seconds });
  return SFX_MODELS[modelId]?.approxCostUsd ?? SFX_MODELS[FALLBACK_SFX_MODEL].approxCostUsd;
}

/** What the user is charged — fixed price per call, so the gate can be exact. */
function sfxChargeEstimateUsd(modelId, seconds) {
  return sfxCostEstimateUsd(modelId, seconds) * MARKUP;
}

/**
 * Generate a sound effect → { buffer, mimeType, model, durationSeconds }.
 * Bills 'sfxGen'. Throws {statusCode,code} on bad input / provider failure.
 *
 * Callers MUST have cleared assertMediaModelAllowed first — see the block
 * comment above. This function does not gate itself, for the same reason
 * generateImage doesn't: the gate needs the request's requireZdr /
 * allowNonZdrMedia, which is route-shaped, not service-shaped.
 */
async function generateSfx({ userId, prompt, modelId, duration, billingMarkup, origin = 'app' }) {
  if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
    throw Object.assign(new Error('prompt is required'), { statusCode: 400, code: 'PROMPT_REQUIRED' });
  }
  const model = resolveSfxModel(modelId);
  const durationSeconds = resolveSfxDuration(duration, model);

  // The request shape is per model — text field, duration field, output format
  // and safety flag all differ between the three (see data/falModels.js). Every
  // fixed field there is restated rather than inherited, so a silent flip of a
  // provider default can't change what our users can generate without a change
  // here to explain it. A 200 with no audio object is SFX_EMPTY — most often the
  // safety checker declining a prompt, so it gets a distinct code rather than
  // reading to the user as a network failure.
  const { buffer, mimeType } = await runFalAudio(model, {
    prompt, seconds: durationSeconds, promptMax: SFX_PROMPT_MAX,
    timeoutMs: SFX_TIMEOUT_MS, emptyCode: 'SFX_EMPTY',
  });

  // Billed after the fact and never fatal, exactly as in generateMusic: fal has
  // already charged us and the user already has the audio, so a billing hiccup
  // must not withhold it. The route's balance gate is what keeps an empty
  // wallet from starting a generation in the first place.
  try {
    await chargeAudio(userId, sfxCostEstimateUsd(model, durationSeconds), {
      model, kind: 'sfxGen', markup: billingMarkup, origin,
    });
  } catch (err) {
    Sentry.captureException(err, { level: 'warning', tags: { op: 'audio_charge_sfxGen' } });
  }

  return { buffer, mimeType, model, durationSeconds };
}

module.exports = {
  transcribe,
  synthesizeSpeech,
  synthesizeSpeechStream,
  generateMusic,
  generateSfx,
  resolveSfxModel,
  resolveSfxDuration,
  sfxCostEstimateUsd,
  sfxChargeEstimateUsd,
  resolveMusicModel,
  musicCostEstimateUsd,
  musicChargeEstimateUsd,
  resolveRequireZdr,
  pcmToWav,
  // Exported for test/audioModels.test.js — pure helpers over model ids and
  // response headers, asserted without touching a provider.
  resolveAudioModel,
  resolveResponseFormat,
  // Also used by routes/audio.js → /voice-preview: the shared preview cache has
  // to key on the SAME (model, voice, format) triple synthesis will actually
  // run, or two spellings of one clip get two cache entries.
  resolveVoice,
  parsePcmParams,
  // Exported for test/audioCostFloor.test.js — the invariant worth pinning is
  // that neither ever over-reports what the audio holds.
  estimateAudioSeconds,
  estimateAudioSecondsFromBase64,
  base64Bytes,
  RETIRED_AUDIO_MODELS,
  DEFAULT_STT_MODEL,
  DEFAULT_TTS_MODEL,
  DEFAULT_TTS_VOICE,
  DEFAULT_MUSIC_MODEL,
  MUSIC_MODELS,
  MUSIC_PROMPT_MAX,
  DEFAULT_SFX_MODEL,
  SFX_MODELS,
  SFX_PROMPT_MAX,
  SFX_MIN_DURATION,
  SFX_MAX_DURATION,
  SFX_DEFAULT_DURATION,
};
