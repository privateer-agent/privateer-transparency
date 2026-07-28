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
 * Shared speech-to-text / text-to-speech / music-generation logic.
 *
 * Extracted from routes/audio.js so both the app voice path and the developer
 * /v1 audio endpoints (routes/v1.js) go through one provider-branched
 * implementation: NEAR AI / Tinfoil confidential enclaves, else OpenRouter's
 * dedicated /audio/transcriptions and /audio/speech endpoints. Billing is done
 * here (kinds 'stt' / 'tts' / 'musicGen'); callers just shape the HTTP response.
 *
 * E2EE note (CLAUDE.md §5): recorded audio (STT) and reply text (TTS) transit
 * to the provider exactly like chat inference — forwarded, never persisted.
 * Music generation carries a wider, deliberate carve-out — see generateMusic.
 */
const logger = require('../utils/logger');
const Sentry = require('../instrument');
const billingService = require('./billingService');
const inferenceService = require('./inferenceService');
const nearAiService = require('./nearAiService');
const tinfoilService = require('./tinfoilService');
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
  let costUsd = Number(data?.usage?.cost);
  if (!Number.isFinite(costUsd) || costUsd <= 0) {
    costUsd = await fetchGenerationCost(r.headers.get('x-generation-id'), requireZdr);
  }
  await chargeAudio(userId, costUsd, { model, kind: 'stt', markup: billingMarkup, origin });
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

  let r;
  let tinfoilCostUsd = null;
  if (tinfoilService.isTinfoilModel(model)) {
    const out = await tinfoilService.speechRequest({ text: text.slice(0, 8000), voice: wireVoice, responseFormat, modelId: model });
    r = out.response;
    tinfoilCostUsd = out.providerCostUsd;
  } else {
    r = await fetch(`${OPENROUTER_BASE}/audio/speech`, {
      method: 'POST',
      headers: { ...inferenceService.orHeaders(requireZdr), 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, input: text.slice(0, 8000), voice: wireVoice, response_format: responseFormat }),
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
    fetchGenerationCost(generationId, requireZdr)
      .then(cost => chargeAudio(userId, cost, { model, kind: 'tts', markup: billingMarkup, origin }))
      .catch(() => {});
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
  if (PCM_ONLY_TTS_MODEL.test(model)) {
    // Not a failure — just not streamable. A distinct code so the client falls
    // back to the buffered endpoint instead of surfacing an error.
    throw Object.assign(new Error('model cannot stream'), { statusCode: 409, code: 'TTS_STREAM_UNSUPPORTED' });
  }
  const responseFormat = resolveResponseFormat(model, format);
  const wireVoice = resolveVoice(voice, model);

  let r;
  let tinfoilCostUsd = null;
  if (tinfoilService.isTinfoilModel(model)) {
    const out = await tinfoilService.speechRequest({ text: text.slice(0, 8000), voice: wireVoice, responseFormat, modelId: model });
    r = out.response;
    tinfoilCostUsd = out.providerCostUsd;
  } else {
    r = await fetch(`${OPENROUTER_BASE}/audio/speech`, {
      method: 'POST',
      headers: { ...inferenceService.orHeaders(requireZdr), 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, input: text.slice(0, 8000), voice: wireVoice, response_format: responseFormat }),
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
    fetchGenerationCost(generationId, requireZdr)
      .then(cost => chargeAudio(userId, cost, { model, kind: 'tts', markup: billingMarkup, origin }))
      .catch(() => {});
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

/** Provider-side price of one generation, before markup. */
function musicCostEstimateUsd(modelId) {
  return MUSIC_MODELS[modelId]?.approxCostUsd ?? MUSIC_MODELS[FALLBACK_MUSIC_MODEL].approxCostUsd;
}

/**
 * What the user is actually charged for one generation. Music is fixed-price
 * per call, so unlike chat/image the balance gate can be exact instead of the
 * bare $0.01 minimum — a user with $0.05 shouldn't start a $0.10 generation.
 */
function musicChargeEstimateUsd(modelId) {
  return musicCostEstimateUsd(modelId) * MARKUP;
}

/**
 * Generate music from a text prompt → { buffer, mimeType, model, costUsd }.
 * Bills 'musicGen'. Throws {statusCode,code} on bad input / provider failure.
 */
async function generateMusic({ userId, prompt, modelId, billingMarkup, origin = 'app' }) {
  if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
    throw Object.assign(new Error('prompt is required'), { statusCode: 400, code: 'PROMPT_REQUIRED' });
  }
  const model = resolveMusicModel(modelId);

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
  let buf = '';

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });

    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      // Skips blank lines, `event:` lines and OpenRouter's `: PROCESSING`
      // keepalive comments in one condition.
      if (!line.startsWith('data:')) continue;
      const payload = line.slice(5).trim();
      if (payload === '[DONE]') return { audioParts, costUsd };
      let chunk;
      try { chunk = JSON.parse(payload); } catch { continue; }
      const data = chunk?.choices?.[0]?.delta?.audio?.data;
      if (typeof data === 'string' && data) audioParts.push(data);
      const cost = Number(chunk?.usage?.cost);
      if (Number.isFinite(cost) && cost > 0) costUsd = cost;
    }
  }
  return { audioParts, costUsd };
}

module.exports = {
  transcribe,
  synthesizeSpeech,
  synthesizeSpeechStream,
  generateMusic,
  resolveMusicModel,
  musicCostEstimateUsd,
  musicChargeEstimateUsd,
  resolveRequireZdr,
  pcmToWav,
  // Exported for test/audioModels.test.js — pure helpers over model ids and
  // response headers, asserted without touching a provider.
  resolveAudioModel,
  resolveResponseFormat,
  parsePcmParams,
  RETIRED_AUDIO_MODELS,
  DEFAULT_STT_MODEL,
  DEFAULT_TTS_MODEL,
  DEFAULT_TTS_VOICE,
  DEFAULT_MUSIC_MODEL,
  MUSIC_MODELS,
  MUSIC_PROMPT_MAX,
};
