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
 * Tinfoil model registry — confidential-compute (secure enclave) models.
 *
 * Tinfoil (https://inference.tinfoil.sh/v1) is OpenAI-compatible and serves
 * every model inside a hardware secure enclave (AMD SEV-SNP CPU + NVIDIA
 * confidential GPU) with a publicly fetchable attestation document
 * (/.well-known/tinfoil-attestation). Its public /v1/models catalog carries
 * per-model pricing, context window, modality flags, and the endpoints each
 * model is served on — that's what we classify from.
 *
 * We surface four classes of model, each into the matching picker `action`:
 *   - chat     text→text chat models (`type: "chat"`)
 *   - vision   text+image→text models (`type: "chat"`, `multimodal: true`) —
 *              also appear in the chat picker
 *   - stt      audio→text models served on /v1/audio/transcriptions
 *   - tts      text→speech models served on /v1/audio/speech
 * Embeddings, document converters, safety/tool models, and the realtime-only
 * WebSocket transcriber are always dropped. Tinfoil has NO image or video
 * generation models — those actions stay on OpenRouter/NEAR.
 *
 * Surfaced ids are namespaced with a `tinfoil/` sentinel (e.g.
 * `tinfoil/gpt-oss-120b`), which also gives the bare upstream ids the
 * slash-form the rest of the app requires. The upstream id is the part after
 * `tinfoil/`.
 *
 * The mapped list + raw pricing are cached in-process; failed refreshes fall
 * back to the last successful value (empty on cold-start failure), so a
 * Tinfoil outage never breaks the OpenRouter model list. Like NEAR, the
 * catalog only loads when TINFOIL_API_KEY is configured — otherwise we'd
 * surface models no one can invoke.
 */

const TINFOIL_PREFIX = 'tinfoil/';
const TINFOIL_TEE_STACK = 'AMD SEV-SNP + NVIDIA confidential GPU';
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

const _cache = { models: [], pricing: new Map(), expiresAt: 0, inflight: null };

function tinfoilBase() {
  return process.env.TINFOIL_BASE_URL || 'https://inference.tinfoil.sh/v1';
}

// The catalog only exposes slugs (`gpt-oss-120b`); pretty labels + one-line
// descriptions come from Tinfoil's model docs. Unknown slugs fall back to a
// title-cased slug so new upstream models still render acceptably.
const MODEL_INFO = {
  'deepseek-v4-pro':        { name: 'DeepSeek V4 Pro',        description: 'Long-context reasoning, coding, math, and agentic tasks.' },
  'glm-5-2':                { name: 'GLM 5.2',                 description: 'Agentic engineering, long-horizon tool use, sustained reasoning.' },
  'kimi-k2-6':              { name: 'Kimi K2.6',               description: 'Multimodal understanding (text + images) with strong tool calling.' },
  'gemma4-31b':             { name: 'Gemma 4 31B',             description: 'Built-in thinking mode, image understanding, native function calling.' },
  'gpt-oss-120b':           { name: 'GPT-OSS 120B',            description: 'Configurable reasoning effort with full chain-of-thought access.' },
  'llama3-3-70b':           { name: 'Llama 3.3 70B',           description: 'Multilingual, dialogue-optimized, function calling.' },
  'qwen3-vl-30b':           { name: 'Qwen3-VL 30B',            description: 'Vision-language understanding, OCR, screenshot-to-code.' },
  'whisper-large-v3-turbo': { name: 'Whisper Large v3 Turbo',  description: 'Fast confidential speech-to-text transcription.' },
  'voxtral-small-24b':      { name: 'Voxtral Small 24B',       description: 'Transcription, audio Q&A, summarization, and translation.' },
  'qwen3-tts':              { name: 'Qwen3 TTS',               description: 'Lightweight, low-latency speech generation.' },
  'voxtral-tts':            { name: 'Voxtral TTS',             description: 'Natural-sounding text-to-speech synthesis.' },
};

function prettyName(slug) {
  return MODEL_INFO[slug]?.name
    || slug.split('-').map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w)).join(' ');
}

/**
 * Preset speakers per TTS model.
 *
 * Tinfoil's /v1/models catalog does NOT publish these (every entry's `voices`
 * is null), but /v1/audio/speech *requires* a `voice` and rejects anything
 * outside the model's own set — so an empty list here is not a harmless
 * "unknown", it's a guaranteed 400. These were read off the endpoint's own
 * rejection message ("Invalid speaker 'x'. Supported: …").
 *
 * First entry is the default when the user hasn't chosen one. Voice names are
 * strictly per-model: passing a Gemini name ("Zephyr") or an OpenAI one
 * ("alloy") to either of these 400s.
 */
const TINFOIL_VOICES = {
  'voxtral-tts': [
    'neutral_female', 'neutral_male', 'casual_female', 'casual_male', 'cheerful_female',
    'ar_male', 'de_female', 'de_male', 'es_female', 'es_male', 'fr_female', 'fr_male',
    'hi_female', 'hi_male', 'it_female', 'it_male', 'nl_female', 'nl_male',
    'pt_female', 'pt_male',
  ],
  'qwen3-tts': ['serena', 'aiden', 'dylan', 'eric', 'ono_anna', 'ryan', 'sohee', 'uncle_fu', 'vivian'],
};

/**
 * Preset speakers for a Tinfoil TTS model, by namespaced or upstream id.
 * Returns [] for non-TTS / unknown models. Synchronous — the list is static,
 * so callers on the request path don't need to await the catalog.
 */
function tinfoilVoicesFor(modelId) {
  if (typeof modelId !== 'string') return [];
  const slug = modelId.startsWith(TINFOIL_PREFIX) ? modelId.slice(TINFOIL_PREFIX.length) : modelId;
  return TINFOIL_VOICES[slug] || [];
}

// Catalog prices are USD per 1M tokens → USD per token (null when absent).
const perTokenFromPer1M = (v) => (typeof v === 'number' ? v / 1_000_000 : null);

const calcIsFree = (...prices) => {
  const known = prices.filter((p) => p !== null && p !== undefined);
  return known.length > 0 && known.every((p) => p === 0);
};

// Map the catalog's capability booleans to the `supportedParameters` strings
// the client's capability flags look for (Tools / Reasoning / JSON). Every
// Tinfoil chat model supports structured outputs per their model docs.
function mapSupportedParameters(m) {
  const out = [];
  if (m.tool_calling) out.push('tools');
  if (m.reasoning) out.push('reasoning');
  if (m.type === 'chat') out.push('response_format', 'structured_outputs');
  return out;
}

// Action buckets a Tinfoil model can satisfy. Vision models are also chat
// models, so they appear in both pickers.
const ACTION_CLASSES = {
  chat:   new Set(['chat', 'vision']),
  vision: new Set(['vision']),
  stt:    new Set(['stt']),
  tts:    new Set(['tts']),
};

/**
 * Catalog entries we refuse to surface even though Tinfoil serves them.
 *
 * `voxtral-tts` is listed, priced, and returns a well-formed 24 kHz mono MP3 —
 * it just doesn't say what you asked it to. Measured 2026-07-27: "The quick
 * brown fox jumps over the lazy dog." with `neutral_female` produced 8.3s of
 * audio that transcribes to "Thank you.", and the same kind of babble for
 * casual_male / cheerful_female / de_male, for `wav` as well as `mp3`, and for
 * every candidate sample-rate reinterpretation of the raw PCM (so it is not a
 * container mislabel). `qwen3-tts`, same host and same request shape, returns
 * the sentence verbatim. Offering a model that bills for unusable audio is
 * worse than offering one fewer voice — delete this entry when it's fixed.
 * (audioService.RETIRED_AUDIO_MODELS heals prefs that already point here.)
 */
const UNSERVABLE_MODELS = new Set(['voxtral-tts']);

// Classify a raw catalog entry into one of our action classes, or null to drop
// it. Classification keys off the catalog's own `type` + served `endpoints` so
// new models slot in without a code change.
function classifyTinfoilModel(m) {
  if (UNSERVABLE_MODELS.has(m?.id)) return null;
  const endpoints = Array.isArray(m?.endpoints) ? m.endpoints : [];
  switch (m?.type) {
    case 'chat':
      if (!endpoints.includes('/v1/chat/completions')) return null;
      return m.multimodal ? 'vision' : 'chat';
    case 'audio':
      // The realtime-only WebSocket transcriber has no batch endpoint we use.
      return endpoints.includes('/v1/audio/transcriptions') ? 'stt' : null;
    case 'tts':
      return endpoints.includes('/v1/audio/speech') ? 'tts' : null;
    default:
      // embedding | document | safety | tool — not user-selectable here.
      return null;
  }
}

// Shape a raw catalog entry into the same object the client `OpenRouterModel`
// consumer expects from /api/models/openrouter, plus TEE fields.
function mapTinfoilModel(m, cls) {
  const prompt = perTokenFromPer1M(m.pricing?.inputTokenPricePer1M);
  const completion = perTokenFromPer1M(m.pricing?.outputTokenPricePer1M);
  const perRequest = typeof m.pricing?.requestPrice === 'number' ? m.pricing.requestPrice : null;
  const inputModalities = cls === 'stt' ? ['audio'] : cls === 'vision' ? ['text', 'image'] : ['text'];
  const outputModalities = cls === 'tts' ? ['audio'] : ['text'];
  return {
    id: TINFOIL_PREFIX + m.id,
    name: prettyName(m.id),
    description: MODEL_INFO[m.id]?.description || '',
    contextLength: m.context_window || null,
    maxCompletionTokens: null,
    isModerated: false,
    supportedParameters: mapSupportedParameters(m),
    pricing: {
      promptPerMToken:        prompt     !== null ? prompt     * 1_000_000 : null,
      completionPerMToken:    completion !== null ? completion * 1_000_000 : null,
      imageInputPerMToken:    null,
      audioPerMToken:         null,
      imagePerImage:          null,
      inputCostPerMegapixel:  null,
      outputCostPerMegapixel: null,
      videoPerSecond:         null,
      videoSkus:              null,
      perRequest,
      isFree:                 calcIsFree(prompt, completion, perRequest),
    },
    provider: 'tinfoil',
    inputModalities,
    outputModalities,
    // The catalog publishes no voice list, but /v1/audio/speech requires one —
    // see TINFOIL_VOICES. Serving them here is what lets the client's voice
    // picker work and stops a foreign voice name reaching the endpoint.
    supportedVoices: cls === 'tts' ? tinfoilVoicesFor(m.id) : [],
    tokenizer: null,
    rankings: null,
    // Hardware confidential compute is a strictly stronger guarantee than
    // contractual ZDR, so enclave models satisfy the "Require Zero Data
    // Retention" gate AND carry their own distinct badge (mirrors NEAR).
    isZdr: true,
    isTee: true,
    teeStack: TINFOIL_TEE_STACK,
  };
}

async function _fetchTinfoilModels() {
  const key = process.env.TINFOIL_API_KEY;
  if (!key) throw new Error('TINFOIL_API_KEY not configured');

  // /v1/models is public, but send the key anyway — it keeps the request shape
  // uniform and future-proofs against the catalog going authenticated.
  const r = await fetch(`${tinfoilBase()}/models`, {
    headers: { Authorization: `Bearer ${key}` },
  });
  if (!r.ok) throw new Error(`Tinfoil /models ${r.status}`);
  const data = await r.json();
  const raw = Array.isArray(data?.data) ? data.data : [];

  const classified = raw
    .map((m) => ({ m, cls: classifyTinfoilModel(m) }))
    .filter((x) => x.cls);

  const models = classified.map(({ m, cls }) => ({ ...mapTinfoilModel(m, cls), tinfoilClass: cls }));
  const pricing = new Map(
    classified.map(({ m }) => [m.id, {
      promptPerToken: perTokenFromPer1M(m.pricing?.inputTokenPricePer1M),
      completionPerToken: perTokenFromPer1M(m.pricing?.outputTokenPricePer1M),
      perRequest: typeof m.pricing?.requestPrice === 'number' ? m.pricing.requestPrice : null,
    }])
  );
  return { models, pricing };
}

/**
 * Returns the cached array of mapped Tinfoil enclave models for a given picker
 * `action` ('chat' | 'vision' | 'stt' | 'tts'), refreshing lazily when the TTL
 * expires. Never throws — on failure returns the last successful value (or
 * []), so callers can concat unconditionally. The internal `tinfoilClass`
 * field is stripped from the returned objects.
 */
async function loadTinfoilModels(action = 'chat') {
  const now = Date.now();
  const fresh = now < _cache.expiresAt && _cache.models.length > 0;
  if (!fresh) {
    if (!_cache.inflight) {
      _cache.inflight = (async () => {
        try {
          const { models, pricing } = await _fetchTinfoilModels();
          _cache.models = models;
          _cache.pricing = pricing;
          _cache.expiresAt = Date.now() + CACHE_TTL_MS;
          return models;
        } catch (err) {
          console.warn('[tinfoilModels] refresh failed:', err.message);
          return _cache.models;
        } finally {
          _cache.inflight = null;
        }
      })();
    }
    await _cache.inflight;
  }

  const classes = ACTION_CLASSES[action];
  if (!classes) return [];
  return _cache.models
    .filter((m) => classes.has(m.tinfoilClass))
    .map(({ tinfoilClass, ...rest }) => rest);
}

/**
 * True if `modelId` is a Tinfoil vision model (text+image→text). Lets the
 * inference image-input gate keep an image attachment on the confidential
 * model instead of silently falling back to an OpenRouter vision model.
 */
async function isTinfoilImageInputModel(modelId) {
  if (typeof modelId !== 'string' || !modelId.startsWith(TINFOIL_PREFIX)) return false;
  const visionModels = await loadTinfoilModels('vision');
  return visionModels.some((m) => m.id === modelId);
}

/**
 * USD pricing for a Tinfoil model ({ promptPerToken, completionPerToken,
 * perRequest }), used to compute inference cost. Accepts either the namespaced
 * id (`tinfoil/<id>`) or the upstream id. Returns null if unknown (caller
 * falls back to flat rates).
 */
async function getTinfoilPricing(modelId) {
  await loadTinfoilModels();
  const upstream = typeof modelId === 'string' && modelId.startsWith(TINFOIL_PREFIX)
    ? modelId.slice(TINFOIL_PREFIX.length)
    : modelId;
  return _cache.pricing.get(upstream) || null;
}

module.exports = {
  loadTinfoilModels,
  getTinfoilPricing,
  isTinfoilImageInputModel,
  tinfoilVoicesFor,
  // Exported for test/audioModels.test.js — classification is pure, so it can be
  // asserted against catalog-shaped fixtures without touching the network.
  classifyTinfoilModel,
  UNSERVABLE_MODELS,
  TINFOIL_PREFIX,
  TINFOIL_TEE_STACK,
};
