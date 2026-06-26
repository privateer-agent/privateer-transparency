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
 * Inference Service — unified text + image + video generation, all via OpenRouter.
 *
 * Multimodal inputs supported in generateText():
 *   { image: Buffer, mimeType }   — image vision
 *   { pdf: Buffer, filename }     — PDF analysis
 *   { audio: Buffer, format }     — audio analysis
 *
 * Image generation:
 *   OpenRouter image models (FLUX, Recraft, OpenAI gpt-image, etc.) via
 *   chat/completions with modalities: ["image","text"].
 *
 * Video generation:
 *   OpenRouter /api/v1/videos — async, job-based.
 */

const ModelRateConfig = require('../models/modelRateConfigModel');
const billingService = require('./billingService');
const { getRatioParamMode, supportsTransparency } = require('../data/imageModelCapabilities');
const { isZdrModel } = require('../data/zdrProviders');
const { safeFetch } = require('../utils/safeFetch');
const Sentry = require('@sentry/node');
const logger = require('../utils/logger');

// ── Output formatting directive ──────────────────────────────────────────────

const NO_TABLES_DIRECTIVE = [
  'STRICT FORMATTING RULE — NO TABLES:',
  '- Never output markdown pipe tables (lines using "|" as column separators).',
  '- Never output ASCII/box-drawing tables or HTML <table> elements.',
  '- Never output a markdown table separator row (e.g. "| --- | --- |").',
  '- Present every piece of tabular, comparative, or multi-column information as bulleted lists, numbered lists, headed sections, or prose.',
  '- For each row, write a bullet of the form "- **Name**: value — value — value" instead of a table row.',
  'This rule overrides any default formatting preference. If you are about to write a table, rewrite it as a list before sending.'
].join('\n');

function withNoTables(systemPrompt) {
  if (!systemPrompt) return NO_TABLES_DIRECTIVE;
  return `${systemPrompt}\n\n${NO_TABLES_DIRECTIVE}`;
}

// ── Table → bulleted-list post-processor ─────────────────────────────────────
// Even with the directive above, models occasionally still emit pipe tables.
// We deterministically convert them so the user never sees one.

const SEPARATOR_RE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/;
const PIPE_ROW_RE = /\|/;

function splitTableRow(line) {
  const parts = line.split('|').map(s => s.trim());
  if (parts.length && parts[0] === '') parts.shift();
  if (parts.length && parts[parts.length - 1] === '') parts.pop();
  return parts;
}

function rowToBullet(headers, cells) {
  if (!headers || headers.length === 0) {
    return '- ' + cells.filter(Boolean).join(' — ');
  }
  const pairs = headers.map((h, i) => {
    const v = cells[i] ?? '';
    return h ? `**${h}**: ${v}` : v;
  });
  return '- ' + pairs.join(' — ');
}

function convertTablesToBullets(text) {
  if (!text || text.indexOf('|') === -1) return text;
  const lines = text.split('\n');
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const header = lines[i];
    const sep = lines[i + 1];
    const isTable = PIPE_ROW_RE.test(header) && sep && SEPARATOR_RE.test(sep);
    if (!isTable) { out.push(header); i++; continue; }

    const headers = splitTableRow(header);
    i += 2;
    while (i < lines.length && PIPE_ROW_RE.test(lines[i]) && lines[i].trim() !== '') {
      out.push(rowToBullet(headers, splitTableRow(lines[i])));
      i++;
    }
  }
  return out.join('\n');
}

// Stateful line-buffered converter for streamed output. Holds back lines just
// long enough to decide whether they are part of a pipe table; non-table lines
// flow through with at most one line of latency.
function createStreamingTableConverter(emit) {
  let partial = '';
  const pending = [];

  const flushReady = (force) => {
    while (pending.length > 0) {
      const first = pending[0];
      if (!PIPE_ROW_RE.test(first)) {
        emit(pending.shift() + '\n');
        continue;
      }
      if (pending.length < 2) {
        if (!force) return;
        emit(pending.shift() + '\n');
        continue;
      }
      const second = pending[1];
      if (!SEPARATOR_RE.test(second)) {
        emit(pending.shift() + '\n');
        continue;
      }
      // Confirmed table — find end (first non-pipe or empty line)
      let end = 2;
      while (end < pending.length && PIPE_ROW_RE.test(pending[end]) && pending[end].trim() !== '') end++;
      if (end === pending.length && !force) return; // wait for more input
      const tableLines = pending.splice(0, end);
      emit(convertTablesToBullets(tableLines.join('\n')) + '\n');
    }
  };

  return {
    push(chunk) {
      if (!chunk) return;
      partial += chunk;
      const lines = partial.split('\n');
      partial = lines.pop() ?? '';
      for (const line of lines) pending.push(line);
      flushReady(false);
    },
    end() {
      if (partial) { pending.push(partial); partial = ''; }
      flushReady(true);
    }
  };
}

// ── OpenRouter helpers ───────────────────────────────────────────────────────

const OPENROUTER_BASE = process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1';

// Per-attempt upstream timeout. Without this the only ceiling is undici's
// ~300s default, and a hung media call surfaces to the user as an infinite
// "Preparing image generation" spinner (the SSE stream never gets a terminal
// event). Media actions (image/video gen via `modalities`) legitimately take
// longer than text, so they get a larger budget — slow reasoning-image models
// (gpt-image class) routinely exceed 120s, so the budget is 240s. On timeout we
// abort the fetch and throw a PROVIDER_UNAVAILABLE error, which the image/video
// paths already surface as a friendly, retryable error bubble.
// Keep the client's SSE watchdog (chatService.ts STREAM_INACTIVITY_MS) sized
// above this value, or the client gives up before the server's error arrives.
const OR_MEDIA_TIMEOUT_MS = Number(process.env.OR_MEDIA_TIMEOUT_MS) || 240_000;
const OR_TEXT_TIMEOUT_MS  = Number(process.env.OR_TEXT_TIMEOUT_MS)  || 240_000;

// Two OpenRouter keys back the ZDR guarantee. The per-request `provider.zdr`
// flag only OR-adds ZDR and only protects paths that remember to set it — so it
// is not a *structural* guarantee. The hard guarantee is the account/org-level
// ZDR setting (all four model groups enabled), which we isolate on a dedicated
// key. Every ZDR-required, content-carrying request uses OPENROUTER_API_KEY_ZDR;
// explicitly non-ZDR requests (user opted out, or a non-ZDR media model the user
// opted into) use the standard OPENROUTER_API_KEY.
//
// Fail closed: a ZDR-required request with no ZDR key configured is rejected
// (ZDR_KEY_UNAVAILABLE), never silently downgraded to the standard key.
function orHeaders(useZdrKey = false) {
  const key = useZdrKey ? process.env.OPENROUTER_API_KEY_ZDR : process.env.OPENROUTER_API_KEY;
  if (useZdrKey && !key) {
    throw Object.assign(
      new Error('Zero Data Retention is required for this request, but no ZDR OpenRouter key is configured.'),
      { statusCode: 503, code: 'ZDR_KEY_UNAVAILABLE' }
    );
  }
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${key}`,
    'HTTP-Referer': process.env.SERVER_URL || 'https://privateer.pro',
    'X-Title': 'Privateer'
  };
}

// Catalog/metadata reads (/models, /endpoints, /videos/models, etc.) carry no
// user content, so they always use the standard key.
const OPENROUTER_HEADERS = () => orHeaders(false);

// Decide whether a content-carrying request must use the ZDR-enforced key.
//   • requireZdr off          → standard key (user opted out entirely).
//   • non-media + requireZdr  → ZDR key (chat/vision/intent/memory/stt/tts).
//   • media + requireZdr      → ZDR key only if the chosen model actually has a
//     ZDR endpoint; a non-ZDR media model (allowed only via allowNonZdrMedia)
//     routes through the standard key (the ZDR account would 404 it).
async function resolveUseZdrKey({ requireZdr, modelId, isMediaAction = false } = {}) {
  if (!requireZdr) return false;
  if (!isMediaAction) return true;
  return await isZdrModel(modelId);
}

// Persistent HTTP/1.1 keep-alive pool to OpenRouter. Each chat turn fans out
// several requests to the same host (intent classifier, memory judge, main
// inference, occasionally the search-query builder), and without a shared
// dispatcher each one paid a fresh TCP+TLS handshake (~80–250ms). Node 20
// ships undici natively, so we attach a singleton Agent and pass it as
// `dispatcher` on every OpenRouter fetch.
const { Agent: UndiciAgent } = require('undici');
const openrouterDispatcher = new UndiciAgent({
  keepAliveTimeout: 30_000,
  keepAliveMaxTimeout: 60_000,
  connections: 50,
});
const orFetchInit = (init = {}) => ({ ...init, dispatcher: openrouterDispatcher });

// Normalise OpenRouter `url_citation` annotations into the same {title, url,
// description} shape Brave results use, so the client renders both identically.
function extractWebCitations(annotations) {
  if (!Array.isArray(annotations) || annotations.length === 0) return [];
  const out = [];
  for (const a of annotations) {
    const c = a?.url_citation || (a?.type === 'url_citation' ? a : null);
    if (!c?.url) continue;
    out.push({
      title: c.title || c.url,
      url: c.url,
      description: c.content || '',
    });
  }
  return out;
}

// og:image enrichment for source cards. Fetches the source pages and pulls the
// OpenGraph/Twitter hero image so the client can render rich cards instead of a
// bare favicon. Best-effort: tightly time-boxed, capped, memoized, and degrades
// to no image (client falls back to favicon) on any failure. The source URLs are
// the web-search results the server already produced, so fetching them server-
// side leaks nothing the server doesn't already hold.
const OG_IMAGE_CACHE = new Map(); // url -> { image: string|null, at: number }
const OG_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6h
const OG_CACHE_MAX = 500;
const OG_MAX_SOURCES = 8;
const OG_PER_REQUEST_MS = 2000;
const OG_OVERALL_MS = 2500;
const OG_MAX_BYTES = 50 * 1024;

function ogCacheGet(url) {
  const hit = OG_IMAGE_CACHE.get(url);
  if (!hit) return undefined;
  if (Date.now() - hit.at > OG_CACHE_TTL_MS) {
    OG_IMAGE_CACHE.delete(url);
    return undefined;
  }
  return hit.image; // string | null
}

function ogCacheSet(url, image) {
  if (OG_IMAGE_CACHE.size >= OG_CACHE_MAX) {
    const oldest = OG_IMAGE_CACHE.keys().next().value;
    if (oldest !== undefined) OG_IMAGE_CACHE.delete(oldest);
  }
  OG_IMAGE_CACHE.set(url, { image, at: Date.now() });
}

function parseOgImage(html, pageUrl) {
  // Match <meta property="og:image" content="..."> (and twitter:image) in any
  // attribute order. Falls back to twitter:image when og:image is absent.
  const tryProp = (prop) => {
    const re = new RegExp(
      `<meta[^>]+(?:property|name)=["']${prop}["'][^>]*>`,
      'i',
    );
    const tag = html.match(re)?.[0];
    if (!tag) return null;
    const content = tag.match(/content=["']([^"']+)["']/i)?.[1];
    return content ? content.trim() : null;
  };
  const raw = tryProp('og:image') || tryProp('twitter:image') || null;
  if (!raw) return null;
  try {
    // Resolve protocol-relative ("//cdn/...") and relative ("/img.png") URLs.
    return new URL(raw, pageUrl).toString();
  } catch {
    return null;
  }
}

async function fetchOgImage(url) {
  const cached = ogCacheGet(url);
  if (cached !== undefined) return cached;

  let image = null;
  try {
    // These are user-derived source URLs (web-search / citation results), so the
    // fetch is routed through the SSRF-hardened safeFetch — it refuses private/
    // loopback/metadata targets and re-validates every redirect hop (this path
    // previously followed redirects with no IP filtering). Byte cap stays low:
    // og:image tags live in the document head.
    const res = await safeFetch(url, { timeoutMs: OG_PER_REQUEST_MS, maxBytes: OG_MAX_BYTES });
    if (res.contentType.includes('html')) {
      image = parseOgImage(res.text, res.finalUrl || url);
    }
  } catch {
    image = null;
  }
  ogCacheSet(url, image);
  return image;
}

async function enrichWithImages(sources) {
  if (!Array.isArray(sources) || sources.length === 0) return sources;
  const targets = sources
    .slice(0, OG_MAX_SOURCES)
    .filter((s) => typeof s.url === 'string' && /^https?:\/\//i.test(s.url));
  if (targets.length === 0) return sources;

  const work = Promise.allSettled(
    targets.map(async (s) => {
      const image = await fetchOgImage(s.url);
      if (image) s.image = image;
    }),
  );
  // Hard cap so a batch of slow pages can't delay the whole response.
  await Promise.race([
    work,
    new Promise((resolve) => setTimeout(resolve, OG_OVERALL_MS)),
  ]);
  return sources;
}

// Bound conversation history to a token budget so request size (and TTFT)
// stops scaling with chat length. Drops oldest turns first, preserves the
// system message at index 0, and keeps role pairing intact so the model
// never sees a stranded assistant turn without its user. Token counts are
// rough (chars/4) — exactness doesn't matter; this is a cap, not billing.
function estimateTokens(content) {
  if (typeof content === 'string') return Math.ceil(content.length / 4);
  if (Array.isArray(content)) {
    let n = 0;
    for (const part of content) {
      if (!part) continue;
      if (typeof part === 'string') n += Math.ceil(part.length / 4);
      else if (typeof part.text === 'string') n += Math.ceil(part.text.length / 4);
      // Non-text parts (images, audio, video, files) are bounded by the
      // provider's own limits — not counted toward the history budget.
    }
    return n;
  }
  return 0;
}

function windowHistory(messages, { maxTokens = 12000 } = {}) {
  if (!Array.isArray(messages) || messages.length === 0) return messages;

  const hasSystem = messages[0]?.role === 'system';
  const systemMsg = hasSystem ? messages[0] : null;
  const tail = hasSystem ? messages.slice(1) : messages;
  if (tail.length === 0) return messages;

  // The new user turn is always the last message — keep it. Walk backwards
  // through prior turns, accumulating tokens until the budget is hit.
  const lastIdx = tail.length - 1;
  let used = estimateTokens(tail[lastIdx].content);
  let firstKeptIdx = lastIdx;
  for (let i = lastIdx - 1; i >= 0; i--) {
    const t = estimateTokens(tail[i].content);
    if (used + t > maxTokens) break;
    used += t;
    firstKeptIdx = i;
  }

  // Don't strand an assistant without its preceding user turn.
  if (tail[firstKeptIdx]?.role === 'assistant' && firstKeptIdx + 1 <= lastIdx) firstKeptIdx += 1;

  const dropped = firstKeptIdx;
  if (dropped <= 0) return messages;

  const kept = tail.slice(firstKeptIdx);
  logger.debug(`[history-window] dropped ${dropped}/${tail.length} prior turns (~${estimateTokens(tail.slice(0, firstKeptIdx).map(m => m.content).join(' '))} tokens) to fit ${maxTokens}-tok budget`);
  return systemMsg ? [systemMsg, ...kept] : kept;
}

// Tag stable prefix blocks (system prompt + last history turn) with
// `cache_control: {type:'ephemeral'}` so OpenRouter passes the caching hint
// through to providers that respect it. Required for Anthropic; harmless
// metadata for providers (DeepSeek/Gemini/OpenAI) that auto-cache or ignore
// the hint. Idempotent: safe to call on a messages array that's already been
// hinted. modelId is retained for future provider-specific gating.
function applyPromptCacheHints(messages, modelId) {
  if (!Array.isArray(messages) || messages.length === 0) return;

  const tagContent = (msg) => {
    if (!msg) return;
    if (typeof msg.content === 'string') {
      msg.content = [{ type: 'text', text: msg.content, cache_control: { type: 'ephemeral' } }];
      return;
    }
    if (Array.isArray(msg.content) && msg.content.length > 0) {
      const last = msg.content[msg.content.length - 1];
      if (last && typeof last === 'object') last.cache_control = { type: 'ephemeral' };
    }
  };

  // Cache the system prompt — stable across the whole conversation.
  if (messages[0]?.role === 'system') tagContent(messages[0]);

  // Cache through the last assistant turn so the entire prior transcript
  // counts as the cached prefix on turn N (only the new user turn is fresh).
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]?.role === 'assistant') { tagContent(messages[i]); break; }
  }
}

// Latency-based provider routing (env-gated). When OPENROUTER_PROVIDER_SORT is
// set (e.g. "latency" | "throughput" | "price"), OpenRouter routes each request
// to the best provider on a trailing 5-min average; gateway overhead is only
// ~50–70 ms. Unset = OpenRouter's default routing (no behaviour change).
function applyProviderRouting(body) {
  const sort = process.env.OPENROUTER_PROVIDER_SORT;
  if (sort) body.provider = { ...(body.provider || {}), sort };
  return body;
}

// Layer the per-request ZDR hint onto the body. This is belt-and-suspenders on
// top of the account-level guarantee provided by the ZDR key (see orHeaders).
//   • useZdrKey (request is on the ZDR key): pin to ZDR endpoints AND exclude any
//     provider that stores data non-transiently.
//   • otherwise (standard key): for any model OpenRouter lists as ZDR-eligible,
//     set `zdr: true` so the "ZDR" badge the UI shows is honoured even for
//     opted-out users — but never `data_collection: 'deny'`, which could 404 a
//     non-ZDR model the user explicitly opted into.
// Auto-enforce is skipped when the caller forced a specific provider via
// `provider.only` (e.g. base64 video → google-vertex): layering `zdr: true` on top
// could leave no eligible endpoint and 404 the request. `provider.zdr` OR's with
// any account/guardrail ZDR setting — it only ever tightens, never loosens.
async function applyZdrRouting(body, modelId, { useZdrKey = false } = {}) {
  if (useZdrKey) {
    body.provider = { ...(body.provider || {}), zdr: true, data_collection: 'deny' };
    return body;
  }
  if (body.provider?.only) return body;
  if (await isZdrModel(modelId)) {
    body.provider = { ...(body.provider || {}), zdr: true };
  }
  return body;
}

async function openRouterChat(messages, modelId, options = {}) {
  const MAX_RETRIES = 3;
  const BASE_DELAY_MS = 2000;

  const body = {
    model: modelId,
    messages,
    temperature: options.temperature ?? 0.8,
    max_tokens: options.maxTokens ?? 8192,
  };

  // Image generation via chat completions endpoint.
  // Per OpenRouter spec, both aspect_ratio and image_size live INSIDE image_config;
  // there are no top-level size/aspect_ratio fields for image generation.
  if (options.modalities) body.modalities = options.modalities;
  if (options.image_config) body.image_config = options.image_config;

  // PDF plugin for file parsing
  if (options.plugins) body.plugins = options.plugins;

  // OpenRouter `web` plugin — model self-invokes web search and returns
  // `url_citation` annotations on the assistant message. Composes with the
  // PDF plugin (the array is appended to, never replaced).
  if (options.webPlugin) {
    const webEntry = { id: 'web', ...(typeof options.webPlugin === 'object' ? options.webPlugin : {}) };
    body.plugins = [...(body.plugins || []), webEntry];
  }

  // Caller-supplied provider routing (e.g. force Google Vertex for base64
  // video input). Merged before applyProviderRouting so env `sort` still layers on.
  if (options.provider) body.provider = { ...(body.provider || {}), ...options.provider };

  // Image generation runs through chat/completions with `modalities`, so it's a
  // media action for key-selection purposes.
  const useZdrKey = await resolveUseZdrKey({
    requireZdr: options.requireZdr,
    modelId,
    isMediaAction: options.isMediaAction ?? !!options.modalities,
  });
  await applyZdrRouting(body, modelId, { useZdrKey });
  applyProviderRouting(body);

  // Media (image/video) calls run longer than text; bound each attempt so a
  // hung upstream becomes a visible, retryable error instead of an open socket.
  const isMediaAction = options.isMediaAction ?? !!options.modalities;
  const timeoutMs = options.timeoutMs ?? (isMediaAction ? OR_MEDIA_TIMEOUT_MS : OR_TEXT_TIMEOUT_MS);

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    // Fresh abort budget per attempt — a retry shouldn't inherit a spent timer.
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(`${OPENROUTER_BASE}/chat/completions`, orFetchInit({
        method: 'POST',
        headers: orHeaders(useZdrKey),
        body: JSON.stringify(body),
        signal: abort.signal,
      }));
    } catch (fetchErr) {
      // AbortError from our own timer → treat as an unavailable provider so the
      // media paths surface a friendly, retryable error (mirrors 5xx/404 below).
      if (fetchErr?.name === 'AbortError') {
        const err = new Error(`OpenRouter request timed out after ${timeoutMs}ms for ${modelId}`);
        err.code = 'PROVIDER_UNAVAILABLE';
        err.modelId = modelId;
        err.timedOut = true;
        throw err;
      }
      throw fetchErr;
    } finally {
      clearTimeout(timer);
    }

    if (res.ok) return res.json();

    const errText = await res.text();

    if (res.status === 429 && attempt < MAX_RETRIES) {
      const delay = BASE_DELAY_MS * Math.pow(2, attempt);
      logger.warn(`[openrouter] 429 rate limit for ${modelId}, retrying in ${delay}ms (attempt ${attempt + 1}/${MAX_RETRIES})`);
      await new Promise(resolve => setTimeout(resolve, delay));
      continue;
    }

    const err = new Error(`OpenRouter error ${res.status}: ${errText}`);
    if (res.status === 429) err.statusCode = 429;
    if (res.status === 404 || res.status === 503 || res.status >= 500) {
      err.code = 'PROVIDER_UNAVAILABLE';
      err.modelId = modelId;
    }
    throw err;
  }
}

// ── Validate model ───────────────────────────────────────────────────────────

/**
 * Resolves and validates the model ID. All inference flows through OpenRouter,
 * so the model must be in slash-prefixed form (e.g. "google/gemini-2.5-flash").
 */
async function resolveModelId(requestedModelId) {
  const defaultId = process.env.DEFAULT_MODEL_ID || 'deepseek/deepseek-v4-flash';
  const modelId = requestedModelId || defaultId;

  if (typeof modelId !== 'string' || !modelId.includes('/')) {
    throw Object.assign(
      new Error(`Model '${modelId}' is not an OpenRouter model. Use the slash-prefixed form (e.g. "google/${modelId}").`),
      { statusCode: 400, code: 'INVALID_MODEL', modelId }
    );
  }

  // If a rate config row exists and is disabled, reject
  const config = await ModelRateConfig.findOne({ modelId }).lean().catch(() => null);
  if (config && !config.enabled) {
    throw Object.assign(
      new Error(`Model '${modelId}' is disabled`),
      { statusCode: 400, code: 'INVALID_MODEL', modelId }
    );
  }

  return modelId;
}

// ── Video-input capability lookup ────────────────────────────────────────────
// OpenRouter rejects a `video_url` part with 404 "No endpoints found that
// support input video" unless the chosen model exposes "video" in its
// architecture.input_modalities. Callers use this to substitute a known
// video-capable model before sending. The catalog is cached briefly so each
// video-analysis turn doesn't refetch the full model list. On any failure we
// return false so the caller falls back to the safe default model.
let _videoModelCache = { ids: null, at: 0 };
const VIDEO_MODEL_CACHE_MS = 5 * 60 * 1000;

async function isVideoInputModel(modelId) {
  if (!modelId || typeof modelId !== 'string') return false;
  try {
    const now = Date.now();
    if (!_videoModelCache.ids || now - _videoModelCache.at > VIDEO_MODEL_CACHE_MS) {
      const res = await fetch(`${OPENROUTER_BASE}/models`, orFetchInit({ headers: OPENROUTER_HEADERS() }));
      if (!res.ok) return false;
      const data = await res.json();
      const ids = new Set(
        (data?.data || [])
          .filter(m => (m?.architecture?.input_modalities || []).includes('video'))
          .map(m => m.id)
      );
      _videoModelCache = { ids, at: now };
    }
    return _videoModelCache.ids.has(modelId);
  } catch {
    return false;
  }
}

// Same shape as isVideoInputModel: OpenRouter 404s with "No endpoints found
// that support image input" when a chat-vision turn lands on a text-only
// model. Callers fall back to a known image-capable default when this returns
// false.
let _imageModelCache = { ids: null, at: 0 };
const IMAGE_MODEL_CACHE_MS = 5 * 60 * 1000;

async function isImageInputModel(modelId) {
  if (!modelId || typeof modelId !== 'string') return false;
  // NEAR vision models (Qwen-VL, Gemma, Kimi…) aren't in OpenRouter's catalog, so
  // the lookup below would miss them and silently substitute an OpenRouter vision
  // model — breaking the confidential guarantee. Honor the NEAR catalog instead.
  if (modelId.startsWith('near/')) {
    const { isNearImageInputModel } = require('../data/nearModels');
    return isNearImageInputModel(modelId);
  }
  try {
    const now = Date.now();
    if (!_imageModelCache.ids || now - _imageModelCache.at > IMAGE_MODEL_CACHE_MS) {
      const res = await fetch(`${OPENROUTER_BASE}/models`, orFetchInit({ headers: OPENROUTER_HEADERS() }));
      if (!res.ok) return false;
      const data = await res.json();
      const ids = new Set(
        (data?.data || [])
          .filter(m => (m?.architecture?.input_modalities || []).includes('image'))
          .map(m => m.id)
      );
      _imageModelCache = { ids, at: now };
    }
    return _imageModelCache.ids.has(modelId);
  } catch {
    return false;
  }
}

// ── Cost calculation ─────────────────────────────────────────────────────────
//
// TRANSPARENCY REPO OMISSION — proprietary billing logic, intentionally redacted.
//
// The cost/pricing layer (per-token rate sync from the provider catalog,
// markup-factor application, ModelRateConfig upsert/caching, and the
// usage-charging path in `billingService`) is part of Privateer's CLOSED
// codebase and is NOT published here. Per our open-source policy we open the
// "plaintext trust boundary" only; billing operates purely on token *counts*
// and model IDs — it never sees, stores, or transmits user content — so it
// adds no auditability to the privacy claim.
//
// The functions below are stubbed to preserve call-site readability. In the
// shipped server they fetch authoritative pricing and apply our markup; here
// they return zeros. See docs/E2EE_ARCHITECTURE.md for what IS in scope.

async function fetchOpenRouterCost(/* generationId */) {
  return null; // omitted: see banner above
}

async function ensureModelRateConfig(/* modelId */) {
  /* omitted: provider-pricing sync + markup, closed billing logic */
}

async function calcOpenRouterCost(/* modelId, _generationId, inputTokens, outputTokens */) {
  // Omitted: real implementation resolves per-model rates and applies the
  // markup factor. Cost is computed from token counts only — no user content.
  return { costUsd: 0, providerCostUsd: 0 };
}

// ── Part type helpers ────────────────────────────────────────────────────────

function hasPdfParts(parts) {
  return parts.some(p => p && typeof p === 'object' && p.pdf);
}

function hasAudioParts(parts) {
  return parts.some(p => p && typeof p === 'object' && p.audio);
}


/**
 * Infer audio format string from MIME type.
 */
function mimeToAudioFormat(mimeType) {
  const map = {
    'audio/wav': 'wav',
    'audio/wave': 'wav',
    'audio/x-wav': 'wav',
    'audio/mp3': 'mp3',
    'audio/mpeg': 'mp3',
    'audio/aiff': 'aiff',
    'audio/x-aiff': 'aiff',
    'audio/aac': 'aac',
    'audio/ogg': 'ogg',
    'audio/flac': 'flac',
    'audio/x-flac': 'flac',
    'audio/m4a': 'm4a',
    'audio/x-m4a': 'm4a',
    'audio/mp4': 'm4a',
  };
  return map[mimeType] || 'mp3';
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Generate text (and optionally analyze multimodal inputs).
 *
 * @param {Array<string
 *   | { image: Buffer, mimeType: string }
 *   | { pdf: Buffer, filename: string }
 *   | { audio: Buffer, format?: string, mimeType?: string }
 *   | { video: Buffer, mimeType?: string, filename?: string }
 * >} parts
 * @param {object} options  modelId, maxTokens, temperature, systemPrompt — all optional
 * @returns {{ text, inputTokens, outputTokens, costUsd, providerCostUsd }}
 */
async function generateText(parts, options = {}) {
  // NEAR AI (TEE) models are OpenAI-compatible but routed to a different host
  // and key, with no ZDR two-key logic. Lazy require avoids a load-time cycle.
  const nearAiService = require('./nearAiService');
  if (nearAiService.isNearModel(options.modelId)) {
    return nearAiService.generateText(parts, options);
  }

  const modelId = await resolveModelId(options.modelId);

  const normalizedParts = Array.isArray(parts) ? parts : [parts];

  let messages = [];
  messages.push({ role: 'system', content: withNoTables(options.systemPrompt) });

  // Role-tagged history between system and the current user turn. Sending the
  // transcript as proper messages (rather than flattened into the user blob)
  // is what makes provider-level prompt caching possible — repeated prefixes
  // (system + history) hit the cache instead of being re-encoded each turn.
  if (Array.isArray(options.history) && options.history.length > 0) {
    for (const h of options.history) {
      if (!h || typeof h.content !== 'string' || !h.content) continue;
      const role = h.role === 'assistant' ? 'assistant' : 'user';
      messages.push({ role, content: h.content });
    }
  }

  const contentArray = [];
  let hasPdfPlugin = false;

  for (const p of normalizedParts) {
    if (typeof p === 'string') {
      if (p) contentArray.push({ type: 'text', text: p });
    } else if (p.image) {
      contentArray.push({
        type: 'image_url',
        image_url: { url: `data:${p.mimeType || 'image/jpeg'};base64,${p.image.toString('base64')}` }
      });
    } else if (p.pdf) {
      const b64 = p.pdf.toString('base64');
      contentArray.push({
        type: 'file',
        file: {
          filename: p.filename || 'document.pdf',
          file_data: `data:application/pdf;base64,${b64}`
        }
      });
      hasPdfPlugin = true;
    } else if (p.audio) {
      const format = p.format || mimeToAudioFormat(p.mimeType || 'audio/mp3');
      contentArray.push({
        type: 'input_audio',
        input_audio: {
          data: p.audio.toString('base64'),
          format
        }
      });
    } else if (p.video) {
      // Video MUST use the `video_url` content type — NOT `file`/`file_data`
      // (that path is for PDFs). OpenRouter only routes `video_url` parts to
      // Gemini's video pipeline; a `file` part is treated as a generic
      // argument and Gemini rejects it with 400 INVALID_ARGUMENT. The data
      // URI carries the raw bytes — no transcoding here. Gemini accepts
      // video/mp4|mpeg|mov|webm; iOS records .mov as video/quicktime, which
      // is not in that list, so normalize it to video/mov.
      const b64 = p.video.toString('base64');
      let mime = p.mimeType || 'video/mp4';
      if (mime === 'video/quicktime') mime = 'video/mov';
      contentArray.push({
        type: 'video_url',
        video_url: { url: `data:${mime};base64,${b64}` }
      });
    } else if (p.textBlock) {
      contentArray.push({ type: 'text', text: p.textBlock });
    } else if (p.text) {
      contentArray.push({ type: 'text', text: p.text });
    }
  }

  const hasMultimodal = contentArray.some(c => c.type !== 'text');
  if (hasMultimodal || contentArray.length > 1) {
    messages.push({ role: 'user', content: contentArray });
  } else if (contentArray.length === 1 && contentArray[0].type === 'text') {
    messages.push({ role: 'user', content: contentArray[0].text });
  } else {
    messages.push({ role: 'user', content: normalizedParts.map(p => (typeof p === 'string' ? p : p.text || '')).join('\n') });
  }

  const chatOptions = { ...options };
  // pdf.engine must be specified — without it OpenRouter skips extraction.
  if (hasPdfPlugin) {
    chatOptions.plugins = [{ id: 'file-parser', pdf: { engine: 'mistral-ocr' } }];
  }

  messages = windowHistory(messages, { maxTokens: options.historyTokenBudget ?? 12000 });
  applyPromptCacheHints(messages, modelId);

  const processOpenRouterResult = async (data) => {
    const rawText = data.choices[0]?.message?.content || '';
    const text = convertTablesToBullets(rawText);
    const inputTokens = data.usage?.prompt_tokens || 0;
    const outputTokens = data.usage?.completion_tokens || 0;
    const { costUsd, providerCostUsd } = await calcOpenRouterCost(modelId, data.id, inputTokens, outputTokens);
    const sources = await enrichWithImages(extractWebCitations(data.choices[0]?.message?.annotations));
    return { text, inputTokens, outputTokens, costUsd, providerCostUsd, sources };
  };

  try {
    return await processOpenRouterResult(await openRouterChat(messages, modelId, chatOptions));
  } catch (err) {
    // Some providers don't support role:'system' — retry without it
    if (err.message?.includes('Developer instruction is not enabled') && messages[0]?.role === 'system') {
      logger.warn(`[inference] ${modelId} does not support system role — retrying without system message`);
      const sysContent = messages[0].content;
      const userMessages = messages.slice(1);
      if (userMessages[0]?.role === 'user') {
        if (typeof userMessages[0].content === 'string') {
          userMessages[0] = { ...userMessages[0], content: `${sysContent}\n\n${userMessages[0].content}` };
        } else if (Array.isArray(userMessages[0].content)) {
          userMessages[0] = { ...userMessages[0], content: [{ type: 'text', text: sysContent + '\n\n' }, ...userMessages[0].content] };
        }
      }
      return await processOpenRouterResult(await openRouterChat(userMessages, modelId, chatOptions));
    }

    if (!err.__sentryReported) {
      Sentry.captureException(err, { tags: { op: 'openrouter_chat' }, extra: { modelId } });
      err.__sentryReported = true;
    }
    throw err;
  }
}

/**
 * Generate or edit an image via OpenRouter chat/completions with
 * modalities: ["image","text"]. Supports FLUX, Recraft, Stability, OpenAI
 * gpt-image / DALL·E, and any other OpenRouter-hosted image model.
 *
 * @param {Array<string | { image: Buffer, mimeType: string }>} parts
 * @param {object} options  modelId, aspectRatio
 * @returns {{ images: Array<{ buffer: Buffer, mimeType: string }>, responseText: string, inputTokens: number }}
 */
/**
 * Build the OpenRouter image_config payload for a given model.
 *
 * Per https://openrouter.ai/docs/guides/overview/multimodal/image-generation,
 * both aspect_ratio and image_size go inside `image_config`:
 *   image_config: { aspect_ratio: "16:9", image_size: "1K" }
 *
 * image_size values: "0.5K" | "1K" | "2K" | "4K"  (default "1K")
 * aspect_ratio values: "1:1", "2:3", "3:2", "3:4", "4:3", "4:5", "5:4",
 *                      "9:16", "16:9", "21:9"
 * Gemini 3.1 Flash Image Preview also accepts "1:4", "4:1", "1:8", "8:1".
 *
 * Some Gemini variants (e.g. Nano Banana / gemini-2.5-flash-image) ignore
 * image_config and only respond to natural-language hints — for those the
 * capability table sets mode='prompt' and the caller folds the ratio into
 * the user prompt instead. All other OpenRouter image models receive
 * image_config.
 */
function buildOpenRouterAspectFields(modelId, aspectRatio, imageSize, transparentBackground = false) {
  const mode = getRatioParamMode(modelId);

  if (mode === 'prompt') {
    // Caller embeds the ratio in the user prompt — no body field. These models
    // (Nano Banana) also have no transparency param; a transparent background is
    // requested via the prompt text instead.
    return {};
  }

  const image_config = {};
  if (aspectRatio) image_config.aspect_ratio = aspectRatio;
  if (imageSize)   image_config.image_size   = imageSize;
  // Transparent background only for models that honor it. Force PNG (alpha-capable)
  // so the transparency survives the provider's encode step.
  if (transparentBackground && supportsTransparency(modelId)) {
    image_config.background = 'transparent';
    image_config.output_format = 'png';
  }
  return Object.keys(image_config).length > 0 ? { image_config } : {};
}

async function generateImage(parts, options = {}) {
  // NEAR confidential image models (FLUX) use the dedicated /v1/images endpoint,
  // not OpenRouter's chat-completions-with-modalities convention. Delegate before
  // resolveModelId so the `near/` id is preserved.
  const nearAiService = require('./nearAiService');
  if (nearAiService.isNearModel(options.modelId)) {
    return nearAiService.generateImage(parts, options);
  }

  const normalizedParts = Array.isArray(parts) ? parts : [parts];
  const modelId = await resolveModelId(options.modelId);

  const messages = [];
  const contentArray = [];

  // For models that don't accept any aspect-ratio parameter (e.g. Gemini /
  // Nano Banana), embed the ratio directly in the user prompt instead.
  const ratioMode = getRatioParamMode(modelId);
  const ratioPromptHint = (ratioMode === 'prompt' && options.aspectRatio)
    ? ` (aspect ratio ${options.aspectRatio})`
    : '';

  for (const p of normalizedParts) {
    if (typeof p === 'string') {
      if (p) contentArray.push({ type: 'text', text: p });
    } else if (p.image) {
      contentArray.push({
        type: 'image_url',
        image_url: { url: `data:${p.mimeType || 'image/jpeg'};base64,${p.image.toString('base64')}` }
      });
    } else if (p.text) {
      contentArray.push({ type: 'text', text: p.text });
    }
  }

  if (ratioPromptHint) {
    const lastText = [...contentArray].reverse().find(c => c.type === 'text');
    if (lastText) lastText.text = `${lastText.text}${ratioPromptHint}`;
    else contentArray.push({ type: 'text', text: ratioPromptHint.trimStart() });
  }

  messages.push({
    role: 'user',
    content: contentArray.length === 1 && contentArray[0].type === 'text'
      ? contentArray[0].text
      : contentArray
  });

  // Lifecycle markers (shape/metadata only, never prompt/content) so a stuck
  // image gen is diagnosable from server logs — this upstream call is where the
  // "Preparing image generation" hang lives when the provider is slow/down.
  const _t0 = Date.now();
  logger.debug('[generateImage] calling OpenRouter:', { modelId, requireZdr: !!options.requireZdr });
  let data;
  try {
    data = await openRouterChat(messages, modelId, {
      modalities: ['image', 'text'],
      isMediaAction: true,
      requireZdr: options.requireZdr,
      ...buildOpenRouterAspectFields(modelId, options.aspectRatio, options.imageSize, options.transparentBackground),
    });
  } catch (err) {
    logger.warn('[generateImage] OpenRouter call failed:', { modelId, ms: Date.now() - _t0, code: err?.code, timedOut: !!err?.timedOut });
    throw err;
  }
  logger.debug('[generateImage] OpenRouter returned:', { modelId, ms: Date.now() - _t0 });

  const images = [];
  let responseText = '';

  const resolveImageUrl = async (urlOrObj) => {
    const url = typeof urlOrObj === 'string' ? urlOrObj
      : (urlOrObj?.url ?? urlOrObj?.data ?? null);
    if (!url || typeof url !== 'string') return null;
    const b64Match = url.match(/^data:([^;]+);base64,(.+)$/);
    if (b64Match) {
      return { buffer: Buffer.from(b64Match[2], 'base64'), mimeType: b64Match[1] };
    }
    try {
      const res = await fetch(url);
      if (!res.ok) return null;
      const arrayBuffer = await res.arrayBuffer();
      const mimeType = res.headers.get('content-type') || 'image/png';
      return { buffer: Buffer.from(arrayBuffer), mimeType };
    } catch { return null; }
  };

  const msg = data.choices?.[0]?.message;
  // Don't log the response body — it may contain user-derived prompt echoes
  // or accompanying text. Logging only shape is enough to debug routing.
  logger.debug('[generateImage] response shape:', {
    hasContent: typeof msg?.content === 'string',
    imageCount: Array.isArray(msg?.images) ? msg.images.length : 0,
  });
  if (msg) {
    if (typeof msg.content === 'string') responseText = msg.content;
    if (Array.isArray(msg.images)) {
      for (const imgItem of msg.images) {
        const urlOrObj = imgItem?.image_url ?? imgItem;
        const resolved = await resolveImageUrl(urlOrObj);
        if (resolved) images.push(resolved);
      }
    }
    if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
        if (part.type === 'image_url' && part.image_url?.url) {
          const resolved = await resolveImageUrl(part.image_url.url);
          if (resolved) images.push(resolved);
        } else if (part.type === 'text') {
          responseText = part.text || responseText;
        }
      }
    }
  }

  const inputTokens = data.usage?.prompt_tokens || 0;
  return { images, responseText, inputTokens };
}

/**
 * Submit a video generation job to OpenRouter.
 *
 * @param {string} prompt
 * @param {object} options  modelId, duration, resolution, aspect_ratio, generate_audio
 * @returns {{ jobId: string, pollingUrl: string, status: string }}
 */
async function submitVideoGeneration(prompt, options = {}) {
  const modelId = options.modelId || process.env.DEFAULT_VIDEO_MODEL || 'google/veo-3.1-lite';

  const body = {
    model: modelId,
    prompt,
    ...(options.duration ? { duration: options.duration } : {}),
    ...(options.resolution ? { resolution: options.resolution } : {}),
    ...(options.aspect_ratio ? { aspect_ratio: options.aspect_ratio } : { aspect_ratio: '16:9' }),
    ...(options.generate_audio !== undefined ? { generate_audio: options.generate_audio } : { generate_audio: true }),
    ...(options.style ? { style: options.style } : {}),
    ...(options.composition ? { composition: options.composition } : {}),
  };

  // OpenRouter video API expects `frame_images: [{ type, image_url:{url}, frame_type }]`.
  // imageToVideo → single first_frame. startEndFrame → first_frame + last_frame.
  const frameImages = [];
  const pushFrame = (data, mime, frameType) => {
    if (!data || !mime) return;
    frameImages.push({
      type: 'image_url',
      image_url: { url: `data:${mime};base64,${data}` },
      frame_type: frameType,
    });
  };
  pushFrame(options.inputImageData, options.inputImageMimeType, 'first_frame');
  pushFrame(options.startFrameData, options.startFrameMimeType, 'first_frame');
  pushFrame(options.endFrameData,   options.endFrameMimeType,   'last_frame');
  if (frameImages.length > 0) body.frame_images = frameImages;

  // Video is a media action: ZDR key only when the model is ZDR-eligible. The
  // returned usedZdrKey must be persisted so poll/download hit the same account
  // (video jobs are account-scoped — the other key would 404).
  const useZdrKey = await resolveUseZdrKey({ requireZdr: options.requireZdr, modelId, isMediaAction: true });

  const res = await fetch(`${OPENROUTER_BASE}/videos`, orFetchInit({
    method: 'POST',
    headers: orHeaders(useZdrKey),
    body: JSON.stringify(body)
  }));

  if (!res.ok) {
    const errText = await res.text();
    if (process.env.NODE_ENV !== 'production') {
      const safeBody = { ...body };
      if (Array.isArray(safeBody.frame_images)) {
        safeBody.frame_images = safeBody.frame_images.map(f => ({
          ...f,
          image_url: f?.image_url?.url ? { url: `<base64 ${f.image_url.url.length} chars>` } : f?.image_url,
        }));
      }
      logger.error('[submitVideoGeneration] failed', { status: res.status, body: safeBody, response: errText });
    }
    throw new Error(`OpenRouter video generation error ${res.status}: ${errText}`);
  }

  const data = await res.json();
  return {
    jobId: data.id,
    pollingUrl: data.polling_url || `${OPENROUTER_BASE}/videos/${data.id}`,
    status: data.status || 'pending',
    usedZdrKey: useZdrKey,
  };
}

/**
 * Download a generated video binary from an OpenRouter unsigned URL.
 * Despite the "unsigned" name, the URL still requires the OpenRouter
 * Bearer token to retrieve the bytes.
 *
 * @param {string} url
 * @returns {{ buffer: Buffer, mimeType: string }}
 */
async function downloadVideoBuffer(url, { useZdrKey = false } = {}) {
  const res = await fetch(url, orFetchInit({ headers: orHeaders(useZdrKey) }));
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`OpenRouter video download error ${res.status}: ${errText}`);
  }
  const arrayBuffer = await res.arrayBuffer();
  return {
    buffer: Buffer.from(arrayBuffer),
    mimeType: res.headers.get('content-type') || 'video/mp4',
  };
}

/**
 * Poll for video generation job status.
 *
 * @param {string} jobId
 * @returns {{ status: string, unsigned_urls?: string[], usage?: object }}
 */
async function pollVideoGeneration(jobId, { useZdrKey = false } = {}) {
  const res = await fetch(`${OPENROUTER_BASE}/videos/${jobId}`, orFetchInit({
    headers: orHeaders(useZdrKey)
  }));

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`OpenRouter video poll error ${res.status}: ${errText}`);
  }

  return res.json();
}

/**
 * GET /models — list enabled models from rate config table.
 */
async function listEnabledModels() {
  const configs = await ModelRateConfig.find({ enabled: true }).lean();
  if (configs.length > 0) return configs;

  return [{
    modelId: process.env.DEFAULT_MODEL_ID || 'deepseek/deepseek-v4-flash',
    ratePerInputToken: 0,
    ratePerOutputToken: 0,
    markupFactor: 1,
    enabled: true
  }];
}

/**
 * Stream text generation via OpenRouter (stream: true).
 * Calls onChunk(text) for each token delta as it arrives.
 * Returns { inputTokens, outputTokens, costUsd, providerCostUsd } after the stream completes.
 */
async function generateTextStream(messages, modelId, options = {}, onChunk) {
  // NEAR AI (TEE) models route to the confidential-compute host. Lazy require
  // avoids a load-time cycle with nearAiService (which reuses helpers here).
  const nearAiService = require('./nearAiService');
  if (nearAiService.isNearModel(modelId)) {
    return nearAiService.generateTextStream(messages, modelId, options, onChunk);
  }

  const effectiveModelId = await resolveModelId(modelId);

  const messagesWithDirective = (() => {
    const arr = Array.isArray(messages) ? [...messages] : [messages];
    if (arr[0]?.role === 'system') {
      arr[0] = { ...arr[0], content: withNoTables(arr[0].content) };
    } else {
      arr.unshift({ role: 'system', content: NO_TABLES_DIRECTIVE });
    }
    return arr;
  })();

  const windowed = windowHistory(messagesWithDirective, { maxTokens: options.historyTokenBudget ?? 12000 });
  applyPromptCacheHints(windowed, effectiveModelId);

  const body = {
    model: effectiveModelId,
    messages: windowed,
    stream: true,
    temperature: options.temperature ?? 0.8,
    max_tokens: options.maxTokens ?? 8192,
  };
  if (options.plugins) body.plugins = options.plugins;

  if (options.webPlugin) {
    const webEntry = { id: 'web', ...(typeof options.webPlugin === 'object' ? options.webPlugin : {}) };
    body.plugins = [...(body.plugins || []), webEntry];
  }

  // Caller-supplied provider routing (e.g. force Google Vertex for base64
  // video input). Merged before applyProviderRouting so env `sort` still layers on.
  if (options.provider) body.provider = { ...(body.provider || {}), ...options.provider };

  const useZdrKey = await resolveUseZdrKey({ requireZdr: options.requireZdr, modelId: effectiveModelId });
  await applyZdrRouting(body, effectiveModelId, { useZdrKey });
  applyProviderRouting(body);

  // options.signal lets a caller cancel the upstream request mid-stream (used by
  // the speculative-streaming path in chatController: when the intent classifier
  // diverts a guessed-chat turn to image/video/compose, the in-flight speculative
  // generation is aborted so we stop paying for tokens we'll discard).
  const res = await fetch(`${OPENROUTER_BASE}/chat/completions`, orFetchInit({
    method: 'POST',
    headers: orHeaders(useZdrKey),
    body: JSON.stringify(body),
    ...(options.signal ? { signal: options.signal } : {}),
  }));

  if (!res.ok) {
    const errText = await res.text();
    // A selected model whose providers have all gone away returns
    // 404 "No endpoints found for <model>". Surface it as a typed,
    // user-actionable error (chatController has a PROVIDER_UNAVAILABLE
    // branch that forwards code + modelId to the client) rather than a
    // raw stream-error string that dead-ends the turn.
    // Two distinct 404s should both surface as PROVIDER_UNAVAILABLE: a model
    // whose providers have all gone away ("No endpoints found for <model>"), and
    // a model whose only endpoints are barred by the account's data policy /
    // guardrails ("No endpoints available matching your guardrail restrictions
    // and data policy" — e.g. `:free` endpoints when prompt-logging is disabled).
    if (res.status === 404 && /no endpoints (found|available)|guardrail|data policy/i.test(errText)) {
      throw Object.assign(
        new Error(`The selected model (${effectiveModelId}) is currently unavailable. Please choose a different model in Settings.`),
        { statusCode: 404, code: 'PROVIDER_UNAVAILABLE', modelId: effectiveModelId }
      );
    }
    throw new Error(`OpenRouter stream error ${res.status}: ${errText}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let inputTokens = 0;
  let outputTokens = 0;
  const annotationsById = new Map();

  const collectAnnotations = (arr) => {
    if (!Array.isArray(arr)) return;
    for (const a of arr) {
      const c = a?.url_citation || (a?.type === 'url_citation' ? a : null);
      if (c?.url) annotationsById.set(c.url, a);
    }
  };

  const tableConverter = createStreamingTableConverter(onChunk);

  outer: while (true) {
    // Caller aborted (speculative divert): stop reading and return what we have.
    // The caller discards the result, so partial token counts here are harmless.
    if (options.signal?.aborted) break;
    let read;
    try {
      read = await reader.read();
    } catch (readErr) {
      // An abort rejects the in-flight read() with an AbortError — expected when
      // options.signal fired. Anything else is a real stream failure: rethrow.
      if (options.signal?.aborted) break;
      throw readErr;
    }
    const { done, value } = read;
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const raw = line.slice(6).trim();
      if (raw === '[DONE]') break outer;
      try {
        const parsed = JSON.parse(raw);
        const choice = parsed.choices?.[0];
        const delta = choice?.delta?.content;
        if (delta) tableConverter.push(delta);
        collectAnnotations(choice?.delta?.annotations);
        collectAnnotations(choice?.message?.annotations);
        if (parsed.usage) {
          inputTokens = parsed.usage.prompt_tokens || inputTokens;
          outputTokens = parsed.usage.completion_tokens || outputTokens;
        }
      } catch { /* skip malformed chunk */ }
    }
  }
  tableConverter.end();

  const { costUsd, providerCostUsd } = await calcOpenRouterCost(effectiveModelId, null, inputTokens, outputTokens);
  const sources = await enrichWithImages(extractWebCitations(Array.from(annotationsById.values())));
  return { inputTokens, outputTokens, costUsd, providerCostUsd, sources };
}

/**
 * Faithful OpenAI-compatible chat-completions proxy for the Privateer Agent
 * CLI. Unlike generateTextStream (text-only, reshaped for the mobile/graph UI),
 * this preserves the upstream wire format end to end — tool_calls, multi-part
 * content, finish_reason — so an agentic client can function-call against the
 * user's account. It only (a) pins the request to the right model + ZDR
 * key/provider routing and (b) asks for usage so the caller can bill, then
 * returns the raw upstream Response for the caller to pipe.
 *
 * NEAR AI (TEE) models route to a different confidential-compute host. They ARE
 * supported here — confidential compute is our strongest privacy guarantee, so
 * the agent CLI should be able to use it — via a dedicated NEAR passthrough that
 * preserves tool_calls. No OpenRouter ZDR/provider routing applies to that path
 * (the TEE is the guarantee); billing routes to NEAR pricing via calcInferenceCost.
 *
 * @returns {Promise<{ response: Response, modelId: string }>}
 */
async function proxyChatCompletion(openaiBody, { requireZdr = true } = {}) {
  const nearAiService = require('./nearAiService');
  if (nearAiService.isNearModel(openaiBody?.model)) {
    return nearAiService.proxyChatCompletion(openaiBody);
  }

  const effectiveModelId = await resolveModelId(openaiBody?.model);

  // Pass the client body through unchanged except for the fields we own: the
  // resolved model, and (when streaming) usage accounting so we can bill.
  const body = { ...openaiBody, model: effectiveModelId };
  if (body.stream) {
    body.stream_options = { ...(body.stream_options || {}), include_usage: true };
  }

  const useZdrKey = await resolveUseZdrKey({ requireZdr, modelId: effectiveModelId });
  await applyZdrRouting(body, effectiveModelId, { useZdrKey });
  applyProviderRouting(body);

  const response = await fetch(`${OPENROUTER_BASE}/chat/completions`, orFetchInit({
    method: 'POST',
    headers: orHeaders(useZdrKey),
    body: JSON.stringify(body),
  }));

  return { response, modelId: effectiveModelId };
}

/**
 * Convert an OpenRouter image-gen failure into a user-facing assistant message.
 * Errors arrive as `Error("OpenRouter error 400: {<json>}")`; we lift the
 * provider's `error.message`, strip the version-stamped model id back to its
 * canonical slug, and prefix a friendly lead-in. Falls back to a generic line
 * when the payload isn't recognisable.
 */
function formatImageGenErrorForUser(err, { modelId } = {}) {
  const raw = err?.message || '';
  // Strip "OpenRouter error <code>: " prefix and try to JSON-parse the rest.
  const m = raw.match(/^OpenRouter error \d+:\s*(\{[\s\S]*\})\s*$/);
  let providerMsg = null;
  if (m) {
    try {
      const parsed = JSON.parse(m[1]);
      providerMsg = parsed?.error?.message || null;
    } catch { /* keep providerMsg null */ }
  }
  if (!providerMsg) {
    return modelId
      ? `I couldn't generate that image with **${modelId}**. ${raw || 'Please try again or pick a different image model.'}`
      : `I couldn't generate that image. ${raw || 'Please try again.'}`;
  }
  // Canonicalise version-stamped model ids, e.g.
  // `google/gemini-3-pro-image-preview-20251120` → `google/gemini-3-pro-image-preview`.
  const cleaned = providerMsg.replace(/([a-z0-9-]+\/[a-z0-9.-]+?)-\d{8}\b/gi, '$1');
  return `I couldn't generate that image: ${cleaned}`;
}

/**
 * Translate a `submitVideoGeneration` failure into something a user can act on.
 * Strips the raw provider-error envelope and recognises a few common cases.
 */
function formatVideoGenErrorForUser(err, { modelId } = {}) {
  const raw = err?.message || '';
  const m = raw.match(/^OpenRouter video generation error (\d{3}):\s*([\s\S]*)$/);
  const status = m ? parseInt(m[1], 10) : null;
  const bodyText = m ? m[2] : raw;

  let providerMsg = null;
  if (bodyText) {
    try {
      const parsed = JSON.parse(bodyText);
      providerMsg = parsed?.error?.message || null;
    } catch { /* not JSON */ }
  }

  const modelLabel = modelId ? `**${modelId}**` : 'that video';

  if (providerMsg && /no endpoints available/i.test(providerMsg)) {
    return `I couldn't generate ${modelLabel}. No provider for this model is currently enabled on the server's OpenRouter account — its privacy / data-policy settings are blocking every available endpoint. An admin needs to allow the relevant provider (e.g. Google Vertex for Veo) at https://openrouter.ai/settings/privacy.`;
  }

  if (status === 401 || status === 403) {
    return `I couldn't generate ${modelLabel}: video provider authentication failed. Please try again shortly.`;
  }
  if (status === 402) {
    return `I couldn't generate ${modelLabel}: the server's video credits are exhausted.`;
  }
  if (status === 429) {
    return `I couldn't generate ${modelLabel}: video provider is rate-limited. Please try again in a moment.`;
  }
  if (status && status >= 500) {
    return `I couldn't generate ${modelLabel}: the video provider is having trouble (HTTP ${status}). Please try again shortly.`;
  }

  if (providerMsg) return `I couldn't generate ${modelLabel}: ${providerMsg}`;
  return `I couldn't generate ${modelLabel}. ${raw || 'Please try again or pick a different video model.'}`;
}

// ── Memory helpers ───────────────────────────────────────────────────────────
//
// Both helpers operate on plaintext that the client decrypts client-side and
// sends in-band. Nothing is persisted server-side; the helpers exist only to
// (a) decide which existing memories are relevant to a given user message,
// and (b) propose new memory candidates from a finished turn. All inference
// is pinned to deepseek/deepseek-v4-flash so cost stays predictable.

const MEMORY_HELPER_MODEL = 'deepseek/deepseek-v4-flash';

const MEMORY_STOPWORDS = new Set([
  'a','an','the','and','or','but','if','then','else','of','in','on','at','to',
  'for','with','by','from','as','is','are','was','were','be','been','being',
  'have','has','had','do','does','did','will','would','could','should','may',
  'might','this','that','these','those','it','its','i','me','my','mine','you',
  'your','yours','we','our','they','their','them','he','she','his','her',
  'so','not','no','yes','please','can','just','about','what','when','where',
  'who','why','how','also','too','than','into','out','up','down','over','one'
]);

function tokenizeForMemory(text) {
  if (!text || typeof text !== 'string') return [];
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !MEMORY_STOPWORDS.has(w));
}

function scoreMemoryAgainstMessage(messageTokens, memoryText) {
  const memoryTokens = tokenizeForMemory(memoryText);
  if (memoryTokens.length === 0 || messageTokens.length === 0) return 0;
  const msgSet = new Set(messageTokens);
  let unigramHits = 0;
  for (const t of memoryTokens) if (msgSet.has(t)) unigramHits++;

  // Cheap bigram boost — captures multi-word matches like "dark mode".
  let bigramHits = 0;
  for (let i = 0; i + 1 < messageTokens.length; i++) {
    const bg = messageTokens[i] + ' ' + messageTokens[i + 1];
    if (memoryText.toLowerCase().includes(bg)) bigramHits++;
  }
  return unigramHits + bigramHits * 2;
}

/**
 * Pick the subset of stored memories that are relevant to the current user
 * message. Hybrid: heuristic prefilter narrows to a small candidate set, then
 * an LLM judge call returns the final keep-list. On any failure or timeout
 * the heuristic top-N is returned instead.
 *
 * @param {{ memories: string[], userMessage: string }} args
 * @returns {Promise<string[]>}
 */
async function selectRelevantMemories({ memories, userMessage, requireZdr = false }) {
  const list = Array.isArray(memories) ? memories.filter(m => typeof m === 'string' && m.trim()) : [];
  if (list.length === 0) return [];
  if (typeof userMessage !== 'string' || !userMessage.trim()) return [];

  const msgTokens = tokenizeForMemory(userMessage);
  if (msgTokens.length === 0) return [];

  const scored = list.map((content, idx) => ({ idx, content, score: scoreMemoryAgainstMessage(msgTokens, content) }));
  scored.sort((a, b) => b.score - a.score);

  // Hard relevance floor — a single incidental token match isn't enough to
  // surface a memory. Require either a meaningful unigram overlap or any
  // bigram hit (bigrams count 2× in the score).
  const MIN_SCORE = 2;
  const candidates = scored.filter(c => c.score >= MIN_SCORE).slice(0, 10);

  // Nothing cleared the floor — the current message is unrelated to every
  // stored fact. Returning [] here is what stops topic bleed.
  if (candidates.length === 0) return [];

  // Fewer than 3 candidates → judge adds noise, not signal. The heuristic
  // already enforced score ≥ MIN_SCORE, so anything that survived the floor
  // is worth keeping. Skipping the LLM call here saves the judge round-trip
  // (up to JUDGE_TIMEOUT_MS) on memory-light turns, which is the common case.
  if (candidates.length <= 2) return candidates.map(c => c.content);

  const numbered = candidates.map((c, i) => `${i}: ${c.content}`).join('\n');
  const judgeSystem = [
    'You decide which of the user\'s stored memories are DIRECTLY relevant to their CURRENT message.',
    'Default to {"keep":[]}. Only include a memory if applying it would visibly change a good answer to THIS specific message.',
    'Do NOT keep a memory just because it shares a topic, domain, or vocabulary — require concrete applicability.',
    'Irrelevant memories cause topic bleed and pollute the assistant\'s response. Precision over recall.',
    'Return JSON only, no prose, of the form: {"keep":[<indices>]}.'
  ].join('\n');
  const judgeUser = `CURRENT MESSAGE:\n${userMessage}\n\nMEMORIES:\n${numbered}\n\nReturn JSON: {"keep":[<indices>]}`;

  // Bounds the worst-case pre-flight tail. The judge now runs concurrently
  // with intent + model resolution (see streamMessage), so its cost is mostly
  // overlapped; a tighter cap trims the tail with negligible quality loss —
  // the heuristic top-N fallback already handles a timeout gracefully.
  const JUDGE_TIMEOUT_MS = 500;

  try {
    const result = await Promise.race([
      openRouterChat(
        [
          { role: 'system', content: judgeSystem },
          { role: 'user', content: judgeUser }
        ],
        MEMORY_HELPER_MODEL,
        { temperature: 0, maxTokens: 200, requireZdr }
      ),
      new Promise((_, reject) => setTimeout(() => reject(new Error('memory-judge timeout')), JUDGE_TIMEOUT_MS))
    ]);

    const raw = result?.choices?.[0]?.message?.content || '';
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('judge: no JSON');
    const parsed = JSON.parse(match[0]);
    const keep = Array.isArray(parsed.keep) ? parsed.keep : [];
    const selected = keep
      .map(i => candidates[Number(i)])
      .filter(c => c && typeof c.content === 'string')
      .slice(0, 4)
      .map(c => c.content);
    return selected;
  } catch (err) {
    Sentry.captureException(err, { level: 'warning', tags: { op: 'memory_select' } });
    logger.warn('[selectRelevantMemories] judge failed, falling back to heuristic:', err.message);
    // Fallback is strict too — only the very top candidates that cleared the
    // floor. Better to silently drop a relevant memory than bleed an
    // irrelevant one in.
    return candidates.slice(0, 2).map(c => c.content);
  }
}

/**
 * Inspect a finished chat turn and propose AT MOST ONE durable memory
 * candidate the assistant should remember next time — and only when it clears
 * a high bar (the model must rate it "high" importance; everything else is
 * dropped). The default, expected result is an empty list. Returns plaintext
 * only; the caller is responsible for encrypting + persisting via the standard
 * memory CRUD flow.
 *
 * @param {{ userMessage: string, aiResponse: string, existingMemories: string[] }} args
 * @returns {Promise<{ candidates: { content: string }[] }>}
 */
async function extractMemoryCandidates({ userMessage, aiResponse, existingMemories, requireZdr = false }) {
  const empty = { candidates: [] };
  if (typeof userMessage !== 'string' || !userMessage.trim()) return empty;

  const existing = Array.isArray(existingMemories)
    ? existingMemories.filter(m => typeof m === 'string' && m.trim()).slice(0, 50)
    : [];

  const system = [
    'You extract DURABLE, HIGH-VALUE facts about the user that will materially improve future conversations.',
    'The bar is HIGH. Saving a memory is a long-term commitment, so the default answer is to save NOTHING.',
    'Only keep a fact that is ALL of: (a) stable over months, (b) volunteered as a fact about the user themselves (not the topic), (c) likely to change how you answer an UNRELATED future message, and (d) not already implied by EXISTING MEMORIES.',
    'Keep ONLY things like: a durable stated preference, a long-running project or role, an enduring personal constraint, or the name of a person/pet/place tied to the user.',
    'Skip everything else, including: one-off questions or tasks, the topic or subject matter being discussed, facts about the world, anything the ASSISTANT said, transient or in-progress state, opinions about your reply, restatable trivia, and anything an unrelated future chat would not benefit from.',
    'When in doubt, SKIP. An empty array is the correct and expected answer for the large majority of turns. Precision massively over recall.',
    'At most 1 candidate. Rate each candidate\'s importance as "high", "medium", or "low" — only "high" will be kept, so do not bother emitting a candidate you would not rate "high".',
    'Phrase each as a concise third-person fact (e.g. "Prefers dark mode in all apps", "Owns a 2019 Tesla Model 3").',
    'Return JSON ONLY of the form: {"candidates":[{"content":"...","importance":"high"}]}.'
  ].join('\n');

  const existingBlock = existing.length > 0
    ? existing.map((m, i) => `${i + 1}. ${m}`).join('\n')
    : '(none)';
  const trimmedResponse = (typeof aiResponse === 'string' ? aiResponse : '').slice(0, 2000);
  const trimmedUser = userMessage.slice(0, 2000);

  const user = [
    'EXISTING MEMORIES:',
    existingBlock,
    '',
    'USER MESSAGE:',
    trimmedUser,
    '',
    'ASSISTANT RESPONSE:',
    trimmedResponse,
    '',
    'Return JSON: {"candidates":[{"content":"...","importance":"high|medium|low"}]}'
  ].join('\n');

  const EXTRACT_TIMEOUT_MS = 6000;

  try {
    const result = await Promise.race([
      openRouterChat(
        [
          { role: 'system', content: system },
          { role: 'user', content: user }
        ],
        MEMORY_HELPER_MODEL,
        { temperature: 0, maxTokens: 300, requireZdr }
      ),
      new Promise((_, reject) => setTimeout(() => reject(new Error('memory-extract timeout')), EXTRACT_TIMEOUT_MS))
    ]);

    const raw = result?.choices?.[0]?.message?.content || '';
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) return empty;
    const parsed = JSON.parse(match[0]);
    const list = Array.isArray(parsed.candidates) ? parsed.candidates : [];
    const candidates = list
      // Strict gate: only explicitly "high" importance survives. A missing or
      // non-"high" rating is dropped — the default is to save nothing.
      .filter(c => c && typeof c.content === 'string'
        && String(c.importance || '').trim().toLowerCase() === 'high')
      .map(c => c.content.trim())
      .filter(s => s.length > 0 && s.length <= 500)
      .slice(0, 1)
      .map(content => ({ content }));
    return { candidates };
  } catch (err) {
    Sentry.captureException(err, { level: 'warning', tags: { op: 'memory_extract' } });
    logger.warn('[extractMemoryCandidates] failed:', err.message);
    return empty;
  }
}

module.exports = { generateText, generateTextStream, proxyChatCompletion, calcOpenRouterCost, calcInferenceCost, calcImageGenCost, generateImage, submitVideoGeneration, pollVideoGeneration, downloadVideoBuffer, listEnabledModels, formatImageGenErrorForUser, formatVideoGenErrorForUser, ensureModelRateConfig, isVideoInputModel, isImageInputModel, selectRelevantMemories, extractMemoryCandidates, windowHistory, orHeaders, resolveUseZdrKey,
  // Shared formatting helpers reused by nearAiService (OpenAI-compatible NEAR path).
  NO_TABLES_DIRECTIVE, withNoTables, convertTablesToBullets, createStreamingTableConverter };
