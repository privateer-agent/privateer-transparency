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
const { getRatioParamMode, supportsTransparency, getMaxImageSize, getSupportedAspectRatios } = require('../data/imageModelCapabilities');
const { isZdrModel } = require('../data/zdrProviders');
const { safeFetch } = require('../utils/safeFetch');
const { createPersonaGuard } = require('./personaGuard');
const Sentry = require('@sentry/node');
const logger = require('../utils/logger');
const providerHealth = require('./providerHealthService');

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

// Continuation nudge for a length-truncated reply (generateTextStream auto-
// continue). The partial output is re-sent as the assistant turn; this asks the
// model to resume verbatim so the concatenated stream is one seamless document.
const CONTINUE_DIRECTIVE = [
  'Your previous message was cut off because it hit the length limit.',
  'Continue it from EXACTLY where it stopped — pick up at the next character.',
  'Do NOT repeat anything you already wrote, do NOT restart, and do NOT add any',
  'preamble, apology, or explanation. Output only the raw continuation so the two',
  'parts join seamlessly (if you were mid-code-block, keep emitting its contents).',
].join(' ');

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

// Separate dispatcher for STREAMING generation. undici's default headers/body
// timeouts (~300s) are inactivity windows: `headersTimeout` bounds time-to-first
// response header, `bodyTimeout` bounds the gap between body reads. A slow model
// or a long reasoning pause before the first token is a legitimately long gap —
// under the defaults it throws mid-stream and dead-ends a long build. These are
// intentionally generous (a real hang is bounded elsewhere: the job's cancel
// flag + heartbeat watchdog), so total generation length is unbounded as long as
// tokens keep flowing. Short JSON calls keep the tighter default dispatcher.
const openrouterStreamDispatcher = new UndiciAgent({
  keepAliveTimeout: 30_000,
  keepAliveMaxTimeout: 60_000,
  connections: 50,
  headersTimeout: Number(process.env.OR_STREAM_HEADERS_TIMEOUT_MS) || 120_000,
  bodyTimeout: Number(process.env.OR_STREAM_BODY_TIMEOUT_MS) || 600_000,
});
const orStreamFetchInit = (init = {}) => ({ ...init, dispatcher: openrouterStreamDispatcher });

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
    // Brave hands us a thumbnail on most web results (braveSearchService maps it
    // straight onto `image`), so this now only fills the gaps — a source that
    // already has a hero needs no page fetch at all.
    .filter((s) => !s.image && typeof s.url === 'string' && /^https?:\/\//i.test(s.url));
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

// Models where an explicit breakpoint is REQUIRED for prompt caching to happen
// at all. OpenAI/DeepSeek/xAI auto-cache and Gemini caches implicitly, so
// tagging them buys nothing and only rewrites a caller's wire format.
const EXPLICIT_CACHE_BREAKPOINT_MODEL = /^anthropic\//i;

function hasCacheControl(msg) {
  return Array.isArray(msg?.content)
    && msg.content.some((p) => p && typeof p === 'object' && p.cache_control);
}

/**
 * Return a COPY of `msg` carrying a cache breakpoint on its last content block,
 * or null when there is nothing to tag.
 *
 * Copies rather than mutates because on the proxy path `messages` is the
 * caller's request body, which we are otherwise passing through untouched.
 *
 * `promoteString` converts a plain string `content` into single-element block
 * form (the only way to attach a breakpoint to it). That is safe and routine for
 * system/user/tool turns, but callers pass `false` for assistant turns: an
 * assistant string is the one place the rewrite could change how a provider
 * reads the turn, and it is never the anchor we actually need — an agent
 * transcript ends on a tool result, not on an assistant message.
 */
function taggedCacheCopy(msg, { promoteString = true } = {}) {
  if (!msg) return null;
  const mark = { type: 'ephemeral' };

  if (typeof msg.content === 'string') {
    if (!promoteString || !msg.content) return null;
    return { ...msg, content: [{ type: 'text', text: msg.content, cache_control: mark }] };
  }

  if (Array.isArray(msg.content) && msg.content.length > 0) {
    const parts = msg.content.slice();
    const last = parts[parts.length - 1];
    if (!last || typeof last !== 'object') return null;
    parts[parts.length - 1] = { ...last, cache_control: mark };
    return { ...msg, content: parts };
  }

  // Assistant turns that are pure `tool_calls` carry `content: null` — nothing
  // to hang a breakpoint on. Not an error; the caller walks further back.
  return null;
}

/**
 * Prompt-cache breakpoints for the OpenAI-compatible PROXY surfaces (Agent CLI,
 * developer /v1, in-app connector turns).
 *
 * Separate from applyPromptCacheHints, which anchors its rolling breakpoint on
 * the last *assistant* turn. That is right for app chat and wrong here: an agent
 * transcript ends on a tool result and its assistant turns routinely carry
 * `content: null` with `tool_calls`, so the assistant anchor lands on a message
 * with nothing to tag and the growing transcript goes entirely uncached.
 *
 * That is not hypothetical — it is what this function was written for. On
 * 2026-08-11 a single routine ran 39 CLI turns on claude-opus-5 in under eight
 * minutes; prompt tokens climbed 3,858 → 123,852 because every turn re-billed
 * the whole transcript at full input price. 2,697,087 prompt tokens against
 * 23,653 completion — 99.1% of the spend was re-sent context, and it tied out
 * to list price to the cent, i.e. not one cache read.
 *
 * Two of the four allowed breakpoints:
 *   1. the system prompt. Anthropic renders tools → system → messages, so one
 *      breakpoint here covers the tool definitions too;
 *   2. the newest taggable message, whatever its role — the standard
 *      incremental pattern. Each turn reads the prefix it matches and writes
 *      only the delta, so cost tracks new tokens instead of total context.
 *
 * Verified live against OpenRouter before shipping: turn 1 wrote 8,142 tokens,
 * turns 2 and 3 read 8,142 from cache.
 *
 * Deliberately does NOT touch provider routing. Anthropic caches are per
 * provider, so in principle `OPENROUTER_PROVIDER_SORT=latency` could bounce a
 * conversation between Anthropic/Bedrock/Vertex and lose the cache — but pinning
 * `provider.order` measured *worse*, not better (see PROMPT_CACHE_NOTES in the
 * test), and latency routing held one provider across a run. Leave it alone.
 */
function withProxyPromptCacheHints(messages, modelId) {
  if (String(process.env.PROXY_PROMPT_CACHE || '').toLowerCase() === 'false') return messages;
  if (!Array.isArray(messages) || messages.length === 0) return messages;
  if (!EXPLICIT_CACHE_BREAKPOINT_MODEL.test(String(modelId || ''))) return messages;

  // The caller already placed breakpoints. Respect their placement rather than
  // adding a second pair — the ceiling is 4 and they may be using the others.
  if (messages.some(hasCacheControl)) return messages;

  const out = messages.slice();
  const firstIdx = out[0]?.role === 'system' ? 1 : 0;

  if (firstIdx === 1) {
    const tagged = taggedCacheCopy(out[0]);
    if (tagged) out[0] = tagged;
  }

  for (let i = out.length - 1; i >= firstIdx; i--) {
    const tagged = taggedCacheCopy(out[i], { promoteString: out[i]?.role !== 'assistant' });
    if (tagged) { out[i] = tagged; break; }
  }

  return out;
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

  // Model "thinking" control (see generateTextStream for why Build turns want
  // it off). A model with no reasoning to configure ignores it; an endpoint
  // that reasons MANDATORILY rejects it outright — handled below.
  if (options.reasoning) body.reasoning = options.reasoning;

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

    if (res.ok) {
      providerHealth.recordSuccess(useZdrKey ? 'openrouter_zdr' : 'openrouter');
      return res.json();
    }

    const errText = await res.text();

    // An always-thinking endpoint 400s the request that asks it not to think
    // ("Reasoning is mandatory for this endpoint and cannot be disabled")
    // rather than ignoring the field. Drop the hint and retry with no backoff
    // (nothing upstream is wrong, so there is nothing to wait out). It spends
    // one of the MAX_RETRIES attempts, and can't loop — the field is gone.
    if (res.status === 400 && body.reasoning && /reasoning/i.test(errText) && attempt < MAX_RETRIES) {
      logger.debug(`[openrouter] ${modelId} requires reasoning — retrying without the hint`);
      delete body.reasoning;
      continue;
    }

    // Retry transient upstream failures: 429 (rate limit) and any 5xx incl. 503
    // (provider overloaded or briefly down — common for busy image backends).
    // 404 is permanent ("no endpoints found" / unknown model) and never retried.
    const isTransient = res.status === 429 || res.status >= 500;
    if (isTransient && attempt < MAX_RETRIES) {
      const delay = BASE_DELAY_MS * Math.pow(2, attempt);
      logger.warn(`[openrouter] ${res.status} for ${modelId}, retrying in ${delay}ms (attempt ${attempt + 1}/${MAX_RETRIES}): ${errText.slice(0, 200)}`);
      await new Promise(resolve => setTimeout(resolve, delay));
      continue;
    }

    providerHealth.recordFailure(useZdrKey ? 'openrouter_zdr' : 'openrouter', {
      status: res.status, message: errText, kind: options.modalities ? 'imageGen' : 'inference'
    });
    const err = new Error(`OpenRouter error ${res.status}: ${errText}`);
    if (res.status === 429) err.statusCode = 429;
    if (res.status === 404 || res.status === 503 || res.status >= 500) {
      err.code = 'PROVIDER_UNAVAILABLE';
      err.modelId = modelId;
      err.statusCode = err.statusCode || res.status;
      // Preserve a snippet of the upstream body so the failure is diagnosable
      // in logs (which model/provider said what) without dumping user content.
      err.upstreamBody = errText.slice(0, 500);
    }
    throw err;
  }
}

// ── Validate model ───────────────────────────────────────────────────────────

// Retired slugs → their replacement.
//
// A `-preview` alias stays listed in OpenRouter's /models after the GA id ships,
// but its endpoints get deranked to status -5 (dead). That is invisible to us on
// the happy path *except* for ZDR: applyZdrRouting pins `provider.zdr: true` for
// any ZDR-eligible model, which excludes the one still-healthy non-ZDR endpoint
// (Google AI Studio) and leaves only the dead Vertex one — so the request 404s
// with `Publisher model ... was not found or your project does not have access`.
// Rewriting here (rather than only at the call sites) also heals the id already
// persisted in UserStoragePrefs.preferredModelId / preferredVisionModelId /
// preferredImageGenModelId.
const RETIRED_MODEL_ALIASES = {
  'google/gemini-3.1-flash-image-preview': 'google/gemini-3.1-flash-image',
  // `tinfoil/kimi-k2-6 → tinfoil/gemma4-31b` lived here 2026-07-28 → 2026-08-03:
  // Tinfoil delisted the slug from /v1/models and this alias kept persisted
  // prefs from 404ing. Tinfoil RELISTED it (confirmed live in /v1/models,
  // 2026-08-03, ctx 256k), so the alias was removed — leaving it would silently
  // rewrite a live confidential-vision pick to Gemma. If Tinfoil delists it
  // again, restore the mapping (Gemma 4 31B is the substitution that keeps both
  // implied properties: enclave compute and image input).
};

/**
 * Resolves and validates the model ID. All inference flows through OpenRouter,
 * so the model must be in slash-prefixed form (e.g. "google/gemini-2.5-flash").
 */
async function resolveModelId(requestedModelId) {
  const defaultId = process.env.DEFAULT_MODEL_ID || 'deepseek/deepseek-v4-flash';
  const modelId = RETIRED_MODEL_ALIASES[requestedModelId] || requestedModelId || defaultId;

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
  // NEAR/Tinfoil vision models (Qwen-VL, Gemma…) aren't in OpenRouter's
  // catalog, so the lookup below would miss them and silently substitute an
  // OpenRouter vision model — breaking the confidential guarantee. Honor the
  // provider's own catalog instead.
  if (modelId.startsWith('near/')) {
    const { isNearImageInputModel } = require('../data/nearModels');
    return isNearImageInputModel(modelId);
  }
  if (modelId.startsWith('tinfoil/')) {
    const { isTinfoilImageInputModel } = require('../data/tinfoilModels');
    return isTinfoilImageInputModel(modelId);
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
  // NEAR AI (TEE) and Tinfoil (secure enclave) models are OpenAI-compatible but
  // routed to different hosts and keys, with no ZDR two-key logic. Lazy
  // requires avoid a load-time cycle.
  const nearAiService = require('./nearAiService');
  if (nearAiService.isNearModel(options.modelId)) {
    return nearAiService.generateText(parts, options);
  }
  const tinfoilService = require('./tinfoilService');
  if (tinfoilService.isTinfoilModel(options.modelId)) {
    return tinfoilService.generateText(parts, options);
  }

  const modelId = await resolveModelId(options.modelId);

  const normalizedParts = Array.isArray(parts) ? parts : [parts];

  let messages = [];
  // HTML-answer mode wants real <table> elements, so it opts out of the
  // NO_TABLES directive (the system prompt already carries the HTML directive).
  messages.push({
    role: 'system',
    content: options.richHtml ? (options.systemPrompt || '') : withNoTables(options.systemPrompt),
  });

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
  // Never forward an aspect_ratio the model doesn't advertise — the provider
  // rejects the entire request (400 invalid_value) rather than clamping, so a
  // stray/misparsed ratio would sink an otherwise-valid generation. Unknown
  // models (null list) can't be validated, so pass through as before.
  if (aspectRatio) {
    const allowed = getSupportedAspectRatios(modelId);
    if (!allowed || allowed.includes(aspectRatio)) {
      image_config.aspect_ratio = aspectRatio;
    } else {
      logger.warn(`[imageGen] dropping unsupported aspect_ratio "${aspectRatio}" for ${modelId}`);
    }
  }
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

  // "Upscale" toggle: when the user picked no explicit size, request the model's
  // largest supported image_size. Resolved here (per call, per model) so a retry
  // on the fallback model never inherits a size the fallback rejects. Unknown
  // models resolve to null → image_size stays unset; the prompt directive the
  // controller appends is the only upscale signal that reaches them.
  const imageSize = options.imageSize || (options.upscale ? getMaxImageSize(modelId) : null);

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
      ...buildOpenRouterAspectFields(modelId, options.aspectRatio, imageSize, options.transparentBackground),
    });
  } catch (err) {
    logger.warn('[generateImage] OpenRouter call failed:', {
      modelId,
      ms: Date.now() - _t0,
      code: err?.code,
      statusCode: err?.statusCode,
      timedOut: !!err?.timedOut,
      // The upstream reason — a 404 "no endpoints" (bad/unavailable model) reads
      // very differently from a 503 "provider overloaded"; log it to tell them apart.
      detail: err?.upstreamBody || err?.message?.slice(0, 300),
    });
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
 * Runtime duration/aspect-ratio lists for a video model, from the cached
 * `/videos/models` catalog (same source the model picker serves). Null lists
 * when the catalog is unavailable or omits the field — callers fall back to
 * the static table in data/videoModelCapabilities.
 */
async function getVideoModelRuntimeCaps(modelId) {
  try {
    const { fetchCatalog } = require('../data/openrouterCatalog');
    const data = await fetchCatalog(`${OPENROUTER_BASE}/videos/models`, orHeaders());
    const v = (data?.data || []).find(m => m.id === modelId);
    return {
      aspectRatios: Array.isArray(v?.supported_aspect_ratios) && v.supported_aspect_ratios.length
        ? v.supported_aspect_ratios : null,
      durations: Array.isArray(v?.supported_durations) && v.supported_durations.length
        ? v.supported_durations.map(Number) : null,
    };
  } catch {
    return { aspectRatios: null, durations: null };
  }
}

/**
 * Submit a video generation job to OpenRouter.
 *
 * @param {string} prompt
 * @param {object} options  modelId, duration, resolution, aspect_ratio, generate_audio,
 *   plus at most ONE kind of image conditioning: frames (inputImageData /
 *   startFrameData+endFrameData) or `referenceImages` [{data, mimeType}].
 *   Frames win if both arrive — see the comment at the build site.
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

  // `input_references` is the OTHER way to hand the model a picture: style and
  // content guidance rather than an exact frame, which is what "alter this with
  // an image" wants.
  //
  // The two are mutually exclusive AT THE PROVIDER, and silently so: "if both
  // fields are provided, frame_images takes precedence and the request is
  // treated as image-to-video". So a body carrying both renders a clip that
  // ignored every reference the user chose and bills the full price for it.
  // Frames win here too — they are the stronger, better-supported conditioning
  // and the caller that sent one meant it — but the references are DROPPED
  // deliberately and loudly rather than handed over to be discarded upstream.
  const references = Array.isArray(options.referenceImages) ? options.referenceImages : [];
  if (references.length > 0 && frameImages.length > 0) {
    logger.warn(
      '[submitVideoGeneration] dropping input_references: frame_images take ' +
      'precedence at the provider, so sending both renders from the frames alone',
      { modelId, references: references.length, frames: frameImages.length },
    );
  }

  if (frameImages.length > 0) {
    body.frame_images = frameImages;
  } else if (references.length > 0) {
    body.input_references = references
      .filter(r => r?.data && r?.mimeType)
      .map(r => ({ type: 'image_url', image_url: { url: `data:${r.mimeType};base64,${r.data}` } }));
    if (body.input_references.length === 0) delete body.input_references;
  }

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
      const redactUrls = arr => arr.map(f => ({
        ...f,
        image_url: f?.image_url?.url ? { url: `<base64 ${f.image_url.url.length} chars>` } : f?.image_url,
      }));
      if (Array.isArray(safeBody.frame_images)) {
        safeBody.frame_images = redactUrls(safeBody.frame_images);
      }
      if (Array.isArray(safeBody.input_references)) {
        safeBody.input_references = redactUrls(safeBody.input_references);
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

// ── Video job key affinity ───────────────────────────────────────────────────
// The two OpenRouter keys are separate ACCOUNTS, and a video job belongs to
// whichever one submitted it. Poll and download must reach that same account or
// the job reads as missing.
//
// The submit-time choice is not reliably reproducible later. getVideoStatus
// re-derives it from `resolveUseZdrKey({ requireZdr, modelId })` where:
//   • `modelId` is read off a client-written videoAttachment that may not exist
//     yet on the first poll — and `isZdrModel(null)` is false, so the derivation
//     silently collapses to the STANDARD key for a job submitted on the ZDR one;
//   • `requireZdr` comes from the account pref, which the user can flip mid-job,
//     and which the submit path may have overridden (explicit body flag, or a
//     ZDR-only project's floor).
// Any of those disagreeing turns a perfectly healthy job into a hard 404.
//
// Rather than requiring every future caller to reproduce the submit's decision,
// make the read paths independent of it: try the caller's best guess, and on an
// auth/not-found status retry on the other key. With exactly two keys the
// fallback is exhaustive — if neither account has the job, it really is gone,
// and we surface the original error unchanged. This cannot leak across users:
// both keys are our own accounts and the job id is account-scoped, so the retry
// only ever succeeds when that account genuinely owns the job. It also carries
// no content — poll and download are reads of an already-submitted job.
const VIDEO_KEY_RETRY_STATUSES = new Set([401, 403, 404]);

/**
 * Run an authenticated OpenRouter video request, transparently retrying on the
 * other API key when the first reports the job as missing/unauthorized.
 *
 * @param {(useZdrKey: boolean) => Promise<Response>} run
 * @param {boolean} useZdrKey  the caller's best guess at the submit-time key
 * @param {string} label       for the disagreement log line
 */
async function fetchVideoWithEitherKey(run, useZdrKey, label) {
  // orHeaders throws ZDR_KEY_UNAVAILABLE when the ZDR key isn't configured;
  // treat that as "this key can't answer" and let the other one try.
  const attempt = async (key) => {
    try {
      return await run(key);
    } catch (err) {
      if (err?.code === 'ZDR_KEY_UNAVAILABLE') return null;
      throw err;
    }
  };

  const res = await attempt(useZdrKey);
  // Only a missing/unauthorized job is ambiguous. 402/429/5xx are real
  // conditions on the right account — retrying them would just double the load.
  if (res && (res.ok || !VIDEO_KEY_RETRY_STATUSES.has(res.status))) return res;

  const altRes = await attempt(!useZdrKey);
  if (altRes?.ok) {
    logger.debug(
      `[video] ${label}: the ${useZdrKey ? 'ZDR' : 'standard'} key returned ` +
      `${res ? res.status : 'no-key'}; served by the ${useZdrKey ? 'standard' : 'ZDR'} key instead ` +
      `— submit/poll key derivation disagreed for this job`
    );
    return altRes;
  }
  // Neither account has it. Prefer the original response so the caller's error
  // message describes the key it actually expected the job to live on.
  if (res) return res;
  if (altRes) return altRes;
  throw Object.assign(
    new Error('Zero Data Retention is required for this request, but no ZDR OpenRouter key is configured.'),
    { statusCode: 503, code: 'ZDR_KEY_UNAVAILABLE' }
  );
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
  const res = await fetchVideoWithEitherKey(
    (key) => fetch(url, orFetchInit({ headers: orHeaders(key) })),
    useZdrKey,
    'download'
  );
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
  const res = await fetchVideoWithEitherKey(
    (key) => fetch(`${OPENROUTER_BASE}/videos/${jobId}`, orFetchInit({ headers: orHeaders(key) })),
    useZdrKey,
    `poll ${jobId}`
  );

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`OpenRouter video poll error ${res.status}: ${errText}`);
  }

  return res.json();
}

/**
 * GET /models — list enabled models from rate config table.
 */
// Honest privacy tier per model — surfaced as `privacy.tier` so the CLI/app model
// pickers can shield each row. Mirrors the inference routing (§4 auto-route by model
// ID) so the label can never overclaim relative to how the request is actually served:
//   • near/… , tinfoil/…  → confidential-compute enclaves. We assert only the CLAIM
//     here ('tee-unverified'); the client still runs remote attestation and upgrades
//     the shield to 'tee-verified' (green) itself — the server can't verify the
//     client's live TLS-key binding, so it must not assert a verified TEE.
//   • OpenRouter model with a ZDR endpoint → the account channel serves it on the
//     ZDR-enforced key (proxyChatCompletion defaults requireZdr=true), an observable
//     enforcement, so 'zdr-enforced'.
//   • everything else → 'standard' (no special guarantee).
// Tier strings match pi-privacy's PrivacyTier ladder (posture/tiers.ts).
async function privacyTierFor(modelId) {
  try {
    const nearAiService = require('./nearAiService');
    if (nearAiService.isNearModel(modelId)) return 'tee-unverified';
    const tinfoilService = require('./tinfoilService');
    if (tinfoilService.isTinfoilModel(modelId)) return 'tee-unverified';
    if (await isZdrModel(modelId)) return 'zdr-enforced';
  } catch (_) {
    // Fail safe: an unknown routing state must never inflate the claim.
  }
  return 'standard';
}

async function withPrivacy(configs) {
  return Promise.all(
    configs.map(async (c) => ({ ...c, privacy: { tier: await privacyTierFor(c.modelId) } }))
  );
}

// Chat-model matcher for the subscription catalog — mirrors the `chat` branch of
// the /api/models/openrouter route's matchesAction (server.js): text→text only,
// excluding image/video output and embed/moderation/audio-only noise. Keep in sync
// with that route so the CLI list stays a subset of the app's browsable list.
function isChatModel(m) {
  const inMods  = m.architecture?.input_modalities  || [];
  const outMods = m.architecture?.output_modalities || [];
  const modalityStr = (m.architecture?.modality || '').toLowerCase();
  const id = (m.id || '').toLowerCase();
  const outputIncludes = (t) => outMods.includes(t) || modalityStr.includes(`->${t}`) || modalityStr.includes(`-> ${t}`);
  const inputIncludes  = (t) => inMods.includes(t) || modalityStr.startsWith(t) || modalityStr.includes(`+${t}`) || modalityStr.includes(`${t}+`);
  if (id.includes('embed') || id.includes('moderation') || id.includes('whisper') || id.includes('tts')) return false;
  return inputIncludes('text') && outputIncludes('text') && !outputIncludes('image') && !outputIncludes('video');
}

// USD-per-million-token (the TEE catalogs' unit) → USD-per-token (ModelRateConfig's).
const perMTokenToRate = (v) => (typeof v === 'number' && isFinite(v) ? v / 1_000_000 : 0);

// Build the account channel's SERVABLE model catalog: OpenRouter chat models that
// have a ZDR endpoint (the account forces data_collection:deny on text inference —
// resolveUseZdrKey — so a non-ZDR model would 404) plus the TEE providers (NEAR,
// Tinfoil; Phala only when SEALED_MODELS_ENABLED, which gates the still-dev Sealed
// routing path). This is the ZDR-safe subset of the app's /api/models/openrouter
// list — we never advertise a model the subscription can't actually serve. Every
// source is best-effort: an upstream outage drops that source, never the whole list.
async function listSubscriptionCatalog() {
  const out = new Map(); // modelId → entry

  // 1) OpenRouter, restricted to ZDR-covered chat models.
  try {
    const { fetchCatalog } = require('../data/openrouterCatalog');
    const { loadZdrModelIds } = require('../data/zdrProviders');
    const { hasZdrCoverage } = require('../data/guestAllowedModels');
    const [data, zdrIds] = await Promise.all([
      fetchCatalog(`${OPENROUTER_BASE}/models`, OPENROUTER_HEADERS()),
      loadZdrModelIds(),
    ]);
    for (const m of (data.data || [])) {
      if (!m.pricing || !isChatModel(m) || !hasZdrCoverage(zdrIds, m.id)) continue;
      const prompt = parseFloat(m.pricing.prompt);
      const completion = parseFloat(m.pricing.completion);
      out.set(m.id, {
        modelId: m.id,
        displayName: m.name || m.id,
        provider: (m.id || '').split('/')[0] || 'unknown',
        ratePerInputToken: isFinite(prompt) ? prompt : 0,
        ratePerOutputToken: isFinite(completion) ? completion : 0,
        enabled: true,
        privacy: { tier: 'zdr-enforced' },
      });
    }
  } catch (err) {
    logger.warn('[listSubscriptionCatalog] OpenRouter merge failed:', err.message);
  }

  // 2) TEE providers — confidential compute is strictly stronger than ZDR, so they
  // are always servable. They arrive pre-shaped like the client model (id, name,
  // pricing.promptPerMToken, provider). Phala stays behind SEALED_MODELS_ENABLED.
  const teeSources = [
    { name: 'NEAR',    on: true,                                        load: () => require('../data/nearModels').loadNearModels('chat') },
    { name: 'Tinfoil', on: true,                                        load: () => require('../data/tinfoilModels').loadTinfoilModels('chat') },
    { name: 'Phala',   on: process.env.SEALED_MODELS_ENABLED !== '0',   load: () => require('../data/phalaModels').loadPhalaModels('chat') },
  ];
  for (const src of teeSources) {
    if (!src.on) continue;
    try {
      for (const m of (await src.load()) || []) {
        out.set(m.id, {
          modelId: m.id,
          displayName: m.name || m.id,
          provider: m.provider || (m.id || '').split('/')[0] || 'unknown',
          ratePerInputToken: perMTokenToRate(m.pricing?.promptPerMToken),
          ratePerOutputToken: perMTokenToRate(m.pricing?.completionPerMToken),
          enabled: true,
          privacy: { tier: 'tee-unverified' },
        });
      }
    } catch (err) {
      logger.warn(`[listSubscriptionCatalog] ${src.name} merge failed:`, err.message);
    }
  }

  return out;
}

/**
 * GET /api/models — the account channel's servable model catalog.
 *
 * Returns the ZDR-safe union of the OpenRouter (ZDR-covered) and TEE catalogs, with
 * ModelRateConfig rows applied as authoritative overrides: a config row's rates and
 * displayName win, and an `enabled:false` row removes a model (admin kill-switch).
 * An enabled config row NOT present in the live catalog is still surfaced (manual
 * admin additions). Falls back to the default model if every source is empty.
 */
async function listEnabledModels() {
  const catalog = await listSubscriptionCatalog();

  const configs = await ModelRateConfig.find({}).lean().catch(() => []);
  for (const c of configs) {
    if (!c.modelId) continue;
    if (c.enabled === false) { catalog.delete(c.modelId); continue; }
    const existing = catalog.get(c.modelId);
    if (existing) {
      // Admin/manual rates + label are authoritative over catalog-derived values.
      if (c.ratePerInputToken != null) existing.ratePerInputToken = c.ratePerInputToken;
      if (c.ratePerOutputToken != null) existing.ratePerOutputToken = c.ratePerOutputToken;
      if (c.displayName) existing.displayName = c.displayName;
      if (c.provider) existing.provider = c.provider;
    } else {
      // Manual model not in the live catalog — surface it with its honest tier.
      catalog.set(c.modelId, {
        modelId: c.modelId,
        displayName: c.displayName || c.modelId,
        provider: c.provider || (c.modelId || '').split('/')[0] || 'unknown',
        ratePerInputToken: c.ratePerInputToken ?? 0,
        ratePerOutputToken: c.ratePerOutputToken ?? 0,
        enabled: true,
        privacy: { tier: await privacyTierFor(c.modelId) },
      });
    }
  }

  const models = [...catalog.values()].sort((a, b) => a.modelId.localeCompare(b.modelId));
  if (models.length > 0) return models;

  // Nothing reachable (cold-start upstream outage + empty DB) — keep the account
  // usable with the default model rather than returning an empty picker.
  return withPrivacy([{
    modelId: process.env.DEFAULT_MODEL_ID || 'deepseek/deepseek-v4-flash',
    ratePerInputToken: 0,
    ratePerOutputToken: 0,
    markupFactor: 1,
    enabled: true
  }]);
}

/**
 * Stream text generation via OpenRouter (stream: true).
 * Calls onChunk(text) for each token delta as it arrives.
 * Returns { inputTokens, outputTokens, costUsd, providerCostUsd } after the stream completes.
 */
async function generateTextStream(messages, modelId, options = {}, onChunk) {
  // NEAR AI (TEE) and Tinfoil (secure enclave) models route to their
  // confidential-compute hosts. Lazy requires avoid a load-time cycle with the
  // provider services (which reuse helpers here).
  const nearAiService = require('./nearAiService');
  if (nearAiService.isNearModel(modelId)) {
    return nearAiService.generateTextStream(messages, modelId, options, onChunk);
  }
  const tinfoilService = require('./tinfoilService');
  if (tinfoilService.isTinfoilModel(modelId)) {
    return tinfoilService.generateTextStream(messages, modelId, options, onChunk);
  }

  const effectiveModelId = await resolveModelId(modelId);

  const messagesWithDirective = (() => {
    const arr = Array.isArray(messages) ? [...messages] : [messages];
    // HTML-answer mode wants real <table> elements — skip the NO_TABLES directive.
    if (options.richHtml) return arr;
    if (arr[0]?.role === 'system') {
      arr[0] = { ...arr[0], content: withNoTables(arr[0].content) };
    } else {
      arr.unshift({ role: 'system', content: NO_TABLES_DIRECTIVE });
    }
    return arr;
  })();

  const windowed = windowHistory(messagesWithDirective, { maxTokens: options.historyTokenBudget ?? 12000 });
  applyPromptCacheHints(windowed, effectiveModelId);

  const baseBody = {
    model: effectiveModelId,
    messages: windowed,
    stream: true,
    temperature: options.temperature ?? 0.8,
    max_tokens: options.maxTokens ?? 8192,
  };
  if (options.plugins) baseBody.plugins = options.plugins;

  // Model "thinking" control. A hybrid reasoning model (Kimi K3, GLM, Qwen
  // thinking variants…) reasons by DEFAULT, and those tokens are billed at the
  // completion rate, count against `max_tokens`, and — since only
  // `delta.content` is rendered below — never reach the user. On a Build turn
  // that trade is all cost and no benefit, so callers pass
  // `{ enabled: false }`; see ARTIFACT_REASONING in chatController.
  // A model that CAN'T stop thinking (o-series, kimi-k2-thinking) rejects the
  // request rather than ignoring the field — the 400 is caught below and the
  // hint dropped — and then thinks anyway, which is why `onReasoning` exists.
  if (options.reasoning) baseBody.reasoning = options.reasoning;

  if (options.webPlugin) {
    const webEntry = { id: 'web', ...(typeof options.webPlugin === 'object' ? options.webPlugin : {}) };
    baseBody.plugins = [...(baseBody.plugins || []), webEntry];
  }

  // Caller-supplied provider routing (e.g. force Google Vertex for base64
  // video input). Merged before applyProviderRouting so env `sort` still layers on.
  if (options.provider) baseBody.provider = { ...(baseBody.provider || {}), ...options.provider };

  // Routing depends only on the model + account, so resolve it once and reuse it
  // across any continuation requests (below).
  const useZdrKey = await resolveUseZdrKey({ requireZdr: options.requireZdr, modelId: effectiveModelId });
  await applyZdrRouting(baseBody, effectiveModelId, { useZdrKey });
  applyProviderRouting(baseBody);

  const decoder = new TextDecoder();
  let inputTokens = 0;
  let outputTokens = 0;
  // Set when the upstream stream failed mid-flight AFTER content had already been
  // delivered — the reply is salvaged as a truncated partial instead of throwing
  // the whole turn away (see the readErr catch in streamOnce).
  let interrupted = false;
  const annotationsById = new Map();

  const collectAnnotations = (arr) => {
    if (!Array.isArray(arr)) return;
    for (const a of arr) {
      const c = a?.url_citation || (a?.type === 'url_citation' ? a : null);
      if (c?.url) annotationsById.set(c.url, a);
    }
  };

  // Persona guard sits LAST, closest to the wire, so it sees the final text
  // after table conversion. Opt out with `{ personaGuard: false }` where a
  // first-person model name is legitimate content (translation, Build
  // artifacts, drafted messages, internal structured calls).
  const personaGuard = createPersonaGuard(onChunk, options);
  const tableConverter = createStreamingTableConverter((text) => personaGuard.push(text));
  // Raw (pre-table-conversion) text accumulated so a truncated reply can be fed
  // back verbatim as the assistant turn for continuation. Seeded with
  // `options.resumeFrom` when a caller is RESUMING a partial artifact across
  // process restarts (durable-queue retry): the model is primed with what was
  // already generated and streams only the remaining tail — so onChunk fires for
  // the tail only, the caller appends it to its own partial, and a further
  // in-request continuation still carries the full text forward.
  const resumeSeed = typeof options.resumeFrom === 'string' && options.resumeFrom.length > 0
    ? options.resumeFrom
    : '';
  let fullText = resumeSeed;

  // Stream one upstream request to completion, pushing deltas through the shared
  // table converter and accumulating token/annotation state. Returns the upstream
  // finish_reason ('stop' | 'length' | null) so the caller can decide whether to
  // continue a length-truncated reply.
  const streamOnce = async (reqMessages) => {
    const body = { ...baseBody, messages: reqMessages };
    // options.signal lets a caller cancel the upstream request mid-stream (used by
    // the speculative-streaming path in chatController: when the intent classifier
    // diverts a guessed-chat turn to image/video/compose, the in-flight speculative
    // generation is aborted so we stop paying for tokens we'll discard).
    const res = await fetch(`${OPENROUTER_BASE}/chat/completions`, orStreamFetchInit({
      method: 'POST',
      headers: orHeaders(useZdrKey),
      body: JSON.stringify(body),
      ...(options.signal ? { signal: options.signal } : {}),
    }));

    if (!res.ok) {
      const errText = await res.text();
      // Not every endpoint that ignores an unsupported parameter ignores THIS
      // one: an always-thinking endpoint answers `reasoning: {enabled:false}`
      // with a hard 400 ("Reasoning is mandatory for this endpoint and cannot
      // be disabled") instead of quietly reasoning anyway. Drop the hint and
      // retry — mutating baseBody, so a continuation doesn't re-buy the round
      // trip, and so the retry can't recurse (the field is gone). Not counted
      // against provider health: the request was malformed for this endpoint,
      // which says nothing about whether the provider is up.
      if (res.status === 400 && baseBody.reasoning && /reasoning/i.test(errText)) {
        logger.debug('[generateTextStream] endpoint requires reasoning — retrying without the hint', { modelId: effectiveModelId });
        delete baseBody.reasoning;
        return streamOnce(reqMessages);
      }
      providerHealth.recordFailure(useZdrKey ? 'openrouter_zdr' : 'openrouter', {
        status: res.status, message: errText, kind: 'inference'
      });
      // A selected model whose providers have all gone away returns
      // 404 "No endpoints found for <model>". Surface it as a typed,
      // user-actionable error (chatController has a PROVIDER_UNAVAILABLE
      // branch that forwards code + modelId to the client) rather than a
      // raw stream-error string that dead-ends the turn.
      // Every 404 from /chat/completions is a model-routing failure, so treat
      // the whole status as PROVIDER_UNAVAILABLE rather than matching on the
      // error prose. OpenRouter has at least three wordings for it — "No
      // endpoints found for <model>", "No endpoints available matching your
      // guardrail restrictions and data policy" (`:free` endpoints under a
      // prompt-logging-denied key), and "This model is unavailable for free.
      // The paid version is available now - use this slug instead: <slug>"
      // (a free variant retired to paid). Matching on prose meant that third
      // wording threw an untyped `OpenRouter stream error 404` with no
      // `statusCode`, which dead-ended the guest fallback chain on its first
      // candidate instead of advancing to the next model.
      if (res.status === 404) {
        throw Object.assign(
          new Error(`The selected model (${effectiveModelId}) is currently unavailable. Please choose a different model in Settings.`),
          { statusCode: 404, code: 'PROVIDER_UNAVAILABLE', modelId: effectiveModelId }
        );
      }
      // Carry the status on every upstream failure, not just the typed 404 —
      // callers (guest fallback chain, chatController) classify retryability
      // from `statusCode` and shouldn't have to regex the message.
      throw Object.assign(
        new Error(`OpenRouter stream error ${res.status}: ${errText}`),
        { statusCode: res.status },
      );
    }
    providerHealth.recordSuccess(useZdrKey ? 'openrouter_zdr' : 'openrouter');

    const reader = res.body.getReader();
    let buffer = '';
    let finishReason = null;
    // Per-request usage. OpenRouter reports a single cumulative usage object (some
    // providers repeat it), so take the latest within this request, then fold it
    // into the cross-request totals once the request completes.
    let reqInput = 0;
    let reqOutput = 0;

    outer: while (true) {
      // Caller aborted (speculative divert): stop reading and return what we have.
      // The caller discards the result, so partial token counts here are harmless.
      if (options.signal?.aborted) break;
      let read;
      try {
        read = await reader.read();
      } catch (readErr) {
        // An abort rejects the in-flight read() with an AbortError — expected when
        // options.signal fired.
        if (options.signal?.aborted) break;
        // A real mid-stream failure. If the model already delivered content, the
        // dominant shape is a trailing connection reset after the reply was
        // (mostly) sent — don't discard it. Mark the reply interrupted, stop
        // reading, and let the caller finalize the partial (the finally below
        // still flushes the buffered persona-guard tail). With nothing delivered
        // yet there's no partial to save and a caller may fall back to another
        // model, so rethrow.
        if (fullText.length > resumeSeed.length) { interrupted = true; break outer; }
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
          if (delta) { fullText += delta; tableConverter.push(delta); }
          // Thinking tokens, when the model reasons anyway (see baseBody.reasoning
          // above). NEVER folded into `fullText` — that text is the artifact, and
          // a continuation replays it back to the model as its own prior turn.
          // Callers opt in to be told the model is alive during a reasoning pause
          // that emits no content for minutes. `reasoning_content` is the
          // alternate spelling some providers stream.
          const reasoningDelta = choice?.delta?.reasoning ?? choice?.delta?.reasoning_content;
          if (reasoningDelta && options.onReasoning) {
            // Isolated: a throwing callback must not skip the rest of this frame.
            try { options.onReasoning(reasoningDelta); } catch { /* ignore */ }
          }
          if (choice?.finish_reason) finishReason = choice.finish_reason;
          collectAnnotations(choice?.delta?.annotations);
          collectAnnotations(choice?.message?.annotations);
          if (parsed.usage) {
            reqInput = parsed.usage.prompt_tokens || reqInput;
            reqOutput = parsed.usage.completion_tokens || reqOutput;
          }
        } catch { /* skip malformed chunk */ }
      }
    }
    // Fold this request's usage into the totals — a continuation re-sends the
    // partial as context (its own prompt tokens) and emits fresh completion
    // tokens, so both must be billed across all requests.
    inputTokens += reqInput;
    outputTokens += reqOutput;
    return finishReason;
  };

  // On resume, prime the first request as a continuation of the partial so the
  // model emits only the tail (mirrors the length-continuation shape below).
  const firstMessages = resumeSeed
    ? [...windowed, { role: 'assistant', content: resumeSeed }, { role: 'user', content: CONTINUE_DIRECTIVE }]
    : windowed;
  let finishReason = null;
  try {
    finishReason = await streamOnce(firstMessages);

    // Auto-continue a length-truncated reply. Opt-in via options.maxContinuations
    // (default 0 → unchanged behavior): a large artifact (Build/Cargo mode) can
    // exceed max_tokens, and the model stops mid-document with finish_reason
    // 'length'. Feed the partial back as the assistant turn and ask it to continue
    // verbatim, streaming the tail through the same onChunk so the client sees one
    // continuous reply. Bounded so a model that never emits 'stop' can't loop.
    let continuations = options.maxContinuations ?? 0;
    while (
      finishReason === 'length' &&
      continuations > 0 &&
      !options.signal?.aborted
    ) {
      continuations--;
      const contMessages = [
        ...windowed,
        { role: 'assistant', content: fullText },
        { role: 'user', content: CONTINUE_DIRECTIVE },
      ];
      finishReason = await streamOnce(contMessages);
    }
  } finally {
    // Always flush the table-converter / persona-guard tail — even if streamOnce
    // threw (a trailing connection reset after the last delta, an undici
    // body-timeout at stream close). Both transformers hold back the trailing
    // window (up to CARRY_CHARS, and for a short reply the ENTIRE text) until
    // end(); skipping it silently drops that tail and leaves the reply cut off
    // mid-sentence. See personaGuard.js.
    tableConverter.end();
    personaGuard.end();
  }

  const { costUsd, providerCostUsd } = await calcOpenRouterCost(effectiveModelId, null, inputTokens, outputTokens);
  const sources = await enrichWithImages(extractWebCitations(Array.from(annotationsById.values())));
  // `truncated` is true when the reply is incomplete for either reason: it was
  // still length-capped after the continuation budget ran out, OR the upstream
  // stream was interrupted mid-flight after partial delivery. Callers surface a
  // soft "may be incomplete" note. `interrupted` distinguishes the latter cause.
  return {
    inputTokens, outputTokens, costUsd, providerCostUsd, sources, finishReason,
    truncated: finishReason === 'length' || interrupted,
    interrupted,
  };
}

// ── Proxy request bounds ─────────────────────────────────────────────────────
//
// The proxy surfaces (/v1, the agent CLI, in-app connector turns) pass the
// client's body through essentially unchanged — that faithfulness is the point.
// It also meant a single request had no bounded cost: no completion ceiling, no
// input ceiling, under a 20MB JSON body limit. Combined with a pre-flight gate
// that only ever checked a flat $0.05 floor, one request could be worth orders
// of magnitude more than the balance that was allowed to start it.
//
// These two ceilings make the worst case of a proxied turn computable, which is
// what lets the caller size its balance check to the actual request instead of a
// constant. Both are generous by default — this is a backstop against unbounded
// cost, not a product limit — and both are env-tunable.
const PROXY_MAX_COMPLETION_TOKENS = Number(process.env.PROXY_MAX_COMPLETION_TOKENS) || 32_000;
const PROXY_MAX_INPUT_TOKENS = Number(process.env.PROXY_MAX_INPUT_TOKENS) || 400_000;

/**
 * Worst-case token bounds for a proxied OpenAI-shaped request.
 *
 * `inputTokens` is the rough chars/4 estimate `estimateTokens` uses elsewhere —
 * exactness doesn't matter, this sizes a gate, not a bill. Note it does not
 * count image/audio parts, so a heavily multimodal request is under-estimated;
 * the ceilings below are the real backstop, not this number.
 *
 * `completionTokens` is what the caller asked for, clamped — or the ceiling when
 * they asked for nothing, since "unspecified" means the model's own maximum and
 * that is exactly the unbounded case.
 */
function proxyRequestBounds(openaiBody) {
  const messages = Array.isArray(openaiBody?.messages) ? openaiBody.messages : [];
  let inputTokens = 0;
  for (const m of messages) inputTokens += estimateTokens(m?.content);

  // `max_completion_tokens` is OpenAI's newer spelling; reasoning models take
  // only that one. Honour whichever the caller used.
  const field = openaiBody?.max_completion_tokens != null ? 'max_completion_tokens' : 'max_tokens';
  const asked = Number(openaiBody?.[field]);
  const completionTokens = Number.isFinite(asked) && asked > 0
    ? Math.min(asked, PROXY_MAX_COMPLETION_TOKENS)
    : PROXY_MAX_COMPLETION_TOKENS;

  return {
    inputTokens,
    completionTokens,
    field,
    inputOverLimit: inputTokens > PROXY_MAX_INPUT_TOKENS,
    maxInputTokens: PROXY_MAX_INPUT_TOKENS,
    maxCompletionTokens: PROXY_MAX_COMPLETION_TOKENS,
  };
}

/**
 * Faithful OpenAI-compatible chat-completions proxy for the Privateer Agent
 * CLI. Unlike generateTextStream (text-only, reshaped for the mobile/graph UI),
 * this preserves the upstream wire format intact — tool_calls, multi-part
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
  const tinfoilService = require('./tinfoilService');
  if (tinfoilService.isTinfoilModel(openaiBody?.model)) {
    return tinfoilService.proxyChatCompletion(openaiBody);
  }

  const effectiveModelId = await resolveModelId(openaiBody?.model);

  // Pass the client body through unchanged except for the fields we own: the
  // resolved model, (when streaming) usage accounting so we can bill, and the
  // completion ceiling that keeps a single turn's cost bounded.
  const body = { ...openaiBody, model: effectiveModelId };
  if (body.stream) {
    body.stream_options = { ...(body.stream_options || {}), include_usage: true };
  }

  // Clamped here rather than only at the route, so the ceiling holds for every
  // caller of this function — a new surface cannot forget it. Writing back to
  // whichever field the caller used avoids sending both spellings, which some
  // providers reject.
  const bounds = proxyRequestBounds(openaiBody);
  body[bounds.field] = bounds.completionTokens;

  // Cache breakpoints belong here, beside the ceiling, and for the same reason:
  // every proxy surface goes through this function, so a new one cannot forget
  // them. Without this an agent loop re-bills its whole transcript every turn.
  body.messages = withProxyPromptCacheHints(body.messages, effectiveModelId);

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

module.exports = { generateText, generateTextStream, proxyChatCompletion, proxyRequestBounds, withProxyPromptCacheHints, estimateTokens, calcOpenRouterCost, calcInferenceCost, calcImageGenCost, generateImage, submitVideoGeneration, getVideoModelRuntimeCaps, pollVideoGeneration, downloadVideoBuffer, listEnabledModels, listSubscriptionCatalog, formatImageGenErrorForUser, formatVideoGenErrorForUser, ensureModelRateConfig, isVideoInputModel, isImageInputModel, selectRelevantMemories, extractMemoryCandidates, windowHistory, orHeaders, resolveUseZdrKey,
  // Shared formatting helpers reused by nearAiService (OpenAI-compatible NEAR path).
  NO_TABLES_DIRECTIVE, withNoTables, convertTablesToBullets, createStreamingTableConverter,
  // og:image enrichment for source cards — also applied to the Brave web-search path.
  enrichWithImages,
  // Exported for regression tests (retiredModelAlias / videoKeyAffinity).
  RETIRED_MODEL_ALIASES, fetchVideoWithEitherKey };
