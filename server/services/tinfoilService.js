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
 * Tinfoil inference — OpenAI-compatible text, streaming, STT and TTS.
 *
 * Tinfoil (https://inference.tinfoil.sh/v1) serves every model inside a
 * hardware secure enclave (AMD SEV-SNP CPU + NVIDIA confidential GPU) with a
 * publicly fetchable attestation document. Its API is OpenAI-compatible, so
 * this mirrors nearAiService.js (the other confidential-compute provider) and
 * drops everything OpenRouter-specific: the ZDR two-key dance, `provider`
 * routing, web/PDF plugins, and prompt-cache hints. Confidential compute is
 * the privacy guarantee, so there is no per-request ZDR negotiation — every
 * Tinfoil call uses the single server-side Tinfoil key.
 *
 * inferenceService.generateText / generateTextStream delegate here when the
 * model id is `tinfoil/`-prefixed, so chatController is untouched. Returned
 * shapes match the OpenRouter path so billing/usage recording is identical.
 *
 * Shared formatting helpers (NO_TABLES directive, table→bullet post-processor,
 * history windowing) are reused from inferenceService via a lazy require to
 * avoid a load-time circular dependency.
 */

const Sentry = require('@sentry/node');
const { getTinfoilPricing, TINFOIL_PREFIX } = require('../data/tinfoilModels');
// Standalone module (requires nothing back into inferenceService), so unlike the
// shared() helpers below it can be required eagerly without a load-time cycle.
const { createPersonaGuard } = require('./personaGuard');
const providerHealth = require('./providerHealthService');

const TINFOIL_BASE = () => process.env.TINFOIL_BASE_URL || 'https://inference.tinfoil.sh/v1';
const TINFOIL_TIMEOUT_MS = Number(process.env.TINFOIL_TEXT_TIMEOUT_MS) || 240_000;
const TINFOIL_MEDIA_TIMEOUT_MS = Number(process.env.TINFOIL_MEDIA_TIMEOUT_MS) || 120_000;

function isTinfoilModel(modelId) {
  return typeof modelId === 'string' && modelId.startsWith(TINFOIL_PREFIX);
}

function toUpstreamId(modelId) {
  return isTinfoilModel(modelId) ? modelId.slice(TINFOIL_PREFIX.length) : modelId;
}

function tinfoilHeaders() {
  const key = process.env.TINFOIL_API_KEY;
  if (!key) {
    throw Object.assign(
      new Error('Tinfoil is not configured on this server.'),
      { statusCode: 503, code: 'TINFOIL_KEY_UNAVAILABLE' }
    );
  }
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` };
}

// Lazy to avoid the inferenceService <-> tinfoilService load-time cycle.
function shared() {
  return require('./inferenceService');
}

// ── Cost calculation ─────────────────────────────────────────────────────────
//
// TRANSPARENCY REPO OMISSION — proprietary billing logic, intentionally redacted.
//
// The cost/pricing layer (markup-factor application and fallback token rates)
// is part of Privateer's CLOSED codebase and is NOT published here. Per our
// open-source policy we open the "plaintext trust boundary" only; billing
// operates purely on token *counts*, per-request catalog prices, and model
// IDs — it never sees, stores, or transmits user content — so it adds no
// auditability to the privacy claim.
//
// The function below is stubbed to preserve call-site readability. In the
// shipped server it resolves Tinfoil's catalog pricing and applies our markup;
// here it returns zeros. See docs/E2EE_ARCHITECTURE.md for what IS in scope.

async function calcTinfoilCost(/* modelId, inputTokens, outputTokens */) {
  return { costUsd: 0, providerCostUsd: 0 }; // omitted: see banner above
}

// ── Provider error mapping ───────────────────────────────────────────────────

// Map a non-OK / network failure into the same typed, retryable error the
// chat paths already understand (PROVIDER_UNAVAILABLE → friendly bubble).
function asProviderError(message, modelId, extra = {}) {
  return Object.assign(new Error(message), { code: 'PROVIDER_UNAVAILABLE', modelId, ...extra });
}

// Assemble OpenAI-style messages from the inferenceService `parts` + options.
// Tinfoil enclave models are text-first; we still handle inline images for the
// vision-capable models (Kimi, Gemma), but skip pdf/audio/video (not offered
// on chat/completions).
function buildMessages(parts, options) {
  const { withNoTables } = shared();
  const normalizedParts = Array.isArray(parts) ? parts : [parts];

  const messages = [{ role: 'system', content: withNoTables(options.systemPrompt) }];

  if (Array.isArray(options.history)) {
    for (const h of options.history) {
      if (!h || typeof h.content !== 'string' || !h.content) continue;
      messages.push({ role: h.role === 'assistant' ? 'assistant' : 'user', content: h.content });
    }
  }

  const contentArray = [];
  for (const p of normalizedParts) {
    if (typeof p === 'string') {
      if (p) contentArray.push({ type: 'text', text: p });
    } else if (p.image) {
      contentArray.push({
        type: 'image_url',
        image_url: { url: `data:${p.mimeType || 'image/jpeg'};base64,${p.image.toString('base64')}` },
      });
    } else if (p.textBlock) {
      contentArray.push({ type: 'text', text: p.textBlock });
    } else if (p.text) {
      contentArray.push({ type: 'text', text: p.text });
    }
  }

  const hasMultimodal = contentArray.some((c) => c.type !== 'text');
  if (hasMultimodal || contentArray.length > 1) {
    messages.push({ role: 'user', content: contentArray });
  } else if (contentArray.length === 1 && contentArray[0].type === 'text') {
    messages.push({ role: 'user', content: contentArray[0].text });
  } else {
    messages.push({
      role: 'user',
      content: normalizedParts.map((p) => (typeof p === 'string' ? p : p.text || '')).join('\n'),
    });
  }

  return messages;
}

async function tinfoilChatRequest(body, modelId, { signal } = {}) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TINFOIL_TIMEOUT_MS);
  // Honour a caller-supplied cancel signal in addition to our timeout.
  if (signal) {
    if (signal.aborted) abort.abort();
    else signal.addEventListener('abort', () => abort.abort(), { once: true });
  }
  let res;
  try {
    res = await fetch(`${TINFOIL_BASE()}/chat/completions`, {
      method: 'POST',
      headers: tinfoilHeaders(),
      body: JSON.stringify(body),
      signal: abort.signal,
    });
  } catch (fetchErr) {
    if (fetchErr?.name === 'AbortError' && !signal?.aborted) {
      throw asProviderError(`Tinfoil request timed out after ${TINFOIL_TIMEOUT_MS}ms for ${modelId}`, modelId, { timedOut: true });
    }
    throw fetchErr;
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    providerHealth.recordFailure('tinfoil', { status: res.status, message: errText, kind: 'inference' });
    if (res.status === 404 || res.status === 503 || res.status >= 500) {
      throw asProviderError(`The selected model (${modelId}) is currently unavailable. Please choose a different model in Settings.`, modelId, { statusCode: res.status });
    }
    const err = new Error(`Tinfoil error ${res.status}: ${errText}`);
    if (res.status === 429) err.statusCode = 429;
    throw err;
  }
  providerHealth.recordSuccess('tinfoil');
  return res;
}

/**
 * Non-streaming text generation. Mirrors inferenceService.generateText's return:
 * { text, inputTokens, outputTokens, costUsd, providerCostUsd, sources }.
 */
async function generateText(parts, options = {}) {
  const modelId = options.modelId;
  const upstream = toUpstreamId(modelId);
  const { windowHistory, convertTablesToBullets } = shared();

  let messages = buildMessages(parts, options);
  messages = windowHistory(messages, { maxTokens: options.historyTokenBudget ?? 12000 });

  const body = {
    model: upstream,
    messages,
    temperature: options.temperature ?? 0.8,
    max_tokens: options.maxTokens ?? 8192,
  };

  try {
    const res = await tinfoilChatRequest(body, modelId);
    const data = await res.json();
    const rawText = data.choices?.[0]?.message?.content || '';
    const text = convertTablesToBullets(rawText);
    const inputTokens = data.usage?.prompt_tokens || 0;
    const outputTokens = data.usage?.completion_tokens || 0;
    const { costUsd, providerCostUsd } = await calcTinfoilCost(modelId, inputTokens, outputTokens);
    return { text, inputTokens, outputTokens, costUsd, providerCostUsd, sources: [] };
  } catch (err) {
    if (!err.__sentryReported) {
      Sentry.captureException(err, { tags: { op: 'tinfoil_chat' }, extra: { modelId } });
      err.__sentryReported = true;
    }
    throw err;
  }
}

/**
 * Streaming text generation. Mirrors inferenceService.generateTextStream:
 * pushes content deltas through `onChunk` and resolves to
 * { inputTokens, outputTokens, costUsd, providerCostUsd, sources }.
 */
async function generateTextStream(messages, modelId, options = {}, onChunk) {
  const upstream = toUpstreamId(modelId);
  const { windowHistory, withNoTables, NO_TABLES_DIRECTIVE, createStreamingTableConverter } = shared();

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

  const body = {
    model: upstream,
    messages: windowed,
    stream: true,
    // OpenAI-compatible servers only emit token usage mid-stream when this is
    // set; without it inputTokens/outputTokens stay 0 and the turn isn't billed.
    stream_options: { include_usage: true },
    temperature: options.temperature ?? 0.8,
    max_tokens: options.maxTokens ?? 8192,
  };

  const res = await tinfoilChatRequest(body, modelId, { signal: options.signal });

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let inputTokens = 0;
  let outputTokens = 0;
  let sawContent = false;
  // Set when the stream failed mid-flight after content was already delivered —
  // the partial is salvaged as a truncated reply instead of throwing the turn.
  let interrupted = false;

  // Persona guard sits last, closest to the wire (see inferenceService).
  const personaGuard = createPersonaGuard(onChunk, options);
  const tableConverter = createStreamingTableConverter((text) => personaGuard.push(text));

  try {
    outer: while (true) {
      if (options.signal?.aborted) break;
      let read;
      try {
        read = await reader.read();
      } catch (readErr) {
        if (options.signal?.aborted) break;
        // Mid-stream failure after partial delivery (trailing reset): salvage the
        // partial rather than discard it. Nothing delivered yet → rethrow. See
        // inferenceService.js.
        if (sawContent) { interrupted = true; break outer; }
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
          const delta = parsed.choices?.[0]?.delta?.content;
          if (delta) { sawContent = true; tableConverter.push(delta); }
          if (parsed.usage) {
            inputTokens = parsed.usage.prompt_tokens || inputTokens;
            outputTokens = parsed.usage.completion_tokens || outputTokens;
          }
        } catch { /* skip malformed chunk */ }
      }
    }
  } finally {
    // Always flush the buffered tail, even if reader.read() threw mid-stream
    // (trailing connection reset). Both transformers hold back the trailing
    // window until end(); skipping it drops that tail and cuts the reply off
    // mid-sentence. See inferenceService.js / personaGuard.js.
    tableConverter.end();
    personaGuard.end();
  }

  const { costUsd, providerCostUsd } = await calcTinfoilCost(modelId, inputTokens, outputTokens);
  return { inputTokens, outputTokens, costUsd, providerCostUsd, sources: [], truncated: interrupted, interrupted };
}

/**
 * Faithful OpenAI-compatible passthrough for the agent CLI billed endpoint.
 * Unlike generateText/generateTextStream (which massage messages for the
 * mobile app — NO_TABLES, table→bullet, history windowing), this forwards the
 * client's OpenAI body untouched so agent **tool_calls** pass through both
 * ways. Mirrors nearAiService.proxyChatCompletion: no ZDR two-key dance or
 * provider routing — the secure enclave is the privacy guarantee, and every
 * Tinfoil call uses the single server key. Returns the raw upstream Response
 * for the caller to pipe; billing uses calcTinfoilCost. Non-OK responses are
 * returned (not thrown) so the route can forward the OpenAI-shaped error body
 * verbatim.
 *
 * @returns {Promise<{ response: Response, modelId: string }>} modelId stays
 *   `tinfoil/`-prefixed so the caller bills via the Tinfoil pricing path.
 */
async function proxyChatCompletion(openaiBody) {
  const modelId = openaiBody?.model;
  const headers = tinfoilHeaders(); // throws TINFOIL_KEY_UNAVAILABLE (503) if unset
  const body = { ...openaiBody, model: toUpstreamId(modelId) };
  if (body.stream) {
    // OpenAI-compatible servers only emit the usage chunk when this is set —
    // without it the usage stays 0 and the turn under-bills.
    body.stream_options = { ...(body.stream_options || {}), include_usage: true };
  }

  // Cover time-to-headers with the Tinfoil timeout; the body stream is
  // unbounded (the route owns inactivity handling), so we clear the timer once
  // headers land.
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TINFOIL_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(`${TINFOIL_BASE()}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: abort.signal,
    });
  } catch (fetchErr) {
    if (fetchErr?.name === 'AbortError') {
      throw asProviderError(`Tinfoil request timed out after ${TINFOIL_TIMEOUT_MS}ms for ${modelId}`, modelId, { timedOut: true, statusCode: 504 });
    }
    throw fetchErr;
  } finally {
    clearTimeout(timer);
  }

  return { response, modelId };
}

async function tinfoilMediaRequest(path, init, modelId) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TINFOIL_MEDIA_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${TINFOIL_BASE()}${path}`, { ...init, signal: abort.signal });
  } catch (fetchErr) {
    if (fetchErr?.name === 'AbortError') {
      throw asProviderError(`Tinfoil request timed out after ${TINFOIL_MEDIA_TIMEOUT_MS}ms for ${modelId}`, modelId, { timedOut: true });
    }
    throw fetchErr;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    providerHealth.recordFailure('tinfoil', {
      status: res.status, message: errText, kind: String(path).includes('audio') ? 'stt' : 'imageGen'
    });
    if (res.status === 404 || res.status === 503 || res.status >= 500) {
      throw asProviderError(`The selected model (${modelId}) is currently unavailable. Please choose a different model in Settings.`, modelId, { statusCode: res.status });
    }
    const err = new Error(`Tinfoil error ${res.status}: ${errText}`);
    if (res.status === 429) err.statusCode = 429;
    throw err;
  }
  providerHealth.recordSuccess('tinfoil');
  return res;
}

// ── Confidential transcription (Whisper / Voxtral) ───────────────────────────
//
// Tinfoil STT is an OpenAI-compatible ASR endpoint: multipart/form-data POST
// to /v1/audio/transcriptions with a `file` part (NOT OpenRouter's JSON
// `input_audio` body). Returns { text, providerCostUsd } so the audio route
// bills identically; provider cost comes from the catalog's per-request price
// (Whisper) or a token estimate (Voxtral).
async function transcribe({ audioBase64, format, language, modelId }) {
  const upstream = toUpstreamId(modelId);
  const bytes = Buffer.from(audioBase64, 'base64');
  const ext = (format || 'm4a').replace(/[^a-z0-9]/gi, '') || 'm4a';

  const form = new FormData();
  form.append('model', upstream);
  form.append('file', new Blob([bytes]), `audio.${ext}`);
  form.append('temperature', '0');
  if (language) form.append('language', language);

  const { Authorization } = tinfoilHeaders(); // throws TINFOIL_KEY_UNAVAILABLE if unset
  const res = await tinfoilMediaRequest('/audio/transcriptions', {
    method: 'POST',
    headers: { Authorization }, // let fetch set the multipart Content-Type + boundary
    body: form,
  }, modelId);
  const data = await res.json();
  const text = typeof data?.text === 'string' ? data.text : '';

  // No cost/generation-id on the response → per-request price when the catalog
  // has one, else estimate from completion pricing.
  const pricing = await getTinfoilPricing(modelId).catch(() => null);
  let providerCostUsd = pricing?.perRequest || 0;
  if (!providerCostUsd && pricing?.completionPerToken != null) {
    const estTokens = Math.ceil(text.length / 4);
    providerCostUsd = estTokens * pricing.completionPerToken;
  }
  return { text, providerCostUsd };
}

// ── Confidential speech synthesis (Qwen3 TTS / Voxtral TTS) ──────────────────
//
// OpenAI-compatible POST /v1/audio/speech. Returns the raw upstream Response
// so the audio route can reuse its shared content-type/PCM handling, plus the
// per-request provider cost for billing (the response carries no cost or
// generation-id).
async function speechRequest({ text, voice, responseFormat, modelId }) {
  const upstream = toUpstreamId(modelId);
  const body = {
    model: upstream,
    input: text,
    response_format: responseFormat || 'mp3',
    // Tinfoil's voice param is optional (model default when omitted); voice
    // identifiers are model-specific, so only forward an explicit choice.
    ...(voice ? { voice } : {}),
  };
  const res = await tinfoilMediaRequest('/audio/speech', {
    method: 'POST',
    headers: tinfoilHeaders(),
    body: JSON.stringify(body),
  }, modelId);

  const pricing = await getTinfoilPricing(modelId).catch(() => null);
  return { response: res, providerCostUsd: pricing?.perRequest || 0 };
}

module.exports = { isTinfoilModel, toUpstreamId, generateText, generateTextStream, proxyChatCompletion, calcTinfoilCost, transcribe, speechRequest };
