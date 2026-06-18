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
 * NEAR AI Cloud inference — OpenAI-compatible text + streaming.
 *
 * NEAR AI Cloud (https://cloud-api.near.ai/v1) hosts a subset of models inside a
 * hardware Trusted Execution Environment (Intel TDX + NVIDIA confidential GPU).
 * Its API is OpenAI-compatible, so this mirrors the OpenRouter chat path in
 * inferenceService.js but drops everything OpenRouter-specific: the ZDR two-key
 * dance, `provider` routing, web/PDF plugins, and prompt-cache hints (which the
 * open TEE models don't accept). Confidential compute is the privacy guarantee
 * here, so there is no per-request ZDR negotiation — every NEAR call uses the
 * single server-side NEAR key.
 *
 * inferenceService.generateText / generateTextStream delegate here when the
 * model id is `near/`-prefixed, so chatController is untouched. Returned shapes
 * match the OpenRouter path so billing/usage recording is identical.
 *
 * Shared formatting helpers (NO_TABLES directive, table→bullet post-processor,
 * history windowing) are reused from inferenceService via a lazy require to
 * avoid a load-time circular dependency.
 */

const Sentry = require('@sentry/node');
const { getNearPricing, NEAR_PREFIX } = require('../data/nearModels');

const NEAR_BASE = () => process.env.NEAR_AI_BASE_URL || 'https://cloud-api.near.ai/v1';
const NEAR_TIMEOUT_MS = Number(process.env.NEAR_TEXT_TIMEOUT_MS) || 240_000;

// Billing knobs mirror inferenceService's fallbacks so cost is comparable.
const DEFAULT_MARKUP = parseFloat(process.env.BILLING_MARKUP_FACTOR || '2.5');
const FALLBACK_INPUT_RATE = 0.000005;
const FALLBACK_OUTPUT_RATE = 0.000015;

function isNearModel(modelId) {
  return typeof modelId === 'string' && modelId.startsWith(NEAR_PREFIX);
}

function toUpstreamId(modelId) {
  return isNearModel(modelId) ? modelId.slice(NEAR_PREFIX.length) : modelId;
}

function nearHeaders() {
  const key = process.env.NEAR_AI_API_KEY;
  if (!key) {
    throw Object.assign(
      new Error('NEAR AI is not configured on this server.'),
      { statusCode: 503, code: 'NEAR_KEY_UNAVAILABLE' }
    );
  }
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` };
}

// Lazy to avoid the inferenceService <-> nearAiService load-time cycle.
function shared() {
  return require('./inferenceService');
}

async function calcNearCost(modelId, inputTokens, outputTokens) {
  const pricing = await getNearPricing(modelId).catch(() => null);
  let providerCostUsd;
  if (pricing && (pricing.promptPerToken != null || pricing.completionPerToken != null)) {
    providerCostUsd =
      inputTokens * (pricing.promptPerToken || 0) +
      outputTokens * (pricing.completionPerToken || 0);
  } else {
    providerCostUsd = inputTokens * FALLBACK_INPUT_RATE + outputTokens * FALLBACK_OUTPUT_RATE;
  }
  return { costUsd: providerCostUsd * DEFAULT_MARKUP, providerCostUsd };
}

// Map a non-OK / network failure into the same typed, retryable error the
// chat paths already understand (PROVIDER_UNAVAILABLE → friendly bubble).
function asProviderError(message, modelId, extra = {}) {
  return Object.assign(new Error(message), { code: 'PROVIDER_UNAVAILABLE', modelId, ...extra });
}

// Assemble OpenAI-style messages from the inferenceService `parts` + options.
// NEAR TEE models are text-first; we still handle inline images for any
// vision-capable TEE model, but skip pdf/audio/video (not offered).
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

async function nearChatRequest(body, modelId, { stream = false, signal } = {}) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), NEAR_TIMEOUT_MS);
  // Honour a caller-supplied cancel signal in addition to our timeout.
  if (signal) {
    if (signal.aborted) abort.abort();
    else signal.addEventListener('abort', () => abort.abort(), { once: true });
  }
  let res;
  try {
    res = await fetch(`${NEAR_BASE()}/chat/completions`, {
      method: 'POST',
      headers: nearHeaders(),
      body: JSON.stringify(body),
      signal: abort.signal,
    });
  } catch (fetchErr) {
    if (fetchErr?.name === 'AbortError' && !signal?.aborted) {
      throw asProviderError(`NEAR AI request timed out after ${NEAR_TIMEOUT_MS}ms for ${modelId}`, modelId, { timedOut: true });
    }
    throw fetchErr;
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    if (res.status === 404 || res.status === 503 || res.status >= 500) {
      throw asProviderError(`The selected model (${modelId}) is currently unavailable. Please choose a different model in Settings.`, modelId, { statusCode: res.status });
    }
    const err = new Error(`NEAR AI error ${res.status}: ${errText}`);
    if (res.status === 429) err.statusCode = 429;
    throw err;
  }
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
    const res = await nearChatRequest(body, modelId);
    const data = await res.json();
    const rawText = data.choices?.[0]?.message?.content || '';
    const text = convertTablesToBullets(rawText);
    const inputTokens = data.usage?.prompt_tokens || 0;
    const outputTokens = data.usage?.completion_tokens || 0;
    const { costUsd, providerCostUsd } = await calcNearCost(modelId, inputTokens, outputTokens);
    return { text, inputTokens, outputTokens, costUsd, providerCostUsd, sources: [] };
  } catch (err) {
    if (!err.__sentryReported) {
      Sentry.captureException(err, { tags: { op: 'near_chat' }, extra: { modelId } });
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
    // vLLM/OpenAI-compatible servers only emit token usage mid-stream when this
    // is set; without it inputTokens/outputTokens stay 0 and the turn isn't billed.
    stream_options: { include_usage: true },
    temperature: options.temperature ?? 0.8,
    max_tokens: options.maxTokens ?? 8192,
  };

  const res = await nearChatRequest(body, modelId, { stream: true, signal: options.signal });

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let inputTokens = 0;
  let outputTokens = 0;

  const tableConverter = createStreamingTableConverter(onChunk);

  outer: while (true) {
    if (options.signal?.aborted) break;
    let read;
    try {
      read = await reader.read();
    } catch (readErr) {
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
        const delta = parsed.choices?.[0]?.delta?.content;
        if (delta) tableConverter.push(delta);
        if (parsed.usage) {
          inputTokens = parsed.usage.prompt_tokens || inputTokens;
          outputTokens = parsed.usage.completion_tokens || outputTokens;
        }
      } catch { /* skip malformed chunk */ }
    }
  }
  tableConverter.end();

  const { costUsd, providerCostUsd } = await calcNearCost(modelId, inputTokens, outputTokens);
  return { inputTokens, outputTokens, costUsd, providerCostUsd, sources: [] };
}

module.exports = { isNearModel, toUpstreamId, generateText, generateTextStream };
