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
const { getNearPricing, loadNearModels, NEAR_PREFIX } = require('../data/nearModels');
// Standalone module (requires nothing back into inferenceService), so unlike the
// shared() helpers below it can be required eagerly without a load-time cycle.
const { createPersonaGuard } = require('./personaGuard');
const providerHealth = require('./providerHealthService');

const NEAR_BASE = () => process.env.NEAR_AI_BASE_URL || 'https://cloud-api.near.ai/v1';
const NEAR_TIMEOUT_MS = Number(process.env.NEAR_TEXT_TIMEOUT_MS) || 240_000;
const NEAR_MEDIA_TIMEOUT_MS = Number(process.env.NEAR_MEDIA_TIMEOUT_MS) || 120_000;

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

// ── Cost calculation ─────────────────────────────────────────────────────────
//
// TRANSPARENCY REPO OMISSION — proprietary billing logic, intentionally redacted.
//
// The cost/pricing layer (markup-factor application and fallback token rates)
// is part of Privateer's CLOSED codebase and is NOT published here. Per our
// open-source policy we open the "plaintext trust boundary" only; billing
// operates purely on token *counts* and model IDs — it never sees, stores, or
// transmits user content — so it adds no auditability to the privacy claim.
//
// The function below is stubbed to preserve call-site readability. In the
// shipped server it resolves NEAR's catalog pricing and applies our markup;
// here it returns zeros. See docs/E2EE_ARCHITECTURE.md for what IS in scope.

async function calcNearCost(/* modelId, inputTokens, outputTokens */) {
  return { costUsd: 0, providerCostUsd: 0 }; // omitted: see banner above
}

// ── Provider error mapping ───────────────────────────────────────────────────

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

// NEAR's OpenAI-compatible endpoint accepts a message `content` that is either a
// string or an array of `text` / `image_url` parts — nothing else. A richer part
// (`file` PDF, `input_audio`, `video_url`, meant for OpenRouter) makes vLLM
// reject the WHOLE request with 400 "did not match any variant of untagged enum
// MessageContent", which would hard-fail a default (NEAR) model. Upstream now
// extracts PDFs to text and routes audio/video elsewhere, so these parts should
// never reach here — but this is the last-line guard that guarantees a stray one
// can't, ever. Unsupported parts collapse to a short text note; a lone text part
// collapses back to a plain string.
function sanitizeNearContent(content) {
  if (!Array.isArray(content)) return content;
  const out = [];
  for (const part of content) {
    if (typeof part === 'string') { if (part) out.push({ type: 'text', text: part }); continue; }
    if (!part || typeof part !== 'object') continue;
    if (part.type === 'text' || part.type === 'image_url') { out.push(part); continue; }
    const note =
      part.type === 'file'
        ? `[attachment ${part.file?.filename ? `"${part.file.filename}" ` : ''}omitted — not supported by this model]`
        : part.type === 'input_audio'
          ? '[audio attachment omitted — not supported by this model]'
          : part.type === 'video_url'
            ? '[video attachment omitted — not supported by this model]'
            : '';
    if (note) out.push({ type: 'text', text: note });
  }
  if (out.length === 0) return ' ';
  if (out.length === 1 && out[0].type === 'text') return out[0].text || ' ';
  return out;
}

function sanitizeNearMessages(messages) {
  const arr = Array.isArray(messages) ? messages : [messages];
  return arr.map((m) =>
    m && typeof m === 'object' && 'content' in m ? { ...m, content: sanitizeNearContent(m.content) } : m
  );
}

/**
 * Does this provider 400 mean "the prompt didn't fit"?
 *
 * vLLM (which NEAR fronts) doesn't say "context length exceeded" for the case
 * that actually bites a multi-image turn. It subtracts the prompt from the
 * window first and reports the ARITHMETIC:
 *   `max_tokens must be at least 1, got -31298`
 * — i.e. the images alone were 31k tokens past the ceiling. Left unclassified
 * that reaches the user as raw provider JSON; classified, chatController turns
 * it into the context-length bubble with its "choose a model" CTA.
 */
function looksLikeContextOverflow(text) {
  if (!text) return false;
  return /max_tokens must be at least \d+, got -\d+/i.test(text)
    || /context[\s_]?length|maximum context|reduce the length|prompt is too long|too many tokens/i.test(text);
}

/**
 * Cap the requested completion budget at what the model actually offers.
 *
 * Callers pass a flat 8192 (or an artifact-sized ceiling), which is more than
 * some TEE models will emit and, on a small-window model, more than the window
 * has left after a large prompt. Asking for a budget the model can't honour is
 * how a vision turn came back with zero completion tokens — billed, and an
 * empty bubble on screen. Unknown model or a failed catalog read leaves the
 * request exactly as it was.
 */
async function clampMaxTokens(modelId, requested) {
  const want = requested ?? 8192;
  const ceiling = (await catalogRow(modelId))?.maxCompletionTokens;
  if (typeof ceiling === 'number' && ceiling > 0 && want > ceiling) return ceiling;
  return want;
}

/** The model's row in the live TEE catalog, or null if unknown/unreachable. */
async function catalogRow(modelId) {
  try {
    const models = await loadNearModels();
    return models.find((m) => m.id === modelId) || null;
  } catch (_) {
    return null;
  }
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
    providerHealth.recordFailure('near', { status: res.status, message: errText, kind: 'inference' });
    if (res.status === 400 && looksLikeContextOverflow(errText)) {
      throw Object.assign(
        new Error(`The attachments and conversation are larger than ${modelId} can read in one turn.`),
        { code: 'CONTEXT_LENGTH_EXCEEDED', modelId, statusCode: 400 }
      );
    }
    const err = new Error(`Upstream inference error ${res.status}: ${errText}`);
    if (res.status === 429) err.statusCode = 429;
    throw err;
  }
  providerHealth.recordSuccess('near');
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
  messages = sanitizeNearMessages(messages);

  const body = {
    model: upstream,
    messages,
    temperature: options.temperature ?? 0.8,
    max_tokens: await clampMaxTokens(modelId, options.maxTokens),
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

  const windowed = sanitizeNearMessages(
    windowHistory(messagesWithDirective, { maxTokens: options.historyTokenBudget ?? 12000 })
  );

  const maxTokens = await clampMaxTokens(modelId, options.maxTokens);

  const body = {
    model: upstream,
    messages: windowed,
    stream: true,
    // vLLM/OpenAI-compatible servers only emit token usage mid-stream when this
    // is set; without it inputTokens/outputTokens stay 0 and the turn isn't billed.
    stream_options: { include_usage: true },
    temperature: options.temperature ?? 0.8,
    max_tokens: maxTokens,
  };

  const res = await nearChatRequest(body, modelId, { stream: true, signal: options.signal });

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

  // A completion of zero tokens is never an answer — and it is exactly what a
  // prompt that nearly fills the window produces: the provider accepts the
  // request, charges for the prompt, and emits nothing. Measured on a
  // 16k-context vision model handed ONE full-resolution photo: an empty bubble
  // the account had paid for. Raise it instead of resolving, and when the token
  // counts show the window was the reason, raise it as the context error so the
  // client renders the "choose a model" CTA rather than a bare failure.
  if (!sawContent && outputTokens === 0 && !interrupted) {
    // The prompt plus the budget we asked to write into it — that sum, not the
    // prompt alone, is what has to fit, and it is what the provider silently
    // gave up on.
    const ctx = (await catalogRow(modelId))?.contextLength;
    if (typeof ctx === 'number' && ctx > 0 && inputTokens > 0 && inputTokens + maxTokens > ctx) {
      throw Object.assign(
        new Error(`The attachments and conversation are larger than ${modelId} can read in one turn.`),
        { code: 'CONTEXT_LENGTH_EXCEEDED', modelId }
      );
    }
    throw asProviderError(`${modelId} returned an empty reply. Please try again or choose a different model.`, modelId);
  }

  const { costUsd, providerCostUsd } = await calcNearCost(modelId, inputTokens, outputTokens);
  return { inputTokens, outputTokens, costUsd, providerCostUsd, sources: [], truncated: interrupted, interrupted };
}

/**
 * Faithful OpenAI-compatible passthrough for the agent CLI billed endpoint.
 * Unlike generateText/generateTextStream (which massage messages for the mobile
 * app — NO_TABLES, table→bullet, history windowing), this forwards the client's
 * OpenAI body untouched so agent **tool_calls** pass through both ways. Mirrors
 * inferenceService.proxyChatCompletion's contract but targets the NEAR TEE host:
 * there is no ZDR two-key dance or provider routing here — confidential compute
 * (the TEE) is the privacy guarantee, and every NEAR call uses the single server
 * key. Returns the raw upstream Response for the caller to pipe; billing uses
 * calcNearCost. Non-OK responses are returned (not thrown) so the route can
 * forward NEAR's OpenAI-shaped error body verbatim.
 *
 * @returns {Promise<{ response: Response, modelId: string }>} modelId stays
 *   `near/`-prefixed so the caller bills via the NEAR pricing path.
 */
async function proxyChatCompletion(openaiBody) {
  const modelId = openaiBody?.model;
  const headers = nearHeaders(); // throws NEAR_KEY_UNAVAILABLE (503) if unset
  const body = { ...openaiBody, model: toUpstreamId(modelId) };
  if (body.stream) {
    // vLLM only emits the usage chunk when this is set — without it the usage
    // stays 0 and the turn under-bills.
    body.stream_options = { ...(body.stream_options || {}), include_usage: true };
  }

  // Cover time-to-headers with the NEAR timeout; the body stream is unbounded
  // (the route owns inactivity handling), so we clear the timer once headers land.
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), NEAR_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(`${NEAR_BASE()}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: abort.signal,
    });
  } catch (fetchErr) {
    if (fetchErr?.name === 'AbortError') {
      throw asProviderError(`NEAR AI request timed out after ${NEAR_TIMEOUT_MS}ms for ${modelId}`, modelId, { timedOut: true, statusCode: 504 });
    }
    throw fetchErr;
  } finally {
    clearTimeout(timer);
  }

  return { response, modelId };
}

// ── Confidential image generation (FLUX) ─────────────────────────────────────
//
// NEAR's image models (e.g. FLUX.2) are raw OpenAI-compatible vLLM endpoints, so
// they use the dedicated POST /v1/images/generations route (NOT chat/completions
// with modalities, which is OpenRouter's convention). Returns the same shape as
// inferenceService.generateImage — { images: [{buffer, mimeType}], responseText,
// inputTokens } — so chatController's persistence/billing path is untouched.

// Map our aspect-ratio + size selection to the pixel `size` ("WxH") the OpenAI
// images API expects. Long edge tracks the size tier; both edges snapped to a
// multiple of 32 (FLUX latent stride).
function ratioToPixelSize(aspectRatio, imageSize) {
  const base = imageSize === '4K' ? 4096 : imageSize === '2K' ? 2048 : imageSize === '0.5K' ? 512 : 1024;
  let [w, h] = String(aspectRatio || '1:1').split(':').map(Number);
  if (!Number.isFinite(w) || !Number.isFinite(h) || w <= 0 || h <= 0) { w = 1; h = 1; }
  const long = Math.max(w, h);
  const snap = (px) => Math.max(256, Math.round((base * px / long) / 32) * 32);
  return `${snap(w)}x${snap(h)}`;
}

async function nearMediaRequest(path, init, modelId) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), NEAR_MEDIA_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${NEAR_BASE()}${path}`, { ...init, signal: abort.signal });
  } catch (fetchErr) {
    if (fetchErr?.name === 'AbortError') {
      throw asProviderError(`NEAR AI request timed out after ${NEAR_MEDIA_TIMEOUT_MS}ms for ${modelId}`, modelId, { timedOut: true });
    }
    throw fetchErr;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    providerHealth.recordFailure('near', {
      status: res.status, message: errText, kind: String(path).includes('audio') ? 'stt' : 'imageGen'
    });
    if (res.status === 404 || res.status === 503 || res.status >= 500) {
      throw asProviderError(`The selected model (${modelId}) is currently unavailable. Please choose a different model in Settings.`, modelId, { statusCode: res.status });
    }
    const err = new Error(`Upstream inference error ${res.status}: ${errText}`);
    if (res.status === 429) err.statusCode = 429;
    throw err;
  }
  providerHealth.recordSuccess('near');
  return res;
}

async function generateImage(parts, options = {}) {
  const modelId = options.modelId;
  const upstream = toUpstreamId(modelId);
  const normalizedParts = Array.isArray(parts) ? parts : [parts];

  // FLUX via the images endpoint is text→image: collapse the parts into a single
  // prompt string. (Reference-image edits use a different multipart endpoint we
  // don't surface yet; the controller's fallback covers that case.)
  const prompt = normalizedParts
    .map((p) => (typeof p === 'string' ? p : (p?.text || p?.textBlock || '')))
    .filter(Boolean)
    .join('\n')
    .trim();

  const body = {
    model: upstream,
    prompt,
    n: 1,
    size: ratioToPixelSize(options.aspectRatio, options.imageSize),
    response_format: 'b64_json',
  };

  let data;
  try {
    const res = await nearMediaRequest('/images/generations', {
      method: 'POST',
      headers: nearHeaders(),
      body: JSON.stringify(body),
    }, modelId);
    data = await res.json();
  } catch (err) {
    if (!err.__sentryReported) {
      Sentry.captureException(err, { tags: { op: 'near_image' }, extra: { modelId } });
      err.__sentryReported = true;
    }
    throw err;
  }

  const images = [];
  for (const item of (Array.isArray(data?.data) ? data.data : [])) {
    if (item?.b64_json) {
      images.push({ buffer: Buffer.from(item.b64_json, 'base64'), mimeType: 'image/png' });
    } else if (typeof item?.url === 'string') {
      try {
        const r = await fetch(item.url);
        if (r.ok) {
          images.push({ buffer: Buffer.from(await r.arrayBuffer()), mimeType: r.headers.get('content-type') || 'image/png' });
        }
      } catch { /* skip unfetchable url */ }
    }
  }

  return { images, responseText: '', inputTokens: data?.usage?.prompt_tokens || 0 };
}

// ── Confidential transcription (Whisper) ─────────────────────────────────────
//
// NEAR's Whisper is an OpenAI-compatible vLLM ASR endpoint: multipart/form-data
// POST to /v1/audio/transcriptions with a `file` part (NOT OpenRouter's JSON
// `input_audio` body). Returns { text, providerCostUsd } so the audio route bills
// identically; provider cost is estimated from token pricing since the ASR
// response carries no cost/generation-id.
async function transcribe({ audioBase64, format, language, modelId }) {
  const upstream = toUpstreamId(modelId);
  const bytes = Buffer.from(audioBase64, 'base64');
  const ext = (format || 'm4a').replace(/[^a-z0-9]/gi, '') || 'm4a';

  const form = new FormData();
  form.append('model', upstream);
  form.append('file', new Blob([bytes]), `audio.${ext}`);
  form.append('temperature', '0');
  if (language) form.append('language', language);

  const { Authorization } = nearHeaders(); // throws NEAR_KEY_UNAVAILABLE if unset
  const res = await nearMediaRequest('/audio/transcriptions', {
    method: 'POST',
    headers: { Authorization }, // let fetch set the multipart Content-Type + boundary
    body: form,
  }, modelId);
  const data = await res.json();
  const text = typeof data?.text === 'string' ? data.text : '';

  // No cost/generation-id on the response → estimate from completion pricing.
  const pricing = await getNearPricing(modelId).catch(() => null);
  const estTokens = Math.ceil(text.length / 4);
  const providerCostUsd = pricing?.completionPerToken != null
    ? estTokens * pricing.completionPerToken
    : 0;
  return { text, providerCostUsd };
}

module.exports = { isNearModel, toUpstreamId, generateText, generateTextStream, proxyChatCompletion, calcNearCost, generateImage, transcribe };
