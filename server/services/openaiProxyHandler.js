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
 * Shared OpenAI-compatible chat-completions handler.
 *
 * One billed, ZDR-pinned, streaming proxy body used by two auth surfaces:
 *   - routes/agentInference.js  → JWT-authed internal Agent CLI (kind 'agent_cli')
 *   - routes/v1.js              → sk-priv-… developer API keys   (kind 'api')
 *
 * Auth-agnostic: reads only req.userId and req.body (both auth middlewares set
 * req.userId). Speaks the raw OpenAI wire format both ways via
 * inferenceService.proxyChatCompletion so tool-calls / multi-part content pass
 * through untouched. Stateless — nothing is persisted here except billing
 * metadata (token counts, model, cost); never the prompt or completion.
 */
const logger = require('../utils/logger');
const Sentry = require('@sentry/node');
const inferenceService = require('./inferenceService');
const billingService = require('./billingService');
const { resolveUserModelId, resolveRequireZdr } = require('../controllers/chatController');

// Bill the user after a completion. Never throws — a billing failure must not
// corrupt an already-streamed response. CRITICAL: a completion that runs but
// isn't charged is free inference, so every un-billed path here is made
// OBSERVABLE (Sentry + log) rather than returning silently — never invisible.
async function billCompletion(userId, modelId, usage, ctx = {}) {
  const kind = ctx.kind || 'agent_cli';
  const inputTokens = usage?.prompt_tokens || 0;
  const outputTokens = usage?.completion_tokens || 0;

  // No usage reported. With include_usage forced upstream this should only happen
  // on a client-aborted stream (expected — a partial turn) or a provider that
  // omits the usage chunk. Flag the non-aborted case so unbilled turns surface in
  // monitoring and can be reconciled, instead of silently running free.
  if (!inputTokens && !outputTokens) {
    if (ctx.aborted) {
      logger.info('OpenAI-proxy turn aborted before usage — not billed', { userId: String(userId), modelId, kind });
    } else {
      logger.warn('OpenAI-proxy completion had no usage — UNBILLED', { userId: String(userId), modelId, kind, stream: !!ctx.stream });
      Sentry.captureMessage('openai_proxy_unbilled_no_usage', {
        level: 'warning',
        tags: { op: 'openai_proxy_bill', reason: 'no_usage', kind, stream: String(!!ctx.stream) },
        extra: { userId: String(userId), modelId },
      });
    }
    return;
  }

  try {
    const { costUsd, providerCostUsd } = await inferenceService.calcInferenceCost(
      modelId, inputTokens, outputTokens
    );
    // Developer API (sk-priv-…) bills at its own flat rate (API_MARKUP_FACTOR);
    // the internal Agent CLI keeps its cost-plus rate (AGENT_CLI_MARKUP_FACTOR),
    // falling back to the app rate when that's unset.
    const billedUsd = kind === 'api'
      ? billingService.apiBilledCost({ costUsd, providerCostUsd })
      : billingService.agentCliBilledCost({ costUsd, providerCostUsd });
    // Attribute the spend to its surface for the usage summary: developer API
    // → 'api', internal Agent CLI → 'cli'.
    const origin = kind === 'api' ? 'api' : 'cli';
    await billingService.chargeUsd(userId, billedUsd, {
      model: modelId,
      tokensPrompt: inputTokens,
      tokensCompletion: outputTokens,
      providerCostUsd,
      kind,
      origin,
    });
  } catch (err) {
    // Charge failed AFTER the response was served → the user got free inference.
    // Capture the full token context at warning level so it can be reconciled.
    logger.warn('OpenAI-proxy billing FAILED — completion served UNBILLED', {
      userId: String(userId), modelId, kind, inputTokens, outputTokens, error: err.message,
    });
    Sentry.captureException(err, {
      level: 'warning',
      tags: { op: 'openai_proxy_bill', reason: 'charge_failed', kind },
      extra: { userId: String(userId), modelId, inputTokens, outputTokens },
    });
  }
}

/**
 * Handle POST .../chat/completions. Expects req.userId set by an auth
 * middleware. opts.kind selects the UsageEvent kind ('agent_cli' | 'api').
 */
async function handleChatCompletion(req, res, opts = {}) {
  const kind = opts.kind || 'agent_cli';
  const userId = req.userId;
  const body = req.body || {};

  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    return res.status(400).json({ error: { message: 'messages[] is required', type: 'invalid_request_error', code: 'INVALID_REQUEST' } });
  }

  try {
    // body.model → user DB pref → default; then strict-ZDR resolution (default on).
    const modelId = await resolveUserModelId(userId, body.model);
    const requireZdr = await resolveRequireZdr(userId, body.requireZdr);

    const { response, modelId: effectiveModelId } = await inferenceService.proxyChatCompletion(
      { ...body, model: modelId },
      { requireZdr }
    );

    // Forward upstream failures verbatim (OpenRouter already returns an
    // OpenAI-shaped { error } body the AI SDK understands).
    if (!response.ok) {
      const errText = await response.text();
      res.status(response.status).type(response.headers.get('content-type') || 'application/json');
      return res.send(errText);
    }

    const isStream = body.stream === true;

    if (!isStream) {
      const json = await response.json();
      await billCompletion(userId, effectiveModelId, json?.usage, { stream: false, kind });
      return res.json(json);
    }

    // Streaming: pipe raw SSE bytes through while scanning for the usage chunk.
    res.status(200);
    res.setHeader('Content-Type', response.headers.get('content-type') || 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = '';
    let usage = null;
    let aborted = false;
    res.on('close', () => { aborted = true; });

    while (true) {
      const { done, value } = await reader.read();
      if (done || aborted) break;
      res.write(Buffer.from(value));

      // Tee a decoded copy to extract the final usage object for billing.
      sseBuffer += decoder.decode(value, { stream: true });
      const lines = sseBuffer.split('\n');
      sseBuffer = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        if (raw === '[DONE]') continue;
        try {
          const parsed = JSON.parse(raw);
          if (parsed.usage) usage = parsed.usage;
        } catch { /* partial/non-JSON chunk — ignore */ }
      }
    }

    if (aborted) { try { await reader.cancel(); } catch (_) {} }
    res.end();
    await billCompletion(userId, effectiveModelId, usage, { stream: true, aborted, kind });
  } catch (err) {
    const status = err.statusCode || 500;
    const code = err.code || 'INFERENCE_ERROR';
    if (status >= 500) {
      Sentry.captureException(err, { tags: { op: 'openai_proxy', kind } });
      logger.error('OpenAI-proxy inference error:', err.message);
    }
    if (res.headersSent) {
      // Stream already started — signal the error inline and close.
      try { res.write(`data: ${JSON.stringify({ error: { message: err.message, code } })}\n\n`); } catch (_) {}
      return res.end();
    }
    return res.status(status).json({ error: { message: err.message, type: 'invalid_request_error', code } });
  }
}

module.exports = { handleChatCompletion, billCompletion };
