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
 * One billed, ZDR-pinned, streaming proxy body used by three surfaces:
 *   - routes/agentInference.js  → JWT-authed internal Agent CLI (kind 'agent_cli')
 *   - routes/v1.js              → sk-priv-… developer API keys   (kind 'api')
 *   - routes/appTools.js        → in-app connector turns         (kind 'app_tools')
 *
 * The third exists because the app's own chat stream reshapes everything to text
 * for the UI, and a connector turn needs `tool_calls` intact. Same body, app
 * billing rates, its own concurrency pool.
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

/**
 * Apply a surface's billing policy to a provider cost.
 *
 * Shared by the pre-flight estimate and the post-completion charge so the two
 * cannot drift: a gate that priced a turn differently from the bill would either
 * block affordable requests or admit unaffordable ones, and the second is how
 * this file's costs got away from us in the first place.
 */
function billedCostFor(kind, { costUsd, providerCostUsd }) {
  // Developer API (sk-priv-…) bills at its own flat rate (API_MARKUP_FACTOR);
  // the internal Agent CLI keeps its cost-plus rate (AGENT_CLI_MARKUP_FACTOR),
  // falling back to the app rate when that's unset. 'app_tools' is an in-app
  // connector turn — it is an app chat turn that happens to need the raw
  // tool_calls wire format, so it bills at APP rates (costUsd, no CLI factor)
  // and must never be repriced as terminal usage.
  if (kind === 'api') return billingService.apiBilledCost({ costUsd, providerCostUsd });
  if (kind === 'app_tools') return costUsd;
  return billingService.agentCliBilledCost({ costUsd, providerCostUsd });
}

/**
 * Refuse a turn whose worst case the account cannot cover, before it is served.
 *
 * The gate on these routes was `checkCreditBalance(0.05)` — a flat floor, the
 * same $0.05 whether the request was a one-line completion on a cheap model or a
 * million-token Opus turn. Nothing connected the amount required to start a
 * request with the amount that request could cost, so an account holding pennies
 * could commit us to arbitrary provider spend.
 *
 * This prices the request's ceiling (estimated input + the clamped completion
 * bound) through the same policy that will bill it, and requires that much
 * balance. Returns true when it has already answered the request.
 *
 * Deliberately a *worst case*, so it over-asks: a caller who wants a short reply
 * on an expensive model should say so with `max_tokens`, which lowers both the
 * ceiling and the requirement. The 402 says exactly that, because otherwise this
 * reads as "you are out of credit" to someone who is not.
 */
async function refuseIfUnaffordable(req, res, { userId, modelId, kind, body }) {
  const bounds = inferenceService.proxyRequestBounds(body);

  if (bounds.inputOverLimit) {
    res.status(413).json({ error: {
      message: `This request is about ${bounds.inputTokens.toLocaleString()} tokens of input, over the ${bounds.maxInputTokens.toLocaleString()} limit for a single call. Split it into smaller turns.`,
      type: 'invalid_request_error',
      code: 'REQUEST_TOO_LARGE',
    } });
    return true;
  }

  let requiredUsd;
  try {
    const { costUsd, providerCostUsd } = await inferenceService.calcInferenceCost(
      modelId, bounds.inputTokens, bounds.completionTokens
    );
    requiredUsd = billedCostFor(kind, { costUsd, providerCostUsd });
  } catch (err) {
    // Pricing is unavailable (catalog miss, provider hiccup). Fail OPEN: the
    // post-completion charge still runs, and blocking paying users because we
    // could not look up a rate is the worse failure. Observable, not silent.
    logger.warn('Pre-flight cost estimate failed — serving without it', { modelId, kind, error: err.message });
    return false;
  }
  if (!Number.isFinite(requiredUsd) || requiredUsd <= 0) return false;

  const { status, totalUsd } = await billingService.checkBalance(userId, requiredUsd);
  if (status !== 'blocked') return false;

  res.status(402).json({ error: {
    message: `This request could cost up to $${requiredUsd.toFixed(2)} on ${modelId} (up to ${bounds.completionTokens.toLocaleString()} completion tokens), which is more than the $${(totalUsd || 0).toFixed(2)} on this account. Add credit, lower max_tokens, or use a cheaper model.`,
    type: 'invalid_request_error',
    code: 'INSUFFICIENT_FUNDS',
  } });
  return true;
}

/**
 * Characters of *generated* output in one SSE chunk.
 *
 * All three carry completion tokens the provider bills for, so all three count:
 * visible content, emitted reasoning, and tool-call arguments — the last being
 * the one that matters most here, since an agent turn the user interrupts is
 * very often mid-tool-call and would otherwise measure as almost nothing.
 */
function deltaChars(parsed) {
  let n = 0;
  for (const choice of parsed?.choices || []) {
    const delta = choice?.delta;
    if (!delta) continue;
    if (typeof delta.content === 'string') n += delta.content.length;
    if (typeof delta.reasoning === 'string') n += delta.reasoning.length;
    for (const call of delta.tool_calls || []) {
      const args = call?.function?.arguments;
      if (typeof args === 'string') n += args.length;
    }
  }
  return n;
}

/**
 * Reconstruct a usage object for a turn the provider never priced for us.
 *
 * The provider reports usage in the FINAL chunk, so any turn that does not reach
 * that chunk carries none — and this used to mean the turn was simply not
 * billed. That is the opposite of free: OpenRouter has charged us for the entire
 * prompt (the bulk of an agent turn's cost — 99% of it on a long transcript)
 * plus every token generated before the stream stopped. Both causes are ordinary
 * on the surface this mostly serves: an interrupt (every Esc in the Agent CLI,
 * every dropped connection, every client-side tool-loop cancel) AND a stream
 * that ENDS early — an upstream that died mid-generation, which never emits the
 * usage chunk because it never finished.
 *
 * The estimate is the same chars/4 heuristic `proxyRequestBounds` prices the
 * pre-flight gate with, applied to the prompt we sent and the bytes we actually
 * streamed back. It undercounts (bytes in flight when the stream stopped are
 * lost, and it cannot see server-side reasoning tokens the provider billed but
 * never emitted), which is the direction to err: the alternative on the table is
 * charging zero. It is the LAST resort — `settleUsage` prefers the provider's
 * own report and OpenRouter's generation record ahead of it.
 */
function estimateUnmeteredUsage(body, completionChars) {
  const { inputTokens } = inferenceService.proxyRequestBounds(body);
  // Same chars/4 as inferenceService.estimateTokens, applied to a count rather
  // than to text we deliberately never kept. Parity with it is pinned by
  // test/abortedStreamBilling.test.js so the two cannot drift apart.
  //
  // Coerced first: Math.max(0, NaN) is NaN, which would reach chargeUsd as a
  // NaN bill. It rejects that (non-finite amounts return early), so the failure
  // would be a silently unbilled turn — the exact bug this function exists for.
  const chars = Number(completionChars);
  const completionTokens = Math.ceil((Number.isFinite(chars) && chars > 0 ? chars : 0) / 4);
  if (!inputTokens && !completionTokens) return null;
  return { prompt_tokens: inputTokens, completion_tokens: completionTokens };
}

/**
 * Is this a usage report we can bill from?
 *
 * Absent is not billable — but neither is *zeroed*, and that distinction is the
 * whole point of this function. OpenRouter reports
 * `{prompt_tokens: 0, completion_tokens: 0}` when it has no usage to report, and
 * a truthiness check (`if (usage)`) reads that as a measurement and bills
 * nothing: a turn with a usage object on the wire, and a $0 charge. Zero prompt
 * tokens is also literally impossible for a request that carried messages, so
 * 0/0 is always a missing report wearing a usage object.
 */
function hasBillableUsage(usage) {
  if (!usage) return false;
  const prompt = Number(usage.prompt_tokens) || 0;
  const completion = Number(usage.completion_tokens) || 0;
  return prompt > 0 || completion > 0;
}

/**
 * The usage a finished turn is billed on, from the most authoritative source
 * that has one:
 *
 *   1. the provider's own report (the stream's final chunk, or the response
 *      body) — the normal case, and the only one that costs no lookup;
 *   2. OpenRouter's record for the generation, when that report is missing or
 *      zeroed. Recovery rather than a guess: it is the number OpenRouter billed
 *      US, and it exists precisely when the final chunk never arrived;
 *   3. a chars/4 estimate of the prompt and of what we streamed back.
 *
 * The reported usage always wins, and each fallback is only tried after the one
 * above it came back with nothing billable, so no turn is ever priced twice or
 * priced from a worse source than the one available.
 */
async function settleUsage({ reported, genId, requireZdr, modelId, body, completionChars, userId, kind, aborted }) {
  if (hasBillableUsage(reported)) return { usage: reported, estimated: false };

  const recovered = await inferenceService
    .fetchOpenRouterUsage(genId, { requireZdr, modelId })
    .catch(() => null);
  if (hasBillableUsage(recovered)) {
    logger.info('OpenAI-proxy turn had no usage — recovered it from the generation record', {
      userId: String(userId), modelId, kind, genId,
      inputTokens: recovered.prompt_tokens, outputTokens: recovered.completion_tokens, aborted: !!aborted,
    });
    return { usage: recovered, estimated: false };
  }

  const estimated = estimateUnmeteredUsage(body, completionChars);
  return { usage: estimated, estimated: !!estimated };
}

// Bill the user after a completion. Never throws — a billing failure must not
// corrupt an already-streamed response. CRITICAL: a completion that runs but
// isn't charged is free inference, so every un-billed path here is made
// OBSERVABLE (Sentry + log) rather than returning silently — never invisible.
async function billCompletion(userId, modelId, usage, ctx = {}) {
  const kind = ctx.kind || 'agent_cli';
  const inputTokens = usage?.prompt_tokens || 0;
  const outputTokens = usage?.completion_tokens || 0;

  // Nothing billable reached us: no token counts, no generation record to
  // recover them from, and nothing measurable in the stream. With include_usage
  // forced upstream this is a narrow case — a provider that omits the usage
  // chunk on a stream that then ends before anything countable, or an abort so
  // early that neither a prompt nor a streamed byte can be counted. Either way
  // it surfaces in monitoring rather than running free and silent, and the
  // extra context below is what makes it reconcilable: `genId` is the handle
  // OpenRouter's own record can be read back with, and `completionChars` says
  // how much was generated behind the missing number.
  if (!inputTokens && !outputTokens) {
    logger.warn('OpenAI-proxy completion had no usage — UNBILLED', {
      userId: String(userId), modelId, kind, stream: !!ctx.stream, aborted: !!ctx.aborted,
      genId: ctx.genId || null, completionChars: ctx.completionChars ?? null,
    });
    Sentry.captureMessage('openai_proxy_unbilled_no_usage', {
      level: 'warning',
      tags: {
        op: 'openai_proxy_bill', reason: 'no_usage', kind,
        stream: String(!!ctx.stream), aborted: String(!!ctx.aborted),
      },
      extra: {
        userId: String(userId), modelId,
        genId: ctx.genId || null, completionChars: ctx.completionChars ?? null,
      },
    });
    return;
  }

  if (ctx.estimatedUsage) {
    // Never reported by the provider — the row is flagged so reconciliation can
    // tell a measured charge from an estimated one. See settleUsage.
    logger.info('OpenAI-proxy turn had no usage — billing an estimate', {
      userId: String(userId), modelId, kind, inputTokens, outputTokens,
    });
  }

  try {
    const { costUsd, providerCostUsd } = await inferenceService.calcInferenceCost(
      modelId, inputTokens, outputTokens
    );
    // Same policy the pre-flight estimate used — see billedCostFor.
    const billedUsd = billedCostFor(kind, { costUsd, providerCostUsd });
    // Attribute the spend to its surface for the usage summary: developer API
    // → 'api', internal Agent CLI → 'cli', in-app connector turn → 'app'.
    const origin = kind === 'api' ? 'api' : kind === 'app_tools' ? 'app' : 'cli';
    // A connector turn lands in the same UsageEvent bucket as any other app
    // chat turn ('inference'); 'app_tools' is a billing-policy selector here,
    // not a new spend kind, so usageEventModel's enum is untouched.
    const usageKind = kind === 'app_tools' ? 'inference' : kind;
    await billingService.chargeUsd(userId, billedUsd, {
      model: modelId,
      tokensPrompt: inputTokens,
      tokensCompletion: outputTokens,
      providerCostUsd,
      kind: usageKind,
      origin,
      estimatedUsage: !!ctx.estimatedUsage,
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
 * middleware. opts.kind selects the billing policy and surface attribution
 * ('agent_cli' | 'api' | 'app_tools').
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

    // Sized to THIS request, not a flat floor. Must run after the model is
    // resolved (the price depends on it) and before anything is dispatched.
    if (await refuseIfUnaffordable(req, res, { userId, modelId, kind, body })) return;

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
      const settled = await settleUsage({
        reported: json?.usage, genId: json?.id, requireZdr, modelId: effectiveModelId,
        body, completionChars: null, userId, kind, aborted: false,
      });
      await billCompletion(userId, effectiveModelId, settled.usage, {
        stream: false, kind, estimatedUsage: settled.estimated, genId: json?.id,
      });
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
    // OpenRouter's generation id (`gen-…`): the handle its /generation record is
    // retrievable by when the usage chunk never arrives. Only an OpenRouter-shaped
    // id is kept, so the enclave paths never trigger a lookup (see settleUsage).
    let genId = null;
    // Length only, never the text: this file persists billing metadata and
    // nothing else, and a character count is all the estimate below needs.
    let completionChars = 0;
    let aborted = false;
    res.on('close', () => { aborted = true; });

    while (true) {
      const { done, value } = await reader.read();
      if (done || aborted) break;
      res.write(Buffer.from(value));

      // Tee a decoded copy to extract the final usage object for billing, and to
      // measure what was generated in case the client leaves before it arrives.
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
          if (!genId && typeof parsed.id === 'string' && parsed.id.startsWith('gen-')) genId = parsed.id;
          completionChars += deltaChars(parsed);
        } catch { /* partial/non-JSON chunk — ignore */ }
      }
    }

    if (aborted) { try { await reader.cancel(); } catch (_) {} }
    res.end();

    // A stream that ends without a usable usage chunk is settled on the best
    // source that still has a number — the provider report, OpenRouter's
    // generation record, or an estimate — see settleUsage. Deliberately NOT
    // gated on `aborted`: a stream that ends early (an upstream that died
    // mid-generation) reaches here with `aborted === false` and no usage, which
    // is the same unbilled turn the abort path was fixed for.
    const settled = await settleUsage({
      reported: usage, genId, requireZdr, modelId: effectiveModelId,
      body, completionChars, userId, kind, aborted,
    });
    await billCompletion(userId, effectiveModelId, settled.usage, {
      stream: true, aborted, kind, estimatedUsage: settled.estimated, genId, completionChars,
    });
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

module.exports = {
  handleChatCompletion,
  billCompletion,
  billedCostFor,
  refuseIfUnaffordable,
  // Exported for test/abortedStreamBilling.test.js.
  deltaChars,
  hasBillableUsage,
  estimateUnmeteredUsage,
};
