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

