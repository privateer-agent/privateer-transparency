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

