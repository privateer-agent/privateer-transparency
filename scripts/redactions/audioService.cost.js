// ── Cost calculation ─────────────────────────────────────────────────────────
//
// TRANSPARENCY REPO OMISSION — proprietary billing logic, intentionally redacted.
//
// Audio billing (our markup factor applied to the provider-reported cost) is
// part of Privateer's CLOSED codebase and is NOT published here. Per our policy
// we open the "plaintext trust boundary" only; billing operates on provider
// cost, token/second counts, and model IDs — it never sees, stores, or transmits
// user audio or text — so it adds nothing to the privacy audit. The helpers
// below are stubbed to preserve call-site readability.

async function chargeAudio(/* userId, providerCostUsd, { model, kind } */) {
  /* omitted: provider cost × markup, closed billing logic */
}

async function fetchGenerationCost(/* generationId, useZdrKey */) {
  return null; // omitted: provider-cost lookup
}

