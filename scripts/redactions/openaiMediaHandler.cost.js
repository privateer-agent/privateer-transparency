// ── Cost calculation ─────────────────────────────────────────────────────────
//
// TRANSPARENCY REPO OMISSION — proprietary billing logic, intentionally redacted.
//
// Our video markup factor (applied to the provider-reported render cost) is part
// of Privateer's CLOSED codebase and is NOT published here. Image billing lives
// in inferenceService.calcImageGenCost (also omitted). Billing operates purely on
// provider cost, token counts, and model IDs — it never sees user prompts or
// generated media — so it adds nothing to the privacy audit. The helper below is
// stubbed to preserve call-site readability.

function videoChargeUsd(/* providerCostUsd */) {
  return 0; // omitted: provider cost × markup
}

