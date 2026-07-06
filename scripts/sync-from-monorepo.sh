#!/usr/bin/env bash
#
# Re-mirror the trust-boundary subset from the (closed) Privateer monorepo into
# this transparency repo. Idempotent: copies the manifest, re-applies the
# per-file audit banner, re-applies redactions, then runs the secret-scan gate.
# It STAGES the result and prints the diff — it does NOT commit (review first).
#
# Usage:
#   scripts/sync-from-monorepo.sh [path-to-monorepo]
#   MONOREPO=/path/to/treeview scripts/sync-from-monorepo.sh
#
# When to run: only when a mirrored file (see scripts/manifest.txt) changes in
# the monorepo — i.e. crypto, wire format, the ciphertext-only storage path, the
# vault/auth endpoints, or ZDR inference routing. Billing/infra/UI changes need
# no sync (they never touch plaintext).
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:-${MONOREPO:-/Users/patrick/Documents/treeview}}"

[ -d "$SRC" ] || { echo "Monorepo not found: $SRC (pass it as arg 1 or set \$MONOREPO)"; exit 1; }
echo "Mirroring from: $SRC"
echo

# 1. Copy every manifest file (fail loudly if any moved/renamed upstream).
echo "== copying manifest files =="
while IFS= read -r rel; do
  [ -z "$rel" ] && continue
  case "$rel" in \#*) continue;; esac
  if [ ! -f "$SRC/$rel" ]; then
    echo "  MISSING upstream (manifest stale?): $rel"; exit 1
  fi
  mkdir -p "$ROOT/$(dirname "$rel")"
  cp "$SRC/$rel" "$ROOT/$rel"
done < "$ROOT/scripts/manifest.txt"
echo "  done"

# 2. Prepend the audit banner to every server/*.js (upstream has no banner).
echo "== applying server audit banner =="
while IFS= read -r rel; do
  case "$rel" in
    server/*) [[ "$rel" == *.js ]] || continue ;;
    *) continue ;;
  esac
  tmp="$ROOT/$rel.banner.tmp"
  cat "$ROOT/scripts/banner.txt" > "$tmp"
  printf '\n' >> "$tmp"
  cat "$ROOT/$rel" >> "$tmp"
  mv "$tmp" "$ROOT/$rel"
done < "$ROOT/scripts/manifest.txt"
echo "  done"

# 3a. Redact the proprietary cost/pricing blocks (inference + per-provider
# services). Each upstream file keeps its billing code inside a contiguous
# '// ── Cost calculation' section so one region swap covers it.
echo "== redacting proprietary regions =="
python3 "$ROOT/scripts/redact_region.py" \
  "$ROOT/server/services/inferenceService.js" \
  "$ROOT/scripts/redactions/inferenceService.cost.js" \
  '// ── Cost calculation' \
  '// ── Part type helpers'
python3 "$ROOT/scripts/redact_region.py" \
  "$ROOT/server/services/nearAiService.js" \
  "$ROOT/scripts/redactions/nearAiService.cost.js" \
  '// ── Cost calculation' \
  '// ── Provider error mapping'
python3 "$ROOT/scripts/redact_region.py" \
  "$ROOT/server/services/tinfoilService.js" \
  "$ROOT/scripts/redactions/tinfoilService.cost.js" \
  '// ── Cost calculation' \
  '// ── Provider error mapping'

# 3b. Scrub the internal codename from the published docs (brand: internal-only).
for d in docs/E2EE_ARCHITECTURE.md docs/CONTENT_ENCRYPTION.md; do
  [ -f "$ROOT/$d" ] && perl -pi -e 's/Internal codename: TreeView \| //g' "$ROOT/$d"
done
echo "  done"

# 4. Hard secret-scan gate — refuse to proceed if anything trips.
echo
echo "== secret scan =="
if ! "$ROOT/scripts/secret-scan.sh"; then
  echo
  echo "ABORTED: secret scan failed. Nothing staged. Fix the finding above and re-run."
  exit 1
fi

# 5. Stage and report; leave the commit to a human review.
cd "$ROOT"
git add -A
echo
echo "== staged changes =="
if git diff --cached --quiet; then
  echo "  (no changes — mirror already in sync)"
else
  git --no-pager diff --cached --stat
  echo
  echo "Review with:  git -C \"$ROOT\" diff --cached"
  echo "Then commit:  git -C \"$ROOT\" commit"
fi
