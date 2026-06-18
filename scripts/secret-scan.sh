#!/usr/bin/env bash
#
# Hard gate: refuse to ship if anything secret-shaped, any sensitive file, or
# the internal codename leaks into the published tree. Exits non-zero on any
# finding. Run standalone any time, and automatically by sync-from-monorepo.sh.
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fail=0

echo "== [1/3] secret-shaped strings =="
if grep -rnE \
  'AKIA[0-9A-Z]{12,}|sk_live_[0-9A-Za-z]+|sk_test_[0-9A-Za-z]{10,}|AIza[0-9A-Za-z_-]{30,}|mongodb(\+srv)?://[^ ]*:[^ @]*@|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{30,}' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.json' --include='*.md' --include='*.env*' \
  . ; then
  echo "  FAIL: secret-shaped string above"; fail=1
else echo "  ok"; fi

echo "== [2/3] sensitive files =="
if find . -path ./.git -prune -o -type f \
   \( -name '*.pem' -o -name '*.key' -o -name '*.keystore' -o -name '*.jks' \
      -o -name '*.p12' -o -name 'config.env' -o -name '.env' \) -print | grep -v -- '\.env\.example$' | grep -q .; then
  echo "  FAIL: sensitive file present:"; \
    find . -path ./.git -prune -o -type f \( -name '*.pem' -o -name '*.key' -o -name '*.keystore' -o -name '*.jks' -o -name '*.p12' -o -name 'config.env' -o -name '.env' \) -print | grep -v -- '\.env\.example$'
  fail=1
else echo "  ok"; fi

echo "== [3/3] internal codename leak (TreeView) =="
if grep -rniq 'treeview' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.md' . ; then
  echo "  FAIL: 'TreeView' codename present (internal-only per brand rules):"
  grep -rni 'treeview' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.md' .
  fail=1
else echo "  ok"; fi

if [ "$fail" -ne 0 ]; then
  echo; echo "SECRET SCAN FAILED."; exit 1
fi
echo; echo "Secret scan clean."
