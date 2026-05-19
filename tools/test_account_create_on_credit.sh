#!/usr/bin/env bash
# S-035 Option 1 seed — account auto-creation paths via the credit
# side of apply. accounts_ is a map that auto-creates entries on first
# reference via operator[]; this test pins the SAFE creation paths and
# defends against silent state-corruption from unintended creations.
#
# Covered:
#   - TRANSFER to non-existent domain: account created with balance += amount
#   - Inbound cross-shard receipt to non-existent domain: account created
#   - DEREGISTER from non-registrant: nonce DOES bump (defensive design)
#     but NO registry entry auto-created (the find-first then no-op path
#     in chain.cpp:842)
#   - Stacked credit: receipt + TRANSFER to same fresh domain in same
#     block sums correctly (no double-creation)
#   - Determinism: same auto-creation sequence → same state_root, same
#     accounts-map size
#
# Defends against silent state-corruption regressions where an operator[]
# access would create an unintended account entry that affects
# state_root or balance lookups.
#
# 11 assertions across 5 scenarios.
#
# Run from repo root: bash tools/test_account_create_on_credit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== account auto-creation — TRANSFER / receipt to new domain; DEREGISTER non-registrant ==="
OUT=$($DETERM test-account-create-on-credit 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: account-create-on-credit all assertions"; then
  echo ""
  echo "  PASS: account-create-on-credit unit test"
  exit 0
else
  echo ""
  echo "  FAIL: account-create-on-credit had assertion failures"
  exit 1
fi
