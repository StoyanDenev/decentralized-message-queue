#!/usr/bin/env bash
# S-035 Option 1 seed — Config::from_json permissiveness contract.
#
# Config::from_json is intentionally permissive: every field is fetched
# via j.value(key, default), which means unknown / future / typo'd keys
# are silently ignored. This is the OPERATOR-FACING contract, distinct
# from the strict S-018 validation enforced on CONSENSUS wire surfaces
# (Block / Transaction / GenesisConfig from_json).
#
# Why the permissive default matters:
#   1. Forward-compat: a v2.30 binary's new config field must not break
#      v2.20 binaries reading the same config file (rollback safety).
#   2. Backward-compat: a legacy v1.x config must load cleanly on a
#      newer binary even if some fields it doesn't have now have safe
#      defaults (rolling upgrades without manual config rewrites).
#   3. Operator UX: a typo on an optional knob (e.g., "rpc_prot" vs
#      "rpc_port") must NOT crash the node — the typo just doesn't bind.
#      An opaque "unknown field" error at startup would be hostile to
#      operators.
#
# Covered:
#   - Unknown / future / typo'd / nested keys accepted silently
#   - Many unknown noise fields accepted in bulk
#   - Known + unknown side-by-side: known wins
#   - Real-field-vs-typo'd-sibling: real-field wins, typo ignored
#   - Empty config → full secure defaults (S-001, S-014, BFT, K-of-K)
#   - Legacy "pre-v2" config (missing v2+ fields) loads cleanly
#   - Future "v2.30" config (with unknown v2.x fields) loads cleanly
#
# Defends against drift that would either:
#   - Break operator configs (e.g., switching to strict mode that
#     rejects unknown fields → forward-incompat).
#   - Skip a known field (e.g., a default-binding regression that
#     leaves S-001 rpc_localhost_only = false instead of true).
#
# 18 assertions across 9 scenarios.
#
# Run from repo root: bash tools/test_config_permissive.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Config::from_json permissive contract (legacy + future compat) ==="
OUT=$($DETERM test-config-permissive 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: config-permissive all assertions"; then
  echo ""
  echo "  PASS: config-permissive unit test"
  exit 0
else
  echo ""
  echo "  FAIL: config-permissive had assertion failures"
  exit 1
fi
