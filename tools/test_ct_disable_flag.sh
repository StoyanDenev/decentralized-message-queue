#!/usr/bin/env bash
# D1: the confidential-tx (shielded-pool) master switch.
#
# A deployment disables SHIELD / UNSHIELD / CONFIDENTIAL_TRANSFER at genesis via
# GenesisConfig.confidential_tx_enabled=false. The flag is genesis-pinned and:
#   - default (true) is BYTE-INVARIANT — no genesis-hash mixin, existing goldens
#     and genesis files are unchanged;
#   - disabling mixes a domain-separated tag so the genesis hash DIFFERS, which
#     is the S-039 consensus-safety property (agreement on the flag <=> agreement
#     on the genesis hash);
#   - the validator then rejects the three confidential tx types fail-closed as
#     the authoritative accept-rule.
#
# This test pins the deterministic genesis-hash + JSON surface (3 scenarios,
# 8 assertions):
#   (1) default enabled; deterministic hash.
#   (2) disabling is deterministic AND flips the genesis hash.
#   (3) to_json omits the key when enabled / emits false when disabled;
#       from_json round-trips + defaults to true for pre-D1 genesis files.
#
# Run from repo root: bash tools/test_ct_disable_flag.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== ct-disable-flag: D1 shielded-pool master switch (genesis half) ==="
OUT=$($DETERM test-ct-disable-flag 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ct-disable-flag all assertions"; then
  echo ""
  echo "  PASS: ct-disable-flag unit test"
  exit 0
else
  echo ""
  echo "  FAIL: ct-disable-flag had assertion failures"
  exit 1
fi
