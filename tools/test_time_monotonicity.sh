#!/usr/bin/env bash
# S-035 Path 1 — Block.timestamp monotonicity contract.
#
# Pins the actual current behavior of timestamp handling across all
# layers (chain + validator + hash surfaces). The Preliminaries V14
# invariant says the validator enforces wall-clock proximity only
# (`|B.timestamp - now()| ≤ 30s`, validator.cpp::check_timestamp). The
# spec does NOT require inter-block monotonic non-decrease, and the
# code reflects that:
#
#   - Chain::append performs no timestamp comparison (src/chain/chain.cpp:54)
#   - BlockValidator::validate runs check_timestamp last, enforcing
#     only the wall-clock window — never an across-blocks gate
#
# Surfaces this test pins:
#   IN compute_hash:        block identity binds timestamp
#   IN signing_bytes:       creator signature target binds timestamp
#   NOT in compute_block_digest: K-of-K digest excludes consensus-time
#                                 metadata (S-030 D2 design)
#   Chain layer (append):    accepts backward / equal / future / negative
#                            timestamps without rejection
#   Validator entry:         short-circuits genesis (index 0) regardless
#                            of timestamp value
#
# Documents the documented gap: the V14 invariant is wall-clock-window-
# only, NOT strict monotonic non-decrease. A future revision adding an
# inter-block timestamp gate would require updating this test's
# "current behavior accepts" assertions.
#
# 17 assertions across 9 scenarios.
#
# Run from repo root: bash tools/test_time_monotonicity.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Block.timestamp monotonicity contract — pin chain + validator + hash surfaces ==="
OUT=$($DETERM test-time-monotonicity 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: time-monotonicity all assertions"; then
  echo ""
  echo "  PASS: time-monotonicity unit test"
  exit 0
else
  echo ""
  echo "  FAIL: time-monotonicity had assertion failures"
  exit 1
fi
