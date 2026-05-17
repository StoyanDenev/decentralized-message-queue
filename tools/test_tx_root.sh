#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for compute_tx_root
# (the K-committee union-of-tx-hashes commitment in producer.cpp).
#
# compute_tx_root is the censorship-resistance primitive: a tx is
# included iff ANY of K committee members proposed it (union
# semantics, not intersection). A regression here would either let
# one member silently exclude txs (if intersection got reintroduced
# by mistake — note the S-025 deletion comment) OR scramble the
# canonical tx_root across nodes (if dedup/sort weren't
# deterministic).
#
# 10 assertions:
#
#   1.  empty input deterministic
#   2.  deterministic on single tx
#   3.  union semantics: {A,B} ∪ {B,C} == {A,B,C}
#   4.  union NOT intersection: {A,B} ∪ {B,C} != {B}
#   5.  deduplicates identical hashes across lists
#   6.  list permutation invariance (which member proposed what
#       doesn't affect the canonical root)
#   7.  within-list tx order doesn't affect root (std::set sorts)
#   8.  adding a tx changes the root
#   9.  empty inner list doesn't affect root (committee member
#       with nothing to contribute is valid)
#  10.  multiple empty inner lists don't affect root
#
# Run from repo root: bash tools/test_tx_root.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== compute_tx_root — K-committee union-of-tx-hashes commitment ==="
OUT=$($DETERM test-tx-root 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: tx-root all assertions"; then
  echo ""
  echo "  PASS: tx-root unit test"
  exit 0
else
  echo ""
  echo "  FAIL: tx-root had assertion failures"
  exit 1
fi
