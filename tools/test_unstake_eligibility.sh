#!/usr/bin/env bash
# Trustless UNSTAKE-eligibility reader contract — the in-process FAST
# companion to the determ-light `stake-trustless` cluster reader.
#
# A light client holds a committee-anchored head (height + state_root)
# and asks a possibly-hostile full node for an account's
# (locked, unlock_height). The UNSTAKE-eligibility verdict is the
# predicate
#
#   eligible = unlock_height != UINT64_MAX && head_height >= unlock_height
#
# (mirrors the apply-side gate in src/chain/chain.cpp). The reader
# trusts that answer ONLY when the daemon-supplied cleartext
# reconstructs the SAME s:-namespace leaf that the state_proof
# Merkle-verifies under the anchored state_root, where the leaf
# value-hash encoding is
#
#   SHA256( u64_be(locked) || u64_be(unlock_height) )
#
# matching build_state_leaves() + the determ-light stake-trustless
# subcommand. Distinct from test-stake-accounting (apply-side state
# machine) and test-state-proof (generic proof mechanics): this pins
# the eligibility VERDICT layered on a Merkle-verified read.
#
# Assertions across boundary / genesis / post-DEREGISTER / tamper
# scenarios cover the pure predicate (sentinel + >= boundary), the
# verified-read path (leaf proves under state_root), the eligibility
# flip after DEREGISTER, and tamper rejection of a lied unlock_height
# or locked amount.
#
# Run from repo root: bash tools/test_unstake_eligibility.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== trustless UNSTAKE-eligibility reader (s: leaf verify + eligible() predicate + tamper) ==="
OUT=$($DETERM test-unstake-eligibility 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: unstake-eligibility all assertions"; then
  echo ""
  echo "  PASS: unstake-eligibility unit test"
  exit 0
else
  echo ""
  echo "  FAIL: unstake-eligibility had assertion failures"
  exit 1
fi
