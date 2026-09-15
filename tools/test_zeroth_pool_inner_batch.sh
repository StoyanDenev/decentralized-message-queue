#!/usr/bin/env bash
# S-071 — the Zeroth pool (E1) cannot be spent through a COMPOSABLE_BATCH
# inner TRANSFER (found by the S-068 review, landed 2026-09-15).
#
# The pool is an ordinary accounts_ entry at the all-zero anon address, and an
# anon address IS its Ed25519 key. The all-zero key is a small-order point
# (order 4), so a signature under it is forgeable — (R = O, S = 0) verifies one
# message in four. The E1 guard `tx.from == ZEROTH_ADDRESS` only saw the outer
# tx; a COMPOSABLE_BATCH inner TRANSFER from the pool passed the inner
# signature check with a forged signature and apply debited the pool: anyone
# could sweep it for the price of an outer fee. Now the verifier asserts E1 on
# every inner tx and the apply loop mirrors it (belt-and-suspenders).
#
# The gate DEMONSTRATES the forgery first (a verifying (R = O, S = 0) inner
# transfer from the pool is found within a few amount trials), then pins the
# verifier (batch rejected for the E1 reason), keeps an ordinary batch
# accepted, pins apply (the batch is processed — outer nonce consumed — and
# rolled back, the pool balance unchanged), and pins the node-local ingress
# mirror (an outer forged-signature pool TRANSFER is dropped at gossip).
#
# Falsify-on-mutant (executed 2026-09-15, reverted):
#   M1 delete the inner E1 check in the verifier's COMPOSABLE_BATCH arm ->
#      the "REJECTED by the verifier" arm flips RED (the batch is ACCEPTED).
#   M2 delete the inner E1 check in the apply loop -> both apply arms flip
#      RED (the pool balance drops by the forged amount, alice is credited).
#   M3 delete the outer E1 check in the ingress mirror -> the mirror arm
#      flips RED (the forged pool TRANSFER becomes mempool-resident).
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_zeroth_pool_inner_batch.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-071: the Zeroth pool cannot be spent through a COMPOSABLE_BATCH inner transfer ==="
OUT=$("$DETERM" test-zeroth-pool-inner-batch 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-zeroth-pool-inner-batch"; then
  echo "  PASS: test_zeroth_pool_inner_batch"
  exit 0
else
  echo "  FAIL: test_zeroth_pool_inner_batch (exit $rc)"
  exit 1
fi
