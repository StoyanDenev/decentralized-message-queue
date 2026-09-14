#!/usr/bin/env bash
# S-056 / S-059 / S-061 / S-062 (docs/SECURITY.md), second increment — the
# producer-side admission predicate EVICTS what it rejects and MEMOIZES its
# verdicts per head.
#
# The first increment (tools/test_producer_admit.sh) made build_body ask the
# verifier's own per-tx rule set (BlockValidator::check_transaction) before
# including a transaction, closing the "producer includes what the verifier
# rejects, nothing evicts, chain halts" class. Its recorded residual: a
# rejected transaction stayed resident, was re-checked (signature / proof
# verification) on every one of the (K+1)+ rebuilds a round, and blocked its
# sender's later nonces; a VALID resident transaction was re-verified on every
# rebuild too. Now Node::tx_admit_locked evicts a rejected transaction (store +
# (from, nonce) index) and memoizes verdicts keyed by (tx hash, expected
# nonce) for one head hash — check_transaction is deterministic over (tx,
# head state), so each resident transaction is verified at most once per head.
#
# In-process M=K=1 node harness; the predicate is driven through the
# tx_admit_for_test seam (no round needed); rpc_status()["mempool_size"] and
# admit_verifications_for_test() are the observables.
#
# Falsify-on-mutant (executed 2026-09-14, reverted):
#   M1 drop the evict_tx_locked call -> the eviction arm and the quota arm
#      flip RED.
#   M2 drop the memo lookup (always verify) -> the three memo arms flip RED.
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_mempool_admit_eviction.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-056/S-059/S-061/S-062 (2nd increment): build-time rejection evicts; verdicts memoized per head ==="
OUT=$("$DETERM" test-mempool-admit-eviction 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-mempool-admit-eviction"; then
  echo "  PASS: test_mempool_admit_eviction"
  exit 0
else
  echo "  FAIL: test_mempool_admit_eviction (exit $rc)"
  exit 1
fi
