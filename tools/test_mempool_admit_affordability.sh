#!/usr/bin/env bash
# S-079 (docs/SECURITY.md; DECISION-LOG 2026-09-16 D19a backlog item 2), with
# S-070 as its REGISTER-shaped instance — mempool admission is AFFORDABILITY-
# and quota-gated, node-locally.
#
# The defect: `Node::mempool_admit_check` performed no funding check,
# `mempool_make_room_for` evicted the MINIMUM-fee entry, and the producer
# skipped an unaffordable transaction WITHOUT evicting it (the 2026-09-14
# build-time eviction fires only on verifier rejections, and the verifier
# has no balance rule). So 100 self-certifying anonymous senders x 100
# `amount = 0, fee = UINT64_MAX` TRANSFERs — validly signed, S-049-clean,
# within the per-sender quota — filled MEMPOOL_MAX_TXS with entries no block
# would ever apply, and `tx.fee <= min_fee` then rejected every representable
# fee for ever: a remote, zero-cost, PERMANENT seal of the mempool.
#
# Now (no accept-rule / apply change — BlockValidator and Chain untouched):
#   I1 ingress admits a tx only if the sender's balance at the head covers
#      the transparent debit apply would charge (mempool_tx_cost) PLUS the
#      debits of its other resident txs (the running commitment); both
#      channels (gossip: silent drop; RPC: a definitive "unaffordable" error);
#   I2 the S-008 per-sender quota (100) stays;
#   I3 at the cap an UNAFFORDABLE resident (re-checked against the current
#      head, per sender in nonce order) is evicted first, at any incoming fee;
#   I4 the build-time predicate (Node::tx_admit_locked) evicts a resident the
#      head can no longer fund, like a verifier rejection;
#   I5 the admission fee floor is derived from AFFORDABLE residents only.
#
# Deterministic in-process fixture (fixed seeds, VirtualClock, virtual-time
# VirtualEventLoop, SeededRng): the 100 x 100 flood, the S-070 REGISTER squat,
# the quota, the running commitment (incl. replace-by-fee), a REAL round
# including exactly the affordable residents, an unaffordable resident
# manufactured by a block built elsewhere (an alternate at the same nonce
# drains the sender) and evicted at build, and the eviction order + the floor
# at the cap (9998 affordable fillers + two unaffordable residents).
#
# Falsify-on-mutant (executed 2026-09-16, reverted; logs under the audit dir):
#   M1 drop the I1 ingress affordability check     -> the seal / S-070 / floor arms RED
#   M2 count only the single tx (committed := 0)   -> the commitment arms RED
#   M3 drop the per-sender quota                   -> the 101st-tx arm RED
#   M4 floor over ALL residents (unaffordable too)  -> the fee-3-at-cap arm RED
#   M5 eviction ignores affordability (pure min-fee)-> the fee-6-at-cap arm RED
#   M6 build-time skip without eviction            -> the I4 arms RED
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_mempool_admit_affordability.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-079 (+ S-070): mempool admission is affordability- and quota-gated; the zero-cost permanent seal is closed ==="
OUT=$("$DETERM" test-mempool-admit-affordability 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-mempool-admit-affordability all assertions"; then
  echo "  PASS: test_mempool_admit_affordability"
  exit 0
else
  echo "  FAIL: test_mempool_admit_affordability (exit $rc)"
  exit 1
fi
