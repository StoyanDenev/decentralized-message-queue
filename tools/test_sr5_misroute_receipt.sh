#!/usr/bin/env bash
# SR-5 (ShardRoutingSoundness, Theorem SR-5 — misroute detection), a HIGH gate-gap
# in docs/proofs/ProofClaimGateTraceability.md.
#
# A block claiming a cross-shard receipt whose dst_shard != ρ_{S,salt}(to) is
# rejected by check_cross_shard_receipts (src/node/validator.cpp): the receiver
# RECOMPUTES the destination shard from (to, shard_count, salt) rather than
# trusting the producer's claimed dst_shard. Without this, an A_misroute
# adversary could propose a block that redirects another party's funds to a
# shard of its choosing (ShardRoutingSoundness.md §4.5, threat A_misroute).
#
# The subcommand drives the check in isolation via the public
# check_cross_shard_receipts_for_test seam (2-arg, no registry — the check reads
# only b + chain). Both-legs: a correctly-routed receipt (dst == ρ(to)) is
# ACCEPTED; a misrouted one (dst != ρ(to)) is REJECTED, and the SPECIFIC
# "dst_shard mismatch" message proves the dst_shard-recompute gate fired (not the
# earlier src_shard / size guards, identical between the legs).
#
# Falsify-on-mutant (executed, reverted): deleting the dst_shard reject
# (src/node/validator.cpp) lets a misrouted receipt through — all three SR-5 legs
# flip RED while the correctly-routed control stays GREEN.
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_sr5_misroute_receipt.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== SR-5: cross-shard receipt dst_shard misroute reject ==="
OUT=$("$DETERM" test-sr5-misroute-receipt 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-sr5-misroute-receipt"; then
  echo "  PASS: test_sr5_misroute_receipt"
  exit 0
else
  echo "  FAIL: test_sr5_misroute_receipt (exit $rc)"
  exit 1
fi
