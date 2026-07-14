#!/usr/bin/env bash
# D3.5e-7d (ShardTipMergeDesign.md §9.6 pt4): the UNIVERSAL witness re-verification
# falsifier — the S-036 CLOSED-maker's consumption side.
#
# BlockValidator::check_shardtip_witnesses runs on EVERY honest node at block
# accept, BEFORE the t: fold applies carried ShardTipRecords: each record must
# carry its index-aligned full-tip witness, re-verified against the beacon's OWN
# committed cc:[E_source] via the e-7b shared helper (the byte-identical code the
# honest beacon ran contemporaneously at on_shard_tip). This is what actually
# denies a fully-Byzantine K-of-K BEACON committee the ability to commit
# fabricated distress records network-wide.
#
# Asserts (in-process via the check_shardtip_witnesses_for_test const seam,
# against a REAL frozen committee — a chain whose cc:[1] checkpoint holds two
# real-keyed members, and a source tip genuinely K-of-K-signed by them):
#   1. fixture: cc:[1] frozen at the epoch boundary;
#   2. GENUINE distress record + witness → ACCEPTED (the liveness half);
#   3. record WITHOUT witness (a pre-e7 Byzantine fold) → REJECTED;
#   4. FORGED committee signature → REJECTED (frozen-only sig verify);
#   5-6. (digest,sigs)-REUSE: a genuine HEALTHY tip under a fabricated distress
#        count → REJECTED both ways (count mismatch; rewritten count breaks the
#        signed digest);
#   7. UNPINNED epoch (no cc:[E_source]) → fail-closed REJECT;
#   8. FORGED region (≠ the genesis-committed map) → REJECTED;
#   9. tampered committee_sig_root → REJECTED (recompute mismatch);
#  10. record/witness height mismatch (the anti-reuse binding) → REJECTED;
#  11. shard_tip_witnesses on a non-EXTENDED chain → REJECTED.
#
# Run from repo root: bash tools/test_shardtip_witness_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== shardtip-witness-verify: the universal fold re-verification (D3.5e-7d) ==="
OUT=$($DETERM test-shardtip-witness-verify 2>&1)
echo "$OUT"

if echo "$OUT" | tail -2 | grep -q "PASS: test-shardtip-witness-verify"; then
  echo ""
  echo "  PASS: shardtip-witness-verify unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shardtip-witness-verify unit test"
  exit 1
fi
