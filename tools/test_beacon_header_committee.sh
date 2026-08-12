#!/usr/bin/env bash
# INGRESS beacon-header committee floor (DECISION-LOG 2026-07-31 Hole 2).
#
# Node::on_beacon_header's hand-rolled K-of-K loop was vacuous for an empty (or
# shrunken) creators list: size match 0==0, zero loop iterations, 0 != 0 false
# -> ACCEPTED. An untrusted mesh peer could push a creator-less beacon header
# carrying attacker-chosen cumulative_rand into beacon_headers_, which feeds
# shard epoch-committee selection (current_epoch_rand). The fix routes the
# handler through the ONE shared committee-signature core verify_committee_sigs
# (shardtip_verify.cpp — the same core verify_shard_tip_committee_sig_root
# routes through): NON-EMPTY creators + signed_count >= cfg_.k_block_sigs,
# keeping the caller-side signed_count == creators.size() completeness rule.
#
# In-process SHARD-role node harness (K=2) drives on_beacon_header_for_test:
#   EMPTY-COMMITTEE FORGE: creators={} REJECTED (headline falsifier);
#   UNDER-K FORGE:         creators={node0}, fully signed, REJECTED by the
#                          signed_count >= required_k floor;
#   ZERO-SENTINEL FORGE:   3 creators, 2 sign (passes floor), REJECTED by the
#                          retained completeness rule;
#   POSITIVE CONTROL:      honest full K-of-K ACCEPTED (acceptance unchanged).
# Falsify-on-mutant: (a) re-admit the vacuous loop -> EMPTY case flips RED;
# (b) delete the signed_count < required_k arm in the helper -> UNDER-K RED.
#
# Run from repo root: bash tools/test_beacon_header_committee.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== beacon-header-committee — on_beacon_header committee floor (Hole 2) ==="
OUT=$($DETERM test-beacon-header-committee 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-beacon-header-committee"; then
  echo ""
  echo "  PASS: beacon-header-committee unit test"
  exit 0
else
  echo ""
  echo "  FAIL: beacon-header-committee had assertion failures"
  exit 1
fi
