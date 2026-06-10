#!/usr/bin/env bash
# Phase-1 ContribMsg end-to-end wire + sig-verification semantics — pin the
# exact chain the f99eeb8 liveness regression broke:
#
#   sender (make_contrib, non-zero proposer_time per the production path)
#     -> to_json / from_json wire roundtrip
#     -> RECEIVER-formula recompute (Node::on_contrib's
#        make_contrib_commitment call shape, S-030-D2 DTM-TS-v1 tail re-bound)
#     -> Ed25519 verify.
#
# WHY THIS EXISTS: f99eeb8 shipped the sender + validator halves of the
# S-030-D2 proposer_time commitment binding, but Node::on_contrib's gossip-
# side recompute kept the 7-arg call (defaulted proposer_time=0) — so EVERY
# honest production contrib failed sig-verify at every peer, Phase-1 never
# gathered K contribs, and no multi-node cluster could mint a block. The
# in-process suite missed it because nothing exercised the
# sign->serialize->deserialize->recompute->verify chain with a non-zero
# proposer_time (the codec roundtrip test uses a default zero-time contrib;
# test-make-contrib-commitment-distinct tests the hash, not the wire+verify
# semantics). This test IS that chain; assertion 2 turns RED the instant the
# receiver formula drops the time again.
#
# 8 assertions across 6 scenarios: wire presence/roundtrip of proposer_time,
# receiver-formula verify, the pre-fix 7-arg recompute REJECTED (the
# regression class), transit tamper rejected, legacy zero-time v1
# short-circuit, F2 views + TS composition (incl. its no-TS negative).
#
# Companions: tools/test_make_contrib_commitment_distinct.sh (hash
# distinctness), tools/test_timestamp_reconciliation.sh (median semantics),
# the live legs in any cluster test (block production exercises this path
# end-to-end with real gossip).
#
# Run from repo root: bash tools/test_contrib_wire_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== ContribMsg wire + receiver-formula sig-verify contract ==="
OUT=$($DETERM test-contrib-wire-verify 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: contrib-wire-verify all assertions"; then
  echo ""
  echo "  PASS: contrib-wire-verify unit test"
  exit 0
else
  echo ""
  echo "  FAIL: contrib-wire-verify had assertion failures"
  exit 1
fi
