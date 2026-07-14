#!/usr/bin/env bash
# D3.5e-7a (ShardTipMergeDesign.md §9.6 pt4): the shard-tip WITNESS carrier codec —
# the DORMANT schema for the S-036 CLOSED-maker (witness-carrying fold re-verification).
#
# Block::shard_tip_witnesses carries the FULL source tip Block (index-aligned to
# shard_tip_records) so every honest node can later re-derive the frozen source
# committee and re-verify a distress record against it. At e-7a the field is a pure
# schema: no producer emission, no validator gate, no apply/fold touch — byte-neutral
# for every existing chain.
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. round-trip: witnesses serialize to JSON + round-trip byte-identically (each
#      witness Block's compute_hash preserved; carrier block hash preserved);
#   2. byte-neutrality: an empty witness vector is ELIDED from JSON + adds nothing to
#      the block hash (the dormant-off-the-distress-path invariant);
#   3. anti-strip binding (signing_bytes): dropping / forging / adding a witness
#      changes the block hash — the closure that stops a relayer stripping a witness;
#   4. order-independence: the witness+record roots are set-based (swapping the
#      aligned pairs keeps the block hash identical);
#   5. layering: the witness set changes the block HASH but NOT compute_block_digest
#      (signing_bytes-only, not digest-bound — the decisive layering choice);
#   6. depth-1 leaf/DoS guard: a witness carrying nested shard_tip_witnesses OR its own
#      shard_tip_records is REJECTED at from_json (bounds parse recursion).
#
# Run from repo root: bash tools/test_shardtip_witness_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== shardtip-witness-codec: Block::shard_tip_witnesses carrier codec (D3.5e-7a) ==="
OUT=$($DETERM test-shardtip-witness-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -2 | grep -q "PASS: test-shardtip-witness-codec"; then
  echo ""
  echo "  PASS: shardtip-witness-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shardtip-witness-codec unit test"
  exit 1
fi
