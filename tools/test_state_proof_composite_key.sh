#!/usr/bin/env bash
# R41 round-4 — Chain::state_proof verify path across the three
# COMPOSITE-key state namespaces. The sibling
# `test-state-proof-namespaces` unit covers the five SIMPLE per-domain
# namespaces (a/s/r/b/d — key = "<ns>:" + domain). This test extends to
# the composite keys that build_state_leaves constructs from binary key
# bodies — exactly the keys the daemon's state_proof RPC now serves to
# light clients (rpc_state_proof hex-decodes the binary body):
#   - i:  applied_inbound_receipts_  key = 'i' ':' u64_be(src_shard) tx_hash
#   - m:  merge_state_               key = 'm' ':' u32_be(shard_id)
#   - p:  pending_param_changes_     key = 'p' ':' u64_be(eff) u32_be(idx)
#
# A light client reconstructing one of these keys byte-for-byte and
# re-verifying the returned proof against compute_state_root() is the
# trust model exercised here. The key reconstruction in the unit mirrors
# src/chain/chain.cpp::build_state_leaves exactly.
#
# 11 assertions:
#
#   Per-composite-namespace inclusion + verify (4):
#     - i:/m:/p: each: state_proof returns a proof whose returned key
#       equals the reconstructed query key AND re-verifies under root
#       (the i: case is split across two assertions: key match + verify)
#
#   Cross-namespace distinctness (1):
#     - i:/m:/p: value_hashes pairwise distinct
#
#   Wrong/absent-key rejection (3):
#     - absent i: tx_hash, unmerged m: shard, absent p: idx → nullopt
#
#   Endianness contract (1):
#     - little-endian m: key body returns nullopt (big-endian wire form)
#
#   Tamper rejection + determinism (2):
#     - i: proof with flipped value_hash rejected
#     - 2 proofs for same p: composite key byte-identical
#
# Run from repo root: bash tools/test_state_proof_composite_key.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== state_proof across the composite-key namespaces (i/m/p) ==="
OUT=$($DETERM test-state-proof-composite-key 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-proof-composite-key all assertions"; then
  echo ""
  echo "  PASS: state-proof-composite-key unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-proof-composite-key had assertion failures"
  exit 1
fi
