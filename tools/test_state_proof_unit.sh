#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `Chain::state_proof`,
# the v2.2 light-client inclusion-proof primitive.
#
# Generates a Merkle inclusion proof for any state key against the
# chain's `compute_state_root`. A light client fetches a trusted Block
# header (via gossip / committee-signed beacon), reads `block.state_root`,
# and asks any full node for a state_proof. The light client then runs
# `crypto::merkle_verify` to confirm the (key, value_hash) pair is
# committed by state_root — without trusting the full node beyond the
# proof being well-formed.
#
# Key encoding (per PROTOCOL.md §4.1.1 — ten-namespace table):
#   accounts:                "a:" + domain
#   stakes:                  "s:" + domain
#   registrants:             "r:" + domain
#   dapp_registry:           "d:" + domain                   (v2.18)
#   applied_inbound_receipts:"i:" + src_shard_be8 + tx_hash
#   abort_records:           "b:" + domain
#   merge_state:             "m:" + shard_id_be4
#   pending_param_changes:   "p:" + eff_height_be8 + idx_be4
#   constants:               "k:" + name
#   counters:                "k:c:" + name
#
# The network-level `tools/test_state_proof.sh` exercises the RPC path
# end-to-end (3-node cluster + RPC + verify-state-proof CLI); this
# in-process test pins the core primitive in <1s.
#
# 12 assertions in three blocks:
#
#   Inclusion + verify (8):
#     - state_proof('a:alice') returns a proof
#     - returned proof's key matches the query key
#     - merkle_verify accepts the proof under the chain's state_root
#     - tampered value_hash fails verification (malicious-server defense)
#     - tampered sibling-hash in proof path fails
#     - wrong target_index fails (sibling-shuffle defense)
#     - distinct keys → distinct value_hashes
#     - cross-proof-swap (alice's proof certifying bob's value) fails
#
#   Non-membership (1):
#     - state_proof('a:nonexistent') returns nullopt (sorted-leaves
#       design doesn't support non-membership proofs)
#
#   Determinism + state-root consistency (3):
#     - 2 proofs for same key over unchanged chain → byte-identical
#     - mutation (TRANSFER) changes value_hash AND new proof verifies
#       under new state_root
#
# Run from repo root: bash tools/test_state_proof_unit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::state_proof (v2.2 light-client inclusion-proof primitive) ==="
OUT=$($DETERM test-state-proof 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-proof all assertions"; then
  echo ""
  echo "  PASS: state-proof unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-proof had assertion failures"
  exit 1
fi
