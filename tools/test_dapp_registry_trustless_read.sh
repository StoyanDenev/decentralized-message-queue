#!/usr/bin/env bash
# R42 Theme — v2.18 DApp registry: trustless d:-namespace reader. The
# d: sibling of `test-state-proof-value-hash` (a:/s:/k:/c: value-hash
# binding) and `test-state-proof-composite-key` (i:/m:/p: composite-key
# verify), completing the trustless-read family across every queryable
# state namespace. A light client that wants a DApp's registration —
# service_pubkey / endpoint_url / topics / activity — without trusting
# the full node must:
#   1. reconstruct the "d:" + domain key,
#   2. fetch the state_proof for that key,
#   3. INDEPENDENTLY recompute the d: leaf value_hash from the entry's
#      canonical fields using the same encoding as
#      src/chain/chain.cpp::build_state_leaves, and bind it to the proof's
#      value_hash (proves the reported entry is the one in the root), then
#   4. merkle_verify the leaf under the committee-signed state_root.
#
# The in-process unit drives exactly that pipeline. The sibling
# `test-dapp-registry-determinism` covers snapshot/restore of the WHOLE
# d: namespace; this test pins the single-entry off-node reconstruction +
# binding contract that an external verify-dapp-registration reader
# depends on, plus the field-tamper / deactivation / absent-domain
# rejection cases.
#
# 10 assertions:
#
#   Membership (2):
#     - state_proof returns a proof whose key == reconstructed d: key
#     - the proof verifies under compute_state_root
#
#   Value-hash binding (the core trustless-read contract) (4):
#     - independently recomputed value_hash == proof value_hash
#     - recomputed value_hash ALSO verifies under root (full pipeline)
#     - tampered endpoint_url breaks the binding
#     - tampered service_pubkey breaks the binding
#
#   Activity transition (1, multi-check):
#     - op=1 deactivation flips inactive_from, changes the committed
#       value_hash, and the post-deactivation value_hash re-binds + verifies
#
#   Absent / wrong-namespace (2):
#     - unregistered domain returns nullopt
#     - wrong "x:" prefix for a registered domain returns nullopt
#
#   Determinism (1):
#     - 2 proofs for the d: key over the unchanged chain byte-identical
#
# Run from repo root: bash tools/test_dapp_registry_trustless_read.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== trustless d:-namespace DApp-registry reader ==="
OUT=$($DETERM test-dapp-registry-trustless-read 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dapp-registry-trustless-read all assertions"; then
  echo ""
  echo "  PASS: dapp-registry-trustless-read unit test"
  exit 0
else
  echo ""
  echo "  FAIL: dapp-registry-trustless-read had assertion failures"
  exit 1
fi
