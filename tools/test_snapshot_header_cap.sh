#!/usr/bin/env bash
# RpcIngressGateAudit §3 SNAP-header-count-uncapped — the snapshot "headers" page cap.
#
# Chain::serialize_state (chain.cpp:2367) builds the snapshot's trailing "headers"
# array from a client-supplied header_count. It backs BOTH external snapshot ingress
# paths -- on_snapshot_request (gossip, node.cpp:2300) + rpc_snapshot (RPC,
# node.cpp:4533) -- but walked an UNBOUNDED header_count: header_count >= height
# forced start=0 -> to_json() over the ENTIRE chain per request (a per-request-work
# DoS the sibling handlers on_get_chain / rpc_headers / chain_summary all cap at
# 256). serialize_state is NOT used for full-chain disk persistence (Chain::save has
# its own path), so the clamp caps header_count to kSnapshotHeaderMax=256 with no
# persistence impact.
#
# Builds a real >256-block bare chain (genesis + 300 empty blocks) and pins the
# serialized-header count: header_count <= 256 is honored exactly; above the cap
# (257 / 1000 / UINT32_MAX) it clamps to a 256-header window; a short chain returns
# all its headers regardless. Falsifies on mutant: neuter the clamp and every
# over-cap assert flips back to the whole chain (see the register).
#
# Run from repo root: bash tools/test_snapshot_header_cap.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== snapshot-header-cap — serialize_state's 256-header anti-DoS bound ==="
OUT=$($DETERM test-snapshot-header-cap 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-snapshot-header-cap"; then
  echo ""
  echo "  PASS: snapshot-header-cap unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-header-cap had assertion failures"
  exit 1
fi
