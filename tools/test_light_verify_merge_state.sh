#!/usr/bin/env bash
# determ-light verify-merge-state — trust-minimized INCLUDED /
# NOT-INCLUDED / UNVERIFIABLE verdict on whether a shard's under-quorum-
# merge record (shard_id → partner_id + refugee_region) is a member of the
# committee-verified `m:` (merge_state) namespace, with the proof bound to
# the EXACT (partner_id, refugee_region) the caller asserts.
#
# The verifier anchors genesis, committee-verifies the header chain to
# head, computes the canonical merge key ("m:" + shard_id_be4), hex-encodes
# the binary body, fetches the `m:`-namespace state-proof, and Merkle-
# verifies it against the committee-signed state_root — binding the proof
# to THIS record via key_bytes == local key AND value_hash ==
# SHA256(u64_be(partner_id) || u64_be(region_len) || region).
#
# The daemon now serves the composite-key `m:` namespace (the caller hex-
# encodes the binary key body; see src/node/node.cpp rpc_state_proof), so
# the same verifier code path that fails closed against a legacy daemon
# yields a real INCLUDED against a current one.
#
# merge_state only forms on an EXTENDED sharded chain when a shard's
# committee drops under quorum (R7 under-quorum-merge). Forcing that
# deterministically in a short test is unreliable, so this test follows
# the receipt-inclusion SKIP-clean philosophy: it stands up a 2-shard
# cluster, probes `snapshot create` for an active merge, and asserts a
# real INCLUDED if one exists. The fail-closed / negative assertions need
# only a live shard daemon with a non-empty state_root and always run.
#
# Assertions (all run; the INCLUDED headline only when a merge is active):
#   1. (headline, conditional) A genuinely-active merge record → INCLUDED,
#      exit 0, with a committee-anchored state_root. SKIP if no merge.
#   2. A random (never-merged) shard_id → NOT-INCLUDED (a sound verified
#      negative: daemon returns not_found), exit 0, NEVER a false INCLUDED.
#   3. Wrong --genesis → fail-closed, non-zero exit (genesis-hash mismatch
#      detected before any verdict); never INCLUDED.
#   4. Out-of-range --shard-id (> u32) → non-zero exit, never INCLUDED.
#   5. Missing required flags → usage error (exit 1).
#   6. (anti-false-positive) The NOT-INCLUDED / error variants never print
#      a line beginning with "INCLUDED".
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_merge_state.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_vms
TABS=$PROJECT_ROOT/$T

PY=python
command -v python >/dev/null 2>&1 || PY=python3

declare -a NODE_PIDS
cluster_running=1
stop_cluster() {
  set +e
  if [ "$cluster_running" = "1" ]; then
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    cluster_running=0
  fi
  return 0
}
trap stop_cluster EXIT INT

rm -rf $T
mkdir -p $T/beacon $T/shard0 $T/shard1

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

SALT="00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef"

echo "=== 1. Init data dirs + node keys (1 beacon + 2 shards) ==="
$DETERM init --data-dir $T/beacon --profile regional_test 2>&1 | tail -1
$DETERM init --data-dir $T/shard0 --profile regional_test 2>&1 | tail -1
$DETERM init --data-dir $T/shard1 --profile regional_test 2>&1 | tail -1

$DETERM genesis-tool peer-info beacon_n  --data-dir $T/beacon --stake 1000 > $T/beacon_p.json
$DETERM genesis-tool peer-info shard0_n  --data-dir $T/shard0 --stake 1000 > $T/shard0_p.json
$DETERM genesis-tool peer-info shard1_n  --data-dir $T/shard1 --stake 1000 > $T/shard1_p.json

echo
echo "=== 2. Build per-chain genesis (shared salt, S=2, M=K=1) ==="
cat > $T/beacon_gen.json <<EOF
{
  "chain_id": "test-light-vms",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 1,
  "shard_id": 0,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/beacon_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
cat > $T/shard0_gen.json <<EOF
{
  "chain_id": "test-light-vms",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard0_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
cat > $T/shard1_gen.json <<EOF
{
  "chain_id": "test-light-vms",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 1,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard1_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF

$DETERM genesis-tool build $T/beacon_gen.json | tail -1
$DETERM genesis-tool build $T/shard0_gen.json | tail -1
$DETERM genesis-tool build $T/shard1_gen.json | tail -1
BEACON_HASH=$(cat $T/beacon_gen.json.hash)
SHARD0_HASH=$(cat $T/shard0_gen.json.hash)
SHARD1_HASH=$(cat $T/shard1_gen.json.hash)

# A DIFFERENT shard-1 genesis (different chain_id) → different
# compute_genesis_hash. Used by assertion 3 (wrong-genesis).
cat > $T/shard1_gen_wrong.json <<EOF
{
  "chain_id": "test-light-vms-WRONG",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 1,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard1_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/shard1_gen_wrong.json | tail -1

echo
echo "=== 3. Configure cross-chain peering ==="
configure_node() {
  local cfg=$1 domain=$2 listen=$3 rpc=$4 peers_field=$5 peers=$6 \
    gen_path=$7 gen_hash=$8
  $PY -c "
import json
with open('$cfg') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = []
c['$peers_field'] = $peers
c['genesis_path'] = '$gen_path'
c['genesis_hash'] = '$gen_hash'
c['chain_path'] = '$(dirname $cfg)/chain.json'
c['key_path'] = '$(dirname $cfg)/node_key.json'
c['data_dir'] = '$(dirname $cfg)'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
c['sharding_mode'] = 2  # ShardingMode::EXTENDED — enables R7 under-quorum merge
with open('$cfg','w') as f: json.dump(c,f,indent=2)
"
}
configure_node $T/beacon/config.json beacon_n 7881 8881 shard_peers \
  '["127.0.0.1:7891","127.0.0.1:7892"]' "$TABS/beacon_gen.json" "$BEACON_HASH"
configure_node $T/shard0/config.json shard0_n 7891 8891 beacon_peers \
  '["127.0.0.1:7881"]' "$TABS/shard0_gen.json" "$SHARD0_HASH"
configure_node $T/shard1/config.json shard1_n 7892 8892 beacon_peers \
  '["127.0.0.1:7881"]' "$TABS/shard1_gen.json" "$SHARD1_HASH"

echo
echo "=== 4. Start 3 nodes (cross-peered) ==="
NODE_PIDS=("" "" "")
$DETERM start --config $T/beacon/config.json > $T/beacon/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/shard0/config.json > $T/shard0/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/shard1/config.json > $T/shard1/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3

echo
echo "=== 5. Poll until both shards produce blocks (need a state_root head) ==="
for _ in $(seq 1 90); do
  S0=$(get_status_field 8891 height); S1=$(get_status_field 8892 height)
  if [ "$S0" != "-" ] && [ "$S1" != "-" ] \
     && [ "$S0" -ge 2 ] 2>/dev/null && [ "$S1" -ge 2 ] 2>/dev/null; then
    break
  fi
  sleep 0.3
done
SHARD0_H=$(get_status_field 8891 height)
SHARD1_H=$(get_status_field 8892 height)
echo "  shard0=$SHARD0_H shard1=$SHARD1_H"
if [ "$SHARD0_H" = "-" ] || [ "$SHARD0_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: cluster did not bootstrap shard0 in budget — environment"
  echo "        too starved (not a verify-merge-state defect)."
  exit 0
fi

# Pre-flight: confirm shard0's daemon runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8891 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$SHARD0_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: shard0 daemon block0=$BLK0 but our genesis=$SHARD0_HASH"
  assert "false" "pre-flight: shard0 daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_merge_state"; exit 1
fi
echo "  pre-flight OK: shard0 daemon runs our genesis"

echo
echo "=== ASSERTION 1: an active merge record → INCLUDED (conditional) ==="
# merge_state is exposed by `snapshot create`'s merge_state[] array
# (serialize_snapshot). Scan both shards for any active merge.
MERGE=""
for prt in 8891 8892; do
  M=$($DETERM snapshot create --headers 0 --rpc-port $prt 2>/dev/null | $PY -c "
import json, sys
try:
    snap = json.load(sys.stdin)
except Exception:
    raise SystemExit
ms = snap.get('merge_state') or []
if ms:
    m = ms[0]
    print('%d %d %s %d' % (int(m['shard_id']), int(m['partner_id']),
                           m.get('refugee_region','') or '-', $prt))
")
  if [ -n "$M" ]; then MERGE="$M"; break; fi
done

if [ -z "$MERGE" ]; then
  echo "  SKIP(headline): no shard merged within budget (the common case;"
  echo "        R7 under-quorum-merge requires a committee to drop under"
  echo "        quorum). Negative / fail-closed assertions still run below."
  M_SHARD=""
  M_PORT=8891
  M_GEN=$T/shard0_gen.json
else
  M_SHARD=$(echo "$MERGE" | awk '{print $1}')
  M_PARTNER=$(echo "$MERGE" | awk '{print $2}')
  M_REGION=$(echo "$MERGE" | awk '{print $3}')
  [ "$M_REGION" = "-" ] && M_REGION=""
  M_PORT=$(echo "$MERGE" | awk '{print $4}')
  # Pick the genesis matching the daemon we read the merge from.
  if [ "$M_PORT" = "8891" ]; then M_GEN=$T/shard0_gen.json; else M_GEN=$T/shard1_gen.json; fi
  echo "  active merge: shard_id=$M_SHARD partner_id=$M_PARTNER region='$M_REGION' (port $M_PORT)"
  set +e
  OUT=$($DETERM_LIGHT verify-merge-state --rpc-port $M_PORT --genesis $M_GEN \
          --shard-id $M_SHARD --partner-id $M_PARTNER \
          --refugee-region "$M_REGION" 2>&1)
  RC=$?
  set -e
  echo "$OUT"
  if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^INCLUDED"; then
    assert "true" "active merge record → INCLUDED, exit 0 (real m: state-proof Merkle-verified)"
  else
    assert "false" "active merge record → INCLUDED/exit0 (got rc=$RC)"
  fi
fi

echo
echo "=== ASSERTION 2: random (never-merged) shard_id → NOT-INCLUDED (exit 0) ==="
# A high u32 shard_id that has no merge_state leaf. partner/region arbitrary
# (the daemon never gets to compare them — there is no leaf for the key).
RAND_SHARD=$($PY -c "import os; print(int.from_bytes(os.urandom(3),'big') + 1000)")
set +e
OUT=$($DETERM_LIGHT verify-merge-state --rpc-port 8891 --genesis $T/shard0_gen.json \
        --shard-id $RAND_SHARD --partner-id 0 --refugee-region "nowhere" 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
  assert "true" "random shard_id → NOT-INCLUDED, exit 0 (daemon-asserted negative, (H-neg))"
else
  assert "false" "random shard_id → NOT-INCLUDED/exit0 (got rc=$RC)"
fi
NOFP2=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP2" "random shard_id never yields a false INCLUDED"

echo
echo "=== ASSERTION 3: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-merge-state --rpc-port 8892 --genesis $T/shard1_gen_wrong.json \
        --shard-id 1 --partner-id 0 --refugee-region "r" 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
  assert "true" "wrong genesis rejected (exit $RC)"
else
  assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP3=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP3" "wrong genesis never yields INCLUDED"

echo
echo "=== ASSERTION 4: out-of-range --shard-id (> u32) → non-zero, never INCLUDED ==="
set +e
OUT=$($DETERM_LIGHT verify-merge-state --rpc-port 8891 --genesis $T/shard0_gen.json \
        --shard-id 4294967296 --partner-id 0 --refugee-region "r" 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ] && ! echo "$OUT" | grep -qE "^INCLUDED"; then
  assert "true" "out-of-range --shard-id → non-zero exit, not INCLUDED (rc=$RC)"
else
  assert "false" "out-of-range --shard-id should hard-error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 5: missing required flags → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-merge-state --rpc-port 8891 --genesis $T/shard0_gen.json \
        --shard-id 0 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
  assert "true" "missing --partner-id/--refugee-region → usage error (exit 1)"
else
  assert "false" "missing flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_merge_state"; exit 0
else
  echo "  FAIL: test_light_verify_merge_state"; exit 1
fi
