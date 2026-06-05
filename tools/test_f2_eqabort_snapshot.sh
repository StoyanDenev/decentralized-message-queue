#!/usr/bin/env bash
# v2.7 F2 / S-030-D2 — equivocation/abort evidence survives snapshot bootstrap.
#
# Closes the S-037-class coverage gap the adversarial review of 48c4b45 flagged:
# the code round-trips the new per-creator creator_view_eq_lists /
# creator_view_abort_lists through Block::to_json / from_json + restore_from_snapshot
# (verified by inspection), but NO test exercised snapshot bootstrap on a chain
# that actually carries F2 equivocation/abort evidence. The S-037 dapp_registry
# bug shipped silently for exactly this reason (correct code, disjoint tests), so
# this test joins the two surfaces.
#
# Flow (mirrors test_dapp_snapshot.sh, with equivocation in place of DAPP_REGISTER):
#   1. 3-node donor chain (M=K=3, F2 active from genesis) advances.
#   2. A synthesized equivocation is submitted to all donors -> baked into a block
#      (the block carries reconciled equivocation_events + the per-creator eq view
#      lists) -> apply slashes the equivocator's stake to 0.
#   3. Snapshot donor1; freeze its state_root + head_hash from the snapshot file.
#   4. Stop donors; boot a bare receiver (snapshot_path only, no genesis, no peers).
#   5. Assert the receiver boots with NO "state_root mismatch" (the S-033 gate
#      passes -> the eq-bearing tail blocks + slashed state restored coherently),
#      its state_root EXACTLY matches the snapshot's, and the slash (stake 0)
#      survived the restore.
#
# Run from repo root: bash tools/test_f2_eqabort_snapshot.sh

set -u
cd "$(dirname "$0")/.."
source tools/common.sh
T=test_f2_eqabort_snap
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

rm -rf $T; mkdir -p $T/donor1 $T/donor2 $T/donor3 $T/receiver

echo "=== 1. Init 3 donor nodes + receiver data dir ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/donor$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info donor$n --data-dir $T/donor$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-f2-eqabort-snap",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

echo
echo "=== 2. Configure 3 donor nodes ==="
configure_donor() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/donor$n/config.json') as f: c = json.load(f)
c['domain'] = 'donor$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/donor$n/chain.json'
c['key_path'] = '$TABS/donor$n/node_key.json'
c['data_dir'] = '$TABS/donor$n'
c['tx_commit_ms'] = 1000
c['block_sig_ms'] = 1000
c['abort_claim_ms'] = 500
with open('$T/donor$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_donor 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_donor 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_donor 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 3. Start 3 donors + wait for chain to advance (height >= 3) ==="
NODE_PIDS=("" "" "" "")
$DETERM start --config $T/donor1/config.json > $T/donor1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/donor2/config.json > $T/donor2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/donor3/config.json > $T/donor3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3
for _ in $(seq 1 80); do
  DH=$($DETERM status --rpc-port 8771 2>/dev/null \
        | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$DH" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.3
done
echo "  donor chain height: $DH"

echo
echo "=== 4. Synthesize + submit an EquivocationEvent for donor1 to all donors ==="
python <<EOF
import hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
with open("$T/donor1/node_key.json") as f: nk = json.load(f)
pkey = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(nk["priv_seed"]))
da = hashlib.sha256(b"snap-eqabort-A").digest(); db = hashlib.sha256(b"snap-eqabort-B").digest()
ev = {"equivocator":"donor1","block_index":1,"digest_a":da.hex(),"sig_a":pkey.sign(da).hex(),
      "digest_b":db.hex(),"sig_b":pkey.sign(db).hex(),"shard_id":0,"beacon_anchor_height":0}
json.dump(ev, open("$T/ev.json","w"))
print("  synthesized equivocation for donor1")
EOF
EV_JSON=$(cat $T/ev.json | python -c "import sys,json; print(json.dumps(json.load(sys.stdin)))")
for port in 8771 8772 8773; do
  python -c "
import socket, json
s = socket.create_connection(('127.0.0.1', $port))
s.sendall((json.dumps({'method':'submit_equivocation','params':{'event': $EV_JSON}})+'\n').encode())
buf=b''
while b'\n' not in buf:
    ch=s.recv(4096)
    if not ch: break
    buf+=ch
print('  submit(port $port):', buf.decode().strip())
"
done

echo
echo "=== 5. Wait for the equivocation to be baked + slashed (donor1 stake -> 0) ==="
DSTAKE="-"
for _ in $(seq 1 120); do
  sleep 0.5
  DSTAKE=$($DETERM stake_info donor1 --rpc-port 8771 2>/dev/null \
            | python -c "import sys,json; print(json.load(sys.stdin).get('locked','-'))" 2>/dev/null)
  if [ "$DSTAKE" = "0" ]; then break; fi
done
echo "  donor1 stake post-slash: $DSTAKE (expected 0)"
[ "$DSTAKE" = "0" ] && assert true "donor: F2 equivocation reconciled + slashed (stake 0)" \
  || assert false "donor: equivocation not slashed under F2 (stake=$DSTAKE)"

echo
echo "=== 6. Create snapshot from donor1; freeze state_root + head_hash ==="
$DETERM snapshot create --out $T/snap.json --rpc-port 8771 2>&1 | tail -2
SNAP_HEAD=$(python -c "
import json
try: print(json.load(open('$T/snap.json'))['head_hash'])
except: print('')")
SNAP_SR=$(python -c "
import json
try:
    s = json.load(open('$T/snap.json')); hdrs = s.get('headers', [])
    print(hdrs[-1].get('state_root','') if hdrs else '')
except: print('')")
echo "  snapshot head_hash:  ${SNAP_HEAD:0:24}..."
echo "  snapshot state_root: ${SNAP_SR:0:24}..."
ZERO="0000000000000000000000000000000000000000000000000000000000000000"
[ -n "$SNAP_SR" ] && [ "$SNAP_SR" != "$ZERO" ] \
  && assert true "snapshot tail head state_root populated (S-038)" \
  || assert false "snapshot head state_root empty/zero (S-038 regression)"

echo
echo "=== 7. Stop donors so receiver bootstraps from snapshot ALONE ==="
for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
sleep 2

echo
echo "=== 8. Configure + start bare receiver (snapshot_path only) ==="
$DETERM init --data-dir $T/receiver --profile single_test 2>&1 | tail -1
python -c "
import json
with open('$T/receiver/config.json') as f: c = json.load(f)
c['domain'] = 'receiver_n'
c['listen_port'] = 7799
c['rpc_port'] = 8799
c['bootstrap_peers'] = []
c['genesis_path'] = ''
c['genesis_hash'] = ''
c['chain_path'] = '$TABS/receiver/chain.json'
c['snapshot_path'] = '$TABS/snap.json'
c['key_path'] = '$TABS/receiver/node_key.json'
c['data_dir'] = '$TABS/receiver'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/receiver/config.json','w') as f: json.dump(c,f,indent=2)
"
NODE_PIDS=("")
$DETERM start --config $T/receiver/config.json > $T/receiver/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
for _ in $(seq 1 60); do
  RH=$($DETERM status --rpc-port 8799 2>/dev/null \
        | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash',''))
except: print('')")
  if [ -n "$RH" ]; then break; fi
  sleep 0.3
done

if [ -z "$RH" ]; then
  echo "  receiver log tail:"; tail -20 $T/receiver/log
  assert false "receiver booted from eq/abort-bearing snapshot (head_hash populated)"
else
  assert true "receiver booted from eq/abort-bearing snapshot (head_hash populated, S-033 gate passed)"
fi
if grep -q "state_root mismatch" $T/receiver/log 2>/dev/null; then
  grep "state_root mismatch" $T/receiver/log
  assert false "no state_root mismatch in receiver log"
else
  assert true "no state_root mismatch in receiver log"
fi

echo
echo "=== 9. Verify receiver state_root + head_hash match the frozen snapshot ==="
RECV_SR_JSON=$($DETERM state-root --rpc-port 8799 2>/dev/null)
RECV_SR=$(echo "$RECV_SR_JSON" | python -c "import sys,json; print(json.load(sys.stdin)['state_root'])" 2>/dev/null || echo "")
RECV_HEAD=$(echo "$RECV_SR_JSON" | python -c "import sys,json; print(json.load(sys.stdin)['head_hash'])" 2>/dev/null || echo "")
echo "  receiver state_root: ${RECV_SR:0:24}..."
echo "  receiver head_hash:  ${RECV_HEAD:0:24}..."
[ -n "$RECV_HEAD" ] && [ "$RECV_HEAD" = "$SNAP_HEAD" ] \
  && assert true "receiver head_hash matches snapshot (eq-bearing tail block round-tripped)" \
  || assert false "receiver head_hash mismatch (recv=${RECV_HEAD:0:24}, snap=${SNAP_HEAD:0:24})"
[ -n "$RECV_SR" ] && [ "$RECV_SR" = "$SNAP_SR" ] \
  && assert true "receiver state_root EXACTLY matches snapshot (S-033 gate over the post-slash state)" \
  || assert false "receiver state_root mismatch (recv=${RECV_SR:0:24}, snap=${SNAP_SR:0:24})"

echo
echo "=== 10. Verify the slash survived the restore (donor1 stake == 0 on receiver) ==="
RECV_STAKE=$($DETERM stake_info donor1 --rpc-port 8799 2>/dev/null \
              | python -c "import sys,json; print(json.load(sys.stdin).get('locked','-'))" 2>/dev/null || echo "-")
echo "  receiver: donor1 stake = $RECV_STAKE (expected 0)"
[ "$RECV_STAKE" = "0" ] \
  && assert true "receiver: slashed stake (donor1=0) survived snapshot restore" \
  || assert false "receiver: donor1 stake '$RECV_STAKE' (expected 0) — eq evidence did not restore coherently"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: F2 equivocation/abort evidence survives snapshot bootstrap"
  exit 0
else
  echo "  FAIL: F2 eq/abort snapshot regression"
  exit 1
fi
