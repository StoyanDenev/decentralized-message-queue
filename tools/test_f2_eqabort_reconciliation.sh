#!/usr/bin/env bash
# v2.7 F2 / S-030-D2 — equivocation/abort view-reconciliation regression test.
#
# Exercises the LIVE F2 eq/abort dimension (gate active from genesis): each
# committee member commits its equivocation/abort pool view into its Phase-1
# commit (node.cpp start_contrib_phase); build_body reconciles the committee-wide
# UNION and bakes the subset it can materialize; compute_block_digest binds the
# reconciled set; the validator (check_eqabort_reconciliation) authenticates the
# carried per-creator lists against their committed roots and enforces that the
# block's evidence is a subset of the union.
#
# The load-bearing assertion is (A) below: NO node ever logs
# "invalid block: F2:". That guards the zero-root regression class — an F2-active
# block whose creators committed all-empty views carries zero (v1-sentinel) roots,
# and the validator must treat a zero root as "no view" rather than recomputing
# compute_view_root({}) (the non-zero empty-SHA-256) and spuriously rejecting.
# A regression there stalls every shard whose blocks carry no evidence (the
# common case), which is exactly how this surfaced during development.
#
# Run from repo root: bash tools/test_f2_eqabort_reconciliation.sh

set -u
cd "$(dirname "$0")/.."
source tools/common.sh
T=test_f2_eqabort
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT

rm -rf $T; mkdir -p $T
PASS=true

echo "=== 1. Init 3 validator nodes (M=K=3) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build genesis (F2 active from genesis: v2_7_f2_active_from_height = 0 default) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-f2-eqabort",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GEN_HASH=$(cat $T/gen.json.hash)

echo
echo "=== 3. Configure 3-mesh ==="
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GEN_HASH'
c['chain_path'] = '$TABS/n$n/chain.json'
c['key_path'] = '$TABS/n$n/node_key.json'
c['data_dir'] = '$TABS/n$n'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 4. Start 3 nodes ==="
NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3

echo
echo "=== 5. Let the chain advance to height >= 3 on plain (no-evidence) F2 blocks ==="
# These blocks carry all-empty eq/abort views (zero v1-sentinel roots). If the
# validator mishandled the zero root, production would stall here at height 1.
HEIGHT=0
for _ in $(seq 1 120); do
  HEIGHT=$($DETERM status --rpc-port 8771 2>/dev/null \
            | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$HEIGHT" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.25
done
echo "  chain height after plain F2 blocks: $HEIGHT (expected >= 3)"
if [ "$HEIGHT" -lt 3 ] 2>/dev/null; then
  echo "  FAIL: chain did not advance on plain F2 blocks (possible zero-root regression)"
  PASS=false
fi

echo
echo "=== 6. Synthesize + submit an EquivocationEvent to all nodes ==="
python <<EOF
import hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
with open("$T/n1/node_key.json") as f: nk = json.load(f)
pkey = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(nk["priv_seed"]))
da = hashlib.sha256(b"f2-eqabort-A").digest(); db = hashlib.sha256(b"f2-eqabort-B").digest()
ev = {"equivocator":"node1","block_index":1,"digest_a":da.hex(),"sig_a":pkey.sign(da).hex(),
      "digest_b":db.hex(),"sig_b":pkey.sign(db).hex(),"shard_id":0,"beacon_anchor_height":0}
with open("$T/ev.json","w") as f: json.dump(ev,f)
print("  synthesized equivocation for node1")
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
echo "=== 7. Poll up to 60s for the equivocation to be baked + slashed under F2 ==="
STAKE_POST="-"; HEIGHT_POST="$HEIGHT"
for attempt in $(seq 1 120); do
  sleep 0.5
  STAKE_POST=$($DETERM stake_info node1 --rpc-port 8771 2>/dev/null \
                | python -c "import sys,json; print(json.load(sys.stdin).get('locked','-'))" 2>/dev/null)
  HEIGHT_POST=$($DETERM status --rpc-port 8771 2>/dev/null \
                 | python -c "import sys,json; print(json.load(sys.stdin).get('height','?'))" 2>/dev/null)
  if [ "$STAKE_POST" = "0" ]; then echo "  slashed after attempt $attempt (height=$HEIGHT_POST)"; break; fi
done
echo "  node1 stake post: $STAKE_POST (expected 0)"
[ "$STAKE_POST" = "0" ] || { echo "  FAIL: equivocation not slashed under F2 (stake=$STAKE_POST)"; PASS=false; }

echo
echo "=== 8. (A) Assert NO node ever rejected a block with 'invalid block: F2:' ==="
F2_REJECTS=$(grep -hcE 'invalid block: F2:' $T/n1/log $T/n2/log $T/n3/log 2>/dev/null | paste -sd+ | bc 2>/dev/null)
F2_REJECTS=${F2_REJECTS:-0}
echo "  total 'invalid block: F2:' across all node logs: $F2_REJECTS (expected 0)"
if [ "$F2_REJECTS" != "0" ]; then
  echo "  FAIL: a node rejected an F2 block — eq/abort reconciliation regression"
  grep -hE 'invalid block: F2:' $T/n1/log $T/n2/log $T/n3/log 2>/dev/null | sort -u | head
  PASS=false
fi

echo
echo "=== 9. (B) Assert the equivocation landed in a block ==="
EQUIV_BLOCK=""
for ((i = HEIGHT; i <= HEIGHT_POST; i++)); do
  HAS=$($DETERM show-block $i --rpc-port 8771 2>/dev/null \
         | python -c "import sys,json
try: print('y' if json.load(sys.stdin).get('equivocation_events') else 'n')
except: print('n')" 2>/dev/null)
  if [ "$HAS" = "y" ]; then EQUIV_BLOCK=$i; break; fi
done
if [ -n "$EQUIV_BLOCK" ]; then
  echo "  block #$EQUIV_BLOCK carries equivocation_events (reconciled + digest-bound)"
else
  echo "  FAIL: no block in [$HEIGHT..$HEIGHT_POST] carries an equivocation event"
  PASS=false
fi

echo
if $PASS; then
  # Detail lines ABOVE the terminal marker; explicit exit 0 so the marker is
  # the final output line (run_all.sh greps the last 10 lines for ^\s*PASS:).
  echo "  ok: plain F2 blocks (zero-root views) accepted (no stall)"
  echo "  ok: equivocation reconciled into block #$EQUIV_BLOCK + slashed"
  echo "  ok: zero 'invalid block: F2:' rejections across the committee"
  echo "  PASS: test_f2_eqabort_reconciliation"
  exit 0
else
  echo "  FAIL: test_f2_eqabort_reconciliation"
  exit 1
fi
