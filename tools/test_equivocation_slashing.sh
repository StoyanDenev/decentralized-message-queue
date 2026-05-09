#!/usr/bin/env bash
# B5 — equivocation slashing closed-loop test (synthesized evidence).
#
# Verifies the full path:
#   submit_equivocation RPC → on_equivocation_evidence (validates two
#   sigs against equivocator's registered pubkey + dedupes) → adds to
#   pending_equivocation_evidence_ → next block bakes equivocation_events
#   → apply_transactions zeroes stake + sets inactive_from.
#
# This is a synthesis test (we sign two digests with the validator's
# own key), not real equivocation observed in production. The on-chain
# semantics are identical: the protocol slashes anyone whose key signed
# two conflicting digests at the same height, regardless of whether the
# evidence came from gossip detection or external submission.
#
# Run from repo root: bash tools/test_equivocation_slashing.sh

set -u
cd "$(dirname "$0")/.."

DHCOIN=C:/sauromatae/build/Release/dhcoin.exe
T=test_equiv_slash
TABS=C:/sauromatae/$T

declare -a NODE_PIDS

cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T

echo "=== 1. Init validator node + 2 spectator nodes (M=K=3) ==="
# We need M >= 3 so a slashed validator drops below the K threshold and
# the chain can continue on the others. Validators node1, node2, node3.
for n in 1 2 3; do
  $DHCOIN init --data-dir $T/n$n --profile web 2>&1 | tail -1
  $DHCOIN genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 \
    > $T/p$n.json
done

echo
echo "=== 2. Build genesis with 3 creators ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-equiv-slash",
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
$DHCOIN genesis-tool build $T/gen.json | tail -1
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
c['delay_T'] = 200000
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
$DHCOIN start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DHCOIN start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DHCOIN start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3

echo
echo "=== 5. Wait 15s for chain to advance + grab a block_index for evidence ==="
sleep 15
HEIGHT_PRE=$($DHCOIN status --rpc-port 8771 2>/dev/null \
              | python -c "import sys,json; print(json.load(sys.stdin)['height'])")
echo "  chain height pre-submission: $HEIGHT_PRE"

# node1's stake before slash.
STAKE_PRE=$($DHCOIN stake_info node1 --rpc-port 8771 2>/dev/null \
             | python -c "import sys,json; print(json.load(sys.stdin).get('locked','-'))")
echo "  node1 stake pre-slash: $STAKE_PRE (expected 1000)"

echo
echo "=== 6. Synthesize EquivocationEvent (two sigs from node1 over distinct digests) ==="
python <<EOF
import hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

with open("$T/n1/node_key.json") as f:
    nk = json.load(f)
priv_seed = bytes.fromhex(nk["priv_seed"])
pubkey    = bytes.fromhex(nk["pubkey"])
pkey = Ed25519PrivateKey.from_private_bytes(priv_seed)

# Two distinct digests at the same (claimed) block_index. The
# protocol's only requirement is that the same key signed two
# different digests at the same height. We use 1 as a safely-past
# height; the chain has progressed beyond it.
digest_a = hashlib.sha256(b"forensic-evidence-A").digest()
digest_b = hashlib.sha256(b"forensic-evidence-B").digest()
sig_a = pkey.sign(digest_a)
sig_b = pkey.sign(digest_b)

ev = {
    "equivocator": "node1",
    "block_index": 1,
    "digest_a": digest_a.hex(),
    "sig_a":    sig_a.hex(),
    "digest_b": digest_b.hex(),
    "sig_b":    sig_b.hex(),
    "shard_id": 0,
    "beacon_anchor_height": 0,
}
with open("$T/ev.json","w") as f: json.dump(ev,f,indent=2)
print("event written:", "$T/ev.json")
print("  equivocator:", ev["equivocator"])
print("  digest_a:",   ev["digest_a"][:16], "...")
print("  digest_b:",   ev["digest_b"][:16], "...")
EOF

echo
echo "=== 7. Submit via RPC against any node (gossips to peers) ==="
EV_JSON=$(cat $T/ev.json | python -c "import sys,json; print(json.dumps(json.load(sys.stdin)))")
RESPONSE=$(python -c "
import socket, json
s = socket.create_connection(('127.0.0.1', 8772))
req = json.dumps({'method':'submit_equivocation','params':{'event': $EV_JSON}})
s.sendall((req + '\n').encode())
buf = b''
while b'\n' not in buf:
    chunk = s.recv(4096)
    if not chunk: break
    buf += chunk
print(buf.decode().strip())
")
echo "  RPC response: $RESPONSE"

echo
echo "=== 8. Poll up to 60s for evidence to be baked into a block + applied ==="
# Budget: after slash, node1 is deregistered → pool drops below K → BFT
# escalation kicks in (ceil(2K/3) sigs) after threshold round-1 aborts
# (~10s @ 2s rounds). Extra slack for the second post-slash block to
# settle, plus margin for K-of-K agreement on pending_equivocation
# pool (different pools across producers cause round retries until
# gossip converges).
STAKE_POST="-"
HEIGHT_POST="$HEIGHT_PRE"
for attempt in $(seq 1 30); do
  sleep 2
  STAKE_POST=$($DHCOIN stake_info node1 --rpc-port 8771 2>/dev/null \
                | python -c "import sys,json; print(json.load(sys.stdin).get('locked','-'))")
  HEIGHT_POST=$($DHCOIN status --rpc-port 8771 2>/dev/null \
                 | python -c "import sys,json; print(json.load(sys.stdin)['height'])")
  if [ "$STAKE_POST" = "0" ]; then
    echo "  slashed after attempt $attempt (height=$HEIGHT_POST)"
    break
  fi
done

echo
echo "=== 9. Verify ==="
echo "  chain height post: $HEIGHT_POST"
echo "  node1 stake post-slash: $STAKE_POST (expected 0)"

# Find the block containing the equivocation event (between HEIGHT_PRE+1
# and HEIGHT_POST). The first block after submission that bakes the
# event is the slashing block.
EQUIV_BLOCK=""
for ((i = HEIGHT_PRE; i <= HEIGHT_POST; i++)); do
  HAS_EV=$($DHCOIN show-block $i --rpc-port 8771 2>/dev/null \
            | python -c "import sys,json
b = json.load(sys.stdin)
print('y' if b.get('equivocation_events') else 'n')" 2>/dev/null)
  if [ "$HAS_EV" = "y" ]; then EQUIV_BLOCK=$i; break; fi
done

PASS=true
if [ -z "$EQUIV_BLOCK" ]; then
  echo "  FAIL: no block in [$HEIGHT_PRE..$HEIGHT_POST] contains an equivocation event"
  PASS=false
else
  echo "  block #$EQUIV_BLOCK contains equivocation_events"
fi

if [ "$STAKE_POST" != "0" ]; then
  echo "  FAIL: node1 stake didn't go to 0 (still $STAKE_POST)"
  PASS=false
fi

if $PASS; then
  echo
  echo "  PASS: equivocation slashing closed-loop"
  echo "        - submit_equivocation RPC accepted synthesized evidence"
  echo "        - evidence baked into block #$EQUIV_BLOCK"
  echo "        - node1's stake forfeited (0) on apply"
fi

echo
echo "=== 10. Tail of n1 log ==="
grep -E "equivocation|adopted|accepted block|epoch" $T/n1/log | tail -8
