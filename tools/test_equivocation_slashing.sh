#!/usr/bin/env bash
# B5 — equivocation evidence closed-loop test (synthesized evidence).
#
# Verifies the full path:
#   submit_equivocation RPC → on_equivocation_evidence (validates two
#   sigs against equivocator's registered pubkey + dedupes) → adds to
#   pending_equivocation_evidence_ → next block bakes equivocation_events
#   → apply_transactions records NOTHING from it (D4, owner decision
#   2026-09-16: an EquivocationEvent is an on-chain evidence record with no
#   L1 stake or registry consequence) — node1 keeps its stake and its
#   registry entry, and the chain keeps producing with node1 in it.
#
# This is a synthesis test (we sign two digests with the validator's
# own key), not real equivocation observed in production. The on-chain
# semantics are identical whether the evidence came from gossip detection
# or external submission. (File name kept for the record's references.)
#
# Run from repo root: bash tools/test_equivocation_slashing.sh

set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_equiv_slash
TABS=$PROJECT_ROOT/$T

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
# M = K = 3 validators node1, node2, node3: the evidence targets node1 and,
# under D4, node1 stays in the committee — every later block still carries
# all three creators.
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 \
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
echo "=== 5. Poll until chain advances (height >= 3) ==="
for _ in $(seq 1 50); do
  HEIGHT_PRE=$($DETERM status --rpc-port 8771 2>/dev/null \
                | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$HEIGHT_PRE" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.2
done
HEIGHT_PRE=$($DETERM status --rpc-port 8771 2>/dev/null \
              | python -c "import sys,json; print(json.load(sys.stdin)['height'])")
echo "  chain height pre-submission: $HEIGHT_PRE"

# node1's stake before the evidence lands (must be unchanged afterwards).
STAKE_PRE=$($DETERM stake_info node1 --rpc-port 8771 2>/dev/null \
             | python -c "import sys,json; print(json.load(sys.stdin).get('locked','-'))")
echo "  node1 stake pre-submission: $STAKE_PRE (expected 1000)"

echo
echo "=== 6. Synthesize EquivocationEvent (two sigs from node1 over distinct digests) ==="
python <<EOF
import hashlib, json
# Ed25519 backend: prefer the cryptography module, fall back to PyNaCl (the
# Darwin runner ships pynacl only). Both wrap the same RFC 8032 primitive.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    def _signer(seed):
        k = Ed25519PrivateKey.from_private_bytes(seed)
        return lambda m: k.sign(m)
except ModuleNotFoundError:
    from nacl.signing import SigningKey
    def _signer(seed):
        k = SigningKey(seed)
        return lambda m: k.sign(m).signature

with open("$T/n1/node_key.json") as f:
    nk = json.load(f)
priv_seed = bytes.fromhex(nk["priv_seed"])
pubkey    = bytes.fromhex(nk["pubkey"])
sign = _signer(priv_seed)

# EQV-height-bind + EQV-gen-bind: the evidence carries per-side OPENINGS
# (index, gen, body_root) of two-level digests; the verifier derives each
# signed digest as
#   SHA256("DTM-BLKDIG-v3" || index u64 BE || gen u64 BE || body_root)  (kind 0)
# and asserts index_a == index_b == block_index AND gen_a == gen_b.
# Synthesize two distinct body roots at ONE height (1 — safely past; the chain
# has progressed beyond it) in ONE round generation, compose, and sign the
# DERIVED digests.
body_root_a = hashlib.sha256(b"forensic-evidence-A").digest()
body_root_b = hashlib.sha256(b"forensic-evidence-B").digest()
GEN = 0
def compose(index, gen, root):
    return hashlib.sha256(b"DTM-BLKDIG-v3" + index.to_bytes(8, "big")
                          + gen.to_bytes(8, "big") + root).digest()
sig_a = sign(compose(1, GEN, body_root_a))
sig_b = sign(compose(1, GEN, body_root_b))

ev = {
    "equivocator": "node1",
    "block_index": 1,
    "kind": 0,
    "index_a": 1,
    "gen_a": GEN,
    "body_root_a": body_root_a.hex(),
    "sig_a":       sig_a.hex(),
    "index_b": 1,
    "gen_b": GEN,
    "body_root_b": body_root_b.hex(),
    "sig_b":       sig_b.hex(),
    "shard_id": 0,
    "beacon_anchor_height": 0,
}
with open("$T/ev.json","w") as f: json.dump(ev,f,indent=2)
print("event written:", "$T/ev.json")
print("  equivocator:", ev["equivocator"])
print("  body_root_a:", ev["body_root_a"][:16], "...")
print("  body_root_b:", ev["body_root_b"][:16], "...")
EOF

echo
echo "=== 7. Submit via RPC against ALL nodes (avoids gossip-latency race) ==="
# The chain advances at ~5 blocks/sec under K=M=3 single_test profile (round
# timers don't fire because K contribs arrive ~instantly on loopback). If
# evidence is submitted to ONE node and then gossiped to peers, the peers
# may have already finalized several blocks past the evidence before the
# gossip arrives — and once a peer's chain_.height() is past the new
# block's index, the evidence block is dropped as a dup (apply_block_locked
# L1710 dup-skip). The result: a real consensus fork — submitting node has
# the evidence block, peers don't. v2.7 F2 closes this at the consensus
# layer by binding each member's pending-equivocation-evidence view into
# their Phase-1 commit. Until F2 ships, the test sidesteps the race by
# submitting evidence to ALL nodes simultaneously, ensuring every node has
# it in their local pool before the next finalize.
EV_JSON=$(cat $T/ev.json | python -c "import sys,json; print(json.dumps(json.load(sys.stdin)))")
for port in 8771 8772 8773; do
  RESPONSE=$(python -c "
import socket, json
s = socket.create_connection(('127.0.0.1', $port))
req = json.dumps({'method':'submit_equivocation','params':{'event': $EV_JSON}})
s.sendall((req + '\n').encode())
buf = b''
while b'\n' not in buf:
    chunk = s.recv(4096)
    if not chunk: break
    buf += chunk
print(buf.decode().strip())
")
  echo "  RPC response (port $port): $RESPONSE"
done

echo
echo "=== 8. Poll up to 60s for the evidence to be baked into a block ==="
# Budget: K-of-K agreement on the pending_equivocation pool (different
# pools across producers cause round retries until gossip converges),
# then one more block so the post-evidence state is observable.
HEIGHT_POST="$HEIGHT_PRE"
EQUIV_BLOCK=""
for attempt in $(seq 1 120); do
  sleep 0.5
  HEIGHT_POST=$($DETERM status --rpc-port 8771 2>/dev/null \
                 | python -c "import sys,json; print(json.load(sys.stdin)['height'])")
  for ((i = HEIGHT_PRE; i < HEIGHT_POST; i++)); do
    HAS_EV=$($DETERM show-block $i --rpc-port 8771 2>/dev/null \
              | python -c "import sys,json
b = json.load(sys.stdin)
print('y' if b.get('equivocation_events') else 'n')" 2>/dev/null)
    if [ "$HAS_EV" = "y" ]; then EQUIV_BLOCK=$i; break; fi
  done
  if [ -n "$EQUIV_BLOCK" ] && [ "$HEIGHT_POST" -gt "$((EQUIV_BLOCK + 1))" ]; then
    echo "  evidence baked in block #$EQUIV_BLOCK after attempt $attempt (height=$HEIGHT_POST)"
    break
  fi
done
STAKE_POST=$($DETERM stake_info node1 --rpc-port 8771 2>/dev/null \
              | python -c "import sys,json; print(json.load(sys.stdin).get('locked','-'))")
# The only L1 stake movement that CAN happen to node1 in the window is a
# Phase-1 abort deduction (SUSPENSION_SLASH per round-1 AbortEvent against it);
# count those so the equality below is exact, not a flake.
ABORTS_N1=0
for ((i = HEIGHT_PRE; i < HEIGHT_POST; i++)); do
  N=$($DETERM show-block $i --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
b = json.load(sys.stdin)
print(sum(1 for a in (b.get('abort_events') or []) if a.get('aborting_node') == 'node1' and a.get('round') == 1))" 2>/dev/null)
  ABORTS_N1=$((ABORTS_N1 + ${N:-0}))
done
# suspension_slash from the genesis file this run built ($T/gen.json omits it,
# so the GenesisConfig default 10 applies).
SUSP=$(python -c "import json; print(json.load(open('$T/gen.json')).get('suspension_slash', 10))")
case "$STAKE_PRE" in
  ''|*[!0-9]*) echo "  bad: node1 stake pre-submission unreadable ('$STAKE_PRE')"; STAKE_PRE=0 ;;
esac
EXPECTED_STAKE=$((STAKE_PRE - ABORTS_N1 * SUSP))
# The block after the evidence block must still list node1 as a creator (it
# was neither deregistered nor made ineligible).
POST_CREATORS="-"
if [ -n "$EQUIV_BLOCK" ]; then
  POST_CREATORS=$($DETERM show-block $((EQUIV_BLOCK + 1)) --rpc-port 8771 2>/dev/null \
                   | python -c "import sys,json; print(','.join(json.load(sys.stdin).get('creators', [])))" 2>/dev/null)
fi
# The registry entry via show-account --json (registry.inactive_from stays at
# the UINT64_MAX sentinel while the domain is registered).
REG_POST=$($DETERM show-account node1 --rpc-port 8771 --json 2>/dev/null \
            | python -c "import sys,json
try:
    r = json.load(sys.stdin).get('registry')
    print('active' if r and r.get('inactive_from') == 18446744073709551615 else 'inactive')
except Exception: print('unknown')")

echo
echo "=== 9. Tail of n1 log ==="
# Diagnostics print ABOVE the verdict; raw node-log lines are prefixed
# so they can never collide with run_all.sh's ^\s*PASS:/^\s*FAIL: grep
# over the last 10 output lines.
grep -E "equivocation|adopted|accepted block|epoch" $T/n1/log 2>/dev/null \
  | tail -8 | sed 's/^/    | /'

echo
echo "=== 10. Verify ==="
echo "  chain height post: $HEIGHT_POST"
echo "  node1 stake post-evidence: $STAKE_POST (expected $EXPECTED_STAKE: pre $STAKE_PRE minus $ABORTS_N1 abort deduction(s); the evidence itself moves nothing)"
echo "  node1 registry post-evidence: $REG_POST (expected active)"
echo "  creators of block #$((${EQUIV_BLOCK:-0} + 1)): $POST_CREATORS (must include node1)"

FAILS=0
if [ -z "$EQUIV_BLOCK" ]; then
  echo "  bad: no block in [$HEIGHT_PRE..$HEIGHT_POST) contains an equivocation event"
  FAILS=$((FAILS+1))
else
  echo "  ok:  block #$EQUIV_BLOCK contains equivocation_events"
fi

if [ "$STAKE_POST" != "$EXPECTED_STAKE" ]; then
  echo "  bad: node1 stake moved on evidence ($STAKE_PRE -> $STAKE_POST, expected $EXPECTED_STAKE); D4 forbids any L1 consequence"
  FAILS=$((FAILS+1))
fi

case ",$POST_CREATORS," in
  *,node1,*) ;;
  *) echo "  bad: node1 is not a creator of the block after the evidence block ($POST_CREATORS)"; FAILS=$((FAILS+1)) ;;
esac

if [ "$REG_POST" != "active" ]; then
  echo "  bad: node1 registry entry not active after evidence ($REG_POST)"
  FAILS=$((FAILS+1))
fi

if [ -n "$EQUIV_BLOCK" ] && [ "$HEIGHT_POST" -le "$((EQUIV_BLOCK + 1))" ]; then
  echo "  bad: chain did not advance past the evidence block (height $HEIGHT_POST)"
  FAILS=$((FAILS+1))
fi

if [ "$FAILS" -eq 0 ]; then
  echo "  ok:  submit_equivocation RPC accepted synthesized evidence"
  echo "  ok:  evidence baked into block #$EQUIV_BLOCK"
  echo "  ok:  node1's stake and registry entry unchanged on apply (D4)"
  echo "  ok:  block #$((EQUIV_BLOCK + 1)) still lists node1 as a creator (chain kept producing with node1 in the committee)"
  echo "  PASS: test_equivocation_slashing"
  exit 0
else
  echo "  FAIL: test_equivocation_slashing ($FAILS checks failed)"
  exit 1
fi
