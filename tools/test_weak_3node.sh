#!/usr/bin/env bash
# Minimal weak-mode test: M=5 pool, K=3 committee (single shard, SHARD+CURRENT).
# Genesis pins epoch_blocks=1 so each round re-derives the 3-of-5 committee
# from cumulative_rand (rev.9 B1 epoch-stable seed; the genesis default
# epoch_blocks=1000 would hold ONE committee for the whole run).
# tx_root = union of the K=3 lists (src/node/node.cpp).
#
# Why K=3, not the historical K=2: K=2 committees wedge under ordinary
# timing skew — the abort-claim quorum at K=2 is K-1 = 1, so any single
# phase straggle abort-excludes a member with ONE claim; the resulting
# aborts_gen desync drops contribs and cascades further single-claim
# aborts (aborts clear only on block accept) until the pool falls below
# K and the chain halts permanently. Observed live in this test's K=2
# forms (M=3 AND M=4) even at 2000ms timers; BFT escalation cannot
# rescue because k_bft = ceil(2K/3) = 2 = K. Tracked in SECURITY.md
# (S-044). At K=3 the quorum is 2 claims, so a single straggle cannot
# exclude anyone. K=3-of-5 keeps this test's posture distinct from
# test_weak_mode.sh's K=3-of-4.
#
# Run from repo root: bash tools/test_weak_3node.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_weak3

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

get_height() {
  $DETERM status --rpc-port "$1" 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}
get_head() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash','?'))
except: print('?')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3 $T/n4 $T/n5

echo "=== Init 5 nodes (regional_test profile: SHARD+CURRENT) ==="
# regional_test boots a 1-shard genesis. The old `web` profile pins
# sharding_mode=EXTENDED into config.json, and the A6 startup gate rejects
# EXTENDED without initial_shard_count >= 3 — every node would FATAL at boot.
# Genesis m_creators=5 / k_block_sigs=3 override the profile's M=5/K=4, so
# the 3-of-5 weak-mode posture is pinned exactly.
for n in 1 2 3 4 5; do
  $DETERM init --data-dir $T/n$n --profile regional_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== Build genesis (M_pool=5, K_committee=3 weak BFT) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-weak-3node",
  "m_creators": 5,
  "k_block_sigs": 3,
  "epoch_blocks": 1,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n'),
$(cat $T/p4.json | tr -d '\n'),
$(cat $T/p5.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000000}]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="$PROJECT_ROOT/$T/gen.json"

echo
echo "=== Configure 3-mesh ==="
configure_node() {
  local n=$1 domain=$2 listen=$3 rpc=$4 peers_json=$5
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers_json
c['genesis_path'] = '$GPATH'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/n$n'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
print(f'  n$n: $domain listen=$listen rpc=$rpc')
"
}
configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773","127.0.0.1:7774","127.0.0.1:7775"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773","127.0.0.1:7774","127.0.0.1:7775"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7774","127.0.0.1:7775"]'
configure_node 4 node4 7774 8774 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7773","127.0.0.1:7775"]'
configure_node 5 node5 7775 8775 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7773","127.0.0.1:7774"]'

echo
echo "=== Start 5 nodes ==="
NODE_PIDS=("" "" "" "" "")
for n in 1 2 3 4 5; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  echo "  n$n: pid ${NODE_PIDS[$((n-1))]}"
  sleep 0.3
done

echo
echo "=== Wait for height >= 5 (poll, ceiling ~120s) ==="
# Rounds early-advance the moment all K SELECTED contribs arrive
# (node.cpp: pending_contribs_.size() == current_creator_domains_.size()),
# so a healthy K<M chain produces ~1 block/s here. The generous ceiling
# absorbs abort-churn rounds (a straggle costs a full timer window plus
# re-selection). Poll instead of a fixed sleep so the assertion bar
# (>=3 post-genesis blocks) is met deterministically or fails loudly.
for i in $(seq 1 120); do
  H=$(get_height 8771)
  if [[ "$H" =~ ^[0-9]+$ ]] && [ "$H" -ge 5 ]; then
    echo "  height $H reached after ~${i}s"
    break
  fi
  sleep 1
done

FAILS=0

echo
echo "=== Status (per-node liveness via RPC) ==="
# Liveness is asserted from each node's RPC height, NOT from log greps:
# determ's log lines are partially stdio-buffered when stdout is redirected
# to a file, so a quiet run can grep 0 "accepted block" lines while the
# chain has demonstrably advanced (content flushes only at exit). RPC
# height is the authoritative liveness signal.
for n in 1 2 3 4 5; do
  H=$(get_height 877$n)
  HEAD=$(get_head 877$n)
  echo "  n$n: height=$H head=${HEAD:0:16}..."
  if [[ ! "$H" =~ ^[0-9]+$ ]] || [ "$H" -lt 2 ]; then
    echo "  bad: n$n height '$H' is not numeric >= 2 (dead RPC or no blocks)"
    FAILS=$((FAILS+1))
  fi
done

echo
echo "=== Consistency ==="
# The chain produces ~1 block/s in this posture, so sequential RPC fetches
# can straddle a block boundary (in-flight sampling skew, not divergence).
# Resample up to 5 times; a genuinely forked cluster never agrees on any
# sample and still FAILs. The '?' dead-RPC sentinel is rejected outright
# (five dead nodes must not "agree" on '?').
AGREED=false
for attempt in 1 2 3 4 5; do
  HEAD1=$(get_head 8771)
  if [[ ! "$HEAD1" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "  bad: n1 head_hash is not 64 hex chars (got '$HEAD1' — dead RPC?)"
    break
  fi
  SAME=true
  for n in 2 3 4 5; do
    Hn=$(get_head 877$n)
    [ "$Hn" != "$HEAD1" ] && SAME=false
  done
  if $SAME; then
    AGREED=true
    echo "  ok: all 5 nodes agree on head_hash (sample $attempt)"
    break
  fi
  sleep 1
done
if ! $AGREED; then
  echo "  bad: heads never agreed across 5 samples (genuine divergence or dead RPC)"
  FAILS=$((FAILS+1))
fi

echo
echo "=== K-committee verification ==="
# S-021 wrapped chain.json: {head_hash, blocks}; legacy bare array tolerated.
if ! python -c "
import json, sys
fails = 0
try:
    with open('$T/n1/chain.json') as f: doc = json.load(f)
except Exception as e:
    print(f'  bad: chain.json missing/unreadable: {e}')
    sys.exit(1)
chain = doc['blocks'] if isinstance(doc, dict) else doc
print(f'  chain length: {len(chain)} blocks')
sizes = [len(b['creators']) for b in chain[1:]]
print(f'  block creator-counts (post-genesis): {sizes}')
if not sizes:
    print('  bad: no post-genesis blocks produced')
    fails += 1
elif all(s == 3 for s in sizes):
    print('  ok: every block has exactly K=3 creators (not M_pool=5)')
else:
    print(f'  bad: expected K=3 creators per block; got {sorted(set(sizes))}')
    fails += 1

committees = [tuple(sorted(b['creators'])) for b in chain[1:]]
unique = set(committees)
print(f'  unique committees over {len(committees)} blocks: {len(unique)}')
print(f'  committees: {sorted(unique)}')
if len(committees) >= 3:
    # epoch_blocks=1 => per-block re-derivation; C(5,3)=10 possible
    # committees, so P(no rotation over n blocks) ~ (1/10)^(n-1).
    if len(unique) > 1:
        print('  ok: K-committee rotates across blocks')
    else:
        print('  bad: committee never rotated (epoch_blocks=1 expects per-block re-derivation)')
        fails += 1
else:
    print(f'  bad: too few post-genesis blocks ({len(committees)}) to assert rotation (need >=3)')
    fails += 1
sys.exit(1 if fails else 0)
"; then
  FAILS=$((FAILS+1))
fi

echo
echo "=== Verdict ==="
if [ "$FAILS" -eq 0 ]; then
  echo "  PASS: test_weak_3node"
  exit 0
else
  echo "  FAIL: test_weak_3node ($FAILS checks failed)"
  exit 1
fi
