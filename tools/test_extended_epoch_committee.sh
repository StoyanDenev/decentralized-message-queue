#!/usr/bin/env bash
# D3.3b-read EXTENDED gate (ShardTipMergeDesign.md §9.4): a LIVE EXTENDED cluster
# that CROSSES an epoch boundary, so committee selection switches from the
# present-head fallback (epoch 0, no checkpoint) to the FROZEN cc: checkpoint
# (epoch >= 1, committee_pin_active == true). This is the end-to-end verification
# that the read-side pin (STEP 1-3) sustains consensus on a real multi-process
# cluster: the committee a producer selects from the frozen checkpoint is the one
# every validator re-derives, so the chain keeps a SINGLE head across the boundary.
#
# 3 us-east creators, M=K=3 (3-of-3), epoch_blocks=4 -> the checkpoint for epoch 1
# is folded at block index 3 (the last block of epoch 0); blocks 4..7 are epoch 1
# and are produced/validated through select_committee_pool(frozen). We drive well
# past the boundary and assert:
#   1. SUSTAINED production past the boundary (height >= 9 => >= 2 epoch-1 blocks
#      minted from the frozen committee, plus into epoch 2);
#   2. NO FORK: all 3 nodes agree on head_hash at a common height (the property
#      the pin must preserve — a producer/validator committee skew would fork here);
#   3. the node reports epoch_index >= 1 (the frozen path is actually active);
#   4. every inspected committee is a well-formed K=3 us-east set.
#
# epoch_blocks=4 is injected into the genesis JSON (the source of truth; the
# web_test profile leaves epoch_blocks at the 1000 default, which never crosses a
# boundary in a short run and so only exercises the epoch-0 fallback).
#
# Run from repo root: bash tools/test_extended_epoch_committee.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh
T=test_extended_epoch_committee

declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT

get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}
get_committee() {
  $DETERM show-block "$1" --rpc-port "$2" 2>/dev/null | python -c "import sys,json
try: print(' '.join(json.load(sys.stdin).get('creators', [])))
except: print('')"
}

rm -rf $T
for n in 1 2 3; do mkdir -p $T/n$n; done

echo "=== 1. Init 3 us-east nodes (EXTENDED, web_test profile) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile web_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
  python -c "
import json
e=json.load(open('$T/p$n.json')); e['region']='us-east'; json.dump(e,open('$T/p$n.json','w'))"
done

echo
echo "=== 2. Build EXTENDED genesis with epoch_blocks=4 (boundary at block 3) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-extended-epoch-committee",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 3,
  "committee_region": "us-east",
  "epoch_blocks": 4,
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
GPATH="$PROJECT_ROOT/$T/gen.json"

echo
echo "=== 3. Configure the 3-node mesh (relaxed test timers) ==="
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
c=json.load(open('$T/n$n/config.json'))
c['domain']='node$n'; c['listen_port']=$listen; c['rpc_port']=$rpc
c['bootstrap_peers']=$peers
c['genesis_path']='$GPATH'; c['genesis_hash']='$GHASH'
c['chain_path']='$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path']='$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir']='$PROJECT_ROOT/$T/n$n'
c['tx_commit_ms']=2000; c['block_sig_ms']=2000; c['abort_claim_ms']=1000
json.dump(c,open('$T/n$n/config.json','w'),indent=2)"
}
configure_node 1 7811 8811 '["127.0.0.1:7812","127.0.0.1:7813"]'
configure_node 2 7812 8812 '["127.0.0.1:7811","127.0.0.1:7813"]'
configure_node 3 7813 8813 '["127.0.0.1:7811","127.0.0.1:7812"]'

echo
echo "=== 4. Start the 3 nodes ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Poll for production PAST the epoch boundary (height >= 9) ==="
for _ in $(seq 1 300); do
  H=$(get_status_field 8811 height)
  if [ "$H" != "-" ] && [ "$H" -ge 9 ] 2>/dev/null; then break; fi
  sleep 0.3
done

H1=$(get_status_field 8811 height)
EPI=$(get_status_field 8811 epoch_index)
echo "  node1 height: $H1   epoch_index: $EPI"

PASS=true; FAILS=0
bad() { echo "  bad: $1"; PASS=false; FAILS=$((FAILS+1)); }

# 1. sustained production past the boundary
if [ "$H1" = "-" ] || [ "$H1" -lt 9 ] 2>/dev/null; then
  bad "did not sustain production past the epoch boundary (height=$H1, want >= 9)"
fi
# 3. the frozen path is actually active (epoch_index >= 1)
if [ "$EPI" = "-" ] || [ "$EPI" -lt 1 ] 2>/dev/null; then
  bad "epoch_index=$EPI < 1 — the frozen committee path was never entered"
else
  echo "  ok: epoch_index=$EPI (>=1) — committee selection is on the FROZEN cc: checkpoint"
fi

# 2. NO FORK: all 3 nodes agree on head_hash at node1's height.
if [ "$H1" != "-" ] && [ "$H1" -ge 9 ] 2>/dev/null; then
  target=$((H1 - 1))
  h1=$(get_status_field 8811 head)
  # let 2 + 3 catch up to the same height, then compare heads.
  for _ in $(seq 1 100); do
    H2=$(get_status_field 8812 height); H3=$(get_status_field 8813 height)
    if [ "$H2" != "-" ] && [ "$H3" != "-" ] \
       && [ "$H2" -ge "$H1" ] 2>/dev/null && [ "$H3" -ge "$H1" ] 2>/dev/null; then break; fi
    sleep 0.3
  done
  # compare each node's block at `target` (a settled height below every tip).
  bh1=$($DETERM show-block "$target" --rpc-port 8811 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('prev_hash','?1'))
except: print('?e1')")
  bh2=$($DETERM show-block "$target" --rpc-port 8812 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('prev_hash','?2'))
except: print('?e2')")
  bh3=$($DETERM show-block "$target" --rpc-port 8813 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('prev_hash','?3'))
except: print('?e3')")
  echo "  block[$target] prev_hash: n1=${bh1:0:16} n2=${bh2:0:16} n3=${bh3:0:16}"
  if [ "$bh1" = "$bh2" ] && [ "$bh2" = "$bh3" ] && [ -n "$bh1" ] && [ "${bh1:0:1}" != "?" ]; then
    echo "  ok: all 3 nodes agree on block[$target] (SINGLE head across the epoch boundary — no fork)"
  else
    bad "FORK: nodes disagree on block[$target] (n1=$bh1 n2=$bh2 n3=$bh3)"
  fi
fi

# 4. committees are well-formed K=3 us-east sets (inspect blocks past the boundary).
INSPECTED=0
if [ "$H1" != "-" ] && [ "$H1" -ge 6 ] 2>/dev/null; then
  for b in 4 5 $((H1 - 1)); do
    [ "$b" -lt 1 ] 2>/dev/null && continue
    C=$(get_committee "$b" 8811)
    echo "  epoch-1 block #$b committee: $C"
    [ -z "$C" ] && { bad "block #$b committee empty"; continue; }
    INSPECTED=$((INSPECTED+1))
    NM=0
    for m in $C; do NM=$((NM+1)); case "$m" in node1|node2|node3) ;; *) bad "unexpected committee member $m on block #$b";; esac; done
    [ "$NM" -ne 3 ] && bad "block #$b committee size $NM != K=3"
  done
fi
[ "$INSPECTED" -eq 0 ] && bad "no epoch-1 committee inspected — checks would be vacuous"

echo
if $PASS; then
  echo "  PASS: $T"
  exit 0
else
  echo "  FAIL: $T ($FAILS check(s))"
  exit 1
fi
