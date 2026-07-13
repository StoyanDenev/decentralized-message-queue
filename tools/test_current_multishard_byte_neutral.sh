#!/usr/bin/env bash
# D3.4/D3.3b CURRENT-multishard byte-neutrality regression (the coverage gap the
# D3.4 adversarial review flagged). ShardingMode::CURRENT is a SHIPPED multi-shard
# mode — PROFILE_REGIONAL is chain_role==SHARD + sharding_mode==CURRENT with
# shard_count>1. The D3.4 eligible_count self-report and the D3.3b epoch-committee
# fold (`cc:` leaf) are BOTH scoped to EXTENDED and MUST stay byte-neutral under
# CURRENT-multishard: a gate keyed on the bare shard_count()>1 (instead of
# sharding_mode==EXTENDED) would populate eligible_count / fold `cc:` on a CURRENT
# regional chain, diverging its hash/digest/state_root and hard-forking a rolling
# upgrade of a live regional cluster.
#
# This drives a REAL 3-node CURRENT (sharding_mode=1) + SHARD (chain_role=2)
# cluster with initial_shard_count=3 (so chain_.shard_count()==3>1) + empty
# committee_region (CURRENT mandates it) + epoch_blocks=4, so it CROSSES the epoch
# boundary — exactly where a mis-gated fold/self-report would fire. It asserts:
#   1. SUSTAINED production past the boundary (height>=9) — the EXTENDED-only
#      gating does NOT wedge CURRENT consensus;
#   2. the node's epoch_index advanced (>=1) — NON-VACUOUS: we are past the block
#      where a wrongly-gated fold would have folded a `cc:` checkpoint;
#   3. NO block carries an `eligible_count` field (D3.4: current_source_eligible_
#      count() returns 0 under CURRENT — the field is elided from JSON + digest);
#   4. NO FORK: all 3 nodes agree on a settled block (a fold/self-report skew
#      would diverge the digest here).
#
# Contrast tools/test_extended_epoch_committee.sh (the EXTENDED twin, where the
# fold DOES fire and the frozen `cc:` checkpoint IS active). Standalone cluster
# test (not in the FAST regex).
#
# Run from repo root: bash tools/test_current_multishard_byte_neutral.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh
T=test_current_multishard_byte_neutral

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
block_has_eligible_count() {
  # prints 'yes' if the block JSON at height $1 (rpc $2) carries eligible_count.
  $DETERM show-block "$1" --rpc-port "$2" 2>/dev/null | python -c "import sys,json
try: print('yes' if 'eligible_count' in json.load(sys.stdin) else 'no')
except: print('err')"
}

rm -rf $T
for n in 1 2 3; do mkdir -p $T/n$n; done

echo "=== 1. Init 3 nodes (will be reconfigured to CURRENT) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile web_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build CURRENT-multishard genesis (SHARD role, empty region, S=3, epoch_blocks=4) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-current-multishard-byte-neutral",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 3,
  "committee_region": "",
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
echo "=== 3. Configure the 3-node mesh with sharding_mode=CURRENT (1) ==="
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
c=json.load(open('$T/n$n/config.json'))
c['domain']='node$n'; c['listen_port']=$listen; c['rpc_port']=$rpc
c['bootstrap_peers']=$peers
c['sharding_mode']=1            # CURRENT (web_test init wrote 2=EXTENDED)
c['committee_region']=''        # CURRENT mandates empty region
c['genesis_path']='$GPATH'; c['genesis_hash']='$GHASH'
c['chain_path']='$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path']='$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir']='$PROJECT_ROOT/$T/n$n'
c['tx_commit_ms']=2000; c['block_sig_ms']=2000; c['abort_claim_ms']=1000
json.dump(c,open('$T/n$n/config.json','w'),indent=2)"
}
configure_node 1 7821 8821 '["127.0.0.1:7822","127.0.0.1:7823"]'
configure_node 2 7822 8822 '["127.0.0.1:7821","127.0.0.1:7823"]'
configure_node 3 7823 8823 '["127.0.0.1:7821","127.0.0.1:7822"]'

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
  H=$(get_status_field 8821 height)
  if [ "$H" != "-" ] && [ "$H" -ge 9 ] 2>/dev/null; then break; fi
  sleep 0.3
done

H1=$(get_status_field 8821 height)
EPI=$(get_status_field 8821 epoch_index)
echo "  node1 height: $H1   epoch_index: $EPI"

PASS=true; FAILS=0
bad() { echo "  bad: $1"; PASS=false; FAILS=$((FAILS+1)); }

# 1. sustained production past the boundary (CURRENT gating didn't wedge)
if [ "$H1" = "-" ] || [ "$H1" -lt 9 ] 2>/dev/null; then
  bad "did not sustain production past the epoch boundary (height=$H1, want >= 9)"
fi
# 2. the node crossed the boundary (non-vacuous: this is where a fold would fire)
if [ "$EPI" = "-" ] || [ "$EPI" -lt 1 ] 2>/dev/null; then
  bad "epoch_index=$EPI < 1 — never crossed a boundary, so the check is vacuous"
else
  echo "  ok: epoch_index=$EPI (>=1) — crossed the boundary where a mis-gated fold would fire"
fi

# 3. D3.4 byte-neutrality: NO block carries eligible_count under CURRENT.
if [ "$H1" != "-" ] && [ "$H1" -ge 6 ] 2>/dev/null; then
  INSPECTED=0
  for b in 1 4 5 $((H1 - 1)); do
    [ "$b" -lt 1 ] 2>/dev/null && continue
    HAS=$(block_has_eligible_count "$b" 8821)
    INSPECTED=$((INSPECTED+1))
    case "$HAS" in
      no)  echo "  ok: block[$b] has NO eligible_count field (CURRENT byte-neutral)";;
      yes) bad "block[$b] CARRIES eligible_count under CURRENT — D3.4 byte-neutrality BROKEN";;
      *)   bad "block[$b] eligible_count check errored ($HAS)";;
    esac
  done
  [ "$INSPECTED" -eq 0 ] && bad "no block inspected for eligible_count — check vacuous"
fi

# 4. NO FORK: all 3 nodes agree on a settled block.
if [ "$H1" != "-" ] && [ "$H1" -ge 9 ] 2>/dev/null; then
  target=$((H1 - 1))
  for _ in $(seq 1 100); do
    H2=$(get_status_field 8822 height); H3=$(get_status_field 8823 height)
    if [ "$H2" != "-" ] && [ "$H3" != "-" ] \
       && [ "$H2" -ge "$H1" ] 2>/dev/null && [ "$H3" -ge "$H1" ] 2>/dev/null; then break; fi
    sleep 0.3
  done
  bh1=$($DETERM show-block "$target" --rpc-port 8821 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('prev_hash','?1'))
except: print('?e1')")
  bh2=$($DETERM show-block "$target" --rpc-port 8822 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('prev_hash','?2'))
except: print('?e2')")
  bh3=$($DETERM show-block "$target" --rpc-port 8823 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('prev_hash','?3'))
except: print('?e3')")
  echo "  block[$target] prev_hash: n1=${bh1:0:16} n2=${bh2:0:16} n3=${bh3:0:16}"
  if [ "$bh1" = "$bh2" ] && [ "$bh2" = "$bh3" ] && [ -n "$bh1" ] && [ "${bh1:0:1}" != "?" ]; then
    echo "  ok: all 3 nodes agree on block[$target] (single head — no fork)"
  else
    bad "FORK: nodes disagree on block[$target] (n1=$bh1 n2=$bh2 n3=$bh3)"
  fi
fi

echo
if $PASS; then
  echo "  PASS: $T"
  exit 0
else
  echo "  FAIL: $T ($FAILS check(s))"
  exit 1
fi
