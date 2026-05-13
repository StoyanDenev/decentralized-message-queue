#!/usr/bin/env bash
# S-014 (gossip side) — per-peer-IP token-bucket regression for gossip.
#
# Strategy:
#   1. Bring up a 3-node cluster with gossip_rate=500/s, burst=1000
#      (sensible operator defaults). Verify chain advances normally
#      — consensus traffic flows comfortably under the cap.
#   2. Restart with gossip_rate=1/s, burst=2 (tight). Verify the chain
#      stalls (consensus messages get rate-limited, K-of-K can't
#      complete). This proves the gate is wired into handle_message.
#
# 3-node MD cluster (M=K=3). Run from repo root.
set -u
cd "$(dirname "$0")/.."

UNCHAINED=build/Release/unchained.exe
T=test_gossip_rate
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

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3 nodes + 3-of-3 genesis ==="
for n in 1 2 3; do
  $UNCHAINED init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $UNCHAINED genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-gossip-rate",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ]
}
EOF
$UNCHAINED genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

write_config() {
  local n=$1
  local lp=$2
  local rp=$3
  local rate=$4
  local burst=$5
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain']        = 'node$n'
c['listen_port']   = $lp
c['rpc_port']      = $rp
c['bootstrap_peers'] = ['127.0.0.1:7796','127.0.0.1:7797','127.0.0.1:7798']
c['genesis_path']  = '$TABS/gen.json'
c['genesis_hash']  = '$GHASH'
c['chain_path']    = '$TABS/n$n/chain.json'
c['key_path']      = '$TABS/n$n/node_key.json'
c['data_dir']      = '$TABS/n$n'
c['tx_commit_ms']  = 500
c['block_sig_ms']  = 500
c['abort_claim_ms']= 250
c['gossip_rate_per_sec'] = $rate
c['gossip_rate_burst']   = $burst
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}

start_all() {
  for n in 1 2 3; do
    $UNCHAINED start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
    NODE_PIDS[$((n-1))]=$!
  done
  sleep 2
}

stop_all() {
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
}

poll_height() {
  $UNCHAINED status --rpc-port 8796 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin)['height'])
except Exception: print(0)" 2>/dev/null
}

echo
echo "=== 2. Phase A: gossip_rate=500/s, burst=1000 (sensible defaults) ==="
for n in 1 2 3; do
  case $n in
    1) write_config 1 7796 8796 500.0 1000.0 ;;
    2) write_config 2 7797 8797 500.0 1000.0 ;;
    3) write_config 3 7798 8798 500.0 1000.0 ;;
  esac
done

start_all

echo "  Waiting up to 20s for chain to advance..."
H_BEFORE=$(poll_height)
for attempt in $(seq 1 40); do
  sleep 0.5
  H_NOW=$(poll_height)
  [ "$H_NOW" -ge 10 ] && break
done
H_PHASE_A=$(poll_height)
echo "  Phase A height: $H_PHASE_A (started at $H_BEFORE)"
[ "$H_PHASE_A" -ge 10 ] \
  && assert true "chain advances under sensible gossip rate limit (h=$H_PHASE_A ≥ 10)" \
  || assert false "chain stalls under sensible gossip rate limit (h=$H_PHASE_A, expected ≥10)"

# Confirm log message was emitted.
GREP_OK=0
for n in 1 2 3; do
  if grep -q "gossip\] rate-limit" $T/n$n/log; then
    GREP_OK=$((GREP_OK + 1))
  fi
done
[ "$GREP_OK" = "3" ] \
  && assert true "all 3 nodes logged the gossip rate-limit config line" \
  || assert false "only $GREP_OK/3 nodes logged the rate-limit line"

echo
echo "=== 3. Phase B: gossip_rate=1/s, burst=2 (deliberately too tight) ==="
stop_all
sleep 2
# Wipe chain state so the cluster restarts fresh — otherwise Phase B
# would inherit Phase A's progress and the stall signature wouldn't show.
for n in 1 2 3; do
  rm -f $T/n$n/chain.json
  case $n in
    1) write_config 1 7796 8796 1.0 2.0 ;;
    2) write_config 2 7797 8797 1.0 2.0 ;;
    3) write_config 3 7798 8798 1.0 2.0 ;;
  esac
done

start_all
echo "  Sampling height across 8 seconds..."
H1=$(poll_height); sleep 4; H2=$(poll_height); sleep 4; H3=$(poll_height)
echo "  heights: t=0:$H1  t=4:$H2  t=8:$H3"

# Under MD 3-of-3 with 1/s gossip cap, consensus needs many messages per
# round (contrib + block_sig + status, gossiped to 2 peers each). 1/s
# absolutely starves it; the chain should advance only a handful of
# blocks (or stall completely).
[ "$H3" -lt 8 ] \
  && assert true "chain stalls under starvation gossip rate (h=$H3 < 8)" \
  || assert false "chain advanced too freely under starvation rate (h=$H3, expected <8)"

stop_all

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: S-014 gossip rate limiting"; exit 0
else
  echo "  FAIL"; exit 1
fi
