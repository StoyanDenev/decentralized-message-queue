#!/usr/bin/env bash
# S-014 — RPC rate-limit regression test.
#
# Exercises:
#   1. Rate limit DISABLED: a flood of N requests all succeed.
#   2. Rate limit ENABLED (rate=5/s, burst=10): the first ~10 requests
#      succeed (burst), then subsequent requests within ~1s fail with
#      "rate_limited".
#   3. After a wait of 2 seconds, ~10 more requests succeed (bucket
#      refilled steady-state + accumulated burst).
#   4. Backward compat: rate=0, burst=0 (default config) → no rate
#      limiting.
#
# 1-node SINGLE chain (M=K=1). Run from repo root.
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_rpc_rate
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
mkdir -p $T/n1

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init node + minimal SINGLE genesis ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

cat > $T/gen.json <<EOF
{
  "chain_id": "test-rate",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

# Configure with rate-limit DISABLED first (defaults).
python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7795
c['rpc_port'] = 8795
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
c['rpc_rate_per_sec'] = 0.0
c['rpc_rate_burst']   = 0.0
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

start_node() {
  $DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
  NODE_PIDS[0]=$!
  sleep 1
}

stop_node() {
  if [ -n "${NODE_PIDS[0]:-}" ]; then
    kill "${NODE_PIDS[0]}" 2>/dev/null
    sleep 0.5
    kill -9 "${NODE_PIDS[0]}" 2>/dev/null
  fi
}

echo
echo "=== 2. Rate-limit DISABLED: 30 status queries should all succeed ==="
start_node
disabled_ok=0
for i in $(seq 1 30); do
  if $DETERM status --rpc-port 8795 > $T/out_$i 2>&1; then
    disabled_ok=$((disabled_ok + 1))
  fi
done
[ "$disabled_ok" -ge "30" ] \
  && assert true "30/30 queries succeed when rate limit disabled (got $disabled_ok)" \
  || assert false "rate-limit-disabled: got $disabled_ok/30 (expected 30)"

echo
echo "=== 3. Restart node with rate=0.5/s burst=3 (tight to overcome slow CLI spawn) ==="
stop_node
python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['rpc_rate_per_sec'] = 0.5
c['rpc_rate_burst']   = 3.0
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"
start_node

echo
echo "=== 4. Burst of 15 immediate queries: ~3 succeed, rest rate-limited ==="
# rate=0.5/s burst=3: after 3 calls consumed, next ~12 should
# rate-limit (CLI spawn is ~100ms; 15 × 100ms = ~1.5s × 0.5/s = ~0.75
# refill tokens — well below the consumption rate). Refill is slower
# than CLI iteration, so the bucket stays drained.
enabled_ok=0
enabled_rl=0
for i in $(seq 1 15); do
  OUT=$($DETERM status --rpc-port 8795 2>&1 || true)
  if echo "$OUT" | grep -q '"height"'; then
    enabled_ok=$((enabled_ok + 1))
  elif echo "$OUT" | grep -qi "rate_limited"; then
    enabled_rl=$((enabled_rl + 1))
  fi
done
echo "  succeeded: $enabled_ok, rate-limited: $enabled_rl"
[ "$enabled_ok" -ge "3" ] && [ "$enabled_ok" -le "8" ] \
  && assert true "burst behavior: ~3 succeed within burst window (got $enabled_ok)" \
  || assert false "burst ok-count: $enabled_ok (expected 3-8)"

[ "$enabled_rl" -ge "5" ] \
  && assert true "≥5 requests rate-limited within burst window (got $enabled_rl)" \
  || assert false "rate-limited count: $enabled_rl (expected ≥5)"

echo
echo "=== 5. Wait 6s → bucket refills → 3 more queries succeed ==="
sleep 6
refill_ok=0
for i in $(seq 1 6); do
  OUT=$($DETERM status --rpc-port 8795 2>&1 || true)
  if echo "$OUT" | grep -q '"height"'; then
    refill_ok=$((refill_ok + 1))
  fi
done
# 6s × 0.5/s = 3 refill tokens. Expect at least 2-3 to succeed.
[ "$refill_ok" -ge "2" ] \
  && assert true "≥2 queries succeed after 6s refill (got $refill_ok)" \
  || assert false "post-refill ok: $refill_ok (expected ≥2)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: S-014 RPC rate limiting"; exit 0
else
  echo "  FAIL"; exit 1
fi
