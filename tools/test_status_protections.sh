#!/usr/bin/env bash
# `rpc_status` → `protections` readback for operator monitoring.
#
# Asserts: the status response carries a `protections` JSON object with
# the seven expected keys, and the values reflect the live Config:
#
#   * Phase A — defaults: rpc_localhost_only=true, others off.
#   * Phase B — explicitly opted into a few flags via config.json
#     (log_quiet=true, rpc_rate_per_sec / gossip_rate_per_sec set).
#     `protections` should show rpc_rate_limit=true, gossip_rate_limit
#     =true, log_quiet=true.
#
# Single-node, no TIME_WAIT risk.
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_status_protections
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

echo "=== 1. Init single-node chain ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json
cat > $T/gen.json <<EOF
{
  "chain_id": "test-protections",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

write_config() {
  local rate=$1
  local gossip_rate=$2
  local quiet_py=$3   # 'True' or 'False'
  python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain']       = 'node1'
c['listen_port']  = 7850
c['rpc_port']     = 8850
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path']   = '$TABS/n1/chain.json'
c['key_path']     = '$TABS/n1/node_key.json'
c['data_dir']     = '$TABS/n1'
c['tx_commit_ms']  = 200
c['block_sig_ms']  = 200
c['abort_claim_ms']= 100
c['rpc_rate_per_sec']    = $rate
c['rpc_rate_burst']      = $rate * 2 if $rate > 0 else 0
c['gossip_rate_per_sec'] = $gossip_rate
c['gossip_rate_burst']   = $gossip_rate * 2 if $gossip_rate > 0 else 0
c['log_quiet']    = $quiet_py
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"
}

run_phase() {
  rm -f $T/n1/chain.json
  $DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
  NODE_PIDS[0]=$!
  sleep 2
  for _ in $(seq 1 20); do
    H=$($DETERM status --rpc-port 8850 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
    [ "$H" -ge "2" ] && break
    sleep 0.5
  done
}

stop_phase() {
  kill ${NODE_PIDS[0]} 2>/dev/null
  sleep 1
  kill -9 ${NODE_PIDS[0]} 2>/dev/null
  NODE_PIDS[0]=
}

echo
echo "=== 2. Phase A — defaults: rate limits off, log_quiet=false ==="
write_config 0 0 False
run_phase

STATUS=$($DETERM status --rpc-port 8850 2>/dev/null)
PROT_KEYS=$(echo "$STATUS" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    p = j.get('protections', {})
    print(','.join(sorted(p.keys())))
except Exception as e:
    print('ERROR:' + str(e))
")
echo "  protections keys: $PROT_KEYS"
EXPECTED="bft_enabled,gossip_rate_limit,log_quiet,rpc_hmac_auth,rpc_localhost_only,rpc_rate_limit,sharding_mode"
[ "$PROT_KEYS" = "$EXPECTED" ] \
  && assert true "all 7 protections keys present" \
  || assert false "protections key mismatch (got: $PROT_KEYS)"

VALS_A=$(echo "$STATUS" | python -c "
import sys, json
j = json.load(sys.stdin)
p = j['protections']
print('localhost={}, hmac={}, rpc_rl={}, gossip_rl={}, quiet={}'.format(
    p['rpc_localhost_only'], p['rpc_hmac_auth'],
    p['rpc_rate_limit'], p['gossip_rate_limit'], p['log_quiet']))
")
echo "  Phase A values: $VALS_A"
if echo "$VALS_A" | grep -q "localhost=True" \
   && echo "$VALS_A" | grep -q "hmac=False" \
   && echo "$VALS_A" | grep -q "rpc_rl=False" \
   && echo "$VALS_A" | grep -q "gossip_rl=False" \
   && echo "$VALS_A" | grep -q "quiet=False"; then
  assert true "Phase A default protections: localhost=on, others off"
else
  assert false "Phase A defaults mismatch: $VALS_A"
fi
stop_phase

echo
echo "=== 3. Phase B — opted into rate limits + quiet mode ==="
write_config 100 500 True
run_phase

STATUS_B=$($DETERM status --rpc-port 8850 2>/dev/null)
VALS_B=$(echo "$STATUS_B" | python -c "
import sys, json
j = json.load(sys.stdin)
p = j['protections']
print('rpc_rl={}, gossip_rl={}, quiet={}'.format(
    p['rpc_rate_limit'], p['gossip_rate_limit'], p['log_quiet']))
")
echo "  Phase B values: $VALS_B"
if echo "$VALS_B" | grep -q "rpc_rl=True" \
   && echo "$VALS_B" | grep -q "gossip_rl=True" \
   && echo "$VALS_B" | grep -q "quiet=True"; then
  assert true "Phase B opted-in protections: rate limits ON, quiet ON"
else
  assert false "Phase B opted-in mismatch: $VALS_B"
fi
stop_phase

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: rpc_status protections readback"; exit 0
else
  echo "  FAIL"; exit 1
fi
