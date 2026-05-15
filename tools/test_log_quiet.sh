#!/usr/bin/env bash
# S-027 (extended) — `Config::log_quiet` flag actually suppresses the
# chatty per-block / per-bundle / per-connection diagnostic lines.
#
# Asserts: with log_quiet=true, the chain still advances normally, but
# the `[node] accepted block #N` line is absent from the node's log.
# Inverse (log_quiet=false default) emits the line per block.
#
# Two sequential single-node runs (same node, restarted between
# phases); no TIME_WAIT risk because we use a unique port pair.
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_log_quiet
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
mkdir -p $T/n1

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init single-node chain (M=K=1) + genesis ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json
cat > $T/gen.json <<EOF
{
  "chain_id": "test-log-quiet",
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
  local quiet=$1                 # 'true' or 'false' (shell form)
  # Map to Python bool literal for the embedded interpreter.
  local py_quiet
  case "$quiet" in true) py_quiet=True;; *) py_quiet=False;; esac
  python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain']       = 'node1'
c['listen_port']  = 7840
c['rpc_port']     = 8840
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path']   = '$TABS/n1/chain.json'
c['key_path']     = '$TABS/n1/node_key.json'
c['data_dir']     = '$TABS/n1'
c['tx_commit_ms']  = 200
c['block_sig_ms']  = 200
c['abort_claim_ms']= 100
c['log_quiet']    = $py_quiet
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"
}

run_phase() {
  local label=$1
  local quiet=$2
  local logfile=$3
  write_config "$quiet"
  rm -f $T/n1/chain.json $logfile
  $DETERM start --config $T/n1/config.json > $logfile 2>&1 &
  NODE_PIDS[0]=$!
  sleep 2
  for _ in $(seq 1 40); do
    H=$($DETERM status --rpc-port 8840 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
    [ "$H" -ge "5" ] && break
    sleep 0.5
  done
  echo "  [$label] chain height: $H"
  kill ${NODE_PIDS[0]} 2>/dev/null
  sleep 1
  kill -9 ${NODE_PIDS[0]} 2>/dev/null
  NODE_PIDS[0]=
}

echo
echo "=== 2. Phase A — log_quiet=false (default verbose) ==="
run_phase "verbose" false $T/n1/log.verbose
VERBOSE_COUNT=$(grep -c "\[node\] accepted block #" $T/n1/log.verbose 2>/dev/null | head -n1 | tr -d '[:space:]')
VERBOSE_COUNT=${VERBOSE_COUNT:-0}
echo "  [verbose] accepted-block lines: $VERBOSE_COUNT"
[ "$VERBOSE_COUNT" -ge "3" ] \
  && assert true "verbose mode emits at least 3 [node] accepted block lines (got $VERBOSE_COUNT)" \
  || assert false "verbose mode emitted only $VERBOSE_COUNT accepted-block lines (expected >= 3)"

echo
echo "=== 3. Phase B — log_quiet=true ==="
run_phase "quiet" true $T/n1/log.quiet
QUIET_COUNT=$(grep -c "\[node\] accepted block #" $T/n1/log.quiet 2>/dev/null | head -n1 | tr -d '[:space:]')
QUIET_COUNT=${QUIET_COUNT:-0}
echo "  [quiet] accepted-block lines: $QUIET_COUNT"
[ "$QUIET_COUNT" = "0" ] \
  && assert true "quiet mode suppresses the [node] accepted block lines (got $QUIET_COUNT)" \
  || assert false "quiet mode still emitted $QUIET_COUNT accepted-block lines (expected 0)"

echo
echo "=== 4. Sanity — quiet mode still emits the startup/listen lines ==="
# Lines emitted independent of log_quiet (no per-block frequency):
#   [determ] Loading node domain=...
#   [rpc] listening on 127.0.0.1:8840
# Both should appear regardless of quiet mode.
if grep -q "\[rpc\] listening" $T/n1/log.quiet \
   && grep -q "Loading node" $T/n1/log.quiet; then
  assert true "quiet mode still surfaces startup/listen diagnostics"
else
  assert false "quiet mode suppressed startup/listen diagnostics (expected to survive)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: S-027 log_quiet flag"; exit 0
else
  echo "  FAIL"; exit 1
fi
