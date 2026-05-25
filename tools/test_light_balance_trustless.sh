#!/usr/bin/env bash
# determ-light balance-trustless — verified-against-state-proof balance read.
#
# Boots a 3-node cluster with alice funded in genesis. Runs the composite
# `balance-trustless --json` which: (1) anchors genesis hash, (2) walks
# the chain verifying every committee sig, (3) fetches a state-proof for
# alice's account, (4) cross-checks the daemon's cleartext `account`
# reply against the value_hash in the verified proof. Parity-checks
# against `determ balance alice --json` from the full-binary side.
#
# Assertions:
#   1. balance-trustless --json exits 0.
#   2. JSON has verified=true.
#   3. JSON has balance field that matches full-daemon balance output.
#   4. state_root field populated (post-S-038).
#
# Run from repo root: bash tools/test_light_balance_trustless.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_balance_trustless
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
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3 nodes + genesis with funded alice ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-bt",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "alice", "balance": 500}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

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
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n$n/chain.json'
c['key_path']   = '$TABS/n$n/node_key.json'
c['data_dir']   = '$TABS/n$n'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain past height 5 ==="
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. determ-light balance-trustless --json ==="
set +e
OUT=$($DETERM_LIGHT balance-trustless --rpc-port 8771 --genesis $T/gen.json --domain alice --json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "balance-trustless --json exit 0"
else
    assert "false" "balance-trustless --json exit 0 (got $RC)"
fi

echo
echo "=== 4. JSON has verified=true ==="
VERIFIED=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print('true' if d.get('verified', False) else 'false')
except Exception:
    print('false')
")
assert "$VERIFIED" "balance-trustless JSON has verified=true"

echo
echo "=== 5. balance field present + non-zero ==="
BAL=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('balance', 0))
except Exception:
    print(0)
")
if [ "$BAL" -gt 0 ] 2>/dev/null; then
    assert "true" "balance=$BAL (non-zero)"
else
    assert "false" "balance non-zero (got $BAL)"
fi

echo
echo "=== 6. Parity vs determ balance alice ==="
# `determ balance <domain>` returns a JSON dump (result.dump(2)) with
# a `balance` field. Compare against the light-client's balance.
FULL=$($DETERM balance alice --rpc-port 8771 2>&1 | python -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('balance', 0))
except Exception:
    print(-1)
")
if [ -n "$FULL" ] && [ "$FULL" = "$BAL" ]; then
    assert "true" "parity: light=$BAL == full=$FULL"
else
    assert "false" "parity: light=$BAL vs full=$FULL"
fi

echo
echo "=== 7. state_root present ==="
SR_PRESENT=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    sr = d.get('state_root', '')
    print('true' if len(sr) == 64 else 'false')
except Exception:
    print('false')
")
assert "$SR_PRESENT" "state_root populated (64 hex chars)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_balance_trustless"; exit 0
else
  echo "  FAIL: test_light_balance_trustless"; exit 1
fi
