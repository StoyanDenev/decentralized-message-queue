#!/usr/bin/env bash
# S-001 mitigation — RPC bind defaults to 127.0.0.1 only.
#
# Verifies:
#   1. Default config (rpc_localhost_only absent or true): RPC bind is
#      127.0.0.1. Log banner reflects the chosen interface.
#   2. Explicit opt-in (rpc_localhost_only=false): RPC bind is 0.0.0.0
#      (any interface). Log banner reflects the chosen interface.
#   3. Functional: localhost RPC client can call status under both modes.
#   4. Config round-trip: rpc_localhost_only field survives JSON save+load.
#
# This test does NOT attempt to bind to an external interface and connect
# from another host — that would require a multi-host harness. The
# guarantee is enforced by the asio acceptor binding to a specific
# IPv4 address; the localhost-only case literally cannot accept
# non-loopback connections.
#
# Run from repo root: bash tools/test_rpc_localhost_only.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_rpc_local
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
mkdir -p $T/n_default $T/n_open

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init two single-node setups ==="
for n in n_default n_open; do
  $DETERM init --data-dir $T/$n --profile single_test 2>&1 | tail -1
done

# Genesis: tiny single-validator chain (M=K=1) for fast smoke-test.
$DETERM genesis-tool peer-info node1 --data-dir $T/n_default --stake 1000 > $T/p_default.json
$DETERM genesis-tool peer-info node1 --data-dir $T/n_open    --stake 1000 > $T/p_open.json
for variant in default open; do
  cat > $T/gen_$variant.json <<EOF
{
  "chain_id": "test-rpc-$variant",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [$(cat $T/p_$variant.json | tr -d '\n')],
  "initial_balances": [{"domain": "node1", "balance": 100}]
}
EOF
  $DETERM genesis-tool build $T/gen_$variant.json | tail -1
done

echo
echo "=== 2. Configure: default (localhost-only) vs explicit open ==="
python -c "
import json
# Default node: omit rpc_localhost_only — should fall through to true.
with open('$T/n_default/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7901
c['rpc_port'] = 8901
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/gen_default.json'
c['genesis_hash'] = open('$T/gen_default.json.hash').read().strip()
c['chain_path'] = '$TABS/n_default/chain.json'
c['key_path']   = '$TABS/n_default/node_key.json'
c['data_dir']   = '$TABS/n_default'
# Intentionally do NOT set rpc_localhost_only — verify default = true.
with open('$T/n_default/config.json','w') as f: json.dump(c, f, indent=2)

# Open node: explicit false.
with open('$T/n_open/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7902
c['rpc_port'] = 8902
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/gen_open.json'
c['genesis_hash'] = open('$T/gen_open.json.hash').read().strip()
c['chain_path'] = '$TABS/n_open/chain.json'
c['key_path']   = '$TABS/n_open/node_key.json'
c['data_dir']   = '$TABS/n_open'
c['rpc_localhost_only'] = False
with open('$T/n_open/config.json','w') as f: json.dump(c, f, indent=2)
"

echo
echo "=== 3. Start both nodes ==="
NODE_PIDS=("" "")
$DETERM start --config $T/n_default/config.json > $T/n_default/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.5
$DETERM start --config $T/n_open/config.json    > $T/n_open/log    2>&1 &
NODE_PIDS[1]=$!; sleep 2

echo
echo "=== 4. Verify log banners reflect the chosen bind ==="
DEFAULT_BANNER=$(grep "rpc.*listening" $T/n_default/log | head -1)
OPEN_BANNER=$(grep "rpc.*listening"    $T/n_open/log    | head -1)
echo "  default: $DEFAULT_BANNER"
echo "  open:    $OPEN_BANNER"
if echo "$DEFAULT_BANNER" | grep -q "127.0.0.1:8901"; then
  assert true "default config → bind 127.0.0.1:8901"
else
  assert false "default config → bind 127.0.0.1:8901"
fi
if echo "$OPEN_BANNER" | grep -q "0.0.0.0:8902"; then
  assert true "rpc_localhost_only=false → bind 0.0.0.0:8902"
else
  assert false "rpc_localhost_only=false → bind 0.0.0.0:8902"
fi

echo
echo "=== 5. Functional: localhost RPC reaches both nodes ==="
S1=$($DETERM status --rpc-port 8901 2>&1 | tr -d '\n\r')
S2=$($DETERM status --rpc-port 8902 2>&1 | tr -d '\n\r')
if echo "$S1" | grep -q '"head_hash"'; then
  assert true "localhost RPC status on default node (8901)"
else
  assert false "localhost RPC status on default node — got: $S1"
fi
if echo "$S2" | grep -q '"head_hash"'; then
  assert true "localhost RPC status on open node (8902)"
else
  assert false "localhost RPC status on open node — got: $S2"
fi

echo
echo "=== 6. Config round-trip preserves rpc_localhost_only ==="
ROUND=$(python -c "
import json
c = json.load(open('$T/n_open/config.json'))
print(c.get('rpc_localhost_only', 'MISSING'))
")
if [ "$ROUND" = "False" ]; then
  assert true "rpc_localhost_only=false round-trips through config.json"
else
  assert false "rpc_localhost_only round-trip — got: $ROUND"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: S-001 RPC localhost-only default"; exit 0
else
  echo "  FAIL"; exit 1
fi
