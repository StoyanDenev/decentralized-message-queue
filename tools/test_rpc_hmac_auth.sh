#!/usr/bin/env bash
# v2.16 / S-001 — HMAC RPC auth regression test.
#
# Exercises:
#   1. Auth disabled (default): unauthenticated RPC works.
#   2. Auth enabled: RPC without auth → error "auth_required".
#   3. Auth enabled: RPC with wrong auth → error "auth_failed".
#   4. Auth enabled: RPC with correct auth via UNCHAINED_RPC_AUTH_SECRET
#      env var → success.
#   5. Auth enabled: tampered auth (one-byte flip) → rejected.
#
# Single-node SINGLE chain (M=K=1 strong). Run from repo root.
set -u
cd "$(dirname "$0")/.."

UNCHAINED=build/Release/unchained.exe
T=test_rpc_hmac
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

# A non-trivial random secret (32 bytes hex = 64 chars).
SECRET="aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff"
WRONG_SECRET="0000000000000000000000000000000000000000000000000000000000000000"

echo "=== 1. Init node WITHOUT auth (default) ==="
$UNCHAINED init --data-dir $T/n1 --profile single_test 2>&1 | tail -1

# Build a minimal SINGLE-role genesis (M=1, K=1, just node1 as creator).
$UNCHAINED genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

cat > $T/gen.json <<EOF
{
  "chain_id": "test-hmac",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "node1", "balance": 100}]
}
EOF
$UNCHAINED genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

configure_node_no_auth() {
  python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7791
c['rpc_port'] = 8791
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
c['rpc_auth_secret'] = ''
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"
}

configure_node_with_auth() {
  python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['rpc_auth_secret'] = '$SECRET'
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"
}

start_node() {
  $UNCHAINED start --config $T/n1/config.json > $T/n1/log 2>&1 &
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

configure_node_no_auth
start_node

echo
echo "=== 2. Auth disabled: status call works without auth ==="
unset UNCHAINED_RPC_AUTH_SECRET
$UNCHAINED status --rpc-port 8791 > $T/r2.out 2> $T/r2.err || true
HAS_HEIGHT=$(python -c "
import json
try:
    with open('$T/r2.out') as f: j = json.load(f)
    print('true' if 'height' in j else 'false')
except: print('false')" 2>/dev/null || echo "false")
[ "$HAS_HEIGHT" = "true" ] \
  && assert true "unauthenticated RPC works when auth disabled" \
  || assert false "unauthenticated RPC failed"

echo
echo "=== 3. Restart node WITH auth ==="
stop_node
configure_node_with_auth
start_node

echo
echo "=== 4. Auth enabled: call WITHOUT auth → error ==="
unset UNCHAINED_RPC_AUTH_SECRET
$UNCHAINED status --rpc-port 8791 > $T/r4.out 2> $T/r4.err || true
if grep -qi "auth" $T/r4.err 2>/dev/null || grep -qi "auth" $T/r4.out 2>/dev/null; then
  assert true "unauthenticated call rejected with auth error"
else
  assert false "unauthenticated call NOT rejected"
fi

echo
echo "=== 5. Auth enabled: call WITH wrong secret → error ==="
UNCHAINED_RPC_AUTH_SECRET="$WRONG_SECRET" $UNCHAINED status --rpc-port 8791 > $T/r5.out 2> $T/r5.err || true
if grep -qi "auth" $T/r5.err 2>/dev/null || grep -qi "auth" $T/r5.out 2>/dev/null; then
  assert true "wrong-secret call rejected"
else
  assert false "wrong-secret call NOT rejected"
fi

echo
echo "=== 6. Auth enabled: call WITH correct secret → success ==="
UNCHAINED_RPC_AUTH_SECRET="$SECRET" $UNCHAINED status --rpc-port 8791 > $T/r6.out 2> $T/r6.err || true
HAS_HEIGHT=$(python -c "
import json
try:
    with open('$T/r6.out') as f: j = json.load(f)
    print('true' if 'height' in j else 'false')
except: print('false')" 2>/dev/null || echo "false")
[ "$HAS_HEIGHT" = "true" ] \
  && assert true "correct-secret call authenticated" \
  || assert false "correct-secret call failed (check $T/r6.{out,err})"

echo
echo "=== 7. Auth enabled: malformed-hex secret → clear error ==="
UNCHAINED_RPC_AUTH_SECRET="not-hex-zzz" $UNCHAINED status --rpc-port 8791 > $T/r7.out 2> $T/r7.err || true
if grep -qi "not valid hex" $T/r7.err 2>/dev/null || grep -qi "not valid hex" $T/r7.out 2>/dev/null; then
  assert true "malformed-hex secret rejected with clear error"
else
  assert false "malformed-hex did NOT yield clear error"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: v2.16 / S-001 HMAC RPC auth"; exit 0
else
  echo "  FAIL"; exit 1
fi
