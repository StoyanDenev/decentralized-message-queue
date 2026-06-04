#!/usr/bin/env bash
# determ-light stake-trustless — verified-against-state-proof stake read.
#
# Boots a 3-node cluster. Each initial_creator is genesis-staked (peer-info
# --stake 1000), so node1 has an "s:" leaf with locked=1000,
# unlock_height=UINT64_MAX. Runs the composite `stake-trustless --json`
# which: (1) anchors genesis hash, (2) walks the chain verifying every
# committee sig, (3) fetches a state-proof for node1's stake leaf (s:
# namespace), (4) cross-checks the daemon's cleartext `stake_info` reply
# against the value_hash in the verified proof. Parity-checks against
# `determ stake_info node1` from the full-binary side.
#
# This is the exact stakes-namespace analogue of
# test_light_balance_trustless.sh (a: namespace). The only differences:
# the queried namespace is s:, the cleartext RPC is stake_info, and the
# decoded fields are locked / unlock_height (not balance / next_nonce).
#
# Assertions:
#   1. stake-trustless --json exits 0.
#   2. JSON has verified=true.
#   3. JSON has locked field > 0 (node1 is genesis-staked).
#   4. JSON has an unlock_height field.
#   5. state_root field populated (post-S-038).
#   6. Parity: light locked == full-daemon stake_info locked.
#   7. Parity: light unlock_height == full-daemon stake_info unlock_height.
#
# Run from repo root: bash tools/test_light_stake_trustless.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_stake_trustless
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS

cleanup() {
  rc=$?
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  # Preserve the script's real exit status — the kill -9 of an
  # already-dead PID returns non-zero and would otherwise clobber a
  # passing run's exit 0.
  return $rc
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3 nodes + genesis with staked creators ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-st",
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
configure_node 1 7791 8791 '["127.0.0.1:7792","127.0.0.1:7793"]'
configure_node 2 7792 8792 '["127.0.0.1:7791","127.0.0.1:7793"]'
configure_node 3 7793 8793 '["127.0.0.1:7791","127.0.0.1:7792"]'

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
  H=$($DETERM status --rpc-port 8791 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. determ-light stake-trustless --json ==="
set +e
OUT=$($DETERM_LIGHT stake-trustless --rpc-port 8791 --genesis $T/gen.json --domain node1 --json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "stake-trustless --json exit 0"
else
    assert "false" "stake-trustless --json exit 0 (got $RC)"
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
assert "$VERIFIED" "stake-trustless JSON has verified=true"

echo
echo "=== 5. locked field present + non-zero ==="
LOCKED=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('locked', 0))
except Exception:
    print(0)
")
if [ "$LOCKED" -gt 0 ] 2>/dev/null; then
    assert "true" "locked=$LOCKED (non-zero)"
else
    assert "false" "locked non-zero (got $LOCKED)"
fi

echo
echo "=== 6. unlock_height field present ==="
UNLOCK=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d['unlock_height'] if 'unlock_height' in d else 'MISSING')
except Exception:
    print('MISSING')
")
if [ "$UNLOCK" != "MISSING" ]; then
    assert "true" "unlock_height present (=$UNLOCK)"
else
    assert "false" "unlock_height present"
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
echo "=== 8. Parity vs determ stake_info node1 ==="
# `determ stake_info <domain>` dumps {domain, locked, unlock_height}.
FULL_LOCKED=$($DETERM stake_info node1 --rpc-port 8791 2>&1 | python -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('locked', -1))
except Exception:
    print(-1)
")
FULL_UNLOCK=$($DETERM stake_info node1 --rpc-port 8791 2>&1 | python -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('unlock_height', -1))
except Exception:
    print(-1)
")
if [ -n "$FULL_LOCKED" ] && [ "$FULL_LOCKED" = "$LOCKED" ]; then
    assert "true" "parity locked: light=$LOCKED == full=$FULL_LOCKED"
else
    assert "false" "parity locked: light=$LOCKED vs full=$FULL_LOCKED"
fi
if [ -n "$FULL_UNLOCK" ] && [ "$FULL_UNLOCK" = "$UNLOCK" ]; then
    assert "true" "parity unlock_height: light=$UNLOCK == full=$FULL_UNLOCK"
else
    assert "false" "parity unlock_height: light=$UNLOCK vs full=$FULL_UNLOCK"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_stake_trustless"; exit 0
else
  echo "  FAIL: test_light_stake_trustless"; exit 1
fi
