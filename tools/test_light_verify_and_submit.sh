#!/usr/bin/env bash
# determ-light verify-and-submit — end-to-end composite send.
#
# Fund alice in genesis, boot a 3-node cluster, then run the composite
# `verify-and-submit` which: (1) anchors genesis, (2) walks chain
# verifying committee sigs, (3) trustless-fetches alice's nonce, (4)
# signs a TRANSFER locally with that verified nonce, (5) submits the
# tx via submit_tx RPC. Then verifies the balance change on-chain
# via a second `balance-trustless` read.
#
# Assertions:
#   1. verify-and-submit exits 0.
#   2. Output JSON has submitted_tx_hash field.
#   3. Post-submit balance differs from pre-submit (transfer landed).
#
# Run from repo root: bash tools/test_light_verify_and_submit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"
    exit 0
fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found"
    exit 0
fi

T=test_light_verify_and_submit
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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Mint two anon keypairs ==="
"$DETERM_WALLET" account-create-batch --count 2 --out "$T/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][1]['address'])")

$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
" "$T/keys.json" "$T/key_a.json"

echo
echo "=== 2. Init 3-node cluster with alice funded ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vas",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "$ADDR_A", "balance": 10000}]
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
echo "=== 3. Wait for chain past height 5 ==="
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
echo "=== 4. Capture pre-submit balance (trustless) ==="
PRE=$($DETERM_LIGHT balance-trustless --rpc-port 8771 --genesis $T/gen.json \
        --domain $ADDR_A --json 2>&1 | tail -1 | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('balance', 0))
except Exception:
    print(0)
")
echo "  pre-submit balance: $PRE"

echo
echo "=== 5. determ-light verify-and-submit (TRANSFER 100 from alice→bob) ==="
set +e
OUT=$($DETERM_LIGHT verify-and-submit --rpc-port 8771 --genesis $T/gen.json \
        --keyfile $T/key_a.json --to $ADDR_B --amount 100 --fee 0 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "verify-and-submit exit 0"
else
    assert "false" "verify-and-submit exit 0 (got $RC)"
fi

echo
echo "=== 6. Output JSON has submitted_tx_hash ==="
HASH=$(echo "$OUT" | tail -1 | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('submitted_tx_hash', ''))
except Exception:
    print('')
")
if [ -n "$HASH" ] && [ "${#HASH}" = "64" ]; then
    assert "true" "submitted_tx_hash=$HASH (64 hex)"
else
    assert "false" "submitted_tx_hash present + 64 hex (got '$HASH')"
fi

echo
echo "=== 7. Wait for tx to land + verify post-submit balance change ==="
# Allow up to ~10s for the tx to be included.
POST=$PRE
for _ in $(seq 1 25); do
    sleep 0.5
    POST=$($DETERM_LIGHT balance-trustless --rpc-port 8771 --genesis $T/gen.json \
            --domain $ADDR_A --json 2>&1 | tail -1 | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('balance', 0))
except Exception:
    print(0)
")
    if [ "$POST" != "$PRE" ]; then break; fi
done
echo "  post-submit balance: $POST"
if [ "$POST" != "$PRE" ] && [ "$POST" -lt "$PRE" ] 2>/dev/null; then
    assert "true" "balance decreased from $PRE → $POST (transfer landed)"
else
    assert "false" "balance change observed (pre=$PRE post=$POST)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_and_submit"; exit 0
else
  echo "  FAIL: test_light_verify_and_submit"; exit 1
fi
