#!/usr/bin/env bash
# determ-light genesis-anchor — wrong-genesis rejection check.
#
# Boots a 3-node cluster with one chain_id, then runs verify-chain with
# a DIFFERENT genesis JSON (different chain_id). The local genesis-hash
# computation will differ from the daemon's block 0 hash, and the
# light-client must refuse to proceed with a "GENESIS HASH MISMATCH"
# diagnostic. This validates the load-bearing trust invariant: the
# light-client refuses to talk to a daemon that doesn't run our chain.
#
# Assertions:
#   1. verify-chain with the real genesis succeeds.
#   2. verify-chain with the wrong genesis (different chain_id) FAILS.
#   3. Failure diagnostic contains "GENESIS HASH MISMATCH".
#   4. Exit code on failure is non-zero.
#
# Run from repo root: bash tools/test_light_genesis_anchor.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"
    exit 0
fi

T=test_light_genesis_anchor
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

echo "=== 1. Init 3-node cluster (chain_id=test-light-ga-REAL) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen_real.json <<EOF
{
  "chain_id": "test-light-ga-REAL",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 100}]
}
EOF
$DETERM genesis-tool build $T/gen_real.json | tail -1
GHASH=$(cat $T/gen_real.json.hash)

# Build a WRONG genesis with a different chain_id (everything else
# identical). compute_genesis_hash binds chain_id, so the hashes
# diverge — exactly the kind of "wrong network" mistake the anchor
# is designed to catch.
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "test-light-ga-WRONG",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 100}]
}
EOF

configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen_real.json'
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
echo "=== 2. Wait for chain past height 3 ==="
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. verify-chain with REAL genesis → OK ==="
set +e
OUT=$($DETERM_LIGHT verify-chain --rpc-port 8771 --genesis $T/gen_real.json 2>&1)
RC=$?
set -e
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
if [ "$RC" = "0" ] && [ "$OK" = "true" ]; then
    assert "true" "verify-chain OK with real genesis"
else
    echo "$OUT"
    assert "false" "verify-chain OK with real genesis (RC=$RC OK=$OK)"
fi

echo
echo "=== 4. verify-chain with WRONG genesis → FAIL ==="
set +e
OUT=$($DETERM_LIGHT verify-chain --rpc-port 8771 --genesis $T/gen_wrong.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "verify-chain with wrong genesis exits non-zero (got $RC)"
else
    assert "false" "verify-chain with wrong genesis exits non-zero (got 0)"
fi

echo
echo "=== 5. Diagnostic cites GENESIS HASH MISMATCH ==="
GM=$(echo "$OUT" | grep -q "GENESIS HASH MISMATCH" && echo true || echo false)
assert "$GM" "diagnostic contains 'GENESIS HASH MISMATCH'"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_genesis_anchor"; exit 0
else
  echo "  FAIL: test_light_genesis_anchor"; exit 1
fi
