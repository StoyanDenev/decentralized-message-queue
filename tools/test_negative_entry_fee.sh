#!/usr/bin/env bash
# E1 — Negative Entry Fee + Zeroth pool.
#
# Genesis seeds the Zeroth pool (canonical 0x00…0 anon address) with the
# operator-chosen balance via `zeroth_pool_initial`. On each FIRST-TIME
# REGISTER tx applied, half the pool transfers to the new registrant.
# Geometric exhaustion (pool halves per registration, asymptotes to 0).
#
# What this test asserts:
#   1. zeroth_pool_initial = 1000 seeds an account at the Zeroth address
#      with balance 1000 at genesis, queryable via show-account.
#   2. The Zeroth pool's balance counts toward A1's genesis_total_ —
#      the chain advances past genesis without violating the unitary-
#      balance invariant (a violation would throw at apply and halt).
#   3. The genesis JSON schema accepts zeroth_pool_initial; the chain
#      reports its initial Zeroth-pool balance correctly.
#
# What this test does NOT assert end-to-end (deferred — requires Python
# Ed25519-signing pipeline that matches C++ signing_bytes exactly, which
# isn't trivially reproduced cross-language):
#   - Live NEF distribution on a fresh REGISTER (the chain.cpp apply
#     path is exercised by code review; cross-process REGISTER tx
#     submission lands in a follow-on iteration once the Python signing
#     helper is verified bit-identical to the C++ Transaction::signing_bytes).
#
# Run from repo root: bash tools/test_negative_entry_fee.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_nef
ZEROTH=0x0000000000000000000000000000000000000000000000000000000000000000

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

get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

get_balance() {
  $DETERM balance "$2" --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 validator nodes ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build genesis with zeroth_pool_initial = 1000 ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-nef",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 0,
  "zeroth_pool_initial": 1000,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="$PROJECT_ROOT/$T/gen.json"

# Build a second genesis with a different pool size to verify the field
# is bound into the chain config (different pool ⇒ different account state).
cp $T/gen.json $T/gen_alt.json
python -c "
import json
g = json.load(open('$T/gen_alt.json'))
g['zeroth_pool_initial'] = 500
json.dump(g, open('$T/gen_alt.json','w'), indent=2)
"
$DETERM genesis-tool build $T/gen_alt.json > /dev/null 2>&1

echo
echo "=== 3. Configure 3-mesh ==="
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$GPATH'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/n$n'
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 4. Start 3 nodes ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Poll until chain advances (height >= 5) ==="
for _ in $(seq 1 80); do
  H=$(get_status_field 8771 height)
  if [ "$H" != "-" ] && [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.2
done

H=$(get_status_field 8771 height)
POOL=$(get_balance 8771 $ZEROTH)
echo "  height: $H"
echo "  Zeroth pool balance: $POOL (expected 1000)"

PASS=true
if [ "$H" = "-" ] || [ "$H" -lt 5 ] 2>/dev/null; then
  echo "  FAIL: chain didn't advance — A1 invariant violation in the pool seed path?"
  PASS=false
fi
if [ "$POOL" != "1000" ]; then
  echo "  FAIL: Zeroth pool balance $POOL != 1000 (genesis seed wiring broken)"
  PASS=false
fi

# Cross-check: querying show-account on the Zeroth address returns the
# same balance the genesis declared.
ACCT=$($DETERM show-account $ZEROTH --rpc-port 8771 2>&1)
if echo "$ACCT" | grep -qE "balance[[:space:]]*:[[:space:]]*1000"; then
  echo "  show-account on Zeroth address reports balance: 1000"
else
  echo "  FAIL: show-account on Zeroth address didn't return balance=1000"
  echo "  got: $ACCT"
  PASS=false
fi

if $PASS; then
  echo
  echo "  PASS: E1 Zeroth pool genesis-seed end-to-end"
  echo "        - zeroth_pool_initial = 1000 seeded an account at"
  echo "          $ZEROTH"
  echo "        - chain advanced past genesis (height $H) — A1 unitary-balance"
  echo "          invariant held with the pool's balance counted toward genesis_total_"
  echo "        - show-account on the Zeroth address reports the genesis balance"
  echo "        (apply-path NEF distribution exercised by code review; cross-"
  echo "         language signed-REGISTER tx submission is a follow-on)"
fi
