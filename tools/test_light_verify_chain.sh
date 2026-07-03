#!/usr/bin/env bash
# determ-light verify-chain — composite genesis-anchor + walk-to-head verifier.
#
# Boots a 3-node cluster, lets it advance, runs `determ-light verify-chain`
# which: (1) computes genesis hash locally + cross-checks block 0,
# (2) walks every header to the head verifying prev_hash chain, and
# (3) verifies every block's K-of-K committee signatures against the
# committee seed pulled from the genesis JSON.
#
# This is the full "is this daemon honest?" check operators run before
# trusting any RPC reply for trustless wallet operations.
#
# Assertions:
#   1. verify-chain returns exit 0 + prints structured success summary.
#   2. genesis pin matches reported.
#   3. blocks (sigs) count >= chain height (every header verified).
#
# Run from repo root: bash tools/test_light_verify_chain.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_chain
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

echo "=== 0. R52 --track-registry offline CLI contract (no daemon needed) ==="
# The registry replay reconstructs registrant state from block 0, so a
# resumed suffix (or a persisted anchor that doesn't capture registry
# state) is refused rather than degraded.
OUT=$($DETERM_LIGHT verify-chain --rpc-port 1 --genesis /nonexistent.json \
      --track-registry --resume 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "incompatible with"; then
  assert "true" "--track-registry + --resume refused (exit $RC)"
else
  assert "false" "--track-registry + --resume refused (rc=$RC out=$OUT)"
fi
OUT=$($DETERM_LIGHT verify-chain --rpc-port 1 --genesis /nonexistent.json \
      --track-registry --persist 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "incompatible with"; then
  assert "true" "--track-registry + --persist refused (exit $RC)"
else
  assert "false" "--track-registry + --persist refused (rc=$RC out=$OUT)"
fi
if $DETERM_LIGHT 2>&1 | grep -q -- "--track-registry"; then
  assert "true" "help text documents --track-registry"
else
  assert "false" "help text documents --track-registry"
fi

echo "=== 1. Init 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vc",
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
echo "=== 3. determ-light verify-chain ==="
set +e
OUT=$($DETERM_LIGHT verify-chain --rpc-port 8771 --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"

OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-chain prints OK summary"

if [ "$RC" = "0" ]; then
    assert "true" "verify-chain exit code 0"
else
    assert "false" "verify-chain exit code 0 (got $RC)"
fi

echo
echo "=== 4. genesis pin reported as match ==="
GPIN_OK=$(echo "$OUT" | grep -q "genesis pin:.*matches" && echo true || echo false)
assert "$GPIN_OK" "verify-chain reports 'genesis pin: matches'"

echo
echo "=== 5. blocks (sigs) covers every non-genesis block ==="
# blocks(sigs) verifies committee sigs for indices 1..height; genesis
# (index 0) is anchored via genesis_hash, not via sigs (it has no
# committee — it's the deterministic GenesisConfig→Block seed).
# Expect blocks(sigs) == height - 1, with height meaning "total blocks".
BLK=$(echo "$OUT" | grep "blocks (sigs):" | head -1 | awk '{print $NF}')
HT=$(echo "$OUT" | grep "^  height:" | head -1 | awk '{print $NF}')
EXPECTED=$((HT - 1))
if [ -n "$BLK" ] && [ -n "$HT" ] && [ "$BLK" = "$EXPECTED" ] 2>/dev/null; then
    assert "true" "blocks(sigs)=$BLK == height-1 ($EXPECTED) (genesis anchored separately)"
else
    assert "false" "blocks(sigs)=$BLK == height-1=$EXPECTED (height=$HT)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_chain"; exit 0
else
  echo "  FAIL: test_light_verify_chain"; exit 1
fi
