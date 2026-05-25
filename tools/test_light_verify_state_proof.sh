#!/usr/bin/env bash
# determ-light verify-state-proof — light-client Merkle-inclusion verifier.
#
# Fund an anon account in genesis, fetch its state-proof via the
# light-client's fetch surface, then verify the proof locally. Sibling
# of test_verify_state_proof.sh but exercised through determ-light's
# CLI dispatch (which goes through verify::verify_state_proof in the
# light/verify.cpp module).
#
# Assertions:
#   1. fetch-state-proof writes a structured proof.
#   2. verify-state-proof OK on the fresh proof (no external root).
#   3. verify-state-proof OK with matching --state-root anchor.
#   4. Tampered value_hash → FAIL.
#   5. Wrong --state-root → FAIL.
#
# Run from repo root: bash tools/test_light_verify_state_proof.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_state_proof
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

echo "=== 1. Init 3 nodes + genesis with funded anon ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

$DETERM account create --out $T/anon.json 2>&1 | tail -1
ADDR=$(python -c "import json; print(json.load(open('$T/anon.json'))['address'])")

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vsp",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "$ADDR", "balance": 42}]
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
echo "=== 3. determ-light fetch-state-proof for the anon account ==="
$DETERM_LIGHT fetch-state-proof --rpc-port 8771 --ns a --key "$ADDR" --out $T/proof.json > $T/fetch.out 2>&1
HAS_PROOF=$(python -c "
import json
try:
    p = json.load(open('$T/proof.json'))
    print('true' if 'proof' in p and 'state_root' in p else 'false')
except Exception:
    print('false')")
assert "$HAS_PROOF" "fetch-state-proof produced structured proof"

echo
echo "=== 4. verify-state-proof OK on fresh proof ==="
OUT=$($DETERM_LIGHT verify-state-proof --in $T/proof.json 2>&1)
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-state-proof OK on fresh proof"

echo
echo "=== 5. verify-state-proof OK with matching --state-root ==="
ROOT=$(python -c "import json; print(json.load(open('$T/proof.json'))['state_root'])")
OUT=$($DETERM_LIGHT verify-state-proof --in $T/proof.json --state-root "$ROOT" 2>&1)
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-state-proof OK with matching --state-root"

echo
echo "=== 6. Tampered value_hash → FAIL ==="
python -c "
import json
p = json.load(open('$T/proof.json'))
v = p['value_hash']
p['value_hash'] = ('1' if v[0] != '1' else '2') + v[1:]
with open('$T/proof_bad_vh.json','w') as f: json.dump(p, f)
"
OUT=$($DETERM_LIGHT verify-state-proof --in $T/proof_bad_vh.json 2>&1)
FAIL=$(echo "$OUT" | grep -q "FAIL" && echo true || echo false)
assert "$FAIL" "tampered value_hash → FAIL"

echo
echo "=== 7. Wrong --state-root → FAIL ==="
FAKE=$(python -c "print('a' * 64)")
OUT=$($DETERM_LIGHT verify-state-proof --in $T/proof.json --state-root "$FAKE" 2>&1)
FAIL=$(echo "$OUT" | grep -q "FAIL" && echo true || echo false)
assert "$FAIL" "wrong --state-root → FAIL"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_state_proof"; exit 0
else
  echo "  FAIL: test_light_verify_state_proof"; exit 1
fi
