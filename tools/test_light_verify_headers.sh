#!/usr/bin/env bash
# determ-light verify-headers — light-client chain-of-hashes verifier.
#
# Boots a 3-node cluster, fetches headers via `determ-light fetch-headers`,
# then verifies them locally with `determ-light verify-headers`. This is
# the determ-light surface counterpart to test_headers_rpc.sh — same RPC
# under the hood, but exercised from the third binary.
#
# Assertions:
#   1. fetch-headers writes a well-formed `headers` envelope.
#   2. verify-headers OK on the freshly-fetched chain (no anchor).
#   3. Tampered prev_hash makes verify-headers FAIL.
#   4. --genesis-hash anchor matches → OK.
#   5. --genesis-hash anchor mismatch → FAIL.
#
# Run from repo root: bash tools/test_light_verify_headers.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_headers
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

echo "=== 1. Init 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-verify-headers",
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
echo "=== 3. determ-light fetch-headers writes envelope ==="
$DETERM_LIGHT fetch-headers --rpc-port 8771 --from 0 --count 10 --out $T/hdrs.json > $T/fetch.out 2>&1
SHAPE_OK=$(python -c "
import json
try:
    r = json.load(open('$T/hdrs.json'))
    print('true' if ('headers' in r and isinstance(r['headers'], list) and r['count'] >= 1) else 'false')
except Exception:
    print('false')
")
assert "$SHAPE_OK" "fetch-headers wrote a valid envelope"

echo
echo "=== 4. determ-light verify-headers OK on valid chain ==="
OUT=$($DETERM_LIGHT verify-headers --in $T/hdrs.json 2>&1)
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-headers OK on freshly fetched chain"

echo
echo "=== 5. Tamper prev_hash → FAIL ==="
python -c "
import json
r = json.load(open('$T/hdrs.json'))
if len(r['headers']) >= 2:
    p = r['headers'][1]['prev_hash']
    r['headers'][1]['prev_hash'] = ('1' if p[0] != '1' else '2') + p[1:]
with open('$T/hdrs_tampered.json','w') as f: json.dump(r, f)
"
OUT=$($DETERM_LIGHT verify-headers --in $T/hdrs_tampered.json 2>&1)
FAIL=$(echo "$OUT" | grep -q "FAIL.*prev_hash chain break" && echo true || echo false)
assert "$FAIL" "tampered prev_hash makes verify-headers FAIL"

echo
echo "=== 6. --genesis-hash anchor matches → OK ==="
OUT=$($DETERM_LIGHT verify-headers --in $T/hdrs.json --genesis-hash "$GHASH" 2>&1)
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-headers OK with --genesis-hash anchor"

echo
echo "=== 7. --genesis-hash mismatch → FAIL ==="
WRONG=$(python -c "print('a' * 64)")
OUT=$($DETERM_LIGHT verify-headers --in $T/hdrs.json --genesis-hash "$WRONG" 2>&1)
FAIL=$(echo "$OUT" | grep -q "FAIL.*genesis block_hash mismatch" && echo true || echo false)
assert "$FAIL" "verify-headers FAIL on wrong --genesis-hash"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_headers"; exit 0
else
  echo "  FAIL: test_light_verify_headers"; exit 1
fi
