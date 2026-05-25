#!/usr/bin/env bash
# determ-light verify-block-sigs — K-of-K committee Ed25519 verifier.
#
# Boots a 3-node cluster, fetches block 1's header + committee via the
# light-client's fetch surfaces, then runs verify-block-sigs locally.
# Sibling test of test_verify_block_sigs.sh but exercised through
# determ-light's CLI dispatch.
#
# Assertions:
#   1. Header fetch + validators fetch succeed.
#   2. verify-block-sigs OK against real header + real committee.
#   3. Tampered signature → FAIL.
#   4. Wrong committee pubkey → FAIL.
#   5. Missing committee member → FAIL.
#
# Run from repo root: bash tools/test_light_verify_block_sigs.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_block_sigs
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
  "chain_id": "test-light-vbs",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
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
echo "=== 3. fetch-headers --from 1 --count 1 + validators ==="
$DETERM_LIGHT fetch-headers --rpc-port 8771 --from 1 --count 1 --out $T/hdr.json > $T/fetch.out 2>&1
# Pull committee through the validators CLI (raw JSON) — same surface
# the upstream test uses.
$DETERM validators --rpc-port 8771 --json > $T/committee.json 2>&1
HAVE_HDR=$([ -s "$T/hdr.json" ] && echo true || echo false)
assert "$HAVE_HDR" "fetch-headers + validators produced fixtures"

echo
echo "=== 4. verify-block-sigs OK on real header + committee ==="
OUT=$($DETERM_LIGHT verify-block-sigs --header $T/hdr.json --committee $T/committee.json 2>&1)
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-block-sigs OK on real fixture"

echo
echo "=== 5. Tampered signature → FAIL ==="
python -c "
import json
r = json.load(open('$T/hdr.json'))
hdr = r['headers'][0]
s = hdr['creator_block_sigs'][0]
hdr['creator_block_sigs'][0] = ('1' if s[0] != '1' else '2') + s[1:]
with open('$T/hdr_tampered.json','w') as f: json.dump(r, f)
"
OUT=$($DETERM_LIGHT verify-block-sigs --header $T/hdr_tampered.json --committee $T/committee.json 2>&1)
FAIL=$(echo "$OUT" | grep -q "FAIL.*signature does NOT verify" && echo true || echo false)
assert "$FAIL" "tampered sig → FAIL"

echo
echo "=== 6. Wrong committee pubkey → FAIL ==="
python -c "
import json
c = json.load(open('$T/committee.json'))
arr = c if isinstance(c, list) else c.get('members', c)
if arr:
    pk = arr[0]['ed_pub']
    arr[0]['ed_pub'] = ('1' if pk[0] != '1' else '2') + pk[1:]
with open('$T/committee_wrong.json','w') as f: json.dump(arr, f)
"
OUT=$($DETERM_LIGHT verify-block-sigs --header $T/hdr.json --committee $T/committee_wrong.json 2>&1)
FAIL=$(echo "$OUT" | grep -q "FAIL.*signature does NOT verify" && echo true || echo false)
assert "$FAIL" "wrong committee pubkey → FAIL"

echo
echo "=== 7. Missing committee member → FAIL ==="
python -c "
import json
c = json.load(open('$T/committee.json'))
arr = c if isinstance(c, list) else c.get('members', c)
out = arr[1:]
with open('$T/committee_missing.json','w') as f: json.dump(out, f)
"
OUT=$($DETERM_LIGHT verify-block-sigs --header $T/hdr.json --committee $T/committee_missing.json 2>&1)
FAIL=$(echo "$OUT" | grep -q "FAIL.*not in the supplied committee" && echo true || echo false)
assert "$FAIL" "missing committee member → FAIL"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_block_sigs"; exit 0
else
  echo "  FAIL: test_light_verify_block_sigs"; exit 1
fi
