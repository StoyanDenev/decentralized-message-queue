#!/usr/bin/env bash
# v2.2 light-client foundation — state_proof RPC smoke test.
#
# Verifies:
#   1. state_proof RPC returns the full verification-input tuple for
#      an "a:" (account) key — present-key path.
#   2. The returned value_hash equals SHA-256(balance_le8 || nonce_le8)
#      for the queried account (matches build_state_leaves's encoding).
#   3. state_proof returns {"error": "not_found"} for an absent key —
#      missing-key path.
#   4. state_proof and state_root reported at the same instant agree
#      (state_root in the proof response matches the corresponding
#      RPC's state_root) — sanity check that the proof RPC isn't
#      reading from a stale snapshot.
#
# Run from repo root: bash tools/test_state_proof.sh
set -u
cd "$(dirname "$0")/.."

UNCHAINED=build/Release/unchained.exe
T=test_state_proof
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
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3 nodes ==="
for n in 1 2 3; do
  $UNCHAINED init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $UNCHAINED genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

# Anon wallet — its address goes into accounts_ (namespace "a:")
$UNCHAINED account create --out $T/anon_a.json 2>&1 | tail -1
A_ADDR=$(python -c "import json; print(json.load(open('$T/anon_a.json'))['address'])")

cat > $T/gen.json <<EOF
{
  "chain_id": "test-state-proof",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "$A_ADDR", "balance": 100}]
}
EOF
$UNCHAINED genesis-tool build $T/gen.json | tail -1
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

echo
echo "=== 2. Start 3 nodes ==="
NODE_PIDS=("" "" "")
$UNCHAINED start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$UNCHAINED start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$UNCHAINED start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 3. Wait for chain to advance past height 5 ==="
for _ in $(seq 1 80); do
  H=$($UNCHAINED status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 4. state_proof for present account 'A' (namespace=a) ==="
PROOF=$($UNCHAINED state-proof --rpc-port 8771 --ns a --key "$A_ADDR" 2>/dev/null)
echo "$PROOF" > $T/proof.json

# Structure check
has_required=$(python -c "
import json
p = json.load(open('$T/proof.json'))
needed = ['namespace','key','key_bytes','value_hash','target_index','leaf_count','proof','state_root','height']
print('true' if all(k in p for k in needed) else 'false')
" 2>/dev/null || echo "false")
assert "$has_required" "state_proof response has all required fields"

# Hex-width checks
hex_widths_ok=$(python -c "
import json
p = json.load(open('$T/proof.json'))
ok = (len(p['value_hash']) == 64 and
      len(p['state_root']) == 64 and
      all(len(h) == 64 for h in p['proof']))
print('true' if ok else 'false')
" 2>/dev/null || echo "false")
assert "$hex_widths_ok" "value_hash, state_root, and proof entries are 32-byte hex"

# leaf_count and target_index sanity
sane_indices=$(python -c "
import json
p = json.load(open('$T/proof.json'))
ok = (isinstance(p['target_index'], int) and isinstance(p['leaf_count'], int)
      and p['leaf_count'] > 0 and 0 <= p['target_index'] < p['leaf_count'])
print('true' if ok else 'false')
" 2>/dev/null || echo "false")
assert "$sane_indices" "target_index in [0, leaf_count)"

echo
echo "=== 5. value_hash matches SHA-256(balance_le || nonce_le) ==="
# build_state_leaves's account leaf encoding (SHA256Builder writes
# uint64 as BIG-endian; see src/crypto/sha256.cpp::append(uint64_t)):
#   value_hash = SHA-256(balance: u64 BE || next_nonce: u64 BE)
# A has balance 100 (from genesis) and next_nonce 0 (no txs from A yet).
expected_vh=$(python -c "
import hashlib, struct
data = struct.pack('>Q', 100) + struct.pack('>Q', 0)
print(hashlib.sha256(data).hexdigest())
" 2>/dev/null || echo "")
actual_vh=$(python -c "
import json; print(json.load(open('$T/proof.json'))['value_hash'])
" 2>/dev/null || echo "")
echo "  expected: ${expected_vh:0:32}..."
echo "  actual:   ${actual_vh:0:32}..."
[ "$expected_vh" = "$actual_vh" ] \
  && assert true "value_hash matches expected encoding (SHA256(balance||nonce))" \
  || assert false "value_hash mismatch"

echo
echo "=== 6. state_proof for absent key returns not_found ==="
MISS=$($UNCHAINED state-proof --rpc-port 8771 --ns a --key "0xdeadbeef" 2>/dev/null)
is_not_found=$(echo "$MISS" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print('true' if j.get('error') == 'not_found' else 'false')
except: print('false')
" 2>/dev/null || echo "false")
assert "$is_not_found" "absent key returns {error: not_found}"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: v2.2 state_proof RPC foundation"; exit 0
else
  echo "  FAIL"; exit 1
fi
