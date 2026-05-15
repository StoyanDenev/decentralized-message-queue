#!/usr/bin/env bash
# v2.2 light-client demonstrator — `determ verify-state-proof`.
#
# Spins up a 3-node cluster, fetches a state-proof from one node via
# `determ state-proof`, then verifies that proof LOCALLY via
# `determ verify-state-proof` (which calls crypto::merkle_verify
# against the proof's own state_root). This is the end-to-end
# demonstrator for the light-client primitive: fetch + verify
# without trusting the responding node.
#
# Assertions:
#   1. Genesis-account state-proof verifies locally (OK).
#   2. Tampered value_hash makes verification fail (FAIL).
#   3. Tampered sibling-hash entry makes verification fail (FAIL).
#   4. Externally-supplied --state-root that matches the proof's
#      claimed root verifies OK (real light-client mode).
#   5. Externally-supplied --state-root that DOES NOT match makes
#      verification fail (defense against a node fabricating a root
#      to make its tampered proof check out against itself).
#
# Run from repo root: bash tools/test_verify_state_proof.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_verify_state_proof
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

echo "=== 1. Init 3 nodes + build genesis with a funded anon account ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

# Anon wallet — its address goes into accounts_ (namespace "a:")
$DETERM account create --out $T/anon.json 2>&1 | tail -1
ADDR=$(python -c "import json; print(json.load(open('$T/anon.json'))['address'])")

cat > $T/gen.json <<EOF
{
  "chain_id": "test-verify-state-proof",
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

echo
echo "=== 2. Start 3 nodes ==="
NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 3. Wait for chain to advance past height 5 ==="
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
echo "=== 4. Fetch state-proof for funded anon account ==="
$DETERM state-proof --rpc-port 8771 --ns a --key "$ADDR" > $T/proof.json 2>&1
HAS_PROOF=$(python -c "
import json
try:
    p = json.load(open('$T/proof.json'))
    print('true' if 'proof' in p and 'state_root' in p else 'false')
except Exception:
    print('false')")
assert "$HAS_PROOF" "state-proof RPC returned a structured proof"

echo
echo "=== 5. Local verify (no external root — self-consistency) ==="
OUT=$($DETERM verify-state-proof --in $T/proof.json 2>&1)
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-state-proof OK on valid proof"

echo
echo "=== 6. Verify against externally-supplied matching state_root ==="
# Read the proof's claimed root and pass it back via --state-root.
# This is the real light-client mode (the client trusts its own
# previously-verified root).
ROOT=$(python -c "import json; print(json.load(open('$T/proof.json'))['state_root'])")
OUT=$($DETERM verify-state-proof --in $T/proof.json --state-root "$ROOT" 2>&1)
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$OK" "verify-state-proof OK with matching --state-root"

echo
echo "=== 7. Tampered value_hash should fail verification ==="
python -c "
import json
p = json.load(open('$T/proof.json'))
# Flip a hex char in value_hash.
v = p['value_hash']
p['value_hash'] = ('1' if v[0] != '1' else '2') + v[1:]
with open('$T/proof_tampered_vh.json','w') as f: json.dump(p, f)
"
OUT=$($DETERM verify-state-proof --in $T/proof_tampered_vh.json 2>&1)
FAIL=$(echo "$OUT" | grep -q "^FAIL" && echo true || echo false)
assert "$FAIL" "tampered value_hash makes verify-state-proof FAIL"

echo
echo "=== 8. Tampered sibling-hash in proof should fail verification ==="
python -c "
import json
p = json.load(open('$T/proof.json'))
if not p['proof']:
    # Single-leaf tree (no siblings) — fall back to tampering target_index.
    p['target_index'] = (p['target_index'] + 1) % max(p['leaf_count'], 2)
else:
    s = p['proof'][0]
    p['proof'][0] = ('1' if s[0] != '1' else '2') + s[1:]
with open('$T/proof_tampered_sib.json','w') as f: json.dump(p, f)
"
OUT=$($DETERM verify-state-proof --in $T/proof_tampered_sib.json 2>&1)
FAIL=$(echo "$OUT" | grep -q "^FAIL" && echo true || echo false)
assert "$FAIL" "tampered sibling-hash makes verify-state-proof FAIL"

echo
echo "=== 9. External --state-root mismatch should fail verification ==="
# Pass a different root than the proof claims; should fail.
FAKE_ROOT=$(python -c "print('a' * 64)")
OUT=$($DETERM verify-state-proof --in $T/proof.json --state-root "$FAKE_ROOT" 2>&1)
# The CLI prints a warning + still attempts verification against the
# supplied root, which won't match. Expect FAIL on the verify line.
FAIL=$(echo "$OUT" | grep -q "FAIL" && echo true || echo false)
assert "$FAIL" "mismatched --state-root makes verify-state-proof FAIL"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: v2.2 verify-state-proof light-client demonstrator"; exit 0
else
  echo "  FAIL"; exit 1
fi
