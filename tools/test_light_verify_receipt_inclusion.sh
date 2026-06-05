#!/usr/bin/env bash
# determ-light verify-receipt-inclusion — trust-minimized INCLUDED /
# NOT-INCLUDED / UNVERIFIABLE verdict on whether a cross-shard inbound
# receipt (src_shard, tx_hash) is a member of the committee-verified `i:`
# (applied_inbound_receipts) namespace.
#
# The verifier anchors genesis, committee-verifies the header chain to
# head, computes the canonical receipt key ("i:" + src_shard_be8 +
# tx_hash), fetches the `i:`-namespace state-proof, and Merkle-verifies it
# against the committee-signed state_root — binding the proof to THIS
# receipt via key_bytes == local key AND value_hash == SHA256(0x01).
#
# Fail-closed contract under test: the current daemon's `state_proof` RPC
# exposes only the simple-key namespaces (a|s|r|d|b|k|c) and explicitly
# rejects the composite-key `i:` namespace (see src/node/node.cpp
# rpc_state_proof — "composite-key namespaces (i/m/p) are out of scope").
# So against today's daemon the sound verdict for a well-formed query is
# UNVERIFIABLE (exit 3) — the verifier REFUSES to assert membership it
# cannot prove, and NEVER returns a false INCLUDED. If/when the RPC gains
# `i:` support, the same code path yields a real INCLUDED/NOT-INCLUDED
# with zero changes.
#
# Assertions:
#   1. Well-formed query against the live daemon → UNVERIFIABLE, exit 3,
#      with a fail-closed diagnostic (daemon refused the `i:` proof);
#      crucially NOT a false INCLUDED.
#   2. Wrong --genesis → fail-closed, non-zero exit (genesis-hash
#      mismatch detected before any verdict).
#   3. Malformed --tx-hash (wrong length) → non-zero exit, never INCLUDED.
#   4. Missing required flags → usage error (exit 1).
#   5. --json output parses with {included:false, verdict, src_shard,
#      tx_hash, namespace:"i"} and included is the boolean false.
#   6. (anti-false-positive) Across every variant above, the stdout never
#      begins with "INCLUDED".
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_receipt_inclusion.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found (needed to mint anon keys)"
    exit 0
fi

T=test_light_verify_receipt_inclusion
TABS=$PROJECT_ROOT/$T

PY=python
command -v python >/dev/null 2>&1 || PY=python3

declare -a NODE_PIDS
cluster_running=1
stop_cluster() {
  set +e
  if [ "$cluster_running" = "1" ]; then
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    cluster_running=0
  fi
  return 0
}
trap stop_cluster EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Mint an anon keypair (alice, funded in genesis) ==="
"$DETERM_WALLET" account-create-batch --count 1 --out "$T/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][0]['address'])")
echo "  alice=$ADDR_A"

echo
echo "=== 2. Init 3-node cluster with alice funded in genesis ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vri",
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

# A DIFFERENT genesis (same creators, different chain_id) → different
# compute_genesis_hash. Used by assertion 2 (wrong-genesis refusal).
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "test-light-vri-WRONG",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "$ADDR_A", "balance": 99999}]
}
EOF
$DETERM genesis-tool build $T/gen_wrong.json | tail -1
echo "  genesis hash:        $GHASH"

configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  $PY -c "
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
configure_node 1 7841 8841 '["127.0.0.1:7842","127.0.0.1:7843"]'
configure_node 2 7842 8842 '["127.0.0.1:7841","127.0.0.1:7843"]'
configure_node 3 7843 8843 '["127.0.0.1:7841","127.0.0.1:7842"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

wait_height() {
  local target=$1
  for _ in $(seq 1 360); do
    H=$($DETERM status --rpc-port 8841 2>/dev/null \
         | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
    if [ "$H" -ge "$target" ] 2>/dev/null; then break; fi
    sleep 0.5
  done
}

echo
echo "=== 3. Wait for chain past height 3 ==="
wait_height 3
echo "  chain height: $H"
if [ "$H" -lt 3 ] 2>/dev/null; then
  echo "  SKIP: cluster did not reach height >= 3 in budget (got $H);"
  echo "        environment too starved — not a verify-receipt-inclusion defect."
  exit 0
fi

# Pre-flight: confirm the daemon on 8841 runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8841 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$GHASH" ]; then
    echo "  PRE-FLIGHT FAIL: daemon on RPC 8841 has block0=$BLK0 but our"
    echo "  genesis hash=$GHASH — a foreign/stale daemon is on this port."
    assert "false" "pre-flight: daemon on 8841 runs our genesis"
    echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL: test_light_verify_receipt_inclusion"; exit 1
fi
echo "  pre-flight OK: daemon on 8841 runs our genesis"

# A plausible (src_shard, tx_hash) to query. Any 32-byte hash works for
# exercising the verifier's anchor + fail-closed path; the daemon won't
# serve an `i:` proof regardless, so membership is UNVERIFIABLE.
SRC_SHARD=1
RX_HASH=$($PY -c "import os; print(os.urandom(32).hex())")
echo "  query: src_shard=$SRC_SHARD tx_hash=$RX_HASH"

echo
echo "=== ASSERTION 1: well-formed query → UNVERIFIABLE (exit 3), fail-closed ==="
# The current daemon refuses the `i:` namespace, so a trust-minimized
# verifier MUST NOT assert membership — it reports UNVERIFIABLE and exits
# 3, never a false INCLUDED.
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8841 --genesis $T/gen.json \
        --src-shard $SRC_SHARD --tx-hash $RX_HASH 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qE "^UNVERIFIABLE"; then
    assert "true" "well-formed query → UNVERIFIABLE, exit 3 (daemon refused `i:` proof)"
else
    assert "false" "well-formed query → UNVERIFIABLE/exit3 (got rc=$RC)"
fi
NOFP1=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP1" "never a false INCLUDED against a daemon that can't serve the proof"

echo
echo "=== ASSERTION 2: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8841 --genesis $T/gen_wrong.json \
        --src-shard $SRC_SHARD --tx-hash $RX_HASH 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "wrong genesis rejected (exit $RC)"
else
    assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP2=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP2" "wrong genesis never yields INCLUDED"

echo
echo "=== ASSERTION 3: malformed --tx-hash → non-zero exit, never INCLUDED ==="
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8841 --genesis $T/gen.json \
        --src-shard $SRC_SHARD --tx-hash deadbeef 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ] && ! echo "$OUT" | grep -qE "^INCLUDED"; then
    assert "true" "malformed --tx-hash → non-zero exit, not INCLUDED (rc=$RC)"
else
    assert "false" "malformed --tx-hash should hard-error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 4: missing required flags → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8841 --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
    assert "true" "missing --src-shard/--tx-hash → usage error (exit 1)"
else
    assert "false" "missing flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 5: --json parses with required fields, included=false ==="
set +e
JOUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8841 --genesis $T/gen.json \
        --src-shard $SRC_SHARD --tx-hash $RX_HASH --json 2>&1 | tail -1)
set -e
echo "  json: $JOUT"
JSON_OK=$(echo "$JOUT" | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    need = ['included','verdict','src_shard','tx_hash','namespace']
    if any(k not in d for k in need): print('false'); sys.exit()
    if not isinstance(d['included'], bool): print('false'); sys.exit()
    if d['included'] is not False: print('false'); sys.exit()
    if d['verdict'] != 'UNVERIFIABLE': print('false'); sys.exit()
    if d['namespace'] != 'i': print('false'); sys.exit()
    if int(d['src_shard']) != $SRC_SHARD: print('false'); sys.exit()
    if d['tx_hash'] != '$RX_HASH': print('false'); sys.exit()
    print('true')
except Exception as e:
    sys.stderr.write('parse err: %s\n' % e); print('false')
")
assert "$JSON_OK" "--json: {included:false, verdict:UNVERIFIABLE, src_shard, tx_hash, namespace:i}"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_receipt_inclusion"; exit 0
else
  echo "  FAIL: test_light_verify_receipt_inclusion"; exit 1
fi
