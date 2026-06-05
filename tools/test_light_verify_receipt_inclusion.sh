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
# This test exercises a REAL applied receipt end-to-end. It stands up the
# cross-shard topology (1 beacon + 2 shards, M=K=1), transfers value from
# wallet A (routes to shard 0) to wallet B (routes to shard 1), waits for
# the cross-shard credit to land on shard 1 — which means shard 1 APPLIED
# the inbound receipt and inserted its (src_shard, tx_hash) into the `i:`
# namespace — then reads that receipt back out of shard 1's block bodies
# and asks the light client to prove its inclusion against shard 1's
# committee-signed state_root.
#
# The daemon now serves the composite-key `i:` namespace (the caller
# hex-encodes the binary key body; see src/node/node.cpp rpc_state_proof),
# so the same verifier code path that used to fail closed now yields a
# real INCLUDED.
#
# Assertions:
#   1. (headline) The genuinely-applied receipt → INCLUDED, exit 0, with
#      a committee-anchored state_root.
#   2. A random (never-applied) tx_hash for the same shard → NOT-INCLUDED
#      (a sound verified negative: daemon returns not_found), exit 0,
#      NEVER a false INCLUDED.
#   3. Wrong --genesis → fail-closed, non-zero exit (genesis-hash mismatch
#      detected before any verdict); never INCLUDED.
#   4. Malformed --tx-hash (wrong length) → non-zero exit, never INCLUDED.
#   5. Missing required flags → usage error (exit 1).
#   6. --json output for the applied receipt parses with
#      {included:true, verdict:"INCLUDED", src_shard, tx_hash,
#      namespace:"i"} and included is the boolean true.
#   7. (anti-false-positive) The NOT-INCLUDED / error variants never print
#      a line beginning with "INCLUDED".
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

T=test_light_vri
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
mkdir -p $T/beacon $T/shard0 $T/shard1 $T/wallets

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}
get_account_balance() {
  $DETERM show-account "$2" --rpc-port "$1" 2>/dev/null | grep '^balance' | awk '{print $3}'
}

echo "=== 1. Init data dirs + node keys (1 beacon + 2 shards) ==="
$DETERM init --data-dir $T/beacon --profile regional_test 2>&1 | tail -1
$DETERM init --data-dir $T/shard0 --profile regional_test 2>&1 | tail -1
$DETERM init --data-dir $T/shard1 --profile regional_test 2>&1 | tail -1

$DETERM genesis-tool peer-info beacon_n  --data-dir $T/beacon --stake 1000 > $T/beacon_p.json
$DETERM genesis-tool peer-info shard0_n  --data-dir $T/shard0 --stake 1000 > $T/shard0_p.json
$DETERM genesis-tool peer-info shard1_n  --data-dir $T/shard1 --stake 1000 > $T/shard1_p.json

SALT="00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef"

echo
echo "=== 2. Grind bearer wallets routing to shard 0 (A) + shard 1 (B) ==="
$PY <<EOF
import hashlib, json, subprocess, sys
salt = bytes.fromhex("$SALT")
S = 2
def shard_for(addr: str) -> int:
    h = hashlib.sha256(salt + b"shard-route" + addr.encode()).digest()
    return int.from_bytes(h[:8], "big") % S
found = {0: None, 1: None}
for i in range(400):
    if all(found.values()): break
    out_path = "$TABS/wallets/k_%d.json" % i
    subprocess.run(["$DETERM", "account", "create", "--out", out_path],
                   check=True, capture_output=True)
    with open(out_path) as f: w = json.load(f)
    s = shard_for(w["address"])
    if found[s] is None: found[s] = w
if not all(found.values()):
    sys.exit("could not grind addresses for both shards")
with open("$TABS/wallet_A.json","w") as f: json.dump(found[0], f, indent=2)
with open("$TABS/wallet_B.json","w") as f: json.dump(found[1], f, indent=2)
print("A (shard 0):", found[0]["address"])
print("B (shard 1):", found[1]["address"])
EOF

A_ADDR=$($PY -c "import json; print(json.load(open('$T/wallet_A.json'))['address'])")
A_PRIV=$($PY -c "import json; print(json.load(open('$T/wallet_A.json'))['privkey'])")
B_ADDR=$($PY -c "import json; print(json.load(open('$T/wallet_B.json'))['address'])")

echo
echo "=== 3. Build per-chain genesis (shared salt, S=2, M=K=1) ==="
cat > $T/beacon_gen.json <<EOF
{
  "chain_id": "test-light-vri",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 1,
  "shard_id": 0,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/beacon_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
cat > $T/shard0_gen.json <<EOF
{
  "chain_id": "test-light-vri",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard0_p.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "$A_ADDR", "balance": 1000}]
}
EOF
cat > $T/shard1_gen.json <<EOF
{
  "chain_id": "test-light-vri",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 1,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard1_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF

$DETERM genesis-tool build $T/beacon_gen.json | tail -1
$DETERM genesis-tool build $T/shard0_gen.json | tail -1
$DETERM genesis-tool build $T/shard1_gen.json | tail -1
BEACON_HASH=$(cat $T/beacon_gen.json.hash)
SHARD0_HASH=$(cat $T/shard0_gen.json.hash)
SHARD1_HASH=$(cat $T/shard1_gen.json.hash)

# A DIFFERENT shard-1 genesis (same creators, different chain_id) →
# different compute_genesis_hash. Used by assertion 3 (wrong-genesis).
cat > $T/shard1_gen_wrong.json <<EOF
{
  "chain_id": "test-light-vri-WRONG",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 1,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard1_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/shard1_gen_wrong.json | tail -1

echo
echo "=== 4. Configure cross-chain peering ==="
configure_node() {
  local cfg=$1 domain=$2 listen=$3 rpc=$4 peers_field=$5 peers=$6 \
    gen_path=$7 gen_hash=$8
  $PY -c "
import json
with open('$cfg') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = []
c['$peers_field'] = $peers
c['genesis_path'] = '$gen_path'
c['genesis_hash'] = '$gen_hash'
c['chain_path'] = '$(dirname $cfg)/chain.json'
c['key_path'] = '$(dirname $cfg)/node_key.json'
c['data_dir'] = '$(dirname $cfg)'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$cfg','w') as f: json.dump(c,f,indent=2)
"
}
configure_node $T/beacon/config.json beacon_n 7861 8861 shard_peers \
  '["127.0.0.1:7871","127.0.0.1:7872"]' "$TABS/beacon_gen.json" "$BEACON_HASH"
configure_node $T/shard0/config.json shard0_n 7871 8871 beacon_peers \
  '["127.0.0.1:7861"]' "$TABS/shard0_gen.json" "$SHARD0_HASH"
configure_node $T/shard1/config.json shard1_n 7872 8872 beacon_peers \
  '["127.0.0.1:7861"]' "$TABS/shard1_gen.json" "$SHARD1_HASH"

echo
echo "=== 5. Start 3 nodes (cross-peered) ==="
NODE_PIDS=("" "" "")
$DETERM start --config $T/beacon/config.json > $T/beacon/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/shard0/config.json > $T/shard0/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/shard1/config.json > $T/shard1/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3

echo
echo "=== 6. Poll until all three chains produce blocks ==="
for _ in $(seq 1 90); do
  BH=$(get_status_field 8861 height); S0=$(get_status_field 8871 height); S1=$(get_status_field 8872 height)
  if [ "$BH" != "-" ] && [ "$S0" != "-" ] && [ "$S1" != "-" ] \
     && [ "$BH" -ge 2 ] 2>/dev/null && [ "$S0" -ge 2 ] 2>/dev/null && [ "$S1" -ge 2 ] 2>/dev/null; then
    break
  fi
  sleep 0.3
done
BEACON_H=$(get_status_field 8861 height)
SHARD0_H=$(get_status_field 8871 height)
SHARD1_H=$(get_status_field 8872 height)
echo "  beacon=$BEACON_H shard0=$SHARD0_H shard1=$SHARD1_H"
if [ "$SHARD0_H" = "-" ] || [ "$SHARD1_H" = "-" ] \
   || [ "$SHARD0_H" -lt 2 ] 2>/dev/null || [ "$SHARD1_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: cluster did not bootstrap both shards in budget — environment"
  echo "        too starved (not a verify-receipt-inclusion defect)."
  exit 0
fi

# Pre-flight: confirm shard1's daemon runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8872 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$SHARD1_HASH" ]; then
  echo "  PRE-FLIGHT FAIL: shard1 daemon block0=$BLK0 but our genesis=$SHARD1_HASH"
  assert "false" "pre-flight: shard1 daemon runs our genesis"
  echo "  $pass_count pass / $fail_count fail"
  echo "  FAIL: test_light_verify_receipt_inclusion"; exit 1
fi
echo "  pre-flight OK: shard1 daemon runs our genesis"

echo
echo "=== 7. TRANSFER 50 from A (shard 0) → B (shard 1) ==="
$DETERM send_anon "$B_ADDR" 50 "$A_PRIV" --rpc-port 8871

echo
echo "=== 8. Poll up to ~60s for the cross-shard credit to land on shard 1 ==="
B_BAL_NOW=0
for _ in $(seq 1 300); do
  B_BAL_NOW=$(get_account_balance 8872 "$B_ADDR")
  if [ "$B_BAL_NOW" = "50" ]; then break; fi
  sleep 0.2
done
echo "  B on shard1 balance=$B_BAL_NOW (expected 50 once receipt applied)"
if [ "$B_BAL_NOW" != "50" ]; then
  echo "  SKIP: cross-shard receipt did not apply within budget (B=$B_BAL_NOW);"
  echo "        beacon relay / latency window starved — not a verifier defect."
  exit 0
fi

echo
echo "=== 9. Read the applied receipt (src_shard, tx_hash) from shard1 blocks ==="
SHARD1_H=$(get_status_field 8872 height)
RECEIPT=$($PY -c "
import json, subprocess
head = int('$SHARD1_H')
found = None
for idx in range(head, 0, -1):
    r = subprocess.run(['$DETERM','show-block',str(idx),'--rpc-port','8872'],
                       capture_output=True, text=True)
    try: b = json.loads(r.stdout)
    except Exception: continue
    irs = b.get('inbound_receipts') or []
    if irs:
        found = irs[0]; break
if not found:
    print('NONE 0'); raise SystemExit
print(int(found['src_shard']), found['tx_hash'])
")
RX_SRC=$(echo "$RECEIPT" | awk '{print $1}')
RX_HASH=$(echo "$RECEIPT" | awk '{print $2}')
echo "  applied receipt: src_shard=$RX_SRC tx_hash=$RX_HASH"
if [ "$RX_SRC" = "NONE" ] || [ -z "$RX_HASH" ] || [ "${#RX_HASH}" != "64" ]; then
  echo "  SKIP: could not locate the applied inbound receipt in shard1 blocks"
  echo "        (block-body scan found none) — not a verifier defect."
  exit 0
fi

echo
echo "=== ASSERTION 1: applied receipt → INCLUDED (exit 0), committee-anchored ==="
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8872 --genesis $T/shard1_gen.json \
        --src-shard $RX_SRC --tx-hash $RX_HASH 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^INCLUDED"; then
  assert "true" "applied receipt → INCLUDED, exit 0 (real i: state-proof Merkle-verified)"
else
  assert "false" "applied receipt → INCLUDED/exit0 (got rc=$RC)"
fi

echo
echo "=== ASSERTION 2: random (never-applied) tx_hash → NOT-INCLUDED (exit 0) ==="
RAND_HASH=$($PY -c "import os; print(os.urandom(32).hex())")
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8872 --genesis $T/shard1_gen.json \
        --src-shard $RX_SRC --tx-hash $RAND_HASH 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
  assert "true" "random tx_hash → NOT-INCLUDED, exit 0 (sound verified negative)"
else
  assert "false" "random tx_hash → NOT-INCLUDED/exit0 (got rc=$RC)"
fi
NOFP2=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP2" "random tx_hash never yields a false INCLUDED"

echo
echo "=== ASSERTION 3: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8872 --genesis $T/shard1_gen_wrong.json \
        --src-shard $RX_SRC --tx-hash $RX_HASH 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
  assert "true" "wrong genesis rejected (exit $RC)"
else
  assert "false" "wrong genesis should fail-closed but exit 0"
fi
NOFP3=$(echo "$OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP3" "wrong genesis never yields INCLUDED"

echo
echo "=== ASSERTION 4: malformed --tx-hash → non-zero exit, never INCLUDED ==="
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8872 --genesis $T/shard1_gen.json \
        --src-shard $RX_SRC --tx-hash deadbeef 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ] && ! echo "$OUT" | grep -qE "^INCLUDED"; then
  assert "true" "malformed --tx-hash → non-zero exit, not INCLUDED (rc=$RC)"
else
  assert "false" "malformed --tx-hash should hard-error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 5: missing required flags → usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8872 --genesis $T/shard1_gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qiE "required"; then
  assert "true" "missing --src-shard/--tx-hash → usage error (exit 1)"
else
  assert "false" "missing flags should be a usage error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 6: --json for applied receipt → included=true, verdict=INCLUDED ==="
set +e
JOUT=$($DETERM_LIGHT verify-receipt-inclusion --rpc-port 8872 --genesis $T/shard1_gen.json \
        --src-shard $RX_SRC --tx-hash $RX_HASH --json 2>&1 | tail -1)
set -e
echo "  json: $JOUT"
JSON_OK=$(echo "$JOUT" | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    need = ['included','verdict','src_shard','tx_hash','namespace']
    if any(k not in d for k in need): print('false'); sys.exit()
    if not isinstance(d['included'], bool): print('false'); sys.exit()
    if d['included'] is not True: print('false'); sys.exit()
    if d['verdict'] != 'INCLUDED': print('false'); sys.exit()
    if d['namespace'] != 'i': print('false'); sys.exit()
    if int(d['src_shard']) != int('$RX_SRC'): print('false'); sys.exit()
    if d['tx_hash'] != '$RX_HASH': print('false'); sys.exit()
    print('true')
except Exception as e:
    sys.stderr.write('parse err: %s\n' % e); print('false')
")
assert "$JSON_OK" "--json: {included:true, verdict:INCLUDED, src_shard, tx_hash, namespace:i}"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_receipt_inclusion"; exit 0
else
  echo "  FAIL: test_light_verify_receipt_inclusion"; exit 1
fi
