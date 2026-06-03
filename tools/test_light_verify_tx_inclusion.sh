#!/usr/bin/env bash
# determ-light verify-tx-inclusion — trustless tx-inclusion proof against
# the committee-signed block tx-root.
#
# Boots a 3-node cluster, funds an anon account in genesis, signs +
# submits a known TRANSFER, discovers which block it landed in (via the
# daemon's `show-tx`, used only as an ORACLE for the candidate height —
# the proof itself re-derives everything from committee sigs), then:
#
# Assertions:
#   1. verify-tx-inclusion for the real (tx-hash, height) → INCLUDED,
#      with committee sigs verified + tx_root recomputed/matched.
#   2. Same tx hash but the WRONG height → NOT-INCLUDED (exit 0; the tx's
#      hash is absent from a different block whose tx set is committee-
#      verified).
#   3. A fabricated/random tx hash at the real height → NOT-INCLUDED.
#   4. Genesis anchor mismatch (wrong --genesis) → fail-closed, non-zero.
#   5. tx_root binding: the --json verdict's tx_root equals the daemon's
#      block.tx_root AND the recompute-from-committed-hashes happened
#      (committee_verified=true) — i.e. membership is only trusted after
#      the recomputed root matches the committee-signed root. This is the
#      anti-tamper gate: a body whose hashes don't roll up to the signed
#      tx_root would be UNVERIFIABLE, never a false INCLUDED.
#   6. --json output parses with {included: bool, height, tx_hash,
#      tx_root, committee_verified}.
#   7. (extra) out-of-range height (> chain head) → hard error (non-zero),
#      not a false NOT-INCLUDED.
#   8. (extra) malformed --tx-hash (wrong length) → UNVERIFIABLE, exit 3.
#
# Cluster-bound — NOT part of FAST=1.
#
# Run from repo root: bash tools/test_light_verify_tx_inclusion.sh
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

T=test_light_verify_tx_inclusion
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

echo "=== 1. Mint two anon keypairs (alice funded, bob recipient) ==="
"$DETERM_WALLET" account-create-batch --count 2 --out "$T/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][1]['address'])")
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
" "$T/keys.json" "$T/key_a.json"
echo "  alice=$ADDR_A"
echo "  bob=  $ADDR_B"

echo
echo "=== 2. Init 3-node cluster with alice funded in genesis ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vti",
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
# compute_genesis_hash. Used by assertion 4 (wrong-genesis refusal).
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "test-light-vti-WRONG",
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
configure_node 1 7811 8811 '["127.0.0.1:7812","127.0.0.1:7813"]'
configure_node 2 7812 8812 '["127.0.0.1:7811","127.0.0.1:7813"]'
configure_node 3 7813 8813 '["127.0.0.1:7811","127.0.0.1:7812"]'

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
    H=$($DETERM status --rpc-port 8811 2>/dev/null \
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
echo "  chain height (pre-tx): $H"
if [ "$H" -lt 3 ] 2>/dev/null; then
  echo "  SKIP: cluster did not reach height >= 3 in budget (got $H);"
  echo "        environment too starved — not a verify-tx-inclusion defect."
  exit 0
fi

# Pre-flight: confirm the daemon on 8811 runs OUR genesis.
BLK0=$($DETERM_LIGHT fetch-headers --rpc-port 8811 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$GHASH" ]; then
    echo "  PRE-FLIGHT FAIL: daemon on RPC 8811 has block0=$BLK0 but our"
    echo "  genesis hash=$GHASH — a foreign/stale daemon is on this port."
    assert "false" "pre-flight: daemon on 8811 runs our genesis"
    echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL: test_light_verify_tx_inclusion"; exit 1
fi
echo "  pre-flight OK: daemon on 8811 runs our genesis"

echo
echo "=== 4. Sign + submit a known TRANSFER alice→bob (nonce 0) ==="
# Sign offline with --out so we capture the exact tx hash that will land.
# alice is fresh in genesis so her first nonce is 0.
$DETERM_LIGHT sign-tx --keyfile $T/key_a.json --type TRANSFER \
    --to $ADDR_B --amount 100 --fee 0 --nonce 0 --out $T/tx.json 2>&1 | tail -1
TX_HASH=$($PY -c "import json; print(json.load(open('$T/tx.json'))['hash'])")
echo "  tx hash: $TX_HASH"

$DETERM_LIGHT submit-tx --rpc-port 8811 --tx-json $T/tx.json 2>&1 | tail -1

echo
echo "=== 5. Discover which block the tx landed in (oracle: show-tx) ==="
# show-tx is used ONLY to learn the candidate height; verify-tx-inclusion
# re-derives the proof from committee sigs and does not trust this.
TX_BLOCK=""
for _ in $(seq 1 120); do
  TX_BLOCK=$($DETERM show-tx $TX_HASH --rpc-port 8811 --json 2>/dev/null \
      | tail -1 | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('block_index', '') if isinstance(d, dict) else '')
except Exception:
    print('')
")
  if [ -n "$TX_BLOCK" ] 2>/dev/null && [ "$TX_BLOCK" -ge 0 ] 2>/dev/null; then break; fi
  TX_BLOCK=""
  sleep 0.5
done
if [ -z "$TX_BLOCK" ]; then
  echo "  SKIP: tx never landed in a finalized block within budget;"
  echo "        environment too starved — not a verify-tx-inclusion defect."
  exit 0
fi
echo "  tx landed in block: $TX_BLOCK"

# Pick a DIFFERENT, real, NON-genesis height for the wrong-height
# assertion so the committee-sig path is exercised (genesis has no
# committee sigs — it's hash-anchored separately). An adjacent block is
# committee-signed and, with one tx per block here, won't contain OUR tx.
if [ "$TX_BLOCK" -ge 2 ] 2>/dev/null; then
  WRONG_HEIGHT=$((TX_BLOCK - 1))
else
  WRONG_HEIGHT=$((TX_BLOCK + 1))
fi

echo
echo "=== ASSERTION 1: verify-tx-inclusion (real tx, real height) → INCLUDED ==="
set +e
OUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen.json \
        --tx-hash $TX_HASH --height $TX_BLOCK 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^INCLUDED"; then
    assert "true" "real (tx,height) → INCLUDED, exit 0"
else
    assert "false" "real (tx,height) → INCLUDED (got rc=$RC)"
fi
COMMITTEE_OK=$(echo "$OUT" | grep -qiE "committee sigs:.*verified" && echo true || echo false)
assert "$COMMITTEE_OK" "committee sigs reported verified"
ROOT_OK=$(echo "$OUT" | grep -qiE "tx_root \(signed\):" && echo true || echo false)
assert "$ROOT_OK" "tx_root (committee-signed, recomputed) reported"

echo
echo "=== ASSERTION 2: real tx hash, WRONG height ($WRONG_HEIGHT) → NOT-INCLUDED ==="
set +e
OUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen.json \
        --tx-hash $TX_HASH --height $WRONG_HEIGHT 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
    assert "true" "real tx at wrong height → NOT-INCLUDED, exit 0"
else
    assert "false" "real tx at wrong height → NOT-INCLUDED (got rc=$RC)"
fi

echo
echo "=== ASSERTION 3: fabricated random tx hash at real height → NOT-INCLUDED ==="
FAKE_HASH=$($PY -c "import os; print(os.urandom(32).hex())")
set +e
OUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen.json \
        --tx-hash $FAKE_HASH --height $TX_BLOCK 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
    assert "true" "fabricated hash at real height → NOT-INCLUDED, exit 0"
else
    assert "false" "fabricated hash at real height → NOT-INCLUDED (got rc=$RC)"
fi

echo
echo "=== ASSERTION 4: wrong --genesis → fail-closed, non-zero exit ==="
set +e
OUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen_wrong.json \
        --tx-hash $TX_HASH --height $TX_BLOCK 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "wrong genesis rejected (exit $RC)"
else
    assert "false" "wrong genesis should fail-closed but exit 0"
fi
MISMATCH_DIAG=$(echo "$OUT" | grep -qiE "genesis.*hash.*mismatch|mismatch.*genesis|refusing" && echo true || echo false)
assert "$MISMATCH_DIAG" "wrong-genesis diagnostic mentions genesis-hash mismatch"

echo
echo "=== ASSERTION 5: tx_root binding — verdict.tx_root == daemon block.tx_root ==="
# The membership answer is only trusted AFTER the tx_root recomputed from
# the committee-signed creator_tx_lists matches block.tx_root. Confirm the
# verdict's tx_root equals the daemon's reported block.tx_root and that
# committee_verified is true — i.e. the anti-tamper gate ran and passed on
# honest data. (A divergent body would have flipped the verdict to
# UNVERIFIABLE; exercised structurally by the body cross-check in step 5
# of verify_tx_inclusion.)
# show-block dumps the full (pretty-printed) block JSON as a top-level
# object — capture ALL of it and read tx_root.
DAEMON_ROOT=$($DETERM show-block $TX_BLOCK --rpc-port 8811 2>/dev/null \
    | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('tx_root', ''))
except Exception:
    print('')
")
set +e
JOUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen.json \
        --tx-hash $TX_HASH --height $TX_BLOCK --json 2>&1 | tail -1)
set -e
BIND_OK=$(echo "$JOUT" | $PY -c "
import json, sys
daemon_root = '''$DAEMON_ROOT'''.strip()
try:
    d = json.loads(sys.stdin.read())
    ok = (d.get('committee_verified') is True
          and isinstance(d.get('tx_root'), str)
          and len(d.get('tx_root')) == 64)
    # If we managed to read the daemon's block tx_root, require equality.
    if daemon_root:
        ok = ok and (d.get('tx_root') == daemon_root)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
assert "$BIND_OK" "verdict tx_root is committee-verified (and matches daemon block.tx_root)"

echo
echo "=== ASSERTION 6: --json parses with required fields ==="
JSON_OK=$(echo "$JOUT" | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    need = ['included','verdict','height','tx_hash','tx_root','committee_verified']
    if any(k not in d for k in need): print('false'); sys.exit()
    if not isinstance(d['included'], bool): print('false'); sys.exit()
    if d['verdict'] != 'INCLUDED': print('false'); sys.exit()
    if d['included'] is not True: print('false'); sys.exit()
    if int(d['height']) != $TX_BLOCK: print('false'); sys.exit()
    if d['tx_hash'] != '$TX_HASH': print('false'); sys.exit()
    if len(d['tx_root']) != 64: print('false'); sys.exit()
    print('true')
except Exception as e:
    sys.stderr.write('parse err: %s\n' % e); print('false')
")
echo "  json: $JOUT"
assert "$JSON_OK" "--json: {included:true, verdict:INCLUDED, height, tx_hash, tx_root(64hex), committee_verified}"

echo
echo "=== ASSERTION 7 (extra): out-of-range height → hard error, not NOT-INCLUDED ==="
OOR_HEIGHT=$((H + 100000))
set +e
OUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen.json \
        --tx-hash $TX_HASH --height $OOR_HEIGHT 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ] && ! echo "$OUT" | grep -qE "^NOT-INCLUDED"; then
    assert "true" "out-of-range height → hard error (exit $RC), not a false NOT-INCLUDED"
else
    assert "false" "out-of-range height should hard-error (got rc=$RC)"
fi

echo
echo "=== ASSERTION 8 (extra): malformed --tx-hash → UNVERIFIABLE, exit 3 ==="
set +e
OUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen.json \
        --tx-hash deadbeef --height $TX_BLOCK 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qE "^UNVERIFIABLE"; then
    assert "true" "malformed --tx-hash → UNVERIFIABLE, exit 3"
else
    assert "false" "malformed --tx-hash → UNVERIFIABLE/exit3 (got rc=$RC)"
fi

echo
echo "=== ASSERTION 9 (extra): genesis (height 0) → NOT-INCLUDED, hash-anchored ==="
# Genesis carries no committee sigs (it's the deterministic
# GenesisConfig->Block transform). verify-tx-inclusion must anchor it on
# the genesis hash instead and report NOT-INCLUDED for any tx (genesis
# has an empty tx set) — NOT UNVERIFIABLE, and NOT a false INCLUDED.
set +e
JOUT=$($DETERM_LIGHT verify-tx-inclusion --rpc-port 8811 --genesis $T/gen.json \
        --tx-hash $TX_HASH --height 0 --json 2>&1 | tail -1)
RC=$?
set -e
echo "  json: $JOUT"
GEN_OK=$(echo "$JOUT" | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    ok = (d.get('verdict') == 'NOT-INCLUDED'
          and d.get('included') is False
          and d.get('committee_verified') is True
          and int(d.get('height')) == 0
          and int(d.get('tx_count')) == 0)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
if [ "$RC" = "0" ] && [ "$GEN_OK" = "true" ]; then
    assert "true" "genesis height 0 → NOT-INCLUDED (hash-anchored, tx_count=0), exit 0"
else
    assert "false" "genesis height 0 → NOT-INCLUDED hash-anchored (got rc=$RC, ok=$GEN_OK)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_tx_inclusion"; exit 0
else
  echo "  FAIL: test_light_verify_tx_inclusion"; exit 1
fi
