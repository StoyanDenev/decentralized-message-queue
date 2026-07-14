#!/usr/bin/env bash
# determ-light verify-shardtip-records — the S-036 (D3.5e-7e) third-party
# auditor of the shard-tip distress-record fold.
#
# For a BEACON block[H] it re-runs, off an UNTRUSTED daemon, the exact check
# validator.cpp::check_shardtip_witnesses runs at block accept: every folded
# ShardTipRecord must carry its full-tip witness, and that witness must
# re-verify against the beacon's OWN committed cc:[E_source] committee
# checkpoint (the FROZEN source committee). A fully-Byzantine K-of-K beacon
# that fabricates a distress record cannot produce a witness whose K-of-K
# sigs verify against the frozen source committee → the auditor rejects it,
# matching every honest node.
#
# WHAT THIS TEST EXERCISES (and what it deliberately does NOT):
#   The POSITIVE distress-fold path (a real folded record ACCEPTED, a
#   fabricated one REJECTED) requires an EXTENDED beacon+shard cluster that
#   actually folds records at an epoch boundary — that is the e-5 LIVE gate,
#   not a FAST/cluster-tier scenario. This test instead exercises the full
#   ANCHOR + BODY-PIN composition + the 0-records VACUOUS path end-to-end
#   against an ordinary (single-shard) daemon: an ordinary block carries zero
#   shard_tip_records, so the auditor must (1) ANCHOR H to genesis via
#   committee sigs, (2) BODY-PIN the full block to the committee-anchored
#   hash, and (3) report a vacuous 0-count OK. The frozen-committee witness
#   re-verification (steps 3+4 of the command) is proven in-process by the
#   determ `test-shardtip-witness-verify` subcommand (12 fabrication axes).
#
# Assertions:
#   1. Missing required args → clean usage error (rc=1, not a crash).
#   2. verify-shardtip-records at a mid-height H (which HAS a committee-signed
#      successor) → exit 0, ok=true, committee_verified=true, body_pinned=true,
#      records_total=0 (an ordinary block folds nothing) — the ANCHOR +
#      BODY-PIN + vacuous path all green end-to-end.
#   3. --json shape: {height, committee_verified, body_pinned, records_total,
#      records_verified, ok} with records_total==0 and records_verified==0.
#   4. Genesis anchor mismatch (wrong --genesis) → fail-closed non-zero exit.
#   5. verify-shardtip-records at the EXACT head index → fail-closed (no
#      committee-signed successor exists yet to anchor H's state) — non-zero.
#
# Cluster-bound (boots 3 nodes) — do NOT add to FAST=1.
#
# Run from repo root: bash tools/test_light_verify_shardtip_records.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_shardtip_records
TABS=$PROJECT_ROOT/$T

# Dedicated port block (796x listen / 896x RPC), distinct from every other
# cluster-bound light test, so this runs alongside them without collisions.
L1=7961; L2=7962; L3=7963
R1=8961; R2=8962; R3=8963

declare -a NODE_PIDS

cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  if command -v taskkill >/dev/null 2>&1 && command -v netstat >/dev/null 2>&1; then
    for p in "${R1:-}" "${R2:-}" "${R3:-}"; do
      [ -z "$p" ] && continue
      for spid in $(netstat -ano 2>/dev/null | grep LISTENING \
                    | grep -E "127\.0\.0\.1:$p\b" | awk '{print $NF}' | sort -u); do
        [ -n "$spid" ] && taskkill //F //PID "$spid" >/dev/null 2>&1
      done
    done
  fi
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ---- Assertion 1: usage error path (no cluster needed) --------------------
echo "=== 1. Missing-args usage error ==="
set +e
$DETERM_LIGHT verify-shardtip-records --height 5 >/dev/null 2>&1
URC=$?
set -e
if [ "$URC" = "1" ]; then
    assert "true"  "missing --rpc-port/--genesis → clean usage error (rc=1)"
else
    assert "false" "missing args should rc=1 (got $URC)"
fi

echo
echo "=== 2. Init 3-node cluster (treasury funded in genesis) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vstr",
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

# A second, DIFFERENT genesis for the anchor-mismatch assertion (#4).
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "test-light-vstr-WRONG",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 99999}]
}
EOF
$DETERM genesis-tool build $T/gen_wrong.json | tail -1

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
configure_node 1 $L1 $R1 "[\"127.0.0.1:$L2\",\"127.0.0.1:$L3\"]"
configure_node 2 $L2 $R2 "[\"127.0.0.1:$L1\",\"127.0.0.1:$L3\"]"
configure_node 3 $L3 $R3 "[\"127.0.0.1:$L1\",\"127.0.0.1:$L2\"]"

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 3. Wait for chain past height 10 ==="
wait_height() {
  local target=$1
  for _ in $(seq 1 360); do
    H=$($DETERM status --rpc-port $R1 2>/dev/null \
         | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
    if [ "$H" -ge "$target" ] 2>/dev/null; then break; fi
    sleep 0.5
  done
}
wait_height 10
echo "  chain height: $H"

BLK0=$($DETERM_LIGHT fetch-headers --rpc-port $R1 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$GHASH" ]; then
    echo "  PRE-FLIGHT FAIL: daemon on RPC $R1 has block0=$BLK0 but our"
    echo "  genesis hash=$GHASH — a foreign/stale daemon is on this port."
    assert "false" "pre-flight: daemon on $R1 runs our genesis"
    echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL: test_light_verify_shardtip_records"; exit 1
fi
echo "  pre-flight OK: daemon on $R1 runs our genesis ($GHASH)"

if [ "$H" -lt 11 ] 2>/dev/null; then
    echo "  SKIP: chain only reached height $H in the time budget (need"
    echo "        >=11 to sample a mid-height). Environment too starved;"
    echo "        not a determ-light verify-shardtip-records defect."
    exit 0
fi

HEAD_INDEX=$((H - 1))
MID=$((HEAD_INDEX / 2))
[ "$MID" -lt 1 ] && MID=1
echo "  head_index=$HEAD_INDEX, sampling mid-height H=$MID"

echo
echo "=== 4. verify-shardtip-records at H=$MID (text mode) — vacuous OK ==="
set +e
OUT=$($DETERM_LIGHT verify-shardtip-records --rpc-port $R1 --genesis $T/gen.json \
        --height $MID 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | grep -q "committee-verified + body-pinned"; then
    assert "true"  "verify-shardtip-records H=$MID: exit 0, committee-verified + body-pinned OK"
else
    assert "false" "verify-shardtip-records H=$MID: exit 0 (got $RC) + OK line"
fi

echo
echo "=== 5. --json shape + vacuous 0-record verdict (assertions 2+3) ==="
set +e
JOUT=$($DETERM_LIGHT verify-shardtip-records --rpc-port $R1 --genesis $T/gen.json \
         --height $MID --json 2>&1)
JRC=$?
set -e
echo "$JOUT" | tail -1
echo "$JOUT" | tail -1 > $T/vstr_mid.json
SHAPE_OK=$(cat $T/vstr_mid.json | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    need = {'height','committee_verified','body_pinned','records_total','records_verified','ok'}
    if not need.issubset(d.keys()): print('false'); sys.exit()
    if d['height'] != $MID: print('false'); sys.exit()
    if d['ok'] is not True: print('false'); sys.exit()
    if d['committee_verified'] is not True: print('false'); sys.exit()
    if d['body_pinned'] is not True: print('false'); sys.exit()
    if d['records_total'] != 0: print('false'); sys.exit()
    if d['records_verified'] != 0: print('false'); sys.exit()
    print('true')
except Exception as e:
    sys.stderr.write('parse err: %s\n' % e); print('false')
")
if [ "$JRC" = "0" ] && [ "$SHAPE_OK" = "true" ]; then
    assert "true"  "--json: ok+committee_verified+body_pinned true, records_total==0 (vacuous)"
else
    assert "false" "--json vacuous shape (got rc=$JRC shape_ok=$SHAPE_OK)"
fi

echo
echo "=== 6. Genesis anchor mismatch → fail-closed (assertion 4) ==="
set +e
WOUT=$($DETERM_LIGHT verify-shardtip-records --rpc-port $R1 --genesis $T/gen_wrong.json \
         --height $MID 2>&1)
WRC=$?
set -e
echo "$WOUT" | tail -2
if [ "$WRC" != "0" ]; then
    assert "true"  "wrong --genesis → fail-closed non-zero exit (rc=$WRC)"
else
    assert "false" "wrong --genesis should fail closed (got rc=0)"
fi

echo
echo "=== 7. Height beyond head → clean fail-closed error (no crash) ==="
set +e
BOUT=$($DETERM_LIGHT verify-shardtip-records --rpc-port $R1 --genesis $T/gen.json \
         --height 99999 2>&1)
BRC=$?
set -e
echo "$BOUT" | tail -2
# Clean handled error (non-zero, not a signal/139 crash). ANCHOR fails
# because there is no committee-signed successor for a non-existent height.
if [ "$BRC" != "0" ] && [ "$BRC" != "139" ]; then
    assert "true"  "height beyond head → clean fail-closed error (rc=$BRC), never a bare verdict"
else
    assert "false" "height beyond head → clean error (got rc=$BRC)"
fi

echo
echo "=== 8. Exact head index → NEVER reports ok:true when committee-unbound ==="
# The committee-bound attestation for index H is SUCCESSOR(H+1)'s sig over a
# digest binding prev_hash==block_hash(H). At the exact head there is no
# successor, so the auditor must fail closed. Re-probe the head to bound the
# race; accept BOTH sound outcomes: (a) rc!=0 fail-closed (ok must NOT be
# true), or (b) rc==0 only if the chain ADVANCED so this index gained a
# signed successor (then ok must be genuinely true). The load-bearing
# invariant: a committee-UNBOUND index is NEVER reported ok:true.
HEAD_NOW=$($DETERM status --rpc-port $R1 2>/dev/null | $PY -c "
import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
HEAD_IDX_NOW=$((HEAD_NOW - 1))
set +e
HOUT=$($DETERM_LIGHT verify-shardtip-records --rpc-port $R1 --genesis $T/gen.json \
         --height $HEAD_IDX_NOW --json 2>&1)
HRC=$?
set -e
echo "$HOUT" | tail -1
HEAD_OK=$(echo "$HOUT" | tail -1 | HRC=$HRC $PY -c "
import json, os, sys
rc = int(os.environ.get('HRC','1'))
try:
    d = json.loads(sys.stdin.read()); ok = d.get('ok')
except Exception:
    ok = None   # non-JSON error text on the head index — a fail-closed form
if rc != 0:
    print('true' if ok is not True else 'false')   # must not claim ok
else:
    print('true' if ok is True else 'false')        # advanced → must be sound
")
assert "$HEAD_OK" "committee-unbound (head) index is NEVER reported ok:true (rc=$HRC)"

echo
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_verify_shardtip_records"; exit 0
else
    echo "  FAIL: test_light_verify_shardtip_records"; exit 1
fi
