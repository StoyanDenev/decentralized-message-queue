#!/usr/bin/env bash
# determ-light verify-ct-block — RPC-driven CT block verifier (A3 composition).
#
# Fetches block[H] from a live daemon and proves, in ONE command against the
# pinned genesis:
#   (1) ANCHOR   — H chains to genesis + is committee-attested (verify-state-
#                  root / S-042 successor binding) -> committee-anchored block_hash.
#   (2) BODY-PIN — the full body the daemon serves recomputes to that committee-
#                  anchored block_hash (a doctored body fails closed).
#   (3) CT-PROOFS— every confidential tx re-verified CLIENT-SIDE.
#
# This test boots a 3-node cluster and exercises the ANCHOR + BODY-PIN + vacuous
# CT path on real (non-CT) blocks, plus the fail-closed negatives. The
# CT-PROOFS-with-actual-CT-txs path (real SHIELD/UNSHIELD/DCT1 proofs) is covered
# by tools/test_light_verify_ct.sh (block-verify CT-PROOFS on fixtures) — this
# command calls the SAME verify_ct_transactions, so it inherits that coverage;
# here we validate the NEW composition wiring (fetch + anchor + hash-pin) that
# block-verify's offline file path doesn't exercise.
#
# Assertions:
#   1. verify-ct-block at a mid-height H (has a signed successor) -> rc=0, text
#      "OK", a "body pin" line, and a "CT-PROOFS: 0 of 0 ... vacuous" line.
#   2. --json shape: {height, committee_verified:true, body_pinned:true, ok:true,
#      ct_txs:0, block_hash 64-hex}.
#   3. Wrong --genesis -> fail-closed (rc!=0, GENESIS HASH MISMATCH).
#   4. Height beyond head -> clean non-zero (no crash), detail names the head bound.
#   5. EXACT head index -> fail-closed (no committee-signed successor): rc!=0 and
#      the --json record does NOT claim committee_verified=true.
#   6. Genesis H=0 -> anchored by genesis hash, committee_verified=true, vacuous CT.
#
# Cluster-bound (boots 3 nodes) — do NOT add to FAST=1.
#
# Run from repo root: bash tools/test_light_verify_ct_block.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_ct_block
TABS=$PROJECT_ROOT/$T

# Dedicated port block (795x listen / 895x RPC), distinct from every other
# cluster-bound light test so this runs alongside them without collisions.
L1=7951; L2=7952; L3=7953
R1=8951; R2=8952; R3=8953

declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
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

echo "=== 1. Init 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-vcb",
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

# A DIFFERENT genesis for the anchor-mismatch assertion (#3).
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "test-light-vcb-WRONG",
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
echo "=== 2. Wait for chain past height 10 ==="
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
wait_height 14
echo "  chain height: $H"

BLK0=$($DETERM_LIGHT fetch-headers --rpc-port $R1 --from 0 --count 1 2>/dev/null \
        | tail -1 | $PY -c "
import json, sys
try: print(json.loads(sys.stdin.read())['headers'][0]['block_hash'])
except Exception: print('')
")
if [ "$BLK0" != "$GHASH" ]; then
    echo "  PRE-FLIGHT FAIL: daemon on RPC $R1 block0=$BLK0 != genesis $GHASH"
    assert "false" "pre-flight: daemon on $R1 runs our genesis"
    echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL: test_light_verify_ct_block"; exit 1
fi
echo "  pre-flight OK: daemon on $R1 runs our genesis ($GHASH)"

if [ "$H" -lt 11 ] 2>/dev/null; then
    echo "  SKIP: chain only reached height $H in the time budget (need >=11)."
    echo "        Environment too starved; not a verify-ct-block defect."
    exit 0
fi

HEAD_INDEX=$((H - 1))
MID=$((HEAD_INDEX / 2))
[ "$MID" -lt 1 ] && MID=1
echo "  head_index=$HEAD_INDEX, sampling mid-height H=$MID"

echo
echo "=== 3. verify-ct-block at H=$MID (text mode) — assertion 1 ==="
set +e
OUT=$($DETERM_LIGHT verify-ct-block --rpc-port $R1 --genesis $T/gen.json --height $MID 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] \
   && echo "$OUT" | grep -q "^OK" \
   && echo "$OUT" | grep -qi "body pin:" \
   && echo "$OUT" | grep -qiE "CT-PROOFS: *0 of 0"; then
    assert "true" "verify-ct-block H=$MID: rc=0, OK, body-pin line, vacuous CT (0 of 0)"
else
    assert "false" "verify-ct-block H=$MID: rc=0 (got $RC) + OK + body-pin + 0-of-0 CT"
fi

echo
echo "=== 4. --json shape + committee_verified/body_pinned/ok (assertion 2) ==="
set +e
JOUT=$($DETERM_LIGHT verify-ct-block --rpc-port $R1 --genesis $T/gen.json --height $MID --json 2>&1)
JRC=$?
set -e
echo "$JOUT" | tail -1
SHAPE_OK=$(echo "$JOUT" | tail -1 | MID=$MID $PY -c "
import json, sys, os
mid = int(os.environ['MID'])
try:
    d = json.loads(sys.stdin.read())
    ok = (d.get('height') == mid
          and d.get('committee_verified') is True
          and d.get('body_pinned') is True
          and d.get('ok') is True
          and d.get('ct_txs') == 0
          and len(d.get('block_hash','')) == 64)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
if [ "$JRC" = "0" ] && [ "$SHAPE_OK" = "true" ]; then
    assert "true" "--json: committee_verified+body_pinned+ok=true, ct_txs=0, 64-hex block_hash"
else
    assert "false" "--json shape (rc=$JRC shape_ok=$SHAPE_OK)"
fi

echo
echo "=== 5. Wrong --genesis -> fail-closed (assertion 3) ==="
set +e
WOUT=$($DETERM_LIGHT verify-ct-block --rpc-port $R1 --genesis $T/gen_wrong.json --height $MID 2>&1)
WRC=$?
set -e
echo "$WOUT" | tail -2
if [ "$WRC" != "0" ] && echo "$WOUT" | grep -qi "GENESIS HASH MISMATCH"; then
    assert "true" "wrong --genesis fails closed (rc=$WRC, GENESIS HASH MISMATCH)"
else
    assert "false" "wrong --genesis fails closed (got rc=$WRC)"
fi

echo
echo "=== 6. Height beyond head -> clean non-zero, no crash (assertion 4) ==="
set +e
BOUT=$($DETERM_LIGHT verify-ct-block --rpc-port $R1 --genesis $T/gen.json --height 99999 2>&1)
BRC=$?
set -e
echo "$BOUT" | tail -2
# Fail-closed + handled (rc 1 or 3, NOT a 139/signal crash) + detail names head.
if { [ "$BRC" = "1" ] || [ "$BRC" = "3" ]; } \
   && echo "$BOUT" | grep -qiE "beyond chain head|head"; then
    assert "true" "height beyond head -> clean handled non-zero (rc=$BRC)"
else
    assert "false" "height beyond head -> clean error (got rc=$BRC)"
fi

echo
echo "=== 7. EXACT head index fails closed (assertion 5) ==="
HEAD_NOW=$($DETERM status --rpc-port $R1 2>/dev/null | $PY -c "
import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
HEAD_IDX_NOW=$((HEAD_NOW - 1))
set +e
HOUT=$($DETERM_LIGHT verify-ct-block --rpc-port $R1 --genesis $T/gen.json --height $HEAD_IDX_NOW --json 2>&1)
HRC=$?
set -e
echo "$HOUT" | tail -1
HEAD_OK=$(echo "$HOUT" | tail -1 | HRC=$HRC $PY -c "
import json, sys, os
rc = int(os.environ.get('HRC','1'))
try: cv = json.loads(sys.stdin.read()).get('committee_verified')
except Exception: cv = None
if rc != 0: print('true' if cv is not True else 'false')     # fail-closed: must not claim verified
else:       print('true' if cv is True else 'false')         # advanced: must be genuinely verified
")
assert "$HEAD_OK" "exact head index fails closed (rc=$HRC; no committee-signed successor to bind H)"

echo
echo "=== 8. Genesis H=0 anchored by hash, vacuous CT (assertion 6) ==="
set +e
G0=$($DETERM_LIGHT verify-ct-block --rpc-port $R1 --genesis $T/gen.json --height 0 --json 2>&1)
G0RC=$?
set -e
echo "$G0" | tail -1
G0_OK=$(echo "$G0" | tail -1 | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    ok = (d.get('height') == 0
          and d.get('committee_verified') is True
          and d.get('body_pinned') is True
          and d.get('ct_txs') == 0
          and d.get('ok') is True)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
if [ "$G0RC" = "0" ] && [ "$G0_OK" = "true" ]; then
    assert "true" "genesis H=0 anchored by hash, body-pinned, vacuous CT, ok=true"
else
    assert "false" "genesis H=0 handling (got rc=$G0RC ok=$G0_OK)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_ct_block"; exit 0
else
  echo "  FAIL: test_light_verify_ct_block"; exit 1
fi
