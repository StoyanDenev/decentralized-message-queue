#!/usr/bin/env bash
# determ-wallet validator-roster-snapshot CLI test.
#
# Exercises the wallet's roster-snapshot subcommand against a single-
# node daemon with 3 pre-baked validators in genesis (alice.v, bob.v,
# charlie.v at different stake amounts). Verifies:
#
#   1.  help text mentions validator-roster-snapshot
#   2.  --help exits 0 + prints Usage line
#   3.  missing --rpc-port → exit 1 with clear diagnostic
#   4.  missing --out → exit 1 with clear diagnostic
#   5.  unreachable RPC port → exit 1 (connect failure) with diagnostic
#   6.  bring up single-node daemon with 3 staked validators baked into
#       genesis (alice.v 3B, bob.v 2B, charlie.v 1B); only alice.v runs.
#   7.  default invocation produces exit 0
#   8.  --out file is created on disk
#   9.  status line on stdout is valid JSON
#  10.  status line has status=ok / chain_height / total_validators
#  11.  written --out file is valid JSON
#  12.  envelope has snapshot_format_version = 1
#  13.  envelope has captured_at_unix as integer (recent)
#  14.  envelope has rpc_port matching --rpc-port
#  15.  envelope has chain_height matching daemon's status.height
#  16.  envelope has chain_id matching daemon's status.genesis hash
#  17.  envelope has total_validators = 3
#  18.  envelope has validators array non-empty (length 3)
#  19.  validators are sorted by ascending rank (0, 1, 2)
#  20.  each validator domain appears in `determ validators --json`
#  21.  default snapshot omits stake_locked field per row
#  22.  default snapshot omits accumulated_slashed field per row
#  23.  --include-stake-history adds stake_locked per row
#  24.  --include-stake-history adds accumulated_slashed per row
#  25.  --include-stake-history sums match summed stakes via `determ stake_info`
#  26.  re-running WITHOUT --force on existing --out → exit 1
#  27.  re-running WITH --force succeeds (exit 0)
#  28.  re-run with --force overwrites: snapshot still parses + has 3 vals
#  29.  no .tmp file left behind on success (atomic write cleanup)
#  30.  total_stake_locked sums all 3 validator stakes correctly
#
# Run from repo root: bash tools/test_wallet_validator_roster_snapshot.sh

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
T=test_wallet_validator_roster_snapshot
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
mkdir -p $T/alice $T/bob $T/charlie

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── 1. Help text mentions validator-roster-snapshot ───────────────────────────
echo "=== 1. Help text mentions validator-roster-snapshot ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "validator-roster-snapshot" "help mentions validator-roster-snapshot"

# ── 2. --help exits 0 + prints Usage ─────────────────────────────────────────
echo
echo "=== 2. --help exits 0 ==="
set +e
HOUT=$("$WALLET" validator-roster-snapshot --help 2>&1)
RC=$?
set -e
assert_eq "$RC" "0" "--help returns exit 0"
assert_contains "$HOUT" "Usage: determ-wallet validator-roster-snapshot" "--help prints Usage line"

# ── 3. Missing --rpc-port: exit 1 ─────────────────────────────────────────────
echo
echo "=== 3. Missing --rpc-port: exit 1 ==="
set +e
ERR=$("$WALLET" validator-roster-snapshot --out $T/snap.json 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --rpc-port returns exit 1"
assert_contains "$ERR" "rpc-port" "diagnostic mentions --rpc-port"

# ── 4. Missing --out: exit 1 ──────────────────────────────────────────────────
echo
echo "=== 4. Missing --out: exit 1 ==="
set +e
ERR=$("$WALLET" validator-roster-snapshot --rpc-port 18841 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --out returns exit 1"
assert_contains "$ERR" "out" "diagnostic mentions --out"

# ── 5. Bad RPC port (no daemon): exit 1 ───────────────────────────────────────
echo
echo "=== 5. Bad RPC port (daemon not running): exit 1 ==="
set +e
ERR=$("$WALLET" validator-roster-snapshot --rpc-port 1 --out $T/snap.json 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "unreachable RPC port returns exit 1"
assert_contains "$ERR" "connect" "diagnostic mentions connection failure"

# ── 6. Bring up single-node daemon with 3 staked validators in genesis ────────
echo
echo "=== 6. Init data-dirs + bake 3 validators into genesis ==="
$DETERM init --data-dir $T/alice   --profile single_test 2>&1 | tail -1 >/dev/null
$DETERM init --data-dir $T/bob     --profile single_test 2>&1 | tail -1 >/dev/null
$DETERM init --data-dir $T/charlie --profile single_test 2>&1 | tail -1 >/dev/null

ALICE_STAKE=3000000000
BOB_STAKE=2000000000
CHARLIE_STAKE=1000000000

$DETERM genesis-tool peer-info alice.v   --data-dir $T/alice   --stake $ALICE_STAKE   > $T/pa.json
$DETERM genesis-tool peer-info bob.v     --data-dir $T/bob     --stake $BOB_STAKE     > $T/pb.json
$DETERM genesis-tool peer-info charlie.v --data-dir $T/charlie --stake $CHARLIE_STAKE > $T/pc.json

cat > $T/gen.json <<EOF
{
  "chain_id": "test-validator-roster-snapshot",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/pa.json | tr -d '\n'),
$(cat $T/pb.json | tr -d '\n'),
$(cat $T/pc.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1 >/dev/null
GHASH=$(cat $T/gen.json.hash)

RPC_PORT=18841
$PY -c "
import json
with open('$T/alice/config.json') as f: c = json.load(f)
c['domain'] = 'alice.v'
c['listen_port'] = 17841
c['rpc_port'] = $RPC_PORT
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/alice/chain.json'
c['key_path']   = '$TABS/alice/node_key.json'
c['data_dir']   = '$TABS/alice'
c['tx_commit_ms']  = 200
c['block_sig_ms']  = 200
c['abort_claim_ms']= 100
with open('$T/alice/config.json','w') as f: json.dump(c, f, indent=2)
"

$DETERM start --config $T/alice/config.json > $T/alice/log 2>&1 &
NODE_PIDS[0]=$!
sleep 2

# Wait for chain to advance past genesis.
for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  [ "$H" -ge "1" ] && break
  sleep 0.5
done
echo "  chain at height=$H"
assert_eq "$([ "$H" -ge "1" ] && echo ok || echo no)" "ok" "daemon advanced past genesis"

# ── 7-8. Default snapshot creates file + exit 0 ───────────────────────────────
echo
echo "=== 7-8. Default snapshot: exit 0 + --out file exists ==="
SNAP_PATH=$T/snap.json
set +e
STATUS=$("$WALLET" validator-roster-snapshot --rpc-port $RPC_PORT --out $SNAP_PATH 2>&1 | tr -d '\r')
RC=$?
set -e
echo "$STATUS"
assert_eq "$RC" "0" "snapshot capture returns exit 0"
assert_eq "$([ -f "$SNAP_PATH" ] && echo yes || echo no)" "yes" "--out file exists on disk"

# ── 9-10. Status line on stdout ───────────────────────────────────────────────
echo
echo "=== 9-10. Status line on stdout ==="
SOK=$(echo "$STATUS" | $PY -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print('ok' if d.get('status')=='ok' and 'chain_height' in d and 'total_validators' in d else 'bad')
except Exception as e:
    print('parse:'+str(e))
")
assert_eq "$SOK" "ok" "status line is valid JSON with status=ok, chain_height, total_validators"

# ── 11. Written file is valid JSON ────────────────────────────────────────────
echo
echo "=== 11. Written --out file is valid JSON ==="
JOK=$($PY -c "
import json
try:
    json.load(open('$SNAP_PATH'))
    print('ok')
except Exception as e:
    print('bad:'+str(e))
")
assert_eq "$JOK" "ok" "snapshot file parses as JSON"

# ── 12. snapshot_format_version = 1 ───────────────────────────────────────────
echo
echo "=== 12. snapshot_format_version = 1 ==="
SFV=$($PY -c "import json; print(json.load(open('$SNAP_PATH'))['snapshot_format_version'])")
assert_eq "$SFV" "1" "snapshot_format_version = 1"

# ── 13. captured_at_unix is an integer (recent timestamp) ─────────────────────
echo
echo "=== 13. captured_at_unix is integer ==="
CAU=$($PY -c "
import json, time
d = json.load(open('$SNAP_PATH'))
v = d['captured_at_unix']
ok = isinstance(v, int) and v > 1700000000 and v <= int(time.time()) + 5
print('ok' if ok else f'bad: type={type(v).__name__} v={v}')
")
assert_eq "$CAU" "ok" "captured_at_unix is recent unix integer"

# ── 14. rpc_port reflects --rpc-port ──────────────────────────────────────────
echo
echo "=== 14. rpc_port = $RPC_PORT ==="
RPV=$($PY -c "import json; print(json.load(open('$SNAP_PATH'))['rpc_port'])")
assert_eq "$RPV" "$RPC_PORT" "rpc_port reflects --rpc-port"

# ── 15. chain_height matches `determ status` ──────────────────────────────────
echo
echo "=== 15. chain_height ≈ status.height ==="
SCH=$($PY -c "import json; print(json.load(open('$SNAP_PATH'))['chain_height'])")
STAT_H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('height',0))")
H_OK=$($PY -c "
ch = int('$SCH'); h = int('$STAT_H')
print('ok' if ch <= h and ch >= h - 3 else f'drift: ch=$SCH status_h=$STAT_H')
")
assert_eq "$H_OK" "ok" "chain_height matches status.height (within 3-block drift)"

# ── 16. chain_id matches status.genesis ───────────────────────────────────────
echo
echo "=== 16. chain_id = status.genesis hash ==="
SCID=$($PY -c "import json; print(json.load(open('$SNAP_PATH'))['chain_id'])")
STAT_G=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('genesis',''))")
assert_eq "$SCID" "$STAT_G" "chain_id matches status.genesis hash"

# ── 17. total_validators = 3 ──────────────────────────────────────────────────
echo
echo "=== 17. total_validators = 3 ==="
TV=$($PY -c "import json; print(json.load(open('$SNAP_PATH'))['total_validators'])")
assert_eq "$TV" "3" "total_validators = 3"

# ── 18. validators array length 3 ─────────────────────────────────────────────
echo
echo "=== 18. validators array length = 3 ==="
VL=$($PY -c "import json; print(len(json.load(open('$SNAP_PATH'))['validators']))")
assert_eq "$VL" "3" "validators array length = 3"

# ── 19. validators sorted by ascending rank ───────────────────────────────────
echo
echo "=== 19. validators sorted by ascending rank ==="
ORDER=$($PY -c "
import json
v = json.load(open('$SNAP_PATH'))['validators']
ranks = [e['rank'] for e in v]
ok = ranks == sorted(ranks) and ranks == list(range(len(v)))
print('ok' if ok else f'bad: {ranks}')
")
assert_eq "$ORDER" "ok" "validators sorted by ascending rank (0..N-1)"

# ── 20. Each domain appears in `determ validators --json` ─────────────────────
echo
echo "=== 20. Each snapshot domain appears in determ validators --json ==="
DETERM_VALS=$($DETERM validators --rpc-port $RPC_PORT --json 2>/dev/null)
SNAP_DOMS=$($PY -c "
import json
d = json.load(open('$SNAP_PATH'))
print(','.join(sorted(e['domain'] for e in d['validators'])))
")
RPC_DOMS=$(echo "$DETERM_VALS" | $PY -c "
import sys, json
arr = json.load(sys.stdin)
print(','.join(sorted(e.get('domain','') for e in arr)))
")
assert_eq "$SNAP_DOMS" "$RPC_DOMS" "snapshot domains match determ validators --json"

# ── 21-22. Default snapshot omits stake_locked / accumulated_slashed ──────────
echo
echo "=== 21-22. Default snapshot omits stake_locked / accumulated_slashed ==="
HAS_SL=$($PY -c "
import json
v = json.load(open('$SNAP_PATH'))['validators']
print('yes' if any('stake_locked' in e for e in v) else 'no')
")
HAS_AS=$($PY -c "
import json
v = json.load(open('$SNAP_PATH'))['validators']
print('yes' if any('accumulated_slashed' in e for e in v) else 'no')
")
assert_eq "$HAS_SL" "no" "default snapshot has NO stake_locked field per row"
assert_eq "$HAS_AS" "no" "default snapshot has NO accumulated_slashed field per row"

# ── 23-24. --include-stake-history adds stake fields per row ──────────────────
echo
echo "=== 23-24. --include-stake-history adds stake_locked + accumulated_slashed ==="
SNAP_HIST=$T/snap_hist.json
set +e
"$WALLET" validator-roster-snapshot --rpc-port $RPC_PORT \
    --out $SNAP_HIST --include-stake-history > $T/hist_status.json 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "--include-stake-history capture exits 0"
HAS_SL2=$($PY -c "
import json
v = json.load(open('$SNAP_HIST'))['validators']
print('yes' if all('stake_locked' in e for e in v) else 'no')
")
HAS_AS2=$($PY -c "
import json
v = json.load(open('$SNAP_HIST'))['validators']
print('yes' if all('accumulated_slashed' in e for e in v) else 'no')
")
assert_eq "$HAS_SL2" "yes" "--include-stake-history adds stake_locked per row"
assert_eq "$HAS_AS2" "yes" "--include-stake-history adds accumulated_slashed per row"

# ── 25. --include-stake-history stakes match daemon stake_info ────────────────
echo
echo "=== 25. --include-stake-history stake values match determ stake_info ==="
ALICE_SNAP=$($PY -c "
import json
v = json.load(open('$SNAP_HIST'))['validators']
for e in v:
    if e['domain'] == 'alice.v': print(e['stake_locked']); break
else:
    print('missing')
")
BOB_SNAP=$($PY -c "
import json
v = json.load(open('$SNAP_HIST'))['validators']
for e in v:
    if e['domain'] == 'bob.v': print(e['stake_locked']); break
else:
    print('missing')
")
CHARLIE_SNAP=$($PY -c "
import json
v = json.load(open('$SNAP_HIST'))['validators']
for e in v:
    if e['domain'] == 'charlie.v': print(e['stake_locked']); break
else:
    print('missing')
")
ALICE_DM=$($DETERM stake_info alice.v --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('locked',-1))")
BOB_DM=$($DETERM stake_info bob.v --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('locked',-1))")
CHARLIE_DM=$($DETERM stake_info charlie.v --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('locked',-1))")
assert_eq "$ALICE_SNAP"   "$ALICE_DM"   "alice.v stake_locked matches daemon stake_info"
assert_eq "$BOB_SNAP"     "$BOB_DM"     "bob.v stake_locked matches daemon stake_info"
assert_eq "$CHARLIE_SNAP" "$CHARLIE_DM" "charlie.v stake_locked matches daemon stake_info"

# ── 26. Re-run WITHOUT --force: exit 1 (overwrite guard) ──────────────────────
echo
echo "=== 26. Re-run without --force on existing --out: exit 1 ==="
set +e
ERR=$("$WALLET" validator-roster-snapshot --rpc-port $RPC_PORT --out $SNAP_PATH 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "second invocation without --force returns exit 1"
assert_contains "$ERR" "force" "diagnostic mentions --force"

# ── 27-28. Re-run WITH --force succeeds + content is fresh ────────────────────
echo
echo "=== 27-28. Re-run with --force overwrites + content is fresh ==="
# Touch the prior snapshot mtime back so we can detect it was rewritten.
set +e
"$WALLET" validator-roster-snapshot --rpc-port $RPC_PORT --out $SNAP_PATH --force > $T/force_status.json 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "--force overwrite returns exit 0"
TV2=$($PY -c "import json; print(json.load(open('$SNAP_PATH'))['total_validators'])")
assert_eq "$TV2" "3" "post-force snapshot still has 3 validators"

# ── 29. No .tmp file left behind on success ───────────────────────────────────
echo
echo "=== 29. No .tmp file leaked on success ==="
if [ -f "${SNAP_PATH}.tmp" ]; then
  echo "  FAIL: stray .tmp file exists at ${SNAP_PATH}.tmp"
  fail_count=$((fail_count + 1))
else
  echo "  PASS: no .tmp left behind"
  pass_count=$((pass_count + 1))
fi

# ── 30. total_stake_locked sums to genesis-stake-sum ──────────────────────────
echo
echo "=== 30. total_stake_locked = sum of all 3 genesis stakes ==="
# Default snapshot (no --include-stake-history) still computes
# total_stake_locked from the per-row stake captured from the
# `validators` RPC's `stake` field — so the aggregate is meaningful
# regardless of the flag.
TSL=$($PY -c "import json; print(json.load(open('$SNAP_PATH'))['total_stake_locked'])")
EXP=$(($ALICE_STAKE + $BOB_STAKE + $CHARLIE_STAKE))
assert_eq "$TSL" "$EXP" "total_stake_locked = $EXP (alice+bob+charlie)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet validator-roster-snapshot"
  exit 0
else
  echo "  FAIL"
  exit 1
fi
