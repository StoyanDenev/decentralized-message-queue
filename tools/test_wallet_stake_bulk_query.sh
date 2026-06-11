#!/usr/bin/env bash
# determ-wallet stake-bulk-query CLI test.
#
# Exercises the wallet's batch stake-info RPC client against a running
# single-node daemon. Three distinct validator domains (alice.v, bob.v,
# charlie.v) are pre-staked at genesis with different stake amounts —
# this is the on-chain equivalent of REGISTER+STAKE for each, and gives
# the test a deterministic multi-validator roster to query.
#
# Verifies:
#   1.  help text mentions stake-bulk-query
#   2.  --help exits 0 + prints usage
#   3.  missing --rpc-port → exit 1 with clear diagnostic
#   4.  missing --domains → exit 1 with clear diagnostic
#   5.  unreachable RPC port → exit 1 (connect failure)
#   6.  bring up single-node daemon with 3 staked validators baked into
#       genesis (alice.v stake=3_000_000_000, bob.v stake=2_000_000_000,
#       charlie.v stake=1_000_000_000); only alice.v actually runs.
#   7.  default human-readable table has header line + data rows
#   8.  --json output produces valid JSON
#   9.  --json envelope has expected top-level keys
#  10.  rpc_port field reflects --rpc-port arg
#  11.  chain_height matches `determ status` height
#  12.  domains[] has 3 entries
#  13.  alice.v stake_locked matches `determ stake_info alice.v` exactly
#  14.  bob.v stake_locked matches `determ stake_info bob.v` exactly
#  15.  charlie.v stake_locked matches `determ stake_info charlie.v`
#  16.  alice.v exists=true
#  17.  bob.v exists=true
#  18.  charlie.v exists=true
#  19.  alice.v ed_pub is a 64-char hex string
#  20.  alice.v active_from is an integer
#  21.  summary.total_domains = 3
#  22.  summary.total_stake_locked = 3+2+1 billion = 6_000_000_000
#  23.  summary.exists_count = 3
#  24.  summary.total_accumulated_slashed = 0 (no slashes happened)
#  25.  @<file> form yields the same per-domain stake_locked rows
#  26.  @<file> with # comments + blank lines parses correctly (3 entries)
#  27.  Non-existent domain (nobody.v) → stake_locked=0
#  28.  Non-existent domain → exists=false
#  29.  Mixed batch (alice.v + nobody.v) summary.exists_count = 1
#  30.  Mixed batch summary.total_stake_locked = alice.v stake only
#  31.  Default (non-JSON) output sorts by stake_locked DESC
#       (alice.v's row precedes bob.v's row precedes charlie.v's row)
#
# Run from repo root: bash tools/test_wallet_stake_bulk_query.sh

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
T=test_wallet_stake_bulk_query
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

# ── 1. Help text mentions stake-bulk-query ────────────────────────────────────
echo "=== 1. Help text mentions stake-bulk-query ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "stake-bulk-query" "help mentions stake-bulk-query"

# ── 2. --help exits 0 + prints usage ──────────────────────────────────────────
echo
echo "=== 2. --help exits 0 ==="
set +e
HOUT=$("$WALLET" stake-bulk-query --help 2>&1)
RC=$?
set -e
assert_eq "$RC" "0" "--help returns exit 0"
assert_contains "$HOUT" "Usage: determ-wallet stake-bulk-query" "--help prints Usage line"

# ── 3. Missing --rpc-port: exit 1 ─────────────────────────────────────────────
echo
echo "=== 3. Missing --rpc-port: exit 1 ==="
set +e
ERR=$("$WALLET" stake-bulk-query --domains alice.v 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --rpc-port returns exit 1"
assert_contains "$ERR" "rpc-port" "diagnostic mentions --rpc-port"

# ── 4. Missing --domains: exit 1 ──────────────────────────────────────────────
echo
echo "=== 4. Missing --domains: exit 1 ==="
set +e
ERR=$("$WALLET" stake-bulk-query --rpc-port 18839 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --domains returns exit 1"
assert_contains "$ERR" "domains" "diagnostic mentions --domains"

# ── 5. Bad RPC port (no daemon): exit 1 ───────────────────────────────────────
echo
echo "=== 5. Bad RPC port (daemon not running): exit 1 ==="
set +e
ERR=$("$WALLET" stake-bulk-query --rpc-port 1 --domains alice.v 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "unreachable RPC port returns exit 1"
assert_contains "$ERR" "connect" "diagnostic mentions connection failure"

# ── 6. Bring up single-node daemon with 3 staked validators in genesis ────────
echo
echo "=== 6. Init data-dirs + bake 3 validators into genesis ==="
# Init three data-dirs (one per validator key); only alice.v will be
# the running producer. bob.v / charlie.v have their pubkeys baked
# into genesis as initial_creators (REGISTER+STAKE equivalent) but
# their nodes never run — this gives the test a multi-validator
# stake roster against a single-node daemon.
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
  "chain_id": "test-stake-bulk-query",
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

RPC_PORT=18839
$PY -c "
import json
with open('$T/alice/config.json') as f: c = json.load(f)
c['domain'] = 'alice.v'
c['listen_port'] = 17839
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

# ── 7. Default human-readable table output ────────────────────────────────────
echo
echo "=== 7. Default (non-JSON) human-readable table ==="
OUT_TABLE=$("$WALLET" stake-bulk-query --rpc-port $RPC_PORT \
            --domains "alice.v,bob.v,charlie.v" 2>&1 | tr -d '\r')
echo "$OUT_TABLE"
assert_contains "$OUT_TABLE" "chain_height:" "table output has chain_height line"
assert_contains "$OUT_TABLE" "STAKE_LOCKED" "table has STAKE_LOCKED column header"
assert_contains "$OUT_TABLE" "alice.v" "table contains alice.v row"
assert_contains "$OUT_TABLE" "bob.v" "table contains bob.v row"
assert_contains "$OUT_TABLE" "charlie.v" "table contains charlie.v row"

# ── 8. --json output validity ─────────────────────────────────────────────────
echo
echo "=== 8. --json output is valid JSON ==="
OUT=$("$WALLET" stake-bulk-query --rpc-port $RPC_PORT \
        --domains "alice.v,bob.v,charlie.v" --json 2>&1 | tr -d '\r')
echo "$OUT" | head -c 400; echo
JSON_OK=$(echo "$OUT" | $PY -c "
import sys, json
try:
    json.loads(sys.stdin.read())
    print('ok')
except Exception as e:
    print('bad:'+str(e))
")
assert_eq "$JSON_OK" "ok" "--json output parses as valid JSON"

# ── 9. JSON envelope top-level keys ──────────────────────────────────────────
echo
echo "=== 9. JSON envelope has expected top-level keys ==="
ENV_OK=$(echo "$OUT" | $PY -c "
import sys, json
d = json.load(sys.stdin)
keys = sorted(d.keys())
need = sorted(['rpc_port', 'chain_height', 'domains', 'summary'])
print('ok' if keys == need else f'missing: have {keys}, need {need}')
")
assert_eq "$ENV_OK" "ok" "top-level keys are {rpc_port, chain_height, domains, summary}"

# ── 10. rpc_port reflects --rpc-port ──────────────────────────────────────────
echo
echo "=== 10. rpc_port reflects --rpc-port argument ==="
RP=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['rpc_port'])")
assert_eq "$RP" "$RPC_PORT" "rpc_port = $RPC_PORT"

# ── 11. chain_height matches `determ status` ──────────────────────────────────
echo
echo "=== 11. chain_height matches status.height ==="
CH=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['chain_height'])")
STAT_H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('height',0))")
# chain_height was captured by the wallet a moment before; allow it to
# be <= the current status.height (chain may have advanced one block).
$PY -c "
ch = int('$CH'); h = int('$STAT_H')
print('ok' if ch <= h and ch >= h - 2 else f'drift: ch=$CH status_h=$STAT_H')
" > $T/h_check.txt
H_OK=$(cat $T/h_check.txt)
assert_eq "$H_OK" "ok" "chain_height matches status.height (within 2-block drift)"

# ── 12. domains[] has 3 entries ──────────────────────────────────────────────
echo
echo "=== 12. domains[] has 3 entries ==="
NDOM=$(echo "$OUT" | $PY -c "import sys,json; print(len(json.load(sys.stdin)['domains']))")
assert_eq "$NDOM" "3" "domains[] has 3 entries"

# ── 13-15. Per-domain stake_locked matches `determ stake_info` exactly ────────
echo
echo "=== 13-15. Per-domain stake_locked matches determ stake_info ==="
get_stake_locked() {
  echo "$OUT" | $PY -c "
import sys,json
d = json.load(sys.stdin)
for r in d['domains']:
    if r['domain'] == '$1':
        print(r['stake_locked']); break
else:
    print('-1')
"
}

# Daemon's stake_info returns {domain, locked, unlock_height}; assert
# the wallet's stake_locked equals daemon's locked.
ALICE_BULK=$(get_stake_locked "alice.v")
BOB_BULK=$(get_stake_locked "bob.v")
CHARLIE_BULK=$(get_stake_locked "charlie.v")

ALICE_DAEMON=$($DETERM stake_info alice.v --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('locked',-1))")
BOB_DAEMON=$($DETERM stake_info bob.v --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('locked',-1))")
CHARLIE_DAEMON=$($DETERM stake_info charlie.v --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('locked',-1))")

assert_eq "$ALICE_BULK"   "$ALICE_DAEMON"   "alice.v stake_locked matches determ stake_info"
assert_eq "$BOB_BULK"     "$BOB_DAEMON"     "bob.v stake_locked matches determ stake_info"
assert_eq "$CHARLIE_BULK" "$CHARLIE_DAEMON" "charlie.v stake_locked matches determ stake_info"

# Sanity: stakes should also match what we baked into genesis.
assert_eq "$ALICE_BULK"   "$ALICE_STAKE"   "alice.v stake_locked = genesis stake ($ALICE_STAKE)"
assert_eq "$BOB_BULK"     "$BOB_STAKE"     "bob.v stake_locked = genesis stake ($BOB_STAKE)"
assert_eq "$CHARLIE_BULK" "$CHARLIE_STAKE" "charlie.v stake_locked = genesis stake ($CHARLIE_STAKE)"

# ── 16-18. exists=true for each registered validator ─────────────────────────
echo
echo "=== 16-18. exists=true for all 3 staked validators ==="
get_exists() {
  echo "$OUT" | $PY -c "
import sys,json
d = json.load(sys.stdin)
for r in d['domains']:
    if r['domain'] == '$1':
        print(r['exists']); break
else:
    print('missing')
"
}
EX_A=$(get_exists "alice.v")
EX_B=$(get_exists "bob.v")
EX_C=$(get_exists "charlie.v")
assert_eq "$EX_A" "True" "alice.v exists=true"
assert_eq "$EX_B" "True" "bob.v exists=true"
assert_eq "$EX_C" "True" "charlie.v exists=true"

# ── 19. alice.v ed_pub is 64-char hex ─────────────────────────────────────────
echo
echo "=== 19. alice.v ed_pub is 64-char hex ==="
ED_A=$(echo "$OUT" | $PY -c "
import sys,json
d = json.load(sys.stdin)
for r in d['domains']:
    if r['domain'] == 'alice.v':
        print(r['ed_pub']); break
else:
    print('')
")
ED_OK=$($PY -c "
s = '$ED_A'
ok = (len(s) == 64) and all(c in '0123456789abcdef' for c in s.lower())
print('ok' if ok else f'bad: len={len(s)}')
")
assert_eq "$ED_OK" "ok" "alice.v ed_pub is 64-char hex"

# ── 20. alice.v active_from is integer ────────────────────────────────────────
echo
echo "=== 20. alice.v active_from is an integer ==="
AF_OK=$(echo "$OUT" | $PY -c "
import sys,json
d = json.load(sys.stdin)
for r in d['domains']:
    if r['domain'] == 'alice.v':
        v = r['active_from']
        print('ok' if isinstance(v, int) else f'bad: type={type(v).__name__}')
        break
else:
    print('missing')
")
assert_eq "$AF_OK" "ok" "alice.v active_from is int"

# ── 21-24. Summary aggregates ─────────────────────────────────────────────────
echo
echo "=== 21-24. Summary aggregates ==="
TD=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_domains'])")
TS=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_stake_locked'])")
TSL=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_accumulated_slashed'])")
EC=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['exists_count'])")
TOT_STK=$(($ALICE_STAKE + $BOB_STAKE + $CHARLIE_STAKE))
assert_eq "$TD"  "3"        "summary.total_domains = 3"
assert_eq "$TS"  "$TOT_STK" "summary.total_stake_locked = $TOT_STK"
assert_eq "$EC"  "3"        "summary.exists_count = 3"
assert_eq "$TSL" "0"        "summary.total_accumulated_slashed = 0 (no slashes)"

# ── 25-26. @<file> form yields same per-domain rows ──────────────────────────
echo
echo "=== 25-26. @<file> form (with # comments + blank lines) ==="
cat > $T/domains.txt <<EOF
# Test fixture: 3 validator domains, one per line
alice.v
bob.v

# A blank line above + a comment line interleaved
charlie.v
EOF
OUT_F=$("$WALLET" stake-bulk-query --rpc-port $RPC_PORT \
          --domains "@$T/domains.txt" --json 2>&1 | tr -d '\r')
NDOM_F=$(echo "$OUT_F" | $PY -c "import sys,json; print(len(json.load(sys.stdin)['domains']))")
assert_eq "$NDOM_F" "3" "@<file> with 3 entries + 2 comments + 1 blank line → 3 rows"

# Per-domain stake_locked from @<file> form matches per-domain rows
# from inline comma form (regression: any difference in either parser
# would diverge here).
get_stake_locked_in() {
  echo "$1" | $PY -c "
import sys,json
d = json.load(sys.stdin)
for r in d['domains']:
    if r['domain'] == '$2':
        print(r['stake_locked']); break
else:
    print('-1')
"
}
ALICE_F=$(get_stake_locked_in "$OUT_F" "alice.v")
BOB_F=$(get_stake_locked_in "$OUT_F" "bob.v")
CHARLIE_F=$(get_stake_locked_in "$OUT_F" "charlie.v")
assert_eq "$ALICE_F"   "$ALICE_BULK"   "@<file>: alice.v stake_locked matches inline form"
assert_eq "$BOB_F"     "$BOB_BULK"     "@<file>: bob.v stake_locked matches inline form"
assert_eq "$CHARLIE_F" "$CHARLIE_BULK" "@<file>: charlie.v stake_locked matches inline form"

# ── 27-28. Non-existent domain row ────────────────────────────────────────────
echo
echo "=== 27-28. Non-existent domain: stake_locked=0 + exists=false ==="
OUT_N=$("$WALLET" stake-bulk-query --rpc-port $RPC_PORT \
          --domains "nobody.v" --json 2>&1 | tr -d '\r')
NB_STK=$(echo "$OUT_N" | $PY -c "import sys,json; print(json.load(sys.stdin)['domains'][0]['stake_locked'])")
NB_EX=$(echo "$OUT_N" | $PY -c "import sys,json; print(json.load(sys.stdin)['domains'][0]['exists'])")
assert_eq "$NB_STK" "0"     "nobody.v stake_locked = 0"
assert_eq "$NB_EX"  "False" "nobody.v exists=false"

# ── 29-30. Mixed batch (real + nonexistent) summary aggregation ──────────────
echo
echo "=== 29-30. Mixed batch (alice.v + nobody.v): summary aggregation ==="
OUT_M=$("$WALLET" stake-bulk-query --rpc-port $RPC_PORT \
          --domains "alice.v,nobody.v" --json 2>&1 | tr -d '\r')
EC_M=$(echo "$OUT_M" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['exists_count'])")
TS_M=$(echo "$OUT_M" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_stake_locked'])")
assert_eq "$EC_M" "1"             "mixed batch: exists_count = 1 (alice.v only)"
assert_eq "$TS_M" "$ALICE_BULK"   "mixed batch: total_stake_locked = alice.v stake"

# ── 31. Default-output ordering: stake_locked DESC ────────────────────────────
echo
echo "=== 31. Default human-readable output is sorted by stake_locked DESC ==="
# Grab the first 3 data rows from $OUT_TABLE (after the header line).
# The header is "DOMAIN ... STAKE_LOCKED ...", so data rows start
# after that. Order: alice (3B) > bob (2B) > charlie (1B).
A_LINE=$(echo "$OUT_TABLE" | grep -n '^alice.v' | head -1 | cut -d: -f1)
B_LINE=$(echo "$OUT_TABLE" | grep -n '^bob.v' | head -1 | cut -d: -f1)
C_LINE=$(echo "$OUT_TABLE" | grep -n '^charlie.v' | head -1 | cut -d: -f1)
ORDER_OK=$($PY -c "
a, b, c = int('$A_LINE'), int('$B_LINE'), int('$C_LINE')
print('ok' if a < b and b < c else f'bad: alice@{a} bob@{b} charlie@{c}')
")
assert_eq "$ORDER_OK" "ok" "table sorted by stake_locked DESC (alice → bob → charlie)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet stake-bulk-query"
  exit 0
else
  echo "  FAIL: test_wallet_stake_bulk_query"
  exit 1
fi
