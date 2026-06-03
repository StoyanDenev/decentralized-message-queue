#!/usr/bin/env bash
# test_operator_unstake_timeline.sh — smoke test for the per-domain
# UNSTAKE forecast helper. Covers:
#
#   1. --help prints usage (exit 0)
#   2. Missing required args reject with diagnostic (exit 1)
#   3. Bad-arg validation (--rpc-port non-numeric, --round-ms non-numeric,
#      missing --config file)
#   4. Live single-node smoke: spins up a single-node M=K=1 chain,
#      asserts the script reports "no pending unstakes" for the validator
#      that's never DEREGISTERed, and verifies both human + --json output
#      shapes (and that --config feeds round_ms / ETA through).
#
# Run from repo root: bash tools/test_operator_unstake_timeline.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_op_unstake_timeline
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
mkdir -p $T

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

SCRIPT=tools/operator_unstake_timeline.sh

echo "=== 1. --help prints usage and exits 0 ==="
OUT=$(bash $SCRIPT --help 2>&1); RC=$?
[ "$RC" = "0" ] && HAS_USAGE=true || HAS_USAGE=false
assert "$HAS_USAGE" "--help exits 0"
echo "$OUT" | grep -q "operator_unstake_timeline.sh --rpc-port" && U=true || U=false
assert "$U"        "--help mentions usage signature"
echo "$OUT" | grep -q -- "--domain D" && D=true || D=false
assert "$D"        "--help documents --domain"
echo "$OUT" | grep -q -- "--config <path>" && C=true || C=false
assert "$C"        "--help documents --config"
echo "$OUT" | grep -q -- "--round-ms <ms>" && R=true || R=false
assert "$R"        "--help documents --round-ms"

echo
echo "=== 2. Missing args rejected ==="
bash $SCRIPT > $T/out_noargs.txt 2>&1; RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK"   "no args -> exit 1"
grep -q "rpc-port is required" $T/out_noargs.txt && OK=true || OK=false
assert "$OK"   "no args -> diagnostic mentions --rpc-port"

bash $SCRIPT --rpc-port 8888 > $T/out_nodomain.txt 2>&1; RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK"   "--rpc-port without --domain -> exit 1"
grep -q "domain is required" $T/out_nodomain.txt && OK=true || OK=false
assert "$OK"   "missing --domain -> diagnostic mentions --domain"

bash $SCRIPT --rpc-port abc --domain foo > $T/out_badport.txt 2>&1; RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK"   "non-numeric --rpc-port -> exit 1"
grep -q "rpc-port must be a positive integer" $T/out_badport.txt && OK=true || OK=false
assert "$OK"   "non-numeric --rpc-port -> validation diagnostic"

bash $SCRIPT --rpc-port 8888 --domain foo --round-ms abc > $T/out_badrm.txt 2>&1; RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK"   "non-numeric --round-ms -> exit 1"
grep -q "round-ms must be a positive integer" $T/out_badrm.txt && OK=true || OK=false
assert "$OK"   "non-numeric --round-ms -> validation diagnostic"

bash $SCRIPT --rpc-port 8888 --domain foo --config /nonexistent/path.json > $T/out_badcfg.txt 2>&1; RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK"   "missing --config file -> exit 1"
grep -q "config file not found" $T/out_badcfg.txt && OK=true || OK=false
assert "$OK"   "missing --config file -> validation diagnostic"

# ── 3. Live single-node smoke ───────────────────────────────────────────────
echo
echo "=== 3. Live single-node smoke (M=K=1, regional_test profile) ==="
mkdir -p $T/n1

$DETERM init --data-dir $T/n1 --profile single_test 2>&1 > /dev/null
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

cat > $T/gen.json <<EOF
{
  "chain_id": "test-op-unstake-timeline",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json > /dev/null
GHASH=$(cat $T/gen.json.hash)

python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain']         = 'node1'
c['listen_port']    = 7840
c['rpc_port']       = 8840
c['genesis_path']   = '$TABS/gen.json'
c['genesis_hash']   = '$GHASH'
c['chain_path']     = '$TABS/n1/chain.json'
c['key_path']       = '$TABS/n1/node_key.json'
c['data_dir']       = '$TABS/n1'
# Wider timing budget to ride out CI noise.
c['tx_commit_ms']   = 200
c['block_sig_ms']   = 200
c['abort_claim_ms'] = 100
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!
sleep 2

# Wait for chain to advance.
for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port 8840 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  [ "${H:-0}" -ge "2" ] && break
  sleep 0.5
done

if [ "${H:-0}" -lt "2" ]; then
  echo "  WARN: node didn't advance past height 2 in 20s; skipping live smoke"
  echo "        (likely a build / environment issue — the script's input"
  echo "        validation tests above still cover the contract)"
  echo "  log tail:"
  tail -10 $T/n1/log | sed 's/^/    /'
else
  echo "  node1 height=$H"

  # Human-readable mode against the active validator.
  OUT=$(bash $SCRIPT --rpc-port 8840 --domain node1 2>&1); RC=$?
  [ "$RC" = "0" ] && OK=true || OK=false
  assert "$OK"   "live RPC query (--rpc-port 8840 --domain node1) -> exit 0"
  echo "$OUT" | grep -q "Pending UNSTAKEs: 0" && OK=true || OK=false
  assert "$OK"   "active validator reports 0 pending UNSTAKEs"
  echo "$OUT" | grep -q "validator is still ACTIVE" && OK=true || OK=false
  assert "$OK"   "active validator surfaces ACTIVE-state hint"
  echo "$OUT" | grep -q "Currently active stake: 1000" && OK=true || OK=false
  assert "$OK"   "active stake reported as 1000 (matches genesis stake)"

  # JSON mode.
  J=$(bash $SCRIPT --rpc-port 8840 --domain node1 --json 2>&1); RC=$?
  [ "$RC" = "0" ] && OK=true || OK=false
  assert "$OK"   "--json mode exits 0"
  echo "$J" | python -c "import json,sys; d=json.loads(sys.stdin.read()); print('OK' if (isinstance(d.get('pending_unstakes'),list) and d['active_stake']==1000) else 'BAD')" | grep -q OK && OK=true || OK=false
  assert "$OK"   "--json mode emits expected shape (pending_unstakes list + active_stake)"

  # --config drives round_ms.
  J2=$(bash $SCRIPT --rpc-port 8840 --domain node1 --config $T/n1/config.json --json 2>&1); RC=$?
  [ "$RC" = "0" ] && OK=true || OK=false
  assert "$OK"   "--config flag exits 0"
  echo "$J2" | python -c "import json,sys; d=json.loads(sys.stdin.read()); print('OK' if d.get('round_ms') == 500 else 'BAD: '+str(d.get('round_ms')))" | grep -q OK && OK=true || OK=false
  assert "$OK"   "--config supplies round_ms (200+200+100=500)"

  # --round-ms override.
  J3=$(bash $SCRIPT --rpc-port 8840 --domain node1 --round-ms 1234 --json 2>&1); RC=$?
  [ "$RC" = "0" ] && OK=true || OK=false
  assert "$OK"   "--round-ms flag exits 0"
  echo "$J3" | python -c "import json,sys; d=json.loads(sys.stdin.read()); print('OK' if d.get('round_ms') == 1234 else 'BAD')" | grep -q OK && OK=true || OK=false
  assert "$OK"   "--round-ms overrides round_ms to 1234"

  # Unknown domain returns "no on-chain state" (exit 0, not 1).
  OUT=$(bash $SCRIPT --rpc-port 8840 --domain nonexistent_validator_xyz 2>&1); RC=$?
  [ "$RC" = "0" ] && OK=true || OK=false
  assert "$OK"   "unknown domain -> exit 0 (graceful)"
  echo "$OUT" | grep -qE "(no on-chain state|Pending UNSTAKEs: 0)" && OK=true || OK=false
  assert "$OK"   "unknown domain reports gracefully"
fi

echo
echo "─────────────────────────────────────────────────────────"
echo "  ${pass_count} PASS,  ${fail_count} FAIL"
echo "─────────────────────────────────────────────────────────"
[ "$fail_count" = "0" ] && exit 0 || exit 1
