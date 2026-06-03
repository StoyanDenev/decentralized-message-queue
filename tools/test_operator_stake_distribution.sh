#!/usr/bin/env bash
# test_operator_stake_distribution.sh — smoke + fixture test for
# tools/operator_stake_distribution.sh (Nakamoto + Gini decentralization
# metrics).
#
# Coverage:
#   A. --help exits 0 and prints the usage banner (no daemon needed).
#   B. Argument validation:
#        - missing --rpc-port exits 1
#        - non-numeric --rpc-port exits 1
#        - unknown flag exits 1
#   C. Against a live single-node chain seeded with FIVE validators at
#      KNOWN distinct stakes (4000/3000/2500/2000/1500, total 13000):
#        - human output carries the expected headline fields
#        - validators count == 5
#        - Nakamoto coefficient == 2 (top-1=4000 does NOT exceed
#          1/3=4333.3; top-1+top-2=7000 does) — exercises the
#          accumulation loop, not just the single-validator shortcut
#        - Nakamoto coefficient is a positive integer in [1, validators]
#        - Gini coefficient is in (0, 1) for this unequal distribution
#        - K-of-K committee size is reported and positive
#        - --json mode emits a parseable envelope whose
#          nakamoto_coefficient / gini / stake_table agree with the
#          human view and whose stake_table is sorted DESC and sums to
#          total_stake
#
# Single producing node (M=K=1) — the other four validators are seeded
# via genesis initial_creators so they appear in the `stakes` registry
# without needing multi-node consensus. No TIME_WAIT risk.
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_stake_dist
TABS=$PROJECT_ROOT/$T
SCRIPT=tools/operator_stake_distribution.sh

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

rm -rf "$T"
mkdir -p "$T/n1" "$T/n2" "$T/n3" "$T/n4" "$T/n5"

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

RPC_PORT=8841
LISTEN_PORT=7841

echo "=== A. --help exits 0 and prints usage ==="
HELP_OUT=$(bash "$SCRIPT" --help 2>&1); HELP_RC=$?
if [ "$HELP_RC" = "0" ] && printf '%s' "$HELP_OUT" | grep -q "Usage: operator_stake_distribution.sh"; then
  assert true "--help exits 0 with usage banner"
else
  assert false "--help should exit 0 with usage banner (rc=$HELP_RC)"
fi
if printf '%s' "$HELP_OUT" | grep -qi "Nakamoto coefficient"; then
  assert true "--help documents the Nakamoto coefficient"
else
  assert false "--help should mention the Nakamoto coefficient"
fi

echo
echo "=== B. Argument validation ==="
bash "$SCRIPT" >/dev/null 2>&1; RC_MISSING=$?
assert "$([ "$RC_MISSING" = "1" ] && echo true || echo false)" \
  "missing --rpc-port exits 1 (got $RC_MISSING)"
bash "$SCRIPT" --rpc-port abc >/dev/null 2>&1; RC_BADPORT=$?
assert "$([ "$RC_BADPORT" = "1" ] && echo true || echo false)" \
  "non-numeric --rpc-port exits 1 (got $RC_BADPORT)"
bash "$SCRIPT" --rpc-port "$RPC_PORT" --bogus >/dev/null 2>&1; RC_BADFLAG=$?
assert "$([ "$RC_BADFLAG" = "1" ] && echo true || echo false)" \
  "unknown flag exits 1 (got $RC_BADFLAG)"

echo
echo "=== C. Live single-node chain with 5 known-stake validators ==="
# init each node's key, then collect peer-info entries at distinct stakes.
# Stakes: node1=4000 node2=3000 node3=2500 node4=2000 node5=1500
#   total = 13000, one-third = 4333.33
#   top1 cum = 4000        (NOT > 4333) -> keep going
#   top1+2  = 7000         (> 4333)     -> Nakamoto = 2
declare -a STAKES=(4000 3000 2500 2000 1500)
TOTAL_EXPECTED=13000
for i in 1 2 3 4 5; do
  "$DETERM" init --data-dir "$T/n$i" --profile single_test >/dev/null 2>&1
  "$DETERM" genesis-tool peer-info "node$i" --data-dir "$T/n$i" \
      --stake "${STAKES[$((i-1))]}" > "$T/p$i.json"
done

cat > "$T/gen.json" <<EOF
{
  "chain_id": "test-stake-dist",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 0,
  "initial_creators": [
$(cat "$T/p1.json" | tr -d '\n'),
$(cat "$T/p2.json" | tr -d '\n'),
$(cat "$T/p3.json" | tr -d '\n'),
$(cat "$T/p4.json" | tr -d '\n'),
$(cat "$T/p5.json" | tr -d '\n')
  ]
}
EOF
"$DETERM" genesis-tool build "$T/gen.json" | tail -1
GHASH=$(cat "$T/gen.json.hash")

python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = $LISTEN_PORT
c['rpc_port'] = $RPC_PORT
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
# Match the genesis M=K=1 so node1 alone can finalize blocks. The
# single_test profile ships M=K=3 in config.json; genesis pins M=K=1
# but we align config too to avoid any producer/config skew at boot.
c['m_creators']    = 1
c['k_block_sigs']  = 1
c['tx_commit_ms']  = 200
c['block_sig_ms']  = 200
c['abort_claim_ms']= 100
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

"$DETERM" start --config "$T/n1/config.json" > "$T/n1/log" 2>&1 &
NODE_PIDS[0]=$!

# Wait for the node to come up (height >= 1 means genesis applied + 1 block).
UP=0
for _ in $(seq 1 40); do
  H=$("$DETERM" status --rpc-port "$RPC_PORT" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  if [ "${H:-0}" -ge "1" ] 2>/dev/null; then UP=1; break; fi
  sleep 0.5
done
if [ "$UP" != "1" ]; then
  echo "  FAIL: node did not reach height >= 1; log tail:"
  tail -20 "$T/n1/log" 2>/dev/null
  echo "  $pass_count pass / $((fail_count + 1)) fail"
  exit 1
fi

# ── C.1 human-readable run ───────────────────────────────────────────────────
HUMAN_OUT=$(bash "$SCRIPT" --rpc-port "$RPC_PORT" 2>&1); HUMAN_RC=$?
echo "---- human output ----"
echo "$HUMAN_OUT"
echo "----------------------"
assert "$([ "$HUMAN_RC" = "0" ] && echo true || echo false)" \
  "human-mode run exits 0 (got $HUMAN_RC)"

printf '%s' "$HUMAN_OUT" | grep -q "Stake distribution (rpc_port=$RPC_PORT" \
  && assert true "human output has the header line with rpc_port" \
  || assert false "human output missing the header line"

printf '%s' "$HUMAN_OUT" | grep -q "Nakamoto coefficient:" \
  && assert true "human output has Nakamoto coefficient line" \
  || assert false "human output missing Nakamoto coefficient line"

printf '%s' "$HUMAN_OUT" | grep -q "Gini coefficient:" \
  && assert true "human output has Gini coefficient line" \
  || assert false "human output missing Gini coefficient line"

printf '%s' "$HUMAN_OUT" | grep -q "Total staked:" \
  && assert true "human output has Total staked line" \
  || assert false "human output missing Total staked line"

printf '%s' "$HUMAN_OUT" | grep -q "Concentration note:" \
  && assert true "human output has Concentration note line" \
  || assert false "human output missing Concentration note line"

# validators=5 in the header
if printf '%s' "$HUMAN_OUT" | grep -q "validators=5)"; then
  assert true "human header reports validators=5"
else
  assert false "human header should report validators=5"
fi

# ── C.2 JSON run + metric assertions ─────────────────────────────────────────
JSON_OUT=$(bash "$SCRIPT" --rpc-port "$RPC_PORT" --json 2>&1); JSON_RC=$?
assert "$([ "$JSON_RC" = "0" ] && echo true || echo false)" \
  "--json run exits 0 (got $JSON_RC)"

# Parse + validate the envelope in one Python pass; emit a TSV of the
# values we assert on so the shell can compare without re-parsing.
PARSED=$(printf '%s' "$JSON_OUT" | python -c "
import sys, json
try:
    e = json.load(sys.stdin)
except Exception as ex:
    print('PARSE_FAIL'); sys.exit(0)

nak   = e.get('nakamoto_coefficient')
gini  = e.get('gini')
nval  = e.get('validators')
total = e.get('total_stake')
kofk  = e.get('k_of_k_committee_size')
table = e.get('stake_table') or []

# sorted DESC by stake?
stakes_seq = [r.get('stake', 0) for r in table]
sorted_ok = all(stakes_seq[i] >= stakes_seq[i+1] for i in range(len(stakes_seq)-1))
# table sums to total_stake?
sum_ok = (sum(stakes_seq) == total)
# nakamoto a positive int <= nval?
nak_ok = isinstance(nak, int) and 1 <= nak <= (nval or 0)
# gini strictly in (0,1) for this unequal distribution?
gini_ok = isinstance(gini, (int, float)) and 0.0 < gini < 1.0

print('\t'.join(str(x) for x in [
    'OK', nak, ('%.6f' % gini) if isinstance(gini,(int,float)) else 'none',
    nval, total, kofk,
    'Y' if sorted_ok else 'N',
    'Y' if sum_ok else 'N',
    'Y' if nak_ok else 'N',
    'Y' if gini_ok else 'N',
]))
" 2>/dev/null)

if [ -z "$PARSED" ] || [ "$PARSED" = "PARSE_FAIL" ]; then
  assert false "--json output is parseable JSON"
else
  assert true "--json output is parseable JSON"
  IFS=$'\t' read -r TAG J_NAK J_GINI J_NVAL J_TOTAL J_KOFK J_SORTED J_SUM J_NAKOK J_GINIOK <<EOF
$PARSED
EOF
  assert "$([ "$J_NVAL" = "5" ] && echo true || echo false)" \
    "json validators == 5 (got $J_NVAL)"
  assert "$([ "$J_TOTAL" = "$TOTAL_EXPECTED" ] && echo true || echo false)" \
    "json total_stake == $TOTAL_EXPECTED (got $J_TOTAL)"
  assert "$([ "$J_NAK" = "2" ] && echo true || echo false)" \
    "json nakamoto_coefficient == 2 for the known fixture (got $J_NAK)"
  assert "$([ "$J_NAKOK" = "Y" ] && echo true || echo false)" \
    "json nakamoto_coefficient is a positive integer <= validators"
  assert "$([ "$J_GINIOK" = "Y" ] && echo true || echo false)" \
    "json gini is in (0,1) for this unequal distribution (got $J_GINI)"
  assert "$([ "$J_SORTED" = "Y" ] && echo true || echo false)" \
    "json stake_table is sorted by stake DESC"
  assert "$([ "$J_SUM" = "Y" ] && echo true || echo false)" \
    "json stake_table stakes sum to total_stake"
  assert "$([ "${J_KOFK:-0}" -ge 1 ] 2>/dev/null && echo true || echo false)" \
    "json k_of_k_committee_size is positive (got $J_KOFK)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: operator_stake_distribution.sh (Nakamoto + Gini)"; exit 0
else
  echo "  FAIL"; exit 1
fi
