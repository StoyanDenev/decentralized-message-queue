#!/usr/bin/env bash
# test_operator_dapp_census.sh — smoke test for
# tools/operator_dapp_census.sh.
#
# Two tiers:
#
#   Tier 1 (always): argument-surface verification — --help / -h exit 0
#   and render usage; missing/invalid --rpc-port and unknown args exit 1
#   with a diagnostic; an unreachable port exits 1 cleanly (no python
#   crash). This mirrors the operator_*-smoke precedent
#   (tools/test_operator_committee_snapshot.sh): the core algorithm is
#   pure Python that runs in-process on the script's heredoc, so the
#   argument surface is the regression-prone part.
#
#   Tier 2 (opt-in, auto-skips when no build is present): boot a 3-node
#   single-chain cluster, register ONE DApp via submit-dapp-register, and
#   assert the census lists it with the expected fields (domain, owner,
#   service_pubkey short, endpoint_url) in both human and --json modes,
#   and that --with-message-counts adds a numeric msg_count column. The
#   boot recipe mirrors tools/test_dapp_e2e.sh. This tier is gated on the
#   determ binary being resolvable (common.sh) AND a writable temp tree;
#   in a build-less CI lane it prints a skip note and Tier 1 alone gates.
set -u
cd "$(dirname "$0")/.."

SCRIPT="tools/operator_dapp_census.sh"
FAIL_COUNT=0
CHECK_COUNT=0
fail() { echo "  FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
ok()   { echo "  ok: $1"; }
chk()  { CHECK_COUNT=$((CHECK_COUNT + 1)); }

# ──────────────────────────────────────────────────────────────────────────────
# Tier 1: argument-surface checks (no daemon required).
# ──────────────────────────────────────────────────────────────────────────────

echo "=== (1) --help exits 0 + renders usage ==="
chk
OUT=$(bash "$SCRIPT" --help 2>&1)
RC=$?
if [ "$RC" -ne 0 ]; then
  fail "--help should exit 0 (got $RC)"
elif ! echo "$OUT" | grep -q "Usage: operator_dapp_census.sh"; then
  fail "--help output missing 'Usage:' header"
else
  ok "--help works"
fi

echo "=== (2) -h alias exits 0 ==="
chk
bash "$SCRIPT" -h > /dev/null 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
  fail "-h should exit 0 (got $RC)"
else
  ok "-h alias works"
fi

echo "=== (3) missing --rpc-port exits 1 + diagnostic ==="
chk
OUT=$(bash "$SCRIPT" 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "missing --rpc-port should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q -- "--rpc-port is required"; then
  fail "missing --rpc-port diagnostic missing 'is required'"
else
  ok "missing --rpc-port exits 1 with diagnostic"
fi

echo "=== (4) non-numeric --rpc-port exits 1 ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port abc 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "non-numeric --rpc-port should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "positive integer"; then
  fail "non-numeric --rpc-port diagnostic missing 'positive integer'"
else
  ok "non-numeric --rpc-port exits 1 with diagnostic"
fi

echo "=== (5) unknown argument exits 1 + diagnostic ==="
chk
OUT=$(bash "$SCRIPT" --rpc-port 8888 --bogus 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "unknown argument should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -q "unknown argument"; then
  fail "unknown argument diagnostic missing"
else
  ok "unknown argument exits 1 with diagnostic"
fi

echo "=== (6) unreachable RPC port exits 1 cleanly ==="
# Port 1 is unlikely to host a daemon; the status reach-check should fail
# with exit 1 (not a python traceback / bare bash error). NOTE: argument
# validation runs BEFORE `source common.sh`, so checks (3)-(5) pass with
# no build present; this check, however, only reaches the RPC path after
# common.sh resolves the binary. In a build-less lane common.sh itself
# hard-exits 1 with "cannot find determ binary" — also a clean exit-1
# diagnostic — so we accept either message (both satisfy the contract:
# exit 1 + an informative reason, never a bare crash).
chk
OUT=$(bash "$SCRIPT" --rpc-port 1 2>&1)
RC=$?
if [ "$RC" -ne 1 ]; then
  fail "unreachable RPC should exit 1 (got $RC)"
elif ! echo "$OUT" | grep -qE "cannot reach daemon|cannot find determ binary|RPC"; then
  fail "unreachable RPC diagnostic missing reach/binary/RPC reason"
else
  ok "unreachable RPC exits 1 with diagnostic"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Tier 2: live 3-node cluster with one registered DApp (opt-in).
# Auto-skips if the determ binary can't be resolved.
# ──────────────────────────────────────────────────────────────────────────────

echo
echo "=== Tier 2: live cluster census ==="

# Resolve the binary WITHOUT letting common.sh's hard-exit abort Tier 1's
# already-passed checks. We probe the same locations common.sh does.
DETERM_PROBE=""
if   [ -n "${DETERM_BIN:-}" ] && [ -x "${DETERM_BIN:-}" ]; then DETERM_PROBE="$DETERM_BIN"
elif [ -x "build/Release/determ.exe" ]; then DETERM_PROBE="build/Release/determ.exe"
elif [ -x "build/determ.exe" ];         then DETERM_PROBE="build/determ.exe"
elif [ -x "build/determ" ];             then DETERM_PROBE="build/determ"
elif [ -x "build/Release/determ" ];     then DETERM_PROBE="build/Release/determ"
fi

if [ -z "$DETERM_PROBE" ]; then
  echo "  SKIP: no determ binary found (set DETERM_BIN to enable Tier 2)"
else
  # Now safe to source common.sh (binary is present).
  source tools/common.sh
  T=test_operator_dapp_census
  TABS=$PROJECT_ROOT/$T

  declare -a NODE_PIDS
  cleanup() {
    for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
    sleep 1
    for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
  }
  trap cleanup EXIT INT

  # census_retry: run the census, retrying up to 3x on a non-zero exit.
  # A live 3-of-3 committee intermittently drops a single RPC mid-finalize
  # (the same TIME_WAIT / busy-committee flake test_dapp_e2e.sh documents);
  # the script itself already retries each RPC, but back-to-back census
  # invocations under a hot cluster can still catch a blip. We retry at the
  # test layer so the assertions test the RENDERED OUTPUT, not the flake.
  # Sets CENSUS_OUT (stdout) and CENSUS_RC (final exit code).
  census_retry() {
    local i
    for i in 1 2 3; do
      CENSUS_OUT=$(bash "$SCRIPT" "$@" 2>/dev/null)
      CENSUS_RC=$?
      [ "$CENSUS_RC" -eq 0 ] && return 0
      sleep 1
    done
    return "$CENSUS_RC"
  }

  rm -rf "$T"
  mkdir -p "$T/n1" "$T/n2" "$T/n3"

  echo "  --- init 3 nodes ---"
  for n in 1 2 3; do
    "$DETERM" init --data-dir "$T/n$n" --profile single_test >/dev/null 2>&1
    "$DETERM" genesis-tool peer-info "node$n" --data-dir "$T/n$n" --stake 1000 > "$T/p$n.json"
  done

  N1_PRIV=$(python -c "
import json
with open('$T/n1/node_key.json') as f: k = json.load(f)
print(k.get('priv_seed') or k.get('priv') or k.get('seed') or '')")

  SVC_PUBKEY="$(python -c "print('bb' * 32)")"

  cat > "$T/gen.json" <<EOF
{
  "chain_id": "test-operator-dapp-census",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(tr -d '\n' < "$T/p1.json"),
$(tr -d '\n' < "$T/p2.json"),
$(tr -d '\n' < "$T/p3.json")
  ],
  "initial_balances": [
    {"domain": "node1", "balance": 100},
    {"domain": "node2", "balance": 100}
  ]
}
EOF
  "$DETERM" genesis-tool build "$T/gen.json" >/dev/null 2>&1
  GHASH=$(cat "$T/gen.json.hash")

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

  echo "  --- start 3 nodes ---"
  NODE_PIDS=("" "" "")
  "$DETERM" start --config "$T/n1/config.json" > "$T/n1/log" 2>&1 &
  NODE_PIDS[0]=$!; sleep 0.3
  "$DETERM" start --config "$T/n2/config.json" > "$T/n2/log" 2>&1 &
  NODE_PIDS[1]=$!; sleep 0.3
  "$DETERM" start --config "$T/n3/config.json" > "$T/n3/log" 2>&1 &
  NODE_PIDS[2]=$!; sleep 0.5

  echo "  --- wait for chain past height 5 ---"
  H=0
  for _ in $(seq 1 80); do
    H=$("$DETERM" status --rpc-port 8771 2>/dev/null \
         | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
    if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
    sleep 0.5
  done
  echo "  chain height: $H"

  echo "  --- node1 registers a DApp ---"
  "$DETERM" submit-dapp-register --rpc-port 8771 \
    --priv "$N1_PRIV" --from node1 \
    --service-pubkey "$SVC_PUBKEY" \
    --endpoint-url "https://census.example" \
    --topics "audit,inventory" >/dev/null 2>&1

  echo "  --- wait for registration to apply ---"
  for _ in $(seq 1 60); do
    INFO=$("$DETERM" dapp-info --rpc-port 8771 --domain node1 2>/dev/null)
    if echo "$INFO" | python -c "
import sys,json
try:
    j = json.load(sys.stdin)
    sys.exit(0 if j.get('endpoint_url') == 'https://census.example' else 1)
except: sys.exit(1)" 2>/dev/null; then break; fi
    sleep 0.5
  done

  # (7) Human census lists node1 with its endpoint + summary line.
  echo "  === (7) human census lists the registered DApp ==="
  chk
  census_retry --rpc-port 8771
  CENSUS="$CENSUS_OUT"; CRC="$CENSUS_RC"
  if [ "$CRC" -ne 0 ]; then
    fail "census exited $CRC (expected 0); output: $CENSUS"
  elif ! echo "$CENSUS" | grep -q "node1"; then
    fail "census output missing 'node1' row"
  elif ! echo "$CENSUS" | grep -q "https://census.example"; then
    fail "census output missing endpoint 'https://census.example'"
  elif ! echo "$CENSUS" | grep -qE "[0-9]+ DApp(s)? registered"; then
    fail "census output missing 'N DApps registered' summary"
  else
    ok "human census lists node1 + endpoint + summary"
  fi

  # (8) JSON census: dapp_count >= 1 and node1 present with expected fields.
  echo "  === (8) --json census shape ==="
  chk
  census_retry --rpc-port 8771 --json
  CJSON="$CENSUS_OUT"; CRC="$CENSUS_RC"
  JSON_OK=$(echo "$CJSON" | python -c "
import sys,json
try:
    j = json.load(sys.stdin)
except Exception:
    print('false'); sys.exit(0)
if not isinstance(j, dict): print('false'); sys.exit(0)
if j.get('dapp_count', 0) < 1: print('false'); sys.exit(0)
node1 = None
for d in j.get('dapps', []):
    if d.get('domain') == 'node1': node1 = d
if node1 is None: print('false'); sys.exit(0)
needed = ['domain','owner','service_pubkey','endpoint_url','registered_block',
          'owner_registered','owner_active']
ok = (all(k in node1 for k in needed)
      and node1.get('owner') == 'node1'
      and node1.get('endpoint_url') == 'https://census.example')
print('true' if ok else 'false')" 2>/dev/null || echo "false")
  if [ "$CRC" -ne 0 ]; then
    fail "--json census exited $CRC (expected 0)"
  elif [ "$JSON_OK" != "true" ]; then
    fail "--json census missing node1 / required fields"
  else
    ok "--json census has node1 with all required fields"
  fi

  # (9) --with-message-counts adds a numeric msg_count to the JSON record.
  echo "  === (9) --with-message-counts adds msg_count ==="
  chk
  census_retry --rpc-port 8771 --with-message-counts --json
  CMSG="$CENSUS_OUT"; CRC="$CENSUS_RC"
  MSG_OK=$(echo "$CMSG" | python -c "
import sys,json
try:
    j = json.load(sys.stdin)
except Exception:
    print('false'); sys.exit(0)
for d in j.get('dapps', []):
    if d.get('domain') == 'node1':
        c = d.get('msg_count')
        print('true' if isinstance(c, int) and 'msg_count_truncated' in d else 'false')
        sys.exit(0)
print('false')" 2>/dev/null || echo "false")
  if [ "$CRC" -ne 0 ]; then
    fail "--with-message-counts census exited $CRC (expected 0)"
  elif [ "$MSG_OK" != "true" ]; then
    fail "--with-message-counts did not add a numeric msg_count to node1"
  else
    ok "--with-message-counts adds numeric msg_count"
  fi

  # (10) --prefix filters: a non-matching prefix yields zero DApps, exit 0.
  echo "  === (10) --prefix filter (non-matching => 0 DApps, exit 0) ==="
  chk
  census_retry --rpc-port 8771 --prefix zzz-no-match --json
  CPRE="$CENSUS_OUT"; CRC="$CENSUS_RC"
  PRE_OK=$(echo "$CPRE" | python -c "
import sys,json
try: j = json.load(sys.stdin)
except Exception: print('false'); sys.exit(0)
print('true' if j.get('dapp_count', -1) == 0 else 'false')" 2>/dev/null || echo "false")
  if [ "$CRC" -ne 0 ]; then
    fail "--prefix non-match census exited $CRC (expected 0)"
  elif [ "$PRE_OK" != "true" ]; then
    fail "--prefix non-match should report 0 DApps"
  else
    ok "--prefix non-match yields 0 DApps, exit 0"
  fi
fi

# ──────────────────────────────────────────────────────────────────────────────
echo
if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "  PASS: tools/operator_dapp_census.sh smoke test ($CHECK_COUNT checks)"
  exit 0
else
  echo "  FAIL: tools/operator_dapp_census.sh smoke test ($FAIL_COUNT/$CHECK_COUNT checks failed)"
  exit 1
fi
