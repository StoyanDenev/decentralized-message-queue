#!/usr/bin/env bash
# determ-light verify-registrant vs a LYING DAEMON — register claim RP-3
# (RegistrantProof value-hash cleartext cross-check, the WIRE-sourced sibling of
# the argv-sourced CR-2 gate closed in test_light_verify_param_change.sh).
#
# CR-2 proved the cross-check catches an operator asserting a (name,value) the
# chain never committed — testable with a wrong flag against an HONEST daemon.
# RP-3's adversary is different: a LYING DAEMON that serves an honest merkle
# proof for the r: leaf but tampers the `account` registry CLEARTEXT it returns
# separately. No honest daemon serves such a mismatch (node.cpp emits registry
# fields that hash to the committed value_hash), so the lie is injected by a
# transparent man-in-the-middle proxy (tools/rpc_tamper_proxy.py) that rewrites
# ONE field of the `account` reply and forwards everything else — headers,
# block, state_proof, committee — verbatim. A correct client must catch the lie
# cryptographically: the recomputed value_hash over the tampered registry no
# longer equals the committee-proven state-proof value_hash (light/main.cpp:6112).
#
# NON-VACUITY (the CR-2 lesson): the tamper leg means nothing without a control
# proving the value-hash comparison is actually REACHED and honest-passes. So we
# run the SAME verify-registrant through a PASS-THROUGH instance of the SAME
# proxy first and require INCLUDED/exit 0 — that proves the proxy is transparent
# AND the compare passed on honest input. Only then do the tamper legs (registry
# field flipped) prove it REJECTS. exit is asserted == 3 EXACTLY (a value-hash
# UNVERIFIABLE), never merely non-zero: an ed_pub-decode or inconsistent-daemon
# throw exits 1, so a "non-zero" assertion would pass on the wrong gate. Each
# tamper leg also asserts the detail is the ACCOUNT-REGISTRY mismatch, not a
# key-bind message — pinning the key gate did not fire in the comparison's place.
#
# Cluster-bound; NOT part of FAST=1 (needs a bindable local node) — same
# operating envelope as the other *-trustless / verify-* cluster tests.
#
# Run from repo root: bash tools/test_light_registrant_tamper.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found (need the full node for a live cluster)"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3
PROXY=tools/rpc_tamper_proxy.py

T=test_light_reg_tamper
TABS=$PROJECT_ROOT/$T
NODE_RPC=8916
NODE_LISTEN=7916

declare -a NODE_PIDS
PROXY_PID=""
cleanup() {
  set +e
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  [ -n "$PROXY_PID" ] && kill -9 "$PROXY_PID" 2>/dev/null
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
  return 0
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/node

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

# Start a proxy with the given args on $1 -> NODE_RPC, wait for readiness, run
# verify-registrant through it, capture OUT/RC, then stop the proxy.
# Usage: via_proxy <listen_port> <domain> [extra proxy args...]
VIA_OUT=""; VIA_RC=""
via_proxy() {
  local lport=$1; local dom=$2; shift 2
  local plog=$T/proxy_$lport.log
  set +e
  "$PY" "$PROXY" --listen "$lport" --upstream "$NODE_RPC" --log "$T/tamper_$lport.log" "$@" \
      > "$plog" 2>&1 &
  PROXY_PID=$!
  local ready=0
  for _ in $(seq 1 50); do
    if grep -q "PROXY-READY" "$plog" 2>/dev/null; then ready=1; break; fi
    sleep 0.1
  done
  if [ "$ready" != "1" ]; then VIA_OUT="(proxy failed to start)"; VIA_RC=99
  else
    VIA_OUT=$($DETERM_LIGHT verify-registrant --rpc-port "$lport" \
                --genesis $T/node_gen.json --domain "$dom" 2>&1)
    VIA_RC=$?
  fi
  kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; PROXY_PID=""
  set -e
}

# ───────────────────── PART A: proxy self-test (no cluster) ───────────────
echo "=== PART A: proxy transparency + tamper self-test (offline, no node) ==="
# A tiny fake JSON-line server proves the proxy relays verbatim and rewrites a
# named field, independent of any determ node — so a proxy regression is caught
# even where the live cluster SKIPs.
FAKE_PORT=8919
$PY - "$FAKE_PORT" <<'PYEOF' > $T/fake.log 2>&1 &
import socket, json, sys, threading
port = int(sys.argv[1])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(4)
print("FAKE-READY", flush=True)
def handle(c):
    f = c.makefile("rwb", buffering=0)
    while True:
        line = f.readline()
        if not line: break
        try: req = json.loads(line)
        except Exception: break
        m = req.get("method")
        if m == "account":
            res = {"result": {"registry": {"ed_pub": "ab"*32, "registered_at": 7,
                   "active_from": 0, "inactive_from": 0, "region": "eu"}}, "error": None}
        else:
            res = {"result": {"echo": m}, "error": None}
        f.write((json.dumps(res) + "\n").encode())
while True:
    c,_ = srv.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF
FAKE_PID=$!
for _ in $(seq 1 50); do grep -q FAKE-READY $T/fake.log 2>/dev/null && break; sleep 0.1; done

# pass-through proxy: account.registry.registered_at must arrive UNCHANGED (7)
$PY "$PROXY" --listen 8920 --upstream $FAKE_PORT > $T/pt.log 2>&1 &
PT=$!; for _ in $(seq 1 50); do grep -q PROXY-READY $T/pt.log 2>/dev/null && break; sleep 0.1; done
GOT_PT=$(printf '%s\n' '{"method":"account","params":{"address":"x"}}' \
  | $PY -c "import socket,sys,json
s=socket.create_connection(('127.0.0.1',8920)); f=s.makefile('rwb',buffering=0)
f.write(sys.stdin.readline().encode()); r=json.loads(f.readline())
print(r['result']['registry']['registered_at'])")
kill $PT 2>/dev/null; wait $PT 2>/dev/null
[ "$GOT_PT" = "7" ] && assert "true" "proxy pass-through: registered_at relayed unchanged (7)" \
  || assert "false" "proxy pass-through: registered_at unchanged (got $GOT_PT)"

# tamper proxy (bump): registered_at must arrive as 8
$PY "$PROXY" --listen 8921 --upstream $FAKE_PORT \
   --method account --field registry.registered_at --mode bump > $T/tp.log 2>&1 &
TP=$!; for _ in $(seq 1 50); do grep -q PROXY-READY $T/tp.log 2>/dev/null && break; sleep 0.1; done
GOT_TP=$(printf '%s\n' '{"method":"account","params":{"address":"x"}}' \
  | $PY -c "import socket,sys,json
s=socket.create_connection(('127.0.0.1',8921)); f=s.makefile('rwb',buffering=0)
f.write(sys.stdin.readline().encode()); r=json.loads(f.readline())
print(r['result']['registry']['registered_at'])")
kill $TP 2>/dev/null; wait $TP 2>/dev/null
[ "$GOT_TP" = "8" ] && assert "true" "proxy bump: registered_at 7 -> 8 (nested field rewrite)" \
  || assert "false" "proxy bump: registered_at -> 8 (got $GOT_TP)"

kill $FAKE_PID 2>/dev/null; wait $FAKE_PID 2>/dev/null

# ───────────────────── PART B: live cluster tamper legs ───────────────────
echo
echo "=== PART B: live cluster — pass-through control + tamper legs ==="

$DETERM init --data-dir $T/node --profile regional_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-reg-tamper",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/node_p.json | tr -d '\n')
  ],
  "initial_balances": [ {"domain": "node_n", "balance": 100} ]
}
EOF
$DETERM genesis-tool build $T/node_gen.json | tail -1
NODE_HASH=$(cat $T/node_gen.json.hash)

$PY -c "
import json
cfg = '$T/node/config.json'
with open(cfg) as f: c = json.load(f)
c['domain'] = 'node_n'
c['listen_port'] = $NODE_LISTEN
c['rpc_port'] = $NODE_RPC
c['bootstrap_peers'] = []
c['genesis_path'] = '$TABS/node_gen.json'
c['genesis_hash'] = '$NODE_HASH'
c['chain_path'] = '$TABS/node/chain.json'
c['key_path'] = '$TABS/node/node_key.json'
c['data_dir'] = '$TABS/node'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open(cfg,'w') as f: json.dump(c,f,indent=2)
"

NODE_PIDS=("")
$DETERM start --config $T/node/config.json > $T/node/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3

for _ in $(seq 1 90); do
  H=$(get_status_field $NODE_RPC height)
  if [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field $NODE_RPC height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not an RP-3 defect). Reporting PART A only."
  echo
  echo "=== Test summary (proxy self-test only) ==="
  echo "  $pass_count pass / $fail_count fail"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_registrant_tamper (proxy self-test; live leg skipped)"; exit 0
  else
    echo "  FAIL: test_light_registrant_tamper"; exit 1
  fi
fi

# ── CONTROL: verify-registrant through a PASS-THROUGH proxy → INCLUDED/exit 0 ─
# Proves (a) the proxy is transparent and (b) the value-hash compare is REACHED
# and passes on honest input — without this, the tamper legs would be vacuous.
via_proxy 8922 node_n
echo "$VIA_OUT"
if [ "$VIA_RC" = "0" ] && echo "$VIA_OUT" | grep -qE "^INCLUDED"; then
  assert "true" "CONTROL: honest registry via pass-through proxy → INCLUDED, exit 0 (compare reached + passes)"
else
  assert "false" "CONTROL: pass-through proxy → INCLUDED/exit0 (got rc=$VIA_RC) — cannot gate a tamper leg without a live control"
fi

# ── TAMPER leg 1: bump registry.registered_at → value-hash mismatch ──────────
via_proxy 8923 node_n --method account --field registry.registered_at --mode bump
echo "$VIA_OUT"
if [ "$VIA_RC" = "3" ]; then
  assert "true" "TAMPER(registered_at): daemon-lied registry → UNVERIFIABLE, exit EXACTLY 3"
else
  assert "false" "TAMPER(registered_at): expected exit 3, got $VIA_RC"
fi
if echo "$VIA_OUT" | grep -q "does not match the recomputed hash of the account registry"; then
  assert "true" "TAMPER(registered_at): detail is the ACCOUNT-REGISTRY value-hash mismatch (the RP-3 cross-check fired)"
else
  assert "false" "TAMPER(registered_at): expected the account-registry mismatch detail"
fi
NOKEY=$(echo "$VIA_OUT" | grep -qE "locally-computed key|key_bytes" && echo false || echo true)
assert "$NOKEY" "TAMPER(registered_at): NOT a key-bind message — the key gate did not fire in the comparison's place"
NOFP=$(echo "$VIA_OUT" | grep -qE "^INCLUDED" && echo false || echo true)
assert "$NOFP" "TAMPER(registered_at): never a false INCLUDED"

# ── TAMPER leg 2: change registry.region → value-hash mismatch ───────────────
# A DIFFERENT field of the same registry, proving the value_hash binds the WHOLE
# registrant record (ed_pub‖registered_at‖active_from‖inactive_from‖region), not
# one field — "a lie about ANY registrant field is detected".
via_proxy 8924 node_n --method account --field registry.region --mode set --set TAMPERED_REGION
echo "$VIA_OUT"
if [ "$VIA_RC" = "3" ] && echo "$VIA_OUT" | grep -q "does not match the recomputed hash of the account registry"; then
  assert "true" "TAMPER(region): a different registry field lie → UNVERIFIABLE exit 3 (whole-record binding)"
else
  assert "false" "TAMPER(region): expected exit 3 + account-registry mismatch (got rc=$VIA_RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_registrant_tamper"; exit 0
else
  echo "  FAIL: test_light_registrant_tamper"; exit 1
fi
