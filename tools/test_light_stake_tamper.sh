#!/usr/bin/env bash
# determ-light stake-trustless vs a LYING DAEMON — register claim SP-2
# (StakeProofSoundness value-hash cleartext cross-check, the s:-namespace sibling
# of the a:/r:/c: cross-checks already gated by CR-2 / RP-3 / SU-2).
#
# read_stake_trustless (light/main.cpp) Merkle-verifies the `s:` leaf against the
# COMMITTEE-BOUND state_root, then fetches the daemon's `stake_info` cleartext
# (locked, unlock_height) SEPARATELY and recomputes SHA256(u64_be(locked) ‖
# u64_be(unlock_height)) to confirm it equals the proven value_hash
# (light/main.cpp:2395). The Merkle+committee anchor prove WHICH leaf and its
# committed value_hash; this cross-check is the ONLY thing binding the daemon's
# separately-served (locked, unlock_height) cleartext to that hash. Delete it and
# a Byzantine daemon serves a genuine s: proof but a FALSE stake_info reply and the
# operator's stake-trustless output reports attacker-chosen (locked, unlock_height)
# as committee-verified — value mislocation feeding min_stake / unlock-maturity
# decisions off forged numbers. No honest daemon serves such a mismatch
# (node.cpp emits stake_info fields that hash to the committed value_hash), so the
# lie is injected by tools/rpc_tamper_proxy.py rewriting ONE stake_info field and
# forwarding everything else — the state_proof, committee, headers, block — verbatim.
#
# NON-VACUITY (the CR-2/RP-3 lesson): a tamper leg means nothing without a control
# proving the value-hash comparison is REACHED and honest-passes. So the SAME
# stake-trustless runs through a PASS-THROUGH instance of the SAME proxy first and
# must succeed (verified/exit 0) — that proves the proxy is transparent AND :2395
# passes on honest input. Only then do the tamper legs prove it REJECTS.
#
# THE DETAIL DIFFERENTIAL (the SU-2 lesson): stake-trustless maps EVERY throw to
# exit 1 (cmd_stake_trustless catch, light/main.cpp:2469) — the key-bind reject
# (:2312), the committee-attest SECURITY reject (:2361) and an RPC/open failure ALL
# exit 1 too. So "exit non-zero" (or even "exit 1") is NOT discriminating. Each
# tamper leg keys on the SPECIFIC detail: "TAMPERED — daemon's `stake_info` reply",
# and asserts it is NOT a SECURITY / key_bytes message — pinning that :2395 fired,
# not an earlier gate.
#
# Cluster-bound; NOT part of FAST=1 (needs a bindable local node) — same operating
# envelope as the other *-trustless / *-tamper cluster tests. PART A (offline proxy
# self-test) still runs where the live cluster SKIPs.
#
# Run from repo root: bash tools/test_light_stake_tamper.sh
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

T=test_light_stake_tamper
TABS=$PROJECT_ROOT/$T
NODE_RPC=8926
NODE_LISTEN=7926

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
# stake-trustless --json through it, capture OUT/RC, then stop the proxy.
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
    VIA_OUT=$($DETERM_LIGHT stake-trustless --rpc-port "$lport" \
                --genesis $T/node_gen.json --domain "$dom" --json 2>&1)
    VIA_RC=$?
  fi
  kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; PROXY_PID=""
  set +e
}

# ───────────────────── PART A: proxy self-test (no cluster) ───────────────
echo "=== PART A: proxy transparency + integer-set self-test (offline, no node) ==="
# A tiny fake JSON-line server serving a `stake_info` reply proves (1) the proxy
# relays it verbatim and (2) --mode set on an integer field yields an INTEGER on
# the wire (the JSON-coercion the unlock_height tamper leg depends on) — so a
# proxy regression is caught even where the live cluster SKIPs.
FAKE_PORT=8931
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
        if m == "stake_info":
            res = {"result": {"domain": "node_n", "locked": 1000,
                   "unlock_height": 18446744073709551615}, "error": None}
        else:
            res = {"result": {"echo": m}, "error": None}
        f.write((json.dumps(res) + "\n").encode())
while True:
    c,_ = srv.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF
FAKE_PID=$!
for _ in $(seq 1 50); do grep -q FAKE-READY $T/fake.log 2>/dev/null && break; sleep 0.1; done

# pass-through proxy: stake_info.locked must arrive UNCHANGED (1000, integer)
$PY "$PROXY" --listen 8932 --upstream $FAKE_PORT > $T/pt.log 2>&1 &
PT=$!; for _ in $(seq 1 50); do grep -q PROXY-READY $T/pt.log 2>/dev/null && break; sleep 0.1; done
GOT_PT=$(printf '%s\n' '{"method":"stake_info","params":{"domain":"node_n"}}' \
  | $PY -c "import socket,sys,json
s=socket.create_connection(('127.0.0.1',8932)); f=s.makefile('rwb',buffering=0)
f.write(sys.stdin.readline().encode()); r=json.loads(f.readline())
v=r['result']['locked']; print('%s|%s' % (v, type(v).__name__))")
kill $PT 2>/dev/null; wait $PT 2>/dev/null
[ "$GOT_PT" = "1000|int" ] && assert "true" "proxy pass-through: stake_info.locked relayed unchanged (1000, int)" \
  || assert "false" "proxy pass-through: locked unchanged int (got $GOT_PT)"

# integer-set proxy: unlock_height must arrive as INTEGER 12345 (JSON-coerced),
# not the string "12345" — else determ-light's si.value<uint64_t> would throw a
# type error with the WRONG detail instead of the value-hash TAMPERED message.
$PY "$PROXY" --listen 8933 --upstream $FAKE_PORT \
   --method stake_info --field unlock_height --mode set --set 12345 > $T/tp.log 2>&1 &
TP=$!; for _ in $(seq 1 50); do grep -q PROXY-READY $T/tp.log 2>/dev/null && break; sleep 0.1; done
GOT_TP=$(printf '%s\n' '{"method":"stake_info","params":{"domain":"node_n"}}' \
  | $PY -c "import socket,sys,json
s=socket.create_connection(('127.0.0.1',8933)); f=s.makefile('rwb',buffering=0)
f.write(sys.stdin.readline().encode()); r=json.loads(f.readline())
v=r['result']['unlock_height']; print('%s|%s' % (v, type(v).__name__))")
kill $TP 2>/dev/null; wait $TP 2>/dev/null
[ "$GOT_TP" = "12345|int" ] && assert "true" "proxy set: unlock_height -> integer 12345 (JSON-coerced, not a string)" \
  || assert "false" "proxy set: unlock_height -> int 12345 (got $GOT_TP)"

kill $FAKE_PID 2>/dev/null; wait $FAKE_PID 2>/dev/null

# ───────────────────── PART B: live cluster tamper legs ───────────────────
echo
echo "=== PART B: live cluster — pass-through control + tamper legs ==="

$DETERM init --data-dir $T/node --profile regional_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-stake-tamper",
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
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open(cfg,'w') as f: json.dump(c,f,indent=2)
"

NODE_PIDS=("")
$DETERM start --config $T/node/config.json > $T/node/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3

# stake-trustless requires the chain to have activated state_root (S-033); wait
# for a comfortable interior height so the s: leaf is committee-anchored.
for _ in $(seq 1 120); do
  H=$(get_status_field $NODE_RPC height)
  if [ "$H" != "-" ] && [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.3
done
NODE_H=$(get_status_field $NODE_RPC height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 5 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap in budget — environment too starved"
  echo "        (not an SP-2 defect). Reporting PART A only."
  echo
  echo "=== Test summary (proxy self-test only) ==="
  echo "  $pass_count pass / $fail_count fail"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_stake_tamper (proxy self-test; live leg skipped)"; exit 0
  else
    echo "  FAIL: test_light_stake_tamper"; exit 1
  fi
fi

# ── CONTROL: stake-trustless through a PASS-THROUGH proxy → verified/exit 0 ──
# Proves (a) the proxy is transparent and (b) the value-hash compare (:2395) is
# REACHED and passes on honest input — without this the tamper legs are vacuous.
via_proxy 8927 node_n
echo "$VIA_OUT"
VERIFIED=$(echo "$VIA_OUT" | tail -1 | $PY -c "import sys,json
try: print('true' if json.loads(sys.stdin.read()).get('verified') else 'false')
except: print('false')")
if [ "$VIA_RC" = "0" ] && [ "$VERIFIED" = "true" ]; then
  assert "true" "CONTROL: honest stake_info via pass-through proxy → verified=true, exit 0 (compare reached + passes)"
else
  assert "false" "CONTROL: pass-through proxy → verified/exit0 (got rc=$VIA_RC verified=$VERIFIED) — cannot gate a tamper leg without a live control"
fi

# ── TAMPER leg 1: bump stake_info.locked → value-hash mismatch ───────────────
via_proxy 8928 node_n --method stake_info --field locked --mode bump
echo "$VIA_OUT"
if [ "$VIA_RC" = "1" ]; then
  assert "true" "TAMPER(locked): daemon-lied stake_info → exit EXACTLY 1 (the cmd catch)"
else
  assert "false" "TAMPER(locked): expected exit 1, got $VIA_RC"
fi
if echo "$VIA_OUT" | grep -q "TAMPERED" && echo "$VIA_OUT" | grep -q "stake_info"; then
  assert "true" "TAMPER(locked): detail is the stake_info value-hash TAMPERED message (the SP-2 cross-check at :2395 fired)"
else
  assert "false" "TAMPER(locked): expected the stake_info TAMPERED detail"
fi
NOSEC=$(echo "$VIA_OUT" | grep -qE "SECURITY|key_bytes|committee-attested" && echo false || echo true)
assert "$NOSEC" "TAMPER(locked): NOT a SECURITY/key-bind message — an EARLIER gate did not fire in :2395's place"
NOFP=$(echo "$VIA_OUT" | tail -1 | $PY -c "import sys,json
try: print('false' if json.loads(sys.stdin.read()).get('verified') else 'true')
except: print('true')")
assert "$NOFP" "TAMPER(locked): never a false verified=true"

# ── TAMPER leg 2: set stake_info.unlock_height → value-hash mismatch ─────────
# A DIFFERENT scalar of the same leaf, proving the value_hash binds BOTH
# (locked ‖ unlock_height), not just locked — "a lie about EITHER scalar is caught".
via_proxy 8929 node_n --method stake_info --field unlock_height --mode set --set 12345
echo "$VIA_OUT"
if [ "$VIA_RC" = "1" ] && echo "$VIA_OUT" | grep -q "TAMPERED" && echo "$VIA_OUT" | grep -q "stake_info"; then
  assert "true" "TAMPER(unlock_height): a different leaf scalar lie → exit 1 + stake_info TAMPERED (whole-leaf binding)"
else
  assert "false" "TAMPER(unlock_height): expected exit 1 + stake_info TAMPERED (got rc=$VIA_RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_stake_tamper"; exit 0
else
  echo "  FAIL: test_light_stake_tamper"; exit 1
fi
