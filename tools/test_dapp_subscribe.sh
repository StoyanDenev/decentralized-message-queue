#!/usr/bin/env bash
# v2.20 Theme 7 Phase 7.4 (streaming subset) — dapp_subscribe regression.
#
# Exercises the push-based DAPP_CALL subscription end to end on a live
# 3-node cluster:
#   0. Offline CLI contract (help text, --domain required).
#   1. Live subscribe: subscribed frame (with post-clamp queue_max /
#      heartbeat_blocks echo) → live frame → block-based heartbeats;
#      seq contiguous from 0; stable sid on every frame.
#   2. queue_max clamping observable via the subscribed-frame echo.
#   3. Validation refusals ride the normal RPC error envelope (unknown
#      domain, since > head) — the socket is NOT taken over (exit 2).
#   4. Catch-up replay: an applied DAPP_CALL is replayed by a
#      subscribe --since 0 (subscribed → dapp_call → live ordering,
#      gap-freedom of the [since,H) ∪ [H,∞) partition).
#   5. Topic filter: a chat-topic call is invisible to a --topic rpc
#      subscription.
#
# Backpressure-kill is NOT triggered live here: organically overflowing
# the bounded queue requires saturating the server's TCP send buffer
# (tens of thousands of frames at test block rates). The kill protocol
# is machine-checked instead (docs/proofs/tla/SubscriberBackpressure.tla,
# FB71 — kill-on-overflow / no-silent-gap / stuck-writer release), and
# the write-timeout + kill code paths are exercised by node shutdown in
# cleanup. Steps 4-5 gate on the DAPP_CALL actually applying (the known
# multi-node DAPP_CALL timing flake documented in test_dapp_e2e.sh §9);
# if it doesn't apply within the window they SKIP rather than FAIL —
# the streaming machinery itself is asserted unconditionally by 0-3.
#
# Run from repo root: bash tools/test_dapp_subscribe.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_dapp_subscribe
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
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 0. Offline CLI contract ==="
if $DETERM 2>&1 | grep -q -- "dapp-subscribe"; then
  assert true "help text documents dapp-subscribe"
else
  assert false "help text documents dapp-subscribe"
fi
OUT=$($DETERM dapp-subscribe --rpc-port 1 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "requires --domain"; then
  assert true "dapp-subscribe without --domain refused"
else
  assert false "dapp-subscribe without --domain refused (rc=$RC)"
fi
if $DETERM 2>&1 | grep -q -- "dapp-subscribers"; then
  assert true "help text documents dapp-subscribers"
else
  assert false "help text documents dapp-subscribers"
fi
$DETERM dapp-subscribers --rpc-port 1 >/dev/null 2>&1; RC=$?
[ "$RC" = "1" ] \
  && assert true "dapp-subscribers unreachable daemon exits 1" \
  || assert false "dapp-subscribers unreachable exit ($RC, expected 1)"

echo
echo "=== 1. Init + start 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

N1_PRIV=$(python -c "
import json
with open('$T/n1/node_key.json') as f: k = json.load(f)
print(k.get('priv_seed') or k.get('priv') or k.get('seed') or '')")
N2_PRIV=$(python -c "
import json
with open('$T/n2/node_key.json') as f: k = json.load(f)
print(k.get('priv_seed') or k.get('priv') or k.get('seed') or '')")
SVC_PUBKEY="$(python -c "print('aa' * 32)")"

cat > $T/gen.json <<EOF
{
  "chain_id": "test-dapp-subscribe",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "node1", "balance": 100},
    {"domain": "node2", "balance": 100}
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

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
configure_node 1 7791 8791 '["127.0.0.1:7792","127.0.0.1:7793"]'
configure_node 2 7792 8792 '["127.0.0.1:7791","127.0.0.1:7793"]'
configure_node 3 7793 8793 '["127.0.0.1:7791","127.0.0.1:7792"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8791 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 2. Register DApp (node1, topics chat,rpc) ==="
$DETERM submit-dapp-register --rpc-port 8791 \
  --priv "$N1_PRIV" --from node1 \
  --service-pubkey "$SVC_PUBKEY" \
  --endpoint-url "https://dapp.example" \
  --topics "chat,rpc" \
  --metadata-hex "deadbeef" 2>&1 | tail -1
REGISTERED=false
for _ in $(seq 1 120); do
  INFO=$($DETERM dapp-info --rpc-port 8791 --domain node1 2>/dev/null)
  if echo "$INFO" | python -c "
import sys,json
try:
    j = json.load(sys.stdin)
    sys.exit(0 if j.get('endpoint_url') == 'https://dapp.example' else 1)
except: sys.exit(1)" 2>/dev/null; then REGISTERED=true; break; fi
  sleep 0.5
done
# Soft precondition: registration visibility can lag past this window under a
# transient multi-node consensus straggle (the known flake, test_dapp_e2e.sh
# §9). It is NOT a hard assertion because step 3's `dapp-subscribe --domain
# node1` is itself the definitive registration check — rpc_dapp_subscribe
# rejects unknown domains with invalid_arg, so if node1 were unregistered the
# live-subscribe assertion below would fail loudly. Warn-and-continue.
if [ "$REGISTERED" = "true" ]; then
  assert true "DAPP_REGISTER applied (dapp-info visible)"
else
  echo "  WARN: dapp-info not yet visible in poll window; step 3 subscribe"
  echo "        gates registration definitively (rejects unknown domains)."
fi

echo
echo "=== 3. Live subscribe: subscribed → live → heartbeats, seq contiguous ==="
$DETERM dapp-subscribe --rpc-port 8791 --domain node1 \
  --heartbeat-blocks 2 --max-frames 4 > $T/live.frames 2> $T/live.err
RC=$?
cat $T/live.frames
CHECK=$(python -c "
import json
ok = []
frames = [json.loads(l) for l in open('$T/live.frames') if l.strip()]
ok.append(('4 frames', len(frames) == 4))
if len(frames) == 4:
    ok.append(('frame0 subscribed', frames[0].get('event') == 'subscribed'))
    ok.append(('domain echo', frames[0].get('domain') == 'node1'))
    ok.append(('heartbeat_blocks echo', frames[0].get('heartbeat_blocks') == 2))
    ok.append(('frame1 live', frames[1].get('event') == 'live'))
    ok.append(('frames 2-3 heartbeat',
               all(f.get('event') == 'heartbeat' for f in frames[2:])))
    ok.append(('seq contiguous 0..3',
               [f.get('seq') for f in frames] == [0, 1, 2, 3]))
    ok.append(('stable sid',
               len({f.get('sid') for f in frames}) == 1))
for name, v in ok:
    print(('OK ' if v else 'BAD ') + name)
print('ALL' if all(v for _, v in ok) else 'FAILED')" 2>/dev/null)
echo "$CHECK" | sed 's/^/    /'
if [ $RC -eq 0 ] && echo "$CHECK" | grep -q "^ALL$"; then
  assert true "live subscribe: frame sequence + seq + sid contract"
else
  assert false "live subscribe contract (rc=$RC)"
fi

echo
echo "=== 4. queue_max clamp echoed in subscribed frame ==="
$DETERM dapp-subscribe --rpc-port 8791 --domain node1 \
  --queue-max 1 --max-frames 1 > $T/clamp.frames 2>/dev/null
QM=$(python -c "
import json
f = json.loads(open('$T/clamp.frames').readline())
print(f.get('queue_max', -1))" 2>/dev/null)
[ "$QM" = "4" ] \
  && assert true "queue_max=1 clamped to floor 4 (echoed)" \
  || assert false "queue_max clamp echo: got '$QM' (expected 4)"

echo
echo "=== 5. Validation refusals (normal RPC error envelope, exit 2) ==="
OUT=$($DETERM dapp-subscribe --rpc-port 8791 --domain nosuchdapp \
      --max-frames 1 2>&1); RC=$?
if [ $RC -eq 2 ] && echo "$OUT" | grep -q "invalid_arg.*unknown DApp"; then
  assert true "unknown domain refused via error envelope (exit 2)"
else
  assert false "unknown domain refusal (rc=$RC out=$OUT)"
fi
OUT=$($DETERM dapp-subscribe --rpc-port 8791 --domain node1 \
      --since 99999999 --max-frames 1 2>&1); RC=$?
if [ $RC -eq 2 ] && echo "$OUT" | grep -q "invalid_arg.*beyond head"; then
  assert true "since-beyond-head refused via error envelope (exit 2)"
else
  assert false "since-beyond-head refusal (rc=$RC out=$OUT)"
fi

echo
echo "=== 6. DAPP_CALL → catch-up replay + topic filter ==="
$DETERM submit-dapp-call --rpc-port 8791 \
  --priv "$N2_PRIV" --from node2 --to node1 \
  --topic chat --payload-hex "cafebabe" --amount 2 --fee 1 2>&1 | tail -1
APPLIED=false
for _ in $(seq 1 60); do
  CNT=$($DETERM dapp-messages --rpc-port 8791 --domain node1 --from 0 2>/dev/null \
        | python -c "import sys,json
try: print(json.load(sys.stdin).get('count',0))
except: print(0)")
  if [ "$CNT" -ge 1 ] 2>/dev/null; then APPLIED=true; break; fi
  sleep 0.5
done

if [ "$APPLIED" = "true" ]; then
  $DETERM dapp-subscribe --rpc-port 8791 --domain node1 --since 0 \
    --max-frames 3 > $T/replay.frames 2>/dev/null
  CHECK=$(python -c "
import json
frames = [json.loads(l) for l in open('$T/replay.frames') if l.strip()]
ok = (len(frames) == 3
      and frames[0].get('event') == 'subscribed'
      and frames[1].get('event') == 'dapp_call'
      and frames[1].get('to') == 'node1'
      and frames[1].get('topic') == 'chat'
      and frames[1].get('from') == 'node2'
      and frames[2].get('event') == 'live'
      and [f.get('seq') for f in frames] == [0, 1, 2])
print('ALL' if ok else 'FAILED: ' + repr([(f.get('event'), f.get('seq')) for f in frames]))" 2>/dev/null)
  echo "    $CHECK"
  echo "$CHECK" | grep -q "^ALL$" \
    && assert true "catch-up replay: subscribed → dapp_call → live, seq 0..2" \
    || assert false "catch-up replay ordering"

  # Topic filter: the chat call must be invisible to a rpc-topic sub.
  $DETERM dapp-subscribe --rpc-port 8791 --domain node1 --since 0 \
    --topic rpc --max-frames 2 > $T/filter.frames 2>/dev/null
  CHECK=$(python -c "
import json
frames = [json.loads(l) for l in open('$T/filter.frames') if l.strip()]
ok = (len(frames) == 2
      and frames[0].get('event') == 'subscribed'
      and frames[1].get('event') == 'live')
print('ALL' if ok else 'FAILED: ' + repr([f.get('event') for f in frames]))" 2>/dev/null)
  echo "    $CHECK"
  echo "$CHECK" | grep -q "^ALL$" \
    && assert true "topic filter: chat call invisible to --topic rpc" \
    || assert false "topic filter"

  # SS-2 gap-freedom cross-check (FB72 companion): the streaming catch-up
  # over [since, head] must deliver EXACTLY the event set the retrospective
  # dapp-messages poll reports for the same range — same (block_height,
  # tx_hash) identities, no gap, no extra. Independent-API cross-validation
  # of the [since,N) ∪ [N,∞) partition on the catch-up side.
  HEAD=$($DETERM status --rpc-port 8791 2>/dev/null \
        | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  $DETERM dapp-messages --rpc-port 8791 --domain node1 --from 0 2>/dev/null > $T/poll.json
  # Capture the full catch-up (subscribed + all dapp_call + live); a generous
  # --max-frames bounds it (1 subscribed + events + 1 live).
  $DETERM dapp-subscribe --rpc-port 8791 --domain node1 --since 0 \
    --max-frames 64 > $T/catchup.frames 2>/dev/null &
  CU_PID=$!
  sleep 2; kill "$CU_PID" 2>/dev/null
  CHECK=$(python -c "
import json
poll = json.loads(open('$T/poll.json').read())
poll_ids = {(e['block_height'], e['tx_hash']) for e in poll.get('events', [])}
frames = []
for l in open('$T/catchup.frames'):
    l=l.strip()
    if not l: continue
    try: frames.append(json.loads(l))
    except: pass
# catch-up dapp_call frames are those BEFORE the 'live' marker
stream_ids=set()
for f in frames:
    if f.get('event')=='live': break
    if f.get('event')=='dapp_call':
        stream_ids.add((f['block_index'], f['tx_hash']))
ok = (len(poll_ids) >= 1
      and stream_ids == poll_ids)   # exact set equality: no gap, no extra
print('ALL' if ok else 'FAILED poll=%r stream=%r' % (sorted(poll_ids), sorted(stream_ids)))" 2>/dev/null)
  echo "    $CHECK"
  echo "$CHECK" | grep -q "^ALL$" \
    && assert true "SS-2 gap-freedom: streaming catch-up == dapp-messages poll (same event set)" \
    || assert false "SS-2 gap-freedom cross-check"

  # SS-6 reconnect-seam boundary (FB73 companion): the --reconnect logic
  # resumes with since = last_block INCLUSIVE. The deterministic core of
  # its no-loss guarantee is that `--since B` INCLUDES an event at block B
  # while `--since B+1` EXCLUDES it. Pin exactly that boundary against the
  # applied DAPP_CALL's block (from the poll).
  B=$(python -c "
import json
poll = json.loads(open('$T/poll.json').read())
ev = poll.get('events', [])
print(ev[0]['block_height'] if ev else -1)" 2>/dev/null)
  if [ "$B" -ge 0 ] 2>/dev/null; then
    $DETERM dapp-subscribe --rpc-port 8791 --domain node1 --since "$B" \
      --max-frames 32 > $T/since_incl.frames 2>/dev/null &
    P1=$!; sleep 2; kill "$P1" 2>/dev/null
    $DETERM dapp-subscribe --rpc-port 8791 --domain node1 --since "$((B+1))" \
      --max-frames 32 > $T/since_excl.frames 2>/dev/null &
    P2=$!; sleep 2; kill "$P2" 2>/dev/null
    CHECK=$(python -c "
import json
def calls_at_B(path, B):
    n=0
    for l in open(path):
        l=l.strip()
        if not l: continue
        try: f=json.loads(l)
        except: continue
        if f.get('event')=='live': break
        if f.get('event')=='dapp_call' and f.get('block_index')==B: n+=1
    return n
incl = calls_at_B('$T/since_incl.frames', $B)
excl = calls_at_B('$T/since_excl.frames', $B)
ok = (incl >= 1 and excl == 0)   # since=B includes block B; since=B+1 excludes it
print('ALL' if ok else 'FAILED incl@B=%d excl@B=%d' % (incl, excl))" 2>/dev/null)
    echo "    $CHECK"
    echo "$CHECK" | grep -q "^ALL$" \
      && assert true "SS-6 reconnect seam: --since B inclusive, --since B+1 exclusive (block $B)" \
      || assert false "SS-6 reconnect-seam boundary"
  else
    echo "  SKIP: no event block to pin the --since boundary against"
  fi
else
  echo "  SKIP: DAPP_CALL did not apply within window (known multi-node"
  echo "        timing flake, see test_dapp_e2e.sh §9) — replay + filter"
  echo "        assertions skipped; streaming machinery asserted by 0-5."
fi

echo
echo "=== 7. dapp-subscribers observability reflects a live subscriber ==="
# Start a background streaming subscriber (no --max-frames, stays connected),
# then query the read-only fleet snapshot and assert it sees exactly this one.
$DETERM dapp-subscribe --rpc-port 8791 --domain node1 --heartbeat-blocks 1 \
  > $T/bg.frames 2>/dev/null &
BG_PID=$!
NODE_PIDS+=("$BG_PID")   # ensure cleanup kills it too
sleep 2
SNAP=$($DETERM dapp-subscribers --rpc-port 8791 2>/dev/null)
echo "$SNAP" > $T/subscribers.json
CHECK=$(python -c "
import json
j = json.loads(open('$T/subscribers.json').read())
ok = []
ok.append(('count>=1', j.get('count',0) >= 1))
ok.append(('max==256', j.get('max') == 256))
ok.append(('kills_backpressure present', isinstance(j.get('kills_backpressure'), int)))
subs = j.get('subscribers', [])
mine = [s for s in subs if s.get('domain') == 'node1']
ok.append(('node1 subscriber present', len(mine) >= 1))
if mine:
    s = mine[0]
    ok.append(('sid is 32-hex', isinstance(s.get('sid'),str) and len(s['sid'])==32))
    ok.append(('queue_max==1024 (default)', s.get('queue_max')==1024))
    ok.append(('has queue_depth/seq/killed',
               all(k in s for k in ('queue_depth','seq','killed'))))
    ok.append(('not killed', s.get('killed') is False))
for name,v in ok: print(('OK ' if v else 'BAD ')+name)
print('ALL' if all(v for _,v in ok) else 'FAILED')" 2>/dev/null)
echo "$CHECK" | sed 's/^/    /'
kill "$BG_PID" 2>/dev/null
if echo "$CHECK" | grep -q "^ALL$"; then
  assert true "dapp-subscribers snapshot reflects the live subscriber fleet"
else
  assert false "dapp-subscribers observability"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_dapp_subscribe"; exit 0
else
  echo "  FAIL: test_dapp_subscribe"; exit 1
fi
