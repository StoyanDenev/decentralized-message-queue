#!/usr/bin/env bash
# determ-light outbox — OFFLINE gate (no daemon). The durable sender outbox's
# local guarantees, each asserted at the layer that enforces it:
#
#   A. the three in-process selftests: the DOX1/DOM1 codec (selftest-outbox-record),
#      the submit-error classifier (selftest-outbox-classify), and the REAL
#      submit/reconcile cores over an in-process committee-signed fixture chain
#      (selftest-outbox-core: lost reply → identical bytes, exactly one application;
#      INCLUDED at head ≠ FINALIZED; SKIPPED from the nonce proof, counted once per
#      inclusion and capped; orphan re-arm; CONSUMED/UNLOCATED and its upgrade;
#      attribution across alternates; backoff; daemon-config; GAP; restart).
#   B. the CLI's durability contract with crash injection at every write step
#      (DETERM_LIGHT_OUTBOX_CRASH_POINT): "queued locally" is printed ONLY after
#      the record is published; before that no record exists and nothing is
#      acknowledged; a crash during a state UPDATE leaves the old record intact.
#   C. the syscall ORDER on Linux (strace, when available): fsync(tmp) precedes
#      the publish (link/rename), the directory fsync precedes the acknowledgement
#      write — the power-loss half of the guarantee, observed from outside.
#   D. corruption: a flipped status byte → CORRUPT-STATUS (bytes intact, `recover`
#      rebuilds as UNKNOWN); a flipped immutable byte → CORRUPT (quarantined, nonce
#      stays reserved); `status` exits 3 while any slot is corrupt; an unreadable
#      outbox.meta is reported, refuses every mutating verb, and `recover`
#      rebuilds it from an intact record.
#   E. bounds: the cap is refused BEFORE any write (file count unchanged); an
#      injected write failure (the ENOSPC path) leaves no record and no ack.
#   F. concurrency: while one process holds the directory lock (through the
#      binary's own fcntl / LockFileEx path) every mutating verb fails closed
#      (exit 5) and `status` still reads; `status` never deletes a stale temp file.
#   G. identity: `replace` keeps the msg_id on a fee bump, refuses a non-increase,
#      and a re-issue carries a new msg_id; a duplicate slot, a reused idempotency
#      key (exit 8, naming the slot it already holds) and a second keyfile (exit 6)
#      are refused. (An explicit --nonce below the
#      prune floor is refused too — gated live, where a floor can be raised.)
#   H. prune never removes a non-terminal slot; the nonce floor is kept.
#
# Mutants (each turns this gate RED; see docs/proofs/DurableOutboxSoundness.md):
#   M1  print the ack before the publish       → B (after_fsync: ack without a record)
#   M2  skip the record hash on load           → D (corruption undetected)
#   M4  "incumbent" classified as failure      → A classify + core 2
#   M5  FINALIZED without the successor bind   → A core 5 (INCLUDED-at-head leg)
#   M5b binding skipped inside verify_and_bind → A core 5b (stale served block)
#   M6  APPLIED on inclusion, no nonce proof   → A core 3 (SKIPPED leg)
#   M7  cap checked after the write            → E (file count)
#   M8  prune removes a non-terminal slot      → H
#   M9  durable write without fsync            → C (strace order; Linux)
#   M10 a skip counted per reconcile pass      → A core 3b (once per inclusion)
#   M11 submit run continues after a lost reply → A core 2b (stream desync)
#   M12 unverifiable probe not blocking        → A core 5c (never a terminal verdict)
#   M13 same-skip test after the height move  → A core 3c (a later skip never counted)
#   M14 proven-skipped inclusion attributed    → A core 11 (APPLIED from a known skip)
#   M15 attribution with an alternate unanswered → A core 12 (wrong alternate named)
#   M16 orphan re-arm of a spent nonce         → A core 13 (stale re-sends forever)
#   M17 CONSUMED never probed again            → A core 13 (no upgrade to APPLIED)
#   M18 same-skip requires a counted skip      → A core 3d (a re-issue re-counts)
#   ("retry re-signs with a fresh nonce" is not expressible: the submit core holds
#    no key; core 2/3 pin the re-sent hash.)
#
# Run from repo root: bash tools/test_light_outbox.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"
    exit 0
fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ] || [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ-wallet / determ binary not found (needed for a keyfile + a DGC1 genesis)"
    exit 0
fi

T=test_light_outbox
rm -rf "$T"; mkdir -p "$T/g"
pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
PY=python
command -v python >/dev/null 2>&1 || PY=python3
L="$DETERM_LIGHT"
TO=0x$($PY -c "print('c'*64)")

echo "=== A. in-process selftests ==="
for st in selftest-outbox-record selftest-outbox-classify selftest-outbox-core; do
  OUT=$("$L" $st 2>&1); RC=$?
  echo "$OUT" | grep -E "^  (PASS|FAIL):" | grep -v "PASS: $st" | sed 's/^/    /' | head -60
  [ "$RC" = "0" ] && echo "$OUT" | grep -q "PASS: $st" && assert true "$st green" || assert false "$st (rc=$RC)"
done

echo
echo "=== setup: DGC1 genesis + two DAK1 keyfiles ==="
cat > "$T/g/gen.json" <<EOF
{"chain_id":"outbox-offline","m_creators":1,"k_block_sigs":1,
 "initial_creators":[{"domain":"n1","ed_pub":"$($PY -c "print('11'*32)")","initial_stake":1000}],
 "initial_balances":[]}
EOF
"$DETERM" genesis-tool build "$T/g/gen.json" >/dev/null 2>&1 || { echo "  FAIL: genesis-tool build"; exit 1; }
G="$T/g/gen.json"
mk_key() {
  local out=$1
  local priv
  priv=$("$DETERM_WALLET" account-create-batch --count 1 --json 2>/dev/null | $PY -c "import json,sys; print(json.load(sys.stdin)['accounts'][0]['privkey_hex'])")
  "$DETERM_WALLET" account-import --priv "$priv" --out "$out" >/dev/null 2>&1
}
mk_key "$T/key_a.bin"; mk_key "$T/key_b.bin"
K="$T/key_a.bin"
[ -s "$K" ] && assert true "keyfiles created" || { assert false "keyfiles created"; exit 1; }
msgs() { ls "$1"/*.msg 2>/dev/null | wc -l | tr -d ' '; }
tmps() { ls "$1"/*.tmp 2>/dev/null | wc -l | tr -d ' '; }
enq() { "$L" outbox enqueue --outbox "$@"; }

echo
echo "=== B. crash points: ack ⟹ record; no record ⟹ no ack; update keeps the old record ==="
OB="$T/ob_crash"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 0 >/dev/null 2>&1
assert "$([ "$(msgs "$OB")" = "1" ] && echo true || echo false)" "baseline enqueue publishes slot 0"
for cp in before_write after_write after_fsync after_publish; do
  OUT=$(DETERM_LIGHT_OUTBOX_CRASH_POINT=$cp enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 6 --fee 1 --nonce 1 2>&1); RC=$?
  ACK=$(echo "$OUT" | grep -c "queued locally")
  N=$(msgs "$OB")
  case $cp in
    before_write|after_write|after_fsync)
      assert "$([ "$RC" = "97" ] && [ "$ACK" = "0" ] && [ "$N" = "1" ] && echo true || echo false)" "crash at $cp: no ack, no record (rc=$RC ack=$ACK msgs=$N)" ;;
    after_publish)
      assert "$([ "$RC" = "97" ] && [ "$ACK" = "0" ] && [ "$N" = "2" ] && echo true || echo false)" "crash at $cp: record published, ack not yet printed (rc=$RC ack=$ACK msgs=$N)" ;;
  esac
  # A crashed run may leave a temp file; it is never a record and the next
  # mutating command removes it under the lock (`status` never does).
  "$L" outbox status --outbox "$OB" >/dev/null 2>&1
  [ "$cp" = "after_fsync" ] && assert "$([ "$(tmps "$OB")" = "1" ] && echo true || echo false)" "status leaves the stale temp file in place (lock-free, read-only)"
done
"$L" outbox status --outbox "$OB" | grep -q "nonce=1 QUEUED" && assert true "the after_publish record is a valid, loadable slot" || assert false "the after_publish record is loadable"
assert "$([ "$(tmps "$OB")" = "0" ] && echo true || echo false)" "a mutating command removed the stale temp file"
# UPDATE path: a crash while `replace` rewrites slot 0 keeps the OLD record.
OUT=$(DETERM_LIGHT_OUTBOX_CRASH_POINT=after_fsync "$L" outbox replace --outbox "$OB" --genesis "$G" --keyfile "$K" --nonce 0 --fee 4 2>&1); RC=$?
ALTS=$("$L" outbox status --outbox "$OB" --json | $PY -c "import json,sys; d=json.load(sys.stdin); print(len([s for s in d['slots'] if s['nonce']==0][0]['alternates']))")
assert "$([ "$RC" = "97" ] && [ "$ALTS" = "1" ] && ! echo "$OUT" | grep -q recorded && echo true || echo false)" "crash during a state update leaves the old record intact (alternates=$ALTS)"

echo
echo "=== C. syscall order (Linux strace): fsync(tmp) < publish < fsync(dir) < ack ==="
if command -v strace >/dev/null 2>&1 && [ "$(uname -s)" = "Linux" ] && strace -o /dev/null true >/dev/null 2>&1; then
  OB="$T/ob_strace"; TR="$T/strace.txt"
  enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 0 >/dev/null 2>&1   # meta already pinned
  strace -f -e trace=fsync,fdatasync,rename,link,write,openat -o "$TR" "$L" outbox enqueue --outbox "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 1 >/dev/null 2>&1
  ORDER=$($PY - "$TR" <<'EOF'
import re, sys
lines = open(sys.argv[1]).read().splitlines()
pub = next((i for i, l in enumerate(lines) if re.search(r'(link|rename)\(".*00000000000000000001\.msg\.[0-9]+\.tmp", ".*00000000000000000001\.msg"\)', l)), None)
ack = next((i for i, l in enumerate(lines) if re.search(r'write\(1, "queued locally', l)), None)
open_tmp = next((i for i, l in enumerate(lines) if re.search(r'openat\(.*00000000000000000001\.msg\.[0-9]+\.tmp"', l)), None)
fs = [i for i, l in enumerate(lines) if re.search(r'\bf(data)?sync\(', l)]
print("ok" if (pub is not None and ack is not None and open_tmp is not None and any(open_tmp < i < pub for i in fs) and any(pub < i < ack for i in fs)) else "bad")
EOF
)
  assert "$([ "$ORDER" = "ok" ] && echo true || echo false)" "strace: an fsync sits between the temp write and the publish, and another between the publish and the ack"
else
  echo "  SKIP: strace not available or ptrace not permitted (the syscall-order leg runs on Linux only; the crash-point leg above still gates the ack ordering)"
fi

echo
echo "=== D. corruption ==="
OB="$T/ob_corrupt"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 0 >/dev/null 2>&1
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 1 >/dev/null 2>&1
$PY - "$OB/00000000000000000001.msg" <<'EOF'
import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[-40]^=1; open(p,'wb').write(b)
EOF
"$L" outbox status --outbox "$OB" > "$T/st.txt" 2>&1; RC=$?
grep -q "nonce=1 CORRUPT-STATUS" "$T/st.txt" && grep -q "nonce=0 QUEUED" "$T/st.txt" && [ "$RC" = "3" ] \
  && assert true "a flipped status byte → CORRUPT-STATUS on that slot only; status exits 3" \
  || assert false "corrupt status detection (rc=$RC): $(cat "$T/st.txt" | tr '\n' ' ' | cut -c1-200)"
"$L" outbox recover --outbox "$OB" >/dev/null 2>&1
"$L" outbox status --outbox "$OB" | grep -q "nonce=1 UNKNOWN" && assert true "recover rebuilds the status (bytes intact) as UNKNOWN" || assert false "recover rebuilds the status"
$PY - "$OB/00000000000000000001.msg" <<'EOF'
import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[52]^=1; open(p,'wb').write(b)
EOF
"$L" outbox status --outbox "$OB" > "$T/st2.txt" 2>&1; RC=$?
grep -q "nonce=1 CORRUPT" "$T/st2.txt" && [ "$RC" = "3" ] && assert true "a flipped immutable byte → CORRUPT (exit 3)" || assert false "corrupt immutable detection (rc=$RC)"
$PY - "$OB/00000000000000000001.msg" <<'EOF'
import sys; p=sys.argv[1]; b=open(p,'rb').read(); open(p,'wb').write(b[:len(b)//2])
EOF
"$L" outbox status --outbox "$OB" 2>&1 | grep -q "nonce=1 CORRUPT.*truncated" && assert true "a truncated record is refused with a field-named diagnostic" || assert false "truncated record diagnostic"
"$L" outbox recover --outbox "$OB" >/dev/null 2>&1
ls "$OB" | grep -q "00000000000000000001.msg.corrupt-" && assert true "recover quarantines the unreadable record (never deletes)" || assert false "quarantine file present"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 >/dev/null 2>&1
"$L" outbox status --outbox "$OB" | grep -q "nonce=2 QUEUED" && assert true "the quarantined nonce stays reserved: the next auto nonce is 2" || assert false "quarantined nonce reserved"
# An unreadable outbox.meta: status reports it (3), mutating verbs refuse (3, no
# write), recover rebuilds the pin from an intact record, the slots are untouched.
cp "$OB/outbox.meta" "$T/meta.bak"
$PY - "$OB/outbox.meta" <<'EOF2'
import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[8]^=1; open(p,'wb').write(b)
EOF2
"$L" outbox status --outbox "$OB" > "$T/st3.txt" 2>&1; RC_S=$?
OUT=$(enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 3 2>&1); RC_E=$?
N=$(msgs "$OB")
assert "$([ "$RC_S" = "3" ] && grep -q "META CORRUPT" "$T/st3.txt" && grep -q "nonce=0 QUEUED" "$T/st3.txt" && [ "$RC_E" = "3" ] && [ "$N" = "2" ] && echo true || echo false)" "a corrupt outbox.meta: status still lists the slots (exit 3); enqueue refuses without writing (status=$RC_S enqueue=$RC_E msgs=$N)"
"$L" outbox recover --outbox "$OB" > "$T/rec3.txt" 2>&1; RC_R=$?
"$L" outbox status --outbox "$OB" > "$T/st4.txt" 2>&1; RC_S=$?
assert "$([ "$RC_R" = "0" ] && grep -q "outbox.meta rebuilt" "$T/rec3.txt" && [ "$RC_S" = "0" ] && grep -q "nonce=0 QUEUED" "$T/st4.txt" && grep -q "nonce=2 QUEUED" "$T/st4.txt" && echo true || echo false)" "recover rebuilds outbox.meta from an intact record; every slot survives (recover=$RC_R status=$RC_S)"

echo
echo "=== E. bounds ==="
OB="$T/ob_cap"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 0 --nonce 0 --max-messages 2 >/dev/null 2>&1
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 0 --nonce 1 --max-messages 2 >/dev/null 2>&1
OUT=$(enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 0 --nonce 2 --max-messages 2 2>&1); RC=$?
assert "$([ "$RC" = "4" ] && [ "$(msgs "$OB")" = "2" ] && ! echo "$OUT" | grep -q "queued locally" && echo true || echo false)" "the cap is refused before any write (exit 4, 2 files remain)"
OB="$T/ob_enospc"
OUT=$(DETERM_LIGHT_OUTBOX_INJECT=write_fail enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 0 --nonce 0 2>&1); RC=$?
assert "$([ "$RC" = "1" ] && [ "$(msgs "$OB")" = "0" ] && ! echo "$OUT" | grep -q "queued locally" && echo "$OUT" | grep -q "write failed" && echo true || echo false)" "an injected write failure (ENOSPC path) leaves no record and no ack"

echo
echo "=== F. concurrency: the directory lock ==="
OB="$T/ob_lock"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 0 --nonce 0 >/dev/null 2>&1
# A mutating verb holds the lock for 4 s through the binary's own lock path
# (fcntl on POSIX, LockFileEx on Windows — the same code every platform runs).
DETERM_LIGHT_OUTBOX_HOLD_LOCK_S=4 "$L" outbox prune --outbox "$OB" >/dev/null 2>&1 & HOLDER=$!
sleep 1
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 0 --nonce 1 > "$T/lock_enq.txt" 2>&1; RC_E=$?
"$L" outbox recover --outbox "$OB" > "$T/lock_rec.txt" 2>&1; RC_R=$?
"$L" outbox status --outbox "$OB" > "$T/lock_st.txt" 2>&1; RC_S=$?
wait $HOLDER
assert "$([ "$RC_E" = "5" ] && [ "$RC_R" = "5" ] && echo true || echo false)" "mutating verbs fail closed (exit 5) while another process holds the lock (enqueue=$RC_E recover=$RC_R)"
assert "$([ "$RC_S" = "0" ] && echo true || echo false)" "status still reads under a held lock"
assert "$([ "$(msgs "$OB")" = "1" ] && echo true || echo false)" "no record was written by the locked-out worker"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 0 --nonce 1 >/dev/null 2>&1 && assert true "the lock is released when the holder exits" || assert false "lock released"

echo "=== G. identity and refusals ==="
OB="$T/ob_id"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 0 --idempotency-key order-77 >/dev/null 2>&1
J=$("$L" outbox status --outbox "$OB" --json)
MSG0=$(echo "$J" | $PY -c "import json,sys; print(json.load(sys.stdin)['slots'][0]['msg_id'])")
"$L" outbox replace --outbox "$OB" --genesis "$G" --keyfile "$K" --nonce 0 --fee 3 >/dev/null 2>&1
J=$("$L" outbox status --outbox "$OB" --json)
echo "$J" | $PY -c "
import json,sys; s=json.load(sys.stdin)['slots'][0]
alts=s['alternates']; ok = len(alts)==2 and alts[0]['kind']=='original' and alts[1]['kind']=='fee-bump' and alts[0]['msg_id']==alts[1]['msg_id']=='$MSG0' and alts[0]['tx_hash']!=alts[1]['tx_hash'] and s['fee']==3
sys.exit(0 if ok else 1)" && assert true "a fee bump keeps the msg_id, adds a new hash, and the active fee rises" || assert false "fee-bump identity"
"$L" outbox replace --outbox "$OB" --genesis "$G" --keyfile "$K" --nonce 0 --fee 3 >/dev/null 2>&1; RC=$?
assert "$([ "$RC" = "1" ] && echo true || echo false)" "a non-increasing fee bump is refused"
"$L" outbox replace --outbox "$OB" --genesis "$G" --keyfile "$K" --nonce 0 --fee 4 --amount 9 >/dev/null 2>&1
"$L" outbox status --outbox "$OB" --json | $PY -c "
import json,sys; s=json.load(sys.stdin)['slots'][0]; a=s['alternates']
sys.exit(0 if len(a)==3 and a[2]['kind']=='reissue' and a[2]['msg_id']!='$MSG0' and s['msg_id']==a[2]['msg_id'] else 1)" && assert true "a re-issue (different content) carries a new msg_id; the original stays watched" || assert false "re-issue identity"
OUT=$(enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 0 2>&1); RC=$?
assert "$([ "$RC" = "1" ] && echo "$OUT" | grep -q "already reserved" && echo true || echo false)" "a duplicate nonce slot is refused"
OUT=$(enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 4 --idempotency-key order-77 2>&1); RC=$?
assert "$([ "$RC" = "8" ] && echo "$OUT" | grep -q "already queued: nonce=0 msg_id=" && [ "$(msgs "$OB")" = "1" ] && echo true || echo false)" "a reused idempotency key is refused with the existing identity (exit 8, nothing written)"
OUT=$(enq "$OB" --genesis "$G" --keyfile "$T/key_b.bin" --to "$TO" --amount 5 --fee 1 --nonce 4 2>&1); RC=$?
assert "$([ "$RC" = "6" ] && echo true || echo false)" "a different sender keyfile is refused for this outbox (exit 6)"
OUT=$(enq "$OB" --genesis "$G" --keyfile "$K" --to "0x$($PY -c "print('C'*64)")" --amount 5 --fee 1 --nonce 4 2>&1); RC=$?
assert "$([ "$RC" = "1" ] && echo "$OUT" | grep -q "S-028" && echo true || echo false)" "a non-canonical anon --to is refused at enqueue (S-028)"
OUT=$(enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 4 --payload-hex "$($PY -c "print('ab'*129)")" 2>&1); RC=$?
assert "$([ "$RC" = "1" ] && echo "$OUT" | grep -q "TRANSFER_PAYLOAD_MAX" && echo true || echo false)" "an oversized payload is refused at enqueue"
OB2="$T/ob_offline"
OUT=$(enq "$OB2" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 2>&1); RC=$?
assert "$([ "$RC" = "1" ] && echo "$OUT" | grep -q "cannot reserve a nonce offline" && echo true || echo false)" "no history + no daemon + no --nonce → refused (never guesses a nonce)"
OUT=$(enq "$OB2" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --rpc-port 1 --nonce 3 2>&1); RC=$?
OUT=$(enq "$OB2" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --rpc-port 1 2>&1); RC=$?
"$L" outbox status --outbox "$OB2" | grep -q "nonce=4 QUEUED" && assert true "with a daemon unreachable the next nonce comes from local reservations (4 after 3)" || assert false "offline nonce continuation"
OUT=$("$L" outbox submit --outbox "$OB2" --genesis "$G" --rpc-port 1 2>&1); RC=$?
"$L" outbox status --outbox "$OB2" | grep -q "last=transport" && [ "$RC" = "0" ] && assert true "submit against an unreachable daemon keeps every slot QUEUED and records the transport error" || assert false "unreachable daemon handling (rc=$RC)"

echo
echo "=== H. prune ==="
OB="$T/ob_prune"
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 0 >/dev/null 2>&1
enq "$OB" --genesis "$G" --keyfile "$K" --to "$TO" --amount 5 --fee 1 --nonce 1 >/dev/null 2>&1
"$L" outbox prune --outbox "$OB" --older-than 0 >/dev/null 2>&1
assert "$([ "$(msgs "$OB")" = "2" ] && echo true || echo false)" "prune never removes a queued (non-terminal) slot, even with --older-than 0"

echo
echo "=== summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_outbox"; exit 0; fi
echo "  FAIL: test_light_outbox"; exit 1
