#!/usr/bin/env bash
# test_light_outbox_flag_surface.sh — S-113: `determ-light outbox`'s PER-VERB option
# surface, measured against the RUNNING BINARY.
#
# THE DEFECT CLASS
# ----------------
# `light/outbox_cli.cpp` has ONE `parse_args` for all seven verbs (enqueue, submit,
# reconcile, status, replace, prune, recover). Until 2026-09-18 it also ACCEPTED the
# union of every verb's flags FOR EVERY VERB, so each verb carried a silent
# accept-and-ignore surface. The instance that was found (S-112) is `--wait`: the
# parser took it on all seven, exactly one (`reconcile`) consumed it, and `enqueue` —
# which has a binding trust-minimized read — dropped it, so `outbox enqueue --wait 30`
# exited having waited for nothing while the operator believed the read would block.
# The other five accepted it with no binding read at all. Nothing in the tree could
# see any of that: an ignored flag changes no output, no exit code and no file, so it
# is invisible to every existing gate, and it stayed invisible for weeks.
#
# WHAT THIS GATE ASSERTS — and how
# --------------------------------
# The property, in two halves:
#   PER VERB        — for every (verb, flag) pair the parser recognizes, the verb
#                     either OBSERVABLY ACTS ON the flag or REFUSES it;
#   PER INVOCATION  — a flag the verb does read, but that nothing reads in the
#                     configuration it was given (`enqueue --wait` with no
#                     `--rpc-port`, or with an explicit `--nonce`; `reconcile
#                     --state` with no `--resume`), is REFUSED there too.
# Nothing here greps light/outbox_cli.cpp for an identifier — a grep-of-source gate is
# precisely what let this defect live. Everything below is read off the binary's
# behaviour: an exit code, a produced or unchanged file, a JSON field, a diagnostic it
# printed, or a wall-clock window.
#
#   A. THE MATRIX. The FLAG UNIVERSE is DERIVED FROM THE BINARY, not listed here: each
#      verb is provoked into its own wrong-verb refusal, which prints "accepted here:
#      <its set>", and the union of the seven printed sets is the universe. All
#      7 x |universe| pairs are then driven through the binary and each is classified
#      from what the process did — ACCEPTED, REFUSED-BY-THIS-VERB, REFUSED-AS-INERT-HERE
#      (accepted by the verb, inert as invoked), or NOT RECOGNIZED BY THE PARSER AT ALL.
#      Three sets must then agree per verb: what the binary ACCEPTS (measured), what the
#      binary SAYS it accepts (its own "accepted here:" line), and the contract restated
#      in this file by hand. A verb that starts accepting a flag it does not read is RED;
#      one that starts refusing a flag it does read is RED; and a 20th flag added to the
#      parser is RED, because it enters the universe through the binary's own answer and
#      then fails the contract. Plus: an invented flag is refused by every verb with the
#      OTHER diagnostic ("unknown arg"), so the refusal is not a blanket rejection of
#      everything, and the refusal classes stay distinguishable to an operator.
#   B. THE EFFECT. For every pair the matrix found ACCEPTED, two runs that differ only
#      in that flag must differ in something observable. This is the half that a
#      "does it parse?" check cannot do and the half the defect lived in. Where the
#      effect genuinely cannot be reached without a chain or a daemon, the leg prints
#      `SKIP:` with the cause and banks NO pass. B5 probes the per-invocation half:
#      each inert configuration must REFUSE fail-closed, naming the flag AND the flag
#      whose presence or absence made it inert, and its enabling configuration must not.
#      B then CLOSES OVER LEG A: every pair leg A measured as accepted must have been
#      probed here or declined here BY NAME, and nothing may be registered that the
#      binary does not accept. Without that assertion leg B's completeness is a fact
#      about today, maintained by hand, with nothing keeping it.
#   C. HELP PARITY. The flags `determ-light help` advertises for a verb must be exactly
#      the flags leg A MEASURED the binary accepting. Both sides are the running binary,
#      so this cannot be satisfied by editing a comment: advertising a flag a verb
#      refuses is RED, and quietly accepting one it does not advertise is RED.
#   D. THE S-112 INSTANCE, end to end: `determ-light selftest-outbox-hint-wait` drives
#      the REAL nonce-hint read over an in-process committee-signed fixture chain and
#      asserts the operator's `--wait` reaches it — by the number of times the reader
#      came back for the successor, by the diagnostic it fails closed with, and by the
#      hint existing at all only when the wait carried through.
#
# WHAT THIS GATE DOES NOT ASSERT (so a green is not misread)
# ---------------------------------------------------------
#   * That `cmd_enqueue` passes the operator's wait INTO the nonce-hint route. Leg D
#     drives the route, not the CLI verb, because reaching the verb's read needs a
#     committee-signed chain behind a socket. That call site is covered by
#     tools/test_light_wait_surface.sh's derived-helper check (its RJ selftest case
#     injects exactly a literal 0 there and requires RED), and by the route's
#     wait parameter having no default, which makes an omitted argument a compile error.
#   * The EFFECT of `--wait` on enqueue: the only peer this gate can start accepts and
#     never answers, so the successor poll the wait bounds is never reached. Declined by
#     name in B; leg D drives the route it feeds. Its REFUSAL in both inert
#     configurations is asserted in B5.
#   * `--older-than` / `--include-unlocated` on prune: both select among PROVEN-consumed
#     slots (FINALIZED/APPLIED, or CONSUMED), and no offline path can produce one — it
#     takes a daemon-verified inclusion. Covered live by tools/test_light_outbox_live.sh.
#   * `--resume` / `--state` / `--json` / `--wait` on reconcile: each is read only after
#     the daemon connection is up (the anchor cache, the JSON emitter and the successor
#     poll all sit past `connect_and_pin`). Covered live by the same gate.
#   * That a verb's accepted flag is honoured CORRECTLY — only that its value changes
#     what the verb does. Correctness of each flag is the business of the gates that own
#     the behaviour (tools/test_light_outbox.sh, the outbox selftests, the live gate).
#
# Needs determ-light, determ-wallet and determ (a DGC1 genesis + two DAK1 keyfiles).
# FAILS CLOSED when any is missing: this gate measures a binary, and one that cannot
# run must not report green. No network beyond 127.0.0.1, no cluster, no daemon; the
# only peer is a local listener started by this script that accepts a connection and
# never answers, which is what makes --timeout-ms and --rpc-port observable. Where it
# cannot be started the legs that need it SKIP by name and bank no pass.
#
# Run from repo root: bash tools/test_light_outbox_flag_surface.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

pass_count=0; fail_count=0; skip_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
decline() { echo "  SKIP: $1"; skip_count=$((skip_count + 1)); }
# Leg B's coverage ledger, closed over leg A's measurement at the end of B. `cover`
# is called AT the probe that measures the pair, `declined_pairs` beside the SKIP
# line that names why a pair is not probed. A pair in neither is a hole and is RED.
B_COVERED=""; B_DECLINED=""
cover()          { for pp in "$@"; do B_COVERED="$B_COVERED $pp"; done; }
declined_pairs() { for pp in "$@"; do B_DECLINED="$B_DECLINED $pp"; done; }

for need in DETERM_LIGHT DETERM_WALLET DETERM; do
  eval "binpath=\${$need:-}"
  if [ -z "$binpath" ] || [ ! -x "$binpath" ]; then
    echo "  FAIL: test_light_outbox_flag_surface — \$$need is not an executable binary;"
    echo "        this gate measures the RUNNING binary and one that cannot run must not report green"
    exit 1
  fi
done
L="$DETERM_LIGHT"
PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "  FAIL: test_light_outbox_flag_surface — python is required to build the fixtures"
  exit 1
fi

T=test_light_outbox_flag_surface
rm -rf "$T"; mkdir -p "$T"
# The listener is always reaped; the scratch tree is removed only on a GREEN run, so a
# RED one leaves its genesis, keyfiles and outboxes on disk to be looked at.
trap 'kill "${STALL_PID:-}" 2>/dev/null' EXIT

echo "=== setup: two DGC1 genesis files, two DAK1 keyfiles, a pinned outbox ==="
mkgen() {   # $1 out path, $2 chain id
  cat > "$1" <<EOF
{"chain_id":"$2","m_creators":1,"k_block_sigs":1,
 "initial_creators":[{"domain":"n1","ed_pub":"$($PY -c "print('11'*32)")","initial_stake":1000}],
 "initial_balances":[]}
EOF
  "$DETERM" genesis-tool build "$1" >/dev/null 2>&1
}
mkgen "$T/gen.json"  "outbox-flagsurface"
mkgen "$T/gen2.json" "outbox-flagsurface-other"
G="$T/gen.json"; G2="$T/gen2.json"; GBAD="$T/no-such-genesis.json"
mkkey() {
  local priv
  priv=$("$DETERM_WALLET" account-create-batch --count 1 --json 2>/dev/null \
         | $PY -c "import json,sys; print(json.load(sys.stdin)['accounts'][0]['privkey_hex'])")
  "$DETERM_WALLET" account-import --priv "$priv" --out "$1" >/dev/null 2>&1
}
mkkey "$T/key_a.bin"; mkkey "$T/key_b.bin"
K="$T/key_a.bin"; K2="$T/key_b.bin"
TO="0x$($PY -c "print('c'*64)")"; TO2="0x$($PY -c "print('d'*64)")"
[ -s "$K" ] && [ -s "$K2" ] && [ -s "$G" ] || { echo "  FAIL: fixtures (genesis/keyfiles) could not be built"; exit 1; }

# A pristine pinned outbox with one QUEUED slot at nonce 0, and a copy helper so every
# mutating probe below runs against its own tree (two runs that differ only in a flag
# must not differ in the state they start from).
OB0="$T/ob_pristine"
"$L" outbox enqueue --outbox "$OB0" --genesis "$G" --keyfile "$K" --to "$TO" \
     --amount 5 --fee 1 --nonce 0 >/dev/null 2>&1
[ -n "$(ls "$OB0"/*.msg 2>/dev/null)" ] || { echo "  FAIL: could not seed the pristine outbox"; exit 1; }
OBN=0
ob() { OBN=$((OBN + 1)); rm -rf "$T/ob_$OBN"; cp -r "$OB0" "$T/ob_$OBN"; rm -f "$T/ob_$OBN/outbox.lock"; echo "$T/ob_$OBN"; }
# An outbox whose meta is unreadable and which holds no intact record to rebuild from:
# every verb has an observable, distinct outcome on it (exit 3).
OBX="$T/ob_meta_corrupt"; mkdir -p "$OBX"; printf 'not-a-DOM1-record' > "$OBX/outbox.meta"

# A peer that accepts a TCP connection and never answers. It makes --rpc-port and
# --timeout-ms observable (the reader's own socket timeout is then the only thing that
# ends a call) without a daemon, a chain or a cluster.
STALL_PID=""; STALL_PORT=""
cat > "$T/stall.py" <<'PYSTALL'
import socket, sys, time
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
srv.settimeout(1.0)
sys.stdout.write("%d\n" % srv.getsockname()[1])
sys.stdout.flush()
held = []
deadline = time.time() + 180
while time.time() < deadline:
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        continue
    except OSError:
        break
    held.append(conn)      # accepted, never answered, never closed
PYSTALL
"$PY" "$T/stall.py" > "$T/stall.port" 2>/dev/null &
STALL_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  STALL_PORT=$(head -1 "$T/stall.port" 2>/dev/null || echo "")
  [ -n "$STALL_PORT" ] && break
  sleep 0.3
done
now_ms() { $PY -c "import time; print(int(time.time()*1000))"; }
# The REASON clause of an inert refusal, and nothing else: the text between the
# "was invoked" marker and the remedy. Grepping the whole diagnostic for the cause
# flag is not an assertion — the remedy names it too, and so does the ordinary
# "pass --nonce or --rpc-port" failure this refusal replaced, so a binary that
# dropped the reason entirely would still match. Measured: it did (mutant N3).
inert_reason() { printf '%s' "$1" | sed -n 's/.*was invoked — \(.*\)\. Refusing rather than ignoring.*/\1/p' | head -1; }

# ── A. the matrix: every (verb, flag) pair, classified from the binary's behaviour ──
echo
echo "=== A. accept/refuse matrix — 7 verbs x the flag universe the BINARY declares ==="
VERBS="enqueue submit reconcile status replace prune recover"

# THE FLAG UNIVERSE, DERIVED FROM THE BINARY. When a verb refuses a flag that some
# OTHER verb accepts, light/outbox_cli.cpp prints "… — accepted here: <that verb's
# whole set>". Provoke that once per verb and the union of the seven printed sets IS
# the set of flags the parser recognizes. Hard-coding the universe here is what made
# this gate blind to a flag ADDED to the parser: it was never probed, so it was never
# measured, so no leg could see it. The seeds below only PROVOKE the refusal; which
# flags come back is the binary's answer, and one that the binary grew is picked up.
PROVOKE_SEEDS="--json --now --resume --older-than --include-unlocated --keyfile --state --nonce --wait"
accepted_here() {   # $1 verb -> the accepted set the binary prints in its OWN refusal
  local v="$1" sd out
  for sd in $PROVOKE_SEEDS; do
    out=$("$L" outbox "$v" --outbox "$T/ob_matrix" "$sd" 2>&1)
    if printf '%s' "$out" | grep -qF "accepted here: "; then
      printf '%s' "$out" | sed -n 's/.*accepted here: //p' | head -1 \
        | tr ' ' '\n' | grep -E '^--' | sort -u | tr '\n' ' ' | sed 's/  *$//'
      return 0
    fi
  done
  return 1
}
UNIVERSE=""; AH_MISSING=""
for v in $VERBS; do
  ah=$(accepted_here "$v") || { AH_MISSING="$AH_MISSING $v"; ah=""; }
  eval "AH_$v=\"\$ah\""
  UNIVERSE="$UNIVERSE $ah"
done
UNIVERSE=$(printf '%s\n' $UNIVERSE | sort -u | tr '\n' ' ' | sed 's/  *$//')
NFLAGS=$(printf '%s\n' $UNIVERSE | grep -c .)
assert "$([ -z "$AH_MISSING" ] && echo true || echo false)" \
  "universe: all 7 verbs printed their own accepted set in their own refusal diagnostic$([ -n "$AH_MISSING" ] && echo " (no set obtained for:$AH_MISSING)")"
# A FLOOR, never a ceiling: 19 flags existed when this gate was written, so fewer means
# the parser lost one and the derivation is measuring less than it used to. MORE is
# fine here and is caught per verb below, which is the whole point of deriving it.
assert "$([ "$NFLAGS" -ge 19 ] && echo true || echo false)" \
  "universe: the binary declares $NFLAGS distinct flags across the 7 verbs (floor 19) — derived, not listed here"
echo "    derived universe ($NFLAGS): $UNIVERSE"
ALL_FLAGS="$UNIVERSE"

# THE CONTRACT, restated here independently of light/outbox_cli.cpp: the flags each verb
# must accept because it reads their value. Every other flag the parser recognizes must
# be REFUSED by that verb. This list stays HAND-PINNED on purpose — the universe above is
# derived from the binary so a flag cannot hide from the probe, and this is the fixed
# point it is measured against. Deriving both would compare the binary with itself.
contract_for() {
  case "$1" in
    enqueue)   echo "--amount --fee --genesis --idempotency-key --json --keyfile --max-messages --nonce --outbox --payload-hex --rpc-port --timeout-ms --to --wait" ;;
    submit)    echo "--genesis --json --now --outbox --rpc-port --timeout-ms" ;;
    reconcile) echo "--genesis --json --outbox --resume --rpc-port --state --timeout-ms --wait" ;;
    status)    echo "--json --outbox" ;;
    replace)   echo "--amount --fee --genesis --keyfile --nonce --outbox --payload-hex --to" ;;
    prune)     echo "--include-unlocated --json --older-than --outbox" ;;
    recover)   echo "--outbox" ;;
    *)         echo "" ;;
  esac
}
probe_value() {
  case "$1" in
    --outbox)           echo "$T/ob_matrix" ;;
    --genesis)          echo "$G" ;;
    --keyfile)          echo "$K" ;;
    --to)               echo "$TO" ;;
    --amount|--fee)     echo "1" ;;
    --nonce|--older-than|--wait) echo "0" ;;
    --payload-hex)      echo "00" ;;
    --idempotency-key)  echo "probe" ;;
    --rpc-port|--max-messages) echo "1" ;;
    --timeout-ms)       echo "50" ;;
    --state)            echo "$T/anchor.bin" ;;
    *)                  echo "" ;;
  esac
}
PAIRS=0
MEASURED_ACCEPTED=""     # "verb:flag" for every pair the BINARY accepted — leg B closes over this
for v in $VERBS; do
  measured_acc=""; bad_refusal=""; unrecognized=""; refused_any=""; inert_here=""; bad_inert=""
  for f in $ALL_FLAGS; do
    PAIRS=$((PAIRS + 1))
    pv=$(probe_value "$f")
    if [ -n "$pv" ]; then out=$("$L" outbox "$v" --outbox "$T/ob_matrix" "$f" "$pv" 2>&1); rc=$?
    else                  out=$("$L" outbox "$v" --outbox "$T/ob_matrix" "$f" 2>&1);     rc=$?
    fi
    # FOUR outcomes, not two. Conflating any of them would let a mutant read as
    # something it is not: a flag DELETED from the parser must not read as "the verb
    # accepts it", and a flag the verb accepts but refuses AS INVOKED is still part of
    # that verb's surface — it is the per-INVOCATION half, not a smaller accepted set.
    if printf '%s' "$out" | grep -qF "is not accepted by \`outbox $v\`"; then
      # REFUSED BY THIS VERB. It must also be fail-closed: a diagnostic with exit 0 is
      # the same lie in a louder voice, and the message must name the flag refused.
      refused_any="$refused_any $f"
      { [ "$rc" != "0" ] && printf '%s' "$out" | grep -qF -- "$f"; } || bad_refusal="$bad_refusal $f(rc=$rc)"
    elif printf '%s' "$out" | grep -qF "unknown arg '$f'"; then
      # UNRECOGNIZED BY THE PARSER AT ALL — not the same thing, and a finding of its own:
      # some verb reads this flag, so the shared parser must still recognize it.
      unrecognized="$unrecognized $f"
    elif printf '%s' "$out" | grep -qF "INERT as \`outbox $v\` was invoked"; then
      # ACCEPTED BY THE VERB, refused in THIS configuration. Fail-closed, and the
      # diagnostic must name the flag AND the flag that made it inert — "names the
      # reason, not just the flag" is the whole difference from a bare rejection.
      measured_acc="$measured_acc $f"; inert_here="$inert_here $f"
      why=$(inert_reason "$out")
      { [ "$rc" != "0" ] && printf '%s' "$out" | grep -qF -- "$f" && [ -n "$why" ] \
        && printf '%s' "$why" | grep -qE -- '--nonce|--rpc-port|--resume'; } \
        || bad_inert="$bad_inert $f(rc=$rc)"
    else
      measured_acc="$measured_acc $f"
    fi
  done
  for f in $measured_acc; do MEASURED_ACCEPTED="$MEASURED_ACCEPTED $v:$f"; done
  [ -z "$unrecognized" ] \
    || { echo "    the shared parser no longer recognizes:$unrecognized"; }
  [ -z "$inert_here" ] || echo "    accepted by \`$v\` but refused as this probe invoked it:$inert_here"
  want=$(contract_for "$v")
  got=$(printf '%s\n' $measured_acc | sort | tr '\n' ' ' | sed 's/  *$//;s/^ *//')
  want=$(printf '%s\n' $want | sort | tr '\n' ' ' | sed 's/  *$//;s/^ *//')
  eval "MEAS_$v=\"\$got\""          # what the BINARY accepts — leg C compares help against this
  # The binary's OWN answer, from its refusal diagnostic — a third independent side.
  eval "said=\$AH_$v"
  said=$(printf '%s\n' $said | sort | tr '\n' ' ' | sed 's/  *$//;s/^ *//')
  if [ "$got" = "$want" ] && [ "$got" = "$said" ]; then
    assert true "matrix: \`outbox $v\` accepts EXACTLY the flags it reads, and says so itself ($(printf '%s\n' $got | grep -c .) of $NFLAGS)"
  else
    echo "    contract:  $want"
    echo "    measured:  $got"
    echo "    binary says: $said"
    assert false "matrix: \`outbox $v\` accepts a different set than the flags it reads, or than it declares"
  fi
  # refused_any is the non-vacuity floor: with an empty refusal set the two emptiness
  # tests below are true having checked nothing, and only the set comparison above
  # would have caught it. Every verb refuses at least one flag of the universe.
  [ -n "$refused_any" ] && [ -z "$bad_refusal" ] && [ -z "$unrecognized" ] && [ -z "$bad_inert" ] \
    && assert true "matrix: every flag \`outbox $v\` does not read is refused fail-closed and by name ($(printf '%s\n' $refused_any | grep -c .) of them), every inert-as-invoked refusal names its cause, and all $NFLAGS are still recognized by the shared parser" \
    || assert false "matrix: \`outbox $v\` refused nothing at all, or refused$bad_refusal$bad_inert without a non-zero exit / without naming the flag or its cause, or the parser dropped$unrecognized"
done
assert "$([ "$PAIRS" = "$((7 * NFLAGS))" ] && echo true || echo false)" "matrix: all $PAIRS (verb, flag) pairs — 7 verbs x the $NFLAGS flags the binary declares — were driven through the binary and classified (non-vacuity)"

unknown_ok=1
for v in $VERBS; do
  out=$("$L" outbox "$v" --outbox "$T/ob_matrix" --not-a-real-flag 2>&1); rc=$?
  printf '%s' "$out" | grep -qF "unknown arg '--not-a-real-flag'" && [ "$rc" != "0" ] || unknown_ok=0
done
assert "$([ "$unknown_ok" = "1" ] && echo true || echo false)" \
  "matrix: an invented flag is refused by all 7 verbs as 'unknown arg' — the refusal is per-flag, not a blanket rejection, and an operator can tell a wrong-verb flag from a typo"

# ── B. the effect: an accepted flag must observably change what the verb does ───────
echo
echo "=== B. every ACCEPTED (verb, flag) pair observably changes the verb's behaviour ==="

# --outbox, all 7 verbs: the same command against an unreadable-meta directory and
# against a healthy one. Exit 3 vs not-3 is read from the process, per verb.
ox_ok=1; ox_detail=""
for v in $VERBS; do
  case "$v" in
    enqueue)   a="--genesis $G --keyfile $K --to $TO --amount 1 --fee 1 --nonce 9" ;;
    submit)    a="--genesis $G --rpc-port 1" ;;
    reconcile) a="--genesis $G --rpc-port 1" ;;
    replace)   a="--genesis $G --keyfile $K --nonce 0 --fee 9" ;;
    *)         a="" ;;
  esac
  "$L" outbox "$v" --outbox "$OBX" $a >/dev/null 2>&1; rc_bad=$?
  "$L" outbox "$v" --outbox "$(ob)" $a >/dev/null 2>&1; rc_ok=$?
  { [ "$rc_bad" = "3" ] && [ "$rc_ok" != "3" ]; } || { ox_ok=0; ox_detail="$ox_detail $v(bad=$rc_bad ok=$rc_ok)"; }
done
cover enqueue:--outbox submit:--outbox reconcile:--outbox status:--outbox replace:--outbox prune:--outbox recover:--outbox
assert "$([ "$ox_ok" = "1" ] && echo true || echo false)" \
  "--outbox: all 7 verbs act on the directory they are given (exit 3 on the unreadable-meta tree, not 3 on the healthy one)$ox_detail"

# --json on the four verbs that have a JSON emitter reachable offline.
json_first_char() { printf '%s' "$1" | tr -d '[:space:]' | cut -c1; }
JO=$("$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 11 --json 2>/dev/null)
JP=$("$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 11 2>/dev/null)
cover enqueue:--json
assert "$([ "$(json_first_char "$JO")" = "{" ] && [ "$(json_first_char "$JP")" != "{" ] && echo true || echo false)" \
  "--json: enqueue emits a JSON object with the flag and a human line without it"
JO=$("$L" outbox submit --outbox "$(ob)" --genesis "$G" --rpc-port 1 --json 2>/dev/null)
JP=$("$L" outbox submit --outbox "$(ob)" --genesis "$G" --rpc-port 1 2>/dev/null)
cover submit:--json
assert "$([ "$(json_first_char "$JO")" = "{" ] && [ "$(json_first_char "$JP")" != "{" ] && echo true || echo false)" \
  "--json: submit emits a JSON object with the flag and a human listing without it"
JO=$("$L" outbox status --outbox "$OB0" --json 2>/dev/null)
JP=$("$L" outbox status --outbox "$OB0" 2>/dev/null)
cover status:--json
assert "$([ "$(json_first_char "$JO")" = "{" ] && [ "$(json_first_char "$JP")" != "{" ] && echo true || echo false)" \
  "--json: status emits a JSON object with the flag and a human listing without it"
JO=$("$L" outbox prune --outbox "$(ob)" --json 2>/dev/null)
JP=$("$L" outbox prune --outbox "$(ob)" 2>/dev/null)
cover prune:--json
assert "$([ "$(json_first_char "$JO")" = "{" ] && [ "$(json_first_char "$JP")" != "{" ] && echo true || echo false)" \
  "--json: prune emits a JSON object with the flag and a human line without it"
declined_pairs reconcile:--json
decline "--json on reconcile: cmd_reconcile's only JSON emitter is the post-read print_status, past connect_and_pin — unreachable without a daemon (live: tools/test_light_outbox_live.sh)"

# --genesis / --keyfile: a valid file for ANOTHER chain or ANOTHER sender is refused
# with the mismatch exit; the matching one is accepted.
"$L" outbox enqueue --outbox "$(ob)" --genesis "$G2" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 12 >/dev/null 2>&1; r_bad=$?
"$L" outbox enqueue --outbox "$(ob)" --genesis "$G"  --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 12 >/dev/null 2>&1; r_ok=$?
cover enqueue:--genesis
assert "$([ "$r_bad" = "6" ] && [ "$r_ok" = "0" ] && echo true || echo false)" \
  "--genesis: enqueue reads the file it is given (another chain's genesis -> exit 6, this one -> exit 0)"
"$L" outbox replace --outbox "$(ob)" --genesis "$G2" --keyfile "$K" --nonce 0 --fee 9 >/dev/null 2>&1; r_bad=$?
"$L" outbox replace --outbox "$(ob)" --genesis "$G"  --keyfile "$K" --nonce 0 --fee 9 >/dev/null 2>&1; r_ok=$?
cover replace:--genesis
assert "$([ "$r_bad" = "6" ] && [ "$r_ok" = "0" ] && echo true || echo false)" \
  "--genesis: replace reads the file it is given (another chain's genesis -> exit 6, this one -> exit 0)"
"$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K2" --to "$TO" --amount 1 --fee 1 --nonce 13 >/dev/null 2>&1; r_bad=$?
"$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K"  --to "$TO" --amount 1 --fee 1 --nonce 13 >/dev/null 2>&1; r_ok=$?
cover enqueue:--keyfile
assert "$([ "$r_bad" = "6" ] && [ "$r_ok" = "0" ] && echo true || echo false)" \
  "--keyfile: enqueue reads the key it is given (a second sender -> exit 6, the pinned one -> exit 0)"
"$L" outbox replace --outbox "$(ob)" --genesis "$G" --keyfile "$K2" --nonce 0 --fee 9 >/dev/null 2>&1; r_bad=$?
"$L" outbox replace --outbox "$(ob)" --genesis "$G" --keyfile "$K"  --nonce 0 --fee 9 >/dev/null 2>&1; r_ok=$?
cover replace:--keyfile
assert "$([ "$r_bad" = "6" ] && [ "$r_ok" = "0" ] && echo true || echo false)" \
  "--keyfile: replace reads the key it is given (a second sender -> exit 6, the pinned one -> exit 0)"

# --to / --amount / --fee / --payload-hex / --nonce on enqueue: the signed bytes are a
# function of every one of them, so the acknowledged tx hash moves when any one moves.
enq_tx() {   # $1.. extra flags -> the tx hash the binary acknowledged
  "$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --nonce 14 "$@" 2>/dev/null \
    | sed -n 's/.* tx=\([0-9a-f]*\).*/\1/p'
}
cover enqueue:--to enqueue:--amount enqueue:--fee enqueue:--payload-hex enqueue:--nonce
BASE=$(enq_tx --to "$TO" --amount 5 --fee 1)
assert "$([ -n "$BASE" ] && echo true || echo false)" "enqueue acknowledges a tx hash the probes below can move (non-vacuity)"
assert "$([ "$(enq_tx --to "$TO2" --amount 5 --fee 1)" != "$BASE" ] && echo true || echo false)" \
  "--to: the acknowledged tx hash moves with the recipient"
assert "$([ "$(enq_tx --to "$TO" --amount 6 --fee 1)" != "$BASE" ] && echo true || echo false)" \
  "--amount: the acknowledged tx hash moves with the amount"
assert "$([ "$(enq_tx --to "$TO" --amount 5 --fee 2)" != "$BASE" ] && echo true || echo false)" \
  "--fee: the acknowledged tx hash moves with the fee"
assert "$([ "$(enq_tx --to "$TO" --amount 5 --fee 1 --payload-hex aabb)" != "$BASE" ] && echo true || echo false)" \
  "--payload-hex: the acknowledged tx hash moves with the payload"
N21=$("$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 21 2>/dev/null | sed -n 's/.*nonce=\([0-9]*\).*/\1/p')
N22=$("$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 22 2>/dev/null | sed -n 's/.*nonce=\([0-9]*\).*/\1/p')
assert "$([ "$N21" = "21" ] && [ "$N22" = "22" ] && echo true || echo false)" \
  "--nonce: enqueue reserves the nonce it is given ($N21 / $N22)"

# --to / --amount / --payload-hex on replace decide fee-bump vs re-issue; --fee decides
# whether the replacement is admissible at all; --nonce picks the slot.
cover replace:--to replace:--amount replace:--payload-hex replace:--fee replace:--nonce
rep() { "$L" outbox replace --outbox "$(ob)" --genesis "$G" --keyfile "$K" --nonce 0 "$@" 2>&1; }
assert "$(rep --fee 9              | grep -q '^fee bump recorded' && echo true || echo false)" \
  "replace with no content flag records a FEE BUMP (the control the three below move)"
assert "$(rep --fee 9 --to "$TO2"  | grep -q '^re-issue recorded' && echo true || echo false)" \
  "--to: replace re-issues instead of fee-bumping when the recipient is given"
assert "$(rep --fee 9 --amount 6   | grep -q '^re-issue recorded' && echo true || echo false)" \
  "--amount: replace re-issues instead of fee-bumping when the amount is given"
assert "$(rep --fee 9 --payload-hex aabb | grep -q '^re-issue recorded' && echo true || echo false)" \
  "--payload-hex: replace re-issues instead of fee-bumping when the payload is given"
"$L" outbox replace --outbox "$(ob)" --genesis "$G" --keyfile "$K" --nonce 0 --fee 1 >/dev/null 2>&1; r_low=$?
"$L" outbox replace --outbox "$(ob)" --genesis "$G" --keyfile "$K" --nonce 0 --fee 9 >/dev/null 2>&1; r_hi=$?
assert "$([ "$r_low" != "0" ] && [ "$r_hi" = "0" ] && echo true || echo false)" \
  "--fee: replace reads the fee it is given (equal to the incumbent -> refused, above it -> recorded)"
"$L" outbox replace --outbox "$(ob)" --genesis "$G" --keyfile "$K" --nonce 99 --fee 9 >/dev/null 2>&1; r_miss=$?
assert "$([ "$r_miss" != "0" ] && [ "$r_hi" = "0" ] && echo true || echo false)" \
  "--nonce: replace acts on the slot it names (no slot at 99 -> refused, slot 0 -> recorded)"

# --idempotency-key: the second use of the same key is refused with the slot it already
# holds; a different key is not.
OBI=$(ob)
"$L" outbox enqueue --outbox "$OBI" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 31 --idempotency-key kk >/dev/null 2>&1
"$L" outbox enqueue --outbox "$OBI" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 32 --idempotency-key kk >/dev/null 2>&1; r_dup=$?
"$L" outbox enqueue --outbox "$OBI" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 32 --idempotency-key other >/dev/null 2>&1; r_new=$?
cover enqueue:--idempotency-key
assert "$([ "$r_dup" = "8" ] && [ "$r_new" = "0" ] && echo true || echo false)" \
  "--idempotency-key: the key's value decides the outcome (reused -> exit 8, fresh -> exit 0)"

# --max-messages: the cap is read from the flag and checked before any write.
"$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 41 --max-messages 1  >/dev/null 2>&1; r_full=$?
"$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --nonce 41 --max-messages 10 >/dev/null 2>&1; r_room=$?
cover enqueue:--max-messages
assert "$([ "$r_full" = "4" ] && [ "$r_room" = "0" ] && echo true || echo false)" \
  "--max-messages: the cap the flag names decides the outcome (1 with a slot present -> exit 4 full, 10 -> exit 0)"

# --now on submit: a slot whose backoff has not elapsed is skipped without it and
# attempted with it. Read back out of the record, not out of the log line.
fails_at() { "$L" outbox status --outbox "$1" --json 2>/dev/null \
  | $PY -c "import json,sys; d=json.load(sys.stdin); print([s for s in d['slots'] if s['nonce']==0][0]['consecutive_failures'])"; }
OBW=$(ob)
"$L" outbox submit --outbox "$OBW" --genesis "$G" --rpc-port 1 >/dev/null 2>&1   # 1st failure arms the backoff
F1=$(fails_at "$OBW")
cp -r "$OBW" "$T/ob_now"; rm -f "$T/ob_now/outbox.lock"
"$L" outbox submit --outbox "$OBW"      --genesis "$G" --rpc-port 1       >/dev/null 2>&1
"$L" outbox submit --outbox "$T/ob_now" --genesis "$G" --rpc-port 1 --now >/dev/null 2>&1
F_no=$(fails_at "$OBW"); F_now=$(fails_at "$T/ob_now")
cover submit:--now
assert "$([ "$F1" = "1" ] && [ "$F_no" = "1" ] && [ "$F_now" = "2" ] && echo true || echo false)" \
  "--now: a slot still inside its backoff is left alone without the flag and re-attempted with it (failures $F1 -> $F_no without, $F1 -> $F_now with)"

# --rpc-port: the port in the flag is the port the verb dials, read out of the
# diagnostic the binary itself printed.
P1=$("$L" outbox submit --outbox "$(ob)" --genesis "$G" --rpc-port 1 2>&1 | grep -c "127.0.0.1:1 ")
P2=$("$L" outbox submit --outbox "$(ob)" --genesis "$G" --rpc-port 2 2>&1 | grep -c "127.0.0.1:2 ")
cover submit:--rpc-port
assert "$([ "$P1" -ge 1 ] && [ "$P2" -ge 1 ] && echo true || echo false)" \
  "--rpc-port: submit dials the port it is given (its own transport diagnostic names 1 and 2)"
P1=$("$L" outbox reconcile --outbox "$(ob)" --genesis "$G" --rpc-port 1 2>&1 | grep -c "127.0.0.1:1 ")
P2=$("$L" outbox reconcile --outbox "$(ob)" --genesis "$G" --rpc-port 2 2>&1 | grep -c "127.0.0.1:2 ")
cover reconcile:--rpc-port
assert "$([ "$P1" -ge 1 ] && [ "$P2" -ge 1 ] && echo true || echo false)" \
  "--rpc-port: reconcile dials the port it is given (its own transport diagnostic names 1 and 2)"

if [ -z "$STALL_PORT" ]; then
  declined_pairs enqueue:--rpc-port enqueue:--timeout-ms submit:--timeout-ms reconcile:--timeout-ms submit:--genesis reconcile:--genesis
  decline "--rpc-port on enqueue, --timeout-ms on all three verbs, and --genesis on submit/reconcile: the local no-answer listener could not be started, and each needs a peer that ACCEPTS the connection"
else
  # enqueue only reaches its nonce-hint read when the connection is established, so a
  # port that accepts and a port that refuses put it on visibly different paths.
  E_open=$("$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 \
            --rpc-port "$STALL_PORT" --timeout-ms 100 2>&1 | grep -c "nonce hint unavailable")
  E_shut=$("$L" outbox enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 \
            --rpc-port 1 --timeout-ms 100 2>&1 | grep -c "nonce hint unavailable")
  cover enqueue:--rpc-port
  assert "$([ "$E_open" -ge 1 ] && [ "$E_shut" = "0" ] && echo true || echo false)" \
    "--rpc-port: enqueue dials the port it is given (a peer that accepts puts it on the nonce-hint path; a closed port does not)"

  # --genesis on submit / reconcile: with a peer that accepts, the local genesis pin runs
  # and a genesis for another chain is refused with the mismatch exit.
  "$L" outbox submit --outbox "$(ob)" --genesis "$G2" --rpc-port "$STALL_PORT" --timeout-ms 100 >/dev/null 2>&1; s_bad=$?
  "$L" outbox submit --outbox "$(ob)" --genesis "$G"  --rpc-port "$STALL_PORT" --timeout-ms 100 >/dev/null 2>&1; s_ok=$?
  cover submit:--genesis
  assert "$([ "$s_bad" = "6" ] && [ "$s_ok" != "6" ] && echo true || echo false)" \
    "--genesis: submit reads the file it is given (another chain's genesis -> exit 6 against the same peer)"
  "$L" outbox reconcile --outbox "$(ob)" --genesis "$G2" --rpc-port "$STALL_PORT" --timeout-ms 100 >/dev/null 2>&1; r_bad=$?
  "$L" outbox reconcile --outbox "$(ob)" --genesis "$G"  --rpc-port "$STALL_PORT" --timeout-ms 100 >/dev/null 2>&1; r_ok=$?
  cover reconcile:--genesis
  assert "$([ "$r_bad" = "6" ] && [ "$r_ok" != "6" ] && echo true || echo false)" \
    "--genesis: reconcile reads the file it is given (another chain's genesis -> exit 6 against the same peer)"

  # --timeout-ms: a TIMING WINDOW. Against a peer that never answers, the flag's value is
  # the only thing that ends the call, so the process must live ~1s longer at 1100ms than
  # at 100ms. Measured in wall clock, per verb.
  window() {   # $1 verb, then args; echoes elapsed-ms(long) - elapsed-ms(short)
    local v="$1"; shift
    local t0 t1 short long
    t0=$(now_ms); "$L" outbox "$v" "$@" --timeout-ms 100  >/dev/null 2>&1; t1=$(now_ms); short=$((t1 - t0))
    t0=$(now_ms); "$L" outbox "$v" "$@" --timeout-ms 1100 >/dev/null 2>&1; t1=$(now_ms); long=$((t1 - t0))
    echo "$((long - short))"
  }
  D=$(window enqueue --outbox "$(ob)" --genesis "$G" --keyfile "$K" --to "$TO" --amount 1 --fee 1 --rpc-port "$STALL_PORT")
  cover enqueue:--timeout-ms
  assert "$([ "$D" -ge 400 ] && echo true || echo false)" \
    "--timeout-ms: enqueue's nonce-hint RPC is bounded by the flag (+${D}ms wall clock from 100ms to 1100ms, against a peer that never answers)"
  D=$(window submit --outbox "$(ob)" --genesis "$G" --rpc-port "$STALL_PORT")
  cover submit:--timeout-ms
  assert "$([ "$D" -ge 400 ] && echo true || echo false)" \
    "--timeout-ms: submit's connection is bounded by the flag (+${D}ms wall clock from 100ms to 1100ms)"
  D=$(window reconcile --outbox "$(ob)" --genesis "$G" --rpc-port "$STALL_PORT")
  cover reconcile:--timeout-ms
  assert "$([ "$D" -ge 400 ] && echo true || echo false)" \
    "--timeout-ms: reconcile's connection is bounded by the flag (+${D}ms wall clock from 100ms to 1100ms)"
fi

declined_pairs prune:--older-than prune:--include-unlocated
decline "--older-than and --include-unlocated on prune: both select among PROVEN-consumed slots (FINALIZED/APPLIED, or CONSUMED with the flag), and no offline path can produce one — it takes a daemon-verified inclusion (live: tools/test_light_outbox_live.sh section 5)"
declined_pairs reconcile:--resume reconcile:--state
decline "--resume and --state on reconcile: the cached anchor is loaded inside anchored_head, past connect_and_pin — unreachable without a daemon serving a chain (live: tools/test_light_outbox_live.sh). Its REFUSAL without --resume is asserted in B5 below."
declined_pairs reconcile:--wait
decline "--wait on reconcile: it bounds the successor poll of each binding reconcile performs, which needs a committee-signed chain (live: tools/test_light_outbox_live.sh drives reconcile --wait 30; the forwarding itself is pinned by tools/test_light_wait_surface.sh invariant C)"
declined_pairs enqueue:--wait
decline "--wait on enqueue: the only peer this gate can start accepts and never answers, so the successor poll the wait bounds is never reached — the flag's EFFECT is leg D's (the route, over a committee-signed fixture chain) and the call site's is tools/test_light_wait_surface.sh RJ. Its REFUSAL in both inert configurations is asserted in B5 below."

# ── B5. the per-INVOCATION half: a flag the verb READS, inert as it was invoked ─────
# Each of the six measured (verb, flag, configuration) triples is probed twice: in the
# configuration where nothing reads it (must REFUSE, non-zero, naming the flag AND the
# flag that made it inert) and in the configuration where something does (must NOT
# refuse for that reason). A refusal asserted only in the inert direction would pass on
# a binary that refused the flag everywhere.
echo
echo "--- B5. flags the verb reads, refused in the configuration where nothing reads them ---"
EQ="--genesis $G --keyfile $K --to $TO --amount 1 --fee 1"
inert_probe() {   # $1 flag, $2 cause flag, $3 verb, rest: argv -> "rc|named|caused"
  local f="$1" cause="$2" v="$3"; shift 3
  local out rc
  out=$("$L" outbox "$v" --outbox "$T/ob_inert" "$@" 2>&1); rc=$?
  local named=no caused=no inert=no why
  printf '%s' "$out" | grep -qF "INERT as \`outbox $v\` was invoked" && inert=yes
  printf '%s' "$out" | grep -qF -- "$f" && named=yes
  # the CAUSE must be named in the reason clause, not merely somewhere in the line
  why=$(inert_reason "$out")
  [ -n "$why" ] && printf '%s' "$why" | grep -qF -- "$cause" && caused=yes
  echo "$rc|$inert|$named|$caused"
}
refuses() {   # $1 flag, $2 cause, $3 verb, rest argv — refused, fail-closed, both named
  local f="$1" cause="$2" v="$3"; shift 3
  local r; r=$(inert_probe "$f" "$cause" "$v" "$@")
  local rc inert named caused; IFS='|' read -r rc inert named caused <<< "$r"
  rm -rf "$T/ob_inert"
  [ "$rc" != "0" ] && [ "$inert" = "yes" ] && [ "$named" = "yes" ] && [ "$caused" = "yes" ] \
    && echo true || echo "false(rc=$rc inert=$inert names-flag=$named names-cause=$caused)"
}
accepts() {   # the same flag in its ENABLING configuration must not be refused as inert
  local f="$1" v="$2"; shift 2
  local out; out=$("$L" outbox "$v" --outbox "$T/ob_inert" "$@" 2>&1)
  rm -rf "$T/ob_inert"
  printf '%s' "$out" | grep -qF "INERT as \`outbox $v\` was invoked" && echo false || echo true
}
cover enqueue:--wait enqueue:--timeout-ms enqueue:--rpc-port reconcile:--state
R1=$(refuses --wait       --nonce     enqueue $EQ --nonce 7 --wait 30)
R2=$(refuses --timeout-ms --nonce     enqueue $EQ --nonce 7 --timeout-ms 900)
R3=$(refuses --rpc-port   --nonce     enqueue $EQ --nonce 7 --rpc-port 1)
assert "$([ "$R1" = "true" ] && [ "$R2" = "true" ] && [ "$R3" = "true" ] && echo true || echo false)" \
  "inert: enqueue refuses --wait / --timeout-ms / --rpc-port when --nonce takes the nonce from the flag, fail-closed and naming --nonce as the reason ($R1 $R2 $R3)"
R4=$(refuses --wait       --rpc-port  enqueue $EQ --wait 30)
R5=$(refuses --timeout-ms --rpc-port  enqueue $EQ --timeout-ms 900)
assert "$([ "$R4" = "true" ] && [ "$R5" = "true" ] && echo true || echo false)" \
  "inert: enqueue refuses --wait / --timeout-ms when no --rpc-port is given, fail-closed and naming --rpc-port as the reason — the verbatim S-112 symptom, one level in ($R4 $R5)"
R6=$(refuses --state      --resume    reconcile --genesis "$G" --rpc-port 1 --state "$T/anchor.bin")
assert "$([ "$R6" = "true" ] && echo true || echo false)" \
  "inert: reconcile refuses --state without --resume, fail-closed and naming --resume as the reason ($R6)"
# The enabling direction, so the six above cannot be satisfied by refusing everywhere.
A1=$(accepts --wait       enqueue $EQ --rpc-port 1 --wait 0)
A2=$(accepts --timeout-ms enqueue $EQ --rpc-port 1 --timeout-ms 100)
A3=$(accepts --rpc-port   enqueue $EQ --rpc-port 1)
A4=$(accepts --state      reconcile --genesis "$G" --rpc-port 1 --resume --state "$T/anchor.bin")
assert "$([ "$A1" = "true" ] && [ "$A2" = "true" ] && [ "$A3" = "true" ] && [ "$A4" = "true" ] && echo true || echo false)" \
  "inert: the SAME four flags are accepted in the configuration that reads them (enqueue with --rpc-port, reconcile with --resume) — the refusal is configuration-specific, not blanket ($A1 $A2 $A3 $A4)"
# A refusal must leave nothing behind: parse_args runs before Lock/Outbox.
rm -rf "$T/ob_inert_side"
"$L" outbox enqueue --outbox "$T/ob_inert_side" $EQ --wait 30 >/dev/null 2>&1; side_rc=$?
assert "$([ "$side_rc" != "0" ] && [ ! -e "$T/ob_inert_side" ] && echo true || echo false)" \
  "inert: a refused invocation creates no directory, no lock and no record (rc=$side_rc, tree absent)"

# ── B closes over A: every measured-ACCEPTED pair is probed above or declined by name ──
b_missing=""; b_extra=""
for pp in $MEASURED_ACCEPTED; do
  case " $B_COVERED $B_DECLINED " in *" $pp "*) ;; *) b_missing="$b_missing $pp" ;; esac
done
for pp in $B_COVERED $B_DECLINED; do
  case " $MEASURED_ACCEPTED " in *" $pp "*) ;; *) b_extra="$b_extra $pp" ;; esac
done
n_acc=$(printf '%s\n' $MEASURED_ACCEPTED | grep -c .)
n_cov=$(printf '%s\n' $B_COVERED | sort -u | grep -c .)
n_dec=$(printf '%s\n' $B_DECLINED | sort -u | grep -c .)
n_uni=$(printf '%s\n' $B_COVERED $B_DECLINED | sort -u | grep -c .)
n_both=$((n_cov + n_dec - n_uni))
[ -n "$b_missing" ] && echo "    measured ACCEPTED but neither probed nor declined here:$b_missing"
[ -n "$b_extra" ]   && echo "    registered here but the binary does not accept:$b_extra"
assert "$([ -z "$b_missing" ] && [ -z "$b_extra" ] && echo true || echo false)" \
  "coverage: all $n_acc pairs leg A measured as ACCEPTED are accounted for here — $n_uni registered: $n_cov probed, $n_dec declined by name, $n_both in both (probed for their refusal, declined for their effect) — and nothing is registered that the binary does not accept. Leg B's completeness is derived from leg A's measurement, not maintained by hand"

# ── C. help parity: what the binary advertises == what the binary accepts ───────────
# BOTH sides are the running binary: `determ-light help` on one side, and on the other
# the set leg A MEASURED the binary accepting (not the contract restated in this file —
# that comparison is leg A's, and making it twice would not add a side). So this cannot
# be satisfied by editing a comment or this script.
echo
echo "=== C. help parity — the advertised surface IS the accepted surface ==="
"$L" help > "$T/help.txt" 2>&1
help_flags() {
  awk -v v="$1" '
    $0 ~ "^  outbox " v " " { inblk = 1; print; next }
    inblk { if (match($0, /^ +/) && RLENGTH >= 14) { print; next } else { inblk = 0 } }
  ' "$T/help.txt" | grep -o -- '--[a-z-]*' | sort -u | tr '\n' ' ' | sed 's/  *$//'
}
for v in $VERBS; do
  hf=$(help_flags "$v")
  eval "mf=\$MEAS_$v"
  mf=$(printf '%s\n' $mf | sort | tr '\n' ' ' | sed 's/  *$//')
  if [ "$hf" = "$mf" ]; then
    assert true "help parity: \`outbox $v\` advertises exactly the flags the binary accepts for it"
  else
    echo "    help:              $hf"
    echo "    measured accepted: $mf"
    assert false "help parity: \`outbox $v\` advertises a different set than it accepts"
  fi
done

# ── D. the S-112 instance, end to end over a committee-signed fixture chain ────────
echo
echo "=== D. S-112: the operator's --wait reaches enqueue's head-anchored nonce hint ==="
HW=$("$L" selftest-outbox-hint-wait 2>&1); HW_RC=$?
echo "$HW" | grep -E "^  (PASS|FAIL):" | grep -v "selftest-outbox-hint-wait" | sed 's/^/    /'
HW_N=$(echo "$HW" | grep -cE "^  PASS:")
assert "$([ "$HW_RC" = "0" ] && echo "$HW" | grep -q "PASS: selftest-outbox-hint-wait" && echo true || echo false)" \
  "selftest-outbox-hint-wait green (rc=$HW_RC)"
assert "$([ "$HW_N" -ge 6 ] && echo true || echo false)" \
  "selftest-outbox-hint-wait asserted its 5 legs plus its terminal marker ($HW_N PASS lines) — a gutted selftest cannot pass this by exiting 0"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail / $skip_count declined"
echo "  flag universe derived from the binary: $NFLAGS flags, $PAIRS (verb, flag) pairs driven."
echo "  not asserted here: cmd_enqueue's own forwarding into the nonce-hint route (static:"
echo "  tools/test_light_wait_surface.sh, RJ), and every flag effect that needs a daemon —"
echo "  each declined above by name, none of them banked as a pass, and every one of them"
echo "  named as a (verb, flag) pair that the coverage assertion in B accounts for."
if [ "$fail_count" -eq 0 ] && [ "$pass_count" -gt 0 ]; then
  echo "  PASS: test_light_outbox_flag_surface ($pass_count assertions; every (verb, flag) pair the parser recognizes is acted on or refused)"
  rm -rf "$T"
  exit 0
fi
if [ "$pass_count" -eq 0 ]; then
  echo "  FAIL: test_light_outbox_flag_surface (0 assertions passed — a gate that asserted nothing is not a green)"
  exit 1
fi
echo "  FAIL: test_light_outbox_flag_surface ($fail_count of $((pass_count + fail_count)) assertions failed)"
exit 1
