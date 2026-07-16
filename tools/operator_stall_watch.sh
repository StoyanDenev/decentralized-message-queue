#!/usr/bin/env bash
# operator_stall_watch.sh — watch a set of peer nodes for the S-050 /
# S-051 stall signatures by polling each one's `status` RPC height over
# a fixed observation window and classifying the height trajectories.
#
# Background (both signatures reproduced live 2026-07-15, recorded in
# docs/proofs/AdversarialTransportHarness.md section 3.4):
#
#   S-050 (FIXED in-node, commit 48bc54f): concurrent abort quorums fork
#   the hash-chained abort tail by adoption order; re-derived committees
#   and delay_outputs diverge and every BlockSig is deterministically
#   rejected — an absorbing livelock the S-047 re-delivery retry cannot
#   heal. The in-node valve (src/node/node.cpp Node::maybe_stall_reset_locked,
#   soft 5 s / hard 30 s wall-clock windows) resets local round state and
#   re-syncs, making the wedge non-absorbing. From outside: heights stop
#   advancing while DIFFERING across nodes, and/or resume after a flat
#   stretch (the valve firing + recovering).
#
#   S-051 (OPEN, owner-gated — no protocol fix shipped): round-1 aborts
#   bake a BASE_SUSPENSION_BLOCKS selection suspension whose expiry is
#   measured in BLOCK INDEX (include/determ/chain/params.hpp). Spurious
#   abort quorums can drain the eligible pool below K: no committee forms,
#   no round runs (so the S-050 valve never fires), and suspensions never
#   expire. The observable signature is a PERMANENT, UNIFORM height freeze:
#   every node stuck at the same height for the whole window.
#
# Read-only RPC (status only, never a mutating call); safe against any
# running daemon. Each port must be listening on 127.0.0.1 (same
# addressing model as operator_consensus_lag.sh).
#
# Usage:
#   tools/operator_stall_watch.sh --rpc-ports 8771,8772,8773 \
#                                 [--interval N] [--window N] [--json]
#
# Exit codes:
#   0   HEALTHY (fleet max height advanced cleanly over the window)
#   1   RPC error (no node reachable at any poll) OR bad arguments
#   2   S-050 signature (stalled non-uniform, or stall-then-recover)
#   3   SUSPECTED S-051 pool-exhaustion halt (uniform frozen height)
#
# Note on exit policy: the 0/1/2-split siblings (operator_chain_health,
# operator_supply_check) separate green / RPC error / alert gate;
# operator_consensus_lag collapses to 0/1. This script keeps the 0/1/2
# convention of the former and extends it with a
# distinct code 3 for the S-051 signature because the two alerts demand
# different operator responses: S-050 territory is self-healing (the
# in-node valve is the fix; watch, don't touch), while a suspected
# S-051 halt is permanent without operator action and must page.
set -u

usage() {
  cat <<'EOF'
Usage: operator_stall_watch.sh --rpc-ports P1,P2,... [--interval N] [--window N] [--json]

Polls `determ status --rpc-port <P>` on each comma-separated port every
--interval seconds for --window seconds, then classifies the fleet's
height trajectories against the two known stall signatures.

S-050 SIGNATURE (stall-recovering — valve territory, FIXED in-node):
  A consensus round can wedge on deterministic mutual rejection —
  concurrent abort quorums for the same round fork the hash-chained
  abort tail by adoption order, the re-derived committees diverge, and
  every BlockSig is dropped, which message re-delivery cannot heal. The
  shipped in-node valve (src/node/node.cpp Node::maybe_stall_reset_locked;
  soft 5 s / hard 30 s wall-clock windows) resets local round state so
  the wedge is non-absorbing. Watched from outside, S-050 territory
  looks like: heights not advancing but DIFFERING across nodes, or
  heights advancing again after a flat stretch of >= the valve's soft
  window (the valve firing and recovering). Reported as
  "stall-recovering (S-050 valve territory)", exit 2. Expected response:
  observe — the valve is the fix; escalate only if it persists across
  repeated runs.

S-051 SIGNATURE (pool-exhaustion halt — OPEN, permanent):
  Round-1 aborts bake a BASE_SUSPENSION_BLOCKS-block selection
  suspension (include/determ/chain/params.hpp) whose expiry is measured
  in BLOCK INDEX, not time. Spurious abort quorums can drain the
  eligible pool below committee size K: no committee can form, no round
  runs (so the S-050 valve never fires), and suspensions never expire —
  a permanent halt. Watched from outside: EVERY node frozen at the SAME
  height for the whole window. Reported loudly as a suspected S-051
  pool-exhaustion halt, exit 3. No protocol fix is shipped (owner-gated);
  the empirical record and fix constraints are in
  docs/proofs/AdversarialTransportHarness.md section 3.4.

Unreachable ports are polled anyway each round and reported; a node
unreachable for the whole window is excluded from the uniform-freeze
test (S-051 requires positive confirmation from every node) but still
counts as evidence against HEALTHY. If NO node answers at any poll the
script exits 1 (RPC error) — there is nothing to classify.

Required:
  --rpc-ports LIST     Comma-separated RPC ports (e.g. 8771,8772,8773).
                       At least one port; duplicates de-duped in stable
                       order. Ports must be listening on 127.0.0.1.

Options:
  --interval N         Seconds between polls (default: 5, minimum 1).
  --window N           Total observation window in seconds (default: 30;
                       must be >= --interval). The number of polls is
                       window/interval + 1, so the defaults take 7
                       samples over ~30 s — long enough to span the
                       S-050 hard window (30 s, src/node/node.cpp
                       kRoundStallHardWindow).
  --json               Emit a structured JSON envelope instead of the
                       human report. Shape:
                         {"classification": "healthy"|"s050_signature"|
                                            "s051_suspected"|"unreachable",
                          "advanced": bool,
                          "interval": N, "window": N, "polls": N,
                          "nodes": [{"port": P, "samples": [H|null, ...],
                                     "reachable": bool, "frozen": bool,
                                     "stall_recovered": bool}, ...]}
  -h, --help           Show this help.

Exit codes:
  0   HEALTHY
  1   RPC error (no node reachable) or bad arguments
  2   S-050 signature (stall-recovering / stalled non-uniform)
  3   SUSPECTED S-051 pool-exhaustion halt (uniform frozen height)
EOF
}

PORTS_RAW=""
INTERVAL=5
WINDOW=30
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --rpc-ports)   PORTS_RAW="${2:-}"; shift 2 ;;
    --interval)    INTERVAL="${2:-}"; shift 2 ;;
    --window)      WINDOW="${2:-}"; shift 2 ;;
    --json)        JSON_OUT=1; shift ;;
    *) echo "operator_stall_watch: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORTS_RAW" ]; then
  echo "operator_stall_watch: --rpc-ports is required (comma-separated, e.g. 8771,8772,8773)" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$INTERVAL" in *[!0-9]*|"")
  echo "operator_stall_watch: --interval must be a positive integer (got '$INTERVAL')" >&2
  exit 1 ;;
esac
case "$WINDOW" in *[!0-9]*|"")
  echo "operator_stall_watch: --window must be a positive integer (got '$WINDOW')" >&2
  exit 1 ;;
esac
if [ "$INTERVAL" -lt 1 ]; then
  echo "operator_stall_watch: --interval must be >= 1" >&2
  exit 1
fi
if [ "$WINDOW" -lt "$INTERVAL" ]; then
  echo "operator_stall_watch: --window ($WINDOW) must be >= --interval ($INTERVAL)" >&2
  exit 1
fi

# Parse + validate ports. Split on comma, strip whitespace, dedup in
# encounter order (same idiom as operator_consensus_lag.sh).
PORTS=""
SEEN=""
IFS=',' read -ra _PORTS <<<"$PORTS_RAW"
for raw in "${_PORTS[@]}"; do
  p="${raw#"${raw%%[![:space:]]*}"}"
  p="${p%"${p##*[![:space:]]}"}"
  if [ -z "$p" ]; then
    continue
  fi
  case "$p" in *[!0-9]*)
    echo "operator_stall_watch: --rpc-ports entry '$p' is not numeric" >&2
    exit 1 ;;
  esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "operator_stall_watch: --rpc-ports entry '$p' must be 1..65535" >&2
    exit 1
  fi
  case " $SEEN " in
    *" $p "*) continue ;;
  esac
  SEEN="$SEEN $p"
  if [ -z "$PORTS" ]; then PORTS="$p"; else PORTS="$PORTS $p"; fi
done

if [ -z "$PORTS" ]; then
  echo "operator_stall_watch: --rpc-ports resolved to an empty list" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Poll loop. `status --field height` is the same read-only RPC that
# operator_consensus_lag.sh uses — the binary extracts the field, so no
# JSON parsing on the sampling hot path. One row per poll, fields
# pipe-delimited in port order (empty field = unreachable at that poll),
# rows joined with ';'. Pipe-delimited so empties survive the split.
#
# Join with explicit first-element flags, NOT the `[ -z "$ACC" ]` idiom:
# an unreachable port yields an EMPTY field, so after appending it the
# accumulator can still be empty and the -z test collapses leading empty
# fields — misaligning every later height one port to the LEFT (and
# leading empty rows one poll earlier). Reproduced before this guard:
# port A unreachable + port B at 7 classified as A=7, B=unreachable.
POLLS=$(( WINDOW / INTERVAL + 1 ))
SAMPLES=""
first_row=1
i=0
while [ "$i" -lt "$POLLS" ]; do
  ROW=""
  first_field=1
  for port in $PORTS; do
    h=$("$DETERM" status --field height --rpc-port "$port" 2>/dev/null || true)
    h="${h%$'\n'}"
    h="${h%$'\r'}"
    h="${h#"${h%%[![:space:]]*}"}"
    h="${h%"${h##*[![:space:]]}"}"
    case "$h" in
      ""|*[!0-9]*) h="" ;;
    esac
    if [ "$first_field" -eq 1 ]; then ROW="$h"; first_field=0; else ROW="$ROW|$h"; fi
  done
  if [ "$first_row" -eq 1 ]; then SAMPLES="$ROW"; first_row=0; else SAMPLES="$SAMPLES;$ROW"; fi
  i=$(( i + 1 ))
  [ "$i" -lt "$POLLS" ] && sleep "$INTERVAL"
done

# Hand off to python for the classification + rendering (sibling-script
# idiom: bash samples, python classifies).
PORTS_PIPE=$(printf '%s' "$PORTS" | tr ' ' '|')
python - "$PORTS_PIPE" "$SAMPLES" "$INTERVAL" "$WINDOW" "$JSON_OUT" <<'PY'
import json, sys

ports_s, samples_s, interval_s, window_s, json_out_s = sys.argv[1:6]
ports    = [int(p) for p in ports_s.split('|') if p]
interval = int(interval_s)
window   = int(window_s)
json_out = json_out_s == "1"

# rows[poll][node] = height (int) or None (unreachable at that poll).
rows = []
for row_s in samples_s.split(';'):
    fields = row_s.split('|')
    while len(fields) < len(ports):   # defensive pad; shouldn't happen
        fields.append("")
    rows.append([int(f) if f != "" else None for f in fields[:len(ports)]])
polls = len(rows)

# Per-node series + derived flags.
#
#   reachable        — answered at least one poll.
#   frozen           — reachable, and every answered sample is one value.
#   stall_recovered  — advanced within the window AFTER a flat stretch
#                      spanning >= the in-node valve's soft window (5 s,
#                      src/node/node.cpp kRoundStallSoftWindow): the
#                      outside-visible shape of the S-050 valve firing
#                      and the round recovering.
S050_SOFT_WINDOW_S = 5
nodes = []
for j, port in enumerate(ports):
    series = [rows[i][j] for i in range(polls)]
    answered = [h for h in series if h is not None]
    reachable = len(answered) > 0
    frozen = reachable and len(set(answered)) == 1
    stall_recovered = False
    run = 1
    prev = None
    for h in series:
        if h is None:
            continue
        if prev is not None:
            if h == prev:
                run += 1
            else:
                if h > prev and (run - 1) * interval >= S050_SOFT_WINDOW_S:
                    stall_recovered = True
                run = 1
        prev = h
    nodes.append({
        "port": port, "samples": series, "reachable": reachable,
        "frozen": frozen, "stall_recovered": stall_recovered,
        "first": answered[0] if answered else None,
        "last":  answered[-1] if answered else None,
    })

reachable_nodes = [n for n in nodes if n["reachable"]]

# Fleet max trajectory: max reachable height per poll, then first/last
# defined values. "Advanced" == the fleet max moved over the window.
poll_max = []
for i in range(polls):
    hs = [h for h in rows[i] if h is not None]
    poll_max.append(max(hs) if hs else None)
defined = [m for m in poll_max if m is not None]
advanced = len(defined) >= 2 and defined[-1] > defined[0]

# Classification (checked in order of severity):
#
#   unreachable      — no node answered any poll: RPC layer, exit 1.
#   s051_suspected   — EVERY node reachable, frozen, at the SAME height
#                      for the whole window: the pool-exhaustion halt's
#                      uniform-freeze signature, exit 3.
#   s050_signature   — fleet max did not advance (non-uniform stall /
#                      partial unreachability), OR it advanced but a node
#                      showed a stall-then-recover shape or stayed frozen
#                      while the fleet moved: valve territory, exit 2.
#   healthy          — fleet max advanced cleanly, exit 0.
if not reachable_nodes:
    classification = "unreachable"
elif (len(reachable_nodes) == len(nodes)
      and all(n["frozen"] for n in nodes)
      and len(set(n["last"] for n in nodes)) == 1):
    classification = "s051_suspected"
elif not advanced:
    classification = "s050_signature"
elif any(n["stall_recovered"] or (n["reachable"] and n["frozen"])
         for n in nodes) or len(reachable_nodes) < len(nodes):
    classification = "s050_signature"
else:
    classification = "healthy"

rc = {"healthy": 0, "unreachable": 1,
      "s050_signature": 2, "s051_suspected": 3}[classification]

if json_out:
    envelope = {
        "classification": classification,
        "advanced":       advanced,
        "interval":       interval,
        "window":         window,
        "polls":          polls,
        "nodes": [{"port": n["port"], "samples": n["samples"],
                   "reachable": n["reachable"], "frozen": n["frozen"],
                   "stall_recovered": n["stall_recovered"]} for n in nodes],
    }
    print(json.dumps(envelope))
    sys.exit(rc)

# Human-readable report.
print(f"=== Stall watch ({polls} polls, every {interval}s, window {window}s) ===")
print()
print(f"  {'port':>6}  {'first':>11}  {'last':>11}  trajectory")
print(f"  {'-'*6}  {'-'*11}  {'-'*11}  {'-'*34}")
for n in nodes:
    if not n["reachable"]:
        f_disp = l_disp = "unreachable"
        traj = "UNREACHABLE (all polls)"
    else:
        f_disp = str(n["first"])
        l_disp = str(n["last"])
        if n["stall_recovered"]:
            traj = "stall-then-advance (valve recovery?)"
        elif n["frozen"]:
            traj = "FROZEN"
        elif n["last"] > n["first"]:
            traj = "advancing"
        else:
            traj = "not advancing"
    print(f"  {n['port']:>6}  {f_disp:>11}  {l_disp:>11}  {traj}")

print()
if classification == "healthy":
    print(f"[OK] HEALTHY: fleet max height advanced "
          f"{defined[0]} -> {defined[-1]} over the window")
elif classification == "unreachable":
    print("[ERROR] no node reachable at any poll -- nothing to classify "
          "(are the daemons running on these ports?)")
elif classification == "s050_signature":
    if advanced:
        detail = ("fleet advanced, but with per-node stall/freeze shapes "
                  "(flat stretch >= the valve's 5 s soft window, or a node "
                  "frozen/unreachable while the fleet moved)")
    else:
        detail = ("fleet max height did NOT advance, but the freeze is not "
                  "uniform across all nodes")
    print(f"[ALERT] stall-recovering (S-050 valve territory): {detail}.")
    print("        The in-node valve (src/node/node.cpp "
          "Node::maybe_stall_reset_locked) is the shipped fix -- expect")
    print("        self-healing; re-run this watch and escalate only if the "
          "signature persists across runs.")
else:  # s051_suspected
    h = nodes[0]["last"]
    print(f"[ALERT] SUSPECTED S-051 POOL-EXHAUSTION HALT: all "
          f"{len(nodes)} node(s) frozen at the SAME height {h} for the "
          f"whole {window}s window.")
    print("        This halt is PERMANENT (suspension expiry is measured in "
          "block index; no blocks means no expiry,")
    print("        and with no round running the S-050 valve never fires) -- "
          "operator action required. S-051 is OPEN")
    print("        (no protocol fix shipped); see "
          "docs/proofs/AdversarialTransportHarness.md section 3.4 for the")
    print("        empirical record and the fix constraints (eligibility "
          "floor mirrored across registry.cpp selection,")
    print("        the validator, and the D3.3b frozen committee "
          "checkpoints).")
sys.exit(rc)
PY
exit $?
