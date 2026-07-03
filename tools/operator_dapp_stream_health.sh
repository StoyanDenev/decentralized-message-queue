#!/usr/bin/env bash
# operator_dapp_stream_health.sh — Read-only fleet-health diagnostic for the
# v2.20 streaming subsystem (dapp_subscribe push RPC + per-subscriber bounded
# queue with KILL-ON-OVERFLOW backpressure). Polls the R54 `dapp_subscribers`
# observability RPC once (or on a bounded --watch loop) and reports:
#
#   1. LIVE COUNT vs the 256 cap  — live Subscriber entries, the
#      SUBSCRIBER_MAX_PER_NODE ceiling (256), the saturation % (count/max),
#      and a WARN band when the fleet is near the cap (a full table means new
#      subscribe attempts are being refused — the operator wants early notice).
#   2. BACKPRESSURE KILLS          — the node's cumulative kills_backpressure
#      counter (subscribers dropped for queue overflow since node start), and
#      — under --watch — the delta since the previous poll (a rising delta is
#      the live-backpressure signal; a flat one is quiescent).
#   3. QUEUE-DEPTH DISTRIBUTION    — across the live fleet: max / mean queue
#      depth, and the BACKPRESSURE-RISK COHORT: how many subscribers sit within
#      --near-ceiling frames of their queue ceiling (i.e. one burst from being
#      killed). This is the leading indicator the kills counter only reports
#      after the fact.
#
# Scope contrast with neighbouring DApp scripts (all read-only):
#   operator_dapp_inventory.sh   registry digest (who's registered, how busy).
#   operator_dapp_health.sh      per-DApp lifecycle (HEALTHY/STALE/ZOMBIE/…).
#   operator_dapp_topic_audit.sh committed-message topic analytics.
#   operator_dapp_stream_health  THIS — live SUBSCRIBER-FLEET health over the
#                                v2.20 push-streaming subsystem. Not a chain
#                                read at all: it snapshots the node's in-memory
#                                subscriber table (queue depths, seqs, kills),
#                                which no chain/block RPC exposes.
#
# ── SAFETY: strictly READ-ONLY (docs/proofs/OperatorToolingReadOnly.md OT-1/OT-2)
#   Every RPC this script issues is non-state-mutating:
#     - dapp_subscribers  — the R54 observability read. Per its contract it
#       takes subscribers_mutex_ (+ each Subscriber::mu briefly) to snapshot,
#       NEVER takes state_mutex_, mutates NO chain or subscriber state, and does
#       NOT perturb the live stream (queues/seqs are read, not advanced).
#   It NEVER issues any of the 6 MUTATING endpoints
#   (send/stake/unstake/register/submit_tx/submit_equivocation), so it joins
#   the OT-1 read-only set. dapp_subscribers is the only wire request made.
#
# ── Anti-hang: --watch is bounded ─────────────────────────────────────────────
#   Default is single-shot (one poll, then exit). --watch REQUIRES --count
#   (no implicit unbounded loop); --count and --interval are hard-capped so the
#   loop always terminates. No node spawning, no block walk.
#
# Usage:
#   tools/operator_dapp_stream_health.sh --rpc-port N
#     [--near-ceiling N] [--warn-saturation-pct P]
#     [--json] [--anomalies-only]
#     [--watch --count C [--interval S]]
#
# Options:
#   --rpc-port N            RPC port to query (REQUIRED — refuses to guess)
#   --near-ceiling N        A live subscriber whose queue_depth is within N
#                           frames of its queue ceiling (max - depth <= N) is
#                           counted in the backpressure-risk cohort
#                           (default: 4)
#   --warn-saturation-pct P Fleet saturation (count*100/max) at or above P
#                           raises the near_cap WARN anomaly (default: 90)
#   --json                  Emit a machine-readable JSON envelope
#   --anomalies-only        Suppress the per-subscriber detail rows; the exit-2
#                           gate below still fires on a CRITICAL anomaly
#   --watch                 Bounded re-poll loop; REQUIRES --count
#   --count C               Number of --watch polls (1..1440)
#   --interval S            Seconds between --watch polls (1..3600; default 5)
#   -h, --help              Show this help
#
# RPC dependency (read-only):
#   dapp_subscribers  {"count","max","kills_backpressure","subscribers":[
#                       {"sid","domain","topic","queue_depth","bytes_buffered",
#                        "seq","killed"}, ...]}
#
# Anomalies (CRITICAL forces exit 2 regardless of --anomalies-only):
#   fleet_saturated     CRITICAL  count >= max (256) — the table is full and
#                                 new dapp_subscribe attempts are being refused.
#   kills_rising        CRITICAL  --watch only: kills_backpressure increased
#                                 between two polls (a subscriber was killed for
#                                 overflow during the observation window).
#   near_cap            WARN      saturation >= --warn-saturation-pct but not yet
#                                 full — approaching refusal.
#   backpressure_risk   WARN      >=1 live subscriber within --near-ceiling of
#                                 its queue ceiling — one burst from a kill.
#
# Exit codes (house contract):
#   0   poll ran, no CRITICAL anomaly (zero subscribers is success, not error)
#   1   RPC error / daemon unreachable / malformed response / bad args /
#       daemon predates R54 (dapp_subscribers unknown method)
#   2   a CRITICAL anomaly fired (fleet_saturated or kills_rising)
set -u

MAX_WATCH_COUNT=1440
MAX_WATCH_INTERVAL=3600

usage() {
  cat <<'EOF'
Usage: operator_dapp_stream_health.sh --rpc-port N
         [--near-ceiling N] [--warn-saturation-pct P]
         [--json] [--anomalies-only]
         [--watch --count C [--interval S]]

Read-only fleet-health diagnostic for the v2.20 streaming subsystem. Polls the
R54 dapp_subscribers observability RPC and reports live-count-vs-256-cap
(saturation % + near-cap WARN), cumulative backpressure kills (with a
delta-since-last-poll under --watch), and the per-subscriber queue-depth
distribution (max / mean / backpressure-risk cohort within N frames of the
queue ceiling).

Options:
  --rpc-port N            RPC port to query (REQUIRED)
  --near-ceiling N        Risk-cohort threshold: max - queue_depth <= N
                          (default: 4)
  --warn-saturation-pct P near_cap WARN when saturation% >= P (default: 90)
  --json                  Emit a machine-readable JSON envelope
  --anomalies-only        Suppress per-subscriber detail rows (exit-2 gate
                          still fires on a CRITICAL anomaly)
  --watch                 Bounded re-poll loop; REQUIRES --count
  --count C               Number of --watch polls (1..1440)
  --interval S            Seconds between --watch polls (1..3600; default 5)
  -h, --help              Show this help

Anomalies (CRITICAL forces exit 2):
  fleet_saturated    CRITICAL  count >= max (256); subscribe attempts refused
  kills_rising       CRITICAL  --watch: kills_backpressure rose between polls
  near_cap           WARN      saturation% >= --warn-saturation-pct
  backpressure_risk  WARN      >=1 subscriber within --near-ceiling of ceiling

Exit codes:
  0   poll ran, no CRITICAL anomaly (zero subscribers is success)
  1   RPC error / daemon unreachable / malformed response / bad args /
      daemon predates R54 (dapp_subscribers unknown method)
  2   CRITICAL anomaly fired (fleet_saturated or kills_rising)
EOF
}

PORT=""
NEAR_CEIL=4
WARN_SAT_PCT=90
JSON_OUT=0
ANOM_ONLY=0
WATCH=0
COUNT=""
INTERVAL=5
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-port)             PORT="${2:-}";         shift 2 ;;
    --near-ceiling)         NEAR_CEIL="${2:-}";    shift 2 ;;
    --warn-saturation-pct)  WARN_SAT_PCT="${2:-}"; shift 2 ;;
    --json)                 JSON_OUT=1;            shift ;;
    --anomalies-only)       ANOM_ONLY=1;           shift ;;
    --watch)                WATCH=1;               shift ;;
    --count)                COUNT="${2:-}";        shift 2 ;;
    --interval)             INTERVAL="${2:-}";     shift 2 ;;
    *) echo "operator_dapp_stream_health: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Argument validation (after --help so --help never trips it) ───────────────
# --rpc-port is required: a defaulted port can silently target the wrong daemon
# on a multi-instance host (mirrors operator_dapp_health.sh / _dapp_inventory).
if [ -z "$PORT" ]; then
  echo "operator_dapp_stream_health: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_stream_health: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

case "$NEAR_CEIL" in *[!0-9]*|"")
  echo "operator_dapp_stream_health: --near-ceiling must be a non-negative integer (got '$NEAR_CEIL')" >&2
  exit 1 ;;
esac

case "$WARN_SAT_PCT" in *[!0-9]*|"")
  echo "operator_dapp_stream_health: --warn-saturation-pct must be an integer 0..100 (got '$WARN_SAT_PCT')" >&2
  exit 1 ;;
esac
if [ "$WARN_SAT_PCT" -gt 100 ]; then
  echo "operator_dapp_stream_health: --warn-saturation-pct must be 0..100 (got '$WARN_SAT_PCT')" >&2
  exit 1
fi

# --watch bounds. --count is mandatory in watch mode (no unbounded loop) and
# both --count / --interval are hard-capped so the loop always terminates.
if [ "$WATCH" = "1" ]; then
  if [ -z "$COUNT" ]; then
    echo "operator_dapp_stream_health: --watch requires --count (no unbounded loop)" >&2
    exit 1
  fi
  case "$COUNT" in *[!0-9]*|"")
    echo "operator_dapp_stream_health: --count must be a positive integer (got '$COUNT')" >&2
    exit 1 ;;
  esac
  if [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt "$MAX_WATCH_COUNT" ]; then
    echo "operator_dapp_stream_health: --count must be in 1..$MAX_WATCH_COUNT (got '$COUNT')" >&2
    exit 1
  fi
  case "$INTERVAL" in *[!0-9]*|"")
    echo "operator_dapp_stream_health: --interval must be a positive integer (got '$INTERVAL')" >&2
    exit 1 ;;
  esac
  if [ "$INTERVAL" -lt 1 ] || [ "$INTERVAL" -gt "$MAX_WATCH_INTERVAL" ]; then
    echo "operator_dapp_stream_health: --interval must be in 1..$MAX_WATCH_INTERVAL (got '$INTERVAL')" >&2
    exit 1
  fi
else
  # --count / --interval are only meaningful under --watch; reject a stray
  # --count so the operator isn't misled into thinking a single-shot run looped.
  if [ -n "$COUNT" ]; then
    echo "operator_dapp_stream_health: --count requires --watch" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path (mirrors operator_dapp_inventory.sh /
# operator_dapp_health.sh — Windows CreateProcessW resolves relative paths
# differently from POSIX exec*() when invoked from python subprocess.run).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── one_poll: fetch dapp_subscribers once, parse + render, evaluate anomalies ──
# Emits the human/JSON output for this poll and, on the LAST line of stdout,
# a machine-readable control record the shell loop reads back:
#   __CTRL__ <rc> <count> <max> <kills> <critical_bool>
# where rc is: 0 ok, 1 rpc/parse/pre-R54 error. The shell layer maps a critical
# anomaly (or a --watch kills-rising delta computed BELOW in shell) to exit 2.
#
# We pass the previous poll's kills value in ($1 of the python call) so the
# delta / kills_rising evaluation happens where the JSON is already parsed.
# PREV_KILLS = -1 sentinel means "no previous poll" (first --watch iter or the
# single-shot run) → no delta reported and kills_rising cannot fire.
one_poll() {
  local prev_kills="$1"
  local sub_out sub_rc

  sub_out=$("$DETERM_ABS" dapp-subscribers --rpc-port "$PORT" 2>&1); sub_rc=$?

  # A non-zero rc is either an unreachable daemon OR a pre-R54 daemon that does
  # not know the dapp_subscribers method (the RPC layer throws "Unknown method:
  # dapp_subscribers"). Disambiguate on the stderr text so the operator gets a
  # precise, actionable message.
  if [ "$sub_rc" -ne 0 ]; then
    case "$sub_out" in
      *[Uu]nknown\ method*|*[Mm]ethod\ not\ found*|*-32601*)
        echo "operator_dapp_stream_health: daemon does not implement dapp_subscribers — requires an R54+ daemon (v2.20 streaming observability)" >&2
        ;;
      *)
        echo "operator_dapp_stream_health: cannot reach daemon on rpc-port $PORT (dapp-subscribers RPC failed)" >&2
        ;;
    esac
    echo "__CTRL__ 1 0 0 0 0"
    return 1
  fi

  # Parse + evaluate + render entirely in python (no jq dependency). The RPC
  # payload is passed via a TEMP FILE (argv), NOT stdin: the python program is
  # itself delivered on stdin via the heredoc, so piping the JSON to stdin too
  # would let the heredoc win and the parse would read nothing (this is the same
  # stdin-collision the sibling operator_dapp_* scripts avoid with temp files).
  # The trailing __CTRL__ line is the shell's machine-readable handle on this poll.
  local pay_file
  pay_file=$(mktemp 2>/dev/null) || {
    echo "operator_dapp_stream_health: cannot create temp file" >&2
    echo "__CTRL__ 1 0 0 0 0"
    return 1
  }
  printf '%s' "$sub_out" > "$pay_file"

  python - \
      "$JSON_OUT" "$ANOM_ONLY" "$NEAR_CEIL" "$WARN_SAT_PCT" "$PORT" "$prev_kills" "$pay_file" <<'PY'
import json, sys

json_out    = sys.argv[1] == "1"
anom_only   = sys.argv[2] == "1"
near_ceil   = int(sys.argv[3])
warn_sat    = int(sys.argv[4])
port        = int(sys.argv[5])
prev_kills  = int(sys.argv[6])   # -1 sentinel = no previous poll
pay_file    = sys.argv[7]

with open(pay_file, "r", encoding="utf-8") as _f:
    raw = _f.read()
try:
    j = json.loads(raw)
except Exception:
    sys.stderr.write("operator_dapp_stream_health: dapp-subscribers returned non-JSON response\n")
    print("__CTRL__ 1 0 0 0 0")
    sys.exit(1)

if not isinstance(j, dict):
    sys.stderr.write("operator_dapp_stream_health: dapp-subscribers response is not a JSON object\n")
    print("__CTRL__ 1 0 0 0 0")
    sys.exit(1)

def as_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default

max_subs = as_int(j.get("max", 256), 256)
if max_subs <= 0:
    max_subs = 256  # defend against a malformed/zero max; 256 is the pinned cap
kills    = as_int(j.get("kills_backpressure", 0), 0)

subs_raw = j.get("subscribers")
if subs_raw is None:
    subs_raw = []
if not isinstance(subs_raw, list):
    sys.stderr.write("operator_dapp_stream_health: dapp-subscribers .subscribers is not an array\n")
    print("__CTRL__ 1 0 0 0 0")
    sys.exit(1)

# .count is authoritative per the contract; fall back to len(subscribers) if
# the field is absent/garbled, and note a mismatch (defensive, not fatal).
count_field = j.get("count", None)
count = as_int(count_field, len(subs_raw)) if count_field is not None else len(subs_raw)
count_mismatch = (count != len(subs_raw))

# Per-subscriber normalization + queue-depth distribution.
#
# queue ceiling: the contract gives per-row queue_depth/bytes_buffered/seq but
# not a per-row queue_max — the ceiling is the node-wide bounded-queue capacity.
# We treat max (SUBSCRIBER_MAX_PER_NODE is the subscriber-count cap, NOT the
# per-queue cap) — so per-row we compute risk from whatever ceiling the row
# exposes: prefer an explicit per-row "queue_max" if the daemon supplies one,
# else fall back to the max frames a row has been seen carrying is unknown, so
# risk is reported ONLY when a per-row queue_max is present. This keeps the
# risk-cohort sound: we never invent a ceiling.
rows = []
depths = []
risk_cohort = 0
risk_measurable = False
for s in subs_raw:
    if not isinstance(s, dict):
        continue
    sid    = str(s.get("sid", ""))
    domain = str(s.get("domain", ""))
    topic  = str(s.get("topic", ""))
    depth  = as_int(s.get("queue_depth", 0), 0)
    bytes_buffered = as_int(s.get("bytes_buffered", 0), 0)
    seq    = as_int(s.get("seq", 0), 0)
    killed = bool(s.get("killed", False))
    # Per-row queue ceiling, if the daemon exposes one (forward-compatible —
    # the contract does not mandate it, so absence is normal, not an error).
    qmax_field = s.get("queue_max", None)
    qmax = as_int(qmax_field, -1) if qmax_field is not None else -1
    at_risk = False
    if qmax > 0:
        risk_measurable = True
        if (qmax - depth) <= near_ceil:
            at_risk = True
            risk_cohort += 1
    depths.append(depth)
    rows.append({
        "sid": sid, "domain": domain, "topic": topic,
        "queue_depth": depth, "bytes_buffered": bytes_buffered,
        "seq": seq, "killed": killed,
        "queue_max": (qmax if qmax > 0 else None),
        "at_risk": at_risk,
    })

killed_now = sum(1 for r in rows if r["killed"])

n = len(depths)
depth_max  = max(depths) if depths else 0
depth_mean = (sum(depths) / n) if n else 0.0

# Saturation. count vs the 256-subscriber cap.
sat_pct = (count * 100 // max_subs) if max_subs > 0 else 0

# ── Anomaly evaluation ────────────────────────────────────────────────────────
anomalies = []
critical  = []

# CRITICAL: fleet_saturated — the table is full; subscribe attempts refused.
if count >= max_subs:
    anomalies.append("fleet_saturated")
    critical.append("fleet_saturated")
else:
    # WARN: near_cap — approaching the ceiling but not yet full.
    if sat_pct >= warn_sat:
        anomalies.append("near_cap")

# WARN: backpressure_risk — >=1 measurable subscriber within near_ceil of its
# queue ceiling. Only fires when a per-row queue_max was actually present.
if risk_measurable and risk_cohort > 0:
    anomalies.append("backpressure_risk")

# kills_rising (CRITICAL) is evaluated by the SHELL loop across polls using the
# kills value on the __CTRL__ line — but we also compute the delta here for the
# human/JSON output when a previous value is known.
kills_delta = None
if prev_kills >= 0:
    kills_delta = kills - prev_kills
    if kills_delta > 0:
        # Surface it in this poll's anomaly list + mark critical so the shell's
        # __CTRL__ critical flag reflects it even on the final --watch iter.
        anomalies.append("kills_rising")
        critical.append("kills_rising")

is_critical = 1 if critical else 0

# ── Render ────────────────────────────────────────────────────────────────────
if json_out:
    envelope = {
        "rpc_port":            port,
        "count":               count,
        "max":                 max_subs,
        "saturation_pct":      sat_pct,
        "kills_backpressure":  kills,
        "kills_delta":         kills_delta,
        "killed_live_rows":    killed_now,
        "queue_depth": {
            "max":  depth_max,
            "mean": round(depth_mean, 3),
        },
        "near_ceiling":        near_ceil,
        "backpressure_risk_cohort": risk_cohort,
        "risk_measurable":     risk_measurable,
        "warn_saturation_pct": warn_sat,
        "count_field_mismatch": count_mismatch,
        "anomalies":           anomalies,
        "critical_anomalies":  critical,
    }
    if not anom_only:
        envelope["subscribers"] = rows
    print(json.dumps(envelope))
else:
    print(f"=== DApp stream health (port {port}) ===")
    print(f"Subscribers: {count}/{max_subs}  saturation={sat_pct}%"
          + (f"  (>= {warn_sat}% WARN band)" if sat_pct >= warn_sat and count < max_subs else ""))
    delta_str = ""
    if kills_delta is not None:
        sign = "+" if kills_delta >= 0 else ""
        delta_str = f"  (delta {sign}{kills_delta} since last poll)"
    print(f"Backpressure kills (cumulative): {kills}{delta_str}")
    if killed_now:
        print(f"Killed rows still in snapshot: {killed_now}")
    if n:
        print(f"Queue depth: max={depth_max}  mean={depth_mean:.2f}  (over {n} live rows)")
        if risk_measurable:
            print(f"Backpressure-risk cohort (within {near_ceil} of ceiling): {risk_cohort}")
        else:
            print(f"Backpressure-risk cohort: n/a (daemon exposes no per-row queue_max)")
    else:
        print("Queue depth: (no live subscribers)")
    if count_mismatch:
        print(f"NOTE: .count ({count}) != len(subscribers) ({len(subs_raw)}) — using .count")
    print()

    if not anom_only:
        if not rows:
            print("(no live subscribers)")
        else:
            hdr = ("SID", "DOMAIN", "TOPIC", "DEPTH", "BYTES", "SEQ", "KILLED", "RISK")
            print(f"{hdr[0]:<18}  {hdr[1]:<20}  {hdr[2]:<16}  {hdr[3]:>6}  {hdr[4]:>10}  {hdr[5]:>10}  {hdr[6]:>6}  {hdr[7]:>4}")
            print("-" * 104)
            # Highest queue depth first — the operator's attention order.
            for r in sorted(rows, key=lambda x: (-x["queue_depth"], x["sid"])):
                topic_disp = r["topic"] if r["topic"] else "-"
                print(f"{r['sid']:<18.18}  {r['domain']:<20.20}  {topic_disp:<16.16}  "
                      f"{r['queue_depth']:>6}  {r['bytes_buffered']:>10}  {r['seq']:>10}  "
                      f"{('yes' if r['killed'] else 'no'):>6}  {('!' if r['at_risk'] else '-'):>4}")
        print()

    if not anomalies:
        print("[OK] No anomalies")
    else:
        print(f"[ANOMALY] {len(anomalies)} flag(s): {','.join(anomalies)}")
        if "fleet_saturated" in anomalies:
            print(f"  - fleet_saturated (CRITICAL): {count}/{max_subs} — table full; "
                  "new dapp_subscribe attempts are being refused")
        if "kills_rising" in anomalies:
            print(f"  - kills_rising (CRITICAL): backpressure kills rose by "
                  f"{kills_delta} during the observation window")
        if "near_cap" in anomalies:
            print(f"  - near_cap (WARN): saturation {sat_pct}% >= {warn_sat}% — approaching the cap")
        if "backpressure_risk" in anomalies:
            print(f"  - backpressure_risk (WARN): {risk_cohort} subscriber(s) within "
                  f"{near_ceil} frames of their queue ceiling")

# Control line — always the LAST line of stdout, read by the shell loop.
print(f"__CTRL__ 0 {count} {max_subs} {kills} {is_critical}")
PY
  local py_rc=$?
  rm -f "$pay_file" 2>/dev/null
  return $py_rc
}

# ── Drive: single-shot or bounded --watch loop ────────────────────────────────
# We capture each poll's stdout, split off the trailing __CTRL__ control line,
# print the rest, and thread the kills counter into the next poll so the delta /
# kills_rising evaluation has a previous value. Overall exit code:
#   1 if any poll hit an RPC/parse/pre-R54 error,
#   2 if any poll flagged a CRITICAL anomaly (and no error),
#   0 otherwise.
FINAL_RC=0
PREV_KILLS=-1

run_one() {
  local prev="$1" out ctrl body
  out=$(one_poll "$prev")   # one_poll's return value is not load-bearing; parse __CTRL__
  # Split trailing control line from the body.
  ctrl=$(printf '%s\n' "$out" | grep '^__CTRL__ ' | tail -1)
  body=$(printf '%s\n' "$out" | grep -v '^__CTRL__ ')
  [ -n "$body" ] && printf '%s\n' "$body"

  # Parse control: __CTRL__ <rc> <count> <max> <kills> <critical>
  # shellcheck disable=SC2086
  set -- $ctrl
  # $1=__CTRL__ $2=rc $3=count $4=max $5=kills $6=critical
  local c_rc="${2:-1}" c_kills="${5:-}" c_crit="${6:-0}"
  case "$c_rc" in *[!0-9]*|"") c_rc=1 ;; esac
  case "$c_crit" in *[!0-9]*|"") c_crit=0 ;; esac

  if [ "$c_rc" -ne 0 ]; then
    FINAL_RC=1
  else
    # Advance PREV_KILLS for the next poll's delta only on a clean poll.
    case "$c_kills" in
      ''|*[!0-9]*) : ;;
      *) PREV_KILLS="$c_kills" ;;
    esac
    if [ "$c_crit" -ne 0 ] && [ "$FINAL_RC" -ne 1 ]; then
      FINAL_RC=2
    fi
  fi
}

if [ "$WATCH" = "1" ]; then
  i=1
  while [ "$i" -le "$COUNT" ]; do
    if [ "$JSON_OUT" != "1" ] && [ "$i" -gt 1 ]; then
      echo "---- poll $i/$COUNT ----"
    fi
    run_one "$PREV_KILLS"
    # A hard RPC error aborts the loop (retrying an unreachable/pre-R54 daemon
    # on every interval just wastes the operator's time).
    if [ "$FINAL_RC" = "1" ]; then
      break
    fi
    if [ "$i" -lt "$COUNT" ]; then
      sleep "$INTERVAL"
    fi
    i=$(( i + 1 ))
  done
else
  run_one "$PREV_KILLS"
fi

exit "$FINAL_RC"
