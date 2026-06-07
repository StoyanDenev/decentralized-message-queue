#!/usr/bin/env bash
# operator_validator_abort_rate.sh — Per-validator ABORT-RATE audit over a
# window of finalized blocks, normalized against committee DUTY.
#
# Liveness axis this fills:
#   Determ's K-of-K consensus has TWO distinct validator-liveness failure
#   modes:
#     (1) MISSED SIGNATURE  — a selected committee member never lands a
#         block-signature; their parallel `creator_block_sigs[]` slot is
#         the all-zero sentinel. (Already covered: operator_signature_audit.sh,
#         operator_validator_uptime.sh, operator_block_inclusion_audit.sh.)
#     (2) ABORT             — a selected committee member triggers a
#         round restart instead of completing the round. The producer
#         records this as an `abort_events[]` entry on the finalized block:
#         {round, aborting_node, timestamp, event_hash, claims}. A
#         validator can be PRESENT and even SIGN the final block yet
#         repeatedly abort earlier rounds, dragging finalization latency
#         and forcing committee re-selection. That is a liveness DRAG the
#         missed-signature lens is structurally blind to (the final block
#         it produced HAS the validator's signature).
#
#   This tool isolates mode (2) and — crucially — normalizes it against
#   each validator's committee DUTY in the window. An abort can only be
#   raised by a SELECTED committee member, so the meaningful signal is
#       abort_rate = aborts / selections
#   not the raw abort COUNT. A validator selected 500 times with 5 aborts
#   (1%) is healthy; one selected 10 times with 5 aborts (50%) is a serial
#   aborter. Raw-count tools conflate the two.
#
# How this differs from the abort-touching siblings:
#   operator_slashing_ledger.sh
#       Groups abort_events by `aborting_node` over a window as raw SLASH
#       EVENTS (and folds in the cumulative S-032 abort_records cache).
#       Reports COUNTS; never divides by committee duty, never uses the
#       per-event `round` field.
#   operator_event_summary.sh
#       Per-validator abort COUNT + an abort-flood absolute threshold
#       (e.g. > 20 aborts). Again a raw count, not a duty-normalized rate;
#       no round breakdown.
#   operator_validator_history.sh
#       Per-validator lifecycle EVENT TAPE; surfaces each abort's `round`
#       as a passthrough display value but never aggregates a round
#       distribution or a rate.
#   operator_signature_audit.sh / _uptime / _block_inclusion_audit
#       The MISSED-SIGNATURE lens (mode 1 above). Orthogonal failure mode.
#   operator_validator_abort_rate.sh  (THIS)
#       Mode (2), DUTY-NORMALIZED: per-validator aborts / selections, plus
#       the first-seen aggregate ROUND DISTRIBUTION of aborts (which round
#       index did validators bail at?) — round 0/1 stalls (early-round
#       failure) read differently from late-round aborts. No sibling
#       computes either of these.
#
# Data source (read-only RPC only):
#   `determ status`               — once, to resolve chain height (next
#                                   index to produce; top finalized index
#                                   = height - 1). Falls back to
#                                   `determ head --field height`.
#   `determ block-info <h> --json` — per block. Reads two fields:
#       creators[]      — the K committee-member domains drawn for that
#                         block (src/chain/block.cpp:377-379). Used to
#                         tally each validator's committee DUTY (selections).
#       abort_events[]  — array of AbortEvent JSON
#                         (src/chain/block.cpp:97-105, 460-461):
#                             round         uint8  — round index the abort
#                                                    was raised in
#                             aborting_node string — validator domain that
#                                                    aborted
#                         We tally aborts per aborting_node, normalize by
#                         that domain's selections, and bucket the `round`
#                         field across all aborts in the window.
#
#   `rpc_block` returns chain_.at(index).to_json() (src/node/node.cpp:2617),
#   so the full Block JSON — including abort_events[] and creators[] — is
#   available read-only. Read-only; safe against any running daemon.
#
# A note on duty vs. attribution:
#   `aborting_node` is the validator the producer ATTRIBUTED the abort to.
#   A validator that aborts a round it was selected for contributes to
#   BOTH numerator (aborts) and denominator (selections, since it was in
#   creators[] of SOME block — though not necessarily this one, because an
#   aborted round may not be the one that finalized into this block's
#   creators[]). We therefore report abort_rate as aborts/selections where
#   selections is the validator's total committee appearances in the
#   window; this is a conservative duty proxy and is documented as such.
#   When a domain appears in abort_events but never in any creators[] over
#   the window (selections == 0), abort_rate is reported as null and the
#   domain is flagged `aborts_without_observed_duty` (the validator's
#   selections sit outside the window, or it aborted before finalizing
#   into any in-window block — surfaced separately so an operator can
#   widen the window).
#
# Anomalies (each gates exit 2; in default mode any one also forces exit 2
# so a monitoring wrapper alerts without --anomalies-only):
#   high_abort_rate          any validator with selections >= --min-duty
#                            AND abort_rate > --abort-rate-threshold
#                            (default 0.10 = 10% of its rounds aborted).
#   abort_volume_high        window-wide total aborts / total selections
#                            > --window-abort-threshold (default 0.05).
#                            Broad cluster-health signal: lots of rounds
#                            are being restarted regardless of culprit.
#   aborts_without_duty      >=1 domain raised aborts but never appeared
#                            in any creators[] in the window (window too
#                            narrow to attribute its duty; informational
#                            but flagged so the operator widens --from).
#
# Args:
#   --rpc-port N               RPC port to query (default: 7778)
#   --from H                   Lower window bound, inclusive (default: head-999)
#   --to H                     Upper window bound, inclusive (default: head)
#   --last N                   Shorthand for [head-N+1, head] (exclusive
#                              with --from/--to)
#   --validator <domain>       Cosmetic filter on the by_validator table;
#                              summary + anomalies still computed across
#                              the full population.
#   --abort-rate-threshold F   high_abort_rate per-validator threshold
#                              (default: 0.10).
#   --window-abort-threshold F abort_volume_high window threshold
#                              (default: 0.05).
#   --min-duty N               minimum selections for a validator to be
#                              eligible for high_abort_rate (default: 5;
#                              avoids flagging a 1/1 small-sample blip).
#   --json                     Emit structured JSON envelope.
#   --anomalies-only           Print only when >=1 anomaly fires; exit 2 then.
#   -h, --help                 Show this help.
#
# Exit codes:
#   0   audit ran; no anomalies (or --anomalies-only with none); or clean
#       SKIP when the daemon is unreachable.
#   1   bad args / RPC error / malformed response / empty window.
#   2   >=1 anomaly fired (operator alert gate).
set -u

usage() {
  cat <<'EOF'
Usage: operator_validator_abort_rate.sh [--rpc-port N]
                                        [--from H] [--to H] [--last N]
                                        [--validator <domain>]
                                        [--abort-rate-threshold F]
                                        [--window-abort-threshold F]
                                        [--min-duty N]
                                        [--json] [--anomalies-only]

Per-validator ABORT-RATE audit over a window of finalized blocks,
normalized against committee DUTY. Isolates the round-restart liveness
failure mode (a selected committee member that aborts rounds) from the
missed-signature mode that the signature/uptime/inclusion tools cover.

For each block in the window, parses `creators[]` (committee duty) and
`abort_events[]` ({round, aborting_node}). Per validator:
  selections    committee appearances in the window (duty denominator)
  aborts        abort_events attributed to this validator (aborting_node)
  abort_rate    aborts / selections   (null when selections == 0)

Window-wide:
  total_selections   sum of len(creators[]) across blocks
  total_aborts       total abort_events in the window
  window_abort_rate  total_aborts / total_selections
  round_distribution histogram of the per-abort `round` field

Reads only `determ status` (once, for chain height) and
`determ block-info <h> --json` (per block). Read-only; safe against any
running daemon.

Options:
  --rpc-port N                RPC port (default: 7778)
  --from H                    Lower window bound, inclusive
                              (default: max(0, head - 999))
  --to H                      Upper window bound, inclusive (default: head)
  --last N                    Shorthand for [head-N+1, head]
                              (exclusive with --from/--to)
  --validator <domain>        Cosmetic by_validator filter; summary +
                              anomalies still computed across all domains
  --abort-rate-threshold F    high_abort_rate per-validator threshold
                              (default: 0.10)
  --window-abort-threshold F  abort_volume_high window threshold
                              (default: 0.05)
  --min-duty N                min selections to be eligible for
                              high_abort_rate (default: 5)
  --json                      Emit structured JSON envelope
  --anomalies-only            Suppress healthy output; exit 2 if any anomaly
  -h, --help                  Show this help

Anomalies:
  high_abort_rate        validator with selections >= --min-duty AND
                         abort_rate > --abort-rate-threshold
  abort_volume_high      window_abort_rate > --window-abort-threshold
  aborts_without_duty    >=1 domain aborted but never appeared in
                         creators[] in the window (widen --from)

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W},
   "by_validator": [{"domain":..., "selections":..., "aborts":...,
                     "abort_rate": <float|null>}, ...],
   "summary": {"total_selections":..., "total_aborts":...,
               "window_abort_rate":..., "distinct_aborters":...,
               "round_distribution": {"<round>": <count>, ...}},
   "aborters_without_duty": [<domain>, ...],
   "anomalies": [...],
   "rpc_port": P, "head_height": HH}

Exit codes:
  0   success, no anomalies (or --anomalies-only with none); SKIP if daemon
      unreachable
  1   RPC error / malformed response / bad args / empty window
  2   >=1 anomaly fired (operator alert gate)
EOF
}

PORT=7778
FROM=""
TO=""
LAST=""
VALIDATOR=""
ABORT_RATE_THRESHOLD="0.10"
WINDOW_ABORT_THRESHOLD="0.05"
MIN_DUTY=5
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                 usage; exit 0 ;;
    --rpc-port)                PORT="${2:-}";                  shift 2 ;;
    --from)                    FROM="${2:-}";                  shift 2 ;;
    --to)                      TO="${2:-}";                    shift 2 ;;
    --last)                    LAST="${2:-}";                  shift 2 ;;
    --validator)               VALIDATOR="${2:-}";             shift 2 ;;
    --abort-rate-threshold)    ABORT_RATE_THRESHOLD="${2:-}";  shift 2 ;;
    --window-abort-threshold)  WINDOW_ABORT_THRESHOLD="${2:-}";shift 2 ;;
    --min-duty)                MIN_DUTY="${2:-}";              shift 2 ;;
    --json)                    JSON_OUT=1;                     shift ;;
    --anomalies-only)          ANOM_ONLY=1;                    shift ;;
    *) echo "operator_validator_abort_rate: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Numeric / argument guards ─────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_validator_abort_rate: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_validator_abort_rate: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST" "$MIN_DUTY"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_validator_abort_rate: --from / --to / --last / --min-duty must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_validator_abort_rate: --last must be >= 1" >&2
  exit 1
fi
case "$MIN_DUTY" in *[!0-9]*|"")
  echo "operator_validator_abort_rate: --min-duty must be a non-negative integer (got '$MIN_DUTY')" >&2
  exit 1 ;;
esac
# Float thresholds: accept decimal forms like 0.10, .05, 1, 0 (reject junk).
for pair in "abort-rate-threshold $ABORT_RATE_THRESHOLD" "window-abort-threshold $WINDOW_ABORT_THRESHOLD"; do
  name="${pair%% *}"; val="${pair#* }"
  case "$val" in
    ""|*[!0-9.]*|*.*.*)
      echo "operator_validator_abort_rate: --${name} must be a non-negative decimal (got '$val')" >&2
      exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python resolves
# it regardless of cwd (matches operator_escalation_episodes.sh /
# operator_committee_audit.sh convention).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain head ────────────────────────────────────────────────
# Prefer `determ status` (carries height); fall back to `determ head
# --field height`. An unreachable daemon yields a clean SKIP (exit 0) so a
# monitoring wrapper that runs this against a node that's down for
# maintenance doesn't page — distinguishing "daemon down" (informational)
# from "daemon up but malformed" (error).
STATUS_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null)
if [ -z "$STATUS_JSON" ]; then
  if [ "$JSON_OUT" -eq 1 ]; then
    echo '{"skipped":true,"reason":"daemon unreachable","rpc_port":'"$PORT"'}'
  else
    echo "operator_validator_abort_rate: INFO daemon unreachable on rpc-port $PORT (no status response) — SKIP"
  fi
  exit 0
fi
HEIGHT=$(printf '%s' "$STATUS_JSON" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    h = j.get('height')
    print(int(h) if h is not None else '')
except Exception:
    print('')
")
if [ -z "$HEIGHT" ]; then
  HEIGHT=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null || echo "")
fi
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_validator_abort_rate: malformed status/head response (height='$HEIGHT', port $PORT)" >&2
  exit 1 ;;
esac
if [ "$HEIGHT" = "0" ]; then
  echo "operator_validator_abort_rate: chain is empty (height=0); nothing to audit" >&2
  exit 1
fi

# Highest finalized index = height - 1 (height is the NEXT index to produce).
TOP=$(( HEIGHT - 1 ))

# Resolve window bounds. Precedence: --last > (--from/--to) > default-last-1000.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TOP - LAST + 1 ))
  fi
  TO=$TOP
else
  if [ -z "$TO" ]; then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    if [ "$TOP" -gt 999 ]; then
      FROM=$(( TOP - 999 ))
    else
      FROM=0
    fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_validator_abort_rate: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk + per-validator abort-rate (Python driver) ─────────
# The Python driver fans out one block-info RPC per block, tallies each
# validator's committee duty (creators[]) and aborts (abort_events
# aborting_node), buckets the per-abort `round` field, normalizes
# abort_rate = aborts / selections, classifies anomalies, and writes the
# full JSON envelope to a temp file. Bash reads it back for rendering +
# the exit-code decision.
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_validator_abort_rate: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" \
         "$ABORT_RATE_THRESHOLD" "$WINDOW_ABORT_THRESHOLD" "$MIN_DUTY" "$HEIGHT" <<'PY'
import json, subprocess, sys

(determ, port, from_h, to_h, out_path,
 abort_rate_thr, window_abort_thr, min_duty, height) = sys.argv[1:10]
from_h, to_h     = int(from_h), int(to_h)
abort_rate_thr   = float(abort_rate_thr)
window_abort_thr = float(window_abort_thr)
min_duty         = int(min_duty)
head_height      = int(height)

def fetch_block(h):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        sys.stderr.write(f"operator_validator_abort_rate: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_validator_abort_rate: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_validator_abort_rate: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        sys.stderr.write(f"operator_validator_abort_rate: block-info {h} not a JSON object\n")
        sys.exit(1)
    return blk

selections = {}   # domain -> committee appearances (duty denominator)
aborts     = {}   # domain -> abort_events attributed (aborting_node)
round_dist = {}   # round (str) -> count, across all aborts in the window
total_selections = 0
total_aborts     = 0

for h in range(from_h, to_h + 1):
    blk = fetch_block(h)

    # creators[]: committee duty. src/chain/block.cpp:377-379.
    creators = blk.get("creators") or []
    if isinstance(creators, list):
        for c in creators:
            if isinstance(c, str) and c:
                selections[c] = selections.get(c, 0) + 1
                total_selections += 1

    # abort_events[]: {round, aborting_node}. src/chain/block.cpp:97-105,460-461.
    aes = blk.get("abort_events") or []
    if isinstance(aes, list):
        for ae in aes:
            if not isinstance(ae, dict):
                continue
            dom = ae.get("aborting_node", "")
            if isinstance(dom, str) and dom:
                aborts[dom] = aborts.get(dom, 0) + 1
                total_aborts += 1
                rnd = ae.get("round", None)
                try:
                    rkey = str(int(rnd))
                except Exception:
                    rkey = "unknown"
                round_dist[rkey] = round_dist.get(rkey, 0) + 1

# ── Per-validator rows ─────────────────────────────────────────────────────────
# Union of everyone who was selected and everyone who aborted, so a domain
# that aborted but never appeared in creators[] (selections==0) is still
# surfaced (and flagged separately).
domains = set(selections) | set(aborts)
by_validator = []
aborters_without_duty = []
for d in sorted(domains):
    sel = selections.get(d, 0)
    ab  = aborts.get(d, 0)
    rate = (ab / sel) if sel > 0 else None
    if sel == 0 and ab > 0:
        aborters_without_duty.append(d)
    by_validator.append({
        "domain":     d,
        "selections": sel,
        "aborts":     ab,
        "abort_rate": rate,
    })

# Sort: highest abort_rate first (null rate sorts last), then by raw aborts.
def sort_key(r):
    rate = r["abort_rate"]
    return (0 if rate is None else 1, -(rate if rate is not None else 0.0), -r["aborts"])
by_validator.sort(key=sort_key)

window_abort_rate = (total_aborts / total_selections) if total_selections > 0 else 0.0

# ── Anomalies ──────────────────────────────────────────────────────────────────
anomalies = []
for r in by_validator:
    if r["abort_rate"] is not None and r["selections"] >= min_duty \
       and r["abort_rate"] > abort_rate_thr:
        anomalies.append({
            "kind":       "high_abort_rate",
            "domain":     r["domain"],
            "selections": r["selections"],
            "aborts":     r["aborts"],
            "abort_rate": r["abort_rate"],
        })
if total_selections > 0 and window_abort_rate > window_abort_thr:
    anomalies.append({
        "kind":              "abort_volume_high",
        "window_abort_rate": window_abort_rate,
        "total_aborts":      total_aborts,
        "total_selections":  total_selections,
    })
if aborters_without_duty:
    anomalies.append({
        "kind":    "aborts_without_duty",
        "domains": aborters_without_duty,
    })

envelope = {
    "window": {"from": from_h, "to": to_h, "block_count": to_h - from_h + 1},
    "by_validator": by_validator,
    "summary": {
        "total_selections":   total_selections,
        "total_aborts":       total_aborts,
        "window_abort_rate":  window_abort_rate,
        "distinct_aborters":  len(aborts),
        "round_distribution": round_dist,
    },
    "aborters_without_duty": aborters_without_duty,
    "anomalies": anomalies,
    "rpc_port": int(port),
    "head_height": head_height,
}
with open(out_path, "w") as f:
    json.dump(envelope, f)
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  # Python driver already wrote a diagnostic to stderr.
  exit 1
fi
if [ ! -s "$TMP_OUT" ]; then
  echo "operator_validator_abort_rate: driver produced no output" >&2
  exit 1
fi

# ── Step 3: render + exit-code decision ───────────────────────────────────────
N_ANOM=$(python -c "
import sys, json
j = json.load(open('$TMP_OUT'))
print(len(j.get('anomalies', [])))
" 2>/dev/null)
case "$N_ANOM" in *[!0-9]*|"")
  echo "operator_validator_abort_rate: failed to parse driver output" >&2
  exit 1 ;;
esac

if [ "$JSON_OUT" -eq 1 ]; then
  if [ "$ANOM_ONLY" -eq 1 ] && [ "$N_ANOM" -eq 0 ]; then
    :
  else
    cat "$TMP_OUT"
    echo
  fi
else
  python - "$TMP_OUT" "$VALIDATOR" "$ANOM_ONLY" "$ABORT_RATE_THRESHOLD" \
           "$WINDOW_ABORT_THRESHOLD" "$MIN_DUTY" <<'PY'
import json, sys
path, vfilter, anom_only_s, art, wat, min_duty = sys.argv[1:7]
anom_only = (anom_only_s == "1")
j = json.load(open(path))
w = j["window"]; s = j["summary"]
anomalies = j.get("anomalies", [])

if anom_only and not anomalies:
    print(f"[OK] operator_validator_abort_rate: no anomalies "
          f"(window [{w['from']}..{w['to']}], {s['total_aborts']} aborts / "
          f"{s['total_selections']} selections)")
    sys.exit(0)

print(f"operator_validator_abort_rate — window [{w['from']}..{w['to']}] "
      f"({w['block_count']} blocks), duty-normalized abort rate")
print(f"  thresholds: per-validator abort_rate > {art} (min-duty {min_duty}); "
      f"window abort_rate > {wat}")
print(f"  total selections : {s['total_selections']}")
print(f"  total aborts     : {s['total_aborts']}")
wr = s["window_abort_rate"]
print(f"  window abort_rate: {wr:.4f}")
print(f"  distinct aborters: {s['distinct_aborters']}")

rd = s.get("round_distribution") or {}
if rd:
    # Sort numeric round keys numerically; 'unknown' last.
    def rk(k):
        try: return (0, int(k))
        except Exception: return (1, 0)
    parts = ", ".join(f"r{k}={rd[k]}" for k in sorted(rd, key=rk))
    print(f"  abort round dist : {parts}")
else:
    print(f"  abort round dist : (no aborts in window)")

rows = j.get("by_validator", [])
if vfilter:
    rows = [r for r in rows if r["domain"] == vfilter]

if not anom_only:
    print("  per-validator (abort_rate desc):")
    if not rows:
        print("    (no validators in window"
              + (f" matching '{vfilter}'" if vfilter else "") + ")")
    for r in rows:
        rate = r["abort_rate"]
        rate_s = "n/a " if rate is None else f"{rate:6.4f}"
        print(f"    {r['domain']:<28} sel={r['selections']:>5} "
              f"aborts={r['aborts']:>4}  rate={rate_s}")

if anomalies:
    print("  ANOMALIES:")
    for a in anomalies:
        k = a["kind"]
        if k == "high_abort_rate":
            print(f"    [high_abort_rate] {a['domain']}: "
                  f"{a['aborts']}/{a['selections']} = {a['abort_rate']:.4f} "
                  f"(> {art})")
        elif k == "abort_volume_high":
            print(f"    [abort_volume_high] window abort_rate "
                  f"{a['window_abort_rate']:.4f} > {wat} "
                  f"({a['total_aborts']}/{a['total_selections']})")
        elif k == "aborts_without_duty":
            doms = ", ".join(a["domains"])
            print(f"    [aborts_without_duty] aborted but no in-window duty: {doms} "
                  f"(widen --from)")
    print(f"[ANOMALY] {len(anomalies)} finding(s)")
else:
    print("[OK] no anomalies")
PY
fi

# ── Exit-code contract ────────────────────────────────────────────────────────
#   2  when an anomaly fired (regardless of --anomalies-only).
#   0  otherwise.
if [ "$N_ANOM" -gt 0 ]; then
  exit 2
fi
exit 0
