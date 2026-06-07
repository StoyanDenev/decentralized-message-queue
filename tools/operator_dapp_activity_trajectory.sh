#!/usr/bin/env bash
# operator_dapp_activity_trajectory.sh — Per-DApp DAPP_CALL message-rate
# TRAJECTORY (direction-of-travel) audit over a window of finalized
# blocks on a running determ daemon. Splits the audit window into a
# FIRST half and a SECOND half, counts DAPP_CALL messages addressed to
# each registered DApp in each half, and classifies every DApp's
# activity trajectory as RISING / FALLING / STEADY / DORMANT based on
# the half-over-half message-rate delta.
#
# The defining operator question — answered by NO existing DApp tool:
#   "For each registered DApp, is its call traffic ACCELERATING,
#    DECELERATING, or FLAT across this window? Which DApps RAMPED UP
#    (surge) and which COLLAPSED (active early, silent late)?"
#
# ── Why this is a distinct lane (the gap it fills) ────────────────────────────
# Every neighbouring DApp tool reports an AGGREGATE or a CONCENTRATION
# over the window, NOT a within-window DIRECTION-OF-TRAVEL per DApp:
#
#   operator_dapp_call_audit.sh        global DAPP_CALL routing (top callers
#                                      / targets, payload sizes) — single
#                                      window AGGREGATE, no temporal axis.
#   operator_dapp_call_volume_audit.sh per-DApp + per-SENDER concentration
#                                      + spam-burst (single sender > N calls
#                                      per 100-block sub-window). That is an
#                                      ABUSE / Sybil signal, not a
#                                      growth/decline DIRECTION.
#   operator_dapp_message_audit.sh     per-DApp message VOLUME + topic
#                                      distribution + lifecycle
#                                      (ACTIVE/DORMANT/ABANDONED vs. a fixed
#                                      block threshold). Lifecycle is an
#                                      absolute recency cutoff, NOT a
#                                      half-over-half rate trend.
#   operator_dapp_topic_audit.sh       topic REGISTRATION distribution
#                                      (registry, not call activity).
#   operator_dapp_registration_audit   DAPP_REGISTER buckets (registration
#                                      cadence, not call traffic).
#   operator_dapp_health.sh            registry + recent-message liveness +
#                                      mass-deactivation burst.
#
#   operator_dapp_activity_trajectory.sh  THIS — per-DApp FIRST-half vs
#                                      SECOND-half DAPP_CALL message-RATE
#                                      delta and a RISING / FALLING / STEADY
#                                      / DORMANT classification. The unit is
#                                      the RATE CHANGE between the two halves
#                                      of one window — a momentum / trend
#                                      direction signal absent everywhere
#                                      else in the DApp lane.
#
# ── Data source (read-only RPC; verified against src/) ────────────────────────
#   1. `determ head --field height --rpc-port N`
#        → chain tip; daemon-unreachable ⇒ clean SKIP (exit 0).
#          (cmd_head, src/main.cpp:2692; --field height path
#           src/main.cpp:2715–2720.)
#   2. `determ dapp-list --rpc-port N`
#        → enumerate registered DApps. JSON shape {height,count,dapps:[
#          {domain,endpoint_url,topics,active}]} per Node::rpc_dapp_list
#          (src/node/node.cpp:3142; out.push_back fields 3169–3174).
#   3. `determ dapp-messages --domain D --from H --to H [--topic T]`
#        → per-DApp DAPP_CALL event page. JSON shape {domain,from_height,
#          to_height,last_scanned,truncated,count,events:[{block_height,
#          tx_hash,from,to,amount,fee,nonce,topic,payload_hex}]} per
#          Node::rpc_dapp_messages (src/node/node.cpp:3086; event fields
#          3112–3122; pagination via last_scanned/truncated 3128–3137).
#          Server window is HALF-OPEN [from_height, to_height) — loop body
#          `for (h = from_height; h < to_height; ++h)` (node.cpp:3096).
#          Page cap DAPP_MESSAGES_PAGE_LIMIT = 256 (node.cpp:3083); we
#          resume from last_scanned+1 until truncated == false (same
#          idiom as operator_dapp_message_audit.sh).
#
# Only events with tx.to == domain and tx.type == DAPP_CALL are returned
# by the server (node.cpp:3099–3100), so every counted message is a
# genuine DAPP_CALL addressed to that DApp. This tool COUNTS messages per
# half; it never decodes payloads and never sends a transaction.
#
# ── Trajectory classification (per DApp) ──────────────────────────────────────
# Window [FROM..TO] (inclusive) is split at the midpoint MID = FROM +
# floor((TO-FROM+1)/2). FIRST half = [FROM, MID-1], SECOND half =
# [MID, TO]. Let n1, n2 be the DAPP_CALL counts in each half and b1, b2
# the block-spans (b1+b2 = window length). Rates r1 = n1/b1, r2 = n2/b2
# (per-block message rate, robust to an odd-length split). delta_pct =
# 100*(r2-r1)/r1 (or +inf-sentinel when r1==0 and r2>0).
#
#   DORMANT   n1 == 0 AND n2 == 0           (no calls either half)
#   RISING    r2 >= r1 * (1 + steady_band)  (accelerating; includes
#                                            0→positive "ignition")
#   FALLING   r2 <= r1 * (1 - steady_band)  (decelerating; includes
#                                            positive→0 "collapse")
#   STEADY    otherwise                     (within +/- steady_band)
#
#   steady_band defaults to 0.20 (20%): |delta| < 20% counts as flat.
#
# ── Anomaly flags (--anomalies-only; exit 2 if any fire) ──────────────────────
#   dapp_collapse   any DApp with n1 >= --collapse-min-first calls in the
#                   FIRST half but n2 == 0 in the SECOND half — was busy,
#                   went fully silent. A candidate abandonment / outage
#                   signal the absolute-cutoff lifecycle tools miss when
#                   the silence is recent.
#   dapp_surge      any DApp with r2 >= --surge-factor * r1 AND n2 >=
#                   --surge-min-second calls — a runaway ramp (the
#                   absolute floor avoids flagging a 0→2 blip as a surge).
#
# Both anomaly legs are advisory operator signals; neither implies a
# protocol fault.
#
# ── Usage ─────────────────────────────────────────────────────────────────────
#   tools/operator_dapp_activity_trajectory.sh --rpc-port N
#        [--from H] [--to H] [--topic T] [--prefix P]
#        [--steady-band F] [--surge-factor F]
#        [--collapse-min-first N] [--surge-min-second N]
#        [--top-N N] [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N            RPC port (REQUIRED)
#   --from H                window start (inclusive; default: max(0, head-4999))
#   --to H                  window end (inclusive; default: head)
#   --topic T               restrict counts to one DAPP_CALL topic (server filter)
#   --prefix P              restrict DApps to domains with this prefix (server filter)
#   --steady-band F         half-over-half rate band that counts as STEADY
#                           (fraction, default: 0.20 = +/-20%)
#   --surge-factor F        r2 >= F*r1 fires dapp_surge (default: 3.0)
#   --collapse-min-first N  min FIRST-half calls to qualify for dapp_collapse
#                           (default: 5)
#   --surge-min-second N    min SECOND-half calls to qualify for dapp_surge
#                           (default: 5)
#   --top-N N               rows printed in the human table (default: 25)
#   --json                  emit a structured JSON envelope
#   --anomalies-only        print only flagged anomalies; exit 2 if any fire
#   -h, --help              show this help and exit 0
#
# Exit codes:
#   0   success (with or without anomalies in default mode), INFO, or SKIP
#   1   bad args / RPC error / malformed response / empty window
#   2   --anomalies-only AND >= 1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_activity_trajectory.sh --rpc-port N
         [--from H] [--to H] [--topic T] [--prefix P]
         [--steady-band F] [--surge-factor F]
         [--collapse-min-first N] [--surge-min-second N]
         [--top-N N] [--json] [--anomalies-only]

Per-DApp DAPP_CALL message-rate TRAJECTORY audit. Splits the audit
window into a first half and a second half, counts DAPP_CALL messages
addressed to each registered DApp in each half (via paginated
dapp-messages), and classifies each DApp's trajectory as
RISING / FALLING / STEADY / DORMANT from the half-over-half per-block
rate delta. Read-only; never sends a transaction.

Options:
  --rpc-port N            RPC port (REQUIRED)
  --from H                Window start (inclusive; default: max(0, head-4999))
  --to H                  Window end (inclusive; default: head)
  --topic T               Restrict counts to one DAPP_CALL topic (server filter)
  --prefix P              Restrict DApps to a domain prefix (server filter)
  --steady-band F         Rate band counted as STEADY (fraction, default: 0.20)
  --surge-factor F        r2 >= F*r1 fires dapp_surge (default: 3.0)
  --collapse-min-first N  Min first-half calls for dapp_collapse (default: 5)
  --surge-min-second N    Min second-half calls for dapp_surge (default: 5)
  --top-N N               Rows in the human table (default: 25)
  --json                  Emit a machine-readable JSON envelope
  --anomalies-only        Print only anomaly lines; exit 2 if any fire
  -h, --help              Show this help

Anomaly flags:
  dapp_collapse   DApp busy in first half (>= --collapse-min-first) but
                  fully silent in second half
  dapp_surge      DApp second-half rate >= --surge-factor * first-half rate
                  AND >= --surge-min-second second-half calls

Exit codes:
  0   success / INFO / SKIP (daemon unreachable is a no-op, not an error)
  1   bad args / RPC error / malformed response / empty window
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=""
FROM_H=""
TO_H=""
TOPIC=""
PREFIX=""
STEADY_BAND="0.20"
SURGE_FACTOR="3.0"
COLLAPSE_MIN_FIRST="5"
SURGE_MIN_SECOND="5"
TOP_N="25"
JSON_OUT=0
ANOM_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-port)             PORT="${2:-}";              shift 2 ;;
    --from)                 FROM_H="${2:-}";            shift 2 ;;
    --to)                   TO_H="${2:-}";              shift 2 ;;
    --topic)                TOPIC="${2:-}";             shift 2 ;;
    --prefix)               PREFIX="${2:-}";            shift 2 ;;
    --steady-band)          STEADY_BAND="${2:-}";       shift 2 ;;
    --surge-factor)         SURGE_FACTOR="${2:-}";      shift 2 ;;
    --collapse-min-first)   COLLAPSE_MIN_FIRST="${2:-}"; shift 2 ;;
    --surge-min-second)     SURGE_MIN_SECOND="${2:-}";  shift 2 ;;
    --top-N|--top-n)        TOP_N="${2:-}";             shift 2 ;;
    --json)                 JSON_OUT=1;                 shift ;;
    --anomalies-only)       ANOM_ONLY=1;                shift ;;
    *) echo "operator_dapp_activity_trajectory: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port required (sibling operator convention; never guesses a port
# on a multi-instance host).
if [ -z "$PORT" ]; then
  echo "operator_dapp_activity_trajectory: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_activity_trajectory: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Unsigned-integer guards for the block-window bounds.
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_activity_trajectory: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

# Unsigned-integer guards for the count thresholds.
for pair in "collapse-min-first:$COLLAPSE_MIN_FIRST" \
            "surge-min-second:$SURGE_MIN_SECOND" \
            "top-N:$TOP_N"; do
  name="${pair%%:*}"; val="${pair#*:}"
  case "$val" in *[!0-9]*|"")
    echo "operator_dapp_activity_trajectory: --$name must be a non-negative integer (got '$val')" >&2
    exit 1 ;;
  esac
done
if [ "$TOP_N" -lt 1 ]; then
  echo "operator_dapp_activity_trajectory: --top-N must be >= 1 (got '$TOP_N')" >&2
  exit 1
fi

# Non-negative decimal guards for the rate factors (allow integer or
# decimal forms like 0.2, .2, 3, 3.0).
for pair in "steady-band:$STEADY_BAND" "surge-factor:$SURGE_FACTOR"; do
  name="${pair%%:*}"; val="${pair#*:}"
  case "$val" in
    ''|*[!0-9.]*|*.*.*)
      echo "operator_dapp_activity_trajectory: --$name must be a non-negative decimal (got '$val')" >&2
      exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote $DETERM to an absolute path: some Windows shells mishandle a
# relative argv[0] inside the python subprocess loop (mirrors
# operator_dapp_message_audit.sh / operator_dapp_endpoint_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# Clean SKIP (exit 0) when the daemon is unreachable: a not-yet-running
# daemon is an operational state, not an audit failure, so a monitoring
# cron can schedule this unconditionally.
emit_skip() {
  local reason="$1"
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":true,"reason":"%s","rpc_port":%s}\n' "$reason" "$PORT"
  else
    echo "INFO: operator_dapp_activity_trajectory: $reason (port $PORT) — SKIP"
  fi
  exit 0
}

# ── Step 1: resolve chain tip ─────────────────────────────────────────────────
HEAD_H=$("$DETERM_ABS" head --field height --rpc-port "$PORT" 2>/dev/null) || \
  emit_skip "daemon unreachable"
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
if [ -z "$HEAD_H" ]; then
  emit_skip "daemon returned empty height"
fi
case "$HEAD_H" in *[!0-9]*)
  echo "operator_dapp_activity_trajectory: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# head --field height prints the chain HEIGHT (block count); the tip
# block INDEX is height-1 (genesis = index 0).
if [ "$HEAD_H" -lt 1 ]; then
  emit_skip "empty chain (height=$HEAD_H)"
fi
TIP=$(( HEAD_H - 1 ))

# Default window: last 5000 block indices ending at the tip.
if [ -z "$FROM_H" ]; then
  if [ "$TIP" -ge 5000 ]; then
    FROM=$(( TIP - 4999 ))
  else
    FROM=0
  fi
else
  FROM="$FROM_H"
fi
TO=${TO_H:-$TIP}
if [ "$TO" -gt "$TIP" ]; then TO=$TIP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_activity_trajectory: --from ($FROM) > --to ($TO); empty window" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))
if [ "$WIN_BLOCKS" -lt 2 ]; then
  # A single block can't be split into two halves — clean SKIP so this is
  # safe to run against a freshly-bootstrapped node.
  emit_skip "window too short (blocks=$WIN_BLOCKS); need >= 2 for a half-split"
fi

# ── Step 2: enumerate DApps via dapp-list (optional server-side prefix) ───────
DAPP_LIST_ARGS=("dapp-list" "--rpc-port" "$PORT")
[ -n "$PREFIX" ] && DAPP_LIST_ARGS+=("--prefix" "$PREFIX")
LIST_OUT=$("$DETERM_ABS" "${DAPP_LIST_ARGS[@]}" 2>/dev/null) || {
  echo "operator_dapp_activity_trajectory: dapp-list RPC failed (port $PORT)" >&2
  exit 1
}

TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_activity_trajectory: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_activity_trajectory: cannot create temp file" >&2
  rm -f "$TMP_LIST" 2>/dev/null
  exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" 2>/dev/null' EXIT
printf '%s' "$LIST_OUT" > "$TMP_LIST"

# ── Step 3: per-DApp half-over-half count + classification (Python) ───────────
python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TOPIC" \
         "$STEADY_BAND" "$SURGE_FACTOR" "$COLLAPSE_MIN_FIRST" \
         "$SURGE_MIN_SECOND" "$TMP_LIST" "$TMP_OUT" <<'PY'
import json, subprocess, sys

(determ, port, from_s, to_s, topic,
 steady_s, surge_s, collapse_first_s, surge_second_s,
 list_path, out_path) = sys.argv[1:12]

from_h          = int(from_s)
to_h            = int(to_s)            # inclusive tip of the window
steady_band     = float(steady_s)
surge_factor    = float(surge_s)
collapse_first  = int(collapse_first_s)
surge_second    = int(surge_second_s)

# Half-split: FIRST = [from_h, mid-1], SECOND = [mid, to_h].
win_len = to_h - from_h + 1
mid     = from_h + (win_len // 2)        # first SECOND-half index
b1      = mid - from_h                    # FIRST-half block span (>= 1)
b2      = to_h - mid + 1                  # SECOND-half block span (>= 1)

# Server dapp_messages window is HALF-OPEN [from_height, to_height); to
# count an inclusive index range [lo, hi] we pass to_height = hi+1.
PAGE_LIMIT = 256   # DAPP_MESSAGES_PAGE_LIMIT (src/node/node.cpp:3083)

def run_rpc(args, what):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    except Exception as e:
        sys.stderr.write(f"operator_dapp_activity_trajectory: {what} exception: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_dapp_activity_trajectory: {what} rc={r.returncode}: "
            f"{r.stderr.strip()}\n")
        sys.exit(1)
    try:
        return json.loads(r.stdout)
    except Exception:
        sys.stderr.write(
            f"operator_dapp_activity_trajectory: {what} non-JSON response\n")
        sys.exit(1)

def count_calls(domain, lo, hi_inclusive):
    """Count DAPP_CALL messages to `domain` over inclusive index
    [lo, hi_inclusive] via paginated dapp-messages. Returns the count."""
    if hi_inclusive < lo:
        return 0
    rpc_to = hi_inclusive + 1            # half-open upper bound
    total  = 0
    page_from = lo
    # Bound the pagination loop: at most ceil(span/PAGE_LIMIT)+4 pages.
    max_pages = max(1, ((hi_inclusive - lo + 1) // PAGE_LIMIT) + 4)
    pages = 0
    while page_from < rpc_to:
        pages += 1
        if pages > max_pages:
            sys.stderr.write(
                "operator_dapp_activity_trajectory: dapp-messages pagination "
                f"exceeded {max_pages} pages for {domain}\n")
            sys.exit(1)
        args = [determ, "dapp-messages",
                "--domain", domain,
                "--from",   str(page_from),
                "--to",     str(rpc_to),
                "--rpc-port", port, "--json"]
        if topic:
            args += ["--topic", topic]
        page = run_rpc(args, f"dapp-messages {domain} from={page_from}")
        if not isinstance(page, dict):
            sys.stderr.write(
                "operator_dapp_activity_trajectory: dapp-messages non-object page\n")
            sys.exit(1)
        evs = page.get("events")
        if not isinstance(evs, list):
            sys.stderr.write(
                "operator_dapp_activity_trajectory: dapp-messages missing .events array\n")
            sys.exit(1)
        total += len(evs)
        truncated = bool(page.get("truncated", False))
        if not truncated:
            break
        try:
            last_scan = int(page.get("last_scanned", page_from))
        except Exception:
            last_scan = page_from
        if last_scan < page_from:
            sys.stderr.write(
                "operator_dapp_activity_trajectory: dapp-messages regressed "
                f"last_scanned ({last_scan} < {page_from})\n")
            sys.exit(1)
        page_from = last_scan + 1
    return total

# ── Load dapp-list ────────────────────────────────────────────────────────────
try:
    with open(list_path, "r", encoding="utf-8") as f:
        listed = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_dapp_activity_trajectory: dapp-list parse failed: {e}\n")
    sys.exit(1)

dapps_listed = listed.get("dapps")
if not isinstance(dapps_listed, list):
    sys.stderr.write(
        "operator_dapp_activity_trajectory: dapp-list missing .dapps array\n")
    sys.exit(1)

domains = []
active_map = {}
for d in dapps_listed:
    if isinstance(d, dict):
        dom = d.get("domain")
        if isinstance(dom, str) and dom:
            domains.append(dom)
            active_map[dom] = bool(d.get("active", False))

def classify(n1, n2):
    r1 = n1 / b1 if b1 > 0 else 0.0
    r2 = n2 / b2 if b2 > 0 else 0.0
    if n1 == 0 and n2 == 0:
        return "DORMANT", r1, r2, None
    if r1 == 0.0:
        # 0 -> positive: ignition counts as RISING; delta undefined (inf).
        return "RISING", r1, r2, None
    delta = (r2 - r1) / r1                # signed fractional change
    if r2 >= r1 * (1.0 + steady_band):
        cls = "RISING"
    elif r2 <= r1 * (1.0 - steady_band):
        cls = "FALLING"
    else:
        cls = "STEADY"
    return cls, r1, r2, delta

rows = []
tot_first = 0
tot_second = 0
cls_counts = {"RISING": 0, "FALLING": 0, "STEADY": 0, "DORMANT": 0}
collapse_offenders = []
surge_offenders = []

for dom in domains:
    n1 = count_calls(dom, from_h, mid - 1)
    n2 = count_calls(dom, mid, to_h)
    tot_first  += n1
    tot_second += n2
    cls, r1, r2, delta = classify(n1, n2)
    cls_counts[cls] += 1

    # Anomaly: collapse — busy early, silent late.
    is_collapse = (n1 >= collapse_first and n2 == 0)
    if is_collapse:
        collapse_offenders.append(dom)
    # Anomaly: surge — runaway ramp with an absolute floor on n2.
    is_surge = (n2 >= surge_second and r2 >= surge_factor * r1 and (r1 > 0.0 or n2 > 0))
    # When r1 == 0 the >= test is trivially true; gate it on the floor only.
    if r1 == 0.0:
        is_surge = (n2 >= surge_second)
    if is_surge:
        surge_offenders.append(dom)

    rows.append({
        "domain":        dom,
        "active":        active_map.get(dom, False),
        "first_calls":   n1,
        "second_calls":  n2,
        "first_rate":    round(r1, 6),
        "second_rate":   round(r2, 6),
        "delta_pct":     (round(delta * 100.0, 2) if delta is not None else None),
        "trajectory":    cls,
        "collapse":      is_collapse,
        "surge":         is_surge,
    })

# Sort: surges first, then collapses, then by total in-window calls desc,
# then domain for determinism.
rows.sort(key=lambda r: (not r["surge"], not r["collapse"],
                         -(r["first_calls"] + r["second_calls"]), r["domain"]))

anomalies = []
if collapse_offenders:
    anomalies.append("dapp_collapse")
if surge_offenders:
    anomalies.append("dapp_surge")

# Window-wide momentum: compare global per-block rate across halves.
gr1 = tot_first / b1 if b1 > 0 else 0.0
gr2 = tot_second / b2 if b2 > 0 else 0.0
if tot_first == 0 and tot_second == 0:
    window_momentum = "IDLE"
elif gr1 == 0.0:
    window_momentum = "RISING"
elif gr2 >= gr1 * (1.0 + steady_band):
    window_momentum = "RISING"
elif gr2 <= gr1 * (1.0 - steady_band):
    window_momentum = "FALLING"
else:
    window_momentum = "STEADY"

summary = {
    "rpc_port":           int(port),
    "from":               from_h,
    "to":                 to_h,
    "mid":                mid,
    "first_half_blocks":  b1,
    "second_half_blocks": b2,
    "dapps_total":        len(domains),
    "first_half_calls":   tot_first,
    "second_half_calls":  tot_second,
    "window_momentum":    window_momentum,
    "steady_band":        steady_band,
    "surge_factor":       surge_factor,
    "collapse_min_first": collapse_first,
    "surge_min_second":   surge_second,
    "trajectory_counts":  cls_counts,
    "collapse_offenders": collapse_offenders,
    "surge_offenders":    surge_offenders,
    "anomalies":          anomalies,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"summary": summary, "rows": rows}, f)
PY

PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  exit 1
fi

# ── Step 4: render ────────────────────────────────────────────────────────────
python - "$TMP_OUT" "$JSON_OUT" "$ANOM_ONLY" "$TOP_N" <<'PY'
import json, sys

out_path, json_out_s, anom_only_s, top_n_s = sys.argv[1:5]
json_out  = (json_out_s == "1")
anom_only = (anom_only_s == "1")
top_n     = int(top_n_s)

try:
    with open(out_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_dapp_activity_trajectory: result parse failed: {e}\n")
    sys.exit(1)

summary = data["summary"]
rows    = data["rows"]
anomalies = summary["anomalies"]
has_anom  = len(anomalies) > 0

if json_out:
    envelope = {
        "skipped":   False,
        "anomalies": anomalies,
        "summary":   summary,
    }
    if not anom_only:
        envelope["dapps"] = rows
    else:
        envelope["dapps"] = [r for r in rows if r["collapse"] or r["surge"]]
    print(json.dumps(envelope))
    sys.exit(2 if (anom_only and has_anom) else 0)

# ── Human output ──────────────────────────────────────────────────────────────
if anom_only:
    if not has_anom:
        print(f"[OK] no DApp trajectory anomalies over [{summary['from']}..{summary['to']}]")
        sys.exit(0)
    print(f"[ANOMALY] DApp trajectory anomalies over [{summary['from']}..{summary['to']}]:")
    if "dapp_surge" in anomalies:
        offs = summary["surge_offenders"]
        print(f"  - dapp_surge: {len(offs)} DApp(s) with second-half rate "
              f">= {summary['surge_factor']}x first-half rate "
              f"(>= {summary['surge_min_second']} second-half calls)")
        for d in offs:
            print(f"      {d}")
    if "dapp_collapse" in anomalies:
        offs = summary["collapse_offenders"]
        print(f"  - dapp_collapse: {len(offs)} DApp(s) busy in first half "
              f"(>= {summary['collapse_min_first']}) then fully silent")
        for d in offs:
            print(f"      {d}")
    sys.exit(2)

print(f"=== DApp activity trajectory (port {summary['rpc_port']}) ===")
print(f"Window: [{summary['from']}..{summary['to']}]  "
      f"(mid={summary['mid']}; first={summary['first_half_blocks']} blk, "
      f"second={summary['second_half_blocks']} blk)")
print(f"DApps: {summary['dapps_total']}   "
      f"calls: first={summary['first_half_calls']}, "
      f"second={summary['second_half_calls']}   "
      f"window momentum: {summary['window_momentum']}")
tc = summary["trajectory_counts"]
print(f"Trajectory mix: RISING={tc['RISING']}  FALLING={tc['FALLING']}  "
      f"STEADY={tc['STEADY']}  DORMANT={tc['DORMANT']}")
print(f"Bands: steady=+/-{int(summary['steady_band']*100)}%  "
      f"surge>={summary['surge_factor']}x  "
      f"collapse-min-first={summary['collapse_min_first']}  "
      f"surge-min-second={summary['surge_min_second']}")
print()

shown = [r for r in rows if not (r["trajectory"] == "DORMANT")][:top_n]
if not shown:
    print("  (no DApp had any in-window DAPP_CALL traffic)")
else:
    hdr = (f"  {'domain':<28} {'traj':<8} {'1st':>6} {'2nd':>6} "
           f"{'r1/blk':>9} {'r2/blk':>9} {'delta%':>9}  flags")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in shown:
        dp = "n/a" if r["delta_pct"] is None else f"{r['delta_pct']:+.1f}"
        flags = []
        if r["surge"]:    flags.append("SURGE")
        if r["collapse"]: flags.append("COLLAPSE")
        if not r["active"]: flags.append("inactive")
        dom = r["domain"]
        if len(dom) > 28:
            dom = dom[:25] + "..."
        print(f"  {dom:<28} {r['trajectory']:<8} {r['first_calls']:>6} "
              f"{r['second_calls']:>6} {r['first_rate']:>9.4f} "
              f"{r['second_rate']:>9.4f} {dp:>9}  {','.join(flags)}")
    n_dormant = summary["trajectory_counts"]["DORMANT"]
    if n_dormant:
        print(f"  ... plus {n_dormant} DORMANT DApp(s) (no calls either half)")

print()
if has_anom:
    print(f"[ANOMALY] {', '.join(anomalies)} — see flagged rows above")
else:
    print("[OK] no DApp trajectory anomalies")
sys.exit(0)
PY

exit $?
