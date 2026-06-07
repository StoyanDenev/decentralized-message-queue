#!/usr/bin/env bash
# operator_escalation_episodes.sh — BFT-mode escalation EPISODE-structure
# audit over a window of finalized blocks. Treats the per-block
# consensus_mode field as a time series and segments it into contiguous
# runs of BFT-mode blocks ("episodes"), then reports how OFTEN the
# cluster escalates and how LONG each escalation lasts.
#
# Operator concern this fills:
#   The sibling tools already report BFT-mode prevalence as a *static
#   ratio* (bft_mode_blocks / total) or assert per-block escalation
#   *legality*. None of them describe the TEMPORAL structure. But to an
#   operator, "12% of blocks were BFT-mode" reads completely differently
#   depending on the episode shape:
#     * ONE 120-block run            → a sustained consensus outage /
#                                       stuck escalation (page someone).
#     * SIXTY isolated 1-block runs  → chronic borderline-quorum FLAPPING
#                                       (a member is intermittently slow;
#                                       the cluster keeps tipping into the
#                                       BFT fallback and recovering).
#   Same ratio, opposite root cause + opposite remediation. This tool
#   makes that distinction first-class: episode COUNT, run-length
#   distribution (max / mean / median / p95), the single longest stuck
#   episode (with its block range), and an escalation-rate-per-1000-blocks
#   figure operators can trend over time.
#
# Sibling tools and how this one differs:
#   operator_signature_audit.sh
#       Window-wide SIG-FILL ratios + a static k_mode/bft_mode bucket
#       COUNT + a bft_mode_dominant >50% ratio anomaly. Counts BFT blocks
#       but never segments them into runs — it cannot tell one long stall
#       from many short flaps.
#   operator_escalation_consistency.sh
#       Per-block escalation LEGALITY (invariants I1..I5: illegal BFT
#       under bft_enabled=false, wrong committee size, missing proposer,
#       sub-quorum sigs). Asks "is each mode field self-consistent?", not
#       "how is escalation distributed in TIME?".
#   operator_block_inclusion_audit.sh
#       Per-validator participation + bft_proposer CONCENTRATION. A
#       per-actor lens, not a per-episode lens.
#   operator_consensus_latency.sh
#       Inter-block wall-clock deltas (timing). Orthogonal axis: it sees
#       slow finalization but is blind to the consensus_mode field.
#   operator_escalation_episodes.sh  (THIS)
#       Segments consensus_mode into contiguous BFT runs and reports the
#       EPISODE structure: count, run-length stats, longest episode +
#       range, escalation rate /1000 blocks, flapping vs stuck classifier,
#       and (optionally) wall-clock dwell time per episode from block
#       timestamps.
#
# Data source (read-only RPC only):
#   `determ status`            — once, to resolve chain height (the next
#                                index to produce; highest finalized index
#                                is height-1). Falls back to `determ head
#                                --field height` if status lacks height.
#   `determ block-info <h> --json` — per block. We read two fields:
#       consensus_mode   uint8 enum (block.cpp emits it as an int; per
#                        ConsensusMode in block.hpp MUTUAL_DISTRUST=0,
#                        BFT=1). Any non-zero value is treated as BFT
#                        (escalated). Genesis block 0 carries
#                        MUTUAL_DISTRUST and never counts as escalated.
#       timestamp        int64 Unix epoch SECONDS (block.cpp line ~371).
#                        Used only for the optional per-episode wall-clock
#                        dwell figure; not required for the run-length
#                        math, which is purely block-count based.
#
# Episode definition:
#   An "episode" is a maximal contiguous run of blocks (in chain index
#   order) whose consensus_mode is BFT. Its LENGTH is the block count of
#   that run. A transition is the boundary where mode flips MD→BFT
#   (escalation) or BFT→MD (recovery). The episode count equals the number
#   of MD→BFT transitions observed within the window (a window that opens
#   already inside a BFT run counts that leading run as one episode whose
#   true start may predate --from; this is noted in the output as a
#   left-censored episode).
#
# Anomalies (each gates exit 2 under --anomalies-only; any one also makes
# default mode exit 2 so a monitoring wrapper can alert without the flag):
#   stuck_escalation     the longest episode is >= --stuck-len blocks
#                        (default 20). One long unbroken BFT run is a
#                        sustained consensus degradation, not noise.
#   flapping_escalation  episode_count >= --flap-count (default 8) AND the
#                        mean episode length is < 2.0 blocks. Many short
#                        runs == the cluster is repeatedly tipping into and
#                        out of the fallback (borderline quorum / one slow
#                        member).
#   high_escalation_rate escalation episodes per 1000 blocks exceeds
#                        --rate-per-1k (default 50). Trend signal: how
#                        often does this cluster need the fallback at all?
#
# Args:
#   --rpc-port N         RPC port to query (default: 7778)
#   --from H             Lower window bound, inclusive (default: head-999)
#   --to H               Upper window bound, inclusive (default: head)
#   --last N             Shorthand for [head-N+1, head] (exclusive with
#                        --from/--to)
#   --stuck-len N        stuck_escalation threshold in blocks (default 20)
#   --flap-count N       flapping_escalation episode-count threshold
#                        (default 8)
#   --rate-per-1k N      high_escalation_rate threshold, episodes per 1000
#                        blocks (default 50)
#   --json               Emit structured JSON envelope
#   --anomalies-only     Print only when >=1 anomaly fires; exit 2 then
#   -h, --help           Show this help
#
# Exit codes:
#   0   audit ran; no anomalies (or --anomalies-only with none)
#   1   bad args / RPC error / daemon unreachable / malformed response
#   2   >=1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_escalation_episodes.sh [--rpc-port N]
                                       [--from H] [--to H] [--last N]
                                       [--stuck-len N] [--flap-count N]
                                       [--rate-per-1k N]
                                       [--json] [--anomalies-only]

Segment the per-block consensus_mode field over a window of finalized
blocks into contiguous BFT-mode runs ("episodes") and report the TEMPORAL
structure of escalation: how often the cluster escalates and how long
each escalation lasts. Distinguishes one long stuck escalation from many
short flaps — same BFT-block ratio, opposite root cause.

Reads only `determ status` (once, for chain height) and
`determ block-info <h> --json` (per block: consensus_mode + timestamp).
Read-only; safe against any running daemon.

Episode = maximal contiguous run of BFT-mode blocks. consensus_mode is
the uint8 enum (MUTUAL_DISTRUST=0, BFT=1 per block.hpp); any non-zero is
treated as escalated. An episode already in progress at --from is
left-censored (its true start may predate the window) and labelled so.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --from H             Lower window bound, inclusive (default: head-999)
  --to H               Upper window bound, inclusive (default: head)
  --last N             Shorthand for [head-N+1, head] (exclusive with
                       --from/--to)
  --stuck-len N        stuck_escalation threshold in blocks (default: 20)
  --flap-count N       flapping_escalation episode-count threshold
                       (default: 8)
  --rate-per-1k N      high_escalation_rate threshold, episodes per 1000
                       blocks (default: 50)
  --json               Emit structured JSON envelope instead of human table
  --anomalies-only     Suppress healthy output; only print anomalies +
                       exit 2 if any fire
  -h, --help           Show this help

Anomalies:
  stuck_escalation     longest episode >= --stuck-len blocks
  flapping_escalation  episode_count >= --flap-count AND mean length < 2.0
  high_escalation_rate episodes per 1000 blocks > --rate-per-1k

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W},
   "bft_blocks": B, "md_blocks": M, "bft_block_ratio": R,
   "episode_count": E, "left_censored": bool,
   "lengths": {"max": .., "mean": .., "median": .., "p95": .., "min": ..},
   "longest_episode": {"start": H, "end": H, "length": L,
                       "wall_clock_seconds": S|null},
   "escalation_rate_per_1k": RATE,
   "episodes": [{"start": H, "end": H, "length": L,
                 "wall_clock_seconds": S|null, "left_censored": bool}, ...],
   "anomalies": [...],
   "rpc_port": P, "head_height": HH}

Exit codes:
  0   success, no anomalies (or --anomalies-only with none)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   >=1 anomaly fired (operator alert gate)
EOF
}

PORT=7778
FROM=""
TO=""
LAST=""
STUCK_LEN=20
FLAP_COUNT=8
RATE_PER_1K=50
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";        shift 2 ;;
    --from)           FROM="${2:-}";        shift 2 ;;
    --to)             TO="${2:-}";          shift 2 ;;
    --last)           LAST="${2:-}";        shift 2 ;;
    --stuck-len)      STUCK_LEN="${2:-}";   shift 2 ;;
    --flap-count)     FLAP_COUNT="${2:-}";  shift 2 ;;
    --rate-per-1k)    RATE_PER_1K="${2:-}"; shift 2 ;;
    --json)           JSON_OUT=1;           shift ;;
    --anomalies-only) ANOM_ONLY=1;          shift ;;
    *) echo "operator_escalation_episodes: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Numeric guards ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_escalation_episodes: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_escalation_episodes: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_escalation_episodes: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_escalation_episodes: --last must be >= 1" >&2
  exit 1
fi
for pair in "stuck-len $STUCK_LEN" "flap-count $FLAP_COUNT" "rate-per-1k $RATE_PER_1K"; do
  name="${pair%% *}"; val="${pair#* }"
  case "$val" in *[!0-9]*|"")
    echo "operator_escalation_episodes: --${name} threshold must be a positive integer (got '$val')" >&2
    exit 1 ;;
  esac
  if [ "$val" -le 0 ]; then
    echo "operator_escalation_episodes: --${name} threshold must be > 0" >&2
    exit 1
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python resolves
# it regardless of cwd (matches operator_escalation_consistency.sh /
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
# --field height`. Either way an unreachable daemon yields a clean SKIP
# (exit 0) so a monitoring wrapper that runs this against a node that
# happens to be down for maintenance doesn't page — distinguishing
# "daemon down" (informational) from "daemon up but malformed" (error).
STATUS_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null)
if [ -z "$STATUS_JSON" ]; then
  echo "operator_escalation_episodes: [SKIP] daemon unreachable on rpc-port $PORT (no status response)"
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
# Fall back to head --field height if status didn't carry a usable height.
if [ -z "$HEIGHT" ]; then
  HEIGHT=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null || echo "")
fi
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_escalation_episodes: malformed status/head response (height='$HEIGHT', port $PORT)" >&2
  exit 1 ;;
esac
if [ "$HEIGHT" = "0" ]; then
  echo "operator_escalation_episodes: chain is empty (height=0); nothing to audit" >&2
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
  echo "operator_escalation_episodes: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk + episode segmentation (Python driver) ─────────────
# The Python driver fans out one block-info RPC per block, segments the
# consensus_mode series into contiguous BFT runs, computes run-length
# statistics + per-episode wall-clock dwell, classifies anomalies, and
# writes the full JSON envelope to a temp file. Bash reads it back for
# rendering + the exit-code decision.
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_escalation_episodes: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" \
         "$STUCK_LEN" "$FLAP_COUNT" "$RATE_PER_1K" "$HEIGHT" <<'PY'
import json, subprocess, sys

(determ, port, from_h, to_h, out_path,
 stuck_len, flap_count, rate_per_1k, height) = sys.argv[1:10]
from_h, to_h   = int(from_h), int(to_h)
stuck_len      = int(stuck_len)
flap_count     = int(flap_count)
rate_per_1k    = int(rate_per_1k)
head_height    = int(height)

def fetch_block(h):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        sys.stderr.write(f"operator_escalation_episodes: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_escalation_episodes: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_escalation_episodes: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        sys.stderr.write(f"operator_escalation_episodes: block-info {h} not a JSON object\n")
        sys.exit(1)
    return blk

# ── Walk the window; build the consensus_mode time series + timestamps ─────────
# is_bft[i] for index from_h+i; ts[i] is that block's Unix-epoch-seconds
# timestamp (for wall-clock dwell). consensus_mode is the uint8 enum:
# MUTUAL_DISTRUST=0, BFT=1 (block.hpp). Any non-zero == escalated.
series = []   # list of (height, is_bft, timestamp)
for h in range(from_h, to_h + 1):
    blk = fetch_block(h)
    mode = blk.get("consensus_mode", 0)
    try:
        mode = int(mode)
    except Exception:
        mode = 0
    is_bft = (mode != 0)
    ts = blk.get("timestamp", None)
    try:
        ts = int(ts) if ts is not None else None
    except Exception:
        ts = None
    series.append((h, is_bft, ts))

bft_blocks = sum(1 for (_, b, _) in series if b)
md_blocks  = len(series) - bft_blocks

# ── Segment into contiguous BFT episodes ───────────────────────────────────────
# An episode is a maximal run of consecutive is_bft=True blocks. We also
# flag the FIRST episode as left-censored if it begins exactly at the
# window's first index (its true start may predate --from).
episodes = []
i = 0
n = len(series)
while i < n:
    h, b, ts = series[i]
    if not b:
        i += 1
        continue
    start_idx = i
    while i < n and series[i][1]:
        i += 1
    end_idx = i - 1   # inclusive
    start_h = series[start_idx][0]
    end_h   = series[end_idx][0]
    length  = end_idx - start_idx + 1
    # Wall-clock dwell: span from the first escalated block's timestamp to
    # the timestamp of the first NON-escalated block AFTER the run (the
    # recovery block) if available, else to the last escalated block's own
    # timestamp. This approximates "time spent escalated". None if any
    # needed timestamp is missing or non-monotonic.
    wall = None
    start_ts = series[start_idx][2]
    # recovery block is at end_idx+1 if it exists and is non-escalated
    rec_ts = None
    if end_idx + 1 < n:
        rec_ts = series[end_idx + 1][2]
    end_ts = series[end_idx][2]
    if start_ts is not None and rec_ts is not None and rec_ts >= start_ts:
        wall = rec_ts - start_ts
    elif start_ts is not None and end_ts is not None and end_ts >= start_ts:
        wall = end_ts - start_ts
    left_censored = (start_idx == 0)
    episodes.append({
        "start":              start_h,
        "end":                end_h,
        "length":             length,
        "wall_clock_seconds": wall,
        "left_censored":      left_censored,
    })

episode_count = len(episodes)
any_left_censored = any(e["left_censored"] for e in episodes)

# ── Run-length statistics ──────────────────────────────────────────────────────
def quantile(sorted_xs, q):
    if not sorted_xs:
        return 0
    if len(sorted_xs) == 1:
        return sorted_xs[0]
    pos = q * (len(sorted_xs) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_xs) - 1)
    frac = pos - lo
    return int(round(sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * frac))

lengths = sorted(e["length"] for e in episodes)
if lengths:
    len_max    = lengths[-1]
    len_min    = lengths[0]
    len_mean   = round(sum(lengths) / len(lengths), 2)
    len_median = quantile(lengths, 0.50)
    len_p95    = quantile(lengths, 0.95)
else:
    len_max = len_min = len_median = len_p95 = 0
    len_mean = 0.0

# Longest episode (first one achieving the max length, in chain order).
longest = None
if episodes:
    longest = max(episodes, key=lambda e: e["length"])
    longest = {
        "start":              longest["start"],
        "end":                longest["end"],
        "length":             longest["length"],
        "wall_clock_seconds": longest["wall_clock_seconds"],
    }

# Escalation rate per 1000 blocks (episodes, not blocks — "how often does
# the cluster START needing the fallback per 1000 blocks of operation").
window_n = len(series)
rate_per_1k_val = round((episode_count / window_n) * 1000, 2) if window_n > 0 else 0.0

bft_block_ratio = round(bft_blocks / window_n, 4) if window_n > 0 else 0.0

# ── Anomaly classification ─────────────────────────────────────────────────────
anomalies = []
if episode_count > 0 and len_max >= stuck_len:
    anomalies.append("stuck_escalation")
if episode_count >= flap_count and len_mean < 2.0:
    anomalies.append("flapping_escalation")
if rate_per_1k_val > rate_per_1k:
    anomalies.append("high_escalation_rate")

envelope = {
    "window":     {"from": from_h, "to": to_h, "block_count": window_n},
    "bft_blocks": bft_blocks,
    "md_blocks":  md_blocks,
    "bft_block_ratio": bft_block_ratio,
    "episode_count":   episode_count,
    "left_censored":   any_left_censored,
    "lengths": {
        "max":    len_max,
        "mean":   len_mean,
        "median": len_median,
        "p95":    len_p95,
        "min":    len_min,
    },
    "longest_episode":        longest,
    "escalation_rate_per_1k": rate_per_1k_val,
    "episodes":               episodes,
    "thresholds": {
        "stuck_len":   stuck_len,
        "flap_count":  flap_count,
        "rate_per_1k": rate_per_1k,
    },
    "anomalies":   anomalies,
    "head_height": head_height,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_escalation_episodes: block-walk failed" >&2
  exit 1
fi

# ── Step 3: render envelope ───────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WINDOW" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
from_h    = int(sys.argv[5])
to_h      = int(sys.argv[6])
window    = int(sys.argv[7])

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)
env["rpc_port"] = port

anomalies = env.get("anomalies", []) or []
n_anom    = len(anomalies)

if json_out:
    print(json.dumps(env))
    sys.exit(0)

if anom_only and n_anom == 0:
    print(f"operator_escalation_episodes: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks)")
    sys.exit(0)

LEGEND = {
    "stuck_escalation":
        "longest episode >= --stuck-len blocks (sustained consensus degradation)",
    "flapping_escalation":
        "many short episodes (>= --flap-count) with mean length < 2 (borderline-quorum flapping)",
    "high_escalation_rate":
        "episodes per 1000 blocks > --rate-per-1k (cluster needs the fallback too often)",
}

th         = env.get("thresholds", {}) or {}
lengths    = env.get("lengths", {}) or {}
longest    = env.get("longest_episode")
episodes   = env.get("episodes", []) or []
ec         = env.get("episode_count", 0)
bft_blocks = env.get("bft_blocks", 0)
md_blocks  = env.get("md_blocks", 0)
ratio      = env.get("bft_block_ratio", 0.0)
rate       = env.get("escalation_rate_per_1k", 0.0)
censored   = env.get("left_censored", False)

print(f"=== Escalation episodes (port {port}, window [{from_h}..{to_h}], "
      f"{window} blocks) ===")
print(f"BFT-mode blocks: {bft_blocks}    MD-mode blocks: {md_blocks}    "
      f"BFT-block ratio: {ratio*100:.2f}%")
print(f"Escalation episodes: {ec}    "
      f"rate: {rate} per 1000 blocks")
if censored:
    print("Note: the window opens INSIDE a BFT run (first episode is "
          "left-censored; its true start may predate --from).")
print()

if ec == 0:
    print("No BFT-mode escalation in window — the cluster stayed in "
          "steady-state K-of-K (MUTUAL_DISTRUST) throughout.")
else:
    print("Episode run-length (blocks):")
    print(f"  max:    {lengths.get('max', 0)}")
    print(f"  mean:   {lengths.get('mean', 0)}")
    print(f"  median: {lengths.get('median', 0)}")
    print(f"  p95:    {lengths.get('p95', 0)}")
    print(f"  min:    {lengths.get('min', 0)}")
    if longest:
        wc = longest.get("wall_clock_seconds")
        wc_s = f"{wc}s" if wc is not None else "n/a"
        print(f"Longest episode: blocks [{longest['start']}..{longest['end']}] "
              f"({longest['length']} blocks, wall-clock {wc_s})")
    print()
    # Print up to the 10 longest episodes for operator triage.
    top = sorted(episodes, key=lambda e: (-e["length"], e["start"]))[:10]
    print(f"Top {len(top)} episode(s) by length "
          f"(of {ec} total):")
    print(f"  {'start':>8} {'end':>8} {'len':>5} {'wall_s':>8}  flags")
    print(f"  {'-'*8} {'-'*8} {'-'*5} {'-'*8}  {'-'*12}")
    for e in top:
        wc = e.get("wall_clock_seconds")
        wc_s = str(wc) if wc is not None else "-"
        flags = "left-censored" if e.get("left_censored") else ""
        print(f"  {e['start']:>8} {e['end']:>8} {e['length']:>5} {wc_s:>8}  {flags}")
    print()

if n_anom == 0:
    print(f"[OK] No escalation-episode anomalies "
          f"(stuck>={th.get('stuck_len')}b, flap>={th.get('flap_count')} eps, "
          f"rate>{th.get('rate_per_1k')}/1k)")
else:
    print(f"[ANOMALY] {n_anom} flag(s): {','.join(anomalies)}")
    for a in anomalies:
        print(f"  {a} — {LEGEND.get(a, a)}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_escalation_episodes: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 4: exit-code policy ──────────────────────────────────────────────────
# Convention (matches sibling tools): default informational mode exits 2
# on any anomaly so a monitoring wrapper can alert without the flag;
# --anomalies-only also gates exit 2 only when >=1 anomaly fired.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: env = json.load(f)
print(len(env.get("anomalies") or []))
PY
)
if [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
