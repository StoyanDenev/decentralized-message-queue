#!/usr/bin/env bash
# operator_chain_freshness.sh — Audit per-block "wall-clock age" across a
# recent window of N blocks. Sibling of operator_block_lag_check.sh and
# operator_consensus_latency.sh, but with a different question:
#
#   - operator_block_lag_check.sh : how stale is the HEAD (one block)?
#   - operator_consensus_latency.sh : inter-block deltas (gather→broadcast)
#   - operator_chain_freshness.sh : age of each of the LAST N blocks
#                                   measured from `now`, aggregated as a
#                                   single freshness distribution.
#
# Why "freshness" is the right per-window metric: a head-only check
# misses the case where the chain stalled mid-window and then resumed
# (head looks fresh, but the bulk of the recent window is hours old).
# By measuring age = now - block[i].timestamp for every block in the
# window we surface that hidden tail.
#
# The "oldest still-recent block" — the largest age in the window — is
# the chain's effective stale tail. On a healthy chain it should be
# ~= expected_per_block × window (one block per expected interval). A
# dramatically larger value implies a stall happened recently enough
# that some of the still-recent window predates the freeze.
#
# Block.timestamp is producer-set Unix epoch SECONDS (int64) per
# PROTOCOL.md §4.1; on sub-second profiles (cluster ~50ms, tactical
# ~20ms) most ages still differ by at least 1s because we measure
# against wall-clock `now`, not inter-block. Seconds-granularity is
# fine for this script's purpose.
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# RPC dependencies (all read-only):
#   - head         (current chain height)
#   - block-info   (per-block JSON; via `determ block-info <i> --json`)
#
# Profile expected-seconds-per-block presets (mirror
# include/determ/chain/params.hpp ProfileParams round-timer sums):
#   cluster   ~0.050s/block (50ms)
#   web       ~0.300s/block (300ms)   (default)
#   regional  ~0.600s/block (600ms)
#   global    ~2.000s/block (2000ms)
#   tactical  ~0.020s/block (20ms)
# Expected window-seconds = expected_seconds_per_block × window_size.
# We track expected as MILLISECONDS internally to avoid losing
# precision on fast profiles, then round to seconds for output. The
# "expected_window_seconds" headline is the rounded total.
#
# Anomaly classification (each adds an entry to anomalies[]):
#   - slow_p95         p95 block age > 2× expected_window_seconds
#                      (the window's tail is older than it should be)
#   - extreme_age      ANY single block age > 10× expected per-block-age
#                      where "expected per-block-age" approximates the
#                      youngest block (recent) → block[i] (i blocks back)
#                      lower bound. We use 10× expected_window_seconds
#                      as a conservative single-block ceiling; a single
#                      block that old at the tail of an N-block window
#                      means the chain effectively halted N×10 intervals
#                      ago.
#   - mid_window_stall median age much older than min age — operationally
#                      detected when (median - min) > 5× expected_window_seconds.
#                      Indicates the chain finalized only a few blocks
#                      recently then most of the window predates them.
#                      (A normal healthy chain has the min near 0 and
#                       median ~ expected_window_seconds/2.)
#
# Usage:
#   tools/operator_chain_freshness.sh [--rpc-port N]
#                                     [--window N]
#                                     [--profile {cluster|web|regional|global|tactical}]
#                                     [--expected-ms N]
#                                     [--json] [--anomalies-only]
#
# Exit codes:
#   0   success — freshness normal
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   anomaly fired (and --anomalies-only honored downstream)
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_freshness.sh [--rpc-port N] [--window N]
                                   [--profile NAME] [--expected-ms N]
                                   [--json] [--anomalies-only]

Audit per-block wall-clock age over the last N blocks. Computes
age = now - block[i].timestamp for every block in the window and
reports mean/median/p95/max age, plus the oldest-still-recent block
(the chain's stale tail). Compares the aggregate freshness against
the profile's expected window duration and flags anomalies.

Distinct from operator_block_lag_check.sh, which only inspects the
head. A head-only check misses mid-window stalls (the chain froze,
unfroze, but the bulk of the window predates the freeze).

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --window N          Number of recent blocks to audit (default: 100;
                      must be >= 1; clamped to head height if larger)
  --profile NAME      Set the expected per-block timing target:
                        cluster   ~50ms   (head should be very fresh)
                        web      ~300ms   (default)
                        regional ~600ms
                        global  ~2000ms
                        tactical  ~20ms
                      An explicit --expected-ms wins over --profile.
  --expected-ms N     Override expected per-block latency in ms (positive int)
  --json              Emit structured JSON envelope instead of human output
  --anomalies-only    Suppress healthy output; only print anomalies +
                      exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  slow_p95            p95 block age > 2× expected_window_seconds
  extreme_age         at least one block with age > 10× expected_window_seconds
  mid_window_stall    median age - min age > 5× expected_window_seconds
                      (chain finalized a few blocks recently then froze)

Exit codes:
  0   success (no anomaly, or informational mode)
  1   RPC error / bad args
  2   anomaly fired
EOF
}

PORT=7778
WINDOW=100
PROFILE=""
EXPECTED_MS=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="$2";        shift 2 ;;
    --window)         WINDOW="$2";      shift 2 ;;
    --profile)        PROFILE="$2";     shift 2 ;;
    --expected-ms)    EXPECTED_MS="$2"; shift 2 ;;
    --json)           JSON_OUT=1;       shift ;;
    --anomalies-only) ANOM_ONLY=1;      shift ;;
    *) echo "operator_chain_freshness: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Numeric guards ───────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_chain_freshness: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$WINDOW" in *[!0-9]*|"")
  echo "operator_chain_freshness: --window must be a positive integer (got '$WINDOW')" >&2
  exit 1 ;;
esac
if [ "$WINDOW" -lt 1 ]; then
  echo "operator_chain_freshness: --window must be >= 1" >&2
  exit 1
fi
if [ -n "$EXPECTED_MS" ]; then
  case "$EXPECTED_MS" in *[!0-9]*|"")
    echo "operator_chain_freshness: --expected-ms must be a positive integer (got '$EXPECTED_MS')" >&2
    exit 1 ;;
  esac
  if [ "$EXPECTED_MS" -le 0 ]; then
    echo "operator_chain_freshness: --expected-ms must be > 0" >&2
    exit 1
  fi
fi

# Resolve expected_ms: explicit --expected-ms wins; otherwise --profile
# preset; otherwise the 300ms web default. Profile values mirror
# include/determ/chain/params.hpp ProfileParams round-timer sums.
if [ -z "$EXPECTED_MS" ]; then
  case "$PROFILE" in
    cluster)  EXPECTED_MS=50 ;;
    web)      EXPECTED_MS=300 ;;
    regional) EXPECTED_MS=600 ;;
    global)   EXPECTED_MS=2000 ;;
    tactical) EXPECTED_MS=20 ;;
    "")       EXPECTED_MS=300; PROFILE="web" ;;
    *)
      echo "operator_chain_freshness: unknown --profile '$PROFILE' (expected: cluster|web|regional|global|tactical)" >&2
      exit 1 ;;
  esac
fi
# If --expected-ms was given without --profile, label as "custom" for
# output clarity.
if [ -z "$PROFILE" ]; then PROFILE="custom"; fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ──────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_chain_freshness: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_chain_freshness: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac
if [ "$HEAD_H" -lt 1 ]; then
  echo "operator_chain_freshness: chain empty (height=0); nothing to audit" >&2
  exit 1
fi
HEAD_INDEX=$(( HEAD_H - 1 ))

# Clamp window to available blocks. With WINDOW=100 and HEAD_H=42 we
# audit indices [0..41] (42 blocks, the entire chain).
EFFECTIVE_WINDOW=$WINDOW
if [ "$EFFECTIVE_WINDOW" -gt "$HEAD_H" ]; then
  EFFECTIVE_WINDOW=$HEAD_H
fi
FROM=$(( HEAD_INDEX - EFFECTIVE_WINDOW + 1 ))
TO=$HEAD_INDEX

# Expected window duration: per-block-ms × window, then we render in
# seconds in the output. Use ms internally to preserve precision on
# fast profiles (cluster=50ms × 100 = 5000ms = 5s).
EXPECTED_WINDOW_MS=$(( EXPECTED_MS * EFFECTIVE_WINDOW ))
# Round-to-nearest seconds for headline output. (ms+500)/1000 floors
# to the nearest second.
EXPECTED_WINDOW_S=$(( (EXPECTED_WINDOW_MS + 500) / 1000 ))

# ── Step 2: walk the window + collect ages ───────────────────────────────────
# Python driver: handles the RPC fan-out + percentile math. Writes a
# single TSV line of stats to TMP_STATS:
#   mean_s<TAB>median_s<TAB>p95_s<TAB>max_s<TAB>min_s<TAB>now_unix<TAB>
#   oldest_index<TAB>oldest_ts<TAB>extreme_count<TAB>negative_count
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_chain_freshness: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" 2>/dev/null' EXIT

# Single-block extreme threshold = 10× expected_window_seconds. Floor
# at 30s so on extremely fast profiles (tactical/cluster, sub-second
# expected_window) we still need a real spike to trip extreme_age,
# not just routine network jitter.
EXTREME_THRESH_S=$(( EXPECTED_WINDOW_S * 10 ))
if [ "$EXTREME_THRESH_S" -lt 30 ]; then EXTREME_THRESH_S=30; fi

python - "$DETERM" "$PORT" "$FROM" "$TO" "$EXTREME_THRESH_S" "$TMP_STATS" <<'PY' || {
  echo "operator_chain_freshness: block-walk failed" >&2; exit 1;
}
import json
import subprocess
import sys
import time

determ, port, from_h, to_h, extreme_thresh_s, out_path = sys.argv[1:7]
from_h = int(from_h)
to_h = int(to_h)
extreme_thresh_s = int(extreme_thresh_s)

# Capture `now` once, before the RPC fan-out, so every per-block age is
# measured against the same reference instant. (Walking the window can
# take several seconds on slow links; using time.time() inside the loop
# would skew later blocks toward "younger" relative to earlier ones.)
now_unix = int(time.time())

def fetch_block(idx):
    try:
        r = subprocess.run(
            [determ, "block-info", str(idx), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        sys.stderr.write(f"operator_chain_freshness: block-info {idx} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_chain_freshness: block-info {idx} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_chain_freshness: block-info {idx} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        sys.stderr.write(f"operator_chain_freshness: block-info {idx} JSON is not an object\n")
        sys.exit(1)
    ts = blk.get("timestamp")
    if not isinstance(ts, int):
        sys.stderr.write(f"operator_chain_freshness: block-info {idx} missing/invalid timestamp\n")
        sys.exit(1)
    return ts

ages = []
oldest_age = -1
oldest_idx = from_h
oldest_ts = 0
extreme_count = 0
negative_count = 0  # timestamp ahead of `now` (clock skew)

for idx in range(from_h, to_h + 1):
    ts = fetch_block(idx)
    age = now_unix - ts
    if age < 0:
        negative_count += 1
        # Clamp negative ages to 0 for the stats (the distribution
        # should not be perturbed by a clock-skewed producer); the
        # raw negative count is reported separately as a flag.
        age = 0
    ages.append(age)
    if age > oldest_age:
        oldest_age = age
        oldest_idx = idx
        oldest_ts = ts
    if age > extreme_thresh_s:
        extreme_count += 1

# Percentile via sort + index (type-7 quantile, same as numpy/R/excel
# and the sibling operator_consensus_latency.sh / operator_block_size_audit.sh).
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

sorted_a = sorted(ages)
mean_s   = int(round(sum(ages) / len(ages))) if ages else 0
median_s = quantile(sorted_a, 0.50)
p95_s    = quantile(sorted_a, 0.95)
min_s    = sorted_a[0]
max_s    = sorted_a[-1]

with open(out_path, "w", encoding="utf-8") as f:
    f.write(
        f"{mean_s}\t{median_s}\t{p95_s}\t{max_s}\t{min_s}\t{now_unix}\t"
        f"{oldest_idx}\t{oldest_ts}\t{extreme_count}\t{negative_count}\n"
    )
PY
if [ "$?" -ne 0 ]; then
  echo "operator_chain_freshness: block-walk failed" >&2
  exit 1
fi

STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_chain_freshness: empty stats payload" >&2
  exit 1
fi
MEAN_S=$(printf       '%s' "$STATS_LINE" | cut -f1)
MEDIAN_S=$(printf     '%s' "$STATS_LINE" | cut -f2)
P95_S=$(printf        '%s' "$STATS_LINE" | cut -f3)
MAX_S=$(printf        '%s' "$STATS_LINE" | cut -f4)
MIN_S=$(printf        '%s' "$STATS_LINE" | cut -f5)
NOW_UNIX=$(printf     '%s' "$STATS_LINE" | cut -f6)
OLDEST_IDX=$(printf   '%s' "$STATS_LINE" | cut -f7)
OLDEST_TS=$(printf    '%s' "$STATS_LINE" | cut -f8)
EXTREME_CT=$(printf   '%s' "$STATS_LINE" | cut -f9)
NEG_CT=$(printf       '%s' "$STATS_LINE" | cut -f10)

# ── Step 3: anomaly classification ───────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

# slow_p95: p95 > 2× expected_window_seconds. Use ms-precision threshold
# to handle fast profiles where 2×expected might round to 0s.
P95_THRESH_MS=$(( EXPECTED_WINDOW_MS * 2 ))
P95_MS=$(( P95_S * 1000 ))
SLOW_P95="false"
if [ "$P95_MS" -gt "$P95_THRESH_MS" ]; then
  SLOW_P95="true"
  add_anom "slow_p95"
fi

# extreme_age: at least one block.age > 10× expected_window_seconds
# (floored at 30s — see EXTREME_THRESH_S).
EXTREME_AGE="false"
if [ "$EXTREME_CT" -gt 0 ]; then
  EXTREME_AGE="true"
  add_anom "extreme_age"
fi

# mid_window_stall: (median - min) > 5× expected_window_seconds. This
# fires when most of the window is much older than the freshest block,
# i.e. the chain stalled mid-window and only a few recent blocks
# finalized.
STALL_GAP_S=$(( MEDIAN_S - MIN_S ))
STALL_THRESH_MS=$(( EXPECTED_WINDOW_MS * 5 ))
STALL_GAP_MS=$(( STALL_GAP_S * 1000 ))
MID_STALL="false"
if [ "$STALL_GAP_MS" -gt "$STALL_THRESH_MS" ]; then
  MID_STALL="true"
  add_anom "mid_window_stall"
fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 4: emit output ──────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":%s,"effective_window":%s,"from_index":%s,"to_index":%s,' \
    "$WINDOW" "$EFFECTIVE_WINDOW" "$FROM" "$TO"
  printf '"profile":"%s","expected_ms":%s,"expected_window_seconds":%s,' \
    "$PROFILE" "$EXPECTED_MS" "$EXPECTED_WINDOW_S"
  printf '"age_stats":{"mean":%s,"median":%s,"p95":%s,"max":%s,"min":%s},' \
    "$MEAN_S" "$MEDIAN_S" "$P95_S" "$MAX_S" "$MIN_S"
  printf '"now_unix":%s,' "$NOW_UNIX"
  printf '"oldest_block":{"index":%s,"timestamp":%s,"age_seconds":%s},' \
    "$OLDEST_IDX" "$OLDEST_TS" "$MAX_S"
  printf '"extreme_count":%s,"negative_count":%s,' "$EXTREME_CT" "$NEG_CT"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_chain_freshness: no anomalies (port $PORT, window=$EFFECTIVE_WINDOW, profile=$PROFILE)"
  else
    echo "=== Chain freshness (port $PORT, last $EFFECTIVE_WINDOW blocks, profile=$PROFILE) ==="
    if [ "$ANOM_ONLY" != "1" ]; then
      echo "Window: indices [$FROM..$TO]"
      printf "Block age stats: mean %ss, median %ss, p95 %ss, max %ss\n" \
        "$MEAN_S" "$MEDIAN_S" "$P95_S" "$MAX_S"
      printf "Profile expected: %sms/block * %s = %ss window\n" \
        "$EXPECTED_MS" "$EFFECTIVE_WINDOW" "$EXPECTED_WINDOW_S"
      printf "Oldest still-recent block: index=%s age=%ss\n" \
        "$OLDEST_IDX" "$MAX_S"
      if [ "$NEG_CT" -gt 0 ]; then
        echo "Note: $NEG_CT block(s) with timestamp ahead of local clock (skew clamped to age=0)"
      fi
    fi
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No staleness anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      if [ "$SLOW_P95" = "true" ]; then
        printf "  slow_p95         : p95=%ss > 2x expected window (%ss)\n" \
          "$P95_S" "$(( EXPECTED_WINDOW_S * 2 ))"
      fi
      if [ "$EXTREME_AGE" = "true" ]; then
        printf "  extreme_age      : %s block(s) with age > %ss (10x expected, floor 30s)\n" \
          "$EXTREME_CT" "$EXTREME_THRESH_S"
      fi
      if [ "$MID_STALL" = "true" ]; then
        printf "  mid_window_stall : median-min=%ss > 5x expected window (%ss) - chain may have stalled mid-window\n" \
          "$STALL_GAP_S" "$(( EXPECTED_WINDOW_S * 5 ))"
      fi
    fi
  fi
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# Convention matches operator_consensus_latency.sh: anomalies fire exit 2
# regardless of --anomalies-only (the flag only suppresses healthy
# output). RPC errors above already exited 1.
if [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
