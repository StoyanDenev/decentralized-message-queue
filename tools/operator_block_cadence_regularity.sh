#!/usr/bin/env bash
# operator_block_cadence_regularity.sh — Audit block-production cadence
# *regularity* (jitter) across a block window. Walks the chain via
# `determ block-info <i> --json` (Block::to_json emits `index` + an int64
# `timestamp` in Unix epoch SECONDS — see src/chain/block.cpp:369,371;
# producer sets b.timestamp = now_unix() at src/node/producer.cpp:737),
# computes inter-block intervals, and reports how *tightly clustered* the
# cadence is around its expected per-block target.
#
# Why this tool exists (the uncovered gap):
#
# The timing-observability lane already has three tools, and each answers
# a DIFFERENT question:
#   - operator_block_lag_check.sh    : head freshness — now - head.timestamp
#                                      (single point: is the TIP stale?).
#   - operator_chain_freshness.sh    : per-block wall-clock AGE vs now
#                                      (mid-window stall detection).
#   - operator_consensus_latency.sh  : inter-block delta CENTRAL TENDENCY +
#                                      tails (mean/median/p95/p99/min/max) +
#                                      stall / negative-delta / zero-delta
#                                      COUNTS.
#   - operator_chain_invariants_audit.sh : timestamp monotonicity as a
#                                      pass/fail INVARIANT (advisory boolean).
#
# None of them measures cadence *regularity* — the DISPERSION of the
# interval distribution and how consistently the chain hits its target.
# A chain whose p95 is fine can still be jittery (alternating 0s / 2× the
# target), and a chain that is on-target on average can still spend most
# intervals outside an acceptable band. That is the signal an operator
# tuning tx_commit_ms / block_sig_ms cares about, and it is uncovered.
#
# This tool fills it with four regularity signals the others don't compute:
#   (1) Jitter — sample standard deviation of the interval distribution
#       and its coefficient of variation (CV = stddev / mean). CV is the
#       scale-free regularity metric: CV≈0 ⇒ metronomic, CV≥1 ⇒ as much
#       spread as signal.
#   (2) On-cadence coverage — the fraction of intervals that land WITHIN
#       ±tolerance of the expected per-block interval. A high mean with
#       low coverage means "fast on average, but rarely on time."
#   (3) Cadence histogram — every interval bucketed against the expected
#       band: zero (same-second) / under-band / on-band / over-band /
#       stall. Surfaces bimodal cadence (lots of 0s + lots of 2× target)
#       that summary stats alone hide.
#   (4) Monotonicity regressions — a DISTINCT count of intervals where
#       block[i].timestamp < block[i-1].timestamp. The chain layer does
#       NOT enforce inter-block monotonicity (src/main.cpp:1004-1009: no
#       inter-block check; only the validator's ±30s wall-clock window at
#       src/node/validator.cpp:1297-1300), so a regression is a real,
#       unenforced operator concern worth its own line.
#
# Resolution caveat (inherited from the seconds-granularity timestamp):
# Block.timestamp is producer-set Unix epoch SECONDS, so on sub-second
# profiles (cluster ~50ms, tactical ~20ms) most intervals quantize to 0s.
# The jitter math still runs, but CV on a near-all-zero distribution is
# dominated by quantization, not true cadence variance — the output flags
# the "mostly-zero" case so an operator doesn't misread quantization as
# instability. The tool is most informative on profiles whose expected
# interval is >= 1s (regional / global), where intervals span several
# integer-second buckets.
#
# Read-only RPC composition; safe against any running daemon. The daemon
# must already be listening on --rpc-port. If the daemon is unreachable,
# the script prints a clean INFO/SKIP line and exits 0 (it is a no-op,
# not a failure) — so an ops cron can run it before the node is up.
#
# Profile expected-ms presets (mirror include/determ/chain/params.hpp,
# matching operator_consensus_latency.sh / operator_chain_freshness.sh):
#   cluster   ~50ms per block
#   web      ~300ms per block   (default)
#   regional ~600ms per block
#   global  ~2000ms per block
#   tactical  ~20ms per block
#
# Usage:
#   tools/operator_block_cadence_regularity.sh [--rpc-port N]
#                                              [--from H] [--to H]
#                                              [--profile NAME]
#                                              [--expected-ms N]
#                                              [--tolerance-pct P]
#                                              [--max-cv-pct C]
#                                              [--min-coverage-pct M]
#                                              [--json] [--anomalies-only]
#                                              [-h|--help]
#
# Options:
#   --rpc-port N         RPC port to query (default: 7778)
#   --from H             Start of audit window (inclusive). The first
#                        interval is computed at index FROM (block FROM
#                        minus block FROM-1), so sampling begins at
#                        max(FROM,1). Default: max(1, tip-1000).
#   --to H               End of audit window (inclusive; default: tip)
#   --profile NAME       Expected per-block target preset:
#                        cluster|web|regional|global|tactical
#                        (an explicit --expected-ms wins over --profile)
#   --expected-ms N      Override expected per-block interval in ms (>0)
#   --tolerance-pct P    On-cadence band half-width as a percent of the
#                        expected interval (default: 50 ⇒ intervals in
#                        [0.5×expected .. 1.5×expected] count as on-cadence)
#   --max-cv-pct C       Jitter ceiling: flag high_jitter when the interval
#                        coefficient-of-variation exceeds C percent
#                        (default: 100 ⇒ CV > 1.0 is anomalous)
#   --min-coverage-pct M Coverage floor: flag low_cadence_coverage when the
#                        on-cadence fraction is below M percent (default: 60)
#   --json               Emit a structured JSON envelope instead of human
#   --anomalies-only     Print only anomalies; exit 2 if any fire
#   -h, --help           Show this help
#
# RPC dependencies (all read-only):
#   - head        (current chain height; via `determ head --field height`)
#   - block       (per-block JSON; via `determ block-info <i> --json`,
#                  fields used: index, timestamp)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   high_jitter             interval CV (stddev/mean) > --max-cv-pct
#                           (cadence is erratic relative to its own mean)
#   low_cadence_coverage    on-cadence fraction < --min-coverage-pct
#                           (chain rarely lands within tolerance of target)
#   monotonicity_regression >=1 interval where block[i].ts < block[i-1].ts
#                           (unenforced at the chain layer — clock backjump
#                           or out-of-order finalization)
#   stall_present           >=1 interval > max(3000ms, 10×expected_ms)
#                           (matches operator_consensus_latency's stall floor)
#
# Exit codes:
#   0   success (audit ran; no anomalies, informational mode, OR daemon
#       unreachable → clean SKIP)
#   1   bad args / RPC-parse error / empty audit window
#   2   --anomalies-only set AND >=1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_cadence_regularity.sh [--rpc-port N] [--from H] [--to H]
                                            [--profile NAME] [--expected-ms N]
                                            [--tolerance-pct P] [--max-cv-pct C]
                                            [--min-coverage-pct M]
                                            [--json] [--anomalies-only]
                                            [-h|--help]

Audit block-production cadence *regularity* (jitter) over a window.
Walks the window via block-info, computes inter-block intervals from the
producer-set `timestamp` field (Unix epoch SECONDS per src/chain/block.cpp),
and reports interval jitter (stddev + coefficient of variation), on-cadence
coverage (fraction within ±tolerance of expected), a cadence histogram
(zero / under / on / over / stall buckets), and a distinct monotonicity-
regression count. Complements the central-tendency view in
operator_consensus_latency.sh and the head-freshness view in
operator_block_lag_check.sh — this is the dispersion/regularity lane.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --from H             Start of window (inclusive; default: max(1, tip-1000))
  --to H               End of window (inclusive; default: tip)
  --profile NAME       cluster|web|regional|global|tactical (--expected-ms wins)
  --expected-ms N      Override expected per-block interval in ms (>0)
  --tolerance-pct P    On-cadence band half-width, percent of expected (default 50)
  --max-cv-pct C       high_jitter ceiling on interval CV, percent (default 100)
  --min-coverage-pct M low_cadence_coverage floor, percent (default 60)
  --json               Emit structured JSON envelope instead of human table
  --anomalies-only     Print only anomalies; exit 2 if any fire
  -h, --help           Show this help

Anomaly flags:
  high_jitter             interval CV (stddev/mean) > --max-cv-pct
  low_cadence_coverage    on-cadence fraction < --min-coverage-pct
  monotonicity_regression >=1 interval with block[i].ts < block[i-1].ts
  stall_present           >=1 interval > max(3000ms, 10×expected_ms)

Exit codes:
  0   success / informational / daemon-unreachable SKIP
  1   bad args / RPC-parse error / empty window
  2   --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=7778
FROM_H=""
TO_H=""
PROFILE=""
EXPECTED_MS=""
TOLERANCE_PCT=50
MAX_CV_PCT=100
MIN_COVERAGE_PCT=60
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           PORT="${2:-}";             shift 2 ;;
    --from)               FROM_H="${2:-}";           shift 2 ;;
    --to)                 TO_H="${2:-}";             shift 2 ;;
    --profile)            PROFILE="${2:-}";          shift 2 ;;
    --expected-ms)        EXPECTED_MS="${2:-}";      shift 2 ;;
    --tolerance-pct)      TOLERANCE_PCT="${2:-}";    shift 2 ;;
    --max-cv-pct)         MAX_CV_PCT="${2:-}";       shift 2 ;;
    --min-coverage-pct)   MIN_COVERAGE_PCT="${2:-}"; shift 2 ;;
    --json)               JSON_OUT=1;                shift ;;
    --anomalies-only)     ANOM_ONLY=1;               shift ;;
    *) echo "operator_block_cadence_regularity: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Numeric guards on user-supplied values ────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_block_cadence_regularity: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_block_cadence_regularity: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$EXPECTED_MS" ]; then
  case "$EXPECTED_MS" in *[!0-9]*|"")
    echo "operator_block_cadence_regularity: --expected-ms must be a positive integer (got '$EXPECTED_MS')" >&2
    exit 1 ;;
  esac
  if [ "$EXPECTED_MS" -le 0 ]; then
    echo "operator_block_cadence_regularity: --expected-ms must be > 0" >&2
    exit 1
  fi
fi
case "$TOLERANCE_PCT" in *[!0-9]*|"")
  echo "operator_block_cadence_regularity: --tolerance-pct must be a non-negative integer (got '$TOLERANCE_PCT')" >&2
  exit 1 ;;
esac
case "$MAX_CV_PCT" in *[!0-9]*|"")
  echo "operator_block_cadence_regularity: --max-cv-pct must be a non-negative integer (got '$MAX_CV_PCT')" >&2
  exit 1 ;;
esac
case "$MIN_COVERAGE_PCT" in *[!0-9]*|"")
  echo "operator_block_cadence_regularity: --min-coverage-pct must be a non-negative integer (got '$MIN_COVERAGE_PCT')" >&2
  exit 1 ;;
esac
if [ "$MIN_COVERAGE_PCT" -gt 100 ]; then
  echo "operator_block_cadence_regularity: --min-coverage-pct must be <= 100 (got '$MIN_COVERAGE_PCT')" >&2
  exit 1
fi

# Resolve expected_ms: explicit --expected-ms wins; else --profile preset;
# else the 300ms web default. Mirrors operator_consensus_latency.sh.
if [ -z "$EXPECTED_MS" ]; then
  case "$PROFILE" in
    cluster)  EXPECTED_MS=50 ;;
    web)      EXPECTED_MS=300 ;;
    regional) EXPECTED_MS=600 ;;
    global)   EXPECTED_MS=2000 ;;
    tactical) EXPECTED_MS=20 ;;
    "")       EXPECTED_MS=300; PROFILE="web" ;;
    *)
      echo "operator_block_cadence_regularity: unknown --profile '$PROFILE' (expected: cluster|web|regional|global|tactical)" >&2
      exit 1 ;;
  esac
fi
# If --expected-ms was given without --profile, label as "custom".
if [ -z "$PROFILE" ]; then PROFILE="custom"; fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve DETERM to an absolute path so the Python driver's subprocess
# call works on Windows (CreateProcessW does not honor the inherited bash
# cwd the way exec*() does — a relative build/Release/determ.exe resolves
# from a bash command but FileNotFoundError's from python). Same approach
# as operator_block_size_audit.sh.
case "$DETERM" in
  /*|[A-Za-z]:/*|[A-Za-z]:\\*) DETERM_ABS="$DETERM" ;;
  *) DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
esac

# Helper: emit a clean SKIP (daemon unreachable) and exit 0. Per the
# operator-script contract a not-yet-running daemon is a no-op, not an
# error, so a monitoring cron can schedule this unconditionally.
emit_skip() {
  local reason="$1"
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":true,"reason":"%s","rpc_port":%s}\n' "$reason" "$PORT"
  else
    echo "INFO: operator_block_cadence_regularity: $reason (port $PORT) — SKIP"
  fi
  exit 0
}

# ── Step 1: resolve current tip ───────────────────────────────────────────────
# head --field height prints the chain height (number of blocks). The tip
# block index is height-1 (genesis = index 0). Daemon-unreachable → SKIP.
HEAD_H=$("$DETERM_ABS" head --field height --rpc-port "$PORT" 2>/dev/null) || \
  emit_skip "daemon unreachable"
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
if [ -z "$HEAD_H" ]; then
  emit_skip "daemon returned empty height"
fi
case "$HEAD_H" in *[!0-9]*)
  echo "operator_block_cadence_regularity: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac
if [ "$HEAD_H" -lt 2 ]; then
  # Need at least two blocks (one interval). A 0- or 1-block chain has no
  # cadence to measure — clean SKIP rather than a hard error, so this is
  # safe to run against a freshly-bootstrapped node.
  emit_skip "chain too short (height=$HEAD_H); need >= 2 blocks for one interval"
fi
HEAD_INDEX=$(( HEAD_H - 1 ))

# ── Step 2: resolve window ────────────────────────────────────────────────────
# The first interval is computed at index FROM (block FROM minus block
# FROM-1), so sampling begins at max(FROM, 1). Defaults to the last 1000
# blocks ending at the tip.
FROM=${FROM_H:-$(( HEAD_INDEX > 1000 ? HEAD_INDEX - 1000 : 1 ))}
TO=${TO_H:-$HEAD_INDEX}
if [ "$FROM" -lt 1 ]; then FROM=1; fi
if [ "$TO" -gt "$HEAD_INDEX" ]; then TO=$HEAD_INDEX; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_block_cadence_regularity: --from ($FROM) > --to ($TO); empty window, nothing to audit" >&2
  exit 1
fi

# We sample timestamps for indices [FROM-1 .. TO] and compute one interval
# per index in [FROM .. TO].
BLOCK_COUNT=$(( TO - FROM + 2 ))   # distinct indices read
INTERVAL_COUNT=$(( TO - FROM + 1 ))

# Stall threshold = max(3000ms, 10×expected_ms), matching
# operator_consensus_latency.sh so the two tools agree on what a stall is.
STALL_THRESH_MS=$(( EXPECTED_MS * 10 ))
if [ "$STALL_THRESH_MS" -lt 3000 ]; then STALL_THRESH_MS=3000; fi

# ── Step 3: walk the window + compute regularity stats ───────────────────────
# Python driver: RPC fan-out + dispersion math + histogram. Writes a
# single TSV line to TMP_STATS:
#   interval_count <TAB> mean_ms <TAB> stddev_ms <TAB> cv_pct
#   <TAB> min_ms <TAB> max_ms
#   <TAB> on_cadence <TAB> coverage_pct
#   <TAB> bkt_zero <TAB> bkt_under <TAB> bkt_on <TAB> bkt_over <TAB> bkt_stall
#   <TAB> regressions <TAB> stalls <TAB> mostly_zero
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_block_cadence_regularity: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" \
       "$EXPECTED_MS" "$TOLERANCE_PCT" "$STALL_THRESH_MS" "$TMP_STATS" <<'PY'
import json, subprocess, sys

(determ, port, from_h, to_h,
 expected_ms, tol_pct, stall_ms, out_path) = sys.argv[1:9]
from_h      = int(from_h)
to_h        = int(to_h)
expected_ms = int(expected_ms)
tol_pct     = int(tol_pct)
stall_ms    = int(stall_ms)

# On-cadence band, in ms. Half-width = tol_pct% of expected. Lower bound
# floored at 0 (a negative lower bound is meaningless for an interval).
band_half = expected_ms * tol_pct // 100
band_lo   = expected_ms - band_half
if band_lo < 0:
    band_lo = 0
band_hi   = expected_ms + band_half

def fetch_block(idx):
    try:
        r = subprocess.run(
            [determ, "block-info", str(idx), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        sys.stderr.write(f"operator_block_cadence_regularity: block-info {idx} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_block_cadence_regularity: block-info {idx} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_block_cadence_regularity: block-info {idx} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        sys.stderr.write(f"operator_block_cadence_regularity: block-info {idx} JSON is not an object\n")
        sys.exit(1)
    ts = blk.get("timestamp")
    if not isinstance(ts, int):
        sys.stderr.write(f"operator_block_cadence_regularity: block-info {idx} missing/invalid integer timestamp\n")
        sys.exit(1)
    return ts

# Walk [from_h-1 .. to_h]; interval ms = (ts[i]-ts[i-1]) * 1000 (timestamps
# are seconds). Bucket each interval relative to the expected band.
prev_ts = fetch_block(from_h - 1)
intervals_ms = []
bkt_zero = bkt_under = bkt_on = bkt_over = bkt_stall = 0
regressions = 0   # interval < 0  (block[i].ts < block[i-1].ts)
stalls      = 0   # interval > stall threshold
on_cadence  = 0   # interval within [band_lo .. band_hi]

for idx in range(from_h, to_h + 1):
    ts = fetch_block(idx)
    d_ms = (ts - prev_ts) * 1000
    intervals_ms.append(d_ms)
    prev_ts = ts

    if d_ms < 0:
        regressions += 1
        # A negative interval is its own concern; do not also count it in
        # the positive-band histogram. Tally it under "stall"-adjacent? No
        # — keep it out of the on/under/over buckets entirely; it is
        # reported via the regressions count. Skip bucketing.
        continue
    if d_ms > stall_ms:
        stalls += 1
        bkt_stall += 1
        continue
    if d_ms == 0:
        bkt_zero += 1
    elif d_ms < band_lo:
        bkt_under += 1
    elif d_ms <= band_hi:
        bkt_on += 1
    else:
        bkt_over += 1

    if band_lo <= d_ms <= band_hi:
        on_cadence += 1

n = len(intervals_ms)

# Mean / sample standard deviation / coefficient of variation. CV is
# scale-free regularity = stddev/mean, reported in percent. We use the
# population stddev (divide by n) for stability on small windows; with
# n>=2 the difference from sample stddev is negligible for an operator
# signal and avoids a divide-by-(n-1) edge at n==1 (which cannot occur
# here since INTERVAL_COUNT>=1 and the chain has >=2 blocks).
if n > 0:
    mean = sum(intervals_ms) / n
    var = sum((x - mean) ** 2 for x in intervals_ms) / n
    stddev = var ** 0.5
else:
    mean = 0.0
    stddev = 0.0

mean_ms   = int(round(mean))
stddev_ms = int(round(stddev))
# CV in percent. Guard mean<=0 (all-zero or net-negative window): CV is
# undefined, report 0 so downstream integer logic stays well-defined; the
# mostly_zero flag covers the all-zero case for the human reader.
if mean > 0:
    cv_pct = int(round(stddev / mean * 100))
else:
    cv_pct = 0

min_ms = min(intervals_ms) if intervals_ms else 0
max_ms = max(intervals_ms) if intervals_ms else 0

# coverage_pct = on_cadence / interval_count, in percent (integer).
coverage_pct = (on_cadence * 100 // n) if n > 0 else 0

# mostly_zero: >50% of intervals are exactly 0ms. On sub-second profiles
# this is expected (seconds-granularity quantization), and it means the CV
# / coverage numbers reflect quantization rather than true cadence
# variance. Surface it so the operator interprets the jitter correctly.
mostly_zero = 1 if (n > 0 and bkt_zero * 2 > n) else 0

with open(out_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        n, mean_ms, stddev_ms, cv_pct, min_ms, max_ms,
        on_cadence, coverage_pct,
        bkt_zero, bkt_under, bkt_on, bkt_over, bkt_stall,
        regressions, stalls, mostly_zero,
    ]) + "\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_block_cadence_regularity: block-walk failed" >&2
  exit 1
fi

# ── Step 4: read stats back ───────────────────────────────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_block_cadence_regularity: empty stats payload" >&2
  exit 1
fi
N_INTERVALS=$(printf '%s'  "$STATS_LINE" | cut -f1)
MEAN_MS=$(printf '%s'      "$STATS_LINE" | cut -f2)
STDDEV_MS=$(printf '%s'    "$STATS_LINE" | cut -f3)
CV_PCT=$(printf '%s'       "$STATS_LINE" | cut -f4)
MIN_MS=$(printf '%s'       "$STATS_LINE" | cut -f5)
MAX_MS=$(printf '%s'       "$STATS_LINE" | cut -f6)
ON_CADENCE=$(printf '%s'   "$STATS_LINE" | cut -f7)
COVERAGE_PCT=$(printf '%s' "$STATS_LINE" | cut -f8)
BKT_ZERO=$(printf '%s'     "$STATS_LINE" | cut -f9)
BKT_UNDER=$(printf '%s'    "$STATS_LINE" | cut -f10)
BKT_ON=$(printf '%s'       "$STATS_LINE" | cut -f11)
BKT_OVER=$(printf '%s'     "$STATS_LINE" | cut -f12)
BKT_STALL=$(printf '%s'    "$STATS_LINE" | cut -f13)
REGRESSIONS=$(printf '%s'  "$STATS_LINE" | cut -f14)
STALLS=$(printf '%s'       "$STATS_LINE" | cut -f15)
MOSTLY_ZERO=$(printf '%s'  "$STATS_LINE" | cut -f16)

# Derived band bounds (for output clarity; recomputed in shell to avoid a
# second round trip through the Python payload).
BAND_HALF=$(( EXPECTED_MS * TOLERANCE_PCT / 100 ))
BAND_LO=$(( EXPECTED_MS - BAND_HALF )); [ "$BAND_LO" -lt 0 ] && BAND_LO=0
BAND_HI=$(( EXPECTED_MS + BAND_HALF ))

# ── Step 5: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
HIGH_JITTER="false"
# high_jitter: only meaningful when the cadence isn't dominated by
# seconds-quantization (mostly_zero). On a near-all-zero distribution CV
# reflects quantization, not instability — suppress the flag there.
if [ "$MOSTLY_ZERO" != "1" ] && [ "$CV_PCT" -gt "$MAX_CV_PCT" ]; then
  HIGH_JITTER="true"
  add_anom "high_jitter"
fi
LOW_COVERAGE="false"
if [ "$COVERAGE_PCT" -lt "$MIN_COVERAGE_PCT" ]; then
  LOW_COVERAGE="true"
  add_anom "low_cadence_coverage"
fi
if [ "$REGRESSIONS" -gt 0 ]; then add_anom "monotonicity_regression"; fi
if [ "$STALLS" -gt 0 ];      then add_anom "stall_present"; fi
ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 6: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":{"from":%s,"to":%s,"blocks":%s,"intervals":%s},' \
    "$FROM" "$TO" "$BLOCK_COUNT" "$INTERVAL_COUNT"
  printf '"expected_ms":%s,"profile":"%s","tolerance_pct":%s,' \
    "$EXPECTED_MS" "$PROFILE" "$TOLERANCE_PCT"
  printf '"on_cadence_band_ms":{"lo":%s,"hi":%s},' "$BAND_LO" "$BAND_HI"
  printf '"interval_stats":{"count":%s,"mean":%s,"stddev":%s,"cv_pct":%s,"min":%s,"max":%s},' \
    "$N_INTERVALS" "$MEAN_MS" "$STDDEV_MS" "$CV_PCT" "$MIN_MS" "$MAX_MS"
  printf '"on_cadence":%s,"coverage_pct":%s,' "$ON_CADENCE" "$COVERAGE_PCT"
  printf '"histogram":{"zero":%s,"under":%s,"on":%s,"over":%s,"stall":%s},' \
    "$BKT_ZERO" "$BKT_UNDER" "$BKT_ON" "$BKT_OVER" "$BKT_STALL"
  printf '"monotonicity_regressions":%s,"stalls_over_%sms":%s,"mostly_zero":%s,' \
    "$REGRESSIONS" "$STALL_THRESH_MS" "$STALLS" \
    "$( [ "$MOSTLY_ZERO" = "1" ] && echo true || echo false )"
  printf '"max_cv_pct":%s,"min_coverage_pct":%s,' "$MAX_CV_PCT" "$MIN_COVERAGE_PCT"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_block_cadence_regularity: no anomalies (port $PORT, window [$FROM..$TO], profile=$PROFILE)"
  else
    echo "=== Block cadence regularity (port $PORT, window [$FROM..$TO], $INTERVAL_COUNT intervals, profile=$PROFILE, expected=${EXPECTED_MS}ms) ==="
    if [ "$ANOM_ONLY" != "1" ]; then
      echo "Interval distribution (ms):"
      printf "  mean:   %s\n" "$MEAN_MS"
      printf "  stddev: %s\n" "$STDDEV_MS"
      printf "  cv:     %s%% (jitter; stddev/mean)\n" "$CV_PCT"
      printf "  min:    %s\n" "$MIN_MS"
      printf "  max:    %s\n" "$MAX_MS"
      printf "On-cadence band: [%s..%s] ms (±%s%% of expected). Coverage: %s/%s (%s%%)\n" \
        "$BAND_LO" "$BAND_HI" "$TOLERANCE_PCT" "$ON_CADENCE" "$N_INTERVALS" "$COVERAGE_PCT"
      printf "Cadence histogram: zero=%s under=%s on=%s over=%s stall=%s\n" \
        "$BKT_ZERO" "$BKT_UNDER" "$BKT_ON" "$BKT_OVER" "$BKT_STALL"
      printf "Monotonicity regressions: %s   Stalls (> %sms): %s\n" \
        "$REGRESSIONS" "$STALL_THRESH_MS" "$STALLS"
      if [ "$MOSTLY_ZERO" = "1" ]; then
        echo "Note: >50% of intervals are 0ms (seconds-granularity quantization on a"
        echo "      sub-second profile). CV/coverage reflect quantization, not true"
        echo "      cadence variance — high_jitter is suppressed in this regime."
      fi
    fi
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] Cadence regular (cv=${CV_PCT}% <= ${MAX_CV_PCT}%, coverage=${COVERAGE_PCT}% >= ${MIN_COVERAGE_PCT}%, no regressions/stalls)"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      if [ "$HIGH_JITTER" = "true" ]; then
        echo "  high_jitter             : cv=${CV_PCT}% > ${MAX_CV_PCT}% (interval spread exceeds its own mean by the ceiling)"
      fi
      if [ "$LOW_COVERAGE" = "true" ]; then
        echo "  low_cadence_coverage    : ${COVERAGE_PCT}% on-cadence < ${MIN_COVERAGE_PCT}% (chain rarely lands within tolerance of target)"
      fi
      if [ "$REGRESSIONS" -gt 0 ]; then
        echo "  monotonicity_regression : $REGRESSIONS interval(s) with block[i].ts < block[i-1].ts (unenforced at chain layer)"
      fi
      if [ "$STALLS" -gt 0 ]; then
        echo "  stall_present           : $STALLS interval(s) > ${STALL_THRESH_MS}ms (= max(3000ms, 10× expected))"
      fi
    fi
  fi
fi

# ── Step 7: exit-code policy ──────────────────────────────────────────────────
# Convention: exit 2 only when --anomalies-only is set AND >=1 anomaly
# fired. Default informational mode exits 0 if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
