#!/usr/bin/env bash
# operator_consensus_latency.sh — Approximate consensus phase latency by
# sampling block timestamps over a window. Walks the chain via
# `determ block-info <i> --field timestamp` (Block::to_json emits
# `timestamp` as int64 Unix epoch seconds; see src/chain/block.cpp line
# 371), computes inter-block deltas (block[i].timestamp - block[i-1].timestamp),
# and aggregates mean / median / p95 / p99 / min / max in milliseconds.
#
# Inter-block delta == wall-clock between two consecutively finalized
# blocks; it is the observable end-to-end consensus latency (Phase 1
# gather + Phase 2 randomized delay + Phase 3 broadcast + propagation
# + apply). It is NOT the producer's local consensus-phase wall-clock
# alone — clock skew between producers shows up here too. Operators
# should read this as "how slow is finalization right now" not "how
# slow is one phase".
#
# Why timestamps are seconds-granularity, not ms: Block.timestamp is a
# producer-set field bound into block_digest and signed by the BFT
# quorum; v1 fixes that to seconds (per PROTOCOL.md §4.1). When
# expected per-block time is < 1s (cluster/tactical/regional profiles),
# the seconds-resolution timestamps mean inter-block deltas will quantize
# to 0s / 1s / 2s — i.e. this script's resolution is coarse on fast
# profiles. We still scale to milliseconds for the output schema so the
# JSON shape stays uniform across profiles; just be aware that on
# cluster (~50ms) most deltas read as 0ms (same-second).
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# Profile expected-ms presets (mirror include/determ/chain/params.hpp):
#   cluster   ~50ms per block
#   web      ~300ms per block   (default)
#   regional ~600ms per block
#   global  ~2000ms per block
#   tactical  ~20ms per block
#
# Anomaly classification:
#   - p95 > 2× expected            (slow consensus path)
#   - any delta > 10× expected     (stall / BFT-mode escalation event)
#   - any delta > 3000ms           (stall, regardless of profile —
#                                   the 3s floor matches operator_block_lag_check)
#   - any delta < 0                (clock skew or out-of-order block)
#   - any delta == 0               (likely duplicate timestamp; on
#                                   profiles with expected_ms > 1000 this
#                                   means truly back-to-back finalization,
#                                   which is rare; on sub-second profiles
#                                   it is the dominant case and NOT flagged)
#
# Usage:
#   tools/operator_consensus_latency.sh [--rpc-port N]
#                                       [--from H --to H]
#                                       [--profile {cluster|web|regional|global|tactical}]
#                                       [--expected-ms N]
#                                       [--json] [--anomalies-only]
#
# Exit codes:
#   0   success — latency normal
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   anomaly fired (p95 > 2× expected, stalls present, negative deltas)
set -u

usage() {
  cat <<'EOF'
Usage: operator_consensus_latency.sh [--rpc-port N] [--from H --to H]
                                     [--profile NAME] [--expected-ms N]
                                     [--json] [--anomalies-only]

Approximate consensus latency by sampling block timestamps over a
window. Computes inter-block deltas in milliseconds (Block.timestamp
is Unix epoch SECONDS per PROTOCOL.md §4.1; we multiply by 1000 for
the output schema so the JSON shape is profile-independent — but
note the underlying resolution is 1s, so sub-second profiles will
see most deltas quantize to 0ms).

Inter-block delta = block[i].timestamp - block[i-1].timestamp; this
is the observable end-to-end consensus latency (gather + randomized
delay + broadcast + apply).

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --from H            Start of audit window (inclusive; default: max(1, tip-1000))
                      Note: index 0 (genesis) cannot be the start of a
                      delta — we always begin sampling at max(FROM, 1).
  --to H              End of audit window (inclusive; default: tip)
  --profile NAME      Set the expected per-block timing target:
                        cluster   ~50ms   (head should be very fresh)
                        web      ~300ms   (default)
                        regional ~600ms
                        global  ~2000ms
                        tactical  ~20ms
                      An explicit --expected-ms wins over --profile.
  --expected-ms N     Override expected per-block latency in ms (positive int)
  --json              Emit structured JSON envelope instead of human table
  --anomalies-only    Suppress healthy output; only print anomalies + exit 2
                      if any fire
  -h, --help          Show this help

Anomaly flags:
  slow_p95            p95 inter-block delta > 2× expected_ms
  stall               at least one inter-block delta > max(3000ms, 10×expected_ms)
  clock_skew          at least one negative inter-block delta
                      (block[i].timestamp < block[i-1].timestamp)

Exit codes:
  0   success (or informational mode with no anomaly)
  1   RPC error / bad args
  2   anomaly fired
EOF
}

PORT=7778
FROM_H=""
TO_H=""
PROFILE=""
EXPECTED_MS=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";        shift 2 ;;
    --from)            FROM_H="$2";      shift 2 ;;
    --to)              TO_H="$2";        shift 2 ;;
    --profile)         PROFILE="$2";     shift 2 ;;
    --expected-ms)     EXPECTED_MS="$2"; shift 2 ;;
    --json)            JSON_OUT=1;       shift ;;
    --anomalies-only)  ANOM_ONLY=1;      shift ;;
    *) echo "operator_consensus_latency: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards. --rpc-port must be > 0; --from / --to may be 0 (genesis)
# but the script promotes a 0 start to 1 (you cannot compute a delta into
# index 0). --expected-ms must be > 0.
case "$PORT" in *[!0-9]*|"")
  echo "operator_consensus_latency: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_consensus_latency: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$EXPECTED_MS" ]; then
  case "$EXPECTED_MS" in *[!0-9]*|"")
    echo "operator_consensus_latency: --expected-ms must be a positive integer (got '$EXPECTED_MS')" >&2
    exit 1 ;;
  esac
  if [ "$EXPECTED_MS" -le 0 ]; then
    echo "operator_consensus_latency: --expected-ms must be > 0" >&2
    exit 1
  fi
fi

# Resolve expected_ms: explicit --expected-ms wins; otherwise --profile
# preset; otherwise the 300ms web default. Profile values mirror
# include/determ/chain/params.hpp ProfileParams::round_p1/p2/p3 sum-ish
# targets (cluster=50ms / web=300ms / regional=600ms / global=2000ms /
# tactical=20ms — these are the per-block targets, not phase splits).
if [ -z "$EXPECTED_MS" ]; then
  case "$PROFILE" in
    cluster)  EXPECTED_MS=50 ;;
    web)      EXPECTED_MS=300 ;;
    regional) EXPECTED_MS=600 ;;
    global)   EXPECTED_MS=2000 ;;
    tactical) EXPECTED_MS=20 ;;
    "")       EXPECTED_MS=300; PROFILE="web" ;;
    *)
      echo "operator_consensus_latency: unknown --profile '$PROFILE' (expected: cluster|web|regional|global|tactical)" >&2
      exit 1 ;;
  esac
fi
# If --expected-ms was given but no --profile, label as "custom" for
# output clarity.
if [ -z "$PROFILE" ]; then PROFILE="custom"; fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_consensus_latency: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_consensus_latency: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac
if [ "$HEAD_H" -lt 2 ]; then
  echo "operator_consensus_latency: chain too short (height=$HEAD_H); need at least 2 blocks for one delta" >&2
  exit 1
fi
HEAD_INDEX=$(( HEAD_H - 1 ))

# Default window: last 1000 blocks ending at tip; floor at 1 (need a
# preceding block at FROM-1 for the first delta).
FROM=${FROM_H:-$(( HEAD_INDEX > 1000 ? HEAD_INDEX - 1000 : 1 ))}
TO=${TO_H:-$HEAD_INDEX}
if [ "$FROM" -lt 1 ]; then FROM=1; fi
if [ "$TO" -gt "$HEAD_INDEX" ]; then TO=$HEAD_INDEX; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_consensus_latency: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi

# The first delta we compute is at index FROM (block FROM minus block
# FROM-1), so we sample timestamps for indices [FROM-1 .. TO].
# block_count == number of blocks scanned (TO - FROM + 2 indices read);
# delta_count == number of inter-block deltas == TO - FROM + 1.
BLOCK_COUNT=$(( TO - FROM + 2 ))
DELTA_COUNT=$(( TO - FROM + 1 ))

# ── Step 2: walk the window + collect timestamps + compute deltas ────────────
# Python driver: handles the RPC fan-out + percentile math. Writes a
# single line summary to TMP_STATS as TSV:
#   mean_ms<TAB>median_ms<TAB>p95_ms<TAB>p99_ms<TAB>min_ms<TAB>max_ms<TAB>
#   stalls_count<TAB>negative_count<TAB>zero_count
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_consensus_latency: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" 2>/dev/null' EXIT

# Stall threshold = max(3000ms, 10×expected_ms). The 3000ms floor matches
# operator_block_lag_check's lower bound (anything > 3s is a stall on
# any profile).
STALL_THRESH_MS=$(( EXPECTED_MS * 10 ))
if [ "$STALL_THRESH_MS" -lt 3000 ]; then STALL_THRESH_MS=3000; fi

python - "$DETERM" "$PORT" "$FROM" "$TO" "$STALL_THRESH_MS" "$TMP_STATS" <<'PY' || {
  echo "operator_consensus_latency: block-walk failed" >&2; exit 1;
}
import subprocess, sys

determ, port, from_h, to_h, stall_ms, out_path = sys.argv[1:7]
from_h = int(from_h); to_h = int(to_h); stall_ms = int(stall_ms)

def fetch_ts(idx):
    try:
        r = subprocess.run(
            [determ, "block-info", str(idx), "--field", "timestamp", "--rpc-port", port],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:
        sys.stderr.write(f"operator_consensus_latency: block-info {idx} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_consensus_latency: block-info {idx} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    s = r.stdout.strip()
    try:
        return int(s)
    except ValueError:
        sys.stderr.write(f"operator_consensus_latency: block-info {idx} returned non-int timestamp '{s}'\n")
        sys.exit(1)

# Walk indices [from_h-1 .. to_h] and compute deltas. We sample one
# timestamp at a time (no batched RPC available); deltas are
# ts[i] - ts[i-1] in seconds → multiply by 1000 for the ms schema.
prev_ts = fetch_ts(from_h - 1)
deltas_ms = []
stalls = 0
negatives = 0
zeros = 0
for idx in range(from_h, to_h + 1):
    ts = fetch_ts(idx)
    delta_s = ts - prev_ts
    delta_ms = delta_s * 1000
    deltas_ms.append(delta_ms)
    if delta_ms > stall_ms: stalls += 1
    if delta_ms < 0:        negatives += 1
    if delta_ms == 0:       zeros += 1
    prev_ts = ts

# Percentile via sort + index (no numpy dep). Definition: linear
# interpolation between order statistics (the "type-7" quantile common
# in numpy/R/excel), so p95 of [0..99] = 94.05.
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

sorted_d = sorted(deltas_ms)
mean_ms   = int(round(sum(deltas_ms) / len(deltas_ms))) if deltas_ms else 0
median_ms = quantile(sorted_d, 0.50)
p95_ms    = quantile(sorted_d, 0.95)
p99_ms    = quantile(sorted_d, 0.99)
min_ms    = sorted_d[0]
max_ms    = sorted_d[-1]

with open(out_path, "w", encoding="utf-8") as f:
    f.write(f"{mean_ms}\t{median_ms}\t{p95_ms}\t{p99_ms}\t{min_ms}\t{max_ms}\t{stalls}\t{negatives}\t{zeros}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_consensus_latency: block-walk failed" >&2
  exit 1
fi

STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_consensus_latency: empty stats payload" >&2
  exit 1
fi
MEAN_MS=$(printf '%s' "$STATS_LINE"   | cut -f1)
MEDIAN_MS=$(printf '%s' "$STATS_LINE" | cut -f2)
P95_MS=$(printf '%s' "$STATS_LINE"    | cut -f3)
P99_MS=$(printf '%s' "$STATS_LINE"    | cut -f4)
MIN_MS=$(printf '%s' "$STATS_LINE"    | cut -f5)
MAX_MS=$(printf '%s' "$STATS_LINE"    | cut -f6)
STALLS=$(printf '%s' "$STATS_LINE"    | cut -f7)
NEGATIVES=$(printf '%s' "$STATS_LINE" | cut -f8)
ZEROS=$(printf '%s' "$STATS_LINE"     | cut -f9)

# ── Step 3: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
P95_THRESH_MS=$(( EXPECTED_MS * 2 ))
SLOW_P95="false"
if [ "$P95_MS" -gt "$P95_THRESH_MS" ]; then
  SLOW_P95="true"
  add_anom "slow_p95"
fi
if [ "$STALLS" -gt 0 ];    then add_anom "stall"; fi
if [ "$NEGATIVES" -gt 0 ]; then add_anom "clock_skew"; fi
ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 4: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":{"from":%s,"to":%s,"blocks":%s,"delta_count":%s},' \
    "$FROM" "$TO" "$BLOCK_COUNT" "$DELTA_COUNT"
  printf '"block_count":%s,"expected_ms":%s,"profile":"%s",' \
    "$DELTA_COUNT" "$EXPECTED_MS" "$PROFILE"
  printf '"stats":{"mean":%s,"median":%s,"p95":%s,"p99":%s,"min":%s,"max":%s},' \
    "$MEAN_MS" "$MEDIAN_MS" "$P95_MS" "$P99_MS" "$MIN_MS" "$MAX_MS"
  printf '"stalls_over_%sms":%s,"negative_deltas":%s,"zero_deltas":%s,' \
    "$STALL_THRESH_MS" "$STALLS" "$NEGATIVES" "$ZEROS"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_consensus_latency: no anomalies (port $PORT, window [$FROM..$TO], profile=$PROFILE)"
  else
    echo "=== Consensus latency (port $PORT, window [$FROM..$TO], $DELTA_COUNT deltas, profile=$PROFILE, expected=${EXPECTED_MS}ms) ==="
    if [ "$ANOM_ONLY" != "1" ]; then
      echo "Inter-block delta times (ms):"
      printf "  mean:   %s\n" "$MEAN_MS"
      printf "  median: %s\n" "$MEDIAN_MS"
      printf "  p95:    %s\n" "$P95_MS"
      printf "  p99:    %s\n" "$P99_MS"
      printf "  min:    %s\n" "$MIN_MS"
      printf "  max:    %s\n" "$MAX_MS"
      echo "Stalls (> ${STALL_THRESH_MS}ms): $STALLS"
      if [ "$NEGATIVES" -gt 0 ]; then
        echo "Negative deltas: $NEGATIVES (clock skew — block[i].timestamp < block[i-1].timestamp)"
      fi
      if [ "$ZEROS" -gt 0 ] && [ "$EXPECTED_MS" -gt 1000 ]; then
        echo "Zero deltas: $ZEROS (back-to-back finalization in same second; rare on this profile)"
      fi
    fi
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] p95 (${P95_MS}ms) within 2× expected (${P95_THRESH_MS}ms)"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      if [ "$SLOW_P95" = "true" ]; then
        echo "  slow_p95   : p95=${P95_MS}ms > 2× expected (${P95_THRESH_MS}ms)"
      fi
      if [ "$STALLS" -gt 0 ]; then
        echo "  stall      : $STALLS delta(s) exceeded stall threshold (${STALL_THRESH_MS}ms = max(3000ms, 10× expected))"
      fi
      if [ "$NEGATIVES" -gt 0 ]; then
        echo "  clock_skew : $NEGATIVES negative delta(s) — block[i].timestamp < block[i-1].timestamp"
      fi
    fi
  fi
fi

# ── Step 5: exit-code policy ──────────────────────────────────────────────────
# Convention: when --anomalies-only is set, anomalies gate the exit
# code; in default informational mode we also exit 2 on anomaly so the
# operator's monitoring wrapper can alert without needing the flag.
if [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
