#!/usr/bin/env bash
# operator_tx_throughput.sh — Measure transaction throughput (TPS) across
# a block window. Walks blocks via `determ block-info <h> --json`,
# extracts per-block tx count + timestamp, and computes both an overall
# TPS for the window and a per-bucket TPS time-series. The expected
# TPS ceiling is derived from the deployment profile so an operator can
# tell at a glance whether observed throughput is normal, well below
# capacity, or anomalously high (capacity test or attack).
#
# Read-only RPC composition; safe against a running daemon. The daemon
# must already be listening on --rpc-port.
#
# TPS computation:
#
#   window_duration_s = last_block.timestamp - first_block.timestamp
#   avg_tps           = total_txs / max(1, window_duration_s)
#
# Per-bucket TPS is computed identically over each contiguous slice of
# --bucket-blocks blocks (default 100). The final bucket may be shorter
# if (window_size % bucket_blocks) != 0. Buckets whose
# (last_ts - first_ts) is zero are treated as zero-TPS rather than
# Inf so the output stays numeric.
#
# Timestamps are Unix epoch seconds (int64) as emitted by Block::to_json
# at src/chain/block.cpp::Block::to_json (`j["timestamp"] = timestamp`).
# A zero or negative window duration (clock skew or single-block window)
# is handled by reporting duration=0 + avg_tps=0 with a note in the
# human output and a sentinel in the JSON envelope.
#
# Profile ceilings (transactions/sec) — soft expectations, not hard caps.
# Derived from profile timing in include/determ/chain/params.hpp:
#   cluster    — 50ms blocks, BEACON, MIN_M=3 K=3        → ~3000 TPS expected ceiling (high)
#   tactical   — 20ms blocks, SHARD, MIN_M=3 K=3         → ~5000 TPS expected ceiling (high)
#   web        — 200ms blocks, SHARD+EXTENDED, M=4 K=3   → ~500 TPS expected ceiling (moderate)
#   regional   — 300ms blocks, SHARD, M=5 K=4            → ~150 TPS expected ceiling (low)
#   global     — 600ms blocks, BEACON+EXTENDED, M=7 K=5  → ~100 TPS expected ceiling (low)
# These are rule-of-thumb planning numbers, not throughput claims; an
# operator can override with --expected-ceiling for non-standard
# deployments.
#
# Usage:
#   tools/operator_tx_throughput.sh [--rpc-port N] [--json]
#                                   [--from H] [--to H]
#                                   [--bucket-blocks N]
#                                   [--profile NAME]
#                                   [--expected-ceiling TPS]
#                                   [--anomalies-only]
#
# Options:
#   --rpc-port N            RPC port to query (default: 7778)
#   --json                  Emit structured JSON envelope instead of human output
#   --from H                Start of window (inclusive; default: max(0, tip-1000))
#   --to H                  End of window (inclusive; default: tip)
#   --bucket-blocks N       Per-bucket size in blocks (default: 100, min 1)
#   --profile NAME          Deployment profile for expected-ceiling default
#                           (cluster|web|regional|global|tactical; default: web)
#   --expected-ceiling TPS  Override expected ceiling (positive integer TPS)
#   --anomalies-only        Print only anomalies; exit 2 if any fire
#   -h, --help              Show this help
#
# RPC dependencies (all read-only):
#   - head                  (current chain height)
#   - block                 (per-block JSON; via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - tps_over_ceiling      avg_tps > 2x expected ceiling for the profile
#   - tps_dropoff           any bucket has TPS less than 50% of the prior bucket
#                           AND the prior bucket carried >0 TPS (potential stall)
#
# Exit codes:
#   0   throughput measured, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_tx_throughput.sh [--rpc-port N] [--json]
                                 [--from H] [--to H]
                                 [--bucket-blocks N]
                                 [--profile NAME]
                                 [--expected-ceiling TPS]
                                 [--anomalies-only]

Measure transaction throughput (TPS) across a block window. Walks
the window via block-info, computes total_txs / (last_ts - first_ts)
for the overall TPS, plus a per-bucket TPS time-series. Compares
against the profile-derived expected ceiling and flags anomalies
(over-ceiling or mid-window drop-off).

Options:
  --rpc-port N            RPC port to query (default: 7778)
  --json                  Emit structured JSON envelope instead of human
  --from H                Start of window (default: max(0, tip-1000))
  --to H                  End of window (default: tip)
  --bucket-blocks N       Per-bucket size in blocks (default: 100)
  --profile NAME          cluster|web|regional|global|tactical (default: web)
  --expected-ceiling TPS  Override expected ceiling (positive integer)
  --anomalies-only        Print only anomalies; exit 2 if any fire
  -h, --help              Show this help

Anomaly flags:
  tps_over_ceiling   avg_tps > 2x expected ceiling for the profile
  tps_dropoff        any bucket's TPS < 50% of the prior non-zero bucket

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
BUCKET_BLOCKS=100
PROFILE=""
EXPECTED_CEILING=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           PORT="$2";              shift 2 ;;
    --json)               JSON_OUT=1;             shift ;;
    --from)               FROM_H="$2";            shift 2 ;;
    --to)                 TO_H="$2";              shift 2 ;;
    --bucket-blocks)      BUCKET_BLOCKS="$2";     shift 2 ;;
    --profile)            PROFILE="$2";           shift 2 ;;
    --expected-ceiling)   EXPECTED_CEILING="$2";  shift 2 ;;
    --anomalies-only)     ANOM_ONLY=1;            shift ;;
    *) echo "operator_tx_throughput: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_tx_throughput: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_tx_throughput: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_tx_throughput: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" -lt 1 ]; then
  echo "operator_tx_throughput: --bucket-blocks must be >= 1 (got '$BUCKET_BLOCKS')" >&2
  exit 1
fi
if [ -n "$EXPECTED_CEILING" ]; then
  case "$EXPECTED_CEILING" in *[!0-9]*|"")
    echo "operator_tx_throughput: --expected-ceiling must be a positive integer (got '$EXPECTED_CEILING')" >&2
    exit 1 ;;
  esac
  if [ "$EXPECTED_CEILING" -lt 1 ]; then
    echo "operator_tx_throughput: --expected-ceiling must be >= 1 (got '$EXPECTED_CEILING')" >&2
    exit 1
  fi
fi

# Profile -> default expected ceiling. Mirrors include/determ/chain/params.hpp
# rule-of-thumb capacity numbers (see header).
case "$PROFILE" in
  cluster)  PROFILE_CEILING=3000; PROFILE_BAND="high" ;;
  tactical) PROFILE_CEILING=5000; PROFILE_BAND="high" ;;
  web|"")   PROFILE_CEILING=500;  PROFILE_BAND="moderate"; PROFILE="${PROFILE:-web}" ;;
  regional) PROFILE_CEILING=150;  PROFILE_BAND="low" ;;
  global)   PROFILE_CEILING=100;  PROFILE_BAND="low" ;;
  *)
    echo "operator_tx_throughput: unknown --profile '$PROFILE' (expected: cluster|web|regional|global|tactical)" >&2
    exit 1 ;;
esac

# Explicit --expected-ceiling overrides the profile default.
if [ -n "$EXPECTED_CEILING" ]; then
  EFFECTIVE_CEILING="$EXPECTED_CEILING"
  CEILING_SOURCE="user"
else
  EFFECTIVE_CEILING="$PROFILE_CEILING"
  CEILING_SOURCE="profile"
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_tx_throughput: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_tx_throughput: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip (per spec).
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_tx_throughput: --from ($FROM) > --to ($TO); nothing to measure" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk window + collect (tx_count, timestamp) per block ─────────────
# Python driver: parses each block-info JSON, extracts timestamp + tx
# count, then computes overall + per-bucket TPS in one pass.
#
# Output schema (TSV summary line written to TMP_STATS):
#   total_blocks<TAB>total_txs<TAB>first_ts<TAB>last_ts
#     <TAB>window_duration_s<TAB>avg_tps_milli<TAB>bucket_count
#     <TAB>min_bucket_tps_milli<TAB>max_bucket_tps_milli
#     <TAB>dropoff_count
# Where *_tps_milli is TPS * 1000 (integer; lets us round-trip with shell
# without floats). The corresponding TMP_BUCKETS file holds one line per
# bucket:
#   <bucket_idx>\t<first_block>\t<last_block>\t<txs>\t<duration_s>\t<tps_milli>
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_tx_throughput: cannot create temp file" >&2; exit 1;
}
TMP_BUCKETS=$(mktemp 2>/dev/null) || {
  echo "operator_tx_throughput: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" "$TMP_BUCKETS" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$BUCKET_BLOCKS" \
       "$TMP_STATS" "$TMP_BUCKETS" <<'PY'
import json, subprocess, sys

(determ, port, from_h, to_h, bucket_blocks,
 stats_path, buckets_path) = sys.argv[1:8]
from_h        = int(from_h)
to_h          = int(to_h)
bucket_blocks = int(bucket_blocks)

# Walk every block in the window once. tx_counts and timestamps are
# parallel lists keyed by relative window position (i.e. heights[i] =
# from_h + i). The producer guarantees monotonic timestamps in the
# normal case, but a tiny non-monotonic step (clock skew on producer
# rotation, leap second) is possible; we don't try to repair it — the
# arithmetic below clamps negative durations to 0 so the math stays
# defensible.
heights    = []
tx_counts  = []
timestamps = []
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_tx_throughput: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_tx_throughput: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_tx_throughput: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []
    ts = blk.get("timestamp", 0)
    if not isinstance(ts, (int, float)):
        sys.stderr.write(f"operator_tx_throughput: block-info {h} has non-numeric timestamp\n")
        sys.exit(1)
    heights.append(h)
    tx_counts.append(len(txs))
    timestamps.append(int(ts))

# Window-overall TPS.
total_blocks = len(tx_counts)
total_txs    = sum(tx_counts)
if total_blocks == 0:
    first_ts = 0
    last_ts  = 0
else:
    first_ts = timestamps[0]
    last_ts  = timestamps[-1]
duration = last_ts - first_ts
if duration < 0:
    duration = 0
# Integer TPS scaled by 1000 (3 decimal places worth) to round-trip
# through the shell without floats.
if duration > 0:
    avg_tps_milli = int(round(total_txs * 1000 / duration))
else:
    avg_tps_milli = 0

# Bucketized TPS time-series. Slice [0..total_blocks) into chunks of
# bucket_blocks. The last bucket may be shorter. A bucket's TPS uses
# the same formula as the window — its own first/last timestamps.
buckets = []
dropoff_count = 0
prev_nonzero_tps = None
for i in range(0, total_blocks, bucket_blocks):
    j = min(i + bucket_blocks, total_blocks)
    if j <= i:
        continue
    b_first_block = heights[i]
    b_last_block  = heights[j-1]
    b_first_ts    = timestamps[i]
    b_last_ts     = timestamps[j-1]
    b_dur = b_last_ts - b_first_ts
    if b_dur < 0:
        b_dur = 0
    b_txs = sum(tx_counts[i:j])
    if b_dur > 0:
        b_tps_milli = int(round(b_txs * 1000 / b_dur))
    else:
        b_tps_milli = 0
    buckets.append((b_first_block, b_last_block, b_txs, b_dur, b_tps_milli))
    # tps_dropoff anomaly: prior bucket TPS > 0, this one < 50% of it.
    if prev_nonzero_tps is not None and prev_nonzero_tps > 0:
        if b_tps_milli * 2 < prev_nonzero_tps:
            dropoff_count += 1
    if b_tps_milli > 0:
        prev_nonzero_tps = b_tps_milli

if buckets:
    min_bucket_milli = min(b[4] for b in buckets)
    max_bucket_milli = max(b[4] for b in buckets)
else:
    min_bucket_milli = 0
    max_bucket_milli = 0

with open(stats_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        total_blocks, total_txs, first_ts, last_ts, duration,
        avg_tps_milli, len(buckets),
        min_bucket_milli, max_bucket_milli, dropoff_count,
    ]) + "\n")

with open(buckets_path, "w", encoding="utf-8") as f:
    for idx, (fb, lb, txs, dur, tps_m) in enumerate(buckets):
        f.write(f"{idx}\t{fb}\t{lb}\t{txs}\t{dur}\t{tps_m}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_tx_throughput: block-walk failed" >&2
  exit 1
fi

# ── Step 3: read stats back into shell-aggregable form ────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_tx_throughput: empty stats payload" >&2
  exit 1
fi
TOTAL_BLOCKS=$(printf '%s'      "$STATS_LINE" | cut -f1)
TOTAL_TXS=$(printf '%s'         "$STATS_LINE" | cut -f2)
FIRST_TS=$(printf '%s'          "$STATS_LINE" | cut -f3)
LAST_TS=$(printf '%s'           "$STATS_LINE" | cut -f4)
DURATION_S=$(printf '%s'        "$STATS_LINE" | cut -f5)
AVG_TPS_MILLI=$(printf '%s'     "$STATS_LINE" | cut -f6)
BUCKET_COUNT=$(printf '%s'      "$STATS_LINE" | cut -f7)
MIN_BUCKET_MILLI=$(printf '%s'  "$STATS_LINE" | cut -f8)
MAX_BUCKET_MILLI=$(printf '%s'  "$STATS_LINE" | cut -f9)
DROPOFF_COUNT=$(printf '%s'     "$STATS_LINE" | cut -f10)

# Helper: render an integer-TPS-milli value as "N.N TPS" (1 decimal).
# We keep one decimal place rather than three because operator output
# is informational; the JSON envelope retains the milli value for
# downstream programmatic consumers.
render_tps_milli() {
  local m="$1"
  case "$m" in *[!0-9]*|"") echo "0.0"; return ;; esac
  local whole=$(( m / 1000 ))
  local frac=$(( (m % 1000) / 100 ))
  printf '%d.%d' "$whole" "$frac"
}

# ── Step 4: anomaly classification ────────────────────────────────────────────
# tps_over_ceiling: avg TPS > 2x effective ceiling. Compare in milli-TPS
# space so we don't lose precision to integer floor division.
CEILING_MILLI=$(( EFFECTIVE_CEILING * 1000 ))
CEILING_2X_MILLI=$(( CEILING_MILLI * 2 ))

ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
if [ "$AVG_TPS_MILLI" -gt "$CEILING_2X_MILLI" ]; then add_anom "tps_over_ceiling"; fi
if [ "$DROPOFF_COUNT" -gt 0 ];                       then add_anom "tps_dropoff"; fi
ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 5: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Bucket array — written as a JSON sub-array. Use jq if available for
  # type safety; otherwise emit raw with shell quoting (numbers only, no
  # injection risk since values are integers we computed).
  BUCKETS_JSON="[]"
  if [ -s "$TMP_BUCKETS" ]; then
    if command -v jq >/dev/null 2>&1; then
      BUCKETS_JSON=$(awk -F'\t' '
        BEGIN { printf "[" }
        {
          if (NR > 1) printf ",";
          printf "{\"index\":%s,\"first_block\":%s,\"last_block\":%s,\"txs\":%s,\"duration_s\":%s,\"tps_milli\":%s}",
            $1, $2, $3, $4, $5, $6
        }
        END { printf "]" }
      ' "$TMP_BUCKETS" | jq -c .)
    else
      BUCKETS_JSON=$(awk -F'\t' '
        BEGIN { printf "[" }
        {
          if (NR > 1) printf ",";
          printf "{\"index\":%s,\"first_block\":%s,\"last_block\":%s,\"txs\":%s,\"duration_s\":%s,\"tps_milli\":%s}",
            $1, $2, $3, $4, $5, $6
        }
        END { printf "]" }
      ' "$TMP_BUCKETS")
    fi
  fi
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_blocks":%s,"total_txs":%s,' "$TOTAL_BLOCKS" "$TOTAL_TXS"
  printf '"first_timestamp":%s,"last_timestamp":%s,"window_duration_s":%s,' \
    "$FIRST_TS" "$LAST_TS" "$DURATION_S"
  printf '"avg_tps_milli":%s,' "$AVG_TPS_MILLI"
  printf '"bucket_blocks":%s,"bucket_count":%s,' "$BUCKET_BLOCKS" "$BUCKET_COUNT"
  printf '"min_bucket_tps_milli":%s,"max_bucket_tps_milli":%s,' \
    "$MIN_BUCKET_MILLI" "$MAX_BUCKET_MILLI"
  printf '"buckets":%s,' "$BUCKETS_JSON"
  printf '"profile":"%s","profile_band":"%s","profile_default_ceiling":%s,' \
    "$PROFILE" "$PROFILE_BAND" "$PROFILE_CEILING"
  printf '"expected_ceiling_tps":%s,"ceiling_source":"%s",' \
    "$EFFECTIVE_CEILING" "$CEILING_SOURCE"
  printf '"dropoff_count":%s,' "$DROPOFF_COUNT"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  # Human-readable layout.
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_tx_throughput: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== TX throughput (port $PORT, window [$FROM..$TO]) ==="
    echo "Total txs: $TOTAL_TXS"
    echo "Window duration: ${DURATION_S}s"
    printf "Average TPS: %s\n" "$(render_tps_milli $AVG_TPS_MILLI)"
    if [ "$ANOM_ONLY" != "1" ]; then
      echo "Per-bucket TPS:"
      if [ ! -s "$TMP_BUCKETS" ]; then
        echo "  (no buckets — empty window)"
      else
        while IFS=$'\t' read -r BIDX BFIRST BLAST BTXS BDUR BTPS_M; do
          printf "  blocks %s-%s: %s TPS (%s txs over %ss)\n" \
            "$BFIRST" "$BLAST" "$(render_tps_milli $BTPS_M)" "$BTXS" "$BDUR"
        done <"$TMP_BUCKETS"
      fi
      printf "Profile: %s (%s band, expected ceiling %s TPS, source=%s)\n" \
        "$PROFILE" "$PROFILE_BAND" "$EFFECTIVE_CEILING" "$CEILING_SOURCE"
    fi
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] Throughput within expected range"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      case ",$ANOMALIES," in
        *,tps_over_ceiling,*)
          printf "  tps_over_ceiling : avg %s TPS > 2x expected ceiling (%s TPS)\n" \
            "$(render_tps_milli $AVG_TPS_MILLI)" "$EFFECTIVE_CEILING" ;;
      esac
      case ",$ANOMALIES," in
        *,tps_dropoff,*)
          echo "  tps_dropoff      : $DROPOFF_COUNT bucket(s) dropped > 50% vs prior non-zero bucket" ;;
      esac
    fi
  fi
fi

# ── Step 6: exit-code policy ──────────────────────────────────────────────────
# Same convention as operator_block_size_audit / operator_subsidy_audit /
# operator_fork_watch: exit 2 only when --anomalies-only is set AND >= 1
# anomaly fired. Default informational mode always exits 0 if the RPC
# walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
