#!/usr/bin/env bash
# operator_inbound_outbound_balance.sh — Audit the NET cross-shard flow
# of a shard over time. Sibling to tools/operator_receipt_audit.sh, which
# reports per-source / per-destination breakdowns at a single point;
# this script focuses on the BALANCE between inbound and outbound over
# time so operators can answer two distinct questions:
#
#   (a) Over the window, is this shard a net importer or net exporter
#       of value?  (signed: total_inbound − total_outbound)
#   (b) Is that balance stable, or is the rate trending in one direction
#       (e.g. ever-increasing outflow → liquidity drain)?
#
# Approach:
#   - Walk [from..to] one block at a time via `determ block-info <h>
#     --json`. Same RPC surface and same JSON shape as the sibling
#     receipt-audit script — see src/chain/block.cpp::Block::to_json and
#     ::CrossShardReceipt::to_json.
#   - Partition the window into buckets of B=--bucket-blocks contiguous
#     heights. For each bucket accumulate:
#       bucket_inbound  = Σ amount over inbound_receipts[]      in bucket
#       bucket_outbound = Σ amount over cross_shard_receipts[]  in bucket
#       bucket_net      = bucket_inbound − bucket_outbound
#     Positive net ⇒ net importer for that bucket; negative ⇒ exporter.
#   - Aggregate to window totals + per-bucket time series + linear-
#     regression slope on bucket_net vs bucket_index (least-squares).
#
# Bucket sizing (--bucket-blocks):
#   Default B=100 with a 1000-block default window ⇒ 10 buckets, which
#   is enough for a reasonable least-squares slope without producing a
#   high-noise per-block series. If --from..--to is short (< B blocks)
#   we clamp B = max(1, window_blocks) so we always get ≥ 1 bucket.
#   Operators tuning for finer-grained drift detection can shrink B to
#   10 or 25; for very long windows we suggest B = window/20.
#
# Trend computation:
#   Standard ordinary least-squares slope of net_i vs i (i = 0..M−1
#   over M buckets) — closed-form:
#     slope = (M·Σ(i·y) − Σi·Σy) / (M·Σ(i²) − (Σi)²)
#   Reported as "net per bucket". When M < 2 the slope is reported as
#   null (a single point has no trend); when all y_i are identical, the
#   denominator is non-zero (it depends only on x) so slope = 0 cleanly.
#   The trend's relative magnitude is computed against the mean of
#   |bucket_net| so a slope of "−22 net/bucket" against an average
#   |net|=44 is reported as 50% downtrend — see Anomaly flags below.
#
# Single-shard handling:
#   sharding_mode=="none" ⇒ shard_count=1 ⇒ no cross-shard flow by
#   construction. We exit 0 with an INFO line (same as the sibling
#   receipt-audit script). --shard-count N can override the inference.
#
# Usage:
#   tools/operator_inbound_outbound_balance.sh
#       [--rpc-port N] [--json]
#       [--from H] [--to H] [--bucket-blocks N]
#       [--anomalies-only]
#
# Defaults:
#   --rpc-port       7778
#   --from / --to    last 1000 blocks ending at current head (clamped to 0)
#   --bucket-blocks  100
#
# Output (default human):
#   === Inbound/outbound balance (port 7778, window [1000..2000], buckets of 100) ===
#   Total inbound:  12345
#   Total outbound: 14567
#   Net:            -2222 (net exporter, 18.0% outflow)
#   Per-bucket time series:
#     blocks 1000-1099: in=1100, out=1200, net=-100
#     blocks 1100-1199: in=1230, out=1400, net=-170
#     ...
#   Trend (linear regression on net): -22.0 per bucket (gradual outflow increase)
#   [OK] No anomalies
#
# JSON shape (single-line, stable field order):
#   {"my_shard_id":N,"shard_count":N,"window":{"from":H,"to":H,"blocks":N},
#    "bucket_blocks":N,"total_inbound":N,"total_outbound":N,"net":N,
#    "mean_bucket_net":F,"median_bucket_net":F,
#    "buckets":[{"index":I,"from":H,"to":H,"inbound":N,"outbound":N,"net":N},…],
#    "trend_slope":F|null,"trend_pct_of_mean":F|null,
#    "anomalies":[…],"rpc_port":N,"sharding_mode":"…"}
#
# Anomaly flags:
#   inbound_spike        ≥1 bucket whose inbound > 3 × mean(bucket_inbound)
#                        and mean > 0 (sudden inflow surge)
#   outbound_spike       ≥1 bucket whose outbound > 3 × mean(bucket_outbound)
#                        and mean > 0 (sudden outflow surge)
#   net_inflow_trend     trend_slope > 0 AND |slope|/mean(|net|) > 0.5
#                        (persistently increasing inflow rate)
#   net_outflow_trend    trend_slope < 0 AND |slope|/mean(|net|) > 0.5
#                        (persistently increasing outflow rate / drain)
#
# Exit codes:
#   0   success / informational (single-shard deployment also exits 0)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_inbound_outbound_balance.sh [--rpc-port N] [--json]
                                            [--from H] [--to H]
                                            [--bucket-blocks N]
                                            [--anomalies-only]

Audits net cross-shard flow over a window of finalized blocks. Walks
[from..to] one block at a time, partitions into fixed-size buckets,
and reports per-bucket inbound / outbound / net plus a least-squares
trend slope on the net series. Sibling to operator_receipt_audit.sh
(point-in-time breakdown); this script answers "is the shard a net
importer or exporter and is the rate stable?"

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, head-1000))
  --to H              End of audit window   (default: current head)
  --bucket-blocks N   Bucket size in blocks (default: 100; clamped to
                      window size when window < N)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  inbound_spike       any bucket inbound > 3 × mean(bucket_inbound)
  outbound_spike      any bucket outbound > 3 × mean(bucket_outbound)
  net_inflow_trend    slope > 0 AND |slope|/mean(|net|) > 50%
  net_outflow_trend   slope < 0 AND |slope|/mean(|net|) > 50%

Exit codes:
  0   success / informational (or single-shard deployment)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
BUCKET_BLOCKS=100
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";               shift 2 ;;
    --json)            JSON_OUT=1;                  shift ;;
    --from)            FROM_H="${2:-}";             shift 2 ;;
    --to)              TO_H="${2:-}";               shift 2 ;;
    --bucket-blocks)   BUCKET_BLOCKS="${2:-}";      shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;                 shift ;;
    *) echo "operator_inbound_outbound_balance: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_inbound_outbound_balance: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_inbound_outbound_balance: --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_inbound_outbound_balance: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" -lt 1 ]; then
  echo "operator_inbound_outbound_balance: --bucket-blocks must be ≥ 1 (got $BUCKET_BLOCKS)" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_inbound_outbound_balance: jq is required (per-block JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_inbound_outbound_balance: python is required for per-block aggregation + trend" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# ── Step 1: probe daemon for shard config ────────────────────────────────────
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_inbound_outbound_balance: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}
MY_SHARD_ID=$(printf '%s' "$STATUS_JSON" | jq -r '.shard_id // 0')
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac
SHARDING_MODE=$(printf '%s' "$STATUS_JSON" | jq -r '.protections.sharding_mode // "unknown"')

# Resolve head height.
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_inbound_outbound_balance: RPC error from \`determ head\` (port $PORT)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // 0')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_inbound_outbound_balance: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at current head. Highest
# finalized index is height-1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_inbound_outbound_balance: --to ($TO) < --from ($FROM); nothing to audit" >&2
  exit 1
fi

WIN_BLOCKS=$(( TO - FROM + 1 ))

# Short-circuit on empty chain.
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"shard_count":1,"window":{"from":%s,"to":%s,"blocks":0},"bucket_blocks":%s,"total_inbound":0,"total_outbound":0,"net":0,"mean_bucket_net":0,"median_bucket_net":0,"buckets":[],"trend_slope":null,"trend_pct_of_mean":null,"anomalies":[],"rpc_port":%s,"sharding_mode":"%s","info":"empty_chain"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$BUCKET_BLOCKS" "$PORT" "$SHARDING_MODE"
  else
    echo "operator_inbound_outbound_balance: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# Single-shard short-circuit. sharding_mode=="none" ⇒ shard_count=1 by
# construction. No cross-shard flow possible.
if [ "$SHARDING_MODE" = "none" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"shard_count":1,"window":{"from":%s,"to":%s,"blocks":%s},"bucket_blocks":%s,"total_inbound":0,"total_outbound":0,"net":0,"mean_bucket_net":0,"median_bucket_net":0,"buckets":[],"trend_slope":null,"trend_pct_of_mean":null,"anomalies":[],"rpc_port":%s,"sharding_mode":"none","info":"single_shard_deployment"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$WIN_BLOCKS" "$BUCKET_BLOCKS" "$PORT"
  else
    echo "INFO: single-shard deployment — no cross-shard flow by construction (sharding_mode=none, port $PORT)"
  fi
  exit 0
fi

# Clamp bucket size to window so we always get ≥ 1 bucket.
if [ "$BUCKET_BLOCKS" -gt "$WIN_BLOCKS" ]; then
  BUCKET_BLOCKS="$WIN_BLOCKS"
fi

# ── Step 2: walk window via block-info + bucket-accumulate + trend ───────────
TMP_OUT=$(mktemp) || {
  echo "operator_inbound_outbound_balance: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - "$DETERM" "$PORT" "$FROM" "$TO" "$BUCKET_BLOCKS" "$TMP_OUT" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, bucket_blocks, out_path = sys.argv[1:7]
from_h = int(from_h); to_h = int(to_h); bucket_blocks = int(bucket_blocks)

# Pre-allocate the bucket array. Bucket i covers heights
# [from_h + i*B, from_h + (i+1)*B - 1] (last bucket clamped at to_h).
win_blocks = to_h - from_h + 1
num_buckets = (win_blocks + bucket_blocks - 1) // bucket_blocks  # ceil div
buckets = []
for i in range(num_buckets):
    b_from = from_h + i * bucket_blocks
    b_to   = min(b_from + bucket_blocks - 1, to_h)
    buckets.append({
        "index":    i,
        "from":     b_from,
        "to":       b_to,
        "inbound":  0,
        "outbound": 0,
        "net":      0,
    })

total_inbound = 0
total_outbound = 0
max_shard_observed = 0  # for shard_count inference (matches sibling receipt_audit)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_inbound_outbound_balance: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_inbound_outbound_balance: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_inbound_outbound_balance: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    bi = (h - from_h) // bucket_blocks
    if bi >= num_buckets:
        bi = num_buckets - 1  # paranoia clamp

    # Inbound: credits received from other shards. Per chain.cpp::apply_block,
    # each .amount bumps accumulated_inbound.
    for ib in (blk.get("inbound_receipts") or []):
        amt = int(ib.get("amount", 0))
        src = int(ib.get("src_shard", 0))
        buckets[bi]["inbound"] += amt
        total_inbound += amt
        if src > max_shard_observed: max_shard_observed = src

    # Outbound: cross_shard_receipts emitted by THIS shard in this block.
    # Per producer.cpp B3.2, the producer builds this list by iterating
    # TRANSFER txs whose .to routes off-shard. Using the block's pre-
    # computed list spares us needing the shard_address_salt.
    for o in (blk.get("cross_shard_receipts") or []):
        amt = int(o.get("amount", 0))
        dst = int(o.get("dst_shard", 0))
        buckets[bi]["outbound"] += amt
        total_outbound += amt
        if dst > max_shard_observed: max_shard_observed = dst

# Finalize per-bucket net.
nets = []
for b in buckets:
    b["net"] = b["inbound"] - b["outbound"]
    nets.append(b["net"])

# Mean / median of bucket_net.
def mean(xs):
    return (sum(xs) / len(xs)) if xs else 0.0
def median(xs):
    if not xs: return 0.0
    s = sorted(xs); n = len(s)
    if n % 2 == 1:
        return float(s[n // 2])
    return (s[n // 2 - 1] + s[n // 2]) / 2.0

mean_net   = mean(nets)
median_net = median(nets)

# Linear regression: slope of y = a + b*x where x = bucket index, y = net.
# Closed form: slope = (M·Σxy − Σx·Σy) / (M·Σx² − (Σx)²).
# Denominator depends only on x and is non-zero for M ≥ 2.
M = len(nets)
trend_slope = None
if M >= 2:
    sx  = sum(range(M))
    sy  = sum(nets)
    sxy = sum(i * nets[i] for i in range(M))
    sxx = sum(i * i for i in range(M))
    denom = M * sxx - sx * sx
    if denom != 0:
        trend_slope = (M * sxy - sx * sy) / denom

# Relative trend magnitude: |slope| / mean(|net|). Used for the 50% gates.
trend_pct = None
if trend_slope is not None:
    abs_mean = mean([abs(n) for n in nets])
    if abs_mean > 0:
        trend_pct = abs(trend_slope) / abs_mean

# Anomaly detection.
anomalies = []
inb_buckets = [b["inbound"]  for b in buckets]
out_buckets = [b["outbound"] for b in buckets]
mean_in  = mean(inb_buckets)
mean_out = mean(out_buckets)

if mean_in > 0:
    for b in buckets:
        if b["inbound"] > 3 * mean_in:
            anomalies.append("inbound_spike")
            break
if mean_out > 0:
    for b in buckets:
        if b["outbound"] > 3 * mean_out:
            anomalies.append("outbound_spike")
            break
if trend_pct is not None and trend_pct > 0.5:
    if trend_slope > 0:
        anomalies.append("net_inflow_trend")
    elif trend_slope < 0:
        anomalies.append("net_outflow_trend")

result = {
    "buckets":             buckets,
    "total_inbound":       total_inbound,
    "total_outbound":      total_outbound,
    "net":                 total_inbound - total_outbound,
    "mean_bucket_net":     mean_net,
    "median_bucket_net":   median_net,
    "trend_slope":         trend_slope,
    "trend_pct_of_mean":   trend_pct,
    "anomalies":           anomalies,
    "mean_bucket_in":      mean_in,
    "mean_bucket_out":     mean_out,
    "max_shard_observed":  max_shard_observed,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_inbound_outbound_balance: block-walk failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

TOTAL_IN=$(printf '%s'  "$WALK_JSON" | jq -r '.total_inbound')
TOTAL_OUT=$(printf '%s' "$WALK_JSON" | jq -r '.total_outbound')
NET=$(printf '%s'       "$WALK_JSON" | jq -r '.net')
MEAN_NET=$(printf '%s'  "$WALK_JSON" | jq -r '.mean_bucket_net')
MEDIAN_NET=$(printf '%s' "$WALK_JSON" | jq -r '.median_bucket_net')
TREND=$(printf '%s'     "$WALK_JSON" | jq -r '.trend_slope')
TREND_PCT=$(printf '%s' "$WALK_JSON" | jq -r '.trend_pct_of_mean')
ANOM_LIST=$(printf '%s' "$WALK_JSON" | jq -r '.anomalies | join(",")')
ANOM_COUNT=$(printf '%s' "$WALK_JSON" | jq -r '.anomalies | length')
MAX_SHARD_OBS=$(printf '%s' "$WALK_JSON" | jq -r '.max_shard_observed')

# Infer shard_count from observed receipts (max(src,dst,my)+1). For a
# single-shard chain with sharding_mode!=none but no cross-shard
# activity in this window, max stays at my_shard_id so we'd report
# shard_count == my_shard_id+1 which is still a valid lower bound.
SHARD_COUNT=$MAX_SHARD_OBS
if [ "$MY_SHARD_ID" -gt "$SHARD_COUNT" ]; then SHARD_COUNT=$MY_SHARD_ID; fi
SHARD_COUNT=$(( SHARD_COUNT + 1 ))

# ── Step 3: render ───────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Emit the compact JSON envelope. We re-shape WALK_JSON to match the
  # documented field order + drop the internal "mean_bucket_in/out" +
  # "max_shard_observed" debugging fields.
  printf '%s' "$WALK_JSON" | jq -c \
    --argjson my_shard "$MY_SHARD_ID" \
    --argjson shard_count "$SHARD_COUNT" \
    --argjson from "$FROM" --argjson to "$TO" --argjson blocks "$WIN_BLOCKS" \
    --argjson bucket "$BUCKET_BLOCKS" --argjson port "$PORT" \
    --arg sharding_mode "$SHARDING_MODE" \
    '{
      my_shard_id: $my_shard,
      shard_count: $shard_count,
      window: {from: $from, to: $to, blocks: $blocks},
      bucket_blocks: $bucket,
      total_inbound: .total_inbound,
      total_outbound: .total_outbound,
      net: .net,
      mean_bucket_net: .mean_bucket_net,
      median_bucket_net: .median_bucket_net,
      buckets: .buckets,
      trend_slope: .trend_slope,
      trend_pct_of_mean: .trend_pct_of_mean,
      anomalies: .anomalies,
      rpc_port: $port,
      sharding_mode: $sharding_mode
    }'
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_inbound_outbound_balance: no anomalies (port $PORT, window [$FROM..$TO], buckets of $BUCKET_BLOCKS)"
  else
    echo "=== Inbound/outbound balance (port $PORT, window [$FROM..$TO], buckets of $BUCKET_BLOCKS) ==="
    echo "Total inbound:  $TOTAL_IN"
    echo "Total outbound: $TOTAL_OUT"

    # Net + flavor line. Percent computed in integer basis points to
    # avoid relying on floating point in bash (matches the sibling
    # script's pct_bps convention).
    if [ "$TOTAL_IN" -gt 0 ] || [ "$TOTAL_OUT" -gt 0 ]; then
      DENOM=$TOTAL_IN
      [ "$DENOM" -lt "$TOTAL_OUT" ] && DENOM=$TOTAL_OUT
      ABS_NET=$NET
      [ "$ABS_NET" -lt 0 ] && ABS_NET=$(( - ABS_NET ))
      PCT_BPS=$(( ABS_NET * 10000 / DENOM ))
      WHOLE=$(( PCT_BPS / 100 ))
      FRAC=$(( (PCT_BPS % 100) / 10 ))
      if [ "$NET" -lt 0 ]; then
        printf 'Net:            %s (net exporter, %d.%d%% outflow)\n' "$NET" "$WHOLE" "$FRAC"
      elif [ "$NET" -gt 0 ]; then
        printf 'Net:            +%s (net importer, %d.%d%% inflow)\n' "$NET" "$WHOLE" "$FRAC"
      else
        printf 'Net:            0 (balanced)\n'
      fi
    else
      echo "Net:            0 (no cross-shard activity in window)"
    fi

    if [ "$ANOM_ONLY" != "1" ]; then
      echo "Per-bucket time series:"
      printf '%s' "$WALK_JSON" | jq -r '
        .buckets[]
        | "  blocks \(.from)-\(.to): in=\(.inbound), out=\(.outbound), net=\(.net)"'

      # Mean / median lines (useful operator context — short-window
      # series can have a large mean swamped by a single outlier, so
      # show both).
      printf 'Mean bucket net:   %s\n' "$MEAN_NET"
      printf 'Median bucket net: %s\n' "$MEDIAN_NET"

      # Trend line. The qualitative tag tracks slope direction + the
      # 50% threshold (matches anomaly logic so the descriptive line
      # is consistent with whether net_*flow_trend fires).
      if [ "$TREND" = "null" ]; then
        echo "Trend (linear regression on net): n/a (< 2 buckets)"
      else
        TAG=""
        if [ "$TREND_PCT" != "null" ]; then
          if awk -v p="$TREND_PCT" 'BEGIN{exit !(p > 0.5)}'; then
            if awk -v s="$TREND" 'BEGIN{exit !(s > 0)}'; then
              TAG=" (substantial inflow increase)"
            elif awk -v s="$TREND" 'BEGIN{exit !(s < 0)}'; then
              TAG=" (substantial outflow increase)"
            fi
          else
            if awk -v s="$TREND" 'BEGIN{exit !(s > 0)}'; then
              TAG=" (gradual inflow increase)"
            elif awk -v s="$TREND" 'BEGIN{exit !(s < 0)}'; then
              TAG=" (gradual outflow increase)"
            else
              TAG=" (flat)"
            fi
          fi
        fi
        printf 'Trend (linear regression on net): %s per bucket%s\n' "$TREND" "$TAG"
      fi
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOM_LIST"
    fi
  fi
fi

# ── Step 4: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
