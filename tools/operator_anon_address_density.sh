#!/usr/bin/env bash
# operator_anon_address_density.sh — Audit anon-address-vs-domain
# density across time-bucketed windows on a running determ daemon.
#
# Sibling to operator_payments_audit.sh + operator_inbound_outbound_balance.sh
# (same per-block walking + JSON envelope + time-bucket + anomaly /
# trend pattern), but the unit of measure is TRANSFER classification by
# {sender,receiver} ∈ {anon, domain}. Operators use this to spot
# privacy-pattern shifts: sudden anon-touching spike → mixing-service
# activity; sustained anon-heavy bucket sequence → post-DApp-launch
# population mix shift; sustained domain-heavy buckets → consumer
# adoption gap.
#
# Approach:
#   - Walk [from..to] one block at a time via `determ block-info <h>
#     --json` (same RPC surface as operator_payments_audit.sh — see
#     src/chain/block.cpp::Block::to_json + ::Transaction::to_json).
#   - For each TRANSFER (tx.type == 0; TxType::TRANSFER per
#     include/determ/chain/block.hpp): classify sender + receiver as
#     anon (regex ^0x[a-f0-9]{64}$ — the S-028 canonical lowercase
#     form; we DO NOT case-fold here because the chain stores the
#     normalized form and any non-canonical sender/receiver would have
#     been rejected at the RPC boundary per S-028) or domain
#     (everything else).
#   - Partition the window into buckets of B=--bucket-blocks contiguous
#     heights. Per bucket, accumulate 4 counters:
#       anon_to_anon, anon_to_domain, domain_to_anon, domain_to_domain
#   - Aggregate to window totals + per-bucket time series + linear-
#     regression slope on the anon-touching ratio across buckets.
#
# Anon-touching definition:
#   A TRANSFER is "anon-touching" when at least one of {sender,receiver}
#   is anon — i.e. anon_to_anon + anon_to_domain + domain_to_anon. The
#   complement is domain_to_domain (no anon participation). Per-bucket
#   anon-touching ratio = anon_touching / total_transfers_in_bucket;
#   empty bucket → ratio undefined (skipped from slope fit).
#
# Bucket sizing (--bucket-blocks):
#   Default B=100 with a 1000-block default window ⇒ 10 buckets, which
#   is enough for a stable least-squares slope without high per-block
#   noise. If --from..--to is shorter than B blocks we clamp
#   B = max(1, window_blocks) so we always get ≥ 1 bucket.
#
# Trend computation (linear regression on the anon-touching ratio):
#   Standard ordinary least-squares slope of y = a + b·x where
#   x = bucket index (0..M−1) and y = anon-touching ratio for that
#   bucket. Closed-form:
#     slope = (M·Σ(x·y) − Σx·Σy) / (M·Σ(x²) − (Σx)²)
#   Positive slope = trend toward more anonymity over the window;
#   negative = trend toward less. When M < 2 the slope is reported as
#   null (a single point has no trend). When all y_i are identical, the
#   denominator depends only on x and is non-zero (M ≥ 2), so slope = 0
#   cleanly. Empty buckets (zero TRANSFERs) are excluded from the fit
#   to keep the trend signal centered on populated buckets.
#
# Anomaly flags:
#   anon_density_spike       any single bucket's anon-touching ratio
#                            > 0.80 AND > 2× the window-median bucket
#                            ratio (median over non-empty buckets).
#                            Bulk-anonymity-event signal worth review.
#   domain_density_collapse  any single bucket's domain-to-domain
#                            ratio < 0.10, where the window-median
#                            domain-to-domain ratio (over non-empty
#                            buckets) is > 0.30. Catches sudden
#                            lossless-anonymity-only windows that
#                            differ sharply from the baseline.
#   trend_slope_high         |trend_slope| > 0.20 across the
#                            non-empty buckets. Sustained directional
#                            density shift worth review.
#
# Usage:
#   tools/operator_anon_address_density.sh
#       [--rpc-port N] [--json]
#       [--from H] [--to H] [--bucket-blocks N]
#       [--anomalies-only]
#
# Defaults:
#   --rpc-port       7778  (matches sibling scripts + tools/common.sh
#                           DETERM defaults; override per-deployment)
#   --from / --to    last 1000 blocks ending at current head
#                    (clamped to 0)
#   --bucket-blocks  100
#
# Output (default human):
#   === Anon-address density (port 7778, window [1000..2000], buckets of 100) ===
#   blocks 1000-1099:  a→a=12  a→d=4   d→a=8   d→d=76  anon-touch=24/100 (24.0%)
#   blocks 1100-1199:  a→a=18  a→d=6   d→a=10  d→d=66  anon-touch=34/100 (34.0%)
#   …
#   Trend (linear regression on anon-touching ratio): +0.012 per bucket
#   Window totals: a→a=…  a→d=…  d→a=…  d→d=…  total=…
#   Anon-touching: …/… (…%)
#   [OK] No density anomalies
#
# JSON shape (single-line):
#   {"window":{"from":H,"to":H,"blocks":N},
#    "bucket_blocks":N,
#    "buckets":[
#      {"from":H,"to":H,"anon_to_anon":N,"anon_to_domain":N,
#       "domain_to_anon":N,"domain_to_domain":N,
#       "anon_touching_pct":F},  // pct = 0..1 (1.0 means 100% anon)
#      …
#    ],
#    "trend":{"slope":F|null,"intercept":F|null},
#    "summary":{"anon_to_anon":N,"anon_to_domain":N,
#               "domain_to_anon":N,"domain_to_domain":N,
#               "total_transfers":N,
#               "anon_touching":N,"anon_touching_pct":F,
#               "non_empty_buckets":N,
#               "median_anon_touching_pct":F|null,
#               "median_domain_to_domain_pct":F|null},
#    "anomalies":[…],
#    "rpc_port":N}
#
# Exit codes:
#   0   success (or --anomalies-only AND no anomalies fired)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_anon_address_density.sh [--rpc-port N] [--json]
                                        [--from H] [--to H]
                                        [--bucket-blocks N]
                                        [--anomalies-only]

Audit anon-address-vs-domain TRANSFER density over a window of
finalized blocks, partitioned into fixed-size buckets. Per bucket
counts the four (sender,receiver) ∈ {anon,domain}² classes for
TRANSFER (type==0) txs, reports per-bucket anon-touching ratio + a
window-wide linear-regression slope across buckets, and flags
anomalies. Sibling to operator_payments_audit.sh (same RPC + JSON
shape; this script focuses on time-bucketed density rather than
flow / amount aggregates).

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --json               Emit structured JSON envelope instead of human table
  --from H             Start of audit window (default: max(0, head-1000))
  --to H               End of audit window   (default: current head)
  --bucket-blocks N    Bucket size in blocks (default: 100; clamped to
                       window size when window < N)
  --anomalies-only     Print only flagged anomalies; exit 2 if any fire
  -h, --help           Show this help

Address classification (S-028):
  anon    matches ^0x[a-f0-9]{64}$ (canonical lowercase form;
          chain stores normalized so non-canonical input is
          rejected at the RPC boundary per S-028)
  domain  everything else (registered domain account)

Anomaly flags:
  anon_density_spike       bucket anon-touching ratio > 0.80
                           AND > 2× window-median bucket ratio
  domain_density_collapse  bucket domain-to-domain ratio < 0.10
                           where window-median d→d > 0.30
  trend_slope_high         |regression slope| > 0.20

Exit codes:
  0   success (or --anomalies-only AND no anomalies)
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
    --rpc-port)        PORT="${2:-}";          shift 2 ;;
    --json)            JSON_OUT=1;             shift ;;
    --from)            FROM_H="${2:-}";        shift 2 ;;
    --to)              TO_H="${2:-}";          shift 2 ;;
    --bucket-blocks)   BUCKET_BLOCKS="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;            shift ;;
    *) echo "operator_anon_address_density: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_anon_address_density: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_anon_address_density: --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_anon_address_density: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" -lt 1 ]; then
  echo "operator_anon_address_density: --bucket-blocks must be ≥ 1 (got $BUCKET_BLOCKS)" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_anon_address_density: jq is required (per-block JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
  echo "operator_anon_address_density: awk is required for trend / median arithmetic" >&2
  exit 1
fi

# ── Step 1: resolve current head height ──────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_anon_address_density: RPC error from \`determ head\` (is daemon on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // empty' 2>/dev/null)
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_anon_address_density: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at current head. The highest
# block index is HEIGHT-1 (height is the count of finalized blocks).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_anon_address_density: --to ($TO) < --from ($FROM); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# Short-circuit on empty chain.
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    jq -nc \
      --argjson from "$FROM" --argjson to "$TO" --argjson blocks 0 \
      --argjson bucket "$BUCKET_BLOCKS" --argjson port "$PORT" \
      '{
        window: {from: $from, to: $to, blocks: $blocks},
        bucket_blocks: $bucket,
        buckets: [],
        trend: {slope: null, intercept: null},
        summary: {
          anon_to_anon: 0, anon_to_domain: 0,
          domain_to_anon: 0, domain_to_domain: 0,
          total_transfers: 0,
          anon_touching: 0, anon_touching_pct: null,
          non_empty_buckets: 0,
          median_anon_touching_pct: null,
          median_domain_to_domain_pct: null
        },
        anomalies: [],
        rpc_port: $port,
        info: "empty_chain"
      }'
  else
    echo "operator_anon_address_density: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# Clamp bucket size to window so we always get ≥ 1 bucket.
if [ "$BUCKET_BLOCKS" -gt "$WIN_BLOCKS" ]; then
  BUCKET_BLOCKS="$WIN_BLOCKS"
fi
# Ceil-div bucket count.
NUM_BUCKETS=$(( (WIN_BLOCKS + BUCKET_BLOCKS - 1) / BUCKET_BLOCKS ))

# ── Step 2: walk window, aggregate per-bucket counters ───────────────────────
# Counters per bucket: a2a / a2d / d2a / d2d. Indexed by bucket index
# 0..NUM_BUCKETS-1. Bash arrays carry them.
declare -a BK_A2A BK_A2D BK_D2A BK_D2D
i=0
while [ $i -lt $NUM_BUCKETS ]; do
  BK_A2A[$i]=0
  BK_A2D[$i]=0
  BK_D2A[$i]=0
  BK_D2D[$i]=0
  i=$((i + 1))
done

# Anon-address regex per S-028 canonical form: lowercase hex only.
# Bash =~ is ERE; matches `is_anon_address` semantics on canonical
# storage (the chain rejects non-canonical case at the RPC boundary).
ANON_RE='^0x[a-f0-9]{64}$'

h=$FROM
while [ $h -le $TO ]; do
  BLK_JSON=$("$DETERM" block-info "$h" --json --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_anon_address_density: RPC error from \`determ block-info $h\` (port $PORT)" >&2
    exit 1
  }
  # Bucket index for this height.
  bi=$(( (h - FROM) / BUCKET_BLOCKS ))
  [ $bi -ge $NUM_BUCKETS ] && bi=$((NUM_BUCKETS - 1))

  # Extract TRANSFER (type==0) {from,to} pairs as tab-separated lines.
  # jq guards: if .transactions is missing or wrong type, emit nothing.
  PAIRS=$(printf '%s' "$BLK_JSON" | jq -r '
    if (.transactions? | type) == "array" then
      .transactions[]
      | select((.type? // -1) == 0)
      | "\(.from // "")\t\(.to // "")"
    else empty end
  ' 2>/dev/null) || {
    echo "operator_anon_address_density: malformed block-info JSON at height $h (port $PORT)" >&2
    exit 1
  }

  if [ -n "$PAIRS" ]; then
    while IFS=$'\t' read -r SENDER RECEIVER; do
      [ -z "$SENDER" ] && [ -z "$RECEIVER" ] && continue
      s_anon=0; r_anon=0
      [[ "$SENDER"   =~ $ANON_RE ]] && s_anon=1
      [[ "$RECEIVER" =~ $ANON_RE ]] && r_anon=1
      if [ $s_anon = 1 ] && [ $r_anon = 1 ]; then
        BK_A2A[$bi]=$(( BK_A2A[$bi] + 1 ))
      elif [ $s_anon = 1 ]; then
        BK_A2D[$bi]=$(( BK_A2D[$bi] + 1 ))
      elif [ $r_anon = 1 ]; then
        BK_D2A[$bi]=$(( BK_D2A[$bi] + 1 ))
      else
        BK_D2D[$bi]=$(( BK_D2D[$bi] + 1 ))
      fi
    done <<EOF_PAIRS
$PAIRS
EOF_PAIRS
  fi

  h=$((h + 1))
done

# ── Step 3: build the per-bucket JSON array + summary stats ──────────────────
# Build the buckets[] array as JSONL first, then jq-slurp into a JSON array.
BUCKETS_JSONL=""
TOT_A2A=0; TOT_A2D=0; TOT_D2A=0; TOT_D2D=0
i=0
while [ $i -lt $NUM_BUCKETS ]; do
  B_FROM=$(( FROM + i * BUCKET_BLOCKS ))
  B_TO=$(( B_FROM + BUCKET_BLOCKS - 1 ))
  [ $B_TO -gt $TO ] && B_TO=$TO
  A=${BK_A2A[$i]}; B=${BK_A2D[$i]}; C=${BK_D2A[$i]}; D=${BK_D2D[$i]}
  TOTB=$(( A + B + C + D ))
  AT=$(( A + B + C ))  # anon-touching = a→a + a→d + d→a
  # anon_touching_pct in [0..1]; null when bucket is empty.
  if [ $TOTB -gt 0 ]; then
    PCT=$(awk -v at="$AT" -v t="$TOTB" 'BEGIN{printf "%.6f", at / t}')
    ROW=$(jq -nc \
      --argjson from "$B_FROM" --argjson to "$B_TO" \
      --argjson a2a "$A" --argjson a2d "$B" \
      --argjson d2a "$C" --argjson d2d "$D" \
      --argjson pct "$PCT" \
      '{from: $from, to: $to,
        anon_to_anon: $a2a, anon_to_domain: $a2d,
        domain_to_anon: $d2a, domain_to_domain: $d2d,
        anon_touching_pct: $pct}')
  else
    ROW=$(jq -nc \
      --argjson from "$B_FROM" --argjson to "$B_TO" \
      --argjson a2a "$A" --argjson a2d "$B" \
      --argjson d2a "$C" --argjson d2d "$D" \
      '{from: $from, to: $to,
        anon_to_anon: $a2a, anon_to_domain: $a2d,
        domain_to_anon: $d2a, domain_to_domain: $d2d,
        anon_touching_pct: null}')
  fi
  BUCKETS_JSONL="${BUCKETS_JSONL}${ROW}
"
  TOT_A2A=$(( TOT_A2A + A ))
  TOT_A2D=$(( TOT_A2D + B ))
  TOT_D2A=$(( TOT_D2A + C ))
  TOT_D2D=$(( TOT_D2D + D ))
  i=$((i + 1))
done

# Slurp per-bucket JSONL into one JSON array (drop trailing blank line).
BUCKETS_JSON=$(printf '%s' "$BUCKETS_JSONL" | grep -v '^$' | jq -sc '.')

TOTAL_TRANSFERS=$(( TOT_A2A + TOT_A2D + TOT_D2A + TOT_D2D ))
ANON_TOUCHING=$(( TOT_A2A + TOT_A2D + TOT_D2A ))

# ── Step 4: window-median of anon-touching ratio + d2d ratio over non-empty buckets ──
# awk handles the ratio computation + median across an unsorted list.
read MEDIAN_AT_PCT MEDIAN_D2D_PCT NON_EMPTY_BUCKETS <<EOF_MED
$(printf '%s' "$BUCKETS_JSON" | jq -r '
  .[] | select(.anon_touching_pct != null)
  | "\(.anon_touching_pct) \((.domain_to_domain) / (.anon_to_anon + .anon_to_domain + .domain_to_anon + .domain_to_domain))"
' | awk '
  { at[NR] = $1; d2d[NR] = $2; n = NR }
  END {
    if (n == 0) { print "null null 0"; exit }
    # sort ascending
    for (i = 1; i <= n; i++)
      for (j = i + 1; j <= n; j++) {
        if (at[i]  > at[j])  { t = at[i];  at[i]  = at[j];  at[j]  = t }
      }
    for (i = 1; i <= n; i++)
      for (j = i + 1; j <= n; j++) {
        if (d2d[i] > d2d[j]) { t = d2d[i]; d2d[i] = d2d[j]; d2d[j] = t }
      }
    if (n % 2 == 1) {
      m_at  = at[(n + 1) / 2]
      m_d2d = d2d[(n + 1) / 2]
    } else {
      m_at  = (at[n/2]  + at[n/2 + 1])  / 2
      m_d2d = (d2d[n/2] + d2d[n/2 + 1]) / 2
    }
    printf "%.6f %.6f %d\n", m_at, m_d2d, n
  }
')
EOF_MED

# ── Step 5: linear-regression slope + intercept on (bucket_index, anon-touching pct) ──
# Closed-form OLS over non-empty buckets (so empty buckets don't pull
# the line toward zero). awk handles the floating-point arithmetic.
read TREND_SLOPE TREND_INTERCEPT <<EOF_REG
$(printf '%s' "$BUCKETS_JSON" | jq -r '
  to_entries[]
  | select(.value.anon_touching_pct != null)
  | "\(.key) \(.value.anon_touching_pct)"
' | awk '
  { x[NR] = $1; y[NR] = $2; n = NR }
  END {
    if (n < 2) { print "null null"; exit }
    sx = sy = sxy = sxx = 0
    for (i = 1; i <= n; i++) {
      sx  += x[i]
      sy  += y[i]
      sxy += x[i] * y[i]
      sxx += x[i] * x[i]
    }
    denom = n * sxx - sx * sx
    if (denom == 0) { print "0 " (sy / n); exit }
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    printf "%.6f %.6f\n", slope, intercept
  }
')
EOF_REG

# ── Step 6: anomaly detection ────────────────────────────────────────────────
ANOMS=""

# anon_density_spike: any non-empty bucket with pct > 0.80 AND > 2× median.
if [ "$MEDIAN_AT_PCT" != "null" ]; then
  SPIKE=$(printf '%s' "$BUCKETS_JSON" | jq -r --arg med "$MEDIAN_AT_PCT" '
    [ .[] | select(.anon_touching_pct != null)
          | select(.anon_touching_pct > 0.80)
          | select(.anon_touching_pct > 2 * ($med | tonumber)) ]
    | length')
  if [ "$SPIKE" -gt 0 ] 2>/dev/null; then
    ANOMS="${ANOMS}anon_density_spike "
  fi
fi

# domain_density_collapse: any bucket with d2d ratio < 0.10 AND median d2d > 0.30.
if [ "$MEDIAN_D2D_PCT" != "null" ]; then
  IS_MED_HI=$(awk -v m="$MEDIAN_D2D_PCT" 'BEGIN{ print (m > 0.30) ? 1 : 0 }')
  if [ "$IS_MED_HI" = "1" ]; then
    COLLAPSE=$(printf '%s' "$BUCKETS_JSON" | jq -r '
      [ .[]
        | select(.anon_touching_pct != null)
        | select((.domain_to_domain) / (.anon_to_anon + .anon_to_domain + .domain_to_anon + .domain_to_domain) < 0.10) ]
      | length')
    if [ "$COLLAPSE" -gt 0 ] 2>/dev/null; then
      ANOMS="${ANOMS}domain_density_collapse "
    fi
  fi
fi

# trend_slope_high: |slope| > 0.20.
if [ "$TREND_SLOPE" != "null" ]; then
  HIGH=$(awk -v s="$TREND_SLOPE" 'BEGIN{ a = (s < 0) ? -s : s; print (a > 0.20) ? 1 : 0 }')
  if [ "$HIGH" = "1" ]; then
    ANOMS="${ANOMS}trend_slope_high "
  fi
fi

# Normalize anomalies string → JSON array.
ANOMS_TRIM=$(printf '%s' "$ANOMS" | awk '{$1=$1; print}')
if [ -z "$ANOMS_TRIM" ]; then
  ANOMS_JSON='[]'
  ANOM_COUNT=0
else
  ANOMS_JSON=$(printf '%s' "$ANOMS_TRIM" | tr ' ' '\n' | jq -R . | jq -sc 'map(select(. != ""))')
  ANOM_COUNT=$(printf '%s' "$ANOMS_JSON" | jq 'length')
fi

# Window-wide anon-touching pct (over all transfers, not bucket median).
if [ $TOTAL_TRANSFERS -gt 0 ]; then
  ANON_TOUCH_PCT=$(awk -v at="$ANON_TOUCHING" -v t="$TOTAL_TRANSFERS" 'BEGIN{printf "%.6f", at / t}')
else
  ANON_TOUCH_PCT="null"
fi

# ── Step 7: render envelope ──────────────────────────────────────────────────
build_summary() {
  if [ "$ANON_TOUCH_PCT" = "null" ]; then
    jq -nc \
      --argjson a2a "$TOT_A2A" --argjson a2d "$TOT_A2D" \
      --argjson d2a "$TOT_D2A" --argjson d2d "$TOT_D2D" \
      --argjson tot "$TOTAL_TRANSFERS" --argjson at "$ANON_TOUCHING" \
      --argjson nb  "$NON_EMPTY_BUCKETS" \
      --arg med_at "$MEDIAN_AT_PCT" --arg med_d2d "$MEDIAN_D2D_PCT" \
      '{
        anon_to_anon: $a2a, anon_to_domain: $a2d,
        domain_to_anon: $d2a, domain_to_domain: $d2d,
        total_transfers: $tot,
        anon_touching: $at,
        anon_touching_pct: null,
        non_empty_buckets: $nb,
        median_anon_touching_pct:    (if $med_at  == "null" then null else ($med_at  | tonumber) end),
        median_domain_to_domain_pct: (if $med_d2d == "null" then null else ($med_d2d | tonumber) end)
      }'
  else
    jq -nc \
      --argjson a2a "$TOT_A2A" --argjson a2d "$TOT_A2D" \
      --argjson d2a "$TOT_D2A" --argjson d2d "$TOT_D2D" \
      --argjson tot "$TOTAL_TRANSFERS" --argjson at "$ANON_TOUCHING" \
      --argjson nb  "$NON_EMPTY_BUCKETS" \
      --argjson atp "$ANON_TOUCH_PCT" \
      --arg med_at "$MEDIAN_AT_PCT" --arg med_d2d "$MEDIAN_D2D_PCT" \
      '{
        anon_to_anon: $a2a, anon_to_domain: $a2d,
        domain_to_anon: $d2a, domain_to_domain: $d2d,
        total_transfers: $tot,
        anon_touching: $at,
        anon_touching_pct: $atp,
        non_empty_buckets: $nb,
        median_anon_touching_pct:    (if $med_at  == "null" then null else ($med_at  | tonumber) end),
        median_domain_to_domain_pct: (if $med_d2d == "null" then null else ($med_d2d | tonumber) end)
      }'
  fi
}
SUMMARY_JSON=$(build_summary)

build_trend() {
  if [ "$TREND_SLOPE" = "null" ]; then
    printf '%s' '{"slope":null,"intercept":null}'
  else
    jq -nc \
      --argjson slope "$TREND_SLOPE" --argjson intercept "$TREND_INTERCEPT" \
      '{slope: $slope, intercept: $intercept}'
  fi
}
TREND_JSON=$(build_trend)

if [ "$JSON_OUT" = "1" ]; then
  jq -nc \
    --argjson from "$FROM" --argjson to "$TO" --argjson blocks "$WIN_BLOCKS" \
    --argjson bucket "$BUCKET_BLOCKS" --argjson port "$PORT" \
    --argjson buckets "$BUCKETS_JSON" --argjson trend "$TREND_JSON" \
    --argjson summary "$SUMMARY_JSON" --argjson anomalies "$ANOMS_JSON" \
    '{
      window: {from: $from, to: $to, blocks: $blocks},
      bucket_blocks: $bucket,
      buckets: $buckets,
      trend: $trend,
      summary: $summary,
      anomalies: $anomalies,
      rpc_port: $port
    }'
else
  # Human table layout. Honor --anomalies-only short-circuit.
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_anon_address_density: no anomalies (port $PORT, window [$FROM..$TO], buckets of $BUCKET_BLOCKS)"
  else
    echo "=== Anon-address density (port $PORT, window [$FROM..$TO], buckets of $BUCKET_BLOCKS) ==="
    if [ "$ANOM_ONLY" != "1" ]; then
      # Per-bucket table.
      printf '%s' "$BUCKETS_JSON" | jq -r '
        .[]
        | "blocks \(.from)-\(.to):  "
          + "a→a=\(.anon_to_anon)  "
          + "a→d=\(.anon_to_domain)  "
          + "d→a=\(.domain_to_anon)  "
          + "d→d=\(.domain_to_domain)  "
          + (if .anon_touching_pct == null
             then "(empty bucket)"
             else "anon-touch=\(.anon_to_anon + .anon_to_domain + .domain_to_anon)/\(.anon_to_anon + .anon_to_domain + .domain_to_anon + .domain_to_domain) (\(.anon_touching_pct * 100 | (.*10|round)/10)%)" end)
      '

      # Trend line. The qualitative tag tracks slope direction + the
      # 0.20 threshold (matches anomaly logic so the descriptive line
      # is consistent with whether trend_slope_high fires).
      if [ "$TREND_SLOPE" = "null" ]; then
        echo "Trend (linear regression on anon-touching ratio): n/a (< 2 non-empty buckets)"
      else
        TAG=""
        if awk -v s="$TREND_SLOPE" 'BEGIN{ a = (s < 0) ? -s : s; exit !(a > 0.20) }'; then
          if awk -v s="$TREND_SLOPE" 'BEGIN{exit !(s > 0)}'; then
            TAG=" (substantial shift toward more anonymity)"
          else
            TAG=" (substantial shift toward less anonymity)"
          fi
        else
          if awk -v s="$TREND_SLOPE" 'BEGIN{exit !(s > 0)}'; then
            TAG=" (gradual shift toward more anonymity)"
          elif awk -v s="$TREND_SLOPE" 'BEGIN{exit !(s < 0)}'; then
            TAG=" (gradual shift toward less anonymity)"
          else
            TAG=" (flat)"
          fi
        fi
        printf 'Trend (linear regression on anon-touching ratio): %+.4f per bucket%s\n' "$TREND_SLOPE" "$TAG"
      fi

      # Summary footer.
      echo "Window totals: a→a=$TOT_A2A  a→d=$TOT_A2D  d→a=$TOT_D2A  d→d=$TOT_D2D  total=$TOTAL_TRANSFERS"
      if [ "$ANON_TOUCH_PCT" = "null" ]; then
        echo "Anon-touching: 0/0 (-)"
      else
        AT_PCT_DISP=$(awk -v p="$ANON_TOUCH_PCT" 'BEGIN{printf "%.1f", p * 100}')
        echo "Anon-touching: $ANON_TOUCHING/$TOTAL_TRANSFERS ($AT_PCT_DISP%)"
      fi
      echo "Non-empty buckets: $NON_EMPTY_BUCKETS / $NUM_BUCKETS"
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No density anomalies"
    else
      ANOMS_DISP=$(printf '%s' "$ANOMS_JSON" | jq -r 'join(",")')
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMS_DISP"
    fi
  fi
fi

# ── Step 8: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
