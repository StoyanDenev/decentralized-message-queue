#!/usr/bin/env bash
# operator_reward_budget.sh — Per-block validator-reward composition
# ("security budget") audit over a window of finalized blocks. Answers
# the operator question none of the existing tools answer directly:
#   "Of the value paid to block creators, how much comes from MINTED
#    subsidy versus TRANSFERRED transaction fees, and is the chain
#    maturing toward fee-sustainability or still wholly inflation-funded?"
#
# Read-only RPC composition; safe against a running daemon. The daemon
# must already be listening on --rpc-port.
#
# ── Why this tool exists (sibling positioning) ────────────────────────────────
# Determ credits each block's creators with `total_distributed =
# total_fees + subsidy_this_block` (chain.cpp::apply_block). Two existing
# tools each isolate ONE half of that sum and never combine them:
#
#   operator_subsidy_audit.sh / operator_subsidy_accrual_audit.sh
#       The SUBSIDY half only (E1/E3/E4 mint + per-validator concentration).
#       Explicitly: "This audit isolates the *subsidy* component only."
#
#   operator_fee_distribution_audit.sh
#       The FEE half only (who-got-paid concentration of transferred fees).
#
#   operator_tx_throughput.sh
#       TPS over time — a RATE metric, value-blind.
#
# This tool composes both halves into the reward-budget view PoS/PoW
# operators actually track: the FEE-COVERAGE RATIO = fees / total_reward.
# A young chain sits near 0 (subsidy carries the whole security budget);
# a maturing fee market drives it up. When E4 finally drains the subsidy
# pool, coverage MUST approach 1.0 or the security budget collapses.
# Watching this ratio trend across a window is the early-warning surface
# for "the chain is approaching subsidy exhaustion but fees aren't
# replacing it yet."
#
# ── Reward attribution (mirrors chain.cpp::apply_block) ───────────────────────
#   per-block:
#     block_fees       = Σ tx.fee over the block's transactions[]
#                        (UPPER BOUND — silent-skip txs per FA-Apply-6 T-F2
#                         appear in transactions[] but may not reach the
#                         total_fees credit line; there is no RPC exposing
#                         the apply-time success bitmap, so we take the
#                         upper-bound view exactly as
#                         operator_fee_distribution_audit.sh documents.)
#     block_subsidy    = subsidy basis IF len(creators) > 0, else 0
#                        (empty-creator blocks pay no subsidy/fees —
#                         apply_block skips the credit loop entirely).
#     block_reward     = block_fees + block_subsidy
#   window totals: Σ over the window of each component.
#   fee_coverage     = total_fees / max(1, total_reward)   (in [0,1])
#
# ── Subsidy basis ─────────────────────────────────────────────────────────────
# There is no "per-block subsidy" RPC; the chain exposes lifetime
# `accumulated_subsidy` (via supply) only at the head. Precedence mirrors
# operator_subsidy_audit.sh:
#   --block-subsidy V  → FLAT-mode authoritative value (operator supplies
#                        the same value genesis encoded).
#   else               → (accumulated_subsidy / height) lifetime-average
#                        heuristic. Exact for any FLAT chain; an
#                        expectation for LOTTERY chains. If height==0 or
#                        accumulated_subsidy==0 the basis is 0 and the
#                        subsidy_basis_unavailable anomaly fires (coverage
#                        then trivially reports 1.0 — fees are the only
#                        measurable reward — which is itself a signal worth
#                        the operator's attention, hence the flag).
#
# ── Timestamps / buckets ──────────────────────────────────────────────────────
# Block.timestamp is Unix epoch seconds (int64, Block::to_json). The
# coverage trend is bucketed into contiguous --bucket-blocks slices
# (default 100; final bucket may be shorter). Per-bucket coverage uses
# that bucket's own fee/reward sums. This lets the operator see coverage
# CLIMBING (healthy fee-market maturation) or COLLAPSING (a bucket where
# fee revenue cratered relative to the steady subsidy floor).
#
# Usage:
#   tools/operator_reward_budget.sh [--rpc-port N] [--json]
#                                   [--from H] [--to H] [--last N]
#                                   [--bucket-blocks N]
#                                   [--block-subsidy V]
#                                   [--min-fee-coverage PCT]
#                                   [--anomalies-only]
#
# Options:
#   --rpc-port N            RPC port to query (default: 7778)
#   --json                  Emit structured JSON envelope instead of human output
#   --from H                Start of window (inclusive; default: max(0, tip-100))
#   --to H                  End of window (inclusive; default: tip)
#   --last N                Shorthand for [tip-N+1, tip]
#                           (mutually exclusive with --from / --to)
#   --bucket-blocks N       Per-bucket size in blocks (default: 100, min 1)
#   --block-subsidy V       Per-block subsidy basis override (FLAT-mode
#                           authoritative). Default: accumulated_subsidy/height.
#   --min-fee-coverage PCT  Floor (integer percent, 0..100) below which the
#                           window-overall fee coverage flags fee_coverage_low.
#                           Default: 0 (informational — never fires unless set).
#   --anomalies-only        Print only anomalies; exit 2 if any fire
#   -h, --help              Show this help
#
# RPC dependencies (all read-only):
#   - head    (--field height)               current chain height
#   - supply  (--field accumulated_subsidy)  lifetime mint (subsidy heuristic)
#   - block-info <h> --json                  per-block fees + creators walk
#
# Anomaly flags (each adds an entry to anomalies[]):
#   fee_coverage_low         window-overall coverage < --min-fee-coverage
#                            (only when --min-fee-coverage > 0). Operator-
#                            tunable "security budget still inflation-reliant"
#                            gate.
#   fee_coverage_collapse    any bucket's coverage dropped to < 50% of the
#                            prior bucket's coverage AND the prior bucket
#                            had coverage > 0 (a fee-revenue crater against
#                            a steady subsidy floor).
#   subsidy_basis_unavailable  no usable per-block subsidy basis (height==0
#                            or accumulated_subsidy==0 and no --block-subsidy).
#                            Coverage degenerates to 1.0; informational.
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_reward_budget.sh [--rpc-port N] [--json]
                                 [--from H] [--to H] [--last N]
                                 [--bucket-blocks N]
                                 [--block-subsidy V]
                                 [--min-fee-coverage PCT]
                                 [--anomalies-only]

Per-block validator-reward composition ("security budget") audit. Walks
the window via block-info, sums per-block transaction fees and attributes
per-block subsidy, then reports the fee/subsidy split, total reward, and
the FEE-COVERAGE RATIO (fees / total reward) plus its bucketed trend.

This is the reward-budget view that operator_subsidy_audit.sh (subsidy
only) and operator_fee_distribution_audit.sh (fees only) never combine:
is the chain's validator reward inflation-funded or maturing toward
fee-sustainability?

Options:
  --rpc-port N            RPC port to query (default: 7778)
  --json                  Emit structured JSON envelope instead of human
  --from H                Start of window (default: max(0, tip-100))
  --to H                  End of window (default: tip)
  --last N                Shorthand for [tip-N+1, tip] (excl. --from/--to)
  --bucket-blocks N       Per-bucket size in blocks (default: 100)
  --block-subsidy V       Per-block subsidy basis override (FLAT-mode);
                          default = accumulated_subsidy / height
  --min-fee-coverage PCT  Floor percent (0..100); coverage below it flags
                          fee_coverage_low (default 0 = informational)
  --anomalies-only        Print only anomalies; exit 2 if any fire
  -h, --help              Show this help

RPC dependencies (read-only): head, supply, block-info.

Anomaly flags:
  fee_coverage_low         window coverage < --min-fee-coverage (if set)
  fee_coverage_collapse    a bucket's coverage < 50% of the prior bucket
  subsidy_basis_unavailable  no usable per-block subsidy basis

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
LAST_N=""
BUCKET_BLOCKS=100
BLOCK_SUBSIDY_OVR=""
MIN_FEE_COVERAGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           PORT="${2:-}";              shift 2 ;;
    --json)               JSON_OUT=1;                 shift ;;
    --from)               FROM_H="${2:-}";            shift 2 ;;
    --to)                 TO_H="${2:-}";              shift 2 ;;
    --last)               LAST_N="${2:-}";            shift 2 ;;
    --bucket-blocks)      BUCKET_BLOCKS="${2:-}";     shift 2 ;;
    --block-subsidy)      BLOCK_SUBSIDY_OVR="${2:-}"; shift 2 ;;
    --min-fee-coverage)   MIN_FEE_COVERAGE="${2:-}";  shift 2 ;;
    --anomalies-only)     ANOM_ONLY=1;                shift ;;
    *) echo "operator_reward_budget: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Arg validation ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_reward_budget: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N" "$BLOCK_SUBSIDY_OVR"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_reward_budget: --from / --to / --last / --block-subsidy must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_reward_budget: --last cannot be combined with --from / --to" >&2
  exit 1
fi
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_reward_budget: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" -lt 1 ]; then
  echo "operator_reward_budget: --bucket-blocks must be >= 1 (got '$BUCKET_BLOCKS')" >&2
  exit 1
fi
case "$MIN_FEE_COVERAGE" in *[!0-9]*|"")
  echo "operator_reward_budget: --min-fee-coverage must be an integer percent 0..100 (got '$MIN_FEE_COVERAGE')" >&2
  exit 1 ;;
esac
if [ "$MIN_FEE_COVERAGE" -gt 100 ]; then
  echo "operator_reward_budget: --min-fee-coverage must be <= 100 (got '$MIN_FEE_COVERAGE')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (matches operator_subsidy_audit.sh +
# operator_committee_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip ───────────────────────────────────────────────
# SKIP (exit 0 + INFO) when the daemon is unreachable, matching the
# clean-skip behavior the prompt + sibling tools call for: an operator
# running this in a health loop against a not-yet-started node should not
# see a hard failure. A genuine RPC error after a reachable head still
# exits 1 below.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_reward_budget: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  exit 0
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_reward_budget: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks to audit. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  echo "operator_reward_budget: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  exit 0
fi

# ── Step 2: subsidy basis ─────────────────────────────────────────────────────
# Lifetime accumulated_subsidy via supply --field (single bare scalar).
ACCUM=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_reward_budget: RPC error querying supply (port $PORT)" >&2
  exit 1
}
ACCUM=$(printf '%s' "$ACCUM" | tr -d '[:space:]')
case "$ACCUM" in *[!0-9]*|"")
  echo "operator_reward_budget: supply returned non-numeric accumulated_subsidy '$ACCUM' (port $PORT)" >&2
  exit 1 ;;
esac

if [ -n "$BLOCK_SUBSIDY_OVR" ]; then
  EST_PER_BLOCK=$BLOCK_SUBSIDY_OVR
  EST_SOURCE="override"
elif [ "$HEAD_H" -gt 0 ] && [ "$ACCUM" -gt 0 ]; then
  EST_PER_BLOCK=$(( ACCUM / HEAD_H ))
  EST_SOURCE="heuristic"
else
  EST_PER_BLOCK=0
  EST_SOURCE="unavailable"
fi

# ── Step 3: resolve window bounds ─────────────────────────────────────────────
# Index semantics: `head --field height` returns total block count
# (block 0 = genesis; highest valid index = height - 1). Mirrors
# operator_subsidy_audit.sh.
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -lt 1 ]; then LAST_N=1; fi
  if [ "$LAST_N" -gt $(( TOP + 1 )) ]; then LAST_N=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - LAST_N ))
  TO=$TOP
else
  FROM=${FROM_H:-$(( TOP > 100 ? TOP - 100 : 0 ))}
  TO=${TO_H:-$TOP}
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_reward_budget: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 4: walk window + accumulate fees / subsidy / reward ──────────────────
# Python driver: one block-info round-trip per block. Emits a TSV stats
# line + a per-bucket TSV. Coverage values are scaled by 10000 (basis
# points) so they round-trip through the shell as integers without floats.
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_reward_budget: cannot create temp file" >&2; exit 1;
}
TMP_BUCKETS=$(mktemp 2>/dev/null) || {
  echo "operator_reward_budget: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" "$TMP_BUCKETS" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$BUCKET_BLOCKS" \
       "$EST_PER_BLOCK" "$TMP_STATS" "$TMP_BUCKETS" <<'PY'
import json, subprocess, sys

(determ, port, from_h, to_h, bucket_blocks,
 est_per_block, stats_path, buckets_path) = sys.argv[1:9]
from_h        = int(from_h)
to_h          = int(to_h)
bucket_blocks = int(bucket_blocks)
est_per_block = int(est_per_block)

# Parallel lists keyed by relative window position.
heights     = []
fee_list    = []   # block_fees per block
subsidy_list= []   # block_subsidy per block (0 if empty-creator block)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_reward_budget: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_reward_budget: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_reward_budget: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []
    block_fees = 0
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        f = tx.get("fee", 0)
        if isinstance(f, bool):           # guard: bool is a subclass of int
            continue
        if isinstance(f, (int, float)) and f > 0:
            block_fees += int(f)

    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    # Empty-creator blocks pay no subsidy AND no fees (apply_block skips
    # the credit loop). Mirrors operator_subsidy_audit.sh's empty handling.
    if len(creators) > 0:
        block_subsidy = est_per_block
    else:
        block_subsidy = 0
        block_fees    = 0

    heights.append(h)
    fee_list.append(block_fees)
    subsidy_list.append(block_subsidy)

total_blocks  = len(heights)
total_fees    = sum(fee_list)
total_subsidy = sum(subsidy_list)
total_reward  = total_fees + total_subsidy

# fee_coverage in basis points (0..10000). When total_reward == 0 the
# window is degenerate (no creators anywhere) — report coverage 0 with a
# zero-reward sentinel so downstream doesn't divide by zero.
if total_reward > 0:
    cov_bp = int(round(total_fees * 10000 / total_reward))
else:
    cov_bp = 0

# Bucketized coverage trend.
buckets = []
collapse_count = 0
prev_cov_bp = None
for i in range(0, total_blocks, bucket_blocks):
    j = min(i + bucket_blocks, total_blocks)
    if j <= i:
        continue
    b_first = heights[i]
    b_last  = heights[j-1]
    b_fees    = sum(fee_list[i:j])
    b_subsidy = sum(subsidy_list[i:j])
    b_reward  = b_fees + b_subsidy
    if b_reward > 0:
        b_cov_bp = int(round(b_fees * 10000 / b_reward))
    else:
        b_cov_bp = 0
    buckets.append((b_first, b_last, b_fees, b_subsidy, b_reward, b_cov_bp))
    # fee_coverage_collapse: prior bucket had coverage > 0, this one < 50%.
    if prev_cov_bp is not None and prev_cov_bp > 0:
        if b_cov_bp * 2 < prev_cov_bp:
            collapse_count += 1
    prev_cov_bp = b_cov_bp

if buckets:
    min_cov_bp = min(b[5] for b in buckets)
    max_cov_bp = max(b[5] for b in buckets)
else:
    min_cov_bp = 0
    max_cov_bp = 0

with open(stats_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        total_blocks, total_fees, total_subsidy, total_reward, cov_bp,
        len(buckets), min_cov_bp, max_cov_bp, collapse_count,
    ]) + "\n")

with open(buckets_path, "w", encoding="utf-8") as f:
    for idx, (fb, lb, fees, sub, rew, cov) in enumerate(buckets):
        f.write(f"{idx}\t{fb}\t{lb}\t{fees}\t{sub}\t{rew}\t{cov}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_reward_budget: block-walk failed" >&2
  exit 1
fi

# ── Step 5: read stats back ───────────────────────────────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_reward_budget: empty stats payload" >&2
  exit 1
fi
TOTAL_BLOCKS=$(printf '%s'  "$STATS_LINE" | cut -f1)
TOTAL_FEES=$(printf '%s'    "$STATS_LINE" | cut -f2)
TOTAL_SUBSIDY=$(printf '%s' "$STATS_LINE" | cut -f3)
TOTAL_REWARD=$(printf '%s'  "$STATS_LINE" | cut -f4)
COV_BP=$(printf '%s'        "$STATS_LINE" | cut -f5)
BUCKET_COUNT=$(printf '%s'  "$STATS_LINE" | cut -f6)
MIN_COV_BP=$(printf '%s'    "$STATS_LINE" | cut -f7)
MAX_COV_BP=$(printf '%s'    "$STATS_LINE" | cut -f8)
COLLAPSE_COUNT=$(printf '%s' "$STATS_LINE" | cut -f9)

# Render a basis-point coverage value (0..10000) as "NN.N%".
render_cov_bp() {
  local bp="$1"
  case "$bp" in *[!0-9]*|"") echo "0.0"; return ;; esac
  local whole=$(( bp / 100 ))
  local frac=$(( (bp % 100) / 10 ))
  printf '%d.%d' "$whole" "$frac"
}

# ── Step 6: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

# fee_coverage_low: only when an explicit floor was given. Compare in
# basis points (floor_pct * 100).
if [ "$MIN_FEE_COVERAGE" -gt 0 ]; then
  FLOOR_BP=$(( MIN_FEE_COVERAGE * 100 ))
  if [ "$COV_BP" -lt "$FLOOR_BP" ]; then add_anom "fee_coverage_low"; fi
fi
# fee_coverage_collapse: at least one bucket cratered vs the prior bucket.
if [ "$COLLAPSE_COUNT" -gt 0 ]; then add_anom "fee_coverage_collapse"; fi
# subsidy_basis_unavailable: no usable per-block subsidy basis.
if [ "$EST_SOURCE" = "unavailable" ]; then add_anom "subsidy_basis_unavailable"; fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 7: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  BUCKETS_JSON="[]"
  if [ -s "$TMP_BUCKETS" ]; then
    BUCKETS_JSON=$(awk -F'\t' '
      BEGIN { printf "[" }
      {
        if (NR > 1) printf ",";
        printf "{\"index\":%s,\"first_block\":%s,\"last_block\":%s,\"fees\":%s,\"subsidy\":%s,\"reward\":%s,\"fee_coverage_bp\":%s}",
          $1, $2, $3, $4, $5, $6, $7
      }
      END { printf "]" }
    ' "$TMP_BUCKETS")
    if command -v jq >/dev/null 2>&1; then
      BUCKETS_JSON=$(printf '%s' "$BUCKETS_JSON" | jq -c .)
    fi
  fi
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_blocks":%s,' "$TOTAL_BLOCKS"
  printf '"total_fees":%s,"total_subsidy":%s,"total_reward":%s,' \
    "$TOTAL_FEES" "$TOTAL_SUBSIDY" "$TOTAL_REWARD"
  printf '"fee_coverage_bp":%s,' "$COV_BP"
  printf '"subsidy_basis_per_block":%s,"subsidy_basis_source":"%s",' \
    "$EST_PER_BLOCK" "$EST_SOURCE"
  printf '"bucket_blocks":%s,"bucket_count":%s,' "$BUCKET_BLOCKS" "$BUCKET_COUNT"
  printf '"min_bucket_coverage_bp":%s,"max_bucket_coverage_bp":%s,' \
    "$MIN_COV_BP" "$MAX_COV_BP"
  printf '"coverage_collapse_count":%s,' "$COLLAPSE_COUNT"
  printf '"min_fee_coverage_pct":%s,' "$MIN_FEE_COVERAGE"
  printf '"buckets":%s,' "$BUCKETS_JSON"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_reward_budget: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== Reward budget (port $PORT, window [$FROM..$TO], $TOTAL_BLOCKS blocks) ==="
    echo "Total fees:    $TOTAL_FEES"
    echo "Total subsidy: $TOTAL_SUBSIDY  (basis ${EST_PER_BLOCK}/block, source=$EST_SOURCE)"
    echo "Total reward:  $TOTAL_REWARD"
    printf "Fee coverage:  %s%% (fees / total reward)\n" "$(render_cov_bp "$COV_BP")"
    if [ "$ANOM_ONLY" != "1" ]; then
      echo "Per-bucket fee coverage:"
      if [ ! -s "$TMP_BUCKETS" ]; then
        echo "  (no buckets — empty window)"
      else
        while IFS=$'\t' read -r BIDX BFIRST BLAST BFEES BSUB BREW BCOV; do
          printf "  blocks %s-%s: %s%% coverage (fees %s / subsidy %s)\n" \
            "$BFIRST" "$BLAST" "$(render_cov_bp "$BCOV")" "$BFEES" "$BSUB"
        done <"$TMP_BUCKETS"
      fi
    fi
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] reward budget composed; no anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      case ",$ANOMALIES," in
        *,fee_coverage_low,*)
          printf "  fee_coverage_low          : %s%% < %s%% floor (security budget still inflation-reliant)\n" \
            "$(render_cov_bp "$COV_BP")" "$MIN_FEE_COVERAGE" ;;
      esac
      case ",$ANOMALIES," in
        *,fee_coverage_collapse,*)
          echo "  fee_coverage_collapse     : $COLLAPSE_COUNT bucket(s) dropped > 50% coverage vs prior bucket" ;;
      esac
      case ",$ANOMALIES," in
        *,subsidy_basis_unavailable,*)
          echo "  subsidy_basis_unavailable : no per-block subsidy basis (coverage reads 1.0; pass --block-subsidy)" ;;
      esac
    fi
  fi
fi

# ── Step 8: exit-code policy ──────────────────────────────────────────────────
# Same convention as operator_tx_throughput / operator_subsidy_audit:
# exit 2 only when --anomalies-only is set AND >= 1 anomaly fired.
# Default informational mode always exits 0 if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
