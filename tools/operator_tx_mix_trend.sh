#!/usr/bin/env bash
# operator_tx_mix_trend.sh — Transaction-type COMPOSITION trend + mix-shift
# (regime-change) detector over a window of finalized blocks on a running
# determ daemon. Answers the operator question none of the existing tools
# answer:
#   "Is the WORKLOAD MIX shifting? Across this window, what share of txs is
#    TRANSFER vs STAKE/UNSTAKE vs REGISTER vs PARAM_CHANGE vs DAPP_CALL etc.,
#    and is that share STABLE over time or is it lurching between regimes
#    (a payment network going quiet, a runaway DApp ramping, a staking
#    storm, a governance burst)?"
#
# Read-only RPC composition; safe against a running daemon. The daemon must
# already be listening on --rpc-port.
#
# ── Why this tool exists (sibling positioning) ────────────────────────────────
# Several existing tools each isolate ONE transaction type, or report the
# type mix only as a single window-AGGREGATE with no temporal axis:
#
#   operator_block_size_audit.sh
#       Reports a window-AGGREGATE `tx_type_distribution` (one count +
#       share_bps per type for the WHOLE window) and a single
#       `tx_type_imbalance_high` flag (any type > 80% of the window total).
#       It has NO per-bucket time series and NO adjacent-bucket shift
#       detection — a window where TRANSFER collapses and DAPP_CALL spikes
#       mid-window averages out to a "balanced" aggregate and the shift is
#       invisible. THIS tool adds the temporal axis the aggregate hides.
#
#   operator_payments_audit.sh        TRANSFER (type 0) only.
#   operator_dapp_call_audit.sh       DAPP_CALL (type 10) only.
#   operator_dapp_registration_audit  DAPP_REGISTER (type 9) only.
#   operator_stake_activation_audit.sh / operator_unstake_timeline.sh
#                                     STAKE / UNSTAKE lifecycle only.
#   operator_mempool_inspector.sh     PENDING (mempool) by-type — not the
#                                     CONFIRMED on-chain history this walks.
#
# This tool composes ALL types into a per-bucket composition time-series and
# computes the inter-bucket MIX SHIFT, mirroring the bucket + collapse/dropoff
# detector pattern that operator_reward_budget.sh (fee coverage) and
# operator_tx_throughput.sh (TPS) already apply on their own metric — here
# applied to the type-share dimension.
#
# ── Mix-shift metric (total variation distance) ───────────────────────────────
# Each bucket's per-type shares form a probability distribution p over the
# type universe (shares sum to 1 across the bucket's non-empty txs). The
# shift between two adjacent buckets p (prior) and q (current) is the
# TOTAL VARIATION DISTANCE:
#
#   TVD(p, q) = (1/2) * Σ_i | p_i − q_i |        ∈ [0, 1]
#
# TVD is 0 when the mix is identical and 1 when the two buckets share no
# type in common (e.g. one bucket is 100% TRANSFER, the next is 100%
# DAPP_CALL). It is symmetric, bounded, and needs no smoothing — the right
# off-the-shelf distance for "did the workload regime change between these
# two slices?". Buckets with zero txs are SKIPPED for shift purposes (an
# empty bucket has no defined distribution); the comparison pairs each
# non-empty bucket with the most recent prior non-empty bucket so a gap of
# empty blocks doesn't manufacture a false shift.
#
# TVD is reported scaled by 10000 (basis points, 0..10000) so it round-trips
# through the shell as an integer without floats — the same scaling
# operator_reward_budget.sh uses for fee coverage.
#
# ── tx-type universe (canonical, mirrors block.hpp::TxType) ───────────────────
# Transaction.type is serialized to JSON as a numeric int
# (src/chain/block.cpp::Transaction::to_json: j["type"] = static_cast<int>).
# The integer→name map is taken verbatim from operator_block_size_audit.sh
# so type labels are identical across the two tools:
#   0 TRANSFER 1 REGISTER 2 DEREGISTER 3 STAKE 4 UNSTAKE 5 REGION_CHANGE
#   6 PARAM_CHANGE 7 MERGE_EVENT 8 COMPOSABLE_BATCH 9 DAPP_REGISTER 10 DAPP_CALL
# Unknown integers (forward-compat) render as TYPE_<n> and participate in the
# shares + TVD like any other type.
#
# ── Buckets / window ──────────────────────────────────────────────────────────
# The window is sliced into contiguous --bucket-blocks slices (default 100;
# final bucket may be shorter). Each bucket's share vector uses that bucket's
# own per-type tx counts over its own total txs.
#
# Usage:
#   tools/operator_tx_mix_trend.sh [--rpc-port N] [--json]
#                                  [--from H] [--to H] [--last N]
#                                  [--bucket-blocks N]
#                                  [--max-shift PCT]
#                                  [--max-dominance PCT]
#                                  [--anomalies-only]
#
# Options:
#   --rpc-port N         RPC port to query (default: 7778)
#   --json               Emit a structured JSON envelope instead of human output
#   --from H             Start of window (inclusive; default: max(0, tip-1000))
#   --to H               End of window (inclusive; default: tip)
#   --last N             Shorthand for [tip-N+1, tip]
#                        (mutually exclusive with --from / --to)
#   --bucket-blocks N    Per-bucket size in blocks (default: 100, min 1)
#   --max-shift PCT      Adjacent-bucket TVD threshold (integer percent, 1..100)
#                        at/above which mix_shift_detected fires (default: 50).
#   --max-dominance PCT  Per-bucket single-type share (integer percent, 1..100)
#                        at/above which type_dominance_high fires (default: 95).
#                        Distinct from operator_block_size_audit's window-
#                        aggregate 80% flag: this is PER-BUCKET, so a transient
#                        dominance spike a window-average would dilute is caught.
#   --anomalies-only     Print only anomalies; exit 2 if any fire
#   -h, --help           Show this help
#
# RPC dependencies (all read-only):
#   - head    (--field height)               current chain height
#   - block-info <h> --json                  per-block transactions[] type walk
#
# Anomaly flags (each adds an entry to anomalies[]):
#   mix_shift_detected     >=1 adjacent (non-empty) bucket pair whose TVD
#                          reached --max-shift. The workload regime changed
#                          between two time slices — investigate whether a
#                          DApp ramped, payments stalled, a staking/governance
#                          burst landed, etc.
#   type_dominance_high    >=1 bucket where a single tx-type held >= the
#                          --max-dominance share. A bucket monopolized by one
#                          type (e.g. a runaway DApp, a stuck workload).
#   empty_window           the window contained no transactions at all
#                          (informational; no mix to trend — SKIP-like signal).
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable* / malformed response / bad args
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
#
#   *daemon-unreachable at the FIRST head probe is treated as a clean
#    INFO + SKIP (exit 0), matching operator_reward_budget.sh: an operator
#    running this in a health loop against a not-yet-started node should not
#    see a hard failure. A genuine RPC error after a reachable head exits 1.
set -u

usage() {
  cat <<'EOF'
Usage: operator_tx_mix_trend.sh [--rpc-port N] [--json]
                                [--from H] [--to H] [--last N]
                                [--bucket-blocks N]
                                [--max-shift PCT]
                                [--max-dominance PCT]
                                [--anomalies-only]

Transaction-type composition trend + mix-shift (regime-change) detector.
Walks the window via block-info, computes each bucket's per-type tx-share
vector, and reports the composition time-series plus the TOTAL VARIATION
DISTANCE between adjacent (non-empty) buckets. Flags regime shifts the
window-aggregate view of operator_block_size_audit.sh averages away.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --json               Emit structured JSON envelope instead of human
  --from H             Start of window (default: max(0, tip-1000))
  --to H               End of window (default: tip)
  --last N             Shorthand for [tip-N+1, tip] (excl. --from/--to)
  --bucket-blocks N    Per-bucket size in blocks (default: 100)
  --max-shift PCT      Adjacent-bucket TVD threshold percent (1..100; def 50)
  --max-dominance PCT  Per-bucket single-type share threshold (1..100; def 95)
  --anomalies-only     Print only anomalies; exit 2 if any fire
  -h, --help           Show this help

RPC dependencies (read-only): head, block-info.

Anomaly flags:
  mix_shift_detected   adjacent-bucket TVD reached --max-shift
  type_dominance_high  a bucket's single-type share reached --max-dominance
  empty_window         window contained no transactions (informational)

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
MAX_SHIFT=50
MAX_DOMINANCE=95
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";          shift 2 ;;
    --json)            JSON_OUT=1;             shift ;;
    --from)            FROM_H="${2:-}";        shift 2 ;;
    --to)              TO_H="${2:-}";          shift 2 ;;
    --last)            LAST_N="${2:-}";        shift 2 ;;
    --bucket-blocks)   BUCKET_BLOCKS="${2:-}"; shift 2 ;;
    --max-shift)       MAX_SHIFT="${2:-}";     shift 2 ;;
    --max-dominance)   MAX_DOMINANCE="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;            shift ;;
    *) echo "operator_tx_mix_trend: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Arg validation ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_tx_mix_trend: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_tx_mix_trend: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_tx_mix_trend: --last cannot be combined with --from / --to" >&2
  exit 1
fi
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_tx_mix_trend: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" -lt 1 ]; then
  echo "operator_tx_mix_trend: --bucket-blocks must be >= 1 (got '$BUCKET_BLOCKS')" >&2
  exit 1
fi
case "$MAX_SHIFT" in *[!0-9]*|"")
  echo "operator_tx_mix_trend: --max-shift must be an integer percent 1..100 (got '$MAX_SHIFT')" >&2
  exit 1 ;;
esac
if [ "$MAX_SHIFT" -lt 1 ] || [ "$MAX_SHIFT" -gt 100 ]; then
  echo "operator_tx_mix_trend: --max-shift must be in 1..100 (got '$MAX_SHIFT')" >&2
  exit 1
fi
case "$MAX_DOMINANCE" in *[!0-9]*|"")
  echo "operator_tx_mix_trend: --max-dominance must be an integer percent 1..100 (got '$MAX_DOMINANCE')" >&2
  exit 1 ;;
esac
if [ "$MAX_DOMINANCE" -lt 1 ] || [ "$MAX_DOMINANCE" -gt 100 ]; then
  echo "operator_tx_mix_trend: --max-dominance must be in 1..100 (got '$MAX_DOMINANCE')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (matches operator_reward_budget.sh +
# operator_subsidy_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip ───────────────────────────────────────────────
# SKIP (exit 0 + INFO) when the daemon is unreachable at the first probe,
# matching operator_reward_budget.sh's clean-skip behavior.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_tx_mix_trend: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  exit 0
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_tx_mix_trend: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks to audit. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  echo "operator_tx_mix_trend: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  exit 0
fi

# ── Step 2: resolve window bounds ─────────────────────────────────────────────
# Index semantics: `head --field height` returns total block count
# (block 0 = genesis; highest valid index = height - 1). Mirrors
# operator_reward_budget.sh / operator_subsidy_audit.sh.
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -lt 1 ]; then LAST_N=1; fi
  if [ "$LAST_N" -gt $(( TOP + 1 )) ]; then LAST_N=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - LAST_N ))
  TO=$TOP
else
  FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 : 0 ))}
  TO=${TO_H:-$TOP}
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_tx_mix_trend: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk window + accumulate per-bucket per-type counts ───────────────
# Python driver: one block-info round-trip per block. Computes each bucket's
# per-type share vector, the adjacent (non-empty) bucket TVD, and the
# per-bucket dominant-type share. Emits a TSV stats line + a per-bucket TSV.
#
# stats TSV (one line):
#   total_blocks  total_txs  bucket_count  nonempty_bucket_count
#   max_shift_bp  max_dominance_bp  shift_breach_count  dominance_breach_count
#   overall_dominant_name  overall_dominant_bp
#
# bucket TSV (one line per bucket):
#   idx  first_block  last_block  txs  shift_bp  dominant_name  dominant_bp  shares_json
# where shares_json is a compact {"NAME":bp,...} map (bp = share in 0..10000)
# and shift_bp is the TVD (0..10000) vs the prior NON-EMPTY bucket, or -1 if
# this is the first non-empty bucket / the bucket is empty.
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_tx_mix_trend: cannot create temp file" >&2; exit 1;
}
TMP_BUCKETS=$(mktemp 2>/dev/null) || {
  echo "operator_tx_mix_trend: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" "$TMP_BUCKETS" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$BUCKET_BLOCKS" \
       "$MAX_SHIFT" "$MAX_DOMINANCE" "$TMP_STATS" "$TMP_BUCKETS" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_h, to_h, bucket_blocks,
 max_shift_pct, max_dominance_pct, stats_path, buckets_path) = sys.argv[1:10]
from_h            = int(from_h)
to_h              = int(to_h)
bucket_blocks     = int(bucket_blocks)
max_shift_bp      = int(max_shift_pct) * 100        # percent -> basis points
max_dominance_bp  = int(max_dominance_pct) * 100

# Canonical TxType integer -> name map (verbatim from
# operator_block_size_audit.sh so labels match across tools).
TX_TYPE_NAMES = {
    0:  "TRANSFER",
    1:  "REGISTER",
    2:  "DEREGISTER",
    3:  "STAKE",
    4:  "UNSTAKE",
    5:  "REGION_CHANGE",
    6:  "PARAM_CHANGE",
    7:  "MERGE_EVENT",
    8:  "COMPOSABLE_BATCH",
    9:  "DAPP_REGISTER",
    10: "DAPP_CALL",
}
def type_name(t):
    return TX_TYPE_NAMES.get(t, f"TYPE_{t}")

# Parallel lists keyed by relative window position.
heights      = []
per_block_ct = []   # defaultdict(int) of type_int -> count, per block

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_tx_mix_trend: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_tx_mix_trend: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_tx_mix_trend: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []
    ct = defaultdict(int)
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        t = tx.get("type", None)
        # type is serialized as int; guard bool (subclass of int) + non-int.
        if isinstance(t, bool) or not isinstance(t, int):
            continue
        ct[t] += 1

    heights.append(h)
    per_block_ct.append(ct)

total_blocks = len(heights)

# ── Bucketize: accumulate per-type counts per contiguous slice ────────────────
def share_vector(counts):
    """Return (total, {type_int: share_bp}) where share_bp sums to ~10000.
    Largest-remainder rounding so the basis-point shares sum to exactly
    10000 when total > 0 (keeps TVD well-formed)."""
    total = sum(counts.values())
    if total <= 0:
        return 0, {}
    raw = {}
    floors = {}
    rema = {}
    for t, c in counts.items():
        x = c * 10000.0 / total
        f = int(x)              # floor
        floors[t] = f
        rema[t] = x - f
        raw[t] = x
    assigned = sum(floors.values())
    leftover = 10000 - assigned
    # Distribute the leftover basis points to the largest remainders.
    order = sorted(rema.items(), key=lambda kv: (-kv[1], kv[0]))
    shares = dict(floors)
    i = 0
    while leftover > 0 and order:
        t = order[i % len(order)][0]
        shares[t] += 1
        leftover -= 1
        i += 1
    return total, shares

def tvd_bp(p, q):
    """Total variation distance (0..10000 basis points) between two
    share-vectors p and q (each {type:share_bp})."""
    keys = set(p) | set(q)
    s = 0
    for k in keys:
        s += abs(p.get(k, 0) - q.get(k, 0))
    return s // 2   # (1/2) * Σ|p-q|; both already in basis points

buckets = []   # list of dicts
for i in range(0, total_blocks, bucket_blocks):
    j = min(i + bucket_blocks, total_blocks)
    if j <= i:
        continue
    b_first = heights[i]
    b_last  = heights[j-1]
    agg = defaultdict(int)
    for k in range(i, j):
        for t, c in per_block_ct[k].items():
            agg[t] += c
    total, shares = share_vector(agg)
    # Dominant type within the bucket.
    if shares:
        dom_t = max(shares.items(), key=lambda kv: (kv[1], -kv[0]))[0]
        dom_name = type_name(dom_t)
        dom_bp = shares[dom_t]
    else:
        dom_name = ""
        dom_bp = 0
    buckets.append({
        "first": b_first, "last": b_last, "total": total,
        "shares": shares, "dom_name": dom_name, "dom_bp": dom_bp,
    })

# ── Adjacent (non-empty) bucket shift via TVD ─────────────────────────────────
prev_shares = None
max_shift   = 0
shift_breach = 0
dom_breach   = 0
max_dom      = 0
for b in buckets:
    if b["total"] <= 0:
        b["shift_bp"] = -1          # empty bucket: no defined distribution
        continue
    if prev_shares is None:
        b["shift_bp"] = -1          # first non-empty bucket: no predecessor
    else:
        sb = tvd_bp(prev_shares, b["shares"])
        b["shift_bp"] = sb
        if sb > max_shift:
            max_shift = sb
        if sb >= max_shift_bp:
            shift_breach += 1
    prev_shares = b["shares"]
    if b["dom_bp"] > max_dom:
        max_dom = b["dom_bp"]
    if b["dom_bp"] >= max_dominance_bp:
        dom_breach += 1

# ── Window-overall composition + dominant type ────────────────────────────────
win_agg = defaultdict(int)
for ct in per_block_ct:
    for t, c in ct.items():
        win_agg[t] += c
total_txs = sum(win_agg.values())
_, win_shares = share_vector(win_agg)
if win_shares:
    o_t = max(win_shares.items(), key=lambda kv: (kv[1], -kv[0]))[0]
    overall_dom_name = type_name(o_t)
    overall_dom_bp   = win_shares[o_t]
else:
    overall_dom_name = ""
    overall_dom_bp   = 0

nonempty_buckets = sum(1 for b in buckets if b["total"] > 0)

def shares_json(shares):
    # Sorted by share desc then type-int asc for stable output.
    items = sorted(shares.items(), key=lambda kv: (-kv[1], kv[0]))
    parts = [f'"{type_name(t)}":{bp}' for t, bp in items]
    return "{" + ",".join(parts) + "}"

with open(stats_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        total_blocks, total_txs, len(buckets), nonempty_buckets,
        max_shift, max_dom, shift_breach, dom_breach,
        overall_dom_name if overall_dom_name else "-", overall_dom_bp,
    ]) + "\n")

with open(buckets_path, "w", encoding="utf-8") as f:
    for idx, b in enumerate(buckets):
        f.write("\t".join(str(x) for x in [
            idx, b["first"], b["last"], b["total"], b["shift_bp"],
            b["dom_name"] if b["dom_name"] else "-", b["dom_bp"],
            shares_json(b["shares"]),
        ]) + "\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_tx_mix_trend: block-walk failed" >&2
  exit 1
fi

# ── Step 4: read stats back ───────────────────────────────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_tx_mix_trend: empty stats payload" >&2
  exit 1
fi
TOTAL_BLOCKS=$(printf '%s'      "$STATS_LINE" | cut -f1)
TOTAL_TXS=$(printf '%s'         "$STATS_LINE" | cut -f2)
BUCKET_COUNT=$(printf '%s'      "$STATS_LINE" | cut -f3)
NONEMPTY_BUCKETS=$(printf '%s'  "$STATS_LINE" | cut -f4)
MAX_SHIFT_BP=$(printf '%s'      "$STATS_LINE" | cut -f5)
MAX_DOM_BP=$(printf '%s'        "$STATS_LINE" | cut -f6)
SHIFT_BREACH=$(printf '%s'      "$STATS_LINE" | cut -f7)
DOM_BREACH=$(printf '%s'        "$STATS_LINE" | cut -f8)
OVERALL_DOM_NAME=$(printf '%s'  "$STATS_LINE" | cut -f9)
OVERALL_DOM_BP=$(printf '%s'    "$STATS_LINE" | cut -f10)

# Render a basis-point value (0..10000) as "NN.N%".
render_bp() {
  local bp="$1"
  case "$bp" in *[!0-9]*|"") echo "0.0"; return ;; esac
  local whole=$(( bp / 100 ))
  local frac=$(( (bp % 100) / 10 ))
  printf '%d.%d' "$whole" "$frac"
}

# ── Step 5: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
# empty_window: no transactions anywhere in the window. Informational.
if [ "${TOTAL_TXS:-0}" -le 0 ] 2>/dev/null; then add_anom "empty_window"; fi
# mix_shift_detected: at least one adjacent-bucket TVD reached the threshold.
if [ "${SHIFT_BREACH:-0}" -gt 0 ] 2>/dev/null; then add_anom "mix_shift_detected"; fi
# type_dominance_high: at least one bucket monopolized by a single type.
if [ "${DOM_BREACH:-0}" -gt 0 ] 2>/dev/null; then add_anom "type_dominance_high"; fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 6: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  BUCKETS_JSON="[]"
  if [ -s "$TMP_BUCKETS" ]; then
    BUCKETS_JSON=$(awk -F'\t' '
      BEGIN { printf "[" }
      {
        if (NR > 1) printf ",";
        # $5 shift_bp may be -1 (no predecessor / empty) -> emit null.
        shift = ($5 == -1) ? "null" : $5;
        printf "{\"index\":%s,\"first_block\":%s,\"last_block\":%s,\"txs\":%s,\"shift_bp\":%s,\"dominant_type\":\"%s\",\"dominant_share_bp\":%s,\"shares_bp\":%s}",
          $1, $2, $3, $4, shift, $6, $7, $8
      }
      END { printf "]" }
    ' "$TMP_BUCKETS")
    if command -v jq >/dev/null 2>&1; then
      BUCKETS_JSON=$(printf '%s' "$BUCKETS_JSON" | jq -c .)
    fi
  fi
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_blocks":%s,"total_txs":%s,' "$TOTAL_BLOCKS" "$TOTAL_TXS"
  printf '"bucket_blocks":%s,"bucket_count":%s,"nonempty_bucket_count":%s,' \
    "$BUCKET_BLOCKS" "$BUCKET_COUNT" "$NONEMPTY_BUCKETS"
  printf '"overall_dominant_type":"%s","overall_dominant_share_bp":%s,' \
    "$OVERALL_DOM_NAME" "$OVERALL_DOM_BP"
  printf '"max_shift_bp":%s,"max_dominance_bp":%s,' "$MAX_SHIFT_BP" "$MAX_DOM_BP"
  printf '"max_shift_threshold_bp":%s,"max_dominance_threshold_bp":%s,' \
    "$(( MAX_SHIFT * 100 ))" "$(( MAX_DOMINANCE * 100 ))"
  printf '"shift_breach_count":%s,"dominance_breach_count":%s,' \
    "$SHIFT_BREACH" "$DOM_BREACH"
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
    echo "operator_tx_mix_trend: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== TX mix trend (port $PORT, window [$FROM..$TO], $TOTAL_BLOCKS blocks, $TOTAL_TXS txs) ==="
    if [ "${TOTAL_TXS:-0}" -gt 0 ] 2>/dev/null; then
      printf "Overall dominant type: %s (%s%% of window txs)\n" \
        "$OVERALL_DOM_NAME" "$(render_bp "$OVERALL_DOM_BP")"
    else
      echo "Overall dominant type: (none — window is empty of transactions)"
    fi
    printf "Max adjacent-bucket shift (TVD): %s%% (threshold %s%%)\n" \
      "$(render_bp "$MAX_SHIFT_BP")" "$MAX_SHIFT"
    if [ "$ANOM_ONLY" != "1" ]; then
      echo "Per-bucket composition trend:"
      if [ ! -s "$TMP_BUCKETS" ]; then
        echo "  (no buckets — empty window)"
      else
        while IFS=$'\t' read -r BIDX BFIRST BLAST BTXS BSHIFT BDOM BDOMBP BSHARES; do
          if [ "$BSHIFT" = "-1" ]; then
            SHIFT_STR="shift n/a"
          else
            SHIFT_STR="shift $(render_bp "$BSHIFT")%"
          fi
          printf "  blocks %s-%s: %s txs, dominant %s %s%%, %s, mix=%s\n" \
            "$BFIRST" "$BLAST" "$BTXS" "$BDOM" "$(render_bp "$BDOMBP")" \
            "$SHIFT_STR" "$BSHARES"
        done <"$TMP_BUCKETS"
      fi
    fi
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] tx mix composed; no shift/dominance anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      case ",$ANOMALIES," in
        *,mix_shift_detected,*)
          printf "  mix_shift_detected   : %s adjacent bucket pair(s) reached %s%% TVD (max %s%%) — workload regime change\n" \
            "$SHIFT_BREACH" "$MAX_SHIFT" "$(render_bp "$MAX_SHIFT_BP")" ;;
      esac
      case ",$ANOMALIES," in
        *,type_dominance_high,*)
          printf "  type_dominance_high  : %s bucket(s) had a single type >= %s%% (max %s%%) — possible runaway/stuck workload\n" \
            "$DOM_BREACH" "$MAX_DOMINANCE" "$(render_bp "$MAX_DOM_BP")" ;;
      esac
      case ",$ANOMALIES," in
        *,empty_window,*)
          echo "  empty_window         : no transactions in the window; no mix to trend" ;;
      esac
    fi
  fi
fi

# ── Step 7: exit-code policy ──────────────────────────────────────────────────
# Same convention as operator_reward_budget / operator_tx_throughput:
# exit 2 only when --anomalies-only is set AND >= 1 anomaly fired.
# Default informational mode always exits 0 if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
