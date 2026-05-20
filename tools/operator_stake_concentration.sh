#!/usr/bin/env bash
# operator_stake_concentration.sh — Measure stake-distribution
# (in)equality of a running determ chain via the Gini coefficient on
# the live validator-stake set, plus a top-N concentration audit.
#
# Sibling of operator_balance_distribution.sh: same metric set (Gini,
# percentiles, top-N), different field (stake instead of balance) and
# different population (the active validator set, not the full ledger).
#
# Why this matters separately from balance_distribution:
#   Stakes drive committee selection. The producer/signer pool is
#   sampled via stake-weighted Fisher-Yates (see S-020 + crypto/
#   select_m_creators.cpp), so a single validator with > 50% of total
#   stake is selected proportionally more often. A high stake Gini is
#   therefore a direct consensus-fairness signal, distinct from the
#   wealth-distribution signal that balance_distribution measures.
#
# Pipeline (read-only RPC):
#   1.  `determ stakes --json --rpc-port P` — flat JSON array of
#       {rank, domain, stake, active_from, region, ed_pub}. Already
#       sorted by stake DESC, ties broken by domain ASC. This is
#       node.cpp::rpc_validators() materialized through the `stakes`
#       CLI which adds the rank field. We use the full list (no --top
#       cap) because the Gini denominator must include every entry.
#   2.  (optional, for the min_stake_skew anomaly) `determ snapshot
#       create` → tmp file → `determ snapshot inspect --in <tmp>
#       --json` to recover the chain's `min_stake` threshold. This is
#       a one-off cost paid only when --skip-snapshot is NOT passed;
#       JSON consumers that don't care about min_stake_skew can opt
#       out and run RPC-only.
#   3.  Python computes:
#       - Total stake (Σ over all returned entries).
#       - Per-validator stake / share = stake / total.
#       - Gini coefficient over the stake distribution. Sorted-form
#         G = Σᵢ (2i − n − 1) sᵢ / (n Σ sᵢ) (1-indexed i over
#         non-decreasing sort), algebraically identical to the
#         textbook G = Σᵢⱼ |sᵢ − sⱼ| / (2n Σ sᵢ) but O(n log n) vs
#         O(n²). Same implementation as balance_distribution.sh.
#       - Top-1, top-3, top-10 collective shares (integer basis
#         points so threshold comparisons are exact, no float-equality
#         hazards).
#       - Per-decile breakdown: p90 (top 10%), p99 (top 1%), median.
#
# Anomaly flags (each adds to anomalies[]; --anomalies-only exits 2):
#   - stake_gini_high          Gini > --gini-threshold (default 0.6).
#                              Stake Gini ≥ 0.6 means a small validator
#                              cohort holds most of the consensus weight;
#                              defense in depth via S-010 / FA6 still
#                              applies but selection rotation becomes
#                              skewed and BFT-quorum diversity drops.
#   - top1_validator_dominant  Top-1 validator share > --top-n-
#                              concentration (default 0.50). A single
#                              actor controlling > 50% of stake is the
#                              consensus-centralization signal — even
#                              under FA6 equivocation slashing, the
#                              S-011 cartel-resistance proof requires
#                              majority-honest stake, and this anomaly
#                              flags any drift below that floor.
#   - min_stake_skew           Floor effect: at least one entry's
#                              `stake` exactly equals the chain's
#                              `min_stake` AND the entry count at the
#                              floor exceeds floor-share-threshold
#                              (>=25% of validators at the floor).
#                              Potential floor-effect Sybil — many
#                              minimum-stake registrants is the
#                              cheapest way to pack the pool. Requires
#                              snapshot inspect; skipped under
#                              --skip-snapshot.
#   - total_stake_zero         Σ stakes == 0 (chain-bootstrap edge
#                              case OR catastrophic stake-loss event).
#                              When this fires the Gini is undefined
#                              and all share metrics collapse to 0;
#                              the alert IS the value.
#
# RPC dependencies (read-only):
#   - head                     current chain height (banner only)
#   - stakes                   full validator set + stake
#   - snapshot create          for min_stake_skew, optional
#   - snapshot inspect         for min_stake recovery, optional
#
# Usage:
#   tools/operator_stake_concentration.sh [--rpc-port N] [--json]
#                                         [--gini-threshold F]
#                                         [--top-n-concentration F]
#                                         [--anomalies-only]
#                                         [--skip-snapshot]
#
# Options:
#   --rpc-port N              RPC port to query (required)
#   --gini-threshold F        Flag stake Gini > F (default: 0.6)
#   --top-n-concentration F   Flag top-1 share > F (default: 0.50)
#   --json                    Emit structured JSON envelope
#   --anomalies-only          Print only flagged anomalies; exit 2 if any fire
#   --skip-snapshot           Skip snapshot inspect (disables min_stake_skew)
#   -h, --help                Show this help
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_stake_concentration.sh --rpc-port N [--json]
                                       [--gini-threshold F]
                                       [--top-n-concentration F]
                                       [--anomalies-only]
                                       [--skip-snapshot]

Measure stake-distribution (in)equality on a running determ daemon
via the Gini coefficient on the active validator set, plus top-1 /
top-3 / top-10 concentration and a per-decile breakdown.

Sibling of operator_balance_distribution.sh; same metric, different
field. Stakes drive committee selection so stake concentration is a
direct consensus-fairness signal distinct from the wealth-distribution
signal that balance_distribution measures.

Options:
  --rpc-port N              RPC port to query (required)
  --gini-threshold F        Flag stake Gini > F (default: 0.6)
  --top-n-concentration F   Flag top-1 share > F (default: 0.50)
  --json                    Emit structured JSON envelope
  --anomalies-only          Print only flagged anomalies; exit 2 if any fire
  --skip-snapshot           Skip snapshot inspect (disables min_stake_skew)
  -h, --help                Show this help

Anomaly flags:
  stake_gini_high           Gini > --gini-threshold
  top1_validator_dominant   top-1 share > --top-n-concentration
  min_stake_skew            ≥25% of validators at chain min_stake floor
  total_stake_zero          Σ stakes == 0 (bootstrap / catastrophic loss)

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
SKIP_SNAPSHOT=0
GINI_THRESHOLD="0.6"
TOPN_CONCENTRATION="0.50"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                usage; exit 0 ;;
    --rpc-port)               PORT="${2:-}";                  shift 2 ;;
    --json)                   JSON_OUT=1;                     shift ;;
    --gini-threshold)         GINI_THRESHOLD="${2:-}";        shift 2 ;;
    --top-n-concentration)    TOPN_CONCENTRATION="${2:-}";    shift 2 ;;
    --anomalies-only)         ANOM_ONLY=1;                    shift ;;
    --skip-snapshot)          SKIP_SNAPSHOT=1;                shift ;;
    *) echo "operator_stake_concentration: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required per the spec.
case "$PORT" in *[!0-9]*|"")
  echo "operator_stake_concentration: --rpc-port is required and must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Float guards on the two threshold knobs. Accept the standard decimal
# forms (e.g. "0.6", "0.50", "1.0"). Reject anything that python can't
# parse — caught downstream but cheaper to fail fast.
validate_float() {
  local name="$1" val="$2"
  case "$val" in
    ""|*[!0-9.]*)
      echo "operator_stake_concentration: $name must be a decimal in [0,1] (got '$val')" >&2
      exit 1 ;;
  esac
  # Range check via python so we don't reimplement float compare in
  # POSIX shell. Both thresholds are share-of-total-stake numbers, so
  # they must land in [0.0, 1.0] inclusive. 0.0 and 1.0 are valid
  # corner cases (always-fire / never-fire).
  if ! python -c "import sys; v=float('$val'); sys.exit(0 if 0.0<=v<=1.0 else 1)" 2>/dev/null; then
    echo "operator_stake_concentration: $name must be in [0.0, 1.0] (got '$val')" >&2
    exit 1
  fi
}
validate_float "--gini-threshold"      "$GINI_THRESHOLD"
validate_float "--top-n-concentration" "$TOPN_CONCENTRATION"

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current chain head (banner only) ─────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_concentration: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_stake_concentration: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: fetch full stakes list (NO --top cap; we need everything) ────────
STAKES_OUT=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_concentration: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

# ── Step 3: optional snapshot for min_stake recovery ─────────────────────────
# Pulled only for the min_stake_skew anomaly. Operators who don't care
# about floor-effect Sybil detection can pass --skip-snapshot to drop
# the snapshot RPC + the disk I/O of the temp file.
TMP_SNAP=""
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_stake_concentration: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" 2>/dev/null' EXIT

MIN_STAKE=""
if [ "$SKIP_SNAPSHOT" = "0" ]; then
  TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
    echo "operator_stake_concentration: cannot create temp file" >&2; exit 1;
  }
  if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
    echo "operator_stake_concentration: snapshot create failed (port $PORT)" >&2
    exit 1
  fi
  INSPECT_OUT=$("$DETERM" snapshot inspect --in "$TMP_SNAP" --json 2>&1) || {
    echo "operator_stake_concentration: snapshot inspect failed (malformed snapshot)" >&2
    echo "$INSPECT_OUT" >&2
    exit 1
  }
  if [ "$HAVE_JQ" = "1" ]; then
    MIN_STAKE=$(printf '%s' "$INSPECT_OUT" | jq -r '.min_stake // 0')
  else
    MIN_STAKE=$(printf '%s' "$INSPECT_OUT" | grep -o '"min_stake":[0-9]*' | head -1 | sed 's/.*://')
  fi
  case "$MIN_STAKE" in *[!0-9]*|"") MIN_STAKE=0 ;; esac
fi

# ── Step 4: compute concentration metrics via Python ─────────────────────────
# Same Gini sorted-form as operator_balance_distribution. Top-N share
# arithmetic uses integer basis points (b * 10000 // total) so the
# threshold compares are exact — no float-equality drift on tie-break.
python - "$STAKES_OUT" "$TMP_OUT" "$GINI_THRESHOLD" \
        "$TOPN_CONCENTRATION" "${MIN_STAKE:-0}" "$SKIP_SNAPSHOT" <<'PY'
import json, sys

stakes_raw, out_path, gini_thr_s, top1_thr_s, min_stake_s, skip_snap_s = sys.argv[1:7]
gini_threshold      = float(gini_thr_s)
top1_threshold      = float(top1_thr_s)
min_stake           = int(min_stake_s)
skip_snapshot       = skip_snap_s == "1"

# Threshold-bps form: gini_threshold * 10000, top1_threshold * 10000.
# Using basis-point integers everywhere keeps the comparisons exact:
# 0.50 → 5000, 0.6 → 6000. We use STRICT > so 0.50 is "not flagged at
# exactly 50.00%" — matches the operator_balance_distribution
# convention (whale_dominance uses bps > 5000 too).
gini_thr_bps = int(round(gini_threshold * 10000))
top1_thr_bps = int(round(top1_threshold * 10000))

try:
    stakes = json.loads(stakes_raw)
except Exception as e:
    sys.stderr.write(f"operator_stake_concentration: cannot parse stakes JSON: {e}\n")
    sys.exit(1)
if not isinstance(stakes, list):
    sys.stderr.write("operator_stake_concentration: stakes RPC is not a JSON array\n")
    sys.exit(1)

# Materialize per-validator records. The RPC already returns them
# sorted by stake DESC with ties broken by domain ASC, but we re-sort
# defensively so the script is robust against any future RPC reorder.
validators = []
for v in stakes:
    if not isinstance(v, dict):
        continue
    d = v.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    s = int(v.get("stake", 0) or 0)
    validators.append({"domain": d, "stake": s})

total_validators = len(validators)
# Total stake = denominator of every share calculation below. Σ over
# every returned entry (including zero-stake registrants — they're
# still part of the pool count, just contribute 0 to the sum and 0 to
# the Gini numerator).
total_stake = sum(v["stake"] for v in validators)

# Sort DESC by stake, ASC by domain on tie. This matches the RPC's
# order so the top_validators array is unchanged in the common case
# but guaranteed under any future RPC reorder.
validators.sort(key=lambda v: (-v["stake"], v["domain"]))

# Compute per-validator share in basis points (b * 10000 // total).
# Integer division means the last entry's share may be < (stake /
# total) * 10000 by 1 bps; cumulative shares may not sum to exactly
# 10000. Standard floor-division residual, same convention as
# operator_balance_distribution.
for v in validators:
    v["share_bps"] = (v["stake"] * 10000 // total_stake) if total_stake > 0 else 0

# Gini computation (sorted-form). Identical implementation to
# operator_balance_distribution.sh — Σᵢ (2i − n − 1) sᵢ / (n Σ sᵢ),
# 1-indexed i over a non-decreasing sort. See balance_distribution
# header comment for the algebraic derivation.
#
# Edge cases:
#   - n == 0:           empty pool → Gini undefined (None).
#   - n == 1:           single staker → Gini == 0 by the formula
#                       (the sole (2*1 − 1 − 1) = 0 coefficient).
#                       Concentration signal is still captured via
#                       top1_share = 100% triggering
#                       top1_validator_dominant.
#   - total_stake == 0: all-zero pool → Gini undefined (None);
#                       total_stake_zero anomaly fires.
gini = None
gini_bps = 0
if total_validators >= 2 and total_stake > 0:
    stakes_asc = sorted(v["stake"] for v in validators)
    n = total_validators
    weighted_sum = 0
    for i, s in enumerate(stakes_asc, start=1):
        weighted_sum += (2 * i - n - 1) * s
    denom = n * total_stake
    gini = weighted_sum / denom
    if gini < 0.0:
        gini = 0.0
    gini_bps = int(round(gini * 10000))

# Top-1 / top-3 / top-10 collective shares. validators is already DESC
# by stake so the slice gives us the highest contributors.
def cumulative_share_bps(items, k):
    if total_stake <= 0:
        return 0
    cum = sum(v["stake"] for v in items[:k])
    return (cum * 10000) // total_stake

top1_bps  = cumulative_share_bps(validators, 1)
top3_bps  = cumulative_share_bps(validators, 3)
top10_bps = cumulative_share_bps(validators, 10)

# Per-decile breakdown: p90 (top 10%), p99 (top 1%), median. Use
# nearest-rank percentile (1-indexed) over the ASCENDING-sorted list
# so the indexing matches balance_distribution.sh exactly. Note: p90
# of the ascending list is the lower bound of the "top 10%" cohort,
# which is the natural reading-direction for stake (we report the
# threshold a validator must clear to land in the top decile).
def nearest_rank(sorted_list, pct):
    n = len(sorted_list)
    if n == 0:
        return None
    rank = max(1, (pct * n + 99) // 100)
    if rank > n:
        rank = n
    return sorted_list[rank - 1]

stakes_asc_list = sorted(v["stake"] for v in validators)
p50    = nearest_rank(stakes_asc_list, 50)   # median
p90    = nearest_rank(stakes_asc_list, 90)   # top-10% threshold
p99    = nearest_rank(stakes_asc_list, 99)   # top-1% threshold

# Anomaly classification.
anomalies = []
# total_stake_zero: empty / catastrophic-loss case. Emit this FIRST so
# downstream tooling can short-circuit on the more-fundamental signal
# rather than wading through implied-meaningless Gini / share values.
if total_stake == 0:
    anomalies.append("total_stake_zero")
# stake_gini_high: > threshold-bps. Strict > matches the
# operator_balance_distribution semantics.
if gini is not None and gini_bps > gini_thr_bps:
    anomalies.append("stake_gini_high")
# top1_validator_dominant: single-actor consensus-centralization.
if total_stake > 0 and top1_bps > top1_thr_bps:
    anomalies.append("top1_validator_dominant")
# min_stake_skew: floor-effect Sybil indicator. Suppressed under
# --skip-snapshot (we don't have a min_stake reading) and degenerate
# at total_validators <= 1 (need a non-trivial pool to talk about
# "floor share"). Threshold: >=25% of the validator set sitting
# exactly at the chain's min_stake. The 25% level is the same order
# as the FA6 < 1/3 cartel-resistance margin; once the floor cohort
# exceeds it, you start losing diversity even before the cohort
# exercises BFT power.
floor_count = 0
floor_share_bps = 0
if not skip_snapshot and total_validators >= 2 and min_stake > 0:
    floor_count = sum(1 for v in validators if v["stake"] == min_stake)
    floor_share_bps = (floor_count * 10000) // total_validators
    if floor_share_bps >= 2500:  # 25.00%
        anomalies.append("min_stake_skew")

# Top validators table for the human-readable output. Top-20 by stake,
# unless the pool is smaller in which case we emit everything.
top_validators = []
for i, v in enumerate(validators[:20], start=1):
    top_validators.append({
        "rank":       i,
        "domain":     v["domain"],
        "stake":      v["stake"],
        "share_bps":  v["share_bps"],
    })

result = {
    "total_validators":     total_validators,
    "total_stake":          total_stake,
    "gini":                 gini,
    "gini_ten_thousandths": gini_bps,
    "gini_threshold":       gini_threshold,
    "gini_threshold_bps":   gini_thr_bps,
    "top1_share_bps":       top1_bps,
    "top3_share_bps":       top3_bps,
    "top10_share_bps":      top10_bps,
    "top1_threshold":       top1_threshold,
    "top1_threshold_bps":   top1_thr_bps,
    "by_decile": {
        "p50_median":  p50,
        "p90":         p90,
        "p99":         p99,
    },
    "top_validators":       top_validators,
    "min_stake":            min_stake if not skip_snapshot else None,
    "floor_count":          floor_count,
    "floor_share_bps":      floor_share_bps,
    "skip_snapshot":        skip_snapshot,
    "anomalies":            anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_stake_concentration: distribution computation failed" >&2
  exit 1
fi

# ── Step 5: render envelope (JSON or human) ─────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
head_h    = int(sys.argv[5])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total_validators = r["total_validators"]
total_stake      = r["total_stake"]
gini             = r["gini"]
gini_bps         = r["gini_ten_thousandths"]
gini_thr         = r["gini_threshold"]
gini_thr_bps     = r["gini_threshold_bps"]
top1_bps         = r["top1_share_bps"]
top3_bps         = r["top3_share_bps"]
top10_bps        = r["top10_share_bps"]
top1_thr         = r["top1_threshold"]
top1_thr_bps     = r["top1_threshold_bps"]
deciles          = r["by_decile"]
top_validators   = r["top_validators"]
min_stake        = r["min_stake"]
floor_count      = r["floor_count"]
floor_share_bps  = r["floor_share_bps"]
skip_snapshot    = r["skip_snapshot"]
anomalies        = r["anomalies"]
anom_count       = len(anomalies)

def render_bps_pct(bps):
    """bps in 0..10000 → 'XX.X%' (one decimal of precision)."""
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def render_gini(bps):
    """gini bps (0..10000) → '0.XXXX' (four-decimal canonical form)."""
    return f"{bps // 10000}.{bps % 10000:04d}"

def short(addr):
    if isinstance(addr, str) and addr.startswith("0x") and len(addr) >= 10:
        return addr[:10] + "..."
    if isinstance(addr, str) and len(addr) > 32:
        return addr[:29] + "..."
    return addr

if json_out:
    envelope = {
        "rpc_port":           port,
        "head_height":        head_h,
        "total_validators":   total_validators,
        "total_stake":        total_stake,
        "gini":               gini,
        "gini_ten_thousandths": gini_bps,
        "gini_threshold":     gini_thr,
        "top1_share":         top1_bps / 10000.0,
        "top1_share_bps":     top1_bps,
        "top3_share":         top3_bps / 10000.0,
        "top3_share_bps":     top3_bps,
        "top10_share":        top10_bps / 10000.0,
        "top10_share_bps":    top10_bps,
        "top1_threshold":     top1_thr,
        "by_decile":          deciles,
        "top_validators":     top_validators,
        "min_stake":          min_stake,
        "floor_count":        floor_count,
        "floor_share_bps":    floor_share_bps,
        "skip_snapshot":      skip_snapshot,
        "anomalies":          anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_stake_concentration: no anomalies (port {port})")
    sys.exit(0)

print(f"=== Stake concentration (port {port}) ===")
print(f"Chain height:       {head_h}")
print(f"Total validators:   {total_validators}")
print(f"Total stake:        {total_stake}")
if gini is None:
    print("Gini coefficient:   n/a (fewer than 2 validators or zero total stake)")
else:
    print(f"Gini coefficient:   {render_gini(gini_bps)} "
          f"(threshold {render_gini(gini_thr_bps)})")
if min_stake is not None:
    print(f"Chain min_stake:    {min_stake}")
elif not skip_snapshot:
    print("Chain min_stake:    (snapshot unavailable)")

if not anom_only:
    if top_validators:
        shown = len(top_validators)
        print(f"Top-{shown} by stake:")
        for v in top_validators:
            print(f"  {v['rank']:>2}. {short(v['domain']):<35} "
                  f"stake={v['stake']:<18} share={render_bps_pct(v['share_bps'])}")
        print(f"Top-1 share:  {render_bps_pct(top1_bps)} "
              f"(threshold {render_bps_pct(top1_thr_bps)})")
        print(f"Top-3 share:  {render_bps_pct(top3_bps)}")
        print(f"Top-10 share: {render_bps_pct(top10_bps)}")
    else:
        print("Top-N by stake: (none; empty validator set)")

    # Per-decile breakdown of the stake distribution. We report the
    # ascending-sorted percentile values: p50 (median validator),
    # p90 (threshold for the top 10% cohort), p99 (threshold for the
    # top 1% cohort). At small n some of these collapse onto the same
    # value — that's not a bug, it's the geometry of the distribution.
    if total_validators > 0:
        print("Decile breakdown:")
        print(f"  median (p50)   stake={deciles['p50_median']}")
        print(f"  top-10% (p90)  stake={deciles['p90']}")
        print(f"  top-1%  (p99)  stake={deciles['p99']}")
    else:
        print("Decile breakdown: n/a (empty validator set)")

    if min_stake is not None and total_validators >= 2:
        print(f"Floor cohort:   {floor_count} validator(s) at min_stake "
              f"({render_bps_pct(floor_share_bps)} of pool)")

print()
if anom_count == 0:
    print("[OK] Stake distribution within configured thresholds")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "total_stake_zero" in anomalies:
        print(f"  total_stake_zero        : Σ stakes == 0 "
              f"(bootstrap or catastrophic stake loss)")
    if "stake_gini_high" in anomalies:
        print(f"  stake_gini_high         : Gini = {render_gini(gini_bps)} "
              f"(> {render_gini(gini_thr_bps)} threshold)")
    if "top1_validator_dominant" in anomalies:
        print(f"  top1_validator_dominant : top-1 share = {render_bps_pct(top1_bps)} "
              f"(> {render_bps_pct(top1_thr_bps)} threshold)")
    if "min_stake_skew" in anomalies:
        print(f"  min_stake_skew          : {floor_count}/{total_validators} "
              f"validators at min_stake = {min_stake} "
              f"({render_bps_pct(floor_share_bps)} >= 25.0% threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_stake_concentration: rendering failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ────────────────────────────────────────────────
# Mirrors operator_balance_distribution: exit 2 only when --anomalies-only
# is set AND ≥1 anomaly fired. Default informational mode always exits 0
# if the RPC pipeline succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_stake_concentration: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(str(len(r.get("anomalies", []))))
PY
ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
