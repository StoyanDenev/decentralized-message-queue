#!/usr/bin/env bash
# operator_subsidy_accrual_audit.sh — Per-validator TIME-BUCKETED subsidy
# accrual + bucketed trend slope + concentration audit.
#
# Read-only RPC composition; safe against a producing daemon. Walks a
# block window via `determ block-info <h> --json` (one round-trip per
# block) and attributes per-block subsidy across `creators[]` per the
# apply-side rule in chain.cpp::apply_block (FA-Apply-7):
#
#     total_distributed = total_fees + subsidy_this_block
#     per_creator       = subsidy_this_block / m_creators
#     remainder         = subsidy_this_block % m_creators  → creators[0]
#
# Where this script differs from siblings:
#
#   operator_subsidy_audit.sh             — BLOCK-LEVEL attribution
#                                           (per-block distribution + total
#                                            credit, no time bucketing).
#
#   operator_subsidy_lottery_audit.sh     — LOTTERY-mode chi-squared
#                                           fairness on per-creator hit
#                                           rate.
#
#   operator_subsidy_pool_health.sh       — POOL-DRAIN projection (E1 NEF
#                                           pool depletion + E4 finite
#                                           subsidy_pool exhaustion).
#
#   operator_stake_yield.sh               — yield = (subsidy+fees) / stake;
#                                           per-validator window total.
#
#   operator_subsidy_accrual_audit.sh     — THIS script: per-validator
#                                           TIME-BUCKETED accrual curve +
#                                           trend slope across buckets +
#                                           dormancy detection +
#                                           concentration ratio.
#
# Model:
#   Walk blocks in window. For each block, look at creators[]. Attribute
#   each creator one share of subsidy_this_block (equal split + remainder
#   to creators[0], matching chain.cpp). Aggregate per-validator per-
#   bucket. Bucket numbering starts at FROM and rolls forward in chunks
#   of --bucket-blocks N.
#
#   Per validator we report:
#
#     total                    Σ subsidy_in_window
#     buckets                  list of {bucket_from, bucket_to, subsidy}
#                              with one row per bucket (incl. zero-row
#                              buckets — needed for trend stability)
#     trend_slope              least-squares slope of subsidy_in_bucket
#                              vs bucket_idx (units: subsidy per bucket)
#     in_stakes                whether currently in `determ stakes` (used
#                              to discriminate dormancy from natural
#                              non-participation)
#
# Anomalies:
#
#   subsidy_drift_high       (WARN) any validator with
#                            |trend_slope| > 0.50 * median_total_per_bucket
#                            (sustained over- OR under-accrual; per spec).
#                            Threshold computed *across validators* on the
#                            median per-bucket total — gives a magnitude
#                            scale so trend slope is comparable to "what's
#                            normal" rather than an absolute value.
#                            Requires ≥3 buckets for slope stability.
#
#   validator_zero_in_window (INFO) any validator currently in
#                            `determ stakes` (stake > 0) but zero subsidy
#                            credited across the entire window.
#                            Distinct from operator_subsidy_audit's
#                            concentration metric — this is the
#                            "validator was excluded from committee"
#                            signal.
#
#   max_to_median_ratio_high (WARN) top-1 validator's window-total
#                            > 3 * median across non-zero validators.
#                            Concentration signal that's NORMALIZED to
#                            median (robust to outliers vs share_bps
#                            which would saturate when committee shrinks).
#                            Requires ≥3 non-zero validators (else
#                            ratio is degenerate / always-true).
#
# JSON shape:
#   {"rpc_port": P, "head_height": H,
#    "window": {"from": F, "to": T, "blocks": W},
#    "bucket_blocks": B, "bucket_count": K,
#    "block_subsidy": V, "block_subsidy_source": S,
#    "validators": [
#      {"domain": D, "buckets": [{"bucket_from": F, "bucket_to": T,
#                                 "subsidy": V}, ...],
#       "total": T, "trend_slope": SL, "in_stakes": bool}, ...],
#    "summary": {"n_validators": N, "n_dormant": D,
#                "median_total": M, "max_total": MX,
#                "max_to_median_ratio": R, "median_per_bucket": MPB},
#    "anomalies": [...]}
#
# Exit codes:
#   0   audit ran; no anomalies (or default informational mode)
#   1   bad args / RPC error / malformed response
#   2   --anomalies-only AND ≥1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_subsidy_accrual_audit.sh --rpc-port N
                                         [--from H] [--to H]
                                         [--bucket-blocks N]
                                         [--block-subsidy V]
                                         [--json] [--anomalies-only]

Per-validator TIME-BUCKETED subsidy accrual audit. Walks the block
window, attributes subsidy_this_block / m_creators to each creator per
chain.cpp::apply_block (FA-Apply-7), aggregates per-validator per-
bucket, and reports total + bucketed trend slope + concentration ratio.

Required:
  --rpc-port N            RPC port to query (default: 8545)

Window:
  --from H                Start of audit window (inclusive)
  --to H                  End   of audit window (inclusive)
                          Default: last 5000 blocks ending at head
  --bucket-blocks N       Bucket size in blocks (default: 1000)

Distribution basis:
  --block-subsidy V       Per-block subsidy value (overrides auto-detect).
                          If omitted, auto-detected from supply RPC as
                          accumulated_subsidy / head_height (FLAT-mode
                          exact / LOTTERY-mode expectation).

Output:
  --json                  Emit structured JSON envelope
  --anomalies-only        Suppress healthy rows; exit 2 if any fire
  -h, --help              Show this help

Anomalies:
  subsidy_drift_high       WARN  — |trend_slope| > 0.50 * median per-
                                   bucket total (per-validator sustained
                                   over- OR under-accrual)
  validator_zero_in_window INFO  — in `determ stakes` but zero subsidy
                                   credited across the window
  max_to_median_ratio_high WARN  — top-1 validator total > 3x median
                                   across non-zero validators

Exit codes:
  0   audit ran successfully; no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT="8545"
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
BUCKET_BLOCKS="1000"
BLOCK_SUBSIDY_OVR=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           PORT="${2:-}";              shift 2 ;;
    --from)               FROM_H="${2:-}";            shift 2 ;;
    --to)                 TO_H="${2:-}";              shift 2 ;;
    --bucket-blocks)      BUCKET_BLOCKS="${2:-}";     shift 2 ;;
    --block-subsidy)      BLOCK_SUBSIDY_OVR="${2:-}"; shift 2 ;;
    --json)               JSON_OUT=1;                 shift ;;
    --anomalies-only)     ANOM_ONLY=1;                shift ;;
    *) echo "operator_subsidy_accrual_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port numeric guard.
case "$PORT" in *[!0-9]*|"")
  echo "operator_subsidy_accrual_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Window-bound + bucket + override numeric guards.
for v in "$FROM_H" "$TO_H" "$BLOCK_SUBSIDY_OVR"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_subsidy_accrual_audit: numeric option must be unsigned integer (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_subsidy_accrual_audit: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" = "0" ]; then
  echo "operator_subsidy_accrual_audit: --bucket-blocks must be >= 1" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to absolute path so subprocess.run works under MSYS-
# virtualized Git Bash (matches operator_validator_uptime + operator_subsidy_audit).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain head + accumulated_subsidy ─────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_accrual_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_subsidy_accrual_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

ACCUM=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_accrual_audit: cannot reach supply RPC (port $PORT)" >&2
  exit 1
}
case "$ACCUM" in *[!0-9]*|"")
  echo "operator_subsidy_accrual_audit: supply returned non-numeric '$ACCUM' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: resolve window bounds ───────────────────────────────────────────
# Index semantics: `head --field height` returns *total block count*
# (block 0 = genesis); highest valid index = height - 1. Default window
# is last 5000 blocks ending at the top (per spec).
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -z "$FROM_H" ]; then
  if [ "$TOP" -gt 4999 ]; then
    FROM=$(( TOP - 4999 ))
  else
    FROM=0
  fi
else
  FROM=$FROM_H
fi
if [ -z "$TO_H" ]; then
  TO=$TOP
else
  TO=$TO_H
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_subsidy_accrual_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: determine per-block subsidy basis ───────────────────────────────
# Precedence: --block-subsidy override > lifetime-average heuristic
# (accumulated_subsidy / head_height). The heuristic is exact for FLAT
# chains without slashing-during-apply and an expectation for LOTTERY.
if [ -n "$BLOCK_SUBSIDY_OVR" ]; then
  EST_PER_BLOCK=$BLOCK_SUBSIDY_OVR
  EST_SOURCE="override"
elif [ "$HEAD_H" -gt 0 ]; then
  EST_PER_BLOCK=$(( ACCUM / HEAD_H ))
  EST_SOURCE="auto-detected"
else
  EST_PER_BLOCK=0
  EST_SOURCE="zero-height"
fi

# ── Step 4: stakes snapshot (for dormancy + in_stakes flag) ──────────────────
# Degrade gracefully when the daemon doesn't speak stakes (older build /
# dapp-only deploy): empty list → no dormancy detection but accrual
# walk continues unimpeded.
STAKES_JSON=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null || true)
if [ -z "$STAKES_JSON" ]; then
  STAKES_JSON="[]"
fi

# ── Step 5: walk the window + attribute per-creator/per-bucket shares ────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_accrual_audit: cannot create temp file" >&2; exit 1;
}
TMP_STAKES=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_accrual_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_STAKES" 2>/dev/null' EXIT

printf '%s' "$STAKES_JSON" >"$TMP_STAKES"

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$BUCKET_BLOCKS" \
        "$EST_PER_BLOCK" "$TMP_STAKES" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_h, to_h, bucket_blocks_s,
 est_per_block_s, stakes_path, out_path) = sys.argv[1:9]
from_h         = int(from_h)
to_h           = int(to_h)
bucket_blocks  = int(bucket_blocks_s)
est_per_block  = int(est_per_block_s)

# Window bookkeeping.
window_size  = to_h - from_h + 1
bucket_count = (window_size + bucket_blocks - 1) // bucket_blocks if window_size > 0 else 0

def bucket_of(h):
    # 0-indexed; bucket B covers heights [from + B*bb, from + (B+1)*bb - 1]
    # (last bucket truncates at to_h).
    return (h - from_h) // bucket_blocks

# Per-validator running totals.
#   total[domain]          Σ subsidy_in_window
#   buckets[domain][b]     Σ subsidy_in_bucket_b
# (b is the 0-indexed bucket position; missing entries default to 0.)
total_credit  = defaultdict(int)
bucket_credit = defaultdict(lambda: defaultdict(int))
empty_blocks  = 0     # blocks with zero creators (no subsidy paid)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_subsidy_accrual_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_subsidy_accrual_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_subsidy_accrual_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue
    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    if len(creators) == 0:
        empty_blocks += 1
        continue   # apply-side: no creators ⇒ no subsidy credited

    m    = len(creators)
    each = est_per_block // m
    rem  = est_per_block - each * m   # equivalent to est_per_block % m
    b    = bucket_of(h)
    for c in creators:
        if not isinstance(c, str) or not c:
            continue
        total_credit[c]            += each
        bucket_credit[c][b]        += each
    # Remainder to creators[0] (matches chain.cpp::apply_block).
    first = creators[0]
    if isinstance(first, str) and first:
        total_credit[first]        += rem
        bucket_credit[first][b]    += rem

# ── Load stakes snapshot for in_stakes / dormancy ─────────────────────────
try:
    with open(stakes_path, "r", encoding="utf-8") as f:
        stakes = json.load(f)
    if not isinstance(stakes, list):
        stakes = []
except Exception:
    stakes = []

staked_domains = set()
for st in stakes:
    if isinstance(st, dict):
        d = st.get("domain", "")
        s = st.get("stake", 0)
        if isinstance(d, str) and d and isinstance(s, int) and s > 0:
            staked_domains.add(d)

# Merge staked-with-zero-window into stats so they surface as
# validator_zero_in_window. Their total / buckets stay zero.
for d in staked_domains:
    if d not in total_credit:
        total_credit[d]  = 0
        bucket_credit[d] = defaultdict(int)

# ── Build per-validator records ───────────────────────────────────────────
def linreg_slope(xs, ys):
    # Simple least-squares slope. Returns 0.0 on degenerate input.
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    num = 0.0
    den = 0.0
    for x, y in zip(xs, ys):
        dx = x - mx
        num += dx * (y - my)
        den += dx * dx
    if den == 0.0:
        return 0.0
    return num / den

def bucket_range(b):
    # Inclusive [from, to] heights for bucket index b.
    bf = from_h + b * bucket_blocks
    bt = min(bf + bucket_blocks - 1, to_h)
    return bf, bt

validators = []
for dom in sorted(total_credit.keys()):
    # Emit one row per bucket (including zero-rows) — trend slope
    # stability requires consistent X coordinates across validators.
    buckets = []
    for b in range(bucket_count):
        bf, bt = bucket_range(b)
        buckets.append({
            "bucket_from": bf,
            "bucket_to":   bt,
            "subsidy":     bucket_credit[dom].get(b, 0),
        })

    if bucket_count >= 3:
        xs = [i for i in range(bucket_count)]
        ys = [bk["subsidy"] for bk in buckets]
        slope = linreg_slope(xs, ys)
    else:
        slope = 0.0

    validators.append({
        "domain":       dom,
        "buckets":      buckets,
        "total":        total_credit[dom],
        "trend_slope":  slope,
        "in_stakes":    dom in staked_domains,
    })

# ── Summary metrics ──────────────────────────────────────────────────────
totals_nonzero = sorted(v["total"] for v in validators if v["total"] > 0)
n_nonzero      = len(totals_nonzero)

def median(values):
    if not values:
        return 0
    n  = len(values)
    s  = sorted(values)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) // 2

median_total = median(totals_nonzero) if n_nonzero > 0 else 0
max_total    = max(totals_nonzero) if n_nonzero > 0 else 0

# Per-bucket median used as the drift-threshold base. We aggregate
# per-bucket totals across all validators, then take the median of the
# non-zero per-bucket cell values — this is "what does a typical
# validator earn in a typical bucket?" used to scale the slope test.
per_bucket_cells = []
for v in validators:
    for bk in v["buckets"]:
        if bk["subsidy"] > 0:
            per_bucket_cells.append(bk["subsidy"])
median_per_bucket = median(per_bucket_cells) if per_bucket_cells else 0

if median_total > 0:
    max_to_median_ratio = max_total / median_total
else:
    max_to_median_ratio = 0.0

n_dormant = sum(
    1 for v in validators
    if v["in_stakes"] and v["total"] == 0
)

# ── Anomaly classification ──────────────────────────────────────────────
anomalies = []

# subsidy_drift_high: per-validator trend slope magnitude > 50% of
# median per-bucket total. Needs ≥3 buckets (else slope is degenerate).
# Threshold scales with what's "typical" so it remains meaningful across
# small-K and large-K chains.
drift_threshold = (median_per_bucket * 50) / 100 if median_per_bucket > 0 else 0
if bucket_count >= 3 and drift_threshold > 0:
    drift_offenders = [
        v for v in validators
        if v["total"] > 0 and abs(v["trend_slope"]) > drift_threshold
    ]
    if drift_offenders:
        anomalies.append("subsidy_drift_high")

# validator_zero_in_window: in stakes with stake > 0 AND zero subsidy.
zero_in_window = [
    v for v in validators
    if v["in_stakes"] and v["total"] == 0
]
if zero_in_window:
    anomalies.append("validator_zero_in_window")

# max_to_median_ratio_high: top-1 > 3x median (non-zero validators).
# Requires ≥3 non-zero validators (else ratio is degenerate).
if n_nonzero >= 3 and median_total > 0 and max_total > 3 * median_total:
    anomalies.append("max_to_median_ratio_high")

# Sort validators: total desc, then domain asc; dormant rows (total=0)
# tied at end by total but sorted by domain for stable output.
validators.sort(key=lambda v: (-v["total"], v["domain"]))

summary = {
    "n_validators":         len(validators),
    "n_dormant":            n_dormant,
    "empty_blocks":         empty_blocks,
    "median_total":         median_total,
    "max_total":            max_total,
    "max_to_median_ratio":  max_to_median_ratio,
    "median_per_bucket":    median_per_bucket,
    "drift_threshold":      drift_threshold,
}

result = {
    "window":         {"from": from_h, "to": to_h, "blocks": window_size},
    "bucket_blocks":  bucket_blocks,
    "bucket_count":   bucket_count,
    "validators":     validators,
    "summary":        summary,
    "anomalies":      anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f, allow_nan=False)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_subsidy_accrual_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 6: render output ────────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" \
        "$PORT" "$HEAD_H" "$EST_PER_BLOCK" "$EST_SOURCE" <<'PY'
import json, sys

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
out_path      = sys.argv[3]
port          = int(sys.argv[4])
head_h        = int(sys.argv[5])
est_per_block = int(sys.argv[6])
est_source    = sys.argv[7]

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)

# Inject runtime context the Python walker didn't have.
env["rpc_port"]               = port
env["head_height"]            = head_h
env["block_subsidy"]          = est_per_block
env["block_subsidy_source"]   = est_source

anomalies     = env.get("anomalies", []) or []
n_anom        = len(anomalies)
window        = env["window"]
bucket_blocks = env["bucket_blocks"]
bucket_count  = env["bucket_count"]
validators    = env["validators"]
summary       = env["summary"]

if json_out:
    print(json.dumps(env))
    sys.exit(0)

# --anomalies-only: suppress healthy output unless an anomaly fired.
if anom_only and n_anom == 0:
    print(f"operator_subsidy_accrual_audit: no anomalies "
          f"(port {port}, window [{window['from']}..{window['to']}], "
          f"{window['blocks']} blocks, {bucket_count} buckets x {bucket_blocks})")
    sys.exit(0)

print(f"=== Subsidy accrual audit (port {port}, window "
      f"[{window['from']}..{window['to']}], {window['blocks']} blocks, "
      f"{bucket_count} bucket(s) of {bucket_blocks}) ===")
print(f"Per-block subsidy basis : {est_per_block}  (source: {est_source})")
print(f"Validators observed     : {summary['n_validators']}    "
      f"Dormant (staked, 0 in window): {summary['n_dormant']}    "
      f"Empty-creators blocks: {summary['empty_blocks']}")
print(f"Median total per val    : {summary['median_total']}    "
      f"Max total: {summary['max_total']}    "
      f"Max/median ratio: {summary['max_to_median_ratio']:.2f}x")
print(f"Median per-bucket cell  : {summary['median_per_bucket']}    "
      f"Drift threshold (50%): {summary['drift_threshold']}")
print()

if not validators:
    print("[INFO] No committee activity or stakes observed in window")
else:
    print("Per-validator accrual (ranked by total desc; dormant last):")
    print(f"  {'domain':<28} {'total':>12} {'slope/bucket':>14} "
          f"{'buckets>0':>10} {'in_stakes':>9}")
    print(f"  {'-'*28} {'-'*12} {'-'*14} {'-'*10} {'-'*9}")
    for v in validators:
        dom        = v["domain"][:28]
        total      = v["total"]
        slope      = v["trend_slope"]
        n_active   = sum(1 for bk in v["buckets"] if bk["subsidy"] > 0)
        ins        = "yes" if v["in_stakes"] else "no"
        if bucket_count >= 3:
            sl_str = f"{slope:+.1f}"
        else:
            sl_str = "-"
        print(f"  {dom:<28} {total:>12} {sl_str:>14} "
              f"{n_active:>10} {ins:>9}")

print()
if n_anom == 0:
    print("[OK] No accrual anomalies")
else:
    for a in anomalies:
        if a == "subsidy_drift_high":
            thr = summary["drift_threshold"]
            offenders = [
                f"{v['domain']} (slope={v['trend_slope']:+.1f}/bucket)"
                for v in validators
                if v["total"] > 0 and abs(v["trend_slope"]) > thr
            ]
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            print(f"[WARN] subsidy_drift_high — |trend_slope| > 50% of median "
                  f"per-bucket ({thr}): {disp}")
        elif a == "validator_zero_in_window":
            offenders = [v["domain"] for v in validators
                         if v["in_stakes"] and v["total"] == 0]
            disp = ", ".join(offenders[:5])
            if len(offenders) > 5:
                disp += f", +{len(offenders)-5} more"
            print(f"[INFO] validator_zero_in_window — staked but 0 subsidy "
                  f"in window: {disp}")
        elif a == "max_to_median_ratio_high":
            ratio = summary["max_to_median_ratio"]
            top   = validators[0] if validators else None
            top_d = top["domain"] if top else "?"
            print(f"[WARN] max_to_median_ratio_high — top-1 {top_d} "
                  f"= {summary['max_total']} > 3x median "
                  f"({summary['median_total']}); ratio={ratio:.2f}x")
        else:
            print(f"[WARN] {a}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_subsidy_accrual_audit: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 7: exit-code policy ────────────────────────────────────────────────
# Sibling convention (operator_subsidy_audit, operator_validator_uptime):
# exit 2 only when --anomalies-only is set AND ≥1 anomaly fired.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: env = json.load(f)
print(len(env.get("anomalies") or []))
PY
)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
