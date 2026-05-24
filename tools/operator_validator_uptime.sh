#!/usr/bin/env bash
# operator_validator_uptime.sh — Per-validator UPTIME-METRIC tracker.
#
# Rolling sign-rate per validator over a window of finalized blocks,
# bucketed for temporal trend (slope) detection, plus dormancy
# cross-reference against `determ stakes` (validators currently staked
# but never selected in the window).
#
# Sibling positioning — three uptime-axis operator tools:
#
#   operator_block_inclusion_audit.sh
#       Operator-facing miss-streak detector. Cares about CONSECUTIVE
#       failure runs ("I missed 5 rounds in a row") — captures
#       short-burst downtime. Carries BFT proposer concentration.
#
#   operator_validator_history.sh
#       Per-validator EVENT TAPE (REGISTER / DEREGISTER / ABORT /
#       EQUIVOCATE). Cares about lifecycle + slashing, not uptime curve.
#
#   operator_validator_uptime.sh         (this script)
#       UPTIME METRIC — rolling sign-rate + trend slope across buckets +
#       longest LOW-uptime streak (bucket-level, not block-level), plus
#       dormancy detection (staked validators with zero appearances).
#       This is the "are my validators degrading over time?" lens —
#       complementary to the burst-streak lens above.
#
# Model:
#   Walk blocks in window. For each block, look at creators[] (the K
#   committee members) and creator_block_sigs[] (parallel array; each
#   slot is a 64-byte Ed25519 sig or the all-zero sentinel = "did not
#   sign"). Bucket by --bucket-blocks N so we can fit a trend slope
#   per validator. Per validator:
#
#     selections   total committee draws in the window
#     signs        total non-zero-sig slots
#     uptime_pct   signs / selections (undefined if 0)
#     bucket_trend list of {bucket_idx, from, to, selections, signs, pct}
#     trend_slope  least-squares slope of pct over bucket_idx
#                  (units: pct-points per bucket; bucket_pct is in [0,1])
#     low_uptime_buckets    count of buckets where pct < target_uptime_pct
#                           AND selections > 0
#     longest_low_uptime_streak
#                  longest run of CONSECUTIVE buckets where the validator
#                  was selected at least once AND uptime_pct fell below
#                  --target-uptime-pct. Buckets where the validator was
#                  not selected at all neither extend nor reset the
#                  streak — they're off-duty and don't carry a signal.
#
#   Bucket numbering is 1-indexed in the order they roll across the
#   window. Trend slope uses bucket_idx as the X coordinate so trend is
#   invariant to bucket size; a negative slope means uptime is falling
#   bucket-over-bucket.
#
# Dormancy:
#   A validator may currently be in `determ stakes` (active staking
#   committee candidate) but never get drawn in the window. That's the
#   classic "validator is up + staked but bench-warming because the
#   committee size is small and the lottery just didn't pick them
#   often." Surfaced separately from low_uptime (they're DIFFERENT
#   problems and an operator needs to know which).
#
# Empty-signature sentinel:
#   block.creator_block_sigs[i] is an std::array<uint8_t,64> serialized
#   to JSON as a 128-character hex string. The all-zero sentinel
#   ("0"*128) means "validator did not sign / signature was not
#   gathered in time". Block.cpp's to_hex emits lowercase; we
#   case-insensitive-compare for safety.
#
# Args:
#   --rpc-port N              RPC port (REQUIRED)
#   --from H                  Lower window bound, inclusive
#                             (default: see --last)
#   --to H                    Upper window bound, inclusive
#                             (default: current head)
#   --last N                  Shorthand for [head-N+1, head]
#                             (default: 5000; exclusive with --from/--to)
#   --bucket-blocks N         Window subdivision size (default: 100).
#                             Smaller → more buckets, finer trend.
#                             Trend slope unstable with <3 buckets, so
#                             we report it as 0.0 in that degenerate case.
#   --target-uptime-pct F     Floor under which a bucket counts as
#                             "low-uptime" (default: 0.95). Same value
#                             used for the validator_low_uptime anomaly
#                             gate.
#   --json                    Emit structured JSON envelope
#   --anomalies-only          Print only when ≥1 anomaly fires
#   -h, --help                Show this help
#
# Anomaly flags:
#   validator_low_uptime         (CRITICAL) any validator with
#                                selections > 10 AND
#                                uptime_pct < --target-uptime-pct.
#                                The selections > 10 floor avoids
#                                false-positives on a single missed
#                                round when the validator was only
#                                drawn 2-3 times.
#   validator_declining_uptime   (WARN) any validator with
#                                trend_slope < -0.10 AND
#                                len(bucket_trend) >= 3.
#                                A negative-slope cliff over ≥3 buckets
#                                is a "getting worse" signal worth
#                                noticing BEFORE the absolute floor is
#                                breached.
#   validator_dormant            (INFO) any validator currently in
#                                `determ stakes` with 0 selections
#                                in window. Not a problem on its own
#                                (the lottery just didn't pick them)
#                                but worth surfacing for capacity
#                                planning + selection-fairness diff.
#
# Exit codes:
#   0   audit ran; no anomalies (or default informational mode)
#   1   bad args / RPC error / malformed response
#   2   --anomalies-only AND ≥1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_validator_uptime.sh --rpc-port N
                                    [--from H] [--to H] [--last N]
                                    [--bucket-blocks N]
                                    [--target-uptime-pct F]
                                    [--json] [--anomalies-only]

Per-validator uptime tracking: rolling sign-rate per validator,
bucketed for trend slope, plus dormancy detection (staked validators
with zero appearances in window).

For each validator that appeared on ≥1 committee in the window:
  selections           — blocks where they were drawn
  signs                — blocks where their slot had a non-zero sig
  uptime_pct           — signs / selections
  trend_slope          — least-squares slope of per-bucket uptime_pct
                         (units: pct-points per bucket; negative = falling)
  low_uptime_buckets   — count of buckets where pct < target
                         (with selections > 0 in that bucket)
  longest_low_uptime_streak
                       — longest run of CONSECUTIVE buckets where the
                         validator was selected AND uptime_pct fell
                         below --target-uptime-pct. Buckets where the
                         validator was not selected at all neither
                         extend nor reset the streak.

Validators are discovered from observed committees in the window (NOT
the current `determ stakes` snapshot) PLUS — for dormancy detection
only — currently-staked validators are joined in and flagged if their
in-window selections came in at zero.

Options:
  --rpc-port N            RPC port (REQUIRED)
  --from H                Lower window bound, inclusive
                          (default: see --last)
  --to H                  Upper window bound, inclusive
                          (default: current head)
  --last N                Shorthand for [head-N+1, head]
                          (default: 5000; exclusive with --from/--to)
  --bucket-blocks N       Window subdivision size (default: 100)
  --target-uptime-pct F   Bucket-low + anomaly floor (default: 0.95)
  --json                  Emit structured JSON envelope
  --anomalies-only        Print only when ≥1 anomaly fires (exit 2)
  -h, --help              Show this help

Anomalies:
  validator_low_uptime         CRITICAL — validator with selections > 10
                               AND uptime_pct < --target-uptime-pct
  validator_declining_uptime   WARN — trend_slope < -0.10 over ≥3 buckets
  validator_dormant            INFO — in `determ stakes` but selections = 0

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W,
              "bucket_blocks": B, "bucket_count": K},
   "rpc_port": P,
   "target_uptime_pct": F,
   "by_validator": [
     {"domain": "...",
      "selections": S, "signs": G,
      "uptime_pct": U,
      "trend_slope": SL,
      "low_uptime_buckets": LB,
      "longest_low_uptime_streak": LS,
      "in_stakes": bool,
      "bucket_trend": [{"bucket_idx": I, "from": F, "to": T,
                        "selections": S, "signs": G, "pct": P}, ...]
      }, ...],
   "summary": {"n_validators": N, "n_dormant": D,
               "min_uptime_pct": M, "max_low_streak": L},
   "anomalies": [...]}

Exit codes:
  0   success, no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
BUCKET_BLOCKS=100
TARGET_PCT="0.95"
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           PORT="${2:-}";           shift 2 ;;
    --from)               FROM="${2:-}";           shift 2 ;;
    --to)                 TO="${2:-}";             shift 2 ;;
    --last)               LAST="${2:-}";           shift 2 ;;
    --bucket-blocks)      BUCKET_BLOCKS="${2:-}";  shift 2 ;;
    --target-uptime-pct)  TARGET_PCT="${2:-}";     shift 2 ;;
    --json)               JSON_OUT=1;              shift ;;
    --anomalies-only)     ANOM_ONLY=1;             shift ;;
    *) echo "operator_validator_uptime: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORT" ]; then
  echo "operator_validator_uptime: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_validator_uptime: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_validator_uptime: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_validator_uptime: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_validator_uptime: --last must be >= 1" >&2
  exit 1
fi
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_validator_uptime: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" = "0" ]; then
  echo "operator_validator_uptime: --bucket-blocks must be >= 1" >&2
  exit 1
fi
# --target-uptime-pct: float in [0,1]. Validate via Python (bash float
# handling is portable hell; just delegate).
if ! python -c "
import sys
try:
    v = float('$TARGET_PCT')
    if not (0.0 <= v <= 1.0):
        sys.exit(1)
except Exception:
    sys.exit(1)
sys.exit(0)
" >/dev/null 2>&1; then
  echo "operator_validator_uptime: --target-uptime-pct must be a float in [0,1] (got '$TARGET_PCT')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to absolute path so subprocess.run from Python works the
# same on Linux/Mac/Git Bash (matches operator_block_inclusion_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain head ────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_uptime: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
except Exception:
    print('')")
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_validator_uptime: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (height is the NEXT-to-produce).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. --last > (--from/--to) > default-last-5000.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TOP - LAST + 1 ))
  fi
  TO=$TOP
else
  if [ -z "$TO" ]; then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    # Default last 5000.
    if [ "$TOP" -gt 4999 ]; then
      FROM=$(( TOP - 4999 ))
    else
      FROM=0
    fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_validator_uptime: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: stakes snapshot (for dormancy detection) ─────────────────────────
# A validator currently in `determ stakes` with 0 in-window appearances
# is flagged as validator_dormant (INFO). If the daemon isn't returning
# stakes (older build / dapp-only deploy), we degrade gracefully: no
# dormancy detection, the script still ships uptime/trend results.
STAKES_JSON=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null || true)
if [ -z "$STAKES_JSON" ]; then
  STAKES_JSON="[]"
fi

# ── Step 3: per-block walk + tally (driven from Python) ───────────────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_validator_uptime: cannot create temp file" >&2; exit 1;
}
TMP_STAKES=$(mktemp 2>/dev/null) || {
  echo "operator_validator_uptime: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_STAKES" 2>/dev/null' EXIT

printf '%s' "$STAKES_JSON" >"$TMP_STAKES"

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" \
        "$BUCKET_BLOCKS" "$TARGET_PCT" "$TMP_STAKES" <<'PY'
import json, subprocess, sys

(determ, port, from_h, to_h, out_path,
 bucket_blocks_s, target_pct_s, stakes_path) = sys.argv[1:9]
from_h, to_h = int(from_h), int(to_h)
bucket_blocks = int(bucket_blocks_s)
target_pct = float(target_pct_s)

ZERO_SIG_HEX = "0" * 128  # 64 bytes of zero (canonical "didn't sign")

# Window bookkeeping.
window_size = to_h - from_h + 1
# Bucket count: ceil(window_size / bucket_blocks). Each bucket holds
# bucket_blocks consecutive heights starting at FROM.
bucket_count = (window_size + bucket_blocks - 1) // bucket_blocks if window_size > 0 else 0

def bucket_of(h):
    # 0-indexed bucket position; rendered as 1-indexed in output for
    # operator readability.
    return (h - from_h) // bucket_blocks

# Per-validator counters; lazy-populated on first observation.
#   selections, signs    — overall window
#   buckets              — bucket_idx → {selections, signs}
stats = {}

def get(dom):
    if dom not in stats:
        stats[dom] = {
            "selections": 0,
            "signs":      0,
            "buckets":    {},   # bucket_idx → {sel, sig}
        }
    return stats[dom]

def bget(s, b):
    if b not in s["buckets"]:
        s["buckets"][b] = {"sel": 0, "sig": 0}
    return s["buckets"][b]

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_validator_uptime: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_validator_uptime: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_validator_uptime: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators") or []
    sigs     = blk.get("creator_block_sigs") or []
    if not isinstance(creators, list): creators = []
    if not isinstance(sigs,     list): sigs     = []

    b = bucket_of(h)
    for idx, dom in enumerate(creators):
        if not isinstance(dom, str) or not dom:
            continue
        s  = get(dom)
        bb = bget(s, b)
        s["selections"]  += 1
        bb["sel"]        += 1
        signed = False
        if idx < len(sigs) and isinstance(sigs[idx], str):
            sig_hex = sigs[idx]
            # Defensive case-insensitive compare; block.cpp's to_hex
            # emits lowercase but we shouldn't rely on that.
            if sig_hex and sig_hex.lower() != ZERO_SIG_HEX:
                signed = True
        if signed:
            s["signs"] += 1
            bb["sig"]  += 1

# Load stakes snapshot for dormancy + in_stakes flag.
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
        if isinstance(d, str) and d:
            staked_domains.add(d)

# Merge staked-but-never-selected validators into the stats so they
# surface as dormant. Their selections / signs / bucket trend stay zero.
for d in staked_domains:
    if d not in stats:
        stats[d] = {"selections": 0, "signs": 0, "buckets": {}}

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

# Build per-validator records.
rows = []
for dom, s in stats.items():
    selections = s["selections"]
    signs      = s["signs"]
    uptime_pct = (signs / selections) if selections > 0 else 0.0

    # bucket_trend list. Emit ONE row per bucket index that the
    # validator actually had selections in. Off-duty buckets are
    # OMITTED — they carry no uptime signal and would just dilute the
    # slope toward zero with phantom data.
    bucket_trend = []
    for b in sorted(s["buckets"].keys()):
        bb = s["buckets"][b]
        sel = bb["sel"]
        sig = bb["sig"]
        if sel == 0:
            continue
        b_from = from_h + b * bucket_blocks
        b_to   = min(b_from + bucket_blocks - 1, to_h)
        bucket_trend.append({
            "bucket_idx":  b + 1,  # 1-indexed for human output
            "from":        b_from,
            "to":          b_to,
            "selections":  sel,
            "signs":       sig,
            "pct":         (sig / sel),
        })

    # Trend slope: pct vs bucket_idx, requires ≥3 buckets for stability.
    if len(bucket_trend) >= 3:
        xs = [bt["bucket_idx"] for bt in bucket_trend]
        ys = [bt["pct"]        for bt in bucket_trend]
        trend_slope = linreg_slope(xs, ys)
    else:
        trend_slope = 0.0

    # low_uptime_buckets: per-bucket pct < target, selections > 0.
    low_buckets = [bt for bt in bucket_trend if bt["pct"] < target_pct]

    # longest_low_uptime_streak: consecutive buckets in bucket_trend
    # (the on-duty subset) where pct < target. Because off-duty buckets
    # were omitted earlier, "consecutive" here means consecutive
    # on-duty buckets — that matches the documented model that off-duty
    # buckets neither extend nor reset the streak.
    cur = 0
    longest_low = 0
    for bt in bucket_trend:
        if bt["pct"] < target_pct:
            cur += 1
            if cur > longest_low:
                longest_low = cur
        else:
            cur = 0

    rows.append({
        "domain":                     dom,
        "selections":                 selections,
        "signs":                      signs,
        "uptime_pct":                 uptime_pct,
        "trend_slope":                trend_slope,
        "low_uptime_buckets":         len(low_buckets),
        "longest_low_uptime_streak":  longest_low,
        "in_stakes":                  dom in staked_domains,
        "bucket_trend":               bucket_trend,
    })

# Sort by uptime_pct asc (worst first), ties by selections desc, then
# domain asc. Dormant rows (selections == 0) sort last by selections
# desc — but they all tie at uptime_pct == 0, which would otherwise
# muddy the "worst first" intent. Apply a two-pass split: non-dormant
# (selections > 0) first, then dormant.
rows.sort(key=lambda r: (
    0 if r["selections"] > 0 else 1,    # non-dormant first
    r["uptime_pct"],                    # asc (worst signed-rate first)
    -r["selections"],                   # ties: more selections first
    r["domain"],                        # ties: domain asc
))

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []

# validator_low_uptime (CRITICAL): selections > 10 AND uptime_pct < target.
if any(r["selections"] > 10 and r["uptime_pct"] < target_pct for r in rows):
    anomalies.append("validator_low_uptime")

# validator_declining_uptime (WARN): trend_slope < -0.10 AND ≥3 buckets.
# Bucket count is implicit in trend_slope having been computed (≥3).
# We must re-check the bucket_trend length because trend_slope = 0.0
# could be either "stable" or "<3 buckets" — only the former should
# fire the anomaly.
if any(
    len(r["bucket_trend"]) >= 3 and r["trend_slope"] < -0.10
    for r in rows
):
    anomalies.append("validator_declining_uptime")

# validator_dormant (INFO): in_stakes AND selections == 0.
if any(r["in_stakes"] and r["selections"] == 0 for r in rows):
    anomalies.append("validator_dormant")

# Summary row.
non_dormant = [r for r in rows if r["selections"] > 0]
min_uptime = min((r["uptime_pct"] for r in non_dormant), default=0.0)
max_low    = max((r["longest_low_uptime_streak"] for r in rows), default=0)
n_dormant  = sum(1 for r in rows if r["in_stakes"] and r["selections"] == 0)

summary = {
    "n_validators":   len(rows),
    "n_dormant":      n_dormant,
    "min_uptime_pct": min_uptime,
    "max_low_streak": max_low,
}

envelope = {
    "window": {
        "from":          from_h,
        "to":            to_h,
        "block_count":   window_size,
        "bucket_blocks": bucket_blocks,
        "bucket_count":  bucket_count,
    },
    "target_uptime_pct":  target_pct,
    "by_validator":       rows,
    "summary":            summary,
    "anomalies":          anomalies,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f, allow_nan=False)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 4: render ───────────────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WINDOW" \
        "$BUCKET_BLOCKS" "$TARGET_PCT" <<'PY'
import json, sys

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
out_path      = sys.argv[3]
port          = int(sys.argv[4])
from_h        = int(sys.argv[5])
to_h          = int(sys.argv[6])
window        = int(sys.argv[7])
bucket_blocks = int(sys.argv[8])
target_pct    = float(sys.argv[9])

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)
env["rpc_port"] = port

anomalies     = env.get("anomalies", []) or []
n_anom        = len(anomalies)
bucket_count  = env["window"].get("bucket_count", 0)

if json_out:
    print(json.dumps(env))
    sys.exit(0)

# --anomalies-only: suppress normal output unless an anomaly fired.
if anom_only and n_anom == 0:
    print(f"operator_validator_uptime: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks, "
          f"{bucket_count} buckets x {bucket_blocks})")
    sys.exit(0)

rows    = env["by_validator"]
summary = env["summary"]

print(f"=== Validator uptime (port {port}, window [{from_h}..{to_h}], "
      f"{window} blocks, {bucket_count} bucket(s) of {bucket_blocks}) ===")
print(f"Validators observed: {summary['n_validators']}    "
      f"Dormant (staked, 0 selections): {summary['n_dormant']}")
print(f"Target uptime: {target_pct*100:.1f}%    "
      f"Min uptime observed: {summary['min_uptime_pct']*100:.1f}%    "
      f"Max low-uptime bucket streak: {summary['max_low_streak']}")
print()

if not rows:
    print("[INFO] No committee activity or stakes observed in window")
else:
    print("Per-validator uptime (ranked worst first; dormant validators last):")
    print(f"  {'domain':<28} {'sel':>6} {'signs':>6} {'uptime%':>8} "
          f"{'slope':>8} {'low_buckets':>11} {'low_streak':>10} "
          f"{'in_stakes':>9}")
    print(f"  {'-'*28} {'-'*6} {'-'*6} {'-'*8} {'-'*8} {'-'*11} {'-'*10} {'-'*9}")
    for r in rows:
        dom = r["domain"][:28]
        sel = r["selections"]
        sig = r["signs"]
        if sel > 0:
            up  = f"{r['uptime_pct']*100:.1f}%"
        else:
            up  = "-"
        # trend_slope rendered as pct-points/bucket (×100). Show "-"
        # when fewer than 3 buckets (slope not meaningful).
        if len(r["bucket_trend"]) >= 3:
            sl = f"{r['trend_slope']*100:+.2f}"
        else:
            sl = "-"
        lb  = r["low_uptime_buckets"]
        ls  = r["longest_low_uptime_streak"]
        ins = "yes" if r["in_stakes"] else "no"
        print(f"  {dom:<28} {sel:>6} {sig:>6} {up:>8} {sl:>8} "
              f"{lb:>11} {ls:>10} {ins:>9}")

print()
if n_anom == 0:
    print("[OK] No uptime anomalies")
else:
    for a in anomalies:
        if a == "validator_low_uptime":
            offenders = [
                f"{r['domain']} ({r['uptime_pct']*100:.1f}% on {r['selections']} sel)"
                for r in rows
                if r["selections"] > 10 and r["uptime_pct"] < target_pct
            ]
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            print(f"[CRITICAL] validator_low_uptime — uptime_pct < "
                  f"{target_pct*100:.1f}% on >10 selections: {disp}")
        elif a == "validator_declining_uptime":
            offenders = [
                f"{r['domain']} (slope={r['trend_slope']*100:+.2f} pp/bucket "
                f"over {len(r['bucket_trend'])} buckets)"
                for r in rows
                if len(r["bucket_trend"]) >= 3 and r["trend_slope"] < -0.10
            ]
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            print(f"[WARN] validator_declining_uptime — trend slope < "
                  f"-0.10 pct-points/bucket: {disp}")
        elif a == "validator_dormant":
            offenders = [
                r["domain"]
                for r in rows
                if r["in_stakes"] and r["selections"] == 0
            ]
            disp = ", ".join(offenders[:5])
            if len(offenders) > 5:
                disp += f", +{len(offenders)-5} more"
            print(f"[INFO] validator_dormant — currently staked but 0 "
                  f"selections in window: {disp}")
        else:
            print(f"[WARN] {a}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_validator_uptime: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 5: exit-code policy ────────────────────────────────────────────────
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: env = json.load(f)
print(len(env.get("anomalies") or []))
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
