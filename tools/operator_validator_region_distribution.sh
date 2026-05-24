#!/usr/bin/env bash
# operator_validator_region_distribution.sh — Per-region active-validator
# distribution histogram + rotation timeline over a window of finalized
# blocks. Companion to (but complementary with):
#
#   operator_region_balance_audit.sh           Per-region STAKE / BALANCE
#                                              fairness — answers "is each
#                                              region carrying its weight
#                                              in token holdings?"
#   operator_committee_audit.sh                Per-validator stake-fairness
#                                              audit — answers "did each
#                                              validator get its share of
#                                              slots?"
#   operator_committee_membership_history.sh   Per-validator timeline +
#                                              pair co-occurrence — answers
#                                              "WHICH blocks did each
#                                              validator show up in?"
#   operator_validator_region_distribution.sh  (THIS)
#                                              Per-region COUNT + TIMELINE
#                                              of validators that actually
#                                              appeared in creators[] —
#                                              answers "is every region
#                                              still rotating into the
#                                              committee, or has one
#                                              silently dropped out?"
#
# Algorithm:
#   Step A: Pull validator set via `determ stakes --json`. Group by
#           `region` (empty string is canonicalized to "(global)" since
#           Determ's R4 path treats an empty region as a sentinel for
#           non-regional / global pools).
#   Step B: For each block in [--from..--to] (default last 1000), extract
#           creators[] via `determ block-info <h> --json`. Map each
#           creator-domain back to its region (from the stakes snapshot).
#   Step C: Bucket the window in fixed-size slices of --bucket-blocks
#           (default 100). For each bucket and each known region:
#             * present_blocks = count of blocks in the bucket where
#               >=1 creator from that region appeared.
#             * appearance_rate = present_blocks / bucket_size.
#           The "dominant region" of a bucket is the region with the
#           HIGHEST total creator-appearance count across all blocks
#           in the bucket (ties broken alphabetically).
#   Step D: A "region-rotation event" is a bucket whose dominant region
#           differs from the prior bucket's dominant region. The total
#           count is reported as `rotation_events`.
#   Step E: Per-region across the full window:
#             * total_active_blocks  = sum of present_blocks over buckets
#                                      (equivalently: # of blocks where
#                                      >=1 creator from this region
#                                      appeared)
#             * appearance_rate      = total_active_blocks / window
#             * longest_absence      = longest run of consecutive blocks
#                                      with zero creator-appearances from
#                                      this region.
#
# Anomalies (alert-worthy):
#   region_abandoned         CRITICAL.  Any region with >=1 registered
#                            validator in the stakes snapshot but ZERO
#                            creator-appearances across the entire window.
#                            Signals a silent regional drop-out — the
#                            registry says the region is staffed, but
#                            no validator from that region got selected
#                            (or all of them have been unreachable
#                            long enough that selection silently routed
#                            around them).
#   region_imbalance_high    WARN.  Bucket-level max:min appearance-rate
#                            ratio > 5.  Rotation cadence is skewed —
#                            some buckets are dominated by one region
#                            and other regions are barely participating.
#   single_region_lock       WARN.  Same region is the bucket-level
#                            dominant for > 80% of buckets.  Committee
#                            rotation has effectively stalled to a single
#                            region — selection bias OR all other regions
#                            have collapsed.
#
# Region snapshot caveat: regions are inferred from `determ stakes --json`
# at audit time (same caveat as the validator-history script).  Mid-window
# REGION_CHANGE txs or churn (REGISTER / DEREGISTER from a different
# region) introduce minor reporting error — a creator whose REGISTER was
# in region "us-east" at block H but who currently shows as "eu-west"
# in the stakes snapshot will count toward eu-west for ALL window blocks.
# For high-accuracy multi-region churn windows, run on a tighter window.
#
# Args:
#   [--rpc-port N]            RPC port to query (REQUIRED)
#   [--from H]                Lower window bound, inclusive (default: head-999)
#   [--to H]                  Upper window bound, inclusive (default: head)
#   [--last N]                Shorthand for --from (head-N+1) --to head
#                             (mutually exclusive with --from / --to)
#   [--bucket-blocks N]       Time-bucket size for the rotation timeline
#                             (default 100). Smaller buckets give a finer
#                             rotation cadence; bucket count is clamped
#                             so the LAST bucket always covers the
#                             remainder of the window.
#   [--json]                  Emit structured JSON envelope
#   [--anomalies-only]        Suppress healthy rows; exit 2 if anomaly fires
#                             (CRITICAL = region_abandoned)
#   [-h|--help]               Show this help
#
# Exit codes:
#   0   success, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND >=1 anomaly detected (CRITICAL = region_abandoned)
set -u

usage() {
  cat <<'EOF'
Usage: operator_validator_region_distribution.sh --rpc-port N
                                                 [--from H] [--to H] [--last N]
                                                 [--bucket-blocks N]
                                                 [--json] [--anomalies-only]

Per-region validator-distribution histogram + active-region rotation
timeline over a window of finalized blocks. For each region (resolved
from `determ stakes --json`), counts blocks in each --bucket-blocks
slice where >=1 creator from that region appeared. Flags abandoned
regions, skewed rotation cadence, and single-region locks.

Options:
  --rpc-port N         RPC port to query (REQUIRED)
  --from H             Lower window bound, inclusive (default: head-999)
  --to H               Upper window bound, inclusive (default: head)
  --last N             Shorthand for [head-N+1 .. head] (exclusive with
                       --from / --to)
  --bucket-blocks N    Time-bucket size for the rotation timeline
                       (default 100)
  --json               Emit structured JSON envelope
  --anomalies-only     Suppress healthy rows; exit 2 if any anomaly fires
  -h, --help           Show this help

Anomalies:
  region_abandoned         CRITICAL  region has >=1 registered validator
                                     but ZERO appearances in window
  region_imbalance_high    WARN      max:min region-activity ratio > 5
  single_region_lock       WARN      single region dominant for > 80%
                                     of buckets

JSON shape:
  {"rpc_port": P,
   "window": {"from": F, "to": T, "block_count": W},
   "bucket_blocks": B,
   "by_region": [
     {"region": "...", "total_active_blocks": N, "appearance_rate": R,
      "longest_absence": L, "validator_count": V}, ...],
   "buckets": [
     {"from": F, "to": T, "dominant_region": "...",
      "region_counts": {"region": N, ...}}, ...],
   "rotation_events": N,
   "anomalies": [...]}

Exit codes:
  0   success (or default informational mode without anomalies)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND >=1 anomaly detected
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
BUCKET="100"
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 1 ;;
    --rpc-port)           PORT="${2:-}";       shift 2 ;;
    --from)               FROM="${2:-}";       shift 2 ;;
    --to)                 TO="${2:-}";         shift 2 ;;
    --last)               LAST="${2:-}";       shift 2 ;;
    --bucket-blocks)      BUCKET="${2:-}";     shift 2 ;;
    --json)               JSON_OUT=1;          shift ;;
    --anomalies-only)     ANOM_ONLY=1;         shift ;;
    *) echo "operator_validator_region_distribution: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; refuses to guess
# the daemon on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_validator_region_distribution: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_validator_region_distribution: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --last is mutually exclusive with --from / --to.
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_validator_region_distribution: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_validator_region_distribution: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_validator_region_distribution: --last must be >= 1" >&2
  exit 1
fi

# --bucket-blocks: positive integer.
case "$BUCKET" in *[!0-9]*|"")
  echo "operator_validator_region_distribution: --bucket-blocks must be a positive integer (got '$BUCKET')" >&2
  exit 1 ;;
esac
if [ "$BUCKET" = "0" ]; then
  echo "operator_validator_region_distribution: --bucket-blocks must be >= 1" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (matches sibling scripts).
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
  echo "operator_validator_region_distribution: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
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
  echo "operator_validator_region_distribution: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (block 0 is genesis with an empty
# creators[]; included in the window if --from 0).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Window-bound resolution. Precedence: --last > (--from/--to) > defaults.
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
    # Default: last 1000 blocks ending at tip.
    if [ "$TOP" -gt 999 ]; then
      FROM=$(( TOP - 999 ))
    else
      FROM=0
    fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_validator_region_distribution: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: stakes snapshot (domain → region) ─────────────────────────────────
STAKES_JSON=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_region_distribution: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

# ── Step 3: per-block walk + per-region aggregation (driven from Python) ──────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_validator_region_distribution: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$BUCKET" "$TMP_OUT" <<PY
import json, subprocess, sys

determ, port, from_h, to_h, bucket_s, out_path = sys.argv[1:7]
from_h, to_h, bucket = int(from_h), int(to_h), int(bucket_s)

stakes_json = '''$STAKES_JSON'''
try:
    stakes = json.loads(stakes_json)
except Exception:
    sys.stderr.write("operator_validator_region_distribution: malformed stakes JSON\n")
    sys.exit(1)
if not isinstance(stakes, list):
    sys.stderr.write("operator_validator_region_distribution: stakes RPC returned non-array\n")
    sys.exit(1)

# Canonicalize empty region to "(global)". The stakes RPC returns the
# raw `region` field which is an empty string for non-regional pools;
# using a sentinel keeps the histogram + JSON output unambiguous.
GLOBAL = "(global)"

def canon(r):
    if not isinstance(r, str): return GLOBAL
    r = r.strip()
    return r if r else GLOBAL

# domain → region map; per-region validator-count for the registered set.
domain_to_region = {}        # str → str
region_validator_count = {}  # str → int
for s in stakes:
    if not isinstance(s, dict): continue
    dom = s.get("domain")
    if not isinstance(dom, str) or not dom: continue
    reg = canon(s.get("region"))
    domain_to_region[dom] = reg
    region_validator_count[reg] = region_validator_count.get(reg, 0) + 1

# Region universe = every region with >=1 registered validator in the
# stakes snapshot. We use this as the baseline for region_abandoned
# detection (a region that's registered but never appears in creators[]
# is the alert). Creators that don't appear in the stakes snapshot
# (e.g. a validator that DEREGISTERED mid-window) fall into a synthetic
# "(unknown)" region; that's still tracked for completeness but is
# explicitly excluded from region_abandoned checks.
all_regions = set(region_validator_count.keys())

# Per-block walk. Store, for each block (height-indexed):
#   * per_block_region_counts: dict[region → count of that region's
#     creators in this block]
#   * per_block_present_regions: set of regions with >=1 creator
per_block_region_counts = []  # list[dict[str,int]] parallel to range(from_h, to_h+1)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_validator_region_distribution: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_validator_region_distribution: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_validator_region_distribution: block-info {h} returned non-JSON\n")
        sys.exit(1)

    region_counts = {}
    if isinstance(blk, dict):
        creators = blk.get("creators") or []
        if isinstance(creators, list):
            for c in creators:
                if not isinstance(c, str): continue
                reg = domain_to_region.get(c, "(unknown)")
                region_counts[reg] = region_counts.get(reg, 0) + 1
                # Also surface unknown-region creators so the universe
                # of regions in the report reflects what we actually saw.
                # We deliberately DON'T add (unknown) to all_regions
                # because abandonment is defined against the stakes
                # snapshot — but the bucket histogram should include it
                # so operators see the leftover.
    per_block_region_counts.append(region_counts)

W = to_h - from_h + 1

# Build the global region universe for the histogram = stakes-snapshot
# regions ∪ regions actually observed in block creators[].
observed_regions = set()
for rc in per_block_region_counts:
    observed_regions.update(rc.keys())
display_regions = all_regions | observed_regions

# ── Per-region totals across the full window ────────────────────────────────
def longest_absence_run(present_flags):
    # Longest run of consecutive False values in present_flags.
    best = cur = 0
    for f in present_flags:
        if not f:
            cur += 1
            if cur > best: best = cur
        else:
            cur = 0
    return best

by_region = []
for reg in sorted(display_regions):
    present_flags = [reg in rc for rc in per_block_region_counts]
    total_active = sum(1 for f in present_flags if f)
    rate = (total_active / W) if W > 0 else 0.0
    by_region.append({
        "region":                reg,
        "total_active_blocks":   total_active,
        "appearance_rate":       rate,
        "longest_absence":       longest_absence_run(present_flags),
        "validator_count":       region_validator_count.get(reg, 0),
    })

# ── Bucket the window for the rotation timeline ──────────────────────────────
buckets = []
dominant_per_bucket = []
b_lo = from_h
while b_lo <= to_h:
    b_hi = min(b_lo + bucket - 1, to_h)
    # Index range into per_block_region_counts:
    i_lo = b_lo - from_h
    i_hi = b_hi - from_h
    # Per-region counts in this bucket:
    #   * total creator-appearances (used to pick dominant region)
    #   * blocks with >=1 creator from the region (used for activity-rate
    #     histogram bars)
    total_counts   = {}
    present_blocks = {}
    for i in range(i_lo, i_hi + 1):
        rc = per_block_region_counts[i]
        seen = set()
        for reg, c in rc.items():
            total_counts[reg] = total_counts.get(reg, 0) + c
            seen.add(reg)
        for reg in seen:
            present_blocks[reg] = present_blocks.get(reg, 0) + 1
    # Dominant region = highest total creator-appearance count
    # (ties broken alphabetically). If the bucket has no creator
    # observations (e.g. all blocks empty), dominant = None.
    if total_counts:
        dom = sorted(total_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    else:
        dom = None
    dominant_per_bucket.append(dom)
    buckets.append({
        "from":            b_lo,
        "to":              b_hi,
        "size":            b_hi - b_lo + 1,
        "dominant_region": dom,
        "region_counts":   present_blocks,  # blocks-with-presence per region
        "total_counts":    total_counts,    # raw creator-appearance counts
    })
    b_lo = b_hi + 1

# Rotation events: each bucket whose dominant region differs from the
# prior bucket's dominant region. Buckets with dom = None never trip a
# rotation event (we treat them as "no signal" rather than a transition).
rotation_events = 0
prev_dom = None
for i, dom in enumerate(dominant_per_bucket):
    if dom is None:
        continue
    if prev_dom is not None and dom != prev_dom:
        rotation_events += 1
    if dom is not None:
        prev_dom = dom

# ── Anomaly classification ───────────────────────────────────────────────────
anomalies = []

# region_abandoned: registered region with ZERO appearances across window.
# Defined ONLY against all_regions (stakes-snapshot universe) so an
# observation-only "(unknown)" doesn't trigger false positives.
abandoned_regions = []
for reg in sorted(all_regions):
    total = sum(1 for rc in per_block_region_counts if reg in rc)
    if total == 0:
        abandoned_regions.append(reg)
if abandoned_regions:
    anomalies.append("region_abandoned")

# region_imbalance_high: bucket-level max:min appearance-rate ratio > 5.
# Compute per bucket across regions that have any appearance in the
# bucket; if any bucket's ratio > 5 we trip the anomaly. A bucket with
# only one active region trivially has min==max so we skip it (no ratio
# to compare against).
imbalance_buckets = []
for i, b in enumerate(buckets):
    counts = b["region_counts"]
    if len(counts) < 2:
        continue
    vmax = max(counts.values())
    vmin = min(counts.values())
    if vmin == 0:
        # Defensive — shouldn't appear given the "blocks with >=1" gate
        # above; ratio is undefined, treat as imbalance signal.
        continue
    ratio = vmax / vmin
    if ratio > 5.0:
        imbalance_buckets.append({"bucket_idx": i, "from": b["from"],
                                   "to": b["to"], "ratio": ratio})
if imbalance_buckets:
    anomalies.append("region_imbalance_high")

# single_region_lock: same region is the dominant for > 80% of buckets
# (excluding buckets with no signal). We measure against signal-bearing
# buckets only — an empty-window region wouldn't satisfy a meaningful
# rotation requirement either way.
dom_counts = {}
signal_bucket_count = 0
for dom in dominant_per_bucket:
    if dom is None: continue
    dom_counts[dom] = dom_counts.get(dom, 0) + 1
    signal_bucket_count += 1
locked_region = None
if signal_bucket_count > 0:
    top_dom, top_count = max(dom_counts.items(), key=lambda kv: (kv[1], kv[0]))
    if (top_count / signal_bucket_count) > 0.80:
        locked_region = top_dom
        anomalies.append("single_region_lock")

# Summary block carried alongside anomalies for the renderer.
summary = {
    "abandoned_regions":  abandoned_regions,
    "imbalance_buckets":  imbalance_buckets[:10],  # cap renderer load
    "imbalance_total":    len(imbalance_buckets),
    "locked_region":      locked_region,
    "lock_share":         (max(dom_counts.values()) / signal_bucket_count) if signal_bucket_count > 0 and dom_counts else 0.0,
    "distinct_regions":   len(display_regions),
    "registered_regions": len(all_regions),
    "signal_buckets":     signal_bucket_count,
}

# Stable sort: appearance_rate desc, then region asc — matches the
# convention used by the validator-history audit (most-active rows
# first).
by_region.sort(key=lambda r: (-r["total_active_blocks"], r["region"]))

envelope = {
    "window": {
        "from":        from_h,
        "to":          to_h,
        "block_count": W,
    },
    "bucket_blocks":   bucket,
    "by_region":       by_region,
    "buckets":         buckets,
    "rotation_events": rotation_events,
    "summary":         summary,
    "anomalies":       anomalies,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 4: render envelope (text or JSON) ───────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WINDOW" "$BUCKET" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
from_h    = int(sys.argv[5])
to_h      = int(sys.argv[6])
window    = int(sys.argv[7])
bucket    = int(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)
env["rpc_port"] = port

anomalies = env.get("anomalies", []) or []
n_anom    = len(anomalies)

if json_out:
    # JSON shape per CLI contract: drop the helper-only `total_counts` /
    # `size` keys from each bucket (the `region_counts` field is the
    # documented "blocks-with-presence" histogram) and drop `summary`
    # (it's a renderer convenience; anomalies are the contract).
    out = {
        "rpc_port":        env["rpc_port"],
        "window":          {"from": env["window"]["from"], "to": env["window"]["to"]},
        "bucket_blocks":   env["bucket_blocks"],
        "by_region":       env["by_region"],
        "buckets":         [{"from": b["from"], "to": b["to"],
                             "dominant_region": b["dominant_region"],
                             "region_counts": b["region_counts"]}
                            for b in env["buckets"]],
        "rotation_events": env["rotation_events"],
        "anomalies":       anomalies,
    }
    print(json.dumps(out))
    sys.exit(0)

# --anomalies-only: suppress normal output unless an anomaly fired.
if anom_only and n_anom == 0:
    print(f"operator_validator_region_distribution: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks, "
          f"bucket {bucket})")
    sys.exit(0)

by_region = env["by_region"]
buckets   = env["buckets"]
rotation  = env["rotation_events"]
summary   = env["summary"]

print(f"=== Validator-region distribution (port {port}, "
      f"window [{from_h}..{to_h}], {window} blocks, bucket {bucket}) ===")
print(f"Distinct regions observed: {summary['distinct_regions']}    "
      f"Registered regions: {summary['registered_regions']}    "
      f"Rotation events: {rotation}")
print()

# Per-region table.
if by_region and not (anom_only and n_anom == 0):
    print("Per-region distribution (sorted by active blocks desc):")
    print(f"  {'region':<24} {'validators':>10} {'active_blks':>11} "
          f"{'rate':>7} {'long_absence':>13}")
    print(f"  {'-'*24} {'-'*10} {'-'*11} {'-'*7} {'-'*13}")
    for r in by_region:
        reg = r["region"][:24]
        rate_pct = f"{r['appearance_rate']*100:.1f}%"
        if anom_only:
            # Only show rows implicated in firing anomalies.
            implicated = False
            if r["region"] in (summary.get("abandoned_regions") or []):
                implicated = True
            if r["region"] == summary.get("locked_region"):
                implicated = True
            if not implicated:
                continue
        print(f"  {reg:<24} {r['validator_count']:>10} "
              f"{r['total_active_blocks']:>11} {rate_pct:>7} "
              f"{r['longest_absence']:>13}")
    print()

# Bucket histogram (compressed when there are >20 buckets — we show
# the first 10, an ellipsis, and the last 10 to keep terminal output
# scannable on long windows).
if buckets and not (anom_only and n_anom == 0):
    print(f"Per-bucket activity histogram ({len(buckets)} buckets of "
          f"{bucket} blocks):")
    # All region keys that appear in any bucket — order them by total
    # presence DESC so the histogram columns are stable across runs.
    region_totals = {}
    for b in buckets:
        for reg, c in b["region_counts"].items():
            region_totals[reg] = region_totals.get(reg, 0) + c
    region_order = [r for r, _ in sorted(region_totals.items(),
                                           key=lambda kv: (-kv[1], kv[0]))]

    # Truncate region columns when very wide (helps terminals).
    MAX_COLS = 6
    truncated_regions = region_order[:MAX_COLS]
    overflow = len(region_order) - len(truncated_regions)

    header = "  bucket               dominant      "
    for reg in truncated_regions:
        col = reg[:10]
        header += f"{col:>11} "
    if overflow > 0:
        header += f"(+{overflow} more)"
    print(header)
    print("  " + "-" * (len(header) - 2))

    def render_bucket(b):
        rng = f"[{b['from']:>5}..{b['to']:>5}]"
        dom = (b["dominant_region"] or "(none)")[:14]
        line = f"  {rng:<20} {dom:<14}"
        for reg in truncated_regions:
            c = b["region_counts"].get(reg, 0)
            line += f" {c:>10}"
        return line

    N = len(buckets)
    if N <= 20:
        for b in buckets:
            print(render_bucket(b))
    else:
        for b in buckets[:10]:
            print(render_bucket(b))
        print(f"  ... ({N - 20} buckets elided) ...")
        for b in buckets[-10:]:
            print(render_bucket(b))
    print()

# Rotation summary.
if not (anom_only and n_anom == 0):
    sig = summary["signal_buckets"]
    print(f"Rotation summary: {rotation} dominant-region transition(s) "
          f"across {sig} signal-bearing bucket(s)")
    if summary.get("locked_region") is not None:
        print(f"  Lock candidate: '{summary['locked_region']}' dominant in "
              f"{summary['lock_share']*100:.1f}% of signal-bearing buckets")
    print()

# Anomalies footer.
if n_anom == 0:
    print("[OK] Region distribution healthy")
else:
    for a in anomalies:
        if a == "region_abandoned":
            offenders = summary.get("abandoned_regions", []) or []
            disp = ", ".join(offenders[:5])
            if len(offenders) > 5:
                disp += f", +{len(offenders)-5} more"
            print(f"[CRITICAL] region_abandoned — {len(offenders)} region(s) "
                  f"with registered validators had ZERO creator-appearances "
                  f"in the window: {disp}")
        elif a == "region_imbalance_high":
            n = summary.get("imbalance_total", 0)
            print(f"[WARN] region_imbalance_high — {n} bucket(s) had "
                  f"max:min region-activity ratio > 5 (top examples):")
            for ib in (summary.get("imbalance_buckets", []) or [])[:5]:
                print(f"           bucket [{ib['from']}..{ib['to']}] "
                      f"ratio={ib['ratio']:.1f}")
            remaining = n - min(5, len(summary.get("imbalance_buckets", []) or []))
            if remaining > 0:
                print(f"           +{remaining} more buckets")
        elif a == "single_region_lock":
            print(f"[WARN] single_region_lock — '{summary.get('locked_region')}' "
                  f"was dominant in {summary['lock_share']*100:.1f}% of "
                  f"signal-bearing buckets (> 80% lock threshold)")
        else:
            print(f"[WARN] {a}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_validator_region_distribution: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# Same convention as sibling operator scripts: exit 2 only when
# --anomalies-only AND >=1 anomaly fired. The CRITICAL distinction
# (region_abandoned) is surfaced in the text output but doesn't change
# the exit code in default informational mode.
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
