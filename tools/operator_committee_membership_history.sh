#!/usr/bin/env bash
# operator_committee_membership_history.sh — Per-validator committee
# membership timeline + cross-validator co-occurrence audit over a
# window of finalized blocks. Companion to (but more granular than)
# its siblings:
#
#   operator_committee_audit.sh       Stake-proportional fairness audit
#                                     (deviation from stake-weighted
#                                     null) — answers "did each validator
#                                     get the right SHARE of slots?"
#   operator_committee_rotation.sh    Committee-as-multiset rotation rate
#                                     across the window — answers "how
#                                     often did the SET change?"
#   operator_committee_membership_history.sh  (THIS)
#                                     Per-validator timeline + pair-wise
#                                     co-occurrence — answers "WHICH
#                                     blocks did each validator appear
#                                     in, what gaps did they have, and
#                                     which validators consistently
#                                     showed up TOGETHER?"
#
# Algorithm:
#   For each block in [--from..--to] (default last 1000), extract
#   creators[] via `determ block-info H --json`. For each validator
#   observed in any block:
#     appearances             = count of blocks present in creators[]
#     appearance_rate         = appearances / window_size
#     longest_consecutive_in  = longest run of consecutive heights
#                               where the validator appeared
#     longest_consecutive_out = longest run of consecutive heights
#                               where the validator was absent
#     first_seen_height       = lowest block index with a hit
#     last_seen_height        = highest block index with a hit
#   For each ordered-pair (d1 < d2): count blocks where BOTH appeared.
#
# Co-occurrence model:
#   Under a uniform-random committee selection from a pool of size N
#   with committee size K, the expected co-occurrence rate between any
#   two pool members in any single block is approximately (K/N)*((K-1)/(N-1)).
#   In a stake-weighted draw it tracks (stake_i*stake_j)/(total^2)·K(K-1).
#   Substantially-higher empirical co-occurrence between a SPECIFIC pair
#   relative to each validator's individual selection rate is the classic
#   Sybil-clique signature: two domains that "always show up together"
#   are likely controlled by one operator coordinating draws.
#
# Anomalies (alert-worthy; gate exit code 2 under --anomalies-only):
#   validator_long_absence    any validator with longest_consecutive_out
#                             > 0.50 * window_size — sustained committee
#                             exclusion despite being registered (selection
#                             bias OR honest under-staking).
#   validator_clique_detected any pair with co-occurrence > 80% of either
#                             validator's individual appearance count AND
#                             both have > 10 appearances — co-occurrence
#                             higher than chance would predict; Sybil
#                             signal.
#   validator_overrepresented any single validator with appearance_rate >
#                             0.50 * (K / pool_size) * 3 — appears at
#                             3x the fair expected rate; concentration
#                             signal that complements the bias audit's
#                             "validator_dominant" check (this one fires
#                             earlier — at 3x fair, not at 50% of blocks).
#
# Pool composition: validators are inferred from `determ validators
# --json` at audit time, same caveat as operator_committee_audit.sh —
# the snapshot reflects the *current* registry; mid-window churn introduces
# minor reporting error. The `pool_size` used for the over-representation
# anomaly is len(validators) at the time of the RPC call.
#
# Args:
#   [--rpc-port N]            RPC port to query (REQUIRED)
#   [--from H]                Lower window bound, inclusive (default: head-999)
#   [--to H]                  Upper window bound, inclusive (default: head)
#   [--last N]                Shorthand for --from (head-N+1) --to head
#                             (mutually exclusive with --from / --to)
#   [--validator <domain>]    Filter human-table output to a single
#                             validator (cosmetic; per-validator stats
#                             + anomalies still computed across the full
#                             population so cross-validator anomalies
#                             remain visible)
#   [--top-cooccurrence N]    Emit the top-N validator pairs that
#                             co-occurred most frequently in default
#                             mode (default 10; N=0 suppresses)
#   [--json]                  Emit structured JSON envelope
#   [--anomalies-only]        Suppress healthy-state rows; exit 2 if
#                             any anomaly fires
#   [-h|--help]               Show this help
#
# Exit codes:
#   0   success, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND >=1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_committee_membership_history.sh --rpc-port N
                                                [--from H] [--to H] [--last N]
                                                [--validator <domain>]
                                                [--top-cooccurrence N]
                                                [--json] [--anomalies-only]

Per-validator committee membership timeline over a window of finalized
blocks. For each block, extracts creators[] via `determ block-info <h>
--json` and tracks which validators appeared. Reports per-validator
appearance counts, longest in-streak / out-streak, first/last seen
heights, and the top-N most-frequent validator co-occurrence pairs
(Sybil-clique signal).

Options:
  --rpc-port N            RPC port to query (REQUIRED)
  --from H                Lower window bound, inclusive (default: head-999)
  --to H                  Upper window bound, inclusive (default: head)
  --last N                Shorthand for [head-N+1 .. head] (exclusive
                          with --from / --to)
  --validator <domain>    Filter the per-validator table to a single
                          domain (cosmetic only; cross-validator
                          anomalies still computed across full pool)
  --top-cooccurrence N    Emit the top-N most-frequent validator pairs
                          (default 10; pass 0 to suppress)
  --json                  Emit structured JSON envelope
  --anomalies-only        Suppress healthy-state rows; exit 2 if any
                          anomaly fires
  -h, --help              Show this help

Anomalies:
  validator_long_absence       longest_consecutive_out > 0.50 * window
  validator_clique_detected    pair co-occurrence > 80% of either
                               validator's individual appearance count
                               AND both have > 10 appearances
  validator_overrepresented    appearance_rate > 0.50 * (K/pool_size) * 3

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W},
   "K": K, "pool_size": N,
   "by_validator": [
     {"domain": "...", "appearances": A, "rate": R,
      "longest_consecutive_in": I, "longest_consecutive_out": O,
      "first_seen_height": F|null, "last_seen_height": L|null}, ...],
   "cooccurrence": [
     {"pair": [d1, d2], "count": C}, ...],
   "summary": {"distinct_validators": D, "total_pairs": P},
   "anomalies": [...],
   "rpc_port": P}

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
VALIDATOR=""
TOP_COOC="10"
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 1 ;;
    --rpc-port)           PORT="${2:-}";       shift 2 ;;
    --from)               FROM="${2:-}";       shift 2 ;;
    --to)                 TO="${2:-}";         shift 2 ;;
    --last)               LAST="${2:-}";       shift 2 ;;
    --validator)          VALIDATOR="${2:-}";  shift 2 ;;
    --top-cooccurrence)   TOP_COOC="${2:-}";   shift 2 ;;
    --json)               JSON_OUT=1;          shift ;;
    --anomalies-only)     ANOM_ONLY=1;         shift ;;
    *) echo "operator_committee_membership_history: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; refuses to guess
# the daemon on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_committee_membership_history: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_committee_membership_history: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --last is mutually exclusive with --from / --to.
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_committee_membership_history: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_committee_membership_history: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_committee_membership_history: --last must be >= 1" >&2
  exit 1
fi

# --top-cooccurrence: non-negative integer.
case "$TOP_COOC" in *[!0-9]*|"")
  echo "operator_committee_membership_history: --top-cooccurrence must be a non-negative integer (got '$TOP_COOC')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (matches operator_committee_audit.sh /
# operator_dapp_inventory.sh).
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
  echo "operator_committee_membership_history: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
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
  echo "operator_committee_membership_history: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1. (Block 0 is genesis with empty
# creators[]; it contributes a "no validators present" sample to the
# window if included.)
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. Precedence: --last > (--from/--to) > defaults.
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
  echo "operator_committee_membership_history: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: pool snapshot from validators RPC ─────────────────────────────────
VAL_JSON=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_membership_history: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}

# ── Step 3: per-block walk + per-validator timeline (driven from Python) ──────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_committee_membership_history: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" "$TOP_COOC" <<PY
import json, subprocess, sys

determ, port, from_h, to_h, out_path, top_cooc_s = sys.argv[1:7]
from_h, to_h = int(from_h), int(to_h)
top_cooc = int(top_cooc_s)

# Validators snapshot for pool-size baseline. The membership data itself
# is sourced from blocks (any creator in any block is tracked), so a
# validator that left the registry mid-window still gets a timeline.
val_json = '''$VAL_JSON'''
try:
    validators = json.loads(val_json)
except Exception:
    sys.stderr.write("operator_committee_membership_history: malformed validators JSON\n")
    sys.exit(1)
if not isinstance(validators, list):
    sys.stderr.write("operator_committee_membership_history: validators RPC returned non-array\n")
    sys.exit(1)

# Pool snapshot (used only for the over-representation anomaly's
# "fair expected rate" baseline).
pool_size = sum(1 for v in validators if isinstance(v, dict) and isinstance(v.get("domain"), str))

# Per-validator presence vector. presence[domain] is a sorted list of
# block heights where the validator appeared. Building the vector first
# (rather than running stats inline) keeps the longest-streak math
# straightforward.
presence       = {}  # domain -> list[int] (ascending block heights)
# Per-block committee snapshot, used for the co-occurrence pass after
# the walk. Stored as sorted tuples (multiset is fine because creators
# rarely repeat within a single block — but defensively dedupe with set()
# before sorting to avoid double-counting if it ever does).
block_creators = []  # list[tuple(str)] indexed parallel to range(from_h, to_h+1)
size_dist      = {}  # K -> count

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_committee_membership_history: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_committee_membership_history: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_committee_membership_history: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        block_creators.append(tuple())
        continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    # Dedupe + filter to strings. Sorted tuple gives the co-occurrence
    # pass a deterministic iteration order.
    creators = tuple(sorted(set(c for c in creators if isinstance(c, str))))

    K = len(creators)
    size_dist[K] = size_dist.get(K, 0) + 1

    for dom in creators:
        presence.setdefault(dom, []).append(h)
    block_creators.append(creators)

W = to_h - from_h + 1

# Modal K (matches operator_committee_audit.sh convention — tie-break
# toward the larger K).
if size_dist:
    K_modal = max(size_dist.items(), key=lambda kv: (kv[1], kv[0]))[0]
else:
    K_modal = 0

# ── Per-validator stats ──────────────────────────────────────────────────────
def longest_run_consecutive(heights):
    # Longest run of consecutive integers in the sorted list.
    if not heights:
        return 0
    best = cur = 1
    for i in range(1, len(heights)):
        if heights[i] == heights[i-1] + 1:
            cur += 1
            if cur > best: best = cur
        else:
            cur = 1
    return best

def longest_absence(heights, lo, hi):
    # Longest stretch of consecutive heights in [lo..hi] NOT in `heights`.
    # `heights` is sorted ascending and a subset of [lo..hi].
    # Compute by scanning gaps between successive presences + the head
    # gap [lo..first-1] + the tail gap [last+1..hi].
    if not heights:
        return hi - lo + 1
    best = 0
    head_gap = heights[0] - lo
    if head_gap > best: best = head_gap
    for i in range(1, len(heights)):
        gap = heights[i] - heights[i-1] - 1
        if gap > best: best = gap
    tail_gap = hi - heights[-1]
    if tail_gap > best: best = tail_gap
    return best

by_validator = []
for dom, hits in presence.items():
    A = len(hits)
    rate = (A / W) if W > 0 else 0.0
    by_validator.append({
        "domain":                  dom,
        "appearances":             A,
        "rate":                    rate,
        "longest_consecutive_in":  longest_run_consecutive(hits),
        "longest_consecutive_out": longest_absence(hits, from_h, to_h),
        "first_seen_height":       hits[0],
        "last_seen_height":        hits[-1],
    })

# Sort: appearances desc, then domain asc (stable for tie display).
by_validator.sort(key=lambda r: (-r["appearances"], r["domain"]))

# ── Pair co-occurrence ───────────────────────────────────────────────────────
# Count blocks where both domains appeared. Using a dict keyed by the
# sorted-tuple pair so each unordered pair is counted once. For pools
# of N validators with committee size K, each block contributes
# K*(K-1)/2 pairs — bounded across the full window.
pair_counts = {}
for creators in block_creators:
    n = len(creators)
    for i in range(n):
        for j in range(i + 1, n):
            key = (creators[i], creators[j])
            pair_counts[key] = pair_counts.get(key, 0) + 1

# Sort: count desc, then domain pair asc (deterministic display).
cooccurrence_all = sorted(
    ({"pair": list(p), "count": c} for p, c in pair_counts.items()),
    key=lambda r: (-r["count"], r["pair"][0], r["pair"][1])
)

# Top-N for default-output cap. JSON envelope carries the same top-N
# slice (full pair list would balloon JSON size with no operator
# benefit at the usual W=1000 / N=O(10) scale).
if top_cooc > 0:
    cooccurrence_top = cooccurrence_all[:top_cooc]
else:
    cooccurrence_top = []

# ── Anomaly classification ───────────────────────────────────────────────────
anomalies = []

# validator_long_absence: any validator's longest_consecutive_out exceeds
# 50% of window. Only meaningful when the validator actually appeared in
# the window — a fully-absent validator's longest_out IS the whole window
# and would always trip this; that's covered by the existing
# operator_committee_audit's `validator_excluded` anomaly so we skip it
# here.
absence_threshold = W * 0.5
absent_offenders = []
for row in by_validator:
    if row["appearances"] > 0 and row["longest_consecutive_out"] > absence_threshold:
        absent_offenders.append(row["domain"])
if absent_offenders:
    anomalies.append("validator_long_absence")

# validator_overrepresented: any validator with appearance_rate >
# 0.50 * (K/pool_size) * 3. Fair expected rate per validator under
# uniform draw is K/pool_size; we flag at 3x that scaled by 50%
# (i.e. 1.5x K/pool_size in raw terms). The 0.50 multiplier mirrors
# the task spec's exact threshold. Skip when pool_size == 0 (cannot
# compute baseline).
over_offenders = []
if pool_size > 0 and K_modal > 0:
    fair_rate = K_modal / pool_size
    over_threshold = 0.50 * fair_rate * 3
    for row in by_validator:
        if row["rate"] > over_threshold:
            over_offenders.append(row["domain"])
if over_offenders:
    anomalies.append("validator_overrepresented")

# validator_clique_detected: any pair with co-occurrence > 80% of EITHER
# validator's individual appearance count AND both have > 10 appearances.
# The 80%-of-either bound catches asymmetric cliques (a "satellite"
# validator who only shows up when its "anchor" does — even if the anchor
# also shows up sometimes alone). The 10-appearances floor avoids
# small-sample noise (two validators each appearing twice and overlapping
# both times trivially satisfy the ratio bound).
appearance_map = {r["domain"]: r["appearances"] for r in by_validator}
clique_pairs = []
for entry in cooccurrence_all:
    d1, d2 = entry["pair"]
    c = entry["count"]
    a1 = appearance_map.get(d1, 0)
    a2 = appearance_map.get(d2, 0)
    if a1 <= 10 or a2 <= 10:
        continue
    ratio_to_max = c / max(a1, a2) if max(a1, a2) > 0 else 0.0
    if ratio_to_max > 0.80:
        clique_pairs.append({"pair": [d1, d2], "count": c,
                              "rate_vs_max": ratio_to_max})
if clique_pairs:
    anomalies.append("validator_clique_detected")

# Summary footer.
summary = {
    "distinct_validators": len(by_validator),
    "total_pairs":         len(pair_counts),
    "absent_offenders":    absent_offenders,
    "over_offenders":      over_offenders,
    "clique_pairs":        clique_pairs,
}

envelope = {
    "window": {
        "from":        from_h,
        "to":          to_h,
        "block_count": W,
    },
    "K":            K_modal,
    "pool_size":    pool_size,
    "by_validator": by_validator,
    "cooccurrence": cooccurrence_top,
    "summary":      summary,
    "anomalies":    anomalies,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 4: render envelope (text or JSON) ───────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WINDOW" \
        "$VALIDATOR" "$TOP_COOC" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
from_h    = int(sys.argv[5])
to_h      = int(sys.argv[6])
window    = int(sys.argv[7])
validator = sys.argv[8]
top_cooc  = int(sys.argv[9])

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)
env["rpc_port"] = port

anomalies = env.get("anomalies", []) or []
n_anom    = len(anomalies)

if json_out:
    # JSON mode honors --validator as a filter on by_validator (cosmetic)
    # but keeps the cooccurrence + anomalies arrays intact for machine
    # consumers — they need the full population to detect Sybil cliques.
    if validator:
        env["by_validator"] = [r for r in env["by_validator"]
                                if r["domain"] == validator]
    print(json.dumps(env))
    sys.exit(0)

# --anomalies-only: suppress normal output unless an anomaly fired.
if anom_only and n_anom == 0:
    print(f"operator_committee_membership_history: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks)")
    sys.exit(0)

K           = env["K"]
pool_size   = env["pool_size"]
by_val      = env["by_validator"]
cooc        = env["cooccurrence"]
summary     = env["summary"]

print(f"=== Committee membership history (port {port}, "
      f"window [{from_h}..{to_h}], {window} blocks) ===")
print(f"Distinct validators observed: {summary['distinct_validators']}    "
      f"Committee size K (modal): {K}    Pool size: {pool_size}")
print()

# Apply cosmetic --validator filter (per-validator table only).
if validator:
    rows_disp = [r for r in by_val if r["domain"] == validator]
    if not rows_disp:
        print(f"(no observations for validator '{validator}' in window)")
        rows_disp = []
else:
    rows_disp = by_val

if rows_disp and not (anom_only and n_anom == 0):
    print("Per-validator timeline (sorted by appearances desc):")
    print(f"  {'domain':<32} {'appear':>7} {'rate':>7} "
          f"{'long_in':>8} {'long_out':>9} {'first':>10} {'last':>10}")
    print(f"  {'-'*32} {'-'*7} {'-'*7} "
          f"{'-'*8} {'-'*9} {'-'*10} {'-'*10}")
    for r in rows_disp:
        dom = r["domain"][:32]
        # In anomalies-only mode, hide rows that aren't implicated in any
        # firing anomaly. Implication = present in any of summary's
        # offender lists OR a clique pair.
        if anom_only:
            absent_set = set(summary.get("absent_offenders", []) or [])
            over_set   = set(summary.get("over_offenders", []) or [])
            clique_doms = set()
            for cp in (summary.get("clique_pairs", []) or []):
                clique_doms.update(cp["pair"])
            implicated = (r["domain"] in absent_set
                          or r["domain"] in over_set
                          or r["domain"] in clique_doms)
            if not implicated:
                continue
        rate_pct = f"{r['rate']*100:.1f}%"
        print(f"  {dom:<32} {r['appearances']:>7} {rate_pct:>7} "
              f"{r['longest_consecutive_in']:>8} {r['longest_consecutive_out']:>9} "
              f"{r['first_seen_height']:>10} {r['last_seen_height']:>10}")
    print()

# Top-N co-occurrence (suppressed when --top-cooccurrence 0 or when
# --validator filter is in play AND anomalies-only mode active).
if top_cooc > 0 and cooc and not (anom_only and n_anom == 0):
    print(f"Top-{top_cooc} validator co-occurrence pairs "
          f"(blocks where both appeared):")
    print(f"  {'count':>6}  {'rate_vs_max':>12}  validator pair")
    print(f"  {'-'*6:>6}  {'-'*12:>12}  {'-'*48}")
    appearance_map = {r["domain"]: r["appearances"] for r in by_val}
    for entry in cooc:
        d1, d2 = entry["pair"]
        c = entry["count"]
        a1 = appearance_map.get(d1, 0)
        a2 = appearance_map.get(d2, 0)
        denom = max(a1, a2) if max(a1, a2) > 0 else 1
        rv = c / denom
        pair_disp = f"{d1} <-> {d2}"
        if len(pair_disp) > 48: pair_disp = pair_disp[:45] + "..."
        print(f"  {c:>6}  {rv*100:>11.1f}%  {pair_disp}")
    print()

# Summary footer.
print(f"Summary: distinct_validators={summary['distinct_validators']}, "
      f"total_pairs={summary['total_pairs']}")
print()

if n_anom == 0:
    print("[OK] Membership distribution healthy")
else:
    for a in anomalies:
        if a == "validator_long_absence":
            offenders = summary.get("absent_offenders", []) or []
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            print(f"[WARN] validator_long_absence — validator(s) absent for "
                  f">50% of window: {disp}")
        elif a == "validator_overrepresented":
            offenders = summary.get("over_offenders", []) or []
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            print(f"[WARN] validator_overrepresented — validator(s) "
                  f"selected at >3x the fair rate (rate > 0.5*(K/N)*3 = "
                  f"{(0.5 * (K/pool_size) * 3) if pool_size > 0 else 0:.3f}): "
                  f"{disp}")
        elif a == "validator_clique_detected":
            pairs = summary.get("clique_pairs", []) or []
            print(f"[WARN] validator_clique_detected — {len(pairs)} pair(s) "
                  f"co-occurred in >80% of either validator's appearances "
                  f"(both with >10 appearances) — Sybil-clique signal:")
            for cp in pairs[:5]:
                d1, d2 = cp["pair"]
                print(f"           {d1} <-> {d2} "
                      f"(count={cp['count']}, "
                      f"rate_vs_max={cp['rate_vs_max']*100:.1f}%)")
            if len(pairs) > 5:
                print(f"           +{len(pairs)-5} more pairs")
        else:
            print(f"[WARN] {a}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_committee_membership_history: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# Same convention as operator_committee_audit.sh: exit 2 only when
# --anomalies-only AND >=1 anomaly fired. Default informational mode
# always exits 0 if the RPC walk succeeded.
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
