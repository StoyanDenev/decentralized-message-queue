#!/usr/bin/env bash
# operator_region_balance_audit.sh — Audit per-region balance + stake
# distribution + validator count on a running determ daemon.
#
# Determ R4 sharding is region-aware: each registered validator carries
# a `region` field (RegistryEntry.region from genesis-tool peer-info
# --region T or REGISTER tx region payload). Committee selection
# composes region-pinned subsets so the regional pool's stake mix and
# validator count directly drive censorship-resistance and BFT-quorum
# diversity per region. Operators running multi-region deployments
# need per-region snapshots:
#   - Total stake locked by validators in region R.
#   - Total balance held by validators in region R (idle capital +
#     accrued operator fee revenue).
#   - Validator count + stake-per-validator distribution.
#   - Cross-region imbalance (does one region hold disproportionate
#     stake? — sharding-defeats-Sybil rationale requires no single
#     region exceeds the cartel-resistance floor).
#
# Sibling-script positioning:
#
#   operator_stake_concentration.sh   GLOBAL stake Gini + top-N concentration
#                                     across the entire validator set. Doesn't
#                                     decompose by region.
#
#   operator_balance_distribution.sh  GLOBAL balance Gini across all
#                                     accounts (the full ledger). Doesn't
#                                     restrict to validators or partition by
#                                     region.
#
#   operator_validator_unstake_pipeline.sh
#                                     Exit-pipeline tracker (DEREGISTER →
#                                     UNSTAKE pairing with unlock_height
#                                     countdown). Orthogonal: tracks EXITING
#                                     validators, not the regional
#                                     distribution of active validators.
#
#   operator_region_balance_audit.sh (THIS)
#                                     Per-region aggregation of validator
#                                     count + total stake + total balance,
#                                     plus cross-region skew detection.
#                                     Surfaces single-region-dominance as
#                                     the Sybil-resistance breakdown signal
#                                     for R4 regional sharding (R0-R7).
#
# Pipeline (read-only RPC, no snapshot required):
#   1.  `determ stakes --json --rpc-port P` — flat JSON array of
#       {rank, domain, stake, active_from, region, ed_pub}. Already
#       sorted by stake DESC, ties broken by domain ASC. The `region`
#       field is the per-validator regional tag from RegistryEntry.region
#       (empty string for unpinned / global validators; we normalize
#       to "(global)" in human output and "" in the JSON envelope so
#       JSON consumers can filter cleanly).
#   2.  For each validator domain D, `determ show-account D --json`
#       returns {address, is_anonymous, balance, next_nonce, stake,
#       registry} — same RPC the dapp_balance_audit / supply_check
#       scripts use. We pull .balance which is the per-validator idle
#       balance (separate from stake_locked — `stake` field is
#       redundant with the StakeEntry.locked already in `stakes` but
#       we re-read for consistency with the show-account observation).
#   3.  Per-region aggregation: total_stake, validator_count,
#       mean_stake_per_validator, min_stake, max_stake, total_balance,
#       mean_balance, min_balance, max_balance.
#   4.  Cross-region: standard deviation across region totals,
#       max:min stake ratio, max:min validator-count ratio, regional
#       share of total stake.
#
# Anomaly flags (each adds to anomalies[]; --anomalies-only exits 2 if
# any fire; --single-region-dominance is the CRITICAL escalation):
#
#   - region_stake_imbalance         (WARN) any region's total_stake
#                                    exceeds (1 + imbalance_threshold_pct)
#                                    × mean_region_total_stake. Default
#                                    threshold 0.50 → fires when any
#                                    region holds > 1.50× the mean
#                                    regional stake. Captures "one region
#                                    much larger than others" without
#                                    triggering on the inverse direction
#                                    (under-staked regions are flagged
#                                    via empty_region + skew).
#
#   - single_region_dominance        (CRITICAL) any single region holds
#                                    more than --single-region-dominance-
#                                    threshold-pct of total stake. Default
#                                    0.60 → fires when one region accounts
#                                    for > 60% of all stake. R4 sharding-
#                                    defeats-Sybil rationale requires no
#                                    single region exceeds the cartel-
#                                    resistance floor; once one region
#                                    holds the majority of stake the
#                                    cross-region adversary model collapses
#                                    to the single-region model.
#
#   - empty_region                   (WARN) any region appears in the
#                                    chain's known-region set with 0
#                                    active validators. This is a stale-
#                                    pool signal (all validators in that
#                                    region deregistered or migrated out;
#                                    region tag still in use by the
#                                    chain's region-aware structures
#                                    but no one is selected for it).
#                                    Note: we can only detect empty
#                                    regions that have ever had a
#                                    validator — we don't have access
#                                    to the "configured region set"
#                                    independent of validator membership.
#
#   - region_validator_count_skew    (WARN) max:min validator-count ratio
#                                    > 5. Heavy validator-count asymmetry
#                                    increases coordination cost between
#                                    regions and can degrade cross-shard
#                                    receipt liveness (the smaller region
#                                    can be cornered by a small adversary).
#
# RPC dependencies (read-only):
#   - head                           current chain height (banner only)
#   - validators (via `stakes`)      full validator set + region
#   - account    (via `show-account`)per-validator balance
#
# Usage:
#   tools/operator_region_balance_audit.sh --rpc-port N
#       [--imbalance-threshold-pct F]
#       [--single-region-dominance-threshold-pct F]
#       [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N                                RPC port to query (REQUIRED)
#   --imbalance-threshold-pct F                 Fire region_stake_imbalance
#                                               when region_total_stake >
#                                               (1 + F) × mean. Default 0.50.
#   --single-region-dominance-threshold-pct F   Fire single_region_dominance
#                                               when one region holds > F of
#                                               total stake. Default 0.60.
#   --json                                      Emit structured JSON envelope
#   --anomalies-only                            Suppress healthy rows;
#                                               exit 2 iff any anomaly fires
#   -h, --help                                  Show this help
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate);
#       CRITICAL anomalies (single_region_dominance) always promote to 2
#       even outside --anomalies-only when one fires.
set -u

usage() {
  cat <<'EOF'
Usage: operator_region_balance_audit.sh --rpc-port N
       [--imbalance-threshold-pct F]
       [--single-region-dominance-threshold-pct F]
       [--json] [--anomalies-only]

Audit per-region validator-set distribution on a running determ daemon.
Walks the validator set via `determ stakes --json`, partitions by
RegistryEntry.region, fetches each validator's balance via
`determ show-account --json`, then reports per-region aggregates +
cross-region skew + Sybil-resistance signals.

Sibling of operator_stake_concentration.sh (which does the same
analysis GLOBALLY rather than per-region) and operator_validator_
unstake_pipeline.sh (which tracks the EXIT side rather than the
regional distribution of active validators).

Options:
  --rpc-port N                              RPC port to query (required)
  --imbalance-threshold-pct F               Fire region_stake_imbalance
                                            when any region_total_stake >
                                            (1 + F) × mean. Default: 0.50.
  --single-region-dominance-threshold-pct F Fire single_region_dominance
                                            when any single region holds
                                            > F of total stake. Default: 0.60.
  --json                                    Emit structured JSON envelope
  --anomalies-only                          Suppress healthy rows; exit 2
                                            if ≥1 anomaly fires
  -h, --help                                Show this help

Anomalies:
  region_stake_imbalance        (WARN) region_total_stake > (1 + thr) × mean
  single_region_dominance       (CRITICAL) one region holds > thr of total
  empty_region                  (WARN) region appears with 0 active validators
  region_validator_count_skew   (WARN) max:min validator-count ratio > 5

Exit codes:
  0   success (no anomalies, or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired; single_region_dominance
      (CRITICAL) always promotes to 2 even outside --anomalies-only
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
IMBAL_PCT="0.50"
DOMINANCE_PCT="0.60"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage; exit 0 ;;
    --rpc-port)
      PORT="${2:-}"; shift 2 ;;
    --imbalance-threshold-pct)
      IMBAL_PCT="${2:-}"; shift 2 ;;
    --single-region-dominance-threshold-pct)
      DOMINANCE_PCT="${2:-}"; shift 2 ;;
    --json)
      JSON_OUT=1; shift ;;
    --anomalies-only)
      ANOM_ONLY=1; shift ;;
    *)
      echo "operator_region_balance_audit: unknown argument: $1" >&2
      usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required per the spec.
case "$PORT" in *[!0-9]*|"")
  echo "operator_region_balance_audit: --rpc-port is required and must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Float guards on the two threshold knobs. Accept the standard decimal
# forms (e.g. "0.50", "0.60", "1.0"). Reject anything that python can't
# parse — caught downstream but cheaper to fail fast.
validate_float() {
  local name="$1" val="$2"
  case "$val" in
    ""|*[!0-9.]*)
      echo "operator_region_balance_audit: $name must be a decimal in [0,10] (got '$val')" >&2
      exit 1 ;;
  esac
  # Range check via python so we don't reimplement float compare in
  # POSIX shell. Imbalance threshold can legitimately exceed 1.0 (e.g.
  # 2.0 = "fire when 3× the mean"); we cap at 10.0 to catch typos.
  # Dominance is a share so must land in [0.0, 1.0].
  if ! python -c "import sys; v=float('$val'); sys.exit(0 if 0.0<=v<=10.0 else 1)" 2>/dev/null; then
    echo "operator_region_balance_audit: $name must be in [0.0, 10.0] (got '$val')" >&2
    exit 1
  fi
}
validate_float "--imbalance-threshold-pct"                "$IMBAL_PCT"
validate_float "--single-region-dominance-threshold-pct"  "$DOMINANCE_PCT"
# Extra range check for dominance: it's a share so cap at 1.0.
if ! python -c "import sys; v=float('$DOMINANCE_PCT'); sys.exit(0 if 0.0<=v<=1.0 else 1)" 2>/dev/null; then
  echo "operator_region_balance_audit: --single-region-dominance-threshold-pct must be in [0.0, 1.0] (got '$DOMINANCE_PCT')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current chain head (banner only) ─────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_region_balance_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_region_balance_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: fetch full stakes list (NO --top cap; we need every region) ──────
STAKES_OUT=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_region_balance_audit: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_region_balance_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

# ── Step 3: per-validator balance fetch + per-region aggregation ─────────────
# Python handles: stakes JSON parse, per-validator show-account fan-out,
# region partition, cross-region statistics, anomaly classification.
DETERM_BIN_ABS="$DETERM"
python - "$STAKES_OUT" "$TMP_OUT" "$IMBAL_PCT" "$DOMINANCE_PCT" \
        "$PORT" "$DETERM_BIN_ABS" <<'PY'
import json, sys, subprocess, math

(stakes_raw, out_path, imbal_pct_s, dominance_pct_s,
 port, determ) = sys.argv[1:7]
imbal_pct       = float(imbal_pct_s)
dominance_pct   = float(dominance_pct_s)
# Threshold-bps form for integer comparisons. Dominance is a share so
# *10000 lands in 0..10000. Imbalance is a deviation multiplier so
# *10000 can exceed 10000 (e.g. 2.0 → 20000); int math is still exact.
dominance_thr_bps = int(round(dominance_pct * 10000))

try:
    stakes = json.loads(stakes_raw)
except Exception as e:
    sys.stderr.write(f"operator_region_balance_audit: cannot parse stakes JSON: {e}\n")
    sys.exit(1)
if not isinstance(stakes, list):
    sys.stderr.write("operator_region_balance_audit: stakes RPC is not a JSON array\n")
    sys.exit(1)

# Materialize per-validator records. Region empty-string means "no
# regional pin" — common on small/test deployments without R4 regional
# sharding enabled. We treat empty-string as its own bucket so the
# operator can see at-a-glance how many validators are unpinned.
validators = []
for v in stakes:
    if not isinstance(v, dict):
        continue
    d = v.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    s = int(v.get("stake", 0) or 0)
    r = v.get("region", "") or ""
    if not isinstance(r, str):
        r = ""
    validators.append({"domain": d, "stake": s, "region": r, "balance": 0})

total_validators = len(validators)

# ── Per-validator balance fetch via show-account ───────────────────
# This is the only N-RPC fan-out in the script. For each validator
# domain we issue `determ show-account D --json` and read .balance.
# Failures (non-zero rc, non-JSON, missing balance) abort the whole
# script — we'd rather fail loudly than silently emit per-region
# totals with a missing slice.
for v in validators:
    try:
        r = subprocess.run(
            [determ, "show-account", v["domain"], "--json",
             "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(
            f"operator_region_balance_audit: show-account {v['domain']} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_region_balance_audit: show-account {v['domain']} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        acct = json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception:
        sys.stderr.write(
            f"operator_region_balance_audit: show-account {v['domain']} returned non-JSON\n")
        sys.exit(1)
    if acct is None or acct == {}:
        # No on-chain state — shouldn't happen for a validator we got
        # from the stakes RPC, but defensively treat as zero balance.
        v["balance"] = 0
    else:
        v["balance"] = int(acct.get("balance", 0) or 0)

# ── Per-region aggregation ─────────────────────────────────────────
by_region = {}  # region -> aggregate dict
for v in validators:
    region = v["region"]
    if region not in by_region:
        by_region[region] = {
            "region":          region,
            "validator_count": 0,
            "total_stake":     0,
            "total_balance":   0,
            "min_stake":       None,
            "max_stake":       0,
            "min_balance":     None,
            "max_balance":     0,
        }
    agg = by_region[region]
    agg["validator_count"] += 1
    agg["total_stake"]     += v["stake"]
    agg["total_balance"]   += v["balance"]
    agg["min_stake"]   = v["stake"] if agg["min_stake"] is None \
                                       else min(agg["min_stake"], v["stake"])
    agg["max_stake"]   = max(agg["max_stake"], v["stake"])
    agg["min_balance"] = v["balance"] if agg["min_balance"] is None \
                                       else min(agg["min_balance"], v["balance"])
    agg["max_balance"] = max(agg["max_balance"], v["balance"])

# Finalize means + ordering. Sort by region name ASC for stable output;
# the empty-string ("(global)" in human display) sorts to the top.
region_rows = []
for region in sorted(by_region.keys()):
    agg = by_region[region]
    vc = agg["validator_count"]
    agg["mean_stake"]   = (agg["total_stake"]   // vc) if vc > 0 else 0
    agg["mean_balance"] = (agg["total_balance"] // vc) if vc > 0 else 0
    # Normalize None min_* (the no-validators degenerate case) to 0
    # for clean JSON; the count == 0 elsewhere makes it unambiguous.
    if agg["min_stake"]   is None: agg["min_stake"]   = 0
    if agg["min_balance"] is None: agg["min_balance"] = 0
    region_rows.append(agg)

# ── Cross-region statistics ────────────────────────────────────────
total_regions    = len(region_rows)
total_stake      = sum(r["total_stake"]   for r in region_rows)
total_balance    = sum(r["total_balance"] for r in region_rows)
counts           = [r["validator_count"] for r in region_rows]
stakes_per_reg   = [r["total_stake"]     for r in region_rows]

# Standard deviation of region stake totals. Uses population stddev
# (N denominator) — we're describing the entire region set, not a
# sample from a larger population.
if total_regions > 0:
    mean_region_stake = total_stake / total_regions
    variance = sum((s - mean_region_stake) ** 2 for s in stakes_per_reg) / total_regions
    stake_stddev = math.sqrt(variance)
else:
    mean_region_stake = 0.0
    stake_stddev = 0.0

# max:min validator-count ratio. We exclude regions with 0 validators
# from the denominator so the "ratio is infinity" pathology doesn't
# inflate; the empty_region anomaly handles that case directly.
nonzero_counts = [c for c in counts if c > 0]
if len(nonzero_counts) >= 2:
    vc_max_min_ratio = max(nonzero_counts) / min(nonzero_counts)
elif len(nonzero_counts) == 1:
    vc_max_min_ratio = 1.0
else:
    vc_max_min_ratio = 0.0

# max:min stake ratio — same exclusion logic.
nonzero_stakes = [s for s in stakes_per_reg if s > 0]
if len(nonzero_stakes) >= 2:
    stake_max_min_ratio = max(nonzero_stakes) / min(nonzero_stakes)
elif len(nonzero_stakes) == 1:
    stake_max_min_ratio = 1.0
else:
    stake_max_min_ratio = 0.0

# Region share of total stake (in bps for exact integer comparison
# against the dominance threshold).
for r in region_rows:
    if total_stake > 0:
        r["stake_share_bps"] = (r["total_stake"] * 10000) // total_stake
    else:
        r["stake_share_bps"] = 0

# ── Anomaly classification ────────────────────────────────────────
# Order matters for the human report (most severe first):
#   single_region_dominance  CRITICAL  always promotes exit to 2
#   region_stake_imbalance   WARN      threshold check
#   empty_region             WARN      0-validator region
#   region_validator_count_skew  WARN  ratio > 5
anomalies = []
critical_fired = False

# single_region_dominance: any region's stake_share_bps > dominance_thr_bps.
# Strict > matches the operator_stake_concentration convention (0.60 is
# "not flagged at exactly 60.00%"). Once fired, promotes exit code to 2
# regardless of --anomalies-only.
dominant_regions = []
for r in region_rows:
    if total_stake > 0 and r["stake_share_bps"] > dominance_thr_bps:
        dominant_regions.append({
            "region":          r["region"],
            "stake_share_bps": r["stake_share_bps"],
            "total_stake":     r["total_stake"],
        })
if dominant_regions:
    anomalies.append("single_region_dominance")
    critical_fired = True

# region_stake_imbalance: any region's total_stake > (1 + imbal_pct) ×
# mean_region_stake. Float compare is fine — the threshold knob is a
# float and we're never inside a tight loop. We use strict > so the
# boundary case "exactly at threshold" is not flagged.
imbalanced_regions = []
if total_regions >= 2 and total_stake > 0:
    threshold_value = mean_region_stake * (1.0 + imbal_pct)
    for r in region_rows:
        if r["total_stake"] > threshold_value:
            imbalanced_regions.append({
                "region":          r["region"],
                "total_stake":     r["total_stake"],
                "threshold_value": threshold_value,
                "mean_region_stake": mean_region_stake,
            })
if imbalanced_regions:
    anomalies.append("region_stake_imbalance")

# empty_region: any region row with validator_count == 0. Note: a
# region only appears in by_region if at least one validator referenced
# it; we can't detect "configured but never populated" regions from
# RPC alone. The path that produces empty_region rows here is a future
# DEREGISTER cascade where the region tag persists in chain state
# elsewhere — defensive coverage.
empty_regions = [r["region"] for r in region_rows if r["validator_count"] == 0]
if empty_regions:
    anomalies.append("empty_region")

# region_validator_count_skew: ratio > 5. Float compare strict >.
skew_fired = False
if vc_max_min_ratio > 5.0:
    anomalies.append("region_validator_count_skew")
    skew_fired = True

# ── Compose result envelope ───────────────────────────────────────
result = {
    "rpc_port":         int(port),
    "by_region":        region_rows,
    "summary": {
        "total_regions":                  total_regions,
        "total_validators":               total_validators,
        "total_stake":                    total_stake,
        "total_balance":                  total_balance,
        "mean_region_stake":              mean_region_stake,
        "stake_stddev":                   stake_stddev,
        "validator_count_max_min_ratio":  vc_max_min_ratio,
        "stake_max_min_ratio":            stake_max_min_ratio,
    },
    "thresholds": {
        "imbalance_threshold_pct":                imbal_pct,
        "single_region_dominance_threshold_pct":  dominance_pct,
        "single_region_dominance_threshold_bps":  dominance_thr_bps,
    },
    "anomaly_detail": {
        "dominant_regions":   dominant_regions,
        "imbalanced_regions": imbalanced_regions,
        "empty_regions":      empty_regions,
        "skew_fired":         skew_fired,
        "skew_ratio":         vc_max_min_ratio,
    },
    "anomalies":        anomalies,
    "critical_fired":   critical_fired,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_region_balance_audit: aggregation failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human) ─────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
head_h    = int(sys.argv[5])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

by_region        = r["by_region"]
summary          = r["summary"]
thresholds       = r["thresholds"]
detail           = r["anomaly_detail"]
anomalies        = r["anomalies"]
critical_fired   = r["critical_fired"]
anom_count       = len(anomalies)

def render_bps_pct(bps):
    """bps in 0..10000 → 'XX.X%' (one decimal of precision)."""
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def region_label(s):
    """Empty-string region → '(global)' in human output."""
    return s if s else "(global)"

if json_out:
    envelope = {
        "rpc_port":     port,
        "head_height":  head_h,
        "by_region":    by_region,
        "summary":      summary,
        "thresholds":   thresholds,
        "anomalies":    anomalies,
        "anomaly_detail": detail,
        "critical_fired": critical_fired,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_region_balance_audit: no anomalies (port {port})")
    sys.exit(0)

print(f"=== Region balance + stake audit (port {port}) ===")
print(f"Chain height:       {head_h}")
print(f"Total regions:      {summary['total_regions']}")
print(f"Total validators:   {summary['total_validators']}")
print(f"Total stake:        {summary['total_stake']}")
print(f"Total balance:      {summary['total_balance']}")

if not anom_only:
    if by_region:
        print()
        print("Per-region breakdown:")
        # Compact column-aligned table. Region name capped at 14 chars
        # so the empty-string "(global)" fits without wrap; validators
        # count + stake/balance numbers right-aligned for readability.
        print(f"  {'region':<14} {'validators':>10} "
              f"{'total_stake':>14} {'mean_stake':>12} "
              f"{'total_balance':>14} {'mean_balance':>12} "
              f"{'share':>7}")
        for row in by_region:
            label = region_label(row["region"])
            if len(label) > 14:
                label = label[:11] + "..."
            print(f"  {label:<14} {row['validator_count']:>10} "
                  f"{row['total_stake']:>14} {row['mean_stake']:>12} "
                  f"{row['total_balance']:>14} {row['mean_balance']:>12} "
                  f"{render_bps_pct(row['stake_share_bps']):>7}")
        print()
        print("Cross-region summary:")
        print(f"  stake_stddev:                 {summary['stake_stddev']:.2f}")
        print(f"  stake_max_min_ratio:          {summary['stake_max_min_ratio']:.2f}")
        print(f"  validator_count_max_min_ratio: {summary['validator_count_max_min_ratio']:.2f}")
    else:
        print("Per-region breakdown: (none; no validators returned by RPC)")

print()
if anom_count == 0:
    print("[OK] Per-region distribution within configured thresholds")
else:
    severity_word = "CRITICAL" if critical_fired else "ANOMALY"
    print(f"[{severity_word}] {anom_count} flag(s): {','.join(anomalies)}")
    if "single_region_dominance" in anomalies:
        thr_bps = thresholds["single_region_dominance_threshold_bps"]
        for d in detail["dominant_regions"]:
            print(f"  single_region_dominance      : region={region_label(d['region'])} "
                  f"holds {render_bps_pct(d['stake_share_bps'])} of total stake "
                  f"(> {render_bps_pct(thr_bps)} threshold) "
                  f"— R4 Sybil-resistance margin broken")
    if "region_stake_imbalance" in anomalies:
        for d in detail["imbalanced_regions"]:
            print(f"  region_stake_imbalance       : region={region_label(d['region'])} "
                  f"total_stake={d['total_stake']} > {d['threshold_value']:.0f} "
                  f"({(1.0+thresholds['imbalance_threshold_pct']):.2f}× mean "
                  f"{d['mean_region_stake']:.0f})")
    if "empty_region" in anomalies:
        for region in detail["empty_regions"]:
            print(f"  empty_region                 : region={region_label(region)} "
                  f"has 0 active validators (stale region pool)")
    if "region_validator_count_skew" in anomalies:
        print(f"  region_validator_count_skew  : max:min count ratio = "
              f"{detail['skew_ratio']:.2f} (> 5.0 threshold) — "
              f"coordination-cost asymmetry across regions")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_region_balance_audit: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ────────────────────────────────────────────────
# - Default informational mode: exit 0 unless a CRITICAL fires (single_
#   region_dominance), in which case exit 2 regardless of --anomalies-only.
# - --anomalies-only: exit 2 iff any anomaly fired.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_region_balance_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
crit = 1 if r.get("critical_fired") else 0
acount = len(r.get("anomalies", []))
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(f"{acount} {crit}\n")
PY
read ANOM_COUNT CRIT_FLAG < "$TMP_ANOM"
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac
case "$CRIT_FLAG"  in *[!0-9]*|"") CRIT_FLAG=0  ;; esac

if [ "$CRIT_FLAG" = "1" ]; then
  exit 2
fi
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
