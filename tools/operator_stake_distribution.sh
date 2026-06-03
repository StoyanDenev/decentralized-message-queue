#!/usr/bin/env bash
# operator_stake_distribution.sh — One-glance decentralization health
# check for a running determ chain. Reports the three standard
# stake-concentration metrics an operator or auditor reaches for first:
#
#   1. Nakamoto coefficient — the smallest number of top validators
#      whose CUMULATIVE stake exceeds 1/3 of the total. This is the
#      stake-weighted reading of the Byzantine-fault threshold: determ's
#      K-of-K consensus is safe under f < K/3 dishonest committee
#      members (see proofs/BFTSafety.md, SECURITY.md §S-010/§S-011), so
#      "how many validators must collude to control > 1/3 of the
#      selection weight" is the decentralization question that maps
#      directly onto the safety margin. A Nakamoto coefficient of 1
#      means a single validator already exceeds 1/3 and can unilaterally
#      threaten liveness/safety guarantees that assume an honest
#      super-minority.
#
#   2. Gini coefficient — textbook stake-distribution inequality on
#      [0,1] (0 = every validator holds an equal stake, 1 = one
#      validator holds everything). Computed via the O(n log n)
#      sorted-form identity (same implementation as
#      operator_stake_concentration.sh / operator_balance_distribution.sh).
#
#   3. Per-validator stake table — every validator ranked by stake
#      descending (ties by domain ascending, matching the `stakes` RPC
#      order), with each one's percentage share of total stake.
#
# Positioning vs. the sibling stake tools (no overlap by design):
#
#   operator_stake_distribution.sh        (THIS)
#       Decentralization HEALTH CHECK. Headline = Nakamoto coefficient
#       (the collusion-threshold metric), plus Gini + a full ranked
#       table. Answers "how many validators would need to collude to
#       break the 1/3 Byzantine threshold, and how skewed is the
#       distribution?" No anomaly gating — this is an informational
#       one-glance report; exit code reflects only RPC health.
#
#   operator_stake_concentration.sh
#       ANOMALY-GATED audit. Gini + top-1/3/10 concentration + decile
#       breakdown + min_stake floor-effect Sybil detection, with
#       --anomalies-only / exit-2 alerting for cron. Does NOT compute
#       the Nakamoto coefficient.
#
#   operator_stake_audit.sh
#       Per-validator LOCK-STATE audit (locked / unlocking-pending /
#       unlocked-pending) cross-referencing stake_info; orthogonal to
#       distribution shape.
#
# Why the Nakamoto coefficient uses > 1/3 (not > 1/2):
#   The familiar Nakamoto coefficient in PoW/PoS chains often uses a
#   > 50% (or > 33% for "halting") cutoff depending on the threat model.
#   determ's consensus is BFT-style: a block finalizes under a quorum of
#   the K-member committee and the safety/liveness proofs hold while
#   dishonest weight stays below 1/3 (f < K/3). The > 1/3 cumulative
#   cutoff is therefore the threshold that matters for determ's
#   security argument, and is the value we report as THE Nakamoto
#   coefficient. (A > 1/2 "majority-control" coefficient is also
#   emitted in --json as nakamoto_half for operators who want both.)
#
# RPC dependencies (read-only; safe against any running daemon):
#   - status     current height + K-of-K committee size (k_block_sigs),
#                fetched in one call (`determ status --json`).
#   - stakes     full validator set: flat JSON array of
#                {rank, domain, stake, active_from, region, ed_pub},
#                already sorted by stake DESC, ties by domain ASC. This
#                is node.cpp::rpc_validators() materialized through the
#                `stakes` CLI (which adds the rank field). We pull the
#                FULL list (no --top cap) because the Gini denominator
#                and the Nakamoto accumulation both need every entry.
#
# Usage:
#   tools/operator_stake_distribution.sh --rpc-port N [--json]
#
# Options:
#   --rpc-port N   RPC port to query (required)
#   --json         Emit a structured JSON envelope instead of the
#                  human-readable report
#   -h, --help     Show this help
#
# Exit codes:
#   0   report produced successfully (this is an informational tool;
#       a healthy RPC pipeline always exits 0, regardless of how
#       concentrated the distribution turns out to be)
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_stake_distribution.sh --rpc-port N [--json]

One-glance decentralization health check for a running determ chain.
Reports the Nakamoto coefficient (min validators controlling > 1/3 of
total stake — determ's K-of-K Byzantine safety threshold), the Gini
coefficient of the stake distribution, and a per-validator stake table
ranked descending with each validator's share of total stake.

RPCs used (read-only):
  status   current height + K-of-K committee size (k_block_sigs)
  stakes   full validator -> stake map (sorted by stake DESC)

Options:
  --rpc-port N   RPC port to query (required)
  --json         Emit a structured JSON envelope instead of the report
  -h, --help     Show this help

Metrics:
  Nakamoto coefficient  smallest number of top validators whose
                        cumulative stake exceeds 1/3 of total. Maps onto
                        determ's f < K/3 Byzantine safety margin: this
                        many validators colluding controls > 1/3 of the
                        stake-weighted selection power.
  Gini coefficient      stake-distribution inequality on [0,1]
                        (0 = perfectly equal, 1 = maximally concentrated).
  Per-validator table   every validator ranked by stake descending with
                        its percentage share of total stake.

Exit codes:
  0   report produced successfully (informational; always 0 on a
      healthy RPC pipeline regardless of concentration)
  1   RPC error / daemon unreachable / malformed response / bad args
EOF
}

PORT=""
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    --rpc-port)   PORT="${2:-}"; shift 2 ;;
    --json)       JSON_OUT=1;    shift ;;
    *) echo "operator_stake_distribution: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required and must be a positive integer.
case "$PORT" in *[!0-9]*|"")
  echo "operator_stake_distribution: --rpc-port is required and must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: status RPC → height + K-of-K committee size in one call ──────────
# `determ status` proxies the `status` RPC, whose payload carries both
# `height` and `k_block_sigs` (the genesis-pinned committee size K). We
# fetch the whole object once and extract both fields via Python so the
# parse is robust without requiring jq.
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_distribution: cannot reach daemon on rpc-port $PORT (status RPC failed)" >&2
  exit 1
}
HEAD_H=$(printf '%s' "$STATUS_OUT" | python -c "
import sys, json
try:
    j = json.load(sys.stdin); print(int(j.get('height', 0)))
except Exception:
    print('')")
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_stake_distribution: status returned non-numeric height '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac
KOFK=$(printf '%s' "$STATUS_OUT" | python -c "
import sys, json
try:
    j = json.load(sys.stdin); print(int(j.get('k_block_sigs', 0)))
except Exception:
    print('')")
case "$KOFK" in *[!0-9]*|"") KOFK=0 ;; esac

# ── Step 2: full stakes list (NO --top cap; we need every entry) ─────────────
STAKES_OUT=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_distribution: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

# Stash the RPC payload in a temp file rather than piping it to Python's
# stdin: the metric pass below sources its program from a heredoc
# (`python - <<'PY'`), which already consumes stdin, so the JSON must
# travel by a different channel. A file path passed as argv also sidesteps
# command-line-length limits on large validator sets. Same temp-file
# convention as operator_stake_concentration.sh.
TMP_STAKES=$(mktemp 2>/dev/null) || {
  echo "operator_stake_distribution: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STAKES" 2>/dev/null' EXIT
printf '%s' "$STAKES_OUT" >"$TMP_STAKES"

# ── Step 3: compute metrics + render (single Python pass) ────────────────────
# Float math (Gini ratio, cumulative-share thresholds) lives in Python
# because POSIX shell can't do floating point — the same convention every
# sibling operator_*.sh metric tool follows. Integer basis points are
# used for share thresholds so the > 1/3 and > 1/2 Nakamoto comparisons
# are exact (no float-equality drift on a tie at exactly 1/3).
python - "$JSON_OUT" "$PORT" "$HEAD_H" "$KOFK" "$TMP_STAKES" <<'PY'
import sys, json

json_out   = sys.argv[1] == "1"
port       = int(sys.argv[2])
head_h     = int(sys.argv[3])
kofk       = int(sys.argv[4])
stakes_path = sys.argv[5]

try:
    with open(stakes_path, "r", encoding="utf-8") as f:
        stakes = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_stake_distribution: cannot parse stakes JSON: {e}\n")
    sys.exit(1)
if not isinstance(stakes, list):
    sys.stderr.write("operator_stake_distribution: stakes RPC is not a JSON array\n")
    sys.exit(1)

# Materialize per-validator records. The RPC already returns them sorted
# by stake DESC (ties by domain ASC); we re-sort defensively so the
# script is robust against any future RPC reorder.
validators = []
for v in stakes:
    if not isinstance(v, dict):
        continue
    d = v.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    try:
        s = int(v.get("stake", 0) or 0)
    except Exception:
        s = 0
    if s < 0:
        s = 0
    validators.append({"domain": d, "stake": s})

validators.sort(key=lambda r: (-r["stake"], r["domain"]))
n_validators = len(validators)
total_stake  = sum(v["stake"] for v in validators)

# Per-validator share in basis points (stake * 10000 // total). Integer
# floor-division: the residual means cumulative shares may not sum to
# exactly 10000 (same convention as operator_stake_concentration).
for v in validators:
    v["share_bps"] = (v["stake"] * 10000 // total_stake) if total_stake > 0 else 0

# ── Nakamoto coefficient ─────────────────────────────────────────────────────
# Smallest k such that the cumulative stake of the top-k validators
# STRICTLY EXCEEDS total/3. Accumulate over the DESC-sorted list. To keep
# the > 1/3 comparison exact we compare 3*cumulative against total
# (cum/total > 1/3  <=>  3*cum > total) — pure integer arithmetic, no
# float threshold to drift on a tie at exactly one third.
#
# We also compute the > 1/2 "majority control" coefficient (nakamoto_half)
# the same way (2*cum > total) and surface it in JSON for operators who
# want the classic majority-takeover number alongside the BFT-threshold
# one.
#
# Edge cases:
#   total_stake == 0  → no stake to control; both coefficients are 0 and
#                       the headline note flags the empty/zero-stake pool.
#   n_validators == 0 → empty pool; coefficients 0.
def nakamoto(mult):
    """Min #top validators whose cumulative stake * mult > total_stake."""
    if total_stake <= 0:
        return 0
    cum = 0
    for i, v in enumerate(validators, start=1):
        cum += v["stake"]
        if cum * mult > total_stake:
            return i
    # Cumulative over ALL validators can't exceed total, so for mult>=1
    # with mult*total > total this is unreachable when total>0; guard
    # anyway and report the full set.
    return n_validators

nakamoto_third = nakamoto(3)   # > 1/3  (determ BFT safety threshold)
nakamoto_half  = nakamoto(2)   # > 1/2  (classic majority-control)

# ── Gini coefficient (sorted-form, O(n log n)) ───────────────────────────────
# G = Σᵢ (2i − n − 1) sᵢ / (n Σ sᵢ), 1-indexed i over a NON-DECREASING
# sort. Algebraically identical to the textbook
# G = Σᵢⱼ |sᵢ − sⱼ| / (2n Σ sᵢ) but O(n log n) instead of O(n²). Same
# implementation as operator_stake_concentration.sh /
# operator_balance_distribution.sh.
#   n < 2 or total_stake == 0 → Gini undefined (None). A single validator
#   is trivially "perfectly concentrated" but the textbook ratio is 0 by
#   the (2*1 − 1 − 1) = 0 coefficient; we report None for n<2 and let the
#   Nakamoto coefficient (=1) carry the concentration signal instead.
gini = None
if n_validators >= 2 and total_stake > 0:
    asc = sorted(v["stake"] for v in validators)
    n = n_validators
    wsum = 0
    for i, s in enumerate(asc, start=1):
        wsum += (2 * i - n - 1) * s
    g = wsum / (n * total_stake)
    gini = 0.0 if g < 0.0 else g

# ── Concentration note (plain-English headline) ──────────────────────────────
# Derived purely from the metrics above so the human report leads with an
# at-a-glance verdict. Thresholds chosen to mirror common chain-health
# language; this is advisory, not a gate.
top1_bps = validators[0]["share_bps"] if n_validators >= 1 and total_stake > 0 else 0
# Cumulative top-2 share in bps for the "top-2 hold > 50%" phrasing.
top2_cum = sum(v["stake"] for v in validators[:2])
top2_bps = (top2_cum * 10000 // total_stake) if total_stake > 0 else 0

def concentration_note():
    if total_stake <= 0:
        return "no stake in the validator set - distribution undefined (chain bootstrap or catastrophic stake loss)"
    if n_validators == 1:
        return "single validator holds 100% of stake - fully centralized"
    if nakamoto_third == 1:
        return "a single validator controls > 1/3 of stake - one actor can breach the Byzantine safety threshold alone"
    if top1_bps > 5000:
        return "top validator holds > 50% of stake - severe centralization (single-actor majority)"
    if top2_bps > 5000:
        return "top-2 validators hold > 50% of stake - moderate centralization"
    if gini is not None and gini >= 0.6:
        return "stake is highly unequal (Gini >= 0.60) - selection weight concentrated in a small cohort"
    if nakamoto_third <= 2:
        return f"only {nakamoto_third} validators control > 1/3 of stake - low Byzantine-collusion resistance"
    return f"{nakamoto_third} validators needed to exceed the 1/3 threshold - distribution reasonably decentralized"

note = concentration_note()

# ── JSON envelope ────────────────────────────────────────────────────────────
if json_out:
    envelope = {
        "rpc_port":              port,
        "height":                head_h,
        "k_of_k_committee_size": kofk,
        "validators":            n_validators,
        "total_stake":           total_stake,
        "nakamoto_coefficient":  nakamoto_third,   # > 1/3 (determ BFT threshold)
        "nakamoto_half":         nakamoto_half,    # > 1/2 (majority control)
        "gini":                  gini,             # None when n<2 or total==0
        "top1_share_bps":        top1_bps,
        "top2_share_bps":        top2_bps,
        "concentration_note":    note,
        "stake_table": [
            {
                "rank":      i,
                "domain":    v["domain"],
                "stake":     v["stake"],
                "share_bps": v["share_bps"],
            }
            for i, v in enumerate(validators, start=1)
        ],
    }
    print(json.dumps(envelope))
    sys.exit(0)

# ── Human-readable report ────────────────────────────────────────────────────
def pct(bps):
    """bps in 0..10000 → 'XX.X%' (one decimal)."""
    return f"{bps // 100}.{(bps % 100) // 10}%"

print(f"Stake distribution (rpc_port={port}, height={head_h}, validators={n_validators}):")
print()
if n_validators == 0:
    print("  (no validators registered)")
else:
    print(f"  {'Rank':>4}  {'Domain':<24} {'Stake':>14}  {'Share':>7}")
    for i, v in enumerate(validators, start=1):
        dom = v["domain"] if len(v["domain"]) <= 24 else v["domain"][:21] + "..."
        print(f"  {str(i)+'.':>4}  {dom:<24} {v['stake']:>14}  {pct(v['share_bps']):>7}")
print()
print(f"  Total staked:         {total_stake}")
if total_stake > 0:
    print(f"  Nakamoto coefficient: {nakamoto_third}  (min validators to exceed 1/3 = 33.3% stake)")
else:
    print(f"  Nakamoto coefficient: 0  (no stake to control)")
if gini is None:
    print(f"  Gini coefficient:     n/a  (fewer than 2 validators or zero total stake)")
else:
    print(f"  Gini coefficient:     {gini:.2f}  (0=perfectly equal, 1=maximally concentrated)")
if kofk > 0:
    print(f"  K-of-K committee size: {kofk}")
print(f"  Concentration note:   {note}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_stake_distribution: metric computation / rendering failed" >&2
  exit 1
fi
exit 0
