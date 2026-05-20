#!/usr/bin/env bash
# operator_balance_distribution.sh — Measure the wealth-distribution
# (in)equality of a running determ chain via the Gini coefficient on
# the live account-balance set, plus a top-N holders table and a
# bottom-percentile snapshot.
#
# Pipeline (read-only RPC):
#   1.  `determ snapshot create --out <tmp>` — full state dump JSON.
#       The dump is the per-account ledger; `accounts[].balance` is
#       the live held quantity. Snapshot is the source of truth: the
#       lighter `snapshot inspect` surface returns counts only.
#   2.  (optional) `determ snapshot inspect --in <tmp> --json` —
#       restore round-trip (S-033/S-038 state_root verification) as a
#       defensive sanity check before we trust the file. Avoids
#       acting on a torn/corrupted snapshot. Bypass via --skip-verify
#       when triaging a suspected-broken state.
#   3.  Python computes:
#       - Gini coefficient on non-zero balances. Mathematical form
#         G = Σᵢⱼ |xᵢ − xⱼ| / (2n Σ xᵢ) is the textbook definition;
#         we use the algebraically identical sorted-form
#         G = Σᵢ (2i − n − 1) xᵢ / (n Σ xᵢ)
#         (1-indexed i over a non-decreasing sort) — same value,
#         O(n log n) vs the naive O(n²). At any realistic account
#         population this matters; at small n it's strictly equivalent.
#       - Top-10 holders by balance (descending; ties broken by
#         domain ascending for determinism).
#       - Bottom-percentile snapshot: the median + p10 + p25 of the
#         non-zero distribution, plus a count of accounts at or below
#         each percentile (`bottom_X_count` = floor(p × n)).
#
# Why "non-zero accounts" only:
#   The Zero-class accounts catalogued by operator_dust_audit (balance
#   == 0 AND nonce == 0 AND no stake/registry/dapp) are the auto-
#   creation residue of the six I-4 channels (TRANSFER credit, inbound
#   receipt, REGISTER, etc.) — they have never economically participated.
#   Including them would inflate the Gini towards 1 trivially: an
#   "infinitely poor" account has zero balance, and Gini explodes when
#   the population is dominated by zero entries. The wealth-
#   distribution metric is "among real holders, how concentrated is the
#   stake," which means filtering to balance > 0.
#
# Anomaly flags (each adds to anomalies[]; --anomalies-only exits 2):
#   - extreme_concentration   Gini > 0.90 (post-distribution chain
#                             with all economic power in a tiny set;
#                             healthy chains typically sit 0.30–0.70).
#   - whale_dominance         Top-1 holder > 50% of total non-zero
#                             supply (single-actor majority hold).
#   - cartel_dominance        Top-10 holders collectively > 90% of
#                             total non-zero supply (small-cartel
#                             pre-democratization signal).
#
# RPC dependencies (read-only):
#   - snapshot create        full state dump → tmp file
#   - snapshot inspect       round-trip integrity check (optional)
#   - head                   current chain height (banner only)
#
# Usage:
#   tools/operator_balance_distribution.sh [--rpc-port N] [--json]
#                                          [--top N] [--anomalies-only]
#                                          [--skip-verify]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope
#   --top N             Top-N holders to surface (default: 10)
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   --skip-verify       Skip the inspect round-trip integrity check
#   -h, --help          Show this help
#
# Exit codes (mirrors operator_dust_audit / operator_account_growth):
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / malformed snapshot / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_balance_distribution.sh [--rpc-port N] [--json]
                                        [--top N] [--anomalies-only]
                                        [--skip-verify]

Measure wealth-distribution (in)equality on a running determ daemon
via the Gini coefficient on live account balances, plus top-N holders
and a bottom-percentile snapshot of the non-zero distribution.

Snapshot pipeline:
  1. `snapshot create --out <tmp>` writes the full state dump.
  2. (optional) `snapshot inspect --in <tmp> --json` verifies the
     S-033/S-038 state_root round-trip before we parse it.
  3. Python computes Gini on non-zero balances (O(n log n) sorted-form),
     top-N holders, and p10/p25/median.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope
  --top N             Top-N holders to surface (default: 10)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  --skip-verify       Skip the inspect round-trip integrity check
  -h, --help          Show this help

Anomaly flags:
  extreme_concentration    Gini > 0.90
  whale_dominance          top-1 holder > 50% of non-zero supply
  cartel_dominance         top-10 holders > 90% of non-zero supply

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed snapshot
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
SKIP_VERIFY=0
TOP_N=10
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";       shift 2 ;;
    --json)            JSON_OUT=1;          shift ;;
    --top)             TOP_N="${2:-}";      shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;         shift ;;
    --skip-verify)     SKIP_VERIFY=1;       shift ;;
    *) echo "operator_balance_distribution: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_balance_distribution: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$TOP_N" in *[!0-9]*|"")
  echo "operator_balance_distribution: --top must be a positive integer (got '$TOP_N')" >&2
  exit 1 ;;
esac
if [ "$TOP_N" -lt 1 ]; then
  echo "operator_balance_distribution: --top must be >= 1 (got '$TOP_N')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current tip (banner only) ───────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_balance_distribution: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_balance_distribution: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: snapshot create → tmp file ──────────────────────────────────────
TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
  echo "operator_balance_distribution: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_balance_distribution: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_balance_distribution: snapshot create failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: integrity round-trip via `snapshot inspect` ─────────────────────
# Same S-033 + S-038 gate as operator_dust_audit / operator_account_growth.
# A successful inspect with --json means the snapshot's stored state_root
# matches the recomputed one after Chain::restore_from_snapshot ran.
SNAP_BLOCK_INDEX="$HEAD_H"
SNAP_STATE_ROOT=""
if [ "$SKIP_VERIFY" = "0" ]; then
  INSPECT_OUT=$("$DETERM" snapshot inspect --in "$TMP_SNAP" --json 2>&1) || {
    echo "operator_balance_distribution: snapshot inspect failed (state_root mismatch or malformed snapshot)" >&2
    echo "$INSPECT_OUT" >&2
    exit 1
  }
  if [ "$HAVE_JQ" = "1" ]; then
    SNAP_BLOCK_INDEX=$(printf '%s' "$INSPECT_OUT" | jq -r '.block_index // 0')
    SNAP_STATE_ROOT=$(printf '%s' "$INSPECT_OUT" | jq -r '.state_root // ""')
  else
    SNAP_BLOCK_INDEX=$(printf '%s' "$INSPECT_OUT" | grep -o '"block_index":[0-9]*' | head -1 | sed 's/.*://')
    SNAP_STATE_ROOT=$(printf '%s' "$INSPECT_OUT" | grep -o '"state_root":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
  fi
  case "$SNAP_BLOCK_INDEX" in *[!0-9]*|"") SNAP_BLOCK_INDEX=0 ;; esac
fi

# ── Step 4: compute distribution metrics via Python ─────────────────────────
# Gini implementation note: we compute the sorted-form identity
#   G = Σᵢ (2i − n − 1) xᵢ / (n Σ xᵢ)
# (1-indexed i over a non-decreasing sort), which is algebraically
# identical to the textbook
#   G = Σᵢⱼ |xᵢ − xⱼ| / (2n Σ xᵢ)
# but runs O(n log n) instead of O(n²) — necessary at any realistic
# n. The numerator and denominator are accumulated in pure ints so the
# only float division is the final one. We also emit the integer
# value scaled to four decimal places (gini_ten_thousandths) so JSON
# consumers can compare without float-equality hazards.
python - "$TMP_SNAP" "$TMP_OUT" "$TOP_N" <<'PY'
import json, sys
from collections import defaultdict

snap_path, out_path, top_n_s = sys.argv[1:4]
top_n = int(top_n_s)

try:
    with open(snap_path, "r", encoding="utf-8") as f:
        snap = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_balance_distribution: cannot parse snapshot: {e}\n")
    sys.exit(1)
if not isinstance(snap, dict):
    sys.stderr.write("operator_balance_distribution: snapshot is not a JSON object\n")
    sys.exit(1)

# Per-domain balance (last-write-wins on duplicate entries; matches
# Chain::restore_from_snapshot which overwrites). We don't need to
# merge stake / registry / dapp here — this audit is purely about the
# liquid balance held in `accounts[].balance`. Stake collateral is a
# separate concern (operator_stake_audit covers it).
balances = {}
for a in snap.get("accounts", []) or []:
    if not isinstance(a, dict):
        continue
    d = a.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    balances[d] = int(a.get("balance", 0) or 0)

total_accounts = len(balances)
# Non-zero filter: focus on real holders. Rationale in the header.
nonzero = [(d, b) for d, b in balances.items() if b > 0]
nonzero_accounts = len(nonzero)

# Aggregate total supply across non-zero accounts (the denominator of
# every share calculation below). Zero-balance accounts contribute 0
# trivially so they don't change the sum, but excluding them from the
# count keeps the share percentages meaningful.
total_supply = sum(b for _, b in nonzero)

# Gini computation (sorted-form). Operates on the non-zero set.
# Returns:
#   - gini             float in [0.0, 1.0)
#   - gini_ten_thousandths   integer = round(gini * 10000)
# Edge cases:
#   - n == 0:  no holders → Gini undefined; emit null + 0 bps.
#   - n == 1:  single holder, perfect concentration → Gini == 0 by
#              the sorted-form formula (numerator collapses since
#              the only term has coefficient (2*1 − 1 − 1) = 0). This
#              is the mathematically correct limit — with one
#              observation there is no inequality "across" the set.
#              The top-1 share will still be 100% and trigger
#              whale_dominance, so the concentration signal is
#              preserved via that anomaly.
#   - total_supply == 0: impossible given the b > 0 filter, but we
#              still guard the division.
gini = None
gini_bps = 0  # ten-thousandths
if nonzero_accounts >= 2 and total_supply > 0:
    sorted_balances = sorted(b for _, b in nonzero)
    n = nonzero_accounts
    # 1-indexed i: i in [1, n]. Σ (2i − n − 1) * x_i.
    weighted_sum = 0
    for i, x in enumerate(sorted_balances, start=1):
        weighted_sum += (2 * i - n - 1) * x
    # Pure integer numerator over integer denominator; cast to float
    # at the very end.
    denom = n * total_supply
    gini = weighted_sum / denom
    # Clamp to [0, 1) for the rounded form. weighted_sum can be < 0
    # only under non-monotone sort (impossible) or float drift
    # (impossible at this point — all integers); guard anyway.
    if gini < 0.0:
        gini = 0.0
    gini_bps = int(round(gini * 10000))

# Top-N by balance (descending by balance, ascending by domain on tie
# for determinism across runs).
sorted_desc = sorted(nonzero, key=lambda kv: (-kv[1], kv[0]))
top_holders = [
    {
        "domain":  d,
        "balance": b,
        "share_bps": (b * 10000 // total_supply) if total_supply > 0 else 0,
    }
    for d, b in sorted_desc[:top_n]
]

# Top-1 and top-10 collective share (integer basis points so the
# anomaly thresholds compare exactly).
top1_bps = top_holders[0]["share_bps"] if top_holders else 0
top10_sum = sum(b for _, b in sorted_desc[:10])
top10_bps = (top10_sum * 10000 // total_supply) if total_supply > 0 else 0

# Bottom-percentile snapshot. Percentiles use the "nearest-rank"
# definition (1-indexed): p-th percentile of a sorted list of length n
# is the element at position ceil(p/100 * n). Standard, no
# interpolation — keeps everything integer-arithmetic exact.
def nearest_rank(sorted_list, pct):
    n = len(sorted_list)
    if n == 0:
        return None
    # ceil(pct/100 * n) using integer math: (pct*n + 99) // 100, with
    # a floor of 1.
    rank = max(1, (pct * n + 99) // 100)
    if rank > n:
        rank = n
    return sorted_list[rank - 1]

sorted_balances_asc = sorted(b for _, b in nonzero)
p10    = nearest_rank(sorted_balances_asc, 10)
p25    = nearest_rank(sorted_balances_asc, 25)
median = nearest_rank(sorted_balances_asc, 50)

# bottom_X_count: number of accounts at or below the p_X cut. floor()
# of the percentile rank gives the canonical bottom-X count.
def bottom_count(sorted_list, pct):
    n = len(sorted_list)
    if n == 0:
        return 0
    return (pct * n) // 100

bottom_10_count = bottom_count(sorted_balances_asc, 10)
bottom_25_count = bottom_count(sorted_balances_asc, 25)
bottom_50_count = bottom_count(sorted_balances_asc, 50)

# Anomaly classification.
anomalies = []
# extreme_concentration: Gini > 0.90.
if gini is not None and gini_bps > 9000:
    anomalies.append("extreme_concentration")
# whale_dominance: top-1 share > 50% (5000 bps).
if top1_bps > 5000:
    anomalies.append("whale_dominance")
# cartel_dominance: top-10 collective share > 90% (9000 bps). Only
# meaningful when there are actually >= 10 holders; otherwise the
# top-1/whale flag already covers it and emitting cartel_dominance
# would be a tautology (top-N == 100% by definition).
if nonzero_accounts >= 10 and top10_bps > 9000:
    anomalies.append("cartel_dominance")

result = {
    "total_accounts":     total_accounts,
    "nonzero_accounts":   nonzero_accounts,
    "total_supply":       total_supply,
    "gini":               gini,
    "gini_ten_thousandths": gini_bps,
    "top_holders":        top_holders,
    "top_n":              top_n,
    "top1_share_bps":     top1_bps,
    "top10_share_bps":    top10_bps,
    "percentiles": {
        "p10":    p10,
        "p25":    p25,
        "median": median,
    },
    "bottom_counts": {
        "bottom_10_count": bottom_10_count,
        "bottom_25_count": bottom_25_count,
        "bottom_50_count": bottom_50_count,
    },
    "anomalies":          anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_balance_distribution: distribution computation failed" >&2
  exit 1
fi

# ── Step 5: render envelope (JSON or human) ─────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" \
        "$SNAP_BLOCK_INDEX" "$SNAP_STATE_ROOT" "$SKIP_VERIFY" "$TOP_N" <<'PY'
import json, sys

json_out         = sys.argv[1] == "1"
anom_only        = sys.argv[2] == "1"
out_path         = sys.argv[3]
port             = int(sys.argv[4])
head_h           = int(sys.argv[5])
snap_block_index = int(sys.argv[6])
snap_state_root  = sys.argv[7]
skip_verify      = sys.argv[8] == "1"
top_n            = int(sys.argv[9])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total_accts    = r["total_accounts"]
nonzero_accts  = r["nonzero_accounts"]
total_supply   = r["total_supply"]
gini           = r["gini"]
gini_bps       = r["gini_ten_thousandths"]
top_holders    = r["top_holders"]
top1_bps       = r["top1_share_bps"]
top10_bps      = r["top10_share_bps"]
pcts           = r["percentiles"]
btm            = r["bottom_counts"]
anomalies      = r["anomalies"]
anom_count     = len(anomalies)

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
        "rpc_port":             port,
        "head_height":          head_h,
        "snapshot_block_index": snap_block_index,
        "snapshot_state_root":  snap_state_root if snap_state_root else None,
        "verify_skipped":       skip_verify,
        "total_accounts":       total_accts,
        "nonzero_accounts":     nonzero_accts,
        "total_supply":         total_supply,
        "gini":                 gini,
        "gini_ten_thousandths": gini_bps,
        "top_holders":          top_holders,
        "top_n":                top_n,
        "top1_share_bps":       top1_bps,
        "top10_share_bps":      top10_bps,
        "percentiles":          pcts,
        "bottom_counts":        btm,
        "anomalies":            anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_balance_distribution: no anomalies (port {port})")
    sys.exit(0)

print(f"=== Balance distribution (port {port}) ===")
verify_note = " [verify skipped]" if skip_verify else ""
print(f"Snapshot block: {snap_block_index}{verify_note}")
print(f"Total accounts: {total_accts}")
print(f"Non-zero accounts: {nonzero_accts}")
print(f"Total non-zero supply: {total_supply}")
if gini is None:
    print("Gini coefficient: n/a (fewer than 2 holders)")
else:
    print(f"Gini coefficient: {render_gini(gini_bps)}")

if not anom_only:
    if top_holders:
        shown = min(top_n, len(top_holders))
        print(f"Top-{shown} by balance:")
        for i, h in enumerate(top_holders, start=1):
            print(f"  {i:>2}. {short(h['domain']):<35} "
                  f"balance={h['balance']:<18} share={render_bps_pct(h['share_bps'])}")
        print(f"Top-1 share:  {render_bps_pct(top1_bps)}")
        print(f"Top-10 share: {render_bps_pct(top10_bps)}")
    else:
        print("Top-N by balance: (none; no non-zero accounts)")

    # Bottom-percentile snapshot. Median/p25/p10 of the non-zero
    # distribution, plus how many accounts are at or below each cut.
    if nonzero_accts > 0:
        print("Bottom-percentile snapshot:")
        print(f"  p10    balance={pcts['p10']:<18} bottom-10%  count={btm['bottom_10_count']}")
        print(f"  p25    balance={pcts['p25']:<18} bottom-25%  count={btm['bottom_25_count']}")
        print(f"  median balance={pcts['median']:<18} bottom-50%  count={btm['bottom_50_count']}")
    else:
        print("Bottom-percentile snapshot: n/a (no non-zero accounts)")

print()
if anom_count == 0:
    print("[OK] Distribution within normal range")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "extreme_concentration" in anomalies:
        print(f"  extreme_concentration  : Gini = {render_gini(gini_bps)} (> 0.9000 threshold)")
    if "whale_dominance" in anomalies:
        print(f"  whale_dominance        : top-1 share = {render_bps_pct(top1_bps)} (> 50% threshold)")
    if "cartel_dominance" in anomalies:
        print(f"  cartel_dominance       : top-10 share = {render_bps_pct(top10_bps)} (> 90% threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_balance_distribution: rendering failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ────────────────────────────────────────────────
# Mirrors operator_dust_audit / operator_account_growth: exit 2 only when
# --anomalies-only is set AND ≥1 anomaly fired. Default informational mode
# always exits 0 if the snapshot pipeline succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_balance_distribution: cannot create temp file" >&2; exit 1;
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
