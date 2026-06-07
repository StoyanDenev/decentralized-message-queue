#!/usr/bin/env bash
# operator_balance_band_histogram.sh — "Wealth-pyramid" view of a running
# determ chain: bucket every account into order-of-magnitude (log-scale)
# balance bands and report a count + supply-share histogram across them.
#
# Read-only / pure diagnostic — NO mutation.
#
# Why this exists (gap vs. the sibling balance/supply tools):
#   operator_balance_distribution.sh  Gini + top-N holders + p10/p25/median
#                                     percentiles. One scalar (Gini) for
#                                     inequality + a tail snapshot. Does NOT
#                                     show the SHAPE of the distribution —
#                                     how many accounts sit in each
#                                     order-of-magnitude band.
#   operator_account_age_distribution Buckets accounts by inferred CREATION
#                                     HEIGHT (age), not by balance.
#   operator_stake_distribution.sh    Nakamoto + Gini on validator STAKE
#                                     (collateral), not liquid balance.
#   operator_dust_audit.sh            Catalogs the balance==0 zero-class.
#   operator_balance_band_histogram   THIS — every account binned into
#                                     log10 balance bands (0, 1-9, 10-99,
#                                     100-999, ...), per-band account count
#                                     + cumulative count + that band's share
#                                     of total supply. The classic "wealth
#                                     pyramid" an operator reads to answer
#                                     "is value spread across many small
#                                     holders or piled into a few huge ones,
#                                     and how fat is the dust floor?"
#
# Gini summarizes inequality to a single number; this histogram shows the
# population SHAPE behind that number — two chains with identical Gini can
# have very different band profiles (a fat dust floor vs. a smooth taper).
#
# Banding scheme (log10, integer-exact — no float binning):
#   band 0 (the "zero floor")  : balance == 0
#   band k>=1                   : 10^(k-1) <= balance < 10^k
#     band 1 : [1, 9]      band 2 : [10, 99]     band 3 : [100, 999] ...
#   Each account lands in exactly one band; the band index for a non-zero
#   balance is (number of decimal digits) = len(str(balance)). This is
#   computed by repeated integer division, so there is zero float-precision
#   risk even at very large balances (the ledger holds 64-bit-ish quantities).
#
# Pipeline (read-only RPC):
#   1.  `determ head --field height` — current tip (banner only).
#   2.  `determ snapshot create --out <tmp>` — full state dump. The dump's
#       accounts[].balance is the live held quantity. The lighter
#       `snapshot stats` surface returns counts only, so the full create
#       is required to enumerate per-account balances.
#   3.  (optional) `determ snapshot inspect --in <tmp> --json` — S-033/S-038
#       state_root restore round-trip, a defensive integrity check before we
#       trust the file. Bypass via --skip-verify when triaging a suspected-
#       broken state.
#   4.  Python bins every account by log10 band and computes per-band
#       count, cumulative count, and supply-share (basis points).
#
# Anomaly flags (each adds to anomalies[]; --anomalies-only exits 2):
#   - dust_floor_dominant   The zero-balance band holds > 50% of all
#                           accounts (state bloat / auto-creation residue
#                           dominates the ledger; cross-ref
#                           operator_dust_audit for remediation).
#   - top_band_supply_capture  The single highest-balance occupied band
#                           holds > 90% of total supply (value piled into a
#                           tiny order-of-magnitude tier — pre-distribution
#                           or whale-dominated chain).
#   - empty_middle          There is a gap of >= 3 consecutive empty bands
#                           strictly between the lowest and highest OCCUPIED
#                           non-zero bands (a "missing middle class" — the
#                           population is bimodal: many tiny holders + a few
#                           huge ones with nothing between).
#
# RPC dependencies (read-only):
#   - head                   current chain height (banner only)
#   - snapshot create        full state dump → tmp file
#   - snapshot inspect       round-trip integrity check (optional)
#
# Usage:
#   tools/operator_balance_band_histogram.sh [--rpc-port N] [--json]
#                                            [--include-zero]
#                                            [--anomalies-only] [--skip-verify]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope
#   --include-zero      Count the balance==0 band toward the supply-share
#                       denominator basis (no-op for supply since zero
#                       contributes 0; affects only the account-count
#                       percentage base). Default: account-count percentages
#                       are over ALL accounts including the zero band; this
#                       flag is reserved for symmetry with sibling tools and
#                       currently documents the default (zero always shown).
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   --skip-verify       Skip the inspect round-trip integrity check
#   -h, --help          Show this help
#
# Exit codes (mirrors operator_balance_distribution / operator_account_growth):
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / malformed snapshot / bad args
#   2   --anomalies-only set AND >=1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_balance_band_histogram.sh [--rpc-port N] [--json]
                                          [--include-zero]
                                          [--anomalies-only] [--skip-verify]

"Wealth-pyramid" view of a running determ daemon: bins every account into
order-of-magnitude (log10) balance bands and reports a per-band account
count + cumulative count + that band's share of total supply.

Banding (integer-exact, no float binning):
  band 0       balance == 0           (the dust / zero floor)
  band k>=1    10^(k-1) <= bal < 10^k (band 1 = [1,9], band 2 = [10,99], ...)

Complements operator_balance_distribution.sh: Gini gives one inequality
scalar; this shows the population SHAPE behind it.

Snapshot pipeline:
  1. `head --field height` for the tip (banner).
  2. `snapshot create --out <tmp>` writes the full state dump.
  3. (optional) `snapshot inspect --in <tmp> --json` verifies the
     S-033/S-038 state_root round-trip before parsing.
  4. Python bins accounts by log10 band.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope
  --include-zero      Reserved for sibling-tool symmetry (zero band is
                      always shown; documents the default)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  --skip-verify       Skip the inspect round-trip integrity check
  -h, --help          Show this help

Anomaly flags:
  dust_floor_dominant      zero-balance band > 50% of all accounts
  top_band_supply_capture  highest occupied band holds > 90% of supply
  empty_middle             >=3 consecutive empty bands between the lowest
                           and highest occupied non-zero bands

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed snapshot
  2   --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
SKIP_VERIFY=0
INCLUDE_ZERO=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --include-zero)    INCLUDE_ZERO=1;  shift ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    --skip-verify)     SKIP_VERIFY=1;   shift ;;
    *) echo "operator_balance_band_histogram: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guard on the port.
case "$PORT" in *[!0-9]*|"")
  echo "operator_balance_band_histogram: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current tip (banner only) ───────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_balance_band_histogram: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_balance_band_histogram: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: snapshot create → tmp file ──────────────────────────────────────
TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
  echo "operator_balance_band_histogram: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_balance_band_histogram: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_balance_band_histogram: snapshot create failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: integrity round-trip via `snapshot inspect` ─────────────────────
# Same S-033 + S-038 gate as operator_balance_distribution / operator_dust_audit.
# A successful inspect --json means the snapshot's stored state_root matches
# the recomputed one after Chain::restore_from_snapshot ran.
SNAP_BLOCK_INDEX="$HEAD_H"
SNAP_STATE_ROOT=""
if [ "$SKIP_VERIFY" = "0" ]; then
  INSPECT_OUT=$("$DETERM" snapshot inspect --in "$TMP_SNAP" --json 2>&1) || {
    echo "operator_balance_band_histogram: snapshot inspect failed (state_root mismatch or malformed snapshot)" >&2
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

# ── Step 4: bin accounts into log10 balance bands via Python ────────────────
# Band index for a non-zero balance b is the decimal digit count len(str(b)),
# computed by repeated integer division so there's zero float-precision risk:
#   band 1 = [1, 9]      band 2 = [10, 99]      band 3 = [100, 999] ...
# Band 0 is the explicit balance==0 floor. Each account lands in exactly one
# band. We aggregate per-band count + supply, then derive cumulative counts
# (ascending) and supply-share basis points.
python - "$TMP_SNAP" "$TMP_OUT" <<'PY'
import json, sys

snap_path, out_path = sys.argv[1:3]

try:
    with open(snap_path, "r", encoding="utf-8") as f:
        snap = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_balance_band_histogram: cannot parse snapshot: {e}\n")
    sys.exit(1)
if not isinstance(snap, dict):
    sys.stderr.write("operator_balance_band_histogram: snapshot is not a JSON object\n")
    sys.exit(1)

# Per-domain balance (last-write-wins on duplicate entries; matches
# Chain::restore_from_snapshot which overwrites). This audit is purely about
# liquid balance in accounts[].balance — stake collateral is a separate
# concern (operator_stake_distribution covers it).
balances = {}
for a in snap.get("accounts", []) or []:
    if not isinstance(a, dict):
        continue
    d = a.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    try:
        balances[d] = int(a.get("balance", 0) or 0)
    except (TypeError, ValueError):
        balances[d] = 0

total_accounts = len(balances)
total_supply = sum(b for b in balances.values() if b > 0)

# Integer log10 band index. band 0 == zero floor; band k>=1 == decimal-digit
# count (len(str(b))). Repeated integer division → no float-precision hazard.
def band_index(b):
    if b <= 0:
        return 0
    k = 0
    while b > 0:
        b //= 10
        k += 1
    return k

# Aggregate per band: account count + supply held in that band.
band_count = {}
band_supply = {}
for b in balances.values():
    bi = band_index(b)
    band_count[bi] = band_count.get(bi, 0) + 1
    if b > 0:
        band_supply[bi] = band_supply.get(bi, 0) + b

zero_count = band_count.get(0, 0)

# Highest occupied band index (across ALL bands including zero). Used for the
# cumulative-count ceiling and the top-band supply-capture anomaly.
max_band = max(band_count.keys()) if band_count else 0

# Emit one row per band index from 0..max_band INCLUSIVE so empty interior
# bands are visible as zero rows (that's the whole point of a histogram and
# is required for the empty_middle anomaly). For each band:
#   - lower / upper bound (upper is None for band 0; for band k it's 10^k - 1)
#   - count, cumulative count (ascending), supply, supply-share bps
bands = []
cumulative = 0
for bi in range(0, max_band + 1):
    c = band_count.get(bi, 0)
    s = band_supply.get(bi, 0)
    cumulative += c
    if bi == 0:
        lo, hi = 0, 0
    else:
        lo = 10 ** (bi - 1)
        hi = 10 ** bi - 1
    share_bps = (s * 10000 // total_supply) if total_supply > 0 else 0
    bands.append({
        "band":            bi,
        "lo":              lo,
        "hi":              hi,
        "count":           c,
        "cumulative":      cumulative,
        "supply":          s,
        "supply_bps":      share_bps,
    })

# Occupied NON-ZERO bands (band index >= 1 with count > 0). Used for the
# empty_middle gap detection and the supply-capture top band.
occupied_nonzero = [b["band"] for b in bands if b["band"] >= 1 and b["count"] > 0]

# top_band: the highest occupied NON-ZERO band (the wealthiest tier present).
top_nonzero_band = max(occupied_nonzero) if occupied_nonzero else 0
top_band_supply_bps = 0
for b in bands:
    if b["band"] == top_nonzero_band:
        top_band_supply_bps = b["supply_bps"]
        break

# empty_middle: largest run of consecutive EMPTY non-zero bands strictly
# between the lowest and highest occupied non-zero bands.
max_gap = 0
if len(occupied_nonzero) >= 2:
    lo_occ = min(occupied_nonzero)
    hi_occ = max(occupied_nonzero)
    occ_set = set(occupied_nonzero)
    run = 0
    for bi in range(lo_occ + 1, hi_occ):
        if bi in occ_set:
            run = 0
        else:
            run += 1
            if run > max_gap:
                max_gap = run

# Account-count share of the zero band (basis points of all accounts).
zero_share_bps = (zero_count * 10000 // total_accounts) if total_accounts > 0 else 0

# Anomaly classification.
anomalies = []
# dust_floor_dominant: zero-balance band > 50% of all accounts.
if total_accounts > 0 and zero_share_bps > 5000:
    anomalies.append("dust_floor_dominant")
# top_band_supply_capture: highest occupied non-zero band > 90% of supply.
# Requires >= 2 occupied non-zero bands so a single-tier chain (all holders
# in one band by definition holding 100%) doesn't trivially fire.
if len(occupied_nonzero) >= 2 and top_band_supply_bps > 9000:
    anomalies.append("top_band_supply_capture")
# empty_middle: a gap of >= 3 consecutive empty non-zero bands.
if max_gap >= 3:
    anomalies.append("empty_middle")

result = {
    "total_accounts":       total_accounts,
    "nonzero_accounts":     total_accounts - zero_count,
    "zero_accounts":        zero_count,
    "zero_share_bps":       zero_share_bps,
    "total_supply":         total_supply,
    "bands":                bands,
    "occupied_nonzero_bands": occupied_nonzero,
    "top_nonzero_band":     top_nonzero_band,
    "top_band_supply_bps":  top_band_supply_bps,
    "max_empty_middle_run": max_gap,
    "anomalies":            anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_balance_band_histogram: band computation failed" >&2
  exit 1
fi

# ── Step 5: render envelope (JSON or human) ─────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" \
        "$SNAP_BLOCK_INDEX" "$SNAP_STATE_ROOT" "$SKIP_VERIFY" "$INCLUDE_ZERO" <<'PY'
import json, sys

json_out         = sys.argv[1] == "1"
anom_only        = sys.argv[2] == "1"
out_path         = sys.argv[3]
port             = int(sys.argv[4])
head_h           = int(sys.argv[5])
snap_block_index = int(sys.argv[6])
snap_state_root  = sys.argv[7]
skip_verify      = sys.argv[8] == "1"
include_zero     = sys.argv[9] == "1"

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total_accts   = r["total_accounts"]
nonzero_accts = r["nonzero_accounts"]
zero_accts    = r["zero_accounts"]
zero_bps      = r["zero_share_bps"]
total_supply  = r["total_supply"]
bands         = r["bands"]
top_band      = r["top_nonzero_band"]
top_band_bps  = r["top_band_supply_bps"]
max_gap       = r["max_empty_middle_run"]
anomalies     = r["anomalies"]
anom_count    = len(anomalies)

def render_bps_pct(bps):
    """bps in 0..10000 → 'XX.X%' (one decimal of precision)."""
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def band_label(b):
    if b["band"] == 0:
        return "0 (zero floor)"
    return f"[{b['lo']}, {b['hi']}]"

if json_out:
    envelope = {
        "rpc_port":             port,
        "head_height":          head_h,
        "snapshot_block_index": snap_block_index,
        "snapshot_state_root":  snap_state_root if snap_state_root else None,
        "verify_skipped":       skip_verify,
        "total_accounts":       total_accts,
        "nonzero_accounts":     nonzero_accts,
        "zero_accounts":        zero_accts,
        "zero_share_bps":       zero_bps,
        "total_supply":         total_supply,
        "bands":                bands,
        "top_nonzero_band":     top_band,
        "top_band_supply_bps":  top_band_bps,
        "max_empty_middle_run": max_gap,
        "anomalies":            anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_balance_band_histogram: no anomalies (port {port})")
    sys.exit(0)

print(f"=== Balance-band histogram (port {port}) ===")
verify_note = " [verify skipped]" if skip_verify else ""
print(f"Snapshot block: {snap_block_index}{verify_note}")
print(f"Total accounts: {total_accts}")
print(f"Non-zero accounts: {nonzero_accts}")
print(f"Zero-balance (dust floor): {zero_accts} ({render_bps_pct(zero_bps)} of accounts)")
print(f"Total non-zero supply: {total_supply}")

if not anom_only:
    if bands:
        print("Per-band histogram (log10 order-of-magnitude balance bands):")
        # Column widths chosen for readability of the longest expected
        # range string. Bands run 0..max occupied band, empty interior
        # bands shown as zero rows so the pyramid shape is visible.
        for b in bands:
            label = band_label(b)
            print(f"  band {b['band']:>2}  {label:<22} "
                  f"count={b['count']:<10} cum={b['cumulative']:<10} "
                  f"supply-share={render_bps_pct(b['supply_bps'])}")
        if top_band > 0:
            print(f"Highest occupied non-zero band: band {top_band} "
                  f"(supply-share {render_bps_pct(top_band_bps)})")
        if max_gap > 0:
            print(f"Largest empty-middle run: {max_gap} consecutive empty band(s)")
    else:
        print("Per-band histogram: (none; no accounts)")

print()
if anom_count == 0:
    print("[OK] Band profile within normal range")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "dust_floor_dominant" in anomalies:
        print(f"  dust_floor_dominant     : zero band = {render_bps_pct(zero_bps)} of accounts (> 50% threshold)")
    if "top_band_supply_capture" in anomalies:
        print(f"  top_band_supply_capture : band {top_band} holds {render_bps_pct(top_band_bps)} of supply (> 90% threshold)")
    if "empty_middle" in anomalies:
        print(f"  empty_middle            : {max_gap} consecutive empty non-zero bands (>= 3 threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_balance_band_histogram: rendering failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ────────────────────────────────────────────────
# Mirrors operator_balance_distribution / operator_account_growth: exit 2 only
# when --anomalies-only is set AND >=1 anomaly fired. Default informational
# mode always exits 0 if the snapshot pipeline succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_balance_band_histogram: cannot create temp file" >&2; exit 1;
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
