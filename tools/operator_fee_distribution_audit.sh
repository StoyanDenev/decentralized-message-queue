#!/usr/bin/env bash
# operator_fee_distribution_audit.sh — Audit per-block transaction-fee
# distribution to block creators over a window of blocks. Companion to
# operator_subsidy_audit.sh: both flow through the same creator-credit
# algorithm in chain.cpp::apply_block (equal split across creators, integer
# division remainder credited to creators[0]) — the difference is the
# origin of the credited amount. Subsidy is *minted* (E1/E3/E4 pool draw);
# fees are *transferred* from senders (TX_FEE charged on TRANSFER /
# REGISTER / DEREGISTER / STAKE / UNSTAKE / DAPP_REGISTER / DAPP_CALL).
#
# Read-only RPC composition; safe against a running daemon. The script
# walks the requested window via `determ block-info <h> --json` (one
# round-trip per block) to collect both each block's `creators` list and
# its embedded `transactions` array. Per-block total fee is summed over
# every tx's `fee` field. This is a best-effort UPPER BOUND on the
# fee actually credited to creators in apply_block: per FA-Apply-6 T-F2,
# silent-skip txs (insufficient sender balance, failed UNSTAKE refund,
# etc.) appear in the block's transactions list but never reach the
# `total_fees += tx.fee` line in chain.cpp. There is no RPC that exposes
# the apply-time success bitmap, so the audit takes the upper-bound view
# explicitly — operators reading concentration metrics should keep that
# inflation factor in mind. In a healthy mempool with well-formed txs
# the upper bound matches the actual credited fee exactly (the producer
# rejects malformed txs at admission); silent-skip mostly fires under
# nonce-races / mid-flight balance reductions.
#
# Per-block attribution mirrors chain.cpp::apply_block:
#   each       = block_total_fee / len(creators)
#   remainder  = block_total_fee % len(creators)
#   creators[i].balance += each   (for i in 0..m-1)
#   creators[0].balance += remainder
#
# Window totals: total fees collected, distinct receiving creators,
# top-1 / top-3 share concentration, fee collection drop across the
# midpoint (chain-idleness signal), dust-only block ratio (very-low
# transaction-value signal anchored on TX_FEE=1 default per
# src/chain/genesis.cpp — dust threshold of 5 = 5× base fee).
#
# Usage:
#   tools/operator_fee_distribution_audit.sh [--rpc-port N] [--json]
#                                            [--from H] [--to H]
#                                            [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of audit window (default: max(0, tip-1000))
#   --to H              End of audit window (default: tip)
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head              (current chain height)
#   - block             (per-block JSON; via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - top_1_share_high      single creator received > 50% of fees in window
#                           (operator should confirm committee health — high
#                           concentration in M=K creator-pools is normal,
#                           but >50% in a healthy K≥3 selection is a signal)
#   - fee_collection_drop   second-half fee total dropped > 50% vs first
#                           half (chain idleness — TPS collapse or sudden
#                           drop in tx-paying activity; each half must
#                           carry ≥1 fee-bearing block to suppress noise)
#   - dust_only_window      > 50% of blocks in the window have total
#                           fees < 5 units (very-low-value tx activity;
#                           anchored on TX_FEE=1 baseline → threshold is
#                           5× the base fee, i.e. ≤4 fee-bearing txs per
#                           block; signals testnet-style trickle traffic)
#
# Exit codes (mirrors operator_subsidy_audit / operator_payments_audit):
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_fee_distribution_audit.sh [--rpc-port N] [--json]
                                          [--from H] [--to H]
                                          [--anomalies-only]

Audit per-block transaction-fee distribution to creators over a window
of blocks. Walks the window via block-info, sums tx.fee per block as a
best-effort upper bound (silent-skip txs don't pay fee per FA-Apply-6
T-F2 but appear in the block JSON), attributes per-block totals across
creators via the apply-side rule (1/len(creators) each + remainder to
creators[0]), and reports concentration + chain-idleness metrics.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, tip-1000))
  --to H              End of audit window (default: tip)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  top_1_share_high       single creator > 50% of fees in window
  fee_collection_drop    2nd-half fee total < 50% of 1st-half (idleness)
  dust_only_window       > 50% of blocks have total_fees < 5 (TX_FEE=1
                         baseline → 5× base; trickle / testnet signal)

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --from)            FROM_H="${2:-}"; shift 2 ;;
    --to)              TO_H="${2:-}";   shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_fee_distribution_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_fee_distribution_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_fee_distribution_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_fee_distribution_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_fee_distribution_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip (per spec).
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_fee_distribution_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk the window in Python (JSON parse + per-creator aggregate) ───
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_fee_distribution_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, out_path = sys.argv[1:6]
from_h = int(from_h); to_h = int(to_h)

# Per-creator state (mirrors operator_subsidy_audit's ledger).
# blocks_present[creator] = count of blocks in [from, to] where creator
#                           appeared in the `creators` list
# fee_share[creator]      = sum over those blocks of per_creator_fee_credit
fee_share        = defaultdict(int)
blocks_present   = defaultdict(int)
empty_blocks     = 0       # blocks with zero creators (no fees paid)
total_fees_paid  = 0       # sum of per-block total_fee over non-empty blocks;
                           # used as the cross-check vs. sum(fee_share.values())
per_block_fees   = []      # per-block (height, total_fee) for 1st/2nd-half +
                           # dust detection
dust_block_count = 0       # blocks with total_fee < DUST_THRESHOLD (5)

DUST_THRESHOLD = 5

# Split the window at the midpoint for the fee-collection-drop comparator.
mid_h = (from_h + to_h) // 2

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_fee_distribution_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_fee_distribution_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_fee_distribution_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list): creators = []
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): txs = []

    # Per-block total fee = sum of every tx's `fee` field.
    # Best-effort upper bound per the header note (FA-Apply-6 T-F2).
    block_total_fee = 0
    for tx in txs:
        if not isinstance(tx, dict): continue
        try:
            f = int(tx.get("fee", 0) or 0)
        except (TypeError, ValueError):
            f = 0
        if f < 0:
            # Tx fees are u64 per src/chain/block.cpp Transaction::fee;
            # a negative value here would indicate a JSON corruption or
            # an interpreter-cast artifact — skip defensively.
            continue
        block_total_fee += f

    per_block_fees.append((h, block_total_fee))
    if block_total_fee < DUST_THRESHOLD:
        dust_block_count += 1

    if len(creators) == 0:
        empty_blocks += 1
        continue   # apply-side: no creators ⇒ no fee credit (block_total_fee
                   # would also have been zero in steady state since the
                   # producer assembles non-empty creators[] before
                   # admitting txs; defensive skip here matches subsidy_audit)
    if block_total_fee == 0:
        # Track presence (creator appeared in this block) without
        # crediting fee. Lets distinct_creators reflect committee
        # participation, not just fee-bearing participation.
        for c in creators:
            if isinstance(c, str):
                blocks_present[c] += 1
        continue

    total_fees_paid += block_total_fee
    m = len(creators)
    each = block_total_fee // m
    rem  = block_total_fee - each * m   # equivalent to block_total_fee % m
    for c in creators:
        if not isinstance(c, str): continue
        blocks_present[c] += 1
        fee_share[c]      += each
    # Remainder credited to first creator only (matches chain.cpp).
    first = creators[0] if creators else None
    if isinstance(first, str):
        fee_share[first] += rem

# Per-creator ledger sorted by fee_share desc (ties by name asc) —
# mirrors operator_subsidy_audit's emission order.
rows = sorted(
    fee_share.items(),
    key=lambda kv: (-kv[1], kv[0])
)
per_creator = [
    {
        "creator":        c,
        "blocks_present": blocks_present[c],
        "fee_share":      share,
        "share_bps":      (share * 10000 // total_fees_paid) if total_fees_paid > 0 else 0,
    }
    for c, share in rows
]

# Top-N concentration (matches subsidy_audit shape: top-1 + top-3 share).
top_1_share_bps = per_creator[0]["share_bps"] if per_creator else 0
top_1_creator   = per_creator[0]["creator"]   if per_creator else ""
top_3_amt = sum((row["fee_share"] for row in per_creator[:3]), 0)
top_3_share_bps = (top_3_amt * 10000 // total_fees_paid) if total_fees_paid > 0 else 0

# Distinct creators = creators who appeared (with or without fee credit).
distinct_creators = len(blocks_present)

# 1st/2nd-half fee totals (for fee_collection_drop). Match operator_payments_audit's
# midpoint convention: blocks where h <= mid_h are 1st half, h > mid_h are 2nd half.
first_half_fees  = 0
second_half_fees = 0
first_half_count  = 0   # # of blocks with >0 fee in 1st half (for noise guard)
second_half_count = 0
for h, f in per_block_fees:
    if h <= mid_h:
        first_half_fees += f
        if f > 0: first_half_count += 1
    else:
        second_half_fees += f
        if f > 0: second_half_count += 1

# Drop in bps = ((1st - 2nd) / 1st) * 10000. Only meaningful if 1st half
# carried some fee-bearing activity; otherwise no baseline → 0.
fee_drop_bps = 0
if first_half_fees > 0 and second_half_fees < first_half_fees:
    fee_drop_bps = (first_half_fees - second_half_fees) * 10000 // first_half_fees

# Dust-only ratio: fraction of blocks with total_fee < DUST_THRESHOLD.
n_blocks = to_h - from_h + 1
dust_block_ratio_bps = (dust_block_count * 10000 // n_blocks) if n_blocks > 0 else 0

# Anomaly classification.
anomalies = []
if top_1_share_bps > 5000:
    anomalies.append("top_1_share_high")
# Both halves must carry ≥1 fee-bearing block — otherwise the chain
# was idle on one side and a "drop" is ambiguous (idle ↔ idle, not
# idle ← active). Mirrors the ≥10-TRANSFER guard in operator_payments_audit
# but scaled down: fees are emitted by any tx type, so any single
# fee-bearing block on each side is enough signal.
if first_half_count >= 1 and second_half_count >= 1 and fee_drop_bps > 5000:
    anomalies.append("fee_collection_drop")
if dust_block_ratio_bps > 5000:
    anomalies.append("dust_only_window")

# Average fee per block (over the window, including zero-fee blocks).
avg_fee_per_block = (total_fees_paid // n_blocks) if n_blocks > 0 else 0

result = {
    "total_fees":            total_fees_paid,
    "avg_fee_per_block":     avg_fee_per_block,
    "distinct_creators":     distinct_creators,
    "empty_creators_blocks": empty_blocks,
    "dust_block_count":      dust_block_count,
    "dust_block_ratio_bps":  dust_block_ratio_bps,
    "dust_threshold":        DUST_THRESHOLD,
    "first_half_fees":       first_half_fees,
    "second_half_fees":      second_half_fees,
    "first_half_count":      first_half_count,
    "second_half_count":     second_half_count,
    "fee_drop_bps":          fee_drop_bps,
    "top_1_share_bps":       top_1_share_bps,
    "top_3_share_bps":       top_3_share_bps,
    "top_1_creator":         top_1_creator,
    "per_creator":           per_creator,
    "anomalies":             anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_fee_distribution_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 3: render envelope (JSON or human table) ─────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$HEAD_H" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
port       = int(sys.argv[4])
from_h     = int(sys.argv[5])
to_h       = int(sys.argv[6])
win_blocks = int(sys.argv[7])
head_h     = int(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total      = r["total_fees"]
anomalies  = r["anomalies"]
anom_count = len(anomalies)

def render_pct(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = {
        "window":               {"from": from_h, "to": to_h, "blocks": win_blocks},
        "total_fees":           r["total_fees"],
        "avg_fee_per_block":    r["avg_fee_per_block"],
        "distinct_creators":    r["distinct_creators"],
        "empty_creators_blocks": r["empty_creators_blocks"],
        "dust_block_count":     r["dust_block_count"],
        "dust_block_ratio_bps": r["dust_block_ratio_bps"],
        "dust_threshold":       r["dust_threshold"],
        "first_half_fees":      r["first_half_fees"],
        "second_half_fees":     r["second_half_fees"],
        "first_half_count":     r["first_half_count"],
        "second_half_count":    r["second_half_count"],
        "fee_drop_bps":         r["fee_drop_bps"],
        "top_1_share_bps":      r["top_1_share_bps"],
        "top_3_share_bps":      r["top_3_share_bps"],
        "top_1_creator":        r["top_1_creator"],
        "per_creator":          r["per_creator"],
        "anomalies":            anomalies,
        "rpc_port":             port,
        "head_height":          head_h,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout. Same shape as operator_subsidy_audit's table:
#   header, summary metrics, per-creator ledger, concentration line,
#   anomaly line.
if anom_only and anom_count == 0:
    print(f"operator_fee_distribution_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

print(f"=== Fee distribution audit (port {port}, window [{from_h}..{to_h}], "
      f"{win_blocks} blocks) ===")
print(f"Total fees: {total}")
print(f"Avg fee per block (window): {r['avg_fee_per_block']}")
print(f"Empty-creators blocks: {r['empty_creators_blocks']}")
print(f"Distinct creators in window: {r['distinct_creators']}")
print(f"Dust-only blocks (total_fee < {r['dust_threshold']}): "
      f"{r['dust_block_count']} / {win_blocks} ({render_pct(r['dust_block_ratio_bps'])})")

if r["per_creator"] and not anom_only:
    print()
    print("Per-creator share (sorted by fee_share desc):")
    rank = 0
    for row in r["per_creator"]:
        rank += 1
        pct = render_pct(row["share_bps"]) if total > 0 else "-"
        tag = "  [top-1]" if rank == 1 else ""
        print(f"  {row['creator']:<28} : {row['fee_share']} ({pct})  "
              f"blocks={row['blocks_present']}{tag}")

print()
if r["per_creator"]:
    print(f"Top-1 share : {render_pct(r['top_1_share_bps'])}")
    print(f"Top-3 share : {render_pct(r['top_3_share_bps'])}")
print(f"1st-half fees: {r['first_half_fees']} ({r['first_half_count']} fee-bearing blocks)")
print(f"2nd-half fees: {r['second_half_fees']} ({r['second_half_count']} fee-bearing blocks)")
if r["first_half_fees"] > 0:
    print(f"Fee drop : {render_pct(r['fee_drop_bps'])} (1st→2nd half)")

print()
if anom_count == 0:
    print("[OK] No concentration anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_fee_distribution_audit: render failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 4: exit-code policy ─────────────────────────────────────────────────
# Same convention as operator_subsidy_audit / operator_payments_audit /
# operator_fork_watch: exit 2 only when --anomalies-only is set AND at
# least one anomaly fired. Default informational mode always exits 0
# if the RPC walk succeeded.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: r = json.load(f)
print(len(r.get("anomalies") or []))
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
