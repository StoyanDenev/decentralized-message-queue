#!/usr/bin/env bash
# operator_payments_audit.sh — Audit TRANSFER transaction activity over a
# window of blocks on a running determ daemon. Sibling to
# operator_dapp_call_audit.sh; same per-block walking + JSON envelope shape,
# but selects type==0 (TxType::TRANSFER per include/determ/chain/block.hpp)
# and produces payment-flow statistics rather than DApp-call metrics.
#
# Walks the requested window via `determ block-info <h> --json` (one
# round-trip per block) and selects transactions where type == 0
# (TxType::TRANSFER). For each TRANSFER it extracts {from, to, amount,
# fee, block_index} and reports:
#   - Total TRANSFER count + total amount + total fees
#   - Per-amount bucket distribution (micro / small / medium / large / huge)
#   - Top-20 senders by tx count + by total amount sent
#   - Top-20 receivers by tx count + by total amount received
#   - Anon-address (0x + 64 hex per is_anon_address) vs domain breakdown
#     for both sender and receiver legs
#   - Average / median / p95 / p99 amount per TRANSFER
#   - Per-block coverage: how many blocks in the window held ≥1 TRANSFER
#
# Amount-bucket boundaries (rationale anchored in the network's micro-fee
# economy — base TX_FEE = 1 unit per src/chain/genesis.cpp default):
#   micro   ≤ 10       (sub-coffee tip / dust; ≤10× the base fee)
#   small   11 – 100   (typical retail-style payment)
#   medium  101 – 1000 (mid-tier transfer)
#   large   1001 – 10000 (institutional rebalance)
#   huge    > 10000    (whale / exchange flow — exchange-style concentration)
#
# RPC-shape note: TxType is serialized to JSON as a numeric int (0 for
# TRANSFER per src/chain/block.cpp::Transaction::to_json). For forward
# robustness this script also accepts the string forms "0" and "TRANSFER" —
# pattern mirrors operator_dapp_call_audit.sh's is_dapp_call helper.
#
# Usage:
#   tools/operator_payments_audit.sh [--rpc-port N] [--json]
#                                    [--from H] [--to H]
#                                    [--anomalies-only]
#
# Options:
#   --rpc-port N         RPC port to query (default: 7778)
#   --json               Emit structured JSON envelope instead of human table
#   --from H             Start of audit window (inclusive; default: max(0, tip-1000))
#   --to H               End of audit window (inclusive; default: tip)
#   --anomalies-only     Print only flagged anomalies; exit 2 if any fire
#   -h, --help           Show this help
#
# RPC dependencies (all read-only):
#   - head               (current chain height)
#   - block              (per-block JSON; via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - sender_concentration   single sender > 30% of TRANSFER amount in window
#                            (volume concentration; possible exchange hot
#                            wallet or Sybil aggregator — operator should
#                            confirm legitimacy)
#   - receiver_concentration single receiver > 50% of TRANSFER amount in
#                            window (INFORMATIONAL — typical for exchange
#                            deposit addresses; surfaced for awareness, not
#                            as an alert by itself)
#   - mass_dust              average TRANSFER amount in the second half of
#                            the window dropped by > 50% vs the first half
#                            (potential mass-dust attack; sub-windows must
#                            each carry ≥ 10 TRANSFERs to suppress noise)
#
# Exit codes (mirrors operator_dapp_audit / operator_dapp_call_audit):
#   0   audit ran successfully (including zero TRANSFERs in window)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_payments_audit.sh [--rpc-port N] [--json]
                                  [--from H] [--to H]
                                  [--anomalies-only]

Audit TRANSFER (TxType==0) activity over a window of blocks. Walks the
window via block-info, selects type==0 transactions, and reports
aggregate flow / fee / amount-distribution metrics.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --json               Emit structured JSON envelope instead of human table
  --from H             Start of audit window (default: max(0, tip-1000))
  --to H               End of audit window (default: tip)
  --anomalies-only     Print only flagged anomalies; exit 2 if any fire
  -h, --help           Show this help

Amount buckets (anchored on TX_FEE=1 baseline):
  micro   ≤10           sub-fee dust / tip
  small   11..100       retail payment
  medium  101..1000     mid-tier
  large   1001..10000   institutional
  huge    >10000        whale / exchange flow

Anomaly flags:
  sender_concentration    single sender > 30% of total TRANSFER amount
  receiver_concentration  single receiver > 50% of amount (informational)
  mass_dust               2nd-half average < 50% of 1st-half average
                          (each half must carry ≥10 TRANSFERs)

Exit codes:
  0   success (or informational mode, including zero TRANSFERs)
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
    *) echo "operator_payments_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_payments_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_payments_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_payments_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_payments_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip.
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_payments_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk the window in Python (JSON parse + aggregate) ───────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_payments_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, out_path = sys.argv[1:6]
from_h = int(from_h); to_h = int(to_h)

def is_transfer(tx_type):
    # tx.type is serialized to JSON as int per Transaction::to_json
    # (src/chain/block.cpp). Accept string forms for forward robustness.
    if isinstance(tx_type, int):  return tx_type == 0
    if isinstance(tx_type, str):  return tx_type in ("0", "TRANSFER")
    return False

def is_anon(addr):
    # Matches is_anon_address in include/determ/types.hpp:
    # "0x" + 64 hex (case-insensitive). Everything else is treated as
    # a domain account (the RPC + chain accept either form as account
    # identifiers but only domains can register / be selected).
    if not isinstance(addr, str): return False
    if len(addr) != 66: return False
    if addr[:2] != "0x": return False
    for c in addr[2:]:
        if not (("0" <= c <= "9") or ("a" <= c <= "f") or ("A" <= c <= "F")):
            return False
    return True

def classify_amount(a):
    if a <= 10:    return "micro"
    if a <= 100:   return "small"
    if a <= 1000:  return "medium"
    if a <= 10000: return "large"
    return "huge"

# Aggregators
total_transfers   = 0
total_amount      = 0
total_fees        = 0
amount_buckets    = {"micro": 0, "small": 0, "medium": 0, "large": 0, "huge": 0}
sender_count      = defaultdict(int)
sender_amount     = defaultdict(int)
receiver_count    = defaultdict(int)
receiver_amount   = defaultdict(int)
amounts           = []   # per-tx amounts for median / p95 / p99
amounts_1st_half  = []   # for mass-dust detection: first half of window
amounts_2nd_half  = []   # second half of window
anon_senders      = 0
anon_receivers    = 0
blocks_with_tx    = 0    # block-coverage counter

# Split the window at the midpoint for the mass-dust comparator.
mid_h = (from_h + to_h) // 2

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_payments_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_payments_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_payments_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): continue
    block_had_transfer = False
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_transfer(tx.get("type")): continue
        frm    = tx.get("from", "")
        to     = tx.get("to", "")
        amount = int(tx.get("amount", 0) or 0)
        fee    = int(tx.get("fee", 0) or 0)
        total_transfers += 1
        total_amount    += amount
        total_fees      += fee
        amount_buckets[classify_amount(amount)] += 1
        sender_count[frm]     += 1
        sender_amount[frm]    += amount
        receiver_count[to]    += 1
        receiver_amount[to]   += amount
        amounts.append(amount)
        if h <= mid_h: amounts_1st_half.append(amount)
        else:          amounts_2nd_half.append(amount)
        if is_anon(frm): anon_senders   += 1
        if is_anon(to):  anon_receivers += 1
        block_had_transfer = True
    if block_had_transfer:
        blocks_with_tx += 1

# Top-20 lists. Ties broken by sub-key (amount for count, count for amount,
# then domain ascending) for stable, deterministic output across runs.
top_senders_by_count = sorted(
    sender_count.items(),
    key=lambda kv: (-kv[1], -sender_amount[kv[0]], kv[0])
)[:20]
top_senders_by_amount = sorted(
    sender_amount.items(),
    key=lambda kv: (-kv[1], -sender_count[kv[0]], kv[0])
)[:20]
top_receivers_by_count = sorted(
    receiver_count.items(),
    key=lambda kv: (-kv[1], -receiver_amount[kv[0]], kv[0])
)[:20]
top_receivers_by_amount = sorted(
    receiver_amount.items(),
    key=lambda kv: (-kv[1], -receiver_count[kv[0]], kv[0])
)[:20]

# Stat helpers: median + p95 + p99 from the per-tx amount list. Avoid
# importing statistics for the sake of older interpreters; integer index
# arithmetic on a sorted copy is fine here.
def percentile(sorted_xs, q_bps):
    # q_bps in [0, 10000]; returns the value at floor(q_bps/10000 * (n-1)).
    n = len(sorted_xs)
    if n == 0: return 0
    idx = (q_bps * (n - 1)) // 10000
    if idx < 0: idx = 0
    if idx >= n: idx = n - 1
    return sorted_xs[idx]

sorted_amounts = sorted(amounts)
avg_amount = (total_amount // total_transfers) if total_transfers > 0 else 0
median_amount = percentile(sorted_amounts, 5000)
p95_amount    = percentile(sorted_amounts, 9500)
p99_amount    = percentile(sorted_amounts, 9900)

# Average fee per TRANSFER (integer division — operator-facing, not
# a chain-consensus value).
avg_fee = (total_fees // total_transfers) if total_transfers > 0 else 0

# Anomaly classification.
anomalies = []
# Sender concentration: top sender > 30% of TOTAL AMOUNT (volume, not count).
top_sender_amt_pct_bps = 0
top_sender_amt_name    = ""
if total_amount > 0 and top_senders_by_amount:
    top_sender_amt_name    = top_senders_by_amount[0][0]
    top_sender_amt_pct_bps = top_senders_by_amount[0][1] * 10000 // total_amount
    if top_sender_amt_pct_bps > 3000:
        anomalies.append("sender_concentration")
# Receiver concentration: top receiver > 50% of total amount (informational).
top_receiver_amt_pct_bps = 0
top_receiver_amt_name    = ""
if total_amount > 0 and top_receivers_by_amount:
    top_receiver_amt_name    = top_receivers_by_amount[0][0]
    top_receiver_amt_pct_bps = top_receivers_by_amount[0][1] * 10000 // total_amount
    if top_receiver_amt_pct_bps > 5000:
        anomalies.append("receiver_concentration")
# Mass-dust: 2nd-half avg amount dropped > 50% vs 1st-half. Require ≥10
# TRANSFERs per half to suppress sub-window-noise false positives.
mass_dust_drop_bps = 0
avg_1st = 0
avg_2nd = 0
if len(amounts_1st_half) >= 10 and len(amounts_2nd_half) >= 10:
    avg_1st = sum(amounts_1st_half) // len(amounts_1st_half)
    avg_2nd = sum(amounts_2nd_half) // len(amounts_2nd_half)
    if avg_1st > 0 and avg_2nd < avg_1st:
        # Drop in bps: ((avg_1st - avg_2nd) / avg_1st) * 10000.
        mass_dust_drop_bps = (avg_1st - avg_2nd) * 10000 // avg_1st
        if mass_dust_drop_bps > 5000:
            anomalies.append("mass_dust")

result = {
    "total_transfers":            total_transfers,
    "total_amount":               total_amount,
    "total_fees":                 total_fees,
    "avg_fee_per_tx":             avg_fee,
    "avg_amount":                 avg_amount,
    "median_amount":              median_amount,
    "p95_amount":                 p95_amount,
    "p99_amount":                 p99_amount,
    "distinct_senders":           len(sender_count),
    "distinct_receivers":         len(receiver_count),
    "anon_sender_count":          anon_senders,
    "anon_receiver_count":        anon_receivers,
    "blocks_with_transfer":       blocks_with_tx,
    "amount_buckets":             amount_buckets,
    "top_senders_by_count":       [
        {"account": d, "count": n, "amount": sender_amount[d]}
        for d, n in top_senders_by_count
    ],
    "top_senders_by_amount":      [
        {"account": d, "amount": a, "count": sender_count[d]}
        for d, a in top_senders_by_amount
    ],
    "top_receivers_by_count":     [
        {"account": d, "count": n, "amount": receiver_amount[d]}
        for d, n in top_receivers_by_count
    ],
    "top_receivers_by_amount":    [
        {"account": d, "amount": a, "count": receiver_count[d]}
        for d, a in top_receivers_by_amount
    ],
    "anomalies":                  anomalies,
    "top_sender_amt_pct_bps":     top_sender_amt_pct_bps,
    "top_sender_amt_name":        top_sender_amt_name,
    "top_receiver_amt_pct_bps":   top_receiver_amt_pct_bps,
    "top_receiver_amt_name":      top_receiver_amt_name,
    "mass_dust_drop_bps":         mass_dust_drop_bps,
    "avg_1st_half":               avg_1st,
    "avg_2nd_half":               avg_2nd,
    "first_half_count":           len(amounts_1st_half),
    "second_half_count":          len(amounts_2nd_half),
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_payments_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 3: render envelope (JSON or human table) ─────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
port       = int(sys.argv[4])
from_h     = int(sys.argv[5])
to_h       = int(sys.argv[6])
win_blocks = int(sys.argv[7])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total      = r["total_transfers"]
anomalies  = r["anomalies"]
anom_count = len(anomalies)

def render_pct(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def pct(n, denom):
    if denom <= 0: return "-"
    bps = n * 10000 // denom
    return render_pct(bps)

if json_out:
    envelope = {
        "window": {"from": from_h, "to": to_h, "blocks": win_blocks},
        "total":                    total,
        "total_amount":             r["total_amount"],
        "total_fees":               r["total_fees"],
        "avg_fee_per_tx":           r["avg_fee_per_tx"],
        "avg_amount":               r["avg_amount"],
        "median_amount":            r["median_amount"],
        "p95_amount":               r["p95_amount"],
        "p99_amount":               r["p99_amount"],
        "distinct_senders":         r["distinct_senders"],
        "distinct_receivers":       r["distinct_receivers"],
        "anon_sender_count":        r["anon_sender_count"],
        "anon_receiver_count":      r["anon_receiver_count"],
        "blocks_with_transfer":     r["blocks_with_transfer"],
        "amount_buckets":           r["amount_buckets"],
        "top_senders_by_count":     r["top_senders_by_count"],
        "top_senders_by_amount":    r["top_senders_by_amount"],
        "top_receivers_by_count":   r["top_receivers_by_count"],
        "top_receivers_by_amount":  r["top_receivers_by_amount"],
        "anomalies":                anomalies,
        "top_sender_amt_pct_bps":   r["top_sender_amt_pct_bps"],
        "top_sender_amt_name":      r["top_sender_amt_name"],
        "top_receiver_amt_pct_bps": r["top_receiver_amt_pct_bps"],
        "top_receiver_amt_name":    r["top_receiver_amt_name"],
        "mass_dust_drop_bps":       r["mass_dust_drop_bps"],
        "avg_1st_half":             r["avg_1st_half"],
        "avg_2nd_half":             r["avg_2nd_half"],
        "first_half_count":         r["first_half_count"],
        "second_half_count":        r["second_half_count"],
        "rpc_port":                 port,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_payments_audit: no anomalies (port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

print(f"=== Payments audit (port {port}, window [{from_h}..{to_h}], {win_blocks} blocks) ===")
print(f"Total TRANSFERs: {total}")
print(f"Total amount transferred: {r['total_amount']}")
if total > 0:
    print(f"Fee collected: {r['total_fees']} ({r['avg_fee_per_tx']} per tx average)")
else:
    print(f"Fee collected: {r['total_fees']}")
print(f"Blocks with ≥1 TRANSFER: {r['blocks_with_transfer']} / {win_blocks} "
      f"({pct(r['blocks_with_transfer'], win_blocks)})")
print(f"Distinct senders:   {r['distinct_senders']}")
print(f"Distinct receivers: {r['distinct_receivers']}")

if total > 0 and not anom_only:
    print(f"Amount stats (avg/median/p95/p99): "
          f"{r['avg_amount']} / {r['median_amount']} / "
          f"{r['p95_amount']} / {r['p99_amount']}")
    print()
    print("Amount distribution:")
    bk = r["amount_buckets"]
    print(f"  micro (≤10):         {bk['micro']} ({pct(bk['micro'], total)})")
    print(f"  small (11-100):      {bk['small']} ({pct(bk['small'], total)})")
    print(f"  medium (101-1000):   {bk['medium']} ({pct(bk['medium'], total)})")
    print(f"  large (1001-10000):  {bk['large']} ({pct(bk['large'], total)})")
    print(f"  huge (>10000):       {bk['huge']} ({pct(bk['huge'], total)})")
    print()
    print("Top senders by count:")
    if not r["top_senders_by_count"]:
        print("  (none)")
    else:
        for s in r["top_senders_by_count"]:
            print(f"  {s['account']}: {s['count']} ({pct(s['count'], total)}), "
                  f"{s['amount']} amount")
    print()
    print("Top senders by amount:")
    if not r["top_senders_by_amount"]:
        print("  (none)")
    else:
        for s in r["top_senders_by_amount"]:
            print(f"  {s['account']}: {s['amount']} ({pct(s['amount'], r['total_amount'])}), "
                  f"{s['count']} tx")
    print()
    print("Top receivers by count:")
    if not r["top_receivers_by_count"]:
        print("  (none)")
    else:
        for s in r["top_receivers_by_count"]:
            print(f"  {s['account']}: {s['count']} ({pct(s['count'], total)}), "
                  f"{s['amount']} amount")
    print()
    print("Top receivers by amount:")
    if not r["top_receivers_by_amount"]:
        print("  (none)")
    else:
        for s in r["top_receivers_by_amount"]:
            print(f"  {s['account']}: {s['amount']} ({pct(s['amount'], r['total_amount'])}), "
                  f"{s['count']} tx")
    print()
    print(f"Anon involvement: {r['anon_sender_count']} anon senders "
          f"({pct(r['anon_sender_count'], total)}) / "
          f"{r['anon_receiver_count']} anon receivers "
          f"({pct(r['anon_receiver_count'], total)})")

print()
if anom_count == 0:
    print("[OK] No concentration anomalies")
else:
    detail = []
    if "sender_concentration" in anomalies:
        detail.append(
            f"sender_concentration: '{r['top_sender_amt_name']}' = "
            f"{render_pct(r['top_sender_amt_pct_bps'])} of total amount (> 30% threshold)"
        )
    if "receiver_concentration" in anomalies:
        detail.append(
            f"receiver_concentration: '{r['top_receiver_amt_name']}' = "
            f"{render_pct(r['top_receiver_amt_pct_bps'])} of total amount (> 50% — informational)"
        )
    if "mass_dust" in anomalies:
        detail.append(
            f"mass_dust: 2nd-half avg {r['avg_2nd_half']} < 50% of 1st-half avg "
            f"{r['avg_1st_half']} (drop = {render_pct(r['mass_dust_drop_bps'])}; "
            f"{r['first_half_count']}/{r['second_half_count']} tx per half)"
        )
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    for d in detail:
        print(f"  - {d}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_payments_audit: rendering failed" >&2
  exit 1
fi

# ── Step 4: exit-code policy ──────────────────────────────────────────────────
# Pull anomaly count back via Python (JSON envelope holds the canonical list).
# Stash count in a temp file rather than via $(...) command-substitution
# around a heredoc: keeps the parse simple and avoids subtleties with
# nested heredoc terminators inside command substitution.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_payments_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
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
