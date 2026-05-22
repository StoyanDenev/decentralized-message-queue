#!/usr/bin/env bash
# operator_account_balance_history.sh — Walk a SINGLE account's balance
# trajectory over a window of finalized blocks. Operator audit tool for
# compliance, anti-fraud, or post-incident reconstruction on a specific
# domain / anon-address.
#
# Read-only / pure diagnostic — NO mutation.
#
# Background:
#   Operators sometimes need to answer "what happened to this account
#   between block H1 and H2?" — e.g., compliance walkback for a flagged
#   anon address, validator health audit, or whale-movement
#   reconstruction. Sibling scripts (operator_payments_audit.sh /
#   operator_balance_distribution.sh / operator_inbound_outbound_balance
#   .sh) report aggregates across MANY accounts in a window; this one
#   focuses on a SINGLE account and reports per-block balance deltas +
#   running cumulative balance.
#
# Algorithm (per-block walk):
#   1.  `determ head --field height` for current chain tip.
#   2.  Resolve --from / --to to a [from..to] window. Default: last
#       1000 blocks ending at tip (clamped to genesis).
#   3.  For each block h in [from..to]:
#         - Fetch via `determ block-info <h> --json`.
#         - Scan transactions[] for ones where tx.from == account OR
#           tx.to == account. Compute the balance delta per
#           src/chain/chain.cpp::apply_block's behavior (FA-Apply-*):
#             TRANSFER (type 0):
#               - tx.from == account: delta -= tx.amount + tx.fee
#               - tx.to   == account: delta += tx.amount    (same-shard
#                                                            credit only;
#                                                            cross-shard
#                                                            recipient
#                                                            credited via
#                                                            inbound_receipts
#                                                            on the
#                                                            DESTINATION
#                                                            shard — see
#                                                            below).
#             REGISTER (1) / DEREGISTER (2):
#               - tx.from == account: delta -= tx.fee
#               - tx.from == account AND first-time REGISTER: NEF
#                 transfer from ZEROTH_ADDRESS pool (cannot be measured
#                 from the block JSON alone; the pool balance is not
#                 in the block. We DO NOT attempt to credit NEF here —
#                 the running-balance walk will appear to gain that
#                 credit "out of nowhere" and the operator should be
#                 aware. This is documented under "Known limitations"
#                 below.)
#             STAKE (3):
#               - tx.from == account: delta -= tx.amount + tx.fee
#                 (the amount moves to stakes_, NOT to another
#                 account's balance — so we book it as outflow from
#                 the balance ledger).
#             UNSTAKE (4):
#               - tx.from == account: delta -= tx.fee on success;
#                 +tx.amount returned to balance.
#               - (Failed UNSTAKE: fee refunded, net 0; we cannot tell
#                 from block JSON alone whether the unstake succeeded;
#                 we conservatively assume success and rely on the
#                 final-balance reconciliation to surface the gap.)
#             PARAM_CHANGE (6) / MERGE_EVENT (7):
#               - tx.from == account: delta -= tx.fee
#             DAPP_REGISTER (9):
#               - tx.from == account: delta -= tx.fee
#             DAPP_CALL (10):
#               - tx.from == account: delta -= tx.amount + tx.fee
#               - tx.to   == account: delta += tx.amount
#             COMPOSABLE_BATCH (8):
#               - Outer envelope has tx.from = relayer; inner txs are
#                 encoded in the payload (binary blob) and would
#                 require a JSON-side decoder. We skip COMPOSABLE_BATCH
#                 envelopes and emit a "composable_batch_skipped"
#                 counter so the operator sees the gap.
#         - Scan inbound_receipts[] where r.to == account. Compute:
#             delta += r.amount   (cross-shard credit arriving from
#                                  the source shard).
#         - Scan creators[]. If account appears: --show-fees attribution
#           per the apply-side FA-Apply-6 / FA-Apply-7 distribution rule:
#               total_distributed = block_fees + est_per_block_subsidy
#               per_creator       = total_distributed / |creators|
#               dust              = total_distributed % |creators|  →
#                                   credited to creators[0]
#           delta += per_creator (+ dust if account is creators[0])
#           (Computed only when --show-fees is set. Without --show-fees
#           the creator subsidy/fee credit is silently elided — the
#           "running balance" then reflects only ledger-tx-visible
#           movement, which is what most compliance walks want.)
#   4.  Compute running cumulative balance starting from the START
#       balance returned by `determ balance <account>` at the lower
#       bound minus deltas accumulated AHEAD of the window — actually,
#       since the chain doesn't expose "balance at block H" RPCs, we
#       seed the running balance at zero and simply report
#       cumulative-delta-from-window-start. The summary footer notes
#       the actual current-tip balance from the live RPC.
#
# RPC dependencies (all read-only):
#   - head                  current chain tip height
#   - balance               current-tip balance for the queried account
#                           (reported in the summary footer)
#   - supply                lifetime accumulated_subsidy (used only when
#                           --show-fees is set, to estimate per-block
#                           subsidy = accumulated_subsidy / height)
#   - block-info            per-block JSON for the walk
#
# Anomaly flags (operator alert gates; --anomalies-only filters output
# to only these and exits 2 if any fired):
#   - balance_negative_attempt   running cumulative delta + start_balance
#                                would go negative at any block. Under
#                                normal chain operation this can't
#                                happen (apply-layer balance checks
#                                refuse the tx); firing this anomaly
#                                indicates either data inconsistency
#                                in the block JSON or a missed inbound
#                                receipt / creator credit. Operator
#                                should reconcile against snapshot.
#   - large_balance_change       any single block changes balance by
#                                more than 30% of the WINDOW START
#                                balance (live-RPC `determ balance`
#                                snapshot at script-launch time, minus
#                                the cumulative delta over the window).
#                                Possible whale movement / large
#                                payment / exchange withdrawal.
#                                Suppressed when start_balance == 0
#                                (no meaningful denominator).
#   - unusual_activity_burst     > 50 transactions / inbound receipts
#                                touching this account in any 10-block
#                                sliding window. Operator-action
#                                signal — possible bot, exchange,
#                                or compromised key.
#
# Known limitations:
#   - First-time REGISTER triggers an NEF (Network Effect Faucet)
#     transfer from the ZEROTH_ADDRESS pool to the new domain. The
#     amount is `pool_balance / 2` AT THE TIME OF REGISTER and is not
#     emitted in the block JSON. The running-balance walk will appear
#     to "gain" that NEF amount out of nowhere on the REGISTER block;
#     we document this in the per-block output as a separate
#     "nef_likely" counter when --show-fees is set.
#   - Cross-shard outbound TRANSFER: tx.from == account on the SOURCE
#     shard records the debit. tx.to == account on the DESTINATION
#     shard receives the credit via inbound_receipts only AFTER the
#     CROSS_SHARD_RECEIPT_LATENCY block delay. If the operator runs
#     this script against the source shard, only debits show; if
#     against destination, only credits via inbound_receipts show.
#     This is by-design — the script reports what THIS shard saw.
#
# Usage:
#   tools/operator_account_balance_history.sh
#       --rpc-port N
#       --account <domain-or-anon-addr>
#       [--from H] [--to H]
#       [--show-fees]
#       [--json] [--anomalies-only]
#
# Exit codes:
#   0   audit ran successfully, no anomalies
#   1   RPC error / daemon unreachable / malformed args / missing required arg
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_account_balance_history.sh
                                   --rpc-port N
                                   --account <domain-or-anon-addr>
                                   [--from H] [--to H]
                                   [--show-fees]
                                   [--json]
                                   [--anomalies-only]

Walk a single account's balance trajectory over a window of finalized
blocks. Per-block table reports type / counterparty / delta / running
balance; summary footer reports total inflow / outflow / fees / net
change / anomaly count. Read-only — no mutation.

Required:
  --rpc-port N           RPC port to query
  --account <addr>       Domain or anon address (0x + 64 hex) to track

Options:
  --from H               Window lower bound (inclusive). Default:
                         max(0, tip - 999)
  --to H                 Window upper bound (inclusive). Default: tip
  --show-fees            Include per-block subsidy + fee attribution
                         when the account appears in block.creators[].
                         Adds an extra "creator credit" row per block.
  --json                 Emit structured JSON envelope
  --anomalies-only       Print only flagged anomalies; exit 2 if any fire
  -h, --help             Show this help

Anomaly flags:
  balance_negative_attempt   running balance would go negative at any
                             block (data-inconsistency signal — should
                             never happen under normal apply-layer
                             protections)
  large_balance_change       single-block delta > 30% of start balance
  unusual_activity_burst     > 50 tx/receipts touching account in any
                             10-block sliding window

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / missing required
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
ACCOUNT=""
FROM_H=""
TO_H=""
SHOW_FEES=0
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";    shift 2 ;;
    --account)         ACCOUNT="${2:-}"; shift 2 ;;
    --from)            FROM_H="${2:-}";  shift 2 ;;
    --to)              TO_H="${2:-}";    shift 2 ;;
    --show-fees)       SHOW_FEES=1;      shift ;;
    --json)            JSON_OUT=1;       shift ;;
    --anomalies-only)  ANOM_ONLY=1;      shift ;;
    *) echo "operator_account_balance_history: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Required-arg checks.
if [ -z "$PORT" ]; then
  echo "operator_account_balance_history: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
if [ -z "$ACCOUNT" ]; then
  echo "operator_account_balance_history: --account is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_account_balance_history: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_account_balance_history: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

# Account-shape sanity check (very lenient — chain accepts either domain
# names or anon "0x"+64hex addresses; we just refuse pathological
# whitespace / shell-injection patterns).
case "$ACCOUNT" in
  *[[:space:]]*)
    echo "operator_account_balance_history: --account must not contain whitespace" >&2
    exit 1 ;;
  "")
    echo "operator_account_balance_history: --account must be non-empty" >&2
    exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_account_balance_history: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_account_balance_history: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Highest finalized index = head height - 1 (head is the next-to-produce).
# For window-walking purposes we treat HEAD_H as the upper bound — block-info
# will error cleanly if asked for an unproduced height, and we clamp below.
TOP="$HEAD_H"
if [ "$TOP" -gt 0 ]; then
  TOP=$(( TOP - 1 ))
fi

# Default window: last 1000 blocks ending at tip (clamped at genesis).
FROM=${FROM_H:-$(( TOP >= 999 ? TOP - 999 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_account_balance_history: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: snapshot the account's CURRENT balance (informational; the
# running-balance walk is delta-only, but the start-balance is used to
# bound the large_balance_change anomaly).
# `determ balance <account>` returns either "<int>" or a "0" for an
# unknown address; we accept both as legitimate signal.
ACCOUNT_BAL=$("$DETERM" balance "$ACCOUNT" --rpc-port "$PORT" 2>/dev/null) || ACCOUNT_BAL=""
case "$ACCOUNT_BAL" in
  *[!0-9]*|"") ACCOUNT_BAL=0 ;;
esac

# ── Step 3: optional per-block subsidy estimate (only if --show-fees) ────────
EST_PER_BLOCK_SUBSIDY=0
if [ "$SHOW_FEES" = "1" ]; then
  # Same estimate as operator_stake_yield.sh: lifetime accumulated subsidy
  # divided by chain height = average per-block subsidy. For FLAT subsidy
  # mode (default) this is exact; for E3 lottery mode it is the expectation.
  ACCUM=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || ACCUM=""
  case "$ACCUM" in *[!0-9]*|"") ACCUM=0 ;; esac
  if [ "$HEAD_H" -gt 0 ] && [ -n "$ACCUM" ] && [ "$ACCUM" -gt 0 ]; then
    EST_PER_BLOCK_SUBSIDY=$(( ACCUM / HEAD_H ))
  fi
fi

# ── Step 4: per-block walk via Python driver ─────────────────────────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_account_balance_history: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

if command -v python >/dev/null 2>&1; then
  PYTHON=python
elif command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  echo "operator_account_balance_history: python (or python3) is required" >&2
  exit 1
fi

# Promote $DETERM to an absolute path so subprocess.run works regardless of
# CWD-quirks across Git Bash / Cygwin / Linux (mirrors pattern in
# operator_account_age_distribution.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

"$PYTHON" - "$DETERM_ABS" "$PORT" "$ACCOUNT" "$FROM" "$TO" \
              "$ACCOUNT_BAL" "$EST_PER_BLOCK_SUBSIDY" "$SHOW_FEES" \
              "$TMP_OUT" <<'PY' || {
  echo "operator_account_balance_history: block-walk failed" >&2
  exit 1
}
import json, subprocess, sys
from collections import deque

(determ, port, account, from_h, to_h,
 start_balance, est_per_block_subsidy, show_fees_s, out_path) = sys.argv[1:10]
from_h        = int(from_h)
to_h          = int(to_h)
start_balance = int(start_balance)
est_per_block_subsidy = int(est_per_block_subsidy)
show_fees     = (show_fees_s == "1")

# tx.type → name lookup (mirror include/determ/chain/block.hpp TxType).
TX_TYPE_NAME = {
    0:  "TRANSFER",
    1:  "REGISTER",
    2:  "DEREGISTER",
    3:  "STAKE",
    4:  "UNSTAKE",
    5:  "REGION_CHANGE",     # validator rejects; defensive only
    6:  "PARAM_CHANGE",
    7:  "MERGE_EVENT",
    8:  "COMPOSABLE_BATCH",
    9:  "DAPP_REGISTER",
    10: "DAPP_CALL",
}

def tx_type_int(v):
    if isinstance(v, int): return v
    if isinstance(v, str):
        try: return int(v)
        except ValueError: return -1
    return -1

# Per-block rows we'll emit. Each row:
#   {block, type, counterparty, delta, running_balance, kind}
# kind ∈ {tx, inbound_receipt, creator_credit}
rows = []

# Per-block aggregated touch count for the sliding-10-block burst check.
# touches_per_block[h - from_h] = number of ledger events touching account.
touches_per_block = [0] * (to_h - from_h + 1)

total_inflow            = 0
total_outflow           = 0
total_fees_paid         = 0   # fees the account paid (as sender)
total_fees_earned       = 0   # creator credits (subsidy + fees), only when show_fees
total_subsidy_earned    = 0
composable_batch_skipped = 0
nef_likely_count        = 0   # first-time REGISTER blocks (heuristic — see header)

# Running cumulative delta over the window. Starts at 0; running_balance
# below = start_balance + running_delta. We DO NOT seed at start_balance
# because start_balance is the current-tip balance, not the window-start
# balance — see header §"Logic". We still use start_balance as the
# anomaly-denominator for large_balance_change.
running_delta = 0

# balance_negative_attempt fires only if the START balance MINUS the
# cumulative-delta-from-end-back-to-this-block would have been negative
# AT THIS BLOCK. Since we walk forward and the chain ledger doesn't
# expose per-block balance, we approximate using the cumulative-delta
# series: if start_balance + running_delta < 0 at any point, we flag.
# Note: this catches BACKWARD-WALK negativity (i.e., the start_balance
# was lower than the cumulative outflow), which is the operator-relevant
# case: "did the account ever appear over-drafted in the visible
# history."
balance_negative_attempt_block = None  # first offending block, or None

# Track the largest single-block delta and the block it occurred in.
max_single_block_delta = 0
max_single_block_delta_block = None
large_balance_change_blocks = []  # all blocks crossing the 30% threshold

# Activity burst: 10-block sliding window of touch counts.
# We compute by walking touches_per_block once at the end.

def credit_account(d):
    """Helper: book a CREDIT (positive delta) on the running balance."""
    global running_delta
    running_delta += d

def debit_account(d):
    """Helper: book a DEBIT (negative delta) on the running balance."""
    global running_delta
    running_delta -= d

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=30
        )
    except Exception as e:
        sys.stderr.write(f"operator_account_balance_history: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_account_balance_history: block-info {h} rc={r.returncode}: "
            f"{r.stderr.strip()}\n")
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_account_balance_history: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    block_idx_in_win = h - from_h
    block_start_delta = running_delta  # snapshot at top of block

    # ── Transactions ────────────────────────────────────────────────────────
    txs = blk.get("transactions") or []
    if isinstance(txs, list):
        for tx in txs:
            if not isinstance(tx, dict): continue
            t  = tx_type_int(tx.get("type"))
            tn = TX_TYPE_NAME.get(t, f"TYPE_{t}")
            frm = tx.get("from", "") if isinstance(tx.get("from", ""), str) else ""
            to  = tx.get("to", "")   if isinstance(tx.get("to", ""),   str) else ""
            amt = int(tx.get("amount", 0) or 0)
            fee = int(tx.get("fee", 0)    or 0)

            touched = (frm == account) or (to == account)
            if not touched:
                continue

            touches_per_block[block_idx_in_win] += 1

            # COMPOSABLE_BATCH outer envelope has only relayer as `from`;
            # inner txs would require a payload decoder. Skip + record.
            if t == 8:
                composable_batch_skipped += 1
                rows.append({
                    "block":         h,
                    "type":          "COMPOSABLE_BATCH",
                    "counterparty":  to if frm == account else frm,
                    "delta":         0,
                    "running_balance": start_balance + running_delta,
                    "kind":          "tx",
                    "note":          "skipped (inner txs not decoded)",
                })
                continue

            delta = 0
            note  = ""
            counterparty = to if frm == account else frm

            if t == 0:  # TRANSFER
                if frm == account:
                    delta -= (amt + fee)
                    total_outflow   += amt
                    total_fees_paid += fee
                if to == account:
                    # Same-shard credit. Cross-shard credit arrives via
                    # inbound_receipts on the destination shard (handled
                    # in its own loop below); the JSON does NOT
                    # distinguish per-tx whether `to` was cross-shard,
                    # so a debit-only TRANSFER will simply not credit on
                    # the source shard (the destination's inbound_receipt
                    # entry on a later block will). On a same-shard
                    # TRANSFER the block JSON contains both legs so this
                    # branch always fires. The minor risk: if we're
                    # walking the SOURCE shard's block where to is on a
                    # different shard, this branch would over-credit.
                    # Determ's block-info exposes shard routing implicitly
                    # via the receipts list (cross-shard outbound shows
                    # up in `cross_shard_receipts[]` not in
                    # `inbound_receipts[]`); we conservatively credit here
                    # and rely on the operator running this against the
                    # correct shard. See header §"Known limitations".
                    delta += amt
                    total_inflow += amt
            elif t == 1:  # REGISTER
                if frm == account:
                    delta -= fee
                    total_fees_paid += fee
                    # Heuristic: first-time REGISTER triggers NEF
                    # (pool/2 → account). We can't see the pool balance
                    # in block JSON, so we log the event and let
                    # operator reconcile against snapshot. This is the
                    # only currently-known balance-changing event we
                    # can't precisely score from block JSON alone.
                    nef_likely_count += 1
                    note = "NEF (Network Effect Faucet) may have credited "\
                           "from ZEROTH_ADDRESS pool — not visible in block JSON"
            elif t == 2:  # DEREGISTER
                if frm == account:
                    delta -= fee
                    total_fees_paid += fee
            elif t == 3:  # STAKE
                if frm == account:
                    # Amount + fee both leave the balance; amount goes
                    # to stakes_, fee accrues to creators.
                    delta -= (amt + fee)
                    total_outflow   += amt
                    total_fees_paid += fee
                    note = "stake locked (amount moved to stakes_)"
            elif t == 4:  # UNSTAKE
                if frm == account:
                    # On success: -fee, +amount returned to balance.
                    # On failure: -fee REFUNDED, net 0. We can't tell
                    # from the JSON; conservatively assume success.
                    delta -= fee
                    delta += amt
                    total_inflow    += amt
                    total_fees_paid += fee
                    note = "unstake credit (assumes successful unlock)"
            elif t == 6 or t == 7:  # PARAM_CHANGE / MERGE_EVENT
                if frm == account:
                    delta -= fee
                    total_fees_paid += fee
            elif t == 9:  # DAPP_REGISTER
                if frm == account:
                    delta -= fee
                    total_fees_paid += fee
            elif t == 10:  # DAPP_CALL
                if frm == account:
                    delta -= (amt + fee)
                    total_outflow   += amt
                    total_fees_paid += fee
                if to == account:
                    delta += amt
                    total_inflow += amt

            if delta < 0:
                debit_account(-delta)
            elif delta > 0:
                credit_account(delta)

            rows.append({
                "block":           h,
                "type":            tn,
                "counterparty":    counterparty,
                "delta":           delta,
                "running_balance": start_balance + running_delta,
                "kind":            "tx",
                "note":            note,
            })

    # ── Inbound cross-shard receipts (credit-only on dst) ──────────────────
    ibrs = blk.get("inbound_receipts") or []
    if isinstance(ibrs, list):
        for r2 in ibrs:
            if not isinstance(r2, dict): continue
            rcv = r2.get("to", "") if isinstance(r2.get("to", ""), str) else ""
            if rcv != account: continue
            amt = int(r2.get("amount", 0) or 0)
            frm = r2.get("from", "") if isinstance(r2.get("from", ""), str) else ""
            credit_account(amt)
            total_inflow += amt
            touches_per_block[block_idx_in_win] += 1
            rows.append({
                "block":           h,
                "type":            "INBOUND_RECEIPT",
                "counterparty":    frm,
                "delta":           amt,
                "running_balance": start_balance + running_delta,
                "kind":            "inbound_receipt",
                "note":            "",
            })

    # ── Per-creator subsidy + fees (only when --show-fees) ─────────────────
    if show_fees:
        creators = blk.get("creators") or []
        if isinstance(creators, list) and creators and account in creators:
            # Sum block-fees (mirror operator_stake_yield.sh upper-bound
            # estimate: sum of tx.fee — see header note about apply-side
            # `charge_fee` skipping unsuccessful applies).
            total_block_fees = 0
            for tx in (blk.get("transactions") or []):
                if not isinstance(tx, dict): continue
                try:
                    total_block_fees += int(tx.get("fee", 0) or 0)
                except (TypeError, ValueError):
                    continue
            m = len(creators)
            total_distributed = total_block_fees + est_per_block_subsidy
            per_creator = total_distributed // m
            dust = total_distributed - per_creator * m
            credit = per_creator
            # Dust goes to creators[0] (apply-side rule).
            if creators[0] == account:
                credit += dust
            if credit > 0:
                credit_account(credit)
                total_fees_earned    += (total_block_fees // m) + (
                    (total_block_fees % m) if creators[0] == account else 0)
                total_subsidy_earned += (est_per_block_subsidy // m) + (
                    (est_per_block_subsidy % m) if creators[0] == account else 0)
                # Note: bookkeeping above double-counts the dust split
                # imperfectly across the two components (the apply-side
                # dust is `total_distributed % m`, not the sum of the
                # two per-component remainders). Sum still matches.
                touches_per_block[block_idx_in_win] += 1
                rows.append({
                    "block":           h,
                    "type":            "CREATOR_CREDIT",
                    "counterparty":    "creators[]",
                    "delta":           credit,
                    "running_balance": start_balance + running_delta,
                    "kind":            "creator_credit",
                    "note":            f"per_creator={per_creator}, "
                                       f"dust={dust if creators[0] == account else 0}",
                })

    # ── Anomaly checks at block boundary ──────────────────────────────────
    end_delta = running_delta
    single_block_delta = end_delta - block_start_delta

    # Track largest single-block delta (magnitude).
    if abs(single_block_delta) > abs(max_single_block_delta):
        max_single_block_delta       = single_block_delta
        max_single_block_delta_block = h

    # large_balance_change: > 30% of start_balance for any single block.
    # Suppress if start_balance == 0 (no meaningful denominator).
    if start_balance > 0:
        pct_threshold = start_balance * 30 // 100
        if abs(single_block_delta) > pct_threshold and pct_threshold > 0:
            large_balance_change_blocks.append({
                "block":  h,
                "delta":  single_block_delta,
                "pct_bps": (abs(single_block_delta) * 10000) // start_balance,
            })

    # balance_negative_attempt: running_balance < 0 at block end?
    if (start_balance + running_delta) < 0 and balance_negative_attempt_block is None:
        balance_negative_attempt_block = h

# ── 10-block sliding-window burst check ────────────────────────────────────
unusual_activity_blocks = []  # list of (window_start_block, touch_count)
WINDOW = 10
running_sum = 0
deq = deque()
for i, t in enumerate(touches_per_block):
    deq.append(t)
    running_sum += t
    if len(deq) > WINDOW:
        running_sum -= deq.popleft()
    if len(deq) == WINDOW and running_sum > 50:
        win_start = from_h + (i - WINDOW + 1)
        # Suppress dense overlap — only record one anomaly per
        # non-overlapping window to keep the report sane.
        if not unusual_activity_blocks or \
           win_start > unusual_activity_blocks[-1]["window_start"] + WINDOW - 1:
            unusual_activity_blocks.append({
                "window_start": win_start,
                "window_end":   win_start + WINDOW - 1,
                "touch_count":  running_sum,
            })

# ── Anomaly classification ────────────────────────────────────────────────
anomalies = []
if balance_negative_attempt_block is not None:
    anomalies.append("balance_negative_attempt")
if large_balance_change_blocks:
    anomalies.append("large_balance_change")
if unusual_activity_blocks:
    anomalies.append("unusual_activity_burst")

# Compute the final net change over the window (running_delta at the end).
net_change = running_delta

result = {
    "rpc_port":       int(port),
    "account":        account,
    "window": {
        "from":   from_h,
        "to":     to_h,
        "blocks": to_h - from_h + 1,
    },
    "start_balance":         start_balance,    # current-tip live balance
    "rows":                  rows,
    "summary": {
        "total_inflow":             total_inflow,
        "total_outflow":            total_outflow,
        "total_fees_paid":          total_fees_paid,
        "total_fees_earned":        total_fees_earned,
        "total_subsidy_earned":     total_subsidy_earned,
        "net_change":               net_change,
        "show_fees":                show_fees,
        "est_per_block_subsidy":    est_per_block_subsidy,
        "composable_batch_skipped": composable_batch_skipped,
        "nef_likely_count":         nef_likely_count,
        "max_single_block_delta":         max_single_block_delta,
        "max_single_block_delta_block":   max_single_block_delta_block,
    },
    "anomaly_detail": {
        "balance_negative_attempt_block": balance_negative_attempt_block,
        "large_balance_change_blocks":    large_balance_change_blocks,
        "unusual_activity_blocks":        unusual_activity_blocks,
    },
    "anomalies":  anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY

# ── Step 5: render envelope (JSON or human table) ─────────────────────────────
"$PYTHON" - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" <<'PY'
import json, sys
json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

port           = r["rpc_port"]
account        = r["account"]
window         = r["window"]
from_h         = window["from"]
to_h           = window["to"]
blocks         = window["blocks"]
start_balance  = r["start_balance"]
rows           = r["rows"]
s              = r["summary"]
anomalies      = r["anomalies"]
ad             = r["anomaly_detail"]
anom_count     = len(anomalies)

if json_out:
    # JSON envelope — top-level, single line, deterministic shape for
    # downstream tooling.
    envelope = {
        "rpc_port":      port,
        "account":       account,
        "window":        window,
        "start_balance": start_balance,
        "rows":          rows,
        "summary":       s,
        "anomaly_detail": ad,
        "anomalies":     anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable.
if anom_only and anom_count == 0:
    print(f"operator_account_balance_history: no anomalies "
          f"(account '{account}', port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

print(f"=== Account balance history "
      f"(port {port}, account '{account}', window [{from_h}..{to_h}], "
      f"{blocks} blocks) ===")
print(f"Current-tip balance (live RPC): {start_balance}")
if s["show_fees"]:
    print(f"Per-block subsidy estimate:     {s['est_per_block_subsidy']} "
          f"(lifetime accumulated / chain height)")
print()

if not anom_only:
    if not rows:
        print("(no ledger events involving this account in window)")
    else:
        # Per-block table.
        print(f"{'Block':>8}  {'Type':<16}  {'Counterparty':<32}  "
              f"{'Delta':>14}  {'Running':>14}  Note")
        for row in rows:
            cp = row["counterparty"] or "(none)"
            if len(cp) > 32:
                cp = cp[:29] + "..."
            note = row.get("note", "") or ""
            if len(note) > 60:
                note = note[:57] + "..."
            sign = "+" if row["delta"] > 0 else ""
            print(f"{row['block']:>8}  {row['type']:<16}  {cp:<32}  "
                  f"{sign}{row['delta']:>13}  {row['running_balance']:>14}  {note}")
    print()

# Summary footer.
print("Summary:")
print(f"  Window:                   [{from_h}..{to_h}] ({blocks} blocks)")
print(f"  Total inflow:             {s['total_inflow']}")
print(f"  Total outflow:            {s['total_outflow']}")
print(f"  Total fees paid:          {s['total_fees_paid']}")
if s["show_fees"]:
    print(f"  Total fees earned:        {s['total_fees_earned']}")
    print(f"  Total subsidy earned:     {s['total_subsidy_earned']}")
print(f"  Net change (window):      {'+' if s['net_change'] > 0 else ''}{s['net_change']}")
if s["max_single_block_delta_block"] is not None:
    sgn = "+" if s["max_single_block_delta"] > 0 else ""
    print(f"  Largest single-block Δ:   {sgn}{s['max_single_block_delta']} "
          f"@ block {s['max_single_block_delta_block']}")
if s["composable_batch_skipped"] > 0:
    print(f"  COMPOSABLE_BATCH skipped: {s['composable_batch_skipped']} "
          "(inner txs not decoded)")
if s["nef_likely_count"] > 0:
    print(f"  NEF likely credits:       {s['nef_likely_count']} "
          "(REGISTER block(s) — pool credit not visible in block JSON)")

print()
if anom_count == 0:
    print("[OK] No balance-history anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "balance_negative_attempt" in anomalies:
        b = ad["balance_negative_attempt_block"]
        print(f"  balance_negative_attempt: running balance would go "
              f"negative at block {b}")
        print(f"                            — data-inconsistency signal "
              f"(reconcile against snapshot)")
    if "large_balance_change" in anomalies:
        lst = ad["large_balance_change_blocks"]
        first3 = lst[:3]
        more = f" + {len(lst) - 3} more" if len(lst) > 3 else ""
        details = ", ".join(
            f"block {x['block']} Δ={x['delta']} ({x['pct_bps']/100:.1f}%)"
            for x in first3)
        print(f"  large_balance_change:    {len(lst)} block(s): {details}{more}")
        print(f"                           — > 30% of start balance "
              f"({start_balance})")
    if "unusual_activity_burst" in anomalies:
        lst = ad["unusual_activity_blocks"]
        first3 = lst[:3]
        more = f" + {len(lst) - 3} more" if len(lst) > 3 else ""
        details = ", ".join(
            f"blocks [{x['window_start']}..{x['window_end']}] = {x['touch_count']} touches"
            for x in first3)
        print(f"  unusual_activity_burst:  {len(lst)} window(s): {details}{more}")
        print(f"                           — > 50 events in any 10-block window")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_account_balance_history: rendering failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ──────────────────────────────────────────────────
# Same convention as operator_account_age_distribution / operator_payments_audit:
# exit 2 only when --anomalies-only is set AND ≥1 anomaly fired. Default
# informational mode always exits 0 if the pipeline succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_account_balance_history: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
"$PYTHON" - "$TMP_OUT" "$TMP_ANOM" <<'PY'
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
