#!/usr/bin/env bash
# operator_account_age_distribution.sh — Audit the age distribution of
# every account in a running determ daemon's state, bucketed by inferred
# creation-block height. Intended as a state-bloat / Sybil-onboarding-
# burst diagnostic.
#
# Read-only / pure diagnostic — NO mutation.
#
# Background:
#   Determ's chain state includes a per-account map
#     accounts_[domain] -> AccountState (balance, next_nonce, ...).
#   Accounts are auto-created via one of the I-4 channels (TRANSFER
#   credit on receipt, REGISTER, DEREGISTER non-registrant flow,
#   inbound cross-shard receipt destination, per-creator subsidy,
#   DAPP_CALL credit — see docs/proofs/AccountStateInvariants.md).
#   Once created, accounts persist forever; there is no GC pass.
#   Operator concern: account count grows without bound. This script
#   surfaces the age skew so an operator can answer "are we accruing
#   dust faster than we should be?" / "did we just see an onboarding
#   spike?" without pulling raw block dumps.
#
# Why "infer" the creation block:
#   The chain does not preserve a per-account creation height — the
#   accounts_ map stores (balance, next_nonce) only. We approximate
#   "creation block" by walking the chain history backwards from head
#   and recording the FIRST block in which each currently-extant
#   account appears as the destination of an I-4 channel (TRANSFER
#   recipient, REGISTER actor, DEREGISTER actor, inbound receipt
#   destination, DAPP_CALL recipient, or per-creator subsidy slot —
#   matching operator_account_growth.sh's I-4 attribution).
#
#   Limitation: the walk is bounded by --max-walk-blocks (default
#   10000). Accounts that exist in current state but were created
#   before that window are bucketed as "older than --max-walk-blocks"
#   — the audit cannot precisely date them without re-running with a
#   larger window. The historical_account_dominance anomaly flag
#   surfaces when that bucket is dominant (> 80% of total accounts).
#
# Sibling-script contrast (avoid overlap):
#   operator_account_growth.sh        Tracks per-window growth + by-source
#                                     breakdown over a SHORT, recent
#                                     window. Doesn't bucket by age.
#   operator_orphan_account_scan.sh   Looks for dormant orphan accounts
#                                     (balance ≤ 0, no recent activity).
#                                     Doesn't bucket by age.
#   operator_balance_distribution.sh  Wealth-distribution + Gini. Doesn't
#                                     bucket by age.
#   operator_account_age_distribution THIS — every account in current
#                                     state bucketed by inferred creation-
#                                     block height; per-bucket count +
#                                     descriptive balance stats; summary
#                                     percentiles + long-tail fraction +
#                                     state-bloat anomaly classification.
#
# Pipeline (read-only RPC):
#   1.  `determ chain-summary --json` for the chain tip height H.
#   2.  `determ snapshot create --out <tmp>` for the full account set
#       (accounts_[domain] entries → the population we're aging). The
#       snapshot is the canonical enumeration; the lighter
#       `snapshot stats --json` returns counts only.
#   3.  Walk [max(0, H - max_walk_blocks), H] via `block-info <h> --json`,
#       low-to-high so the FIRST observation per account wins. For each
#       block, scan transactions (tx.to for TRANSFER/DAPP_CALL, tx.from
#       for REGISTER/DEREGISTER/DAPP_REGISTER), inbound_receipts (.to),
#       and creators (per-creator subsidy slot). An account appearing
#       on any of these channels is credited with that block as
#       first_seen, then never overwritten.
#   4.  For each account in current state:
#         - if first_seen is set → bucketize by age = (H - first_seen)
#         - if first_seen is unset → bucket "older than --max-walk-blocks"
#       Each bucket aggregates: count, total_balance, mean_balance,
#       max_balance.
#   5.  Compute summary stats over the per-account age list (accounts
#       with first_seen known): median age in blocks, p90, p99,
#       oldest-known-account creation block, fraction of accounts
#       older than 50% of chain age (the "long-tail" fraction).
#
# Anomaly flags (each adds to anomalies[]; --anomalies-only exits 2):
#   - recent_account_burst       > 100 accounts whose first_seen falls
#                                in the last 100 blocks (Sybil-onboarding
#                                burst signal; pair with
#                                operator_stake_concentration.sh /
#                                operator_payments_audit.sh).
#   - account_state_bloat        total account count > 10000 AND
#                                > 50% of accounts have zero balance
#                                AND zero nonce (dust-residue
#                                accumulation — state-prune candidate
#                                identification).
#   - historical_account_dominance
#                                Fraction of accounts older than
#                                --max-walk-blocks > 80%. The chain has
#                                a long tail of old accounts this audit
#                                cannot directly date; recommend re-
#                                running with a larger --max-walk-blocks
#                                if precise ages are needed on those.
#
# RPC dependencies (all read-only):
#   - chain_summary             current chain tip height (the "now"
#                               reference for age calculation)
#   - snapshot create           full state dump → tmp file (the
#                               canonical account-set enumeration)
#   - block                     per-block JSON for the creation-walk
#                               (via `determ block-info <h> --json`)
#
# Usage:
#   tools/operator_account_age_distribution.sh [--rpc-port N]
#                                              [--max-walk-blocks N]
#                                              [--bucket-size-blocks N]
#                                              [--json]
#                                              [--anomalies-only]
#
# Options:
#   --rpc-port N             RPC port to query (default: 8081)
#   --max-walk-blocks N      Bound on the creation-walk window
#                            (default: 10000). Accounts created before
#                            this window are bucketed as "older than
#                            --max-walk-blocks" — see header.
#   --bucket-size-blocks N   Age-bucket width in blocks (default: 1000)
#   --json                   Emit structured JSON envelope
#   --anomalies-only         Print only flagged anomalies; exit 2 if any
#                            fire
#   -h, --help               Show this help
#
# Exit codes (mirrors operator_account_growth / operator_orphan_account_scan):
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / malformed snapshot / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_account_age_distribution.sh [--rpc-port N]
                                            [--max-walk-blocks N]
                                            [--bucket-size-blocks N]
                                            [--json]
                                            [--anomalies-only]

Audit the age distribution of every account in a running determ daemon
by inferring per-account creation block from the chain history. Walks
the chain backwards from head bounded by --max-walk-blocks, records the
first-seen block per account across the six I-4 auto-creation channels
(TRANSFER credit, REGISTER, DEREGISTER, inbound receipt, per-creator
subsidy, DAPP_CALL credit), and buckets every account in current state
by age = (H - first_seen). Accounts created before the walk window are
bucketed as "older than --max-walk-blocks".

Reports per-bucket count + total_balance + mean_balance + max_balance,
plus summary stats (median / p90 / p99 age in blocks, oldest-known
account creation block, fraction of accounts older than 50% of chain
age — the "long-tail" fraction) and anomaly classification.

Pure diagnostic — NO mutation.

Options:
  --rpc-port N             RPC port to query (default: 8081)
  --max-walk-blocks N      Bound on the creation-walk (default: 10000)
  --bucket-size-blocks N   Age-bucket width in blocks (default: 1000)
  --json                   Emit structured JSON envelope
  --anomalies-only         Print only flagged anomalies; exit 2 if any fire
  -h, --help               Show this help

Anomaly flags:
  recent_account_burst         > 100 accounts created in last 100 blocks
  account_state_bloat          > 10000 accounts AND > 50% zero-balance
                               zero-nonce
  historical_account_dominance > 80% of accounts older than walk window

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed snapshot
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=8081
MAX_WALK=10000
BUCKET_SIZE=1000
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-port)             PORT="${2:-}";        shift 2 ;;
    --max-walk-blocks)      MAX_WALK="${2:-}";    shift 2 ;;
    --bucket-size-blocks)   BUCKET_SIZE="${2:-}"; shift 2 ;;
    --json)                 JSON_OUT=1;           shift ;;
    --anomalies-only)       ANOM_ONLY=1;          shift ;;
    *) echo "operator_account_age_distribution: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_account_age_distribution: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$MAX_WALK" in *[!0-9]*|"")
  echo "operator_account_age_distribution: --max-walk-blocks must be a non-negative integer (got '$MAX_WALK')" >&2
  exit 1 ;;
esac
case "$BUCKET_SIZE" in *[!0-9]*|"")
  echo "operator_account_age_distribution: --bucket-size-blocks must be a positive integer (got '$BUCKET_SIZE')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_SIZE" -lt 1 ]; then
  echo "operator_account_age_distribution: --bucket-size-blocks must be >= 1 (got '$BUCKET_SIZE')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote $DETERM to an absolute path so the python subprocess.run call
# below works regardless of CWD-quirks across Git Bash / Cygwin / Linux.
# Same pattern as operator_orphan_account_scan.sh / operator_dapp_inventory.sh.
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve chain tip via chain-summary --json ──────────────────────
# Per task spec: chain-summary --json returns top-level state stats; we
# pull `height` as the H reference. Fallback parser (no jq) covers minimal
# CI environments — chain_summary's height field is always a bare integer.
CHAIN_SUMMARY=$("$DETERM" chain-summary --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_account_age_distribution: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  HEAD_H=$(printf '%s' "$CHAIN_SUMMARY" | jq -r '.height // 0' 2>/dev/null)
else
  HEAD_H=$(printf '%s' "$CHAIN_SUMMARY" | grep -o '"height":[ ]*[0-9]*' | head -1 | sed 's/.*://; s/ //g')
fi
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_account_age_distribution: chain-summary returned non-numeric height ('$HEAD_H', port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: snapshot dump → tmp file (the account-set enumeration) ──────────
TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
  echo "operator_account_age_distribution: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_account_age_distribution: cannot create temp file" >&2;
  rm -f "$TMP_SNAP" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_account_age_distribution: snapshot create failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: creation-walk + bucketize via Python driver ─────────────────────
# We walk the window low-to-high so first-write-wins captures the FIRST
# block in which each currently-extant account appeared. Channels mirror
# operator_account_growth.sh's I-4 attribution (TRANSFER recipient,
# REGISTER/DEREGISTER/DAPP_REGISTER actor, inbound receipt destination,
# per-creator subsidy slot, DAPP_CALL recipient). Accounts in current
# state that the walk never observes are bucketed as "older than the
# walk window" (i.e., they existed before [scan_from, head]). Bucketing
# uses age = (H - first_seen) with integer-floor division by
# --bucket-size-blocks.
python - "$DETERM_ABS" "$PORT" "$TMP_SNAP" "$TMP_OUT" \
        "$HEAD_H" "$MAX_WALK" "$BUCKET_SIZE" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, snap_path, out_path,
 head_h_s, max_walk_s, bucket_size_s) = sys.argv[1:8]
head_h      = int(head_h_s)
max_walk    = int(max_walk_s)
bucket_size = int(bucket_size_s)

# ── Load snapshot (current account set) ─────────────────────────────────────
try:
    with open(snap_path, "r", encoding="utf-8") as f:
        snap = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_account_age_distribution: cannot parse snapshot: {e}\n")
    sys.exit(1)
if not isinstance(snap, dict):
    sys.stderr.write("operator_account_age_distribution: snapshot is not a JSON object\n")
    sys.exit(1)

accounts = {}   # domain -> {balance, next_nonce}
for a in snap.get("accounts", []) or []:
    if not isinstance(a, dict): continue
    d = a.get("domain")
    if isinstance(d, str) and d:
        accounts[d] = {
            "balance":    int(a.get("balance",    0) or 0),
            "next_nonce": int(a.get("next_nonce", 0) or 0),
        }

total_accounts = len(accounts)

# ── tx.type → relevant-side mapping (mirror operator_account_growth.sh) ─────
# Per src/chain/block.hpp:
#   0 TRANSFER, 1 REGISTER, 2 DEREGISTER, 3 STAKE, 4 UNSTAKE,
#   5 REGION_CHANGE, 6 PARAM_CHANGE, 7 MERGE_EVENT, 8 COMPOSABLE_BATCH,
#   9 DAPP_REGISTER, 10 DAPP_CALL
# I-4 auto-creation channels:
#   - tx.to    for TRANSFER (0)  and DAPP_CALL (10)
#   - tx.from  for REGISTER (1), DEREGISTER (2), DAPP_REGISTER (9)
#   - r.to     for every inbound_receipt entry
#   - c        for each creator in block.creators (per-creator subsidy)
# Other tx types (STAKE/UNSTAKE/REGION_CHANGE/PARAM_CHANGE/MERGE_EVENT/
# COMPOSABLE_BATCH inner) reference sender via nonce-bump only on an
# already-registered account; not a creation channel.
def tx_type_int(v):
    if isinstance(v, int): return v
    if isinstance(v, str):
        try: return int(v)
        except ValueError: return -1
    return -1

# ── Walk the window low-to-high; first-seen wins ────────────────────────────
# scan_from = max(0, H - max_walk). Inclusive on both ends. An empty /
# pre-genesis chain (head_h < 1) or --max-walk-blocks 0 skips the walk
# entirely (every account ends up "older than walk window").
if max_walk > 0 and head_h > 0:
    scan_from = head_h - max_walk
    if scan_from < 0:
        scan_from = 0
    scan_to = head_h
else:
    scan_from = None
    scan_to   = None

first_seen = {}  # domain -> first block index where it appeared

def credit(domain, h):
    if not isinstance(domain, str) or not domain:
        return
    # Only credit accounts that currently exist (skip ephemerals / off-state
    # references). Once set, never overwrite — first-seen wins.
    if domain in accounts and domain not in first_seen:
        first_seen[domain] = h

if scan_from is not None and scan_to is not None:
    for h in range(scan_from, scan_to + 1):
        try:
            r = subprocess.run(
                [determ, "block-info", str(h), "--json", "--rpc-port", port],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            sys.stderr.write(f"operator_account_age_distribution: block-info {h} failed: {e}\n")
            sys.exit(1)
        if r.returncode != 0:
            sys.stderr.write(
                f"operator_account_age_distribution: block-info {h} rc={r.returncode}: "
                f"{r.stderr.strip()}\n"
            )
            sys.exit(1)
        try:
            blk = json.loads(r.stdout)
        except Exception:
            sys.stderr.write(f"operator_account_age_distribution: block-info {h} non-JSON\n")
            sys.exit(1)
        if not isinstance(blk, dict):
            continue

        # Per-creator subsidy slot (one of the I-4 channels — see header).
        # Each creator c gets credited at block h iff this is the first
        # block we've observed c in. In steady state creators are
        # REGISTER'd much earlier; this branch matters mostly at genesis
        # or for newly-activated creators whose REGISTER falls in-window.
        creators = blk.get("creators") or []
        if isinstance(creators, list):
            for c in creators:
                credit(c, h)

        txs = blk.get("transactions") or []
        if isinstance(txs, list):
            for tx in txs:
                if not isinstance(tx, dict): continue
                t = tx_type_int(tx.get("type"))
                sender   = tx.get("from", "") if isinstance(tx.get("from", ""), str) else ""
                receiver = tx.get("to", "")   if isinstance(tx.get("to", ""),   str) else ""
                if t == 0:                          # TRANSFER credit
                    credit(receiver, h)
                elif t == 1 or t == 9:              # REGISTER / DAPP_REGISTER
                    credit(sender, h)
                elif t == 2:                        # DEREGISTER non-registrant
                    credit(sender, h)
                elif t == 10:                       # DAPP_CALL credit
                    credit(receiver, h)
                # Other tx types: sender is already-registered, not an
                # I-4 channel — skip.

        ibrs = blk.get("inbound_receipts") or []
        if isinstance(ibrs, list):
            for r2 in ibrs:
                if not isinstance(r2, dict): continue
                to = r2.get("to", "") if isinstance(r2.get("to", ""), str) else ""
                credit(to, h)

# ── Bucketize ───────────────────────────────────────────────────────────────
# age = head_h - first_seen ≥ 0. Bucket index = age // bucket_size.
# Accounts without first_seen → "older than walk window" sentinel bucket.
# Each bucket aggregates (count, total_balance, max_balance), plus we
# track zero-balance/zero-nonce accounts globally for the
# account_state_bloat anomaly.
buckets = defaultdict(lambda: {"count": 0, "total_balance": 0, "max_balance": 0})
older_than_walk = {"count": 0, "total_balance": 0, "max_balance": 0}
ages = []        # per-account ages for percentile computation (walk-known)
oldest_known = None  # min first_seen across all known accounts
zero_balance_zero_nonce = 0

# Recent burst counter: accounts with first_seen >= (head_h - 100).
# A 100-block sliding window is the spec-mandated threshold; an account
# created in [head_h - 99, head_h] inclusive counts toward the burst.
recent_burst_floor = head_h - 99 if head_h >= 99 else 0
recent_burst_count = 0

for d, a in accounts.items():
    bal = a["balance"]; nonce = a["next_nonce"]
    if bal == 0 and nonce == 0:
        zero_balance_zero_nonce += 1
    if d in first_seen:
        fs = first_seen[d]
        if oldest_known is None or fs < oldest_known:
            oldest_known = fs
        age = head_h - fs
        if age < 0:
            age = 0
        ages.append(age)
        if fs >= recent_burst_floor:
            recent_burst_count += 1
        bidx = age // bucket_size
        b = buckets[bidx]
        b["count"]         += 1
        b["total_balance"] += bal
        if bal > b["max_balance"]:
            b["max_balance"] = bal
    else:
        # Older than walk window.
        older_than_walk["count"]         += 1
        older_than_walk["total_balance"] += bal
        if bal > older_than_walk["max_balance"]:
            older_than_walk["max_balance"] = bal

# Convert bucket dict to a sorted list (ascending by bidx).
# age_low  = bidx * bucket_size   (inclusive)
# age_high = (bidx + 1) * bucket_size - 1   (inclusive)
# An additional "older_than_walk_window" pseudo-bucket with age_low =
# (max_walk + 1) is appended only if it has any members.
bucket_list = []
for bidx in sorted(buckets.keys()):
    b = buckets[bidx]
    cnt = b["count"]
    age_low  = bidx * bucket_size
    age_high = (bidx + 1) * bucket_size - 1
    mean_bal = (b["total_balance"] // cnt) if cnt > 0 else 0
    bucket_list.append({
        "age_low":       age_low,
        "age_high":      age_high,
        "count":         cnt,
        "total_balance": b["total_balance"],
        "mean_balance":  mean_bal,
        "max_balance":   b["max_balance"],
    })
# Pseudo-bucket for the "older than walk window" cohort. We emit the
# lower bound as (max_walk + 1) so it sorts after every real bucket
# and signals "ages of these accounts are not bounded by the walk."
if older_than_walk["count"] > 0:
    cnt = older_than_walk["count"]
    mean_bal = older_than_walk["total_balance"] // cnt
    bucket_list.append({
        "age_low":       max_walk + 1 if max_walk > 0 else 0,
        "age_high":      None,  # unbounded
        "count":         cnt,
        "total_balance": older_than_walk["total_balance"],
        "mean_balance":  mean_bal,
        "max_balance":   older_than_walk["max_balance"],
    })

# ── Summary statistics (operate on the walk-known ages) ─────────────────────
# Percentiles use the standard nearest-rank definition (1-indexed):
#   p-th = sorted_ages[ceil(p/100 * n) - 1]
# floor(1) on the rank guards against a 0-rank corner.
def nearest_rank(sorted_list, pct):
    n = len(sorted_list)
    if n == 0:
        return None
    rank = max(1, (pct * n + 99) // 100)
    if rank > n:
        rank = n
    return sorted_list[rank - 1]

ages_sorted = sorted(ages)
median_age = nearest_rank(ages_sorted, 50)
p90_age    = nearest_rank(ages_sorted, 90)
p99_age    = nearest_rank(ages_sorted, 99)

# Long-tail fraction: number of accounts older than 50% of chain age.
# Threshold = head_h // 2. An account with age > threshold counts.
# Accounts older than the walk window are presumed older than 50% of
# chain age and ARE counted as long-tail (definitionally).
long_tail_threshold = head_h // 2 if head_h > 0 else 0
long_tail_count = 0
for a in ages:
    if a > long_tail_threshold:
        long_tail_count += 1
long_tail_count += older_than_walk["count"]
long_tail_fraction_bps = (long_tail_count * 10000 // total_accounts) if total_accounts > 0 else 0

# Older-than-walk fraction (drives historical_account_dominance anomaly).
older_than_walk_fraction_bps = (older_than_walk["count"] * 10000 // total_accounts) if total_accounts > 0 else 0

# Zero-balance/zero-nonce fraction (drives account_state_bloat anomaly).
zb_zn_fraction_bps = (zero_balance_zero_nonce * 10000 // total_accounts) if total_accounts > 0 else 0

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []
# recent_account_burst: > 100 accounts created in the last 100 blocks.
# The 100-account / 100-block thresholds are spec-mandated.
if recent_burst_count > 100:
    anomalies.append("recent_account_burst")
# account_state_bloat: > 10000 total accounts AND > 50% zero-balance
# zero-nonce. The 10000 threshold avoids firing on small testnets; the
# > 50% gate (5000 bps) targets sustained dust-residue accumulation.
if total_accounts > 10000 and zb_zn_fraction_bps > 5000:
    anomalies.append("account_state_bloat")
# historical_account_dominance: > 80% of accounts older than walk window
# (8000 bps). Surfaces when the audit can't precisely date most accounts
# and the operator should re-run with a larger --max-walk-blocks.
if older_than_walk_fraction_bps > 8000:
    anomalies.append("historical_account_dominance")

result = {
    "rpc_port":          int(port),
    "chain_height":      head_h,
    "max_walk_blocks":   max_walk,
    "bucket_size_blocks": bucket_size,
    "scan_from":         scan_from,
    "scan_to":           scan_to,
    "buckets":           bucket_list,
    "summary": {
        "total_accounts":          total_accounts,
        "median_age":              median_age,
        "p90_age":                 p90_age,
        "p99_age":                 p99_age,
        "oldest_known":            oldest_known,  # creation block, not age
        "long_tail_count":         long_tail_count,
        "long_tail_fraction_bps":  long_tail_fraction_bps,
        "older_than_walk_count":   older_than_walk["count"],
        "older_than_walk_fraction_bps": older_than_walk_fraction_bps,
        "zero_balance_zero_nonce_count":     zero_balance_zero_nonce,
        "zero_balance_zero_nonce_fraction_bps": zb_zn_fraction_bps,
        "recent_burst_count":      recent_burst_count,
    },
    "anomalies":         anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_account_age_distribution: scan failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human) ─────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

port               = r["rpc_port"]
head_h             = r["chain_height"]
max_walk           = r["max_walk_blocks"]
bucket_size        = r["bucket_size_blocks"]
scan_from          = r["scan_from"]
scan_to            = r["scan_to"]
buckets            = r["buckets"]
s                  = r["summary"]
anomalies          = r["anomalies"]
anom_count         = len(anomalies)

total_accounts     = s["total_accounts"]
median_age         = s["median_age"]
p90_age            = s["p90_age"]
p99_age            = s["p99_age"]
oldest_known       = s["oldest_known"]
long_tail_bps      = s["long_tail_fraction_bps"]
older_walk_count   = s["older_than_walk_count"]
older_walk_bps     = s["older_than_walk_fraction_bps"]
zb_zn_count        = s["zero_balance_zero_nonce_count"]
zb_zn_bps          = s["zero_balance_zero_nonce_fraction_bps"]
recent_burst_count = s["recent_burst_count"]

def render_bps_pct(bps):
    """bps in 0..10000 → 'XX.X%' (one decimal of precision)."""
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = {
        "rpc_port":          port,
        "chain_height":      head_h,
        "max_walk_blocks":   max_walk,
        "bucket_size_blocks": bucket_size,
        "scan_from":         scan_from,
        "scan_to":           scan_to,
        "buckets":           buckets,
        "summary": {
            "total_accounts":      total_accounts,
            "median_age":          median_age,
            "p90_age":             p90_age,
            "p99_age":             p99_age,
            "oldest_known":        oldest_known,
            "long_tail_fraction":  long_tail_bps / 10000.0,
        },
        "anomalies":         anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_account_age_distribution: no anomalies (port {port})")
    sys.exit(0)

print(f"=== Account age distribution (port {port}) ===")
print(f"Chain height:            {head_h}")
if scan_from is not None and scan_to is not None:
    print(f"Creation-walk window:    [{scan_from}..{scan_to}] ({max_walk} blocks)")
else:
    print(f"Creation-walk window:    (skipped — head_height=0 or max-walk-blocks=0)")
print(f"Bucket size:             {bucket_size} blocks")
print(f"Total accounts:          {total_accounts}")

if not anom_only and buckets:
    # Per-bucket histogram. Width chosen so the longest range fits
    # the column even at large bucket-size values.
    # Format: "age_low..age_high"   count  total_balance  mean_balance
    print("Per-bucket histogram (age in blocks since creation):")
    print(f"  {'age_range':<22} {'count':>8} {'total_balance':>20} {'mean_balance':>18}")
    for b in buckets:
        if b["age_high"] is None:
            # The "older than walk window" pseudo-bucket.
            label = f">{max_walk} (pre-walk)"
        else:
            label = f"{b['age_low']}..{b['age_high']}"
        print(f"  {label:<22} {b['count']:>8} {b['total_balance']:>20} {b['mean_balance']:>18}")

if not anom_only:
    print("Summary statistics:")
    if median_age is not None:
        print(f"  median age:            {median_age} blocks")
    else:
        print(f"  median age:            n/a (no walk-known accounts)")
    if p90_age is not None:
        print(f"  p90 age:               {p90_age} blocks")
    else:
        print(f"  p90 age:               n/a")
    if p99_age is not None:
        print(f"  p99 age:               {p99_age} blocks")
    else:
        print(f"  p99 age:               n/a")
    if oldest_known is not None:
        print(f"  oldest-known account:  block {oldest_known}")
    else:
        print(f"  oldest-known account:  n/a (no walk-known accounts)")
    print(f"  long-tail fraction:    {render_bps_pct(long_tail_bps)} "
          f"(accounts older than 50% of chain age)")
    if older_walk_count > 0:
        print(f"  older-than-walk:       {older_walk_count} accounts "
              f"({render_bps_pct(older_walk_bps)})")

print()
print(f"Total accounts:   {total_accounts}")
print(f"Chain height:     {head_h}")
print(f"Median age:       {median_age if median_age is not None else 'n/a'}")
print(f"p90 age:          {p90_age if p90_age is not None else 'n/a'}")
print(f"p99 age:          {p99_age if p99_age is not None else 'n/a'}")
print(f"Long-tail frac:   {render_bps_pct(long_tail_bps)}")
print(f"Anomaly count:    {anom_count}")

print()
if anom_count == 0:
    print("[OK] No account-age anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "recent_account_burst" in anomalies:
        print(f"  recent_account_burst         : {recent_burst_count} accounts "
              f"created in the last 100 blocks (> 100 threshold)")
        print(f"                                 — Sybil-onboarding burst signal; "
              f"pair with operator_stake_concentration.sh / operator_payments_audit.sh")
    if "account_state_bloat" in anomalies:
        print(f"  account_state_bloat          : {total_accounts} accounts, "
              f"{zb_zn_count} ({render_bps_pct(zb_zn_bps)}) zero-balance+zero-nonce")
        print(f"                                 — dust-residue accumulation; "
              f"state-prune candidate identification")
    if "historical_account_dominance" in anomalies:
        print(f"  historical_account_dominance : {older_walk_count}/{total_accounts} "
              f"({render_bps_pct(older_walk_bps)}) older than walk window")
        print(f"                                 — re-run with larger --max-walk-blocks "
              f"if precise ages on those are needed")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_account_age_distribution: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ────────────────────────────────────────────────
# Mirrors operator_account_growth / operator_orphan_account_scan: exit 2
# only when --anomalies-only is set AND ≥1 anomaly fired. Default
# informational mode always exits 0 if the pipeline succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_account_age_distribution: cannot create temp file" >&2; exit 1;
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
