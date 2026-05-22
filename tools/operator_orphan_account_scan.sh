#!/usr/bin/env bash
# operator_orphan_account_scan.sh — Diagnose auto-created accounts on a
# running determ daemon that have gone fully dormant: anon-address
# entries (created by auto-creation-on-credit) that hold zero balance,
# zero stake, no registry, and have not appeared in the last N blocks
# as a TRANSFER source/recipient.
#
# Read-only / pure diagnostic — NO mutation.
#
# Background:
#   Per docs/proofs/AccountStateInvariants.md (I-4 channels), a TRANSFER
#   to a previously-unseen anon-address auto-creates accounts_[to] with
#   the credit amount. The recipient never has to sign anything to come
#   into existence. Once created, the entry is monotone — v1 has no
#   purge path. Common origins of dormant orphans:
#     - a typo'd send (funds trapped at an address with no key)
#     - one-off airdrops to a list of addresses, most never used
#     - test fixtures that leaked into a production snapshot
#     - an anon recipient that immediately spent everything (next_nonce
#       advanced) and now sits at 0 — see "Variants" below
#
# Sibling-script contrast (avoid overlap):
#   operator_dust_audit.sh        Four-way bucket classification across
#                                 the WHOLE account set; dust-receiver
#                                 cohort uses balance ≤ threshold AND
#                                 nonce == 0. No recent-activity check.
#   operator_orphan_check.sh      Cross-map orphan check (stakes /
#                                 registrants / accounts coherence). No
#                                 dormancy / recent-activity dimension.
#   operator_account_growth.sh    Walks blocks for first-seen domains
#                                 over a window — growth direction, not
#                                 dormancy direction.
#   operator_orphan_account_scan  THIS — every account that meets
#                                 "candidate orphan" structural rule
#                                 (balance ≤ threshold, zero stake, no
#                                 registry) AND has not appeared as a
#                                 TRANSFER source/recipient anywhere in
#                                 the last --max-scan-blocks blocks.
#
# Pipeline (read-only RPC):
#   1.  `determ snapshot create --out <tmp>` — full state dump JSON.
#       The dump is the canonical per-account ledger; the lighter
#       `snapshot inspect` surface returns counts only. We also need
#       stakes[] and registrants[] from the same dump so the "no stake
#       + no registry" filter is coherent at a single height.
#   2.  Filter accounts → orphan-candidate set:
#       balance ≤ --include-balance-threshold (default 0)
#       AND no entry in stakes_ (locked == 0 if entry exists)
#       AND no entry in registrants_
#   3.  Walk the last --max-scan-blocks blocks via `determ block-info
#       <h> --json` and, for each block, mark any candidate that
#       appears as tx.from or tx.to in ANY transaction (every tx type;
#       not just TRANSFER — STAKE / UNSTAKE / DAPP_CALL etc. also count
#       as "recent activity" because they prove the address is still
#       being used). For each candidate, the highest block where it
#       appeared in the window is the last_seen_block. Anything still
#       unseen after the window scan is the orphan output set.
#   4.  Optional --inactive-threshold-blocks is the dormancy floor: an
#       orphan reported here must have last_seen_block < (head -
#       inactive-threshold-blocks) OR have no observation at all. The
#       default (10000) is intentionally larger than --max-scan-blocks
#       (5000) so the default scan reports EVERY candidate-zero
#       account that didn't appear in the last 5000 blocks; operators
#       who want tighter dormancy windows set both knobs together.
#
# Why no "creation_block" recovery:
#   v1 doesn't preserve per-account creation height; the accounts_ map
#   stores (balance, next_nonce) only. We emit `null` for that field
#   (per the task spec); operators who want creation provenance can
#   pair this with operator_account_growth.sh over the same window.
#
# Variants caught:
#   - Pure auto-creation residue:  balance == 0, next_nonce == 0,
#     anon-address shape. The canonical orphan: funds-trapped airdrop
#     or typo. Reported.
#   - Drained anon hot wallet:     balance == 0, next_nonce >= 1,
#     anon-address shape. The address USED to be active but is now
#     fully drained. Reported (operators often want both — flag
#     "drained" via next_nonce in the per-record output).
#   - Non-anon orphan:             balance == 0 named-domain entry
#     (no 0x prefix). Could only land here via a REGISTER that was
#     later DEREGISTER'd and the balance was swept. Reported and
#     marked "named" in the per-record output. Rare.
#
# Anomaly flags (each adds to anomalies[]; --anomalies-only exits 2):
#   - orphan_supply_nonzero   Σ orphan-held supply > 0. Funds parked
#                             at addresses that have shown no activity
#                             in the scan window. Either funds-trapped-
#                             at-typo or a test fixture leak — operator
#                             should investigate the senders.
#   - orphan_share_high       n_orphans > 50% of total accounts. Gas-
#                             grief / chain-bloat signal — most of the
#                             ledger is auto-creation pollution; many
#                             one-off airdrops cluttering.
#
# RPC dependencies (all read-only):
#   - status                  current chain height (banner; also drives
#                             the recent-activity window upper bound)
#   - snapshot create         full state dump → tmp file
#   - block-info              per-block JSON for the recent-activity walk
#
# Usage:
#   tools/operator_orphan_account_scan.sh --rpc-port N
#                                         [--inactive-threshold-blocks N]
#                                         [--include-balance-threshold N]
#                                         [--max-scan-blocks N]
#                                         [--json]
#                                         [--anomalies-only]
#
# Options:
#   --rpc-port N                    RPC port to query (REQUIRED)
#   --inactive-threshold-blocks N   Dormancy floor; orphans must have no
#                                   recent activity for this long
#                                   (default: 10000 blocks)
#   --include-balance-threshold N   Accounts with balance ≤ this are
#                                   considered orphan candidates
#                                   (default: 0)
#   --max-scan-blocks N             Block window for recent-activity scan
#                                   (default: 5000)
#   --json                          Emit structured JSON envelope
#   --anomalies-only                Print only flagged anomalies; exit 2
#                                   if any fire
#   -h, --help                      Show this help
#
# Exit codes (mirrors operator_dust_audit / operator_stake_concentration):
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / malformed snapshot / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_orphan_account_scan.sh --rpc-port N
                                       [--inactive-threshold-blocks N]
                                       [--include-balance-threshold N]
                                       [--max-scan-blocks N]
                                       [--json]
                                       [--anomalies-only]

Diagnose auto-created accounts that have gone dormant. Enumerates every
account in accounts_, filters for candidate orphans (balance ≤ threshold,
zero stake, no registry), walks the last --max-scan-blocks blocks to
prove no recent activity (tx.from/tx.to appearance in any transaction),
and reports the resulting orphan set with held-supply totals.

Pure diagnostic — NO mutation.

Options:
  --rpc-port N                    RPC port to query (REQUIRED)
  --inactive-threshold-blocks N   Dormancy floor (default: 10000)
  --include-balance-threshold N   Balance ≤ this is candidate (default: 0)
  --max-scan-blocks N             Recent-activity window (default: 5000)
  --json                          Emit structured JSON envelope
  --anomalies-only                Print only flagged anomalies; exit 2 if any fire
  -h, --help                      Show this help

Anomaly flags:
  orphan_supply_nonzero    Σ orphan-held supply > 0
  orphan_share_high        n_orphans > 50% of total accounts

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed snapshot
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
INACTIVE_THRESHOLD=10000
BALANCE_THRESHOLD=0
MAX_SCAN_BLOCKS=5000
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                       usage; exit 0 ;;
    --rpc-port)                      PORT="${2:-}";               shift 2 ;;
    --inactive-threshold-blocks)     INACTIVE_THRESHOLD="${2:-}"; shift 2 ;;
    --include-balance-threshold)     BALANCE_THRESHOLD="${2:-}";  shift 2 ;;
    --max-scan-blocks)               MAX_SCAN_BLOCKS="${2:-}";    shift 2 ;;
    --json)                          JSON_OUT=1;                  shift ;;
    --anomalies-only)                ANOM_ONLY=1;                 shift ;;
    *) echo "operator_orphan_account_scan: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required per the spec (avoids silently targeting the
# wrong daemon on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_orphan_account_scan: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_orphan_account_scan: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$INACTIVE_THRESHOLD" in *[!0-9]*|"")
  echo "operator_orphan_account_scan: --inactive-threshold-blocks must be a non-negative integer (got '$INACTIVE_THRESHOLD')" >&2
  exit 1 ;;
esac
case "$BALANCE_THRESHOLD" in *[!0-9]*|"")
  echo "operator_orphan_account_scan: --include-balance-threshold must be a non-negative integer (got '$BALANCE_THRESHOLD')" >&2
  exit 1 ;;
esac
case "$MAX_SCAN_BLOCKS" in *[!0-9]*|"")
  echo "operator_orphan_account_scan: --max-scan-blocks must be a non-negative integer (got '$MAX_SCAN_BLOCKS')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote $DETERM to an absolute path so the python subprocess.run call
# below works regardless of CWD-quirks across Git Bash / Cygwin / Linux.
# (Same pattern as operator_dapp_inventory.sh.)
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain height ────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_orphan_account_scan: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_orphan_account_scan: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: snapshot dump → tmp file ────────────────────────────────────────
TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
  echo "operator_orphan_account_scan: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_orphan_account_scan: cannot create temp file" >&2;
  rm -f "$TMP_SNAP" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_orphan_account_scan: snapshot create failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: filter candidates + recent-activity walk + classify ─────────────
# Python driver because we need set arithmetic across three associative
# arrays (accounts / stakes / registrants), plus a block-walk that
# subprocess-calls `determ block-info` per height. Cleaner than POSIX
# shell with sorted-file joins on arbitrary domain strings, and Python
# is already a required test-suite dependency.
#
# Recent-activity rule: an account D is "active" in the window if any
# block in [HEAD_H - MAX_SCAN_BLOCKS + 1, HEAD_H] contains a transaction
# whose tx.from == D or tx.to == D. We scan EVERY tx type, not just
# TRANSFER — a STAKE / UNSTAKE / DAPP_CALL still proves the keyholder
# is alive and using the address. Activity is keyed by the LATEST block
# where D appeared (the .last_seen_block field).
#
# Dormancy rule: after the window walk, D is reported as orphan iff
#   D never appeared in the window
#   OR D's last_seen_block < HEAD_H - --inactive-threshold-blocks
# The second clause is rarely triggered by the default knobs (the
# window scans 5000 blocks, the dormancy floor is 10000 — anything in
# the window is fresher than the floor), but operators who pass
# --max-scan-blocks > --inactive-threshold-blocks can extract a tighter
# dormancy report.
python - "$DETERM_ABS" "$PORT" "$TMP_SNAP" "$TMP_OUT" \
        "$HEAD_H" "$INACTIVE_THRESHOLD" "$BALANCE_THRESHOLD" \
        "$MAX_SCAN_BLOCKS" <<'PY'
import json, subprocess, sys

(determ, port, snap_path, out_path,
 head_h_s, inactive_thr_s, bal_thr_s, max_scan_s) = sys.argv[1:9]
head_h          = int(head_h_s)
inactive_thr    = int(inactive_thr_s)
balance_thr     = int(bal_thr_s)
max_scan_blocks = int(max_scan_s)

# Load the snapshot. Cheap parse — the dump is already on local disk.
try:
    with open(snap_path, "r", encoding="utf-8") as f:
        snap = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_orphan_account_scan: cannot parse snapshot: {e}\n")
    sys.exit(1)
if not isinstance(snap, dict):
    sys.stderr.write("operator_orphan_account_scan: snapshot is not a JSON object\n")
    sys.exit(1)

# Build per-domain views from accounts/stakes/registrants. We keep the
# locked stake (S-013/S-014 namespace) so a domain with a stale stake
# entry but locked == 0 still qualifies as a candidate. Registrants
# entries are a hard exclusion: an account with a registry record was
# never auto-created; it came in via REGISTER. Same shape as
# operator_orphan_check.sh's snapshot loader.
accounts = {}     # domain -> {balance, next_nonce}
stakes   = {}     # domain -> {locked, unlock_height}
regs     = set()  # set of registered domains
for a in snap.get("accounts", []) or []:
    if not isinstance(a, dict): continue
    d = a.get("domain")
    if isinstance(d, str) and d:
        accounts[d] = {
            "balance":    int(a.get("balance", 0) or 0),
            "next_nonce": int(a.get("next_nonce", 0) or 0),
        }
for s in snap.get("stakes", []) or []:
    if not isinstance(s, dict): continue
    d = s.get("domain")
    if isinstance(d, str) and d:
        stakes[d] = {
            "locked":        int(s.get("locked", 0) or 0),
            "unlock_height": int(s.get("unlock_height", 0) or 0),
        }
for r in snap.get("registrants", []) or []:
    if not isinstance(r, dict): continue
    d = r.get("domain")
    if isinstance(d, str) and d:
        regs.add(d)

total_accounts = len(accounts)

# Anon-shape check (mirrors include/determ/types.hpp::is_anon_address).
# 0x + 64 hex chars (case-insensitive) — 66 chars total.
def is_anon(addr):
    if not isinstance(addr, str) or len(addr) != 66:
        return False
    if addr[0] != "0" or addr[1] != "x":
        return False
    for c in addr[2:]:
        if not ((c >= "0" and c <= "9")
                or (c >= "a" and c <= "f")
                or (c >= "A" and c <= "F")):
            return False
    return True

# Candidate set:
#   balance ≤ balance_thr
#   AND (no stakes entry OR stakes[d].locked == 0)
#   AND d not in registrants
# We KEEP the non-anon entries (named accounts that ended up empty) for
# completeness and tag them via address_type = "named" in the output.
# Default is the anon orphan, but operators auditing a chain with
# deregistered named domains will want both.
candidates = {}
for d, a in accounts.items():
    if a["balance"] > balance_thr:
        continue
    locked = stakes.get(d, {}).get("locked", 0)
    if locked > 0:
        continue
    if d in regs:
        continue
    candidates[d] = a

# Recent-activity scan over [scan_from, head_h]. Half-open is awkward
# here since block-info is single-height; we walk [scan_from..head_h]
# inclusive. scan_from is bounded by 0 (genesis), upper end is the tip.
# An empty / pre-genesis chain (head_h < 1) skips the walk entirely.
scan_from = max(0, head_h - max_scan_blocks + 1) if max_scan_blocks > 0 else (head_h + 1)
last_seen = {}  # domain -> last block index where it appeared

def mark(addr, h):
    if addr in candidates and (addr not in last_seen or last_seen[addr] < h):
        last_seen[addr] = h

# Walk the window. Per-block: scan tx.from / tx.to across every tx, AND
# the inbound_receipts[].to field (cross-shard credit that lands on an
# anon recipient is still an "activity" signal — the address is being
# used as an intentional destination). We deliberately do NOT scan
# block.creators (creators are validators with a registry entry — they
# already fail the regs hard-exclude in the candidate filter).
if max_scan_blocks > 0 and head_h > 0:
    for h in range(scan_from, head_h + 1):
        try:
            r = subprocess.run(
                [determ, "block-info", str(h), "--json", "--rpc-port", port],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            sys.stderr.write(f"operator_orphan_account_scan: block-info {h} failed: {e}\n")
            sys.exit(1)
        if r.returncode != 0:
            sys.stderr.write(f"operator_orphan_account_scan: block-info {h} rc={r.returncode}: {r.stderr.strip()}\n")
            sys.exit(1)
        try:
            blk = json.loads(r.stdout)
        except Exception:
            sys.stderr.write(f"operator_orphan_account_scan: block-info {h} non-JSON\n")
            sys.exit(1)
        if not isinstance(blk, dict):
            continue
        txs = blk.get("transactions") or []
        if isinstance(txs, list):
            for tx in txs:
                if not isinstance(tx, dict): continue
                f_ = tx.get("from", "")
                t_ = tx.get("to", "")
                if isinstance(f_, str) and f_:
                    mark(f_, h)
                if isinstance(t_, str) and t_:
                    mark(t_, h)
        ibrs = blk.get("inbound_receipts") or []
        if isinstance(ibrs, list):
            for r2 in ibrs:
                if not isinstance(r2, dict): continue
                to = r2.get("to", "")
                if isinstance(to, str) and to:
                    mark(to, h)

# Final dormancy gate: an orphan must have last_seen_block missing OR
# strictly less than (head_h - inactive_thr). The strict-less is so an
# orphan at the boundary block doesn't count as "still dormant for the
# threshold" — it just crossed the line.
dormancy_floor = head_h - inactive_thr  # last_seen < this => orphan
orphans = []
for d, a in candidates.items():
    ls = last_seen.get(d, None)
    if ls is not None and ls >= dormancy_floor:
        continue
    addr_type = "anon" if is_anon(d) else "named"
    drained = (a["next_nonce"] > 0)
    orphans.append({
        "address":         d,
        "balance":         a["balance"],
        "next_nonce":      a["next_nonce"],
        "last_seen_block": ls,            # null if never seen in window
        "creation_block":  None,          # v1 doesn't preserve this
        "address_type":    addr_type,
        "drained":         drained,
    })

# Sort: balance ascending (most empty first), then address ascending for
# deterministic tie-break.
orphans.sort(key=lambda o: (o["balance"], o["address"]))

n_orphans          = len(orphans)
orphan_held_supply = sum(o["balance"] for o in orphans)
orphan_share_bps   = (n_orphans * 10000 // total_accounts) if total_accounts > 0 else 0

# Anomaly classification.
anomalies = []
# orphan_supply_nonzero: any non-trivial total value parked at dormant
# auto-created accounts. Critical for the funds-trapped audit.
if orphan_held_supply > 0:
    anomalies.append("orphan_supply_nonzero")
# orphan_share_high: > 50% of total accounts. Chain-bloat / gas-grief
# signal. Uses basis-point integer comparison to dodge float drift.
if total_accounts > 0 and orphan_share_bps > 5000:
    anomalies.append("orphan_share_high")

result = {
    "head_height":          head_h,
    "scan_from":            scan_from if max_scan_blocks > 0 else None,
    "scan_to":              head_h    if max_scan_blocks > 0 else None,
    "inactive_threshold":   inactive_thr,
    "balance_threshold":    balance_thr,
    "max_scan_blocks":      max_scan_blocks,
    "total_accounts":       total_accounts,
    "n_orphans":            n_orphans,
    "orphan_share_bps":     orphan_share_bps,
    "orphan_held_supply":   orphan_held_supply,
    "orphans":              orphans,
    "anomalies":            anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_orphan_account_scan: scan failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human) ─────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

head_h            = r["head_height"]
scan_from         = r["scan_from"]
scan_to           = r["scan_to"]
inactive_thr      = r["inactive_threshold"]
balance_thr       = r["balance_threshold"]
max_scan          = r["max_scan_blocks"]
total_accounts    = r["total_accounts"]
n_orphans         = r["n_orphans"]
orphan_share_bps  = r["orphan_share_bps"]
orphan_supply     = r["orphan_held_supply"]
orphans           = r["orphans"]
anomalies         = r["anomalies"]
anom_count        = len(anomalies)

def render_bps_pct(bps):
    """bps in 0..10000 → 'XX.X%' (one decimal of precision)."""
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def short(addr):
    """Truncate long addresses for column alignment in the text table.
    Anon addresses are 66 chars; show prefix + suffix so collisions are
    obvious even after truncation."""
    if isinstance(addr, str) and len(addr) > 24:
        return addr[:10] + "..." + addr[-6:]
    return addr

if json_out:
    envelope = {
        "rpc_port":             port,
        "chain_height":         head_h,
        "scan_from":            scan_from,
        "scan_to":              scan_to,
        "inactive_threshold":   inactive_thr,
        "balance_threshold":    balance_thr,
        "max_scan_blocks":      max_scan,
        "orphans":              orphans,
        "summary": {
            "n_orphans":          n_orphans,
            "n_total_accounts":   total_accounts,
            "orphan_share_bps":   orphan_share_bps,
            "orphan_share_pct":   orphan_share_bps / 100.0,
            "orphan_held_supply": orphan_supply,
        },
        "anomalies":            anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_orphan_account_scan: no anomalies (port {port})")
    sys.exit(0)

print(f"=== Orphan account scan (port {port}) ===")
print(f"Chain height:              {head_h}")
if max_scan > 0 and head_h > 0:
    print(f"Activity-scan window:      [{scan_from}..{scan_to}] ({max_scan} blocks)")
else:
    print(f"Activity-scan window:      (skipped — head_height=0 or max-scan-blocks=0)")
print(f"Inactive threshold:        {inactive_thr} blocks")
print(f"Balance threshold:         {balance_thr}")
print(f"Total accounts:            {total_accounts}")
print(f"Orphans found:             {n_orphans} "
      f"({render_bps_pct(orphan_share_bps)} of total)")
print(f"Orphan-held supply:        {orphan_supply}")

if not anom_only and orphans:
    shown = min(50, len(orphans))
    print(f"Top-{shown} orphans (balance ascending):")
    for i, o in enumerate(orphans[:shown], start=1):
        ls = o["last_seen_block"]
        ls_s = "never" if ls is None else str(ls)
        flags = []
        if o["drained"]:           flags.append("drained")
        if o["address_type"] == "named": flags.append("named")
        flag_str = (" [" + ",".join(flags) + "]") if flags else ""
        print(f"  {i:>3}. {short(o['address']):<24} "
              f"balance={o['balance']:<8} nonce={o['next_nonce']:<4} "
              f"last_seen={ls_s}{flag_str}")
    if len(orphans) > shown:
        print(f"  ... +{len(orphans) - shown} more")

print()
if anom_count == 0:
    print("[OK] No orphan-account anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "orphan_supply_nonzero" in anomalies:
        print(f"  orphan_supply_nonzero  : Σ orphan-held supply = {orphan_supply} "
              f"(> 0 — funds parked at dormant addresses)")
    if "orphan_share_high" in anomalies:
        print(f"  orphan_share_high      : {n_orphans}/{total_accounts} accounts "
              f"({render_bps_pct(orphan_share_bps)}) > 50% threshold")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_orphan_account_scan: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ────────────────────────────────────────────────
# Mirrors operator_dust_audit / operator_stake_concentration: exit 2 only
# when --anomalies-only is set AND ≥1 anomaly fired. Default informational
# mode always exits 0 if the pipeline succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_orphan_account_scan: cannot create temp file" >&2; exit 1;
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
