#!/usr/bin/env bash
# operator_dust_audit.sh — Audit zero-and-near-zero balance accounts on
# a running determ daemon. Classifies every account in the live state
# into one of four buckets and surfaces operator-relevant patterns:
#
#   - Zero          balance == 0 AND nonce == 0 AND no stake AND no
#                   registry. True empty residue — most often the
#                   transient auto-creation footprint left by the I-4
#                   channels (TRANSFER credit / inbound receipt /
#                   DAPP_CALL credit) when the credited entry never
#                   funded itself afterwards. A few are expected; a
#                   large share signals auto-creation pollution.
#   - Dust-sender   balance ≤ dust-threshold AND nonce ≥ 1. The
#                   account spent something (nonce advanced) and is
#                   now sitting near-zero — classic exhausted-key
#                   pattern OR a hot wallet that fully drained.
#   - Dust-receiver balance ≤ dust-threshold AND nonce == 0. Account
#                   has received credit but never sent — typical dust-
#                   attack signal where an attacker sprays many tiny
#                   credits to many addresses for tracking / Sybil
#                   onboarding / chain bloat.
#   - Active        balance > dust-threshold OR has stake OR has
#                   registry. Normal account.
#
# Pipeline (read-only RPC):
#   1.  `determ snapshot create --out <tmp>` — full state dump JSON.
#       The dump IS the per-account ledger (the `accounts` /
#       `stakes` / `registrants` / `dapp_registry` arrays per
#       Chain::serialize_state in src/chain/chain.cpp ~L1541). The
#       lighter `snapshot inspect` surface only returns COUNTS, so we
#       parse the create-output JSON file directly.
#   2.  `determ snapshot inspect --in <tmp> --json` — restore
#       round-trip (S-033/S-038 state_root verification) as a
#       defensive sanity check before we trust the file. Avoids
#       acting on a torn/corrupted snapshot file. Skipped via
#       --skip-verify for operator triage on suspicious states.
#   3.  Walk the dump in Python: per-account merge of balance + nonce
#       + stake (locked) + registry presence + DApp presence, then
#       four-way classification with the rules above.
#
# Per-class aggregates:
#   - Counts + share-percent of total
#   - Total dust value (sum of balances ≤ threshold across both
#     dust-sender and dust-receiver buckets; excludes Zero accounts
#     trivially)
#   - Top-20 dust receivers (single domain receiving many tiny
#     credits, ranked by per-class membership not balance — the
#     dust-receiver bucket already has balance ≤ threshold by
#     definition; what's interesting is which addresses are repeated
#     targets within the cohort. Since the snapshot stores only the
#     current state and not historic credit count, we surface the
#     top-20 by lowest non-zero balance within the dust-receiver
#     cohort — these are the most extreme "received almost nothing"
#     accounts, the canonical mass-dust attack fingerprint).
#
# Anomaly flags (each adds to anomalies[]; --anomalies-only exits 2):
#   - mass_dust_receivers     dust-receiver count > 100 (mass-dust
#                             attack signal — defender should
#                             investigate whether one or a few sender
#                             addresses are the origin via a paired
#                             block-walk audit, e.g. via
#                             operator_anon_address_usage.sh).
#   - auto_creation_pollution Zero-account count > 50% of total
#                             accounts. Indicates the chain is
#                             accumulating ledger entries that have
#                             never actually been funded — a
#                             chain-bloat / dust-attack residue
#                             pattern.
#
# RPC dependencies (read-only):
#   - snapshot create        full state dump → tmp file
#   - snapshot inspect       round-trip integrity check (optional)
#   - head                   current chain height (banner only)
#
# Usage:
#   tools/operator_dust_audit.sh [--rpc-port N] [--json]
#                                [--threshold T] [--top N]
#                                [--anomalies-only] [--skip-verify]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope
#   --threshold T       Dust-threshold (integer; default: 10). Accounts
#                       at or below this balance count as dust unless
#                       they hold stake or registry status.
#   --top N             Top-N dust receivers to surface (default: 20)
#   --anomalies-only    Print only flagged anomalies; exit 2 if any
#   --skip-verify       Skip the `snapshot inspect` round-trip
#                       (faster on large snapshots; less safe — only
#                       use when triaging known-suspect state)
#   -h, --help          Show this help
#
# Exit codes (mirrors operator_account_growth / operator_dapp_*):
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / malformed snapshot / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_dust_audit.sh [--rpc-port N] [--json]
                              [--threshold T] [--top N]
                              [--anomalies-only] [--skip-verify]

Audit zero-and-near-zero balance accounts on a running determ daemon.
Classifies every account in the live state into Zero / Dust-sender /
Dust-receiver / Active, reports per-class counts + total dust value
+ top-N dust receivers, and flags mass-dust + auto-creation-pollution
anomaly patterns.

Snapshot pipeline:
  1. `snapshot create --out <tmp>` writes the full state dump.
  2. (optional) `snapshot inspect --in <tmp> --json` verifies the
     S-033/S-038 state_root round-trip before we parse it.
  3. Python walks the dump's `accounts` / `stakes` / `registrants`
     / `dapp_registry` arrays and classifies each domain.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope
  --threshold T       Dust-threshold integer (default: 10)
  --top N             Top-N dust receivers to surface (default: 20)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  --skip-verify       Skip the inspect round-trip integrity check
  -h, --help          Show this help

Anomaly flags:
  mass_dust_receivers       dust-receiver count > 100
  auto_creation_pollution   Zero-account count > 50% of total accounts

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
THRESHOLD=10
TOP_N=20
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";       shift 2 ;;
    --json)            JSON_OUT=1;          shift ;;
    --threshold)       THRESHOLD="${2:-}";  shift 2 ;;
    --top)             TOP_N="${2:-}";      shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;         shift ;;
    --skip-verify)     SKIP_VERIFY=1;       shift ;;
    *) echo "operator_dust_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dust_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$THRESHOLD" in *[!0-9]*|"")
  echo "operator_dust_audit: --threshold must be an unsigned integer (got '$THRESHOLD')" >&2
  exit 1 ;;
esac
case "$TOP_N" in *[!0-9]*|"")
  echo "operator_dust_audit: --top must be a positive integer (got '$TOP_N')" >&2
  exit 1 ;;
esac
if [ "$TOP_N" -lt 1 ]; then
  echo "operator_dust_audit: --top must be >= 1 (got '$TOP_N')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current tip (banner only; the snapshot is the source of truth) ──
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dust_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dust_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: snapshot create → tmp file ──────────────────────────────────────
TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
  echo "operator_dust_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dust_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_dust_audit: snapshot create failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: integrity round-trip via `snapshot inspect` ─────────────────────
# S-033 + S-038 state_root gate: a successful inspect with --json means
# the snapshot's stored state_root matches the recomputed one after
# Chain::restore_from_snapshot ran. Without this, we'd be classifying
# accounts from a potentially torn / mid-write snapshot — operators
# triaging an incident might still want that (raw view), so the
# --skip-verify escape hatch exists.
SNAP_BLOCK_INDEX="$HEAD_H"
SNAP_STATE_ROOT=""
if [ "$SKIP_VERIFY" = "0" ]; then
  INSPECT_OUT=$("$DETERM" snapshot inspect --in "$TMP_SNAP" --json 2>&1) || {
    echo "operator_dust_audit: snapshot inspect failed (state_root mismatch or malformed snapshot)" >&2
    echo "$INSPECT_OUT" >&2
    exit 1
  }
  # Pull block_index + state_root for the JSON envelope. Both are
  # informational; their presence is what gates the audit.
  if [ "$HAVE_JQ" = "1" ]; then
    SNAP_BLOCK_INDEX=$(printf '%s' "$INSPECT_OUT" | jq -r '.block_index // 0')
    SNAP_STATE_ROOT=$(printf '%s' "$INSPECT_OUT" | jq -r '.state_root // ""')
  else
    SNAP_BLOCK_INDEX=$(printf '%s' "$INSPECT_OUT" | grep -o '"block_index":[0-9]*' | head -1 | sed 's/.*://')
    SNAP_STATE_ROOT=$(printf '%s' "$INSPECT_OUT" | grep -o '"state_root":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
  fi
  case "$SNAP_BLOCK_INDEX" in *[!0-9]*|"") SNAP_BLOCK_INDEX=0 ;; esac
fi

# ── Step 4: classify every account via Python ───────────────────────────────
# Python reads the raw snapshot dump JSON, merges per-domain
# (balance, next_nonce) ⨉ (locked stake) ⨉ (registry presence) ⨉
# (DApp registry presence), applies the four-way classification rule,
# and writes a results JSON to $TMP_OUT for the rendering pass to
# consume. The rule is documented in the script header; encoding it
# in one place (here) keeps both the JSON envelope and the human
# table consistent.
python - "$TMP_SNAP" "$TMP_OUT" "$THRESHOLD" "$TOP_N" <<'PY'
import json, sys
from collections import defaultdict

snap_path, out_path, threshold_s, top_n_s = sys.argv[1:5]
threshold = int(threshold_s)
top_n     = int(top_n_s)

try:
    with open(snap_path, "r", encoding="utf-8") as f:
        snap = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_dust_audit: cannot parse snapshot: {e}\n")
    sys.exit(1)
if not isinstance(snap, dict):
    sys.stderr.write("operator_dust_audit: snapshot is not a JSON object\n")
    sys.exit(1)

# Per-domain merged record. defaultdict default = "empty" structure;
# only fields actually observed in the snapshot get overwritten.
def empty_rec():
    return {
        "balance":      0,
        "next_nonce":   0,
        "stake_locked": 0,
        "has_registry": False,
        "has_dapp":     False,
    }

records = defaultdict(empty_rec)

# accounts[]: {domain, balance, next_nonce}
for a in snap.get("accounts", []) or []:
    if not isinstance(a, dict):
        continue
    d = a.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    rec = records[d]
    # value() defaults match Chain::restore_from_snapshot's behavior
    # for missing fields (legacy snapshot tolerance).
    rec["balance"]    = int(a.get("balance",    0) or 0)
    rec["next_nonce"] = int(a.get("next_nonce", 0) or 0)

# stakes[]: {domain, locked, unlock_height}
for s in snap.get("stakes", []) or []:
    if not isinstance(s, dict):
        continue
    d = s.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    rec = records[d]
    rec["stake_locked"] = int(s.get("locked", 0) or 0)

# registrants[]: {domain, ed_pub, registered_at, active_from, inactive_from, region}
# An entry being present marks the domain as "has_registry" regardless
# of active/inactive state — the dust classification is about the
# economic shape of the account, not the validator lifecycle. A
# DEREGISTER'd registrant still has a registry entry per
# AccountStateInvariants.md I-4 (entries are never removed).
for r in snap.get("registrants", []) or []:
    if not isinstance(r, dict):
        continue
    d = r.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    records[d]["has_registry"] = True

# dapp_registry[]: {domain, ...}. DApp-owner accounts are commercial
# accounts (DAPP_CALL revenue sink) — never treat them as dust even
# if currently empty.
for e in snap.get("dapp_registry", []) or []:
    if not isinstance(e, dict):
        continue
    d = e.get("domain", "")
    if not isinstance(d, str) or not d:
        continue
    records[d]["has_dapp"] = True

# Classify.
total          = 0
zero_count     = 0
dust_send_cnt  = 0
dust_recv_cnt  = 0
active_cnt     = 0
total_dust_value = 0

# For the top-N dust receivers ranking: collect (domain, balance) for
# every dust-receiver, then sort by (balance asc, domain asc) so the
# smallest-credit dust is surfaced first. Ties broken
# deterministically by domain for reproducibility across runs.
dust_receivers_list = []

for d, rec in records.items():
    total += 1
    bal     = rec["balance"]
    nonce   = rec["next_nonce"]
    locked  = rec["stake_locked"]
    has_reg = rec["has_registry"]
    has_dap = rec["has_dapp"]

    # Active wins over every other class:
    #   - balance above threshold        → real value held
    #   - any stake locked               → validator collateral
    #   - has registry / DApp entry      → protocol-role account
    if bal > threshold or locked > 0 or has_reg or has_dap:
        active_cnt += 1
        continue

    # From here: balance ≤ threshold AND no stake/registry/dapp.
    if bal == 0 and nonce == 0:
        zero_count += 1
        continue

    # balance ≤ threshold (may be 0 if nonce ≥ 1, otherwise nonzero).
    # Dust value sum excludes Zero-class trivially (balance==0).
    total_dust_value += bal
    if nonce >= 1:
        dust_send_cnt += 1
    else:
        # nonce == 0 AND (bal > 0 OR (bal == 0 AND we're here because
        # nonce ≥ 1 was false but the Zero branch didn't take it —
        # impossible in current logic; bal must be > 0 here). The
        # ranking only matters when bal > 0 so we exclude the
        # bal == 0 / nonce == 0 corner (caught by Zero above) and
        # treat any bal > 0 / nonce == 0 / no-stake/reg/dapp as
        # dust-receiver.
        dust_recv_cnt += 1
        dust_receivers_list.append((d, bal))

# Top-N dust receivers: smallest balance first (the canonical
# "received almost nothing" fingerprint of a dust spray).
dust_receivers_list.sort(key=lambda kv: (kv[1], kv[0]))
top_receivers = [
    {"domain": d, "balance": b}
    for d, b in dust_receivers_list[:top_n]
]

# Anomaly classification.
anomalies = []
# mass_dust_receivers: > 100 dust-receivers in the live state.
if dust_recv_cnt > 100:
    anomalies.append("mass_dust_receivers")
# auto_creation_pollution: > 50% of accounts are Zero-class.
# Guard against the division-by-zero case (fresh chain, no accounts
# beyond genesis): rule only fires when total > 0.
pollution_bps = 0
if total > 0:
    pollution_bps = zero_count * 10000 // total
    if pollution_bps > 5000:
        anomalies.append("auto_creation_pollution")

# Per-class share basis points (out of 10000). Renderer formats them
# into "PP.P%" with one decimal of precision.
def bps(n, d):
    if d <= 0: return 0
    return n * 10000 // d

result = {
    "total":             total,
    "threshold":         threshold,
    "active_count":      active_cnt,
    "dust_sender_count": dust_send_cnt,
    "dust_receiver_count": dust_recv_cnt,
    "zero_count":        zero_count,
    "active_bps":        bps(active_cnt,     total),
    "dust_sender_bps":   bps(dust_send_cnt,  total),
    "dust_receiver_bps": bps(dust_recv_cnt,  total),
    "zero_bps":          bps(zero_count,     total),
    "total_dust_value":  total_dust_value,
    "dust_account_count": dust_send_cnt + dust_recv_cnt,
    "pollution_bps":     pollution_bps,
    "top_dust_receivers": top_receivers,
    "anomalies":         anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dust_audit: classification pass failed" >&2
  exit 1
fi

# ── Step 5: render envelope (JSON or human) ─────────────────────────────────
# Python is already required by Step 4, so a single render pass keeps
# the layout consistent with the upstream classification (no
# duplicated logic between bash and python sides).
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" \
        "$SNAP_BLOCK_INDEX" "$SNAP_STATE_ROOT" "$SKIP_VERIFY" "$THRESHOLD" "$TOP_N" <<'PY'
import json, sys

json_out         = sys.argv[1] == "1"
anom_only        = sys.argv[2] == "1"
out_path         = sys.argv[3]
port             = int(sys.argv[4])
head_h           = int(sys.argv[5])
snap_block_index = int(sys.argv[6])
snap_state_root  = sys.argv[7]
skip_verify      = sys.argv[8] == "1"
threshold        = int(sys.argv[9])
top_n            = int(sys.argv[10])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total           = r["total"]
active_cnt      = r["active_count"]
dust_send_cnt   = r["dust_sender_count"]
dust_recv_cnt   = r["dust_receiver_count"]
zero_cnt        = r["zero_count"]
total_dust      = r["total_dust_value"]
dust_acct_cnt   = r["dust_account_count"]
top_receivers   = r["top_dust_receivers"]
anomalies       = r["anomalies"]
anom_count      = len(anomalies)

def render_bps(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def short(addr):
    # Anon addresses are 66 chars; truncate to 10 + "..." for table.
    if isinstance(addr, str) and addr.startswith("0x") and len(addr) >= 10:
        return addr[:10] + "..."
    # Domain names: truncate to 32 chars to keep the column readable.
    if isinstance(addr, str) and len(addr) > 32:
        return addr[:29] + "..."
    return addr

if json_out:
    envelope = {
        "rpc_port":              port,
        "head_height":           head_h,
        "snapshot_block_index":  snap_block_index,
        "snapshot_state_root":   snap_state_root if snap_state_root else None,
        "verify_skipped":        skip_verify,
        "threshold":             threshold,
        "total_accounts":        total,
        "categories": {
            "active": {
                "count": active_cnt,
                "share": (active_cnt    / total) if total > 0 else None,
            },
            "dust_sender": {
                "count": dust_send_cnt,
                "share": (dust_send_cnt / total) if total > 0 else None,
            },
            "dust_receiver": {
                "count": dust_recv_cnt,
                "share": (dust_recv_cnt / total) if total > 0 else None,
            },
            "zero": {
                "count": zero_cnt,
                "share": (zero_cnt      / total) if total > 0 else None,
            },
        },
        "total_dust_value":      total_dust,
        "dust_account_count":    dust_acct_cnt,
        "top_dust_receivers":    top_receivers,
        "top_n":                 top_n,
        "anomalies":             anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_dust_audit: no anomalies (port {port}, threshold {threshold})")
    sys.exit(0)

print(f"=== Dust audit (port {port}) ===")
verify_note = " [verify skipped]" if skip_verify else ""
print(f"Snapshot block: {snap_block_index}{verify_note}")
print(f"Dust threshold: {threshold} (balance <= {threshold} qualifies as dust)")
print(f"Total accounts: {total}")
if total > 0 and not anom_only:
    print("Categories:")
    # Aligned column width chosen so the widest label ("Dust-receiver:")
    # has at least one space of separation from the count.
    fmt = "  {label:<15} {count:>6} ({pct})"
    print(fmt.format(label="Active:",        count=active_cnt,
                     pct=render_bps(r["active_bps"])))
    print(fmt.format(label="Dust-sender:",   count=dust_send_cnt,
                     pct=render_bps(r["dust_sender_bps"])))
    print(fmt.format(label="Dust-receiver:", count=dust_recv_cnt,
                     pct=render_bps(r["dust_receiver_bps"])))
    print(fmt.format(label="Zero:",          count=zero_cnt,
                     pct=render_bps(r["zero_bps"])))

    if top_receivers:
        print(f"Top-{min(top_n, len(top_receivers))} dust receivers (smallest balance first):")
        for d in top_receivers:
            print(f"  {short(d['domain']):<35} balance={d['balance']}")
    else:
        print(f"Top-{top_n} dust receivers: (none; no dust-receiver accounts)")

    print(f"Total dust value: {total_dust} (sum across {dust_acct_cnt} dust accounts)")

print()
if anom_count == 0:
    print("[OK] No mass-dust pattern")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "mass_dust_receivers" in anomalies:
        print(f"  mass_dust_receivers      : {dust_recv_cnt} dust-receiver accounts (> 100 threshold)")
    if "auto_creation_pollution" in anomalies:
        print(f"  auto_creation_pollution  : {zero_cnt} zero accounts = "
              f"{render_bps(r['pollution_bps'])} of total (> 50% threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dust_audit: rendering failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ─────────────────────────────────────────────────
# Same convention as operator_account_growth / operator_anon_address_usage
# / operator_dapp_balance_audit: exit 2 only when --anomalies-only is set
# AND at least one anomaly fired. Default informational mode always
# exits 0 if the snapshot pipeline succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dust_audit: cannot create temp file" >&2; exit 1;
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
