#!/usr/bin/env bash
# operator_dapp_balance_audit.sh — Audit the *accrued balance* state of
# each registered DApp on a running determ daemon. Balance-side
# counterpart to operator_dapp_audit.sh (registration lifecycle) and
# operator_dapp_call_audit.sh (per-tx routing flow); this script asks
# the orthogonal question "where did the money end up?" by joining
# the DApp registry against the chain account state and the recent
# DAPP_CALL credit history.
#
# Pipeline (read-only RPC):
#   1.  Enumerate DApps via `determ dapp-list --json` (compact registry
#       walk; lock-free path Node::rpc_dapp_list).
#   2.  For each DApp domain D, fetch `determ show-account D --json`
#       — the v2.19 apply-side DAPP_CALL credit lands on accounts_[D]
#       (Chain::apply, src/chain/chain.cpp ~L1215), so the domain
#       address IS the DApp owner's accrued-balance account. Returned
#       record carries {address, is_anonymous, balance, next_nonce,
#       stake, registry: {ed_pub, registered_at, active_from,
#       inactive_from}}.
#   3.  Walk the requested block window [FROM..TO] via
#       `determ block-info <h> --json` and accumulate DAPP_CALL
#       inflows per target domain (tx.type == 10 && tx.to == D);
#       this gives the "revenue accrued in window" leg.
#   4.  Cross-reference: also fetch `determ dapp-info --domain D
#       --json` for status classification (ACTIVE / DEACTIVATING /
#       INACTIVE per inactive_from vs current height). dapp-list
#       already returns a coarse `active` bool, but the lifecycle
#       split mirrors operator_dapp_audit.sh for consistency.
#
# Per-DApp report fields:
#   - balance         current accrued balance (show-account.balance)
#   - revenue         sum of DAPP_CALL tx.amount routed to this DApp
#                     within the requested window
#   - revenue_pct     percent of total in-window revenue (0..100)
#   - status          ACTIVE / DEACTIVATING / INACTIVE
#   - nonce           current next_nonce (operator-spend indicator)
#   - stake_locked    operator-side stake locked (typically 0 for
#                     non-validator DApp owners; non-zero indicates
#                     the DApp owner is also a registered validator)
#
# Aggregates:
#   - total_dapps                    count of registered DApps
#   - total_revenue                  sum of DAPP_CALL amounts in window
#   - top_by_revenue                 top-10 DApps by revenue in window
#   - top_by_balance                 top-10 DApps by current balance
#
# Anomaly flags (--anomalies-only; exit 2 if any fire):
#   - inactive_with_recent_revenue   INACTIVE DApp with non-zero
#                                    in-window revenue. After
#                                    DAPP_GRACE_BLOCKS the apply-layer
#                                    drops new DAPP_CALL credits
#                                    (Chain::apply rejects when
#                                    inactive_from <= height); so this
#                                    should be empty in steady state.
#                                    Any hit warrants investigation
#                                    (race vs deregister at grace
#                                    boundary, or a malformed validator
#                                    let a credit through).
#   - zero_balance_with_revenue      DApp balance == 0 but revenue > 0
#                                    in window. Informational — most
#                                    commonly indicates the operator
#                                    has already moved/swept the funds
#                                    via TRANSFER. Not a bug; surfaced
#                                    so operators notice forwarded
#                                    revenue streams.
#   - revenue_concentration          single DApp > 50% of total window
#                                    revenue. Informational — normal
#                                    for a popular DApp, but worth
#                                    surfacing for capacity planning
#                                    + Sybil-target awareness.
#
# RPC dependencies (all read-only):
#   - dapp_list                      registry enumeration
#   - dapp_info                      per-DApp lifecycle detail
#   - account                        per-DApp balance / nonce / stake
#   - block                          per-block walk (DAPP_CALL credits)
#   - head                           current chain height
#
# Usage:
#   tools/operator_dapp_balance_audit.sh [--rpc-port N] [--json]
#                                        [--from H] [--to H]
#                                        [--prefix STR] [--topic STR]
#                                        [--anomalies-only]
#
# Exit codes (mirrors operator_dapp_audit / operator_dapp_call_audit):
#   0   audit ran successfully (including zero DApps)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_balance_audit.sh [--rpc-port N] [--json]
                                      [--from H] [--to H]
                                      [--prefix STR] [--topic STR]
                                      [--anomalies-only]

Audit the accrued balance state of each registered DApp. Joins the
DApp registry (dapp-list / dapp-info) against the apply-side credit
account (show-account) and the recent DAPP_CALL revenue history
(block-info walk). Reports per-DApp balance + window revenue +
status, plus aggregates (total revenue, top-10 by revenue, top-10
by balance).

Options:
  --rpc-port N       RPC port to query (default: 7778)
  --json             Emit structured JSON envelope instead of human table
  --from H           Start of revenue window (inclusive; default: max(0, tip-1000))
  --to H             End of revenue window (inclusive; default: tip)
  --prefix STR       Pass-through dapp-list domain-prefix filter
  --topic STR        Pass-through dapp-list topic filter
  --anomalies-only   Print only flagged anomalies; exit 2 if any fire
  -h, --help         Show this help

Anomaly flags:
  inactive_with_recent_revenue   INACTIVE DApp with non-zero in-window revenue
                                 (apply-layer should reject post-grace; investigate)
  zero_balance_with_revenue      DApp balance == 0 but revenue > 0 (operator
                                 may have swept funds; informational)
  revenue_concentration          single DApp > 50% of in-window total revenue
                                 (informational — normal for popular DApps)

Exit codes:
  0   success (including zero DApps in registry)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
PREFIX=""
TOPIC=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --from)            FROM_H="${2:-}"; shift 2 ;;
    --to)              TO_H="${2:-}";   shift 2 ;;
    --prefix)          PREFIX="${2:-}"; shift 2 ;;
    --topic)           TOPIC="${2:-}";  shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_dapp_balance_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_balance_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_balance_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_balance_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dapp_balance_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip.
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_balance_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: enumerate DApps ──────────────────────────────────────────────────
TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_balance_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_balance_audit: cannot create temp file" >&2
  rm -f "$TMP_LIST" 2>/dev/null
  exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" 2>/dev/null' EXIT

LIST_ARGS=("dapp-list" "--rpc-port" "$PORT")
[ -n "$PREFIX" ] && LIST_ARGS+=("--prefix" "$PREFIX")
[ -n "$TOPIC" ]  && LIST_ARGS+=("--topic"  "$TOPIC")
if ! "$DETERM" "${LIST_ARGS[@]}" > "$TMP_LIST" 2>/dev/null; then
  echo "operator_dapp_balance_audit: RPC error querying dapp-list (port $PORT)" >&2
  exit 1
fi

# ── Step 3: drive the rest of the pipeline in Python ─────────────────────────
# Python handles: dapp_list parse, per-DApp show-account + dapp-info,
# block-window walk for DAPP_CALL credits, aggregates, anomaly classification.
# Single process keeps the RPC round-trip count proportional to
# (num_dapps * 2 + window_blocks), no per-DApp shell-fork overhead.
python - "$DETERM" "$PORT" "$FROM" "$TO" "$HEAD_H" "$TMP_LIST" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, head_h, list_path, out_path = sys.argv[1:8]
from_h = int(from_h); to_h = int(to_h); head_h = int(head_h)

# UINT64_MAX sentinel value used for inactive_from on never-deactivated entries.
UINT64_MAX = (1 << 64) - 1

def is_dapp_call(tx_type):
    # tx.type is serialized as int per Transaction::to_json
    # (src/chain/block.cpp). Accept string forms for forward robustness,
    # mirroring operator_dapp_call_audit.sh's tolerance.
    if isinstance(tx_type, int):  return tx_type == 10
    if isinstance(tx_type, str):  return tx_type in ("10", "DAPP_CALL")
    return False

# ── Load dapp-list ──────────────────────────────────────────────────
try:
    with open(list_path, "r", encoding="utf-8") as f:
        listed = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_dapp_balance_audit: dapp-list JSON parse failed: {e}\n")
    sys.exit(1)

dapps_listed = listed.get("dapps")
if not isinstance(dapps_listed, list):
    sys.stderr.write("operator_dapp_balance_audit: malformed dapp-list (no .dapps array)\n")
    sys.exit(1)

domains = [d.get("domain", "") for d in dapps_listed if isinstance(d, dict)]
domains = [d for d in domains if d]

# ── Per-DApp queries: show-account + dapp-info ──────────────────────
per_dapp = {}  # domain -> dict of attrs
for domain in domains:
    # show-account D --json (RPC method "account")
    try:
        r = subprocess.run(
            [determ, "show-account", domain, "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_dapp_balance_audit: show-account {domain} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_dapp_balance_audit: show-account {domain} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        acct = json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception:
        sys.stderr.write(
            f"operator_dapp_balance_audit: show-account {domain} returned non-JSON\n")
        sys.exit(1)
    # null / empty object => no on-chain state. This can happen for a
    # freshly-registered DApp that hasn't received any DAPP_CALL credit
    # yet. We still want a row for it (balance=0, status from dapp-info).
    if acct is None or acct == {}:
        balance, nonce, stake, owner_pubkey = 0, 0, 0, ""
    else:
        balance = int(acct.get("balance", 0) or 0)
        nonce   = int(acct.get("next_nonce", 0) or 0)
        stake   = int(acct.get("stake", 0) or 0)
        # owner_pubkey == the registrant's ed25519 pubkey. Comes from
        # the registry entry (registrants[]). For a DApp domain that's
        # also a registered validator this is populated; otherwise null.
        reg = acct.get("registry")
        owner_pubkey = (reg or {}).get("ed_pub", "") if isinstance(reg, dict) else ""

    # dapp-info D --json (RPC method "dapp_info")
    try:
        r = subprocess.run(
            [determ, "dapp-info", "--domain", domain, "--rpc-port", port,
             "--json"],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(
            f"operator_dapp_balance_audit: dapp-info {domain} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_dapp_balance_audit: dapp-info {domain} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        info = json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception:
        sys.stderr.write(
            f"operator_dapp_balance_audit: dapp-info {domain} returned non-JSON\n")
        sys.exit(1)
    # Skip entries that errored (race vs deregister). dapp-info returns
    # {error:"not_found", domain:D} on miss.
    if isinstance(info, dict) and info.get("error"):
        continue
    inactive_from = int(info.get("inactive_from", UINT64_MAX) or 0)
    registered_at = int(info.get("registered_at", 0) or 0)
    # Status classification mirrors operator_dapp_audit.sh:
    #   ACTIVE       inactive_from == UINT64_MAX
    #   DEACTIVATING inactive_from > head_h (in grace)
    #   INACTIVE     inactive_from <= head_h (past grace)
    if inactive_from == UINT64_MAX:
        status = "ACTIVE"
    elif inactive_from > head_h:
        status = "DEACTIVATING"
    else:
        status = "INACTIVE"

    per_dapp[domain] = {
        "domain":         domain,
        "balance":        balance,
        "nonce":          nonce,
        "stake_locked":   stake,
        "owner_pubkey":   owner_pubkey,
        "registered_at":  registered_at,
        "inactive_from":  inactive_from,
        "status":         status,
        "revenue":        0,
        "revenue_pct":    0,   # bps; filled after block walk
        "call_count":     0,
    }

# ── Window walk: accumulate DAPP_CALL revenue per target domain ─────
total_revenue = 0
total_calls   = 0
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_dapp_balance_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_dapp_balance_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_dapp_balance_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): continue
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_dapp_call(tx.get("type")): continue
        to = tx.get("to", "")
        amount = int(tx.get("amount", 0) or 0)
        if to in per_dapp:
            per_dapp[to]["revenue"]    += amount
            per_dapp[to]["call_count"] += 1
            total_revenue              += amount
            total_calls                += 1
        # else: DAPP_CALL targeting a domain not currently in dapp-list
        # (e.g. registry mutation between list and walk, or filtered
        # out by --prefix/--topic). Skip — out of scope for this audit
        # since we only care about CURRENTLY-registered DApps.

# Compute revenue percentage (bps) per DApp.
for d in per_dapp.values():
    if total_revenue > 0:
        d["revenue_pct"] = d["revenue"] * 10000 // total_revenue
    else:
        d["revenue_pct"] = 0

# Sort dispatch: rendering order is by revenue desc, then balance desc,
# then domain asc (deterministic ordering).
sorted_dapps = sorted(
    per_dapp.values(),
    key=lambda d: (-d["revenue"], -d["balance"], d["domain"])
)
top_by_revenue = sorted(
    per_dapp.values(),
    key=lambda d: (-d["revenue"], -d["balance"], d["domain"])
)[:10]
top_by_balance = sorted(
    per_dapp.values(),
    key=lambda d: (-d["balance"], -d["revenue"], d["domain"])
)[:10]

# ── Anomaly classification ──────────────────────────────────────────
anomalies = []
inactive_with_revenue_list = []
zero_balance_with_revenue_list = []
top_revenue_pct_bps = 0
top_revenue_name = ""

for d in per_dapp.values():
    if d["status"] == "INACTIVE" and d["revenue"] > 0:
        inactive_with_revenue_list.append(
            {"domain": d["domain"], "revenue": d["revenue"],
             "inactive_from": d["inactive_from"]})
    if d["balance"] == 0 and d["revenue"] > 0:
        zero_balance_with_revenue_list.append(
            {"domain": d["domain"], "revenue": d["revenue"]})

if inactive_with_revenue_list:
    anomalies.append("inactive_with_recent_revenue")
if zero_balance_with_revenue_list:
    anomalies.append("zero_balance_with_revenue")
# Concentration: single DApp > 50% of total revenue
if top_by_revenue and total_revenue > 0:
    top_revenue_name    = top_by_revenue[0]["domain"]
    top_revenue_pct_bps = top_by_revenue[0]["revenue_pct"]
    if top_revenue_pct_bps > 5000:
        anomalies.append("revenue_concentration")

result = {
    "total_dapps":          len(per_dapp),
    "total_revenue":        total_revenue,
    "total_calls":          total_calls,
    "per_dapp":             sorted_dapps,
    "top_by_revenue":       top_by_revenue,
    "top_by_balance":       top_by_balance,
    "anomalies":            anomalies,
    "inactive_with_revenue":   inactive_with_revenue_list,
    "zero_balance_with_revenue": zero_balance_with_revenue_list,
    "top_revenue_name":     top_revenue_name,
    "top_revenue_pct_bps":  top_revenue_pct_bps,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dapp_balance_audit: audit pipeline failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human table) ────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$PREFIX" "$TOPIC" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
from_h    = int(sys.argv[5])
to_h      = int(sys.argv[6])
win_blocks= int(sys.argv[7])
prefix_f  = sys.argv[8]
topic_f   = sys.argv[9]

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total_dapps   = r["total_dapps"]
total_revenue = r["total_revenue"]
anomalies     = r["anomalies"]
anom_count    = len(anomalies)

def render_pct_bps(bps):
    # bps integer (basis points). Render as "NN.N%".
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = {
        "window": {"from": from_h, "to": to_h, "blocks": win_blocks},
        "total_dapps":      total_dapps,
        "total_revenue":    total_revenue,
        "total_calls":      r["total_calls"],
        "per_dapp":         r["per_dapp"],
        "top_by_revenue":   r["top_by_revenue"],
        "top_by_balance":   r["top_by_balance"],
        "anomalies":        anomalies,
        "inactive_with_revenue":     r["inactive_with_revenue"],
        "zero_balance_with_revenue": r["zero_balance_with_revenue"],
        "top_revenue_name":          r["top_revenue_name"],
        "top_revenue_pct_bps":       r["top_revenue_pct_bps"],
        "filters": {
            "prefix": prefix_f if prefix_f else None,
            "topic":  topic_f  if topic_f  else None,
        },
        "rpc_port":         port,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
flt_disp = ""
if prefix_f or topic_f:
    parts = []
    if prefix_f: parts.append(f"prefix={prefix_f}")
    if topic_f:  parts.append(f"topic={topic_f}")
    flt_disp = " " + ",".join(parts)

if anom_only and anom_count == 0:
    print(f"operator_dapp_balance_audit: no anomalies (port {port}, "
          f"window [{from_h}..{to_h}]{flt_disp})")
    sys.exit(0)

print(f"=== DApp balance audit (port {port}, "
      f"window [{from_h}..{to_h}], {win_blocks} blocks{flt_disp}) ===")
print(f"Total DApps: {total_dapps}")
print(f"Total revenue routed in window: {total_revenue}")
print(f"Total DAPP_CALLs in window:     {r['total_calls']}")

if total_dapps > 0 and not anom_only:
    print()
    print("Per-DApp (sorted by revenue desc):")
    for d in r["per_dapp"]:
        pct_str = render_pct_bps(d["revenue_pct"]) if total_revenue > 0 else "-"
        print(f"  {d['domain']:32s}  "
              f"balance={d['balance']:>14}  "
              f"revenue={d['revenue']:>14} ({pct_str:>6} of total)  "
              f"calls={d['call_count']:>5}  "
              f"[{d['status']}]")

    if r["top_by_revenue"]:
        print()
        print("Top by revenue:")
        for d in r["top_by_revenue"]:
            pct_str = render_pct_bps(d["revenue_pct"]) if total_revenue > 0 else "-"
            print(f"  {d['domain']:32s}  revenue={d['revenue']} ({pct_str})  "
                  f"calls={d['call_count']}  [{d['status']}]")

    if r["top_by_balance"]:
        print()
        print("Top by balance:")
        for d in r["top_by_balance"]:
            print(f"  {d['domain']:32s}  balance={d['balance']}  "
                  f"stake_locked={d['stake_locked']}  [{d['status']}]")

print()
if anom_count == 0:
    print("[OK] No anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "inactive_with_recent_revenue" in anomalies:
        cnt = len(r["inactive_with_revenue"])
        print(f"  - inactive_with_recent_revenue: {cnt} DApp(s) had revenue "
              "despite being past DAPP_GRACE_BLOCKS")
        for d in r["inactive_with_revenue"][:5]:
            print(f"      {d['domain']}: revenue={d['revenue']} "
                  f"(inactive_from={d['inactive_from']})")
    if "zero_balance_with_revenue" in anomalies:
        cnt = len(r["zero_balance_with_revenue"])
        print(f"  - zero_balance_with_revenue: {cnt} DApp(s) had revenue but "
              "zero current balance (operator may have moved funds)")
        for d in r["zero_balance_with_revenue"][:5]:
            print(f"      {d['domain']}: revenue={d['revenue']}, balance=0")
    if "revenue_concentration" in anomalies:
        pct_str = render_pct_bps(r["top_revenue_pct_bps"])
        print(f"  - revenue_concentration: '{r['top_revenue_name']}' "
              f"= {pct_str} of total revenue (> 50% — informational)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_balance_audit: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ──────────────────────────────────────────────────
# Pull anomaly count from JSON envelope (canonical list).
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_balance_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
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
