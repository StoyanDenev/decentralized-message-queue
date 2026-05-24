#!/usr/bin/env bash
# operator_dapp_health.sh — Per-DApp HEALTH classification audit over a
# window of blocks on a running determ daemon.
#
# Health-side counterpart to:
#   operator_dapp_inventory.sh         compact registry digest
#   operator_dapp_audit.sh             lifecycle ACTIVE / DEACTIVATING /
#                                      INACTIVE (vs DAPP_GRACE_BLOCKS)
#   operator_dapp_balance_audit.sh     accrued balance + revenue
#   operator_dapp_call_audit.sh        per-tx routing flow
#   operator_dapp_message_audit.sh     message volume + topics
#   operator_dapp_health.sh            THIS — HEALTHY / STALE / ZOMBIE /
#                                      DEACTIVATED / ORPHAN classification.
#                                      Operator alert focus: which DApps
#                                      are wasting registry slots (ZOMBIE),
#                                      which are receiving calls after
#                                      deactivation (ORPHAN), which are
#                                      simply quiet (STALE).
#
# Pipeline (read-only RPC):
#   1.  Enumerate registered DApps via `determ dapp-list --json`.
#   2.  Per-DApp full record via `determ dapp-info --domain D --json`
#       (registered_at, active_from, inactive_from, endpoint_url,
#       service_pubkey).
#   3.  Walk the requested block window via `determ block-info <h> --json`
#       once globally and bucket DAPP_CALL (tx.type == 10) transactions
#       by tx.to (target domain). For each DApp this yields
#       last_call_block + call_count over the window.
#   4.  Classify each DApp:
#         HEALTHY      active && last_call within --stale-threshold-blocks
#         STALE        active && (never called || last_call older than
#                                  --stale-threshold-blocks)
#         ZOMBIE       active && registered > --zombie-threshold-blocks ago
#                      && zero calls EVER (window-wide tested; see note)
#         DEACTIVATED  !active && inactive_from is set (post-grace)
#         ORPHAN       !active && >=1 DAPP_CALL observed at block >=
#                      inactive_from (grace-window violation OR replay
#                      attempt — operator alert)
#
# Note on ZOMBIE: "zero calls EVER" is approximated as "zero calls in the
# audit window AND the DApp was registered before the window started"
# (so any pre-window activity would still be captured by the audit-window
# walk only if it falls inside it). For deep-history zombie detection
# operators should widen --last (or use --from 0).
#
# Anomaly flags (--anomalies-only; exit 2 if any CRITICAL fire):
#   - zombie_dapp_detected      (CRITICAL) any DApp in ZOMBIE state.
#                               Registered, never called, sitting on
#                               the registry consuming slot — operator
#                               should encourage deregistration.
#   - orphan_call_detected      (CRITICAL) any DApp in ORPHAN state.
#                               A DAPP_CALL was applied after the DApp's
#                               inactive_from boundary. Either a grace-
#                               window misconfiguration OR a replay attempt
#                               that the apply-layer should have rejected.
#                               Investigate immediately.
#   - stale_dapp_high           (WARN) > 50% of registered DApps in STALE
#                               state. Registry-wide inactivity signal.
#   - mass_deactivation_burst   (INFO) > 5 DApps with inactive_from in
#                               any single 100-block sub-window of the
#                               audit window. Synchronized deregistration
#                               pulse — coordinated event or operator
#                               cleanup; surfaced for awareness.
#
# Exit codes:
#   0   audit ran successfully (no CRITICAL anomalies, OR --anomalies-only
#       with no anomalies firing)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   any CRITICAL anomaly fired (zombie_dapp_detected OR
#       orphan_call_detected); independent of --anomalies-only
#
# Usage:
#   tools/operator_dapp_health.sh --rpc-port N
#     [--from H] [--to H] [--last N]
#     [--stale-threshold-blocks N]
#     [--zombie-threshold-blocks N]
#     [--json] [--anomalies-only]
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_health.sh --rpc-port N
         [--from H] [--to H] [--last N]
         [--stale-threshold-blocks N]
         [--zombie-threshold-blocks N]
         [--json] [--anomalies-only]

Per-DApp HEALTH classification audit. Joins the DApp registry
(dapp-list / dapp-info) against the DAPP_CALL history in the audit
window (block-info walk) and classifies each DApp as HEALTHY, STALE,
ZOMBIE, DEACTIVATED, or ORPHAN.

Options:
  --rpc-port N                   RPC port to query (REQUIRED)
  --from H                       Start of audit window (inclusive)
  --to H                         End of audit window (inclusive; default: tip)
  --last N                       Audit last N blocks (mutually exclusive
                                 with --from; default: 5000)
  --stale-threshold-blocks N     Blocks since last DAPP_CALL above which
                                 an active DApp is STALE (default: 1000)
  --zombie-threshold-blocks N    Active DApps registered more than this
                                 many blocks ago with zero calls in the
                                 window are ZOMBIE (default: 5000)
  --json                         Emit machine-readable JSON envelope
  --anomalies-only               Suppress HEALTHY rows in output; CRITICAL
                                 anomalies still force exit 2
  -h, --help                     Show this help

Classification:
  HEALTHY      active && last_call within --stale-threshold-blocks
  STALE        active && last_call older than threshold (or never called
               but registered within --zombie-threshold-blocks)
  ZOMBIE       active && registered > --zombie-threshold-blocks ago
               && zero calls in window
  DEACTIVATED  !active && inactive_from <= head (past grace)
  ORPHAN       !active && DAPP_CALL observed at block >= inactive_from
               (grace-window violation OR replay attempt)

Anomalies (CRITICAL forces exit 2):
  zombie_dapp_detected     CRITICAL  any DApp in ZOMBIE state
  orphan_call_detected     CRITICAL  any DApp in ORPHAN state
  stale_dapp_high          WARN      > 50% of DApps in STALE state
  mass_deactivation_burst  INFO      > 5 deactivations in any 100-block
                                     sub-window of the audit window

Exit codes:
  0   audit ran, no CRITICAL anomalies (or --anomalies-only + no anomalies)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   CRITICAL anomaly fired (zombie or orphan)
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
STALE_TH=1000
ZOMBIE_TH=5000
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                   usage; exit 0 ;;
    --rpc-port)                  PORT="${2:-}";      shift 2 ;;
    --from)                      FROM_H="${2:-}";    shift 2 ;;
    --to)                        TO_H="${2:-}";      shift 2 ;;
    --last)                      LAST_N="${2:-}";    shift 2 ;;
    --stale-threshold-blocks)    STALE_TH="${2:-}";  shift 2 ;;
    --zombie-threshold-blocks)   ZOMBIE_TH="${2:-}"; shift 2 ;;
    --json)                      JSON_OUT=1;         shift ;;
    --anomalies-only)            ANOM_ONLY=1;        shift ;;
    *) echo "operator_dapp_health: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (refuse to guess for multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_dapp_health: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_health: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_health: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$STALE_TH" in *[!0-9]*|"")
  echo "operator_dapp_health: --stale-threshold-blocks must be a positive integer (got '$STALE_TH')" >&2
  exit 1 ;;
esac
case "$ZOMBIE_TH" in *[!0-9]*|"")
  echo "operator_dapp_health: --zombie-threshold-blocks must be a positive integer (got '$ZOMBIE_TH')" >&2
  exit 1 ;;
esac
if [ "$STALE_TH" -lt 1 ]; then
  echo "operator_dapp_health: --stale-threshold-blocks must be >= 1 (got '$STALE_TH')" >&2
  exit 1
fi
if [ "$ZOMBIE_TH" -lt 1 ]; then
  echo "operator_dapp_health: --zombie-threshold-blocks must be >= 1 (got '$ZOMBIE_TH')" >&2
  exit 1
fi
if [ -n "$FROM_H" ] && [ -n "$LAST_N" ]; then
  echo "operator_dapp_health: --from and --last are mutually exclusive" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path (mirrors operator_dapp_inventory.sh
# pattern — Windows CreateProcessW resolves relative paths differently
# from POSIX exec*() when invoked from python subprocess.run).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip ──────────────────────────────────────────────
HEAD_H=$("$DETERM_ABS" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_health: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dapp_health: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: resolve window ───────────────────────────────────────────────────
# Precedence:
#   1. --from / --to explicit → use as-is (clamp --to to HEAD_H).
#   2. --last N (with optional --to) → window = max(0, TO - N + 1) .. TO.
#   3. Default → max(0, HEAD_H - 4999) .. HEAD_H (last 5000 blocks).
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi

if [ -n "$FROM_H" ]; then
  FROM="$FROM_H"
elif [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -lt 1 ]; then
    echo "operator_dapp_health: --last must be >= 1 (got '$LAST_N')" >&2
    exit 1
  fi
  N1=$(( LAST_N - 1 ))
  if [ "$TO" -gt "$N1" ]; then
    FROM=$(( TO - N1 ))
  else
    FROM=0
  fi
else
  # Default: last 5000 blocks.
  if [ "$TO" -gt 4999 ]; then
    FROM=$(( TO - 4999 ))
  else
    FROM=0
  fi
fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_health: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi

# ── Step 3: enumerate DApps + per-DApp full record + block walk in Python ────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_health: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$HEAD_H" "$STALE_TH" "$ZOMBIE_TH" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, head_h, stale_th, zombie_th, out_path = sys.argv[1:9]
from_h    = int(from_h)
to_h      = int(to_h)
head_h    = int(head_h)
stale_th  = int(stale_th)
zombie_th = int(zombie_th)

# UINT64_MAX sentinel — entry.inactive_from is set to UINT64_MAX on
# initial DAPP_REGISTER and only changes when DAPP_DEREGISTER applies
# (sets it to current_height + DAPP_GRACE_BLOCKS).
UINT64_MAX = (1 << 64) - 1

def run_rpc(args, what):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except Exception as e:
        sys.stderr.write(f"operator_dapp_health: {what} exception: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_dapp_health: {what} rc={r.returncode}: {r.stderr.strip()}\n")
        sys.exit(1)
    try:
        return json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_dapp_health: {what} non-JSON response\n")
        sys.exit(1)

def is_dapp_call(tx_type):
    # tx.type is serialized as int per Transaction::to_json
    # (src/chain/block.cpp). Accept string forms for forward robustness
    # (matches operator_dapp_call_audit.sh's tolerance pattern).
    if isinstance(tx_type, int): return tx_type == 10
    if isinstance(tx_type, str): return tx_type in ("10", "DAPP_CALL")
    return False

# 3a) dapp-list — enumerate every domain on the committed bundle.
list_resp = run_rpc(
    [determ, "dapp-list", "--rpc-port", port],
    "dapp-list")
if not isinstance(list_resp, dict):
    sys.stderr.write("operator_dapp_health: dapp-list not a JSON object\n")
    sys.exit(1)
dapps_raw = list_resp.get("dapps")
if not isinstance(dapps_raw, list):
    sys.stderr.write("operator_dapp_health: dapp-list missing .dapps array\n")
    sys.exit(1)

# 3b) Per-domain dapp-info — extract registered_at + active_from +
# inactive_from + endpoint_url + service_pubkey. Domains that race with
# DAPP_DEREGISTER between dapp-list and dapp-info are silently skipped
# (the registry can mutate between RPC calls).
records = {}
domain_order = []
for entry in dapps_raw:
    if not isinstance(entry, dict): continue
    domain = entry.get("domain")
    if not isinstance(domain, str) or not domain: continue
    if domain in records: continue  # dedupe defensively
    info = run_rpc(
        [determ, "dapp-info", "--domain", domain, "--rpc-port", port],
        f"dapp-info {domain}")
    if isinstance(info, dict) and info.get("error"):
        continue
    try:
        reg_at = int(info.get("registered_at", 0) or 0)
    except Exception:
        reg_at = 0
    try:
        inactive_from = int(info.get("inactive_from", UINT64_MAX) or UINT64_MAX)
    except Exception:
        inactive_from = UINT64_MAX
    try:
        active_from = int(info.get("active_from", 0) or 0)
    except Exception:
        active_from = 0
    svc = str(info.get("service_pubkey", "")) if isinstance(info, dict) else ""
    ep  = str(info.get("endpoint_url",   "")) if isinstance(info, dict) else ""
    records[domain] = {
        "domain":         domain,
        "service_pubkey": svc,
        "endpoint_url":   ep,
        "registered_at":  reg_at,
        "active_from":    active_from,
        "inactive_from":  inactive_from,
        "active":         inactive_from > head_h,
        "last_call_block": None,
        "call_count":     0,
        "calls_after_inactive": 0,   # ORPHAN evidence
    }
    domain_order.append(domain)

# 3c) Block-window walk — single sweep through [FROM..TO], bucketing
# DAPP_CALL transactions by tx.to (target domain). Skip blocks with
# missing/non-existent block-info (defensive — should not happen for
# finalized blocks, but the script must not abort on a single bad block).
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15)
    except Exception as e:
        sys.stderr.write(f"operator_dapp_health: block-info {h} exception: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_dapp_health: block-info {h} rc={r.returncode}: {r.stderr.strip()}\n")
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_dapp_health: block-info {h} non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): continue
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_dapp_call(tx.get("type")): continue
        to_dom = tx.get("to", "")
        if not isinstance(to_dom, str) or not to_dom: continue
        rec = records.get(to_dom)
        if rec is None: continue  # call targeting a domain not in current registry
        rec["call_count"] += 1
        prev = rec["last_call_block"]
        if prev is None or h > prev:
            rec["last_call_block"] = h
        # ORPHAN evidence: call applied at-or-after the inactive_from
        # boundary on a deactivated DApp. The apply-layer should reject
        # this; observation here means either a race at the grace edge
        # or a finalized block contained one and warrants investigation.
        if rec["inactive_from"] != UINT64_MAX and h >= rec["inactive_from"]:
            rec["calls_after_inactive"] += 1

# 3d) Classify each DApp.
#   HEALTHY:     active && last_call within stale_th
#   STALE:       active && (never called || last_call > stale_th old)
#   ZOMBIE:      active && registered > zombie_th ago && call_count == 0
#                (ZOMBIE supersedes STALE — the registry-slot-wasted view
#                 is the operator-actionable signal)
#   DEACTIVATED: !active && inactive_from set (past grace per head_h)
#   ORPHAN:      !active && calls_after_inactive > 0
classified = []
for domain in domain_order:
    rec = records[domain]
    active = rec["active"]
    last_call = rec["last_call_block"]
    if not active:
        # ORPHAN takes precedence over DEACTIVATED.
        if rec["calls_after_inactive"] > 0:
            cls = "ORPHAN"
        else:
            cls = "DEACTIVATED"
    else:
        # ZOMBIE first (subset of STALE with stricter criteria).
        if last_call is None and (head_h - rec["registered_at"]) > zombie_th:
            cls = "ZOMBIE"
        elif last_call is None:
            cls = "STALE"
        else:
            age = head_h - last_call
            if age > stale_th:
                cls = "STALE"
            else:
                cls = "HEALTHY"
    rec["classification"] = cls
    classified.append(rec)

# Summary counts.
counts = defaultdict(int)
for rec in classified:
    counts[rec["classification"]] += 1
total = len(classified)

# Anomalies.
anomalies = []
critical = []

# CRITICAL: zombie_dapp_detected — any ZOMBIE entry.
if counts["ZOMBIE"] > 0:
    anomalies.append("zombie_dapp_detected")
    critical.append("zombie_dapp_detected")

# CRITICAL: orphan_call_detected — any ORPHAN entry.
if counts["ORPHAN"] > 0:
    anomalies.append("orphan_call_detected")
    critical.append("orphan_call_detected")

# WARN: stale_dapp_high — > 50% of DApps in STALE state.
# Computed as integer half-comparison to avoid float; "> 50%" means
# stale_count * 2 > total. Requires total > 0 to avoid spurious fires.
if total > 0 and counts["STALE"] * 2 > total:
    anomalies.append("stale_dapp_high")

# INFO: mass_deactivation_burst — > 5 deactivations in any 100-block
# sub-window of the audit window. We iterate over the in-window
# inactive_from values and slide a 100-block window. Only count
# deactivations that fall inside [FROM..TO] (out-of-window deactivations
# are historical context, not a burst signal for this run).
deact_blocks = sorted(
    rec["inactive_from"] for rec in classified
    if rec["inactive_from"] != UINT64_MAX
       and from_h <= rec["inactive_from"] <= to_h)
mass_burst = False
mass_burst_window = None
if len(deact_blocks) > 5:
    # Two-pointer sweep: for each left pointer, advance right until
    # window > 100 blocks; if (right - left) > 5 anywhere, fire.
    j = 0
    for i in range(len(deact_blocks)):
        if j < i: j = i
        while j < len(deact_blocks) and deact_blocks[j] - deact_blocks[i] < 100:
            j += 1
        # [i .. j-1] inclusive sits inside a 100-block window.
        in_window = j - i
        if in_window > 5:
            mass_burst = True
            mass_burst_window = {
                "start_block": deact_blocks[i],
                "end_block":   deact_blocks[j-1],
                "count":       in_window,
            }
            break
if mass_burst:
    anomalies.append("mass_deactivation_burst")

# Sort: ORPHAN > ZOMBIE > STALE > DEACTIVATED > HEALTHY (operator-priority
# order — actionable items first). Then ties broken by oldest registration.
sort_rank = {"ORPHAN": 0, "ZOMBIE": 1, "STALE": 2, "DEACTIVATED": 3, "HEALTHY": 4}
classified.sort(key=lambda r: (sort_rank.get(r["classification"], 5),
                                r["registered_at"], r["domain"]))

# Serialize. inactive_from of UINT64_MAX is JSON-encoded as null for
# downstream tooling clarity (UINT64_MAX is a sentinel not a real height).
dapps_out = []
for rec in classified:
    inact = rec["inactive_from"]
    dapps_out.append({
        "domain":         rec["domain"],
        "classification": rec["classification"],
        "registered_at":  rec["registered_at"],
        "last_call_block": rec["last_call_block"],
        "call_count":     rec["call_count"],
        "active":         rec["active"],
        "active_from":    rec["active_from"],
        "inactive_from":  None if inact == UINT64_MAX else inact,
        "calls_after_inactive": rec["calls_after_inactive"],
        "endpoint_url":   rec["endpoint_url"],
        "service_pubkey": rec["service_pubkey"],
    })

result = {
    "head_height":      head_h,
    "stale_threshold":  stale_th,
    "zombie_threshold": zombie_th,
    "dapps":            dapps_out,
    "summary": {
        "total":       total,
        "healthy":     counts["HEALTHY"],
        "stale":       counts["STALE"],
        "zombie":      counts["ZOMBIE"],
        "deactivated": counts["DEACTIVATED"],
        "orphan":      counts["ORPHAN"],
    },
    "anomalies":         anomalies,
    "critical_anomalies": critical,
    "mass_burst_detail": mass_burst_window,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  exit 1
fi

# ── Step 4: render envelope (JSON or human table) ────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
from_h    = int(sys.argv[5])
to_h      = int(sys.argv[6])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

dapps     = r["dapps"]
summary   = r["summary"]
anomalies = r["anomalies"]
critical  = r["critical_anomalies"]
mass_det  = r["mass_burst_detail"]

if json_out:
    envelope = {
        "rpc_port":         port,
        "window":           {"from": from_h, "to": to_h},
        "head_height":      r["head_height"],
        "stale_threshold":  r["stale_threshold"],
        "zombie_threshold": r["zombie_threshold"],
        "dapps":            dapps,
        "summary":          summary,
        "anomalies":        anomalies,
        "critical_anomalies": critical,
        "mass_burst_detail":  mass_det,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable.
print(f"=== DApp health audit (port {port}, window [{from_h}..{to_h}], head {r['head_height']}) ===")
print(f"Stale threshold: {r['stale_threshold']} blocks   "
      f"Zombie threshold: {r['zombie_threshold']} blocks")
print(f"Total: {summary['total']}   Healthy: {summary['healthy']}   "
      f"Stale: {summary['stale']}   Zombie: {summary['zombie']}   "
      f"Deactivated: {summary['deactivated']}   Orphan: {summary['orphan']}")
print()

# Filter rows in --anomalies-only mode (suppress HEALTHY rows).
shown = [d for d in dapps if (not anom_only or d["classification"] != "HEALTHY")]

if not shown:
    if anom_only:
        print("(no non-HEALTHY DApps)")
    elif not dapps:
        print("(no DApps registered)")
    else:
        print("(no rows after filtering)")
else:
    header = ("CLASSIFICATION", "DOMAIN", "REG_AT", "LAST_CALL", "CALLS", "INACTIVE_FROM")
    print(f"{header[0]:<14}  {header[1]:<32}  {header[2]:>8}  {header[3]:>10}  {header[4]:>6}  {header[5]:>14}")
    print("-" * 96)
    for d in shown:
        lc = d["last_call_block"]
        lc_disp = "-" if lc is None else str(lc)
        inact = d["inactive_from"]
        inact_disp = "-" if inact is None else str(inact)
        print(f"{d['classification']:<14}  {d['domain']:<32}  "
              f"{d['registered_at']:>8}  {lc_disp:>10}  {d['call_count']:>6}  "
              f"{inact_disp:>14}")

print()
if not anomalies:
    print("[OK] No anomalies")
else:
    print(f"[ANOMALY] {len(anomalies)} flag(s): {','.join(anomalies)}")
    if "zombie_dapp_detected" in anomalies:
        print(f"  - zombie_dapp_detected (CRITICAL): {summary['zombie']} ZOMBIE DApp(s) — "
              "registered, never called, wasting registry slots")
    if "orphan_call_detected" in anomalies:
        print(f"  - orphan_call_detected (CRITICAL): {summary['orphan']} ORPHAN DApp(s) — "
              "DAPP_CALL applied at-or-after inactive_from; investigate grace boundary / replay")
    if "stale_dapp_high" in anomalies:
        pct = summary['stale'] * 100 // summary['total'] if summary['total'] else 0
        print(f"  - stale_dapp_high (WARN): {summary['stale']}/{summary['total']} = "
              f"~{pct}% of DApps STALE — registry-wide inactivity")
    if "mass_deactivation_burst" in anomalies and mass_det:
        print(f"  - mass_deactivation_burst (INFO): {mass_det['count']} deactivations "
              f"in 100-block window [{mass_det['start_block']}..{mass_det['end_block']}]")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_health: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# CRITICAL anomalies (zombie or orphan) force exit 2 regardless of
# --anomalies-only. Non-CRITICAL anomalies (stale_dapp_high WARN,
# mass_deactivation_burst INFO) keep exit 0. This mirrors the convention
# in operator_dapp_balance_audit.sh / operator_dapp_call_audit.sh where
# exit 2 is an operator-alert gate, not a "something was flagged" gate.
#
# Pull the critical-anomaly count back via Python (envelope is the
# canonical source); stash in a temp file to avoid heredoc + command-
# substitution nesting subtleties.
TMP_CRIT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_health: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_CRIT" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_CRIT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(str(len(r.get("critical_anomalies", []))))
PY
CRIT_COUNT=$(cat "$TMP_CRIT" 2>/dev/null)
case "$CRIT_COUNT" in *[!0-9]*|"") CRIT_COUNT=0 ;; esac

if [ "$CRIT_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
