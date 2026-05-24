#!/usr/bin/env bash
# operator_dapp_call_volume_audit.sh — Per-DApp DAPP_CALL call-volume
# + per-sender concentration + spam-burst-detection audit over a
# window of blocks on a running determ daemon.
#
# Scope contrast with neighbouring DApp operator scripts:
#   operator_dapp_inventory.sh        compact registry digest (no
#                                     per-block walk; lifecycle counts
#                                     only)
#   operator_dapp_health.sh           registry + recent-message
#                                     liveness join (no per-call
#                                     aggregation)
#   operator_dapp_balance_audit.sh    accrued-balance + DAPP_CALL
#                                     revenue (joins block-info walk
#                                     against show-account; per-target
#                                     revenue concentration)
#   operator_dapp_message_audit.sh    per-DApp dapp_messages volume +
#                                     topic distribution + lifecycle
#                                     (driven by dapp_messages page
#                                     RPC; no per-sender attribution
#                                     since dapp_messages doesn't
#                                     surface caller spam patterns)
#   operator_dapp_call_audit.sh      window-wide DAPP_CALL routing
#                                     (top-10 callers + targets;
#                                     payload-size + topic decode;
#                                     global anomaly leg only)
#   operator_dapp_call_volume_audit.sh THIS — per-DApp + per-sender call
#                                     concentration with explicit
#                                     spam-burst detection. The
#                                     question this audit asks is
#                                     "for each registered DApp, is
#                                     a SINGLE sender dominating the
#                                     call traffic, and is that
#                                     sender bursting > N calls per
#                                     100-block sub-window?" — i.e.
#                                     a per-DApp Sybil / abuse signal
#                                     missing from the global view in
#                                     operator_dapp_call_audit.sh.
#
# Pipeline (read-only RPC):
#   1.  Resolve current chain head via `determ head --field height`.
#   2.  Enumerate DApps via `determ dapp-list --json` (so we can label
#      the `dormant_dapp_called` anomaly leg: dapp.active=false
#      receiving calls is informational — may indicate a stale client
#      still calling a deregistered DApp or the apply-layer letting
#      a credit through at the DAPP_GRACE boundary).
#   3.  Walk the requested window [FROM..TO] via `determ block-info
#      <h> --json` (one round-trip per block; matches the per-block
#      pattern in operator_dapp_call_audit.sh / operator_dapp_balance_audit.sh).
#      For each transaction with type == 10 (DAPP_CALL per
#      include/determ/chain/block.hpp TxType::DAPP_CALL), aggregate:
#        - per-DApp total_calls
#        - per-DApp unique_senders set
#        - per-DApp per-sender call count (for top-3 + concentration)
#        - per-DApp + per-sender sliding 100-block sub-window
#          burst counts (rolling counter, indexed by sub-window
#          floor((h - FROM) / 100))
#   4.  Per DApp: compute sender_concentration_ratio = top-1 sender
#      count / total_calls (Herfindahl-like single-sender dominance
#      measure; matches the global caller_concentration leg in
#      operator_dapp_call_audit.sh but scoped per-DApp so a single-
#      DApp Sybil attack isn't masked by aggregate noise).
#   5.  Cross-reference each DApp against the dapp-list registry-active
#      flag to label `dormant_dapp_called`.
#
# Per-DApp report fields (sorted by total_calls desc, then domain asc):
#   - domain                       DApp address (the call target)
#   - total_calls                  count of DAPP_CALL where tx.to == domain
#   - unique_senders               distinct tx.from count
#   - top_3_senders                [{sender, calls}, ...] descending
#   - sender_concentration_ratio   bps (0..10000); top-1 sender's
#                                  share of this DApp's total calls
#   - max_sender_burst_per_100_blk peak count of calls from any single
#                                  sender within ANY 100-block sub-
#                                  window (anchored at FROM); 0 if
#                                  no calls
#   - max_sender_burst_sender      sender address that achieved
#                                  max_sender_burst_per_100_blk
#                                  (empty string if 0)
#   - max_sender_burst_window_start  block index where the burst sub-
#                                    window starts (-1 if 0)
#   - dapp_active                  registry-active flag (dapp-list)
#
# Aggregates / summary:
#   - total_calls                  sum across all DApps in window
#   - total_dapps_called           count of distinct target DApps with
#                                  > 0 in-window calls
#   - total_dapps_registered       registered DApps (dapp-list size)
#
# Anomaly flags (printed in human mode + present in JSON):
#   - single_sender_dominant       WARN — any DApp with
#                                  sender_concentration_ratio >
#                                  --sender-concentration-threshold
#                                  (default 0.30). Per-DApp Sybil /
#                                  abuse signal.
#   - dapp_spam_burst              WARN — any DApp with a single sender
#                                  emitting > 100 DAPP_CALLs within
#                                  any 100-block sub-window. Rate-
#                                  control / Sybil signal independent
#                                  of long-term concentration.
#   - dormant_dapp_called          INFO — DApp with dapp.active=false
#                                  receiving non-zero in-window calls.
#                                  Either a stale client still pointing
#                                  at a deregistered DApp, or a credit
#                                  slipped through at the DAPP_GRACE
#                                  boundary (paired with
#                                  inactive_with_recent_revenue in
#                                  operator_dapp_balance_audit.sh).
#
# RPC dependencies (all read-only):
#   - head                         current chain height
#   - dapp_list                    registered DApps + active flag
#   - block                        per-block walk (via block-info)
#
# Usage:
#   tools/operator_dapp_call_volume_audit.sh --rpc-port N
#     [--from H] [--to H] [--last N]
#     [--sender-concentration-threshold F]
#     [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N                          RPC port (REQUIRED)
#   --from H                              Start block of audit window
#                                         (default: max(0, head - 999))
#   --to H                                End block of audit window
#                                         (default: head). If both --last
#                                         and --from/--to are given,
#                                         --from/--to take precedence.
#   --last N                              Convenience: audit last N blocks
#                                         (default: 1000). Equivalent to
#                                         --from max(0, head-N+1) --to head.
#   --sender-concentration-threshold F   Fraction (0..1) at which a
#                                         single sender dominating a
#                                         DApp's calls fires
#                                         single_sender_dominant
#                                         (default: 0.30).
#   --json                                Emit machine-readable JSON envelope.
#   --anomalies-only                      Print only anomaly lines; exit 2
#                                         if any fire.
#   -h, --help                            Show this help.
#
# Exit codes (mirrors operator_dapp_call_audit / operator_dapp_message_audit):
#   0   audit ran successfully (no anomalies OR anomalies in default mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_call_volume_audit.sh --rpc-port N
         [--from H] [--to H] [--last N]
         [--sender-concentration-threshold F]
         [--json] [--anomalies-only]

Per-DApp DAPP_CALL call-volume + per-sender concentration audit with
spam-burst (100-block sub-window) detection. Walks the requested
window via block-info, filters tx.type == 10, aggregates per-DApp +
per-(DApp,sender), and flags single-sender dominance + spam-burst
patterns.

Options:
  --rpc-port N                         RPC port (REQUIRED)
  --from H                             Window start (default: max(0, head - 999))
  --to H                               Window end   (default: head)
  --last N                             Convenience for --from/--to (default: 1000)
  --sender-concentration-threshold F   0..1, fires single_sender_dominant
                                       when a DApp's top-1 sender's share
                                       exceeds it (default: 0.30)
  --json                               Emit machine-readable JSON envelope
  --anomalies-only                     Print only anomaly lines; exit 2 if any fire
  -h, --help                           Show this help

Anomaly flags:
  single_sender_dominant   WARN — DApp with top-1 sender share > threshold
  dapp_spam_burst          WARN — single sender > 100 calls / 100-block sub-window
  dormant_dapp_called      INFO — dapp.active=false DApp receiving in-window calls

Exit codes:
  0   success (with or without anomalies in default mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
FROM_H=""
TO_H=""
LAST_N=""
SENDER_CONC_THRESH="0.30"
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                                usage; exit 0 ;;
    --rpc-port)                               PORT="${2:-}";              shift 2 ;;
    --from)                                   FROM_H="${2:-}";            shift 2 ;;
    --to)                                     TO_H="${2:-}";              shift 2 ;;
    --last)                                   LAST_N="${2:-}";            shift 2 ;;
    --sender-concentration-threshold)         SENDER_CONC_THRESH="${2:-}"; shift 2 ;;
    --json)                                   JSON_OUT=1;                 shift ;;
    --anomalies-only)                         ANOM_ONLY=1;                shift ;;
    *) echo "operator_dapp_call_volume_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port required (per sibling operator script convention; refuses
# to silently guess on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_dapp_call_volume_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_call_volume_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_call_volume_audit: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && [ "$LAST_N" -lt 1 ]; then
  echo "operator_dapp_call_volume_audit: --last must be >= 1 (got '$LAST_N')" >&2
  exit 1
fi
# Float-shape guard for sender-concentration threshold; full numeric
# range check lives in the Python pass (which can render bps properly).
case "$SENDER_CONC_THRESH" in
  ""|*[!0-9.]*|*.*.*)
    echo "operator_dapp_call_volume_audit: --sender-concentration-threshold must be a number in [0,1] (got '$SENDER_CONC_THRESH')" >&2
    exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to absolute path (some Windows shells trip on relative
# paths inside subprocess.run — mirror operator_dapp_message_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current chain head ────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_call_volume_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dapp_call_volume_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window resolution. --from / --to take precedence over --last;
# --last defaults to 1000 if neither is given.
if [ -z "$FROM_H" ] && [ -z "$TO_H" ]; then
  N_LAST=${LAST_N:-1000}
  if [ "$HEAD_H" -ge "$N_LAST" ]; then
    FROM=$(( HEAD_H - N_LAST + 1 ))
  else
    FROM=0
  fi
  TO=$HEAD_H
else
  if [ -n "$FROM_H" ]; then
    FROM="$FROM_H"
  else
    # --to given but no --from: derive --from from --last (or its default).
    N_LAST=${LAST_N:-1000}
    TO_TMP=${TO_H:-$HEAD_H}
    if [ "$TO_TMP" -ge "$N_LAST" ]; then
      FROM=$(( TO_TMP - N_LAST + 1 ))
    else
      FROM=0
    fi
  fi
  TO=${TO_H:-$HEAD_H}
fi
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_call_volume_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: enumerate DApps ───────────────────────────────────────────────────
TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_call_volume_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_call_volume_audit: cannot create temp file" >&2
  rm -f "$TMP_LIST" 2>/dev/null
  exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" dapp-list --rpc-port "$PORT" > "$TMP_LIST" 2>/dev/null; then
  echo "operator_dapp_call_volume_audit: dapp-list RPC failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: walk window in Python (block-info per block; aggregate) ──────────
python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_LIST" \
         "$SENDER_CONC_THRESH" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_s, to_s, list_path,
 sender_conc_s, out_path) = sys.argv[1:8]
from_h     = int(from_s)
to_h       = int(to_s)

# Validate threshold range (the shell layer only checks shape).
try:
    sender_conc_thresh = float(sender_conc_s)
except Exception:
    sys.stderr.write(
        f"operator_dapp_call_volume_audit: --sender-concentration-threshold "
        f"not a float ({sender_conc_s})\n")
    sys.exit(1)
if sender_conc_thresh < 0.0 or sender_conc_thresh > 1.0:
    sys.stderr.write(
        f"operator_dapp_call_volume_audit: --sender-concentration-threshold "
        f"must be in [0,1] (got {sender_conc_thresh})\n")
    sys.exit(1)
# bps = basis points (10000ths) for comparable integer math with the
# rest of the operator-script family.
sender_conc_thresh_bps = int(round(sender_conc_thresh * 10000))

# Sub-window size for the dapp_spam_burst gate. Anchored at --from
# (block (from_h + k*100) .. (from_h + (k+1)*100 - 1)) so deterministic
# w.r.t. window boundaries; this keeps the test fixtures stable.
SPAM_BURST_WINDOW    = 100
SPAM_BURST_THRESHOLD = 100   # > 100 calls / 100-block sub-window → fires

def is_dapp_call(tx_type):
    # tx.type is serialized to JSON as int per Transaction::to_json
    # (src/chain/block.cpp). Accept string forms for forward robustness
    # (matches operator_dapp_call_audit.sh's is_dapp_call helper).
    if isinstance(tx_type, int):  return tx_type == 10
    if isinstance(tx_type, str):  return tx_type in ("10", "DAPP_CALL")
    return False

# ── Load dapp-list ──────────────────────────────────────────────────────────
try:
    with open(list_path, "r", encoding="utf-8") as f:
        listed = json.load(f)
except Exception as e:
    sys.stderr.write(
        f"operator_dapp_call_volume_audit: dapp-list parse failed: {e}\n")
    sys.exit(1)

dapps_listed = listed.get("dapps")
if not isinstance(dapps_listed, list):
    sys.stderr.write(
        "operator_dapp_call_volume_audit: dapp-list missing .dapps array\n")
    sys.exit(1)

# Index registry-active flag per domain (active iff inactive_from >
# current head; dapp-list already pre-computes this).
registered_active = {}
for d in dapps_listed:
    if isinstance(d, dict):
        dom = d.get("domain")
        if isinstance(dom, str) and dom:
            registered_active[dom] = bool(d.get("active", False))

# ── Walk window ─────────────────────────────────────────────────────────────
# Per-DApp aggregators.
per_dapp_total       = defaultdict(int)
per_dapp_senders     = defaultdict(set)            # domain -> {sender,...}
per_dapp_sender_cnt  = defaultdict(lambda: defaultdict(int))   # [domain][sender]
# Per-(dapp, sender) sub-window bursts: [domain][sender][window_idx] -> count.
per_dapp_sender_bw   = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(
            f"operator_dapp_call_volume_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_dapp_call_volume_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(
            f"operator_dapp_call_volume_audit: block-info {h} non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): continue
    win_idx = (h - from_h) // SPAM_BURST_WINDOW
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_dapp_call(tx.get("type")): continue
        sender = str(tx.get("from", "") or "")
        target = str(tx.get("to",   "") or "")
        if not target: continue
        per_dapp_total[target]                       += 1
        per_dapp_senders[target].add(sender)
        per_dapp_sender_cnt[target][sender]          += 1
        per_dapp_sender_bw[target][sender][win_idx]  += 1

# ── Compose per-DApp records ────────────────────────────────────────────────
per_dapp = []
for target, total in per_dapp_total.items():
    senders_map  = per_dapp_sender_cnt[target]
    # Top-3 senders by count, ties broken by sender address asc.
    sorted_senders = sorted(senders_map.items(),
                            key=lambda kv: (-kv[1], kv[0]))
    top3 = [{"sender": s, "calls": c} for s, c in sorted_senders[:3]]

    top1_count = sorted_senders[0][1] if sorted_senders else 0
    sender_conc_bps = (top1_count * 10000 // total) if total > 0 else 0

    # Peak burst across all (sender, sub-window) cells.
    burst_max    = 0
    burst_sender = ""
    burst_win    = -1
    for s, win_map in per_dapp_sender_bw[target].items():
        for w, n in win_map.items():
            if n > burst_max:
                burst_max    = n
                burst_sender = s
                burst_win    = w
    burst_window_start = (from_h + burst_win * SPAM_BURST_WINDOW
                          if burst_win >= 0 else -1)

    # Registry-active flag; default True for unregistered targets (we
    # only flag dormant_dapp_called for KNOWN-inactive DApps to avoid
    # firing on the common "DApp registered after the audit started"
    # case).
    is_active_in_reg = registered_active.get(target, True)

    per_dapp.append({
        "domain":                        target,
        "total_calls":                   total,
        "unique_senders":                len(per_dapp_senders[target]),
        "top_3_senders":                 top3,
        "sender_concentration_ratio_bps": sender_conc_bps,
        "max_sender_burst_per_100_blk":  burst_max,
        "max_sender_burst_sender":       burst_sender,
        "max_sender_burst_window_start": burst_window_start,
        "dapp_active":                   is_active_in_reg,
    })

# Sort per-DApp by total_calls desc, then domain asc (deterministic).
per_dapp.sort(key=lambda d: (-d["total_calls"], d["domain"]))

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []

single_sender_offenders = [
    d for d in per_dapp
    if d["total_calls"] > 0
    and d["sender_concentration_ratio_bps"] > sender_conc_thresh_bps
]
if single_sender_offenders:
    anomalies.append("single_sender_dominant")

spam_burst_offenders = [
    d for d in per_dapp
    if d["max_sender_burst_per_100_blk"] > SPAM_BURST_THRESHOLD
]
if spam_burst_offenders:
    anomalies.append("dapp_spam_burst")

dormant_called_offenders = [
    d for d in per_dapp
    if d["total_calls"] > 0 and (not d["dapp_active"])
]
if dormant_called_offenders:
    anomalies.append("dormant_dapp_called")

# ── Summary ────────────────────────────────────────────────────────────────
total_calls_global = sum(d["total_calls"] for d in per_dapp)
result = {
    "window": {"from": from_h, "to": to_h, "blocks": to_h - from_h + 1},
    "dapps":  per_dapp,
    "summary": {
        "total_calls":                  total_calls_global,
        "total_dapps_called":           sum(1 for d in per_dapp if d["total_calls"] > 0),
        "total_dapps_registered":       len(registered_active),
        "sender_concentration_threshold_bps": sender_conc_thresh_bps,
        "spam_burst_window_blocks":     SPAM_BURST_WINDOW,
        "spam_burst_threshold":         SPAM_BURST_THRESHOLD,
        "single_sender_offenders":      [d["domain"] for d in single_sender_offenders],
        "spam_burst_offenders":         [d["domain"] for d in spam_burst_offenders],
        "dormant_called_offenders":     [d["domain"] for d in dormant_called_offenders],
        "anomalies":                    anomalies,
    },
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dapp_call_volume_audit: aggregation pass failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human) ───────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" \
         "$WIN_BLOCKS" "$SENDER_CONC_THRESH" <<'PY'
import json, sys

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
out_path      = sys.argv[3]
port          = int(sys.argv[4])
from_h        = int(sys.argv[5])
to_h          = int(sys.argv[6])
win_blocks    = int(sys.argv[7])
sender_thresh = float(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

summary    = r["summary"]
anomalies  = summary["anomalies"]
anom_count = len(anomalies)

def render_pct_bps(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = {
        "window":     r["window"],
        "dapps": [
            {
                "domain":                         d["domain"],
                "total_calls":                    d["total_calls"],
                "unique_senders":                 d["unique_senders"],
                "top_3_senders":                  d["top_3_senders"],
                "sender_concentration_ratio":     render_pct_bps(d["sender_concentration_ratio_bps"]),
                "sender_concentration_ratio_bps": d["sender_concentration_ratio_bps"],
                "max_sender_burst_per_100_blk":   d["max_sender_burst_per_100_blk"],
                "max_sender_burst_sender":        d["max_sender_burst_sender"],
                "max_sender_burst_window_start":  d["max_sender_burst_window_start"],
                "dapp_active":                    d["dapp_active"],
            } for d in r["dapps"]
        ],
        "summary": {
            "total_calls":                  summary["total_calls"],
            "total_dapps_called":           summary["total_dapps_called"],
            "total_dapps_registered":       summary["total_dapps_registered"],
            "sender_concentration_threshold":     render_pct_bps(summary["sender_concentration_threshold_bps"]),
            "sender_concentration_threshold_bps": summary["sender_concentration_threshold_bps"],
            "spam_burst_window_blocks":     summary["spam_burst_window_blocks"],
            "spam_burst_threshold":         summary["spam_burst_threshold"],
            "single_sender_offenders":      summary["single_sender_offenders"],
            "spam_burst_offenders":         summary["spam_burst_offenders"],
            "dormant_called_offenders":     summary["dormant_called_offenders"],
            "anomalies":                    anomalies,
        },
        "rpc_port":  port,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_dapp_call_volume_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {win_blocks} blocks)")
    sys.exit(0)

print(f"=== DApp call-volume audit (port {port}, window [{from_h}..{to_h}], "
      f"{win_blocks} blocks; sender-concentration-threshold={sender_thresh:.2f}) ===")
print(f"Total DAPP_CALLs: {summary['total_calls']}")
print(f"Distinct target DApps called: {summary['total_dapps_called']} "
      f"(of {summary['total_dapps_registered']} registered)")

if not anom_only:
    # Per-DApp summary table.
    print()
    if not r["dapps"] or summary["total_calls"] == 0:
        print("(no DAPP_CALL traffic in window)")
    else:
        print("Per-DApp call volume:")
        for d in r["dapps"]:
            top1 = d["top_3_senders"][0] if d["top_3_senders"] else None
            top1_disp = (f"{top1['sender']} ({top1['calls']})"
                         if top1 else "-")
            active_disp = "active" if d["dapp_active"] else "INACTIVE"
            print(f"  {d['domain']:32s}  "
                  f"calls={d['total_calls']:>7}  "
                  f"unique_senders={d['unique_senders']:>5}  "
                  f"top1_share={render_pct_bps(d['sender_concentration_ratio_bps']):>6s}  "
                  f"burst/100blk={d['max_sender_burst_per_100_blk']:>5}  "
                  f"[{active_disp}]")
            # Top-3 detail.
            for s in d["top_3_senders"]:
                print(f"      sender={s['sender']:48s}  calls={s['calls']:>6}")
            if d["max_sender_burst_per_100_blk"] > 0:
                print(f"      peak burst: sender={d['max_sender_burst_sender']} "
                      f"@ window start={d['max_sender_burst_window_start']} "
                      f"({d['max_sender_burst_per_100_blk']} calls / 100 blk)")

# Anomaly lines.
print()
if anom_count == 0:
    print("[OK] No anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "single_sender_dominant" in anomalies:
        thresh_bps = summary["sender_concentration_threshold_bps"]
        offenders = summary["single_sender_offenders"]
        print(f"  - single_sender_dominant: {len(offenders)} DApp(s) with "
              f"top-1 sender share > {render_pct_bps(thresh_bps)} (WARN)")
        for d in r["dapps"]:
            if d["domain"] in offenders:
                top1 = d["top_3_senders"][0]
                print(f"      {d['domain']}: top sender={top1['sender']} "
                      f"({top1['calls']}/{d['total_calls']} = "
                      f"{render_pct_bps(d['sender_concentration_ratio_bps'])})")
    if "dapp_spam_burst" in anomalies:
        offenders = summary["spam_burst_offenders"]
        thresh    = summary["spam_burst_threshold"]
        win       = summary["spam_burst_window_blocks"]
        print(f"  - dapp_spam_burst: {len(offenders)} DApp(s) with "
              f"> {thresh} calls / {win}-block sub-window from a single sender (WARN)")
        for d in r["dapps"]:
            if d["domain"] in offenders:
                print(f"      {d['domain']}: sender={d['max_sender_burst_sender']} "
                      f"burst={d['max_sender_burst_per_100_blk']} calls "
                      f"@ window start={d['max_sender_burst_window_start']}")
    if "dormant_dapp_called" in anomalies:
        offenders = summary["dormant_called_offenders"]
        print(f"  - dormant_dapp_called: {len(offenders)} INACTIVE DApp(s) "
              f"receiving in-window calls (INFO — stale client / grace-boundary race)")
        for d in r["dapps"]:
            if d["domain"] in offenders:
                print(f"      {d['domain']}: calls={d['total_calls']}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_call_volume_audit: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ──────────────────────────────────────────────────
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_call_volume_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(str(len(r["summary"].get("anomalies", []))))
PY
ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
