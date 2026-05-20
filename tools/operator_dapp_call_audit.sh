#!/usr/bin/env bash
# operator_dapp_call_audit.sh — Audit v2.19 DAPP_CALL activity over a
# window of blocks on a running determ daemon. Call-side counterpart
# to operator_dapp_audit.sh (which audits the DAPP_REGISTER registry).
#
# Walks the requested window via `determ block-info <h> --json` (one
# round-trip per block) and selects transactions where type == 10
# (TxType::DAPP_CALL per include/determ/chain/block.hpp). For each
# DAPP_CALL it extracts {from (caller), to (target DApp domain), amount,
# fee, payload_size, topic, block_index} and reports:
#   - Total DAPP_CALL count + distinct target / caller counts
#   - Total amount routed to DApp owners (apply-side credit leg)
#   - Total fees collected
#   - Per-target call count + amount routed + fees collected (top-10)
#   - Per-caller call count (top-10)
#   - Payload size distribution against MAX_DAPP_CALL_PAYLOAD (16 KB)
#
# Topic field is decoded best-effort from the canonical DAPP_CALL payload
# layout: [topic_len:u8][topic:utf8][ciphertext_len:u32 LE][ciphertext].
#
# RPC-shape note: TxType is serialized to JSON as a numeric int (10 for
# DAPP_CALL per src/chain/block.cpp::Transaction::to_json). For forward
# robustness this script also accepts the string forms "10" and
# "DAPP_CALL" — pattern mirrors operator_param_history.sh's is_param_change
# helper.
#
# Usage:
#   tools/operator_dapp_call_audit.sh [--rpc-port N] [--json]
#                                     [--from H] [--to H]
#                                     [--target-domain D] [--caller D]
#                                     [--anomalies-only]
#
# Options:
#   --rpc-port N         RPC port to query (default: 7778)
#   --json               Emit structured JSON envelope instead of human table
#   --from H             Start of audit window (inclusive; default: max(0, tip-1000))
#   --to H               End of audit window (inclusive; default: tip)
#   --target-domain D    Restrict to calls where tx.to == D (target DApp)
#   --caller D           Restrict to calls where tx.from == D (caller)
#   --anomalies-only     Print only flagged anomalies; exit 2 if any fire
#   -h, --help           Show this help
#
# RPC dependencies (all read-only):
#   - head               (current chain height)
#   - block              (per-block JSON; via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - caller_concentration   single caller > 30% of all calls in window
#                            (Sybil / abuse signal)
#   - target_concentration   single DApp > 50% of all calls (INFORMATIONAL —
#                            normal for a popular DApp; surfaced for
#                            operator awareness, not as an alert by itself)
#   - oversize_payload       any call with payload > MAX_DAPP_CALL_PAYLOAD
#                            (defense-in-depth — the validator should
#                            reject such payloads at apply time; an
#                            observation here means a finalized block
#                            contained one and warrants investigation)
#
# Exit codes (mirrors operator_dapp_audit / operator_subsidy_audit):
#   0   audit ran successfully (including zero DAPP_CALLs in window)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_call_audit.sh [--rpc-port N] [--json]
                                   [--from H] [--to H]
                                   [--target-domain D] [--caller D]
                                   [--anomalies-only]

Audit v2.19 DAPP_CALL activity over a window of blocks. Walks the
window via block-info, selects type==10 transactions, decodes their
canonical payload framing (topic + ciphertext_len), and reports
aggregate routing / fee / payload-size metrics.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --json               Emit structured JSON envelope instead of human table
  --from H             Start of audit window (default: max(0, tip-1000))
  --to H               End of audit window (default: tip)
  --target-domain D    Restrict to calls where tx.to == D
  --caller D           Restrict to calls where tx.from == D
  --anomalies-only     Print only flagged anomalies; exit 2 if any fire
  -h, --help           Show this help

Anomaly flags:
  caller_concentration  single caller > 30% of window calls (abuse signal)
  target_concentration  single DApp > 50% of window calls (informational)
  oversize_payload      any call payload > MAX_DAPP_CALL_PAYLOAD (16 KB);
                        validator should reject such, defense-in-depth flag

Exit codes:
  0   success (or informational mode, including zero DAPP_CALLs)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
TARGET=""
CALLER=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --from)            FROM_H="${2:-}"; shift 2 ;;
    --to)              TO_H="${2:-}";   shift 2 ;;
    --target-domain)   TARGET="${2:-}"; shift 2 ;;
    --caller)          CALLER="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_dapp_call_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_call_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_call_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_call_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dapp_call_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip.
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_call_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk the window in Python (JSON parse + payload decode) ──────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_call_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$TARGET" "$CALLER" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, target_filter, caller_filter, out_path = sys.argv[1:8]
from_h = int(from_h); to_h = int(to_h)

# MAX_DAPP_CALL_PAYLOAD per include/determ/chain/block.hpp (v2.19).
MAX_DAPP_CALL_PAYLOAD = 16384

def is_dapp_call(tx_type):
    # tx.type is serialized to JSON as int per Transaction::to_json
    # (src/chain/block.cpp). Accept string forms for forward robustness
    # (matches the type-tolerance pattern in operator_param_history.sh).
    if isinstance(tx_type, int):  return tx_type == 10
    if isinstance(tx_type, str):  return tx_type in ("10", "DAPP_CALL")
    return False

def decode_topic(hex_str):
    # DAPP_CALL payload layout per include/determ/chain/block.hpp:
    #   [topic_len:u8][topic:utf8]
    #   [ciphertext_len:u32 LE][ciphertext:bytes]
    # Returns (topic, payload_total_bytes) — payload_total = full hex/2.
    # On malformed framing returns ("", payload_total) so we can still
    # surface the call with its raw size for anomaly flagging.
    try:
        p = bytes.fromhex(hex_str)
    except Exception:
        return ("", 0)
    total = len(p)
    if total < 1: return ("", total)
    tl = p[0]
    if 1 + tl > total: return ("", total)
    try:
        topic = p[1:1+tl].decode("utf-8", errors="replace")
    except Exception:
        topic = ""
    return (topic, total)

# Aggregators
total_calls       = 0
total_amount      = 0
total_fees        = 0
oversize_count    = 0
calls_by_target   = defaultdict(lambda: {"calls": 0, "amount": 0, "fees": 0})
calls_by_caller   = defaultdict(int)
size_buckets      = {"le_64": 0, "64_1k": 0, "1k_4k": 0, "4k_16k": 0, "over_16k": 0}
sample_calls      = []   # bounded sample for JSON output (cap below)
SAMPLE_CAP        = 100

def classify_size(n):
    if n <= 64:           return "le_64"
    if n <= 1024:         return "64_1k"
    if n <= 4096:         return "1k_4k"
    if n <= MAX_DAPP_CALL_PAYLOAD: return "4k_16k"
    return "over_16k"

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_dapp_call_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_dapp_call_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_dapp_call_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): continue
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_dapp_call(tx.get("type")): continue
        frm    = tx.get("from", "")
        to     = tx.get("to", "")
        amount = int(tx.get("amount", 0) or 0)
        fee    = int(tx.get("fee", 0) or 0)
        payload_hex = tx.get("payload", "") or ""
        topic, payload_size = decode_topic(payload_hex)
        # Filters
        if target_filter and to  != target_filter: continue
        if caller_filter and frm != caller_filter: continue
        total_calls  += 1
        total_amount += amount
        total_fees   += fee
        calls_by_target[to]["calls"]   += 1
        calls_by_target[to]["amount"]  += amount
        calls_by_target[to]["fees"]    += fee
        calls_by_caller[frm]           += 1
        bucket = classify_size(payload_size)
        size_buckets[bucket] += 1
        if payload_size > MAX_DAPP_CALL_PAYLOAD:
            oversize_count += 1
        if len(sample_calls) < SAMPLE_CAP:
            sample_calls.append({
                "block_index":  h,
                "from":         frm,
                "to":           to,
                "amount":       amount,
                "fee":          fee,
                "payload_size": payload_size,
                "topic":        topic,
            })

# Top-10 targets by call count (ties: by total amount desc, then domain asc).
top_targets = sorted(
    calls_by_target.items(),
    key=lambda kv: (-kv[1]["calls"], -kv[1]["amount"], kv[0])
)[:10]
# Top-10 callers by call count (ties: domain asc).
top_callers = sorted(
    calls_by_caller.items(),
    key=lambda kv: (-kv[1], kv[0])
)[:10]

# Anomaly classification.
anomalies = []
# Caller concentration: > 30% of all calls from one account.
top_caller_pct_bps = 0
top_caller_name    = ""
if total_calls > 0 and top_callers:
    top_caller_name = top_callers[0][0]
    top_caller_pct_bps = top_callers[0][1] * 10000 // total_calls
    if top_caller_pct_bps > 3000:
        anomalies.append("caller_concentration")
# Target concentration: > 50% of all calls to one DApp (informational).
top_target_pct_bps = 0
top_target_name    = ""
if total_calls > 0 and top_targets:
    top_target_name    = top_targets[0][0]
    top_target_pct_bps = top_targets[0][1]["calls"] * 10000 // total_calls
    if top_target_pct_bps > 5000:
        anomalies.append("target_concentration")
# Defense-in-depth: validator should already reject oversize payloads.
if oversize_count > 0:
    anomalies.append("oversize_payload")

result = {
    "total_calls":        total_calls,
    "total_amount":       total_amount,
    "total_fees":         total_fees,
    "distinct_targets":   len(calls_by_target),
    "distinct_callers":   len(calls_by_caller),
    "oversize_count":     oversize_count,
    "top_targets":        [
        {"domain": d, "calls": v["calls"], "amount": v["amount"], "fees": v["fees"]}
        for d, v in top_targets
    ],
    "top_callers":        [{"domain": d, "calls": n} for d, n in top_callers],
    "size_buckets":       size_buckets,
    "anomalies":          anomalies,
    "top_caller_pct_bps": top_caller_pct_bps,
    "top_caller_name":    top_caller_name,
    "top_target_pct_bps": top_target_pct_bps,
    "top_target_name":    top_target_name,
    "sample_calls":       sample_calls,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dapp_call_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 3: render envelope (JSON or human table) ─────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$TARGET" "$CALLER" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
from_h    = int(sys.argv[5])
to_h      = int(sys.argv[6])
win_blocks= int(sys.argv[7])
target_f  = sys.argv[8]
caller_f  = sys.argv[9]

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total      = r["total_calls"]
anomalies  = r["anomalies"]
anom_count = len(anomalies)

def render_pct(bps, total_calls):
    if total_calls <= 0: return "  -  "
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def pct(n, total_calls):
    if total_calls <= 0: return "-"
    bps = n * 10000 // total_calls
    return render_pct(bps, total_calls)

if json_out:
    envelope = {
        "window": {"from": from_h, "to": to_h, "blocks": win_blocks},
        "total":            total,
        "total_amount":     r["total_amount"],
        "total_fees":       r["total_fees"],
        "distinct_targets": r["distinct_targets"],
        "distinct_callers": r["distinct_callers"],
        "by_target":        r["top_targets"],
        "by_caller":        r["top_callers"],
        "payload_distribution": {
            "le_64":    r["size_buckets"]["le_64"],
            "64_1k":    r["size_buckets"]["64_1k"],
            "1k_4k":    r["size_buckets"]["1k_4k"],
            "4k_16k":   r["size_buckets"]["4k_16k"],
            "over_16k": r["size_buckets"]["over_16k"],
        },
        "oversize_count":   r["oversize_count"],
        "top_caller_pct_bps": r["top_caller_pct_bps"],
        "top_caller_name":    r["top_caller_name"],
        "top_target_pct_bps": r["top_target_pct_bps"],
        "top_target_name":    r["top_target_name"],
        "anomalies":        anomalies,
        "filters": {
            "target_domain": target_f if target_f else None,
            "caller":        caller_f if caller_f else None,
        },
        "rpc_port":         port,
        "sample_calls":     r["sample_calls"],
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    flt = ""
    if target_f or caller_f:
        parts = []
        if target_f: parts.append(f"target={target_f}")
        if caller_f: parts.append(f"caller={caller_f}")
        flt = " " + ",".join(parts)
    print(f"operator_dapp_call_audit: no anomalies (port {port}, window [{from_h}..{to_h}]{flt})")
    sys.exit(0)

flt_disp = ""
if target_f or caller_f:
    parts = []
    if target_f: parts.append(f"target={target_f}")
    if caller_f: parts.append(f"caller={caller_f}")
    flt_disp = " " + ",".join(parts)

print(f"=== DAPP_CALL audit (port {port}, window [{from_h}..{to_h}], {win_blocks} blocks{flt_disp}) ===")
print(f"Total DAPP_CALLs: {total}")
print(f"Distinct targets: {r['distinct_targets']} DApps")
print(f"Distinct callers: {r['distinct_callers']} accounts")
print(f"Total amount routed: {r['total_amount']} (to DApp owners)")
print(f"Total fees collected: {r['total_fees']}")

if total > 0 and not anom_only:
    print()
    print("Top targets:")
    if not r["top_targets"]:
        print("  (none)")
    else:
        for t in r["top_targets"]:
            print(f"  {t['domain']}: {t['calls']} calls, {t['amount']} routed, {t['fees']} fees")
    print()
    print("Top callers:")
    if not r["top_callers"]:
        print("  (none)")
    else:
        for c in r["top_callers"]:
            print(f"  {c['domain']}: {c['calls']} calls")
    print()
    print("Payload distribution:")
    bk = r["size_buckets"]
    print(f"  <=64B:     {bk['le_64']} ({pct(bk['le_64'], total)})")
    print(f"  64B-1KB:   {bk['64_1k']} ({pct(bk['64_1k'], total)})")
    print(f"  1KB-4KB:   {bk['1k_4k']} ({pct(bk['1k_4k'], total)})")
    print(f"  4KB-16KB:  {bk['4k_16k']} ({pct(bk['4k_16k'], total)})")
    if bk["over_16k"] > 0:
        print(f"  >16KB:     {bk['over_16k']} ({pct(bk['over_16k'], total)})  [INVALID — exceeds MAX_DAPP_CALL_PAYLOAD]")

print()
if anom_count == 0:
    print("[OK] No concentration anomalies")
else:
    detail = []
    if "caller_concentration" in anomalies:
        detail.append(
            f"caller_concentration: '{r['top_caller_name']}' = "
            f"{render_pct(r['top_caller_pct_bps'], total)} of calls (> 30% threshold)"
        )
    if "target_concentration" in anomalies:
        detail.append(
            f"target_concentration: '{r['top_target_name']}' = "
            f"{render_pct(r['top_target_pct_bps'], total)} of calls (> 50% — informational)"
        )
    if "oversize_payload" in anomalies:
        detail.append(
            f"oversize_payload: {r['oversize_count']} call(s) exceed MAX_DAPP_CALL_PAYLOAD (16 KB); "
            "validator should have rejected — investigate"
        )
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    for d in detail:
        print(f"  - {d}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_call_audit: rendering failed" >&2
  exit 1
fi

# ── Step 4: exit-code policy ──────────────────────────────────────────────────
# Pull anomaly count back via Python (JSON envelope holds the canonical list).
# Stash count in a temp file rather than via $(...) command-substitution
# around a heredoc: keeps the parse simple and avoids subtleties with
# nested heredoc terminators inside command substitution.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_call_audit: cannot create temp file" >&2; exit 1;
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
