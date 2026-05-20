#!/usr/bin/env bash
# operator_dapp_registration_audit.sh — Chronological audit of
# DAPP_REGISTER (TxType=9) activity over a block window. Walks each
# block in [--from, --to], filters DAPP_REGISTER txs, classifies each
# as first-time-create / update / deactivate, aggregates per-bucket
# counts and top-N registration prefixes, and (with --anomalies-only)
# flags Sybil / burst / mass-deactivation patterns.
#
# Sibling of operator_dapp_audit.sh (which inspects the current
# registry STATE) and operator_param_history.sh (which audits a
# different tx type, PARAM_CHANGE, over the chain). This script
# audits DAPP_REGISTER FLOWS instead of STATE.
#
# Classification rules:
#   first-time create — DAPP_REGISTER op=0 where tx.from has no prior
#                       successful op=0 in the scan window AND was not
#                       already in dapp_registry_ at scan start. The
#                       "not already in registry at scan start" check
#                       is approximated by checking the daemon's
#                       current dapp_registry_ membership — entries
#                       present at scan start but absent now are
#                       classified as first-time IF this scan covered
#                       the only registration; for partial windows we
#                       may misclassify an update as first-time. This
#                       is a documented limitation; full accuracy
#                       requires scanning from genesis.
#   update            — DAPP_REGISTER op=0 where tx.from has had at
#                       least one prior successful op=0 in the scan
#                       window OR is currently in dapp_registry_.
#   deactivate        — DAPP_REGISTER op=1.
#
# Read-only RPC; safe against any running daemon.
#
# Usage:
#   tools/operator_dapp_registration_audit.sh
#       [--rpc-port N]
#       [--from HEIGHT]      # default: head - 1000
#       [--to HEIGHT]        # default: head
#       [--bucket-size N]    # block-window for per-bucket histogram
#                            # (default: 100)
#       [--top-prefixes N]   # how many prefixes in the top-N
#                            # (default: 10)
#       [--prefix-depth N]   # prefix-grouping: take the first N
#                            # dot-segments of each domain
#                            # (default: 1, i.e. "news.foo.bar" -> "news.")
#       [--anomalies-only]   # only emit the anomalies block; suppress
#                            # the full histogram + top-prefix output
#       [--json]             # JSON envelope instead of human-readable
#
# Anomaly rules (--anomalies-only or always in JSON output):
#   - burst        : > 50 first-time registrations in a single bucket
#                    of width 100 blocks (thresholds scale with
#                    --bucket-size: threshold = 50 * (bucket_size/100))
#   - sybil_sender : a single tx.from accounts for > 30% of all
#                    DAPP_REGISTER txs in the scan window (needs >= 10
#                    total to fire)
#   - mass_deact   : > 20 deactivations in any 100-block bucket
#                    (threshold scales with --bucket-size)
#
# RPC dependencies (all read-only):
#   - head
#   - block-info <h> --json
#   - dapp-list (to disambiguate first-time vs update at scan start)
#
# Exit codes:
#   0   success, no anomalies (or --anomalies-only and clean)
#   2   success, but anomalies detected
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_registration_audit.sh
       [--rpc-port N] [--from HEIGHT] [--to HEIGHT]
       [--bucket-size N] [--top-prefixes N] [--prefix-depth N]
       [--anomalies-only] [--json]

Chronological audit of DAPP_REGISTER (TxType=9) activity over a block
window. Walks each block in [--from, --to], filters DAPP_REGISTER txs,
classifies each as first-time-create / update / deactivate, aggregates
per-bucket counts and top-N registration prefixes, and flags Sybil /
burst / mass-deactivation patterns.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --from HEIGHT        Start of scan range (inclusive; default: head-1000)
  --to HEIGHT          End of scan range (inclusive; default: head)
  --bucket-size N      Block-window for per-bucket histogram (default: 100)
  --top-prefixes N     How many prefixes in the top-N (default: 10)
  --prefix-depth N     Take the first N dot-segments of each domain
                       (default: 1; e.g. "news.foo.bar" with depth=1
                       groups under "news.")
  --anomalies-only     Suppress full histogram + top-prefix output;
                       emit only the anomalies block
  --json               Emit structured JSON envelope instead of table
  -h, --help           Show this help

Anomaly rules:
  burst        — > 50 first-time creates in any one 100-block bucket
                 (threshold scales: 50 * bucket_size/100)
  sybil_sender — single tx.from > 30% of all DAPP_REGISTER txs
                 (needs >= 10 total to fire)
  mass_deact   — > 20 deactivations in any 100-block bucket
                 (threshold scales)

Exit codes:
  0   success, no anomalies
  2   success, anomalies detected
  1   RPC error / daemon unreachable / malformed response / bad args
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
BUCKET_SIZE=100
TOP_PREFIXES=10
PREFIX_DEPTH=1
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";          shift 2 ;;
    --from)           FROM_H="${2:-}";        shift 2 ;;
    --to)             TO_H="${2:-}";          shift 2 ;;
    --bucket-size)    BUCKET_SIZE="${2:-}";   shift 2 ;;
    --top-prefixes)   TOP_PREFIXES="${2:-}";  shift 2 ;;
    --prefix-depth)   PREFIX_DEPTH="${2:-}";  shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;            shift ;;
    --json)           JSON_OUT=1;             shift ;;
    *) echo "operator_dapp_registration_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guard for user-supplied integer args.
for pair in "from:$FROM_H" "to:$TO_H" "bucket-size:$BUCKET_SIZE" \
            "top-prefixes:$TOP_PREFIXES" "prefix-depth:$PREFIX_DEPTH"; do
  k="${pair%%:*}"
  v="${pair#*:}"
  if [ -n "$v" ]; then
    case "$v" in
      *[!0-9]*)
        echo "operator_dapp_registration_audit: --${k} must be an unsigned integer (got '$v')" >&2
        exit 1 ;;
    esac
  fi
done

if [ "${BUCKET_SIZE:-0}" -lt 1 ] 2>/dev/null; then
  echo "operator_dapp_registration_audit: --bucket-size must be >= 1" >&2
  exit 1
fi
if [ "${TOP_PREFIXES:-0}" -lt 1 ] 2>/dev/null; then
  echo "operator_dapp_registration_audit: --top-prefixes must be >= 1" >&2
  exit 1
fi
if [ "${PREFIX_DEPTH:-0}" -lt 1 ] 2>/dev/null; then
  echo "operator_dapp_registration_audit: --prefix-depth must be >= 1" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_dapp_registration_audit: requires 'jq' (not found on PATH)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_dapp_registration_audit: requires 'python' or 'python3' (not found on PATH)" >&2
  exit 1
fi
PYTHON=python
if ! command -v python >/dev/null 2>&1; then PYTHON=python3; fi

# Resolve current head height.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_registration_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*)
  echo "operator_dapp_registration_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at head. Clamp.
if [ -z "$TO_H" ];   then TO=$HEAD_H;   else TO=$TO_H; fi
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ -z "$FROM_H" ]; then
  if [ "$HEAD_H" -ge 1000 ] 2>/dev/null; then
    FROM=$((HEAD_H - 1000))
  else
    FROM=0
  fi
else
  FROM=$FROM_H
fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_registration_audit: --from ($FROM) > --to ($TO); nothing to scan" >&2
  exit 1
fi

# Snapshot the current registry membership: used to disambiguate
# first-time vs update for senders whose only op=0 in the window is
# their FIRST occurrence (no prior in-window observation).
REG_OUT=$("$DETERM" dapp-list --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_registration_audit: RPC error querying dapp-list (port $PORT)" >&2
  exit 1
}
REG_DOMAINS=$(printf '%s' "$REG_OUT" | jq -r '.dapps[]?.domain // empty')

TMP_DIR=$(mktemp -d 2>/dev/null) || {
  echo "operator_dapp_registration_audit: cannot create temp dir" >&2; exit 1;
}
trap 'rm -rf "$TMP_DIR" 2>/dev/null' EXIT
TMP_REG="$TMP_DIR/reg.txt"
TMP_TXS="$TMP_DIR/txs.jsonl"
: > "$TMP_REG"
: > "$TMP_TXS"
if [ -n "$REG_DOMAINS" ]; then
  printf '%s\n' "$REG_DOMAINS" > "$TMP_REG"
fi

# Scan blocks and emit one JSON line per DAPP_REGISTER tx. Decode the
# op byte (and domain when op=0) inline so the renderer doesn't have
# to re-parse hex. See block.hpp TxType::DAPP_REGISTER for layout:
#   [op:u8]
#   if op == 0: [service_pubkey:32B][endpoint_len:u8][endpoint:utf8]
#               [topic_count:u8] topic_count*{[topic_len:u8][topic:utf8]}
#               [retention:u8][metadata_len:u16 LE][metadata:bytes]
#   if op == 1: (no further bytes — tx.from identifies the entry)
# tx.from carries the DApp's owning DETERM domain.
"$PYTHON" - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_TXS" <<'PY' || {
  echo "operator_dapp_registration_audit: block scan failed" >&2; exit 1;
}
import json, subprocess, sys

determ, port, from_h, to_h, out_path = sys.argv[1:6]
from_h = int(from_h); to_h = int(to_h)

def is_dapp_register(tx_type):
    # TxType::DAPP_REGISTER = 9. May render as int 9 or string "9"
    # or "DAPP_REGISTER" depending on RPC version.
    if isinstance(tx_type, int): return tx_type == 9
    if isinstance(tx_type, str): return tx_type in ("9", "DAPP_REGISTER")
    return False

def decode_payload(hex_str):
    # Returns dict with op (int) and (only for op=0) endpoint, topics,
    # retention. Topic info is informational only; we don't use it
    # for classification, just expose it for JSON output.
    try:
        p = bytes.fromhex(hex_str or "")
    except Exception:
        return {"op": None, "error": "non-hex payload"}
    if len(p) < 1:
        return {"op": None, "error": "empty payload"}
    o = 0
    op = p[o]; o += 1
    if op == 1:
        return {"op": 1}
    if op != 0:
        return {"op": op, "error": f"unknown op {op}"}
    # op == 0: parse the remaining structure best-effort.
    out = {"op": 0}
    if len(p) < o + 32:
        out["error"] = "truncated service_pubkey"; return out
    o += 32  # service_pubkey
    if len(p) < o + 1:
        out["error"] = "truncated endpoint_len"; return out
    el = p[o]; o += 1
    if len(p) < o + el:
        out["error"] = "truncated endpoint"; return out
    try:
        out["endpoint"] = p[o:o+el].decode("utf-8", errors="replace")
    except Exception:
        out["endpoint"] = ""
    o += el
    if len(p) < o + 1:
        return out  # rest is optional from our PoV
    tc = p[o]; o += 1
    topics = []
    for _ in range(tc):
        if len(p) < o + 1: break
        tl = p[o]; o += 1
        if len(p) < o + tl: break
        topics.append(p[o:o+tl].decode("utf-8", errors="replace"))
        o += tl
    out["topics"] = topics
    return out

rows = []
fail_count = 0
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=10
        )
    except Exception as e:
        sys.stderr.write(f"operator_dapp_registration_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_dapp_registration_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_dapp_registration_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_dapp_register(tx.get("type")): continue
        dec = decode_payload(tx.get("payload", ""))
        row = {
            "height": h,
            "from":   tx.get("from", ""),
            "op":     dec.get("op"),
        }
        if "endpoint" in dec: row["endpoint"] = dec["endpoint"]
        if "topics" in dec:   row["topics"]   = dec["topics"]
        if "error" in dec:    row["decode_error"] = dec["error"]
        rows.append(row)

with open(out_path, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")
PY

# Aggregate + render. Single Python pass handles classification,
# bucketing, prefix top-N, anomaly detection, and final emission in
# either human or JSON form. Keeping it in one script makes
# JSON/human output identical for downstream consumers. Python's
# exit code is propagated verbatim (0 clean / 2 anomaly / 1 error).
"$PYTHON" - "$JSON_OUT" "$ANOM_ONLY" "$PORT" "$FROM" "$TO" \
              "$BUCKET_SIZE" "$TOP_PREFIXES" "$PREFIX_DEPTH" \
              "$TMP_TXS" "$TMP_REG" <<'PY'
import json, sys, os
from collections import Counter, defaultdict

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
port          = sys.argv[3]
from_h        = int(sys.argv[4])
to_h          = int(sys.argv[5])
bucket_size   = int(sys.argv[6])
top_n         = int(sys.argv[7])
prefix_depth  = int(sys.argv[8])
txs_path      = sys.argv[9]
reg_path      = sys.argv[10]

# Load pre-existing registry membership at scan time.
existing_at_scan = set()
if os.path.exists(reg_path):
    with open(reg_path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln: existing_at_scan.add(ln)

# Load txs.
txs = []
with open(txs_path, "r", encoding="utf-8") as f:
    for ln in f:
        ln = ln.rstrip("\n")
        if not ln: continue
        try:
            txs.append(json.loads(ln))
        except Exception:
            continue

# Sort by (height, then array-position-implicit). We've already
# emitted in scan order, but be defensive.
txs.sort(key=lambda r: r["height"])

# Classify. Track which senders we've already seen op=0 for in-window:
# the first op=0 in-window for a sender NOT in existing_at_scan is a
# first-time create; otherwise it's an update. Deactivations are
# unambiguous (op=1).
seen_op0 = set()
n_first = 0
n_update = 0
n_deact = 0
n_decode_err = 0
classified = []
sender_counts = Counter()
for tx in txs:
    op = tx.get("op")
    snd = tx.get("from", "")
    sender_counts[snd] += 1
    if "decode_error" in tx:
        n_decode_err += 1
        cls = "decode_error"
    elif op == 1:
        n_deact += 1
        cls = "deactivate"
    elif op == 0:
        if snd in seen_op0 or snd in existing_at_scan:
            n_update += 1
            cls = "update"
        else:
            n_first += 1
            cls = "first_time"
        seen_op0.add(snd)
    else:
        n_decode_err += 1
        cls = "decode_error"
    tx["class"] = cls
    classified.append(tx)

total = len(classified)

# Per-bucket distribution. Bucket b covers heights
# [from_h + b*bucket_size, from_h + (b+1)*bucket_size). Last bucket
# may be partial — that's fine for histogram purposes.
buckets = defaultdict(lambda: {
    "start": 0, "end": 0,
    "total": 0, "first_time": 0, "update": 0, "deactivate": 0
})
total_span = (to_h - from_h + 1)
n_buckets = (total_span + bucket_size - 1) // bucket_size
for b in range(n_buckets):
    s = from_h + b * bucket_size
    e = min(s + bucket_size - 1, to_h)
    buckets[b]["start"] = s
    buckets[b]["end"]   = e

for tx in classified:
    b = (tx["height"] - from_h) // bucket_size
    buckets[b]["total"] += 1
    if tx["class"] == "first_time":  buckets[b]["first_time"] += 1
    elif tx["class"] == "update":    buckets[b]["update"]     += 1
    elif tx["class"] == "deactivate":buckets[b]["deactivate"] += 1

bucket_list = []
for b in range(n_buckets):
    e = buckets[b]
    bucket_list.append({
        "bucket":     b,
        "start":      e["start"],
        "end":        e["end"],
        "total":      e["total"],
        "first_time": e["first_time"],
        "update":     e["update"],
        "deactivate": e["deactivate"],
    })

# Top-N registration prefixes. Prefix is the first --prefix-depth
# dot-segments of the SENDER domain (tx.from), with a trailing "."
# appended when the depth is shallower than the segment count.
def domain_prefix(d, depth):
    if not d: return ""
    parts = d.split(".")
    if depth >= len(parts):
        return d
    return ".".join(parts[:depth]) + "."

prefix_counts = Counter()
for tx in classified:
    if tx["class"] in ("first_time", "update"):
        prefix_counts[domain_prefix(tx["from"], prefix_depth)] += 1
top_prefixes = [
    {"prefix": p, "count": c}
    for p, c in prefix_counts.most_common(top_n)
]

# Anomaly detection. Burst + mass-deact thresholds scale linearly
# with bucket_size (rules baseline at 100).
burst_thresh   = int(50 * (bucket_size / 100.0)) if bucket_size > 0 else 50
massdeact_thresh = int(20 * (bucket_size / 100.0)) if bucket_size > 0 else 20
# Don't let scaling drive the threshold to 0 for tiny buckets.
burst_thresh   = max(burst_thresh, 1)
massdeact_thresh = max(massdeact_thresh, 1)

anomalies = []
for b in bucket_list:
    if b["first_time"] > burst_thresh:
        anomalies.append({
            "type": "burst",
            "bucket": b["bucket"],
            "range": [b["start"], b["end"]],
            "first_time": b["first_time"],
            "threshold": burst_thresh,
            "detail": (f"{b['first_time']} first-time creates in bucket "
                       f"[{b['start']}..{b['end']}] exceeds threshold "
                       f"{burst_thresh}"),
        })
    if b["deactivate"] > massdeact_thresh:
        anomalies.append({
            "type": "mass_deact",
            "bucket": b["bucket"],
            "range": [b["start"], b["end"]],
            "deactivate": b["deactivate"],
            "threshold": massdeact_thresh,
            "detail": (f"{b['deactivate']} deactivations in bucket "
                       f"[{b['start']}..{b['end']}] exceeds threshold "
                       f"{massdeact_thresh}"),
        })

# Sybil: any single sender > 30% of all DAPP_REGISTER (>= 10 floor).
if total >= 10:
    for snd, c in sender_counts.most_common(5):
        pct = (c * 100.0) / total
        if pct > 30.0:
            anomalies.append({
                "type": "sybil_sender",
                "from": snd,
                "count": c,
                "total": total,
                "pct": round(pct, 2),
                "detail": (f"sender '{snd}' accounts for {c}/{total} "
                           f"DAPP_REGISTER txs ({pct:.1f}%) — Sybil pattern"),
            })

anomaly_flag = bool(anomalies)
exit_code = 2 if anomaly_flag else 0

if json_out:
    envelope = {
        "rpc_port":         int(port),
        "scan_from":        from_h,
        "scan_to":          to_h,
        "bucket_size":      bucket_size,
        "prefix_depth":     prefix_depth,
        "total":            total,
        "first_time":       n_first,
        "update":           n_update,
        "deactivate":       n_deact,
        "decode_error":     n_decode_err,
        "buckets":          bucket_list,
        "top_prefixes":     top_prefixes,
        "anomalies":        anomalies,
        "anomaly_flag":     anomaly_flag,
    }
    if not anom_only:
        # Include the per-tx classified rows only when not suppressed.
        envelope["transactions"] = classified
    print(json.dumps(envelope, indent=2))
    sys.exit(exit_code)

# Human-readable rendering.
print(f"=== DApp registration audit (port {port}, window [{from_h}..{to_h}]) ===")
print(f"Total DAPP_REGISTER txs: {total}")
print(f"First-time creates: {n_first}")
print(f"Updates: {n_update}")
print(f"Deactivations: {n_deact}")
if n_decode_err:
    print(f"Decode errors: {n_decode_err}")

if not anom_only:
    print()
    print("Per-bucket distribution:")
    if not bucket_list:
        print("  (no buckets — empty range)")
    else:
        header = (f"  {'bucket':>6}  {'range':<22}  "
                  f"{'total':>5}  {'first':>5}  {'updt':>5}  {'deact':>5}")
        print(header)
        print("  " + "-" * (len(header) - 2))
        # Only emit non-empty buckets to keep large windows readable.
        any_nonempty = False
        for b in bucket_list:
            if b["total"] == 0: continue
            any_nonempty = True
            print(f"  {b['bucket']:>6}  "
                  f"[{b['start']:>7}..{b['end']:>7}]  "
                  f"{b['total']:>5}  {b['first_time']:>5}  "
                  f"{b['update']:>5}  {b['deactivate']:>5}")
        if not any_nonempty:
            print("  (no DAPP_REGISTER activity in window)")
    print()
    if top_prefixes:
        items = ", ".join(f"'{p['prefix']}' ({p['count']})" for p in top_prefixes)
        print(f"Top prefixes: {items}")
    else:
        print("Top prefixes: (none)")

print()
if anomaly_flag:
    print("[ANOMALY] Detected:")
    for a in anomalies:
        print(f"  - [{a['type']}] {a['detail']}")
else:
    print("[OK] No anomalies")

sys.exit(exit_code)
PY
exit $?
