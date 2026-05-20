#!/usr/bin/env bash
# operator_unique_address_audit.sh — Track unique-address activity over
# a block window as a chain-engagement / health metric. Walks the chain
# via `determ block-info <h> --json`, extracts distinct from + to
# addresses from TRANSFER (tx.type == 0) transactions, buckets them
# into fixed-size block ranges, and reports:
#
#   - cumulative-unique-addresses curve over the window (running set
#     size after each bucket — monotone non-decreasing)
#   - per-bucket-active counts (number of distinct addresses that
#     touched at least one TRANSFER in the bucket)
#   - window-total distinct (size of the union over all buckets)
#
# Read-only RPC; safe against a running daemon.
#
# RPC-shape notes (mirror operator_anon_address_usage.sh):
#   - `determ block-info <h> --json` returns the full Block JSON per
#     Block::to_json (src/chain/block.cpp). TRANSFER == 0 per
#     src/chain/block.hpp tx-type enum.
#   - tx.from / tx.to are arbitrary strings (domain names OR anon
#     addresses) — we accept any non-empty string. Anon-address case
#     is canonicalized to lowercase per S-028 so the same key never
#     splits across two case spellings when the operator paste-bombs
#     a mixed-case window into a follow-up tool.
#
# Bucketing:
#   Default bucket size is 100 blocks (--bucket-blocks). The first
#   bucket starts at FROM; the last bucket may be partial (covering
#   fewer than --bucket-blocks blocks) when the window length isn't a
#   multiple of the bucket size. The cumulative curve is reported per
#   bucket boundary, NOT per block, which keeps the human-table output
#   compact for large windows.
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - sudden_drop     a bucket's active count is < 30% of the prior
#                     bucket's count (i.e. > 70% lower). Indicates a
#                     traffic cliff worth investigating: outage,
#                     mempool stall, peer split, or genuine engagement
#                     collapse. The FIRST drop-bucket is flagged.
#   - sudden_spike    a bucket's active count is > 5× the prior
#                     bucket's count. Indicates a traffic surge:
#                     bot wave, airdrop, faucet-drain, or post-outage
#                     catch-up. The FIRST spike-bucket is flagged.
#   Both gates ignore the first bucket (no prior to compare against)
#   and any bucket where the prior bucket had zero active addresses
#   (division-by-zero / undefined ratio — the next bucket can't be a
#   "drop" or a "spike" in any meaningful sense).
#
# Usage:
#   tools/operator_unique_address_audit.sh [--rpc-port N] [--json]
#                                          [--from H] [--to H]
#                                          [--bucket-blocks N]
#                                          [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of audit window (inclusive; default: max(0, tip-1000))
#   --to H              End of audit window   (inclusive; default: tip)
#   --bucket-blocks N   Bucket size in blocks (default: 100; must be > 0)
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_unique_address_audit.sh [--rpc-port N] [--json]
                                        [--from H] [--to H]
                                        [--bucket-blocks N]
                                        [--anomalies-only]

Audit unique-address activity over a block window. Walks the window
via block-info, extracts distinct from + to addresses from TRANSFER
(tx.type == 0) transactions, and reports cumulative-unique-addresses
curve over buckets + per-bucket active counts.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, tip-1000))
  --to H              End of audit window   (default: tip)
  --bucket-blocks N   Bucket size in blocks (default: 100)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  sudden_drop     bucket active count < 30% of prior bucket (>70% lower)
  sudden_spike    bucket active count > 5x prior bucket

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
BUCKET_BLOCKS=100
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";          shift 2 ;;
    --json)            JSON_OUT=1;             shift ;;
    --from)            FROM_H="${2:-}";        shift 2 ;;
    --to)              TO_H="${2:-}";          shift 2 ;;
    --bucket-blocks)   BUCKET_BLOCKS="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;            shift ;;
    *) echo "operator_unique_address_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_unique_address_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_unique_address_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$BUCKET_BLOCKS" in *[!0-9]*|"")
  echo "operator_unique_address_audit: --bucket-blocks must be a positive integer (got '$BUCKET_BLOCKS')" >&2
  exit 1 ;;
esac
if [ "$BUCKET_BLOCKS" -le 0 ]; then
  echo "operator_unique_address_audit: --bucket-blocks must be > 0 (got '$BUCKET_BLOCKS')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_unique_address_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_unique_address_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip.
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_unique_address_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk the window + bucketize ──────────────────────────────────────
# Python driver: handles JSON parse, per-block address extraction
# (TRANSFER tx.from + tx.to), per-bucket distinct-address set
# accumulation, cumulative-set accumulation across buckets, and
# drop/spike anomaly detection at bucket boundaries.
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_unique_address_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$BUCKET_BLOCKS" "$TMP_OUT" <<'PY'
import json, subprocess, sys, re
from collections import defaultdict

determ, port, from_h, to_h, bucket_blocks, out_path = sys.argv[1:7]
from_h        = int(from_h)
to_h          = int(to_h)
bucket_blocks = int(bucket_blocks)

# S-028 anon-address predicate (lowercased canonical form). Domain
# names are passed through unchanged so the same helper is safe to
# call on any tx.from / tx.to string.
ANON_RE = re.compile(r'^0x[0-9a-fA-F]{64}$')

def normalize(s):
    if not isinstance(s, str) or not s:
        return ""
    if ANON_RE.match(s):
        return "0x" + s[2:].lower()
    return s

def tx_type_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return -1
    return -1

# Bucket layout. The first bucket starts at FROM; the last bucket may
# be partial (covering < bucket_blocks blocks). We pre-compute the
# bucket list so the per-block walk just dispatches into the active
# bucket without re-deriving boundaries.
buckets = []  # list of dicts {start, end, addrs:set, active:int}
b_start = from_h
while b_start <= to_h:
    b_end = b_start + bucket_blocks - 1
    if b_end > to_h:
        b_end = to_h
    buckets.append({"start": b_start, "end": b_end, "addrs": set()})
    b_start = b_end + 1

def bucket_for(h):
    # buckets are contiguous + non-overlapping; integer-divide to find
    # the bucket index. O(1) regardless of window size.
    return (h - from_h) // bucket_blocks

# Walk the window block-by-block. We collect distinct TRANSFER
# participants per bucket. Non-TRANSFER tx types (REGISTER, STAKE,
# DAPP_*, etc.) are NOT counted: the spec asks for distinct from + to
# addresses from TRANSFERs specifically (engagement = payment activity).
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_unique_address_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_unique_address_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_unique_address_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    bi = bucket_for(h)
    if bi < 0 or bi >= len(buckets):
        continue
    target = buckets[bi]["addrs"]

    txs = blk.get("transactions") or []
    if isinstance(txs, list):
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            if tx_type_int(tx.get("type")) != 0:
                continue
            sender = tx.get("from", "")
            recv   = tx.get("to", "")
            sn = normalize(sender)
            rn = normalize(recv)
            if sn:
                target.add(sn)
            if rn:
                target.add(rn)

# Per-bucket active count + cumulative running-set. cumulative[i] is
# the size of the union of buckets[0..i].addrs.
running = set()
per_bucket = []
cumulative = []
for b in buckets:
    active = len(b["addrs"])
    running |= b["addrs"]
    per_bucket.append({
        "start":  b["start"],
        "end":    b["end"],
        "blocks": b["end"] - b["start"] + 1,
        "active": active,
    })
    cumulative.append({
        "end":    b["end"],
        "total":  len(running),
    })

window_total = len(running)

# Anomaly detection: drop > 70% (current < 30% of prior) or spike > 5x
# (current > 5 * prior). Skip the first bucket (no prior) and any
# bucket whose prior had zero active addresses (ratio undefined).
anomalies = []
drop_bucket = None
spike_bucket = None
for i in range(1, len(per_bucket)):
    prev = per_bucket[i - 1]["active"]
    cur  = per_bucket[i]["active"]
    if prev <= 0:
        continue
    if drop_bucket is None and cur * 100 < prev * 30:
        drop_bucket = {
            "index": i,
            "start": per_bucket[i]["start"],
            "end":   per_bucket[i]["end"],
            "prior_active": prev,
            "active":       cur,
            "ratio_bps":    cur * 10000 // prev,
        }
        anomalies.append("sudden_drop")
    if spike_bucket is None and cur > prev * 5:
        spike_bucket = {
            "index": i,
            "start": per_bucket[i]["start"],
            "end":   per_bucket[i]["end"],
            "prior_active": prev,
            "active":       cur,
            "ratio_bps":    cur * 10000 // prev,
        }
        anomalies.append("sudden_spike")

result = {
    "window_total":  window_total,
    "per_bucket":    per_bucket,
    "cumulative":    cumulative,
    "anomalies":     anomalies,
    "drop_bucket":   drop_bucket,
    "spike_bucket":  spike_bucket,
    "bucket_blocks": bucket_blocks,
    "bucket_count":  len(per_bucket),
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_unique_address_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 3: anomaly count for exit-code policy ───────────────────────────────
# Pull anomaly count from the python result via jq (preferred) or a
# python fallback so we honor the --anomalies-only gate regardless of
# environment.
if [ "$HAVE_JQ" = "1" ]; then
  ANOM_COUNT=$(jq -r '.anomalies | length' "$TMP_OUT" 2>/dev/null)
else
  ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
print(len(r.get("anomalies", [])))
PY
)
fi
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

# ── Step 4: render envelope (JSON or human table) ────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$HEAD_H" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
port       = int(sys.argv[4])
from_h     = int(sys.argv[5])
to_h       = int(sys.argv[6])
win_blocks = int(sys.argv[7])
head_h     = int(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

anomalies     = r["anomalies"]
anom_count    = len(anomalies)
per_bucket    = r["per_bucket"]
cumulative    = r["cumulative"]
window_total  = r["window_total"]
bucket_blocks = r["bucket_blocks"]
drop_bucket   = r.get("drop_bucket")
spike_bucket  = r.get("spike_bucket")

def render_pct_bps(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def render_ratio_x(bps):
    # bps relative to prior bucket (10000 = 1.0x). Render as "N.Nx".
    whole = bps // 10000
    frac  = (bps % 10000) // 1000
    return f"{whole}.{frac}x"

if json_out:
    envelope = {
        "window": {"from": from_h, "to": to_h, "blocks": win_blocks},
        "bucket_blocks":   bucket_blocks,
        "bucket_count":    r["bucket_count"],
        "window_total":    window_total,
        "per_bucket":      per_bucket,
        "cumulative":      cumulative,
        "anomalies":       anomalies,
        "drop_bucket":     drop_bucket,
        "spike_bucket":    spike_bucket,
        "rpc_port":        port,
        "head_height":     head_h,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_unique_address_audit: no anomalies (port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

print(f"=== Unique address audit (port {port}, window [{from_h}..{to_h}]) ===")
print(f"Distinct addresses (window total): {window_total}")

if not anom_only:
    print("Per-bucket active:")
    if not per_bucket:
        print("  (no buckets in window)")
    else:
        for b in per_bucket:
            print(f"  blocks {b['start']}-{b['end']}: {b['active']} active")
    print("Cumulative unique (running total at each bucket boundary):")
    if not cumulative:
        print("  (no buckets in window)")
    else:
        for c in cumulative:
            print(f"  through block {c['end']}: {c['total']}")

print()
if anom_count == 0:
    print("[OK] Activity stable")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if drop_bucket is not None:
        print(f"  sudden_drop:  blocks {drop_bucket['start']}-{drop_bucket['end']} = "
              f"{drop_bucket['active']} active vs prior {drop_bucket['prior_active']} "
              f"({render_ratio_x(drop_bucket['ratio_bps'])} - threshold <30%)")
    if spike_bucket is not None:
        print(f"  sudden_spike: blocks {spike_bucket['start']}-{spike_bucket['end']} = "
              f"{spike_bucket['active']} active vs prior {spike_bucket['prior_active']} "
              f"({render_ratio_x(spike_bucket['ratio_bps'])} - threshold >5x)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_unique_address_audit: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ──────────────────────────────────────────────────
# Same convention as operator_anon_address_usage / operator_account_growth:
# exit 2 only when --anomalies-only is set AND at least one anomaly
# fired. Default informational mode always exits 0 on a clean walk.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
