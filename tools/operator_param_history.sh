#!/usr/bin/env bash
# operator_param_history.sh — A5 governance PARAM_CHANGE chronological
# audit log. Scans the chain for every PARAM_CHANGE tx that landed
# on-chain, decodes its (parameter_name, new_value, effective_height)
# payload, and prints a time-ordered table or JSON envelope. Optional
# --include-pending also lists changes staged-but-not-yet-active via
# the pending-params RPC.
#
# A5 governance is a permissioned PARAM_CHANGE mechanism: an N-of-N
# (or M-of-N) keyholder multisig stages a (name, value) update that
# activates at a specified effective_height. Pre-activation entries
# show up in `determ pending-params`; post-activation entries are
# only visible as on-chain PARAM_CHANGE transactions inside the block
# they landed in. This script unifies both views into one audit log.
#
# Usage:
#   tools/operator_param_history.sh [--rpc-port N] [--json]
#                                   [--from HEIGHT] [--to HEIGHT]
#                                   [--include-pending]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of table
#   --from HEIGHT       Start of scan range (inclusive; default: 0)
#   --to HEIGHT         End of scan range (inclusive; default: current head)
#   --include-pending   Also list staged-but-not-yet-active changes
#                       from the pending-params RPC
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head           (current chain height)
#   - block          (per-block JSON; via `determ block-info <i> --json`)
#   - pending_params (with --include-pending only)
#
# Exit codes:
#   0   success
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_param_history.sh [--rpc-port N] [--json]
                                 [--from HEIGHT] [--to HEIGHT]
                                 [--include-pending]

Chronological audit log of A5 PARAM_CHANGE transactions: scans the
chain over [--from, --to] (default whole chain) and decodes each
PARAM_CHANGE tx's (name, value, effective_height) payload. Reports
status ACTIVE (effective_height <= current head) vs PENDING (future
activation). Optional --include-pending also lists changes staged
via pending-params RPC.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of table
  --from HEIGHT       Start of scan range (inclusive; default: 0)
  --to HEIGHT         End of scan range (inclusive; default: head)
  --include-pending   Also list staged-but-not-yet-active changes
  -h, --help          Show this help

Exit codes:
  0   success
  1   RPC error / daemon unreachable / malformed response / bad args
EOF
}

PORT=7778
JSON_OUT=0
INCLUDE_PENDING=0
FROM_H=""
TO_H=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";        shift 2 ;;
    --json)            JSON_OUT=1;       shift ;;
    --from)            FROM_H="$2";      shift 2 ;;
    --to)              TO_H="$2";        shift 2 ;;
    --include-pending) INCLUDE_PENDING=1; shift ;;
    *) echo "operator_param_history: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guard for user-supplied range bounds.
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in
      *[!0-9]*)
        echo "operator_param_history: --from / --to must be unsigned integers (got '$v')" >&2
        exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve current head height. `determ head --field height` already
# returns a bare number on stdout and exit 1 on RPC failure.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_param_history: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*)
  echo "operator_param_history: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default range: [0, head]. User-supplied bounds override; clamp --to
# to head so requested-beyond-head doesn't fail later block-info calls.
FROM=${FROM_H:-0}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_param_history: --from ($FROM) > --to ($TO); nothing to scan" >&2
  exit 1
fi

# Collect every PARAM_CHANGE tx in [FROM, TO]. One block-info RPC per
# block — predictable and bounded; the chain_summary --last N path
# would be denser but caps differently across versions, so we pay the
# extra RPCs for clarity. Output: one TSV line per PARAM_CHANGE tx:
#   <staged_at_block>\t<effective_height>\t<name>\t<value_hex>\t<value_bytes>\t<decoded_or_empty>
TMP_CHANGES=$(mktemp 2>/dev/null) || {
  echo "operator_param_history: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_CHANGES" "$TMP_PENDING" 2>/dev/null' EXIT

# Drive the scan + decode in Python — handles hex parsing, varint
# layout (u8 name_len / u16 LE value_len / u64 LE effective_height),
# and tolerates type-field-as-int vs type-field-as-string both.
python - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_CHANGES" <<'PY' || {
  echo "operator_param_history: block scan failed" >&2; exit 1;
}
import json, subprocess, sys

determ, port, from_h, to_h, out_path = sys.argv[1:6]
from_h = int(from_h); to_h = int(to_h)

def is_param_change(tx_type):
    # tx.type may be the int 6 or the string "PARAM_CHANGE" / "6"
    if isinstance(tx_type, int):    return tx_type == 6
    if isinstance(tx_type, str):    return tx_type in ("6", "PARAM_CHANGE")
    return False

def decode_payload(hex_str):
    # Per src/chain/block.hpp::TxType::PARAM_CHANGE:
    #   [name_len:u8][name:utf8]
    #   [value_len:u16 LE][value:bytes]
    #   [effective_height:u64 LE]
    #   [sig_count:u8] + sig_count * { [keyholder_index:u16 LE][ed_sig:64B] }
    try:
        p = bytes.fromhex(hex_str)
    except Exception:
        return None
    o = 0
    if len(p) < 1: return None
    nl = p[o]; o += 1
    if len(p) < o + nl: return None
    name = p[o:o+nl].decode("utf-8", errors="replace"); o += nl
    if len(p) < o + 2: return None
    vl = int.from_bytes(p[o:o+2], "little"); o += 2
    if len(p) < o + vl: return None
    value = p[o:o+vl]; o += vl
    if len(p) < o + 8: return None
    eff = int.from_bytes(p[o:o+8], "little"); o += 8
    return {"name": name, "value": value, "effective_height": eff}

def decode_value(b):
    # Best-effort: u64 LE for 8-byte values; hex for everything else.
    if len(b) == 8:
        return str(int.from_bytes(b, "little"))
    return None

rows = []
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=10
        )
    except Exception as e:
        sys.stderr.write(f"operator_param_history: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_param_history: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_param_history: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_param_change(tx.get("type")): continue
        decoded = decode_payload(tx.get("payload", ""))
        if decoded is None:
            # Malformed payload — record what we can.
            rows.append({
                "staged_at_block": h,
                "effective_height": 0,
                "name": "(undecodable)",
                "value_hex": tx.get("payload", ""),
                "value_bytes": 0,
                "decoded_value": None,
            })
            continue
        rows.append({
            "staged_at_block": h,
            "effective_height": decoded["effective_height"],
            "name": decoded["name"],
            "value_hex": decoded["value"].hex(),
            "value_bytes": len(decoded["value"]),
            "decoded_value": decode_value(decoded["value"]),
        })

with open(out_path, "w", encoding="utf-8") as f:
    for r in rows:
        dv = r["decoded_value"] if r["decoded_value"] is not None else ""
        f.write(f'{r["staged_at_block"]}\t{r["effective_height"]}\t{r["name"]}\t{r["value_hex"]}\t{r["value_bytes"]}\t{dv}\n')
PY

# Optional pending overlay.
TMP_PENDING=""
if [ "$INCLUDE_PENDING" = "1" ]; then
  TMP_PENDING=$(mktemp 2>/dev/null) || {
    echo "operator_param_history: cannot create temp file" >&2; exit 1;
  }
  "$DETERM" pending-params --json --rpc-port "$PORT" > "$TMP_PENDING" 2>/dev/null || {
    echo "operator_param_history: pending-params RPC failed (port $PORT)" >&2
    exit 1
  }
fi

# Render — JSON envelope or human table — in Python so we get the
# same parse path for both modes.
python - "$JSON_OUT" "$HEAD_H" "$TMP_CHANGES" "$TMP_PENDING" "$INCLUDE_PENDING" "$FROM" "$TO" <<'PY' || exit 1
import json, sys

json_out = sys.argv[1] == "1"
head_h = int(sys.argv[2])
changes_path = sys.argv[3]
pending_path = sys.argv[4]
include_pending = sys.argv[5] == "1"
from_h, to_h = int(sys.argv[6]), int(sys.argv[7])

changes = []
with open(changes_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line: continue
        parts = line.split("\t")
        # 6 fields per writer above; pad if dv was empty.
        while len(parts) < 6: parts.append("")
        staged, eff, name, vhex, vbytes, dv = parts[:6]
        eff_i = int(eff)
        status = "ACTIVE" if eff_i <= head_h else "PENDING"
        entry = {
            "staged_at_block": int(staged),
            "effective_height": eff_i,
            "name": name,
            "value_hex": vhex,
            "value_bytes": int(vbytes) if vbytes else 0,
            "status": status,
        }
        if dv: entry["decoded_value"] = dv
        changes.append(entry)

pending = []
if include_pending and pending_path:
    try:
        with open(pending_path, "r", encoding="utf-8") as f:
            arr = json.load(f)
        if isinstance(arr, list):
            for e in arr:
                if not isinstance(e, dict): continue
                pending.append({
                    "effective_height": int(e.get("effective_height", 0)),
                    "name":             e.get("name", ""),
                    "value_hex":        e.get("value_hex", ""),
                    "value_bytes":      int(e.get("value_bytes", 0)),
                    "status":           "PENDING",
                })
    except Exception as ex:
        sys.stderr.write(f"operator_param_history: cannot parse pending-params JSON: {ex}\n")
        sys.exit(1)

# Summary footer.
by_name = {}
for c in changes:
    by_name[c["name"]] = by_name.get(c["name"], 0) + 1
oldest_staged = min((c["staged_at_block"] for c in changes), default=None)
newest_staged = max((c["staged_at_block"] for c in changes), default=None)

if json_out:
    envelope = {
        "changes":  changes,
        "summary":  {
            "total_changes":  len(changes),
            "total_pending":  len(pending),
            "by_name":        by_name,
            "oldest_staged":  oldest_staged,
            "newest_staged":  newest_staged,
            "scan_from":      from_h,
            "scan_to":        to_h,
            "head":           head_h,
        },
    }
    if include_pending:
        envelope["pending"] = pending
    print(json.dumps(envelope, indent=2))
    sys.exit(0)

# Human-readable table.
print(f"operator_param_history: scan [{from_h}..{to_h}] (head={head_h})")
print()
if not changes:
    print("(no on-chain PARAM_CHANGE transactions in scan range)")
else:
    print(f"{'staged_at':>10}  {'effective':>10}  {'status':<8}  {'name':<26}  value")
    print(f"{'-'*10:>10}  {'-'*10:>10}  {'-'*8:<8}  {'-'*26:<26}  {'-'*20}")
    for c in changes:
        val = c.get("decoded_value")
        if val is None:
            val_disp = c["value_hex"][:32] + ("..." if len(c["value_hex"]) > 32 else "")
        else:
            val_disp = f"{val} ({c['value_bytes']}B)"
        print(f"{c['staged_at_block']:>10}  {c['effective_height']:>10}  "
              f"{c['status']:<8}  {c['name']:<26}  {val_disp}")

if include_pending:
    print()
    if not pending:
        print("(no staged-but-not-yet-active changes from pending-params)")
    else:
        print("Pending (staged but not yet active):")
        print(f"{'effective':>10}  {'name':<26}  value_hex")
        print(f"{'-'*10:>10}  {'-'*26:<26}  {'-'*32}")
        for p in pending:
            hex_disp = p["value_hex"][:32] + ("..." if len(p["value_hex"]) > 32 else "")
            print(f"{p['effective_height']:>10}  {p['name']:<26}  {hex_disp}")

print()
print(f"total_changes={len(changes)}  total_pending={len(pending)}")
if by_name:
    print("by_name:")
    for n in sorted(by_name):
        print(f"  {n:<26}  {by_name[n]}")
if oldest_staged is not None:
    print(f"oldest_staged_at_block={oldest_staged}  newest_staged_at_block={newest_staged}")
PY
