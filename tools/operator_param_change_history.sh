#!/usr/bin/env bash
# operator_param_change_history.sh — A5 governance PARAM_CHANGE event
# enumeration over an explicit block window. Companion to (but distinct
# from) operator_param_history.sh:
#
#   operator_param_history.sh         whole-chain audit log; reports only
#                                     name + new value + effective_height
#                                     + ACTIVE/PENDING status; default
#                                     range = [0..head].
#
#   operator_param_change_history.sh  THIS — windowed enumeration; reports
#                                     proposer (tx.from), parsed approval
#                                     count, threshold (if discoverable),
#                                     and old_value derived from prior
#                                     same-key entries seen in the window;
#                                     default range = [head-5000..head]
#                                     with --last shorthand and --key
#                                     filter; supports --include-pending.
#
# A5 governance is a permissioned PARAM_CHANGE mechanism: an N-of-N (or
# M-of-N) keyholder multisig stages a (name, value) update that activates
# at a specified effective_height. The submitting tx's `from` field is
# the proposer; the payload tail carries `sig_count` (keyholder_index,
# ed_sig) pairs. The validator (src/node/validator.cpp PARAM_CHANGE
# case) verifies each sig against the corresponding pubkey in
# `param_keyholders` and rejects if good_sigs < param_threshold. By the
# time a PARAM_CHANGE lands on-chain, sig_count must equal or exceed
# threshold; this script reports the parsed sig_count as `approvals`.
#
# Threshold note: `param_threshold` is a per-chain governance constant
# (set at genesis, mutable only via PARAM_CHANGE itself). No RPC exposes
# it directly, so threshold is reported as `null` in JSON / "?" in text
# unless --include-pending also surfaces a future param_threshold change.
# Operators who need the active threshold should read it from the
# genesis JSON or the deployment config.
#
# Old-value derivation: the apply path doesn't write old_value alongside
# the new one (chain.cpp simply overwrites the named field at apply
# time). This script reconstructs `old_value` by tracking the last
# decoded value for each parameter name across the window: the first
# occurrence of a key in the window reports old_value = "(unknown)";
# subsequent occurrences of the same key chain off the previous entry's
# new_value. Cross-window history (changes before `from`) is not seen.
# For full-chain old-value lineage, run with `--from 0`.
#
# Read-only RPC composition; safe against a running daemon.
#
# Usage:
#   tools/operator_param_change_history.sh --rpc-port N
#                                          [--from H] [--to H | --last N]
#                                          [--key <param-key>]
#                                          [--include-pending]
#                                          [--json]
#
# Options:
#   --rpc-port N        RPC port to query (REQUIRED)
#   --from H            Start of scan range (inclusive; default: head-5000)
#   --to H              End of scan range (inclusive; default: head)
#   --last N            Shorthand: [head-N+1 .. head]; mutually exclusive
#                       with --from / --to
#   --key KEY           Filter to a specific param key (e.g. MIN_STAKE,
#                       UNSTAKE_DELAY, SUSPENSION_SLASH, tx_commit_ms,
#                       block_sig_ms, abort_claim_ms, bft_escalation_threshold,
#                       param_keyholders, param_threshold). Case-sensitive,
#                       matches the canonical whitelist names from
#                       src/node/validator.cpp.
#   --include-pending   Also list staged-but-not-yet-active changes from
#                       the pending_params RPC
#   --json              Emit structured JSON envelope
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - status         (current chain height)
#   - block          (per-block JSON; via `determ block-info <i> --json`)
#   - pending_params (with --include-pending only)
#
# Output shapes:
#
#   Text (default; chronological table, oldest first):
#     === PARAM_CHANGE history (port P, window [F..T], B blocks) ===
#         block  proposer                            key                   old → new                approvals  threshold  effective  status
#         -----  --------                            ---                   ---------                ---------  ---------  ---------  ------
#           ...
#     Summary: total_changes=N, keys=[k1,k2,...]
#     Pending: ... (with --include-pending)
#
#   JSON (--json):
#     {
#       "window": {"from": F, "to": T, "block_count": B},
#       "changes": [
#         {"block": int, "proposer": str, "key": str,
#          "old_value": str|null, "new_value": str|null, "value_hex": str,
#          "value_bytes": int, "approvals": int, "threshold": int|null,
#          "effective_block": int, "status": "ACTIVE"|"PENDING"}, ...
#       ],
#       "summary": {"total_changes": int, "keys_changed": [str,...]},
#       "pending": [ ... ]   // only if --include-pending
#     }
#
# Exit codes:
#   0   success — RPC walk completed (including zero PARAM_CHANGE events)
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_param_change_history.sh --rpc-port N
                                        [--from H] [--to H | --last N]
                                        [--key <param-key>]
                                        [--include-pending]
                                        [--json]

Enumerate A5 PARAM_CHANGE governance events over a block window.
Reports proposer (tx.from), key, old_value (from prior same-key
entries seen in the window), new_value, approvals (parsed sig_count
from payload), threshold (null unless discoverable), effective_block,
and ACTIVE / PENDING status.

Options:
  --rpc-port N        RPC port to query (REQUIRED)
  --from H            Start of scan range (inclusive; default: head-5000)
  --to H              End of scan range (inclusive; default: head)
  --last N            Shorthand: [head-N+1 .. head]; mutex with --from/--to
  --key KEY           Filter to a specific param key (case-sensitive,
                      matches canonical whitelist names)
  --include-pending   Also list staged-but-not-yet-active changes
  --json              Emit structured JSON envelope
  -h, --help          Show this help

Exit codes:
  0   success (incl. zero PARAM_CHANGE events in window)
  1   RPC error / daemon unreachable / malformed response / bad args
EOF
}

PORT=""
JSON_OUT=0
INCLUDE_PENDING=0
FROM_H=""
TO_H=""
LAST_N=""
KEY_FILTER=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";        shift 2 ;;
    --json)            JSON_OUT=1;           shift ;;
    --from)            FROM_H="${2:-}";      shift 2 ;;
    --to)              TO_H="${2:-}";        shift 2 ;;
    --last)            LAST_N="${2:-}";      shift 2 ;;
    --key)             KEY_FILTER="${2:-}";  shift 2 ;;
    --include-pending) INCLUDE_PENDING=1;    shift ;;
    *) echo "operator_param_change_history: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (multi-instance hosts can silently target the
# wrong daemon if we default a port; this script refuses to guess).
if [ -z "$PORT" ]; then
  echo "operator_param_change_history: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_param_change_history: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_param_change_history: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

# Range-form mutual exclusion: --last conflicts with --from / --to.
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_param_change_history: --last is mutually exclusive with --from / --to" >&2
  exit 1
fi
if [ -n "$LAST_N" ] && [ "$LAST_N" = "0" ]; then
  echo "operator_param_change_history: --last must be > 0 (got '$LAST_N')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current head height ───────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_param_change_history: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_param_change_history: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: resolve [FROM..TO] window from CLI args ───────────────────────────
# Default: last 5000 blocks ending at head.
# `head` is the chain height, so the highest valid block index is head-1
# only if the chain stores indices 0..head-1. In Determ the head's index
# equals chain.height (block at h has index h), so we clamp TO to HEAD_H
# and let block-info return null for non-existent indices. We avoid
# scanning below 0 with max(0, ...).
if [ -n "$LAST_N" ]; then
  if [ "$HEAD_H" -ge "$LAST_N" ]; then
    FROM=$(( HEAD_H - LAST_N + 1 ))
  else
    FROM=0
  fi
  TO=$HEAD_H
else
  FROM=${FROM_H:-$(( HEAD_H > 5000 ? HEAD_H - 5000 : 0 ))}
  TO=${TO_H:-$HEAD_H}
fi
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_param_change_history: --from ($FROM) > --to ($TO); nothing to scan" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk the window, decode PARAM_CHANGE txs ──────────────────────────
# One block-info RPC per block. The PARAM_CHANGE payload layout is fixed
# in src/chain/block.hpp comments + decoded in src/node/validator.cpp
# (case TxType::PARAM_CHANGE):
#   [name_len: u8][name: utf8]
#   [value_len: u16 LE][value: bytes]
#   [effective_height: u64 LE]
#   [sig_count: u8] + sig_count × { [keyholder_index: u16 LE][ed_sig: 64B] }
#
# Old-value derivation: walk in ascending block order; track the latest
# decoded value per parameter name; entry K's old_value = the previous
# value tracked for that name (or "(unknown)" for the first occurrence
# in the window).
TMP_CHANGES=$(mktemp 2>/dev/null) || {
  echo "operator_param_change_history: cannot create temp file" >&2
  exit 1
}
TMP_PENDING=""
trap 'rm -f "$TMP_CHANGES" "$TMP_PENDING" 2>/dev/null' EXIT

# Promote $DETERM to absolute (mirrors operator_dapp_inventory.sh — Git
# Bash on Windows can fail subprocess.run with relative paths).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$KEY_FILTER" "$TMP_CHANGES" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, key_filter, out_path = sys.argv[1:7]
from_h = int(from_h); to_h = int(to_h)

def is_param_change(tx_type):
    # tx.type may be the int 6 or the string "PARAM_CHANGE" / "6"
    if isinstance(tx_type, int): return tx_type == 6
    if isinstance(tx_type, str): return tx_type in ("6", "PARAM_CHANGE")
    return False

def decode_payload(hex_str):
    # Per src/node/validator.cpp PARAM_CHANGE decode:
    #   [name_len:u8][name:utf8]
    #   [value_len:u16 LE][value:bytes]
    #   [effective_height:u64 LE]
    #   [sig_count:u8] + sig_count × {[keyholder_index:u16 LE][ed_sig:64B]}
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
    if len(p) < o + 1: return None
    sigc = p[o]; o += 1
    # We don't re-verify sigs (the validator already did); just count
    # the tail to make sure it's well-formed.
    expected_tail = sigc * (2 + 64)
    sig_tail_ok = (len(p) == o + expected_tail)
    return {
        "name":             name,
        "value":            value,
        "effective_height": eff,
        "approvals":        sigc,
        "sig_tail_ok":      sig_tail_ok,
    }

def decode_value(name, b):
    # Numeric whitelist params (per validator.cpp + chain.cpp
    # activate_pending_params): u64 LE for 8-byte values.
    # `param_keyholders` carries an opaque blob (operator-supplied
    # serialization); always return None for that one.
    if name == "param_keyholders":
        return None
    if len(b) == 8:
        return str(int.from_bytes(b, "little"))
    # Non-8-byte numeric whitelist entries are out-of-spec but the
    # validator may have admitted them historically (the whitelist is
    # name-keyed, not size-keyed); fall back to hex.
    return None

# Last-seen new_value per param name, for old_value derivation.
last_value = {}

rows = []
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_param_change_history: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_param_change_history: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_param_change_history: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue
    txs = blk.get("transactions") or []
    for tx in txs:
        if not isinstance(tx, dict): continue
        if not is_param_change(tx.get("type")): continue
        proposer = str(tx.get("from", "")) if isinstance(tx.get("from"), str) else ""
        decoded = decode_payload(tx.get("payload", ""))
        if decoded is None:
            # Malformed payload — record what we can and skip the rest.
            rows.append({
                "block":           h,
                "proposer":        proposer,
                "key":             "(undecodable)",
                "value_hex":       tx.get("payload", ""),
                "value_bytes":     0,
                "new_value":       None,
                "old_value":       None,
                "approvals":       0,
                "effective_block": 0,
            })
            continue
        name = decoded["name"]
        if key_filter and name != key_filter:
            # Still record the prior-value bookkeeping even when filtered
            # out — old_value chains across filtered entries must be
            # honest. But we DON'T emit a row for filtered-out names.
            dv = decode_value(name, decoded["value"])
            if dv is not None:
                last_value[name] = dv
            continue
        new_value = decode_value(name, decoded["value"])
        old_value = last_value.get(name)  # None if first sighting
        if new_value is not None:
            last_value[name] = new_value
        rows.append({
            "block":           h,
            "proposer":        proposer,
            "key":             name,
            "value_hex":       decoded["value"].hex(),
            "value_bytes":     len(decoded["value"]),
            "new_value":       new_value,
            "old_value":       old_value,
            "approvals":       decoded["approvals"],
            "effective_block": decoded["effective_height"],
        })

# Persist rows as JSON for the render step.
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(rows, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_param_change_history: block scan failed" >&2
  exit 1
fi

# ── Step 4: optional pending overlay ──────────────────────────────────────────
if [ "$INCLUDE_PENDING" = "1" ]; then
  TMP_PENDING=$(mktemp 2>/dev/null) || {
    echo "operator_param_change_history: cannot create temp file" >&2
    exit 1
  }
  "$DETERM" pending-params --json --rpc-port "$PORT" > "$TMP_PENDING" 2>/dev/null || {
    echo "operator_param_change_history: pending-params RPC failed (port $PORT)" >&2
    exit 1
  }
fi

# ── Step 5: render envelope (text or JSON) ────────────────────────────────────
python - "$JSON_OUT" "$HEAD_H" "$TMP_CHANGES" "$TMP_PENDING" "$INCLUDE_PENDING" \
        "$FROM" "$TO" "$WIN_BLOCKS" "$PORT" "$KEY_FILTER" <<'PY'
import json, sys

json_out        = sys.argv[1] == "1"
head_h          = int(sys.argv[2])
changes_path    = sys.argv[3]
pending_path    = sys.argv[4]
include_pending = sys.argv[5] == "1"
from_h          = int(sys.argv[6])
to_h            = int(sys.argv[7])
win_blocks      = int(sys.argv[8])
port            = int(sys.argv[9])
key_filter      = sys.argv[10] if len(sys.argv) > 10 else ""

with open(changes_path, "r", encoding="utf-8") as f:
    rows = json.load(f)

# Assign status using the chain's *current* head: ACTIVE iff the change
# has already been activated (effective_block <= head). Pending changes
# (future effective_block) appear here as PENDING — they're already
# on-chain (the tx landed) but the named parameter hasn't yet mutated.
changes = []
for r in rows:
    eff = int(r.get("effective_block", 0) or 0)
    status = "ACTIVE" if eff <= head_h else "PENDING"
    changes.append({
        "block":           int(r["block"]),
        "proposer":        r.get("proposer", ""),
        "key":             r.get("key", ""),
        "old_value":       r.get("old_value"),    # None if first sighting in window
        "new_value":       r.get("new_value"),    # None if non-numeric
        "value_hex":       r.get("value_hex", ""),
        "value_bytes":     int(r.get("value_bytes", 0)),
        "approvals":       int(r.get("approvals", 0)),
        "threshold":       None,                  # no RPC exposes this
        "effective_block": eff,
        "status":          status,
    })
# Sort ascending by block (oldest first).
changes.sort(key=lambda c: c["block"])

# Pending (staged-but-not-yet-active from pending_params RPC).
pending = []
if include_pending and pending_path:
    try:
        with open(pending_path, "r", encoding="utf-8") as f:
            arr = json.load(f)
        if isinstance(arr, list):
            for e in arr:
                if not isinstance(e, dict): continue
                p_name = e.get("name", "")
                if key_filter and p_name != key_filter:
                    continue
                vh = e.get("value_hex", "")
                try:
                    vb = bytes.fromhex(vh) if isinstance(vh, str) else b""
                except Exception:
                    vb = b""
                # Try u64 LE decode if 8 bytes (mirrors decode_value).
                decoded = None
                if p_name != "param_keyholders" and len(vb) == 8:
                    decoded = str(int.from_bytes(vb, "little"))
                pending.append({
                    "name":              p_name,
                    "value_hex":         vh,
                    "value_bytes":       int(e.get("value_bytes", 0)),
                    "decoded_value":     decoded,
                    "effective_height":  int(e.get("effective_height", 0)),
                })
    except Exception as ex:
        sys.stderr.write(f"operator_param_change_history: cannot parse pending-params JSON: {ex}\n")
        sys.exit(1)

# Summary footer.
keys_changed = sorted({c["key"] for c in changes})
summary = {
    "total_changes": len(changes),
    "keys_changed":  keys_changed,
}

if json_out:
    envelope = {
        "window": {
            "from":        from_h,
            "to":          to_h,
            "block_count": win_blocks,
        },
        "changes": changes,
        "summary": summary,
        "rpc_port":     port,
        "head_height":  head_h,
    }
    if key_filter:
        envelope["key_filter"] = key_filter
    if include_pending:
        envelope["pending"] = pending
    print(json.dumps(envelope))
    sys.exit(0)

# ── Human-readable layout ─────────────────────────────────────────────────────
title = f"=== PARAM_CHANGE history (port {port}, window [{from_h}..{to_h}], {win_blocks} blocks) ==="
print(title)
if key_filter:
    print(f"Filter: key == '{key_filter}'")

if not changes:
    print("(no PARAM_CHANGE events in window)")
else:
    # Column widths chosen to keep most rows on a single 132-char line.
    print()
    print(f"{'block':>8}  {'proposer':<32}  {'key':<26}  "
          f"{'old → new':<28}  {'appr':>4}  {'thr':>4}  "
          f"{'effective':>10}  status")
    print(f"{'-'*8:>8}  {'-'*32:<32}  {'-'*26:<26}  "
          f"{'-'*28:<28}  {'-'*4:>4}  {'-'*4:>4}  "
          f"{'-'*10:>10}  {'-'*7}")
    for c in changes:
        prop = c["proposer"]
        if len(prop) > 32: prop = prop[:29] + "..."
        ov = c["old_value"]
        nv = c["new_value"]
        # Format the old → new column. Both may be None (non-numeric
        # value or first-sighting). "?" for first-sighting old_value;
        # hex-prefix for non-numeric new_value.
        if ov is None:
            ov_str = "?"
        else:
            ov_str = str(ov)
        if nv is None:
            # Non-numeric: show value_bytes + truncated hex (fits in col).
            vh = c["value_hex"]
            nv_str = f"hex:{vh[:8]}{'..' if len(vh) > 8 else ''}({c['value_bytes']}B)"
        else:
            nv_str = str(nv)
        on = f"{ov_str} -> {nv_str}"
        if len(on) > 28: on = on[:25] + "..."
        thr = "?"      # no RPC exposes param_threshold
        key_disp = c["key"]
        if len(key_disp) > 26: key_disp = key_disp[:23] + "..."
        print(f"{c['block']:>8}  {prop:<32}  {key_disp:<26}  "
              f"{on:<28}  {c['approvals']:>4}  {thr:>4}  "
              f"{c['effective_block']:>10}  {c['status']}")

print()
print(f"Summary: total_changes={summary['total_changes']}, "
      f"keys={','.join(summary['keys_changed']) if summary['keys_changed'] else '-'}")

if include_pending:
    print()
    if not pending:
        print("Pending: (none)")
    else:
        print(f"Pending ({len(pending)} staged-but-not-yet-active from pending_params):")
        print(f"  {'effective':>10}  {'name':<26}  value")
        print(f"  {'-'*10:>10}  {'-'*26:<26}  {'-'*32}")
        for p in pending:
            dv = p["decoded_value"]
            if dv is None:
                vh = p["value_hex"]
                val_disp = f"hex:{vh[:16]}{'..' if len(vh) > 16 else ''}({p['value_bytes']}B)"
            else:
                val_disp = str(dv)
            name = p["name"]
            if len(name) > 26: name = name[:23] + "..."
            print(f"  {p['effective_height']:>10}  {name:<26}  {val_disp}")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_param_change_history: render failed" >&2
  exit 1
fi

exit 0
