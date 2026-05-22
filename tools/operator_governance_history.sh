#!/usr/bin/env bash
# operator_governance_history.sh — Comprehensive governance event timeline
# across a window of finalized blocks on a running determ daemon.
#
# Sibling-script positioning:
#
#   operator_param_change_history.sh   PARAM_CHANGE-only; reports proposer,
#                                      key, old → new value derivation,
#                                      approvals, effective_block,
#                                      ACTIVE / PENDING status. Default
#                                      window = last 5000 blocks.
#
#   operator_validator_history.sh      Per-validator behavior history —
#                                      classifies a single (--domain) or
#                                      every (--all) validator's
#                                      committee appearances + sig
#                                      participation + abort /
#                                      equivocation slashing + current
#                                      registry status.
#
#   operator_governance_history.sh     THIS — broader governance surface
#                                      than the PARAM_CHANGE sibling.
#                                      Walks the same block window but
#                                      surfaces a chronological table of
#                                      every PARAM_CHANGE + DEREGISTER +
#                                      REGISTER event (filterable via
#                                      --filter-type). Aggregates
#                                      per-type counts + anomaly flags
#                                      for governance-churn / mass-
#                                      register / mass-deregister
#                                      signals. Does NOT track per-tx
#                                      old-value lineage (that's the
#                                      sibling's job).
#
# Read-only RPC composition; safe against a running daemon.
#
# Usage:
#   tools/operator_governance_history.sh --rpc-port N
#                                        [--from H] [--to H] [--last N]
#                                        [--filter-type T1,T2,...]
#                                        [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (REQUIRED)
#   --from H            Start of scan range (inclusive; default: head-5000)
#   --to H              End of scan range (inclusive; default: head)
#   --last N            Shorthand: [head-N+1 .. head]; mutex with --from/--to
#   --filter-type LIST  Comma-separated tx-type filter. Allowed values:
#                       PARAM_CHANGE, DEREGISTER, REGISTER (default = all
#                       three). Names are case-insensitive in --filter-type;
#                       output always uses canonical uppercase. Unknown
#                       names → bad-args exit.
#   --json              Emit structured JSON envelope
#   --anomalies-only    Suppress normal output unless ≥1 anomaly fires;
#                       exit 2 then.
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head              current chain height
#   - block-info        per-block JSON (via `determ block-info <i> --json`)
#   - validators        current registered pool (anomaly-rate denominator)
#
# Output shapes:
#
#   Text (default; chronological, oldest first):
#     === Governance history (port P, window [F..T], B blocks) ===
#         block  tx_hash       from                                 type           summary
#         -----  -------       --------                             ----           -------
#           ...
#     Summary: total=N, PARAM_CHANGE=N, DEREGISTER=N, REGISTER=N
#     Anomalies: ...
#
#   JSON (--json):
#     {
#       "window": {"from": F, "to": T, "block_count": B},
#       "events": [
#         {"block": int, "tx_hash": str, "from": str, "type": str,
#          "summary": str, "details": {...type-specific...}}, ...
#       ],
#       "by_type": {"PARAM_CHANGE": int, "DEREGISTER": int, "REGISTER": int},
#       "summary": {"n_total": int, "n_unique_actors": int,
#                   "n_unique_keys_modified": int},
#       "anomalies": [str, ...],
#       "rpc_port": P,
#       "head_height": H,
#       "filter_type": [str, ...]   // canonical filter (uppercase)
#     }
#
# Anomalies (governance-churn signals; raised on the WINDOW, not the chain):
#   unusual_param_change_rate    > 10 PARAM_CHANGE events in the window
#                                (param thrash; coordinated keyholder
#                                push or stuck governance loop)
#   mass_deregister              > 25% of currently-registered validators
#                                appear as DEREGISTER from-addresses in
#                                the window (potential coordination /
#                                exit signal). Denominator uses the
#                                AT-AUDIT-TIME pool size from
#                                `determ validators --json` (so the rate
#                                is honest only when the pool isn't
#                                churning faster than the window).
#   mass_register                > 25% growth in registered pool —
#                                count of REGISTER events ÷ at-audit-
#                                time pool size > 0.25 (potential
#                                Sybil attempt or healthy adoption).
#                                Same denominator caveat as
#                                mass_deregister applies.
#
# Exit codes:
#   0   walk completed; no anomalies (or default mode without
#       --anomalies-only)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_governance_history.sh --rpc-port N
                                      [--from H] [--to H] [--last N]
                                      [--filter-type T1,T2,...]
                                      [--json] [--anomalies-only]

Enumerate governance events (PARAM_CHANGE + DEREGISTER + REGISTER) over
a block window. Reports a chronological event table + per-type counts +
anomaly flags for governance churn signals.

Options:
  --rpc-port N        RPC port to query (REQUIRED)
  --from H            Start of scan range (inclusive; default: head-5000)
  --to H              End of scan range (inclusive; default: head)
  --last N            Shorthand: [head-N+1 .. head]; mutex with --from/--to
  --filter-type LIST  Comma-separated tx-type filter; allowed values:
                      PARAM_CHANGE, DEREGISTER, REGISTER
                      (default = all three; case-insensitive)
  --json              Emit structured JSON envelope
  --anomalies-only    Suppress output unless ≥1 anomaly fires; exit 2 then
  -h, --help          Show this help

Anomalies:
  unusual_param_change_rate    > 10 PARAM_CHANGE events in window
  mass_deregister              > 25% of registered validators DEREGISTER
                               in window (denominator = at-audit-time pool)
  mass_register                > 25% pool growth (REGISTER count ÷
                               at-audit-time pool size)

Exit codes:
  0   walk completed; no anomalies (or default mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
FILTER_RAW=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";        shift 2 ;;
    --json)            JSON_OUT=1;           shift ;;
    --anomalies-only)  ANOM_ONLY=1;          shift ;;
    --from)            FROM_H="${2:-}";      shift 2 ;;
    --to)              TO_H="${2:-}";        shift 2 ;;
    --last)            LAST_N="${2:-}";      shift 2 ;;
    --filter-type)     FILTER_RAW="${2:-}";  shift 2 ;;
    *) echo "operator_governance_history: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; multi-instance hosts
# can silently target the wrong daemon if we default a port).
if [ -z "$PORT" ]; then
  echo "operator_governance_history: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards on user-supplied integers.
case "$PORT" in *[!0-9]*|"")
  echo "operator_governance_history: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_governance_history: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

# Range-form mutual exclusion: --last conflicts with --from / --to.
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_governance_history: --last is mutually exclusive with --from / --to" >&2
  exit 1
fi
if [ -n "$LAST_N" ] && [ "$LAST_N" = "0" ]; then
  echo "operator_governance_history: --last must be > 0 (got '$LAST_N')" >&2
  exit 1
fi

# Filter-type parse and validate. Empty = all three. Case-insensitive on
# input; canonical uppercase emitted.
FILTER_CANON=""
if [ -n "$FILTER_RAW" ]; then
  # Split on comma; uppercase; validate each token; dedupe.
  FILTER_CANON=$(printf '%s' "$FILTER_RAW" | python -c "
import sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
allowed = {'PARAM_CHANGE', 'DEREGISTER', 'REGISTER'}
parts = [p.strip().upper() for p in raw.split(',') if p.strip()]
seen = []
for p in parts:
    if p not in allowed:
        sys.stderr.write(f\"operator_governance_history: --filter-type unknown value '{p}' (allowed: PARAM_CHANGE, DEREGISTER, REGISTER)\n\")
        sys.exit(1)
    if p not in seen:
        seen.append(p)
print(','.join(seen))
") || exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

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

# ── Step 1: resolve current head height ───────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_governance_history: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_governance_history: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: resolve [FROM..TO] window ─────────────────────────────────────────
# Default: last 5000 blocks ending at head (matches the PARAM_CHANGE sibling).
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
  echo "operator_governance_history: --from ($FROM) > --to ($TO); nothing to scan" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: current pool size for mass_* anomaly denominators ────────────────
# Use the at-audit-time validator pool count as the denominator for
# mass_deregister / mass_register. The walk itself doesn't model pool
# evolution mid-window — for windows shorter than registry churn this
# is honest; for longer windows the anomaly thresholds become looser.
POOL_COUNT=$("$DETERM" validators --count --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_governance_history: cannot reach validators RPC (port $PORT)" >&2
  exit 1
}
POOL_COUNT=$(printf '%s' "$POOL_COUNT" | tr -d '[:space:]')
case "$POOL_COUNT" in *[!0-9]*|"")
  echo "operator_governance_history: validators --count returned non-numeric '$POOL_COUNT'" >&2
  exit 1 ;;
esac

# ── Step 4: per-block walk + tx classification (driven from Python) ──────────
TMP_EVENTS=$(mktemp 2>/dev/null) || {
  echo "operator_governance_history: cannot create temp file" >&2
  exit 1
}
trap 'rm -f "$TMP_EVENTS" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$FILTER_CANON" "$TMP_EVENTS" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, filter_raw, out_path = sys.argv[1:7]
from_h = int(from_h); to_h = int(to_h)

# Empty filter_raw means "all three". Otherwise split on comma; the
# bash side has already canonicalized to uppercase + validated.
if filter_raw:
    filter_set = set(filter_raw.split(','))
else:
    filter_set = {"PARAM_CHANGE", "DEREGISTER", "REGISTER"}

# tx.type → canonical name (matches block.hpp TxType enum).
TX_TYPE_NAME = {
    0: "TRANSFER",
    1: "REGISTER",
    2: "DEREGISTER",
    3: "STAKE",
    4: "UNSTAKE",
    5: "REGION_CHANGE",
    6: "PARAM_CHANGE",
    7: "MERGE_EVENT",
}

def tx_type_name(t):
    # tx.type in block JSON is emitted as int (block.cpp:38), but be
    # defensive against future string encoding.
    if isinstance(t, int):
        return TX_TYPE_NAME.get(t, f"UNKNOWN({t})")
    if isinstance(t, str):
        try:
            ti = int(t)
            return TX_TYPE_NAME.get(ti, f"UNKNOWN({ti})")
        except Exception:
            return t.upper()
    return "UNKNOWN"

def decode_param_change(payload_hex):
    # PARAM_CHANGE payload layout per src/node/validator.cpp:
    #   [name_len:u8][name:utf8]
    #   [value_len:u16 LE][value:bytes]
    #   [effective_height:u64 LE]
    #   [sig_count:u8] + sig_count × {[keyholder_index:u16 LE][ed_sig:64B]}
    # Returns {name, value_bytes, value_hex, value_decoded (u64 LE if
    # 8B and name != param_keyholders), effective_height, approvals}
    # or None on truncation.
    try:
        p = bytes.fromhex(payload_hex)
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
    sigc = p[o]
    # u64 LE decode if 8 bytes and not the opaque blob name.
    decoded = None
    if name != "param_keyholders" and len(value) == 8:
        decoded = int.from_bytes(value, "little")
    return {
        "name":               name,
        "value_hex":          value.hex(),
        "value_bytes":        len(value),
        "value_decoded":      decoded,
        "effective_height":   eff,
        "approvals":          sigc,
    }

def decode_register(payload_hex):
    # REGISTER payload layout per src/node/validator.cpp:
    #   [pubkey: 32B][region_len: u8][region: utf8]
    # Legacy = 32B pubkey only → empty region.
    # The "register_authorization" tail is reserved for a future
    # DOMAIN_INCLUSION-mode attestation extension (mentioned in
    # task brief); current wire format has no such field, so we
    # surface region only and label any tail-trailing bytes as
    # `extra_bytes` for forward-compat (current validator rejects
    # them, but a future revision may carry an attestation here).
    try:
        p = bytes.fromhex(payload_hex)
    except Exception:
        return None
    if len(p) < 32:
        return {"region": "", "pubkey_hex": "", "extra_bytes": 0,
                "payload_truncated": True}
    pubkey_hex = p[:32].hex()
    if len(p) == 32:
        return {"region": "", "pubkey_hex": pubkey_hex, "extra_bytes": 0,
                "payload_truncated": False}
    rlen = p[32]
    if len(p) < 33 + rlen:
        return {"region": "", "pubkey_hex": pubkey_hex,
                "extra_bytes": len(p) - 33,
                "payload_truncated": True}
    region = p[33:33+rlen].decode("utf-8", errors="replace")
    extra = len(p) - (33 + rlen)
    return {"region": region, "pubkey_hex": pubkey_hex,
            "extra_bytes": extra, "payload_truncated": False}

events = []
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_governance_history: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_governance_history: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_governance_history: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    for tx in (blk.get("transactions") or []):
        if not isinstance(tx, dict): continue
        tname = tx_type_name(tx.get("type"))
        if tname not in ("PARAM_CHANGE", "DEREGISTER", "REGISTER"):
            continue
        if tname not in filter_set:
            continue

        sender   = str(tx.get("from", "")) if isinstance(tx.get("from"), str) else ""
        tx_hash  = str(tx.get("hash", "")) if isinstance(tx.get("hash"), str) else ""
        details  = {}
        summary  = ""

        if tname == "PARAM_CHANGE":
            decoded = decode_param_change(tx.get("payload", ""))
            if decoded is None:
                details = {"payload_truncated": True}
                summary = "(undecodable payload)"
            else:
                details = decoded
                if decoded["value_decoded"] is not None:
                    summary = f"{decoded['name']}={decoded['value_decoded']} eff@{decoded['effective_height']} approvals={decoded['approvals']}"
                else:
                    vh = decoded["value_hex"]
                    summary = f"{decoded['name']}=hex:{vh[:12]}{'..' if len(vh) > 12 else ''} ({decoded['value_bytes']}B) eff@{decoded['effective_height']} approvals={decoded['approvals']}"
        elif tname == "DEREGISTER":
            # Per src/node/validator.cpp the DEREGISTER tx has no
            # decoded payload (the from-field identifies the
            # deregistering domain; payload is unused). Surface the
            # raw payload-bytes-count only.
            try:
                pb = bytes.fromhex(tx.get("payload", ""))
            except Exception:
                pb = b""
            details = {"payload_bytes": len(pb)}
            summary = f"deregister: {sender}"
        elif tname == "REGISTER":
            decoded = decode_register(tx.get("payload", ""))
            details = decoded or {}
            if decoded is None or decoded.get("payload_truncated"):
                summary = f"register: {sender} (payload truncated)"
            else:
                region = decoded.get("region", "") or "(global)"
                extra  = decoded.get("extra_bytes", 0)
                if extra > 0:
                    summary = f"register: {sender} region={region} (+{extra}B attestation tail)"
                else:
                    summary = f"register: {sender} region={region}"

        events.append({
            "block":    h,
            "tx_hash":  tx_hash,
            "from":     sender,
            "type":     tname,
            "summary":  summary,
            "details":  details,
        })

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(events, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_governance_history: block scan failed" >&2
  exit 1
fi

# ── Step 5: classify anomalies + render envelope ──────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_EVENTS" "$HEAD_H" "$FROM" "$TO" "$WIN_BLOCKS" "$PORT" "$POOL_COUNT" "$FILTER_CANON" <<'PY'
import json, sys

json_out    = sys.argv[1] == "1"
anom_only   = sys.argv[2] == "1"
events_path = sys.argv[3]
head_h      = int(sys.argv[4])
from_h      = int(sys.argv[5])
to_h        = int(sys.argv[6])
win_blocks  = int(sys.argv[7])
port        = int(sys.argv[8])
pool_count  = int(sys.argv[9])
filter_raw  = sys.argv[10] if len(sys.argv) > 10 else ""

with open(events_path, "r", encoding="utf-8") as f:
    events = json.load(f)

# Stable chronological sort: ascending by (block, type, from).
events.sort(key=lambda e: (e["block"], e["type"], e["from"]))

# Per-type counts.
by_type = {"PARAM_CHANGE": 0, "DEREGISTER": 0, "REGISTER": 0}
for e in events:
    t = e["type"]
    if t in by_type:
        by_type[t] += 1

# Summary stats.
unique_actors = {e["from"] for e in events if e.get("from")}
unique_keys   = {e["details"].get("name", "") for e in events
                 if e["type"] == "PARAM_CHANGE"
                 and isinstance(e.get("details"), dict)
                 and e["details"].get("name")}
summary = {
    "n_total":                len(events),
    "n_unique_actors":        len(unique_actors),
    "n_unique_keys_modified": len(unique_keys),
}

# Anomaly classification.
# unusual_param_change_rate: > 10 PARAM_CHANGE events in window.
# mass_deregister: > 25% of pool DEREGISTER (denominator = pool_count).
# mass_register:   > 25% pool growth (REGISTER count / pool_count).
anomalies = []
if by_type["PARAM_CHANGE"] > 10:
    anomalies.append("unusual_param_change_rate")
if pool_count > 0:
    dereg_rate = by_type["DEREGISTER"] / pool_count
    reg_rate   = by_type["REGISTER"]   / pool_count
    if dereg_rate > 0.25:
        anomalies.append("mass_deregister")
    if reg_rate > 0.25:
        anomalies.append("mass_register")
# pool_count == 0 is a degenerate edge case (no validators); skip the
# rate-based anomalies (division by zero would mask honest empty-pool
# state). Operator can spot a zero pool from the validators RPC directly.

# Build the filter-type list emitted in JSON. Default (no filter) =
# all three canonical types.
if filter_raw:
    filter_list = filter_raw.split(",")
else:
    filter_list = ["PARAM_CHANGE", "DEREGISTER", "REGISTER"]

envelope = {
    "window": {
        "from":        from_h,
        "to":          to_h,
        "block_count": win_blocks,
    },
    "events":      events,
    "by_type":     by_type,
    "summary":     summary,
    "anomalies":   anomalies,
    "rpc_port":    port,
    "head_height": head_h,
    "pool_size":   pool_count,
    "filter_type": filter_list,
}

if json_out:
    print(json.dumps(envelope))
    sys.exit(0)

# --anomalies-only: suppress normal output unless ≥1 anomaly fired.
if anom_only and not anomalies:
    print(f"operator_governance_history: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {win_blocks} blocks, "
          f"events={summary['n_total']})")
    sys.exit(0)

# ── Human-readable layout ────────────────────────────────────────────────────
print(f"=== Governance history (port {port}, window [{from_h}..{to_h}], "
      f"{win_blocks} blocks) ===")
if filter_raw:
    print(f"Filter: type in [{','.join(filter_list)}]")
print(f"Pool size (at audit time): {pool_count}")
print()

if not events:
    print("(no governance events in window)")
else:
    print(f"{'block':>8}  {'tx_hash':<16}  {'from':<32}  "
          f"{'type':<12}  summary")
    print(f"{'-'*8:>8}  {'-'*16:<16}  {'-'*32:<32}  "
          f"{'-'*12:<12}  {'-'*40}")
    for e in events:
        # tx_hash truncated to 16 chars (block-info emits 64-char hex);
        # from truncated to 32 chars to keep rows on one line at 132 col.
        th = e.get("tx_hash", "") or ""
        if len(th) > 16: th = th[:13] + "..."
        fr = e.get("from", "") or ""
        if len(fr) > 32: fr = fr[:29] + "..."
        ty = e["type"]
        sm = e.get("summary", "")
        # Cap summary at ~70 chars so the row stays readable; full
        # detail is in --json mode.
        if len(sm) > 70: sm = sm[:67] + "..."
        print(f"{e['block']:>8}  {th:<16}  {fr:<32}  {ty:<12}  {sm}")

print()
print(f"Summary: total={summary['n_total']}, "
      f"PARAM_CHANGE={by_type['PARAM_CHANGE']}, "
      f"DEREGISTER={by_type['DEREGISTER']}, "
      f"REGISTER={by_type['REGISTER']}")
print(f"  unique_actors={summary['n_unique_actors']}, "
      f"unique_keys_modified={summary['n_unique_keys_modified']}")

print()
if not anomalies:
    print("[OK] No governance anomalies detected")
else:
    for a in anomalies:
        if a == "unusual_param_change_rate":
            print(f"[WARN] unusual_param_change_rate — {by_type['PARAM_CHANGE']} "
                  f"PARAM_CHANGE events in window (threshold: > 10)")
        elif a == "mass_deregister":
            pct = (by_type['DEREGISTER'] / pool_count) * 100 if pool_count > 0 else 0
            print(f"[WARN] mass_deregister — {by_type['DEREGISTER']} DEREGISTER "
                  f"events vs pool size {pool_count} ({pct:.1f}%; threshold > 25%)")
        elif a == "mass_register":
            pct = (by_type['REGISTER'] / pool_count) * 100 if pool_count > 0 else 0
            print(f"[WARN] mass_register — {by_type['REGISTER']} REGISTER "
                  f"events vs pool size {pool_count} ({pct:.1f}% growth; threshold > 25%)")
        else:
            print(f"[WARN] {a}")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_governance_history: render failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ─────────────────────────────────────────────────
# Same convention as sibling scripts: --anomalies-only AND ≥1 anomaly
# fires → exit 2. Default mode always exits 0 if the walk succeeded.
ANOM_COUNT=$(python - "$TMP_EVENTS" "$POOL_COUNT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    events = json.load(f)
pool = int(sys.argv[2])
by_type = {"PARAM_CHANGE": 0, "DEREGISTER": 0, "REGISTER": 0}
for e in events:
    t = e.get("type", "")
    if t in by_type: by_type[t] += 1
n = 0
if by_type["PARAM_CHANGE"] > 10:                n += 1
if pool > 0 and by_type["DEREGISTER"] / pool > 0.25: n += 1
if pool > 0 and by_type["REGISTER"]   / pool > 0.25: n += 1
print(n)
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "${ANOM_COUNT:-0}" -gt 0 ]; then
  exit 2
fi
exit 0
