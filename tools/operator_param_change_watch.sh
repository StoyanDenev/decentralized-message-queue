#!/usr/bin/env bash
# operator_param_change_watch.sh — Read-only PENDING PARAM_CHANGE
# inspector. Queries a running determ daemon's `pending_params` RPC for
# A5 governance changes that have been staged but not yet activated, then
# tabulates each one with its blocks-until-active countdown:
#
#     name | value | effective_height | blocks_until_active
#
# where blocks_until_active = effective_height - current_height (0 means
# "activates at the next apply"; a value <= 0 means the change is already
# due and will activate on the next block the daemon applies).
#
# THE OPERATOR QUESTION
#   "What governance PARAM_CHANGEs are queued on this chain, and how many
#   blocks until each one takes effect?" — the at-a-glance pre-upgrade
#   countdown an operator wants before a planned governance activation
#   window, without scanning any block history.
#
# Scope contrast with the two neighbouring governance scripts (keep lanes
# distinct):
#   operator_param_history.sh
#       Whole-chain ([0..head]) chronological AUDIT LOG of every
#       PARAM_CHANGE tx that ever landed. One block-info RPC per block.
#       Reports ACTIVE/PENDING status but NOT a blocks-until-active
#       countdown. `pending_params` is only an opt-in overlay there.
#   operator_param_change_history.sh
#       Windowed enumeration with proposer + approvals + old->new value
#       lineage. Also one block-info RPC per block. History focus.
#   operator_param_change_watch.sh
#       THIS — the cheap, FORWARD-LOOKING pending snapshot. Two RPCs
#       total (head + pending_params), no block scan. The defining
#       column is `blocks_until_active`, which neither history script
#       computes. A single query then exit by default; an optional
#       bounded --watch loop re-queries a fixed number of times.
#
# WHY pending_params (not a block scan)
#   The daemon exposes the staging buffer directly via the
#   `pending_params` RPC (CLI: `determ pending-params [--at-height N]
#   [--json]`; handler Node::rpc_pending_params in src/node/node.cpp).
#   It returns a JSON array of
#       {effective_height, name, value_hex, value_bytes}
#   sorted ascending by effective_height — exactly the staged-but-not-
#   yet-active set. Activation happens at apply time: at each block,
#   entries with effective_height <= block.index activate in insertion
#   order (Chain::activate_pending_params). So the staging buffer IS the
#   authoritative pending set; no history walk is needed.
#
# VALUE DECODING (best-effort, same convention as the history scripts)
#   The RPC returns the raw value as value_hex (+ value_bytes). The A5
#   numeric whitelist params (MIN_STAKE, UNSTAKE_DELAY, SUSPENSION_SLASH,
#   tx_commit_ms, block_sig_ms, abort_claim_ms, bft_escalation_threshold,
#   param_threshold, ...) are serialized as 8-byte u64 LE, so an 8-byte
#   value is rendered as its decoded integer. `param_keyholders` carries
#   an opaque operator-supplied blob (never an integer), so it — and any
#   non-8-byte value — is rendered as a truncated hex string + byte
#   count. This mirrors decode_value() in operator_param_change_history.sh.
#
# Read-only RPC; safe against any running daemon. Daemon must already be
# listening on --rpc-port. No jq dependency (python-heredoc parser, like
# operator_slashing_ledger.sh / operator_dapp_census.sh).
#
# Usage:
#   tools/operator_param_change_watch.sh --rpc-port N
#                                        [--at-height H]
#                                        [--name KEY]
#                                        [--json]
#                                        [--watch --count C [--interval S]]
#
# Options:
#   --rpc-port N    RPC port to query (REQUIRED)
#   --at-height H   Only show entries with effective_height <= H (i.e.
#                   what WILL have activated by block H). Passed through
#                   to `pending-params --at-height`.
#   --name KEY      Filter to a single param name (case-sensitive,
#                   matches the canonical whitelist names).
#   --json          Emit a structured JSON envelope instead of a table.
#   --watch         Re-query on a bounded loop. REQUIRES --count. Each
#                   iteration re-reads head + pending_params and re-prints
#                   the table. Hard-capped (see MAX_WATCH_COUNT); there is
#                   NO unbounded/infinite mode.
#   --count C       Number of --watch iterations (1..MAX_WATCH_COUNT).
#   --interval S    Seconds to sleep between --watch iterations
#                   (1..MAX_WATCH_INTERVAL; default 5). Ignored without
#                   --watch.
#   -h, --help      Show this help.
#
# Exit codes:
#   0   success (zero pending entries is also success)
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

# Anti-hang hard caps. --watch must terminate: --count is bounded so the
# loop runs a fixed, finite number of times, and --interval is bounded so
# a single sleep can't wedge the script. There is deliberately no
# "follow forever" mode — operators wanting continuous monitoring wrap a
# single-query invocation in their own supervisor (cron/systemd timer).
MAX_WATCH_COUNT=1440
MAX_WATCH_INTERVAL=3600

usage() {
  cat <<'EOF'
Usage: operator_param_change_watch.sh --rpc-port N
                                      [--at-height H]
                                      [--name KEY]
                                      [--json]
                                      [--watch --count C [--interval S]]

Read-only inspector for PENDING A5 governance PARAM_CHANGEs on a running
determ daemon. Queries the pending_params RPC (no block scan) and prints,
for each staged-but-not-yet-active change:

    name | value | effective_height | blocks_until_active

blocks_until_active = effective_height - current_height (<= 0 means the
change is already due and activates on the next applied block).

Options:
  --rpc-port N    RPC port to query (REQUIRED)
  --at-height H   Only entries with effective_height <= H
  --name KEY      Filter to a single param name (case-sensitive)
  --json          Emit a structured JSON envelope instead of a table
  --watch         Bounded re-query loop; REQUIRES --count (no infinite mode)
  --count C       Number of --watch iterations (1..1440)
  --interval S    Seconds between --watch iterations (1..3600; default 5)
  -h, --help      Show this help

Exit codes:
  0   success (zero pending entries is also success)
  1   RPC error / daemon unreachable / malformed response / bad args
EOF
}

PORT=""
JSON_OUT=0
AT_HEIGHT=""
NAME_FILTER=""
WATCH=0
COUNT=""
INTERVAL=5
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    --rpc-port)   PORT="${2:-}";        shift 2 ;;
    --at-height)  AT_HEIGHT="${2:-}";   shift 2 ;;
    --name)       NAME_FILTER="${2:-}"; shift 2 ;;
    --json)       JSON_OUT=1;           shift ;;
    --watch)      WATCH=1;              shift ;;
    --count)      COUNT="${2:-}";       shift 2 ;;
    --interval)   INTERVAL="${2:-}";    shift 2 ;;
    *) echo "operator_param_change_watch: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Argument validation (post --help so --help never trips it) ────────────────
# --rpc-port is required: a defaulted port can silently target the wrong
# daemon on a multi-instance host (mirrors operator_dapp_census.sh /
# operator_slashing_ledger.sh, which also refuse to guess).
if [ -z "$PORT" ]; then
  echo "operator_param_change_watch: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_param_change_watch: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --at-height, if given, must be an unsigned integer.
if [ -n "$AT_HEIGHT" ]; then
  case "$AT_HEIGHT" in *[!0-9]*)
    echo "operator_param_change_watch: --at-height must be an unsigned integer (got '$AT_HEIGHT')" >&2
    exit 1 ;;
  esac
fi

# --watch bounds. --count is mandatory in watch mode (no implicit
# unbounded loop) and both --count / --interval are hard-capped.
if [ "$WATCH" = "1" ]; then
  if [ -z "$COUNT" ]; then
    echo "operator_param_change_watch: --watch requires --count (no unbounded loop)" >&2
    exit 1
  fi
  case "$COUNT" in *[!0-9]*|"")
    echo "operator_param_change_watch: --count must be a positive integer (got '$COUNT')" >&2
    exit 1 ;;
  esac
  if [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt "$MAX_WATCH_COUNT" ]; then
    echo "operator_param_change_watch: --count must be in 1..$MAX_WATCH_COUNT (got '$COUNT')" >&2
    exit 1
  fi
  case "$INTERVAL" in *[!0-9]*|"")
    echo "operator_param_change_watch: --interval must be a positive integer (got '$INTERVAL')" >&2
    exit 1 ;;
  esac
  if [ "$INTERVAL" -lt 1 ] || [ "$INTERVAL" -gt "$MAX_WATCH_INTERVAL" ]; then
    echo "operator_param_change_watch: --interval must be in 1..$MAX_WATCH_INTERVAL (got '$INTERVAL')" >&2
    exit 1
  fi
else
  # --count / --interval are only meaningful in --watch mode; reject a
  # stray --count without --watch so the operator isn't misled into
  # thinking a single-shot run looped.
  if [ -n "$COUNT" ]; then
    echo "operator_param_change_watch: --count requires --watch" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── one_query: fetch head + pending_params once, parse + render ────────────────
# Two cheap RPCs (no block scan):
#   determ head --field height   -> bare current height integer
#   determ pending-params --json -> JSON array of staged changes
# Renders either the human table or the JSON envelope. Returns 1 on any
# RPC / parse failure so callers (including the watch loop) can bail.
one_query() {
  local head_h pending_json

  head_h=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_param_change_watch: cannot reach daemon on rpc-port $PORT" >&2
    return 1
  }
  head_h=$(printf '%s' "$head_h" | tr -d '[:space:]')
  case "$head_h" in *[!0-9]*|"")
    echo "operator_param_change_watch: head returned non-numeric '$head_h' (port $PORT)" >&2
    return 1 ;;
  esac

  # Build the pending-params argv. --at-height (if set) is handled
  # server-side-ish by the CLI's client-side post-filter, so we pass it
  # straight through and don't re-filter on effective_height here.
  local pp_args
  pp_args=("pending-params" "--json" "--rpc-port" "$PORT")
  [ -n "$AT_HEIGHT" ] && pp_args+=("--at-height" "$AT_HEIGHT")

  pending_json=$("$DETERM" "${pp_args[@]}" 2>/dev/null) || {
    echo "operator_param_change_watch: pending-params RPC failed (port $PORT)" >&2
    return 1
  }
  [ -z "$pending_json" ] && pending_json="[]"

  # Parse + render in python (no jq dependency). Pass the raw JSON, the
  # resolved head, the name filter, output mode, and port as argv.
  python - "$pending_json" "$head_h" "$NAME_FILTER" "$JSON_OUT" "$PORT" "$AT_HEIGHT" <<'PY'
import json, sys

pending_raw, head_s, name_filter, json_out_s, port_s, at_height_s = sys.argv[1:7]
head      = int(head_s)
json_out  = (json_out_s == "1")
port      = int(port_s)
at_height = int(at_height_s) if at_height_s else None

def die(msg):
    sys.stderr.write(f"operator_param_change_watch: {msg}\n")
    sys.exit(1)

try:
    entries = json.loads(pending_raw)
except Exception as e:
    die(f"malformed pending-params JSON ({e}) (port {port})")
if not isinstance(entries, list):
    die(f"pending-params did not return a JSON array (port {port})")

def decode_value(name, value_hex, value_bytes):
    # Best-effort, mirrors decode_value() in
    # operator_param_change_history.sh: 8-byte numeric-whitelist values
    # are u64 LE; param_keyholders + any non-8-byte value stays as hex.
    if name == "param_keyholders":
        return None
    try:
        b = bytes.fromhex(value_hex)
    except Exception:
        return None
    if len(b) == 8:
        return int.from_bytes(b, "little")
    return None

rows = []
for e in entries:
    if not isinstance(e, dict):
        continue
    name = e.get("name", "")
    if not isinstance(name, str):
        name = str(name)
    if name_filter and name != name_filter:
        continue
    try:
        eff = int(e.get("effective_height", 0) or 0)
    except Exception:
        eff = 0
    vhex = e.get("value_hex", "")
    if not isinstance(vhex, str):
        vhex = ""
    try:
        vbytes = int(e.get("value_bytes", 0) or 0)
    except Exception:
        vbytes = 0
    decoded = decode_value(name, vhex, vbytes)
    # blocks_until_active is signed: a change whose effective_height has
    # already been reached/passed (eff <= head) is "due" and reported as
    # <= 0. We do NOT clamp at 0 so an operator can see how overdue an
    # entry is (it should activate on the very next applied block).
    blocks_until = eff - head
    rows.append({
        "name":                name,
        "effective_height":    eff,
        "blocks_until_active": blocks_until,
        "value_hex":           vhex,
        "value_bytes":         vbytes,
        "decoded_value":       decoded,
    })

# Stable ordering: soonest activation first (ascending effective_height),
# tie-break by name ascending (deterministic).
rows.sort(key=lambda r: (r["effective_height"], r["name"]))

if json_out:
    envelope = {
        "rpc_port":       port,
        "current_height": head,
        "at_height":      at_height,
        "name_filter":    name_filter or None,
        "pending_count":  len(rows),
        "pending":        rows,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# ── Human table ───────────────────────────────────────────────────────────────
note = ""
if at_height is not None:
    note += f", at-height<={at_height}"
if name_filter:
    note += f", name='{name_filter}'"
print(f"Pending PARAM_CHANGEs (port {port}, current height {head}{note})")

if not rows:
    print("(no pending PARAM_CHANGE entries)")
    print()
    print("0 pending PARAM_CHANGE entries")
    sys.exit(0)

def value_cell(r):
    dv = r["decoded_value"]
    if dv is not None:
        return str(dv)
    vh = r["value_hex"]
    head_hex = vh[:16] + (".." if len(vh) > 16 else "")
    return f"hex:{head_hex}({r['value_bytes']}B)"

name_w = max(4, max(len(r["name"]) for r in rows))
val_cells = [value_cell(r) for r in rows]
val_w = max(5, max(len(v) for v in val_cells))

header = f"{'NAME':<{name_w}}  {'VALUE':<{val_w}}  {'EFFECTIVE':>10}  {'BLOCKS_LEFT':>11}"
print(header)
print("-" * (name_w + 2 + val_w + 2 + 10 + 2 + 11))
for r, vcell in zip(rows, val_cells):
    bl = r["blocks_until_active"]
    # A due/overdue entry (<= 0) is annotated so it stands out.
    bl_disp = str(bl) if bl > 0 else (f"{bl} (due)" if bl == 0 else f"{bl} (overdue)")
    print(f"{r['name']:<{name_w}}  {vcell:<{val_w}}  {r['effective_height']:>10}  {bl_disp:>11}")
print("-" * (name_w + 2 + val_w + 2 + 10 + 2 + 11))

n = len(rows)
soonest = rows[0]
print(f"{n} pending PARAM_CHANGE entr{'y' if n == 1 else 'ies'} "
      f"(soonest: '{soonest['name']}' in {soonest['blocks_until_active']} block(s) "
      f"at height {soonest['effective_height']})")
PY
  return $?
}

# ── Single query (default) or bounded watch loop ──────────────────────────────
if [ "$WATCH" != "1" ]; then
  one_query
  exit $?
fi

# Bounded watch: exactly COUNT iterations, sleeping INTERVAL seconds
# between them (no trailing sleep after the final iteration). The loop
# variable is the sole driver — there is no condition that could keep it
# spinning past COUNT, so the script always terminates. A failed query
# aborts the whole watch (an unreachable daemon won't silently loop).
i=1
while [ "$i" -le "$COUNT" ]; do
  echo "=== operator_param_change_watch: iteration $i/$COUNT (port $PORT) ==="
  one_query || exit 1
  if [ "$i" -lt "$COUNT" ]; then
    sleep "$INTERVAL"
  fi
  i=$(( i + 1 ))
done
exit 0
