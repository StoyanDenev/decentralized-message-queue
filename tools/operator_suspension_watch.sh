#!/usr/bin/env bash
# operator_suspension_watch.sh — Live FA6 abort-suspension registry forecast
# on a running determ daemon.
#
# THE OPERATOR QUESTION
#   "Which validators are RIGHT NOW excluded from committee selection by the
#   exponential-backoff abort-suspension cascade, until what height does each
#   suspension run, and how many blocks of cool-down remain?"
#
# This is the REGISTRY-EFFECT view of the FA6 abort path (AbortEventApply.md
# FA-Apply-11 + StakeForfeitureCascade.md). The node never stores a
# `suspended_until` field on the registry entry; instead the eligibility
# filter in `src/node/registry.cpp::build_from_chain` recomputes a suspension
# window on the fly from the S-032 abort_records cache:
#
#     exp = min(count - 1, MAX_ABORT_EXPONENT)            # MAX_ABORT_EXPONENT = 10
#     len = min(BASE_SUSPENSION_BLOCKS * 2^exp,           # BASE_SUSPENSION_BLOCKS = 10
#               MAX_SUSPENSION_BLOCKS)                     # MAX_SUSPENSION_BLOCKS = 10000
#     suspended_until = last_block + len
#     is_suspended    = (head <= last_block + len)
#
# (constants: include/determ/node/registry.hpp:19-21). A suspended domain is
# skipped by `build_from_chain` (registry.cpp:64), so it cannot be drawn into
# any committee until `head` passes `suspended_until`. This script reconstructs
# that exact arithmetic against the live `abort-records` cache + current head,
# giving operators a forecast the daemon computes but never exposes directly.
#
# WHY THIS IS NOT A DUPLICATE OF ITS SIBLINGS:
#   operator_slashing_ledger.sh   Cumulative `accumulated_slashed` counter +
#                                 A1 reconciliation + per-domain abort/equiv
#                                 EVENT tallies. It reports WHO was slashed
#                                 and HOW MUCH — it does NOT compute the
#                                 forward-looking suspension WINDOW or say who
#                                 is currently committee-ineligible.
#   operator_equivocation_digest.sh   Per-OFFENDER FA6 equivocation EVENT
#                                 digest over a block window. Equivocation
#                                 (terminal full-stake forfeit) only; nothing
#                                 about the recoverable abort-suspension
#                                 backoff window.
#   operator_escalation_consistency.sh   Per-block BFT-escalation LEGALITY
#                                 audit. Orthogonal: it checks consensus_mode
#                                 invariants, not registry suspension state.
#   operator_committee_audit.sh / _snapshot.sh   Current committee COMPOSITION.
#                                 They show who IS selected; this shows who is
#                                 forcibly EXCLUDED and for how long.
#   THIS (operator_suspension_watch.sh)   The forward registry-eligibility
#                                 forecast: who is suspended now, until what
#                                 height, blocks remaining, and which domains
#                                 are cooling-off (have an abort record but the
#                                 window has elapsed → eligible again).
#
# Reads ONLY two cheap read RPCs — no block scan:
#   * `determ abort-records --json`   the S-032 cache: [{domain,count,last_block}]
#                                     (bounded by validator-pool size).
#   * `determ status --field height`  current chain head (one integer).
# Read-only; safe against any running daemon. No jq dependency (python driver).
#
# Usage:
#   tools/operator_suspension_watch.sh --rpc-port N
#                                      [--suspended-only] [--json]
#
# Options:
#   --rpc-port N      RPC port to query (REQUIRED)
#   --suspended-only  Only report domains whose suspension window is still
#                     open at the current head (cooled-off domains are still
#                     counted in the summary but not row-printed). Also flips
#                     the exit code to an alert gate (see below).
#   --json            Emit a structured JSON envelope instead of human output
#   -h, --help        Show this help
#
# Output:
#   Human (default): a table — domain, abort_count, last_block, window_len,
#     suspended_until, blocks_remaining, state (SUSPENDED / cooling-off) —
#     sorted suspended-first then by blocks_remaining descending; then a
#     footer with currently-suspended / cooled-off / total counts.
#   --json: {head, suspended:[...], cooled_off:[...],
#            summary:{currently_suspended, cooled_off, total_with_aborts,
#                     constants:{base,max_blocks,max_exp}}, rpc_port}
#
# Exit codes:
#   0   success (zero suspensions is also success); default informational mode
#       always exits 0 if the RPCs succeeded.
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --suspended-only AND >=1 domain is currently suspended (alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_suspension_watch.sh --rpc-port N [--suspended-only] [--json]

Reconstructs the live FA6 abort-suspension window for every domain in the
S-032 abort_records cache and reports which validators are currently excluded
from committee selection (and for how many more blocks). Mirrors the exact
exponential-backoff arithmetic in src/node/registry.cpp::build_from_chain:

    exp = min(count - 1, 10);  len = min(10 * 2^exp, 10000)
    suspended_until = last_block + len;  suspended = head <= suspended_until

Required:
  --rpc-port N      RPC port to query

Options:
  --suspended-only  Only row-print domains still inside their suspension
                    window (cooled-off domains stay in the summary counts).
                    Turns the exit code into an alert gate (exit 2 if any
                    domain is currently suspended).
  --json            Emit a structured JSON envelope instead of human output
  -h, --help        Show this help

Exit codes:
  0   success (zero suspensions is also success)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --suspended-only AND >=1 domain currently suspended (alert gate)
EOF
}

PORT=""
JSON_OUT=0
SUSPENDED_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";  shift 2 ;;
    --json)           JSON_OUT=1;     shift ;;
    --suspended-only) SUSPENDED_ONLY=1; shift ;;
    *) echo "operator_suspension_watch: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Argument validation (post --help so --help never trips it) ────────────────
if [ -z "$PORT" ]; then
  echo "operator_suspension_watch: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_suspension_watch: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: current chain head ────────────────────────────────────────────────
# `determ status --field height` prints a bare integer (no JSON envelope) —
# the next-to-be-produced index. The highest finalized block is height - 1,
# but the registry filter compares against `at_index = chain.height()`
# (registry.cpp build_from_chain is called with chain.height()), so we use the
# raw height as the suspension-eligibility reference point to match the node.
HEAD=$("$DETERM" status --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_suspension_watch: RPC error from \`determ status\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEAD=$(printf '%s' "$HEAD" | tr -d '[:space:]')
case "$HEAD" in *[!0-9]*|"")
  echo "operator_suspension_watch: malformed status height ('$HEAD') (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: abort_records cache (S-032) — cheap, no block scan ────────────────
ABORT_RECORDS_JSON=$("$DETERM" abort-records --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_suspension_watch: RPC error from \`determ abort-records\` on port $PORT" >&2
  exit 1
}
[ -z "$ABORT_RECORDS_JSON" ] && ABORT_RECORDS_JSON="[]"

# ── Step 3: reconstruct suspension windows + render (python; no jq) ───────────
python - "$ABORT_RECORDS_JSON" "$HEAD" "$PORT" "$JSON_OUT" "$SUSPENDED_ONLY" <<'PY'
import json, sys

abort_raw, head_s, port_s, json_out_s, susp_only_s = sys.argv[1:6]
head      = int(head_s)
port      = int(port_s)
json_out  = (json_out_s == '1')
susp_only = (susp_only_s == '1')

# Constants — must track include/determ/node/registry.hpp:19-21 exactly.
BASE_SUSPENSION_BLOCKS = 10
MAX_SUSPENSION_BLOCKS  = 10000
MAX_ABORT_EXPONENT     = 10

def die(msg, code=1):
    sys.stderr.write(f"operator_suspension_watch: {msg}\n")
    sys.exit(code)

try:
    records = json.loads(abort_raw)
except Exception as e:
    die(f"malformed abort-records JSON ({e}) (port {port})")
if not isinstance(records, list):
    die(f"abort-records payload is not an array (port {port})")

def window_len(count):
    # Mirrors registry.cpp:47-49.  count is the abort tally (>= 1 for any
    # entry in the cache); exp = count - 1 clamped at MAX_ABORT_EXPONENT.
    exp = min(count - 1, MAX_ABORT_EXPONENT)
    if exp < 0:
        exp = 0
    return min(BASE_SUSPENSION_BLOCKS * (1 << exp), MAX_SUSPENSION_BLOCKS)

suspended  = []   # window still open at head
cooled_off = []   # has an abort record but window has elapsed

for e in records:
    if not isinstance(e, dict):
        continue
    dom = e.get("domain")
    if not isinstance(dom, str):
        continue
    try:
        count = int(e.get("count", 0))
    except Exception:
        count = 0
    try:
        last_block = int(e.get("last_block", 0))
    except Exception:
        last_block = 0
    if count <= 0:
        continue
    wlen = window_len(count)
    suspended_until = last_block + wlen
    # registry.cpp:50  is_suspended := at_index <= last_block + len
    is_susp = (head <= suspended_until)
    blocks_remaining = (suspended_until - head + 1) if is_susp else 0
    row = {
        "domain":           dom,
        "abort_count":      count,
        "last_block":       last_block,
        "window_len":       wlen,
        "suspended_until":  suspended_until,
        "blocks_remaining": blocks_remaining,
        "window_capped":    (wlen == MAX_SUSPENSION_BLOCKS),
    }
    (suspended if is_susp else cooled_off).append(row)

# Suspended: most cool-down remaining first; tie-break domain ascending.
suspended.sort(key=lambda r: (-r["blocks_remaining"], r["domain"]))
# Cooled-off: most-recent abort first; tie-break domain ascending.
cooled_off.sort(key=lambda r: (-r["last_block"], r["domain"]))

n_susp   = len(suspended)
n_cool   = len(cooled_off)
n_total  = n_susp + n_cool

# Exit code: alert gate only under --suspended-only with >=1 open window.
exit_code = 2 if (susp_only and n_susp > 0) else 0

if json_out:
    env = {
        "head":       head,
        "suspended":  suspended,
        "cooled_off": ([] if susp_only else cooled_off),
        "summary": {
            "currently_suspended": n_susp,
            "cooled_off":          n_cool,
            "total_with_aborts":   n_total,
            "constants": {
                "base":       BASE_SUSPENSION_BLOCKS,
                "max_blocks": MAX_SUSPENSION_BLOCKS,
                "max_exp":    MAX_ABORT_EXPONENT,
            },
        },
        "rpc_port": port,
    }
    print(json.dumps(env))
    sys.exit(exit_code)

# ── Human render ──────────────────────────────────────────────────────────────
print(f"Suspension watch (port {port}, head {head}):")
print(f"  formula: len = min({BASE_SUSPENSION_BLOCKS} * 2^min(count-1,{MAX_ABORT_EXPONENT}), "
      f"{MAX_SUSPENSION_BLOCKS}); suspended_until = last_block + len")
print(f"  ---")

if n_total == 0:
    print(f"  no abort records on this chain — no domains suspended or cooling-off")
    sys.exit(exit_code)

def print_table(title, rows, show_state):
    print(f"  {title}")
    print(f"    {'domain':<28}{'aborts':<8}{'last_blk':<10}{'win_len':<9}"
          f"{'until':<10}{'remaining':<11}state")
    for r in rows:
        state = "SUSPENDED" if r["blocks_remaining"] > 0 else "cooling-off"
        cap   = " (capped)" if r["window_capped"] else ""
        print(f"    {r['domain'][:27]:<28}{r['abort_count']:<8}{r['last_block']:<10}"
              f"{r['window_len']:<9}{r['suspended_until']:<10}"
              f"{r['blocks_remaining']:<11}{state}{cap}")

if suspended:
    print_table("Currently SUSPENDED (committee-ineligible, FA-Apply-11):", suspended, True)
else:
    print(f"  Currently SUSPENDED: none (all abort windows elapsed)")

if not susp_only:
    if cooled_off:
        if suspended:
            print(f"  ---")
        print_table("Cooled-off (has abort record, eligible again):", cooled_off, False)
    elif suspended:
        print(f"  ---")
        print(f"  Cooled-off: none")

print(f"  ---")
print(f"  currently suspended: {n_susp}   cooled-off: {n_cool}   "
      f"total with aborts: {n_total}")
if susp_only and n_susp > 0:
    print(f"  [ALERT] {n_susp} domain(s) currently excluded from committee selection")

sys.exit(exit_code)
PY
RC=$?
exit $RC
