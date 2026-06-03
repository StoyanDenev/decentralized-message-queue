#!/usr/bin/env bash
# operator_slashing_ledger.sh — Slashing-ledger forensics + A1 unitary-
# supply identity check on a running determ daemon.
#
# THE OPERATOR QUESTION
#   "How much stake has been slashed on this chain (the cumulative
#   `accumulated_slashed` counter), does the A1 unitary-supply identity
#   still hold, and — when asked — WHICH domains were slashed and how?"
#
# This is the operational view of three apply-path proofs:
#   * EquivocationSlashingApply.md (FA-Apply-10) — an EquivocationEvent
#     baked into a finalized block forfeits the equivocator's ENTIRE
#     locked stake and DEACTIVATES the registry entry (terminal,
#     non-recoverable double-sign penalty).
#   * AbortEventApply.md (FA-Apply-11) — a Phase-1 AbortEvent applies a
#     PROPORTIONAL SUSPENSION_SLASH to the aborting node (economic
#     disincentive; the validator survives — recoverable).
#   * StakeForfeitureCascade.md — the stake-unlock cascade that both
#     penalties feed; the forfeited stake leaves `live_total_supply`
#     and is accumulated into `accumulated_slashed`, preserving the A1
#     identity:  live_total_supply + accumulated_slashed
#                  = genesis_total + accumulated_subsidy
#                    + accumulated_inbound - accumulated_outbound.
#
# DEFAULT MODE (one RPC, cheap):
#   Calls `determ supply --json` (→ chain_summary RPC) and reports the
#   cumulative `accumulated_slashed` total alongside the full A1 ledger,
#   then runs the A1 identity check (exit 2 on violation — operator
#   alert gate). It ALSO folds in `determ abort-records --json` (the
#   S-032 abort_records cache — also cheap, bounded by validator-pool
#   size) for a per-domain Phase-1 ABORT tally without scanning blocks.
#   Equivocation per-domain events are NOT in the default mode because
#   they require a block scan (see --with-events).
#
# --with-events --from H --to H  (bounded block scan, opt-in):
#   Scans the [from,to] header range via `determ block-range --json`
#   (paged headers RPC, which retains `equivocation_events` AND
#   `abort_events` per block) and reports per-domain slash EVENTS:
#     - equivocation events grouped by `equivocator` domain (FA-Apply-10)
#     - abort events grouped by `aborting_node` domain (FA-Apply-11),
#       windowed (complements the cumulative abort-records cache).
#   --from AND --to are BOTH required in this mode (no implicit
#   unbounded scan); the window is hard-capped (see MAX_EVENT_WINDOW).
#
# SIBLING TOOLS — how this one differs (run those for their angle):
#   operator_supply_check.sh
#       A1 invariant pass/fail ONLY (exit 0/2). No slashing breakdown,
#       no per-domain view, no abort/equivocation events. This script is
#       a superset: it surfaces the same A1 gate PLUS the slashing-ledger
#       decomposition + per-domain forensics.
#   operator_equivocation_digest.sh
#       Per-OFFENDER equivocation digest over a window (FA6 only; jq-
#       based). This script (a) leads with the cumulative
#       `accumulated_slashed` counter + A1 identity reconciliation
#       (neither of which the digest reports), (b) covers BOTH
#       equivocation (FA-Apply-10) AND abort (FA-Apply-11) slash paths,
#       and (c) uses the python-heredoc RPC driver (no jq dependency).
#       Use the digest for a deep per-offender equivocation drill-down;
#       use THIS for the cumulative ledger + A1 reconciliation.
#
# Read-only RPC; safe against any running daemon. Daemon must already be
# listening on --rpc-port. No jq dependency (python-heredoc RPC driver).
#
# Usage:
#   tools/operator_slashing_ledger.sh --rpc-port N
#                                     [--with-events --from H --to H]
#                                     [--json]
#
# Exit codes:
#   0   success (zero slashing is also success)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   A1 unitary-supply identity VIOLATED (operator alert gate)
set -u

# Hard cap on the --with-events scan window so an operator can't ask the
# tool to walk an unbounded range (anti-hang: bounds the work + the
# number of paged headers RPCs the block-range driver issues).
MAX_EVENT_WINDOW=100000

usage() {
  cat <<'EOF'
Usage: operator_slashing_ledger.sh --rpc-port N
                                   [--with-events --from H --to H] [--json]

Audits the chain's slashing ledger: cumulative accumulated_slashed total,
the A1 unitary-supply identity check, and (with --with-events) per-domain
slash events for the equivocation (FA-Apply-10) and abort (FA-Apply-11)
apply paths. Default mode also includes the per-domain Phase-1 abort tally
from the S-032 abort_records cache (one extra cheap RPC, no block scan).

Required:
  --rpc-port N    RPC port to query

Options:
  --with-events   Scan the [--from,--to] block range for slash EVENTS
                  (equivocation + abort) and report per-domain totals.
                  Requires both --from and --to.
  --from H        Lower window bound (inclusive). Only with --with-events.
  --to H          Upper window bound (inclusive). Only with --with-events.
  --json          Emit a structured JSON envelope instead of human output
  -h, --help      Show this help

Exit codes:
  0   success (zero slashing is also success)
  1   RPC error / bad args / malformed response
  2   A1 unitary-supply identity VIOLATED (operator alert gate)
EOF
}

PORT=""
JSON_OUT=0
WITH_EVENTS=0
FROM=""
TO=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --rpc-port)    PORT="${2:-}";  shift 2 ;;
    --json)        JSON_OUT=1;     shift ;;
    --with-events) WITH_EVENTS=1;  shift ;;
    --from)        FROM="${2:-}";  shift 2 ;;
    --to)          TO="${2:-}";    shift 2 ;;
    *) echo "operator_slashing_ledger: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Argument validation (post --help so --help never trips it) ────────────────
if [ -z "$PORT" ]; then
  echo "operator_slashing_ledger: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_slashing_ledger: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --from / --to are only meaningful with --with-events. Reject stray bounds
# without the mode flag so the operator isn't misled into thinking the
# default mode windowed anything.
if [ "$WITH_EVENTS" = "0" ]; then
  if [ -n "$FROM" ] || [ -n "$TO" ]; then
    echo "operator_slashing_ledger: --from / --to require --with-events" >&2
    exit 1
  fi
else
  if [ -z "$FROM" ] || [ -z "$TO" ]; then
    echo "operator_slashing_ledger: --with-events requires both --from and --to (no implicit unbounded scan)" >&2
    exit 1
  fi
  for v in "$FROM" "$TO"; do
    case "$v" in *[!0-9]*|"")
      echo "operator_slashing_ledger: --from / --to must be unsigned integers" >&2
      exit 1 ;;
    esac
  done
  if [ "$TO" -lt "$FROM" ]; then
    echo "operator_slashing_ledger: --to ($TO) must be >= --from ($FROM)" >&2
    exit 1
  fi
  WINDOW=$(( TO - FROM + 1 ))
  if [ "$WINDOW" -gt "$MAX_EVENT_WINDOW" ]; then
    echo "operator_slashing_ledger: window [$FROM..$TO] = $WINDOW blocks exceeds cap $MAX_EVENT_WINDOW (narrow --from/--to)" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: supply / chain_summary RPC — the cumulative ledger ────────────────
# `determ supply --json` calls the chain_summary RPC and computes
# expected_total + a1_invariant_ok server-side. It exits 2 on an A1
# violation, but we don't rely on its exit code — we capture stdout
# (so we can render + then re-derive the exit code from a1_invariant_ok).
# `|| true` keeps a non-zero supply exit (e.g. its own 2) from killing
# us; we validate the JSON ourselves below.
SUPPLY_JSON=$("$DETERM" supply --json --rpc-port "$PORT" 2>/dev/null) || true
if [ -z "$SUPPLY_JSON" ]; then
  echo "operator_slashing_ledger: RPC error from \`determ supply\` (is daemon running on port $PORT?)" >&2
  exit 1
fi

# ── Step 2: abort_records RPC — per-domain Phase-1 abort tally (cheap) ─────────
# S-032 cache, bounded by validator-pool size. One extra RPC; folds the
# FA-Apply-11 per-domain view into the default mode without a block scan.
ABORT_RECORDS_JSON=$("$DETERM" abort-records --json --rpc-port "$PORT" 2>/dev/null) || true
[ -z "$ABORT_RECORDS_JSON" ] && ABORT_RECORDS_JSON="[]"

# ── Step 3: optional bounded block scan for slash EVENTS ──────────────────────
RANGE_JSON=""
if [ "$WITH_EVENTS" = "1" ]; then
  RANGE_JSON=$("$DETERM" block-range "$FROM" "$TO" --json --rpc-port "$PORT" 2>/dev/null) || true
  if [ -z "$RANGE_JSON" ]; then
    echo "operator_slashing_ledger: RPC error fetching block-range [$FROM..$TO] on port $PORT" >&2
    exit 1
  fi
fi

# ── Step 4: parse + render in python (no jq dependency) ───────────────────────
python - "$SUPPLY_JSON" "$ABORT_RECORDS_JSON" "$RANGE_JSON" \
         "$PORT" "$JSON_OUT" "$WITH_EVENTS" "$FROM" "$TO" <<'PY'
import json, sys

supply_raw, abort_raw, range_raw, port_s, json_out_s, with_events_s, from_s, to_s = sys.argv[1:9]
port        = int(port_s)
json_out    = (json_out_s == '1')
with_events = (with_events_s == '1')

def die(msg, code=1):
    sys.stderr.write(f"operator_slashing_ledger: {msg}\n")
    sys.exit(code)

# ── supply / chain_summary envelope ───────────────────────────────────────────
try:
    supply = json.loads(supply_raw)
except Exception as e:
    die(f"malformed supply JSON ({e}) (port {port})")
if not isinstance(supply, dict):
    die(f"supply JSON is not an object (port {port})")

def u64(d, k):
    v = d.get(k, 0)
    try:
        return int(v)
    except Exception:
        return 0

genesis_total = u64(supply, "genesis_total")
acc_subsidy   = u64(supply, "accumulated_subsidy")
acc_inbound   = u64(supply, "accumulated_inbound")
acc_slashed   = u64(supply, "accumulated_slashed")
acc_outbound  = u64(supply, "accumulated_outbound")
expected      = u64(supply, "expected_total")
live          = u64(supply, "live_total_supply")

# Trust the server's a1_invariant_ok when present (it is the authoritative
# bit per cmd_supply); fall back to recomputing the identity from the
# counters if the field is missing/garbled.
a1_field = supply.get("a1_invariant_ok", None)
if isinstance(a1_field, bool):
    a1_ok = a1_field
else:
    a1_ok = (expected == live)

# The A1 identity restated in the slashing-ledger framing:
#   live + slashed == genesis + subsidy + inbound - outbound
# (algebraically identical to expected == live, since
#  expected = genesis + subsidy + inbound - slashed - outbound). We surface
# this slashing-centric form explicitly because it is the reconciliation an
# operator auditing slashing actually wants ("does the slashed stake
# account for the gap between minted-in and live?").
identity_lhs = live + acc_slashed
identity_rhs = genesis_total + acc_subsidy + acc_inbound - acc_outbound
identity_ok  = (identity_lhs == identity_rhs)

# ── abort_records cache → per-domain Phase-1 abort tally ──────────────────────
try:
    abort_records = json.loads(abort_raw)
except Exception:
    abort_records = []
if not isinstance(abort_records, list):
    abort_records = []
abort_rows = []
total_abort_count = 0
for e in abort_records:
    if not isinstance(e, dict):
        continue
    dom = e.get("domain")
    if not isinstance(dom, str):
        continue
    cnt = e.get("count", 0)
    try:
        cnt = int(cnt)
    except Exception:
        cnt = 0
    lb = e.get("last_block", 0)
    try:
        lb = int(lb)
    except Exception:
        lb = 0
    abort_rows.append({"domain": dom, "count": cnt, "last_block": lb})
    total_abort_count += cnt
# abort_records RPC is already sorted count-desc; keep that order.

# ── optional windowed slash events from the header range ──────────────────────
equiv_by_domain = {}      # domain -> {events, containing_blocks:set, heights:set, last_block}
abort_evt_by_domain = {}  # domain -> {events, containing_blocks:set, last_block}
scanned_blocks = 0
equiv_event_total = 0
abort_event_total = 0

if with_events:
    try:
        rng = json.loads(range_raw)
    except Exception as e:
        die(f"malformed block-range payload ({e}) (port {port})")
    headers = rng.get("headers") if isinstance(rng, dict) else None
    if not isinstance(headers, list):
        die(f"block-range payload missing 'headers' array (port {port})")
    scanned_blocks = len(headers)
    for h in headers:
        if not isinstance(h, dict):
            continue
        h_index = h.get("index", None)
        try:
            h_index = int(h_index)
        except Exception:
            h_index = None
        # equivocation_events: FA-Apply-10, grouped by `equivocator`.
        for ev in (h.get("equivocation_events") or []):
            if not isinstance(ev, dict):
                continue
            dom = ev.get("equivocator")
            if not isinstance(dom, str):
                continue
            equiv_event_total += 1
            slot = equiv_by_domain.setdefault(
                dom, {"events": 0, "containing_blocks": set(),
                      "heights": set(), "last_block": -1})
            slot["events"] += 1
            if h_index is not None:
                slot["containing_blocks"].add(h_index)
                if h_index > slot["last_block"]:
                    slot["last_block"] = h_index
            db = ev.get("block_index", None)
            try:
                slot["heights"].add(int(db))
            except Exception:
                pass
        # abort_events: FA-Apply-11, grouped by `aborting_node`.
        for ev in (h.get("abort_events") or []):
            if not isinstance(ev, dict):
                continue
            dom = ev.get("aborting_node")
            if not isinstance(dom, str):
                continue
            abort_event_total += 1
            slot = abort_evt_by_domain.setdefault(
                dom, {"events": 0, "containing_blocks": set(), "last_block": -1})
            slot["events"] += 1
            if h_index is not None:
                slot["containing_blocks"].add(h_index)
                if h_index > slot["last_block"]:
                    slot["last_block"] = h_index

def equiv_rows_sorted():
    rows = []
    for dom, s in equiv_by_domain.items():
        rows.append({
            "domain": dom,
            "events": s["events"],
            "containing_blocks": sorted(s["containing_blocks"]),
            "occurred_at_heights": sorted(s["heights"]),
            "last_containing_block": (s["last_block"] if s["last_block"] >= 0 else None),
        })
    # Most events first; tie-break domain ascending (deterministic).
    rows.sort(key=lambda r: (-r["events"], r["domain"]))
    return rows

def abort_evt_rows_sorted():
    rows = []
    for dom, s in abort_evt_by_domain.items():
        rows.append({
            "domain": dom,
            "events": s["events"],
            "containing_blocks": sorted(s["containing_blocks"]),
            "last_containing_block": (s["last_block"] if s["last_block"] >= 0 else None),
        })
    rows.sort(key=lambda r: (-r["events"], r["domain"]))
    return rows

# ── exit code: A1 identity is the alert gate ──────────────────────────────────
exit_code = 0 if (a1_ok and identity_ok) else 2

# ── JSON envelope ─────────────────────────────────────────────────────────────
if json_out:
    env = {
        "rpc_port": port,
        "accumulated_slashed": acc_slashed,
        "ledger": {
            "genesis_total":        genesis_total,
            "accumulated_subsidy":  acc_subsidy,
            "accumulated_inbound":  acc_inbound,
            "accumulated_slashed":  acc_slashed,
            "accumulated_outbound": acc_outbound,
            "expected_total":       expected,
            "live_total_supply":    live,
        },
        "a1_identity": {
            "a1_invariant_ok":            a1_ok,
            "lhs_live_plus_slashed":      identity_lhs,
            "rhs_minted_minus_outbound":  identity_rhs,
            "identity_holds":             identity_ok,
        },
        "abort_records": {
            "by_domain":         abort_rows,
            "total_abort_count": total_abort_count,
            "unique_domains":    len(abort_rows),
            "note": "cumulative S-032 abort_records cache (Phase-1 aborts; not windowed)",
        },
    }
    if with_events:
        env["events"] = {
            "range": {"from": int(from_s), "to": int(to_s)},
            "scanned_blocks": scanned_blocks,
            "equivocation": {
                "by_domain":      equiv_rows_sorted(),
                "total_events":   equiv_event_total,
                "unique_domains": len(equiv_by_domain),
            },
            "abort": {
                "by_domain":      abort_evt_rows_sorted(),
                "total_events":   abort_event_total,
                "unique_domains": len(abort_evt_by_domain),
            },
        }
    print(json.dumps(env))
    sys.exit(exit_code)

# ── Human render ──────────────────────────────────────────────────────────────
print(f"Slashing ledger (port {port}):")
print(f"  accumulated_slashed:  {acc_slashed}   <-- cumulative stake forfeited (equivocation + abort)")
print(f"  ---")
print(f"  genesis_total:        {genesis_total}")
print(f"  +accumulated_subsidy: {acc_subsidy}")
print(f"  +accumulated_inbound: {acc_inbound}")
print(f"  -accumulated_slashed: {acc_slashed}")
print(f"  -accumulated_outbound:{acc_outbound}")
print(f"  expected_total:       {expected}")
print(f"  live_total_supply:    {live}")
print(f"  ---")
# A1 identity, slashing-centric framing.
print(f"  A1 identity: live_total_supply + accumulated_slashed == genesis + subsidy + inbound - outbound")
print(f"               {identity_lhs} == {identity_rhs}  ->  {'OK' if identity_ok else 'VIOLATED'}")
if a1_ok and identity_ok:
    print(f"  A1 invariant: OK")
else:
    print(f"  A1 invariant: VIOLATED  (operator alert — reconcile slashing ledger / supply counters)")

# Per-domain Phase-1 abort tally (always available, cheap).
print(f"  ---")
if abort_rows:
    print(f"  Phase-1 abort tally (S-032 cache, cumulative, FA-Apply-11):")
    print(f"    {'domain':<28}{'aborts':<10}last_block")
    for r in abort_rows:
        print(f"    {r['domain'][:27]:<28}{r['count']:<10}{r['last_block']}")
    print(f"    (total aborts: {total_abort_count} across {len(abort_rows)} domain(s))")
else:
    print(f"  Phase-1 abort tally (S-032 cache): none (no Phase-1 aborts recorded)")

# Windowed slash events (opt-in).
if with_events:
    print(f"  ---")
    print(f"  Slash events in window [{from_s}..{to_s}] ({scanned_blocks} blocks scanned):")
    eq_rows = equiv_rows_sorted()
    if eq_rows:
        print(f"    Equivocation (FA-Apply-10, terminal — full stake forfeit + deactivation):")
        print(f"      {'offender':<28}{'events':<8}last_block")
        for r in eq_rows:
            lb = r["last_containing_block"]
            lb_s = str(lb) if lb is not None else "?"
            print(f"      {r['domain'][:27]:<28}{r['events']:<8}{lb_s}")
        print(f"      (total equivocation events: {equiv_event_total} across {len(eq_rows)} offender(s))")
    else:
        print(f"    Equivocation (FA-Apply-10): none in window")
    ab_rows = abort_evt_rows_sorted()
    if ab_rows:
        print(f"    Abort (FA-Apply-11, proportional suspension slash — recoverable):")
        print(f"      {'aborter':<28}{'events':<8}last_block")
        for r in ab_rows:
            lb = r["last_containing_block"]
            lb_s = str(lb) if lb is not None else "?"
            print(f"      {r['domain'][:27]:<28}{r['events']:<8}{lb_s}")
        print(f"      (total abort events: {abort_event_total} across {len(ab_rows)} aborter(s))")
    else:
        print(f"    Abort (FA-Apply-11): none in window")
    print(f"  note: per-event slashed amounts are not stamped on the event payloads")
    print(f"        (equivocation forfeits ENTIRE stake; abort applies a proportional")
    print(f"        SUSPENSION_SLASH) — the authoritative cumulative figure is")
    print(f"        accumulated_slashed above.")

sys.exit(exit_code)
PY
RC=$?
exit $RC
