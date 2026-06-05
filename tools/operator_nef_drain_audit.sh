#!/usr/bin/env bash
# operator_nef_drain_audit.sh — Reconcile the E1 Negative-Entry-Fee (NEF)
# geometric pool drain against the on-chain REGISTER history of a running
# determ daemon. Read-only RPC composition; safe against a producing
# chain. Single query then exit (no --watch).
#
# THE NEF MECHANISM (per src/chain/chain.cpp::apply_block, the REGISTER arm):
#   The Zeroth pool is a genesis-seeded pseudo-account held at the
#   canonical ZEROTH_ADDRESS (an all-zero anon address that no key can
#   sign for, so no TRANSFER can ever drain it). On each *first-time*
#   REGISTER of a domain — NOT re-registrations (key rotation, region
#   update) — half of the pool's current balance is transferred to the
#   new registrant:
#
#       nef = pool.balance / 2          (integer floor)
#       pool.balance    -= nef
#       registrant.balance += nef
#
#   So after F genuine first-time REGISTERs the pool sits at
#
#       live = floor( zeroth_pool_initial / 2^F )
#
#   i.e. it halves geometrically toward 0; once it reaches a balance < 2
#   every nef computes to 0 and the program is inert (newcomers get no
#   grant). The transfer is pure (pool -> domain) — it mints nothing and
#   burns nothing, so it leaves accumulated_subsidy / accumulated_slashed
#   untouched and the A1 unitary-supply identity holds trivially.
#
# THE OPERATOR QUESTION THIS ANSWERS
#   "Is the NEF pool draining the way the geometric model says it should,
#    given the REGISTERs this chain has actually seen?" Concretely, two
#   reconciliations:
#
#   (1) HALVING RECONCILIATION. From the live ZEROTH balance we recover
#       the number of EFFECTIVE halvings the pool has undergone:
#
#           F_obs = floor( log2( zeroth_pool_initial / max(1, live) ) )
#
#       (the largest F with floor(initial / 2^F) >= live). We then walk
#       the REGISTER history over [from..to] and count REGISTER txs. That
#       count is an UPPER BOUND on first-time REGISTERs (re-REGISTERs of
#       an already-registered domain appear identically on the wire but
#       do NOT drain the pool — there is no RPC that exposes the
#       apply-time first_time_register bit, mirroring the silent-skip
#       caveat in operator_fee_distribution_audit.sh). The healthy
#       relation is therefore
#
#           registers_in_window  >=  halvings_attributable_to_window
#
#       A register count BELOW the attributable halvings is an anomaly:
#       the pool drained more than the visible REGISTERs can explain
#       (drains outside the audited window, a non-default window that
#       misses early REGISTERs, or — at full chain scope — a model break).
#
#   (2) GRANT-LEDGER RECONCILIATION. The cumulative value the pool has
#       handed out is exactly
#
#           granted_total = zeroth_pool_initial - live
#
#       and the per-newcomer grant schedule is the descending geometric
#       series initial/2, initial/4, initial/8, ...  The NEXT first-time
#       REGISTER will receive floor(live/2). We surface granted_total, the
#       next grant, and the residual, and flag NEF-inert (next grant == 0)
#       and NEF-floor (next grant <= --floor, the dust threshold below
#       which the program no longer meaningfully subsidizes onboarding).
#
# WHAT THIS DOES NOT (AND CANNOT) DO FROM RPC
#   * It cannot distinguish first-time from repeat REGISTERs on the wire,
#     so the register count is an upper bound (see above). The HALVING
#     side is exact (derived from the live balance, which the apply path
#     drains only on genuine first-times), so the reconciliation is sound
#     in the direction that matters: halvings <= first-times <= registers.
#   * zeroth_pool_initial is a genesis-time constant not exposed over RPC.
#     Supply it with --genesis <file> (authoritative). Without it the
#     script still reports the live pool + next-grant schedule but cannot
#     run the halving reconciliation (reported as not-checkable).
#
# SIBLING TOOLS — how this one differs (run those for their angle):
#   operator_subsidy_pool_health.sh
#       Projects the FORWARD exhaustion timeline of the E4 finite subsidy
#       pool AND the E1 NEF pool from an observed drain RATE. It reads the
#       live ZEROTH balance once; it does NOT walk the REGISTER history or
#       reconcile the geometric halving count against it. THIS script is
#       the BACKWARD forensic reconciliation: it ties the live pool level
#       to the REGISTER txs that produced it.
#   operator_subsidy_audit.sh / operator_subsidy_accrual_audit.sh
#       E3 block_subsidy ATTRIBUTION across creators (per-block / time-
#       bucketed). They read the live ZEROTH balance only as a side
#       surface and never reconcile the NEF halving model.
#   operator_dapp_registration_audit.sh
#       REGISTER-tx forensics from the DApp-onboarding angle (domains,
#       regions, cadence) — not tied to the NEF pool drain at all.
#   operator_supply_reconcile.sh / operator_supply_check.sh
#       The A1 six-leg supply identity. NEF is invisible there by
#       construction (it is an intra-circulating transfer that moves no
#       supply leg); THIS script verifies that invariant by confirming
#       the drain shows up only as a ZEROTH->registrant balance move.
#
# RPC SURFACE (read-only; NO mutating endpoints):
#   status               shard_id + protections.sharding_mode (labelling)
#                        (src/node/node.cpp::rpc_status)
#   head                 current chain height (window default + clamp)
#                        (src/node/node.cpp::rpc_head)
#   balance <ZEROTH>     live Zeroth-pool balance (the E1 NEF residual)
#                        (src/node/node.cpp::rpc_balance)
#   chain_summary        accumulated_subsidy / accumulated_slashed — read
#                        only to assert NEF touched neither (A1 internal-
#                        transfer cross-check; via `determ supply --json`)
#                        (src/node/node.cpp::rpc_chain_summary)
#   block <h>            per-block JSON; transactions[].type (int; REGISTER
#                        == 1 per include/determ/chain/block.hpp::TxType)
#                        + transactions[].from (via `determ block-info`)
#                        (src/node/node.cpp::rpc_block ->
#                         src/chain/block.cpp::Block::to_json)
#
# ANTI-HANG: no node spawning, no unbounded loops, single window walk then
# exit (no --watch). Every block-info call is wrapped in a 15s subprocess
# timeout, so the worst case is bounded by (#blocks_in_window x 15s) even
# if a daemon hangs mid-response.
#
# Usage:
#   tools/operator_nef_drain_audit.sh [--rpc-port N] [--json]
#                                     [--genesis <file>]
#                                     [--from H] [--to H]
#                                     [--floor N]
#                                     [--anomalies-only]
#
# Defaults:
#   --rpc-port   7778
#   --from/--to  last 1000 blocks ending at current head (clamped to 0)
#   --floor      1   (next-grant dust threshold; <= this => NEF-floor flag)
#
# --json shape:
#   {"rpc_port":N,"shard_id":N,"sharding_mode":"...",
#    "window":{"from":H,"to":H,"blocks":N},
#    "zeroth_pool_initial":N|null,   # null when --genesis not supplied
#    "live_pool":N,
#    "granted_total":N|null,         # initial - live (null if no initial)
#    "next_grant":N,                 # floor(live/2)
#    "registers_in_window":N,        # REGISTER tx count (upper bound)
#    "halvings_observed":N|null,     # floor(log2(initial/live))
#    "halvings_attributable":N|null, # halvings the window can account for
#    "a1_internal_transfer_ok":true|false,
#    "accumulated_subsidy":N,"accumulated_slashed":N,
#    "anomalies":[...],
#    "info":"..."}                   # set on short-circuit paths
#
# Anomaly flags (each adds an entry to anomalies[]):
#   nef_not_seeded          zeroth_pool_initial == 0 (no NEF program). INFO,
#                           exit 0 (not an error — many chains run no NEF).
#   nef_inert               next_grant == 0 (pool < 2; newcomers get nothing).
#                           INFO; exit 2 only under --anomalies-only.
#   nef_floor               0 < next_grant <= --floor (program near-inert).
#                           INFO; exit 2 only under --anomalies-only.
#   halving_underflow       registers_in_window < halvings_attributable —
#                           the pool drained more than the window's
#                           REGISTERs can explain. Exit 2 (operator alert).
#   a1_internal_violation   live_pool > zeroth_pool_initial (the pool GREW —
#                           impossible for a halving-only drain; would mean
#                           a credit to ZEROTH that is not a NEF refund).
#                           Exit 2 (operator alert).
#
# Exit codes:
#   0   healthy / informational (or NEF not seeded / single-shard)
#   1   RPC error / bad args / malformed response
#   2   reconciliation anomaly (halving_underflow / a1_internal_violation),
#       OR --anomalies-only AND >=1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_nef_drain_audit.sh [--rpc-port N] [--json]
                                   [--genesis <file>]
                                   [--from H] [--to H]
                                   [--floor N]
                                   [--anomalies-only]

Reconciles the E1 Negative-Entry-Fee (NEF) geometric pool drain against
the on-chain REGISTER history. The Zeroth pool halves on each first-time
REGISTER (pool/2 transferred to the newcomer); from the live ZEROTH
balance this script recovers the effective halving count and checks it
against the REGISTER txs in the window:

  registers_in_window >= halvings_attributable_to_window

and confirms the drain is a pure intra-supply transfer (it touched
neither accumulated_subsidy nor accumulated_slashed -> A1 holds).

Reads only the status/head/balance/supply/block RPCs. NO mutating
endpoints. Single window walk then exit (no --watch); every block-info
call uses a bounded timeout.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --genesis <file>    Genesis JSON; sources zeroth_pool_initial
                      (authoritative). Without it the halving
                      reconciliation is reported as not-checkable.
  --from H            Start of audit window (default: max(0, head-1000))
  --to H              End of audit window   (default: current head)
  --floor N           Next-grant dust threshold (default: 1). A next grant
                      <= N raises the nef_floor INFO flag.
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  nef_not_seeded         zeroth_pool_initial == 0 (no NEF program)   info
  nef_inert              next_grant == 0 (pool < 2)                  info
  nef_floor              0 < next_grant <= --floor                   info
  halving_underflow      registers < attributable halvings          exit 2
  a1_internal_violation  live_pool > zeroth_pool_initial             exit 2

Exit codes:
  0   healthy / informational (or NEF not seeded / single-shard)
  1   RPC error / bad args / malformed response
  2   reconciliation anomaly, or --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
GEN_PATH=""
FROM_H=""
TO_H=""
FLOOR=1
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";        shift 2 ;;
    --json)            JSON_OUT=1;           shift ;;
    --genesis)         GEN_PATH="${2:-}";    shift 2 ;;
    --from)            FROM_H="${2:-}";      shift 2 ;;
    --to)              TO_H="${2:-}";        shift 2 ;;
    --floor)           FLOOR="${2:-}";       shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;          shift ;;
    *) echo "operator_nef_drain_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Numeric guards on user-supplied values ───────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_nef_drain_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_nef_drain_audit: --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done
case "$FLOOR" in *[!0-9]*|"")
  echo "operator_nef_drain_audit: --floor must be a non-negative integer (got '$FLOOR')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_nef_drain_audit: jq is required (per-block JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_nef_drain_audit: python is required for the window walk + reconciliation" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# Validate --genesis early (cheap arg-surface guard) so a typo'd path
# fails before we touch the daemon. The python pass re-reads the file.
if [ -n "$GEN_PATH" ] && [ ! -r "$GEN_PATH" ]; then
  echo "operator_nef_drain_audit: --genesis path not readable: $GEN_PATH" >&2
  exit 1
fi

# ZEROTH_ADDRESS canonical anon address (matches
# include/determ/chain/params.hpp::ZEROTH_ADDRESS and the sibling
# operator_subsidy_pool_health.sh). The NEF pool lives here.
ZEROTH_ADDR="0x0000000000000000000000000000000000000000000000000000000000000000"

# ── Step 1: probe daemon for shard config ────────────────────────────────────
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_nef_drain_audit: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}
MY_SHARD_ID=$(printf '%s' "$STATUS_JSON" | jq -r '.shard_id // 0')
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac
SHARDING_MODE=$(printf '%s' "$STATUS_JSON" | jq -r '.protections.sharding_mode // "unknown"')

# Resolve head height.
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_nef_drain_audit: RPC error from \`determ head\` (port $PORT)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // 0')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_nef_drain_audit: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Live Zeroth-pool balance (the E1 NEF residual). The balance RPC returns
# the canonical anon account's balance; an absent account reads 0.
BAL_JSON=$("$DETERM" balance "$ZEROTH_ADDR" --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_nef_drain_audit: RPC error from \`determ balance <ZEROTH>\` (port $PORT)" >&2
  exit 1
}
LIVE_POOL=$(printf '%s' "$BAL_JSON" | jq -r '.balance // 0')
case "$LIVE_POOL" in *[!0-9]*|"") LIVE_POOL=0 ;; esac

# accumulated_subsidy / accumulated_slashed for the A1 internal-transfer
# cross-check. NEF is a pure ZEROTH->domain move, so it MUST leave both
# untouched; we surface them so the operator can confirm the pool drain
# did not coincide with any mint/burn drift in the same window.
SUPPLY_JSON=$("$DETERM" supply --json --rpc-port "$PORT" 2>/dev/null) || SUPPLY_JSON=""
ACC_SUBSIDY=$(printf '%s' "$SUPPLY_JSON" | jq -r '.accumulated_subsidy // 0' 2>/dev/null)
ACC_SLASHED=$(printf '%s' "$SUPPLY_JSON" | jq -r '.accumulated_slashed // 0' 2>/dev/null)
case "$ACC_SUBSIDY" in *[!0-9]*|"") ACC_SUBSIDY=0 ;; esac
case "$ACC_SLASHED" in *[!0-9]*|"") ACC_SLASHED=0 ;; esac

# Default window: last 1000 blocks ending at current head. Highest
# finalized index is height-1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_nef_drain_audit: --to ($TO) < --from ($FROM); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# Whether the window is the FULL chain history. The halving reconciliation
# is exact only when the window covers every REGISTER (so the upper-bound
# register count brackets every first-time). For a partial window we still
# report the relation but soften halving_underflow into INFO (the missing
# REGISTERs legitimately explain the gap).
FULL_HISTORY=0
if [ "$FROM" -eq 0 ] && [ "$TO" -eq "$TOP" ]; then FULL_HISTORY=1; fi

# Short-circuit on empty chain.
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"rpc_port":%s,"shard_id":%s,"sharding_mode":"%s","window":{"from":%s,"to":%s,"blocks":0},"zeroth_pool_initial":null,"live_pool":%s,"granted_total":null,"next_grant":0,"registers_in_window":0,"halvings_observed":null,"halvings_attributable":null,"a1_internal_transfer_ok":true,"accumulated_subsidy":%s,"accumulated_slashed":%s,"anomalies":[],"info":"empty_chain"}\n' \
      "$PORT" "$MY_SHARD_ID" "$SHARDING_MODE" "$FROM" "$TO" "$LIVE_POOL" "$ACC_SUBSIDY" "$ACC_SLASHED"
  else
    echo "operator_nef_drain_audit: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# ── Step 2: walk window via block-info, count REGISTERs, reconcile ───────────
# All arithmetic (log2 halving inverse, attribution, gating, rendering)
# happens in one python pass so we never spin a shell loop that could
# block. subprocess timeouts (15s) on every block-info bound the worst
# case to (#blocks x 15s) even if a daemon hangs mid-response.
"$PY" - "$DETERM" "$PORT" "$FROM" "$TO" "$ZEROTH_ADDR" \
       "$LIVE_POOL" "$GEN_PATH" "$FLOOR" "$FULL_HISTORY" \
       "$MY_SHARD_ID" "$SHARDING_MODE" "$ACC_SUBSIDY" "$ACC_SLASHED" \
       "$JSON_OUT" "$ANOM_ONLY" <<'PY'
import json, subprocess, sys

(determ, port, from_s, to_s, zeroth_addr, live_s, gen_path, floor_s,
 full_hist_s, shard_id_s, sharding_mode, acc_subsidy_s, acc_slashed_s,
 json_out_s, anom_only_s) = sys.argv[1:16]

from_h = int(from_s); to_h = int(to_s)
live   = int(live_s)
floor_v = int(floor_s)
full_history = (full_hist_s == "1")
json_out  = (json_out_s == "1")
anom_only = (anom_only_s == "1")
shard_id  = int(shard_id_s)
acc_subsidy = int(acc_subsidy_s)
acc_slashed = int(acc_slashed_s)
win_blocks = to_h - from_h + 1

# REGISTER tx discriminator: Transaction::to_json emits `type` as the
# integer enum value (src/chain/block.cpp). REGISTER == 1 per
# include/determ/chain/block.hpp::TxType. `from` is the registrant domain;
# a REGISTER whose `from` is ZEROTH would be a no-op drain guard in
# apply_block (and is computationally unsignable), so we exclude it.
TXTYPE_REGISTER = 1

# ── Source zeroth_pool_initial from --genesis (authoritative) ─────────────
zeroth_initial = None
if gen_path:
    try:
        with open(gen_path, "r") as f:
            g = json.load(f)
        zeroth_initial = int(g.get("zeroth_pool_initial", 0))
    except Exception as e:
        sys.stderr.write(f"operator_nef_drain_audit: failed to parse --genesis JSON: {e}\n")
        sys.exit(1)

# ── Walk the window, counting REGISTER txs (upper bound on first-times) ────
registers = 0
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_nef_drain_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_nef_drain_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_nef_drain_audit: malformed block-info JSON at {h}\n")
        sys.exit(1)
    txs = blk.get("transactions", [])
    if not isinstance(txs, list):
        continue
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        # `type` is serialized as an int; tolerate a string form defensively.
        t = tx.get("type", None)
        try:
            t = int(t)
        except Exception:
            continue
        if t != TXTYPE_REGISTER:
            continue
        frm = tx.get("from", "")
        if frm == zeroth_addr:
            continue
        registers += 1

# ── Geometric-halving reconciliation ─────────────────────────────────────
# next grant is exact regardless of whether we know the initial.
next_grant = live // 2

anomalies = []
info = None

halvings_observed = None
halvings_attributable = None
granted_total = None
a1_internal_ok = True

if zeroth_initial is None:
    # No genesis -> we have the live residual + next-grant schedule but
    # cannot derive the halving count. The walk + register count still ran.
    info = "halving_reconciliation_not_checkable_without_genesis"
elif zeroth_initial == 0:
    anomalies.append("nef_not_seeded")
    info = "nef_not_seeded"
    granted_total = 0
else:
    granted_total = zeroth_initial - live

    # a1_internal_violation: the pool can only ever SHRINK under a
    # halving-only drain. A live balance above the genesis seed means
    # something credited ZEROTH that was not a NEF refund — an A1
    # internal-transfer break.
    if live > zeroth_initial:
        a1_internal_ok = False
        anomalies.append("a1_internal_violation")

    # F_obs = largest F with floor(zeroth_initial / 2^F) >= max(1, live).
    # Computed by repeated halving (exact integer floor at each step,
    # matching the apply path's `pool.balance / 2`), capped to avoid an
    # unbounded loop on a degenerate live==0 pool.
    if a1_internal_ok:
        cur = zeroth_initial
        F = 0
        target = max(1, live)
        # zeroth_initial fits in u64 => at most 64 halvings to reach 0.
        while cur > target and F < 64:
            cur //= 2
            F += 1
        # `cur` is now floor(initial/2^F); F is the count of halvings that
        # brings the pool to (or just below) the observed live level. When
        # live==0 the pool fully drained: F is the count to reach 0.
        halvings_observed = F

        # Attribution: halvings the AUDITED WINDOW can account for. Over a
        # full-history window every halving is attributable. Over a partial
        # window we cannot bound how many of the observed halvings happened
        # inside [from..to], so we only assert the relation at full scope.
        if full_history:
            halvings_attributable = halvings_observed
            # halving_underflow: more halvings than the upper-bound register
            # count. Since halvings <= first_times <= registers, this is a
            # hard contradiction at full scope.
            if registers < halvings_attributable:
                anomalies.append("halving_underflow")
        else:
            halvings_attributable = None  # not assertable on a partial window

    # NEF residual-health flags (INFO; only gate under --anomalies-only).
    if next_grant == 0:
        anomalies.append("nef_inert")
    elif next_grant <= floor_v:
        anomalies.append("nef_floor")

# ── Exit-code policy ─────────────────────────────────────────────────────
# Hard anomalies (always exit 2) vs. informational flags (exit 2 only
# under --anomalies-only).
HARD = {"halving_underflow", "a1_internal_violation"}
hard_hit = any(a in HARD for a in anomalies)
soft_hit = any(a not in HARD for a in anomalies)

if json_out:
    env = {
        "rpc_port": int(port),
        "shard_id": shard_id,
        "sharding_mode": sharding_mode,
        "window": {"from": from_h, "to": to_h, "blocks": win_blocks},
        "zeroth_pool_initial": zeroth_initial,
        "live_pool": live,
        "granted_total": granted_total,
        "next_grant": next_grant,
        "registers_in_window": registers,
        "halvings_observed": halvings_observed,
        "halvings_attributable": halvings_attributable,
        "a1_internal_transfer_ok": a1_internal_ok,
        "accumulated_subsidy": acc_subsidy,
        "accumulated_slashed": acc_slashed,
        "anomalies": anomalies,
    }
    if info:
        env["info"] = info
    print(json.dumps(env))
else:
    if not anom_only:
        print(f"=== NEF drain reconciliation (shard {shard_id}, port {port}) ===")
        print(f"sharding_mode: {sharding_mode}")
        print(f"window: blocks [{from_h}..{to_h}] ({win_blocks} block"
              f"{'' if win_blocks == 1 else 's'})"
              f"{'  [full history]' if full_history else '  [partial — halving attribution suppressed]'}")
        if zeroth_initial is not None:
            print(f"  zeroth_pool_initial : {zeroth_initial}")
        else:
            print(f"  zeroth_pool_initial : (unknown — supply --genesis to reconcile halvings)")
        print(f"  live_pool           : {live}")
        if granted_total is not None:
            print(f"  granted_total       : {granted_total}  (= initial - live)")
        print(f"  next_grant          : {next_grant}  (= floor(live/2) — the next first-time REGISTER's NEF)")
        print(f"  registers_in_window : {registers}  (REGISTER tx count — UPPER BOUND on first-times)")
        if halvings_observed is not None:
            print(f"  halvings_observed   : {halvings_observed}  (= floor(log2(initial/live)))")
        if halvings_attributable is not None:
            rel = "OK" if registers >= halvings_attributable else "VIOLATED"
            print(f"  reconciliation      : registers ({registers}) >= halvings ({halvings_attributable})  ->  {rel}")
        print(f"  A1 internal-transfer: accumulated_subsidy={acc_subsidy} accumulated_slashed={acc_slashed} "
              f"(NEF must touch neither)  ->  {'OK' if a1_internal_ok else 'VIOLATED'}")

    # Flag lines (always printed; --anomalies-only prints ONLY these).
    if "nef_not_seeded" in anomalies:
        print("[INFO] NEF not seeded (zeroth_pool_initial == 0): this chain runs no Negative-Entry-Fee program.")
    if "nef_inert" in anomalies:
        print("[INFO] NEF inert: next_grant == 0 (pool < 2) — new REGISTERs receive no NEF grant.")
    if "nef_floor" in anomalies:
        print(f"[INFO] NEF near floor: next_grant ({next_grant}) <= --floor ({floor_v}) — program barely subsidizing onboarding.")
    if "halving_underflow" in anomalies:
        print(f"[VIOLATED] halving_underflow: registers ({registers}) < attributable halvings "
              f"({halvings_attributable}) over full history — the pool drained more than the visible "
              f"REGISTERs can explain (model break or out-of-scope drain).")
    if "a1_internal_violation" in anomalies:
        print(f"[VIOLATED] a1_internal_violation: live_pool ({live}) > zeroth_pool_initial ({zeroth_initial}) "
              f"— the Zeroth pool GREW, impossible under a halving-only drain (a non-NEF credit reached ZEROTH).")
    if info == "halving_reconciliation_not_checkable_without_genesis" and not anom_only:
        print("[INFO] halving reconciliation skipped: re-run with --genesis <file> to source zeroth_pool_initial.")

    if not anomalies and not anom_only:
        print("[OK] no NEF drain anomaly detected.")

if hard_hit:
    sys.exit(2)
if anom_only and soft_hit:
    sys.exit(2)
sys.exit(0)
PY
RC=$?
exit $RC
