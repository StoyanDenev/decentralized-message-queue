#!/usr/bin/env bash
# operator_supply_reconcile.sh — Read-only reconciliation of the A1
# unitary-supply identity for a running determ daemon (single shard) and,
# with --peer-ports, across the whole shard fleet (the chain-wide
# conservation law).
#
# THE OPERATOR QUESTION
#   "Does the money add up?" Concretely: for THIS shard, does the A1
#   unitary-supply identity hold, and — across the fleet — is total value
#   conserved once cross-shard in-flight receipts are accounted for?
#
# THE IDENTITY (per shard, server-computed by `determ supply`):
#   A1 holds iff
#       live_total_supply
#         == genesis_total + accumulated_subsidy + accumulated_inbound
#            - accumulated_slashed - accumulated_outbound
#   (i.e. expected_total == live_total_supply; the server stamps
#    a1_invariant_ok). Rearranged into the conservation framing this is
#       live + slashed + outbound  ==  genesis + subsidy + inbound
#   — every unit either still circulates (live), was burned as a slash
#   penalty (slashed), or left this shard as a cross-shard receipt
#   (outbound); and every unit was either minted at genesis, minted as
#   subsidy, or arrived as an applied inbound receipt.
#
# THE CHAIN-WIDE CONSERVATION (fleet, with --peer-ports):
#   Each shard's A1 identity is exact on its own, so summing over the
#   reachable fleet is also exact:
#       Σ live + Σ slashed + Σ outbound  ==  Σ genesis + Σ subsidy + Σ inbound
#   The cross-shard legs Σ inbound / Σ outbound are what tie shards
#   together. The value that has been DEBITED on a sending shard
#   (counted in Σ outbound) but NOT YET APPLIED on a receiving shard
#   (Σ inbound) is in-flight:
#       in_flight = Σ outbound − Σ inbound  ≥ 0    (steady state)
#   Folding the in-flight term to the mint side gives the operator's
#   "supply is conserved" headline:
#       Σ genesis + Σ subsidy  ==  Σ live + Σ slashed + in_flight
#   i.e. (Σ genesis + Σ subsidy) − (Σ live + Σ slashed) == in_flight ≥ 0.
#   A negative in_flight (Σ inbound > Σ outbound) is CATASTROPHIC: more
#   value was applied across the fleet than was ever emitted (an FA7 / A1
#   cross-shard double-credit or a forged receipt). See
#   docs/proofs/CrossShardSupplyConservation.md.
#
# WHAT ONE SHARD CAN vs CANNOT TELL YOU:
#   A single daemon's `determ supply` already computes its OWN A1 gate
#   server-side (a1_invariant_ok). So the single-port mode is a faithful
#   per-shard A1 reconciliation. But the fleet-wide conservation law can
#   only be verified when every shard's counters are visible — so:
#     * single --rpc-port   → reconcile THIS shard's A1 ledger; report
#                             balanced / VIOLATED. The fleet conservation
#                             law is reported as "not checkable from one
#                             shard".
#     * --peer-ports P1,..   → query every shard daemon, sum the six legs,
#                             reconcile the fleet identity, and surface the
#                             cross-shard in-flight residual.
#
# SIBLING TOOLS — how this one differs (run those for their angle):
#   operator_supply_check.sh
#       The bare per-shard A1 pass/fail gate (exit 0/2), one RPC, no
#       ledger decomposition and no fleet view. THIS script is the
#       reconciliation superset: it prints the full six-leg ledger, frames
#       it as the conservation law, AND adds the multi-shard chain-wide
#       identity via --peer-ports.
#   operator_slashing_ledger.sh
#       Single-shard A1 identity in the SLASHING-centric framing
#       (live + slashed == genesis + subsidy + inbound − outbound) plus
#       per-domain slash forensics. Single shard only; no fleet sum.
#   operator_receipt_flow.sh
#       Fleet-level CROSS-SHARD receipt flow: balances the two receipt
#       legs (Σ outbound vs Σ inbound + pending) only. THIS script
#       reconciles the FULL A1 supply identity (all six legs incl.
#       genesis / subsidy / slashed), of which the receipt legs are a
#       part, and folds the in-flight term into the supply headline.
#   operator_inbound_outbound_balance.sh
#       Per-shard net cross-shard flow + trend over a block window
#       (block-walk). Different question (flow over time, not the
#       supply identity).
#
# RPC SURFACE (read-only; NO mutating endpoints; safe against any running
# daemon):
#   supply  →  genesis_total, accumulated_subsidy, accumulated_inbound,
#              accumulated_slashed, accumulated_outbound, expected_total,
#              live_total_supply, a1_invariant_ok
#              (src/main.cpp::cmd_supply, computed from the chain_summary
#               RPC; a1_invariant_ok is the authoritative per-shard gate)
#   status  →  shard_id, protections.sharding_mode  (only to label the
#              fleet table + drive the single-shard short-circuit;
#              src/node/node.cpp::rpc_status)
#
# Single-shard deployments (sharding_mode == "none"): the cross-shard
# legs (inbound/outbound) are 0 by construction, so the fleet identity
# degenerates to the per-shard A1 gate. The script still reconciles A1
# and reports it; --peer-ports adds nothing and is noted as such.
#
# ANTI-HANG: no node spawning, no unbounded loops, single query then exit
# (no --watch). Every RPC call is wrapped in an 8s subprocess timeout, so
# the worst case is bounded by (#ports × 2 calls × 8s) even if a daemon
# hangs mid-response.
#
# Usage:
#   tools/operator_supply_reconcile.sh --rpc-port N
#                                      [--peer-ports P1,P2,...]
#                                      [--json]
#
# --rpc-port is the LOCAL shard daemon (REQUIRED). --peer-ports is a
# comma-separated list of OTHER shard daemons' RPC ports; the local port
# is always folded into the fleet aggregate (de-duplicated). All ports
# are assumed to be on 127.0.0.1 (the determ CLI's RPC host).
#
# --json shape:
#   single-port:
#     {"mode":"single","rpc_port":N,"shard_id":N,"sharding_mode":"...",
#      "ledger":{genesis_total,accumulated_subsidy,accumulated_inbound,
#                accumulated_slashed,accumulated_outbound,expected_total,
#                live_total_supply},
#      "a1_invariant_ok":true|false,
#      "fleet_conservation_checkable":false,"anomalies":[...]}
#   fleet (--peer-ports):
#     {"mode":"fleet","ports":[N,...],
#      "shards":[{rpc_port,shard_id,sharding_mode,a1_invariant_ok,
#                 genesis_total,accumulated_subsidy,accumulated_inbound,
#                 accumulated_slashed,accumulated_outbound,
#                 expected_total,live_total_supply}, ...],
#      "totals":{genesis_total,accumulated_subsidy,accumulated_inbound,
#                accumulated_slashed,accumulated_outbound,
#                live_total_supply,
#                mint_side,            # Σgenesis + Σsubsidy
#                burn_side,            # Σlive + Σslashed
#                in_flight},           # Σoutbound − Σinbound
#      "fleet_conservation_ok":true|false,
#      "duplicate_shard_ids":[...],"unreachable_ports":[...],
#      "anomalies":[...]}
#
# Anomaly flags:
#   a1_violation          A reachable shard reports a1_invariant_ok=false
#                         (its own ledger does not reconcile). Exit 2.
#   fleet_double_credit   Σ inbound > Σ outbound across the fleet
#                         (in_flight < 0) — more value applied than ever
#                         emitted. CATASTROPHIC. Exit 2.
#   fleet_conservation_violation
#                         The fleet identity Σ(live+slashed+outbound) ==
#                         Σ(genesis+subsidy+inbound) does not hold even
#                         though every shard is reachable and reports A1
#                         OK (would indicate an arithmetic/counter bug —
#                         impossible if each shard's A1 holds, so it is a
#                         belt-and-suspenders gate). Exit 2.
#   duplicate_shard_id    two queried daemons report the same shard_id
#                         (mis-aimed --peer-ports — pointing at two
#                         replicas of one shard double-counts its
#                         counters). Exit 1 (operator error).
#   unreachable_peer      a --peer-ports entry could not be queried. The
#                         fleet conservation gate is suppressed (cannot
#                         reconcile a fleet we can't fully see). Exit 1.
#
# Exit codes:
#   0   balanced / healthy (single-shard deployment also exits 0)
#   1   RPC error / bad args / unreachable peer / duplicate shard_id
#   2   A1 supply-identity VIOLATED (per-shard a1_violation, fleet
#       double-credit, or fleet conservation violation) — operator alert
set -u

usage() {
  cat <<'EOF'
Usage: operator_supply_reconcile.sh --rpc-port N
                                    [--peer-ports P1,P2,...]
                                    [--json]

Read-only reconciliation of the A1 unitary-supply identity for a running
determ daemon (single shard) and, with --peer-ports, the chain-wide
conservation law across the shard fleet.

Per-shard (always): reconciles
  live == genesis + subsidy + inbound - slashed - outbound
using the server-stamped a1_invariant_ok from `determ supply`.

Fleet (--peer-ports): sums the six supply legs over every reachable shard
and reconciles
  Sigma(live + slashed + outbound) == Sigma(genesis + subsidy + inbound),
surfacing the cross-shard in-flight residual in_flight = Sigma_out - Sigma_in
(value emitted but not yet applied; must be >= 0). See
docs/proofs/CrossShardSupplyConservation.md.

Reads only the supply/status RPCs. NO mutating endpoints. Single query
then exit (no --watch); all RPC calls use bounded timeouts.

Required:
  --rpc-port N             LOCAL shard daemon RPC port

Options:
  --peer-ports P1,P2,...   Comma-separated RPC ports of OTHER shard
                           daemons (all on 127.0.0.1). The local port is
                           always folded into the fleet aggregate.
  --json                   Emit a structured JSON envelope
  -h, --help               Show this help

Anomaly flags:
  a1_violation                 a reachable shard's own A1 ledger fails    exit 2
  fleet_double_credit          Sigma_in > Sigma_out (in_flight < 0)        exit 2
  fleet_conservation_violation fleet identity fails despite per-shard OK   exit 2
  duplicate_shard_id           two daemons report the same shard_id        exit 1
  unreachable_peer             a --peer-ports entry could not be queried   exit 1

Exit codes:
  0   balanced / healthy (or single-shard deployment)
  1   RPC error / bad args / unreachable peer / duplicate shard_id
  2   A1 supply-identity VIOLATED (operator alert gate)
EOF
}

PORT=""
PEER_PORTS=""
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)      usage; exit 0 ;;
    --rpc-port)     PORT="${2:-}";       shift 2 ;;
    --peer-ports)   PEER_PORTS="${2:-}"; shift 2 ;;
    --json)         JSON_OUT=1;          shift ;;
    *) echo "operator_supply_reconcile: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Argument validation (post --help so --help never trips it) ────────────────
if [ -z "$PORT" ]; then
  echo "operator_supply_reconcile: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_supply_reconcile: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Validate each --peer-ports entry up-front (cheap arg-surface guard; the
# python driver re-parses the same list but we want a clean early error).
if [ -n "$PEER_PORTS" ]; then
  OLD_IFS="$IFS"; IFS=','
  for p in $PEER_PORTS; do
    [ -z "$p" ] && continue
    case "$p" in *[!0-9]*)
      IFS="$OLD_IFS"
      echo "operator_supply_reconcile: --peer-ports entries must be unsigned integers (got '$p')" >&2
      exit 1 ;;
    esac
  done
  IFS="$OLD_IFS"
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# python required for JSON parse + multi-port fan-out (status JSON is
# nested under protections.* and we avoid a hard jq dependency, matching
# operator_receipt_flow.sh's python-heredoc RPC driver convention).
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_supply_reconcile: python is required (JSON parse + multi-port fan-out)" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# Promote DETERM to an absolute path so python's subprocess.run resolves
# the binary identically on Linux/Mac/Git Bash (matches the pattern used
# in operator_receipt_flow.sh / operator_cross_shard_health.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# All work (RPC fan-out, summation, gating, rendering) happens in one
# python pass so we never spin a shell loop that could block. subprocess
# timeouts (8s) on every RPC call bound the worst case to
# (#ports × 2 calls × 8s) even if a daemon hangs mid-response.
"$PY" - "$DETERM_ABS" "$PORT" "$PEER_PORTS" "$JSON_OUT" <<'PY'
import json, subprocess, sys

determ, local_port_s, peer_ports_s, json_out_s = sys.argv[1:5]
local_port = int(local_port_s)
json_out   = (json_out_s == "1")

# Build the de-duplicated port list: local first, then any peers not equal
# to local (preserving first-seen order).
ports = [local_port]
for chunk in (peer_ports_s.split(",") if peer_ports_s else []):
    chunk = chunk.strip()
    if not chunk:
        continue
    p = int(chunk)
    if p not in ports:
        ports.append(p)
fleet_mode = len(ports) > 1 or bool(peer_ports_s)

def rpc(port, cmd):
    """Run `determ <cmd> --json --rpc-port <port>`; return parsed JSON or
    None on any error (unreachable, non-zero rc, non-JSON). NOTE: `supply`
    exits 2 on an A1 violation, so we MUST NOT treat a non-zero rc as a
    hard failure for it — we read the rc==2 path's JSON too (the body
    carries a1_invariant_ok=false). We therefore parse stdout regardless
    of rc and only fall back to None when stdout is not valid JSON."""
    try:
        r = subprocess.run(
            [determ, cmd, "--json", "--rpc-port", str(port)],
            capture_output=True, text=True, timeout=8
        )
    except Exception:
        return None
    out = (r.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None

def probe(port):
    """Two light RPC calls for one shard daemon: `supply` (the six A1 legs
    + server-stamped gate) and `status` (shard_id + sharding_mode label).
    Returns a dict or marks the port unreachable. `supply` is the
    load-bearing call; `status` is only for labelling, so a status failure
    does NOT mark the shard unreachable (we fall back to shard_id=0 /
    sharding_mode=unknown)."""
    sup = rpc(port, "supply")
    if not isinstance(sup, dict):
        return {"rpc_port": port, "reachable": False}

    def u64(k):
        try:
            return int(sup.get(k, 0))
        except Exception:
            return 0

    a1 = sup.get("a1_invariant_ok", None)
    a1 = bool(a1) if isinstance(a1, bool) else None  # None => field absent

    st = rpc(port, "status")
    shard_id = 0
    sharding_mode = "unknown"
    if isinstance(st, dict):
        try:
            shard_id = int(st.get("shard_id", 0))
        except Exception:
            shard_id = 0
        prot = st.get("protections") or {}
        sharding_mode = str(prot.get("sharding_mode", "unknown"))

    return {
        "rpc_port":             port,
        "reachable":            True,
        "shard_id":             shard_id,
        "sharding_mode":        sharding_mode,
        "genesis_total":        u64("genesis_total"),
        "accumulated_subsidy":  u64("accumulated_subsidy"),
        "accumulated_inbound":  u64("accumulated_inbound"),
        "accumulated_slashed":  u64("accumulated_slashed"),
        "accumulated_outbound": u64("accumulated_outbound"),
        "expected_total":       u64("expected_total"),
        "live_total_supply":    u64("live_total_supply"),
        "a1_invariant_ok":      a1,
    }

def shard_a1_ok(s):
    """Resolve a shard's own A1 gate. Trust the server bit when present;
    otherwise recompute from the six legs."""
    if isinstance(s.get("a1_invariant_ok"), bool):
        return s["a1_invariant_ok"]
    return s["expected_total"] == s["live_total_supply"]

# ── Probe the local shard first. A local RPC failure is always fatal. ─────────
local = probe(local_port)
if not local["reachable"]:
    sys.stderr.write(
        f"operator_supply_reconcile: RPC error talking to local daemon on "
        f"port {local_port} (is determ running there?)\n")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────
# SINGLE-PORT MODE: reconcile this shard's A1 ledger. The fleet-wide
# conservation law is NOT checkable from one shard.
# ──────────────────────────────────────────────────────────────────────────
if not fleet_mode:
    a1_ok = shard_a1_ok(local)
    anomalies = [] if a1_ok else ["a1_violation"]
    exit_code = 0 if a1_ok else 2

    if json_out:
        env = {
            "mode": "single",
            "rpc_port": local_port,
            "shard_id": local["shard_id"],
            "sharding_mode": local["sharding_mode"],
            "ledger": {
                "genesis_total":        local["genesis_total"],
                "accumulated_subsidy":  local["accumulated_subsidy"],
                "accumulated_inbound":  local["accumulated_inbound"],
                "accumulated_slashed":  local["accumulated_slashed"],
                "accumulated_outbound": local["accumulated_outbound"],
                "expected_total":       local["expected_total"],
                "live_total_supply":    local["live_total_supply"],
            },
            "a1_invariant_ok": a1_ok,
            "fleet_conservation_checkable": False,
            "anomalies": anomalies,
        }
        print(json.dumps(env))
        sys.exit(exit_code)

    g  = local["genesis_total"]
    sb = local["accumulated_subsidy"]
    ib = local["accumulated_inbound"]
    sl = local["accumulated_slashed"]
    ob = local["accumulated_outbound"]
    ex = local["expected_total"]
    lv = local["live_total_supply"]
    print(f"=== A1 supply reconciliation (shard {local['shard_id']}, "
          f"port {local_port}) ===")
    print(f"sharding_mode: {local['sharding_mode']}")
    print(f"  genesis_total        : {g}")
    print(f"  + accumulated_subsidy : {sb}")
    print(f"  + accumulated_inbound : {ib}")
    print(f"  - accumulated_slashed : {sl}")
    print(f"  - accumulated_outbound: {ob}")
    print(f"  = expected_total      : {ex}")
    print(f"    live_total_supply   : {lv}")
    print(f"  conservation form: live + slashed + outbound == genesis + subsidy + inbound")
    print(f"                     {lv + sl + ob} == {g + sb + ib}  ->  "
          f"{'OK' if (lv + sl + ob) == (g + sb + ib) else 'VIOLATED'}")
    if a1_ok:
        print(f"[OK] A1 invariant holds (expected_total == live_total_supply).")
    else:
        print(f"[VIOLATED] A1 invariant FAILS: expected_total ({ex}) != "
              f"live_total_supply ({lv}) — operator alert.")
    print("Fleet conservation law: not checkable from a single shard "
          "(only this shard's counters are visible).")
    print("  Re-run with --peer-ports <other shard RPC ports> to reconcile the "
          "chain-wide identity")
    print("  Sigma(live+slashed+outbound) == Sigma(genesis+subsidy+inbound)  "
          "(see docs/proofs/CrossShardSupplyConservation.md).")
    sys.exit(exit_code)

# ──────────────────────────────────────────────────────────────────────────
# FLEET MODE (--peer-ports): probe every shard, sum, reconcile.
# ──────────────────────────────────────────────────────────────────────────
shards = [local]
for p in ports[1:]:
    shards.append(probe(p))

reachable   = [s for s in shards if s.get("reachable")]
unreachable = [s["rpc_port"] for s in shards if not s.get("reachable")]

# Duplicate shard_id detection across REACHABLE daemons. Pointing
# --peer-ports at two replicas of the same shard would double-count that
# shard's counters and corrupt the fleet identity, so we treat it as an
# operator error (exit 1) rather than a chain anomaly.
seen = {}
dup_shard_ids = []
for s in reachable:
    sid = s["shard_id"]
    if sid in seen:
        if sid not in dup_shard_ids:
            dup_shard_ids.append(sid)
    else:
        seen[sid] = s["rpc_port"]

# Fleet totals over reachable shards.
tot_genesis  = sum(s["genesis_total"]        for s in reachable)
tot_subsidy  = sum(s["accumulated_subsidy"]  for s in reachable)
tot_inbound  = sum(s["accumulated_inbound"]  for s in reachable)
tot_slashed  = sum(s["accumulated_slashed"]  for s in reachable)
tot_outbound = sum(s["accumulated_outbound"] for s in reachable)
tot_live     = sum(s["live_total_supply"]    for s in reachable)

mint_side = tot_genesis + tot_subsidy            # value entering the fleet
burn_side = tot_live + tot_slashed               # value still here or burned
in_flight = tot_outbound - tot_inbound           # emitted but not applied

# Fleet conservation: Σ(live + slashed + outbound) == Σ(genesis + subsidy + inbound)
fleet_lhs = tot_live + tot_slashed + tot_outbound
fleet_rhs = tot_genesis + tot_subsidy + tot_inbound
fleet_identity_holds = (fleet_lhs == fleet_rhs)

# Per-shard A1 gate over the reachable fleet.
a1_fail_ports = [s["rpc_port"] for s in reachable if not shard_a1_ok(s)]

anomalies = []
if a1_fail_ports:
    anomalies.append("a1_violation")
# fleet_double_credit: Σ_in > Σ_out → in_flight < 0 → value applied that
# was never emitted. Catastrophic regardless of per-shard A1 (a shard can
# locally reconcile while the cross-shard ledger is globally broken).
if in_flight < 0:
    anomalies.append("fleet_double_credit")

# The fleet conservation gate is only trustworthy when we can see the
# whole fleet AND there are no duplicate-shard double-counts; otherwise
# the sums are untrustworthy and we suppress the value gate.
gate_trustworthy = (not unreachable) and (not dup_shard_ids)
if gate_trustworthy and not fleet_identity_holds:
    anomalies.append("fleet_conservation_violation")

fleet_conservation_ok = (
    gate_trustworthy
    and fleet_identity_holds
    and not a1_fail_ports
    and in_flight >= 0
)

# Sort the per-shard table by shard_id (then port) for stable display.
shard_rows = sorted(reachable, key=lambda s: (s["shard_id"], s["rpc_port"]))

if json_out:
    env = {
        "mode": "fleet",
        "ports": ports,
        "shards": [
            {
                "rpc_port":             s["rpc_port"],
                "shard_id":             s["shard_id"],
                "sharding_mode":        s["sharding_mode"],
                "a1_invariant_ok":      shard_a1_ok(s),
                "genesis_total":        s["genesis_total"],
                "accumulated_subsidy":  s["accumulated_subsidy"],
                "accumulated_inbound":  s["accumulated_inbound"],
                "accumulated_slashed":  s["accumulated_slashed"],
                "accumulated_outbound": s["accumulated_outbound"],
                "expected_total":       s["expected_total"],
                "live_total_supply":    s["live_total_supply"],
            } for s in shard_rows
        ],
        "totals": {
            "genesis_total":        tot_genesis,
            "accumulated_subsidy":  tot_subsidy,
            "accumulated_inbound":  tot_inbound,
            "accumulated_slashed":  tot_slashed,
            "accumulated_outbound": tot_outbound,
            "live_total_supply":    tot_live,
            "mint_side":            mint_side,
            "burn_side":            burn_side,
            "in_flight":            in_flight,
        },
        "fleet_conservation_ok": fleet_conservation_ok,
        "a1_failed_ports":       a1_fail_ports,
        "duplicate_shard_ids":   dup_shard_ids,
        "unreachable_ports":     unreachable,
        "anomalies":             anomalies,
    }
    print(json.dumps(env))
else:
    print(f"=== A1 fleet supply reconciliation "
          f"({len(reachable)} shard(s) reachable of {len(ports)} queried) ===")
    print("Per-shard ledger (genesis / subsidy / inbound / slashed / outbound / "
          "live / A1):")
    print(f"  {'shard':>5} {'port':>6} {'genesis':>12} {'subsidy':>12} "
          f"{'inbound':>12} {'slashed':>12} {'outbound':>12} {'live':>14} {'A1':>4}")
    for s in shard_rows:
        print(f"  {s['shard_id']:>5} {s['rpc_port']:>6} "
              f"{s['genesis_total']:>12} {s['accumulated_subsidy']:>12} "
              f"{s['accumulated_inbound']:>12} {s['accumulated_slashed']:>12} "
              f"{s['accumulated_outbound']:>12} {s['live_total_supply']:>14} "
              f"{'OK' if shard_a1_ok(s) else 'BAD':>4}")
    if unreachable:
        print(f"  (unreachable ports: {', '.join(str(p) for p in unreachable)})")
    print(f"Fleet totals: genesis={tot_genesis} subsidy={tot_subsidy} "
          f"inbound={tot_inbound} slashed={tot_slashed} outbound={tot_outbound} "
          f"live={tot_live}")
    print(f"Mint side  (Sigma genesis + Sigma subsidy)         : {mint_side}")
    print(f"Burn side  (Sigma live + Sigma slashed)            : {burn_side}")
    print(f"In-flight  (Sigma outbound - Sigma inbound)        : {in_flight}  "
          f"(value emitted but not yet applied; must be >= 0)")
    print(f"Conservation: Sigma(live+slashed+outbound) == Sigma(genesis+subsidy+inbound)")
    print(f"              {fleet_lhs} == {fleet_rhs}  ->  "
          f"{'OK' if fleet_identity_holds else 'VIOLATED'}")
    print(f"Headline: mint_side - burn_side == in_flight  ->  "
          f"{mint_side - burn_side} == {in_flight}  "
          f"({'OK' if (mint_side - burn_side) == in_flight else 'MISMATCH'})")

    if a1_fail_ports:
        print(f"[VIOLATED] per-shard A1 fails on port(s): "
              f"{', '.join(str(p) for p in a1_fail_ports)} — that shard's own "
              f"ledger does not reconcile.")
    if dup_shard_ids:
        print(f"[ERROR] duplicate shard_id(s) across queried daemons: "
              f"{', '.join(str(d) for d in dup_shard_ids)}")
        print("        --peer-ports pointed at two replicas of the same shard; "
              "counters would be double-counted. Fix the port list.")
    if unreachable:
        print(f"[WARN] {len(unreachable)} port(s) unreachable; fleet conservation "
              f"gate suppressed (cannot reconcile a fleet we can't fully see).")
    if "fleet_double_credit" in anomalies:
        print(f"[CATASTROPHIC] Sigma_in ({tot_inbound}) > Sigma_out ({tot_outbound}) "
              f"— in_flight {in_flight} < 0: more value applied than ever emitted "
              f"(FA7 / A1 cross-shard double-credit).")
    if "fleet_conservation_violation" in anomalies:
        print(f"[VIOLATED] fleet conservation identity fails ({fleet_lhs} != "
              f"{fleet_rhs}) despite full fleet visibility.")

    if fleet_conservation_ok:
        print("[OK] chain-wide supply conserved: every shard's A1 holds, the "
              "fleet identity balances, and in-flight >= 0.")
    elif gate_trustworthy and not anomalies:
        print("[OK] no supply anomaly detected.")

# ── Exit-code policy ───────────────────────────────────────────────────────
# 2  A1 supply identity violated (per-shard a1_violation, fleet
#    double-credit, or fleet conservation violation) — operator alert
# 1  operator error (duplicate shard_id) or incomplete view (unreachable)
# 0  clean
if ("a1_violation" in anomalies
        or "fleet_double_credit" in anomalies
        or "fleet_conservation_violation" in anomalies):
    sys.exit(2)
if dup_shard_ids or unreachable:
    sys.exit(1)
sys.exit(0)
PY
RC=$?
exit $RC
