#!/usr/bin/env bash
# operator_receipt_flow.sh — Cross-shard receipt-FLOW audit driven by the
# A1 supply-bearing counters (NOT a per-block walk). Answers the
# operational question behind FA7 cross-shard atomicity + the K-shard
# supply identity (see docs/proofs/CrossShardSupplyConservation.md):
#
#   "Across the shard fleet, does every receipt that was EMITTED
#    (accumulated_outbound) eventually get APPLIED exactly once
#    (accumulated_inbound)? How much value is in-flight right now, and
#    is any shard-pair imbalanced?"
#
# The supply-bearing counters are chain_.accumulated_outbound_ (bumped
# when a cross-shard TRANSFER debits locally and emits a receipt off-
# shard) and chain_.accumulated_inbound_ (bumped when an inbound receipt
# is applied and credits a local account) — see
# src/chain/chain.cpp::apply_block (accumulated_inbound_ += block_inbound;
# accumulated_outbound_ += block_outbound). Over the WHOLE fleet the
# K-shard supply identity holds in steady state:
#
#       Σ_shards accumulated_outbound  ==  Σ_shards accumulated_inbound
#                                           +  (receipts in-flight)
#
# i.e. Σ_out − Σ_in == total value emitted but not-yet-applied ≥ 0. A
# fleet-wide Σ_in > Σ_out is CATASTROPHIC (a receipt was applied that was
# never emitted, or applied twice — an FA7 / A1 double-credit). A large
# positive Σ_out − Σ_in that is NOT explained by the live pending pools
# is an in-flight imbalance (stuck or lost receipts).
#
# Why counter-driven (not a block walk):
#   The neighbouring scripts (operator_receipt_audit.sh,
#   operator_inbound_outbound_balance.sh, operator_cross_shard_health.sh)
#   all walk a window of finalized blocks one `block-info` call at a time
#   and aggregate the per-block inbound_receipts[] / cross_shard_receipts[]
#   arrays. That is the right tool for per-shard-PAIR volume breakdowns,
#   trend lines, and dedup-set forensics. THIS script is the cheap fleet-
#   level FLOW + IMBALANCE probe: two light RPC calls per shard daemon
#   (`status` + `supply`), no block walk, so it scales to a many-shard
#   fleet and runs in well under a second per port. It is the
#   "is the cross-shard ledger balanced across the fleet right now?"
#   on-call probe.
#
# Sibling contrast:
#   operator_receipt_audit.sh           per-shard-pair volume table + FA7
#                                       dedup-set health + A1 delta, over a
#                                       block window (single shard).
#   operator_inbound_outbound_balance.sh net flow + least-squares trend over
#                                       time buckets (single shard).
#   operator_cross_shard_health.sh      pending-pool depth + apply-lag +
#                                       per-block emit/apply trace (single
#                                       shard).
#   operator_receipt_flow.sh  (THIS)    fleet-level outbound-vs-inbound
#                                       counter balance + per-shard-pair-able
#                                       flow matrix + in-flight estimate +
#                                       supply-identity imbalance gate.
#                                       Counter-driven; multi-daemon via
#                                       --peer-ports.
#
# RPC surface (read-only; safe against any running daemon):
#   status   →  shard_id, pending_inbound_receipts, height,
#               protections.sharding_mode   (src/node/node.cpp::rpc_status)
#   supply   →  accumulated_inbound, accumulated_outbound
#               (src/main.cpp::cmd_supply, pulled from chain_summary RPC;
#                see src/node/node.cpp::rpc_chain_summary lines 2799-2800)
#
# IMPORTANT — what one shard can and cannot tell you:
#   A SINGLE shard's daemon only exposes ITS OWN two legs
#   (accumulated_outbound = value this shard sent out;
#    accumulated_inbound = value this shard received in). The fleet-wide
#   supply identity Σ_out == Σ_in (+ in-flight) can ONLY be verified when
#   you can see every shard's counters. So:
#     * single --rpc-port            → report this shard's outbound /
#                                       inbound / net / live pending pool;
#                                       the supply-identity gate is reported
#                                       as "not checkable from one shard".
#     * --peer-ports P1,P2,...        → query each shard daemon, build the
#                                       per-shard flow table, sum, and run
#                                       the supply-identity imbalance gate.
#
# Single-shard deployments (sharding_mode == "none"): every cross-shard
# counter is trivially 0 by construction. The script short-circuits to a
# single INFO line and exits 0.
#
# Usage:
#   tools/operator_receipt_flow.sh --rpc-port N
#                                  [--peer-ports P1,P2,...]
#                                  [--imbalance-tolerance N]
#                                  [--json]
#
# --rpc-port is the LOCAL shard daemon (REQUIRED). --peer-ports is a
# comma-separated list of OTHER shard daemons' RPC ports; the local port
# is always included in the fleet aggregate (de-duplicated). All ports
# are assumed to be on 127.0.0.1 (the determ CLI's RPC host).
#
# --imbalance-tolerance N (default 0): in --peer-ports mode the
#   "fleet_imbalance" anomaly fires when (Σ_out − Σ_in − Σ_pending) is
#   outside ±N. With perfectly-synced counters and an idle pipeline the
#   residual is 0; in practice a receipt that is debited (counted in
#   Σ_out) and gossiped but not yet ADMITTED to any pending pool will
#   sit in the residual for up to CROSS_SHARD_RECEIPT_LATENCY (3) +
#   gossip-propagation blocks, so a small non-zero residual is normal on
#   a busy fleet. Set a tolerance to suppress that steady-state churn.
#
# --json shape:
#   single-port:
#     {"mode":"single","shard_id":N,"sharding_mode":"...","height":N,
#      "outbound":N,"inbound":N,"net":N,"pending_inbound":N,
#      "supply_identity_checkable":false,"anomalies":[...],"rpc_port":N}
#   fleet (--peer-ports):
#     {"mode":"fleet","ports":[N,...],
#      "shards":[{"rpc_port":N,"shard_id":N,"outbound":N,"inbound":N,
#                 "net":N,"pending_inbound":N,"sharding_mode":"..."}, ...],
#      "totals":{"outbound":N,"inbound":N,"pending":N,
#                "in_flight":N,"residual":N},
#      "supply_identity_ok":true|false,"imbalance_tolerance":N,
#      "duplicate_shard_ids":[...],"unreachable_ports":[...],
#      "anomalies":[...]}
#
# Anomaly flags:
#   fleet_double_credit   Σ_in > Σ_out across the fleet (more value
#                         applied than was ever emitted). CATASTROPHIC —
#                         an FA7 / A1 double-credit or forged receipt.
#                         Exit 2.
#   fleet_imbalance       |Σ_out − Σ_in − Σ_pending| > tolerance. Value is
#                         emitted+un-applied beyond what the live pending
#                         pools account for (stuck / lost receipts, or a
#                         shard daemon that is behind). Exit 2.
#   duplicate_shard_id    two queried daemons report the same shard_id
#                         (mis-aimed --peer-ports — you pointed at two
#                         replicas of the same shard, which would double-
#                         count that shard's counters). Exit 1 (operator
#                         error, not a chain anomaly).
#   unreachable_peer      a --peer-ports entry could not be queried.
#                         Reported; does NOT by itself fail the supply gate
#                         (we can't balance a fleet we can't fully see), so
#                         the supply-identity gate is suppressed and the run
#                         exits 1.
#
# Exit codes:
#   0   success / informational (single-shard deployment also exits 0)
#   1   RPC error / bad args / unreachable peer / duplicate shard_id
#   2   imbalance detected (fleet_double_credit or fleet_imbalance)
set -u

usage() {
  cat <<'EOF'
Usage: operator_receipt_flow.sh --rpc-port N
                                [--peer-ports P1,P2,...]
                                [--imbalance-tolerance N]
                                [--json]

Cross-shard receipt-FLOW audit driven by the A1 supply counters
(accumulated_outbound / accumulated_inbound) — NOT a per-block walk.

Single-port mode reports this shard's outbound-emitted + inbound-applied
totals, net flow, and live pending-pool depth (in-flight into this shard).
The fleet-wide supply identity cannot be verified from one shard.

--peer-ports mode queries every shard daemon (two light RPC calls each:
`status` + `supply`), builds the per-shard flow table, and runs the
K-shard supply-identity gate: Σ_out == Σ_in + (in-flight). A fleet-wide
Σ_in > Σ_out is catastrophic (double-credit); a residual beyond the live
pending pools (± tolerance) is an in-flight imbalance.

Required:
  --rpc-port N             LOCAL shard daemon RPC port

Options:
  --peer-ports P1,P2,...   Comma-separated RPC ports of OTHER shard
                           daemons (all on 127.0.0.1). The local port is
                           always folded into the fleet aggregate.
  --imbalance-tolerance N  Allowed |Σ_out − Σ_in − Σ_pending| residual
                           before fleet_imbalance fires (default: 0)
  --json                   Emit structured JSON envelope
  -h, --help               Show this help

Anomaly flags:
  fleet_double_credit   Σ_in > Σ_out fleet-wide (CATASTROPHIC)         exit 2
  fleet_imbalance       residual beyond pending pools (± tolerance)     exit 2
  duplicate_shard_id    two daemons report the same shard_id           exit 1
  unreachable_peer      a --peer-ports entry could not be queried       exit 1

Exit codes:
  0   success / informational (or single-shard deployment)
  1   RPC error / bad args / unreachable peer / duplicate shard_id
  2   imbalance detected
EOF
}

PORT=""
PEER_PORTS=""
IMBALANCE_TOL=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                usage; exit 0 ;;
    --rpc-port)               PORT="${2:-}";          shift 2 ;;
    --peer-ports)             PEER_PORTS="${2:-}";    shift 2 ;;
    --imbalance-tolerance)    IMBALANCE_TOL="${2:-}"; shift 2 ;;
    --json)                   JSON_OUT=1;             shift ;;
    *) echo "operator_receipt_flow: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (multi-instance hosts; refuse to guess).
if [ -z "$PORT" ]; then
  echo "operator_receipt_flow: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_receipt_flow: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$IMBALANCE_TOL" in *[!0-9]*|"")
  echo "operator_receipt_flow: --imbalance-tolerance must be a non-negative integer (got '$IMBALANCE_TOL')" >&2
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
      echo "operator_receipt_flow: --peer-ports entries must be unsigned integers (got '$p')" >&2
      exit 1 ;;
    esac
  done
  IFS="$OLD_IFS"
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# python required for JSON parse + multi-port fan-out (status/supply JSON
# is nested under protections.* and we avoid a hard jq dependency, matching
# operator_committee_snapshot.sh's python-heredoc RPC driver convention).
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_receipt_flow: python is required (JSON parse + multi-port fan-out)" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# Promote DETERM to an absolute path so python's subprocess.run resolves
# the binary identically on Linux/Mac/Git Bash (matches the pattern used
# in operator_cross_shard_health.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# All work (RPC fan-out, aggregation, gating, rendering) happens in one
# python pass so we never spin a shell loop that could block. subprocess
# timeouts (8s) on every RPC call bound the worst case to
# (#ports × 2 calls × 8s) even if a daemon hangs mid-response.
"$PY" - "$DETERM_ABS" "$PORT" "$PEER_PORTS" "$IMBALANCE_TOL" "$JSON_OUT" <<'PY'
import json, subprocess, sys

determ, local_port_s, peer_ports_s, tol_s, json_out_s = sys.argv[1:6]
local_port = int(local_port_s)
tol        = int(tol_s)
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
    None on any error (unreachable, non-zero rc, non-JSON)."""
    try:
        r = subprocess.run(
            [determ, cmd, "--json", "--rpc-port", str(port)],
            capture_output=True, text=True, timeout=8
        )
    except Exception:
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except Exception:
        return None

def probe(port):
    """Two light RPC calls for one shard daemon. Returns a dict or marks
    the port unreachable."""
    st = rpc(port, "status")
    if not isinstance(st, dict):
        return {"rpc_port": port, "reachable": False}
    sup = rpc(port, "supply")
    if not isinstance(sup, dict):
        return {"rpc_port": port, "reachable": False}
    prot = st.get("protections") or {}
    try:
        shard_id = int(st.get("shard_id", 0))
    except Exception:
        shard_id = 0
    try:
        height = int(st.get("height", 0))
    except Exception:
        height = 0
    try:
        pending = int(st.get("pending_inbound_receipts", 0))
    except Exception:
        pending = 0
    try:
        outb = int(sup.get("accumulated_outbound", 0))
    except Exception:
        outb = 0
    try:
        inb = int(sup.get("accumulated_inbound", 0))
    except Exception:
        inb = 0
    return {
        "rpc_port":        port,
        "reachable":       True,
        "shard_id":        shard_id,
        "height":          height,
        "pending_inbound": pending,
        "outbound":        outb,
        "inbound":         inb,
        "net":             inb - outb,
        "sharding_mode":   str(prot.get("sharding_mode", "unknown")),
    }

# ── Probe the local shard first (drives single-vs-fleet + single-shard
#    short-circuit). A local RPC failure is always fatal (exit 1). ──────────
local = probe(local_port)
if not local["reachable"]:
    sys.stderr.write(
        f"operator_receipt_flow: RPC error talking to local daemon on "
        f"port {local_port} (is determ running there?)\n")
    sys.exit(1)

# ── Single-shard deployment short-circuit ─────────────────────────────────
# sharding_mode == "none" guarantees no cross-shard counters can ever be
# non-zero. Report and exit 0 regardless of single/fleet mode.
if local["sharding_mode"] == "none":
    if json_out:
        env = {
            "mode": "single_shard",
            "shard_id": local["shard_id"],
            "sharding_mode": "none",
            "height": local["height"],
            "outbound": local["outbound"],
            "inbound": local["inbound"],
            "net": local["net"],
            "pending_inbound": local["pending_inbound"],
            "supply_identity_checkable": False,
            "anomalies": [],
            "rpc_port": local_port,
            "info": "single_shard_deployment",
        }
        print(json.dumps(env))
    else:
        print("INFO: single-shard deployment — no cross-shard receipt flow "
              "by construction")
        print(f"      sharding_mode=none, shard_id={local['shard_id']}, "
              f"pending_inbound_receipts={local['pending_inbound']}, "
              f"port {local_port}")
    sys.exit(0)

# ──────────────────────────────────────────────────────────────────────────
# SINGLE-PORT MODE: report this shard's two legs. The fleet-wide supply
# identity is NOT checkable from one shard (you only see your own out/in).
# ──────────────────────────────────────────────────────────────────────────
if not fleet_mode:
    net = local["net"]
    if json_out:
        env = {
            "mode": "single",
            "shard_id": local["shard_id"],
            "sharding_mode": local["sharding_mode"],
            "height": local["height"],
            "outbound": local["outbound"],
            "inbound": local["inbound"],
            "net": net,
            "pending_inbound": local["pending_inbound"],
            "supply_identity_checkable": False,
            "anomalies": [],
            "rpc_port": local_port,
        }
        print(json.dumps(env))
        sys.exit(0)

    print(f"=== Cross-shard receipt flow (shard {local['shard_id']}, "
          f"port {local_port}) ===")
    print(f"sharding_mode: {local['sharding_mode']}  (height {local['height']})")
    print(f"Outbound emitted (accumulated_outbound): {local['outbound']}")
    print(f"Inbound applied  (accumulated_inbound):  {local['inbound']}")
    if net > 0:
        print(f"Net (inbound - outbound): +{net} (this shard is a net importer)")
    elif net < 0:
        print(f"Net (inbound - outbound): {net} (this shard is a net exporter)")
    else:
        print("Net (inbound - outbound): 0 (balanced)")
    print(f"Live pending-inbound pool: {local['pending_inbound']} receipt(s) "
          f"admitted but not yet applied (in-flight INTO this shard)")
    print("Supply-identity gate: not checkable from a single shard "
          "(only this shard's two legs are visible).")
    print("  Re-run with --peer-ports <other shard RPC ports> to verify the "
          "fleet-wide K-shard identity")
    print("  Sigma_out == Sigma_in + (in-flight)  "
          "(see docs/proofs/CrossShardSupplyConservation.md).")
    print("[OK] single-shard view rendered")
    sys.exit(0)

# ──────────────────────────────────────────────────────────────────────────
# FLEET MODE (--peer-ports): probe every shard, aggregate, gate.
# ──────────────────────────────────────────────────────────────────────────
shards = [local]
for p in ports[1:]:
    shards.append(probe(p))

reachable      = [s for s in shards if s.get("reachable")]
unreachable    = [s["rpc_port"] for s in shards if not s.get("reachable")]

# Duplicate shard_id detection across REACHABLE daemons. Pointing
# --peer-ports at two replicas of the same shard would double-count that
# shard's counters and corrupt the supply gate, so we treat it as an
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
tot_out     = sum(s["outbound"] for s in reachable)
tot_in      = sum(s["inbound"]  for s in reachable)
tot_pending = sum(s["pending_inbound"] for s in reachable)
in_flight   = tot_out - tot_in              # value emitted but not applied
residual    = in_flight - tot_pending       # un-applied beyond live pools

anomalies = []
# fleet_double_credit: more applied than ever emitted → catastrophic.
if tot_in > tot_out:
    anomalies.append("fleet_double_credit")
# fleet_imbalance: residual outside ±tolerance. Only meaningful when we
# can see the whole fleet AND there are no duplicate-shard double-counts;
# otherwise the totals are untrustworthy and we suppress the value gate.
gate_trustworthy = (not unreachable) and (not dup_shard_ids)
if gate_trustworthy and (residual > tol or residual < -tol):
    # Distinct from fleet_double_credit: even when Σ_in > Σ_out has already
    # fired the catastrophic flag, we still record fleet_imbalance so the
    # operator sees both signals (a double-credit is also, trivially, an
    # imbalance, but the residual magnitude is its own diagnostic).
    anomalies.append("fleet_imbalance")

supply_identity_ok = gate_trustworthy and (tot_in <= tot_out) \
    and (-tol <= residual <= tol)

# Sort the per-shard table by shard_id for stable display.
shard_rows = sorted(
    [s for s in reachable],
    key=lambda s: (s["shard_id"], s["rpc_port"]))

if json_out:
    env = {
        "mode": "fleet",
        "ports": ports,
        "shards": [
            {
                "rpc_port":        s["rpc_port"],
                "shard_id":        s["shard_id"],
                "outbound":        s["outbound"],
                "inbound":         s["inbound"],
                "net":             s["net"],
                "pending_inbound": s["pending_inbound"],
                "sharding_mode":   s["sharding_mode"],
            } for s in shard_rows
        ],
        "totals": {
            "outbound":  tot_out,
            "inbound":   tot_in,
            "pending":   tot_pending,
            "in_flight": in_flight,
            "residual":  residual,
        },
        "supply_identity_ok":  supply_identity_ok,
        "imbalance_tolerance": tol,
        "duplicate_shard_ids": dup_shard_ids,
        "unreachable_ports":   unreachable,
        "anomalies":           anomalies,
    }
    print(json.dumps(env))
else:
    print(f"=== Cross-shard receipt-flow audit "
          f"({len(reachable)} shard(s) reachable of {len(ports)} queried) ===")
    print("Per-shard flow (outbound emitted / inbound applied / net / pending):")
    print(f"  {'shard':>5}  {'port':>6}  {'outbound':>14}  {'inbound':>14}  "
          f"{'net':>14}  {'pending':>8}")
    for s in shard_rows:
        print(f"  {s['shard_id']:>5}  {s['rpc_port']:>6}  "
              f"{s['outbound']:>14}  {s['inbound']:>14}  "
              f"{s['net']:>14}  {s['pending_inbound']:>8}")
    if unreachable:
        print(f"  (unreachable ports: {', '.join(str(p) for p in unreachable)})")
    print(f"Fleet totals: outbound={tot_out}  inbound={tot_in}  "
          f"pending={tot_pending}")
    print(f"In-flight (Sigma_out - Sigma_in): {in_flight}")
    print(f"Residual (in-flight - pending):   {residual}  "
          f"(tolerance ±{tol})")

    if dup_shard_ids:
        print(f"[ERROR] duplicate shard_id(s) across queried daemons: "
              f"{', '.join(str(d) for d in dup_shard_ids)}")
        print("        --peer-ports pointed at two replicas of the same "
              "shard; counters would be double-counted. Fix the port list.")
    if unreachable:
        print(f"[WARN] {len(unreachable)} port(s) unreachable; supply-identity "
              f"gate suppressed (cannot balance a fleet we can't fully see).")

    if "fleet_double_credit" in anomalies:
        print(f"[CATASTROPHIC] Sigma_in ({tot_in}) > Sigma_out ({tot_out}) — "
              f"more value applied than ever emitted (FA7 / A1 double-credit).")
    if "fleet_imbalance" in anomalies:
        print(f"[ANOMALY] fleet_imbalance — residual {residual} outside "
              f"±{tol} after accounting for live pending pools "
              f"(stuck / lost receipts or a lagging shard).")

    if supply_identity_ok:
        print("[OK] K-shard supply identity holds: "
              "Sigma_out == Sigma_in + in-flight, residual within tolerance.")
    elif gate_trustworthy and not anomalies:
        print("[OK] no imbalance detected.")

# ── Exit-code policy ───────────────────────────────────────────────────────
# 2  imbalance detected (double-credit or residual-beyond-pending)
# 1  operator error (duplicate shard_id) or incomplete fleet view (unreachable)
# 0  clean
if "fleet_double_credit" in anomalies or "fleet_imbalance" in anomalies:
    sys.exit(2)
if dup_shard_ids or unreachable:
    sys.exit(1)
sys.exit(0)
PY
RC=$?
exit $RC
