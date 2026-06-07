#!/usr/bin/env bash
# operator_sync_progress.sh — SINGLE-NODE catch-up / bootstrap-readiness
# gauge for one determ daemon that is (or might be) still syncing.
#
# Use case: an operator who just (re)started a node from cold storage —
# or restored from a snapshot — wants ONE command that answers
# "how far through catch-up is THIS node, and is it caught up enough to
# be put back into rotation / start serving traffic?" The node's own
# `status` RPC already self-reports a coarse `sync_state` boolean
# ("syncing" | "in_sync"), but that flag flips to "in_sync" the moment
# the node merely STOPS making forward progress on a received block — it
# does NOT tell you whether the node's height has actually CONVERGED on
# the network tip. This tool combines the self-reported sync_state with a
# height comparison against one or more reference peers to produce a real
# catch-up percentage + a blocks-behind deficit, and a single
# bootstrap-ready verdict.
#
# ── Sibling positioning (sync / lag / connectivity lane) ─────────────
# Distinct from every existing tool in the adjacent lanes:
#   * operator_consensus_lag.sh — N-way SYMMETRIC straggler scan: every
#       port is a peer, lag is measured against the fleet max, and there
#       is NO node-under-test and NO sync_state. It answers "which peers
#       in this fleet are behind?" — a steady-state fleet view.
#   * operator_peer_connectivity_health.sh — SINGLE-port connectivity
#       digest. Reads sync_state ONLY to flag isolation (in_sync AND
#       peer_count==0); it NEVER compares this node's height to any peer
#       and NEVER computes a catch-up percentage.
#   * operator_block_lag_check.sh — SINGLE-node WALL-CLOCK head staleness
#       (now - head.timestamp). No peer comparison; a node that is far
#       behind but still receiving recent blocks looks "fresh" to it.
#   * operator_chain_freshness.sh / operator_snapshot_check.sh — chain-
#       file / snapshot-donor checks, not live catch-up progress.
# THIS tool is the missing CATCH-UP view: it has an explicit ASYMMETRIC
# node-under-test (--rpc-port) measured against one or more reference
# peers (--peer-ports), folds in the node's self-reported sync_state,
# and emits a bootstrap-ready verdict. No other tool computes a
# sync-progress percentage.
#
# ── RPCs consumed (read-only) ────────────────────────────────────────
#   determ status --field <k> --rpc-port P  →  rpc_status() at
#       src/node/node.cpp:2461. cmd_status --field mode at
#       src/main.cpp:1491 prints exactly one top-level value (string /
#       number / bool) or an empty line for an absent/null key.
#       Fields used (all proven present in rpc_status):
#         .height      (node.cpp:2464  = chain_.height())
#         .sync_state  (node.cpp:2471  "in_sync" | "syncing"; derived
#                        from Node::state_, the SyncState enum at
#                        include/determ/node/node.hpp:171)
#   Reference peers are polled for .height the same way (peers need not
#   expose anything beyond a reachable status RPC).
#
# No tx is ever sent; no chain file is read or written. Pure read.
#
# ── Progress / verdict logic ─────────────────────────────────────────
# Let H    = node-under-test height (status.height),
#     Href = max height across all REACHABLE reference peers,
#     T    = target = max(H, Href)  (the node may legitimately be the
#            tip — never report negative deficit).
#   deficit  = T - H                (blocks the node is behind the tip)
#   progress = H / T * 100          (100% when caught up; T==0 ⇒ 100%,
#                                     a fresh genesis-only network)
# The node is BOOTSTRAP-READY when BOTH hold:
#   (1) sync_state == "in_sync"   (the node itself believes it is synced)
#   (2) deficit <= --max-deficit  (and it has actually converged on the
#                                  tip within the operator's tolerance)
# Requiring BOTH closes the gap each signal leaves alone: sync_state can
# read "in_sync" on a node that simply stalled mid-catch-up, while a
# pure height deficit can't tell a still-applying node from a converged
# one. If NO reference peer is reachable, Href is unknown — the height
# half is reported as "unknown" and the verdict falls back to sync_state
# alone (clearly labelled as unverified).
#
# Anomalies (each gates --anomalies-only exit 2):
#   not_in_sync     sync_state != "in_sync".
#   behind_tip      deficit > --max-deficit (only when a reference peer
#                   was reachable; otherwise we cannot assert it).
#
# ── Exit-code contract ───────────────────────────────────────────────
#   0   ok / info / clean SKIP (node-under-test unreachable on --rpc-port)
#   1   argument error OR malformed/unparseable status response
#   2   --anomalies-only AND at least one anomaly present
#
# ── Usage ────────────────────────────────────────────────────────────
#   tools/operator_sync_progress.sh [--rpc-port N] [--peer-ports a,b,c]
#       [--max-deficit N] [--json] [--anomalies-only]
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

usage() {
  cat <<'EOF'
Usage: operator_sync_progress.sh [--rpc-port N] [--peer-ports a,b,c]
           [--max-deficit N] [--json] [--anomalies-only]

Single-node catch-up / bootstrap-readiness gauge. Queries ONE daemon's
own `determ status` for its height + self-reported sync_state, then
(optionally) polls one or more reference peers for their heights to
compute a real catch-up percentage and a blocks-behind-tip deficit.
Emits a bootstrap-ready verdict: the node is ready only when it both
self-reports in_sync AND has converged on the network tip within the
deficit tolerance.

Options:
  --rpc-port N      RPC port of the node UNDER TEST (default: 7778). This
                    is the node whose catch-up progress is measured.
  --peer-ports L    Comma-separated RPC ports of REFERENCE peers used to
                    establish the network tip height (e.g. 8772,8773).
                    Optional: with none supplied (or none reachable) the
                    height comparison is reported as "unknown" and the
                    verdict falls back to sync_state alone (unverified).
                    The node-under-test's own port is ignored if it also
                    appears here. Entries must be 1..65535 integers.
  --max-deficit N   Max blocks-behind-tip still considered caught up.
                    Default 2 (absorbs the normal one-block-stale skew
                    between a node and a proposer mid Phase-2 reveal).
                    Must be a non-negative integer.
  --json            Emit a machine-readable JSON envelope instead of the
                    human digest.
  --anomalies-only  Print only anomaly rows + verdict. With this flag set,
                    ANY anomaly present makes the exit code 2.
  -h, --help        Show this help and exit 0.

Anomalies:
  not_in_sync   sync_state != "in_sync" (node still catching up).
  behind_tip    deficit > --max-deficit (only asserted when a reference
                peer was reachable to establish the tip).

Exit codes:
  0   ok / info / clean SKIP (node-under-test unreachable on --rpc-port)
  1   argument error or malformed status response
  2   --anomalies-only AND at least one anomaly present
EOF
}

PORT=7778
PEER_PORTS_RAW=""
MAX_DEFICIT=2
JSON=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)          usage; exit 0 ;;
    --rpc-port)         PORT="${2:-}"; shift 2 || { echo "operator_sync_progress: --rpc-port needs a value" >&2; exit 1; } ;;
    --peer-ports)       PEER_PORTS_RAW="${2:-}"; shift 2 || { echo "operator_sync_progress: --peer-ports needs a value" >&2; exit 1; } ;;
    --max-deficit)      MAX_DEFICIT="${2:-}"; shift 2 || { echo "operator_sync_progress: --max-deficit needs a value" >&2; exit 1; } ;;
    --json)             JSON=1; shift ;;
    --anomalies-only)   ANOM_ONLY=1; shift ;;
    *) echo "operator_sync_progress: unknown argument '$1'" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Argument validation ──────────────────────────────────────────────
case "$PORT" in ""|*[!0-9]*)
  echo "operator_sync_progress: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "operator_sync_progress: --rpc-port must be 1..65535 (got '$PORT')" >&2
  exit 1
fi

case "$MAX_DEFICIT" in ""|*[!0-9]*)
  echo "operator_sync_progress: --max-deficit must be a non-negative integer (got '$MAX_DEFICIT')" >&2
  exit 1 ;;
esac

# Parse + validate reference peer ports. Split on comma, trim, dedup in
# encounter order, drop the node-under-test's own port if listed.
PEER_PORTS=""
SEEN=" $PORT "   # seed with node-under-test so we skip it
if [ -n "$PEER_PORTS_RAW" ]; then
  IFS=',' read -ra _PP <<<"$PEER_PORTS_RAW"
  for raw in "${_PP[@]}"; do
    p="${raw#"${raw%%[![:space:]]*}"}"
    p="${p%"${p##*[![:space:]]}"}"
    [ -z "$p" ] && continue
    case "$p" in *[!0-9]*)
      echo "operator_sync_progress: --peer-ports entry '$p' is not numeric" >&2
      exit 1 ;;
    esac
    if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
      echo "operator_sync_progress: --peer-ports entry '$p' must be 1..65535" >&2
      exit 1
    fi
    case "$SEEN" in *" $p "*) continue ;; esac
    SEEN="$SEEN$p "
    if [ -z "$PEER_PORTS" ]; then PEER_PORTS="$p"; else PEER_PORTS="$PEER_PORTS $p"; fi
  done
fi

# ── Probe the node-under-test ────────────────────────────────────────
# Two field reads. An unreachable node yields empty output (cmd_status
# returns 1 on RPC error → 2>/dev/null swallows the stderr, || true keeps
# us going). A reachable node with a present field prints exactly one
# token. We treat a totally-empty height as "unreachable" → clean SKIP.
NODE_HEIGHT=$("$DETERM" status --field height --rpc-port "$PORT" 2>/dev/null || true)
NODE_HEIGHT="${NODE_HEIGHT%$'\r'}"; NODE_HEIGHT="${NODE_HEIGHT%$'\n'}"
NODE_HEIGHT="${NODE_HEIGHT#"${NODE_HEIGHT%%[![:space:]]*}"}"
NODE_HEIGHT="${NODE_HEIGHT%"${NODE_HEIGHT##*[![:space:]]}"}"

NODE_SYNC=$("$DETERM" status --field sync_state --rpc-port "$PORT" 2>/dev/null || true)
NODE_SYNC="${NODE_SYNC%$'\r'}"; NODE_SYNC="${NODE_SYNC%$'\n'}"
NODE_SYNC="${NODE_SYNC#"${NODE_SYNC%%[![:space:]]*}"}"
NODE_SYNC="${NODE_SYNC%"${NODE_SYNC##*[![:space:]]}"}"

# Unreachable node-under-test → clean informational SKIP (exit 0).
if [ -z "$NODE_HEIGHT" ] && [ -z "$NODE_SYNC" ]; then
  if [ "$JSON" -eq 1 ]; then
    printf '{"skipped":true,"reason":"node-under-test unreachable on rpc-port %s"}\n' "$PORT"
  else
    echo "INFO: node-under-test unreachable on --rpc-port $PORT (is the daemon running?); SKIP"
  fi
  exit 0
fi

# Node answered but height field was empty/non-numeric → malformed.
case "$NODE_HEIGHT" in ""|*[!0-9]*)
  echo "operator_sync_progress: node status returned no parseable height (got '$NODE_HEIGHT')" >&2
  exit 1 ;;
esac

# ── Probe reference peers (best-effort; unreachable = skipped) ────────
PEER_HEIGHTS=""
for pp in $PEER_PORTS; do
  h=$("$DETERM" status --field height --rpc-port "$pp" 2>/dev/null || true)
  h="${h%$'\r'}"; h="${h%$'\n'}"
  h="${h#"${h%%[![:space:]]*}"}"; h="${h%"${h##*[![:space:]]}"}"
  case "$h" in ""|*[!0-9]*) h="" ;; esac
  if [ -z "$PEER_HEIGHTS" ]; then PEER_HEIGHTS="$pp:$h"; else PEER_HEIGHTS="$PEER_HEIGHTS|$pp:$h"; fi
done

# ── Summarize / render in python (max + deficit + verdict) ───────────
python - "$NODE_HEIGHT" "$NODE_SYNC" "$PEER_HEIGHTS" "$MAX_DEFICIT" "$JSON" "$ANOM_ONLY" "$PORT" <<'PY'
import json, sys

node_h_s, node_sync, peers_s, max_def_s, json_s, anom_s, port_s = sys.argv[1:8]
node_h    = int(node_h_s)
max_def   = int(max_def_s)
json_out  = json_s == "1"
anom_only = anom_s == "1"
port      = int(port_s)

# Parse reference peers ("port:height" tokens; empty height = unreachable).
peers = []
ref_heights = []
if peers_s:
    for tok in peers_s.split("|"):
        if not tok:
            continue
        pp, _, hh = tok.partition(":")
        if hh == "":
            peers.append({"port": int(pp), "height": None, "reachable": False})
        else:
            h = int(hh)
            peers.append({"port": int(pp), "height": h, "reachable": True})
            ref_heights.append(h)

have_ref = len(ref_heights) > 0
href = max(ref_heights) if have_ref else None

# Target tip: never let the node-under-test show a negative deficit — it
# may legitimately BE the tip (ahead of a lagging reference peer).
target = max(node_h, href) if have_ref else node_h
deficit = (target - node_h) if have_ref else None
if target > 0:
    progress = round(node_h / target * 100.0, 2)
else:
    progress = 100.0  # genesis-only network: trivially caught up

in_sync = (node_sync == "in_sync")

anomalies = []
if not in_sync:
    anomalies.append("not_in_sync")
if have_ref and deficit is not None and deficit > max_def:
    anomalies.append("behind_tip")

# Bootstrap-ready: both signals must agree. Without a reachable reference
# peer the height half is unverified, so readiness is reported but flagged
# as such (verdict still requires in_sync).
if have_ref:
    ready = in_sync and (deficit is not None and deficit <= max_def)
else:
    ready = in_sync  # height-unverified

has_anomaly = len(anomalies) > 0

if json_out:
    env = {
        "rpc_port":       port,
        "node_height":    node_h,
        "sync_state":     node_sync,
        "reference_tip":  href,
        "have_reference": have_ref,
        "target_height":  target,
        "deficit":        deficit,
        "progress_pct":   progress,
        "max_deficit":    max_def,
        "in_sync":        in_sync,
        "bootstrap_ready": ready,
        "height_verified": have_ref,
        "peers":          peers,
        "anomalies":      anomalies,
        "ok":             not has_anomaly,
    }
    print(json.dumps(env))
    sys.exit(2 if (anom_only and has_anomaly) else 0)

# ── Human digest ─────────────────────────────────────────────────────
print(f"=== Sync / bootstrap progress (node rpc-port {port}) ===")
if not anom_only:
    print(f"  node height       : {node_h}")
    print(f"  sync_state        : {node_sync or '?'}")
    if have_ref:
        print(f"  reference tip     : {href}  (max over {len(ref_heights)} reachable peer(s))")
        print(f"  target            : {target}")
        print(f"  deficit           : {deficit} block(s) behind tip (tolerance {max_def})")
        print(f"  catch-up progress : {progress:.2f}%")
    else:
        print(f"  reference tip     : unknown (no reachable --peer-ports; height unverified)")
        print(f"  catch-up progress : unverified")

    if peers:
        print()
        print(f"  {'peer port':>10}  {'height':>11}  status")
        print(f"  {'-'*10}  {'-'*11}  {'-'*13}")
        for p in peers:
            if p["reachable"]:
                print(f"  {p['port']:>10}  {p['height']:>11}  reachable")
            else:
                print(f"  {p['port']:>10}  {'unreachable':>11}  unreachable")

if anomalies:
    print()
    for a in anomalies:
        if a == "not_in_sync":
            print(f"  [ANOMALY] not_in_sync — node self-reports sync_state='{node_sync}' (still catching up)")
        elif a == "behind_tip":
            print(f"  [ANOMALY] behind_tip — {deficit} block(s) behind tip (> tolerance {max_def})")

print()
if ready and not has_anomaly:
    if have_ref:
        print(f"[OK] node is BOOTSTRAP-READY (in_sync AND within {max_def} block(s) of tip)")
    else:
        print(f"[OK] node self-reports in_sync (height unverified — supply --peer-ports to confirm)")
elif not has_anomaly:
    print(f"[OK] no anomalies (node not yet bootstrap-ready; still converging)")
else:
    print(f"[ANOMALY] node NOT bootstrap-ready: {', '.join(anomalies)}")

sys.exit(2 if (anom_only and has_anomaly) else 0)
PY
exit $?
