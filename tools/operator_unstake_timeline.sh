#!/usr/bin/env bash
# operator_unstake_timeline.sh — Per-domain pending-UNSTAKE forecast helper.
#
# Operators running multiple validators want a quick answer to "when will my
# pending UNSTAKEs become claimable?" without manually walking the chain or
# parsing the registry. This script computes the per-domain timeline of the
# UNSTAKE pipeline.
#
# Determ UNSTAKE flow (PROTOCOL.md §3.3 + SECURITY.md §S-017):
#   1. DEREGISTER tx (TxType=2) sets RegistryEntry.inactive_from to a
#      randomized future height and StakeEntry.unlock_height to
#      inactive_from + unstake_delay (src/chain/chain.cpp:844-851).
#   2. Once head_height >= StakeEntry.unlock_height, the locked stake is
#      claimable via an UNSTAKE tx (TxType=4) — refunded to the validator's
#      balance.
#
# Data-model note: each domain has at most ONE StakeEntry, and that entry
# carries at most one pending unlock_height (UINT64_MAX = no pending
# unstake; while active). So per-domain "pending UNSTAKEs" is in
# {0, 1} — the script presents that accurately. The list-shape in the
# spec accommodates a future multi-entry model without changing the
# output shape.
#
# Sibling-script positioning:
#
#   operator_validator_unstake_pipeline.sh
#                                     Cross-validator audit walking a
#                                     window of finalized blocks; pairs
#                                     DEREGISTER + UNSTAKE txs and surfaces
#                                     pipeline anomalies across the cluster.
#                                     Read this for the global view.
#
#   operator_unstake_timeline.sh (THIS)
#                                     Per-DOMAIN view: "what's the ETA on
#                                     MY pending UNSTAKE?" Single-domain
#                                     query against the live registry +
#                                     ETA computation from the per-round
#                                     timing budget. The right tool for
#                                     operator dashboards/alerts driven
#                                     by a known validator domain set.
#
# ETA calculation:
#   round_ms = tx_commit_ms + block_sig_ms + abort_claim_ms
#   eta_sec  = (blocks_remaining * round_ms) / 1000
#
# Timing fields are not exposed by any RPC handler (only persisted in
# Config::to_json on disk). Operators pass --config <path> to surface
# ETA, or --round-ms <N> to override directly. Without either, ETA is
# omitted and the script still prints the canonical (unlock_height,
# blocks_remaining) view.
#
# Read-only; safe against a running daemon.
#
# Usage:
#   tools/operator_unstake_timeline.sh --rpc-port <N> --domain <D>
#                                      [--config <path>] [--round-ms <ms>]
#                                      [--json]
#
# Options:
#   --rpc-port N      RPC port to query (REQUIRED)
#   --domain D        Validator domain (REQUIRED)
#   --config <path>   Path to the node's config.json — read for the
#                     timing-profile triple to compute round_ms. Optional;
#                     ETA omitted if absent.
#   --round-ms <ms>   Override round_ms directly (skips --config). Use
#                     this if you know the chain's round budget but
#                     don't have a node config handy.
#   --json            Emit structured JSON instead of human-readable.
#   -h, --help        Show this help.
#
# Exit codes:
#   0   query succeeded; pending unstakes printed (or "no pending unstakes").
#   1   RPC error / daemon unreachable / bad args / unknown domain.
#
# Limitations:
#   - There is no `config` or `genesis_info` RPC exposing the per-round
#     timing triple at runtime. ETA requires --config or --round-ms.
#   - "Pending UNSTAKEs" per domain is currently {0, 1}. The list shape
#     reflects the spec but the underlying data model has at most one
#     unlock_height per StakeEntry.
#   - Approximate-time formatting is best-effort; clock skew, abort
#     cycles, and BFT escalation can stretch real round durations.
set -u

usage() {
  cat <<'EOF'
Usage: operator_unstake_timeline.sh --rpc-port <N> --domain <D>
                                    [--config <path>] [--round-ms <ms>]
                                    [--json]

Per-domain pending-UNSTAKE forecast helper. Queries the live registry +
stake table for a single validator domain, prints all pending UNSTAKE
entries (currently {0, 1}; one StakeEntry.unlock_height per domain) with
their unlock_height, blocks-until-unlock, and ETA in seconds.

Options:
  --rpc-port N      RPC port to query (REQUIRED)
  --domain D        Validator domain (REQUIRED)
  --config <path>   Path to the node's config.json — read for the
                    timing-profile triple to compute round_ms. Optional;
                    ETA omitted if neither --config nor --round-ms given.
  --round-ms <ms>   Override round_ms directly. Use this if you know the
                    chain's round budget but don't have a node config
                    handy.
  --json            Emit structured JSON instead of human-readable.
  -h, --help        Show this help.

Exit codes:
  0   query succeeded
  1   RPC error / daemon unreachable / bad args / unknown domain
EOF
}

PORT=""
DOMAIN=""
CONFIG_PATH=""
ROUND_MS_OVERRIDE=""
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    --rpc-port)   PORT="${2:-}";              shift 2 ;;
    --domain)     DOMAIN="${2:-}";            shift 2 ;;
    --config)     CONFIG_PATH="${2:-}";       shift 2 ;;
    --round-ms)   ROUND_MS_OVERRIDE="${2:-}"; shift 2 ;;
    --json)       JSON_OUT=1;                 shift ;;
    *) echo "operator_unstake_timeline: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port + --domain are both required (sibling-script convention;
# refuses to guess the daemon on multi-instance hosts or the operator's
# validator identity).
if [ -z "$PORT" ]; then
  echo "operator_unstake_timeline: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_unstake_timeline: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -z "$DOMAIN" ]; then
  echo "operator_unstake_timeline: --domain is required" >&2
  usage >&2
  exit 1
fi
if [ -n "$ROUND_MS_OVERRIDE" ]; then
  case "$ROUND_MS_OVERRIDE" in *[!0-9]*|"")
    echo "operator_unstake_timeline: --round-ms must be a positive integer (got '$ROUND_MS_OVERRIDE')" >&2
    exit 1 ;;
  esac
fi
if [ -n "$CONFIG_PATH" ] && [ ! -f "$CONFIG_PATH" ]; then
  echo "operator_unstake_timeline: --config file not found: $CONFIG_PATH" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current head height ───────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_unstake_timeline: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_unstake_timeline: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: pull stake_info + account for the domain ─────────────────────────
# stake_info exposes locked + unlock_height (rpc_stake_info; lock-free).
# account exposes registry sub-block (registered_at, active_from,
# inactive_from) and the duplicate stake-locked + balance (rpc_account
# also reads stakes_ in its bundled commit view).
STAKE_INFO=$("$DETERM" stake_info "$DOMAIN" --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_unstake_timeline: stake_info RPC failed (port $PORT, domain $DOMAIN)" >&2
  exit 1
}
ACCOUNT_INFO=$("$DETERM" show-account "$DOMAIN" --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_unstake_timeline: show-account RPC failed (port $PORT, domain $DOMAIN)" >&2
  exit 1
}

# ── Step 3: render via Python (handles the timing math + JSON) ──────────────
python - "$DOMAIN" "$PORT" "$HEAD_H" "$CONFIG_PATH" "$ROUND_MS_OVERRIDE" \
        "$JSON_OUT" "$STAKE_INFO" "$ACCOUNT_INFO" <<'PY'
import json, sys

domain         = sys.argv[1]
port           = int(sys.argv[2])
head_h         = int(sys.argv[3])
config_path    = sys.argv[4]
round_ms_arg   = sys.argv[5]
json_out       = sys.argv[6] == "1"
stake_info_raw = sys.argv[7]
account_raw    = sys.argv[8]

UINT64_MAX = 0xFFFFFFFFFFFFFFFF

# Parse stake_info — shape: {"domain":..., "locked":N, "unlock_height":N}
try:
    stake_info = json.loads(stake_info_raw)
except Exception as e:
    sys.stderr.write(f"operator_unstake_timeline: malformed stake_info JSON: {e}\n")
    sys.exit(1)

if not isinstance(stake_info, dict):
    sys.stderr.write("operator_unstake_timeline: stake_info RPC returned non-object\n")
    sys.exit(1)

locked        = int(stake_info.get("locked", 0) or 0)
unlock_height = int(stake_info.get("unlock_height", UINT64_MAX) or UINT64_MAX)

# Parse account JSON — shape: {"address":..., "balance":N, "stake":N,
# "registry": {"registered_at":N, "active_from":N, "inactive_from":N,
# "ed_pub":...}} OR an empty {} if domain is unknown (account RPC returns
# null which the CLI flattens to {} under --json).
try:
    account = json.loads(account_raw) if account_raw.strip() else {}
except Exception as e:
    sys.stderr.write(f"operator_unstake_timeline: malformed account JSON: {e}\n")
    sys.exit(1)

if not isinstance(account, dict):
    sys.stderr.write("operator_unstake_timeline: account RPC returned non-object\n")
    sys.exit(1)

# If the domain has no on-chain state at all (no balance, no nonce, no
# registry entry), surface that explicitly.
has_on_chain = bool(account) and (
    account.get("balance", 0) > 0
    or account.get("next_nonce", 0) > 0
    or (isinstance(account.get("registry"), dict) and account["registry"])
)

# ── Step 3a: derive round_ms ────────────────────────────────────────────────
round_ms = None
round_ms_source = None
if round_ms_arg:
    try:
        round_ms = int(round_ms_arg)
        round_ms_source = "--round-ms"
    except ValueError:
        sys.stderr.write(f"operator_unstake_timeline: bad --round-ms: {round_ms_arg}\n")
        sys.exit(1)
elif config_path:
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            sys.stderr.write(f"operator_unstake_timeline: config root not an object: {config_path}\n")
            sys.exit(1)
        tx_commit  = int(cfg.get("tx_commit_ms",   0) or 0)
        block_sig  = int(cfg.get("block_sig_ms",   0) or 0)
        abort_claim= int(cfg.get("abort_claim_ms", 0) or 0)
        if tx_commit > 0 and block_sig > 0 and abort_claim > 0:
            round_ms = tx_commit + block_sig + abort_claim
            round_ms_source = f"--config {config_path}"
        else:
            sys.stderr.write(
                f"operator_unstake_timeline: config {config_path} missing "
                "tx_commit_ms/block_sig_ms/abort_claim_ms; ETA disabled\n"
            )
    except Exception as e:
        sys.stderr.write(f"operator_unstake_timeline: cannot read config {config_path}: {e}\n")
        sys.exit(1)

# ── Step 3b: build the pending-UNSTAKE list ─────────────────────────────────
# At most one entry per domain (per the StakeEntry model). An entry is
# "pending" iff unlock_height != UINT64_MAX (= still active) AND
# head_h < unlock_height. If head_h >= unlock_height, the stake is
# already claimable — we surface that as a separate state below the
# pending list.
pending = []
already_claimable = False
if unlock_height != UINT64_MAX:
    if head_h < unlock_height:
        blocks_remaining = unlock_height - head_h
        eta_sec = None
        if round_ms is not None:
            eta_sec = (blocks_remaining * round_ms) / 1000.0
        pending.append({
            "amount":           locked,
            "unlock_height":    unlock_height,
            "blocks_remaining": blocks_remaining,
            "eta_seconds":      eta_sec,
        })
    else:
        already_claimable = True

# Active stake = locked when stake is locked-but-not-pending (i.e.,
# while the validator is still active and unlock_height == UINT64_MAX).
# Once a DEREGISTER fires, locked is the pending amount; active stake
# becomes 0 from the operator's POV.
active_stake = locked if unlock_height == UINT64_MAX else 0
total_pending_stake = sum(p["amount"] for p in pending)

# ── Step 3c: ETA formatting helper ───────────────────────────────────────────
def fmt_eta(sec):
    if sec is None:
        return "(unknown — no --config / --round-ms)"
    if sec < 0:
        return "0s (already unlocked)"
    if sec < 60:
        return f"{sec:.0f}s"
    if sec < 3600:
        return f"~{sec/60:.1f}m"
    if sec < 86400:
        return f"~{sec/3600:.2f}h"
    return f"~{sec/86400:.2f}d"

# Earliest unlock = first pending entry (only one possible today).
earliest = None
if pending:
    earliest = min(pending, key=lambda p: p["unlock_height"])

# ── Step 4: emit ────────────────────────────────────────────────────────────
if json_out:
    out = {
        "domain":              domain,
        "rpc_port":            port,
        "current_height":      head_h,
        "round_ms":            round_ms,
        "round_ms_source":     round_ms_source,
        "active_stake":        active_stake,
        "total_pending_stake": total_pending_stake,
        "pending_unstakes":    pending,
        "earliest_unlock":     earliest,
        "already_claimable":   already_claimable,
        "claimable_amount":    locked if already_claimable else 0,
        "on_chain":            has_on_chain or locked > 0,
    }
    print(json.dumps(out))
    sys.exit(0)

# Human-readable output.
if not has_on_chain and locked == 0:
    print(f"operator_unstake_timeline: domain '{domain}' has no on-chain state on this node.")
    sys.exit(0)

print(f"Unstake timeline for {domain} (rpc_port={port}, current_height={head_h}):")
print()
print(f"  Pending UNSTAKEs: {len(pending)}")
if pending:
    for i, p in enumerate(pending, 1):
        eta_str = fmt_eta(p["eta_seconds"])
        if p["eta_seconds"] is not None:
            eta_field = f"eta={p['eta_seconds']:.1f}s (~{eta_str.lstrip('~')})"
        else:
            eta_field = f"eta={eta_str}"
        print(f"    {i}. amount={p['amount']} unlock_height={p['unlock_height']} "
              f"blocks_remaining={p['blocks_remaining']} {eta_field}")
elif already_claimable:
    # unlock_height passed but no UNSTAKE tx submitted yet.
    print(f"    (0 pending — stake is ALREADY CLAIMABLE: "
          f"unlock_height={unlock_height} <= current_height={head_h})")
else:
    # Either active (UINT64_MAX) or never deregistered.
    if unlock_height == UINT64_MAX and locked > 0:
        print("    (0 pending — validator is still ACTIVE; submit DEREGISTER to start unstake pipeline)")
    elif locked == 0:
        print("    (0 pending — no locked stake)")
    else:
        print("    (0 pending)")

print()
if pending:
    e = earliest
    eta_str = fmt_eta(e["eta_seconds"])
    if e["eta_seconds"] is not None:
        print(f"  Earliest unlock: height={e['unlock_height']} eta=~{eta_str.lstrip('~')}")
    else:
        print(f"  Earliest unlock: height={e['unlock_height']} eta={eta_str}")
print(f"  Total pending stake: {total_pending_stake}")
print(f"  Currently active stake: {active_stake}")

if round_ms is None and pending:
    print()
    print("  Note: ETA omitted because neither --config nor --round-ms was supplied.")
    print("        Pass either to enable ETA forecasting.")
elif round_ms is not None:
    print()
    print(f"  (round_ms={round_ms} from {round_ms_source})")

sys.exit(0)
PY
RC=$?
exit $RC
