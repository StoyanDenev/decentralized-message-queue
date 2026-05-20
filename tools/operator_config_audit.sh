#!/usr/bin/env bash
# operator_config_audit.sh — audit an operator's `config.json` against
# the security best-practices encoded in SECURITY.md + PROTOCOL.md.
#
# Unlike most operator_*.sh scripts which call into a running daemon
# via RPC, this one is purely a local-file linter — it reads the
# config.json from disk and applies a fixed checklist of audit rules,
# each tied to a known security finding or hardening guideline.
#
# Checks (each mapped to a SECURITY.md finding or default rationale):
#
#   S-001  rpc_localhost_only        secure default = true. CRITICAL if
#                                    false AND rpc_auth_secret is empty
#                                    (network-reachable RPC with no
#                                    HMAC auth). INFO if false WITH
#                                    rpc_auth_secret (operator opted
#                                    into network RPC + HMAC, fine).
#
#   S-014  rpc/gossip rate limits    rpc_rate_per_sec / gossip_rate_per_sec
#                                    > 0. WARN if either is 0 (per-IP
#                                    token-bucket disabled — operator
#                                    may be relying on an upstream LB).
#
#   BFT    bft_enabled               secure default = true (liveness
#                                    escape hatch). WARN if false.
#
#   K=M    k_block_sigs == m_creators
#                                    full mutual-distrust mode. INFO
#                                    if K < M (hybrid BFT-from-start).
#
#   GEN    genesis_path              CRITICAL if unset or file missing.
#
#   KEY    key_path                  CRITICAL if unset or file missing.
#
#   CHAIN  chain_path                INFO if unset (defaults to working
#                                    directory at daemon startup).
#
#   PORTS  listen_port vs rpc_port   CRITICAL if equal (conflict).
#                                    INFO if defaults (7777/7778).
#
#   PROF   tx_commit_ms / block_sig_ms / abort_claim_ms
#                                    WARN if all three are 0 or all
#                                    three are UINT32_MAX (operator-
#                                    error indicator, never a sensible
#                                    profile).
#
# Severity policy:
#   CRITICAL — a security-critical default has been broken and there is
#              no compensating control. Script exits 2 (operator alert
#              gate, same convention as operator_genesis_verify_live.sh).
#   WARN     — operator may have intentionally diverged from the secure
#              default. Script continues (exit 0); operator should
#              still confirm the divergence was deliberate.
#   INFO     — informational only; no action required.
#
# Usage:
#   tools/operator_config_audit.sh [--config <file>] [--json]
#
# Exit codes:
#   0   no CRITICAL findings (WARN/INFO entries may be present)
#   1   config file missing/unreadable/malformed; bad args
#   2   at least one CRITICAL finding (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_config_audit.sh [--config <file>] [--json]

Audits a determ operator config.json against security best practices
encoded in SECURITY.md. Each check maps to a known finding (S-001,
S-014, BFT escalation, K-of-K, genesis/key paths, port conflicts) and
is classified CRITICAL / WARN / INFO / OK.

Options:
  --config <file>   Path to config.json (default: $HOME/.determ/config.json)
  --json            Emit single-line JSON envelope instead of human table
  -h, --help        Show this help

Exit codes:
  0   no CRITICAL findings (WARN/INFO may still be present)
  1   config file missing / unreadable / malformed; bad args
  2   at least one CRITICAL finding (operator alert gate)

JSON shape (--json):
  {"config_path": "...",
   "checks": [{"id":"S-001", "name":"rpc_localhost_only",
               "severity":"OK"|"INFO"|"WARN"|"CRITICAL",
               "message":"...", "value": ...}, ...],
   "summary": {"critical":N, "warn":N, "info":N, "ok":N},
   "exit_code": 0|2}
EOF
}

CONFIG="${HOME:-}/.determ/config.json"
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)  usage; exit 0 ;;
    --config)   CONFIG="$2"; shift 2 ;;
    --json)     JSON_OUT=1;  shift ;;
    *) echo "operator_config_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$CONFIG" ]; then
  echo "operator_config_audit: --config <file> is required (HOME unset?)" >&2
  exit 1
fi
if [ ! -f "$CONFIG" ]; then
  echo "operator_config_audit: config file not found: $CONFIG" >&2
  exit 1
fi
if [ ! -r "$CONFIG" ]; then
  echo "operator_config_audit: config file not readable: $CONFIG" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
# Unlike most operator_*.sh scripts this one never invokes the determ
# binary — it's a pure local-file linter — so the binary-presence
# check in common.sh would force the audit to fail on hosts that don't
# have a built determ.exe (e.g. an ops workstation auditing a remote
# operator's config snapshot). Pre-set DETERM_BIN to `:` (the POSIX
# no-op) so common.sh's `[ -x ... ]` check succeeds without finding a
# real binary. PROJECT_ROOT (the only sourced variable this script
# actually benefits from for log readability) still gets computed.
: "${DETERM_BIN:=:}"
export DETERM_BIN
source tools/common.sh

# Drive parse + check evaluation in Python; jq alone can't elegantly
# do the cross-field conditionals (S-001 needs both rpc_localhost_only
# AND rpc_auth_secret; PORTS needs listen_port AND rpc_port equal but
# also recognises the 7777/7778 default pair). Python ships everywhere
# the determ build pipeline ships, so this is no new dep.
#
# Python emits the script's final exit code (0 on no-CRITICAL, 2 on
# any CRITICAL). We must preserve that — a bare `|| exit 1` after the
# heredoc would collapse exit 2 into exit 1 and silently swallow the
# operator-alert gate. Capture the rc and fan it out explicitly.
python - "$CONFIG" "$JSON_OUT" <<'PY'
import json, os, sys

config_path = sys.argv[1]
json_out    = sys.argv[2] == "1"

try:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_config_audit: cannot parse {config_path}: {e}\n")
    sys.exit(1)

if not isinstance(cfg, dict):
    sys.stderr.write(f"operator_config_audit: config root is not a JSON object: {config_path}\n")
    sys.exit(1)

UINT32_MAX = 0xFFFFFFFF

# Field accessors with secure-defaults matching Config::from_json in
# src/node/node.cpp. An absent field is treated as the daemon default,
# NOT as a missing-value error — the daemon would happily start with
# that absent field, so the audit must reflect that runtime reality.
def g(name, default):
    v = cfg.get(name, default)
    return v if v is not None else default

rpc_localhost_only   = bool(g("rpc_localhost_only", True))
rpc_auth_secret      = str (g("rpc_auth_secret",     ""))
rpc_rate_per_sec     = float(g("rpc_rate_per_sec",   0.0))
gossip_rate_per_sec  = float(g("gossip_rate_per_sec",0.0))
bft_enabled          = bool(g("bft_enabled",         True))
m_creators           = int (g("m_creators",          3))
k_block_sigs         = int (g("k_block_sigs",        m_creators))
genesis_path         = str (g("genesis_path",        ""))
key_path             = str (g("key_path",            ""))
chain_path           = str (g("chain_path",          ""))
listen_port          = int (g("listen_port",         7777))
rpc_port             = int (g("rpc_port",            7778))
tx_commit_ms         = int (g("tx_commit_ms",        200))
block_sig_ms         = int (g("block_sig_ms",        200))
abort_claim_ms       = int (g("abort_claim_ms",      200))

checks = []
def add(cid, name, severity, message, value=None):
    checks.append({
        "id":       cid,
        "name":     name,
        "severity": severity,
        "message":  message,
        "value":    value,
    })

# ── S-001: rpc_localhost_only ────────────────────────────────────────
# Secure default is True. False without rpc_auth_secret is the danger
# case (network-reachable RPC with zero authentication). False WITH
# rpc_auth_secret is operator-intentional (HMAC-authenticated public
# RPC, e.g. for a remote wallet) and is acceptable.
if rpc_localhost_only:
    add("S-001", "rpc_localhost_only", "OK",
        "true (secure default)", value=True)
else:
    if rpc_auth_secret:
        add("S-001", "rpc_localhost_only", "INFO",
            "false WITH rpc_auth_secret (HMAC-authenticated network RPC)",
            value=False)
    else:
        add("S-001", "rpc_localhost_only", "CRITICAL",
            "false WITHOUT rpc_auth_secret (unauthenticated network RPC)",
            value=False)

# ── S-014: per-IP token bucket on RPC + gossip ───────────────────────
# Both rates are advisory: an operator behind a load balancer may have
# deliberately disabled the in-process rate limiter to delegate to the
# LB. We can't tell from config alone, so this is WARN (not CRITICAL).
if rpc_rate_per_sec > 0:
    add("S-014", "rpc_rate_per_sec", "OK",
        f"{rpc_rate_per_sec}/sec", value=rpc_rate_per_sec)
else:
    add("S-014", "rpc_rate_per_sec", "WARN",
        "disabled (0/sec) — per-IP rate limit off; rely on upstream LB?",
        value=rpc_rate_per_sec)

if gossip_rate_per_sec > 0:
    add("S-014", "gossip_rate_per_sec", "OK",
        f"{gossip_rate_per_sec}/sec", value=gossip_rate_per_sec)
else:
    add("S-014", "gossip_rate_per_sec", "WARN",
        "disabled (0/sec) — per-IP gossip rate limit off",
        value=gossip_rate_per_sec)

# ── BFT escalation ───────────────────────────────────────────────────
# Default is True (liveness escape hatch when honest committee drops
# below K). Disabling it locks the chain to strict K-of-K mode, which
# trades liveness for safety — sometimes intentional in a permissioned
# deployment, hence WARN not CRITICAL.
if bft_enabled:
    add("BFT", "bft_enabled", "OK",
        "true (default; liveness escape hatch enabled)", value=True)
else:
    add("BFT", "bft_enabled", "WARN",
        "false (strict K-of-K; chain stalls on K-honest dropout)",
        value=False)

# ── K-of-K strong ────────────────────────────────────────────────────
# k_block_sigs == m_creators is the default "full mutual distrust"
# mode. Hybrid K<M means BFT-from-start (no escalation needed), which
# is a deliberate operator choice — INFO, not WARN.
if k_block_sigs == m_creators:
    add("KofK", "k_block_sigs_vs_m_creators", "OK",
        f"k={k_block_sigs}, m={m_creators} (full mutual distrust)",
        value={"k": k_block_sigs, "m": m_creators})
else:
    add("KofK", "k_block_sigs_vs_m_creators", "INFO",
        f"k={k_block_sigs} < m={m_creators} (hybrid BFT-from-start)",
        value={"k": k_block_sigs, "m": m_creators})

# ── Genesis path ─────────────────────────────────────────────────────
if not genesis_path:
    add("GEN", "genesis_path", "CRITICAL",
        "unset — daemon will fail to bootstrap chain identity",
        value="")
elif not os.path.isfile(genesis_path):
    add("GEN", "genesis_path", "CRITICAL",
        f"set to '{genesis_path}' but file does not exist",
        value=genesis_path)
else:
    add("GEN", "genesis_path", "OK",
        f"{genesis_path} exists", value=genesis_path)

# ── Key path ─────────────────────────────────────────────────────────
if not key_path:
    add("KEY", "key_path", "CRITICAL",
        "unset — daemon cannot sign blocks / Phase-2 contributions",
        value="")
elif not os.path.isfile(key_path):
    add("KEY", "key_path", "CRITICAL",
        f"set to '{key_path}' but file does not exist",
        value=key_path)
else:
    add("KEY", "key_path", "OK",
        f"{key_path} exists", value=key_path)

# ── Chain path ───────────────────────────────────────────────────────
# Empty chain_path is acceptable — daemon falls back to working
# directory. Operators in a managed-deployment should still set it
# explicitly, but it's not a security issue.
if not chain_path:
    add("CHAIN", "chain_path", "INFO",
        "unset (will default to daemon working dir)", value="")
else:
    add("CHAIN", "chain_path", "OK",
        f"{chain_path}", value=chain_path)

# ── Port conflict + defaults ─────────────────────────────────────────
# listen_port == rpc_port is a daemon-startup hard error; flag it
# CRITICAL here so the operator catches it before launching. If both
# are the documented defaults (7777/7778), call that out as INFO so
# the operator can decide whether to harden via firewall rules.
if listen_port == rpc_port:
    add("PORTS", "listen_port_vs_rpc_port", "CRITICAL",
        f"listen_port == rpc_port == {listen_port} (conflict; daemon will refuse to start)",
        value={"listen_port": listen_port, "rpc_port": rpc_port})
elif listen_port == 7777 and rpc_port == 7778:
    add("PORTS", "listen_port_vs_rpc_port", "INFO",
        "7777 / 7778 (distinct, defaults — harden via firewall)",
        value={"listen_port": listen_port, "rpc_port": rpc_port})
else:
    add("PORTS", "listen_port_vs_rpc_port", "OK",
        f"{listen_port} / {rpc_port} (distinct, non-default)",
        value={"listen_port": listen_port, "rpc_port": rpc_port})

# ── Profile timing sanity ────────────────────────────────────────────
# All three timing knobs at 0 or all three at UINT32_MAX is a
# transcription error indicator — no sensible profile uses those
# values together. (See PROTOCOL.md §12.3 profile presets.)
timings = (tx_commit_ms, block_sig_ms, abort_claim_ms)
if all(t == 0 for t in timings):
    add("PROF", "round_timings", "WARN",
        "tx_commit_ms / block_sig_ms / abort_claim_ms all 0 (likely operator-error)",
        value={"tx_commit_ms": tx_commit_ms,
               "block_sig_ms": block_sig_ms,
               "abort_claim_ms": abort_claim_ms})
elif all(t == UINT32_MAX for t in timings):
    add("PROF", "round_timings", "WARN",
        "tx_commit_ms / block_sig_ms / abort_claim_ms all UINT32_MAX (likely operator-error)",
        value={"tx_commit_ms": tx_commit_ms,
               "block_sig_ms": block_sig_ms,
               "abort_claim_ms": abort_claim_ms})
else:
    add("PROF", "round_timings", "OK",
        f"tx={tx_commit_ms}ms block_sig={block_sig_ms}ms abort={abort_claim_ms}ms",
        value={"tx_commit_ms": tx_commit_ms,
               "block_sig_ms": block_sig_ms,
               "abort_claim_ms": abort_claim_ms})

# ── Summary + exit code ──────────────────────────────────────────────
summary = {"critical": 0, "warn": 0, "info": 0, "ok": 0}
for c in checks:
    s = c["severity"].lower()
    if s in summary: summary[s] += 1

exit_code = 2 if summary["critical"] > 0 else 0

if json_out:
    print(json.dumps({
        "config_path": config_path,
        "checks":      checks,
        "summary":     summary,
        "exit_code":   exit_code,
    }))
    sys.exit(exit_code)

# Human-readable table.
print(f"=== Config audit ({config_path}) ===")
# Width-fitted labels so all rows align in the column.
label_for = {
    "rpc_localhost_only":        "S-001 rpc_localhost_only:",
    "rpc_rate_per_sec":          "S-014 RPC rate limit:",
    "gossip_rate_per_sec":       "S-014 gossip rate limit:",
    "bft_enabled":               "BFT escalation:",
    "k_block_sigs_vs_m_creators":"K-of-K strong:",
    "genesis_path":              "Genesis path:",
    "key_path":                  "Key path:",
    "chain_path":                "Chain path:",
    "listen_port_vs_rpc_port":   "Listen + RPC ports:",
    "round_timings":             "Profile timings:",
}
label_width = max(len(v) for v in label_for.values())

# Bracketed severity tags. Width 10 keeps human columns aligned across
# OK / INFO / WARN / CRITICAL.
sev_tag = {
    "OK":       "[OK]",
    "INFO":     "[INFO]",
    "WARN":     "[WARN]",
    "CRITICAL": "[CRIT]",
}

for c in checks:
    label = label_for.get(c["name"], c["name"] + ":")
    tag   = sev_tag.get(c["severity"], "[?]")
    print(f"{label:<{label_width}}  {tag:<7} {c['message']}")

print()
print(f"Audit summary: {summary['critical']} CRITICAL, "
      f"{summary['warn']} WARN, {summary['info']} INFO")
if summary["critical"] == 0:
    print("[OK] No critical security findings")
else:
    print(f"[CRIT] {summary['critical']} critical finding(s) — review above")

sys.exit(exit_code)
PY
PY_RC=$?
# Map Python rc → bash exit. Python exits 1 on its own internal errors
# (parse failures emitted to stderr above), 0 on no-CRITICAL, 2 on any
# CRITICAL. Forward whatever rc Python produced so the operator-alert
# gate at exit 2 is preserved end-to-end.
exit "$PY_RC"
