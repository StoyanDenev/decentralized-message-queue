#!/usr/bin/env bash
# operator_config_lint.sh — READ-ONLY production-hardening linter for a
# determ node config.json.
#
# Where operator_config_audit.sh applies a CRITICAL/WARN/INFO severity
# model with an exit-2 operator-alert gate, this linter takes the
# lighter "advisory checklist" stance the test-suite idiom expects: it
# emits one PASS:/WARN: line per check, a final summary line, and ALWAYS
# exits 0 on a successfully-read config — even when it found risky
# settings. It is NOT a hard gate. The non-zero finding count is printed
# so a CI wrapper can grep for "WARN findings: N" and decide its own
# policy. exit 1 is reserved for a genuinely broken invocation (bad args
# / unreadable / malformed config). A missing determ binary SKIPs the
# run with a PASS so the script is a no-op in minimal build envs.
#
# The checks below name REAL Config fields as defined in
# include/determ/node/node.hpp (struct Config) + their from_json
# secure-defaults. An absent field is treated as the daemon default,
# never as an error — the daemon would happily start with that field
# absent, so the lint must reflect that runtime reality.
#
# Checks (each tied to a SECURITY.md finding or hardening default):
#
#   rpc_localhost_only   S-001. Secure default = true. WARN if false AND
#                        rpc_auth_secret empty (network-reachable RPC with
#                        zero HMAC auth — the worst posture). false WITH a
#                        secret is an operator-intentional authenticated
#                        public-RPC posture and passes.
#   rpc_auth_secret      S-001 v2.16. WARN when localhost_only is false but
#                        the HMAC secret is empty (unauthenticated network
#                        RPC). PASS when set OR when localhost-only pins
#                        the surface shut anyway.
#   rpc_rate_per_sec     S-014. WARN if 0 (per-IP token bucket off) AND the
#                        RPC surface is network-reachable. Localhost-only
#                        RPC with the limiter off is acceptable.
#   gossip_rate_per_sec  S-014 (gossip side). WARN if 0 AND the node binds
#                        for external peers (bootstrap_peers populated or
#                        RPC is network-reachable — a proxy for a
#                        public-facing node).
#   log_quiet            S-027. WARN if false (default) — verbose per-block
#                        /handshake/snapshot logging widens the passive-
#                        observer scrape surface on a production box.
#   key_path             Hardening. WARN if the referenced keyfile is a
#                        PLAINTEXT node_key ({pubkey, priv_seed}) rather
#                        than the S-004 passphrase-encrypted
#                        "DETERM-NODE-V1 ..." envelope. WARN (separately)
#                        if key_path is set but the file is absent.
#   genesis_hash         Eclipse defense. WARN if genesis_path is set but
#                        genesis_hash is empty — without the pin a peer
#                        can feed a forked genesis at bootstrap.
#   listen_port/rpc_port Sanity. WARN if equal (daemon would refuse to
#                        start).
#
# Read-only: this script opens config.json + (optionally) the keyfile it
# references for read, contacts NO daemon, and mutates NOTHING.
#
# Usage:
#   tools/operator_config_lint.sh [--config <file>]
#
# Exit codes:
#   0   config read OK (advisory; WARN findings may be present) OR SKIP
#   1   bad args / config missing / unreadable / malformed
set -u

usage() {
  cat <<'EOF'
Usage: operator_config_lint.sh [--config <file>]

READ-ONLY production-hardening linter for a determ node config.json.
Emits PASS:/WARN: lines per check against the real Config fields in
include/determ/node/node.hpp, then a summary line. Advisory only:
always exits 0 on a successfully-read config (prints the WARN count so
a CI wrapper can apply its own policy). Contacts no daemon; mutates
nothing.

Options:
  --config <file>   Path to config.json (default: $HOME/.determ/config.json)
  -h, --help        Show this help

Exit codes:
  0   config read OK (WARN findings may be present) or SKIP (no binary)
  1   bad args / config missing / unreadable / malformed
EOF
}

CONFIG="${HOME:-}/.determ/config.json"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --config)  CONFIG="${2:-}"; shift 2 ;;
    *) echo "operator_config_lint: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."

# This linter never invokes the determ binary (it's a pure local-file
# reader), but it still sources common.sh for the PROJECT_ROOT helper
# and to honour the suite-wide binary-detection contract. common.sh's
# detection block hard-exits 1 when no determ binary is found, which on a
# minimal env (ops workstation with no build tree) would turn this
# advisory linter into a hard failure. Probe for a binary first and SKIP
# with a PASS when none exists — the suite-wide no-op-PASS convention —
# rather than letting common.sh abort the run.
if [ -z "${DETERM_BIN:-}" ] \
   && [ ! -x "build/Release/determ.exe" ] \
   && [ ! -x "build/determ.exe" ] \
   && [ ! -x "build/determ" ] \
   && [ ! -x "build/Release/determ" ]; then
  echo "SKIP: determ binary not found — config-lint is a no-op in this env"
  echo "  PASS: operator_config_lint (skipped)"
  exit 0
fi
source tools/common.sh

if [ -z "$CONFIG" ]; then
  echo "operator_config_lint: --config <file> is required (HOME unset?)" >&2
  exit 1
fi
if [ ! -f "$CONFIG" ]; then
  echo "operator_config_lint: config file not found: $CONFIG" >&2
  exit 1
fi
if [ ! -r "$CONFIG" ]; then
  echo "operator_config_lint: config file not readable: $CONFIG" >&2
  exit 1
fi

# Normalize $CONFIG for the native-Windows Python below (Git Bash hands
# us MSYS paths that os.open() can't grok).
if command -v cygpath >/dev/null 2>&1; then
  CONFIG_FOR_PY=$(cygpath -m -- "$CONFIG" 2>/dev/null || printf '%s' "$CONFIG")
else
  CONFIG_FOR_PY="$CONFIG"
fi

echo "=== operator config-lint (production hardening) -- $CONFIG ==="

# Drive the cross-field checks in Python: several rules are conditional
# on TWO fields (rpc auth depends on localhost_only + auth_secret; the
# rate-limit checks depend on the bind posture; the keyfile check reads a
# second file referenced by key_path). Python ships everywhere the
# determ build pipeline ships, matching operator_config_audit.sh /
# operator_keystore_audit.sh. Python prints the PASS:/WARN: lines and the
# trailing "WARN findings: N" summary; it always exits 0 on a parseable
# config and 1 only when the config can't be parsed.
python - "$CONFIG_FOR_PY" <<'PY'
import json, os, sys

config_path = sys.argv[1]

try:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_config_lint: cannot parse {config_path}: {e}\n")
    sys.exit(1)

if not isinstance(cfg, dict):
    sys.stderr.write(f"operator_config_lint: config root is not a JSON object: {config_path}\n")
    sys.exit(1)

# Field accessors mirroring Config::from_json secure-defaults in
# include/determ/node/node.hpp. Absent field == daemon default.
def g(name, default):
    v = cfg.get(name, default)
    return v if v is not None else default

rpc_localhost_only  = bool (g("rpc_localhost_only", True))
rpc_auth_secret     = str  (g("rpc_auth_secret",    ""))
rpc_rate_per_sec    = float(g("rpc_rate_per_sec",   0.0))
gossip_rate_per_sec = float(g("gossip_rate_per_sec",0.0))
log_quiet           = bool (g("log_quiet",          False))
key_path            = str  (g("key_path",           ""))
genesis_path        = str  (g("genesis_path",       ""))
genesis_hash        = str  (g("genesis_hash",       ""))
listen_port         = int  (g("listen_port",        7777))
rpc_port            = int  (g("rpc_port",            7778))
bootstrap_peers     = g("bootstrap_peers", [])
if not isinstance(bootstrap_peers, list):
    bootstrap_peers = []

# A node is "externally exposed" when RPC is not pinned to localhost OR
# it has bootstrap peers configured (a proxy for a real network node
# rather than a single-box test rig). Used to gate the rate-limit checks.
externally_exposed = (not rpc_localhost_only) or bool(bootstrap_peers)

warns = 0
def emit_pass(msg):
    print(f"  PASS: {msg}")
def emit_warn(msg):
    global warns
    warns += 1
    print(f"  WARN: {msg}")

# ── S-001: RPC bind + HMAC auth ──────────────────────────────────────
if rpc_localhost_only:
    emit_pass("rpc_localhost_only=true (RPC bound to 127.0.0.1; S-001 default)")
else:
    if rpc_auth_secret:
        emit_pass("rpc_localhost_only=false but rpc_auth_secret set "
                  "(HMAC-authenticated network RPC)")
    else:
        emit_warn("rpc_localhost_only=false AND rpc_auth_secret empty -- "
                  "unauthenticated network-reachable RPC (S-001); set "
                  "rpc_auth_secret or pin localhost-only")

# ── S-014: per-IP token bucket (RPC) ─────────────────────────────────
if rpc_rate_per_sec > 0:
    emit_pass(f"rpc_rate_per_sec={rpc_rate_per_sec} (per-IP RPC limiter on; S-014)")
elif externally_exposed:
    emit_warn("rpc_rate_per_sec=0 on an externally-exposed node -- per-IP "
              "RPC token bucket disabled (S-014); set ~100/sec or rely on "
              "an upstream LB")
else:
    emit_pass("rpc_rate_per_sec=0 but RPC is localhost-only "
              "(limiter not required)")

# ── S-014: per-IP token bucket (gossip) ──────────────────────────────
if gossip_rate_per_sec > 0:
    emit_pass(f"gossip_rate_per_sec={gossip_rate_per_sec} "
              "(per-IP gossip limiter on; S-014)")
elif externally_exposed:
    emit_warn("gossip_rate_per_sec=0 on an externally-exposed node -- per-IP "
              "gossip token bucket disabled (S-014); set ~500/sec for a "
              "public-facing node")
else:
    emit_pass("gossip_rate_per_sec=0 but node is not externally exposed "
              "(limiter not required)")

# ── S-027: log verbosity ─────────────────────────────────────────────
if log_quiet:
    emit_pass("log_quiet=true (chatty per-block/handshake logs suppressed; S-027)")
else:
    emit_warn("log_quiet=false (default) -- verbose [node]/[gossip]/[rpc] "
              "logging on a production box widens the passive-observer "
              "scrape surface (S-027); set log_quiet=true")

# ── Keyfile passphrase-encryption (S-004) ────────────────────────────
# key_path points at the node's signing keyfile. The plaintext node_key
# shape is a JSON object with hex {pubkey, priv_seed}; the S-004 hardened
# form is a 2-line "DETERM-NODE-V1 <pubkey>\n<DWE1 envelope>" text file.
# Read-only: we open the file to classify the first bytes, never decrypt.
def classify_keyfile(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return "unreadable"
    if head.startswith(b"DETERM-NODE-V1 "):
        return "encrypted"
    try:
        doc = json.loads(head.decode("utf-8", errors="strict"))
    except Exception:
        # Truncated read of a large JSON, or some other on-disk shape.
        # Don't claim plaintext we can't prove; treat as unknown.
        return "unknown"
    if isinstance(doc, dict) and isinstance(doc.get("pubkey"), str) \
       and isinstance(doc.get("priv_seed"), str):
        return "plaintext"
    return "unknown"

if not key_path:
    emit_warn("key_path unset -- daemon cannot sign blocks; an operator "
              "node MUST set key_path")
elif not os.path.isfile(key_path):
    emit_warn(f"key_path='{key_path}' set but file is absent")
else:
    kind = classify_keyfile(key_path)
    if kind == "encrypted":
        emit_pass("key_path references an S-004 passphrase-encrypted keyfile "
                  "(DETERM-NODE-V1 envelope)")
    elif kind == "plaintext":
        emit_warn(f"key_path='{key_path}' is a PLAINTEXT node_key "
                  "({pubkey,priv_seed}) -- encrypt it with "
                  "`determ-wallet keyfile-encrypt` (S-004) so a host "
                  "compromise doesn't leak the signing seed")
    elif kind == "unreadable":
        emit_warn(f"key_path='{key_path}' present but not readable for "
                  "classification")
    else:
        emit_pass(f"key_path='{key_path}' is not a recognizable plaintext "
                  "node_key (assumed hardened / external)")

# ── Eclipse defense: genesis_hash pin ────────────────────────────────
if genesis_path:
    if genesis_hash:
        emit_pass("genesis_hash pinned (eclipse-defense: bootstrap rejects "
                  "a mismatched genesis)")
    else:
        emit_warn("genesis_path set but genesis_hash empty -- without the pin "
                  "a malicious bootstrap peer can serve a forked genesis")
else:
    emit_pass("genesis_path unset (no genesis_hash pin needed)")

# ── Port conflict sanity ─────────────────────────────────────────────
if listen_port == rpc_port:
    emit_warn(f"listen_port == rpc_port == {listen_port} -- port conflict; "
              "the daemon will refuse to start")
else:
    emit_pass(f"listen_port={listen_port} / rpc_port={rpc_port} (distinct)")

# ── Summary ──────────────────────────────────────────────────────────
print()
if warns == 0:
    print("  PASS: operator_config_lint -- no hardening findings")
else:
    print(f"  PASS: operator_config_lint -- advisory run complete "
          f"({warns} setting(s) flagged for review)")
print(f"WARN findings: {warns}")
sys.exit(0)
PY
PY_RC=$?

# Python exits 1 only on an unparseable config (already reported to
# stderr above). Anything else is a successful advisory run — including
# runs that surfaced WARN findings. Map Python rc -> the test-suite
# convention: 0 = pass/skip, 1 = real (operational) failure. WARN
# findings never escalate to a non-zero exit; this is an advisory tool,
# not a hard gate.
if [ "$PY_RC" -ne 0 ]; then
  echo ""
  echo "  FAIL: operator_config_lint -- config unparseable"
  exit 1
fi
exit 0
