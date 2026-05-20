#!/usr/bin/env bash
# operator_genesis_verify_live.sh — Verify a running determ daemon's
# genesis-block hash matches the chain-identity hash computed from an
# expected genesis.json file.
#
# Composes two existing, read-only surfaces:
#   * `determ chain-id --rpc-port P`         (queries running daemon)
#   * `determ verify-genesis --in <file> --json`  (local file → hash)
#
# Both are read-only; safe against any running daemon.
#
# Usage:
#   tools/operator_genesis_verify_live.sh --genesis <file>
#                                         [--rpc-port N] [--json] [--verbose]
#
# Exit codes:
#   0 — hashes match (chain identity confirmed)
#   1 — RPC error / missing file / malformed file / verify-genesis error / bad args
#   2 — hashes MISMATCH (operator alert gate)
#
# Use cases:
#   1. Pre-deployment: verify a staging daemon's genesis matches the
#      expected genesis.json before promoting to prod — defeats config-
#      rewrite attacks where a deployment template smuggles in a
#      different chain identity.
#   2. Cross-node sanity: paired with operator_fork_watch.sh — if forks
#      are detected, first check whether the two nodes are even on the
#      same chain (different genesis ⇒ they're not forks, they're
#      different chains).
#   3. Disaster recovery: after restoring from backup, verify the
#      restored daemon's genesis still matches the deployment manifest
#      pinned at the time of the original deployment.
#
# S-039 surface: --verbose also prints the full verify-genesis output,
# including operational params (m_creators, k_block_sigs, bft_enabled,
# block_subsidy, min_stake, initial_shard_count, chain_role, shard_id,
# committee_region) that are NOT bound to compute_genesis_hash. Useful
# when hashes diverge AND the operator wants to see whether the
# divergence stems from an identity-bound field vs. an operational-but-
# unbound one (the latter category produces the SAME hash but still
# matters for deployment correctness).
set -u

usage() {
  cat <<'EOF'
Usage: operator_genesis_verify_live.sh --genesis <file>
                                       [--rpc-port N] [--json] [--verbose]

Verifies a running determ daemon's genesis-block hash matches the
chain-identity hash computed from an expected genesis.json file.

Required:
  --genesis <file>   Path to the expected genesis.json on disk

Options:
  --rpc-port N       RPC port of the running daemon (default: 7778)
  --json             Emit single-line JSON instead of human digest
  --verbose          Additionally print full `determ verify-genesis`
                     output (operational params: m_creators,
                     k_block_sigs, bft_enabled, sharding_mode, etc.).
                     Helpful when hashes diverge to see WHICH field is
                     responsible.
  -h, --help         Show this help

Exit codes:
  0   genesis match (daemon's chain identity == file's computed hash)
  1   RPC error / missing or malformed file / verify-genesis error / bad args
  2   genesis MISMATCH (operator alert gate)

Use cases:
  1. Pre-deployment — verify staging daemon's genesis matches the
     expected genesis.json before promoting to prod.
  2. Cross-node sanity — when operator_fork_watch.sh reports
     divergence, first rule out a genesis mismatch (different chains,
     not forks).
  3. Disaster recovery — after restoring from backup, verify the
     restored daemon's genesis matches the deployment manifest.

JSON shape (--json):
  {"match": true|false,
   "daemon_hash": "<64hex>",
   "file_hash":   "<64hex>",
   "genesis_path":"<path>",
   "rpc_port":    <N>}
EOF
}

GENESIS=""
PORT=7778
JSON_OUT=0
VERBOSE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)   usage; exit 0 ;;
    --genesis)   GENESIS="$2"; shift 2 ;;
    --rpc-port)  PORT="$2";    shift 2 ;;
    --json)      JSON_OUT=1;   shift ;;
    --verbose)   VERBOSE=1;    shift ;;
    *) echo "operator_genesis_verify_live: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$GENESIS" ]; then
  echo "operator_genesis_verify_live: --genesis <file> is required" >&2
  usage >&2
  exit 1
fi

# Numeric guard on the port — protects downstream RPC + the JSON
# emitter from a non-numeric value sneaking through.
case "$PORT" in
  *[!0-9]*|"")
    echo "operator_genesis_verify_live: --rpc-port must be a positive integer (got '$PORT')" >&2
    exit 1 ;;
esac

# File-existence + readability check up front. verify-genesis already
# reports cannot_open; we do it here too so the diagnostic mentions the
# operator-supplied path explicitly before any subprocess fires.
if [ ! -f "$GENESIS" ]; then
  echo "operator_genesis_verify_live: --genesis file not found: $GENESIS" >&2
  exit 1
fi
if [ ! -r "$GENESIS" ]; then
  echo "operator_genesis_verify_live: --genesis file not readable: $GENESIS" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── 1. Query the running daemon's genesis hash via chain-id RPC ──
# `determ chain-id` prints just the 64-hex genesis hash on stdout (no
# label) and exits 1 on RPC failure or if the chain hasn't loaded a
# genesis block yet.
DAEMON_HASH=$("$DETERM" chain-id --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_genesis_verify_live: RPC error querying chain-id (is daemon running on port $PORT?)" >&2
  exit 1
}
# Strip any whitespace / trailing newline that may have leaked through.
DAEMON_HASH=$(printf '%s' "$DAEMON_HASH" | tr -d ' \t\r\n')

if [ -z "$DAEMON_HASH" ] || [ ${#DAEMON_HASH} -ne 64 ]; then
  echo "operator_genesis_verify_live: daemon returned malformed chain-id (got '$DAEMON_HASH', expected 64 hex chars)" >&2
  exit 1
fi

# ── 2. Compute the expected hash from the local file ──
# verify-genesis exits 1 on any parse/validation error and prints a
# {"status":"error",...} JSON envelope (or `FAIL: ...` text without --json).
VG_OUT=$("$DETERM" verify-genesis --in "$GENESIS" --json 2>&1)
VG_RC=$?
if [ "$VG_RC" -ne 0 ]; then
  echo "operator_genesis_verify_live: verify-genesis failed on $GENESIS (rc=$VG_RC)" >&2
  echo "$VG_OUT" >&2
  exit 1
fi

# Extract genesis_hash from verify-genesis --json output.
if command -v jq >/dev/null 2>&1; then
  FILE_HASH=$(printf '%s' "$VG_OUT" | jq -r '.genesis_hash // empty' 2>/dev/null)
  VG_STATUS=$(printf '%s' "$VG_OUT" | jq -r '.status // empty' 2>/dev/null)
else
  FILE_HASH=$(printf '%s' "$VG_OUT" | grep -o '"genesis_hash":"[^"]*"' | head -1 | sed 's/.*: *//; s/"//g')
  VG_STATUS=$(printf '%s' "$VG_OUT" | grep -o '"status":"[^"]*"'       | head -1 | sed 's/.*: *//; s/"//g')
fi

if [ "$VG_STATUS" != "ok" ] || [ -z "$FILE_HASH" ] || [ ${#FILE_HASH} -ne 64 ]; then
  echo "operator_genesis_verify_live: verify-genesis returned malformed JSON or status!=ok (file=$GENESIS)" >&2
  echo "$VG_OUT" >&2
  exit 1
fi

# Optional verbose dump: full human-readable verify-genesis output so
# the operator can spot WHICH field diverges (especially useful for the
# S-039 operational-but-unbound params).
if [ "$VERBOSE" = "1" ]; then
  echo "── verify-genesis details ($GENESIS) ──"
  # Re-invoke without --json for the human-readable form (the JSON
  # already-captured pass exposed all fields, but the human form is
  # more scannable). Best-effort: failures here don't change the
  # script's exit code since the JSON pass already succeeded.
  "$DETERM" verify-genesis --in "$GENESIS" 2>&1 || true
  echo "──"
fi

# ── 3. Compare ──
MATCH="false"
if [ "$DAEMON_HASH" = "$FILE_HASH" ]; then
  MATCH="true"
fi

if [ "$JSON_OUT" = "1" ]; then
  printf '{"match":%s,"daemon_hash":"%s","file_hash":"%s","genesis_path":"%s","rpc_port":%s}\n' \
    "$MATCH" "$DAEMON_HASH" "$FILE_HASH" "$GENESIS" "$PORT"
fi

if [ "$MATCH" = "true" ]; then
  [ "$JSON_OUT" = "1" ] || echo "operator_genesis_verify_live: genesis OK (hash=$DAEMON_HASH, port=$PORT)"
  exit 0
else
  if [ "$JSON_OUT" != "1" ]; then
    echo "operator_genesis_verify_live: genesis MISMATCH" >&2
    echo "  daemon: $DAEMON_HASH" >&2
    echo "  file:   $FILE_HASH" >&2
  fi
  exit 2
fi
