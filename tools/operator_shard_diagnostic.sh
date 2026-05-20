#!/usr/bin/env bash
# operator_shard_diagnostic.sh — Shard-routing diagnostic for multi-shard
# determ deployments. Probes the daemon for its current chain identity
# and configured shard_id, reads shard_count + shard_address_salt from a
# supplied genesis.json (required — see "RPC-shape gap" below), generates
# or loads a sample of addresses, computes the routing target for each
# via `determ where-is`, aggregates the distribution, and compares it
# against the uniform expectation (~N/shard_count per shard ±sqrt(N)).
#
# Operator use cases:
#   - "Is our salt biasing the routing distribution?" — flag any shard
#     with > 2× expected count (potential salt-bias signal that would
#     indicate either a CSPRNG failure at genesis-build time or a hash
#     truncation bug; both are S-018 / S-039 territory).
#   - "Is any shard empty?" — only an anomaly if shard_count > 1.
#   - "How much load does THIS shard carry from this address class?"
#     With --include-this-shard, the human/JSON output highlights how
#     many of the sample's addresses route to the daemon's `my_shard_id`.
#
# RPC-shape gap (documented runtime limitation):
#   The `status` RPC surfaces `shard_id` (this node's shard) but does
#   NOT expose `shard_count` or the chain's `shard_address_salt`. Both
#   are part of the genesis configuration and are not currently echoed
#   by any read-only RPC method. The script therefore REQUIRES
#   `--genesis <file>` to learn shard_count + salt. We use `verify-genesis
#   --json` to validate + extract `initial_shard_count`, and read the
#   `shard_address_salt` field directly from the JSON file (since
#   `verify-genesis --json` does not echo the salt — by design, since
#   the salt is operationally sensitive and verify-genesis is intended
#   for chain-identity comparison, not raw config dumps).
#
# Anomaly flags:
#   shard_imbalance    — at least one shard's observed count is > 2×
#                         the uniform expected count (potential salt-
#                         bias or a defective hash truncation step).
#                         Triggers exit 2 with --anomalies-only.
#   shard_empty        — at least one shard received zero sample
#                         addresses AND shard_count > 1. Strong
#                         indicator of a deterministic routing bug if
#                         sample is large; weaker signal at small N.
#                         Triggers exit 2 with --anomalies-only.
#
# Args:
#   [--rpc-port N]            RPC port to query (default: 7778)
#   [--json]                  Emit structured JSON instead of human output
#   [--anomalies-only]        Suppress normal output unless an anomaly
#                              was found; exit 2 if anomalies detected
#   [--genesis <file>]        REQUIRED. Path to genesis.json — source of
#                              shard_count + shard_address_salt
#   [--sample N]              Sample size (default: 100)
#   [--addresses <file>]      Optional file of addresses (one per line).
#                              If omitted, generates N random anon-style
#                              addresses via /dev/urandom + sha256.
#   [--include-this-shard]    Add a "this shard" highlight line listing
#                              how many sample addresses routed to the
#                              daemon's my_shard_id
#   [-h|--help]                Show this help
#
# Exit codes:
#   0   diagnostic ran, no anomalies
#   1   RPC error / daemon unreachable / bad args / missing dependency
#   2   --anomalies-only AND ≥1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_shard_diagnostic.sh --genesis <file>
                                    [--rpc-port N] [--json]
                                    [--anomalies-only]
                                    [--sample N] [--addresses <file>]
                                    [--include-this-shard]

Shard-routing diagnostic for multi-shard determ deployments. Probes a
running daemon for its chain identity (`determ chain-id`), current
state (`determ head`), peer set (`determ peers`), and configured
shard_id (`determ status --field shard_id`), reads shard_count + salt
from the supplied genesis.json, generates or loads a sample of
addresses, routes each via `determ where-is`, and reports the
distribution vs. the uniform-with-sqrt-N tolerance expectation.

Why --genesis is required:
  The `status` RPC surfaces this node's shard_id but does NOT expose
  the chain's shard_count or shard_address_salt. Both come from
  genesis. We use `verify-genesis --json` to extract initial_shard_count
  and read shard_address_salt directly from the JSON file. There is
  currently no runtime RPC for these values.

Options:
  --rpc-port N           RPC port to query (default: 7778)
  --json                 Emit a structured JSON envelope (shape below)
  --anomalies-only       Suppress normal output unless an anomaly was
                          found; exit 2 if anomalies present
  --genesis <file>       REQUIRED. genesis.json — source of shard_count
                          and shard_address_salt
  --sample N             Number of sample addresses to route (default 100)
  --addresses <file>     Optional file of addresses (one per line). If
                          omitted, the script generates N random anon-
                          style 0x+64hex addresses
  --include-this-shard   Highlight how many of the sample routed to the
                          daemon's my_shard_id
  -h, --help             Show this help

Anomalies:
  shard_imbalance     any shard's observed count > 2× expected uniform
  shard_empty         any shard received zero addresses AND
                       shard_count > 1

JSON shape:
  {"genesis_hash":"…","height":H,"shard_count":S,"my_shard_id":I,
   "salt_hex":"…","sample_size":N,
   "distribution":[{"shard":0,"count":k0},…],
   "expected_per_shard":E,"tolerance":T,
   "anomalies":["…",…],"rpc_port":P}

Exit codes:
  0   diagnostic ran, no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / bad args / missing dependency
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
GENESIS_PATH=""
SAMPLE_N=100
ADDR_FILE=""
INCLUDE_THIS=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           PORT="${2:-}";          shift 2 ;;
    --json)               JSON_OUT=1;             shift ;;
    --anomalies-only)     ANOM_ONLY=1;            shift ;;
    --genesis)            GENESIS_PATH="${2:-}";  shift 2 ;;
    --sample)             SAMPLE_N="${2:-}";      shift 2 ;;
    --addresses)          ADDR_FILE="${2:-}";     shift 2 ;;
    --include-this-shard) INCLUDE_THIS=1;         shift ;;
    *) echo "operator_shard_diagnostic: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric / required-arg guards.
case "$PORT" in
  *[!0-9]*|"") echo "operator_shard_diagnostic: --rpc-port must be a positive integer (got '$PORT')" >&2; exit 1 ;;
esac
case "$SAMPLE_N" in
  *[!0-9]*|"") echo "operator_shard_diagnostic: --sample must be a positive integer (got '$SAMPLE_N')" >&2; exit 1 ;;
esac
if [ "$SAMPLE_N" -lt 1 ]; then
  echo "operator_shard_diagnostic: --sample must be >= 1" >&2; exit 1
fi
if [ -z "$GENESIS_PATH" ]; then
  echo "operator_shard_diagnostic: --genesis <file> is required" >&2
  echo "  (the daemon does not expose shard_count + salt via any RPC; see --help)" >&2
  exit 1
fi
if [ ! -r "$GENESIS_PATH" ]; then
  echo "operator_shard_diagnostic: cannot read --genesis '$GENESIS_PATH'" >&2; exit 1
fi
if [ -n "$ADDR_FILE" ] && [ ! -r "$ADDR_FILE" ]; then
  echo "operator_shard_diagnostic: cannot read --addresses '$ADDR_FILE'" >&2; exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: validate genesis + extract shard_count via verify-genesis ─────────
# verify-genesis applies the same parsing + sane-bounds checks as
# `determ start` and emits a structured JSON summary. It does NOT echo
# shard_address_salt (operational-sensitivity / chain-identity scope).
GV_OUT=$("$DETERM" verify-genesis --in "$GENESIS_PATH" --json 2>/dev/null) || {
  echo "operator_shard_diagnostic: \`determ verify-genesis\` failed for $GENESIS_PATH" >&2
  exit 1
}

if [ "$HAVE_JQ" = "1" ]; then
  GV_STATUS=$(printf '%s' "$GV_OUT"  | jq -r '.status // ""')
  if [ "$GV_STATUS" != "ok" ]; then
    GV_MSG=$(printf '%s' "$GV_OUT" | jq -r '.message // "(unknown)"')
    echo "operator_shard_diagnostic: genesis validation failed: $GV_MSG" >&2
    exit 1
  fi
  SHARD_COUNT=$(printf '%s' "$GV_OUT" | jq -r '.initial_shard_count // 0')
  GENESIS_HASH_FROM_FILE=$(printf '%s' "$GV_OUT" | jq -r '.genesis_hash // ""')
else
  GV_STATUS=$(printf '%s' "$GV_OUT" | grep -o '"status":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
  if [ "$GV_STATUS" != "ok" ]; then
    echo "operator_shard_diagnostic: genesis validation failed (status='$GV_STATUS')" >&2
    exit 1
  fi
  SHARD_COUNT=$(printf '%s' "$GV_OUT" | grep -o '"initial_shard_count":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  GENESIS_HASH_FROM_FILE=$(printf '%s' "$GV_OUT" | grep -o '"genesis_hash":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
fi
case "$SHARD_COUNT" in
  *[!0-9]*|"") echo "operator_shard_diagnostic: cannot parse initial_shard_count from verify-genesis (got '$SHARD_COUNT')" >&2; exit 1 ;;
esac
if [ "$SHARD_COUNT" -lt 1 ]; then
  echo "operator_shard_diagnostic: initial_shard_count must be >= 1 (got $SHARD_COUNT)" >&2; exit 1
fi

# ── Step 2: extract shard_address_salt from the genesis file directly ────────
# verify-genesis --json does not emit the salt; read the source JSON.
if [ "$HAVE_JQ" = "1" ]; then
  SALT_HEX=$(jq -r '.shard_address_salt // ""' "$GENESIS_PATH" 2>/dev/null)
else
  # Pretty-printed genesis.json has whitespace between `:` and the
  # value — be tolerant of any whitespace. Extract the hex inside the
  # quoted value.
  SALT_HEX=$(grep -oE '"shard_address_salt"[[:space:]]*:[[:space:]]*"[^"]*"' "$GENESIS_PATH" | head -1 | sed 's/.*"\([0-9a-fA-F]*\)"[[:space:]]*$/\1/')
fi
# Salt may be absent in legacy / single-shard genesis files; default to
# 64 zeros (matches `determ where-is`'s default behavior when --salt-hex
# is omitted).
if [ -z "$SALT_HEX" ] || [ "$SALT_HEX" = "null" ]; then
  SALT_HEX="0000000000000000000000000000000000000000000000000000000000000000"
fi
case "$SALT_HEX" in
  *[!0-9a-fA-F]*)
    echo "operator_shard_diagnostic: shard_address_salt is not hex (got '$SALT_HEX')" >&2; exit 1 ;;
esac
if [ "${#SALT_HEX}" != "64" ]; then
  echo "operator_shard_diagnostic: shard_address_salt must be 64 hex chars (got ${#SALT_HEX})" >&2; exit 1
fi

# ── Step 3: probe daemon ──────────────────────────────────────────────────────
# `chain-id` returns the genesis hash; cross-check against the file's
# computed hash so an operator notices if --genesis points at the wrong
# chain.
CHAIN_ID_OUT=$("$DETERM" chain-id --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_shard_diagnostic: RPC error from \`determ chain-id\` (is daemon running on port $PORT?)" >&2
  exit 1
}
GENESIS_HASH=$(printf '%s' "$CHAIN_ID_OUT" | tr -d '\r\n ' | head -c 200)
case "$GENESIS_HASH" in
  *[!0-9a-fA-F]*|"")
    echo "operator_shard_diagnostic: malformed chain-id response ('$GENESIS_HASH')" >&2; exit 1 ;;
esac

HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_shard_diagnostic: RPC error from \`determ head\`" >&2; exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  HEIGHT=$(printf '%s' "$HEAD_OUT" | jq -r '.height // 0')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT" | jq -r '.head_hash // ""')
else
  HEIGHT=$(printf '%s' "$HEAD_OUT" | grep -o '"height":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT" | grep -o '"head_hash":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
fi
case "$HEIGHT" in *[!0-9]*|"") echo "operator_shard_diagnostic: malformed head JSON (height='$HEIGHT')" >&2; exit 1 ;; esac

MY_SHARD_ID=$("$DETERM" status --field shard_id --rpc-port "$PORT" 2>/dev/null | tr -d '\r\n ') || {
  echo "operator_shard_diagnostic: RPC error from \`determ status --field shard_id\`" >&2; exit 1
}
# status --field returns empty string for missing/null fields; treat as 0.
[ -z "$MY_SHARD_ID" ] && MY_SHARD_ID=0
case "$MY_SHARD_ID" in
  *[!0-9]*) echo "operator_shard_diagnostic: malformed status shard_id ('$MY_SHARD_ID')" >&2; exit 1 ;;
esac

# `peers` is queried for completeness (operator workflow context) but
# isn't used in the routing computation. If the call fails, we degrade
# to peer_count=0 rather than aborting — diagnostic still useful offline.
PEER_COUNT=$("$DETERM" peers --count --rpc-port "$PORT" 2>/dev/null | tr -d '\r\n ')
case "$PEER_COUNT" in *[!0-9]*|"") PEER_COUNT=0 ;; esac

# Mismatch check (informational; doesn't gate exit code since operators
# legitimately run the diagnostic against a different chain's genesis
# during cross-deployment audits).
GENESIS_MATCHES=1
if [ -n "$GENESIS_HASH" ] && [ -n "$GENESIS_HASH_FROM_FILE" ] \
   && [ "$GENESIS_HASH" != "$GENESIS_HASH_FROM_FILE" ]; then
  GENESIS_MATCHES=0
fi

# ── Step 4: assemble sample addresses ────────────────────────────────────────
TMP_ADDRS=$(mktemp)
TMP_DIST=$(mktemp)
trap 'rm -f "$TMP_ADDRS" "$TMP_DIST"' EXIT

if [ -n "$ADDR_FILE" ]; then
  # Take the first SAMPLE_N non-blank lines.
  grep -v '^[[:space:]]*$' "$ADDR_FILE" | head -n "$SAMPLE_N" >"$TMP_ADDRS"
  ACTUAL_N=$(grep -c . "$TMP_ADDRS" || true)
  case "$ACTUAL_N" in *[!0-9]*|"") ACTUAL_N=0 ;; esac
  if [ "$ACTUAL_N" = "0" ]; then
    echo "operator_shard_diagnostic: --addresses file '$ADDR_FILE' has no usable lines" >&2; exit 1
  fi
  # Honor the smaller of (--sample, file_size) so the report's
  # sample_size reflects what was actually routed.
  SAMPLE_N="$ACTUAL_N"
else
  # Generate SAMPLE_N random anon-style addresses (0x + 64 hex). Source
  # entropy from /dev/urandom; fall back to date+PID seed via sha256sum
  # if /dev/urandom is unavailable (extremely rare on POSIX). Avoid
  # querying the daemon for entropy — keeps the script offline-friendly
  # once chain-id/head are captured.
  if [ ! -r /dev/urandom ]; then
    echo "operator_shard_diagnostic: /dev/urandom is not readable; cannot generate sample" >&2
    echo "  workaround: pass --addresses <file>" >&2; exit 1
  fi
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "operator_shard_diagnostic: need sha256sum (or shasum) to generate sample addresses" >&2
    echo "  workaround: pass --addresses <file>" >&2; exit 1
  fi
  hash256() {
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum | awk '{print $1}'
    else
      shasum -a 256 | awk '{print $1}'
    fi
  }
  i=0
  while [ "$i" -lt "$SAMPLE_N" ]; do
    # 32 bytes of entropy -> sha256 -> 64 hex chars. Prefix with 0x to
    # match the anon-address convention; `where-is` accepts either form
    # but the canonical anon form is the documented operator surface.
    HEX=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | hash256)
    printf '0x%s\n' "$HEX" >>"$TMP_ADDRS"
    i=$((i + 1))
  done
fi

# ── Step 5: route each address ───────────────────────────────────────────────
# `where-is` is pure-local (no RPC), so we can call it SAMPLE_N times
# without worrying about RPC rate-limits. The bottleneck is binary
# fork/exec overhead — fine for default N=100 (sub-second on any modern
# host) and tolerable for N=10000.
while IFS= read -r ADDR; do
  [ -z "$ADDR" ] && continue
  WI_OUT=$("$DETERM" where-is "$ADDR" --shard-count "$SHARD_COUNT" --salt-hex "$SALT_HEX" --json 2>/dev/null) || {
    echo "operator_shard_diagnostic: \`determ where-is\` failed for address '$ADDR'" >&2; exit 1
  }
  if [ "$HAVE_JQ" = "1" ]; then
    SH=$(printf '%s' "$WI_OUT" | jq -r '.shard // empty')
  else
    SH=$(printf '%s' "$WI_OUT" | grep -o '"shard":[0-9]*' | head -1 | sed 's/.*: *//')
  fi
  case "$SH" in
    *[!0-9]*|"") echo "operator_shard_diagnostic: cannot parse shard from where-is (got '$SH')" >&2; exit 1 ;;
  esac
  printf '%s\n' "$SH" >>"$TMP_DIST"
done <"$TMP_ADDRS"

# ── Step 6: aggregate distribution ────────────────────────────────────────────
# Build a dense `shard count` table covering ALL shards in [0,
# SHARD_COUNT-1], including any that received zero addresses (otherwise
# the shard_empty anomaly would be silent).
COUNTS_FILE=$(mktemp)
trap 'rm -f "$TMP_ADDRS" "$TMP_DIST" "$COUNTS_FILE"' EXIT
s=0
while [ "$s" -lt "$SHARD_COUNT" ]; do
  N=$(grep -c "^${s}$" "$TMP_DIST" || true)
  case "$N" in *[!0-9]*|"") N=0 ;; esac
  printf '%s\t%s\n' "$s" "$N" >>"$COUNTS_FILE"
  s=$((s + 1))
done

# Expected uniform allocation per shard. Use integer division — sqrt
# tolerance below absorbs the rounding.
EXPECTED=$(( SAMPLE_N / SHARD_COUNT ))

# Tolerance: sqrt(SAMPLE_N), rounded up to nearest integer. Use a
# portable Newton iteration that avoids awk -- bash arithmetic only.
# Standard deviation of a binomial(N, 1/S) is sqrt(N * (1/S) * (1-1/S))
# which for moderate S is close enough to sqrt(N/S) ~= sqrt(EXPECTED).
# Using sqrt(SAMPLE_N) is a generous bound that absorbs both finite-S
# correction and the rounding-error of integer EXPECTED.
isqrt() {
  local n="$1"
  if [ "$n" -le 0 ]; then echo 0; return; fi
  if [ "$n" -lt 2 ]; then echo 1; return; fi
  local x="$n"
  local y=$(( (x + 1) / 2 ))
  while [ "$y" -lt "$x" ]; do
    x="$y"
    y=$(( (x + n / x) / 2 ))
  done
  # Round up to ceil(sqrt(n)).
  if [ $(( x * x )) -lt "$n" ]; then x=$(( x + 1 )); fi
  echo "$x"
}
TOLERANCE=$(isqrt "$SAMPLE_N")

# ── Step 7: anomaly detection ────────────────────────────────────────────────
ANOMALIES=""
add_anomaly() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

# shard_imbalance: any shard's count > 2 * EXPECTED.
# At shard_count=1 the threshold is 2 * SAMPLE_N which can never trip;
# the check is suppressed in that case (a single-shard chain trivially
# has 100% concentration on the one shard).
IMBALANCE_LIMIT=$(( 2 * EXPECTED ))
EMPTY_COUNT=0
IMBALANCE_COUNT=0
while IFS=$'\t' read -r SHARD CNT; do
  if [ "$SHARD_COUNT" -gt 1 ] && [ "$IMBALANCE_LIMIT" -gt 0 ] && [ "$CNT" -gt "$IMBALANCE_LIMIT" ]; then
    IMBALANCE_COUNT=$(( IMBALANCE_COUNT + 1 ))
  fi
  if [ "$SHARD_COUNT" -gt 1 ] && [ "$CNT" = "0" ]; then
    EMPTY_COUNT=$(( EMPTY_COUNT + 1 ))
  fi
done <"$COUNTS_FILE"
[ "$IMBALANCE_COUNT" -gt 0 ] && add_anomaly "shard_imbalance"
[ "$EMPTY_COUNT" -gt 0 ]     && add_anomaly "shard_empty"

# Count of "alert-worthy" anomalies (for the --anomalies-only gate).
ALERT_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ALERT_COUNT=$(printf '%s' "$ANOMALIES" | tr ',' '\n' | grep -c . || true)
fi
case "$ALERT_COUNT" in *[!0-9]*|"") ALERT_COUNT=0 ;; esac

# How many of the sample addresses route to MY shard (for the
# --include-this-shard highlight)?
MY_SHARD_COUNT=0
if [ "$MY_SHARD_ID" -lt "$SHARD_COUNT" ]; then
  MY_SHARD_COUNT=$(awk -F'\t' -v S="$MY_SHARD_ID" '$1 == S { print $2 }' "$COUNTS_FILE")
  case "$MY_SHARD_COUNT" in *[!0-9]*|"") MY_SHARD_COUNT=0 ;; esac
fi

# ── Step 8: rendering ────────────────────────────────────────────────────────
emit_json() {
  printf '{"genesis_hash":"%s","height":%s,"shard_count":%s,"my_shard_id":%s,"salt_hex":"%s","sample_size":%s,"distribution":[' \
    "$GENESIS_HASH" "$HEIGHT" "$SHARD_COUNT" "$MY_SHARD_ID" "$SALT_HEX" "$SAMPLE_N"
  FIRST=1
  while IFS=$'\t' read -r SHARD CNT; do
    [ "$FIRST" = "1" ] || printf ','
    FIRST=0
    printf '{"shard":%s,"count":%s}' "$SHARD" "$CNT"
  done <"$COUNTS_FILE"
  printf '],"expected_per_shard":%s,"tolerance":%s,"anomalies":[' "$EXPECTED" "$TOLERANCE"
  if [ -n "$ANOMALIES" ]; then
    AFIRST=1
    printf '%s' "$ANOMALIES" | tr ',' '\n' | while IFS= read -r A; do
      [ -z "$A" ] && continue
      [ "$AFIRST" = "1" ] || printf ','
      AFIRST=0
      printf '"%s"' "$A"
    done
  fi
  printf '],"genesis_matches_daemon":%s,"peer_count":%s,"rpc_port":%s}\n' \
    "$([ "$GENESIS_MATCHES" = "1" ] && echo true || echo false)" "$PEER_COUNT" "$PORT"
}

emit_human() {
  HASH_SHORT="(empty)"
  [ -n "$GENESIS_HASH" ] && HASH_SHORT="$(printf '%s' "$GENESIS_HASH" | cut -c1-8)..."
  HEAD_SHORT="(empty)"
  [ -n "$HEAD_HASH" ] && HEAD_SHORT="$(printf '%s' "$HEAD_HASH" | cut -c1-8)..."
  SALT_SHORT="$(printf '%s' "$SALT_HEX" | cut -c1-8)..."

  echo "=== Shard-routing diagnostic (port $PORT) ==="
  echo "Daemon: genesis=$HASH_SHORT, height=$HEIGHT, head=$HEAD_SHORT"
  echo "Shard config: count=$SHARD_COUNT, my_shard_id=$MY_SHARD_ID, salt=$SALT_SHORT"
  if [ "$GENESIS_MATCHES" = "0" ]; then
    echo "[WARN] Daemon genesis_hash differs from --genesis file's computed hash"
    echo "       daemon : $(printf '%s' "$GENESIS_HASH"           | cut -c1-16)..."
    echo "       file   : $(printf '%s' "$GENESIS_HASH_FROM_FILE" | cut -c1-16)..."
  fi
  echo "Routing sample: $SAMPLE_N addresses"
  echo "Distribution:"
  while IFS=$'\t' read -r SHARD CNT; do
    PCT="0.0"
    if [ "$SAMPLE_N" -gt 0 ]; then
      # Percentage to 1 decimal place via integer math: pct * 10.
      PCT_TIMES_10=$(( CNT * 1000 / SAMPLE_N ))
      WHOLE=$(( PCT_TIMES_10 / 10 ))
      FRAC=$(( PCT_TIMES_10 - WHOLE * 10 ))
      PCT="${WHOLE}.${FRAC}"
    fi
    TAG=""
    if [ "$SHARD" = "$MY_SHARD_ID" ] && [ "$INCLUDE_THIS" = "1" ]; then
      TAG="  [this shard]"
    fi
    printf '  shard %s:  %s (%s%%)%s\n' "$SHARD" "$CNT" "$PCT" "$TAG"
  done <"$COUNTS_FILE"
  echo "Expected per shard: $EXPECTED ±$TOLERANCE (uniform with sqrt-N tolerance)"

  if [ "$ALERT_COUNT" = "0" ]; then
    if [ "$SHARD_COUNT" = "1" ]; then
      echo "[INFO] Single-shard chain (shard_count=1) — uniformity check trivially holds"
    else
      echo "[OK] Routing distribution within tolerance"
    fi
  fi
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | tr ',' '\n' | while IFS= read -r A; do
      [ -z "$A" ] && continue
      case "$A" in
        shard_imbalance)
          echo "[WARN] Shard imbalance: at least one shard's count > 2× expected ($IMBALANCE_LIMIT)"
          ;;
        shard_empty)
          echo "[WARN] Empty shard(s): $EMPTY_COUNT of $SHARD_COUNT shards received zero addresses"
          ;;
      esac
    done
  fi

  if [ "$INCLUDE_THIS" = "1" ]; then
    PCT_TIMES_10=0
    if [ "$SAMPLE_N" -gt 0 ]; then
      PCT_TIMES_10=$(( MY_SHARD_COUNT * 1000 / SAMPLE_N ))
    fi
    WHOLE=$(( PCT_TIMES_10 / 10 ))
    FRAC=$(( PCT_TIMES_10 - WHOLE * 10 ))
    printf '[INFO] This shard receives %s.%s%% of the sample (%s/%s addresses)\n' \
      "$WHOLE" "$FRAC" "$MY_SHARD_COUNT" "$SAMPLE_N"
  fi
}

# --anomalies-only mode: silent unless an anomaly fired.
if [ "$ANOM_ONLY" = "1" ]; then
  if [ "$ALERT_COUNT" -gt 0 ]; then
    if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
    exit 2
  fi
  exit 0
fi

if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
exit 0
