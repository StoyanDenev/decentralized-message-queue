#!/usr/bin/env bash
# operator_mempool_diagnostic.sh — Forward-staged mempool state diagnostic.
#
# Probes the daemon for a `mempool` RPC method that dumps the full set of
# pending transactions, then aggregates:
#   - Total pending tx count
#   - By tx-type breakdown   (TRANSFER, REGISTER, DEREGISTER, STAKE, UNSTAKE,
#                             DAPP_REGISTER, DAPP_CALL, PARAM_CHANGE, ...)
#   - Top-10 senders         (by pending tx count; Sybil/spam signal)
#   - Total pending fee value (sum of tx.fee over all pending)
#   - Average tx body size   (mean(tx.body.size()) when wire size observable)
#
# Computes S-008 pressure: pending_count / MEMPOOL_MAX_TXS as a percentage.
# Flags anomalies:
#   - pressure_warning       pending >= 80% of MEMPOOL_MAX_TXS (S-008 zone)
#   - sender_dominance       single sender holds > 30% of pending (Sybil)
#
# ── Forward-staging note (read this) ──────────────────────────────────────────
# The v1.x RPC surface (`src/rpc/rpc.cpp`) does NOT expose a `mempool`
# dump method. The only mempool-visible field today is `mempool_size`
# inside the `status` RPC (count only — no per-tx details). Without
# per-tx records the by-type / by-sender / fee-value aggregates are not
# computable from outside the daemon.
#
# Therefore this script:
#   1. Documents the RPC requirement in --help (this comment block + usage)
#   2. Exits 1 with a clear diagnostic when run against a current daemon
#      whose `determ mempool` subcommand is missing
#   3. Carries the full Python aggregation logic in a heredoc so that the
#      moment v2.x ships a `mempool` RPC of the expected shape, the script
#      is wired and works without further changes.
#
# Expected v2.x RPC shape (see V2-DESIGN.md / V2-DAPP-DESIGN.md):
#   `determ mempool --json --rpc-port P` →
#     {
#       "pending": [
#         {"hash":"...", "from":"...", "to":"...", "type":"TRANSFER",
#          "fee":<u64>, "amount":<u64>, "nonce":<u64>, "size":<u64>},
#         ...
#       ],
#       "count":   <u64>,         // === pending.length
#       "bound":   <u64>          // current MEMPOOL_MAX_TXS (10000 today)
#     }
# `count` and `bound` are advisory — count is recomputed from the array
# length, and bound falls back to the compile-time constant 10000 if the
# daemon omits it.
#
# Until that ships, an operator who needs a count-only sanity check should
# use `determ status --json | jq .mempool_size` (which is exposed today).
#
# Args:
#   [--rpc-port N]        RPC port to query (default: 7778)
#   [--json]              Emit structured JSON envelope instead of table
#   [--anomalies-only]    Print ONLY anomaly summary (suppress per-tx breakdown);
#                         in this mode exit 2 if anomalies were found
#   [-h|--help]           Show this help
#
# Exit codes:
#   0   success, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / mempool RPC method not available /
#       malformed response / bad args
#   2   --anomalies-only set AND >=1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_mempool_diagnostic.sh [--rpc-port N] [--json]
                                       [--anomalies-only]

Mempool state diagnostic. Dumps pending-tx aggregates from a running
determ daemon and computes S-008 pressure + anomaly signals.

REQUIRES: daemon `mempool` RPC method exposing per-tx records (NOT
currently exposed in v1.x; tracked for v2.x). When run against a
daemon without the `mempool` method, this script exits 1 with a
diagnostic. It is shipped now as a forward-staged template so that
v2.x deployments inherit a working operator tool the moment the RPC
lands. For a count-only check today, use:

    determ status --json --rpc-port P | jq .mempool_size

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope:
                        {pending, bound, pressure_pct, total_fee,
                         avg_size, by_type:{TYPE:count,...},
                         top_senders:[{from,count},...],
                         anomalies:[...], rpc_port}
  --anomalies-only    Print only anomaly summary (no per-tx tables);
                      exit 2 if any anomaly found
  -h, --help          Show this help

Anomaly flags:
  pressure_warning   pending >= 80% of MEMPOOL_MAX_TXS (default cap 10000)
  sender_dominance   single sender holds > 30% of pending (Sybil/spam)

Exit codes:
  0   success, no anomalies (or informational mode)
  1   RPC error / mempool RPC not available / bad args
  2   --anomalies-only set AND >=1 anomaly detected
EOF
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
PORT=7778
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="$2"; shift 2 ;;
    --json)           JSON_OUT=1; shift ;;
    --anomalies-only) ANOM_ONLY=1; shift ;;
    *) echo "operator_mempool_diagnostic: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done
case "$PORT" in *[!0-9]*|"") echo "operator_mempool_diagnostic: --rpc-port must be a positive integer (got '$PORT')" >&2; exit 1 ;; esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Compile-time S-008 bound; mirrors include/determ/node/node.hpp::MEMPOOL_MAX_TXS.
# Used as the fallback when the (future) `mempool` RPC omits its own .bound field.
MEMPOOL_MAX_TXS_DEFAULT=10000

# Anomaly thresholds (percent integers; portable bash int compare).
PRESSURE_WARN_PCT=80
SENDER_DOMINANCE_PCT=30

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

HAVE_PY=0
if command -v python3 >/dev/null 2>&1; then HAVE_PY=1; PY=python3
elif command -v python  >/dev/null 2>&1; then HAVE_PY=1; PY=python
fi

# ── Step 1: probe for the mempool RPC method ─────────────────────────────────
# Capture stdout AND stderr so we can surface upstream auth/connect errors.
MEMPOOL_OUT=$("$DETERM" mempool --json --rpc-port "$PORT" 2>&1) || RPC_RC=$?
RPC_RC=${RPC_RC:-0}

# Distinguish "method not available" from "transport error".
# A current daemon will return either a JSON-RPC `method not found` error
# wrapped in an envelope, or the CLI itself will report "unknown subcommand:
# mempool" before sending anything over the wire. The CLI dispatch in
# src/main.cpp emits a stderr message that lacks a JSON `pending` field.
# Test for the presence of `"pending"` (which the v2.x RPC will emit) as
# the positive signal that the method exists and returned a usable payload.
if ! printf '%s' "$MEMPOOL_OUT" | grep -q '"pending"'; then
  if [ "$JSON_OUT" = "1" ]; then
    # Emit a parseable error envelope so callers (cron / dashboards) can
    # distinguish "RPC method missing" from "RPC unreachable" without
    # parsing the human stderr text.
    printf '{"error":"mempool_rpc_unavailable","rpc_port":%s,"detail":"daemon does not expose `mempool` RPC method; this script is forward-staged for v2.x — see --help"}\n' "$PORT"
  else
    cat >&2 <<EOF
operator_mempool_diagnostic: Mempool RPC not available on port $PORT.

The \`mempool\` RPC method is not exposed by the running daemon (v1.x
ships only \`mempool_size\` as a scalar inside the \`status\` RPC, which
lacks the per-tx records this script needs).

This script is shipped as a forward-looking template for the v2.x
mempool-RPC addition (see --help). It will start working automatically
once the daemon exposes \`determ mempool --json\` returning
\`{pending:[{hash,from,type,fee,size,...}], count, bound}\`.

For a count-only check against today's daemon, use:
  determ status --json --rpc-port $PORT | jq .mempool_size
EOF
    # Surface the upstream stderr for operator diagnosis (truncated to
    # avoid dumping multi-MB binary garbage if the daemon mis-responded).
    if [ -n "$MEMPOOL_OUT" ]; then
      echo >&2
      echo "Upstream output (first 8 lines):" >&2
      printf '%s\n' "$MEMPOOL_OUT" | head -8 >&2
    fi
  fi
  exit 1
fi

# ── Step 2: aggregate ────────────────────────────────────────────────────────
# Python is the strongly-preferred path: by-type + top-N + averaging across
# an array of objects in pure POSIX shell + jq is doable but brittle, and
# the script already ships forward-staged — we accept the python dependency
# for the live-data path. If python is absent we degrade to a count-only
# summary derived from .count / .bound.
#
# The python aggregator is written to a temp file (not piped via heredoc)
# because `python - <<EOF | … ` collides with our need to also feed the
# mempool JSON over stdin. argv carries the JSON path + three numeric
# thresholds; the temp script reads + parses + emits a TSV stream we then
# re-render for the human/JSON output.

TMP_PY=""
TMP_JSON=""
if [ "$HAVE_PY" = "1" ]; then
  TMP_PY=$(mktemp)
  TMP_JSON=$(mktemp)
  # Stash MEMPOOL_OUT verbatim (preserves newlines, unlike `printf '%s'`).
  printf '%s' "$MEMPOOL_OUT" >"$TMP_JSON"
  cat >"$TMP_PY" <<'PYEOF'
import sys, json, collections
with open(sys.argv[1], "rb") as fh:
    raw = fh.read().decode("utf-8", errors="replace")
try:
    doc = json.loads(raw)
except Exception as e:
    print(f"PARSE_ERROR\t{e}")
    sys.exit(0)
pending = doc.get("pending") or []
if not isinstance(pending, list):
    print("PARSE_ERROR\tpending field not a list")
    sys.exit(0)
bound_default = int(sys.argv[2])
pressure_warn = int(sys.argv[3])
sender_dom    = int(sys.argv[4])
bound = doc.get("bound")
try:
    bound = int(bound) if bound is not None else bound_default
except Exception:
    bound = bound_default
if bound <= 0:
    bound = bound_default

count = len(pending)
total_fee = 0
size_sum = 0
size_observed = 0
by_type = collections.Counter()
by_sender = collections.Counter()
for tx in pending:
    if not isinstance(tx, dict):
        continue
    t = tx.get("type") or "UNKNOWN"
    by_type[t] += 1
    f = tx.get("from")
    if isinstance(f, str) and f:
        by_sender[f] += 1
    try:
        total_fee += int(tx.get("fee", 0) or 0)
    except Exception:
        pass
    sz = tx.get("size")
    if sz is None:
        # Fallback: estimate body size from the canonical JSON encoding.
        try:
            sz = len(json.dumps(tx, separators=(",", ":")).encode("utf-8"))
        except Exception:
            sz = 0
    try:
        sz = int(sz)
        if sz > 0:
            size_sum += sz
            size_observed += 1
    except Exception:
        pass

avg_size = (size_sum // size_observed) if size_observed > 0 else 0
pressure_pct = (count * 100.0 / bound) if bound > 0 else 0.0
top_senders = by_sender.most_common(10)

anomalies = []
# pressure_warning fires at >= PRESSURE_WARN_PCT% of bound.
if bound > 0 and (count * 100) >= (pressure_warn * bound):
    anomalies.append(f"pressure_warning:{count}/{bound}")
# sender_dominance fires when any single sender holds > SENDER_DOMINANCE_PCT%
# of pending. Empty mempool can't be dominated.
if count > 0 and top_senders:
    dom_from, dom_count = top_senders[0]
    if (dom_count * 100) > (sender_dom * count):
        anomalies.append(f"sender_dominance:{dom_from}:{dom_count}/{count}")

# Emit ONE tab-separated header line plus repeated lines for the maps.
# Format chosen to be unambiguously parseable from shell:
#   SUM\t<count>\t<bound>\t<pressure_pct_float>\t<total_fee>\t<avg_size>
#   TYPE\t<type>\t<count>
#   SENDER\t<from>\t<count>
#   ANOMALY\t<flag>
# Sorting: TYPE rows in desc count, then asc name; SENDER rows preserve
# Counter.most_common order (desc count, insertion order for ties).
print(f"SUM\t{count}\t{bound}\t{pressure_pct:.1f}\t{total_fee}\t{avg_size}")
for ty, n in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0])):
    print(f"TYPE\t{ty}\t{n}")
for s, n in top_senders:
    print(f"SENDER\t{s}\t{n}")
for a in anomalies:
    print(f"ANOMALY\t{a}")
PYEOF
  AGG=$("$PY" "$TMP_PY" "$TMP_JSON" "$MEMPOOL_MAX_TXS_DEFAULT" "$PRESSURE_WARN_PCT" "$SENDER_DOMINANCE_PCT")
else
  # No python: fall back to a count-only summary parsed via jq or grep.
  if [ "$HAVE_JQ" = "1" ]; then
    COUNT=$(printf '%s' "$MEMPOOL_OUT" | jq -r '.count // (.pending | length // 0)')
    BOUND=$(printf '%s' "$MEMPOOL_OUT" | jq -r '.bound // empty')
  else
    COUNT=$(printf '%s' "$MEMPOOL_OUT" | grep -o '"count":[0-9]*' | head -1 | sed 's/.*://')
    [ -z "$COUNT" ] && COUNT=0
    BOUND=$(printf '%s' "$MEMPOOL_OUT" | grep -o '"bound":[0-9]*' | head -1 | sed 's/.*://')
  fi
  case "$COUNT" in *[!0-9]*|"") COUNT=0 ;; esac
  case "$BOUND" in *[!0-9]*|"") BOUND="$MEMPOOL_MAX_TXS_DEFAULT" ;; esac
  PCT_NUM=$(( COUNT * 1000 / BOUND ))   # tenths of a percent, integer math
  PCT_INT=$(( PCT_NUM / 10 ))
  PCT_TEN=$(( PCT_NUM % 10 ))
  AGG=$(printf 'SUM\t%s\t%s\t%s.%s\t0\t0\n' "$COUNT" "$BOUND" "$PCT_INT" "$PCT_TEN")
  if [ "$BOUND" -gt 0 ] && [ $((COUNT * 100)) -ge $((PRESSURE_WARN_PCT * BOUND)) ]; then
    AGG="$AGG"$'\n'"ANOMALY"$'\t'"pressure_warning:$COUNT/$BOUND"
  fi
fi

# ── Step 3: split AGG into shell-side variables/files ────────────────────────
TMP_TYPE=$(mktemp)
TMP_SEND=$(mktemp)
TMP_ANOM=$(mktemp)
trap 'rm -f "$TMP_TYPE" "$TMP_SEND" "$TMP_ANOM" "${TMP_PY:-}" "${TMP_JSON:-}"' EXIT

COUNT=0; BOUND=0; PRESSURE=0.0; TOTAL_FEE=0; AVG_SIZE=0
PARSE_ERR=""

# Route TYPE / SENDER / ANOMALY rows to temp files. SUM/PARSE_ERROR rows are
# pulled out with a second awk pass below (avoids the bash `read -r KIND A B C`
# field-clobber problem when SUM has 6 columns but other rows have 3).
while IFS=$'\t' read -r KIND A B; do
  case "$KIND" in
    TYPE)        printf '%s\t%s\n' "$A" "$B" >>"$TMP_TYPE" ;;
    SENDER)      printf '%s\t%s\n' "$A" "$B" >>"$TMP_SEND" ;;
    ANOMALY)     printf '%s\n'     "$A"      >>"$TMP_ANOM" ;;
    PARSE_ERROR) PARSE_ERR="$A" ;;
  esac
done <<EOF
$AGG
EOF

# Extract the SUM row's 6 fields via awk (where field count is known).
SUM_LINE=$(printf '%s\n' "$AGG" | awk -F'\t' '$1=="SUM"{print; exit}')
if [ -n "$SUM_LINE" ]; then
  COUNT=$(printf    '%s' "$SUM_LINE" | awk -F'\t' '{print $2}')
  BOUND=$(printf    '%s' "$SUM_LINE" | awk -F'\t' '{print $3}')
  PRESSURE=$(printf '%s' "$SUM_LINE" | awk -F'\t' '{print $4}')
  TOTAL_FEE=$(printf '%s' "$SUM_LINE" | awk -F'\t' '{print $5}')
  AVG_SIZE=$(printf '%s' "$SUM_LINE" | awk -F'\t' '{print $6}')
fi

if [ -n "$PARSE_ERR" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"error":"mempool_rpc_parse_error","rpc_port":%s,"detail":"%s"}\n' "$PORT" "$PARSE_ERR"
  else
    echo "operator_mempool_diagnostic: malformed mempool RPC response: $PARSE_ERR" >&2
  fi
  exit 1
fi

ANOMALY_COUNT=0
[ -s "$TMP_ANOM" ] && ANOMALY_COUNT=$(wc -l <"$TMP_ANOM" | tr -d ' ')

# ── Step 4: emit output ──────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Build by_type object.
  TYPE_JSON=$(awk -F'\t' '
    BEGIN { printf "{"; first=1 }
    { if(!first) printf ","; first=0; gsub(/"/,"\\\"",$1); printf "\"%s\":%s",$1,$2 }
    END   { printf "}" }
  ' "$TMP_TYPE")
  [ -z "$TYPE_JSON" ] && TYPE_JSON="{}"

  # Build top_senders array.
  SEND_JSON=$(awk -F'\t' '
    BEGIN { printf "["; first=1 }
    { if(!first) printf ","; first=0; gsub(/"/,"\\\"",$1); printf "{\"from\":\"%s\",\"count\":%s}",$1,$2 }
    END   { printf "]" }
  ' "$TMP_SEND")
  [ -z "$SEND_JSON" ] && SEND_JSON="[]"

  # Build anomalies array.
  ANOM_JSON=$(awk -F'\t' '
    BEGIN { printf "["; first=1 }
    { if(!first) printf ","; first=0; gsub(/"/,"\\\"",$0); printf "\"%s\"",$0 }
    END   { printf "]" }
  ' "$TMP_ANOM")
  [ -z "$ANOM_JSON" ] && ANOM_JSON="[]"

  printf '{"pending":%s,"bound":%s,"pressure_pct":%s,"total_fee":%s,"avg_size":%s,"by_type":%s,"top_senders":%s,"anomalies":%s,"rpc_port":%s}\n' \
    "${COUNT:-0}" "${BOUND:-0}" "${PRESSURE:-0.0}" "${TOTAL_FEE:-0}" "${AVG_SIZE:-0}" \
    "$TYPE_JSON" "$SEND_JSON" "$ANOM_JSON" "$PORT"
else
  # Human-readable output.
  echo "=== Mempool diagnostic (port $PORT) ==="
  if [ "$BOUND" -gt 0 ] 2>/dev/null; then
    echo "Pending: $COUNT / $BOUND ($PRESSURE% of S-008 bound)"
  else
    echo "Pending: $COUNT (bound unknown)"
  fi
  echo "Total fee value: ${TOTAL_FEE:-0}"
  if [ "${AVG_SIZE:-0}" -gt 0 ] 2>/dev/null; then
    echo "Avg tx size:    $AVG_SIZE bytes"
  fi

  if [ "$ANOM_ONLY" = "1" ]; then
    :  # skip the by_type / top_senders tables in anomaly-only mode
  else
    if [ -s "$TMP_TYPE" ]; then
      echo "By type:"
      awk -F'\t' -v c="${COUNT:-0}" '{
        pct = (c > 0) ? ($2 * 100.0 / c) : 0.0;
        printf "  %-14s %6d (%5.1f%%)\n", $1 ":", $2, pct
      }' "$TMP_TYPE"
    fi
    if [ -s "$TMP_SEND" ]; then
      echo "Top senders:"
      awk -F'\t' '{ printf "  %-24s %6d\n", $1 ":", $2 }' "$TMP_SEND"
    fi
  fi

  echo
  if [ "$ANOMALY_COUNT" = "0" ]; then
    echo "[OK] Mempool pressure normal"
  else
    while IFS= read -r FLAG; do
      echo "[WARN] $FLAG"
    done <"$TMP_ANOM"
  fi
fi

# ── Step 5: exit code policy ─────────────────────────────────────────────────
# Mirrors operator_stake_audit.sh: exit 2 fires only with --anomalies-only.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOMALY_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
