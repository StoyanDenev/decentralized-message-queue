#!/usr/bin/env bash
# operator_anon_address_usage.sh — Audit anon-address usage patterns
# across a block window on a running determ daemon. Walks the window via
# `determ block-info <h> --json` and identifies anon addresses (per the
# S-028 predicate: literally "0x" + 64 lowercase hex chars; we match the
# C++ inline `is_anon_address` semantics with the post-S-028 case
# tolerance — see include/determ/types.hpp) among:
#   - tx.from / tx.to             across all transactions
#   - inbound_receipt.to          credit-side of cross-shard receipts
#
# Reports:
#   - Total transactions involving at least one anon participant
#   - Distinct anon addresses (by from-side, to-side, union total)
#   - Direction split: anon → anon, anon → domain, domain → anon
#   - Top-20 most-active anon addresses (combined send + receive count)
#   - Avg transferred amount per anon-involving TRANSFER (type==0)
#   - Optional shard routing distribution for sampled anon addresses
#     when `--genesis <file>` is supplied (uses `determ where-is`).
#
# RPC-shape notes:
#   - The block JSON shape encodes tx.type as a numeric int per
#     `Transaction::to_json` (src/chain/block.cpp). TRANSFER == 0.
#   - `inbound_receipts[]` is a top-level Block field per Block::to_json;
#     each entry exposes {from, to, amount, src_shard, dst_shard, …}.
#   - "Anon address" is defined exactly as `is_anon_address` in C++:
#     length 66, starts with "0x", remainder is hex. Canonical form is
#     lowercase (S-028); we accept either case at parse time but key all
#     aggregations by the lowercased canonical form so an operator never
#     sees the same key in two cases.
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - concentration_single_anon   single anon address > 30% of all
#                                 anon-involving txs (Sybil / specific-
#                                 user-pattern signal). Exit 2.
#   - high_anon_to_anon_ratio     anon → anon transfers > 80% of all
#                                 anon-involving txs (deviation from
#                                 typical domain-name-based payment
#                                 pattern; could indicate mixer-style
#                                 traffic). Exit 2.
#   - mass_anon_creation_spike    any single block contained > 50
#                                 distinct anon addresses (potential
#                                 mass-creation / Sybil onboarding).
#                                 Exit 2.
#
# Usage:
#   tools/operator_anon_address_usage.sh [--rpc-port N] [--json]
#                                        [--from H] [--to H]
#                                        [--anomalies-only]
#                                        [--genesis <file>]
#                                        [--shard-sample N]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of audit window (inclusive; default: max(0, tip-1000))
#   --to H              End of audit window   (inclusive; default: tip)
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   --genesis <file>    Path to genesis.json — enables shard routing
#                       distribution for a sample of anon addresses
#                       (parses initial_shard_count + shard_address_salt
#                       the same way operator_shard_diagnostic.sh does).
#   --shard-sample N    Cap on how many distinct anon addresses to route
#                       via `determ where-is` (default: 50; ignored
#                       unless --genesis supplied). Larger N raises
#                       fork/exec overhead linearly.
#   -h, --help          Show this help
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_anon_address_usage.sh [--rpc-port N] [--json]
                                      [--from H] [--to H]
                                      [--anomalies-only]
                                      [--genesis <file>]
                                      [--shard-sample N]

Audit anon-address usage patterns across a block window. Walks the
window via block-info, identifies anon addresses (S-028 predicate:
"0x" + 64 hex chars; case-tolerant input, lowercase canonical
aggregation key) among tx.from / tx.to / inbound_receipt.to, and
reports aggregate involvement / direction split / top senders +
receivers / avg amount, plus optional shard routing distribution.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, tip-1000))
  --to H              End of audit window   (default: tip)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  --genesis <file>    Enable shard routing for sampled anon addresses
                      (reads initial_shard_count + shard_address_salt
                      from the supplied genesis.json)
  --shard-sample N    Distinct anon addresses to route (default: 50;
                      requires --genesis)
  -h, --help          Show this help

Anomaly flags:
  concentration_single_anon   single anon address > 30% of anon txs
  high_anon_to_anon_ratio     anon→anon > 80% of anon-involving txs
  mass_anon_creation_spike    any block had > 50 distinct anon addrs

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
GENESIS_PATH=""
SHARD_SAMPLE=50
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";        shift 2 ;;
    --json)            JSON_OUT=1;           shift ;;
    --from)            FROM_H="${2:-}";      shift 2 ;;
    --to)              TO_H="${2:-}";        shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;          shift ;;
    --genesis)         GENESIS_PATH="${2:-}";shift 2 ;;
    --shard-sample)    SHARD_SAMPLE="${2:-}";shift 2 ;;
    *) echo "operator_anon_address_usage: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_anon_address_usage: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_anon_address_usage: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$SHARD_SAMPLE" in *[!0-9]*|"")
  echo "operator_anon_address_usage: --shard-sample must be a positive integer (got '$SHARD_SAMPLE')" >&2
  exit 1 ;;
esac
if [ -n "$GENESIS_PATH" ] && [ ! -r "$GENESIS_PATH" ]; then
  echo "operator_anon_address_usage: cannot read --genesis '$GENESIS_PATH'" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_anon_address_usage: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_anon_address_usage: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip.
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_anon_address_usage: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: optional genesis extract for shard routing ───────────────────────
# Mirrors operator_shard_diagnostic.sh's two-step extract: verify-genesis
# for shard_count, raw-file read for shard_address_salt (salt isn't echoed
# by verify-genesis by design). Skipped silently when --genesis absent.
SHARD_COUNT=0
SALT_HEX=""
if [ -n "$GENESIS_PATH" ]; then
  GV_OUT=$("$DETERM" verify-genesis --in "$GENESIS_PATH" --json 2>/dev/null) || {
    echo "operator_anon_address_usage: \`determ verify-genesis\` failed for $GENESIS_PATH" >&2
    exit 1
  }
  if [ "$HAVE_JQ" = "1" ]; then
    GV_STATUS=$(printf '%s' "$GV_OUT" | jq -r '.status // ""')
    if [ "$GV_STATUS" != "ok" ]; then
      GV_MSG=$(printf '%s' "$GV_OUT" | jq -r '.message // "(unknown)"')
      echo "operator_anon_address_usage: genesis validation failed: $GV_MSG" >&2
      exit 1
    fi
    SHARD_COUNT=$(printf '%s' "$GV_OUT" | jq -r '.initial_shard_count // 0')
    SALT_HEX=$(jq -r '.shard_address_salt // ""' "$GENESIS_PATH" 2>/dev/null)
  else
    GV_STATUS=$(printf '%s' "$GV_OUT" | grep -o '"status":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
    if [ "$GV_STATUS" != "ok" ]; then
      echo "operator_anon_address_usage: genesis validation failed (status='$GV_STATUS')" >&2
      exit 1
    fi
    SHARD_COUNT=$(printf '%s' "$GV_OUT" | grep -o '"initial_shard_count":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
    SALT_HEX=$(grep -oE '"shard_address_salt"[[:space:]]*:[[:space:]]*"[^"]*"' "$GENESIS_PATH" | head -1 | sed 's/.*"\([0-9a-fA-F]*\)"[[:space:]]*$/\1/')
  fi
  case "$SHARD_COUNT" in *[!0-9]*|"")
    echo "operator_anon_address_usage: cannot parse initial_shard_count (got '$SHARD_COUNT')" >&2
    exit 1 ;;
  esac
  if [ -z "$SALT_HEX" ] || [ "$SALT_HEX" = "null" ]; then
    SALT_HEX="0000000000000000000000000000000000000000000000000000000000000000"
  fi
  case "$SALT_HEX" in
    *[!0-9a-fA-F]*) echo "operator_anon_address_usage: salt non-hex ('$SALT_HEX')" >&2; exit 1 ;;
  esac
  if [ "${#SALT_HEX}" != "64" ]; then
    echo "operator_anon_address_usage: shard_address_salt must be 64 hex chars (got ${#SALT_HEX})" >&2
    exit 1
  fi
fi

# ── Step 3: walk the window in Python ────────────────────────────────────────
# Python driver handles JSON parse, anon-address detection, direction
# classification, per-address counters, and per-block distinct-anon
# spike tracking.
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_anon_address_usage: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_OUT" <<'PY'
import json, subprocess, sys, re
from collections import defaultdict, Counter

determ, port, from_h, to_h, out_path = sys.argv[1:6]
from_h = int(from_h); to_h = int(to_h)

# S-028 anon-address predicate: matches include/determ/types.hpp
# is_anon_address byte-for-byte (length 66, "0x" prefix, remainder hex
# in either case). The canonical lowercase form is what we key by so
# the same pubkey never splits across two case spellings in aggregates.
ANON_RE = re.compile(r'^0x[0-9a-fA-F]{64}$')

def is_anon(s):
    return isinstance(s, str) and bool(ANON_RE.match(s))

def normalize(s):
    # Canonical lowercase; "0x" prefix preserved. Domain names pass
    # through unchanged so the helper is safe to call on any string.
    if not is_anon(s):
        return s
    return "0x" + s[2:].lower()

def tx_type_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return -1
    return -1

# Aggregators
total_tx_count       = 0
anon_tx_count        = 0
anon_to_anon         = 0
anon_to_domain       = 0
domain_to_anon       = 0
anon_transfer_amount_sum = 0
anon_transfer_count      = 0
sender_counter       = Counter()    # anon-from address -> tx count
receiver_counter     = Counter()    # anon-to address (txs OR receipts) -> count
combined_counter     = Counter()    # send + receive activity per anon
distinct_anon        = set()
distinct_anon_from   = set()
distinct_anon_to     = set()
spike_block          = -1
spike_count          = 0
per_block_max        = 0

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_anon_address_usage: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_anon_address_usage: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_anon_address_usage: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    block_distinct_anon = set()

    # Walk transactions[]. TRANSFER (type 0) is the only tx type where
    # tx.from / tx.to can legally be an anon address — anon accounts
    # cannot REGISTER, STAKE, etc. (anon addresses fail the V2 gate for
    # those types). We still scan ALL tx types for from/to anon shape:
    # an off-protocol anon appearance in a non-TRANSFER tx would itself
    # be an anomaly worth surfacing (and an apply-time validator should
    # reject it; defense-in-depth).
    txs = blk.get("transactions") or []
    if isinstance(txs, list):
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            total_tx_count += 1
            t      = tx_type_int(tx.get("type"))
            sender = tx.get("from", "") if isinstance(tx.get("from", ""), str) else ""
            recv   = tx.get("to", "")   if isinstance(tx.get("to", ""),   str) else ""
            amount = int(tx.get("amount", 0) or 0)

            sender_anon = is_anon(sender)
            recv_anon   = is_anon(recv)
            sn          = normalize(sender) if sender_anon else sender
            rn          = normalize(recv)   if recv_anon   else recv

            if not (sender_anon or recv_anon):
                continue

            anon_tx_count += 1

            # Direction split. We count "anon → anon" when BOTH endpoints
            # are anon, "anon → domain" when only sender is anon, and
            # "domain → anon" when only receiver is anon.
            if sender_anon and recv_anon:
                anon_to_anon += 1
            elif sender_anon and not recv_anon:
                anon_to_domain += 1
            else:
                domain_to_anon += 1

            if sender_anon:
                sender_counter[sn] += 1
                combined_counter[sn] += 1
                distinct_anon.add(sn)
                distinct_anon_from.add(sn)
                block_distinct_anon.add(sn)
            if recv_anon:
                receiver_counter[rn] += 1
                combined_counter[rn] += 1
                distinct_anon.add(rn)
                distinct_anon_to.add(rn)
                block_distinct_anon.add(rn)

            # Average-amount metric scoped to TRANSFER (type 0) so we
            # exclude fee-only / no-value tx types that would dilute
            # the operator-facing "average value per anon transfer".
            if t == 0 and (sender_anon or recv_anon):
                anon_transfer_amount_sum += amount
                anon_transfer_count      += 1

    # Inbound cross-shard receipts also credit anon addresses (the
    # apply-time receipt path goes through accounts_[r.to] with auto-
    # creation, same as a TRANSFER credit). Count receipt.to as a
    # "receive" event for any anon target. We don't classify direction
    # here because the receipt's `from` lives on the source shard's
    # block, not this one — domain-vs-anon for the source side would
    # require cross-shard correlation we don't have locally.
    ibrs = blk.get("inbound_receipts") or []
    if isinstance(ibrs, list):
        for r2 in ibrs:
            if not isinstance(r2, dict):
                continue
            recv = r2.get("to", "") if isinstance(r2.get("to", ""), str) else ""
            if is_anon(recv):
                rn = normalize(recv)
                receiver_counter[rn] += 1
                combined_counter[rn] += 1
                distinct_anon.add(rn)
                distinct_anon_to.add(rn)
                block_distinct_anon.add(rn)
                # Receipts also count as "anon-involving txs" for the
                # operator-facing total (matches the spec which
                # explicitly lists inbound_receipt.to as a probe site).
                anon_tx_count += 1
                # Receipts contribute amount info too — treat as a
                # cross-shard TRANSFER for average-amount purposes
                # since the source side's intent is a transfer.
                amount = int(r2.get("amount", 0) or 0)
                anon_transfer_amount_sum += amount
                anon_transfer_count      += 1
                # The receipt's outbound counterpart was already counted
                # in total_tx_count when it executed on the source
                # shard — but we observe it locally only here, so
                # bump total_tx_count too to keep the ratio meaningful
                # (otherwise an inbound-heavy node would show >100%
                # anon involvement).
                total_tx_count += 1

    if len(block_distinct_anon) > per_block_max:
        per_block_max = len(block_distinct_anon)
    if len(block_distinct_anon) > 50 and spike_block < 0:
        spike_block = h
        spike_count = len(block_distinct_anon)

# Top-20 senders, receivers, combined. Tie-break: count desc, then
# address asc for determinism.
def topn(counter, n=20):
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]

top_senders   = topn(sender_counter, 20)
top_receivers = topn(receiver_counter, 20)
top_combined  = topn(combined_counter, 20)

# Average anon-transfer amount (integer; basis-point precision not
# meaningful for ledger amounts which are already integers).
avg_amount = (anon_transfer_amount_sum // anon_transfer_count) if anon_transfer_count > 0 else 0

# Anomaly classification.
anomalies = []

# concentration_single_anon: any single address > 30% of anon txs.
# "Activity" for this gate is the combined send+receive count, which
# matches the spec's "top anon senders" framing while also catching
# heavy-receiver patterns (mixer-output, faucet, etc).
top_single_pct_bps = 0
top_single_name    = ""
if anon_tx_count > 0 and top_combined:
    top_single_name    = top_combined[0][0]
    top_single_pct_bps = top_combined[0][1] * 10000 // anon_tx_count
    if top_single_pct_bps > 3000:
        anomalies.append("concentration_single_anon")

# high_anon_to_anon_ratio: anon → anon > 80% of anon-involving txs.
a2a_pct_bps = 0
if anon_tx_count > 0:
    a2a_pct_bps = anon_to_anon * 10000 // anon_tx_count
    if a2a_pct_bps > 8000:
        anomalies.append("high_anon_to_anon_ratio")

# mass_anon_creation_spike: any block had > 50 distinct anon addresses.
if spike_block >= 0:
    anomalies.append("mass_anon_creation_spike")

# Sample distinct anon addresses for downstream shard routing
# (capped — `where-is` is a binary fork-exec per call, so we keep the
# default small). Sample is deterministic: sorted-asc order.
sampled_anon = sorted(distinct_anon)

result = {
    "anon_tx_count":        anon_tx_count,
    "total_tx_count":       total_tx_count,
    "anon_to_anon":         anon_to_anon,
    "anon_to_domain":       anon_to_domain,
    "domain_to_anon":       domain_to_anon,
    "distinct_anon":        len(distinct_anon),
    "distinct_anon_from":   len(distinct_anon_from),
    "distinct_anon_to":     len(distinct_anon_to),
    "anon_transfer_count":  anon_transfer_count,
    "anon_transfer_amount_sum": anon_transfer_amount_sum,
    "avg_amount":           avg_amount,
    "top_senders":          [{"address": a, "count": n} for a, n in top_senders],
    "top_receivers":        [{"address": a, "count": n} for a, n in top_receivers],
    "top_combined":         [{"address": a, "count": n} for a, n in top_combined],
    "per_block_max_distinct": per_block_max,
    "spike_block":          spike_block,
    "spike_count":          spike_count,
    "top_single_name":      top_single_name,
    "top_single_pct_bps":   top_single_pct_bps,
    "a2a_pct_bps":          a2a_pct_bps,
    "anomalies":            anomalies,
    "sampled_anon":         sampled_anon,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_anon_address_usage: block-walk failed" >&2
  exit 1
fi

# ── Step 4: optional shard routing for sampled anon addresses ────────────────
# Pure-local `where-is` per address. Bounded by --shard-sample.
SHARD_DIST_JSON="null"
if [ -n "$GENESIS_PATH" ] && [ "$SHARD_COUNT" -gt 0 ]; then
  TMP_DIST=$(mktemp 2>/dev/null) || {
    echo "operator_anon_address_usage: cannot create temp file" >&2; exit 1;
  }
  trap 'rm -f "$TMP_OUT" "$TMP_DIST" 2>/dev/null' EXIT

  # Extract the sampled-anon list from the python result, head -N, route each.
  ROUTED=0
  if [ "$HAVE_JQ" = "1" ]; then
    SAMPLED_LIST=$(jq -r '.sampled_anon[]' "$TMP_OUT" 2>/dev/null | head -n "$SHARD_SAMPLE")
  else
    SAMPLED_LIST=$(python - "$TMP_OUT" "$SHARD_SAMPLE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
n = int(sys.argv[2])
for a in r.get("sampled_anon", [])[:n]:
    print(a)
PY
)
  fi

  if [ -n "$SAMPLED_LIST" ]; then
    while IFS= read -r ADDR; do
      [ -z "$ADDR" ] && continue
      WI_OUT=$("$DETERM" where-is "$ADDR" --shard-count "$SHARD_COUNT" --salt-hex "$SALT_HEX" --json 2>/dev/null) || {
        echo "operator_anon_address_usage: \`determ where-is\` failed for '$ADDR'" >&2
        exit 1
      }
      if [ "$HAVE_JQ" = "1" ]; then
        SH=$(printf '%s' "$WI_OUT" | jq -r '.shard // empty')
      else
        SH=$(printf '%s' "$WI_OUT" | grep -o '"shard":[0-9]*' | head -1 | sed 's/.*: *//')
      fi
      case "$SH" in *[!0-9]*|"")
        echo "operator_anon_address_usage: cannot parse shard from where-is (got '$SH')" >&2
        exit 1 ;;
      esac
      printf '%s\n' "$SH" >>"$TMP_DIST"
      ROUTED=$(( ROUTED + 1 ))
    done <<EOF_LIST
$SAMPLED_LIST
EOF_LIST
  fi

  # Build a dense distribution covering all shards (including zero-count).
  SHARD_DIST_JSON=$(python - "$TMP_DIST" "$SHARD_COUNT" "$ROUTED" <<'PY'
import json, sys
from collections import Counter
path, sc, routed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
counts = Counter()
try:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: counts[int(line)] += 1
            except ValueError: pass
except FileNotFoundError:
    pass
dist = [{"shard": s, "count": counts.get(s, 0)} for s in range(sc)]
print(json.dumps({"sample_size": routed, "shard_count": sc, "distribution": dist}))
PY
)
fi

# ── Step 5: render envelope (JSON or human table) ────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$SHARD_DIST_JSON" "$GENESIS_PATH" <<'PY'
import json, sys

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
out_path      = sys.argv[3]
port          = int(sys.argv[4])
from_h        = int(sys.argv[5])
to_h          = int(sys.argv[6])
win_blocks    = int(sys.argv[7])
shard_dist_s  = sys.argv[8]
genesis_path  = sys.argv[9]

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

try:
    shard_dist = json.loads(shard_dist_s) if shard_dist_s != "null" else None
except Exception:
    shard_dist = None

anon_tx    = r["anon_tx_count"]
total_tx   = r["total_tx_count"]
anomalies  = r["anomalies"]
anom_count = len(anomalies)

def render_pct_bps(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def ratio_bps(n, d):
    if d <= 0: return 0
    return n * 10000 // d

def short(addr):
    # First 8 chars after 0x + ellipsis; matches the human-table style
    # in operator_shard_diagnostic.sh.
    if isinstance(addr, str) and addr.startswith("0x") and len(addr) >= 10:
        return addr[:10] + "..."
    return addr

if json_out:
    envelope = {
        "window": {"from": from_h, "to": to_h, "blocks": win_blocks},
        "anon_tx_count":   anon_tx,
        "total_tx_count":  total_tx,
        "anon_ratio":      (anon_tx / total_tx) if total_tx > 0 else None,
        "distinct_anon":   r["distinct_anon"],
        "distinct_anon_from": r["distinct_anon_from"],
        "distinct_anon_to":   r["distinct_anon_to"],
        "by_direction": {
            "anon_to_anon":   r["anon_to_anon"],
            "anon_to_domain": r["anon_to_domain"],
            "domain_to_anon": r["domain_to_anon"],
        },
        "top_senders":     r["top_senders"],
        "top_receivers":   r["top_receivers"],
        "top_combined":    r["top_combined"],
        "anon_transfer_count":      r["anon_transfer_count"],
        "anon_transfer_amount_sum": r["anon_transfer_amount_sum"],
        "avg_amount":      r["avg_amount"],
        "per_block_max_distinct": r["per_block_max_distinct"],
        "spike_block":     r["spike_block"] if r["spike_block"] >= 0 else None,
        "spike_count":     r["spike_count"],
        "top_single_name":    r["top_single_name"],
        "top_single_pct_bps": r["top_single_pct_bps"],
        "a2a_pct_bps":     r["a2a_pct_bps"],
        "anomalies":       anomalies,
        "shard_distribution": shard_dist,
        "genesis_supplied":   bool(genesis_path),
        "rpc_port":        port,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_anon_address_usage: no anomalies (port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

ratio_disp = "-"
if total_tx > 0:
    ratio_disp = render_pct_bps(ratio_bps(anon_tx, total_tx))

print(f"=== Anon-address usage (port {port}, window [{from_h}..{to_h}], {win_blocks} blocks) ===")
print(f"Anon-involving transactions: {anon_tx} / {total_tx} total ({ratio_disp})")
print(f"Distinct anon addresses: {r['distinct_anon']} ({r['distinct_anon_from']} senders, {r['distinct_anon_to']} recipients)")

if anon_tx > 0 and not anom_only:
    print("By direction:")
    print(f"  anon -> anon:   {r['anon_to_anon']} ({render_pct_bps(ratio_bps(r['anon_to_anon'],   anon_tx))})")
    print(f"  anon -> domain: {r['anon_to_domain']} ({render_pct_bps(ratio_bps(r['anon_to_domain'], anon_tx))})")
    print(f"  domain -> anon: {r['domain_to_anon']} ({render_pct_bps(ratio_bps(r['domain_to_anon'], anon_tx))})")

    if r["top_senders"]:
        print("Top anon senders:")
        for s in r["top_senders"]:
            print(f"  {short(s['address'])}:  {s['count']} transfers")
    if r["top_receivers"]:
        print("Top anon receivers:")
        for s in r["top_receivers"]:
            print(f"  {short(s['address'])}:  {s['count']} credits")

    if r["anon_transfer_count"] > 0:
        print(f"Avg amount per anon transfer: {r['avg_amount']}")
    else:
        print("Avg amount per anon transfer: -  (no anon-involving TRANSFERs in window)")

    if shard_dist is not None and shard_dist.get("sample_size", 0) > 0:
        print(f"Shard routing (sampled {shard_dist['sample_size']} distinct anon addrs):")
        sample_size = shard_dist["sample_size"]
        for d in shard_dist["distribution"]:
            pct_b = ratio_bps(d["count"], sample_size)
            print(f"  shard {d['shard']}:  {d['count']} ({render_pct_bps(pct_b)})")
    elif genesis_path and shard_dist is not None and shard_dist.get("sample_size", 0) == 0:
        print("Shard routing: (no distinct anon addresses observed; nothing to route)")

print()
if anom_count == 0:
    print("[OK] No concentration anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "concentration_single_anon" in anomalies:
        print(f"  concentration_single_anon: '{short(r['top_single_name'])}' = "
              f"{render_pct_bps(r['top_single_pct_bps'])} of anon-involving txs (> 30% threshold)")
    if "high_anon_to_anon_ratio" in anomalies:
        print(f"  high_anon_to_anon_ratio: anon->anon = "
              f"{render_pct_bps(r['a2a_pct_bps'])} of anon-involving txs (> 80% threshold)")
    if "mass_anon_creation_spike" in anomalies:
        print(f"  mass_anon_creation_spike: block {r['spike_block']} had "
              f"{r['spike_count']} distinct anon addresses (> 50 threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_anon_address_usage: rendering failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ──────────────────────────────────────────────────
# Pull anomaly count from the python result-file so we honor the
# --anomalies-only gate. Pattern mirrors operator_dapp_call_audit.sh.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_anon_address_usage: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_DIST" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(str(len(r.get("anomalies", []))))
PY
ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
