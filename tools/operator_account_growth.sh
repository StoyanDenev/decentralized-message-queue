#!/usr/bin/env bash
# operator_account_growth.sh — Track account-set growth over a block
# window. Walks the chain via `determ block-info <h> --json`, collects
# every domain that appears as a first-time reference through any of
# the six I-4 auto-creation channels (per docs/proofs/AccountStateInvariants.md),
# and reports growth metrics: total delta, per-block deltas, peak block,
# and a best-effort by-source-type breakdown.
#
# Read-only RPC; safe against a running daemon.
#
# RPC-shape note: the chain does not expose an "accounts as-of-block-H"
# RPC. We therefore approximate as follows:
#   - end_count   = `snapshot create` (live head) → `snapshot stats --json`
#                   exposes `accounts` (count of distinct registered domains
#                   at head). Taken ONCE at audit end.
#   - new_in_win  = set of domains first observed inside [FROM,TO] via the
#                   I-4 channels listed below. Deduplicated; a domain
#                   appearing on multiple channels in the window counts
#                   once for the size metric, but every channel hit is
#                   credited under by_source (first-seen channel wins for
#                   the categorical attribution to avoid double-counting).
#   - start_count = end_count - len(new_in_win). This is the approximation:
#                   it assumes no account that existed at FROM disappeared
#                   between FROM and the snapshot. In v1 the accounts_ map
#                   is monotone (entries only added, never removed — see
#                   AccountStateInvariants.md §I-4 + T-A4), so the
#                   assumption holds for any practical operator window.
#
# I-4 channels observed (canonical reference: docs/proofs/AccountStateInvariants.md):
#   1. TRANSFER credit-on-receipt        — tx.to    when tx.type == 0
#   2. Inbound cross-shard receipt       — r.to     for r in inbound_receipts
#   3. REGISTER                          — tx.from  when tx.type == 1
#   4. DEREGISTER                        — tx.from  when tx.type == 2
#   5. Per-creator subsidy distribution  — c        for c in creators
#   6. DAPP_CALL credit                  — tx.to    when tx.type == 10
#
# DAPP_REGISTER (type 9) auto-creates the dapp-owner account via the same
# sender-reference path as REGISTER; tracked as REGISTER bucket for
# operator-readability.
#
# Usage:
#   tools/operator_account_growth.sh [--rpc-port N] [--json]
#                                    [--from H] [--to H]
#                                    [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of audit window (inclusive; default: max(0, tip-1000))
#   --to H              End of audit window   (inclusive; default: tip)
#   --anomalies-only    Suppress healthy output; only print flagged anomalies.
#                       Exit 2 if any anomaly fires.
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head                (current chain height)
#   - block               (per-block JSON; via `determ block-info <h> --json`)
#   - snapshot            (full state dump → tmp file)
#   - snapshot stats      (fast metadata read from the temp snapshot file)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - mass_creation_spike   single block in window added > 50 new accounts
#                           (potential mass-creation attack signal)
#   - rapid_expansion       account-set grew > 100% over the window
#                           (operator-attention growth; legitimate at
#                           network bootstrap, suspicious mid-life)
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_account_growth.sh [--rpc-port N] [--json]
                                  [--from H] [--to H]
                                  [--anomalies-only]

Track account-set growth over a block window. Walks the chain via
block-info, counts first-time domain references across the six I-4
account-auto-creation channels (TRANSFER credit, REGISTER, DEREGISTER,
inbound receipts, DAPP_CALL credit, per-creator subsidy), and reports
growth metrics + by-source breakdown + peak-spike block.

end_count is sampled once via `snapshot create`/`snapshot stats`. The
v1 accounts_ map is monotone, so start_count = end_count - new_in_win
is exact under the assumption that no entry was removed inside [FROM,
TO] (always true on v1 — see docs/proofs/AccountStateInvariants.md §I-4).

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, tip-1000))
  --to H              End of audit window   (default: tip)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  mass_creation_spike    single block added > 50 new accounts
  rapid_expansion        account-set grew > 100% over the window

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
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";   shift 2 ;;
    --json)            JSON_OUT=1;  shift ;;
    --from)            FROM_H="$2"; shift 2 ;;
    --to)              TO_H="$2";   shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1; shift ;;
    *) echo "operator_account_growth: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_account_growth: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_account_growth: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_account_growth: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_account_growth: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip.
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_account_growth: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi

WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk the window + collect new-domain ledger ──────────────────────
# Python driver: handles JSON parsing + per-block aggregation. Writes:
#   TMP_DOMAINS  — one TSV row per first-seen domain:
#                  <domain>\t<first_seen_block>\t<first_seen_source>
#   TMP_PERBLOCK — one TSV row per block in window with non-zero new accounts:
#                  <block_index>\t<new_count>
#   TMP_META     — one line: <peak_block>\t<peak_count>\t<spike_block>\t<spike_count>
#                  spike_block is the FIRST block whose new_count > 50, or
#                  empty/"-" if none.
TMP_DOMAINS=$(mktemp 2>/dev/null) || {
  echo "operator_account_growth: cannot create temp file" >&2; exit 1;
}
TMP_PERBLOCK=$(mktemp 2>/dev/null) || {
  echo "operator_account_growth: cannot create temp file" >&2; exit 1;
}
TMP_META=$(mktemp 2>/dev/null) || {
  echo "operator_account_growth: cannot create temp file" >&2; exit 1;
}
TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
  echo "operator_account_growth: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_DOMAINS" "$TMP_PERBLOCK" "$TMP_META" "$TMP_SNAP" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" \
        "$TMP_DOMAINS" "$TMP_PERBLOCK" "$TMP_META" <<'PY' || {
  echo "operator_account_growth: block-walk failed" >&2; exit 1;
}
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, dom_path, pb_path, meta_path = sys.argv[1:8]
from_h = int(from_h); to_h = int(to_h)

# tx.type integer → source-bucket label. Per src/chain/block.hpp:
#   0 TRANSFER, 1 REGISTER, 2 DEREGISTER, 3 STAKE, 4 UNSTAKE,
#   5 REGION_CHANGE, 6 PARAM_CHANGE, 7 MERGE_EVENT, 8 COMPOSABLE_BATCH,
#   9 DAPP_REGISTER, 10 DAPP_CALL
def tx_type_int(v):
    if isinstance(v, int): return v
    if isinstance(v, str):
        try: return int(v)
        except ValueError: return -1
    return -1

# seen[domain] = (first_seen_block, first_seen_source). Once set, never
# overwritten — first-wins captures the channel that introduced the
# entry to accounts_, matching I-4 semantics ("first successful apply").
seen = {}
per_block = []   # list of (block_index, new_count_in_this_block)
spike_block = -1
spike_count = 0
peak_block = -1
peak_count = -1

def credit(domain, h, src):
    if not isinstance(domain, str) or not domain:
        return False
    if domain in seen:
        return False
    seen[domain] = (h, src)
    return True

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_account_growth: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_account_growth: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_account_growth: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    new_this_block = 0

    # Channel 5: per-creator subsidy distribution. Creators are already
    # REGISTER'd in steady state, so this is mostly a lookup — but at
    # genesis or just after a creator's REGISTER it may be the *first*
    # accounts_[c] reference seen across the window if FROM started
    # mid-chain.
    creators = blk.get("creators") or []
    if isinstance(creators, list):
        for c in creators:
            if credit(c, h, "subsidy_creator"):
                new_this_block += 1

    # Channels 1, 3, 4, 6: per-tx classification.
    txs = blk.get("transactions") or []
    if isinstance(txs, list):
        for tx in txs:
            if not isinstance(tx, dict): continue
            t = tx_type_int(tx.get("type"))
            sender   = tx.get("from", "") if isinstance(tx.get("from", ""), str) else ""
            receiver = tx.get("to", "")   if isinstance(tx.get("to", ""),   str) else ""
            if t == 0:                          # TRANSFER
                if credit(receiver, h, "transfer_credit"):
                    new_this_block += 1
            elif t == 1 or t == 9:              # REGISTER / DAPP_REGISTER
                if credit(sender, h, "register"):
                    new_this_block += 1
            elif t == 2:                        # DEREGISTER
                if credit(sender, h, "deregister"):
                    new_this_block += 1
            elif t == 10:                       # DAPP_CALL credit
                if credit(receiver, h, "dapp_call_credit"):
                    new_this_block += 1
            # Other tx types (STAKE/UNSTAKE/REGION_CHANGE/PARAM_CHANGE/
            # MERGE_EVENT/COMPOSABLE_BATCH) reference sender via
            # accounts_[sender] (nonce bump) but the sender is already
            # registered (V2 gate), so we don't credit them here.
            # COMPOSABLE_BATCH inner txs aren't decoded — operator
            # impact for that channel is negligible at v1 traffic
            # levels; documented limitation.

    # Channel 2: inbound cross-shard receipts.
    ibrs = blk.get("inbound_receipts") or []
    if isinstance(ibrs, list):
        for r2 in ibrs:
            if not isinstance(r2, dict): continue
            recv = r2.get("to", "") if isinstance(r2.get("to", ""), str) else ""
            if credit(recv, h, "inbound_receipt"):
                new_this_block += 1

    if new_this_block > 0:
        per_block.append((h, new_this_block))
    if new_this_block > peak_count:
        peak_count = new_this_block
        peak_block = h
    if new_this_block > 50 and spike_block < 0:
        spike_block = h
        spike_count = new_this_block

# Write outputs.
with open(dom_path, "w", encoding="utf-8") as f:
    for d, (h, src) in seen.items():
        f.write(f"{d}\t{h}\t{src}\n")

with open(pb_path, "w", encoding="utf-8") as f:
    for h, n in per_block:
        f.write(f"{h}\t{n}\n")

if peak_block < 0:
    # Window contained zero new accounts. Emit sentinel.
    peak_block = from_h
    peak_count = 0
spike_str = str(spike_block) if spike_block >= 0 else "-"
with open(meta_path, "w", encoding="utf-8") as f:
    f.write(f"{peak_block}\t{peak_count}\t{spike_str}\t{spike_count}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_account_growth: block-walk failed" >&2
  exit 1
fi

# Read meta back.
META_LINE=$(head -1 "$TMP_META" 2>/dev/null || echo "0\t0\t-\t0")
PEAK_BLOCK=$(printf '%s' "$META_LINE" | cut -f1)
PEAK_COUNT=$(printf '%s' "$META_LINE" | cut -f2)
SPIKE_BLOCK=$(printf '%s' "$META_LINE" | cut -f3)
SPIKE_COUNT=$(printf '%s' "$META_LINE" | cut -f4)
case "$PEAK_BLOCK"  in *[!0-9]*|"") PEAK_BLOCK=0 ;; esac
case "$PEAK_COUNT"  in *[!0-9]*|"") PEAK_COUNT=0 ;; esac
case "$SPIKE_COUNT" in *[!0-9]*|"") SPIKE_COUNT=0 ;; esac

# Count distinct new accounts + classify by source.
NEW_TOTAL=0
if [ -s "$TMP_DOMAINS" ]; then
  NEW_TOTAL=$(awk 'END {print NR}' "$TMP_DOMAINS")
fi

# By-source aggregation (TSV: source\tcount), sorted by count desc.
BY_TRANSFER=0
BY_REGISTER=0
BY_DEREGISTER=0
BY_INBOUND=0
BY_DAPP_CALL=0
BY_SUBSIDY=0
if [ -s "$TMP_DOMAINS" ]; then
  while IFS=$'\t' read -r D H S; do
    case "$S" in
      transfer_credit)    BY_TRANSFER=$(( BY_TRANSFER + 1 ));;
      register)           BY_REGISTER=$(( BY_REGISTER + 1 ));;
      deregister)         BY_DEREGISTER=$(( BY_DEREGISTER + 1 ));;
      inbound_receipt)    BY_INBOUND=$(( BY_INBOUND + 1 ));;
      dapp_call_credit)   BY_DAPP_CALL=$(( BY_DAPP_CALL + 1 ));;
      subsidy_creator)    BY_SUBSIDY=$(( BY_SUBSIDY + 1 ));;
    esac
  done < "$TMP_DOMAINS"
fi

# ── Step 3: sample end_count via snapshot ────────────────────────────────────
# `determ snapshot create --out file` triggers a snapshot RPC and writes
# the full JSON payload locally. `determ snapshot stats <file> --json`
# then reads `accounts` (count of accounts_ entries at head) without
# the heavy restore-and-verify pipeline.
if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_account_growth: snapshot create failed (port $PORT)" >&2
  exit 1
fi
SNAP_STATS=$("$DETERM" snapshot stats "$TMP_SNAP" --json 2>/dev/null) || {
  echo "operator_account_growth: snapshot stats failed on temp file" >&2
  exit 1
}

# Parse `accounts` count out of stats JSON. jq if available, fallback to
# python; python is already required upstream so always present here.
END_COUNT=$(python - "$SNAP_STATS" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print(""); sys.exit(0)
if not isinstance(d, dict):
    print(""); sys.exit(0)
print(d.get("accounts", ""))
PY
)
case "$END_COUNT" in *[!0-9]*|"")
  echo "operator_account_growth: snapshot stats returned non-numeric accounts ('$END_COUNT')" >&2
  exit 1 ;;
esac

# start_count = end_count - new-domains-in-window. Floor at 0 just in
# case the snapshot raced a block-apply that removed an entry (the
# accounts_ map is monotone in v1, but defense-in-depth).
START_COUNT=$(( END_COUNT - NEW_TOTAL ))
if [ "$START_COUNT" -lt 0 ]; then START_COUNT=0; fi

DELTA=$NEW_TOTAL

# growth_rate in basis points (out of 10000). 0% if start_count == 0
# (degenerate: cannot grow from nothing) — instead render as "∞" / null.
GROWTH_BPS=0
if [ "$START_COUNT" -gt 0 ]; then
  GROWTH_BPS=$(( DELTA * 10000 / START_COUNT ))
fi

# Average new-accounts/block: keep two-decimal precision via basis points
# of new-per-block (NEW_PER_BLOCK_HUNDREDTHS = round(DELTA*100 / WIN_BLOCKS)).
NEW_PER_BLOCK_HUNDREDTHS=0
if [ "$WIN_BLOCKS" -gt 0 ]; then
  NEW_PER_BLOCK_HUNDREDTHS=$(( (DELTA * 100 + WIN_BLOCKS / 2) / WIN_BLOCKS ))
fi

# ── Step 4: assemble anomalies list ──────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
# Spike: >50 new accounts in any single block (mass-creation attack).
if [ "$PEAK_COUNT" -gt 50 ]; then add_anom "mass_creation_spike"; fi
# Rapid expansion: >100% growth over the window. Only fires when
# START_COUNT > 0 (otherwise growth is undefined; pre-genesis bootstrap
# is not an anomaly).
if [ "$START_COUNT" -gt 0 ] && [ "$GROWTH_BPS" -gt 10000 ]; then
  add_anom "rapid_expansion"
fi
ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# Helpers for rendering.
render_pct() {
  local bps="$1"
  local whole=$(( bps / 100 ))
  local frac=$(( (bps % 100) / 10 ))
  printf '%d.%d%%' "$whole" "$frac"
}
render_share() {
  # arg1 = count, arg2 = total; emits "C (PP.P%)" or "C (-)".
  local c="$1" tot="$2"
  if [ "$tot" -le 0 ]; then printf '%s (-)' "$c"; return; fi
  local bps=$(( c * 10000 / tot ))
  printf '%s (%s)' "$c" "$(render_pct "$bps")"
}
render_avg() {
  # hundredths → "0.NN"
  local h="$1"
  local whole=$(( h / 100 ))
  local frac=$(( h % 100 ))
  printf '%d.%02d' "$whole" "$frac"
}

# ── Step 5: emit output ──────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # growth_rate as float string ("0.333"). JSON numbers don't support
  # ±Inf, so emit null when start_count == 0.
  if [ "$START_COUNT" -gt 0 ]; then
    GROWTH_RATE_JSON=$(python - "$GROWTH_BPS" <<'PY'
import sys
print(f"{int(sys.argv[1]) / 10000.0:.4f}")
PY
)
  else
    GROWTH_RATE_JSON="null"
  fi
  AVG_JSON=$(python - "$NEW_PER_BLOCK_HUNDREDTHS" <<'PY'
import sys
print(f"{int(sys.argv[1]) / 100.0:.3f}")
PY
)
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"start_count":%s,"end_count":%s,"delta":%s,' "$START_COUNT" "$END_COUNT" "$DELTA"
  if [ "$GROWTH_RATE_JSON" = "null" ]; then
    printf '"growth_rate":null,'
  else
    printf '"growth_rate":%s,' "$GROWTH_RATE_JSON"
  fi
  printf '"new_per_block_avg":%s,' "$AVG_JSON"
  printf '"peak_block":{"index":%s,"new_count":%s},' "$PEAK_BLOCK" "$PEAK_COUNT"
  printf '"by_source":{'
  printf '"transfer_credit":%s,'   "$BY_TRANSFER"
  printf '"register":%s,'          "$BY_REGISTER"
  printf '"deregister":%s,'        "$BY_DEREGISTER"
  printf '"inbound_receipt":%s,'   "$BY_INBOUND"
  printf '"dapp_call_credit":%s,'  "$BY_DAPP_CALL"
  printf '"subsidy_creator":%s'    "$BY_SUBSIDY"
  printf '},'
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_account_growth: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== Account growth (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    if [ "$START_COUNT" -gt 0 ]; then
      GROWTH_PCT_RENDER=$(render_pct "$GROWTH_BPS")
      echo "Account-set growth: $START_COUNT -> $END_COUNT (+$DELTA, +$GROWTH_PCT_RENDER)"
    else
      echo "Account-set growth: $START_COUNT -> $END_COUNT (+$DELTA, growth-rate undefined: start=0)"
    fi
    echo "New accounts: $DELTA distinct"
    echo "Avg new accounts/block: $(render_avg "$NEW_PER_BLOCK_HUNDREDTHS")"
    if [ "$PEAK_COUNT" -gt 0 ]; then
      echo "Peak block: $PEAK_BLOCK (+$PEAK_COUNT new accounts)"
    else
      echo "Peak block: -  (window had zero new-account activity)"
    fi
    if [ "$ANOM_ONLY" != "1" ]; then
      echo "By source type (approximate):"
      # Pretty-printed by-source; alignment widths chosen for the
      # longest expected label ("dapp_call_credit").
      printf "  TRANSFER credit:    %s\n" "$(render_share "$BY_TRANSFER"  "$DELTA")"
      printf "  REGISTER:           %s\n" "$(render_share "$BY_REGISTER"  "$DELTA")"
      printf "  Inbound receipt:    %s\n" "$(render_share "$BY_INBOUND"   "$DELTA")"
      printf "  DEREGISTER:         %s\n" "$(render_share "$BY_DEREGISTER" "$DELTA")"
      printf "  DAPP_CALL credit:   %s\n" "$(render_share "$BY_DAPP_CALL" "$DELTA")"
      printf "  Subsidy creator:    %s\n" "$(render_share "$BY_SUBSIDY"   "$DELTA")"
    fi
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No mass-creation / rapid-expansion anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      if [ "$PEAK_COUNT" -gt 50 ]; then
        echo "  mass_creation_spike : block $PEAK_BLOCK added $PEAK_COUNT accounts (>50)"
      fi
      if [ "$START_COUNT" -gt 0 ] && [ "$GROWTH_BPS" -gt 10000 ]; then
        echo "  rapid_expansion     : window grew $(render_pct "$GROWTH_BPS") (>100%)"
      fi
    fi
  fi
fi

# ── Step 6: exit-code policy ──────────────────────────────────────────────────
# Same convention as operator_subsidy_audit / operator_stake_audit /
# operator_fork_watch: exit 2 only when --anomalies-only is set AND at
# least one anomaly fired. Default informational mode always exits 0
# if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
