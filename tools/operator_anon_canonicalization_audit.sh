#!/usr/bin/env bash
# operator_anon_canonicalization_audit.sh — Read-only S-028 anon-address
# canonicalization + account-lifecycle conformance audit against a running
# determ daemon. Two independent invariants, both pure-diagnostic (no
# mutating RPC is ever issued):
#
#   (A) STORED-FORM CANONICALITY (passive state audit)
#       Every anon address persisted in chain state — as an accounts_
#       store-key, a stakes_ key, or a transaction/receipt endpoint in
#       the recent block window — must already be in the S-028 canonical
#       lowercase form ("0x" + 64 LOWERCASE hex chars). The chain stores
#       the normalized form (rpc_balance / rpc_send / submit_tx all
#       normalize-or-reject at the boundary per S-028), so any stored key
#       that is anon-SHAPED but contains an uppercase hex digit is a
#       conformance violation worth an operator alert.
#
#   (B) LIVE RPC-NORMALIZATION CONFORMANCE (active probe)
#       For a bounded sample of distinct anon addresses observed in (A),
#       re-query the three read RPCs that S-028 G-2 made case-folding —
#       balance / nonce / stake_info — with BOTH the canonical lowercase
#       spelling AND a synthesized all-uppercase spelling of the same
#       address. The daemon MUST return identical numeric results for
#       both spellings AND echo the canonical lowercase `domain` field
#       regardless of input case. A divergence means the live handler
#       drifted from the normalize-at-input contract (rpc_nonce /
#       rpc_stake_info / rpc_balance in src/node/node.cpp). Probe RPCs are
#       all reads; no tx is submitted.
#
# Account-lifecycle classification (theme: auto-creation on first credit):
#   Per docs/proofs/AccountStateInvariants.md, a TRANSFER / inbound-receipt
#   credit to a previously-unseen anon address auto-creates accounts_[to]
#   with no signature from the recipient. We classify each distinct anon
#   account from the snapshot into:
#     - credit_only   next_nonce == 0 AND never seen as a tx.from in the
#                     window — i.e. it exists purely because something
#                     credited it (the canonical auto-creation residue).
#     - active        next_nonce >= 1 OR seen as a tx.from in the window
#                     — the keyholder has signed at least once.
#   The credit_only cohort is the auto-creation-on-credit population an
#   operator wants visibility into (airdrops, faucet outputs, mis-sends).
#
# Sibling-script contrast (avoid overlap — confirmed before writing):
#   operator_anon_address_usage.sh    Direction split / top senders+
#                                     receivers / avg amount / shard
#                                     routing of a SAMPLE. Usage patterns,
#                                     not canonicality or live probing.
#   operator_anon_address_density.sh  Time-bucketed anon-vs-domain density
#                                     TREND (least-squares slope). No
#                                     stored-form audit, no RPC probe.
#   operator_orphan_account_scan.sh   Dormant ZERO-balance auto-created
#                                     accounts (recent-activity dimension).
#                                     Overlaps on "auto-created" framing
#                                     but keys on dormancy + balance, not
#                                     canonicality + live normalization.
#   operator_unique_address_audit.sh  Distinct-address counting. No anon
#                                     canonicality, no RPC case probe.
#   THIS                              S-028 stored-form canonicality +
#                                     LIVE balance/nonce/stake_info case
#                                     conformance + credit-only lifecycle.
#
# Pipeline (read-only RPC only):
#   1.  `determ head --field height`               resolve tip
#   2.  `determ snapshot create --out <tmp>`        full state dump JSON
#       (accounts[] / stakes[] / registrants[]) — the canonical
#       per-account ledger keyed by the stored (normalized) form.
#   3.  Walk [from..to] via `determ block-info <h> --json` to collect the
#       set of anon addresses appearing as tx.from / tx.to and
#       inbound_receipt.to, plus the set ever seen as a tx.from (the
#       "has signed" set used for the active vs credit_only split).
#   4.  Stored-form audit: every anon-shaped store-key / endpoint that is
#       NOT already canonical lowercase is a violation.
#   5.  Live probe (capped by --probe-sample): per sampled anon address,
#       query balance / nonce / stake_info twice (lower + UPPER) and
#       diff. Any mismatch (numeric value OR echoed canonical domain) is
#       a live-conformance failure.
#
# Anomaly flags (each adds an entry to anomalies[]; --anomalies-only
# exits 2 if any fire):
#   noncanonical_stored_key    >=1 anon-shaped stored store-key / observed
#                              endpoint was NOT canonical lowercase. This
#                              is the S-028 stored-form invariant broken —
#                              a high-severity correctness signal because
#                              two case spellings would split one logical
#                              account across two store-keys.
#   live_normalization_drift   >=1 sampled address returned a DIFFERENT
#                              balance / next_nonce / locked for its
#                              uppercase spelling than its lowercase
#                              spelling, OR the echoed `domain` field for
#                              the uppercase query was not the canonical
#                              lowercase form. The live handler diverged
#                              from the normalize-at-input contract.
#   credit_only_share_high     credit_only anon accounts > 70% of all
#                              distinct anon accounts. Heavy auto-creation
#                              residue (mass airdrop / faucet / mis-send
#                              accumulation) worth review.
#
# Usage:
#   tools/operator_anon_canonicalization_audit.sh
#       [--rpc-port N] [--json]
#       [--from H] [--to H]
#       [--probe-sample N]
#       [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of block window (inclusive; default:
#                       max(0, tip-1000)). The window feeds the
#                       endpoint-observation + tx.from sets only; the
#                       snapshot in step 2 covers ALL accounts regardless.
#   --to H              End of block window (inclusive; default: tip)
#   --probe-sample N    Max distinct anon addresses to actively case-probe
#                       in step 5 (default: 25). Each sampled address costs
#                       6 read RPCs (balance/nonce/stake_info x2 spellings),
#                       so larger N raises probe latency linearly. Sample
#                       is deterministic (sorted-asc order).
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND >=1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_anon_canonicalization_audit.sh [--rpc-port N] [--json]
                                               [--from H] [--to H]
                                               [--probe-sample N]
                                               [--anomalies-only]

Read-only S-028 anon-address canonicalization + account-lifecycle audit.
Two invariants:
  (A) Stored-form canonicality — every anon address persisted in state
      (accounts_ / stakes_ keys, recent tx + receipt endpoints) must be
      canonical lowercase ("0x" + 64 lowercase hex). Non-canonical
      stored forms split one logical account across two keys.
  (B) Live RPC normalization — balance / nonce / stake_info must return
      identical results for the lowercase and uppercase spelling of the
      same address, and echo the canonical lowercase `domain`.
Plus account-lifecycle: classifies anon accounts as credit_only
(auto-created on first credit; next_nonce==0, never a tx.from) vs active.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of block window (default: max(0, tip-1000))
  --to H              End of block window   (default: tip)
  --probe-sample N    Distinct anon addresses to case-probe (default: 25;
                      each costs 6 read RPCs)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  noncanonical_stored_key    >=1 anon-shaped stored key/endpoint not
                             canonical lowercase (S-028 stored-form broken)
  live_normalization_drift   >=1 sampled address gave a different
                             balance/nonce/locked for its uppercase form,
                             or echoed a non-canonical domain
  credit_only_share_high     credit_only anon accounts > 70% of all
                             distinct anon accounts

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
PROBE_SAMPLE=25
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";         shift 2 ;;
    --json)           JSON_OUT=1;            shift ;;
    --from)           FROM_H="${2:-}";       shift 2 ;;
    --to)             TO_H="${2:-}";         shift 2 ;;
    --probe-sample)   PROBE_SAMPLE="${2:-}"; shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;           shift ;;
    *) echo "operator_anon_canonicalization_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_anon_canonicalization_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_anon_canonicalization_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$PROBE_SAMPLE" in *[!0-9]*|"")
  echo "operator_anon_canonicalization_audit: --probe-sample must be a positive integer (got '$PROBE_SAMPLE')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Absolute binary path so the python block-walk can fork-exec it from any cwd.
DETERM_ABS="$DETERM"
case "$DETERM_ABS" in
  /*|?:*) : ;;  # already absolute (POSIX or Windows drive-letter)
  *) DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
esac

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_anon_canonicalization_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_anon_canonicalization_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip.
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_anon_canonicalization_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: full state dump ───────────────────────────────────────────────────
TMP_SNAP=$(mktemp 2>/dev/null) || {
  echo "operator_anon_canonicalization_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_anon_canonicalization_audit: cannot create temp file" >&2
  rm -f "$TMP_SNAP" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_anon_canonicalization_audit: snapshot create failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3+4: snapshot canonicality + window walk + lifecycle classify ────────
# Single python driver: parse snapshot (accounts/stakes/registrants),
# walk the block window via subprocess `block-info`, audit anon-shaped
# store-keys + observed endpoints for canonicality, and split anon
# accounts into credit_only vs active. Output the result JSON + the
# deterministic probe sample list for step 5.
python - "$DETERM_ABS" "$PORT" "$TMP_SNAP" "$TMP_OUT" "$FROM" "$TO" <<'PY'
import json, subprocess, sys, re
from collections import Counter

determ, port, snap_path, out_path, from_s, to_s = sys.argv[1:7]
from_h = int(from_s); to_h = int(to_s)

# Anon-SHAPE predicate (case-tolerant): "0x" + 64 hex chars in EITHER
# case. This deliberately matches the shape WITHOUT requiring canonical
# lowercase, so we can detect a stored key that is anon-shaped but NOT
# yet canonical — exactly the S-028 stored-form violation we audit for.
ANON_SHAPE_RE = re.compile(r'^0x[0-9a-fA-F]{64}$')
# Canonical form per include/determ/types.hpp normalize_anon_address:
# "0x" + 64 LOWERCASE hex chars.
ANON_CANON_RE = re.compile(r'^0x[0-9a-f]{64}$')

def is_anon_shape(s):
    return isinstance(s, str) and bool(ANON_SHAPE_RE.match(s))

def is_canonical(s):
    return isinstance(s, str) and bool(ANON_CANON_RE.match(s))

def canon(s):
    # Lowercase the hex body; "0x" preserved. Only meaningful for
    # anon-shaped input (callers gate on is_anon_shape first).
    return "0x" + s[2:].lower()

# ── snapshot ──────────────────────────────────────────────────────────────
try:
    with open(snap_path, "r", encoding="utf-8") as f:
        snap = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_anon_canonicalization_audit: cannot parse snapshot: {e}\n")
    sys.exit(1)
if not isinstance(snap, dict):
    sys.stderr.write("operator_anon_canonicalization_audit: snapshot is not a JSON object\n")
    sys.exit(1)

# Per-domain account view (canonical-keyed). We collect, for every anon
# account, balance + next_nonce. We also record any NON-canonical stored
# key as a violation (the chain should never persist one, but we audit
# the actual bytes the daemon serialized).
anon_accounts   = {}    # canonical addr -> {balance, next_nonce}
noncanon_keys   = []     # raw stored keys that were anon-shaped but not canonical
total_accounts  = 0
for a in snap.get("accounts", []) or []:
    if not isinstance(a, dict):
        continue
    d = a.get("domain")
    if not (isinstance(d, str) and d):
        continue
    total_accounts += 1
    if is_anon_shape(d):
        if not is_canonical(d):
            noncanon_keys.append({"source": "accounts", "key": d})
        c = canon(d)
        anon_accounts.setdefault(c, {"balance": 0, "next_nonce": 0})
        anon_accounts[c]["balance"]    = int(a.get("balance", 0) or 0)
        anon_accounts[c]["next_nonce"] = int(a.get("next_nonce", 0) or 0)

# Stakes keys: anon addresses can't stake, but we audit the stored key
# shape anyway (defense-in-depth — a non-canonical stake key would be an
# equally severe stored-form violation).
anon_staked = set()
for s in snap.get("stakes", []) or []:
    if not isinstance(s, dict):
        continue
    d = s.get("domain")
    if isinstance(d, str) and is_anon_shape(d):
        if not is_canonical(d):
            noncanon_keys.append({"source": "stakes", "key": d})
        anon_staked.add(canon(d))

# ── block window walk ───────────────────────────────────────────────────────
# Collect: every anon endpoint observed (tx.from / tx.to / receipt.to)
# and, separately, the set ever seen as a tx.FROM (proves a signature ⇒
# "active"). Any observed endpoint that is anon-shaped but non-canonical
# is also a stored-form violation (the block was serialized with a
# non-canonical address — submit_tx should have rejected it).
observed_anon   = set()     # canonical
seen_as_from    = set()     # canonical — has signed at least once
noncanon_seen   = set()     # raw non-canonical endpoints observed in blocks

def note_endpoint(addr, is_from):
    if not is_anon_shape(addr):
        return
    if not is_canonical(addr):
        noncanon_seen.add(addr)
    c = canon(addr)
    observed_anon.add(c)
    if is_from:
        seen_as_from.add(c)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_anon_canonicalization_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_anon_canonicalization_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_anon_canonicalization_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    for tx in blk.get("transactions") or []:
        if not isinstance(tx, dict):
            continue
        f = tx.get("from", "")
        t = tx.get("to", "")
        if isinstance(f, str):
            note_endpoint(f, True)
        if isinstance(t, str):
            note_endpoint(t, False)

    for rc in blk.get("inbound_receipts") or []:
        if not isinstance(rc, dict):
            continue
        t = rc.get("to", "")
        if isinstance(t, str):
            note_endpoint(t, False)   # credit side — not a tx.from

# ── lifecycle classification ────────────────────────────────────────────────
# An anon account is credit_only iff next_nonce == 0 AND it never appears
# as a tx.from in the window — the canonical auto-creation-on-credit
# residue (it exists only because something credited it; the keyholder
# has never signed). Anything with next_nonce >= 1 or an observed tx.from
# is active. We classify over the union of snapshot anon accounts AND
# window-observed anon addresses (a window endpoint may be a fresh credit
# the snapshot also reflects).
all_anon = set(anon_accounts.keys()) | observed_anon
credit_only = []
active      = []
for c in sorted(all_anon):
    nn = anon_accounts.get(c, {}).get("next_nonce", 0)
    is_active = (nn >= 1) or (c in seen_as_from)
    if is_active:
        active.append(c)
    else:
        credit_only.append(c)

distinct_anon = len(all_anon)

# Deterministic probe sample: prefer addresses that exist in the snapshot
# (so balance/nonce/stake_info return real committed values), sorted asc.
# Fall back to window-only addresses if the snapshot set is small.
probe_pool = sorted(set(anon_accounts.keys()) | observed_anon)

result = {
    "total_accounts":     total_accounts,
    "distinct_anon":      distinct_anon,
    "anon_in_snapshot":   len(anon_accounts),
    "anon_in_window":     len(observed_anon),
    "anon_staked":        len(anon_staked),
    "credit_only_count":  len(credit_only),
    "active_count":       len(active),
    "noncanon_stored":    noncanon_keys,
    "noncanon_seen":      sorted(noncanon_seen),
    "credit_only_sample": credit_only[:20],
    "probe_pool":         probe_pool,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_anon_canonicalization_audit: snapshot/window walk failed" >&2
  exit 1
fi

# ── Step 5: live RPC case-normalization probe ─────────────────────────────────
# For a deterministic sample of distinct anon addresses, query balance /
# nonce / stake_info with the lowercase canonical form AND a synthesized
# all-uppercase form. The daemon must return identical numeric values AND
# echo the canonical lowercase `domain`. Pure reads — no mutation.
TMP_PROBE=$(mktemp 2>/dev/null) || {
  echo "operator_anon_canonicalization_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" "$TMP_PROBE" 2>/dev/null' EXIT
: >"$TMP_PROBE"

PROBED=0
DRIFTS=0
# Extract the deterministic probe pool, capped by --probe-sample.
if command -v jq >/dev/null 2>&1; then
  PROBE_LIST=$(jq -r '.probe_pool[]' "$TMP_OUT" 2>/dev/null | head -n "$PROBE_SAMPLE")
else
  PROBE_LIST=$(python - "$TMP_OUT" "$PROBE_SAMPLE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
for a in r.get("probe_pool", [])[:int(sys.argv[2])]:
    print(a)
PY
)
fi

if [ -n "$PROBE_LIST" ]; then
  while IFS= read -r ADDR; do
    [ -z "$ADDR" ] && continue
    # Synthesize the all-uppercase spelling of the hex body.
    UPPER=$(printf '%s' "$ADDR" | python -c "import sys; s=sys.stdin.read().strip(); print('0x' + s[2:].upper())")

    # Six read RPCs. Each `determ <cmd> <addr> --rpc-port N --json`-style
    # subcommand prints the JSON response; we diff the relevant fields.
    BAL_L=$("$DETERM" balance    "$ADDR"  --rpc-port "$PORT" 2>/dev/null)
    BAL_U=$("$DETERM" balance    "$UPPER" --rpc-port "$PORT" 2>/dev/null)
    NON_L=$("$DETERM" nonce      "$ADDR"  --rpc-port "$PORT" 2>/dev/null)
    NON_U=$("$DETERM" nonce      "$UPPER" --rpc-port "$PORT" 2>/dev/null)
    STK_L=$("$DETERM" stake_info "$ADDR"  --rpc-port "$PORT" 2>/dev/null)
    STK_U=$("$DETERM" stake_info "$UPPER" --rpc-port "$PORT" 2>/dev/null)

    # Compare in python: numeric fields must match across spellings, and
    # the uppercase-query echoed `domain` must equal the canonical addr.
    DRIFT=$(python - "$ADDR" "$BAL_L" "$BAL_U" "$NON_L" "$NON_U" "$STK_L" "$STK_U" <<'PY'
import json, sys
addr = sys.argv[1]
def g(s, *keys):
    try:
        o = json.loads(s)
    except Exception:
        return None
    cur = o
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur

bal_l, bal_u, non_l, non_u, stk_l, stk_u = sys.argv[2:8]
problems = []

if g(bal_l, "balance") != g(bal_u, "balance"):
    problems.append("balance")
if g(non_l, "next_nonce") != g(non_u, "next_nonce"):
    problems.append("next_nonce")
if g(stk_l, "locked") != g(stk_u, "locked"):
    problems.append("locked")
# Echoed canonical domain on the UPPERCASE query.
for name, s in (("nonce", non_u), ("stake_info", stk_u), ("balance", bal_u)):
    d = g(s, "domain")
    if d is not None and d != addr:
        problems.append(f"{name}.domain")

print(",".join(problems))
PY
)
    PROBED=$(( PROBED + 1 ))
    if [ -n "$DRIFT" ]; then
      DRIFTS=$(( DRIFTS + 1 ))
      printf '%s\t%s\n' "$ADDR" "$DRIFT" >>"$TMP_PROBE"
    fi
  done <<EOF_LIST
$PROBE_LIST
EOF_LIST
fi

# ── Step 6: render envelope (JSON or human table) + classify anomalies ────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$TMP_PROBE" \
         "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$PROBED" "$DRIFTS" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
probe_path = sys.argv[4]
port       = int(sys.argv[5])
from_h     = int(sys.argv[6])
to_h       = int(sys.argv[7])
win_blocks = int(sys.argv[8])
probed     = int(sys.argv[9])
drifts     = int(sys.argv[10])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

# Read the drift records (addr <tab> comma-joined-problem-fields).
drift_records = []
try:
    with open(probe_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t", 1)
            addr = parts[0]
            fields = parts[1].split(",") if len(parts) > 1 and parts[1] else []
            drift_records.append({"address": addr, "fields": fields})
except FileNotFoundError:
    pass

distinct_anon    = r["distinct_anon"]
credit_only      = r["credit_only_count"]
active           = r["active_count"]
noncanon_stored  = r["noncanon_stored"]
noncanon_seen    = r["noncanon_seen"]
noncanon_total   = len(noncanon_stored) + len(noncanon_seen)

def ratio_bps(n, d):
    if d <= 0:
        return 0
    return n * 10000 // d

def render_pct_bps(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def short(addr):
    if isinstance(addr, str) and addr.startswith("0x") and len(addr) >= 10:
        return addr[:10] + "..."
    return addr

# ── anomaly classification ────────────────────────────────────────────────
anomalies = []
if noncanon_total > 0:
    anomalies.append("noncanonical_stored_key")
if drifts > 0:
    anomalies.append("live_normalization_drift")
credit_share_bps = ratio_bps(credit_only, distinct_anon)
if distinct_anon > 0 and credit_share_bps > 7000:
    anomalies.append("credit_only_share_high")

anom_count = len(anomalies)

if json_out:
    envelope = {
        "window": {"from": from_h, "to": to_h, "blocks": win_blocks},
        "total_accounts":   r["total_accounts"],
        "distinct_anon":    distinct_anon,
        "anon_in_snapshot": r["anon_in_snapshot"],
        "anon_in_window":   r["anon_in_window"],
        "anon_staked":      r["anon_staked"],
        "lifecycle": {
            "credit_only":      credit_only,
            "active":           active,
            "credit_only_bps":  credit_share_bps,
            "credit_only_sample": r["credit_only_sample"],
        },
        "canonicality": {
            "noncanonical_stored_keys": noncanon_stored,
            "noncanonical_observed":    noncanon_seen,
            "noncanonical_total":       noncanon_total,
        },
        "live_probe": {
            "probed":  probed,
            "drifts":  drifts,
            "records": drift_records,
        },
        "anomalies": anomalies,
        "rpc_port":  port,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# ── human-readable layout ───────────────────────────────────────────────────
if anom_only and anom_count == 0:
    print(f"operator_anon_canonicalization_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

print(f"=== Anon canonicalization audit (port {port}, window [{from_h}..{to_h}], {win_blocks} blocks) ===")
print(f"Distinct anon addresses: {distinct_anon} "
      f"({r['anon_in_snapshot']} in snapshot, {r['anon_in_window']} observed in window, "
      f"{r['anon_staked']} staked)")

if not anom_only:
    print("Lifecycle (auto-creation on first credit):")
    print(f"  credit_only: {credit_only} ({render_pct_bps(credit_share_bps)} of anon accounts)")
    print(f"  active:      {active}")
    if r["credit_only_sample"]:
        print("  credit_only sample:")
        for a in r["credit_only_sample"]:
            print(f"    {short(a)}")

    print("Stored-form canonicality (S-028):")
    if noncanon_total == 0:
        print("  [OK] every anon-shaped stored key / observed endpoint is canonical lowercase")
    else:
        print(f"  [VIOLATION] {noncanon_total} non-canonical anon-shaped form(s):")
        for v in noncanon_stored:
            print(f"    {v['source']}: {short(v['key'])}")
        for k in noncanon_seen:
            print(f"    block-endpoint: {short(k)}")

    print(f"Live RPC normalization probe: {probed} address(es) probed (balance/nonce/stake_info x lower+UPPER)")
    if probed == 0:
        print("  (no anon addresses to probe)")
    elif drifts == 0:
        print("  [OK] every probed address returned identical results for both spellings + canonical domain echo")
    else:
        print(f"  [DRIFT] {drifts} address(es) diverged across case spellings:")
        for d in drift_records:
            print(f"    {short(d['address'])}: {','.join(d['fields'])}")

print()
if anom_count == 0:
    print("[OK] No canonicalization anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "noncanonical_stored_key" in anomalies:
        print(f"  noncanonical_stored_key: {noncanon_total} anon-shaped form(s) "
              f"not in canonical lowercase (S-028 stored-form invariant broken)")
    if "live_normalization_drift" in anomalies:
        print(f"  live_normalization_drift: {drifts} sampled address(es) returned different "
              f"balance/nonce/locked or non-canonical domain across case spellings")
    if "credit_only_share_high" in anomalies:
        print(f"  credit_only_share_high: credit_only = {render_pct_bps(credit_share_bps)} "
              f"of anon accounts (> 70% threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_anon_canonicalization_audit: rendering failed" >&2
  exit 1
fi

# ── Step 7: exit-code policy ──────────────────────────────────────────────────
# Recompute the anomaly count from the result file + probe drift count so
# the --anomalies-only gate is authoritative. Pattern mirrors
# operator_anon_address_usage.sh.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_anon_canonicalization_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_OUT" "$TMP_PROBE" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$DRIFTS" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
drifts = int(sys.argv[2])
distinct = r["distinct_anon"]
credit   = r["credit_only_count"]
noncanon = len(r["noncanon_stored"]) + len(r["noncanon_seen"])
n = 0
if noncanon > 0:
    n += 1
if drifts > 0:
    n += 1
if distinct > 0 and credit * 10000 // distinct > 7000:
    n += 1
with open(sys.argv[3], "w", encoding="utf-8") as f:
    f.write(str(n))
PY
ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
