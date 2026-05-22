#!/usr/bin/env bash
# operator_mempool_inspector.sh — Live mempool depth + age + sender-
# concentration audit with Sybil-detection anomalies.
#
# Complements operator_mempool_diagnostic.sh (which is also forward-
# staged for the same v2.x `mempool` RPC, focused on tx-type breakdown +
# S-008 pressure). This script focuses on the orthogonal axis: who is
# filling the mempool, how stale is it, and is a single sender
# monopolizing it (Sybil-flood signal)?
#
# Three distinct anomaly tiers (operator alert escalation order):
#   1. depth — how full the mempool is.
#   2. age   — are entries stuck (miner-side rejection / fee-priority
#              starvation).
#   3. sender — Sybil-concentration on per-sender entry counts AND a
#              nonce-gap scan that catches sender-side bugs + replay
#              scenarios.
#
# ── RPC dependency note ───────────────────────────────────────────────
# Today's daemon (v1.x) does NOT expose a per-tx `mempool` RPC; the
# scalar `mempool_size` is the only mempool-visible field in `status`
# (see src/node/node.cpp::rpc_status). Without per-tx records, the
# sender-concentration / age / nonce-gap aggregates cannot be computed
# from outside the daemon.
#
# So this script runs in TWO modes:
#
#   FULL mode    — the daemon exposes `determ mempool --json` returning
#                  `{pending:[{hash,from,type,nonce,fee,
#                              received_at_block | received_at_unix,
#                              size}], count, bound}`.
#                  Every anomaly is computable; per-sender table,
#                  age histogram, nonce-gap scan are all emitted.
#
#   FALLBACK mode — the daemon does NOT expose `determ mempool`.
#                   This script emits a clearly labelled INFO line
#                   `mempool RPC not exposed; this script requires
#                   --rpc-port to a daemon that supports mempool
#                   inspection. Falling back to header-level audit
#                   only.` and then walks the recent block window via
#                   `block-info` to surface PROXY metrics from
#                   already-applied blocks:
#                     - total tx count in the recent window
#                     - top-N senders by recent-block tx count (proxy
#                       for sender concentration in the mempool, since
#                       the mempool feeds the producer)
#                     - per-sender nonce-gap scan across recent blocks
#                       (catches sender-side replay regressions even
#                       without mempool visibility)
#                   In fallback mode the depth + age anomalies are
#                   marked `INDETERMINATE` (the count is still emitted
#                   from status.mempool_size, but the per-tx age
#                   histogram is unavailable). Critical depth fires
#                   only if status.mempool_size already crosses the
#                   threshold.
#
# Forward staging: when the v2.x `mempool` RPC ships (see
# operator_mempool_diagnostic.sh's header for the expected shape), this
# script automatically promotes to FULL mode with no code changes — the
# detection happens at runtime.
#
# Args:
#   --rpc-port N                          RPC port (required)
#   --depth-threshold-warn N              default 1000; warn level
#   --depth-threshold-critical N          default 5000; critical level
#   --sender-concentration-threshold F    default 0.30; top-1 sender
#                                         share threshold (Sybil signal)
#   --age-threshold-blocks N              default 100; tx older than
#                                         N blocks → stuck flag
#   --json                                Structured envelope
#   --anomalies-only                      Print only flagged anomalies
#                                         (still exits 2 on any flag)
#   -h, --help                            Show help
#
# Anomaly flags:
#   mempool_depth_critical   depth > --depth-threshold-critical
#   mempool_depth_warn       depth > --depth-threshold-warn (and not
#                            already critical)
#   single_sender_dominant   top-1 sender share > --sender-
#                            concentration-threshold (Sybil-flood)
#   stuck_transactions       ≥1 tx older than --age-threshold-blocks
#                            (FULL mode only; INDETERMINATE in fallback)
#   nonce_gap_detected       sender has tx with nonce N submitted but
#                            nonce N-1 missing (sender-side bug /
#                            replay scenario worth review)
#
# Exit codes (mirrors sibling operator_*.sh — 0/1/2 only; criticality is
# carried in the anomaly LABEL rather than a non-standard exit code, so
# operator alerting scripts can rely on a single binary exit gate):
#   0   audit ran successfully, no anomalies (or default informational)
#   1   RPC error / daemon unreachable / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_mempool_inspector.sh --rpc-port N
           [--depth-threshold-warn N]
           [--depth-threshold-critical N]
           [--sender-concentration-threshold F]
           [--age-threshold-blocks N]
           [--json]
           [--anomalies-only]

Audit a running determ daemon's mempool: depth, per-tx age, per-sender
concentration, and nonce-gap scan. Operates in FULL mode when the
daemon exposes the v2.x `mempool` RPC (per-tx records), and in
FALLBACK mode otherwise (status.mempool_size + recent-block walk).

Options:
  --rpc-port N                          RPC port to query (required)
  --depth-threshold-warn N              warn at depth > N (default 1000)
  --depth-threshold-critical N          critical at depth > N (default 5000)
  --sender-concentration-threshold F    Sybil flag at top-1 share > F (default 0.30)
  --age-threshold-blocks N              stuck flag if any tx older than N blocks
                                        (default 100; FULL mode only)
  --json                                emit structured JSON envelope
  --anomalies-only                      print only flagged anomalies; exit 2 if any
  -h, --help                            show this help

Anomaly flags:
  mempool_depth_critical    depth > critical threshold
  mempool_depth_warn        depth > warn threshold (and not critical)
  single_sender_dominant    top-1 sender share > sender-concentration-threshold
  stuck_transactions        any tx older than age-threshold-blocks (FULL only)
  nonce_gap_detected        sender has nonce-N tx but nonce-(N-1) missing

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / unreachable daemon
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
DEPTH_WARN="1000"
DEPTH_CRIT="5000"
SENDER_THR="0.30"
AGE_THR="100"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage; exit 0 ;;
    --rpc-port)
      PORT="${2:-}";                            shift 2 ;;
    --depth-threshold-warn)
      DEPTH_WARN="${2:-}";                      shift 2 ;;
    --depth-threshold-critical)
      DEPTH_CRIT="${2:-}";                      shift 2 ;;
    --sender-concentration-threshold)
      SENDER_THR="${2:-}";                      shift 2 ;;
    --age-threshold-blocks)
      AGE_THR="${2:-}";                         shift 2 ;;
    --json)
      JSON_OUT=1;                               shift ;;
    --anomalies-only)
      ANOM_ONLY=1;                              shift ;;
    *)
      echo "operator_mempool_inspector: unknown argument: $1" >&2
      usage >&2
      exit 1 ;;
  esac
done

# ── Arg validation ──────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_mempool_inspector: --rpc-port is required and must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for pair in "DEPTH_WARN:$DEPTH_WARN" "DEPTH_CRIT:$DEPTH_CRIT" "AGE_THR:$AGE_THR"; do
  name="${pair%%:*}"; val="${pair#*:}"
  case "$val" in *[!0-9]*|"")
    echo "operator_mempool_inspector: $name must be a non-negative integer (got '$val')" >&2
    exit 1 ;;
  esac
done
# Critical > warn — anything else is a config error (we'd never fire the
# higher-tier flag if it's behind the lower-tier one).
if [ "$DEPTH_CRIT" -lt "$DEPTH_WARN" ]; then
  echo "operator_mempool_inspector: --depth-threshold-critical ($DEPTH_CRIT) must be >= --depth-threshold-warn ($DEPTH_WARN)" >&2
  exit 1
fi
# Float guard on sender concentration. Accept the standard decimal
# forms (0.30, 0.50, 1.0). Range checked via python so we don't
# reimplement float compare in shell.
case "$SENDER_THR" in
  ""|*[!0-9.]*)
    echo "operator_mempool_inspector: --sender-concentration-threshold must be a decimal in [0,1] (got '$SENDER_THR')" >&2
    exit 1 ;;
esac
if ! python -c "import sys; v=float('$SENDER_THR'); sys.exit(0 if 0.0<=v<=1.0 else 1)" 2>/dev/null; then
  echo "operator_mempool_inspector: --sender-concentration-threshold must be in [0.0, 1.0] (got '$SENDER_THR')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current chain tip ───────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_mempool_inspector: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_mempool_inspector: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: pull status (mempool_size scalar — works on every daemon) ───────
# Even in FULL mode the status RPC is the authoritative depth source —
# the per-tx array length is a check, but status.mempool_size is what
# the bound-enforcement code path actually compares against.
STATUS_OUT=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_mempool_inspector: status RPC failed (port $PORT)" >&2
  exit 1
}
MEMPOOL_SIZE=$(printf '%s' "$STATUS_OUT" | python -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(int(d.get('mempool_size', 0)))
except Exception:
    print(0)
" 2>/dev/null)
case "$MEMPOOL_SIZE" in *[!0-9]*|"") MEMPOOL_SIZE=0 ;; esac

# ── Step 3: probe for `mempool` RPC (FULL vs FALLBACK mode) ────────────────
MEMPOOL_OUT=$("$DETERM" mempool --json --rpc-port "$PORT" 2>&1) || RPC_RC=$?
RPC_RC=${RPC_RC:-0}
HAVE_FULL=0
# Positive signal: response contains a `pending` array — see
# operator_mempool_diagnostic.sh for the expected v2.x shape.
if printf '%s' "$MEMPOOL_OUT" | grep -q '"pending"'; then
  HAVE_FULL=1
fi

# ── Step 4: dispatch to FULL or FALLBACK aggregator ─────────────────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_mempool_inspector: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "${TMP_FALLBACK:-}" 2>/dev/null' EXIT

if [ "$HAVE_FULL" = "1" ]; then
  # ── FULL mode: parse per-tx records ───────────────────────────────────────
  python - "$MEMPOOL_OUT" "$TMP_OUT" "$HEAD_H" \
           "$DEPTH_WARN" "$DEPTH_CRIT" "$SENDER_THR" "$AGE_THR" \
           "$MEMPOOL_SIZE" <<'PY'
import json, sys
from collections import defaultdict, Counter

mempool_raw, out_path, head_h_s, dw_s, dc_s, st_s, ab_s, ms_s = sys.argv[1:9]
head_h        = int(head_h_s)
depth_warn    = int(dw_s)
depth_crit    = int(dc_s)
sender_thr    = float(st_s)
age_thr       = int(ab_s)
status_depth  = int(ms_s)

try:
    doc = json.loads(mempool_raw)
except Exception as e:
    sys.stderr.write(f"operator_mempool_inspector: cannot parse mempool RPC JSON: {e}\n")
    sys.exit(1)
pending = doc.get("pending") or []
if not isinstance(pending, list):
    sys.stderr.write("operator_mempool_inspector: mempool.pending not a list\n")
    sys.exit(1)

# True mempool depth = length of the pending array. status.mempool_size
# is reported separately for cross-check; if the two diverge by more
# than 5% it's worth surfacing (a TOCTOU between the two RPC calls is
# normal and small drift is expected, but large drift hints at the
# daemon being mid-eviction).
depth = len(pending)

# Per-sender aggregates.
by_sender_count   = defaultdict(int)
by_sender_fee     = defaultdict(int)
by_sender_oldest  = defaultdict(lambda: head_h + 1)   # min received_at_block
sender_nonces     = defaultdict(list)                  # for nonce-gap scan
type_counter      = Counter()
age_buckets       = {"0-10": 0, "11-50": 0, "51-100": 0, "101-500": 0, "501+": 0}
oldest_age_blocks = 0
oldest_pending_block = head_h + 1
total_fee         = 0
stuck_tx_count    = 0

def classify_age(blocks_old):
    if blocks_old <= 10:   return "0-10"
    if blocks_old <= 50:   return "11-50"
    if blocks_old <= 100:  return "51-100"
    if blocks_old <= 500:  return "101-500"
    return "501+"

for tx in pending:
    if not isinstance(tx, dict): continue
    frm   = tx.get("from", "")
    nonce = tx.get("nonce")
    fee   = int(tx.get("fee", 0) or 0)
    ttype = tx.get("type", "UNKNOWN")
    # Prefer received_at_block; fall back to received_at_unix if the
    # daemon emits Unix timestamps instead. In Unix-mode we can't
    # compute "blocks old" without a block-time anchor, so we treat
    # missing received_at_block as age=0 (informational; the stuck-tx
    # detector becomes a no-op for that tx).
    recv_block = tx.get("received_at_block")
    if not isinstance(recv_block, int):
        recv_block = None
    blocks_old = 0
    if recv_block is not None and recv_block <= head_h:
        blocks_old = head_h - recv_block
        if recv_block < oldest_pending_block:
            oldest_pending_block = recv_block
        if blocks_old > oldest_age_blocks:
            oldest_age_blocks = blocks_old
    age_buckets[classify_age(blocks_old)] += 1
    if blocks_old > age_thr:
        stuck_tx_count += 1

    if isinstance(frm, str) and frm:
        by_sender_count[frm] += 1
        by_sender_fee[frm]   += fee
        if recv_block is not None and recv_block < by_sender_oldest[frm]:
            by_sender_oldest[frm] = recv_block
        if isinstance(nonce, int):
            sender_nonces[frm].append(nonce)
    total_fee += fee
    type_counter[ttype if isinstance(ttype, str) else str(ttype)] += 1

# Top-20 senders by entry count. Tie-break by total-fee DESC (concrete
# economic weight first), then by address ASC for determinism.
top_senders = sorted(
    by_sender_count.items(),
    key=lambda kv: (-kv[1], -by_sender_fee[kv[0]], kv[0])
)[:20]

# Nonce-gap scan: for each sender, sort their submitted nonces; if any
# gap exists (i.e. min < n < max and n not in set), record the gap. A
# single gap entry is enough to flag the sender — we don't enumerate
# every missing nonce because that would explode for a sender with two
# pending txs separated by a million nonces. The signal is "this sender
# has a hole", not "list every hole".
nonce_gap_senders = []
for frm, ns in sender_nonces.items():
    if len(ns) < 2: continue
    nset = set(ns)
    lo, hi = min(ns), max(ns)
    # Bound the gap search so a sender with nonce=0 and nonce=2^63 doesn't
    # hang the script. If the span exceeds 1000 we sample the boundaries.
    span = hi - lo
    found = None
    if span <= 1000:
        for n in range(lo + 1, hi):
            if n not in nset:
                found = n
                break
    else:
        # Sparse-scan: check the immediate neighbors of every present
        # nonce — gaps within the dense neighborhood are the real
        # signal; a gap from 5 to 5_000_000 is just two unrelated txs.
        for n in ns:
            if (n - 1) not in nset and (n - 1) >= lo:
                found = n - 1
                break
            if (n + 1) not in nset and (n + 1) <= hi:
                found = n + 1
                break
    if found is not None:
        nonce_gap_senders.append({"from": frm, "gap_at_nonce": found,
                                  "min_nonce": lo, "max_nonce": hi,
                                  "pending_count": len(ns)})

# Concentration: top-1 sender share (entry-count basis, NOT fee basis —
# Sybil floods are about entry count, the per-entry fee can be trivially
# spoofed at TX_FEE=1 baseline).
total_entries = depth if depth > 0 else 1   # guard against /0
top1_count    = top_senders[0][1] if top_senders else 0
top1_addr     = top_senders[0][0] if top_senders else ""
top1_share_bps = (top1_count * 10000) // total_entries if depth > 0 else 0

# Anomaly classification. Critical pre-empts warn (we don't double-fire
# the depth tier).
anomalies = []
if depth > depth_crit:
    anomalies.append("mempool_depth_critical")
elif depth > depth_warn:
    anomalies.append("mempool_depth_warn")
# Sender concentration: only meaningful when depth is non-trivial.
# Require depth >= 4 so we don't fire on (1/1 = 100%) for a single tx
# (which would be a noisy alert on a near-empty mempool).
sender_thr_bps = int(round(sender_thr * 10000))
if depth >= 4 and top1_share_bps > sender_thr_bps:
    anomalies.append("single_sender_dominant")
if stuck_tx_count > 0:
    anomalies.append("stuck_transactions")
if nonce_gap_senders:
    anomalies.append("nonce_gap_detected")

# Status-mempool-size cross-check: small TOCTOU drift is normal; flag
# only when the two diverge by > 5% in a way that exceeds the depth
# warn threshold (i.e. the daemon is reporting one bound-relevant value
# via status but a different one via mempool — operator should
# investigate the daemon's internal consistency).
status_drift_warn = False
if status_depth > 0 and depth > 0:
    drift_bps = abs(status_depth - depth) * 10000 // max(status_depth, depth)
    if drift_bps > 500:  # > 5%
        status_drift_warn = True

# Total fees: redundant w/ by-sender sum but cheap, and useful for the
# "Total fee value" summary line that mirrors operator_mempool_
# diagnostic.sh's output for cross-tool consistency.
oldest_pending_age = max(0, head_h - oldest_pending_block) if oldest_pending_block <= head_h else 0

result = {
    "mode":                "FULL",
    "depth":               depth,
    "status_mempool_size": status_depth,
    "status_drift_warn":   status_drift_warn,
    "total_fee":           total_fee,
    "oldest_pending_block":  oldest_pending_block if oldest_pending_block <= head_h else None,
    "oldest_age_blocks":   oldest_age_blocks,
    "stuck_tx_count":      stuck_tx_count,
    "age_threshold":       age_thr,
    "age_histogram":       age_buckets,
    "by_type":             dict(type_counter),
    "top_senders": [
        {
            "rank":         i + 1,
            "from":         frm,
            "count":        cnt,
            "fee_total":    by_sender_fee[frm],
            "oldest_block": (by_sender_oldest[frm]
                             if by_sender_oldest[frm] <= head_h else None),
            "share_bps":    (cnt * 10000) // total_entries if depth > 0 else 0,
        }
        for i, (frm, cnt) in enumerate(top_senders)
    ],
    "top1_share_bps":      top1_share_bps,
    "top1_address":        top1_addr,
    "sender_threshold":    sender_thr,
    "sender_threshold_bps":sender_thr_bps,
    "nonce_gap_senders":   nonce_gap_senders,
    "depth_warn":          depth_warn,
    "depth_crit":          depth_crit,
    "anomalies":           anomalies,
    "head_height":         head_h,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
  if [ "$?" -ne 0 ]; then
    echo "operator_mempool_inspector: FULL-mode aggregation failed" >&2
    exit 1
  fi
else
  # ── FALLBACK mode: header-level audit on the recent block window ────────
  # We don't have per-tx mempool visibility, but we DO have the
  # already-applied block tail. Walking the last N blocks gives:
  #   - distinct-sender count + top senders by recent tx count (proxy
  #     for who's *been* spamming the chain — the producer drains from
  #     the mempool so heavy senders in recent blocks are the best
  #     proxy for heavy senders in the current pending pool);
  #   - nonce-gap scan across recent blocks (catches sender-side
  #     replay-protection regressions visible at apply time).
  # Window size: last 100 blocks, capped at the chain length. Smaller
  # window than payments_audit.sh's default 1000 because this is a
  # proxy and we want the freshest signal.
  WINDOW=100
  WIN_FROM=$(( HEAD_H > WINDOW ? HEAD_H - WINDOW + 1 : 0 ))
  if [ "$WIN_FROM" -lt 0 ]; then WIN_FROM=0; fi

  TMP_FALLBACK=$(mktemp 2>/dev/null) || {
    echo "operator_mempool_inspector: cannot create temp file" >&2; exit 1;
  }

  python - "$DETERM" "$PORT" "$WIN_FROM" "$HEAD_H" "$TMP_OUT" \
           "$DEPTH_WARN" "$DEPTH_CRIT" "$SENDER_THR" "$AGE_THR" \
           "$MEMPOOL_SIZE" <<'PY'
import json, subprocess, sys
from collections import defaultdict, Counter

determ, port, from_h_s, to_h_s, out_path, dw_s, dc_s, st_s, ab_s, ms_s = sys.argv[1:11]
from_h        = int(from_h_s)
to_h          = int(to_h_s)
depth_warn    = int(dw_s)
depth_crit    = int(dc_s)
sender_thr    = float(st_s)
age_thr       = int(ab_s)
status_depth  = int(ms_s)

by_sender_count = defaultdict(int)
by_sender_fee   = defaultdict(int)
sender_nonces   = defaultdict(set)
total_tx        = 0

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_mempool_inspector: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        # Skip past-chain holes (some test chains have intermittent
        # heights); a missing block at the tail boundary is fine.
        continue
    try:
        blk = json.loads(r.stdout)
    except Exception:
        continue
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): continue
    for tx in txs:
        if not isinstance(tx, dict): continue
        frm   = tx.get("from", "")
        fee   = int(tx.get("fee", 0) or 0)
        nonce = tx.get("nonce")
        if isinstance(frm, str) and frm:
            by_sender_count[frm] += 1
            by_sender_fee[frm]   += fee
            if isinstance(nonce, int):
                sender_nonces[frm].add(nonce)
        total_tx += 1

# Top senders. Proxy for mempool concentration: who has been heaviest
# in the recent producer drains.
top_senders = sorted(
    by_sender_count.items(),
    key=lambda kv: (-kv[1], -by_sender_fee[kv[0]], kv[0])
)[:20]

# Nonce-gap scan across recent applied blocks. Same dense/sparse logic
# as the FULL aggregator; in fallback mode we're looking at applied
# nonces (which should NEVER have gaps post-apply if the chain is
# honest), so any gap is a strong signal of operator-side trouble.
nonce_gap_senders = []
for frm, ns_set in sender_nonces.items():
    if len(ns_set) < 2: continue
    ns = sorted(ns_set)
    lo, hi = ns[0], ns[-1]
    span = hi - lo
    found = None
    if span <= 1000:
        for n in range(lo + 1, hi):
            if n not in ns_set:
                found = n
                break
    else:
        for n in ns:
            if (n - 1) not in ns_set and (n - 1) >= lo:
                found = n - 1
                break
            if (n + 1) not in ns_set and (n + 1) <= hi:
                found = n + 1
                break
    if found is not None:
        nonce_gap_senders.append({"from": frm, "gap_at_nonce": found,
                                  "min_nonce": lo, "max_nonce": hi,
                                  "pending_count": len(ns_set)})

# Top-1 share is computed from recent-block tx counts. depth here is
# the proxy (status.mempool_size is also reported for the depth tier).
total_entries = total_tx if total_tx > 0 else 1
top1_count    = top_senders[0][1] if top_senders else 0
top1_addr     = top_senders[0][0] if top_senders else ""
top1_share_bps = (top1_count * 10000) // total_entries if total_tx > 0 else 0

# Anomaly classification in FALLBACK mode:
#   - depth_critical / warn fire from status.mempool_size (no per-tx
#     records but the scalar is reliable);
#   - single_sender_dominant is a PROXY signal (recent-applied basis,
#     not pending basis) — still useful, labelled as such in output;
#   - stuck_transactions is INDETERMINATE (no received_at_block
#     visibility) — we DO NOT add it to anomalies, but we add a marker
#     to the JSON so callers can distinguish "no stuck txs" from "we
#     couldn't check";
#   - nonce_gap_detected fires from applied-block scan.
anomalies = []
if status_depth > depth_crit:
    anomalies.append("mempool_depth_critical")
elif status_depth > depth_warn:
    anomalies.append("mempool_depth_warn")
sender_thr_bps = int(round(sender_thr * 10000))
if total_tx >= 20 and top1_share_bps > sender_thr_bps:
    anomalies.append("single_sender_dominant")
if nonce_gap_senders:
    anomalies.append("nonce_gap_detected")

result = {
    "mode":                "FALLBACK",
    "fallback_window":     {"from": from_h, "to": to_h, "blocks": to_h - from_h + 1},
    "depth":               status_depth,
    "status_mempool_size": status_depth,
    "status_drift_warn":   False,
    "total_fee":           sum(by_sender_fee.values()),
    "oldest_pending_block":  None,
    "oldest_age_blocks":   None,
    "stuck_tx_count":      None,                # INDETERMINATE
    "age_threshold":       age_thr,
    "age_histogram":       None,                # INDETERMINATE
    "by_type":             {},                  # not aggregated in fallback
    "total_recent_tx":     total_tx,
    "top_senders": [
        {
            "rank":         i + 1,
            "from":         frm,
            "count":        cnt,
            "fee_total":    by_sender_fee[frm],
            "oldest_block": None,                # INDETERMINATE
            "share_bps":    (cnt * 10000) // total_entries if total_tx > 0 else 0,
        }
        for i, (frm, cnt) in enumerate(top_senders)
    ],
    "top1_share_bps":      top1_share_bps,
    "top1_address":        top1_addr,
    "sender_threshold":    sender_thr,
    "sender_threshold_bps":sender_thr_bps,
    "nonce_gap_senders":   nonce_gap_senders,
    "depth_warn":          depth_warn,
    "depth_crit":          depth_crit,
    "anomalies":           anomalies,
    "head_height":         to_h,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
  if [ "$?" -ne 0 ]; then
    echo "operator_mempool_inspector: FALLBACK-mode aggregation failed" >&2
    exit 1
  fi
fi

# ── Step 5: render envelope (JSON or human) ─────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
head_h    = int(sys.argv[5])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

mode             = r["mode"]
depth            = r["depth"]
anomalies        = r["anomalies"]
anom_count       = len(anomalies)
top_senders      = r["top_senders"]
nonce_gaps       = r["nonce_gap_senders"]
sender_thr_bps   = r["sender_threshold_bps"]
top1_share_bps   = r["top1_share_bps"]

def render_pct(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def short(addr):
    if isinstance(addr, str) and addr.startswith("0x") and len(addr) >= 14:
        return addr[:14] + "..."
    if isinstance(addr, str) and len(addr) > 36:
        return addr[:33] + "..."
    return addr

if json_out:
    envelope = {
        "rpc_port":     port,
        "head_height":  head_h,
        "mode":         mode,
        "mempool": {
            "total_depth":       depth,
            "status_mempool_size": r["status_mempool_size"],
            "status_drift_warn": r["status_drift_warn"],
            "total_fee":         r["total_fee"],
            "oldest_pending":    r.get("oldest_pending_block"),
            "oldest_age_blocks": r.get("oldest_age_blocks"),
            "stuck_tx_count":    r.get("stuck_tx_count"),
            "age_threshold":     r["age_threshold"],
            "age_histogram":     r["age_histogram"],
            "by_type":           r["by_type"],
            "by_sender":         top_senders,
            "top1_share_bps":    top1_share_bps,
            "top1_address":      r["top1_address"],
            "sender_threshold":  r["sender_threshold"],
            "nonce_gap_senders": nonce_gaps,
        },
        "depth_thresholds": {
            "warn":     r["depth_warn"],
            "critical": r["depth_crit"],
        },
        "anomalies": anomalies,
    }
    if mode == "FALLBACK":
        envelope["fallback_window"]  = r["fallback_window"]
        envelope["total_recent_tx"]  = r["total_recent_tx"]
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_mempool_inspector: no anomalies (port {port}, mode {mode})")
    sys.exit(0)

print(f"=== Mempool inspector (port {port}, mode {mode}) ===")
print(f"Chain height:    {head_h}")
print(f"Mempool depth:   {depth} "
      f"(warn>{r['depth_warn']}, critical>{r['depth_crit']})")

if mode == "FULL":
    drift = "" if not r["status_drift_warn"] else " [DRIFT]"
    print(f"  via status:    {r['status_mempool_size']}{drift}")
    print(f"  via mempool:   {depth}")
    age_h = r["age_histogram"] or {}
    if depth > 0 and not anom_only:
        print("Age histogram (blocks waiting):")
        for label in ("0-10", "11-50", "51-100", "101-500", "501+"):
            n = age_h.get(label, 0)
            print(f"  {label:>8}: {n}")
        oldest_blk = r.get("oldest_pending_block")
        oldest_age = r.get("oldest_age_blocks", 0)
        if oldest_blk is not None:
            print(f"Oldest pending: block {oldest_blk} ({oldest_age} blocks old)")
        else:
            print("Oldest pending: (no received_at_block on any tx)")
        if r["by_type"]:
            print("By type:")
            for ty in sorted(r["by_type"].keys()):
                n = r["by_type"][ty]
                pct = (n * 1000 // depth) if depth > 0 else 0
                print(f"  {ty:<14}: {n:>6} ({pct/10:.1f}%)")
else:
    # FALLBACK mode: explain the limitation clearly.
    win = r["fallback_window"]
    print()
    print("[INFO] mempool RPC not exposed; this script requires --rpc-port to a")
    print("       daemon that supports mempool inspection. Falling back to")
    print("       header-level audit only.")
    print(f"       Walked recent window [{win['from']}..{win['to']}] "
          f"({win['blocks']} blocks, {r['total_recent_tx']} txs).")
    print("       Per-tx age + stuck-transaction detection: INDETERMINATE.")

if top_senders and not anom_only:
    print()
    label = "Top senders by mempool entry count" if mode == "FULL" \
            else "Top senders by RECENT-BLOCK tx count (proxy)"
    print(f"{label}:")
    print(f"  {'rank':>4}  {'from':<40}  {'count':>6}  {'share':>6}  {'fee':>10}")
    for s in top_senders:
        share = render_pct(s["share_bps"])
        print(f"  {s['rank']:>4}  {short(s['from']):<40}  "
              f"{s['count']:>6}  {share:>6}  {s['fee_total']:>10}")

print()
if anom_count == 0:
    print("[OK] Mempool within configured thresholds")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "mempool_depth_critical" in anomalies:
        print(f"  mempool_depth_critical  : depth = {depth} "
              f"(> {r['depth_crit']} critical threshold) — "
              "investigate stalled processing")
    if "mempool_depth_warn" in anomalies:
        print(f"  mempool_depth_warn      : depth = {depth} "
              f"(> {r['depth_warn']} warn threshold) — review for "
              "upcoming saturation")
    if "single_sender_dominant" in anomalies:
        basis = "of mempool" if mode == "FULL" else "of recent-block tx (proxy)"
        print(f"  single_sender_dominant  : '{short(r['top1_address'])}' = "
              f"{render_pct(top1_share_bps)} {basis} "
              f"(> {render_pct(sender_thr_bps)} threshold; Sybil-flood signal)")
    if "stuck_transactions" in anomalies:
        n = r.get("stuck_tx_count", 0)
        oldest = r.get("oldest_age_blocks", 0)
        print(f"  stuck_transactions      : {n} tx(s) older than "
              f"{r['age_threshold']} blocks (oldest {oldest} blocks) — "
              "miner-side rejection or fee-priority issue")
    if "nonce_gap_detected" in anomalies:
        n = len(nonce_gaps)
        print(f"  nonce_gap_detected      : {n} sender(s) with nonce holes — "
              "sender-side bug or replay scenario worth review")
        for g in nonce_gaps[:5]:
            print(f"    - {short(g['from'])}: gap at nonce {g['gap_at_nonce']} "
                  f"(observed range [{g['min_nonce']}..{g['max_nonce']}], "
                  f"{g['pending_count']} entries)")
        if n > 5:
            print(f"    ... ({n - 5} more)")
    if mode == "FALLBACK" and ("stuck_transactions" not in anomalies):
        print("  NOTE                     : stuck_transactions check skipped "
              "(INDETERMINATE in FALLBACK mode — no per-tx age visibility)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_mempool_inspector: rendering failed" >&2
  exit 1
fi

# ── Step 6: exit-code policy ────────────────────────────────────────────────
# Mirrors operator_stake_concentration / operator_payments_audit: exit 2
# only when --anomalies-only is set AND ≥1 anomaly fired. Default
# informational mode always exits 0 on a clean RPC pipeline. Per-anomaly
# severity (critical vs warn) is encoded in the LABEL inside the
# anomalies list — operator alert scripts can grep for
# `mempool_depth_critical` if they need to escalate.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_mempool_inspector: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "${TMP_FALLBACK:-}" "$TMP_ANOM" 2>/dev/null' EXIT
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
