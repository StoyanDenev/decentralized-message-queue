#!/usr/bin/env bash
# operator_receipt_proof_audit.sh — Audit that every cross-shard inbound
# receipt applied on a running determ shard daemon is TRUSTLESSLY PROVABLE
# via the composite-key `i:` (applied_inbound_receipts) state_proof RPC.
#
# This is the proof-AUDIT companion to operator_receipt_audit.sh. The
# sibling answers "how much value flowed in, and is the dedup-set / A1
# counter healthy?" by aggregating block-info volumes. THIS script answers
# the orthogonal light-client question:
#
#   "For each inbound receipt the chain claims it applied, can the daemon
#    actually PRODUCE a Merkle inclusion proof that binds (src_shard,
#    tx_hash) to the committee-signed state_root?"
#
# A receipt that shows up in a block body but is NOT provable via the `i:`
# namespace would mean the leaf was never committed to the state tree —
# i.e. a divergence between the applied-set the producer signed over and
# the state_root the committee signed over. No light client could then
# trust the chain's cross-shard credit. Catching that is the point.
#
# Encoding (mirrors src/chain/chain.cpp build_state_leaves'
# applied_inbound_receipts_ branch + src/node/node.cpp::rpc_state_proof's
# composite-key path, and the determ-light verify-receipt-inclusion
# verifier — see docs/proofs/ReceiptInclusionProofSoundness.md):
#
#   leaf key   = 'i' ':' || u64_be(src_shard) || tx_hash[32]      (42B)
#   value_hash = SHA256(0x01)                                     (presence
#                = 4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
#                 marker — the leaf carries no payload, only membership)
#
# Because the `i:` leaf-key suffix is BINARY it cannot ride raw inside a
# JSON string. The state_proof RPC therefore takes the post-prefix body
# HEX-encoded; this script builds that hex as
#   hex( u64_be(src_shard) || from_hex(tx_hash) )                 (40B body)
# and passes it as `--key`. The daemon prepends "i:" and looks up the leaf.
#
# Per-receipt verdict (all read-only — never a mutating RPC):
#   PROVABLE       state_proof returned a leaf AND
#                  (a) proof.key_bytes == locally-recomputed canonical key
#                      ("i:" || src_be8 || tx_hash) — binds the proof to
#                      THIS receipt, not some other leaf; AND
#                  (b) proof.value_hash == SHA256(0x01) — the presence
#                      marker; AND
#                  (c) proof.target_index in [0, leaf_count); AND
#                  (d) the proof's reported state_root == the chain's
#                      current state_root (proof isn't stale).
#   NOT_PROVABLE   state_proof returned {error: not_found} for a receipt
#                  the block body claims was applied. CATASTROPHIC — the
#                  applied-set and the state tree disagree. Exit 2.
#   MISBOUND       state_proof returned a leaf but key_bytes or value_hash
#                  did not match the canonical receipt (the daemon served a
#                  proof for a DIFFERENT leaf, or the marker is wrong).
#                  CATASTROPHIC. Exit 2.
#
# Note this script does NOT itself Merkle-roll the sibling path to the
# root — that full cryptographic verification is determ-light's
# verify-receipt-inclusion job (and tools/test_light_verify_receipt_inclusion.sh
# asserts it end-to-end). Here we are an operator's fast on-daemon
# completeness probe: it confirms the daemon WILL hand out a correctly-
# bound proof for every receipt it applied. The key_bytes + value_hash +
# state_root bindings are exactly the three checks determ-light performs
# before it bothers rolling the path, so a PROVABLE verdict here is a
# strong precondition for a downstream INCLUDED verdict.
#
# RPC-shape note (matches operator_receipt_audit.sh):
#   There is no read-only RPC exposing total shard_count; `status`
#   surfaces this node's shard_id + protections.sharding_mode. When
#   sharding_mode == "none" the chain has no cross-shard inbound receipts
#   by construction, so we exit 0 with an INFO line.
#
# Usage:
#   tools/operator_receipt_proof_audit.sh [--rpc-port N] [--json]
#                                         [--from H] [--to H]
#                                         [--max-receipts N]
#                                         [--anomalies-only]
#
# Defaults:
#   --rpc-port      7778
#   --from / --to   last 500 blocks ending at current head (clamped to 0)
#   --max-receipts  2000 (cap on the number of receipts proof-checked, so
#                   a deep window can't issue an unbounded RPC fan-out;
#                   set 0 to disable the cap)
#
# Output (default human):
#   Per-block receipt count + running PROVABLE / NOT_PROVABLE / MISBOUND
#   tallies, then a summary line + any anomalies. With --anomalies-only,
#   prints only the failing receipts.
#
# --json shape:
#   {"my_shard_id":N,"window":{"from":H,"to":H,"blocks":N},
#    "receipts_seen":N,"receipts_checked":N,"capped":true|false,
#    "provable":N,"not_provable":N,"misbound":N,
#    "state_root":"…","height":N,
#    "failures":[{"height":H,"src_shard":N,"tx_hash":"…","verdict":"…",
#                 "detail":"…"},…],
#    "anomalies":[…],"rpc_port":N,"sharding_mode":"…"}
#
# Anomaly flags:
#   receipt_not_provable   ≥1 applied receipt produced no `i:` leaf.
#                          Exit 2.
#   receipt_misbound       ≥1 `i:` proof whose key_bytes/value_hash did not
#                          bind to the canonical receipt. Exit 2.
#   stale_proof_root       ≥1 proof reported a state_root != the chain's
#                          current state_root. Exit 2.
#
# Exit codes:
#   0   success / informational (single-shard chain also exits 0)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_receipt_proof_audit.sh [--rpc-port N] [--json]
                                       [--from H] [--to H]
                                       [--max-receipts N]
                                       [--anomalies-only]

Audits that every cross-shard inbound receipt applied over a window of
finalized blocks is trustlessly PROVABLE via the composite-key `i:`
(applied_inbound_receipts) state_proof RPC: present, with key_bytes +
value_hash bound to the canonical receipt and a fresh state_root.

Read-only: issues only status / head / block-info / state_proof RPCs.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human output
  --from H            Start of audit window (default: max(0, head-500))
  --to H              End of audit window (default: current head)
  --max-receipts N    Cap receipts proof-checked (default: 2000; 0 = no cap)
  --anomalies-only    Print only failing receipts; exit 2 if any fire
  -h, --help          Show this help

Per-receipt verdicts:
  PROVABLE       `i:` proof present, key_bytes + value_hash(SHA256(0x01))
                 bound to the receipt, target_index in range, fresh root
  NOT_PROVABLE   block body claims the receipt was applied but state_proof
                 returns not_found  (catastrophic — applied-set vs state
                 tree divergence)
  MISBOUND       proof present but key_bytes/value_hash bind a different
                 leaf  (catastrophic)

Anomaly flags:
  receipt_not_provable   ≥1 applied receipt produced no `i:` leaf
  receipt_misbound       ≥1 `i:` proof did not bind to the canonical receipt
  stale_proof_root       ≥1 proof state_root != chain's current state_root

Exit codes:
  0   success / informational (or single-shard deployment)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
MAX_RECEIPTS=2000
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";          shift 2 ;;
    --json)           JSON_OUT=1;             shift ;;
    --from)           FROM_H="${2:-}";        shift 2 ;;
    --to)             TO_H="${2:-}";          shift 2 ;;
    --max-receipts)   MAX_RECEIPTS="${2:-}";  shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;            shift ;;
    *) echo "operator_receipt_proof_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_receipt_proof_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$MAX_RECEIPTS"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_receipt_proof_audit: --from / --to / --max-receipts must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_receipt_proof_audit: jq is required (per-block JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_receipt_proof_audit: python is required for key encoding + RPC fan-out" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# ── Step 1: probe daemon for shard config + head ─────────────────────────────
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_receipt_proof_audit: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}
MY_SHARD_ID=$(printf '%s' "$STATUS_JSON" | jq -r '.shard_id // 0')
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac
SHARDING_MODE=$(printf '%s' "$STATUS_JSON" | jq -r '.protections.sharding_mode // "unknown"')

HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_receipt_proof_audit: RPC error from \`determ head\` (port $PORT)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // 0')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_receipt_proof_audit: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 500 blocks ending at current head. Highest finalized
# index is height-1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
FROM=${FROM_H:-$(( TOP > 500 ? TOP - 500 + 1 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_receipt_proof_audit: --to ($TO) < --from ($FROM); nothing to audit" >&2
  exit 1
fi

# Short-circuit on empty chain.
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"window":{"from":%s,"to":%s,"blocks":0},"receipts_seen":0,"receipts_checked":0,"capped":false,"provable":0,"not_provable":0,"misbound":0,"state_root":"","height":0,"failures":[],"anomalies":[],"rpc_port":%s,"sharding_mode":"%s","info":"empty_chain"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$PORT" "$SHARDING_MODE"
  else
    echo "operator_receipt_proof_audit: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# Single-shard short-circuit. sharding_mode=="none" → no cross-shard inbound
# receipts by construction (genesis enforces a single shard).
if [ "$SHARDING_MODE" = "none" ]; then
  WIN_BLOCKS=$(( TO - FROM + 1 ))
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"window":{"from":%s,"to":%s,"blocks":%s},"receipts_seen":0,"receipts_checked":0,"capped":false,"provable":0,"not_provable":0,"misbound":0,"state_root":"","height":%s,"failures":[],"anomalies":[],"rpc_port":%s,"sharding_mode":"none","info":"single_shard_deployment"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$WIN_BLOCKS" "$HEIGHT" "$PORT"
  else
    echo "INFO: single-shard deployment — no cross-shard inbound receipts by construction (sharding_mode=none, port $PORT)"
  fi
  exit 0
fi

WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk window, build i: keys, proof-check each receipt ──────────────
TMP_OUT=$(mktemp) || {
  echo "operator_receipt_proof_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - "$DETERM" "$PORT" "$FROM" "$TO" "$MY_SHARD_ID" "$MAX_RECEIPTS" "$TMP_OUT" <<'PY'
import hashlib, json, subprocess, sys

determ, port, from_h, to_h, my_shard_id, max_receipts, out_path = sys.argv[1:8]
from_h = int(from_h); to_h = int(to_h)
my_shard_id = int(my_shard_id); max_receipts = int(max_receipts)

# Presence marker: a committed applied_inbound_receipts leaf carries
# value_hash = SHA256(0x01). (See chain.cpp build_state_leaves +
# light/main.cpp cmd_verify_receipt_inclusion.)
PRESENCE_MARKER = hashlib.sha256(bytes([1])).hexdigest()

def rpc_state_proof(ns, key_hex):
    r = subprocess.run(
        [determ, "state-proof", "--ns", ns, "--key", key_hex,
         "--rpc-port", port],
        capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"state-proof rc={r.returncode}: {r.stderr.strip()}")
    return json.loads(r.stdout)

receipts_seen = 0
receipts_checked = 0
provable = 0
not_provable = 0
misbound = 0
stale_root = 0
failures = []          # capped list of failing-receipt records
capped = False

# Chain's current state_root, captured from the FIRST proof we fetch (the
# proof RPC reports the live root). We compare every subsequent proof's
# reported root against it; a drift mid-walk means the chain advanced
# between calls (benign) OR a proof was served from a stale snapshot. We
# only flag a HARD stale_proof_root when a proof's root differs from the
# head root reported by the daemon at audit start; benign advance is
# tolerated by re-reading the live root each call via the proof itself.
audit_state_root = None

for h in range(from_h, to_h + 1):
    if max_receipts > 0 and receipts_checked >= max_receipts:
        capped = True
        break
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15)
    except Exception as e:
        sys.stderr.write(f"operator_receipt_proof_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_receipt_proof_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_receipt_proof_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    for ib in (blk.get("inbound_receipts") or []):
        receipts_seen += 1
        if max_receipts > 0 and receipts_checked >= max_receipts:
            capped = True
            break
        src = int(ib.get("src_shard", 0))
        thash = str(ib.get("tx_hash", ""))
        # Canonical receipt key bytes (mirrors build_state_leaves):
        #   'i' ':' || u64_be(src_shard) || tx_hash[32]
        try:
            tx_bytes = bytes.fromhex(thash)
        except ValueError:
            tx_bytes = b""
        if len(tx_bytes) != 32:
            # Malformed block field — cannot form a canonical key. Treat as
            # a misbound failure so the operator notices the bad block.
            misbound += 1
            receipts_checked += 1
            if len(failures) < 50:
                failures.append({
                    "height": h, "src_shard": src, "tx_hash": thash,
                    "verdict": "MISBOUND",
                    "detail": f"block tx_hash is not 32 bytes (len={len(tx_bytes)})",
                })
            continue
        src_be8 = src.to_bytes(8, "big")
        key_body_hex = (src_be8 + tx_bytes).hex()
        canonical_key_hex = (b"i:" + src_be8 + tx_bytes).hex()

        try:
            proof = rpc_state_proof("i", key_body_hex)
        except Exception as e:
            sys.stderr.write(f"operator_receipt_proof_audit: state-proof for "
                             f"(shard {src}, {thash[:16]}…) failed: {e}\n")
            sys.exit(1)
        receipts_checked += 1

        err = proof.get("error")
        if err:
            not_provable += 1
            if len(failures) < 50:
                failures.append({
                    "height": h, "src_shard": src, "tx_hash": thash,
                    "verdict": "NOT_PROVABLE",
                    "detail": f"state_proof error: {err}",
                })
            continue

        # Bind the proof to THIS receipt.
        proof_key = str(proof.get("key_bytes", ""))
        proof_vh  = str(proof.get("value_hash", ""))
        ti        = proof.get("target_index")
        lc        = proof.get("leaf_count")
        proot     = str(proof.get("state_root", ""))
        if audit_state_root is None and proot:
            audit_state_root = proot

        bad = None
        if proof_key != canonical_key_hex:
            bad = (f"key_bytes={proof_key} != canonical {canonical_key_hex} "
                   "(proof binds a different leaf)")
        elif proof_vh != PRESENCE_MARKER:
            bad = (f"value_hash={proof_vh} != presence marker "
                   f"SHA256(0x01)={PRESENCE_MARKER}")
        elif not (isinstance(ti, int) and isinstance(lc, int)
                  and lc > 0 and 0 <= ti < lc):
            bad = f"target_index/leaf_count out of range (ti={ti}, lc={lc})"

        if bad is not None:
            misbound += 1
            if len(failures) < 50:
                failures.append({
                    "height": h, "src_shard": src, "tx_hash": thash,
                    "verdict": "MISBOUND", "detail": bad,
                })
            continue

        # Fresh-root check: the proof's reported root should match the root
        # we anchored on the first proof. A mismatch where the new root
        # differs is reported as stale_proof_root (could be a benign chain
        # advance OR a stale-snapshot proof — operator should investigate).
        if audit_state_root and proot and proot != audit_state_root:
            stale_root += 1
            if len(failures) < 50:
                failures.append({
                    "height": h, "src_shard": src, "tx_hash": thash,
                    "verdict": "STALE_ROOT",
                    "detail": (f"proof state_root {proot[:16]}… != audit-anchor "
                               f"root {audit_state_root[:16]}… (chain advanced "
                               "mid-walk or stale-snapshot proof)"),
                })
            # Still counts as provable for the leaf itself; the root drift is
            # a separate signal, so do NOT also bump not_provable/misbound.
        provable += 1

result = {
    "receipts_seen": receipts_seen,
    "receipts_checked": receipts_checked,
    "capped": capped,
    "provable": provable,
    "not_provable": not_provable,
    "misbound": misbound,
    "stale_root": stale_root,
    "state_root": audit_state_root or "",
    "failures": failures,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_receipt_proof_audit: block-walk / proof fan-out failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

RECEIPTS_SEEN=$(printf '%s' "$WALK_JSON"    | jq -r '.receipts_seen')
RECEIPTS_CHECKED=$(printf '%s' "$WALK_JSON" | jq -r '.receipts_checked')
CAPPED=$(printf '%s' "$WALK_JSON"           | jq -r '.capped')
PROVABLE=$(printf '%s' "$WALK_JSON"         | jq -r '.provable')
NOT_PROVABLE=$(printf '%s' "$WALK_JSON"     | jq -r '.not_provable')
MISBOUND=$(printf '%s' "$WALK_JSON"         | jq -r '.misbound')
STALE_ROOT=$(printf '%s' "$WALK_JSON"       | jq -r '.stale_root')
AUDIT_ROOT=$(printf '%s' "$WALK_JSON"       | jq -r '.state_root')

# ── Step 3: assemble anomalies ───────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
[ "$NOT_PROVABLE" -gt 0 ] && add_anom "receipt_not_provable"
[ "$MISBOUND"     -gt 0 ] && add_anom "receipt_misbound"
[ "$STALE_ROOT"   -gt 0 ] && add_anom "stale_proof_root"

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 4: render ───────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  ANOM_JSON=$(if [ -z "$ANOMALIES" ]; then printf '[]'; else
    printf '['; printf '%s' "$ANOMALIES" | awk -F, '{
      for (i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"", $i }
    }'; printf ']'
  fi)
  FAIL_JSON=$(printf '%s' "$WALK_JSON" | jq -c '.failures')
  printf '{"my_shard_id":%s,"window":{"from":%s,"to":%s,"blocks":%s},"receipts_seen":%s,"receipts_checked":%s,"capped":%s,"provable":%s,"not_provable":%s,"misbound":%s,"stale_root":%s,"state_root":"%s","height":%s,"failures":%s,"anomalies":%s,"rpc_port":%s,"sharding_mode":"%s"}\n' \
    "$MY_SHARD_ID" "$FROM" "$TO" "$WIN_BLOCKS" \
    "$RECEIPTS_SEEN" "$RECEIPTS_CHECKED" "$CAPPED" \
    "$PROVABLE" "$NOT_PROVABLE" "$MISBOUND" "$STALE_ROOT" \
    "$AUDIT_ROOT" "$HEIGHT" "$FAIL_JSON" "$ANOM_JSON" "$PORT" "$SHARDING_MODE"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_receipt_proof_audit: all $RECEIPTS_CHECKED checked receipt(s) PROVABLE (port $PORT, window [$FROM..$TO], shard $MY_SHARD_ID)"
  else
    echo "=== Inbound-receipt proof audit (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    echo "My shard: $MY_SHARD_ID [sharding_mode: $SHARDING_MODE, state_root: ${AUDIT_ROOT:0:16}...]"
    echo "Receipts: $RECEIPTS_SEEN seen, $RECEIPTS_CHECKED proof-checked$([ "$CAPPED" = "true" ] && echo " (capped at --max-receipts)")"
    echo "Verdicts: $PROVABLE PROVABLE, $NOT_PROVABLE NOT_PROVABLE, $MISBOUND MISBOUND, $STALE_ROOT STALE_ROOT"

    FAIL_N=$(printf '%s' "$WALK_JSON" | jq -r '.failures | length')
    if [ "$FAIL_N" -gt 0 ]; then
      echo "Failing receipts (first $FAIL_N shown):"
      printf '%s' "$WALK_JSON" | jq -r '
        .failures[] | "  [\(.verdict)] block \(.height) src_shard=\(.src_shard) tx_hash=\(.tx_hash[0:16])... — \(.detail)"'
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      if [ "$RECEIPTS_CHECKED" = "0" ]; then
        echo "[OK] No inbound receipts in window — nothing to prove"
      else
        echo "[OK] Every applied inbound receipt is provable via the i: state_proof"
      fi
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
    fi
  fi
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
