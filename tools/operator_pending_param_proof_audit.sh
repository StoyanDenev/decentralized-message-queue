#!/usr/bin/env bash
# operator_pending_param_proof_audit.sh — Audit that every governance-staged
# PARAM_CHANGE entry a running determ daemon reports as PENDING is TRUSTLESSLY
# PROVABLE via the composite-key `p:` (pending_param_changes) state_proof RPC.
#
# This is the `p:`-namespace member of the composite-key proof-audit trilogy,
# alongside operator_receipt_proof_audit.sh (`i:` applied_inbound_receipts) and
# operator_merge_audit.sh (`m:` merge_state). Those two answer "is every applied
# cross-shard receipt / active merge committed to the state tree?"; THIS one
# answers the orthogonal governance question:
#
#   "For each parameter change the chain claims it has STAGED (it will mutate a
#    named chain constant at a future effective_height), can the daemon actually
#    PRODUCE a Merkle inclusion proof that binds (effective_height, idx) AND the
#    scheduled (name, value) to the committee-signed state_root?"
#
# A staged change surfaced by the `pending_params` RPC but NOT provable via the
# `p:` namespace would mean the governance projection the node serves over RPC
# disagrees with the state_root the committee signed over — a light client could
# then not trust the node's claim about what the chain will become. Catching
# that divergence is the point.
#
# Encoding (mirrors src/chain/chain.cpp build_state_leaves'
# pending_param_changes_ branch + src/node/node.cpp::rpc_state_proof's
# composite-key `p:` path):
#
#   leaf key   = 'p' ':' || u64_be(effective_height) || u32_be(idx)   (14B)
#                idx = the entry's 0-based position WITHIN its effective_height
#                bucket (insertion = apply order). pending_param_changes_ is a
#                std::map keyed by effective_height (ascending), so the
#                `pending_params` RPC streams buckets in that order and entries
#                in bucket-insertion order — exactly the idx build_state_leaves
#                assigns.
#   value_hash = SHA256( u64_be(len(name)) || name
#                        || u64_be(len(value)) || value )
#                (SHA256Builder::append(uint64_t) is big-endian; append(string)
#                 / append(bytes) are raw — see src/crypto/sha256.cpp). Unlike
#                the `i:` presence marker, the `p:` leaf carries a real payload,
#                so this audit recomputes the EXACT expected value_hash from the
#                RPC-reported (name, value_hex) and asserts the proof matches —
#                binding the proof to the precise scheduled mutation, not merely
#                to "some leaf at this (eff_height, idx)".
#
# Because the `p:` leaf-key suffix is BINARY it cannot ride raw inside a JSON
# string. The state_proof RPC therefore takes the post-prefix body HEX-encoded;
# this script builds that hex as
#   hex( u64_be(effective_height) || u32_be(idx) )                    (12B body)
# and passes it as `--key`. The daemon prepends "p:" and looks up the leaf.
#
# Per-entry verdict (all read-only — never a mutating RPC):
#   PROVABLE       state_proof returned a leaf AND
#                  (a) proof.key_bytes == locally-recomputed canonical key
#                      ("p:" || eff_be8 || idx_be4) — binds the proof to THIS
#                      (effective_height, idx), not some other leaf; AND
#                  (b) proof.value_hash == locally-recomputed
#                      SHA256(len(name)||name||len(value)||value) — binds the
#                      proof to the EXACT scheduled (name, value); AND
#                  (c) proof.target_index in [0, leaf_count); AND
#                  (d) the proof's reported state_root == the audit-anchor
#                      state_root (proof isn't served from a stale snapshot).
#   NOT_PROVABLE   state_proof returned {error: not_found} for an entry the
#                  pending_params RPC claims is staged. CATASTROPHIC — the
#                  governance projection and the state tree disagree. Exit 2.
#   MISBOUND       state_proof returned a leaf but key_bytes or value_hash did
#                  not match the canonical staged entry (the daemon served a
#                  proof for a DIFFERENT leaf, or the scheduled value the proof
#                  commits to differs from what the RPC reports). CATASTROPHIC.
#                  Exit 2.
#
# Note this script does NOT itself Merkle-roll the sibling path to the root —
# that full cryptographic verification is `determ verify-state-proof`'s job.
# Here we are an operator's fast on-daemon completeness probe: it confirms the
# daemon WILL hand out a correctly-bound proof for every change it reports as
# staged, with key_bytes + value_hash + state_root all bound. Those are exactly
# the bindings verify-state-proof checks before it bothers rolling the path, so
# a PROVABLE verdict here is a strong precondition for a downstream verified
# inclusion.
#
# RPC-shape note: the `pending_params` RPC (CLI `determ pending-params`) returns
# the full staged list ordered by effective_height ascending. Governance may be
# disabled or simply have nothing staged — both yield an empty list, in which
# case we exit 0 with an INFO line (no `p:` leaves exist by construction).
#
# Usage:
#   tools/operator_pending_param_proof_audit.sh [--rpc-port N] [--json]
#                                               [--at-height H]
#                                               [--max-entries N]
#                                               [--anomalies-only]
#
# Defaults:
#   --rpc-port      7778
#   --at-height     unset (audit ALL staged entries). When set, only entries
#                   with effective_height <= H are proof-checked (the same
#                   client-side filter `determ pending-params --at-height`
#                   applies); idx is still computed against the FULL bucket so
#                   the canonical key matches build_state_leaves.
#   --max-entries   2000 (cap on the number of entries proof-checked so a chain
#                   with a huge staged backlog can't issue an unbounded RPC
#                   fan-out; set 0 to disable the cap)
#
# Output (default human):
#   Per-entry effective_height / name + running PROVABLE / NOT_PROVABLE /
#   MISBOUND tallies, then a summary line + any anomalies. With
#   --anomalies-only, prints only the failing entries.
#
# --json shape:
#   {"window":{"at_height":H|null},"total_staged":N,"status_count":N,
#    "entries_seen":N,"entries_checked":N,"capped":true|false,
#    "provable":N,"not_provable":N,"misbound":N,"stale_root":N,
#    "state_root":"…","height":N,
#    "failures":[{"effective_height":H,"idx":I,"name":"…","verdict":"…",
#                 "detail":"…"},…],
#    "anomalies":[…],"rpc_port":N}
#
# Anomaly flags:
#   pending_not_provable   ≥1 staged change produced no `p:` leaf. Exit 2.
#   pending_misbound       ≥1 `p:` proof whose key_bytes/value_hash did not
#                          bind to the canonical staged entry. Exit 2.
#   stale_proof_root       ≥1 proof reported a state_root != the audit-anchor
#                          state_root. Exit 2.
#   count_mismatch         status's pending_param_changes count != the length
#                          of the pending_params list (node-internal
#                          inconsistency — both read the same map). Exit 2
#                          under --anomalies-only.
#
# Exit codes:
#   0   success / informational (no staged changes also exits 0)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_pending_param_proof_audit.sh [--rpc-port N] [--json]
                                             [--at-height H]
                                             [--max-entries N]
                                             [--anomalies-only]

Audits that every governance-staged PARAM_CHANGE entry the daemon reports as
pending is trustlessly PROVABLE via the composite-key `p:`
(pending_param_changes) state_proof RPC: present, with key_bytes bound to
(effective_height, idx), value_hash bound to the scheduled (name, value), and a
fresh state_root.

Read-only: issues only pending-params / head / status / state-proof RPCs.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human output
  --at-height H       Only proof-check entries with effective_height <= H
                      (default: audit ALL staged entries). idx is still
                      computed against the full bucket so the key matches.
  --max-entries N     Cap entries proof-checked (default: 2000; 0 = no cap)
  --anomalies-only    Print only failing entries; exit 2 if any fire
  -h, --help          Show this help

Per-entry verdicts:
  PROVABLE       `p:` proof present, key_bytes bound to (eff_height, idx),
                 value_hash bound to the scheduled (name, value), index in
                 range, fresh root
  NOT_PROVABLE   pending_params claims the change is staged but state_proof
                 returns not_found  (catastrophic — governance projection vs
                 state tree divergence)
  MISBOUND       proof present but key_bytes/value_hash bind a different leaf
                 or a different scheduled value  (catastrophic)

Anomaly flags:
  pending_not_provable   ≥1 staged change produced no `p:` leaf
  pending_misbound       ≥1 `p:` proof did not bind to the canonical entry
  stale_proof_root       ≥1 proof state_root != audit-anchor state_root
  count_mismatch         status's pending_param_changes count != the
                         pending_params list length (node-internal divergence)

Exit codes:
  0   success / informational (or governance disabled / nothing staged)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
AT_HEIGHT=""
MAX_ENTRIES=2000
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";          shift 2 ;;
    --json)           JSON_OUT=1;             shift ;;
    --at-height)      AT_HEIGHT="${2:-}";     shift 2 ;;
    --max-entries)    MAX_ENTRIES="${2:-}";   shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;            shift ;;
    *) echo "operator_pending_param_proof_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_pending_param_proof_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$AT_HEIGHT" "$MAX_ENTRIES"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_pending_param_proof_audit: --at-height / --max-entries must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_pending_param_proof_audit: jq is required (pending_params JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_pending_param_proof_audit: python is required for key encoding + RPC fan-out" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# ── Step 1: probe daemon for the staged-change count + head ──────────────────
# `status` carries `pending_param_changes` — the integer count of staged
# entries. We cross-check it against the length of the detailed `pending_params`
# list below; a mismatch is itself a node-internal divergence (the count and the
# list are computed from the same pending_param_changes_ map, so they must
# agree) and is surfaced as a count_mismatch anomaly.
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_pending_param_proof_audit: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}
STATUS_COUNT=$(printf '%s' "$STATUS_JSON" | jq -r '.pending_param_changes // 0')
case "$STATUS_COUNT" in *[!0-9]*|"") STATUS_COUNT=0 ;; esac

HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_pending_param_proof_audit: RPC error from \`determ head\` (port $PORT)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // 0')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_pending_param_proof_audit: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: pull the staged-change list (full, ordered by effective_height) ──
PENDING_JSON=$("$DETERM" pending-params --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_pending_param_proof_audit: RPC error from \`determ pending-params\` (port $PORT)" >&2
  exit 1
}
if ! printf '%s' "$PENDING_JSON" | jq -e 'type == "array"' >/dev/null 2>&1; then
  echo "operator_pending_param_proof_audit: pending-params returned non-array JSON (port $PORT)" >&2
  exit 1
fi
TOTAL_STAGED=$(printf '%s' "$PENDING_JSON" | jq -r 'length')

# Short-circuit when nothing is staged — no `p:` leaves exist by construction.
# A status_count != 0 here would mean status and pending_params disagree on the
# empty set; flag it rather than silently exiting clean.
if [ "$TOTAL_STAGED" -eq 0 ]; then
  if [ "$STATUS_COUNT" -ne 0 ]; then
    if [ "$JSON_OUT" = "1" ]; then
      printf '{"window":{"at_height":%s},"entries_seen":0,"entries_checked":0,"capped":false,"provable":0,"not_provable":0,"misbound":0,"stale_root":0,"state_root":"","height":%s,"failures":[],"anomalies":["count_mismatch"],"rpc_port":%s,"status_count":%s,"info":"empty_list_but_status_count_nonzero"}\n' \
        "$([ -z "$AT_HEIGHT" ] && echo null || echo "$AT_HEIGHT")" "$HEIGHT" "$PORT" "$STATUS_COUNT"
    else
      echo "[ANOMALY] status reports $STATUS_COUNT staged change(s) but pending_params returned an empty list (port $PORT)"
    fi
    [ "$ANOM_ONLY" = "1" ] && exit 2
    exit 0
  fi
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"window":{"at_height":%s},"entries_seen":0,"entries_checked":0,"capped":false,"provable":0,"not_provable":0,"misbound":0,"stale_root":0,"state_root":"","height":%s,"failures":[],"anomalies":[],"rpc_port":%s,"status_count":0,"info":"no_pending_changes"}\n' \
      "$([ -z "$AT_HEIGHT" ] && echo null || echo "$AT_HEIGHT")" "$HEIGHT" "$PORT"
  else
    echo "INFO: no pending PARAM_CHANGE entries staged — no p: leaves to prove (port $PORT)"
  fi
  exit 0
fi

# ── Step 3: per-entry idx assignment + proof fan-out ─────────────────────────
TMP_OUT=$(mktemp) || {
  echo "operator_pending_param_proof_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

printf '%s' "$PENDING_JSON" | "$PY" - "$DETERM" "$PORT" "$AT_HEIGHT" "$MAX_ENTRIES" "$TMP_OUT" <<'PY'
import hashlib, json, subprocess, sys

determ, port, at_height_arg, max_entries, out_path = sys.argv[1:6]
at_height = int(at_height_arg) if at_height_arg else None
max_entries = int(max_entries)

try:
    staged = json.load(sys.stdin)
except Exception:
    sys.stderr.write("operator_pending_param_proof_audit: could not parse pending_params JSON\n")
    sys.exit(1)
if not isinstance(staged, list):
    sys.stderr.write("operator_pending_param_proof_audit: pending_params is not a list\n")
    sys.exit(1)

def value_hash(name_bytes, value_bytes):
    # Mirror build_state_leaves' p: branch: SHA256Builder appends
    #   u64_be(len(name)) || name || u64_be(len(value)) || value.
    # append(uint64_t) is big-endian (src/crypto/sha256.cpp).
    h = hashlib.sha256()
    h.update(len(name_bytes).to_bytes(8, "big"))
    h.update(name_bytes)
    h.update(len(value_bytes).to_bytes(8, "big"))
    h.update(value_bytes)
    return h.hexdigest()

def rpc_state_proof(ns, key_hex):
    r = subprocess.run(
        [determ, "state-proof", "--ns", ns, "--key", key_hex,
         "--rpc-port", port],
        capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"state-proof rc={r.returncode}: {r.stderr.strip()}")
    return json.loads(r.stdout)

entries_seen = 0
entries_checked = 0
provable = 0
not_provable = 0
misbound = 0
stale_root = 0
failures = []          # capped list of failing-entry records
capped = False

# idx is the 0-based position WITHIN each effective_height bucket. The RPC
# streams entries grouped by effective_height ascending (pending_param_changes_
# is a std::map), so we reset the per-bucket counter whenever effective_height
# changes. This reproduces build_state_leaves' idx exactly — and crucially we
# compute it over the FULL list even when --at-height filters which entries we
# proof-check, so the canonical key still matches.
audit_state_root = None
prev_eff = None
bucket_idx = 0

for e in staged:
    if not isinstance(e, dict):
        continue
    try:
        eff = int(e.get("effective_height", 0))
    except (TypeError, ValueError):
        eff = 0
    if prev_eff is None or eff != prev_eff:
        bucket_idx = 0
        prev_eff = eff
    idx = bucket_idx
    bucket_idx += 1

    # --at-height filter: skip proof-checking entries that land past the cutoff,
    # but they STILL advanced bucket_idx above (so later same-bucket entries get
    # the right idx). This matches `determ pending-params --at-height` semantics.
    if at_height is not None and eff > at_height:
        continue

    entries_seen += 1
    if max_entries > 0 and entries_checked >= max_entries:
        capped = True
        break

    name = str(e.get("name", ""))
    value_hex = str(e.get("value_hex", ""))
    name_bytes = name.encode("utf-8")
    try:
        value_bytes = bytes.fromhex(value_hex) if value_hex else b""
    except ValueError:
        # Malformed RPC value field — cannot form a canonical value_hash.
        misbound += 1
        entries_checked += 1
        if len(failures) < 50:
            failures.append({
                "effective_height": eff, "idx": idx, "name": name,
                "verdict": "MISBOUND",
                "detail": f"pending_params value_hex is not valid hex ('{value_hex[:24]}')",
            })
        continue

    # Canonical p: key bytes (mirrors build_state_leaves):
    #   'p' ':' || u64_be(effective_height) || u32_be(idx)
    eff_be8 = eff.to_bytes(8, "big")
    idx_be4 = idx.to_bytes(4, "big")
    key_body_hex = (eff_be8 + idx_be4).hex()
    canonical_key_hex = (b"p:" + eff_be8 + idx_be4).hex()
    expected_vh = value_hash(name_bytes, value_bytes)

    try:
        proof = rpc_state_proof("p", key_body_hex)
    except Exception as ex:
        sys.stderr.write(f"operator_pending_param_proof_audit: state-proof for "
                         f"(eff {eff}, idx {idx}, '{name}') failed: {ex}\n")
        sys.exit(1)
    entries_checked += 1

    err = proof.get("error")
    if err:
        not_provable += 1
        if len(failures) < 50:
            failures.append({
                "effective_height": eff, "idx": idx, "name": name,
                "verdict": "NOT_PROVABLE",
                "detail": f"state_proof error: {err}",
            })
        continue

    # Bind the proof to THIS staged entry.
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
    elif proof_vh != expected_vh:
        bad = (f"value_hash={proof_vh} != expected "
               f"SHA256(len(name)||name||len(value)||value)={expected_vh} "
               "(proof commits to a different scheduled value)")
    elif not (isinstance(ti, int) and isinstance(lc, int)
              and lc > 0 and 0 <= ti < lc):
        bad = f"target_index/leaf_count out of range (ti={ti}, lc={lc})"

    if bad is not None:
        misbound += 1
        if len(failures) < 50:
            failures.append({
                "effective_height": eff, "idx": idx, "name": name,
                "verdict": "MISBOUND", "detail": bad,
            })
        continue

    # Fresh-root check: every proof should report the same root we anchored on
    # the first proof. A drift means the chain advanced mid-walk (benign) OR a
    # proof was served from a stale snapshot — operator should investigate.
    if audit_state_root and proot and proot != audit_state_root:
        stale_root += 1
        if len(failures) < 50:
            failures.append({
                "effective_height": eff, "idx": idx, "name": name,
                "verdict": "STALE_ROOT",
                "detail": (f"proof state_root {proot[:16]}... != audit-anchor "
                           f"root {audit_state_root[:16]}... (chain advanced "
                           "mid-walk or stale-snapshot proof)"),
            })
        # The leaf itself still proved out; the root drift is a separate signal,
        # so do NOT also bump not_provable/misbound.
    provable += 1

result = {
    "entries_seen": entries_seen,
    "entries_checked": entries_checked,
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
  echo "operator_pending_param_proof_audit: pending-param walk / proof fan-out failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

ENTRIES_SEEN=$(printf '%s' "$WALK_JSON"    | jq -r '.entries_seen')
ENTRIES_CHECKED=$(printf '%s' "$WALK_JSON" | jq -r '.entries_checked')
CAPPED=$(printf '%s' "$WALK_JSON"          | jq -r '.capped')
PROVABLE=$(printf '%s' "$WALK_JSON"        | jq -r '.provable')
NOT_PROVABLE=$(printf '%s' "$WALK_JSON"    | jq -r '.not_provable')
MISBOUND=$(printf '%s' "$WALK_JSON"        | jq -r '.misbound')
STALE_ROOT=$(printf '%s' "$WALK_JSON"      | jq -r '.stale_root')
AUDIT_ROOT=$(printf '%s' "$WALK_JSON"      | jq -r '.state_root')

# ── Step 4: assemble anomalies ───────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
[ "$NOT_PROVABLE" -gt 0 ] && add_anom "pending_not_provable"
[ "$MISBOUND"     -gt 0 ] && add_anom "pending_misbound"
[ "$STALE_ROOT"   -gt 0 ] && add_anom "stale_proof_root"
# status's count and pending_params' length read the same map; a disagreement
# is a node-internal inconsistency worth surfacing.
[ "$STATUS_COUNT" -ne "$TOTAL_STAGED" ] && add_anom "count_mismatch"

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 5: render ───────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  ANOM_JSON=$(if [ -z "$ANOMALIES" ]; then printf '[]'; else
    printf '['; printf '%s' "$ANOMALIES" | awk -F, '{
      for (i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"", $i }
    }'; printf ']'
  fi)
  FAIL_JSON=$(printf '%s' "$WALK_JSON" | jq -c '.failures')
  AT_FIELD=$([ -z "$AT_HEIGHT" ] && echo null || echo "$AT_HEIGHT")
  printf '{"window":{"at_height":%s},"total_staged":%s,"status_count":%s,"entries_seen":%s,"entries_checked":%s,"capped":%s,"provable":%s,"not_provable":%s,"misbound":%s,"stale_root":%s,"state_root":"%s","height":%s,"failures":%s,"anomalies":%s,"rpc_port":%s}\n' \
    "$AT_FIELD" "$TOTAL_STAGED" "$STATUS_COUNT" "$ENTRIES_SEEN" "$ENTRIES_CHECKED" "$CAPPED" \
    "$PROVABLE" "$NOT_PROVABLE" "$MISBOUND" "$STALE_ROOT" \
    "$AUDIT_ROOT" "$HEIGHT" "$FAIL_JSON" "$ANOM_JSON" "$PORT"
else
  WIN_DESC=$([ -z "$AT_HEIGHT" ] && echo "all staged" || echo "effective_height <= $AT_HEIGHT")
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_pending_param_proof_audit: all $ENTRIES_CHECKED checked staged change(s) PROVABLE (port $PORT, $WIN_DESC)"
  else
    echo "=== Pending-param proof audit (port $PORT, $WIN_DESC, $TOTAL_STAGED total staged) ==="
    echo "Staged: $TOTAL_STAGED via pending_params, $STATUS_COUNT via status [state_root: ${AUDIT_ROOT:0:16}..., height: $HEIGHT]"
    echo "Entries: $ENTRIES_SEEN seen, $ENTRIES_CHECKED proof-checked$([ "$CAPPED" = "true" ] && echo " (capped at --max-entries)")"
    echo "Verdicts: $PROVABLE PROVABLE, $NOT_PROVABLE NOT_PROVABLE, $MISBOUND MISBOUND, $STALE_ROOT STALE_ROOT"

    FAIL_N=$(printf '%s' "$WALK_JSON" | jq -r '.failures | length')
    if [ "$FAIL_N" -gt 0 ]; then
      echo "Failing entries (first $FAIL_N shown):"
      printf '%s' "$WALK_JSON" | jq -r '
        .failures[] | "  [\(.verdict)] eff_height=\(.effective_height) idx=\(.idx) name=\(.name) — \(.detail)"'
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      if [ "$ENTRIES_CHECKED" = "0" ]; then
        echo "[OK] No staged changes in window — nothing to prove"
      else
        echo "[OK] Every staged PARAM_CHANGE is provable via the p: state_proof"
      fi
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
    fi
  fi
fi

# ── Step 6: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
