#!/usr/bin/env bash
# operator_dapp_registry_proof_audit.sh — Audit that every DApp a running determ
# daemon reports as registered is TRUSTLESSLY PROVABLE via the simple-key `d:`
# (dapp_registry) state_proof RPC.
#
# This is the `d:`-namespace member of the trustless proof-audit family, the
# DApp-registry sibling of the composite-key proof-audit trilogy:
#   operator_receipt_proof_audit.sh        (`i:` applied_inbound_receipts)
#   operator_merge_audit.sh                (`m:` merge_state)
#   operator_pending_param_proof_audit.sh  (`p:` pending_param_changes)
# Those three audit the COMPOSITE-key (binary-suffix) namespaces; THIS one closes
# the family across the simple-key application namespace, answering the
# application-layer light-client question:
#
#   "For each DApp the chain claims it has REGISTERED (the d:-namespace registry
#    leaf the V2-DAPP-DESIGN.md light-client read path resolves), can the daemon
#    actually PRODUCE a Merkle inclusion proof that binds the owning domain (the
#    `d:` key) AND the entry's canonical fields (service_pubkey, endpoint_url,
#    topics, retention, metadata, registered_at/active_from/inactive_from) to the
#    committee-signed state_root?"
#
# A DApp surfaced by the `dapp_info` / `dapp_list` projection but NOT provable
# via the `d:` namespace would mean the registry view the node serves over RPC
# disagrees with the state_root the committee signed over — a light client could
# then not trust the node's claim that a given DApp (its discovery endpoint, its
# service encryption key) is on-chain. Catching that divergence is the point.
#
# Encoding (mirrors src/chain/chain.cpp build_state_leaves' dapp_registry_ branch
# + src/node/node.cpp::rpc_state_proof's simple-key `d:` path):
#
#   leaf key   = 'd' ':' || domain                    (UTF-8 domain, no hex)
#                Unlike the i:/m:/p: composite keys, the `d:` suffix is the
#                printable owning domain, so it rides raw in the state_proof RPC
#                `--key` param (the daemon prepends "d:"). key_bytes in the proof
#                response is the hex of those raw bytes.
#   value_hash = SHA256( service_pubkey[32]
#                        || u64_be(registered_at)
#                        || u64_be(active_from)
#                        || u64_be(inactive_from)
#                        || u64_be(len(endpoint_url)) || endpoint_url
#                        || u64_be(len(topics))
#                          (per topic: u64_be(len(topic)) || topic)
#                        || u64_be(retention)
#                        || u64_be(len(metadata)) || metadata )
#                (SHA256Builder::append(uint64_t) is big-endian; append(string) /
#                 append(bytes) are raw — see src/crypto/sha256.cpp. retention is
#                 a u8 promoted to u64 before hashing, matching chain.cpp.) The
#                `d:` leaf carries a real multi-field payload, so this audit
#                RECOMPUTES the exact expected value_hash from the RPC-reported
#                `dapp_info` fields and asserts the proof matches — binding the
#                proof to the precise registry entry, not merely to "some leaf at
#                this domain".
#
# Per-DApp verdict (all read-only — never a mutating RPC):
#   PROVABLE       state_proof returned a leaf AND
#                  (a) proof.key_bytes == locally-recomputed canonical key
#                      ("d:" || domain) — binds the proof to THIS domain; AND
#                  (b) proof.value_hash == locally-recomputed
#                      SHA256(service_pubkey||registered_at||active_from||
#                      inactive_from||len(url)||url||len(topics)||topics||
#                      retention||len(meta)||meta) — binds the proof to the EXACT
#                      registry entry the node reports; AND
#                  (c) proof.target_index in [0, leaf_count); AND
#                  (d) the proof's reported state_root == the audit-anchor
#                      state_root (proof isn't served from a stale snapshot).
#   NOT_PROVABLE   state_proof returned {error: not_found} for a DApp the
#                  dapp_list RPC claims is registered. CATASTROPHIC — the registry
#                  projection and the state tree disagree. Exit 2.
#   MISBOUND       state_proof returned a leaf but key_bytes or value_hash did not
#                  match the canonical registry entry (the daemon served a proof
#                  for a DIFFERENT leaf, or the entry the proof commits to differs
#                  from what dapp_info reports). CATASTROPHIC. Exit 2.
#
# Note this script does NOT itself Merkle-roll the sibling path to the root —
# that full cryptographic verification is `determ verify-state-proof`'s job. Here
# we are an operator's fast on-daemon completeness probe: it confirms the daemon
# WILL hand out a correctly-bound proof for every DApp it reports as registered,
# with key_bytes + value_hash + state_root all bound. Those are exactly the
# bindings verify-state-proof checks before it bothers rolling the path, so a
# PROVABLE verdict here is a strong precondition for a downstream verified
# inclusion.
#
# Usage:
#   tools/operator_dapp_registry_proof_audit.sh [--rpc-port N] [--json]
#                                               [--prefix P] [--topic T]
#                                               [--max-dapps N]
#                                               [--anomalies-only]
#
# Defaults:
#   --rpc-port      7778
#   --prefix        unset (audit ALL registered DApps). When set, only DApps whose
#                   owning domain has this prefix are enumerated — the same
#                   server-side filter `determ dapp-list --prefix` applies.
#   --topic         unset (no topic filter). Passed to dapp-list --topic; only
#                   DApps advertising the topic are enumerated.
#   --max-dapps     2000 (cap on the number of DApps proof-checked so a chain with
#                   a huge registry can't issue an unbounded RPC fan-out; set 0 to
#                   disable the cap)
#
# Output (default human):
#   Per-DApp domain + running PROVABLE / NOT_PROVABLE / MISBOUND tallies, then a
#   summary line + any anomalies. With --anomalies-only, prints only the failing
#   DApps.
#
# --json shape:
#   {"filter":{"prefix":"…"|null,"topic":"…"|null},"total_registered":N,
#    "list_count":N,"dapps_seen":N,"dapps_checked":N,"capped":true|false,
#    "provable":N,"not_provable":N,"misbound":N,"stale_root":N,
#    "state_root":"…","height":N,
#    "failures":[{"domain":"…","verdict":"…","detail":"…"},…],
#    "anomalies":[…],"rpc_port":N}
#
# Anomaly flags:
#   dapp_not_provable      ≥1 registered DApp produced no `d:` leaf. Exit 2.
#   dapp_misbound          ≥1 `d:` proof whose key_bytes/value_hash did not bind
#                          to the canonical registry entry. Exit 2.
#   stale_proof_root       ≥1 proof reported a state_root != the audit-anchor
#                          state_root. Exit 2.
#   count_mismatch         dapp_list's reported `count` != the length of its
#                          `dapps` array (node-internal inconsistency — both are
#                          computed from the same registry projection). Exit 2
#                          under --anomalies-only.
#
# Exit codes:
#   0   success / informational (no registered DApps also exits 0)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_registry_proof_audit.sh [--rpc-port N] [--json]
                                             [--prefix P] [--topic T]
                                             [--max-dapps N]
                                             [--anomalies-only]

Audits that every DApp the daemon reports as registered is trustlessly PROVABLE
via the simple-key `d:` (dapp_registry) state_proof RPC: present, with key_bytes
bound to the owning domain, value_hash bound to the entry's canonical fields
(service_pubkey, endpoint_url, topics, retention, metadata, registered_at /
active_from / inactive_from), and a fresh state_root.

Read-only: issues only dapp-list / dapp-info / head / status / state-proof RPCs.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human output
  --prefix P          Only audit DApps whose owning domain has this prefix
                      (server-side dapp-list filter; default: all DApps)
  --topic T           Only audit DApps advertising this topic
                      (server-side dapp-list filter; default: no topic filter)
  --max-dapps N       Cap DApps proof-checked (default: 2000; 0 = no cap)
  --anomalies-only    Print only failing DApps; exit 2 if any fire
  -h, --help          Show this help

Per-DApp verdicts:
  PROVABLE       `d:` proof present, key_bytes bound to the domain, value_hash
                 bound to the canonical entry fields, index in range, fresh root
  NOT_PROVABLE   dapp_list claims the DApp is registered but state_proof returns
                 not_found  (catastrophic — registry projection vs state tree
                 divergence)
  MISBOUND       proof present but key_bytes/value_hash bind a different leaf or
                 a different registry entry  (catastrophic)

Anomaly flags:
  dapp_not_provable   ≥1 registered DApp produced no `d:` leaf
  dapp_misbound       ≥1 `d:` proof did not bind to the canonical entry
  stale_proof_root    ≥1 proof state_root != audit-anchor state_root
  count_mismatch      dapp_list's `count` != its `dapps` array length

Exit codes:
  0   success / informational (or no DApps registered)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
PREFIX=""
TOPIC=""
MAX_DAPPS=2000
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";          shift 2 ;;
    --json)           JSON_OUT=1;             shift ;;
    --prefix)         PREFIX="${2:-}";        shift 2 ;;
    --topic)          TOPIC="${2:-}";         shift 2 ;;
    --max-dapps)      MAX_DAPPS="${2:-}";     shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;            shift ;;
    *) echo "operator_dapp_registry_proof_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied integer values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_registry_proof_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$MAX_DAPPS" in *[!0-9]*)
  echo "operator_dapp_registry_proof_audit: --max-dapps must be an unsigned integer (got '$MAX_DAPPS')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_dapp_registry_proof_audit: jq is required (dapp_list JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_dapp_registry_proof_audit: python is required for value-hash recompute + RPC fan-out" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# ── Step 1: anchor head/state_root ───────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_registry_proof_audit: RPC error from \`determ head\` (port $PORT)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // 0')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_dapp_registry_proof_audit: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: enumerate the registry projection (server-side prefix/topic filter)─
# dapp-list returns {"height":H,"count":N,"dapps":[{domain,endpoint_url,topics,
# active},…]}. We re-fetch each DApp's FULL entry via dapp-info below (the
# compact dapp-list row omits service_pubkey/retention/metadata/registered_at
# which the value_hash recompute needs).
LIST_ARGS=(dapp-list --json --rpc-port "$PORT")
[ -n "$PREFIX" ] && LIST_ARGS+=(--prefix "$PREFIX")
[ -n "$TOPIC" ]  && LIST_ARGS+=(--topic "$TOPIC")
LIST_JSON=$("$DETERM" "${LIST_ARGS[@]}" 2>/dev/null) || {
  echo "operator_dapp_registry_proof_audit: RPC error from \`determ dapp-list\` (port $PORT)" >&2
  exit 1
}
if ! printf '%s' "$LIST_JSON" | jq -e 'has("dapps") and (.dapps | type == "array")' >/dev/null 2>&1; then
  echo "operator_dapp_registry_proof_audit: dapp-list returned malformed JSON (port $PORT)" >&2
  exit 1
fi
LIST_COUNT=$(printf '%s' "$LIST_JSON"  | jq -r '.count // 0')
ARR_LEN=$(printf '%s' "$LIST_JSON"     | jq -r '.dapps | length')
case "$LIST_COUNT" in *[!0-9]*|"") LIST_COUNT=0 ;; esac

# Short-circuit when nothing is registered — no `d:` leaves exist by
# construction. A reported count != array length here is itself a node-internal
# divergence (both read the same projection); flag rather than silently exit.
if [ "$ARR_LEN" -eq 0 ]; then
  if [ "$LIST_COUNT" -ne 0 ]; then
    if [ "$JSON_OUT" = "1" ]; then
      printf '{"filter":{"prefix":%s,"topic":%s},"total_registered":%s,"list_count":%s,"dapps_seen":0,"dapps_checked":0,"capped":false,"provable":0,"not_provable":0,"misbound":0,"stale_root":0,"state_root":"","height":%s,"failures":[],"anomalies":["count_mismatch"],"rpc_port":%s,"info":"empty_array_but_count_nonzero"}\n' \
        "$([ -z "$PREFIX" ] && echo null || jq -Rn --arg p "$PREFIX" '$p')" \
        "$([ -z "$TOPIC" ]  && echo null || jq -Rn --arg t "$TOPIC"  '$t')" \
        "$ARR_LEN" "$LIST_COUNT" "$HEIGHT" "$PORT"
    else
      echo "[ANOMALY] dapp-list reports count=$LIST_COUNT but the dapps array is empty (port $PORT)"
    fi
    [ "$ANOM_ONLY" = "1" ] && exit 2
    exit 0
  fi
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"filter":{"prefix":%s,"topic":%s},"total_registered":0,"list_count":0,"dapps_seen":0,"dapps_checked":0,"capped":false,"provable":0,"not_provable":0,"misbound":0,"stale_root":0,"state_root":"","height":%s,"failures":[],"anomalies":[],"rpc_port":%s,"info":"no_registered_dapps"}\n' \
      "$([ -z "$PREFIX" ] && echo null || jq -Rn --arg p "$PREFIX" '$p')" \
      "$([ -z "$TOPIC" ]  && echo null || jq -Rn --arg t "$TOPIC"  '$t')" \
      "$HEIGHT" "$PORT"
  else
    echo "INFO: no registered DApps in the queried scope — no d: leaves to prove (port $PORT)"
  fi
  exit 0
fi

# ── Step 3: per-DApp dapp-info fetch + value-hash recompute + proof fan-out ───
TMP_OUT=$(mktemp) || {
  echo "operator_dapp_registry_proof_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

# Feed the dapp-list `dapps` array on stdin; the walker fetches dapp-info +
# state-proof per domain. Keeping the fan-out in one Python pass makes the
# JSON/human output identical for downstream consumers.
printf '%s' "$LIST_JSON" | jq -c '.dapps' \
  | "$PY" - "$DETERM" "$PORT" "$MAX_DAPPS" "$TMP_OUT" <<'PY'
import hashlib, json, subprocess, sys

determ, port, max_dapps, out_path = sys.argv[1:5]
max_dapps = int(max_dapps)

try:
    dapps = json.load(sys.stdin)
except Exception:
    sys.stderr.write("operator_dapp_registry_proof_audit: could not parse dapp-list dapps array\n")
    sys.exit(1)
if not isinstance(dapps, list):
    sys.stderr.write("operator_dapp_registry_proof_audit: dapp-list dapps is not a list\n")
    sys.exit(1)

def dapp_value_hash(info):
    # Mirror build_state_leaves' d: branch (src/chain/chain.cpp):
    #   service_pubkey[32]
    #   u64_be(registered_at) || u64_be(active_from) || u64_be(inactive_from)
    #   u64_be(len(endpoint_url)) || endpoint_url
    #   u64_be(len(topics)) (per topic: u64_be(len(t)) || t)
    #   u64_be(retention)    (u8 promoted to u64)
    #   u64_be(len(metadata)) || metadata
    # SHA256Builder.append(uint64_t) is big-endian; append(string)/append(bytes)
    # are raw (src/crypto/sha256.cpp). service_pubkey + metadata arrive hex from
    # rpc_dapp_info (to_hex); endpoint_url + topics are UTF-8 strings.
    h = hashlib.sha256()
    sp = bytes.fromhex(str(info.get("service_pubkey", "")))
    if len(sp) != 32:
        raise ValueError(f"service_pubkey is {len(sp)}B, expected 32")
    h.update(sp)
    h.update(int(info.get("registered_at", 0)).to_bytes(8, "big"))
    h.update(int(info.get("active_from", 0)).to_bytes(8, "big"))
    h.update(int(info.get("inactive_from", 0)).to_bytes(8, "big"))
    url = str(info.get("endpoint_url", "")).encode("utf-8")
    h.update(len(url).to_bytes(8, "big"))
    h.update(url)
    topics = info.get("topics") or []
    h.update(len(topics).to_bytes(8, "big"))
    for t in topics:
        tb = str(t).encode("utf-8")
        h.update(len(tb).to_bytes(8, "big"))
        h.update(tb)
    h.update(int(info.get("retention", 0)).to_bytes(8, "big"))
    meta = bytes.fromhex(str(info.get("metadata", "")))
    h.update(len(meta).to_bytes(8, "big"))
    h.update(meta)
    return h.hexdigest()

def rpc(args):
    r = subprocess.run([determ, *args, "--rpc-port", port],
                       capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} rc={r.returncode}: {r.stderr.strip()}")
    return json.loads(r.stdout)

dapps_seen = 0
dapps_checked = 0
provable = 0
not_provable = 0
misbound = 0
stale_root = 0
failures = []          # capped list of failing-DApp records
capped = False
audit_state_root = None

for d in dapps:
    if not isinstance(d, dict):
        continue
    domain = str(d.get("domain", ""))
    if not domain:
        continue
    dapps_seen += 1
    if max_dapps > 0 and dapps_checked >= max_dapps:
        capped = True
        break

    # Fetch the FULL registry entry — the compact dapp-list row omits the fields
    # the value_hash needs (service_pubkey / retention / metadata / *_at).
    try:
        info = rpc(["dapp-info", "--domain", domain])
    except Exception as ex:
        sys.stderr.write(f"operator_dapp_registry_proof_audit: dapp-info for '{domain}' failed: {ex}\n")
        sys.exit(1)
    if isinstance(info, dict) and info.get("error"):
        # dapp_list claimed it but dapp_info now says not_found: registry view
        # is internally inconsistent across the two projections.
        dapps_checked += 1
        not_provable += 1
        if len(failures) < 50:
            failures.append({
                "domain": domain, "verdict": "NOT_PROVABLE",
                "detail": f"dapp_info error: {info.get('error')} (listed but not resolvable)",
            })
        continue

    # Canonical d: key bytes (mirrors build_state_leaves: "d:" + domain, raw).
    canonical_key_hex = (b"d:" + domain.encode("utf-8")).hex()
    try:
        expected_vh = dapp_value_hash(info)
    except Exception as ex:
        dapps_checked += 1
        misbound += 1
        if len(failures) < 50:
            failures.append({
                "domain": domain, "verdict": "MISBOUND",
                "detail": f"cannot recompute canonical value_hash from dapp_info: {ex}",
            })
        continue

    # Simple-key namespace: --key is the raw domain (daemon prepends "d:").
    try:
        proof = rpc(["state-proof", "--ns", "d", "--key", domain])
    except Exception as ex:
        sys.stderr.write(f"operator_dapp_registry_proof_audit: state-proof for '{domain}' failed: {ex}\n")
        sys.exit(1)
    dapps_checked += 1

    err = proof.get("error")
    if err:
        not_provable += 1
        if len(failures) < 50:
            failures.append({
                "domain": domain, "verdict": "NOT_PROVABLE",
                "detail": f"state_proof error: {err}",
            })
        continue

    # Bind the proof to THIS registry entry.
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
               f"SHA256(service_pubkey||registered_at||active_from||"
               f"inactive_from||len(url)||url||len(topics)||topics||"
               f"retention||len(meta)||meta)={expected_vh} "
               "(proof commits to a different registry entry)")
    elif not (isinstance(ti, int) and isinstance(lc, int)
              and lc > 0 and 0 <= ti < lc):
        bad = f"target_index/leaf_count out of range (ti={ti}, lc={lc})"

    if bad is not None:
        misbound += 1
        if len(failures) < 50:
            failures.append({"domain": domain, "verdict": "MISBOUND", "detail": bad})
        continue

    # Fresh-root check: every proof should report the same root we anchored on
    # the first proof. A drift means the chain advanced mid-walk (benign) OR a
    # proof was served from a stale snapshot — operator should investigate.
    if audit_state_root and proot and proot != audit_state_root:
        stale_root += 1
        if len(failures) < 50:
            failures.append({
                "domain": domain, "verdict": "STALE_ROOT",
                "detail": (f"proof state_root {proot[:16]}... != audit-anchor "
                           f"root {audit_state_root[:16]}... (chain advanced "
                           "mid-walk or stale-snapshot proof)"),
            })
        # The leaf itself still proved out; the root drift is a separate signal,
        # so do NOT also bump not_provable/misbound.
    provable += 1

result = {
    "dapps_seen": dapps_seen,
    "dapps_checked": dapps_checked,
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
  echo "operator_dapp_registry_proof_audit: registry walk / proof fan-out failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

DAPPS_SEEN=$(printf '%s' "$WALK_JSON"    | jq -r '.dapps_seen')
DAPPS_CHECKED=$(printf '%s' "$WALK_JSON" | jq -r '.dapps_checked')
CAPPED=$(printf '%s' "$WALK_JSON"        | jq -r '.capped')
PROVABLE=$(printf '%s' "$WALK_JSON"      | jq -r '.provable')
NOT_PROVABLE=$(printf '%s' "$WALK_JSON"  | jq -r '.not_provable')
MISBOUND=$(printf '%s' "$WALK_JSON"      | jq -r '.misbound')
STALE_ROOT=$(printf '%s' "$WALK_JSON"    | jq -r '.stale_root')
AUDIT_ROOT=$(printf '%s' "$WALK_JSON"    | jq -r '.state_root')

# ── Step 4: assemble anomalies ───────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
[ "$NOT_PROVABLE" -gt 0 ] && add_anom "dapp_not_provable"
[ "$MISBOUND"     -gt 0 ] && add_anom "dapp_misbound"
[ "$STALE_ROOT"   -gt 0 ] && add_anom "stale_proof_root"
# dapp_list's `count` and its `dapps` array length read the same projection; a
# disagreement is a node-internal inconsistency worth surfacing.
[ "$LIST_COUNT" -ne "$ARR_LEN" ] && add_anom "count_mismatch"

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
  PREFIX_FIELD=$([ -z "$PREFIX" ] && echo null || jq -Rn --arg p "$PREFIX" '$p')
  TOPIC_FIELD=$([ -z "$TOPIC" ]   && echo null || jq -Rn --arg t "$TOPIC"  '$t')
  printf '{"filter":{"prefix":%s,"topic":%s},"total_registered":%s,"list_count":%s,"dapps_seen":%s,"dapps_checked":%s,"capped":%s,"provable":%s,"not_provable":%s,"misbound":%s,"stale_root":%s,"state_root":"%s","height":%s,"failures":%s,"anomalies":%s,"rpc_port":%s}\n' \
    "$PREFIX_FIELD" "$TOPIC_FIELD" "$ARR_LEN" "$LIST_COUNT" "$DAPPS_SEEN" "$DAPPS_CHECKED" "$CAPPED" \
    "$PROVABLE" "$NOT_PROVABLE" "$MISBOUND" "$STALE_ROOT" \
    "$AUDIT_ROOT" "$HEIGHT" "$FAIL_JSON" "$ANOM_JSON" "$PORT"
else
  SCOPE_DESC="all registered"
  [ -n "$PREFIX" ] && SCOPE_DESC="prefix '$PREFIX'"
  [ -n "$TOPIC" ]  && SCOPE_DESC="$SCOPE_DESC topic '$TOPIC'"
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_dapp_registry_proof_audit: all $DAPPS_CHECKED checked DApp(s) PROVABLE (port $PORT, $SCOPE_DESC)"
  else
    echo "=== DApp-registry proof audit (port $PORT, $SCOPE_DESC, $ARR_LEN registered) ==="
    echo "Registry: $ARR_LEN via dapp-list, count=$LIST_COUNT [state_root: ${AUDIT_ROOT:0:16}..., height: $HEIGHT]"
    echo "DApps: $DAPPS_SEEN seen, $DAPPS_CHECKED proof-checked$([ "$CAPPED" = "true" ] && echo " (capped at --max-dapps)")"
    echo "Verdicts: $PROVABLE PROVABLE, $NOT_PROVABLE NOT_PROVABLE, $MISBOUND MISBOUND, $STALE_ROOT STALE_ROOT"

    FAIL_N=$(printf '%s' "$WALK_JSON" | jq -r '.failures | length')
    if [ "$FAIL_N" -gt 0 ]; then
      echo "Failing DApps (first $FAIL_N shown):"
      printf '%s' "$WALK_JSON" | jq -r '
        .failures[] | "  [\(.verdict)] domain=\(.domain) — \(.detail)"'
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      if [ "$DAPPS_CHECKED" = "0" ]; then
        echo "[OK] No DApps in scope — nothing to prove"
      else
        echo "[OK] Every registered DApp is provable via the d: state_proof"
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
