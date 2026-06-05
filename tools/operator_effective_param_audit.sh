#!/usr/bin/env bash
# operator_effective_param_audit.sh — Trustlessly audits the CURRENT
# EFFECTIVE value of each governance-activatable consensus scalar against
# the committee-signed `k:` namespace state_root, and cross-references
# every whitelisted PARAM_CHANGE name against the daemon's PENDING (`p:`)
# staged changes.
#
# Theme positioning (governance parameter-change lifecycle):
#
#   A PARAM_CHANGE is STAGED into the `p:` namespace at an
#   effective_height (operator_pending_param_proof_audit.sh proves THOSE
#   — the SCHEDULED-but-not-yet-active changes). When the activation
#   height arrives, src/chain/chain.cpp::activate_pending_params drains
#   the effective_height<=b.index buckets exactly-once and writes the new
#   value into the per-Chain instance scalar (min_stake_ / suspension_slash_
#   / unstake_delay_). That ACTIVATED scalar is then committed into the
#   `k:` namespace of the state_root via build_state_leaves' const_leaf
#   calls. THIS script audits the OTHER END of the lifecycle: not what is
#   PENDING, but what is CURRENTLY EFFECTIVE — and proves that effective
#   value against the committee-anchored state_root.
#
# Sibling-script positioning (all read-only; none overlaps this surface):
#
#   operator_pending_param_proof_audit.sh   proves PENDING `p:` staged
#                                            changes (future activation)
#   operator_governance_audit.sh            pending posture from RPC
#                                            (no state_root proof)
#   operator_governance_history.sh          historical event timeline
#   operator_param_history.sh /             chronological PARAM_CHANGE
#   operator_param_change_history.sh         audit logs
#
#   operator_effective_param_audit.sh (THIS) is the only one that proves
#   the CURRENTLY-EFFECTIVE `k:`-namespace consensus scalar against the
#   state_root — the activated value, not a staged one.
#
# Provability classification (the load-bearing governance fact):
#
#   The validator whitelist (src/node/validator.cpp::kWhitelist) admits
#   nine PARAM_CHANGE names. They split into TWO classes by where the
#   activated value lands:
#
#     PROVABLE   MIN_STAKE / SUSPENSION_SLASH / UNSTAKE_DELAY have
#                per-Chain instance storage (min_stake_ / suspension_slash_
#                / unstake_delay_, set by activate_pending_params) AND a
#                build_state_leaves const_leaf ("min_stake" / "suspension_slash"
#                / "unstake_delay"). Their effective value is committed to
#                the `k:` namespace, so a state_proof binds it to the
#                committee-signed state_root.
#
#     HOOK_ONLY  bft_escalation_threshold / tx_commit_ms / block_sig_ms /
#                abort_claim_ms / param_keyholders / param_threshold have
#                NO per-Chain scalar; activate_pending_params forwards them
#                to the Node-installed hook (or they remain params.hpp
#                constants). They are NOT `k:` leaves, so there is no
#                state-root proof of their effective value today. This
#                script reports them as HOOK_ONLY (not provable via
#                state_proof) so an operator never mistakes the absence of
#                a proof for a missing parameter.
#
# Per-scalar verdict (PROVABLE class only; all read-only — never a
# mutating RPC):
#
#   VERIFIED       state_proof for `k:`+<leaf_name> returned a leaf AND
#                  (a) proof.key_bytes == locally-recomputed "k:"+<leaf_name>;
#                      AND
#                  (b) proof.value_hash == locally-recomputed
#                      SHA256( be8(expected_value) ) — binds the proof to
#                      the EXACT effective scalar value the operator
#                      asserts (const_leaf value-hash encoding: a single
#                      big-endian u64 per src/crypto/sha256.cpp
#                      SHA256Builder::append(uint64_t)); AND
#                  (c) proof.target_index in [0, leaf_count); AND
#                  (d) proof.height / proof.state_root == the audit-anchor
#                      state_root captured at start (proof isn't served
#                      from a stale snapshot).
#   MISMATCH       proof present but value_hash != SHA256(be8(expected)):
#                  the committee-signed state binds a DIFFERENT effective
#                  value than the operator expects. Exit 2.
#   NOT_PROVABLE   state_proof returned not_found for a `k:` leaf the chain
#                  always commits. CATASTROPHIC — the const_leaf set and
#                  the state tree disagree. Exit 2.
#
# The operator supplies the EXPECTED effective value per PROVABLE scalar
# via --expect NAME=VALUE (repeatable). Without an --expect for a scalar,
# the script cannot recompute value_hash (SHA256 is one-way — there is no
# inversion), so it reports that scalar as UNCHECKED (the proof exists and
# binds SOME value, but the audit can't assert WHICH without the operator's
# expected value). --expect is therefore how an operator pins the value it
# believes governance has activated and gets a trustless YES/NO against the
# state_root. Expected values are typically the genesis defaults plus every
# activated PARAM_CHANGE the operator has applied, or simply the value the
# operator reads from the deployment's config.
#
# A staged future change to a PROVABLE scalar is surfaced inline:
# `pending_change` lists each `p:` entry whose name maps to that scalar,
# with its effective_height and decoded value, so the operator sees both
# "what is effective now (proven)" and "what will change it (staged)".
#
# Usage:
#   tools/operator_effective_param_audit.sh [--rpc-port N]
#                                           [--expect NAME=VALUE ...]
#                                           [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --expect NAME=VAL   Assert the effective value of a PROVABLE scalar.
#                       NAME is the governance whitelist name (MIN_STAKE,
#                       SUSPENSION_SLASH, UNSTAKE_DELAY); VAL is an
#                       unsigned u64. Repeatable. Scalars without an
#                       --expect are reported UNCHECKED.
#   --json              Emit a single-line JSON envelope
#   --anomalies-only    Suppress the per-scalar table; exit 2 if >=1
#                       MISMATCH / NOT_PROVABLE / stale-root anomaly fired
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - state-root        current committee-anchored state_root + height
#   - state-proof       per `k:`-scalar Merkle inclusion proof
#   - pending-params    staged `p:` changes (future-change cross-reference)
#
# Exit codes:
#   0   audit completed; every checked scalar VERIFIED (or informational)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   >=1 MISMATCH / NOT_PROVABLE / stale-proof-root anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_effective_param_audit.sh [--rpc-port N]
                                         [--expect NAME=VALUE ...]
                                         [--json] [--anomalies-only]

Trustlessly audits the CURRENT EFFECTIVE value of each governance-
activatable consensus scalar (the values activate_pending_params writes
into the `k:` namespace of the state_root) against the committee-signed
state_root, and cross-references every whitelisted PARAM_CHANGE name
against the daemon's PENDING `p:` staged changes.

Distinct from operator_pending_param_proof_audit.sh (which proves the
PENDING `p:` staged changes) — this proves the CURRENTLY-EFFECTIVE
`k:`-namespace value, the OTHER end of the parameter-change lifecycle.

Provability classes:
  PROVABLE   MIN_STAKE / SUSPENSION_SLASH / UNSTAKE_DELAY — committed as
             `k:` leaves; effective value provable against state_root.
  HOOK_ONLY  bft_escalation_threshold / tx_commit_ms / block_sig_ms /
             abort_claim_ms / param_keyholders / param_threshold —
             forwarded to the Node hook; no `k:` leaf, not provable.

Per-scalar verdict (PROVABLE class):
  VERIFIED      proof present; key_bytes == "k:"+leaf_name AND
                value_hash == SHA256(be8(expected)) AND fresh state_root
  MISMATCH      proof binds a value != the operator's --expect (exit 2)
  NOT_PROVABLE  `k:` leaf absent from state tree (catastrophic; exit 2)
  UNCHECKED     no --expect for this scalar; proof exists but the audit
                cannot assert WHICH value it binds (SHA256 is one-way)

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --expect NAME=VAL   Assert a PROVABLE scalar's effective u64 value
                      (MIN_STAKE / SUSPENSION_SLASH / UNSTAKE_DELAY);
                      repeatable. Scalars without --expect are UNCHECKED.
  --json              Single-line JSON envelope instead of human report
  --anomalies-only    Suppress the per-scalar table; exit 2 if >=1
                      MISMATCH / NOT_PROVABLE / stale-root anomaly fired
  -h, --help          Show this help

Exit codes:
  0   audit completed; every checked scalar VERIFIED (or informational)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   >=1 MISMATCH / NOT_PROVABLE / stale-proof-root anomaly fired

JSON shape (--json):
  {"rpc_port":<P>,"height":<H>,"state_root":"<hex64>",
   "scalars":[
     {"whitelist_name":"MIN_STAKE","leaf_name":"min_stake",
      "class":"PROVABLE","verdict":"VERIFIED"|"MISMATCH"|"NOT_PROVABLE"|"UNCHECKED",
      "expected":<u64>|null,"value_hash":"<hex64>"|null,
      "target_index":<n>|null,"leaf_count":<n>|null,
      "pending_change":[{"effective_height":<H>,"value":<u64>|null,
                         "value_hex":"<hex>"}],
      "detail":"..."},
     {"whitelist_name":"bft_escalation_threshold","class":"HOOK_ONLY",
      "verdict":"NOT_APPLICABLE","pending_change":[...]}, ...],
   "anomalies":[{"kind":"...","name":"..."}, ...],
   "summary":{"provable":<n>,"verified":<n>,"mismatch":<n>,
              "not_provable":<n>,"unchecked":<n>,"hook_only":<n>,
              "pending_total":<n>,"anomaly_count":<n>}}
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
EXPECT_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";          shift 2 ;;
    --expect)         EXPECT_ARGS+=("${2:-}"); shift 2 ;;
    --json)           JSON_OUT=1;             shift ;;
    --anomalies-only) ANOM_ONLY=1;            shift ;;
    *) echo "operator_effective_param_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guard on the port.
case "$PORT" in *[!0-9]*|"")
  echo "operator_effective_param_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Validate each --expect NAME=VALUE up-front so a typo is caught before
# any subprocess fires. NAME must be a PROVABLE whitelist name; VALUE must
# be an unsigned integer that fits in u64.
EXPECT_PAIRS=""   # newline-separated NAME=VALUE, passed to Python
for kv in "${EXPECT_ARGS[@]:-}"; do
  [ -z "$kv" ] && continue
  case "$kv" in
    *=*) : ;;
    *) echo "operator_effective_param_audit: --expect must be NAME=VALUE (got '$kv')" >&2
       exit 1 ;;
  esac
  name="${kv%%=*}"
  val="${kv#*=}"
  case "$name" in
    MIN_STAKE|SUSPENSION_SLASH|UNSTAKE_DELAY) : ;;
    *) echo "operator_effective_param_audit: --expect NAME must be a PROVABLE scalar (MIN_STAKE | SUSPENSION_SLASH | UNSTAKE_DELAY), got '$name'" >&2
       exit 1 ;;
  esac
  case "$val" in
    ""|*[!0-9]*)
      echo "operator_effective_param_audit: --expect $name value must be an unsigned integer (got '$val')" >&2
      exit 1 ;;
  esac
  EXPECT_PAIRS="${EXPECT_PAIRS}${name}=${val}"$'\n'
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_effective_param_audit: python is required for value-hash recompute + RPC fan-out" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# Promote $DETERM to absolute (mirrors operator_governance_history.sh —
# Git Bash on Windows can fail subprocess.run with relative paths).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: anchor the chain's current state_root + height ───────────────────
STATE_ROOT_JSON=$("$DETERM" state-root --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_effective_param_audit: cannot reach daemon on rpc-port $PORT (state-root RPC failed)" >&2
  exit 1
}

# ── Step 2: pending-params (p: staged changes) for the future-change view ────
TMP_PENDING=$(mktemp 2>/dev/null) || {
  echo "operator_effective_param_audit: cannot create temp file" >&2
  exit 1
}
trap 'rm -f "$TMP_PENDING" 2>/dev/null' EXIT
"$DETERM" pending-params --json --rpc-port "$PORT" >"$TMP_PENDING" 2>/dev/null || {
  echo "operator_effective_param_audit: pending-params RPC failed (port $PORT)" >&2
  echo "  (requires a daemon exposing the pending_params RPC method)" >&2
  exit 1
}

# ── Step 3: per-scalar proof fetch + value-hash recompute + reconcile ────────
# Drive in Python: anchor the state_root, fan out one state-proof per
# PROVABLE `k:` scalar, recompute the const_leaf value_hash from each
# --expect, classify HOOK_ONLY names, and fold in pending `p:` changes.
"$PY" - "$DETERM_ABS" "$PORT" "$JSON_OUT" "$ANOM_ONLY" "$STATE_ROOT_JSON" \
       "$TMP_PENDING" "$EXPECT_PAIRS" <<'PY'
import hashlib, json, subprocess, sys

determ        = sys.argv[1]
port          = sys.argv[2]
json_out      = sys.argv[3] == "1"
anom_only     = sys.argv[4] == "1"
state_root_in = sys.argv[5]
pending_path  = sys.argv[6]
expect_blob   = sys.argv[7]

# ── Anchor: parse the state-root RPC envelope ─────────────────────────────
try:
    sr = json.loads(state_root_in)
except Exception as e:
    sys.stderr.write(f"operator_effective_param_audit: cannot parse state-root JSON: {e}\n")
    sys.exit(1)
if not isinstance(sr, dict) or "state_root" not in sr:
    sys.stderr.write("operator_effective_param_audit: state-root RPC returned no state_root field\n")
    sys.exit(1)
anchor_root = str(sr.get("state_root", ""))
anchor_height = int(sr.get("height", 0))

# ── Parse --expect NAME=VALUE pairs ───────────────────────────────────────
expected = {}
for line in expect_blob.splitlines():
    line = line.strip()
    if not line or "=" not in line:
        continue
    n, v = line.split("=", 1)
    expected[n] = int(v)

# ── Governance whitelist (src/node/validator.cpp::kWhitelist) split by where
# the activated value lands. PROVABLE names map to a build_state_leaves
# const_leaf (k: namespace) via their per-Chain scalar; HOOK_ONLY names are
# forwarded to the Node hook / remain params.hpp constants (no k: leaf). ──
# whitelist_name -> k: leaf_name (chain.cpp const_leaf argument)
PROVABLE = {
    "MIN_STAKE":        "min_stake",
    "SUSPENSION_SLASH": "suspension_slash",
    "UNSTAKE_DELAY":    "unstake_delay",
}
HOOK_ONLY = [
    "bft_escalation_threshold",
    "tx_commit_ms",
    "block_sig_ms",
    "abort_claim_ms",
    "param_keyholders",
    "param_threshold",
]

def const_leaf_value_hash(value_u64):
    """value_hash for a k: const_leaf: SHA256( be8(value) ).
    SHA256Builder::append(uint64_t) writes big-endian 8 bytes
    (src/crypto/sha256.cpp), and const_leaf appends exactly that one
    field (src/chain/chain.cpp build_state_leaves)."""
    b = value_u64.to_bytes(8, "big")
    return hashlib.sha256(b).hexdigest()

def rpc_state_proof_k(leaf_name):
    """state-proof --ns k --key <leaf_name>. The k: namespace is a simple-key
    path: node.cpp rpc_state_proof prepends "k:" + key verbatim (no hex
    body), so leaf_name is passed through directly."""
    r = subprocess.run(
        [determ, "state-proof", "--ns", "k", "--key", leaf_name,
         "--rpc-port", port],
        capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"state-proof rc={r.returncode}: {r.stderr.strip()}")
    return json.loads(r.stdout)

# ── Load pending `p:` staged changes; index by whitelist name ─────────────
try:
    with open(pending_path, "r", encoding="utf-8") as f:
        pending_raw = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_effective_param_audit: cannot parse pending-params JSON: {e}\n")
    sys.exit(1)
if not isinstance(pending_raw, list):
    pending_raw = []

pending_by_name = {}      # whitelist_name -> [ {effective_height, value, value_hex} ]
pending_total = 0
for e in pending_raw:
    if not isinstance(e, dict):
        continue
    name = str(e.get("name", ""))
    eff  = int(e.get("effective_height", 0))
    vhex = str(e.get("value_hex", ""))
    vbytes = int(e.get("value_bytes", 0))
    # u64-LE decode for 8-byte values (matches the pending-params RPC's own
    # value layout; opaque blob names like param_keyholders stay None).
    val = None
    if name != "param_keyholders" and vbytes == 8:
        try:
            bb = bytes.fromhex(vhex)
            if len(bb) == 8:
                val = int.from_bytes(bb, "little")
        except Exception:
            val = None
    pending_by_name.setdefault(name, []).append(
        {"effective_height": eff, "value": val, "value_hex": vhex})
    pending_total += 1
for lst in pending_by_name.values():
    lst.sort(key=lambda p: p["effective_height"])

# ── Audit each PROVABLE scalar against the anchored state_root ────────────
scalars = []
anomalies = []
n_verified = n_mismatch = n_not_provable = n_unchecked = 0

for wname, leaf_name in PROVABLE.items():
    rec = {
        "whitelist_name": wname,
        "leaf_name":      leaf_name,
        "class":          "PROVABLE",
        "verdict":        "UNCHECKED",
        "expected":       expected.get(wname),
        "value_hash":     None,
        "target_index":   None,
        "leaf_count":     None,
        "pending_change": pending_by_name.get(wname, []),
        "detail":         "",
    }
    try:
        proof = rpc_state_proof_k(leaf_name)
    except Exception as e:
        sys.stderr.write(f"operator_effective_param_audit: state-proof for k:{leaf_name} failed: {e}\n")
        sys.exit(1)

    if isinstance(proof, dict) and proof.get("error") == "not_found":
        rec["verdict"] = "NOT_PROVABLE"
        rec["detail"]  = "k: const_leaf absent from state tree (catastrophic)"
        anomalies.append({"kind": "scalar_not_provable", "name": wname})
        n_not_provable += 1
        scalars.append(rec)
        continue
    if not isinstance(proof, dict) or "value_hash" not in proof:
        rec["verdict"] = "NOT_PROVABLE"
        rec["detail"]  = "state-proof returned malformed response (no value_hash)"
        anomalies.append({"kind": "scalar_not_provable", "name": wname})
        n_not_provable += 1
        scalars.append(rec)
        continue

    proof_vh   = str(proof.get("value_hash", ""))
    proof_kb   = str(proof.get("key_bytes", ""))
    proof_ti   = int(proof.get("target_index", -1))
    proof_lc   = int(proof.get("leaf_count", 0))
    proof_root = str(proof.get("state_root", "")) or anchor_root
    rec["value_hash"]   = proof_vh
    rec["target_index"] = proof_ti
    rec["leaf_count"]   = proof_lc

    # (d) freshness: the proof's reported state_root must match the anchor.
    # A drift means the chain advanced between state-root and state-proof
    # (benign) OR the proof was served from a stale snapshot. Either way we
    # cannot soundly bind to the anchor, so flag and refuse VERIFIED.
    if proof_root and proof_root != anchor_root:
        rec["verdict"] = "NOT_PROVABLE"
        rec["detail"]  = (f"proof state_root {proof_root[:16]}.. != anchor "
                          f"{anchor_root[:16]}.. (chain advanced / stale snapshot)")
        anomalies.append({"kind": "stale_proof_root", "name": wname})
        n_not_provable += 1
        scalars.append(rec)
        continue

    # (a) key-binding: key_bytes must be the canonical "k:"+leaf_name. The
    # daemon emits key_bytes as hex of the raw leaf key.
    want_kb = ("k:" + leaf_name).encode("utf-8").hex()
    if proof_kb and proof_kb != want_kb:
        rec["verdict"] = "MISMATCH"
        rec["detail"]  = (f"key_bytes {proof_kb} != canonical {want_kb} "
                          f"(proof bound a different leaf)")
        anomalies.append({"kind": "scalar_misbound_key", "name": wname})
        n_mismatch += 1
        scalars.append(rec)
        continue

    # (c) target_index sanity.
    if not (0 <= proof_ti < proof_lc):
        rec["verdict"] = "MISMATCH"
        rec["detail"]  = (f"target_index {proof_ti} out of range [0,{proof_lc})")
        anomalies.append({"kind": "scalar_index_oob", "name": wname})
        n_mismatch += 1
        scalars.append(rec)
        continue

    # (b) value-binding: only assertable when the operator supplied --expect.
    exp = expected.get(wname)
    if exp is None:
        rec["verdict"] = "UNCHECKED"
        rec["detail"]  = ("proof present and binds a value, but no --expect "
                          f"{wname}=<u64> supplied to assert WHICH (SHA256 one-way)")
        n_unchecked += 1
        scalars.append(rec)
        continue

    want_vh = const_leaf_value_hash(exp)
    if proof_vh == want_vh:
        rec["verdict"] = "VERIFIED"
        rec["detail"]  = (f"effective value {exp} bound to state_root "
                          f"(value_hash {proof_vh[:16]}..)")
        n_verified += 1
    else:
        rec["verdict"] = "MISMATCH"
        rec["detail"]  = (f"state_root binds value_hash {proof_vh[:16]}.. != "
                          f"SHA256(be8({exp})) {want_vh[:16]}.. "
                          f"(effective value is NOT {exp})")
        anomalies.append({"kind": "scalar_value_mismatch", "name": wname})
        n_mismatch += 1
    scalars.append(rec)

# ── HOOK_ONLY names: report class + any staged change, no proof ───────────
for wname in HOOK_ONLY:
    scalars.append({
        "whitelist_name": wname,
        "leaf_name":      None,
        "class":          "HOOK_ONLY",
        "verdict":        "NOT_APPLICABLE",
        "expected":       None,
        "value_hash":     None,
        "target_index":   None,
        "leaf_count":     None,
        "pending_change": pending_by_name.get(wname, []),
        "detail":         "forwarded to Node hook / params.hpp constant; not a k: leaf",
    })

summary = {
    "provable":      len(PROVABLE),
    "verified":      n_verified,
    "mismatch":      n_mismatch,
    "not_provable":  n_not_provable,
    "unchecked":     n_unchecked,
    "hook_only":     len(HOOK_ONLY),
    "pending_total": pending_total,
    "anomaly_count": len(anomalies),
}

exit_code = 2 if summary["anomaly_count"] > 0 else 0

# ── Emit ──────────────────────────────────────────────────────────────────
if json_out:
    print(json.dumps({
        "rpc_port":   int(port),
        "height":     anchor_height,
        "state_root": anchor_root,
        "scalars":    scalars,
        "anomalies":  anomalies,
        "summary":    summary,
    }))
    sys.exit(exit_code)

print(f"=== Effective-param audit (port {port}, height {anchor_height}) ===")
print(f"state_root: {anchor_root}")
print(f"Provable scalars: {summary['provable']}  "
      f"hook-only: {summary['hook_only']}  "
      f"pending changes: {summary['pending_total']}")

def fmt_pending(lst):
    if not lst:
        return ""
    bits = []
    for p in lst:
        v = p["value"] if p["value"] is not None else \
            ("hex:" + (p["value_hex"][:12] + ".." if len(p["value_hex"]) > 12 else p["value_hex"]))
        bits.append(f"{v}@{p['effective_height']}")
    return "  staged: " + ", ".join(bits)

if not anom_only:
    print()
    for rec in scalars:
        if rec["class"] == "PROVABLE":
            line = f"  [{rec['verdict']:<12}] {rec['whitelist_name']} (k:{rec['leaf_name']})"
            if rec["detail"]:
                line += f" — {rec['detail']}"
            print(line)
        else:
            line = f"  [{rec['verdict']:<12}] {rec['whitelist_name']} (HOOK_ONLY)"
            print(line)
        pend = fmt_pending(rec["pending_change"])
        if pend:
            print(f"      {pend.strip()}")

print()
if not anomalies:
    print("[OK] No effective-param anomalies "
          f"(verified={summary['verified']}, unchecked={summary['unchecked']})")
else:
    for a in anomalies:
        print(f"[ANOMALY] {a['kind']}: {a['name']}")

sys.exit(exit_code)
PY
PY_RC=$?
# Python emits the final exit code (0, 2, or 1 on its own internal error).
# Forward verbatim so the anomaly exit-2 gate survives.
exit "$PY_RC"
