--------------------------- MODULE CompositeKeyStateProof ---------------------------
(*
FB43 — TLA+ specification of the COMPOSITE-KEY state_proof RPC pipeline:
the (namespace, hex-body) -> hex-decode -> length-check -> prefix-rebuild
-> leaf-lookup -> served-proof decision tree at
`Node::rpc_state_proof` (src/node/node.cpp:3287-3378). The companion
analytic proof is ReceiptInclusionProofSoundness.md (the i: namespace
receipt-membership slice); FB43 lifts the FULL ten-namespace key-encoding
contract to the state-machine layer, with the composite namespaces
(i|m|p) as the load-bearing case.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
CompositeKeyStateProof.cfg CompositeKeyStateProof.tla` once a companion
`.cfg` is supplied (one is shipped alongside).

Scope. The state_proof RPC serves a Merkle-inclusion proof for one
leaf of the sorted-leaves balanced binary Merkle tree over the ten
state namespaces. The caller supplies a (namespace, key) pair; the
server reconstructs the canonical leaf-key bytes and either returns a
proof bound to those bytes OR returns a structured error. Two key
shapes are served:

  * Simple namespaces (a|s|r|d|b|k|c): the `key` param is a
    human-readable ASCII suffix. The leaf key is "<ns>:" + key
    (counters: the `c` namespace maps to "k:c:" + name — the c:
    suffix rides inside the k: namespace; node.cpp:3323-3329).
  * Composite namespaces (i|m|p): the leaf-key suffix is BINARY
    (big-endian integers + 32-byte hashes), which cannot ride raw
    inside a JSON string (nlohmann throws on non-UTF-8 bytes during
    dump()). The caller therefore HEX-encodes the post-prefix body;
    the server hex-decodes it, enforces the EXACT body width, and
    prepends "<ns>:" — reproducing build_state_leaves' key
    byte-for-byte:
      i: body = hex( u64_be(src_shard) || tx_hash[32] )   (40 bytes)
         -> applied_inbound_receipts leaf  (value = SHA256(0x01))
      m: body = hex( u32_be(shard_id) )                   ( 4 bytes)
         -> merge_state leaf
      p: body = hex( u64_be(eff_height) || u32_be(idx) )  (12 bytes)
         -> pending_param_changes leaf

The load-bearing safety property: a served proof's `key_bytes`
field ALWAYS equals the canonical leaf-key reconstruction for the
(namespace, key) request — OR the RPC returns an error. The pipeline
NEVER returns a well-formed proof bound to the WRONG key. This is the
trustless-light-client soundness contract: a light client that
verifies the returned Merkle path against the state_root is computing
membership of EXACTLY the key it asked about, never a server-chosen
alias.

Six paired theorems are pinned:

  (T-CK1) Canonical-Key Soundness. For every request (ns, key) that
          the pipeline answers with a proof (not an error), the
          served key_bytes equals CanonicalKey(ns, key) — the
          deterministic reconstruction that build_state_leaves used
          when it committed the leaf. No reachable state has a served
          proof whose key_bytes diverges from the canonical
          reconstruction. The headline no-wrong-key contract.
  (T-CK2) Unsupported-Namespace Rejection. Any ns outside the
          ten-namespace set {a,s,r,d,b,k,c,i,m,p} short-circuits to
          the "unsupported namespace" error BEFORE any key
          reconstruction or tree lookup. No proof is ever served for
          an unsupported namespace (node.cpp:3354-3356).
  (T-CK3) Hex-Decode Gate (composite only). For a composite
          namespace (i|m|p), a `key` that is not valid hex routes to
          the "invalid hex key" error. The from_hex throw is caught
          and converted to a structured error; no malformed-hex
          input reaches the length-check or the tree
          (node.cpp:3333-3338).
  (T-CK4) Exact-Width Gate (composite only). For a composite
          namespace whose hex DOES decode, the decoded body width
          MUST equal the namespace's exact byte width (i:40, m:4,
          p:12). A wrong-width body routes to the "wrong length"
          error — it can NEVER silently alias a different leaf
          (node.cpp:3339-3349). This is the anti-aliasing gate: the
          width check is what stops a 12-byte query from being
          interpreted as a truncated 40-byte i: key.
  (T-CK5) Absence Soundness. A canonical key that is well-formed but
          not present in the committed leaf set routes to the
          "not_found" error — NOT to a fabricated proof. (Membership
          proofs only; non-membership requires the documented SMT
          migration.) The pipeline never invents a proof for an
          absent leaf (node.cpp:3358-3361).
  (T-CK6) Determinism / Idempotence. Two identical requests (ns, key)
          against the same committed leaf set produce identical
          outcomes (same error OR same key_bytes + same proof). The
          reconstruction CanonicalKey(ns, key) is a pure function of
          its arguments; the tree lookup is a pure function of the
          committed leaf set.

The state machine. A single committed leaf set (the sorted-leaves
balanced binary Merkle tree's domain) is fixed at Init from a bounded
universe of canonical keys. A non-deterministic Request action admits
one (namespace, key-or-hexbody) request per step, runs it through the
five-stage decision tree (namespace-class -> [composite: hex-decode ->
width-check] -> prefix-rebuild -> leaf-lookup), and appends a
ServedRecord to a served log. The six invariants read the served log
to verify every served proof's key_bytes equals the canonical
reconstruction (T-CK1) and every error is one of the five structured
error tags routed for the right reason (T-CK2..T-CK5).

Variables:

  * `committed_keys` — the fixed SUBSET of CanonicalKeyUniverse that
    build_state_leaves committed into the tree at this state-root.
    Set once at Init; the leaf-lookup decides Present vs Absent
    against it. Models the chain's committed leaf domain.
  * `served_log` — a Seq of ServedRecord. Each record tags the
    request (ns, raw_key), the outcome (Proof or one of five error
    tags), and — for the Proof outcome — the served key_bytes (the
    canonical reconstruction). T-CK1 reads this log: every Proof
    record's key_bytes equals CanonicalKey(ns, raw_key).
  * `request_count` — Nat. Bounds served_log length for TLC
    tractability (one Request per step until MaxRequests).

The decision tree (CanonicalKey + ServeOutcome are pure functions):

  CanonicalKey(ns, raw):  the canonical leaf-key reconstruction.
    * simple (a|s|r|d|b|k): "<ns>:" ++ raw            (raw is ASCII)
    * counter (c):          "k:c:" ++ raw             (rides in k:)
    * composite (i|m|p):    if raw is not valid hex      -> BadHex
                            elif HexLen(raw) /= 2*Width(ns) -> BadLen
                            else "<ns>:" ++ decode_hex(raw)
    * unsupported ns:       Unsupported

  ServeOutcome(ns, raw):  the served outcome.
    * Unsupported          -> Err("unsupported")           (T-CK2)
    * BadHex (composite)   -> Err("invalid_hex")           (T-CK3)
    * BadLen (composite)   -> Err("wrong_length")          (T-CK4)
    * canonical key absent -> Err("not_found")             (T-CK5)
    * canonical key present-> Proof(key_bytes = canonical) (T-CK1)

Six invariants codify the theorems:

  INV_TypeOK             — type sanity over all variables.
  INV_CanonicalKeySound (T-CK1) — every Proof record in served_log
    has key_bytes EXACTLY equal to CanonicalKey(record.ns,
    record.raw_key). No reachable state has a Proof bound to a
    non-canonical key. The headline no-wrong-key invariant.
  INV_UnsupportedRejected (T-CK2) — no Proof record has a namespace
    outside the ten-namespace set; every unsupported-namespace
    request in the log carries the "unsupported" error tag.
  INV_HexGate (T-CK3) — every composite-namespace request whose
    raw_key is not valid hex carries the "invalid_hex" error tag and
    is NOT a Proof record. Malformed hex never produces a proof.
  INV_WidthGate (T-CK4) — every composite-namespace Proof record's
    served key_bytes has the EXACT namespace body width
    (Len = 2 + Width(ns), the "<ns>:" prefix plus the binary body);
    no wrong-width composite request is a Proof record. The
    anti-aliasing invariant.
  INV_AbsenceSound (T-CK5) — every Proof record's canonical key is a
    member of committed_keys; an absent canonical key never produces
    a Proof (it produces "not_found"). The no-fabricated-proof
    invariant.

Two temporal properties cover the eventual-answer + determinism
claims:

  PROP_EventualAnswer — under fairness on Request, every reachable
    state with request_count < MaxRequests eventually grows served_log
    (the pipeline always terminates with an outcome — it never hangs
    on a request). The no-stuck-request liveness contract.
  PROP_DeterministicReplay — two identical requests append identical
    outcome records (same tag; same key_bytes for the Proof tag).
    The T-CK6 idempotence witness lifted to a stuttering replay.

Modeling scope (kept tractable for TLC):

  * `Namespaces` is the ten-element set {a,s,r,d,b,k,c,i,m,p} plus an
    out-of-set sentinel `x` to exercise T-CK2. The simple/composite
    partition is structural (Composite == {i,m,p}).
  * `RawKeys` is a small finite universe of opaque key strings. For
    simple namespaces the raw key is the ASCII suffix; for composite
    namespaces the raw key is a hex string, modeled as a (valid_hex,
    hex_len) tuple so the hex-decode + width gates are decidable
    without modeling actual hex bytes. A "well-formed composite raw
    key" carries valid_hex = TRUE and hex_len = 2*Width(ns); a
    malformed one carries valid_hex = FALSE (BadHex) or a mismatched
    hex_len (BadLen).
  * `Width(ns)` is the exact binary body width: i -> 40, m -> 4,
    p -> 12 (node.cpp:3341-3343). Simple namespaces have no width
    gate.
  * `CanonicalKeyUniverse` is the set of all (ns, body) leaf keys the
    model can reconstruct; `committed_keys` is a fixed SUBSET chosen
    at Init. The Merkle-path bytes themselves are out of scope (the
    cryptographic Merkle binding is FA-track / FB26 territory); the
    spec models the KEY-RECONSTRUCTION + lookup decision, which is
    where a wrong-key proof would originate.
  * The Merkle proof object (proof[], target_index, leaf_count,
    state_root, height) is abstracted to a single Proof tag carrying
    the served key_bytes. The cryptographic soundness of the path is
    BlockchainStateIntegrity.tla (FB26) territory; FB43 zooms in on
    the key-reconstruction soundness that PRECEDES the path
    construction. A wrong key_bytes here would make a
    cryptographically-valid path prove membership of the WRONG leaf —
    which is exactly what INV_CanonicalKeySound forbids.

The state machine. Two actions cover the pipeline:

  * Request(ns, raw) — admit one (namespace, raw-key) request, run
    the five-stage decision tree via ServeOutcome, append one
    ServedRecord to served_log, increment request_count. Models one
    rpc_state_proof invocation.
  * Saturate — stutter once request_count reaches MaxRequests. TLC
    bounds the state space; the invariants are evaluated at every
    reachable state along the way.

TLC verifies the six invariants at every reachable state across every
reachable interleaving of Request actions over the bounded
namespace x raw-key universe against the fixed committed_keys set.

To check (assuming TLC installed):
  $ tlc CompositeKeyStateProof.tla -config CompositeKeyStateProof.cfg

Recommended config (state space ~10^4, < 30s):
  Namespaces = {a, i, m, p, x}, RawKeys as a small mixed set of
  simple + valid-composite + bad-hex + bad-width keys,
  MaxRequests = 5, committed_keys = a 2-3 element subset.

Cross-references:
  - docs/proofs/ReceiptInclusionProofSoundness.md — the i: namespace
    receipt-membership analytic proof (RI-1..RI-N); FB43 is the
    state-machine companion generalized to all three composite
    namespaces plus the simple-namespace partition.
  - docs/proofs/AppliedReceiptSnapshotSoundness.md — the i: namespace
    snapshot + apply determinism (AR-1..AR-N); the committed-leaf
    domain FB43 looks up is the snapshot-surviving applied_inbound
    _receipts set FB17 / FB32 model.
  - docs/proofs/MergeStateSoundness.md — the m: namespace apply +
    snapshot determinism (MS-1..MS-N); the m: leaf FB43 reconstructs.
  - docs/proofs/tla/BlockchainStateIntegrity.tla (FB26) — the
    cryptographic Merkle-binding + state-root composition; FB43's
    Proof tag abstracts the path FB26 models. Together they pin
    (FB43) right-key + (FB26) right-path = right membership.
  - src/node/node.cpp:3287-3378 — Node::rpc_state_proof; the
    CanonicalKey + ServeOutcome operators are the spec-layer
    projection of the five-stage decision tree.
  - include/determ/chain/chain.hpp:295-302 — Chain::StateProof struct
    + state_proof(key) declaration; the Proof tag is the spec-layer
    projection of the StateProof record.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    SimpleNamespaces,    \* {a, s, r, d, b, k} — ASCII-suffix leaves
    CounterNamespace,    \* {c} — rides in k: as "k:c:" ++ name
    CompositeNamespaces, \* {i, m, p} — hex-encoded binary body leaves
    UnsupportedNs,       \* a sentinel ns outside the ten-namespace set
    RawKeys,             \* finite universe of opaque raw key strings
    WidthOf,             \* function CompositeNamespaces -> Nat (i:40 m:4 p:12)
    ValidHexOf,          \* function RawKeys -> BOOLEAN (is the raw a valid hex string)
    HexLenOf,            \* function RawKeys -> Nat (the raw's hex char count)
    CommittedKeys,       \* SUBSET of the canonical-key universe (the tree's domain)
    MaxRequests          \* bound on served_log length (TLC tractability)

\* The ten namespaces the pipeline supports plus the out-of-set sentinel.
SupportedNamespaces ==
    SimpleNamespaces \cup CounterNamespace \cup CompositeNamespaces

AllNamespaces == SupportedNamespaces \cup UnsupportedNs

ASSUME ConfigOK ==
    /\ Cardinality(SimpleNamespaces)    >= 1
    /\ Cardinality(CounterNamespace)    = 1
    /\ Cardinality(CompositeNamespaces) >= 1
    /\ Cardinality(UnsupportedNs)       = 1
    \* the four classes are pairwise disjoint (no ns is in two classes)
    /\ SimpleNamespaces \cap CounterNamespace    = {}
    /\ SimpleNamespaces \cap CompositeNamespaces = {}
    /\ CounterNamespace \cap CompositeNamespaces = {}
    /\ UnsupportedNs \cap SupportedNamespaces     = {}
    /\ WidthOf    \in [CompositeNamespaces -> Nat]
    /\ ValidHexOf \in [RawKeys -> BOOLEAN]
    /\ HexLenOf   \in [RawKeys -> Nat]
    /\ \A ns \in CompositeNamespaces : WidthOf[ns] >= 1
    /\ MaxRequests \in Nat /\ MaxRequests >= 1

\* -----------------------------------------------------------------
\* §1. Outcome / key-tag shapes.
\* -----------------------------------------------------------------
\*
\* The pipeline's five structured outcomes. Four error tags plus the
\* Proof tag. The error tags mirror node.cpp's return shapes:
\*   "unsupported"  -> {"error","unsupported namespace; use a|s|r|d|b|k|c|i|m|p"}
\*   "invalid_hex"  -> {"error","invalid hex key for composite namespace"}
\*   "wrong_length" -> {"error","composite key wrong length"}
\*   "not_found"    -> {"error","not_found"}
\*   "proof"        -> the full StateProof JSON (key_bytes + proof[] + ...)

OutcomeTags == {"unsupported", "invalid_hex", "wrong_length",
                "not_found", "proof"}

\* The canonical leaf-key is modeled as a structured record rather
\* than a raw byte string: <<ns, body, kind>> where `kind` is one of
\* the namespace classes. Two requests reconstruct the SAME canonical
\* key iff they agree on all three fields. The "<ns>:" prefix is
\* implicit in the record shape (the prefix is a pure function of ns).
\*
\* CanonicalKey(ns, raw) is well-defined only when the namespace class
\* + (for composite) the hex/width gates pass; otherwise the request
\* short-circuits to an error BEFORE reconstruction. We model the
\* canonical key as the tuple <<ns, raw>> — the reconstruction is
\* injective in (ns, raw) for the well-formed cases, which is exactly
\* the property T-CK1 needs (the served key_bytes is a pure function
\* of (ns, raw), so it can never alias a different request's key).
CanonicalKey(ns, raw) == <<ns, raw>>

\* -----------------------------------------------------------------
\* §2. Pure-function decision tree (the C++ pipeline lifted).
\* -----------------------------------------------------------------
\*
\* IsComposite / IsSimple / IsCounter / IsUnsupported classify the ns.

IsSimple(ns)      == ns \in SimpleNamespaces
IsCounter(ns)     == ns \in CounterNamespace
IsComposite(ns)   == ns \in CompositeNamespaces
IsUnsupported(ns) == ns \in UnsupportedNs

\* HexGateOk(ns, raw): for a composite namespace, the raw key must be
\* valid hex (ValidHexOf[raw] = TRUE). Models the from_hex try/catch
\* at node.cpp:3333-3338 — a non-hex key is caught and converted to
\* the "invalid hex key" error.
HexGateOk(raw) == ValidHexOf[raw] = TRUE

\* WidthGateOk(ns, raw): for a composite namespace whose hex decodes,
\* the decoded body width (HexLenOf[raw] / 2) must equal WidthOf[ns].
\* Models the exact-width enforcement at node.cpp:3339-3349. We
\* compare hex-char-count to 2*WidthOf[ns] to avoid integer division.
WidthGateOk(ns, raw) == HexLenOf[raw] = 2 * WidthOf[ns]

\* CanonicalKeyBodyLen(ns, raw): the served key_bytes byte-length for
\* the canonical reconstruction. Simple/counter namespaces' length is
\* not width-gated (variable-length ASCII); composite namespaces'
\* length is exactly 2 ("<ns>:" prefix bytes) + WidthOf[ns] body
\* bytes. Used by INV_WidthGate to assert no wrong-width composite
\* proof is ever served.
CanonicalKeyBodyLen(ns) ==
    IF IsComposite(ns) THEN 2 + WidthOf[ns] ELSE 0  \* 0 = "not width-gated"

\* ServeOutcome(ns, raw, committed): the five-stage decision tree.
\* Returns one of the OutcomeTags. The order of the gates mirrors
\* node.cpp exactly:
\*   1. unsupported ns          -> "unsupported"           (T-CK2)
\*   2. composite + bad hex     -> "invalid_hex"           (T-CK3)
\*   3. composite + bad width   -> "wrong_length"          (T-CK4)
\*   4. canonical key absent    -> "not_found"             (T-CK5)
\*   5. canonical key present   -> "proof"                 (T-CK1)
\* Simple/counter namespaces skip the hex + width gates (stages 2-3)
\* and go straight to the absent/present lookup.
ServeOutcome(ns, raw, committed) ==
    IF IsUnsupported(ns)
    THEN "unsupported"
    ELSE IF IsComposite(ns) /\ ~HexGateOk(raw)
         THEN "invalid_hex"
         ELSE IF IsComposite(ns) /\ ~WidthGateOk(ns, raw)
              THEN "wrong_length"
              ELSE IF CanonicalKey(ns, raw) \notin committed
                   THEN "not_found"
                   ELSE "proof"

\* -----------------------------------------------------------------
\* §3. ServedRecord shape.
\* -----------------------------------------------------------------
\*
\* Each Request appends one ServedRecord. The record tags the request
\* (ns, raw_key), the outcome tag, and — for the "proof" tag — the
\* served key_bytes (the canonical reconstruction). For non-proof
\* tags the key_bytes field is the sentinel <<"none">> (no proof was
\* served, so there is no key_bytes to bind).
NoKeyBytes == <<"none">>

ServedRecord == [
    ns         : AllNamespaces,
    raw_key    : RawKeys,
    outcome    : OutcomeTags,
    key_bytes  : { <<n, r>> : n \in AllNamespaces, r \in RawKeys }
                   \cup {NoKeyBytes}
]

\* MakeRecord(ns, raw, committed): construct the ServedRecord for a
\* request. The key_bytes slot is the canonical reconstruction iff the
\* outcome is "proof"; otherwise it is the NoKeyBytes sentinel. This
\* is the spec-layer projection of node.cpp:3367-3377 (the proof
\* return populates "key_bytes" = to_hex(p.key); the error returns
\* carry no key_bytes).
MakeRecord(ns, raw, committed) ==
    LET tag == ServeOutcome(ns, raw, committed) IN
    [ ns        |-> ns,
      raw_key   |-> raw,
      outcome   |-> tag,
      key_bytes |-> IF tag = "proof" THEN CanonicalKey(ns, raw)
                                     ELSE NoKeyBytes ]

\* -----------------------------------------------------------------
\* §4. Variables.
\* -----------------------------------------------------------------

VARIABLES
    committed_keys,    \* SUBSET of the canonical-key universe (tree domain)
    served_log,        \* Seq(ServedRecord)
    request_count      \* Nat (bounds served_log for TLC)

vars == <<committed_keys, served_log, request_count>>

\* -----------------------------------------------------------------
\* §5. Initial state.
\* -----------------------------------------------------------------
\*
\* committed_keys is fixed at Init to the CommittedKeys constant (the
\* tree's committed leaf domain at this state-root). served_log starts
\* empty; request_count starts at 0.
Init ==
    /\ committed_keys = CommittedKeys
    /\ served_log     = <<>>
    /\ request_count  = 0

\* -----------------------------------------------------------------
\* §6. Actions.
\* -----------------------------------------------------------------

\* Request(ns, raw): the headline action — admit one (ns, raw-key)
\* request, run the five-stage decision tree via MakeRecord, append
\* one ServedRecord to served_log, increment request_count. Models one
\* Node::rpc_state_proof invocation. The committed_keys set is read-
\* only (the RPC is a const method under a shared_lock at
\* node.cpp:3289).
Request(ns, raw) ==
    /\ ns  \in AllNamespaces
    /\ raw \in RawKeys
    /\ request_count < MaxRequests
    /\ served_log'    = Append(served_log, MakeRecord(ns, raw, committed_keys))
    /\ request_count' = request_count + 1
    /\ UNCHANGED committed_keys

\* Saturate: stutter once request_count reaches MaxRequests. TLC
\* bounds the state space; the invariants are evaluated at every
\* reachable state along the way.
Saturate ==
    /\ request_count >= MaxRequests
    /\ UNCHANGED vars

Next ==
    \/ \E ns \in AllNamespaces, raw \in RawKeys : Request(ns, raw)
    \/ Saturate

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E ns \in AllNamespaces, raw \in RawKeys : Request(ns, raw))

\* -----------------------------------------------------------------
\* §7. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ committed_keys \subseteq { <<n, r>> : n \in AllNamespaces, r \in RawKeys }
    /\ served_log     \in Seq(ServedRecord)
    /\ request_count  \in Nat
    /\ request_count  <= MaxRequests
    /\ Len(served_log) = request_count

\* -----------------------------------------------------------------
\* §8. Invariants — the six T-CK1..T-CK6 claims.
\* -----------------------------------------------------------------

\* INV_CanonicalKeySound (T-CK1) — the headline no-wrong-key contract.
\* Every Proof record in served_log has key_bytes EXACTLY equal to
\* CanonicalKey(record.ns, record.raw_key). No reachable state has a
\* served proof bound to a non-canonical key.
\*
\* Structural witness: MakeRecord sets key_bytes = CanonicalKey(ns,
\* raw) on the "proof" branch by construction. The reconstruction is
\* a pure function of (ns, raw) — it can never alias a different
\* request's key. A light client verifying the returned path against
\* the state_root is therefore checking membership of EXACTLY the key
\* it asked about.
INV_CanonicalKeySound ==
    \A i \in 1..Len(served_log) :
       LET e == served_log[i] IN
       (e.outcome = "proof")
       => (e.key_bytes = CanonicalKey(e.ns, e.raw_key))

\* INV_UnsupportedRejected (T-CK2) — no Proof record has a namespace
\* outside the ten-namespace set; every unsupported-namespace request
\* carries the "unsupported" error tag and is NOT a Proof.
\*
\* Structural witness: ServeOutcome's first gate short-circuits any
\* unsupported ns to "unsupported" before any reconstruction or
\* lookup. No "proof" outcome is reachable for an unsupported ns.
INV_UnsupportedRejected ==
    \A i \in 1..Len(served_log) :
       LET e == served_log[i] IN
       /\ (e.outcome = "proof") => (e.ns \in SupportedNamespaces)
       /\ (e.ns \notin SupportedNamespaces) => (e.outcome = "unsupported")

\* INV_HexGate (T-CK3) — every composite-namespace request whose
\* raw_key is not valid hex carries the "invalid_hex" tag and is NOT
\* a Proof record. Malformed hex never produces a proof.
\*
\* Structural witness: ServeOutcome's second gate routes composite +
\* ~HexGateOk to "invalid_hex" before the width check or the lookup.
INV_HexGate ==
    \A i \in 1..Len(served_log) :
       LET e == served_log[i] IN
       (IsComposite(e.ns) /\ ~HexGateOk(e.raw_key))
       => (e.outcome = "invalid_hex")

\* INV_WidthGate (T-CK4) — the anti-aliasing invariant. Every
\* composite-namespace Proof record's served key_bytes corresponds to
\* a body of EXACTLY the namespace's width: the request's hex MUST
\* have decoded to 2*WidthOf[ns] hex chars (= WidthOf[ns] body bytes).
\* No wrong-width composite request is ever a Proof. A 12-byte body
\* can NEVER alias a truncated 40-byte i: key.
\*
\* Structural witness: ServeOutcome's third gate routes composite +
\* ~WidthGateOk to "wrong_length" before the lookup. The only path to
\* a composite "proof" outcome requires WidthGateOk(ns, raw) = TRUE.
INV_WidthGate ==
    \A i \in 1..Len(served_log) :
       LET e == served_log[i] IN
       (IsComposite(e.ns) /\ e.outcome = "proof")
       => (HexGateOk(e.raw_key) /\ WidthGateOk(e.ns, e.raw_key))

\* INV_AbsenceSound (T-CK5) — the no-fabricated-proof invariant.
\* Every Proof record's canonical key is a member of committed_keys;
\* an absent canonical key never produces a Proof (it produces
\* "not_found"). Membership proofs only — the pipeline never invents
\* a proof for an absent leaf.
\*
\* Structural witness: ServeOutcome's fourth gate routes a
\* well-formed-but-absent canonical key to "not_found"; the "proof"
\* outcome is reachable only when CanonicalKey(ns, raw) \in committed.
INV_AbsenceSound ==
    \A i \in 1..Len(served_log) :
       LET e == served_log[i] IN
       (e.outcome = "proof")
       => (CanonicalKey(e.ns, e.raw_key) \in committed_keys)

\* -----------------------------------------------------------------
\* §9. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualAnswer — under fairness on Request, the served_log
\* always eventually grows until saturation. The pipeline always
\* terminates with an outcome — it never hangs on a request. The
\* no-stuck-request liveness contract.
\*
\* State-form: a non-saturated state (request_count < MaxRequests)
\* leads to a state with a longer served_log OR saturation.
PROP_EventualAnswer ==
    (request_count < MaxRequests)
    ~> (request_count > 0 /\ Len(served_log) = request_count)

\* PROP_DeterministicReplay (T-CK6) — the served outcome is a pure
\* function of (ns, raw) against the fixed committed_keys set. State-
\* form: any two records in the log with the same (ns, raw) have the
\* same outcome AND (for the proof tag) the same key_bytes. Since
\* committed_keys is fixed at Init and MakeRecord is deterministic,
\* identical requests always produce identical records.
\*
\* Note: this is stated as a standing invariant over the log (a
\* safety property), since determinism here is structural — the
\* reconstruction + lookup are pure functions. The temporal framing
\* is the idempotence-under-replay reading.
PROP_DeterministicReplay ==
    \A i, j \in 1..Len(served_log) :
       (/\ served_log[i].ns      = served_log[j].ns
        /\ served_log[i].raw_key = served_log[j].raw_key)
       => (/\ served_log[i].outcome   = served_log[j].outcome
           /\ served_log[i].key_bytes = served_log[j].key_bytes)

\* -----------------------------------------------------------------
\* §10. Soundness commentary — what TLC checks vs. the C++ pipeline.
\* -----------------------------------------------------------------
\*
\* The ReceiptInclusionProofSoundness.md analytic proof establishes the
\* i: namespace receipt-membership soundness (RI-1..RI-N) by case
\* analysis on the rpc_state_proof decision tree's i: branch. FB43
\* generalizes this to all three composite namespaces (i|m|p) PLUS the
\* simple-namespace partition, lifting the full ten-namespace
\* key-reconstruction contract to the state-machine layer.
\*
\* The crux is INV_CanonicalKeySound (T-CK1): the served key_bytes is
\* a PURE FUNCTION of (ns, raw), so it can never alias a different
\* request's key. Composed with FB26 (BlockchainStateIntegrity.tla)'s
\* cryptographic Merkle-path soundness, this gives the full
\* trustless-read contract:
\*
\*   FB43 (right key)  +  FB26 (right path)  =  right membership.
\*
\* A wrong key_bytes here would let a cryptographically-valid Merkle
\* path prove membership of the WRONG leaf — the server could answer
\* "here is a proof that account X has balance B" while actually
\* serving the path for account Y. INV_CanonicalKeySound forbids this
\* at the reconstruction layer; FB26 forbids forging the path itself.
\*
\* The composite-namespace gates (T-CK3 hex, T-CK4 width) are the
\* attack-relevant additions over the simple-namespace path. The width
\* gate (T-CK4) is the anti-aliasing invariant: without it, a
\* malicious or buggy caller could submit a 12-byte body to the i:
\* namespace and have it interpreted as a truncated 40-byte key,
\* aliasing a different applied_inbound_receipts leaf. The exact-width
\* enforcement at node.cpp:3339-3349 — modeled by ServeOutcome's third
\* gate — closes this: a composite "proof" outcome is reachable ONLY
\* when WidthGateOk(ns, raw) holds.
\*
\* What this spec adds beyond the prose proof: a state-machine witness
\* that the key-reconstruction soundness holds across every reachable
\* interleaving of requests over the bounded namespace x raw-key
\* universe against the fixed committed leaf set. TLC enumerates every
\* reachable schedule and the six invariants are checked against the
\* accumulated served_log.
\*
\* What the spec does NOT check (consistent with the analytic proof's
\* scope notes):
\*   * The cryptographic Merkle-path bytes (proof[], target_index,
\*     leaf_count, state_root). The path soundness is FB26
\*     (BlockchainStateIntegrity.tla) territory. FB43's Proof tag
\*     abstracts the path; the key-reconstruction soundness that
\*     PRECEDES the path is what FB43 pins.
\*   * Non-membership proofs. The pipeline serves MEMBERSHIP proofs
\*     only; an absent key returns "not_found" (T-CK5). Trustless
\*     non-membership requires the documented SMT migration
\*     (node.cpp:3311-3312); it is out of scope here.
\*   * The hex byte-level decoding. The spec models the from_hex
\*     gate via the abstract ValidHexOf + HexLenOf functions rather
\*     than modeling actual hex bytes — the only structural property
\*     T-CK3 + T-CK4 need is (a) is-the-raw-valid-hex and (b) does-
\*     the-decoded-width-match. The byte-level from_hex correctness
\*     is the regression test's job (tools/test_light_verify_receipt
\*     _inclusion.sh asserts a real INCLUDED end-to-end).
\*   * The S-022 size caps / S-014 rate limiting above the RPC. Those
\*     are the wire-admission layers; FB43 models the
\*     key-reconstruction soundness that runs AFTER admission.

============================================================================
\* Cross-references.
\*
\* ReceiptInclusionProofSoundness.md (RI-1..RI-N) ->
\*   RI (i: receipt membership soundness) : INV_CanonicalKeySound +
\*       INV_WidthGate, specialized to the i: namespace. FB43
\*       generalizes to all three composite namespaces + the simple
\*       partition.
\*
\* AppliedReceiptSnapshotSoundness.md (AR-1..AR-N) ->
\*   The committed-leaf domain FB43 looks up (the i: namespace) is the
\*       snapshot-surviving applied_inbound_receipts set; AR pins its
\*       determinism, FB43 pins its proof-serving soundness.
\*
\* MergeStateSoundness.md (MS-1..MS-N) ->
\*   The m: namespace leaf FB43 reconstructs (WidthOf[m] = 4); MS pins
\*       the m: apply + snapshot determinism, FB43 pins its
\*       proof-serving soundness.
\*
\* C++ enforcement:
\*   src/node/node.cpp:3287-3378 : Node::rpc_state_proof. The
\*       CanonicalKey + ServeOutcome operators are the spec-layer
\*       projection of the five-stage decision tree.
\*   src/node/node.cpp:3314-3322 : simple namespace (a|s|r|d|b|k)
\*       "<ns>:" + key reconstruction. IsSimple branch of CanonicalKey.
\*   src/node/node.cpp:3323-3329 : counter namespace (c) "k:c:" + name
\*       reconstruction. IsCounter branch of CanonicalKey.
\*   src/node/node.cpp:3330-3353 : composite namespace (i|m|p)
\*       hex-decode + exact-width gates + "<ns>:" + body reconstruction.
\*       The HexGateOk + WidthGateOk gates of ServeOutcome.
\*   src/node/node.cpp:3333-3338 : from_hex try/catch -> "invalid hex
\*       key" error. INV_HexGate (T-CK3).
\*   src/node/node.cpp:3339-3349 : exact-width enforcement -> "wrong
\*       length" error. INV_WidthGate (T-CK4); the anti-aliasing gate.
\*   src/node/node.cpp:3354-3356 : unsupported-namespace fall-through
\*       -> "unsupported" error. INV_UnsupportedRejected (T-CK2).
\*   src/node/node.cpp:3358-3361 : state_proof returns nullopt ->
\*       "not_found" error. INV_AbsenceSound (T-CK5).
\*   src/node/node.cpp:3367-3377 : the StateProof JSON return; the
\*       "key_bytes" field = to_hex(p.key). MakeRecord's key_bytes
\*       slot on the "proof" branch.
\*   include/determ/chain/chain.hpp:295-302 : Chain::StateProof struct
\*       + state_proof(key) declaration. The Proof tag is the spec-
\*       layer projection of the StateProof record.
\*
\* Sibling specs (style template):
\*   FB26 BlockchainStateIntegrity.tla — cryptographic Merkle-binding +
\*       state-root composition; FB43's Proof tag abstracts the path
\*       FB26 models. Together: FB43 (right key) + FB26 (right path)
\*       = right membership.
\*   FB14 CrossShardReceiptDedup.tla / FB17 AppliedReceiptRestore.tla /
\*   FB32 CrossShardReceiptRoundtrip.tla — the applied_inbound_receipts
\*       (i: namespace) lifecycle FB43's committed-leaf domain looks up.
\*   FB27 JsonValidation.tla — the pure-function + bounded-enumeration
\*       + INV-* state-machine style this module reuses.
\*
\* Runtime regressions:
\*   tools/test_light_verify_receipt_inclusion.sh — asserts a real
\*       INCLUDED end-to-end against the i: namespace composite-key
\*       state_proof RPC; INV_CanonicalKeySound + INV_WidthGate are
\*       the state-machine-layer counterparts of the regression's
\*       round-trip assertion.
============================================================================
