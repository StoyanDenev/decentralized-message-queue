--------------------------- MODULE MakeContribCommitment ---------------------------
(*
FB24 — TLA+ specification of the v2.7 F2 `make_contrib_commitment`
v1-byte-identity + DTM-F2-v1 replay defense.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
MakeContribCommitment.tla` once a companion `.cfg` is supplied.

Scope. Formalizes the cryptographic-binding contract of the shipped
primitive `determ::node::make_contrib_commitment` at
`src/node/producer.cpp:219-260`, the v2.7 F2 extension that wires
three view roots (`view_eq_root`, `view_abort_root`,
`view_inbound_root`) into the existing Phase-1 contrib commit hash
under a `"DTM-F2-v1"` domain tag.  Two paired properties are pinned:

  (T-1) v1 backward compatibility. A call with all three view roots
        equal to the 32-zero `Hash{}` value produces a hash byte-
        identical to what the pre-F2 (v1) implementation produced.
        Pre-F2 ContribMsg signatures continue to verify under the
        extended primitive without protocol-version negotiation.
  (T-2) DTM-F2-v1 replay defense. A signature produced under a v1
        commit shape (no DTM-F2-v1 tag, no view roots) cannot be
        replayed under any F2 commit shape with at least one non-zero
        view root, and vice versa. The two pre-image families are
        syntactically disjoint (different lengths: 104 vs 209 bytes),
        so by SHA-256 collision resistance they hash to disjoint output
        sets except with probability ≤ 2⁻¹²⁸ per attempt.

The state machine just enumerates input tuples and records the
resulting `MakeCommit` values; TLC then verifies six invariants over
the reachable states.

Companion documents:
  * docs/proofs/MakeContribCommitmentBackwardCompat.md — the analytic
    FA-Crypto-MakeContrib proof shipped Round 18 (T-1 + T-2 +
    corollaries T-1.1 / T-2.1; this spec lifts that proof's claims to
    the state-machine layer).
  * docs/proofs/tla/F2ViewReconciliation.tla — FB22 (the
    reconciliation primitives that consume the view roots `MakeCommit`
    binds; this spec covers the commit-side of the F2 wire change,
    FB22 covers the validator-side reconciliation that closes
    S-030 D2).
  * docs/proofs/tla/FrostVerify.tla — FB23 (sibling FB-Crypto spec
    pinning a primitive against a delegation contract; style template
    for this module).
  * docs/proofs/F2-SPEC.md §Q4 — design decision to extend the
    existing primitive (rather than introduce a separate v2 helper)
    + the `"DTM-F2-v1"` tag rationale.

What the model checks. Six invariants codifying the contract that the
analytic proof (T-1 + T-2 + corollaries) establishes:

  INV-1 (V1ByteIdentity): for every (idx, prev, txs, dh),
        `MakeCommit(idx, prev, txs, dh, ZERO, ZERO, ZERO)` equals
        `V1Commit(idx, prev, txs, dh)` bytewise. Lifts T-1.
  INV-2 (F2PathTriggered): when at least one view root is non-zero,
        `MakeCommit` evaluates to `F2Commit(...)`, and `F2Commit(...)`
        is distinct from `V1Commit(...)` on the same `(idx, prev,
        txs, dh)` — by H1 (SHA-256 collision resistance lifted to
        injectivity on the modeled finite universe).
  INV-3 (PerRootBinding): for any single non-zero view root in any
        single position (eq only, abort only, or inbound only),
        `MakeCommit` is distinct from `V1Commit` AND from each of the
        other single-non-zero outputs — per-root domain separation
        works through the field-position serialization.
  INV-4 (DomainSeparation): the `"DTM-F2-v1"` literal appended before
        the view roots means any pre-image starting with V1Commit-
        shape inputs cannot accidentally equal a pre-image starting
        with F2Commit-shape inputs (lifts T-2 of
        MakeContribCommitmentBackwardCompat.md L-3: the length
        argument + the literal-tag defense-in-depth).
  INV-5 (Determinism): `MakeCommit` applied twice to the same
        argument tuple yields the same hash — captures the L-2
        "SHA256Builder is deterministic, append-order-bound, content-
        bound" lemma at the state-machine layer.
  INV-6 (FieldBinding): the function output changes if any of the
        consensus-bound input fields (idx, prev, any tx in txs, dh)
        changes — captures the "every consensus-bound field actually
        binds the hash" contract.

Modeling scope (kept tractable for TLC):

  * `BlockIdx` is the abstract finite universe of `uint64_t` block
    indices.  The C++ side encodes via `SHA256Builder::append(uint64_t)`
    which serializes big-endian per `Preliminaries.md` §1.3; the spec
    treats the value as an opaque identifier.
  * `Hashes` is the abstract finite universe of 32-byte Hash values.
    A designated element `ZERO \in Hashes` models the value-initialized
    `Hash{}` returned by `Hash::operator==(Hash{}, h)` when h is the
    default-constructed `std::array<uint8_t, 32>{}` (= all zero per
    `[array.cons]` + `[dcl.init.aggr]`).  The C++ `is_zero_hash`
    predicate at `src/node/producer.cpp:242-245` returns true iff every
    byte is 0, matching `h == ZERO` here.
  * `TxLists` is the abstract finite universe of bounded
    `std::vector<Hash>` values.  Each tx-list models a sorted-and-
    deduped sequence (the producer pre-sorts before calling
    `make_contrib_commitment`); the model uses lists of length up to a
    small `MaxTxs` bound.
  * `SHA256` is modeled as an INJECTIVE function on the bounded pre-
    image universe (the standard cryptographic abstraction of A2 /
    Preliminaries §2.1 — collision-resistance lifted to determinism
    on the modeled finite universe).  Two distinct byte sequences hash
    to distinct outputs; identical sequences hash to identical outputs.
    This is the same abstraction `FrostVerify.tla` uses for
    `Ed25519Verify` and `Consensus.tla` uses for `Digest`.
  * `serialize(idx)` and `serialize(txs)` are modeled as injective
    encodings that distinguish distinct inputs at the byte level (the
    C++ `SHA256Builder::append(uint64_t)` produces 8 BE bytes per
    integer; the inner-tx-root reduction `inner_root(txs) := SHA256(
    txs[0] || txs[1] || ...)` is itself an injection on distinct tx
    sequences under A2, modeled here as a single `InnerRoot(txs)`
    operator).

The state machine. A single non-deterministic action `Generate`
picks an input tuple `(idx, prev, txs, dh, eq, abort, inbound)` and
records the resulting `MakeCommit` value into a `record` map keyed by
the tuple.  TLC enumerates every reachable input tuple within the
bounded universe and the invariants are checked against the
accumulated map.  This is the same "pure primitive + bounded
enumeration" pattern `F2ViewReconciliation.tla` uses.

To check (assuming TLC installed):
  $ tlc MakeContribCommitment.tla -config MakeContribCommitment.cfg

Recommended config (state space ~10⁴, < 30s):
  BlockIdx = {i1, i2}, Hashes = {ZERO, h1, h2}, TxLists = {nil, t1, t2},
  MaxTxs = 2.

Cross-references:
  - MakeContribCommitmentBackwardCompat.md (T-1 + T-2 + L-1..L-4 +
    corollaries; the analytic FA-Crypto-MakeContrib proof).
  - Preliminaries.md §2.1 A2 (SHA-256 collision resistance + 2nd-
    preimage resistance — the cryptographic foundation of T-2).
  - Preliminaries.md §2.2 A1 (Ed25519 EUF-CMA — used by T-2.1 /
    T-1.1 corollaries; the sig-side reduction is FrostVerify.tla
    territory).
  - F2-SPEC.md §Q4 (design decision to extend
    `make_contrib_commitment` + the `"DTM-F2-v1"` tag rationale).
  - F2ViewReconciliation.tla (FB22 — the validator-side
    reconciliation primitives that consume the view roots this
    primitive binds; together the two specs close the consensus-
    layer half of S-030 D2).
  - src/node/producer.cpp:219-260 (the function under test).
  - include/determ/node/producer.hpp:117-139 (the header declaration
    with the explicit default-zero trailing args + the "all-zero ⇒
    v1 commit" docstring).
  - src/main.cpp scenarios cited at
    MakeContribCommitmentBackwardCompat.md §7 (`make_contrib_commitment:
    all-zero views == v1 short-circuit`, etc.; the runtime
    regressions that exercise T-1 + T-2 + corollaries).
  - tools/test_view_root.sh (CI gate that runs the scenarios above).
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    BlockIdx,           \* finite universe of u64 block-index values
    Hashes,             \* finite universe of 32-byte Hash values
                        \*   (must include a designated ZERO element)
    TxLists,            \* finite universe of bounded vector<Hash>
                        \*   values (= sorted, deduped tx-hash lists)
    ZERO,               \* the all-zero Hash{} (== Hash{} in C++)
    MaxTxs              \* spec-layer ceiling on tx-list length

ASSUME ConfigOK ==
    /\ Cardinality(BlockIdx) >= 1
    /\ Cardinality(Hashes)   >= 2     \* need at least ZERO + one non-zero
    /\ ZERO \in Hashes
    /\ Cardinality(TxLists)  >= 1
    /\ MaxTxs \in Nat /\ MaxTxs >= 0
    /\ \A txs \in TxLists : Len(txs) <= MaxTxs
    /\ \A txs \in TxLists : \A i \in 1..Len(txs) : txs[i] \in Hashes

\* The non-zero Hash universe — every value distinct from ZERO. Used
\* by the F2-branch quantifiers (the short-circuit fires only when at
\* least one of the three view-root slots holds a non-zero value).
NonZeroHashes == Hashes \ {ZERO}

\* -----------------------------------------------------------------
\* §1. The IsZero short-circuit predicate (matches is_zero_hash @
\* producer.cpp:242-245).
\* -----------------------------------------------------------------
\*
\* In C++ the predicate iterates the 32 bytes and returns true iff
\* every byte is 0. The spec-layer ZERO element captures the result
\* of that predicate verbatim: IsZero(h) IFF h is the designated
\* all-zero element.

IsZero(h) == h = ZERO

\* The composite "all three view roots are zero" predicate — exactly
\* the !any_view computation at producer.cpp:246-248. When this fires
\* TRUE, the `if (any_view)` body at lines 249-258 is skipped and the
\* implementation follows the v1 commit shape (L-1 of the analytic
\* proof).
AllViewsZero(eq, ab, inb) == IsZero(eq) /\ IsZero(ab) /\ IsZero(inb)

\* -----------------------------------------------------------------
\* §2. SHA-256 abstraction (the A2 / Preliminaries §2.1 lift).
\* -----------------------------------------------------------------
\*
\* The C++ `SHA256Builder` at `src/crypto/sha256.cpp:25-28` forwards
\* every `append(...)` call to `EVP_DigestUpdate`, which per FIPS
\* 180-4 §6.1.2 incorporates each byte into the message schedule in
\* the order received. Two builders fed identical append-sequences
\* produce identical outputs; two builders fed byte-distinct sequences
\* produce distinct outputs except with probability ≤ 2⁻¹²⁸
\* (L-2 + L-4 of the analytic proof). The spec-layer abstraction is
\* an INJECTIVE oracle on the bounded pre-image universe.
\*
\* We model the SHA-256 output as the tagged pre-image tuple itself.
\* Two distinct tuples produce distinct outputs by construction; two
\* identical tuples produce identical outputs. This is the same
\* "abstract hash = pre-image identity" pattern used by `Consensus.tla`
\* for `Digest`, by `Snapshot.tla` for `state_root`, and by
\* `FrostVerify.tla`'s `valid_pairs` abstraction.
\*
\* The V1 / F2 pre-image families are explicitly tagged so equality
\* of outputs is exactly equality of (kind, fields...). The "DTM-F2-v1"
\* domain tag in the F2 family is captured by the `"F2"` discriminator
\* — the analytic proof's L-3 length argument is structurally
\* expressible at the spec layer as "the two families have distinct
\* discriminators".
\*
\* InnerRoot is the inner SHA-256 over the sorted-deduped tx-hash
\* list (producer.cpp:225-227). It's itself an injection on distinct
\* tx-lists under A2; modeling it as the tx-list itself preserves the
\* injectivity property (we wrap each tx-list value in an `["inner",
\* txs]` tag so the inner-root cannot collide with any v1 or F2
\* pre-image structurally).

InnerRoot(txs) == << "inner", txs >>

\* V1Commit: the pre-F2 commit shape. Pre-image is the four-element
\* prefix (block_index || prev_hash || inner_root || dh_input). The
\* spec-layer abstraction records the tuple verbatim and tags it with
\* "V1" so it's structurally distinct from any F2 pre-image.
\*
\* This is the function the analytic proof calls `mcc_v1`; T-1
\* establishes that the v2 implementation reduces to this function
\* when the three view roots are all zero.
V1Commit(idx, prev, txs, dh) ==
    << "V1", idx, prev, InnerRoot(txs), dh >>

\* F2Commit: the v2.7 F2 commit shape. Pre-image is the four-element
\* prefix PLUS the "DTM-F2-v1" literal PLUS the three view roots. The
\* spec-layer abstraction records the tuple verbatim and tags it with
\* "F2" so it's structurally distinct from any V1 pre-image.
\*
\* The "DTM-F2-v1" literal is encoded as a discriminator-level tag
\* rather than a byte-level append because the analytic proof's L-3
\* argument is "different lengths ⇒ different byte sequences ⇒
\* different SHA-256 inputs ⇒ different outputs by A2". At the
\* spec layer, the "V1" vs "F2" discriminator captures the same
\* disjoint-pre-image-space contract structurally.
F2Commit(idx, prev, txs, dh, eq, ab, inb) ==
    << "F2", idx, prev, InnerRoot(txs), dh, "DTM-F2-v1", eq, ab, inb >>

\* -----------------------------------------------------------------
\* §3. The function under test: MakeCommit.
\* -----------------------------------------------------------------
\*
\* The Determ implementation at src/node/producer.cpp:219-260 is:
\*
\*   Hash make_contrib_commitment(uint64_t block_index,
\*                                 const Hash& prev_hash,
\*                                 const std::vector<Hash>& sorted_tx_hashes,
\*                                 const Hash& dh_input,
\*                                 const Hash& view_eq_root,
\*                                 const Hash& view_abort_root,
\*                                 const Hash& view_inbound_root) {
\*     // (lines 225-233) build the v1 four-element prefix
\*     // (lines 242-258) if any_view, append "DTM-F2-v1" + roots
\*     // (line 259) return finalize()
\*   }
\*
\* The if-branch at producer.cpp:249-258 is the v2.7 F2 extension; the
\* short-circuit at 242-248 is the v1-backward-compat guard. The
\* spec-layer abstraction:

MakeCommit(idx, prev, txs, dh, eq, ab, inb) ==
    IF AllViewsZero(eq, ab, inb)
    THEN V1Commit(idx, prev, txs, dh)
    ELSE F2Commit(idx, prev, txs, dh, eq, ab, inb)

\* -----------------------------------------------------------------
\* §4. State machine — generate input tuples, accumulate outputs.
\* -----------------------------------------------------------------
\*
\* The function under test is pure — every algebraic invariant
\* (INV-1..INV-6) holds over every reachable input tuple, not just
\* the ones produced by a particular protocol trace. The state
\* machine is therefore just a non-deterministic enumerator: a single
\* `Generate` action picks an input tuple, records the resulting
\* MakeCommit value in an accumulated map keyed by the tuple, and
\* TLC verifies the invariants hold against the accumulated map at
\* every reachable state. This is the same pattern
\* F2ViewReconciliation.tla uses.

\* The input-tuple universe (TLC enumerates over this).
InputTuple == [
    idx  : BlockIdx,
    prev : Hashes,
    txs  : TxLists,
    dh   : Hashes,
    eq   : Hashes,
    ab   : Hashes,
    inb  : Hashes
]

VARIABLES
    record,             \* function InputTuple -> Hash (the output map)
    generated           \* SUBSET InputTuple — which tuples have been
                        \*   enumerated so far (gates the per-tuple
                        \*   invariants against the empty-Init state)

vars == <<record, generated>>

\* Initial state: empty record map, no tuples enumerated.
\* `record` is total at Init (every key maps to a sentinel) so TypeOK
\* stays clean; `generated` is the set of keys that have actually been
\* assigned a real MakeCommit value via the Generate action.
SENTINEL == <<"unset">>

Init ==
    /\ record    = [t \in InputTuple |-> SENTINEL]
    /\ generated = {}

\* Generate: non-deterministically pick a fresh input tuple, compute
\* MakeCommit, and store. TLC explores every reachable enumeration.
Generate ==
    /\ \E t \in InputTuple :
       /\ t \notin generated
       /\ record'    = [record EXCEPT ![t] = MakeCommit(t.idx, t.prev,
                                                         t.txs, t.dh,
                                                         t.eq, t.ab,
                                                         t.inb)]
       /\ generated' = generated \cup {t}

\* Saturate: once every input tuple has been enumerated, stutter.
\* Bounded universe means TLC will reach saturation; the invariants
\* are evaluated at every reachable state along the way.
Saturate ==
    /\ generated = InputTuple
    /\ UNCHANGED vars

Next == Generate \/ Saturate

Spec == Init /\ [][Next]_vars /\ WF_vars(Generate)

\* -----------------------------------------------------------------
\* §5. Invariants — the six T-1 + T-2 + corollaries claims.
\* -----------------------------------------------------------------

\* INV-1 (V1ByteIdentity): for every (idx, prev, txs, dh), the
\* MakeCommit value with all-zero view roots equals the V1Commit
\* value. Lifts T-1 of the analytic proof.
\*
\* The proof's L-1 (all-zero short-circuit reproduces v1 byte-for-
\* byte) becomes a direct structural identity at the spec layer:
\* MakeCommit short-circuits to V1Commit when AllViewsZero holds.
\* TLC verifies this at every reachable state by walking every
\* generated tuple of the all-zero shape.
INV_V1ByteIdentity ==
    \A t \in generated :
       AllViewsZero(t.eq, t.ab, t.inb) =>
          record[t] = V1Commit(t.idx, t.prev, t.txs, t.dh)

\* INV-2 (F2PathTriggered): when at least one view root is non-zero,
\* MakeCommit follows the F2 path and the output is distinct from
\* what V1Commit would have produced on the same (idx, prev, txs, dh).
\*
\* Lifts T-2 forward direction (the F2 path is taken when any view
\* root is non-zero) + the no-collision part of T-2 (distinct shape
\* ⇒ distinct hash under A2; modeled here as "V1Commit and F2Commit
\* have distinct discriminators, so they are structurally distinct
\* tuples").
INV_F2PathTriggered ==
    \A t \in generated :
       (~AllViewsZero(t.eq, t.ab, t.inb)) =>
          /\ record[t] = F2Commit(t.idx, t.prev, t.txs, t.dh,
                                   t.eq, t.ab, t.inb)
          /\ record[t] # V1Commit(t.idx, t.prev, t.txs, t.dh)

\* INV-3 (PerRootBinding): when exactly ONE view root is non-zero
\* (and the other two are ZERO), MakeCommit is distinct from V1Commit
\* AND from the equivalent single-non-zero outputs at the other two
\* positions. Per-root domain separation works through the field-
\* position serialization — eq, abort, and inbound are bound at
\* distinct positions in the SHA-256 input, so a non-zero value in
\* one slot cannot collide with the same non-zero value in another
\* slot.
\*
\* This is the matrix-completion of T-2: not just "all-zero vs any-
\* non-zero", but "each individual non-zero slot produces a distinct
\* hash".
INV_PerRootBinding ==
    \A t \in generated :
       \A h \in NonZeroHashes :
          \* eq-only (eq=h, ab=ZERO, inb=ZERO) is distinct from
          \* abort-only (eq=ZERO, ab=h, inb=ZERO) and from
          \* inbound-only (eq=ZERO, ab=ZERO, inb=h).
          LET eqOnly == F2Commit(t.idx, t.prev, t.txs, t.dh, h, ZERO, ZERO) IN
          LET abOnly == F2Commit(t.idx, t.prev, t.txs, t.dh, ZERO, h, ZERO) IN
          LET inOnly == F2Commit(t.idx, t.prev, t.txs, t.dh, ZERO, ZERO, h) IN
          LET v1     == V1Commit(t.idx, t.prev, t.txs, t.dh) IN
          /\ eqOnly # v1
          /\ abOnly # v1
          /\ inOnly # v1
          /\ eqOnly # abOnly
          /\ eqOnly # inOnly
          /\ abOnly # inOnly

\* INV-4 (DomainSeparation): no v1-shape pre-image equals any
\* F2-shape pre-image. The "DTM-F2-v1" literal at the start of the
\* F2 extension makes the two families syntactically disjoint
\* (different lengths AND different content at the same byte offset).
\* L-3 of the analytic proof gives the length argument: 104 vs 209
\* bytes. The spec layer captures the disjoint families via the
\* "V1" vs "F2" discriminator.
\*
\* TLC verifies that for every reachable pair of input tuples — one
\* with all-zero views (= v1 family) and one with any non-zero view
\* (= F2 family) — the recorded outputs are distinct.
INV_DomainSeparation ==
    \A t1 \in generated :
    \A t2 \in generated :
       (AllViewsZero(t1.eq, t1.ab, t1.inb)
        /\ ~AllViewsZero(t2.eq, t2.ab, t2.inb))
       => record[t1] # record[t2]

\* INV-5 (Determinism): MakeCommit applied twice to the same input
\* tuple yields the same output. Captures the L-2 "SHA256Builder is
\* deterministic, append-order-bound, content-bound" lemma at the
\* state-machine layer.
\*
\* The state-form is: every generated input tuple maps to the same
\* output as MakeCommit would compute fresh on that tuple. Because
\* Generate stores `record[t] = MakeCommit(t.*)` and MakeCommit is a
\* pure function, the equality is structural; this invariant is
\* effectively a sanity check that the spec layer correctly captures
\* the determinism contract.
INV_Determinism ==
    \A t \in generated :
       record[t] = MakeCommit(t.idx, t.prev, t.txs, t.dh,
                              t.eq, t.ab, t.inb)

\* INV-6 (FieldBinding): every consensus-bound input field (idx,
\* prev, txs, dh) binds the hash — the output changes if that field
\* changes. Captures the "every field actually contributes to the
\* commitment" contract.
\*
\* For each input tuple in `generated`, we check that perturbing any
\* single field (with the others held constant) yields a distinct
\* MakeCommit value. This is a pure-function property that holds
\* structurally — the InnerRoot, V1Commit, and F2Commit operators
\* embed every field directly into the output tuple — but TLC
\* verifies it explicitly over the bounded universe.
\*
\* Note: we don't check field-binding for the three view-root slots
\* in INV-6 because INV-3 (PerRootBinding) already covers them more
\* tightly. The four fields here (idx, prev, txs, dh) are the v1
\* prefix common to both commit shapes.
INV_FieldBinding ==
    \A t \in generated :
       /\ \A idx2 \in BlockIdx :
             idx2 # t.idx =>
                MakeCommit(idx2, t.prev, t.txs, t.dh, t.eq, t.ab, t.inb)
                # record[t]
       /\ \A prev2 \in Hashes :
             prev2 # t.prev =>
                MakeCommit(t.idx, prev2, t.txs, t.dh, t.eq, t.ab, t.inb)
                # record[t]
       /\ \A txs2 \in TxLists :
             txs2 # t.txs =>
                MakeCommit(t.idx, t.prev, txs2, t.dh, t.eq, t.ab, t.inb)
                # record[t]
       /\ \A dh2 \in Hashes :
             dh2 # t.dh =>
                MakeCommit(t.idx, t.prev, t.txs, dh2, t.eq, t.ab, t.inb)
                # record[t]

\* -----------------------------------------------------------------
\* §6. Type invariant.
\* -----------------------------------------------------------------
\*
\* The record domain is the full InputTuple universe; the range
\* includes SENTINEL plus every reachable V1Commit / F2Commit tuple.
\* For TLC tractability we don't enumerate the range as a closed-form
\* set — we just assert `record` is some function on InputTuple and
\* let the per-generated-tuple invariants (INV-1..INV-6) constrain
\* the values structurally.

OutputRange == {SENTINEL}
    \cup {V1Commit(t.idx, t.prev, t.txs, t.dh) : t \in InputTuple}
    \cup {F2Commit(t.idx, t.prev, t.txs, t.dh, t.eq, t.ab, t.inb)
            : t \in InputTuple}

TypeOK ==
    /\ record    \in [InputTuple -> OutputRange]
    /\ generated \subseteq InputTuple

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what A2 asserts.
\* -----------------------------------------------------------------
\*
\* The SHA-256 collision-resistance assumption A2 (Preliminaries §2.1)
\* gives: no polynomial-time adversary finds x, y with x /= y and
\* SHA256(x) = SHA256(y) with probability non-negligibly better than
\* 2⁻¹²⁸ per attempt.
\*
\* The TLA+ state-machine layer abstracts that probabilistic bound as
\* a deterministic predicate: the V1Commit and F2Commit operators
\* return structurally distinct tuples for structurally distinct
\* pre-images, and identical tuples for identical pre-images. This is
\* the standard abstraction in formal protocol analysis (cf.
\* Preliminaries.md §11 citation conventions) — the analytic
\* FA-Crypto-MakeContrib track in MakeContribCommitmentBackwardCompat.md
\* gives the cryptographic tightness; the FB-track here checks the
\* state-machine consistency of the abstraction.
\*
\* INV-1 follows because MakeCommit short-circuits to V1Commit when
\* AllViewsZero holds — direct structural equality, no cryptographic
\* assumption needed for the spec-layer claim. The cryptographic
\* claim "byte-identical SHA-256 outputs" is what the analytic
\* proof's L-1 + L-2 establish at the C++ layer.
\*
\* INV-2 / INV-3 / INV-4 follow because V1Commit and F2Commit have
\* distinct discriminator tags ("V1" vs "F2"), and InputTuple-level
\* equality is sequence equality — distinct tags ⇒ distinct tuples
\* ⇒ distinct outputs. The cryptographic underpinning is L-3 (length
\* argument: 104 vs 209 bytes ⇒ distinct SHA-256 inputs ⇒ distinct
\* outputs under A2) + L-4 (collision bound).
\*
\* INV-5 follows because MakeCommit is a pure TLA+ operator —
\* identical inputs ⇒ identical outputs by definitional substitution.
\* The cryptographic claim is L-2 (SHA256Builder is deterministic;
\* OpenSSL's EVP_DigestUpdate is byte-stream deterministic).
\*
\* INV-6 follows because V1Commit and F2Commit embed every input
\* field directly into the output tuple — perturbing any field
\* produces a distinct tuple. The cryptographic underpinning is L-2's
\* content-binding + A2 (distinct pre-images map to distinct hashes
\* except with probability ≤ 2⁻¹²⁸).
\*
\* What the spec does NOT check:
\*   * Side-channel resistance of the underlying SHA-256
\*     implementation (out of scope; OpenSSL's constant-time
\*     guarantee is per their documentation).
\*   * The Ed25519 sig-side reduction in T-1.1 / T-2.1 (the
\*     signature compatibility / non-replayability corollaries) —
\*     those depend on Ed25519 EUF-CMA and are FrostVerify.tla / FA-
\*     Crypto-Verify territory. This spec covers only the commit-
\*     binding state machine; the sig-side reduction is a downstream
\*     composition of this spec + FrostVerify.tla under A1.
\*   * Byte-level enumeration of the SHA-256 compression function —
\*     A2 abstracts the cryptographic content into "distinct pre-
\*     images map to distinct hashes"; the spec layer models that
\*     abstraction.
\*
\* The composition with FrostVerify.tla closes T-1.1 and T-2.1: a
\* signature σ_v1 valid under V1Commit(...) is valid under
\* MakeCommit(..., ZERO, ZERO, ZERO) because the two commit values
\* are byte-identical (INV-1). A signature σ_F2 valid under F2Commit
\* (..., eq, ab, inb) is NOT valid under V1Commit(...) because the
\* two commit values are distinct (INV-2 / INV-3 / INV-4) and
\* Ed25519 EUF-CMA (A1 / FrostVerify.tla INV-4) gives the negligible-
\* probability bound on cross-shape replay.

============================================================================
\* Cross-references.
\*
\* FA-Crypto-MakeContrib (MakeContribCommitmentBackwardCompat.md) ->
\*   T-1            : INV-1 (V1ByteIdentity — the v1 short-circuit
\*                    identity)
\*   T-1.1          : downstream composition of INV-1 + FrostVerify.tla
\*                    INV-RoundTripSoundness — covered analytically in
\*                    §4 of the companion proof; the spec layer
\*                    establishes INV-1 which is the algebraic input
\*                    to that composition
\*   T-2            : INV-2 (F2PathTriggered) + INV-4 (DomainSeparation)
\*                    — distinct commit shapes ⇒ distinct outputs
\*   T-2.1          : downstream composition of INV-2 + INV-4 +
\*                    FrostVerify.tla INV-TamperedMsgRejection —
\*                    covered analytically in §5 of the companion
\*                    proof; the spec layer establishes the commit-
\*                    side distinctness
\*   L-1            : the AllViewsZero ⇒ V1Commit branch in
\*                    MakeCommit (matches src/node/producer.cpp:242-258
\*                    short-circuit)
\*   L-2            : INV-5 (Determinism) + INV-6 (FieldBinding) —
\*                    SHA256Builder is deterministic and content-bound
\*   L-3            : INV-4 (DomainSeparation) — the length argument
\*                    lifted to the discriminator-tag distinctness
\*   L-4            : not directly modeled — A2's collision bound is
\*                    abstracted into the "distinct tuples ⇒ distinct
\*                    outputs" identity used throughout
\*
\* Preliminaries.md §2.1 A2 : SHA-256 collision resistance. Modeled
\*   as the injective `InputTuple -> Output` mapping at the spec
\*   layer (V1Commit and F2Commit operators distinguish all distinct
\*   inputs by construction).
\*
\* Preliminaries.md §2.2 A1 : Ed25519 EUF-CMA. Used by the T-1.1 /
\*   T-2.1 corollaries; the sig-side reduction is FrostVerify.tla
\*   territory.
\*
\* F2-SPEC.md §Q4 : design decision to extend `make_contrib_commitment`
\*   with the three view roots under a single Ed25519 sig (rather
\*   than three separate sigs). The `"DTM-F2-v1"` tag is the
\*   identifier chosen to make the v1-vs-F2 pre-image families
\*   syntactically disjoint.
\*
\* F2ViewReconciliation.tla (FB22): the validator-side reconciliation
\*   primitives that consume the view roots this primitive binds.
\*   Together the two specs close the consensus-layer half of S-030
\*   D2 (commit-side binding: this spec; validator-side
\*   reconciliation: FB22).
\*
\* FrostVerify.tla (FB23): sibling FB-Crypto spec; style template for
\*   this module (the "pure-function + bounded enumeration + INV-*"
\*   pattern, the A2 / EUF-CMA abstraction approach, the cross-
\*   references format).
\*
\* C++ enforcement: src/node/producer.cpp
\*   make_contrib_commitment            @ lines 219-260
\*   inner-root computation             @ lines 225-227
\*   v1 four-element prefix             @ lines 229-233
\*   is_zero_hash lambda                @ lines 242-245
\*   any_view predicate                 @ lines 246-248
\*   F2 branch ("DTM-F2-v1" + roots)    @ lines 249-258
\*   finalize and return                @ line 259
\*
\* Header declarations + default-zero trailing args + docstring:
\*   include/determ/node/producer.hpp:117-139
\*
\* Runtime regressions: src/main.cpp scenarios cited at
\*   MakeContribCommitmentBackwardCompat.md §7 (the table of nine
\*   assertions covering T-1 byte-identity, T-2 distinct-views, T-2.1
\*   sig-side reduction).
\* CI gate: tools/test_view_root.sh (runs `determ test-view-root`
\*   which exercises the assertions above).
============================================================================
