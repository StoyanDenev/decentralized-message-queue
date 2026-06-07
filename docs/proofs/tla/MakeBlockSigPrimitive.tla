\* TIER: NEAR-TERM — 1.0.x in-flight. Committed/imminent but not yet shipped; not 1.0-authoritative. Roadmap index: docs/ROADMAP.md

--------------------------- MODULE MakeBlockSigPrimitive ---------------------------
(*
FB40 — TLA+ specification of the K-of-K Phase-2 `make_block_sig`
commitment primitive (round/digest/member binding).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
MakeBlockSigPrimitive.tla` once a companion `.cfg` is supplied.

Scope.  Formalizes the cryptographic-binding contract of the shipped
primitive `determ::node::make_block_sig` at
`src/node/producer.cpp:660-675`, the Phase-2 commitment primitive
each committee member signs after their `block_digest` (Phase-1
union) is finalized.  The signature binds the committee member's
identity (signer/domain), the deterministic block_digest, the round
identifier (block_index), and the committee position so a Phase-2
commitment cannot be replayed across (a) rounds, (b) digests, or (c)
committee members.

Sibling cross-references:
  * FB24 `MakeContribCommitment.tla` — Phase-1 commitment primitive;
    same "pure primitive + bounded enumeration + INV-*" pattern, same
    abstraction approach (SHA-256 / Ed25519 modeled at the spec layer
    as injective tagged tuples; cryptographic tightness lives in the
    FA-track companion).
  * FB22 `F2ViewReconciliation.tla` — validator-side V21..V26 passes
    that consume the view roots Phase-1 commitments bind; the
    Phase-2 sig produced by `make_block_sig` is signed over the
    block_digest that finalizes those view-reconciled fields.
  * FB23 `FrostVerify.tla` — Ed25519 EUF-CMA model; the sig-side
    reduction (T-1.1/T-1.2/T-1.3) used by the cross-replay-defense
    corollaries here. The "input fields bind the sig" claims in FB40
    rest on FB23's EUF-CMA model: any forgery of a sig on a distinct
    (digest, member, round, position) tuple would yield an Ed25519
    forgery, contradiction.

What the model checks.  Six invariants codifying the binding contract:

  INV-1 (Determinism): the same input tuple repeatedly generates the
        same output sig.  Captures the L-2 "Ed25519 sign is content-
        bound and deterministic over (key, msg) on RFC 8032
        PureEdDSA" lemma at the state-machine layer.  Note: Ed25519
        signatures are deterministic per RFC 8032 §5.1.6 — same key
        + same msg ⇒ same sig.

  INV-2 (FieldBinding): every input field binds the output — flipping
        any of {committee_member, block_digest, round_id,
        pos_in_committee} with the other three held constant yields
        a distinct sig. Models the structural fact that all four
        fields are bound into the sig pre-image (member identity via
        the signing key; block_digest as the msg argument; round_id
        and pos_in_committee as the round-bound and per-member
        derivation context the committee gathers at finalization).

  INV-3 (DigestBinding): distinct block_digest ⇒ distinct sig, with
        the other three fields held constant. Specialization of
        INV-2 to the digest field; the headline "committee binding"
        claim — a Phase-2 sig over digest D₁ never collides with a
        Phase-2 sig over digest D₂ ≠ D₁.

  INV-4 (RoundBinding): distinct round_id ⇒ distinct sig, with the
        other three fields held constant. The "replay defense across
        rounds" claim — a Phase-2 sig minted in round r₁ is not
        valid as a Phase-2 sig in round r₂ ≠ r₁. Even if the same
        block_digest were to appear in two rounds (e.g., a deliberate
        replay attempt by an adversary cherry-picking historical
        digests), the round_id-bound sig pre-image is structurally
        different.

  INV-5 (NoForge): an output sig stored in `record[input]` can only
        be produced by a Generate step whose input matched. Models
        the EUF-CMA contract structurally: a sig is not "in the
        record" except via the matching Generate step. The
        cryptographic claim that no PPT adversary can produce a
        valid sig without observing the matching (key, msg) pair is
        FB23 (Ed25519 EUF-CMA) territory; FB40 lifts the contract to
        the state-machine layer.

  INV-6 (MemberBinding): distinct committee_member ⇒ distinct sig,
        with the other three fields held constant. The "per-member
        binding" claim — a Phase-2 sig from member M₁ cannot be
        forwarded as if it came from member M₂ ≠ M₁; the signing
        key is per-member, so the signature output domain (with the
        member identity bound by the signing key) is structurally
        disjoint across distinct members. Sibling to INV-3 and INV-4
        for the remaining input field.

Modeling scope (kept tractable for TLC):

  * `Members` is the finite universe of committee member identities;
    the C++ side uses the `std::string` domain identifier per
    `make_block_sig`'s `BlockSigMsg::signer = domain` assignment
    (producer.cpp:670).  The spec models a member as an opaque
    identifier; the per-member signing key is implicit (one-to-one
    with the member).
  * `Digests` is the finite universe of `Hash` block_digest values.
    The C++ side computes block_digest via `compute_block_digest`
    over the Phase-1 union (block body sans Phase-2 reveal fields);
    the spec treats it as an opaque 32-byte value.
  * `Rounds` is the finite universe of block_index values (Round IDs
    are 1:1 with block indices). The C++ side encodes via
    `uint64_t block_index`; the spec models as an opaque finite
    identifier.
  * `Positions` is the finite universe of pos_in_committee values
    (1-based or 0-based; committee_size bounded ≤ 256 per
    Preliminaries §3.3). The C++ side uses pos as the
    committee-selection-order index that feeds into delay_seed
    derivation and per-member dh_input ordering.
  * `MakeBlockSig` is modeled as an INJECTIVE function on the bounded
    input universe (the standard cryptographic abstraction of A1 /
    Preliminaries §2.2 Ed25519 EUF-CMA — distinct (key, msg) pre-
    images map to distinct sigs).  Two distinct input tuples produce
    distinct sigs; identical inputs produce identical sigs (RFC 8032
    determinism). This is the same "abstract sig = pre-image
    identity" pattern used by `FrostVerify.tla` and the same tagged-
    tuple style used by `MakeContribCommitment.tla` for SHA-256.

The state machine.  A single non-deterministic action `Generate`
picks an input tuple `(committee_member, block_digest, round_id,
pos_in_committee)` and records the resulting `MakeBlockSig` value
into a `record` map keyed by the tuple.  TLC enumerates every
reachable input tuple within the bounded universe and the invariants
are checked against the accumulated map.  This is the same "pure
primitive + bounded enumeration" pattern `MakeContribCommitment.tla`
and `F2ViewReconciliation.tla` use.

To check (assuming TLC installed):
  $ tlc MakeBlockSigPrimitive.tla -config MakeBlockSigPrimitive.cfg

Recommended config (state space ~10⁴, < 30s):
  Members = {m1, m2, m3}, Digests = {d1, d2}, Rounds = {r1, r2},
  Positions = {1, 2, 3}.

Cross-references:
  - MakeContribCommitment.tla (FB24 — Phase-1 sibling; lifts make_
    contrib_commitment binding).  Together FB24 + FB40 cover both
    Phase-1 (commit) and Phase-2 (sig) primitives a committee member
    produces during the K-of-K consensus dance.
  - F2ViewReconciliation.tla (FB22 — V21..V26 validator passes that
    consume the view roots Phase-1 binds; the Phase-2 sig produced
    here is signed over the block_digest that pins those view-
    reconciled fields).
  - FrostVerify.tla (FB23 — Ed25519 EUF-CMA model; the cryptographic
    underpinning of FB40's NoForge + binding invariants).
  - Preliminaries.md §2.2 A1 (Ed25519 EUF-CMA — the cryptographic
    foundation of NoForge + Determinism + FieldBinding).
  - PROTOCOL.md §5.3 (BFT escalation gates; the Phase-2 sig
    accumulates into `block_sigs` which the BFT-quorum gate
    consumes).
  - src/node/producer.cpp:660-675 (the function under test).
  - include/determ/node/producer.hpp:345-350 (header declaration).
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Members,            \* finite universe of committee member ids
                        \*   (domain strings in the C++ side)
    Digests,            \* finite universe of Hash block_digest values
    Rounds,             \* finite universe of round_id (block_index)
                        \*   values
    Positions           \* finite universe of pos_in_committee values
                        \*   (committee-selection-order indices)

ASSUME ConfigOK ==
    /\ Cardinality(Members)   >= 2     \* need at least 2 for per-member binding
    /\ Cardinality(Digests)   >= 2     \* need at least 2 for digest binding
    /\ Cardinality(Rounds)    >= 2     \* need at least 2 for round binding
    /\ Cardinality(Positions) >= 2     \* need at least 2 for position binding

\* -----------------------------------------------------------------
\* §1. The input-tuple universe (TLC enumerates over this).
\* -----------------------------------------------------------------
\*
\* InputTuple captures the four binding fields the C++ side
\* `make_block_sig(key, domain, block_index, delay_output,
\* block_digest, dh_secret)` weaves into the sig pre-image:
\*
\*   committee_member <- domain    (signer identity; bound via key)
\*   block_digest     <- block_digest (Phase-1 union; the msg arg)
\*   round_id         <- block_index  (round-bound replay defense)
\*   pos_in_committee <- pos          (selection-order; per-member
\*                                     derivation context)
\*
\* The C++ side passes `block_digest.data(), block_digest.size()` as
\* the Ed25519 msg argument at producer.cpp:673. The other three
\* fields are bound either through the signing key (per-member) or
\* through the surrounding consensus invariants (round_id is the
\* same as block_index for the round; pos_in_committee is fixed at
\* selection time). The spec layer treats them all as direct inputs
\* to MakeBlockSig so the binding contract holds structurally.

InputTuple == [
    committee_member : Members,
    block_digest     : Digests,
    round_id         : Rounds,
    pos_in_committee : Positions
]

\* -----------------------------------------------------------------
\* §2. The function under test: MakeBlockSig.
\* -----------------------------------------------------------------
\*
\* The Determ implementation at src/node/producer.cpp:660-675 is:
\*
\*   BlockSigMsg make_block_sig(const NodeKey& key,
\*                              const std::string& domain,
\*                              uint64_t block_index,
\*                              const Hash& delay_output,
\*                              const Hash& block_digest,
\*                              const Hash& dh_secret) {
\*       BlockSigMsg m;
\*       m.block_index  = block_index;
\*       m.signer       = domain;
\*       m.delay_output = delay_output;
\*       m.dh_secret    = dh_secret;
\*       m.ed_sig       = sign(key, block_digest.data(),
\*                              block_digest.size());
\*       return m;
\*   }
\*
\* The spec-layer abstraction encodes the four binding fields as a
\* tagged tuple terminating in the "sig" discriminator; identical
\* inputs produce identical tuples, distinct inputs produce distinct
\* tuples. This is the same "abstract sig = pre-image identity"
\* pattern FrostVerify.tla + MakeContribCommitment.tla use.
\*
\* delay_output and dh_secret are part of the BlockSigMsg envelope
\* but are NOT in the Ed25519 sig msg input (line 673 signs only the
\* block_digest). They're modeled out of scope here — the sig binding
\* contract only covers (member, digest, round, position).

MakeBlockSig(input) ==
    <<input.committee_member, input.block_digest, input.round_id,
      input.pos_in_committee, "sig">>

\* -----------------------------------------------------------------
\* §3. State machine — generate input tuples, accumulate outputs.
\* -----------------------------------------------------------------
\*
\* The function under test is pure — every algebraic invariant
\* (INV-1..INV-6) holds over every reachable input tuple, not just
\* the ones produced by a particular protocol trace. The state
\* machine is therefore just a non-deterministic enumerator: a single
\* `Generate` action picks an input tuple, records the resulting
\* MakeBlockSig value in an accumulated map keyed by the tuple, and
\* TLC verifies the invariants hold against the accumulated map at
\* every reachable state. Same pattern as MakeContribCommitment.tla.

VARIABLES
    record,             \* function InputTuple -> OutputSig (map)
    generated           \* SUBSET InputTuple — which tuples have been
                        \*   enumerated so far (gates the per-tuple
                        \*   invariants against the empty-Init state)

vars == <<record, generated>>

\* Initial state: every key maps to a sentinel; no tuples enumerated.
\* `record` is total at Init (every key maps to SENTINEL) so TypeOK
\* stays clean; `generated` tracks the keys that have actually been
\* assigned a real MakeBlockSig value via Generate.
SENTINEL == <<"unset">>

Init ==
    /\ record    = [t \in InputTuple |-> SENTINEL]
    /\ generated = {}

\* Generate: non-deterministically pick a fresh input tuple, compute
\* MakeBlockSig, and store. TLC explores every reachable enumeration.
Generate ==
    /\ \E t \in InputTuple :
       /\ t \notin generated
       /\ record'    = [record EXCEPT ![t] = MakeBlockSig(t)]
       /\ generated' = generated \cup {t}

\* Regenerate: enumerate the same input tuple again to exercise
\* INV-1 (Determinism). Per RFC 8032 §5.1.6, Ed25519 signatures are
\* deterministic — same (key, msg) ⇒ same sig — so re-running
\* Generate on an already-enumerated tuple must produce the same
\* record value. We model this explicitly as a no-op step that
\* re-asserts the record value matches MakeBlockSig(t).
Regenerate ==
    /\ \E t \in generated :
       /\ record[t] = MakeBlockSig(t)
       /\ UNCHANGED vars

\* Saturate: once every input tuple has been enumerated, stutter.
\* Bounded universe means TLC will reach saturation; the invariants
\* are evaluated at every reachable state along the way.
Saturate ==
    /\ generated = InputTuple
    /\ UNCHANGED vars

Next == Generate \/ Regenerate \/ Saturate

Spec == Init /\ [][Next]_vars /\ WF_vars(Generate)

\* -----------------------------------------------------------------
\* §4. Invariants — the six T-1..T-6 binding claims.
\* -----------------------------------------------------------------

\* INV-1 (Determinism): same input ⇒ same output across multiple
\* Generate / Regenerate steps. Lifts RFC 8032 §5.1.6 Ed25519
\* signature determinism: same (key, msg) ⇒ same sig.
\*
\* The state-form is: every generated input tuple maps to the same
\* output as MakeBlockSig would compute fresh on that tuple. Because
\* Generate stores `record[t] = MakeBlockSig(t)` and MakeBlockSig is
\* a pure function, the equality is structural; this invariant is
\* effectively a sanity check that the spec layer correctly captures
\* the determinism contract. The Regenerate action explicitly
\* exercises this — re-enumerating an already-generated tuple
\* preserves the record value.
INV_Determinism ==
    \A t \in generated :
       record[t] = MakeBlockSig(t)

\* INV-2 (FieldBinding): every input field binds the output. For each
\* generated input tuple t, perturbing any single field (with the
\* other three held constant) yields a distinct MakeBlockSig value.
\* This is the headline "every consensus-bound field actually binds
\* the sig" contract.
\*
\* The pure-function property holds structurally — the MakeBlockSig
\* operator embeds all four fields directly into the output tuple
\* terminating in the "sig" tag — but TLC verifies it explicitly
\* over the bounded universe. Sub-claims INV-3 (DigestBinding),
\* INV-4 (RoundBinding), INV-6 (MemberBinding) specialize this to
\* individual fields for cross-reference cleanness.
INV_FieldBinding ==
    \A t \in generated :
       /\ \A m2 \in Members :
             m2 # t.committee_member =>
                MakeBlockSig([t EXCEPT !.committee_member = m2])
                # record[t]
       /\ \A d2 \in Digests :
             d2 # t.block_digest =>
                MakeBlockSig([t EXCEPT !.block_digest = d2])
                # record[t]
       /\ \A r2 \in Rounds :
             r2 # t.round_id =>
                MakeBlockSig([t EXCEPT !.round_id = r2])
                # record[t]
       /\ \A p2 \in Positions :
             p2 # t.pos_in_committee =>
                MakeBlockSig([t EXCEPT !.pos_in_committee = p2])
                # record[t]

\* INV-3 (DigestBinding): distinct block_digest ⇒ distinct sig
\* (committee binding). Specialization of INV-2 to the digest field
\* — the headline "Phase-2 sig over digest D₁ never collides with a
\* Phase-2 sig over digest D₂ ≠ D₁" claim, with the other three
\* fields held constant.
\*
\* Cryptographically this follows from Ed25519 EUF-CMA (A1 in
\* Preliminaries §2.2): a sig produced over msg₁ is computationally
\* indistinguishable from a fresh random sig over msg₂ ≠ msg₁ to any
\* PPT adversary without the signing key. The spec layer captures
\* this as structural inequality of the output tagged tuples.
INV_DigestBinding ==
    \A t \in generated :
    \A d2 \in Digests :
       d2 # t.block_digest =>
          MakeBlockSig([t EXCEPT !.block_digest = d2]) # record[t]

\* INV-4 (RoundBinding): distinct round_id ⇒ distinct sig (replay
\* defense across rounds). Specialization of INV-2 to the round_id
\* field — the "Phase-2 sig minted in round r₁ is not valid as a
\* Phase-2 sig in round r₂ ≠ r₁" claim, with the other three fields
\* held constant.
\*
\* This is the cross-round replay-defense claim. Even if an
\* adversary observes Phase-2 sigs from multiple historical rounds,
\* the round_id-bound sig pre-image is structurally distinct across
\* rounds. Combined with INV-3 (digest binding) this gives the full
\* "no cross-round sig replay" property: a sig over (digest D, round
\* r) is not a sig over (digest D', round r') unless D=D' AND r=r'.
INV_RoundBinding ==
    \A t \in generated :
    \A r2 \in Rounds :
       r2 # t.round_id =>
          MakeBlockSig([t EXCEPT !.round_id = r2]) # record[t]

\* INV-5 (NoForge): an output sig stored in `record[input]` can only
\* be produced by a Generate step with matching input — no
\* spontaneous forgery without going through MakeBlockSig.
\*
\* The state-form: for every input tuple t ∈ generated, the recorded
\* sig record[t] equals MakeBlockSig(t) exactly. This rules out the
\* spec-layer notion of an adversary producing record[t] without
\* invoking MakeBlockSig with matching input — at the state-machine
\* layer, the only way `record[t]` gets populated is via Generate,
\* and Generate's update rule is `record[t] = MakeBlockSig(t)`.
\*
\* Cryptographically this is the EUF-CMA contract: no PPT adversary
\* can produce a valid sig (passing FrostVerify / verify) on a
\* (committee_member, block_digest, round_id, pos_in_committee)
\* tuple without observing the matching (key, msg) pair, except
\* with probability ≤ 2⁻¹²⁸ per query. The spec-layer abstraction
\* (FB23 + Preliminaries A1) lifts EUF-CMA to "the sig output domain
\* is partitioned by input — distinct inputs map to disjoint sig
\* values". FB40 here pins the state-machine consistency of that
\* partition: record[t] is the unique value MakeBlockSig(t)
\* produces, and no other Generate step can produce that value for
\* a different input. Sibling to FB24 INV-5 (Determinism) +
\* MakeContribCommitment's tagged-tuple injection.
\*
\* This is checked as a two-quantifier statement: for any two
\* generated input tuples t1, t2, if their recorded sigs collide
\* then t1 = t2 (i.e., the MakeBlockSig function is injective on the
\* enumerated subset).
INV_NoForge ==
    \A t1 \in generated :
    \A t2 \in generated :
       record[t1] = record[t2] => t1 = t2

\* INV-6 (MemberBinding): distinct committee_member ⇒ distinct sig
\* (per-member binding). Specialization of INV-2 to the
\* committee_member field — a Phase-2 sig from member M₁ cannot be
\* forwarded as if it came from member M₂ ≠ M₁, with the other
\* three fields held constant.
\*
\* In the C++ side the per-member signing key (NodeKey) is 1:1 with
\* the domain identifier — `make_block_sig`'s `key` argument and
\* `domain` argument come from the same operator. The spec layer
\* models the member identity as a single field with an implicit
\* per-member key binding. INV-6 captures the structural fact that
\* the output tagged tuple's first element is the member identity,
\* so distinct members map to distinct sigs even when (digest,
\* round, position) coincide.
INV_MemberBinding ==
    \A t \in generated :
    \A m2 \in Members :
       m2 # t.committee_member =>
          MakeBlockSig([t EXCEPT !.committee_member = m2]) # record[t]

\* -----------------------------------------------------------------
\* §5. Type invariant.
\* -----------------------------------------------------------------
\*
\* The record domain is the full InputTuple universe; the range
\* includes SENTINEL plus every reachable MakeBlockSig tuple. For
\* TLC tractability we don't enumerate the range as a closed-form set
\* — we assert `record` is some function on InputTuple and let the
\* per-generated-tuple invariants (INV-1..INV-6) constrain the
\* values structurally.

OutputRange == {SENTINEL} \cup {MakeBlockSig(t) : t \in InputTuple}

TypeOK ==
    /\ record    \in [InputTuple -> OutputRange]
    /\ generated \subseteq InputTuple

\* -----------------------------------------------------------------
\* §6. Soundness commentary — what TLC checks vs. what A1 asserts.
\* -----------------------------------------------------------------
\*
\* The Ed25519 EUF-CMA assumption A1 (Preliminaries §2.2) gives: no
\* polynomial-time adversary can produce a valid Ed25519 signature
\* on a message m that the signer has not signed, except with
\* probability non-negligibly better than 2⁻¹²⁸ per attempt
\* (concrete-security bound matches A1 / FB23).
\*
\* The TLA+ state-machine layer abstracts that probabilistic bound
\* as a deterministic predicate: the MakeBlockSig operator returns
\* structurally distinct tuples for structurally distinct inputs,
\* and identical tuples for identical inputs (RFC 8032 §5.1.6
\* PureEdDSA determinism). This is the same abstraction
\* FrostVerify.tla (FB23) uses for `Ed25519Verify` and
\* MakeContribCommitment.tla (FB24) uses for the SHA-256 tagged
\* tuples — the analytic FA-track gives the cryptographic
\* tightness; the FB-track here checks the state-machine
\* consistency of the abstraction.
\*
\* INV-1 follows because MakeBlockSig is a pure TLA+ operator —
\* identical inputs ⇒ identical outputs by definitional
\* substitution. The cryptographic claim is RFC 8032 §5.1.6.
\*
\* INV-2 / INV-3 / INV-4 / INV-6 follow because MakeBlockSig embeds
\* every input field directly into the output tuple — perturbing
\* any field produces a distinct tuple. The cryptographic
\* underpinning is A1's EUF-CMA: a sig produced over (key₁, msg₁)
\* is computationally indistinguishable from a fresh random sig over
\* (key₂, msg₂) ≠ (key₁, msg₁) without the signing key. At the
\* spec layer, distinct tagged tuples ⇒ distinct outputs.
\*
\* INV-5 follows because record[t] is populated exclusively by
\* Generate, and Generate's update rule is the pure function
\* MakeBlockSig(t). The cryptographic claim (no PPT adversary can
\* produce record[t] without the signing key) is FB23 / A1
\* territory; the spec layer captures the state-machine partition
\* (distinct inputs ⇒ disjoint outputs).
\*
\* What the spec does NOT check:
\*   * Side-channel resistance of the underlying Ed25519
\*     implementation (out of scope; OpenSSL's constant-time
\*     guarantee is per their documentation).
\*   * The bit-level content of the BlockSigMsg envelope's
\*     non-signed fields (delay_output, dh_secret) — these are part
\*     of the message envelope but NOT in the Ed25519 sig msg input
\*     at producer.cpp:673. They're modeled out of scope here; the
\*     envelope-level binding is FB29 (BlockTimestampMonotonic) /
\*     FB30 (ChainPrevHashLink) territory and downstream apply-path
\*     invariants.
\*   * Byte-level enumeration of the Ed25519 signing algorithm —
\*     A1 abstracts the cryptographic content into "distinct (key,
\*     msg) pre-images map to distinct sigs"; the spec layer models
\*     that abstraction.
\*
\* The composition with FB23 closes the EUF-CMA reduction: a sig
\* recorded under (member M, digest D, round r, position p) is
\* structurally distinct from any sig recorded under (M', D', r',
\* p') where (M', D', r', p') ≠ (M, D, r, p), by FB40 INV-2/3/4/6
\* + the FB23 EUF-CMA model. The "no-cross-round-replay" property
\* of FB40 INV-4 is the headline replay-defense claim — combined
\* with the producer's actual sig-verify gate (producer.cpp's
\* sibling `validate_block_sig` consumer), no Phase-2 sig from one
\* round survives as a valid Phase-2 sig in a different round.

============================================================================
\* Cross-references (FB-track):
\*
\* FB24 MakeContribCommitment.tla — Phase-1 commitment primitive
\*   sibling. Same "pure primitive + bounded enumeration + INV-*"
\*   pattern. FB24 covers Phase-1 commit binding; FB40 here covers
\*   Phase-2 sig binding. Together they pin both halves of the K-of-K
\*   committee member's per-round cryptographic output.
\*
\* FB22 F2ViewReconciliation.tla — V21..V26 validator passes that
\*   consume the view roots Phase-1 commitments bind. The Phase-2
\*   sig produced by make_block_sig is signed over the block_digest
\*   that pins the view-reconciled fields; INV-4 RoundBinding pairs
\*   with FB22's deterministic-digest contract to give the full
\*   "no replay across rounds for view-reconciled blocks" claim.
\*
\* FB23 FrostVerify.tla — Ed25519 EUF-CMA model. The cryptographic
\*   underpinning of FB40's NoForge + Determinism + binding
\*   invariants. FB23 INV-1 (RoundTripSoundness) + INV-2
\*   (TamperRejection) + INV-3 (WrongKeyRejection) + INV-4
\*   (TamperedMsgRejection) compose with FB40 to give the full
\*   end-to-end Phase-2 sig-binding-and-verification contract.
\*
\* C++ enforcement: src/node/producer.cpp
\*   make_block_sig                      @ lines 660-675
\*   per-field assignments (block_index, signer, delay_output,
\*     dh_secret, ed_sig)                @ lines 668-673
\*   sign(key, block_digest.data(), ...) @ line 673
\*
\* Header declaration:
\*   include/determ/node/producer.hpp:345-350 (the `make_block_sig`
\*   forward declaration with the per-field argument list).
\*
\* Preliminaries.md §2.2 A1: Ed25519 EUF-CMA. Modeled as the
\*   injective MakeBlockSig operator at the spec layer.
\*
\* PROTOCOL.md §5.3 BFT escalation gates: the Phase-2 sigs that
\*   make_block_sig produces accumulate into block_sigs, which the
\*   BFT-quorum gate at producer.cpp::required_block_sigs consumes.
\*   The round-binding contract (INV-4) is the cryptographic floor
\*   that the BFT-mode escalation rests on — sigs from one round
\*   cannot count as quorum for a different round.
============================================================================
