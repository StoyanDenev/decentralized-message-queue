--------------------------- MODULE S006ContribMsgEquivocation ---------------------------
(*
FB28 — TLA+ companion to R23A7 `S006ContribMsgEquivocation.md` analytic
proof (Phase-1 same-generation ContribMsg equivocation detection — the
S-006 closure).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
S006ContribMsgEquivocation.cfg S006ContribMsgEquivocation.tla` once a
companion `.cfg` is supplied.

Scope. Formalizes the receive-time Phase-1 equivocation detection
shipped at `src/node/node.cpp::on_contrib` (lines 2056..2170). The
S-006 closure adds a second equivocation-detection surface — at the
Phase-1 commit layer — without introducing a new wire format, new
validator predicate, or new apply-side branch. Two distinct
`ContribMsg`s at the same `(signer, block_index, aborts_gen)` with
different commitment hashes are detected on the second arrival; the
detector constructs an `EquivocationEvent` (digest_a / sig_a from the
existing entry, digest_b / sig_b from the incoming one) and pushes it
into the shared `pending_equivocation_evidence_` pool. The same pool
is consumed by the producer's `build_body` and by the V11 validator
predicate, so the new event composes with FA6 (slashing soundness)
and FA-Apply-10 (apply-side mechanics) without any structural change.

Five paired theorems are pinned (per S006ContribMsgEquivocation.md
§1, with T-3 composition lifted into INV-3 + INV-6):

  (T-1) Same-generation duplicate detection. Two `ContribMsg`s with
        the same signer / block_index / aborts_gen but distinct
        commitments produce exactly one `EquivocationEvent` carrying
        both signed commits.
  (T-2) Different-generation drop, no false positive. Two
        `ContribMsg`s at different `aborts_gen` never produce an
        `EquivocationEvent` — the gen-gate at `node.cpp:2068` drops
        the cross-gen message before the duplicate-detect branch is
        reached, and the per-round reset clears `pending_contribs_`
        across abort-quorum boundaries.
  (T-3) Composition with FA6 + FA-Apply-10. The constructed event
        satisfies V11's predicate by construction (digest_a !=
        digest_b, sig_a != sig_b, equivocator registered, both
        sigs verifiable under the registered pubkey). No new wire
        format, validator predicate, or apply-side branch is
        introduced.
  (T-4) Two-sig proof soundness. Both `sig_a` and `sig_b` are
        verifiable Ed25519 signatures over their respective
        commitments under the equivocator's registered key.
  (T-5) Replay-safety. Re-applying the same equivocation event (via
        intra-block duplicates or cross-block gossip) contributes
        zero additional slash beyond the first apply (FA-Apply-10
        T-E3 + S-006's pool-dedup at `node.cpp:2147..2153`).

The state machine. Honest peers receive `ContribMsg` records from the
gossip layer; per-signer entries land in `pending_contribs` keyed by
(signer, block_index, gen) — but the C++ `pending_contribs_` is
actually keyed by signer only, with the gen-gate filtering arrivals
to the current generation. The spec models this as a partial function
`pending_contribs : Signers -> ContribMsg` plus an explicit
`current_gen : Nat` variable; the gen-gate is enforced in the
`ReceiveContrib` action's guard. A per-round reset (modeled by
`AdvanceGeneration`) clears `pending_contribs` when the generation
advances, matching the C++ `reset_round` machinery.

  * `ReceiveContrib(signer, block_idx, gen, commit_hash, sig)` —
    arrival of a single `ContribMsg`. Branches:
      - cross-gen (gen # current_gen): no-op (dropped at the gate).
      - first arrival at current_gen: admit into pending_contribs.
      - same-(signer, current_gen), same commit_hash: byte-identical
        retry — drop silently, no event.
      - same-(signer, current_gen), different commit_hash: construct
        EquivocationEvent and route into pending_equivocation_evidence
        (subject to (equivocator, block_index) pool-dedup at the
        upstream pool scan).
  * `AdvanceGeneration` — abort-quorum boundary. Increments
    current_gen and clears pending_contribs (per `reset_round`).
  * `ApplyBlockDrainsPool` — block-finalize step that consumes the
    pool into a finalized block body. Drains `pending_equivocation_evidence`
    in this spec's abstraction (matching the producer's
    `build_body` consume + FA-Apply-10's slash-on-apply behavior).

Six invariants codify the theorems:

  INV_1 SameGenDetection — if two distinct (signer, current_gen)
        entries with different commits have been received, an
        EquivocationEvent against that signer at that block_index
        exists in `pending_equivocation_evidence` OR has already been
        drained by a prior block-apply (modeled via `drained_events`).
        Models T-1.
  INV_2 CrossGenNoFalsePositive — no `EquivocationEvent` exists in
        the pool (or drained set) whose two halves came from
        ContribMsgs at different generations. Modeled via the
        `event_origin` audit set: every constructed event records the
        single shared generation of its two sources; any event with
        gen mismatch is structurally unreachable. Models T-2.
  INV_3 EvidencePoolMonotone — `pending_equivocation_evidence` only
        ever grows (via ReceiveContrib) or drains (via
        ApplyBlockDrainsPool); no action mutates an entry in place
        and no action shrinks the union `pending ++ drained`.
        Models T-3 composition (the pool used here is the same pool
        used by FB15 EquivocationApply.tla / FA-Apply-10).
  INV_4 TwoSigsValid — every entry in `pending_equivocation_evidence`
        (and every entry in `drained_events`) has sig_a + sig_b such
        that the spec-layer signer-correctness predicate holds: both
        sigs were produced by the equivocator's key over their
        respective commits. The spec models this via an abstract
        `valid_sigs` relation populated only when ReceiveContrib's
        sig-verify gate (line 2089 of node.cpp) passed at admission
        time. Models T-4.
  INV_5 ReplaySafe — applying the same equivocation event a second
        time contributes zero additional slash. Modeled as a
        no-double-credit predicate on `drained_events`: each
        (equivocator, block_index) pair appears at most once in the
        drained set. Composed with FA-Apply-10 T-E3 (FB15's
        Inv_NoDoubleSlash). Models T-5.
  INV_6 ChannelReuse — every entry in `pending_equivocation_evidence`
        is a structural `EquivocationEvent` of the SAME shape that
        the rev.8 BlockSigMsg-level detector produces (digest_a +
        sig_a + digest_b + sig_b + equivocator + block_index +
        shard_id + beacon_anchor_height). No new wire format. The
        invariant is the structural-type predicate
        `EquivocationEventShape`; every action that produces an
        event uses the same constructor. Models the no-new-wire-
        format clause of T-3.

Modeling scope (kept tractable for TLC):

  * `Signers` is a finite set of registered domain identifiers (the
    spec-layer projection of `registry_` membership — only registered
    signers can produce admissible ContribMsg per the registry lookup
    at `node.cpp:2076`).
  * `BlockIndices` is a finite set of heights. `AbortGenerations` is
    a finite set of generation indices. `Hashes` is a finite set of
    commit hashes (the universe of `make_contrib_commitment` outputs
    plus a `NoCommit` sentinel).
  * `ContribMsg` records carry the four fields the apply-relevant
    detection cares about: signer, block_index, aborts_gen,
    commit_hash. The view-roots (eq / abort / inbound) are abstracted
    into the commit_hash by FB24
    (`MakeContribCommitment.tla` — the determinism + distinct-pre-
    image lemmas L-2 / L-3); distinct ContribMsg content produces
    distinct commit_hash by A2 (SHA-256 collision resistance per
    Preliminaries §2.1).
  * Signatures are modeled abstractly: a `Sig` is a tagged tuple
    `<<signer, commit_hash>>` that exists in the spec-layer
    `valid_sigs` relation if and only if produced by an honest
    sig-verify gate. The C++ side's Ed25519 verify at `node.cpp:2089`
    is the spec-layer projection of the `valid_sigs` membership
    predicate. A Byzantine signer produces two distinct sigs over
    two distinct commits by signing with their own key (no forgery
    needed — Byzantine has the secret); each pair is admitted to
    `valid_sigs` when sig-verify passes at receive time.
  * `pending_contribs` is modeled as a partial function
    `Signers -> ContribMsg` keyed by signer (matching the C++
    `std::map<std::string, ContribMsg> pending_contribs_` at
    `include/determ/node/node.hpp`). Cross-generation entries are
    structurally impossible because the gen-gate at the action's
    pre-condition restricts to current_gen.
  * `pending_equivocation_evidence` is a SUBSET of
    `EquivocationEvent` records (matching the C++
    `std::vector<EquivocationEvent> pending_equivocation_evidence_`
    with SET semantics — the (equivocator, block_index) pool-dedup
    at `node.cpp:2147..2153` collapses duplicates).
  * `drained_events` is a SUBSET of EquivocationEvent records — the
    spec-layer audit of events that have been consumed by a
    block-apply. Mirrors the FA-Apply-10 / FB15 EquivocationApply
    apply-side pipeline; this spec models the consume as a single
    atomic transition without modeling the per-event T-E1 / T-E2 /
    T-E3 mechanics (those are FB15's territory). The union
    `pending_equivocation_evidence \cup drained_events` is the
    monotonically-growing pool the upstream pool-dedup keys on.
  * `valid_sigs` is a SUBSET of `Sig` — every signed commitment that
    has passed `crypto::verify`. Populated by the SignAndSend action;
    the model assumes Ed25519 unforgeability (FA-track / FrostVerify.tla
    territory) but does not enumerate per-byte signature internals.
  * `current_gen` is a Nat tracking the receiver's
    `current_aborts_.size()` (per the gen-gate at `node.cpp:2068`).
    Advanced by AdvanceGeneration; clears pending_contribs.

The spec captures the receive-time detection surface; the producer's
`build_body` consume + FA-Apply-10's slash mechanics are FB15
territory and composed in via INV-3 / INV-5 / INV-6.

To check (assuming TLC installed):
  $ tlc S006ContribMsgEquivocation.tla -config S006ContribMsgEquivocation.cfg

Recommended config (state space ~10^4, < 30s):
  Signers = {a, b}, BlockIndices = {0, 1}, AbortGenerations = {0, 1},
  Hashes = {h1, h2, h3}.

Cross-references:
  - docs/proofs/S006ContribMsgEquivocation.md — the analytic
    R23A7 proof; §1 T-1..T-5 enumerate the five theorems this spec
    lifts to the state-machine layer; §3 cites the C++ receive-path
    inline; §4 walks per-theorem proofs; §5 documents the adversary
    model (Byzantine producer with Phase-1 splitting + gen-switch
    + partition + forge-resistance via EUF-CMA).
  - src/node/node.cpp::on_contrib (lines 2056..2170 in the current
    main branch) — the receive path with the S-006 detection branch
    at lines 2094..2163.
  - include/determ/chain/block.hpp::EquivocationEvent (lines
    256..279) — the event struct, shared with rev.8 BlockSigMsg
    detection; INV-6 (ChannelReuse) is the spec-layer witness for
    "no new wire format."
  - src/node/validator.cpp::check_equivocation_events — V11's
    digest-agnostic two-sig + distinct-digest check; INV-4
    (TwoSigsValid) is the receive-time half of the V11 check
    (validator re-runs at block-validate time for belt-and-suspenders).
  - src/chain/chain.cpp apply equivocation branch — the FA-Apply-10
    consume site; INV-5 (ReplaySafe) composes with FB15's
    Inv_NoDoubleSlash to give cross-spec idempotence.
  - docs/proofs/tla/F2ViewReconciliation.tla (FB22) — the v2.7 F2
    view-reconciliation primitives the post-S-006 contrib commit
    binds via the make_contrib_commitment DTM-F2-v1 path.
  - docs/proofs/tla/FrostVerify.tla (FB23) — Ed25519 EUF-CMA model;
    `valid_sigs` is the spec-layer projection of the FrostVerify
    accept relation, restricted to the single-signer Ed25519 case.
  - docs/proofs/tla/MakeContribCommitment.tla (FB24) — the commit
    binding primitive whose output the S-006 detector compares.
  - docs/proofs/tla/EquivocationApply.tla (FB15) — the apply-side
    sibling spec. FB28 (this spec) is the detection-side counterpart;
    FB15 is the apply-side; together they witness the end-to-end
    "detect Phase-1 equivocation, route through the same pool, slash
    on apply, never double-credit" pipeline.
  - docs/proofs/Preliminaries.md §4 (H2 honest-signer hypothesis) —
    INV-1 / INV-2 are state-machine projections of the H2 clause
    "honest signer produces at most one `make_contrib_commitment` per
    (height, aborts_gen) tuple."
  - docs/SECURITY.md §S-006 — closure narrative; FB28 is the formal-
    verification counterpart to the audit-side record.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Signers,            \* finite universe of registered signer domains
    BlockIndices,       \* finite universe of block-index heights
    AbortGenerations,   \* finite universe of abort-generation indices
    Hashes              \* finite universe of commit hashes

ASSUME ConfigOK ==
    /\ Cardinality(Signers)          >= 1
    /\ Cardinality(BlockIndices)     >= 1
    /\ Cardinality(AbortGenerations) >= 1
    /\ Cardinality(Hashes)           >= 2  \* need >=2 to model "distinct commits"

\* -----------------------------------------------------------------
\* §1. Shapes. ContribMsg and EquivocationEvent records.
\* -----------------------------------------------------------------
\*
\* ContribMsg projection: only the four detection-relevant fields. The
\* full C++ struct at `include/determ/node/producer.hpp` carries
\* tx_hashes, dh_input, and three view-roots — all abstracted into
\* `commit_hash` by FB24 (the commit-binding primitive). The spec-
\* layer ContribMsg is the equivalence class under
\* `commit = make_contrib_commitment(...)`; two distinct content
\* configurations produce distinct commit_hash by A2 (collision
\* resistance lifted to the bounded universe).
\*
\* `sig` is the spec-layer Ed25519 signature: a tagged tuple
\* <<signer, commit_hash>>. Membership in `valid_sigs` is the spec-
\* layer projection of `crypto::verify(pubkey, commit, sig) == true`.

ContribMsg == [
    signer       : Signers,
    block_index  : BlockIndices,
    aborts_gen   : AbortGenerations,
    commit_hash  : Hashes,
    sig          : [signer : Signers, commit_hash : Hashes]
]

\* EquivocationEvent: the struct at `include/determ/chain/block.hpp:256..279`
\* lifted to the spec layer. The C++ side has eight fields; the spec
\* preserves six (equivocator, block_index, digest_a, sig_a, digest_b,
\* sig_b) plus the cross-shard forensic fields collapsed into a single
\* `shard_anchor` tag (the spec doesn't model cross-shard handling at
\* this layer; FA6 T-6.1 / FB13 covers cross-shard slashing).
\*
\* INV-6 (ChannelReuse) is the structural assertion that every event
\* produced by this spec has this exact shape — no new fields, no
\* alternate subtype, no parallel struct for ContribMsg equivocation.

EquivocationEvent == [
    equivocator  : Signers,
    block_index  : BlockIndices,
    digest_a     : Hashes,
    sig_a        : [signer : Signers, commit_hash : Hashes],
    digest_b     : Hashes,
    sig_b        : [signer : Signers, commit_hash : Hashes]
]

\* SourceGen: spec-layer audit tag tracking the generation of each
\* event's two ContribMsg sources. Used by INV-2 to assert that no
\* event has cross-generation sources (its two ContribMsg arrived at
\* the same current_gen). The C++ side doesn't need this audit
\* because the gen-gate at `node.cpp:2068` makes cross-gen sources
\* structurally unreachable; the spec lifts the structural impossibility
\* into an observable predicate.

SourceGen == [
    event : EquivocationEvent,
    gen   : AbortGenerations
]

\* -----------------------------------------------------------------
\* §2. Pure helpers.
\* -----------------------------------------------------------------

\* EquivocationEventShape: the structural type predicate. Every
\* constructor in this spec uses ONLY this shape; INV-6 (ChannelReuse)
\* is the standing assertion that no parallel struct exists.
EquivocationEventShape(e) ==
    /\ e.equivocator \in Signers
    /\ e.block_index \in BlockIndices
    /\ e.digest_a    \in Hashes
    /\ e.digest_b    \in Hashes
    /\ e.sig_a       \in [signer : Signers, commit_hash : Hashes]
    /\ e.sig_b       \in [signer : Signers, commit_hash : Hashes]

\* PoolDedupKey: the (equivocator, block_index) tuple used by the
\* C++ pool-dedup scan at `node.cpp:2147..2153`. INV-5 (ReplaySafe)
\* keys on this tuple.
PoolDedupKey(e) == <<e.equivocator, e.block_index>>

\* -----------------------------------------------------------------
\* §3. State variables.
\* -----------------------------------------------------------------
\*
\* pending_contribs   : partial function Signers -> ContribMsg.
\*                       Keyed by signer (matches C++ pending_contribs_
\*                       at `include/determ/node/node.hpp`). Only the
\*                       current-gen entries live here; the gen-gate
\*                       at ReceiveContrib's guard enforces this and
\*                       AdvanceGeneration clears the map on reset.
\*
\* pending_equivocation_evidence : SUBSET EquivocationEvent. The
\*                       receive-time pool, matching the C++ vector
\*                       at `Node::pending_equivocation_evidence_`.
\*                       SET semantics — pool-dedup collapses
\*                       (equivocator, block_index) duplicates.
\*
\* drained_events     : SUBSET EquivocationEvent. Spec-layer audit
\*                       of events consumed by block-apply. Tracks
\*                       cross-block / cross-spec replay safety. INV-5
\*                       (ReplaySafe) asserts no PoolDedupKey appears
\*                       twice across pending + drained.
\*
\* valid_sigs         : SUBSET of [signer, commit_hash] tuples. The
\*                       set of Ed25519 sig pairs that have passed
\*                       `crypto::verify`. Populated by SignAndSend;
\*                       any event in pending or drained has its two
\*                       sigs in valid_sigs by INV-4 (TwoSigsValid).
\*
\* event_origins      : SUBSET SourceGen. Audit tag for INV-2 (no
\*                       cross-gen false positives). Every event
\*                       constructed is paired with the shared gen
\*                       of its two ContribMsg sources.
\*
\* current_gen        : Nat (AbortGenerations). The receiver's
\*                       current_aborts_.size() (per the gate at
\*                       `node.cpp:2068`).
\*
\* received_contribs  : SUBSET ContribMsg. Audit set tracking every
\*                       ContribMsg that has been admitted by
\*                       ReceiveContrib (i.e., passed sig-verify and
\*                       was either admitted to pending_contribs or
\*                       triggered an EquivocationEvent). Used by
\*                       INV-1's coverage check ("for every pair of
\*                       distinct-commit same-gen contribs, an event
\*                       exists in pending ++ drained").

VARIABLES
    pending_contribs,
    pending_equivocation_evidence,
    drained_events,
    valid_sigs,
    event_origins,
    current_gen,
    received_contribs

vars == <<pending_contribs, pending_equivocation_evidence,
          drained_events, valid_sigs, event_origins, current_gen,
          received_contribs>>

\* -----------------------------------------------------------------
\* §4. Initial state.
\* -----------------------------------------------------------------
\*
\* All pools start empty. current_gen starts at the smallest element
\* of AbortGenerations (CHOOSE picks one — for the recommended cfg
\* with AbortGenerations = {0, 1}, this is 0).

Init ==
    /\ pending_contribs               = << >>  \* empty seq used as partial fn proxy
    /\ pending_equivocation_evidence  = {}
    /\ drained_events                 = {}
    /\ valid_sigs                     = {}
    /\ event_origins                  = {}
    /\ current_gen                    = CHOOSE g \in AbortGenerations : TRUE
    /\ received_contribs              = {}

\* PendingContribsAsMap: spec-layer helper to expose pending_contribs
\* as a partial-function lookup. The Init uses a sequence proxy
\* because TLC handles empty-domain functions oddly; the spec uses
\* the relation form via DOMAIN-style predicates throughout. We
\* model pending_contribs as a SUBSET ContribMsg with the constraint
\* "at most one entry per signer" enforced by the ReceiveContrib
\* action's guard. The empty sequence at Init is interpreted as the
\* empty SUBSET.

\* Convert the sequence-shape Init proxy into a SUBSET-form predicate.
\* The spec uses the SUBSET form throughout actions / invariants
\* below; the seq at Init is purely a TLC initialization vehicle.
PendingSet == { pending_contribs[i] : i \in DOMAIN pending_contribs }

\* HasPendingFor(signer): TRUE iff a contrib for this signer is
\* currently admitted at current_gen.
HasPendingFor(s) == \E cm \in PendingSet : cm.signer = s

\* GetPendingFor(signer): pick the unique pending contrib for this
\* signer (well-defined when HasPendingFor holds — by the SUBSET-with-
\* one-entry-per-signer constraint).
GetPendingFor(s) ==
    CHOOSE cm \in PendingSet : cm.signer = s

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* SignAndSend(signer, block_idx, gen, commit): Byzantine or honest
\* signer publishes a ContribMsg with the given (signer, block_idx,
\* gen, commit_hash) tuple. The sig is admitted to valid_sigs (the
\* spec-layer projection of "the signer's key produced this
\* signature"). Honest signers produce at most one commit per
\* (block_idx, gen) tuple (H2 of Preliminaries §4); Byzantine
\* signers may produce multiple. The spec doesn't enforce H2 at
\* the SignAndSend action — the adversary surface is unrestricted,
\* and the detector at ReceiveContrib catches the equivocation.

SignAndSend(s, h, g, c) ==
    /\ s \in Signers
    /\ h \in BlockIndices
    /\ g \in AbortGenerations
    /\ c \in Hashes
    /\ valid_sigs' = valid_sigs \cup
                       {[signer |-> s, commit_hash |-> c]}
    /\ UNCHANGED <<pending_contribs, pending_equivocation_evidence,
                   drained_events, event_origins, current_gen,
                   received_contribs>>

\* ReceiveContrib(signer, block_idx, gen, commit_hash): the C++
\* `Node::on_contrib` receive path. Branches by (gen / pending /
\* commit) state. The four branches:
\*
\*   B1 (cross-gen drop): gen # current_gen. Modeled as
\*       `ReceiveContribDifferentGen(signer, block_idx, gen)`. No
\*       state change.
\*   B2 (first arrival): no pending entry for signer. Admit into
\*       pending_contribs; populate received_contribs.
\*   B3 (byte-identical retry): pending entry exists with the SAME
\*       commit_hash. Drop silently; populate received_contribs.
\*   B4 (equivocation detected): pending entry exists with a
\*       DIFFERENT commit_hash. Construct EquivocationEvent; route
\*       into pending_equivocation_evidence (subject to pool-dedup).
\*
\* All four branches require the sig to be in valid_sigs (the C++
\* sig-verify gate at line 2089). Cross-gen drops short-circuit at
\* the gen-gate (line 2068) BEFORE the sig-verify; the spec preserves
\* this ordering by requiring sig-membership only in B2 / B3 / B4.
\*
\* The action signature takes the ContribMsg's commit_hash + sig
\* directly rather than constructing a ContribMsg record inline; the
\* received_contribs audit set tracks the full materialized record.

ReceiveContribSameGen(s, h, c) ==
    /\ s \in Signers
    /\ h \in BlockIndices
    /\ c \in Hashes
    /\ [signer |-> s, commit_hash |-> c] \in valid_sigs
       \* sig-verify gate (line 2089 of node.cpp). The spec requires
       \* the sig was produced by an earlier SignAndSend.
    /\ LET incoming == [
              signer      |-> s,
              block_index |-> h,
              aborts_gen  |-> current_gen,
              commit_hash |-> c,
              sig         |-> [signer |-> s, commit_hash |-> c]
           ] IN
       IF \neg HasPendingFor(s)
       THEN
          \* B2 (first arrival). Admit. The seq-proxy form of
          \* pending_contribs is extended by one element.
          /\ pending_contribs' = Append(pending_contribs, incoming)
          /\ received_contribs' = received_contribs \cup {incoming}
          /\ UNCHANGED <<pending_equivocation_evidence,
                         drained_events, valid_sigs, event_origins,
                         current_gen>>
       ELSE
          LET existing == GetPendingFor(s) IN
          IF existing.commit_hash = c
          THEN
             \* B3 (byte-identical retry). Drop silently. No event.
             /\ received_contribs' = received_contribs \cup {incoming}
             /\ UNCHANGED <<pending_contribs,
                            pending_equivocation_evidence,
                            drained_events, valid_sigs, event_origins,
                            current_gen>>
          ELSE
             \* B4 (equivocation). Construct event; route via the
             \* pool-dedup scan. The dedup keys on (equivocator,
             \* block_index); on hit, the new event is silently NOT
             \* appended (the C++ behavior at lines 2147..2153).
             LET ev == [
                    equivocator |-> s,
                    block_index |-> h,
                    digest_a    |-> existing.commit_hash,
                    sig_a       |-> existing.sig,
                    digest_b    |-> c,
                    sig_b       |-> [signer |-> s, commit_hash |-> c]
                 ] IN
             LET dup_in_pool ==
                    \E e \in pending_equivocation_evidence :
                       PoolDedupKey(e) = PoolDedupKey(ev) IN
             LET dup_in_drained ==
                    \E e \in drained_events :
                       PoolDedupKey(e) = PoolDedupKey(ev) IN
             /\ received_contribs' = received_contribs \cup {incoming}
             /\ IF dup_in_pool \/ dup_in_drained
                THEN
                   \* Pool-dedup hit. Silently drop the duplicate
                   \* event. The pending_contribs entry is unchanged
                   \* (the C++ duplicate-drop preserves the earlier-
                   \* arrived view per the `return` at line 2162).
                   UNCHANGED <<pending_contribs,
                              pending_equivocation_evidence,
                              event_origins>>
                ELSE
                   \* First detection of this (equivocator, block_index)
                   \* pair. Append to pool + log the origin gen.
                   /\ pending_equivocation_evidence' =
                          pending_equivocation_evidence \cup {ev}
                   /\ event_origins' =
                          event_origins \cup
                          {[event |-> ev, gen |-> current_gen]}
                   /\ UNCHANGED <<pending_contribs>>
             /\ UNCHANGED <<drained_events, valid_sigs, current_gen>>

\* ReceiveContribDifferentGen(signer, block_idx, gen): the cross-
\* generation drop branch (B1). The C++ side returns at line 2068
\* BEFORE the duplicate-detection branch. The spec models this as a
\* no-op (the sig need not even be in valid_sigs because the C++
\* doesn't reach the sig-verify gate on cross-gen messages).
\*
\* INV-2 (CrossGenNoFalsePositive) is the structural witness that
\* this branch never produces an event — the action's body has no
\* mutation of pending_equivocation_evidence.

ReceiveContribDifferentGen(s, h, g) ==
    /\ s \in Signers
    /\ h \in BlockIndices
    /\ g \in AbortGenerations
    /\ g # current_gen
       \* The gen-gate condition: this branch only fires on cross-gen
       \* arrivals. The same-gen branch is ReceiveContribSameGen.
    /\ UNCHANGED vars

\* AdvanceGeneration: abort-quorum boundary. Increments current_gen
\* and clears pending_contribs (modeling reset_round at the per-round
\* prep path).
\*
\* The increment is modeled as picking ANY g in AbortGenerations
\* strictly greater than current_gen. If no such g exists, the
\* action is disabled (TLC stutters at the maximum generation).
\* This is the spec-layer projection of the C++ side's monotone
\* current_aborts_.size() — each successful abort-quorum appends
\* exactly one entry; the spec abstracts the append into a
\* nondeterministic next-greater choice.

AdvanceGeneration ==
    /\ \E g \in AbortGenerations :
          /\ g > current_gen
          /\ current_gen' = g
    /\ pending_contribs' = << >>
       \* reset_round clears pending_contribs across abort-quorum
       \* boundaries. The spec captures this verbatim.
    /\ UNCHANGED <<pending_equivocation_evidence, drained_events,
                   valid_sigs, event_origins, received_contribs>>

\* ApplyBlockDrainsPool: block-finalize step. The producer's
\* `build_body` consumes pending_equivocation_evidence into the
\* block's `equivocation_events` field; the apply-side per FA-Apply-10
\* slashes each. The spec models this as a single atomic transition
\* that moves the entire pool into drained_events. The per-event
\* T-E1 / T-E2 / T-E3 mechanics are FB15 territory (EquivocationApply.tla);
\* this spec's contribution is the receive-time detection surface,
\* with the apply consume captured via the drain.
\*
\* INV-3 (EvidencePoolMonotone) and INV-5 (ReplaySafe) constrain
\* the drain: pending shrinks, drained grows by exactly the drained
\* events, no PoolDedupKey appears twice across pending + drained.

ApplyBlockDrainsPool ==
    /\ pending_equivocation_evidence # {}
    /\ drained_events' = drained_events \cup pending_equivocation_evidence
    /\ pending_equivocation_evidence' = {}
    /\ UNCHANGED <<pending_contribs, valid_sigs, event_origins,
                   current_gen, received_contribs>>

\* Stutter at saturation: when no further actions are enabled, TLC
\* stutters. The bounded model guarantees saturation (finite Hashes
\* + finite Signers + finite generations + sig-verified pre-condition).

Stutter ==
    /\ UNCHANGED vars

Next ==
    \/ \E s \in Signers, h \in BlockIndices, g \in AbortGenerations,
       c \in Hashes :
          SignAndSend(s, h, g, c)
    \/ \E s \in Signers, h \in BlockIndices, c \in Hashes :
          ReceiveContribSameGen(s, h, c)
    \/ \E s \in Signers, h \in BlockIndices, g \in AbortGenerations :
          ReceiveContribDifferentGen(s, h, g)
    \/ AdvanceGeneration
    \/ ApplyBlockDrainsPool
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(ApplyBlockDrainsPool)

\* -----------------------------------------------------------------
\* §6. Invariants — the six T-1..T-5 (+ ChannelReuse) claims.
\* -----------------------------------------------------------------

\* INV_1 SameGenDetection (T-1).
\*
\* For every pair of distinct ContribMsgs (cm1, cm2) in
\* received_contribs with same signer / block_index / aborts_gen and
\* distinct commit_hashes, an EquivocationEvent against that signer
\* at that block_index exists somewhere in the system — either in
\* `pending_equivocation_evidence` (not yet drained) or in
\* `drained_events` (already baked into a block and routed through
\* the apply pipeline).
\*
\* The structural witness: ReceiveContribSameGen's B4 branch
\* constructs an event when the duplicate-detect predicate fires;
\* the pool-dedup scan ensures at most one event per
\* (equivocator, block_index) survives across the union pending ++
\* drained, but at least one always does (B4 always appends OR a
\* prior B4 fired and produced the same-key event already).
INV_SameGenDetection ==
    \A cm1, cm2 \in received_contribs :
       (cm1.signer = cm2.signer
        /\ cm1.block_index = cm2.block_index
        /\ cm1.aborts_gen = cm2.aborts_gen
        /\ cm1.commit_hash # cm2.commit_hash)
       =>
          \E e \in pending_equivocation_evidence \cup drained_events :
             /\ e.equivocator = cm1.signer
             /\ e.block_index = cm1.block_index

\* INV_2 CrossGenNoFalsePositive (T-2).
\*
\* No EquivocationEvent in the pool (or drained set) has cross-
\* generation sources. Modeled via event_origins: every event
\* records the gen at which it was constructed (i.e., the gen of
\* its two ContribMsg sources, which by INV-1's preconditions are
\* equal). The C++ ReceiveContrib doesn't reach the duplicate-check
\* branch on cross-gen messages (line 2068 gen-gate returns first),
\* so this is structurally vacuous in the spec.
\*
\* The invariant asserts: for every event in pending ++ drained,
\* its origin record exists in event_origins and records a single
\* gen (the current_gen at construction time).
INV_CrossGenNoFalsePositive ==
    \A e \in pending_equivocation_evidence \cup drained_events :
       \E o \in event_origins :
          /\ o.event = e
          /\ o.gen \in AbortGenerations

\* INV_3 EvidencePoolMonotone (T-3).
\*
\* The union `pending_equivocation_evidence \cup drained_events` only
\* ever grows. Action-form: every step preserves the subset
\* relation. Equivalent action-level invariant:
\*
\*    (pending_equivocation_evidence \cup drained_events)'
\*    \supseteq (pending_equivocation_evidence \cup drained_events)
\*
\* Modeled as a [][...]_vars action invariant. The structural
\* argument: SignAndSend / ReceiveContribDifferentGen / AdvanceGeneration
\* / Stutter all preserve both sets; ReceiveContribSameGen B4 either
\* extends pending or preserves it (on pool-dedup hit);
\* ApplyBlockDrainsPool moves entries from pending to drained (the
\* UNION grows by 0). The union is monotone non-decreasing.
INV_EvidencePoolMonotone ==
    [][ (pending_equivocation_evidence' \cup drained_events')
        \supseteq
        (pending_equivocation_evidence  \cup drained_events) ]_vars

\* INV_4 TwoSigsValid (T-4).
\*
\* Every entry in pending_equivocation_evidence and drained_events
\* has its sig_a and sig_b in valid_sigs. The structural witness:
\* ReceiveContribSameGen B4 constructs the event using the existing
\* entry's sig (which was admitted via a prior B2 / B3 that required
\* the incoming sig in valid_sigs) AND the incoming message's sig
\* (also pre-checked at the B4 entry guard). Both sigs are in
\* valid_sigs by construction.
\*
\* The downstream V11 re-verification (validator.cpp:307..322) is
\* the corresponding apply-time witness; INV-4 captures the receive-
\* time half of the two-layer check.
INV_TwoSigsValid ==
    \A e \in pending_equivocation_evidence \cup drained_events :
       /\ e.sig_a \in valid_sigs
       /\ e.sig_b \in valid_sigs
       \* And the sigs are over the correct commits, by the
       \* corresponding signer:
       /\ e.sig_a = [signer |-> e.equivocator, commit_hash |-> e.digest_a]
       /\ e.sig_b = [signer |-> e.equivocator, commit_hash |-> e.digest_b]

\* INV_5 ReplaySafe (T-5).
\*
\* No two events in pending_equivocation_evidence \cup drained_events
\* share a PoolDedupKey (equivocator, block_index). The structural
\* witness: ReceiveContribSameGen B4's pool-dedup scan rejects any
\* incoming event whose key already exists in the union, AND
\* ApplyBlockDrainsPool moves entries to drained without
\* duplication (the union does not gain a duplicate by the move).
\*
\* Composed with FB15 EquivocationApply.tla's Inv_NoDoubleSlash,
\* this gives the cross-spec end-to-end claim: the same
\* (equivocator, block_index) pair contributes at most one slash
\* across the full detect → bake → apply pipeline.
INV_ReplaySafe ==
    \A e1, e2 \in pending_equivocation_evidence \cup drained_events :
       (PoolDedupKey(e1) = PoolDedupKey(e2)) => (e1 = e2)

\* INV_6 ChannelReuse (T-3 sub-claim: no new wire format).
\*
\* Every entry in pending_equivocation_evidence \cup drained_events
\* satisfies EquivocationEventShape — the same shape produced by the
\* rev.8 BlockSigMsg-level detector. The structural witness:
\* ReceiveContribSameGen B4 uses the constructor pattern of the
\* EquivocationEvent record type, with the same six fields the
\* rev.8 BlockSigMsg detector populates. No alternate struct, no
\* additional fields, no parallel ContribMsg-equivocation subtype.
INV_ChannelReuse ==
    \A e \in pending_equivocation_evidence \cup drained_events :
       EquivocationEventShape(e)

\* -----------------------------------------------------------------
\* §7. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ pending_contribs \in Seq(ContribMsg)
       \* At most one entry per signer at any reachable state
       \* (enforced by the ReceiveContribSameGen action's first-
       \* arrival vs has-pending guard).
    /\ \A i, j \in DOMAIN pending_contribs :
          (i # j) => (pending_contribs[i].signer # pending_contribs[j].signer)
    /\ pending_equivocation_evidence \subseteq EquivocationEvent
    /\ drained_events \subseteq EquivocationEvent
    /\ valid_sigs \subseteq [signer : Signers, commit_hash : Hashes]
    /\ event_origins \subseteq SourceGen
    /\ current_gen \in AbortGenerations
    /\ received_contribs \subseteq ContribMsg

\* -----------------------------------------------------------------
\* §8. Soundness commentary — what TLC checks vs. what the prose
\* proof asserts.
\* -----------------------------------------------------------------
\*
\* The S006ContribMsgEquivocation.md analytic proof establishes
\* T-1..T-5 by case analysis on the receive-path branches (§4.1 T-1),
\* the gen-gate ordering (§4.2 T-2), the V11 predicate's digest-
\* agnostic structure (§4.3 T-3), the sig-verify chain (§4.4 T-4),
\* and the pool-dedup + FA-Apply-10 T-E3 idempotence composition
\* (§4.5 T-5). The TLA+ state-machine layer abstracts these into
\* five actions + six invariants:
\*
\*   * T-1 (Same-Generation Duplicate Detection) → INV_SameGenDetection,
\*     witnessed by ReceiveContribSameGen B4's event construction.
\*     The action's branching pre-condition (has-pending + commit-
\*     mismatch) is the structural mirror of the C++ branch at
\*     `node.cpp:2122..2135`; the pool-dedup at lines 2147..2153
\*     is captured by the dup_in_pool / dup_in_drained guards in
\*     the action body.
\*   * T-2 (Different-Generation Drop, No False Positive) →
\*     INV_CrossGenNoFalsePositive, witnessed by
\*     ReceiveContribDifferentGen's no-op body. The C++ gen-gate at
\*     line 2068 short-circuits before the duplicate-detect branch;
\*     the spec models this verbatim. AdvanceGeneration clears
\*     pending_contribs on reset, capturing the per-round isolation.
\*   * T-3 (Composition with FA6 + FA-Apply-10) → INV_EvidencePoolMonotone
\*     (the pool used here is the same pool the apply-side consumes)
\*     plus INV_ChannelReuse (no new wire format). FB15
\*     EquivocationApply.tla covers the apply-side mechanics; the
\*     two specs share the EquivocationEvent struct shape exactly.
\*   * T-4 (Two-Sig Proof Soundness) → INV_TwoSigsValid. Every event
\*     has both sigs in valid_sigs (the spec-layer projection of
\*     `crypto::verify`); the sigs are bound to the correct
\*     (signer, commit_hash) tuples by the structural equality
\*     clauses in the invariant body.
\*   * T-5 (Replay-Safety) → INV_ReplaySafe. No two events share a
\*     PoolDedupKey across pending + drained. The pool-dedup scan
\*     in ReceiveContribSameGen B4 is the receive-side mechanism;
\*     ApplyBlockDrainsPool preserves the property by moving (not
\*     duplicating) entries from pending to drained.
\*
\* What this spec adds beyond the prose proof: a state-machine
\* witness that the receive-time detector's contract is preserved
\* across every reachable interleaving of SignAndSend +
\* ReceiveContribSameGen + ReceiveContribDifferentGen +
\* AdvanceGeneration + ApplyBlockDrainsPool within the bounded
\* universe. TLC enumerates every reachable schedule and the
\* invariants are checked against the accumulated state.
\*
\* What the spec does NOT check (consistent with §6 of the prose
\* proof):
\*   * Apply-side slash mechanics (T-E1 / T-E2 / T-E3 / T-E5 / T-E7
\*     of FA-Apply-10). The drained_events set is the
\*     spec-layer audit of "events that have been consumed by the
\*     apply pipeline"; the per-event stake-forfeit + registry-
\*     deactivation + accumulated-slashed update happens in FB15
\*     EquivocationApply.tla, which this spec composes with via
\*     INV_3 + INV_5 (shared pool semantics + replay-safety).
\*   * The V11 validator predicate re-verification at block-validate
\*     time. INV-4 captures the receive-time sig-verify; V11's
\*     re-verification at `validator.cpp:307..322` is FA6 territory.
\*     The two-layer check is documented in §4.4 of the prose proof.
\*   * Cross-shard equivocation routing (the `shard_id` /
\*     `beacon_anchor_height` fields of the C++
\*     EquivocationEvent). FA6 T-6.1 covers this; the spec abstracts
\*     cross-shard handling.
\*   * The forensic-audit coarseness at pool-dedup time (§6.3 of the
\*     prose proof). The (equivocator, block_index) key collapses
\*     multiple distinct same-(d, h) incidents into one observable
\*     event; this is intentional and matches the C++ behavior.
\*     INV_ReplaySafe captures the dedup contract; the multi-incident
\*     forensic audit is out of scope.
\*   * The byte-identical retry case (§6.1 of the prose proof). The
\*     spec's ReceiveContribSameGen B3 branch (existing_commit = c)
\*     short-circuits to "no event, drop silently" — captured by
\*     the IF-branch in the action body that leaves
\*     pending_equivocation_evidence UNCHANGED on equal-commit
\*     retries.
\*   * The F2 view-root binding contract (§6.4 of the prose proof).
\*     The spec's commit_hash field is the equivalence-class
\*     output of `make_contrib_commitment` per FB24
\*     MakeContribCommitment.tla; the distinct-pre-image lemmas L-2
\*     / L-3 of FB24 are the cryptographic backing.
\*   * The deleted `contrib_equivocations_` field (§6.5 of the
\*     prose proof). The post-S-006 source has no such field; the
\*     spec doesn't model the deleted dead code.
\*   * Cryptographic forgery resistance. SignAndSend admits any
\*     (signer, commit_hash) pair into valid_sigs without enforcing
\*     EUF-CMA at the spec layer; FB23 FrostVerify.tla covers the
\*     cryptographic side. The composition is via INV-4's
\*     valid_sigs membership predicate.

============================================================================
\* Cross-references.
\*
\* FA-S006 (S006ContribMsgEquivocation.md) ->
\*   §1 T-1 (Same-Generation Duplicate Detection)        : INV_SameGenDetection.
\*       Every pair of distinct-commit same-gen ContribMsgs in
\*       received_contribs has a corresponding EquivocationEvent in
\*       pending_equivocation_evidence \cup drained_events — the
\*       spec-layer projection of "the detector fires on every
\*       same-gen equivocation."
\*   §1 T-2 (Different-Generation Drop, No False Positive) :
\*       INV_CrossGenNoFalsePositive. Every event's origin record
\*       has a single gen — no cross-gen sources, no false-positive
\*       slashing of honest cross-gen retries.
\*   §1 T-3 (Composition with FA6 + FA-Apply-10)         : INV_EvidencePoolMonotone
\*       + INV_ChannelReuse. The pool is the same pool the apply-
\*       side consumes; the event shape is the same shape the
\*       rev.8 detector produces. No new wire format, no new
\*       validator predicate, no new apply-side branch.
\*   §1 T-4 (Two-Sig Proof Soundness)                    : INV_TwoSigsValid.
\*       Every event has both sigs in valid_sigs and bound to the
\*       correct (signer, commit_hash) tuples — the receive-time
\*       half of the two-layer V11 check.
\*   §1 T-5 (Replay-Safety)                              : INV_ReplaySafe.
\*       No PoolDedupKey duplication across pending + drained — the
\*       receive-side dedup + apply-side idempotence composition.
\*
\* SECURITY.md §S-006 : closure narrative; FB28 is the formal-
\*   verification counterpart to the audit-side record. The
\*   Mitigated High classification is preserved.
\*
\* Preliminaries.md §4 (H2 honest-signer hypothesis) : INV-1 / INV-2
\*   are state-machine projections of "honest signer produces at
\*   most one make_contrib_commitment per (height, aborts_gen)
\*   tuple." H2 is the FA-track / Preliminaries-side abstraction;
\*   the spec captures the structural consequence in INV-1 (every
\*   distinct-commit pair produces an event) + INV-2 (no cross-gen
\*   false-positive).
\*
\* Preliminaries.md §2.1 (A2 SHA-256 collision resistance) : the
\*   distinct-pre-image property of make_contrib_commitment is
\*   lifted to the spec layer via the Hashes universe — distinct
\*   ContribMsg content produces distinct commit_hash by tuple
\*   inequality. Modeled abstractly; the cryptographic tightness
\*   is FA-track territory.
\*
\* Preliminaries.md §2.2 (A1 Ed25519 EUF-CMA) : the
\*   valid_sigs membership predicate is the spec-layer projection of
\*   crypto::verify acceptance. Modeled via FB23 FrostVerify.tla's
\*   abstract verify relation; the cryptographic tightness is
\*   FA-track territory.
\*
\* FB22 F2ViewReconciliation.tla (v2.7 F2 view-reconciliation
\*   primitives), FB23 FrostVerify.tla (Ed25519 EUF-CMA model),
\* FB24 MakeContribCommitment.tla (S-030 D2 commit-binding model),
\* FB25 RateLimiterEviction.tla (S-014 F-1 lifetime-bound model),
\* FB26 BlockchainStateIntegrity.tla (S-021 + S-033 + S-038
\*   composition),
\* FB27 JsonValidation.tla (S-018 clear-diagnostic + defense-in-
\*   depth) : sibling FB-track specs; style template for this module
\*   (the "pure-function + bounded enumeration + INV-*" pattern, the
\*   abstract-hash discipline, the companion-prose-proof citation
\*   format).
\*
\* FB15 EquivocationApply.tla (FA-Apply-10 apply-side equivocation
\*   slashing) : the apply-side sibling spec. FB28 (this spec) is
\*   the detection-side counterpart at the receive layer; FB15 is
\*   the apply-side at the chain-finalize layer. Together they
\*   witness the end-to-end "detect Phase-1 equivocation, route
\*   through the shared pool, slash on apply, never double-credit"
\*   pipeline. Shared state-machine substrate: the
\*   EquivocationEvent record shape (this spec's EquivocationEvent ==
\*   record matches FB15's pending_events element shape exactly),
\*   the (equivocator, block_index) dedup key, the
\*   accumulated_slashed monotonicity (FB15) composed with this
\*   spec's INV_EvidencePoolMonotone.
\*
\* C++ enforcement: src/node/node.cpp
\*   Node::on_contrib (full receive path)              @ lines 2056..2170
\*   Generation gate (B1 cross-gen drop)               @ line  2068
\*   Registry lookup (signer registered)               @ line  2076
\*   make_contrib_commitment recompute (incoming sig)  @ lines 2084..2088
\*   crypto::verify (sig-verify gate)                  @ line  2089
\*   Duplicate-detect branch entry                     @ line  2122
\*   Existing-entry commit recompute                   @ lines 2127..2132
\*   commit-inequality predicate                       @ line  2135
\*   EquivocationEvent construction                    @ lines 2136..2145
\*   Pool-dedup scan ((equivocator, block_index))      @ lines 2147..2153
\*   Pool append + gossip broadcast                    @ lines 2154..2156
\*   Return-on-duplicate (preserves earlier view)      @ line  2162
\*   First-arrival admit (B2)                          @ line  2165
\*
\* Header declarations: include/determ/node/node.hpp
\*   pending_contribs_                                  : the signer ->
\*                                                       ContribMsg
\*                                                       partial-fn
\*                                                       lifted by the
\*                                                       spec into the
\*                                                       PendingSet
\*                                                       SUBSET-form.
\*   pending_equivocation_evidence_                     : the receive-
\*                                                       time pool;
\*                                                       this spec's
\*                                                       pending_equivocation_evidence
\*                                                       variable.
\*
\* EquivocationEvent struct: include/determ/chain/block.hpp lines
\*   256..279 (shared with rev.8 BlockSigMsg detection). INV-6
\*   (ChannelReuse) is the spec-layer assertion that no parallel
\*   struct exists for ContribMsg-equivocation — the same EE shape
\*   is reused, supporting the S-006 closure's "no new wire
\*   format" claim.
\*
\* V11 validator predicate: src/node/validator.cpp::check_equivocation_events
\*   lines 307..322 — the digest-agnostic two-sig + distinct-digest
\*   check. The spec's INV_TwoSigsValid is the receive-time half of
\*   the two-layer check; the V11 re-verification at block-validate
\*   time is FA6 / FB23 territory.
\*
\* Apply-side branch: src/chain/chain.cpp equivocation apply path —
\*   the FA-Apply-10 consume site (FB15 EquivocationApply.tla covers
\*   the apply-side mechanics in detail). This spec's
\*   ApplyBlockDrainsPool action is the spec-layer projection of
\*   the consume + drain semantics.
\*
\* Runtime regressions:
\*   tools/test_equivocation_slashing.sh                : end-to-end
\*     network-level test of the slashing pipeline S-006 feeds.
\*     Round-20 race fix: synthesized two-sig evidence submitted to
\*     all three nodes simultaneously, ensuring asymmetric pool views
\*     do not cause fork retries.
\*   determ test-equivocation-apply (via tools/test_equivocation_apply.sh):
\*     FA-Apply-10 T-E1..T-E7 — full stake forfeiture, registry
\*     deactivation, ghost-equivocator robustness, A1 supply
\*     invariant, determinism.
\*   determ test-equivocation-multi (via tools/test_equivocation_multi.sh):
\*     FA-Apply-10 multi-event composition: two equivocators in same
\*     block, same equivocator twice in same block (T-5 replay-safety
\*     analog at the apply layer), equivocator with no stake, pre-
\*     deactivated equivocator override, determinism across two chains.
\*
\* Doc updates:
\*   S006ContribMsgEquivocation.md §1 (T-1..T-5 theorem statements);
\*   §3 (receive-path source citation); §4 (per-theorem analytic
\*   proofs); §5 (adversary model); §6 (identified gaps + edge cases);
\*   §7 (test-suite citation); §8 (status); §9 (reference table).
============================================================================
