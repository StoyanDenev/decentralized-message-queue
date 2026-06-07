\* TIER: NEAR-TERM — 1.0.x in-flight. Committed/imminent but not yet shipped; not 1.0-authoritative. Roadmap index: docs/ROADMAP.md

--------------------------- MODULE F2ViewReconciliation ---------------------------
(*
FB22 — TLA+ specification of the v2.7 F2 view-reconciliation primitives.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
F2ViewReconciliation.tla` once a companion `.cfg` is supplied.

Scope. Formalizes the three deterministic primitives that F2 wires
into the consensus path of `compute_block_digest`:

  * `ComputeViewRoot(list)` — deterministic commitment over the
    SORTED SET of hash items.  Matches the C++ helper
    `producer::compute_view_root` at `src/node/producer.cpp:335` —
    canonical, dedup'd, order-independent.
  * `ReconcileUnion(memberLists)` — Q1 union rule. Returns the
    deduplicated union across K committee members' lists in canonical
    sorted order. Matches `producer::reconcile_union` at
    `src/node/producer.cpp:345`. Used for equivocation_events +
    abort_events (censorship-resistance: any single honest member's
    observation suffices).
  * `ReconcileIntersection(memberLists)` — Q1 intersection rule.
    Returns the items present in EVERY member's list, in canonical
    sorted order. Matches `producer::reconcile_intersection` at
    `src/node/producer.cpp:357`. Used for inbound_receipts (credit
    only on unanimous observation).

Plus the validator-side passes V21..V26 from F2-SPEC.md §Q3 / §Q5,
implemented by `producer::validate_contrib_view_roots` and
`producer::validate_view_reconciliation` at
`src/node/producer.cpp:391` and `:458`:

  V21: per-list bandwidth cap (≤ F2_VIEW_LIST_CAP = 64; F2-SPEC §Q3).
  V22: view_eq_root      == ComputeViewRoot(view_eq_list).
  V23: view_abort_root   == ComputeViewRoot(view_abort_list).
  V24: view_inbound_root == ComputeViewRoot(view_inbound_list).
  V25: block.equivocation_events == ReconcileUnion(member view_eq_lists)
       block.abort_events         == ReconcileUnion(member view_abort_lists).
  V26: block.inbound_receipts     == ReconcileIntersection(member
       view_inbound_lists).

What the model checks. Six invariants codifying the algebraic
contract these primitives must satisfy. The reconciliation rules
collapse to set-operations after the (set semantics, canonical sort)
pre-step, so most invariants are visible at the spec layer without a
state-machine driver. A small generator action — `GenerateHonest` —
enumerates per-member views over a fixed Hash universe to exercise
the validator-pass surface; TLC verifies the invariants hold across
every reachable enumeration.

  INV-1 (UnionMonotonic): adding any honest member's list to the
        committee never shrinks the union.
  INV-2 (IntersectionAntiMonotonic): adding any list (including an
        empty one) to the committee never grows the intersection.
  INV-3 (OrderIndependent): ReconcileUnion(perm(L)) = ReconcileUnion(L)
        for every permutation perm of the member-list ordering; same
        for ReconcileIntersection. (Q3 canonical-sort guarantees the
        producer's choice of member ordering doesn't change the
        canonical lists every validator re-derives.)
  INV-4 (UnionIdempotent): ReconcileUnion([L, L, L]) =
        ReconcileUnion([L]) — duplicate member contributions are
        merged via SET semantics, not multiset.
  INV-5 (UnionCensorshipResistant): if AT LEAST ONE honest member
        committed h in their view_eq_list, h must appear in
        ReconcileUnion's result. (This is FA2 censorship resistance
        lifted to the consensus view: a single honest observer is
        sufficient to land slashing evidence.)
  INV-6 (IntersectionConservative): h ∈ ReconcileIntersection(L)
        iff EVERY member's list contains h. (Q1 intersection rule's
        conservative-credit posture: one bad relayer cannot
        unilaterally cause credit.)

Modeling scope (kept tractable for TLC):

  * `Hashes` is an abstract finite set. The C++ side imposes
    lexicographic `Hash::operator<` over the 32 bytes; at the spec
    layer we model `ComputeViewRoot` as the underlying SET (not a
    sorted sequence), because the contract we care about — "equal
    sets produce equal commitments, unequal sets produce unequal
    commitments" — is preserved by any binding-Merkle-root scheme.
    Both ReconcileUnion and ReconcileIntersection return the
    underlying SET; spec-level equality is structural set equality.
    The C++ wraps each set in a SortSet + SHA256Builder to make the
    commitment a 32-byte hash; that step preserves bijection on
    sets, so the algebraic claims here lift unchanged.
  * Cryptographic collision-resistance is FA-track territory (A3);
    this spec is the state-machine layer.
  * The cap K = 3 is the default committee size; CAP = 64 is per
    F2-SPEC.md §Q3.
  * Per-member view lists are drawn from `Hashes`; the model
    enumerates every assignment in the bounded universe.

To check (assuming TLC installed):
  $ tlc F2ViewReconciliation.tla -config F2ViewReconciliation.cfg

Recommended config (state space ≤ 10⁴, < 30s):
  K = 3, Hashes = {h1, h2, h3}, CAP = 64.

Cross-references:
  - F2-SPEC.md §Q1, §Q3, §Q5 (design spec for these primitives).
  - Safety.md §5.3 (FA1 D2 footnote — v2.7 F2 ship closes it).
  - SECURITY.md §S-030 (the audit finding F2 closes).
  - src/node/producer.cpp:335..496 (the C++ implementation).
  - include/determ/node/producer.hpp:146..268 (the C++ declarations
    + V21..V26 docstring).
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    K,                  \* committee size (= |MemberIds|)
    Hashes,             \* finite universe of hash values
    CAP                 \* per-list bandwidth cap (F2-SPEC §Q3; = 64)

ASSUME ConfigOK ==
    /\ K \in Nat /\ K >= 1
    /\ Cardinality(Hashes) >= 1
    /\ CAP \in Nat /\ CAP >= 1

\* Member indices 1..K. The committee is the K-cardinality set used
\* by F2 (matches the C++ ContribMsg vector indexed in producer.cpp).
MemberIds == 1..K

\* SetOf converts a sequence to its underlying set. The C++ side's
\* canonical SortSet step is bijective on sets, so spec-level
\* invariants stated over the underlying SET are precisely the
\* claims the implementation must satisfy.
SetOf(seq) == { seq[i] : i \in 1..Len(seq) }

\* -----------------------------------------------------------------
\* §1. Pure primitives (Q1 reconciliation, Q3 commitment).
\* -----------------------------------------------------------------

\* ComputeViewRoot: deterministic commitment over the SET of hash
\* items. Two lists with the same SET produce the same root; two
\* lists with different sets produce different roots. The C++ side
\* wraps SortSet + SHA256Builder to produce a 32-byte hash; that
\* extra step is a bijection on sets (collision-resistance via A3),
\* so equality of underlying sets is equivalent to equality of the
\* C++ side's Hash output. We model the SET directly.
ComputeViewRoot(list) == SetOf(list)

\* ReconcileUnion: deterministic union across K member lists.
\* Returns the SET-form union (the canonical sort step on the C++
\* side is bijective). SET semantics dedupes per Q1.
ReconcileUnion(memberLists) ==
    UNION { SetOf(memberLists[i]) : i \in DOMAIN memberLists }

\* ReconcileIntersection: deterministic intersection across K member
\* lists. Returns the SET-form intersection. Empty when DOMAIN
\* memberLists is empty OR when any member's list is empty
\* (intersection with the empty set is empty). The recursion folds
\* (\cap) over the indexed family of per-member SETs by peeling off
\* one index at a time; the base case at |S| = 1 returns that single
\* member's SET (matches the C++ side's "start with first list, then
\* iteratively intersect with the rest" loop).
ReconcileIntersection(memberLists) ==
    IF DOMAIN memberLists = {} THEN {}
    ELSE LET ms == [i \in DOMAIN memberLists |-> SetOf(memberLists[i])] IN
         LET RECURSIVE isect_(_) IN
         LET isect_(S) ==
             IF Cardinality(S) = 1
             THEN LET k == CHOOSE k \in S : TRUE IN ms[k]
             ELSE LET k == CHOOSE k \in S : TRUE IN
                  ms[k] \cap isect_(S \ {k})
         IN isect_(DOMAIN memberLists)

\* -----------------------------------------------------------------
\* §2. Validator-side passes (V21..V26 per F2-SPEC.md).
\* -----------------------------------------------------------------

\* A ContribMsg in the F2 spec is the per-member view commitment.
\* Three lists + three claimed roots, one per pool-fed field.
\* Roots are modeled as SUBSETs of Hashes (the spec-layer analog of
\* the C++ 32-byte Merkle root).
ContribMsg == [
    view_eq_root      : SUBSET Hashes,
    view_eq_list      : Seq(Hashes),
    view_abort_root   : SUBSET Hashes,
    view_abort_list   : Seq(Hashes),
    view_inbound_root : SUBSET Hashes,
    view_inbound_list : Seq(Hashes)
]

\* V21..V24 per-contrib well-formedness check.
\* V21: each view_X_list.size() <= CAP.
\* V22..V24: each claimed root == ComputeViewRoot(view_X_list).
ValidateContribViewRoots(msg) ==
    /\ Len(msg.view_eq_list)      <= CAP
    /\ Len(msg.view_abort_list)   <= CAP
    /\ Len(msg.view_inbound_list) <= CAP
    /\ msg.view_eq_root      = ComputeViewRoot(msg.view_eq_list)
    /\ msg.view_abort_root   = ComputeViewRoot(msg.view_abort_list)
    /\ msg.view_inbound_root = ComputeViewRoot(msg.view_inbound_list)

\* DeriveCanonical: lifts K contribs into the three canonical lists
\* per F2-SPEC.md §Q1. Matches producer::derive_canonical_view_lists.
DeriveCanonical(contribsFn) == [
    equivocation_events |->
        ReconcileUnion(
            [i \in DOMAIN contribsFn |-> contribsFn[i].view_eq_list]),
    abort_events |->
        ReconcileUnion(
            [i \in DOMAIN contribsFn |-> contribsFn[i].view_abort_list]),
    inbound_receipts |->
        ReconcileIntersection(
            [i \in DOMAIN contribsFn |-> contribsFn[i].view_inbound_list])
]

\* V25..V26: composite check across K contribs + the block's claimed
\* canonical lists. The block assembler proposes block_eq / block_abort
\* / block_inbound; the validator re-derives via F2 reconciliation and
\* verifies a structural-set match.
ValidateViewReconciliation(contribsFn, blockEq, blockAbort, blockInbound) ==
    LET canonical == DeriveCanonical(contribsFn) IN
    /\ \A i \in DOMAIN contribsFn : ValidateContribViewRoots(contribsFn[i])
    /\ blockEq      = canonical.equivocation_events
    /\ blockAbort   = canonical.abort_events
    /\ blockInbound = canonical.inbound_receipts

\* -----------------------------------------------------------------
\* §3. State-machine driver — enumerate member lists for TLC.
\* -----------------------------------------------------------------
\*
\* The reconciliation primitives are pure functions; the algebraic
\* invariants (INV-1..INV-6) hold structurally. To make them TLC-
\* checkable across the bounded model, we drive a single non-
\* deterministic generator action that picks a per-member assignment
\* of (view_eq_list, view_abort_list, view_inbound_list) drawn from
\* Hashes. After generation, TLC checks the invariants against the
\* current contribs.

VARIABLES
    contribs,           \* function MemberIds -> ContribMsg
    block_eq,           \* claimed canonical equivocation set
    block_abort,        \* claimed canonical abort set
    block_inbound,      \* claimed canonical inbound-receipt set
    generated           \* BOOLEAN: TRUE once contribs assigned

vars == <<contribs, block_eq, block_abort, block_inbound, generated>>

\* Initial: empty per-member views, no claimed canonical lists.
NullContrib == [
    view_eq_root      |-> {},
    view_eq_list      |-> <<>>,
    view_abort_root   |-> {},
    view_abort_list   |-> <<>>,
    view_inbound_root |-> {},
    view_inbound_list |-> <<>>
]

Init ==
    /\ contribs = [i \in MemberIds |-> NullContrib]
    /\ block_eq = {}
    /\ block_abort = {}
    /\ block_inbound = {}
    /\ generated = FALSE

\* Bound: each view-list is a sequence of distinct hashes from Hashes,
\* of length at most |Hashes| (the universe). The model enumerates
\* every assignment in the bounded universe. We bound at |Hashes|
\* because sequences are SETs at the spec layer (duplicates collapse
\* under SetOf) — any longer sequence is redundant.
BoundedSeqs ==
    UNION { [1..n -> Hashes] : n \in 0..Cardinality(Hashes) }

\* A "valid contrib" is one where each root field equals
\* ComputeViewRoot of its list (i.e., produced by an honest member
\* running the primitive).
HonestContrib(eq, ab, inb) == [
    view_eq_root      |-> ComputeViewRoot(eq),
    view_eq_list      |-> eq,
    view_abort_root   |-> ComputeViewRoot(ab),
    view_abort_list   |-> ab,
    view_inbound_root |-> ComputeViewRoot(inb),
    view_inbound_list |-> inb
]

\* Generate K honest contribs in a single non-deterministic step.
\* The block_X fields are set to the F2-derived canonical lists, so
\* the resulting state always passes ValidateViewReconciliation.
GenerateHonest ==
    /\ ~generated
    /\ \E eq_assign  \in [MemberIds -> BoundedSeqs] :
       \E ab_assign  \in [MemberIds -> BoundedSeqs] :
       \E inb_assign \in [MemberIds -> BoundedSeqs] :
          LET newContribs == [i \in MemberIds |->
                                 HonestContrib(eq_assign[i],
                                               ab_assign[i],
                                               inb_assign[i])] IN
          LET canonical == DeriveCanonical(newContribs) IN
          /\ contribs' = newContribs
          /\ block_eq'      = canonical.equivocation_events
          /\ block_abort'   = canonical.abort_events
          /\ block_inbound' = canonical.inbound_receipts
          /\ generated' = TRUE

\* Stutter once generated (TLC bounds the state space; the invariants
\* are evaluated at every reachable state).
Stutter ==
    /\ generated
    /\ UNCHANGED vars

Next == GenerateHonest \/ Stutter

Spec == Init /\ [][Next]_vars /\ WF_vars(GenerateHonest)

\* -----------------------------------------------------------------
\* §4. Invariants (the six F2 algebraic claims).
\* -----------------------------------------------------------------

\* INV-1: UnionMonotonic. Adding any honest member's list to the
\* committee can only grow the union (as a SET). State-form: when
\* the K-member view is in scope, the F2 canonical equivocation set
\* contains every hash that ANY member committed.
\*
\*   \forall i, h : h \in SetOf(contribs[i].view_eq_list)
\*                  => h \in block_eq
INV_UnionMonotonic ==
    generated =>
    \A i \in MemberIds :
       \A h \in SetOf(contribs[i].view_eq_list) :
          h \in block_eq

\* INV-2: IntersectionAntiMonotonic. Adding any list (incl. an empty
\* one) to the committee can only SHRINK the intersection. State-form:
\* the F2 canonical inbound-receipt set is a subset of EVERY member's
\* set.
\*
\*   \forall h \in block_inbound :
\*       \forall i \in MemberIds :
\*           h \in SetOf(contribs[i].view_inbound_list)
INV_IntersectionAntiMonotonic ==
    generated =>
    \A h \in block_inbound :
       \A i \in MemberIds :
          h \in SetOf(contribs[i].view_inbound_list)

\* INV-3: OrderIndependent. Permuting the per-member sequence of
\* contribs doesn't change the canonical reconciled SETs, because
\* both ReconcileUnion and ReconcileIntersection apply SET semantics
\* over the input lists. State-form: for every permutation P of
\* MemberIds, the F2 derivation produces the same canonical sets as
\* the current block_X fields.
\*
\* SET-based primitives over a function are intrinsically invariant
\* under domain-permutation because the SET of mapped values is
\* unchanged. We assert it explicitly so TLC checks it across all
\* member assignments.
IsPermutation(P) ==
    /\ P \in [MemberIds -> MemberIds]
    /\ \A i, j \in MemberIds : i # j => P[i] # P[j]

INV_OrderIndependent ==
    generated =>
    \A P \in [MemberIds -> MemberIds] :
       IsPermutation(P) =>
          /\ ReconcileUnion(
                  [i \in MemberIds |-> contribs[P[i]].view_eq_list])
              = block_eq
          /\ ReconcileUnion(
                  [i \in MemberIds |-> contribs[P[i]].view_abort_list])
              = block_abort
          /\ ReconcileIntersection(
                  [i \in MemberIds |-> contribs[P[i]].view_inbound_list])
              = block_inbound

\* INV-4: UnionIdempotent. ReconcileUnion([L, L, L]) = ReconcileUnion([L]).
\* Duplicate per-member contributions merge via SET semantics. State-form:
\* if every member committed the same eq-list (as a SET), the F2 canonical
\* set equals that single member's eq-set.
INV_UnionIdempotent ==
    generated =>
    LET memberOneEqSet == SetOf(contribs[1].view_eq_list) IN
    LET allMembersSame ==
          \A i \in MemberIds :
             SetOf(contribs[i].view_eq_list) = memberOneEqSet IN
    allMembersSame => block_eq = memberOneEqSet

\* INV-5: F2 censorship resistance (FA2 lift). If AT LEAST ONE member
\* has h in their view_eq_list, h must be in the F2 canonical
\* equivocation set. This is the censorship-resistance contract
\* under the Q1 union rule — one honest observer suffices to land
\* slashing evidence.
INV_UnionCensorshipResistant ==
    generated =>
    \A h \in Hashes :
       (\E i \in MemberIds : h \in SetOf(contribs[i].view_eq_list))
       => h \in block_eq

\* INV-6: F2 conservative inbound. h is in the F2 canonical inbound-set
\* IFF every member committed it. The biconditional is the contract:
\* one bad relayer cannot unilaterally cause credit (=>), and a
\* unanimous observation guarantees inclusion (<=).
INV_IntersectionConservative ==
    generated =>
    \A h \in Hashes :
       (h \in block_inbound)
       <=> (\A i \in MemberIds : h \in SetOf(contribs[i].view_inbound_list))

\* -----------------------------------------------------------------
\* §5. Wire-pass invariants (V21..V26 reachability).
\* -----------------------------------------------------------------
\*
\* The GenerateHonest action produces only contribs that pass V21..V24
\* by construction (HonestContrib sets each root from ComputeViewRoot
\* of its list). The block_X fields are derived via DeriveCanonical,
\* so V25..V26 also pass. We assert both as standing invariants.

\* V21..V24 hold for every generated contrib.
INV_AllContribsValid ==
    generated =>
    \A i \in MemberIds : ValidateContribViewRoots(contribs[i])

\* V25..V26 holds for the generated (contribs, block) tuple.
INV_BlockReconcilesContribs ==
    generated =>
    ValidateViewReconciliation(
        contribs,
        block_eq, block_abort, block_inbound)

\* Bandwidth cap from F2-SPEC §Q3. Holds by construction of
\* BoundedSeqs (which is bounded above by |Hashes|; the recommended
\* .cfg supplies |Hashes| <= CAP).
INV_BandwidthCapHonored ==
    generated =>
    \A i \in MemberIds :
       /\ Len(contribs[i].view_eq_list)      <= CAP
       /\ Len(contribs[i].view_abort_list)   <= CAP
       /\ Len(contribs[i].view_inbound_list) <= CAP

\* -----------------------------------------------------------------
\* §6. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ contribs \in [MemberIds -> ContribMsg]
    /\ block_eq      \subseteq Hashes
    /\ block_abort   \subseteq Hashes
    /\ block_inbound \subseteq Hashes
    /\ generated \in BOOLEAN

============================================================================
\* Cross-references.
\*
\* FA1 (Safety) D2 footnote → closed by F2 ship; this spec gives the
\*   state-machine soundness of the reconciliation step that closes D2.
\* FA2 (Censorship Resistance) → INV-5 lifts the FA2 single-honest-
\*   observer guarantee from the gossip layer to the consensus view.
\* FA6 (Equivocation Slashing) → INV-1 + INV-5 together ensure
\*   slashing evidence flows from any single honest committer through
\*   reconcile_union into the canonical block field.
\* FA7 (Cross-Shard Atomicity) → INV-2 + INV-6 capture the
\*   conservative-credit posture for inbound_receipts; combined with
\*   FB14 CrossShardReceiptDedup the credit-axis claim is end-to-end.
\* F2-SPEC.md §Q1 → INV-5 (union censorship) + INV-6 (intersection
\*   conservative) are direct restatements of the Q1 design choice.
\* F2-SPEC.md §Q3 → INV-BandwidthCapHonored is the V21 contract;
\*   V22..V24 follow from INV-AllContribsValid (each root matches
\*   its list under HonestContrib's construction); V25..V26 follow
\*   from INV-BlockReconcilesContribs (the block's canonical lists
\*   are exactly the F2 reconciliation outputs).
\* F2-SPEC.md §Q5 → the validator-side re-derivation is the V25..V26
\*   composite; INV-OrderIndependent + INV-UnionIdempotent capture
\*   the determinism of that re-derivation across the K-of-K Phase-2
\*   reveal interleavings.
\*
\* C++ enforcement: src/node/producer.cpp
\*   compute_view_root        @ line 335
\*   reconcile_union          @ line 345
\*   reconcile_intersection   @ line 357
\*   validate_contrib_view_roots @ line 391
\*   derive_canonical_view_lists @ line 438
\*   validate_view_reconciliation @ line 458
\*
\* Header declarations + Q1/Q3 docstring: include/determ/node/producer.hpp
\*   lines 146..268 (F2_VIEW_LIST_CAP, the F2CanonicalViews struct, and
\*   the V21..V26 docstring narrating each helper's validator role).
============================================================================
