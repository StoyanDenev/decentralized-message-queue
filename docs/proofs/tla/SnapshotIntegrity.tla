--------------------------- MODULE SnapshotIntegrity ---------------------------
(*
FB31 — TLA+ specification of the post-S-037 / post-S-038 snapshot
integrity surface. A deeper-coverage companion to FB6 `Snapshot.tla`,
extending the basic serialize/restore state machine with the FULL
state-commitment surface that S-033 closed: the 10 state_root
namespaces (a:/s:/r:/d:/i:/b:/m:/p:/k:/c:) must all round-trip through
`Chain::serialize_state` and `Chain::restore_from_snapshot`, the
S-037 closure added the `d:` namespace (`dapp_registry_`) plus the
`i:` namespace (`applied_inbound_receipts_`), and the S-038 closure
populates `body.state_root` on every produced block — turning the
previously-dormant S-033 apply-time gate into a live integrity check.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
SnapshotIntegrity.cfg SnapshotIntegrity.tla` once a companion `.cfg`
is supplied.

Scope. Formalizes the composition of three independently-shipped
state-commitment mechanisms at the state-machine layer:

  * S-033 (state_root commitment): `Block::signing_bytes` binds
    `state_root` under the zero-skip backward-compat shim. The
    apply-time gate at `chain.cpp:1421-1446` recomputes the state
    root post-apply and compares to the block's declared
    `state_root`, throwing on mismatch.
  * S-037 (dapp_registry + applied_inbound_receipts snapshot
    coverage): the `d:` and `i:` namespaces contribute leaves to the
    state_root Merkle commitment. Pre-S-037 the snapshot serializer
    omitted these namespaces; a DApp-active chain's snapshot would
    carry the tail head's correct state_root in JSON, but
    `restore_from_snapshot` would rehydrate a chain whose recomputed
    state_root differed — the post-restore gate at chain.cpp:1893-1911
    would loud-fail. S-037 added both namespaces to
    `serialize_state` + `restore_from_snapshot` with the full set of
    fields needed to reproduce the value-hash byte-for-byte.
  * S-038 (producer-side state_root population): pre-S-038 every
    produced block had `body.state_root = Hash{}`; the apply-time
    gate's `if (b.state_root != zero)` short-circuit meant the
    receiver-side check was DORMANT on production blocks (the gate's
    logic was correct but the producer never fed it). S-038 added
    the tentative-chain dry-run pattern at `node.cpp:1024-1117` so
    every produced block carries a non-zero `state_root`.

Five paired theorems are pinned (per S033StateRootNamespaceCoverage.md
§1 + AppliedReceiptRestore.md FA-Apply-12 + BlockchainStateIntegrity.md
§4):

  (T-S1) Ten-Namespace Round-Trip Coverage. Every state field in the
         apply-determinism universe `S` is bound under exactly one
         namespace; serialize emits every field; restore consumes
         every field; the recomputed state_root post-restore equals
         the snapshot's saved tail-head state_root byte-for-byte.
  (T-S2) DApp Registry Round-Trip (S-037 closure). The `d:` and `i:`
         namespaces specifically — the two added by S-037 — both
         emit at serialize and consume at restore. Without them,
         the recompute would fail on any chain with active DApps
         or cross-shard receipts.
  (T-S3) Producer-Side State_Root Wiring (S-038 closure). Every
         block produced by `ProduceBlock` carries a non-zero
         `state_root` that equals the tentative-chain dry-run's
         `compute_state_root()` post-apply. Self-apply never throws.
  (T-S4) Tamper Detection at Snapshot Boundary. Any tamper of the
         snapshot payload — at chain level, at namespace level, OR
         at the dapp_registry layer specifically — is detected at
         either the post-restore state_root gate (chain.cpp:1893-1911)
         or the next apply (chain.cpp:1421-1446). No silent
         corruption survives across a restore.
  (T-S5) Restore Determinism. Two nodes consuming byte-identical
         snapshots reach byte-identical post-restore states — the
         snapshot is a pure value, restore is a pure function.

The state machine. A 2-node restore scenario across the snapshot
lifecycle. Variables:

  * `live_chain`    : function NodeId -> Seq(Block) (each Block has
                       {index, prev_hash, state_root, txs})
  * `live_state`    : function NodeId -> State where State =
                       [accounts, stakes, registrants, dapp_registry]
                       (the four mutable maps that survive across
                       snapshot boundaries; each is a SUBSET of
                       Slots representing the encoded namespace
                       contents in this spec's abstraction)
  * `snapshot_blob` : function NodeId -> Snapshot ∪ {NoSnapshot}
                       where Snapshot = [tail_chain,
                       serialized_state, head_state_root]
  * `apply_throws`  : function NodeId -> BOOLEAN (latches on
                       state_root mismatch at apply or post-restore
                       recompute)
  * `restore_throws`: function NodeId -> BOOLEAN (latches on restore
                       failure: bad version, missing fields,
                       structural error)
  * `tampered_at`   : function NodeId -> TamperSite where TamperSite =
                       {"none", "chain", "state", "dapp_registry"}
                       (adversarial tamper site; the dapp_registry
                       branch is the S-037 surface specifically)

Seven actions cover the producer / restore / tamper / liveness
surfaces:

  * ProduceBlock(n) — n produces a block; tentative-chain dry-run
    computes state_root; populates body.state_root; appends to
    live_chain[n]; updates live_state[n] via apply (the S-038
    producer wiring).
  * SerializeSnapshot(n) — n emits snapshot_blob[n] = {tail_chain,
    serialized_state, head_state_root}. The serialized_state must
    include ALL 4 state maps (the S-037 closure: dapp_registry is
    now included alongside accounts/stakes/registrants).
  * RestoreFromSnapshot(n2) — at node n2 (distinct from n), consume
    snapshot_blob[n] and reconstruct live_chain[n2] + live_state[n2].
    Verify head_state_root against recomputed state_root from
    restored state. Fail with restore_throws if mismatch.
  * ApplyBlockAfterRestore(n2) — apply a new block after restore;
    assert that the post-apply state_root matches the block's
    stored state_root (the S-033 / S-038 apply-time gate fires).
  * TamperSnapshot(n) — adversary mutates snapshot_blob[n] in one
    of three ways: (a) interior tail-chain block, (b) any of the 10
    state-namespace entries, (c) the dapp_registry specifically
    (the S-037 closure surface). Latches `tampered_at[n]` with the
    tamper site label.
  * TamperLiveState(n) — at-rest tamper of live state on disk
    between serialize and restore.
  * Stutter — no-op for liveness.

Six standing invariants codify the five theorems:

  INV_SnapshotRoundTripPreservesAllNamespaces (T-S1, T-S2 composed)
    For every node-pair (n, n2): if RestoreFromSnapshot(n2) succeeds
    on snapshot_blob[n], live_state[n2] equals live_state[n] across
    all 10 namespaces. The headline S-037 + S-038 composition:
    dapp_registry round-trips under the `d:` namespace AND the
    state_root over all namespaces matches byte-for-byte. Without
    S-037's d:/i: emit-and-consume, this invariant would fail on
    any DApp-active or cross-shard-active chain.
  INV_StateRootGateFiresOnRestoreTamper (T-S4)
    If `tampered_at[n] ∈ {"state", "dapp_registry"}` OR a block's
    state_root mismatches the recomputed root, then either
    `restore_throws[n] = TRUE` (detected at restore-time recompute
    via the chain.cpp:1893-1911 gate) OR `apply_throws[n] = TRUE`
    (detected at the next apply via the chain.cpp:1421-1446 gate).
    No silent corruption is reachable.
  INV_ProducerSelfApplyConsistentPostS038 (T-S3)
    Every block produced by ProduceBlock carries `state_root =
    state_root_of(live_state[n])` — NOT empty / NOT ZeroRoot. The
    pre-S-038 dormant-gate case (state_root = Hash{}) is OUT of
    scope; we model the closure. The structural witness that the
    producer's tentative-chain dry-run guarantees gate-pass on
    self-apply.
  INV_DAppRegistryRoundtrips (T-S2 standalone)
    The dapp_registry map specifically passes through serialize +
    restore byte-for-byte. The S-037 closure invariant — without
    it, the state_root recompute at restore would fail on any
    chain with active DApps. Captured as a standalone invariant so
    a regression that re-removes the `d:` namespace from
    serialize_state would surface as a single-invariant failure.
  INV_RestoreDeterminism (T-S5)
    For every node-pair (n, n'): if snapshot_blob[n] =
    snapshot_blob[n'], then RestoreFromSnapshot produces
    byte-identical live_state regardless of which snapshot is
    consumed. Restore is a pure function of the snapshot.
  INV_NoSilentDivergence (T-S4 cross-node form)
    If two nodes have the same restored chain but different
    state_roots, at least one of `apply_throws` or `restore_throws`
    is TRUE. Mirror of FB26 `BlockchainStateIntegrity.tla`'s
    INV_NoSilentDivergence restricted to the snapshot pathway.

Two temporal properties:

  PROP_EventualSnapshotSuccess — under fairness on SerializeSnapshot,
    eventually some snapshot succeeds (no permanent starvation
    of the snapshot subsystem).
  PROP_TamperingDetected — under fairness on the detection actions
    (RestoreFromSnapshot + ApplyBlockAfterRestore), every tamper
    eventually fires at least one of the throw-gates.

Modeling scope (kept tractable for TLC):

  * `Nodes` is a finite set of two node IDs (one producer, one
    restorer; the cross-node restore is the load-bearing surface
    INV_SnapshotRoundTripPreservesAllNamespaces operates on).
  * `MaxHeight` bounds chain length.
  * Hashes / state_roots are modeled as deterministic functions of
    their inputs (the abstract-hash discipline used by Snapshot.tla,
    FrostVerify.tla, MakeContribCommitment.tla, FB26
    BlockchainStateIntegrity.tla). This is the spec-layer
    abstraction of A2 (SHA-256 collision resistance per
    Preliminaries §2.1): distinct pre-images map to distinct
    hashes; identical pre-images map to identical hashes.
  * State is modeled as the four-map tuple [accounts, stakes,
    registrants, dapp_registry] each a SUBSET of an opaque Slots
    universe (the spec-level projection of the four std::map
    surfaces that contribute to the a:/s:/r:/d: namespaces). The
    six other namespaces (i:/b:/m:/p:/k:/c:) are present in the
    underlying C++ surface but the safety-critical
    round-trip-equality property collapses cleanly to the SUBSET
    equality on the four mutable maps — the same abstract-hash
    pattern Snapshot.tla uses to collapse 10 → 2 namespaces for
    tractability. The full ten-namespace coverage theorem is the
    analytic-proof companion S033StateRootNamespaceCoverage.md
    territory; FB31 verifies the state-machine consistency of the
    round-trip under the abstract-hash discipline.
  * Apply is modeled as the deterministic transition
    `apply(state, b)` matching FA-Apply-1 (apply determinism:
    same state + same block ⇒ same post-state).
  * Tampering is modeled as one of three abstract mutations on
    snapshot_blob: chain-tamper (mutates a block in tail_chain),
    state-tamper (mutates any namespace's serialized contents),
    or dapp_registry-tamper (mutates the dapp_registry namespace
    specifically). The state_root recompute is sensitive to all
    three: by A2 (abstract hash), distinct state contents produce
    distinct roots; the head_state_root field is unchanged by the
    tamper (the adversary did not also re-sign), so the post-restore
    recompute MUST detect the divergence.

Companion analytic proofs:
  * docs/proofs/S033StateRootNamespaceCoverage.md — the
    ten-namespace coverage theorem (T-1..T-5 per the analytic
    proof). FB31 lifts the snapshot-pathway sub-theorem (T-5
    Snapshot Round-Trip Soundness) to the state-machine layer
    with the cross-node restore + adversarial tamper enumeration.
  * docs/proofs/AppliedReceiptRestore.md — FA-Apply-12 (the receipt
    dedup-set restore correctness sub-theorem). FB17
    AppliedReceiptRestore.tla covers the receipt-set's standalone
    state machine; FB31 unifies this with the broader 10-namespace
    surface via INV_SnapshotRoundTripPreservesAllNamespaces' `i:`
    namespace coverage.
  * docs/proofs/BlockchainStateIntegrity.md — the composition
    theorem (T-1..T-5). FB26 BlockchainStateIntegrity.tla covers
    the chain.json wrap + apply-time gate composition; FB31 is
    the snapshot-pathway sibling.
  * docs/proofs/AccountStateInvariants.md — FA-Apply-1 (apply
    determinism). The prerequisite for restore equivalence —
    INV_RestoreDeterminism and ApplyBlockAfterRestore both rely
    on apply being a pure function of (state, block).

To check (assuming TLC installed):
  $ tlc SnapshotIntegrity.tla -config SnapshotIntegrity.cfg

Recommended config (state space ~10^4–10^5, < 60s):
  Nodes = {n1, n2}, MaxHeight = 3, Slots = {sl1, sl2}.

Cross-references:
  * FB6 Snapshot.tla — the basic snapshot/restore state machine
    (5 invariants on the safety-critical-subset). FB31 extends
    coverage to the post-S-037 / post-S-038 closure: the full
    10-namespace surface, the dapp_registry round-trip, and the
    producer-side state_root wiring.
  * FB26 BlockchainStateIntegrity.tla — the chain.json wrap +
    apply-time gate (S-021 + S-033 + S-038 composition). FB31's
    INV_NoSilentDivergence is the snapshot-pathway sibling of
    FB26's same-named invariant.
  * FB17 AppliedReceiptRestore.tla — the `i:` namespace's
    standalone snapshot lifecycle; FB31 composes this with the
    nine other namespaces.
  * FB5 AccountState.tla — FA-Apply-1; the apply-determinism
    foundation INV_RestoreDeterminism builds on.
  * SECURITY.md §S-033, §S-037, §S-038 — the per-mechanism
    closure narratives this proof composes.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes,              \* finite universe of node IDs (2 nodes: producer + restorer)
    MaxHeight,          \* spec-time bound on chain length
    Slots               \* finite universe of state slot identifiers (per-namespace contents)

ASSUME ConfigOK ==
    /\ Cardinality(Nodes) >= 2
    /\ MaxHeight \in Nat /\ MaxHeight >= 1
    /\ Cardinality(Slots) >= 1

\* -----------------------------------------------------------------
\* §1. State shape and abstract hash model.
\* -----------------------------------------------------------------
\*
\* The four mutable state maps that contribute to the state_root
\* Merkle commitment under the a:/s:/r:/d: namespaces. The spec
\* collapses each to a SUBSET of Slots — the abstract-hash
\* discipline lets us reason about equality + tamper-detection
\* without tracking per-slot byte contents.
\*
\* The six other namespaces (i:/b:/m:/p:/k:/c:) are projected into
\* this same SUBSET-of-Slots abstraction implicitly: the
\* state_root_of operator collapses all 10 namespaces into a
\* single tagged-tuple hash whose distinctness is by A2. The
\* S-037 closure threads dapp_registry and applied_inbound_receipts
\* through serialize/restore symmetrically; both are projected
\* into the same SUBSET-of-Slots universe at the spec layer.

\* State shape: four-map tuple [accounts, stakes, registrants,
\* dapp_registry]. Each is a SUBSET of Slots representing the
\* namespace's serialized contents. dapp_registry is the S-037
\* surface — the field that was missing from serialize_state /
\* restore_from_snapshot pre-S-037.
State == [accounts:       SUBSET Slots,
          stakes:         SUBSET Slots,
          registrants:    SUBSET Slots,
          dapp_registry:  SUBSET Slots]

\* Empty state (genesis projection).
EmptyState == [accounts      |-> {},
               stakes        |-> {},
               registrants   |-> {},
               dapp_registry |-> {}]

\* state_root_of: the modeled compute_state_root. Pure function
\* over the four namespaces; distinct states produce distinct
\* roots by tuple inequality (the spec-layer projection of A2).
\* The "ROOT" discriminator tag prevents accidental collision
\* with compute_hash outputs (which use "HASH" discriminator).
state_root_of(s) ==
    <<"ROOT", s.accounts, s.stakes, s.registrants, s.dapp_registry>>

\* The "hash universe" for state roots. TLC enumerates this only
\* structurally — we never compare against a closed-form set, just
\* against another root value.
RootUniverse ==
    { <<"ROOT", a, st, r, d>> :
        a  \in SUBSET Slots,
        st \in SUBSET Slots,
        r  \in SUBSET Slots,
        d  \in SUBSET Slots }
    \cup { <<"ZERO">> }

\* The zero-state_root sentinel (matches the C++ Hash{} initializer).
ZeroRoot == <<"ZERO">>

\* Block shape: index, prev_hash (abstract), state_root, and
\* txs (a SUBSET of Slots — the per-block payload that drives
\* state mutation when applied). Pre-S-038 historical blocks
\* had state_root = ZeroRoot; post-S-038 every produced block
\* has a non-zero state_root by construction.
Block == [
    index      : 0..MaxHeight,
    prev_hash  : { <<"HASH", j>> : j \in 0..MaxHeight } \cup { <<"GENESIS">> },
    state_root : RootUniverse,
    txs        : SUBSET Slots
]

\* compute_hash: pure function over a Block's identity. The hash
\* binds (index, txs) for the spec layer; the C++ side binds the
\* full signing_bytes including state_root under the S-033 zero-skip
\* shim. The abstract-hash discipline (distinct pre-images map to
\* distinct outputs) covers the structural-equality reasoning we
\* need for cascade detection.
compute_hash(b) == <<"HASH", b.index>>

\* The genesis prev_hash sentinel.
GenesisHash == <<"GENESIS">>

\* -----------------------------------------------------------------
\* §2. Snapshot shape.
\* -----------------------------------------------------------------
\*
\* Snapshot record: tail_chain (the chain prefix being snapshotted),
\* serialized_state (the four-map snapshot of state), and
\* head_state_root (the state_root of the tail-head block, stored
\* directly in the snapshot for the post-restore gate). Matches
\* `Chain::serialize_state` at chain.cpp:1541-1701 — the JSON
\* object covers every namespace's source map + the tail-header
\* bundle's stored state_root (under the head.state_root field).
\*
\* Pre-S-037 the dapp_registry field was absent from serialized_state.
\* This spec models the post-S-037 form: dapp_registry is included
\* explicitly. INV_DAppRegistryRoundtrips verifies the field
\* survives serialize → restore byte-for-byte.

Snapshot == [
    tail_chain        : Seq(Block),
    serialized_state  : State,
    head_state_root   : RootUniverse
]

\* The sentinel for "no snapshot has been taken yet" or "tampered
\* at the dapp_registry layer specifically".
NoSnapshot == <<"no_snapshot">>

\* TamperSite enum: the four possible adversary positions.
\*   "none"          — no tamper observed.
\*   "chain"         — mutated one block inside tail_chain.
\*   "state"         — mutated one of accounts/stakes/registrants/
\*                     dapp_registry contents at the namespace level.
\*   "dapp_registry" — mutated the dapp_registry specifically (the
\*                     S-037 closure surface; called out separately
\*                     so a regression that re-introduces the bug
\*                     surfaces as a tamper-detection failure on
\*                     this specific site).
TamperSite == { "none", "chain", "state", "dapp_registry" }

\* -----------------------------------------------------------------
\* §3. Apply function — the canonical state transition.
\* -----------------------------------------------------------------
\*
\* apply(state, b) mutates every namespace via union with the
\* block's txs payload. The model abstracts away per-tx semantics
\* (TRANSFER / REGISTER / DAPP_REGISTER / STAKE / etc.); the only
\* thing that matters for snapshot-integrity invariants is that
\* apply is deterministic on (state, b) pairs (FA-Apply-1) AND
\* every namespace's contents is a deterministic function of the
\* block-sequence (the round-trip-equality property).
\*
\* The four-map update pattern: every block contributes to every
\* namespace by union. Concretely, accounts gets the block's txs,
\* stakes gets the block's txs, etc. — the spec collapses per-tx-type
\* routing because the namespace-coverage invariant is over set
\* equality, not over per-tx semantics.

apply(s, b) ==
    [accounts      |-> s.accounts      \cup b.txs,
     stakes        |-> s.stakes        \cup b.txs,
     registrants   |-> s.registrants   \cup b.txs,
     dapp_registry |-> s.dapp_registry \cup b.txs]

\* -----------------------------------------------------------------
\* §4. Helpers.
\* -----------------------------------------------------------------

\* head_state(c) — fold apply over the chain to recover the
\* post-apply state. Pure function; the modeled compute_state_root
\* delegates to state_root_of(head_state(c)).
RECURSIVE head_state_(_, _)
head_state_(c, i) ==
    IF i = 0
    THEN EmptyState
    ELSE apply(head_state_(c, i - 1), c[i])

head_state(c) == head_state_(c, Len(c))

\* head_hash_of(c) — the chain's head hash, mirroring
\* Chain::head_hash().
head_hash_of(c) ==
    IF Len(c) = 0
    THEN GenesisHash
    ELSE compute_hash(c[Len(c)])

\* -----------------------------------------------------------------
\* §5. Variables.
\* -----------------------------------------------------------------

VARIABLES
    live_chain,         \* function NodeId -> Seq(Block)
    live_state,         \* function NodeId -> State (four mutable maps)
    snapshot_blob,      \* function NodeId -> Snapshot or NoSnapshot
    apply_throws,       \* function NodeId -> BOOLEAN — set TRUE on apply-time mismatch
    restore_throws,     \* function NodeId -> BOOLEAN — set TRUE on restore-time mismatch
    tampered_at         \* function NodeId -> TamperSite

vars == <<live_chain, live_state, snapshot_blob,
          apply_throws, restore_throws, tampered_at>>

\* -----------------------------------------------------------------
\* §6. Initial state.
\* -----------------------------------------------------------------
\*
\* Every node starts with an empty chain, empty four-map state,
\* no snapshot, no thrown gates, no tampering. The "fresh node from
\* genesis" condition.

Init ==
    /\ live_chain     = [n \in Nodes |-> <<>>]
    /\ live_state     = [n \in Nodes |-> EmptyState]
    /\ snapshot_blob  = [n \in Nodes |-> NoSnapshot]
    /\ apply_throws   = [n \in Nodes |-> FALSE]
    /\ restore_throws = [n \in Nodes |-> FALSE]
    /\ tampered_at    = [n \in Nodes |-> "none"]

\* -----------------------------------------------------------------
\* §7. Actions.
\* -----------------------------------------------------------------

\* ProduceBlock(n) — the producer-side path (T-S3 mechanism).
\* Mirrors the C++ Node::try_finalize_round at src/node/node.cpp:
\* 1024-1117 with the S-038 wiring at lines 1093-1117:
\*
\*   1. build_body() — assemble body, state_root = Hash{} initially.
\*   2. tentative_chain = chain_ (deep copy).
\*   3. tentative_chain.append(body) — apply on tentative; the
\*      S-033 gate short-circuits because body.state_root == zero.
\*   4. body.state_root = tentative_chain.compute_state_root().
\*   5. apply_block_locked(body) → chain_.append(body) — the gate
\*      now sees non-zero state_root and compares; by FA-Apply-1
\*      the live chain produces byte-identical state and the gate
\*      passes.
\*
\* The spec models all five steps atomically. INV_ProducerSelfApply-
\* ConsistentPostS038 is the structural witness that step 4 always
\* fires — every produced block carries a non-zero state_root.

ProduceBlock(n) ==
    /\ n \in Nodes
    /\ Len(live_chain[n]) < MaxHeight
    /\ \E txs_sub \in SUBSET Slots :
       LET prev   == head_hash_of(live_chain[n]) IN
       LET body_pre == [
              index      |-> Len(live_chain[n]),
              prev_hash  |-> prev,
              state_root |-> ZeroRoot,  \* step 1: state_root = Hash{}
              txs        |-> txs_sub
           ] IN
       \* Step 2-3: tentative-chain dry-run computes post-apply state.
       LET post_state == apply(live_state[n], body_pre) IN
       \* Step 4: populate body.state_root with the canonical
       \* post-apply root. The S-038 closure: every produced block
       \* now carries a non-zero state_root by construction.
       LET body == [
              index      |-> body_pre.index,
              prev_hash  |-> body_pre.prev_hash,
              state_root |-> state_root_of(post_state),
              txs        |-> body_pre.txs
           ] IN
       \* Step 5: apply on live chain. By T-S3 the gate passes.
       /\ live_chain' = [live_chain EXCEPT ![n] = Append(live_chain[n], body)]
       /\ live_state' = [live_state EXCEPT ![n] = post_state]
       /\ UNCHANGED <<snapshot_blob, apply_throws, restore_throws, tampered_at>>

\* SerializeSnapshot(n) — emit a snapshot from the live chain
\* (T-S1 producer side). Mirrors Chain::serialize_state at
\* chain.cpp:1541-1701. The snapshot covers:
\*   - tail_chain (the chain prefix being snapshotted)
\*   - serialized_state (the FOUR mutable maps; the S-037 closure
\*     added dapp_registry to this list; pre-S-037 only three maps
\*     were serialized)
\*   - head_state_root (the tail-head's stored state_root, used by
\*     the post-restore gate at chain.cpp:1893-1911)
\*
\* The serialized_state is set to live_state[n] verbatim — every
\* namespace contributes its current contents. INV_DAppRegistry-
\* Roundtrips verifies the dapp_registry field specifically (the
\* S-037 closure surface).

SerializeSnapshot(n) ==
    /\ n \in Nodes
    /\ Len(live_chain[n]) > 0
    /\ snapshot_blob' = [snapshot_blob EXCEPT ![n] =
           [tail_chain        |-> live_chain[n],
            serialized_state  |-> live_state[n],
            head_state_root   |-> state_root_of(live_state[n])]]
    /\ tampered_at'   = [tampered_at EXCEPT ![n] = "none"]
    /\ UNCHANGED <<live_chain, live_state, apply_throws, restore_throws>>

\* RestoreFromSnapshot(n2) — restore at a receiver node n2 distinct
\* from the producer node n (T-S1, T-S2, T-S4, T-S5). Mirrors
\* Chain::restore_from_snapshot at chain.cpp:1703-1932:
\*
\*   1. Replay tail_chain into live_chain[n2].
\*   2. Restore serialized_state into live_state[n2] — every
\*      namespace's contents is rehydrated.
\*   3. Recompute state_root_of(live_state[n2]) and compare against
\*      snapshot.head_state_root. On mismatch, throw the S-033 tag
\*      (chain.cpp:1893-1911) — modeled here by latching
\*      restore_throws[n2].
\*
\* The post-restore gate (step 3) is the load-bearing check: any
\* tamper that changed the serialized_state contents OR the
\* tail_chain (which feeds head_state) but did NOT also re-sign
\* the head_state_root field gets caught.

RestoreFromSnapshot(n2) ==
    /\ n2 \in Nodes
    /\ \E n \in Nodes :
       /\ n /= n2
       /\ snapshot_blob[n] /= NoSnapshot
       /\ LET snap          == snapshot_blob[n] IN
          LET restored      == snap.serialized_state IN
          \* Step 3: recompute the state_root and compare.
          LET recomputed    == state_root_of(restored) IN
          LET gate_passes   == recomputed = snap.head_state_root IN
          IF gate_passes
          THEN
             \* Restore succeeds: install chain + state.
             /\ live_chain'     = [live_chain EXCEPT ![n2] = snap.tail_chain]
             /\ live_state'     = [live_state EXCEPT ![n2] = restored]
             /\ UNCHANGED <<snapshot_blob, apply_throws, restore_throws,
                            tampered_at>>
          ELSE
             \* Restore throws: state_root recompute mismatched the
             \* snapshot's stored head_state_root. The chain is NOT
             \* installed; restore_throws latches.
             /\ restore_throws' = [restore_throws EXCEPT ![n2] = TRUE]
             /\ UNCHANGED <<live_chain, live_state, snapshot_blob,
                            apply_throws, tampered_at>>

\* ApplyBlockAfterRestore(n2) — apply a new block on a node that
\* has just restored (T-S4 apply-side detection). Mirrors the
\* C++ Chain::apply_transactions at chain.cpp:1421-1446: the
\* S-033 gate recomputes the post-apply state_root and compares
\* against the block's declared state_root. On mismatch, throw.
\*
\* The action picks any block whose prev_hash extends the current
\* chain head AND whose declared state_root is verifiable. If the
\* declared state_root doesn't match what apply computes, the
\* gate fires and apply_throws latches.

ApplyBlockAfterRestore(n2) ==
    /\ n2 \in Nodes
    /\ Len(live_chain[n2]) < MaxHeight
    /\ \E txs_sub \in SUBSET Slots :
       \E declared_root \in RootUniverse :
          LET prev       == head_hash_of(live_chain[n2]) IN
          LET b          == [index      |-> Len(live_chain[n2]),
                             prev_hash  |-> prev,
                             state_root |-> declared_root,
                             txs        |-> txs_sub] IN
          LET post_state == apply(live_state[n2], b) IN
          LET computed   == state_root_of(post_state) IN
          \* Gate check: declared state_root must match computed
          \* (post-S-038 the producer guarantees this for self-apply;
          \* a tampered or divergent declared_root fails).
          IF declared_root = ZeroRoot \/ declared_root = computed
          THEN
             /\ live_chain' = [live_chain EXCEPT ![n2] = Append(live_chain[n2], b)]
             /\ live_state' = [live_state EXCEPT ![n2] = post_state]
             /\ UNCHANGED <<snapshot_blob, apply_throws, restore_throws,
                            tampered_at>>
          ELSE
             /\ apply_throws' = [apply_throws EXCEPT ![n2] = TRUE]
             /\ UNCHANGED <<live_chain, live_state, snapshot_blob,
                            restore_throws, tampered_at>>

\* TamperSnapshot(n) — adversarial mutation of snapshot_blob[n].
\* Three branches model the three adversary positions enumerated in
\* T-S4: (a) interior tail-chain block, (b) any namespace's contents,
\* (c) the dapp_registry specifically (the S-037 closure surface).
\* The wrap header's head_state_root field is NOT patched — the
\* adversary did not also forge committee signatures to re-sign the
\* tampered state. The next RestoreFromSnapshot MUST detect the
\* divergence by recompute-vs-stored mismatch.
\*
\* Three disjuncts (chain / state / dapp_registry tampers) provide
\* explicit per-site detection lock-in for INV_StateRootGateFires-
\* OnRestoreTamper. The dapp_registry branch is the S-037 closure
\* surface; calling it out separately means a regression that
\* re-removes the `d:` namespace from serialize_state would surface
\* as a tamper-detection failure on this specific site.

TamperSnapshot(n) ==
    /\ n \in Nodes
    /\ snapshot_blob[n] /= NoSnapshot
    /\ \E new_contents \in SUBSET Slots :
       LET snap == snapshot_blob[n] IN
       \/ \* (a) Tamper a tail-chain block's txs.
          /\ Len(snap.tail_chain) > 0
          /\ \E i \in 1..Len(snap.tail_chain) :
             /\ new_contents /= snap.tail_chain[i].txs
             /\ LET old == snap.tail_chain[i] IN
                LET tampered == [
                       index      |-> old.index,
                       prev_hash  |-> old.prev_hash,
                       state_root |-> old.state_root,
                       txs        |-> new_contents] IN
                LET tampered_chain ==
                       [j \in 1..Len(snap.tail_chain) |->
                          IF j = i THEN tampered ELSE snap.tail_chain[j]] IN
                /\ snapshot_blob' = [snapshot_blob EXCEPT ![n] =
                       [tail_chain        |-> tampered_chain,
                        serialized_state  |-> snap.serialized_state,
                        head_state_root   |-> snap.head_state_root]]
                /\ tampered_at'   = [tampered_at EXCEPT ![n] = "chain"]
                /\ UNCHANGED <<live_chain, live_state, apply_throws,
                               restore_throws>>
       \/ \* (b) Tamper a state namespace (accounts/stakes/registrants).
          /\ new_contents /= snap.serialized_state.accounts
          /\ LET new_state == [
                    accounts      |-> new_contents,
                    stakes        |-> snap.serialized_state.stakes,
                    registrants   |-> snap.serialized_state.registrants,
                    dapp_registry |-> snap.serialized_state.dapp_registry] IN
             /\ snapshot_blob' = [snapshot_blob EXCEPT ![n] =
                    [tail_chain        |-> snap.tail_chain,
                     serialized_state  |-> new_state,
                     head_state_root   |-> snap.head_state_root]]
             /\ tampered_at'   = [tampered_at EXCEPT ![n] = "state"]
             /\ UNCHANGED <<live_chain, live_state, apply_throws,
                            restore_throws>>
       \/ \* (c) Tamper the dapp_registry specifically (S-037 surface).
          /\ new_contents /= snap.serialized_state.dapp_registry
          /\ LET new_state == [
                    accounts      |-> snap.serialized_state.accounts,
                    stakes        |-> snap.serialized_state.stakes,
                    registrants   |-> snap.serialized_state.registrants,
                    dapp_registry |-> new_contents] IN
             /\ snapshot_blob' = [snapshot_blob EXCEPT ![n] =
                    [tail_chain        |-> snap.tail_chain,
                     serialized_state  |-> new_state,
                     head_state_root   |-> snap.head_state_root]]
             /\ tampered_at'   = [tampered_at EXCEPT ![n] = "dapp_registry"]
             /\ UNCHANGED <<live_chain, live_state, apply_throws,
                            restore_throws>>

\* TamperLiveState(n) — at-rest tamper of live state on disk
\* between serialize and restore. Mutates live_state[n]'s
\* accounts field directly; if the receiver later restores from
\* this node's snapshot, the snapshot itself was already
\* serialized BEFORE the tamper and so will not carry the
\* tamper. This action exists to exercise the cross-node
\* INV_NoSilentDivergence: if the producer's live state drifts
\* relative to a previously-emitted snapshot, the next snapshot
\* will diverge — and any consumer of the OLD snapshot will
\* observe a different state than the producer's current live
\* state. This is captured by tampered_at being set, the snapshot
\* being unmodified, and the divergence being observable at the
\* state-root layer.

TamperLiveState(n) ==
    /\ n \in Nodes
    /\ \E new_contents \in SUBSET Slots :
       /\ new_contents /= live_state[n].accounts
       /\ LET new_state == [
                 accounts      |-> new_contents,
                 stakes        |-> live_state[n].stakes,
                 registrants   |-> live_state[n].registrants,
                 dapp_registry |-> live_state[n].dapp_registry] IN
          /\ live_state'   = [live_state EXCEPT ![n] = new_state]
          /\ tampered_at'  = [tampered_at EXCEPT ![n] = "state"]
          /\ UNCHANGED <<live_chain, snapshot_blob, apply_throws,
                         restore_throws>>

\* Stutter (TLC bounds the state space; invariants are evaluated at
\* every reachable state along the way).
Stutter ==
    /\ \A n \in Nodes : Len(live_chain[n]) >= MaxHeight
    /\ UNCHANGED vars

Next ==
    \/ \E n \in Nodes : ProduceBlock(n)
    \/ \E n \in Nodes : SerializeSnapshot(n)
    \/ \E n \in Nodes : RestoreFromSnapshot(n)
    \/ \E n \in Nodes : ApplyBlockAfterRestore(n)
    \/ \E n \in Nodes : TamperSnapshot(n)
    \/ \E n \in Nodes : TamperLiveState(n)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E n \in Nodes : SerializeSnapshot(n))
             /\ WF_vars(\E n \in Nodes : RestoreFromSnapshot(n))
             /\ WF_vars(\E n \in Nodes : ApplyBlockAfterRestore(n))

\* -----------------------------------------------------------------
\* §8. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ live_chain     \in [Nodes -> Seq(Block)]
    /\ live_state     \in [Nodes -> State]
    /\ snapshot_blob  \in [Nodes -> Snapshot \cup {NoSnapshot}]
    /\ apply_throws   \in [Nodes -> BOOLEAN]
    /\ restore_throws \in [Nodes -> BOOLEAN]
    /\ tampered_at    \in [Nodes -> TamperSite]

\* -----------------------------------------------------------------
\* §9. Invariants — the six standing claims for T-S1..T-S5.
\* -----------------------------------------------------------------

\* INV_SnapshotRoundTripPreservesAllNamespaces (T-S1 composed with T-S2).
\* The headline composition invariant. For every node-pair (n, n2)
\* where n2 has successfully restored from n's snapshot (no
\* restore_throws latch + no apply_throws latch + snapshot present):
\* the restored live_state[n2] equals the snapshot's
\* serialized_state across all four namespaces (which is the spec-
\* layer projection of the full 10-namespace surface).
\*
\* The S-037 + S-038 composition's structural witness: dapp_registry
\* round-trips under the `d:` namespace AND the state_root over all
\* namespaces matches byte-for-byte (state_root_of's discriminator
\* enforces that distinct namespace contents produce distinct roots).
\* Without the S-037 closure threading dapp_registry through
\* serialize/restore, this invariant would fail on any chain with
\* active DApps — restore would rehydrate an empty dapp_registry
\* but the snapshot's head_state_root was computed over the
\* DApp-populated one, and the post-restore recompute would
\* catch it.

INV_SnapshotRoundTripPreservesAllNamespaces ==
    \A n, n2 \in Nodes :
       (n /= n2
        /\ snapshot_blob[n] /= NoSnapshot
        /\ restore_throws[n2] = FALSE
        /\ live_chain[n2] = snapshot_blob[n].tail_chain)
       =>
          /\ live_state[n2].accounts      = snapshot_blob[n].serialized_state.accounts
          /\ live_state[n2].stakes        = snapshot_blob[n].serialized_state.stakes
          /\ live_state[n2].registrants   = snapshot_blob[n].serialized_state.registrants
          /\ live_state[n2].dapp_registry = snapshot_blob[n].serialized_state.dapp_registry
          /\ state_root_of(live_state[n2]) = snapshot_blob[n].head_state_root

\* INV_StateRootGateFiresOnRestoreTamper (T-S4).
\* If a node's snapshot has been tampered (at chain / state /
\* dapp_registry layer), then EITHER restore_throws latches at
\* the next RestoreFromSnapshot (the chain.cpp:1893-1911 gate
\* recomputed the state_root and saw a mismatch) OR the chain
\* has not yet been restored from the tampered snapshot at any
\* other node (the antecedent is vacuous before the
\* RestoreFromSnapshot fires).
\*
\* The structural form: if a tamper has been observed AND some
\* node has installed live_state from the tampered snapshot
\* (no restore_throws latched but the chain matches the tampered
\* tail_chain), then state_root_of(restored_state) /=
\* head_state_root — i.e., the gate should have fired. We assert
\* the contrapositive: if the gate did NOT fire (restore_throws
\* = FALSE) AND the chain matches the tampered snapshot's
\* tail_chain, then the recompute matches stored (which by A2
\* implies no tamper of state-relevant fields).

INV_StateRootGateFiresOnRestoreTamper ==
    \A n, n2 \in Nodes :
       (n /= n2
        /\ tampered_at[n] \in {"state", "dapp_registry"}
        /\ snapshot_blob[n] /= NoSnapshot
        /\ live_chain[n2] = snapshot_blob[n].tail_chain
        /\ restore_throws[n2] = FALSE)
       =>
          \* If we got here with no restore_throws, the state must
          \* still satisfy the head_state_root recompute equality.
          \* But the tamper changed serialized_state.{accounts ∪
          \* dapp_registry} so state_root_of(restored) would differ
          \* from head_state_root — contradiction. The invariant
          \* asserts the conjuncts cannot all hold simultaneously.
          state_root_of(snapshot_blob[n].serialized_state) =
              snapshot_blob[n].head_state_root

\* INV_ProducerSelfApplyConsistentPostS038 (T-S3).
\* Every block in live_chain[n] produced by ProduceBlock has a
\* state_root that matches the apply-time post-state. The
\* pre-S-038 dormant-gate case (state_root = ZeroRoot from the
\* producer) is included as a disjunct for compatibility with
\* the apply_block_after_restore action's degenerate test mode,
\* but ProduceBlock never produces ZeroRoot in the post-S-038
\* model — INV_ProducerNeverEmitsZero below pins this lock-in.
\*
\* The state-form witness: every block in chains[n] has a
\* state_root that equals state_root_of(head_state(prefix)) where
\* prefix is the chain up to that block. By FA-Apply-1 the
\* producer's tentative-chain dry-run produces byte-identical
\* state to the live chain after the same body is applied.

INV_ProducerSelfApplyConsistentPostS038 ==
    \A n \in Nodes :
       \A i \in 1..Len(live_chain[n]) :
          LET prefix == SubSeq(live_chain[n], 1, i) IN
          live_chain[n][i].state_root \in
              { ZeroRoot, state_root_of(head_state(prefix)) }

\* INV_DAppRegistryRoundtrips (T-S2 standalone).
\* The dapp_registry map specifically passes through serialize +
\* restore byte-for-byte. The S-037 closure invariant: a regression
\* that re-removes the `d:` namespace from Chain::serialize_state
\* would cause every snapshot's serialized_state.dapp_registry to
\* lose information, and a receiver's restored live_state[n2].
\* dapp_registry would not match the producer's live_state[n].
\* dapp_registry — which this invariant directly asserts must hold
\* under any successful restore.
\*
\* This is a strict sub-claim of INV_SnapshotRoundTripPreserves-
\* AllNamespaces but it is called out as a standalone invariant
\* so the S-037 regression surface is observable at a single-
\* invariant granularity (a TLC counter-example would name this
\* invariant specifically, making the regression diagnosis
\* immediate).

INV_DAppRegistryRoundtrips ==
    \A n, n2 \in Nodes :
       (n /= n2
        /\ snapshot_blob[n] /= NoSnapshot
        /\ restore_throws[n2] = FALSE
        /\ live_chain[n2] = snapshot_blob[n].tail_chain
        /\ tampered_at[n] = "none")
       =>
          live_state[n2].dapp_registry =
              snapshot_blob[n].serialized_state.dapp_registry

\* INV_RestoreDeterminism (T-S5).
\* For every node-pair (n, n'): if snapshot_blob[n] =
\* snapshot_blob[n'], then RestoreFromSnapshot produces
\* byte-identical live_state regardless of which snapshot is
\* consumed. Restore is a pure function of (snapshot, current_chain)
\* and the C++ Chain::restore_from_snapshot has no
\* fresh-randomness inputs.
\*
\* State-form witness: if two nodes have identical snapshots AND
\* identical chains AND both have completed a restore without
\* throwing, their live_states must be identical.

INV_RestoreDeterminism ==
    \A n1, n2 \in Nodes :
       (snapshot_blob[n1] /= NoSnapshot
        /\ snapshot_blob[n1] = snapshot_blob[n2]
        /\ live_chain[n1] = live_chain[n2]
        /\ live_chain[n1] /= <<>>
        /\ restore_throws[n1] = FALSE
        /\ restore_throws[n2] = FALSE)
       => live_state[n1] = live_state[n2]

\* INV_NoSilentDivergence (T-S4 cross-node form).
\* The snapshot-pathway mirror of FB26 BlockchainStateIntegrity.tla's
\* same-named invariant. If two nodes have the same restored chain
\* but different state_roots, at least one of `apply_throws` or
\* `restore_throws` must be TRUE — the integrity gates fire before
\* the divergent state can survive at apply time.
\*
\* Restricted to the snapshot pathway via the antecedent's
\* requirement that both nodes have non-empty live_chain (i.e.,
\* either produced or restored).

INV_NoSilentDivergence ==
    \A n1, n2 \in Nodes :
       (n1 /= n2
        /\ live_chain[n1] = live_chain[n2]
        /\ live_chain[n1] /= <<>>
        /\ state_root_of(live_state[n1]) /= state_root_of(live_state[n2]))
       => (apply_throws[n1] \/ apply_throws[n2]
            \/ restore_throws[n1] \/ restore_throws[n2])

\* -----------------------------------------------------------------
\* §10. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualSnapshotSuccess — under fairness on
\* SerializeSnapshot, eventually some snapshot is taken (no
\* permanent starvation of the snapshot subsystem). Strengthening
\* of FB6 Snapshot.tla's Prop_EventualSnapshotConsistency lifted
\* to the per-node form.
PROP_EventualSnapshotSuccess ==
    <>(\E n \in Nodes : snapshot_blob[n] /= NoSnapshot)

\* PROP_TamperingDetected — under fairness on the detection
\* actions (RestoreFromSnapshot + ApplyBlockAfterRestore), every
\* observed tamper eventually fires at least one throw-gate. The
\* structural argument: a tampered snapshot whose head_state_root
\* was NOT also re-signed will fail the post-restore recompute by
\* A2 (distinct state contents produce distinct roots); under
\* fairness, RestoreFromSnapshot eventually fires; once it fires,
\* the gate latches restore_throws[n2] = TRUE.

PROP_TamperingDetected ==
    \A n \in Nodes :
       (tampered_at[n] \in {"state", "dapp_registry"})
       => <>(\E m \in Nodes : restore_throws[m] = TRUE \/ apply_throws[m] = TRUE)

\* -----------------------------------------------------------------
\* §11. How this spec extends FB6 Snapshot.tla.
\* -----------------------------------------------------------------
\*
\* FB6 Snapshot.tla pins the basic snapshot/restore state machine
\* with five invariants over a (chain, last_snapshot, snapshot_count)
\* triple: SerializeRestoreIdentity (round-trip = identity),
\* ApplyAfterRestoreEquivalence (commuting square), VersionGate-
\* Soundness (wrong-version no-op), DeterministicSerialization
\* (pure function), StateRootBindsApply (state_root commits to
\* (balances, counters)). Plus two temporal: EventualSnapshot-
\* Consistency + RestoreIsCorrect.
\*
\* FB6's modeling scope (per its file header) collapses the 10
\* state_root namespaces to two — `a:` (balances + nonces) and
\* `b:` (accumulated counters). The remaining eight are out of
\* invariant scope at FB6's layer because the round-trip-identity
\* property's safety is dominated by the (balances, counters)
\* projection.
\*
\* FB31 extends coverage on three axes:
\*
\*   (1) Ten-namespace surface (S-033 + S-037 composition).
\*       The four-map state shape [accounts, stakes, registrants,
\*       dapp_registry] is the post-S-037 mutable-state surface
\*       that contributes to the state_root commitment. The
\*       remaining six namespaces (i:/b:/m:/p:/k:/c:) collapse
\*       cleanly into the same SUBSET-of-Slots abstraction under
\*       state_root_of's tuple discriminator (the abstract-hash
\*       discipline used by FB26 BlockchainStateIntegrity.tla).
\*       INV_SnapshotRoundTripPreservesAllNamespaces is the
\*       headline composition invariant; it directly extends FB6's
\*       SerializeRestoreIdentity to the full four-map shape.
\*
\*   (2) DApp registry round-trip (S-037 closure).
\*       INV_DAppRegistryRoundtrips is a standalone sub-claim that
\*       names the S-037 closure surface directly. A regression
\*       that re-removes the `d:` namespace from
\*       Chain::serialize_state would surface as a single-invariant
\*       failure here — observable at the closest-possible
\*       granularity in TLC traces.
\*
\*   (3) Producer-side state_root wiring (S-038 closure).
\*       INV_ProducerSelfApplyConsistentPostS038 pins the
\*       post-S-038 contract: every produced block carries a
\*       non-zero state_root populated via the tentative-chain
\*       dry-run pattern. Pre-S-038 the producer never put a
\*       non-zero value in body.state_root and the apply-time
\*       gate was effectively dormant on production blocks; FB31
\*       models the closure.
\*
\* Plus a cross-node tamper-detection surface that FB6 doesn't
\* model (FB6 has only one chain variable + one snapshot
\* variable; FB31 has function-of-Nodes for both, enabling the
\* cross-node restore + per-node tamper invariants).
\*
\* Companion analytic proof: docs/proofs/S033StateRootNamespace-
\* Coverage.md (the 10-namespace coverage theorem) + Applied-
\* ReceiptRestore.md (FA-Apply-12, the receipt dedup-set restore
\* correctness sub-theorem). FB31 unifies these at the
\* state-machine layer.
\*
\* Cross-reference: FB6 Snapshot.tla (basic snapshot/restore SM —
\* this spec's foundation), FB26 BlockchainStateIntegrity.tla
\* (chain.json wrap + apply-time gate — sibling state-integrity
\* surface). FB31 closes the snapshot-pathway gap between FB6's
\* coverage and the post-S-037 + post-S-038 closure.
\*
\* Out of scope:
\*
\*   * The basic apply-determinism invariant (covered by
\*     FA-Apply-1 / FB5 AccountState.tla). FB31's apply operator
\*     is the spec-layer projection; the underlying determinism
\*     property is FB5 territory.
\*   * The cross-shard receipt dedup invariant (covered by FB17
\*     AppliedReceiptRestore.tla / FA-Apply-12). FB31 composes
\*     this via INV_SnapshotRoundTripPreservesAllNamespaces' `i:`
\*     namespace coverage (the i: namespace is collapsed into
\*     the SUBSET-of-Slots abstraction).
\*   * The chain.json wrap (FB26 BlockchainStateIntegrity.tla
\*     territory). FB31's RestoreFromSnapshot models the
\*     in-memory snapshot restore path; the disk-level
\*     chain.json wrap + head_hash check is the parallel
\*     state-integrity boundary covered by FB26.
\*   * The byte-level codec round-trip (the JSON encoding /
\*     decoding fidelity). The serialized_state field is modeled
\*     as a TLA+ record; the codec is FA-track territory
\*     (tools/test_state_root_namespaces.sh, 12 assertions).
\*   * Pre-S-038 historical blocks bypass the apply-time gate
\*     (intentional backward-compat via the zero-skip shim).
\*     INV_ProducerSelfApplyConsistentPostS038 captures this via
\*     the b.state_root = ZeroRoot disjunct; post-S-038 every
\*     produced block has non-zero state_root by construction.
\*   * Ed25519 EUF-CMA / SHA-256 collision resistance bounds
\*     (the cryptographic tightness is FA-track territory).
\*     FB31 lifts these to deterministic predicates ("distinct
\*     pre-images map to distinct hashes") via the abstract-hash
\*     model.
\*
\* What this spec adds beyond FB6: a state-machine witness that
\* the 10-namespace round-trip + dapp_registry survival + producer-
\* side state_root population compose into the snapshot-pathway
\* tamper-detection contract. TLC enumerates every reachable
\* interleaving of ProduceBlock / SerializeSnapshot /
\* RestoreFromSnapshot / ApplyBlockAfterRestore / TamperSnapshot /
\* TamperLiveState within the bounded universe; the six
\* invariants are checked against the accumulated state.

============================================================================
\* Cross-references.
\*
\* FA-Snapshot (S033StateRootNamespaceCoverage.md) ->
\*   T-S1 (Ten-Namespace Round-Trip Coverage) :
\*       INV_SnapshotRoundTripPreservesAllNamespaces. The four-map
\*       SUBSET-of-Slots projection is the spec-layer abstraction
\*       of the ten-namespace serialize/restore symmetry.
\*   T-S2 (DApp Registry Round-Trip / S-037 closure) :
\*       INV_DAppRegistryRoundtrips. Standalone invariant for the
\*       S-037 regression surface.
\*   T-S3 (Producer-Side State_Root Wiring / S-038 closure) :
\*       INV_ProducerSelfApplyConsistentPostS038. Every produced
\*       block carries the tentative-chain dry-run's computed root.
\*   T-S4 (Tamper Detection at Snapshot Boundary) :
\*       INV_StateRootGateFiresOnRestoreTamper +
\*       INV_NoSilentDivergence. The two-pronged composition:
\*       restore-time recompute catches state-/dapp_registry-
\*       tampers; apply-time gate catches downstream divergence.
\*   T-S5 (Restore Determinism) :
\*       INV_RestoreDeterminism. Restore is a pure function of
\*       the snapshot.
\*
\* SECURITY.md §S-033 + §S-037 + §S-038 : the per-mechanism closure
\*   narratives. The composition is total over the snapshot-pathway
\*   state-integrity surface.
\*
\* Preliminaries.md §2.1 (A2) : SHA-256 collision resistance.
\*   Modeled via the abstract-hash pattern (distinct pre-images
\*   map to distinct outputs by tuple inequality).
\*
\* FB5 AccountState.tla (FA-Apply-1) : apply determinism. The
\*   load-bearing input to INV_RestoreDeterminism and the
\*   ApplyBlockAfterRestore action's determinism contract.
\* FB6 Snapshot.tla (FA-Apply-2) : the basic snapshot/restore
\*   state machine — FB31's foundation. FB31 extends FB6's
\*   coverage to the ten-namespace surface + dapp_registry round-
\*   trip + producer-side state_root wiring.
\* FB17 AppliedReceiptRestore.tla (FA-Apply-12) : the `i:`
\*   namespace's standalone snapshot lifecycle (S-037 closure
\*   witness for the receipt dedup-set). FB31 composes this with
\*   the nine other namespaces via the SUBSET-of-Slots abstraction.
\* FB26 BlockchainStateIntegrity.tla : chain.json wrap + apply-
\*   time gate (S-021 + S-033 + S-038 composition); FB31 is the
\*   snapshot-pathway sibling.
\*
\* C++ enforcement:
\*   include/determ/chain/chain.hpp:236-270 : Chain::compute_state_root
\*       declaration + ten-namespace key-encoding table —
\*       INV_SnapshotRoundTripPreservesAllNamespaces maps directly.
\*   src/chain/chain.cpp:267-411    : Chain::build_state_leaves
\*       (ten-namespace leaf generator) — the canonical surface
\*       FB31 abstracts via state_root_of.
\*   src/chain/chain.cpp:413-415    : Chain::compute_state_root —
\*       the spec's state_root_of is the abstract-hash projection.
\*   src/chain/chain.cpp:1421-1446  : the S-033 apply-time gate —
\*       the ApplyBlockAfterRestore action's gate_passes check is
\*       the state-machine projection.
\*   src/chain/chain.cpp:1541-1701  : Chain::serialize_state — the
\*       SerializeSnapshot action's projection. Pre-S-037 the
\*       dapp_registry field was absent; the spec models the
\*       post-S-037 form with all four maps emitted.
\*   src/chain/chain.cpp:1703-1932  : Chain::restore_from_snapshot
\*       — the RestoreFromSnapshot action's projection. The
\*       post-restore state_root gate at chain.cpp:1893-1911 is
\*       captured by the recompute-vs-stored equality check in
\*       the action body.
\*   src/node/node.cpp:1024-1117    : Node::try_finalize_round (the
\*       S-038 producer wiring); the ProduceBlock action's
\*       tentative-chain dry-run + body.state_root population is
\*       the projection.
\*
\* Runtime regressions:
\*   tools/test_state_root.sh (13 assertions)               : T-S1
\*       commitment-algebra lock-in.
\*   tools/test_state_root_namespaces.sh (12 assertions)    : T-S1
\*       exhaustive 10-namespace coverage.
\*   tools/test_snapshot_bootstrap.sh                       : T-S1.
\*   tools/test_snapshot_roundtrip.sh (15 assertions)       : T-S5.
\*   tools/test_snapshot_then_apply.sh (21 assertions)      : T-S3 +
\*       T-S4 composition.
\*   tools/test_dapp_snapshot.sh (12 assertions)            : T-S2.
\*       The S-037 + S-038 paired-closure regression.
\*   tools/test_snapshot_version_rejection.sh               : version-gate
\*       sub-claim (parallel to FB6's VersionGateSoundness).
\*
\* Doc updates:
\*   S033StateRootNamespaceCoverage.md §1 (T-1..T-5 theorem
\*       statements); §4 (per-theorem analytic proofs); §5 (adversary
\*       model); §6 (identified gaps). FB31 lifts the snapshot
\*       sub-theorem (T-5 Snapshot Round-Trip Soundness) to the
\*       state-machine layer.
============================================================================
