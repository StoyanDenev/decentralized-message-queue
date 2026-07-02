--------------------------- MODULE SnapshotIntegrity ---------------------------
(*
FB31 — TLA+ specification of the post-S-037 / post-S-038 snapshot
integrity surface: the S-033 state_root commitment, the S-037
namespace closure (dapp_registry in serialize/restore), and the
S-038 producer-side state_root wiring, composed at the
restore-from-snapshot boundary.

REDESIGN (2026-07-02). The original FB31 was quarantined: replacing
the untyped <<"no_snapshot">> tuple sentinel with the house typed
sentinel (same-shape record with an impossible field, per FB14 /
AppliedReceiptRestore.tla) unmasked three pre-existing modeling
bugs. This redesign fixes them structurally:

  (1) PROVENANCE, not proxies. The old round-trip and gate
      invariants used the coincidence-matchable antecedent
      "live_chain[n2] = snapshot_blob.tail_chain /\
      ~restore_throws[n2]" as a stand-in for "n2 restored from this
      blob". A ghost variable `restored_from[n]` now records the
      exact snapshot value a node last successfully restored from,
      while the node still sits at that restore point (set ONLY by
      RestoreFromSnapshot's accept branch; cleared on departure —
      block append or live tamper). Both invariants key on it.
  (2) LIVE-TAMPER FLAG. TamperLiveState followed by a block append
      legitimately diverges a node's state from pure replay (the
      producer dry-runs ITS OWN state — chain.cpp comment at the
      S-033 gate: a corrupted-state node is outside the honest-node
      claim). A latched `tampered_live[n]` flag excludes such nodes;
      INV_ProducerSelfApplyConsistentPostS038 is restated over
      honest runs. The flag latches forever because a self-consistent
      snapshot from a corrupted producer PASSES the C++ restore gate
      (committee signatures, not the gate, are the production
      defense — out of scope here), so corruption can propagate
      through an honest restore.
  (3) TWO-CHECK GATE. The old RestoreFromSnapshot accepted on a
      single serialized-state recompute, so a chain-site tamper was
      silently accepted. The C++ gate performs TWO checks and the
      action now models both:
        check 1 — head-hash recompute (chain.cpp:1868-1877): the
          restored head block's compute_hash() must equal the
          snapshot's stored head_hash claim. compute_hash covers the
          full signing bytes (index, state_root, txs), so a tamper
          of the head block is caught.
        check 2 — state_root recompute (chain.cpp:1908-1926): the
          recomputed state root over the restored namespaces must
          equal the head block's declared state_root. A tamper of
          any serialized namespace (incl. dapp_registry, the S-037
          surface) is caught.

Model shape. Two symmetric nodes plus ONE published-snapshot
channel: `snapshot_blob` is the latest snapshot value published by
any node (C++ snapshots live in operator files and
SNAPSHOT_RESPONSE gossip — a value store, not per-node registers;
no claim ever compares two nodes' blobs, and per-node registers
only square the state space). Any node may publish; the adversary
may tamper the channel at rest; any node may restore from it —
self-restore included, matching the C++ bootstrap-from-own-file
path.

Deleted claims / machinery (KISS: recorded rationale, no re-add
without a code claim to back it):

  * tampered_at site-marker variable — DELETED. A tamper marker can
    drift from blob reality (tamper A->B->A restores the original
    bytes but leaves the marker latched), the recurring
    typed-sentinel/bookkeeping spec-bug class. Detection is now
    stated semantically: GateConsistent(blob) is what the gate
    accepts, and INV_StateRootGateFiresOnRestoreTamper asserts only
    gate-consistent blobs are ever installed. TamperSnapshot always
    breaks GateConsistent (abstract-hash injectivity), so every
    modeled tamper is un-restorable.
  * Separate ProduceBlock action — MERGED into AppendBlock. The
    S-038 producer path (declared root := tentative-chain dry-run
    over the node's own state, node.cpp:1024-1117) and the S-033
    receiver gate (chain.cpp:1421-1446) generate the same accept
    successors; AppendBlock models both: the accept branch IS the
    producer wiring (every appended block carries the recomputed
    post-apply root), the reject branch IS the apply-time gate.
  * Zero-root backward-compat shim (chain.cpp:1910-1911 zero-skip)
    — OUT OF SCOPE. This spec models the post-S-038 universe only:
    every block carries a non-zero state_root. Modeling the legacy
    zero-root accept path would make restored-from-unverifiable-
    snapshot states indistinguishable from honest ones without
    taint-tracking machinery; the shim is a documented accept-path,
    not a detection claim.
  * Interior-tail-chain tamper branch — RESTATED to the head block
    only. Chain::restore_from_snapshot binds ONLY the head: the
    head_hash claim (1868-1877) and the head's declared state_root
    (1908-1926). Interior headers are metadata here; interior
    linkage/tamper detection is the chain.json wrap + gossip
    continuity surface (FB26 BlockchainStateIntegrity.tla).
    Modeling interior-tamper detection at THIS gate would assert a
    check the code does not perform.
  * PROP_TamperingDetected — DELETED. The old form evaluated its
    antecedent at the initial state (vacuously true); the honest
    leads-to form is FALSE in both model and code (a tampered blob
    overwritten by a fresh SerializeSnapshot before any restore is
    never observed, so no throw ever fires). The safety invariant
    INV_StateRootGateFiresOnRestoreTamper carries the actual code
    claim: a tampered blob can never be INSTALLED.
  * Snapshot head_state_root field — DELETED. The C++ snapshot has
    no separate state-root field; the gate compares against the
    head BLOCK's declared state_root (chain.cpp:1909). The snapshot
    record now carries head_hash (the C++ "head_hash" JSON claim,
    chain.cpp:1546-1548) instead.
  * Snapshot version gate (chain.cpp:1711-1717) — out of scope;
    covered by FB6 Snapshot.tla Inv_VersionGateSoundness +
    tools/test_snapshot_version_rejection.sh.

Theorem census (T-S1..T-S5 of the original, all kept, restated):

  T-S1/T-S2 (namespace round-trip incl. S-037 d: closure)
      INV_SnapshotRoundTripPreservesAllNamespaces — a node sitting
      at its restore point has live_state equal to the provenance
      blob's serialized_state across all four modeled namespaces.
      INV_DAppRegistryRoundtrips — the dapp_registry field alone;
      standalone so an S-037-class regression (d: dropped from
      serialize/restore) fails at single-invariant granularity.
  T-S3 (S-038 producer wiring)
      INV_ProducerSelfApplyConsistentPostS038 — in honest runs (no
      TamperLiveState anywhere), every block's state_root equals
      the pure replay of its prefix.
  T-S4 (tamper detection at the snapshot boundary)
      INV_StateRootGateFiresOnRestoreTamper — everything installed
      passed the two-check gate; tampered blobs (head-block or
      namespace site) never install, the attempt latches
      restore_throws.
      INV_NoSilentDivergence — untampered same-chain nodes cannot
      hold different state roots unless a throw-gate latched
      (FB26's sibling, snapshot pathway).
  T-S5 (restore determinism)
      INV_RestoreDeterminism — equal provenance blobs at the
      restore point imply equal live_state.

Abstraction notes:
  * State collapses the 10 state_root namespaces to the four
    mutable maps [accounts, stakes, registrants, dapp_registry],
    each a SUBSET of an opaque Slots universe; the remaining six
    (i:/b:/m:/p:/k:/c:) project into the same abstraction. Full
    ten-namespace coverage is the analytic companion
    S033StateRootNamespaceCoverage.md.
  * state_root_of / signing_hash are injective tagged tuples — the
    spec-layer projection of A2 (SHA-256 collision resistance,
    Preliminaries §2.1). The adversary cannot re-sign: TamperSnapshot
    mutates contents but never patches the head_hash claim or the
    head block's declared state_root.
  * apply is the deterministic FA-Apply-1 transition; per-tx
    semantics collapse to set-union of the block's txs payload into
    every namespace.

C++ enforcement (exoneration references — the code is ground truth):
  * chain.cpp:1711-1717  restore version gate (out of scope, FB6).
  * chain.cpp:1830-1849  namespace restore incl. dapp_registry
                         (S-037 closure) — RestoreFromSnapshot's
                         accept branch installs every namespace.
  * chain.cpp:1868-1877  head_hash recompute — gate check 1.
  * chain.cpp:1908-1926  state_root recompute gate — gate check 2.
  * chain.cpp:1541-1701  serialize_state — SerializeSnapshot.
  * node.cpp:1024-1117   S-038 tentative-chain dry-run —
                         AppendBlock's accept branch.
Runtime witness: tools/test_dapp_snapshot.sh (12/12) plus
test_snapshot_roundtrip.sh / test_snapshot_then_apply.sh /
test_state_root_namespaces.sh.

To check: bash tools/test_tla_model_check.sh --only SnapshotIntegrity
(or: tlc -deadlock -config SnapshotIntegrity.cfg SnapshotIntegrity.tla)
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes,              \* finite universe of node IDs (2 symmetric nodes)
    MaxHeight,          \* spec-time bound on chain length
    Slots               \* finite universe of state slot identifiers

ASSUME ConfigOK ==
    /\ Cardinality(Nodes) >= 2
    /\ MaxHeight \in Nat /\ MaxHeight >= 1
    /\ Cardinality(Slots) >= 1

\* -----------------------------------------------------------------
\* §1. State, roots, blocks, hashes.
\* -----------------------------------------------------------------

\* The four mutable namespace maps (a:/s:/r:/d: projection).
State == [accounts:       SUBSET Slots,
          stakes:         SUBSET Slots,
          registrants:    SUBSET Slots,
          dapp_registry:  SUBSET Slots]

EmptyState == [accounts      |-> {},
               stakes        |-> {},
               registrants   |-> {},
               dapp_registry |-> {}]

\* compute_state_root, abstract-hash form: injective by tuple
\* equality (A2 projection). Zero roots are out of scope (see
\* header: post-S-038 universe only).
state_root_of(s) ==
    <<"ROOT", s.accounts, s.stakes, s.registrants, s.dapp_registry>>

RootUniverse ==
    { <<"ROOT", a, st, r, d>> :
        a  \in SUBSET Slots,
        st \in SUBSET Slots,
        r  \in SUBSET Slots,
        d  \in SUBSET Slots }

\* Block: index, declared state_root, txs payload. prev_hash is not
\* modeled — no restore-gate check consults it (linkage is FB26
\* territory).
Block == [
    index      : 0..MaxHeight,
    state_root : RootUniverse,
    txs        : SUBSET Slots
]

\* Block::compute_hash over the full signing bytes — covers the
\* declared state_root and the txs payload, so any head-block tamper
\* changes the hash (abstract-hash injectivity).
signing_hash(b) == <<"BHASH", b.index, b.state_root, b.txs>>

\* apply: FA-Apply-1 deterministic transition; every namespace
\* accumulates the block's txs payload by union.
apply(s, txs) ==
    [accounts      |-> s.accounts      \cup txs,
     stakes        |-> s.stakes        \cup txs,
     registrants   |-> s.registrants   \cup txs,
     dapp_registry |-> s.dapp_registry \cup txs]

\* replay(c): pure chain replay from genesis.
RECURSIVE replay_(_, _)
replay_(c, i) ==
    IF i = 0 THEN EmptyState ELSE apply(replay_(c, i - 1), c[i].txs)
replay(c) == replay_(c, Len(c))

HeadOf(c) == c[Len(c)]

\* -----------------------------------------------------------------
\* §2. Snapshot shape, typed sentinel, the two-check gate.
\* -----------------------------------------------------------------

\* Snapshot record: the tail chain, the serialized namespace maps,
\* and the head_hash claim (chain.cpp:1546-1548).
\* Typed sentinel (house pattern, per FB14 / AppliedReceiptRestore):
\* a record of the same field set carrying an impossible value —
\* every real snapshot has Len(tail_chain) >= 1 (SerializeSnapshot
\* guard; tampering preserves length) and a "BHASH" head_hash, so no
\* action can ever produce this value.
NoSnapshot == [tail_chain        |-> <<>>,
               serialized_state  |-> EmptyState,
               head_hash         |-> <<"BHASH_NONE">>]

\* Alias for the restored_from ghost variable's empty value.
NoBlob == NoSnapshot

\* The two-check acceptance gate of Chain::restore_from_snapshot.
\*   check 1 (chain.cpp:1868-1877): recomputed head-block hash
\*     equals the snapshot's stored head_hash claim.
\*   check 2 (chain.cpp:1908-1926): recomputed state root over the
\*     restored namespaces equals the head block's declared
\*     state_root.
\* Only call on a non-sentinel snapshot (guarded at all use sites).
GateConsistent(s) ==
    /\ signing_hash(HeadOf(s.tail_chain)) = s.head_hash
    /\ state_root_of(s.serialized_state) = HeadOf(s.tail_chain).state_root

\* -----------------------------------------------------------------
\* §3. Variables.
\* -----------------------------------------------------------------

VARIABLES
    live_chain,         \* Nodes -> Seq(Block)
    live_state,         \* Nodes -> State
    snapshot_blob,      \* the published-snapshot channel: latest
                        \*   snapshot value published by any node
                        \*   (NoSnapshot = none yet). Attacker-mutable
                        \*   at rest (TamperSnapshot).
    restored_from,      \* Nodes -> Snapshot GHOST: the blob a node
                        \*   last successfully restored from, while the
                        \*   node still SITS AT that restore point
                        \*   (NoBlob = never restored / departed). Set
                        \*   ONLY by RestoreFromSnapshot's accept
                        \*   branch; cleared back to NoBlob when the
                        \*   node departs the restored state (block
                        \*   append or live-state tamper). Every
                        \*   invariant consumes provenance only at the
                        \*   restore point, so clearing on departure
                        \*   loses no claim coverage and prunes the
                        \*   provenance x evolution cross-product that
                        \*   otherwise dominates the state space.
                        \*   Never attacker-mutable.
    apply_throws,       \* Nodes -> BOOLEAN, latches on apply-gate mismatch
    restore_throws,     \* Nodes -> BOOLEAN, latches on restore-gate mismatch
    tampered_live       \* Nodes -> BOOLEAN GHOST: latches forever on
                        \*   TamperLiveState (corruption can propagate
                        \*   through a gate-passing restore, so the
                        \*   flag must not reset — see header note 2).

vars == <<live_chain, live_state, snapshot_blob, restored_from,
          apply_throws, restore_throws, tampered_live>>

Init ==
    /\ live_chain     = [n \in Nodes |-> <<>>]
    /\ live_state     = [n \in Nodes |-> EmptyState]
    /\ snapshot_blob  = NoSnapshot
    /\ restored_from  = [n \in Nodes |-> NoBlob]
    /\ apply_throws   = [n \in Nodes |-> FALSE]
    /\ restore_throws = [n \in Nodes |-> FALSE]
    /\ tampered_live  = [n \in Nodes |-> FALSE]

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* AppendBlock(n) — block production AND the S-033 apply-time gate
\* in one action (header: "Separate ProduceBlock action — MERGED"):
\*   accept branch = the S-038 producer path (node.cpp:1024-1117):
\*     the tentative-chain dry-run recomputes the post-apply root
\*     and the appended block carries exactly that declared root;
\*   reject branch = the S-033 receiver gate (chain.cpp:1421-1446):
\*     a declared root that mismatches the recomputed post-apply
\*     root latches apply_throws, nothing is appended.
\* The declared root ranges over the gate's two equivalence classes
\* — matching and non-matching — instead of all of RootUniverse:
\* the gate predicate distinguishes nothing finer, and every
\* non-matching choice yields the identical throw-latch successor
\* (state-space collapse, no claim lost). WrongRoot flips the
\* accounts namespace to its complement, so it always differs.
WrongRoot(post) ==
    state_root_of([post EXCEPT !.accounts = Slots \ post.accounts])

AppendBlock(n) ==
    /\ Len(live_chain[n]) < MaxHeight
    /\ \E txs \in SUBSET Slots :
       \E declared \in {state_root_of(apply(live_state[n], txs)),
                        WrongRoot(apply(live_state[n], txs))} :
       LET post == apply(live_state[n], txs) IN
       IF declared = state_root_of(post)
       THEN /\ live_chain' = [live_chain EXCEPT ![n] =
                   Append(@, [index      |-> Len(live_chain[n]),
                              state_root |-> declared,
                              txs        |-> txs])]
            /\ live_state' = [live_state EXCEPT ![n] = post]
            /\ restored_from' = [restored_from EXCEPT ![n] = NoBlob]  \* departs restore point
            /\ UNCHANGED <<snapshot_blob, apply_throws,
                           restore_throws, tampered_live>>
       ELSE /\ apply_throws' = [apply_throws EXCEPT ![n] = TRUE]
            /\ UNCHANGED <<live_chain, live_state, snapshot_blob,
                           restored_from, restore_throws, tampered_live>>

\* SerializeSnapshot(n) — Chain::serialize_state (chain.cpp:
\* 1541-1701): all four namespace maps (S-037: dapp_registry
\* included) + the head_hash claim, published to the channel.
\* Overwrites any previous publication.
SerializeSnapshot(n) ==
    /\ Len(live_chain[n]) > 0
    /\ snapshot_blob' =
           [tail_chain        |-> live_chain[n],
            serialized_state  |-> live_state[n],
            head_hash         |-> signing_hash(HeadOf(live_chain[n]))]
    /\ UNCHANGED <<live_chain, live_state, restored_from,
                   apply_throws, restore_throws, tampered_live>>

\* RestoreFromSnapshot(n) — Chain::restore_from_snapshot
\* (chain.cpp:1711-1948) consuming the published channel (file or
\* SNAPSHOT_RESPONSE gossip; self-restore is the C++ bootstrap-from-
\* own-file path, so no source-node restriction).
\* Accept: two-check gate passes -> install chain + all namespaces
\* (1830-1849) and record provenance. Reject: latch restore_throws;
\* nothing is installed.
RestoreFromSnapshot(n) ==
    /\ snapshot_blob /= NoSnapshot
    /\ IF GateConsistent(snapshot_blob)
       THEN /\ live_chain'    = [live_chain    EXCEPT ![n] = snapshot_blob.tail_chain]
            /\ live_state'    = [live_state    EXCEPT ![n] = snapshot_blob.serialized_state]
            /\ restored_from' = [restored_from EXCEPT ![n] = snapshot_blob]
            /\ UNCHANGED <<snapshot_blob, apply_throws,
                           restore_throws, tampered_live>>
       ELSE /\ restore_throws' = [restore_throws EXCEPT ![n] = TRUE]
            /\ UNCHANGED <<live_chain, live_state, snapshot_blob,
                           restored_from, apply_throws, tampered_live>>

\* TamperSnapshot — adversary mutates the published blob at one of
\* three sites, WITHOUT re-signing (the head_hash claim and the head
\* block's declared state_root are never patched — A2/EUF-CMA out of
\* band):
\*   (a) head-block txs (the site this gate binds; interior headers
\*       are FB26 territory — header),
\*   (b) the accounts namespace,
\*   (c) the dapp_registry namespace (the S-037 closure surface).
\* Every branch breaks GateConsistent by abstract-hash injectivity.
\* Guarded on the blob still being pristine (GateConsistent):
\* composing further tampers on an already-inconsistent blob either
\* keeps it inconsistent (the same un-installable detection class a
\* single tamper already exhibits) or restores the exact pristine
\* bytes (= a value the pristine branch already explores), so the
\* guard prunes the composed-tamper product per publication without
\* losing any distinguishable gate behavior.
TamperSnapshot ==
    /\ snapshot_blob /= NoSnapshot
    /\ GateConsistent(snapshot_blob)
    /\ LET snap == snapshot_blob IN
       \E new_contents \in SUBSET Slots :
          \/ /\ new_contents /= HeadOf(snap.tail_chain).txs
             /\ snapshot_blob' =
                    [snap EXCEPT !.tail_chain[Len(snap.tail_chain)] =
                        [HeadOf(snap.tail_chain) EXCEPT !.txs = new_contents]]
          \/ /\ new_contents /= snap.serialized_state.accounts
             /\ snapshot_blob' =
                    [snap EXCEPT !.serialized_state.accounts = new_contents]
          \/ /\ new_contents /= snap.serialized_state.dapp_registry
             /\ snapshot_blob' =
                    [snap EXCEPT !.serialized_state.dapp_registry = new_contents]
    /\ UNCHANGED <<live_chain, live_state, restored_from,
                   apply_throws, restore_throws, tampered_live>>

\* TamperLiveState(n) — at-rest corruption of a node's live state.
\* Latches tampered_live[n]; a subsequent AppendBlock legitimately
\* diverges this node (and, via a self-consistent snapshot, its
\* restorers) from pure replay — hence the honest-run antecedent on
\* INV_ProducerSelfApplyConsistentPostS038. Guarded to once per node
\* per run: after the flag latches, every kept claim already
\* excludes the node (honest-run antecedents) or reasons about the
\* corrupt lineage semantically (gate checks), so repeat tampers
\* multiply the state space without new claim coverage.
TamperLiveState(n) ==
    /\ ~tampered_live[n]
    /\ \E new_contents \in SUBSET Slots :
       /\ new_contents /= live_state[n].accounts
       /\ live_state'    = [live_state EXCEPT ![n].accounts = new_contents]
       /\ tampered_live' = [tampered_live EXCEPT ![n] = TRUE]
       /\ restored_from' = [restored_from EXCEPT ![n] = NoBlob]  \* departs restore point
       /\ UNCHANGED <<live_chain, snapshot_blob,
                      apply_throws, restore_throws>>

Next ==
    \/ \E n \in Nodes :
          \/ AppendBlock(n)
          \/ SerializeSnapshot(n)
          \/ RestoreFromSnapshot(n)
          \/ TamperLiveState(n)
    \/ TamperSnapshot

\* Fairness: WF(AppendBlock) bootstraps chain growth from genesis;
\* WF(Serialize) then forces a publication — together they carry
\* PROP_EventualSnapshotSuccess. No other property needs fairness.
Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E n \in Nodes : AppendBlock(n))
             /\ WF_vars(\E n \in Nodes : SerializeSnapshot(n))

\* -----------------------------------------------------------------
\* §5. Type invariant.
\* -----------------------------------------------------------------

SnapshotOK(s) ==
    \/ s = NoSnapshot
    \/ /\ DOMAIN s = {"tail_chain", "serialized_state", "head_hash"}
       /\ s.tail_chain \in Seq(Block)
       /\ Len(s.tail_chain) >= 1
       /\ s.serialized_state \in State
       /\ s.head_hash[1] = "BHASH"

TypeOK ==
    /\ live_chain     \in [Nodes -> Seq(Block)]
    /\ live_state     \in [Nodes -> State]
    /\ SnapshotOK(snapshot_blob)
    /\ \A n \in Nodes : SnapshotOK(restored_from[n])
    /\ apply_throws   \in [Nodes -> BOOLEAN]
    /\ restore_throws \in [Nodes -> BOOLEAN]
    /\ tampered_live  \in [Nodes -> BOOLEAN]

\* -----------------------------------------------------------------
\* §6. Invariants (T-S1..T-S5).
\* -----------------------------------------------------------------

\* AtRestorePoint(n): n restored and has not departed the restore
\* point since — no block append and no live tamper, both of which
\* clear the provenance ghost back to NoBlob. (A restore after a
\* live tamper wholesale-replaces live_chain + live_state, so the
\* re-opened provenance window is again a pure image of the blob.)
AtRestorePoint(n) == restored_from[n] /= NoBlob

\* T-S1 + T-S2 composed: at the restore point, live_state equals the
\* provenance blob's serialized_state across all four namespaces
\* (accounts / stakes / registrants / dapp_registry — record
\* equality). The S-037 closure witness: drop any namespace from the
\* modeled restore install and this fails.
INV_SnapshotRoundTripPreservesAllNamespaces ==
    \A n \in Nodes :
       AtRestorePoint(n) => live_state[n] = restored_from[n].serialized_state

\* T-S2 standalone: dapp_registry alone, so an S-037-class
\* regression fails at single-invariant granularity.
INV_DAppRegistryRoundtrips ==
    \A n \in Nodes :
       AtRestorePoint(n) =>
          live_state[n].dapp_registry =
              restored_from[n].serialized_state.dapp_registry

\* T-S4: everything ever installed passed the two-check gate — a
\* blob whose head block or namespaces were tampered (and not
\* re-signed) is GateConsistent-breaking, hence un-installable; the
\* attempt latches restore_throws instead. Non-vacuity probe:
\* accepting unconditionally in RestoreFromSnapshot makes TLC fail
\* this invariant on a TamperSnapshot->Restore trace.
INV_StateRootGateFiresOnRestoreTamper ==
    \A n \in Nodes :
       AtRestorePoint(n) => GateConsistent(restored_from[n])

\* T-S3 (S-038): in honest runs — no live-state corruption anywhere,
\* ever — every block's declared state_root equals the pure replay
\* of its prefix. Global antecedent because a corrupted producer's
\* self-consistent snapshot passes the gate (header note 2): the
\* honest-node claim is exactly what node.cpp:1024-1117 provides.
INV_ProducerSelfApplyConsistentPostS038 ==
    (\A m \in Nodes : ~tampered_live[m]) =>
       \A n \in Nodes :
          \A i \in 1..Len(live_chain[n]) :
             live_chain[n][i].state_root =
                 state_root_of(replay(SubSeq(live_chain[n], 1, i)))

\* T-S5: equal provenance blobs at the restore point imply equal
\* live state — restore is a pure function of the snapshot value.
INV_RestoreDeterminism ==
    \A n1, n2 \in Nodes :
       (/\ AtRestorePoint(n1)
        /\ AtRestorePoint(n2)
        /\ restored_from[n1] = restored_from[n2])
       => live_state[n1] = live_state[n2]

\* T-S4 cross-node form (FB26 sibling): two untampered nodes on the
\* same non-empty chain cannot hold different state roots unless a
\* throw-gate latched. Holds structurally because the head block's
\* state_root pins the state of every gate-passing path; the
\* non-vacuity probe (gate removed) violates it.
INV_NoSilentDivergence ==
    \A n1, n2 \in Nodes :
       (/\ n1 /= n2
        /\ ~tampered_live[n1] /\ ~tampered_live[n2]
        /\ live_chain[n1] = live_chain[n2]
        /\ live_chain[n1] /= <<>>
        /\ state_root_of(live_state[n1]) /= state_root_of(live_state[n2]))
       => (apply_throws[n1] \/ apply_throws[n2]
            \/ restore_throws[n1] \/ restore_throws[n2])

\* -----------------------------------------------------------------
\* §7. Temporal property.
\* -----------------------------------------------------------------

\* Under the declared fairness, the snapshot subsystem is not
\* permanently starved (sanity liveness: the modeled pipeline runs).
PROP_EventualSnapshotSuccess ==
    <>(snapshot_blob /= NoSnapshot)

============================================================================
\* Cross-references.
\*
\* FA-Snapshot (S033StateRootNamespaceCoverage.md):
\*   T-S1/T-S2 : INV_SnapshotRoundTripPreservesAllNamespaces +
\*               INV_DAppRegistryRoundtrips
\*   T-S3      : INV_ProducerSelfApplyConsistentPostS038
\*   T-S4      : INV_StateRootGateFiresOnRestoreTamper +
\*               INV_NoSilentDivergence
\*   T-S5      : INV_RestoreDeterminism
\* AppliedReceiptRestore.md FA-Apply-12 : the i: namespace's
\*   standalone lifecycle (FB17); projected into the SUBSET-of-Slots
\*   abstraction here.
\* BlockchainStateIntegrity.md / FB26 : chain.json wrap + apply-time
\*   gate; owns interior-header linkage (out of scope here).
\* FB6 Snapshot.tla : basic snapshot/restore SM + version gate.
\* FB5 AccountState.tla FA-Apply-1 : apply determinism.
\* SECURITY.md §S-033 §S-037 §S-038 : closure narratives.
\* Preliminaries.md §2.1 A2 : abstract-hash injectivity discipline.
\*
\* Runtime regressions: tools/test_dapp_snapshot.sh (12/12, the
\* S-037+S-038 paired closure), test_snapshot_roundtrip.sh,
\* test_snapshot_then_apply.sh, test_state_root.sh,
\* test_state_root_namespaces.sh, test_snapshot_version_rejection.sh.
============================================================================
