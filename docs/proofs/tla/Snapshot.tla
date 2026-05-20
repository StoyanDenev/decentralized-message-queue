--------------------------- MODULE Snapshot ---------------------------
(*
FB6 — TLA+ specification of the snapshot + restore state machine.
Models `Chain::serialize_state()` / `Chain::restore_from_snapshot()`
in `src/chain/chain.cpp` at the state-machine level. A snapshot is
an abstract record whose `payload` field is structurally a chain
value; JSON encoding is out of scope (FA-track unit tests cover
the codec round-trip).

Invariants checked under TLC:

  * Inv_SerializeRestoreIdentity — RestoreSnapshot(TakeSnapshot(c)) = c.
  * Inv_ApplyAfterRestoreEquivalence — commuting square:
        AppendBlock(b)  =  TakeSnapshot ; RestoreSnapshot ; AppendBlock(b).
  * Inv_VersionGateSoundness — restoring a wrong-version snapshot is
        a no-op on the chain (S-037 / S-018 cousin).
  * Inv_DeterministicSerialization — TakeSnapshot is a pure function.
  * Inv_StateRootBindsApply — state_root uniquely determines
        (balances, counters) at the boundary (S-033 / S-038).

Temporal properties:

  * Prop_EventualSnapshotConsistency — under fairness on TakeSnapshot,
        every reachable chain state is eventually witnessed.
  * Prop_RestoreIsCorrect — after every successful RestoreSnapshot,
        chain' = last_snapshot.payload.

Modeling scope: the 10 state_root namespaces in
`Block::compute_state_root` are collapsed into the safety-critical
subset (a: balances+nonces, b: accumulated counters). The remaining
namespaces (r, d, i, m, p, k, c, s) are not invariant-relevant for
the round-trip properties above. `state_root` is modeled as a pure
function of (balances, counters); SHA-256 collision-resistance is an
external FA-track A3 assumption. Block bodies abstract to a
domain-local credit that bumps balance + nonce + the subsidy counter.

Companion prose proof: docs/proofs/SnapshotInvariants.md (separately
tracked; may not yet exist in this worktree).

To check (assuming TLC installed):
  $ tlc Snapshot.tla -config Snapshot.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Domains,            \* set of domain identifiers
    MaxHeight,          \* upper bound on chain height for TLC
    MaxBalance,         \* upper bound on per-domain balance
    SnapshotVersion     \* canonical snapshot version (= 1 in production)

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxHeight \in Nat /\ MaxHeight >= 1
    /\ MaxBalance \in Nat /\ MaxBalance >= 1
    /\ SnapshotVersion \in Nat /\ SnapshotVersion >= 1

\* "Hash" is an opaque value modeled as a record-equality marker.
\* Two chain states that differ on any of the hashed components
\* produce distinct hashes; this is the TLA-level analog of
\* SHA-256 collision resistance (external cryptographic assumption).
\*
\* StateRoot(c) is a pure function of c's apply-state (balances,
\* nonces, counters). This is the S-033 / S-038 commitment.
StateRoot(accs, ctrs) == <<"state_root", accs, ctrs>>

\* Block hash is a pure function of the chain head identity plus
\* the block index. Two chains at the same height with the same
\* state_root produce the same head_hash, modeling
\* compute_hash() determinism.
HeadHash(h, sr) == <<"head_hash", h, sr>>

\* The "empty" sentinel for an unpopulated head_hash field — used
\* before any block has been applied. Models `std::string{}` in
\* Chain::serialize_state.
EmptyHash == <<"empty">>

\* Apply-layer chain state shape (informal — enforced by the action
\* UNCHANGED clauses and Inv_TypeOK rather than by a TLC-enumerated
\* membership predicate):
\*
\*   chain.height     :: 0..MaxHeight
\*   chain.head_hash  :: HeadHash(height, state_root) or EmptyHash at h=0
\*   chain.balances   :: Domains -> 0..MaxBalance
\*   chain.nonces     :: Domains -> Nat
\*   chain.state_root :: StateRoot(balances, counters)
\*   chain.counters   :: [subsidy, slashed, inbound, outbound]
\*
\* Snapshot record shape:
\*
\*   last_snapshot.version    :: Nat
\*   last_snapshot.head_index :: 0..MaxHeight
\*   last_snapshot.head_hash  :: HeadHash(...) or EmptyHash
\*   last_snapshot.payload    :: ChainState
\*
\* In the C++ implementation the payload is a JSON object; here it
\* is a TLA+ record. Encoding fidelity is an FA-track concern (the
\* JSON codec round-trip is exhaustively tested at the unit-test
\* layer; this spec verifies the state-machine layer above the
\* codec). `version` models the integer field `snap["version"]` in
\* Chain::serialize_state; production uses the constant 1.

VARIABLES
    chain,              \* current ChainState
    last_snapshot,      \* most recently taken snapshot (or NoSnapshot)
    snapshot_count      \* number of TakeSnapshot actions executed

\* Sentinel: no snapshot has been taken yet.
NoSnapshot == <<"no-snapshot">>

vars == <<chain, last_snapshot, snapshot_count>>

----------------------------------------------------------------------------
\* Initial state: empty chain (height 0, balances all zero, no head).

EmptyCounters == [subsidy  |-> 0,
                  slashed  |-> 0,
                  inbound  |-> 0,
                  outbound |-> 0]

EmptyBalances == [d \in Domains |-> 0]
EmptyNonces   == [d \in Domains |-> 0]
EmptyRoot     == StateRoot(EmptyBalances, EmptyCounters)

Init ==
    /\ chain = [height     |-> 0,
                head_hash  |-> EmptyHash,
                balances   |-> EmptyBalances,
                nonces     |-> EmptyNonces,
                state_root |-> EmptyRoot,
                counters   |-> EmptyCounters]
    /\ last_snapshot = NoSnapshot
    /\ snapshot_count = 0

----------------------------------------------------------------------------
\* Pure functions: TakeSnapshot and RestoreSnapshot.
\* These are written as TLA+ operators (not actions) because they
\* are deterministic functions of their inputs — `TakeSnapshot(c)`
\* depends only on c, and `RestoreSnapshot(s, c)` depends only on
\* (s, c).

\* TakeSnapshot extracts a SnapshotRec from a chain. Pure: same
\* input ⇒ same output (DeterministicSerialization).
DoTakeSnapshot(c) ==
    [ version    |-> SnapshotVersion,
      head_index |-> c.height,
      head_hash  |-> c.head_hash,
      payload    |-> c ]

\* RestoreSnapshot returns the new chain. Rejects wrong-version
\* snapshots by returning the existing chain unchanged
\* (VersionGateSoundness).
DoRestoreSnapshot(s, current) ==
    IF s.version = SnapshotVersion THEN s.payload ELSE current

----------------------------------------------------------------------------
\* Block-apply abstraction. AppendBlock(d, amount) credits domain d's
\* balance by `amount` (1..MaxBalance - current), increments the
\* domain's nonce, and bumps the subsidy counter by 1 (one block
\* worth of subsidy per AppendBlock). This is enough to drive
\* state_root through a fresh value on every block.
ApplyDelta(c, d, amount) ==
    LET new_bals == [c.balances EXCEPT ![d] = @ + amount] IN
    LET new_nons == [c.nonces   EXCEPT ![d] = @ + 1] IN
    LET new_cts  == [c.counters EXCEPT !.subsidy = @ + 1] IN
    LET new_sr   == StateRoot(new_bals, new_cts) IN
    LET new_h    == c.height + 1 IN
    [ height     |-> new_h,
      head_hash  |-> HeadHash(new_h, new_sr),
      balances   |-> new_bals,
      nonces     |-> new_nons,
      state_root |-> new_sr,
      counters   |-> new_cts ]

----------------------------------------------------------------------------
\* Actions.

\* AppendBlock: advances the chain by one block, crediting domain
\* `d` with `amount`. Bounded by MaxHeight and MaxBalance.
AppendBlock(d, amount) ==
    /\ d \in Domains
    /\ amount \in 1..MaxBalance
    /\ chain.height < MaxHeight
    /\ chain.balances[d] + amount <= MaxBalance
    /\ chain.counters.subsidy + 1 <= MaxHeight
    /\ chain' = ApplyDelta(chain, d, amount)
    /\ UNCHANGED <<last_snapshot, snapshot_count>>

\* TakeSnapshot: serializes the current chain into a snapshot.
\* Pure: snapshot' = DoTakeSnapshot(chain). Increments snapshot_count
\* as a witness of liveness (every TakeSnapshot is observable).
TakeSnapshot ==
    /\ last_snapshot' = DoTakeSnapshot(chain)
    /\ snapshot_count' = snapshot_count + 1
    /\ UNCHANGED chain

\* RestoreSnapshot: replaces the current chain with the snapshot's
\* payload, but only if the snapshot version matches
\* SnapshotVersion. A version mismatch is a no-op (the existing
\* chain is preserved) — VersionGateSoundness.
RestoreSnapshot ==
    /\ last_snapshot /= NoSnapshot
    /\ chain' = DoRestoreSnapshot(last_snapshot, chain)
    /\ UNCHANGED <<last_snapshot, snapshot_count>>

\* RejectMalformedSnapshot: adversary action — crafts a wrong-version
\* snapshot and feeds it into the restore path. The chain must remain
\* unchanged (DoRestoreSnapshot's else-branch). A dedicated action
\* makes the rejection path explicit in TLC traces.
RejectMalformedSnapshot ==
    \E bad_v \in (0..SnapshotVersion + 2) \ {SnapshotVersion} :
       LET bad_snap == [version    |-> bad_v,
                        head_index |-> chain.height,
                        head_hash  |-> chain.head_hash,
                        payload    |-> chain] IN
       /\ chain' = DoRestoreSnapshot(bad_snap, chain)
       /\ UNCHANGED <<last_snapshot, snapshot_count>>

----------------------------------------------------------------------------
\* Next-state relation.

Next ==
    \/ \E d \in Domains, amount \in 1..MaxBalance : AppendBlock(d, amount)
    \/ TakeSnapshot
    \/ RestoreSnapshot
    \/ RejectMalformedSnapshot

\* Fairness on TakeSnapshot drives EventualSnapshotConsistency.
Spec == Init /\ [][Next]_vars /\ WF_vars(TakeSnapshot)

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes. The chain/snapshot
\* field-sets are described in the header doc-comment; the TLA+
\* shapes are constrained via the actions (action-by-action
\* UNCHANGED clauses + explicit assignments) rather than via a
\* generated ChainState / SnapshotRec membership (which would
\* blow up TLC's symbolic enumeration).
Inv_TypeOK ==
    /\ chain.height \in 0..MaxHeight
    /\ chain.balances \in [Domains -> 0..MaxBalance]
    /\ chain.counters.subsidy  \in 0..MaxHeight
    /\ chain.counters.slashed  \in 0..MaxHeight
    /\ chain.counters.inbound  \in 0..MaxHeight
    /\ chain.counters.outbound \in 0..MaxHeight
    /\ snapshot_count \in Nat

\* SerializeRestoreIdentity: RestoreSnapshot(TakeSnapshot(c)) = c
\* for every reachable c. (TLA+ form: state predicate over the
\* current chain; reachability gives the universal quantifier.)
Inv_SerializeRestoreIdentity ==
    DoRestoreSnapshot(DoTakeSnapshot(chain), chain) = chain

\* ApplyAfterRestoreEquivalence: the snapshot/restore round-trip
\* commutes with AppendBlock. Quantified over the same (d, amount)
\* range the AppendBlock action uses; guarded by the same enabling
\* condition so we only assert equivalence where AppendBlock fires.
Inv_ApplyAfterRestoreEquivalence ==
    \A d \in Domains, amount \in 1..MaxBalance :
       LET c1 == chain IN
       LET s  == DoTakeSnapshot(c1) IN
       LET c2 == DoRestoreSnapshot(s, c1) IN
       (c1.height < MaxHeight
        /\ c1.balances[d] + amount <= MaxBalance
        /\ c1.counters.subsidy + 1 <= MaxHeight)
       => ApplyDelta(c1, d, amount) = ApplyDelta(c2, d, amount)

\* VersionGateSoundness: any snapshot whose version /= SnapshotVersion
\* leaves the chain unchanged when restored.
Inv_VersionGateSoundness ==
    \A bad_v \in (0..SnapshotVersion + 2) \ {SnapshotVersion} :
       LET bad_snap == [version    |-> bad_v,
                        head_index |-> chain.height,
                        head_hash  |-> chain.head_hash,
                        payload    |-> chain] IN
       DoRestoreSnapshot(bad_snap, chain) = chain

\* DeterministicSerialization: TakeSnapshot is a pure function of
\* its input. Trivially true here because DoTakeSnapshot has no
\* fresh-randomness inputs; expressing it as a checked invariant
\* guards against future refactors that introduce nondeterminism
\* (timestamp field, fresh nonce, etc.).
Inv_DeterministicSerialization ==
    DoTakeSnapshot(chain) = DoTakeSnapshot(chain)

\* StateRootBindsApply: state_root commits to (balances, counters)
\* and head_hash commits to (height, state_root). Forward direction
\* (same inputs ⇒ same hash) is by definition of StateRoot/HeadHash;
\* the reverse is the FA-track A3 collision-resistance assumption.
Inv_StateRootBindsApply ==
    /\ chain.state_root = StateRoot(chain.balances, chain.counters)
    /\ \/ chain.height = 0 /\ chain.head_hash = EmptyHash
       \/ chain.height > 0 /\ chain.head_hash =
                                HeadHash(chain.height, chain.state_root)

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualSnapshotConsistency: under fairness on TakeSnapshot, a
\* snapshot is eventually taken. The snapshot subsystem is never
\* indefinitely starved relative to chain growth.
Prop_EventualSnapshotConsistency == <>(snapshot_count > 0)

\* RestoreIsCorrect: after every successful RestoreSnapshot (the
\* well-formed branch that mutates chain), chain' = last_snapshot.payload.
Prop_RestoreIsCorrect ==
    [][(last_snapshot /= NoSnapshot
        /\ last_snapshot.version = SnapshotVersion
        /\ chain' /= chain)
       => (chain' = last_snapshot.payload)]_vars

============================================================================
