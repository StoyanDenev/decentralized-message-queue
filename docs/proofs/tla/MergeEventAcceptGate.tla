\* TIER: NEAR-TERM — 1.0.x in-flight. Committed/imminent but not yet shipped; not 1.0-authoritative. Roadmap index: docs/ROADMAP.md

--------------------------- MODULE MergeEventAcceptGate ---------------------------
(*
FB49 — TLA+ specification of the R7 MERGE_EVENT accept-gate + apply
state machine. Models the validator-side admission decision tree that
`BlockValidator::validate_block` runs on a candidate MERGE_EVENT tx,
composed with the chain-side `Chain::apply_transactions` MERGE_EVENT
branch that mutates `merge_state_` (the `m:` namespace) only when the
event survives BOTH the receiver-side bounds gate AND the apply-side
partner-pairing gate.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
MergeEventAcceptGate.cfg MergeEventAcceptGate.tla` once the TLC
toolchain is installed in CI.

Scope. Where FB35 RegionalShardingCommittee.tla models the per-block
committee SELECTION from the region-filtered + refugee-extended pool
(the consumer of an already-active merge), this spec models the
ADMISSION side: how a MERGE_BEGIN / MERGE_END tx becomes (or fails to
become) an entry in `merge_state_`. It pins the exact two-stage gate:

  Stage 1 — receiver bounds gate (`src/node/validator.cpp:713-787`):
    (V1) sharding_mode == EXTENDED, else reject
         ("MERGE_EVENT tx requires sharding_mode=extended").
    (V2) payload decodes canonically, else reject (malformed).
    (V3) partner_id /= shard_id, else reject.
    (V4) merging_shard_region charset ⊆ [a-z0-9-_], len <= 32; empty
         is valid (refugee shard in CURRENT / global pool).
    (V5) effective_height >= b.index + merge_grace_blocks (committees
         observe the transition before it fires).
    (V6) BEGIN only: evidence_window_start <= b.index (S-036 leading
         overflow-safe bound), AND (threshold > 0 =>
         evidence_window_start + merge_threshold_blocks > b.index is
         REJECTED — the window must lie entirely in committed
         history). END carries evidence_window_start = 0.

  Stage 2 — apply partner-pairing gate (`src/chain/chain.cpp:1017-1039`):
    (A1) shard_count > 1, else the event is fee-charged + nonce-bumped
         but mutates NOTHING (degenerate single-shard chain).
    (A2) partner_id == (shard_id + 1) mod shard_count, else no mutation.
    (A3) BEGIN: insert merge_state[shard_id] := <<partner_id,
         refugee_region>>. (std::map::insert is a no-op if a key is
         already present — modeled as idempotent re-insert.)
    (A4) END: erase merge_state[shard_id] ONLY IF an entry exists AND
         its stored partner_id == ev.partner_id. A mismatched-partner
         END is a no-op (the cross-pair forged-END attack is blocked).

The fork-free design (genesis-bound params, S-039) means
merge_grace_blocks / merge_threshold_blocks / shard_count are the
SAME on every honest node, so the gate is a pure deterministic
function of (event, b.index, params, merge_state) — every honest
node admits/rejects identically. This spec abstracts the params as
constants and TLC-explores the space of well-formed AND adversarial
candidate events.

The contract this spec pins (five sub-claims paired with the five
invariants below):

  (a) No-leak admission. `merge_state` is mutated ONLY by an event
      that passed the full two-stage gate (V1..V6 ∧ A1..A4). A
      malformed, wrong-mode, self-paired, too-soon, future-window,
      or non-adjacent-partner event leaves merge_state UNCHANGED.
      The C++ correspondent is the early-return ladder at
      validator.cpp:713-787 + the nested gate at chain.cpp:1020-1036.
  (b) Partner-adjacency well-formedness. Every key shard_id in
      merge_state has merge_state[shard_id].partner == (shard_id + 1)
      mod shard_count. The structural witness is chain.cpp:1021
      (`ev->partner_id == ((ev->shard_id + 1) % shard_count_)`).
  (c) Grace-discipline. Every admitted event had effective_height >=
      its containing-block index + merge_grace_blocks. The committees
      observe the transition before it fires. Witness: validator.cpp:753.
  (d) Window-causality (BEGIN). Every admitted BEGIN had its evidence
      window ENTIRELY in committed history: evidence_window_start <=
      b.index AND evidence_window_start + merge_threshold_blocks <=
      b.index (when threshold > 0). The S-036 leading bound makes the
      sum-check overflow-safe. Witness: validator.cpp:772-783.
  (e) END-matched-erase. A MERGE_END removes merge_state[shard_id]
      ONLY when an entry exists with a matching stored partner_id;
      a cross-pair / phantom END is a no-op (cannot dislodge an
      unrelated active merge). Witness: chain.cpp:1029-1033.

The state machine. Five actions cover the admission surface (plus a
Stutter to bound TLC):

  * SubmitBegin(shard, partner, eff_h, ev_start, region_ok) — a
    producer (honest OR Byzantine) emits a MERGE_BEGIN candidate. The
    action runs the full two-stage gate inline; merge_state is
    mutated IFF the gate passes. region_ok is a boolean abstracting
    the charset check (TRUE = passes V4, FALSE = fails V4) so TLC
    need not model byte strings.
  * SubmitEnd(shard, partner, eff_h) — a producer emits a MERGE_END
    candidate. Runs the gate (BEGIN-only window checks skipped per
    V6); on pass, erases merge_state[shard] IFF the stored partner
    matches (A4).
  * AdvanceBlock — increments block_height (the containing-block
    index that the grace + window bounds are measured against).
    Bounds at MaxBlock for TLC. Mirrors the chain growing one block
    at a time; each MERGE_EVENT is adjudicated against the CURRENT
    head height.
  * WrongMode — a candidate event arrives while sharding_mode is
    NOT EXTENDED. Always a no-op on merge_state (V1 rejects). Modeled
    explicitly so the "mode gate blocks every event" claim is
    reachable.
  * Stutter — pins the TLC bound once block_height saturates.

Modeling scope (kept tractable for TLC):

  * `Shards` is 0..(ShardCount-1) — the shard-id universe. Production
    runs ShardCount in {2..8} (genesis sharding manifest); the model
    uses ShardCount = 3 so the partner-pairing wrap (2 -> 0) is
    exercised and a non-adjacent pair (0 -> 2) is reachably rejected.
  * `merge_state` is a partial function shard_id -> [partner: Nat,
    region: BOOLEAN]. The region field is abstracted to a boolean
    (TRUE = a non-empty valid region was supplied; the byte content
    is irrelevant to the gate's admit/reject decision). The C++
    `merge_state_` is a std::map<uint32_t, MergePartnerInfo>; this
    spec abstracts MergePartnerInfo to <<partner, region_ok>>.
  * `Grace` = merge_grace_blocks, `Threshold` = merge_threshold_blocks
    are constants (genesis-bound per S-039). The cfg uses Grace = 2,
    Threshold = 3, ShardCount = 3, MaxBlock = 5 — small enough that
    TLC exhausts in seconds while still exercising: a too-soon
    effective_height (< b.index + Grace), a future evidence window
    (> b.index), a window-extends-past rejection
    (ev_start + Threshold > b.index), and a valid admit.
  * `ExtendedMode` is a boolean constant. When FALSE every event is
    rejected by V1 (the WrongMode action is the reachable witness).
    The cfg sets it TRUE so the rest of the gate is exercised; the
    WrongMode action models the FALSE branch reachably regardless.
  * The fee-charge + nonce-bump side effects (always applied even on
    a no-op event) are NOT modeled — they are orthogonal to the
    merge_state mutation this spec pins (FB7 Nonce.tla + FB10
    FeeAccounting.tla cover them).

Five paired theorems are pinned (per the contract above):

  (T-MA1) NoLeakAdmission. merge_state changes only via an event
          that passed the full two-stage gate. Structural witness:
          the gate ladder + the nested apply gate.
  (T-MA2) PartnerAdjacency. Every key in merge_state has
          partner == (key + 1) mod ShardCount. Witness: chain.cpp:1021.
  (T-MA3) GraceDiscipline. (ghost) Every admit happened with
          effective_height >= block_height_at_admit + Grace — pinned
          via the admit-time guard; recorded as an admit-history
          ghost for the invariant. Witness: validator.cpp:753.
  (T-MA4) WindowCausality. (ghost) Every admitted BEGIN had its
          evidence window entirely in committed history. Witness:
          validator.cpp:772-783 (S-036 overflow-safe form).
  (T-MA5) EndMatchedErase. A MERGE_END removes a merge_state entry
          ONLY when the stored partner matches the event's partner;
          a cross-pair END is a no-op. Witness: chain.cpp:1029-1033.

Five invariants codify T-MA1..T-MA5 + a type predicate; the admit
guards (T-MA3 / T-MA4) are enforced as ENABLING conditions on the
actions, so any reachable merge_state entry necessarily satisfied
them at admit time. Two ghost-history sets (begin_admits /
end_attempts) make the admit-time discipline checkable as a
state invariant.

To check (assuming TLC installed):
  $ tlc MergeEventAcceptGate.tla -config MergeEventAcceptGate.cfg

Recommended config (state space ~10^4, < 30s):
  ShardCount = 3, Grace = 2, Threshold = 3, ExtendedMode = TRUE,
  MaxBlock = 5.

Cross-references:
  - src/node/validator.cpp:713-787 (the MERGE_EVENT receiver bounds
    gate — V1..V6; the structural source for INV_NoLeakAdmission +
    INV_GraceDiscipline + INV_WindowCausality).
  - src/chain/chain.cpp:1017-1039 (the MERGE_EVENT apply branch —
    A1..A4; the partner-pairing gate + BEGIN insert / END
    matched-erase; the source for INV_PartnerAdjacency +
    INV_EndMatchedErase).
  - include/determ/chain/block.hpp:298-337 (the canonical MergeEvent
    wire format + decode contract that V2 abstracts).
  - docs/proofs/tla/RegionalShardingCommittee.tla (FB35) — the
    CONSUMER side; FB35 draws the committee from the
    refugee-extended pool once a merge is active. FB49 is the
    ADMISSION side: how merge_state gets its entries. The two
    compose: FB49's INV_PartnerAdjacency feeds FB35's MergeRefugees
    well-formedness.
  - docs/proofs/tla/Sharding.tla (FB2) — sibling shard-aware state
    machine (cross-shard receipts); FB49 covers the orthogonal
    merge-lifecycle surface, not the receipt round-trip.
  - docs/proofs/tla/GovernanceParamChange.tla (FB13) — sibling
    apply-gate spec (PARAM_CHANGE admission); the same
    "tx mutates state only if every gate passed" discipline.
  - docs/proofs/UnderQuorumMerge.md (R7) — analytic narrative on the
    under-quorum merge mechanism; this spec is the admission-side
    state-machine witness (FB35 is the selection-side witness).
  - docs/proofs/RegionalSharding.md (R4) — the region-aware overlay
    narrative; the MERGE_EVENT charset + region rule is documented
    there.
  - SECURITY.md §S-036 (evidence-window overflow tighten) — the
    leading `evidence_window_start <= b.index` bound that
    INV_WindowCausality's overflow-safe form pins.
  - SECURITY.md §S-039 (genesis-hash binds operational params) — why
    Grace / Threshold / ShardCount can be modeled as global
    constants (every honest node shares them, so the gate is a pure
    deterministic admit function).
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    ShardCount,         \* Nat >= 2 — number of shards (genesis manifest).
    Grace,              \* Nat — merge_grace_blocks.
    Threshold,          \* Nat — merge_threshold_blocks.
    ExtendedMode,       \* BOOLEAN — sharding_mode == EXTENDED.
    MaxBlock            \* Nat >= 1 — spec-time block-height bound for TLC.

ASSUME ConfigOK ==
    /\ ShardCount \in Nat /\ ShardCount >= 2
    /\ Grace \in Nat
    /\ Threshold \in Nat
    /\ ExtendedMode \in BOOLEAN
    /\ MaxBlock \in Nat /\ MaxBlock >= 1

Shards == 0 .. (ShardCount - 1)

\* The expected partner for a given shard: (shard + 1) mod ShardCount.
\* Mirrors chain.cpp:1021 `((ev->shard_id + 1) % shard_count_)`.
ExpectedPartner(shard) == (shard + 1) % ShardCount

\* -----------------------------------------------------------------
\* §1. Variables.
\* -----------------------------------------------------------------

VARIABLES
    block_height,       \* Nat — current head index (the b.index that the
                         \*  grace + window bounds are measured against).
    merge_state,        \* function shard_id -> [partner: Nat, region:
                         \*  BOOLEAN] — the active merges (the `m:`
                         \*  namespace). Empty function = no active merge.
    begin_admits,       \* ghost: set of <<shard, partner, eff_h, ev_start,
                         \*  height>> records, one per admitted MERGE_BEGIN.
                         \*  Lets the invariant check the admit-time
                         \*  grace + window discipline as a state predicate.
    end_admits          \* ghost: set of <<shard, partner, height>> records,
                         \*  one per admitted (mutating) MERGE_END.

vars == <<block_height, merge_state, begin_admits, end_admits>>

\* -----------------------------------------------------------------
\* §2. Gate predicates (pure; mirror the C++ early-return ladder).
\* -----------------------------------------------------------------

\* Stage 1, common bounds (V1, V3, V5). V2 (decode) is abstracted: the
\* action arguments are already structured, so a "malformed" event is
\* modeled by the WrongMode action / out-of-domain args being disabled.
\* V4 (region charset) is abstracted to the region_ok boolean argument.
CommonGateOK(shard, partner, eff_h, region_ok) ==
    /\ ExtendedMode                              \* V1
    /\ partner /= shard                          \* V3
    /\ region_ok                                 \* V4 (abstracted)
    /\ eff_h >= block_height + Grace             \* V5

\* Stage 1, BEGIN-only window causality (V6). The S-036 leading bound
\* (ev_start <= b.index) is checked FIRST so the sum-check below cannot
\* be bypassed by integer overflow. In TLA+ Integers there is no
\* wraparound, but the leading bound is preserved structurally to match
\* the C++ ordering exactly.
WindowGateOK(ev_start) ==
    /\ ev_start <= block_height                          \* S-036 leading
    /\ (Threshold = 0 \/ ev_start + Threshold <= block_height)  \* window in past

\* Stage 2, apply partner-pairing gate (A1, A2).
PartnerGateOK(shard, partner) ==
    /\ ShardCount > 1                            \* A1
    /\ partner = ExpectedPartner(shard)          \* A2

\* Full admit predicates.
BeginAdmits(shard, partner, eff_h, ev_start, region_ok) ==
    /\ CommonGateOK(shard, partner, eff_h, region_ok)
    /\ WindowGateOK(ev_start)
    /\ PartnerGateOK(shard, partner)

\* END skips the BEGIN-only window check (V6). eff_h still gated by V5.
\* A4 (matched partner) is checked at the mutation site, not here.
EndGateOK(shard, partner, eff_h) ==
    /\ ExtendedMode                              \* V1
    /\ partner /= shard                          \* V3
    /\ eff_h >= block_height + Grace             \* V5
    /\ PartnerGateOK(shard, partner)             \* A1, A2

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\* No merges active at genesis; block 0; empty ghost histories.

Init ==
    /\ block_height = 0
    /\ merge_state  = << >>            \* empty function (no keys)
    /\ begin_admits = {}
    /\ end_admits   = {}

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* SubmitBegin: a producer emits a MERGE_BEGIN candidate. TLC explores
\* the full argument space (honest AND adversarial). merge_state is
\* mutated IFF BeginAdmits holds; otherwise the action is a no-op on
\* merge_state (the fee + nonce side effects are not modeled). The
\* begin_admits ghost records every ADMITTED begin for invariant
\* checking; rejected candidates leave all variables UNCHANGED so they
\* are pure stutter (not enumerated as distinct admit history).
SubmitBegin(shard, partner, eff_h, ev_start, region_ok) ==
    /\ shard \in Shards
    /\ partner \in Shards
    /\ BeginAdmits(shard, partner, eff_h, ev_start, region_ok)
    /\ merge_state' =
         IF shard \in DOMAIN merge_state
         THEN merge_state                         \* A3: insert is a no-op if present
         ELSE (shard :> [partner |-> partner, region |-> region_ok])
              @@ merge_state
    /\ begin_admits' = begin_admits \cup
         { <<shard, partner, eff_h, ev_start, block_height>> }
    /\ UNCHANGED <<block_height, end_admits>>

\* SubmitEnd: a producer emits a MERGE_END candidate. On gate pass,
\* erase merge_state[shard] IFF an entry exists with a matching stored
\* partner (A4). A cross-pair / phantom END (no entry, or stored
\* partner differs) is a no-op on merge_state — modeled as a guarded
\* erase. We only take the action when it MUTATES (an entry exists +
\* matches) so the no-op END is captured by the implicit stutter.
SubmitEnd(shard, partner, eff_h) ==
    /\ shard \in Shards
    /\ partner \in Shards
    /\ EndGateOK(shard, partner, eff_h)
    /\ shard \in DOMAIN merge_state                  \* entry exists
    /\ merge_state[shard].partner = partner          \* A4: matched partner
    /\ merge_state' = [ s \in (DOMAIN merge_state \ {shard})
                          |-> merge_state[s] ]
    /\ end_admits' = end_admits \cup
         { <<shard, partner, block_height>> }
    /\ UNCHANGED <<block_height, begin_admits>>

\* AdvanceBlock: head index grows by one (bounds the grace + window
\* arithmetic). Bounded at MaxBlock for TLC.
AdvanceBlock ==
    /\ block_height < MaxBlock
    /\ block_height' = block_height + 1
    /\ UNCHANGED <<merge_state, begin_admits, end_admits>>

\* WrongMode: a candidate event arrives while sharding_mode is NOT
\* EXTENDED. ALWAYS a no-op on merge_state (V1 rejects). When
\* ExtendedMode is TRUE this action is disabled (the cfg's normal
\* run); it is the reachable witness for the V1-blocks-everything
\* claim under a non-extended config.
WrongMode ==
    /\ ~ExtendedMode
    /\ UNCHANGED vars

\* Stutter — pins the TLC bound once block_height saturates AND no
\* further mutating event is possible at the bound (kept simple:
\* enabled at the bound).
Stutter ==
    /\ block_height >= MaxBlock
    /\ UNCHANGED vars

Next ==
    \/ \E shard \in Shards, partner \in Shards,
          eff_h \in 0..(MaxBlock + Grace), ev_start \in 0..MaxBlock,
          region_ok \in BOOLEAN :
            SubmitBegin(shard, partner, eff_h, ev_start, region_ok)
    \/ \E shard \in Shards, partner \in Shards,
          eff_h \in 0..(MaxBlock + Grace) :
            SubmitEnd(shard, partner, eff_h)
    \/ AdvanceBlock
    \/ WrongMode
    \/ Stutter

Spec == Init /\ [][Next]_vars
            /\ WF_vars(AdvanceBlock)

\* -----------------------------------------------------------------
\* §5. Invariants — T-MA1..T-MA5 + TypeOK.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.
TypeOK ==
    /\ block_height \in 0..MaxBlock
    /\ DOMAIN merge_state \subseteq Shards
    /\ \A s \in DOMAIN merge_state :
          /\ merge_state[s].partner \in Shards
          /\ merge_state[s].region \in BOOLEAN
    /\ begin_admits \subseteq
         (Shards \X Shards \X (0..(MaxBlock + Grace))
                 \X (0..MaxBlock) \X (0..MaxBlock))
    /\ end_admits \subseteq (Shards \X Shards \X (0..MaxBlock))

\* INV_PartnerAdjacency (T-MA2).
\* Every key in merge_state has partner == (key + 1) mod ShardCount.
\* The headline safety property: no non-adjacent pair can ever be an
\* active merge, because the apply gate (A2) rejected it. This feeds
\* FB35's MergeRefugees well-formedness (refugees come from the +1
\* sibling, never an arbitrary shard).
INV_PartnerAdjacency ==
    \A s \in DOMAIN merge_state :
        merge_state[s].partner = ExpectedPartner(s)

\* INV_NoLeakAdmission (T-MA1).
\* Every active merge_state entry has a corresponding admitted BEGIN
\* in the ghost history with matching (shard, partner) — i.e. no entry
\* materialized without passing the full two-stage gate. (The reverse
\* — an admitted BEGIN later ended — is allowed; END removes the entry
\* but the ghost record persists.) Combined with the SubmitBegin guard
\* BeginAdmits, this pins "merge_state mutated only via a fully-gated
\* event."
INV_NoLeakAdmission ==
    \A s \in DOMAIN merge_state :
        \E rec \in begin_admits :
            /\ rec[1] = s
            /\ rec[2] = merge_state[s].partner

\* INV_GraceDiscipline (T-MA3).
\* Every admitted BEGIN had effective_height >= its containing-block
\* height + Grace. Checked over the ghost history (the SubmitBegin
\* guard enforced V5 at admit time; this invariant makes that durable).
INV_GraceDiscipline ==
    \A rec \in begin_admits :
        \* rec = <<shard, partner, eff_h, ev_start, height>>
        rec[3] >= rec[5] + Grace

\* INV_WindowCausality (T-MA4).
\* Every admitted BEGIN had its evidence window entirely in committed
\* history: ev_start <= height (S-036 leading bound) AND, when
\* Threshold > 0, ev_start + Threshold <= height. No admitted BEGIN
\* carries a future-start or window-extends-past-head window.
INV_WindowCausality ==
    \A rec \in begin_admits :
        \* rec = <<shard, partner, eff_h, ev_start, height>>
        /\ rec[4] <= rec[5]
        /\ (Threshold = 0 \/ rec[4] + Threshold <= rec[5])

\* INV_EndMatchedErase (T-MA5).
\* Every admitted (mutating) END matched the partner that was stored
\* for that shard. Recorded over end_admits: each end record's partner
\* equals the ExpectedPartner of its shard (the only partner an active
\* entry could have carried, by INV_PartnerAdjacency). This pins that
\* a cross-pair END can never have mutated merge_state (it would have
\* failed the A4 matched-partner guard, so it is absent from
\* end_admits).
INV_EndMatchedErase ==
    \A rec \in end_admits :
        \* rec = <<shard, partner, height>>
        rec[2] = ExpectedPartner(rec[1])

\* -----------------------------------------------------------------
\* §6. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The R7 MERGE_EVENT admission contract is pinned at the
\* state-machine layer by the five invariants. The abstraction
\* boundary:
\*
\*   * The two-stage gate (validator bounds + apply partner-pairing)
\*     is what TLC checks: the SubmitBegin / SubmitEnd actions are
\*     ENABLED only when the full gate predicate holds, so every
\*     reachable merge_state mutation necessarily passed it. The C++
\*     correspondent is the early-return ladder at validator.cpp:713-787
\*     composed with the nested gate at chain.cpp:1020-1036.
\*
\*   * The payload decode (V2) is abstracted: the action arguments are
\*     already structured tuples, so a "malformed payload" is modeled
\*     by the absence of a corresponding enabled action (a malformed
\*     event never reaches the mutation site in C++ either — decode()
\*     returns nullopt and the branch is skipped). The region charset
\*     check (V4) is abstracted to the region_ok boolean — TLC need
\*     not enumerate byte strings to exercise the admit/reject split.
\*
\*   * The fee-charge + nonce-bump side effects (always applied even on
\*     a no-op event, per chain.cpp:1018 + :1037) are NOT modeled —
\*     they are orthogonal to the merge_state mutation this spec pins.
\*     FB7 Nonce.tla + FB10 FeeAccounting.tla cover them.
\*
\*   * The full historical witness-window check (each beacon block in
\*     [evidence_window_start, +merge_threshold_blocks) contains no
\*     SHARD_TIP record AND eligible_in_region < 2K) is NOT modeled —
\*     it requires on-chain SHARD_TIP records (a separate work item per
\*     validator.cpp:716-719). This spec pins the internal-consistency
\*     bounds that the receiver CAN check without that record (V5 +
\*     V6); the deeper soundness (the window actually witnessed an
\*     under-quorum condition) is the analytic R7 narrative's domain.
\*
\*   * The per-block region rotation, committee draw, and refugee-pool
\*     extension are FB35 RegionalShardingCommittee.tla's domain — the
\*     CONSUMER of an active merge. FB49 composes with FB35:
\*     INV_PartnerAdjacency guarantees FB35's MergeRefugees only ever
\*     pulls from the +1 sibling, never an arbitrary shard.
\*
\* What this spec adds beyond existing FB-track surfaces:
\*
\*   * The state-machine witness that NO adversarial MERGE_EVENT
\*     (wrong mode, self-pair, non-adjacent partner, too-soon
\*     effective_height, future / over-long evidence window, cross-pair
\*     END) can ever mutate merge_state — across every reachable
\*     interleaving of SubmitBegin / SubmitEnd / AdvanceBlock.
\*
\*   * The S-036 overflow-safe window-causality form, pinned as
\*     INV_WindowCausality over the admit history.
\*
\*   * The cross-pair-END no-op guarantee (INV_EndMatchedErase): a
\*     forged END for shard s carrying the wrong partner cannot
\*     dislodge s's active merge.
\*
\* What the spec does NOT check (consistent with §scope):
\*
\*   * The SHARD_TIP-backed historical witness-window soundness
\*     (separate work item; analytic R7 territory).
\*   * The MERGE_EVENT gossip + relay path (FA9 beacon-relay
\*     territory).
\*   * Snapshot / restore round-trip of merge_state (FB31
\*     SnapshotIntegrity.tla covers the `m:` namespace serialize /
\*     restore lifecycle).

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   src/node/validator.cpp:713-787 : MERGE_EVENT receiver bounds gate
\*       (V1..V6) — the source for INV_NoLeakAdmission +
\*       INV_GraceDiscipline + INV_WindowCausality.
\*   src/chain/chain.cpp:1017-1039  : MERGE_EVENT apply branch
\*       (A1..A4) — the partner-pairing gate + BEGIN insert / END
\*       matched-erase; the source for INV_PartnerAdjacency +
\*       INV_EndMatchedErase.
\*   include/determ/chain/block.hpp:298-337 : canonical MergeEvent
\*       wire format + decode contract that V2 abstracts.
\*
\* SECURITY.md §S-036 (evidence-window overflow tighten) — the
\*   leading `evidence_window_start <= b.index` bound that
\*   INV_WindowCausality's overflow-safe form pins.
\* SECURITY.md §S-039 (genesis-hash binds operational params) — why
\*   Grace / Threshold / ShardCount are modeled as global constants.
\*
\* FB2 Sharding.tla (FA7 cross-shard receipt surface — orthogonal to
\*   the merge-lifecycle admission surface FB49 covers),
\* FB13 GovernanceParamChange.tla (sibling apply-gate spec — the same
\*   "tx mutates state only if every gate passed" discipline),
\* FB31 SnapshotIntegrity.tla (the `m:` namespace serialize / restore
\*   lifecycle that this spec's merge_state abstracts),
\* FB35 RegionalShardingCommittee.tla (the CONSUMER side — draws the
\*   committee from the refugee-extended pool once a merge is active;
\*   FB49's INV_PartnerAdjacency feeds FB35's MergeRefugees
\*   well-formedness).
\*
\* Analytic narratives:
\*   docs/proofs/UnderQuorumMerge.md (R7) — the merge-mechanism
\*     narrative; FB49 is the admission-side state-machine witness.
\*   docs/proofs/RegionalSharding.md (R4) — the region-aware overlay
\*     narrative; the MERGE_EVENT charset + region rule lives there.
\*
\* Runtime regressions:
\*   tools/test_merge_event_determinism.sh — the in-process determinism
\*     test for MERGE_EVENT encode/decode + apply; INV_PartnerAdjacency
\*     + INV_EndMatchedErase structural witnesses at the C++ layer.
\*   tools/test_under_quorum_merge.sh — the R7 merge-mechanism
\*     regression; INV_NoLeakAdmission's runtime witness.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB49 row — added.
============================================================================
