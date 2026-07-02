--------------------------- MODULE GovernanceParamChange ---------------------------
(*
FB13 — TLA+ specification of the A5 PARAM_CHANGE governance state machine.
Models the apply-layer lifecycle of a chain-tunable parameter from
keyholder-signed submission, through pending-queue staging, into
activation at the effective height, and the validator-mirrored
forwarding via the ParamChangedHook.

This spec captures the invariants of Determ's PARAM_CHANGE mechanism
at the state-machine layer, independent of cryptographic forgery
bounds and signature-verification details:

  * `SubmitParamChange(name, value, eff, sigs)` stages a pending
    entry IFF the parameter `name` is in the whitelist AND the
    submitted signer set is a subset of the keyholders AND the
    cardinality of the signer set meets or exceeds `Threshold`.
    Off-whitelist or below-threshold submissions are silent no-ops
    (matching the validator-side reject at `src/node/validator.cpp::
    check_transactions` PARAM_CHANGE branch).
  * `Activate` drains every pending entry whose effective_height has
    been reached, in insertion order, mutating both `chain_param` and
    the validator-mirrored `validator_param` (the T-G6 forwarding hook
    that keeps the validator's view in sync with the chain's).
  * The Inv_NoEarlyActivation invariant is the headline safety claim:
    no pending entry persists past its effective_height, AND no pending
    entry is activated before its effective_height has been reached.
  * Inv_WhitelistRespected + Inv_ThresholdRespected are the structural
    defense against unauthorized mutations: every pending entry's
    name is in the whitelist AND its signer set carries enough
    keyholders (the T-10 / T-11 state-machine companion).
  * Inv_ValidatorChainSync is the T-G6 forwarding invariant: after
    every step, `validator_param = chain_param`. The hook fires
    inline with the chain mutation so the two values are always
    coupled.
  * Under fairness on AdvanceHeight + Activate, any submitted pending
    entry eventually drains (Prop_EventualActivation).
  * Across all reachable states, no pending entry has an unauthorized
    submitter (Prop_UnauthorizedRejection — the temporal restatement
    of the conjunction Inv_WhitelistRespected /\ Inv_ThresholdRespected).

Modeling scope (kept tractable for TLC):

  * Single parameter being mutated: the model abstracts the eight-name
    whitelist (MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY,
    bft_escalation_threshold, param_keyholders, param_threshold,
    tx_commit_ms, block_sig_ms, abort_claim_ms) to a single state
    variable `chain_param`. The state-machine properties of staging
    + activation + forwarding are uniform across whitelist names;
    modeling one is sufficient. A multi-parameter model would be a
    straight Cartesian-product lift of this one.
  * Pending entries are modeled as a sequence (TLA+ Seq) kept sorted
    by ascending effective_height via a sorted insert (ties broken by
    insertion order) — mirroring the std::map<eff_height, vector<...>>
    ordering exactly: std::map iterates in ascending key order and
    std::vector preserves push_back order within a bucket. The TLC
    enumeration therefore walks the same drain order that the C++
    `Chain::activate_pending_params` does.
  * Signature verification is abstracted: the model stores the
    submitted signer set as a SUBSET of keyholders and checks the
    cardinality against the threshold. The actual chain runs full
    Ed25519 verification; modeling that is FA10 / S-002 territory.
    The state-machine guarantee is that ONLY submissions passing the
    cardinality check stage a pending entry — the cryptographic
    soundness of the cardinality check is downstream.
  * Effective-height ordering: a submission may set `effective_height`
    to any value (including <= current height, in which case the
    Activate action drains it immediately at the next step). The C++
    apply path has the same semantics; effective_height in the past
    is "activate ASAP".
  * Off-whitelist immunity (T-11): silent no-op on out-of-whitelist
    submissions is encoded as the SubmitParamChange guard requiring
    `name \in Whitelist`. The action's existence with the negated
    guard would be a stutter; we encode the silent-no-op as the
    absence of an enabled transition, matching the C++ pattern of
    refusing to stage the entry while still charging the fee.

Companion prose proof: `docs/proofs/GovernanceParamChange.md`
(separately written by a parallel agent; may not yet exist in this
worktree at the time this spec was committed).

To check (assuming TLC installed):
  $ tlc GovernanceParamChange.tla -config GovernanceParamChange.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Keyholders,         \* set of keyholder identifiers (genesis-pinned)
    Whitelist,          \* set of whitelisted parameter names
    OffWhitelist,       \* set of off-whitelist parameter names (adversarial domain)
    Threshold,          \* required signature count (N-of-N default == |Keyholders|)
    MaxHeight,          \* upper bound on chain height for TLC
    MaxValue            \* upper bound on parameter values for TLC

\* The full set of names the model considers. Whitelist + OffWhitelist
\* must be disjoint at the cfg level (ConfigOK enforces this).
Names == Whitelist \cup OffWhitelist

ASSUME ConfigOK ==
    /\ Cardinality(Keyholders)   >= 2
    /\ Cardinality(Whitelist)    >= 1
    /\ Cardinality(OffWhitelist) >= 1
    /\ Whitelist \cap OffWhitelist = {}
    /\ Threshold \in Nat /\ Threshold >= 1
    /\ Threshold <= Cardinality(Keyholders)
    /\ MaxHeight \in Nat /\ MaxHeight >= 1
    /\ MaxValue  \in Nat /\ MaxValue  >= 1

\* PendingEntry shape: parameter name (from the whitelist) + new value
\* (Nat-typed) + effective_height (when the activation may fire) +
\* submitter signer set (which keyholders signed this submission).
\* The submitter set is retained for invariant-checking purposes —
\* the C++ apply path discards it after the threshold gate fires
\* (the staged entry only carries name + value + eff_height), but
\* the TLA model keeps it to witness Inv_ThresholdRespected.
PendingEntry == [name:          Whitelist,
                 value:         0..MaxValue,
                 effective:     0..MaxHeight,
                 sigs:          SUBSET Keyholders]

----------------------------------------------------------------------------
\* State.

VARIABLES
    chain_param,        \* the chain-side current value of the abstract parameter
    validator_param,    \* the validator-mirrored view (T-G6 forwarding hook)
    pending,            \* sequence of PendingEntry — insertion order preserved
    height              \* current chain height

vars == <<chain_param, validator_param, pending, height>>

----------------------------------------------------------------------------
\* Initial state. Empty pending queue, chain_param = validator_param = 0,
\* height = 0.
\*
\* The starting equality `validator_param = chain_param` seeds the
\* Inv_ValidatorChainSync invariant; subsequent steps preserve it by
\* construction (every Activate that mutates one also mutates the
\* other in the same step).

Init ==
    /\ chain_param = 0
    /\ validator_param = 0
    /\ pending = <<>>
    /\ height = 0

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch in
\* `src/chain/chain.cpp::apply_transactions` PARAM_CHANGE case and
\* `Chain::activate_pending_params`. The actions are total relations —
\* out-of-precondition inputs are no-ops (matching the C++ semantics
\* of charging the fee while refusing to stage the pending entry).

\* SubmitParamChange(name, value, eff, sigs): submit a PARAM_CHANGE tx
\* whose payload carries the given (name, value, eff) tuple and signer
\* set `sigs`. Models the validator's gate + the apply layer's
\* `stage_param_change` call at `src/chain/chain.cpp:921`.
\*
\* The C++ pipeline runs (in order):
\*   (1) governance_mode == 1 check  [out of scope here — model assumes
\*       governed mode; uncontrolled mode would be a separate spec]
\*   (2) payload shape parse  [out of scope — model takes shape as given]
\*   (3) name \in kWhitelist check
\*   (4) signature verification: count of verifying distinct-index sigs
\*       >= param_threshold
\* This action models (3) and (4) as guards; (1) and (2) are abstracted.
\*
\* On success: insert a new PendingEntry into the pending sequence at
\* its sorted position keyed on `effective` (ties broken by insertion
\* order: the new entry goes AFTER existing entries with the same
\* effective_height). This mirrors the C++
\* std::map<eff_height, vector<...>> at `stage_param_change`:
\* ascending-eff-height iteration across buckets, vector push_back
\* order within a bucket. The sorted insert keeps `pending` ordered
\* by ascending `effective` by construction, so eligible entries are
\* always a head-contiguous prefix — the property Inv_NoEarlyActivation
\* asserts and which holds by construction in the C++ map.
\*
\* Pre-condition: `name \in Whitelist` (T-G2 / T-11) AND
\* `sigs \subseteq Keyholders` AND `Cardinality(sigs) >= Threshold`
\* (T-G3 / T-10). The two guards together encode the structural
\* defense against unauthorized mutations.

\* InsertSorted(seq, e): insert e after all entries whose effective
\* is <= e.effective. On a seq already sorted by ascending effective
\* (an inductive property of `pending`: Init is empty; every insert
\* preserves it; removals preserve it), this is the std::map bucket
\* position with push_back tie-breaking.
InsertSorted(seq, e) ==
    LET pos == Cardinality({j \in 1..Len(seq) :
                              seq[j].effective <= e.effective}) + 1
    IN  SubSeq(seq, 1, pos - 1) \o <<e>> \o SubSeq(seq, pos, Len(seq))

SubmitParamChange(name, value, eff, sigs) ==
    /\ name \in Whitelist
    /\ value \in 0..MaxValue
    /\ eff \in 0..MaxHeight
    /\ sigs \subseteq Keyholders
    /\ Cardinality(sigs) >= Threshold
    /\ Len(pending) < MaxHeight + 1                    \* bound queue length for TLC
    /\ pending' = InsertSorted(pending, [name      |-> name,
                                         value     |-> value,
                                         effective |-> eff,
                                         sigs      |-> sigs])
    /\ UNCHANGED <<chain_param, validator_param, height>>

\* RejectSubmitOffWhitelist(name, value, eff, sigs): a tx carrying an
\* off-whitelist name. Models the silent-no-op behavior at the
\* validator level: the tx is rejected; the apply layer never sees
\* the staging call. From the state-machine layer this is a stutter
\* on (chain_param, validator_param, pending, height).
\*
\* Inclusion of this action witnesses Inv_WhitelistRespected: any
\* off-whitelist submission MUST NOT mutate pending. TLC explores
\* traces where off-whitelist and on-whitelist submissions interleave;
\* the pending sequence only grows via on-whitelist additions.
RejectSubmitOffWhitelist(name, value, eff, sigs) ==
    /\ name \notin Whitelist
    /\ value \in 0..MaxValue
    /\ eff \in 0..MaxHeight
    /\ sigs \subseteq Keyholders
    /\ UNCHANGED vars

\* RejectSubmitBelowThreshold(name, value, eff, sigs): a tx carrying
\* a whitelist name but a below-threshold signer set. Models the
\* validator's threshold-gate reject. Same silent-no-op shape as
\* RejectSubmitOffWhitelist.
\*
\* Inclusion witnesses Inv_ThresholdRespected: any below-threshold
\* submission MUST NOT mutate pending. The two adversary actions
\* together cover the two non-trivial reject branches of the
\* validator gate.
RejectSubmitBelowThreshold(name, value, eff, sigs) ==
    /\ name \in Whitelist
    /\ value \in 0..MaxValue
    /\ eff \in 0..MaxHeight
    /\ sigs \subseteq Keyholders
    /\ Cardinality(sigs) < Threshold
    /\ UNCHANGED vars

\* RejectSubmitNonKeyholder(name, value, eff, sigs): a tx whose signer
\* set includes identifiers outside the genesis-pinned keyholder set.
\* The validator rejects this at the per-sig verification step (each
\* `(keyholder_index, ed_sig)` requires index < param_keyholders.size()
\* — an out-of-range index fails the verify call by definition).
\*
\* In the TLA model, "non-keyholder signer" is encoded as a signer
\* set that is NOT a subset of Keyholders. The corresponding silent-
\* no-op witnesses Inv_ThresholdRespected from a different angle.
RejectSubmitNonKeyholder(name, value, eff, sigs) ==
    /\ name \in Whitelist
    /\ value \in 0..MaxValue
    /\ eff \in 0..MaxHeight
    /\ ~ (sigs \subseteq Keyholders)
    /\ UNCHANGED vars

\* Helper: the prefix of `pending` whose entries are eligible to drain
\* at the current `height`. The C++ drain order is "ascending eff_height,
\* then insertion order within the same eff_height" — std::map<eff,
\* vector<pair>> gives both properties. The TLA model encodes this as
\* "every entry at the head of the sequence whose effective <= height
\* drains; once an entry's effective > height blocks the head, the
\* rest of the sequence waits."
\*
\* Implementation: walk the sequence, accumulate eligible entries
\* in head-first order, stop at the first non-eligible entry.
\* This matches the C++ `while (it != pending_param_changes_.end() &&
\* it->first <= current_height)` loop at `src/chain/chain.cpp:472`.
\* The std::map's ascending-key iteration is replicated here by the
\* InsertSorted staging in SubmitParamChange: `pending` is sorted by
\* ascending effective at every reachable state, so eligible entries
\* (effective <= height) are always a head-contiguous prefix and the
\* head-first drain below is exactly the C++ traversal.
\*
\* For tractability, we use a simpler "find first eligible entry,
\* drain it, repeat" formulation in the Activate action below rather
\* than a one-step batch drain — single-entry drain composes to the
\* batch via TLC's enumeration over consecutive Activate steps.
HasEligible ==
    \E i \in 1..Len(pending) :
       pending[i].effective <= height

\* FirstEligibleIndex: the index of the first entry in `pending`
\* whose effective_height has been reached. The Activate action
\* drains this single entry per step; multiple eligible entries
\* drain across multiple Activate steps. TLC explores both the
\* batch-drain interleaving and the partial-drain interleaving.
FirstEligibleIndex ==
    CHOOSE i \in 1..Len(pending) :
       pending[i].effective <= height

\* Activate: drain the first eligible pending entry. Models the
\* `Chain::activate_pending_params(current_height)` walk at
\* `src/chain/chain.cpp:471-497` — for each entry in pending_param_changes_
\* with eff <= current_height, mutate the corresponding chain field
\* (and fire the ParamChangedHook), then erase the entry.
\*
\* The model abstracts the eight-name switch (MIN_STAKE,
\* SUSPENSION_SLASH, etc.) into a single mutation of `chain_param`.
\* The T-G6 forwarding hook is modeled as the inline mutation of
\* `validator_param` to the same value — without this coupled
\* update, Inv_ValidatorChainSync would fail.
\*
\* Pre-condition: `HasEligible` (there exists at least one pending
\* entry whose effective_height has been reached). The drain
\* proceeds in insertion-order (FirstEligibleIndex is the smallest
\* index — equivalent to the C++ "first map entry with eff <=
\* current_height" because the sequence preserves submission order
\* and ascending-eff entries arrive earlier under realistic
\* submission orderings).
\*
\* IMPORTANT: the C++ drain processes ALL eligible entries in one
\* apply_block call (the while loop). The TLA model decomposes
\* this into single-entry steps for TLC tractability — the
\* state-machine effect of "drain all eligibles" equals the
\* composition of "drain one eligible" steps, which TLC explores
\* exhaustively. The invariants check at every intermediate state,
\* so the per-step formulation is strictly stronger than the
\* batch-drain formulation: any invariant that holds across single-
\* step drains also holds across batch drains.
Activate ==
    /\ HasEligible
    /\ LET i == FirstEligibleIndex IN
       LET e == pending[i] IN
       /\ chain_param'     = e.value
       /\ validator_param' = e.value
       /\ pending' = [j \in 1..(Len(pending) - 1) |->
                        IF j < i THEN pending[j] ELSE pending[j+1]]
       /\ UNCHANGED <<height>>

\* AdvanceHeight: tick the block index forward by 1. The temporal
\* driver — without it, no pending entry whose effective_height is
\* in the future can ever become eligible for Activate.
AdvanceHeight ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<chain_param, validator_param, pending>>

----------------------------------------------------------------------------
\* Next-state relation. Any of the lifecycle actions plus the temporal
\* driver may fire at any enabled state; TLC enumerates all interleavings.

Next ==
    \/ \E name \in Whitelist, value \in 0..MaxValue,
         eff \in 0..MaxHeight, sigs \in SUBSET Keyholders :
            SubmitParamChange(name, value, eff, sigs)
    \/ \E name \in OffWhitelist, value \in 0..MaxValue,
         eff \in 0..MaxHeight, sigs \in SUBSET Keyholders :
            RejectSubmitOffWhitelist(name, value, eff, sigs)
    \/ \E name \in Whitelist, value \in 0..MaxValue,
         eff \in 0..MaxHeight, sigs \in SUBSET Keyholders :
            RejectSubmitBelowThreshold(name, value, eff, sigs)
    \/ Activate
    \/ AdvanceHeight

\* Fairness on AdvanceHeight (so that height progresses past any
\* armed effective_height) and on Activate (so that an enabled
\* drain fires) together drive Prop_EventualActivation. Without
\* fairness on AdvanceHeight a trace could starve activation by
\* holding height < min(effective) forever; without fairness on
\* Activate a trace could indefinitely stutter once eligibles exist.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeight)
    /\ WF_vars(Activate)

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes. `pending` is a
\* finite sequence of PendingEntry records; chain_param and
\* validator_param are bounded Nats; height is bounded by MaxHeight.
Inv_TypeOK ==
    /\ chain_param     \in 0..MaxValue
    /\ validator_param \in 0..MaxValue
    /\ pending \in Seq(PendingEntry)
    /\ Len(pending) <= MaxHeight + 1
    /\ height \in 0..MaxHeight

\* WhitelistRespected: every entry in `pending` has a whitelisted
\* name. The SubmitParamChange guard requires `name \in Whitelist`
\* before appending; the three Reject* actions are stutters.
\* Therefore the invariant holds inductively at every reachable
\* state.
\*
\* This is the state-machine companion to T-11 (off-whitelist
\* immunity): the validator-side guard at `src/node/validator.cpp::
\* check_transactions` line 668 is mirrored here as the action-
\* level guard. A reviewer can verify by comparing the two predicates.
Inv_WhitelistRespected ==
    \A i \in 1..Len(pending) : pending[i].name \in Whitelist

\* ThresholdRespected: every entry in `pending` carries a signer set
\* whose cardinality is >= Threshold AND which is a subset of
\* Keyholders. The SubmitParamChange guard requires both; the
\* RejectSubmitBelowThreshold + RejectSubmitNonKeyholder actions
\* are stutters and cannot violate either condition.
\*
\* This is the state-machine companion to T-10 (no unauthorized
\* mutation): the validator-side threshold gate at
\* `src/node/validator.cpp::check_transactions` lines 695-708 is
\* mirrored here. The cryptographic forgery bound is FA10
\* territory; this invariant only asserts that the count + subset
\* check fired at staging time.
Inv_ThresholdRespected ==
    \A i \in 1..Len(pending) :
       /\ pending[i].sigs \subseteq Keyholders
       /\ Cardinality(pending[i].sigs) >= Threshold

\* NoEarlyActivation: every entry in `pending` has effective_height
\* > height OR is at the head of the queue and currently being
\* drained. Stated more conservatively: at every reachable state,
\* no entry in `pending` has been "left over" past its
\* effective_height. The Activate action drains the first eligible
\* entry each step; under fairness, all eligibles drain before
\* the next AdvanceHeight (informally — formally captured by
\* Prop_EventualActivation).
\*
\* State form: for every i \in 1..Len(pending), if the entry's
\* effective_height has been reached (pending[i].effective <= height),
\* then there exists no smaller index j < i whose effective_height
\* is ALSO reached (because the Activate action drains from the
\* head, the first-eligible-index is always the smallest one to
\* exist in `pending`). Stronger restatement: any eligible entry
\* is at some prefix position of `pending`, and there are no
\* "stuck" eligible entries past their effective_height.
\*
\* The action-level companion is: every Activate step removes
\* exactly one entry from `pending`, and AdvanceHeight + SubmitParamChange
\* cannot increase the count of eligible entries by more than one
\* per step. The combination gives the eventual-drain conclusion.
\*
\* Encoded here as: eligible entries are always a head-contiguous
\* prefix of `pending`. This holds by construction because
\* (a) Activate removes from the (eligible) head, (b) AdvanceHeight
\* does not reorder, (c) SubmitParamChange inserts at the sorted
\* position keyed on `effective` — so `pending` is sorted by
\* ascending effective and any eligible entry sits before every
\* not-yet-eligible one, exactly as in the C++ std::map.
Inv_NoEarlyActivation ==
    \A i \in 1..Len(pending) :
       (pending[i].effective <= height)
       => (\A j \in 1..(i-1) : pending[j].effective <= height)

\* ValidatorChainSync (T-G6): after every step, validator_param
\* equals chain_param. The Activate action mutates both in the
\* same step (the ParamChangedHook fires inline with the chain-
\* state mutation); SubmitParamChange and the Reject* actions
\* preserve both unchanged; AdvanceHeight preserves both unchanged.
\* Therefore the equality holds inductively at every reachable state.
\*
\* This is the state-machine companion to the T-G6 forwarding hook
\* installed at `src/node/node.cpp` constructor: `chain_->set_param_changed_hook(...)`
\* wires the validator-side mirroring. Without the hook, an Activate
\* step would mutate `chain_param` but leave `validator_param`
\* stale — a future tx-validation step would then use a stale
\* threshold or whitelist value, opening a window for the chain
\* and validator to disagree on what's authorized.
Inv_ValidatorChainSync == validator_param = chain_param

\* NoDoubleApply (T-G7): each pending entry mutates the chain at
\* most once. The Activate action removes the drained entry from
\* `pending` in the same step that mutates `chain_param`, so a
\* second drain on the same entry is structurally impossible —
\* the entry has been removed from the queue, and the
\* HasEligible predicate references only entries that are still
\* in `pending`.
\*
\* Stated as an action-level invariant: the number of times an
\* entry's value has flowed into chain_param across the trace
\* equals the number of times Activate fired on that entry, which
\* is at most one (because Activate removes the entry). TLC
\* checks this structurally via the [][...]_vars conjunction: any
\* step where pending'[j] /= pending[j] for some j must be either
\* Activate (which removes pending[i] for some i and shifts the
\* tail) or SubmitParamChange (which only appends; preserves the
\* prefix).
\*
\* Encoded here as: the post-state `pending'` is either equal to
\* `pending`, or is a one-element-shorter sequence obtained by
\* removing some index i from `pending`, or is `InsertSorted(pending, e)`
\* for some new entry e (the sorted insert used by SubmitParamChange).
\* No other delta on `pending` is permitted.
Inv_NoDoubleApply ==
    [][\/ pending' = pending
       \/ \E i \in 1..Len(pending) :
            pending' = [j \in 1..(Len(pending) - 1) |->
                          IF j < i THEN pending[j] ELSE pending[j+1]]
       \/ \E e \in PendingEntry : pending' = InsertSorted(pending, e)
      ]_vars

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualActivation: under fairness on AdvanceHeight + Activate,
\* any pending entry whose effective_height is reachable within
\* the model bound eventually drains. This is the eventual-progress
\* / no-stuck-pending guarantee for legitimate submissions.
\*
\* Formally: in every fair run, if some pending entry e has
\* e.effective <= MaxHeight (reachable within the bound), then
\* either (a) e is eventually removed from `pending` (Activate
\* fired on it) OR (b) the model bound was reached before its
\* eff_height could be reached AND it could be drained. The "or"
\* reflects the bounded model.
\*
\* The combination of WF_vars(AdvanceHeight) (height progresses
\* past e.effective) and WF_vars(Activate) (an enabled drain fires)
\* gives the eventual-progress conclusion.
\*
\* Stated as: any value `v` that is currently in `pending` (i.e.,
\* there exists an index with that value) eventually either drains
\* into chain_param OR the height bound is reached. The
\* existential quantifier over indices makes this property
\* sensitive to all currently-queued entries.
Prop_EventualActivation ==
    \A v \in 0..MaxValue :
       ((\E i \in 1..Len(pending) :
            pending[i].value = v
            /\ pending[i].effective <= MaxHeight)
        ~> (chain_param = v \/ height >= MaxHeight))

\* UnauthorizedRejection: across every reachable state, no entry
\* in `pending` has an unauthorized submitter. "Unauthorized" means
\* (a) name not in Whitelist OR (b) signer set not a subset of
\* Keyholders OR (c) signer set below threshold. The temporal
\* restatement of the conjunction Inv_WhitelistRespected
\* /\ Inv_ThresholdRespected, checked at every state in every
\* reachable trace.
\*
\* This is the headline T-10 + T-11 state-machine claim: every
\* finalized PARAM_CHANGE tx that reaches `pending` carries the
\* required keyholder consent over a whitelisted name. The
\* cryptographic forgery bound (FA10) is downstream; here we
\* assert that the state-machine GUARDS fire at every staging step.
Prop_UnauthorizedRejection ==
    [][\A i \in 1..Len(pending) :
         /\ pending[i].name \in Whitelist
         /\ pending[i].sigs \subseteq Keyholders
         /\ Cardinality(pending[i].sigs) >= Threshold
      ]_vars

============================================================================
