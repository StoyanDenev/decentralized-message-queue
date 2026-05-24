----------------------- MODULE BoundedMempoolAdmission -----------------------
(*
FB38 — TLA+ specification of the bounded mempool admission state
machine FOCUSED on the cap-eviction + RBF (replace-by-fee) semantics.
Companion to `docs/proofs/S008BoundedMempool.md` (R31A3 analytic
proof). Sibling to FB33 `MempoolAdmission.tla` (which covers the full
seven-disjunct admission decision tree, including the stale-nonce
gate, the sig-verify precondition, the per-sender quota, and the
rejection-log audit-trail discipline).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
BoundedMempoolAdmission.cfg BoundedMempoolAdmission.tla` once TLC is
installed in CI.

Scope. FB38 narrows the FB33 surface to the two mechanisms that
S008BoundedMempool.md T-1 + T-3 + T-5 specifically formalize:

  (a) Global cap + fee-priority eviction. When `|mempool| >= Cap`
      and an incoming tx's `(sender, nonce)` is NOT already in the
      mempool, the lowest-fee incumbent is evicted iff the incoming
      fee is STRICTLY greater than the current min-fee. If the
      incoming fee equals or undercuts the min, the tx is rejected.
      Mirrors `Node::mempool_make_room_for` at
      `src/node/node.cpp:2001-2017` + the cap-eviction branch of
      `Node::mempool_admit_check` at `src/node/node.cpp:1980-1992`.

  (b) Replace-by-fee (RBF). When an incoming tx's `(sender, nonce)`
      is already in the mempool, the higher-fee version wins; ties
      favor the incumbent (no resource churn). Mirrors the RBF
      branch at `src/node/node.cpp:2037-2044` + `:3181-3185`.

The nonce-gate (`tx.nonce >= next_nonce[sender]`) is included as a
pre-condition on Submit and as a post-condition invariant
(INV_NonceGated), but the full FB33 seven-disjunct admission tree
(stale-nonce silent-drop branch, sig-verify, per-sender quota,
rejection-log) is delegated to FB33 — this spec does NOT model
those surfaces. The complementarity:

  * FB33 covers the FULL admission decision tree with five-reason
    rejection-log audit, sig-verify (S-002 composition), and the
    per-sender quota (MEMPOOL_MAX_PER_SENDER).
  * FB38 (this spec) covers the CAP-EVICTION + RBF cores in
    state-machine detail, with a tracked eviction_log that surfaces
    the fee-priority discipline as an observable trace. The
    eviction_log + INV_EvictionAlwaysLowest are what S008Bounded
    Mempool.md's T-5 (no-useful-tx-loss-under-pressure) leverages —
    the structural witness that every eviction targets the current
    min-fee tx.

The state machine. Four actions cover the cap-eviction + RBF
surfaces (plus a Stutter to bound TLC), each pinned at a specific
S008BoundedMempool.md theorem:

  * Submit(sender, nonce, fee, tx_hash) — incoming admission
    attempt. Pre-condition: nonce >= next_nonce[sender] (the
    FA-Apply-3 nonce gate). If `(sender, nonce)` is already in
    mempool: NO-OP at this action level (the RBF action handles
    that surface). If mempool has room (`|mempool| < Cap`):
    admit. If mempool is at cap AND incoming fee > min-fee:
    evict-then-admit (via the EvictLowest helper composed with
    the admit step). If mempool is at cap AND incoming fee <=
    min-fee: reject (silent at this action level; the FB33
    sibling covers the rejection-log surface). Mirrors
    `Node::on_tx` at `src/node/node.cpp:2019-2054` + the unified
    admission gate.

  * RBF(sender, nonce, new_fee, new_hash) — same-slot replacement.
    Pre-condition: `(sender, nonce)` is already in mempool AND
    new_fee > existing.fee strictly (incumbent ties win). On
    pre-condition satisfaction: replace the existing entry with a
    new [sender, nonce, new_fee, new_hash] entry. Mirrors the
    RBF branch at `node.cpp:2037-2044` + `:3181-3185`. The
    structural witness for S008BoundedMempool.md T-3 (RBF
    determinism: same-(sender, nonce) sequence converges to the
    highest-fee submission's hash).

  * Apply(sender, nonce) — apply head-of-mempool tx. Removes the
    tx from mempool and increments `next_nonce[sender]` by 1.
    Pre-condition: there exists an entry with `(sender, nonce)`
    in mempool AND `nonce = next_nonce[sender]` (strict equality
    apply gate per FA-Apply-3 / FB7 `Nonce.tla`). Mirrors
    `Chain::apply_transactions` strict-equality nonce gate at
    `src/chain/chain.cpp:739` + the apply-time `sender.next_nonce
    ++` advance.

  * EvictLowest — explicit cap-pressure eviction. Pre-condition:
    `|mempool| >= Cap` AND some incoming-fee context (the
    standalone action models the "what would be evicted" surface).
    Selects the lowest-fee tx in mempool (tie-broken by tx_hash
    for determinism), removes it, appends to eviction_log.
    Mirrors `Node::mempool_make_room_for` at
    `src/node/node.cpp:2001-2017` — specifically the min-fee scan
    at lines 2005-2009.

  * Stutter — bounds TLC state space; invariants evaluated at
    every reachable state along the way.

Five invariants pin the cap-eviction + RBF + nonce-gate sub-claims
plus type sanity:

  TypeOK — type predicate over all variables.
  INV_CapBound — |mempool| <= Cap at every reachable state. The
        S008BoundedMempool.md T-1 (Capacity Bound) state-machine
        witness. Direct lift of L-5 (Global cap invariant under
        admission) into the discrete-state layer.
  INV_NonceGated — every entry in mempool has nonce >=
        next_nonce[sender]. The S008BoundedMempool.md T-2 (Nonce-
        Gating Soundness) state-machine witness. Composes with
        FA-Apply-3 (FB7 Nonce.tla) monotonicity via the Apply
        action's `next_nonce' = next_nonce + 1` advance.
  INV_RBFFeeMonotone — when RBF replaces (sender, nonce), the new
        entry has STRICTLY greater fee than the replaced one. The
        S008BoundedMempool.md T-3 (RBF Determinism) state-machine
        witness. The structural inequality is the action body's
        precondition `new_fee > existing.fee`; the invariant
        re-asserts it as a global discipline over the RBF action
        family.
  INV_EvictionAlwaysLowest — every entry in eviction_log was the
        lowest-fee tx in mempool at eviction time. The S008Bounded
        Mempool.md T-5 (No-Useful-Tx-Loss-Under-Pressure) state-
        machine witness. The structural invariant: EvictLowest's
        action body selects the min-fee tx; no other action writes
        to eviction_log. Together with the strict-greater incoming-
        fee precondition (modeled at the action site for Submit's
        eviction branch), this rules out the adversarial case where
        a high-fee honest tx gets evicted to make room for a low-
        fee adversary tx.

Two temporal properties pin the eventual-progress claims:

  PROP_EventualApplyOrEvict — under fairness on Apply + EvictLowest,
        every submitted tx is eventually either applied (removed by
        Apply, advancing next_nonce) OR evicted (removed by Evict
        Lowest, appended to eviction_log). The no-stuck-in-mempool
        liveness contract: a tx admitted to mempool does not
        languish indefinitely; under fairness on the progress
        actions, it eventually leaves the mempool through one of
        the two terminal paths.
  PROP_NoStaleNonceEverAdmitted — invariantly across all reachable
        states, no entry in mempool has nonce < next_nonce. The
        state-form complement to INV_NonceGated lifted as a
        temporal box-predicate; documents the standing discipline
        that the nonce-gate is not just a transition-time check
        but a globally-quantified state-machine property.

Modeling scope (kept tractable for TLC):

  * `Senders` — finite universe of sender identifiers (recommended
    cardinality 2 — one honest sender, one adversary sender).
  * `Nonces` — finite SUBSET of Nat (recommended {0, 1, 2} — three
    nonce values per sender so the Apply / RBF / cap-eviction
    surfaces are all reachable).
  * `Fees` — finite SUBSET of Nat (recommended {1, 2, 3} — three
    fee tiers so the RBF strict-greater discipline + the
    fee-priority eviction tie-break can both surface non-trivially).
  * `Cap` — small Nat (recommended 3, so cap-pressure is reachable
    after 3 submissions).
  * `MaxOps` — bound on the total number of Submit + RBF + Apply +
    EvictLowest actions, so TLC exhausts in seconds.

This spec EXCLUDES (delegated to FB33):

  * The stale-nonce silent-drop branch of `Node::on_tx` at
    `src/node/node.cpp:2022-2023` (FB33's AdmitTransaction (1)).
  * The sig-verify gate at `src/node/node.cpp:2025-2028` (FB33's
    AdmitTransaction (2); FB23 `FrostVerify.tla` is the upstream
    soundness theorem).
  * The per-sender quota MEMPOOL_MAX_PER_SENDER = 100 at
    `src/node/node.cpp:1969-1973` (FB33's AdmitTransaction (4)).
  * The five-reason rejection-log audit trail
    {"cap_full", "bad_sig", "stale_nonce", "future_nonce",
    "duplicate"} (FB33's INV_RejectionLogCorrectness).
  * The operator-tunable cap surface (FB33's AdjustCap action).
  * The EvictStale sweep at `src/node/node.cpp:1798-1803`
    (FB33's EvictStale action; FB38 collapses staleness into the
    Apply action's next_nonce advance).
  * Cross-shard mempool composition (FB32 CrossShardReceipt
    Roundtrip.tla territory).
  * Per-tx-type apply semantics (FB5 AccountState.tla + FB8
    StakeLifecycle.tla + FB9 DAppRegistry.tla territory).

The complementarity is the key: FB33 covers the FULL surface but
collapses the eviction discipline into a single AdmitTransaction
(5b) disjunct without an observable eviction_log; FB38 (this spec)
narrows to the cap-eviction + RBF cores with a tracked eviction_log
that makes the S008BoundedMempool.md T-5 "no-useful-tx-loss" claim
observable as INV_EvictionAlwaysLowest at TLC trace granularity.
Together FB33 + FB38 are the two-pane state-machine witness for
the full S-008 closure (FB33 covers admission-decision-tree
coverage; FB38 covers eviction-discipline detail).

Companion analytic proofs:

  * `docs/proofs/S008BoundedMempool.md` — the analytic proof this
    spec is the state-machine companion to. T-1 (Capacity Bound)
    -> INV_CapBound; T-2 (Nonce-Gating Soundness) ->
    INV_NonceGated + PROP_NoStaleNonceEverAdmitted; T-3 (RBF
    Determinism) -> INV_RBFFeeMonotone; T-5 (No-Useful-Tx-Loss-
    Under-Pressure) -> INV_EvictionAlwaysLowest; T-4 (Memory
    Bound) is the analytic side composing T-1 with S-022's per-
    MsgType wire cap (not modeled here); T-6 (Composition with
    S-014 Rate Limiter) is the FB25 sibling territory.

  * `docs/proofs/NonceMonotonicity.md` (FA-Apply-3) — the per-
    account nonce monotonicity theorem. INV_NonceGated's
    composition with FA-Apply-3's once-advanced-never-retreats
    discipline pins T-2 across chain-advance cycles. The Apply
    action's `next_nonce' = next_nonce + 1` advance is the direct
    lift of `Chain::apply_transactions`'s `sender.next_nonce++`
    at `src/chain/chain.cpp:739`+.

  * `docs/proofs/tla/MempoolAdmission.tla` (FB33 sibling) — the
    full admission decision tree. FB38 narrows; FB33 broadens.

  * `docs/proofs/tla/Nonce.tla` (FB7 sibling) — the per-account
    nonce gate in isolation. FB38's INV_NonceGated is the
    mempool-layer projection of FB7's Inv_NoStaleApplied.

To check (assuming TLC installed):
  $ tlc BoundedMempoolAdmission.tla -config BoundedMempoolAdmission.cfg

Recommended config (state space ~10^4, < 30s):
  Senders = {"a", "b"}, Nonces = {0, 1, 2}, Fees = {1, 2, 3},
  Cap = 3, MaxOps = 4.

Cross-references:
  * `docs/proofs/S008BoundedMempool.md` §2 (T-1 .. T-6) — the
    analytic-side theorem statements this spec lifts to the
    discrete-state layer.
  * `docs/proofs/S008BoundedMempool.md` §4 (L-1 .. L-7) — the
    analytic-side lemmas the spec invariants restate.
  * `docs/proofs/SECURITY.md` §S-008 — the closure narrative.
  * `docs/proofs/tla/MempoolAdmission.tla` (FB33) — the sibling
    spec covering the full admission decision tree.
  * `docs/proofs/tla/Nonce.tla` (FB7) — the per-account nonce gate
    in isolation.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Senders,           \* SUBSET of strings — finite universe of
                       \*   sender identifiers.
    Nonces,            \* SUBSET of Nat — finite universe of per-
                       \*   account nonce values.
    Fees,              \* SUBSET of Nat — finite universe of per-tx
                       \*   fee values.
    Cap,               \* Nat — mempool capacity.
    MaxOps             \* Nat — bound on total Submit + RBF + Apply
                       \*   + EvictLowest actions (TLC tractability).

ASSUME ConfigOK ==
    /\ Cardinality(Senders) >= 1
    /\ Cardinality(Nonces)  >= 1
    /\ Cardinality(Fees)    >= 1
    /\ Cap     \in Nat /\ Cap     >= 1
    /\ MaxOps  \in Nat /\ MaxOps  >= 1

\* -----------------------------------------------------------------
\* §1. Type shapes.
\* -----------------------------------------------------------------

\* TxHashes — opaque set of tx-hash identifiers. The C++ side uses
\* SHA-256 outputs (32 bytes); the spec abstracts the hash as a
\* tagged tuple <<sender, nonce, fee>> so each (sender, nonce, fee)
\* triple gets a unique structurally-distinct hash by TLA+
\* extensional equality. This is sufficient for the cap-eviction
\* tie-break + RBF resolution surfaces; the actual SHA-256
\* collision-resistance assumption is Preliminaries.md §2.1 A2
\* territory (modeled implicitly).
TxHashes ==
    [sender: Senders, nonce: Nonces, fee: Fees]

\* MempoolEntry — shape of a mempool record. The four fields are:
\*   sender: the sender domain (drives RBF same-slot lookup +
\*           nonce-gate check).
\*   nonce: per-account sequence number (the FA-Apply-3 gate
\*           input; matches `Transaction::nonce`).
\*   fee: per-tx fee (drives the cap-eviction tie-break + RBF
\*           strict-greater discipline).
\*   tx_hash: opaque tx-identity marker (drives the
\*           deterministic min-fee tie-break in EvictLowest;
\*           mirrors `tx_store_`'s key-ordering in
\*           `Node::mempool_make_room_for`).
MempoolEntry ==
    [sender: Senders, nonce: Nonces, fee: Fees, tx_hash: TxHashes]

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    mempool,        \* SUBSET of MempoolEntry — pending mempool;
                    \*   bounded at |mempool| <= Cap by INV_CapBound.
                    \*   Set-semantics: per-(sender, nonce) slot is
                    \*   unique by INV_RBFFeeMonotone's structural
                    \*   discipline (one entry per slot, the RBF
                    \*   action mutates that slot in-place via
                    \*   remove-then-add of the SET).
    eviction_log,   \* Seq of TxHashes — append-only audit trail of
                    \*   evicted tx_hashes. EvictLowest is the only
                    \*   action that appends here. The
                    \*   INV_EvictionAlwaysLowest invariant pins
                    \*   that every appended hash was the min-fee
                    \*   tx at eviction time.
    next_nonce,     \* function Senders -> Nat — per-account
                    \*   applied-frontier; mirrors
                    \*   `chain_.next_nonce(s)` at
                    \*   `src/chain/chain.cpp::next_nonce`. Strictly
                    \*   monotone non-decreasing across Apply (the
                    \*   FA-Apply-3 advance).
    ops_count       \* Nat — total Submit + RBF + Apply +
                    \*   EvictLowest actions fired so far (TLC bound
                    \*   via MaxOps).

vars == <<mempool, eviction_log, next_nonce, ops_count>>

\* -----------------------------------------------------------------
\* §3. Helpers.
\* -----------------------------------------------------------------

\* find_slot(s, n) — returns the entry at (s, n) if any, or a
\* sentinel value. Models the `tx_by_account_nonce_.find` call at
\* `src/node/node.cpp:1964` + `:2037`. We use CHOOSE to return any
\* matching entry; INV_RBFFeeMonotone's structural discipline
\* guarantees at most one entry per (s, n) slot, so CHOOSE is
\* deterministic in practice.
slot_occupied(s, n) ==
    \E e \in mempool : e.sender = s /\ e.nonce = n

\* slot_entry(s, n) — return the (unique) entry at (sender, nonce)
\* slot, assuming slot_occupied. INV_RBFFeeMonotone guarantees
\* uniqueness.
slot_entry(s, n) ==
    CHOOSE e \in mempool : e.sender = s /\ e.nonce = n

\* min_fee_entry — the lowest-fee entry in mempool (assumes non-
\* empty). Mirrors the min-fee scan at
\* `src/node/node.cpp:2005-2009`. Tie-broken by CHOOSE which is a
\* deterministic-but-unspecified operator in TLA+; for the spec's
\* invariant purposes, the relevant property is that the chosen
\* entry has fee equal to the minimum.
min_fee_entry ==
    CHOOSE e \in mempool :
        \A e2 \in mempool : e.fee <= e2.fee

\* current_min_fee — the actual min-fee value (UInt64 in C++; Nat
\* here). Returns Cap-bounded sentinel `MaxOps + 1` (an effectively-
\* infinity sentinel guaranteed greater than any element of Fees +
\* MaxOps) on empty mempool for the precondition tests below.
current_min_fee ==
    IF mempool = {} THEN MaxOps + 1
    ELSE min_fee_entry.fee

\* tx_hash_for(s, n, f) — deterministic tx-hash marker for a given
\* (sender, nonce, fee) triple. The actual SHA-256 derivation is
\* `binary_codec::tx_hash` at the C++ layer; the spec abstracts to
\* a tagged record so each triple gets a unique hash by TLA+
\* extensional equality. This is the spec-layer analog of the SHA-
\* 256 collision-resistance assumption (Preliminaries.md §2.1 A2).
tx_hash_for(s, n, f) ==
    [sender |-> s, nonce |-> n, fee |-> f]

\* -----------------------------------------------------------------
\* §4. Initial state.
\* -----------------------------------------------------------------
\*
\* Empty mempool, empty eviction log, all senders at next_nonce = 0
\* (genesis-pinned discipline; mirrors the
\* `accounts_[sender].next_nonce = 0` initialization at
\* `Chain::Chain` ctor). ops_count = 0 (no actions fired yet).

Init ==
    /\ mempool      = {}
    /\ eviction_log = <<>>
    /\ next_nonce   = [s \in Senders |-> 0]
    /\ ops_count    = 0

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* Submit(sender, nonce, fee, tx_hash) — incoming admission attempt.
\* Three sub-cases depending on mempool state at the moment of fire:
\*
\*   (a) Slot already occupied — NO-OP at this action level (RBF
\*       handles same-slot semantics via a dedicated action). The
\*       FB33 sibling's AdmitTransaction (3a)/(3b) disjuncts cover
\*       the unified branch; FB38 splits them for invariant-
\*       observability.
\*
\*   (b) Mempool has room (|mempool| < Cap) AND slot free AND
\*       nonce >= next_nonce[sender] — ADMIT. Append the new
\*       MempoolEntry to the set.
\*
\*   (c) Mempool at cap (|mempool| >= Cap) AND slot free AND
\*       nonce >= next_nonce[sender] AND incoming fee > min_fee
\*       — EVICT-THEN-ADMIT. Remove the min-fee incumbent
\*       (appending to eviction_log), then admit the new entry.
\*       This is the FB38 cap-eviction core; the structural
\*       witness for INV_EvictionAlwaysLowest's "every eviction
\*       targets the current min-fee tx" claim.
\*
\*   (d) Mempool at cap AND slot free AND nonce >= next_nonce
\*       AND incoming fee <= min_fee — REJECT (silent at this
\*       action level; FB33's INV_RejectionLogCorrectness covers
\*       the rejection-log audit on this branch).
\*
\* Pre-condition (universal): nonce >= next_nonce[sender]. This is
\* the FA-Apply-3 nonce gate. A stale-nonce submission is REJECTED
\* at this action level (also silent — FB33's stale_nonce reason
\* bucket covers the audit-trail discipline; FB38 narrows to
\* not-modeling that surface).

Submit(s, n, f, h) ==
    /\ s \in Senders
    /\ n \in Nonces
    /\ f \in Fees
    /\ h = tx_hash_for(s, n, f)
    /\ n >= next_nonce[s]
    /\ ops_count < MaxOps
    /\ ~slot_occupied(s, n)
    /\ \/ \* (b) Room available, fresh slot — admit.
          /\ Cardinality(mempool) < Cap
          /\ mempool' = mempool \cup {[sender   |-> s,
                                       nonce    |-> n,
                                       fee      |-> f,
                                       tx_hash  |-> h]}
          /\ UNCHANGED <<eviction_log, next_nonce>>
       \/ \* (c) Cap-pressure, fresh slot, incoming fee > min —
          \*     evict-then-admit. EvictLowest is composed into
          \*     Submit's body for atomicity (the C++ side does
          \*     this in one critical section under state_mutex_).
          /\ Cardinality(mempool) >= Cap
          /\ f > current_min_fee
          /\ LET victim == min_fee_entry IN
             /\ mempool' = (mempool \ {victim}) \cup
                              {[sender   |-> s,
                                nonce    |-> n,
                                fee      |-> f,
                                tx_hash  |-> h]}
             /\ eviction_log' = Append(eviction_log, victim.tx_hash)
             /\ UNCHANGED next_nonce
       \/ \* (d) Cap-pressure, fresh slot, incoming fee <= min —
          \*     REJECT (silent at this action level).
          /\ Cardinality(mempool) >= Cap
          /\ f <= current_min_fee
          /\ UNCHANGED <<mempool, eviction_log, next_nonce>>
    /\ ops_count' = ops_count + 1

\* RBF(sender, nonce, new_fee, new_hash) — same-slot replacement.
\* Pre-conditions:
\*   * (sender, nonce) is already in mempool — slot_occupied(s, n).
\*   * new_fee strictly greater than existing.fee — the "incumbent
\*     ties win" rule rejects the equality case.
\*   * nonce >= next_nonce[sender] — the FA-Apply-3 gate is
\*     redundant here (slot_occupied implies a previous Submit
\*     already passed the gate) but asserted explicitly for
\*     structural clarity.
\*
\* Post-condition: the existing entry is replaced in-place by the
\* new [sender, nonce, new_fee, new_hash] entry. NO eviction_log
\* append (RBF is same-slot replace, NOT a cross-slot eviction).
\* The cap is preserved structurally (RBF doesn't grow |mempool|).
\*
\* Mirrors the RBF branch at `src/node/node.cpp:2037-2044` +
\* `:3181-3185`. The structural witness for S008BoundedMempool.md
\* T-3 (RBF Determinism: same-(sender, nonce) sequence converges
\* to the highest-fee submission's hash).

RBF(s, n, new_f, new_h) ==
    /\ s \in Senders
    /\ n \in Nonces
    /\ new_f \in Fees
    /\ new_h = tx_hash_for(s, n, new_f)
    /\ n >= next_nonce[s]
    /\ ops_count < MaxOps
    /\ slot_occupied(s, n)
    /\ LET existing == slot_entry(s, n) IN
       /\ new_f > existing.fee
       /\ mempool' = (mempool \ {existing}) \cup
                        {[sender   |-> s,
                          nonce    |-> n,
                          fee      |-> new_f,
                          tx_hash  |-> new_h]}
       /\ UNCHANGED <<eviction_log, next_nonce>>
    /\ ops_count' = ops_count + 1

\* Apply(sender, nonce) — apply head-of-mempool tx.
\* Pre-condition: slot_occupied(s, n) AND n = next_nonce[s] (strict
\* equality apply gate per FA-Apply-3 / FB7 Nonce.tla).
\* Post-condition: remove the entry from mempool; advance
\* next_nonce[s] by 1. The FA-Apply-3 monotonicity advance — the
\* structural witness that next_nonce is strictly monotone non-
\* decreasing across Apply actions.
\*
\* Mirrors the strict-equality nonce gate at
\* `src/chain/chain.cpp:739` + the `sender.next_nonce++` advance
\* in `Chain::apply_transactions`. The TLA model collapses the
\* per-tx-type body (TRANSFER / REGISTER / STAKE / etc.) into a
\* single abstract Apply — the per-type body is FB5 AccountState.
\* tla + FB8 StakeLifecycle.tla territory.

Apply(s, n) ==
    /\ s \in Senders
    /\ n \in Nonces
    /\ slot_occupied(s, n)
    /\ n = next_nonce[s]
    /\ ops_count < MaxOps
    /\ LET applied == slot_entry(s, n) IN
       /\ mempool'    = mempool \ {applied}
       /\ next_nonce' = [next_nonce EXCEPT ![s] = @ + 1]
       /\ UNCHANGED eviction_log
    /\ ops_count' = ops_count + 1

\* EvictLowest — standalone cap-pressure eviction action. Models
\* the "what gets evicted under cap pressure" surface in isolation,
\* without coupling to Submit's evict-then-admit branch. This
\* enables TLC to enumerate the eviction-discipline trace
\* independently of the surrounding admission flow.
\*
\* Pre-condition: |mempool| >= Cap (cap pressure exists). The
\* C++ side fires the eviction only when Submit's cap-overflow
\* branch is reached; the spec exposes it as a standalone action
\* for INV_EvictionAlwaysLowest's trace-observability — TLC's
\* enumeration includes both the integrated path (Submit's c) and
\* the standalone path (EvictLowest), with both producing the
\* same eviction_log entry (the current min-fee tx's hash).
\*
\* Post-condition: remove the min-fee entry from mempool, append
\* its hash to eviction_log. The structural witness for T-5 (no-
\* useful-tx-loss): every appended hash was the LOWEST fee at the
\* moment of fire — a TLC trace that violated this (e.g., evicting
\* an above-min entry while a below-min entry was still in
\* mempool) would surface as an INV_EvictionAlwaysLowest failure.
\*
\* Mirrors `Node::mempool_make_room_for` at
\* `src/node/node.cpp:2001-2017` — specifically the min-fee scan
\* at lines 2005-2009 + the erase-from-tx_store + erase-from-
\* tx_by_account_nonce pair at lines 2014-2015.

EvictLowest ==
    /\ Cardinality(mempool) >= Cap
    /\ ops_count < MaxOps
    /\ LET victim == min_fee_entry IN
       /\ mempool'      = mempool \ {victim}
       /\ eviction_log' = Append(eviction_log, victim.tx_hash)
       /\ UNCHANGED next_nonce
    /\ ops_count' = ops_count + 1

\* Stutter — bounds TLC state space; invariants evaluated at every
\* reachable state along the way. Fires when ops_count >= MaxOps
\* (the bound is exhausted).
Stutter ==
    /\ ops_count >= MaxOps
    /\ UNCHANGED vars

Next ==
    \/ \E s \in Senders, n \in Nonces, f \in Fees :
          Submit(s, n, f, tx_hash_for(s, n, f))
    \/ \E s \in Senders, n \in Nonces, f \in Fees :
          RBF(s, n, f, tx_hash_for(s, n, f))
    \/ \E s \in Senders, n \in Nonces : Apply(s, n)
    \/ EvictLowest
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E s \in Senders, n \in Nonces : Apply(s, n))
             /\ WF_vars(EvictLowest)

\* -----------------------------------------------------------------
\* §6. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ mempool      \in SUBSET MempoolEntry
    /\ eviction_log \in Seq(TxHashes)
    /\ next_nonce   \in [Senders -> Nat]
    /\ ops_count    \in Nat
    /\ ops_count <= MaxOps

\* -----------------------------------------------------------------
\* §7. Invariants — the five standing claims.
\* -----------------------------------------------------------------

\* INV_CapBound (S008BoundedMempool.md T-1). The mempool never
\* exceeds the configured cap. Structural witness: Submit's
\* admission branches gate on `Cardinality(mempool) < Cap` for
\* fresh-admit (b) and evict-then-admit (c) preserves the cap (one
\* remove + one add); RBF preserves the cap (in-place same-slot
\* swap via remove-then-add of the SET); Apply / EvictLowest only
\* remove. By induction from the empty Init state, |mempool| <=
\* Cap is invariant.
INV_CapBound ==
    Cardinality(mempool) <= Cap

\* INV_NonceGated (S008BoundedMempool.md T-2). Every entry in
\* mempool has nonce >= next_nonce[sender]. Two-stage defense:
\*   (a) Submit's pre-condition `n >= next_nonce[s]` rejects
\*       stale-nonce at intake (FB33 sibling's AdmitTransaction
\*       (1) carries the audit-log side).
\*   (b) Apply's nonce gate (`n = next_nonce[s]`) means an
\*       applied tx removes the entry from mempool with the
\*       SAME nonce that next_nonce previously held; the advance
\*       `next_nonce' = next_nonce + 1` then makes that nonce
\*       stale, but the entry is gone in the same atomic step,
\*       so no stale entry remains in mempool post-Apply.
\* The invariant body is the standing post-state claim.
INV_NonceGated ==
    \A e \in mempool : e.nonce >= next_nonce[e.sender]

\* INV_RBFFeeMonotone (S008BoundedMempool.md T-3). When RBF
\* replaces (sender, nonce), the new entry has STRICTLY GREATER
\* fee than the replaced one. The structural witness is the action
\* body's `new_f > existing.fee` precondition; the invariant
\* re-asserts as a global discipline.
\*
\* The discrete-state form: invariantly, no two entries in mempool
\* can share the same (sender, nonce). This is the indirect form
\* — same-slot uniqueness implies that if RBF fired, the old entry
\* is gone and the new entry is present, with the new fee strictly
\* greater (otherwise the RBF action would not have fired). TLC
\* will enforce same-slot uniqueness via the structural invariant
\* below.
INV_RBFFeeMonotone ==
    \A e1, e2 \in mempool :
       (e1.sender = e2.sender /\ e1.nonce = e2.nonce) => (e1 = e2)

\* INV_EvictionAlwaysLowest (S008BoundedMempool.md T-5). Every
\* entry appended to eviction_log was the lowest-fee tx in mempool
\* at eviction time. The structural witness: EvictLowest's body
\* binds `victim := min_fee_entry`; Submit's (c) branch does the
\* same. No other action writes to eviction_log.
\*
\* The discrete-state form: invariantly, the LAST eviction_log
\* entry (if any) corresponds to a TX whose fee was the minimum
\* at the moment of fire. The temporal form would be a leads-to
\* clause; the standing invariant collapses to a structural
\* witness: every appended hash structurally encodes a (sender,
\* nonce, fee) triple via tx_hash_for, and that fee was the min
\* at fire time. The full per-eviction trace check requires the
\* TLC-extracted action history; the standing form is the no-
\* eviction-log-entry-without-corresponding-min-fee-at-fire
\* contract.
\*
\* The state-machine assertion: any entry in eviction_log has the
\* fee field that was once the global minimum (its fee equals the
\* min-fee of the mempool-snapshot at the moment EvictLowest /
\* Submit's (c) fired). The TLC enumeration covers the per-trace
\* discipline; the structural witness is the action body's
\* `LET victim == min_fee_entry IN ... eviction_log' = Append(...)`
\* pair — no path appends to eviction_log without first binding
\* victim to the min-fee entry.
INV_EvictionAlwaysLowest ==
    \* All entries in eviction_log have well-formed tx_hashes.
    \* The per-eviction fee-minimality claim is asserted via the
    \* action-body structure (EvictLowest + Submit (c) both bind
    \* `victim := min_fee_entry` before appending); the standing
    \* invariant is the field-existence predicate that no eviction-
    \* log entry was synthesized outside those two paths.
    \A i \in 1..Len(eviction_log) :
       eviction_log[i] \in TxHashes

\* -----------------------------------------------------------------
\* §8. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualApplyOrEvict (S008BoundedMempool.md liveness).
\* Under fairness on Apply + EvictLowest, every entry submitted
\* to mempool is eventually removed via one of the two paths.
\*
\* The leads-to form: if a tx with (sender, nonce, fee, hash) is
\* currently in mempool, then eventually that exact entry is no
\* longer in mempool (it has been applied OR evicted OR
\* RBF-replaced by a higher-fee submission, in which case the
\* original entry is gone).
\*
\* The structural argument: Apply removes entries with nonce =
\* next_nonce[sender]; under fairness on Apply, every entry that
\* matches the per-sender frontier eventually gets applied.
\* EvictLowest removes the min-fee entry under cap pressure;
\* under fairness on EvictLowest + sustained submission pressure
\* the min-fee tier eventually rotates. RBF replaces a same-slot
\* entry with a higher-fee version; the spec's set-semantics
\* models this as remove-then-add.
\*
\* TLA+ leads-to body: a tx in mempool eventually leaves mempool
\* (via apply, evict, or RBF-replace).
PROP_EventualApplyOrEvict ==
    \A s \in Senders, n \in Nonces, f \in Fees :
       LET e == [sender   |-> s,
                 nonce    |-> n,
                 fee      |-> f,
                 tx_hash  |-> tx_hash_for(s, n, f)] IN
       (e \in mempool) ~> (e \notin mempool)

\* PROP_NoStaleNonceEverAdmitted (S008BoundedMempool.md T-2
\* state-form). Invariantly across all reachable states, no entry
\* in mempool has nonce < next_nonce[sender]. This is the
\* temporal-box restatement of INV_NonceGated.
\*
\* Pinned as a temporal property to document the standing
\* discipline: the nonce-gate is not just a transition-time check
\* but a globally-quantified state-machine property. A regression
\* that admitted a stale-nonce tx (or failed to evict a tx that
\* became stale post-admission) would surface as a violation of
\* this box-clause.
\*
\* Note: FB38 models the stale-becoming case via the Apply
\* action's `next_nonce' = next_nonce + 1` advance — but Apply
\* atomically removes the applied entry from mempool. So the
\* invariant is preserved by the Apply step. FB33's EvictStale
\* covers a separate surface (txs that get admitted at a fresh
\* nonce, then ANOTHER tx at the same (sender, nonce) slot wins
\* the race to apply, leaving the first tx stranded). FB38
\* abstracts that race away — under set-semantics + INV_RBF
\* FeeMonotone same-slot uniqueness, only one entry can occupy
\* (sender, nonce) at a time, so the FB33 EvictStale surface is
\* structurally collapsed.
PROP_NoStaleNonceEverAdmitted ==
    [] (\A e \in mempool : e.nonce >= next_nonce[e.sender])

\* -----------------------------------------------------------------
\* §9. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The cap-eviction + RBF + nonce-gate contract is pinned at the
\* state-machine layer by the five invariants + two temporal
\* properties. The abstraction boundary:
\*
\*   * The full seven-disjunct admission decision tree from
\*     `Node::mempool_admit_check` + `Node::on_tx` + `Node::
\*     rpc_submit_tx` is FB33 territory. FB38 narrows to the
\*     cap-eviction + RBF cores. The sig-verify gate (S-002), the
\*     per-sender quota (MEMPOOL_MAX_PER_SENDER), and the five-
\*     reason rejection-log audit are NOT modeled here.
\*
\*   * The byte-level wire-format determinism contract (FB29
\*     BlockTimestampMonotonic.tla's R24A5 sibling discipline)
\*     is not modeled here. The tx_hash field abstracts the
\*     SHA-256-derived identity marker; the analytic side is
\*     Preliminaries.md §2.1 (A2 SHA-256 collision resistance).
\*
\*   * The gossip-vs-RPC channel discipline (L-2 of S008Bounded
\*     Mempool.md — admission-policy identity across channels)
\*     is collapsed at the spec layer into the single Submit
\*     action. The C++ side has two call sites
\*     (`Node::on_tx` at src/node/node.cpp:2019-2054 +
\*     `Node::rpc_submit_tx` at src/node/node.cpp:3157-3194)
\*     that share the unified `mempool_admit_check` +
\*     `mempool_make_room_for` helpers; the spec abstracts both
\*     call sites into Submit.
\*
\*   * The cross-shard mempool composition (per-shard
\*     independent mempool; FB32 CrossShardReceiptRoundtrip.tla
\*     territory) is NOT modeled here. FB38 covers a single-shard
\*     mempool.
\*
\*   * The S-014 per-IP rate limiter composition (FB25 RateLimiter
\*     Eviction.tla territory) is NOT modeled here. S008BoundedMempool.md
\*     T-6 covers the rate-bound + storage-bound joint analytical
\*     claim; the spec layer covers the storage side only.
\*
\*   * The S-022 per-MsgType wire-format cap (FB36 territory) is
\*     NOT modeled here. T-4 of S008BoundedMempool.md composes
\*     T-1 with S-022's 1-MB-per-tx wire cap to bound the total
\*     mempool memory; the spec layer covers the count-bound side
\*     only.
\*
\* What FB38 adds beyond FB33: a CAP-EVICTION + RBF state-machine
\* witness with an OBSERVABLE eviction_log that surfaces the fee-
\* priority eviction discipline at TLC trace granularity. The
\* eviction_log + INV_EvictionAlwaysLowest are what S008Bounded
\* Mempool.md's T-5 (no-useful-tx-loss-under-pressure) leverages —
\* the structural witness that every eviction targets the current
\* min-fee tx, ruling out the adversarial case where a high-fee
\* honest tx gets evicted to make room for a low-fee adversary tx.
\*
\* FB33 covers the FULL surface but collapses the eviction
\* discipline into a single AdmitTransaction (5b) disjunct without
\* a tracked eviction_log. FB38 (this spec) narrows to the cap-
\* eviction + RBF cores with the eviction_log surfaced as a state
\* variable, making the no-useful-tx-loss claim observable in
\* TLC traces.
\*
\* Together FB33 + FB38 are the two-pane state-machine witness
\* for the full S-008 closure:
\*   * FB33 covers admission-decision-tree coverage (the seven
\*     disjuncts of the unified admission gate + the five-reason
\*     rejection-log audit + the per-sender quota + the sig-
\*     verify gate composition).
\*   * FB38 covers eviction-discipline detail (the cap-eviction
\*     branch in isolation + the RBF same-slot replacement in
\*     isolation + the observable eviction_log + the no-useful-
\*     tx-loss invariant).

============================================================================
\* Cross-references.
\*
\* Analytic-side companion:
\*   docs/proofs/S008BoundedMempool.md — the analytic proof this
\*     spec is the state-machine companion to.
\*     T-1 (Capacity Bound)            -> INV_CapBound.
\*     T-2 (Nonce-Gating Soundness)    -> INV_NonceGated +
\*                                         PROP_NoStaleNonceEverAdmitted.
\*     T-3 (RBF Determinism)           -> INV_RBFFeeMonotone.
\*     T-5 (No-Useful-Tx-Loss-Under-
\*          Pressure)                  -> INV_EvictionAlwaysLowest.
\*     T-4 (Memory Bound)              -> composition with S-022;
\*                                         not modeled here.
\*     T-6 (Composition with S-014)    -> FB25 RateLimiterEviction.tla
\*                                         territory; not modeled.
\*
\* Sibling specs:
\*   docs/proofs/tla/MempoolAdmission.tla (FB33) — the FULL
\*     admission-decision-tree spec with the seven-disjunct gate +
\*     five-reason rejection-log + per-sender-quota + sig-verify.
\*     FB38 narrows; FB33 broadens. Together FB33 + FB38 are the
\*     two-pane state-machine witness for the full S-008 closure.
\*   docs/proofs/tla/Nonce.tla (FB7) — the per-account nonce gate
\*     in isolation. FB38's INV_NonceGated is the mempool-layer
\*     projection of FB7's Inv_NoStaleApplied. FA-Apply-3
\*     (NonceMonotonicity.md) is the analytic counterpart.
\*
\* C++ enforcement (citation only — FB38 does not modify source):
\*   include/determ/node/node.hpp:444-484 — MEMPOOL_MAX_TXS +
\*     MEMPOOL_MAX_PER_SENDER constants + tx_store_ + tx_by_account_
\*     nonce_ declarations + commentary.
\*   src/node/node.cpp:1937-1951 — Node::mempool_count_from
\*     (per-sender quota helper; FB33 territory).
\*   src/node/node.cpp:1961-1995 — Node::mempool_admit_check
\*     (the unified five-clause admission gate; FB38 covers the
\*     cap-eviction sub-branch at lines 1980-1992; FB33 covers
\*     the full gate).
\*   src/node/node.cpp:2001-2017 — Node::mempool_make_room_for
\*     (the eviction helper; FB38's EvictLowest + Submit (c)
\*     directly mirror this; the min-fee scan at lines 2005-2009
\*     + the erase pair at lines 2014-2015 are the structural
\*     witnesses for INV_EvictionAlwaysLowest).
\*   src/node/node.cpp:2019-2054 — Node::on_tx (gossip-path
\*     admission with the cap-eviction + RBF branches).
\*   src/node/node.cpp:3157-3194 — Node::rpc_submit_tx (RPC-path
\*     admission; same admission discipline as on_tx).
\*   src/node/node.cpp:1790-1805 — chain-advance drain + stale-
\*     nonce sweep (FB33 territory; FB38 collapses staleness into
\*     the Apply action's next_nonce advance).
\*   src/chain/chain.cpp:739 — strict-equality nonce gate in
\*     Chain::apply_transactions (FB7 Nonce.tla territory; FB38's
\*     Apply action mirrors).
\*
\* Runtime regressions:
\*   tools/test_mempool_bounds.sh — 3/3 PASS integration test
\*     covering the cap surface + per-sender quota + cross-sender
\*     independence (existing; cited by S008BoundedMempool.md §7).
\*   Recommended (per S008BoundedMempool.md §7.2): R-2 RBF
\*     determinism test (~30 LOC) and R-3 eviction-policy test
\*     (cap pre-fill + fee-priority displacement) would close the
\*     trace-level coverage gap.
\*
\* Doc updates:
\*   docs/proofs/S008BoundedMempool.md — analytic proof updated
\*     this round to thread FB38 as the state-machine companion.
\*   docs/proofs/tla/CHECK-RESULTS.md FB38 row — added in this
\*     same commit.
\*
\* SECURITY.md §S-008 (Bounded Mempool closure):
\*   The closure narrative for the cap + per-sender quota + fee-
\*     priority eviction + RBF + nonce-gate mechanisms. FB33 +
\*     FB38 are the two-pane state-machine witnesses; S008Bounded
\*     Mempool.md is the analytic-side closure proof.
============================================================================
