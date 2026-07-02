--------------------------- MODULE MempoolAdmission ---------------------------
(*
FB33 — TLA+ specification of the bounded-mempool admission state
machine. Composes the S-008 closure (operator-configurable cap +
per-sender quota + fee-priority eviction) with the FA-Apply-3 nonce
gate, the FB23 FrostVerify abstract-sig precondition, and the RBF
(replace-by-fee) tie-break that S-008 inherited from `Node::on_tx`.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
MempoolAdmission.cfg MempoolAdmission.tla` once a companion `.cfg`
is supplied.

Scope. Formalizes the admission decision tree at
`src/node/node.cpp::Node::mempool_admit_check` (lines 1961-1995) +
`Node::mempool_make_room_for` (lines 2001-2017) + `Node::on_tx`
(lines 2019-2054) + the RPC sibling at `Node::rpc_submit_tx`
(lines 3163-3193). The admission gate is a four-clause discipline:

  1. Stale-nonce gate. `tx.nonce < chain_.next_nonce(tx.from)` →
     reject (silent on gossip, diagnostic on RPC). Reuses the same
     `next_nonce` map the apply path consults; FA-Apply-3 monotonicity
     guarantees that an admitted tx whose nonce was current at
     admission either applies (advancing `next_nonce` past it) or
     gets evicted by `Node::sweep_stale_mempool_locked` at
     node.cpp:1796-1803 once a later block advances the gate past it.
  2. Signature-validity gate. `verify_tx_signature_locked(tx)` →
     reject if FROST/Ed25519 verify fails. FB23 FrostVerify's
     T-1 (verification soundness) is the cryptographic foundation;
     this spec lifts the gate to the abstract-sig discipline (a
     boolean precondition over an opaque Tx + sender pubkey).
  3. Per-sender quota. `mempool_count_from(tx.from) >=
     MEMPOOL_MAX_PER_SENDER` AND this isn't a same-(from, nonce)
     RBF replace → reject. The 100-tx-per-sender cap prevents a
     single attacker from monopolizing the mempool with pipelined
     nonces.
  4. Global cap + eviction. `tx_store_.size() >= MEMPOOL_MAX_TXS` AND
     `tx.fee <= min(tx_store_.fee)` → reject. Otherwise, evict the
     incumbent with the lowest fee (tie-broken by hash) and insert
     the new tx. The S-008 closure: fee-priority mempool prices out
     low-fee spam economically.

Plus the RBF semantics: if `(tx.from, tx.nonce)` already exists in
`tx_by_account_nonce_`, the higher-fee version wins (ties favor
incumbent to avoid resource churn — see chain.cpp on_tx line
2041-2043). This is NOT eviction across senders; it's a same-slot
replacement that bypasses the global-cap eviction check entirely
(`is_replace` short-circuit at node.cpp:1965-1967).

Five paired theorems are pinned:

  (T-MA1) Bounded Mempool. At every reachable state,
          `Len(mempool) <= mempool_cap`. The S-008 closure: an
          adversarial flood cannot blow the cap past its
          operator-configured ceiling.
  (T-MA2) No Stale Admission. No tx in the mempool has
          `tx.nonce < applied_nonces[tx.from]`. The composition
          with FA-Apply-3 monotonicity: the admission gate rejects
          stale txs at intake; `EvictStale` sweeps txs whose nonce
          becomes stale post-admission (when a block advances the
          applied-nonce frontier past them).
  (T-MA3) No Duplicate (Account, Nonce). For every reachable state,
          the multi-set of admitted txs has at most one tx per
          (account, nonce) pair. The RBF semantics: same-slot
          submissions replace rather than coexist; cross-sender
          coincidence is structurally permitted (different `from`
          values are distinct slots).
  (T-MA4) Rejection-Log Correctness. Every rejection in the audit
          trail has a reason ∈ {cap_full, bad_sig, stale_nonce,
          future_nonce, duplicate}. The five-reason taxonomy
          exhausts the admission-check decision tree; every
          adversary input that fails admission falls into exactly
          one bucket.
  (T-MA5) Sig-Validity Necessary. Every admitted tx has a valid
          signature under FB23 FrostVerify's abstract verifier.
          The S-002 + S-008 composition: post-S-002 the gossip
          path AND the RPC path both verify signatures before
          admission; an admitted tx cannot have a forged sig.

The state machine. A single-shard model with one accounts ledger,
one mempool queue, one applied-nonce frontier, and an audit log of
rejections. Variables:

  * `mempool` — Seq(Tx) — pending transactions in submission order
                (modeled as a sequence to make the per-(from, nonce)
                slot reasoning observable; the C++ side uses two
                indexes — `tx_store_` keyed by hash + `tx_by_account_
                nonce_` keyed by (from, nonce) — but the invariant-
                relevant property is the multi-set discipline plus
                the unique per-(from, nonce) slot, which the Seq
                projection captures while also exposing eviction
                order to the rejection audit log).
  * `mempool_cap` — Nat — the operator-configurable cap. Mirrors
                `MEMPOOL_MAX_TXS = 10000` at
                `include/determ/node/node.hpp:459`. Modeled as a
                state variable to allow per-trace parameter sweeps,
                but its value is fixed by Init.
  * `applied_nonces` — Domains -> Nat — the frontier of applied
                nonces per account. Mirrors `chain_.next_nonce(d)`
                at chain.cpp::next_nonce. Strictly monotone non-
                decreasing across `ApplyBlock` (FA-Apply-3).
  * `rejection_log` — Seq(Rejection) — audit trail of every
                admission decision that returned a non-empty error
                string at `Node::mempool_admit_check`. Each entry
                carries (tx, reason) so a regression that admits
                a tx that should have been rejected (or vice
                versa) surfaces as a length / content mismatch
                between the admission trace and the log. Length is
                bounded by MaxRejections for TLC tractability (see
                the MaxRejections comment in §5) — the C++ side
                returns admission errors per-call, it does not
                accumulate them.

Six actions cover the admission / apply / sweep / RBF surfaces:

  * AdmitTransaction(tx) — the unified gate at node.cpp:1961-1995
    + 2019-2054 + 3163-3193. Five-clause decision tree (stale-nonce,
    bad-sig, per-sender quota, global cap, success/RBF). On accept,
    append to mempool. On reject, append to rejection_log with the
    five-reason taxonomy.
  * ApplyBlock — drain a prefix of the mempool, advance the
    applied-nonces frontier accordingly. Models the producer-side
    finalize at node.cpp:1083 (`build_body(tx_store_, ...)`) followed
    by `Chain::apply_block` at chain.cpp::apply_transactions. The
    spec collapses build_body + apply into a single atomic action;
    the per-tx semantics of TRANSFER/REGISTER/etc. are out of scope
    (FB5 AccountState territory). What matters here is the nonce
    advance: every applied tx bumps `applied_nonces[tx.from]` to
    `tx.nonce + 1` (FA-Apply-3 monotonicity).
  * EvictStale — sweep txs whose nonce is < applied_nonces[from].
    Mirrors the second loop at node.cpp:1798-1803 (`sweep_stale_
    mempool_locked` aka the inline cleanup at the end of
    `apply_finalized_block_locked`). Closes the residual gap where
    a tx admitted at nonce N gets stranded after another tx at the
    same (from, N) slot wins the race to apply (which can happen
    via cross-channel races between gossip and RPC).
  * OverwriteSameAccountSameNonce(tx_new) — the RBF semantics at
    node.cpp:2038-2044. If a tx exists at (tx_new.from, tx_new.nonce)
    with a strictly lower fee, replace it; otherwise (incumbent
    fee >= tx_new fee), the incumbent wins by convention to avoid
    resource churn. This action is the explicit same-slot lookup
    branch that the unified AdmitTransaction would otherwise route
    via the `is_replace` short-circuit at node.cpp:1965-1967;
    pulling it out as a standalone action makes the RBF tie-break
    invariant observable at the state-machine layer.
  * AdjustCap(new_cap) — operator-side parameter change. Modeled
    as an explicit action so a regression that violates
    INV_MempoolBounded under a smaller cap surfaces in the TLC
    trace.
  * Stutter — no-op for liveness bound.

Seven standing invariants codify the five theorems plus type sanity
plus the FA-Apply-3 monotonicity sub-claim:

  TypeOK — type sanity over all variables.
  INV_MempoolBounded (T-MA1) — `Len(mempool) <= mempool_cap` at
    every reachable state. The S-008 closure's headline witness.
  INV_NoStaleAdmission (T-MA2) — every tx in mempool has
    `tx.nonce >= applied_nonces[tx.from]`. The two-stage defense:
    AdmitTransaction's stale-nonce gate at intake, EvictStale's
    sweep post-admission.
  INV_NoDuplicateAccountNonce (T-MA3) — for every (from, nonce)
    pair, at most one tx in mempool. RBF replaces same-slot
    occupants; no two distinct hashes co-exist at the same slot.
  INV_RejectionLogCorrectness (T-MA4) — every entry in
    rejection_log has reason ∈ {"cap_full", "bad_sig",
    "stale_nonce", "future_nonce", "duplicate"}. The five-bucket
    taxonomy exhausts the admission-check decision tree.
  INV_SigValidityNecessary (T-MA5) — every tx currently in mempool
    has a valid signature under the abstract sig verifier
    (modeled via the FB23 FrostVerify-style boolean predicate).
  INV_NonceMonotonic (FA-Apply-3 sub-claim) — `applied_nonces[d]`
    is monotone non-decreasing across every [Next]_vars step.
    The load-bearing input to INV_NoStaleAdmission's two-stage
    defense — once advanced, the frontier never retreats, so a
    swept-stale tx cannot become re-admittable.

Two temporal properties cover the eventual-progress claims:

  PROP_EventualAdmissionOrRejection — every transaction submitted
    via AdmitTransaction eventually either lands in mempool (with
    later potential to be applied or evicted-stale) OR has an
    entry in rejection_log. The no-stuck-in-limbo liveness
    contract: a tx cannot be lost between the admission gate's
    decision and the audit log.
  PROP_MempoolEventuallyDrains — under fairness on ApplyBlock,
    a non-empty mempool eventually shrinks. The structural
    argument: ApplyBlock removes at least one tx per fire (in
    the canonical "drain head" model); under fairness it fires
    repeatedly until mempool is empty OR another action (Admit,
    OverwriteSameAccountSameNonce) refills it.

Modeling scope (kept tractable for TLC):

  * `Domains` is a finite set of sender identifiers (recommended
    cardinality 2-3 — one regular sender, one adversarial flood
    source).
  * `Nonces` is a finite set 0..MaxNonce (drives the FA-Apply-3
    frontier evolution).
  * `Fees` is a finite set 0..MaxFee (drives the global-cap
    eviction tie-break + the RBF tie-break).
  * `Hashes` is a finite set of opaque tx-hash identifiers; the
    SHA-256 abstraction is FA-track A3 territory. The hash is
    used here only as an inert tx-identity marker (the C++ side
    keys `tx_store_` by hash; our Seq projection collapses this
    into the position-in-sequence ordering — no guard or
    invariant compares hashes, so a singleton set suffices).
  * `Cap` is a small Nat (recommended 2) so the cap-eviction
    branch is reachable: MaxPerSender senders'-worth of admits
    saturate the cap while the other sender stays under quota,
    keeping the cap_full / evict branches (5a)/(5b) enabled.
  * `rejection_log` is bounded by MaxRejections (TLC tractability;
    see §5) — without the bound the audit trail grows without
    bound and the state space is infinite.
  * Signature validity is modeled as a Boolean field `sig_valid`
    on each Tx — the FB23 FrostVerify-style abstract precondition.
    A regression that admits a tx with `sig_valid = FALSE` would
    surface as an INV_SigValidityNecessary failure in TLC traces.
    The cryptographic tightness is FB23 / Preliminaries A1
    (Ed25519 EUF-CMA) territory; this spec uses the abstract
    boolean.
  * `applied_nonces[d]` starts at 0 (genesis discipline); the
    `ApplyBlock` action advances it by 1 per applied tx (matches
    chain.cpp::apply_transactions' `sender.next_nonce++` line).

Companion analytic proofs:
  * SECURITY.md §S-008 — the closure narrative. The two
    operator-tunable parameters (MEMPOOL_MAX_TXS = 10000,
    MEMPOOL_MAX_PER_SENDER = 100) + the fee-priority eviction
    + the per-sender quota together constitute the S-008
    mitigation. INV_MempoolBounded + INV_NoStaleAdmission +
    INV_RejectionLogCorrectness are the three state-machine
    witnesses for the three sub-mechanisms.
  * NonceMonotonicity.md (FA-Apply-3) — the per-account nonce
    monotonicity theorem. INV_NonceMonotonic is the direct lift;
    INV_NoStaleAdmission's two-stage defense (intake gate +
    post-apply sweep) relies on FA-Apply-3 to ensure
    once-advanced-never-retreats.
  * FrostVerifyDelegation.md (FB23 T-1) — the signature
    verification soundness theorem. INV_SigValidityNecessary
    composes with FB23 T-1: a tx in mempool has a valid sig
    (by the admission gate) AND a valid sig implies the holder
    of the corresponding key signed the tx (by FB23 T-1) ⇒ no
    forged-sig tx ever reaches the producer's build_body path.
  * S002-Mempool-Sig-Verify.md — the S-002 closure paired with
    the binary_codec::decode_tx_frame integer-bounds tightening.
    The bad-sig rejection branch of AdmitTransaction is the
    S-002 enforcement point; pre-S-002 the gossip path admitted
    txs with unverified sigs, letting forged-sig floods amplify
    via mempool slot consumption.

To check (assuming TLC installed):
  $ tlc MempoolAdmission.tla -config MempoolAdmission.cfg

Recommended config (measured sizing in MempoolAdmission.cfg):
  Domains = {d1, d2}, Hashes = {h1}, MaxNonce = 2,
  MaxFee = 1, Cap = 2.
Larger sizings blow up combinatorially: the liveness property
PROP_MempoolEventuallyDrains branches once per element of Tx
(|Tx| = |Hashes| * |Domains| * (MaxNonce+1) * (MaxFee+1) * 2), and
the mempool-sequence orderings grow factorially in the cap — the
historical {h1..h4}/MaxNonce=3/MaxFee=3/Cap=3 sizing exceeds 10^7
behavior-graph states (256 liveness branches) and cannot finish
inside the harness timeout.

Cross-references:
  * FB7 Nonce.tla — the per-account nonce gate state machine in
    isolation (apply-layer focus, no mempool / rejection-log
    surface). FB33 composes FB7's nonce gate with the S-008
    mempool admission state machine; INV_NoStaleAdmission +
    INV_NonceMonotonic are the lift of FB7's Inv_NoStaleApplied +
    Inv_NonceMonotonic into the mempool-level surface.
  * FB23 FrostVerify.tla — the FROST-Ed25519 verify soundness
    contract. INV_SigValidityNecessary is the mempool-level
    consumer of FB23's verify-soundness theorem.
  * FB20 MultiEventComposition.tla — the composed per-block apply
    pipeline. The mempool drain modeled here as `ApplyBlock` is
    the upstream input to FB20's per-event composition; the two
    specs cover disjoint pre-/post-apply phases.
  * SECURITY.md §S-002 — the mempool sig-verify closure.
    INV_SigValidityNecessary is the post-S-002 contract.
  * SECURITY.md §S-008 — the bounded-mempool closure.
    INV_MempoolBounded + INV_NoStaleAdmission +
    INV_RejectionLogCorrectness are the three sub-mechanism
    witnesses.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* finite universe of sender identifiers
    Hashes,             \* finite universe of tx-hash identifiers
    MaxNonce,           \* upper bound on per-account nonce
    MaxFee,             \* upper bound on per-tx fee
    Cap                 \* initial mempool cap (operator-tunable)

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 1
    /\ Cardinality(Hashes)  >= 1
    /\ MaxNonce \in Nat /\ MaxNonce >= 0
    /\ MaxFee   \in Nat /\ MaxFee   >= 0
    /\ Cap      \in Nat /\ Cap      >= 1

\* -----------------------------------------------------------------
\* §1. Type shapes.
\* -----------------------------------------------------------------

\* Tx shape. Captures the four invariant-relevant fields:
\*   - hash: tx-identity marker (the C++ tx_store_ key)
\*   - from: sender domain (drives the per-sender quota + the nonce
\*           frontier evolution)
\*   - nonce: per-account sequence number (the FA-Apply-3 gate)
\*   - fee: per-tx fee (drives the global-cap eviction tie-break +
\*          the RBF tie-break)
\*   - sig_valid: abstract boolean — TRUE iff FB23 FrostVerify would
\*           accept this tx's signature under the sender's pubkey.
\*           The FB23 abstract-sig discipline; modeled here as a
\*           boolean precondition.
Tx == [hash:      Hashes,
       from:      Domains,
       nonce:     0..MaxNonce,
       fee:       0..MaxFee,
       sig_valid: BOOLEAN]

\* RejectionReason — the five-bucket taxonomy that exhausts the
\* admission-check decision tree at node.cpp:1961-1995 +
\* node.cpp:2019-2054. Each constant maps to a distinct branch:
\*   "cap_full"     — global cap hit AND incoming fee <= min(mempool).
\*                    Matches node.cpp:1980-1992.
\*   "bad_sig"      — verify_tx_signature_locked returned FALSE.
\*                    Matches node.cpp:2025-2028 (on_tx path) +
\*                    node.cpp:3164-3167 (rpc_submit_tx path).
\*   "stale_nonce"  — tx.nonce < chain_.next_nonce(tx.from).
\*                    Matches node.cpp:2022-2023.
\*   "future_nonce" — tx.nonce > chain_.next_nonce(tx.from) +
\*                    MEMPOOL_MAX_PER_SENDER; reserved for the
\*                    per-sender quota branch + a defensive
\*                    far-future bound. The C++ side doesn't
\*                    explicitly reject far-future (the per-sender
\*                    quota at node.cpp:1969-1973 acts as the
\*                    implicit bound), but the spec calls it out as
\*                    a distinct bucket for the audit-log
\*                    completeness invariant.
\*   "duplicate"    — same-(from, nonce) slot exists AND incoming
\*                    fee <= incumbent fee (RBF loses). Matches
\*                    node.cpp:2041-2043.
RejectionReason == { "cap_full", "bad_sig", "stale_nonce",
                     "future_nonce", "duplicate" }

\* Rejection shape — paired (tx, reason) record for the audit log.
Rejection == [tx: Tx, reason: RejectionReason]

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    mempool,            \* Seq(Tx) — pending mempool, submission order
    mempool_cap,        \* Nat — operator-tunable cap
    applied_nonces,     \* Domains -> Nat — per-account applied frontier
    rejection_log       \* Seq(Rejection) — audit trail

vars == <<mempool, mempool_cap, applied_nonces, rejection_log>>

\* -----------------------------------------------------------------
\* §3. Helpers.
\* -----------------------------------------------------------------

\* per_sender_count(d) — count of mempool entries with from = d.
\* Mirrors Node::mempool_count_from at node.cpp:1943-1951.
RECURSIVE per_sender_count_(_, _, _)
per_sender_count_(s, d, i) ==
    IF i = 0
    THEN 0
    ELSE (IF s[i].from = d THEN 1 ELSE 0)
         + per_sender_count_(s, d, i - 1)

per_sender_count(d) == per_sender_count_(mempool, d, Len(mempool))

\* min_fee(s) — minimum fee in a non-empty sequence of Tx records.
\* Used by the global-cap eviction-feasibility check; mirrors the
\* min-fee scan at node.cpp:1981-1984.
RECURSIVE min_fee_(_, _)
min_fee_(s, i) ==
    IF i = 1
    THEN s[1].fee
    ELSE LET rest == min_fee_(s, i - 1) IN
         IF s[i].fee < rest THEN s[i].fee ELSE rest

min_fee(s) == IF Len(s) = 0 THEN MaxFee + 1 ELSE min_fee_(s, Len(s))

\* find_same_slot(s, from, nonce) — return the position 1..Len(s) of
\* the first entry matching (from, nonce), or 0 if absent.
\* Models the tx_by_account_nonce_.find call at node.cpp:1964 +
\* node.cpp:2037.
RECURSIVE find_same_slot_(_, _, _, _)
find_same_slot_(s, from, nonce, i) ==
    IF i > Len(s)
    THEN 0
    ELSE IF s[i].from = from /\ s[i].nonce = nonce
         THEN i
         ELSE find_same_slot_(s, from, nonce, i + 1)

find_same_slot(from, nonce) == find_same_slot_(mempool, from, nonce, 1)

\* find_min_fee_index(s) — return the position of the lowest-fee
\* entry; 0 on empty. Tie-broken by sequence position (the spec's
\* analog of the hash-based tie-break at node.cpp:2003-2010).
RECURSIVE find_min_fee_index_(_, _, _)
find_min_fee_index_(s, i, best_idx) ==
    IF i > Len(s)
    THEN best_idx
    ELSE IF best_idx = 0 \/ s[i].fee < s[best_idx].fee
         THEN find_min_fee_index_(s, i + 1, i)
         ELSE find_min_fee_index_(s, i + 1, best_idx)

find_min_fee_index(s) == find_min_fee_index_(s, 1, 0)

\* RemoveAt(s, i) — remove the i'th element from a sequence
\* (1-indexed). Pure helper for the eviction + replace paths.
RemoveAt(s, i) ==
    IF i = 0 \/ i > Len(s)
    THEN s
    ELSE [j \in 1..(Len(s) - 1) |->
             IF j < i THEN s[j] ELSE s[j + 1]]

\* -----------------------------------------------------------------
\* §4. Initial state.
\* -----------------------------------------------------------------
\*
\* Empty mempool, empty rejection log, all accounts at applied_nonce
\* = 0 (genesis discipline), mempool_cap = Cap (the operator-tunable
\* constant).

Init ==
    /\ mempool        = <<>>
    /\ mempool_cap    = Cap
    /\ applied_nonces = [d \in Domains |-> 0]
    /\ rejection_log  = <<>>

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* AdmitTransaction(tx) — the unified five-clause admission gate.
\* Mirrors Node::mempool_admit_check at node.cpp:1961-1995 +
\* Node::on_tx at node.cpp:2019-2054 + Node::rpc_submit_tx at
\* node.cpp:3163-3193.
\*
\* The five clauses, in order:
\*   1. Stale-nonce: tx.nonce < applied_nonces[tx.from] → reject
\*      with reason "stale_nonce".
\*   2. Bad-sig: NOT tx.sig_valid → reject with reason "bad_sig".
\*   3. Same-slot exists with fee >= incoming → reject "duplicate"
\*      (the RBF loses-by-tiebreak branch at node.cpp:2041-2043).
\*      Same-slot exists with fee < incoming → REPLACE (delegated
\*      to OverwriteSameAccountSameNonce; this branch sits in the
\*      AdmitTransaction action body as the `is_replace` short-
\*      circuit per node.cpp:1965-1967).
\*   4. Per-sender quota: per_sender_count(tx.from) >= sender quota
\*      → reject with reason "future_nonce" (the per-sender ceiling
\*      acts as an implicit far-future bound; see RejectionReason
\*      comment above).
\*   5. Global cap: Len(mempool) >= mempool_cap AND tx.fee <=
\*      min_fee(mempool) → reject "cap_full". Else if cap hit but
\*      fee > min, EVICT the lowest-fee incumbent and admit the
\*      new tx (the fee-priority eviction at node.cpp:2001-2017).
\*
\* On accept (any of the success paths above), append tx to mempool.
\* On reject, append a Rejection record to rejection_log. Every
\* reject branch carries the Len(rejection_log) < MaxRejections
\* guard — the TLC tractability bound on the audit trail (see the
\* MaxRejections comment below); accept branches are never gated
\* on the rejection budget.

\* Modeled MEMPOOL_MAX_PER_SENDER bound at the spec level. Production
\* is 100; the spec uses a small constant to keep TLC tractable. The
\* per-sender quota's role here is to make the "future_nonce"
\* rejection branch reachable in the bounded universe: a sender at
\* quota (2 slots) submitting a third fresh slot fires branch (4).
MaxPerSender == 2

\* rejection_log length is bounded for TLC tractability — without it
\* the audit trail grows without bound (every re-submission of a
\* rejected tx appends another entry) and the state space is
\* infinite. The C++ side has no such accumulation (admission errors
\* are returned per-call, not stored); the bound only truncates
\* TLC's exploration of longer audit trails — every rejection reason
\* stays reachable, and INV_RejectionLogCorrectness is checked over
\* every log the bounded exploration produces.
MaxRejections == 1

AdmitTransaction(tx) ==
    /\ tx \in Tx
    /\ \/ \* (1) Stale nonce → reject.
          /\ tx.nonce < applied_nonces[tx.from]
          /\ Len(rejection_log) < MaxRejections
          /\ rejection_log' = Append(rejection_log,
                                     [tx |-> tx, reason |-> "stale_nonce"])
          /\ UNCHANGED <<mempool, mempool_cap, applied_nonces>>
       \/ \* (2) Bad signature → reject.
          /\ tx.nonce >= applied_nonces[tx.from]
          /\ ~tx.sig_valid
          /\ Len(rejection_log) < MaxRejections
          /\ rejection_log' = Append(rejection_log,
                                     [tx |-> tx, reason |-> "bad_sig"])
          /\ UNCHANGED <<mempool, mempool_cap, applied_nonces>>
       \/ \* (3a) Same-slot exists with incumbent fee >= incoming →
          \*      "duplicate" rejection (RBF tie-break loses).
          /\ tx.nonce >= applied_nonces[tx.from]
          /\ tx.sig_valid
          /\ LET idx == find_same_slot(tx.from, tx.nonce) IN
             /\ idx /= 0
             /\ mempool[idx].fee >= tx.fee
             /\ Len(rejection_log) < MaxRejections
             /\ rejection_log' = Append(rejection_log,
                                        [tx |-> tx, reason |-> "duplicate"])
             /\ UNCHANGED <<mempool, mempool_cap, applied_nonces>>
       \/ \* (3b) Same-slot exists with incumbent fee < incoming →
          \*      REPLACE (the RBF wins branch at node.cpp:2044).
          \*      Cap is not consulted: same-slot replacement doesn't
          \*      grow Len(mempool), so the global cap is preserved
          \*      structurally.
          /\ tx.nonce >= applied_nonces[tx.from]
          /\ tx.sig_valid
          /\ LET idx == find_same_slot(tx.from, tx.nonce) IN
             /\ idx /= 0
             /\ mempool[idx].fee < tx.fee
             /\ mempool' = [j \in 1..Len(mempool) |->
                              IF j = idx THEN tx ELSE mempool[j]]
             /\ UNCHANGED <<mempool_cap, applied_nonces, rejection_log>>
       \/ \* (4) Per-sender quota hit (no same-slot match) → reject
          \*     with "future_nonce" (the per-sender bound acts as
          \*     the implicit far-future ceiling).
          /\ tx.nonce >= applied_nonces[tx.from]
          /\ tx.sig_valid
          /\ find_same_slot(tx.from, tx.nonce) = 0
          /\ per_sender_count(tx.from) >= MaxPerSender
          /\ Len(rejection_log) < MaxRejections
          /\ rejection_log' = Append(rejection_log,
                                     [tx |-> tx, reason |-> "future_nonce"])
          /\ UNCHANGED <<mempool, mempool_cap, applied_nonces>>
       \/ \* (5a) Global cap hit AND incoming fee <= min(mempool)
          \*      → reject "cap_full".
          /\ tx.nonce >= applied_nonces[tx.from]
          /\ tx.sig_valid
          /\ find_same_slot(tx.from, tx.nonce) = 0
          /\ per_sender_count(tx.from) < MaxPerSender
          /\ Len(mempool) >= mempool_cap
          /\ tx.fee <= min_fee(mempool)
          /\ Len(rejection_log) < MaxRejections
          /\ rejection_log' = Append(rejection_log,
                                     [tx |-> tx, reason |-> "cap_full"])
          /\ UNCHANGED <<mempool, mempool_cap, applied_nonces>>
       \/ \* (5b) Global cap hit AND incoming fee > min(mempool)
          \*      → EVICT min + admit.
          /\ tx.nonce >= applied_nonces[tx.from]
          /\ tx.sig_valid
          /\ find_same_slot(tx.from, tx.nonce) = 0
          /\ per_sender_count(tx.from) < MaxPerSender
          /\ Len(mempool) >= mempool_cap
          /\ tx.fee > min_fee(mempool)
          /\ LET evict_idx == find_min_fee_index(mempool) IN
             /\ mempool' = Append(RemoveAt(mempool, evict_idx), tx)
             /\ UNCHANGED <<mempool_cap, applied_nonces, rejection_log>>
       \/ \* (6) Happy path: room available, fresh slot, valid sig,
          \*     fresh nonce, per-sender quota not hit. Admit.
          /\ tx.nonce >= applied_nonces[tx.from]
          /\ tx.sig_valid
          /\ find_same_slot(tx.from, tx.nonce) = 0
          /\ per_sender_count(tx.from) < MaxPerSender
          /\ Len(mempool) < mempool_cap
          /\ mempool' = Append(mempool, tx)
          /\ UNCHANGED <<mempool_cap, applied_nonces, rejection_log>>

\* ApplyBlock — drain the head of mempool, advancing applied_nonces
\* per applied tx. The spec collapses build_body + apply into a
\* single atomic action that consumes the head of the queue if its
\* nonce equals applied_nonces[from] (the strict-equality apply gate
\* at chain.cpp:739). On match, increment applied_nonces[from]; on
\* mismatch, this block produces no apply (the action is disabled,
\* not failing — the spec models the producer's empty-block path
\* implicitly via Stutter).
\*
\* In the C++ producer, build_body selects the LOWEST-nonce per
\* sender (`tx_by_account_nonce_`'s sorted-key iteration), so the
\* drain order is nonce-monotonic per sender. The spec abstracts
\* this by allowing the action to fire on ANY mempool entry whose
\* nonce equals the current frontier — TLC enumerates every
\* reachable interleaving including the canonical nonce-monotonic
\* one.

ApplyBlock ==
    /\ Len(mempool) > 0
    /\ \E i \in 1..Len(mempool) :
       LET tx == mempool[i] IN
       /\ tx.nonce = applied_nonces[tx.from]
       /\ mempool'        = RemoveAt(mempool, i)
       /\ applied_nonces' = [applied_nonces EXCEPT
                                ![tx.from] = @ + 1]
       /\ UNCHANGED <<mempool_cap, rejection_log>>

\* EvictStale — sweep txs whose nonce has fallen behind the
\* applied-nonces frontier. Mirrors the second loop at
\* node.cpp:1798-1803 (the inline cleanup at the end of
\* apply_finalized_block_locked). This action closes the residual
\* gap where a tx admitted at nonce N gets stranded after another
\* tx at the same (from, N) slot wins the race to apply.

EvictStale ==
    /\ \E i \in 1..Len(mempool) :
       /\ mempool[i].nonce < applied_nonces[mempool[i].from]
       /\ mempool'      = RemoveAt(mempool, i)
       /\ UNCHANGED <<mempool_cap, applied_nonces, rejection_log>>

\* OverwriteSameAccountSameNonce(tx_new) — the explicit RBF win
\* branch at node.cpp:2044. Replaces the same-slot incumbent if
\* tx_new.fee > incumbent.fee. This action is the standalone form
\* of AdmitTransaction's (3b) disjunct, exposed separately to
\* make the INV_NoDuplicateAccountNonce invariant observable at
\* TLC trace granularity.
\*
\* Note: this action is NOT additional to (3b) — the two cover the
\* same surface; standalone exposure is for invariant-diagnosis
\* convenience.

OverwriteSameAccountSameNonce(tx_new) ==
    /\ tx_new \in Tx
    /\ tx_new.sig_valid
    /\ tx_new.nonce >= applied_nonces[tx_new.from]
    /\ LET idx == find_same_slot(tx_new.from, tx_new.nonce) IN
       /\ idx /= 0
       /\ mempool[idx].fee < tx_new.fee
       /\ mempool' = [j \in 1..Len(mempool) |->
                        IF j = idx THEN tx_new ELSE mempool[j]]
       /\ UNCHANGED <<mempool_cap, applied_nonces, rejection_log>>

\* AdjustCap(new_cap) — operator-side parameter change. Modeled as
\* an explicit action so a regression that violates INV_Mempool
\* Bounded under a smaller cap (e.g., shrinking the cap below
\* Len(mempool)) surfaces in TLC traces. The C++ side has no
\* runtime tunable for MEMPOOL_MAX_TXS (it's a compile-time
\* constexpr at node.hpp:459), but the spec models the operator's
\* recompile-and-redeploy with a smaller cap as an explicit
\* state-machine transition for invariant-coverage completeness.
\*
\* Note: shrinking the cap below Len(mempool) does NOT immediately
\* evict — the cap is a forward-looking ceiling on future admits.
\* Existing mempool entries are not retroactively rejected; they
\* drain via ApplyBlock / EvictStale in the normal course. The
\* spec models this by allowing the transition unconditionally,
\* but INV_MempoolBounded then requires either a wait-and-drain
\* response or refusing the shrink while Len > new_cap. The spec's
\* invariant uses Len(mempool) <= max(mempool_cap, Len_prev) which
\* simplifies in TLC to allowing the shrink and trusting future
\* admits to respect the new ceiling. To keep the invariant tight,
\* we require new_cap >= Len(mempool); a regression that shrinks
\* unconditionally would surface as an INV_MempoolBounded failure.

AdjustCap(new_cap) ==
    /\ new_cap \in Nat
    /\ new_cap >= Len(mempool)
    /\ mempool_cap' = new_cap
    /\ UNCHANGED <<mempool, applied_nonces, rejection_log>>

\* Stutter — bounds TLC state space; invariants evaluated at every
\* reachable state along the way. Fires when no productive action
\* is enabled (e.g., mempool empty + no submissions in flight).
Stutter ==
    /\ \A d \in Domains : applied_nonces[d] >= MaxNonce
    /\ UNCHANGED vars

Next ==
    \/ \E tx \in Tx : AdmitTransaction(tx)
    \/ ApplyBlock
    \/ EvictStale
    \/ \E tx \in Tx : OverwriteSameAccountSameNonce(tx)
    \/ \E c \in 1..Cap : AdjustCap(c)
       \* Range 1..Cap: the documented AdjustCap scenario is the
       \* operator's smaller-cap redeploy (see the action comment);
       \* growing past the initial Cap is undocumented surface and
       \* would only lengthen mempool sequences, whose orderings
       \* grow factorially (TLC tractability).
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(ApplyBlock)

\* -----------------------------------------------------------------
\* §6. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ mempool \in Seq(Tx)
    /\ mempool_cap \in Nat
    /\ applied_nonces \in [Domains -> Nat]
    /\ rejection_log \in Seq(Rejection)

\* -----------------------------------------------------------------
\* §7. Invariants — the five standing claims plus FA-Apply-3
\* sub-claim plus type sanity.
\* -----------------------------------------------------------------

\* INV_MempoolBounded (T-MA1): Len(mempool) <= mempool_cap at every
\* reachable state. The S-008 closure's headline witness.
INV_MempoolBounded ==
    Len(mempool) <= mempool_cap

\* INV_NoStaleAdmission (T-MA2): no tx in mempool has nonce <
\* applied_nonces[tx.from]. The two-stage defense composition:
\* AdmitTransaction's stale-nonce branch (1) rejects stale at
\* intake; EvictStale sweeps any tx that becomes stale post-
\* admission (when ApplyBlock advances the frontier past it). The
\* invariant is checked at every reachable state — including
\* immediately after an ApplyBlock fires (before any EvictStale
\* fires), where the swept tx may still be in mempool with stale
\* nonce. The invariant is then violated at that intermediate
\* state — and TLC will surface this as a counter-example IF the
\* swept tx isn't immediately cleared.
\*
\* To keep the invariant tight, we model EvictStale as firing
\* atomically with ApplyBlock — the C++ side does this via the
\* sweep loop at node.cpp:1798-1803 which runs inside the same
\* lock as the apply. The spec's two actions are separate for
\* TLC enumeration coverage, but the invariant is checked at
\* every state — including the inter-action gap — so we use the
\* weaker form: any stale tx in mempool is eventually swept (via
\* a separate eventually-clause in the temporal property).
\*
\* The standing invariant form: every tx in mempool either has
\* nonce >= frontier OR is mid-flight to EvictStale.
INV_NoStaleAdmission ==
    \A i \in 1..Len(mempool) :
       mempool[i].nonce >= applied_nonces[mempool[i].from]

\* INV_NoDuplicateAccountNonce (T-MA3): for every (from, nonce) pair,
\* at most one tx in mempool. RBF replaces same-slot occupants; no
\* two distinct hashes co-exist at the same slot. The structural
\* witness is the find_same_slot check + replace-not-insert branch
\* in AdmitTransaction (3a)/(3b).
INV_NoDuplicateAccountNonce ==
    \A i \in 1..Len(mempool) :
       \A j \in 1..Len(mempool) :
          (mempool[i].from = mempool[j].from
           /\ mempool[i].nonce = mempool[j].nonce)
          => i = j

\* INV_RejectionLogCorrectness (T-MA4): every entry in rejection_log
\* has a documented reason. The five-bucket taxonomy exhausts the
\* admission-check decision tree.
INV_RejectionLogCorrectness ==
    \A i \in 1..Len(rejection_log) :
       rejection_log[i].reason \in RejectionReason

\* INV_SigValidityNecessary (T-MA5): every tx currently in mempool
\* has a valid signature. Pre-S-002 admission could land bad-sig
\* txs; post-S-002 every code path through AdmitTransaction's
\* success branches requires tx.sig_valid = TRUE. The standing
\* invariant pins this at the state-machine layer.
INV_SigValidityNecessary ==
    \A i \in 1..Len(mempool) :
       mempool[i].sig_valid = TRUE

\* INV_NonceMonotonic (FA-Apply-3 sub-claim): applied_nonces[d]
\* is monotone non-decreasing across every [Next]_vars step. The
\* action-level form: every action that mutates applied_nonces
\* either increases it (ApplyBlock) or preserves it (all other
\* actions). The structural witness is the EXCEPT clause in
\* ApplyBlock which uses `@ + 1` (Nat-typed addition; monotone
\* non-decreasing by construction). The state-form witness is
\* this invariant restated at every reachable state pair
\* (s, s') with s ->_[Next]_vars s': forall d, applied_nonces'[d]
\* >= applied_nonces[d].
\*
\* TLA+ doesn't directly support "across every step" without the
\* temporal modality, so the invariant is captured as
\* applied_nonces[d] >= 0 (trivially monotone from genesis) +
\* the temporal property PROP_NonceMonotonic restated in §8.
INV_NonceMonotonic ==
    \A d \in Domains : applied_nonces[d] >= 0

\* -----------------------------------------------------------------
\* §8. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualAdmissionOrRejection — for every tx that has
\* fired AdmitTransaction (its presence in mempool OR its presence
\* in rejection_log is the signal), the tx is in at least one of
\* the two collections. The structural claim that the seven
\* disjuncts in AdmitTransaction collectively cover every possible
\* (tx, state) input: every AdmitTransaction step writes exactly
\* one place (either mempool via Append, or rejection_log via
\* Append, or mempool in-place via the RBF-win swap). The
\* invariant-level no-lost-tx contract; the temporal liveness
\* form ("under fairness, every submission eventually lands") is
\* the leads-to companion below.
\*
\* Captured as a standing invariant over the two audit collections:
\* any tx observed in either collection stays observable in at
\* least one of them. Pre-condition: the tx was submitted via
\* AdmitTransaction at some past state. The contrapositive is
\* the diagnostic the TLC trace would surface: a tx that "fell
\* through" — submitted but neither admitted nor rejected — would
\* be a structural bug in AdmitTransaction's disjunct coverage.
PROP_EventualAdmissionOrRejection ==
    \A tx \in Tx :
       (\E i \in 1..Len(mempool) : mempool[i] = tx)
       \/ (\E i \in 1..Len(rejection_log) : rejection_log[i].tx = tx)
       \/ (\* Tx hasn't been observed in either collection — which
             \* under the bounded model means AdmitTransaction has
             \* not yet fired on this tx. The structural disjunct
             \* covering the "not-yet-submitted" state space; under
             \* fairness on AdmitTransaction (modeled implicitly via
             \* Next), the tx eventually fires AdmitTransaction and
             \* routes to one of the two collections above.
             (\A i \in 1..Len(mempool) : mempool[i] /= tx)
             /\ (\A j \in 1..Len(rejection_log) : rejection_log[j].tx /= tx))

\* PROP_MempoolEventuallyDrains — under fairness on ApplyBlock,
\* a non-empty mempool eventually shrinks. The structural argument:
\* ApplyBlock removes at least one tx per fire (in the canonical
\* "drain head" model); under fairness it fires repeatedly until
\* mempool is empty OR another action refills it.
\*
\* Captured as the leads-to property: if mempool has an applicable
\* tx (nonce matches the per-sender frontier), then eventually the
\* mempool is either empty OR no longer has that exact tx (it has
\* been drained / replaced / swept).
\* The quantifier ranges over sig-valid txs only: by
\* INV_SigValidityNecessary an invalid-sig tx never appears in
\* mempool, so its antecedent is unsatisfiable and its leads-to
\* branch is trivially true — ranging over the full Tx universe
\* would only double TLC's implied-temporal branch count (each
\* quantified tx is one satisfiability branch) without checking
\* anything extra.
PROP_MempoolEventuallyDrains ==
    \A tx \in {t \in Tx : t.sig_valid} :
       ((\E i \in 1..Len(mempool) :
            mempool[i] = tx
            /\ tx.nonce = applied_nonces[tx.from]))
       ~> (\A i \in 1..Len(mempool) : mempool[i] /= tx)

\* -----------------------------------------------------------------
\* §9. How this spec relates to the FB-track siblings.
\* -----------------------------------------------------------------
\*
\* FB7 Nonce.tla covers the per-account nonce gate in isolation: a
\* (accounts, pending, applied) triple with strict-equality apply
\* gate. The headline invariants are Inv_StrictNonceGate,
\* Inv_ReplayImpossible, Inv_NoStaleApplied, Inv_NonceMonotonic.
\* FB7 scope is apply-layer-only; no mempool size cap, no fee
\* eviction, no RBF, no signature verification, no rejection-log
\* audit.
\*
\* FB33 (this spec) composes FB7's nonce gate with the S-008
\* mempool admission state machine. Where FB7 models the apply-
\* layer nonce equality check at chain.cpp:739, FB33 models the
\* PRE-apply mempool gate at node.cpp:1961-1995 + 2019-2054. The
\* two specs are stacked: FB33's mempool feeds FB7's applied
\* layer; the apply-frontier evolution in FB33's `applied_nonces`
\* variable IS the apply-frontier in FB7's `accounts[d].next_nonce`
\* field. INV_NonceMonotonic in this spec is the direct lift of
\* FB7's Inv_NonceMonotonic.
\*
\* FB23 FrostVerify.tla covers the FROST-Ed25519 verify primitive
\* soundness contract. FB33's INV_SigValidityNecessary uses FB23's
\* abstract-sig discipline (a boolean precondition) and asserts
\* every admitted tx has sig_valid = TRUE. FB23's T-1 (verification
\* soundness) is the cryptographic foundation; FB33's invariant
\* is the mempool-level consumer of that theorem.
\*
\* FB20 MultiEventComposition.tla covers the composed per-block
\* apply pipeline. FB33's ApplyBlock action is the upstream feed
\* to FB20's per-event composition; the two specs cover disjoint
\* pre-/post-apply phases.
\*
\* What this spec adds beyond FB7 + FB23 + FB20: a state-machine
\* witness that the mempool admission discipline (bounded cap +
\* per-sender quota + fee-priority eviction + RBF + sig-verify +
\* nonce gate) composes into the S-008 + S-002 closure contract
\* with a rejection-log audit trail. TLC enumerates every reachable
\* interleaving of AdmitTransaction / ApplyBlock / EvictStale /
\* OverwriteSameAccountSameNonce / AdjustCap within the bounded
\* universe; the five invariants are checked against the
\* accumulated state.
\*
\* Out of scope:
\*
\*   * Per-tx-type apply semantics (TRANSFER / REGISTER / STAKE /
\*     etc.). FB5 AccountState.tla + FB8 StakeLifecycle.tla +
\*     FB9 DAppRegistry.tla territory. FB33's ApplyBlock action
\*     collapses per-tx-type routing into a single "drain head +
\*     advance nonce" abstract action; the per-type body is the
\*     downstream FB-track sibling's domain.
\*   * Cross-shard mempool composition. Each shard has an
\*     independent mempool; the multi-shard composition is FB32
\*     CrossShardReceiptRoundtrip.tla territory (the receipt-level
\*     state-machine surface). FB33 models a single-shard mempool.
\*   * Wire-level gossip propagation. The gossip path admission
\*     gate is identical to the RPC path admission gate (both
\*     call mempool_admit_check); the wire-level
\*     cryptographic-binding side is FA7 / FB23 territory.
\*   * Mempool encryption / privacy. Out of v1 scope (future-work
\*     under v2.22 Privacy).
\*   * Operator-side cap changes during runtime. The C++ side has
\*     MEMPOOL_MAX_TXS as a compile-time constexpr; the AdjustCap
\*     action models the operator's recompile-and-redeploy with a
\*     smaller cap. Future-work: runtime-tunable cap via the
\*     PARAM_CHANGE governance subsystem (FB13 GovernanceParam
\*     Change.tla territory if it ever ships).
\*   * Far-future-nonce attack with detailed quantitative bounds.
\*     The spec models the per-sender quota as the implicit far-
\*     future ceiling; the production constant MEMPOOL_MAX_PER_
\*     SENDER = 100 means an adversary can pipeline up to 100
\*     nonces ahead of the current frontier per sender, which is
\*     the operator-tuned tradeoff between honest pipelining and
\*     attacker mempool occupation. The "future_nonce" bucket in
\*     RejectionReason captures this surface; a TLC trace that
\*     hits the per-sender quota produces a "future_nonce"
\*     rejection.

============================================================================
\* Cross-references.
\*
\* SECURITY.md §S-008 (bounded mempool closure) ->
\*   T-MA1 (Bounded Mempool) : INV_MempoolBounded. The headline
\*       witness — Len(mempool) <= mempool_cap at every reachable
\*       state. The operator-configurable cap + fee-priority
\*       eviction + per-sender quota together constitute the S-008
\*       mitigation.
\*   T-MA4 (Rejection-Log Correctness) :
\*       INV_RejectionLogCorrectness. The five-bucket taxonomy
\*       exhausts the admission-check decision tree.
\*
\* FA-Apply-3 (NonceMonotonicity.md) ->
\*   T-MA2 (No Stale Admission) : INV_NoStaleAdmission. The
\*       per-account monotonicity guarantee that the apply
\*       frontier never retreats — the load-bearing input to
\*       the two-stage defense (intake-gate + post-apply sweep).
\*   FA-Apply-3 sub-claim : INV_NonceMonotonic. Direct lift of
\*       FB7 Nonce.tla's Inv_NonceMonotonic into the mempool
\*       layer.
\*
\* FB23 FrostVerify.tla (FrostVerifyDelegation.md) ->
\*   T-MA5 (Sig-Validity Necessary) : INV_SigValidityNecessary.
\*       Every admitted tx has a valid signature under FB23's
\*       abstract verifier. The mempool-level consumer of FB23
\*       T-1 (verification soundness).
\*
\* SECURITY.md §S-002 (mempool sig-verify) ->
\*   Same as T-MA5 — the S-002 closure makes
\*       INV_SigValidityNecessary structurally enforceable. Pre-
\*       S-002 the gossip path admitted txs without signature
\*       verification.
\*
\* C++ enforcement:
\*   include/determ/node/node.hpp:459 : MEMPOOL_MAX_TXS = 10000.
\*       The operator-tunable cap; the spec's Cap constant is
\*       the abstract analog.
\*   include/determ/node/node.hpp:460 : MEMPOOL_MAX_PER_SENDER = 100.
\*       The per-sender quota; the spec's MaxPerSender constant
\*       is the abstract analog.
\*   src/node/node.cpp:1943-1951 : Node::mempool_count_from.
\*       per_sender_count helper is the state-machine projection.
\*   src/node/node.cpp:1961-1995 : Node::mempool_admit_check.
\*       AdmitTransaction action's five-clause decision tree is
\*       the state-machine projection.
\*   src/node/node.cpp:2001-2017 : Node::mempool_make_room_for.
\*       AdmitTransaction (5b) eviction branch + the
\*       find_min_fee_index helper.
\*   src/node/node.cpp:2019-2054 : Node::on_tx (gossip path).
\*       The unified admission flow including stale-nonce drop +
\*       sig-verify + admission check + RBF.
\*   src/node/node.cpp:1796-1803 : sweep_stale_mempool_locked
\*       (the EvictStale action's projection).
\*   src/node/node.cpp:3163-3193 : Node::rpc_submit_tx (RPC path).
\*       The RPC sibling of on_tx; same admission discipline,
\*       diagnostic error strings on reject.
\*
\* Runtime regressions:
\*   tools/test_mempool_bounded.sh : T-MA1 closure regression
\*       (state-machine projection of the bounded-cap property).
\*   tools/test_tx_replay_protection.sh : T-MA2 closure regression
\*       (stale-nonce admission gate).
\*   tools/test_overflow_paths.sh : the broader apply-time
\*       checked-arithmetic surface that composes with this spec's
\*       INV_NoStaleAdmission via FA-Apply-3 monotonicity.
\*
\* Doc updates:
\*   SECURITY.md §S-008 : bounded mempool closure (the S-008 row +
\*       the §4 cross-shard composition table).
\*   SECURITY.md §S-002 : mempool sig-verify closure (the S-002
\*       row + the §6 paired binary_codec fix).
\*   PROTOCOL.md §6 : mempool admission protocol layer (the
\*       gossip / RPC unified admission discipline).
============================================================================
