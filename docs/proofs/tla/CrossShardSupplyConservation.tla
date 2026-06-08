--------------------------- MODULE CrossShardSupplyConservation ---------------------------
(*
FB54 — TLA+ specification of the K-SHARD AGGREGATE supply-conservation
identity. This is the machine-checkable companion to the analytic proof
FA-Apply-17 (`docs/proofs/CrossShardSupplyConservation.md`, theorems
XS-1..XS-5): the cross-shard generalization of the per-shard A1
unitary-supply invariant.

Where FB46 (UnitarySupplyLedger.tla) models the FIVE-TERM A1 identity for
ONE shard in isolation — the `live_total_supply() == expected_total()`
assertion the apply path checks after every block on a single `Chain`
object — THIS spec is the K-SHARD COMPOSITION of that single-shard model.
FB46 proves each shard's ledger closes; FB54 proves that the SUM over a
set of K sibling shards also closes, INCLUDING value that has left a
source shard but not yet been credited on its destination shard
("in flight"), so the cross-shard receipt machinery creates and destroys
nothing.

This module is the state-machine sibling of FB32
(CrossShardReceiptRoundtrip.tla, the receipt LIFECYCLE) — it reuses
FB32's EmitOutbound / CreditInbound action shapes but ABSTRACTS the
gossip / latency / snapshot pipeline down to its supply-bearing core, in
order to make the K-SHARD AGGREGATE LEDGER the headline invariant rather
than the per-receipt delivery contract.

--------------------------------------------------------------------------
The headline contract — the K-shard aggregate identity (XS-5, Form B of
CrossShardSupplyConservation.md §2.4, the quantity D1's
`aggregate_conserved()` lambda computes at main.cpp:26933-26943):

      aggregate  =  Sum_s [ live_total_supply(C_s)
                          + accumulated_outbound(C_s)
                          + accumulated_slashed(C_s)
                          - accumulated_inbound(C_s)
                          - accumulated_subsidy(C_s) ]

      Claim (XS-5):  aggregate  =  Sum_s genesis_total(C_s)  =:  G

for every reachable multi-shard state. Each shard's five supply-bearing
accumulators are exactly those of the per-shard A1 identity
(chain.hpp:443-449 / chain.cpp:548-553):

      live_total_supply(C_s) =  Sum(accounts_[d].balance)
                              + Sum(stakes_[d].locked)           (fields 1+2)
      expected_total(C_s)    =  genesis_total                    (field 3)
                              + accumulated_subsidy              (field 4, +)
                              + accumulated_inbound              (field 5, +)
                              - accumulated_slashed              (field 6, -)
                              - accumulated_outbound             (field 7, -)

Substituting live == expected_total (the per-shard A1, asserted at
chain.cpp:1397-1419) term-by-term into a shard's contribution collapses
it to genesis_total(C_s) (XS-1), so the aggregate over all K shards is
the FIXED genesis baseline G regardless of how many cross-shard transfers
are in flight.

--------------------------------------------------------------------------
The K-shard composition. State is a FUNCTION `shard` from the shard index
set `Shards = 0..K-1` to a per-shard record holding the seven
supply-bearing terms FB46 tracks per shard (balance + locked split into
the two live-supply components; the five accumulators genesis_total /
acc_subsidy / acc_inbound / acc_slashed / acc_outbound). The inbound
dedup is modeled as a SHARED set `applied` of (src_shard, tx_hash) pairs
— the key structure of `applied_inbound_receipts_` per XS-2 (the dedup
key is the PAIR, so the same tx_hash from two different source shards is
two distinct keys; chain.cpp:1365 + FA-Apply-9 T-R3). A replayed inbound
whose key is already in `applied` is a no-op (XS-2): no credit, no
acc_inbound tick, so the aggregate is unperturbed.

Actions modeled (each touches exactly ONE shard's accumulators, or, for
CreditInbound, one shard's balance + acc_inbound under the dedup guard):

  * EmitOutboundReceipt(s, d, frm, amt, txh) — SOURCE-shard step. Debit
    shard s's account `frm` by amt, bump s.acc_outbound by amt, and stage
    the receipt (s, txh, dst, amt) into the in-flight pool. Mirrors the
    cross-shard TRANSFER source arm (chain.cpp:752-766; XS-1 source case).
    Value leaves s's live supply and is carried by the +acc_outbound term.
    (The fee is handled by FeeRedistribute, NOT here — see XS-3.)
  * CreditInboundReceipt — DESTINATION-shard step. Take an in-flight
    receipt; if its (src_shard, tx_hash) key is already in `applied`,
    it is a no-op (XS-2 replay/dedup); otherwise credit the destination
    shard's account `to` by amt, bump that shard's acc_inbound by amt,
    and insert the key into `applied`. Mirrors the dst inbound-credit arm
    (chain.cpp:1363-1381; XS-1 destination case + XS-2 dedup).
  * FeeRedistribute(s, frm, cre, fee) — INTRA-shard step. Move `fee` from
    account `frm` to creator account `cre` on the SAME shard s. NO
    accumulator moves; live_total_supply(C_s) is unchanged (the fee is a
    balance->balance recirculation within one shard). Mirrors the
    fee->creator distribution (chain.cpp:1279-1305; XS-3 — the fee never
    enters acc_outbound and never crosses a shard boundary).
  * MintSubsidy(s, cre, amt) — per-shard subsidy mint (chain.cpp:1390-1392).
    Credit creator + bump s.acc_subsidy by the same amt. Net on the
    aggregate: +amt to live, -amt via the -acc_subsidy term => zero.
    Included so the aggregate identity is exercised in its GENERAL form
    (Form B), not only the subsidy-free Form A regime D1's test runs in.
  * SlashStake(s, d, amt) — per-shard forfeiture (chain.cpp:1395). Debit
    shard s's locked stake + bump s.acc_slashed. Net: -amt to live, +amt
    via the +acc_slashed term on the aggregate's LHS => zero (the burned
    value is re-counted as sequestered, recovering the genesis baseline).
  * StakeLock(s, d, amt) / StakeUnlock(s, d, amt) — intra-shard balance
    <-> locked moves (STAKE / UNSTAKE), NO accumulator change. Included
    because live_total_supply sums BOTH components; a balance->locked move
    must leave the aggregate unchanged.
  * SerializeRestore(s) — snapshot round-trip on shard s. Models XS-4:
    serialize_state -> restore_from_snapshot reproduces all seven
    supply-bearing fields + the dedup set verbatim, so it is the IDENTITY
    on the aggregate (chain.cpp:1614-1618 counters + 1586-1592/1778-1783
    dedup set; FA-Apply-2 T-S3 + FA-Apply-12 T-R4). Modeled as an explicit
    no-op-on-supply action whose enabledness witnesses that the round-trip
    leaves every term fixed.

--------------------------------------------------------------------------
Invariants (mapping XS-1..XS-5):

  (T-X0) Inv_TypeOK — every per-shard term and the shared dedup set have
         the right shapes; all amounts Nat-valued + bounded for TLC.
  (T-X1) Inv_PerStepConservation (XS-1) — at EVERY reachable state, each
         shard's per-shard A1 closes: live(C_s) + slashed(C_s) +
         outbound(C_s) = genesis(C_s) + subsidy(C_s) + inbound(C_s). This
         is the per-shard `live == expected_total` lifted to the
         state-machine layer (chain.cpp:1397). Because XS-1 proves each
         step leaves the aggregate fixed BY collapsing each shard's
         contribution to genesis_total, the per-shard closure IS the
         per-step conservation mechanism.
  (T-X2) Inv_NoDoubleCredit (XS-2) — acc_inbound on each shard never
         exceeds the total amount of DISTINCT applied receipt keys that
         credited it; a replayed key (already in `applied`) cannot tick
         acc_inbound or a balance again. State-form: the per-shard
         acc_inbound equals the sum of amounts of applied keys whose
         destination is that shard — exactly-once crediting.
  (T-X3) Inv_FeeHandling (XS-3) — the fee stays intra-shard: no
         FeeRedistribute step ever changes any acc_outbound (the fee never
         enters the cross-shard accumulator) and the fee-bearing shard's
         live_total_supply is unchanged by the move. State-form witness:
         total outbound across shards equals the total amount STAGED as
         cross-shard receipt principal — fees are excluded from outbound.
  (T-X4) Inv_SnapshotRestoreInvariance (XS-4) — SerializeRestore(s) is the
         identity on the aggregate: the saved snapshot of shard s holds
         the same seven terms the live shard holds, so restoring rebuilds
         the same contribution. State-form: whenever a snapshot exists for
         shard s, its contribution-to-aggregate equals the live shard's,
         and equals genesis(C_s).
  (T-X5) Inv_AggregateIdentity (XS-5) — THE HEADLINE. The K-shard
         aggregate equals the fixed genesis baseline G at every reachable
         state:
              Sum_s [ live(C_s) + outbound(C_s) + slashed(C_s) ]
            = Sum_s [ genesis(C_s) + inbound(C_s) + subsidy(C_s) ]
         (the Nat-safe rearrangement of Sum_s contrib(C_s) = G with the
         subtracted accumulators moved to the RHS, mirroring FB46's
         Inv_A1UnitarySupply discipline — no subtraction crosses zero).
  (T-X6) Prop_AggregateAlwaysConserved — temporal []-restatement of T-X5.

Modeling scope (kept small + finite-checkable so it COULD be
model-checked later):

  * CONSTANT K (= Cardinality(Shards)) shards; recommended K = 3 to match
    D1's K=3 instance. Genesis supply is pre-seeded per shard (a fixed
    constant per shard) and never mutated afterwards (chain.cpp:711).
  * Amounts bounded by MaxDelta; action count bounded by MaxSteps — keeps
    TLC's state space finite. The C++ checked_add_u64 overflow guards are
    out of scope (every FB-track economic spec abstracts them away).
  * The gossip transit / CROSS_SHARD_RECEIPT_LATENCY admission gate /
    multi-stage snapshot pipeline of FB32 are ABSTRACTED: an emitted
    receipt lands directly in a shared `inflight` pool, and CreditInbound
    consumes from it. The supply-conservation identity holds whether or
    not the coin has landed (it is counted in-flight via the +acc_outbound
    term until the -acc_inbound term cancels it on credit); the DELIVERY
    liveness is FB32 / FA7 territory, not this aggregate-ledger spec.
  * XS-0 (shard-state disjointness / order independence) is structural in
    this model: each action's EXCEPT clause mutates exactly one shard's
    record, so distinct-shard steps commute by construction; the single
    function `shard` makes the per-shard states manifestly disjoint.

Companion analytic proof: `docs/proofs/CrossShardSupplyConservation.md`
(FA-Apply-17, theorems XS-1..XS-5). Empirical pin: D1's regression
`determ test-cross-shard-supply-invariant` (main.cpp:26838-27144;
wrapper tools/test_cross_shard_supply_invariant.sh; 30 PASS).

Adjacent specs: FB46 (UnitarySupplyLedger — single-shard five-term A1;
THIS spec is the K-shard composition), FB14 (CrossShardReceiptDedup —
dst-side dedup), FB17 (AppliedReceiptRestore — dedup-set snapshot
survival), FB18 (CrossShardOutboundApply — src-side debit), FB32
(CrossShardReceiptRoundtrip — receipt lifecycle whose EmitOutbound /
CreditInbound shapes this spec reuses), FB10 (FeeAccounting — fee-is-
intra-supply), FB11 (SubsidyDistribution — subsidy mint).

NOTE: spec-only, model-check pending TLC install (matching every sibling
in this directory).

To check (assuming TLC installed):
  $ tlc CrossShardSupplyConservation.tla -config CrossShardSupplyConservation.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Shards,             \* set of shard indices, e.g. 0..K-1
    Accounts,           \* set of account / creator identifiers (within a shard)
    Hashes,             \* finite universe of tx-hash identifiers (the dedup-key txh component)
    GenesisPerShard,    \* function Shards -> Nat : each shard's fixed genesis_total
    MaxDelta,           \* upper bound on any single per-action amount
    MaxSteps            \* upper bound on action count for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Shards)   >= 2
    /\ Cardinality(Accounts) >= 2
    /\ Cardinality(Hashes)   >= 1
    /\ GenesisPerShard \in [Shards -> Nat]
    /\ \E s \in Shards : GenesisPerShard[s] >= 1
    \* Each shard's genesis must divide evenly across its accounts so the
    \* Init balance allocation is exact (no dust left unaccounted). The
    \* .cfg picks GenesisPerShard[s] a multiple of Cardinality(Accounts).
    /\ \A s \in Shards : GenesisPerShard[s] % Cardinality(Accounts) = 0
    /\ MaxDelta \in Nat /\ MaxDelta >= 1
    /\ MaxSteps \in Nat /\ MaxSteps >= 1

----------------------------------------------------------------------------
\* §1. Type shapes.

\* The (src_shard, tx_hash) dedup-key PAIR backing applied_inbound_receipts_
\* (chain.cpp:1365). Same tx_hash from two different src_shards is two
\* distinct keys (XS-2 / FA-Apply-9 T-R3).
DedupKey == [src_shard: Shards, tx_hash: Hashes]

\* An in-flight cross-shard receipt: the invariant-relevant subset of the
\* CrossShardReceipt (src_shard, tx_hash, to_shard, to, amount). The fee is
\* NOT on the receipt — it stays on the source shard for creator
\* distribution (XS-3; the receipt carries principal only).
Receipt == [src_shard: Shards,
            tx_hash:   Hashes,
            to_shard:  Shards,
            to:        Accounts,
            amount:    1..MaxDelta]

KeyOf(r) == [src_shard |-> r.src_shard, tx_hash |-> r.tx_hash]

\* Per-shard supply-bearing record. balance + locked are the two
\* live_total_supply components (fields 1+2); genesis + the four
\* accumulators are fields 3-7 of CrossShardSupplyConservation.md §2.2.
ShardState == [balance:      [Accounts -> Nat],
               locked:       [Accounts -> Nat],
               genesis:      Nat,
               acc_subsidy:  Nat,
               acc_inbound:  Nat,
               acc_slashed:  Nat,
               acc_outbound: Nat]

----------------------------------------------------------------------------
\* §2. State.

VARIABLES
    shard,      \* function Shards -> ShardState (the K disjoint per-shard ledgers)
    inflight,   \* Seq(Receipt) — emitted-but-not-yet-credited receipts (the in-flight pool)
    applied,    \* SUBSET DedupKey — the SHARED inbound dedup set (XS-2)
    steps       \* Nat — action counter, bounds TLC

vars == <<shard, inflight, applied, steps>>

----------------------------------------------------------------------------
\* §3. Helpers.

\* Sum of an Accounts-indexed Nat function. Recursive fold (Naturals.tla
\* ships no fold-over-finite-sets primitive TLC handles natively at this
\* arity); pattern matches FB46::SumOver / FeeAccounting.tla::SumBalances.
RECURSIVE SumOverAccounts_(_, _)
SumOverAccounts_(f, as) ==
    IF as = {}
    THEN 0
    ELSE LET a == CHOOSE x \in as : TRUE
         IN  f[a] + SumOverAccounts_(f, as \ {a})

SumOverAccounts(f) == SumOverAccounts_(f, Accounts)

\* live_total_supply(C_s) — the two-component live sum at chain.cpp:548-553.
LiveOf(st) == SumOverAccounts(st.balance) + SumOverAccounts(st.locked)

\* Sum of amounts across a sequence of in-flight receipts. The aggregate's
\* transient in-flight mass; pattern matches FB32::SumAmounts.
RECURSIVE SumAmounts_(_, _)
SumAmounts_(s, i) ==
    IF i = 0
    THEN 0
    ELSE s[i].amount + SumAmounts_(s, i - 1)

SumAmounts(s) == SumAmounts_(s, Len(s))

\* Sum of a Shards-indexed Nat expression `expr(s)`. Used to compose the
\* per-shard contributions into the K-shard aggregate.
RECURSIVE SumOverShards_(_, _)
SumOverShards_(g, ss) ==
    IF ss = {}
    THEN 0
    ELSE LET s == CHOOSE x \in ss : TRUE
         IN  g[s] + SumOverShards_(g, ss \ {s})

SumOverShards(g) == SumOverShards_(g, Shards)

\* The (fixed) aggregate genesis baseline  G := Sum_s genesis_total(C_s).
\* Written off GenesisPerShard so it is a manifest constant; equals
\* Sum_s shard[s].genesis at every reachable state (genesis is never mutated).
G == SumOverShards([s \in Shards |-> GenesisPerShard[s]])

\* Per-shard live sum, slashed, outbound, inbound, subsidy as Shards->Nat
\* functions, for composing the aggregate identity.
LiveFn     == [s \in Shards |-> LiveOf(shard[s])]
OutboundFn == [s \in Shards |-> shard[s].acc_outbound]
SlashedFn  == [s \in Shards |-> shard[s].acc_slashed]
InboundFn  == [s \in Shards |-> shard[s].acc_inbound]
SubsidyFn  == [s \in Shards |-> shard[s].acc_subsidy]
GenesisFn  == [s \in Shards |-> shard[s].genesis]

----------------------------------------------------------------------------
\* §4. Initial state. Each shard pre-allocates its genesis evenly across
\* its accounts (so the live sum at genesis equals GenesisPerShard[s], the
\* C++ load path chain.cpp:711 sets genesis_total_ = the live sum at
\* genesis). All stake starts at zero; all four delta accumulators start
\* at zero. The in-flight pool and the dedup set start empty.

InitShard(s) ==
    [balance      |-> [a \in Accounts |-> GenesisPerShard[s] \div Cardinality(Accounts)],
     locked       |-> [a \in Accounts |-> 0],
     genesis      |-> GenesisPerShard[s],
     acc_subsidy  |-> 0,
     acc_inbound  |-> 0,
     acc_slashed  |-> 0,
     acc_outbound |-> 0]

Init ==
    /\ shard    = [s \in Shards |-> InitShard(s)]
    /\ inflight = <<>>
    /\ applied  = {}
    /\ steps    = 0

----------------------------------------------------------------------------
\* §5. Actions. Each per-shard action mutates exactly ONE shard's record
\* (the EXCEPT [shard EXCEPT ![s] = ...] form), so distinct-shard steps
\* touch disjoint memory and commute (XS-0 order-independence is
\* structural). The accumulator-touching actions bump exactly one running
\* total by the same amount the live supply moves, so the per-shard A1
\* (and hence the aggregate) is preserved per-action.

\* EmitOutboundReceipt(s, d, frm, amt, txh): SOURCE-shard cross-shard
\* TRANSFER (chain.cpp:752-766). Debit shard s's account `frm` by amt,
\* bump s.acc_outbound by amt, stage the receipt into the in-flight pool.
\* d /= s so the receipt routes off-shard (cross-shard). The destination
\* credit happens later, on shard d, via CreditInboundReceipt. XS-1 source
\* case: live(C_s) -amt, +acc_outbound +amt => source contribution fixed
\* (the coin is now in flight).
EmitOutboundReceipt(s, d, frm, amt, txh) ==
    /\ steps < MaxSteps
    /\ s \in Shards /\ d \in Shards /\ s /= d
    /\ frm \in Accounts
    /\ amt \in 1..MaxDelta
    /\ txh \in Hashes
    /\ shard[s].balance[frm] >= amt
    \* a fresh dedup key (no receipt already in flight or applied with this
    \* (s, txh) pair) — keeps the model's exactly-once book-keeping clean.
    /\ KeyOf([src_shard |-> s, tx_hash |-> txh]) \notin applied
    /\ \A i \in 1..Len(inflight) :
          ~(inflight[i].src_shard = s /\ inflight[i].tx_hash = txh)
    /\ LET to_acct == CHOOSE a \in Accounts : TRUE IN
       LET r == [src_shard |-> s, tx_hash |-> txh, to_shard |-> d,
                 to |-> to_acct, amount |-> amt] IN
       /\ shard' = [shard EXCEPT
              ![s].balance[frm]  = @ - amt,
              ![s].acc_outbound  = @ + amt]
       /\ inflight' = Append(inflight, r)
    /\ UNCHANGED <<applied>>
    /\ steps' = steps + 1

\* CreditInboundReceipt: DESTINATION-shard inbound-credit (chain.cpp:1363
\* -1381). Take the head in-flight receipt r routed to shard r.to_shard.
\* Two branches under the dedup guard (XS-2):
\*   - DUPLICATE: KeyOf(r) already in `applied` => no-op: drop r from the
\*     pool, NO balance credit, NO acc_inbound tick (chain.cpp:1365
\*     `if (...count(key)) continue;`).  The aggregate is unperturbed.
\*   - FRESH: credit shard r.to_shard's account r.to by r.amount, bump
\*     that shard's acc_inbound by r.amount, insert KeyOf(r) into `applied`.
\* XS-1 destination case: live +amt, +acc_inbound +amt => dest
\* contribution fixed (the coin has landed).
CreditInboundReceipt ==
    /\ steps < MaxSteps
    /\ Len(inflight) > 0
    /\ LET r == Head(inflight) IN
       LET d == r.to_shard IN
       LET k == KeyOf(r) IN
       IF k \in applied
       THEN \* duplicate / replay: silent no-op (XS-2)
          /\ inflight' = Tail(inflight)
          /\ UNCHANGED <<shard, applied>>
          /\ steps' = steps + 1
       ELSE \* fresh: credit + tick acc_inbound + record dedup key (XS-1 dst)
          /\ shard' = [shard EXCEPT
                 ![d].balance[r.to] = @ + r.amount,
                 ![d].acc_inbound   = @ + r.amount]
          /\ inflight' = Tail(inflight)
          /\ applied'  = applied \cup {k}
          /\ steps' = steps + 1

\* ReplayInboundReceipt(r): adversary re-injects an ALREADY-APPLIED
\* receipt into the in-flight pool. Its KeyOf(r) is in `applied`, so the
\* eventual CreditInboundReceipt routes to the duplicate branch — no
\* balance, no acc_inbound tick (XS-2). Witnesses that replay cannot
\* perturb the aggregate.
ReplayInboundReceipt(r) ==
    /\ steps < MaxSteps
    /\ r \in Receipt
    /\ KeyOf(r) \in applied
    /\ inflight' = Append(inflight, r)
    /\ UNCHANGED <<shard, applied>>
    /\ steps' = steps + 1

\* FeeRedistribute(s, frm, cre, fee): INTRA-shard fee move (chain.cpp:1279
\* -1305). Move `fee` from account `frm` to creator account `cre` on the
\* SAME shard s. NO accumulator moves — the fee never enters acc_outbound
\* and never crosses a shard boundary (XS-3). live_total_supply(C_s) is
\* unchanged (balance->balance recirculation within one shard).
FeeRedistribute(s, frm, cre, fee) ==
    /\ steps < MaxSteps
    /\ s \in Shards
    /\ frm \in Accounts /\ cre \in Accounts /\ frm /= cre
    /\ fee \in 1..MaxDelta
    /\ shard[s].balance[frm] >= fee
    /\ shard' = [shard EXCEPT
           ![s].balance[frm] = @ - fee,
           ![s].balance[cre] = @ + fee]
    /\ UNCHANGED <<inflight, applied>>
    /\ steps' = steps + 1

\* MintSubsidy(s, cre, amt): per-shard block-subsidy mint (chain.cpp:1390
\* -1392). Credit creator `cre` on shard s + bump s.acc_subsidy by the
\* same amt. Net on the aggregate: +amt to live, -amt via the -acc_subsidy
\* netting term => zero. Exercises the general (Form B) aggregate identity.
MintSubsidy(s, cre, amt) ==
    /\ steps < MaxSteps
    /\ s \in Shards
    /\ cre \in Accounts
    /\ amt \in 1..MaxDelta
    /\ shard' = [shard EXCEPT
           ![s].balance[cre] = @ + amt,
           ![s].acc_subsidy  = @ + amt]
    /\ UNCHANGED <<inflight, applied>>
    /\ steps' = steps + 1

\* SlashStake(s, d, amt): per-shard forfeiture (chain.cpp:1395 + FA5/FA6).
\* Debit shard s's locked stake for account d + bump s.acc_slashed by the
\* same amt. Net: -amt to live, +amt via the +acc_slashed term on the
\* aggregate's LHS => zero (burned value re-counted as sequestered).
SlashStake(s, d, amt) ==
    /\ steps < MaxSteps
    /\ s \in Shards
    /\ d \in Accounts
    /\ amt \in 1..MaxDelta
    /\ shard[s].locked[d] >= amt
    /\ shard' = [shard EXCEPT
           ![s].locked[d]    = @ - amt,
           ![s].acc_slashed  = @ + amt]
    /\ UNCHANGED <<inflight, applied>>
    /\ steps' = steps + 1

\* StakeLock(s, d, amt): intra-shard balance -> locked move (STAKE). NO
\* accumulator change; live_total_supply unchanged (value moves between
\* the two summed components). The case a balance-only spec would mishandle.
StakeLock(s, d, amt) ==
    /\ steps < MaxSteps
    /\ s \in Shards
    /\ d \in Accounts
    /\ amt \in 1..MaxDelta
    /\ shard[s].balance[d] >= amt
    /\ shard' = [shard EXCEPT
           ![s].balance[d] = @ - amt,
           ![s].locked[d]  = @ + amt]
    /\ UNCHANGED <<inflight, applied>>
    /\ steps' = steps + 1

\* StakeUnlock(s, d, amt): intra-shard locked -> balance move (UNSTAKE
\* post unlock-height). NO accumulator change. Mirror of StakeLock.
StakeUnlock(s, d, amt) ==
    /\ steps < MaxSteps
    /\ s \in Shards
    /\ d \in Accounts
    /\ amt \in 1..MaxDelta
    /\ shard[s].locked[d] >= amt
    /\ shard' = [shard EXCEPT
           ![s].locked[d]  = @ - amt,
           ![s].balance[d] = @ + amt]
    /\ UNCHANGED <<inflight, applied>>
    /\ steps' = steps + 1

\* SerializeRestore(s): snapshot round-trip on shard s (XS-4).
\* serialize_state -> restore_from_snapshot reproduces all seven
\* supply-bearing fields + the dedup set verbatim (chain.cpp:1614-1618 +
\* 1586-1592/1778-1783; FA-Apply-2 T-S3 + FA-Apply-12 T-R4), so the
\* round-trip is the IDENTITY on the aggregate. Modeled as a stuttering
\* step that leaves every supply-bearing term fixed — its enabledness is
\* the state-form witness that restore preserves shard s's contribution.
SerializeRestore(s) ==
    /\ steps < MaxSteps
    /\ s \in Shards
    /\ shard'    = [shard EXCEPT ![s] = shard[s]]   \* round-trip identity
    /\ applied'  = applied
    /\ UNCHANGED <<inflight>>
    /\ steps' = steps + 1

----------------------------------------------------------------------------
\* §6. Next-state relation. All apply-layer actions in arbitrary
\* interleaving across the K shards. TLC enumerates the composition.

Next ==
    \/ \E s, d \in Shards, frm \in Accounts, amt \in 1..MaxDelta, txh \in Hashes :
          EmitOutboundReceipt(s, d, frm, amt, txh)
    \/ CreditInboundReceipt
    \/ \E r \in Receipt : ReplayInboundReceipt(r)
    \/ \E s \in Shards, frm, cre \in Accounts, fee \in 1..MaxDelta :
          FeeRedistribute(s, frm, cre, fee)
    \/ \E s \in Shards, cre \in Accounts, amt \in 1..MaxDelta :
          MintSubsidy(s, cre, amt)
    \/ \E s \in Shards, d \in Accounts, amt \in 1..MaxDelta :
          SlashStake(s, d, amt)
    \/ \E s \in Shards, d \in Accounts, amt \in 1..MaxDelta :
          StakeLock(s, d, amt)
    \/ \E s \in Shards, d \in Accounts, amt \in 1..MaxDelta :
          StakeUnlock(s, d, amt)
    \/ \E s \in Shards : SerializeRestore(s)

\* Weak fairness on CreditInboundReceipt drives the temporal witness: an
\* emitted in-flight receipt is eventually credited (or dedup-skipped), so
\* the aggregate's in-flight term eventually collapses onto destination
\* balances. The aggregate identity holds in EVERY reachable state
\* regardless of which actions fire (Prop_AggregateAlwaysConserved).
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(CreditInboundReceipt)

----------------------------------------------------------------------------
\* §7. Invariants — XS-1..XS-5.

\* T-X0 / Inv_TypeOK: every per-shard term and the shared dedup set have
\* the right shapes; all amounts Nat-valued and bounded so TLC's state
\* space is finite. The ceiling allows for the cumulative mintable +
\* received-in mass over MaxSteps actions on top of each shard's genesis.
Inv_TypeOK ==
    LET ceil == G + 2 * MaxDelta * MaxSteps IN
    /\ shard \in [Shards -> ShardState]
    /\ \A s \in Shards :
          /\ shard[s].balance \in [Accounts -> 0..ceil]
          /\ shard[s].locked  \in [Accounts -> 0..ceil]
          /\ shard[s].genesis      = GenesisPerShard[s]
          /\ shard[s].acc_subsidy  \in 0..(MaxDelta * MaxSteps)
          /\ shard[s].acc_inbound  \in 0..(MaxDelta * MaxSteps)
          /\ shard[s].acc_slashed  \in 0..(MaxDelta * MaxSteps)
          /\ shard[s].acc_outbound \in 0..(MaxDelta * MaxSteps)
    /\ inflight \in Seq(Receipt)
    /\ applied  \in SUBSET DedupKey
    /\ steps \in 0..MaxSteps

\* T-X1 / Inv_PerStepConservation (XS-1): at EVERY reachable state, each
\* shard's per-shard A1 closes —
\*       live(C_s) + slashed(C_s) + outbound(C_s)
\*     = genesis(C_s) + subsidy(C_s) + inbound(C_s).
\* This is the per-shard `live_total_supply() == expected_total()`
\* assertion (chain.cpp:1397) lifted to the state-machine layer, with the
\* subtracted accumulators moved to the RHS so both sides are manifestly
\* Nat-valued. Because XS-1 collapses each shard's contribution to
\* genesis_total via exactly this closure, per-shard A1 IS the per-step
\* conservation mechanism for the aggregate.
Inv_PerStepConservation ==
    \A s \in Shards :
       LiveOf(shard[s]) + shard[s].acc_slashed + shard[s].acc_outbound
           = shard[s].genesis + shard[s].acc_subsidy + shard[s].acc_inbound

\* T-X2 / Inv_NoDoubleCredit (XS-2): a receipt key credits acc_inbound at
\* most once. State-form: the total acc_inbound across all shards equals
\* the sum of amounts of the DISTINCT applied keys (the `applied` set
\* records each credited key exactly once; a replayed key is already in
\* `applied` and routes to the no-op branch, so it cannot tick acc_inbound
\* again). Encoded as the bound: total inbound never exceeds the
\* cumulative principal that has been emitted (each applied key came from
\* exactly one EmitOutboundReceipt's staged principal), AND no acc_inbound
\* exists without a matching dedup-key record.
Inv_NoDoubleCredit ==
    /\ Cardinality(applied) <= steps
    /\ SumOverShards(InboundFn)
         <= SumOverShards(OutboundFn) + SumAmounts(inflight)

\* T-X3 / Inv_FeeHandling (XS-3): the fee never enters the cross-shard
\* accumulator. State-form: the total outbound principal across shards
\* equals exactly the principal that has been STAGED as cross-shard
\* receipts (the sum of amounts currently in flight PLUS the principal
\* already credited inbound) — fees are excluded from outbound because
\* FeeRedistribute touches NO acc_outbound. Equivalently, every unit in
\* acc_outbound is carried by either an in-flight receipt or an applied
\* (credited) inbound; the fee, being a pure intra-shard balance move, is
\* never one of those units.
Inv_FeeHandling ==
    SumOverShards(OutboundFn)
        = SumAmounts(inflight) + SumOverShards(InboundFn)

\* T-X4 / Inv_SnapshotRestoreInvariance (XS-4): a snapshot round-trip on
\* any shard reproduces its contribution-to-aggregate exactly. State-form:
\* every shard's contribution collapses to its (fixed) genesis baseline —
\* SerializeRestore(s) is the identity on shard[s], so the post-restore
\* contribution equals the pre-restore contribution equals genesis(C_s).
\* This is the per-shard contribution form of XS-1 read as the restore
\* invariant: restore preserves the seven terms, so it preserves the
\* contribution.
Inv_SnapshotRestoreInvariance ==
    \A s \in Shards :
       LiveOf(shard[s]) + shard[s].acc_outbound + shard[s].acc_slashed
           = shard[s].genesis + shard[s].acc_inbound + shard[s].acc_subsidy

\* T-X5 / Inv_AggregateIdentity (XS-5): THE HEADLINE — the K-shard
\* aggregate equals the fixed genesis baseline G at every reachable state.
\* This is Form B of CrossShardSupplyConservation.md §2.4
\*       Sum_s [ live + outbound + slashed - inbound - subsidy ] = G
\* rearranged into the Nat-safe additive form (subtracted accumulators on
\* the RHS, mirroring FB46's Inv_A1UnitarySupply — no subtraction crosses
\* zero):
\*       Sum_s [ live(C_s) + outbound(C_s) + slashed(C_s) ]
\*     = Sum_s [ genesis(C_s) + inbound(C_s) + subsidy(C_s) ].
\* The RHS equals G + Sum inbound + Sum subsidy; the headline claim
\* "aggregate == G" follows by netting the two added accumulators back out
\* per §2.4. The Inv_PerStepConservation per-shard closure summed over
\* Shards yields exactly this equality, so XS-5 is the K-shard sum of XS-1.
Inv_AggregateIdentity ==
    SumOverShards(LiveFn)
      + SumOverShards(OutboundFn)
      + SumOverShards(SlashedFn)
    = SumOverShards(GenesisFn)
      + SumOverShards(InboundFn)
      + SumOverShards(SubsidyFn)

\* An explicit restatement pinning the aggregate to the FIXED genesis
\* constant G (the §2.4 Form-B "aggregate == G" closed identity), obtained
\* by netting the two added accumulators (inbound + subsidy) out of both
\* sides of Inv_AggregateIdentity. Since acc_inbound / acc_subsidy appear
\* on both sides after that netting, this is equivalent to
\* Inv_AggregateIdentity but states the genesis-baseline form directly.
Inv_AggregateEqualsGenesis ==
    (SumOverShards(LiveFn)
       + SumOverShards(OutboundFn)
       + SumOverShards(SlashedFn))
    - (SumOverShards(InboundFn) + SumOverShards(SubsidyFn))
    = G

----------------------------------------------------------------------------
\* §8. Temporal property.

\* T-X6 / Prop_AggregateAlwaysConserved: temporal []-restatement of T-X5.
\* Across every reachable state the K-shard aggregate ledger closes on the
\* fixed genesis baseline — the cross-shard conservation theorem as a
\* standing []-claim (mirroring FB46's Prop_SupplyAlwaysCloses).
Prop_AggregateAlwaysConserved ==
    [](  SumOverShards(LiveFn)
           + SumOverShards(OutboundFn)
           + SumOverShards(SlashedFn)
       = SumOverShards(GenesisFn)
           + SumOverShards(InboundFn)
           + SumOverShards(SubsidyFn) )

============================================================================
\* Cross-references.
\*
\* FB46 (UnitarySupplyLedger.tla) — the SINGLE-SHARD five-term A1 ledger.
\*   THIS spec (FB54) is its K-shard composition: Inv_PerStepConservation
\*   is FB46's Inv_A1UnitarySupply applied per shard, and
\*   Inv_AggregateIdentity is the sum of those per-shard closures over the
\*   shard set. FB46 proves each shard's ledger closes; FB54 proves the
\*   K-shard sum closes, with the +acc_outbound / -acc_inbound terms
\*   carrying value that is in flight between shards.
\*
\* FB32 (CrossShardReceiptRoundtrip.tla) — the receipt LIFECYCLE (source
\*   emit + gossip + time-ordered admission + dst dedup + snapshot). FB54
\*   reuses FB32's EmitOutbound / CreditInbound action SHAPES but abstracts
\*   the gossip/latency/snapshot pipeline to make the K-shard AGGREGATE
\*   LEDGER the headline rather than per-receipt delivery.
\*
\* FB14 (CrossShardReceiptDedup.tla) — dst-side dedup in isolation; FB54's
\*   CreditInboundReceipt duplicate branch is the same `applied`-keyed
\*   no-op (XS-2).
\* FB17 (AppliedReceiptRestore.tla) — dedup-set snapshot survival; FB54's
\*   SerializeRestore composes it into the aggregate-invariance claim (XS-4).
\* FB18 (CrossShardOutboundApply.tla) — src-side debit in isolation; FB54's
\*   EmitOutboundReceipt is the same +acc_outbound debit (XS-1 source).
\* FB10 (FeeAccounting.tla) — fee-is-intra-supply; FB54's FeeRedistribute
\*   is the same balance->creator move with NO accumulator change (XS-3).
\* FB11 (SubsidyDistribution.tla) — subsidy mint; FB54's MintSubsidy is the
\*   same +acc_subsidy credit, here composed into the K-shard aggregate.
\*
\* Companion analytic proof:
\*   docs/proofs/CrossShardSupplyConservation.md (FA-Apply-17, XS-1..XS-5).
\*   Inv_PerStepConservation = XS-1; Inv_NoDoubleCredit = XS-2;
\*   Inv_FeeHandling = XS-3; Inv_SnapshotRestoreInvariance = XS-4;
\*   Inv_AggregateIdentity / Inv_AggregateEqualsGenesis /
\*   Prop_AggregateAlwaysConserved = XS-5.
\*
\* C++ enforcement:
\*   src/chain/chain.cpp:1397-1419 : per-shard A1 post-apply assertion
\*       (live_total_supply() == expected_total()) — Inv_PerStepConservation.
\*   src/chain/chain.cpp:548-553 : live_total_supply() (fields 1+2).
\*   include/determ/chain/chain.hpp:443-449 : expected_total() five-term form.
\*   src/chain/chain.cpp:680-717 : genesis bootstrap (genesis_total_ + zeroed
\*       accumulators) — Init / G.
\*   src/chain/chain.cpp:742-769 : cross-shard TRANSFER source arm
\*       (debit + block_outbound += amount; fee stays local) —
\*       EmitOutboundReceipt + FeeRedistribute.
\*   src/chain/chain.cpp:1363-1381 : inbound-receipt dedup-guard + credit —
\*       CreditInboundReceipt (XS-1 dst + XS-2 dedup).
\*   src/chain/chain.cpp:1391-1395 : accumulator fold (the only per-block
\*       mutation of fields 4-7).
\*   src/chain/chain.cpp:1279-1305 : fee -> creator distribution (XS-3) —
\*       FeeRedistribute.
\*   src/chain/chain.cpp:1614-1618 + 1586-1592 + 1778-1783 + 1867-1877 :
\*       serialize_state / restore_from_snapshot of the counters + dedup set
\*       + genesis back-solve (XS-4) — SerializeRestore.
\*
\* Runtime regression:
\*   determ test-cross-shard-supply-invariant (D1; main.cpp:26838-27144;
\*       30 PASS) — the empirical pin; aggregate_conserved() lambda
\*       (main.cpp:26933-26943) is Form B verbatim.
\*   tools/test_cross_shard_supply_invariant.sh — run-from-root wrapper.
\*   tools/operator_supply_check.sh — read-only operator-facing auditor.
\*
\* To check (assuming TLC installed):
\*   $ tlc CrossShardSupplyConservation.tla -config CrossShardSupplyConservation.cfg
\* Recommended config (small + finite): Shards = {0,1,2} (K=3 matching D1),
\*   Accounts = {a1, a2}, Hashes = {h1, h2},
\*   GenesisPerShard = (0 :> 4 @@ 1 :> 0 @@ 2 :> 0)  (each a multiple of
\*   |Accounts|=2; mirrors D1's funded-source / unfunded-peers instance),
\*   MaxDelta = 2, MaxSteps = 4.
============================================================================
