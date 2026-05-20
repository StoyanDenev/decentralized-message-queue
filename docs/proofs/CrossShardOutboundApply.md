# FA-Apply-13 — Cross-shard outbound TRANSFER apply (source side)

This document formalizes the apply-layer mechanics for the **source side** of a cross-shard `TRANSFER` — i.e., a `TRANSFER` whose `to` address routes (via `crypto::shard_id_for_address`) to a shard different from `my_shard_id_`. The destination-side mechanics (credit, dedup, A1 inbound accounting) are the scope of `CrossShardReceiptDedup.md` (FA-Apply-9); the present proof is the symmetric source-side proof, covering the debit, the receipt emission, the `accumulated_outbound_` accumulator update, and the per-shard A1 closure that consumes it.

The mechanism: `Chain::is_cross_shard(to)` (`chain.cpp:198–202`) returns `true` iff `shard_count_ > 1` AND `shard_id_for_address(to, shard_count_, shard_salt_) != my_shard_id_`. The TRANSFER apply branch at `chain.cpp:742–770` then forks: same-shard takes the local credit-debit path (`accounts_[to].balance += amount`), cross-shard takes the **outbound** path (no local credit, `block_outbound += amount` instead). The producer earlier baked the matching `CrossShardReceipt` into `block.cross_shard_receipts[]` via `producer.cpp:449–465`, and the V12 validator (`validator.cpp:1081–1110`) enforced 1:1 binding between cross-shard `TRANSFER` txs and receipt entries. The apply path consumes a V12-cleared block, so it can assume the receipt list is well-formed; its job is to keep the per-shard A1 books straight as value leaves the local supply.

The proof's strength is consolidation: FA7 (`CrossShardReceipts.md`) covers the protocol-level atomicity claim T-7 / T-7.1 by composing both halves (source debit + destination credit) into a global supply invariant; the present proof drills into the source-side mechanism that L-7.3 cites as a black-box ("Source-side debit precedes receipt emission"). The companion FA-Apply-9 covers the symmetric destination side. Together, FA-Apply-9 + FA-Apply-13 are the apply-layer skeleton of FA7.

**Companion documents:** `Preliminaries.md` (F0) for notation and V12 (`check_cross_shard_receipts`); `AccountStateInvariants.md` (FA-Apply) for I-5 debit-channel decomposition (the cross-shard TRANSFER source branch is one of the named debit channels) + I-6 A1 closure that consumes `accumulated_outbound_`; `CrossShardReceipts.md` (FA7) for the upstream atomicity theorems T-7 / T-7' / T-7.1 (the source-side debit precedes-receipt-emission L-7.3 lemma is what this proof formalizes mechanically); `CrossShardReceiptDedup.md` (FA-Apply-9) for the destination-side symmetric proof (T-R1..T-R7 cover the credit-side mechanism) — composition with FA-Apply-9 is the joint cross-shard A1 atomicity story; `AppliedReceiptRestore.md` (FA-Apply-12) for the snapshot-round-trip story on the destination side (the source side has no analogous dedup-set, since outbound emission is a one-shot per-block event, but `accumulated_outbound_` is itself snapshot-restored via the `c:` namespace per FA-Apply-2 T-S3); `EconomicSoundness.md` (FA11) for the A1 unitary-balance invariant that this proof preserves; `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot equivalence that carries `accumulated_outbound_` across restore boundaries.

---

## 1. Setup

### 1.1 The `is_cross_shard` predicate

Per `chain.cpp:198–202`:

```cpp
bool Chain::is_cross_shard(const std::string& to) const {
    if (shard_count_ <= 1) return false;
    return crypto::shard_id_for_address(to, shard_count_, shard_salt_)
           != my_shard_id_;
}
```

The short-circuit at line 199 is the single-shard fallback: when `shard_count_ <= 1` (SINGLE / BEACON mode), the predicate is identically `false` — no address is cross-shard, every TRANSFER takes the local-credit path, and `accumulated_outbound_` stays at zero forever. The branch at line 200 invokes `crypto::shard_id_for_address(to, shard_count_, shard_salt_)`, the SHA-256-based deterministic routing function that maps every address to a `ShardId ∈ [0, shard_count_)` under the per-chain `shard_salt_` (S-019 hardening). The predicate returns `true` iff the routed shard differs from `my_shard_id_`. The function is `const` and pure — no side effects, no clock reads, no randomness.

### 1.2 The TRANSFER apply branch fork

Per `chain.cpp:742–770`:

```cpp
case TxType::TRANSFER: {
    uint64_t cost = tx.amount + tx.fee;
    if (sender.balance < cost) continue;
    sender.balance -= cost;
    if (!is_cross_shard(tx.to)) {
        auto& rcv = accounts_[tx.to].balance;
        if (!checked_add_u64(rcv, tx.amount, &rcv)) {
            throw std::runtime_error(
                "S-007: TRANSFER credit would overflow recipient "
                "balance (to=" + tx.to + ")");
        }
    } else {
        // A1: amount has left this shard's accounted supply.
        // Fee stays here (accrues to creators below).
        block_outbound += tx.amount;
    }
    total_fees += tx.fee;
    sender.next_nonce++;
    break;
}
```

The sender debit at line 745 (`sender.balance -= cost`) is **unconditional** across both branches — same-shard and cross-shard TRANSFER both debit the sender by `amount + fee`. The fork at line 752 determines whether the destination gets a local credit (same-shard) or whether the value is booked into the per-block outbound accumulator (cross-shard). The fee is gathered into `total_fees` (line 767) regardless of the fork; it stays on the source shard and distributes to `b.creators` at apply-tail (`chain.cpp:1264–1380` subsidy distribution). The nonce increment at line 768 also fires unconditionally.

The asymmetry is deliberate: `amount` leaves the source shard's supply pool (and re-enters the destination shard's via the inbound receipt — T-R1 of FA-Apply-9); `fee` stays on the source shard as compensation for the source committee's work of producing and gossiping the receipt. The split is what makes `accumulated_outbound_` track only `tx.amount`, not `tx.amount + tx.fee` — see T-O4 for the precise A1 contribution.

### 1.3 The `block_outbound` accumulator and per-shard A1

Per `chain.cpp:723 + 765 + 1394`:

```cpp
// chain.cpp:723 — per-block accumulator declaration:
uint64_t block_outbound = 0;   // cross-shard TRANSFER amount that left this shard
// chain.cpp:765 — per-event accumulation (inside the TRANSFER cross-shard arm):
block_outbound += tx.amount;
// chain.cpp:1394 — block-tail fold into the chain-wide accumulator:
accumulated_outbound_ += block_outbound;
```

The per-block `block_outbound` is reset to zero at the start of each apply (line 723), accumulates one `tx.amount` per cross-shard TRANSFER (line 765), and folds into the chain-wide `accumulated_outbound_` at apply-tail (line 1394). The per-block scope is what makes the A9 atomic-apply rollback work: a throw inside the loop reverts `accumulated_outbound_` to its pre-block value because the chain-wide counter is only mutated at the tail, after every per-event accumulation has succeeded.

`accumulated_outbound_` is one of the five A1 counters (`include/determ/chain/chain.hpp:609–611`). The A1 expected-total formula at `chain.hpp:443`:

```cpp
uint64_t expected_total() const {
    return genesis_total_ + accumulated_subsidy_ + accumulated_inbound_
           - accumulated_slashed_ - accumulated_outbound_;
}
```

deducts `accumulated_outbound_` from the supply ceiling. The closure at `chain.cpp:1397–1419` asserts `live_total_supply() == expected_total()` after every apply; a mismatch throws the diagnostic and rolls back the block. Each cross-shard TRANSFER reduces the right-hand side by `tx.amount` (via the `accumulated_outbound_` increment) AND reduces the left-hand side by `tx.amount` (the sender's balance drops by `amount + fee` while a creator's balance rises by the fee, net `−amount`); the two sides decrease in lockstep, so the invariant holds.

### 1.4 The CrossShardReceipt emission (producer-side context)

The apply path does not produce receipts — the producer at `producer.cpp:434–470` builds `block.cross_shard_receipts[]` during block construction, and V12 (`validator.cpp:1081–1110`) enforces 1:1 binding between cross-shard `TRANSFER` entries and receipt entries before the block is admitted to apply. Specifically:

- **Producer** (`producer.cpp:449–465`): for each cross-shard TRANSFER, emit a `CrossShardReceipt` with `src_shard = my_shard_id_`, `dst_shard = shard_id_for_address(tx.to, ...)`, `src_block_index = b.index`, `tx_hash = tx.hash`, plus copies of `from`, `to`, `amount`, `fee`, `nonce`.
- **Validator V12** (`validator.cpp:1095–1108`): iterate the cross-shard tx subset of `b.transactions`, assert `cross.size() == b.cross_shard_receipts.size()` (size match), then field-equality at each index (`tx_hash`, `from`, `to`, `amount`, `fee`, `nonce` all match between tx and receipt; `src_shard == my_shard_id`; `dst_shard == shard_id_for_address(tx.to, ...)`; `src_block_index == b.index`).

The apply path consumes a V12-cleared block; it can therefore assume that for every cross-shard TRANSFER it processes, the matching receipt is present in `b.cross_shard_receipts[]`. The receipt itself is part of the block's signed-digest preimage (the block hash binds the receipt list), so the source-side commitment to the outbound value is K-of-K cryptographically signed by the source committee — which is the L-7.4 ratification that the destination-side admission path verifies.

---

## 2. Theorems

### T-O1 — Cross-shard TRANSFER detection

**Statement.** For every block `B` applied successfully to a Chain `C` and every `tx ∈ B.transactions` with `tx.type == TxType::TRANSFER`, the apply branch executes the cross-shard arm at `chain.cpp:762–766` if and only if `C.is_cross_shard(tx.to) == true`. The detection is deterministic, depends only on `(shard_count_, shard_salt_, my_shard_id_, tx.to)`, and the routing function `crypto::shard_id_for_address` is the shared primitive across producer + validator + apply (no drift possible between layers).

**Proof sketch.** The fork at `chain.cpp:752` (`if (!is_cross_shard(tx.to))`) reads its predicate from the single shared `Chain::is_cross_shard` function defined at lines 198–202. By inspection, the function consults only the four named inputs — no clock, no randomness, no peer state — so for fixed `(shard_count_, shard_salt_, my_shard_id_, tx.to)` it returns a fixed boolean. The producer (`producer.cpp:449`) and validator V12 (`validator.cpp:1086`) call the same function, so the three layers agree on every classification. The apply path's decision to take the cross-shard arm is therefore exactly the producer's decision to emit a receipt AND the validator's decision to require one in `b.cross_shard_receipts[]`. ∎

**Code witness.** `src/chain/chain.cpp:198–202` (the predicate body); `src/chain/chain.cpp:752` (apply-side branch); `src/node/producer.cpp:449` (producer-side branch); `src/node/validator.cpp:1086` (V12 binding).

**Test witness.** `tools/test_cross_shard_outbound_apply.sh` "fixture: found a cross-shard address" assertion (`src/main.cpp:17036`) and the subsequent debit assertions confirm the apply path takes the cross-shard branch. `tools/test_cross_shard_atomicity.sh` exercises the same predicate on both source + destination chains in lock-step. The single-shard negative is covered by T-O7.

### T-O2 — Sender debit

**Statement.** For every block `B` applied successfully and every cross-shard TRANSFER `tx ∈ B.transactions` whose pre-apply `sender.balance ≥ tx.amount + tx.fee`, apply produces:

```
Δaccounts_[tx.from].balance      = −(tx.amount + tx.fee)
Δaccounts_[tx.from].next_nonce   = +1
Δtotal_fees                       = +tx.fee
```

The cost gate at `chain.cpp:744` (`if (sender.balance < cost) continue;`) silently skips the entire TRANSFER on insufficient-balance — no debit, no nonce bump, no fee accumulation, no receipt-side accounting (but V12 has already enforced 1:1 receipt presence, so a skipped tx would leave a corresponding receipt entry with no source-side state change; in practice the validator's V15 nonce + balance pre-checks gate this case before apply runs, so the apply-side cost-gate is a defense-in-depth backstop).

**Proof sketch.** By inspection of `chain.cpp:742–770`. Line 743 computes `cost = tx.amount + tx.fee`. Line 744 short-circuits with `continue` if `sender.balance < cost`, taking us to the next tx without any mutation. Line 745 executes the unconditional debit `sender.balance -= cost`. The if-else at lines 752–766 then dispatches the same-shard credit OR the outbound accumulator — neither of these branches touches `sender.balance` further. Line 767 (`total_fees += tx.fee`) and line 768 (`sender.next_nonce++`) execute unconditionally on the post-debit path. The net per-tx delta to the sender is therefore exactly the stated triple. The fee accumulation into `total_fees` later distributes to `b.creators` via the subsidy branch — see `SubsidyDistribution.md` (FA-Apply-3) T-S1 for the fee-mint mechanics. ∎

**Code witness.** `src/chain/chain.cpp:743–745` (cost gate + debit); `src/chain/chain.cpp:767–768` (fee accumulation + nonce bump); `include/determ/chain/account.hpp` (`AccountState` struct).

**Test witness.** `tools/test_cross_shard_outbound_apply.sh` "outbound TRANSFER: alice debited 100 + 1 fee, fee returns via creator" assertion (`src/main.cpp:17052`) — alice starts at 1000, sends `amount=100, fee=1` cross-shard, then receives `+1` back as creator-fee; final balance is `1000 − 101 + 1 = 900`. The "outbound TRANSFER: alice nonce 0 → 1" assertion at line 17056 exercises the nonce bump.

### T-O3 — NO local credit

**Statement.** For every block `B` applied successfully and every cross-shard TRANSFER `tx ∈ B.transactions`, apply does NOT modify `accounts_[tx.to].balance`. Specifically, `Δaccounts_[tx.to].balance = 0` from the cross-shard TRANSFER apply iteration. If `tx.to` was not previously present in `accounts_`, the cross-shard apply does NOT create the entry — no `accounts_[tx.to]` access occurs on the cross-shard branch.

**Proof sketch.** The cross-shard arm at `chain.cpp:762–766` consists of two statements: a comment and `block_outbound += tx.amount;`. There is no read or write to `accounts_[tx.to]`. The same-shard arm at lines 752–761 contains the credit (`auto& rcv = accounts_[tx.to].balance; ... checked_add_u64(rcv, tx.amount, &rcv)`), but the if-else dispatch is exclusive — the cross-shard branch's else-clause is unreachable from the cross-shard branch. Crucially, the `accounts_[tx.to]` map access on the same-shard branch would create the entry via `std::map::operator[]`'s default-construction behavior, but the cross-shard branch never enters that code; if `tx.to` is a never-before-seen address on this shard, the cross-shard apply leaves `accounts_` without the key.

The design rationale: the destination credit happens on the **destination shard** when a future block bakes the receipt into `b.inbound_receipts[]` and applies the FA-Apply-9 T-R1 credit branch (`chain.cpp:1366–1380`). The source shard never holds the credit obligation; it only books the value as "departed" via `accumulated_outbound_`. From the global supply view (FA7 T-7.1), the value is in the `Pending` ledger between source-finalization and destination-credit; the per-shard A1 invariant on the source side correctly accounts for the departure, and the per-shard A1 invariant on the destination side correctly accounts for the arrival. ∎

**Code witness.** `src/chain/chain.cpp:762–766` (cross-shard arm, no `accounts_[tx.to]` access); compare with `src/chain/chain.cpp:752–761` (same-shard arm, which DOES access `accounts_[tx.to]`).

**Test witness.** `tools/test_cross_shard_outbound_apply.sh` "outbound TRANSFER: dst address NOT credited locally (credit via inbound receipt)" assertion (`src/main.cpp:17054`) — `c.balance(remote) == 0` after the apply, where `remote` was set up to route to a different shard. The complementary destination-side credit is exercised by `tools/test_cross_shard_atomicity.sh` which runs both shards.

### T-O4 — accumulated_outbound update

**Statement.** For every block `B` applied successfully containing `n ≥ 0` cross-shard TRANSFER transactions, the chain-wide `accumulated_outbound_` counter advances by exactly:

```
Δaccumulated_outbound_ = Σ {tx.amount : tx ∈ B.transactions
                            AND tx.type == TRANSFER
                            AND is_cross_shard(tx.to)
                            AND tx passed the cost gate at chain.cpp:744}
```

The sum is over `tx.amount` (not `tx.amount + tx.fee`): the fee stays on the source shard as creator compensation, only the amount leaves the supply pool. Same-shard TRANSFER, REGISTER, STAKE, UNSTAKE, DEREGISTER, DAPP_REGISTER, DAPP_CALL, and PARAM_CHANGE contribute zero to `block_outbound`.

**Proof sketch.** The per-block accumulator `block_outbound` is declared at `chain.cpp:723` and initialized to zero. The only mutation site is `chain.cpp:765` (`block_outbound += tx.amount`), which is inside the TRANSFER case's cross-shard else-arm at lines 762–766. All other tx-type cases (REGISTER, STAKE, etc.) do not touch `block_outbound`. The cost gate at line 744 (`if (sender.balance < cost) continue;`) short-circuits before the cross-shard arm is reached, so a tx with insufficient balance contributes nothing. The block-tail fold at `chain.cpp:1394` (`accumulated_outbound_ += block_outbound`) then advances the chain-wide counter by exactly the per-block sum. The arithmetic is u64 unchecked at the block-tail (block_outbound is bounded by Σ tx.amount which is itself bounded by Σ sender.balance ≤ live_total_supply ≤ u64-max, so overflow at this stage is impossible without first overflowing the supply ceiling — a property the genesis allocation enforces). ∎

**Code witness.** `src/chain/chain.cpp:723` (per-block declaration); `src/chain/chain.cpp:765` (per-event accumulation); `src/chain/chain.cpp:1394` (block-tail fold into chain-wide counter); `include/determ/chain/chain.hpp:441` (`accumulated_outbound()` getter); `include/determ/chain/chain.hpp:609–611` (the five A1 counters comment).

**Test witness.** `tools/test_cross_shard_outbound_apply.sh` "A1: accumulated_outbound = amount (fee stays)" assertion (`src/main.cpp:17083`) — after a TRANSFER with `amount=75, fee=1`, `accumulated_outbound() == 75` (the fee does not contribute to the counter). `tools/test_cross_shard_atomicity.sh` cross-checks the chain-pair conservation `src.accumulated_outbound == dst.accumulated_inbound`. `tools/test_supply_lifecycle.sh` exercises `accumulated_outbound_` across a mixed-tx lifecycle.

### T-O5 — Receipt emission (apply-side post-condition)

**Statement.** For every block `B` applied successfully and every cross-shard TRANSFER `tx ∈ B.transactions` that passed the cost gate, `B.cross_shard_receipts[]` contains exactly one entry `r` with `r.src_shard == my_shard_id_`, `r.dst_shard == shard_id_for_address(tx.to, shard_count_, shard_salt_)`, `r.src_block_index == B.index`, `r.tx_hash == tx.hash`, `r.from == tx.from`, `r.to == tx.to`, `r.amount == tx.amount`, `r.fee == tx.fee`, `r.nonce == tx.nonce`. The receipt's binding to the source-side debit is enforced by V12 before apply runs; the apply path is downstream of the validator and consumes a V12-cleared block.

**Proof sketch.** This theorem is the apply-side consequence of FA7 L-7.1 (V12 binds receipt to source transaction). The apply path does not emit receipts — the producer does, at `producer.cpp:449–465`. The validator's V12 at `validator.cpp:1081–1110` enforces the binding: size-match between cross-shard TRANSFER subset and `b.cross_shard_receipts[]`, plus field-wise equality at each index. A block that fails V12 is rejected before apply (the validator's pipeline orders V12 ahead of `apply_transactions`). Therefore every block reaching apply has `b.cross_shard_receipts.size() == cross_count(b)` and field-matching receipts per cross-shard tx. The apply path's job under this assumption is to make the source-side state consistent with the (now-immutable) receipt list — which is exactly what T-O2 + T-O3 + T-O4 establish.

The receipt itself is part of the block's signed digest preimage (`block.hpp` block-hash computation includes `cross_shard_receipts[]`), so the K-of-K committee signatures on the block constitute a cryptographic commitment to the receipt list. This is the source-side ratification that FA-Apply-9 L-7.4 cites: a destination shard verifying an inbound receipt requires the source block's K signatures, and the receipt's field values are pinned by the source committee's signed digest. ∎

**Code witness.** `src/node/producer.cpp:449–465` (producer-side receipt emission); `src/node/validator.cpp:1081–1110` (V12 receipt binding); `include/determ/chain/block.hpp::CrossShardReceipt` (struct definition); `include/determ/chain/block.hpp` block-hash digest computation (includes `cross_shard_receipts[]`).

**Test witness.** `tools/test_cross_shard_atomicity.sh` exercises the joint surface: the source-side block carries the receipt, the receipt bundle is gossipped, the destination side credits via FA-Apply-9 T-R1. `tools/test_cross_shard_transfer.sh` is the end-to-end 3-node beacon + 2-shard cluster that exercises receipt emission + propagation + delivery. The apply path's reliance on V12 is structural — no separate apply-level assertion exists because V12 is the upstream gate.

### T-O6 — A1 invariance on source shard

**Statement.** For every block `B` applied successfully containing `n ≥ 0` cross-shard TRANSFER transactions with amounts `a_1, ..., a_n` and fees `f_1, ..., f_n` (only the txs that passed the cost gate are counted), the chain's `live_total_supply()` after apply satisfies:

```
live_post = live_pre − Σ a_i
                     + (subsidy mints, if creators non-empty)
```

i.e., the source shard's live supply decreases by exactly Σ a_i from the cross-shard outbound channel (fees do NOT contribute to the decrease — they return to the creators via the subsidy branch). The A1 invariant `live_total_supply() == expected_total()` holds at apply-tail because the same delta is reflected in `accumulated_outbound_` (T-O4): `expected_post − expected_pre = − Σ a_i + (subsidy mints)`, so `live_post − expected_post = live_pre − expected_pre = 0` (assuming the invariant held pre-apply, which is the inductive hypothesis).

**Proof sketch.** Decompose the per-tx contribution to `live_total_supply()`. For a cross-shard TRANSFER `tx_i` with `amount = a_i`, `fee = f_i`, applied to sender with pre-apply balance `b_i`:

- Sender's balance drops by `a_i + f_i` (T-O2): contribution to `live_pre - live_post` is `+a_i + f_i`.
- Destination's balance unchanged (T-O3): contribution is `0`.
- Fee `f_i` is collected into `total_fees` (T-O2), which distributes to `b.creators[]` at the subsidy branch (`chain.cpp:1264–1380`, `SubsidyDistribution.md` FA-Apply-3): contribution to `live_post - live_pre` is `+f_i` (the creator's balance rises by their share of the fees).

Summing across `n` cross-shard TRANSFERs: `Δlive = − Σ (a_i + f_i) + Σ f_i = − Σ a_i`. The expected-total side: `Δexpected = − Δaccumulated_outbound_ = − Σ a_i` (T-O4), plus any subsidy mint contribution that affects both sides equally (the subsidy mint shows up symmetrically in `Δlive = +block_subsidy_minted` AND `Δexpected = +block_subsidy_minted`, so it cancels in the invariant). The two sides decrease in lockstep, and the closure at `chain.cpp:1397–1419` confirms the equality by direct arithmetic.

This is the per-shard A1 invariance specialized to the outbound channel. It composes with FA-Apply-9 T-R5 (destination-side A1 invariance) to give the chain-pair conservation T-7.1 of FA7. ∎

**Code witness.** `src/chain/chain.cpp:545` (sender debit by `amount + fee`); `src/chain/chain.cpp:765` (`block_outbound += tx.amount`, fee not included); `src/chain/chain.cpp:1394` (block-tail fold); `src/chain/chain.cpp:1397–1419` (A1 closure assertion); `include/determ/chain/chain.hpp:443` (`expected_total()` formula including `−accumulated_outbound_` term).

**Test witness.** `tools/test_cross_shard_outbound_apply.sh` "A1: live supply decreases by amount (fee returns via creator)" assertion (`src/main.cpp:17111`) — the live supply drops by exactly `amount`, not `amount + fee`. The follow-up "A1 invariant: expected == live after outbound" assertion at line 17113 closes the invariant. `tools/test_supply_lifecycle.sh` exercises the A1 closure across a mixed-tx lifecycle including cross-shard outbound. `tools/test_cross_shard_atomicity.sh` cross-checks the chain-pair: `src.live - src.live_pre == −amount` AND `dst.live - dst.live_pre == +amount` (T-R5 of FA-Apply-9 covers the destination side).

### T-O7 — Single-shard short-circuit

**Statement.** For every Chain `C` with `shard_count_ <= 1` (SINGLE / BEACON mode), `C.is_cross_shard(to) == false` for every `to`, the cross-shard arm at `chain.cpp:762–766` is never taken, `block_outbound` stays at zero across every apply, and `accumulated_outbound_` is invariant at zero. Every TRANSFER takes the local-credit path at `chain.cpp:752–761`, so `accounts_[tx.to].balance` is credited locally and the SINGLE/BEACON-mode A1 invariant `live_post = live_pre + (subsidy mints) − Σ (slash, if any)` holds without any outbound contribution.

**Proof sketch.** Direct from the line-199 short-circuit in `Chain::is_cross_shard`: when `shard_count_ <= 1` the function returns `false` unconditionally, without even consulting `shard_id_for_address`. The apply-side fork at `chain.cpp:752` therefore always takes the same-shard arm; the cross-shard arm at lines 762–766 is dead code in SINGLE/BEACON mode. `block_outbound` is initialized to zero at line 723 and never incremented; `accumulated_outbound_` is initialized to zero at chain construction (or restored from snapshot) and never advanced. The A1 invariant collapses to the SINGLE-mode form `live = genesis + subsidy + inbound − slashed − outbound` with `outbound = 0` and (for SINGLE chains) `inbound = 0` as well, leaving `live = genesis + subsidy − slashed` — the classic single-shard supply equation.

The short-circuit is the design's defense against accidental cross-shard logic on a single-shard chain: a stray address that would otherwise route to a different shard cannot trigger outbound emission because `shard_count_ <= 1` returns false first. This is what makes `tools/test_cross_shard_outbound_apply.sh`'s "single-shard fallback" assertions provable as a hard invariant rather than a probabilistic check. ∎

**Code witness.** `src/chain/chain.cpp:199` (the `shard_count_ <= 1` short-circuit); `src/chain/chain.cpp:723` (`block_outbound = 0` initialization).

**Test witness.** `tools/test_cross_shard_outbound_apply.sh` "shard_count=1: is_cross_shard always false" assertion (`src/main.cpp:17126`), "single-shard fallback: local credit happens" assertion at line 17139 (`balance(local_recipient) == 30`), and "single-shard fallback: accumulated_outbound unchanged" assertion at line 17141 (`accumulated_outbound() == 0` after a TRANSFER on a `shard_count=1` chain).

### T-O8 — Determinism

**Statement.** For any two Chain instances `C₁` and `C₂` with `C₁ ≡_S C₂` (per FA-Apply-2 §1.2 state-equivalence, including identical `shard_count_`, `shard_salt_`, `my_shard_id_`), and any block `B` containing cross-shard TRANSFER transactions, the apply results satisfy `apply_transactions(C₁, B) ≡_S apply_transactions(C₂, B)`. In particular: identical `block_outbound` accumulation, identical post-apply `accumulated_outbound_`, identical post-apply `accounts_` (no spurious destination credits), and identical `compute_state_root(C₁_post) == compute_state_root(C₂_post)` byte-for-byte.

**Proof sketch.** The cross-shard apply branch is a pure function of (a) the TRANSFER fields (`from`, `to`, `amount`, `fee`, `nonce`), (b) the pre-apply sender balance + nonce, (c) the chain's shard-routing inputs (`shard_count_`, `shard_salt_`, `my_shard_id_`), and (d) the per-block `block_outbound` accumulator (initialized to zero, monotonically increasing through the loop). No I/O, no clock, no randomness, no peer queries. `crypto::shard_id_for_address` is itself a pure SHA-256-based function (deterministic over its inputs).

Under hypothesis `C₁ ≡_S C₂`, conditions (a)–(c) are identical between the two chains: the block `B` is the same on both sides (txs are immutable consensus inputs), the sender balances are equal (state-equivalence includes `accounts_`), and the shard-routing fields are equal (state-equivalence includes the routing tuple per `chain.hpp:393`). The loop body executes the same arithmetic in the same order on both chains, producing the same post-state. The `compute_state_root` byte-equality follows from `build_state_leaves` being a pure function of the maps + scalars (FA-Apply-2 L-S0) and `merkle_root` being deterministic over the sorted leaves.

The `accumulated_outbound_` contribution is captured in the state-root via the `c:` namespace (`chain.cpp:408` — `const_leaf("c:accumulated_outbound", accumulated_outbound_)`), so any non-determinism in the outbound counter would surface as a state_root mismatch on snapshot restore (FA-Apply-2 T-S3 cross-namespace coverage) or on inter-node apply (the S-033 + S-038 validator gate would catch a divergent state_root). The byte-level determinism is therefore enforced at the wire layer, not just at the apply layer. ∎

**Code witness.** `src/chain/chain.cpp:742–770` (deterministic apply branch); `src/chain/chain.cpp:408` (state-root `c:` namespace contribution for `accumulated_outbound_`); `include/determ/crypto/random.cpp::shard_id_for_address` (pure SHA-256 routing); the absence of any clock read, RNG call, or peer query in the TRANSFER branch.

**Test witness.** `tools/test_cross_shard_outbound_apply.sh` "determinism: same outbound TRANSFER → same state_root" assertion (`src/main.cpp:17169`) — two chains with the same genesis + same shard-routing apply the same block, and `c1.compute_state_root() == c2.compute_state_root()`. `tools/test_cross_shard_multi_receipt.sh` "Determinism" assertion across mixed inbound/outbound traffic. `tools/test_chain_save_load.sh` covers snapshot-roundtrip determinism, which includes `accumulated_outbound_` via the `c:` namespace.

---

## 3. Composition with FA-Apply-9

The chain-pair conservation theorem T-7.1 of FA7 reads: at any consistent multi-shard cut, `LiveGlobal + Pending == GenesisGlobal + SubsidyGlobal − SlashedGlobal`, where `Pending = Σ in-flight receipt amounts`. The composition of FA-Apply-13 + FA-Apply-9 is the apply-layer skeleton of this claim:

- **T-O6 (source-side A1 invariance):** for each cross-shard TRANSFER of amount `a` on the source shard, `src.live_post = src.live_pre − a` (the fee returns via the creator and cancels out of the invariant). The source's `accumulated_outbound_` advances by exactly `a`.
- **T-R1 (destination-side first-application credit, FA-Apply-9):** for the corresponding receipt delivered on the destination shard, `dst.accounts_[r.to].balance += r.amount = a`, so `dst.live_post = dst.live_pre + a`. The destination's `accumulated_inbound_` advances by exactly `a`.

Summing across the chain pair:

```
Δ(src.live + dst.live) = − a + a = 0     (the chain pair's joint supply is conserved per receipt)
Δ(src.accumulated_outbound) = + a
Δ(dst.accumulated_inbound)  = + a
```

The cross-shard A1 atomicity is therefore a direct consequence of T-O4 (source-side counter advance) + T-R5 of FA-Apply-9 (destination-side counter advance) at the apply-layer, modulo the in-flight `Pending` window during which the source has emitted but the destination has not yet credited. The `Pending` is the cumulative `accumulated_outbound − accumulated_inbound` across the chain pair at any given moment; it goes to zero in quiescence (T-7' of FA7 under FA4 liveness).

This composition is what makes FA-Apply-13 + FA-Apply-9 the *minimal* apply-side coverage of FA7's atomicity. Neither half is sufficient alone: FA-Apply-13 alone would let the source emit a receipt without any destination-side guarantee that the credit will land; FA-Apply-9 alone would let the destination credit without any source-side guarantee that the value was actually debited. The two halves together close the loop, and FA7's L-7.3 (source-debit-precedes-emission) + L-7.4 (K-of-K source-block ratification) are the cryptographic backstops that make the composition robust against forgery.

A test reviewer can confirm the joint surface via `tools/test_cross_shard_atomicity.sh`, which exercises BOTH chains in lock-step and asserts the conservation explicitly: `src.accumulated_outbound == dst.accumulated_inbound` after the receipt has been delivered, AND each chain's per-shard A1 invariant `expected == live` holds throughout. The 10-assertion regression is the joint witness for FA-Apply-13 T-O6 + FA-Apply-9 T-R5 + FA7 T-7.1.

---

## 4. What this doesn't cover

The theorems above target the source-side apply branch in isolation. They do not extend to:

- **Cross-shard receipt wire format / encoding.** The `CrossShardReceipt` struct's binary layout, V12 (`check_cross_shard_receipts`) source-side field-equality check, and the producer's emission logic are the scope of FA7 + `docs/PROTOCOL.md` §6. The present proof references the receipt fields only insofar as the apply-side debit + accumulator are consistent with the receipt's amount field; the canonical definitions live in `include/determ/chain/block.hpp::CrossShardReceipt`.
- **Destination-side credit (FA-Apply-9).** T-O3 establishes the NEGATIVE property that the source side does not credit `tx.to`. The POSITIVE claim that the destination side eventually credits is FA-Apply-9 T-R1 + T-R4 (across snapshot restore boundaries) + FA7 T-7' (liveness of delivery). The present proof composes with FA-Apply-9 in §3 but does not re-prove it.
- **K-of-K source-block signing.** The K Ed25519 signatures on the source block that ratify the receipt to the destination side are the scope of FA1 (BFT safety) + FA7 L-7.4. The present proof assumes the apply path operates on a finalized block; the cryptographic ratification is upstream.
- **Receipt bundle gossip + destination-side admission.** The path from source-block finalization to destination-side `pending_inbound_receipts_` insertion is `net/gossip.cpp::on_cross_shard_receipt_bundle` + `node.cpp::on_cross_shard_receipt_bundle`. The present proof terminates at the source-side apply; what happens between source finalization and destination block production is FA7's territory.
- **Liveness of delivery.** FA7 T-7' (Receipt completeness — eventual delivery) covers the "every emitted receipt is eventually credited" claim under FA4 liveness on both shards. The present proof's T-O5 covers only the existence of the receipt in the source block; the eventuality claim is FA7's scope. If a destination shard goes permanently silent, the value is stuck in `Pending` indefinitely (FA7 §6.1's "Failure modes" discussion).
- **Refund mechanism for stuck receipts.** Determ has no source-side refund for a receipt whose destination shard never credits. The value remains in `Pending` indefinitely; a future v2+ refund-mechanism gated on observed destination silence is tracked as a design item in `docs/V2-DESIGN.md`. T-O6's source-side A1 invariance does not depend on delivery — the value is correctly accounted as `accumulated_outbound_` regardless.
- **Apply-failure rollback.** The A9 atomic-apply property at `chain.cpp:671–1499` ensures that any throw inside the apply path rolls back `accounts_`, `accumulated_outbound_`, and all other mutated state via `restore_state_snapshot`. The present proof's deltas are stated for **successful applies only**; rollback semantics are inherited from `AccountStateInvariants.md` (FA-Apply) I-1 (atomic apply).
- **Snapshot restore preserves accumulated_outbound.** The `accumulated_outbound_` counter is one of the five A1 scalar counters serialized at `chain.cpp:1618` and restored at `chain.cpp:1735`, plus it contributes to the state-root via the `c:` namespace at `chain.cpp:408`. Restore equivalence (FA-Apply-2 T-S1, T-S2) carries the counter across snapshot boundaries. The present proof's counter delta composes through snapshot restore via T-S2; no re-derivation here.
- **DAPP_CALL cross-shard path.** A `DAPP_CALL` transaction whose `to` routes off-shard is REJECTED at apply time (`chain.cpp:1205–1209`) with the sender's fee charged but no state mutation — v2.19 single-shard-only restriction, Phase 7.6 follow-on adds cross-shard DAPP_CALL via beacon-relay. The present proof's outbound mechanism applies ONLY to TRANSFER, not DAPP_CALL.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V12 (cross-shard receipt binding); A3 (SHA-256 collision resistance) underpins `shard_id_for_address` routing determinism; F-15 (transaction-apply rules). |
| `AccountStateInvariants.md` (FA-Apply) | I-5 debit-channel decomposition (cross-shard TRANSFER source is one of the named debit channels); I-6 A1 closure consuming `accumulated_outbound_`. |
| `CrossShardReceipts.md` (FA7) | Upstream protocol-level atomicity theorems T-7 / T-7' / T-7.1; L-7.1 V12 receipt-tx binding; L-7.3 source-debit-precedes-emission (the present proof formalizes this mechanically); L-7.4 K-of-K source-block ratification. |
| `CrossShardReceiptDedup.md` (FA-Apply-9) | Symmetric destination-side proof. T-R1 (fresh receipt credits), T-R2 (duplicate silent skip), T-R5 (A1 invariance under dedup) — composed with T-O6 for cross-shard A1 atomicity in §3. |
| `AppliedReceiptRestore.md` (FA-Apply-12) | Snapshot-round-trip story for the destination dedup set. The source-side `accumulated_outbound_` has no analogous mechanism — it's a scalar counter, not a dedup set — but is carried via the `c:` state-root namespace per FA-Apply-2 T-S3. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 (serialization-restore identity), T-S3 (cross-namespace coverage including `c:`); the `accumulated_outbound_` scalar round-trips via `chain.cpp:1618` ↔ `chain.cpp:1735`. |
| `SubsidyDistribution.md` (FA-Apply-3) | Fee distribution to creators — the `+tx.fee` contribution to `total_fees` from T-O2 distributes to `b.creators[]` via the subsidy branch, which is why T-O6's live-supply delta is `−amount` (not `−(amount + fee)`). |
| `AbortEventApply.md` (FA-Apply-11) | Structural template — both are apply-side proofs over the same apply-loop scaffold. |
| `EconomicSoundness.md` (FA11) | T-12 A1 unitary-balance closure; the `accumulated_outbound_` channel that T-O4 + T-O6 advance. |
| `docs/PROTOCOL.md` §4.1.1 | State-root `c:` namespace (counter-bearing leaves including `accumulated_outbound_`). |
| `docs/PROTOCOL.md` §6 | Cross-shard receipt wire format + V12 / V13 validator predicates. |
| `docs/SECURITY.md` §S-019 | `shard_salt_` per-chain randomization that hardens the `is_cross_shard` routing function. |
| `docs/SECURITY.md` §S-033 / §S-038 | State-root commitment that binds `accumulated_outbound_` to the block via the `c:` namespace; T-O8 determinism is enforced at the wire layer by these. |
| `tools/test_cross_shard_outbound_apply.sh` | Canonical regression — 11 assertions covering T-O1 / T-O2 / T-O3 / T-O4 / T-O6 / T-O7 / T-O8. |
| `tools/test_cross_shard_atomicity.sh` | Chain-pair model for the §3 composition with FA-Apply-9; 10 assertions including the joint `src.accumulated_outbound == dst.accumulated_inbound` conservation. |
| `tools/test_cross_shard_multi_receipt.sh` | Mixed inbound + outbound in a single block; 19 assertions covering the multi-direction A1 closure. |
| `tools/test_cross_shard_transfer.sh` | End-to-end 3-node beacon + 2-shard cluster (network-level cross-shard transfer). |
| `tools/test_supply_lifecycle.sh` | Composed A1 conservation across the outbound channel + other channels (subsidy, fees, inbound receipts, slashing). |
| `tools/test_state_root_namespaces.sh` | `c:` namespace state-root contribution (cross-checks T-O8 state-root binding). |
| `include/determ/chain/chain.hpp:198–202` | `is_cross_shard` predicate. |
| `include/determ/chain/chain.hpp:441` | `accumulated_outbound()` getter. |
| `include/determ/chain/chain.hpp:443` | `expected_total()` formula including `−accumulated_outbound_`. |
| `include/determ/chain/chain.hpp:609–611` | The five A1 counters comment. |
| `src/chain/chain.cpp:198–202` | `is_cross_shard` definition. |
| `src/chain/chain.cpp:408` | `c:accumulated_outbound` state-root leaf. |
| `src/chain/chain.cpp:723` | Per-block `block_outbound` declaration. |
| `src/chain/chain.cpp:742–770` | TRANSFER apply branch with source/cross-shard fork. |
| `src/chain/chain.cpp:765` | `block_outbound += tx.amount` (the source-side outbound accumulator). |
| `src/chain/chain.cpp:1394` | Block-tail fold `accumulated_outbound_ += block_outbound`. |
| `src/chain/chain.cpp:1397–1419` | A1 closure assertion. |
| `src/chain/chain.cpp:1618` | Snapshot serialize for `accumulated_outbound_`. |
| `src/chain/chain.cpp:1735` | Snapshot restore for `accumulated_outbound_`. |
| `src/node/producer.cpp:449–465` | Producer-side `CrossShardReceipt` emission. |
| `src/node/validator.cpp:1081–1110` | V12 cross-shard receipt binding. |

---

## 6. Status

All eight theorems (T-O1 through T-O8) are closed in the current codebase:

- **T-O1** (cross-shard TRANSFER detection) closed via the `Chain::is_cross_shard` predicate at `chain.cpp:198–202` shared across producer + validator + apply; regression `test_cross_shard_outbound_apply.sh` "fixture: found a cross-shard address" assertion.
- **T-O2** (sender debit by `amount + fee`, nonce bump, fee gathered into `total_fees`) closed via `chain.cpp:743–745 + 767–768`; regression `test_cross_shard_outbound_apply.sh` "outbound TRANSFER: alice debited" + "alice nonce 0 → 1" assertions.
- **T-O3** (NO local credit on cross-shard branch) closed structurally by the absence of any `accounts_[tx.to]` access in the cross-shard arm at `chain.cpp:762–766`; regression `test_cross_shard_outbound_apply.sh` "dst address NOT credited locally" assertion.
- **T-O4** (`accumulated_outbound_` advance by exactly `tx.amount`) closed via the per-event `block_outbound += tx.amount` at `chain.cpp:765` + the block-tail fold at `chain.cpp:1394`; regression `test_cross_shard_outbound_apply.sh` "A1: accumulated_outbound = amount (fee stays)" assertion.
- **T-O5** (receipt emission as apply-side post-condition) closed via the producer-side emission at `producer.cpp:449–465` + V12 binding at `validator.cpp:1081–1110`; regression `test_cross_shard_atomicity.sh` chain-pair surface + `test_cross_shard_transfer.sh` end-to-end.
- **T-O6** (A1 invariance on source shard, live supply decreases by exactly `amount`) closed via the fee-returns-via-creator decomposition + the `expected_total()` formula at `chain.hpp:443` + A1 closure at `chain.cpp:1397–1419`; regression `test_cross_shard_outbound_apply.sh` "A1: live supply decreases by amount" + "expected == live after outbound" assertions.
- **T-O7** (single-shard short-circuit, `shard_count_ <= 1` ⇒ no outbound) closed via the line-199 short-circuit in `is_cross_shard`; regression `test_cross_shard_outbound_apply.sh` "shard_count=1: is_cross_shard always false" + "single-shard fallback: local credit happens" + "single-shard fallback: accumulated_outbound unchanged" assertions.
- **T-O8** (apply-determinism with cross-shard outbound) closed via the pure-function nature of `is_cross_shard` + `shard_id_for_address` (no I/O, no clock, no randomness) + the `c:` namespace state-root binding at `chain.cpp:408` enforcing byte-level equivalence at the wire layer; regression `test_cross_shard_outbound_apply.sh` "determinism: same outbound TRANSFER → same state_root" assertion + `test_cross_shard_multi_receipt.sh` mixed-direction determinism.

No theorem is open or partial. The proof rests on a small set of primitives: the `Chain::is_cross_shard` predicate (the routing decision), the TRANSFER apply branch fork at `chain.cpp:752` (the same-shard vs cross-shard dispatch), the `block_outbound` accumulator (the per-block A1 contribution), the chain-tail `accumulated_outbound_ += block_outbound` fold (the chain-wide A1 contribution), and the `expected_total()` formula's `−accumulated_outbound_` term (the A1 closure). The breadth of consequences — eight theorems, the §3 composition with FA-Apply-9 for cross-shard A1 atomicity, and a regression scenario covering each — is testimony to how few primitives the chain needs to express the source-side outbound mechanism cleanly while keeping the per-shard A1 invariant a hard equality at every apply.

The §3 composition with FA-Apply-9 closes the apply-layer side of FA7's chain-pair conservation theorem T-7.1: T-O6 (source-side `live` decreases by `amount`) + T-R1 (destination-side `live` increases by `amount`) gives the joint supply conservation modulo the in-flight `Pending` term. Combined with FA7's L-7.4 K-of-K source-block ratification, this is the cryptographically-grounded cross-shard atomicity proof at the apply-layer granularity.
