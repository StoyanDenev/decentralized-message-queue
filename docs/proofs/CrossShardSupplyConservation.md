# FA-Apply-17 — Cross-shard aggregate supply conservation (K-shard unitary-supply identity)

This document formalizes the **K-shard aggregate supply-conservation theorem**: across a full cross-shard transfer cycle on a set of `K` shards, the total accounted supply is conserved. Concretely, for any reachable multi-shard state,

```
Σ_shards ( Σ balances + Σ staked + outbound_in_flight )  +  Σ_shards accumulated_slashed
    =  Σ_shards genesis_total
```

i.e. value that has left a source shard but not yet been credited on its destination shard ("in flight") is counted, value burned by forfeiture is counted, and nothing is created or destroyed by the cross-shard machinery. This is the multi-shard composition of the **per-shard A1 unitary-supply invariant** (`AccountStateInvariants.md`, FA-Apply-1) — the property `live_total_supply + accumulated_slashed = expected_total` that the apply path asserts after every block (`chain.cpp:1397–1419`).

**A-number namespace.** This proof concerns the apply-layer **accounting** identity historically labelled "the A1 unitary-supply invariant" in the `FA-Apply-*` series. Per `Preliminaries.md` §2.0, that label is an *accounting* invariant — `live_total_supply + accumulated_slashed = expected_total` — and is **unrelated** to the cryptographic assumption A1 (Ed25519 EUF-CMA). Throughout this document, "A1" written bare means the accounting identity. The cryptographic assumptions used are A2 (SHA-256 collision resistance, `Preliminaries.md` §2.1), which underpins the receipt-key uniqueness this proof relies on for dedup, and — only indirectly via FA7 — the surrounding consensus assumptions. The selective-abort family (FA-track) is unrelated and not cited here; FA3 is *not* a SHA-256 assumption (FA3 = SelectiveAbort).

The strength of this proof is **consolidation**, not novel cryptography. None of the existing per-shard / per-receipt proofs states the conservation law as a single closed identity over the whole `K`-shard set:

- `AccountStateInvariants.md` (FA-Apply-1, I-6) proves the A1 identity *per shard*, for one chain in isolation.
- `CrossShardOutboundApply.md` (FA-Apply-13) proves the *source-side* debit-then-emit mechanics that feed `accumulated_outbound_`.
- `CrossShardReceiptDedup.md` (FA-Apply-9) proves the *destination-side* credit + exactly-once dedup that feed `accumulated_inbound_`.
- `CrossShardReceipts.md` (FA7) proves protocol-level exactly-once delivery (no double-credit) for a receipt pair.
- `AppliedReceiptRestore.md` (FA-Apply-12) + `SnapshotEquivalence.md` (FA-Apply-2) prove that the dedup-set and the supply counters survive snapshot restore.

The present proof **composes** these into the K-shard aggregate conservation theorem (XS-1..XS-5). It is the cross-shard generalization that sibling D1's regression `determ test-cross-shard-supply-invariant` (commit `7ee49da`, wrapper `tools/test_cross_shard_supply_invariant.sh`) pins empirically across a `K = 3` shard set with a non-zero staked term, both mid-cycle (coin in flight) and after the credit lands.

**Companion documents:** `Preliminaries.md` (F0) for notation, §2.0 A-number canonicalization (the A1-accounting / A1-crypto namespace split), §2.1 (A2 SHA-256 collision resistance), and validator predicates V12/V13 (cross-shard receipt binding + dedup); `AccountStateInvariants.md` (FA-Apply-1) for the per-shard A1 identity I-6 that this proof sums over the shard set; `CrossShardOutboundApply.md` (FA-Apply-13) for the source-side debit + `accumulated_outbound_` accounting (T-O2/T-O6); `CrossShardReceiptDedup.md` (FA-Apply-9) for the destination-side credit + exactly-once dedup (T-R1/T-R2/T-R5); `CrossShardReceipts.md` (FA7) for the protocol-level exactly-once delivery atomicity (T-7/T-7.1); `AppliedReceiptRestore.md` (FA-Apply-12) for the dedup-set snapshot restore (T-R4); `SnapshotEquivalence.md` (FA-Apply-2) for serialize↔restore equivalence and the S-033 state_root cross-namespace coverage (T-S1/T-S3); `FeeAccounting.md` (FA-Apply-6) for the fee-is-intra-supply property (T-F6) that this proof's XS-3 relies on; `EconomicSoundness.md` (FA11) for the A1 invariant's economic framing.

---

## 1. Scope

This proof states and proves the **K-shard aggregate supply identity** — that the sum of all accounted value across a set of `K` sibling shards, including value in flight between shards, equals the sum of the shards' genesis baselines, for every reachable multi-shard state.

### 1.1 What this proof adds over the per-shard proofs

The per-shard A1 invariant (FA-Apply-1 I-6, asserted at `chain.cpp:1397–1419`) is a statement about **one** `Chain` object: after every block,

```
live_total_supply()  =  expected_total()
```

where (per `chain.hpp:443–449` and `chain.cpp:548–553`)

```
live_total_supply  =  Σ accounts_[d].balance  +  Σ stakes_[d].locked
expected_total     =  genesis_total
                    +  accumulated_subsidy
                    +  accumulated_inbound
                    -  accumulated_slashed
                    -  accumulated_outbound
```

A cross-shard `TRANSFER` debits the sender on the source shard `S` and emits a receipt; the destination shard `D` credits the recipient when it applies the inbound receipt. On `S`, the per-shard A1 stays balanced because the debit is matched by `accumulated_outbound_ += amount` (the `-accumulated_outbound` term). On `D`, the per-shard A1 stays balanced because the credit is matched by `accumulated_inbound_ += amount` (the `+accumulated_inbound` term). **Each shard's A1 holds in isolation** — but neither shard's invariant, on its own, says anything about whether the value that left `S` is *the same* value that arrived at `D`, nor that the K-shard total is conserved across the whole transfer.

That global statement — "outbound on `S` is exactly matched by inbound on `D`, so the aggregate over all `K` shards equals the genesis baseline regardless of how many transfers have flowed" — is what this proof formalizes as a single closed identity. It is the property D1's test pins and that none of FA-Apply-1/9/13 or FA7 states as one equation over the shard set.

### 1.2 Relationship to FA7

FA7 (`CrossShardReceipts.md`) proves the protocol-level claim that a cross-shard transfer delivers **exactly once** — the source debit and the destination credit are paired, and no receipt is credited twice. FA7's T-7.1 already composes both halves into "no global supply inflation/deflation" *for a single receipt pair*. The present proof generalizes that from one receipt pair to the **whole K-shard set with arbitrarily many receipts in flight**, and pins it to the concrete chain-state accumulators (`accumulated_outbound_`, `accumulated_inbound_`, `accumulated_slashed_`, `genesis_total_`) that the apply path maintains and that D1's test reads via the public accessors. FA7 is the per-receipt atomicity black box; FA-Apply-17 is the K-shard ledger sum that consumes it.

---

## 2. Model

### 2.1 The K-shard set

Let `𝕊 = {C_0, C_1, …, C_{K−1}}` be a set of `K` `Chain` objects, one per shard, all configured with the same chain-wide routing parameters: identical `shard_count_ = K` and identical `shard_salt_`, with distinct `my_shard_id_ ∈ {0, …, K−1}`. (In D1's test these are installed via `set_shard_routing(kShards, salt, ShardId{s})` after each shard's genesis; `chain.cpp:198–202` shows `is_cross_shard` keying off exactly this triple.) Each shard runs the standard apply path `Chain::apply_transactions` (`chain.cpp:633`).

A cross-shard `TRANSFER` is a transaction `tx` on some shard `S` whose recipient `tx.to` routes (via `crypto::shard_id_for_address(tx.to, K, salt)`) to a shard `D ≠ S`. The destination shard `D` later applies a matching `CrossShardReceipt` carrying `(src_shard, tx_hash, to, amount, …)`.

### 2.2 Per-shard supply-bearing fields (exact, from `chain.cpp`)

The complete set of supply-bearing chain-state fields — the fields that contribute to `live_total_supply()` or to `expected_total()` — is, on each shard:

| # | Field | Type | Role | Code anchor |
|---|-------|------|------|-------------|
| 1 | `accounts_[d].balance` | `uint64_t` per account | summed into `live_total_supply` | `chain.cpp:550` |
| 2 | `stakes_[d].locked` | `uint64_t` per stake entry | summed into `live_total_supply` | `chain.cpp:551` |
| 3 | `genesis_total_` | `uint64_t` | baseline (Σ initial balances + Σ initial stakes at block 0) | `chain.cpp:687–711`, `chain.hpp:444` |
| 4 | `accumulated_subsidy_` | `uint64_t` | block-subsidy minted to creators (E1/E3/E4); `+` term | `chain.cpp:1391`, `chain.hpp:445` |
| 5 | `accumulated_inbound_` | `uint64_t` | cross-shard receipt value credited *into* this shard; `+` term | `chain.cpp:1393`, `chain.hpp:446` |
| 6 | `accumulated_slashed_` | `uint64_t` | suspension + equivocation forfeiture; `−` term | `chain.cpp:1395`, `chain.hpp:447` |
| 7 | `accumulated_outbound_` | `uint64_t` | cross-shard `TRANSFER` value that *left* this shard; `−` term | `chain.cpp:1394`, `chain.hpp:448` |

This list is **complete**. The genesis bootstrap (`chain.cpp:711–715`) initializes fields 3–7 (`genesis_total_` from the Σ at lines 687–709; the four accumulators to `0`). The apply tail (`chain.cpp:1391–1395`) is the *only* site that mutates fields 4–7 per block, folding the per-block running counters `block_inbound / block_outbound / block_slashed` (declared `chain.cpp:723–725`) and `subsidy_this_block` into them. `live_total_supply()` (`chain.cpp:548–553`) sums *only* fields 1 and 2 — there is no other balance-bearing container (no pseudo-account pool, no separate fee escrow: fees flow through `accounts_` via the creator-distribution at `chain.cpp:1286–1305`; see XS-3). The post-apply assertion `actual == expected` (`chain.cpp:1397–1399`) ties (1+2) to (3+4+5−6−7) on every block.

There is **no `nef_pool` field on the conservation path in v1.x**: the NEF subsidy stream is a sub-channel of `accumulated_subsidy_` for accounting purposes (FA-Apply-14 NefPoolDrain shows the geometric drain converts pool → registrant balance under the same A1 identity); it does not introduce a supply-bearing field outside the seven above. (`genesis_total()` at `chain.cpp:682–686` explicitly notes that any future pool's initial balance would be added into `genesis_total_` at block 0, leaving the invariant formula unchanged.)

### 2.3 The in-flight quantity

There is **no separate `outbound_receipts_` member** on `Chain`. The block struct carries the emitted receipts in `Block::cross_shard_receipts` (`block.hpp:428`) and `Block::inbound_receipts` (`block.hpp:437`), but the *chain-state* signal that value is in flight from this shard is the monotone counter `accumulated_outbound_`. The only `cross_shard_receipts` reference inside `chain.cpp` is a comment (`chain.cpp:749`); the apply path's source arm does not store a per-receipt queue — it just books `block_outbound += tx.amount` (`chain.cpp:765`), folded into `accumulated_outbound_` at the tail (`chain.cpp:1394`). Accordingly:

```
outbound_in_flight(C_s)  :=  accumulated_outbound_(C_s)  −  ( inbound already applied on the matching destinations )
```

This is an *aggregate* quantity, not a per-shard field: a unit of value is "in flight" once `S` has incremented `accumulated_outbound_` but before `D` has incremented `accumulated_inbound_`. We make this precise in §2.4 by defining the aggregate so that inbound on the destination is netted against outbound on the source.

### 2.4 The aggregate TotalSupply

Define the **K-shard aggregate supply** in two equivalent forms.

**Form A (intuitive, the task framing).** When no subsidy has been minted and inbound is netted against the matching outbound, the live balances already include credited inbound, so the "in-flight" surplus is exactly `Σ accumulated_outbound − Σ accumulated_inbound` (value sent but not yet credited):

```
TotalSupply  =  Σ_s ( Σ balances(C_s) + Σ staked(C_s) )         (live, fields 1+2)
             +  ( Σ_s accumulated_outbound(C_s) − Σ_s accumulated_inbound(C_s) )   (net in-flight)
             +  Σ_s accumulated_slashed(C_s)                     (burned)
             −  Σ_s accumulated_subsidy(C_s)                     (newly minted, already in live)
```

**Form B (the test's accumulator, fully general).** Rearranging Form A and substituting the per-shard A1 identity `live(C_s) = expected_total(C_s)` term by term gives the quantity D1's `aggregate_conserved()` lambda computes (`main.cpp:26933–26943`):

```
aggregate  =  Σ_s [ live_total_supply(C_s)
                  + accumulated_outbound(C_s)
                  + accumulated_slashed(C_s)
                  − accumulated_inbound(C_s)
                  − accumulated_subsidy(C_s) ]
```

**Claim (proved below as XS-5):** `aggregate = Σ_s genesis_total(C_s)` for every reachable multi-shard state.

**Why the two `−` terms.** `accumulated_inbound` and `accumulated_subsidy` are subtracted because their value is *already counted inside `live_total_supply`*: an inbound credit raised an `accounts_[to].balance` on the destination (so it is in fields 1+2), and a subsidy mint raised a creator's `accounts_[creator].balance` (likewise). To compare the live sum against the *genesis* baseline (which predates both), we net them back out. Symmetrically, `accumulated_outbound` is *added* because that value was debited out of live balances on the source but has not yet (or has only partially) re-appeared as inbound elsewhere — it must be re-counted to recover the conserved total. `accumulated_slashed` is added because forfeited value was removed from live `stakes_[d].locked` but is not destroyed from the *conservation* viewpoint — it is sequestered, and re-adding it recovers the genesis baseline.

The task's simplified identity `Σ(balances + staked + outbound_in_flight) + Σ slashed = Σ genesis_total` is exactly **Form A specialized to `Σ accumulated_subsidy = 0` and with `outbound_in_flight = Σ outbound − Σ inbound`** — the regime D1's test runs in (no block subsidy configured; one outbound, one matching inbound). Form B is the general statement that holds even with subsidy minting and partial flows; the rest of this proof proves Form B, from which Form A and the task's simplified identity follow by substitution.

### 2.5 Per-transaction-type A1 closure (why each shard's invariant holds)

XS-1 consumes the per-shard A1 invariant as a hypothesis. That hypothesis is FA-Apply-1 I-6, which establishes that every transaction type and every event type in the apply path adjusts `live_total_supply` and the accumulators *together* so that `live = expected_total` is restored at the apply tail. For completeness, the following table records — for each value-bearing apply branch — the `live` delta, the matching accumulator delta, and the net effect on `expected_total`, so a reviewer can confirm the closure without re-deriving I-6:

| Apply branch | `live` delta | matching accumulator delta | net on `expected − live` | code anchor |
|---|---|---|---|---|
| TRANSFER, same-shard | `0` (sender `−(a+f)`, recipient `+a`, creator `+f`) | none | `0` | `chain.cpp:742–768` |
| TRANSFER, cross-shard (source) | `−a` (sender `−(a+f)`, creator `+f`) | `accumulated_outbound += a` | `0` (`−out` drops by `a`) | `chain.cpp:762–767` |
| Inbound receipt (dest) | `+a` (recipient `+a`) | `accumulated_inbound += a` | `0` (`+in` rises by `a`) | `chain.cpp:1363–1381` |
| STAKE | `0` (balance → locked, both in `live`) | none | `0` | `chain.cpp` STAKE arm |
| UNSTAKE (post-unlock) | `0` (locked → balance, both in `live`) | none | `0` | `chain.cpp` UNSTAKE arm |
| Suspension slash (Phase-1 abort) | `−d` (locked `−d`) | `accumulated_slashed += d` | `0` (`−slashed` rises by `d`) | `chain.cpp:1313–1328` |
| Equivocation slash | `−L` (locked `−L`, full forfeit) | `accumulated_slashed += L` | `0` | `chain.cpp:1344–1356` |
| Subsidy mint | `+s` (creators `+s`) | `accumulated_subsidy += s` | `0` (`+subsidy` rises by `s`) | `chain.cpp:1390–1392` |
| Fee redistribution | `0` (sender `−f` already counted, creator `+f`) | none | `0` | `chain.cpp:1286–1305` |
| REGISTER / DEREGISTER / DAPP_REGISTER / PARAM_CHANGE | `0` (or `−f` fee, redistributed) | none | `0` | `chain.cpp` respective arms |

Every row is net-zero on `expected − live`, which is why the post-apply assertion `actual == expected` (`chain.cpp:1397–1399`) holds. The only two rows that touch the *cross-shard* accumulators are the cross-shard TRANSFER source (`+out`) and the inbound receipt (`+in`) — the two rows XS-1's case analysis exercises. The slash rows feed `accumulated_slashed` (the `Σ slashed` term of the aggregate); the subsidy row feeds `accumulated_subsidy` (the `−subsidy` netting term). This table is the apply-layer foundation on which the K-shard sum of XS-5 rests.

---

## 3. Conservation theorem

We prove conservation as a per-step invariant (XS-1), show it is robust to receipt replay (XS-2), show fees stay intra-shard (XS-3), show it survives snapshot restore (XS-4), and conclude the closed aggregate identity by induction (XS-5).

Throughout, write `G := Σ_s genesis_total(C_s)` for the (fixed) aggregate genesis baseline, and `A(t)` for the value of the `aggregate` quantity of §2.4 Form B at multi-shard time `t`.

### XS-0 — Shard-state disjointness (order independence)

**Statement.** Distinct shards' chain states are disjoint `Chain` objects; one shard's apply step touches no other shard's `accounts_ / stakes_ / accumulated_*` fields. Consequently the multi-shard state is the (independent) product of the per-shard states, and `A` is well-defined and order-independent under any interleaving of per-shard apply steps.

**Proof.** Each `C_s ∈ 𝕊` is a separate `Chain` instance with its own `accounts_`, `stakes_`, and accumulator members (no shared static/global supply state exists in `chain.cpp` — every field read by `live_total_supply` / `expected_total` is a non-static member). A cross-shard `TRANSFER` on `S` mutates only `S`'s members (debit + `block_outbound`); it does **not** reach into the destination shard's `Chain` object — the destination credit happens later, as a *separate* apply step on `D` consuming a `CrossShardReceipt` (the receipt is the only inter-shard channel, and it is data moved by the network/operator, not a direct cross-object mutation). Hence `A = Σ_s contrib(C_s)` is a sum of independent per-object quantities, and applying a block on `C_s` changes only the `s`-th summand. Two apply steps on distinct shards commute (they touch disjoint memory), so any interleaving of the per-shard block sequences yields the same `A`. This is what licenses the single-shard induction in XS-5 to conclude a property of the *multi-shard* state. ∎

### XS-1 — Per-step conservation

**Statement.** Every apply step on any shard `C_s ∈ 𝕊` leaves the aggregate `A` unchanged: if a single block apply on one shard transitions `A` from `A⁻` to `A⁺`, then `A⁺ = A⁻`.

**Proof.** Fix one shard `C_s` and one block `b` it applies. By the per-shard A1 invariant (FA-Apply-1 I-6, enforced at `chain.cpp:1397–1399`), *after* the apply, `live_total_supply(C_s) = expected_total(C_s)`. Substituting `expected_total = genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` (`chain.hpp:443–449`) into shard `C_s`'s contribution to Form B:

```
contrib(C_s) =  live(C_s)
              + accumulated_outbound(C_s)
              + accumulated_slashed(C_s)
              − accumulated_inbound(C_s)
              − accumulated_subsidy(C_s)

            =  [ genesis_total(C_s) + accumulated_subsidy(C_s) + accumulated_inbound(C_s)
                 − accumulated_slashed(C_s) − accumulated_outbound(C_s) ]    (← live = expected_total)
              + accumulated_outbound(C_s) + accumulated_slashed(C_s)
              − accumulated_inbound(C_s) − accumulated_subsidy(C_s)

            =  genesis_total(C_s).
```

Every accumulator term cancels its mirror, leaving `contrib(C_s) = genesis_total(C_s)`, which is **constant across all blocks** (`genesis_total_` is written once at block 0, `chain.cpp:711`, and never mutated again on the apply path; the only other writer is the snapshot back-solve of XS-4, which by construction reproduces the same value). The other `K−1` shards' contributions are untouched by `C_s`'s apply. Hence `A⁺ = Σ_s genesis_total(C_s) = A⁻`. ∎

**Mechanism, case by case.** XS-1 above is the algebraic short proof. For concreteness, here is the case analysis on the actual debit/emit/credit code that *makes* the per-shard A1 hold (these are the FA-Apply-13 and FA-Apply-9 results that XS-1 invokes):

- **Source debit + emit (cross-shard TRANSFER on `S`)** — `chain.cpp:742–769`. The sender is debited `cost = amount + fee` unconditionally (`chain.cpp:743–745`). The fork at `chain.cpp:752` takes the `else` (cross-shard) arm: **no local credit** to `tx.to`; instead `block_outbound += tx.amount` (`chain.cpp:765`). The `fee` is added to `total_fees` (`chain.cpp:767`) and stays on `S` (XS-3). At the tail, `accumulated_outbound_ += block_outbound` (`chain.cpp:1394`). Net effect on `S`'s per-shard A1: `live` drops by `amount` (the `fee` portion returns to `S`'s live supply via creator distribution — XS-3), and `−accumulated_outbound` drops by `amount` too, so `live = expected_total` is preserved. Net effect on the *source contribution* to Form B: `live` `−amount`, `+accumulated_outbound` `+amount` ⇒ source contribution unchanged. The coin is now *in flight*.

- **Destination credit (inbound receipt on `D`)** — `chain.cpp:1363–1381`. For each `r ∈ b.inbound_receipts` whose key `(r.src_shard, r.tx_hash)` is not already in `applied_inbound_receipts_`, the recipient is credited `accounts_[r.to].balance += r.amount` (overflow-checked, `chain.cpp:1367–1372`), the key is inserted into the dedup set (`chain.cpp:1374`), and `block_inbound += r.amount` (`chain.cpp:1377`). At the tail, `accumulated_inbound_ += block_inbound` (`chain.cpp:1393`). Net effect on `D`'s per-shard A1: `live` rises by `amount`, `+accumulated_inbound` rises by `amount`, so `live = expected_total` is preserved. Net effect on the *destination contribution* to Form B: `live` `+amount`, `−accumulated_inbound` `−amount` ⇒ destination contribution unchanged. The coin has *landed*.

The two net-zero deltas compose: the source contribution is invariant under the debit-emit, the destination contribution is invariant under the credit, and every other shard is untouched. So the closed-cycle aggregate delta is `0`. This is precisely what D1 pins as `src.accumulated_outbound() == dst.accumulated_inbound()` at the cycle close (`main.cpp:27034–27036`).

**Worked numerical trace (D1's concrete K=3 instance).** D1's test instantiates `K = 3`, `genesis_total(C_0) = balance(1000) + stake(500) = 1500` on the source shard `S = C_0`, and `genesis_total(C_1) = genesis_total(C_2) = 0` (unfunded peers, each with a registered-but-empty creator). So `G = 1500`. A single cross-shard `TRANSFER` of `amount = 100, fee = 1` flows from `alice` on `C_0` to a recipient routing to some `C_d, d ≠ 0`. The per-shard accumulators evolve as follows (only non-zero shards shown; `bal`/`stk` are the live `balance + locked` sum on that shard):

| Multi-shard time | `C_0` (source) | `C_d` (dest) | Form-B aggregate `A` |
|---|---|---|---|
| genesis | bal+stk=1500, out=0, in=0 | bal+stk=0, out=0, in=0 | 1500 + 0 + 0 − 0 − 0 = **1500** |
| after source debit (`amount+fee` out of alice; `fee` returns to sole-creator alice) | bal+stk = 1500 − 100 = 1400, out=100 | (unchanged) bal+stk=0 | (1400 + 100 − 0 − 0) + (0) = **1500** |
| after dest credit (recipient += 100) | (unchanged) bal+stk=1400, out=100 | bal+stk = 100, in=100 | (1400 + 100) + (100 − 100) = **1500** |
| after duplicate inbound (no-op) | bal+stk=1400, out=100 | bal+stk=100, in=100 | **1500** (unchanged — XS-2) |

The aggregate is `1500 = G` at every step, including the mid-cycle "coin in flight" row where the value has been debited from `C_0` but not yet credited on `C_d`: the `+out=100` term on `C_0` exactly carries the in-flight coin until the `−in` term on `C_d` cancels it. (The `fee = 1` never appears in any accumulator: it cycles from `alice` back to `alice` as the block's sole creator, net zero on `C_0`'s live sum — XS-3.) D1 asserts `aggregate_conserved() == kGenesisAggregate` at each of these rows (`main.cpp:26959`, `26999`, `27038`, `27138`).

### XS-2 — No double-credit ⇒ no inflation

**Statement.** Under receipt replay (gossip duplication, chain reload, or a malicious peer re-broadcasting a receipt), the aggregate `A` is still conserved: a replayed inbound receipt is a no-op and cannot inflate any destination balance, so `accumulated_inbound_` increments at most once per emitted receipt.

**Proof.** The dedup guard at `chain.cpp:1365` is `if (applied_inbound_receipts_.count(key)) continue;` where `key = (r.src_shard, r.tx_hash)`. On the *first* application of a receipt, the key is absent, the credit fires, and the key is inserted (`chain.cpp:1374`). On *every subsequent* application of a receipt with the same key, `count(key) == 1`, the `continue` fires *before* the balance credit and *before* the `block_inbound += r.amount` tick — so neither `accounts_[r.to].balance` nor `accumulated_inbound_` changes. This is FA-Apply-9 T-R2 (duplicate application silently skips).

Key uniqueness rests on A2 (SHA-256 collision resistance, `Preliminaries.md` §2.1): `r.tx_hash` is the SHA-256-derived transaction hash, and the dedup key is the **pair** `(src_shard, tx_hash)`, so even if two distinct source shards emitted receipts whose `tx_hash` collided (negligible under A2), the pair key keeps them distinct (FA-Apply-9 T-R3). Hence each emitted receipt contributes to `accumulated_inbound_` *exactly once*, matching the *exactly-once* outbound increment on the source side (FA-Apply-13: each cross-shard `TRANSFER` increments `block_outbound` exactly once, `chain.cpp:765`, and FA7's exactly-once delivery binds the two).

Therefore the per-step conservation of XS-1 holds even under arbitrary receipt replay: a duplicate inbound is a no-op, so it does not perturb `live`, `accumulated_inbound`, or the destination contribution. `A` is unchanged. D1 pins this directly: after re-applying an identical receipt, `dst.balance(remote)`, `dst.accumulated_inbound()`, and `dst.live_total_supply()` are all unchanged, and `aggregate_conserved()` still equals the genesis baseline (`main.cpp:27115–27139`). ∎

### XS-3 — Fee handling (the fee never escapes the aggregate)

**Statement.** The fee on a cross-shard `TRANSFER` stays on the source shard and never leaves the K-shard accounted supply; it moves from the sender's balance to creator balances (and/or a same-shard distribution), both of which are within `S`'s `live_total_supply`.

**Proof.** On the cross-shard arm (`chain.cpp:762–766`), only `tx.amount` is booked into `block_outbound`; the `fee` is **not**. The fee is added to `total_fees` (`chain.cpp:767`), which is the source shard's per-block fee accumulator. At the apply tail (`chain.cpp:1279–1305`), `total_fees` is folded into `total_distributed = total_fees + subsidy_this_block` (`chain.cpp:1280`) and, if `total_distributed > 0 && !b.creators.empty()`, distributed to the block's creators: each creator's `accounts_[domain].balance += per_creator` (`chain.cpp:1290–1297`), with the division remainder ("dust") credited to `creators[0]` (`chain.cpp:1299–1304`). All recipients are `accounts_` entries **on the source shard `C_s`**, so the fee value moves from `accounts_[sender].balance` to `accounts_[creator].balance` — *within the same `live_total_supply(C_s)`*.

Consequently the fee contributes **zero net change** to `live_total_supply(C_s)`: it is a redistribution among `accounts_` entries, not a debit out of the shard. (This is FA-Apply-6 T-F6: "fees are intra-supply.") Note the fee is *not* part of `accumulated_subsidy_` — that accumulator tracks only the minted `subsidy_this_block`, and only when it was actually paid (`chain.cpp:1390–1392`); the fee portion of `total_distributed` is pre-existing supply being recirculated, so it must not be double-counted as new inflation, and the code correctly excludes it.

Therefore the fee never enters `accumulated_outbound_`, never crosses a shard boundary, and leaves `S`'s contribution to Form B unchanged. D1 pins the edge case where the sole creator *is* the sender: `src.balance("alice") == alice_before − amount − fee + fee` (`main.cpp:26988–26989`) — the fee debited from alice returns to alice as the sole creator, net change `= amount` (the only value that actually left the shard). ∎

### XS-4 — Snapshot-restore invariance

**Statement.** `serialize_state` → `restore_from_snapshot` preserves every supply-bearing field and the dedup set, so `TotalSupply` (and each shard's `expected_total`, `live_total_supply`, and contribution to Form B) is identical post-restore.

**Proof.** `serialize_state` (`chain.cpp:1614–1618`) persists fields 3–7 verbatim:

```
snap["genesis_total"]        = genesis_total_;
snap["accumulated_subsidy"]  = accumulated_subsidy_;
snap["accumulated_slashed"]  = accumulated_slashed_;
snap["accumulated_inbound"]  = accumulated_inbound_;
snap["accumulated_outbound"] = accumulated_outbound_;
```

and the `applied_inbound_receipts` dedup set (`chain.cpp:1586–1592`, each entry serialized as `src_shard` + `tx_hash`), as well as `accounts_` and `stakes_` (fields 1, 2) — which carry the balances and locked stake. `restore_from_snapshot` reads them all back: the four delta counters at `chain.cpp:1732–1735` (subsidy/slashed/inbound/outbound) and `genesis_total_` at `chain.cpp:1867–1868` (with a back-solve fallback — see below); the dedup set at `chain.cpp:1778–1783` (`c.applied_inbound_receipts_.insert({src, txhash})`); and accounts/stakes via the standard state load. This is FA-Apply-2 T-S3 (cross-namespace coverage — fields 1–7 live in the `a:`/`s:`/`c:` namespaces of `compute_state_root`, see `chain.cpp:404–408`) composed with FA-Apply-12 T-R4 (dedup-set restore).

**The back-solve preserves the identity even for legacy snapshots.** If `genesis_total` is absent from the snapshot (legacy form), `restore_from_snapshot` back-solves it (`chain.cpp:1869–1877`):

```
live       = c.live_total_supply();
deltas_pos = c.accumulated_subsidy_ + c.accumulated_inbound_;
deltas_neg = c.accumulated_slashed_ + c.accumulated_outbound_;
c.genesis_total_ = live + deltas_neg − deltas_pos;
```

This is exactly `genesis_total = live − (subsidy + inbound) + (slashed + outbound)`, the rearrangement of the per-shard A1 identity — so the restored chain satisfies `live_total_supply == expected_total` *by construction*, and the restored `genesis_total_` equals the original (because the original also satisfied the same identity). Either way, all seven supply-bearing fields are reproduced, so each shard's contribution to Form B (which equals `genesis_total(C_s)` by XS-1) is identical post-restore, and the aggregate `A` is unchanged.

Moreover, S-033 binds it: the snapshot head's `state_root` covers the `c:` namespace (the five counters, `chain.cpp:404–408`), so a tampered counter would fail the post-restore `compute_state_root()` check (`chain.cpp:1879+`). D1 pins this as the snapshot round-trip: `restored.compute_state_root() == dst.compute_state_root()`, `restored.live_total_supply() == dst.live_total_supply()`, `restored.expected_total() == dst.expected_total()`, and `restored.accumulated_inbound() == dst.accumulated_inbound()` (`main.cpp:27053–27066`), plus a full replay-from-genesis producing byte-identical state_roots on both source and destination (`main.cpp:27068–27109`). ∎

### XS-5 — Aggregate identity (the conservation theorem)

**Statement.** For any reachable multi-shard state `t`, `A(t) = G = Σ_s genesis_total(C_s)`. Equivalently (Form A / task framing, specialized to `Σ accumulated_subsidy = 0`):

```
Σ_s ( Σ balances + Σ staked + outbound_in_flight )  +  Σ_s accumulated_slashed  =  Σ_s genesis_total.
```

**Proof.** By induction over the sequence of apply steps that produced state `t` (each step is one block applied on one shard; the multi-shard state evolves by interleaving these, and the order does not matter because distinct shards' states are disjoint and each step touches one shard).

- **Base case (genesis).** Immediately after every shard has applied its block 0, each shard has `accumulated_subsidy_ = accumulated_inbound_ = accumulated_slashed_ = accumulated_outbound_ = 0` (`chain.cpp:712–715`) and `live_total_supply(C_s) = genesis_total(C_s)` (`chain.cpp:716` comment: "Genesis-time invariant trivially holds (live == genesis_total)"; established because `genesis_total_` is computed as exactly `Σ initial balance + Σ initial stake`, `chain.cpp:687–709`). Hence each contribution to Form B is `genesis_total(C_s) + 0 + 0 − 0 − 0 = genesis_total(C_s)`, and `A(genesis) = Σ_s genesis_total(C_s) = G`. D1 pins this: per-shard `expected_total == live_total_supply` for every shard, and `aggregate_conserved() == aggregate_genesis()` at genesis (`main.cpp:26952–26960`).

- **Inductive step.** Assume `A = G` after some prefix of apply steps. The next step applies one block on one shard `C_s`. By XS-1 (whose hypothesis — the per-shard A1 — holds because the apply path *asserted* it at `chain.cpp:1397–1399` for this very block, throwing otherwise), the step leaves `A` unchanged: `A⁺ = A⁻ = G`. XS-2 guarantees this remains true even if the step re-applies a duplicate receipt (no-op). XS-3 guarantees the fee redistribution inside the step is intra-shard and does not perturb the aggregate. XS-4 guarantees that a snapshot-restore "step" (replacing a shard's chain object with one restored from its serialized state) also leaves `A` unchanged.

By induction, `A(t) = G` for every reachable `t`. The Form A / task-simplified statement follows by substituting `Σ accumulated_subsidy = 0` and `outbound_in_flight := Σ accumulated_outbound − Σ accumulated_inbound` into §2.4's equivalence. ∎

**Corollary (closed cycle ⇒ live sum unchanged).** When every emitted receipt has been credited (no coin in flight: `Σ accumulated_outbound = Σ accumulated_inbound`) and no subsidy was minted and nothing was slashed, Form A collapses to `Σ_s live_total_supply(C_s) = G` — the live balances-plus-stake across the whole set equal the genesis baseline. D1 pins exactly this after the cycle closes: `Σ live_total_supply across shards == kGenesisAggregate` (`main.cpp:27042–27050`).

---

## 4. Relationship to D1's test

D1's regression `determ test-cross-shard-supply-invariant` (handler `src/main.cpp:26838–27144`; wrapper `tools/test_cross_shard_supply_invariant.sh`; 30 PASS assertions) is the empirical pin for this proof. It builds a `K = 3` shard set, funds the source shard's account `alice` with both a balance (`1000`) and a non-zero stake (`500`), routes a `TRANSFER` of `amount = 100, fee = 1` to a recipient that provably routes off the source shard, and checks the aggregate identity at genesis, mid-cycle (coin in flight), and after the credit lands. It uses `accumulated_outbound()` as the source-side in-flight signal — there is no `outbound_receipts_` member (confirmed §2.3); the counter *is* the signal.

The mapping from XS-theorems to test assertions:

| XS theorem | Pinned by (assertion text → `main.cpp` line) |
|---|---|
| **XS-1** (per-step conservation, genesis) | "genesis: per-shard A1 holds (expected == live)" + "genesis: K-shard aggregate conservation == Σ genesis_total" (`26952–26960`) |
| **XS-1** (per-step, source debit) | "src: alice debited amount+fee (fee returns to sole creator)" + "src: remote NOT credited on the source shard" + "src: accumulated_outbound += amount" + "src: per-shard A1 still holds after outbound debit" (`26985–26995`) |
| **XS-1** (in-flight) | "in-flight: aggregate conservation holds (coin debited, not yet credited)" (`26998–26999`) |
| **XS-1** (destination credit) | "dst: remote credited the cross-shard amount" + "dst: accumulated_inbound += amount" + "dst: dedup set marks the applied inbound receipt" + "dst: per-shard A1 still holds after inbound credit" (`27017–27026`) |
| **XS-1** (cycle close) | "cycle: src outbound debit == dst inbound credit" + "cycle: K-shard aggregate supply identity == Σ genesis_total (A1)" + "cycle: Σ live_total_supply across shards unchanged" (`27034–27050`) |
| **XS-2** (no double-credit) | "dedup: duplicate inbound receipt does NOT re-credit remote" + "dedup: duplicate inbound does NOT tick accumulated_inbound" + "dedup: duplicate inbound does NOT inflate live supply" + "dedup: K-shard aggregate supply identity unchanged (no double-credit)" (`27128–27139`) |
| **XS-3** (fee intra-shard) | "src: alice debited amount+fee (fee returns to sole creator)" — the `+ kFee` term in the expected balance (`26988–26989`) directly exercises the source-local fee redistribution |
| **XS-4** (snapshot restore) | "determinism: restored dst state_root is byte-identical" + "... live_total_supply identical" + "... expected_total identical" + "... accumulated_inbound identical" (`27053–27066`); replay-from-genesis byte-identical state_roots (`27097–27108`) |
| **XS-5** (aggregate identity) | the conjunction of the genesis base case (`26959`) and every mid/post-cycle `aggregate_conserved() == kGenesisAggregate` (`26999`, `27038`, `27138`) is the inductive trace of the closed identity |

D1's `aggregate_conserved()` lambda (`main.cpp:26933–26943`) is **Form B of §2.4** verbatim (live + outbound + slashed − inbound − subsidy, summed over shards), and `aggregate_genesis()` (`main.cpp:26944–26948`) is `G`. The proof's XS-5 is the statement `aggregate_conserved() == aggregate_genesis()` for all reachable states; the test pins the specific reachable states traversed by one cross-shard cycle plus a duplicate-receipt block plus a snapshot round-trip.

---

## 5. Limitations / scope

1. **Single deployment, bounded shard set.** The theorem is over the `K`-shard set *within one deployment* sharing one `shard_salt_` and one `shard_count_`. Cross-deployment bridges (value moving between two independent Determ chains) are out of scope — that is the v2.23 bridge work, which would introduce a lock/mint accounting layer not modeled here.

2. **Conditional on honest apply.** Conservation is an **apply-correctness** property: it holds whenever the apply rules execute as written. It does *not* by itself defend against Byzantine *block content* — a malicious producer fabricating a receipt with no matching source debit, or a forged balance. Those are caught by orthogonal mechanisms: the V12/V13 validator predicates (`Preliminaries.md`; cross-shard receipt 1:1 binding + dedup) reject ill-formed receipts before apply; FA1 (Ed25519 EUF-CMA) authenticates transactions; S-033 state_root (`chain.cpp:1421–1446`) makes any apply-state divergence a detectable consensus break. This proof composes *on top of* those: given a V12/V13-cleared, signature-valid, state_root-bound block, the apply step conserves the aggregate.

3. **Receipt delivery is assumed, not proved here.** XS-1's source/destination pairing relies on FA7's exactly-once *delivery* (every outbound receipt is eventually deliverable to its destination, and no spurious receipt is). This proof treats FA7 as a black box; it proves that *given* exactly-once delivery, the aggregate is conserved, and that even *duplicate* delivery (XS-2) cannot break it. Liveness of delivery (that the in-flight coin *eventually* lands) is a separate property (`CrossShardReceipts.md` / `S016InboundReceiptTimeOrdered.md`); conservation holds whether or not the coin has landed (it is counted as in-flight until it does).

4. **`u64` arithmetic / overflow.** All supply fields are `uint64_t`. The apply path guards every credit with `checked_add_u64` (S-007; e.g. `chain.cpp:1368`, `chain.cpp:757`) and the per-block sums likewise (`chain.cpp:1377`, `chain.cpp:1280`), throwing rather than wrapping. A thrown overflow rolls the block back (A9 atomic apply), so the conserved state is never corrupted by wraparound. D1's magnitudes are tiny; the test uses a signed `int64_t` accumulator for the aggregate (portable, no `__int128`) since intermediate per-shard terms can net negative (a shard that has received more than it sent) while the total stays non-negative and equal to `G`.

5. **Subsidy/slashing are conserved, not absent.** The theorem holds *with* subsidy minting and slashing active (Form B carries both terms). D1's test runs with `subsidy = 0` and no slashing to isolate the cross-shard flow, so it pins Form A; FA-Apply-7 (subsidy) and FA-Apply-10/11 (slashing) pin the per-shard A1 invariance of those channels, which XS-1 consumes to extend the conservation theorem to the general case.

6. **R4 under-quorum merge does not move supply.** The R4 `MERGE_EVENT` apply branch (`chain.cpp:929–945`) mutates only `merge_state_` — a `shard_id → refugee_region` metadata map in the `m:` namespace (`chain.cpp:242`, `349–358`) — and consumes fee + nonce. It does **not** transfer `accounts_` or `stakes_` between shards: a merge changes *which committee produces blocks* for an under-quorum region, not *where value is held*. Accordingly `merge_state_` is not a supply-bearing field (it is absent from §2.2's list of seven), and MERGE_BEGIN/MERGE_END leave every shard's `live_total_supply` and accumulators untouched — the per-shard A1 row for MERGE is the "fee redistributed, otherwise net-zero" case of §2.5. The conservation identity is therefore invariant across merge events; FA9 (`UnderQuorumMerge.md`) covers the consensus-safety side, and this proof's XS-5 holds verbatim across BEGIN/END because those steps fall under the §2.5 net-zero rows.

---

## 6. Cross-references

| Surface | Location | Relevance |
|---|---|---|
| Per-shard A1 assertion | `src/chain/chain.cpp:1397–1419` | the `actual == expected` post-apply check that XS-1 consumes |
| `live_total_supply()` | `src/chain/chain.cpp:548–553` | fields 1+2 (balances + locked stake) |
| `expected_total()` | `include/determ/chain/chain.hpp:443–449` | the `genesis + subsidy + inbound − slashed − outbound` formula |
| Genesis bootstrap | `src/chain/chain.cpp:680–717` | `genesis_total_` Σ + zeroing the four accumulators (XS-5 base case) |
| Cross-shard TRANSFER (source) | `src/chain/chain.cpp:742–769` | debit + `block_outbound += amount`; fee stays local (XS-1, XS-3) |
| Inbound receipt apply (destination) | `src/chain/chain.cpp:1363–1381` | dedup guard + credit + `block_inbound += amount` (XS-1, XS-2) |
| Accumulator fold (apply tail) | `src/chain/chain.cpp:1391–1395` | the only per-block mutation of fields 4–7 |
| Fee → creator distribution | `src/chain/chain.cpp:1279–1305` | fee is intra-shard recirculation (XS-3) |
| `is_cross_shard` | `src/chain/chain.cpp:198–202` | the routing predicate that defines a cross-shard transfer |
| `serialize_state` (counters) | `src/chain/chain.cpp:1614–1618` | persist fields 3–7 (XS-4) |
| `serialize_state` (dedup set) | `src/chain/chain.cpp:1586–1592` | persist `applied_inbound_receipts_` (XS-4) |
| `restore_from_snapshot` (counters + back-solve) | `src/chain/chain.cpp:1732–1735`, `1867–1877` | reload fields 4–7; back-solve `genesis_total` for legacy (XS-4) |
| `restore_from_snapshot` (dedup set) | `src/chain/chain.cpp:1778–1783` | reload `applied_inbound_receipts_` (XS-4) |
| `c:` namespace in state_root | `src/chain/chain.cpp:404–408` | S-033 binds the five counters (XS-4 tamper-detection) |
| R4 MERGE_EVENT apply | `src/chain/chain.cpp:929–945`, `m:` namespace `:242`/`:349–358` | metadata-only; does not move supply (§5 limitation 6) |
| `Block::cross_shard_receipts` / `inbound_receipts` | `include/determ/chain/block.hpp:428`, `:437` | source-emitted vs destination-applied receipt lists (§2.3) |
| **FA7** | `docs/proofs/CrossShardReceipts.md` | exactly-once delivery / no double-credit (XS-1 source/dest pairing) |
| **FA-Apply-1** | `docs/proofs/AccountStateInvariants.md` | per-shard A1 invariant I-6 (the single-shard form this proof sums) |
| **FA-Apply-9** | `docs/proofs/CrossShardReceiptDedup.md` | destination-side credit + dedup T-R1/T-R2/T-R3/T-R5 (XS-2) |
| **FA-Apply-13** | `docs/proofs/CrossShardOutboundApply.md` | source-side debit + `accumulated_outbound_` T-O2/T-O6 (XS-1) |
| **FA-Apply-2** | `docs/proofs/SnapshotEquivalence.md` | serialize↔restore equivalence T-S1/T-S3 (XS-4) |
| **FA-Apply-12** | `docs/proofs/AppliedReceiptRestore.md` | dedup-set snapshot restore T-R4 (XS-4) |
| **FA-Apply-6** | `docs/proofs/FeeAccounting.md` | fee-is-intra-supply T-F6 (XS-3) |
| **FA11** | `docs/proofs/EconomicSoundness.md` | A1 unitary-supply economic framing |
| TLA+ companions | `docs/proofs/tla/CrossShardReceiptDedup.tla`, `CrossShardOutboundApply.tla`, `CrossShardReceiptRoundtrip.tla` | machine-checkable models of the source/destination/round-trip mechanics XS-1/XS-2/XS-4 compose |
| **D1 test** | `determ test-cross-shard-supply-invariant` → `src/main.cpp:26838–27144` | 30-assertion empirical pin (§4 mapping) |
| **D1 wrapper** | `tools/test_cross_shard_supply_invariant.sh` | run-from-root harness; FAST `run_all.sh` integration |
| Operator audit | `tools/operator_receipt_audit.sh` | operator-facing cross-shard receipt-flow audit (complementary tooling) |

---

## 7. Status

**Test shipped** — `determ test-cross-shard-supply-invariant` (D1, commit `7ee49da`), 30 PASS assertions, integrated into the FAST `tools/run_all.sh` suite. **Proof complete** (XS-1..XS-5). The §2.2 supply-component list (7 fields: `accounts_[d].balance`, `stakes_[d].locked`, `genesis_total_`, `accumulated_subsidy_`, `accumulated_inbound_`, `accumulated_slashed_`, `accumulated_outbound_`) matches `src/chain/chain.cpp` exactly; there is no separate `outbound_receipts_` member — the source-side in-flight signal is the `accumulated_outbound_` counter, consistent with D1's test.
