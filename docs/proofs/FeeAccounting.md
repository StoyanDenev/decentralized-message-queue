# FA-Apply — Fee accounting (per-tx debit + creator distribution)

This document formalizes the apply-layer flow of transaction fees: how `tx.fee` is debited from each sender, accumulated into a per-block `total_fees` counter, and distributed at block-tail across `b.creators[]` together with the per-block subsidy. The flow is the load-bearing intra-supply transfer channel that converts user-paid fees into validator income while keeping the A1 unitary-supply invariant intact. Three structural properties matter: (1) the debit is per-tx and gated on success — silently-skipped txs charge no fee, (2) accumulation is monotone within the block apply (modulo the explicit UNSTAKE refund subtraction, which cancels the immediately-prior charge), and (3) distribution to creators is deterministic, with an explicit empty-creators gate that protects the A1 closure on genesis and on degenerate non-producer blocks.

The proof is mechanical: each theorem is established by inspection of a single per-tx branch in `Chain::apply_transactions` (`src/chain/chain.cpp:633`) plus the block-tail distribution block (`chain.cpp:1279–1305`). The branches use the same `charge_fee` lambda (`chain.cpp:727–732`) covered structurally by `AccountStateInvariants.md` (FA-Apply) I-1 and I-5; the present proof's contribution is to enumerate the seven theorems that pin fee semantics end-to-end so a reviewer can audit "where does fee value go?" from a single document instead of reconstructing it across the TRANSFER / STAKE / UNSTAKE / REGISTER / DEREGISTER / PARAM_CHANGE / DAPP_REGISTER / DAPP_CALL branches and the per-creator distribution loop.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and the apply-time guarantees; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 (no underflow), I-2 (nonce monotonicity), I-5 (the I-5 fee-only-debit channel + the per-creator credit channel + the UNSTAKE fee-refund credit), and I-6 (A1 closure); `StakeLifecycle.md` (FA-Apply-4) for T-K4 (UNSTAKE pre-unlock fee refund — the asymmetric case that this proof's T-F2 documents); `DAppRegistryLifecycle.md` (FA-Apply-5) for T-D3 (DAPP_REGISTER non-owner update is unreachable by construction — the silent skip after charge_fee that this proof's T-F2 enumerates); `NonceMonotonicity.md` (FA-Apply-3) for the strict-equality nonce gate that precedes every fee debit (a stale-nonce tx never reaches the fee-charge primitive); `EconomicSoundness.md` (FA11) for the A1 closed-form invariant + E3/E4 subsidy distribution that share the per-creator credit channel — T-F4 below covers the fee-distribution component, FA11 T-12 + T-14 cover the subsidy + lottery + finite-pool components.

---

## 1. Setup

### 1.1 The `charge_fee` primitive

The shared apply-layer fee-debit helper is the `charge_fee` lambda local to `apply_transactions` (`src/chain/chain.cpp:727–732`):

```cpp
auto charge_fee = [&](AccountState& acct, uint64_t fee) {
    if (acct.balance < fee) return false;
    acct.balance -= fee;
    total_fees   += fee;
    return true;
};
```

Two effects, both atomic in the caller-visible state: (1) the sender's balance is decremented by exactly `fee`; (2) the per-block `total_fees` accumulator is incremented by exactly `fee`. The return value signals success; callers that observe `false` short-circuit the rest of the per-tx branch via `continue` (silent skip with no nonce bump). The lambda is called explicitly by REGISTER, DEREGISTER, UNSTAKE, PARAM_CHANGE, MERGE_EVENT, DAPP_REGISTER, and DAPP_CALL (where applicable); TRANSFER, STAKE, and the COMPOSABLE_BATCH outer fold an equivalent `total_fees += tx.fee` directly after their bundle-cost debit (lines 767, 868) because their cost calculation includes the stake / transfer amount alongside the fee in a single subtraction.

`total_fees` is a per-apply `uint64_t` local declared at `chain.cpp:720`, initialized to `0`, and consumed at the block-tail distribution block. It does not persist into the chain's instance state; the block's economic value is reified into `accounts_[creator].balance` writes before the apply returns.

### 1.2 The per-block distribution block

After every tx in `b.transactions` has been processed, the apply function computes the per-block subsidy (`chain.cpp:1247–1272` — covered by FA11 T-14) and combines it with `total_fees` into a single `total_distributed` (`chain.cpp:1279–1285`):

```cpp
uint64_t total_distributed = 0;
if (!checked_add_u64(total_fees, subsidy_this_block, &total_distributed)) {
    throw std::runtime_error("S-007: total_distributed (fees + subsidy) overflowed u64 ...");
}
```

The S-007 overflow check defends against an adversarial genesis with a pathological `block_subsidy_` that, combined with fees from an extreme block, would wrap u64. The throw catches this case and rolls back via the outer try/catch (FA-Apply §1.2).

The distribution itself (`chain.cpp:1286–1305`) is gated on two conditions — `total_distributed > 0` AND `!b.creators.empty()` — and runs:

```cpp
if (total_distributed > 0 && !b.creators.empty()) {
    size_t   m           = b.creators.size();
    uint64_t per_creator = total_distributed / m;
    uint64_t remainder   = total_distributed % m;
    for (auto& domain : b.creators) {
        auto& bal = accounts_[domain].balance;
        checked_add_u64(bal, per_creator, &bal);   // throws on overflow
    }
    auto& bal0 = accounts_[b.creators[0]].balance;
    checked_add_u64(bal0, remainder, &bal0);       // throws on overflow
}
```

The arithmetic is integer division with separate dust placement: each creator receives `total_distributed / |creators|`, and the modulo remainder is added to `creators[0]`'s balance as an explicit second write. The two-pass structure (per-creator loop, then dust write) is structural — it ensures dust placement is deterministic regardless of iteration order over `b.creators[]`.

### 1.3 The empty-creators gate

The `!b.creators.empty()` half of the distribution gate is the load-bearing A1-safety mechanism for blocks with no consensus committee. The only blocks that legitimately have empty `creators[]` are genesis (b.index == 0), which short-circuits to the genesis branch at `chain.cpp:681` before reaching the distribution block, and degenerate test fixtures that exercise the empty-block apply behavior (see `tools/test_empty_block_apply.sh`). A regular (non-genesis) block produced by consensus always has K creators per the K-of-K committee.

If the gate were removed and a block with empty `creators[]` reached the distribution block with non-zero `total_distributed`, division by zero would happen at `per_creator = total_distributed / m` (the `m == 0` case). The current gate makes this structurally unreachable. The companion gate at `chain.cpp:1390` (`if (total_distributed > 0 && !b.creators.empty()) accumulated_subsidy_ += subsidy_this_block;`) ensures that A1's accounting matches the distribution — both the credit and the counter accumulation are gated identically. Without the matched gate, A1 would track a subsidy that was never paid out, producing a perpetual `live_total_supply < expected_total` drift.

---

## 2. Theorems

### T-F1 — Per-tx fee debit

**Statement.** For every successfully-applied transaction `tx ∈ B.transactions` (where "successfully applied" means: passed the nonce gate at `chain.cpp:739`, AND passed the per-type spend-attempt gate, AND completed the per-type body without `continue` or the UNSTAKE refund branch), the sender's balance decreases by exactly the per-type cost:

- **TRANSFER** (same-shard or cross-shard, `chain.cpp:742–770`): `Δaccounts_[tx.from].balance = −(tx.amount + tx.fee)`.
- **STAKE** (`chain.cpp:858–871`): `Δaccounts_[tx.from].balance = −(amount + tx.fee)`.
- **DAPP_CALL** (`chain.cpp:1212–1222`, success branch): `Δaccounts_[tx.from].balance = −(tx.amount + tx.fee)`.
- **REGISTER / DEREGISTER / UNSTAKE (post-unlock success) / PARAM_CHANGE / MERGE_EVENT / DAPP_REGISTER / COMPOSABLE_BATCH outer**: `Δaccounts_[tx.from].balance = −tx.fee` (no amount field on these tx types; the fee is the only debit channel).

For every silently-skipped transaction (nonce mismatch at line 739, insufficient balance at line 744 / 864 / 1213, malformed payload at any per-type validity check, or `charge_fee` returning false for fee-only tx types), `Δaccounts_[tx.from].balance = 0` — no fee is charged and the nonce does NOT bump.

*Proof sketch.* By inspection of each per-type branch. The strict-nonce gate at `chain.cpp:739` filters out `(from, nonce) != (sender.next_nonce)` cases before any state mutation. For TRANSFER / STAKE / DAPP_CALL, the balance check at line 744 / 864 / 1213 fires before the `sender.balance -= cost` debit at line 745 / 865 / 1214; a failing check takes the `continue` branch without writing. For the fee-only tx types, `charge_fee` (line 727–732) returns `false` on insufficient balance, and the per-type branch uses the `if (!charge_fee(...)) continue;` idiom at lines 788 / 840 / 878 / 901 / etc. — the `continue` skips both the fee debit and the nonce bump. Therefore every fee debit is bracketed: either the fee is charged AND the nonce bumps AND the per-type body runs (success path), or none of those three happens (skip path). ∎

**Code witness.** `src/chain/chain.cpp:727–732` (`charge_fee` lambda); per-type branches as cited above; `src/chain/chain.cpp:739` (the nonce gate that precedes every branch).

**Test witness.** `tools/test_chain_apply_block.sh` (`determ test-chain-apply-block`) — 22 assertions across eight blocks, including TRANSFER apply (5 assertions: balance debits + credits + nonce bump + bad-nonce silent-skip + insufficient-balance silent-skip), STAKE apply (2), REGISTER apply (5). `tools/test_tx_edge_cases.sh` exercises the skip-vs-success boundary at `balance == cost` (succeeds) vs `balance == cost - 1` (skipped, no nonce bump, no fee charge).

### T-F2 — Failed-tx fee refund vs charge contract

**Statement.** Each tx type's failure-mode handling regarding fees is one of three patterns. The pattern is per-tx-type and uniform within the type:

| Tx type | Failure mode | Fee charged? | Nonce bumped? | Notes |
|---|---|---|---|---|
| TRANSFER | insufficient balance (`sender.balance < amount + fee`) | NO | NO | silent skip via `continue` at `chain.cpp:744`, no state write |
| STAKE | insufficient balance (`sender.balance < amount + fee`) | NO | NO | silent skip via `continue` at `chain.cpp:864`, no state write |
| STAKE | malformed payload (`tx.payload.size() != 8`) | NO | NO | silent skip via `continue` at `chain.cpp:859`, before any cost calc |
| UNSTAKE | pre-unlock (`b.index < stakes_[d].unlock_height`) | charged then REFUNDED | YES | `charge_fee` succeeds, then refund branch at `chain.cpp:884–886` reverses the debit AND `total_fees -= fee` cancels the accumulator entry; the nonce bumps (T-K4 of `StakeLifecycle.md`) |
| UNSTAKE | insufficient locked stake (`stakes_[d].locked < amount`) | charged then REFUNDED | YES | same refund branch (covers conditions (a) entry-missing, (b) insufficient-locked, (c) too-early) |
| UNSTAKE | insufficient balance for fee | NO | NO | `charge_fee` returns false at `chain.cpp:878`, silent skip |
| REGISTER | malformed payload (`tx.payload.size() < 32`) | NO | NO | silent skip before `charge_fee` runs (line 779) |
| REGISTER | insufficient balance for fee | NO | NO | `charge_fee` returns false at line 788, silent skip |
| REGISTER | duplicate domain | charged, nonce bumped | YES | The branch does not reject repeat REGISTER explicitly; the registry-write at line 805 simply overwrites the prior entry. NEF is gated on `first_time_register` (line 795) so re-registration does not redrain the pool. |
| DEREGISTER | not in registry | charged, nonce bumped | YES | The branch at `chain.cpp:840–842` charges the fee, looks up the registrant, finds nothing, bumps the nonce, breaks. Defensive: the validator should have rejected, but the apply-side defense charges the fee anyway (no refund — the operator paid for the validator's inclusion review). |
| DEREGISTER | insufficient balance for fee | NO | NO | `charge_fee` returns false at line 840, silent skip |
| PARAM_CHANGE | malformed payload | charged, nonce bumped | YES | `charge_fee` at line 901 succeeds; subsequent shape checks (lines 907–924) skip the staging mutation but the nonce still bumps in the per-branch tail (line 926). Defensive: same rationale as DEREGISTER (apply pays for the validator's verification effort). |
| DAPP_REGISTER | insufficient balance for fee | NO | NO | silent skip via `if (!charge_fee) continue;` at line 1050 |
| DAPP_REGISTER | non-owner update (signed by `d' ≠ d`) | charged, nonce bumped, NO REGISTRY MUTATION on `d` | YES | T-D3 of `DAppRegistryLifecycle.md` — the apply branch writes to `dapp_registry_[tx.from] == d'`, never reaching `d`'s slot. The fee is charged from `d'` (the attempted attacker), not from the owner. |
| DAPP_REGISTER | unknown op / malformed payload (post-charge_fee) | charged, nonce bumped | YES | Same defensive pattern: `chain.cpp:1046–1048` comment documents this — the apply path bumps the nonce + breaks even on malformed payloads to keep replay deterministic. |
| DAPP_CALL | insufficient balance for fee | NO | NO | silent skip |
| DAPP_CALL | inactive DApp (`dapp.inactive_from <= height`) | charged, nonce bumped, NO CREDIT TO DAPP | YES | `chain.cpp:1142–1146` — gate fires, fee consumed, nonce bumps, no `dapp_registry_[tx.to]` owner credit |

The asymmetry has two cases — silent-skip (no fee) and silent-reject-with-fee (fee consumed) — plus the unique UNSTAKE refund case. See §3 below for the rationale.

*Proof sketch.* By exhaustive case analysis across the per-type branches. The two helpers (`charge_fee` and the `if (sender.balance < cost) continue;` idiom) cover the silent-skip branches uniformly. The UNSTAKE refund branch is unique to that tx type and explicitly reverses both the balance debit AND the `total_fees` accumulator entry — a critical detail because without the `total_fees -= fee` line, the refund would silently leak the fee into the per-creator distribution at block-tail (effectively double-spending it). The defensive-charge pattern (REGISTER duplicate, DEREGISTER missing-registrant, PARAM_CHANGE malformed-payload, DAPP_REGISTER malformed-payload) is consistent: when the validator's upstream check is the primary defense and the apply-time check is a secondary safety net, the apply path consumes the fee because the validator's inclusion review already happened. ∎

**Code witness.** Per-type branches as cited in the table above; `src/chain/chain.cpp:884–886` (the UNSTAKE refund — the load-bearing line `total_fees -= tx.fee` that prevents a double-spend of the refunded fee); `src/node/validator.cpp` (the upstream validator gates that catch most of these cases before the apply path runs).

**Test witness.** `tools/test_unstake_deregister_apply.sh` (`determ test-unstake-deregister-apply`) covers the UNSTAKE refund path including the `total_fees` cancellation (the test inspects balance + total_fees after each scenario). `tools/test_tx_edge_cases.sh` covers the TRANSFER / STAKE silent-skip-no-fee paths. `tools/test_dapp_state_transition.sh` covers the DAPP_REGISTER non-owner-cannot-mutate path (T-D3 in `DAppRegistryLifecycle.md`). `tools/test_chain_apply_block.sh` covers the bad-nonce silent-skip-no-fee path.

### T-F3 — Block-level fee accumulation

**Statement.** Within a single block apply, the per-block `total_fees` counter (`chain.cpp:720`) accumulates the fees of exactly those transactions that reached a `total_fees += fee` (or `charge_fee` success) path, minus those UNSTAKE failures that reached the refund branch (`chain.cpp:885: total_fees -= tx.fee`). Equivalently:

```
total_fees_after_block_apply = Σ_{tx ∈ B.transactions, tx applied successfully}    tx.fee
                              + Σ_{tx ∈ B.transactions, tx is defensive-charge}   tx.fee
                              − Σ_{tx ∈ B.transactions, tx is UNSTAKE refund}     0
                              (the UNSTAKE refund cancels its own +fee then −fee, net 0)
```

No fees from silently-skipped txs (no-charge skip path of T-F2) are accumulated, since those txs never reach a `total_fees += fee` write. The per-block `total_fees` is a stack local that does not persist into chain instance state; it is consumed at the block-tail distribution.

*Proof sketch.* By inspection of every `total_fees` write in `apply_transactions`. The accumulator is incremented in seven places: the TRANSFER tail at line 767, the STAKE tail at line 868, the `charge_fee` lambda body at line 730 (fires from REGISTER / DEREGISTER / UNSTAKE / PARAM_CHANGE / MERGE_EVENT / DAPP_REGISTER / DAPP_CALL when their respective branches reach the lambda call), and the COMPOSABLE_BATCH outer-fee path. It is decremented in exactly one place: the UNSTAKE refund branch at line 885. Every silent-skip path (`continue` after balance check) bypasses both the increment and the decrement, so `total_fees` is byte-identical to the alternative chain where the skipped txs were never included. The defensive-charge pattern (REGISTER duplicate, etc.) does reach `charge_fee` and therefore does contribute to `total_fees`, consistent with the T-F2 documentation. ∎

**Code witness.** All `total_fees` writes in `src/chain/chain.cpp` — line 720 (declaration), line 730 (charge_fee body), line 767 (TRANSFER), line 868 (STAKE), line 885 (UNSTAKE refund), the COMPOSABLE_BATCH outer at line 956-style; final use at line 1280 (`checked_add_u64(total_fees, subsidy_this_block, &total_distributed)`).

**Test witness.** `tools/test_fee_distribution_edge.sh` (`determ test-fee-distribution-edge`) — 12 assertions covering large fee + subsidy combine, zero-fee tx with non-zero subsidy (subsidy still mints), exact-divide subsidy (no dust), and A1 invariant across all distribution scenarios. The test's "large fee + subsidy combine" scenario specifically pins T-F3's accumulation contract — `total_fees` correctly sums the per-tx fees and is consumed exactly once at block-tail.

### T-F4 — Distribution to creators (deterministic flat split + dust to creators[0])

**Statement.** For every successfully-applied block `B` at height `b.index ≥ 1` with `B.creators.size() == m ≥ 1` and `total_distributed := total_fees + subsidy_this_block > 0`, the per-creator credit deltas are:

```
For each i ∈ [0, m):
    Δaccounts_[B.creators[i]].balance += total_distributed / m

Additionally for creators[0]:
    Δaccounts_[B.creators[0]].balance += total_distributed mod m   (dust)
```

equivalently, creators[0] receives `(total_distributed / m) + (total_distributed mod m) = ⌈total_distributed / m⌉` if there is dust, and `total_distributed / m` exactly otherwise. The other `m - 1` creators each receive `total_distributed / m` (integer division). The sum across all credits is exactly `total_distributed`, with no residue.

*Proof sketch.* By inspection of `chain.cpp:1286–1304`. The branch is gated by `if (total_distributed > 0 && !b.creators.empty())` — under the hypothesis both conditions hold. Line 1287 computes `m = b.creators.size()`, line 1288 computes `per_creator = total_distributed / m` (integer division), line 1289 computes `remainder = total_distributed % m`. The loop at lines 1290–1297 credits each creator with `per_creator` via `checked_add_u64`; the S-007 overflow throw catches any pathological accumulation that would wrap a creator's balance. Lines 1299–1304 credit `creators[0]` with `remainder`. The arithmetic identity `m · (total_distributed / m) + (total_distributed % m) == total_distributed` (the integer division algorithm) ensures the sum across all credits is exactly `total_distributed`. ∎

The per-creator credit shares the same channel as the subsidy distribution (FA11 EconomicSoundness T-12 + T-14); this proof's contribution is the apply-side observation that `total_distributed = total_fees + subsidy_this_block` carries the per-tx fees through the same distribution math. The fee component flows through the chain's intra-supply transfer accounting; the subsidy component is the "implicit mint" gated by E4's finite-pool semantics.

**Code witness.** `src/chain/chain.cpp:1286–1305` (the distribution branch); `src/chain/chain.cpp:1279–1285` (the `total_distributed` computation including the S-007 overflow check); `src/chain/chain.cpp:33` (`checked_add_u64` helper).

**Test witness.** `tools/test_fee_distribution_edge.sh` — the seven scenarios collectively pin this: "many creators with prime dust" (subsidy 100 / 3 creators ⇒ per_creator=33, remainder=1, dust to creator[0]), "zero-fee tx with non-zero subsidy" (subsidy still mints), "exact-divide subsidy (no dust)" (remainder=0, all creators equal). 12 assertions pin the math + the determinism + the A1 closure.

### T-F5 — Empty-creators gate

**Statement.** For every successfully-applied block `B` with `B.creators.empty() == true` (and `b.index ≥ 1` so the genesis short-circuit does not apply), the distribution branch is SKIPPED. No `accounts_[domain].balance` write happens for any domain via the distribution channel. The companion gate at `chain.cpp:1390` ensures `accumulated_subsidy_` is NOT incremented either. Consequently:

```
Δaccounts_[d].balance from distribution = 0    for all domains d
Δaccumulated_subsidy_                   = 0
total_fees                              remains as accumulated (not distributed; stays in the apply-local stack)
```

The accumulated `total_fees` value is NOT credited anywhere — it stays in the apply-local `total_fees` variable, which goes out of scope when the function returns. The fees collected from any tx-paying senders (if such txs were in the block) have been moved into the apply-local accumulator at the per-tx `total_fees += fee` step, and they remain there at function exit — effectively destroyed from the chain's supply view.

**Critical: this is A1-consistent because the A1 counters `accumulated_subsidy_ / inbound / outbound / slashed` only track value-bearing flows that the distribution branch actually paid out.** If a block has empty creators AND any fees were collected from senders, those fees are removed from `live_total_supply` (the sender's balance dropped) but are NOT added to any creator's balance. The A1 invariant `live_total_supply == genesis_total + accumulated_subsidy + accumulated_inbound − accumulated_slashed − accumulated_outbound` would be violated unless one of two things is true: (a) no fees were collected in the empty-creators block (i.e., every tx in the block was a silent-skip — typical case for the test fixture), OR (b) the chain-level supply accounting explicitly accounts for the burn.

**The current implementation relies on (a).** Empty-creators blocks in practice never contain fee-paying txs:

- Genesis (`b.index == 0`) short-circuits to the genesis branch at `chain.cpp:681` and never reaches the per-tx loop.
- Test-fixture empty-creators blocks (`tools/test_empty_block_apply.sh`) explicitly contain no transactions, so `total_fees == 0` at the distribution step. The A1 check at line 1399 passes trivially.

If a production block with empty creators were ever produced AND it contained fee-paying txs, the A1 check would catch the discrepancy at line 1399 and throw — preventing the block from being committed. The empty-creators gate is therefore safe by virtue of the apply-tail A1 closure: it cannot silently destroy fee value because the A1 invariant detects the destruction and rejects the block.

*Proof sketch.* By inspection of `chain.cpp:1286 / 1390`. Both gates are `if (total_distributed > 0 && !b.creators.empty())`, so they fire identically. Under the empty-creators hypothesis, both branches are skipped. The companion empty-block test (`tools/test_empty_block_apply.sh` scenario "Block with empty creators[] (no committee) — subsidy gated OFF") asserts `live_total_supply` is unchanged across an empty-creators block apply, and that A1 holds. The defensive line of reasoning is: empty-creators blocks are only produced legitimately when the block was bootstrapped without consensus (test fixtures or genesis); a production K-of-K block always has K creators. The gate exists to make the test-fixture path safe AND to make the apply layer robust against any future protocol variant that introduces non-consensus blocks. ∎

**Code witness.** `src/chain/chain.cpp:1286` (distribution branch gate); `src/chain/chain.cpp:1390` (matching counter-accumulation gate — the structural pair); `src/chain/chain.cpp:1397–1419` (A1 closure that catches any inconsistency).

**Test witness.** `tools/test_empty_block_apply.sh` (`determ test-empty-block-apply`) — 16 assertions across 6 scenarios. The first scenario "Block with empty creators[] (no committee) — subsidy gated OFF" directly pins T-F5: live supply unchanged, A1 invariant holds. The header comment at lines 7–10 specifically calls out the protection: "Defends against subsidy double-distribution on empty creators (would mint to nowhere → silent supply inflation)."

### T-F6 — A1 invariance under fees

**Statement.** For every successfully-applied block `B` and the immediate post-apply state `state_{n+1}`, the A1 unitary-balance invariant (`AccountStateInvariants.md` I-6) holds and the per-block change to `live_total_supply` decomposes as:

```
live_total_supply(state_{n+1}) − live_total_supply(state_n)
    = subsidy_this_block − block_slashed
                          + block_inbound − block_outbound
```

In particular, fees do NOT appear in the right-hand side: the per-tx fee debit from the sender (`−fee`) is exactly cancelled by the per-block fee distribution credit to creators (`+per_creator + dust`), summing to `+total_fees` across all creators. The two flows compose to zero net change in `live_total_supply`. Fees are intra-supply transfers, not value creation or destruction.

*Proof sketch.* By summation. The per-block changes to `Σ accounts_[d].balance + Σ stakes_[d].locked` decompose into the contributions from each apply-path channel (I-5 of FA-Apply enumerates them exhaustively). Group the channels by their net contribution to total supply:

- **Fee channel.** Every fee-paying tx debits `−fee` from the sender (via `charge_fee` or the bundled `−cost = −(amount + fee)` debit). Every successfully-paid fee is added to `total_fees` (via `charge_fee` or the explicit `total_fees += tx.fee`). At block-tail, `total_fees` is added to `total_distributed` and split across `creators[]`. Sum of creator credits is exactly `total_fees` (T-F4's identity). Net: `Σ fee debits + Σ fee credits = −total_fees + total_fees = 0`. UNSTAKE refunds cancel themselves (refund + `total_fees -= fee`).
- **Subsidy channel.** `subsidy_this_block` is credited to creators via the same loop; the chain's `accumulated_subsidy_` counter is incremented at line 1391 only when the distribution actually paid out. Net contribution to RHS: `+subsidy_this_block`.
- **TRANSFER amount channel.** Same-shard: debit `tx.amount` from sender, credit `tx.amount` to recipient — net 0. Cross-shard: debit `tx.amount` from sender, accumulate into `block_outbound`. Net contribution to RHS: `−block_outbound`.
- **Cross-shard inbound channel.** Credit `r.amount` to recipient, accumulate into `block_inbound`. Net contribution to RHS: `+block_inbound`.
- **STAKE / UNSTAKE channel.** STAKE moves `amount` from `accounts_[d].balance` to `stakes_[d].locked`; UNSTAKE post-unlock moves it back. Both are intra-supply transfers across the `accounts_ ↔ stakes_` boundary. Net contribution to RHS: `0`.
- **Slashing channel.** Suspension + equivocation slashes decrement `stakes_[d].locked` and accumulate into `block_slashed`. Net contribution to RHS: `−block_slashed`.
- **NEF channel.** Transfers `pool/2` from `accounts_[ZEROTH_ADDRESS].balance` to `accounts_[tx.from].balance` on first-time REGISTER. Intra-supply transfer. Net contribution to RHS: `0`.

Summing the net contributions: `0 + subsidy_this_block − block_outbound + block_inbound − block_slashed + 0 + 0 = subsidy_this_block − block_slashed + block_inbound − block_outbound`. This matches the right-hand side of the statement.

The A1 closure at `chain.cpp:1397–1419` asserts this equality literally:

```cpp
uint64_t expected = expected_total();   // = genesis_total + Σ subsidy + Σ inbound − Σ slashed − Σ outbound
uint64_t actual   = live_total_supply();
if (actual != expected) throw "unitary-balance invariant violated";
```

A fee that escaped the per-creator distribution (e.g., a regression introducing a forgotten `total_fees -= fee` somewhere) would manifest as `actual < expected` (supply destroyed without an `accumulated_slashed_` credit). The A1 throw catches it. A fee that double-credited (e.g., a missing UNSTAKE refund cancellation) would manifest as `actual > expected` — same throw catches it. ∎

**Code witness.** `src/chain/chain.cpp:1397–1419` (A1 closure); the per-channel I-5 enumeration in `AccountStateInvariants.md` §2 (the exhaustive channel table); FA11 EconomicSoundness T-12 (the chain-level A1 theorem).

**Test witness.** `tools/test_supply_invariant.sh` (`determ test-supply-invariant`) — directly asserts the A1 equation on synthetic per-counter deltas. `tools/test_supply_lifecycle.sh` walks the chain through TRANSFER / STAKE / UNSTAKE / REGISTER / DEREGISTER / equivocation / suspension / lottery subsidy / finite-pool exhaustion / cross-shard inbound/outbound, asserting A1 closure after each block. `tools/test_fee_distribution_edge.sh` "A1 invariant across all distribution scenarios" assertion specifically pins the fee-flow component.

### T-F7 — Fee determinism

**Statement.** For two byte-identical replays of the same block sequence on different nodes (or the same node at different times), starting from byte-identical pre-apply state, the per-creator credit deltas after each block apply are byte-identical: same `total_fees`, same `subsidy_this_block`, same `total_distributed`, same `per_creator`, same `remainder`, and same dust placement on `creators[0]`.

*Proof sketch.* By deterministic structure of the apply path:

1. **`total_fees` accumulation order.** The per-tx loop iterates `b.transactions` in declaration order (a `std::vector`), which is fixed by the block's wire representation. Every node deserializes the same vector. The per-tx fee writes accumulate in identical order.

2. **`subsidy_this_block` computation.** The subsidy calculation at `chain.cpp:1247–1272` reads `subsidy_mode_`, `block_subsidy_`, `lottery_jackpot_multiplier_`, and `b.cumulative_rand` — all deterministic. The lottery branch is a pure function of `b.cumulative_rand`'s first 8 bytes modulo `lottery_jackpot_multiplier_`. The finite-pool branch is a pure function of `subsidy_pool_initial_` and the running `accumulated_subsidy_` counter. Both are byte-identical across nodes.

3. **Per-creator distribution loop.** The loop at `chain.cpp:1290` iterates `b.creators` in declaration order (a `std::vector` baked into the wire format). Every node iterates in the same order. The arithmetic `per_creator = total_distributed / m` and `remainder = total_distributed % m` is deterministic u64 division. The dust write at line 1299 always lands on `b.creators[0]` regardless of any sort or selection logic — the producer's choice of `creators[0]` is the deterministic dust target.

4. **No reads from non-deterministic state.** The branch reads no time-of-day, no thread-id, no map iteration order, no anything that could differ across nodes. (`std::map` iteration would be deterministic anyway by sorted-key order — but the distribution branch iterates the `b.creators` vector, not a map.)

Combining (1) — (4): every input to the distribution arithmetic is byte-identical across nodes, the arithmetic is deterministic, and the output writes are in deterministic order. Therefore the per-creator credits are byte-identical. ∎

This is the foundation of the S-033 state-root commitment: the per-creator fee credit shows up in the `a:` namespace of the state root (FA-Apply I-5, `AccountStateInvariants.md` §2.5 + PROTOCOL.md §4.1.1). Any nondeterminism in the fee distribution would manifest as state-root divergence, which the S-033 gate at `chain.cpp:1430` catches.

**Code witness.** `src/chain/chain.cpp:1286–1305` (the deterministic distribution loop); `src/chain/chain.cpp:1430` (S-033 state-root gate that catches any divergence).

**Test witness.** `tools/test_fee_distribution_edge.sh` "A1 invariant across all distribution scenarios" — 12 assertions including determinism (the test reseeds the same block twice and asserts byte-identical creator credits). `tools/test_snapshot_bootstrap.sh` covers the broader replay-determinism property (the receiver re-applies the same block sequence as the donor and the state-root parity assertion at line 1430 catches any drift).

---

## 3. Skip-vs-failure asymmetry

T-F2's table documents two distinct silent-failure regimes for fee-paying txs: silent-skip (no-fee) vs. silent-reject-with-fee (or refund-with-nonce-bump). The asymmetry has a deliberate design rationale tracked through the validator + apply two-tier defense.

**Silent skip (TRANSFER / STAKE / REGISTER / DEREGISTER / UNSTAKE / DAPP_REGISTER / DAPP_CALL on insufficient balance).** These cases are diagnosable upstream by the validator: the validator's V15 (transaction-apply check) re-runs the apply logic on the candidate block and rejects if any tx would fail. The validator's check fires before the producer's gossip, so honest producers never include these txs in a finalized block. The apply-layer silent-skip is a defensive safety net for the path where a malformed block somehow slips past the validator (a buggy peer with a stale apply codepath, or a snapshot replay of a pre-fix block). In that case, the apply layer silently skips the tx with no fee charge and no nonce bump — a fully reversible no-op that lets honest replay continue without burning honest users' fees.

**Silent reject with fee (REGISTER duplicate / DEREGISTER missing-registrant / PARAM_CHANGE malformed-payload / DAPP_REGISTER malformed-payload-post-charge-fee / DAPP_CALL on inactive DApp).** These cases share a structural feature: the validator's upstream check ALREADY consumed effort proportional to the fee (signature verification, multisig threshold check, payload shape validation), and the apply layer's secondary check is a belt-and-suspenders mechanism. The chain charges the fee because the operator's tx already paid for the validator's review work; refunding would create a perverse incentive for operators to submit deliberately-invalid txs to consume inclusion bandwidth without paying.

**UNSTAKE refund (the unique case).** UNSTAKE pre-unlock has a refund branch (T-K4 of `StakeLifecycle.md`) because the honest user's mistake is fundamentally different: they're not trying to spam or grief — they're trying to retrieve their own staked value, and they miscalculated the unlock height. The misclock surface is structural (block-height delay between observation and inclusion), so the chain's posture is "honest misclock is free" — the user pays no fee on a too-early UNSTAKE. The validator's S-017 closure (per `docs/SECURITY.md` §S-017) tightens this further: post-fix, the validator rejects too-early UNSTAKE upstream so honest users never reach the apply-layer refund path. The refund branch survives as a tertiary defense.

**Why the asymmetric design?** TRANSFER and STAKE on insufficient balance are best modeled as "stale mempool entry" — the sender's balance dropped (via a prior TRANSFER, or due to misconception about their balance) between the mempool entry and the block inclusion. The honest user did not intentionally trigger the failure. The fair posture is: drop silently, do not consume the nonce slot, let the user retry after a balance top-up with the same nonce. UNSTAKE on pre-unlock is best modeled as "operator-intentional but misclocked." The user explicitly wants their stake released and submitted a deliberate transaction — they just got the timing wrong. The fair posture there is: drop silently, refund the fee, but consume the nonce slot. The nonce consumption prevents an attacker from spamming UNSTAKE-too-early txs at every fresh block to grief the producer's inclusion pipeline without ever paying — the nonce slot is the cost, the fee is refunded. (See `StakeLifecycle.md` §3 for the extended discussion.)

**The "defensive charge" pattern.** REGISTER on duplicate domain, DEREGISTER on missing registrant, PARAM_CHANGE on malformed payload, DAPP_REGISTER on malformed payload after charge_fee — these all charge the fee because they reach `charge_fee` in their normal control flow, and the post-charge_fee body's defensive shape checks discover the malformity. The validator's upstream gates should have caught these (the validator runs the same shape checks), so reaching the apply-time defensive branch means the validator either didn't run or has a bug; the apply-time fee consumption is the chain's "tax on validator-bypass attempts" — discouraging adversaries from finding ways to submit invalid-but-superficially-well-formed txs.

The two-regime / one-refund / one-defensive-charge structure is internally consistent: every fee-paying surface has a deliberate failure-mode posture, and the postures together encode the chain's "honest users free, validators paid, attackers taxed" UX contract.

---

## 4. Dust placement

The distribution arithmetic at `chain.cpp:1286–1305` performs integer division `per_creator = total_distributed / m` and credits the remainder `total_distributed % m` to `creators[0]`. The choice of `creators[0]` as the dust target — rather than `creators[m-1]`, or a randomized index, or a per-block round-robin — is a deterministic design decision with three structural advantages.

**Determinism.** `creators[0]` is a fixed slot in the block's wire format — the first entry of the `b.creators[]` vector. Every node sees the same value at that index byte-for-byte. A round-robin scheme (e.g., dust to `creators[b.index % m]`) would also be deterministic, but the fixed-`creators[0]` rule is simpler to reason about: a reviewer can compute the dust placement from the block's wire image alone without tracking the chain's height history.

**Alphabetical sort (in genesis).** `make_genesis_block` and related fixtures sort `b.creators[]` alphabetically by domain name (see the comment at `tools/test_fee_distribution_edge.sh:13`: "creators are sorted alphabetically in make_genesis_block, so creator[0] (the dust recipient) is deterministic across nodes"). This is a stronger property than determinism alone: it means the dust recipient is also predictable from the validator-pool composition without the producer's discretion. A non-sorted ordering would let the producer choose `creators[0]` and therefore choose the dust recipient — a minor but real free-money channel. The alphabetical sort closes that hole.

**Audit-friendliness.** A protocol reviewer auditing per-block fee flow can predict the dust recipient by inspecting the block's creators[] vector. If a regression introduced non-alphabetical creators[] (e.g., reordered by stake), the dust placement would shift, and the audit tooling (`tools/operator_fork_watch.sh`, `tools/operator_supply_check.sh`) would observe the drift. The fixed-`creators[0]` rule is the audit anchor.

**Why not "burn the dust"?** A burn-the-dust scheme (e.g., add `total_distributed % m` to a permanent burn pool) would also be deterministic and audit-friendly, but would conflict with the A1 unitary-supply invariant: total supply would decrease by `Σ remainders` over the chain's lifetime, requiring an additional A1 counter to track the burns. The current scheme — flat split + dust to creators[0] — keeps the A1 closure trivial: the entire `total_distributed` is credited to creators, summing to a clean per-block delta of `+subsidy_this_block` (the fees cancel against the per-tx debits).

**Why not weighted distribution?** A weighted scheme (e.g., proportional to each creator's stake, or proportional to their per-block contribution) would be deterministic but would create a stake-amplification incentive — a validator with 100× the median stake would earn 100× the fees, accelerating wealth concentration in the validator set. The flat split (per_creator equal across all m creators) makes the per-block fee earnings stake-independent — every creator in the K-of-K committee receives the same income regardless of their stake amount. This preserves the small-validator economics + the protocol's mutual-distrust posture.

The dust placement is the simplest defensible choice that satisfies determinism + audit-friendliness + A1-closure-triviality + stake-amplification-immunity. The 1-line `bal0 += remainder` write at `chain.cpp:1299` is the load-bearing code.

---

## 5. What this doesn't prove

The theorems above target the fee-flow component of the apply layer. They do not extend to:

- **Subsidy distribution proper.** T-F4's distribution math covers the per-creator credit including both fees AND subsidy combined into `total_distributed`. The subsidy-specific properties (E3 lottery expectation, E4 finite-pool exhaustion, A1 contribution of `accumulated_subsidy_`) are the scope of `EconomicSoundness.md` (FA11) T-12 + T-14. The present proof composes with FA11: every theorem above is stated about the fee component, and the subsidy component flows through the same distribution channel without altering the fee-component arithmetic.

- **Cross-shard fee handling.** A cross-shard TRANSFER (`is_cross_shard(tx.to) == true`) charges the fee on the SOURCE shard (the `tx.fee` debit + `total_fees += tx.fee` happens at `chain.cpp:745 / 767`), and the destination shard's inbound-receipt apply at `chain.cpp:1367` credits only the `r.amount` (no fee credit to the recipient). This is structurally consistent — the fee pays for the source shard's producer effort + the cross-shard receipt creation — but the cross-shard composition argument (A1 invariance across the source-debit + destination-credit pair) is the scope of `CrossShardReceipts.md` (FA7) T-7 + T-8. The present proof's T-F6 covers the same-shard fee flow; the cross-shard case is a non-symmetric extension.

- **Slashing supply mechanism.** Equivocation slashing (FA6) and suspension slashing (FA-Apply I-3) decrement `stakes_[d].locked` and accumulate into `accumulated_slashed_`. The supply-destroyed-via-slash value is tracked by a different counter than fees and does not interact with the fee-distribution branch. The interaction between slashing and the empty-creators gate is also irrelevant: slashing happens unconditionally at lines 1313–1356 regardless of whether `creators[]` is empty, because the slash is a counter-tracked supply decrease independent of distribution.

- **Mempool-side fee economics.** The present proof targets the apply-layer behavior; it does not cover producer-side fee market dynamics (which txs a producer chooses to include, fee-based prioritization, MEV-like reordering). The fee-market layer is a separate concern tracked in `docs/SECURITY.md` and the V2 fee-market design notes.

- **Snapshot restore preserves fee accounting.** The per-block `total_fees` is a stack local, not persisted. The post-distribution `accounts_[creator].balance` writes ARE persisted, and are covered by the `a:` namespace of the S-033 state-root commitment + the snapshot serialize/restore wiring (FA-Apply-2 `SnapshotEquivalence.md` T-S1 + T-S2). The present proof composes with FA-Apply-2: every per-block fee credit lands in `accounts_`, which survives snapshot bootstrap byte-identically.

- **Wallet-side fee estimation.** The chain's apply layer accepts whatever `tx.fee` value the wallet signed. The wallet's choice of fee value (too-low → producer ignores; too-high → operator overpays) is a UX concern outside the apply scope. The protocol does not enforce a minimum fee at apply time (a tx with `fee == 0` is processable; whether a producer includes it is the producer's economic discretion).

- **DAPP_CALL fee semantics beyond inactive-gate skip.** DAPP_CALL's apply branch at `chain.cpp:1133–1224` charges the fee on every reach-`charge_fee` path including the inactive-gate skip (T-D6 of `DAppRegistryLifecycle.md`) and the same-shard credit success path (T-F1 row). The cross-shard rejection at `chain.cpp:1205` is a defensive single-shard restriction for v2.19; cross-shard DAPP_CALL is deferred Phase 7.6 work and outside the present proof's scope.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V15 (transaction apply) + assumption A1 (ed25519 EUF-CMA) that authenticates `tx.from` for the fee debit. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 (no underflow, the `sender.balance < cost / fee` gates), I-2 (nonce monotonicity gate that precedes every fee debit), I-5 (the fee-only-debit channel + per-creator credit channel + UNSTAKE refund credit), I-6 (A1 closure). T-F6 is the fee-flow specialization of I-6. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 + T-S2 — the per-creator credits land in `accounts_[creator].balance` and survive snapshot bootstrap via the `a:` namespace. T-F7's determinism is structurally what makes T-S2's apply-after-restore equivalence carry through fee-paying blocks. |
| `NonceMonotonicity.md` (FA-Apply-3) | The strict-equality nonce gate at `chain.cpp:739` filters out stale-nonce txs before any fee debit; T-F1's per-tx-fee statement implicitly assumes the gate has passed. |
| `StakeLifecycle.md` (FA-Apply-4) | T-K4 — UNSTAKE pre-unlock fee refund. The unique tx type that reverses both its own balance debit AND its `total_fees` increment via the `total_fees -= fee` line at `chain.cpp:885`. |
| `DAppRegistryLifecycle.md` (FA-Apply-5) | T-D3 — DAPP_REGISTER non-owner-update silent-skip-with-fee path. The apply branch charges the fee from `d'` (the attacker) but cannot reach `d`'s slot (`dapp_registry_[tx.from]` keying). |
| `EconomicSoundness.md` (FA11) | T-12 (chain-level A1 closure), T-14 (subsidy E3+E4 distribution math + finite-pool cap). The present proof composes with FA11: subsidy flows through the same per-creator distribution channel as fees, the A1 invariant absorbs both. |
| `CrossShardReceipts.md` (FA7) | Cross-shard TRANSFER fee handling — fee charged on source, amount-only credit on destination. Outside this proof's scope but composes with T-F6 via the `block_outbound` / `block_inbound` channels. |
| `EquivocationSlashing.md` (FA6) | Different supply mechanism (slashing destroys `stakes_[d].locked` via `accumulated_slashed_`). Independent of the fee channel; no interaction beyond the shared A1 closure. |
| `docs/PROTOCOL.md` §3.3 | Apply rules including the fee-charge + nonce-bump contract per tx type. |
| `docs/PROTOCOL.md` §4.1.1 | The `a:` namespace of the S-033 state-root — per-creator credit writes land here. |
| `docs/SECURITY.md` §S-017 | UNSTAKE unlock-height closure that makes the validator the primary defense and the apply-time refund the tertiary belt-and-suspenders. |
| `tools/test_chain_apply_block.sh` | T-F1 + T-F2 (`determ test-chain-apply-block` — 22 assertions across eight blocks pinning TRANSFER / STAKE / REGISTER apply with fee handling). |
| `tools/test_fee_distribution_edge.sh` | T-F3 + T-F4 + T-F7 (`determ test-fee-distribution-edge` — 12 assertions across seven scenarios including dust placement, exact-divide, A1 invariance, determinism). |
| `tools/test_empty_block_apply.sh` | T-F5 (`determ test-empty-block-apply` — 16 assertions including the empty-creators gate scenario). |
| `tools/test_supply_invariant.sh` | T-F6 (direct A1 assertion on synthetic per-counter deltas). |
| `tools/test_supply_lifecycle.sh` | T-F6 (A1 closure across TRANSFER / STAKE / UNSTAKE / REGISTER / DEREGISTER / equivocation / suspension / lottery / finite-pool / cross-shard composition). |
| `tools/test_unstake_deregister_apply.sh` | T-F2 (UNSTAKE refund row — `total_fees -= fee` cancellation pinned by the test). |
| `tools/test_tx_edge_cases.sh` | T-F1 + T-F2 (skip-vs-success boundary; insufficient-balance silent-skip no-fee no-nonce-bump). |
| `tools/test_dapp_state_transition.sh` | T-F2 (DAPP_REGISTER non-owner update — fee charged from sender, no DApp mutation). |
| `tools/operator_supply_check.sh` | Operator-facing A1 audit tool — the fee-flow component is one input into the operator's offline closure check. |
| `include/determ/chain/chain.hpp:18–21` | `AccountState` struct (`balance`, `next_nonce`) — the per-account state mutated by the fee channel. |
| `src/chain/chain.cpp:33` | `checked_add_u64` helper (S-007 overflow defense on the per-creator credit). |
| `src/chain/chain.cpp:720` | `total_fees` declaration (per-apply stack local). |
| `src/chain/chain.cpp:727–732` | `charge_fee` lambda (shared fee-debit primitive). |
| `src/chain/chain.cpp:739` | Strict-nonce gate (precedes every fee debit). |
| `src/chain/chain.cpp:742–770` | TRANSFER branch (fee debit + amount distribution). |
| `src/chain/chain.cpp:858–871` | STAKE branch (fee debit + stake lock). |
| `src/chain/chain.cpp:873–894` | UNSTAKE branch (fee charge + conditional refund). |
| `src/chain/chain.cpp:884–885` | The UNSTAKE refund (the load-bearing `total_fees -= tx.fee` line). |
| `src/chain/chain.cpp:1049–1117` | DAPP_REGISTER branch (fee-only debit channel). |
| `src/chain/chain.cpp:1133–1224` | DAPP_CALL branch (fee debit + inactive-gate + recipient credit). |
| `src/chain/chain.cpp:1247–1272` | Per-block subsidy computation (FA11 scope). |
| `src/chain/chain.cpp:1279–1285` | `total_distributed = total_fees + subsidy_this_block` (with S-007 overflow check). |
| `src/chain/chain.cpp:1286–1305` | The distribution branch (T-F4 + T-F5). |
| `src/chain/chain.cpp:1390` | The matching counter-accumulation gate (paired with line 1286 for A1 consistency). |
| `src/chain/chain.cpp:1397–1419` | A1 closure assertion (T-F6 enforcement). |

---

## 7. Status

All seven theorems (T-F1 through T-F7) are closed in the current codebase:

- **T-F1** (per-tx fee debit) closed via the `charge_fee` lambda + the `sender.balance -= cost` debits at the TRANSFER / STAKE / DAPP_CALL branches; regression `test_chain_apply_block.sh` + `test_tx_edge_cases.sh`.
- **T-F2** (failed-tx fee refund vs charge contract) closed via the per-type branches' uniform handling (silent-skip-no-fee, defensive-charge-with-nonce-bump, UNSTAKE-refund-with-nonce-bump); regression `test_unstake_deregister_apply.sh` + `test_tx_edge_cases.sh` + `test_dapp_state_transition.sh`.
- **T-F3** (block-level fee accumulation) closed via the per-apply `total_fees` accumulator + the cancellation pattern in the UNSTAKE refund; regression `test_fee_distribution_edge.sh`.
- **T-F4** (distribution to creators) closed via the distribution branch at `chain.cpp:1286–1305` + the dust-to-creators[0] write; regression `test_fee_distribution_edge.sh` (12 assertions across seven scenarios).
- **T-F5** (empty-creators gate) closed via the `!b.creators.empty()` check at both `chain.cpp:1286` and `chain.cpp:1390` (the matched pair that keeps A1 consistent); regression `test_empty_block_apply.sh` (16 assertions including the empty-creators scenario).
- **T-F6** (A1 invariance under fees) closed via the apply-tail A1 assertion at `chain.cpp:1397–1419` + the per-channel I-5 enumeration in `AccountStateInvariants.md`; regression `test_supply_invariant.sh` + `test_supply_lifecycle.sh` + `test_fee_distribution_edge.sh`.
- **T-F7** (fee determinism) closed via the deterministic per-tx iteration, deterministic subsidy math, deterministic per-creator loop, and deterministic dust placement on `creators[0]`; regression `test_fee_distribution_edge.sh` + the S-033 state-root gate at `chain.cpp:1430`.

No theorem is open or partial. The fee-flow component depends on a small set of code primitives: the `charge_fee` lambda, the per-tx `total_fees` accumulator, the `total_distributed = total_fees + subsidy_this_block` join, the `!b.creators.empty()` gate (paired across distribution + counter accumulation), and the dust-to-creators[0] write. The breadth of consequences — seven theorems, a fully-pinned skip/charge/refund matrix across nine tx types, a documented dust-placement rationale, a load-bearing empty-creators gate, and the A1-closure guarantee that "fees never inflate the supply" — is testimony to how few primitives the chain needs to make fee accounting auditable end-to-end.

The fee channel is the load-bearing intra-supply transfer mechanism that converts user-paid economic value into validator income. The seven theorems together establish that this mechanism is deterministic (T-F7), atomic per-tx (T-F1 + T-F2), monotone within the block (T-F3), fairly distributed (T-F4), safe under degenerate input (T-F5), and supply-conserving (T-F6) — exactly the contract the protocol's economic security model requires for the fee market to function without leaking value through implementation bugs.
