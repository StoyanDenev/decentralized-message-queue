# FA-Apply — Stake lifecycle (STAKE / DEREGISTER / UNSTAKE)

This document formalizes the apply-layer state machine governing a validator's stake: the STAKE transaction that locks balance into the `stakes_` map, the DEREGISTER transaction that schedules the registry exit and arms the `unlock_height` countdown, and the UNSTAKE transaction that releases locked value back to balance once the countdown has elapsed. Together these three tx types define a per-domain three-state machine — `(unstaked, staked-active, staked-pending-unlock)` — whose transitions must preserve the A1 unitary-supply invariant, must enforce the `unstake_delay_` waiting window as the slashing-evidence window, and must refund fees to honest users who misclock a too-early UNSTAKE so the cost of misjudging the unlock countdown is bounded at zero.

The proof is mechanical: each transition is implemented by a single per-tx-type branch in `Chain::apply_transactions` (`src/chain/chain.cpp:858–894` for STAKE/UNSTAKE; `chain.cpp:839–856` for DEREGISTER). The branches use the same `charge_fee` / `sender.balance` / `sender.next_nonce` primitives covered by `AccountStateInvariants.md` (FA-Apply) and `NonceMonotonicity.md` (FA-Apply-3); the present proof's contribution is to enumerate the legitimate stake-channel transitions, prove each preserves I-3 (balance ↔ stake independence) and I-6 (A1 contribution) from FA-Apply, and pin the fee-refund UX guarantee against regression. The strength is consolidation: stake lifecycle is implicit in FA-Apply I-3 and in `docs/SECURITY.md` §S-017 (the validator/producer/chain alignment finding) but no single document collects the theorem statements, the unlock-window safety argument, and the test witnesses.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and the apply-time guarantees; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 through I-6, especially I-3 (balance ↔ stake independence channel enumeration) which names STAKE / UNSTAKE / slashing as the three transfer channels; `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot ↔ replay equivalence that carries `stakes_[d]` (locked, unlock_height) via the `s:` state-root namespace; `NonceMonotonicity.md` (FA-Apply-3) for the strict-equality nonce gate that precedes every STAKE / DEREGISTER / UNSTAKE branch and for the T-N2 analogue to T-K4 (fee-refund on future-nonce — symmetric UX guarantee); `EquivocationSlashing.md` (FA6) for the equivocation-slashing apply path that consumes `stakes_[d].locked` during the deferred-unlock window without crossing into `accounts_[d].balance`; `EconomicSoundness.md` (FA11) for the A1 closure that the STAKE → UNSTAKE round-trip preserves; `docs/SECURITY.md` §S-017 for the producer/validator/chain three-layer alignment of the `unlock_height` check.

---

## 1. Setup

### 1.1 The `StakeEntry` struct

Per `include/determ/chain/chain.hpp:23–30`:

```cpp
struct StakeEntry {
    uint64_t locked{0};
    // Block height at which UNSTAKE is allowed to release `locked` back to
    // balance. While the domain is registered (active_from <= h < inactive_from)
    // unlock_height is held at UINT64_MAX. A DEREGISTER tx at block h sets
    // unlock_height = inactive_from + UNSTAKE_DELAY.
    uint64_t unlock_height{UINT64_MAX};
};
```

`stakes_` is `std::map<std::string, StakeEntry>` (sibling of `accounts_` and `registrants_`; see `chain.hpp:540` for the full map declaration block). The `unlock_height` field is the load-bearing sentinel: it holds `UINT64_MAX` while the domain is registered (the "active" state), and is set to a finite value strictly greater than `b.index` at the moment DEREGISTER fires (the "pending-unlock" state). UNSTAKE checks `height < sit->second.unlock_height` to gate the locked-to-balance transfer; the `UINT64_MAX` sentinel makes the gate trivially false for any actively-registered domain, since no `b.index ≤ UINT64_MAX − 1` can satisfy `height ≥ UINT64_MAX`. This is the structural mechanism that prevents UNSTAKE during the active-registration window.

The `unstake_delay_` parameter (`include/determ/chain/chain.hpp:590`) is genesis-pinned (default `1000` blocks per `params.hpp:UNSTAKE_DELAY`) and mutable only via the A5 PARAM_CHANGE multisig (the `UNSTAKE_DELAY` entry is on the whitelist; see `Governance.md` FA10). The parameter expresses the chain's chosen safety window — the number of blocks between `inactive_from` and `unlock_height` during which the deregistering validator's stake remains slashable for equivocation evidence that surfaces post-DEREGISTER but inside the window.

### 1.2 The three-state machine

Each domain's stake state at every height is one of:

- **`unstaked`** — `stakes_[d].locked == 0` (or `stakes_` does not contain `d`), `registrants_[d]` may or may not exist.
- **`staked-active`** — `stakes_[d].locked > 0` AND `stakes_[d].unlock_height == UINT64_MAX` AND `registrants_[d].inactive_from == UINT64_MAX` (the canonical "validator currently participating" state).
- **`staked-pending-unlock`** — `stakes_[d].locked > 0` AND `stakes_[d].unlock_height < UINT64_MAX` AND `registrants_[d].inactive_from < UINT64_MAX` (post-DEREGISTER, pre-UNSTAKE, inside the slashing-evidence window).

The legitimate transitions are:

```
unstaked       ──STAKE──> staked-active
staked-active  ──STAKE──> staked-active           (additive — locked += amount)
staked-active  ──DEREGISTER──> staked-pending-unlock
pending-unlock ──UNSTAKE (height ≥ unlock_height)──> unstaked  (if locked == amount)
                                                  ──> pending-unlock  (if locked > amount)
```

Plus the slashing transitions (covered by FA6):

```
staked-active  ──suspension-slash──> staked-active  (locked -= SUSPENSION_SLASH, bounded)
staked-active  ──equivocation-slash──> unstaked     (locked := 0)
pending-unlock ──suspension-slash──> pending-unlock
pending-unlock ──equivocation-slash──> unstaked     (locked := 0, but evidence inside window)
```

The slashing transitions consume `stakes_[d].locked` without touching `accounts_[d].balance` (I-3 of `AccountStateInvariants.md`). They are listed here for completeness; the apply-correctness of the slashing branches is the scope of FA6, not this proof.

### 1.3 The fee-refund convention

Three transactions in this proof use the `charge_fee` lambda (`chain.cpp:727–732`) or an inline equivalent: DEREGISTER (line 840), UNSTAKE (line 878), and the implicit fee path inside STAKE (line 868 — fees folded into the `cost = amount + fee` debit at line 863). The fee is consumed before any state mutation that could fail. For STAKE, the `cost` includes the stake amount so insufficient-balance is a single check at line 864 with `continue` semantics — no partial debit, no fee charged. For DEREGISTER, the fee is consumed unconditionally on entry (line 840) and the rest of the branch runs even on the defensive "no registry entry" path at line 842. For UNSTAKE, the fee is consumed at line 878 before the unlock-height / locked-amount checks; on failure of any of those checks the fee is explicitly refunded via `sender.balance += tx.fee; total_fees -= tx.fee;` at lines 884–885 before the nonce bump and `break`.

The fee-refund pattern is a deliberate UX choice — it makes honest users penalty-free if they submit an UNSTAKE before the chain has advanced past `unlock_height`. The symmetric pattern in `NonceMonotonicity.md` (T-N2) is the future-nonce silent-skip: a misclock on the nonce side is also penalty-free (the tx is dropped at the nonce gate before `charge_fee` runs). Together these two refund conventions cover the two primary misclock surfaces a wallet can hit.

---

## 2. Theorems

### T-K1 — STAKE locks balance into stake

**Statement.** For every domain `d` and every block `B` containing a STAKE transaction `tx ∈ B.transactions` with `tx.from == d`, `tx.type == TxType::STAKE`, `tx.payload.size() == 8`, and `tx.nonce == state.accounts_[d].next_nonce`, let `amount := decode_le_u64(tx.payload)` and `cost := amount + tx.fee`. If `state.accounts_[d].balance ≥ cost`, then apply produces the deltas:

```
Δaccounts_[d].balance       = −cost          (= −amount − tx.fee)
Δstakes_[d].locked          = +amount
Δtotal_fees                 = +tx.fee
Δaccounts_[d].next_nonce    = +1
```

with no other state mutation. The A1 unitary-supply invariant holds — STAKE moves `amount` from balance to stake and the `tx.fee` portion enters the per-block `total_fees` accumulator (later distributed to creators per FA11), so total supply is conserved at the apply-tail A1 evaluation (`chain.cpp:1399`).

*Proof sketch.* By inspection of `chain.cpp:858–871`. The nonce gate at line 739 admits the tx (hypothesis). The payload-size check at line 859 admits a `continue` on length mismatch — under the 8-byte hypothesis the branch proceeds. `amount` is decoded at lines 860–862 (little-endian 8-byte field). `cost = amount + tx.fee` at line 863; balance check `sender.balance < cost` at line 864 fails the hypothesis, so the apply proceeds. `sender.balance -= cost` at line 865 debits the source (single atomic write); `stakes_[tx.from].locked += amount` at line 867 credits the stake map (single atomic write). `total_fees += tx.fee` at line 868 captures the fee for later distribution. `sender.next_nonce++` at line 869 bumps the nonce. The four deltas in the statement are exactly the four state writes; no other field is touched. The A1 closure follows from I-5 + I-6 of FA-Apply: `cost = amount + tx.fee` is split exactly between the `Δstakes_[d].locked` term and the `total_fees` accumulator, and the apply-tail check at `chain.cpp:1399` confirms `live_total_supply` (which sums balances AND stakes) is invariant under this transition. ∎

**Code witness.** `src/chain/chain.cpp:858–871` (STAKE branch); `src/chain/chain.cpp:1399` (A1 closure assertion); `include/determ/chain/chain.hpp:23–30` (`StakeEntry` struct).

**Test witness.** `tools/test_stake_accounting.sh` (`determ test-stake-accounting`) — 12 assertions across seven scenarios pin the STAKE state machine including the A1 conservation under STAKE (value moves balance → stake, supply unchanged). `tools/test_unstake_deregister_apply.sh` (`determ test-unstake-deregister-apply`) exercises the joint STAKE / UNSTAKE / DEREGISTER apply lifecycle.

### T-K2 — STAKE-on-empty-balance silent skip

**Statement.** For every domain `d` and every block `B` containing a STAKE transaction `tx` with `tx.from == d`, `tx.nonce == state.accounts_[d].next_nonce`, `tx.payload.size() == 8`, `amount := decode_le_u64(tx.payload)`, `cost := amount + tx.fee`, if `state.accounts_[d].balance < cost`, then apply produces no state mutation: `Δaccounts_[d].balance == 0`, `Δstakes_[d].locked == 0`, `Δtotal_fees == 0`, `Δaccounts_[d].next_nonce == 0`. The tx is silently dropped.

*Proof sketch.* By inspection of `chain.cpp:864`: `if (sender.balance < cost) continue;`. Under the hypothesis `balance < cost`, the `continue` branch is taken before any state mutation. The subsequent lines (865–869) — balance debit, stake credit, fee accounting, nonce bump — are unreached. The validator's V15 should have rejected the tx upstream; the apply-time `continue` is the safety net (see I-1 of FA-Apply for the same pattern across all debit channels). Critically, the nonce is NOT bumped: a STAKE on an empty balance does not consume the nonce slot, so the user can retry the same `(from, nonce)` after a balance top-up — no penalty for a too-eager STAKE. ∎

**Code witness.** `src/chain/chain.cpp:864` (the gate); `src/chain/chain.cpp:739` (upstream nonce gate, which precedes this and is unaffected by the balance check).

**Test witness.** `tools/test_tx_edge_cases.sh` exercises the skip-vs-success boundary at `balance == cost` (succeeds) vs `balance == cost - 1` (skipped, no nonce bump) — the test covers the TRANSFER branch but the STAKE branch uses the identical `cost`-style gate at line 864. `tools/test_stake_accounting.sh` covers the STAKE success path; the negative case is structurally identical to the TRANSFER negative case in `test_tx_edge_cases.sh`.

### T-K3 — DEREGISTER deferred-unlock

**Statement.** For every domain `d` registered at `state` (`registrants_[d]` exists, `registrants_[d].inactive_from == UINT64_MAX`) and every block `B` at height `b.index` containing a DEREGISTER transaction `tx` with `tx.from == d`, `tx.nonce == state.accounts_[d].next_nonce`, and `state.accounts_[d].balance ≥ tx.fee`, apply produces the deltas:

```
Δregistrants_[d].inactive_from = (b.index + 1) + δ_reg − UINT64_MAX_as_NULL
                               = b.index + 1 + δ_reg
                              where δ_reg ∈ [0, REGISTRATION_DELAY_WINDOW)
                              and δ_reg = derive_delay(b.cumulative_rand, tx.hash)
Δstakes_[d].unlock_height      = inactive_from + unstake_delay_  (only if stakes_[d] exists)
Δaccounts_[d].balance          = −tx.fee
Δaccounts_[d].next_nonce       = +1
Δtotal_fees                    = +tx.fee
```

with no other state mutation. Crucially, `stakes_[d].locked` is **unchanged**: DEREGISTER does NOT release the stake — it only schedules the unlock window to begin. The slashing window remains open until `b.index ≥ stakes_[d].unlock_height`, which is `inactive_from + unstake_delay_` blocks in the future.

*Proof sketch.* By inspection of `chain.cpp:839–856`. The nonce gate at line 739 admits the tx (hypothesis). `charge_fee(sender, tx.fee)` at line 840 debits the fee (succeeds under the balance hypothesis). The registry lookup at line 841 finds the entry (hypothesis). `inactive_from = height + derive_delay(b.cumulative_rand, tx.hash)` at line 844 — the `derive_delay` helper at `chain.cpp:42–47` returns `1 + (v % REGISTRATION_DELAY_WINDOW)` where `v` is the leading 8 bytes of `SHA256(tx.hash ‖ b.cumulative_rand)` — so `inactive_from ∈ [b.index + 1, b.index + REGISTRATION_DELAY_WINDOW]` with a value the deregistering operator cannot pre-pick (the binding through `b.cumulative_rand`, which is committee-randomness-derived per F0 §1.3 V9, prevents operator-side bias on the deactivation height). Line 846 writes the registry's `inactive_from`. Lines 848–852 conditionally write `stakes_[d].unlock_height = inactive_from + unstake_delay_` — the deferred-unlock-height. `sender.next_nonce++` at line 854 bumps the nonce. `stakes_[d].locked` appears nowhere in the branch's write set — the stake is not released by DEREGISTER. The slashing-window safety claim follows: any equivocation or suspension event with `evidence_height ∈ [b.index + 1, inactive_from + unstake_delay_]` lands while `stakes_[d].locked > 0`, so the slash mechanism in `chain.cpp:1313–1356` can still take effect on the staked value. ∎

**Code witness.** `src/chain/chain.cpp:839–856` (DEREGISTER branch); `src/chain/chain.cpp:42–47` (`derive_delay` helper); `include/determ/chain/chain.hpp:590` (`unstake_delay_` field); `include/determ/node/registry.hpp:15` (`REGISTRATION_DELAY_WINDOW` constant = 10).

**Test witness.** `tools/test_unstake_deregister_apply.sh` (`determ test-unstake-deregister-apply`) — the DEREGISTER scenario asserts `inactive_from = height + derive_delay > height` and `unlock_height = inactive_from + unstake_delay`. Three assertions in the DEREGISTER scenario block; the `set_unstake_delay(1)` call in the test bypasses the production 1000-block window to make the test fast.

### T-K4 — UNSTAKE pre-unlock fee refund

**Statement.** For every domain `d` and every block `B` at height `b.index` containing an UNSTAKE transaction `tx` with `tx.from == d`, `tx.nonce == state.accounts_[d].next_nonce`, `tx.payload.size() == 8`, `amount := decode_le_u64(tx.payload)`, `state.accounts_[d].balance ≥ tx.fee`, and either (a) `stakes_` does not contain `d`, OR (b) `state.stakes_[d].locked < amount`, OR (c) `b.index < state.stakes_[d].unlock_height` (i.e., the unstake is too early), apply produces the deltas:

```
Δaccounts_[d].balance       = 0    (fee debited then refunded — net zero)
Δaccounts_[d].next_nonce    = +1
Δtotal_fees                 = 0    (fee added then removed — net zero)
Δstakes_[d].locked          = 0    (no release; unlock-failure)
```

with no other state mutation. The honest user's misclock is penalty-free: balance is unchanged, the stake is unchanged, only the nonce slot is consumed so the user can retry at a later height with a fresh nonce.

*Proof sketch.* By inspection of `chain.cpp:873–894`. The nonce gate at line 739 admits the tx (hypothesis). The payload-size check at line 874 admits (hypothesis). `amount` is decoded at lines 875–877. `charge_fee` at line 878 succeeds (balance hypothesis); state at this point shows `sender.balance -= tx.fee; total_fees += tx.fee;`. The conditional at lines 880–881 is the unlock-failure check: `(sit == stakes_.end()) OR (sit->second.locked < amount) OR (height < sit->second.unlock_height)` — under the hypothesis at least one of (a), (b), (c) holds, so the branch enters the refund body at lines 882–887. Line 884 refunds the fee: `sender.balance += tx.fee` (un-doing the `charge_fee` debit). Line 885 reverses the `total_fees += tx.fee` from `charge_fee` so the per-block fee accumulator is also restored. Line 886 bumps the nonce (the nonce slot IS consumed — see Discussion §3 below for the rationale). Line 887 `break`s out of the switch. `stakes_[d]` is untouched. The net deltas are: balance unchanged (+fee on refund cancels −fee from charge_fee), `total_fees` unchanged (same cancellation), `stakes_[d].locked` unchanged (no write reaches line 890), `next_nonce` bumped by exactly one. The branch's only persistent state mutation is the nonce bump. ∎

**Code witness.** `src/chain/chain.cpp:878–887` (the charge / refund / bump pattern); `src/chain/chain.cpp:727–732` (`charge_fee` lambda); `src/chain/chain.cpp:884–885` (the refund itself — load-bearing for the UX guarantee).

**Test witness.** `tools/test_unstake_deregister_apply.sh` (`determ test-unstake-deregister-apply`) — two scenarios test the refund path: "UNSTAKE too-early" (3 assertions: stake unchanged, balance unchanged after refund, nonce bumped) and "UNSTAKE insufficient locked" (2 assertions: same negative invariants for the (b) sub-condition). Combined with the validator-layer S-017 check at `src/node/validator.cpp:606–614` (which rejects too-early UNSTAKE at block-validation time post-fix), the apply-time refund is the belt-and-suspenders defense that the SECURITY.md §S-017 closure documents.

### T-K5 — UNSTAKE post-unlock success

**Statement.** For every domain `d` and every block `B` at height `b.index` containing an UNSTAKE transaction `tx` with `tx.from == d`, `tx.nonce == state.accounts_[d].next_nonce`, `tx.payload.size() == 8`, `amount := decode_le_u64(tx.payload)`, `state.accounts_[d].balance ≥ tx.fee`, `state.stakes_[d]` exists, `state.stakes_[d].locked ≥ amount`, and `b.index ≥ state.stakes_[d].unlock_height`, apply produces the deltas:

```
Δaccounts_[d].balance       = −tx.fee + amount   (fee out, unstake amount in)
Δstakes_[d].locked          = −amount
Δaccounts_[d].next_nonce    = +1
Δtotal_fees                 = +tx.fee
```

with no other state mutation. The A1 unitary-supply invariant holds: `amount` moves from `stakes_[d].locked` to `accounts_[d].balance` (an intra-domain transfer), and the `tx.fee` enters `total_fees` for distribution (same channel as STAKE's fee). Total supply is invariant; the apply-tail A1 check at `chain.cpp:1399` succeeds.

*Proof sketch.* By inspection of `chain.cpp:873–893`. The nonce gate at line 739 admits the tx (hypothesis). Payload size at line 874, amount decode at lines 875–877. `charge_fee` at line 878 succeeds (balance hypothesis): `sender.balance -= tx.fee; total_fees += tx.fee;`. The conditional at lines 880–881 is FALSE under the hypothesis (stake entry exists, `locked ≥ amount`, `height ≥ unlock_height`), so the refund branch at lines 882–887 is skipped. The apply proceeds to line 889 `__ensure_stakes()` (no-op if `stakes_` already exists, which it must by `sit != stakes_.end()` from line 880), line 890 `sit->second.locked -= amount` debits the stake, line 891 `sender.balance += amount` credits the balance, line 892 bumps the nonce. The four deltas are exactly the four state writes. A1 closure: the `amount` round-trip from stake to balance is captured in I-5 of FA-Apply (the UNSTAKE post-unlock credit channel + the STAKE locked-balance debit channel), and `tx.fee` enters `total_fees` exactly as for STAKE. ∎

**Code witness.** `src/chain/chain.cpp:889–893` (the unstake success path); `src/chain/chain.cpp:1399` (A1 closure).

**Test witness.** `tools/test_unstake_deregister_apply.sh` "UNSTAKE success after unlock" scenario — 3 assertions (stake reduced by amount, balance increased by amount net of fee-return, height advance to unlock_height verified). `tools/test_stake_accounting.sh` covers the full STAKE → UNSTAKE round-trip A1 conservation.

### T-K6 — Pre-DEREGISTER UNSTAKE silent skip (with fee refund)

**Statement.** For every domain `d` registered at `state` (`registrants_[d]` exists with `inactive_from == UINT64_MAX`, equivalently in the `staked-active` state) and every block `B` containing an UNSTAKE transaction `tx` with `tx.from == d` satisfying the basic admission hypotheses (nonce match, payload size, sufficient fee balance), apply produces zero net deltas on balance / stake / total_fees and a +1 delta on next_nonce — equivalently, the T-K4 fee-refund outcome.

*Proof sketch.* In the `staked-active` state, `state.stakes_[d].unlock_height == UINT64_MAX` (initialized to that value at STAKE-after-REGISTER per `chain.cpp:807–811`, never modified except by DEREGISTER which has not yet fired by hypothesis). The unlock-failure condition at `chain.cpp:881` evaluates `height < UINT64_MAX`, which is `true` for any `b.index ≤ UINT64_MAX − 1` — i.e., every reachable block height. The refund branch at lines 882–887 fires, producing the T-K4 outcome. The operator must DEREGISTER first to enter the `staked-pending-unlock` state (T-K3), then wait until `b.index ≥ stakes_[d].unlock_height` to satisfy T-K5's success precondition. The sentinel-based gating is what makes "UNSTAKE before DEREGISTER" structurally a no-op rather than a special-cased error: the unlock-height check is the unified gate. ∎

**Code witness.** `src/chain/chain.cpp:807–811` (REGISTER initializes `stakes_[d].unlock_height = UINT64_MAX`); `src/chain/chain.cpp:881` (the unified unlock-height gate); `include/determ/chain/chain.hpp:29` (`unlock_height{UINT64_MAX}` struct default).

**Test witness.** `tools/test_unstake_deregister_apply.sh` "UNSTAKE too-early" scenario covers the case where `unlock_height == UINT64_MAX` (no DEREGISTER yet) — the assertions are stake unchanged, balance unchanged, nonce bumped. This is the same negative-invariant set as T-K4's case (c), exercised against the sentinel value.

### T-K7 — Independent stakes across distinct domains

**Statement.** For every pair of distinct domains `d1, d2` (`d1 ≠ d2`) and every block `B`, the stake-lifecycle mutations on `d1` (any of STAKE, DEREGISTER, UNSTAKE with `tx.from == d1`) do not read or write `stakes_[d2]`, `accounts_[d2]`, or `registrants_[d2]`. Equivalently: one validator's stake lifecycle is fully isolated from another's; no cross-account write or read exists in the STAKE / DEREGISTER / UNSTAKE branches.

*Proof sketch.* By inspection of the three branches at `chain.cpp:839–894`. Each branch resolves a single `sender` reference at line 735 (`accounts_[tx.from]`), a single `stakes_[tx.from]` access (line 867 for STAKE, line 851 for DEREGISTER, line 880 for UNSTAKE), and at most a single `registrants_[tx.from]` lookup (line 841 for DEREGISTER, not touched by STAKE or UNSTAKE). Every map access is keyed by `tx.from`; no second-key access (`stakes_[other_domain]`, `accounts_[other_domain]`) appears anywhere in the three branches' body. `std::map` access semantics give the standard guarantee: reading or writing `m[k1]` does not modify `m[k2]` for `k1 ≠ k2` (the underlying red-black tree is structurally shared only by lookup; `operator[]` allocates a node for `k1` if missing without disturbing any `k2` node). Therefore the independence claim follows directly from the per-`tx.from` keying of every access. ∎

**Code witness.** `src/chain/chain.cpp:858–871` (STAKE — all accesses keyed by `tx.from`); `src/chain/chain.cpp:839–856` (DEREGISTER — same); `src/chain/chain.cpp:873–894` (UNSTAKE — same); `include/determ/chain/chain.hpp:540` (`stakes_` map declaration).

**Test witness.** `tools/test_stake_accounting.sh` covers seven scenarios; among them is a multi-domain trace that confirms independent evolution (one domain's STAKE / UNSTAKE has zero effect on a peer domain's stake state). The 12 assertions across the scenarios include cross-domain checks: `bob.locked` and `bob.balance` are explicitly asserted unchanged after each `alice.STAKE` / `alice.UNSTAKE` event in the test sequence. The same independence claim is also covered by `tools/test_unstake_deregister_apply.sh` — the non-registrant DEREGISTER scenario asserts the unregistered domain's nonce bumps without affecting any other domain.

---

## 3. Why fee refund on too-early UNSTAKE?

The fee-refund branch at `chain.cpp:884–885` is a deliberate UX choice. The honest user's only way to know whether `b.index ≥ stakes_[d].unlock_height` at the moment a transaction lands is to consult the chain's current head height at the moment of submission and add a margin for tx propagation + block-production delay. If the operator misjudges that margin (network congestion, peer-list freshness, abort-induced block delay), their UNSTAKE arrives one block early and would — without the refund — burn `tx.fee` for an apply that produced no state mutation. The refund neutralizes the cost: the misclocked tx is a no-op modulo the nonce slot.

**Analogue with `NonceMonotonicity.md` T-N2 (future-nonce silent skip).** A future-nonce tx (`tx.nonce > sender.next_nonce`) is silently dropped at the nonce gate `chain.cpp:739` before `charge_fee` runs. The user pays no fee — same UX outcome as T-K4. The two misclock surfaces (nonce vs unlock-height) are symmetric in their UX guarantee: misjudging either side of the chain's state machine produces a no-op tx, not a fee burn.

The asymmetry is structural: T-N2's silent skip is "before charge_fee," T-K4's silent skip is "after charge_fee with refund." Both routes achieve zero net fee debit. The difference is consumed nonce slot: T-N2 does NOT consume the nonce (the gate fires before any per-type branch), while T-K4 DOES consume the nonce (the gate that fails is the unlock-height check inside the UNSTAKE branch, after the nonce-strict-equality gate has already passed at line 739). The T-K4 nonce consumption is intentional: a non-consuming variant would let an attacker who observed the unlock_height computation re-submit a stream of UNSTAKE-too-early txs at every fresh height to spam the producer's tx-inclusion queue without ever paying a fee. The nonce consumption forces the attacker to either (a) wait for the unlock to actually occur and have their UNSTAKE succeed, or (b) pay the gossip/inclusion cost without making progress on stake — neither of which is amplified.

**Comparison with Ethereum gas burning.** Ethereum's analogue is the gasUsed semantics on a reverting tx: gas is consumed even on revert (the EVM ran instructions before the revert path), and the user pays. Determ's apply-layer refund is more user-favorable because the chain's "this was too early" check is cheap and unambiguous — the apply layer can determine the failure without any EVM-like execution, so refunding the fee costs nothing. The refund is also one-tier-only: it covers the apply-time failure path, not validator-rejected blocks (a too-early UNSTAKE rejected at validate-time per S-017's validator-layer check never enters a block at all, so there is no fee to refund). The two-tier defense (validator rejects upstream, apply refunds downstream) ensures honest users never lose a fee regardless of which producer attempts to include the tx.

The strict-equality nonce gate (FA-Apply-3) and the unlock-height refund (this proof) together encode the two corners of the protocol's "honest misclock is free" UX contract. Both are foundational to operator confidence in submitting transactions without rigorous local-clock or chain-tip synchronization — a meaningful posture for permissioned-consortium deployments where multiple operator endpoints may submit concurrently from different vantage points.

---

## 4. Slashing intersection

STAKE-locked balance is subject to two slashing channels (FA6 + suspension):

1. **Suspension slash** (`chain.cpp:1313–1328`): each Phase-1 abort event baked into the block deducts `SUSPENSION_SLASH` (= 10 by genesis default; `chain.cpp:1324`) from the aborted domain's `stakes_[d].locked`, bounded by available stake.
2. **Equivocation slash** (`chain.cpp:1344–1356`): each `EquivocationEvent` baked into the block zeros the equivocator's `stakes_[d].locked` AND sets `registrants_[d].inactive_from = b.index + 1`.

**Critical claim — slashing is active during the deferred-unlock window.** A domain in the `staked-pending-unlock` state (post-DEREGISTER but pre-UNSTAKE, equivalently `stakes_[d].locked > 0` AND `stakes_[d].unlock_height < UINT64_MAX` AND `b.index < stakes_[d].unlock_height`) is still slashable. The slashing branches at lines 1313–1356 do not consult `stakes_[d].unlock_height` — they consume `locked` unconditionally on the trigger event. This is intentional: the `unstake_delay_` window IS the slashing-evidence window. An operator who DEREGISTERs at height `h` and discovers an equivocation-evidence transaction at height `h + δ` for `δ ∈ [1, unstake_delay_]` can still bake the evidence into a block within the window and slash the operator's stake.

**The pending-unlock domain is also non-eligible for selection.** Once DEREGISTER fires and `registrants_[d].inactive_from < UINT64_MAX`, the domain falls out of the eligible-creator pool at `b.index ≥ inactive_from` (V2 of F0). The domain therefore cannot itself create blocks that contain equivocation evidence about peers (no self-attestation worry), and the chain's validators are responsible for noting the equivocation against the still-staked-but-deregistering domain. The window arithmetic is:

```
deregister_block_height           = h
inactive_from                     = h + δ_reg     where δ_reg ∈ [1, REGISTRATION_DELAY_WINDOW]
unlock_height (slashable until)   = h + δ_reg + unstake_delay_
selection_eligibility (active)    = [registered_at + active_from, inactive_from)
slashable_window                  = [registered_at, unlock_height)
```

The slashable window strictly contains the selection-eligibility window. Said differently: a deregistering domain has a "tail" period — `[inactive_from, unlock_height)` — during which it is no longer selectable for new committees but its stake remains forfeitable for equivocation evidence that surfaces in this window. The genesis-pinned `unstake_delay_` parameter (default 1000 blocks) gives the slashing detector that much time to collect evidence after the operator has stopped participating but before they can recover the locked value.

**Composition with FA6.** `EquivocationSlashing.md` (FA6) covers the apply-correctness of the slashing branches themselves: only equivocators are slashed (no false positives), the slash deduction is bounded by available stake (no negative balances), the apply path is deterministic. The interaction between FA6 and the present proof is that the stake-lifecycle state machine in §1.2 includes a "still-slashable but deregistering" state (`staked-pending-unlock`) that FA6's invariants must continue to hold over. They do — FA6's analysis depends only on the per-block evidence-event invariant + the apply-side I-3 channel (`Δlocked < 0, Δbalance == 0`), neither of which depends on the registry's active/inactive state.

**Suspension intersection.** The suspension slash at `chain.cpp:1313–1328` is gated on Phase-1 abort events for the validator's domain. A deregistering domain that has reached `inactive_from` is no longer in any committee (V2 filter), so no new Phase-1 abort events for it can be created — the suspension channel naturally tapers off after deregistration. The equivocation channel, in contrast, can fire on evidence from any earlier block (the validator gathers evidence from observed gossip with no per-block freshness requirement beyond V11), so a deregistering domain's pre-deregistration equivocation can be punished any time before `unlock_height`. This asymmetry is the intended design: suspension is a real-time mechanism for "behaving badly now," equivocation is an archival mechanism for "behaved badly at some past point in the slashable window."

---

## 5. What this doesn't prove

The theorems above target the STAKE / DEREGISTER / UNSTAKE apply branches in isolation. They do not extend to:

- **Apply correctness of equivocation slashing per se.** T-K3's slashing-intersection note describes the window in which slashing is active; the proof that an equivocation-slash actually achieves "only Byzantine validators are slashed" is the scope of `EquivocationSlashing.md` (FA6). FA6's H2 (honest validators sign at most one digest per (height, round, aborts_gen)) is what guarantees no honest domain is slashed; the present proof's T-K3 inherits that guarantee structurally.
- **EXTENDED-mode sharding edge cases for stake.** A domain registered with `region == X` on shard `S_X` has its stake tracked by `S_X`'s chain, but if shard `S_X` undergoes an R7 under-quorum merge into shard `S_Y`, the refugee-region carry-over rules in `UnderQuorumMerge.md` (FA9) govern how the merged shard's `stakes_` map is reconstructed. The present proof assumes a single-shard or non-merging-shard context; the merge-boundary semantics are FA9's scope.
- **STAKE / UNSTAKE in DOMAIN_INCLUSION mode.** When the chain's `inclusion_model == DOMAIN` (no stake gate on validator eligibility — `min_stake_ == 0`), STAKE and UNSTAKE still work mechanically but are not the gating mechanism for selection. The lifecycle proof above is mode-agnostic — every theorem (T-K1 through T-K7) holds in both STAKE_INCLUSION and DOMAIN_INCLUSION modes — but the economic significance of stake differs. DOMAIN_INCLUSION still uses equivocation slashing to deregister offenders (the `registrants_[d].inactive_from` mutation at `chain.cpp:1354` is independent of stake state), so the "still-slashable in the unlock window" property is meaningful for both modes.
- **Apply-failure rollback semantics for stake state.** The A9 atomic-apply property at `chain.cpp:671–1499` (`AccountStateInvariants.md` §1.2) ensures that any throw inside the apply path (S-007 overflow, A1 violation, S-033 mismatch) rolls back `stakes_` along with `accounts_` and the other maps. The present proof's deltas are stated for **successful applies only**; rollback semantics are inherited from FA-Apply's §1.2 framing, not re-derived here. A regression introducing a path where `stakes_[d]` mutation persists across an apply-time throw would manifest as an FA-Apply I-3 violation (balance/stake leakage), caught by the A1 closure at `chain.cpp:1399`.
- **Wallet-side nonce coordination for stake txs.** The strict-equality nonce gate (NonceMonotonicity.md T-N3) applies to STAKE / DEREGISTER / UNSTAKE as much as to TRANSFER. A wallet that batches a STAKE then an UNSTAKE in the same block must allocate consecutive nonces. The present proof's T-K7 (independent stakes) covers cross-domain isolation; intra-domain nonce sequencing is FA-Apply-3's scope.
- **Snapshot restore preserves stake state.** The `stakes_[d]` (locked, unlock_height) pair is included in the `s:` namespace of the S-033 state-root commitment (`AccountStateInvariants.md` I-3 + `SnapshotEquivalence.md` L-S0). Restore equivalence (T-S1, T-S2 of FA-Apply-2) carries stake state across snapshot boundaries. The present proof's stake-state deltas compose through snapshot restore by T-S2; the lifecycle is replay-equivalent, no re-derivation here.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V15 (transaction apply) + S-017 closure that aligns validator + producer + chain on the unlock-height check. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 (no underflow), I-3 (balance ↔ stake independence), I-5 (channel enumeration), I-6 (A1 closure). The STAKE / UNSTAKE / DEREGISTER branches are three of the I-3 channels (STAKE: balance → locked; UNSTAKE: locked → balance, slashing: locked → ∅). |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S2 apply-after-restore equivalence; `stakes_[d]` (locked, unlock_height) is in the `s:` namespace, restored byte-identically across snapshot boundaries. |
| `NonceMonotonicity.md` (FA-Apply-3) | T-N2 future-nonce silent skip — symmetric UX guarantee to T-K4 fee-refund. Both ensure honest misclocks are penalty-free. |
| `EquivocationSlashing.md` (FA6) | Apply-side equivocation slash; the slash is active during the `staked-pending-unlock` window per §4. FA6's H2 invariant ensures no honest domain is ever slashed. |
| `EconomicSoundness.md` (FA11) | T-12 A1 unitary-balance closure; STAKE / UNSTAKE round-trip is supply-conserving. |
| `Governance.md` (FA10) | A5 PARAM_CHANGE whitelist — `UNSTAKE_DELAY` is on the whitelist, mutable via N-of-N multisig. |
| `docs/SECURITY.md` §S-017 | Producer / validator / chain alignment on the unlock-height check (closed Option 2: validator + producer both gain the gate; apply-time refund retained as belt-and-suspenders). |
| `docs/PROTOCOL.md` §3.3 | Apply rules for STAKE / DEREGISTER / UNSTAKE including the deferred-unlock semantics. |
| `tools/test_stake_accounting.sh` | T-K1 + T-K7 (12 assertions across seven scenarios — STAKE state-machine invariants including A1 conservation; see `determ test-stake-accounting`). |
| `tools/test_unstake_deregister_apply.sh` | T-K3 + T-K4 + T-K5 + T-K6 (~16 assertions across six scenarios — UNSTAKE + DEREGISTER lifecycle including too-early refund, post-unlock success, insufficient locked, defensive non-registrant DEREGISTER; see `determ test-unstake-deregister-apply`). |
| `tools/test_tx_edge_cases.sh` | T-K2 (skip-vs-success boundary; the STAKE balance-underflow case uses the identical gate as the TRANSFER case exercised here). |
| `tools/test_supply_lifecycle.sh` | A1 conservation across the STAKE → UNSTAKE round-trip composed with the rest of the apply surface. |
| `include/determ/chain/chain.hpp:23–30` | `StakeEntry` struct (`locked`, `unlock_height`). |
| `include/determ/chain/chain.hpp:590` | `unstake_delay_` field (instance-state mutable via A5 PARAM_CHANGE). |
| `include/determ/chain/params.hpp:23` | `UNSTAKE_DELAY` build-time default (= 1000 blocks). |
| `include/determ/node/registry.hpp:15` | `REGISTRATION_DELAY_WINDOW` (= 10 blocks; bounds `derive_delay` output). |
| `src/chain/chain.cpp:42–47` | `derive_delay` helper (randomized cooldown derivation). |
| `src/chain/chain.cpp:807–811` | REGISTER's initialization of `stakes_[d].unlock_height = UINT64_MAX`. |
| `src/chain/chain.cpp:839–856` | DEREGISTER apply branch (T-K3). |
| `src/chain/chain.cpp:858–871` | STAKE apply branch (T-K1, T-K2). |
| `src/chain/chain.cpp:873–894` | UNSTAKE apply branch (T-K4, T-K5, T-K6). |
| `src/chain/chain.cpp:1313–1356` | Suspension + equivocation slash branches (FA6 scope; §4 intersection). |
| `src/chain/chain.cpp:1399` | A1 unitary-balance closure assertion. |
| `src/node/validator.cpp:606–614` | S-017 validator-layer unlock-height check (rejects too-early UNSTAKE upstream). |

---

## 7. Status

All seven theorems (T-K1 through T-K7) are closed in the current codebase:

- **T-K1** (STAKE locks balance) closed via the STAKE branch at `chain.cpp:858–871` + I-3 (balance → locked channel) + I-6 A1 closure; regression `test_stake_accounting.sh`.
- **T-K2** (STAKE-on-empty silent skip) closed via the `if (sender.balance < cost) continue;` gate at `chain.cpp:864`; structurally identical to the TRANSFER negative case in `test_tx_edge_cases.sh`.
- **T-K3** (DEREGISTER deferred-unlock) closed via the `inactive_from = height + derive_delay` + `unlock_height = inactive_from + unstake_delay_` writes at `chain.cpp:844 / 851`; regression `test_unstake_deregister_apply.sh` DEREGISTER scenario.
- **T-K4** (UNSTAKE pre-unlock refund) closed via the refund branch at `chain.cpp:884–885` (the load-bearing UX guarantee); regression `test_unstake_deregister_apply.sh` "UNSTAKE too-early" + "UNSTAKE insufficient locked".
- **T-K5** (UNSTAKE post-unlock success) closed via the success path at `chain.cpp:889–893` + A1 closure; regression `test_unstake_deregister_apply.sh` "UNSTAKE success after unlock".
- **T-K6** (pre-DEREGISTER UNSTAKE silent skip) closed via the `UINT64_MAX` sentinel default at `StakeEntry` initialization + the unified unlock-height gate at `chain.cpp:881`; regression `test_unstake_deregister_apply.sh` "UNSTAKE too-early" (covers the sentinel case).
- **T-K7** (independent stakes) closed via per-`tx.from` keying of every map access in the three branches + `std::map` per-key isolation; regression `test_stake_accounting.sh` multi-domain trace.

No theorem is open or partial. The S-017 closure (Option 2 — validator + producer both gained the unlock-height check, apply-time refund retained as belt-and-suspenders) is the structural alignment that makes T-K4 a tertiary defense rather than a primary one — honest users see the validator rejection upstream and never have to rely on the apply-time refund, but the refund branch defends against any path that slips past the validator (e.g., snapshot replay of a pre-S-017 block, or a buggy peer that produced a block bypassing its own validator). The two-tier defense is the SECURITY.md §S-017 "no behavioral regression" guarantee.

The proof's foundation rests on a small set of code primitives: the `charge_fee` lambda, the `derive_delay` helper, the `UINT64_MAX` sentinel on `StakeEntry.unlock_height`, and the strict-equality nonce gate from FA-Apply-3. The breadth of consequences — seven theorems, a fully-pinned three-state machine, a fee-refund UX contract, and a documented slashing-window intersection — is testimony to how few primitives the chain actually needs to express the lifecycle.
