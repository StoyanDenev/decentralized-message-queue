# FA-Apply — AccountState invariants

This document consolidates the per-account invariants that Determ's apply layer (`Chain::apply_transactions` in `src/chain/chain.cpp`) preserves across every finalized block. The `AccountState` struct is the smallest unit of mutable user-visible state; every value-bearing transaction type mutates it through a small set of well-defined channels. The properties below are the invariants those channels collectively maintain.

The proofs are mechanical: each invariant is established by inspection of the apply path's explicit guards, and each is defended by at least one regression test under `tools/test_*.sh`. The strength of this document is not novel cryptographic argument — it is consolidation. The invariants are scattered across the apply path's TRANSFER / STAKE / UNSTAKE / REGISTER / DEREGISTER / DAPP_CALL / inbound-receipt / equivocation / suspension / subsidy branches; this proof gathers them into one place so a reviewer can audit a single document rather than reconstruct the invariant set from the code.

**Companion documents:** `Preliminaries.md` (F0) for notation, assumptions A1–A2, validator predicate V1–V15; `Safety.md` (FA1) for the higher-level fork-freedom property that consumes these invariants via V15; `EquivocationSlashing.md` (FA6) for the apply-side slash that decreases stake (and the corresponding I-3 independence claim); `CrossShardReceipts.md` (FA7) for the cross-shard credit channel that I-4 and I-5 cover; `EconomicSoundness.md` (FA11) for the A1 unitary-balance composition (I-6) that these per-account invariants sum into.

---

## 1. Setup

### 1.1 The `AccountState` struct

```cpp
struct AccountState {
    uint64_t balance{0};
    uint64_t next_nonce{0};
};
```

Defined at `include/determ/chain/chain.hpp` (lines 18–21). The struct is value-only: it does NOT carry an `ed_pub` field. Per-domain signing key material lives in the sibling `RegistryEntry` struct (`include/determ/chain/chain.hpp` lines 32–44) under `registrants_[domain].ed_pub`. Registry membership and account balance are independent state — a domain can have a non-zero balance with no registry entry (any TRANSFER recipient), and a domain can be registered with a zero balance (the common state after a fresh REGISTER pays its fee from a small starting balance, then sits idle). Sender authentication on transactions uses the ed25519 signature over the transaction hash, verified against the resolved `ed_pub` from the registry (anon addresses use a key derived from the address itself, falling outside the AccountState scope).

Per-domain stake lives in another sibling struct, `StakeEntry` (lines 23–30):

```cpp
struct StakeEntry {
    uint64_t locked{0};
    uint64_t unlock_height{UINT64_MAX};
};
```

`accounts_` (declared at `include/determ/chain/chain.hpp:540`) is `std::map<std::string, AccountState>`. Map iteration order is deterministic (sorted by key string), which is consumed by the S-033 state-root computation (`Chain::compute_state_root`, see PROTOCOL.md §4.1.1 namespace `a:`).

### 1.2 Per-block apply hook

Every chain mutation lands in one of two functions:

- `Chain::apply_transactions(const Block& b)` (`src/chain/chain.cpp:633`) — the per-block apply path. All `AccountState` mutations covered here happen inside this function.
- `Chain::atomic_scope` (`src/chain/chain.cpp:519`) — a per-fn atomic-scope wrapper used by the COMPOSABLE_BATCH branch. State changes inside `atomic_scope` are either all committed or all rolled back via `restore_state_snapshot`.

`apply_transactions` is wrapped at line 671–1501 in `try { ... } catch (...) { restore_state_snapshot(...); throw; }`. Any exception thrown from the apply body (including S-007 overflow throws, unitary-balance violations, and S-033 state-root mismatches) leaves the chain in its pre-apply state. This is the A9 atomic-apply property; the invariants below are stated about successfully-applied blocks, which equivalently means "blocks for which the apply path did not throw."

### 1.3 Per-block invariants H_n

Let `state_n` denote the chain state after the n-th block has been applied (so `state_0` is the post-genesis state). The invariants below are stated as predicates over `state_n` for every `n ≥ 0`. Each I-X is a property that holds for every `n` such that `apply_transactions(B_n)` returned successfully.

---

## 2. Invariants

### I-1 — Non-negative balance (no apply-path underflow)

**Motivation.** `AccountState.balance` is stored as `uint64_t`. C++ unsigned arithmetic wraps on underflow rather than producing a negative value, so a literal "non-negative" check is trivially satisfied by the storage type. The substantive form of the invariant is therefore that no apply path takes a debit from an account whose balance is less than the debit amount — wrapping is prevented by explicit pre-debit checks, not by the storage type.

**Formal statement.** For every account `a` in `state_n.accounts_` and every successful apply of `B_{n+1}`, all debits from `a.balance` are gated by a strict precondition `balance ≥ debit` evaluated before the subtraction. The four debit channels are:

1. **TRANSFER source** (`chain.cpp:743–745`): `if (sender.balance < cost) continue;` then `sender.balance -= cost;` where `cost = tx.amount + tx.fee`.
2. **STAKE** (`chain.cpp:863–865`): `if (sender.balance < cost) continue;` then `sender.balance -= cost;`.
3. **DAPP_CALL** (`chain.cpp:1212–1214`): `if (sender.balance < cost) continue;` then `sender.balance -= cost;`.
4. **charge_fee lambda** (`chain.cpp:727–732`), shared by REGISTER / DEREGISTER / UNSTAKE / PARAM_CHANGE / MERGE_EVENT / DAPP_REGISTER fee paths: `if (acct.balance < fee) return false;` then `acct.balance -= fee; return true;`. The caller skips the rest of the tx body if `charge_fee` returns false.

The COMPOSABLE_BATCH inner-TRANSFER path uses the same balance check (`chain.cpp:1002`: `if (isender.balance < inner.amount) return false;`), but its failure path triggers the surrounding `atomic_scope` to roll back any inner debits already applied.

Credits are guarded against u64 wrap by the static helper `checked_add_u64` (`chain.cpp:33`), which returns `false` on overflow. Every credit path that uses it either throws an S-007 diagnostic (TRANSFER recipient at line 757, DAPP_CALL recipient at line 1216, inbound receipt at line 1368, per-creator subsidy/fee distribution at lines 1292 and 1300, per-block inbound sum at line 1377) or returns from the COMPOSABLE_BATCH inner fn to trigger rollback (line 1006). The S-007 throws are caught by the outer try/catch and trigger `restore_state_snapshot`, leaving `accounts_` exactly as it was at apply entry.

**Test surface.** `tools/test_overflow_paths.sh` exercises the S-007 overflow throws on TRANSFER recipient, DAPP_CALL recipient, inbound receipt, and subsidy distribution paths, asserting that the chain rolls back rather than wraps. `tools/test_tx_edge_cases.sh` exercises the skip-vs-success boundary: a tx whose amount+fee exactly equals `sender.balance` succeeds; a tx whose amount+fee exceeds it by one is silently skipped (the nonce does NOT bump, per I-2). Both tests defend the invariant against the most common regression class — an unguarded subtraction on a u64 producing a near-`UINT64_MAX` value.

### I-2 — Nonce monotonicity (replay defense)

**Motivation.** Replay defense requires that a successfully-applied transaction with `(from, nonce)` can never be applied again on the same chain. Determ enforces this by requiring the transaction's nonce to exactly equal the sender's current `next_nonce`, and by bumping `next_nonce` by exactly one only for transactions that pass their type-specific spend-attempt gate. The "exactly equal" rule (strict equality, not `≥`) prevents nonce-skipping attacks where an attacker queues high-nonce transactions to leapfrog future state.

**Formal statement.** For every account `a` and every pair of consecutive successful applies `state_n → state_{n+1}`:

1. **(Monotone.)** `state_{n+1}.accounts_[a].next_nonce ≥ state_n.accounts_[a].next_nonce`.
2. **(Strict-equality gate.)** Any transaction `tx` with `tx.from == a` included in `B_{n+1}` is evaluated against `if (tx.nonce != sender.next_nonce) continue;` at `chain.cpp:739` before any state mutation. A tx whose nonce does not match is silently skipped, including no nonce bump.
3. **(At most +1 per applied tx.)** Each transaction that passes the spend-attempt gate executes exactly one `sender.next_nonce++` on its success path. The TRANSFER path bumps at line 768; STAKE at line 869; UNSTAKE at line 892 (both on the success path and on the early-return refund path at line 886, since the validator can't always pre-check `unlock_height`); REGISTER at line 835; DEREGISTER at line 854 (and at line 842 if there is no registrant); PARAM_CHANGE at line 926; COMPOSABLE_BATCH at line 957 (outer; inner-tx nonces bump at line 1010 only on the all-or-nothing inner success); MERGE_EVENT at line 1037; DAPP_REGISTER at line 1051; DAPP_CALL at lines 1138 / 1144 / 1153 / 1160 / 1173 / 1184 / 1193 / 1198 / 1207 / 1222 (every branch that consumed the fee bumps the nonce).
4. **(Insufficient-balance does NOT bump.)** TRANSFER / STAKE / DAPP_CALL with `sender.balance < cost` execute `continue;` without bumping the nonce (lines 744 / 864 / 1213). The validator should have rejected these txs upstream; the apply-path no-op is a safety net for blocks containing such txs.

**Test surface.** `tools/test_tx_replay_protection.sh` constructs two successive blocks each containing a TRANSFER from the same `(from, nonce)`; the first applies and bumps nonce, the second's tx is silently skipped (nonce mismatch), and the recipient's balance reflects exactly one credit. `tools/test_tx_edge_cases.sh` exercises the insufficient-balance branch and asserts no nonce bump in that case. Together they pin both halves of the invariant: matched-nonce txs that pass the spend gate advance state; everything else is a no-op.

### I-3 — Balance / stake independence

**Motivation.** A single domain has both a fluid `balance` (transactions, fees, subsidy receipts) and a separately-tracked `stake.locked` (staking commitment with delay-gated withdrawal). Conflating the two would let a STAKE transaction silently underflow `balance` while increasing `locked`, or let UNSTAKE credit `balance` without decrementing `locked`. The independence claim is that the two counters are isolated except through explicit transfer channels.

**Formal statement.** For every domain `d` and every successful apply `state_n → state_{n+1}`:

1. **(Disjoint storage.)** `state.accounts_[d].balance` and `state.stakes_[d].locked` live in separate maps (`accounts_` and `stakes_`); no apply path reads from one map and writes to the other except via the explicit channels in (2)–(4).
2. **(STAKE channel: balance → locked.)** STAKE transactions (`chain.cpp:858–871`) read `amount` from the 8-byte payload, decrement `sender.balance` by `amount + fee`, then increment `stakes_[tx.from].locked` by exactly `amount`. The fee is added to `total_fees` and distributed to creators at block-tail (it does not enter stake).
3. **(UNSTAKE channel: locked → balance, post-unlock.)** UNSTAKE transactions (`chain.cpp:873–894`) require `height ≥ stakes_[tx.from].unlock_height` AND `locked ≥ amount`. On success, `sit->second.locked -= amount; sender.balance += amount;`. On failure (early UNSTAKE or insufficient lock), the fee is refunded (`sender.balance += tx.fee; total_fees -= tx.fee;`) and the nonce still bumps. The unlock-height gate prevents the channel from running during the active-registration window.
4. **(Slashing channel: locked → ∅, no balance change.)** Two apply-path branches decrease `stakes_[d].locked` without touching `accounts_[d].balance`:
   - Suspension slash for Phase-1 abort events (`chain.cpp:1313–1328`): `deduct = min(suspension_slash_, sit->second.locked); sit->second.locked -= deduct;`.
   - Full equivocation slash (`chain.cpp:1344–1356`): `sit->second.locked = 0;` plus `rit->second.inactive_from = b.index + 1;`.
   Both branches add the deducted amount to the per-block `block_slashed` counter, which feeds into the A1 invariant (I-6). Neither writes to `accounts_[d].balance`. The slashed value leaves the live supply for the purpose of A1.

**Test surface.** `tools/test_stake_accounting.sh` exercises STAKE / UNSTAKE state transitions including the unlock-height gate and the fee-refund path on early UNSTAKE. `tools/test_equivocation_slashing.sh` confirms that equivocation zeros `stakes_[equivocator].locked` without affecting `accounts_[equivocator].balance`. The A1 invariant (I-6) provides a second-order check: if any apply path leaked between balance and stake without crediting `block_slashed` or `block_outbound`, the unitary-balance check would throw at apply tail.

### I-4 — Account auto-creation paths

**Motivation.** `accounts_` is a `std::map`; `accounts_[k]` auto-creates a default-constructed `AccountState` (balance=0, nonce=0) on first reference. This is a powerful footgun: any apply path that reads `accounts_[domain]` for a domain that doesn't yet exist creates an entry, which contributes to the S-033 state-root commitment regardless of whether it carries any meaningful value. The invariant pins down the legitimate auto-creation paths and excludes accidental ones.

**Formal statement.** An `accounts_` map entry for domain `d` is created at the FIRST successful apply that satisfies any of:

1. **(TRANSFER credit-on-receipt.)** `chain.cpp:756` — `auto& rcv = accounts_[tx.to].balance;` creates an entry for `tx.to` if it doesn't exist, then `checked_add_u64(rcv, tx.amount, &rcv)` credits it. Same-shard TRANSFER only; cross-shard TRANSFER does not credit on the source side (the receipt-side credit creates the entry on the destination shard).
2. **(Inbound cross-shard receipt.)** `chain.cpp:1367` — `auto& rcv = accounts_[r.to].balance;` creates an entry for `r.to`, then `checked_add_u64(rcv, r.amount, &rcv)` credits it.
3. **(Sender reference.)** `chain.cpp:735` — `AccountState& sender = accounts_[tx.from];` creates an entry for `tx.from` if it doesn't exist. This path is normally a no-op when the sender has no balance: the strict-nonce gate at line 739 rejects (continue) before any mutation, leaving the freshly-created zero-balance/zero-nonce entry in `accounts_`. The validator's V15 + ed25519 signature check filter out senders without ed25519-key authority earlier; the apply-time creation is a defensive consequence of `operator[]`.
4. **(NEF distribution.)** `chain.cpp:830` — `accounts_[tx.from].balance += nef;` creates an entry for the new registrant if the REGISTER fee already pre-created one (which it does via the `sender` reference at line 735); this is therefore redundant with (3) for registrants and exists for the credit semantics.
5. **(Per-creator subsidy + fee distribution.)** `chain.cpp:1291` — `auto& bal = accounts_[domain].balance;` for each `domain` in `b.creators`. Creators must be registered (V2) and therefore have already been auto-created at REGISTER time (their REGISTER tx referenced `sender` at line 735), so this is a lookup not a creation in steady state. The path is safe even if a creator's accounts entry was somehow removed: the auto-create yields a zero-balance entry and the credit proceeds normally.
6. **(DAPP_CALL credit.)** `chain.cpp:1215` — `auto& rcv = accounts_[tx.to].balance;`, analogous to TRANSFER credit.

DEREGISTER (`chain.cpp:839–856`) does NOT auto-create an `accounts_` entry beyond the sender reference at line 735; the `find` at line 841 is in `registrants_`, not `accounts_`. A DEREGISTER from a non-registrant nonetheless bumps `sender.next_nonce` (line 842), and the sender reference auto-creates an account entry in `accounts_` if none existed. This is the observed "defensive design" behavior tested in `tools/test_account_create_on_credit.sh`.

**Test surface.** `tools/test_account_create_on_credit.sh` is the canonical defense. It exercises five scenarios across 11 assertions: TRANSFER to a non-existent domain creates an entry with `balance = amount`; inbound cross-shard receipt to a non-existent domain creates an entry; DEREGISTER from a non-registrant bumps nonce without creating a registry entry; stacked credit (receipt + TRANSFER to the same fresh domain in the same block) sums correctly; and determinism — the same auto-creation sequence produces a byte-identical state_root and identical `accounts_` size. The determinism assertion catches any non-deterministic auto-creation path (e.g., one keyed off iteration order of an unsorted container) that would silently fork the state_root.

### I-5 — Balance arithmetic (exhaustive channel enumeration)

**Motivation.** I-1 covers the no-underflow / no-overflow side. I-5 is the structural form: every change to any account's balance is attributable to exactly one of a small set of channels, and no apply path produces spontaneous balance changes outside those channels. This is the property an external auditor needs to track value flow end-to-end without enumerating every line of `apply_transactions`.

**Formal statement.** For every domain `d` and every successful apply `state_n → state_{n+1}`, the delta `state_{n+1}.accounts_[d].balance − state_n.accounts_[d].balance` decomposes into a sum of contributions from exactly the following channels (each direction signed):

**Debit channels (balance decreases):**

| Channel | Apply site | Magnitude per event |
|---|---|---|
| TRANSFER source (same-shard or cross-shard) | `chain.cpp:745` | `tx.amount + tx.fee` |
| STAKE lock | `chain.cpp:865` | `payload.amount + tx.fee` |
| DAPP_CALL source | `chain.cpp:1214` | `tx.amount + tx.fee` |
| COMPOSABLE_BATCH inner TRANSFER source | `chain.cpp:1004` | `inner.amount` (outer fee charged separately) |
| Fee-only debit (REGISTER / DEREGISTER / UNSTAKE / PARAM_CHANGE / MERGE_EVENT / DAPP_REGISTER) | `charge_fee` at `chain.cpp:729` | `tx.fee` |
| NEF source (Zeroth pool) | `chain.cpp:829` | `pool_balance / 2` |
| UNSTAKE fee refund (negation of the immediately-prior fee debit, on early-unstake failure) | `chain.cpp:884` | `+tx.fee` (this is a credit) |

**Credit channels (balance increases):**

| Channel | Apply site | Magnitude per event |
|---|---|---|
| TRANSFER same-shard credit | `chain.cpp:757` | `tx.amount` |
| DAPP_CALL same-shard credit | `chain.cpp:1216` | `tx.amount` |
| COMPOSABLE_BATCH inner TRANSFER credit | `chain.cpp:1006` | `inner.amount` |
| UNSTAKE post-unlock credit | `chain.cpp:891` | `tx.payload.amount` |
| Inbound cross-shard receipt | `chain.cpp:1368` | `r.amount` |
| Subsidy + fee distribution to creator | `chain.cpp:1292` | `total_distributed / |creators|` |
| Subsidy + fee dust to creator[0] | `chain.cpp:1300` | `total_distributed mod |creators|` |
| NEF destination (first-time REGISTER) | `chain.cpp:830` | `pool_balance / 2` |

There are NO other apply-path writes to `accounts_[d].balance`. Genesis (line 689) writes initial balances at index-0 apply; it is not a delta over a prior state since there is no prior state — it bootstraps `state_0`. The two A1 counters `accumulated_subsidy_` (line 1391) and `accumulated_inbound_` / `accumulated_outbound_` / `accumulated_slashed_` (lines 1393–1395) are running-sum aggregators, not balance writes.

**Test surface.** `tools/test_supply_invariant.sh`, `tools/test_supply_lifecycle.sh`, and `tools/test_fee_distribution_edge.sh` collectively traverse the listed channels under varied block compositions (TRANSFER-only, STAKE+UNSTAKE, NEF on first REGISTER, lottery subsidy, finite-pool exhaustion). Each test asserts the A1 unitary-balance closing equality at block tail, which would diverge if any channel produced a balance change not captured in the per-block deltas `total_fees + subsidy_this_block + block_inbound − block_outbound − block_slashed`. The structural property is therefore checked indirectly via the A1 invariant — if a hypothetical phantom credit channel were introduced, A1 would throw at apply tail.

### I-6 — A1 unitary-balance contribution

**Motivation.** The per-account invariants I-1 through I-5 are the inputs to the chain-level unitary-balance invariant proved in `EconomicSoundness.md` (T-12). I-6 is the statement that the per-account view sums correctly into the chain-level view — the connecting bridge between this proof's per-account scope and FA11's chain-wide scope.

**Formal statement.** After every successful apply of `B_{n+1}`:

```
Σ_{d ∈ accounts_} state_{n+1}.accounts_[d].balance
    + Σ_{d ∈ stakes_} state_{n+1}.stakes_[d].locked
== state_n.genesis_total_
   + state_{n+1}.accumulated_subsidy_
   + state_{n+1}.accumulated_inbound_
   − state_{n+1}.accumulated_slashed_
   − state_{n+1}.accumulated_outbound_
```

The left-hand side is computed by `Chain::live_total_supply()` (`chain.cpp:548`). The right-hand side is `Chain::expected_total()`. The equality is asserted at `chain.cpp:1397–1419`; a mismatch throws a "unitary-balance invariant violated" diagnostic with the per-counter breakdown, which is caught by the outer try/catch and rolls the apply back via `restore_state_snapshot`.

This invariant is the chain-level companion of the per-account view. The full proof is in `EconomicSoundness.md` T-12 (and T-13 for the NEF supply-neutrality subclaim, and T-14 for the E3 / E4 expected-value preservation under lottery + finite pool). The relevance to AccountState is structural: every channel listed in I-5 contributes to exactly one of the five right-hand-side terms, and the equality at apply-tail confirms the per-account deltas closed correctly.

**Test surface.** `tools/test_supply_lifecycle.sh` walks the chain through TRANSFER, STAKE, UNSTAKE, REGISTER (with and without NEF), DEREGISTER, equivocation slash, suspension slash, lottery subsidy, finite-pool exhaustion, and cross-shard inbound/outbound, asserting the A1 closing equality after each block. `tools/test_supply_invariant.sh` exercises the assertion directly with synthetic per-counter deltas. `tools/operator_supply_check.sh` is the operator-facing tool that re-runs the A1 check from snapshot data — useful for offline audit of a downloaded chain.

---

## 3. Theorems

The invariants in §2 are stated as predicates over `state_n`. The corresponding theorems state that those predicates hold for every `n ≥ 0` under the assumptions A1–A2 (Preliminaries §2) plus the validator-V1-through-V15 predicate (Preliminaries §5). The proofs are by induction on block height; the base case is genesis (where each I-X holds trivially), and the inductive step is the per-tx case analysis already enumerated in §2.

**Theorem T-A1 (Non-negative balance / no apply-path underflow).** Under A1 + A2 + V1–V15, for every domain `d` and every height `n ≥ 0`, `state_n.accounts_[d].balance` does not undergo an unguarded subtraction. Formally: at every site in `apply_transactions` where `balance` is decremented, the decrement is preceded by a strict precondition `balance ≥ debit` evaluated in the same call frame, and any path that would violate this precondition takes a `continue` / `return false` / `false` branch instead.

*Proof.* By inspection of the four debit channels enumerated in I-1, each guarded as cited. The `checked_add_u64` helper handles the credit-side wrap. The outer try/catch + `restore_state_snapshot` ensures that any apply-time throw (from S-007 overflow, A1 violation, or S-033 mismatch) leaves `accounts_` exactly as it was at apply entry. ∎

**Theorem T-A2 (Nonce monotonicity).** Under V15, for every domain `d`, `state_{n+1}.accounts_[d].next_nonce ≥ state_n.accounts_[d].next_nonce`, with strict increment by exactly one per successfully-applied transaction with `tx.from == d`.

*Proof.* The only apply-path writes to `next_nonce` are the `sender.next_nonce++` lines enumerated in I-2 (3). No path decrements `next_nonce`. The strict-equality gate at line 739 ensures each successful tx contributes exactly one increment; the insufficient-balance early-return paths skip the increment. ∎

**Theorem T-A3 (Balance / stake independence).** Under V15, no apply path produces a non-zero `Δaccounts_[d].balance` and a non-zero `Δstakes_[d].locked` in the same atomic step except via the three explicit transfer channels enumerated in I-3 (STAKE: balance → locked; UNSTAKE: locked → balance; slashing: locked → ∅).

*Proof.* By inspection of all apply-path branches in `apply_transactions`. The STAKE, UNSTAKE, suspension, and equivocation branches are the only ones that read or write `stakes_`; each follows the I-3 channel pattern. ∎

**Theorem T-A4 (Auto-creation enumeration).** For every domain `d`, an entry `accounts_[d]` is created exactly when one of the six channels in I-4 fires.

*Proof.* By inspection of every `accounts_[...]` reference in `apply_transactions`. Each is either a read (no entry creation in `std::map` if the key is missing — `accounts_.find(...)` is used in those cases), or it is one of the listed `accounts_[d]` / `accounts_[d].balance` / `accounts_[d].next_nonce` writes that auto-create on first reference. The enumeration in I-4 is the union of these write sites. ∎

**Theorem T-A5 (Exhaustive balance-channel decomposition).** Every `Δaccounts_[d].balance` across a successful apply is the sum of contributions from exactly the eight credit channels and seven debit channels in I-5 (a UNSTAKE fee refund counts as a negation of the immediately-prior fee debit).

*Proof.* By inspection of every `accounts_[...].balance` write in `apply_transactions`. The §2 I-5 tables enumerate them; no other site writes to `.balance`. ∎

**Theorem T-A6 (A1 contribution).** The per-account state at `state_n` sums (across all `accounts_` keys plus all `stakes_` keys) to `expected_total(state_n)`.

*Proof.* See `EconomicSoundness.md` T-12, which establishes the chain-level invariant by induction on block height. The per-account I-5 decomposition is the inductive step's enumeration of balance deltas; the per-stake decomposition is the I-3 channel enumeration. The five running counters absorb the corresponding deltas (`accumulated_subsidy_` accepts the per-block subsidy debit from the implicit mint; `accumulated_inbound_` / `accumulated_outbound_` accept the cross-shard credits / debits; `accumulated_slashed_` accepts the suspension + equivocation slash; `genesis_total_` is the index-0 anchor). Apply-tail assertion at `chain.cpp:1399` would throw if the per-account deltas failed to close. ∎

---

## 4. Failure-mode handling

If any apply-path branch were to violate one of I-1 through I-6, the consequence is well-defined:

- **I-1 violation (debit underflow).** A u64 wrap would produce a near-`UINT64_MAX` balance. Subsequent A1 evaluation at apply tail would detect a `live_total_supply > expected_total` by approximately `2^64 - debit`. The throw at line 1418 would trigger `restore_state_snapshot` and reject the block. The S-033 state-root re-derivation at line 1430 would also detect the corruption locally (the producer's tentative-chain dry-run would produce a state_root incompatible with any other honest node's apply).
- **I-2 violation (replay).** The strict-equality nonce gate at line 739 would fail. The apply-side branch is `continue` (silent skip), so a replay attempt produces no state change. The validator V15's transaction-apply check would have rejected the block earlier if the block's overall apply produced an invalid state, but a pure replay tx is silently ignored at apply-time.
- **I-3 violation (balance ↔ stake leakage).** No legitimate apply path can produce this; a regression introducing it would manifest as an A1 mismatch (the leaked value is unaccounted for in any per-block counter). The throw at line 1418 would catch it.
- **I-4 violation (silent auto-creation).** A regression introducing an unguarded `accounts_[key]` access on an unintended path would create a phantom zero-balance entry that contributes to the S-033 state_root. On the producer's apply this is benign (the entry is empty); on a receiving node applying the same block from a different code revision, the produced state_root would diverge. The S-033 gate at line 1430 would detect this on the validator side, reject the block, and roll back via the catch path at line 1499.
- **I-5 violation (phantom balance channel).** A regression introducing a balance change not captured in the per-block deltas would produce an A1 mismatch at line 1399. Same throw-and-rollback path as I-1 and I-3.
- **I-6 violation (A1 mismatch directly).** Already the failure path for I-1 / I-3 / I-5. The chain explicitly rejects the block; no partial state survives.

In every failure mode, the A9 atomic-apply guarantee (try/catch at lines 671 / 1489) ensures that observers see either the full block applied or no change at all. There is no partial-apply state that could leak to peers via gossip — the producer's try_finalize_round + tentative-chain dry-run (`Node::try_finalize_round`, per the S-038 closure noted in PROTOCOL.md §5.1) catches I-1 / I-3 / I-4 / I-5 / I-6 violations on the local node before the block is broadcast.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Safety.md` (FA1) | Higher-level fork-freedom property; V15 (transaction apply) consumes the invariants here as one of its preconditions. |
| `EquivocationSlashing.md` (FA6) | Apply-side stake slash; the slash path is one of the legitimate "decrease `stakes_[d].locked` without changing `accounts_[d].balance`" channels in I-3. |
| `CrossShardReceipts.md` (FA7) | Cross-shard inbound credit; the I-4 auto-creation path (2) and the I-5 inbound credit channel. |
| `EconomicSoundness.md` (FA11) | A1 unitary-balance invariant; I-6 is the bridge between per-account decomposition and chain-wide closure. |
| `tools/test_account_create_on_credit.sh` | I-4 defense across 11 assertions. |
| `tools/test_tx_replay_protection.sh` | I-2 defense. |
| `tools/test_overflow_paths.sh` | I-1 defense (S-007 throws). |
| `tools/test_tx_edge_cases.sh` | I-1 + I-2 defenses (skip-vs-success boundary, insufficient-balance no-nonce-bump). |
| `tools/test_stake_accounting.sh` | I-3 defense (STAKE / UNSTAKE / unlock_height gate). |
| `tools/test_equivocation_slashing.sh` | I-3 defense (slash path leaves balance untouched). |
| `tools/test_supply_lifecycle.sh` | I-5 + I-6 defense (channel enumeration via end-to-end A1 closure). |
| `tools/test_supply_invariant.sh` | I-6 defense (direct A1 assertion). |
| `tools/operator_supply_check.sh` | Operator-facing offline A1 audit tool. |
| `include/determ/chain/chain.hpp` (lines 18–21) | `AccountState` struct declaration. |
| `include/determ/chain/chain.hpp` (lines 23–30) | `StakeEntry` struct declaration. |
| `include/determ/chain/chain.hpp` (lines 32–44) | `RegistryEntry` struct declaration (ed_pub lives here, not on `AccountState`). |
| `src/chain/chain.cpp` (lines 633–1502) | `Chain::apply_transactions`; every apply-path mutation. |
| `src/chain/chain.cpp` (line 33) | `checked_add_u64` helper (S-007). |
| `src/chain/chain.cpp` (line 519) | `Chain::atomic_scope` (COMPOSABLE_BATCH wrapper). |
| `src/chain/chain.cpp` (lines 1397–1419) | A1 unitary-balance assertion + rollback throw. |

---

## 6. Status

All six invariants (I-1 through I-6) are closed in the current codebase:

- **I-1** closed via S-007 `checked_add_u64` + explicit pre-debit balance checks at every debit channel.
- **I-2** closed via the strict-equality nonce gate at `chain.cpp:739` + the `sender.next_nonce++` lines on every successful tx-type branch.
- **I-3** closed via separate-map storage (`accounts_` vs `stakes_`) + explicit STAKE / UNSTAKE / slash transfer channels.
- **I-4** closed via the six legitimate auto-creation paths in §2 I-4 + regression test `test_account_create_on_credit.sh`.
- **I-5** closed via the exhaustive channel enumeration in §2 I-5 + the A1 invariant as second-order check.
- **I-6** closed via `EconomicSoundness.md` T-12 (chain-level) + the per-account decomposition here.

The invariant set is also defended by the S-033 + S-038 state-root verification gate at `chain.cpp:1430`, which independently catches any regression that produces a state diverging from another honest node's apply. The producer's tentative-chain dry-run in `Node::try_finalize_round` (PROTOCOL.md §5.1, S-038 closure) catches every I-X violation locally before block broadcast, narrowing the inter-node state-divergence window to zero blocks (the prior per-block recovery via prev_hash is now structurally unnecessary for these invariants).

No invariant in §2 is open or partial; no follow-on closure work is tracked.
