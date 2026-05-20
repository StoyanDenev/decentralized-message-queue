# FA-Apply — Nonce monotonicity and tx-replay defense

This document formalizes Determ's per-account replay-protection property: the rule that `apply_transactions` advances `account.next_nonce` only if the candidate transaction's nonce matches the account's expected next nonce in **strict equality** (not `≥`, not `>`), which yields per-account tx-once semantics that defeat both stale-tx replay (`tx.nonce < expected`) and future-nonce skip-ahead attacks (`tx.nonce > expected`) without breaking honest in-order delivery. The companion FA-Apply proof `AccountStateInvariants.md` invariant I-2 states the property in a single paragraph; the present proof expands it into six theorems and pins the strict-equality choice against the most common regression class (drift to `≥`) and against unintentional gap-filling semantics imported from other chains.

The proof is mechanical: the entire defense reduces to a single line at `src/chain/chain.cpp:739` — `if (tx.nonce != sender.next_nonce) continue;` — plus the per-tx-type `sender.next_nonce++` lines that execute only on the success path of each tx-type branch. Each theorem below cites the relevant code line, the corresponding regression test, and the failure-mode classification (silent skip vs throw vs rollback). The strength is consolidation: the property is implicit in every replay-related discussion in `docs/SECURITY.md`, but no single document collects the theorem statements, proofs, and witness pointers.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and `compute_hash` / `signing_bytes` definitions; `AccountStateInvariants.md` (FA-Apply) for the per-account invariants I-1 through I-6 that the apply path preserves and where I-2 names the nonce-monotonicity property without enumerating its sub-claims; `SnapshotEquivalence.md` (FA-Apply-2) for the snapshot ↔ replay equivalence that inherits nonce monotonicity from the per-account `next_nonce` field included in the `a:` state-root namespace; `EquivocationSlashing.md` (FA6) for a different replay-defense category (consensus-layer signed-message replay, distinct from per-account tx replay covered here); `CrossShardReceipts.md` (FA7) for the cross-shard at-most-once credit property (the `applied_inbound_receipts_` dedup set), which is the receipt-side analog of nonce-gated tx replay on the source side.

---

## 1. Setup

### 1.1 The nonce field

Per `include/determ/chain/chain.hpp:18–21`:

```cpp
struct AccountState {
    uint64_t balance{0};
    uint64_t next_nonce{0};
};
```

`next_nonce` is the per-account counter of "the nonce value the next successful tx from this account must carry." Default construction sets it to zero — the value a brand-new account auto-created by either an inbound TRANSFER credit (`chain.cpp:756`) or a sender reference (`chain.cpp:735`) starts with. Genesis bootstrap at `chain.cpp:689` writes only the initial balance (`accounts_[a.domain].balance = a.balance;`) and relies on the default `next_nonce = 0` — the comment on line 690 is explicit: `// accounts_[a.domain].next_nonce = 0  (default)`. There is no apply-path branch that initializes `next_nonce` to any value other than zero, so every account in `accounts_` carries `next_nonce` starting from zero and advancing only via the `sender.next_nonce++` lines enumerated in §1.3.

### 1.2 The strict-equality gate

`Chain::apply_transactions` iterates over `b.transactions` in canonical order. For every tx, the very first action after resolving `sender` is the nonce gate at `chain.cpp:739`:

```cpp
for (auto& tx : b.transactions) {
    AccountState& sender = accounts_[tx.from];

    // Sequential nonce: skip txs that don't match. Validator should have
    // rejected them; this is a safety net during apply.
    if (tx.nonce != sender.next_nonce) continue;

    switch (tx.type) { /* per-tx-type branches */ }
}
```

The `!=` operator is strict equality. A tx whose nonce is `sender.next_nonce - 1` (stale, replay attempt), `sender.next_nonce + 1` (future, gap), or any other non-matching value falls through to `continue` — no state change, no balance debit, no fee deduction, no nonce bump. The comment on line 737–738 names this an apply-time safety net; the validator's primary nonce check fires at `src/node/validator.cpp:569–572` (V15 contribution: `if (tx.nonce != n) return {false, "nonce mismatch..."};`) and rejects the entire block on any nonce mismatch. The apply-time gate is the second line of defense — necessary because the validator pass is bypassed on snapshot restore and on already-finalized blocks loaded from chain.json.

### 1.3 The success-path nonce bump

`sender.next_nonce++` fires exactly once per tx that passes both its nonce gate (§1.2) and its per-type spend gate (insufficient-balance branches in TRANSFER / STAKE / DAPP_CALL silently skip without bumping). The full enumeration, copied from `AccountStateInvariants.md` I-2 (3):

- **TRANSFER** at `chain.cpp:768` (after the cross-shard-or-same-shard credit completes).
- **REGISTER** at `chain.cpp:835` (after registry insert + optional NEF transfer).
- **DEREGISTER** at `chain.cpp:854` (success path); also at `chain.cpp:842` if the sender has no registry entry (defensive — fee already charged, nonce still bumps).
- **STAKE** at `chain.cpp:869` (after `stakes_[tx.from].locked += amount`).
- **UNSTAKE** at `chain.cpp:892` (success path, post-unlock credit); also at `chain.cpp:886` on early-unstake refund (fee returned, nonce still bumps so the sender can retry at a later height).
- **PARAM_CHANGE** at `chain.cpp:926` (fee charged, governance change staged or silently dropped if malformed).
- **COMPOSABLE_BATCH** outer at `chain.cpp:957` (before `atomic_scope` runs the inner batch); inner-tx nonces bump at `chain.cpp:1010` inside `atomic_scope`, contingent on the all-or-nothing inner success.
- **MERGE_EVENT** at `chain.cpp:1037` (fee charged, merge-state mutation conditional on `partner_id == (shard_id + 1) mod shard_count`).
- **DAPP_REGISTER** at `chain.cpp:1051` (immediately after fee, before payload decode — even malformed payloads consume the nonce so honest replay stays consistent).
- **DAPP_CALL** at all ten reject-or-success branches (lines 1138 / 1144 / 1153 / 1160 / 1173 / 1184 / 1193 / 1198 / 1207 / 1222). Every reject branch consumes fee + nonce; the success branch at 1222 also credits the recipient.

No apply-path branch decrements `next_nonce` or sets it to an explicit value other than `next_nonce++`. No apply-path branch reads `next_nonce` for any purpose other than the strict-equality gate. The field is therefore monotonically non-decreasing, advancing by exactly one per successfully-gated transaction.

---

## 2. Theorems

### T-N1 — Stale-nonce rejection

**Statement.** For every account `a` and every block `B`, if a transaction `tx ∈ B.transactions` has `tx.from == a` and `tx.nonce < state.accounts_[a].next_nonce`, then `apply_transactions(B)` neither bumps `accounts_[a].next_nonce`, nor debits `accounts_[a].balance` (no fee, no transfer cost), nor credits any other account on `tx`'s behalf, nor mutates any other backing map (`stakes_`, `registrants_`, `dapp_registry_`, `applied_inbound_receipts_`, `abort_records_`, `merge_state_`, `pending_param_changes_`).

*Proof sketch.* The gate at `chain.cpp:739` evaluates `tx.nonce != sender.next_nonce`. Under the hypothesis `tx.nonce < sender.next_nonce`, the `!=` operator returns `true` (strict numerical inequality), so the `continue` branch is taken before any subsequent action. The `switch (tx.type)` block at `chain.cpp:741` is the only entry point to any per-type apply branch; `continue` skips the switch entirely. The per-type branches are the only sites of state mutation in the loop body. By skipping the switch, the iteration produces no state change. Iteration advances to the next tx; subsequent iterations evaluate their own nonce gates against the unchanged `sender.next_nonce`. ∎

**Code witness.** `src/chain/chain.cpp:739` (gate) + `src/chain/chain.cpp:741–1231` (all per-type branches, all unreachable on `continue`).

**Test witness.** `tools/test_tx_replay_protection.sh` exercises this exact construction: two blocks are constructed each containing a TRANSFER from the same `(alice, nonce=0)`. The first block applies (alice's `next_nonce` advances 0 → 1, bob's balance credits by `amount`). The second block's tx has `tx.nonce = 0 < alice.next_nonce = 1` — the gate trips, the tx is silently skipped, alice's balance is unchanged, bob's balance is unchanged, the nonce stays at 1 (NOT re-bumped to 2), and no fee is charged. The `determ test-tx-replay-protection` CLI subcommand contains 13 assertions across 6 scenarios; the stale-nonce surface is scenarios 1 + 2 (the prefix where the first block's apply is the prerequisite for the second block's stale replay).

### T-N2 — Future-nonce rejection

**Statement.** For every account `a` and every block `B`, if a transaction `tx ∈ B.transactions` has `tx.from == a` and `tx.nonce > state.accounts_[a].next_nonce`, then `apply_transactions(B)` neither bumps `accounts_[a].next_nonce`, nor debits `accounts_[a].balance`, nor mutates any other backing map. Equivalently: gap-filling (a future-dated tx queued for later delivery) is NOT supported by the apply path.

*Proof sketch.* Symmetric to T-N1. Under the hypothesis `tx.nonce > sender.next_nonce`, the `!=` operator at `chain.cpp:739` returns `true` (strict numerical inequality), the `continue` branch is taken, no per-type branch runs. The iteration produces no state change. There is no apply-path code that buffers the tx for replay at a later height; the tx is dropped from this block's apply and the block proceeds to the next tx in canonical order. ∎

The same hypothesis is also caught one tier earlier by the validator's V15 check (`src/node/validator.cpp:569–572`), which rejects the entire block with a `"nonce mismatch from X: expected N got M"` diagnostic. The apply-time `continue` is the second line of defense for blocks that bypass the validator pass (snapshot restore, prior-finalized blocks loaded from chain.json).

**Code witness.** `src/chain/chain.cpp:739` (gate) + `src/node/validator.cpp:569–572` (V15 upstream rejection).

**Test witness.** `tools/test_tx_replay_protection.sh` scenario 3 constructs a block containing a TRANSFER from alice with `tx.nonce = 5` when `alice.next_nonce = 0` (no prior alice tx); the tx is silently skipped, alice's balance + nonce unchanged. This pins the future-nonce rejection contract against any regression that would let a future-dated tx slip through (e.g., a drift of `!=` to `<` or to `>` would either allow stale replay or allow future-nonce skip; both regressions are caught by this test row).

### T-N3 — Per-account independence

**Statement.** For every pair of distinct accounts `a, b` (`a ≠ b`) and every block `B`, the nonce-gating decision for any `tx ∈ B.transactions` with `tx.from == a` consults only `state.accounts_[a].next_nonce` — never `state.accounts_[b].next_nonce`. Equivalently: account `a`'s nonce advancement is independent of account `b`'s nonce state, and a tx from `a` with `tx.nonce == a.next_nonce` succeeds regardless of any `b.next_nonce` value.

*Proof sketch.* The gate at `chain.cpp:739` reads `sender.next_nonce` where `sender = accounts_[tx.from] = accounts_[a]`. The reference is resolved at line 735 by `std::map::operator[]` using only `tx.from` as the key. `std::map<std::string, AccountState>` keys are independent — accessing `accounts_[a]` does not read, write, or even iterate over `accounts_[b]` for `b ≠ a`. The `sender.next_nonce++` increment on the success path also writes only to `accounts_[a].next_nonce`. The state-mutation channels for `b`'s nonce are exclusively the success paths of `b`'s own txs (from a tx with `tx.from == b`); no cross-account write exists in the apply path. ∎

**Code witness.** `src/chain/chain.cpp:735` (sender reference resolved by `tx.from` key); `src/chain/chain.cpp:739` (gate consults only `sender.next_nonce`); `include/determ/chain/chain.hpp:540` (`accounts_` is `std::map<std::string, AccountState>` — keyed independence).

**Test witness.** `tools/test_tx_replay_protection.sh` scenario 4 constructs a block with two TRANSFERs in canonical order: `(alice, nonce=0)` then `(bob, nonce=0)`. Both apply successfully; alice's `next_nonce` advances 0 → 1, bob's `next_nonce` advances 0 → 1 independently. A follow-on block with `(alice, nonce=1)` and `(bob, nonce=0)` exercises asymmetric advancement: alice's tx applies (matched nonce), bob's tx fails the gate (now 1, not 0), only alice's tx affects state. The test asserts the post-apply state matches this asymmetry — alice's balance reflects two debits, bob's reflects one — pinning per-account independence.

### T-N4 — Replay defense

**Statement.** For every tx `tx_1` that successfully applies in some block `B_n` (`tx_1 ∈ B_n.transactions`, the apply passes both the nonce gate and the per-type spend gate, and `accounts_[tx_1.from].next_nonce` advances from `N` to `N+1`), and for every subsequent tx `tx_2` in any later block `B_m` (`m > n`) such that `tx_2.signing_bytes() == tx_1.signing_bytes()` (byte-identical signing message, equivalently identical `(from, type, to, amount, nonce, fee, payload)` tuple), `tx_2`'s apply silently skips because `tx_2.nonce = tx_1.nonce = N < state_m.accounts_[tx_1.from].next_nonce ≥ N+1`.

*Proof sketch.* The signing-bytes hypothesis `tx_2.signing_bytes() == tx_1.signing_bytes()` includes `nonce` in the serialized field set (see `Transaction::signing_bytes` in `src/chain/block.cpp`), so `tx_2.nonce = tx_1.nonce = N`. Between `B_n` and `B_m`, no apply-path branch decrements `accounts_[tx_1.from].next_nonce` (see §1.3 enumeration: every site is `++`, never `--` or reset). Therefore `state_m.accounts_[tx_1.from].next_nonce ≥ state_{n+1}.accounts_[tx_1.from].next_nonce = N+1 > N = tx_2.nonce`. The gate at `chain.cpp:739` evaluates `tx_2.nonce != sender.next_nonce` to `true`, triggering `continue`. By T-N1, no state change results. This is the formal replay-attack defense: an attacker who captures `tx_1`'s wire bytes from the gossip channel and re-broadcasts the exact same bytes at any later time cannot induce a second debit/credit because the gate enforces strict-equality and `next_nonce` has already advanced past the replayed tx's nonce. ∎

The signature on `tx_2` is also still valid (Ed25519 EUF-CMA only requires the signing key was used to sign these bytes once — a replay does not weaken the signature's validity). What defeats the replay is not the signature layer (the signature is genuinely correct) but the strict-equality nonce gate, which makes the previously-applied nonce un-reusable per-account. This is the apply-layer analog of bitcoin's UTXO consumption: once a (from, nonce) is consumed, no second tx with the same (from, nonce) can apply, even if it carries a valid signature.

**Code witness.** `src/chain/chain.cpp:739` (gate); `src/chain/chain.cpp:768` (TRANSFER nonce bump); all other per-type nonce bumps enumerated in §1.3.

**Test witness.** `tools/test_tx_replay_protection.sh` scenario 1 is the canonical replay test: alice signs a TRANSFER to bob with `nonce=0, amount=100, fee=1`. Block 1 includes this tx and applies; alice's balance decreases by 101, bob's increases by 100, alice's `next_nonce = 1`. Block 2 includes the **byte-identical** tx (same signature, same wire bytes); the apply hits the gate (alice's `next_nonce = 1 ≠ 0 = tx.nonce`), the tx is silently skipped, alice's balance unchanged at the post-block-1 value, bob's unchanged at the post-block-1 value. The test asserts post-block-2 balances match the post-block-1 baseline. The same scenario also exercises A1 invariance under repeated replay attempts (5 successive replay blocks): the supply equation is identical across all 5 blocks, since no debit/credit/fee delta is produced on any of them.

### T-N5 — Monotonic accumulation across blocks

**Statement.** For every account `a` and every chain of validly-applied blocks `B_0, B_1, …, B_n`, the sequence `state_0.accounts_[a].next_nonce, state_1.accounts_[a].next_nonce, …, state_n.accounts_[a].next_nonce` is monotonically non-decreasing. Equivalently: `next_nonce` never goes down. A stricter form holds for blocks containing `a`-sourced txs: if exactly `c_n` transactions from `a` are successfully gated (pass both `chain.cpp:739` and the per-type spend gate) in `B_n`, then `state_n.accounts_[a].next_nonce = state_{n-1}.accounts_[a].next_nonce + c_n`.

*Proof sketch.* By induction on block height `n`. **Base case (n = 0):** `state_0.accounts_[a].next_nonce = 0` for every account either populated by genesis (`chain.cpp:689` writes only balance; default-constructed `AccountState` carries `next_nonce = 0`) or auto-created later via the I-4 channels (each channel default-constructs an entry, again `next_nonce = 0`). Monotonicity at index 0 is trivial. **Inductive step:** assume monotonicity holds up to height `n-1`. By §1.3, the only writes to `accounts_[a].next_nonce` inside `apply_transactions(B_n)` are `sender.next_nonce++` lines on the success paths of per-type tx branches with `tx.from == a`. Each such line increments by exactly 1; no path decrements or resets. Therefore `state_n.accounts_[a].next_nonce = state_{n-1}.accounts_[a].next_nonce + c_n` where `c_n` is the count of `a`-sourced txs in `B_n` that passed the nonce gate AND the per-type spend gate. `c_n ≥ 0` (count of successful gates is non-negative), so `state_n.accounts_[a].next_nonce ≥ state_{n-1}.accounts_[a].next_nonce`. ∎

The A9 atomic-apply property (`AccountStateInvariants.md` §1.2) extends T-N5 across throw-and-rollback: if `apply_transactions(B_n)` throws (e.g., S-007 overflow, A1 violation, S-033 state-root mismatch), `restore_state_snapshot` rolls `accounts_` back to its pre-apply value, so `state_n` is defined exclusively for blocks whose apply returned successfully. Under that definition, monotonicity holds across every state index.

**Code witness.** `src/chain/chain.cpp:633–1502` (`apply_transactions` body — exhaustive search confirms no `--` or assignment-to-zero on `next_nonce`); `src/chain/chain.cpp:671–1499` (A9 try/catch wrapping the loop, with rollback on throw).

**Test witness.** `tools/test_tx_replay_protection.sh` scenarios 1–4 establish the per-block increments; the asserted state at each post-block point gives a monotonic sequence `0 → 1 → 1 → 2 → ...` for alice and `0 → 0 → 1 → 1 → ...` for bob across the test's block series. `tools/test_chain_apply_block.sh` exercises the broader apply contract across mixed tx types and asserts post-apply nonces match the expected increment count per sender.

### T-N6 — Genesis bootstrap

**Statement.** After the index-0 (genesis) apply, every account `a ∈ state_0.accounts_` has `state_0.accounts_[a].next_nonce = 0`. Equivalently: the first tx from any account, at any height after genesis, must carry `tx.nonce = 0` to pass the nonce gate.

*Proof sketch.* Two cases. **Genesis-populated accounts:** `apply_transactions` at `chain.cpp:681–718` handles `b.index == 0` separately. The per-account init at line 689 is `accounts_[a.domain].balance = a.balance;` — a single field write. `AccountState`'s default constructor (per `include/determ/chain/chain.hpp:18–21`) initializes `next_nonce{0}`, so the auto-created struct has `next_nonce = 0`. No code in the index-0 branch overrides this; line 690 carries the explicit comment `// accounts_[a.domain].next_nonce = 0  (default)`. **Auto-created accounts** (those not present in `b.initial_state` at genesis, created later by an inbound credit channel listed in I-4): the auto-creation site uses `accounts_[k]` which default-constructs on first access, again with `next_nonce = 0`. Therefore every account in `accounts_` starts at `next_nonce = 0` regardless of which path created it. The strict-equality gate then requires the first `a`-sourced tx to carry `tx.nonce = 0`. ∎

**Code witness.** `include/determ/chain/chain.hpp:18–21` (struct default); `src/chain/chain.cpp:689–690` (genesis init writes only balance); `src/chain/chain.cpp:735` (sender reference auto-creation); `src/chain/chain.cpp:756` + `src/chain/chain.cpp:1215` + `src/chain/chain.cpp:1367` (inbound credit auto-creation paths — see `AccountStateInvariants.md` I-4 for the full enumeration).

**Test witness.** `tools/test_tx_replay_protection.sh` scenario 1 baseline: alice's first tx carries `nonce = 0` and applies; the test would fail if alice's account had any other initial nonce. `tools/test_account_create_on_credit.sh` (the `AccountStateInvariants.md` I-4 defense) asserts that an account auto-created by an inbound credit channel has `next_nonce = 0` immediately after creation, before any sender-side tx from that account exists.

---

## 3. Why strict equality (not `≥`)

The choice of `!=` (strict equality) instead of a tolerant form like `>=` (accept the current nonce or any future nonce, gap-filling) or `>` (accept any nonce ≥ next) is load-bearing. Three classes of attack are blocked by the strict form:

**(a) Future-nonce skip attack.** Under `tx.nonce >= sender.next_nonce`, an attacker observing the validator's mempool can submit a tx with `nonce = next_nonce + 1000` (a large gap). If the chain advances `next_nonce` to whatever value the accepted tx carried (i.e., the apply path writes `sender.next_nonce = tx.nonce + 1`), the legitimate user's pending `next_nonce` txs become un-applyable: their `tx.nonce` is now less than the post-apply `next_nonce`. Under the alternative semantics where `next_nonce++` after a `>=` gate, the attacker has succeeded in introducing a permanent gap that other parties cannot fill — denying service. Strict equality forces `tx.nonce == next_nonce` so the per-account nonce sequence is dense (no holes), and an attacker cannot leapfrog the sender's intended order.

**(b) Gap-filling complexity.** Under `tx.nonce >= sender.next_nonce` with mempool gap-buffering (the Ethereum model — see §4), an honest user submits txs in order but a later one arrives first via the gossip network. The mempool must buffer the future-nonce tx, wait for the gap-filling tx to arrive, and apply both in order. This adds complexity (gap-buffer storage bounds, gap-buffer eviction policy under memory pressure, gap-filling DoS where an attacker submits gap-filling txs to compete for buffer slots) without changing the protocol's semantics on the apply layer — the chain still requires consecutive nonces in some canonical order. Strict equality on the apply side, combined with mempool drop-on-mismatch (`src/node/validator.cpp:569`), pushes the in-order-delivery requirement onto the sender's wallet (which is the entity with full ordering knowledge anyway), simplifying the mempool to a single-tier admission policy.

**(c) Replay variant via signed-byte mismatch.** Under `tx.nonce > sender.next_nonce` (strict-greater, not equality), the apply path would silently increment `next_nonce` past holes, making it possible to "consume" a nonce value that no signed tx actually used. A captured replay tx with the original signed `tx.nonce` value would then fail the gate (its nonce is now less than the current next_nonce — same as under strict equality), but the chain's commitment to "every consumed nonce has a corresponding signed tx in the block history" is broken. Strict equality preserves this commitment: every `next_nonce` increment corresponds to exactly one signed tx in some applied block, and the history of `(from, nonce, signed_bytes)` tuples is fully reconstructable from `blocks_`.

The trade-off is operator-side: senders must submit txs in strict nonce order. A wallet that batches multiple txs at once must serialize them by nonce; a wallet that uses multiple devices for the same address must coordinate nonce allocation (or accept that one device's tx will silently fail if another device claims the same nonce first). This is the cost of the strict form; the benefit is the three classes of attack above are structurally blocked, not just mitigated.

---

## 4. Comparison with Ethereum nonce model

Ethereum (pre- and post-EIP-1559) uses a tolerant nonce-gating model with mempool gap-buffering. Concretely: a tx with `tx.nonce > account.nonce` is buffered in the "queued" tier of the mempool (geth's `txPool.queue` map), waiting for the gap-filling tx(s) to arrive and promote the queued tx to the "pending" tier. The apply path then requires consecutive nonces in block inclusion, but the mempool absorbs out-of-order arrival.

Determ takes the opposite trade. The apply path requires strict equality (`chain.cpp:739`), the validator requires the block-level nonce to match the chain's `next_nonce(from)` for the first `from`-sourced tx and to advance by 1 per subsequent same-`from` tx in the block (`src/node/validator.cpp:569`), and the mempool drops any tx whose nonce doesn't match `chain.next_nonce(from)` at admission time. There is no queued/pending two-tier model; a future-nonce tx is dropped from the mempool, not buffered.

| Property | Ethereum | Determ |
|---|---|---|
| Apply-layer gate | `tx.nonce == account.nonce` (strict) | `tx.nonce == account.next_nonce` (strict, same) |
| Mempool admission | `tx.nonce >= account.nonce` (gap-tolerant) | `tx.nonce == chain.next_nonce(from)` (strict) |
| Out-of-order delivery | Buffered in `txPool.queue` until gap fills | Dropped at mempool ingress |
| Wallet responsibility | Wallet can submit in any order; mempool re-orders | Wallet must submit in strict order |
| Gap-buffer DoS surface | Yes (slot exhaustion attack on `txPool.queue`) | No (no buffer to exhaust) |
| Implementation LOC | ~500 lines mempool reorder + promotion | 1 line apply-time gate + 1 line mempool gate |

The trade reduces implementation surface and removes a DoS class, at the cost of pushing nonce ordering onto the sender. In practice this matches Determ's "operators submit txs from a single trusted wallet endpoint" deployment assumption better than Ethereum's "many users with many wallets" assumption. The strict choice is documented in `docs/PROTOCOL.md` §3.3 (apply rules) and `docs/QUICKSTART.md` (wallet/SDK section). The choice is not a v1.x retrofit — it has been the design since the original DLT MVP, predating the multi-shard and DApp themes.

---

## 5. What this doesn't prove

The theorems above target the per-account, same-shard, same-tx-type-set apply-layer nonce gate. They do not extend to:

- **Cross-shard replay defense.** A tx that applies on shard A and produces a cross-shard receipt is delivered to shard B as an `inbound_receipts[]` entry. The destination-side at-most-once-credit property is enforced by `applied_inbound_receipts_` (a `std::set<std::pair<ShardId, Hash>>`) checked under V13 (`Preliminaries.md` §5). The receipt's tx hash includes the source-shard nonce, so two distinct nonces on the source produce distinct receipt hashes; a replay of the same receipt is dedup'd by `applied_inbound_receipts_`. This is FA7's scope (`CrossShardReceipts.md`), not this proof's.
- **Consensus-layer signed-message replay.** A Phase-1 `ContribMsg` or Phase-2 `BlockSigMsg` carries an Ed25519 signature over consensus-protocol bytes. Replaying these on the gossip wire is a network-layer concern (peer-level rate limiting, sequence numbers in the protocol header). The protocol's signing-bytes binding includes `(height, round)` for `BlockSigMsg` and `(height, aborts_gen)` for `ContribMsg` (post-S-006), so a replay across heights or generations fails the wire-message validity check; replay within the same (height, round) is the equivocation surface, covered by FA6 (`EquivocationSlashing.md`). The current proof is specifically about per-account *transaction* replay, not signed-message replay.
- **Snapshot-restore nonce preservation.** A snapshot serialized at chain tip `C_k` and restored to a fresh receiver carries every account's `next_nonce` field (the `a:` namespace contributes `(balance, next_nonce)` per `compute_state_root` — see `SnapshotEquivalence.md` L-S0 row `a:`). T-S2 in that document proves apply-after-restore equivalence; the per-account nonce preservation is one of the conditions that the proof inherits. The current proof does not re-derive that conclusion; the dependency is one-way (T-N5's monotonicity claim composes through snapshot restore by T-S2, not the other way around).
- **Wallet-side nonce allocation.** The proofs assume the wallet submits tx nonces in strict order matching the chain's current `next_nonce(from)`. A wallet bug that allocates the same nonce twice (e.g., two threads racing) produces two byte-distinct txs with the same `(from, nonce)`. One will apply (whichever lands first in a block); the other is silently skipped under T-N1. This is correct behavior — the chain rejects the duplicate — but it is not "the chain's defense against wallet bugs" in any sense beyond fail-safe behavior. The wallet must still avoid double-allocation; `tools/operator_pending_tx_check.sh` is the operational tool for detecting silently-dropped txs.
- **Equivocation replay defense.** A validator that signs two distinct block digests at the same height (BlockSigMsg equivocation) or two distinct contrib commitments at the same (height, generation) (ContribMsg equivocation post-S-006) is slashed via `EquivocationEvent`. This is a wire-layer rule, not an apply-layer rule on `AccountState`. The slash deducts from `stakes_[equivocator].locked`, which leaves `accounts_[equivocator].balance` and `accounts_[equivocator].next_nonce` untouched (I-3 of `AccountStateInvariants.md`). The equivocator's regular tx-flow continues to be gated by `next_nonce` per this proof; the equivocation slash is orthogonal.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V15 (transaction apply) — V15's verbal description "no negative balances, sequential nonces, valid signatures" makes nonce monotonicity an explicit precondition of block validity. |
| `AccountStateInvariants.md` (FA-Apply) | Invariant I-2 names nonce monotonicity in one paragraph; this proof expands the I-2 surface into six theorems. T-N5 is the formal version of I-2's "monotone" sub-claim; T-N1 + T-N2 are the formal versions of the "strict-equality gate" sub-claim. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S2 apply-after-restore equivalence; per-account `next_nonce` is one of the fields restored via the `a:` namespace, so T-N5's monotonicity composes through snapshot restore. |
| `EquivocationSlashing.md` (FA6) | Consensus-layer signed-message replay (BlockSigMsg + ContribMsg equivocation); a different replay category, covered separately. |
| `CrossShardReceipts.md` (FA7) | Cross-shard at-most-once credit via `applied_inbound_receipts_`; the receipt-side analog of per-account nonce gating. |
| `docs/SECURITY.md` §S-002 | Mempool sig-verify closure; the upstream mempool gate that drops nonce-mismatched txs before they reach `apply_transactions`. |
| `docs/PROTOCOL.md` §3.3 | Apply rules narrative — names the strict-equality nonce rule and the per-tx-type `next_nonce++` enumeration. |
| `tools/test_tx_replay_protection.sh` | T-N1 through T-N4 + T-N6 (13 assertions across 6 scenarios — see `determ test-tx-replay-protection` for the unit-test surface). |
| `tools/test_tx_edge_cases.sh` | T-N5 (insufficient-balance branch asserts no nonce bump — the §1.3 enumeration's negative-control). |
| `tools/test_chain_apply_block.sh` | T-N5 (mixed-tx-type apply asserting per-sender increment counts). |
| `tools/test_account_create_on_credit.sh` | T-N6 (auto-created accounts via inbound credits carry `next_nonce = 0`). |
| `include/determ/chain/chain.hpp:18–21` | `AccountState` struct, including `next_nonce{0}` default. |
| `src/chain/chain.cpp:739` | The strict-equality nonce gate — load-bearing line for the entire proof. |
| `src/chain/chain.cpp:735` | Sender reference (auto-creation site). |
| `src/chain/chain.cpp:689–690` | Genesis init — comment explicitly cites the `next_nonce = 0` default. |
| `src/chain/chain.cpp:768 / 835 / 842 / 854 / 869 / 886 / 892 / 926 / 957 / 1010 / 1037 / 1051 / 1138 / 1144 / 1153 / 1160 / 1173 / 1184 / 1193 / 1198 / 1207 / 1222` | All `sender.next_nonce++` sites — §1.3 enumeration. |
| `src/node/validator.cpp:569–572` | Upstream V15 nonce check at block-validation time. |

---

## 7. Status

All six theorems (T-N1 through T-N6) are closed in the current codebase:

- **T-N1** (stale rejection) closed via the strict-equality gate at `chain.cpp:739` + `continue` semantics that skip the switch; regression `test_tx_replay_protection.sh` scenarios 1+2.
- **T-N2** (future rejection) closed via the same gate (symmetric to T-N1) + upstream V15 rejection in the validator; regression `test_tx_replay_protection.sh` scenario 3.
- **T-N3** (per-account independence) closed via `std::map`-keyed access — accessing `accounts_[a]` does not read or write `accounts_[b]` for `b ≠ a`; regression `test_tx_replay_protection.sh` scenario 4.
- **T-N4** (replay defense — the formal property) closed via T-N1 + the success-path `next_nonce++` that makes the prior nonce un-reusable; regression `test_tx_replay_protection.sh` scenario 1 (byte-identical replay across two blocks).
- **T-N5** (monotonic accumulation) closed via the §1.3 enumeration (only-`++`, no `--`); regressions `test_tx_replay_protection.sh`, `test_tx_edge_cases.sh`, `test_chain_apply_block.sh`.
- **T-N6** (genesis bootstrap) closed via the `AccountState` default initializer + the genesis init's deliberate reliance on the default; regression `test_tx_replay_protection.sh` scenario 1 baseline + `test_account_create_on_credit.sh`.

No theorem is open or partial. The strict-equality design choice is documented in `docs/PROTOCOL.md` §3.3 and reaffirmed by every regression-test pin against drift to `>=` or `>`. The proof's foundation is a single line of code (`chain.cpp:739`); the breadth of consequences — six theorems, four attack classes blocked, replay-immune by construction — is testimony to the choice's leverage.
