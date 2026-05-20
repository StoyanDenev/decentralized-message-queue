# FA-Apply — Governance PARAM_CHANGE apply path (A5 Phase 2)

This document formalizes the apply-layer mechanics of the A5 PARAM_CHANGE two-phase governance substrate: the validator-accepted PARAM_CHANGE transaction that **stages** a `(name, value, effective_height)` entry into `Chain::pending_param_changes_`, and the height-keyed **activation drain** at the start of every `Chain::apply_transactions(b)` that mutates the named chain-config field and invokes the Node-installed `ParamChangedHook` to forward the value into validator state. Together these two phases define a deterministic-replay-safe parameter-mutation channel whose transitions must (1) preserve every prior A1 / I-1..I-6 invariant, (2) inherit the validator's mode + whitelist + multisig gate without re-checking it at apply time, (3) drain pending entries exactly once at the height threshold, (4) keep the chain's view and the validator's view in lock-step via the forwarding hook, and (5) leave the chain in a fully-defined state on every apply-side malformed-payload edge case (fee-consumed, nonce-bumped, no staging).

The proof is mechanical: the entire substrate is a single per-tx-type branch in `Chain::apply_transactions` (`src/chain/chain.cpp:895–928`) covering PARAM_CHANGE, plus the staging primitive `Chain::stage_param_change` (`chain.cpp:212–217`) and the activation drain `Chain::activate_pending_params` (`chain.cpp:471–497`) called unconditionally for `b.index > 0` at apply entry (`chain.cpp:676`). The branch shares the `charge_fee` / `sender.next_nonce++` primitives covered by `AccountStateInvariants.md` (FA-Apply) I-1 + I-2; the present proof's contribution is to enumerate the legitimate two-phase transitions, prove that activation determinism survives multi-entry same-height races + replay + snapshot round-trip, and pin the apply-side gotcha: without the Node-installed forwarding hook, chain state and validator state diverge after a `bft_escalation_threshold` / `param_keyholders` / `param_threshold` activation. The strength is consolidation: `Governance.md` (FA10) covers the soundness side (no unauthorized mutation, off-whitelist immunity) and the determinism corollary T-10.1, but the apply-side mechanics (staging primitive, drain ordering, hook necessity, idempotency) are scattered across `chain.cpp` + `node.cpp` + `validator.cpp` and the apply-side test commentary in `tools/test_pending_param_changes.sh` + `tools/test_param_change_apply.sh`. No single document collects the eight theorem statements about the apply-side state machine.

**Companion documents:** `Preliminaries.md` (F0) for notation and validity predicates V1–V15; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 (no underflow via the `charge_fee` gate that PARAM_CHANGE shares with every fee-only-debit channel) and I-2 (the strict-equality nonce gate that precedes the PARAM_CHANGE branch at `chain.cpp:739`); `NonceMonotonicity.md` (FA-Apply-3) for T-N1 / T-N3 (the per-account strict-equality gate and per-account independence that PARAM_CHANGE inherits unchanged); `StakeLifecycle.md` (FA-Apply-4) for the closest structural template (both are state-machine proofs over a chain-instance map gated by deferred-effect semantics tied to a future block height — STAKE's `unlock_height` ≈ PARAM_CHANGE's `effective_height`); `DAppRegistryLifecycle.md` (FA-Apply-5) for the apply-side state-machine proof style; `Governance.md` (FA10) for the upstream soundness theorems T-10 (no unauthorized mutation under A1) + T-11 (off-whitelist immunity) + T-10.1 (activation determinism) — the present proof depends on FA10 for the validator-side gate (mode + whitelist + multisig) and refines T-10.1 by exhibiting the eight apply-side mechanisms that produce the determinism; `SnapshotEquivalence.md` (FA-Apply-2) for the `p:` state-root namespace coverage that carries pending entries through snapshot bootstrap; `EconomicSoundness.md` (FA11) for the A1 closure under the fee channel that PARAM_CHANGE shares with every other fee-only-debit type.

---

## 1. Setup

### 1.1 Storage

Per `include/determ/chain/chain.hpp:618–624`:

```cpp
std::map<uint64_t,
         std::vector<std::pair<std::string, std::vector<uint8_t>>>>
                                            pending_param_changes_;
ParamChangedHook                            param_changed_hook_{};
```

`pending_param_changes_` is keyed by `effective_height` (the activation block index) and valued by a `std::vector` of `(name, value)` pairs. The choice of `std::map` is load-bearing: ascending-key iteration is a structural guarantee of the red-black tree, so the activation drain processes future-effective heights in chronological order without explicit sorting. The vector inside each bucket preserves apply-order via `push_back` semantics: two PARAM_CHANGE txs landing in different blocks but targeting the same `effective_height` activate in the order their blocks were applied. The `ParamChangedHook` is a function object installed by the Node during construction (`src/node/node.cpp:195–247`); the chain holds a borrowed reference and invokes it from `activate_pending_params` after the in-chain field mutation completes.

Companion chain-instance state mutated by activation:

```cpp
uint64_t min_stake_;             // MIN_STAKE
uint64_t suspension_slash_;      // SUSPENSION_SLASH
uint64_t unstake_delay_;         // UNSTAKE_DELAY
```

These three live on `Chain` itself (`include/determ/chain/chain.hpp:586–590` block) and are written directly by `activate_pending_params`'s `parse_u64` decoder. Three other whitelisted names — `param_keyholders`, `param_threshold`, `bft_escalation_threshold` — have no chain-instance storage; they live on the validator and are reached only via the `ParamChangedHook` forward. The three timing fields — `tx_commit_ms`, `block_sig_ms`, `abort_claim_ms` — live on the Node's `cfg_` and are also reached only via the hook.

### 1.2 The two-phase model

The PARAM_CHANGE life cycle has exactly two apply-layer events:

```
                      PARAM_CHANGE tx                 b.index >= effective_height
   (validator-       ──────────────────>  STAGED  ─────────────────────────────>  ACTIVATED
    accepted)        (chain.cpp:900–928)            (chain.cpp:471–497)
```

**STAGE.** A PARAM_CHANGE that survives the validator's mode + whitelist + multisig gate enters the apply-side PARAM_CHANGE branch at `chain.cpp:900`. The branch consumes the tx fee (`charge_fee`), defensively re-parses the canonical header (`[name_len, name, value_len, value, effective_height]`), calls `stage_param_change(eff, name, value)` to push the pair into `pending_param_changes_[eff]`, and bumps the sender nonce. The signature tail of the payload is NOT re-verified at apply time — the validator's threshold gate is the unique consent surface, and apply trusts it for deterministic replay (see §5 "Forwarding hook necessity" + §7 "What this doesn't prove" for the rationale).

**ACTIVATE.** Every call to `Chain::apply_transactions(b)` with `b.index > 0` begins by invoking `activate_pending_params(b.index)` (`chain.cpp:676`) BEFORE the tx replay loop. The drain walks `pending_param_changes_` in ascending-key order, processes every bucket whose `eff_height <= b.index`, mutates the chain-instance field if the name has chain storage, invokes the Node-installed hook for every activation (regardless of whether chain storage applied), and erases the drained bucket from the map. Subsequent `apply_transactions(b+1)` calls do not re-encounter the drained entry.

The placement of activate-before-replay is itself an invariant: a tx in block `b` that depends on the new parameter value (e.g., a STAKE check against the just-activated `MIN_STAKE`) sees the new value because the drain ran first. Theorem T-G4 formalizes the drain semantics; the placement guarantee falls out of the apply-entry single-call-site at `chain.cpp:676`.

### 1.3 Mode pinning

The `governance_mode` field on `GenesisConfig` (`include/determ/chain/genesis.hpp:221`, type `uint8_t`) is exactly one of:

- **`0` — uncontrolled.** Validator rejects every PARAM_CHANGE outright (`validator.cpp:625–628`). The chain's parameters are immutable for the lifetime of the chain; the only way to change them is a new genesis = new chain identity. The default for any chain that doesn't opt in.
- **`1` — governed.** Validator runs the mode-passing branch, applies whitelist + multisig checks, and accepts PARAM_CHANGE txs that satisfy both. The apply branch reaches the staging primitive.

The mode is genesis-pinned: there is no PARAM_CHANGE entry that maps to `governance_mode` (the whitelist at `validator.cpp:662–667` does not list it). Allowing `governance_mode` to be mutable would be self-referentially circular — a governed chain could vote to leave governance, after which no further mutation could undo the move; an uncontrolled chain could not vote to enter governance because the mode-gate would reject the proposal up front. Pinning at genesis is the only stable design, and the mode is mixed into the genesis hash (it is part of `GenesisConfig::to_json` and therefore the deterministic genesis-hash computation) so the chain identity binds it.

---

## 2. Theorems

### T-G1 — Validator-accepted PARAM_CHANGE stages exactly one entry

**Statement.** For every block `B` at height `b.index > 0` containing a PARAM_CHANGE transaction `tx` such that (i) `tx.from`'s nonce gate at `chain.cpp:739` admits the tx, (ii) `state.accounts_[tx.from].balance >= tx.fee`, and (iii) the canonical payload header `[name_len, name, value_len, value, effective_height]` parses with `name ∈ kWhitelist` (the validator already enforced this upstream — FA10 T-10), apply produces the deltas:

```
Δaccounts_[tx.from].balance                = −tx.fee
Δaccounts_[tx.from].next_nonce             = +1
Δtotal_fees                                = +tx.fee
Δpending_param_changes_[effective_height]  = append((name, value))   (single push_back)
```

with no other state mutation. The threshold-signature tail is not re-verified at apply time — it was verified at validate time, and apply trusts that result for deterministic replay.

*Proof sketch.* By inspection of `chain.cpp:900–928`. The nonce gate at line 739 admits the tx (hypothesis i). `charge_fee(sender, tx.fee)` at line 901 succeeds (hypothesis ii); on success the sender balance debits `tx.fee` and `total_fees` accumulates `+tx.fee` per the lambda body at `chain.cpp:727–732`. Lines 902–906 enter the payload-decode block; the defensive shape checks at lines 907–914 (which restate the validator's payload-shape gate for apply-side determinism if a malformed tx somehow slipped past validation) pass under hypothesis (iii). Lines 908–917 decode `name`, `value`, and `eff` deterministically. Line 921 calls `stage_param_change(eff, std::move(name), std::move(value))`, which executes `pending_param_changes_[eff].emplace_back(...)` at `chain.cpp:215` — a single `push_back` on the height-keyed vector. Line 926 bumps the sender nonce. No other state mutation occurs in the branch. ∎

**Code witness.** `src/chain/chain.cpp:895–928` (PARAM_CHANGE apply branch); `src/chain/chain.cpp:212–217` (`stage_param_change` helper); `src/chain/chain.cpp:727–732` (`charge_fee` lambda); `src/node/validator.cpp:621–712` (the validator-side gate whose acceptance is the precondition for reaching the apply branch).

**Test witness.** `tools/test_pending_param_changes.sh` (`determ test-pending-param-changes`) — 13 assertions exercising the staging primitive directly: default-empty, single-stage produces map size 1 + bucket size 1 + name/value preserved, multi-stage at same height produces bucket size 2 with insertion order preserved, multi-stage at different heights produces sorted map iteration, edge-value cases (empty value, 256-byte value) round-trip intact, chain independence (one chain's stage doesn't leak to another). `tools/test_governance_param_change.sh` exercises the full validator → apply → stage flow end-to-end in a 3-node 3-of-3 keyholder governed-mode chain.

### T-G2 — Off-whitelist + uncontrolled-mode silently rejected at validator (no apply-side staging)

**Statement.** For every block `B` containing a PARAM_CHANGE transaction `tx` with either (i) `governance_mode == 0` (uncontrolled chain) or (ii) `name ∉ kWhitelist` (off-whitelist parameter name), the apply-side PARAM_CHANGE branch is **unreachable**: the block fails validation upstream (`validator.cpp:625–628` or `validator.cpp:668–671`), is not finalized, and produces no state delta on any honest chain. Equivalently: no entry corresponding to `name` ever enters `pending_param_changes_`, no fee is charged, no nonce is bumped, and the off-whitelist parameter name has no observable effect on any honest chain's state.

*Proof sketch.* By upstream rejection. The validator-side gate at `validator.cpp:621–712` is the unique entrypoint to apply-side acceptance: blocks containing validator-rejected txs fail block validation in `Validator::check_block`, which is called by every honest node before `Chain::apply_transactions` is invoked. A block whose PARAM_CHANGE fails any gate is rejected by the K-of-K committee and never finalized (per FA1 + FA5). Therefore no honest chain ever calls `apply_transactions` on a block containing such a tx, and the apply branch is structurally unreachable.

The argument has two structural layers. **Layer 1 (validator rejection).** `validator.cpp:625` checks `governance_mode == 0` and returns `{false, "PARAM_CHANGE rejected: chain is in uncontrolled governance mode"}`; `validator.cpp:668` checks `kWhitelist.find(name) == kWhitelist.end()` and returns `{false, "PARAM_CHANGE rejected: parameter '...' is not on the governance whitelist"}`. Both rejections happen before the signature-verification loop, so a payload that fails either is rejected without further per-signature CPU work. **Layer 2 (apply-path closure under the unreachable hypothesis).** Even if a future regression somehow allowed an off-whitelist tx to reach apply, the activation drain's switch (`chain.cpp:483–493`) has explicit cases ONLY for `MIN_STAKE`, `SUSPENSION_SLASH`, `UNSTAKE_DELAY` chain-instance writes plus the hook forward (which itself has explicit branches for the validator/node mirror fields). Off-whitelist names trigger no chain-state mutation; the activation switch's default behavior is no-op + hook fire. The hook's branches in `node.cpp:198–247` are similarly explicit — off-whitelist names produce no state delta on the validator or Node either. So the two-layer defense is conservative: layer 1 prevents the tx from reaching apply; layer 2 would prevent the mutation even if layer 1 regressed. ∎

**Code witness.** `src/node/validator.cpp:625–628` (uncontrolled-mode reject); `src/node/validator.cpp:660–671` (off-whitelist reject); `src/chain/chain.cpp:483–493` (activation switch default no-op); `src/node/node.cpp:198–247` (hook default no-op for unrecognized names).

**Test witness.** `tools/test_governance_param_change.sh` exercises the positive case (governed mode + whitelisted name → accepted). The negative cases are covered by inspection — the validator's reject branches are deterministic on inputs, and a regression that loosened either would surface immediately as PARAM_CHANGE acceptance on a chain whose genesis pins `governance_mode = 0` (FA10 T-11's structural-induction argument).

### T-G3 — Threshold enforcement: sub-threshold sigs silently rejected at validator (no partial application)

**Statement.** For every block `B` containing a PARAM_CHANGE transaction `tx` whose multisig section yields fewer than `param_threshold` verifying signatures from distinct `param_keyholders` indices, the validator rejects the tx (`validator.cpp:705–710`), the block is not finalized, and no apply-side staging occurs. Equivalently: signature thresholds are atomic — there is no "partial application" where a tx with sub-threshold sigs commits a partial mutation.

*Proof sketch.* By inspection of `validator.cpp:688–710`. The validator iterates the signature tail at lines 690–704: for each `(keyholder_index, ed_sig)` pair, it checks (a) `idx < param_keyholders_.size()` (line 696, fail-fast with `{false, ...}` on out-of-range), (b) `seen_idx.insert(idx).second` (line 698, fail on duplicate index — prevents same-keyholder signing twice), and (c) `verify(param_keyholders_[idx], sig_msg.data(), ..., msig)` (line 700–701). The loop increments `good_sigs` only on successful verify. Line 705 checks `good_sigs < param_threshold_` and returns `{false, "PARAM_CHANGE signature threshold not met (got X, need Y)"}` on any shortfall. The threshold check fires before the branch returns success, so a tx with sub-threshold verifying sigs is rejected.

The "atomic" claim follows: the apply branch is unreachable on the validator's reject (T-G2's structural argument), so no `stage_param_change` call occurs. No mid-way mutation is possible because the validator's signature loop is pure (it touches no chain state, only the local `good_sigs` counter + `seen_idx` set), and the apply branch's staging is a single `emplace_back` (one mutation, no rollback path needed because there's no preceding mutation in the branch). ∎

**Code witness.** `src/node/validator.cpp:688–710` (signature-loop + threshold gate); `src/node/validator.cpp:696` (index-range check); `src/node/validator.cpp:698` (distinct-index check); `src/node/validator.cpp:700–702` (per-sig verify counting good sigs).

**Test witness.** Covered by FA10 T-10's concrete-security bound (`Governance.md` §7): a sub-threshold tx requires forging at least one additional Ed25519 signature for a chosen message, which is `≤ 2⁻¹²⁸` per attempt. The test `tools/test_governance_param_change.sh` exercises the positive 3-of-3 case; the negative (sub-threshold) case is structurally unreachable on any honest chain.

### T-G4 — Activation drain on height match: in-order, deterministic, exactly-once

**Statement.** For every chain state with `pending_param_changes_` containing entries at heights `h_1 < h_2 < ... < h_k` and every block `B` at height `b.index = H`, the activation drain at `chain.cpp:471–497` produces (in this exact order) for every `h_i ≤ H`:

1. For each `(name, value)` pair in the `h_i` bucket, in insertion order:
   1. If `name == "MIN_STAKE"`: parse `value` as little-endian uint64; assign to `Chain::min_stake_`.
   2. Else if `name == "SUSPENSION_SLASH"`: same pattern; assign to `Chain::suspension_slash_`.
   3. Else if `name == "UNSTAKE_DELAY"`: same pattern; assign to `Chain::unstake_delay_`.
   4. Else: no chain-instance mutation (the four no-storage names live on the validator/Node via the hook).
   5. Invoke `param_changed_hook_(name, value)` if a hook is installed (regardless of whether step 1.i–iv mutated anything).
2. Erase the `h_i` bucket from `pending_param_changes_`.

After the drain returns, `pending_param_changes_` contains exactly the entries with `eff_height > H`. No entry that was drained reappears on any subsequent block's drain (idempotent-by-erasure).

*Proof sketch.* By inspection of `chain.cpp:471–497`. The function opens with `auto it = pending_param_changes_.begin()` (line 472) — `std::map<uint64_t, ...>::begin()` returns the iterator to the smallest key. The loop predicate `it != end() && it->first <= current_height` (line 473) admits buckets in ascending-key order up to and including `H`. The inner loop at line 474 iterates `it->second` (the vector) in its native `push_back`-induced order, which by T-G1 reflects the apply-order of the staging txs. The `parse_u64` lambda at lines 476–482 performs an 8-byte LE decode into the destination field; the conditional chain at lines 483–485 dispatches the three chain-instance names to their respective `Chain::*_` slots; line 493 unconditionally invokes the hook (regardless of whether the previous if-chain matched). Line 495 calls `it = pending_param_changes_.erase(it)` — the standard `std::map::erase(iterator)` returns the iterator past the erased element, so the outer loop continues with the next bucket. After the loop, `pending_param_changes_` contains exactly the buckets with `eff_height > H`.

The "exactly-once" property follows from the `erase` semantics: a drained bucket is removed from the map, so `pending_param_changes_.begin()` on the next `apply_transactions(b+1)` returns the next-larger-key bucket. There is no other code path that re-inserts a drained `(eff_height, name, value)` tuple — staging happens only from the PARAM_CHANGE apply branch (T-G1), and the apply branch always inserts under the tx's `eff` field, not the drained one. ∎

**Code witness.** `src/chain/chain.cpp:471–497` (the drain function); `src/chain/chain.cpp:676` (the single call site, at apply entry for `b.index > 0`); `src/chain/chain.cpp:483–485` (chain-instance dispatch); `src/chain/chain.cpp:493` (hook fire); `src/chain/chain.cpp:495` (erase + iterator advance).

**Test witness.** `tools/test_param_change_apply.sh` (`determ test-param-change-apply`) — ~16 assertions in eight blocks pinning the drain semantics: staging contract (3 assertions: default field, stage-only no-mutation, pending map reflects entry), activation (3: chain field mutated at apply boundary, pending drained, `eff=0` activates at first non-genesis apply), multi-param same-height (1: 3 params staged at same height all activate in apply order), multi-param different-height (4: earlier-height drains first, later still pending; all-heights-reached map empty), unknown name (2: chain storage unchanged + hook fires anyway), hook for known params (2: hook fires + chain field updated), determinism (1: two chains with identical staging produce identical state_root).

### T-G5 — Future-effective preserves staging

**Statement.** For every chain state with `pending_param_changes_` containing an entry `(name, value)` at `effective_height = E`, and every block `B` at height `b.index = H < E`, the activation drain produces no mutation to `pending_param_changes_[E]` — the entry remains in the map unmodified. Equivalently: a too-early apply does not "early-drain" a future-effective entry, and the entry survives unchanged until the first block at height `≥ E`.

*Proof sketch.* By inspection of `chain.cpp:471–497`'s loop predicate. The loop entry condition `it->first <= current_height` is evaluated at each iteration. Under hypothesis `H < E`, the iterator at `(E, [...])` produces `it->first = E > H = current_height`, so the predicate is false and the loop exits without entering the body. The erase at line 495 does not fire; the bucket at `E` is untouched.

The same argument applies to every later bucket at `eff > E`: by the std::map sorted-key contract, `it->first > E > H` for every iterator past the first preserved one, so the loop terminates at the first preserved bucket without falling through to later ones. The full set of preserved entries is exactly `{ (eff, [...]) : eff > H }`. ∎

**Code witness.** `src/chain/chain.cpp:473` (loop predicate); `src/chain/chain.cpp:474–494` (loop body — unreached under the future-effective hypothesis).

**Test witness.** `tools/test_param_change_apply.sh` "Staging contract" + "Multi-param different-height" blocks — the "stage only: field unchanged before activation height" and "earlier-height entry activates first; later still pending" assertions exercise this directly.

### T-G6 — Validator-field forwarding via ParamChangedHook

**Statement.** For every successful activation at `chain.cpp:493` of a name `n ∈ {"bft_escalation_threshold", "param_keyholders", "param_threshold", "tx_commit_ms", "block_sig_ms", "abort_claim_ms"}` (the validator/Node-mirror set), the Node-installed `param_changed_hook_` writes the parsed value into the corresponding validator-side or `cfg_` field. After the drain returns and `apply_transactions(b)` completes its tx replay, the validator's view of the parameter is byte-identical to the chain's view of any chain-instance parameter that activated in the same call.

*Proof sketch.* By inspection of the hook body at `src/node/node.cpp:195–247`. The hook is a lambda installed during Node construction; its closure captures `this`, so the hook's writes reach the Node's `validator_` and `cfg_` fields. The hook's body is a switch on `name`:

- `"bft_escalation_threshold"` (line 198): parse 8-byte LE → `validator_.set_bft_escalation_threshold(uint32_t(v))`.
- `"param_threshold"` (line 202): parse 8-byte LE → `validator_.set_param_threshold(uint32_t(v))`.
- `"param_keyholders"` (line 206): parse `[count: u8][count × 32B]` → `validator_.set_param_keyholders(std::move(ks))`.
- `"tx_commit_ms"`, `"block_sig_ms"`, `"abort_claim_ms"` (lines 229, 234, 239): parse 8-byte LE → assign to `cfg_.tx_commit_ms` etc.
- Any other name (including `MIN_STAKE` / `SUSPENSION_SLASH` / `UNSTAKE_DELAY`): no hook-side action (per comments at lines 244–246: "chain-local: the chain wrote them itself before this hook fired, so no mirror needed here").

The hook fires *after* the chain-instance mutation (`activate_pending_params` writes the chain field at lines 483–485, then invokes the hook at line 493), so for the chain-instance names the hook is intentionally redundant. For the validator/Node-mirror names, the chain has no storage to mutate (lines 483–485 don't match) and the hook is the unique writer. Either way the validator's view ends up consistent with the chain's view by the time the drain returns. ∎

**Code witness.** `src/node/node.cpp:195–247` (hook body); `src/chain/chain.cpp:493` (hook invocation site, post-mutation); `src/chain/chain.cpp:483–492` (the chain-instance-mutation block whose absence for validator-only names is what makes the hook load-bearing).

**Test witness.** `tools/test_param_change_apply.sh` "Hook for known params" block — the "hook fires AND chain field updated" assertion exercises the consistency case for a chain-instance name; the "Unknown name" block's "hook still fires" assertion exercises the hook-only path (no chain mutation, hook still receives). The end-to-end `tools/test_governance_param_change.sh` exercises the `MIN_STAKE` activation through a 3-node gossip chain and verifies via snapshot inspect that the chain field reflects the new value — implicitly the validator's `set_*` setters were not the failure mode for that test.

### T-G7 — Idempotent activation (drained-once-only)

**Statement.** For every pending entry `(name, value)` at `effective_height = E` staged at chain state `state_n`, after a successful `apply_transactions(b)` with `b.index = H ≥ E` the entry is drained exactly once. Subsequent calls to `apply_transactions(b+1)`, `apply_transactions(b+2)`, ... do NOT re-apply the entry (no double-write to the chain-instance field, no second hook fire). Equivalently: the activation effect is a one-shot per `(E, name, value)` tuple, regardless of how many later blocks the chain applies.

*Proof sketch.* By inspection of `chain.cpp:495`: the activation loop invokes `it = pending_param_changes_.erase(it)` after each drained bucket. `std::map::erase` removes the element from the tree; subsequent iteration over the map cannot encounter the removed key. On `apply_transactions(b+1)`, the loop body at line 472 starts from the (now-different) `begin()`, which is either the next-larger-key bucket or `end()` if no future-effective entries remain. The drained bucket is gone.

The "no double-write to chain-instance field" claim follows directly: the only writer to `min_stake_` / `suspension_slash_` / `unstake_delay_` post-genesis is the activation switch at `chain.cpp:483–485` (the snapshot restorer is the only other writer; see `chain.cpp:621–623` — distinct call site, not invoked during ordinary apply). After the drained bucket is gone, the switch's match condition cannot fire for that `(name, value)` again unless a *new* PARAM_CHANGE tx stages a fresh entry at some future effective_height. The "no second hook fire" claim follows symmetrically: the hook invocation at line 493 is inside the activation loop's body, which only runs once per drained bucket.

The argument composes with T-G4 cleanly. T-G4 specifies the in-order, deterministic activation; T-G7 specifies the one-shot-per-stage property. Together they pin the staging primitive's full one-to-one correspondence: every successful PARAM_CHANGE stages exactly one entry (T-G1), every drained entry produces exactly one activation event at the first block with `b.index ≥ E` (T-G4 + T-G7), and no further activation events fire for that entry. ∎

**Code witness.** `src/chain/chain.cpp:495` (`erase(it)` returning the post-erase iterator); `src/chain/chain.cpp:472` (`begin()` re-read at each apply); `src/chain/chain.cpp:483–485` (the single writer to chain-instance param fields outside snapshot restore); `src/chain/chain.cpp:493` (single hook invocation per drained bucket).

**Test witness.** `tools/test_param_change_apply.sh` "Activation" block — "pending map drained after activation" assertion + subsequent block apply does not re-mutate (the implicit absence of a second mutation is verified by the state_root determinism assertion at the test tail).

### T-G8 — A1 invariance under PARAM_CHANGE apply (no supply mutation)

**Statement.** For every successful apply of a block `B` containing one or more PARAM_CHANGE transactions, the A1 unitary-balance invariant (`AccountStateInvariants.md` I-6) holds: `live_total_supply(state_{n+1}) == expected_total(state_{n+1})`. PARAM_CHANGE is a chain-config mutation, not a supply mutation: it does NOT modify `accumulated_subsidy_`, `accumulated_slashed_`, `accumulated_inbound_`, or `accumulated_outbound_`, and it does NOT mutate any `accounts_[*].balance` or `stakes_[*].locked` field except the canonical fee-only debit on `sender.balance` (which is offset by the matching `total_fees` accumulation that feeds the block-tail creator distribution).

*Proof sketch.* By inspection of the two PARAM_CHANGE-touching code paths (stage + activate). The stage path at `chain.cpp:900–928` mutates exactly:

- `accounts_[tx.from].balance` — debit by `tx.fee` via `charge_fee` (the same channel as every fee-only-debit tx type).
- `accounts_[tx.from].next_nonce` — bump by 1 (no supply effect).
- `total_fees` — accumulate `+tx.fee` (the matching credit side of the fee debit; covered by I-6's "fees redistributed" channel at the block-tail creator credit at `chain.cpp:1287–1304`).
- `pending_param_changes_[effective_height]` — append `(name, value)`. This field carries no value-bearing semantics; it is consulted only at the activation drain to look up which chain-config field to mutate.

The activation drain at `chain.cpp:471–497` mutates exactly:

- `min_stake_` / `suspension_slash_` / `unstake_delay_` — chain-config fields, no supply effect.
- The Node's `validator_` mirror fields and `cfg_` — also no supply effect.
- The drained bucket is `erase`'d from `pending_param_changes_` — again no supply effect.

Neither code path touches `accumulated_subsidy_`, `accumulated_slashed_`, `accumulated_inbound_`, or `accumulated_outbound_`. The fee debit goes through the standard `charge_fee` channel that I-5 of `AccountStateInvariants.md` lists as the "fee-only debit" category (`REGISTER / DEREGISTER / UNSTAKE / PARAM_CHANGE / MERGE_EVENT / DAPP_REGISTER`), so the A1 closure at apply-tail (`chain.cpp:1399`) holds by composition with FA-Apply I-6.

The chain-config fields whose values change at activation (`min_stake_`, `unstake_delay_`, etc.) participate in A1 only indirectly — e.g., changing `MIN_STAKE` from 1000 to 2000 affects which future STAKE txs the validator accepts, but does not retroactively mutate any already-applied `stakes_` entries. The new value is in effect only for blocks at `index >= effective_height`, where it gates downstream tx admission via the validator's per-tx checks. The historical `stakes_` map carries the locked balances at the time they were staked, unmodified by the parameter change. ∎

**Code witness.** `src/chain/chain.cpp:727–732` (`charge_fee` lambda — the only `accounts_` mutation in the PARAM_CHANGE branch); `src/chain/chain.cpp:1287–1304` (per-creator fee + subsidy distribution at block-tail — the matching credit for the fee debit); `src/chain/chain.cpp:1399` (apply-tail A1 closure assertion); `src/chain/chain.cpp:471–497` (activation drain — no `accumulated_*` mutation, no `accounts_` or `stakes_` mutation).

**Test witness.** `tools/test_supply_lifecycle.sh` exercises the chain through TRANSFER / STAKE / UNSTAKE / REGISTER / DEREGISTER / equivocation / suspension / cross-shard / subsidy variants and asserts A1 closure block-by-block. The apply-tail A1 assertion at `chain.cpp:1399` fires for every block, including PARAM_CHANGE-bearing blocks exercised by `tools/test_governance_param_change.sh`. Any A1 violation in the PARAM_CHANGE branch would throw at apply-tail and the test would fail.

---

## 3. Uncontrolled vs governed mode

The `governance_mode` field on `GenesisConfig` (`include/determ/chain/genesis.hpp:221`) is a 1-byte enum with exactly two values; the mode is **genesis-pinned and never mutable**.

**Uncontrolled (`mode = 0`).** Default for any chain that doesn't explicitly opt in. The validator's PARAM_CHANGE branch fails-fast at `validator.cpp:625–628`: every PARAM_CHANGE tx is silently rejected with `{false, "PARAM_CHANGE rejected: chain is in uncontrolled governance mode"}`. No apply-side staging is ever reached. Chain parameters that are mutable in governed mode (`MIN_STAKE`, `SUSPENSION_SLASH`, `UNSTAKE_DELAY`, `bft_escalation_threshold`, `param_keyholders`, `param_threshold`, `tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`) are **immutable for the lifetime of the chain**. Changing any of them requires a new genesis = new chain identity. This is the appropriate default for permissionless or trust-minimized deployments: the chain is "fork-free" in the strongest sense — every parameter the operators care about is baked into the chain hash, and any apparent mutation indicates a different chain.

**Governed (`mode = 1`).** Opt-in for permissioned, consortium, or operator-coordinated deployments. The validator runs the full PARAM_CHANGE gate (mode + whitelist + multisig), and accepted txs flow through the apply-side staging + activation path. The keyholder set (`param_keyholders`) and threshold (`param_threshold`) are themselves on the whitelist, so the founder set can rotate its own keys via a PARAM_CHANGE; the bootstrap is genesis-pinned as the founder-set chosen at chain launch.

**Why mode is not itself mutable.** Allowing `governance_mode` to be a whitelist entry would be self-referentially circular:

- A governed chain could pass a PARAM_CHANGE setting `mode = 0`, after which no further mutation could undo the move. Subsequent PARAM_CHANGE txs would be rejected, including a hypothetical "restore governance" proposal. The chain becomes a frozen-config chain whose parameters are permanently locked at whatever values were active at the moment of transition. This is recoverable in principle (the operators can fork to a new genesis), but the transition is not reversible on the live chain.
- An uncontrolled chain could not vote to enter governance because the mode-gate at `validator.cpp:625–628` rejects every PARAM_CHANGE up front — there is no proposal mechanism to evaluate. The only way to enter governance is to fork to a new genesis with `mode = 1`.

In both directions, the live-chain mutation path is degenerate. Pinning at genesis is the only stable design. The mode is mixed into the genesis hash (via `GenesisConfig::to_json` + the deterministic hash computation), so the chain identity binds the choice; an operator pointing a node at the "wrong" genesis fails the genesis-hash gate at boot (per `docs/PROTOCOL.md` §3.1).

---

## 4. Forwarding hook necessity

Theorem T-G6 establishes that the Node-installed `ParamChangedHook` writes the new parameter value into validator-side or `cfg_` state for the six "no chain storage" names. Why is this load-bearing? Because **without the hook, the chain's view of a mutated parameter would diverge from the validator's view, breaking the consensus invariant that every honest node enforces the same predicate**.

Consider a concrete scenario in a 3-node governed chain. The operators broadcast a PARAM_CHANGE setting `bft_escalation_threshold` from 3 (default) to 6 at effective_height 100. The flow:

1. Block at height 100 lands; every honest node calls `apply_transactions(b=100)`.
2. The drain at `chain.cpp:471–497` finds the pending entry; the name is `bft_escalation_threshold`, which is NOT in the if-chain at `chain.cpp:483–485` (those handle only the three chain-instance names). No chain field mutates.
3. **With the hook installed:** line 493 invokes `param_changed_hook_("bft_escalation_threshold", value)`, which dispatches to `node.cpp:198–201`'s `validator_.set_bft_escalation_threshold(6)`. The validator's escalation threshold is now 6 on every honest node.
4. **Without the hook installed** (regression scenario): line 493 is a no-op (the hook is `nullptr`-equivalent). The chain's `pending_param_changes_` records that an activation occurred — but the validator's escalation threshold is still the default 3. The validator's view diverged from the chain's view.

In the no-hook scenario, the divergence is observable at the next BFT escalation decision: the chain's pending log says the threshold is 6, but the validator's check at `validator.cpp::should_escalate_to_bft` (or its callers) consults `validator_.bft_escalation_threshold_`, which still reads 3. Honest nodes that would have rejected a block under the new threshold instead accept it; honest nodes that would have accepted a block under the old threshold instead reject it. This produces an irreversible consensus break — the same block hash has different acceptance results across nodes.

The same argument applies to the timing fields. A chain that activates `tx_commit_ms = 1000` via a PARAM_CHANGE without the hook would still produce blocks at the old timing — the producer's timer schedulers read from `cfg_.tx_commit_ms` at timer-arming time, and without the hook update, `cfg_.tx_commit_ms` retains the genesis value. This is less catastrophic than the BFT-threshold case (timing is best-effort, not consensus-critical), but it still produces operator-visible parameter drift.

The hook is therefore the "apply-side gotcha" that the proof's T-G6 pins. The validator's view of every governable parameter must be re-fed at activation time, even though the chain has already "applied" the change in its pending-log accounting. The forwarding is the unique mechanism that closes the loop. A regression that removed the hook installation in `node.cpp::Node::ctor` (line 195) or that silently dropped a hook branch (e.g., forgetting to add a case for a new whitelisted name) would produce exactly this divergence — and the chain's snapshot serialization would mask the bug, because the snapshot carries the `pending_param_changes_` log correctly (so a freshly-restored node would re-apply the activation and re-call the hook on the next post-restore block).

The hook's design is intentionally conservative: it is invoked **unconditionally on every activation**, regardless of whether the chain-instance switch matched. This means the chain-instance names (`MIN_STAKE`, etc.) also receive a hook call after the chain has already mutated itself; the hook's body at `node.cpp:244–246` explicitly observes that no validator-side mirror is needed for those names and falls through. The unconditional invocation makes future additions safer — adding a new validator-mirror name only requires extending the hook body, not also threading the dispatch logic into the activation switch.

---

## 5. Determinism corollary (companion to FA10 T-10.1)

FA10's T-10.1 (Activation determinism, `Governance.md` §5) states that two honest nodes applying the same block sequence reach byte-identical chain state after each block. The present proof refines that result by exhibiting the eight apply-side mechanisms that produce determinism:

1. **Pure-function staging (T-G1).** `stage_param_change(eff, name, value)` is a `std::map::operator[].emplace_back` — deterministic insert order under a sorted-key map.
2. **Validator-side rejection (T-G2 + T-G3).** Off-whitelist / sub-threshold / wrong-mode txs are rejected uniformly across nodes by the same `validator.cpp` predicate.
3. **In-order drain (T-G4).** `std::map::begin()` produces the smallest-key iterator; the loop predicate walks ascending; insertion order inside each bucket is preserved by `std::vector::push_back`.
4. **Future-effective preservation (T-G5).** The loop predicate `it->first <= current_height` cleanly separates "ready to drain" from "still pending" by the height field alone — no other state is consulted.
5. **Forwarding hook consistency (T-G6).** Every honest node installs the same hook body in `node.cpp:195–247`, so the validator-side mirror writes the same values for the same names.
6. **Erase-on-drain (T-G7).** `std::map::erase(iterator)` is a deterministic structural mutation; the post-erase tree has the same shape on every node.
7. **A1 conservation (T-G8).** Fees flow through the standard channel; no chain-config field affects A1's accounting per se.
8. **Snapshot round-trip.** `Chain::serialize_state` writes `pending_param_changes_` as a canonical JSON array (`chain.cpp:1671–1685`); `restore_from_snapshot` parses it back (`chain.cpp:1835–1846`). Two nodes booting from the same snapshot have byte-identical `pending_param_changes_`. The `p:` namespace contribution at `chain.cpp:361–390` (state_root) cryptographically binds the pending map into the state-root, so any divergence would surface as a state-root mismatch at the S-033 gate.

The eight mechanisms compose: two honest nodes applying the same block sequence call `stage_param_change` with the same arguments in the same order (1, 2), then `activate_pending_params` at the same heights (3, 4) with the same hook side effects (5), then `erase` the same buckets (6), preserving A1 (7), with the pending state cryptographically bound into every snapshot they exchange (8). The full deterministic-replay property follows.

---

## 6. What this doesn't prove

The theorems above target the apply-layer mechanics of PARAM_CHANGE. They do not extend to:

- **PARAM_CHANGE wire format.** The canonical payload `[name_len, name, value_len, value, effective_height, sig_count, sig_count × (keyholder_index, ed_sig)]` is documented in `Governance.md` (FA10) §1 and `docs/PROTOCOL.md` §3.3. The present proof references the wire format only insofar as the apply-side defensive shape check at `chain.cpp:907–914` re-parses it; the canonical definition lives in FA10.

- **Keyholder signature scheme.** The N-of-N Ed25519 threshold check at `validator.cpp:688–710` is the consent surface; its soundness reduces to A1 (EUF-CMA, Preliminaries §2.2) per FA10 T-10. The present proof's T-G3 cites the threshold mechanism as a black box; the cryptographic reduction is FA10's scope.

- **Per-param semantics.** What happens if `block_subsidy` is changed mid-chain? What if `MIN_STAKE` is increased above existing staked amounts? What if `param_keyholders` is rotated to an empty list (effectively bricking governance)? These are per-parameter design questions whose answers are codified in `docs/PROTOCOL.md` per-field semantics + `docs/SECURITY.md` operator-guidance entries. The present proof's T-G4 establishes that the field mutation occurs deterministically; the downstream consequences of the new value are out of scope.

- **Genesis-hash binding of `governance_mode`.** Section 3 argues that `governance_mode` is genesis-pinned and mixed into the genesis hash. The cryptographic argument that an operator pointing at the "wrong" genesis fails the genesis-hash boot gate is `docs/PROTOCOL.md` §3.1's scope.

- **`pending_param_changes_` snapshot round-trip.** The S-033 + `p:` namespace argument in §5(8) cites the snapshot equivalence as a structural fact; the cryptographic proof of round-trip identity is `SnapshotEquivalence.md` (FA-Apply-2)'s T-S1 / T-S2.

- **Cross-shard PARAM_CHANGE.** In a multi-shard chain, parameter changes are per-shard (each shard's chain has its own `pending_param_changes_`). The cross-shard coordination story (operators sending PARAM_CHANGE txs to every shard in lock-step) is a deployment concern, not an apply-layer mechanism. The present proof is single-shard.

- **What if the hook misbehaves.** T-G6 establishes the hook writes the correct value when invoked. The hook is installed by `node.cpp:195–247`'s fixed body; a hostile or buggy Node could install a divergent hook (e.g., one that writes wrong values), but every honest Node installs the canonical body. The honest-hook assumption is identical to the broader H1–H4 honest-node assumptions in Preliminaries §3.

- **Liveness of governance proposals.** The proof covers the apply-side mechanics once a PARAM_CHANGE is finalized. The off-chain proposal mechanism (operators coordinating on the value, gathering N-of-N signatures, broadcasting the tx, waiting for inclusion) is a human-process concern, not a chain mechanism. The chain's role is to make finalized PARAM_CHANGE txs activate cleanly; how the operators agree on the proposal is FA10's scope (specifically the "human-trust layer" caveat at FA10 §6).

---

## 7. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V1–V15 + assumption A1 (Ed25519 EUF-CMA) that backs FA10's threshold-gate soundness, on which T-G1 depends. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 (no underflow via `charge_fee`), I-2 (nonce monotonicity gate that precedes the PARAM_CHANGE branch), I-5 (PARAM_CHANGE is a "fee-only debit" channel), I-6 (A1 closure that T-G8 builds on). |
| `NonceMonotonicity.md` (FA-Apply-3) | T-N1 (strict-equality gate at `chain.cpp:739`) + T-N3 (per-account independence) — both inherited unchanged by the PARAM_CHANGE apply branch. |
| `StakeLifecycle.md` (FA-Apply-4) | Closest structural template — STAKE's `unlock_height` deferred-effect ≈ PARAM_CHANGE's `effective_height` deferred-activation. The state-machine proof style transfers directly. |
| `DAppRegistryLifecycle.md` (FA-Apply-5) | Apply-side state-machine proof style (T-D-prefixed theorem labels, code-witness + test-witness pairs per theorem); the present proof adopts the same shape with T-G-prefixed labels. |
| `Governance.md` (FA10) | Upstream soundness theorems T-10 (no unauthorized mutation) + T-11 (off-whitelist immunity) + T-10.1 (activation determinism). The present proof depends on FA10 for the validator-side gate and refines T-10.1 into the eight apply-side determinism mechanisms enumerated in §5. |
| `SnapshotEquivalence.md` (FA-Apply-2) | T-S1 / T-S2 — `pending_param_changes_` survives snapshot round-trip via the `p:` namespace (cited in §5(8)). |
| `EconomicSoundness.md` (FA11) | A1 closure under the fee channel (T-G8). |
| `docs/PROTOCOL.md` §3.3 | Apply rules for PARAM_CHANGE. |
| `docs/PROTOCOL.md` §4.1.1 | State-root namespace table including the `p:` namespace. |
| `docs/SECURITY.md` | A5 governance soundness writeup (operator-facing summary). |
| `tools/test_pending_param_changes.sh` | T-G1 (`determ test-pending-param-changes` — 13 assertions on the staging primitive). |
| `tools/test_param_change_apply.sh` | T-G4 + T-G5 + T-G6 + T-G7 (`determ test-param-change-apply` — ~16 assertions on the activation drain, including hook-fire and determinism). |
| `tools/test_governance_param_change.sh` | End-to-end 3-node 3-of-3 governed chain (T-G1 through T-G8 in composition with the validator pipeline). |
| `tools/test_supply_lifecycle.sh` | T-G8 (A1 closure across PARAM_CHANGE-bearing blocks). |
| `include/determ/chain/chain.hpp:369–386` | `ParamChangedHook` typedef + `set_param_changed_hook` setter + `stage_param_change` declaration + `pending_param_changes()` accessor. |
| `include/determ/chain/chain.hpp:618–624` | `pending_param_changes_` + `param_changed_hook_` field declarations. |
| `include/determ/chain/genesis.hpp:210–223` | `governance_mode` + `param_keyholders` + `param_threshold` genesis fields + whitelist comment. |
| `src/chain/chain.cpp:212–217` | `Chain::stage_param_change` helper (T-G1's mutation). |
| `src/chain/chain.cpp:471–497` | `Chain::activate_pending_params` drain (T-G4 through T-G7). |
| `src/chain/chain.cpp:676` | Single drain call site at apply entry (`b.index > 0`). |
| `src/chain/chain.cpp:895–928` | PARAM_CHANGE apply branch (T-G1's flow). |
| `src/chain/chain.cpp:1671–1685` | Snapshot serialize for `pending_param_changes_`. |
| `src/chain/chain.cpp:1835–1846` | Snapshot restore for `pending_param_changes_`. |
| `src/node/node.cpp:195–247` | `ParamChangedHook` installation (T-G6's body). |
| `src/node/validator.cpp:621–712` | PARAM_CHANGE validator gate (mode + payload-shape + whitelist + threshold). |

---

## 8. Status

All eight theorems (T-G1 through T-G8) are closed in the current codebase:

- **T-G1** (validator-accepted PARAM_CHANGE stages exactly one entry) closed via the PARAM_CHANGE branch at `chain.cpp:900–928` with the single `stage_param_change` call at line 921; regression `test_pending_param_changes.sh` (13 assertions on the staging primitive) + `test_governance_param_change.sh` (end-to-end stage path).
- **T-G2** (off-whitelist + uncontrolled-mode silently rejected at validator) closed via the structural-induction argument from FA10 T-11 + the `validator.cpp:625–628` (mode reject) and `validator.cpp:668–671` (whitelist reject) gates; defensive activation-switch no-op at `chain.cpp:483–493` provides the second layer.
- **T-G3** (threshold enforcement: sub-threshold sigs silently rejected) closed via the signature-loop + threshold gate at `validator.cpp:688–710`; concrete-security bound `≤ Q · 2⁻¹²⁸·(N-1)` per FA10 §7.
- **T-G4** (activation drain on height match: in-order, deterministic, exactly-once) closed via the `std::map`-ordered loop at `chain.cpp:472–495` with `push_back`-ordered inner vector iteration; regression `test_param_change_apply.sh` "Activation" + "Multi-param same-height" + "Multi-param different-height" blocks.
- **T-G5** (future-effective preserves staging) closed via the loop predicate `it->first <= current_height` at `chain.cpp:473`; regression `test_param_change_apply.sh` "Staging contract" block.
- **T-G6** (validator-field forwarding via ParamChangedHook) closed via the hook body at `node.cpp:198–247` with explicit branches for the six validator/Node-mirror names + the unconditional invocation site at `chain.cpp:493`; regression `test_param_change_apply.sh` "Hook for known params" + "Unknown name" blocks.
- **T-G7** (idempotent activation, drained-once-only) closed via `chain.cpp:495`'s `erase(it)` removing the drained bucket from the map; the post-erase `begin()` re-read at the next apply cannot encounter the removed key.
- **T-G8** (A1 invariance under PARAM_CHANGE apply) closed via the restriction to the fee-only-debit channel (no `accumulated_*`, no `accounts_`/`stakes_` mutation outside `charge_fee`) + the apply-tail A1 closure at `chain.cpp:1399`; regression covered indirectly via every test that includes PARAM_CHANGE and lands the block successfully.

No theorem is open or partial. The proof's foundation rests on a small set of code primitives: the `pending_param_changes_` std::map (sorted-key + push_back-preserved-bucket-order), the `activate_pending_params` drain (the unique writer to `min_stake_` / `suspension_slash_` / `unstake_delay_` post-genesis, modulo snapshot restore), the `ParamChangedHook` (the unique validator/Node-mirror writer for the six no-chain-storage names), and the validator-side mode + whitelist + multisig gate (the unique consent surface). The breadth of consequences — eight theorems, a deterministic-replay-safe two-phase mechanism, an apply-side gotcha (the forwarding hook necessity) formally pinned, an uncontrolled-vs-governed mode argument that explains why mode itself cannot be mutable — is testimony to how few primitives the chain needs to express live parameter governance without compromising replay determinism or A1 conservation.
