# GovernanceWhitelistSoundness — A5 mutable-parameter whitelist closure, bounds posture, and state-root binding (GW-1..GW-3)

This document proves three properties of the A5 governance parameter system that are adjacent to — but distinct from — the soundness theorems in `Governance.md` (FA10) and the apply-layer mechanics in `GovernanceParamChange.md` (FA-Apply governance). FA10 establishes that *no* whitelisted parameter mutates without N-of-N keyholder consent (a cryptographic-forgery reduction); the apply-layer proof establishes that an accepted change *stages and activates deterministically* (a state-machine argument). The present proof targets the **whitelist surface itself** and the **value channel**:

1. **(GW-1) Whitelist closure.** The set of mutable parameter names is a *closed, finite, code-pinned enumeration*. Exactly nine names are mutable; every other parameter name — including the consensus-defining ones (committee size `K`, sharding mode, chain identity, crypto primitives) — is rejected at validate time by a single set-membership test, even under a full N-of-N keyholder signature. A non-whitelisted name therefore has *no reachable mutation path* on any honest chain.

2. **(GW-2) Bounds posture.** Staged values are subjected to a **width / well-formedness** check before they can mutate a chain-instance scalar, but **not** a semantic range / sanity check. This proof states the boundary honestly: the protocol's value-acceptance model is *consent-over-bounds* — the N-of-N keyholder threshold is the value-correctness oracle, not a numeric range gate. The one mechanical check that does exist (the 8-byte little-endian width requirement) is cited precisely; the *absence* of a per-parameter range gate (e.g. nothing rejects `MIN_STAKE = 0` or `MIN_STAKE = 2⁶⁴−1`) is flagged as a deliberate design boundary rather than a closed theorem.

3. **(GW-3) Determinism + state-root binding.** Every accepted change flows through the `p:` state-root namespace into `Chain::compute_state_root`, so two honest nodes that apply the same block sequence converge on byte-identical parameter state and byte-identical state roots, and the per-height committee-signed `state_root` anchor binds the pending-change set cryptographically. This composes with `ParamChangeDeterminism.md` (the determinism sibling shipped this round) and `S033StateRootNamespaceCoverage.md` (the ten-namespace coverage-completeness theorem), and is the mechanism that lets a syncing node detect a divergent operational-parameter value despite the **S-039** caveat that `compute_genesis_hash` does not bind every operational parameter.

The proof exists because the whitelist is a security-critical *closed set* whose closure property is asserted across several docs (`Governance.md` §1, `GovernanceParamChange.md` T-G2, `genesis.hpp` comment) but never isolated as a standalone theorem with the exact code witness, and because the bounds question ("can keyholders set a nonsensical value?") recurs in operator review and deserves an honest, code-grounded answer rather than an implied guarantee.

**Companion documents.** `Preliminaries.md` (F0) §2.0 for the canonical assumption labels A1 (Ed25519 EUF-CMA, §2.2) and A2 (SHA-256 collision resistance, §2.1) that underwrite GW-1's consent surface and GW-3's Merkle binding; `Governance.md` (FA10) for the upstream T-10 (no unauthorized mutation) + T-11 (off-whitelist immunity) + T-10.1 (activation determinism) — GW-1 is the standalone closure statement that FA10 T-11 proves as a corollary of off-whitelist immunity, and GW-1 cites the same `kWhitelist` code witness; `GovernanceParamChange.md` (FA-Apply governance) for T-G1 (staging), T-G2 (off-whitelist + uncontrolled-mode reject), T-G3 (threshold enforcement), and T-G4..T-G8 (the activation drain mechanics) that GW-3's determinism leans on; `ParamChangeDeterminism.md` (the determinism sibling this round) for the per-block parameter-state convergence corollary that GW-3 composes with; `S033StateRootNamespaceCoverage.md` (state-root coverage completeness) for T-1 (the `p:` namespace is in scope) + T-2 (namespace disjointness) + T-3 (deterministic leaf ordering) that GW-3 invokes; `StateRootAnchorSoundness.md` for the per-height anchor that binds the `p:` leaves; `AccountStateInvariants.md` (FA-Apply-1) for the fee-channel + apply-determinism baseline; `docs/SECURITY.md` §S-039 for the genesis-hash operational-param binding gap that GW-3 §5 reconciles against; `docs/PROTOCOL.md` §3.3 (PARAM_CHANGE apply rules) + §4.1.1 (state-root namespace table).

---

## 1. Setup

### 1.1 The whitelist constant

The mutable-parameter whitelist is a single `static const std::set<std::string>` defined inside the validator's PARAM_CHANGE branch (`src/node/validator.cpp:662-667`):

```cpp
static const std::set<std::string> kWhitelist = {
    "tx_commit_ms", "block_sig_ms", "abort_claim_ms",
    "bft_escalation_threshold", "SUSPENSION_SLASH",
    "MIN_STAKE", "UNSTAKE_DELAY",
    "param_keyholders", "param_threshold",
};
```

Nine names, partitioned by where the mutated value lands:

| Whitelist name | Sink | Storage location | Activation writer |
|---|---|---|---|
| `MIN_STAKE` | chain-instance scalar | `Chain::min_stake_` | `activate_pending_params` (`chain.cpp:483`) |
| `SUSPENSION_SLASH` | chain-instance scalar | `Chain::suspension_slash_` | `activate_pending_params` (`chain.cpp:484`) |
| `UNSTAKE_DELAY` | chain-instance scalar | `Chain::unstake_delay_` | `activate_pending_params` (`chain.cpp:485`) |
| `bft_escalation_threshold` | validator field | `Validator::bft_escalation_threshold_` | `ParamChangedHook` (`node.cpp`) |
| `param_keyholders` | validator field | `Validator::param_keyholders_` | `ParamChangedHook` |
| `param_threshold` | validator field | `Validator::param_threshold_` | `ParamChangedHook` |
| `tx_commit_ms` | Node config | `Node::cfg_.tx_commit_ms` | `ParamChangedHook` |
| `block_sig_ms` | Node config | `Node::cfg_.block_sig_ms` | `ParamChangedHook` |
| `abort_claim_ms` | Node config | `Node::cfg_.abort_claim_ms` | `ParamChangedHook` |

The same nine-name enumeration is mirrored in the genesis documentation comment (`include/determ/chain/genesis.hpp:239-245`), which also enumerates the *off-list* parameters: "committee size K, consensus mode, sharding mode, chain identity, crypto primitives — require a new genesis = new chain." The three chain-instance names are also exactly the three `k:`-namespace scalars whose runtime value (not just the genesis-pinned value) appears in `build_state_leaves` — `min_stake`, `suspension_slash`, `unstake_delay` at `chain.cpp:389-391` — which is what makes GW-3's binding tight for the consensus-relevant subset.

> **Whitelist-vs-prompt note.** The task brief lists `block_subsidy` and "merge thresholds" as example mutable scalars. The shipped `kWhitelist` does **not** include `block_subsidy`, `merge_threshold_blocks`, `revert_threshold_blocks`, or `merge_grace_blocks`: those are genesis-pinned constants emitted into the `k:` state-root namespace (`chain.cpp:385-394`) but are **not** on the PARAM_CHANGE whitelist, so they are immutable post-genesis (their mutation path is "new genesis = new chain", per `genesis.hpp:243-245`). GW-1 below proves closure of the *actual* nine-name set; this note records the discrepancy between the brief's illustrative list and the code so the closure theorem is not misread as covering `block_subsidy`.

### 1.2 The validator gate (the unique consent + admission funnel)

`Validator::check_transactions`' PARAM_CHANGE branch (`src/node/validator.cpp:621-711`) is the only entry point to apply-side acceptance. In order, it performs:

1. **Mode gate** (`validator.cpp:625-628`): `governance_mode_ == 0` ⇒ reject with `"PARAM_CHANGE rejected: chain is in uncontrolled governance mode"`. An uncontrolled chain rejects *every* PARAM_CHANGE regardless of name or signatures.
2. **Payload-shape / truncation checks** (`validator.cpp:633-656`): decode `[name_len:u8][name][value_len:u16 LE][value][effective_height:u64 LE][sig_count:u8]` plus the `sig_count × (keyholder_index:u16 LE, ed_sig:64B)` tail; any truncation or trailing-byte mismatch is rejected.
3. **Whitelist gate** (`validator.cpp:668-671`): `kWhitelist.find(name) == kWhitelist.end()` ⇒ reject with `"PARAM_CHANGE rejected: parameter '<name>' is not on the governance whitelist"`.
4. **Multisig threshold gate** (`validator.cpp:688-710`): per `(keyholder_index, ed_sig)`, check index range (`:696-697`), distinct index (`:698-699`), and Ed25519 verify against the canonical `(name ‖ value ‖ effective_height)` signing message (`:700-702`); count *verifying* sigs and reject if `good_sigs < param_threshold_` (`:705-710`).

A block whose PARAM_CHANGE fails any gate fails `check_block`, is rejected by the K-of-K committee, and is never finalized (FA1 + FA5). The apply branch (`chain.cpp:900-928`) is therefore reachable only for txs that passed all four gates.

### 1.3 The value channel

The 16-bit `value_len` admits a value of up to 65 535 bytes. The validator does *not* constrain the value beyond the `value_len`-consistency check at `validator.cpp:644-646`; it explicitly drops the decoded value (`(void)value;` at `validator.cpp:658`) after using it only to build the signing message. Semantic interpretation of the bytes happens later, at activation, and is *per-parameter*: the three chain-instance scalars decode via the `parse_u64` lambda (`chain.cpp:476-482`), which requires `value.size() == 8` and reads a little-endian `uint64`. This 8-byte width requirement is the only mechanical well-formedness gate on the value bytes for the chain-instance names, and it is **fail-silent** (a wrong-width value produces no mutation; see GW-2).

---

## 2. Theorems

### GW-1 — Whitelist closure (only enumerated names are mutable)

**Statement.** Let `kWhitelist` be the nine-element set at `validator.cpp:662-667`. For every parameter name `n`:

- If `n ∉ kWhitelist`, then no finalized block on any honest chain mutates any chain-instance scalar, validator field, or Node-config field as a consequence of a PARAM_CHANGE transaction naming `n` — regardless of how many valid keyholder signatures the tx carries, and regardless of `governance_mode`. The name `n` has no reachable mutation path.
- The set `kWhitelist` is closed and finite: it is a compile-time `static const` literal, not assembled from runtime input, so no transaction, configuration, or chain-state value can extend it. Adding a mutable parameter requires a source change + recompile (and, for the chain-instance subset, an `activate_pending_params` case + a `build_state_leaves` leaf — see GW-3).

**Proof.** Two independent layers, either of which alone suffices on an honest chain; together they are conservative-by-design (a regression in one is caught by the other), mirroring FA10 T-11.

*Layer 1 — validator rejection (the live defense).* The whitelist gate at `validator.cpp:668-671` executes for every PARAM_CHANGE that passes the mode + shape gates, *before* the multisig gate. The test is `kWhitelist.find(name) == kWhitelist.end()`; for `n ∉ kWhitelist` it returns true and the branch returns `{false, ...}`. Because `kWhitelist` is a `static const std::set<std::string>` initialized from a brace-enclosed literal, its membership is fixed at program load and is independent of `tx`, `governance_mode_`, `param_keyholders_`, `param_threshold_`, or any chain state. No input path writes to it (audit: it is `const`, declared `static` inside the function body, with no `&` taken). Therefore an off-list `n` is rejected uniformly across all honest nodes, the containing block fails `check_block`, and apply is never invoked on it (the FA1/FA5 finalization argument). The rejection is also *signature-independent*: it fires before the multisig loop, so even a correct N-of-N signature set over an off-list name is rejected.

*Layer 2 — apply-path closure (the belt-and-suspenders).* Suppose, counterfactually, an off-list `n` reached the apply-side PARAM_CHANGE branch (e.g. a future regression weakened Layer 1). The apply branch (`chain.cpp:900-928`) re-parses the header and calls `stage_param_change(eff, n, value)` (`chain.cpp:921`), inserting into `pending_param_changes_[eff]`. At activation, `activate_pending_params` (`chain.cpp:471-497`) dispatches on `name`: the `if`/`else if` chain at `chain.cpp:483-485` has cases *only* for `"MIN_STAKE"`, `"SUSPENSION_SLASH"`, `"UNSTAKE_DELAY"`. For any other `name` — including every off-list `n` — none of the three branches match, so no chain-instance scalar is written. The unconditional hook fire at `chain.cpp:493` forwards `(n, value)` to `param_changed_hook_`, whose body in `src/node/node.cpp` likewise dispatches on `name` with explicit branches only for the six validator/Node-mirror names; an unrecognized `name` produces no validator or Node mutation. Hence even under the counterfactual, an off-list name mutates nothing — the only residual effect is the fee debit + nonce bump from the apply branch, which is supply-neutral (GovernanceParamChange T-G8). ∎

**Code witness.** `src/node/validator.cpp:662-667` (`kWhitelist` definition); `src/node/validator.cpp:668-671` (whitelist reject); `src/node/validator.cpp:625-628` (uncontrolled-mode reject, the mode half of "regardless of `governance_mode`"); `src/chain/chain.cpp:483-485` (chain-instance dispatch with only three cases); `src/chain/chain.cpp:493` (unconditional hook fire); `include/determ/chain/genesis.hpp:239-245` (the off-list enumeration the whitelist is the complement of).

**Test witness.** `tools/test_governance_param_change.sh` exercises the positive path (governed mode + whitelisted `MIN_STAKE` → accepted + activated). The off-list negative is structurally unreachable on any honest chain, established by the Layer-1 set-membership argument; `GovernanceParamChange.md` T-G2's test commentary covers the same gate. A regression loosening either layer would surface as PARAM_CHANGE acceptance of a name not in the nine-element literal.

### GW-2 — Bounds posture: width-checked, not range-checked (consent-over-bounds)

**Statement.** For the three chain-instance scalar names, a staged value mutates the destination scalar *only if* it is exactly 8 bytes wide (little-endian `uint64`); a wrong-width value is silently ignored (no mutation, fail-soft). Beyond this width gate, **no semantic range / sanity check is applied** to a PARAM_CHANGE value at either validate or activate time. Consequently:

1. (Positive — well-formedness.) `activate_pending_params` cannot write a partially-decoded or mis-sized value into `min_stake_` / `suspension_slash_` / `unstake_delay_`; the `parse_u64` lambda's `value.size() != 8` guard (`chain.cpp:477`) returns `false` and leaves the destination unchanged.
2. (Honest gap — no range gate.) Any 8-byte value in `[0, 2⁶⁴−1]` is accepted for these scalars under a passing N-of-N signature. In particular nothing in the validate path (`validator.cpp:621-711`) or the activate path (`chain.cpp:471-497`) rejects `MIN_STAKE = 0`, `MIN_STAKE = 2⁶⁴−1`, `UNSTAKE_DELAY = 2⁶⁴−1`, or any other in-range-but-operationally-nonsensical value. The keyholder threshold is the value-correctness oracle, not a numeric bounds gate.

**Proof.**

*Part 1 (width gate).* The chain-instance activation path routes through the `parse_u64` lambda (`chain.cpp:476-482`):

```cpp
auto parse_u64 = [&](uint64_t& dst) {
    if (value.size() != 8) return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
    dst = v;
    return true;
};
if (name == "MIN_STAKE")            { parse_u64(min_stake_); }
else if (name == "SUSPENSION_SLASH") { parse_u64(suspension_slash_); }
else if (name == "UNSTAKE_DELAY")    { parse_u64(unstake_delay_); }
```

If `value.size() != 8`, `parse_u64` returns immediately *before* assigning `dst`, so `min_stake_` / `suspension_slash_` / `unstake_delay_` retain their prior value. The lambda's return value is discarded by the three call sites — the design is "assign on well-formed, no-op on malformed," and there is no error propagation, which is the documented fail-soft posture (`chain.cpp:466-470`: "unknown names are activated as no-ops … fail-soft at apply, fail-loud at validate"). Width is therefore a precondition for mutation, establishing Part 1.

*Part 2 (no range gate — gap).* By exhaustive inspection of the two code paths a PARAM_CHANGE value traverses:

- **Validate** (`validator.cpp:621-711`): the value is decoded at `:644-646` solely to (a) confirm `value_len` consistency and (b) feed the canonical signing message at `:684`. It is then explicitly discarded (`(void)value;` at `:658`). No comparison of the decoded value against any per-parameter floor/ceiling/positivity constraint appears anywhere in the branch. The branch's only rejections are mode, truncation, whitelist, and signature-threshold.
- **Activate** (`chain.cpp:471-497`): `parse_u64` checks width only; the assignment `dst = v` is unconditional once width passes. No subsequent clamp, range check, or rejection exists.

Therefore any 8-byte value is accepted for the chain-instance scalars given keyholder consent. This is consistent with `Governance.md` §6, which states the chain "is structurally unable to prevent N-of-N keyholders from coordinating to set `MIN_STAKE = 2⁶⁴ − 1` or similar denial-of-service moves." The validator/Node-mirror names (`param_threshold`, `param_keyholders`, `bft_escalation_threshold`, timing fields) are likewise width/format-parsed in the hook body (`node.cpp`) without semantic range gating; e.g. nothing prevents setting `param_threshold` above `param_keyholders.size()` (which would brick future governance) or `param_keyholders` to an empty list. These are flagged identically: format-checked, not sanity-checked. ∎

**Honest-gap classification.** GW-2 Part 2 is **not a closed theorem** — it is a documented design boundary. The protocol's value-acceptance model is *consent-over-bounds*: governance is opt-in human trust in the genesis-pinned founder set (FA10 §6), and the cryptographic layer enforces *who* may change a parameter, deliberately leaving *to what value* under keyholder discretion. A range-gate layer (per-parameter `[min, max]` validation at `validator.cpp` before the signing-message build) is a candidate hardening for a future revision and would compose cleanly with GW-1 (it is an additional rejection in the same funnel); it is recorded here as absent so that operator-facing review does not assume a guarantee the code does not provide. The width gate (Part 1) is the only mechanical value constraint and *is* closed.

**Code witness.** `src/chain/chain.cpp:476-485` (`parse_u64` width gate + the three chain-instance dispatches); `src/chain/chain.cpp:466-470` (fail-soft-at-apply comment); `src/node/validator.cpp:644-646` (value-length decode), `:658` (`(void)value;` — value discarded, not range-checked), `:621-711` (the full branch, exhaustively containing no range check); `docs/proofs/Governance.md` §6 (the consent-over-bounds boundary stated upstream).

**Test witness.** `tools/test_param_change_apply.sh` exercises the width path implicitly via its edge-value cases (the staging tests round-trip empty and over-length values through `pending_param_changes_`; a non-8-byte value staged for a chain-instance name activates as a no-op on the scalar). No test asserts a range rejection, consistent with the gap: there is no range rejection to assert.

### GW-3 — Determinism + state-root binding (p:-namespace ⇒ honest-node convergence)

**Statement.** Let `C_1`, `C_2` be two honest chains that apply the same finalized block sequence (each block having passed the §1.2 validator gate). Then after every block:

1. (Determinism.) `C_1.pending_param_changes_` and `C_2.pending_param_changes_` are byte-identical, and the activated values of `min_stake_` / `suspension_slash_` / `unstake_delay_` (and the validator/Node-mirror fields) are byte-identical.
2. (State-root binding.) The `p:` namespace slice of `build_state_leaves` (`chain.cpp:361-378`) emits one leaf per pending `(eff, idx)` entry whose value-hash commits the `(name, value)` pair, and the three chain-instance scalars are additionally committed as `k:`-namespace leaves (`chain.cpp:389-391`). Therefore `C_1.compute_state_root() == C_2.compute_state_root()`, and any divergence in the pending set or the activated scalars manifests as a state-root mismatch caught by the apply-time gate at `chain.cpp:1432-1444` (S-033) — up to A2 (SHA-256 collision resistance).

**Proof.**

*Part 1 (determinism).* This is the composition of `GovernanceParamChange.md` T-G1 (pure-function staging — `stage_param_change` is a deterministic `std::map::operator[].emplace_back`), T-G4 (in-order, exactly-once activation drain over the `std::map`'s ascending-key iteration), T-G5 (future-effective preservation), and T-G7 (idempotent erase-on-drain), together with `ParamChangeDeterminism.md`'s per-block parameter-state convergence corollary. Each step is a pure function of chain state + block content with no time-, allocator-, or platform-dependence (the `parse_u64` decode is fixed little-endian; the `std::map`/`std::vector` iteration orders are structural). Two honest nodes applying the same block sequence therefore call `stage_param_change` with identical arguments in identical order and `activate_pending_params` at identical heights with identical effects, yielding byte-identical pending sets and activated scalars.

*Part 2 (state-root binding).* The `p:` leaf emission (`chain.cpp:361-378`) is:

```cpp
for (auto& [eff, entries] : pending_param_changes_) {
    for (size_t idx = 0; idx < entries.size(); ++idx) {
        auto& [name, value] = entries[idx];
        // key = 'p' ':' + eff_be8 + idx_be4
        crypto::SHA256Builder b;
        b.append(static_cast<uint64_t>(name.size()));
        b.append(name);
        b.append(static_cast<uint64_t>(value.size()));
        if (!value.empty()) b.append(value.data(), value.size());
        leaves.push_back({key, hash_bytes(b)});
    }
}
```

The key is domain-separated by the `"p:"` prefix (disjoint from the other nine namespaces — `S033StateRootNamespaceCoverage.md` T-2) and totally ordered by `(effective_height, index)` big-endian, so the leaf set is a deterministic function of `pending_param_changes_` (T-3: `crypto::merkle_root` sorts leaves by key before reduction, and no two `p:` keys tie because `(eff, idx)` is unique per entry). The value-hash binds `name` and `value` under length-prefixing, so distinct `(name, value)` pairs almost-surely produce distinct value-hashes (A2). `compute_state_root` (`chain.cpp:413-415`) is `merkle_root(build_state_leaves())`; combining T-1 (the `p:` namespace is in the apply-determining state surface) with Part 1, byte-identical pending sets ⇒ byte-identical `p:` slices ⇒ byte-identical roots.

The three chain-instance scalars are *doubly* bound: once transiently via the `p:` entry while pending, and permanently via the `k:` constant leaves `const_leaf("min_stake", min_stake_)`, `const_leaf("suspension_slash", suspension_slash_)`, `const_leaf("unstake_delay", unstake_delay_)` (`chain.cpp:389-391`), which reflect the *activated* runtime value (these are member fields, mutated by `activate_pending_params`, not frozen genesis values). So after a change activates and its `p:` entry is drained, the new scalar value remains committed via the `k:` leaf — the state-root continues to bind the live parameter at every subsequent height. The apply-time gate at `chain.cpp:1432-1444` recomputes the root and rejects on mismatch against the committee-signed `Block.state_root`; the snapshot round-trip is covered by `serialize_state` (`chain.cpp:1679-1693`) + `restore_from_snapshot` (`chain.cpp:1850-1858`) reproducing the `p:` inputs byte-for-byte (`S033StateRootNamespaceCoverage.md` T-5), so a node bootstrapping from a snapshot recomputes an identical root. ∎

**Code witness.** `src/chain/chain.cpp:361-378` (`p:` leaf emission); `src/chain/chain.cpp:389-391` (`k:` leaves for the three activated chain-instance scalars); `src/chain/chain.cpp:413-415` (`compute_state_root`); `src/chain/chain.cpp:1432-1444` (S-033 apply-time gate); `src/chain/chain.cpp:1679-1693` (snapshot serialize of `pending_param_changes_`); `src/chain/chain.cpp:1850-1858` (snapshot restore).

**Test witness.** `tools/test_param_change_apply.sh` includes a determinism assertion (two chains with identical staging produce identical state_root). `tools/test_governance_param_change.sh` runs a 3-node 3-of-3 governed chain and verifies via snapshot inspect that the activated `MIN_STAKE` is reflected in chain state — the per-node state-root agreement is what lets the K-of-K committee finalize the PARAM_CHANGE-bearing block in the first place. `tools/test_dapp_snapshot.sh` exercises the sibling pattern (a namespace's snapshot round-trip must reproduce the tail head's stored state_root exactly), the same mechanism the `p:` namespace relies on.

---

## 3. The S-039 caveat and why GW-3 is the real binding

`docs/SECURITY.md` §S-039 records that `compute_genesis_hash` binds operational parameters only partially: it binds `chain_id`, `chain_role`, `shard_id`, the creators' pubkeys, governance fields *when non-default*, and `suspension_slash` / `unstake_delay` / merge thresholds *when non-default* — but it does **not** bind `m_creators` (committee size `K`) and several other operational params, and it omits a parameter entirely when that parameter still holds its default. The practical consequence: an operator pointing a node at a genesis file that differs only in an *unbound* (or default-valued) operational parameter does not get a genesis-hash mismatch at boot. S-039 is classified Low/Op (a diagnostic-UX gap), with a lock-in test shipped and the fix deferred as a wire-compat break.

GW-3 is the reason S-039 is *only* a diagnostic-UX gap and not a soundness hole for the whitelisted scalars. The three chain-instance scalars (`min_stake`, `suspension_slash`, `unstake_delay`) are bound into the **per-height** `state_root` via the `k:` namespace (`chain.cpp:389-391`), and the `state_root` is committee-signed and verified at every block (`chain.cpp:1432-1444`). So even where the *genesis hash* fails to bind the initial value (S-039), the *state-root anchor* binds the live value at every height: a node that disagrees with the network about `min_stake_` — whether from a wrong genesis default or a divergent activation — computes a different root and is rejected by the S-033 gate. The binding GW-3 establishes is therefore the load-bearing one for cross-node agreement on the whitelisted scalars; the genesis hash is a convenience/diagnostic layer on top, and its gap (S-039) does not weaken the per-height guarantee. For the *non-scalar* whitelist names (validator/Node-mirror fields), the analogous per-height binding is weaker — `param_threshold` / `param_keyholders` / `bft_escalation_threshold` / timing fields are not all emitted as state-root leaves — which is noted in §4 as out of GW-3's scalar scope.

---

## 4. What this proof does not cover

- **Cryptographic soundness of the consent surface.** GW-1 cites the multisig gate as a black box (the off-list rejection is set-membership, independent of signatures). The Ed25519-forgery reduction that proves *whitelisted* mutations require genuine N-of-N consent is `Governance.md` T-10 (FA10), under A1. GW-1 does not re-derive it.
- **A range / sanity gate.** GW-2 Part 2 is an honest gap, not a theorem. There is no per-parameter bounds check; a future revision adding one would extend the §1.2 funnel. The present proof asserts only the width gate (Part 1).
- **State-root binding of the non-scalar whitelist names.** GW-3's `state_root` argument is tight for the three chain-instance scalars (doubly bound via `p:` + `k:`). The six validator/Node-mirror names are bound transiently via `p:` *while pending*, but after activation+drain their live values live on the validator/`cfg_` and are not all re-emitted as state-root leaves; cross-node agreement on those rests on the determinism half (GW-3 Part 1 + the `ParamChangedHook` consistency argument in `GovernanceParamChange.md` T-G6), not on a permanent state-root leaf. `param_threshold` / `param_keyholders` / `bft_escalation_threshold` consistency is therefore a determinism property, not a `k:`-leaf property.
- **`governance_mode` immutability.** That the mode itself is genesis-pinned and not on the whitelist (so a governed chain cannot vote out of governance, and an uncontrolled chain cannot vote in) is argued in `GovernanceParamChange.md` §3 and `Governance.md` §1. GW-1 treats `governance_mode` as one more off-list name (it is absent from `kWhitelist`), inheriting the off-list-immunity conclusion.
- **Keyholder compromise / collusion.** Out of scope identically to FA10 §6: GW-2's consent-over-bounds posture means N-of-N compromised keyholders can set any in-range value. The proof covers the enforcement mechanism, not the human-trust assumption.
- **The S-039 fix.** §3 reconciles GW-3 against the S-039 genesis-hash gap; it does not implement or specify the deferred fix (which is a wire-compat-breaking expansion of `compute_genesis_hash`). See `docs/SECURITY.md` §S-039.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) §2.0 | Canonical assumption labels — A1 (Ed25519 EUF-CMA, §2.2) backs GW-1's consent surface via FA10; A2 (SHA-256 collision resistance, §2.1) backs GW-3's Merkle value-hash binding. |
| `Governance.md` (FA10) | T-10 (no unauthorized mutation, the forgery reduction GW-1 black-boxes) + T-11 (off-whitelist immunity, of which GW-1 is the standalone closure statement) + §6 (the consent-over-bounds boundary GW-2 formalizes). |
| `GovernanceParamChange.md` (FA-Apply governance) | T-G1/T-G4/T-G5/T-G7 (staging + drain determinism GW-3 Part 1 composes) + T-G2 (off-whitelist + mode reject, GW-1's apply-layer companion) + T-G6 (the `ParamChangedHook` consistency that §4 leans on for the non-scalar names) + T-G8 (supply-neutrality of the residual fee debit in GW-1 Layer 2). |
| `ParamChangeDeterminism.md` (this round) | Per-block parameter-state convergence corollary — GW-3 Part 1 composes with it for honest-node agreement on activated values. |
| `S033StateRootNamespaceCoverage.md` | T-1 (the `p:` namespace is in the apply-determining surface) + T-2 (namespace disjointness — `"p:"` distinct) + T-3 (deterministic sorted-leaf ordering) + T-5 (snapshot round-trip reproduces `p:` inputs) — all invoked by GW-3 Part 2. |
| `StateRootAnchorSoundness.md` | The per-height committee-signed `state_root` anchor (SR-1..SR-5) that binds the `p:`/`k:` leaves — the mechanism §3 invokes to defang S-039 for the scalar subset. |
| `AccountStateInvariants.md` (FA-Apply-1) | Apply-determinism baseline (byte-identical start + same block ⇒ byte-identical post-apply) underwriting GW-3 Part 1; the fee-only-debit channel for GW-1 Layer 2's supply-neutral residual. |
| `BlockchainStateIntegrity.md` | The four-surface S-021 + S-033 + S-038 composition the apply-time gate (`chain.cpp:1432-1444`) sits inside. |
| `docs/SECURITY.md` §S-039 | The genesis-hash operational-param binding gap reconciled in §3. |
| `docs/SECURITY.md` §S-010/§S-011 | Operator stake-pricing context for why `MIN_STAKE` is on the whitelist (governed-mode deployments may need to retune it) — adjacent to GW-2's gap. |
| `docs/PROTOCOL.md` §3.3 | PARAM_CHANGE apply rules. |
| `docs/PROTOCOL.md` §4.1.1 | State-root namespace table including `p:` and `k:`. |
| `src/node/validator.cpp:621-711` | The PARAM_CHANGE validator gate (mode + shape + whitelist + multisig) — GW-1 + GW-2 Part 2 witness. |
| `src/node/validator.cpp:662-667` | `kWhitelist` definition — GW-1's closed-set witness. |
| `src/node/validator.cpp:668-671` | Whitelist rejection — GW-1 Layer 1. |
| `src/chain/chain.cpp:471-497` | `activate_pending_params` — GW-1 Layer 2 + GW-2 Part 1 (`parse_u64` width gate at `:476-482`). |
| `src/chain/chain.cpp:361-378` | `p:` state-root leaf emission — GW-3 Part 2. |
| `src/chain/chain.cpp:389-391` | `k:` leaves for the activated chain-instance scalars — GW-3 Part 2's permanent binding. |
| `src/chain/chain.cpp:413-415` | `compute_state_root` — GW-3. |
| `src/chain/chain.cpp:1432-1444` | S-033 apply-time state-root gate — GW-3 + §3. |
| `src/chain/chain.cpp:1679-1693` / `:1850-1858` | Snapshot serialize / restore of `pending_param_changes_` — GW-3 Part 2 round-trip. |
| `include/determ/chain/genesis.hpp:239-246` | Genesis-doc whitelist + off-list enumeration + `governance_mode` field. |
| `include/determ/chain/chain.hpp:369-386` | `ParamChangedHook` typedef + `stage_param_change` decl + `pending_param_changes()` accessor. |
| `tools/test_governance_param_change.sh` | End-to-end 3-node 3-of-3 governed chain (GW-1 positive + GW-3 cross-node agreement). |
| `tools/test_param_change_apply.sh` | Activation drain + width edge-values + determinism (GW-2 Part 1 + GW-3 Part 1). |
| `tools/test_pending_param_changes.sh` | Staging primitive (GW-3 Part 1 base). |

---

## 6. Status

- **GW-1** (whitelist closure) — **closed.** The nine-name `kWhitelist` is a compile-time `static const` literal (`validator.cpp:662-667`); off-list names are rejected by set-membership at `validator.cpp:668-671` independent of signatures and mode, with the apply-path dispatch (`chain.cpp:483-485`) providing a second no-mutation layer. Off-list immunity matches FA10 T-11.
- **GW-2** (bounds posture) — **partial / honest gap.** Part 1 (the 8-byte width gate at `chain.cpp:477` gating chain-instance mutation, fail-soft on mismatch) is **closed**. Part 2 (no semantic range / sanity check on values) is an explicitly flagged **design boundary**, not a theorem: the consent-over-bounds model deliberately leaves value-correctness to the N-of-N keyholder threshold (consistent with `Governance.md` §6). A per-parameter range gate is a candidate future hardening and would slot into the §1.2 funnel.
- **GW-3** (determinism + state-root binding) — **closed for the chain-instance scalar subset.** The `p:` namespace (`chain.cpp:361-378`) commits every pending entry and the three activated scalars are permanently bound via the `k:` namespace (`chain.cpp:389-391`); honest-node convergence follows by composition with `GovernanceParamChange.md` T-G1/T-G4 + `ParamChangeDeterminism.md` + `S033StateRootNamespaceCoverage.md` T-1/T-3, enforced by the S-033 apply-time gate (`chain.cpp:1432-1444`). The non-scalar whitelist names are bound transiently via `p:` while pending and rest on the determinism half (T-G6 hook consistency) post-activation — noted in §4 as outside the `k:`-leaf scalar scope. §3 reconciles the binding against the S-039 genesis-hash gap: the per-height state-root anchor is the real cross-node guarantee, so S-039 remains a diagnostic-UX gap rather than a soundness hole for the whitelisted scalars.

The proof's contribution is to isolate the whitelist *as a closed set* (GW-1, previously only a corollary of FA10 T-11), to answer the recurring bounds question *honestly* (GW-2 — width-checked, not range-checked, with the gap named rather than papered over), and to tie the parameter channel to the per-height state-root anchor in a way that explains why the S-039 genesis-hash gap does not compromise cross-node agreement on the consensus-relevant scalars (GW-3 + §3).
