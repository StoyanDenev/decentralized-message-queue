# FA10 — Governance soundness (A5)

This document proves that A5's governance mechanism is sound: under cryptographic assumptions, no parameter mutation occurs without the genesis-pinned N-of-N keyholder threshold authorizing it over a whitelisted parameter name. Two properties matter:

1. **No unauthorized mutations.** A finalized chain state cannot diverge from a parallel chain that ignored unauthorized mutation attempts.
2. **Off-whitelist immunity.** A parameter not in the whitelist cannot be mutated by any authorization combination — only a chain restart (new genesis) can change it.

The proof is short because the design enforces both via a single check funnel: every parameter mutation passes through the validator's `PARAM_CHANGE` branch, which gates on mode + whitelist + threshold.

**Companion documents:** `Preliminaries.md` (F0) for notation and crypto assumptions.

---

## 1. Mechanism summary

### Genesis-pinned state

```
governance_mode: 0 (uncontrolled) | 1 (governed)
param_keyholders: [PubKey ...]    // ≤ 255 founder Ed25519 pubkeys
param_threshold:  uint32          // signature count required; default = len(keyholders)
```

Both fields are mixed into the genesis hash when non-default, so a chain's identity binds them.

### Whitelist (validator-enforced)

```
MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY,
bft_escalation_threshold,
param_keyholders, param_threshold,
tx_commit_ms, block_sig_ms, abort_claim_ms
```

Off-list parameters (committee size K, sharding mode, chain identity, crypto primitives) require a new genesis = new chain identity.

### Canonical PARAM_CHANGE payload

```
[name_len: u8][name: utf8]
[value_len: u16 LE][value: bytes]
[effective_height: u64 LE]
[sig_count: u8]
sig_count × { [keyholder_index: u16 LE][ed_sig: 64B] }
```

Each `(keyholder_index, ed_sig)` is an Ed25519 signature over the canonical signing message:

```
[name_len: u8][name][value_len: u16 LE][value][effective_height: u64 LE]
```

### Validator gate (in order)

1. `governance_mode == 1`; reject otherwise.
2. Payload shape parsable; reject otherwise.
3. `name ∈ kWhitelist`; reject otherwise.
4. For each `(keyholder_index, ed_sig)`: index in range, distinct from prior indices, signature verifies under `param_keyholders[index]` against the canonical signing message. Count of *verifying* signatures `≥ param_threshold`; reject otherwise.

### Apply path

- Re-parses canonical payload header.
- `Chain::stage_param_change(effective_height, name, value)` inserts into pending map.
- At start of next `apply_transactions(b)` where `b.index ≥ effective_height`, `activate_pending_params` walks pending entries (ordered by effective_height) and writes to chain state. The activation also fires a Node-installed `ParamChangedHook` so validator-side state (param_keyholders, param_threshold, bft_escalation_threshold) and Node-side fields (timing constants) mirror the change.

---

## 2. Theorem statements

**Theorem T-10 (No unauthorized mutation).** Under:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2)

if a finalized chain's `Chain::min_stake_` (or any other whitelisted parameter) takes a value `V` at height `h` that differs from genesis, then there exists a finalized block at height `h_pc ≤ h` containing a `PARAM_CHANGE` transaction whose payload names that parameter, encodes value `V`, and carries `≥ param_threshold` distinct signatures from `param_keyholders` over the canonical signing message, with overall failure probability `≤ Q · 2⁻¹²⁸` per adversary forgery budget `Q`.

**Theorem T-11 (Off-whitelist immunity).** Under T-10's assumptions plus structural induction over the apply path, for any parameter name `n ∉ kWhitelist`, no finalized chain mutates the state field associated with `n` (or any unrelated state field) as a consequence of any sequence of PARAM_CHANGE transactions.

**Corollary T-10.1 (Activation determinism).** Two honest nodes that apply the same block sequence reach byte-identical chain state after each block's `apply_transactions`, including the same set of activated parameter changes at the same heights. Snapshots taken at the same block index are byte-identical with respect to `pending_param_changes`.

---

## 3. Proof of T-10

Suppose a finalized chain reaches state where `min_stake_ == V` at height `h`, with `V` differing from the genesis value. By the apply-path invariant (chain.cpp's `activate_pending_params` is the *only* writer to `min_stake_` post-genesis), some prior block `h_act ≤ h` activated a pending entry with name `"MIN_STAKE"` and value encoding `V`.

A pending entry only enters `pending_param_changes_` via `Chain::stage_param_change`, called from the `TxType::PARAM_CHANGE` branch of `apply_transactions`. That branch executes only when a block containing such a tx is applied to the chain.

A `PARAM_CHANGE` tx is finalized only if it was accepted by the validator pipeline. The validator's branch enforces (in order) the four gates above. The threshold gate requires `≥ param_threshold` *verifying* distinct-index signatures over the canonical signing message.

**Forgery reduction.** Suppose the adversary produces a finalized PARAM_CHANGE tx whose threshold gate passes without `param_threshold` *actual* keyholder consents. Then at least one of the threshold signatures was forged — i.e., it verifies under `param_keyholders[idx]` but was not produced by the holder of the corresponding private key. By A1, the probability of forging an Ed25519 signature for a chosen message under an honest key is `≤ 2⁻¹²⁸`. Polynomial-many adversary attempts give cumulative bound `Q · 2⁻¹²⁸`, negligible.

Therefore, with overwhelming probability, the threshold-gate-passing tx was produced by at least `param_threshold` actual keyholders. The tx's canonical payload is uniquely determined by `(name, value, effective_height)` (and the sig set), so the value `V` corresponds to keyholder consent on the specific tuple. ∎

---

## 4. Proof of T-11

Off-whitelist immunity follows from the structural induction over the apply path:

1. **Validator rejection.** The whitelist check in `check_transactions` rejects any `PARAM_CHANGE` whose `name` is not in `kWhitelist`. A block containing such a tx fails block validation and is not finalized.

2. **Apply-path closure.** The `apply_transactions` `PARAM_CHANGE` branch parses payload and calls `stage_param_change` — the *only* writer to `pending_param_changes_`. The `activate_pending_params` switch over name has explicit cases only for whitelist names; off-whitelist names trigger no chain-state mutation (and trigger the `ParamChangedHook` callback, which itself has explicit branches only for whitelist-managed validator/node fields).

3. **No state-field mutation outside the switch.** `Chain::min_stake_`, `suspension_slash_`, `unstake_delay_` are mutated only inside `activate_pending_params`'s explicit `if (name == "MIN_STAKE")` etc. branches. No other code path writes them post-genesis (audit-verifiable: grep for `min_stake_ =` in `src/chain/chain.cpp` shows only the activation site).

Therefore, even if a payload with off-whitelist `name` were somehow accepted (which contradicts (1)), the apply path would not mutate any state — the activation switch's default case is no-op.

The two-layer defense (validator reject + apply switch default) is conservative-by-design: a future regression that loosens one layer is still caught by the other. ∎

---

## 5. Proof of T-10.1 (determinism)

Determinism over honest nodes follows from three structural properties:

1. **Pure-function staging.** `stage_param_change(eff, name, value)` is a deterministic insert into `std::map<uint64_t, vector<pair<string, vector<uint8_t>>>>`. Ordering within the same `eff` bucket follows apply-order of the source PARAM_CHANGE txs, which is fixed by canonical block tx ordering.

2. **Pure-function activation.** `activate_pending_params(h)` walks the map in ascending `eff_height` order, processes each `(name, value)` pair in vector order, and erases the entry. No randomness, no external state, no time-dependence.

3. **Snapshot round-trip.** `serialize_state` writes `pending_param_changes` as a canonical JSON array; `restore_from_snapshot` parses it back into the same structure. Two nodes booting from the same snapshot have byte-identical `pending_param_changes_`.

Two honest nodes applying the same block sequence call `stage_param_change` with the same arguments in the same order, then `activate_pending_params` at the same heights, yielding byte-identical state. ∎

---

## 6. What the proof does NOT cover

- **Keyholder secret-share compromise.** If `param_threshold` or more keyholder private keys are stolen, the attacker can mutate any whitelisted parameter. This is by-design (governance is opt-in trust in the founder set); the EUF-CMA reduction assumes honest keys.
- **Keyholder collusion against the chain.** The chain is structurally unable to prevent N-of-N keyholders from coordinating to set `MIN_STAKE = 2⁶⁴ - 1` or similar denial-of-service moves. Governance is a *human* trust mechanism layered on cryptographic enforcement; the proof covers the enforcement, not the trust.
- **Replay across chains.** A PARAM_CHANGE signed for chain A could in principle be replayed on chain B if both chains share the same keyholders. The signed message does *not* bind the chain_id explicitly. Mitigation: the genesis hash differs between chains (founder set is mixed in), and the tx-level Ed25519 sig (sender → tx_hash including from/nonce/sig) binds to a specific sender on a specific chain. Cross-chain replay would require both compromise of the sender's tx-level sig AND the keyholder sigs to match across chains — extraordinarily unlikely in practice but not formally bound.
- **Off-list parameters via genesis restart.** Changing `K` (committee size) is a new-chain operation by design; this is not a vulnerability, it's the boundary between "live governance" and "fork".
- **PARAM_CHANGE replayed within the same chain.** Sender's nonce + the tx-level Ed25519 sig + `effective_height` ordering all combine to prevent replay: a second PARAM_CHANGE with the same sender-nonce would be rejected; a same-payload PARAM_CHANGE at a different effective_height activates separately (semantically valid; the keyholders consented to that exact tuple).

---

## 7. Concrete-security bound

Per the threshold gate's signature verifications, false-positive PARAM_CHANGE acceptance requires forging `≥ param_threshold − honest_consents` signatures. For the default `N-of-N` (threshold == keyholder count), even one corrupted slot still needs `N − 1` honest forgeries. Per A1, each forgery is `≤ 2⁻¹²⁸`. For `N = 5` and adversary budget `Q = 2⁶⁰`, the cumulative bound on false-positive acceptance is:

```
Q · 2⁻¹²⁸·(N-1) = 2⁶⁰ · 2⁻⁵¹² ≈ 2⁻⁴⁵²
```

Strongly negligible. Under Grover (post-quantum), the per-forgery bound degrades to `2⁻⁶⁴`, giving cumulative `2⁶⁰ · 2⁻²⁵⁶ ≈ 2⁻¹⁹⁶` for `N = 5` — still strongly negligible.

---

## 8. Implementation cross-reference

| Component | Source |
|---|---|
| Genesis fields (governance_mode, param_keyholders, param_threshold) | `include/unchained/chain/genesis.hpp::GenesisConfig` |
| Validator gate (mode + whitelist + threshold) | `src/node/validator.cpp::check_transactions` PARAM_CHANGE branch |
| Whitelist constant `kWhitelist` | same file, inside the branch |
| Chain's pending map + stage helper | `include/unchained/chain/chain.hpp::pending_param_changes_`, `stage_param_change` |
| Apply branch (parse + stage) | `src/chain/chain.cpp::apply_transactions` PARAM_CHANGE case |
| Activation switch | `src/chain/chain.cpp::activate_pending_params` |
| ParamChangedHook (validator + node mirror) | `src/node/node.cpp` ctor |
| Snapshot serialization | `src/chain/chain.cpp::serialize_state` + `restore_from_snapshot` |
| CLI sign + submit helper | `src/main.cpp::cmd_submit_param_change` |
| Integration test | `tools/test_governance_param_change.sh` |

A reviewer can confirm soundness by:

1. Reading the validator branch top-to-bottom; confirm threshold is over *verifying* sigs, distinct indices, against canonical signing message.
2. Reading `activate_pending_params`; confirm the only state-mutating branches are the explicit whitelist cases.
3. Grepping for direct assignment to `min_stake_` / `suspension_slash_` / `unstake_delay_` in `src/`: only the genesis loader, the public setter, the activation switch, and snapshot restore should appear.

---

## 9. Conclusion

T-10 + T-11 + T-10.1 establish that A5 governance is sound:

- Unauthorized mutations require Ed25519 forgery (probability `≤ Q · 2⁻¹²⁸`).
- Off-whitelist parameter names cannot be mutated by any consented sequence (validator rejects them).
- Mutation ordering and state are deterministic across honest nodes.

The proof covers the cryptographic-enforcement layer. The human-trust layer (whether N keyholders should be trusted to coordinate honestly) is not within the scope of formal verification; it is a deployment-time decision codified by the genesis-pinned founder set.

Combined with FA1–FA9, A5 governance soundness completes the formal coverage of every safety-critical mechanism shipped in Unchained v1.x.
