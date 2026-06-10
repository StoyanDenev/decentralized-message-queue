# ConstantProofSoundness — trust-minimized `k:`-namespace constant read soundness (`determ-light verify-constant`)

This document formalizes the security of the **trust-minimized constant read**: the `determ-light verify-constant --name <N> (--value <u64> | --value-hex <64-hex>)` command lets an operator verify, against a *single untrusted daemon*, that the daemon's chain runs exactly the consensus/economic parameter the operator expects (`min_stake`, `unstake_delay`, the subsidy schedule, the shard topology) — without trusting the daemon's config files, logs, or status output. The read targets the `k:` (genesis-pinned constants) namespace of the S-033 state-commitment surface. The `k:` namespace already had a reader — `verify-param-value` (`light/main.cpp:4449`, the same pipeline: `"k:"+name` key-bind, S-042 anchor, `not_found` → UNVERIFIABLE) covers the 12 u64 constants; `verify-constant`'s delta is **`shard_salt` coverage** (the 32-byte leaf no prior reader could assert), the **closed compiled-in name whitelist** (unknown names rejected before any RPC), `anchored_head` `--resume`/`--state` support, and the distinct **MISMATCH-exit-2 contract** (`verify-param-value` exits 0 on MISMATCH; consumers gating on exit codes get a sound non-zero signal here). The last namespace to gain its FIRST reader was `b:` (`verify-abort-record`, FB65).

The trust posture is structural, not cryptographic: like the `b:` abort-record read (`AbortRecordProofSoundness.md`, FB65 — the closest structural sibling), the command composes existing primitives — the committee's Ed25519 signature set binds `state_root` to the operator's pinned chain via the successor-block `prev_hash` chain (the S-042 `committee_bound_state_root` binding, `StateRootAnchorSoundness.md` SR-1), and the sorted-leaves Merkle inclusion proof binds a single `k:` leaf to that root — into an end-to-end pipeline under a malicious-daemon adversary. No new cryptographic primitive is introduced. What distinguishes this reader within the family is its **shape**: `k:` has **no cleartext RPC**, so the read is **CONFIRM-shaped** (the closest precedent is `verify-param-value` itself — same namespace, same shape, same key-bind; `verify-merge-state` is the other operator-asserting reader, with `MergeStateSoundness.md` cited for what it proves: MS-3 `m:`-leaf injectivity and the `m:` chain-side soundness) — the operator asserts `(name, value)`, the verifier computes the expected leaf `value_hash` *locally, before any RPC*, and the verdict is a comparison of two hashes: the locally-computed one and the committee-attested one. Two consequences get their own theorems. First (CP-2), **both verdict arms are cryptographic**: `CONFIRMED` and `MISMATCH` each carry an A2-class soundness bound — there is no daemon-asserted arm. Second (CP-3), **there is no (H-neg) premise anywhere in this reader**: every `k:` leaf is unconditionally committed on every S-033 chain, so `not_found` can never be a sound negative — the reader maps *every* daemon refusal to `UNVERIFIABLE` (exit 3), never to a verdict. Like `verify-param-value` (whose identical `k:` UNVERIFIABLE discipline `NegativeVerdictSoundness.md`'s out-of-scope note already records), and unlike the eight NV-2/NV-3 (H-neg) readers, no branch of this reader rests on a daemon-honesty premise (contrast `AbortRecordProofSoundness.md` AB-3).

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage resistance §2.1) — this proof reduces to **A1** and **A2** only; `AbortRecordProofSoundness.md` (FB65, the `b:` sibling and structural template — its AB-1 key-bind + committee-anchor decomposition is mirrored as CP-1; its AB-3 negative-footing theorem is what CP-3 shows this reader does *not* need); `MergeStateSoundness.md` (the `m:` namespace chain-side soundness — MS-3 leaf injectivity, whose style is reused for the `k:` leaf; NOT a command-shape precedent — the CONFIRM-shape precedent is the `verify-param-value` command itself); `StakeProofSoundness.md` (SP-1/SP-2/SP-3, the family's original decomposition, inherited via FB65); `MerkleTreeSoundness.md` (MT-1 determinism, MT-2 domain separation, MT-4 inclusion-proof soundness, MT-5 positive-membership-only; §6.2 S-040 CLOSED — `leaf_count` bound into the committed root); `StateRootAnchorSoundness.md` (F6 — **SR-1** is exactly the committee-anchoring this reader routes through via `committee_bound_state_root`, plus SR-2/SR-3 inherited for the walk); `WaitHoldAndWaitSoundness.md` (FB64 — the `--wait` seconds this command forwards are proven soundness-neutral there; this command is one of the eleven direct binding sites in its WH-6 census, `light/main.cpp:2565`); `NegativeVerdictSoundness.md` (**NV-5a** canonical-key locality — here strengthened into a closed-list gate; NV-2/NV-3 cited by *contrast*: the (H-neg) row of its §10 table has no instance in this reader; **F-6** — the forge-class key-bind lesson CP-1 carries); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its §2.1 table fixes the `k:` and `k:c:` key + value-hash encodings, and its prefix-distinctness witness is CP-1's counter-separation argument); `LightClientThreatModel.md` (the malicious-daemon adversary `A_daemon`, T-L1 genesis anchor, T-L2 committee-sig head trust, T-L3 state-proof correctness, L-6 fail-closed exit); `docs/SECURITY.md` §S-033 / §S-038 / §S-040 / §S-041 / §S-042 closure narratives; `docs/PROTOCOL.md` §4.1.1 (`k:` Merkle-leaf rows) + §10.2 (`state_proof` RPC contract).

---

## 1. Scope

### 1.1 In scope

The `determ-light verify-constant --rpc-port P --genesis G --name N (--value V | --value-hex S) [--json] [--resume] [--state F] [--wait W]` composite command, `light/main.cpp::cmd_verify_constant` (`light/main.cpp:2413-2611`, header comment `:2382-2405`, dispatched at `:7535`), which executes:

0. **Local gates, before any network I/O.** (a) The **canonical-name gate**: `--name` must be one of the 12 entries of `kKnownU64Constants` (`light/main.cpp:2406-2411`) or the 13th constant `shard_salt` (`:2445-2447`); an unknown name is rejected with the full canonical list (exit 1, `:2448-2453`). (b) The **value-form gates**: a u64 constant requires `--value <u64>` (`:2455-2459`); `shard_salt` — a 32-byte leaf — requires `--value-hex <64-hex>` (`:2460-2464`). (c) The **expected leaf hash is computed locally from the operator-asserted value**: `SHA256(u64_be(value))` via `SHA256Builder::append(uint64_t)` for the u64 constants (`:2470-2473`), `SHA256(salt_32)` for `shard_salt` (`:2474-2478`, `from_hex_arr<32>` throws on bad hex/length). All of this happens *before* `load_genesis` / `rpc.open` (`:2481-2487`) — the daemon never sees, and cannot influence, the assertion being tested.
1. **Genesis anchor + committee-verified header walk** — `anchored_head(rpc, committee_seed, genesis, resume, state_path)` (`light/main.cpp:2490`; helper `light/trustless_read.cpp:278-333`): always re-pins genesis, then either a full `verify_chain_to_head` from block 0 or, with `--resume`, only the suffix above a cached anchor (T-L1 + T-L2). An empty `vc.head_state_root` throws the "chain has not activated state_root (S-033)" diagnostic (`:2492-2496`) — so by the time any proof is fetched, the operator's pinned chain is *known* to be S-033-active.
2. **`k:` state-proof fetch** — `rpc.call("state_proof", {{"namespace","k"},{"key",name}})` (`light/main.cpp:2501-2502`). The daemon's `Node::rpc_state_proof` (`src/node/node.cpp:3363-3454`) serves the simple-namespace key shape `"k:" + key` (`:3390-3398`) and returns `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)` in **one** JSON envelope (`:3443-3453`), computed under the daemon's `state_mutex_` read lock (`:3365`). An absent key returns `{"error":"not_found"}` (`:3434-3437`, from `Chain::state_proof`'s `nullopt` at `src/chain/chain.cpp:449`); a legacy daemon without the namespace returns `{"error":"unsupported namespace; …"}` (`:3430-3432`).
3. **Refusal dispatch — `UNVERIFIABLE`, never a negative.** *Any* error-marked reply (`proof.contains("error") && !proof["error"].is_null()`, `light/main.cpp:2503`) — `not_found`, `unsupported namespace`, anything — yields `UNVERIFIABLE` and **exit 3** (`:2504-2521`, return at `:2520`), with the diagnostic "constants are always committed on an S-033 chain". There is no `not_found`-specific branch and no substring matcher at all (contrast FB65's AB-F2): the absence/refusal distinction is irrelevant here because *neither* can ever be a verdict (CP-3). No verdict is emitted; `verified:false` is tagged in `--json` (`:2506-2513`).
4. **Key-bind (step 3a)** — `proof.key_bytes` must equal, byte-for-byte, the hex of the locally-built canonical key `"k:" ‖ N` (`light/main.cpp:2526-2539`; local key construction `:2527-2530`, compare `:2533`, mismatch throws `:2534-2538`). This is the F-6-pattern bind (`NegativeVerdictSoundness.md` F-6): without it a Byzantine daemon could serve a valid proof for a *different* constant's leaf whose committed value happens to equal the asserted one (§8, CP-F5).
5. **Merkle self-consistency** — `verify_state_proof(proof, {})` (`light/main.cpp:2542-2545`; `light/verify.cpp:330-394`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:131-161`, invoked at `light/verify.cpp:378-382`), which re-derives the leaf hash from the (now key-bound) `key_bytes` + `value_hash`, walks the sibling chain, and re-applies the S-040 root-wrapper with the caller-supplied `leaf_count` (`merkle.cpp:158-161`) before comparing to the proof's claimed root.
6. **Committee anchoring of the claimed root (S-042)** — a stale-state gate (`proof_height < vc.height` throws, `light/main.cpp:2551-2556`), then `committee_bound_state_root(rpc, committee_json, anchor_index = proof_height − 1, wait_seconds)` (`:2564-2566`; helper at `light/trustless_read.cpp:335-437`): fetch the FULL block at the anchor index and recompute its `block_hash` locally (`:339-364`), fetch + committee-sig-verify the successor header at index `proof_height` (`:408-415`), and require `successor.prev_hash == recomputed block_hash` (`:417-432`). The attested root must equal `proof.state_root` byte-for-byte or the command throws the SECURITY diagnostic (`light/main.cpp:2567-2572`). The `--wait` seconds forward only into this helper's hold-and-wait loop (`light/trustless_read.cpp:383-387`; FB64).
7. **The verdict** — `proof.value_hash` (now key-bound, Merkle-bound, committee-anchored) is compared against the locally-precomputed expected hash (`light/main.cpp:2578-2580`): equality ⇒ `CONFIRMED`, **exit 0**; inequality ⇒ `MISMATCH`, **exit 2** (`:2606`). No cleartext RPC is consulted in either arm (`:2574-2577` comment). Every throw propagates to exit 1 (`:2607-2610`, L-6).

### 1.2 The `k:` leaf encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:267-411`), the genesis-pinned-constants block at `:379-408`:

```cpp
// genesis-pinned constants (one leaf each, fixed keys).
auto const_leaf = [&](const char* name, uint64_t value) {
    crypto::SHA256Builder b;
    b.append(value);
    leaves.push_back({k_with_prefix("k:", name), hash_bytes(b)});
};
const_leaf("block_subsidy",                block_subsidy_);
// … subsidy_pool_initial, subsidy_mode, lottery_jackpot_multiplier,
// … min_stake, suspension_slash, unstake_delay, merge_threshold_blocks,
// … revert_threshold_blocks, merge_grace_blocks, shard_count, my_shard_id
//                                                       (:385-396, 12 calls)
// shard_salt is 32 bytes — own leaf form.                (:397-402)
{   crypto::SHA256Builder b;
    b.append(shard_salt_);
    leaves.push_back({k_with_prefix("k:", "shard_salt"), hash_bytes(b)}); }
// A1 supply counters.                                    (:404-408)
const_leaf("c:genesis_total",        genesis_total_);     // key = "k:c:…" !
// … c:accumulated_subsidy/slashed/inbound/outbound
```

so for a u64 constant named `N` with chain-member value `v`, and for `shard_salt` with 32-byte salt `σ`:

$$
\text{key}_k(N) = \texttt{"k:"} \,\|\, N, \qquad
\text{value\_hash}_k(N) = H(u64\_be(v)), \qquad
\text{value\_hash}_k(\texttt{shard\_salt}) = H(\sigma),
$$

with `SHA256Builder::append(uint64_t)` serializing big-endian (`src/crypto/sha256.cpp:30-34`) and `append(const Hash&)` appending the raw 32 bytes (`include/determ/crypto/sha256.hpp:17`). The light client's local recompute (`light/main.cpp:2470-2478`) invokes the *same* `append` overloads on the asserted value, so the two encodings are identical by construction, not by convention. This is the `k:` row of `PROTOCOL.md` §4.1.1 and of `S033StateRootNamespaceCoverage.md` §2.1 ("thirteen genesis-pinned scalar constants").

**Three structural facts to record precisely:**

1. **Unconditional emission.** Unlike the `a:`/`s:`/`r:`/`b:`/`m:` namespaces (loops over possibly-empty maps), the `k:` block is straight-line code: all 13 plain `k:` leaves (and the 5 `k:c:` counter leaves) are emitted on **every** root computation of **every** chain, at every height including a genesis-only chain. There is no reachable state in which a `k:` leaf is absent. This is the load-bearing premise of CP-3.
2. **The `k:c:` counter keys are disjoint, not colliding.** The five A1 supply counters are emitted via `const_leaf("c:…", …)` (`:404-408`), so their full leaf keys are `"k:c:genesis_total"` etc. — *inside* the `k:` prefix space but disjoint from every plain constant key: no admitted constant name begins with `"c:"` (none even begins with `c`), and `S033StateRootNamespaceCoverage.md`'s prefix-distinctness table exhibits the byte-2 witness (`'c'` vs the plain names' first letters) for exactly this pair. The canonical-name gate additionally forecloses *querying* a counter through this command (`"c:genesis_total"` is not in `kKnownU64Constants` and is not `shard_salt` → rejected at step 0 before any RPC); the supply counters have their own reader (`supply-trustless`, via the `c` namespace route of `rpc_state_proof`, `node.cpp:3399-3405`).
3. **Fixed-width u64 canonicalization.** Several underlying members are narrower than u64 (`merge_threshold_blocks_` is `uint32_t`, `chain.hpp:600`; `my_shard_id_` is `ShardId` = u32, `:609`); `const_leaf`'s `uint64_t` parameter widens them losslessly, and the verifier's `--value` is parsed and hashed as the same 8-byte big-endian widening. An external client computing `k:` leaves MUST hash the 8-byte widening, not the member's natural width (the `m:`-namespace sibling of this note is `MergeStateSoundness.md` F-3). A `--value` exceeding the member's natural range simply yields an honest `MISMATCH` (the committed value can never have those high bytes set).

### 1.3 Out of scope (inherited)

- **Non-membership proofs.** The sorted-leaves tree supports positive membership only (MT-5) — irrelevant here, because no branch of this reader ever needs an absence claim (CP-3): absence of a `k:` leaf is not a chain state, it is a daemon fault.
- **Stale-state lies across invocations, multi-peer redundancy, transport encryption, RPC auth, genesis-only committee map.** Inherited verbatim from `LightClientThreatModel.md` §6. Within one invocation the stale-height gate + S-042 binding are sound.
- **How the value got there** — genesis loading, the PARAM_CHANGE governance pipeline (`GovernanceParamChange.md`, `ParamChangeDeterminism.md`), and the S-041 snapshot-serialization closure of the merge-threshold constants are apply-layer concerns; this proof reads the *committed* `k:` leaf and does not re-prove its provenance. CP-4 states exactly what the leaf attests.

---

## 2. Threat model and adversary

The adversary is `A_daemon` (`LightClientThreatModel.md` §2.1): the single RPC endpoint is fully adversary-controlled and may return arbitrary JSON (forged headers, forged proofs, mislabeled errors), drop or stall requests, and adapt across calls. Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis`.

**Security goal.** Under `A_daemon`, an honest light client running `verify-constant --name N --value V` never acts on a **false verdict in either direction**: it never sees `CONFIRMED` when the genesis-pinned chain's committed value differs from `V`, and never sees `MISMATCH` when the committed value equals `V`. "Acts on" means displays as authoritative or feeds a downstream decision (e.g., accepting a daemon as correctly configured before delegating stake to it, or alarming on a governance parameter). The daemon retains exactly one degree of freedom: **refusal**, which yields `UNVERIFIABLE` (exit 3) and no verdict — an availability failure, not a soundness failure (L-6).

---

## 3. Verification primitives reused

The command reuses the family's four primitives unchanged — genesis anchor, committee-sig verify, header continuity (all inside `anchored_head`), and Merkle state-proof verify — plus the shared S-042 anchoring helper `committee_bound_state_root` that `verify-abort-record`, `verify-merge-state`, `verify-param-change`, and the other binding consumers route through (this command is the `:2565` row of FB64's WH-6 eleven-site census). The only `k:`-specific elements are the namespace argument, the compiled-in canonical name list, the local expected-hash precomputation (step 0c — the CONFIRM-shape's defining move), and the *absence* of any cleartext leg: where `verify-abort-record` ends with a cleartext hash-bind (FB65 AB-2), `verify-constant` ends with a pure hash comparison, because the assertion to test arrived from the operator, not from the daemon. Anchoring style is identical to the `b:`/`s:`/`a:` readers: stale-height gate, then `committee_bound_state_root` at `anchor_index = proof_height − 1`; when that anchor is still the chain head, the binding fails closed immediately or holds-and-waits under `--wait` (FB64).

---

## 4. Security theorems

Throughout, let `N` be the queried constant name, `V` the operator-asserted value (u64, or 32-byte salt for `shard_salt`), `e := H(enc(V))` the locally-precomputed expected hash (step 0c), `v_T` the true committed value of `N` in the chain's state at the anchor height (true leaf value-hash `H(enc(v_T))`), `R := state_root` at the anchor height, `n := leaf_count`, and `K` the committee size. `enc` is the fixed-width encoding of §1.2 (`u64_be`, or identity on 32 bytes) — **injective on its domain**.

### 4.1 Theorem CP-1 (key-bind + committee anchor: the verdict concerns exactly the leaf `"k:" ‖ N`)

**Statement.** Under (A1) + (A2), in the S-033-active regime, if `verify-constant --name N` emits *any* verdict (`CONFIRMED` or `MISMATCH`), then the Merkle-verified leaf whose `value_hash` decided that verdict is (i) the leaf with key **exactly** `"k:" ‖ N`, and (ii) committed under a `state_root` equal to the genuine committee-attested root of the operator's pinned chain at the anchor index — except with probability `≤ K·2⁻¹²⁸ + 2⁻¹²⁸ + log₂(n)·2⁻¹²⁸` per invocation.

**Proof.**

*(i) Key-bind + canonical-name gate.* `verify_state_proof` Merkle-verifies whatever `key_bytes` the daemon supplies — the leaf hash is recomputed over the served key, so a valid proof for a *different* leaf would pass the Merkle leg. Two gates foreclose this. First, the canonical-name gate (step 0a) admits only the 13 compiled-in names: the daemon has no input into which key is asked about (the NV-5a canonical-key discipline, here *strengthened* — the key suffix is not even an operator-free-form string but a member of a closed list baked into the binary, `light/main.cpp:2406-2411`). Second, the step-3a bind requires `proof.key_bytes == hex("k:" ‖ N)` byte-for-byte (`:2533`), throwing otherwise. The daemon therefore either serves the canonical key — and the Merkle leg now verifies a leaf hash incorporating that key — or fails closed. To pass the Merkle leg with the canonical key but a forged `value_hash`, the daemon must chain a forged leaf hash to the anchored root: an MT-4 extraction yields a SHA-256 collision, `≤ log₂(n)·2⁻¹²⁸` (A2). **Counter-key separation:** the five `k:c:` counter leaves share the `"k:"` prefix but cannot masquerade as any admitted constant — their keys carry `'c' ':'` at bytes 2-3 while no admitted name begins with `"c:"` (§1.2 fact 2; the byte-2 distinctness witness of `S033StateRootNamespaceCoverage.md`'s prefix table), so `key_bytes` equality with `"k:" ‖ N` is unsatisfiable by a counter leaf. Cross-namespace masquerade generally is foreclosed by MT-2 (the key is bound into the leaf preimage after the domain tag and length prefix). The S-040 root-wrapper re-application inside `merkle_verify` (`merkle.cpp:158-161`) makes a forged `leaf_count` equally a collision (inherited SP-3 closure).

*(ii) Committee anchor.* Identical to FB65 AB-1(ii), executed by the same helper: the stale-height gate (`light/main.cpp:2551-2556`) pins the proof at or above the committee-verified head; `committee_bound_state_root` performs the SR-1 binding at `anchor_index = proof_height − 1` — full-body `block_hash` recompute (`light/trustless_read.cpp:355-364`), committee-sig verify of the successor header (`:408-415`), `prev_hash` equality (`:417-432`). By the SR-1 case split (`StateRootAnchorSoundness.md` §4.1): a daemon that swapped the anchor's `state_root` field either keeps `block_hash(anchor)` unchanged (a SHA-256 collision, `≤ 2⁻¹²⁸`, A2) or must exhibit committee signatures over a successor digest containing the new `prev_hash` (`≤ K·2⁻¹²⁸`, A1). The command finally requires `attested == proof.state_root` byte-for-byte (`light/main.cpp:2567-2572`). Genesis- and height-binding of the walk are SR-2 + SR-3 + T-L1, inherited via `anchored_head`. Union bound over (i) + (ii) gives the statement.   ∎

### 4.2 Theorem CP-2 (the CONFIRM dichotomy is sound in BOTH directions — the distinguishing theorem)

**Statement.** Under (A2), given CP-1's bound leaf:

(a) **CONFIRMED ⇒ `v_T = V`**, except with probability `≤ 2⁻¹²⁸`. A `CONFIRMED` verdict for a value the chain does not commit requires a SHA-256 collision.

(b) **MISMATCH ⇒ `v_T ≠ V`**, with probability 1 (no cryptographic assumption needed beyond CP-1's binding). Equal values can never produce `MISMATCH`.

Unlike the DISCOVER-shaped readers (`stake-trustless`, `verify-abort-record`), no cleartext RPC participates and no arm of the dichotomy is daemon-asserted: the verdict is a deterministic function of two hashes, one computed locally before any RPC and one committee-attested.

**Proof.** By CP-1, `proof.value_hash = H(enc(v_T))` — the genuine committed leaf hash — except within CP-1's bound. The verdict compares it to `e = H(enc(V))` (`light/main.cpp:2578-2580`), computed at step 0c from the operator's own argument using the identical encoder (§1.2: `light/main.cpp:2470-2478` vs `src/chain/chain.cpp:380-383`/`:397-402`, both through `src/crypto/sha256.cpp:30-34`).

*(a)* `CONFIRMED` fires iff `H(enc(v_T)) = H(enc(V))`. Suppose `v_T ≠ V`. Then `enc(v_T) ≠ enc(V)` — `enc` is **injective**: `u64_be` is a bijection on the u64 domain (8 fixed bytes), and the salt encoding is the identity on 32 bytes. So the hash equality exhibits two distinct preimages with equal SHA-256 digests — **within the u64 domain, a value collision IS an A2 break**, not merely an encoding ambiguity. Probability `≤ 2⁻¹²⁸` (A2).

*(b)* Suppose `v_T = V`. Then `enc(v_T) = enc(V)` byte-for-byte, and SHA-256 is a deterministic function, so `H(enc(v_T)) = e` *with certainty* — the `MISMATCH` branch is unreachable. Hence an emitted `MISMATCH` implies `v_T ≠ V` unconditionally, given CP-1. (Unconditionally overall: a false `MISMATCH` requires the daemon to have defeated CP-1's binding itself — serving a wrong `value_hash` that still chains to the attested root — which is CP-1's bound, not a new term.)

**Honest subtlety (the asymmetry of the two arms).** `CONFIRMED` proves the committed value *equals* the asserted one. `MISMATCH` proves *inequality only* — it does **not** reveal `v_T`. The verifier holds `H(enc(v_T))` and no preimage-extraction capability (that would be an A3-class inversion, neither available nor claimed); the committed value stays hidden behind the hash. An operator who needs the actual running value must either assert candidates one at a time (each invocation soundly confirms or refutes one candidate) or consult a daemon-trusting surface (`status`, config) — which is exactly the trust this command exists to avoid. This is inherent to the CONFIRM shape, not a defect: `k:` has no cleartext RPC to bind (§8, CP-F4).   ∎

### 4.3 Theorem CP-3 (UNVERIFIABLE completeness: there is no (H-neg) premise anywhere in this reader)

**Statement.** A `not_found` (or any other refusal) can never be a sound negative for a `k:` query, and the reader correctly refuses any verdict on it: every error-marked daemon reply yields `UNVERIFIABLE`, exit 3 (`light/main.cpp:2503-2521`), with no verdict emitted. Consequently — unlike all eight state-proof readers covered by `NegativeVerdictSoundness.md` NV-2/NV-3 and unlike FB65's AB-3 — **no branch of `verify-constant` rests on the single-daemon negative-honesty premise (H-neg)**. Both verdict arms are cryptographic (CP-1 + CP-2); the only daemon-controllable outcome is the fail-safe non-verdict.

**Proof.** *Absence is never a chain state.* `build_state_leaves` emits all 13 plain `k:` leaves unconditionally, as straight-line code with no guard, on every root computation of every chain at every height (§1.2 fact 1, `chain.cpp:379-402`). So on any chain that computes state roots at all, the leaf `"k:" ‖ N` exists for every admitted `N`. The reader runs the S-033 activation gate *before* the fetch (`light/main.cpp:2492-2496`): if the committee-verified head carries no `state_root`, the command throws (exit 1) and never queries. Therefore, at the moment the `state_proof` call is made, the operator's pinned chain is known to commit state — and an honest daemon serving that chain *must* be able to produce the proof (`Chain::state_proof` finds every key present in the leaf vector, `chain.cpp:435-462`). A `not_found` ⇒ the daemon is not serving that chain's state surface: a legacy binary (whose `rpc_state_proof` lacks the `k` namespace, `node.cpp:3430-3432`), or a refusal, or a lie. None of these is information about the chain.

*The reader's response is correct.* The error branch (`:2503`) catches every error-marked reply uniformly and returns exit 3 with `verdict: "UNVERIFIABLE"`, `verified: false` (`:2506-2513`) — never `CONFIRMED`, never `MISMATCH`, never a fabricated "constant absent." The branch returns *before* steps 3a/4/5/6, so no binding cryptography has any purchase on it — but unlike NV-2's bypass concern, nothing value-bearing flows out of this branch for the bypass to taint. In the NV-§10 summary-table taxonomy, `verify-constant` contributes rows only to the "positive" class (both arms, by CP-2) and the `UNVERIFIABLE` class; it has **no row** in the (H-neg) absence class. Contrast AB-3/NV-2, where `NOT-RECORDED` is a real (forgeable-with-probability-1) verdict requiring the `negative_footing` tag — `verify-constant` emits no such tag because it has no such verdict.   ∎

### 4.4 Theorem CP-4 (honest semantic boundary: what a verdict means, and `--wait` neutrality)

**Statement.** On an honest chain, `CONFIRMED` for `(N, V)` means exactly: **the value of the `Chain` member backing `N`, as read by `build_state_leaves` when the state root at the committee-verified anchor height was computed, equals `V`** — nothing more. Three refinements: (a) "genesis-pinned" is the namespace's historical label, not an immutability guarantee — where governance is wired, the committed value is the *currently effective* one; (b) per-node fields attest *this daemon-chain's* value; (c) `--wait` changes none of this.

**Proof.** *Semantics.* The committed `value_hash` is `H(enc(member))` where `member` is whatever the Chain member held at root-computation time (§1.2). For most of the 13 constants that is the genesis-loaded value for the chain's whole life. But three are PARAM_CHANGE-mutable at apply time: `activate_pending_params` (`src/chain/chain.cpp:471-497`) overwrites `min_stake_`, `suspension_slash_`, `unstake_delay_` when a staged governance change activates (`:483-485`) — these three are the ONLY PARAM_CHANGE-mutable constants; the merge thresholds have plain C++ setters (`chain.hpp:321-326`, R4 genesis/test wiring), are not on the PARAM_CHANGE whitelist, and are genesis-pinned in production. A `CONFIRMED min_stake` therefore attests the **effective** stake floor at the anchor height — post any activated PARAM_CHANGE — which is precisely what a live-parameter audit wants, and *not* necessarily the genesis file's value. (The pending-but-not-yet-active changes live in the separate `p:` namespace, readable via `verify-param-change`.) *(b)* `my_shard_id_` (and the routing trio generally — genesis-pinned, never snapshotted, `chain.hpp:708-709`) is a per-daemon-chain field: in a sharded deployment, `verify-constant --name my_shard_id` soundly attests which shard *the queried daemon's* chain is — a feature (shard-identity audit), recorded so no one reads it as a network-global claim. *(c) `--wait` neutrality.* `wait_seconds` is parsed at `light/main.cpp:2431-2432` and forwarded **only** into `committee_bound_state_root` (`:2565-2566`), whose hold-and-wait loop (`light/trustless_read.cpp:383-387`) is the sole wait-dependent control flow; the proof envelope is captured at step 2, before the wait, and never re-fetched. FB64 (WH-1..WH-5) proves this delta soundness-empty; this command is the `:2565` row of its WH-6 census. With `--wait 0` (default) the head-anchor case fails closed immediately.   ∎

### 4.5 Corollary CP-E (end-to-end composition + concrete security)

Under A1 + A2, `verify-constant --name N --value V` emits a **wrong verdict in either direction** — `CONFIRMED` with `v_T ≠ V`, or `MISMATCH` with `v_T = V` — only by defeating the walk, the anchor, the Merkle leg, or the hash comparison. Composing T-L1 + T-L2 (`anchored_head`) with CP-1 (key-bind + SR-1 + MT-4) and CP-2 (value-hash dichotomy), union-bounded in the family style:

$$
\Pr[A_{\text{daemon}} \text{ forges a verdict}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; \log_2(n)\cdot 2^{-128} \;+\; 2\cdot 2^{-128},
$$

(the header-walk + successor sig-verify A1 terms; the MT-4 term; the SR-1 collision case + the CP-2(a) value collision — CP-2(b)'s direction costs nothing, being deterministic given CP-1). For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible — the same order as the balance/stake/abort reads, as expected: the pipeline is FB65's with the cleartext leg replaced by a local precomputation. **This bound covers the complete verdict surface** — there is no residual (H-neg) row (CP-3); `verify-param-value` shares this property, the eight NV-2/NV-3 readers do not. The daemon's only unbounded power is to force exit 3 — withholding, the fail-safe direction.   ∎

---

## 5. Composition with companion proofs

- **`AbortRecordProofSoundness.md` (FB65)** — structural template. CP-1 mirrors AB-1 (same key-bind discipline, same S-042 helper, same SR-1 discharge); where FB65 continues into AB-2's cleartext hash-bind, this reader's CONFIRM shape replaces the daemon cleartext with the operator's assertion (step 0c), and where FB65 needs AB-3's (H-neg) footing, CP-3 shows this reader needs none.
- **`verify-param-value`** — the true CONFIRM-shape precedent (same `k:` namespace, same key-bind, same UNVERIFIABLE discipline); the deltas are recorded in §1 (salt coverage, closed whitelist, MISMATCH exit 2 vs its exit 0). **`MergeStateSoundness.md`** + `verify-merge-state` — the other operator-asserting reader. The difference CP-3 isolates: an `m:` leaf's absence is a legitimate chain state (no active merge), so `verify-merge-state` retains a daemon-asserted negative (the `m:` row of NV's table); a `k:` leaf's absence is not a state at all, so this reader retains nothing.
- **`StateRootAnchorSoundness.md` (F6)** — CP-1(ii) *is* SR-1 applied at `anchor_index = proof_height − 1`, via the same `committee_bound_state_root` helper; SR-2/SR-3 inherited for the walk.
- **`WaitHoldAndWaitSoundness.md` (FB64)** — CP-4(c) is a citation, not a derivation; this command's binding call (`light/main.cpp:2565`) is one of the eleven direct sites in the WH-6 census, so WH-1–WH-5 apply verbatim.
- **`NegativeVerdictSoundness.md`** — cited by contrast: CP-3 establishes that `verify-constant` is outside the (H-neg) regime entirely (no absence verdict, no `negative_footing` tag, no NV-4 confinement needed because there is nothing to confine). NV-5a's canonical-key locality is inherited and strengthened (closed compiled-in list); F-6's both-binds lesson is carried by CP-1 + CP-2.
- **`MerkleTreeSoundness.md`** — MT-2/MT-4 under CP-1; §6.2 (S-040 CLOSED) under CP-1; MT-5 is why no absence proof *could* exist — and CP-3 is why none is needed.
- **`S033StateRootNamespaceCoverage.md`** — the `k:` + `k:c:` rows fix the encodings §1.2 reads off source; its prefix-distinctness witness is CP-1's counter-separation argument; its coverage + disjointness guarantee the constants are committed through `k:` and no other namespace.
- **`LightClientThreatModel.md`** — `A_daemon`, T-L1/T-L2/T-L3, L-6 fail-closed exit, §6 residual single-daemon limitations, all inherited.

---

## 6. Known limitations

All of `LightClientThreatModel.md` §6 applies (single daemon, no persistence beyond the `--resume` anchor cache, genesis-only committee map, no transport encryption). Specific to this reader:

### 6.1 MISMATCH does not disclose the committed value

CP-2's asymmetry: inequality is proven, the true value is not extracted (no preimage capability is assumed). Auditing an unknown parameter requires per-candidate invocations or a daemon-trusting read. By design — the CONFIRM shape exists because `k:` has no cleartext RPC.

### 6.2 "Genesis-pinned" ≠ immutable

`min_stake`, `suspension_slash`, `unstake_delay` are PARAM_CHANGE-mutable (`chain.cpp:483-485`); the merge thresholds are genesis-pinned in production (their `chain.hpp` setters are R4 genesis/test wiring, not governance). A verdict speaks to the *effective* value at the anchor height (CP-4). Operators comparing against a genesis file on a governance-active chain should expect honest `MISMATCH`es after activated changes — that is the command working, not failing.

### 6.3 Per-node semantics of the routing fields

`my_shard_id` (and the daemon's view of `shard_count`/`shard_salt`) attest the queried daemon-chain's values (CP-4(b)). Cross-shard claims need per-shard invocations.

### 6.4 Refusal is uniform

Every daemon error lands on exit 3 with no sub-classification (§8, CP-F1). Operationally this folds transient daemon errors and genuine legacy-daemon incompatibility into one exit code; soundness is unaffected (no verdict either way).

---

## 7. Implementation cross-reference

Line numbers verified against the current tree at the time of writing.

| Theorem | Component | File:lines | Role |
|---|---|---|---|
| all | `cmd_verify_constant` | `light/main.cpp:2413-2611` (dispatch `:7535`) | The composite command; header comment `:2382-2405`. |
| CP-1(i) | `kKnownU64Constants` + canonical-name gate | `light/main.cpp:2406-2411`, `:2443-2454` | Closed 13-name whitelist (12 u64 + `shard_salt`); unknown name → exit 1 with the canonical list, before any RPC. |
| CP-2 | value-form gates + local expected hash | `light/main.cpp:2455-2479` | `--value`/`--value-hex` form enforcement; `H(u64_be(V))` / `H(salt₃₂)` computed BEFORE any RPC (`:2470-2478`). |
| CP-1, CP-E | `anchored_head` + S-033 gate | `light/main.cpp:2490-2496`; `light/trustless_read.cpp:278-333` | T-L1 genesis pin + T-L2 committee-verified walk; empty `head_state_root` throws. |
| CP-3 | refusal branch → UNVERIFIABLE exit 3 | `light/main.cpp:2501-2521` | Fetch `:2501-2502`; ANY error → no verdict, `return 3` at `:2520`. No substring matcher exists. |
| CP-1(i) | step 3a key-bind | `light/main.cpp:2526-2539` | `proof.key_bytes == hex("k:" ‖ N)` byte-for-byte; the F-6-pattern bind; throw `:2534-2538`. |
| CP-1 | `verify_state_proof` | `light/verify.cpp:330-394` | Proof JSON validation; delegate to `merkle_verify` `:378-382`. |
| CP-1 | `merkle_verify` (+ S-040 wrapper) | `src/crypto/merkle.cpp:131-161` | Sibling-chain recompute; root-wrapper re-application with caller-supplied `leaf_count` `:158-161`. |
| CP-1(ii) | stale-height gate + root equality | `light/main.cpp:2549-2572` | `proof_height < vc.height` throws `:2551-2556`; `attested != proof_root` SECURITY throw `:2567-2572`. |
| CP-1(ii), CP-4 | `committee_bound_state_root` | `light/trustless_read.cpp:335-437` | S-042 binding: full-block recompute `:355-364`, hold-and-wait `:383-387`, successor sig verify `:408-415`, `prev_hash` bind `:417-432`. |
| CP-2 | verdict comparison | `light/main.cpp:2578-2606` | `proof.value_hash == expected` → CONFIRMED exit 0; else MISMATCH exit 2 (`:2606`); no cleartext RPC in either arm. |
| CP-2, CP-3 | `k:` leaf emission | `src/chain/chain.cpp:379-408` | `const_leaf` lambda `:380-384`; 12 u64 calls `:385-396`; `shard_salt` `:397-402`; `k:c:` counters `:404-408`. Unconditional straight-line emission. |
| CP-2 | `SHA256Builder::append(uint64_t)` | `src/crypto/sha256.cpp:30-34` | Big-endian u64 serialization shared by both sides. |
| CP-1, CP-3 | `Node::rpc_state_proof` | `src/node/node.cpp:3363-3454` | `k` simple-namespace key shape `:3390-3398`; `c` → `"k:c:"` route `:3399-3405`; `not_found` `:3434-3437`; unsupported-namespace `:3430-3432`; single envelope `:3443-3453`. |
| CP-3 | `Chain::state_proof` | `src/chain/chain.cpp:435-462` | `nullopt` for an absent key `:449` → the RPC's `not_found` (unreachable for admitted `k:` names on an honest S-033 daemon). |
| CP-4 | `activate_pending_params` | `src/chain/chain.cpp:471-497` | MIN_STAKE / SUSPENSION_SLASH / UNSTAKE_DELAY governance mutation sites `:483-485`. |
| CP-4 | routing-field members + setters | `include/determ/chain/chain.hpp:321-322`, `:402-403`, `:600`, `:608-609`, `:708-709` | Width facts (u32 members), per-node `my_shard_id_`, never-snapshotted routing trio. |
| CP-4 | `--wait` plumbing | `light/main.cpp:2431-2432`, `:2565-2566` | Forwarded only into the S-042 binding (FB64; WH-6 census row `:2565`). |

**Tests** (offline contract here; live legs are CI/WSL2 cluster legs):

| Test | Coverage |
|---|---|
| `tools/test_light_verify_constant.sh` | The command's offline contract: help advertises `verify-constant` with `--name` + `--wait`; the canonical-name gate rejects an unknown name *listing* the 12 u64 constants + `shard_salt`; the value-form gates reject a u64 constant without `--value` and `shard_salt` without `--value-hex`; bad `--wait` rejected; no-daemon read fails fast with **no** verdict (no false CONFIRMED/MISMATCH). Live legs (CONFIRMED on the genesis's real `min_stake`; MISMATCH **exit 2** on `min_stake+1`; `k:`-refusing daemon → UNVERIFIABLE exit 3; wrong-leaf key-bind fail-closed) documented + SKIPPED offline, CI/WSL2. |
| `tools/test_merkle_proof_tampering.sh` + `determ test-merkle-proof-tampering` | MT-4 tamper rejection + S-040 forged-`leaf_count` rejection CP-1 inherits. |
| `tools/test_state_proof_namespaces.sh` / `tools/test_state_root_namespaces.sh` | Cross-namespace swap rejection / namespace-mutation-changes-root coverage the `k:` leaves share (including the `k:` vs `k:c:` separation). |
| `tools/test_state_root_determinism.sh` | The deterministic leaf emission CP-3's unconditional-commitment premise rides on. |

---

## 8. Findings

- **CP-F1 (uniform refusal handling — stronger than the family's substring matchers, documented).** The error branch (`light/main.cpp:2503`) classifies *nothing*: every error-marked reply — `not_found`, `unsupported namespace`, or arbitrary daemon text — lands on `UNVERIFIABLE` exit 3. This is strictly more conservative than the `b:`/`s:` substring matchers (FB65 AB-F2 / NV-5's caveat): there is no token an honest-but-buggy daemon could emit that gets misread as a verdict, because no error maps to a verdict at all. The cost is purely diagnostic (a transient error and a legacy daemon share an exit code, §6.4); the soundness delta is zero — and favorable.
- **CP-F2 ("genesis-pinned" is a label, not an immutability claim — honest boundary).** Three of the 13 constants are governance-mutable at apply time (`chain.cpp:483-485`) and the merge thresholds carry setters (`chain.hpp:321-322`). CP-4 fixes the exact claim: the leaf attests the value `build_state_leaves` read from the Chain member at the verified anchor height — the *currently effective* parameter. A genesis-file comparison on a governance-active chain can honestly `MISMATCH`; that is signal, not error.
- **CP-F3 (fixed-width u64 canonicalization — informational, the `m:` F-3 sibling).** Narrower members (`uint32_t` thresholds, `ShardId` fields) are widened to 8-byte big-endian in the leaf preimage; the verifier hashes the same widening. External clients MUST hash the 8-byte form, not the natural width. Lossless, no aliasing; recorded for byte-exact reimplementations.
- **CP-F4 (MISMATCH proves inequality, not the value — inherent to the CONFIRM shape).** No preimage extraction exists or is claimed (would be A3-class); the committed value stays behind its hash. Candidate-by-candidate assertion is the sound discovery path; anything faster is a daemon-trusting read. Named so the boundary is a design decision, not an oversight.
- **CP-F5 (key-bind is load-bearing even with a closed name list).** The canonical-name gate alone does not pin which *leaf* the daemon proves — only which name the verifier asked about. Without step 3a, a daemon could serve a valid proof for a *different* constant whose committed value equals the asserted one (e.g., proving `merge_grace_blocks`'s leaf to "confirm" an asserted `unstake_delay` when the two happen to share a value — both hash to the same `value_hash` form `H(u64_be(v))`). The F-6 lesson (single-leaf readers need BOTH the key-bind and the value-hash-bind) applies verbatim; the bind shipped in the initial landing (`light/main.cpp:2526-2539`), the same commit that retrofitted it to the `b:` reader (FB65 AB-F1).

---

## 9. Status

- **Spec.** Complete (this document). Analytic; changes no code.
- **Implementation.** Shipped: `determ-light verify-constant` (`light/main.cpp::cmd_verify_constant`, landed in commit `ba5dde1` with the key-bind in place from the first landing — completing determ-light coverage of all 10 committed state namespaces); the `k:` namespace served by `Node::rpc_state_proof` (`src/node/node.cpp:3390-3398`) and unconditionally committed by `Chain::build_state_leaves` (`src/chain/chain.cpp:379-402`). Anchored by `tools/test_light_verify_constant.sh` (offline contract; live legs CI/WSL2).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision resistance) — per `Preliminaries.md` §2.0. **No (H-neg) premise anywhere** (CP-3): this reader has no daemon-asserted verdict in any branch.
- **Adversary model.** `A_daemon` (malicious single daemon). Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis`.
- **Theorems.** CP-1 (key-bind + canonical-name gate + committee anchor — the verdict concerns exactly `"k:" ‖ N` under an SR-1-anchored root; `k:c:` counter keys separated); CP-2 (the CONFIRM dichotomy is sound both ways — CONFIRMED ⇒ equality except an A2 collision, with `u64_be` injectivity making any in-domain value collision a genuine A2 break; MISMATCH ⇒ inequality deterministically; MISMATCH does not disclose the committed value); CP-3 (UNVERIFIABLE completeness — absence is never a chain state, every refusal is exit 3 with no verdict, zero (H-neg) exposure); CP-4 (honest semantic boundary — the leaf attests the effective Chain-member value at the anchor height; governance-mutable trio; per-node routing fields; `--wait` soundness-neutral per FB64). Corollary CP-E composes to `≤ 2⁻⁹²` end-to-end for practical parameters — and, uniquely in the family, that bound covers the **entire** verdict surface.
- **Composes with.** `AbortRecordProofSoundness.md` (FB65 template), `MergeStateSoundness.md` (+ `verify-merge-state`, the CONFIRM precedent), `StakeProofSoundness.md` (SP-1/SP-2/SP-3), `StateRootAnchorSoundness.md` (SR-1/SR-2/SR-3), `WaitHoldAndWaitSoundness.md` (FB64, WH-6 row `:2565`), `NegativeVerdictSoundness.md` (NV-5a inherited; (H-neg) row vacuous here), `MerkleTreeSoundness.md` (MT-2/MT-4/MT-5, §6.2 S-040 CLOSED), `S033StateRootNamespaceCoverage.md` (`k:`/`k:c:` rows + prefix disjointness), `LightClientThreatModel.md`.
- **Known limitations.** §6.1 (no value disclosure on MISMATCH — inherent to the shape), §6.2 (effective-value semantics under governance), §6.3 (per-node routing fields), §6.4 (uniform refusal exit). None undermine the per-invocation verdict soundness claim — which here, exceptionally, covers both verdict arms.

---

## 10. References

### Implementation sites
- `light/main.cpp:2382-2411` — header comment + `kKnownU64Constants`; `:2413-2611` — `cmd_verify_constant` (canonical-name gate `:2443-2454`; value-form gates `:2455-2464`; local expected hash `:2466-2479`; S-033 gate `:2492-2496`; UNVERIFIABLE branch `:2503-2521`; key-bind `:2526-2539`; S-042 anchor `:2549-2572`; verdict `:2578-2606`); dispatch `:7535`.
- `light/trustless_read.cpp:278-333` — `anchored_head`; `:335-437` — `committee_bound_state_root`.
- `light/verify.cpp:330-394` — `verify_state_proof` (delegation `:378-382`).
- `src/crypto/merkle.cpp:131-161` — `merkle_verify` (S-040 wrapper `:158-161`).
- `src/crypto/sha256.cpp:30-34` — `SHA256Builder::append(uint64_t)` (big-endian).
- `src/chain/chain.cpp:379-408` — `k:` + `k:c:` leaf emission; `:435-462` — `Chain::state_proof` (`nullopt` `:449`); `:471-497` — `activate_pending_params` (governance mutation `:483-485`).
- `src/node/node.cpp:3363-3454` — `Node::rpc_state_proof` (`k` `:3390-3398`; `c` `:3399-3405`; `not_found` `:3434-3437`).
- `include/determ/chain/chain.hpp:321-322`, `:402-403`, `:600`, `:608-609`, `:708-709` — member widths, accessors, routing-field comments.
- `tools/test_light_verify_constant.sh` — offline contract anchor.

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §2.0 canonical labels (A1/A2).
- `docs/proofs/AbortRecordProofSoundness.md` (FB65) — the `b:` sibling and structural template.
- `docs/proofs/MergeStateSoundness.md` — the `m:` namespace chain-side soundness (MS-3 injectivity); the command-shape precedent is `verify-param-value`.
- `docs/proofs/StakeProofSoundness.md` — SP-1/SP-2/SP-3.
- `docs/proofs/StateRootAnchorSoundness.md` (F6) — SR-1/SR-2/SR-3.
- `docs/proofs/WaitHoldAndWaitSoundness.md` (FB64) — `--wait` soundness-neutrality; WH-6 census.
- `docs/proofs/NegativeVerdictSoundness.md` — NV-2/NV-3 ((H-neg), cited by contrast), NV-5a, F-6.
- `docs/proofs/MerkleTreeSoundness.md` — MT-2/MT-4/MT-5, §6.2 (S-040 CLOSED).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — `k:`/`k:c:` rows, prefix disjointness, coverage.
- `docs/proofs/LightClientThreatModel.md` — `A_daemon`, T-L1..T-L4, L-6.

### Specifications
- `docs/PROTOCOL.md` §4.1.1 (`k:` Merkle-leaf rows), §10.2 (`state_proof` RPC).
- `docs/SECURITY.md` §S-033, §S-038, §S-040, §S-041, §S-042.
- NIST FIPS 180-4 — SHA-256 (A2). RFC 8032 — Ed25519 (A1).

This document is `FB66` in the proof family.
