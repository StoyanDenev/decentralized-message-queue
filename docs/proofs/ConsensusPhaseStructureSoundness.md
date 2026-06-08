# FA-Phase — Two-phase per-block consensus structure soundness

This document proves the **structural soundness** of Determ's two-phase per-block consensus: the Phase-1 commit (`ContribMsg.dh_input`) / Phase-2 reveal (`BlockSigMsg.dh_secret`) construction, considered as a *deterministic, binding state machine* rather than as a randomness beacon. Four properties are pinned:

- **T-1 (Phase-1 commit determinism):** the K committee members converge on the same ordered `dh_input` vector before any Phase-2 reveal, so the `delay_seed` and the `block_digest` each member signs are identical across honest members.
- **T-2 (Phase-1→Phase-2 binding):** each revealed `dh_secret_i` is bound to its Phase-1 commitment `dh_input_i` by `dh_input_i = SHA256(dh_secret_i ‖ pubkey_i)`, so no member (and no relayer) can substitute a different secret after Phase 1 without producing a SHA-256 second-preimage.
- **T-3 (Derivation determinism):** `delay_seed`, `delay_output`, and `cumulative_rand` are each a pure deterministic function of the ordered committee inputs; every honest node that admits the same block re-derives identical values.
- **T-4 (Phase-transition gate):** an honest node transitions from Phase 1 to Phase 2 (begins signing) **only after exactly K Phase-1 commits have been gathered** in committee-selection order; a Phase-2 signature therefore always attests over a sealed Phase-1 commitment set.

**Scope boundary — this is NOT a beacon-bias proof.** The property that *no committee member can predictively bias the randomness `R = delay_output` by choosing its secret strategically or by selectively aborting* is **FA3** (`SelectiveAbort.md`, Theorem T-3). FA3 supplies the information-theoretic hiding argument (commitments hide secrets under SHA-256 preimage resistance, so a deciding member's expected utility is invariant to its own secret choice). This proof **cites FA3 for hiding and does not re-prove it**; the work here is the *orthogonal* structural claim that, hiding aside, the two-phase construction is deterministic and tamper-evident — i.e., that the inputs FA3 reasons about are themselves well-defined, agreed-upon, and irreversibly bound once Phase 1 seals.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validity predicates V4–V8, and assumptions A2 (SHA-256 collision resistance + 2nd-preimage resistance) / A3 (SHA-256 preimage resistance + ROM) / A4 (CSPRNG uniformity); `SelectiveAbort.md` (FA3) for the hiding/bias-resistance property this proof deliberately excludes; `S020CommitteeSelection.md` (S-020) for the determinism + uniformity of the committee-index draw that fixes the *order* `σ` over which both phases are serialized; `Safety.md` (FA1) for the K-of-K finalization guarantee that consumes T-4's sealed-commit-set property; `docs/proofs/tla/MakeContribCommitment.tla` (FB24) and `docs/proofs/tla/MakeBlockSigPrimitive.tla` (FB40) for the per-primitive state-machine models this structural proof composes. `docs/PROTOCOL.md` §5.1 for the wire-level statement of the two phases.

---

## 1. Introduction

### 1.1 The two-phase construction

Determ finalizes each block through a per-round two-phase exchange among the K-member committee `K_h = (v_0, …, v_{K-1})` selected for height `h` (the committee order `σ` is the `select_m_creators` output, fixed deterministically per `S020CommitteeSelection.md` T-5). The phases are:

- **Phase 1 (CONTRIB).** Each member `v_i` draws a fresh 32-byte secret `s_i` from the OS CSPRNG, computes the commitment `dh_input_i = SHA256(s_i ‖ pubkey_i)`, packs it (with its mempool tx snapshot) into a `ContribMsg`, signs the message's commitment hash with Ed25519, and gossips it. The secret `s_i` is held locally and NOT revealed.
- **Phase 2 (BLOCK_SIG).** Once all K Phase-1 commitments have arrived, each member computes the placeholder `delay_seed = SHA256(index ‖ prev_hash ‖ tx_root ‖ ordered dh_inputs)`, signs the canonical `block_digest`, and gossips a `BlockSigMsg` that **reveals** `s_i` in its `dh_secret` field. After K reveals gather, the block's `delay_output = SHA256(delay_seed ‖ ordered secrets)` is computed and finalization proceeds.

The construction is the standard *commit-then-reveal* pattern. FA3 proves the security consequence (no predictive bias). This proof pins the four structural facts that make the construction a sound state machine in the first place: the commitments are agreed-upon and ordered (T-1), the reveals are bound to the commitments (T-2), every derived value is a deterministic function of the agreed inputs (T-3), and the reveal phase cannot begin before the commit phase seals (T-4).

### 1.2 What this proof covers and does NOT cover

**Covered (structural/determinism):**

- T-1: Phase-1 commit-set agreement + ordering. All honest members that reach Phase 2 hold the same ordered `dh_input` vector.
- T-2: 2nd-preimage binding from `dh_secret` to `dh_input`, enforced by the validator at apply time.
- T-3: pure-function determinism of `delay_seed` / `delay_output` / `cumulative_rand`.
- T-4: the K-arrived phase-transition gate.

**NOT covered (delegated):**

- **Bias-resistance / hiding of `R`.** This is FA3 (`SelectiveAbort.md` T-3). This proof treats "the secret is hidden in Phase 1" as an *input* (cited, used in the discussion of why binding matters) and does not re-derive the hybrid argument.
- **Committee-selection uniformity + determinism (the order `σ`).** This is `S020CommitteeSelection.md` (T-1/T-2 uniformity, T-5 determinism). This proof *uses* `σ`'s determinism as a premise for T-1 but does not re-prove it.
- **K-of-K finalization safety (≤1 finalized digest/height).** This is FA1 (`Safety.md`). T-4 here supplies the "Phase-2 sig attests a sealed Phase-1 set" lemma that FA1 consumes.
- **Liveness** (that the gate eventually fires, or aborts and retries). This is FA4 (`Liveness.md`). T-4 is a *safety* statement about the gate's precondition, not a *liveness* statement that the gate fires.
- **The BFT-mode quorum shrinkage** (Phase-2 finalization at `Q = ⌈2·k_bft/3⌉` of `k_bft`). This is FA5 (`BFTSafety.md`). T-4 below covers the **Phase-1 unanimity** that holds in *both* modes; the Phase-2 *signature* threshold's mode-dependence is FA5's territory and is noted but not re-derived.

---

## 2. Setup and primitives

### 2.1 The committee order `σ`

Both phases serialize their per-member data in **committee-selection order**: the vector `current_creator_domains_` (producer side) / `b.creators` (validator side), which is the `select_m_creators` output mapped to domain identities. Per `S020CommitteeSelection.md` T-5 (cross-node determinism), every honest node computing the committee against the same `(random_state, N_pool, K)` derives the *same* ordered domain vector. This proof takes `σ` as a fixed, agreed permutation; all the "ordered" qualifiers below refer to `σ`.

The validator re-derives `σ` and checks the block's `creators` against it position-by-position at `src/node/validator.cpp:128-132`:

```cpp
for (size_t i = 0; i < m; ++i) {
    if (avail_domains[indices[i]] != b.creators[i])
        return {false, "creator[" + std::to_string(i) + "] mismatch: expected "
                     + avail_domains[indices[i]]};
}
```

So a block whose `creators` ordering differs from the canonical `σ` is rejected; downstream theorems may assume `b.creators = σ`.

### 2.2 The Phase-1 commitment primitive

`make_contrib_commitment` (`src/node/producer.cpp:219-260`) builds the hash a member signs in Phase 1. The consensus-bound core (the v1 shape, exercised when all three F2 view roots are zero) is:

```cpp
SHA256Builder inner;
for (auto& h : sorted_tx_hashes) inner.append(h);
Hash inner_root = inner.finalize();

SHA256Builder b;
b.append(block_index);
b.append(prev_hash);
b.append(inner_root);
b.append(dh_input);
...
return b.finalize();
```

The secret itself is drawn and committed at `src/node/node.cpp:844-851`:

```cpp
Hash my_secret{};
if (RAND_bytes(my_secret.data(), 32) != 1)
    throw std::runtime_error("RAND_bytes failed for dh_secret");
current_round_secret_ = my_secret;
Hash my_commit = crypto::SHA256Builder{}
    .append(my_secret)
    .append(key_.pub.data(), key_.pub.size())
    .finalize();
```

so `dh_input = SHA256(s_i ‖ pubkey_i)` exactly. The per-primitive binding contract of `make_contrib_commitment` is formalized at the state-machine layer by FB24 (`tla/MakeContribCommitment.tla`), whose INV-5 (Determinism) and INV-6 (FieldBinding) are the TLA+ lifts of the C++ purity/content-binding facts this proof uses in T-1 and T-3.

### 2.3 The Phase-2 reveal primitive

`make_block_sig` (`src/node/producer.cpp:703-716`) packs the revealed secret and signs the digest:

```cpp
BlockSigMsg make_block_sig(const NodeKey& key, ..., const Hash& dh_secret) {
    BlockSigMsg m;
    m.block_index  = block_index;
    m.signer       = domain;
    m.delay_output = delay_output;
    m.dh_secret    = dh_secret;
    m.ed_sig       = sign(key, block_digest.data(), block_digest.size());
    return m;
}
```

The producer passes `current_round_secret_` as `dh_secret` at `src/node/node.cpp:1047-1050`, so the secret revealed in Phase 2 is exactly the one committed in Phase 1 (same `current_round_secret_` field, set once per round at `node.cpp:847`). FB40 (`tla/MakeBlockSigPrimitive.tla`) is the per-primitive model of this signature's round/digest/member binding.

### 2.4 The derivation functions

Three pure functions derive the consensus values from the ordered inputs:

- `compute_delay_seed(index, prev_hash, tx_root, creator_dh_inputs)` — `src/node/producer.cpp:509-518`. Appends `index`, `prev_hash`, `tx_root`, then each `dh_input` in order, and finalizes.
- `compute_block_rand(delay_seed, ordered_secrets)` — `src/node/producer.cpp:637-643`. Appends `delay_seed` then each ordered secret and finalizes. This is `delay_output = R`.
- The `cumulative_rand` chaining at `src/node/producer.cpp:819-822` (`build_body`): `cumulative_rand = SHA256(prev_rand ‖ delay_output)`.

Each is a `SHA256Builder` append chain over its arguments and nothing else (no clock, no global mutable state). This is the purity property T-3 formalizes.

---

## 3. Theorems

Throughout, "honest member" means a committee member following the protocol (assumptions H1–H4, `Preliminaries.md`); `K = |K_h|` is the committee size; A2/A3 are the SHA-256 assumptions from `Preliminaries.md` §2.1.

### T-1 (Phase-1 commit determinism / commit-set agreement)

**Claim.** Let `v_a` and `v_b` be two honest committee members that both transition into Phase 2 at height `h`, abort-generation `g`. Then at the moment each transitions, they hold the **same** ordered vector of Phase-1 commitments `(dh_input_0, …, dh_input_{K-1})` (indexed by `σ`), and therefore compute the **same** `delay_seed` and (given equal Phase-1 inputs to `build_body`) the **same** `block_digest` that each signs in Phase 2.

**Proof.**

*Step 1 — each position holds an authenticated commitment from a fixed identity.* The Phase-1→Phase-2 transition assembles the ordered commitment vector by looking up `pending_contribs_[d]` for each `d` in `current_creator_domains_` (= `σ`), at `src/node/node.cpp:923-928` (`enter_block_sig_phase`):

```cpp
for (auto& d : current_creator_domains_) {
    auto it = pending_contribs_.find(d);
    if (it == pending_contribs_.end()) return;
    ordered_lists.push_back(it->second.tx_hashes);
    ordered_dh_inputs.push_back(it->second.dh_input);
}
```

The `return` on a missing entry is the gate (T-4): the transition does not proceed unless every `σ`-member's contrib is present. So position `i` of the vector is `pending_contribs_[σ(i)].dh_input`.

*Step 2 — each `pending_contribs_[d]` entry is the unique, signature-authenticated first contrib from `d` at `(h, g)`.* On receipt, `on_contrib` (`node.cpp:2098`) (a) gates on `msg.block_index == chain_.height()` (`node.cpp:2102`), (b) gates on `msg.prev_hash == prev_hash` (`node.cpp:2104-2105`), (c) gates on `msg.aborts_gen == current_aborts_.size()` (the generation gate, `node.cpp:2110`), and (d) verifies the Ed25519 signature over the recomputed commitment (`node.cpp:2126-2134`). Only after all four checks does it store `pending_contribs_[msg.signer] = msg` (`node.cpp:2223`). A *second* distinct contrib from the same signer at the same `(h, g)` is NOT overwritten: `on_contrib` detects the existing entry (`node.cpp:2164-2165`) and, if the v1 core commit differs (`node.cpp:2188-2193`), routes it to equivocation evidence and `return`s without replacing the stored entry (`node.cpp:2220`). Hence the stored `pending_contribs_[d]` is the **first-arrived, signed** contrib from `d` for `(h, g)`, and its `dh_input` is fixed once stored.

*Step 3 — both honest nodes agree on the same per-position value.* For each `σ`-position `i = σ(d)`, both `v_a` and `v_b` store the contrib from domain `d` only if its Ed25519 commitment signature verifies under `d`'s registered pubkey (`node.cpp:2131`). By A1 (Ed25519 EUF-CMA, `Preliminaries.md` §2.2), `d` is the only party that can produce a contrib that passes this check; an honest `d` gossips exactly one `dh_input` per `(h, g)`. A Byzantine `d` could gossip two different signed contribs, but Step 2 shows each honest receiver keeps the **first** it admits — and the equivocation detector (`node.cpp:2193-2218`) flags the conflict for slashing. The case where `v_a` and `v_b` admit *different* first-arrivals from a Byzantine `d` (gossip race) does not break T-1's *finalization* consequence: by T-4 a Phase-2 signature is computed over `block_digest`, which binds the *exact* ordered `dh_input` set via `compute_block_digest`'s `for (auto& d : b.creator_dh_inputs) h.append(d);` (`src/node/producer.cpp:589`). Two honest nodes that admitted different commitments for `d` therefore compute *different* digests and sign *different* blocks; FA1 (`Safety.md`) then guarantees at most one such block reaches K-of-K finalization. So either (i) all honest finalizing nodes agreed on the per-position commitments and produce one digest, or (ii) they disagreed and **no** block gets K signatures (the round aborts and retries with the equivocator slashed). In neither case does a block finalize over an *ambiguous* commitment set.

*Step 4 — equal commit vector ⇒ equal `delay_seed` ⇒ equal digest.* Given the same ordered `dh_input` vector and the same `(index, prev_hash, tx_root)`, `compute_delay_seed` (a pure append chain, §2.4) returns the same `delay_seed` (this is T-3 below applied to `delay_seed`). The `tx_root` is itself the deterministic union `compute_tx_root` over the same ordered `creator_tx_lists` (`producer.cpp:262-270`, a `std::set<Hash>` insert + ordered append — order-independent and content-determined). `compute_block_digest` (`producer.cpp:577-632`) is a pure append chain over `index`, `prev_hash`, `tx_root`, `delay_seed`, `consensus_mode`, `bft_proposer`, the ordered `creators`, `creator_tx_lists`, `creator_ed_sigs`, and `creator_dh_inputs` (plus the F2 sets when active). With all those equal, the digest is equal. ∎

**Corollary T-1.1 (digest excludes the secrets, by design).** `compute_block_digest` does NOT append `delay_output` or `creator_dh_secrets` (`producer.cpp:555-564` documents the exclusion). T-1's digest-agreement therefore holds at Phase-2 *signing* time, *before* any secret is revealed — which is exactly what makes the construction a commit-reveal: the digest seals the commitments, and the secrets are revealed afterward without changing the signed digest. The uniqueness of block *identity* (which DOES bind the secrets) is preserved separately via `Block::signing_bytes` (FA1 / `Preliminaries.md` §4; `validator.cpp:382-385` comment).

### T-2 (Phase-1 → Phase-2 binding)

**Claim.** For a block `B` that passes validation, every revealed secret is the 2nd-preimage-bound opening of its Phase-1 commitment:

$$
\forall i \in [0, K): \quad \mathrm{SHA256}(B.\texttt{creator\_dh\_secrets}[i] \,\|\, \mathrm{pubkey}_{B.\texttt{creators}[i]}) = B.\texttt{creator\_dh\_inputs}[i].
$$

Consequently, **no party** (the member itself, a relayer, or a Byzantine assembler) can present a secret `s'_i \neq s_i` that the validator accepts in place of the Phase-1-committed `s_i`, except by finding a SHA-256 second preimage — probability `≤ 2⁻¹²⁸` per attempt under A2.

**Proof.** The binding is enforced by `BlockValidator::check_creator_dh_secrets` (`src/node/validator.cpp:355-371`):

```cpp
for (size_t i = 0; i < b.creators.size(); ++i) {
    auto e = registry.find(b.creators[i]);
    if (!e) return {false, "creator not found: " + b.creators[i]};
    Hash expected = SHA256Builder{}
        .append(b.creator_dh_secrets[i])
        .append(e->pubkey.data(), e->pubkey.size())
        .finalize();
    if (expected != b.creator_dh_inputs[i])
        return {false, "creator_dh_secret[" + std::to_string(i)
                     + "] does not match commit"};
}
```

This recomputes `SHA256(secret_i ‖ pubkey_i)` and rejects the block unless it equals the Phase-1 commitment `creator_dh_inputs[i]`. The `creator_dh_inputs[i]` value is itself authenticated as the member's Phase-1 commitment: `check_creator_tx_commitments` (`validator.cpp:167-173`) recomputes `make_contrib_commitment(... , creator_dh_inputs[i], ...)` and verifies `creator_ed_sigs[i]` over it under the member's pubkey. So `creator_dh_inputs[i]` is *exactly the value the member signed in Phase 1* (A1 EUF-CMA: only the member could produce that signature).

Now suppose a Byzantine party wishes the finalized block to carry `s'_i ≠ s_i` at position `i` while keeping the same (signed) `creator_dh_inputs[i]`. Acceptance requires `SHA256(s'_i ‖ pubkey_i) = creator_dh_inputs[i] = SHA256(s_i ‖ pubkey_i)` with `s'_i ≠ s_i` — i.e., a SHA-256 collision on the two distinct preimages `(s'_i ‖ pubkey_i)` and `(s_i ‖ pubkey_i)`, equivalently a second preimage of `creator_dh_inputs[i]`. By A2 (`Preliminaries.md` §2.1) this succeeds with probability `≤ 2⁻¹²⁸` per attempt. Alternatively the party could change `creator_dh_inputs[i]` to `SHA256(s'_i ‖ pubkey_i)`, but then `check_creator_tx_commitments` rejects unless the party also forges `creator_ed_sigs[i]` over the new commitment — an Ed25519 forgery (A1), again negligible. So the reveal is bound to the commitment, and the commitment is bound to the member, to within the cryptographic assumptions. ∎

**Corollary T-2.1 (post-Phase-1 substitution is detectable, not silent).** Because the binding is checked at *every* validator (not just by the assembler), a tampered secret does not produce a "silently accepted" divergent block — it produces a block that *fails* `check_creator_dh_secrets` at every honest node and `check_delay` (next theorem) downstream. This is the structural precondition FA3 relies on when it asserts "validator V5 explicitly checks `SHA256(reveal ‖ pubkey) == dh_input` and rejects on mismatch" (`SelectiveAbort.md` L-3.2). T-2 is the C++-grounded statement of that V5 check; FA3 uses it as a lemma. (Matches `Preliminaries.md` V5.)

**Scope note.** T-2 binds the reveal to the commitment. It does NOT claim the *secret was unpredictable* before reveal — that hiding property is A3-based and is FA3's L-3.1/L-3.3. Binding (A2) and hiding (A3) are distinct properties of the same commitment; this proof owns binding, FA3 owns hiding.

### T-3 (Derivation determinism)

**Claim.** `delay_seed`, `delay_output` (= `R`), and `cumulative_rand` are each a pure deterministic function of their inputs. For fixed ordered inputs, every node — on any architecture, in any process, across snapshot reload — computes byte-identical values; and the validator's independent re-derivation matches the producer's iff the block's stored values are the canonical ones.

**Proof.**

*Purity.* Each of `compute_delay_seed` (`producer.cpp:509-518`), `compute_block_rand` (`producer.cpp:637-643`), and the `cumulative_rand` line (`producer.cpp:819-822`) consists solely of `SHA256Builder` `append` calls over the function arguments followed by `finalize()`. There is no read of wall-clock, environment, PRNG, or shared mutable state inside these functions. SHA-256 is bit-exact across architectures (FIPS 180-4); integer `append(uint64_t)` is big-endian-serialized identically everywhere (`Preliminaries.md` §1.3). Hence each is a pure function of its arguments — same inputs ⇒ byte-identical output. (This is the C++ correlate of FB24 INV-5 / FB40 INV-1 at the per-primitive layer; here it is composed across the three derivation steps.)

*Validator re-derivation equals producer's.* `BlockValidator::check_delay` (`validator.cpp:373-391`) recomputes both values from the block's stored fields:

```cpp
Hash expected_seed = compute_delay_seed(b.index, b.prev_hash, b.tx_root,
                                          b.creator_dh_inputs);
if (expected_seed != b.delay_seed)
    return {false, "delay_seed mismatch"};
...
Hash expected_output = compute_block_rand(b.delay_seed, b.creator_dh_secrets);
if (expected_output != b.delay_output)
    return {false, "delay_output mismatch (commit-reveal)"};
```

The validator calls the *same* `compute_delay_seed` / `compute_block_rand` functions the producer used (`build_body` at `producer.cpp:804`, `:810`). By purity, `expected_seed == b.delay_seed` iff the producer computed `b.delay_seed` over the same `(index, prev_hash, tx_root, creator_dh_inputs)` the validator reads from the block — and `tx_root` is itself re-checked against `union(creator_tx_lists)` at `validator.cpp:180-182`, and each `creator_dh_inputs[i]` is authenticated by T-1's Step 2. Likewise `expected_output == b.delay_output` iff `b.delay_output = SHA256(b.delay_seed ‖ ordered b.creator_dh_secrets)` with the secrets that passed T-2's binding check. So a block survives `check_delay` **only if** its `delay_seed` and `delay_output` are the canonical functions of the authenticated, bound Phase-1/Phase-2 inputs; any other value is rejected.

*Cross-node / cross-reload determinism.* The inputs to these functions are all block-resident or chain-resident: `index`, `prev_hash`, `tx_root`, `creator_dh_inputs`, `creator_dh_secrets`, and (for `cumulative_rand`) `chain.head().cumulative_rand`. The chain-resident `prev_rand` is byte-stable across snapshot reload by the snapshot-equivalence result (`SnapshotEquivalence.md` / `SnapshotDeterminismComposition.md`), and the block-resident inputs are fixed once the block exists. By purity, every node that admits block `B` derives the same `delay_seed`/`delay_output`/`cumulative_rand`. ∎

**Corollary T-3.1 (the inputs FA3 reasons about are well-defined).** FA3's Theorem T-3 reasons about `R = SHA256(delay_seed ‖ s_{σ(1)} ‖ … ‖ s_{σ(K)})`. T-3 here establishes that this `R` is a *single, agreed, deterministically-derived* value once the committee and secrets are fixed — there is no ambiguity in "the" `R` that FA3's bias bound applies to. The two proofs compose: FA3 bounds the adversary's predictive advantage over `R`; T-3 guarantees `R` is the unique deterministic image of the agreed inputs.

### T-4 (Phase-transition gate: Phase-2 signing only after K Phase-1 commits)

**Claim.** An honest node begins Phase 2 (signs and broadcasts a `BlockSigMsg`) for height `h`, generation `g`, **only after** it has gathered, in committee order `σ`, a Phase-1 contrib from **every** one of the K committee members. Consequently every Phase-2 signature an honest node emits attests over a `block_digest` that binds a *complete, sealed* ordered Phase-1 commitment set. This holds in **both** consensus modes (the Phase-1 unanimity requirement is mode-independent).

**Proof.**

*The gate condition.* The only sites that trigger the Phase-1→Phase-2 transition are the two identical guards:

- in `start_contrib_phase`, after this node injects its own contrib: `if (pending_contribs_.size() == current_creator_domains_.size()) enter_block_sig_phase();` (`node.cpp:902-903`), and
- in `on_contrib`, after admitting a peer's contrib: `if (phase_ == ConsensusPhase::CONTRIB && pending_contribs_.size() == current_creator_domains_.size()) enter_block_sig_phase();` (`node.cpp:2225-2227`).

Both require `pending_contribs_.size() == current_creator_domains_.size()`, i.e. the number of distinct admitted Phase-1 contribs equals `|σ| = K`.

*Size equality ⇒ every committee member present.* `current_creator_domains_` is the committee `σ` (K distinct domains). `pending_contribs_` is a map keyed by signer domain. A contrib is inserted only after the four admission gates of T-1 Step 2 pass (`node.cpp:2102`–`2131`), and only for a signer in the registry. `enter_block_sig_phase` then iterates `σ` and `return`s early if *any* `σ`-member's contrib is missing (`node.cpp:923-928`, quoted in T-1). So even though the size check alone counts *distinct admitted signers* (which could in principle include a non-committee registry member admitted before the committee was known — `on_contrib` deliberately does not filter by committee at admit time, per its comment at `node.cpp:2112-2116`), the actual transition into signing is guarded a *second* time by the per-`σ`-member lookup: `enter_block_sig_phase` only proceeds to `start_block_sig_phase` when `pending_contribs_.find(d)` succeeds for **every** `d ∈ σ`. Therefore the node reaches `start_block_sig_phase` only with a contrib present for each of the K committee members.

*Signing happens strictly inside the gated region.* `start_block_sig_phase` (`node.cpp:992`) is the sole producer of this node's `BlockSigMsg`: it builds the tentative block from the `σ`-ordered contribs (re-looking-up each `pending_contribs_[d]` and `return`ing if absent, `node.cpp:1000-1005`), computes the digest, calls `make_block_sig`, stores it, and broadcasts (`node.cpp:1045-1053`). It is reached only via `enter_block_sig_phase` (`node.cpp:935-938`, inside an `asio::post`). There is no other call path that emits a `BlockSigMsg` for a fresh round. Hence the Phase-2 signature is emitted strictly after the K-complete gate.

*The digest binds the sealed set.* The digest signed in `start_block_sig_phase` is `compute_block_digest(tentative)` over the K `σ`-ordered contribs; `compute_block_digest` appends every `creator_dh_inputs[i]` (`producer.cpp:589`). So the signature attests over the *complete* ordered commitment set — none missing, order fixed by `σ`.

*Mode-independence of Phase-1 unanimity.* The K-complete gate is in `start_contrib_phase` / `on_contrib` / `enter_block_sig_phase`, none of which branch on `ConsensusMode`. Finalization (`try_finalize_round`, `node.cpp:1066`) re-asserts Phase-1 unanimity in both modes ("Phase 1 unanimity preserved in both modes: all K contribs required", `node.cpp:1067-1073`): it gathers `σ`-ordered contribs and `return`s if any is missing, *before* counting Phase-2 signatures. The *Phase-2 signature* threshold does differ by mode (K-of-K in MD; `Q = ⌈2·k_bft/3⌉` of `k_bft` in BFT — `required_block_sigs`, `producer.cpp:541-553`), but that is a property of *how many reveals finalize*, not of the *Phase-1 commit gate*; the BFT threshold is FA5's subject. T-4's claim — Phase-2 *begins* only after K Phase-1 commits — is mode-independent. ∎

**Corollary T-4.1 (no signing over a partial commitment set).** Combining T-4 with T-1's Step 4: every honest Phase-2 signature is over a digest that binds all K ordered commitments. There is no protocol state in which an honest node signs a block whose `creator_dh_inputs` is shorter than K or out of `σ`-order. The validator enforces the same on receipt: `check_creator_tx_commitments` requires `creator_dh_inputs.size() == creators.size()` (`validator.cpp:143-144`) and `check_creator_dh_secrets` / `check_delay` require `creator_dh_secrets.size() == creators.size()` (`validator.cpp:357-358`, `:386-387`). So a malformed (short) commitment/reveal vector is rejected at apply time regardless of producer behavior.

**Corollary T-4.2 (reveal strictly follows seal).** A node sets `current_round_secret_` once in `start_contrib_phase` (`node.cpp:847`) and reveals it only in `start_block_sig_phase` via `make_block_sig` (`node.cpp:1050`). Since `start_block_sig_phase` runs strictly after the K-complete gate (this theorem), the reveal of any honest member's secret strictly follows the sealing of all K commitments. This is the temporal ordering FA3's hiding argument presumes: at Phase-1 *decision time* no honest secret has been revealed, so a deciding member's view of the others' secrets is only their commitments (FA3 L-3.3). T-4.2 is the C++-grounded statement that the implementation never reveals before the commit phase seals.

---

## 4. Composition with sibling proofs

- **FA3 (`SelectiveAbort.md`) — hiding / bias-resistance.** FA3 proves no member gains predictive advantage over `R` by selective secret choice or abort, under A3 preimage resistance + ROM. This proof supplies the structural scaffolding FA3 stands on: T-2 is the binding (FA3 L-3.2 V5 check), T-3.1 is the well-definedness of the `R` FA3 bounds, T-4.2 is the "no reveal before seal" temporal ordering FA3 L-3.3 presumes. The division of labor: **FA3 = hiding (A3); FA-Phase = binding + determinism + gate (A2 + purity).** Neither subsumes the other.
- **S-020 (`S020CommitteeSelection.md`) — the order `σ`.** S-020 T-5 gives the cross-node determinism of `σ` that T-1 takes as a premise; T-1 in turn is what lets the per-position commitment lookups (`enter_block_sig_phase`, `try_finalize_round`) agree across nodes. S-020 owns *which* members and *what order*; FA-Phase owns *what each member contributes and when*.
- **FA1 (`Safety.md`) — K-of-K finalization.** T-4 + T-4.1 supply the "every K-of-K signature attests a complete sealed commitment set in canonical order" lemma. FA1 then argues ≤1 finalized digest per height. T-1 Step 3 explicitly defers the ambiguous-commitment-race resolution to FA1.
- **FA5 (`BFTSafety.md`) — BFT Phase-2 quorum.** T-4 covers Phase-1 unanimity (mode-independent); the Phase-2 *signature* threshold `Q = ⌈2·k_bft/3⌉` and the sentinel-slot accounting are FA5's. This proof does not re-derive the BFT quorum arithmetic.
- **FB24 / FB40 (TLA+ primitives).** FB24 (`MakeContribCommitment.tla`) models the Phase-1 commitment primitive's determinism (INV-5) + field-binding (INV-6) + domain separation; FB40 (`MakeBlockSigPrimitive.tla`) models the Phase-2 sig's round/digest/member binding. This proof *composes* those per-primitive contracts into a per-block structural claim: T-1/T-3 use FB24's determinism at each Phase-1 position; T-2 uses the commitment's field-binding; T-4 sequences the two primitives via the K-arrived gate. The TLA+ specs pin the primitives; this proof pins their composition into the two-phase state machine.

---

## 5. Adversary model

### 5.1 A1 — post-Phase-1 secret substitution

*Setup.* A Byzantine member (or a relayer that received a member's `ContribMsg`) tries to make the finalized block carry a different secret `s'_i ≠ s_i` than the one committed in Phase 1 — e.g. to retarget `R`.

*Closure.* T-2: acceptance requires a SHA-256 second preimage of `creator_dh_inputs[i]` (≤ 2⁻¹²⁸) or an Ed25519 forgery of `creator_ed_sigs[i]` (negligible under A1). The substitution is rejected by `check_creator_dh_secrets` at every honest validator, not silently absorbed (T-2.1).

### 5.2 A2 — partial-commit-set Phase-2 sign

*Setup.* A Byzantine assembler tries to drive honest members into Phase 2 (signing) before all K commitments are in, hoping to seal a digest over a `< K` commitment set it can later extend favorably.

*Closure.* T-4: an honest node reaches `start_block_sig_phase` only after `enter_block_sig_phase` confirms a contrib is present for *every* `σ`-member (`node.cpp:923-928`); the size check is a necessary precondition and the per-`σ`-member lookup is the sufficient one. A short or out-of-order `creator_dh_inputs` vector is additionally rejected at validation (T-4.1). The assembler cannot make an honest node sign over a partial commitment set.

### 5.3 A3 — commitment-order manipulation

*Setup.* A Byzantine assembler reorders `creators` / `creator_dh_inputs` so the digest (and `delay_seed`) differ from what honest committee members signed, attempting to split the committee or bias the seed-input ordering.

*Closure.* The validator re-derives `σ` from `(random_state, N_pool, K)` and rejects any block whose `creators` order differs (`validator.cpp:128-132`, S-020 T-5 for the determinism of the re-derivation). `compute_delay_seed` and `compute_block_digest` consume `creator_dh_inputs` strictly in the block's `creators` order, which must equal `σ`. So a reordered block fails `check_creator_selection`; honest members never signed it, and it cannot reach K-of-K. (Bias from *choosing* a favorable ordering among many candidate seeds is a grinding attack closed by FA3 §5.3 / S-020 §5.3, not re-argued here.)

### 5.4 A4 — equivocating Phase-1 commitment

*Setup.* A Byzantine member gossips two different signed `ContribMsg` values at the same `(h, g)`, hoping different honest nodes seal different commitment sets.

*Closure.* Each honest node keeps the **first** admitted contrib per signer (T-1 Step 2; `on_contrib` does not overwrite, `node.cpp:2220`) and routes the conflict to slashing evidence (`node.cpp:2193-2218`). If the race causes honest nodes to seal different digests, FA1 guarantees at most one reaches K-of-K finalization (T-1 Step 3); the equivocator is slashed via FA6 (`EquivocationSlashing.md`). The two-phase structure does not finalize over an ambiguous commitment set.

---

## 6. What this proof does NOT establish (honest limitations)

1. **It does not prove `R` is unbiased / unpredictable.** That is FA3 (A3 + ROM). T-1–T-4 are silent on whether a member can *predict* or *bias* `R`; they only establish that `R` is a deterministic, binding, gated function of the agreed inputs. A reader needing the bias-resistance guarantee must read FA3.
2. **It does not prove liveness of the gate.** T-4 is a safety statement (Phase 2 begins *only after* K commits). It does not assert the gate *eventually* fires; an adversary who withholds a Phase-1 commitment stalls the round until the contrib timeout (`node.cpp:895-900`) triggers an abort + retry. That the chain makes progress despite such withholding is FA4 (`Liveness.md`).
3. **It does not cover the BFT Phase-2 quorum.** The mode-dependent *signature* threshold (`required_block_sigs`) and sentinel-slot accounting are FA5. T-4 covers only the mode-independent Phase-1 unanimity.
4. **It does not re-derive committee selection.** The determinism/uniformity of `σ` is S-020; this proof consumes S-020 T-5 as a premise.
5. **It does not analyze the F2 view-root extension's reconciliation.** When F2 is active the digest additionally binds reconciled evidence/receipt roots (`producer.cpp:598-630`); the *reconciliation* soundness is `EqAbortViewDigestExtension.md` / `F2ViewReconciliation.tla` (FB22). T-1–T-4 hold over the v1 core commitment shape and are unaffected by whether the F2 roots are zero (the `make_contrib_commitment` short-circuit, `producer.cpp:242-258`, keeps the core binding identical).

---

## 7. Implementation cross-reference

| Property | Source | Validator enforcement |
|---|---|---|
| Phase-1 secret draw + commit | `node.cpp:844-851` (`start_contrib_phase`) | — |
| Phase-1 commitment hash | `producer.cpp:219-260` (`make_contrib_commitment`) | `validator.cpp:167-173` |
| Phase-1 contrib admission (4 gates) | `node.cpp:2102-2131` (`on_contrib`) | — |
| First-arrival kept; equivocation flagged | `node.cpp:2164-2220` | `validator.cpp` equivocation checks (FA6) |
| K-arrived gate | `node.cpp:902-903`, `:2225-2227`, `:923-928` | — |
| Phase-2 sign (after gate) | `node.cpp:992-1053` (`start_block_sig_phase`) | — |
| Phase-2 reveal primitive | `producer.cpp:703-716` (`make_block_sig`) | — |
| Commit-reveal binding (T-2) | `node.cpp:847` ↔ `:1050` (same `current_round_secret_`) | `validator.cpp:355-371` (`check_creator_dh_secrets`) |
| `delay_seed` derivation (T-3) | `producer.cpp:509-518` | `validator.cpp:373-377` |
| `delay_output` derivation (T-3) | `producer.cpp:637-643` | `validator.cpp:386-390` |
| `cumulative_rand` chaining (T-3) | `producer.cpp:819-822` | (transitive via `prev_hash`) |
| Phase-1 unanimity at finalize | `node.cpp:1066-1073` (`try_finalize_round`) | — |
| Digest excludes secrets (T-1.1) | `producer.cpp:555-564`, `:577-632` | `validator.cpp:443` |

A reviewer can re-validate by reading those sites and confirming: (a) the same `current_round_secret_` is committed at `node.cpp:847` and revealed at `node.cpp:1050`; (b) `enter_block_sig_phase` `return`s on any missing `σ`-member contrib; (c) `check_creator_dh_secrets` is a strict-equality `SHA256(secret ‖ pubkey) == dh_input` check; (d) `compute_delay_seed` / `compute_block_rand` are pure append-and-finalize chains. These are the protocol-level corollaries of T-1 through T-4.

---

## 8. Conclusion

Determ's two-phase per-block consensus is a sound deterministic, binding, gated state machine: the K committee members converge on the same ordered Phase-1 commitment set before any reveal (T-1); each reveal is second-preimage-bound to its commitment and the binding is checked at every validator (T-2); the seed, randomness, and cumulative-randomness values are pure deterministic functions of the agreed inputs and the validator's independent re-derivation matches the producer's (T-3); and Phase-2 signing begins only after all K Phase-1 commitments are sealed in canonical order, in both consensus modes (T-4). These structural guarantees are the scaffolding on which FA3's bias-resistance (hiding) and FA1's finalization-safety stand — this proof owns the binding/determinism/gate layer (A2 + purity); FA3 owns the hiding layer (A3 + ROM); the two compose to give the full commit-reveal beacon guarantee.
