# CommitteeSelectionAbortDeterminismSoundness — abort-driven committee re-selection is deterministic across honest nodes

This document proves that Determ's **committee re-selection under round aborts** is a deterministic function of the *shared abort history*: any two honest nodes that observe the same ordered list of `AbortEvent`s at a given height re-derive a **byte-identical** committee. Consequently a Byzantine actor who grinds aborts can change *which* committee is selected, but cannot make honest nodes *disagree* on the committee — abort-grinding moves the committee identically for everyone, it does not fork the selection.

The load-bearing surface is the abort-seed-mixing loop at the producer (`src/node/node.cpp:796-808`) and its byte-for-byte mirror at the validator (`src/node/validator.cpp:122-133`, with the per-event reconstruction in `check_abort_certs` at `src/node/validator.cpp:238-310`). The mixing recurrence is

```
rand_0     = epoch_committee_seed(epoch_rand, shard_id)
rand_{i+1} = SHA256(rand_i ‖ abort_events[i].event_hash)
committee  = select_m_creators(rand_{|A|}, |avail|, k_use)
```

This proof closes the **abort path** that `S020CommitteeSelection.md` §1.3 explicitly defers: that document proves the *no-abort* hybrid-sampler determinism (`select_m_creators` for a fixed `(random_state, N, K)`, its T-5) and notes that the abort-shifted re-selection "is covered in §3 of `Censorship.md` as a sister case." On inspection, `Censorship.md` §3–§4 *uses* `select_m_creators`'s determinism + uniformity as a premise for the censorship bound but does **not** prove that the abort-mixed *seed* `rand_{|A|}` is itself deterministically shared across honest nodes. That seed-mixing determinism is the genuinely new ground this proof establishes.

**Companion documents:** `Preliminaries.md` (F0) for `N`, `K`, `random_state`, `cumulative_rand` notation; H1–H4 honest-validator assumptions; the H-det shared-prefix consensus precondition; A1 Ed25519 EUF-CMA; A2 SHA-256 collision resistance; A3 SHA-256 preimage resistance + the ROM treatment of SHA-256. `S020CommitteeSelection.md` (S-020) for the hybrid Fisher-Yates / rejection-sampler determinism (T-5) and the modulo-bias bound — this proof **composes** S-020's T-5 (it does not re-derive the sampler internals) and supplies the abort-path determinism S-020 §1.3 defers. `Censorship.md` (FA2) §3–§4 for the union-tx-root censorship bound whose `(f/N)^{KR}` persistent-censorship factor consumes the *uniformity* of each re-drawn committee — this proof supplies the orthogonal *determinism* of the re-draw. `BFTProposerElectionSoundness.md` for the within-committee *proposer* election (`proposer_idx`), which mixes the same ordered abort list into a *different* output (one leader index, not a committee set) — cross-referenced, not duplicated. `AbortCertificateSoundness.md` (FA-Cert / V10) for the abort-certificate quorum verification that authenticates each `AbortEvent` before it is admitted to the shared abort list — this proof takes the abort list's authenticity as given (FA-Cert's territory) and proves the *determinism* of consuming it. `Liveness.md` (FA4) for the abort-driven rotation progress argument. `docs/PROTOCOL.md` §5.1/§5.3 for the wire-level abort-event specification.

---

## 1. Introduction

### 1.1 Why aborts re-select the committee

Determ runs K-of-K MUTUAL_DISTRUST consensus: at each height a `K`-member committee is selected from the eligible pool, and the block finalizes only when all `K` contribute and sign. When a round attempt fails to gather a complete committee — a selected creator never contributes, or Phase-2 signature gathering stalls — the honest committee quorum assembles an `AbortEvent` against the missing creator (`Node::on_abort_claim`, `src/node/node.cpp:1273-1289`), appends it to the per-height `current_aborts_` list, and re-runs `check_if_selected` (`node.cpp:729`). The re-run **excludes** the aborted domains from the available pool and **re-derives** a fresh committee, so the next attempt routes around the stuck member. This is the liveness lever FA4 leans on.

The re-selection must satisfy two distinct correctness properties:

1. **Uniformity** (so a Byzantine coalition cannot grind aborts to land a fully-Byzantine committee with better-than-`(f/N)^K` probability) — owned by `Censorship.md` T-2.1 + `S020CommitteeSelection.md` T-1/T-2.
2. **Determinism across honest nodes** (so the re-selection produces the *same* committee everywhere, hence the validator's recompute matches the producer's selection and no honest fork arises from abort handling) — **this proof**.

Property 2 is non-trivial precisely because the re-selection seed is no longer the static per-epoch value: it is the static seed *mixed with a sequence of abort-event hashes*. If the mixing were sensitive to the order or membership of the abort list in a way that two honest nodes could observe differently, the committee would diverge.

### 1.2 The seed-mixing recurrence

The producer computes the re-selection seed at `src/node/node.cpp:796-800`:

```cpp
Hash epoch_rand = current_epoch_rand();
Hash rand = crypto::epoch_committee_seed(epoch_rand, cfg_.shard_id);
for (auto& ae : current_aborts_) {
    rand = crypto::SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
}
```

then selects at `node.cpp:803`:

```cpp
current_creator_indices_ = crypto::select_m_creators(rand, avail_domains.size(), k_use);
```

The validator's `check_creator_selection` mirror is at `src/node/validator.cpp:122-126`:

```cpp
Hash rand = prev_rand;                       // = epoch_committee_seed(epoch_rand, shard_id_)
for (auto& ae : b.abort_events) {
    rand = SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
}
auto indices = select_m_creators(rand, avail_domains.size(), m);
```

with `prev_rand = epoch_committee_seed(epoch_rand, shard_id_)` set at `validator.cpp:92`, exactly the producer's `rand_0`. The validator then equality-checks each selected domain against the block's claimed `creators` (`validator.cpp:128-132`).

Three structural facts drive the proof:

1. **The base seed is epoch-pinned and shared.** `rand_0 = epoch_committee_seed(epoch_rand, shard_id)` (`random.cpp:169-175`) is a pure SHA-256 over `(epoch_rand ‖ "shard-committee" ‖ shard_id)`. Under H-det all three inputs are agreed across honest nodes.
2. **The mixing input is a canonical ordered list.** The abort list is consumed in `std::vector` index order at both sites (`node.cpp:798` / `validator.cpp:123`), and that order is fixed by the block's `abort_events` field, which the validator reads from the *same* serialized block the producer broadcast. §2 establishes the list is linearly ordered and identically observed.
3. **Each `event_hash` is a fixed-width, content-bound 32-byte value.** `AbortEvent.event_hash` is a `Hash` (`include/determ/chain/block.hpp:228-237`) derived by `compute_abort_hash` / `chain_abort_hash` (`random.cpp:102-120`); the mix appends it via `SHA256Builder::append(const Hash&)`, a fixed 32-byte emission.

### 1.3 What this proof covers

- **T-1 (Canonical abort-list ordering).** The abort list consumed by the mixing loop is linearly ordered (by append order, which both honest nodes observe identically via the block's `abort_events` field), so the mixing *input sequence* is canonical.
- **T-2 (Seed-mixing recurrence determinism).** For any two honest nodes with the same `(epoch_rand, shard_id, abort-list)`, the recurrence `rand_{i+1} = SHA256(rand_i ‖ ae_i.event_hash)` produces a **byte-identical** final seed `rand_{|A|}`. Pure-function + fixed-width-serialization argument; no probabilistic term.
- **T-3 (End-to-end committee determinism).** Composing T-2 with `S020CommitteeSelection.md` T-5 (sampler determinism for a fixed seed) and the shared available-pool derivation: all honest nodes re-derive a byte-identical committee, so the validator's V3 recompute (`check_creator_selection`) accepts exactly the producer's committee and no honest fork arises from abort handling.
- **T-4 (Grind-invariance, not grind-immunity).** A Byzantine actor who influences the abort list changes the committee — but identically for every honest node. Abort-grinding is a *shared* state transition, never a divergence primitive. The bound on what that shared transition can *buy* the adversary (uniformity, slashing cost) is delegated to `Censorship.md` / `Liveness.md` / `AbortCertificateSoundness.md`; this proof pins only that the transition is shared.

### 1.4 What this proof does NOT cover

- **Sampler internals.** The uniformity, bounded runtime, and fixed-seed determinism of `select_m_creators` are `S020CommitteeSelection.md`'s territory (its T-1..T-6). This proof consumes S-020 T-5 as a black box: "for a fixed `(seed, N, K)`, `select_m_creators` is a deterministic pure function." It does not re-derive the rejection/Fisher-Yates branch behavior.
- **Abort-event authenticity.** That each `AbortEvent` in the list is backed by a valid `M−1` quorum certificate (so a Byzantine node cannot inject a fabricated abort against an honest member) is `AbortCertificateSoundness.md` (FA-Cert / V10). This proof assumes the abort list is *authentic*; it proves the *determinism* of consuming whatever authentic list is shared.
- **Unpredictability of `epoch_rand`.** That the base seed is unpredictable to the adversary before the epoch boundary is `Liveness.md` L4 + `SelectiveAbort.md` (FA3). This proof treats `epoch_rand` as an agreed value (H-det) and proves determinism, not unpredictability.
- **The grinding *payoff* bound.** Whether abort-grinding *helps* the adversary (it does not, beyond a uniform redraw at slashing cost) is `Censorship.md` §4 Step 4 + `BFTProposerElectionSoundness.md` PE-3 + `AbortEventApply.md` (FA-Apply-11). T-4 below states only the determinism half (grinding is shared), and cross-references those documents for the payoff half.
- **The *proposer* election within the committee.** `proposer_idx` (`producer.cpp`) mixes the *same* ordered abort list into a *single leader index*, a different output. `BFTProposerElectionSoundness.md` PE-1 proves that election's determinism; this proof proves the *committee-set* determinism. The two are seed-separated by the `"bft-proposer"` domain tag and are independent results.

---

## 2. Notation and assumptions

Fix a non-genesis height `h` with chain prefix `B_0, …, B_{h-1}` (genesis is excluded: both `check_creator_selection` and `check_abort_certs` early-return `{true,""}` / handle `chain.empty()` at `validator.cpp:63` and `validator.cpp:194-198`). Write:

- `K = cfg.k_block_sigs` — genesis-pinned committee size; `k_bft = ⌈2K/3⌉ = (2K+2)/3` (`node.cpp:778`, `validator.cpp:99`).
- `epoch_rand` — `cumulative_rand` resolved at the epoch boundary for `h` via `current_epoch_rand()` (producer, `node.cpp:796`) / `resolve_epoch_rand(epoch_start, chain)` (validator, `validator.cpp:91`). Constant across the epoch; agreed under H-det.
- `shard_id` — this chain's shard id, read identically at both sites.
- `rand_0 := epoch_committee_seed(epoch_rand, shard_id) = SHA256(epoch_rand ‖ "shard-committee" ‖ shard_id)` (`random.cpp:169-175`).
- `A = [ae_0, ae_1, …, ae_{n-1}]` — the ordered abort-event list for height `h`: `current_aborts_` at the producer, `b.abort_events` in the block / at the validator. Each `ae_i.event_hash` is a 32-byte SHA-256 digest (`block.hpp:228-237`).
- `rand_{i+1} := SHA256(rand_i ‖ ae_i.event_hash)` — the mixing recurrence; `rand_n` is the final re-selection seed.
- `avail` — the available domain pool: the region/refugee-filtered registry minus `{ae_i.aborting_node}` (`node.cpp:762-768`, `validator.cpp:110-118`). `N = |avail|`.
- `k_use` — `K` (MD mode) or `k_bft` (BFT escalation), chosen by the identical 4-gate predicate at `node.cpp:781-787` / `validator.cpp:100-108` (escalation soundness is `S025BFTEscalationSoundness.md`'s territory; here it suffices that the predicate is a deterministic function of agreed inputs).

**Assumptions.** (A2) SHA-256 collision resistance; (A3) SHA-256 preimage resistance, with SHA-256 modeled as a random oracle where a uniformity claim is invoked (none is invoked in T-1..T-3 — those are exact determinism results requiring no ROM). (H-det) all honest nodes share the same chain prefix at `h` (standard consensus precondition): they agree on `epoch_rand`, `shard_id`, the eligible registry snapshot, and the block's `abort_events` ordering. The determinism theorems T-1..T-3 require **no cryptographic hardness assumption at all** — they are byte-equality arguments over a pure function; A2/A3 enter only in §5's adversary discussion (to argue the adversary cannot make two honest nodes' authentic abort lists *differ* without breaking the certificate channel, which is FA-Cert's result).

---

## 3. Theorems

### T-1 (Canonical abort-list ordering)

**Theorem.** At height `h`, the abort list `A` consumed by the mixing loop is a finite, linearly-ordered sequence whose order and membership are observed identically by every honest node that accepts block `B_h`.

**Proof.** The list is a `std::vector<AbortEvent>`: `current_aborts_` at the producer (`node.cpp:763`, `798`) and `b.abort_events` at the validator (`validator.cpp:113`, `123`). A `std::vector` is index-ordered by definition; iteration `for (auto& ae : …)` traverses positions `0, 1, …, n-1` in that fixed order. So the *sequence* `[ae_0, …, ae_{n-1}]` is linearly ordered (totally ordered by index), independent of any comparator on the elements.

It remains to show two honest nodes observe the *same* sequence. The producer serializes its `current_aborts_` into the block as `B_h.abort_events`, in the same order (the block-body assembly carries the vector verbatim; `build_body` is invoked with `current_aborts_` at `node.cpp:1010`/`1125`/`2299`). The validator reads `b.abort_events` directly from the deserialized block it is validating — the *same bytes* the producer broadcast. Under H-det both nodes hold the same block `B_h`, hence the same `abort_events` vector, hence the same ordered sequence `A`.

A second honest node *producing* a competing attempt at the same height (e.g. after observing the same aborts via gossip) converges on the same `current_aborts_` content because each `AbortEvent` is adopted from the gossiped quorum certificate (`Node::on_abort_event`, `node.cpp:1306-1352`), which dedups by `(round, aborting_node)` before push (`node.cpp:1315-1320`). The *order* of adoption can in principle differ across nodes, but the order that enters the *chain* is the producer's serialized order; the validator (and any node that accepts `B_h`) consumes that canonical serialized order, not its local adoption order. So the order that matters for committee re-derivation — the order in `B_h.abort_events` — is canonical and identically observed. ∎

**Remark (chain-linkage rationale).** The abort assembly chains each event's hash to its predecessor: `chain_abort_hash(prev.event_hash, round, aborting_node, ts)` for non-first events (`node.cpp:1276-1280`). This linkage is *not* required for T-1 (the vector order alone is canonical), but it gives a second, intrinsic ordering signal: a reordered abort list would carry `event_hash` values inconsistent with the chained construction, which the abort-certificate verification path (`check_abort_certs`, `validator.cpp:238-310`) re-walks in order. So order is enforced both by the vector index *and* by the hash chain — T-1 holds under either reading.

### T-2 (Seed-mixing recurrence determinism)

**Theorem.** Fix `(epoch_rand, shard_id, A)`. The mixing recurrence

```
rand_0 = epoch_committee_seed(epoch_rand, shard_id)
rand_{i+1} = SHA256(rand_i ‖ ae_i.event_hash),  i = 0 … n-1
```

evaluates to the **byte-identical** 32-byte value `rand_n` on every honest node, every build, and every replay. No cryptographic assumption is needed.

**Proof.** Every step is a pure function of byte-exact, fixed-width inputs:

1. **Base seed.** `epoch_committee_seed` (`random.cpp:169-175`) appends `epoch_rand` (a 32-byte `Hash`, fixed width), the literal ASCII string `"shard-committee"` (fixed bytes), and `static_cast<uint64_t>(shard_id)` via `SHA256Builder::append(uint64_t)`. The latter emits a fixed **big-endian** 8-byte encoding (`src/crypto/sha256.cpp:30-34`: `for (int i = 7; i >= 0; --i) { buf[i] = v & 0xFF; v >>= 8; }`), so the seed bytes are endianness-independent. `epoch_rand` and `shard_id` are agreed under H-det. Hence `rand_0` is byte-identical across nodes.

2. **Mix step.** `SHA256Builder{}.append(rand_i).append(ae_i.event_hash).finalize()` (`node.cpp:799` / `validator.cpp:124`) appends two 32-byte `Hash` values via `append(const Hash&)` (`include/determ/crypto/sha256.hpp:17`, a fixed 32-byte emission) and finalizes via OpenSSL `EVP_DigestFinal_ex` (`sha256.cpp:40-44`). SHA-256 is bit-exact across architectures (FIPS 180-4 defines it at the bit level), and `Hash = std::array<uint8_t,32>` has a layout-defined byte sequence with no endianness ambiguity. So given byte-identical `rand_i` and `ae_i.event_hash`, the output `rand_{i+1}` is byte-identical.

3. **Induction.** By (1), `rand_0` is shared. By T-1, the sequence `[ae_0.event_hash, …]` is identical across honest nodes. By (2) applied inductively, if `rand_i` is shared then `rand_{i+1}` is shared. Hence `rand_n` is byte-identical everywhere.

The producer's loop (`node.cpp:798-800`) and the validator's loop (`validator.cpp:123-125`) are textually identical (`SHA256Builder{}.append(rand).append(ae.event_hash).finalize()` over the same ordered list seeded from the same `epoch_committee_seed`), so the producer's `rand_n` equals the validator's `rand_n` by the same induction. No I/O, clock, RNG, map-iteration-order, or floating-point operation appears in the recurrence; it is a pure function of its byte-exact inputs. ∎

**Corollary T-2.1 (Order sensitivity is shared, not divergent).** The recurrence is order-sensitive: permuting `A` generally changes `rand_n` (because `SHA256(SHA256(s ‖ x) ‖ y) ≠ SHA256(SHA256(s ‖ y) ‖ x)` for `x ≠ y` except with collision probability `≤ 2⁻¹²⁸` under A2). But by T-1 the order is canonical and shared, so this sensitivity is *not* a divergence channel — every honest node consumes the identical order and obtains the identical `rand_n`. Order sensitivity is what binds the seed to the *exact* abort history, which is the security-relevant property (Censorship.md), not a determinism hazard.

### T-3 (End-to-end committee determinism)

**Theorem.** At height `h`, every honest node re-derives a byte-identical committee `creators = [avail[idx_0], …, avail[idx_{k-1}]]`. Consequently the validator's V3 gate (`check_creator_selection`, `validator.cpp:128-132`) accepts a block iff its claimed `creators` equals the producer's deterministically-selected committee — no honest node disagrees, and the abort-handling path introduces no honest fork.

**Proof.** Decompose committee re-derivation into three deterministic stages, each a pure function of H-det-agreed inputs:

1. **Available pool `avail`.** Both sites filter the eligible registry by `committee_region` and the refugee-shard extension (`node.cpp:738-755` / `validator.cpp:72-88`), then exclude `{ae_i.aborting_node : ae_i ∈ A}` (`node.cpp:762-768` / `validator.cpp:110-118`). The registry snapshot, region, refugee set, and abort list are agreed under H-det; the filtering iterates the registry in its canonical sorted order (`eligible_in_region` returns the sorted eligible set) and the exclusion is a set-membership test. So `avail` (and `N = |avail|`) is byte-identically derived everywhere. The same exclusion-then-mix discipline is documented as the explicit mirror at `validator.cpp:111` ("Mirrors node.cpp::check_if_selected — exclusion + abort-mixed rand").

2. **Re-selection seed `rand_n`.** By T-2, the abort-mixed seed is byte-identical everywhere.

3. **Sampler output.** By `S020CommitteeSelection.md` T-5 (cross-node convergence), `select_m_creators(rand_n, N, k_use)` is a deterministic pure function of `(rand_n, N, k_use)`: same seed + same pool size + same committee size ⇒ byte-identical index vector. `k_use` is fixed by the identical escalation predicate at both sites (`node.cpp:781-787` / `validator.cpp:100-108`) over agreed inputs. So the index vector `[idx_0, …, idx_{k-1}]` is identical, and mapping through the identically-ordered `avail` (`node.cpp:806-808` / `validator.cpp:128-129`) yields a byte-identical `creators` list.

Composing (1)–(3): the committee is a deterministic pure function of the H-det-agreed `(registry snapshot, region, refugee set, epoch_rand, shard_id, A, K)`. The validator's `check_creator_selection` recomputes exactly this function and equality-checks `avail[indices[i]] == b.creators[i]` for each `i` (`validator.cpp:128-132`); the check passes iff the block's claimed committee equals the locally-recomputed one. Since every honest node recomputes the same committee, every honest node reaches the same accept/reject verdict on `B_h.creators`. There is no input by which two honest nodes could derive different committees from the same abort history, so abort-driven re-selection introduces no honest divergence. ∎

**Corollary T-3.1 (V3 ⇒ no honest fork via abort handling).** Two honest nodes attempting height `h` after observing the same authentic abort list `A` select the same committee (by T-3) and therefore the same set of permitted contributors; any block claiming a *different* committee for the same `A` is rejected by V3 at every honest validator. The residual case — two *different* abort lists `A ≠ A'` reaching different honest nodes — is a *liveness* / convergence question (gossip eventually converges the abort set; FA4) and a certificate-authenticity question (a fabricated abort cannot enter an honest node's list; FA-Cert), not a determinism failure of the re-selection function. Given a shared `A`, the committee is shared.

### T-4 (Grind-invariance: abort-grinding is a shared transition, not a divergence primitive)

**Theorem.** Let `Adv` be an adversary who influences the abort list (by inducing or withholding contributions to force aborts against chosen members). Any abort list `A'` that `Adv` causes to be admitted to the chain at height `h` yields, via T-3, a committee that is **identical across all honest nodes**. `Adv` cannot use abort-grinding to make two honest nodes select *different* committees at the same height.

**Proof.** Suppose `Adv` forces an authentic abort list `A'` to be serialized into `B_h.abort_events` (each event backed by a valid quorum certificate per FA-Cert; otherwise honest validators reject the block at `check_abort_certs`, `validator.cpp:238-310`, and it never enters the chain). Every honest node that accepts `B_h` reads the same `A'` (T-1) and, by T-3, re-derives the same committee. So whatever committee `A'` induces is induced *identically* for every honest node.

The only way `Adv` could create an honest *disagreement* would be to make two honest nodes consume *different* abort lists for the same accepted block — impossible, because they read the *same serialized block*. Alternatively `Adv` would have to make the mixing recurrence or sampler behave non-deterministically — impossible by T-2 + S-020 T-5 (both pure functions). Or `Adv` would inject an abort against an honest member into one honest node's list but not another's *before* a block is finalized — but a re-selection acts on the producer's serialized `abort_events`, and an un-certified local abort cannot enter the chain (FA-Cert); the transient pre-finalization divergence in local `current_aborts_` adoption order (T-1 remark) does not affect the canonical chain order.

Hence abort-grinding changes *which* committee is selected, identically for everyone — a shared state transition. ∎

**Scope disclaimer (what T-4 does NOT claim).** T-4 proves only *invariance of agreement under grinding*. It does **not** claim grinding is useless to the adversary in the uniformity / payoff sense — that is a separate, delegated result:

- That each abort-induced redraw is *uniform* (so `Adv` cannot bias toward a fully-Byzantine committee beyond `(f/N)^K` per draw) is `Censorship.md` T-2.1 + `S020CommitteeSelection.md` T-1/T-2.
- That the number of grinding rounds is *bounded* (by the BFT-escalation threshold, after which the committee shrinks and stops re-randomizing freely) is `Censorship.md` §4 Step 4 + `Liveness.md` §6.
- That each induced Round-1 abort carries a *slashing cost* (proportional stake forfeiture) is `AbortEventApply.md` (FA-Apply-11) T-A1.
- The analogous grind-resistance for the within-committee *proposer* index is `BFTProposerElectionSoundness.md` PE-3.

This proof's contribution is strictly the determinism half: whatever the adversary grinds, honest nodes agree on the result.

---

## 4. Adversary scenarios

| Adversary | Goal | Defeated by |
|---|---|---|
| `A_diverge` (committee-fork via aborts) | Make two honest nodes select different committees at one height by manipulating the abort sequence | T-3 + T-4: all honest nodes read the same serialized `B_h.abort_events`, run the same pure mixing recurrence (T-2) and sampler (S-020 T-5), and re-derive the same committee. No abort manipulation creates honest disagreement. |
| `A_reorder` (abort-list permutation) | Reorder `abort_events` so the producer's seed differs from the validator's recompute | T-1: the validator consumes the block's canonical serialized order, byte-for-byte the producer's; the hash-chain linkage (`chain_abort_hash`, `node.cpp:1276-1280`) gives a second intrinsic order signal re-walked by `check_abort_certs`. T-2.1: order sensitivity is shared, not divergent. |
| `A_inject` (fabricated abort) | Inject an abort against an honest member into one node's list to shift its committee | Out of scope here, closed by `AbortCertificateSoundness.md` (FA-Cert / V10): an un-certified abort is rejected at `check_abort_certs` (`validator.cpp:267-305`) and never enters the canonical list. T-3 then applies to whatever *authentic* list is shared. |
| `A_grind` (steer committee) | Grind aborts to land a favorable committee | T-4: grinding is a *shared* transition (favorable identically for everyone, so no fork); the *payoff* bound (uniform redraw, slashing cost, bounded rounds) is delegated to `Censorship.md` §4 + `Liveness.md` §6 + `AbortEventApply.md` T-A1. |
| `A_nondeterm` (replay divergence) | Make a node re-derive a different committee on chain reload / snapshot restore | T-2 + T-3: the recurrence is a pure function of agreed inputs; `epoch_rand` is restored byte-identically (`SnapshotEquivalence.md`), `abort_events` is part of the block body, so replay reproduces the identical seed and committee. |

---

## 5. Concrete-security summary

- **Ordering (T-1):** exact — the abort list is `std::vector` index-ordered and the validator consumes the producer's canonical serialized order; zero failure probability.
- **Seed-mixing (T-2):** exact — a pure-function byte-equality result over fixed-width SHA-256 inputs; no cryptographic assumption, zero failure probability. The only place A2 enters is Corollary T-2.1's *order-sensitivity* claim (distinct orders give distinct seeds except with `≤ 2⁻¹²⁸` collision probability), which is a security *feature* (binding the seed to the exact history), not a determinism risk.
- **Committee determinism (T-3):** exact — composes T-2 with the pure-function pool-derivation and `S020CommitteeSelection.md` T-5 sampler determinism; zero failure probability for the agreement property.
- **Grind-invariance (T-4):** exact — agreement under grinding holds with probability 1; the orthogonal payoff bound is delegated.

Net: abort-driven committee re-selection contributes **no new failure term** to the consensus safety budget. It is an exact (probability-1) deterministic function of the shared abort history, so a Byzantine abort-grinder can move the committee but cannot fork honest nodes' view of it. The security argument for why the residual (grinding moves the committee *somewhere*) is bounded lives in `Censorship.md` (uniformity), `Liveness.md` (bounded rounds), and `AbortEventApply.md` (slashing cost) — this proof supplies the determinism precondition those arguments rest on.

---

## 6. Implementation cross-reference

| Property / element | Source |
|---|---|
| Producer abort-seed-mixing loop | `src/node/node.cpp:796-800` (`epoch_committee_seed` base + `SHA256(rand ‖ ae.event_hash)` mix) |
| Producer re-selection + map to domains | `src/node/node.cpp:803-808` (`select_m_creators` + `avail_domains[idx]`) |
| Producer available-pool derivation (region + refugee + abort-exclude) | `src/node/node.cpp:738-768` |
| Producer escalation predicate (`k_use` choice) | `src/node/node.cpp:781-787` |
| Producer abort-event assembly + hash chaining | `src/node/node.cpp:1273-1289` (`compute_abort_hash` / `chain_abort_hash`) |
| Producer gossiped-abort adoption + dedup | `src/node/node.cpp:1306-1352` |
| Validator V3 mirror (`check_creator_selection`) | `src/node/validator.cpp:61-134` (seed mix `122-125`, equality check `128-132`) |
| Validator base seed `prev_rand` | `src/node/validator.cpp:91-92` (`resolve_epoch_rand` → `epoch_committee_seed`) |
| Validator per-event committee reconstruction (`check_abort_certs`) | `src/node/validator.cpp:238-310` (mix step `309`) |
| Hybrid sampler `select_m_creators` | `src/crypto/random.cpp:70-99` |
| `epoch_committee_seed` (domain-separated base seed) | `src/crypto/random.cpp:169-175` |
| `compute_abort_hash` / `chain_abort_hash` | `src/crypto/random.cpp:102-120` |
| `SHA256Builder::append(uint64_t)` big-endian fixed-width | `src/crypto/sha256.cpp:30-34` |
| `SHA256Builder::append(const Hash&)` fixed 32-byte | `include/determ/crypto/sha256.hpp:17` |
| `AbortEvent` struct (`event_hash`, `aborting_node`, `round`, `claims_json`) | `include/determ/chain/block.hpp:228-237` |

A reviewer can confirm:

- The producer mix loop (`node.cpp:798-800`) and the validator mix loop (`validator.cpp:123-125`) are textually identical SHA-256 recurrences over the same ordered list seeded from the same `epoch_committee_seed` — the mirror is structural, not coincidental.
- The base seed at both sites is `epoch_committee_seed(epoch_rand, shard_id)` with the same `"shard-committee"` domain tag (`random.cpp:172`), so the abort path inherits the same shard/epoch pinning as the no-abort path.
- `append(uint64_t)` emits big-endian (`sha256.cpp:32`), so the seed and committee are byte-identical across CPU architectures — closing the cross-node determinism requirement T-2 leans on.

---

## 7. Relationship to the consensus proof family

This proof closes the abort-determinism sub-case deferred by `S020CommitteeSelection.md` §1.3 and threads between three sibling results:

```
S-020 (hybrid sampler determinism, fixed seed)  ──→  select_m_creators is a pure function of (seed, N, K)
        │
        ▼
THIS PROOF (abort-seed-mixing determinism)  ──→  rand_n is byte-identical across honest nodes for a shared abort list (T-2)
        │                                          ⇒ committee is byte-identical across honest nodes (T-3)
        ├──────────────→  Censorship.md (FA2): uniformity of each (re)drawn committee  ⇒  (f/N)^{KR} censorship bound
        ├──────────────→  Liveness.md (FA4): abort-driven rotation makes progress in bounded rounds
        └──────────────→  AbortCertificateSoundness.md (FA-Cert): the abort list is authentic (V10 quorum verification)

  (sibling, seed-separated by "bft-proposer" tag)
  BFTProposerElectionSoundness.md (PE-1): the SAME ordered abort list deterministically elects ONE proposer index
```

- **From S-020:** the fixed-seed sampler determinism (T-5), consumed as a black box in T-3 stage 3.
- **To Censorship.md (FA2):** FA2's `(f/N)^{KR}` persistent-censorship bound needs each re-drawn committee to be *uniform*; FA2 supplies that. This proof supplies the orthogonal *determinism* — that the re-draw is the same for everyone — which FA2 §3–§4 assumes implicitly when it treats `select_m_creators(rand, …)` as "the unique valid block's committee."
- **To Liveness.md (FA4):** abort-driven rotation (excluding the stuck member, re-mixing the seed) is the progress lever; T-3 guarantees the rotation lands the same committee at every honest node so the next attempt is coherent.
- **To AbortCertificateSoundness.md (FA-Cert):** FA-Cert authenticates each abort before it joins the shared list; this proof proves determinism of consuming the authenticated list. The two compose: an honest member is never falsely aborted (FA-Cert) *and* whatever authentic aborts occur drive a shared committee re-selection (this proof).
- **To BFTProposerElectionSoundness.md:** the same ordered abort list feeds `proposer_idx` (a leader index) and the committee mix (a member set) through *separate* domain tags (`"bft-proposer"` vs `"shard-committee"`); PE-1 proves the proposer election's determinism, this proof the committee-set's. Independent outputs, parallel determinism arguments.
