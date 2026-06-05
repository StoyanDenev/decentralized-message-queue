# BFTProposerElectionSoundness — within-BFT-committee deterministic proposer election soundness

This document is the analytic soundness proof for the **within-committee proposer election** that fires once a height has escalated to BFT mode: `proposer_idx` at `src/node/producer.cpp:520-533`, driven by the epoch-pinned, shard-salted seed `epoch_committee_seed(epoch_rand, shard_id)` (`src/crypto/random.cpp:169-175`) and the round's accumulated `AbortEvent` list. The election names exactly one of the `|K_h|` BFT-committee members as the round's `bft_proposer`; that member alone finalizes the block (`src/node/node.cpp:1039`), eliminating the silent-fork race in which different peers would otherwise pick different `Q`-subsets of the available signatures. The validator independently re-derives the same index and rejects any block whose `bft_proposer` field disagrees, whose proposer index lands out of range, or whose proposer slot is sentinel-zero (`src/node/validator.cpp:408-426`).

This proof exists because the FA5 BFT-mode safety proof (`BFTSafety.md`) covers the *quorum-intersection* property of a finalized BFT block, and the S-025 escalation proof (`S025BFTEscalationSoundness.md`) covers the *4-gate transition predicate* that decides whether a height runs in BFT mode at all — but neither formalizes the *leader-selection function* that picks which committee member is permitted to finalize. The proposer election is the load-bearing decision between those two: it is the mechanism by which "≥ Q members signed" (FA5) collapses to "exactly one canonical block" (no fork). If the election were non-deterministic across honest nodes, two honest proposers could each finalize a distinct valid block at the same height; if it were grindable by an adversary, a Byzantine pool member could steer the proposer role onto itself across many heights; if its seed lacked domain separation it could collide with the committee-set seed and leak structure. The four theorems below close exactly those gaps.

**Companion documents:** `Preliminaries.md` (F0) for the `K`, `|K_h|`, `random_state`, `cumulative_rand` notation; H1–H4 honest-validator assumptions; A1 Ed25519 EUF-CMA; A2 SHA-256 collision resistance; A3 SHA-256 preimage resistance + the ROM treatment of SHA-256 used in §3. `BFTSafety.md` (FA5) for the BFT-mode conditional-safety theorem (`f_h < |K_h|/3`) whose "exactly one canonical block" conclusion this proof supplies the proposer-uniqueness half of. `S025BFTEscalationSoundness.md` (S-025) for the 4-gate predicate that establishes BFT mode is in scope at the height in question — the precondition under which `proposer_idx` is ever consulted. `S020CommitteeSelection.md` (S-020) for the hybrid Fisher-Yates selection of the *committee set* `K_h ⊂ V` from which this election picks one leader — the two are deliberately seed-separated (S-020 derives committee membership; this proof derives the leader *within* that membership). `Safety.md` (FA1) for the MD-mode K-of-K safety the proposer field is forbidden in (`bft_proposer` must be empty in MUTUAL_DISTRUST blocks, `validator.cpp:406`). `EquivocationSlashing.md` (FA6) for the slashing path that punishes a proposer who signs two distinct digests at one height — the economic backing that makes a grindability win worthless. `Liveness.md` (FA4) for the rotational-progress argument the abort-driven proposer rotation feeds. `docs/PROTOCOL.md` §5.3.1 for the `bft_proposer` wire specification; `docs/SECURITY.md` §S-025 + §S-030 for the closure context.

---

## 1. Introduction

### 1.1 Why BFT mode needs a designated proposer

Determ's default consensus is MUTUAL_DISTRUST (MD) K-of-K: every one of the `K` committee members must contribute and sign, and the block finalizes only when all `K` `creator_block_sigs[]` are non-zero. In MD mode there is no proposer — the block is fully determined by the canonical contribution ordering, so any honest node that has gathered all `K` signatures finalizes the *same* block. There is nothing to elect.

BFT mode (escalation per S-025's 4-gate predicate) breaks that symmetry. The committee shrinks from `K` to `|K_h| = ⌈2K/3⌉`, and a block finalizes on only `Q = ⌈2|K_h|/3⌉` of the `|K_h|` sigs being present; the remaining `|K_h| − Q` slots may be sentinel-zero (`validator.cpp` BFT branch via `producer.cpp::required_block_sigs`). With a *strict subset* of the committee sufficient to finalize, two honest nodes that each gathered a *different* `Q`-subset of the available signatures would assemble two distinct blocks (different sentinel-zero positions ⇒ different `creator_block_sigs[]` vectors ⇒ different `compute_block_digest` ⇒ different block hash). Both could be individually valid under V8's "≥ Q non-zero" rule. That is the **silent-fork race**: two valid, non-equivocating blocks at one height, produced by two honest nodes who simply observed signatures in a different order.

The fix is to designate exactly one committee member as the round's **proposer** and require, at the validator, that the block's `bft_proposer` field equals the deterministically-elected member AND that member's signature slot is non-zero (`validator.cpp:420-425`). Only the elected proposer finalizes (`node.cpp:1039`: `if (mode == BFT && cfg_.domain != proposer) return;`). Every honest node now agrees on *who* finalizes, so the silent-fork race cannot arise from honest nodes alone. This proof pins the properties that make that designation sound.

### 1.2 The election function

The election is `proposer_idx` (`src/node/producer.cpp:520-533`):

```cpp
size_t proposer_idx(const Hash& prev_cum_rand,
                    const std::vector<AbortEvent>& aborts,
                    size_t committee_size) {
    if (committee_size == 0) return 0;
    SHA256Builder b;
    b.append(prev_cum_rand);
    for (auto& ae : aborts) b.append(ae.event_hash);
    b.append(std::string("bft-proposer"));
    Hash mix = b.finalize();
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i)
        v = (v << 8) | mix[i];
    return static_cast<size_t>(v % committee_size);
}
```

The first argument is **not** the raw prior-block `cumulative_rand`; both call sites pass the **epoch-pinned, shard-salted** seed:

```cpp
// Producer side (node.cpp:942-946, via current_proposer_domain):
Hash epoch_rand = current_epoch_rand();
Hash seed = crypto::epoch_committee_seed(epoch_rand, cfg_.shard_id);
size_t idx = proposer_idx(seed, current_aborts_, current_creator_domains_.size());

// Validator side (validator.cpp:414-417, within check_block_sigs BFT branch):
Hash erand = resolve_epoch_rand(estart, chain);
Hash seed  = epoch_committee_seed(erand, shard_id_);
size_t expected_idx = proposer_idx(seed, b.abort_events, b.creators.size());
```

with

```cpp
// random.cpp:169-175
Hash epoch_committee_seed(const Hash& epoch_rand, ShardId shard_id) {
    return SHA256Builder{}
        .append(epoch_rand)
        .append(std::string("shard-committee"))
        .append(static_cast<uint64_t>(shard_id))
        .finalize();
}
```

The returned index is into `current_creator_domains_` (producer) / `b.creators` (validator) — the *already-ordered* BFT committee. The elected domain is `creators[idx]`.

Three structural facts drive the proof:

1. **Epoch-pinning.** The seed is keyed on `epoch_rand` (the `cumulative_rand` at the epoch boundary, `node.cpp:914-933`), not the immediately-prior block. Within one epoch, the *only* thing that moves the proposer is the accumulated abort list. This is by design: it keeps proposer derivation consistent with the S-020 committee-selection seed (same `epoch_committee_seed` salting), so the proposer is always a member of the committee that was selected from the same epoch seed.
2. **Abort-driven rotation.** Each round-attempt that aborts appends an `AbortEvent` whose `event_hash` enters the mix. So a stalled proposer is rotated off on the next attempt (the mix changes, `v % |K_h|` moves), which is the liveness lever FA4 leans on.
3. **Double domain separation.** The seed carries the `"shard-committee"` tag (S-020's committee-set domain) and `proposer_idx` adds a second `"bft-proposer"` tag before finalizing. The committee-set draw and the leader draw therefore consume *independent* random oracles even though both descend from the same `epoch_rand`.

### 1.3 What this proof covers and does not

**In scope.**

- **PE-1 (Determinism / honest agreement).** For a fixed `(epoch_rand, shard_id, abort-list, |K_h|)`, every honest node computes the same proposer index, hence the same `bft_proposer` domain — across any node, build, or replay. This is the property that kills the silent-fork race from honest nodes.
- **PE-2 (Near-uniform, low-bias selection).** The elected index is distributed over `[0, |K_h|)` with modulo bias `≤ 2⁻⁵⁶` for every supported `|K_h| ≤ 256`, under the ROM treatment of SHA-256. No committee position is materially favored.
- **PE-3 (Grinding / steering resistance).** Under A3 + the commit-reveal unpredictability of `epoch_rand` (Preliminaries; Liveness L4), an adversary controlling a subset of committee members cannot steer the proposer role onto a chosen member with probability better than the honest near-uniform baseline, except by inducing aborts — and abort-induced rotation is itself bounded and economically penalized (FA6).
- **PE-4 (Producer–validator mirror).** The producer's elected proposer and the validator's independently-recomputed `expected_idx` are byte-identical given the same chain prefix, so no block that names the wrong proposer (or an out-of-range index, or an unsigned proposer slot) is ever accepted. This is the gate that turns PE-1's honest agreement into a hard rejection of adversarial mis-naming.

**Out of scope (delegated).**

- The 4-gate predicate that puts the height in BFT mode in the first place — `S025BFTEscalationSoundness.md`. This proof assumes BFT mode is already in scope.
- The selection of the committee *set* `K_h` from the validator pool — `S020CommitteeSelection.md`. This proof takes `creators` / `current_creator_domains_` as given and elects *within* it.
- The quorum-intersection safety of a finalized BFT block — `BFTSafety.md` (FA5). PE-4 supplies the proposer-uniqueness half; FA5 supplies the signature-intersection half.
- The unpredictability of `epoch_rand` as a random value — `Liveness.md` L4 + `Censorship.md` T-2.1 + `SelectiveAbort.md` (FA3). This proof consumes that unpredictability as a hypothesis (H-rand below), it does not re-derive it.
- The slashing that punishes a proposer who finalizes two distinct digests at one height — `EquivocationSlashing.md` (FA6). This proof shows the *honest* path is fork-free; FA6 shows the *dishonest* path is detected and slashed.
- The straight-modulo choice (vs. rejection-sampled debias) is justified here by the bias bound PE-2; the analogous bias analysis for the committee-set `hash_mod` is in `S020CommitteeSelection.md` §2.

---

## 2. Notation and assumptions

Let `h` be a height that has escalated to BFT mode (per S-025's 4-gate predicate; this is the standing precondition). Write:

- `K` — genesis-pinned committee size (`cfg.k_block_sigs`).
- `K_h ⊂ V` — the BFT committee at height `h`, `|K_h| = ⌈2K/3⌉`, ordered as the vector `creators` (producer: `current_creator_domains_`). Worked sizes: `K=3 ⇒ |K_h|=2`; `K=6 ⇒ |K_h|=4`; `K=9 ⇒ |K_h|=6`.
- `epoch_rand` — `cumulative_rand` resolved at the epoch boundary for `h` (`current_epoch_rand` / `resolve_epoch_rand`). Constant across the epoch.
- `seed := epoch_committee_seed(epoch_rand, shard_id)` — the domain-separated, shard-salted committee seed.
- `A_h = [ae_0, ae_1, …]` — the ordered abort-event list for the current attempt (`current_aborts_` at the producer; `b.abort_events` in the block). Each `ae_i.event_hash` is a 32-byte SHA-256 digest.
- `mix := SHA256(seed ‖ ae_0.event_hash ‖ … ‖ "bft-proposer")`.
- `v := be64(mix[0..8))` — the leading 8 bytes of `mix` read big-endian into a `uint64_t`.
- `p := v mod |K_h|` — the elected index; `proposer := creators[p]`.

**Assumptions.** (A1) Ed25519 EUF-CMA; (A2) SHA-256 collision resistance; (A3) SHA-256 preimage resistance, with SHA-256 modeled as a random oracle for the uniformity argument (Preliminaries §2.1; the same ROM treatment S-020 uses). (H-det) all honest nodes share the same chain prefix at `h` (standard consensus precondition; they agree on `epoch_rand`, `shard_id`, the committee ordering, and the abort list carried in the block). (H-rand) `epoch_rand` is unpredictable to the adversary before the epoch boundary is finalized — the commit-reveal property proven in `SelectiveAbort.md` (FA3) and consumed by `Liveness.md` L4. This proof treats (H-rand) as a hypothesis; it is established elsewhere.

---

## 3. Theorems

### PE-1 (Determinism / honest agreement)

**Theorem.** Fix `(epoch_rand, shard_id, A_h, |K_h|)` with `|K_h| > 0`. Then `proposer_idx(epoch_committee_seed(epoch_rand, shard_id), A_h, |K_h|)` returns the same value on every honest node, every build, and every replay; consequently `proposer = creators[p]` is the same domain everywhere.

**Proof.** `proposer_idx` is a pure function: it reads only its three arguments, allocates a `SHA256Builder`, appends a fixed, argument-determined byte sequence, finalizes, reads 8 fixed bytes, and returns a modulo. There is no I/O, no clock, no RNG state, no map iteration whose order could vary, and no floating point. The `for (auto& ae : aborts)` loop iterates a `std::vector` in index order, which is identical across nodes given the same vector contents and ordering (H-det guarantees the same abort list: the producer's `current_aborts_` is serialized into the block as `b.abort_events` in the same order, and the validator reads that same ordered vector). `epoch_committee_seed` is likewise a pure SHA-256 over `(epoch_rand, "shard-committee", shard_id)`, all three of which are agreed under H-det. The big-endian read `v = (v<<8)|mix[i]` over `i ∈ [0,8)` is endianness-independent (it is byte-wise, not a reinterpret-cast). `v mod |K_h|` is integer-exact in `uint64_t`. Therefore the entire pipeline is a deterministic function of agreed inputs, and all honest nodes obtain the identical `p`, hence the identical `proposer`. ∎

**Remark (why this kills the honest silent-fork race).** With every honest node agreeing on `proposer`, and only `proposer` permitted to finalize (`node.cpp:1039`), at most one honest-produced block can exist per height: the one assembled by `creators[p]`. Two distinct honest blocks would require two distinct honest finalizers, contradicting PE-1. The residual case — `proposer` itself is Byzantine and finalizes two digests — is not a fork between honest nodes; it is detectable equivocation, handled by FA6 (and PE-4 ensures no node accepts a block naming a *different* proposer).

### PE-2 (Near-uniform, low-bias selection)

**Theorem.** Under the ROM treatment of SHA-256 (A3), for every supported committee size `|K_h| ∈ [1, 256]`, the elected index `p = v mod |K_h|` is distributed over `[0, |K_h|)` with total-variation distance from uniform at most `2⁻⁵⁶`. No committee position is favored by more than that bias.

**Proof.** Under ROM, `mix` is a uniform 256-bit string; `v` is then a uniform 64-bit integer in `[0, 2⁶⁴)`. The modulo `v mod n` (with `n = |K_h|`) is uniform iff `n` divides `2⁶⁴`; otherwise it carries the standard modulo bias. Write `2⁶⁴ = qn + r` with `0 ≤ r < n`. The first `r` residues `{0, …, r−1}` each receive `q+1` of the `2⁶⁴` preimages; the remaining `n−r` residues receive `q` each. The per-residue probability gap is `1/2⁶⁴`, and the total-variation distance from uniform is

$$
\Delta \;=\; \tfrac12 \sum_{j=0}^{n-1}\Bigl| \Pr[p=j] - \tfrac1n \Bigr|
\;\le\; \frac{r(n-r)}{n \cdot 2^{64}} \;\le\; \frac{n}{4\cdot 2^{64}} \;<\; \frac{n}{2^{66}}.
$$

For the protocol's supported BFT committee sizes `|K_h| ≤ 256 = 2⁸` (a hard structural ceiling: `K` is genesis-pinned and no production or test profile sets `K` anywhere near 256 — the largest test profile is `global_test` K=5, so `|K_h| ≤ 256` holds with vast margin), `Δ < 2⁸ / 2⁶⁶ = 2⁻⁵⁸ < 2⁻⁵⁶`. The 8-byte (64-bit) truncation of `mix` is sufficient: even the worst-case `n` near 256 leaves 56 bits of headroom over the modulus, so the bias is dominated by the `2⁻⁵⁸` term, not by truncation. ∎

**Remark (why straight-modulo, not rejection-debias).** S-020's committee-set draw uses an internal rejection loop in `hash_mod` to make the per-pick modulo *exactly* uniform, because that draw is repeated `K` times and any bias compounds across picks and across the harmonic blow-up regime. The proposer election is a *single* pick per round over a *tiny* modulus (`|K_h| ≤ 256`), so the `2⁻⁵⁸` bias is already cryptographically negligible and a rejection loop would add latency variance (a faint timing channel) for no security gain. The straight-modulo choice is the correct engineering trade here; PE-2 quantifies that it is safe.

### PE-3 (Grinding / steering resistance)

**Theorem.** Let `M ⊊ K_h` be the set of committee members an adversary controls, `m = |M|`. Under (A3) + (H-rand), the adversary cannot bias the event `proposer ∈ M` above the honest baseline `m/|K_h| + 2⁻⁵⁶` by any choice the adversary makes *before* `epoch_rand` is finalized, and within an epoch can influence the election only by inducing aborts, each of which (a) advances the mix to a fresh near-uniform draw (PE-2) and (b) carries the FA6 / abort-slashing cost.

**Proof.** Decompose the adversary's possible influence on `p` into the three inputs of `proposer_idx`:

1. **`seed` (via `epoch_rand`).** Under (H-rand), `epoch_rand` is unpredictable to the adversary until the epoch boundary block is finalized — at which point the committee `K_h` and the seed are *jointly* fixed and the adversary can no longer change either. The adversary cannot choose `epoch_rand` to land the proposer on `M`: by (A3)/ROM, `seed = SHA256(epoch_rand ‖ "shard-committee" ‖ shard_id)` is a fresh uniform value the adversary cannot precompute a preimage for, and `mix = SHA256(seed ‖ … ‖ "bft-proposer")` is a second uniform value. To force `p ∈ {indices of M}` the adversary would need to find an `epoch_rand` whose double-hashed image lands `v mod |K_h|` in a chosen residue class — a preimage-search against SHA-256 with success probability `≤ |M|/|K_h|` per query (no better than guessing), i.e. no advantage over the honest baseline. The `"shard-committee"` and `"bft-proposer"` domain tags prevent the adversary from re-using a grinding effort spent on the *committee-set* draw (S-020) to also bias the *proposer* draw: the two oracles are separated, so a preimage useful for one is useless for the other.

2. **`A_h` (the abort list).** The adversary *can* affect the abort list — inducing an abort appends an `AbortEvent` and changes the mix. But (i) by PE-2 each fresh mix yields a near-uniform redraw, so an abort moves the proposer to a *uniformly random* new index, not a chosen one (the adversary cannot pre-image the post-abort `event_hash` to a target residue without a SHA-256 preimage win, A3); (ii) each induced abort is itself an observable, slashable event — Round-1 aborts trigger proportional stake slashing (`AbortEventApply.md` FA-Apply-11 T-A1), and an equivocating proposer is fully slashed + deregistered (FA6). So abort-driven rotation is a bounded, costly random walk over `[0,|K_h|)`, not a steering primitive. The expected number of aborts to land any *specific* target index is `|K_h|` (geometric), and each costs the adversary stake; the steering "gain" is strictly negative in expectation.

3. **`|K_h|`** is genesis-pinned (`⌈2K/3⌉` from `cfg.k_block_sigs`) and not adversary-controlled at runtime.

Combining: the only knob with non-negligible effect is abort-induction, which yields uniform redraws at slashing cost, never a chosen index. Hence `Pr[proposer ∈ M] ≤ m/|K_h| + 2⁻⁵⁶` per round for any pre-`epoch_rand` strategy, and any within-epoch deviation above that baseline is paid for in slashed stake. ∎

**Remark.** PE-3 is the reason epoch-pinning the seed is *safer* than re-seeding per block from the immediately-prior `cumulative_rand`: a per-block reseed would give a producer-aligned adversary a fresh grinding target every height (it could try to influence the next block's `cumulative_rand` to steer the following proposer). Epoch-pinning collapses the grinding surface to one boundary value per epoch (covered by H-rand) plus the abort list (covered by slashing). This is the same hardening rationale S-020 uses for the committee-set seed; the two share `epoch_committee_seed` deliberately.

### PE-4 (Producer–validator mirror)

**Theorem.** For any block `B` with `B.consensus_mode = BFT` accepted by an honest validator against chain prefix `C`, the validator's recomputed `expected_idx = proposer_idx(epoch_committee_seed(resolve_epoch_rand(estart, C), shard_id), B.abort_events, |B.creators|)` satisfies (i) `expected_idx < |B.creators|`, (ii) `B.bft_proposer == B.creators[expected_idx]`, and (iii) `B.creator_block_sigs[expected_idx] ≠ 0`. Equivalently: no BFT block that names the wrong proposer, an out-of-range index, or an unsigned proposer slot is ever accepted; and an MD block carrying any non-empty `bft_proposer` is rejected.

**Proof.** The validator's BFT branch (`validator.cpp:408-426`) executes exactly:

```cpp
EpochIndex epi = epoch_blocks_ ? (b.index % epoch_blocks_) : 0;
uint64_t   estart = epi * (epoch_blocks_ ? epoch_blocks_ : 1);
Hash erand = resolve_epoch_rand(estart, chain);
Hash seed  = epoch_committee_seed(erand, shard_id_);
size_t expected_idx = proposer_idx(seed, b.abort_events, b.creators.size());
if (expected_idx >= b.creators.size())              return {false, "proposer index out of range"};
if (b.bft_proposer != b.creators[expected_idx])     return {false, "wrong BFT proposer: …"};
Signature zero{};
if (b.creator_block_sigs[expected_idx] == zero)     return {false, "BFT proposer did not sign"};
```

The validator's seed computation is *byte-identical* to the producer's (`node.cpp:942-944` vs `validator.cpp:414-416`): same `epoch_committee_seed`, same `shard_id` (both read the chain's shard id), same `proposer_idx`. The only sourcing difference is `current_epoch_rand()` (producer, walks its in-memory chain) vs `resolve_epoch_rand(estart, chain)` (validator, walks the chain prefix it is validating against) — and under H-det these return the same `epoch_rand` because both resolve the `cumulative_rand` at the same epoch-start index of the same agreed prefix. The abort list is sourced from `b.abort_events` (the validator) which is precisely the producer's `current_aborts_` serialized into the block (the block carries its own abort history); PE-1's determinism over that shared list gives `expected_idx == p` (the producer's elected index).

Now:

- (i) holds because `p = v mod |B.creators|` is by construction in `[0, |B.creators|)` for `|B.creators| > 0`; a BFT block with empty `creators` fails the committee-size check upstream (`check_creator_selection`, which already enforces `|creators| = |K_h| = ⌈2K/3⌉ > 0` for BFT mode).
- (ii) holds because the honest producer set `B.bft_proposer = creators[p]` (`current_proposer_domain`, `node.cpp:947`) with the same `p`; any block where `B.bft_proposer ≠ B.creators[expected_idx]` (an adversary substituting a different proposer) is rejected by the equality check. The adversary cannot satisfy the check with a chosen proposer because `expected_idx` is fixed by inputs the adversary cannot forge under H-det (changing `b.abort_events` to move `expected_idx` onto the chosen member requires a SHA-256 preimage win, PE-3; and any change to `b.abort_events` also changes `compute_block_digest` and thus the signatures, which then fail V8).
- (iii) holds because the producer's finalize path refuses to emit a BFT block whose proposer slot is sentinel-zero (`node.cpp:1060-1065`: it locates `proposer` in `creators` and returns without finalizing if `ordered_block_sigs[pidx] == zero_sig`), and the validator re-checks the same condition. An adversary cannot present a block where the elected proposer's slot is zero — V8 would also need ≥ Q non-zero sigs, but specifically *this* index must be non-zero, closing the "finalize without the leader's own sig" gap.

Finally, the MD-mode guard (`validator.cpp:406-407`) rejects any MUTUAL_DISTRUST block with non-empty `bft_proposer`, so the proposer field is confined to BFT blocks and cannot be smuggled into MD-mode consensus where FA1's unconditional safety governs. ∎

**Corollary PE-4.1 (no honest fork in BFT mode).** Combining PE-1 (honest nodes agree on `proposer`), PE-4 (validators reject any block naming a different proposer), and the proposer-only finalize gate (`node.cpp:1039`): at any BFT height, every block an honest validator accepts names the same proposer `creators[p]`, and only that proposer finalizes. Two distinct accepted blocks at one height therefore share a proposer who signed two distinct digests — i.e. provable equivocation, slashed by FA6. There is no fork between honest nodes, and the dishonest-proposer fork is detected and economically punished. This is exactly the proposer-uniqueness half of FA5's "exactly one canonical BFT block per height." ∎

---

## 4. Adversary scenarios

| Adversary | Goal | Defeated by |
|---|---|---|
| `A_fork` (honest-looking double-finalize) | Two honest nodes each finalize a distinct valid `Q`-subset block at one height | PE-1 + proposer-only finalize (`node.cpp:1039`): only `creators[p]` finalizes, and all honest nodes agree on `p`. |
| `A_misname` (wrong proposer) | Finalize a block naming a non-elected committee member as `bft_proposer` (e.g. itself) | PE-4 (ii): validator's equality check `b.bft_proposer == b.creators[expected_idx]` rejects it. |
| `A_grind` (steer the role) | Land the proposer index on an adversary-controlled member across many heights | PE-3: pre-`epoch_rand` strategies get no advantage over `m/\|K_h\|` (A3 + H-rand); within-epoch only abort-induced uniform redraws, at FA6/abort-slash cost. |
| `A_unsigned` (leaderless finalize) | Finalize a BFT block where the elected proposer's own slot is sentinel-zero | PE-4 (iii): producer refuses (`node.cpp:1060-1065`) and validator re-checks `creator_block_sigs[expected_idx] ≠ 0`. |
| `A_smuggle` (proposer in MD) | Set `bft_proposer` on a MUTUAL_DISTRUST block to perturb digest/acceptance | PE-4: `validator.cpp:406-407` rejects any MD block with non-empty `bft_proposer`. |
| `A_oob` (out-of-range index) | Force `expected_idx ≥ \|creators\|` via crafted abort list / committee | PE-2 construction (`p = v mod \|K_h\|` is in-range by definition) + PE-4 (i) explicit `expected_idx >= b.creators.size()` reject + upstream committee-size check. |
| `A_seedcross` (cross-oracle grind) | Reuse a preimage spent biasing the S-020 committee-set draw to also bias the proposer draw | Double domain separation: `"shard-committee"` (seed) vs `"bft-proposer"` (mix) tags make the two oracles independent (PE-3, step 1). |

---

## 5. Concrete-security summary

- **Determinism (PE-1):** exact — zero failure probability; the election is a pure function of agreed inputs.
- **Bias (PE-2):** `Δ < 2⁻⁵⁸ < 2⁻⁵⁶` over uniform for all `|K_h| ≤ 256`; negligible.
- **Grinding (PE-3):** pre-seed advantage `0` over the `m/|K_h|` baseline; within-epoch steering bounded by a geometric (`E ≈ |K_h|` aborts to hit a target) random walk at slashing cost — economically infeasible.
- **Mirror (PE-4):** exact — any mis-named / out-of-range / unsigned-proposer / MD-smuggled block is rejected with probability `1` (the checks are equality/range tests over byte-identical recomputation), modulo the `≤ 2⁻¹²⁸` SHA-256 collision term inherited from `compute_block_digest` binding (A2).

Net: the within-BFT-committee proposer election contributes **no new non-negligible failure term** beyond the cryptographic floors FA5/FA6 already carry. It converts FA5's "≥ Q signed" into "exactly one canonical block" with exact (probability-1) determinism among honest nodes and exact validator rejection of every adversarial deviation enumerated in §4.

---

## 6. Implementation cross-reference

| Property / element | Source |
|---|---|
| Election function `proposer_idx` | `src/node/producer.cpp:520-533` (declared `include/determ/node/producer.hpp`) |
| Domain-separated, shard-salted seed | `src/crypto/random.cpp:169-175` (`epoch_committee_seed`, `"shard-committee"` tag + `shard_id`) |
| Second domain tag `"bft-proposer"` | `src/node/producer.cpp:527` (inside `proposer_idx`) |
| Producer-side election | `src/node/node.cpp:936-948` (`Node::current_proposer_domain`) |
| Epoch-rand resolution (producer) | `src/node/node.cpp:914-933` (`Node::current_epoch_rand`) |
| Proposer-only finalize gate | `src/node/node.cpp:1039` (`if (mode == BFT && cfg_.domain != proposer) return;`) |
| Proposer-must-sign gate (producer) | `src/node/node.cpp:1060-1065` (proposer slot non-zero before finalize) |
| Validator re-derivation + 3 checks | `src/node/validator.cpp:408-426` (range / equality / non-zero-sig) |
| Epoch-rand resolution (validator) | `src/node/validator.cpp:414` (`resolve_epoch_rand`) |
| MD-mode `bft_proposer` prohibition | `src/node/validator.cpp:406-407` |
| Equivocation detection on dishonest proposer | `src/node/node.cpp:1718-1748` (`bft_proposer`-keyed `EquivocationEvent` assembly) → FA6 |
| Wire spec | `docs/PROTOCOL.md` §5.3.1 (`bft_proposer` field + election algorithm) |

A reviewer can confirm:

- The producer seed (`node.cpp:942-944`) and validator seed (`validator.cpp:414-416`) are computed by the same two functions with the same arguments — the mirror is structural, not coincidental.
- The `"bft-proposer"` tag is distinct from the `"shard-committee"` tag, so the committee-set and proposer draws are independent oracles over the same `epoch_rand`.
- The three validator checks (range, equality, non-zero proposer sig) collectively reject every adversarial mis-naming enumerated in §4.
- The proposer-only finalize gate plus PE-1's honest agreement means no two honest nodes can finalize distinct blocks at one BFT height — the FA5 proposer-uniqueness obligation.

---

## 7. Relationship to the consensus proof family

This proof sits between S-025 (escalation trigger) and FA5 (BFT-mode safety) in the BFT-mode proof lattice:

```
S-025 (4-gate predicate)  ──→  height h is in BFT mode
        │
        ▼
S-020 (committee-set draw) ──→  K_h ⊂ V, ordered as `creators`
        │
        ▼
THIS PROOF (proposer election within K_h) ──→  one canonical proposer per height (PE-1, PE-4)
        │
        ▼
FA5 (quorum intersection) + FA6 (slashing) ──→  exactly one canonical, safe BFT block
```

- **From S-025:** the standing precondition (BFT mode in scope). This proof is vacuous in MD mode (where `bft_proposer` is forbidden, PE-4 final clause).
- **From S-020:** the committee set `K_h` and its ordering, plus the shared `epoch_committee_seed` infrastructure and its domain-separation discipline (extended here with the second `"bft-proposer"` tag).
- **To FA5:** the proposer-uniqueness half of "exactly one canonical BFT block per height" (Corollary PE-4.1). FA5 supplies the signature-intersection half; together they give BFT-mode safety under `f_h < |K_h|/3`.
- **To FA6:** the residual dishonest-proposer fork (a proposer signing two digests) is precisely the equivocation FA6 detects and slashes; this proof shows that is the *only* residual fork once honest nodes agree.
- **To FA4 (Liveness):** the abort-driven proposer rotation (PE-3, step 2) is the within-epoch progress lever — a stalled proposer is rotated off on the next attempt via a fresh near-uniform redraw, which FA4's geometric-bound liveness argument consumes.
