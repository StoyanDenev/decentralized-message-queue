# S-029 — Fork-choice rule soundness: deterministic tiebreak + confluence + safety composition

This document proves the closure of `docs/SECURITY.md` §S-029 (BFT-mode multi-proposer fork-choice undefined — Medium → Mitigated) shipped as `Chain::resolve_fork` at `src/chain/chain.cpp:1516–1537`. The pre-fix gap had the chain's K-of-K consensus layer well-protected against equivocation but silent on what an honest node should do when *two* signed-and-validated blocks at the same height arrive concurrently — a scenario that the BFT-mode shrinkage `|K_h| = ⌈2K/3⌉` + within-committee quorum `Q = ⌈2·|K_h|/3⌉` makes structurally possible (the quorum admits multiple signature subsets of size ≥ Q against the same proposer's block-digest, and a Byzantine producer signing two divergent blocks combined with gossip lag can give two honest peers two distinct sig-valid views at the same height). The fix is a three-criterion lexicographic comparator on `(sig_count, abort_event_count, block_hash)` that maps every (`Block`, `Block`) pair to a canonical winner. The proof here pins the algebraic properties — determinism, confluence (order-independence under pairwise reduction), termination, and composition with K-of-K + BFT — that make the comparator a sound fork-choice rule.

The proof is short and largely structural because the comparator is a total order on a three-element tuple with concrete-cryptography ties as the leaf-level disambiguator. The non-obvious work is the confluence theorem (T-2) — proving that pairwise reduction of `N` competing chains converges on the same winner regardless of pairwise-reduction order. This is what makes the rule a *fork-choice rule* (a global property) rather than just a *tiebreak rule* (a local property).

**Companion documents:** `Preliminaries.md` (F0) for the H1..H4 honest-validator assumptions and V8 K-of-K validity predicate; `Safety.md` (FA1) for the MD-mode safety theorem that the fork-choice rule complements (FA1 proves ≤1 finalized digest per height in MD mode, so the fork-choice rule fires only on the BFT-mode tail of blocks where FA5's conditional safety can admit multi-block disagreement); `BFTSafety.md` (FA5) for the BFT-mode safety + slashing-recovery proof that the fork-choice rule depends on; `EquivocationSlashing.md` (FA6) for the slashing pipeline that punishes the Byzantine producer creating the fork in the first place; `Censorship.md` (FA2) §3 for the role fork-choice plays in censorship-resistance (an honest minority's tx survives provided the fork-choice rule picks the censorship-resistant chain); `BlockchainStateIntegrity.md` for the sister state-integrity surface (S-021 chain.json head_hash recompute); `docs/SECURITY.md` §S-029 for the closure narrative.

---

## 1. Theorem statements

**Setup.** A `Block` `B` carries `B.creator_block_sigs : std::vector<Signature>` of size `|K_h|` (the active committee size for the consensus mode — `K` for MD-mode, `⌈2K/3⌉` for BFT-mode). For MD-mode blocks all `|K_h|` entries are non-zero per V8 (Preliminaries §5). For BFT-mode blocks, at least `Q = ⌈2·|K_h|/3⌉` entries are non-zero and the remaining `|K_h| − Q` may be sentinel-zero. Each non-zero entry is a valid Ed25519 signature by the corresponding committee member over `compute_block_digest(B)`. The block also carries `B.abort_events : std::vector<AbortEvent>` of round-level abort certificates for that height, and `B.compute_hash() : Hash` yielding a 32-byte digest binding `signing_bytes(B)` ∪ committee sigs ∪ (S-033) state_root etc.

Define:

- `sig_count(B) := |{ σ ∈ B.creator_block_sigs : σ ≠ 0 }|` — the cardinality of the *active* signature set, ignoring sentinel-zero slots.
- `abort_count(B) := |B.abort_events|`.
- `block_hash(B) := B.compute_hash()` — interpreted as a 256-bit unsigned integer for the lexicographic byte-wise compare.

Let `resolve_fork(A, B)` denote `Chain::resolve_fork(A, B)` — a binary function returning `const Block&` (a reference to either `A` or `B`).

**Theorem T-1 (Deterministic Tiebreak).** For every pair of valid blocks `A, B` at the same height `h` against the same chain prefix, `resolve_fork(A, B)` returns the *same* block regardless of which node evaluates it, provided both nodes have observed both `A` and `B`. Formally: for any two honest node instances `n_1, n_2` with `A, B ∈ observed_blocks(n_1) ∩ observed_blocks(n_2)`, `resolve_fork^{n_1}(A, B) ≡ resolve_fork^{n_2}(A, B)` where ≡ denotes "is a reference to the same `Block` value (byte-equal)". The proof proceeds by exhaustive case analysis on the three-criterion comparator (heaviest-sigs > / = ; fewer-aborts > / = ; smallest-hash) and reduces the leaf cases to A1 Ed25519 EUF-CMA + A2 SHA-256 collision resistance.

**Theorem T-2 (Pairwise-Reduction Confluence).** For every set of `N ≥ 2` competing blocks `{B_1, ..., B_N}` at the same height `h` against the same chain prefix, and every pair of reduction orderings `π_1, π_2` over `{1, ..., N}`, the iterated pairwise reduction:

```
fold(resolve_fork, B_{π_1(1)}, B_{π_1(2)}, ..., B_{π_1(N)}) ≡ fold(resolve_fork, B_{π_2(1)}, B_{π_2(2)}, ..., B_{π_2(N)})
```

produces byte-identical final winners. Equivalently: the fork-choice rule, as a *binary operation* on `Block` references, satisfies (effective) commutativity and associativity over the equivalence class induced by T-1's "byte-equal winner" relation. The reduction order is irrelevant; every node converges on the same canonical tip regardless of the order in which it merges fork branches into its view.

**Theorem T-3 (Safety Composition with K-of-K).** Under H1 (each honest validator follows the protocol), H2 (each honest committee member signs at most one block-digest per height), H3 (gossip is best-effort but eventually delivering), and H4 (the adversary cannot forge Ed25519 signatures of honest keys — concrete bound `≤ 2⁻¹²⁸` per attempt under A1), the composition of (a) K-of-K committee signatures binding each block to a verified `compute_block_digest(B)` via V8, (b) T-1's deterministic tiebreak, and (c) T-2's confluence ensures that any two honest nodes converge on the same canonical chain. The proof composes FA1 (MD-mode: ≤1 finalized digest per height ⇒ resolve_fork never fires) and FA5 (BFT-mode under `f_h < |K_h|/3`: at most one digest ⇒ resolve_fork never fires; under `f_h ≥ |K_h|/3` ⇒ FA6 slashing-recovery + T-2 confluence on the surviving honest committee for height `h+1`).

**Theorem T-4 (Termination / No Liveness Stall).** `resolve_fork(A, B)` is `O(|K_h|) + O(|B.abort_events| + |A.abort_events|)` per pairwise comparison (sig-count + abort-count linear scans), with a final `O(1)` 32-byte hash compare. The function contains no loops over the chain history, no recursive calls, and no waits — it is constant-time per `(A, B)` pair in `|K_h|` (committee size, genesis-pinned constant) and the bounded `abort_events` list (capped per the protocol's per-block abort-event ceiling). The pairwise reduction of `N` competing blocks runs in `O(N · |K_h|)`. Therefore the rule cannot stall consensus, deadlock on a misordered input, or amplify into a quadratic cost on a flood of synthetic competing chains.

**Theorem T-5 (Compositional with BFT escalation).** When consensus escalates to BFT mode per the 4-gate trigger in PROTOCOL.md §5.3 / WHITEPAPER §3.3 (`bft_enabled` AND `total_aborts ≥ threshold` AND `pool < K` AND `pool ≥ ⌈2K/3⌉`), the BFT-finalized block satisfying `sig_count(B) ≥ Q = ⌈2·|K_h|/3⌉` (against the within-committee 2/3 quorum) is the *unique* canonical tip selected by `resolve_fork`. Any non-BFT-quorum competitor at the same height has strictly fewer signatures (`< Q`) and loses on the first criterion of T-1's comparator. The composition is structural: K-of-K (MD mode) + BFT quorum (BFT mode) + fork-choice produces a single converged chain that every honest node accepts as canonical.

---

## 2. Background

### 2.1 Pre-S-029 gap

Before S-029, the chain's consensus layer had:

- **V8 K-of-K validity predicate** (Preliminaries §5, `validator.cpp::check_block_sigs`). A block carries `|K_h|` signatures of which at least `Q` (1 in MD mode, `⌈2·|K_h|/3⌉` in BFT mode) must be valid Ed25519 over `compute_block_digest(B)` by the corresponding committee member's registered public key.
- **FA6 equivocation slashing** (`EquivocationSlashing.md`). A Byzantine committee member who signs two distinct block-digests at the same height is detected (the two signatures + two digests are evidence), gossip-baked into the next block's `equivocation_events[]`, and slashed at apply-time (full stake forfeiture + registry deactivation per FA-Apply-10).
- **MD-mode safety** (`Safety.md` FA1 T-1). Under H1..H4 with ≥1 honest in committee, at most one digest is finalizable per height — `resolve_fork` is never called in MD mode because the pigeonhole on K-of-K signatures rules out two same-height blocks both reaching `apply_block`.

What was *not* covered: the BFT-mode tail of blocks. Under BFT mode, V8 admits any signature subset of size `≥ Q`, so a Byzantine producer signing two distinct blocks `B, B'` with two distinct sig subsets `S(B), S(B') ⊆ K_h` (each of size `≥ Q`) can — combined with gossip lag — present an honest node `n_1` with `B` and an honest node `n_2` with `B'`. Both blocks pass V8 against their respective sig subsets. Both blocks have valid `creator_block_sigs[]`. Both blocks are valid against the same chain prefix at height `h`. Without a fork-choice rule, `n_1` and `n_2` diverge silently on their canonical tip.

FA5 (BFT-mode safety, conditional under `f_h < |K_h|/3`) proves that this two-digest scenario *implies* equivocation in the intersection `S(B) ∩ S(B') ≥ 2Q − |K_h|`, and FA6 + FA-Apply-10 close the slashing loop. But: while the *evidence* is gossiped + baked into the next block, the *current* height's tip is still ambiguous between `B` and `B'` until the next block lands. An honest node receiving both `B` and `B'` needs a rule for which to write to its chain.json file (S-021), which to feed into `compute_state_root` (S-033/S-038), and which to gossip as its "head".

S-029 closes this by adding `Chain::resolve_fork` — a pure function that takes two competing blocks and deterministically picks one. The rule is invoked at the receive path (`node.cpp::on_block`) when the incoming block matches an existing block's height; the rule's output is the new tip. Because the rule is *deterministic on the (Block, Block) input pair* (T-1) and *independent of arrival order* (T-2), every honest node observing both `B` and `B'` writes the same tip to its chain — even before the FA6 slashing pipeline lands the evidence in the next block.

### 2.2 The three-criterion comparator

The actual implementation at `src/chain/chain.cpp:1516–1537`:

```cpp
const Block& Chain::resolve_fork(const Block& a, const Block& b) {
    auto sig_count = [](const Block& blk) {
        Signature zero{};
        size_t n = 0;
        for (auto& s : blk.creator_block_sigs)
            if (s != zero) ++n;
        return n;
    };

    size_t na = sig_count(a), nb = sig_count(b);
    if (na != nb) return na > nb ? a : b;       // heaviest sig set wins

    if (a.abort_events.size() != b.abort_events.size())
        return a.abort_events.size() < b.abort_events.size() ? a : b;

    // Tie-break on smallest block hash (deterministic, agrees across peers).
    Hash ha = a.compute_hash();
    Hash hb = b.compute_hash();
    for (size_t i = 0; i < 32; ++i)
        if (ha[i] != hb[i]) return ha[i] < hb[i] ? a : b;
    return a; // identical
}
```

The comparator has three priority levels, each a strict tiebreaker for the level above:

- **Level 1 (heaviest sig set)**: more committee members ratified ⇒ block is more legitimate. The `sig_count` lambda explicitly skips sentinel-zero signatures (Signature{} default-constructed), so a BFT-mode block with `Q` real sigs + `|K_h| − Q` sentinel-zero slots has `sig_count = Q`, not `|K_h|`. This matters because the comparator must reflect the *real* committee buy-in, not the slot count.
- **Level 2 (fewest abort events)**: at equal signature weight, the chain with less round-1 disruption is preferred — an honest chain proceeded through Phase-1 + Phase-2 cleanly, while a chain with multiple aborts represents a noisier consensus path. This level is not safety-critical (both chains are V8-valid; the abort-event difference is a quality signal), but it acts as a Schelling point: the chain that escalated less is the more honest-aligned one.
- **Level 3 (smallest block hash)**: at equal signature weight + equal abort count, the lexicographically smallest 32-byte hash wins. This is the irreducible tiebreaker — a pure function of the block's content (signing_bytes + sigs + delay_output + state_root etc., all binding the block's identity) — that produces the same answer on every node observing both blocks.

The final `return a` after the for-loop is the byte-identical-blocks case: `a.compute_hash() == b.compute_hash()` implies (modulo SHA-256 collision, ≤ 2⁻¹²⁸) that `signing_bytes(a) = signing_bytes(b)` and the full signature sets coincide, so `a` and `b` are identical blocks and the comparator returns the first argument by convention.

### 2.3 Why three criteria and not one

A single-criterion comparator (e.g., "smallest hash always wins") would be deterministic but would *not* prefer the honest-majority chain in the typical attack scenario. An attacker mining a competing block with one signature and a small hash would beat the honest chain with `K` signatures and a larger hash. The three-level comparator routes the decision through (1) signature weight first (the security-meaningful criterion), then (2) abort count (the quality signal), and finally (3) hash (the irreducible determinism source).

The price: an adversary controlling exactly `K_adv` committee keys (where `K_adv ≥ Q`) can produce a competing chain whose sig_count ties the honest chain's sig_count, forcing the comparator to fall through to abort count + hash. But the attacker has not gained safety here — they have signed `K_adv ≥ Q` digests under their own committee keys, producing exactly the evidence FA6 + FA-Apply-10 will slash them on. The fork-choice rule does not need to defeat this attacker (they slash themselves); it only needs to produce the same answer on every honest node, which it does (T-1).

---

## 3. Implementation citation

### 3.1 The comparator — `src/chain/chain.cpp:1516–1537`

Reproduced in §2.2. The function is `const Block&`-returning, takes two `const Block&` args, lives on the `Chain` class as a `static` member (declared at `include/determ/chain/chain.hpp:456`). The `static` declaration matters: the function does not read any `Chain` instance state, so two different `Chain` instances on two different nodes will yield identical outputs given identical `(a, b)` inputs — a structural prerequisite for T-1.

### 3.2 The `sig_count` lambda

```cpp
auto sig_count = [](const Block& blk) {
    Signature zero{};
    size_t n = 0;
    for (auto& s : blk.creator_block_sigs)
        if (s != zero) ++n;
    return n;
};
```

The `Signature zero{}` default-constructs a 64-byte zero buffer (the `Signature` type is `std::array<uint8_t, 64>` per `types.hpp`). The `s != zero` check is a byte-wise inequality over 64 bytes. A *valid* Ed25519 signature has overwhelming probability of being non-zero (the signature's `s` and `R` components are pseudo-random 32-byte chunks; the probability of either coinciding with the zero buffer is `≤ 2⁻²⁵⁶`). In practice every real Ed25519 signature is non-zero, so `sig_count` returns the count of slots that were actually signed.

For BFT-mode blocks, the slots that *weren't* signed are explicitly set to `Signature{}` (zero) by the producer when assembling `creator_block_sigs[]` — this is the documented "sentinel-zero" convention from `BFTSafety.md` §1. The producer at `producer.cpp::finalize_block_in_bft_mode` writes zero to slots that no committee member signed (because the producer received < `|K_h|` sigs); the validator's V8 (BFT-mode form) then accepts blocks with `Q ≤ sig_count(B) ≤ |K_h|`. So `sig_count` measures the real committee buy-in.

### 3.3 The block hash compare

```cpp
Hash ha = a.compute_hash();
Hash hb = b.compute_hash();
for (size_t i = 0; i < 32; ++i)
    if (ha[i] != hb[i]) return ha[i] < hb[i] ? a : b;
return a; // identical
```

`Hash` is `std::array<uint8_t, 32>` (per `types.hpp`). The compare is byte-wise from index 0 (most-significant for big-endian interpretation), short-circuiting on the first differing byte. This produces a strict total order on 32-byte hashes: ha < hb iff at the first differing index, ha[i] < hb[i].

`Block::compute_hash` is a SHA-256 of `signing_bytes(B)` ∪ all committee sigs ∪ (S-033) state_root ∪ delay_output (per the WireFormatBackwardCompat.md backward-compat extension). Two blocks that differ in any of these fields have, with overwhelming probability (≥ 1 − 2⁻¹²⁸), distinct compute_hash values per A2 SHA-256 collision resistance. Two byte-identical blocks have identical compute_hash by SHA-256's deterministic function property.

### 3.4 Test harness — `src/main.cpp:11909–12062`

The `test-resolve-fork` in-process unit test (added under S-035 Option 1, the test-coverage hardening track) drives `Chain::resolve_fork` through seven scenarios covering each comparator level + edge cases. The full source is at `src/main.cpp:11909–12062`; the scenarios are:

1. **Heaviest sigs wins (3 > 2)** — two assertions (forward + reverse arg order).
2. **Same sigs → fewer aborts wins** — two assertions (forward + reverse).
3. **Same sigs + same aborts → smallest hash wins** — two assertions (forward winner + symmetric across arg order).
4. **Identical blocks → returns first arg** — one assertion documenting the byte-identical convention.
5. **Zero sigs on both** — one assertion ensuring the function doesn't crash on the pathological all-zero-sigs case.
6. **Sentinel-zero handling** — one assertion proving that the `sig_count` lambda's zero-skip is the load-bearing detail (a block with 2 real sigs + 1 sentinel beats a block with 1 real sig + 2 sentinels, even though both have `|K_h| = 3` slots).
7. **Abort tie-break beats hash tie-break** — one assertion confirming the priority order: a block with fewer aborts wins over a block with smaller hash but more aborts.

The harness uses a deterministic `patterned_hash` helper to construct blocks with predictable `prev_hash` / `tx_root` / `delay_seed` values, and a `make_block(index, n_sigs, n_aborts, variant)` helper that produces blocks with the requested signature count + abort count + a `variant` byte mixed into the tx_root to force hash divergence. Each block has `consensus_mode = ConsensusMode::BFT` (the comment at line 11952 notes "resolve_fork is BFT-only" — this is the structural observation that MD-mode blocks never reach `resolve_fork` because FA1 already rules out same-height divergence under MD-mode).

The harness's exit code is 0 iff all 10 assertions pass. The wrapper script `tools/test_resolve_fork.sh` invokes the binary, captures stdout, and grep's for `PASS: resolve-fork all assertions` to set the script's exit code.

### 3.5 Invocation sites

The comparator is invoked at the chain's receive-side block-admission paths. Per the architectural narrative in `docs/SECURITY.md` §S-029, the call sites are (a) the `Chain::apply_block` extension that detects a same-height tip already exists and replaces it with the comparator's output, and (b) the `Node::on_block` gossip receive path that pre-checks against the current tip before invoking `apply_block`. The exact call-site filenames are out of scope for this proof (the comparator's properties are pure-function properties, independent of how often or where it's called); see `BlockchainStateIntegrity.md` for the composition with S-021 chain.json load-time recompute that ensures restart-safety.

---

## 4. Proofs

### 4.1 Proof of T-1 (Deterministic Tiebreak)

**Claim.** For every pair `(A, B)` of valid blocks at the same height, every honest node `n` computing `resolve_fork(A, B)` returns the same `Block` value (byte-equal).

**Proof.** The comparator is a pure function: its output depends only on its arguments `(A, B)`, not on any per-node state. We verify this by inspection:

- `sig_count(blk)` reads `blk.creator_block_sigs` (a field of the `Block` argument) and compares each entry against a default-constructed `Signature` (a compile-time zero buffer). No per-node randomness, no clock reads, no chain-state lookups.
- `a.abort_events.size()` and `b.abort_events.size()` are `Block`-field reads.
- `a.compute_hash()` and `b.compute_hash()` are deterministic functions of the block's content; per SHA-256's deterministic property (A2 / FIPS 180-4), `compute_hash(B) == compute_hash(B')` iff the SHA-256 input — `signing_bytes(B)` ∪ committee sigs ∪ state_root ∪ delay_output etc. — is byte-identical. So the hash is a pure function of the `Block` value.

All three criteria are pure-function reads of the `Block` arguments. The comparator's control flow is a deterministic dispatch on these reads:

- if `sig_count(a) ≠ sig_count(b)`: return whichever has more sigs.
- else if `a.abort_events.size() ≠ b.abort_events.size()`: return whichever has fewer aborts.
- else if `compute_hash(a) ≠ compute_hash(b)`: return whichever has the smaller hash.
- else: return `a`.

Each branch is a total order on the criterion (size_t < / > or byte-wise hash compare), so the dispatch resolves to a single branch per `(A, B)` pair. Two different node instances `n_1, n_2` evaluating `resolve_fork(A, B)` against byte-identical `A, B` values execute the same branch and return references to the same block.

The byte-identical case (`compute_hash(a) == compute_hash(b)`) returns `a` by convention. Per A2 SHA-256 collision resistance, the case requires `signing_bytes(A) = signing_bytes(B)` ∪ identical sigs, which means `A` and `B` are byte-equal blocks. Returning `a` vs returning `b` makes no observable difference (the returned reference points to a block byte-equal to the other argument).

Hence `resolve_fork^{n_1}(A, B) ≡ resolve_fork^{n_2}(A, B)` over the byte-equal equivalence class. ∎

**Corollary T-1.1 (Anti-symmetry).** `resolve_fork(A, B) ≡ resolve_fork(B, A)` byte-equal for all non-identical pairs `(A, B)`. The comparator's three branches are anti-symmetric: `(na > nb)` swaps to `(nb > na)` under argument reversal but the *winner* (the block with the larger sig_count) is the same `Block` value either way. Same for the aborts and hash branches. Only the identical-block case `A == B` shows asymmetry (`resolve_fork(A, B) == A` but `resolve_fork(B, A) == B`), and in that case `A == B` so the returned values are still byte-equal.

### 4.2 Proof of T-2 (Pairwise-Reduction Confluence)

**Claim.** Given a set `S = {B_1, ..., B_N}` of competing blocks at the same height, and two reduction orderings `π_1, π_2`, the iterated pairwise reduction yields byte-identical winners.

**Proof sketch (semilattice argument).** Define a total order `≼` on blocks at the same height by inverting `resolve_fork`'s losing relation:

- `A ≼ B` iff `resolve_fork(A, B) ≡ B` (B wins over A under the comparator).

`≼` is:

- **Reflexive**: `A ≼ A` because `resolve_fork(A, A) == A` (the identical-block case).
- **Antisymmetric**: `A ≼ B` and `B ≼ A` ⇒ both `resolve_fork(A, B) ≡ B` and `resolve_fork(B, A) ≡ A`. By T-1.1, both should be byte-equal — so `A` and `B` are byte-equal blocks.
- **Transitive**: if `A ≼ B` and `B ≼ C`, then by the comparator's lexicographic total order on `(sig_count, abort_count, hash)`, the triple of `A` is ≤ the triple of `B` is ≤ the triple of `C`, so the triple of `A` is ≤ the triple of `C`, hence `A ≼ C`.
- **Total**: for any `A, B`, either `A ≼ B` or `B ≼ A` (the comparator returns one of the two; the leaf case `compute_hash(A) == compute_hash(B)` reduces to byte-equal blocks so both relations hold).

So `(Block_height_h, ≼)` is a totally ordered set. The maximum of a totally ordered finite set is unique. Iterated pairwise `resolve_fork` over the set `S` computes the maximum under `≼` — that is, the block `B*` such that `B* ≽ B_i` for all `i`. The maximum is independent of the order in which the pairwise reductions are applied:

```
fold(resolve_fork, B_{π_1(1)}, ..., B_{π_1(N)})
  = max_{≼}(B_{π_1(1)}, B_{π_1(2)}, ..., B_{π_1(N)})
  = max_{≼}(S)
  = max_{≼}(B_{π_2(1)}, B_{π_2(2)}, ..., B_{π_2(N)})
  = fold(resolve_fork, B_{π_2(1)}, ..., B_{π_2(N)})
```

The equality `max_{≼}(B_{π(1)}, ..., B_{π(N)}) = max_{≼}(S)` holds for any permutation `π` because `max` of a totally ordered set is permutation-invariant (a standard lattice-theory result; the maximum is uniquely defined by `(∀ i) B* ≽ B_i`, which doesn't reference any ordering of the indices).

Hence the iterated fold over `S` yields byte-identical winners regardless of reduction order. ∎

**Practical implication.** A node that receives competing blocks `B_1, B_2, B_3` in the order `(B_1, B_2, B_3)` and reduces as `resolve_fork(resolve_fork(B_1, B_2), B_3)` produces the same canonical tip as a node that received them in the order `(B_3, B_1, B_2)` and reduced as `resolve_fork(resolve_fork(B_3, B_1), B_2)`. Network arrival order is irrelevant to the chain-tip choice — only the set of observed blocks matters.

**Corollary T-2.1 (Closure under restart).** A node that has applied a sequence of `resolve_fork` operations and persisted the resulting tip to chain.json (via the S-021 wrap), then restarted and re-observed the same competing blocks via gossip, computes the same tip. This is just T-2 applied to the post-restart observation set, which equals (or is a superset of) the pre-restart observation set — the maximum under `≼` of either set is `max_{≼}({all observed blocks})`.

### 4.3 Proof of T-3 (Safety Composition with K-of-K)

**Claim.** Under H1..H4 + A1 + A2, any two honest nodes `n_1, n_2` observing both `B` and `B'` at the same height converge on the same canonical tip.

**Proof.** Case-split on consensus mode:

**Case 1: MD-mode block at height h.** By FA1 T-1, at most one digest is finalizable at height `h` in MD mode under ≥1 honest in committee. If `B` and `B'` are both MD-mode-valid against the same chain prefix at the same height, they must be the same digest (because K-of-K means all K members signed, and H2 forbids any honest committee member from signing two distinct digests). So `B = B'` byte-equal. T-1's identical-blocks case applies; both nodes get `B` as the tip.

**Case 2: BFT-mode block at height h with `f_h < |K_h|/3`.** By FA5 T-5, BFT-mode safety is conditional on the Byzantine fraction bound; under `f_h < |K_h|/3`, at most one BFT-mode block is finalizable at height `h`. The proof goes via L-5.1 (quorum intersection `≥ 2Q − |K_h|`) and L-5.2 (honest member in the intersection forces digest equality). So `B = B'` byte-equal; same as Case 1.

**Case 3: BFT-mode block at height h with `f_h ≥ |K_h|/3`.** The standard BFT safety condition is violated; two distinct blocks `B ≠ B'` can be valid at the same height. This is the scenario `resolve_fork` exists for. By T-1, both nodes compute `resolve_fork(B, B')` to the same `Block` value (whichever wins the three-criterion comparator). By T-2 (if a third honest peer broadcasts a `B''`), the final tip is `max_{≼}(B, B', B'', ...)` independent of reduction order. The chain extends with the comparator's winner at height `h+1`.

Concurrent with the comparator's selection, FA6 + FA-Apply-10 detect the equivocation evidence — both `B` and `B'` were signed by committee members in `S(B) ∩ S(B') ≥ 2Q − |K_h|`, and at least one such member is in `F_h` (by L-5.2's contrapositive). The evidence gossips, gets baked into block `h+1`, and slashes the equivocator at apply-time. The next BFT-mode committee selection (at height `h+1`) reflects the post-slash registrant set per the deactivation flip; the chain continues with a smaller, more-honest committee.

So in all three cases, the two honest nodes converge on the same canonical tip. The K-of-K committee signatures (V8) restrict what can be a candidate tip (only V8-valid blocks), and `resolve_fork` is the deterministic choice among candidates. ∎

### 4.4 Proof of T-4 (Termination / No Liveness Stall)

**Claim.** `resolve_fork(A, B)` runs in `O(|K_h|) + O(|A.abort_events| + |B.abort_events|)` per pairwise comparison.

**Proof.** Inspecting the implementation at §3.1:

- `sig_count(blk)` is a single `for` loop over `blk.creator_block_sigs`, comparing each entry byte-wise against a 64-byte zero buffer. The loop runs in `O(|K_h|)` per block, so `O(|K_h|)` total across the two calls.
- The first dispatch (`na != nb`) is `O(1)` after the `sig_count` calls.
- `a.abort_events.size()` and `b.abort_events.size()` are `O(1)` (std::vector::size is constant-time).
- The second dispatch is `O(1)`.
- `a.compute_hash()` and `b.compute_hash()` are `O(|signing_bytes(blk)|)` — proportional to the block's serialized size, which is bounded by the protocol's per-block size cap (`max_message_bytes(BLOCK) = 4 MB` per S-022). So `O(4 MB)` per hash, `O(8 MB)` total.
- The final byte-wise hash compare is `O(32)`.

The asymptotic dominant term is the hash computation (`O(block_size)`), which is bounded by S-022's per-message cap. The wall-clock cost is microseconds per pair (SHA-256 over a few-megabyte block).

The pairwise reduction of `N` competing blocks is `O(N · block_size)` — strictly linear in `N`. No iteration loops, no recursion, no waits.

The function cannot stall consensus because (a) it has no waits or blocking I/O, (b) its dispatch reaches a return in every case (every branch is `return` or `if-else-return`; the final `return a;` covers the identical-block case), and (c) `compute_hash` is a synchronous deterministic function with no failure mode (SHA-256 of bounded input completes in bounded time). ∎

**Corollary T-4.1 (No quadratic amplification).** A flood of `N` synthetic competing blocks at the same height costs `O(N · block_size)` to reduce — strictly linear in `N`. An attacker mining `N` competing blocks pays `O(N)` to mine (signature + hash work per block) and inflicts `O(N)` cost on every honest node — the cost ratio is `1:1`, no amplification. The flood does not stall the chain because `resolve_fork`'s output is deterministic and each pairwise reduction is fast.

### 4.5 Proof of T-5 (Compositional with BFT escalation)

**Claim.** When BFT mode engages (per the 4-gate trigger), the BFT-quorum-signed block (`sig_count ≥ Q`) is the unique canonical tip selected by `resolve_fork`.

**Proof.** The 4-gate trigger from PROTOCOL.md §5.3 / WHITEPAPER §3.3 is:

1. `bft_enabled` (genesis-pinned operator flag).
2. `total_aborts ≥ threshold` (recent abort pressure).
3. `pool < K` (active pool can't form a full K-of-K).
4. `pool ≥ ⌈2K/3⌉` (pool can form a BFT committee of size `|K_h|`).

Under all four gates, the producer constructs a block in BFT mode: `|K_h| = ⌈2K/3⌉` committee members, V8 requires `sig_count ≥ Q = ⌈2·|K_h|/3⌉`. Any block with `sig_count < Q` fails V8 and is rejected at validation — it never reaches `resolve_fork` because `resolve_fork`'s arguments are V8-valid blocks (the receive path filters via `validator.cpp::check_block_sigs` before calling apply_block, and apply_block is where the comparator's tip-swap logic lives).

So in BFT mode, every candidate block at height `h` has `sig_count ≥ Q`. A pair of candidates `(B, B')` both satisfy `sig_count(B), sig_count(B') ≥ Q`. The comparator's Level 1 (`sig_count`) either:

- **Resolves the tie**: one block has more sigs than the other (`sig_count(B) > sig_count(B') ≥ Q`). The block with more sigs wins. This is the "more committee buy-in" criterion: even within the BFT-quorum-passing set, the block with more endorsements is preferred.
- **Doesn't resolve the tie** (`sig_count(B) = sig_count(B')`): both blocks have the same number of real sigs. Falls through to Level 2 (abort count) and then Level 3 (hash).

Either way, the comparator produces a single winner per T-1. T-2 extends to `N`-block reductions. T-3 ensures all honest nodes converge.

Note that a candidate block with `sig_count < Q` is rejected by V8 *before* reaching `resolve_fork`, so the comparator never has to "defeat" a non-quorum competitor — V8 does that job upstream. The composition is:

```
V8 (BFT-mode form) — restricts candidates to {sig_count ≥ Q}.
resolve_fork        — picks the canonical winner among V8-valid candidates.
FA6 + FA-Apply-10  — slashes the equivocator(s) responsible for the multi-candidate scenario.
```

Hence the BFT-escalation path composes cleanly: V8 admits, `resolve_fork` selects, FA6 punishes. The single converged chain is the resolve_fork-winner's chain. ∎

**Corollary T-5.1 (Cross-mode composition).** A chain that has alternated between MD-mode and BFT-mode blocks (per the per-block escalation logic) still satisfies T-3 across the mode boundary: MD-mode blocks at height `h` are unique by FA1 (so resolve_fork either returns the unique block or wasn't called), BFT-mode blocks at height `h+1` are unique-or-resolved by T-5, etc. The canonical chain is the concatenation of per-height resolve_fork outputs.

### 4.6 Proof of T-3's contingent corollary (Chain extension after fork)

**Claim.** After `resolve_fork` selects block `B*` at height `h`, all honest nodes extend the chain at `h+1` from `B*.compute_hash()` as the `prev_hash`. The losing branch `B'` is orphaned.

**Proof.** Per chain.json's `head_hash` field (S-021 closure, `BlockchainStateIntegrity.md` T-1), the canonical chain's tip is identified by its `compute_hash()`. After `resolve_fork(B*, B')` returns `B*`, the node writes `B*.compute_hash()` as the new chain head. The next block-producer (at height `h+1`) reads `head_hash` and constructs `B_{h+1}` with `prev_hash = head_hash`. By T-1, all honest nodes have the same `head_hash`, so all producers build `B_{h+1}` on top of `B*`.

The loser `B'` is orphaned: no honest producer builds on `B'.compute_hash()`, so the chain from `B'` does not extend. A peer that has `B'` as its tip (because it observed `B'` first and hasn't received `B*`) will, upon receiving `B*`, invoke `resolve_fork(B', B*)` and (by T-1) get the same winner as everyone else — switching its tip to `B*`. T-2 ensures this convergence is order-independent. ∎

---

## 5. Adversary model

### 5.1 Threat T1: Adversary mines a competing chain with `K` synthetic sigs

**Setup.** Attacker controls `K_adv < K` committee keys at height `h`. They wish to make `resolve_fork` pick their chain by inflating `sig_count`.

**Closure.** `sig_count` counts non-zero entries in `creator_block_sigs[]`. A "signature" in `creator_block_sigs[i]` must, to pass V8, be a valid Ed25519 signature by the `i`-th committee member's *registered* public key. The attacker controls only `K_adv` of the `|K_h|` committee keys; the remaining `|K_h| − K_adv` slots cannot be filled with valid signatures (forging an Ed25519 sig by an honest key costs ≥ 2¹²⁸ work per A1). So the attacker's `sig_count` is at most `K_adv`. An honest chain has `sig_count = |K_h|` (MD mode) or `sig_count ≥ Q` (BFT mode), both ≥ `K_adv` for `K_adv < K`.

If the attacker tries to fill the remaining slots with garbage non-zero bytes (not valid Ed25519 sigs), V8 rejects the block before it reaches `resolve_fork`. So the comparator never sees a chain with inflated-but-invalid sig counts.

The only way for the attacker to tie or beat the honest sig count is to compromise more committee keys — but that requires compromising honest validators' registered keypairs (a violation of H4), and even then, equivocation slashing (FA6) zeroes the compromised validator's stake on detection. The cost-benefit is unfavorable.

### 5.2 Threat T2: Adversary minimizes aborts in their preferred chain

**Setup.** Attacker is a Byzantine committee member who can choose between (a) aborting in Phase-1 of round 1 (forcing a retry) or (b) participating cleanly. They want their preferred chain (with their preferred tx set) to win on the abort tie-break.

**Closure.** This is not really an attack against `resolve_fork` — it's a vote on what chain to build. By choosing not to abort, the attacker is choosing to participate in the protocol's mainline path. The honest committee members do the same. The chain that emerges with fewer abort events is the one all committee members agreed to extend without dispute. This is the desired outcome.

Note that an attacker who *injects* abort events into a competing chain (to make the comparator prefer their chain by having "fewer" aborts) cannot do so unilaterally: abort events are signed by the relevant committee members per V11/V12. The attacker would have to forge signatures (violating A1) or compromise honest members (violating H4) to inject abort events into a chain they don't control.

What an attacker *can* do is selectively abort rounds — see FA3 SelectiveAbort.md for the selective-abort defense. The defense is information-theoretic: even if the attacker aborts at will, the commit-reveal scheme prevents them from gaining information about `delay_output` before they decide whether to abort. So the attacker's ability to minimize aborts in their preferred chain is limited to "don't abort when it helps me" — which doesn't gain them anything beyond what an honest member could achieve.

### 5.3 Threat T3: Adversary grinds for a small block hash

**Setup.** Attacker is a block producer (or coalition of committee members). They want their block's `compute_hash()` to be the smallest among same-height candidates, so the comparator's Level 3 (hash) tiebreak picks their block.

**Closure.** Grinding for a small hash requires varying the block's content (which changes its serialized bytes, which changes the SHA-256 output) until the hash is small. Each grind iteration:

- Costs the producer one SHA-256 computation (cheap).
- Requires the modified block to still pass V8 — i.e., all K signatures still verify against the new `compute_block_digest`. So every grind iteration requires re-signing by every committee member.
- Each committee member's signing is gated by H2 (sign at most one digest per height). So a committee member who signs `M > 1` distinct digests at the same height is provably equivocating per FA6; their evidence gossips and they get slashed.

So the attacker's grind cost per iteration is one Ed25519 sig per committee member per iteration *plus* the slashing risk (which is full stake forfeiture per FA-Apply-10). The economic infeasibility argument from `EconomicSoundness.md` §S-010 applies: even if the attacker controls `K - 1` keys (the maximum they can compromise without violating H4), grinding for a small hash to win Level 3 costs `(K - 1) · min_stake` worth of forfeiture per attempt — and even if they win the hash tie, they only get a one-block advantage (the next height's committee selection re-randomizes per Preliminaries §6).

Furthermore: the hash tiebreak only fires *after* the sig_count and abort_count tiebreaks both resolve to equality. So the attacker can only win on hash if their `sig_count` exactly matches the honest chain's `sig_count` — which they can only achieve by either matching the honest committee's full participation (no advantage) or having the same partial sig count (which means they're a participating committee member, not an outside attacker).

Net: grinding for hash advantage is economically infeasible and gains the attacker at most a one-block tip-divergence, which the next height's committee selection re-randomizes away.

### 5.4 Threat T4: Adversary partitions the network to delay convergence

**Setup.** Attacker has network-level control and wants to keep two honest sub-networks on divergent tips for as long as possible by delaying gossip propagation.

**Closure.** Per H3 (gossip is best-effort but *eventually delivering*), the partition cannot last forever. As soon as the two sub-networks reconnect, each node observes both competing blocks and invokes `resolve_fork`. By T-1, both sides compute the same winner; by T-2, the order of arrival doesn't matter. Convergence is immediate at the reconnect.

During the partition, each sub-network believes it has the canonical tip. But because `resolve_fork` is deterministic on `(A, B)` input pairs, the *post-reconnect* tip is the same on both sides — the partition delays convergence but doesn't cause it to fail.

The post-reconnect tip-swap is observable to chain extensions: a node that was on the losing branch may have produced or relayed blocks at heights `h+1, h+2, ...` building on the losing tip. After the swap, those blocks are orphaned (their `prev_hash` no longer points to the canonical tip). The orphaned blocks' txs return to the mempool per the standard reorganization handling (per `node.cpp`'s receive-side handler — out of scope for this proof).

### 5.5 Threat T5: Adversary causes the comparator to compare on incomparable criteria

**Setup.** Attacker constructs two blocks `A, B` such that the comparator's invariants break — e.g., a block with `creator_block_sigs[]` of a different size than `|K_h|`, or with `abort_events[]` of pathological size, or with `compute_hash()` returning identical hashes for distinct blocks (a SHA-256 collision).

**Closure.** Each pathology is upstream-rejected:

- `creator_block_sigs[]` size ≠ `|K_h|`: V8 rejects the block (the sigs vector size is part of the validity predicate).
- `abort_events[]` pathologically large: per S-022 message-size caps, the block's serialized form is capped at 4 MB; an over-large abort_events list pushes the block over the cap and the wire-level reject fires.
- SHA-256 collision: by A2 collision resistance, no PPT attacker can find a collision with probability > 2⁻¹²⁸. The comparator's final `return a` in the byte-identical case is structurally safe (returning either argument is observationally equivalent to the caller).

Hence the comparator's preconditions are upstream-enforced. The function cannot be tricked into producing inconsistent outputs across nodes by constructing pathological inputs.

---

## 6. Identified gaps and finding-register

### F-1: Hash-grinding cost vs benefit (Level 3 tiebreak)

The smallest-hash tiebreak (Level 3) is a Schelling point: every node computes the same answer because SHA-256 is deterministic, so this is the canonical disambiguator. An attacker mining a competing chain *could* attempt to grind for a small hash to win Level 3.

**Closure status.** Per §5.3, the attack is economically infeasible at any chain with meaningful `min_stake`: grinding requires re-signing by `|K_h|` committee members per iteration, and each member's re-sign is provably-equivocating evidence under FA6. The attacker's expected reward (one-block tip-advantage at height `h`) is negligible compared to the cost (full stake forfeiture across at least `Q` committee keys).

**Residual risk.** On a small-`min_stake` deployment (e.g., a community chain with `min_stake = 0` per DOMAIN_INCLUSION model), the economic disincentive is weaker. The trade is documented in `docs/SECURITY.md` §S-010 (operator stake-pricing formula) — operators choosing low `min_stake` should accept higher fork-grind susceptibility. The fork-choice rule itself does not regress under low `min_stake`; only the *cost of grinding* changes. Determinism (T-1) and confluence (T-2) hold unconditionally.

### F-2: BFT-mode multi-quorum scenario (Level 1 tiebreak ties)

In BFT mode, a Byzantine producer can sign two blocks `B, B'` with sig subsets `S(B), S(B')` of equal size `|S(B)| = |S(B')| = q` for some `q ≥ Q`. The comparator's Level 1 (sig_count) ties; it falls through to Level 2 (aborts).

**Closure status.** This is the expected behavior — Level 1 catches "honest chain has more sigs than attacker's chain," and Level 2/3 catch "equal sigs but quality / hash differs." The two-block scenario is exactly the equivocation case FA5/FA6 detect-and-slash. T-2 ensures convergence on the comparator's output regardless of which block any individual node sees first.

**Note on Q-vs-K boundary at K=3.** At the genesis-default K=3, `|K_h| = 2`, `Q = 2`, so BFT-mode is degenerate: `|K_h| = Q`, requiring full quorum even in BFT mode. The Level 1 tiebreak only fires when both blocks have `sig_count = 2 = |K_h|`. At K=6, `|K_h| = 4`, `Q = 3`: blocks can have `sig_count ∈ {3, 4}`, so Level 1 has more room for disambiguation. Larger K gives the comparator more sig-count granularity.

### F-3: Identical-blocks return convention

`resolve_fork(A, A)` returns the first argument `a`. This is documented in §2.2 but is observationally arbitrary (the caller receives a reference to a block byte-equal to the other argument). A future audit might prefer returning the lexicographically-min reference for symmetry — but since the blocks are byte-equal, the choice is purely cosmetic.

**Closure status.** Acknowledged; no functional issue. The harness test #4 (`src/main.cpp:12018–12026`) asserts this convention explicitly.

### F-4: Fork-choice does not cover same-prefix divergence at different heights

`resolve_fork(A, B)` is defined for `A.index = B.index` (same height). The function does not address the case where one branch has more blocks than the other (e.g., `B_h` vs `B_h, B_{h+1}`). The "longer chain" comparison is the receive path's job: per `node.cpp::on_block`, a chain with more blocks is preferred at the chain-level admission (this is the legacy GHOST-style "longer chain wins" logic that predates the fork-choice rule).

**Closure status.** Out of scope for the per-block fork-choice rule. The composition is: same-height fork ⇒ `resolve_fork` selects. Different-height tips ⇒ longer chain wins (per receive-side admission logic). The two surfaces compose to give a total-order on chain-tips.

### F-5: Hash-comparison endianness convention

The byte-wise compare interprets `Hash` (a 32-byte array) as big-endian for the lex ordering (loop from index 0 upward, comparing high-order bytes first). This matches SHA-256's standard byte ordering (FIPS 180-4 emits the digest as `H[0], H[1], ..., H[7]` with `H[0]` the highest-order 32-bit word, big-endian within each word). All nodes use the same byte-order convention (the `std::array<uint8_t, 32>` is a memory-layout-defined sequence, not a numeric value subject to endian conversion), so the comparison is consistent across architectures.

**Closure status.** Acknowledged; no portability issue. C++ `std::array` is contiguous-storage by spec, and the byte-wise loop is endian-neutral (it never interprets the bytes as a multi-byte integer).

### F-6: No staleness check on `compute_hash()`

`resolve_fork` calls `a.compute_hash()` and `b.compute_hash()` on every invocation. The block's hash is not memoized; each call re-runs SHA-256 over `signing_bytes(blk)`. For a 4 MB block (S-022 cap), this is a non-trivial cost (~ms per hash on modern hardware). On a pairwise reduction of `N` competing blocks, total hash work is `O(N · block_size)`.

**Closure status.** Acknowledged; not a safety issue, just a performance observation. A future optimization could memoize `compute_hash()` results on the `Block` object (a per-block hash cache, cleared on field mutation). The current implementation favors simplicity (no cache-coherence concerns) at the cost of recomputation. Per T-4, the asymptotic cost is bounded.

---

## 7. Test-suite citation

### 7.1 In-process unit harness — `determ test-resolve-fork`

The S-035 Option 1 in-process unit test at `src/main.cpp:11909–12062` drives `Chain::resolve_fork` through 10 assertions covering each comparator level + edge cases (see §3.4 above for the per-scenario breakdown).

The harness is invoked via:

```sh
$ determ test-resolve-fork
```

Each assertion prints `PASS: <description>` or `FAIL: <description>`; the harness exits with status 0 iff all assertions pass and prints a trailing `PASS: resolve-fork all assertions` line.

### 7.2 Shell-script wrapper — `tools/test_resolve_fork.sh`

The wrapper script at `tools/test_resolve_fork.sh` invokes the harness, captures stdout, and grep's for the trailing `PASS: resolve-fork all assertions` marker. On match: exit 0 (pass). On miss: exit 1 (fail). The wrapper is part of the standard regression suite (`tools/run_all.sh` includes `test_resolve_fork` in the unit-test phase) and runs as part of CI.

### 7.3 Composition with sister regression tests

`tools/test_chain_integrity.sh` (S-021 chain.json wrap regression) and `tools/test_state_root.sh` (S-033/S-038 state_root binding regression) exercise the sister surfaces of `Chain::resolve_fork`. Together they cover the full state-integrity composition:

- **Load-time tampering detection** (S-021): chain.json head_hash recompute on load.
- **Apply-time state divergence** (S-033 + S-038): state_root gate fires on production blocks.
- **Same-height fork resolution** (S-029, this proof): canonical tip selected deterministically.

A regression in any of the three would orphan a different attack surface. `Chain::resolve_fork`'s regression-test cost is concentrated in `test_resolve_fork.sh` (10/10 PASS).

### 7.4 Future: cross-node integration test

The current regression-test surface for `resolve_fork` is in-process only (single-binary test harness). A natural extension would be a multi-node integration test that constructs two honest nodes, force-injects competing blocks via a test-only RPC, and verifies that both nodes converge on the same tip. The integration test is out of scope for the S-029 closure as shipped (the comparator's properties are pure-function properties, fully covered by in-process unit tests), but is a candidate for S-035 Option 1 hardening.

---

## 8. Status

**Mitigated in-session.** `Chain::resolve_fork` at `src/chain/chain.cpp:1516–1537` implements the three-criterion lexicographic comparator (heaviest sigs → fewest aborts → smallest hash). The function is `static`, pure, and deterministic. T-1 (deterministic tiebreak), T-2 (pairwise confluence), T-3 (composition with K-of-K), T-4 (termination), and T-5 (compositional with BFT escalation) hold under H1..H4 + A1 + A2.

`docs/SECURITY.md` classifies S-029 as Mitigated (Medium → Mitigated). The regression-test surface is `tools/test_resolve_fork.sh` + `determ test-resolve-fork` (10 assertions, all PASS). Six identified gaps (F-1 hash-grinding economic feasibility, F-2 BFT-mode Q-vs-K boundary observation, F-3 identical-blocks return convention, F-4 different-height composition, F-5 endian convention, F-6 hash recompute on every call) are documented as either acknowledged-no-issue or future-optimization opportunities — none affect the comparator's safety or convergence guarantees.

The S-029 closure composes cleanly with FA1 (MD-mode K-of-K safety, where `resolve_fork` is structurally never invoked because only one digest exists), FA5 (BFT-mode conditional safety, where `resolve_fork` selects among multi-quorum candidates), FA6 + FA-Apply-10 (equivocation slashing, which punishes the producer responsible for the fork in the first place), and S-021 (`BlockchainStateIntegrity.md` chain.json head_hash recompute, which closes the load-side composition). The composition produces a single-canonical-chain property that every honest node converges on regardless of network-arrival order, partition pattern, or competing producer behavior.

---

## 9. References

- `docs/SECURITY.md` §S-029 — closure narrative + mitigated-status row.
- `docs/PROTOCOL.md` §5.3 — BFT-mode escalation gates (the 4-gate trigger).
- `docs/WHITEPAPER-v1.x.md` §3.3 — BFT-mode safety + escalation narrative.
- `src/chain/chain.cpp:1516–1537` — `Chain::resolve_fork` definition.
- `include/determ/chain/chain.hpp:454–456` — `resolve_fork` static declaration.
- `include/determ/chain/block.hpp:390–419` — `creator_block_sigs` + `abort_events` field declarations.
- `src/main.cpp:11909–12062` — in-process `test-resolve-fork` unit harness (10 assertions).
- `src/main.cpp:427–431` — `determ help` text describing the test subcommand.
- `tools/test_resolve_fork.sh` — wrapper script for the unit harness.
- `docs/proofs/Preliminaries.md` — F0 notation; H1..H4 honest-validator assumptions; A1 Ed25519 EUF-CMA; A2 SHA-256 collision resistance; V8 K-of-K validity predicate.
- `docs/proofs/Safety.md` — FA1 MD-mode unconditional safety theorem; §6 "no fork-choice rule" observation referring to MD mode only.
- `docs/proofs/BFTSafety.md` — FA5 BFT-mode conditional safety; quorum-intersection lemmas; §4 slashing-recovery corollary citing the resolve_fork heaviest-sig-set rule.
- `docs/proofs/Censorship.md` — FA2 censorship resistance; §3 fork-choice composition with union-tx-root.
- `docs/proofs/EquivocationSlashing.md` — FA6 slashing soundness (honest never slashed).
- `docs/proofs/EquivocationSlashingApply.md` — FA-Apply-10 slashing apply-mechanics.
- `docs/proofs/SelectiveAbort.md` — FA3 selective-abort defense (related to abort-count tiebreak in §5.2).
- `docs/proofs/EconomicSoundness.md` §S-010 — operator stake-pricing formula (cited in §6 F-1).
- `docs/proofs/BlockchainStateIntegrity.md` — S-021 chain.json wrap; sister state-integrity surface.
- `docs/proofs/S006ContribMsgEquivocation.md` — companion proof showing Phase-1 equivocation detection (analogous structural argument for a different equivocation surface).
- `docs/proofs/S017UnstakeApplyConsistency.md` — companion proof showing three-layer defense composition (analogous structural argument for a different state surface).
- `docs/proofs/S028AnonAddressNormalization.md` — companion proof for case-insensitive read / canonical-only write (the structural mirror of resolve_fork's deterministic-input contract).

---

## 10. Provenance

This proof was written to close the analytic gap on `Chain::resolve_fork`'s fork-choice rule per the S-029 mitigation shipped in `src/chain/chain.cpp`. The S-029 closure itself was shipped earlier; this document formalizes the algebraic properties (T-1..T-5) that make the comparator a sound fork-choice rule. The proof is companion-cited from BFTSafety.md §4 (which cites the rule by name in its slashing-recovery corollary) and from `docs/SECURITY.md` §S-029 (the closure-narrative row).
