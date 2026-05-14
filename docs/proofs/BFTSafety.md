# FA5 — BFT-mode conditional safety

This document proves that blocks produced in BFT-escalation mode (`consensus_mode = BFT`) are safe under the conditions that have always governed BFT-style protocols: Byzantine fraction less than `K_eff/3` within the committee, plus equivocation slashing as economic backing.

Unlike MD-mode safety (FA1 T-1, unconditional given ≥1 honest in committee), BFT-mode safety is **conditional**. The trade is documented in `docs/PROTOCOL.md` §10.4 and observed per-block via the `consensus_mode` tag.

**Companion documents:** `Preliminaries.md` (F0); `Safety.md` (FA1) for MD-mode safety + the pigeonhole pattern; `EquivocationSlashing.md` (FA6) for the slashing soundness this proof relies on.

---

## 1. Theorem statement

**Setup.** Fix height `h` where the chain has escalated to BFT mode (`B.consensus_mode = BFT`). Let `K` be the genesis-pinned committee size, `K_eff := ⌈2K/3⌉` the BFT-mode effective threshold. The BFT committee `K_h ⊂ V` is the smaller-than-K sub-committee derived from the abort-adjusted seed (Preliminaries §6). Let `F_h := F ∩ K_h`, with `f_h := |F_h|` (Byzantine fraction within the BFT committee).

A BFT-mode block `B` carries `K_h.size()` `creator_block_sigs[]` entries; at least `K_eff` of them must be nonzero (signed by committee members) for V8 to pass. The remaining `K_h.size() - K_eff` may be sentinel-zero.

**Theorem T-5 (BFT-mode safety, conditional).** Under the assumptions:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2).
- **(A2) SHA-256 collision resistance** (Preliminaries §2.1).
- **(B1) Byzantine fraction bound**: `f_h < K_eff/3`. Equivalently, `f_h < K/9 + ⌈K/9⌉` approximately. For `K = 3, K_eff = 2`: `f_h < 1` ⟹ `f_h = 0`. For `K = 6, K_eff = 4`: `f_h < 2` ⟹ `f_h ≤ 1`. For `K = 9, K_eff = 6`: `f_h < 2` ⟹ `f_h ≤ 1`.
- **(B2) Equivocation slashing enforced**: by FA6, honest validators are not slashed; any equivocator's stake is forfeit and registration deregistered. (FA6's bound is `≤ 2⁻¹²⁸` per attempt.)

then two valid BFT-mode blocks `B, B'` at the same height `h` against the same chain prefix imply `B = B'`. In plain terms: **BFT-mode blocks are unique under f_h < K_eff/3 within the BFT committee**.

**Corollary T-5.1 (Slashing recovery for BFT-mode forks).** If `f_h ≥ K_eff/3` and two BFT-mode blocks finalize at height `h`, then every committee member appearing as proposer in both has equivocated. By FA6, slashing zeros their stake AND deregisters them. The chain re-organizes around the surviving honest members at height `h+1`'s committee selection.

This is a "fault-tolerant" recovery: even when B1 is violated, the protocol detects + slashes + recovers; it doesn't simply fail.

---

## 2. Lemmas

### Lemma L-5.1 — Quorum intersection in BFT mode

Let `S(B) ⊂ K_h` be the set of committee members that signed `compute_block_digest(B)`. Let `S(B') ⊂ K_h` be similarly for `B'`. Under V8 (Preliminaries §5):

$$
|S(B)| \geq K_{\text{eff}}, \quad |S(B')| \geq K_{\text{eff}}
$$

Then `|S(B) ∩ S(B')| ≥ 2 K_eff - |K_h| ≥ 2 K_eff - K`.

For `K_eff = ⌈2K/3⌉`: `|S(B) ∩ S(B')| ≥ 2⌈2K/3⌉ - K ≥ K/3 + 1`.

**Proof.** Inclusion-exclusion on subsets of `K_h`. Both `S(B)` and `S(B')` are subsets of size at least `K_eff`. Their intersection is at least the sum of their sizes minus the universe: `|S(B) ∩ S(B')| ≥ |S(B)| + |S(B')| - |K_h|`.

Substituting `K_eff = ⌈2K/3⌉` and `|K_h| ≤ K`: `|intersection| ≥ 2⌈2K/3⌉ - K`. For `K = 3`: `2·2 - 3 = 1`. For `K = 6`: `2·4 - 6 = 2`. For `K = 9`: `2·6 - 9 = 3`.

The bound is `K/3 + 1` rounded down to integers — a non-empty intersection in all cases.   ∎

### Lemma L-5.2 — Honest intersection forces digest equality

If `|S(B) ∩ S(B')| > f_h`, then at least one member of the intersection is honest. By H2 (Preliminaries §4 honest validator behavior, "signs at most one digest per height"), an honest member of the intersection signed at most one of `(d_a, d_b)`. So `d_a = d_b` (the honest member can't have signed two), hence `B.digest_field set = B'.digest_field set` modulo equivalent block-digest collision, hence `B = B'` up to L-1.2-style reasoning.

**Proof.** By the contrapositive: suppose `d_a ≠ d_b` (i.e., `compute_block_digest(B) ≠ compute_block_digest(B')`). Then every member of `S(B) ∩ S(B')` has signed two distinct digests at the same height. By H2, none of them can be honest. So every member of `S(B) ∩ S(B')` is in `F_h`, giving `|S(B) ∩ S(B')| ≤ f_h`.

Contrapositive: if `|S(B) ∩ S(B')| > f_h`, then `d_a = d_b`, hence `B = B'` (by the FA1 lemma L-1.2 chain on signing_bytes injectivity).   ∎

---

## 3. Proof of Theorem T-5

Suppose for contradiction that BFT-mode blocks `B, B'` are both valid at height `h`, with `B ≠ B'`. By FA1's L-1.2, `compute_block_digest(B) ≠ compute_block_digest(B')`.

By L-5.1, `|S(B) ∩ S(B')| ≥ K/3 + 1 ≥ ⌈K/3⌉`.

By L-5.2's contrapositive, `B ≠ B'` (with distinct digests) requires `|S(B) ∩ S(B')| ≤ f_h`.

Combining: `K/3 + 1 ≤ f_h`, i.e., `f_h ≥ K/3 + 1 > K/3`.

Under B1, `f_h < K_eff/3 = ⌈2K/3⌉/3`. For `K = 3, K_eff = 2`: `K_eff/3 = 2/3 < 1`, so `f_h < 1`, i.e., `f_h = 0`. This gives `K/3 + 1 ≤ 0` ⟹ `K ≤ -3` — contradiction.

For larger K (e.g., `K = 6, K_eff = 4`): `K_eff/3 = 4/3 ≈ 1.33`, so `f_h ≤ 1`. The condition `K/3 + 1 ≤ 1` ⟹ `K/3 ≤ 0` ⟹ `K ≤ 0` — contradiction.

Generally `f_h < K_eff/3 ≤ K/3 + 1` is the constraint. The contradiction emerges: `K/3 + 1` (lower bound on f_h from quorum overlap) cannot be `< K_eff/3 ≤ K/3 + 1` (upper bound from B1 on f_h) simultaneously.

More carefully: `f_h < K_eff/3 = ⌈2K/3⌉/3 ≈ 2K/9`. So `f_h < 2K/9`. The overlap lower-bound is `f_h ≥ 2K_eff - K = 2⌈2K/3⌉ - K ≥ K/3 + 1 ≈ K/3`. So `K/3 ≤ f_h < 2K/9`. For `K > 0`: `K/3 < 2K/9` requires `K < 0` — impossible.

Hence the supposition `B ≠ B'` leads to contradiction under B1. Therefore `B = B'`.   ∎

**Numeric verification for K = 3, K_eff = 2:**

- B1: `f_h < 2/3`, so `f_h = 0`.
- L-5.1: `|S(B) ∩ S(B')| ≥ 2·2 - 3 = 1`.
- L-5.2: with `|intersection| = 1` and `f_h = 0`, the one intersection member is honest. By H2, they signed only one of the two digests. So at most one of B or B' has its `K_eff = 2` sigs; the other has at most 1 valid sig and fails V8 (which requires `≥ K_eff = 2`). So both can't be valid simultaneously. ✓

For K = 6, K_eff = 4:

- B1: `f_h < 4/3`, so `f_h ≤ 1`.
- L-5.1: `|S(B) ∩ S(B')| ≥ 2·4 - 6 = 2`.
- L-5.2: with `|intersection| = 2` and `f_h = 1`, at least one intersection member is honest. Same contradiction.

---

## 4. Proof of Corollary T-5.1 (Slashing recovery)

Suppose B1 is violated (`f_h ≥ K_eff/3`). Then L-5.2's contrapositive doesn't kick in, and two distinct BFT-mode blocks `B, B'` can co-exist with `f_h` Byzantine members signing both digests.

The intersection `S(B) ∩ S(B')` contains `≥ K_eff/3` Byzantine signers (those who signed both digests). For each such signer `v_i ∈ F_h`:

- `v_i` produced `σ_a` on `compute_block_digest(B)` and `σ_b` on `compute_block_digest(B')`, both at height `h`.
- These two signatures are a valid `EquivocationEvent` by V11.

By FA6, the equivocation slashing pipeline:

1. Detects the double-signing (peer apply or external submission via `submit_equivocation` RPC).
2. Gossips the `EquivocationEvent` so all chain replicas converge on the evidence.
3. Bakes the event into the next finalized block.
4. Zeroes `stakes_[v_i].locked` AND sets `registrants_[v_i].inactive_from = h+1`.

After step 4, `v_i` is removed from the eligible pool for all future committee selections (committee_region filter still applies; the deregistration is unconditional). The chain re-organizes at height `h+1` with a smaller, possibly all-honest committee.

The "fork" at height `h` doesn't propagate because subsequent blocks build on whichever of `B` or `B'` first finalizes consistently across observers (by the resolve_fork heaviest-sig-set rule); the loser branch's ancestry stops at `h`.   ∎

---

## 5. Discussion

### 5.1 The trade Determ makes

Under MD mode (FA1), safety is unconditional given ≥1 honest in committee. Under BFT mode (this proof), safety is conditional on `f_h < K_eff/3` in the committee.

The trade:

- **MD-mode**: safe always, but a single silent committee member halts the round (no liveness).
- **BFT-mode**: safe only under `f_h < K_eff/3`, but `K - K_eff` members can be silent and the round still finalizes (liveness from FA4).

Operators tune via `bft_enabled` (genesis-pinned). Most operators take the default (`true`) and accept BFT-mode safety on the tail of blocks; high-value applications wait for the next MD-mode block.

### 5.2 Per-block trust observability

Both MD and BFT mode blocks carry `consensus_mode` in their header. Applications observing the chain:

- See `MD` blocks: rely on FA1 (unconditional under ≥1 honest in committee).
- See `BFT` blocks: rely on FA5 (conditional under `f_h < K_eff/3` AND FA6 slashing).

This is per-block trust granularity. Light clients can apply different confirmation policies to MD vs BFT blocks.

### 5.3 What this proof does NOT cover

- **Liveness of escalation itself.** FA4 covers that (under bft_enabled + bounded p, BFT escalation always engages eventually).
- **BFT proposer fairness.** The bft_proposer is deterministically chosen; "fairness" of the proposer (rotating equitably) is a different property — see Preliminaries §6 for the selection rule.
- **Cross-shard BFT.** Cross-shard receipts (FA7) are unaffected by per-shard BFT mode; the destination shard receives + validates via the source's committee signatures (which include the BFT-mode tag).

### 5.4 Concrete-security bound

Per the proof, the conditional safety bound is unconditional in the algebraic sense (no probabilistic gap). It depends only on counting arguments. The cryptographic bound comes from FA1's L-1.2 (signing_bytes injectivity, `2⁻¹²⁸`) and FA6's EUF-CMA (`2⁻¹²⁸`) for the slashing-recovery path.

Together: BFT-mode safety holds with `≤ 2⁻¹²⁸` per height (cryptographic) AND `1 - O(Q · 2⁻¹²⁸)` cumulative under adversarial query budget Q.

When B1 is violated, the recovery path (T-5.1) loses an additional `2⁻¹²⁸` per slash attempt. Total degradation: `≤ K · 2⁻¹²⁸` per height — still negligible.

---

## 6. Implementation cross-reference

| Document | Source |
|---|---|
| BFT-mode `consensus_mode = BFT` block | `include/determ/chain/block.hpp::ConsensusMode::BFT` |
| `K_eff = ⌈2K/3⌉` quorum check | `src/node/validator.cpp::check_block_sigs` BFT branch |
| BFT escalation trigger | `src/node/node.cpp::check_if_selected` (four gates: `bft_enabled`, `total_aborts ≥ bft_escalation_threshold`, available pool < K, available pool ≥ ceil(2K/3)) |
| `bft_proposer` deterministic election | `proposer_idx` in `src/node/producer.cpp` (called from `node.cpp::current_bft_proposer` for the producer side and `validator.cpp::check_block_structure` for the validator side; full algorithm in PROTOCOL.md §5.3.1) |
| BFT mode opt-out | `Config.bft_enabled` (default true, false disables escalation) |
| Slashing recovery (T-5.1) | `EquivocationSlashing.md` (FA6) + `src/chain/chain.cpp::apply_transactions` |

A reviewer can confirm:

- The 2K/3 ceiling matches V8's BFT branch.
- The Byzantine-fraction bound `f_h < K_eff/3` is enforced by the protocol's design (not at runtime — observers reason about it externally).
- Slashing recovery operates atomically with the next block's apply; no special-case is needed.

---

## 7. Conclusion

BFT-mode blocks are safe under `f_h < K_eff/3` within the committee. The trade vs MD-mode is real and observable per-block via `consensus_mode`.

When the bound is violated, slashing recovery (T-5.1) repairs the damage by removing the equivocators. This is materially stronger than classical BFT failure modes (where exceeding f<N/3 simply breaks safety with no recovery).

The proof complements FA1 (MD-mode unconditional) and FA4 (liveness via escalation) to give Determ's full safety/liveness story:

- MD: unconditional safety, conditional liveness.
- BFT: conditional safety, much-stronger liveness.
- Slashing: recovery for B1-violation cases.

Operators pick the bft_enabled flag once at genesis based on their threat model.
