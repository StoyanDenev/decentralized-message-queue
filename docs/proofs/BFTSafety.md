# FA5 — BFT-mode conditional safety

This document proves that blocks produced in BFT-escalation mode (`consensus_mode = BFT`) are safe under the condition that has always governed BFT-style protocols: Byzantine fraction less than `|K_h|/3` within the committee.

> **RE-DERIVED 2026-09-17 (sequence step 3c; owner decision D4, DECISION-LOG 2026-09-16).** This document
> used to carry a fourth assumption **(B2) "equivocation slashing enforced"** and a Corollary **T-5.1**
> ("slashing recovery"). Equivocation carries **no L1 consequence**: `Chain::apply_transactions` reads
> nothing from `b.equivocation_events` — no stake moves, no registrant is deactivated. B2 is therefore
> FALSE and has been **deleted**; T-5.1 is **WITHDRAWN** and replaced by T-5.1-R (§4), which states what
> a B1 violation actually produces now. **T-5 itself is unchanged in content**: its proof (§3) consumes
> L-5.1 (counting) and L-5.2 (honest single-sign + A1/A2) and never consumed B2 at any step, so deleting
> B2 removes a decorative hypothesis rather than a load-bearing one — the theorem now holds under strictly
> fewer assumptions. §5.4's concrete-security paragraph and §7's "materially stronger than classical BFT"
> claim are corrected accordingly. What T-5 needs instead, and did not label, is the honest single-sign
> assumption made explicit as **(B2′)** below — which is NOT unconditional; see §4.2.

Unlike MD-mode safety (FA1 T-1, unconditional given ≥1 honest in committee), BFT-mode safety is **conditional**. The trade is documented in `docs/PROTOCOL.md` §10.4 and observed per-block via the `consensus_mode` tag.

**Companion documents:** `Preliminaries.md` (F0); `Safety.md` (FA1) for MD-mode safety + the pigeonhole pattern; `EquivocationSlashing.md` (FA6) for the slashing soundness this proof relies on.

---

## 1. Theorem statement

**Setup.** Fix height `h` where the chain has escalated to BFT mode (`B.consensus_mode = BFT`). Let `K` be the genesis-pinned committee size and `K_h ⊂ V` the smaller BFT committee derived from the abort-adjusted seed (Preliminaries §6) with `|K_h| = ⌈2K/3⌉`. Define `Q := ⌈2 · |K_h| / 3⌉` — the **within-committee 2/3 quorum** the validator's V8 enforces in BFT mode (`src/node/producer.cpp::required_block_sigs` for the formula `(2·k + 2) / 3`). Let `F_h := F ∩ K_h`, with `f_h := |F_h|` (Byzantine fraction within the BFT committee).

A BFT-mode block `B` carries `|K_h|` `creator_block_sigs[]` entries; at least `Q` of them must be nonzero (signed by committee members) for V8 to pass. The remaining `|K_h| − Q` slots may be sentinel-zero. Worked examples (K = 3 ⇒ |K_h| = 2, Q = 2; K = 6 ⇒ |K_h| = 4, Q = 3; K = 9 ⇒ |K_h| = 6, Q = 4). The K_eff notation used in earlier revisions of this proof has been replaced with the explicit `|K_h|` (committee size) and `Q` (quorum) to avoid conflating two distinct numbers — they only coincide at the genesis-default K = 3.

**Theorem T-5 (BFT-mode safety, conditional).** Under the assumptions:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2).
- **(A2) SHA-256 collision resistance** (Preliminaries §2.1).
- **(B1) Byzantine fraction bound**: `f_h < |K_h|/3` (standard BFT bound applied within the smaller BFT committee). Worked examples: K = 3 ⇒ |K_h| = 2 ⇒ f_h < 2/3 ⇒ f_h = 0. K = 6 ⇒ |K_h| = 4 ⇒ f_h < 4/3 ⇒ f_h ≤ 1. K = 9 ⇒ |K_h| = 6 ⇒ f_h < 2 ⇒ f_h ≤ 1.
- **(B2′) Honest single-sign at height `h`**: every honest member of `K_h` produces at most one `compute_block_digest` signature at height `h` in the execution considered (Preliminaries §4, H2). This is the assumption L-5.2 actually consumes. It replaces the deleted (B2); it is **not unconditional** and §4.2 states exactly when the shipped code satisfies it.

then two valid BFT-mode blocks `B, B'` at the same height `h` against the same chain prefix imply `B = B'`. In plain terms: **BFT-mode blocks are unique under f_h < |K_h|/3 within the BFT committee, per round instance** — standard BFT safety re-targeted at the shrunk committee.

**Corollary T-5.1-R (What a B1 violation produces — replaces the withdrawn T-5.1).** If `f_h ≥ |K_h|/3` and two BFT-mode blocks finalize at height `h`, then every committee member that signed both digests has equivocated, and any honest peer that observes both signature sets constructs a V11-valid `EquivocationEvent` which gossips and is baked into a later block. That is the whole of it. Since D4 (2026-09-16) the baked event **moves no L1 state**: the equivocators keep their stake, keep their registration, and remain in the eligible pool, so they may be selected again at height `h+1` and at every height after. **There is no recovery.** What bounds the damage is not removal but `Chain::resolve_fork` (`S029ForkChoiceSoundness.md` T-1/T-2): every honest node ranks the two blocks identically and converges on one, so the chain does not split — it simply accepts a block a Byzantine super-third chose, and can do so again.

---

## 2. Lemmas

### Lemma L-5.1 — Quorum intersection in BFT mode

Let `S(B) ⊂ K_h` be the set of committee members that signed `compute_block_digest(B)`. Let `S(B') ⊂ K_h` be similarly for `B'`. Under V8 (Preliminaries §5), each block's signing set has cardinality at least the within-committee 2/3 quorum:

$$
|S(B)| \geq Q, \quad |S(B')| \geq Q \quad \text{where } Q = \lceil 2|K_h|/3 \rceil
$$

Then `|S(B) ∩ S(B')| ≥ 2Q - |K_h|`.

**Proof.** Inclusion-exclusion on subsets of `K_h`. Both `S(B)` and `S(B')` are subsets of size at least `Q`. Their intersection is at least the sum of their sizes minus the universe: `|S(B) ∩ S(B')| ≥ |S(B)| + |S(B')| - |K_h| ≥ 2Q - |K_h|`.

Substituting `|K_h| = ⌈2K/3⌉` and `Q = ⌈2|K_h|/3⌉`, the intersection is bounded below by approximately `|K_h|/3 + 1`. Worked values:

| K | |K_h| | Q | 2Q − |K_h| (intersection lower bound) |
|---|---|---|---|
| 3 | 2 | 2 | 2 |
| 6 | 4 | 3 | 2 |
| 9 | 6 | 4 | 2 |
| 12 | 8 | 6 | 4 |

The intersection is non-empty in every case, and in fact has size `≥ |K_h|/3 + 1` whenever the formula admits an integer. ∎

### Lemma L-5.2 — Honest intersection forces digest equality

If `|S(B) ∩ S(B')| > f_h`, then at least one member of the intersection is honest. By H2 (Preliminaries §4 honest validator behavior, "signs at most one digest per height"), an honest member of the intersection signed at most one of `(d_a, d_b)`. So `d_a = d_b` (the honest member can't have signed two), hence `B.digest_field set = B'.digest_field set` modulo equivalent block-digest collision, hence `B = B'` up to L-1.2-style reasoning.

**Proof.** By the contrapositive: suppose `d_a ≠ d_b` (i.e., `compute_block_digest(B) ≠ compute_block_digest(B')`). Then every member of `S(B) ∩ S(B')` has signed two distinct digests at the same height. By H2, none of them can be honest. So every member of `S(B) ∩ S(B')` is in `F_h`, giving `|S(B) ∩ S(B')| ≤ f_h`.

Contrapositive: if `|S(B) ∩ S(B')| > f_h`, then `d_a = d_b`, hence `B = B'` (by the FA1 lemma L-1.2 chain on signing_bytes injectivity).   ∎

---

## 3. Proof of Theorem T-5

Suppose for contradiction that BFT-mode blocks `B, B'` are both valid at height `h`, with `B ≠ B'`. By FA1's L-1.2, `compute_block_digest(B) ≠ compute_block_digest(B')`.

By L-5.1, `|S(B) ∩ S(B')| ≥ 2Q − |K_h| ≥ ⌈|K_h|/3⌉ + 1` (the standard BFT 2/3-quorum intersection).

By L-5.2's contrapositive, `B ≠ B'` (with distinct digests) requires `|S(B) ∩ S(B')| ≤ f_h`.

Combining: `f_h ≥ ⌈|K_h|/3⌉ + 1 > |K_h|/3`.

Under B1, `f_h < |K_h|/3`. The two bounds contradict.

Hence the supposition `B ≠ B'` leads to contradiction under B1. Therefore `B = B'`.   ∎

**Numeric verification for K = 3 (|K_h| = 2, Q = 2):**

- B1: `f_h < 2/3`, so `f_h = 0`.
- L-5.1: `|S(B) ∩ S(B')| ≥ 2·2 − 2 = 2`.
- L-5.2: with `|intersection| = 2` and `f_h = 0`, both intersection members are honest. By H2, neither signed two distinct digests at h. So `compute_block_digest(B) = compute_block_digest(B')`, hence `B = B'`. ✓

For K = 6 (|K_h| = 4, Q = 3):

- B1: `f_h < 4/3`, so `f_h ≤ 1`.
- L-5.1: `|S(B) ∩ S(B')| ≥ 2·3 − 4 = 2`.
- L-5.2: with `|intersection| = 2` and `f_h ≤ 1`, at least one intersection member is honest. Same contradiction.

For K = 12 (|K_h| = 8, Q = 6):

- B1: `f_h < 8/3`, so `f_h ≤ 2`.
- L-5.1: `|S(B) ∩ S(B')| ≥ 2·6 − 8 = 4`.
- L-5.2: with `|intersection| = 4` and `f_h ≤ 2`, at least 2 honest members in the intersection. Contradiction.

---

## 4. Corollary T-5.1-R — what a B1 violation produces (replaces the withdrawn T-5.1)

### 4.1 The argument

Suppose B1 is violated (`f_h ≥ |K_h|/3`). Then L-5.2's contrapositive doesn't kick in, and two distinct BFT-mode blocks `B, B'` can co-exist with `f_h` Byzantine members signing both digests.

The intersection `S(B) ∩ S(B')` contains `≥ ⌈|K_h|/3⌉` Byzantine signers (those who signed both digests). For each such signer `v_i ∈ F_h`:

- `v_i` produced `σ_a` on `compute_block_digest(B)` and `σ_b` on `compute_block_digest(B')`, both at height `h`.
- These two signatures are a valid `EquivocationEvent` by V11 (the two openings share `index` and, when the two blocks carry the same abort-event count, `gen`).

The evidence pipeline then runs, and stops one step earlier than it used to:

1. **Detects** the double-signing (the `apply_block_locked` cross-block check, the `on_contrib` S-006 check, gossip, or external submission via `submit_equivocation`).
2. **Gossips** the `EquivocationEvent` — one hop only; there is no relay and no re-request (S-090, OPEN), so "all replicas converge on the evidence" is NOT guaranteed.
3. **Bakes** the event into a later finalized block, where it is V11-verified and committed under the block hash.
4. **Applies it — as a no-op.** `Chain::apply_transactions` reads no field of the event. `stakes_[v_i].locked` is untouched; `registrants_[v_i].inactive_from` is untouched. Gate: `determ test-equivocation-apply` (state neutrality against an event-free twin, A1, positive control; mutants M1–M8 RED).

So after step 4 `v_i` is still staked, still registered and still eligible. **The chain does not re-organize.** The height-`h` fork does not propagate — every honest node runs the same deterministic `resolve_fork` comparator and keeps one branch (`S029ForkChoiceSoundness.md` T-1 determinism, T-2 confluence) — but the same super-third can repeat the attack at `h+1`, and nothing at L1 makes the second attempt cost more than the first. The only thing that accumulates is evidence.   ∎

### 4.2 What T-5 still gives, and what it no longer gives

**Still given (unchanged by D4/D13):**

- **Uniqueness under B1, per round instance.** T-5's proof is L-5.1 (a counting bound on `Q`-sized subsets of `K_h`) plus L-5.2 (an honest member cannot have signed both digests) plus A1/A2. None of those steps mentions stake, forfeiture, deregistration or the abort deduction. Deleting B2 changes no line of §3.
- **Detectability.** A B1 violation is *provable after the fact* from public bytes: two signatures by one registered key over two derivable digests at one index. That property is cryptographic (FA6 T-6) and survives.
- **No chain split.** Fork-choice determinism keeps the fleet on one branch.

**No longer given:**

- **Accountable safety in the punitive sense.** "Accountable" now means *evidence-only*: the protocol can name who broke B1, and can do nothing to them. There is no forfeiture, no exclusion, no re-organization around survivors, and no cost that rises with repetition.
- **Recovery.** The withdrawn T-5.1 was the document's only recovery claim. There is no L1 replacement. The intended replacement is the L2 bond policy (D22, v1.1 DApp scope, NOT designed and NOT a launch blocker for L1); until it exists, a B1 violation has no consequence at all.
- **The comparison to classical BFT.** See §7.

**The honest status of (B2′).** (B2′) is an assumption, not a shipped invariant, and two shipped honest behaviours falsify it at *height* granularity:

1. **Abort re-round.** `gen` is `b.abort_events.size()` and is bound into `compute_block_digest` (`src/node/producer.cpp::compose_block_digest`). An honest member that signs in round `g` and again, after an abort quorum, in round `g+1` at the same height has signed two distinct digests at height `h` — so (B2′) is false for it, and L-5.2 cannot conclude `d_a = d_b` from that member's honesty. (Whether V11 would ACCEPT the resulting pair as evidence is a separate question with a different answer: `check_equivocation_events` asserts `gen_a == gen_b`, so a cross-gen pair is rejected. The two questions must not be conflated — T-5 needs "an honest member did not sign both", not "the pair is admissible evidence".) The adjacent evidence-side residual is R-1 / `EquivocationSlashing.md` §2 Case (c), DECIDED under D4 as evidence-requiring-corroboration, never an L1 verdict.
2. **The S-050 stall valve.** The valve clears `current_aborts_` and re-enters selection; with an *empty* abort tail it restarts a round at the same height **and the same `gen`** with fresh randomness (`RoundStallValveSoundness.md` C-2 as corrected 2026-09-17; ledger S-095).

What holds unconditionally is the weaker **(B2′′)**: an honest member signs at most one digest per *round instance*. T-5 should therefore be read as "two blocks of the SAME round instance at height `h` are equal"; two blocks of DIFFERENT round instances at one height are not excluded by T-5 and are handled by fork-choice, not by uniqueness. The same granularity gap applies to FA1's Corollary T-1.1 (`Safety.md`), which invokes the same H2; correcting FA1 is **not** part of this increment and is recorded as OPEN in the step-3c DECISION-LOG entry.

---

## 5. Discussion

### 5.1 The trade Determ makes

Under MD mode (FA1), safety is unconditional given ≥1 honest in committee. Under BFT mode (this proof), safety is conditional on `f_h < |K_h|/3` in the smaller BFT committee.

The trade:

- **MD-mode**: safe always, but a single silent committee member halts the round (no liveness).
- **BFT-mode**: safe only under `f_h < |K_h|/3`, but `K − |K_h|` members can be silent (committee shrinks) and within `|K_h|`, `|K_h| − Q` more positions can carry sentinel-zero, and the round still finalizes (liveness from FA4).

Operators tune via `bft_enabled` (genesis-pinned). Most operators take the default (`true`) and accept BFT-mode safety on the tail of blocks; high-value applications wait for the next MD-mode block.

### 5.2 Per-block trust observability

Both MD and BFT mode blocks carry `consensus_mode` in their header. Applications observing the chain:

- See `MD` blocks: rely on FA1 (unconditional under ≥1 honest in committee).
- See `BFT` blocks: rely on FA5 (conditional under `f_h < |K_h|/3` alone; the FA6 leg is deleted — FA6 gives evidence, not backing).

This is per-block trust granularity. Light clients can apply different confirmation policies to MD vs BFT blocks.

### 5.3 What this proof does NOT cover

- **Liveness of escalation itself.** FA4 covers that (under bft_enabled + bounded p, BFT escalation always engages eventually).
- **BFT proposer fairness.** The bft_proposer is deterministically chosen; "fairness" of the proposer (rotating equitably) is a different property — see Preliminaries §6 for the selection rule.
- **Cross-shard BFT.** Cross-shard receipts (FA7) are unaffected by per-shard BFT mode; the destination shard receives + validates via the source's committee signatures (which include the BFT-mode tag).

### 5.4 Concrete-security bound

Per the proof, the conditional safety bound is unconditional in the algebraic sense (no probabilistic gap). It depends only on counting arguments. The cryptographic bound comes from FA1's L-1.2 (signing_bytes injectivity, `2⁻¹²⁸`).

Together: BFT-mode safety holds with `≤ 2⁻¹²⁸` per height (cryptographic) AND `1 - O(Q · 2⁻¹²⁸)` cumulative under adversarial query budget Q.

**Corrected 2026-09-17 (step 3c).** The former third paragraph priced "an additional `2⁻¹²⁸` per slash attempt" for the T-5.1 recovery path. That path no longer exists (T-5.1-R, §4): when B1 is violated there is no slash and therefore no term to add. The concrete-security accounting for the FA6 EUF-CMA bound now belongs where the evidence is USED — it is the false-naming probability of the record the L2 policy (D22) consumes, not a term in this document's safety bound.

---

## 6. Implementation cross-reference

| Document | Source |
|---|---|
| BFT-mode `consensus_mode = BFT` block | `include/determ/chain/block.hpp::ConsensusMode::BFT` |
| `Q = ⌈2|K_h|/3⌉` quorum check (with `|K_h| = ⌈2K/3⌉` BFT committee size) | `src/node/validator.cpp::check_block_sigs` BFT branch via `producer.cpp::required_block_sigs` |
| BFT escalation trigger | `src/node/node.cpp::check_if_selected` (four gates: `bft_enabled`, `total_aborts ≥ bft_escalation_threshold`, available pool < K, available pool ≥ ceil(2K/3)) |
| `bft_proposer` deterministic election | `proposer_idx` in `src/node/producer.cpp` (called from `node.cpp::Node::current_proposer_domain` for the producer side and `validator.cpp::BlockValidator::check_block_sigs` (BFT branch, ~lines 480–498) for the validator side; full algorithm in PROTOCOL.md §5.3.1; straight-modulo bias `≤ 2⁻⁵⁶` because `committee_size ≤ 256`) |
| BFT mode opt-out | `Config.bft_enabled` (default true, false disables escalation) |
| Evidence record (T-5.1-R) | `EquivocationSlashing.md` (FA6) + `src/node/validator.cpp::check_equivocation_events` (V11). NOT `Chain::apply_transactions` — that function reads nothing from `b.equivocation_events` since D4. |

A reviewer can confirm:

- The 2|K_h|/3 quorum matches V8's BFT branch — note this is the 2/3 of the *BFT committee size*, not 2/3 of the genesis K (the two differ at K ≥ 6).
- The Byzantine-fraction bound `f_h < |K_h|/3` is enforced by the protocol's design (not at runtime — observers reason about it externally).
- The evidence record is committed atomically with the next block's apply and changes no state leaf; the state-neutrality is gated by `determ test-equivocation-apply`.

---

## 7. Conclusion

BFT-mode blocks are safe under `f_h < |K_h|/3` within the committee (per round instance, §4.2). The trade vs MD-mode is real and observable per-block via `consensus_mode`.

**When the bound is violated there is no repair.** The former conclusion — "slashing recovery (T-5.1) repairs the damage by removing the equivocators … materially stronger than classical BFT failure modes" — is **WITHDRAWN** (D4, 2026-09-16; re-derived here 2026-09-17). Exceeding `f_h < |K_h|/3` breaks BFT-mode safety exactly as it does in a classical BFT protocol, and, exactly as there, nothing removes the offenders. Determ's two remaining advantages over classical BFT are narrower and should be claimed as such:

1. **MD-mode has no threshold.** FA1 clause 1 needs one honest committee member, not a two-thirds majority, and no BFT protocol offers that. A deployment that sets `bft_enabled = false` never enters the conditional regime at all (it trades liveness for it).
2. **Failure is attributable.** A B1 violation leaves two signatures by one registered key over two derivable digests, verifiable by anyone from public bytes and committed on-chain. Classical BFT above threshold typically leaves nothing. Attribution is not punishment: on L1 it buys exactly a record, whose consumer is the L2 bond policy (D22) and which does not exist yet.

The proof complements FA1 (MD-mode unconditional) and FA4 (liveness via escalation) to give Determ's safety/liveness story:

- MD: unconditional safety (≥ 1 honest member), conditional liveness.
- BFT: conditional safety (`f_h < |K_h|/3`), much-stronger liveness.
- Evidence: attribution for B1-violation cases — and, on L1, nothing else.

Operators pick the bft_enabled flag once at genesis based on their threat model. The flag is the whole of the safety/liveness trade; there is no third mechanism catching the tail.
