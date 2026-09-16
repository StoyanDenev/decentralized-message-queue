# FA6 — Equivocation slashing soundness

> **STATUS 2026-09-16 — D13 landed: a Phase-1 AbortEvent records the abort (S-032) and deducts NOTHING; T-A1 and every statement below that rests on the deduction are historical and are re-derived in step 3c (DECISION-LOG 2026-09-16 "D13 landed").**

> **STATUS 2026-09-16 — equivocation carries NO L1 consequence (owner decision D4, DECISION-LOG 2026-09-16; landed as O-1 step 3a).** The full-stake forfeiture and registry deactivation that this document treats as shipped apply-path behaviour were removed from `Chain::apply_transactions`; an `EquivocationEvent` is now an on-chain evidence record only (gate `determ test-equivocation-apply`). Every statement below that rests on that consequence is pending re-derivation in step 3c of the recorded sequence and must not be cited as current; until then the DECISION-LOG entry is the authority.

This document proves that Determ's equivocation-slashing mechanism produces no false positives: under EUF-CMA, an **honest** validator is **never** named as the equivocator in a finalized `EquivocationEvent`.

The proof is short and direct. It exists to make explicit the security gap that would otherwise be implicit: "slashing only the guilty" is a property of the design, not an obvious fact.

**Companion documents:** `Preliminaries.md` (F0) for notation; `Safety.md` (FA1) for the related "fully-Byzantine committee" branch.

---

## 1. Theorem statement

**Setup (restated 2026-08-12 — the EQV-height-bind restructure).** An `EquivocationEvent` is a tuple `(equivocator, h, kind, (i_a, r_a, σ_a), (i_b, r_b, σ_b))` carrying:

- `equivocator ∈ V`: a registered validator with public key `pk` known on-chain.
- `h`: the height the proof is ABOUT (`block_index`).
- `kind ∈ {0, 1}`: the digest family — `0 = BLOCK_DIGEST`, `1 = CONTRIB_COMMIT`.
- per side, an **opening** `(i, r)` = (signed height `u64`, digest body root `∈ {0,1}²⁵⁶`).
- `σ_a, σ_b ∈ {0,1}⁵¹²`: two Ed25519 signatures.

The signed digests are **not carried** — they are DERIVED by the verifier from the openings under the kind's domain tag:

```
D(kind, i, r)  =  SHA-256(TAG(kind) ‖ i u64 BE ‖ r)
TAG(0) = "DTM-BLKDIG-v3"      TAG(1) = "DTM-CONTRIB-v3"      (shipped: D = SHA-256(TAG ‖ i ‖ gen ‖ r); tags corrected 2026-09-14)
```

Block validity V11 (Preliminaries §5) requires all of:

```
kind ≤ 1
i_a = i_b = h                                   ← the HEIGHT ASSERT
r_a ≠ r_b        and        σ_a ≠ σ_b
Verify(pk, D(kind, i_a, r_a), σ_a) = 1
Verify(pk, D(kind, i_b, r_b), σ_b) = 1
```

Because the derived digests are functions of the asserted indices, `h` is **signature-bound**: an accepted event proves the equivocator signed two distinct bodies *at height h*, in *one* digest family. (Prior to 2026-08-12 the event carried two opaque digests with no index relation whatsoever; §2 Case (b) below records why that was unsound and what changed.)

When an `EquivocationEvent` is baked into a finalized block, `apply_transactions` (Preliminaries §9) zeroes `stakes_[equivocator].locked` and sets `registrants_[equivocator].inactive_from = h + 1`.

**Theorem T-6 (Soundness of equivocation slashing).** Under:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2): no polynomial-time adversary forges a signature by an honest key with non-negligible probability.
- **(H2) Honest validator behavior** (Preliminaries §4): an honest validator signs at most one `compute_block_digest` per (height, round) pair AND at most one `make_contrib_commitment` per (height, aborts_gen) tuple (the latter clause is the S-006 closure that brings ContribMsg-level equivocation under the same V11 channel — now `kind`-discriminated rather than digest-agnostic; see §5 cross-reference for both detection paths).
- **(H3) Single-round hypothesis** (NEW, and the honest boundary of this theorem): at height `h`, the honest validator participated in at most ONE round per digest family. §2 Case (c) shows the theorem's conclusion is conditional on H3 and identifies the open residual when H3 fails.

then for every `v_i ∈ V \ F` (honest validator) **that satisfies H3**:

$$
\Pr[v_i \text{ is named as equivocator in any finalized } EquivocationEvent] \;\leq\; \mathrm{negl}(\lambda)
$$

with concrete bound `≤ 2⁻¹²⁸` per attempted forgery. In plain terms: **slashing only catches the guilty**, with cryptographic certainty.

**Corollary T-6.1 (Cross-shard slashing soundness).** The theorem extends to cross-chain `EquivocationEvent` (where `shard_id ≠ 0` and `beacon_anchor_height` is set per the `EquivocationEvent` cross-chain fields). The reduction is identical: honest `v_i` never produces two signatures over distinct body roots at the same `(shard, height, round, kind)`. The Case (c) residual carries over unchanged to the cross-shard variant.

---

## 2. Proof of Theorem T-6

Suppose for contradiction that a finalized block contains an `EquivocationEvent` naming honest validator `v_i ∈ V \ F`. Let `pk_i` be `v_i`'s registered public key.

By V11, the event carries `(kind, (i_a, r_a, σ_a), (i_b, r_b, σ_b))` with:

- `i_a = i_b = h` (the height assert)
- `Verify(pk_i, D(kind, h, r_a), σ_a) = 1`
- `Verify(pk_i, D(kind, h, r_b), σ_b) = 1`
- `r_a ≠ r_b`

By H2 (Preliminaries §4), `v_i` signs at most one `compute_block_digest` per (height, round) AND at most one `make_contrib_commitment` per (height, aborts_gen) (S-006 closure — see §5 for the two implementation sites). **V11 is `kind`-discriminated, not digest-agnostic**: the two families are separated by their outer domain tags, so a block signature and a contrib signature can never be paired as one proof (see §2.1). Two cases below cover the block-digest mechanism (`kind = 0`); the contrib-commitment mechanism (`kind = 1`) is symmetric (substitute `(height, aborts_gen)` for `(height, round)`, `make_contrib_body_root` for `compute_block_digest_body`, and `TAG(1)` for `TAG(0)`):

**Case (a): Both signatures are over digests at the same round `r` at height `h`** (or, in the contrib-commitment branch: same `(height, aborts_gen)`).

By H2 with `(h, r)` fixed (or `(h, aborts_gen)` fixed for the Phase-1 branch), `v_i` has signed at most one such digest/commitment. If both `σ_a` and `σ_b` exist with `r_a ≠ r_b` (hence distinct derived digests) both verifying under `pk_i`, then at least one of them is a signature `v_i` did not produce. The party that produced it must have done so without `v_i`'s private key — i.e., must have forged it. By A1 (EUF-CMA), the probability of such a forgery is `≤ 2⁻¹²⁸`.

**Case (b): The two signatures are over digests at different HEIGHTS.** — **cryptographically excluded since 2026-08-12.**

`D(kind, i, r)` binds `i` inside the hash preimage, and V11 asserts `i_a = i_b = h` *before* verifying. An honest `v_i` only ever produces signatures over digests composed with its true height under the correct tag. To present one of those signatures under an opening `(h, r)` with `h ≠` the height it actually signed, an adversary must find `r` with `D(kind, h, r) = D(kind, h_true, r_true)` — a SHA-256 collision/second-preimage, probability `≤ 2⁻¹²⁸` per attempt (Preliminaries §2.1). So harvesting a validator's ordinary signatures from two different heights no longer yields a valid event.

**RETRACTION (recorded, per B3 — nothing aspirational).** The pre-2026-08-12 revision of this document argued Case (b) away on protocol-bookkeeping grounds ("the protocol's round-based bookkeeping prevents this from being framed as equivocation", "the chain has explicit evidence of which rounds aborted vs finalized"). **That argument was wrong.** `check_equivocation_events` performed no such bookkeeping: it accepted any two distinct digests signed by the accused key, with `block_index` an attacker-chosen, unsigned field. An attacker who observed one honest validator's `creator_block_sigs` at two different heights — both public, both on the wire — could assemble a valid event and forge a full-stake slash plus deregistration, remotely and unauthenticated. Tracked as **S-052** in `docs/SECURITY.md`; closed by the height binding above. The lesson recorded for future proofs: an argument that a field "is bookkept elsewhere" is not a proof unless the verifier reads that bookkeeping.

**Case (c): The two signatures are over digests at the SAME height `h` but different rounds** (e.g. `σ_a` from round `r`, `σ_b` from round `r+1` after an abort re-selection) — **OPEN residual; this is exactly what H3 excludes.**

An honest `v_i` selected onto the committee at both round `r` and round `r+1` of the same height signs two *different* bodies (the abort changes the committee, the tx set, and the fresh `dh_input`), hence two distinct body roots `r_a ≠ r_b` at one `h` under one tag. Both signatures are honest, both are public, and **V11 accepts the pair.** So the theorem holds only under H3.

This residual is:

- **pre-existing and strictly narrower** than before the fix (previously ANY two heights sufficed; now only the same height does, which requires the adversary to catch an actual abort re-round in which the victim was re-selected);
- **not closed**, and **not claimed closed** anywhere in this corpus;
- the round / `aborts_gen` IS bound into the opening at HEAD — `D = SHA-256(TAG ‖ i ‖ gen ‖ r)` (v3 tags; `src/node/producer.cpp` `compose_block_digest` / `compose_contrib_commitment`) and the verifier asserts `gen_a == gen_b` (`src/node/validator.cpp`, "(2b) THE ROUND ASSERT") — so a cross-round pair no longer satisfies V11.

**Status 2026-09-14: OPEN — the gen binding is SHIPPED and EVADABLE.** `gen` is signer-chosen off-chain, so a deliberate splitter signs side B at `gen + 1` and is acquitted, while an honest node's two openings are bit-identical to a splitter's (only delivery differs) — DECISION-LOG 2026-08-13 `b5838fb` and the six 2026-08-12 designs "final".."final+9": no predicate over two signed openings is both sound and complete under asynchrony. The consequence is being relocated out of consensus (CLAUDE.md SLASHING block; owner item O-1) and the forfeiture code is still live at HEAD until that lands. No proof in this corpus may assume Case (c) closed; do not re-propose a two-opening predicate.

**Combining cases**: a finalized `EquivocationEvent` falsely accusing honest `v_i` requires either:

- forging a signature by `pk_i` (Case (a)), probability `≤ 2⁻¹²⁸` by EUF-CMA; or
- breaking SHA-256 to re-open an honest signature at a different height (Case (b)), probability `≤ 2⁻¹²⁸`; or
- harvesting two honest same-height cross-round signatures (Case (c)) — **not cryptographically excluded**, and the reason T-6 is stated under H3.

Therefore, for any honest `v_i` satisfying H3, `Pr[v_i is slashed] ≤ 2⁻¹²⁷`, which is negligible.   ∎

### 2.1 Domain separation is load-bearing, not hygiene

The two outer tags `TAG(0) = "DTM-BLKDIG-v3"` and `TAG(1) = "DTM-CONTRIB-v3"` **must differ**. Suppose they did not. At one height `h` an honest committee member produces both a block signature over `D(h, r_blk)` and a contrib signature over `D(h, r_ctb)`, with `r_blk ≠ r_ctb` (different preimages entirely). Under a shared tag those are two distinct digests at one height signed by one key — a *complete* V11-valid event assembled entirely from honest behavior. Domain separation is therefore a **correctness requirement of this theorem**, not a stylistic convention: it is what makes "two distinct body roots at one height under one tag" mean "the signer committed to two conflicting things of the same kind".

Gate: the `test-abort-cert-validation` EQV block carries a `kind = 1` accept control and a cross-kind reject (contrib-signed signatures presented as `kind = 0` are REJECTED), pinning this leg specifically.

---

## 3. Proof of Corollary T-6.1 (cross-shard slashing)

The cross-shard `EquivocationEvent` extension (Preliminaries §9 + `EquivocationEvent.shard_id` and `beacon_anchor_height` fields) routes a slash through the beacon when the equivocation occurred on a shard.

The beacon validates the event by:

1. Reconstructing the shard's committee at `(shard_id, height, beacon_anchor_height)` from its own pool view.
2. Confirming `equivocator` was on that committee.
3. Verifying both `(σ_a, σ_b)` against `pk_equivocator`.

These checks are EXACTLY V11 with the extra step (1). Step (1) doesn't introduce a new false-positive surface: if the beacon's committee derivation differs from the shard's, the equivocator isn't recognized as a member, and the slash doesn't fire. If they agree, the rest of the check is the same as in Theorem T-6.

So the cross-shard slash is sound under the same EUF-CMA bound — `≤ 2⁻¹²⁸` per fabrication attempt — and over polynomially many attempts the probability stays negligible.   ∎

---

## 4. Discussion

### 4.1 Why "no false positives" is the right property

A consensus protocol with overly-aggressive slashing creates the wrong incentives: honest validators face slash risk for honest mistakes (NTP drift, packet loss, brief offline windows). Determ's design carefully distinguishes:

- **Equivocation slash** (this proof, FA6): cryptographic, no false positives. An honest validator can NEVER be slashed for equivocation — the only way they get slashed is if they actually signed two conflicting blocks.
- **Suspension slash** (`SUSPENSION_SLASH = 10`, Preliminaries §1): economic, occurs on round-1 aborts that are baked into the chain. This is a livelihood penalty for unavailability, not for misbehavior. False positives are possible (an honest but slow validator gets suspension-slashed) but bounded in magnitude.

T-6 covers the cryptographic case. The economic case is documented separately in `docs/SECURITY.md` (S-008 considerations around suspension thresholds).

### 4.2 Why the proof needed to be done

The intuition "equivocation requires two signatures, honest validators sign one, so honest never get slashed" is true but underspecified:

- What does "at most one signature" mean across rounds? (H2 ambiguity, resolved in Case (b).)
- What if an adversary harvests an old aborted-round signature? (Subcase b.2.)
- Does the cross-shard variant change the picture? (T-6.1.)

The proof formalizes each of these. The conclusion is the same as the intuition but the bookkeeping is what makes it rigorous.

### 4.3 What the proof does NOT cover

- **Byzantine validator who equivocates and then has a partner forge a legitimate-looking event.** If `v_i` is Byzantine, FA6 doesn't apply — slashing is correct in this case (the validator did equivocate). The theorem is one-sided: it gives soundness, not completeness.
- **Completeness (every actual equivocator gets caught).** A different theorem would prove "all equivocators get slashed." This isn't proved here — it's a livenessproperty (FA4-ish) for the slashing pipeline. In practice, the gossip layer's `EQUIVOCATION_EVIDENCE` propagation + the pending-evidence-pool dedup makes most actual equivocations get caught, but the theorem here is only soundness.
- **Suspension slashing** (round-1 aborts): handled in §4.1 above; not a cryptographic guarantee, just an economic one.

### 4.4 Concrete-security bound

Per the proof, the bound is `2⁻¹²⁸` per forgery attempt under standard EUF-CMA. Polynomial-many attempts give `Q · 2⁻¹²⁸`. For `Q = 2⁶⁰` (a generous adversary budget over the chain's lifetime), the cumulative false-positive probability is `≤ 2⁻⁶⁸` — strongly negligible.

In the post-quantum era under Grover, the bound degrades to roughly `Q · 2⁻⁶⁴` for Ed25519 (quantum-classical), which is still negligible for any operational `Q`.

---

## 5. Implementation cross-reference

| Document | Source |
|---|---|
| `EquivocationEvent` struct (kind + per-side openings; `digest_a`/`digest_b` DELETED) | `include/determ/chain/block.hpp:448` |
| V11 validation (kind gate, height assert, derived-digest verify) | `src/node/validator.cpp:380 check_equivocation_events` |
| Digest compose — `D(0, ·, ·)` / body | `src/node/producer.cpp:968 compose_block_digest` / `:820 compute_block_digest_body` |
| Digest compose — `D(1, ·, ·)` / body | `src/node/producer.cpp:332 compose_contrib_commitment` / `:252 make_contrib_body_root` |
| Wire (GENESIS-DEADLINE) | `src/chain/block.cpp:1301` (`kMinEquivEvent` = 246) + `src/net/binary_codec.cpp:547` (fixed 245 B after the lp_str; gen-bound layout) |
| Gate (falsify-on-mutant, 8 arms) | the EQV block of `determ test-abort-cert-validation`, driven via `check_equivocation_events_for_test` |
| Apply slash (zero stake + deregister) | `src/chain/chain.cpp::apply_transactions` (EquivocationEvent branch) |
| Equivocation detection — BlockSigMsg-level (rev.8) | `src/node/node.cpp::apply_block_locked` (cross-block check when a duplicate-height block arrives with a different `block_hash`) |
| Equivocation detection — ContribMsg same-generation (S-006 closure) | `src/node/node.cpp::on_contrib` (recompute the contrib commitment when a same-signer duplicate arrives at the same `(block_index, prev_hash, aborts_gen)`) |
| Gossip relay | `src/net/gossip.cpp` `EQUIVOCATION_EVIDENCE` message type |
| Cross-shard `shard_id` / `beacon_anchor_height` fields | `EquivocationEvent::shard_id`, `EquivocationEvent::beacon_anchor_height` |
| RPC submission for forensics | `src/node/node.cpp::rpc_submit_equivocation` |

The two detection paths feed the **same** `EquivocationEvent` struct through the **same** V11 validator and the **same** apply path, distinguished only by `kind` and therefore by the outer domain tag (§2.1). An external implementer must wire both paths — missing either leaves an equivocation surface unslashable — and must NOT merge them: a shared tag would make an honest block signature plus an honest contrib signature at one height a valid forgery. PROTOCOL.md §6.1 also flags this two-source requirement.

A reviewer can confirm soundness by:

- Reading `check_equivocation_events` to confirm both signatures are strictly verified.
- Reading the apply-path to confirm slashing is gated on V11 success.
- Confirming the height assert `index_a == index_b == block_index` runs BEFORE signature verification and that both digests are derived, never read from the event (Case (b)).
- Confirming `EquivocationEvent` round / `aborts_gen` tracking is **absent** — slashing is per `(height, kind, key)`, not per `(height, round, kind, key)`. That is the Case (c) residual, not a design conclusion.
- Reading both detection sites (`apply_block_locked` cross-block check and `on_contrib` recompute-then-compare) to confirm both feed the same channel.

---

## 6. Conclusion

T-6 establishes that slashing produces no cryptographic false positives **for an honest validator satisfying H3** (at most one round per height per digest family). The proof is short because the protocol design is clean: V11 strictly verifies both signatures against DERIVED digests, asserts a single height, and discriminates the digest family; EUF-CMA forbids honest-key forgery and SHA-256 preimage resistance forbids re-opening a signature at another height.

The corollary T-6.1 carries the same property cross-chain. Cross-shard slashing inherits soundness from V11's cryptographic checks; the beacon's committee-derivation step doesn't introduce new false-positive surfaces.

Honest validators bear no cryptographic equivocation-slash risk **within H3**. The H3 boundary — same-height cross-round honest double-signing (Case (c)) — is **OPEN and needs owner review**; it is recorded, not argued away. Suspension slashing (economic, not cryptographic) is a separate concern with its own bounded behavior.
