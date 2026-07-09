# Wire-format backward compatibility — unified zero-skip theorem

This document consolidates the four shipped instances of the "zero-skip + (optional) domain-separator" pattern that Determ uses to extend commit / signing primitives without breaking pre-feature peers, and proves a single generalized theorem (T-1..T-3) covering all current and future field additions made under this discipline.

The pattern has shipped four times across v2.1, v2.6 R4 Phase 3, v2.7 F2, and the genesis-hash anchor at v2.7 / S-039's lock-in surface:

1. `partner_subset_hash` in `Block::signing_bytes` (R4 Phase 3 region-aware committee).
2. `state_root` in `Block::signing_bytes` (S-033 + S-038 state Merkle commitment).
3. `view_eq_root` / `view_abort_root` / `view_inbound_root` in `make_contrib_commitment` (v2.7 F2 ContribMsg extension; previously analyzed in `MakeContribCommitmentBackwardCompat.md`).
4. `committee_region` / `genesis_message` / governance fields / suspension knobs / merge thresholds in `compute_genesis_hash` (rev.9 R1 + A5 + R4 backward-compat sequence; the surface that S-039 tracks as a deferred wire-compat-break for the *un*-zero-skipped fields).

Each instance is gated on a syntactic test (all-zero hash, empty string, or default-equality with a constant) that, when true, replays the pre-feature pre-image byte-for-byte. The proof formalizes the generic argument so any future field added under the same discipline inherits the same backward-compat guarantee without re-deriving the cryptography.

**Companion documents.** `Preliminaries.md` (F0) for SHA-256 collision / 2nd-preimage assumptions (A2 / §2.1) and the Ed25519 EUF-CMA bound (A1 / §2.2); `MakeContribCommitmentBackwardCompat.md` (the F2-specific instance of this theorem, with full pre-image-length argument + DTM-F2-v1 replay-defense Corollary T-2.1); `Safety.md` (FA1) for the chain-anchor identity that consumes `Block::signing_bytes`; `Censorship.md` (FA2) for the `tx_root` union commitment that `signing_bytes` transitively binds; `EquivocationSlashing.md` (FA6) for the digest-agnostic V11 mechanism whose pre-image-space disjointness arguments T-2 generalizes; `SECURITY.md` §S-033 / §S-038 / §S-039 for the audit-trail of the four shipped instances.

---

## 1. Theorem statements

**Setup.** Let `P_pre(x)` denote a SHA-256-based commit primitive (signing_bytes, compute_block_digest, make_contrib_commitment, compute_genesis_hash, or any future analogue) over the pre-feature input space `x ∈ X_pre`. Let `P(x, f)` denote the same primitive extended with a new field `f ∈ F` where `F` has a distinguished "default" value `0_F ∈ F` (32-byte zero for `Hash`, empty for `std::string`, or the literal pre-feature value for arbitrary types).

The extension is implemented under the **zero-skip pattern** iff `P(x, f)` is structurally equivalent to:

```cpp
SHA256Builder b;
// ... pre-feature appends derived from x ...
if (f != 0_F) {
    // optional domain-separator prefix:
    b.append("DTM-<TAG>-v1");
    b.append(serialize(f));
}
return b.finalize();
```

That is, the new field contributes zero bytes to the hash pre-image when `f == 0_F`, and exactly `len(domain-tag) + len(serialize(f))` bytes when `f != 0_F`.

**Theorem T-1 (Zero-Skip Backward-Compat).** For every primitive `P(x, f)` implemented under the zero-skip pattern,

$$
\forall x \in X_{pre}, \quad P(x, 0_F) \;=\; P_{pre}(x).
$$

That is, any pre-feature caller invoking `P` without setting `f` (default-initialized to `0_F`) produces a hash byte-identical to the pre-feature primitive's output.

**Corollary (Signature-Compatibility).** For every Ed25519 signature `σ` valid under `P_pre(x)`, `Verify(pk, P(x, 0_F), σ) = Verify(pk, P_pre(x), σ) = 1`. Pre-feature signatures continue to verify under the extended primitive without protocol-version negotiation, mempool-side translation, or wire-version flag-day coordination.

**Theorem T-2 (Domain-Separator Replay Defense).** Suppose the zero-skip pattern additionally prepends a fixed literal domain tag `T ∈ {0,1}^{8t}` (`t` bytes) before serializing `f`. Under SHA-256 collision resistance (A2 / §2.1), for every adversary `A` of polynomial-time complexity producing a pre-image pair `(p_1, p_2)` with `p_1` in the pre-feature family (i.e., `p_1 = serialize_pre(x_1)`) and `p_2` in the f-active family (i.e., `p_2 = serialize_pre(x_2) || T || serialize(f_2)` with `f_2 ≠ 0_F`),

$$
\Pr\!\bigl[\mathrm{SHA256}(p_1) = \mathrm{SHA256}(p_2)\bigr] \;\leq\; 2^{-128} + \mathrm{negl}(\lambda).
$$

That is, the pre-image space for `f`-inactive commits and the pre-image space for `f`-active commits are disjoint, so a signature captured under one shape cannot be replayed under the other except with cryptographically negligible probability.

**Theorem T-3 (Compositional Soundness).** Suppose `N` orthogonal fields `f_1, f_2, …, f_N` are added to the same primitive `P`, each under its own independent zero-skip branch (with or without a domain separator). Then T-1 holds across all `2^N` combinations of which fields are active:

$$
\forall (\mathit{active}_1, …, \mathit{active}_N) \in \{0, 1\}^N, \quad P(x, f_1^{\mathit{active}_1}, …, f_N^{\mathit{active}_N}) \;\text{ depends only on the active fields' values.}
$$

In particular, the "all-zero" combination reproduces `P_pre(x)` byte-for-byte (Corollary of T-1 at the leaf), and any other combination is uniquely determined by the set of active fields' serialized bytes.

---

## 2. Background

### 2.1 The three commit surfaces

Determ's wire format has three SHA-256-backed commit primitives that the protocol's safety + censorship + slashing proofs reference:

- **`Block::signing_bytes`** (`src/chain/block.cpp:235-354`) — the canonical block serialization that the K-of-K committee Ed25519-signs. Binds every consensus-bound block field. FA1 (Safety) treats this as the chain anchor.
- **`Block::compute_hash`** (`src/chain/block.cpp:356-362`) — `SHA256(signing_bytes || sig_1 || … || sig_K)`. The `prev_hash` chain field references this; FA1 + FA6 lift the field-by-field binding into a chain-wide invariant.
- **`make_contrib_commitment`** (`src/node/producer.cpp:219-260`) — the Phase-1 ContribMsg commit primitive each committee member Ed25519-signs. Binds the member's view of block-bound material (tx hashes, dh_input, F2 view roots).
- **`compute_genesis_hash`** (`src/chain/genesis.cpp:429-432`) — a wrapper that computes `make_genesis_block(cfg).compute_hash()`. The genesis block's `cumulative_rand` field (set at `src/chain/genesis.cpp:373-424`) is the actual cumulant point for the protocol-config commitment.

Each surface has its own pre-image structure. Each field added to a surface is added at one specific append site, and the zero-skip pattern decides whether that site is reachable on default-value inputs.

### 2.2 Why backward compatibility matters

The protocol's deployment model is **rolling upgrade across heterogeneous peers**, not flag-day. The wire-protocol's version negotiation (A3) carries a binary-codec version but does not gate field-by-field. Peers exchanging gossip during the pre-activation window of any new feature can be either pre-feature or feature-aware; both must accept each other's messages.

The zero-skip pattern handles this without any version-flag-on-the-wire by ensuring:

1. **Pre-feature peers** (which never set the new field; the field defaults to `0_F`) produce hashes byte-identical to their pre-feature codebase. Other pre-feature peers verify their sigs as before; feature-aware peers verify under the extended primitive but, by T-1, get the same hash.
2. **Feature-aware peers** producing pre-feature-shape commits (e.g., during the pre-activation epoch where `v2_7_f2_active_from_height` hasn't fired) emit `0_F` for the new field and inherit T-1's identity.
3. **Feature-aware peers** producing feature-active commits (post-activation) bind the new field's value into the hash. By T-2, those sigs cannot be replayed under the pre-feature shape, so the "mixed-version replay attack" surface is cryptographically negligible.

The replay defense (T-2) is the load-bearing argument. Without domain separators, an adversary could harvest pre-feature signatures from gossip and try to replay them in post-activation rounds against forged feature-active fields. The domain tag forces the pre-image to begin with a fixed literal that doesn't occur as a tail of the pre-feature pre-image (length-distinguishing argument; see `MakeContribCommitmentBackwardCompat.md` §3 Lemma L-3 for the worked-example length-mismatch proof at 104 vs 209 bytes).

### 2.3 Where the pattern has shipped

The four shipped instances are at:

| Instance | Primitive | Field(s) | Site | Zero-test |
|---|---|---|---|---|
| (1) R4 Phase 3 | `Block::signing_bytes` | `partner_subset_hash` | `block.cpp:329-334` | `partner_subset_hash != Hash{}` |
| (2) S-033 + S-038 | `Block::signing_bytes` | `state_root` | `block.cpp:345-350` | `state_root != Hash{}` |
| (3) v2.7 F2 | `make_contrib_commitment` | `view_eq_root`, `view_abort_root`, `view_inbound_root` | `producer.cpp:242-258` | `any_view = !is_zero_hash(...)` |
| (4) rev.9 R1 / A5 / R4 | `compute_genesis_hash` | `committee_region`, `genesis_message`, governance fields, suspension knobs, merge thresholds | `genesis.cpp:378-423` | per-field default-equality |

A fifth instance — `GenesisAlloc::region` in `signing_bytes`'s `initial_state` loop — is structurally identical (variable-length empty-string default at `block.cpp:317-320`). All five are covered by T-1 + T-3.

S-039 tracks the *unbinded* genesis fields (`m_creators`, `k_block_sigs`, `block_subsidy`, etc.) — those that should be bound but are not. The fix for S-039 is deferred as a wire-compat-break specifically because adding them is *not* a zero-skip extension: a non-zero-skipped add changes every existing chain's `genesis_hash` regardless of default values, breaking the very property T-1 establishes. The maintenance discipline §6 calls out is: future field additions MUST go through zero-skip, OR explicitly accept the wire-compat break.

---

## 3. Implementation pattern audit

### 3.1 partner_subset_hash (R4 Phase 3)

At `src/chain/block.cpp:323-334`:

```cpp
// R4 Phase 3: bind partner_subset_hash into block signing-bytes
// ONLY when non-zero. Default zero-hash preserves byte-identical
// signing bytes for all pre-R4 / non-merged blocks — every existing
// test stays hash-stable. Non-zero binds the partner shard's tx
// subset commitment into the K-of-K committee signature, closing
// the cross-chain merged-signing path described in the R4 design.
{
    Hash zero{};
    if (partner_subset_hash != zero) {
        b.append(partner_subset_hash);
    }
}
```

The append-site is bare (no domain tag prepended). Backward compat for the field is established by T-1's branch-skip identity. Replay defense is established structurally by the field's deterministic derivation from merge state (F2-SPEC.md §Q1: "Deterministic from merge state — Computed identically on every honest node from the chain's `merge_state` at this height"). Because the field's value at any given height is a public function of the chain's `merge_state` at that height, there is no adversary-controlled distinction between "zero" and "non-zero" pre-images at the producer; the validator re-derives and rejects mismatches. T-2 still applies trivially (different bytes → different SHA-256 outputs by L-2 of `MakeContribCommitmentBackwardCompat.md`).

### 3.2 state_root (S-033 + S-038)

At `src/chain/block.cpp:336-350`:

```cpp
// S-033 / v2.1: bind state_root into the block hash chain ONLY when
// non-zero. Same backward-compat pattern as partner_subset_hash —
// pre-S-033 blocks have zero state_root and contribute nothing to
// signing_bytes. When the producer populates it (post-feature-toggle),
// the K-of-K committee signatures cover the state-after-apply
// commitment. Validator re-derives and rejects on mismatch. The
// prev_hash chain then forward-binds the commitment so any future
// block's verification transitively authenticates all prior state
// roots — turning the chain into a verifiable state log.
{
    Hash zero{};
    if (state_root != zero) {
        b.append(state_root);
    }
}
```

Identical structural pattern to §3.1: bare append-site, branch-skipped on default zero. The S-033 gate at `Chain::apply_transactions` (chain.cpp:~1430) checks the locally-recomputed root against `b.state_root`; pre-S-038 the producer never populated it, leaving the gate dormant — S-038 closed that by populating `body.state_root` from a tentative-chain dry-run between `build_body` and `apply_block_locked` (see `SECURITY.md` §S-038). The backward-compat shim itself (the `if (b.state_root != zero)` branch in the validator gate) is the apply-side mirror of T-1's producer-side branch: pre-S-033 blocks must continue to load/replay under the extended chain code without modification.

### 3.3 view_eq_root / view_abort_root / view_inbound_root (v2.7 F2)

At `src/node/producer.cpp:242-258`:

```cpp
auto is_zero_hash = [](const Hash& h) {
    for (auto byte : h) if (byte != 0) return false;
    return true;
};
bool any_view = !is_zero_hash(view_eq_root)
             || !is_zero_hash(view_abort_root)
             || !is_zero_hash(view_inbound_root);
if (any_view) {
    // Domain separator: prepend the F2 schema tag so an attacker
    // can't construct a v2-shaped pre-image that hashes to a v1
    // commit value (and vice versa).
    b.append(std::string("DTM-F2-v1"));
    b.append(view_eq_root);
    b.append(view_abort_root);
    b.append(view_inbound_root);
}
return b.finalize();
```

This is the canonical "T-1 + T-2 fully applied" instance: the 9-byte `"DTM-F2-v1"` literal is the domain separator, and the OR-condition is the multi-field generalized zero-test. The full theorem set (T-1, T-2, Corollary T-1.1 signature compat, Corollary T-2.1 v1-sig non-replayability under F2 envelope) is proved in `MakeContribCommitmentBackwardCompat.md` against the worked-example pre-image lengths (104 bytes v1, 209 bytes F2). The generalized theorem here lifts that worked example to the abstract pattern.

The companion ContribMsg JSON emission (`producer.cpp:36-65`) extends the pattern to **variable-length lists**: the three `view_*_list` fields are emitted only when at least one root is non-zero OR at least one list is non-empty (the `has_view` predicate at line 44-50). This is the natural extension of zero-skip to variadic emission: an empty list is the default-value witness; emission of `{view_eq_list: [], view_abort_list: [], view_inbound_list: []}` would not be byte-identical to the pre-F2 JSON (which omits these keys entirely), so the predicate gate is necessary.

### 3.4 compute_genesis_hash (rev.9 R1 / A5 / R4)

At `src/chain/genesis.cpp:378-423`, five distinct field groups are added under zero-skip:

```cpp
if (!cfg.committee_region.empty()) {
    rb.append(static_cast<uint8_t>(cfg.committee_region.size()));
    rb.append(cfg.committee_region);
}
// ...
if (cfg.genesis_message != DEFAULT_GENESIS_MESSAGE) {
    rb.append(static_cast<uint64_t>(cfg.genesis_message.size()));
    rb.append(cfg.genesis_message);
}
// ...
if (cfg.governance_mode != 0 || !cfg.param_keyholders.empty()) {
    rb.append(static_cast<uint8_t>(cfg.governance_mode));
    rb.append(static_cast<uint8_t>(cfg.param_keyholders.size()));
    for (auto& k : cfg.param_keyholders)
        rb.append(k.data(), k.size());
    rb.append(static_cast<uint64_t>(cfg.param_threshold));
}
if (cfg.suspension_slash != 10 || cfg.unstake_delay != 1000) {
    rb.append(cfg.suspension_slash);
    rb.append(cfg.unstake_delay);
}
if (cfg.merge_threshold_blocks  != 100
    || cfg.revert_threshold_blocks != 200
    || cfg.merge_grace_blocks   != 10) {
    rb.append(static_cast<uint64_t>(cfg.merge_threshold_blocks));
    rb.append(static_cast<uint64_t>(cfg.revert_threshold_blocks));
    rb.append(static_cast<uint64_t>(cfg.merge_grace_blocks));
}
```

Each branch is independent (no cross-field domain tag). T-3 (compositional soundness) is the load-bearing argument for this site: five orthogonal zero-skip extensions, `2^5 = 32` combinations of which fields are active, every combination producing a uniquely determined pre-image. The "all-default" combination reproduces the pre-rev.9 / pre-A5 / pre-R4 `compute_genesis_hash` output byte-for-byte — `tools/test_genesis.sh` locks this in with explicit `expect == base_hash` assertions for each field's default value (S-035 Option 1 seed; see `SECURITY.md` §S-039).

A worked example: a chain configured with `committee_region="us-east"` and all other fields at default produces the same `genesis_hash` as one identical except `committee_region=""` *only if both have everything else at default*. Adding a non-default `genesis_message` to either changes both their hashes independently — T-3 guarantees no cross-field contamination because each branch's appends are wholly contained within its own `if`.

The unbinded fields S-039 tracks (`m_creators`, `k_block_sigs`, `block_subsidy`, …) are NOT bound under any zero-skip branch — they're not bound at all. Adding them is a wire-compat break by definition, because the protocol cannot tell a pre-binding chain's hash from a post-binding chain's hash on the same config. T-1 cannot rescue an add that fails to provide a zero-skip default-equality predicate; this is the inherent maintenance constraint.

---

## 4. Proofs

### Proof of T-1 (Zero-Skip Backward-Compat)

By construction. The zero-skip pattern is defined as:

```cpp
if (f != 0_F) { b.append(serialize(f)); }
```

If `f == 0_F`, the `if`-body is unreachable. The remaining live appends are exactly the pre-feature surface `P_pre(x)`. By determinism of `SHA256Builder` (Lemma L-2 of `MakeContribCommitmentBackwardCompat.md`: `EVP_DigestUpdate` is byte-order-bound, append-sequence-bound), the two builders consume identical byte sequences and produce identical `finalize()` outputs. Therefore `P(x, 0_F) = P_pre(x)`. ∎

**Proof of Corollary (Signature-Compatibility).** Ed25519 `Verify(pk, m, σ)` is a deterministic function of `(pk, m, σ)` (RFC 8032). If `σ = Sign(sk, P_pre(x))` then `Verify(pk, P_pre(x), σ) = 1`. By T-1, `P(x, 0_F) = P_pre(x)`, so `Verify(pk, P(x, 0_F), σ) = Verify(pk, P_pre(x), σ) = 1`. ∎

### Proof of T-2 (Domain-Separator Replay Defense)

Fix any pre-feature input `x_1 ∈ X_pre` and any feature-active input `(x_2, f_2)` with `f_2 ≠ 0_F`. The two pre-images supplied to SHA-256 are:

```
p_1 = serialize_pre(x_1)                                          // pre-feature shape
p_2 = serialize_pre(x_2) || T || serialize(f_2)                   // feature-active shape (T = domain tag)
```

By the construction of `serialize_pre` (every byte determined by `x_*`'s typed fields) and the literal-bytes nature of `T`, `p_2`'s length strictly exceeds `p_1`'s length by `|T| + |serialize(f_2)|` bytes. Since `|T| ≥ 1` and `|serialize(f_2)| ≥ 1` (no zero-byte serialization for a non-default value under any of the four shipped instances), `len(p_1) ≠ len(p_2)`.

SHA-256's Merkle-Damgård length padding (FIPS 180-4 §5.1) folds the bit-length of the input into the final compression block. Two messages of distinct length produce byte-distinct inputs to the final compression call. By SHA-256 collision resistance (A2 / §2.1), `Pr[SHA256(p_1) = SHA256(p_2)] ≤ 2^-128` over any polynomial-time adversary's choice of `(x_1, x_2, f_2)`.

The adversary cannot adjust `serialize_pre(x_2)` to compensate for the length mismatch because the pre-feature serialization has no length-variability surface at any of the four shipped instances (each `serialize_pre` component is a fixed-width type or a length-prefixed variable-length type — see Preliminaries §1.3). Therefore the bound holds uniformly across the adversary's input choices. ∎

**Note (no-tag case).** For instances 1 and 2 (`partner_subset_hash`, `state_root`) the implementation omits the domain tag because the field's value is deterministic from chain state (validator re-derives and rejects mismatch). T-2 still holds in the weaker form `Pr[P_pre(x_1) = P(x_2, f_2)] ≤ 2^-128` per the same length-distinguishing argument: appending a non-zero 32-byte field extends the pre-image by exactly 32 bytes, so lengths differ by 32 and the Merkle-Damgård length padding argument applies. The domain tag is defense-in-depth for the case where the field's value is adversary-controlled (instance 3: F2 view roots); for deterministic fields, the validator-side re-derivation is the load-bearing defense and the cryptographic length argument is sufficient on its own.

### Proof of T-3 (Compositional Soundness)

By induction on `N`.

*Base case `N = 1`:* exactly T-1.

*Inductive step:* assume T-1 + T-3 hold for any `(N-1)`-field extension. Consider an `N`-field extension `P(x, f_1, …, f_N)` with each `f_i` under its own independent zero-skip branch. Let `P'(x, f_1, …, f_{N-1})` denote the `(N-1)`-field extension obtained by collapsing `f_N` into its default value `0_{F_N}`. By T-1 applied at the `f_N` site, `P(x, f_1, …, f_{N-1}, 0_{F_N}) = P'(x, f_1, …, f_{N-1})` for any choice of `f_1, …, f_{N-1}`. By the inductive hypothesis applied to `P'`, the `2^{N-1}` combinations of `(f_1, …, f_{N-1})` activity all preserve T-1 at the leaf. By T-1 applied independently at each `f_i` site, every combination's pre-image is uniquely determined by the set of active fields' serialized bytes. The "all-default" combination collapses every branch and reproduces `P_pre(x)`. ∎

**Note on orthogonality.** The independence assumption is essential: T-3 requires that no field's zero-test depends on another field's value. All four shipped instances satisfy this (each branch's test is a syntactic check on one named field, with the F2 OR-condition being a degenerate case where the *same* three fields are tested together and form a single effective field "any-view"). A future field-add that, e.g., conditions on the previous block's `state_root` value would violate orthogonality and require a separate proof.

---

## 5. Corollaries

### C-1 (partner_subset_hash backward compat)

By T-1 applied at `src/chain/block.cpp:329-334`: every block produced by a pre-R4 codebase (where `partner_subset_hash` is default-zero) has `signing_bytes` byte-identical under pre-R4 and post-R4 code. Every non-merged block produced by a post-R4 codebase (where `partner_subset_hash` is still default-zero by structural absence of merge state) inherits the same identity. R4-merged blocks (non-zero `partner_subset_hash`) form a disjoint pre-image space by T-2 (no-tag form; length argument gives `≤ 2^-128` collision bound). ∎

### C-2 (state_root backward compat)

By T-1 applied at `src/chain/block.cpp:345-350`: every pre-S-033 block (with default-zero `state_root`) has `signing_bytes` byte-identical under pre-S-033 and post-S-038 code. Pre-S-038 blocks produced under post-S-033 code (where the field is declared but the producer didn't populate it) also have default-zero `state_root` and inherit the same identity — this is precisely why S-038 needed to be a separate closure (the gate was dormant because the producer's pre-S-038 path silently kept the field zero). Post-S-038 blocks (non-zero `state_root`) form a disjoint pre-image space by T-2 (no-tag form). ∎

### C-3 (F2 view-root backward compat)

By T-1 + T-2 applied at `src/node/producer.cpp:242-258`: every pre-F2 ContribMsg (with all three view roots default-zero) has `make_contrib_commitment` output byte-identical under pre-F2 and post-F2 code (T-1). Every post-F2 ContribMsg with at least one non-zero view root forms a disjoint pre-image space by T-2 (with-tag form; `"DTM-F2-v1"` literal forces a 9+96 = 105-byte length extension, 104 → 209 byte mismatch). The full worked-example proof, including the L-3 length argument and the Corollary T-2.1 v1-sig non-replayability under F2 envelope, is in `MakeContribCommitmentBackwardCompat.md` §3-§5. ∎

---

## 6. Risks and maintenance discipline

The zero-skip pattern is sound but **not robust to careless extension**. Three failure modes future contributors must avoid:

**R-1 (non-zero-skip add).** Adding a field to a commit primitive without a zero-test silently changes every existing chain's hash. The only outward symptom is "every test's expected hash is wrong" — easy to notice at PR review, but easy to miss if the new field is also being added to the test fixtures in the same commit. The S-039 unbinded-fields situation is the canonical example: adding `m_creators` to `compute_genesis_hash` would change every chain's `genesis_hash` regardless of whether the chain ever used a non-default `m_creators`, breaking T-1 by construction. **Discipline:** every new commit-primitive field MUST go through zero-skip, OR the PR description MUST explicitly call out the wire-compat-break and the migration plan.

**R-2 (orthogonality violation).** Adding a field whose zero-test depends on another field's value (e.g., `if (state_root != zero && partner_subset_hash != zero) b.append(...)`) breaks T-3's independence assumption. The `2^N` combinations are no longer uniquely determined by the set of active fields. **Discipline:** every new field's zero-test MUST be a syntactic check on that field alone, OR the PR MUST add a corresponding proof variant.

**R-3 (forgotten domain tag).** Adding an adversary-controlled field without a domain tag preserves T-1 but weakens T-2: the length-distinguishing argument still applies for pure length mismatches, but if the adversary can also control the pre-feature-shape input to match the post-feature pre-image's length-modulo-block, the SHA-256 padding argument becomes less crisp. The four shipped instances handle this correctly: deterministic fields (instances 1, 2) skip the tag because validator re-derivation is the primary defense; adversary-controlled fields (instance 3) include the tag. **Discipline:** every new field whose value is *not* deterministic from public chain state MUST prepend a unique `"DTM-<TAG>-v<N>"` literal, where `<TAG>` is the field's purpose-name and `<N>` is the version (incremented if the field's serialization changes).

**R-4 (variable-length serialization with empty default).** Variable-length fields (`std::string`, `std::vector<Hash>`) need their zero-test to map "empty" to the same pre-image as "absent." The `region` field at `block.cpp:317-320` does this correctly (`if (!a.region.empty())` skips both length prefix and bytes; an empty region contributes zero bytes). The `genesis_message` field at `genesis.cpp:382-395` extends this to "default-equality" (empty vs default-message both produce different hashes — empty is intentional override, default-message is intentional pre-feature). **Discipline:** the zero-test predicate MUST be chosen to match the desired equivalence class; the comment at the append site MUST state which inputs collapse to which output.

The `tools/test_genesis.sh` regression and `tools/test_block_hash.sh` regression together exercise R-1 + R-4 across every shipped instance: any future commit that silently changes the pre-feature hash of any default-config chain or any zero-state block fails these tests immediately. This is the operational backstop for the maintenance discipline above.

---

## 7. Composition with FA2 (Censorship) and FA6 (Equivocation Slashing)

The zero-skip pattern preserves the pre-feature safety + censorship + slashing proofs because the pre-feature pre-image space is unchanged:

**FA2 (Censorship)** rests on the `tx_root` union commitment binding every mempool tx that any honest member observes (Censorship.md §3). The `tx_root` field's position in `signing_bytes` (at `block.cpp:257`) is unaffected by any of the four shipped instances — all four extensions happen *after* `tx_root` is appended, so the tx-root pre-image is byte-identical pre- and post-extension. By T-1, the pre-feature tx-root binding's collision-resistance argument carries over unchanged. The censorship-resistance bound `(f / N)^K` (FA2 Theorem T-1) is independent of the trailing field-additions.

**FA6 (Equivocation Slashing)** rests on the digest-agnostic V11 mechanism: an honest validator never signs two distinct `compute_block_digest` values at the same height-round (H2 in Preliminaries §4). The S-006 closure extended detection to the `ContribMsg` Phase-1 layer (same-generation duplicate detection). Both detection paths use the *full* signed pre-image — for V11, that's `Block::signing_bytes`; for S-006, that's `make_contrib_commitment`. T-1 guarantees that pre-feature and post-feature pre-images coincide on default-value inputs, so an honest pre-feature signer is provably distinct from a feature-aware signer's distinct-pre-image signature only when the feature is *actually active* (some field non-default). Within the same activation state (both pre-feature OR both feature-active with the same field values), the equivocation-detection invariant H2 reduces to the pre-feature invariant, which FA6 already proves. T-2 ensures the cross-activation pre-image spaces are disjoint, so an honest signer is *never* mistakenly flagged as equivocating across the activation boundary (the two sigs are over different pre-images, which is the *opposite* of equivocation by V11's definition).

In summary: T-1 preserves the pre-feature safety surface unchanged; T-2 preserves the disjoint-witness property that FA6's H2 honest-behavior axiom relies on. No FA2 / FA6 / FA1 / FA5 conclusion needs to be re-derived under the extended primitive, because none of those proofs depends on the *absolute* pre-image structure — they all depend on the *relative* property "two distinct calls of the primitive on distinct inputs produce distinct outputs," which T-1 + T-2 jointly establish across the activation boundary.

---

## 8. Status

**Shipped (analytic).** This document consolidates four already-shipped wire-format extensions under a single theorem set. No code changes are introduced by this proof; it is an audit-trail companion to the four implementation sites already cited in `SECURITY.md` (§S-033, §S-038, §S-039) and `PROTOCOL.md` (§4.1.1, §4 block-field table).

The F2-specific instance is fully covered by `MakeContribCommitmentBackwardCompat.md` (the worked-example proof against the 104-byte v1 / 209-byte F2 pre-image lengths). This document lifts that worked example to the abstract pattern (T-1 + T-2 + T-3) so future field-adds inherit the proof without re-derivation.

The cross-reference structure is:

- `MakeContribCommitmentBackwardCompat.md` — the instance-specific proof for F2 (Corollary C-3 here).
- `WireFormatBackwardCompat.md` (this document) — the generalized theorem.
- `SECURITY.md` §S-039 — the maintenance-discipline backstop for future unbinded-field cases.
- `tools/test_genesis.sh` + `tools/test_block_hash.sh` — the operational regression that catches R-1 + R-4 violations.

A hypothetical next field-add under this discipline was the v2.10 threshold-randomness commitment (per the since-de-scoped-and-deleted `v2.10-DKG-SPEC.md`; the example stays illustrative only): the per-epoch DKG output would become a new `Block::signing_bytes` field, gated on `if (epoch_threshold_pubkey != Point{})`. The proof above generalizes to that case without modification.

---

## 9. References

- `src/chain/block.cpp:235-354` — `Block::signing_bytes` definition (the primary object for instances 1, 2, and the `region` variant at lines 317-320).
- `src/chain/block.cpp:329-334` — `partner_subset_hash` zero-skip branch (instance 1, Corollary C-1).
- `src/chain/block.cpp:345-350` — `state_root` zero-skip branch (instance 2, Corollary C-2).
- `src/node/producer.cpp:219-260` — `make_contrib_commitment` definition with F2 zero-skip + DTM-F2-v1 domain tag (instance 3, Corollary C-3).
- `src/node/producer.cpp:36-65` — `ContribMsg::to_json` view-list zero-skip (instance 3 JSON variant; emits view-list keys only when at least one root non-zero or list non-empty).
- `src/chain/genesis.cpp:373-424` — `make_genesis_block`'s `cumulative_rand` construction with five orthogonal zero-skip branches (instance 4, T-3 in action).
- `src/crypto/sha256.cpp:25-45` — `SHA256Builder::append` + `finalize` backing the cryptographic determinism argument (Lemma L-2 of `MakeContribCommitmentBackwardCompat.md`).
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` — F2-specific instance with worked-example length argument (this document's Corollary C-3 incorporates by reference).
- `docs/proofs/Preliminaries.md` §1.3 (hash + serialization conventions), §2.1 (SHA-256 collision + 2nd-preimage resistance — A2), §2.2 (Ed25519 EUF-CMA — A1).
- `docs/proofs/F2-SPEC.md` §Q1 — the per-field reconciliation table that classifies `partner_subset_hash` as "Deterministic from merge state" (the no-tag justification in §3.1).
- `docs/proofs/S030-D2-Analysis.md` §3.5 — the apply-layer + consensus-layer dual closure of S-030 D2, with `state_root` (S-033 + S-038) covering apply-layer and F2 covering consensus-layer.
- `docs/SECURITY.md` §S-033 — Block.state_root + signing_bytes binding (instance 2).
- `docs/SECURITY.md` §S-038 — producer-side state_root population that activated the dormant S-033 gate (instance 2 supporting closure).
- `docs/SECURITY.md` §S-039 — the genesis-hash unbinded-fields gap; the canonical example of a non-zero-skip add (the deferred fix). Locked in by `tools/test_genesis.sh`.
- `docs/PROTOCOL.md` §4.1 (signing_bytes notes), §4.1.1 (state_root algorithm), §4 block-field table (partner_subset_hash + state_root conditional-binding notes).
- `tools/test_block_hash.sh` + `tools/test_genesis.sh` — operational regressions that pin the byte-identity of pre-feature hashes under post-feature code (R-1 + R-4 backstop in §6).
- NIST FIPS 180-4 (Secure Hash Standard) §5.1, §6.1.2 — SHA-256 padding + compression function definitions used in T-2's length-distinguishing argument.
- RFC 8032 (Edwards-Curve Digital Signature Algorithm) — Ed25519 verify spec used in Corollary (Signature-Compatibility) of T-1.
