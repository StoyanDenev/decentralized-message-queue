# MakeContribCommitment — v1 byte-identity + DTM-F2-v1 replay defense

This document formalizes two paired properties of the v2.7 F2 extension to `make_contrib_commitment` shipped in `src/node/producer.cpp:219-260`:

1. **(T-1) v1 backward compatibility.** Callers that omit the three trailing F2 view-root arguments (or pass all-zero `Hash{}` defaults) produce a hash byte-identical to what the pre-F2 (v1) implementation produced. Pre-F2 ContribMsg signatures continue to verify under the extended primitive without modification.
2. **(T-2) DTM-F2-v1 replay defense.** A signature produced under the v1 commit shape (no DTM-F2-v1 tag, no view roots) cannot be replayed under any F2 commit shape with at least one non-zero view root, and vice versa. The two pre-image families are syntactically disjoint, so by SHA-256 collision resistance they hash to disjoint output sets except with negligible probability.

The proof is short and structural: the extension is gated on a single all-zero-views short-circuit, and the F2 branch is unambiguously prefixed with a 9-byte literal domain tag that cannot occur as a prefix of any v1 pre-image. The proof exists to make that argument explicit so an external reviewer can confirm — without re-running the test suite — that the F2 wire change is safe to ship into a mixed-version peer set.

**Companion documents:** `Preliminaries.md` (F0) for notation and the cryptographic assumptions A1 (Ed25519 EUF-CMA) and A2 / §2.1 (SHA-256 collision + 2nd-preimage resistance); `F2-SPEC.md` §Q4 for the design decision to extend `make_contrib_commitment` rather than introduce a separate `make_contrib_commitment_v2`; `S030-D2-Analysis.md` for the surrounding D2-closure story (this proof covers the wire/commit-binding step F2-SPEC.md §Q4 calls out, not the validator-side V21..V26 reconciliation which `F2-SPEC.md` §Q5 + §Q7 handles).

---

## 1. Theorem statements

**Setup.** Let `mcc_v1(idx, prev, txs, dh)` denote the conceptual pre-F2 implementation of the commit primitive: an `SHA256Builder` fed with `block_index || prev_hash || inner_root(txs) || dh_input` followed by `finalize()`. Let `mcc_v2(idx, prev, txs, dh, eq, abort, in)` denote the shipped implementation at `src/node/producer.cpp:219-260`, with the trailing three view-root parameters defaulted to `Hash{}` (32 zero bytes) per the header declaration at `include/determ/node/producer.hpp:134-139`. Let `inner_root(txs) := SHA256(txs[0] || txs[1] || … || txs[n-1])` over the sorted-and-deduped list as documented in `Preliminaries.md` §1.3.

Define the v1 pre-image prefix `pre_v1(idx, prev, txs, dh) := serialize(idx) || prev || inner_root(txs) || dh` and the F2 pre-image extension `ext_F2(eq, abort, in) := "DTM-F2-v1" || eq || abort || in` (concatenated raw bytes).

**Theorem T-1 (v1 byte-identity).** For every call `mcc_v2(idx, prev, txs, dh, Hash{}, Hash{}, Hash{})`,

$$
\mathrm{mcc\_v2}(\mathit{idx}, \mathit{prev}, \mathit{txs}, \mathit{dh}, \mathbf{0}, \mathbf{0}, \mathbf{0}) \;=\; \mathrm{mcc\_v1}(\mathit{idx}, \mathit{prev}, \mathit{txs}, \mathit{dh}).
$$

**Corollary T-1.1 (signature compatibility).** Any Ed25519 signature `σ` valid under `mcc_v1(...)` is valid under `mcc_v2(..., Hash{}, Hash{}, Hash{})`. Pre-F2 ContribMsg signatures gossiped into an F2-deployed peer continue to verify without protocol-version negotiation.

**Theorem T-2 (DTM-F2-v1 replay defense).** Under the SHA-256 collision-resistance assumption A2 (`Preliminaries.md` §2.1), for every adversary `A` of polynomial-time complexity producing a pre-image pair `(p_1, p_2)` with `p_1` in the v1 family (i.e., `p_1 = pre_v1(idx_1, prev_1, txs_1, dh_1)` for some inputs) and `p_2` in the F2 family (i.e., `p_2 = pre_v1(idx_2, prev_2, txs_2, dh_2) || ext_F2(eq_2, abort_2, in_2)` for some inputs with at least one of `eq_2, abort_2, in_2` non-zero),

$$
\Pr\!\bigl[\mathrm{SHA256}(p_1) = \mathrm{SHA256}(p_2)\bigr] \;\leq\; 2^{-128} + \mathrm{negl}(\lambda).
$$

**Corollary T-2.1 (v1-sig non-replayability under F2 envelope).** An adversary holding `σ_v1 = Sign(sk, mcc_v1(idx, prev, txs, dh))` cannot, except with negligible probability, present `σ_v1` as a valid signature on `mcc_v2(idx', prev', txs', dh', eq, abort, in)` for any choice of inputs with at least one of `eq, abort, in` non-zero. Symmetrically: an F2 signature is not replayable as a v1-shape commit.

---

## 2. Background

The motivation for this commit-binding change is `F2-SPEC.md` §Q4 ("Phase-1 commit binding scope"): F2 view reconciliation requires that each committee member's Phase-1 commit Ed25519 signature bind the member's view of three pool-fed pending lists (`pending_equivocation_evidence_`, `pending_abort_events_`, `pending_inbound_receipts_`). The design decision was to extend the existing `make_contrib_commitment` rather than introduce a separate primitive — a single sig over a composite digest is cheaper than three separate sigs, and the extended hash structure preserves per-field auditability.

The backward-compat requirement is operational. F2 activation is gated by a per-genesis `v2_7_f2_active_from_height` knob (cited in `include/determ/node/producer.hpp:46`). For all heights below the activation threshold, the producer is required to emit ContribMsg with zero view roots and empty view lists (per `F2-SPEC.md` §Q2 + `include/determ/node/producer.hpp:322-324`). During the pre-activation phase, an F2-aware peer must be able to (a) emit a ContribMsg that still verifies under v1 verifiers, and (b) accept ContribMsg from v1 peers without protocol-version negotiation. T-1 covers both.

The replay-defense story (T-2) is the standard domain-separation argument: without an explicit version tag, a malicious peer could harvest a v1 signature `σ_v1` from a pre-activation contrib and replay it post-activation as if it bound a specific F2 view (chosen by the attacker). The attacker would need to find inputs `(eq, abort, in)` such that the F2-shape pre-image hashes to the same value as the v1 pre-image — without domain separation, the only thing preventing this is "luck under SHA-256 collision resistance," and the attacker has unbounded freedom to choose `(eq, abort, in)`. The `"DTM-F2-v1"` tag eliminates the choice space by forcing the F2 pre-image to begin with a fixed 9-byte literal that does not occur as a tail of the v1 pre-image.

---

## 3. Lemmas

### Lemma L-1 (all-zero short-circuit reproduces v1 byte-for-byte)

When `view_eq_root`, `view_abort_root`, `view_inbound_root` are all the 32-zero `Hash{}` value, the executed code path at `src/node/producer.cpp:219-260` is structurally:

```cpp
// Lines 225-227
SHA256Builder inner;
for (auto& h : sorted_tx_hashes) inner.append(h);
Hash inner_root = inner.finalize();

// Lines 229-233
SHA256Builder b;
b.append(block_index);
b.append(prev_hash);
b.append(inner_root);
b.append(dh_input);

// Lines 242-248 evaluate any_view = false
// Lines 249-258 are skipped (the if-body)
// Line 259
return b.finalize();
```

The `is_zero_hash` lambda at `producer.cpp:242-245` returns true for the default `Hash{}` (which `include/determ/types.hpp` defines as `std::array<uint8_t, 32>{}` — value-initialized to all zero per `[array.cons]` + `[dcl.init.aggr]`). Therefore `any_view` at `producer.cpp:246-248` evaluates to `(false || false || false) = false`, and the `if (any_view)` body at `producer.cpp:249-258` is unreachable. The remaining live appends are exactly the four-step prefix `(block_index || prev_hash || inner_root || dh_input)` that `mcc_v1` would have computed.    □

### Lemma L-2 (SHA256Builder is deterministic, append-order-bound, content-bound)

The OpenSSL EVP backing at `src/crypto/sha256.cpp:25-28`

```cpp
SHA256Builder& SHA256Builder::append(const uint8_t* data, size_t len) {
    EVP_DigestUpdate(impl_->ctx, data, len);
    return *this;
}
```

forwards directly to `EVP_DigestUpdate`, which by NIST FIPS 180-4 §6.1.2 incorporates each byte into the message schedule in the order received. Two `SHA256Builder` instances seeded with identical sequences of `append(...)` calls produce identical outputs from `finalize()` (`src/crypto/sha256.cpp:40-45`). Conversely, any two pre-images differing in any byte (including length, since SHA-256's Merkle–Damgård length padding folds the bit-length into the final block) produce inputs to `EVP_DigestFinal_ex` that are byte-distinct, and by collision-resistance (A2 / §2.1) produce distinct hash outputs except with probability ≤ 2⁻¹²⁸.

The integer `append` helpers at `src/crypto/sha256.cpp:30-38` serialize `uint64_t` big-endian (matching `Preliminaries.md` §1.3) and reuse the byte-stream `append`, so integer inputs commute with the byte-stream determinism argument above.    □

### Lemma L-3 (the "DTM-F2-v1" tag does not occur as a tail of any v1 pre-image)

Define `T := "DTM-F2-v1"` (9 ASCII bytes: `0x44 0x54 0x4D 0x2D 0x46 0x32 0x2D 0x76 0x31`). Define a v1 pre-image as a byte sequence of the form

```
pre_v1 = serialize(idx) || prev || inner_root || dh
       = (8 bytes BE u64) || (32 bytes) || (32 bytes) || (32 bytes)
       = 104 bytes total
```

The total length of any v1 pre-image is exactly 104 bytes — a fixed-size, structurally typed concatenation with no length-variability surface (each component has a fixed byte width per `Preliminaries.md` §1.3 + `Hash := std::array<uint8_t, 32>`). The F2-branch pre-image at `producer.cpp:249-258` adds `T || eq || abort || in`, contributing `9 + 32 + 32 + 32 = 105` bytes, for a total F2 pre-image length of `104 + 105 = 209` bytes.

By length alone, `len(pre_v1) = 104 ≠ 209 = len(pre_F2)`, and SHA-256's Merkle–Damgård length-encoding folds the bit-length of the input into the final compression block. Two messages of distinct length produce byte-distinct inputs to the final compression call, hence by L-2 + A2 hash to distinct outputs except with probability ≤ 2⁻¹²⁸.

The length-distinguishing argument is sufficient on its own; the explicit 9-byte `"DTM-F2-v1"` literal is a defense-in-depth marker that makes the disjoint-pre-image-space argument structurally evident to a reviewer who is not tracking lengths.    □

### Lemma L-4 (SHA-256 collision bound → distinct pre-images map to distinct hashes)

By A2 / `Preliminaries.md` §2.1 (collision resistance), no polynomial-time adversary finds `x, y` with `x ≠ y` and `SHA256(x) = SHA256(y)` with probability non-negligibly better than `2⁻¹²⁸`. By L-3, every v1 pre-image and every F2 pre-image differ in byte-length (104 vs 209), hence differ as byte sequences. Composing L-2 with A2:

$$
\Pr\!\bigl[\mathrm{SHA256}(\mathit{pre\_v1}) = \mathrm{SHA256}(\mathit{pre\_F2})\bigr] \;\leq\; 2^{-128}.
$$

The bound holds for any specific pair. Over polynomially many adversary attempts `Q`, the cumulative bound is `Q · 2⁻¹²⁸`, which remains negligible for any operational `Q` (e.g., `Q = 2⁶⁰` ⇒ cumulative `≤ 2⁻⁶⁸`).    □

---

## 4. Proof of T-1 (v1 byte-identity)

Fix any v1 caller input `(idx, prev, txs, dh)`. Both `mcc_v1(idx, prev, txs, dh)` and `mcc_v2(idx, prev, txs, dh, Hash{}, Hash{}, Hash{})` execute the following sequence:

1. Build `inner_root` over `txs` (lines 225-227). The `SHA256Builder inner; for (auto& h : sorted_tx_hashes) inner.append(h); inner_root = inner.finalize();` block is implementation-identical between v1 and v2 — the v2 extension does not touch the inner-root computation.
2. Construct outer builder `b` and append `(block_index, prev_hash, inner_root, dh_input)` (lines 229-233). v1 stops here. v2 evaluates the all-zero-views short-circuit (lines 242-258) and, by L-1, skips the F2-branch body.
3. Return `b.finalize()` (line 259).

By L-2, the outer builder `b` consumed the same byte sequence in both executions (the four-element prefix), so its `finalize()` output is byte-identical between v1 and v2.

Therefore `mcc_v2(idx, prev, txs, dh, Hash{}, Hash{}, Hash{}) = mcc_v1(idx, prev, txs, dh)`.    ∎

**Proof of Corollary T-1.1 (signature compatibility).** Ed25519 `Verify(pk, m, σ) = 1` is a deterministic function of `(pk, m, σ)` (per RFC 8032 + `Preliminaries.md` §1.1). If `σ` is the signature of `m := mcc_v1(idx, prev, txs, dh)` under `sk`, and `m' := mcc_v2(idx, prev, txs, dh, Hash{}, Hash{}, Hash{})` satisfies `m = m'` by T-1, then `Verify(pk, m', σ) = Verify(pk, m, σ) = 1`.    ∎

---

## 5. Proof of T-2 (DTM-F2-v1 replay defense)

Fix any v1 input `(idx_1, prev_1, txs_1, dh_1)` and any F2 input `(idx_2, prev_2, txs_2, dh_2, eq_2, abort_2, in_2)` with at least one of `eq_2, abort_2, in_2` non-zero (so the `any_view` predicate at `producer.cpp:246-248` evaluates true and the F2-branch body at `producer.cpp:249-258` executes).

The two pre-images supplied to `b.finalize()` at line 259 are:

```
pre_v1 := serialize(idx_1) || prev_1 || inner_root(txs_1) || dh_1                  // 104 bytes
pre_F2 := serialize(idx_2) || prev_2 || inner_root(txs_2) || dh_2
       || "DTM-F2-v1" || eq_2 || abort_2 || in_2                                    // 209 bytes
```

By L-3, `len(pre_v1) = 104 ≠ 209 = len(pre_F2)`. By L-2, the SHA-256 inputs into `EVP_DigestFinal_ex` are byte-distinct (different length ⇒ different last-block padding under FIPS 180-4 §5.1). By L-4 (collision-resistance bound), `Pr[SHA256(pre_v1) = SHA256(pre_F2)] ≤ 2⁻¹²⁸`.

The bound holds for any specific pair the adversary chooses. The conjunction of:
- v1 pre-image structure has no length-variability surface (each component is fixed-width),
- F2 branch unconditionally prepends 9 + 32 + 32 + 32 = 105 fresh bytes when `any_view = true`,

means the adversary cannot adjust `(idx_2, prev_2, txs_2, dh_2)` to compensate for the length mismatch. Therefore `Pr[mcc_v1(...) = mcc_v2(..., eq_2, abort_2, in_2)] ≤ 2⁻¹²⁸` for any choice of inputs by the adversary.    ∎

**Proof of Corollary T-2.1 (v1-sig non-replayability).** Suppose, for contradiction, that an adversary holds `σ_v1 = Sign(sk, m_v1)` where `m_v1 = mcc_v1(idx, prev, txs, dh)`, and presents `σ_v1` as a valid signature on `m_F2 = mcc_v2(idx', prev', txs', dh', eq, abort, in)` with at least one of `eq, abort, in` non-zero. By Ed25519 EUF-CMA (A1 / `Preliminaries.md` §2.2), `σ_v1` verifies on `m_F2` iff `m_v1 = m_F2`. By T-2, `Pr[m_v1 = m_F2] ≤ 2⁻¹²⁸`. The reverse direction (F2 sig replayed as v1 commit) is symmetric: any successful F2 sig binds a 209-byte pre-image, and replaying it on a v1 verifier (which feeds a 104-byte pre-image) requires `m_F2 = m_v1`, again negligible.    ∎

---

## 6. Adversary model

The adversary considered in T-2 + T-2.1 is the **mixed-version peer adversary**: a Byzantine peer holding signatures from any pre-F2 (v1) ContribMsg the adversary observed during the pre-activation phase, attempting to replay those signatures into post-activation rounds where committee members enforce F2 view-root binding. The adversary's capabilities:

- Observe gossip traffic, including v1 ContribMsg from honest pre-F2 peers prior to the F2 activation height.
- Choose, at attack time, any pre-image `(idx', prev', txs', dh', eq, abort, in)` to feed into a v1 signature claim. Specifically, the adversary can pick `eq, abort, in` freely (subject only to F2-SPEC.md §Q3's per-contrib bandwidth cap, which doesn't shrink the cryptographic search space).
- Submit the spoofed ContribMsg into the consensus layer at any height.

The adversary cannot:
- Forge the originating Ed25519 signature `σ_v1` (A1 / EUF-CMA).
- Find a SHA-256 collision (A2 / §2.1).

T-2's bound `Pr[success] ≤ 2⁻¹²⁸` per attempt covers the entire adversary's search space. Over polynomially many attempts `Q`, the cumulative bound is `Q · 2⁻¹²⁸`, negligible. The defense is information-theoretic-in-spirit: not "the attacker can't find such inputs," but "no such inputs exist except with cryptographically negligible probability." The defense does NOT depend on validator-side rejection of v1 commits at post-activation heights; the validator's V21..V26 checks (`include/determ/node/producer.hpp:216-219` + `src/node/validator.cpp` integrations) are belt-and-suspenders, not the cryptographic boundary.

The symmetric direction (v2 sig replayed as v1) is operationally less interesting (a v2 peer's commit is more useful with its view roots bound than stripped), but the proof covers it for completeness.

---

## 7. Test-suite citation

The byte-identity (T-1) and domain-separation (T-2) properties are exercised in the determ test suite under `test-view-root` (run via `tools/test_view_root.sh`). The relevant assertions live in `src/main.cpp` and cover both halves of the proof:

| Test | Source line | Property exercised |
|---|---|---|
| `make_contrib_commitment: all-zero views == v1 short-circuit` | `src/main.cpp:9608-9609` | T-1: explicit zero-view call equals the default-args 4-param call (cross-check on L-1) |
| `make_contrib_commitment: eq_root binds the hash` | `src/main.cpp:9626-9627` | T-2: distinct view roots → distinct hash (L-3 length argument materialized) |
| `make_contrib_commitment: abort_root binds the hash` | `src/main.cpp:9628-9629` | T-2: per-root independence |
| `make_contrib_commitment: inbound_root binds the hash` | `src/main.cpp:9630-9631` | T-2: per-root independence |
| `make_contrib_commitment: each root contributes independently` | `src/main.cpp:9632-9633` | T-2: pairwise distinctness across the three root slots |
| `make_contrib_commitment: F2 path deterministic` | `src/main.cpp:9646-9647` | L-2 determinism on the F2 branch |
| `make_contrib (empty F2 args): sig verifies under v1 commit` | `src/main.cpp:10103-10105` | T-1.1: pre-F2 sig accepted by extended primitive |
| `make_contrib (F2 args): sig verifies under F2 commit` | `src/main.cpp:10142-10144` | T-2.1: F2 sig binds F2 commit |
| `make_contrib (F2 args): v1 commit shape REJECTS F2 sig` | `src/main.cpp:10149-10151` | T-2.1 (negative): F2 sig does NOT verify under v1 commit shape |

The assertions complement the formal argument: T-1.1's "v1 sig under v2 verifier accepts" + T-2.1's "F2 sig under v1 verifier rejects" together pin down the bidirectional cross-shape verification matrix that an external implementer needs to reproduce. A wrong implementation that, e.g., always prepends `"DTM-F2-v1"` (no short-circuit) would fail the first row; one that omits the tag would fail the last row.

The regression `tools/test_view_root.sh` invokes `determ test-view-root` which runs the suite at `src/main.cpp` and asserts the trailer line `PASS: view-root all assertions`. CI gates on this passing.

---

## 8. Status

**Shipped.** `make_contrib_commitment` extension at `src/node/producer.cpp:219-260` + header declaration at `include/determ/node/producer.hpp:134-139` + test-suite coverage at `src/main.cpp` (the assertions cited in §7) all live in the current `main` branch. The corresponding F2-SPEC §Q4 work-unit is closed by the commit that introduced this primitive; downstream F2 sub-steps (V21..V26 validator integration per §Q5, canonical-list reconciliation per §Q1) build on the foundation T-1 + T-2 establish.

This proof was added in the same review pass that closed the spec coherence sweep for F2; it does not change any code, only consolidates the cryptographic argument that the wire-extension preserves backward compat AND introduces a sound domain separator.

---

## 9. References

- `src/node/producer.cpp:219-260` — `make_contrib_commitment` definition (the proof's primary object).
- `include/determ/node/producer.hpp:117-139` — header declaration with default-zero trailing args + the explicit "all-zero ⇒ v1 commit" docstring (lines 127-133).
- `src/crypto/sha256.cpp:1-59` — `SHA256Builder` implementation backing the cryptographic determinism argument in L-2.
- `include/determ/crypto/sha256.hpp:9-29` — `SHA256Builder` public interface.
- `src/main.cpp:9594-9648`, `src/main.cpp:10078-10152` — assertion sites referenced in §7.
- `tools/test_view_root.sh` — regression harness that runs the §7 assertions.
- `docs/proofs/Preliminaries.md` §1.3 (hash + serialization conventions), §2.1 (SHA-256 collision + 2nd-preimage resistance — A2), §2.2 (Ed25519 EUF-CMA — A1).
- `docs/proofs/F2-SPEC.md` §Q4 — design decision to extend `make_contrib_commitment` with the three view roots under a single Ed25519 sig (rather than three separate sigs).
- `docs/proofs/S030-D2-Analysis.md` — surrounding D2-closure analysis; F2 view reconciliation is the consensus-layer half of the closure (S-033 + S-038 cover the apply-layer half).
- `docs/proofs/EquivocationSlashing.md` — companion proof; the digest-agnostic V11 mechanism that consumes contrib commitments at the slashing layer.
- NIST FIPS 180-4 (Secure Hash Standard) §5.1, §6.1.2 — SHA-256 padding + compression function definitions used in L-2 + L-3.
- RFC 6234 (US Secure Hash Algorithms) — alternate normative reference for SHA-256.
- RFC 8032 (Edwards-Curve Digital Signature Algorithm) — Ed25519 spec referenced by A1.
- Bellare, Rogaway — "Introduction to Modern Cryptography" §5.3 — textbook treatment of SHA family collision-resistance assumption.
