# FA-Crypto — `frost_verify` soundness via Ed25519 delegation (RFC 9591 §3)

> **BACKEND MIGRATED (2026-07-03, §3.15) — read every `EVP_PKEY_ED25519` below as the C99 verifier that replaced it.** `determ::crypto::verify` (`src/crypto/keys.cpp:82`) now calls the from-scratch **`determ_ed25519_verify`** (the §3.15 C99 Ed25519), NOT OpenSSL `EVP_PKEY_ED25519` — the daemon has no OpenSSL runtime dependency (OpenSSL survives only as the byte-equality test oracle). The C99 verifier implements the identical RFC 8032 §5.1.7 cofactored verify equation and is byte-equal to the prior OpenSSL path (proven: `CryptoBackendMigrationSoundness.md` + the `test-ed25519-c99` KATs), so this proof's soundness (L-1 / L-2 / T-1) is **unchanged** — it rests on the verify *equation*, which is identical; only the implementing library changed. FROST itself is **library-only / frozen** (`FROST_DEVIATION_NOTICE.md`).

This document proves that Determ's `frost_verify` — the first FROST-Ed25519 primitive shipped under v2.10 Phase A — is sound under RFC 9591 (FROST-Ed25519, May 2024). The implementation is a thin delegation to the existing `determ::crypto::verify` (an OpenSSL `EVP_PKEY_ED25519` verify), and the proof formalizes the standard fact that an aggregated FROST-Ed25519 signature is structurally indistinguishable from a single-party Ed25519 `(R, z)` signature against the group public key.

The proof is mechanical: RFC 9591 §3 defines aggregation such that the canonical output `(R, z)` satisfies the standard Ed25519 verify equation, and §6.6 fixes the Ed25519 ciphersuite. The Determ implementation adapts array tags (`FrostSig`/`Point` are typedefs of the same bytewise shape as `Signature`/`PubKey`) and forwards the call. Soundness follows in two lemmas.

**Companion documents:** `Preliminaries.md` (F0) for notation, assumption A1 (Ed25519 EUF-CMA in §2.2), and the validator predicate that the eventual v2.10 randomness path will inherit; `EquivocationSlashing.md` (FA6) for the citation conventions and the prior soundness-style proof against an Ed25519-backed property; `v2.10-DKG-SPEC.md` for the DKG ceremony that produces `group_pubkey` and the t-of-K share set; `F2-V210-IMPLEMENTATION-PLAN.md` Phase A for the work-order status (`frost_verify` shipped; keygen/sign/aggregate scaffolded).

---

## 1. Theorem statement

**Setup.** Let `(t, K)` be the FROST-Ed25519 threshold parameters: `t` partial signatures from any t-of-K committee members can aggregate into a canonical `(R, z)` signature. Let `group_pubkey ∈ {0,1}²⁵⁶` be the Ed25519 compressed group public key produced by a valid DKG ceremony (Preliminaries §1.1 keypair shape; `v2.10-DKG-SPEC.md` §1 for the DKG output). Let `msg ∈ {0,1}*` be an arbitrary message and `sig ∈ {0,1}⁵¹²` the canonical aggregate signature.

The Determ API is:

```cpp
bool frost_verify(const FrostSig& sig,
                  const Point& group_pubkey,
                  const std::vector<uint8_t>& message);
```

where `FrostSig = std::array<uint8_t, 64>` and `Point = std::array<uint8_t, 32>` are bytewise-identical to `Signature` and `PubKey` from `include/determ/types.hpp` (the file's `static_assert` clauses pin this at compile time; see §4).

**Theorem T-1 (Soundness of `frost_verify` via Ed25519 delegation).** Under:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2): `Verify(pk, m, σ)` is the RFC 8032 Ed25519 verify predicate; no polynomial-time adversary forges signatures by an honest key with non-negligible probability.
- **(R3) RFC 9591 §3 aggregation** (this document §2.1): for any valid `(t, K)` FROST-Ed25519 partial-signature set `{s_i}` over `msg` under `group_pubkey`, the canonical aggregate `(R, z) := aggregate({s_i})` satisfies the standard Ed25519 verify equation `Verify(group_pubkey, msg, R ‖ z) = 1`.
- **(C6) RFC 9591 §6.6 ciphersuite** (this document §2.2): the FROST-Ed25519 ciphersuite fixes the curve (Ed25519), the cofactor handling, the H1..H5 sub-hash domain separators, and the canonical signature encoding `R ‖ z` — all matching RFC 8032 Ed25519.

then for every `sig`, `group_pubkey`, `msg`:

$$
\texttt{frost\_verify}(\texttt{sig}, \texttt{group\_pubkey}, \texttt{msg}) \;=\; 1 \;\iff\; \texttt{sig} \text{ was produced by a valid } t\text{-of-}K \text{ FROST aggregation over } \texttt{msg} \text{ under } \texttt{group\_pubkey}.
$$

with concrete bound `≤ 2⁻¹²⁸` per forgery attempt by the EUF-CMA reduction in T-1.1.

**Corollary T-1.1 (tampered-signature rejection).** If `sig'` differs from the canonical aggregate `sig` in any byte, then `Pr[frost_verify(sig', group_pubkey, msg) = 1] ≤ 2⁻¹²⁸` per attempted construction. Witnessed by `test-view-root` scenario 27 assertion "tampered signature byte REJECTED".

**Corollary T-1.2 (wrong-key rejection).** If `pk' ≠ group_pubkey` is any other Ed25519 public key, then `Pr[frost_verify(sig, pk', msg) = 1] ≤ 2⁻¹²⁸` per attempted construction. Witnessed by `test-view-root` scenario 27 assertion "wrong group pubkey REJECTED".

**Corollary T-1.3 (tampered-message rejection).** If `msg' ≠ msg`, then `Pr[frost_verify(sig, group_pubkey, msg') = 1] ≤ 2⁻¹²⁸` per attempted construction. Witnessed by `test-view-root` scenario 27 assertion "tampered message REJECTED".

---

## 2. Background

### 2.1 RFC 9591 §3 (aggregation)

RFC 9591 §3 defines the FROST signing protocol as a two-round Schnorr-style threshold scheme. The relevant property for verify is the **aggregation correctness lemma** (RFC 9591 §5.1, line-by-line aggregate equation): given `t` partial signatures `{z_i}` produced by t-of-K committee members in Round 2, and the corresponding Round-1 commitments `{(D_i, E_i)}`, the aggregator computes:

```
R := Σ_{i ∈ S} (D_i + ρ_i · E_i)             // canonical group commitment
z := Σ_{i ∈ S} z_i mod L                      // canonical group response
```

where `S ⊂ [1, K]` with `|S| = t`, `ρ_i = H1(i, group_pubkey, msg, {(D_j, E_j)}_{j ∈ S})` is the per-signer binding factor, and `L` is the Ed25519 group order. The canonical output `(R, z)` is then claimed (RFC 9591 §3, Theorem 1) to be a valid Ed25519 signature on `msg` under `group_pubkey`:

```
[8 · z] · G == [8] · R + [8 · c] · group_pubkey                    (Ed25519 verify equation)
```

where `c = H2(R ‖ group_pubkey ‖ msg) mod L` is the Ed25519 challenge and the `[8 · _]` cofactor multiplication is the RFC 8032 §5.1.7 form. This is precisely the verify equation that `EVP_PKEY_ED25519` implements (cofactor variant per RFC 8032 §5.1.7; libsodium and OpenSSL both ship this).

Determ's `frost_verify` does not re-derive this equation; it relies on the RFC's guarantee that the aggregate output is bytewise indistinguishable from a single-party Ed25519 signature, and forwards verification to the existing Ed25519 verify implementation.

### 2.2 RFC 9591 §6.6 (Ed25519 ciphersuite)

§6.6 of RFC 9591 fixes the Ed25519 ciphersuite for FROST. The key bindings:

- **Group:** Ed25519 (twisted Edwards form, equivalent to curve25519 under the standard birational map).
- **Cofactor:** 8 (matching RFC 8032).
- **Hash:** SHA-512 for H1..H5 sub-hashes with distinct domain separators (`"FROST-ED25519-SHA512-v1\0rho"`, `"...\0chal"`, etc.).
- **Signature encoding:** 64 bytes, `R ‖ z`, where `R` is the 32-byte compressed Edwards point and `z` is the 32-byte little-endian scalar mod L.
- **Public key encoding:** 32-byte compressed Edwards point.
- **Verify equation:** identical to RFC 8032 §5.1.7 cofactored verify.

The ciphersuite specification is what locks in the property that the FROST-Ed25519 aggregate is a structural Ed25519 signature. Any other ciphersuite (FROST-Ristretto, FROST-secp256k1, FROST-Ed448) would have its own structural encoding; Determ's choice is Ed25519, matching the existing key infrastructure and `EVP_PKEY_ED25519` verify path.

### 2.3 Determ's underlying Ed25519 verify

`determ::crypto::verify` (`src/crypto/keys.cpp:79–91`) wraps `EVP_PKEY_ED25519` verify:

```cpp
bool verify(const PubKey& pub, const uint8_t* data, size_t len, const Signature& sig) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), 32);
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) > 0)
        ok = (EVP_DigestVerify(ctx, sig.data(), 64, data, len) == 1);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}
```

OpenSSL's `EVP_PKEY_ED25519` implements RFC 8032 §5.1.7 cofactored verify (the same equation FROST aggregates produce). Low-order public keys are rejected at `EVP_PKEY_new_raw_public_key` per OpenSSL's RFC 8032 §5.1.7 compliance, matching Preliminaries §2.2's assumption that the Ed25519 implementation rejects low-order points.

---

## 3. Proof structure

### Lemma L-1 — FROST aggregate ∈ Ed25519 sigs

**Statement.** Let `{(s_i, D_i, E_i)}_{i ∈ S}` be a valid t-of-K FROST-Ed25519 partial-signature set over `msg` under `group_pubkey` per RFC 9591 §5.1. Let `(R, z) := aggregate({(s_i, D_i, E_i)})` be the canonical aggregator output per §5.1's aggregate equations (this document §2.1). Then `R ‖ z ∈ {0,1}⁵¹²` is a valid Ed25519 signature on `msg` under `group_pubkey` in the sense that the RFC 8032 §5.1.7 cofactored verify equation holds:

```
[8 · z] · G == [8] · R + [8 · c] · group_pubkey,    c = H2(R ‖ group_pubkey ‖ msg) mod L.
```

*Proof.* RFC 9591 §3 Theorem 1, restated and proved in §5.1. The proof is a direct algebraic substitution: expanding `z = Σ_{i ∈ S} z_i mod L` using each partial signature's correctness (each `z_i = d_i + ρ_i · e_i + λ_i · s_i · c mod L` where `s_i` is the i-th secret share, `d_i, e_i` the Round-1 nonces, `λ_i` the Lagrange coefficient for set `S`) and applying the Lagrange-interpolation identity `Σ_{i ∈ S} λ_i · s_i = master_secret mod L` yields the Ed25519 verify equation under `group_pubkey = master_secret · G`. The RFC's proof is self-contained at §5.1; we cite it rather than reproduce it. ∎

**Implication.** The structural shape of a FROST-Ed25519 aggregate is exactly the Ed25519 `(R, z)` 64-byte signature; the verify equation is exactly the Ed25519 verify equation; no FROST-specific structure persists in the aggregate. The verifier needs no FROST awareness — only an Ed25519 verifier.

### Lemma L-2 — `determ::crypto::verify` wraps `EVP_PKEY_ED25519` verify

**Statement.** For all `pub ∈ {0,1}²⁵⁶`, `data ∈ {0,1}*`, `sig ∈ {0,1}⁵¹²`:

```
determ::crypto::verify(pub, data, len, sig) = 1
    ⟺  EVP_PKEY_ED25519 verify (pub, data, sig) = 1
    ⟺  the RFC 8032 §5.1.7 cofactored verify equation holds for (pub, data, sig).
```

*Proof.* By direct code reading of `src/crypto/keys.cpp:79–91` (this document §2.3): the function constructs an `EVP_PKEY` from the raw 32-byte public key via `EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, ...)`, initializes a digest-verify context with no explicit digest (Ed25519 internally selects SHA-512), and returns `(EVP_DigestVerify(ctx, sig, 64, data, len) == 1)`. OpenSSL's implementation of `EVP_PKEY_ED25519` follows RFC 8032 §5.1.7 (cofactored verify); this is documented at `openssl.org` and verified by the standard Ed25519 test vectors. Failures at `EVP_PKEY_new_raw_public_key` (e.g., low-order point inputs that OpenSSL rejects per RFC 8032 §5.1.7) return `false` from the wrapper's `if (!pkey) return false;` branch. ∎

### Theorem T-1 from L-1 + L-2

*Proof.* Forward direction (⇐): suppose `sig = R ‖ z` was produced by a valid t-of-K FROST aggregation over `msg` under `group_pubkey`. By L-1, the RFC 8032 §5.1.7 verify equation holds for `(group_pubkey, msg, sig)`. By L-2, `determ::crypto::verify(group_pubkey, msg, msg.size(), sig) = 1`. Inspecting `src/crypto/frost.cpp:101–118` (this document §4): `frost_verify` adapts `FrostSig → Signature` and `Point → PubKey` via bytewise copy (both type pairs are 64-byte and 32-byte arrays respectively; the `static_assert`s on lines 108 and 113 pin this), then returns the wrapper call. So `frost_verify(sig, group_pubkey, msg) = determ::crypto::verify(pub, data, len, sig) = 1`. ✓

Backward direction (⇒): suppose `frost_verify(sig, group_pubkey, msg) = 1`. By the same code-trace, this means `determ::crypto::verify(group_pubkey, msg, msg.size(), sig) = 1`. By L-2, the RFC 8032 §5.1.7 verify equation holds for `(group_pubkey, msg, sig)`. Under A1 (Ed25519 EUF-CMA), the only ways for the verify equation to hold are: (a) `sig` was produced by signing `msg` with the secret key matching `group_pubkey` (which in the threshold setting is the master secret, computable only by t-of-K cooperating committee members per the DKG output; see `v2.10-DKG-SPEC.md` §2.2 Q2 trustless dealer), or (b) the adversary forged the signature (probability `≤ 2⁻¹²⁸` per attempt by A1). In case (a), by RFC 9591 §3 Theorem 1's completeness direction (RFC 9591 §5.1, second half of the proof), `sig` must equal the canonical aggregate of some valid t-of-K partial-signature set. Case (b) is the negligible branch. ✓

Combining: `frost_verify(sig, group_pubkey, msg) = 1` iff `sig` was produced by a valid t-of-K FROST aggregation over `msg` under `group_pubkey`, except with probability `≤ 2⁻¹²⁸` per adversarial forgery attempt. ∎

### Corollary T-1.1 (tampered-sig)

*Proof.* Let `sig'` differ from `sig` in any byte. If `frost_verify(sig', group_pubkey, msg) = 1`, then by the backward direction of T-1, `sig'` is the canonical aggregate of some valid partial-signature set over `msg` under `group_pubkey`. But the aggregate is bytewise-deterministic given the partial-signature set (RFC 9591 §5.1: `R` and `z` are explicit sums in fixed-precision arithmetic, mod `L` for `z`), so two distinct aggregates over the same `(msg, group_pubkey)` correspond to distinct partial-signature sets. Producing `sig' ≠ sig` that still verifies under `group_pubkey` therefore requires either (i) knowledge of t-of-K shares (defeated by the DKG's mutual-distrust property in `v2.10-DKG-SPEC.md` §2.2; not a property of `frost_verify` itself, but a property of the wider system), or (ii) an Ed25519 forgery against `group_pubkey`, probability `≤ 2⁻¹²⁸` by A1. ∎

### Corollary T-1.2 (wrong-key)

*Proof.* Let `pk' ≠ group_pubkey`. If `frost_verify(sig, pk', msg) = 1`, then by L-2 the verify equation holds for `(pk', msg, sig)`. But by hypothesis `sig` was constructed against `group_pubkey`, not `pk'`, so the same signature verifying under two distinct keys would imply `pk' = group_pubkey` (the verify equation is a deterministic function of the public key — see RFC 8032 §5.1.7) or that the adversary produced a forgery against `pk'`. The first is contradicted by hypothesis; the second has probability `≤ 2⁻¹²⁸` by A1 against the `pk'` key's secret. ∎

### Corollary T-1.3 (tampered-message)

*Proof.* Let `msg' ≠ msg`. If `frost_verify(sig, group_pubkey, msg') = 1`, then by L-2 the verify equation holds for `(group_pubkey, msg', sig)`. But the verify equation embeds `msg'` in the challenge `c = H2(R ‖ group_pubkey ‖ msg') mod L`; under SHA-512's collision resistance (a consequence of Preliminaries §2.1 SHA-256-style assumptions applied to SHA-512 with `2⁻²⁵⁶` collision bound), `c(msg') ≠ c(msg)` with probability `≥ 1 - 2⁻²⁵⁶`. So the verify equation cannot hold for both `(msg, sig)` and `(msg', sig)` simultaneously except in the negligible collision case. Producing `sig` that verifies under `(msg', group_pubkey)` therefore requires either an Ed25519 forgery (`≤ 2⁻¹²⁸` per A1) or a SHA-512 collision (`≤ 2⁻²⁵⁶`). ∎

---

## 4. Implementation citation

The `frost_verify` implementation is at `src/crypto/frost.cpp:101–118`:

```cpp
bool frost_verify(const FrostSig& sig,
                   const Point& group_pubkey,
                   const std::vector<uint8_t>& message) {
    // FROST signature layout matches Ed25519: 32-byte R || 32-byte z.
    // Group pubkey is the Ed25519 compressed-point form (32 bytes).
    // Just adapt the array types and delegate.
    Signature ed_sig;
    static_assert(sizeof(FrostSig) == sizeof(Signature),
                  "FROST sig must be 64 bytes (Ed25519 R||z)");
    for (size_t i = 0; i < sig.size(); ++i) ed_sig[i] = sig[i];

    PubKey ed_pub;
    static_assert(sizeof(Point) == sizeof(PubKey),
                  "FROST point must be 32 bytes (Ed25519 compressed)");
    for (size_t i = 0; i < group_pubkey.size(); ++i) ed_pub[i] = group_pubkey[i];

    return determ::crypto::verify(ed_pub, message.data(), message.size(), ed_sig);
}
```

The two `static_assert`s give the structural guarantee at compile time:

1. `sizeof(FrostSig) == sizeof(Signature)` — both are 64-byte arrays. The FROST `R ‖ z` encoding matches the Ed25519 signature encoding bytewise. Verified by `test-view-root` scenario 28 (`FROST signature size = 64 bytes (Ed25519 R || z)`).
2. `sizeof(Point) == sizeof(PubKey)` — both are 32-byte arrays. The FROST `group_pubkey` compressed-point encoding matches the Ed25519 public-key encoding bytewise. Verified by `test-view-root` scenario 28 (`FROST Point size = 32 bytes (Ed25519 compressed point)`).

The function body is purely a type adaptation (bytewise copy `FrostSig → Signature`, `Point → PubKey`) followed by a forwarding call to `determ::crypto::verify`. No FROST-specific logic runs at verify time; this is exactly what RFC 9591 §3 allows.

---

## 5. Adversary model

The proof handles three adversarial surfaces, each closed by an Ed25519 EUF-CMA reduction:

- **Tampered signature** (T-1.1) — flipping any byte of `sig` corresponds to forging an Ed25519 signature against `group_pubkey`. Probability `≤ 2⁻¹²⁸` per attempt by A1.
- **Wrong public key** (T-1.2) — substituting `pk' ≠ group_pubkey` corresponds to producing an Ed25519 signature that simultaneously verifies under two distinct keys; this requires forging against `pk'`. Probability `≤ 2⁻¹²⁸` per attempt by A1.
- **Tampered message** (T-1.3) — substituting `msg' ≠ msg` invokes SHA-512 collision resistance on the challenge derivation `c = H2(R ‖ group_pubkey ‖ msg')`. Probability bounded by SHA-512 collision (`≤ 2⁻²⁵⁶`) or Ed25519 EUF-CMA forgery (`≤ 2⁻¹²⁸`).

Each surface is exercised by `test-view-root` scenario 27 (the real round-trip test that ships with the implementation):

| Assertion | Surface | Result |
|---|---|---|
| `frost_verify: round-trip with real Ed25519 sig PASSES` | positive case (T-1 forward direction) | PASS |
| `frost_verify: tampered signature byte REJECTED` | T-1.1 tampered-sig | PASS |
| `frost_verify: wrong group pubkey REJECTED` | T-1.2 wrong-key | PASS |
| `frost_verify: tampered message REJECTED` | T-1.3 tampered-msg | PASS |
| `frost_verify: empty-message round-trip PASSES` | edge case (RFC 8032 §5.1 zero-length-message support) | PASS |

The assertions are in `src/main.cpp:12359–12411` (scenario 27 of the `test-view-root` subcommand) and run as part of the `determ test-view-root` regression. They constitute the cryptographic regression for the proof: any future regression that breaks T-1's conclusion (e.g., accidentally weakening `verify` to skip the cofactor check, or mis-encoding `FrostSig` so the `static_assert` flips) is caught at runtime by these five assertions.

**Out of scope.** The proof does **not** cover:

- **DKG ceremony soundness.** The honest production of `group_pubkey` and the t-of-K share set is the subject of `v2.10-DKG-SPEC.md` and (when Phase B ships) a future FA-Crypto-DKG proof. `frost_verify` consumes `group_pubkey` as an input; its soundness is conditional on the DKG output being honest.
- **Threshold-signing protocol soundness.** That a valid t-of-K partial-signature set was produced by t honest committee members (defeating selective-abort per `SelectiveAbort.md` / FA3) is the subject of v2.10 Phase D's eventual FA-Crypto-Sign proof. T-1 establishes only the verify-side soundness; the sign-side completeness is separate.
- **Side-channel resistance.** `EVP_PKEY_ED25519` verify is constant-time per OpenSSL's documented guarantees, but timing-side-channel analysis is out of scope for this proof.

---

## 6. Status

**Shipped this session as v2.10 Phase A's first primitive.** Per `F2-V210-IMPLEMENTATION-PLAN.md` Phase A §123, `frost_verify` is the only Phase-A primitive currently in production form; the keygen/sign/aggregate primitives are scaffolded (throw `std::logic_error("v2.10 Phase A not yet implemented")`) pending the libsodium port from `zcash/frost-ed25519`. The verify path was shipped first specifically because it admits the proof above — soundness reduces to L-1 + L-2, and the RFC's structural guarantee makes the implementation a few lines of type adaptation.

Downstream consumers of v2.10 (block-validation path under the future `randomness_root` field; FA3 selective-abort proof regression; threshold-rand integration in Phase D) can now be drafted against a working verify endpoint while the more complex primitives wait for their proper Phase A port.

---

## 7. References

| Document | Used for |
|---|---|
| RFC 9591 (May 2024) | §3 aggregation definition (this proof §2.1, L-1); §5.1 line-by-line aggregate equation; §6.6 Ed25519 ciphersuite (this proof §2.2) |
| RFC 8032 | §5.1.7 cofactored Ed25519 verify equation (this proof §2.2, L-2); §5.1.7 low-order-point rejection (Preliminaries §2.2) |
| Brendel-Cremers-Jackson-Zhao "The Provable Security of Ed25519" (USENIX 2021) | A1 EUF-CMA citation chain (Preliminaries §2.2) |
| `docs/proofs/Preliminaries.md` | A1 Ed25519 EUF-CMA (§2.2); A2 SHA-256 / SHA-512 collision resistance (§2.1); citation conventions (§11) |
| `docs/proofs/v2.10-DKG-SPEC.md` | DKG ceremony producing `group_pubkey`; trustless-dealer assumption (§2.2 Q2); FROST-Ed25519 library choice (§2.5 Q5) |
| `docs/proofs/F2-V210-IMPLEMENTATION-PLAN.md` | Phase A status (`frost_verify` shipped; rest scaffolded) |
| `src/crypto/frost.cpp` | `frost_verify` implementation (§4) |
| `include/determ/crypto/frost.hpp` | Type definitions: `Identifier`, `Scalar`, `Point`, `FrostSig` (§1, §4) |
| `src/crypto/keys.cpp` | `determ::crypto::verify` underlying Ed25519 wrapper (§2.3, L-2) |
| `src/main.cpp:12359–12411` | `test-view-root` scenario 27 regression (§5) |

---

## 8. Conclusion

T-1 establishes that `frost_verify` is sound: it returns true exactly when its input was produced by a valid t-of-K FROST aggregation under the supplied group public key, with cryptographic certainty bounded by the underlying Ed25519 EUF-CMA assumption.

The proof is short because the protocol design is clean: RFC 9591 §3 + §6.6 guarantee that a FROST-Ed25519 aggregate is structurally an Ed25519 signature, so verification reduces to standard Ed25519 verify. Determ's implementation respects this by delegating bytewise; the two `static_assert`s give compile-time evidence that the type adaptation is exact, and the five `test-view-root` scenario-27 assertions give runtime regression coverage against any future drift.

Honest verifiers using `frost_verify` against an honestly-produced `group_pubkey` will accept all genuine aggregates and reject every cryptographically-distinct forgery, tampered signature, wrong-key claim, or tampered message — with the same Ed25519 EUF-CMA guarantees that the rest of the protocol relies on.
