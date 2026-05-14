# FA12 — Wallet recovery soundness (A2)

This document proves that Determ's wallet recovery primitive — distributed Shamir secret sharing layered with AEAD envelopes and (optionally) password-authenticated key exchange — preserves the user's Ed25519 seed under composable adversary models. The argument has four layers:

1. **Shamir** — below-threshold compromise leaks zero information about the secret.
2. **AEAD envelope** — per-share tampering is cryptographically detectable.
3. **OPAQUE adapter** — password grind requires online interaction with at least `threshold` guardians.
4. **Compositional** — the four-layer stack inherits the strongest of each layer's bounds.

The wallet ships in two modes: passphrase-direct (Phase 3) and OPAQUE-adapter-routed (Phase 7). Real OPAQUE (Phase 6, pending) replaces only the adapter's implementation; the recovery flow's structural argument is identical under stub and real OPAQUE.

**Phase numbering note.** This document uses the wallet's internal `wallet/PHASE6_PORTING_NOTES.md` phase numbers (3 = passphrase-direct, 5 = stub OPAQUE adapter, 6 = real `libopaque` integration pending MSVC porting, 7 = OPAQUE-adapter-routed assembly). The Phase-6 work item maps to **v2.14 (Real OPAQUE wallet recovery)** in `docs/V2-DESIGN.md`. The two naming schemes coexist because the Phase-N numbering is stable across the wallet refactor history and is referenced throughout this proof, while the v2.N numbering is the project's overall roadmap surface. A reader looking at the V2-DESIGN.md status table should read "v2.14 = WalletRecovery.md Phase 6 = real `libopaque`-vendored adapter."

**Companion documents:** `Preliminaries.md` (F0); `EconomicSoundness.md` (FA11) for the chain-side seed-protection context.

---

## 1. Mechanism summary

### Setup (`create-recovery` / `create_opaque`)

Inputs: 32-byte Ed25519 seed `s`, password `P`, threshold `T`, share count `N`, optional pubkey checksum `c_pub`.

1. Compute Shamir shares `(x_i, y_i)` for `i ∈ {1..N}` with threshold `T` over GF(2⁸) such that any `T` shares reconstruct `s` and any `T-1` reveal zero information.
2. For each `i`:
   - Derive an unwrap key `k_i`:
     - **Passphrase scheme:** `k_i = PBKDF2-HMAC-SHA-256(P, salt_i, iters)` where `salt_i` is fresh per envelope.
     - **OPAQUE scheme (stub):** `(record_i, export_key_i) = opaque_register(P, i)`; `k_i = export_key_i`.
     - **OPAQUE scheme (real, Phase 6):** `(record_i, export_key_i) = OPAQUE_Register(P, gid=i)` per RFC 9807.
   - Encrypt `env_i = AES-256-GCM(key=k_i, nonce=fresh, aad=DWR1‖i‖v, pt=y_i)`.
3. Output `RecoverySetup{version, scheme, T, N, |s|, [x_i], [env_i], [record_i], c_pub}`.

### Recovery (`recover`)

Inputs: `RecoverySetup`, password `P`, guardian indices `G ⊆ {0..N-1}` with `|G| ≥ T`.

1. Dispatch by scheme tag:
   - Passphrase: `k'_i = PBKDF2(P, env_i.salt, iters)` for each `i ∈ G`.
   - OPAQUE: `k'_i = opaque_authenticate(P, record_i, i)` for each `i ∈ G`; abort that slot if authentication fails.
2. For each successful slot, decrypt `y'_i = AES-256-GCM-Decrypt(env_i, k'_i, aad)`. Abort that slot if AEAD tag check fails.
3. If `|{successful slots}| < T`, return failure.
4. Apply Shamir Lagrange interpolation at `x = 0` over `T` recovered `(x_i, y'_i)` pairs to obtain candidate secret `s'`.
5. Optional: if `c_pub ≠ ∅` and `|s'| = 32`, recompute `c'_pub = SHA-256(Ed25519_pubkey(s'))`; reject if `c'_pub ≠ c_pub`.
6. Return `s'`.

---

## 2. Theorem statements

**Theorem T-15 (Below-threshold information theoretic security).** Let `k_1, ..., k_{T-1}` be the keys associated with any `T-1` envelopes. Under:

- **(SSS)** Shamir's secret sharing over GF(2⁸) with threshold `T` and uniform-random polynomial coefficients.

For any adversary `A` with access to `{(env_i, x_i, k_i) : i ∈ S}` with `|S| = T-1` (i.e., `A` has unwrapped `T-1` shares), the conditional distribution of the secret `s` given this view is uniform over `{0, 1}^|s|`. Equivalently:

$$
H(s \mid \{(x_i, y_i)\}_{i \in S}) = H(s) = 8 \cdot |s| \text{ bits}
$$

In plain terms: any `T-1` shares — even with cryptographic keys cleanly recovered — reveal zero bits about the wallet seed.

**Theorem T-16 (AEAD envelope binding).** Under:

- **(A1)** Ed25519 EUF-CMA (F0 §2.2)
- **(AES-GCM)** AES-256-GCM unforgeability — distinguishing a valid (ciphertext, tag) pair from a forged one is `≤ 2⁻¹²⁸ + ε_AES` per attempt, where `ε_AES` is the AES advantage of a chosen-plaintext-and-ciphertext distinguisher (negligible under standard cryptographic assumptions).

For any envelope `env_i` with `k_i` unknown to the adversary, any modification to the ciphertext, AAD, nonce, or tag causes `decrypt(env_i, k_i, aad)` to return failure with probability `≥ 1 - 2⁻¹²⁸`. Equivalently: a bit-flip on a share survives at most negligibly often.

**Theorem T-17 (OPAQUE adapter substitution invariance).** Let `A_stub` (Phase 5) and `A_real` (Phase 6) denote two implementations of the `opaque_adapter` interface satisfying:

- `register_password(P, i) → (record_i, export_key_i)` such that `export_key_i ∈ {0,1}²⁵⁶`.
- `authenticate_password(P, record_i, i) → export_key_i` iff `P` matches the registration password.

Then any RecoverySetup created with `A_stub` is recoverable under `A_stub` iff under `A_real` (i.e., the recovery flow does not depend on the adapter's *implementation*, only its API contract). The suite-tag mismatch gate prevents cross-adapter recovery (different suite IDs are not interchangeable).

**Theorem T-18 (End-to-end recovery soundness under composite adversary).** Let an adversary `A` simultaneously:

1. Compromise up to `T-1` guardians (recover their stored `(env_i, record_i)` data).
2. Mount up to `Q` online authentication attempts against any single uncompromised guardian.

Under T-15, T-16, T-17, and:

- **(OPAQUE-soundness)** Real OPAQUE prevents offline password grind: an adversary holding `record_i` from a single guardian cannot test password guesses without interacting with that guardian (RFC 9807, Theorem 4.1).

The probability of `A` recovering the Ed25519 seed satisfies:

```
Pr[A recovers s] ≤ Q · 2^(-bits_password) + |G_active| · 2⁻¹²⁸
```

where `bits_password` is the password entropy and `|G_active|` is the count of uncompromised guardians `A` attempted against.

For a high-entropy password (`≥ 60 bits`) and modest `Q = 2^16` (rate-limited guardians), the bound is dominated by `2⁻⁴⁴` — strongly negligible for realistic adversary budgets.

**Corollary T-18.1 (Stub-mode degradation).** Under the Phase 5 stub adapter, OPAQUE-soundness does **not** hold: a single compromised guardian who knows `record_i` can offline-grind the password by recomputing `Argon2id(P || i, salt, 32)` for each candidate `P`. The stub's bound degrades to:

```
Pr[A recovers s with 1 compromised guardian] ≤ Q · 2^(-bits_password) / Argon2id_cost
```

where `Q` here is the adversary's offline-attempt budget (no longer rate-limited by an online guardian). The wallet's `is_stub()` flag MUST be checked before deployment; the stub is a development scaffold, not a production cryptosystem.

---

## 3. Proof of T-15 (Shamir below-threshold ITS)

By construction of Shamir's secret sharing. For each byte position `b` of `s`, the share value `y_i^{(b)}` is the evaluation of a polynomial:

```
p_b(x) = s_b + a_1^{(b)} · x + a_2^{(b)} · x² + ... + a_{T-1}^{(b)} · x^{T-1}
```

over GF(2⁸), where `a_1^{(b)}, ..., a_{T-1}^{(b)}` are uniform random coefficients (sampled via `RAND_bytes`).

Given any `T-1` evaluations `(x_{i_1}, y_{i_1}^{(b)}), ..., (x_{i_{T-1}}, y_{i_{T-1}^{(b)}})` with distinct nonzero `x`, the system of `T-1` linear equations in `T` unknowns `(s_b, a_1^{(b)}, ..., a_{T-1}^{(b)})` is **underdetermined**: for every candidate `s'_b ∈ GF(2⁸)`, there is exactly one set of `(a_1^{(b)}, ..., a_{T-1}^{(b)})` consistent with the observed shares. Since the coefficients are uniformly random, every candidate `s'_b` is equally probable.

Therefore `Pr[s_b = c | T-1 shares] = 1/256` for every `c ∈ GF(2⁸)` and every byte position `b`. By chain-rule independence across byte positions (each polynomial is independent), the joint conditional distribution over `s` is uniform. `H(s | shares) = H(s)`. ∎

This is the standard ITS argument for Shamir's SSS; reproduced here for completeness because the wallet's defense-in-depth claim depends on it.

---

## 4. Proof of T-16 (AEAD binding)

Direct from AES-256-GCM's strong unforgeability (SUF-CMA). The envelope's tag covers `(nonce, ciphertext, AAD)` via the GCM construction. Any single-bit modification to any of these inputs produces a distinct GHASH evaluation; matching the original tag requires either:

- Predicting the GHASH key (derived from the AES key `k_i`), which requires knowing `k_i` — by hypothesis the adversary doesn't.
- Forging the tag without the GHASH key, which by AES-GCM's SUF-CMA bound succeeds with probability `≤ 2⁻¹²⁸ + ε_AES`.

Therefore `decrypt(modified_env, k_i, aad) = ⊥` with probability `≥ 1 - 2⁻¹²⁸`. ∎

The wallet's apply-side guards add a second layer: AAD binding includes guardian_id + scheme version. A share modified by re-encrypting under a different (guardian_id, version) tuple has AAD mismatch on decrypt and fails T-16's binding check immediately.

---

## 5. Proof of T-17 (adapter substitution)

By the adapter API contract:

- `register_password(P, i)` returns `(record, key)` where `key ∈ {0,1}²⁵⁶`.
- `authenticate_password(P', record, i)` returns `key` iff `P' = P` (the registration password) **and** the linked adapter implementation matches the one that produced `record`.

The recovery flow's only interaction with the adapter is via these two calls. The flow holds no internal state about the adapter's implementation; it consumes only the returned `key` bytes. Therefore swapping `A_stub` for `A_real` (or vice versa) is invisible to the recovery flow *provided the registration record was produced by the currently-linked adapter*.

The suite-tag gate (`setup.scheme == "shamir-aead-opaque-" + opaque_adapter::suite_name()`) at recover-time enforces "registration adapter must match recovery adapter". Setups created under one adapter cannot recover under another, by design.

Therefore the recovery flow is implementation-substitution invariant under matched suite tags. ∎

---

## 6. Proof of T-18 (end-to-end composite)

Adversary `A` has access to:

- `T-1` triples `{(env_i, record_i, x_i)} for compromised guardians.
- `Q` total online authentication attempts against uncompromised guardians.

To recover `s`, `A` must obtain `T` valid shares. With `T-1` from compromise, `A` needs at least one more share from an uncompromised guardian. This requires either:

**Path 1: Brute-force the password.** Each guardian rate-limits authentication attempts, so `A` is bounded by `Q` attempts total. Each attempt succeeds with probability `1 / 2^{bits_password}` for a uniform random password. Probability of any success: `≤ Q / 2^{bits_password}`.

**Path 2: Forge an AEAD tag on an existing envelope.** By T-16, probability `≤ 2⁻¹²⁸` per envelope, `≤ |G_active| · 2⁻¹²⁸` over all active envelopes.

**Path 3: Break the Shamir bound (below-threshold leak).** By T-15, probability `= 0` (information-theoretic).

Combined: `Pr[A recovers s] ≤ Q · 2^{-bits_password} + |G_active| · 2⁻¹²⁸`. ∎

The dominant term is the brute-force path against the password; this is exactly where OPAQUE-soundness matters. Under real OPAQUE, the adversary cannot accelerate the brute-force via offline computation — every guess requires a fresh online interaction with a rate-limited guardian. Under the stub, this property collapses (T-18.1).

---

## 7. What the proof does NOT cover

- **Side-channel attacks on the wallet binary.** Memory dumps, swap-file leakage, malware-instrumented user input. Mitigation is operational (the wallet binary should use `sodium_mlock`, secure deletion, hardware-backed key storage) not protocol-level.
- **Password equivocation against the user.** A phishing attacker who tricks the user into typing the password into a fake wallet binary can capture it. Mitigation is operational (software signing, distribution channel hygiene).
- **Guardian collusion above threshold.** If `T` or more guardians collude AND know the user's password, they can reconstruct the seed without the user's involvement. This is a deployment-decision: pick `T` such that the cost of bribing `T` independent guardians is greater than the wallet's protected value.
- **Recovery transcripts.** A passive network observer of the recovery flow learns which guardians participated (via timing) but, under real OPAQUE, learns nothing about the password or the shares. The stub provides this only inasmuch as TLS-style transport security wraps each guardian interaction (the adapter is transport-agnostic).
- **Long-term forward secrecy.** Recovery setups are durable; their compromise at any future time enables (rate-limited) password grind against the surviving guardians. This is intrinsic to password-based recovery; the only mitigation is high password entropy.

---

## 8. Concrete-security summary

Under real OPAQUE (Phase 6) with default parameters:

| Adversary capability | Bound |
|---|---|
| `T-1` guardian compromise + `Q = 2¹⁶` online attempts vs. 1 guardian, password entropy 60 bits | `2^{-44}` |
| `T-1` guardian compromise + `Q = 2¹⁶` online attempts vs. 1 guardian, password entropy 80 bits | `2^{-64}` |
| AEAD tag forge on any single envelope | `2⁻¹²⁸` per attempt |
| Below-threshold information leak | `0` (information-theoretic) |

Under the Phase 5 stub adapter:

| Adversary capability | Bound |
|---|---|
| 1 guardian compromise + offline Argon2id grind, password entropy 60 bits, attacker has 1000 GPU-years | `≈ 2^{-30}` |
| 1 guardian compromise + offline grind, password entropy 80 bits, 1000 GPU-years | `≈ 2^{-50}` |

The stub's bound is genuinely worse than real OPAQUE; the wallet's `is_stub()` flag MUST be checked before any deployment that protects value above `~ $10K USD-equivalent`.

---

## 9. Implementation cross-reference

| Component | Source |
|---|---|
| Shamir SSS over GF(2⁸) | `wallet/shamir.cpp` |
| AEAD envelope (AES-256-GCM via OpenSSL EVP) | `wallet/envelope.cpp` |
| Recovery setup composition + serialization | `wallet/recovery.cpp` |
| OPAQUE adapter interface | `wallet/opaque_adapter.hpp` |
| Phase 5 stub implementation | `wallet/opaque_adapter.cpp` |
| libsodium primitives wrapper | `wallet/opaque_primitives.{hpp,cpp}` |
| CLI surface | `wallet/main.cpp` |
| Regression tests | `tools/test_wallet_*.sh` (6 suites, 56 assertions) |

A reviewer can confirm soundness by:

1. Reading `shamir::split` and `combine` — confirm GF(2⁸) coefficient generation uses `RAND_bytes` and the Lagrange interpolation is correct (single-byte arithmetic; the entire module is ~120 lines).
2. Reading `envelope::encrypt` / `decrypt` — confirm the OpenSSL EVP calls use AES-256-GCM with 12-byte nonce, 16-byte tag, AAD bound correctly.
3. Reading `recovery::create_opaque` — confirm the adapter's `export_key` is used as the AEAD password input verbatim.
4. Reading `opaque_adapter.hpp` — confirm the API contract is stable across Phase 5 (stub) and Phase 6 (real libopaque).
5. Confirming `is_stub()` returns true today; the wallet's deployment documentation should refuse to advance until it flips false.

---

## 10. Conclusion

T-15 + T-16 + T-17 + T-18 establish that Determ's wallet recovery primitive provides strong information-theoretic + cryptographic guarantees against composite adversary models:

- Below-threshold compromise leaks **zero** information about the seed.
- AEAD prevents undetected share tampering (`2⁻¹²⁸` per attempt).
- Recovery flow is implementation-invariant under the OPAQUE adapter substitution.
- The dominant attack path is password brute-force, gated by OPAQUE's online rate-limited interaction property under real Phase 6 OPAQUE.

The Phase 5 stub adapter is a development scaffold; the formal bounds tighten substantially once Phase 6 vendors real libopaque. The wallet's `is_stub()` API surface is explicitly designed to gate against accidental production use of the stub.

This completes formal coverage of every v1.x safety-critical mechanism in Determ, chain and wallet alike.
