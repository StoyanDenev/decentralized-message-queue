# FA12 — Wallet recovery soundness (A2)

This document proves that Determ's wallet recovery primitive — distributed Shamir secret sharing layered with passphrase-derived AEAD envelopes — preserves the user's Ed25519 seed under composable adversary models. The argument has three layers:

1. **Shamir** — below-threshold compromise leaks zero information about the secret.
2. **AEAD envelope** — per-share tampering is cryptographically detectable.
3. **Compositional** — the two-layer stack inherits the strongest of each layer's bounds, gated by passphrase entropy.

The wallet ships in a single recovery mode: **passphrase-direct**. Each share envelope is unwrapped with a key derived from the user's passphrase via PBKDF2-HMAC-SHA-256, using a per-envelope random salt, and sealed under AES-256-GCM with a guardian-bound AAD.

**De-scope note.** Earlier drafts of this proof documented a four-layer stack whose third layer was an OPAQUE guardian-AKE adapter (password-authenticated key exchange offering online-only, rate-limited password grind). That path — the `--scheme opaque` branch, `recovery::create_opaque`, `RecoverySetup.opaque_records`, the `opaque_adapter` interface, and the suite-tag mismatch gate — was **de-scoped and deleted** per `DECISION-LOG.md` (2026-07-03). Recovery is now passphrase-only. The soundness argument below covers exactly the shipped passphrase path.

**Companion documents:** `Preliminaries.md` (F0); `EconomicSoundness.md` (FA11) for the chain-side seed-protection context.

---

## 1. Mechanism summary

### Setup (`create-recovery` → `recovery::create`)

Inputs: 32-byte Ed25519 seed `s`, passphrase `P`, threshold `T`, share count `N`, optional pubkey checksum `c_pub`.

1. Compute Shamir shares `(x_i, y_i)` for `i ∈ {1..N}` with threshold `T` over GF(2⁸) such that any `T` shares reconstruct `s` and any `T-1` reveal zero information.
2. For each `i ∈ {0..N-1}`:
   - Draw a fresh random salt `salt_i` and derive an unwrap key `k_i = PBKDF2-HMAC-SHA-256(P, salt_i, iters)`.
   - Encrypt `env_i = AES-256-GCM(key=k_i, nonce=fresh, aad=DWR1‖i‖v, pt=y_i)`, where `v` is the setup version and `i` is the guardian id.
3. Output `RecoverySetup{version, scheme="shamir-aead-passphrase", T, N, |s|, [x_i], [env_i], c_pub}`. Each `env_i` carries its own `salt_i`, `nonce`, `iters`, and `aad` inline (see `envelope::serialize`).

### Recovery (`recover` → `recovery::recover`)

Inputs: `RecoverySetup`, passphrase `P`, guardian indices `G ⊆ {0..N-1}` with `|G| ≥ T`.

1. For each `i ∈ G`, recompute `aad = DWR1‖i‖v` and derive `k'_i = PBKDF2(P, env_i.salt, env_i.iters)`.
2. Decrypt `y'_i = AES-256-GCM-Decrypt(env_i, k'_i, aad)`. Skip that slot if the passed AAD does not match the envelope's stored AAD, or if the AEAD tag check fails (wrong passphrase or tampered slot).
3. If `|{successful slots}| < T`, return failure.
4. Apply Shamir Lagrange interpolation at `x = 0` over the recovered `(x_i, y'_i)` pairs to obtain candidate secret `s'`.
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

**Theorem T-17 (End-to-end recovery soundness under composite adversary).** Let an adversary `A` simultaneously:

1. Compromise up to `T-1` guardians (recover their stored `(env_i, x_i)` data).
2. Obtain the remaining `N-(T-1)` envelopes' ciphertext (e.g. from a leaked setup blob) but **not** the passphrase `P`.

Under T-15, T-16, and:

- **(PW-entropy)** The passphrase `P` is drawn from a distribution with `bits_password` bits of min-entropy.

The probability of `A` recovering the Ed25519 seed satisfies:

```
Pr[A recovers s] ≤ Q · 2^(-bits_password) / KDF_cost  +  N · 2⁻¹²⁸
```

where `Q` is the adversary's offline PBKDF2 guess budget, `KDF_cost` is the per-guess PBKDF2-HMAC-SHA-256 work factor (`iters` HMAC evaluations), and `N` is the total envelope count.

For a high-entropy passphrase (`≥ 80 bits`) the bound is dominated by `Q · 2⁻⁸⁰ / KDF_cost` — strongly negligible for any realistic offline adversary budget. Because recovery is passphrase-only, the passphrase entropy is the sole gate on the dominant attack path; there is no online guardian rate-limit backstop. Operators MUST provision the passphrase accordingly (see §7).

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

The wallet's recover-side guards add a second layer: the AAD binds `DWR1‖guardian_id‖version` (`recovery::make_aad`), and `envelope::decrypt` explicitly rejects any envelope whose stored AAD does not match the AAD recomputed for its slot. A share re-encrypted under a different `(guardian_id, version)` tuple therefore fails the AAD equality check before the GCM tag is even consulted, and fails T-16's binding check regardless.

---

## 5. Proof of T-17 (end-to-end composite)

Adversary `A` has access to:

- `T-1` pairs `{(env_i, x_i)}` for compromised guardians.
- The remaining envelopes' ciphertext, but not the passphrase `P`.

To recover `s`, `A` must obtain `T` valid shares. With `T-1` from compromise, `A` needs at least one more share. This requires either:

**Path 1: Recover the passphrase.** Every envelope's unwrap key is `k_i = PBKDF2-HMAC-SHA-256(P, salt_i, iters)`. There is no online oracle to gate guessing — `A` may grind offline. Each guess costs one PBKDF2 evaluation (`iters` HMAC calls) and succeeds with probability `1 / 2^{bits_password}` for a passphrase of `bits_password` bits of min-entropy. Over an offline budget of `Q` guesses, the probability of any success is `≤ Q · 2^{-bits_password} / KDF_cost` when the budget is expressed in raw HMAC operations, i.e. the PBKDF2 iteration count multiplies the attacker's cost per guess.

**Path 2: Forge an AEAD tag on an existing envelope.** By T-16, probability `≤ 2⁻¹²⁸` per envelope, `≤ N · 2⁻¹²⁸` over all `N` envelopes.

**Path 3: Break the Shamir bound (below-threshold leak).** By T-15, probability `= 0` (information-theoretic).

Combined: `Pr[A recovers s] ≤ Q · 2^{-bits_password} / KDF_cost + N · 2⁻¹²⁸`. ∎

The dominant term is the passphrase-grind path. Because the recovery scheme is passphrase-only, the sole defenses on that path are (a) the passphrase's min-entropy and (b) the PBKDF2 iteration count, which linearly inflates the attacker's per-guess cost. There is no rate-limited online guardian to cap `Q`; `Q` is bounded only by the adversary's compute budget. This is intrinsic to offline passphrase-based recovery (see §6, forward secrecy).

---

## 6. What the proof does NOT cover

- **Side-channel attacks on the wallet binary.** Memory dumps, swap-file leakage, malware-instrumented user input. Mitigation is operational (secure deletion, hardware-backed key storage) not protocol-level.
- **Passphrase equivocation against the user.** A phishing attacker who tricks the user into typing the passphrase into a fake wallet binary can capture it. Mitigation is operational (software signing, distribution channel hygiene).
- **Guardian collusion above threshold.** If `T` or more guardians collude AND know the user's passphrase, they can reconstruct the seed without the user's involvement. This is a deployment decision: pick `T` such that the cost of colluding `T` independent guardians is greater than the wallet's protected value.
- **Low-entropy passphrases.** The entire T-17 bound collapses toward `1` as `bits_password → 0`. Because recovery is passphrase-only with offline grinding, a weak passphrase is the dominant risk and there is no online rate-limit to compensate. The PBKDF2 iteration count is the only per-guess cost multiplier; high passphrase entropy is mandatory.
- **Long-term forward secrecy.** Recovery setups are durable; their compromise at any future time enables offline passphrase grind against the leaked envelopes. This is intrinsic to passphrase-based recovery; the only mitigations are high passphrase entropy and a large PBKDF2 iteration count.

---

## 7. Concrete-security summary

Under the shipped passphrase scheme with default parameters:

| Adversary capability | Bound |
|---|---|
| `T-1` guardian compromise + offline grind, passphrase entropy 60 bits, `Q = 2⁴⁰` PBKDF2 guesses, `iters` normalized | `≈ 2^{-20}` (dominated by `Q · 2⁻⁶⁰`) |
| `T-1` guardian compromise + offline grind, passphrase entropy 80 bits, `Q = 2⁴⁰` PBKDF2 guesses, `iters` normalized | `≈ 2^{-40}` |
| AEAD tag forge on any single envelope | `2⁻¹²⁸` per attempt |
| Below-threshold information leak | `0` (information-theoretic) |

The bound is dominated by the passphrase-grind path in every row; the PBKDF2 iteration count `iters` multiplies the attacker's per-guess cost and so effectively shifts `Q` downward by `log₂(iters)` bits. A passphrase of `≥ 80` bits of min-entropy keeps the seed strongly protected against any realistic offline adversary budget.

---

## 8. Implementation cross-reference

| Component | Source |
|---|---|
| Shamir SSS over GF(2⁸) | `wallet/shamir.cpp` |
| AEAD envelope (AES-256-GCM + PBKDF2-HMAC-SHA-256 via OpenSSL EVP) | `wallet/envelope.cpp` |
| Recovery setup composition + serialization | `wallet/recovery.cpp` |
| CLI surface (`create-recovery` / `recover`, `--scheme passphrase`) | `wallet/main.cpp` |
| Regression tests | `tools/test_wallet_*.sh` |

A reviewer can confirm soundness by:

1. Reading `shamir::split` and `combine` — confirm GF(2⁸) coefficient generation uses `RAND_bytes` and the Lagrange interpolation is correct (single-byte arithmetic; the entire module is compact).
2. Reading `envelope::encrypt` / `decrypt` — confirm the OpenSSL EVP calls use AES-256-GCM with 12-byte nonce, 16-byte tag, per-envelope random salt, `PKCS5_PBKDF2_HMAC` key derivation, and AAD bound correctly (including the recover-side AAD equality check).
3. Reading `recovery::create` — confirm the passphrase is threaded verbatim into `envelope::encrypt` as the KDF input, and that `RecoverySetup` carries only `{version, scheme, threshold, share_count, secret_len, guardian_x, envelopes, pubkey_checksum}`.
4. Confirming `recovery::recover` skips (does not abort) individual slots on AAD/tag failure and reconstructs only when `≥ T` slots succeed, with the optional pubkey-checksum gate as a final defense-in-depth check.

---

## 9. Conclusion

T-15 + T-16 + T-17 establish that Determ's wallet recovery primitive provides strong information-theoretic + cryptographic guarantees against composite adversary models:

- Below-threshold compromise leaks **zero** information about the seed.
- AEAD prevents undetected share tampering (`2⁻¹²⁸` per attempt), with guardian-bound AAD blocking cross-slot substitution.
- The dominant attack path is offline passphrase grind, gated solely by passphrase min-entropy and the PBKDF2 iteration count.

The OPAQUE guardian-AKE path was de-scoped and deleted (`DECISION-LOG.md`, 2026-07-03); recovery is passphrase-only. Deployments MUST provision high-entropy passphrases, because there is no online rate-limit backstop on the grind path.

This completes formal coverage of the wallet recovery mechanism in Determ.
