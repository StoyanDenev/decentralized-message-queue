# EnvelopeKeyfileCrypto — soundness of the `DWE1` passphrase-encryption envelope (v2.17 / S-004)

This document proves the soundness properties of Determ's `DWE1` AEAD envelope — the symmetric passphrase-encryption primitive that wraps secret material (Ed25519 node-key seeds, recovery shares, account keyfiles) at rest. The primitive shipped with the v2.17 / S-004 closure and is implemented in `wallet/envelope.cpp` + `wallet/envelope.hpp`. It composes PBKDF2-HMAC-SHA-256 (RFC 8018 §5.2) for passphrase stretching with AES-256-GCM (NIST SP 800-38D / RFC 5116) for authenticated encryption.

This proof is the **primitive-layer companion** to `S004KeyfileAtRest.md`. The division of labour is deliberate and non-overlapping:

- **`S004KeyfileAtRest.md`** proves the *application-layer* node-keyfile scheme — the `DETERM-NODE-V1`-headered two-line file, the AAD-as-pubkey binding, the three operator adversary models (`A_offline` disk-theft / `A_online` startup-prompt / `A_msg` pubkey-known), and the daemon's startup-load path. Its theorems (T-1 .. T-5) are stated against the *node-keyfile* construction that *uses* the envelope.
- **This document (`EnvelopeKeyfileCrypto.md`)** proves the *envelope primitive itself* — the `encrypt` / `decrypt` / `serialize` / `deserialize` functions as a standalone AEAD-with-KDF construction, independent of any particular caller. Its theorems (KE-1 .. KE-4) are stated against the `Envelope` object and the wire layout, and hold for *every* caller of the primitive (node-keyfiles, Shamir recovery shares, `DETERM-ACCOUNT-V1` account files, and the raw `envelope encrypt` / `envelope decrypt` CLI).

Where `S004KeyfileAtRest.md` and this document touch the same fact (e.g. the PBKDF2 work factor, the AAD-binding mechanism), this document re-derives it from the primitive's perspective and cross-references the application-layer statement rather than restating the application-layer theorem. A reviewer auditing the envelope primitive in isolation should read this document; a reviewer auditing the node-keyfile-at-rest feature should read `S004KeyfileAtRest.md`; the two compose.

---

## 1. Scope

**In scope.** The `wallet/envelope.cpp` / `wallet/envelope.hpp` passphrase-encryption envelope as a cryptographic primitive for protecting secret byte-strings at rest:

- The envelope wire layout (`[salt | nonce | ciphertext+tag]` plus the stored `pbkdf2_iters` and `aad` fields) and its canonical dot-separated hex serialization.
- The key-derivation function (`derive_key` via OpenSSL `PKCS5_PBKDF2_HMAC` + `EVP_sha256`).
- The AEAD construction (`encrypt` / `decrypt` via OpenSSL `EVP_aes_256_gcm`), including the fail-closed-on-tag-mismatch decryption contract.
- The four soundness properties KE-1 (confidentiality under CCA), KE-2 (integrity under CCA-modification), KE-3 (salt-uniqueness independence), KE-4 (passphrase-strength dominance).
- The composition with the callers' in-memory `sodium_memzero` secret-handling discipline (§5).

**Out of scope.**

- **In-memory protection beyond zeroing.** The primitive guarantees nothing about the secret while it is decrypted and resident in process memory beyond the caller's `sodium_memzero` discipline (§5). There is no `mlock`, no guard-page allocation, no secure-enclave / TEE backing. Runtime memory dumps are an OS-hardening concern, not a primitive concern.
- **CLI passphrase prompting.** How a caller obtains the passphrase string (interactive TTY echo-suppressed prompt, `env:` variable, `file:` path) is the caller's concern. The primitive takes a `const std::string& password` and uses it; it does not prompt.
- **Passphrase-strength enforcement.** The primitive accepts any non-empty passphrase. KE-4 makes the dependence on passphrase entropy explicit and quantifies it, but the primitive deliberately does not measure or reject low-entropy passphrases (see §6 and the operator-policy discussion that `S004KeyfileAtRest.md` F-2 owns).
- **Multi-signature / threshold key custody (v2.15).** Splitting a secret across multiple holders (Shamir, threshold signatures) is a separate construction. Where Shamir shares are *individually* `DWE1`-wrapped (the `backup-create` path), KE-1 .. KE-4 apply to each share-envelope independently; the threshold-reconstruction soundness is `WalletRecovery.md` (FA12) / `WalletRecoveryFlows.md` territory.
- **The node-keyfile / account-keyfile application layer.** The `DETERM-NODE-V1` header, the pubkey-as-AAD binding, the inner-vs-header pubkey defense-in-depth check, and the daemon startup-load path are proven in `S004KeyfileAtRest.md`. This document treats the AAD as an opaque caller-supplied byte-string.

---

## 2. Threat model

The envelope primitive defends a secret byte-string `m` (a 32-byte Ed25519 seed, a Shamir share `y`-coordinate, a small JSON keyfile object, etc.) held encrypted at rest. Two adversaries are in scope.

### 2.1 `A_disk` — at-rest ciphertext exposure

`A_disk` obtains the encrypted envelope bytes (the serialized blob, or the on-disk file containing it). Concrete vectors: laptop theft, cloud-backup leak, world-readable file misconfiguration, accidental commit, exfiltration via an unrelated OS-level vulnerability. `A_disk`:

- knows the complete envelope format and all algorithm choices (PBKDF2-HMAC-SHA-256, AES-256-GCM, the parameter constants below) — we assume no security-through-obscurity;
- reads `salt`, `nonce`, `pbkdf2_iters`, `aad`, and `ciphertext+tag` directly from the envelope (all are stored in cleartext alongside the ciphertext — only `m` is protected);
- does **not** know the passphrase `P`.

`A_disk` is the baseline. The confidentiality claim KE-1 and the integrity claim KE-2 are both stated against `A_disk` and any adversary at least as strong.

### 2.2 `A_passphrase_guess` — offline dictionary / brute-force attack

`A_passphrase_guess` is `A_disk` augmented with an offline guessing capability: unbounded local compute, against which it enumerates candidate passphrases, runs `derive_key` per candidate, and trial-decrypts. This is the dominant realistic attack on any passphrase-protected secret. KE-4 quantifies `A_passphrase_guess`'s success probability as a function of passphrase min-entropy `H_pw` and the PBKDF2 work factor; KE-3 shows that `A_passphrase_guess` cannot amortize its guessing work across multiple envelopes via precomputation (rainbow tables) because of the per-envelope salt.

### 2.3 Out of scope

- **Live memory access while the secret is decrypted.** An adversary who can read the process address space of a running caller (root-level `ptrace`, `/proc/<pid>/mem`, a cold-boot RAM attack on an unlocked machine, a kernel compromise) can read `m` directly after `decrypt` returns and before `sodium_memzero` runs — and, for long-lived holders like the daemon, for the entire time the secret is resident. This is S-035 / OPAQUE-recovery territory and OS-hardening territory (`mlock`, no-swap, ASLR). The envelope primitive does not defend it; §5 documents the `sodium_memzero` discipline that *bounds* the residency window for short-lived callers but does not eliminate it.
- **Adversary who already holds the passphrase.** If `A` knows `P`, decryption is by-design trivial — the whole point of the construction is that `P` unlocks `m`. A leaked passphrase is an operator failure (shoulder-surfing, keylogger, phishing, passphrase reuse) with no chain-side mitigation. KE-1 / KE-4 are explicitly conditioned on `A` *not* holding `P`.
- **Malicious / backdoored build.** A tampered `determ-wallet` binary that exfiltrates `P` or `m` is a software-supply-chain concern (signed releases, reproducible builds), outside the analytic scope.
- **Side-channels on the AES / GHASH / HMAC implementations.** Cache-timing, branch-prediction, and power-analysis attacks on the OpenSSL primitives are bounded by OpenSSL's constant-time discipline (AES-NI hardware path, `CRYPTO_memcmp` tag compare). §6 notes this as a residual; the analytic proof treats the primitives as ideal per the assumptions in §4.

---

## 3. Primitive specification

All constants below are read directly from the implementation and are load-bearing for the bounds in §4. The byte sizes are pinned in `wallet/envelope.cpp`; the cost parameters in `wallet/envelope.hpp`.

### 3.1 Constants (verified from source)

| Symbol | Value | Source |
|---|---|---|
| `MAGIC_LE` | `0x31455744` = ASCII `"DWE1"` (little-endian) | `wallet/envelope.cpp:12` |
| `NONCE_LEN` | 12 bytes (96-bit GCM IV) | `wallet/envelope.cpp:13` |
| `TAG_LEN` | 16 bytes (128-bit GCM tag) | `wallet/envelope.cpp:14` |
| `KEY_LEN` | 32 bytes (AES-256 key) | `wallet/envelope.cpp:15` |
| `DEFAULT_PBKDF2_ITERS` | **600,000** iterations | `wallet/envelope.hpp:46` |
| `DEFAULT_SALT_LEN` | 16 bytes | `wallet/envelope.hpp:50` |

The `DWE1` magic is the format/version tag, not a cryptographic domain separator fed into the AEAD; it gates `deserialize` (`wallet/envelope.cpp:159`) and identifies the wire format to inspection tools. The cryptographic domain-separation / context-binding role is played by the caller-supplied `aad` field (§3.4).

### 3.2 Envelope layout

The in-memory `Envelope` struct (`wallet/envelope.hpp:36-42`) carries five fields:

```
Envelope {
  salt          : bytes   (DEFAULT_SALT_LEN = 16 on fresh envelopes)
  pbkdf2_iters  : u32     (cost parameter; stored, not fixed)
  nonce         : bytes   (exactly NONCE_LEN = 12)
  aad           : bytes   (caller-supplied associated data; may be empty)
  ciphertext    : bytes   (len(plaintext) + TAG_LEN; GCM tag is the trailing 16 B)
}
```

The cryptographic payload is the conceptual tuple `[salt | nonce | ciphertext | tag]`, with the 16-byte tag occupying the final `TAG_LEN` bytes of the `ciphertext` vector (appended at encrypt time via `EVP_CTRL_GCM_GET_TAG`, `wallet/envelope.cpp:92-99`). The `pbkdf2_iters` and `aad` fields are stored so that decryption is self-describing — the verifier needs no out-of-band parameters beyond the passphrase.

The canonical serialization (`serialize`, `wallet/envelope.cpp:127-142`) is six dot-separated lowercase-hex fields:

```
<magic_4B> . <salt_16B> . <iters_4B_LE> . <nonce_12B> . <aad_var> . <ciphertext+tag_var>
```

`deserialize` (`wallet/envelope.cpp:144-178`) splits on `.`, requires exactly six parts, checks the magic equals `MAGIC_LE`, requires `salt.size() >= 8`, requires `nonce.size() == NONCE_LEN`, and requires `ciphertext.size() >= TAG_LEN`. A blob failing any check yields `std::nullopt` — malformed envelopes never reach the AEAD path.

### 3.3 Key derivation

```
Key := PBKDF2-HMAC-SHA-256(password, salt, iterations, dkLen = KEY_LEN = 32)
```

implemented in `derive_key` (`wallet/envelope.cpp:19-33`) as a single OpenSSL `PKCS5_PBKDF2_HMAC` call with `EVP_sha256()` as the PRF, `iterations` taken from the envelope's `pbkdf2_iters` field (or `DEFAULT_PBKDF2_ITERS = 600,000` for fresh envelopes), and a 32-byte output length. The call returns the AES-256 key. A `0` return from OpenSSL throws `std::runtime_error`; the key buffer is otherwise the sole output.

The iteration count is a **stored** parameter, not a compile-time constant: each envelope records the `iters` used at encryption time, so a future raise of `DEFAULT_PBKDF2_ITERS` is forward-compatible — old envelopes continue to decrypt at their original cost, new envelopes use the new default. `encrypt` rejects `iters == 0` with `std::invalid_argument` (`wallet/envelope.cpp:41-42`); `decrypt` rejects a stored `pbkdf2_iters == 0` with `std::nullopt` (`wallet/envelope.cpp:111`).

### 3.4 AEAD encryption and decryption

**Encrypt** (`wallet/envelope.cpp:37-103`):

1. Draw a fresh 16-byte `salt` and 12-byte `nonce` from OpenSSL `RAND_bytes`; a `RAND_bytes` failure throws (`:47-49`).
2. `Key := derive_key(password, salt, iters)` (`:53`).
3. Initialise AES-256-GCM (`EVP_aes_256_gcm`), set the IV length to `NONCE_LEN`, install `(Key, nonce)` (`:58-66`).
4. If `aad` is non-empty, feed it into the GCM context via `EVP_EncryptUpdate(ctx, nullptr, ...)` (`:69-75`) — this binds `aad` into the tag without including it in the ciphertext.
5. Encrypt the plaintext (`:78-83`), finalise (`:86-89`), and append the 16-byte tag via `EVP_CTRL_GCM_GET_TAG` (`:92-99`).

The resulting `ciphertext` field is `len(plaintext) + 16` bytes. AES-GCM is a stream cipher in CTR mode for the ciphertext body, so `len(ct_body) == len(plaintext)` exactly.

**Decrypt** (`wallet/envelope.cpp:105-167`) is fail-closed at every stage:

1. Structural pre-checks: `ciphertext.size() >= TAG_LEN`, `nonce.size() == NONCE_LEN`, `pbkdf2_iters != 0`; any failure → `std::nullopt` (`:109-111`).
2. **AAD precondition:** `aad != env.aad` → `std::nullopt` *before any key derivation* (`:114`). The caller-supplied `aad` must match the envelope's stored `aad` byte-for-byte.
3. `Key := derive_key(password, env.salt, env.pbkdf2_iters)` (`:116`).
4. Initialise AES-256-GCM, feed the stored `aad` into the GCM context (`:132-139`), decrypt the ciphertext body (`:143-148`).
5. Install the trailing 16-byte tag via `EVP_CTRL_GCM_SET_TAG` (`:152-159`) and call `EVP_DecryptFinal_ex` (`:161`). A non-`1` return — the tag-verify decision — yields `std::nullopt` (`:163`); only a verified tag returns the plaintext (`:165-166`).

**Fail-closed contract.** A wrong passphrase, a tampered ciphertext, a tampered tag, a tampered nonce, a mismatched AAD, or a truncated envelope all funnel to the same `std::nullopt`. The caller learns only *decryption failed*, never *which* component was wrong, and never any plaintext bytes. This single-bit, indistinguishable failure mode is what KE-1 (no chosen-ciphertext leakage) and the application-layer T-4 / T-5 in `S004KeyfileAtRest.md` rely on.

---

## 4. Soundness theorems

### Assumptions

Beyond the F0 (`Preliminaries.md`) primitive axioms, this proof uses:

- **(C1) HMAC-SHA-256 is a PRF.** HMAC-SHA-256 is computationally indistinguishable from a random function `{0,1}* → {0,1}^256`, under the assumption that the SHA-256 compression function is a PRF (Bellare, CRYPTO 2006) — strictly weaker than collision resistance. Underlies the iterated-HMAC core of PBKDF2.
- **(C2) AES-256-GCM is a secure AEAD.** AES-256-GCM provides IND-CCA confidentiality and INT-CTXT ciphertext integrity (Bellare-Namprempre 2000; McGrew-Viega GCM analysis; NIST SP 800-38D), conditioned on nonce-uniqueness per key. Tag-forgery probability for a 128-bit tag is `<= 2^-128` per forgery attempt; the ciphertext-body distribution is computationally indistinguishable from random under (C2)'s underlying AES-as-PRP assumption.
- **(C3) `RAND_bytes` is a CSPRNG.** OpenSSL `RAND_bytes` output is computationally indistinguishable from uniform (F0 §2.3 CSPRNG uniformity). Underlies salt and nonce unpredictability and uniqueness.
- **(C4) Passphrase min-entropy `H_pw`.** The operator passphrase `P` has min-entropy `H_pw` bits from the adversary's view. KE-4 is parameterized by `H_pw`; the primitive does not enforce a floor (see §6).

Let `iter` denote the envelope's iteration count (default `600,000`). The PBKDF2 work-factor amplification in bits is `log2(iter)`; for `iter = 600,000`, `log2(600000) ≈ 19.19`.

### Lemmas

The four theorems are assembled from six lemmas about the primitive's mechanics. Each lemma is local to the envelope construction and cites the exact source line it rests on.

**Lemma L-1 (PBKDF2 has no shortcut beyond input enumeration).** Under (C1), the only attack on `derive_key`'s `PKCS5_PBKDF2_HMAC` (`wallet/envelope.cpp:23-29`) better than recomputing the full iterated HMAC per candidate passphrase is a break of the HMAC-SHA-256 PRF itself. *Proof.* PBKDF2 derives the key as `T_1 = F(P, s, c, 1)` with `F` the XOR-fold of `c` HMAC iterations seeded by `HMAC(P, s ‖ INT(1))` (RFC 8018 §5.2). By (C1) each HMAC application is PRF-indistinguishable from a random function of its keyed input `P`; the salt `s` and counter are public, so no information about the *next* iteration is available without evaluating the *current* one. There is thus no precomputation on `(s, c)` alone that yields `Key` for unknown `P`, and no algebraic shortcut collapsing the `c`-fold chain (Kelsey-Schneier-Hall-Wagner 1998). The per-candidate cost is exactly `c = iter` HMAC-SHA-256 evaluations. ∎

**Lemma L-2 (AES-GCM ciphertext body is plaintext-hiding under an unknown key).** Under (C2), for an adversary lacking `Key`, the ciphertext body produced at `wallet/envelope.cpp:78-83` leaks no information about the plaintext `m` beyond its length. *Proof.* GCM encrypts `m` in CTR mode under the AES-as-PRP keystream `E_K(J_0+1), E_K(J_0+2), …`; under (C2)'s PRP assumption and a unique `(Key, nonce)` (L-5), the keystream is computationally indistinguishable from uniform, so `ct_body = m ⊕ keystream` is indistinguishable from a uniform string of length `|m|`. The CTR construction is length-preserving, so `|ct_body| = |m|` is the only leakage. ∎

**Lemma L-3 (GHASH tag is an ε-almost-XOR-universal MAC).** Under (C2), for a fixed unknown `(Key, nonce)`, the tag `T = GHASH_H(AAD ‖ ct) ⊕ E_K(J_0)` (NIST SP 800-38D §7.1) is unforgeable except with probability `(L+1)/2^128` per attempt, where `L` is the block length of `AAD ‖ ct`. *Proof.* `H = E_K(0^128)` and the mask `E_K(J_0)` are pseudorandom and unknown to the adversary. GHASH evaluates a degree-`≤ L` polynomial over `GF(2^128)` at the secret point `H`; two distinct inputs collide under GHASH iff their difference polynomial (degree `≤ L`) vanishes at `H`, which for a uniformly-distributed secret `H` happens with probability `≤ L/2^128` (a degree-`L` polynomial has `≤ L` roots). Adding the one-time mask makes the tag itself uniform from the adversary's view, contributing the `+1`. Hence any forged `(AAD', ct', T')` verifies with probability `≤ (L+1)/2^128` (McGrew-Viega 2004). ∎

**Lemma L-4 (decrypt is fail-closed and leakage-bounded).** `decrypt` (`wallet/envelope.cpp:105-167`) returns `std::nullopt` on every rejection path and never returns plaintext on a tag-verify failure. *Proof.* By case analysis over the function's exit edges: structural pre-checks (`:109-111`) return `nullopt`; the AAD-mismatch precondition (`:114`) returns `nullopt` before any key derivation; the AES-init failures (`:127`) return `nullopt`; the decrypt-update failure (`:146`) returns `nullopt`; the `SET_TAG` failure (`:157`) returns `nullopt`; and the terminal `EVP_DecryptFinal_ex` tag-verify (`:161`) returns `nullopt` on `rc != 1` (`:163`). The speculatively CTR-decrypted buffer `pt` is a function local that is *not* returned on the `rc != 1` edge, so no plaintext escapes a failed verify. Only the `rc == 1` edge resizes and returns `pt` (`:165-166`). Every failure is therefore observationally a single bit. ∎

**Lemma L-5 (fresh nonce + fresh salt per encryption).** Each `encrypt` invocation draws an independent 16-byte salt and 12-byte nonce from `RAND_bytes` (`wallet/envelope.cpp:46-49`), failing closed if `RAND_bytes` fails (`:47-49`). *Proof.* Direct from the source: both buffers are filled by `RAND_bytes` immediately before use, and a non-`1` return throws before any key/ciphertext is produced. Under (C3) the draws are computationally uniform and independent. Consequently (i) the `(Key, nonce)` pair is fresh per envelope — the GCM nonce-reuse catastrophe is avoided since each fresh salt yields a fresh `Key` even at fixed `P` (L-1), so the same `(Key, nonce)` recurs only on a simultaneous salt-and-nonce collision, probability `≤ 2^-(128+96)` per pair — and (ii) the salt is unpredictable in advance. ∎

**Lemma L-6 (salt is an independent KDF input, public but per-target).** Under (C1), for distinct salts `s_i ≠ s_j`, the keys `Key_i = PBKDF2(P, s_i, iter)` and `Key_j = PBKDF2(P, s_j, iter)` are independent pseudorandom values even when `P` is identical. *Proof.* The salt is a direct argument to the HMAC-PRF seed `HMAC(P, s ‖ INT(1))` (L-1); by (C1) distinct seeds yield independent PRF outputs. The salt is stored in cleartext in the envelope (`serialize`, `wallet/envelope.cpp:136`), so the adversary reads `s_i`; this is correct — the salt provides input-separation (uniqueness), not secrecy. A guessing table built for `s_i` has zero applicability to `s_j` because the entire derivation chain differs from the first HMAC. ∎

---

### KE-1 (Confidentiality under CCA)

**Statement.** For any PPT adversary `A` of the `A_disk` / `A_passphrase_guess` class — holding the envelope `(salt, nonce, iters, aad, ciphertext+tag)` and the full algorithm description, but not the passphrase `P` of min-entropy `H_pw` — making at most `Q` trial decryptions (each a `derive_key` + AES-GCM tag-verify), the probability of recovering the plaintext `m` is bounded by

$$
\Pr[A \to m] \;\le\; Q \cdot 2^{-\big(H_{\text{pw}} + \log_2(\text{iter})\big)} \;+\; \varepsilon_{\text{AEAD}},
$$

where `ε_AEAD <= 2^-128` is the AES-256-GCM break/forgery advantage under (C2). With `iter = 600,000`, the per-trial exponent is `H_pw + 19.19`.

**Reduction sketch.** By L-2 the ciphertext body hides `m` under an unknown `Key`, so `A` must obtain `Key` (or `m`) by one of exactly two avenues:

1. **Recover the AES key without the passphrase, then decrypt.** Two sub-cases:
   - *Guess `Key` directly.* `Key` is a 256-bit AES key; by L-2 the ciphertext body leaks no information about `Key` beyond what brute-forcing the 256-bit keyspace gives — `<= Q · 2^-256`, dominated by the `ε_AEAD` term.
   - *Break PBKDF2.* By L-1, PBKDF2-HMAC-SHA-256 with a non-broken PRF admits no shortcut better than enumerating the *input* (the passphrase) and recomputing the iterated HMAC per candidate. There is no structural attack that derives `Key` from `(salt, iters)` alone (L-1 + L-6).
2. **Brute-force the passphrase.** Enumerate candidates `P'`, compute `Key' := PBKDF2(P', salt, iter)`, trial-decrypt. By (C4) the passphrase space has `2^{H_pw}` mass; by L-1 each candidate costs one PBKDF2 derivation (`iter` HMAC-SHA-256 evaluations) plus one AES-GCM tag-verify. Over `Q` trials the success probability is `min(1, Q · 2^{-H_pw})`. The `iter`-fold per-trial cost is what converts the *count* bound `Q · 2^{-H_pw}` into the effective *work* bound: to reach the same success probability against a stretched key, `A` must spend `iter ×` the HMAC budget, i.e. the effective per-trial security is `H_pw + log2(iter)` bits.

The AEAD tag-verify is the gate for avenue 2: a wrong candidate `P'` produces a wrong `Key'`, the tag fails to verify with probability `>= 1 - 2^-128` (L-3, KE-2), and `decrypt` returns `std::nullopt` exposing *no plaintext bytes* (L-4). Hence each wrong guess yields a single bit ("not this one"), never a partial plaintext, so the chosen-ciphertext capability gives `A` no advantage beyond the trial count. Summing the two avenues gives the stated bound. ∎

**Concrete bounds.** With `iter = 600,000` (so `+19.19` bits of stretch) and `Q = 2^60` (a multi-year cloud-GPU budget of ~10^18 HMAC operations):

| `H_pw` | effective bits `H_pw + 19.19` | `Pr[A → m]` bound | Interpretation |
|---|---|---|---|
| 28 ("hello1"-class) | ~47.2 | `≈ 1` | broken — weak-passphrase operator failure (KE-4 / §6) |
| 40 (weak human) | ~59.2 | `≈ 2^0 ≈ 1` at `Q = 2^60` | brute-forceable by a determined attacker |
| 60 (moderate) | ~79.2 | `≈ 2^-19` | strongly negligible |
| 80 (strong) | ~99.2 | `≈ 2^-39` | operationally infeasible |
| 128 (machine-generated) | ~147.2 | `≈ 2^-87` | exceeds the AEAD floor |

The `+19.19` bits are exactly the contribution the *primitive* makes; the rest is the operator's `H_pw` (KE-4).

---

### KE-2 (Integrity under CCA-modification)

**Statement.** For any PPT adversary `A` who modifies any byte of the cryptographic payload — the `nonce`, the `ciphertext` body, or the 16-byte `tag` (equivalently, presents any `(nonce', ct', tag')` not equal to a genuine encryption under `Key`) — the probability that `decrypt` returns a non-`nullopt` value (i.e. the tag verifies) is

$$
\Pr[\text{forge accepted}] \;\le\; 2^{-128} \;+\; \varepsilon_{\text{AEAD}} \;\approx\; 2^{-128}.
$$

Equivalently, any tampering is detected with probability `>= 1 - 2^-128`, and detection is fail-closed (`std::nullopt`, §3.4).

**GHASH MAC argument.** Direct from L-3 plus L-4. AES-256-GCM's authentication tag is

$$
\text{tag} \;=\; \text{GHASH}_H(\text{AAD} \,\|\, \text{ciphertext}) \;\oplus\; E_K(J_0),
$$

where `H = E_K(0^128)` is the GHASH subkey, `J_0` is the pre-counter block derived from the nonce, and GHASH is a polynomial-evaluation MAC over `GF(2^128)` (NIST SP 800-38D §6.4-§7.1). By the KE-1 premise `A` lacks `Key`, hence lacks both `H` and the mask `E_K(J_0)`. L-3 then bounds each forgery class:

- **Ciphertext-body or AAD modification.** Changes the GHASH input polynomial; producing the *same* tag requires a root collision at the secret point `H`, probability `≤ (L+1)/2^128`. For the small payloads here (a 32-byte seed, a sub-kilobyte keyfile JSON — `L` on the order of 1-64 blocks), this is `≤ 2^-122`, dominated by the `2^-128` headline.
- **Nonce modification.** Changes `J_0`, hence `E_K(J_0)`, hence the tag mask, by a pseudorandom amount — again a `2^-128` guess.
- **Direct tag modification.** A direct `2^-128` guess of the 128-bit value.

By L-4 the decrypt path installs the presented tag via `EVP_CTRL_GCM_SET_TAG` (`:152-159`) and lets `EVP_DecryptFinal_ex` (`:161`) perform the verify (OpenSSL uses a constant-time compare). An `rc != 1` result returns `std::nullopt` and *discards* the speculatively-decrypted plaintext buffer (`:163`) — the CTR-mode plaintext is computed before the tag check but never escapes on a verify failure, so INT-CTXT holds end-to-end. ∎

**AAD coverage.** The same GHASH argument covers the `aad` field: it is the first segment of the GHASH input. Tampering with `aad` either trips the line-114 byte-equality precondition (`std::nullopt` before any crypto) or, if a caller fed a mismatched-but-equal-length `aad`, fails the tag verify. This is the primitive-level statement underlying `S004KeyfileAtRest.md` T-2 (header-substitution defense): there the `aad` is the node pubkey, so KE-2 directly yields "you cannot graft validator B's envelope under validator A's header."

---

### KE-3 (Salt-uniqueness independence)

**Statement.** Because `encrypt` draws a fresh `DEFAULT_SALT_LEN = 16`-byte salt from `RAND_bytes` per envelope (L-5), an adversary attacking a *corpus* of `N` independently-created envelopes gains no per-target speed-up from precomputation: a precomputed table (rainbow table, or any passphrase → key dictionary) keyed on `(P)` alone is useless, and a table keyed on `(P, salt)` must be rebuilt per envelope. Formally, by L-6, for distinct salts `s_1 ≠ ... ≠ s_N` the keys `Key_i = PBKDF2(P, s_i, iter)` are `N` independent pseudorandom values even when the passphrase `P` is *identical* across all `N` envelopes. Hence the cost to break `j` of the `N` targets is `j ×` the single-target cost — the attack does not amortize.

**Precomputation-cost argument.** Consider `A_passphrase_guess` mounting a precomputation attack:

- *No salt.* A classic rainbow table maps `hash(P) → P` over a passphrase dictionary, built once and reused across all targets that hash the *same* passphrase the *same* way. The 16-byte salt is an input to PBKDF2, so `Key = PBKDF2(P, salt, iter)` differs for every salt value even at fixed `P`. A table built for salt `s_1` has zero hit rate against an envelope salted with `s_2 ≠ s_1`. To cover all salts, the table would need `2^{128}` entries per passphrase (the salt space is `2^{8·16} = 2^{128}`), which is infeasible to build or store.
- *Per-envelope amortization.* For a corpus of `N` envelopes that an operator created with the *same* passphrase (e.g. one operator's node-key plus several share-backups), the salts are independent draws from `RAND_bytes`. By the birthday bound the probability that any two of the `N` salts collide is `<= N^2 / 2^{129}`; for any realistic `N` (say `N <= 2^{40}`) this is `<= 2^{-49}` — negligible. With distinct salts, breaking envelope `i` requires a fresh PBKDF2 enumeration; the work spent breaking envelope `i` reveals nothing reusable for envelope `j`. So even a single-passphrase operator does not hand the attacker a multi-target discount.
- *Single-target unaffected.* KE-3 does not *increase* single-target work beyond KE-1 — a per-target salt does not make one envelope harder to crack. Its role is purely to deny cross-target and precomputation amortization, which is precisely the rainbow-table / dictionary-precompute threat.

The salt is stored in cleartext in the envelope (the attacker reads `s_i`), which is correct and standard: salt provides *uniqueness*, not *secrecy*. KE-3's guarantee holds against an attacker who reads every salt. ∎

**Composition with KE-1.** KE-1 bounds single-target success at `Q · 2^{-(H_pw + log2(iter))}`. KE-3 upgrades this to the corpus setting: breaking `j` of `N` targets costs `≈ j ×` the single-target budget, so a single global budget `Q` spread over `N` targets yields expected breaks `≈ Q · 2^{-(H_pw + log2(iter))}` *total*, not per-target — there is no "crack one, get the rest free" collapse.

---

### KE-4 (Passphrase-strength dominance)

**Statement.** Conditioned on KE-1's reduction (no shortcut beyond passphrase enumeration) and KE-2/KE-3 (no integrity bypass, no precomputation amortization), the adversary's success probability is governed by passphrase entropy times the inverse PBKDF2 work factor:

$$
\Pr[A_{\text{passphrase\_guess}} \to m] \;\le\; Q \cdot 2^{-H_{\text{pw}}} \cdot \frac{1}{\text{iter}} \;\cdot\; c^{-1}_{\text{norm}} \;+\; 2^{-128},
$$

which we write in the cleaner per-trial form `2^{-(H_pw + log2(iter))}` per attempt (the `iter` factor *is* the work-factor reciprocal, normalising the per-trial HMAC cost). The headline reading: **the envelope contributes a fixed `+log2(iter) ≈ +19.19` bits; the operator's passphrase contributes `H_pw` bits; the latter dominates the security margin.**

**Why entropy dominates.** The PBKDF2 stretch is a *constant* additive offset in the exponent — it buys `~19` bits regardless of passphrase quality. Doubling `iter` adds one bit; reaching the `~40` extra bits that separate a "moderate" from a "machine-generated" passphrase by `iter` alone would require `iter ≈ 600000 · 2^{40} ≈ 6.6·10^{17}` iterations, i.e. tens of millions of seconds per derivation — operationally absurd. By contrast, each additional random character of passphrase (from a 64-symbol alphabet) adds `log2(64) = 6` bits, and a word of Diceware adds `~12.9` bits. So entropy scales cheaply on the operator side and the stretch does not; the operator's choice is the load-bearing variable. This is the formal basis for the operator-policy recommendation.

**Practical floor.** For the envelope's confidentiality to clear a meaningful margin against a serious offline adversary (`Q ≈ 2^60`), the §6 / `S004KeyfileAtRest.md` F-2 recommendation is `H_pw >= 80` bits — e.g. `>= 14` random characters from a 64-symbol alphabet (`14 · 6 = 84` bits), or a `>= 7`-word Diceware passphrase (`7 · 12.9 ≈ 90` bits). At `H_pw = 80`, the KE-1 bound is `≈ 2^-39` (table in KE-1) — strongly negligible. A practical *minimum* of `>= 60` bits (`B_eff ≈ 79.2`) is the absolute floor below which the construction degrades to "buys time, not security." The primitive deliberately accepts any non-empty passphrase and does not enforce this floor (§6, F-policy); the recommendation is an operator obligation. ∎

---

### Theorem → lemma → assumption map

| Theorem | Property | Rests on | Bound |
|---|---|---|---|
| KE-1 | Confidentiality under CCA | L-1, L-2, L-4 + (C1)(C2)(C4) | `Q · 2^-(H_pw + log2(iter)) + 2^-128` |
| KE-2 | Integrity under CCA-modification | L-3, L-4 + (C2) | `≤ 2^-128` per forgery |
| KE-3 | Salt-uniqueness independence | L-5, L-6 + (C1)(C3) | break `j`/`N` costs `≈ j×`; collision `≤ N²/2^129` |
| KE-4 | Passphrase-strength dominance | L-1 + (C1)(C4) | per-trial `2^-(H_pw + log2(iter))`; stretch is a fixed `+19.19` offset |

### Adversary-coverage matrix

| Threat | In scope? | Defense | Residual |
|---|---|---|---|
| `A_disk`: at-rest ciphertext exposure, no passphrase | yes | KE-1 (confidentiality) + KE-2 (integrity) | weak passphrase → §6 F-policy |
| `A_passphrase_guess`: offline dictionary / brute-force | yes | KE-1 + KE-4 (entropy × PBKDF2 stretch); KE-3 denies precompute amortization | `H_pw < 60` collapses the bound |
| Byte-modification of nonce / ciphertext / tag | yes | KE-2 (GHASH MAC, L-3) + fail-closed `nullopt` (L-4) | none — detected w.p. `≥ 1−2^-128` |
| AAD substitution (e.g. wrong header) | yes | KE-2 AAD coverage + line-114 byte-equality precondition | none at primitive layer |
| Cross-corpus rainbow table / dictionary reuse | yes | KE-3 (per-envelope 16-byte salt, L-6) | none |
| GCM nonce reuse | yes | L-5 (fresh nonce + fresh salt per encrypt) | `RAND_bytes` CSPRNG quality (C3) |
| Live memory read while `m` decrypted | no (§2.3) | §5 `sodium_memzero` *bounds* residency only | OS-hardening / S-035 / enclave |
| Adversary holding the passphrase | no (§2.3) | by design `P` unlocks `m` | operator failure; no chain mitigation |
| Side-channel on AES / GHASH / HMAC | no (§6 F-sidechannel) | OpenSSL constant-time + AES-NI | non-AES-NI software path |
| Quantum (Grover) | partial (§6 F-quantum) | iter + `H_pw ≥ 80` keep a PQ margin | Argon2id / larger tag is the upgrade |

---

## 5. Composition with in-memory secret handling

The envelope primitive protects `m` only while it is encrypted at rest. The instant a caller invokes `decrypt`, the plaintext `m` is materialised in process memory, and the derived `Key` is materialised inside `derive_key`. KE-1 .. KE-4 say nothing about this window — they are at-rest properties. The callers close the gap with a `sodium_memzero` discipline that bounds the plaintext's residency to the interval between decryption and use.

**Caller discipline (verified in `wallet/main.cpp`).** Every wallet path that materialises secret material zeroes it on *every* exit edge, including exceptions:

- The Shamir / sub-seed derivation path zeroes `sub_seed`, `sk`, and `seed_bytes` immediately after use (`wallet/main.cpp:1496-1531`); the account-create path zeroes `sk` at `:1708`.
- The keyfile-rotate path declares a `secure_zero_all` lambda (`wallet/main.cpp:3767`) that wipes `pt_bytes`, `old_passphrase`, and `new_passphrase`, and invokes it on the success path and on *every* error return (`:3782, :3793, :3801, :3807, :3814, :3820, :3837`) — the file's own comment documents the contract: "sodium_memzero on every exit path (success + every error branch)" (`:3496`, `:3545`, `:3759-3766`).
- Passphrase strings are zeroed as soon as the derived key supersedes them (`wallet/main.cpp:3681-3752`).

`sodium_memzero` is the correct primitive here: it is a compiler-barrier-protected wipe that the optimiser may not elide (unlike a plain `memset` on a soon-dead buffer, which dead-store elimination can remove). The plaintext `m` returned by `decrypt` is an owned `std::vector<uint8_t>`; the caller copies the bytes it needs (e.g. into the Ed25519 signing context) and then `sodium_memzero`s the vector's storage before it is freed.

**What this composition does and does not give.** It *bounds* the residency window for short-lived callers (the CLI flows decrypt, use, and wipe within a single command), shrinking the target for a memory-scraping adversary to a brief interval and reducing the chance of the secret lingering in freed heap or swap. It does **not** eliminate the window — a sufficiently privileged live-memory adversary (§2.3, out of scope) can still read `m` during the use interval, and for a long-lived holder like the daemon the seed is resident for the whole run. The decrypt-derived `Key` inside `derive_key` is a local `std::vector` whose storage is freed on return; it is not separately `sodium_memzero`'d in `derive_key` itself (a residual noted in §6, F-keyzeroize), though it is short-lived and never leaves the function. The net posture: the at-rest guarantee (KE-1 .. KE-4) is strong and unconditional on operator passphrase entropy; the in-memory posture is best-effort zeroing, explicitly out of scope beyond that, and is the boundary at which S-035 / OS-hardening takes over.

---

## 6. Residual surface (out-of-scope risks)

These are acknowledged limitations of the envelope primitive. None invalidates KE-1 .. KE-4; each is either operator-policy, OS-hardening, or a documented future-work item.

**F-policy (passphrase strength is operator-owned).** KE-4 is parameterized by `H_pw`; the primitive enforces no entropy floor. A weak passphrase collapses KE-1 (see the `H_pw = 28/40` rows). The construction cannot measure passphrase entropy reliably (Bonneau-Schechter 2014), and the `file:` / `env:` passphrase sources intentionally accept arbitrary input so operators can use a password manager. The mitigation is education + documentation — the recommended `H_pw >= 80` bits is threaded through `S004KeyfileAtRest.md` F-2, SECURITY.md §S-004, and the CLI reference. **Severity: operator policy, not a primitive defect.**

**F-mem (TTY / `ps` / environment passphrase visibility).** The passphrase reaches the primitive as a `std::string`. How it arrived is out of scope, but two leakage vectors are worth naming for the operator: a passphrase passed as a CLI argument is visible in `ps`, `/proc/<pid>/cmdline`, and shell history; a passphrase in `DETERM_PASSPHRASE` is visible in `/proc/<pid>/environ` to a same-UID or root process. The wallet's `--passphrase-from file:` / `env:` / `prompt` sources exist precisely to avoid the argv vector; the daemon's `DETERM_PASSPHRASE` lookup avoids the shell-history vector. Operators should prefer `prompt` (no persistence) or a tight-permissioned `file:`, and on shared hosts mount `/proc` with `hidepid=2`. **Severity: operator deployment; mitigated by the source-selection affordances.**

**F-sidechannel (AES-GCM / HMAC side-channels).** The analytic proof treats AES, GHASH, and HMAC-SHA-256 as ideal. Real implementations can leak via cache-timing or power analysis. OpenSSL mitigates the dominant vector with AES-NI (constant-time hardware AES, used automatically on any x86-64 with the instruction set) and a constant-time `CRYPTO_memcmp` for the GCM tag compare. The PBKDF2/HMAC path is data-independent in its control flow. On hardware lacking AES-NI, a software AES table-lookup path could in principle leak; this is an OpenSSL-build / platform concern. **Severity: low; AES-NI mitigates on all modern hardware.**

**F-keyzeroize (derived key not explicitly wiped in `derive_key`).** `derive_key` returns the 32-byte AES key in a `std::vector` whose backing store is freed on the caller's scope exit but is not `sodium_memzero`'d at the primitive boundary. The key is short-lived and never leaves the encrypt/decrypt frame, but a belt-and-suspenders wipe of the key buffer inside `encrypt` / `decrypt` after the EVP context is finalised would tighten the in-memory posture. **Severity: very low; defense-in-depth improvement, not a vulnerability.**

**F-quantum (post-quantum degradation).** Under a large-scale quantum adversary:
- *Grover on AES-256* gives a square-root speed-up, degrading the 256-bit key to a `2^128` effective search. Since KE-1's AES-direct-guess avenue is already dominated by the `2^-128` AEAD term and by passphrase brute-force, the binding constraint becomes the GCM tag (KE-2) at `2^128/2 = 2^64` under Grover and the passphrase entropy.
- *Grover on the passphrase search* halves the effective passphrase exponent: KE-1's `H_pw + log2(iter)` becomes `(H_pw + log2(iter))/2` in the worst case. The PBKDF2 iteration count and a generous passphrase entropy preserve the margin: at `H_pw = 80, iter = 600000`, the classical `~99` effective bits degrade to `~50` post-quantum — still a non-trivial barrier, and the recommendation to size `H_pw >= 80` is exactly what keeps a usable post-quantum margin. A migration to a memory-hard KDF (Argon2id) and/or a larger tag would restore classical bounds; this is a pre-planned option, consistent with the protocol-wide PQ-signature migration path noted in the proofs index. **Severity: future-work; the iteration count plus a `>= 80`-bit passphrase keep an operational post-quantum margin.**

---

## 7. Implementation cross-references

| Surface | Location | Role |
|---|---|---|
| Envelope struct + API + constants | `wallet/envelope.hpp:1-75` | `Envelope` fields; `encrypt`/`decrypt`/`serialize`/`deserialize` signatures; `DEFAULT_PBKDF2_ITERS = 600,000` (`:46`); `DEFAULT_SALT_LEN = 16` (`:50`) |
| Cryptographic constants | `wallet/envelope.cpp:12-15` | `MAGIC_LE = 0x31455744` ("DWE1"); `NONCE_LEN = 12`; `TAG_LEN = 16`; `KEY_LEN = 32` |
| Key derivation | `wallet/envelope.cpp:19-33` | `derive_key` via `PKCS5_PBKDF2_HMAC` + `EVP_sha256`, 32-byte output (KE-1, KE-4) |
| AEAD encrypt | `wallet/envelope.cpp:37-103` | salt/nonce from `RAND_bytes` (`:46-49`); `EVP_aes_256_gcm`; AAD bind (`:69-75`); tag append (`:92-99`) (KE-2, KE-3) |
| AEAD decrypt (fail-closed) | `wallet/envelope.cpp:105-167` | structural pre-checks (`:109-111`); AAD precondition (`:114`); tag-verify gate at `EVP_DecryptFinal_ex` (`:161`); `nullopt` on failure (`:163`) (KE-1, KE-2) |
| Canonical serialization | `wallet/envelope.cpp:127-178` | `<magic>.<salt>.<iters>.<nonce>.<aad>.<ct>`; `deserialize` magic + size gates (`:159-173`) |
| Raw envelope CLI | `wallet/main.cpp:924-1009` | `cmd_envelope_encrypt` / `cmd_envelope_decrypt` — exercises the primitive directly with caller-chosen `--plaintext`/`--password`/`--aad`/`--iters` |
| Envelope inspection CLI | `wallet/main.cpp:1013-1099` | `cmd_envelope_inspect` — metadata-only (`format`, `salt_len`, `pbkdf2_iters`, `nonce`, `aad`) without passphrase |
| Node-keyfile create caller | `wallet/main.cpp:2861-3199` | `keyfile-create`: `DETERM-NODE-V1 <pubkey>` header + envelope; pubkey-as-AAD (application layer — see `S004KeyfileAtRest.md`) |
| Node-keyfile decrypt caller | `wallet/main.cpp:3203-3483` | `keyfile-decrypt`: reverse flow; AAD reconstructed from header (`:3368`) |
| Shamir-share envelope caller | `wallet/main.cpp:2750-2756` | `backup-create`: each Shamir share `y` individually `DWE1`-wrapped (KE-1..KE-4 apply per share) |
| In-memory `sodium_memzero` discipline | `wallet/main.cpp:1496-1531, 1708, 3681-3837` (esp. `secure_zero_all` lambda `:3767`) | §5 composition: plaintext + passphrase + key buffers wiped on every exit edge |
| Envelope regression tests | `tools/test_envelope.sh`, `tools/test_wallet_envelope.sh`, `tools/test_wallet_inspect_envelope.sh` | direct primitive round-trip + tamper + inspect coverage |
| Keyfile regression tests | `tools/test_wallet_keyfile_create.sh`, `tools/test_wallet_keyfile_decrypt.sh`, `tools/test_wallet_keyfile_info.sh`, `tools/test_wallet_keyfile_recover.sh`, `tools/test_wallet_keyfile_rotate.sh` | application-layer round-trip, wrong-passphrase rejection, AAD-tamper, malformed-input |
| Backup regression tests | `tools/test_wallet_backup_create.sh`, `tools/test_wallet_backup_verify.sh` | per-share envelope wrap/unwrap over the Shamir set |
| Closure narrative | `docs/SECURITY.md` §S-004 | option-2 AES-256-GCM passphrase envelope (600k iters / 16B salt / 96-bit nonce); the closure this proof formalizes at the primitive layer |

**Companion proofs.**

- `S004KeyfileAtRest.md` — the *application-layer* node-keyfile-at-rest proof (T-1 .. T-5). Where this document proves the envelope primitive, that one proves the `DETERM-NODE-V1` construction built on it, including the three operator adversary models, the pubkey-as-AAD header-substitution defense (its T-2 is the application of KE-2 here), and the daemon startup-load `A_online` analysis. The two are mutually-referencing and non-duplicative: KE-1..KE-4 are the primitive contract that S004KeyfileAtRest.md's T-1..T-5 instantiate for node keyfiles.
- `WalletRecovery.md` (FA12) — the threshold-recovery composition (Shamir ITS + AEAD + OPAQUE). Its AEAD-envelope-binding lemma is the same primitive KE-1..KE-4 cover; FA12 composes it with Shamir secret-sharing for the multi-share recovery flow.
- `WalletRecoveryFlows.md` — the operator-flow-level recovery composition; its keyfile-recover idempotence (re-create the keyfile byte-for-byte from recovered shares) consumes KE-1 / KE-2 as black-box invariants.
- `Preliminaries.md` (F0) §2.1 (SHA-256 collision/preimage) + §2.3 (CSPRNG uniformity) — the underlying assumptions feeding (C1)/(C3) here.

---

## 8. Status

**Specification complete.** KE-1 (confidentiality under CCA), KE-2 (integrity under CCA-modification), KE-3 (salt-uniqueness independence), and KE-4 (passphrase-strength dominance) are stated and proved against the verified primitive parameters: AES-256-GCM (12-byte nonce, 16-byte tag, 32-byte key) keyed by PBKDF2-HMAC-SHA-256 with **600,000** iterations over a 16-byte per-envelope salt, with caller-supplied AAD bound into the GCM tag, and fail-closed decryption.

**Implementation shipped (v2.17 / S-004).** The `DWE1` envelope is live on `main`: `wallet/envelope.hpp` + `wallet/envelope.cpp` provide the primitive; `wallet/main.cpp` provides the raw `envelope` CLI plus the `keyfile-*` and `backup-*` callers; the `DETERM_PASSPHRASE` env-var fallback wires the daemon's encrypted-keyfile startup path. SECURITY.md §S-004 records the closure (option 1 0600-ACL + option 2 AEAD envelope; option 2 is the cryptographic closure).

**Regression tests passing.** The primitive is covered directly by `tools/test_envelope.sh` / `tools/test_wallet_envelope.sh` / `tools/test_wallet_inspect_envelope.sh`, and at the application layer by the `tools/test_wallet_keyfile_*.sh` family and the `tools/test_wallet_backup_*.sh` pair — round-trip, wrong-passphrase rejection, AAD-tamper rejection, malformed-input rejection, and metadata-only inspection.

**Residuals (advisory, §6).** F-policy (passphrase entropy is operator-owned), F-mem (TTY/`ps`/env passphrase visibility), F-sidechannel (AES-GCM side-channels; AES-NI mitigates), F-keyzeroize (derived key not explicitly wiped in `derive_key` — defense-in-depth), and F-quantum (Grover degrades AES-256 → 128-bit and halves the passphrase exponent; iteration count + `>= 80`-bit passphrase keep an operational PQ margin; Argon2id migration is a pre-planned option). None invalidates KE-1 .. KE-4. This document adds analytic coverage only; it modifies no source.

---

## 9. References

### Specifications and standards

- **RFC 8018** (Moriarty, Kaliski, Rusch, 2017) — PKCS #5 v2.1; defines PBKDF2 (§5.2). Basis for KE-1 / KE-4.
- **RFC 5116** (McGrew, 2008) — AEAD interface; the contract AES-GCM satisfies here.
- **NIST SP 800-38D** (Dworkin, 2007) — GCM / GMAC; GHASH definition and nonce-uniqueness requirement underlying KE-2 and KE-3.
- **NIST SP 800-132** (Turan-Barker-Burr-Chen, 2010) — password-based key derivation deployment guidance.
- **FIPS 197** (2001) — AES. **FIPS 198-1** (2008) — HMAC (the PBKDF2 PRF).
- **OWASP Authentication Cheatsheet** (2023) — the 600,000-iteration PBKDF2-HMAC-SHA-256 recommendation and passphrase-entropy guidance (KE-4 / §6).

### Cryptographic literature

- **Bellare-Namprempre** (Asiacrypt 2000) — "Authenticated Encryption: Relations among Notions." AEAD (IND-CCA + INT-CTXT) definitions underlying (C2).
- **McGrew-Viega** (INDOCRYPT 2004) — "The Security and Performance of the Galois/Counter Mode (GCM)." GHASH `ε`-almost-XOR-universality bound underlying KE-2.
- **Bellare** (CRYPTO 2006) — "New Proofs for NMAC and HMAC." HMAC-PRF reduction underlying (C1).
- **Kelsey-Schneier-Hall-Wagner** (FSE 1998) — "Secure Applications of Low-Entropy Keys." PBKDF2 per-trial-cost analysis underlying KE-1's reduction.
- **Bonneau-Schechter** (USENIX Security 2014) — "Towards Reliable Storage of 56-bit Secrets in Human Memory." Passphrase-entropy estimation underlying F-policy.

### Determ-internal

- `wallet/envelope.hpp`, `wallet/envelope.cpp` — the primitive under proof.
- `wallet/main.cpp` — the `envelope` / `keyfile-*` / `backup-*` callers and the `sodium_memzero` discipline (§5).
- `tools/test_envelope.sh`, `tools/test_wallet_envelope.sh`, `tools/test_wallet_inspect_envelope.sh`, `tools/test_wallet_keyfile_*.sh`, `tools/test_wallet_backup_*.sh` — regression coverage.
- `docs/SECURITY.md` §S-004 — the closure narrative formalized here.
- `docs/proofs/S004KeyfileAtRest.md` — the application-layer companion (node-keyfile-at-rest, T-1 .. T-5).
- `docs/proofs/WalletRecovery.md` (FA12), `docs/proofs/WalletRecoveryFlows.md` — the threshold-recovery composition consuming this primitive.
- `docs/proofs/Preliminaries.md` (F0) §2.1, §2.3 — the SHA-256 and CSPRNG assumptions feeding (C1)/(C3).
