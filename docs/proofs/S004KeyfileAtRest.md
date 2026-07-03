# S004KeyfileAtRest — passphrase-encrypted node-key file soundness (S-004 closure)

This document proves that Determ's S-004 closure — passphrase-encrypted node-key files at rest, shipped in v2.17 — is sound under the standard concrete-security assumptions for PBKDF2-HMAC-SHA-256 (RFC 8018), AES-256-GCM AEAD (NIST SP 800-38D / RFC 5116), and Ed25519 EUF-CMA (RFC 8032). The scheme — closing the original "plaintext private keys on disk" finding from Audit 3.2 / OV-#04 — wraps the canonical `node_key.json` `{pubkey, priv_seed}` payload in a `DETERM-NODE-V1`-headered file whose second line is a `DWE1` AEAD envelope (`wallet/envelope.hpp`). The wallet binary's `keyfile-create` / `keyfile-decrypt` / `keyfile-info` commands own the encrypt + inspect + decrypt flows; the daemon can load the encrypted form directly at startup via `--keyfile` + the `DETERM_PASSPHRASE` env-var lookup.

We prove the PBKDF2 soundness lower bound, the AEAD AAD-binding property (header-substitution defense), confidentiality under three adversary models (A_offline disk-theft, A_online startup-prompt, A_msg pubkey-known), and characterize the operator-passphrase-entropy precondition explicitly. The proof's primary objects are `derive_key` + `encrypt` + `decrypt` in `wallet/envelope.cpp:17-167` plus the `keyfile-create` / `keyfile-decrypt` callers in `wallet/main.cpp:2981-3186` + `wallet/main.cpp:3239-3483`.

**Companion documents:** `WalletRecoveryFlows.md` (T-3 keyfile-decryption soundness — restated and re-derived here from primitives for the S-004 closure perspective; the present proof is the cryptographic-primitive companion to WalletRecoveryFlows.md's operator-flow companion); `WalletRecovery.md` (FA12 T-16 AEAD envelope binding — the underlying primitive proof we cite as a black-box invariant); `S014RateLimiterSoundness.md` (similar finding-register + adversary-model layout used here); `RpcAuthHmacSoundness.md` (S-001 closure) — the daemon-side authentication surface, orthogonal to S-004; `Preliminaries.md` (F0) §2.1 (SHA-256 collision + preimage resistance) + §2.3 (CSPRNG uniformity) for the primitive assumptions A2 + A8 (the v1 hash + RNG axioms) leveraged in §2.

---

## 1. Theorem statements

**Setup.** Let `(pk, sk) ∈ {0,1}²⁵⁶ × {0,1}²⁵⁶` denote an Ed25519 node-identity keypair, with `pk` the public key and `sk` the 32-byte seed from which the libsodium / OpenSSL key derivation reproduces the full Ed25519 expanded key. Let `J := {"pubkey": hex(pk), "priv_seed": hex(sk)}` denote the canonical plaintext `node_key.json` content (per `src/crypto/keys.cpp::save_node_key` lines 35-43). Let `P ∈ {0,1}*` denote the operator passphrase with min-entropy `H_pw`. Let `s, n ∈ {0,1}⁸` be uniformly random salts and nonces drawn from OpenSSL `RAND_bytes` (16 + 12 bytes respectively, per `wallet/envelope.cpp:46-49`). Let `iter := 600,000` (the `DEFAULT_PBKDF2_ITERS` constant at `wallet/envelope.hpp:46`).

The encryption operation `keyfile-create` produces a two-line file:

```
Line 1: "DETERM-NODE-V1 " ‖ hex(pk) ‖ "\n"
Line 2: serialize(envelope::encrypt(J, P, aad := utf8(hex(pk)), iter)) ‖ "\n"
```

— per `wallet/main.cpp:3151-3152`, with the `DWE1` envelope's canonical hex serialization shape `<magic>.<salt>.<iters>.<nonce>.<aad>.<ct>` from `wallet/envelope.cpp:127-142`. The AAD bytes are the UTF-8 encoding of the lowercase pubkey hex string (`wallet/main.cpp:3107` + `:3364`), binding the envelope to the keypair's public identity.

**Theorem T-1 (PBKDF2 Soundness — offline brute-force lower bound).** Let `Key := PBKDF2-HMAC-SHA-256(P, s, iter, dkLen=32)` denote the 32-byte AES key derived per `wallet/envelope.cpp:19-33`. Under (A6) HMAC-SHA-256 PRF assumption + (A2) SHA-256 collision resistance, an adversary `A_offline` holding `(envelope, hex(pk))` but not `P` must perform expected work

$$
\mathbb{E}\bigl[\text{work}(A_{\text{offline}})\bigr] \;\geq\; 2^{H_{\text{pw}}-1} \cdot \text{iter} \cdot c_{\text{PBKDF2}}
$$

to recover `P` (or equivalently `Key`) with probability ≥ 1/2, where `c_PBKDF2` is the per-iteration HMAC-SHA-256 cost (≈ 2 SHA-256 block computations on a single-block password input). Equivalently, the effective-security bit-budget per trial decryption attempt is

$$
B_{\text{eff}} \;=\; H_{\text{pw}} + \log_2(\text{iter}) \;\approx\; H_{\text{pw}} + 19.2
$$

bits. For `H_pw = 40` (worst-case "human" passphrase per A8), `B_eff ≈ 59.2` bits — roughly `10¹⁸` trial decryptions to brute-force at probability ≥ 1/2. For `H_pw = 80` (typical "strong" passphrase per A8), `B_eff ≈ 99.2` bits — well beyond any classical or near-term quantum adversary budget.

**Theorem T-2 (AEAD AAD-Binding — header-substitution defense).** The AEAD GCM construction at `wallet/envelope.cpp:69-75` binds the `aad` parameter into the authentication tag via `EVP_EncryptUpdate(ctx, nullptr, &outlen, aad.data(), aad.size())`. Under (A7) AES-256-GCM AEAD security (Bellare-Namprempre 2000 IND-CCA + integrity-of-ciphertexts), for any adversary `A_tamper` producing a ciphertext-AAD pair `(ct', aad')` with `aad' ≠ aad`, the probability of `EVP_DecryptFinal_ex` (the tag-verify call at `wallet/envelope.cpp:161`) returning success is `≤ 2⁻¹²⁸ + ε_AEAD`, where `ε_AEAD` is the AES-256-GCM tag-forgery bound (negligible under A7). In particular, swapping the file's first-line header from `DETERM-NODE-V1 <pk_a>` to `DETERM-NODE-V1 <pk_b>` (with `pk_a ≠ pk_b`) causes the `keyfile-decrypt` path to recompute `aad := utf8(hex(pk_b))` (per `wallet/main.cpp:3364`), which does not match the envelope's stored AAD (per `wallet/envelope.cpp:114`'s pre-check that `aad == env.aad`) — decrypt returns `std::nullopt` deterministically without revealing whether the passphrase was correct.

**Theorem T-3 (Confidentiality Under Disk Theft, A_offline composition).** For any adversary `A_offline` holding the encrypted keyfile file contents (`DETERM-NODE-V1 <hex(pk)>` header + DWE1 envelope) but not the passphrase `P`, the probability of recovering `sk` is bounded by

$$
\Pr\bigl[A_{\text{offline}} \to sk\bigr] \;\leq\; Q \cdot 2^{-(H_{\text{pw}} + \log_2(\text{iter}))} + \varepsilon_{\text{AEAD}}
$$

where `Q` is the number of trial decryptions the adversary performs (each costing PBKDF2 derivation + AES-GCM tag-verify), and `ε_AEAD ≤ 2⁻¹²⁸` is the AES-256-GCM forgery bound (A7). For `H_pw = 40`, `iter = 600,000`, `Q = 2⁶⁰` (a sophisticated offline attacker with ~10¹⁸ HMAC operations of budget — multi-year cloud-GPU farm), the bound is `~2⁻¹·² · 0.5 + 2⁻¹²⁸ ≈ 0.43` (i.e., a 40-bit passphrase is brute-forceable by such an adversary). For `H_pw = 80` (strong passphrase), the bound is `~2⁻⁴¹ · 0.5 + 2⁻¹²⁸` (cryptographically negligible). **T-3's bound is parameterized by operator passphrase entropy** — see F-2.

**Theorem T-4 (No Online-Guess Amplification, A_online).** The daemon's startup-time keyfile-load path applies a single AES-GCM tag-verify per attempt (`EVP_DecryptFinal_ex` at `wallet/envelope.cpp:161`); a wrong passphrase yields one tag-verify failure followed by daemon exit. No incremental information leakage on wrong guesses: per L-4 below, the only observable output of a single failed attempt is the tag-verify-fail timing — bounded by OpenSSL's constant-time AES-GCM implementation (A7-required for AEAD security). The operator-bound restart-loop rate (the daemon must be re-invoked between attempts) caps the adversary's effective query rate. For an attacker with shell access to the host running the daemon, the restart-loop rate is bounded by the daemon's startup cost (PBKDF2 derivation ≈ 200 ms at `iter = 600,000` on commodity hardware) + the process-spawn cost (typically 5-50 ms on modern OSes). Net: `A_online` is bounded to roughly 1-5 attempts per second per host, with each attempt facing the full T-1 PBKDF2 cost.

**Theorem T-5 (Pubkey-Indistinguishability, A_msg composition).** For any adversary `A_msg` holding the encrypted keyfile, the header pubkey `hex(pk)` in plaintext, AND the publicly-known node identity `pk_target` (e.g., from `rpc_validators --json`), the probability of recovering `sk` is bounded by the same expression as T-3:

$$
\Pr\bigl[A_{\text{msg}} \to sk\bigr] \;\leq\; Q \cdot 2^{-(H_{\text{pw}} + \log_2(\text{iter}))} + \varepsilon_{\text{AEAD}}.
$$

The intuition that "`A_msg` can verify a guess by trial-decrypting + deriving `pk'` from the candidate seed + comparing to `pk_target`" does NOT reduce the effective security below T-3's bound, because the candidate seed is only produced by the AEAD tag-verify path — a wrong-passphrase AEAD attempt fails tag-verify and produces no candidate seed to derive a pubkey from (per L-5 below). The pubkey-check is a post-AEAD predicate; the AEAD tag-verify is the gate, and that gate's failure rate is what T-1 bounds.

---

## 2. Background

### 2.1 The S-004 design rationale

Pre-S-004 (v1.0 to v2.16), the `account create` and operator-side `node_key.json` paths wrote the 32-byte Ed25519 seed in plaintext (hex-encoded inside a small JSON object) to disk. The filesystem ACL (0600 owner-only permissions) was the only access barrier. Two threat surfaces were left open:

1. **Cold-disk theft / backup leak.** An attacker who exfiltrates the operator's home directory backup (or steals the laptop) has the validator's signing key in plaintext. No additional grinding required.
2. **OS-level compromise (root or operator account takeover).** An attacker with the operator's UID (or elevated privileges) reads `node_key.json` directly past the 0600 ACL.

S-004's closure introduces a **second factor**: a passphrase the operator types (or supplies via the `DETERM_PASSPHRASE` env var at startup) that the on-disk material cannot be recovered without. The threat model after S-004 closure is:

- A_offline still needs `H_pw + log2(iter)` bits of effective brute-force work — under operator policy (passphrase ≥ 12 random chars or ≥ 16 memorable chars), this is `≥ 60 + 19.2 = 79.2` bits, intractable for any classical adversary in 2026.
- OS-level compromise (root) still loses, because the operator must enter the passphrase to start the daemon, and root can read the daemon's memory. **S-004 is NOT a defense against runtime memory dumps.** It is a defense against at-rest disk-only theft.

The cryptographic primitives chosen — PBKDF2-HMAC-SHA-256 + AES-256-GCM — are standard, FIPS-approved (FIPS 198-1 + FIPS 197 + NIST SP 800-38D), and have well-understood concrete-security bounds. The `iter = 600,000` default is OWASP's 2023 recommendation for HMAC-SHA-256 PBKDF2 (matching the 1Password 8 and Bitwarden defaults at the time of writing). The `salt_len = 16` + `nonce_len = 12` choices are textbook for GCM (RFC 5116 §3.1 + NIST SP 800-38D §8.2).

### 2.2 Wire format details

The encrypted keyfile is a 2-line text file. **Line 1** is the human-readable header `DETERM-NODE-V1 <hex(pk)>` — the version tag (used as AAD-binding context), then the public key (used as both the AAD-binding payload and an operator-visible identifier). **Line 2** is the canonical `DWE1` envelope serialization: 6 dot-separated lowercase hex fields per `wallet/envelope.cpp:127-142`:

```
<magic_4B>.<salt_16B>.<iters_4B>.<nonce_12B>.<aad_variable>.<ct_+_tag>
```

The plaintext inside the envelope is `{"pubkey": hex(pk), "priv_seed": hex(sk)}` — the same canonical `node_key.json` JSON shape `src/crypto/keys.cpp::save_node_key` writes for unencrypted keyfiles. The receiver-side (daemon at startup, or `keyfile-decrypt` CLI) parses this back via `nlohmann::json::parse` after AEAD-tag-verify success.

The choice to embed the pubkey in Line 1 plaintext is deliberate: it lets `keyfile-info` (the metadata-only inspection CLI per `wallet/main.cpp:4497-4622`) report which validator a keyfile belongs to **without** requiring the passphrase. This is an operator-convenience affordance — the pubkey is public information by definition. Hiding it would only add operational friction without confidentiality benefit (see F-3 below).

### 2.3 Adversary models

The S-004 scheme defends against three adversary families:

1. **A_offline (disk theft).** An attacker holds the encrypted keyfile bytes but not the passphrase. Examples: laptop theft, cloud-storage backup leak, exfiltration via OS-level vulnerability. The attacker has unbounded offline compute budget. **Defended by T-1 + T-3** — the PBKDF2 cost + AES-GCM tag-verify barrier make brute-force economically infeasible for `H_pw ≥ 60` bits.
2. **A_online (startup-prompt guessing).** An attacker has shell access to the host running the daemon and can invoke `determ --keyfile ... --passphrase <guess>` (or set `DETERM_PASSPHRASE`) at restart. Each guess incurs a full daemon startup including the PBKDF2 derivation. **Defended by T-4** — operator-bound restart-loop rate + per-attempt PBKDF2 cost cap the effective query rate to ~1-5/sec.
3. **A_msg (disk theft + public pubkey).** An attacker holds the encrypted keyfile bytes AND the target validator's public key (e.g., from `rpc_validators --json` or chain-public state). The attacker can verify a guess against the publicly known pubkey AFTER decryption succeeds. **Defended by T-5** — the AEAD tag-verify is the gate, not the post-decryption pubkey check; T-5 shows the bound is unchanged from T-3.

Out-of-scope adversaries (operationally-mitigated, not cryptographically):

- **OS-level memory dump while daemon running.** Defense is OS-hardening (`mlock`, kernel address-space randomization, no swap-to-disk for the daemon process). Not a cryptographic concern.
- **Side-channel attacks on the daemon process** (cache-timing, branch-prediction). Defense is via OpenSSL's constant-time AES + libsodium's constant-time primitives; outside the analytic scope.
- **Malicious wallet binary.** Defense is via software-distribution channel hygiene (signed releases, reproducible builds). Outside the analytic scope.

---

## 3. Implementation citation

The proof's primary objects:

**PBKDF2 derivation** at `wallet/envelope.cpp:19-33`:

```cpp
std::vector<uint8_t> derive_key(const std::string& password,
                                  const std::vector<uint8_t>& salt,
                                  uint32_t iters) {
    std::vector<uint8_t> key(KEY_LEN);   // KEY_LEN = 32 (wallet/envelope.cpp:15)
    if (PKCS5_PBKDF2_HMAC(password.data(),
                            static_cast<int>(password.size()),
                            salt.data(), static_cast<int>(salt.size()),
                            static_cast<int>(iters),
                            EVP_sha256(),
                            static_cast<int>(KEY_LEN),
                            key.data()) != 1) {
        throw std::runtime_error("envelope: PBKDF2 derivation failed");
    }
    return key;
}
```

This is the OpenSSL `PKCS5_PBKDF2_HMAC` primitive (RFC 8018 §5.2 / PKCS #5 v2.1) with HMAC-SHA-256 as the underlying PRF — the canonical secure-key-derivation construction for password-based crypto.

**AEAD encrypt** at `wallet/envelope.cpp:37-103`:

```cpp
Envelope encrypt(const std::vector<uint8_t>& plaintext,
                   const std::string& password,
                   const std::vector<uint8_t>& aad,
                   uint32_t iters) {
    // ... salt + nonce drawn from RAND_bytes (wallet/envelope.cpp:46-49) ...
    auto key = derive_key(password, env.salt, iters);
    // EVP_aes_256_gcm + GCM nonce 12B + AAD feed via EncryptUpdate(nullptr, ...)
    // ... EVP_EncryptUpdate(aad), EVP_EncryptUpdate(plaintext), EVP_EncryptFinal,
    //     EVP_CIPHER_CTX_ctrl(GCM_GET_TAG) appended to ciphertext ...
}
```

The 16-byte GCM tag is appended to the ciphertext buffer (line 92-99) so the envelope's `ciphertext` field is `len(plaintext) + 16` bytes.

**AEAD decrypt** at `wallet/envelope.cpp:105-167`:

```cpp
std::optional<std::vector<uint8_t>>
decrypt(const Envelope& env,
          const std::string& password,
          const std::vector<uint8_t>& aad) {
    if (env.ciphertext.size() < TAG_LEN) return std::nullopt;
    if (env.nonce.size()       != NONCE_LEN) return std::nullopt;
    if (env.pbkdf2_iters       == 0) return std::nullopt;
    if (aad != env.aad) return std::nullopt;   // AAD precondition (line 114)
    auto key = derive_key(password, env.salt, env.pbkdf2_iters);
    // ... EVP_aes_256_gcm decrypt + EVP_CIPHER_CTX_ctrl(SET_TAG) ...
    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &outlen);   // (line 161)
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) return std::nullopt;   // tag-verify fail → nullopt
    // ...
}
```

The tag-verify decision is taken at `EVP_DecryptFinal_ex` (line 161); any tag failure returns `std::nullopt` indistinguishably from wrong-passphrase, wrong-AAD, or corrupted-ciphertext. This is the deterministic-leakage-bounded behavior T-4 + T-5 rely on.

**keyfile-create caller** at `wallet/main.cpp:2981-3186`:

```cpp
// ── Build the canonical keyfile JSON (plaintext-inside-envelope) ──── (line 3093)
nlohmann::json keyfile_json = {
    {"pubkey",    pubkey_hex},
    {"priv_seed", priv_seed_hex}
};
std::string pt_str = keyfile_json.dump(2);
std::vector<uint8_t> pt_bytes(pt_str.begin(), pt_str.end());

// AAD = ASCII bytes of pubkey hex. Binds the envelope to this
// validator's public key — a tampered envelope substituted from
// another validator (same passphrase) will fail GCM tag verification.
std::vector<uint8_t> aad(pubkey_hex.begin(), pubkey_hex.end());   // (line 3107)

// ── Encrypt + write the canonical 2-line file ─────────────────────── (line 3109)
auto env  = envelope::encrypt(pt_bytes, passphrase, aad);
blob      = envelope::serialize(env);
// ...
f << "DETERM-NODE-V1 " << pubkey_hex << "\n";   // (line 3151)
f << blob << "\n";                              // (line 3152)
```

The `0600` permissions tightening is applied at line 3163-3169 as belt-and-suspenders — the AEAD layer is the cryptographic guarantee; the ACL is the OS-layer hardening.

**keyfile-decrypt caller** at `wallet/main.cpp:3239-3483`:

```cpp
// Header shape: "DETERM-NODE-V1 <pubkey_hex>"                          (line 3292)
const std::string header_magic = "DETERM-NODE-V1 ";
if (header_line.rfind(header_magic, 0) != 0) {
    std::cerr << "keyfile-decrypt: --in header does not start with "
                 "'DETERM-NODE-V1 ' (not a canonical encrypted node "
                 "keyfile)\n";
    return 1;
}
std::string header_pubkey_hex = header_line.substr(header_magic.size());
// ... length + hex validation ...

// ── Decrypt with pubkey_hex as AAD ──────────────────────────────────  (line 3358)
// AAD binding: keyfile-create binds the header pubkey into the GCM
// AAD. Any tampering with the header pubkey (or substitution of an
// envelope from a different validator) breaks AEAD verification
// here — same exit code / diagnostic as wrong passphrase, so an
// attacker cannot distinguish.
std::vector<uint8_t> aad(header_pubkey_hex.begin(), header_pubkey_hex.end());
auto pt_opt = envelope::decrypt(*env_opt, passphrase, aad);
if (!pt_opt) {
    std::cerr << "keyfile-decrypt: wrong passphrase or corrupted keyfile\n";
    return 2;
}
// ... inner-pubkey vs header-pubkey defense-in-depth check at line 3423 ...
```

The `--passphrase-from` flag supports three sources: `file:<path>` (read passphrase from a file), `env:<NAME>` (read from environment variable, typically `env:DETERM_PASSPHRASE`), or `prompt` (interactive TTY prompt without echo). The daemon-side path (per `src/main.cpp:4416`) defaults to the `DETERM_PASSPHRASE` env var so the operator does not need to type the passphrase on every restart but also does not leak it to shell history.

---

## 4. Lemmas and proofs

### Assumption block (proof-local, beyond Preliminaries §2)

- **(A6) HMAC-SHA-256 PRF assumption.** HMAC-SHA-256 is computationally indistinguishable from a uniformly random function `{0,1}* → {0,1}²⁵⁶`. Per Bellare 2006 ("New Proofs for NMAC and HMAC: Security without Collision-Resistance," CRYPTO 2006), HMAC-SHA-256 is a PRF under the assumption that the SHA-256 compression function is a PRF — strictly weaker than collision resistance. Used in PBKDF2's iterated-HMAC construction.

- **(A7) AES-256-GCM IND-CCA / AEAD security.** AES-256-GCM achieves Authenticated Encryption with Associated Data (AEAD) per Bellare-Namprempre 2000 ("Authenticated Encryption: Relations among Notions"). Concretely: for any PPT adversary `A` with `q` chosen-plaintext queries and `q'` decryption queries, the IND-CCA advantage is bounded by `2 · q · ε_AES + q' · 2⁻¹²⁸` + the nonce-uniqueness condition (each `(key, nonce)` pair used for at most one encryption; satisfied here because nonces are 12 bytes from `RAND_bytes` so collision after `n` envelopes is bounded by `n²/2⁹⁶`, negligible for any practical `n`). Tag forgery probability is `≤ 2⁻¹²⁸`.

- **(A8) Operator passphrase entropy.** The operator-chosen passphrase has min-entropy `H_pw` bits. **For S-004's threat model, the proof is parameterized by `H_pw`.** Per the OWASP Authentication Cheatsheet (2023) + NIST SP 800-63B Memorized-Secret guidance, conservative values are:
  - `H_pw ≥ 40` bits — "weak human" passphrase: ≥ 8 chars from a 256-char alphabet (ASCII printable + extended), or a 4-word Diceware-style passphrase.
  - `H_pw ≥ 60` bits — "moderate" passphrase: ≥ 10 random chars or 5-word Diceware. (`B_eff ≈ 79.2` bits — recommended floor for S-004 closure soundness.)
  - `H_pw ≥ 80` bits — "strong" passphrase: ≥ 14 random chars or 7-word Diceware. (`B_eff ≈ 99.2` bits — exceeds Ed25519 EUF-CMA's 128-bit security floor in conjunction with PBKDF2 cost amplification.)

  **F-2 (below) explicitly registers operator-policy responsibility:** for T-1's bound to translate to operational security, the operator must use `H_pw ≥ 60` bits.

### Lemma L-1 (PBKDF2 effective security)

The PBKDF2-HMAC-SHA-256 construction at `wallet/envelope.cpp:19-33` iterates HMAC-SHA-256 `iter` times per derived 32-byte key. Per RFC 8018 §5.2 + Kelsey-Schneier-Hall-Wagner 1998 ("Secure Applications of Low-Entropy Keys"), the only known attack on a non-broken PBKDF2 is brute-force over the password space — there is no shortcut better than enumerating candidate passwords + recomputing PBKDF2 per candidate. The work-per-trial is `iter · c_HMAC` where `c_HMAC ≈ 2 · c_SHA256_block` (HMAC's inner + outer hash applications).

For an adversary with budget `Q` PBKDF2 trials over a password space of `2^{H_pw}` candidates, the success probability is

$$
\Pr[\text{recover}] \;=\; \min(1, Q / 2^{H_{\text{pw}}}).
$$

To achieve success probability ≥ 1/2 requires `Q ≥ 2^{H_pw - 1}` trials, each costing `iter · c_HMAC ≈ 6 \cdot 10⁵ \cdot c_HMAC`. Equivalently, the effective security bit-budget per trial is `H_pw + log2(iter) ≈ H_pw + 19.2` (the `log2(iter)` term is the work-factor amplification of the iterated HMAC).

For `H_pw = 40, iter = 600,000`: `B_eff ≈ 59.2` bits — `≈ 6.4 \cdot 10¹⁷` HMAC operations of total budget at 50% success. On commodity 2026 GPU hardware (peak ~10¹⁰ HMAC-SHA-256/sec/GPU on a high-end consumer GPU), this is ~6 \cdot 10⁷ GPU-seconds ≈ ~700 GPU-days. Cloud-renting a 10⁴-GPU farm reduces this to ~70 minutes — **A_offline brute-forces a 40-bit passphrase in roughly an hour**. This is precisely the operator-policy precondition F-2 flags.

For `H_pw = 80, iter = 600,000`: `B_eff ≈ 99.2` bits — `~6 \cdot 10²⁹` HMAC operations of total budget at 50% success. At 10¹⁰ HMAC/sec/GPU + 10⁴ GPUs, this is `~6 \cdot 10¹⁵` GPU-seconds ≈ 2 million GPU-years — operationally infeasible.   □

### Lemma L-2 (AAD-binding precondition + post-condition)

Inspect `envelope::decrypt` at `wallet/envelope.cpp:105-167`. The function has two AAD-related branches:

1. **Line 114: explicit precondition `aad == env.aad`.** Before any key derivation or AES context setup, the function checks that the caller-provided `aad` parameter matches the envelope's stored `aad` byte-for-byte. If they differ, the function returns `std::nullopt` immediately — no PBKDF2 cost paid by the attacker on a non-matching AAD attempt.

2. **Lines 132-139: AAD fed into GCM context via `EVP_DecryptUpdate(ctx, nullptr, &outlen, env.aad.data(), env.aad.size())`.** The GCM construction binds AAD into the tag computation: tag = `GHASH(H, AAD ‖ ciphertext)` (per NIST SP 800-38D §7.1). If the AAD differs from what was used at encrypt time, the GHASH computation produces a different value and tag-verify fails at `EVP_DecryptFinal_ex` (line 161).

The composition of (1) and (2) means: any caller who provides a wrong AAD is short-circuited at the line-114 check before any cryptographic work. The line-114 check is structural redundancy — the GCM tag-verify already binds the AAD — but it ensures the caller sees the same `nullopt` result whether they pass the wrong AAD or the wrong passphrase. T-2's claim is direct from (2): the AEAD AAD-binding is built into the GCM tag, and tampering with the AAD (e.g., by substituting the file's Line 1 header) causes tag-verify to fail with probability `≥ 1 - 2⁻¹²⁸` under (A7).

In `keyfile-decrypt` (at `wallet/main.cpp:3364`), the caller recomputes `aad := utf8(header_pubkey_hex)` from the file's Line 1 header. If an attacker tampers with Line 1 — say, substituting `pk_a` (target validator) with `pk_b` (some other validator) — the caller's computed AAD becomes `utf8(hex(pk_b))`, which does NOT match the envelope's stored AAD `utf8(hex(pk_a))`. Line 114 short-circuits to `nullopt`; the attacker learns only that the file failed to decrypt, indistinguishable from a wrong-passphrase failure. **The attacker cannot use this to extract information about the passphrase.**   □

### Lemma L-3 (Pre-decryption + post-decryption defense-in-depth)

Beyond the cryptographic AAD-binding (L-2), the `keyfile-decrypt` flow at `wallet/main.cpp:3417-3429` performs an additional defense-in-depth check after a successful decrypt:

```cpp
if (inner_pubkey_hex != header_pubkey_hex) {
    std::cerr << "keyfile-decrypt: inner 'pubkey' (" << inner_pubkey_hex
              << ") does not match header pubkey (" << header_pubkey_hex
              << "); the encrypted blob was not produced by the "
                 "canonical keyfile-create path\n";
    return 1;
}
```

This is structurally unreachable for any envelope produced by `keyfile-create` (the encryption path at `wallet/main.cpp:3097-3107` writes the same pubkey to both the header line AND the inner JSON, and the AAD-binding ensures any tampering breaks tag-verify before reaching this check). The check exists to detect hand-crafted envelopes that bypass the canonical create path — e.g., an envelope built with a deliberately-mismatched inner JSON and a forged header. Such an envelope would have a valid AAD (matching the forged header) and could decrypt to a meaningful-looking inner JSON, but the post-decrypt pubkey-equality check catches it.

The composition: **(1) AAD-binding prevents header tampering** at the cryptographic layer (L-2); **(2) inner-vs-header pubkey-equality check** catches the residual hand-crafted-envelope case at the application layer. Both layers are required for full defense — an attacker who controls envelope generation could mismatch inner JSON; the AAD-binding alone does not catch this case because the AAD is part of the envelope and the attacker chose it.   □

### Lemma L-4 (Constant-time tag-verify behavior under A_online)

The OpenSSL AES-256-GCM implementation used at `wallet/envelope.cpp:118-161` (`EVP_CIPHER_CTX_new`, `EVP_DecryptInit_ex`, `EVP_DecryptUpdate`, `EVP_CIPHER_CTX_ctrl(GCM_SET_TAG)`, `EVP_DecryptFinal_ex`) is constant-time per OpenSSL's documented security guarantees (OpenSSL Security Policy v3.0 §7.1). The tag-verify decision at `EVP_DecryptFinal_ex` is implemented via `CRYPTO_memcmp` (the constant-time variant of memcmp) on the 16-byte GCM tag.

Consequences for `A_online` (the daemon-startup-prompt adversary):

1. **Timing side-channel.** Successful vs failed tag-verify takes the same wall-clock time within OpenSSL's constant-time implementation (`CRYPTO_memcmp` always compares all 16 bytes regardless of byte position of first mismatch). Per Bernstein 2005 ("Cache-timing attacks on AES") + the OpenSSL constant-time AES discipline, the AES-GCM decrypt path does NOT branch on key material or tag bytes. So timing-channel observation of single-attempt failures does not yield information about the passphrase or key.

2. **Per-attempt cost.** The daemon's startup path must (a) load + parse the keyfile (cheap), (b) derive the PBKDF2 key from the candidate passphrase (`iter = 600,000` HMAC-SHA-256 iterations ≈ 200 ms on commodity CPU), (c) perform AES-GCM tag-verify (microseconds). So each `A_online` attempt costs ≥ 200 ms of PBKDF2 + the daemon-startup overhead (typically 50-200 ms more). Net: ~1-5 attempts/sec achievable per host.

3. **Daemon-exit-on-failure.** The daemon exits with a non-zero status on keyfile-load failure (per the `src/main.cpp:4045` and `wallet/main.cpp:3367` paths). The `A_online` adversary must re-invoke the daemon between attempts, incurring the process-spawn cost. There is NO long-running daemon-side state that accumulates failed-attempt counters — each attempt is independent. **This is a feature, not a bug**: an attempt-count-tracking lockout (Linux PAM `tally2`-style) would require persistent state that the adversary with root could just delete. The PBKDF2 cost is the only rate-limiting primitive.

The composition: A_online's effective query rate is bounded to `1 / (PBKDF2 cost + process-spawn cost) ≈ 1-5 queries/sec`. Over a year of sustained attempts (≈ 3 \cdot 10⁷ seconds), `A_online` performs `≤ 1.5 \cdot 10⁸` queries — well below the `2^{H_pw - 1}` threshold for any `H_pw ≥ 30` bits. T-4's effective-rate-limit-via-PBKDF2-cost claim holds.   □

### Lemma L-5 (Pubkey-check post-AEAD ordering)

Inspect the `keyfile-decrypt` flow at `wallet/main.cpp:3365` and the daemon's startup `load_node_key`-with-decrypt path. In both, the sequence is:

1. Parse the envelope (cheap; no crypto).
2. Compute AAD from the header pubkey.
3. Call `envelope::decrypt(env, passphrase, aad)` — which performs PBKDF2 + AES-GCM tag-verify.
4. If decrypt returned `std::nullopt`, short-circuit return / error-exit. **No candidate seed is produced.**
5. Otherwise, parse the decrypted plaintext as JSON, extract `inner_pubkey_hex` + `priv_seed_hex`.
6. (Optional defense-in-depth, per L-3) compare `inner_pubkey_hex` to `header_pubkey_hex`.

For `A_msg` who holds the public pubkey of the target validator and wants to verify a guess by deriving `pk' = Ed25519_pubkey(seed')` and comparing to the known `pk_target`: step (4) is the gate. If the candidate passphrase guess produces a wrong PBKDF2 key, AEAD tag-verify fails at step (3), and no candidate seed `seed'` is produced — the pubkey-derivation + comparison can never execute. The adversary observes only `nullopt`; no information about the passphrase or seed leaks beyond what the AEAD tag-verify already permits (per A7's IND-CCA bound).

Equivalently: the AEAD tag-verify is the cryptographic bottleneck. The post-AEAD pubkey check is a defense-in-depth verification that produces a candidate-seed-aware check, but it can only run when the AEAD tag-verify has already passed — which is the high-entropy gate. The "pubkey-check verification" attack vector therefore does not amplify A_msg's advantage beyond T-3's bound.   □

### Lemma L-6 (Fresh nonce per encryption)

The encryption path at `wallet/envelope.cpp:46-49` draws a fresh 12-byte nonce from OpenSSL `RAND_bytes` per envelope. Per NIST SP 800-38D §8.2 (GCM uniqueness requirement), this is sufficient to avoid the GCM nonce-reuse catastrophe (which would leak the authentication subkey and break tag-forgery resistance).

The birthday-collision bound on 12-byte random nonces: after `n` envelopes encrypted under the same key, collision probability is `~n²/2⁹⁶`. For the S-004 use case, the same key is used at most a single time — each `keyfile-create` invocation draws a fresh salt (and hence a fresh PBKDF2 key, even if the operator reuses the passphrase). So the per-key envelope count is 1, and collision probability is 0 in the operational sense. Even in a hypothetical re-encrypt loop with `n = 2⁴⁰` envelopes under the same passphrase + same salt, collision probability is `~2⁻¹⁶` — well within the AEAD security budget.

Per (A2) SHA-256 collision resistance + the CSPRNG quality of `RAND_bytes` (Preliminaries §2.3), the nonce uniqueness assumption holds operationally. No nonce-reuse attack vector exists.   □

---

## 5. Proofs of T-1 .. T-5

**Proof of T-1 (PBKDF2 Soundness).** Direct from L-1. Under (A6) HMAC-SHA-256 PRF, the PBKDF2 construction is reduction-tight to enumerating the password space + recomputing the iterated HMAC per candidate. The per-trial cost is `iter · c_HMAC`; to achieve success probability ≥ 1/2 requires `Q ≥ 2^{H_pw - 1}` trials. The effective security bit-budget per trial is `H_pw + log2(iter)`. Substituting `iter = 600,000`, `log2(iter) ≈ 19.2`, gives the stated bound `H_pw + 19.2` bits.   ∎

**Proof of T-2 (AEAD AAD-Binding).** Direct from L-2. Under (A7) AES-256-GCM AEAD security, any adversary `A_tamper` who modifies the AAD (e.g., by substituting the file's Line 1 header) causes the GHASH-based tag computation to produce a different tag value. The probability that the tag-verify at `EVP_DecryptFinal_ex` succeeds on the wrong-AAD ciphertext is `≤ 2⁻¹²⁸ + ε_AEAD` per (A7)'s tag-forgery bound. Combined with the line-114 short-circuit check (L-2 part 1) that catches wrong-AAD attempts before any crypto, the composition is structurally redundant — both layers reject the same attacker.   ∎

**Proof of T-3 (Confidentiality Under Disk Theft, A_offline).** Composition of T-1 + T-2 + L-6. The adversary `A_offline` who holds only the encrypted keyfile bytes (without the passphrase) must either:

(a) Brute-force the passphrase by enumerating candidates + computing PBKDF2 per candidate + AES-GCM tag-verify per candidate. By T-1, the per-trial success probability is `2^{-(H_pw + log2(iter))}`; cumulative success over `Q` trials is bounded by `Q · 2^{-(H_pw + log2(iter))}`.

(b) Find a flaw in AES-256-GCM (forge a tag) — bounded by `ε_AEAD ≤ 2⁻¹²⁸` per (A7).

(c) Find a flaw in PBKDF2-HMAC-SHA-256 — bounded by `ε_PBKDF2` per (A6) + RFC 8018 §B.1; for HMAC-SHA-256 in the PRF model, no such reduction exists. We treat this term as negligible (subsumed in `ε_AEAD` for accounting purposes).

The total success probability is bounded by `Q · 2^{-(H_pw + log2(iter))} + ε_AEAD`, as stated. For `H_pw = 60, iter = 600,000, Q = 2⁶⁰`: bound is `~2⁻¹⁹·² + 2⁻¹²⁸ ≈ 2⁻¹⁹` — strongly negligible. For `H_pw = 40`, bound is `~2⁰·⁸ + 2⁻¹²⁸ ≈ 0.43` — strong reason for F-2 operator policy.   ∎

**Proof of T-4 (No Online-Guess Amplification, A_online).** Direct from L-4. The daemon's startup keyfile-load path performs exactly one PBKDF2 derivation + one AES-GCM tag-verify per attempt, returning `nullopt` on failure (constant-time via OpenSSL's `CRYPTO_memcmp` in tag-verify; per L-4 step 1). Daemon exits on failure (L-4 step 3). No persistent failed-attempt counter; each attempt requires a process restart. The per-attempt cost is dominated by the PBKDF2 derivation (200 ms ≈ at `iter = 600,000` on commodity 2026 CPU), capping the adversary's effective query rate to 1-5 attempts/sec.

For an `A_online` adversary sustaining attacks for time `T_attack` seconds, the cumulative query budget is `Q_online ≤ 5 · T_attack`. Combined with T-1's per-attempt bound, the success probability is bounded by `(5 · T_attack) · 2^{-(H_pw + log2(iter))}`. For `H_pw = 60, T_attack = 1 year ≈ 3 · 10⁷ sec`: `Q_online ≤ 1.5 · 10⁸ ≈ 2²⁷·²`; bound is `~2⁻⁵² + 2⁻¹²⁸ ≈ 2⁻⁵²` — strongly negligible.

The lack of incremental information leakage on wrong guesses (L-4 step 1) means each attempt is "atomic" — the adversary learns only `nullopt`-vs-success, not any partial information about the passphrase or PBKDF2 key. The PBKDF2 cost is the rate-limiting primitive; no additional rate-limit mechanism is required.   ∎

**Proof of T-5 (Pubkey-Indistinguishability, A_msg).** Direct from L-5 + T-3. The adversary `A_msg` who holds the public pubkey `pk_target` in addition to the encrypted keyfile can perform the following "verify-by-pubkey-derivation" attack:

1. Guess a candidate passphrase `P'`.
2. Run PBKDF2 + AEAD tag-verify with `P'`.
3. If tag-verify succeeds, extract candidate seed `seed'` from the decrypted plaintext.
4. Derive `pk' = Ed25519_pubkey(seed')` and compare to `pk_target`.
5. If `pk' == pk_target`, the guess is correct.

The key observation per L-5: step (3) is gated by step (2)'s AEAD tag-verify. A wrong-passphrase guess fails at step (2) and produces NO candidate seed at step (3) — steps (4) + (5) cannot execute on a wrong-passphrase guess. The adversary's effective verification mechanism is identical to T-3's `(Q · 2^{-(H_pw + log2(iter))} + ε_AEAD)` bound; the additional pubkey-derivation check at step (4) does not amplify the adversary's advantage.

In particular: there is no "post-AEAD-success but pre-pubkey-check" failure mode that leaks information distinct from what the AEAD tag-verify already controls. The bound is unchanged from T-3.   ∎

---

## 6. Adversary model + findings

### 6.1 Threat-model coverage matrix

| # | Threat | Defense | Residual risk | Mitigation |
|---|---|---|---|---|
| 1 | Disk theft (cold backup, laptop) | T-3: AEAD + PBKDF2 + AAD-binding | Weak passphrase (`H_pw < 60`) | F-2: operator policy — passphrase ≥ 12 random chars or ≥ 16 memorable chars |
| 2 | Memory dump while daemon running | None (out of scope) | Daemon holds decrypted seed in RAM | OS-level: `mlock` daemon memory, disable swap, kernel ASLR |
| 3 | Startup-time online passphrase guess | T-4: constant-time tag-verify + daemon-exit-on-failure + PBKDF2 cost amplification | Operator-side restart-loop rate (~1-5/sec per host) | Acceptable under F-2 passphrase entropy floor |
| 4 | Side-channel timing on AEAD decrypt | OpenSSL constant-time AES-GCM (per L-4 step 1) | Process-level timing observability (e.g., cache-occupancy) | OpenSSL constant-time discipline; defense-in-depth recommended (compiler hardening, separate decrypt process) |
| 5 | Header-substitution attack (Line 1 tampering) | T-2: AAD-binding of `DETERM-NODE-V1 <hex(pk)>` header | None — AEAD tag-verify deterministically fails | N/A (closed by T-2) |
| 6 | AES-GCM nonce-reuse attack | L-6: fresh 12-byte nonce per envelope from `RAND_bytes` | OS CSPRNG quality (`RAND_bytes` failure mode) | OpenSSL `RAND_bytes` audit + (Preliminaries §2.3) CSPRNG assumption |
| 7 | Envelope substitution (different validator's encrypted keyfile) | T-2: AAD-binding ties envelope to that validator's pubkey | Same-passphrase + same-validator backup-restore: works as intended | N/A (intentional — same operator's own legitimate keyfile) |
| 8 | Inner JSON tampering (hand-crafted envelope with mismatched pubkey) | L-3: post-decrypt `inner_pubkey == header_pubkey` defense-in-depth check | Detected at application layer; envelope decrypts but flagged | N/A (closed by L-3) |
| 9 | Wallet binary tampering (insert backdoor encrypt path) | None (out of scope) | Software supply chain | Signed releases + reproducible builds |
| 10 | Quantum adversary (Grover speedup on AES + PBKDF2) | Partial: 256-bit AES degrades to ~128-bit under Grover; PBKDF2 cost amplification unchanged | Post-quantum migration deferred | F-4: hardware HSM integration (v2.X future work) or PQ-AEAD migration |

### 6.2 Notable findings

**Finding F-1 (PBKDF2 iteration count — keep at 600,000 for 2026 hardware).** The current default `DEFAULT_PBKDF2_ITERS = 600,000` at `wallet/envelope.hpp:46` is the OWASP 2023 recommendation. On commodity 2026 CPU, this yields ~200 ms per derivation — the canonical "user-perceptible-but-tolerable" cost for interactive passphrase entry. For server-side use (operator-supplied via `DETERM_PASSPHRASE` env var, no interactive cost), the 200 ms is paid once per daemon startup and is amortized across the daemon's run lifetime.

**Severity:** None (informational).

**Recommendation:** Maintain `iter = 600,000` until 2028. The OWASP 2027 update is expected to raise the recommendation to 1,000,000+ as GPU HMAC throughput continues to scale. The envelope's wire format includes `pbkdf2_iters` as a u32 field (`wallet/envelope.hpp:46-50` + `wallet/envelope.cpp:131-133`), so a future migration to a higher iteration count is forward-compatible — existing keyfiles continue to work at their original iteration count, new keyfiles use the updated default. **No code change recommended at this time.**

**Finding F-2 (Operator passphrase entropy is OUT OF SCOPE for the bound — operator policy required).** T-1's effective security `B_eff = H_pw + log2(iter)` is parameterized by the operator's passphrase entropy `H_pw`. The S-004 closure's cryptographic primitives provide the `log2(iter) ≈ 19.2` bits of cost amplification, but the underlying `H_pw` is operator-controlled and outside the scope of any cryptographic primitive.

**Severity:** Low (informational — operator policy responsibility).

**Threat scenario:** An operator uses a 6-char-ASCII passphrase (e.g., `"hello1"`), giving `H_pw ≈ 28` bits. Then `B_eff ≈ 47.2` bits — within ~10 GPU-day budget for a determined attacker. T-1's bound is technically correct but provides no operational security.

**Recommended operator policy** (document in `docs/CLI-REFERENCE.md` `keyfile-create` row and in operator-onboarding materials):

- **Minimum.** Passphrase ≥ 12 random chars from the 64-char alphanumeric+symbol alphabet (gives `H_pw ≥ 72` bits). Alternatively, ≥ 7-word Diceware passphrase (gives `H_pw ≥ 90` bits).
- **Recommended.** Passphrase ≥ 16 random chars (gives `H_pw ≥ 96` bits) — exceeds Ed25519 EUF-CMA's 128-bit security floor when combined with PBKDF2 amplification. **At this entropy, T-3's bound is `~2⁻⁹⁶` for any reasonable adversary budget — operationally infeasible.**

The operator-policy gate is enforced by **education + documentation**, not by code. The CLI does not measure passphrase entropy because (a) entropy-estimation heuristics are unreliable (passphrase strength is a deep topic with known counterexamples — see Bonneau-Schechter 2014 "Towards Reliable Storage of 56-bit Secrets in Human Memory"), and (b) operator-side passphrase managers (`pass`, `1Password`, `Bitwarden`) already enforce entropy thresholds at the source. The `--passphrase-from file:<path>` flag deliberately accepts arbitrary input — the wallet binary's role is to use whatever entropy the operator supplies, not to second-guess it.

**No code change recommended.** The S-004 closure documentation must include the operator-policy guidance; PROTOCOL.md + SECURITY.md + CLI-REFERENCE.md S-004 rows are the threading sites (per separate threader-handle scope).

**Finding F-3 (Header pubkey in plaintext — public info, not a confidentiality issue).** The encrypted keyfile's Line 1 `DETERM-NODE-V1 <hex(pk)>` exposes the public key in plaintext. This is **intentional** — the pubkey is public information by definition (it appears in `rpc_validators`, in any block's signing committee, in any operator's chain-state queries). Hiding it in the encrypted blob would only add operational friction (e.g., the `keyfile-info` CLI would need the passphrase to identify the file's account) without confidentiality benefit.

**Severity:** None (informational; not a finding in the defect sense).

**Threat model implication:** This confirms the A_msg adversary model — an attacker who holds the encrypted keyfile already knows the target pubkey. T-5 closes this surface explicitly.

**No mitigation needed.** Documenting the design rationale here so future reviewers do not mistake the plaintext pubkey for a confidentiality leak.

**Finding F-4 (Hardware HSM integration — v2.X future work, out of scope for S-004).** Operator-side hardware HSM integration (e.g., YubiKey + ed25519-on-token, or Ledger / Trezor device) would replace the passphrase factor with a hardware factor. The benefits:

- The private key never leaves the HSM (passphrase + key both bound to physical device).
- Online attacks (A_online) become impossible without physical device access.
- Memory-dump attacks (threat #2 in §6.1 matrix) become impossible (the key is in the HSM, not the daemon's RAM).

The downsides:

- Hardware dependency (operator must physically possess the HSM at every daemon restart).
- Vendor-specific integration code (USB HID + libsodium-with-hardware-Ed25519-signing path).
- Lost-HSM recovery requires backup keys + a separate recovery flow.

This is the v2.X "hardware-second-factor" track — deferred from S-004 closure scope and tracked as a separate future-work item. **No mitigation needed in current S-004 scope.**

The three numbered findings (F-1, F-2) plus the design-rationale notes (F-3, F-4) are advisory. None invalidates T-1..T-5; F-2 is the only one with operator-action implications.

---

## 7. Composition with the rest of the security surface

S-004's encrypted-keyfile-at-rest defense composes with the rest of Determ's security surface as follows:

- **S-001 (RPC auth via HMAC-SHA-256).** Orthogonal. S-001 protects the daemon's RPC surface against unauthorized callers; S-004 protects the daemon's private key at rest before the daemon starts. The two defenses operate at different layers (network vs filesystem) and are independent. See `RpcAuthHmacSoundness.md` for S-001's proof.

- **S-014 (rate limiting on RPC + gossip).** Orthogonal. S-014 rate-limits in-flight network requests against per-peer-IP token buckets; it does NOT cover the startup-time keyfile-decrypt path. The startup-prompt rate-limit is provided by the PBKDF2 cost amplification + operator-side restart-loop rate (T-4 / L-4). See `S014RateLimiterSoundness.md` for S-014's proof.

- **S-027 (info leakage in logs / RPC responses).** Compatible. S-027 audits the daemon for accidental leakage of secret material in logs or RPC outputs. The keyfile ciphertext (and its plaintext after decrypt) never appears in any chain log, RPC response, or gossip message — the seed is held only in the daemon's RAM after a successful keyfile-load. T-3 + T-4 + T-5's confidentiality claims are not undermined by S-027's surface.

- **FA1 (Ed25519 EUF-CMA, K-of-K safety).** Compatible. Once the daemon decrypts the keyfile and loads the seed into memory, the signing operations use the underlying Ed25519 primitive normally — FA1's signature unforgeability bound applies to all daemon-side signing without any S-004 modification. The S-004 defense is at the "before-daemon-starts" boundary; FA1's defense is at the "while-daemon-runs" boundary.

- **FA6 (equivocation slashing).** Compatible. S-004 protects the validator's signing key against pre-runtime theft; FA6 protects against runtime equivocation (two-signature evidence on conflicting blocks). The two defenses target different attack timelines.

- **FA12 (wallet recovery — Shamir + AEAD + OPAQUE composition).** Direct composition. S-004's keyfile-create / decrypt flows use the same `envelope::encrypt` / `envelope::decrypt` primitives as FA12's Shamir-share AEAD-wrap path. The cryptographic soundness arguments (T-2 AAD-binding, T-3 confidentiality, L-2 + L-6) are shared. The `wallet/main.cpp` operator-facing `keyfile-recover` flow (`docs/proofs/WalletRecoveryFlows.md`) composes a Shamir-recovered seed via the same `envelope::encrypt` to produce a new S-004-encrypted keyfile — T-4 idempotence in WalletRecoveryFlows.md depends on T-3 here as a black-box invariant.

The composite security posture: an attacker who wants to extract a validator's signing key must (a) get the encrypted keyfile bytes (defeated by 0600 ACL + operator backup hygiene), (b) brute-force the passphrase (defeated by F-2 entropy + T-1 PBKDF2 cost), AND (c) avoid all the daemon-side defenses (S-001 RPC auth, FA6 equivocation slashing, etc.). The S-004 defense is **one layer in a defense-in-depth stack**, not a sole barrier.

---

## 8. Status

**Shipped (S-004 closed in v2.17 per `docs/SECURITY.md` §S-004).** The encrypted-keyfile-at-rest scheme is live in the current `main` branch:

- `wallet/envelope.hpp:1-75` + `wallet/envelope.cpp:1-249` — the `DWE1` AEAD envelope primitive (PBKDF2-HMAC-SHA-256 + AES-256-GCM).
- `wallet/main.cpp:2981-3186` (`cmd_keyfile_create`) — the encrypted-keyfile producer.
- `wallet/main.cpp:3239-3483` (`cmd_keyfile_decrypt`) — the reverse decryption flow.
- `wallet/main.cpp:4497-4622` (`cmd_keyfile_info`) — the metadata-only inspection flow (no passphrase required).
- `src/main.cpp:4403-4512` (`cmd_account_create`) + `src/main.cpp:4518+` (`cmd_account_decrypt`) — operator-side account encryption (`DETERM-ACCOUNT-V1` header variant; same envelope primitive).
- `src/main.cpp:4416` + `:4526` — `DETERM_PASSPHRASE` env-var fallback lookup at startup + decrypt-CLI paths.
- `tools/test_wallet_keyfile_decrypt.sh`, `tools/test_wallet_keyfile_info.sh`, `tools/test_wallet_keyfile_recover.sh` — regression harnesses for the wallet-side flows.
- `docs/SECURITY.md` §S-004 — closure narrative (option 1 0600 ACL + option 2 AEAD envelope both shipped; option 2 is the S-004 closure).
- `docs/CLI-REFERENCE.md` `keyfile-create` / `keyfile-decrypt` / `keyfile-info` rows — operator-facing documentation.

**Not yet shipped (future work, F-4):**

- Hardware HSM integration (YubiKey / Ledger / Trezor) — v2.X track; deferred.
- Per-attempt anti-brute-force timer (operator-side `tally2`-style lockout) — explicitly NOT recommended; PBKDF2 cost amplification + operator-policy F-2 are the recommended primitives.

This proof was added as part of the analytic-closure sweep for S-004; it does not modify any source code, only formalizes the PBKDF2 + AES-256-GCM composition that the encrypted-keyfile-at-rest scheme closes the threat surface under.

---

## 9. References

### Specifications + standards

- **RFC 8018** (Moriarty, Kaliski, Rusch, Jan 2017) — "PKCS #5: Password-Based Cryptography Specification Version 2.1." Defines PBKDF2 (§5.2). Conceptual reference for T-1's bound.
- **RFC 5116** (McGrew, Jan 2008) — "An Interface and Algorithms for Authenticated Encryption." AEAD interface specification used by AES-GCM here.
- **NIST SP 800-38D** (Dworkin, Nov 2007) — "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC." Defines GCM; the nonce-uniqueness requirement and tag-verify behavior cited in L-2 + L-6.
- **NIST SP 800-132** (Turan, Barker, Burr, Chen, Dec 2010) — "Recommendation for Password-Based Key Derivation: Part 1: Storage Applications." NIST companion to RFC 8018 for PBKDF2 deployment guidance.
- **FIPS 197** (NIST, Nov 2001) — Advanced Encryption Standard. Specifies AES.
- **FIPS 198-1** (NIST, Jul 2008) — The Keyed-Hash Message Authentication Code (HMAC). Underlying PRF for PBKDF2.
- **RFC 8032** (Josefsson, Liusvaara, Jan 2017) — "Edwards-Curve Digital Signature Algorithm (EdDSA)." Reference for Ed25519 (FA1 composition partner; (A1) assumption).
- **OWASP Authentication Cheatsheet** (2023 edition) — passphrase entropy + PBKDF2 iteration-count guidance underlying F-1 + F-2.

### Cryptographic literature

- **Bellare-Namprempre** (Asiacrypt 2000) — "Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm." AEAD security definitions used in (A7).
- **Bellare** (CRYPTO 2006) — "New Proofs for NMAC and HMAC: Security without Collision-Resistance." HMAC PRF reduction underlying (A6).
- **Kelsey-Schneier-Hall-Wagner** (FSE 1998) — "Secure Applications of Low-Entropy Keys." PBKDF2 cryptanalysis underlying L-1's per-trial cost analysis.
- **Brendel-Cremers-Jackson-Zhao** (USENIX 2021) — "The Provable Security of Ed25519: Theory and Practice." Ed25519 EUF-CMA bound underlying FA1 composition partner.
- **Bonneau-Schechter** (USENIX Security 2014) — "Towards Reliable Storage of 56-bit Secrets in Human Memory." Human-passphrase-entropy estimation underlying F-2.

### Determ-internal references

- `wallet/envelope.hpp:1-75` — `Envelope` struct + `encrypt` / `decrypt` / `serialize` / `deserialize` API + `DEFAULT_PBKDF2_ITERS = 600,000` constant.
- `wallet/envelope.cpp:19-33` — `derive_key` via OpenSSL `PKCS5_PBKDF2_HMAC` + EVP_sha256.
- `wallet/envelope.cpp:37-103` — `encrypt` (the AEAD wrap path).
- `wallet/envelope.cpp:105-167` — `decrypt` (the AEAD unwrap path; AAD-precondition + tag-verify).
- `wallet/envelope.cpp:127-178` — `serialize` / `deserialize` (the canonical dot-separated hex format).
- `wallet/main.cpp:2981-3186` — `cmd_keyfile_create` (operator-side encrypt flow).
- `wallet/main.cpp:3107` — AAD set to `utf8(pubkey_hex)`.
- `wallet/main.cpp:3151-3152` — 2-line file format (`DETERM-NODE-V1 <pubkey_hex>` header + envelope blob).
- `wallet/main.cpp:3239-3483` — `cmd_keyfile_decrypt` (operator-side decrypt flow).
- `wallet/main.cpp:3364` — AAD reconstruction from header pubkey at decrypt time.
- `wallet/main.cpp:3417-3429` — defense-in-depth inner-vs-header pubkey-equality check (L-3).
- `wallet/main.cpp:4497-4622` — `cmd_keyfile_info` (metadata-only inspection, no passphrase).
- `src/main.cpp:4416` + `:4526` — `DETERM_PASSPHRASE` env-var fallback for daemon-side + account-decrypt CLI.
- `src/crypto/keys.cpp:35-58` — canonical plaintext `node_key.json` format (the AEAD-wrapped payload).
- `docs/SECURITY.md` §S-004 — closure-status narrative this proof formalizes.
- `docs/CLI-REFERENCE.md` `keyfile-create` / `keyfile-decrypt` / `keyfile-info` rows — operator-facing documentation.
- `docs/proofs/WalletRecoveryFlows.md` — operator-flow-level companion (T-3 keyfile-decryption soundness as restated; T-4 composition idempotence; S-004 + Shamir-recovery composition).
- `docs/proofs/WalletRecovery.md` (FA12) — underlying cryptographic-primitive proofs (T-16 AEAD envelope binding) cited as a black-box invariant here.
- `docs/proofs/Preliminaries.md` (F0) §2.1 — SHA-256 collision resistance assumption underlying HMAC PRF security (A6 dependency chain).
- `docs/proofs/Preliminaries.md` (F0) §2.3 — CSPRNG uniformity assumption underlying L-6 nonce uniqueness.
- `docs/proofs/RpcAuthHmacSoundness.md` — S-001 closure (orthogonal companion at the RPC-auth layer).
- `docs/proofs/S014RateLimiterSoundness.md` — S-014 closure (the network-layer rate-limit companion; threat #3 in §6.1 references the operator-restart-loop residual).
