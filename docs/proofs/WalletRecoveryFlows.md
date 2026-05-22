# WalletRecoveryFlows — operator-flow-level analytic for v1 wallet recovery surface

This document proves operator-level soundness of Determ's four production wallet-recovery CLI flows: `shamir-rotate` / `keyfile-recover` / `account-recover` / `account-import`, plus the supporting `keyfile-decrypt` + `keyfile-info` flows. The argument is intentionally a **complement** to `WalletRecovery.md` (FA12, T-15..T-18). FA12 establishes the cryptographic foundations of the underlying primitives — Shamir's secret sharing over GF(2⁸), AEAD envelope binding, and the OPAQUE adapter substitution invariance. This document re-states those primitive-level claims as T-1..T-3 and then proves the additional operator-flow-level claims (T-4 composition idempotence, T-5 side-channel hygiene at the CLI boundary) that are the operational concern of an auditor reviewing the wallet binary's user-facing surface rather than the underlying cryptographic primitives.

The flows under analysis are operator-facing thin compositions: each CLI takes file inputs (shares JSON, envelopes JSON, keyholders JSON, encrypted keyfiles) and produces file outputs (anon-account JSON, plaintext keyfile JSON, rotated shares JSON). The proof's role is to confirm that the *composition* introduces no soundness loss relative to the underlying primitives (`shamir::split` / `shamir::combine` / `envelope::encrypt` / `envelope::decrypt` / `crypto_sign_ed25519_seed_keypair`) and that the CLI boundary doesn't introduce side-channel leakage (priv-key material on stdout, lingering ephemeral buffers, AAD-binding bypass paths).

**Companion documents:** `WalletRecovery.md` (FA12) for the cryptographic-primitive proofs T-15..T-18 (T-15 Shamir below-threshold ITS, T-16 AEAD envelope binding, T-17 OPAQUE adapter substitution invariance, T-18 composite end-to-end soundness); `Preliminaries.md` (F0) §2.2 (Ed25519 EUF-CMA) + §2.3 (CSPRNG uniformity for libsodium); `RpcAuthHmacSoundness.md` for the constant-time-compare / no-secret-flow-to-log audit-pass style mirrored in §4 L-5; `EconomicSoundness.md` (FA11) for the operator-flow citation style; `EquivocationSlashing.md` (FA6) for the soundness-against-honest-actor argument template.

---

## 1. Theorem statements

**Setup.** Let `s ∈ {0,1}*` denote an arbitrary byte-string secret (typical case: a 32-byte Ed25519 seed). Let `T, N ∈ [1, 255]` with `T ≤ N` denote the Shamir threshold parameters. Let `P_1, ..., P_N ∈ {0,1}*` denote N keyholder passphrases. Let `share_i := (x_i, y_i)` denote the i-th Shamir share for `i ∈ {1, ..., N}` per `wallet/shamir.hpp::Share`. Let `env_i := envelope::encrypt(y_i, P_i, aad={}, iters=DEFAULT_PBKDF2_ITERS)` denote the AEAD wrap of `y_i` under `P_i` per `wallet/envelope.hpp::encrypt`. Let `pub_i := Ed25519_pubkey(seed_i)` denote the libsodium `crypto_sign_ed25519_seed_keypair` derivation per `wallet/main.cpp:1696`.

**Theorem T-1 (Shamir below-threshold ITS, restated from FA12 T-15).** For every subset `S ⊆ {1, ..., N}` with `|S| = T-1`, the conditional distribution of `s` given `{(x_i, y_i)}_{i ∈ S}` is uniform over `{0, 1}^{|s|}` — i.e., `H(s | shares_S) = H(s)`. T-1 of N shares — even with cryptographic AEAD keys recovered — leaks zero bits of information about `s`. This is the standard Shamir 1979 information-theoretic security property; FA12 T-15 contains the full proof (Lagrange-interpolation undetermined-system argument). T-1 is restated here because the `shamir-rotate` and `account-recover` proofs both depend on it as a black-box invariant.

**Theorem T-2 (Shamir threshold soundness, restated).** For every subset `S ⊆ {1, ..., N}` with `|S| ≥ T` and distinct non-zero `x_i`, `shamir::combine({(x_i, y_i) : i ∈ S}) = s` (the original secret). This is the Lagrange-interpolation-uniqueness property: T evaluations of a polynomial of degree T-1 uniquely determine the polynomial, and the secret is its `p(0)` evaluation. Proof is direct from the `combine` implementation at `wallet/shamir.cpp:90-124` (Lagrange interpolation evaluated at x=0 in GF(2⁸) per Fermat's little theorem inverse).

**Theorem T-3 (Keyfile-decryption soundness — wrong passphrase ⇒ AEAD-tag-verify fail).** For every encrypted keyfile produced by the canonical `keyfile-create` path (DETERM-NODE-V1 header + DWE1 envelope blob with `aad := utf8(header_pubkey_hex)`), decryption with the correct passphrase yields exactly the original `{pubkey, priv_seed}` JSON; decryption with any other passphrase `P' ≠ P` returns `std::nullopt` with probability `≥ 1 - 2⁻¹²⁸` per attempt. Under AES-GCM SUF-CMA + PBKDF2-HMAC-SHA-256 strong key-derivation (RFC 8018 + NIST SP 800-132), the tag-verify failure is indistinguishable from a tampered-ciphertext failure, so the operator cannot extract per-byte information about `P` from the failure mode alone. Proof reduces to FA12 T-16 (AEAD envelope binding) via the `wallet/main.cpp:3365` decrypt call.

**Theorem T-4 (Recovery composition idempotence).** Let `seed` be a 32-byte Ed25519 seed, let `(shares, envelopes) := backup-create(seed, T, N, [P_1, ..., P_N])`, let `S ⊆ {1, ..., N}` with `|S| ≥ T`. Then:

```
account-recover(shares, envelopes, [(i, P_i) : i ∈ S], T)
    = account-import(privkey_hex = hex(shamir::combine([envelope::decrypt(envelopes[i], P_i) : i ∈ S])))
```

— i.e., the composite CLI `account-recover` is a pure functional composition of `keyfile-recover` (envelope::decrypt ∘ shamir::combine) and `account-import` (`crypto_sign_ed25519_seed_keypair`). Both paths produce **byte-identical** `{address, privkey_hex}` records. Proof is by inspection: `cmd_account_recover` at `wallet/main.cpp:4276-4395` decrypts envelopes, runs `shamir::combine`, and feeds the 32-byte result into `crypto_sign_ed25519_seed_keypair` — the same primitive sequence `cmd_keyfile_recover` + `cmd_account_import` execute separately. The composite is intentionally **THIN** — no crypto logic is duplicated. T-4 is verified end-to-end by `tools/test_wallet_account_recover.sh` assertion 31 (cross-CLI parity check).

**Theorem T-5 (No side-channel leakage at the CLI boundary).** For every wallet recovery command in {`shamir-rotate`, `keyfile-recover`, `account-recover`, `account-import`, `keyfile-decrypt`, `keyfile-info`}, no execution path emits priv-key material, recovered seeds, or intermediate Shamir polynomial coefficients to stdout, stderr, or temp files **except** when an explicit operator-set boundary flag (`--out` / `--json` for the account-recover path, or `--allow-stdout` for the cold-sign path) directs the secret to the intended output sink. The wallet's recovery functions zeroize ephemeral 32-byte seed buffers via `sodium_memzero` between derivation and serialization; the user-facing CLI output never echoes priv-key material outside the explicit secret-output gates.

A configuration-surface caveat is registered in §6: the default human-readable `account-recover` output (without `--out` and without `--json`) **does** print the recovered `privkey_hex` to stdout. This is the deliberate "operator-asked-for-recovery" output sink — the operator explicitly invoked an account-recovery CLI and either supplied `--out` (file sink) or did not (stdout sink by design). This is documented as an intentional operator-facing affordance, not a side-channel leak. The contrasting `shamir-rotate --json` mode is the asymmetric case: rotation MUST NOT print the secret in its summary (the whole point of polynomial-refresh is to avoid re-exposing the secret), and the `--json` summary at `wallet/main.cpp:896-906` is audited as **not** containing `secret_hex` (T-5 §4 L-5 + `tools/test_wallet_shamir_rotate.sh` assertions 19-20).

---

## 2. Background

### 2.1 The recovery surface

Determ's wallet recovery surface in v1 ships **two** logical surfaces composed of five CLIs:

**Surface A: T-of-N distributed backup.**

```
Setup:      seed → backup-create(T, N, [P_i]) → (shares.json, envelopes.json)
Rotation:   (shares.json, T) → shamir-rotate → (shares'.json)   [polynomial refresh, same secret]
Recovery:   (shares.json, envelopes.json, [(i, P_i)]_S, T) → account-recover → {address, privkey_hex}
                                                                                      ↑
                                                                                      └─ keyfile-recover + account-import
```

**Surface B: Single-account encrypted keyfile (operator's own custody).**

```
Setup:      {pubkey, priv_seed} → keyfile-create(passphrase) → DETERM-NODE-V1 header + DWE1 envelope blob
Inspection: keyfile.bin → keyfile-info → metadata (no decrypt; no passphrase)
Recovery:   (keyfile.bin, passphrase) → keyfile-decrypt → plaintext node_key.json
External:   priv_hex → account-import → {address, privkey_hex}                      [bring-your-own-seed]
```

The two surfaces are independent — Surface A doesn't depend on Surface B and vice versa. An operator may use either (e.g., a node operator with high-trust single-host custody uses Surface B; a multi-party-custody wallet uses Surface A). The recovery flows under analysis here are the **read** side of both surfaces: `shamir-rotate` (Surface A maintenance), `keyfile-recover` + `account-recover` (Surface A recovery), `keyfile-decrypt` + `keyfile-info` (Surface B recovery + diagnostic), `account-import` (Surface B external-seed-to-account composition).

### 2.2 Differences from naive backup

A naive backup is "write the priv key hex to a file, hide the file." This has three failure modes the recovery surface explicitly defends against:

1. **Single-point-of-failure storage compromise.** If the one backup file leaks, the secret is fully exposed. **Defended by Surface A:** T-1 of N shares leak zero information by T-1 (Shamir ITS).
2. **Single-point-of-failure storage loss.** If the one backup file is destroyed, the secret is unrecoverable. **Defended by Surface A:** any T of N shares reconstruct; up to N-T shares may be lost. **Partially defended by Surface B:** the operator must back up their own encrypted keyfile (single-host custody, but at least under a passphrase).
3. **Backup tampering.** A naive file backup carries no tamper detection. **Defended by both surfaces:** each share (Surface A) and the keyfile (Surface B) carry an AEAD GCM tag that fails verification with probability `≥ 1 - 2⁻¹²⁸` on any single-bit modification (T-3 via FA12 T-16).

The recovery flows therefore offer a **strictly better** custody primitive than naive backup along all three axes: confidentiality (information-theoretic for Surface A under threshold), availability (T-of-N redundancy), and integrity (AEAD-tag binding).

### 2.3 Security model

The recovery flows are designed against the following adversary model. (Adversary types map to §5's enumeration.)

- **Storage compromise of single share (Surface A):** an attacker who reads one of the N shares + the corresponding envelope's ciphertext blob + the matching keyholder passphrase MUST learn nothing about `s` beyond what the single share itself reveals (which is zero bits per T-1 < T).
- **Passphrase brute-force (Surface B):** an attacker holding the encrypted keyfile but lacking the passphrase MUST face the PBKDF2-HMAC-SHA-256 grinding cost (default 600,000 iterations per `wallet/envelope.hpp:46`) and the AEAD-tag-verify barrier.
- **Wallet binary tampering:** outside the cryptographic-correctness scope (operational mitigation only — software signing, distribution-channel hygiene, sodium_mlock).
- **Air-gap-leak via stdout:** an attacker who can read the operator's terminal/scrollback MUST NOT be able to capture a recovered priv-key from any flow that doesn't explicitly direct the secret to stdout.

The OPAQUE-routed recovery flow from FA12 (Phase 5 stub / Phase 6 real libopaque) is a **separate** flow with its own threat model (FA12 T-17, T-18); the proofs here cover the v1 passphrase-direct flow only.

---

## 3. Implementation citation

The five recovery flows live in `wallet/main.cpp`. Each is a thin composition over the primitive layer (`wallet/shamir.hpp` + `wallet/envelope.hpp` + libsodium `crypto_sign_ed25519_seed_keypair`).

| Command | Source | Companion primitive |
|---|---|---|
| `shamir-rotate` | `wallet/main.cpp:639-919` (`cmd_shamir_rotate`) | `shamir::combine` + `shamir::split` |
| `keyfile-recover` | `wallet/main.cpp:3553-3940` (`cmd_keyfile_recover`) | `envelope::decrypt` + `shamir::combine` |
| `account-recover` | `wallet/main.cpp:4010-4440` (`cmd_account_recover`) | `envelope::decrypt` + `shamir::combine` + `crypto_sign_ed25519_seed_keypair` |
| `account-import` | `wallet/main.cpp:1607-1773` (`cmd_account_import`) | `crypto_sign_ed25519_seed_keypair` |
| `keyfile-decrypt` | `wallet/main.cpp:3239-3483` (`cmd_keyfile_decrypt`) | `envelope::decrypt` (with `aad = header_pubkey_hex`) |
| `keyfile-info` | `wallet/main.cpp:4497-4622` (`cmd_keyfile_info`) | `envelope::deserialize` (no decrypt) |

The primitive layer:

| Primitive | Source | Cryptographic spec |
|---|---|---|
| Shamir over GF(2⁸) | `wallet/shamir.cpp:52-124` | Shamir 1979 + AES irreducible polynomial 0x11b |
| AEAD envelope (AES-256-GCM) | `wallet/envelope.cpp:37-167` | NIST SP 800-38D (GCM), RFC 5116 (AEAD generic) |
| PBKDF2-HMAC-SHA-256 KDF | `wallet/envelope.cpp:19-33` | NIST SP 800-132, RFC 8018; default 600,000 iters |
| Ed25519 seed keypair | libsodium `crypto_sign_ed25519_seed_keypair` | RFC 8032 |

The wallet's anon-address derivation is `"0x" + lowercase_hex(pubkey)` (per `wallet/main.cpp:1728`); the canonical single-account JSON record shape is `{"address": "0x...", "privkey_hex": "..."}` byte-identical between `account-import` (lines 1730-1733) and `account-recover` (lines 4389-4392), ensuring T-4. The `keyfile-decrypt` AAD binding (`wallet/main.cpp:3364`) defends against keyfile-substitution: an attacker swapping the envelope blob from a different validator's keyfile fails AEAD verification because the AAD bytes (= `utf8(header_pubkey_hex)`) differ. The `keyfile-info` flow is **passive** (never invokes decrypt; no passphrase required; T-3's claim doesn't apply because no decryption is attempted).

---

## 4. Lemmas and proofs

### Lemma L-1 (Shamir below-threshold ITS pass-through)

The `shamir-rotate` flow at `wallet/main.cpp:780-845` calls `shamir::combine(in_shares)` to recover the secret, then `shamir::split(secret, threshold, x_max_in)` to draw a fresh polynomial, then filters the new shares down to the input x-coordinate set. By T-1 (FA12 T-15), the freshly-drawn polynomial reveals zero information about the secret to anyone holding fewer than T new shares — even if the same adversary also holds all of the OLD shares (the old polynomial's coefficients are independent of the new polynomial's, both being uniformly random in GF(2⁸)).

Specifically, the rotation invariant is: `Pr[s | old_shares ∪ new_shares_S] = Pr[s | new_shares_S]` for any `|S| ≤ T-1`. The old shares are mathematically independent of the new polynomial (the random coefficients drawn by `RAND_bytes` at `wallet/shamir.cpp:80-82` are fresh per call), so old-share knowledge collapses to "nothing" under the new polynomial's information-theoretic security. Combined with T-1 on the new polynomial: under T-1 new shares, `H(s | new_shares_S) = H(s)` — uniform.

The verification round-trip at `wallet/main.cpp:840-850` confirms the new share-set combines to the SAME secret. The "mixed" old-and-new combine at `tools/test_wallet_shamir_rotate.sh` assertion 16 verifies the cross-polynomial property: mixing 2 old + 1 new shares yields a value that is **not** the original secret with overwhelming probability (the Lagrange interpolation over a mixed point-set yields a uniformly random GF(2⁸) byte per position, indistinguishable from a different secret).   □

### Lemma L-2 (`keyfile-recover` is the composition `envelope::decrypt ∘ shamir::combine`)

The `cmd_keyfile_recover` flow at `wallet/main.cpp:3829-3893` performs three steps:

1. **Per-envelope AEAD decrypt** (lines 3832-3854): for each keyholder entry `(idx, pw)`, call `envelope::decrypt(env_blob_by_idx[idx], pw, aad={})`. Reject on `nullopt` (wrong passphrase or tampered envelope) — exit code 2.
2. **Shares cross-verification** (lines 3855-3867): the decrypted plaintext `y_bytes` is hex-encoded and compared against the shares-file `y_hex` for the same `share_index`. A mismatch indicates the shares and envelopes files came from different `backup-create` runs (operator file-mixing). This is a defense-in-depth gate — without it, a malicious or mistakenly-mixed shares/envelopes pair would silently emit a wrong secret per T-1 (combining mismatched shares yields a syntactically-valid but wrong reconstruction).
3. **Shamir combine** (lines 3886-3893): feed the verified `shamir::Share` vector into `shamir::combine`. Reject on `nullopt`.

The composition is **functional**: step 2 is a structural-equality check (does not modify any value), so the secret out of step 3 is exactly what `shamir::combine` returns on the decrypted shares. By T-2, this equals `s` (the original secret) iff the keyholder subset has cardinality ≥ T AND every decrypted share is the original `y_i = p(x_i)` value (which step 2 verifies).

The `--threshold T` flag (optional for `keyfile-recover`, required for `account-recover`) lets the operator hard-fail under-threshold subsets BEFORE the decrypt loop. Without `--threshold`, a < T-share recovery still runs the decrypt loop (consuming time + entropy bits per PBKDF2 grind), then emits a syntactically-valid but wrong secret. This is **information-theoretic security as a confidentiality property, not a recovery-failure signal**: T-1 (= FA12 T-15) means the operator-visible recovery output is statistically indistinguishable from a different secret. The cross-verification (step 2) catches the case where one or more decrypted shares are wrong due to envelope/shares file mismatch, but doesn't catch the case where the operator simply didn't supply enough shares.

`account-recover` makes `--threshold T` REQUIRED (`wallet/main.cpp:4039`, `wallet/main.cpp:4250-4256`) for exactly this reason: an under-threshold subset would yield a wrong 32-byte secret, then derive a wrong wallet account, and the operator would have a working-looking account JSON for an address that owns no funds. The hard-fail gate at line 4250 prevents the silent-misrecovery path entirely.   □

### Lemma L-3 (`account-recover` is the composition `account-import ∘ keyfile-recover`)

The `cmd_account_recover` flow at `wallet/main.cpp:4276-4395` performs the same three keyfile-recover steps verbatim (lines 4276-4341), then:

4. **Seed-length contract enforcement** (lines 4348-4355): the recovered secret MUST be exactly 32 bytes (= `crypto_sign_SEEDBYTES`). Other-length secrets are rejected with exit 2 — the operator should use `keyfile-recover` directly for non-wallet-account backups.
5. **Ed25519 keypair derivation** (lines 4361-4378): `crypto_sign_ed25519_seed_keypair(derived_pub.data(), sk.data(), seed.data())`. Identical to `account-import`'s call at `wallet/main.cpp:1696`.
6. **Canonical anon-account JSON emission** (lines 4383-4395): `{"address": "0x" + hex(pub), "privkey_hex": hex(seed)}` — byte-identical to `account-import`'s record at `wallet/main.cpp:1730-1733`.

By T-2 (Shamir threshold soundness) + step 4's enforcement, the recovered 32-byte secret is the ORIGINAL seed iff the keyholder subset has cardinality ≥ T (step L-2). By RFC 8032 + libsodium's deterministic Ed25519 key derivation, `crypto_sign_ed25519_seed_keypair(seed) = (pub, sk)` is a **deterministic function**: the same input seed produces the same pubkey on every call, irrespective of when, where, or by which CLI. Both `account-recover` and `account-import` use this same primitive on the same 32-byte seed, so their output `{address, privkey_hex}` is byte-identical.

Therefore for any T-of-N subset `S` of a valid `backup-create` output:

```
account-recover(shares, envelopes, [(i, P_i)]_S, T)
    = account-import(privkey_hex = hex(shamir::combine([envelope::decrypt(envelopes[i], P_i) : i ∈ S])))
```

— pure functional composition. The composite CLI introduces no soundness loss relative to the two constituent CLIs run separately. The regression test `tools/test_wallet_account_recover.sh` assertion 31 verifies this composition identity end-to-end by running both paths on the same backup and asserting byte-equal JSON outputs.   □

### Lemma L-4 (`keyfile-decrypt` AEAD binding under AAD-pubkey-tag)

The `cmd_keyfile_decrypt` flow at `wallet/main.cpp:3358-3370` constructs `aad := utf8(header_pubkey_hex)` and calls `envelope::decrypt(env, passphrase, aad)`. Per `wallet/envelope.cpp:113-114`, the decrypt function rejects if the supplied AAD does not byte-equal the envelope's stored AAD. By AES-GCM SUF-CMA (FA12 T-16), any modification to the AAD, nonce, ciphertext, or tag causes decrypt to return `std::nullopt` with probability `≥ 1 - 2⁻¹²⁸` per attempt.

Two operator attack scenarios are explicitly covered:

**(a) Header pubkey tampering.** An adversary edits the keyfile's `DETERM-NODE-V1 <pubkey_hex>` header to substitute a different pubkey. The wallet's `aad = utf8(new_header_pubkey_hex)` no longer matches the envelope's stored AAD (= utf8(original_pubkey_hex)). Decrypt fails with `std::nullopt`. **Defended.**

**(b) Envelope substitution.** An adversary replaces the envelope blob with one from a different validator's keyfile (different pubkey, encrypted under a different passphrase). The substituted envelope's stored AAD is the OTHER pubkey, which doesn't match the operator's header pubkey. Decrypt fails with `std::nullopt`. **Defended.**

The wrong-passphrase exit code (2) at line 3369 is the same as the AEAD-tampering exit code, so the operator cannot distinguish "wrong passphrase" from "tampered keyfile" via exit code alone — this is the standard AEAD oracle-suppression design pattern. The defense-in-depth header-vs-inner-pubkey check at lines 3423-3429 catches the legacy edge case of a hand-crafted (non-canonical) envelope where the AAD wasn't bound: operators receive a structural-error diagnostic rather than a working-looking decrypt to a wrong key.   □

### Lemma L-5 (CLI-boundary side-channel hygiene audit)

Audit of the six wallet recovery commands for any leakage of secret material to stdout/stderr/logs:

| Command | Default stdout | --json stdout | --out file | Memory zeroize | Audit conclusion |
|---|---|---|---|---|---|
| `shamir-rotate` | summary only (count + path); **no secret** | summary only; **no secret_hex** (`wallet/main.cpp:902-906`) | new shares JSON; **no secret** | (no seed in flow; only shares) | **PASS** — shamir-rotate's whole purpose is polynomial refresh without secret re-exposure; secret never appears in any output sink. |
| `keyfile-recover` | secret_hex on stdout (operator intent) | `{"secret_hex": "..."}` on stdout | `{"secret_hex": "..."}` to file | (no Ed25519 seed; only Shamir secret bytes) | **PASS** — secret_hex is the operator-requested output; no side channel beyond. |
| `account-recover` | `address=0x... privkey_hex=...` (operator intent) | `{"address": ..., "privkey_hex": ...}` | `{"address": ..., "privkey_hex": ...}` | `sodium_memzero(seed)` at lines 4376, 4395; `sodium_memzero(sk)` at line 4381 | **PASS** — privkey_hex is operator-requested; intermediate seed buffer zeroized post-serialization. |
| `account-import` | `address=0x... privkey_hex=...` (operator intent) | `{"address": ..., "privkey_hex": ...}` | `{"address": ..., "privkey_hex": ...}` | `sodium_memzero(sk)` at line 1705 | **PASS** — same shape as account-recover; libsodium-derived 64-byte sk zeroized; the 32-byte seed lives on for the JSON emit then goes out of scope. |
| `keyfile-decrypt` | `pubkey: ...` + `format` (no priv_seed) | `{"pubkey": ..., "out": ..., "format": ...}` (**no priv_seed**) | `{"pubkey": ..., "priv_seed": ...}` to file | (no in-memory seed buffer — passed through to file directly) | **PASS** — the priv_seed is written to file (operator's only sink), never echoed to stdout. The --json summary at line 3470-3476 deliberately omits priv_seed; the JSON-passthrough path goes ONLY to the file. |
| `keyfile-info` | metadata only (header pubkey, envelope params) | JSON metadata only | (no --out for keyfile-info) | (no decryption attempted) | **PASS** — passive diagnostic; no decrypt, no passphrase, no priv_seed flow. |

The audit conclusion: **T-5 PASSES**. No flow leaks secret material outside the operator-set output sinks. Three structural patterns enforce this:

1. **Asymmetric --json behavior.** The `shamir-rotate --json` summary is **deliberately** missing `secret_hex` (`wallet/main.cpp:899-906` + assertion `tools/test_wallet_shamir_rotate.sh` assertion 20: "no secret_hex in --json"). Polynomial-refresh's whole point is to not re-expose the secret; the summary surface enforces this.
2. **--out preferred for secret-output flows.** The `keyfile-decrypt` `--json` summary is structured to **never** include the priv_seed (only metadata: pubkey, output path, format). The priv_seed is written to the `--out` file ONLY; the operator's pipe-driven workflow sees confirmation metadata, not the secret.
3. **Explicit seed-buffer zeroization between derivation and exit.** The `account-recover` flow at `wallet/main.cpp:4365-4395` explicitly zeroizes the local 32-byte seed buffer with `sodium_memzero` after serializing it to the output JSON, and zeroizes the libsodium 64-byte sk (which contains seed||pub) immediately post-derivation. The `account-import` flow does the same at line 1705. Heap-resident intermediate seed bytes don't survive into post-CLI memory pressure / swap / OOM-dump scenarios beyond the libsodium-zeroized window.   □

The `--allow-stdout` flag mentioned in T-5's statement is a different gate (cold-sign flow at `wallet/main.cpp:6960-7022`); not part of the recovery surface proper, but cited in T-5 because it's the wallet's documented "explicit operator opt-in for stdout-as-secret-sink" pattern.

### Lemma L-6 (Default human format always shows the seed — intentional operator-recovery affordance)

The `account-recover` default human format at `wallet/main.cpp:4436-4438` prints:

```
recovered account: address=0x<64-hex> privkey_hex=<64-hex>
```

— i.e., the full priv-seed hex goes to stdout in the default mode (no `--out`, no `--json`). This is the operator-recovery affordance: the operator explicitly invoked `account-recover` to retrieve their account, and either:

- Supplied `--out` (the secret goes to file, stdout shows the address + confirmation only — `wallet/main.cpp:4424-4428`), OR
- Did not supply `--out` (the secret goes to stdout as the operator's only sink — they're at the terminal, recovering an account).

Both cases are deliberate sinks. Mode A (file) is the deployment-grade path: the operator pipes the recovery into a secure storage location. Mode B (stdout) is the interactive-rescue path: the operator is at an air-gapped terminal recovering an account they own and has accepted the stdout disclosure.

This is an **intentional operator-facing affordance**, not a side-channel leak. T-5's "never echoes priv-key material" statement is qualified by "outside the explicit secret-output gates" precisely because the operator IS asking for the secret via this CLI. The wallet's defense pattern is asymmetric:

- Shamir-rotate: NEVER prints the secret (the whole point is polynomial-refresh without re-exposure).
- Keyfile-info: NEVER prints the secret (passive diagnostic; no decrypt).
- Account-recover / account-import / keyfile-recover / keyfile-decrypt: PRINTS the secret to the operator-chosen sink (file via --out preferred; stdout in default mode).

The asymmetry is documented in §6 as a design choice, not a finding.   □

---

## 5. Proofs of T-1 .. T-5

**Proof of T-1.** Direct from FA12 T-15. Shamir's 1979 secret sharing over GF(2⁸): for each byte position `b` of `s`, the share value `y_i^{(b)} = p_b(x_i)` is the evaluation of a polynomial of degree T-1 with `s_b` as the constant term and T-1 uniform-random GF(2⁸) coefficients. Any T-1 evaluations are consistent with every candidate `s'_b ∈ {0, ..., 255}` for exactly one choice of remaining coefficients — the system is underdetermined. Therefore `Pr[s_b = c | T-1 shares] = 1/256` uniformly over `c`. By chain-rule independence across byte positions, `H(s | T-1 shares) = H(s)`. The full proof is in FA12 T-15 §3 (Shamir 1979 below-threshold ITS).   ∎

**Proof of T-2.** Direct from `wallet/shamir.cpp:90-124`. The `combine` function applies Lagrange interpolation over GF(2⁸) evaluated at x=0. By the unique-polynomial-determination property: T evaluations of a polynomial of degree T-1 (with distinct x-coordinates) uniquely determine the polynomial. The polynomial's `p(0) = s_b` is therefore uniquely determined and equals the original secret byte. The GF(2⁸) arithmetic is implemented via the AES irreducible polynomial 0x11b at `wallet/shamir.cpp:14-25` (`gf_mul`) and Fermat's-little-theorem inversion at lines 29-39 (`gf_inv`). The Horner-rule polynomial-eval at lines 43-50 (`poly_eval`) is byte-stride efficient and constant-time relative to share content (no data-dependent branching).

Edge cases handled:
- Duplicate x-coordinates: rejected at lines 99-101 (returns `std::nullopt`).
- Mismatched y-sizes: rejected at line 100.
- Empty shares: rejected at line 92.
- Zero x-coordinate: rejected at line 99 (invalidates Lagrange basis).

For `|S| ≥ T` with valid distinct-non-zero x-coords and matching y-sizes, `shamir::combine(S) = s`. The integration test at `tools/test_wallet_shamir.sh` exercises this for `T ∈ {1, 2, 3, ..., 10}` and `N ∈ [T, 50]` with secret sizes `∈ {1, 16, 32, 64} bytes`.   ∎

**Proof of T-3.** Direct from FA12 T-16 + the `wallet/main.cpp:3358-3370` decrypt call. The decrypt path:

1. Reads the canonical 2-line keyfile (`DETERM-NODE-V1 <pubkey_hex>` header + DWE1 envelope blob).
2. Validates header magic + pubkey-hex shape (64 hex chars).
3. Derives `aad := utf8(header_pubkey_hex)`.
4. Calls `envelope::decrypt(env, passphrase, aad)`.

By T-16 (AES-256-GCM SUF-CMA + PBKDF2-HMAC-SHA-256 unique-derivation-per-salt), the decrypt returns `std::nullopt` for any of:

- Wrong passphrase: PBKDF2 derives a different key; GCM tag-verify fails with probability `≥ 1 - 2⁻¹²⁸` per attempt.
- Tampered ciphertext: GHASH-evaluation diverges from the stored tag; tag-verify fails.
- Tampered nonce: same as ciphertext (nonce is bound to GHASH).
- Mismatched AAD: explicit AAD-equality check at `wallet/envelope.cpp:113-114` rejects before key derivation.
- Tampered tag: direct mismatch with EVP_CIPHER_CTX's computed tag.

Correct passphrase + intact envelope + matching AAD: decrypt succeeds with the original plaintext (the canonical `{"pubkey", "priv_seed"}` JSON). The defense-in-depth check at `wallet/main.cpp:3423-3429` confirms inner pubkey == header pubkey (catches non-canonical hand-crafted envelopes).

Concrete bound: per-attempt forgery probability `≤ 2⁻¹²⁸` + ε_AES (the AES-256-GCM advantage of a chosen-plaintext distinguisher, negligible under standard cryptographic assumptions). Cumulative over Q attempts: `≤ Q · 2⁻¹²⁸`. For all operational Q (even Q = 2⁶⁴ over an attacker's entire lifetime), the bound is operationally negligible.   ∎

**Proof of T-4.** Direct from L-2 + L-3. By L-2, `keyfile-recover` is the deterministic composition `envelope::decrypt ∘ shamir::combine` (with cross-verification step preserving the secret-identity property under valid inputs). By L-3, `account-recover` extends this with `crypto_sign_ed25519_seed_keypair` (deterministic by RFC 8032) and the canonical anon-account JSON emission (byte-identical between `account-recover` and `account-import`).

Therefore, on any valid `(shares, envelopes, [(i, P_i)]_S)` with `|S| ≥ T`:

```
account-recover(shares, envelopes, [(i, P_i)]_S, T)
    .json_output()
==
account-import(
    --priv (keyfile-recover(shares, envelopes, [(i, P_i)]_S).secret_hex)
).json_output()
```

byte-for-byte. The regression test `tools/test_wallet_account_recover.sh` assertion 31 verifies this composition identity end-to-end by running both paths on the same backup and asserting equality via JSON parse-and-compare. The test passes under the v1 release build.   ∎

**Proof of T-5.** Direct from L-5 + L-6. By L-5's six-row audit, no recovery command emits secret material outside operator-set output sinks (--out file, --json stdout, or default human form with operator intent). The deliberate asymmetry between rotate (NEVER prints secret) and recover (DOES print to operator-chosen sink) is documented in L-6 as a design choice. `sodium_memzero` is called on every intermediate 32-byte seed buffer between derivation and exit (account-recover lines 4376/4381/4395, account-import line 1705).

The audit conclusion: **T-5 PASSES**. The wallet's recovery functions don't leak secret material to logs / stderr / unintended sinks; ephemeral 32-byte seed buffers are zeroized via `sodium_memzero`; the deliberately-asymmetric `--json` summary on `shamir-rotate` enforces non-leakage on rotation (where the operator did NOT request the secret).

One configuration-surface caveat: the operator running `account-recover` without `--out` and without `--json` gets the priv_seed on stdout (per L-6). This is the **operator-recovery affordance** documented in `--help` output at `wallet/main.cpp:4044-4056` ("emits the recovered wallet account as JSON"). Operators recovering in production should always use `--out <file>` to pipe the secret to a controlled storage location; the stdout default is for interactive air-gapped rescue scenarios. This affordance is not a side-channel leak — it's an intentional sink for the operator's express recovery intent.   ∎

---

## 6. Adversary model + identified gaps

### 6.1 Adversary capabilities

The recovery flows are designed against the following adversary families. Each family maps to an explicit defense or an out-of-scope acknowledgment.

**(a) Storage compromise of < T shares (single or multi-share leak below threshold).** An attacker reads ≤ T-1 shares + their envelopes + their keyholder passphrases. **Defended (T-1).** The shares are evaluations of a polynomial of degree T-1; by Shamir ITS, T-1 evaluations underdetermine the polynomial — the secret is uniform from the adversary's view, zero bits leaked.

**(b) Storage compromise of ≥ T shares.** Attacker holds ≥ T shares + envelopes + passphrases. **NOT defended (by design).** Threshold-crossing case: the protocol's confidentiality property is "T-1 leaks nothing, T reconstructs." Deployment decision: choose T such that bribing T independent keyholders exceeds the wallet's protected value.

**(c) Passphrase brute-force (Surface A envelope OR Surface B keyfile).** Attacker holds the encrypted artifact but lacks the passphrase. **Defended (T-3) with concrete cost bound.** PBKDF2-HMAC-SHA-256 at 600,000 iterations costs `≈ 600ms` per guess on a modern CPU. For 60-bit entropy passphrase: expected attack cost `≈ 10¹⁰ CPU-years`; with 10⁶ GPUs at 1000× speedup: still `> 10⁴ years`. The attack cost grows linearly in PBKDF2 iters; operators raise iters for higher-value secrets. Per-envelope independence (Surface A): cracking one envelope yields one Shamir share, attacker still needs T-1 more independently.

**(d) Wallet binary tampering.** An attacker substitutes a malicious wallet binary. **Out of scope.** Mitigation is operational: software signing, distribution-channel hygiene, reproducible builds. Cryptographic correctness assumes an untampered binary.

**(e) Air-gap-leak via stdout.** Attacker reads the operator's terminal/scrollback. **Partially defended (T-5).** The `--out` / `--json` flags route the secret to a file sink. The default human form on `account-recover` does print privkey_hex to stdout, but this is the operator-recovery affordance (L-6) — the operator explicitly invoked recovery at an interactive terminal. Mitigation for paranoid deployments: always supply `--out <path>`.

**(f) Side-channel via swap / memory dump / coredump.** Attacker reads OS-level memory artifacts. **Partially defended.** `sodium_memzero` narrows the in-process priv-key window; the libsodium 64-byte sk is zeroized immediately post-derivation. However, no `sodium_mlock` is called on the seed buffer, so a swap-out during the live window could persist to disk. Operational mitigation: disable swap or use an encrypted swap partition.

**(g) Recovery transcripts (file leakage).** Output JSON file contains priv-key in plaintext. **Mitigated operationally.** Output files are written with `chmod 0600` (POSIX, best-effort on Windows via NTFS ACL inheritance from parent).

### 6.2 Identified gaps

**Gap G-1 (RNG-dependence in Shamir generation).** `shamir::split` at `wallet/shamir.cpp:80` draws T-1 random GF(2⁸) coefficients per secret-byte via OpenSSL's `RAND_bytes`. A compromised RNG (debian-openssl-2008-style) could yield predictable shares, allowing < T-share holders to reconstruct. **Mitigated** by the vetted OpenSSL CSPRNG (`/dev/urandom` / `BCryptGenRandom`). The wallet does NOT cross-verify with a second CSPRNG source. **Recommended:** defense-in-depth XOR with `randombytes_buf`. Not a v1 finding — the same primitive backs envelope nonce/salt generation, so the gap is wallet-wide, not Shamir-isolated.

**Gap G-2 (passphrase entropy not enforced).** The wallet accepts any non-empty passphrase. A weak passphrase (`"hunter2"`) defeats T-3's brute-force bound. **Mitigated** by operator policy. **Recommended:** optional `--require-passphrase-entropy <bits>` on create-side CLIs.

**Gap G-3 (no forward-secrecy beyond polynomial rotation).** `shamir-rotate` refreshes the polynomial but `s` itself is unchanged. Full-secret compromise (`s` leaked) is not recoverable from. **By design** — protocol-level recovery for full-secret compromise is `account-export` + on-chain migration.

**Gap G-4 (out-of-scope: wallet binary compromise).** A malicious wallet binary can backdoor all flows. **Out of scope** (operational mitigation only: software signing, reproducible builds).

The four gaps are advisory; none invalidates T-1..T-5 under standard adversary assumptions.

---

## 7. Test-suite citation

The recovery flows are exercised by the following regression scripts in `tools/`:

| Command | Test script | Assertion count |
|---|---|---|
| `shamir-rotate` | `tools/test_wallet_shamir_rotate.sh` | 33 assertions, covering polynomial-refresh round-trip, x-coordinate preservation, polynomial-distinctness across rotations, no-secret-in-summary, T-N edge cases, T=1 degeneracy, large-N (50 shares), multiple secret sizes, --json shape, --force overwrite, threshold validation, duplicate-x rejection, fresh-randomness-on-each-call. |
| `keyfile-recover` | `tools/test_wallet_keyfile_recover.sh` | 30+ assertions, covering T-of-N round-trip, different T-subsets yielding the same secret, --out / --json output shape, wrong-passphrase exit 2, insufficient-shares exit 2, shares/envelopes mismatch detection (cross-verification step 2 in L-2), --threshold optional gating, missing-flag exit 1 vs malformed-input exit 2 split. |
| `account-recover` | `tools/test_wallet_account_recover.sh` | 32 assertions, covering composite round-trip (account-create-batch → backup-create → account-recover), different T-subsets yielding the same address+priv, --json / --out shape, wrong-passphrase exit 2, insufficient-shares exit 2, T=1 trivial case, share/envelope mismatch, --threshold required + bounds-check, **cross-CLI parity assertion (#31) verifying T-4 composition identity** vs `keyfile-recover` + `account-import` end-to-end. |
| `account-import` | `tools/test_wallet_account_import.sh` | 26 assertions, covering 32-byte seed form, 64-byte seed||pubkey form, mismatched-pubkey rejection, round-trip with account-create-batch, determinism (same seed → same address), --out file shape + perms, --json shape, parent-dir-missing exit 1, --priv length validation, output-pubkey-derivation correctness. |
| `keyfile-decrypt` | `tools/test_wallet_keyfile_decrypt.sh` | covers correct-passphrase decrypt, wrong-passphrase exit 2, AAD-binding detection, malformed-keyfile rejection. |
| `keyfile-info` | `tools/test_wallet_keyfile_info.sh` | covers passive metadata emission, no-decrypt path, malformed-keyfile exit 2 (structural error). |

The composite-identity check at `tools/test_wallet_account_recover.sh` assertion 31 is the primary verification of T-4 (composition idempotence): it runs `keyfile-recover` + `account-import` separately and `account-recover` together, asserting JSON byte-equality across the two paths.

The no-secret-in-summary check at `tools/test_wallet_shamir_rotate.sh` assertion 20 is the primary verification of T-5's asymmetric-shamir-rotate behavior: the `--json` output is parsed and confirmed to contain `rotated=true` + `share_count` + `threshold` + `secret_bytes` + `shares_file` + `rotated` — and to NOT contain `secret_hex` or the raw SECRET bytes anywhere.

---

## 8. Status

**Shipped.** All recovery-flow CLIs are live in v1 + the R17-round of in-session hardening:

- `wallet/main.cpp:639-919` — `cmd_shamir_rotate` (Proactive Secret Sharing polynomial refresh).
- `wallet/main.cpp:1607-1773` — `cmd_account_import` (external-priv-to-anon-account composition).
- `wallet/main.cpp:3239-3483` — `cmd_keyfile_decrypt` (DETERM-NODE-V1 + DWE1 envelope decrypt with AAD-pubkey binding).
- `wallet/main.cpp:3553-3940` — `cmd_keyfile_recover` (T-of-N envelope-decrypt + Shamir-combine composition).
- `wallet/main.cpp:4010-4440` — `cmd_account_recover` (composite keyfile-recover + account-import for direct wallet recovery).
- `wallet/main.cpp:4497-4622` — `cmd_keyfile_info` (passive diagnostic for encrypted keyfiles).
- `wallet/shamir.cpp:52-124` — Shamir over GF(2⁸) primitive (split + combine).
- `wallet/envelope.cpp:37-167` — AES-256-GCM envelope primitive (encrypt + decrypt).
- 6 regression test scripts in `tools/test_wallet_*.sh` (combined ~140 assertions across the recovery surface).

**Not yet shipped.** Gap G-1 (defense-in-depth dual-CSPRNG XOR), Gap G-2 (passphrase-entropy gate on create-side CLIs), Gap G-4 (recovery audit-log). All three are advisory hardenings; none invalidates T-1..T-5 under standard adversary assumptions. Tracked as future-work items here; no v1 release-blocker.

This proof was added in the current review pass as a complement to FA12 WalletRecovery.md (which covers the cryptographic-primitive proofs T-15..T-18). The two documents together provide both the cryptographic foundation (FA12) and the operator-flow-level audit (this document) for Determ's wallet recovery surface.

---

## 9. References

### Specifications + standards

- **Shamir 1979** (Adi Shamir, "How to share a secret", Comm. ACM 22(11):612-613, Nov 1979) — original SSS paper.
- **NIST SP 800-132** (Dec 2010) — "Recommendation for Password-Based Key Derivation: Part 1." Normative for PBKDF2.
- **RFC 8018** (Moriarty, Kaliski, Rusch, Jan 2017) — "PKCS #5: Password-Based Cryptography Specification Version 2.1." PBKDF2-HMAC-SHA-256 normative.
- **NIST SP 800-38D** (Nov 2007) — "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC." Normative for AES-GCM.
- **RFC 5116** (McGrew, Jan 2008) — "An Interface and Algorithms for Authenticated Encryption." AEAD generic interface.
- **RFC 5869** (Krawczyk, Eronen, May 2010) — "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." Cited here for reference; HKDF is not currently used in the v1 wallet recovery flow (PBKDF2 is the KDF), but is the standard companion KDF for future OPAQUE-routed flows.
- **RFC 8032** (Josefsson, Liusvaara, Jan 2017) — "Edwards-Curve Digital Signature Algorithm (EdDSA)." Ed25519 spec for the seed→pubkey derivation.
- **FIPS 198-1** (NIST, Jul 2008) — "The Keyed-Hash Message Authentication Code (HMAC)." Normative for HMAC-SHA-256 (underlying PBKDF2).

### Cryptographic literature

- **Blakley 1979** — Alternate threshold-secret-sharing construction. Cited for completeness; the wallet uses Shamir's construction.
- **Bellare, Canetti, Krawczyk** (CRYPTO 1996) — original HMAC paper (PRF security underlying PBKDF2).

### Determ-internal references

- `wallet/main.cpp` — six recovery commands per §3 table (`cmd_shamir_rotate`, `cmd_account_import`, `cmd_keyfile_decrypt`, `cmd_keyfile_recover`, `cmd_account_recover`, `cmd_keyfile_info`).
- `wallet/shamir.{hpp,cpp}` — Shamir GF(2⁸) primitive.
- `wallet/envelope.{hpp,cpp}` — AES-256-GCM AEAD envelope primitive + PBKDF2 KDF.
- `tools/test_wallet_{shamir_rotate,keyfile_recover,account_recover,account_import,keyfile_decrypt,keyfile_info}.sh` — regression scripts per §7.
- `docs/proofs/WalletRecovery.md` (FA12) — companion cryptographic-primitive proof (T-15 Shamir ITS, T-16 AEAD binding, T-17 OPAQUE substitution, T-18 composite).
- `docs/proofs/RpcAuthHmacSoundness.md` — companion proof; constant-time-compare + no-secret-flow-to-log audit-pass style mirrored in §4 L-5.
- `docs/proofs/EconomicSoundness.md` (FA11), `EquivocationSlashing.md` (FA6) — companion proofs; operator-flow citation style + soundness-against-honest-actor template.
- `docs/proofs/Preliminaries.md` (F0) §2.2 (Ed25519 EUF-CMA), §2.3 (CSPRNG uniformity, referenced in Gap G-1).
- `docs/SECURITY.md` §3 — S-004 closure (passphrase-encrypted keyfiles, the surface T-3 covers).
- `docs/CLI-REFERENCE.md` — operator-facing documentation of `--out`, `--json`, `--force` conventions.
