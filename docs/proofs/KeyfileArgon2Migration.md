# KeyfileArgon2Migration — soundness of the R58 keyfile KDF migration (PBKDF2 → Argon2id)

This document proves the soundness of the **R58** keyfile key-derivation migration: fresh Determ wallet envelopes now default to a memory-hard **Argon2id** KDF (the `DWE2` wire layout) instead of PBKDF2-HMAC-SHA-256 (the `DWE1` layout). Shipped on `main` in `wallet/envelope.cpp` + `wallet/envelope.hpp` + `include/determ/crypto/argon2/argon2id.h`.

This proof is a **migration delta**, not a from-scratch envelope proof. The AEAD leg is byte-identical to `DWE1`, so the confidentiality / integrity / salt-uniqueness results are **inherited verbatim** from `EnvelopeKeyfileCrypto.md` (KE-1..KE-4, lemmas L-1..L-6) and its application-layer companion `S004KeyfileAtRest.md` (T-1..T-5). This document proves only what actually changed: the KDF leg, the versioned wire format, back-compat, fail-closed parameter validation, and the qualitative hardening of the dictionary-attack bound. Read `EnvelopeKeyfileCrypto.md` first; the theorems below (KM-1..KM-5) reference its results rather than restating them.

---

## 1. Scope

**In scope.** The delta introduced by R58:

- The second, versioned wire layout `DWE2` and the shared 4-byte magic that disambiguates it from `DWE1` (`wallet/envelope.cpp:25-26`).
- The Argon2id KDF leg (`derive_key_argon2`, `wallet/envelope.cpp:45-60`) built on the C99-native `determ_argon2id` (`include/determ/crypto/argon2/argon2id.h:41-44`, RFC 9106).
- The default-selection change: `encrypt` now defaults to Argon2id (`wallet/envelope.cpp:126-131`).
- The KDF-parameter validation on both encrypt and decrypt/deserialize (`:92-93`, `:145-146`, `:250-262`).
- The back-compatibility contract: every `DWE1` envelope on disk still decrypts; unknown magic fails closed.

**Out of scope (inherited, not re-proved).**

- The AES-256-GCM AEAD construction, its IND-CCA confidentiality, INT-CTXT integrity, GHASH-MAC unforgeability, per-envelope salt/nonce freshness, and fail-closed decrypt contract — all proved in `EnvelopeKeyfileCrypto.md` (KE-1/KE-2/KE-3, L-2..L-6) and unchanged here (KM-1 establishes the carry-over).
- The `DETERM-NODE-V1` / `DETERM-ACCOUNT-V1` application layer, pubkey-as-AAD binding, and the operator adversary models — `S004KeyfileAtRest.md` (T-1..T-5). The migration is KDF-only and does not touch the header, AAD binding, or startup-load path.
- In-memory secret handling beyond the `determ_secure_zero` discipline (`EnvelopeKeyfileCrypto.md` §5); the key buffer is now zeroed inside `seal`/`decrypt` (`wallet/envelope.cpp:74`, `:164`), which tightens — never weakens — that posture.

---

## 2. Threat model (delta)

The adversaries are exactly those of `EnvelopeKeyfileCrypto.md` §2 — `A_disk` (at-rest ciphertext exposure, no passphrase) and `A_passphrase_guess` (offline dictionary / brute-force). R58 changes **only** the cost `A_passphrase_guess` pays per candidate guess: PBKDF2's per-candidate cost is pure serial compute (cheaply parallelized on GPU/ASIC), whereas Argon2id additionally forces the attacker to *materialize and traverse* `m_cost` KiB of memory per guess. The confidentiality/integrity guarantees against `A_disk` are unchanged (KM-1).

One new consideration enters scope, and is explicitly **left out of the defended set**: Argon2id's data-dependent memory-access pattern is a function of the password, so an adversary with fine-grained microarchitectural measurement (cache/power side channels) on the host *during KDF execution* could in principle learn information about the password (KM-5). This is the Argon2d GPU-resistance component and is intentional per RFC 9106; the threat model trusts the host against such side channels, exactly as `EnvelopeKeyfileCrypto.md` §2.3 / F-sidechannel already trusts it against AES/GHASH side channels.

---

## 3. Migration specification (verified from source)

### 3.1 Two versioned layouts, one magic discriminator

| Symbol | Value | Source |
|---|---|---|
| `MAGIC1_LE` (DWE1, PBKDF2) | `0x31455744` = ASCII `"DWE1"` LE | `wallet/envelope.cpp:25` |
| `MAGIC2_LE` (DWE2, Argon2id) | `0x32455744` = ASCII `"DWE2"` LE | `wallet/envelope.cpp:26` |
| `NONCE_LEN` / `TAG_LEN` / `KEY_LEN` | 12 / 16 / 32 bytes (**unchanged**) | `wallet/envelope.cpp:27-29` |
| `DEFAULT_ARGON2_T_COST` | 3 passes | `wallet/envelope.hpp:64` |
| `DEFAULT_ARGON2_M_COST_KIB` | 65,536 KiB = 64 MiB | `wallet/envelope.hpp:65` |
| `DEFAULT_ARGON2_LANES` | 1 | `wallet/envelope.hpp:66` |
| `DEFAULT_SALT_LEN` | 16 bytes (**unchanged**) | `wallet/envelope.hpp:70` |

Both layouts serialize as **6 dot-separated hex parts** — `magic . salt . params . nonce . aad . ciphertext` (`serialize`, `wallet/envelope.cpp:208-228`). The **only** structural difference is the `params` slot:

- `DWE1`: `params` = 4 bytes (`pbkdf2_iters` u32 LE) — `wallet/envelope.cpp:217-218`.
- `DWE2`: `params` = 12 bytes (`argon2_t | argon2_m_kib | argon2_p`, each u32 LE) — `wallet/envelope.cpp:211-216`.

The magic is emitted from the KDF discriminant (`argon ? MAGIC2_LE : MAGIC1_LE`, `:221`) and, on the read path, *selects* which `params` width and KDF the parser expects (`:250-263`).

### 3.2 The AEAD leg is byte-identical across both layouts

Both `encrypt_argon2id` (`:87-106`) and `encrypt_pbkdf2` (`:108-124`) call the same `fill_salt_nonce` (`:77-83`) and the same `seal` helper (`:64-75`), which runs `determ_aes256_gcm_encrypt` with a 12-byte nonce, binds `aad` into the tag, and appends the 16-byte tag to the ciphertext. `decrypt` (`:133-167`) selects the KDF from `env.kdf` (`:144-152`) but then runs one shared `determ_aes256_gcm_decrypt` (`:158-163`) regardless of layout. **The ciphertext, nonce, tag, and AAD-binding bytes are produced by identical code paths** — only the 32-byte key handed to `seal`/decrypt differs in *how it was derived*, never in how it is used. This byte-identity is the entire basis of KM-1.

### 3.3 KDF leg

- **Argon2id** (`derive_key_argon2`, `:45-60`) → `determ_argon2id(out, 32, pwd, pwdlen, salt, saltlen, t_cost, m_kib, lanes)` (`include/determ/crypto/argon2/argon2id.h:41-44`), RFC 9106 v1.3, built on C99 BLAKE2b. A non-zero return throws.
- **PBKDF2** (`derive_key_pbkdf2`, `:33-43`) → `determ_pbkdf2_hmac_sha256(...)`, the legacy `DWE1` path, retained for interop and the `envelope encrypt --iters` CLI (`wallet/envelope.hpp:88-93`).

### 3.4 Default and interop

`encrypt(plaintext, password, aad)` (`:126-131`) delegates to `encrypt_argon2id` with the §3.1 defaults — **Argon2id is now the default for every fresh envelope**. The legacy PBKDF2 path is reachable only through the explicit `encrypt_pbkdf2` entry point and the `--iters` CLI flag. Test leg 2 (`tools/test_wallet_keyfile_argon2.sh:81-88`) confirms `envelope encrypt` emits magic `44574532` (DWE2) by default and `--iters N` emits `44574531` (DWE1).

---

## 4. Soundness theorems

### Assumptions

Beyond `EnvelopeKeyfileCrypto.md`'s (C1)–(C4), this delta uses:

- **(C5) Argon2id memory-hardness.** Argon2id (RFC 9106) is a memory-hard function: computing `Argon2id(P, s, t, m, p)` requires materializing `m` KiB of memory and performing `t` passes over it, and no algorithm computes it in asymptotically less than `Ω(m·t)` memory-bandwidth-time without a proportional memory penalty (Biryukov–Dinu–Khovratovich, the RFC 9106 / PHC analysis). The data-independent addressing of pass-0 first-half (Argon2i component) plus the data-dependent addressing of the remainder (Argon2d component) is the RFC 9106 §3.4 hybrid.
- **(C6) BLAKE2b is a PRF / RO-indifferentiable compression core.** `determ_argon2id`'s block-mixing and its final tag are derived through BLAKE2b (`argon2id.h:2-3, :24`); the KDF output is computationally indistinguishable from uniform under an unknown password, the Argon2id analogue of `EnvelopeKeyfileCrypto.md`'s (C1) for the PBKDF2 leg.

### KM-1 — AEAD theorems carry over verbatim to DWE2

**Statement.** For a `DWE2` envelope, the confidentiality (KE-1), integrity (KE-2), and salt-uniqueness-independence (KE-3) results of `EnvelopeKeyfileCrypto.md` hold **verbatim**, with the sole change confined to KE-4's work bound (KM-2). Lemmas L-2 (ciphertext-body hiding), L-3 (GHASH ε-AXU MAC), L-4 (fail-closed decrypt), L-5 (fresh nonce+salt per encryption), and L-6 (salt as independent KDF input) apply unchanged.

**Proof.** KE-1/KE-2/KE-3 and L-2..L-6 are stated over the AEAD payload `[salt | nonce | ciphertext | tag]` and the `RAND_bytes`/`determ_rng_bytes`-drawn salt+nonce, and are agnostic to *how the 32-byte key is derived*. By §3.2 the AEAD leg is byte-identical between `DWE1` and `DWE2`: same `fill_salt_nonce` (`:77-83`), same `seal` → `determ_aes256_gcm_encrypt` (`:64-73`), same `determ_aes256_gcm_decrypt` tag-verify (`:158-165`), same fail-closed `std::nullopt` edges (`:137-141, :165`). The derived key is a uniform 32-byte value under (C6) exactly as it is under (C1) for PBKDF2, so L-2's "unknown key ⇒ keystream indistinguishable from uniform" and L-3's "unknown `H`, `E_K(J_0)`" premises hold identically. L-5's fresh-salt-per-encryption argument holds because `fill_salt_nonce` is shared; L-6's "distinct salts ⇒ independent keys" holds under (C6) as it did under (C1). Hence every AEAD-layer property transfers with no re-derivation. The *only* property whose quantitative bound moves is the passphrase-guessing work factor (KE-4), because that bound is a function of the KDF's per-candidate cost — addressed in KM-2. ∎

### KM-2 — memory-hard per-guess cost strictly hardens KE-4's dictionary bound

**Statement.** `A_passphrase_guess`'s per-candidate cost under `DWE2` is lower-bounded by **both** a time factor (`t_cost = 3` passes) **and** a memory factor (`m_cost = 64 MiB` that must be materialized and traversed), i.e. `Ω(m·t)` memory-bandwidth-time per guess (C5), with parallelism `p = 1`. This is a strict, qualitative hardening of `EnvelopeKeyfileCrypto.md` KE-4's dictionary-attack bound relative to PBKDF2, whose per-candidate cost is `iter` serial HMAC evaluations with **negligible memory** — a workload that GPUs and ASICs parallelize at very high throughput per dollar. Argon2id's mandatory 64 MiB working set caps an attacker's parallelism at (available memory bandwidth ÷ 64 MiB), so at equal defender wall-clock the effective per-candidate work is raised above the PBKDF2 baseline.

**Parameters (verified).** `t = 3`, `m = 64 MiB` (65,536 KiB), `p = 1` (`wallet/envelope.hpp:64-66`). These sit comfortably above the OWASP Argon2id minimum floor (`m ≥ 19 MiB`, `t ≥ 2`, `p = 1`).

**Argument.** By (C5), any evaluator of `Argon2id(P', s, 3, 64\text{MiB}, 1)` must hold ≈64 MiB live and stream it three times; there is no low-memory shortcut without a super-linear time penalty (the tradeoff-resistance of the Argon2d addressing). Against a PBKDF2 keyspace, `A_passphrase_guess` amortizes across thousands of parallel cores because each guess needs only a few hundred bytes of state; against Argon2id, the same silicon budget is bottlenecked on memory capacity and bandwidth rather than raw ALUs, which is precisely the GPU/ASIC-resistance property Argon2id was designed for. Substituting into KE-4's reduction: KE-4 writes the per-trial success as `2^{-(H_pw + log2(work_factor))}`; the migration replaces PBKDF2's `work_factor` (a pure-compute `iter`) with Argon2id's `Ω(m·t)` memory-bandwidth-bounded cost, which is strictly larger *per dollar of attacker hardware* at equal defender latency.

**We deliberately do not claim a specific bit-security number.** The `+bits` a memory-hard KDF buys is a function of the attacker's memory-bandwidth economics, not a clean `log2` of a compute count, so quoting a fixed exponent would overclaim. The honest statement is the qualitative-but-real one above: at equal defender wall-clock (~150–300 ms per derivation, `wallet/envelope.hpp:58-63`), Argon2id raises `A_passphrase_guess`'s real per-candidate cost above PBKDF2 by resisting the parallel-hardware discount PBKDF2 concedes. The operator-passphrase-entropy dependence of KE-4 is otherwise unchanged: `H_pw` still dominates, and the §6 `H_pw ≥ 80`-bit recommendation of `EnvelopeKeyfileCrypto.md` still governs. ∎

### KM-3 — versioned back-compat: no orphaned envelopes

**Statement.** Every `DWE1` envelope ever written to disk still decrypts byte-for-byte after R58; the 4-byte magic selects the KDF; an unknown magic fails closed (`deserialize → std::nullopt`). A versioned format migration never orphans field envelopes.

**Proof.** `deserialize` (`wallet/envelope.cpp:230-274`) reads the 4-byte magic and accepts *only* `MAGIC1_LE` or `MAGIC2_LE`, returning `std::nullopt` on any other value (`:243`). On `MAGIC1_LE` it takes the 4-byte-`params` PBKDF2 branch (`:258-262`) and sets `env.kdf = Kdf::PBKDF2`; `decrypt` then routes to `derive_key_pbkdf2` (`:149-151`), i.e. the identical legacy KDF+AEAD path. The invariant is regression-locked two ways:

1. **Format-freeze guard.** `tools/test_wallet_envelope_compat.sh` embeds a `DWE1` blob generated by a *past* build (`44574531.…`, magic `DWE1`, 10,000 iters, `:86-89`) and requires it to decrypt to the exact pinned payload; its header (`:22-27`) forbids re-pinning the fixture absent a versioned migration with a legacy-decrypt path — which R58 is. The guard stays green post-R58 because the `DWE1` read path is untouched.
2. **Migration test leg 3.** `tools/test_wallet_keyfile_argon2.sh:90-98` re-decrypts the *same* pinned pre-R58 `DWE1` fixture with the current binary and asserts byte-for-byte equality ("pinned pre-R58 DWE1 envelope decrypts"), directly proving the migration did not orphan it. Test leg 2 (`:85-88`) independently confirms a fresh `--iters` `DWE1` blob still round-trips at HEAD.

Unknown/garbage magic → `nullopt` (`:243`) is the fail-closed catch-all for anything that is neither layout. ∎

### KM-4 — fail-closed KDF-parameter validation

**Statement.** `deserialize`/`decrypt` reject every malformed or degenerate envelope with `std::nullopt`, and a wrong passphrase fails the AEAD tag (CLI exit 2) on **both** layouts. Specifically:

- A `DWE2` blob whose `params` slot ≠ 12 bytes → `nullopt` (`wallet/envelope.cpp:251`).
- A `DWE2` blob with `argon2_t == 0`, `argon2_p == 0`, or `argon2_m_kib < 8·argon2_p` → `nullopt`, checked at **both** deserialize (`:256-257`) and decrypt (`:145-146`), matching the encrypt-side guard (`:92-93`).
- A `DWE1` blob whose `params` ≠ 4 bytes → `nullopt` (`:259`); `iters == 0` → `nullopt` at deserialize (`:262`) and decrypt (`:150`).
- Structural failures — `parts.size() != 6` (`:238`), 4-byte-magic check (`:241`), `salt.size() < 8` (`:247`), `nonce.size() != 12` (`:266`), `ciphertext.size() < 16` (`:269`), any `from_hex` exception (`:271-272`) — all → `nullopt`.
- A wrong passphrase derives a wrong key; `determ_aes256_gcm_decrypt` fails the constant-time tag compare and returns non-zero → `nullopt` (`:165`), surfaced as CLI exit 2.

**Proof.** By case analysis over the read-path exit edges cited above: every rejection edge returns `std::nullopt`; the constructed `Envelope` is returned only when all width, magic, size, and KDF-parameter checks pass (`:270`). The Argon2-parameter guard `m_kib < 8·p` mirrors `determ_argon2id`'s own `m_cost ≥ 8·parallelism` precondition (`include/determ/crypto/argon2/argon2id.h:37-38`), so a blob that would make the KDF itself return `-1` is rejected *before* derivation rather than throwing. The wrong-passphrase→exit-2 contract is verified on both layouts by test leg 4 (`tools/test_wallet_keyfile_argon2.sh:100-108`: `RC2==2` for DWE2, `RC1==2` for DWE1) and, for the pinned legacy blob, by the format-freeze guard's leg 3 (`tools/test_wallet_envelope_compat.sh:113-120`). This is `EnvelopeKeyfileCrypto.md` L-4 (fail-closed, leakage-bounded decrypt) extended to the new parameter slot. ∎

### KM-5 — non-claims (honest boundary)

R58 hardens the at-rest KDF; it does **not** claim, and this proof does **not** establish, the following:

1. **Argon2id's data-dependent passes are NOT constant-time — by design.** Pass-0's first half is data-*independent* (Argon2i addressing over public parameters only); the remaining slices/passes are data-*dependent*, so their memory-access pattern is a function of the password (`include/determ/crypto/argon2/argon2id.h:13-25`). An adversary with cache/power side-channel measurement on the host *during KDF execution* could in principle learn password information. This is the Argon2d GPU-resistance component, **not a defect**; the threat model trusts the host against fine-grained microarchitectural side channels (same posture as `EnvelopeKeyfileCrypto.md` §2.3 / F-sidechannel for the AES/GHASH primitives). It does not affect the at-rest bounds KM-1..KM-4.
2. **No specific bit-security uplift is quantified.** KM-2 asserts a qualitative-but-real hardening only; the memory-hardness `+bits` depends on attacker memory economics and is not reduced to a fixed exponent (see KM-2's "we deliberately do not claim").
3. **On-wire / consensus surface is unchanged.** This is at-rest keyfile KDF hardening only. No transaction, block, snapshot, RPC, or consensus byte changes; the wallet-envelope TCB is disjoint from the chain path.
4. **No in-place re-keying of existing DWE1 files.** R58 does not migrate envelopes already on disk. They keep decrypting under PBKDF2 (KM-3) and upgrade to Argon2id **opportunistically** on the next `keyfile-reencrypt` / `envelope encrypt` (re-wrap under the Argon2id default), verified by test leg 5 (`tools/test_wallet_keyfile_argon2.sh:110-132`: a re-encrypted keyfile reports `"kdf":"argon2id"` and preserves the seed). An operator who never re-encrypts retains a `DWE1` file at its original PBKDF2 cost — a deliberate, documented choice, not a silent downgrade.

---

## 5. Theorem → assumption map

| Theorem | Property | Rests on | Source anchors |
|---|---|---|---|
| KM-1 | AEAD (KE-1/KE-2/KE-3, L-2..L-6) carry over to DWE2 | byte-identical AEAD leg + (C6) | `envelope.cpp:64-75, 77-83, 158-165`; `EnvelopeKeyfileCrypto.md` KE-1..KE-3 |
| KM-2 | Memory-hard per-guess cost hardens KE-4's dictionary bound | (C5) + KE-4 | `envelope.hpp:64-66`; `argon2id.h:1-25`; OWASP floor `m≥19MiB/t≥2` |
| KM-3 | Versioned back-compat; no orphaned envelopes | magic-select + fail-closed unknown | `envelope.cpp:243, 258-262`; `test_wallet_envelope_compat.sh`; `test_wallet_keyfile_argon2.sh:90-98` |
| KM-4 | Fail-closed KDF-param validation, both layouts | L-4 extended to params slot | `envelope.cpp:92-93, 145-146, 238-269`; `test_wallet_keyfile_argon2.sh:100-108` |
| KM-5 | Non-claims (side-channel, no bit number, no wire change, no in-place re-key) | — | `argon2id.h:13-25`; `test_wallet_keyfile_argon2.sh:110-132` |

---

## 6. Implementation cross-references

| Surface | Location | Role |
|---|---|---|
| Two-layout API + Argon2id defaults | `wallet/envelope.hpp:9-31, 40-70` | `Kdf` enum; `encrypt`(=Argon2id)/`encrypt_argon2id`/`encrypt_pbkdf2`; `t=3`/`m=64MiB`/`p=1`/salt=16 |
| Magic discriminators | `wallet/envelope.cpp:25-26` | `MAGIC1_LE`=DWE1, `MAGIC2_LE`=DWE2 |
| Argon2id KDF leg | `wallet/envelope.cpp:45-60` + `include/determ/crypto/argon2/argon2id.h:41-44` | RFC 9106 v1.3 on C99 BLAKE2b |
| Shared AEAD leg (KM-1) | `wallet/envelope.cpp:64-83` | `seal` + `fill_salt_nonce` — identical bytes both layouts |
| `encrypt` default = Argon2id | `wallet/envelope.cpp:126-131` | R58 default flip |
| Encrypt-side param guard | `wallet/envelope.cpp:92-93` | `t==0 ∥ p==0 ∥ m<8·p` → throw |
| Serialize (params-slot width) | `wallet/envelope.cpp:208-228` | 12-byte DWE2 / 4-byte DWE1 params |
| Deserialize (magic-select + validate) | `wallet/envelope.cpp:230-274` | KM-3 + KM-4 read-path gates |
| Decrypt (KDF auto-detect + validate) | `wallet/envelope.cpp:133-167` | `env.kdf` route + Argon2 param check + fail-closed |
| `inspect-envelope` KDF-aware report | `wallet/main.cpp:1112-1210` (JSON body `:1168-1197`) | `format`/`kdf`/`argon2_t_cost`/`argon2_m_cost_kib`/`argon2_lanes` |
| `keyfile-info` KDF-aware report | `wallet/main.cpp:5930-6068` (envelope block `:6035-6059`) | same metadata, node keyfile, no decrypt |
| `account-import-many` structural check | `wallet/main.cpp:2890-2916` | KDF-aware: DWE2 keys on `argon2_t`, DWE1 on `pbkdf2_iters` |
| Migration test (18/0, 5 legs) | `tools/test_wallet_keyfile_argon2.sh` | KM-2/KM-3/KM-4 + reencrypt upgrade path (KM-5.4) |
| Format-freeze guard | `tools/test_wallet_envelope_compat.sh` | KM-3 pinned pre-R58 DWE1 fixture stays green |

**Companion proofs.**

- `EnvelopeKeyfileCrypto.md` — the `DWE1` AEAD primitive proof (KE-1 confidentiality, KE-2 integrity, KE-3 salt-uniqueness, KE-4 passphrase-strength; lemmas L-1..L-6). KM-1 inherits KE-1/KE-2/KE-3 and L-2..L-6 verbatim; KM-2 refines KE-4.
- `S004KeyfileAtRest.md` — the application-layer node-keyfile-at-rest proof (T-1..T-5). Unaffected by R58: the migration is KDF-only and does not touch the `DETERM-NODE-V1` header, pubkey-as-AAD binding, or startup-load path.
- `Preliminaries.md` (F0) — CSPRNG-uniformity and hash assumptions feeding (C6).

---

## 7. Status

**Specification complete.** KM-1 (AEAD carry-over), KM-2 (memory-hard cost hardening), KM-3 (versioned back-compat), KM-4 (fail-closed param validation), KM-5 (non-claims) are stated and proved against the verified R58 parameters: Argon2id (RFC 9106, `t=3`, `m=64 MiB`, `p=1`) over a 16-byte per-envelope salt, feeding the **unchanged** AES-256-GCM AEAD (12-byte nonce, 16-byte tag, 32-byte key), versioned by the `DWE2` magic with `DWE1` legacy-decrypt retained.

**Implementation shipped (R58, commit `ed39cf2`).** `wallet/envelope.{hpp,cpp}` + `include/determ/crypto/argon2/argon2id.h` on `main`; `encrypt` defaults to Argon2id; PBKDF2 retained for interop; `keyfile-reencrypt` is the opportunistic upgrade path.

**Regression tests passing.** `tools/test_wallet_keyfile_argon2.sh` (18 assertions / 5 legs: fresh DWE2 create+decrypt, magic-based KDF selection, pinned DWE1 back-compat, wrong-passphrase fail-closed on both layouts, reencrypt upgrade) plus the `tools/test_wallet_envelope_compat.sh` format-freeze guard staying green.

**Residuals (advisory, KM-5).** Argon2id data-dependent-pass side-channel (host trusted, by design); no quantified bit uplift; at-rest-only (no wire/consensus change); no in-place re-key (opportunistic upgrade). None invalidates KM-1..KM-4; this document adds analytic coverage only and modifies no source.
