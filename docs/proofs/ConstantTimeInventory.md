> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# C99 Crypto Stack — Per-Primitive Constant-Time Inventory

**Subject:** the secret-input surface and constant-time mechanisms of every module
in the libsodium-free C99 cryptographic stack — `src/crypto/{sha2,blake2,argon2,
chacha20,aes,ed25519,x25519,frost,p256}/` — as implemented, function by function.

**Purpose:** this is the seed inventory for CRYPTO-C99-SPEC.md §3.12 (the
dudect/ctgrind constant-time verification framework). §3.12 needs a concrete list
of *what to measure and why*; that list falls out of knowing, per module, (a) which
inputs are secret, (b) which mechanism keeps the secret-dependent work
constant-time, (c) where every secret-adjacent comparison happens, and (d) which
spots are deliberately NOT constant-time and on what justification. The
adversarial findings audit is `C99CryptoStackAudit.md` (§4, §6–§8f there cover the
per-module CT verdicts); this document is the systematic inventory layered on top.

**Verdict in one line:** every secret-bearing code path in the stack is
constant-time at the source level by one of five named mechanisms (rotation-only
ARX, branchless carry/mask arithmetic, no-table arithmetic S-box, cswap ladder,
no-short-circuit aggregate compare); the residual data-dependent control flow is
exhaustively keyed on public values (lengths, public encodings, protocol-mandated
public constants) with one deliberate by-design exception (Argon2id's
data-dependent passes, RFC 9106), two Info-level discipline notes, and one Low
CT residual — the P-256 `scalar_ok` range check (P256-CT-1) — REMEDIATED
in-session (§4.2; `be_lt` made branchless).

---

## 1. Scope and conventions

### 1.1 What "constant-time" means here

A function is constant-time (CT) when its running time, branch trace, and memory
access pattern are independent of *secret* data. Three leak classes are inventoried:

1. **Secret-dependent branches** — `if`/loop conditions computed from key material.
2. **Secret-dependent memory indexing** — table lookups indexed by key bytes (the
   classic AES cache-timing channel).
3. **Short-circuiting comparisons** — `memcmp`-style early exit, whose duration
   reveals the length of the matching prefix of a MAC/tag/signature.

### 1.2 The public-length contract

Per `include/determ/crypto/ct.h`: buffer **lengths are treated as public**
throughout the stack ("Do not encode secrets in buffer lengths"). Every
length-dependent branch and loop bound (`msglen`, `aadlen`, `keylen`, `outlen`,
`iters`, `t`, `n`) is therefore *justified non-CT by contract* and is listed once
in §4.1 rather than re-litigated per module. This includes password length in
PBKDF2/Argon2id: an observer who can time the KDF learns `pwdlen` — the standard
posture for password KDFs, inherited from the same contract.

Heap allocations (`malloc` in `hmac.c`, `hkdf.c`, `pbkdf2.c`, `ed25519.c` sign/
verify, `frost.c`) are sized from public lengths only, so allocator timing leaks
nothing beyond those lengths.

### 1.3 The shared §3.10 primitives

- **`determ_ct_memcmp`** (`include/determ/crypto/ct.h` + `src/crypto/ct.c`) — the
  one audited equality compare: XOR-differences accumulated with OR across the
  full length, no early return, branchless collapse of the accumulator (the
  unsigned-borrow idiom); running time depends only on `len`. Returns 0 iff
  byte-identical, -1 otherwise (the libsodium `crypto_verify` shape — callers
  should still treat the contract as "0 / nonzero" per `ct.h`);
  **equality only** (no lexicographic order). It consolidates the per-module local
  helpers the stack previously accumulated (`ct_eq16` in `aes_gcm.c` and
  `chacha20_poly1305.c`, `ct_verify_32` in `ed25519.c`, and the point-compare
  `memcmp`s in `frost.c`) into one site. Functional contract pinned by
  `determ test-ct-c99` / `tools/test_ct_c99.sh`; the *timing* property is exactly
  what §3.12 must measure (a functional test cannot).
- **`determ_secure_zero`** (`include/determ/crypto/secure_zero.h`) — the memory-
  hygiene half of §3.10: a dead-store-elimination-proof wipe applied to every
  secret-bearing local across the stack (audit §5.1). It is a hygiene primitive,
  not a timing one; it appears below only where its placement matters.

### 1.4 Module → secret map (summary)

| Module | Secret inputs | Core CT mechanism | Secret-adjacent compares |
|---|---|---|---|
| sha2 (SHA-256/512, HMAC, HKDF, PBKDF2) | HMAC keys, HKDF IKM/PRK/OKM, PBKDF2 password + derived key | data-independent compression (rotate/XOR/add, counter-indexed constants) | none in-module (no tag verify) |
| blake2 (BLAKE2b) | optional MAC key; Argon2id intermediates | rotation-only ARX `G`; counter-indexed `SIGMA` | none in-module |
| argon2 (Argon2id) | password; entire block memory (password-derived) | pass-0 first half data-independent; rest data-dependent **by design** | none in-module |
| chacha20 (ChaCha20, Poly1305, AEAD, XChaCha) | key, keystream, one-time Poly1305 (r,s), accumulator | rotation-only ARX; branchless 5×26 limb carry + mask-select reduction | AEAD tag verify → `determ_ct_memcmp` |
| aes (AES-256 core, GCM) | key, round-key schedule, state, GHASH subkey H, tag mask E_K(J0) | arithmetic no-table S-box (`aes_sbox_ct`); branchless bit-serial GHASH | GCM tag verify → `determ_ct_memcmp` |
| ed25519 | seed, clamped scalar a, prefix, nonce r, S intermediates; FROST scalars via the group API | cswap ladder (`scalarmult`/`sel25519`); branchless `car25519`/`modL`/`sc_lt_L` | verify R-compare → `determ_ct_memcmp` |
| x25519 | DH scalar, shared secret | Montgomery cswap ladder (`sel25519`), fixed 255 iterations | low-order check = branchless OR-aggregate (result is the public return) |
| frost | dealer secret + poly coefficients, shares s_i, nonces d_i/e_i, partials z_i, DKG a_0 + PoP nonce, PSS δ coefficients | all secret scalars flow only through the ed25519 CT scalar/point layer | VSS/PoP point compares → `determ_ct_memcmp` (public operands; discipline) |
| p256 (NIST P-256 / OPRF-P256) | ECDH/base-mul scalar, OPRF blind + input, OPRF server key sk, mod-n scalar operands | double-and-add-always RCB ladder (`pt_scalar_mul` uniform `pt_add`+`pt_cswap`/bit); mask-select field ops (`fe_add`/`fe_sub`/`fe_cswap`/`fe_cmov`); branchless SSWU; Fermat inversions on public exponents | VOPRF DLEQ challenge compare → `determ_ct_memcmp` (public operands; the encodings compared elsewhere are public) |

---

## 2. Per-module inventory

### 2.1 sha2 — SHA-256 / SHA-512 / HMAC / HKDF / PBKDF2

**Files:** `src/crypto/sha2/{sha256.c,sha512.c,hmac.c,hkdf.c,pbkdf2.c}`.

**Secret inputs.** The hashes themselves are unkeyed, but they are the engine for
keyed consumers: `determ_hmac_sha256/512` feed the secret key through the
ipad/opad blocks; `determ_hkdf_sha256` handles the IKM, the PRK (whose recovery
derives all OKM), and the OKM blocks; `determ_pbkdf2_hmac_sha256` handles the
password (as HMAC key) and the derived key blocks `U`/`T` — this is the S-004
wallet-keyfile KDF. `determ_sha512` additionally hashes the Ed25519 secret seed
and the FROST nonce-derivation inputs (see §2.6/§2.8).

**CT mechanisms as implemented.**
- `sha256_block` / `sha512_block`: data-independent compression — rotate/XOR/add
  plus the bitwise Ch/Maj selects (`rotr32`/`rotr64` with compile-time shift
  counts; the AND/NOT in Ch/Maj are as data-independent as the XORs); the
  round-constant tables `K256[i]` / `K512[i]` are indexed by the **loop
  counter**, never by data — no data-dependent table lookup exists. The message
  schedule `w[]` is filled and consumed with fixed loop bounds.
- `determ_sha256` / `determ_sha512`: the only branches (`if (rem)`, the
  `padlen = (rem < 56u) ? 64u : 128u` selection — `(rem < 112u) ? 128u : 256u`
  in the SHA-512 variant — and the second-block branch) key off the **public
  message length**, never message content.
- `determ_hmac_sha256/512`: the `keylen > B` branch and all loop bounds are
  functions of public lengths; key bytes flow only through data-independent
  XOR (`k0[i] ^ 0x36u` / `^ 0x5cu`), copy, and hash.
- `determ_hkdf_sha256` / `determ_pbkdf2_hmac_sha256`: all control flow
  (`outlen`, `infolen`, `saltlen`, `blocks`, `iters`) is public-parameter-driven;
  the per-iteration `T[k] ^= U[k]` XOR loop is fixed-bound (hLen).

**Comparisons.** None in-module: these functions emit MACs/keys and perform no
tag verification. The compare obligation falls on callers (e.g. the RPC-auth HMAC
verify), which is exactly what `determ_ct_memcmp` exists for (§1.3).

**Residual non-CT.** Public-length branches only (§1.2). PBKDF2's iteration count
`iters` and block count are public parameters.

### 2.2 blake2 — BLAKE2b

**File:** `src/crypto/blake2/blake2b.c`.

**Secret inputs.** The optional MAC key in `determ_blake2b_init` (keyed mode:
the key becomes its own zero-padded first block); in the Argon2id stack every
input block is password-derived secret material.

**CT mechanisms as implemented.**
- The `G` macro is rotation-only ARX (`rotr64` with constants 32/24/16/63); the
  permutation schedule `SIGMA[r][...]` is indexed by the round and position
  counters, never by data.
- `compress` runs a fixed 12 rounds over fixed lanes; `load64`/`store64` are
  fixed 8-byte loops.
- `determ_blake2b_update`'s buffering branches (`inlen > fill`, the
  `while (inlen > DETERM_BLAKE2B_BLOCKBYTES)` loop) and `determ_blake2b_final`'s
  zero-pad `memset` depend only on public lengths (`inlen`, `buflen`).
- `determ_blake2b_init` branches on `keylen` (public length); key bytes are
  copied, never branched on. The key block is wiped (`determ_secure_zero`) after
  absorption, and `determ_blake2b_final` wipes the whole context.

**Comparisons.** None in-module (parameter validation `outlen`/`keylen` bounds
are public).

**Residual non-CT.** Public-length branches only.

### 2.3 argon2 — Argon2id

**File:** `src/crypto/argon2/argon2id.c`.

**Secret inputs.** The password `pwd` (hashed into `H0` with BLAKE2b), and
transitively the entire `B[]` block memory plus every `fill_block` intermediate —
all derived from `H0`. The salt and cost parameters are public.

**CT mechanisms as implemented (where CT is intended).**
- `fBlaMka`, the `GB`/`P` permutation, and `fill_block`'s row/column passes are
  branchless ARX-with-multiply over fixed loop bounds — no data-dependent branch
  inside the compression itself.
- **The Argon2id hybrid schedule:** `determ_argon2id` computes
  `data_indep = (pass == 0 && slice < SYNC_POINTS / 2)` — the first half of pass
  0 derives reference indices from a counter-seeded address block
  (`input.v[0..6]` = pass/lane/slice/mem/t_cost/type/counter, expanded via two
  `fill_block` calls), i.e. **data-independently**, exactly per RFC 9106 §3.4.
  This is the half that shields the password during the earliest, most
  leak-sensitive memory accesses.

**Comparisons.** None (parameter guards are on public values).

**Residual non-CT — BY DESIGN (justified).** In every other segment
(`data_indep == 0`) the pseudo-random word is `pr = B[prev].v[0]` — secret-derived
— and `index_alpha(...)` turns it into the reference-block index `ref_index`, so
the **memory access pattern is deliberately data-dependent**. This is the Argon2d
component: the data-dependence is the GPU/ASIC-resistance mechanism and is
RFC 9106-conformant. It is documented in the module header and in
CRYPTO-C99-SPEC §3.6 ("memory-hard, NOT constant-time in the data-dependent
passes by design"). The §3.12 obligation for this module is therefore *negative
scoped*: verify the pass-0 first half really is data-independent, not that the
whole function is CT (§5, target 10). `index_alpha`'s internal branches key on
pass/slice/`same_lane` — public schedule parameters.

### 2.4 chacha20 — ChaCha20 / Poly1305 / ChaCha20-Poly1305 / XChaCha20-Poly1305

**Files:** `src/crypto/chacha20/{chacha20.c,poly1305.c,chacha20_poly1305.c,xchacha20_poly1305.c}`.

**Secret inputs.** The 256-bit key (loaded into `st[4..11]`); the raw keystream
(`block[]`, plaintext-equivalent under known plaintext); the one-time Poly1305 key
`otk` = (r,s) derived from the keystream (`poly1305_keygen`); the Poly1305 key
limbs `r0..r4`/`s1..s4`, pad `pad0..pad3`, and accumulator `h[]`; the HChaCha20
subkey in the XChaCha wrapper.

**CT mechanisms as implemented.**
- `chacha20_block` / `determ_hchacha20`: rotation-only ARX — the `QR` macro is
  add/XOR/`rotl32` with compile-time shift constants {16,12,8,7}; no S-box, no
  table lookup, no secret-dependent branch; fixed 10 double-rounds.
- `determ_poly1305`: the canonical 5×26-bit-limb arithmetic with **branchless
  carry chains** (`c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;` …)
  in `poly1305_absorb` and the final full carry; the final reduction selects `h`
  vs `h − p` via the **unsigned-shift mask** `mask = (g4 >> 31) - 1` and
  mask-AND/OR blending — no branch on the comparison result. The only
  data-dependent control flow is on the public byte count.
- `aead_tag` builds the MAC input from public data only (AAD, ciphertext,
  lengths); the secret `otk` enters only `determ_poly1305`.
- `determ_chacha20_poly1305_decrypt` computes the expected tag **before**
  releasing any plaintext (nothing is written on auth failure) and scrubs
  `otk`/`expect` on every path.
- The XChaCha wrapper adds only `determ_hchacha20` (ARX, above) + public
  nonce-splicing in `derive`; the subkey is wiped per call.

**Comparisons.** The AEAD tag verification in
`determ_chacha20_poly1305_decrypt` is a 16-byte no-short-circuit aggregate
compare routing through **`determ_ct_memcmp`** (CRYPTO-C99-SPEC §3.10 — the
consolidation of this file's former local `ct_eq16` into the shared audited
site). The XChaCha decrypt inherits it by composition.

**Residual non-CT.** Public-length branches (`while (done < len)`,
`bytes >= 16`, partial-block handling) only. The 32-bit block-counter wrap
(audit §3.12 there) is a correctness boundary, not a timing one.

### 2.5 aes — AES-256 core / AES-256-GCM

**Files:** `src/crypto/aes/{aes_core.c,aes_gcm.c}`.

**Secret inputs.** The 256-bit key; the expanded round-key schedule `ctx->rk`
(240 bytes, invertible to the key); the cipher state `s[16]` (key-mixed every
round); the GHASH subkey `H = E_K(0^128)`; the tag mask `ej0 = E_K(J0)`; the
GCTR keystream blocks `ks`.

**CT mechanisms as implemented.**
- **No-table S-box:** `aes_sbox_ct` computes SubBytes arithmetically — `gf_inv`
  is a *fixed* x^254 square-and-multiply addition chain over `gf_mul`, which is a
  branchless fixed-8-iteration multiply with mask-selected partial products
  (`p ^= a & (0u - (b & 1))`) and mask-selected reduction
  (`a ^= 0x1b & hi`, `hi = 0u - ((a >> 7) & 1)`). The canonical `SBOX[256]`
  table exists **only** as the validation oracle for
  `determ_aes256_sbox_selftest` (exhaustive 256-input equality, driven by
  `determ test-aes-c99`); the cipher never indexes it — the classic AES
  cache-timing channel is structurally absent.
- `xtime` is a branchless mask-multiply (`((x >> 7) & 1) * 0x1b`);
  `shift_rows`/`mix_columns` use fixed indices; `determ_aes256_encrypt_block`
  runs fixed 14 rounds; `determ_aes256_init`'s `(i % 32)` branches key on the
  loop counter, not on key bytes.
- **Branchless GHASH:** `ghash_mul` is a bit-serial GF(2^128) multiply with a
  fixed 128 iterations; the per-bit select is the full-width mask
  `mask = (uint8_t)(0u - xbit)` and the reduction is
  `V[0] ^= 0xe1u & (0u - lsb)` — no secret-dependent branch or access pattern.
  `ghash_update`/`gcm_crypt` branch only on public lengths.

**Comparisons.** The GCM tag verification in `determ_aes256_gcm_decrypt` routes
through **`determ_ct_memcmp`** (§3.10; formerly this file's local `ct_eq16`).
Decrypt verifies the tag before producing any plaintext.

**Residual non-CT.** Public-length branches only. (Hygiene note, not timing: see
§4.2 CTI-2 on the decrypt-side `expect[16]` wipe.)

### 2.6 ed25519 — Ed25519 sign/verify + the FROST scalar/group layer

**File:** `src/crypto/ed25519/ed25519.c` (group API in `ed25519_group.h`).

**Secret inputs.** The 32-byte seed; the SHA-512 seed expansion `h[64]` (clamped
scalar `a` = h[0..31], prefix = h[32..63]); the per-signature nonce scalar `r`
(`rh`); the `S = r + k·a mod L` accumulation array `x[64]`; and — via the
exported `determ_ed25519_sc_*` / `determ_ed25519_point_*` API — every FROST
secret scalar (§2.8). Public-key derivation (`determ_ed25519_pubkey_from_seed`)
and signing run the ladder on secret scalars; verification operates on public
data throughout.

**CT mechanisms as implemented.**
- **cswap ladder:** `scalarmult` runs a fixed 256 iterations; each iteration
  executes **both** `add(q, p)` and `add(p, p)` unconditionally, and the secret
  bit flows only through `cswap` → `sel25519`, whose select is the arithmetic
  mask `c = ~(b - 1)` with XOR-swap — no secret-dependent branch, index, or
  table (the table-free `gf[16]` form is what makes this auditable; there is no
  ref10-style precomputed base table to index). `scalarbase` reuses the same
  ladder.
- **Branchless field arithmetic:** `car25519`'s carry chain uses the
  index-arithmetic trick `o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15)`
  (no branch); `M`/`S`/`A`/`Z` are fixed-bound schoolbook loops; `pack25519`'s
  conditional subtraction of p is performed twice with the borrow-derived bit fed
  to `sel25519` — masked select, not a branch; `inv25519`/`pow2523` iterate a
  **public fixed exponent** schedule (the `if (a != 2 && a != 4)` branch in
  `inv25519` and the `if (a != 1)` branch in `pow2523` key on the loop counter).
- **Branchless mod-L scalar arithmetic:** `modL` (and `reduce`) propagate carries
  arithmetically over fixed loop bounds; the `S`-computation in
  `determ_ed25519_sign` is a fixed 32×32 product loop into `x[]` then `modL`.
  `determ_ed25519_sc_muladd` (the Horner workhorse for FROST) is the same
  fixed-shape multiply + `modL`.
- `sc_lt_L` — the RFC 8032 §5.1.7 canonicality gate — computes `s − L` byte-wise
  and inspects only the final borrow: constant-time by construction (no
  data-dependent branch), exported as `determ_ed25519_sc_is_canonical`.
- `determ_ed25519_sc_invert` branches on the bits of the **public constant**
  exponent L−2 (Fermat inversion), not on the base — documented in-source.

**Comparisons.**
- The verifier's final acceptance — recomputed `[S]B − [k]A` against the
  signature's R encoding — routes through **`determ_ct_memcmp`** (§3.10; the
  former local `ct_verify_32`). Both operands are public on this path; the CT
  compare is uniform discipline.
- `neq25519` (internal): packs both field elements and OR-aggregates all 32 byte
  differences before branching on the aggregate — used only inside point
  decompression (`unpackneg`/`point_unpack`) on **public** point encodings.
- `point_y_is_canonical` (RFC 8032 §5.1.3 gate): OR-aggregate compare, branch on
  public key bytes — explicitly annotated in-source as not a CT concern.

**Residual non-CT (justified).** All data-dependent branches are on PUBLIC
values: signature/public-key decode validity (`unpackneg`, `point_unpack`,
`point_y_is_canonical`, `sc_lt_L` result), message lengths, and loop counters.
Verification is a public-data computation end to end.

### 2.7 x25519 — X25519 Diffie-Hellman

**File:** `src/crypto/x25519/x25519.c`.

**Secret inputs.** The DH scalar (clamped into a private copy `z[]` per RFC 7748
§5 — pure bitwise masking); the shared-secret output and all ladder
intermediates (`x[80]`, `a..f`).

**CT mechanisms as implemented.**
- **Montgomery cswap ladder:** `determ_x25519` runs a fixed 255 iterations
  (i = 254..0); the secret bit `r` flows only through the paired
  `sel25519(a,b,r)` / `sel25519(c,d,r)` masked swaps (mask `c = ~(b - 1)`) at the
  top and bottom of each iteration; the ladder body (`fadd`/`fsub`/`fmul`/`fsqr`
  with the constant `_121665`) executes identically every iteration.
- Same branchless `car25519`/`pack25519`(+`sel25519`)/field core as §2.6 (shared
  TweetNaCl `gf[16]` lineage); `inv25519` iterates the public exponent p−2 and
  wipes its scratch (audit finding X25519-MEM-001, remediated).

**Comparisons.** The RFC 7748 contributory check accumulates
`allzero |= out[k]` over all 32 output bytes — a no-short-circuit OR-aggregate —
then branches once on the aggregate. The branch outcome IS the function's public
return value (−1 on a low-order/all-zero result), so nothing is leaked that the
caller-visible result does not already reveal. Justified.

**Residual non-CT.** Only that return-value branch (above). `determ_x25519_base`
adds nothing secret-dependent (fixed base point).

### 2.8 frost — FROST-Ed25519 keygen / two-round sign / DKG / PSS

**File:** `src/crypto/frost/frost.c`. (Status note: per `FROST_DEVIATION_NOTICE.md`
and the CRYPTO-C99-SPEC.md header notice, the FROST module was library-only OUTSIDE
the v1.1 consensus path and was REMOVED from the tree 2026-07-09 (register B2);
this CT inventory is the retained design record.)

**Secret inputs.** The trusted-dealer group secret + polynomial coefficients
(`determ_frost_keygen_trusted`); every participant share `s_i` (and the
reconstructed secret in `determ_frost_reconstruct`); the round-1 nonces
`d_i`/`e_i` and round-2 partials `z_i` (`determ_frost_sign`,
`determ_frost_sign_partial`); the DKG polynomial — in particular `a_0` — and the
deterministic PoP nonce `kn` (`determ_frost_dkg_commit`); the PSS zero-hole
coefficients δ_1..δ_{t−1} (`determ_frost_pss_commit`). Public: signer index sets
`xs[]`, commitment lists D/E, binding factors ρ (derived from public data —
freed without scrubbing, annotated in-source), the message, group_pk, and all
Feldman commitments.

**CT mechanisms as implemented.**
- **Everything secret rides the §2.6 CT layer.** Every secret scalar flows
  exclusively through `determ_ed25519_sc_muladd` / `sc_mul` / `sc_add` / `sc_sub`
  (branchless modL) and `determ_ed25519_point_basemul` (cswap ladder):
  Horner evaluation in `determ_frost_keygen_trusted` and `frost_poly_eval`;
  the `z_i = d_i + e_i·ρ_i + λ_i·s_i·c` chains in `determ_frost_sign` /
  `determ_frost_sign_partial`; the share accumulation in
  `determ_frost_reconstruct`; the PoP response `z = c·a_0 + kn` in
  `determ_frost_dkg_commit`. No FROST function branches on or indexes by a
  secret scalar's value.
- `frost_lagrange` and `frost_check_signer_set` operate purely on the public
  index set `xs[]` (range/duplicate guards are public-parameter validation);
  `determ_ed25519_sc_invert` inside Lagrange runs on a denominator derived from
  public indices, with a public fixed exponent.
- `frost_binding_and_challenge` hashes only public data (domain ‖ index ‖ D/E
  lists ‖ msg; R ‖ group_pk ‖ msg). `determ_frost_dkg_commit` does feed the
  secret `a_0` into the SHA-512 nonce derivation (`nb` buffer) — the
  RFC-6979-style deterministic-nonce pattern; SHA-512's compression is
  data-independent (§2.1), and `nb`/`hbuf`/`kn`/`z` are wiped before return.
- `determ_frost_pss_commit`'s zero-hole check accumulates all 32 bytes of δ_0
  into one OR (`hole |= zeropoly[k]`) and branches once on the aggregate —
  hardened to the house branchless form (audit §8b, PSS-CT-001) even though the
  checked bytes are the protocol-mandated PUBLIC zero constant term.

**Comparisons.** The Feldman-VSS share check (`determ_frost_dkg_verify_share`:
`[share]B` vs `Σ_k j^k·C_k`) and the PoP check (`determ_frost_dkg_verify_pop`:
`[z]B` vs `R + [c]A_0`) route through **`determ_ct_memcmp`** (§3.10 — the
consolidation of this file's former point-compare `memcmp`s). Note the operand
class: both sides are **group elements that are publicly recomputable on the
honest path** (commitments and PoPs are broadcast values), so the uniform CT
compare here is *discipline, not a fix* — it removes the per-site "is this
operand really public?" review burden (the rationale recorded in `ct.h`), it
does not close a live timing leak. The in-source comments at both call sites say
exactly this.

**Residual non-CT.** Public-parameter guards (`t`, `idx`, `pos`, `msglen` cap,
`xs` distinctness); the point-decode failure branches inside
`determ_ed25519_point_mul`/`point_add` (public encodings). One discipline note:
`determ_frost_pss_verify_commit` — see §4.2 CTI-1.

### 2.9 p256 — NIST P-256 (secp256r1) + OPRF-P256 (RFC 9497)

**File:** `src/crypto/p256/p256.c` (public API in
`include/determ/crypto/p256/p256.h`). CRYPTO-C99-SPEC.md §3.8c (the FIPS-profile
curve — supplants secp256k1 in the `tactical`/`cluster` profiles) with the §3.9b
OPRF groundwork (RFC 9380 hash-to-curve) and protocol layer (RFC 9497
OPRF/VOPRF) in the same module. From-scratch C99, no vendored code (same posture
as the §2.6 gf[16] Ed25519).

**Secret inputs.**
- The **scalar** in `determ_p256_base_mul` (`[k]G` — the keygen/DH scalar) and
  `determ_p256_point_mul` (`[k]P` — the ECDH core; the shared secret is the
  result's X coordinate); the OPRF **blind** and OPRF **server key `sk`**, both
  of which reach the same `pt_scalar_mul` ladder via
  `determ_p256_oprf_blind`/`_evaluate`/`voprf_prove`.
- The **mod-n scalar operands** of `determ_p256_scalar_mul_mod_n` /
  `determ_p256_scalar_inv_mod_n` (the OPRF blind-inverse and the `s = r − c·k`
  proof arithmetic in `determ_p256_voprf_prove` — `sk`, the blind, and the proof
  randomness `r`).
- The OPRF **input** `msg` behind `u` in
  `determ_p256_hash_to_curve`/`_hash_to_scalar` (a user secret in the OPRF
  setting, per the module header) — it flows through `expand_message_xmd` and the
  SSWU map.

Public throughout: the SEC1 point encodings, the DST, the curve parameters
(`p`/`n`/`b`/`Gx`/`Gy`), the OPRF context string / mode byte, and the DLEQ
proof `(c, s)` and commitments (broadcast values).

**CT mechanisms as implemented.**
- **Double-and-add-always ladder:** `pt_scalar_mul` runs a fixed 256 iterations;
  every bit executes **both** a complete doubling `pt_add(acc, acc, acc)` and a
  complete addition `pt_add(&tmp, acc, base)` unconditionally, and the secret bit
  flows only through `pt_cswap` → `fe_cswap`, whose select is the arithmetic mask
  `mask = 0 − swap` with XOR-swap — no secret-dependent branch, index, or table.
  The Renes–Costello–Batina complete addition formula (`pt_add`, RCB 2016 alg. 4,
  `a = −3`) is exception-free, so the **same** instruction sequence handles
  `P+Q`, `P+P`, and `P+O`; the ladder needs no special cases. `tmp` is wiped
  with `determ_secure_zero` after the loop.
- **Mask-select field arithmetic:** `fe_add`/`fe_sub` (mod p) perform the
  conditional subtract/add-back branchlessly via a `use_s`/`mask` select
  (`use_s = 0 − ((c | (1 − brw)) & 1)`; `mask = 0 − brw`) rather than an `if`;
  `fe_mont_mul`'s CIOS final reduction uses the same `use_s` blend; `fe_cswap`
  (the ladder swap) and `fe_cmov` (`r = mask ? a : r`) are the two masked-move
  primitives. The mod-n analogues `sc_add_raw`/`sc_sub_raw`/`sc_mont_mul` are the
  same shape over `Nl`.
- **Branchless SSWU:** `sswu_map` (RFC 9380 §6.6.2 simplified SSWU, `Z = −10`)
  selects the square branch with `fe_is_square_mask` (the Legendre symbol
  `a^((p−1)/2)` collapsed to an all-ones/all-zero mask) feeding `fe_cmov`
  (`x_out`/`t` select via `e2`; the `tv1′ == 0` fixup via `e1` from
  `fe_is_zero_mask`), and applies the `sgn0` sign fixup as a masked move
  (`sgn_mask = 0 − (fe_sgn0(y1) ^ fe_sgn0(u))` → `fe_cmov(y_out, y2, ...)`) — no
  branch on the secret-derived field values.
- **Fermat inversions iterate PUBLIC constant exponents:** `fe_inv` (`a^(p−2)`),
  `determ_p256_scalar_inv_mod_n` (`a^(n−2)`), `fe_sqrt` (`a^((p+1)/4)`), and the
  Legendre power in `fe_is_square_mask` (`a^((p−1)/2)`) all iterate the fixed
  bits of a **public** exponent (`e[]` derived once from `P_BE`/`N_BE`) via
  `fe_pow_pub`/the inline square-and-multiply — the `if ((e[i] >> bit) & 1)`
  branch keys on a public constant, never on the base. Annotated `/* public bit */`
  at each site.

**Comparisons.** The **VOPRF DLEQ challenge compare** in
`determ_p256_voprf_verify` — recomputed challenge `c2` vs the proof's `c` —
routes through **`determ_ct_memcmp`** (`return determ_ct_memcmp(c2, c, 32) == 0
? 0 : -1;`, §3.10). Both operands are public here (`c` is part of the transmitted
proof), so this is uniform discipline, not a leak fix — the same class as C3/C7.
The point-encoding compares elsewhere in the module — the `on_curve_m` /
`decode_point` OR-aggregate curve check and the `fe`-diff checks in
`point_decompress` — operate on **public** SEC1 encodings and public validity
outcomes. The scalar-range gate `be_lt` (`be_is_zero` is a branchless
OR-aggregate and is fine) is the one exception: it short-circuits on the first
differing byte and is invoked on **secret** scalars (`scalar_ok(blind)` /
`scalar_ok(sk)` in the OPRF layer; `scalar_ok(scalar_be)` in
`base_mul`/`point_mul`; `be_lt(a, N_BE)` in `scalar_mul_mod_n` /
`scalar_inv_mod_n`), so its running time is secret-dependent — see finding
**P256-CT-1** in §4.2.

**Residual non-CT (justified).**
- **The `determ_p256_oprf_derive_key` counter loop** (`for (counter = 0; counter
  <= 255; counter++)` with an early `break` once `be_is_zero(sk)` is false) is
  data-dependent, but the counter is a **rejection-sampling artifact on the
  PUBLIC `(seed, info)`** (RFC 9497 §3.2.1 DeriveKeyPair) — it is not a per-user
  secret; the near-certain single iteration and its termination depend on the
  hash of public inputs, not on any secret scalar. Same class as the §4.1.3
  public-validity rejections.
- **Public-validity branches on public operands:** the `in[0] != 0x04` prefix
  and `be_lt(..., P_BE)` coordinate gates in `decode_point` (the coordinate is a
  public point encoding); the point-at-infinity `znz == 0` reject in
  `encode_point`; the `0x02`/`0x03` prefix and parity branches in
  `point_compress`/`_decompress`. Each branch outcome is (or determines) the
  function's public return value, and each reads only public data. (The
  `scalar_ok` `>= n` gate's *outcome* is likewise public, but it reads a secret
  scalar via a short-circuiting `be_lt` — a real residual timing dependence
  broken out as finding **P256-CT-1**, §4.2, not a clean public-operand branch.)
- **The one-time `p256_init`/`sc_init`/`sswu_ready` flags** (`if (p256_ready)
  return;` etc.) — a public first-call guard, not secret-dependent.
- **The §4.1.5 64-bit multiply-latency assumption** applies here too:
  `fe_mont_mul`/`sc_mont_mul` multiply secret-valued limbs with the C `*`
  operator (constant-latency on x86-64/ARM64; operand-dependent on some small
  cores) — an architectural assumption to re-validate per target, not a source
  defect.

**Probe-target mapping (→ §3.12).** The tranche-3 `determ ct-timing-probe`
targets registered for this module (see `TimingProbeDesign.md` §4 and the
`src/main.cpp` target table) are **`p256-base-mul`** (secret = scalar; exercises
the RCB ladder), **`p256-h2c`** (secret = fixed-length msg; exercises the
branchless SSWU + `expand_message_xmd`), and **`p256-sc-mul`** (secret = both
mod-n operands; exercises `sc_mont_mul`). First measured runs read clean
(max |t| < 1.5 at smoke sample sizes); the §5 targets below fold them into the
inventory's measurement plan (target 13).

### 2.10 pedersen — P-256 confidential-tx MSM / commit / vector-commit (§3.19)

**Secrets handled:** the range/balance prover's scalars — the committed value `v`, the
blinding factors `r`/`gamma`, the bit-vectors and polynomial-blinding scalars — flow into
the multi-scalar multiplication `Σ s_i·P_i` and the Pedersen commit / vector-commit
(`src/crypto/pedersen/`). The **base points are always public generators** (`G`/`H`/`G_i`/
`H_i`/`u`); the **scalars are the secret**.

**Zero-scalar skip — REMOVED (constant-time, 2026-07-06, owner-authorized).** The
`determ_pedersen_msm` / `_vector_commit` / `_commit` routines had `if (scalar==0) continue`
guards that leaked which secret scalars are zero (in the range prover, the bits of the
committed value). They are gone: the MSM routes through a pt-domain `determ_p256_msm_ct`
(accumulates in the projective representation where the identity `O` needs no special-casing
— `pt_scalar_mul(0,P)=O`, the RCB-complete `pt_add` absorbs `O` — so no `acc_is_identity`
flag and no skip); commit and vector_commit use branchless scalar-substitution
(`ct_scalar_nz`) + point-selects (`ct_point_select`), valid because their accumulator starts
at the non-identity `r*H`. **Byte-output-invariant** (all 35 P-256 corpus vectors byte-equal)
+ independently audited (6/6 CT properties SOUND). The only residual branches are
point-validity / `ge(s,n)` rejects, which never fire for a prover's own honestly-generated
scalars/points (the standard public-validity-rejection residual, §4.1). With this the P-256
confidential-tx prover is constant-time for its own honest inputs — no CT residual remains
before the owner-gated chain integration (`ConfidentialTxIntegrationDesign.md` NC-4/L-4).

**Probe-target mapping (→ §3.12).** The `p256-msm-zeroskip` `ct-timing-probe` target
(`src/main.cpp`) empirically backs the zero-skip removal: its two classes — `both-nonzero`
and `one-zero` — differ ONLY in whether the 2nd secret scalar is zero (the exact contrast
the removed skip leaked, since it ran one fewer scalar-mult for a zero term), timing
`determ_pedersen_msm` over 2 fixed points. A first measured run read **max |t| ≈ 1.39** at
8000 samples (all crop percentiles ≤ 1.4, well under the TVLA |t| > 4.5 threshold) — no
evidence of a zero-dependent timing difference, i.e. the CT MSM times identically whether
or not a scalar is zero. (Per TimingProbeDesign §5.4 this is *evidence*, not a proof;
timing is environment-dependent and the target is out of `run_all.sh` by design.)
---

## 3. Comparison census

Every comparison in the stack that touches secret-adjacent data, in one table:

| # | Site | Operands | Mechanism |
|---|---|---|---|
| C1 | `determ_chacha20_poly1305_decrypt` tag verify | recomputed tag (secret-derived) vs presented tag | `determ_ct_memcmp`, 16 bytes (§3.10 consolidation of local `ct_eq16`) |
| C2 | `determ_aes256_gcm_decrypt` tag verify | recomputed tag (secret-derived) vs presented tag | `determ_ct_memcmp`, 16 bytes (ditto) |
| C3 | `determ_ed25519_verify` final R check | recomputed point encoding vs sig R (both public on honest path) | `determ_ct_memcmp`, 32 bytes (formerly `ct_verify_32`) |
| C4 | `sc_lt_L` (verify gate; `determ_ed25519_sc_is_canonical`) | scalar S vs constant L | branchless byte-wise borrow chain |
| C5 | `pack25519` / Poly1305 final reduction | field element vs modulus | masked conditional subtract (`sel25519` / `(g4 >> 31) - 1` mask) |
| C6 | `neq25519`, `point_y_is_canonical` (ed25519 internal) | public point encodings | OR-aggregate over full width, single branch on aggregate |
| C7 | `determ_frost_dkg_verify_pop` / `_verify_share` | publicly recomputable group elements | `determ_ct_memcmp`, 32 bytes — uniform discipline, not a leak fix |
| C8 | `determ_frost_pss_commit` zero-hole check | δ_0 vs zero (protocol-mandated public constant) | branchless OR-aggregate (hardened per audit §8b) |
| C9 | `determ_x25519` contributory check | DH output vs all-zero | OR-aggregate; branch result = the public return value |
| C10 | `determ_frost_pss_verify_commit` identity check | public commitment C_0 vs `[0]B` | `determ_ct_memcmp`, 32 bytes (as-found per-byte early-return loop remediated in-session — see CTI-1 below) |
| C11 | `determ_p256_voprf_verify` DLEQ challenge check | recomputed challenge c2 vs proof c (both public — c is transmitted) | `determ_ct_memcmp`, 32 bytes — uniform discipline, not a leak fix |
| C12 | `on_curve_m` / `decode_point` curve-membership check (p256) | public point encoding vs `y² = x³ − 3x + b` | OR-aggregate over 8 limbs, single branch on aggregate (public operand) |
| C13 | `fe_add`/`fe_sub`/`fe_mont_mul` mod-p reduction, `sc_*` mod-n reduction (p256) | field/scalar element vs modulus p/n | masked conditional subtract/add-back (`use_s`/`mask` select, no branch) |
| C14 | `be_lt(scalar, N_BE)` via `scalar_ok` (p256) | **secret** scalar (blind/sk/ECDH scalar) vs order n | branchless LSB-first borrow chain (no early return) — **finding P256-CT-1** (§4.2), ✅ REMEDIATED in-session |

---

## 4. Residuals and findings

### 4.1 Justified residual non-CT inventory (no action required)

1. **Public-length control flow, stack-wide** — every loop bound / branch on
   `msglen`/`aadlen`/`keylen`/`outlen`/`saltlen`/`iters`/`t`/`n`/`buflen`.
   Justified by the §1.2 public-length contract (`ct.h`). Includes the
   password-length leak in PBKDF2/Argon2id (standard KDF posture).
2. **Argon2id data-dependent memory addressing** in all segments outside pass-0's
   first half (`fill_block` reference selection from `pr = B[prev].v[0]` via
   `index_alpha`). By design per RFC 9106 §3.4 (GPU resistance); the Argon2id
   hybrid keeps the leak-sensitive early accesses data-independent. Documented
   in CRYPTO-C99-SPEC §3.6 and the module header.
3. **Public-validity rejection branches** — Ed25519/X25519 point-decode failures,
   canonicality gates (`point_y_is_canonical`, `sc_lt_L` outcome), FROST
   signer-set / parameter guards, AEAD auth-failure early return. The branch
   outcome is (or determines) the function's public return value; nothing
   secret is keyed.
4. **Fixed public exponent schedules** — `inv25519`/`pow2523` (p−2, (p−5)/8) and
   `determ_ed25519_sc_invert` (L−2) branch on constant exponent bits, never on
   the base.
5. **64-bit multiply latency assumption** — `M`/`fmul` (gf[16] field),
   `poly1305_absorb`, `fBlaMka`, and `determ_ed25519_sc_muladd` multiply
   secret-valued limbs with the C `*` operator. On the mainstream targets
   (x86-64, ARM64) integer multiply is constant-latency; on some smaller cores
   (e.g. ARM Cortex-M0/M3 `MULS`, older PowerPC) it is operand-dependent. This is
   an *architectural assumption*, not a source defect — recorded here so §3.12
   re-validates it per target before any NH1 embedded deployment (§5, target 11).

### 4.2 Findings (Info — discipline/hygiene, no timing leak)

**CTI-1 — `determ_frost_pss_verify_commit` was the one compare not routed
through `determ_ct_memcmp`.** ✅ **REMEDIATED in-session** (same session this
inventory was written): the per-byte early-return loop was replaced with
`return determ_ct_memcmp(commitment0, id, 32);`.
- **Severity:** Info — **Category:** CT discipline (no leak)
- **Location:** `src/crypto/frost/frost.c`, `determ_frost_pss_verify_commit`
  (as found: `for (k = 0; k < 32; k++) if (commitment0[k] != id[k]) return -1;`)

The identity-point check compares a peer's broadcast Feldman commitment C_0
against `[0]B`; as found it used a per-byte early-return loop. Both operands
are public (a broadcast commitment and a fixed public constant), so this
leaked nothing — the same justification class as C6/C9. But it was the
**only** equality compare in the stack outside the `determ_ct_memcmp`
discipline, and the sibling zero-hole check in `determ_frost_pss_commit` was
already hardened to the aggregate form for exactly this uniformity reason
(audit §8b PSS-CT-001: "matching the §4 house compare discipline, so the form
is no longer flaggable"). Routing C10 through `determ_ct_memcmp` completed the
§3.10 consolidation and removed the last per-site public-operand argument.
Discipline, not a fix.

**CTI-2 — AES-GCM decrypt did not wipe the recomputed tag (`expect[16]`).**
✅ **REMEDIATED in-session**: both exit paths of `determ_aes256_gcm_decrypt`
now scrub `expect` via `determ_secure_zero`, matching the ChaCha sibling.
- **Severity:** Info — **Category:** zeroization hygiene (NOT a timing issue;
  recorded here because §3.10 owns both halves of this discipline)
- **Location:** `src/crypto/aes/aes_gcm.c`, `determ_aes256_gcm_decrypt` — as
  found, the auth-failure and success returns scrubbed `ctx` and `H` but not
  `expect`.

`expect` holds the *valid* tag for the presented (key, IV, AAD, ciphertext);
recovering it from a reclaimed stack frame would let an attacker present a
forged-accepted message for that exact tuple. The ChaCha20-Poly1305 sibling
(`determ_chacha20_poly1305_decrypt`) scrubs its `expect[16]` on every path —
this was a one-line consistency gap against the audit §5.1 convention, same
exploitation-requires-secondary-disclosure caveat as the other Low/Info
zeroization items there.

**P256-CT-1 — `scalar_ok`'s `be_lt(secret, N_BE)` range check was variable-time
on secret scalars.** ✅ **REMEDIATED in-session** (the same session this
inventory was written): `be_lt` was rewritten as a branchless LSB-first
byte-wise borrow chain (no early return; a < b iff the full subtraction
borrows out) — the exact precedent the fix note below recommends. All 30
P-256 vectors stay byte-exact after the change (the compare is
behavior-preserving, only its timing changed), so the header claims
`p256.h` "constant-time in the scalar" and `README` are now accurate.
- **Severity:** Low — **Category:** constant-time (secret-dependent branch
  timing; small exploitable signal for uniformly-random secrets, larger for
  structured/small secrets)
- **Location:** `src/crypto/p256/p256.c`, `be_lt` (lines 281–288, the
  `if (a[i] < b[i]) return 1; if (a[i] > b[i]) return 0;` early-return loop) as
  reached through `scalar_ok` (line 295–297) from the secret-scalar entry points
  `determ_p256_base_mul`/`_point_mul` (lines 343, 358), `determ_p256_oprf_blind`
  /`_evaluate` (lines 919, 934), `determ_p256_voprf_prove` (line 1037), and
  directly as `be_lt(a, N_BE)` in `determ_p256_scalar_mul_mod_n`/`_inv_mod_n`
  (lines 466, 481).

`be_lt` short-circuits at the first byte where the secret scalar differs from
`n`, so its running time reveals how many leading bytes of the secret equal the
corresponding bytes of `n` (`N_BE = ff ff ff ff 00 00 00 00 ff …`). For a
uniformly-random scalar `< n` the top byte is `< 0xff` with probability 255/256,
so the loop almost always exits at iteration 0 and the practical signal is small
— but it is not zero, and it grows for structured secrets (a small blind, or an
`sk` chosen near `n`). This is the ONE short-circuiting compare on a secret
operand in the module; the sibling curve modules avoid the analogue by handling
secret scalars constant-time (X25519 clamps rather than range-checks; Ed25519's
`sc_lt_L` is the branchless byte-wise borrow chain of C4 and runs on the
*public* signature scalar, not the secret). The fix taken mirrors that
precedent: `be_lt` is now a constant-time byte-wise borrow-chain comparator
(equivalent to `sc_lt_L`/`fe_sub`'s masked form). NOTE the registered
`p256-base-mul` probe generator masks `scalar[0] &= 0x0f` (src/main.cpp
~L12719), forcing an iteration-0 exit, so the tranche-3 probe would NOT have
surfaced this. FOLLOW-UP DONE (same session): the p256-base-mul/p256-sc-mul
generators now use full-range [1, n) rejection-sampled secrets with an
n-prefix FIX class (first 16 BE bytes of n), and smoke runs on the branchless
be_lt show max |t| = 2.6-2.7 at small samples — no leakage evidence.

The remaining equality/aggregate compares are clean: no secret-indexed memory
access, and no *other* short-circuiting secret compare exists in any of the nine
modules as read (`be_is_zero` is a branchless OR-aggregate; the DLEQ compare
routes through `determ_ct_memcmp`; the curve-membership and reduction selects are
the branchless C12/C13 forms).

---

## 5. What §3.12 must measure

The dudect/ctgrind harness (CRYPTO-C99-SPEC §3.12) should target this inventory
as follows. Throughout: dudect's fix-vs-random input-class methodology on the
SECRET parameter while pinning all public parameters (lengths above all) —
because lengths are public by contract, classes must never differ in length.
ctgrind (taint = the secret buffer) checks branches/indices; dudect checks wall
time. Measure the shipped optimizer output (`-O2 -fno-strict-aliasing` per spec
Q6) — CT is an object-code property, so re-run per compiler/flag bump.

1. **`determ_ct_memcmp`** — the keystone: fixed length (16/32/64), classes
   {equal, differ-at-byte-0, differ-at-last-byte, differ-everywhere}; timing
   must be indistinguishable across ALL four (position AND count invariance).
   This converts `test_ct_c99.sh`'s functional pins into the timing claim.
2. **AES core** — `determ_aes256_encrypt_block` with fix-vs-random keys (fixed
   plaintext) and fix-vs-random plaintext (fixed key); `determ_aes256_init`
   fix-vs-random key. ctgrind: no taint reaches a branch/index — this is the
   no-table S-box claim (`aes_sbox_ct`/`gf_mul`/`gf_inv`) under measurement.
3. **GHASH** — `ghash_mul` with fix-vs-random `H` and fix-vs-random `X`
   (bit-pattern classes: all-zeros vs all-ones vs random, since the bit-serial
   loop's masks are per-bit).
4. **AEAD decrypt rejection timing** — `determ_aes256_gcm_decrypt` AND
   `determ_chacha20_poly1305_decrypt` with classes {valid tag, tag wrong in
   byte 0, tag wrong in byte 15, tag fully wrong} at fixed lengths: rejection
   time must be independent of the matching-prefix length (C1/C2 measured
   end-to-end through the AEAD, not just the bare compare).
5. **ChaCha20/Poly1305 cores** — `chacha20_block` (via `determ_chacha20`,
   fixed-length message) fix-vs-random key; `determ_poly1305` fix-vs-random
   (r,s) key at fixed message length, plus message classes that force the final
   conditional-subtraction mask both ways (h < p vs h ≥ p) to confirm the C5
   masked select is time-invariant.
6. **Ed25519 secret path** — `determ_ed25519_pubkey_from_seed` and
   `determ_ed25519_sign` (fixed message) with fix-vs-random seeds: covers the
   cswap ladder (`scalarmult`/`sel25519`), `car25519`, `modL`, and the S
   accumulation in one measurement. Scalar bit-pattern classes (low-Hamming vs
   high-Hamming weight) specifically attack the ladder claim.
7. **`sc_lt_L` / `determ_ed25519_sc_is_canonical`** — classes {s = 0, s = L−1,
   s = L, s = 2L−1, random}: the borrow chain must not vary with where the
   first differing byte sits.
8. **X25519** — `determ_x25519` fix-vs-random scalar at a fixed public point
   (and at the base point via `determ_x25519_base`); same Hamming-weight classes
   as target 6. The low-order rejection branch fires only on attacker-chosen
   public points, so exclude low-order points from the secret-class runs.
9. **FROST secret-bearing entry points** — `determ_frost_sign_partial`
   (fix-vs-random share/d/e at fixed public xs/D/E/msg),
   `determ_frost_dkg_share`/`frost_poly_eval` and `determ_frost_dkg_commit`
   (fix-vs-random polynomial), `determ_frost_reconstruct` (fix-vs-random
   shares at fixed xs). Verifies the "all secrets ride the §2.6 layer" claim
   end-to-end; `determ_ed25519_sc_muladd` is the shared microbench target.
10. **Argon2id scoped check** — NOT whole-function dudect (data-dependent by
    design, §4.1.2). Instead: ctgrind/memory-trace assertion that for
    `pass == 0 && slice < 2` the sequence of `ref_index` values is identical
    across two different passwords with identical (salt, costs) — the RFC 9106
    §3.4 hybrid claim, measured rather than argued.
11. **Per-target re-validation** — re-run targets 2–9 on each non-x86-64
    deployment architecture (ARM64 now; any 32-bit/embedded NH1 target later)
    to discharge the §4.1.5 multiply-latency assumption; document per-target
    results alongside the build recipes.
12. **Keyed-hash length-only dependence** — HMAC-SHA-256/512 fix-vs-random key
    at fixed keylen/msglen, BLAKE2b keyed-mode fix-vs-random key, PBKDF2
    fix-vs-random password at fixed pwlen: confirms §2.1/§2.2's "branches key
    on lengths only" for the keyed consumers (the unkeyed hashes need no run —
    no secret input exists).
13. **P-256 secret path** (tranche-3 probe targets, §2.9) —
    `determ_p256_base_mul` fix-vs-random scalar (covers the RCB
    double-and-add-always ladder `pt_scalar_mul`/`fe_cswap` and the mask-select
    field core `fe_add`/`fe_sub`/`fe_mont_mul`; scalar bit-pattern classes
    low- vs high-Hamming-weight specifically attack the ladder claim, as in
    target 6), `determ_p256_scalar_mul_mod_n` fix-vs-random operands (the mod-n
    `sc_mont_mul` reduction, C13), and `determ_p256_hash_to_curve` fix-vs-random
    fixed-length msg (the branchless SSWU `fe_is_square_mask`/`fe_cmov`/`fe_sqrt`
    + `expand_message_xmd`). Registered as `p256-base-mul` / `p256-sc-mul` /
    `p256-h2c` in `determ ct-timing-probe`. The C11 DLEQ compare is measured
    inside target 1 (`determ_ct_memcmp`); the `derive_key` counter loop (§2.9
    residual) is public-`(seed,info)`-driven and is NOT a secret-class run.

Each target maps back to a named mechanism in §2; a §3.12 failure therefore
localizes immediately to the function whose claim broke. Conversely, when all
thirteen pass, every row of the §1.4 table is measured rather than reviewed —
which is the §3.12 exit criterion.

---

## 6. Cross-references

- `CRYPTO-C99-SPEC.md` — §3.10 (the shared CT primitives this inventory's
  comparisons route through), §3.12 (the verification framework §5 seeds),
  §2.Q6 (constant-time discipline decision), §3.5/§3.6 notes (AES CT posture,
  Argon2id by-design non-CT).
- `C99CryptoStackAudit.md` — §4 (per-file CT verdicts for sha2/chacha20/aes),
  §6 (Ed25519 CT posture incl. the cswap-ladder confirmation), §7/§8/§8b
  (FROST sign/DKG/PSS CT dimensions; PSS-CT-001), §8c (X25519), §5.1
  (`determ_secure_zero` rollout the CTI-2 note measures against).
- `include/determ/crypto/ct.h` — the usage contract (equality-only, public
  lengths, uniform discipline on public-but-crypto-adjacent compares).
- `tools/test_ct_c99.sh` + the `test-ct-c99` dispatch block in `src/main.cpp` —
  the functional pins for `determ_ct_memcmp`/`determ_secure_zero`; explicitly
  defers the timing property to §3.12 (this document's §5).
- Per-primitive validation wrappers: `tools/test_{sha2,chacha20,aes,ed25519,
  x25519,blake2b,xchacha,argon2id,frost,p256,p256_h2c,p256_oprf}_c99.sh`
  (byte-equal correctness — the orthogonal dimension §1.1 of the audit).
- `src/crypto/p256/README.md` — the §2.9 module's construction overview, the
  6-assertion `determ test-p256-c99` gate, and the §3.13 vector-file coverage
  (`tools/vectors/p256{,_h2c,_oprf}.json`); `TimingProbeDesign.md` §4 — the
  tranche-3 probe-target registrations (`p256-base-mul`/`-h2c`/`-sc-mul`).

*End of inventory.*
