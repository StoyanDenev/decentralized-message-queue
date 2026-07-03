# src/crypto/aes — AES-256-GCM (C99, libsodium-free)

Per-module provenance + audit README required by CRYPTO-C99-SPEC.md §3.16.
Authoritative references: `docs/proofs/CRYPTO-C99-SPEC.md` §3.5 (status + decisions),
`docs/proofs/C99CryptoStackAudit.md` (audit findings §3.17/§3.18, CT posture §4).

## 1. What this module implements

AES-256-GCM, the AEAD today's S-004 wallet keyfile envelope uses (currently via
OpenSSL — see §5) and, per the spec §2 Q10 feature-availability matrix, the
FIPS-profile AEAD for v2.17 keyfiles, v2.22 amount encryption, and
direct-to-DApp payloads (MODERN profiles use XChaCha20-Poly1305 there). Two files:

- `aes_core.c` — the AES-256 block cipher (FIPS 197), **encrypt direction only**
  (all GCM needs; there is no InvCipher / block-decrypt path). Key schedule
  (15 round keys × 16 bytes in `determ_aes256_ctx`), constant-time arithmetic
  S-box, plus an exhaustive S-box selftest hook.
- `aes_gcm.c` — the GCM mode (NIST SP 800-38D) composed on that block cipher:
  bit-serial GHASH over GF(2^128), GCTR keystream, tag computation/verification.

Public entry points (`include/determ/crypto/aes/aes.h`):

| Function | Role |
|---|---|
| `determ_aes256_init` | expand a 32-byte key into `determ_aes256_ctx` (240-byte schedule) |
| `determ_aes256_encrypt_block` | one 16-byte block, encrypt direction |
| `determ_aes256_sbox_selftest` | returns 1 iff the CT arithmetic S-box equals the canonical FIPS-197 table over all 256 inputs |
| `determ_aes256_gcm_encrypt` | AEAD seal: 96-bit IV, AAD, plaintext → ciphertext + 16-byte tag (thin wrapper over `_encrypt_iv` with ivlen=12) |
| `determ_aes256_gcm_decrypt` | AEAD open: verifies the tag (constant-time) before writing any plaintext; 0 on success, −1 on auth failure (wrapper over `_decrypt_iv`) |
| `determ_aes256_gcm_encrypt_iv` / `_decrypt_iv` | arbitrary-IV-length variants (SP 800-38D §7.1); −1 on ivlen == 0 |

GCM construction as implemented in `aes_gcm.c`:

- `H = E_K(0^128)` (GHASH subkey). `J0`: ivlen == 12 takes the fast path
  `IV ‖ 0^31 ‖ 1`; any other ivlen ≥ 1 derives
  `J0 = GHASH_H(IV ‖ 0-pad ‖ [0]_64 ‖ [ivlen·8]_64)` (`gcm_j0`) — validated
  against OpenSSL EVP per IV length {1,8,16,20,32,60} by `determ test-aes-c99`
  §5 and against the python `cryptography` oracle by
  `tools/vectors/aes_gcm_decrypt.json` (via `test-c99-vectors`).
- GCTR keystream starts at `inc32(J0)`; `inc32` increments the last 32 bits big-endian.
- `tag = GHASH(H, AAD ‖ pad, CT ‖ pad, len64(AAD)‖len64(CT)) ⊕ E_K(J0)`
  (`gcm_tag`), MSB-first bit order, `R = 0xe1‖0^120` reduction (`ghash_mul`).
- Decrypt recomputes the expected tag over the ciphertext first and compares
  constant-time; on mismatch it scrubs and returns −1 without producing plaintext
  (verify-before-decrypt — nothing is written on auth failure).

## 2. Provenance + construction

- **Source:** implemented directly from the published specifications — NIST FIPS 197
  (block cipher + AES-256 key schedule; the Figure 7 S-box table as validation
  oracle; the Appendix C.3 KAT as anchor) + NIST SP 800-38D (GCM/GHASH/GCTR). Not vendored from a third-party codebase; the
  spec §3.5 option to vendor BearSSL's AES-GCM was not taken. No upstream version
  to pin — the provenance anchor is the in-repo commits recorded in spec §3.5
  (`facf915` + `a053964` + the S-box CT-hardening).
- **License posture:** Public domain (spec §2 Q3 module table, row AES-256-GCM).
- **Design choice:** the S-box is computed arithmetically per call — GF(2^8)
  multiplicative inverse as a fixed x^254 square-and-multiply addition chain
  (`gf_inv`) over a branchless 8-iteration field multiply (`gf_mul`), then the
  FIPS-197 affine map (`aes_sbox_ct`). The canonical `SBOX[256]` table is retained
  **only** as the reference oracle for `determ_aes256_sbox_selftest`; the cipher
  never indexes it (that would reintroduce the cache-timing leak this construction
  exists to eliminate).

## 3. Validation evidence

Subcommand: **`determ test-aes-c99`** (dispatch block `cmd == "test-aes-c99"` in
`src/main.cpp`). Wrapper: **`tools/test_aes_c99.sh`**, which runs the subcommand
and gates on the summary line `PASS: aes-c99 all cross-validation + KATs matched`.
Nine assertions, cross-validating against OpenSSL EVP plus published NIST vectors:

1. **CT S-box exhaustive proof** — `determ_aes256_sbox_selftest`: the arithmetic
   S-box is byte-identical to the canonical FIPS-197 table over all 256 inputs.
2. **FIPS-197 Appendix C.3 KAT** — AES-256 block on the standard key/plaintext
   yields `8ea2b7ca516745bfeafc49904b496089`.
3. **Block vs OpenSSL** — byte-equal vs `EVP_aes_256_ecb` over 256 fuzzed
   (key, block) pairs.
4. **AEAD vs OpenSSL (the spec §Q9 gate)** — full AES-256-GCM, ciphertext AND tag,
   byte-equal vs `EVP_aes_256_gcm` over a (plaintext, AAD)-length grid:
   pt ∈ {0,1,16,63,64,65,128,200} × aad ∈ {0,1,12,16,20}.
5. **Decrypt round-trip** — seal/open recovers the plaintext.
6. **Tampered tag rejected** (returns −1).
7. **Tampered ciphertext rejected.**
8. **Tampered AAD value rejected** — the AAD-binding negative path
   `S004KeyfileAtRest.md` T-2 relies on (landed in `c9e5cf2`, audit §5.3).
9. **AAD-length mismatch rejected.**

The audit (`C99CryptoStackAudit.md`) layered an adversarial source review on top of
this cross-validation: `aes_core.c` 1 confirmed finding (§3.17, Low), `aes_gcm.c`
1 confirmed finding (§3.18, Low) — both zeroization-hygiene, both remediated in
`2e0058b` via `determ_secure_zero`. The §3.18 fix landed in full (`ctx`/`H`/
`ej0`/`ks`/`X`); the §3.17 fix as landed scrubs the cipher state `s[16]` — the
audit's additionally-proposed scrub of the `t0..t3`/`a` key-schedule byte
temporaries in `determ_aes256_init` was not taken (per the commit's scope note,
the dominant secret is the schedule itself, which lives in caller-owned
`ctx->rk`). Zero Critical/High, zero confirmed constant-time findings (audit §4).

## 4. Constant-time / hygiene posture

Constant-time end to end at the source level (audit §4 verdict: clean):

- **S-box:** arithmetic, no key-dependent table lookup or branch — `gf_mul` uses
  mask-selected partial-product XOR and mask-selected reduction over a fixed 8
  iterations; `gf_inv` is a fixed addition chain; `xtime` is a branchless
  mask-multiply. The classic AES cache-timing channel is eliminated.
- **GHASH:** `ghash_mul` is branchless bit-serial — a fixed 128 iterations with a
  `0x00/0xff` mask for the conditional XOR and a mask-based `0xe1` reduction; no
  secret-dependent branch or index.
- **Control flow:** all block/round loops have fixed bounds; `gcm_crypt`'s loop
  bound and final-block `take` depend only on the public length.
- **Tag compare:** the 16-byte tag verification in `determ_aes256_gcm_decrypt`
  routes through the shared constant-time equality primitive `determ_ct_memcmp`
  (`include/determ/crypto/ct.h`, CRYPTO-C99-SPEC §3.10) — aggregate-difference,
  no short-circuit, leaks neither byte position nor per-byte timing.
- **Zeroization** (`determ_secure_zero`, the memory-hygiene half of §3.10, from
  `include/determ/crypto/secure_zero.h`): `determ_aes256_encrypt_block` scrubs the
  key-mixed round state `s[16]`; `gcm_tag` scrubs the tag mask `ej0 = E_K(J0)` and
  the GHASH accumulator `X`; `gcm_crypt` scrubs the last keystream block `ks`;
  both AEAD entry points scrub the expanded round-key schedule (`ctx`, 240 bytes —
  invertible back to the master key) and the GHASH subkey `H` on every return,
  including the decrypt auth-failure early return. Callers using the raw block
  API own — and must scrub — their `determ_aes256_ctx`.

## 5. Known limitations / future work

- **Throughput:** the arithmetic S-box trades speed for the CT guarantee. A
  bitsliced / Boyar-Peralta / AES-NI S-box would be faster but is an optional
  throughput optimization, not a security gate — the S-004 keyfile-envelope use
  is one-shot (spec §3.5).
- **Not yet wired into the S-004 call site:** this is an additive validated
  module; the current wallet keyfile envelope still uses OpenSSL AES-GCM
  (`tools/test_aes_c99.sh` header; audit §5.3 AAD-binding note).
- **KAT breadth:** NIST CAVP GCM vectors (`gcmEncryptExtIV256`) to broaden
  known-answer coverage beyond the OpenSSL oracle remain future work
  (audit §5.3; spec §3.5 originally planned CAVP vectors).
- **96-bit IV only:** the arbitrary-IV-length GHASH-derived `J0` path of
  SP 800-38D is not implemented; encrypt direction only (no block decrypt) —
  both deliberate scope limits, sufficient for the AEAD.
