# `src/crypto/chacha20/` — ChaCha20-Poly1305 + XChaCha20-Poly1305

Per-module provenance + audit README (CRYPTO-C99-SPEC.md §3.16). Part of the
libsodium-free C99 crypto stack (CRYPTO-C99-SPEC.md §3.4 — **SHIPPED**).

## 1. What this module implements

| File | Contents |
|---|---|
| `chacha20.c` | ChaCha20 stream cipher (RFC 8439 §2.3–2.4): 256-bit key, 32-bit block counter, 96-bit nonce |
| `poly1305.c` | Poly1305 one-time authenticator (RFC 8439 §2.5): key = r(16) ‖ s(16), 16-byte tag |
| `chacha20_poly1305.c` | ChaCha20-Poly1305 IETF AEAD (RFC 8439 §2.8): composes the two files above |
| `xchacha20_poly1305.c` | HChaCha20 + XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha): 192-bit-nonce AEAD |

Public entry points (headers in `include/determ/crypto/chacha20/`):

- `chacha20.h` — `determ_chacha20` (self-inverse; `out` may alias `in`),
  `determ_poly1305`, `determ_chacha20_poly1305_encrypt` /
  `determ_chacha20_poly1305_decrypt` (both return `0` / `-1`; the `int` return
  on encrypt is backward source-compatible with prior `void` call sites).
- `xchacha20_poly1305.h` — `determ_hchacha20` (draft §2.2 subkey derivation,
  no feed-forward), `determ_xchacha20_poly1305_encrypt` /
  `determ_xchacha20_poly1305_decrypt` (24-byte nonce).

## 2. Provenance + construction

Per the CRYPTO-C99-SPEC §2 Q3 vendoring table: **RFC 8439 reference**
construction, **public domain**, implemented from the RFC text — not a vendored
copy of an upstream library.

- **ChaCha20 / HChaCha20:** the RFC 8439 quarter-round ARX permutation,
  20 rounds as 10 column+diagonal pairs, `"expand 32-byte k"` constants.
  HChaCha20 is the same permutation without the feed-forward addition,
  emitting words 0–3 and 12–15 (draft-irtf-cfrg-xchacha §2.2).
- **Poly1305:** the canonical 5 × 26-bit-limb arithmetic (the
  "poly1305-donna-32" structure — 2¹³⁰−5 lands on a clean 5·26 = 130-bit
  boundary), with the constant-time final conditional subtraction of `p`.
- **AEAD combiner:** RFC 8439 §2.8 — one-time Poly1305 key = first 32
  keystream bytes at counter 0 (`poly1305_keygen`, §2.6); ciphertext starts at
  counter 1; tag over `aad ‖ pad16 ‖ ct ‖ pad16 ‖ len(aad)_le64 ‖ len(ct)_le64`
  (`aead_tag`).
- **XChaCha20-Poly1305 (commit `09849f6`):** defined as
  `ChaCha20-Poly1305-IETF(HChaCha20(key, N24[0:16]), 0x00000000 ‖ N24[16:24], aad, pt)`
  — built directly on the already-validated inner AEAD; the wrapper only
  derives `(subkey, nonce12)`.

## 3. Validation evidence

- **`determ test-chacha20-c99`** (dispatch block in `src/main.cpp`; wrapper
  `tools/test_chacha20_c99.sh`):
  1. ChaCha20 byte-equal vs **OpenSSL `EVP_chacha20`** over a (counter, length)
     grid — lengths {0,1,16,63,64,65,127,128,191,256,300} × counters
     {0,1,7,123456}; OpenSSL's 16-byte IV = [32-bit counter LE][96-bit nonce]
     matches RFC 8439, so the comparison is direct (the §Q9 byte-equal gate,
     no transcribed vector).
  2. Self-inverse round-trip.  3. Block-counter sensitivity.
  4. Poly1305 vs the **RFC 8439 §2.5.2 KAT** (independent published anchor).
  5. Full AEAD (ciphertext AND tag) byte-equal vs **OpenSSL
     `EVP_chacha20_poly1305`** over a (plaintext, aad)-length grid.
  6. Decrypt round-trip + tamper rejection: tag, ciphertext, value-flipped AAD,
     and AAD-length mismatch (the AAD-binding negative paths, audit §5.3).
- **`determ test-xchacha-c99`** (dispatch block in `src/main.cpp`; wrapper
  `tools/test_xchacha_c99.sh`):
  1. HChaCha20 vs the **draft-irtf-cfrg-xchacha §2.2.1 KAT** — the expected
     value was produced by an independent from-scratch reference, not
     transcribed (audit §8e).
  2. Full AEAD byte-equal vs **OpenSSL's inner `EVP_chacha20_poly1305`** on the
     derived (subkey, 96-bit nonce) over the (pt, aad) grid — sound because
     XChaCha20-Poly1305 is *defined* as that composition and (1) pins HChaCha20.
  3. Decrypt round-trip + tamper rejection: tag / ciphertext / AAD / nonce.
- **Adversarial audit** (`docs/proofs/C99CryptoStackAudit.md`): findings
  §3.11–§3.16 (2 ChaCha20, 1 Poly1305, 3 AEAD — 1 Medium, 4 Low, 1 Info; no
  reachable correctness defect — the lone correctness-category item is §3.12's
  RFC-conformant counter wrap). All remediated in commit `2e0058b` except
  §3.12, accepted by design (see §5 below). XChaCha20-Poly1305 went through the same
  four-dimension workflow separately: **0 confirmed findings** (audit §8e).

## 4. Constant-time / hygiene posture

Constant-time by construction (audit §4 — `chacha20.c` / `poly1305.c` /
`chacha20_poly1305.c` all "Clean"; the XChaCha wrapper was audited CT-clean
separately in §8e):

- **ChaCha20 / HChaCha20:** pure ARX — no S-boxes, no table lookups, no
  secret-dependent branch/index/loop bound. Rotation amounts are compile-time
  constants in {16,12,8,7} (no shift UB); loop bounds depend only on the public
  length.
- **Poly1305:** branchless; the only data-dependent control flow is on the
  public message length. The final reduction selects `h` vs `h−p` with an
  unsigned-shift mask (`(g4 >> 31) - 1`), not a branch.
- **Tag verification:** the AEAD decrypt's 16-byte tag compare routes through
  the shared `determ_ct_memcmp` (`include/determ/crypto/ct.h`,
  CRYPTO-C99-SPEC §3.10) — no short-circuit, aggregate-difference, leaks
  neither byte position nor per-byte timing. Decrypt verifies the tag **before**
  writing any plaintext; nothing is written on authentication failure.

Memory hygiene — `determ_secure_zero` (`include/determ/crypto/secure_zero.h`,
the other §3.10 primitive) scrubs every secret-bearing local before return:

- `chacha20.c`: state `st[]` (holds the key words) + last keystream `block[]`
  in `determ_chacha20`; working state `x[]` in `chacha20_block`.
- `poly1305.c`: the `r`/`s` key limbs, the `pad` words, the accumulator, and
  the partial-block scratch `buf` (holds up to 15 message bytes).
- `chacha20_poly1305.c`: the one-time Poly1305 key `otk` on every exit path of
  both encrypt and decrypt, plus the recomputed `expect` tag. The heap MAC
  buffer in `aead_tag` holds only public aad/ct + lengths — freed unscrubbed
  by design.
- `xchacha20_poly1305.c`: the HChaCha20 working state and the derived subkey
  in both encrypt and decrypt.

Robustness guards in `aead_tag` (audit §3.14 Medium + §3.15, both closed):
explicit `size_t`-overflow checks on the MAC-buffer length (blocks the 32-bit
`malloc`-small/`memcpy`-large heap overflow) and a `malloc` NULL check, both
surfaced through the `-1` error channel.

## 5. Known limitations / future work

- **32-bit block counter wraps mod 2³² past 256 GiB per (key, nonce)** —
  audit §3.12 (Info), accepted by design as RFC 8439-conformant: the RFC leaves
  counter overflow undefined and implementations legitimately diverge there
  (OpenSSL carries into the nonce; this code wraps the 32-bit word). The AEAD
  always starts at counter 0/1 and never reaches it; the test grid is
  deliberately bounded below 2³². A *documented-divergence* test at the
  boundary is listed as open in audit §5.3.
- **One-shot MAC buffer:** `aead_tag` allocates an input-sized heap buffer; the
  streaming refactor (Poly1305 init/update/final, dropping the allocation and
  the overflow guard entirely) remains open future hardening (audit §3.14/§5.2).
- **~256 GB RFC AEAD plaintext ceiling** — documenting/guarding it is listed in
  audit §5.2; unreachable for blockchain-sized data.
- **No daemon call site consumes XChaCha20-Poly1305 yet** (audit §8e) — the
  module is additive. Intended consumers per the spec's profile table: the
  MODERN-profile AEAD for v2.17 keyfiles, v2.22 amount encryption, and
  direct-to-DApp payloads.
