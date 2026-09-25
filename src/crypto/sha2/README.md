# src/crypto/sha2 — SHA-2 hash / MAC / KDF family (C99)

Per-module provenance + audit README required by CRYPTO-C99-SPEC.md §3.16.
Part of the libsodium-free C99 crypto stack; closes spec work units **§3.1**
(SHA-256 / SHA-512 / HMAC / HKDF) and **§3.8b** (PBKDF2-HMAC-SHA-256, the
FIPS-profile keyfile KDF).

## 1. What this module implements

Public header: `include/determ/crypto/sha2/sha2.h` (portable C99, `extern "C"`,
no external dependency). Entry points, by file:

| File | Entry point | Construction | Spec work unit |
|---|---|---|---|
| `sha256.c` | `determ_sha256`, `determ_sha256_init`/`_update`/`_final` | SHA-256, FIPS 180-4 §6.2 (the one-shot wraps the incremental engine) | §3.1 |
| `sha512.c` | `determ_sha512`, `determ_sha512_init`/`_update`/`_final` | SHA-512, FIPS 180-4 §6.4 (the one-shot wraps the incremental engine) | §3.1 |
| `hmac.c` | `determ_hmac_sha256` (+ `_init`/`_update`/`_final`), `determ_hmac_sha512` | HMAC, RFC 2104 / FIPS 198-1, streamed through the hash | §3.1 |
| `hkdf.c` | `determ_hkdf_sha256` | HKDF extract-then-expand, RFC 5869 | §3.1 |
| `pbkdf2.c` | `determ_pbkdf2_hmac_sha256` | PBKDF2, RFC 8018 / PKCS #5 v2.1 (SP 800-132) | §3.8b |

Error channels: no file here allocates (2026-09-25, DECISION-LOG "Heap-free
HMAC-SHA-256, HKDF and PBKDF2" and "Streaming SHA-512 and heap-free
HMAC-SHA-512"), so the audit's allocation-failure and size-overflow returns are
gone. Both HMACs stream the message through the hash and always return 0 (the
`int` return is an audit retrofit kept for source compatibility); HKDF returns
`-1` only when `outlen > 255*32 = 8160` (RFC 5869 ceiling); PBKDF2 returns `-1`
only when `iters == 0` or `dkLen > (2^32 − 1)·hLen` (RFC 8018 §5.2 step 1).
Both KDFs fail before writing `out`. A NULL/zero HKDF salt is treated as
HashLen zero bytes per the RFC.

SHA-2 is the foundation the rest of the stack builds on. In-tree consumers
today: `hmac.c` → the SHA-256/512 incremental engines; `hkdf.c` + `pbkdf2.c` →
the streaming HMAC-SHA-256 here;
`src/crypto/ed25519/ed25519.c` (RFC 8032 seed-hash, nonce `r`, and HRAM are
SHA-512) → `determ_sha512`. Production daemon/wallet call sites are still on the OpenSSL
backend — the §Q9 step-2 call-site migration is gated on an explicit go-ahead
because it touches the keyfile on-disk format.

## 2. Provenance + construction

Per the spec's §2 Q3 vendoring table:

- **SHA-256 / SHA-512** — NIST FIPS 180-4 reference construction, written from
  the standard in portable C99. Round constants are the FIPS 180-4 §4.2.2 /
  §4.2.3 tables. License posture: **public domain**.
- **HMAC** — RFC 2104 (trivial wrapper over the in-family SHA-2). Public domain.
- **HKDF** — RFC 5869 (trivial wrapper over the in-family HMAC). Public domain.
- **PBKDF2** — RFC 8018, a trivial wrapper over HMAC-SHA-256 per spec §3.8b;
  the FIPS-validated construction is SP 800-132. It carries no separate Q3
  table row; it follows the family's public-domain posture. This is the
  `cluster` / `tactical` (FIPS-profile) keyfile passphrase KDF in the spec's
  Q10 feature matrix — the MODERN-profile counterpart is Argon2id
  (`src/crypto/argon2/`).

There is no upstream code snapshot to version-pin: the module is implemented
from the published standards (no TweetNaCl/ref10-style lineage here), so the
pins are the standards themselves — FIPS 180-4, RFC 2104, RFC 5869, RFC 8018.

## 3. Validation evidence

One subcommand validates the whole family: **`determ test-sha2-c99`**
(dispatch block in `src/main.cpp`), wrapped by **`tools/test_sha2_c99.sh`** and
run in `tools/run_all.sh` (FAST set). 18 PASS assertions:

1. **SHA-256 / SHA-512 vs OpenSSL, every length 0..300** — byte-equal against
   the daemon's backend (`crypto::sha256` and `EVP_Digest(EVP_sha512)`),
   covering single-block, multi-block, and both padding edges (55/56 for
   SHA-256, 111/112 for SHA-512). This is the spec's §Q9 cross-validation
   gate; it uses no transcribed digest, so it is immune to KAT-transcription
   error. (2 assertions)
2. **NIST FIPS 180-4 KATs** — SHA-256/512 of `"abc"` and `""` as
   OpenSSL-independent anchors. (4)
3. **1 MiB message** — SHA-256 + SHA-512 still byte-equal vs OpenSSL. (2)
4. **HMAC vs OpenSSL `HMAC()`** over a (key,msg)-length grid including the
   key > block-size hashing path. (2)
5. **HMAC RFC 4231 Test Case 1 + 2** for both SHA-256 and SHA-512 — the
   OpenSSL-independent anchor, so a shared us-and-OpenSSL blind spot cannot
   hide. (4)
6. **HKDF RFC 5869 Test Case 1 + 3** — multi-block expand (L=42) with
   salt+info, and the empty-salt/empty-info default path. The build pins
   OpenSSL 1.1.1w (CMake FetchContent), which predates the 3.0 `EVP_KDF` API,
   so the RFC vectors are the anchor; the §Q9 byte-equal gate runs through the
   HMAC building block above. (2)
7. **PBKDF2 vs OpenSSL `PKCS5_PBKDF2_HMAC`** over a (pw,salt,iters,outlen)
   grid (multi-block `outlen ∈ {33,48,100}` included) plus the
   `("password","salt",4096,32)` KAT. (2)

Adversarial audit: `docs/proofs/C99CryptoStackAudit.md`. The five files in this
directory produced 10 confirmed findings (sha256 1, sha512 1, hmac 2, hkdf 3,
pbkdf2 3) — **0 Critical, 0 High**; all fixed output-preservingly (commit
`2e0058b`): block-loop counters `unsigned` → `size_t` (audit §3.1), the PBKDF2
`dkLen` ceiling (§3.8), `malloc` NULL-checks + `size_t`-overflow guards on the
HMAC/HKDF/PBKDF2 allocation sites (§3.3, §3.5, §3.6, §3.9), and the
secret-zeroization sweep (§3.2, §3.4, §3.7, §3.10).

## 4. Constant-time / hygiene posture

Per audit §4, the family is constant-time by construction:

- **SHA-256 / SHA-512**: unkeyed public hashes. The only data-dependent
  branches (`if (rem)`, `padlen` selection, the two-block tail) key off the
  **public message length**, never message content. `K256[i]` / `K512[i]` are
  indexed by the loop counter, not by data — no secret-dependent table lookup.
- **HMAC / HKDF / PBKDF2**: every branch, loop bound, and memory index is a
  function of public parameters only (`keylen`, `msglen`, `outlen`, `infolen`,
  `saltlen`, `blocks`, `iters`); key bytes flow only through data-independent
  XOR/copy/hash.

**No comparison happens in this module** — HMAC emits a MAC and performs no
in-file tag comparison, so the constant-time-compare obligation falls on
callers, who must route tag equality through `determ_ct_memcmp`
(`include/determ/crypto/ct.h`, CRYPTO-C99-SPEC §3.10).

`determ_secure_zero` (`include/determ/crypto/secure_zero.h`, the
memory-hygiene half of §3.10) scrubs every secret-bearing buffer before scope
exit: the message-schedule `w[]` in `sha256_block` / `sha512_block`, and the
padding `tail[]` and the whole ctx in both `_final`s (key-derived when a keyed
caller feeds a secret block); HMAC `k0` / `pad` / `inner`; HKDF `prk` / `t`;
PBKDF2 the keyed HMAC ctx / `U` / `T`. A caller that abandons an HMAC ctx
before `_final` wipes it itself (`sha2.h`).

## 5. Known limitations / future work

Only what the spec + audit record:

- **Streaming landed 2026-09-25.** The audit's streaming-refactor alternative
  (init/update/final, dropping the input-sized heap buffers and the
  secret-bearing `free`) is done for the whole family; `test-c99-crypto-bounds`
  asserts with an allocator hook that the HMACs and hashes allocate nothing.
  This does not admit the files to the freestanding target by itself
  (CRYPTO-C99-SPEC "Heap-free SHA-256 MAC and KDFs").
- **Test-vector coverage** (audit §5.3): the RFC 4231 HMAC KATs, HKDF RFC 5869
  A.1–A.3 with the `L=8160` ceiling and its last block, and PBKDF2 RFC 7914
  vectors at varied `dkLen` including a partial final block are in
  `test-c99-crypto-bounds`; the allocation-failure paths the audit wanted
  interposed no longer exist. Still to add: HKDF `outlen=0`, RFC 6070
  (PBKDF2-HMAC-SHA-1 — not implemented here, so not applicable as written) and
  the NIST CAVP SHAVS files inside the C99 gate (the FAST gate
  `test-c99-vectors` runs `tools/vectors/sha2_cavp_*.json`, whose SHA-512
  lengths include the 111/112/113 padding edge).
- **SHA-512 length field**: the 128-bit length encoding carries only the low
  64 bits (high 64 covered by the zero padding), so single messages are bounded
  at < 2^64 bits — documented in `sha512.c`, unreachable for blockchain-sized
  data.
- **Call-site migration (§Q9 step 2) not yet done**: the daemon/wallet still
  hash/KDF through OpenSSL; switching the keyfile envelope changes on-disk
  format and is gated on an explicit go-ahead.
- **HKDF lacks a direct OpenSSL oracle**: the build pins OpenSSL 1.1.1w and
  the `EVP_KDF` API arrived in OpenSSL 3.0; HKDF anchors on RFC 5869 vectors
  over the OpenSSL-cross-validated HMAC. (The `test-sha2-c99` dispatch comment
  in `src/main.cpp` attributes this to an `OPENSSL_API_COMPAT` pin — no such
  macro is defined in the build; the version pin is the actual cause.)
