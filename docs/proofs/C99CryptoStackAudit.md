# C99 Crypto Stack — Adversarial Correctness + Constant-Time Audit

**Subject:** the libsodium-free C99 cryptographic primitives shipped under
`src/crypto/{sha2,chacha20,aes}/`.

**Status:** all primitives validated byte-equal vs OpenSSL + published KATs by the
`determ test-sha2-c99` / `determ test-chacha20-c99` / `determ test-aes-c99`
subcommands and exercised in `tools/run_all.sh` (FAST mode). This document records
the *additional* adversarial audit layered on top of that cross-validation.

**Verdict in one line:** no Critical or High findings. Every primitive is
cryptographically correct and constant-time at the source level. The confirmed
findings are robustness hardening (unchecked `malloc` / `size_t` overflow on
public-header APIs), two large-input counter-overflow defects unreachable for
blockchain-sized data, and a uniform stack-wide secret-zeroization gap.

> **Remediation status (commit `2e0058b`).** All 18 confirmed findings are now
> fixed — 17 by code change, 1 (§3.12, the ChaCha20 32-bit counter) accepted by
> design as RFC 8439-conformant. Every fix is output-preserving: the byte-equal
> cross-validation vs OpenSSL + KATs (`test-sha2-c99` / `test-chacha20-c99` /
> `test-aes-c99`) and `FAST=1` (151/151) are unchanged. Summary:
> - **Zeroization (§3.2, §3.4, §3.7, §3.10, §3.11, §3.13, §3.16, §3.17, §3.18):**
>   new `determ_secure_zero` (`include/determ/crypto/secure_zero.h` +
>   `src/crypto/secure_zero.c`, a non-elidable volatile-pointer `memset`) applied
>   to every secret-bearing buffer before scope exit across all 10 files.
> - **Correctness (§3.1):** SHA-256/512 block-loop counter `unsigned` → `size_t`.
> - **Spec (§3.8):** PBKDF2 enforces the RFC 8018 `dkLen ≤ (2³²−1)·hLen` ceiling.
> - **Memory safety (§3.3, §3.5, §3.6, §3.9, §3.14, §3.15):** `malloc` NULL-checks
>   + `size_t`-overflow guards on the HMAC / HKDF / PBKDF2 / AEAD allocation sites;
>   HMAC + the AEAD `encrypt` gained a backward-source-compatible `int` error
>   channel. §3.14 (the lone Medium) is closed by the `aead_tag` overflow guard.
>
> The §3 entries below record the **as-found** state — their cited line numbers
> predate the fix. The streaming-refactor alternative noted for §3.3/§3.14 (drop
> the input-sized heap buffers entirely) and the broader CAVP/RFC test vectors of
> §5.3 remain open as future hardening, not correctness gaps.

---

## 1. Scope and Methodology

### 1.1 The two validation layers

**(a) Byte-equal cross-validation (already in the test suite).**
For each primitive, `determ test-*-c99` runs the C99 implementation and the
daemon's OpenSSL backend over a grid of inputs and asserts the outputs are
byte-identical, plus published KATs (NIST/RFC). Coverage by primitive:

- SHA-256 / SHA-512: lengths `0..300` and one 1 MiB message.
- HMAC / HKDF / PBKDF2: RFC 2104 / RFC 5869 / RFC 8018-style KATs; HKDF exercises
  the `outlen=42` two-block expand for RFC 5869 TC1/TC3; PBKDF2 exercises
  `outlen ∈ {33,48,100}` multi-block + the 4096-iteration KAT.
- ChaCha20 / Poly1305 / AEAD: RFC 8439 §2.8.2 KAT + OpenSSL `EVP_chacha20`/
  `EVP_chacha20_poly1305`; counters deliberately bounded well below 2³²; `out==in`
  aliasing only.
- AES-256 / GCM: OpenSSL over plaintext `∈ {0,1,16,63,64,65,128,200}`,
  AAD `∈ {0,1,12,16,20}`.

**(b) This adversarial audit (the present document).**
Cross-validation against a single reference implementation over a bounded length
grid is *structurally blind* to four classes of defect:

1. **Correctness divergence only at extreme lengths** (≥256 GiB / ≥2⁶¹ bytes) —
   the grid never reaches the boundary, and a second correct implementation would
   diverge there too (e.g. OpenSSL ChaCha20 carries into the nonce; this code
   wraps), so the oracle is intentionally kept below it.
2. **Constant-time behaviour** — output bytes are identical whether or not a
   table lookup or branch is secret-dependent; timing is invisible to a byte
   compare.
3. **Memory-safety on adversarial / failure inputs** — unchecked `malloc`,
   `size_t` overflow in allocation sizes. The oracle only ever sees well-formed
   inputs and never an allocation failure.
4. **Secret-zeroization hygiene** — residual key material on the stack/heap after
   return does not change the output bytes.

Each of the 11 source files was audited adversarially against all four
dimensions. Every raw finding was then independently re-verified against the
actual source before being recorded here as confirmed-real.

### 1.2 Files in scope

```
src/crypto/sha2/sha256.c                SHA-256
src/crypto/sha2/sha512.c                SHA-512
src/crypto/sha2/hmac.c                  HMAC-SHA-256 / HMAC-SHA-512
src/crypto/sha2/hkdf.c                  HKDF-SHA-256
src/crypto/sha2/pbkdf2.c                PBKDF2-HMAC-SHA-256
src/crypto/chacha20/chacha20.c          ChaCha20
src/crypto/chacha20/poly1305.c          Poly1305
src/crypto/chacha20/chacha20_poly1305.c ChaCha20-Poly1305 AEAD
src/crypto/aes/aes_core.c               AES-256 block + constant-time S-box
src/crypto/aes/aes_gcm.c                AES-256-GCM
```

---

## 2. Per-Primitive Results

| Primitive | File | Verdict | Raw findings | Confirmed-real |
|---|---|---|---|---|
| SHA-256 | `src/crypto/sha2/sha256.c` | minor issues | 2 | 1 |
| SHA-512 | `src/crypto/sha2/sha512.c` | minor issues | 2 | 1 |
| HMAC-SHA-256/512 | `src/crypto/sha2/hmac.c` | minor issues | 2 | 2 |
| HKDF-SHA-256 | `src/crypto/sha2/hkdf.c` | minor issues | 3 | 3 |
| PBKDF2-HMAC-SHA-256 | `src/crypto/sha2/pbkdf2.c` | minor issues | 3 | 3 |
| ChaCha20 | `src/crypto/chacha20/chacha20.c` | minor issues | 2 | 2 |
| Poly1305 | `src/crypto/chacha20/poly1305.c` | minor issues | 1 | 1 |
| ChaCha20-Poly1305 AEAD | `src/crypto/chacha20/chacha20_poly1305.c` | minor issues | 3 | 3 |
| AES-256 block + S-box | `src/crypto/aes/aes_core.c` | minor issues | 1 | 1 |
| AES-256-GCM | `src/crypto/aes/aes_gcm.c` | minor issues | 2 | 1 |
| **Total** | | | **21** | **18** |

**Severity rollup (18 confirmed):** 0 Critical, 0 High, 1 Medium, 10 Low, 7 Info.

The single Medium is a 32-bit-platform `size_t` overflow in the AEAD tag buffer
(§3.14). No correctness defect is reachable for any blockchain-sized input; the
two correctness findings (§3.1, §3.9) require ≥256 GiB single-buffer messages.

---

## 3. Confirmed-Real Findings

Findings are grouped by file in scope order. Each is verified against the cited
source line; the line numbers below match the current tree.

### 3.1 SHA-256 — block-loop counter declared `unsigned`, truncates against `size_t` block count

- **Severity:** Low — **Category:** correctness
- **Location:** `src/crypto/sha2/sha256.c`, `determ_sha256`, line 73
  (`unsigned i;`) and line 75 (`for (i = 0; i < full; i++)`)

`full = len / 64u` is a `size_t` (line 69; 64-bit on the LLP64 Windows-x64 build
target and on LP64), but the block-loop counter `i` is `unsigned int` (32-bit on
every mainstream ABI). The comparison `i < full` is evaluated in 64-bit (i is
promoted), so it cannot terminate early; the hazard is the increment. When
`full ≥ 2³²` — i.e. message length ≥ 256 GiB — `i` counts `0..0xFFFFFFFF`, and at
`0xFFFFFFFF` the condition is still true, so `i++` wraps modulo 2³² back to 0. The
loop never reaches `full`: it spins forever, re-hashing the first 2³² blocks. The
`(size_t)i * 64u` cast on line 75 governs only the pointer arithmetic and is
applied *after* the wrap, so it does not save the computation.

This is a real divergence from FIPS 180-4 behaviour on ≥256 GiB inputs and is
invisible to the ≤1 MiB cross-validation. Severity is Low: `determ_sha256` is a
one-shot API taking a fully materialized in-memory buffer (no streaming variant),
and blockchain tx/block/state payloads never approach 256 GiB.

**Fix:** declare the block-loop index as `size_t i;` (or a dedicated `size_t bi`).
The other `unsigned i` loops (lines 82, 87, bound 8; the `sha256_block` loops,
bound 16/64) are safe and may remain.

### 3.2 SHA-512 — message schedule and tail staging buffers left un-zeroized

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/sha2/sha512.c`, `sha512_block` (`w[80]`) and
  `determ_sha512` (`tail[256]`, working vars / local `h[8]`)

On return, the message schedule `w[80]`, the `tail[256]` staging buffer (which
holds a verbatim `memcpy` of up to the final 127 input bytes), and the working
variables are left on the stack without scrubbing. For SHA-512 over public data
this is harmless, but this exact one-shot path is the SHA-512 primitive that
keyed downstream consumers build on — HMAC-SHA-512 (feeds the secret key through
the inner/outer pads), RFC 8032 Ed25519 (hashes the secret seed), and the RFC
9591 FROST H1..H5 challenge hashes. When those callers pass secret-bearing input,
`w[]` and `tail[]` transiently hold key-derived material that persists in the
stack frame after return.

The header's documented caveat (`sha2.h`) is narrowly about *timing* ("a public
hash has no timing side channel to protect"); it does not disclaim residual-secret
hygiene. Severity is Low (defense-in-depth): realizing it requires a separate
memory-disclosure primitive. See §5 — the proper fix scrubs the whole keyed
primitive family, not just this file.

**Fix:** scrub `w[80]` at the end of `sha512_block` and `tail[256]` / local `h[8]`
/ working vars at the end of `determ_sha512`, using a non-elidable secure-zero
(volatile-pointer memset / `explicit_bzero` / `SecureZeroMemory`).

### 3.3 HMAC-SHA-256/512 — unchecked `malloc` + `size_t` overflow on `(B + msglen)`

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/sha2/hmac.c`, `determ_hmac_sha256` line 23 (written
  at lines 24–25); `determ_hmac_sha512` line 48 (written at lines 49–50)

`ibuf = malloc(B + msglen)` is never NULL-checked before the loop on line 24
writes `ibuf[0..B-1]` and the `memcpy` on line 25 writes `ibuf+B`:

- **(a)** On allocation failure, line 24 is an immediate NULL-pointer write →
  crash / DoS.
- **(b)** `B + msglen` is computed in `size_t` with no overflow guard. If
  `msglen > SIZE_MAX - B` (`B` = 64 / 128) the sum wraps to a small value, `malloc`
  returns a tiny buffer, and `memcpy(ibuf + B, msg, msglen)` overflows the heap.

`determ_hmac_sha256/512` are public-header API (`sha2.h`). All in-tree callers
(`pbkdf2.c`, `hkdf.c`, `main.cpp`) pass small, controlled lengths, so neither path
is reachable in production today; any future external caller passing an
attacker-influenced `msglen` inherits the bug.

**Fix:** guard the size (`if (msglen > SIZE_MAX - B) …`) and check the result
(`if (!ibuf) …`). Better, stream the inner hash (init/update/final) to eliminate
the heap buffer — and the secret-bearing `free` (§3.4) — entirely.

### 3.4 HMAC-SHA-256/512 — key-derived intermediates not zeroized; `ibuf` freed with key material intact

- **Severity:** Info — **Category:** memory safety
- **Location:** `src/crypto/sha2/hmac.c`, `determ_hmac_sha256` (`k0` line 12,
  `ibuf` line 23 / free 27, `opad_block` line 13, `inner` line 14);
  `determ_hmac_sha512` (analogous, free line 52)

`k0` holds the processed HMAC key; `ibuf` holds `(k0 ^ ipad)` and is handed back
to the allocator via `free()` (line 27 / 52) *without being wiped*, leaving the
ipad-masked key in reclaimable heap; `opad_block` holds `(k0 ^ opad)` on the
stack. Because `ipad`/`opad` are public constants (0x36/0x5c), recovering either
masked buffer recovers the key. This HMAC underpins PBKDF2 keyfile-at-rest (S-004)
and HKDF, so the key is genuinely sensitive.

Severity held at Info because no zeroization primitive exists anywhere in the
C99 crypto stack (a grep for `memset_s` / `explicit_bzero` / `OPENSSL_cleanse` /
`sodium_memzero` / `SecureZeroMemory` across `src/crypto` returns nothing) — this
is a uniform stack-wide convention, and the siblings `pbkdf2.c` / `hkdf.c` leak
the same buffer class. See §5.

**Fix:** add a stack-wide non-elidable secure-zero helper and call it on `k0`,
`opad_block`, `inner`, and `ibuf` *before* `free(ibuf)` and before return — here
and in `pbkdf2.c` / `hkdf.c`.

### 3.5 HKDF-SHA-256 — unchecked `malloc` in expand loop

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/sha2/hkdf.c`, `determ_hkdf_sha256`, line 34 (written
  at lines 37–39)

The expand loop allocates `buf = malloc(n)` (line 34) and immediately writes it:
`memcpy(buf, t, tlen)` (37), `memcpy(buf + off, info, infolen)` (38),
`buf[off] = counter` (39), with no NULL check. On `malloc` failure all three are
writes through NULL → UB / crash. The function already returns `int` and uses
`-1` for failure (the `outlen > 255*HashLen` guard on line 21), so a clean error
return is available and callers already handle it.

**Fix:** `if (!buf) return -1;` immediately after line 34.

### 3.6 HKDF-SHA-256 — integer overflow in `n = tlen + infolen + 1`

- **Severity:** Info — **Category:** memory safety
- **Location:** `src/crypto/sha2/hkdf.c`, `determ_hkdf_sha256`, line 33 (consumed
  at lines 34, 38)

`size_t n = tlen + infolen + 1` (line 33) wraps if `infolen` is within `1..32` of
`SIZE_MAX`: `n` becomes small, `malloc(n)` succeeds undersized, then
`memcpy(buf + off, info, infolen)` (line 38) copies ~`SIZE_MAX` bytes — heap
over-write plus over-read of `info`. The only guard (line 21) bounds `outlen`,
not `infolen`, and the header documents no `info`-length precondition. Impact is
theoretical: a near-`SIZE_MAX` (~16 EiB) `info` cannot be allocated, and all
in-tree callers pass tiny constant `info`. RFC 5869 imposes no `info` limit, so an
explicit guard is the correct defense.

**Fix:** `if (infolen > SIZE_MAX - 33) return -1;` before computing `n`.

### 3.7 HKDF-SHA-256 — sensitive intermediates `prk`/`t`/`buf` not zeroized

- **Severity:** Info — **Category:** memory safety
- **Location:** `src/crypto/sha2/hkdf.c`, `determ_hkdf_sha256`, exit (line 48);
  `prk[32]` line 14, `t[32]` line 15, heap `buf` line 34 / free line 41

`prk[32]` (the HKDF pseudorandom key — recovery of which lets an attacker derive
all OKM; it is the HMAC key in the expand loop at line 40), `t[32]` (OKM blocks),
and the heap `buf` (PRK-derived input `T(i-1) || info || counter`) are left in
stack/heap at return; `free(buf)` does not wipe. Byte-equal KAT cross-validation
cannot detect residual-secret-in-memory. Info-level for the same stack-wide reason
as §3.4.

**Fix:** scrub `prk`, `t`, `zero_salt` at exit and `buf` before `free` with the
shared secure-zero helper from §5.

### 3.8 PBKDF2-HMAC-SHA-256 — missing `dkLen` cap → `uint32_t` counter overflow → infinite loop

- **Severity:** Low — **Category:** spec compliance
- **Location:** `src/crypto/sha2/pbkdf2.c`, `determ_pbkdf2_hmac_sha256`, lines 23
  (`blocks`) + 26 (`for (i = 1; i <= blocks; i++)`)

RFC 8018 §5.2 step 1 requires PBKDF2 to reject `dkLen > (2³² − 1)·hLen` with
"derived key too long". This function performs no such check. `blocks` is a
`size_t` = `ceil(outlen/32)` (line 23); on a 64-bit platform an `outlen` above
`(2³²−1)·32` makes `blocks ≥ 2³²`. The loop counter `i` is `uint32_t` (line 17):
when `i` reaches `0xFFFFFFFF`, the comparison `i <= blocks` (i promoted to
`size_t`) is still true, the body runs, then `i++` wraps `uint32_t` back to 0 —
non-terminating, and the `INT_32_BE(i)` counter (lines 32–35) silently
repeats/wraps instead of producing distinct per-block inputs.

The byte-equal harness can't catch this: `main.cpp` caps the test grid at
`outlen=100` and casts `outlen` to `int` for the OpenSSL oracle, so the boundary
is never approached. Severity Low: the only callers (the S-004 wallet/envelope
KDF with `KEY_LEN=32`, and the self-tests) pass tiny fixed lengths; there is no
untrusted-input path controlling `outlen`. Triggering needs an in-process
buggy/hostile caller passing an absurd (~137 GB) `size_t`.

**Fix:** before computing `blocks`, enforce the RFC ceiling, e.g.
`if (outlen > (size_t)0xFFFFFFFFu * hLen) return -1;` — matching RFC 8018's
mandated "derived key too long" rejection and making the `uint32_t` counter
provably sufficient.

### 3.9 PBKDF2-HMAC-SHA-256 — unchecked `malloc` + `size_t` overflow in `saltlen + 4`

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/sha2/pbkdf2.c`, `determ_pbkdf2_hmac_sha256`, line 24
  (`msg = malloc(saltlen + 4)`), consumed at lines 31–35

`malloc` is never NULL-checked: on failure the code immediately writes
`memcpy(msg, salt, saltlen)` (31) and `msg[saltlen..saltlen+3]` (32–35),
dereferencing NULL. Separately, `saltlen + 4` is computed in `size_t` with no
guard: a `saltlen > SIZE_MAX - 4` wraps the size to a small value, `malloc`
succeeds undersized, and the same `memcpy` overflows the heap. The header places
no upper bound on `saltlen`. In-tree callers pass tiny salts, so neither path is
reachable today.

**Fix:** `if (!msg) return -1;` after `malloc` (free-then-return on error);
optionally `if (saltlen > SIZE_MAX - 4) return -1;`. Apply the same NULL check to
`hmac.c`'s `ibuf` allocation (§3.3).

### 3.10 PBKDF2-HMAC-SHA-256 — derived-key intermediates `U` and `T` not zeroized

- **Severity:** Info — **Category:** memory safety
- **Location:** `src/crypto/sha2/pbkdf2.c`, `determ_pbkdf2_hmac_sha256`, decl
  line 15 + return path lines 47–48

`U` (per-iteration HMAC output) and `T` (the accumulated derived-key block,
byte-identical to the returned key for the final block — `memcpy(out + off, T, take)`
on line 44) hold secret key material on the stack and are not wiped before
`free(msg); return 0;`. This KDF derives the AES-256-GCM wrapping key for the
S-004 wallet keyfile envelope, so residual material on the stack is a
defense-in-depth concern. Constant-time is clean (no secret-dependent branch or
tag comparison in this file). Info-level per §5.

**Fix:** scrub `U` and `T` with a non-elidable wipe just before
`free(msg); return 0;`.

### 3.11 ChaCha20 — key material and keystream left on the stack un-zeroized

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/chacha20/chacha20.c`, `determ_chacha20` (`st[16]`
  line 41, `block[64]` line 42; return line 60) and `chacha20_block` (`x[16]`
  line 22; return line 35)

`determ_chacha20` copies the 256-bit key into `st[4..11]` (line 49) and produces
raw keystream into `block[]` (line 56), then returns without scrubbing either.
`chacha20_block`'s working state `x[16]` (key-derived) is likewise left intact.
The secret key and keystream remain readable in the abandoned stack frame; a
later stack reuse, core dump, swap, or unrelated over-read can recover them. This
is genuine secret material (the master key, and keystream recoverable to plaintext
under known-plaintext), not public data. Byte-equal cross-validation can't surface
it.

**Fix:** before each return, scrub `st[]` and `block[]` in `determ_chacha20` and
`x[]` in `chacha20_block` with a compiler-non-elidable secure-zero (a plain
`memset` is liable to dead-store elimination). See §5.

### 3.12 ChaCha20 — 32-bit block counter wraps silently past 256 GiB

- **Severity:** Info — **Category:** correctness
- **Location:** `src/crypto/chacha20/chacha20.c`, `determ_chacha20`, `st[12]++`
  line 59 (initialized line 50)

`st[12]` is `uint32_t`; after the block at counter `0xFFFFFFFF` the increment
wraps to 0 with no carry into the nonce and no error. For a single message
exceeding 2³² blocks (256 GiB) the keystream silently repeats from the start — a
two-time-pad. This is **RFC 8439-compliant for the IETF 32-bit-counter variant**
(the RFC defines only a 32-bit block counter and does not specify carry-into-nonce;
that belongs to the legacy DJB 64-bit-counter variant), so it is **not** a spec
violation — it is why the test grid keeps counters below 2³² (OpenSSL
`EVP_chacha20` carries into the nonce and would legitimately diverge there).
Flagged Info because the implementation provides no overflow guard. Practical
impact for a payment/identity chain (messages never approach 256 GiB) is
negligible.

**Fix (optional hardening):** document the 256 GiB-per-(key,nonce) limit at the
call boundary, and/or detect when `st[12]` would wrap to 0 while bytes remain and
abort/return an error. No change is required for RFC 8439 conformance.

### 3.13 Poly1305 — `r`/`s` key material and partial-block scratch left un-zeroized

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/chacha20/poly1305.c`, `determ_poly1305` (key limbs
  `r0..r4` / `s1..s4` derived lines 65–70; `pad0..pad3` lines 71–72; partial
  scratch `buf[16]` line 79; return line 127)

`determ_poly1305` derives the secret Poly1305 `r`-key into `r0..r4` and the
precomputed `s1..s4`, copies the secret `s`-key into `pad0..pad3`, and on a
partial final block materializes up to 15 plaintext/ciphertext bytes into
`buf[16]`. None are wiped before return; no `memset`/`explicit_bzero`/`volatile`
appears in the file. For a one-time authenticator, disclosure of `(r,s)` lets an
attacker forge tags for that `(key,nonce)` — exactly the value that must never
leak. Byte-equal KAT/OpenSSL cross-validation checks only the output tag, not
post-return stack contents. Low because exploitation requires a secondary
memory-disclosure primitive.

**Fix:** before returning, scrub `r0..r4`, `s1..s4`, `pad0..pad3`, the accumulator
limbs, and `buf[16]` with a non-elidable wipe (see §5). The sibling `otk` buffers
in `chacha20_poly1305.c` have the same issue — §3.16.

### 3.14 ChaCha20-Poly1305 AEAD — `size_t` overflow in MAC-buffer length → heap overflow on 32-bit targets

- **Severity:** Medium — **Category:** memory safety
- **Location:** `src/crypto/chacha20/chacha20_poly1305.c`, `aead_tag`, lines
  34–44 (length math line 36; writes lines 39, 41)

`n = aadlen + pad_a + ctlen + pad_c + 16` (line 36) is computed in `size_t` with
no overflow check and no upper bound on `aadlen`/`ctlen`. On a 32-bit target
(`SIZE_MAX ≈ 4 GB`), an attacker-controlled `aadlen` and/or `ctlen` near
`SIZE_MAX` wraps `n` to a small value; `malloc(n)` succeeds undersized and the
subsequent `memcpy(mac + off, aad, aadlen)` / `memcpy(mac + off, ct, ctlen)`
(lines 39, 41) write far past the buffer — heap overflow. RFC 8439 §2.8 caps the
message at ~256 GB precisely to keep these in range, but that ceiling is never
enforced here. The functions are exported in the public header for arbitrary
future callers/platforms.

On 64-bit this requires ~2⁶⁴ bytes (impractical), and even on 32-bit the `memcpy`
must read multi-gigabyte source buffers — a real but nontrivial barrier; hence
Medium rather than High. (Co-located: `malloc`'s return at line 37 is also
unchecked — §3.15.)

**Fix:** reject inputs above the RFC ceiling and guard the addition explicitly
(e.g. `if (aadlen > SIZE_MAX - 32 - ctlen || …) return error;`). Better,
restructure `aead_tag` to stream blocks into `determ_poly1305` incrementally
(AAD, its pad, CT, its pad, the 16-byte length block) so no single input-sized
heap allocation exists — removing both the overflow and the allocation-failure
surface.

### 3.15 ChaCha20-Poly1305 AEAD — unchecked `malloc` → NULL-pointer write

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/chacha20/chacha20_poly1305.c`, `aead_tag`, lines
  37–44

`mac = malloc(...)` (line 37) is used at lines 39–44 (`memcpy`/`memset`/
`put_u64_le` into `mac + off`) without a NULL check. On allocation failure every
write targets `NULL + offset` → UB / crash. Both public entry points route through
`aead_tag` (encrypt at line 56, decrypt at line 65), so this is a DoS vector.
Severity Low: the impact is a clean crash, and `n` is sized to the in-flight
message (the overflow path of §3.14 is the only way to reach a tiny `n`).

**Fix:** check `mac` for NULL immediately after `malloc` and propagate failure.
Since `determ_chacha20_poly1305_encrypt` and `aead_tag` return `void`, this needs
an `int` return / abort — or, preferably, eliminate the allocation by streaming
(§3.14).

### 3.16 ChaCha20-Poly1305 AEAD — one-time Poly1305 key and secret stack material not zeroized

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/chacha20/chacha20_poly1305.c`,
  `determ_chacha20_poly1305_encrypt` (`otk[32]` line 53);
  `determ_chacha20_poly1305_decrypt` (`otk[32]`/`expect[16]` line 63);
  `poly1305_keygen` (`otk` line 12) — plus the composed `determ_poly1305`
  `r`/`s`/accumulator and `determ_chacha20` `st`/`block`

The one-time Poly1305 key `otk` (= `r || s`, derived from the secret ChaCha20
key) is left on the stack un-zeroized in both encrypt and decrypt;
`poly1305_keygen` fills `otk` from the keystream and does not wipe it. These are
secret intermediates; leaving them in reclaimable stack frames widens the
disclosure window via later stack reuse, swap, or core dump. RFC 8439 does not
mandate wiping, but it is standard AEAD hygiene.

**Fix:** add a non-elidable secure-zero for `otk` and `expect` at the AEAD entry
points (and for `r`/`s`/`pad`/accumulator in `determ_poly1305`, `st`/`block` in
`determ_chacha20`). A shared `determ_secure_zero` helper (§5) keeps this
consistent.

### 3.17 AES-256 — secret stack intermediates (state, key-schedule words) not zeroized

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/aes/aes_core.c`, `determ_aes256_encrypt_block`
  (`s[16]`, lines 148–161) and `determ_aes256_init` (`t0..t3`/`a`, lines 105–122)

`determ_aes256_encrypt_block` keeps the full AES state in `s[16]` across all 14
rounds and returns immediately after `memcpy(out, s, 16)` (line 161) without
clearing `s`. At round 0 (line 151) `s = plaintext XOR roundkey`, and every
subsequent round holds key-mixed cipher state — secret-correlated material that
persists on the stack. `determ_aes256_init` derives `t0..t3`/`a` directly from
the secret key (lines 105–122) and leaves them on the stack. No compiler is
obligated to clear these, and no secure-zero helper exists in `src/crypto`. This
is exactly the class OpenSSL addresses via `OPENSSL_cleanse`. Low: the dominant
secret (the full expanded key) lives in caller-owned `ctx->rk` (out of scope
here), exploitation needs a secondary disclosure primitive, and the
keyfile-envelope use is one-shot.

**Fix:** scrub `s[16]` just before the final `memcpy`-return in
`determ_aes256_encrypt_block`, and the `t0..t3`/`a` temporaries at the end of
`determ_aes256_init`. The caller (envelope code) should likewise zeroize its
`determ_aes256_ctx` when done.

### 3.18 AES-256-GCM — key schedule, GHASH subkey, and tag mask left un-zeroized

- **Severity:** Low — **Category:** memory safety
- **Location:** `src/crypto/aes/aes_gcm.c`, `determ_aes256_gcm_encrypt`
  (lines 110–124), `determ_aes256_gcm_decrypt` (126–143), `gcm_tag` (68–84),
  `gcm_crypt` (87–101)

None of the AEAD entry/helper functions scrub their sensitive intermediates
before returning: `determ_aes256_gcm_encrypt/decrypt` leave the expanded AES-256
round-key schedule (`ctx`, 240 bytes derived from the secret key) and the GHASH
subkey `H = E_K(0¹²⁸)` (line 119/136) resident; `gcm_tag` leaves
`ej0 = E_K(J0)` (the tag mask, line 82) and the GHASH accumulator `X`; `gcm_crypt`
leaves the keystream block `ks` and counter `ctr`. The round-key schedule is
invertible back to the master symmetric key, and this AEAD is the S-004 wallet
keyfile envelope keyed by a PBKDF2-derived KEK from the user passphrase, so the
lingering `ctx` is high-value. Invisible to the byte-equal OpenSSL check, which
inspects only `ct`/`tag`.

**Fix:** scrub `ctx`, `H`, `ej0`, `ks`, and `X` before each return using a
non-elidable wipe (`memset(&ctx, 0, sizeof ctx)` alone is liable to dead-store
elimination — route through a zeroization primitive). See §5.

---

## 4. Constant-Time Posture of the Stack

Constant-time behaviour is the dimension byte-equal cross-validation cannot
verify, and it is the dimension this stack handles cleanly. Per-file findings:

- **SHA-256 / SHA-512 (`sha256.c`, `sha512.c`):** unkeyed public hashes. The only
  data-dependent branches (`if (rem)`, `padlen` selection, two-block branch) key
  off the **public message length**, never message content. `K256[i]` / `K512[i]`
  are indexed by the loop counter, not by data — no secret-dependent table lookup.
  No MAC/tag comparison. No timing side channel to protect, and none introduced.

- **HMAC-SHA-256/512 (`hmac.c`):** emits a MAC and performs **no** in-file
  tag comparison (the constant-time-compare obligation falls on callers, e.g. the
  `main.cpp` RPC-auth verify). Every branch and loop bound (`keylen > B`, `keylen`,
  `msglen`, `B`, `B+msglen`, `32/64`) is a function of **public lengths** only; key
  bytes flow only through data-independent XOR/copy/hash. Clean.

- **HKDF / PBKDF2 (`hkdf.c`, `pbkdf2.c`):** KDFs with no in-file tag comparison.
  All control flow and memory indexing depend only on public parameters
  (`outlen`, `infolen`, `saltlen`, `blocks`, `iters`); the HMAC/XOR inner loops are
  data-independent. Clean.

- **ChaCha20 (`chacha20.c`):** pure ARX — no S-boxes, no table lookups, no
  secret-dependent branches/indices/loop bounds. `rotl32` shift amounts are
  compile-time constants in `{16,12,8,7}`, so `32−n` is never 0 or ≥32 (no shift
  UB); shifts are on `uint32_t`. Loop bounds depend only on the public `len`.
  Clean.

- **Poly1305 (`poly1305.c`):** the only data-dependent control flow is on the
  public message length `bytes`. The final reduction selects `h` vs `h−p` via an
  **unsigned-shift mask** (`(g4 >> 31) - 1`) — no secret-dependent branch, no
  timing leak, no signed-shift UB. Branchless. Clean.

- **ChaCha20-Poly1305 AEAD (`chacha20_poly1305.c`):** `ct_eq16` accumulates all
  16 byte-differences into a single byte and branches only on the **aggregate**
  pass/fail bit — it leaks neither byte position nor per-byte timing (the textbook
  constant-time-compare idiom). `decrypt` verifies the tag before writing any
  plaintext, so it writes nothing on auth failure. Clean.

- **AES-256 block + S-box (`aes_core.c`):** this is the highest-value constant-time
  result. The **S-box is computed arithmetically** (`aes_sbox_ct`) via `gf_inv`
  (fixed `x²⁵⁴` addition chain) over `gf_mul` (8 fixed iterations with mask-select
  XOR `a & (0u - (b & 1))` and mask-select reduction), with **no key-dependent
  table index** — the classic AES cache-timing channel is eliminated. `xtime`
  uses a branchless mask-multiply. The reference `SBOX[256]` table is used **only**
  in the build-time selftest, never indexed by the cipher. All encrypt/shift/mix
  loops have fixed bounds and constant indices. Clean.

- **AES-256-GCM (`aes_gcm.c`):** `ct_eq16` (lines 103–108) is the same aggregate-OR
  constant-time tag compare; `gcm_crypt` loop bounds and `take` depend only on
  public length; `ghash_mul` is branchless with secret-independent masks. No
  secret-dependent index, branch, or table lookup. Clean.

**Summary:** the AES S-box is arithmetic (no key-dependent table), GHASH and
Poly1305 are branchless, and both AEAD tag comparisons (`chacha20_poly1305.c` and
`aes_gcm.c`) are constant-time aggregate-difference compares. No confirmed
constant-time finding exists in any of the 11 files.

---

## 5. Residual Recommendations

### 5.1 Stack-wide secret zeroization (9 of the 18 findings) — DONE in `2e0058b`

The single highest-leverage change, now landed. At audit time there was **no**
secure-zero primitive anywhere in `src/crypto` (verified by grep: no `memset_s` /
`explicit_bzero` / `OPENSSL_cleanse` / `sodium_memzero` / `SecureZeroMemory`).
Findings §3.2, §3.4, §3.7, §3.10, §3.11, §3.13, §3.16, §3.17, §3.18 all reduced to
this one architectural decision, resolved by adding `determ_secure_zero` and
applying it across the stack (see the remediation banner at the top).

- Introduce a single portable `determ_secure_zero(void *, size_t)` (volatile-pointer
  `memset`, or `explicit_bzero` / `memset_s` / `SecureZeroMemory` where available)
  that the compiler **cannot** dead-store-eliminate — a plain `memset` will be
  elided.
- Call it consistently on every secret-bearing local before return across the
  stack: SHA-512 `w[]`/`tail[]`; HMAC `k0`/`ibuf`/`opad_block`/`inner` (and before
  `free(ibuf)`); HKDF `prk`/`t`/`buf`; PBKDF2 `U`/`T`; ChaCha20 `st`/`block`/`x`;
  Poly1305 `r`/`s`/`pad`/accumulator/`buf`; AEAD `otk`/`expect`; AES `s` and the
  key-schedule temporaries; GCM `ctx`/`H`/`ej0`/`ks`/`X`.

### 5.2 Robustness guards on public-header APIs (the Low / Medium findings)

- **Unchecked `malloc`:** add NULL checks at `hmac.c:23/48`, `hkdf.c:34`,
  `pbkdf2.c:24`, `chacha20_poly1305.c:37`. HKDF and PBKDF2 already have a `-1`
  error channel; HMAC/AEAD return `void` and need an `int` return or abort.
- **`size_t` overflow in allocation sizes:** guard `B + msglen` (`hmac.c`),
  `tlen + infolen + 1` (`hkdf.c`), `saltlen + 4` (`pbkdf2.c`), and the AEAD MAC
  length `n` (`chacha20_poly1305.c`, the Medium — §3.14). The cleanest fix for HMAC
  and the AEAD is to **stream** into the hash/Poly1305 (init/update/final) and drop
  the input-sized heap buffers entirely, removing both the overflow and the
  secret-bearing `free`.
- **RFC-mandated length ceilings:** enforce PBKDF2's `dkLen ≤ (2³²−1)·hLen`
  (`pbkdf2.c`, §3.8) and consider documenting/guarding the SHA-256 ≥256 GiB loop
  (`sha256.c`, §3.1 — fix the `unsigned i` → `size_t i`), the ChaCha20 256 GiB
  per-(key,nonce) limit (`chacha20.c`, §3.12), and the AEAD ~256 GB RFC ceiling.

### 5.3 Test-vector coverage to add

The current grid is sound for the common path but leaves the audited blind spots
untested. Worth adding to `determ test-*-c99`:

- **NIST CAVP** vectors for SHA-256/512 (SHAVS), HMAC (RFC 4231 full set), and
  AES-256-GCM (the NIST GCM test vectors / `gcmEncryptExtIV256`) to broaden KAT
  coverage beyond the OpenSSL oracle.
- **HKDF** RFC 5869 TC2 (long inputs / `outlen=82`), `outlen=0` (zero-output),
  single-block, and the max `L=8160` boundary — none currently exercised.
- **PBKDF2** RFC 6070 / RFC 7914 vectors at varied `dkLen` and the
  partial-final-block boundary.
- **ChaCha20** counter-near-2³² behaviour as a *documented divergence* test
  (the implementation wraps; OpenSSL carries) rather than leaving the boundary
  silently untested.
- A **deliberate allocation-failure** unit test (malloc interposer) to assert the
  NULL-check fixes from §5.2 once landed.

These additions would not change today's correctness verdict — every primitive is
byte-equal to OpenSSL over the validated grid and constant-time at the source
level — but they would convert the §3 hardening items from "argued" to
"regression-tested".
