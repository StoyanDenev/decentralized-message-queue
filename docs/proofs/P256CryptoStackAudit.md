> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# P-256 + OPRF Module — Adversarial Correctness + Constant-Time + Memory-Safety Audit

**Subject:** the from-scratch C99 NIST P-256 field/point layer, the RFC 9380
hash-to-curve suite, and the RFC 9497 OPRF(P-256, SHA-256) protocol layer, all
shipped as one ~1100-line translation unit `src/crypto/p256/p256.c`
(`include/determ/crypto/p256/p256.h`). CRYPTO-C99-SPEC.md §3.8c (base curve) +
§3.9b (hash-to-curve, mod-n scalar field, OPRF/VOPRF).

**Status:** validated byte-equal / byte-exact by three gates —
`determ test-p256-c99` (curve constants vs OpenSSL `EC_GROUP`, `[k]G` vs
`EC_POINT_mul`, ECDH parity + commutativity, reject paths, scalar gates),
`determ test-p256-h2c-c99` (mod-n ops vs the OpenSSL BIGNUM oracle + the RFC 9380
appendix K.1/J.1.1 vectors), `determ test-p256-oprf-c99` (protocol
self-consistency + DLEQ reject paths) — plus the §3.13 vector-file gate over
`tools/vectors/p256{,_h2c,_oprf}.json` (RFC 9380 / RFC 9497 appendix vectors,
re-verified by two independent Python implementations before import). This
document records the *additional* adversarial audit layered on top of that
cross-validation.

**Verdict in one line:** no Critical, High, or Medium findings. The field
arithmetic, CIOS reductions, runtime-derived constants, RCB complete addition,
the double-and-add-always ladder, encode/decode/compress/decompress validation,
SSWU, `expand_message_xmd`, and every OPRF transcript layout and buffer size are
**correct**; the constant-time posture is **clean** (no secret-dependent branch,
index, or table lookup on any secret path). The only confirmed-real findings are
one attacker-reachable error-path secret-zeroization gap in
`determ_p256_oprf_finalize` (Low — `inv = blind⁻¹` left resident on the
`oprf_load33` reject) plus two un-scrubbed-secret-intermediate notes (Info — the
`p`/`n33` locals in the same function, and the scratch `t` in the scalar
inversion) — all defense-in-depth, none a correctness or timing defect.

---

## 1. Scope and Methodology

### 1.1 The two validation layers

**(a) Byte-exact cross-validation (already in the test suite).** For the base
curve, `determ test-p256-c99` asserts the in-source constants byte-equal against
OpenSSL's `EC_GROUP` *before any arithmetic is trusted*, then checks `[k]G`
byte-equal vs `EC_POINT_mul` over a scalar grid, ECDH symmetry/commutativity, and
the on-curve / scalar-range reject paths. For §3.9b, `determ test-p256-h2c-c99`
oracles the mod-n Montgomery ops against OpenSSL BIGNUM and pins the h2c output
to the RFC 9380 appendix vectors; `determ test-p256-oprf-c99` plus the §3.13
`p256_oprf.json` gate pin the OPRF/VOPRF flow to the RFC 9497 A.3.1/A.3.2
vectors. Any single-bit divergence in the field, ladder, SSWU, transcript
layout, or DLEQ math fails one of these immediately.

**(b) This adversarial audit (the present document).** Cross-validation against
OpenSSL/RFC vectors over standard-sized inputs is *structurally blind* to three
classes of defect, which are exactly what a from-scratch bignum + protocol layer
is most likely to get wrong:

1. **Constant-time behaviour** — the ladder, the SSWU map, and the mod-n
   inversion produce byte-identical output whether or not a branch or index is
   secret-dependent; timing is invisible to a byte compare. The OPRF blind and
   the hash-to-curve input `msg` can be user secrets (the header says so), so a
   data-dependent branch there would be a real leak the oracle cannot see.
2. **Memory-safety on failure + adversarial-input paths** — an unchecked
   `malloc`, a `size_t` overflow in a length computation, or a stack buffer that
   is one byte too small for a maximal DST/input. The oracle only ever sees
   well-formed, standard-sized inputs and never an allocation failure.
3. **Extreme-input / boundary correctness** — the vectors are standard-sized, so
   they never exercise the CIOS reduction's `[p, 2p)` escape boundary, the
   `expand_message_xmd` `ell = 255` / `outlen = 65535` / `dstlen = 255` limits,
   the maximal-length OPRF transcript that sizes each stack buffer, or the
   counter-loop exhaustion in `DeriveKeyPair`.

The module was audited adversarially against all three dimensions along the five
areas the task enumerates (field/scalar arithmetic, point ops, hash-to-curve,
the OPRF layer, memory hygiene). Every finding was independently re-verified
against the actual source, and the arithmetic-boundary claims were checked
numerically against the true P-256 `p` and `n` (see §2 notes) before being
recorded here.

### 1.2 File in scope

```
src/crypto/p256/p256.c        NIST P-256 field/point + RFC 9380 h2c + RFC 9497 OPRF
include/determ/crypto/p256/p256.h   public API + contract
```

The module consumes only `determ_sha256` (SHA-2 stack, separately audited in
`C99CryptoStackAudit.md`), `determ_ct_memcmp` / `determ_secure_zero` (the §3.10
shared CT + hygiene primitives), and `stdlib`/`string`.

---

## 2. Per-Area Results

| # | Area | Functions | Verdict | Confirmed-real |
|---|---|---|---|---|
| 1 | Field / scalar arithmetic mod p, n | `fe_add` `fe_sub` `fe_mont_mul` `sc_add_raw` `sc_sub_raw` `sc_mont_mul`; runtime constants `R2`/`ONE_M`/`N0I`/`R2N` | **clean** | 0 |
| 2 | Point ops + encode/decode/compress | `pt_add` (RCB) `pt_scalar_mul` `decode_point` `encode_point` `_point_compress` `_point_decompress` | **clean** | 0 |
| 3 | hash-to-curve / SSWU / xmd | `sswu_map` `fe_from_be48` `sc_from_be48` `determ_p256_expand_message_xmd` `_hash_to_curve` `_hash_to_scalar` | **clean** | 0 |
| 4 | OPRF layer | `_oprf_derive_key` `_oprf_blind` `_oprf_evaluate` `_oprf_finalize` `oprf_composites` `oprf_challenge` `_voprf_prove` `_voprf_verify` | minor issues | 2 |
| 5 | Memory safety / hygiene | all of the above | minor issues | 1 |

**Severity rollup (3 confirmed):** 0 Critical, 0 High, 0 Medium, 1 Low, 2 Info.
**All three REMEDIATED in-session** (the same session as this audit): §3.1 + §3.2
by restructuring `determ_p256_oprf_finalize` to a single `goto cleanup` that
scrubs `inv` / `n33` / `p` on every exit path (exactly the fix §3.1 recommends);
§3.3 by adding the `determ_secure_zero(t, …)` scrub to `determ_p256_scalar_inv_mod_n`.
All 30 P-256 vectors stay byte-exact (the scrubs are behavior-preserving).
(A fourth, independent constant-time finding — the `scalar_ok`/`be_lt`
variable-time secret compare — was surfaced by the companion
`ConstantTimeInventory.md` pass, tracked there as **P256-CT-1** and also
remediated in-session by making `be_lt` branchless; it is not a hygiene issue so
it is not in this audit's zeroization rollup.)

No correctness defect exists in any area. The three confirmed findings
(§3.1–§3.3) are all secret-zeroization hygiene — the same defense-in-depth class
as `C99CryptoStackAudit.md` §3.2/§3.4/§3.7/§3.10 — and are narrower than those,
because this module already applies `determ_secure_zero` on every *success* path
(it shipped after the §5.1 stack-wide zeroization landed); the gaps were only on
specific *error* returns.

---

## 3. Confirmed-Real Findings

### 3.1 `determ_p256_oprf_finalize` — `inv = blind⁻¹` left un-zeroized on the `oprf_load33` error return

- **Severity:** Low — **Category:** memory safety (secret zeroization)
- **Location:** `src/crypto/p256/p256.c`, `determ_p256_oprf_finalize`, the
  `return -1` at the `oprf_load33(&p, eval33)` check (**before** the
  `determ_secure_zero` pair)

As found:

```c
if (determ_p256_scalar_inv_mod_n(inv, blind) != 0) return -1;   /* inv unset here — fine */
if (oprf_load33(&p, eval33) != 0) return -1;   /* inv = blind^-1 is LIVE, not scrubbed */
pt_scalar_mul(&r, inv, &p);
if (oprf_store33(n33, &r) != 0) return -1;     /* see reachability note — this return is dead */
determ_secure_zero(&r, sizeof r);              /* success path only */
determ_secure_zero(inv, sizeof inv);
```

`inv` holds `blind⁻¹ mod n` — the multiplicative inverse of the client's secret
blinding scalar; recovering it recovers `blind`, which lets an attacker unblind
the OPRF exchange (the blind is the value that must stay secret for the whole
protocol to hide the client input). On the `oprf_load33` early `return -1` path
(line 954) `inv = blind⁻¹` is left resident in the stack frame. The success path
*does* scrub both `&r` and `inv` (lines 957–958), so this is purely an
error-path omission.

Reachability — **exactly one** of the two error returns is live:

- **`oprf_load33(&p, eval33) != 0` (line 954) — LIVE.** `oprf_load33` fails on a
  malformed `eval33` (a server-supplied value in the OPRF flow — an attacker
  position) that has a bad SEC1 prefix, `x ≥ p`, a non-residue right-hand side,
  or decodes off-curve. `inv` is already materialized at this point, so a
  malicious server can deterministically drive `finalize` down this path with a
  crafted `eval33`, then rely on a *secondary* memory-disclosure primitive (core
  dump, swap, stack reuse) to read `inv`. This is the real leak.
- **`oprf_store33(n33, &r) != 0` (line 956) — UNREACHABLE (dead branch).** To
  reach it, line 954 must already have succeeded, so `p` is a *validated
  on-curve* point; P-256 has cofactor 1, so every non-identity point has prime
  order `n`, and `inv = blind⁻¹` is nonzero mod `n` (guaranteed by
  `scalar_inv_mod_n` returning 0). Hence `r = [inv]·p` is never the identity, and
  `oprf_store33`→`encode_point` fails *only* on the identity (`znz == 0`).
  So this return cannot be taken; it leaks nothing in practice. It is still worth
  scrubbing for defense-in-depth (an invariant a future refactor could break),
  but it is **not** an attacker-reachable disclosure and does not, on its own,
  justify the finding.

The two-step disclosure requirement (crafted `eval33` **plus** a secondary
memory-read primitive), plus the caller-owned nature of `blind`, holds this at
Low rather than higher.

**Why cross-validation misses it.** The `test-p256-oprf-c99` gate and the RFC
9497 A.3 vectors only exercise the *honest* finalize path with a well-formed
`eval33`, so control never reaches the error return; and even if it did, a
byte-equal output oracle cannot observe post-return stack contents. This is the
§1.1(2) blind spot.

**Fix (reported, not applied):** scrub `inv` before the `oprf_load33` early
return (the live leak); optionally also scrub `inv`/`&r` before the (dead)
`oprf_store33` return — or restructure to a single `goto cleanup` that scrubs
`inv`/`&r` unconditionally, matching the module's own success-path discipline
and making the invariant robust to future edits.

### 3.2 `determ_p256_oprf_finalize` — the decoded eval point `p` and unblinded element `n33` not scrubbed

- **Severity:** Info — **Category:** memory safety (secret zeroization)
- **Location:** `src/crypto/p256/p256.c`, `determ_p256_oprf_finalize`, locals
  `pt p` and `uint8_t n33[33]`

`p` is the decoded evaluated element and `n33` is `compress([blind⁻¹]·eval)` —
the unblinded OPRF group element that is hashed into the final output. Neither is
wiped on any path (only `r`, `inv`, and the `buf`/`stackbuf` transcript are).
These are secret-correlated intermediates (`n33` in particular is a
deterministic function of the client input and blind), and the module's stated
convention (per its own `determ_secure_zero` usage and the
`C99CryptoStackAudit.md` §5.1 posture) is to scrub secret-bearing locals before
return. Held at Info because `n33` is a hash-to-curve group element rather than a
raw scalar and the exploitation path is the same secondary-disclosure
requirement as §3.1.

**Why cross-validation misses it.** Same as §3.1 — residual stack material does
not change the output bytes the oracle checks.

**Fix (reported, not applied):** add `determ_secure_zero(&p, sizeof p)` and
`determ_secure_zero(n33, sizeof n33)` alongside the existing scrubs before every
return.

### 3.3 `determ_p256_scalar_inv_mod_n` — inversion scratch `t` not scrubbed (returned-secret-is-caller-owned)

- **Severity:** Info — **Category:** memory safety (secret zeroization)
- **Location:** `src/crypto/p256/p256.c`, `determ_p256_scalar_inv_mod_n`, local
  `fe t`

The function scrubs `am` and `acc` (the Montgomery input and the Fermat
accumulator) before `return 0`, but not `t`, which transiently holds
`be_to_fe(a)` and then the plain-domain final inverse (`sc_mont_mul(t, acc,
one)`) that is written out to `r`. `t` therefore leaves the low limbs of the
inverse of a secret scalar on the stack. This is Info-level and arguably by
design: the returned value `r` *is* the inverse and is caller-owned (the caller
decides how to scrub the output), so `t` leaks nothing the caller does not
already hold. Recorded for completeness and for symmetry with the `am`/`acc`
scrubs that are present. (The analogous `_voprf_prove` scrubs `km`/`ck`/`rfe`/
`sfe`/`&T` on its single post-computation path and its early returns precede any
secret-scalar materialization, so it has no equivalent gap.)

**Why cross-validation misses it.** Same residual-stack blind spot as §3.1/§3.2.

**Fix (reported, not applied):** if the stricter posture is wanted, add
`determ_secure_zero(t, sizeof t)` before `return 0` (matching `am`/`acc`); or
leave as-is on the caller-owns-the-output rationale.

---

## 4. What the audit confirmed CLEAN (per area)

A clean result is a valid audit outcome; the areas below were examined against
the same three blind-spot dimensions and no defect was found. Each claim was
verified by reading the cited function and, where a boundary was involved,
checked numerically against the real P-256 `p`/`n`.

### 4.1 Field / scalar arithmetic — carries, borrows, and the conditional-subtract masks are correct

- **`fe_add` select mask (line 77).** For `a, b < p` the sum lies in `[0, 2p−2]`,
  which can exceed `2²⁵⁶` (the top carry `c` set) *or* stay below it while still
  being `≥ p`. The mask `use_s = 0 − ((c | (1 − brw)) & 1)` selects the
  `t − p` form iff the sum carried out **or** the trial subtraction produced no
  borrow (`sum ≥ p`). **Both** terms are required and both are present — verified:
  `2p − 2 < 2²⁵⁷` so the 33rd bit is the only extra bit, and `2²⁵⁶ > p` so a
  carry always implies `≥ p`. Correct. `sc_add_raw` (mod n) is byte-identical in
  structure over `Nl[]`; same conclusion.
- **`fe_sub` / `sc_sub_raw` add-p-on-borrow (lines 92–96 / 859–863).** The
  borrow mask `0 − brw` conditionally adds back `p` (resp. `n`); a single
  add-back suffices because `a, b < p` bounds the deficit to one modulus.
  Correct.
- **`fe_from_be48` / `sc_from_be48` lo-reduction (lines 644–652 / 726–734).**
  Here the mask is `use_s = 0 − (1 − brw)` with **no** carry term — and that is
  correct precisely because `lo < 2²⁵⁶`, so no 33rd carry bit can exist; the only
  question is `lo ≥ p` (no borrow), and `2²⁵⁶ − 1 < 2p` guarantees one subtract
  fully reduces it. The deliberate difference from `fe_add`'s two-term mask is
  sound, not a copy-paste slip.
- **CIOS reduction `fe_mont_mul` / `sc_mont_mul` (lines 101–135 / 409–442).** The
  accumulator `t` carries limbs `0..7` plus `t[8]` (with `t[9]` staging the outer
  carry); by the standard Koç-CIOS invariant the post-loop `t < 2p` so
  `t[8] ∈ {0, 1}`, and the final branchless conditional subtract keyed on
  `(t[8] | no-borrow)` maps `[p, 2p)` back into `[0, p)`. A value in `[p, 2p)`
  **cannot** escape unreduced: if `t ≥ 2²⁵⁶` then `t[8] = 1` forces the subtract;
  if `t ∈ [p, 2²⁵⁶)` then `t[8] = 0` but the trial subtract has no borrow, which
  also forces it. Both the p-field (`n0' = 1`, the low limb *is* `m`, line 113)
  and the n-field (`n0' = N0I`, `m = t[0]·N0I`, line 421) reductions were checked;
  the `n0'` difference is the only structural change and it is correct because
  `p ≡ −1 (mod 2³²)` while `n` is not.
- **Runtime-derived constants.** `ONE_M = ~p + 1` computes `2²⁵⁶ − p = R mod p`
  (valid since `p < 2²⁵⁶ < 2p`), verified byte-exact; `R2` by 256 modular
  doublings of `ONE_M` is `R² mod p`; `N0I` by 5 Newton steps
  (`x ← x(2 − n·x)`) from `x = 1` inverts `n` mod `2³²` (each step doubles the
  correct low bits: 1→2→4→8→16→32, so 5 steps cover all 32), negated to
  `−n⁻¹`; `ONE_N`/`R2N` mirror the p-field derivation over `n`. The derivations
  are sound for the fixed public `p`/`n` — and the constant-parity gate in
  `test-p256-c99` re-anchors `p`/`n`/`b`/`Gx`/`Gy` to OpenSSL, so a transcription
  error in the *seeds* would be caught there. No hand-transcribed wide constant
  exists to be wrong.

**Why cross-validation is not sufficient here even though it passes:** OpenSSL
agreement over a scalar grid confirms the *aggregate* multiply/reduce is correct
on standard inputs, but it never forces a reduction input into the `[p, 2p)`
band on purpose; the `[p, 2p)`-escape reasoning above is the part the grid does
not probe, and it holds.

### 4.2 Point ops, encode/decode, compress/decompress — validation is complete

- **`pt_add` (RCB algorithm 4, a = −3).** The 42-operation sequence is the
  exception-free Renes–Costello–Batina complete formula; correctness of the
  *sequence* is exactly what the OpenSSL `[k]G` and scalar-mult-commutativity
  cross-checks exercise exhaustively (a wrong intermediate diverges on the first
  vector). No exceptional-case branch exists, which is what lets the ladder run
  uniformly.
- **`pt_scalar_mul` (double-and-add-always).** Per bit: one `pt_add(acc,acc,acc)`
  doubling, one `pt_add(&tmp,acc,base)`, one `pt_cswap(acc,&tmp,bit)`. The secret
  bit flows **only** through the mask-select `fe_cswap` (mask `0 − swap`); no
  array index, branch, or loop bound depends on the scalar. `tmp` is scrubbed on
  exit. Constant-time — see §5.
- **`decode_point` (lines 311–319).** Rejects prefix ≠ `0x04`, `x ≥ p` or
  `y ≥ p` (both `be_lt(..., P_BE)` checks), and off-curve points
  (`on_curve_m` computes `y² == x³ − 3x + b` via a branchless aggregate compare).
  All three reject reasons are present and the `test-p256-c99` reject-path
  assertion exercises each. Complete.
- **`encode_point` (lines 322–335).** Rejects the point at infinity via the
  `znz == 0` (Z all-limbs-zero) check before inverting Z, returning −1 — so
  `P + (−P)` in `_point_add`/`_hash_to_curve` fails closed. Correct.
- **`_point_decompress` (lines 796–830).** Rejects prefix ∉ {0x02, 0x03} and
  `x ≥ p`; computes `gx = x³ − 3x + b`, takes `sqrt = gx^((p+1)/4)` (valid since
  `p ≡ 3 mod 4`, verified `p % 4 = 3`), and — critically — **verifies
  `y² == gx`** (lines 811–816) before accepting, which rejects non-residue
  right-hand sides (for which the `(p+1)/4` power is not a real square root) and
  covers `gx == 0` trivially. The parity fixup (`y = p − y` when
  `y_be[31] & 1 != prefix & 1`) is applied only after the residue check.
  Correct and complete — this is the one place a naive decompressor would accept
  an off-curve `x`, and it does not.
- **`_point_compress` (lines 787–794).** Decodes+validates the full point first,
  then emits `0x02 | (Y_lsb)`. Round-trips with decompress. Correct.

### 4.3 hash-to-curve / SSWU / expand_message_xmd

- **`expand_message_xmd` (lines 568–628).** Enforces all four RFC 9380 §5.3.1
  bounds — `outlen == 0`, `ell > 255`, `outlen > 65535`, `dstlen > 255` — up
  front (line 575). The `b0` transcript is `Z_pad(64) || msg || I2OSP(outlen,2)
  || 0x00 || DST || I2OSP(dstlen,1)`, assembled in a `small[512]` stack buffer
  when `pre_len ≤ 512` else a heap buffer (**NULL-checked**, line 588; scrubbed +
  freed, line 601). The `bi` chain uses
  `in[32 + 1 + 255 + 1] = in[289]`, and the maximal write is
  `32 + 1 + dstlen(≤255) + 1 = 289` — **exactly** the declared size (verified
  arithmetically). No overflow, no unchecked allocation, and the b0/bi layout
  matches the RFC. The `size_t` length math (`pre_len = 64 + msglen + 2 + 1 +
  dstlen + 1`) is not overflow-guarded, but the four bounds cap `dstlen ≤ 255`
  and `outlen ≤ 65535`, and `msglen` near `SIZE_MAX` is unallocatable — the same
  theoretical, practically-unreachable posture the C99 audit rates Info; no
  in-tree caller approaches it. Noted, not a confirmed finding.
- **`sswu_map` (lines 659–714).** Simplified SSWU (RFC 9380 §6.6.2), Z = −10,
  A = −3. The square-branch selection is `e2 = fe_is_square_mask(gx1)` then
  `x_out = CMOV(x2, x1, e2)` / `t = CMOV(gx2, gx1, e2)` — matching the RFC's
  `x = CMOV(x2, x1, is_square(gx1))`. `fe_is_square_mask` is a branchless
  Legendre `a^((p−1)/2) == 1` aggregate compare returning an all-ones/all-zero
  mask; the `inv0(0) → 0` case is handled by `fe_inv` + the `e1` cmov to `C2`.
  The sign fixup `y = CMOV(y, −y, sgn0(y) XOR sgn0(u))` uses `fe_sgn0` (parity of
  the canonical representative). Every selection is a mask-cmov — no branch on
  the secret `u`. Correct and constant-time.
- **`fe_from_be48` / `sc_from_be48`.** `val = hi(16B)·2²⁵⁶ + lo(32B)`; `hi·2²⁵⁶
  mod p` is computed as `mont_mul(hi, R²) = hi·R` (the plain value, since
  `hi·R·R⁻¹·R = hi·R`… i.e. `hi·2²⁵⁶ ≡ hi·R (mod p)`), added to the
  one-subtract-reduced `lo`. The reduction mask is the correct no-carry-term form
  (§4.1). Both the p-field and n-field variants check out.
- **`_hash_to_curve` (count = 2) / `_hash_to_scalar` (count = 1).** h2c expands
  96 = 2×48 bytes → two field elements → two SSWU images → complete `pt_add`
  (cofactor h = 1, so `clear_cofactor` is identity); h2s expands 48 = 1×L → one
  scalar via `sc_from_be48`. The counts match the RFC 9497 P256-SHA256
  ciphersuite (h2c RO count 2, HashToScalar count 1). Both scrub their uniform
  bytes + intermediate points/scalars on the success path.

### 4.4 OPRF layer — transcript byte-layouts, buffer sizes, and the DLEQ math

Every I2OSP length prefix, DST construction, and stack-buffer size was checked
against RFC 9497 and against the maximal write; **all buffer sizes are exactly
sufficient** (arithmetic below). No overflow, no unchecked allocation on any of
these paths.

- **`contextString` / DSTs.** `oprf_context` builds `"OPRFV1-" ‖ mode ‖
  "-P256-SHA256"` = 20 bytes with `mode` a raw byte between ASCII hyphens
  (RFC 9497 §3.1) — correct. `oprf_dst` prepends a prefix; the
  `"DeriveKeyPair"` DST is built with **no** trailing hyphen before the context
  (`oprf_dst(dst, "DeriveKeyPair", mode)` → `"DeriveKeyPair" ‖ "OPRFV1-"…`),
  matching the RFC 9497 §3.2.1 quirk that `DeriveKeyPair` alone omits the hyphen
  that `HashToGroup-`/`HashToScalar-`/`Seed-` carry. Verified prefix lengths:
  `DeriveKeyPair` = 13, `HashToGroup-` = 12, `HashToScalar-` = 13, `Seed-` = 5.
- **`_oprf_derive_key` buffer.** `dst[13 + 20] = dst[33]`, needed
  `len("DeriveKeyPair") + 20 = 33` — exact. `deriveInput = seed ‖
  I2OSP(len(info),2) ‖ info`, then a counter byte; `base = seedlen + 2 +
  infolen`, buffer `stackbuf[256]` used iff `base + 1 ≤ 256` else a NULL-checked
  heap `malloc(base+1)` (line 895). The counter loop runs `0..255` and rejects a
  zero scalar (`be_is_zero(sk)`), returning −1 only on the ~2⁻²⁰⁴⁸ exhaustion.
  `buf` scrubbed + freed on both paths. Correct.
- **`oprf_composites` buffers.** `st[2 + 33 + 2 + 5 + 20] = st[62]`, maximal
  write `2 + 33 + 2 + seed_dstlen(25) = 62` — **exact**. `ct[2 + 32 + 2 + 2 + 33
  + 2 + 33 + 9] = ct[115]`, maximal write sums to **115 exactly** (len2(seed)=2,
  seed=32, I2OSP(0,2)=2, len2(Ci)=2, Ci=33, len2(Di)=2, Di=33, "Composite"=9).
  `h2s_dst[13+20]=33` exact. The `seed`/`di` transcript matches RFC 9497 §2.2.1
  ComputeComposites with m = 1 and `i = 0`. Correct.
- **`oprf_challenge` buffer.** `tr[5*35 + 9] = tr[184]`, maximal write
  `5·(2 + 33) + 9 = 184` — **exact**. Five `len2 ‖ 33-byte element` blocks
  (`pk, M, Z, t2, t3`) then `"Challenge"` (9). Matches RFC 9497 §2.2.1. Correct.
- **`_oprf_finalize` buffer.** `total = 2 + inputlen + 2 + 33 + 8`;
  `stackbuf[512]` iff `total ≤ 512` else NULL-checked heap. Transcript
  `I2OSP(len(input),2) ‖ input ‖ I2OSP(33,2) ‖ compress(unblinded) ‖ "Finalize"`
  matches RFC 9497 §3.3.1. Buffer sizing correct; the only issues on this
  function are the §3.1/§3.2 zeroization gaps, not sizing.
- **`_voprf_prove` — `s = r − c·k mod n`.** `c·k` is computed in the mod-n
  Montgomery domain (`cm = c·R²`, `km = k·R²`, `ck = cm·km`, then
  `sc_mont_mul(ck, ck, one)` maps back to plain) and subtracted from `r` via
  `sc_sub_raw` (branchless add-n-on-borrow). The proof is `c ‖ s`. This matches
  the RFC 9497 §2.2.1 GenerateProof scalar arithmetic; `km`/`ck`/`rfe`/`sfe`/`&T`
  are all scrubbed. Correct.
- **`_voprf_verify` — recomputation via the public API.** Rebuilds
  `t2 = s·G + c·B` (via `_base_mul` + `_point_mul` on the decompressed `pk` +
  `_point_add`) and `t3 = s·M + c·Z`, recompresses both, re-derives the
  challenge `c2 = oprf_challenge(...)`, and accepts iff
  `determ_ct_memcmp(c2, c, 32) == 0`. This is the RFC 9497 §2.2.2 VerifyProof
  equation, and the CT compare on the final challenge is correct discipline (both
  operands are public here). The up-front `be_lt(c/s, N_BE)` + `be_is_zero(c/s)`
  gate is a fail-closed guard so the downstream `_base_mul`/`_point_mul`
  (which reject a zero/≥n scalar via `scalar_ok`) never surprise it — a legitimate
  proof has `c, s ∈ [1, n)` with overwhelming probability (`c = 0` or `s = 0`
  occurs at ~2⁻²⁵⁶), so this is not a soundness restriction. Correct.

### 4.5 Memory safety — allocations and success-path hygiene

Every `malloc` in the module is NULL-checked: `expand_message_xmd` (line 588),
`_oprf_derive_key` (895), `_oprf_finalize` (960). Each matching `free` is
preceded by a `determ_secure_zero` of the heap block. All stack buffers are sized
exactly to their maximal writes (§4.3/§4.4 arithmetic). The success paths of
every secret-bearing function scrub their secret locals via `determ_secure_zero`
(the module shipped after the §5.1 stack-wide rollout, so this is uniform) — the
`pt r` results in `_base_mul`/`_point_mul`/`_oprf_blind`/`_oprf_evaluate`, the
`&tmp` in the ladder, the `uniform`/`s` in h2s, the `uniform`/`q0`/`q1`/`r` in
h2c, the `am`/`acc` in inversion, and the `km`/`ck`/`rfe`/`sfe`/`&T` in prove.
`determ_secure_zero` is NULL-/zero-len-safe (per its header), so no scrub call
can itself fault. The only residual gaps are the three §3 error-path/scratch
items — no double-free, no use-after-free, no unchecked allocation, no
size overflow reachable by any in-tree caller.

---

## 5. Constant-Time Posture

Constant-time is the dimension the OpenSSL/RFC byte oracle cannot verify, and it
is the dimension this module handles cleanly. The secret inputs are: the scalar
in `_base_mul`/`_point_mul` (the ECDH/OPRF private multiplier), the `blind` in
`_oprf_blind`/`_oprf_finalize`, the OPRF server key `sk`, and the `msg` behind
hash-to-curve/hash-to-scalar (an OPRF input may be a user secret, per the
header). Per-mechanism:

- **The ladder (`pt_scalar_mul`).** Fixed 256 iterations, each executing one
  doubling + one addition + one `pt_cswap` unconditionally; the secret bit routes
  **only** through `fe_cswap`'s arithmetic mask (`0 − swap`). No secret-dependent
  branch, array index, or loop bound. The RCB complete formula means there is no
  exceptional-case branch to leak through either. This is the highest-value CT
  result and it is clean.
- **Field/scalar arithmetic.** `fe_add`/`fe_sub`/`fe_mont_mul`/`sc_*` are all
  branchless carry/borrow-mask code; the conditional subtracts are mask-selects
  (`use_s`), never `if`. No data-dependent memory access.
- **Inversions.** `fe_inv` (p−2), `determ_p256_scalar_inv_mod_n` (n−2), and
  `fe_pow_pub`/`fe_sqrt`/`fe_is_square_mask` (exponents (p+1)/4, (p−1)/2) all
  iterate a **public constant exponent**; the `if ((e[i] >> bit) & 1)` branch is
  on a public bit, data-independent of the base. Standard Fermat CT pattern.
- **SSWU (`sswu_map`).** Every selection is `fe_cmov` / `fe_is_square_mask` /
  `fe_is_zero_mask` / the `sgn0` mask — no branch on `u`. The one-time
  `if (!sswu_ready)` init is a public one-time flag. Clean even though `u` derives
  from a possibly-secret `msg`.
- **The OPRF/VOPRF transcript branches.** The `if (... != 0) return -1` checks in
  `_oprf_blind`/`_evaluate`/`_finalize`/`_voprf_prove`/`_voprf_verify` branch on
  encode/decode **validity outcomes**, not on secret values: a valid scalar × a
  valid on-curve point produces a non-infinity result deterministically (the
  infinity case has ~2⁻²⁵⁶ probability and is independent of *which* secret
  scalar was used), so these branch outcomes are effectively public. The
  `_voprf_verify` final compare routes through `determ_ct_memcmp` (public
  operands — discipline).
- **The DLEQ scalar math.** `s = r − c·k` runs entirely through the branchless
  `sc_mont_mul`/`sc_sub_raw`; `k` (`sk`) and `r` flow only through mask
  arithmetic.

**No secret-dependent branch, secret-indexed memory access, or short-circuiting
secret compare exists on any path in the module.** The residual data-dependent
control flow is exhaustively on public data: encoding validity, scalar-range
outcomes, the public message/DST lengths, the loop counters, and the one-time
init flags — the same justified-residual class as the rest of the stack
(`ConstantTimeInventory.md` §4.1). The `p256-base-mul` (secret = scalar),
`p256-h2c` (secret = msg), and `p256-sc-mul` (secret = both operands)
`determ ct-timing-probe` targets registered in tranche 3 are the empirical
counterpart; first measured runs are clean (max |t| < 1.5 at smoke sample sizes,
per `src/crypto/p256/README.md`). The formal §3.12 dudect/ctgrind sweep over
these targets is the tracked follow-up (`ConstantTimeInventory.md` §5); this
source-level review is its precondition and it passes.

---

## 6. Residual Recommendations

1. **Close the §3.1 error-path zeroization gap in `_oprf_finalize`**
   (Low) — scrub `inv` before the `oprf_load33` return (the live leak); ideally
   also cover the dead `oprf_store33` return via a single `goto cleanup` that
   scrubs `inv` + `&r` unconditionally. This is the one actionable item; it
   removes the leak of `blind⁻¹` on the malformed-`eval33` path.
2. **Optionally scrub the §3.2/§3.3 intermediates** (`p`/`n33` in finalize, `t`
   in scalar inversion) for uniformity with the module's own success-path
   discipline, or document the caller-owns-the-output rationale for `t`. Info.
3. **Add the boundary test vectors the current grid omits** (aligned with the
   §1.1(3) blind spot): an `expand_message_xmd` case at `dstlen = 255` and one at
   the `outlen = 8160` / `ell = 255` ceiling (max stack/`bi` write); an
   `_oprf_finalize` / `oprf_composites` case with a large `input` that forces the
   heap branch; and a `_point_decompress` negative case on an `x` whose
   `gx = x³ − 3x + b` is a non-residue (asserts the §4.2 `y² == gx` reject fires).
   These would convert the §4 boundary arguments from "argued" to
   "regression-tested".
4. **Run the §3.12 dudect/ctgrind sweep** on the three registered probe targets
   to promote the §5 source-level CT verdict to a measured one, and add the
   module's per-mechanism rows to `ConstantTimeInventory.md` (the tracked §3.12
   follow-up noted in the module README).

None of these changes the correctness or CT verdict — the field/point/SSWU/OPRF
math is byte-exact to OpenSSL and the RFC vectors over the validated grid and
constant-time at the source level. Item 1 is the only defense-in-depth fix with a
concrete (if secondary-disclosure-gated) exposure; the rest are hardening.
