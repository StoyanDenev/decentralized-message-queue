# `src/crypto/pedersen/` — Pedersen commitment over NIST P-256

Per-module provenance + audit README required by `docs/proofs/CRYPTO-C99-SPEC.md`
§3.16 (walked by `tools/operator_crypto_selftest.sh`). Status: **increments 1-3 of
the owner-authorized range-proof / confidential-transaction track** (authorized
2026-07-04, library-primitive-first). A Pedersen commitment `C = v*G + r*H` over
NIST P-256 (inc.1), the vector commit `C = r*H + Σ(a_i*G_i + b_i*H_i)` (inc.2), and
the general multi-scalar multiplication `Σ s_i*P_i` (inc.3) — §3.19. **ZERO
consensus touch — purely additive, not wired into any chain call site**;
chain/wallet integration is a later, separately-reviewed step.
Headers under `include/determ/crypto/pedersen/`.

## What this module implements

A Pedersen commitment binds a value `v` under a blinding factor `r`:

```
C = v*G + r*H   (over the P-256 group, order n)
```

`G` is the standard P-256 base point; `H` is a SECOND generator whose discrete log
to `G` is unknown. *Binding* rests on that unknown log: finding `(v', r') != (v, r)`
with `v'*G + r'*H == C` would recover `log_G(H)`. *Hiding* is information-theoretic:
for a uniform `r`, `C` is uniform over the group and reveals nothing about `v`.

`pedersen.c` / `include/determ/crypto/pedersen/pedersen.h`:

- `determ_pedersen_generator_h(out65)` — the nothing-up-my-sleeve second generator
  `H` (SEC1 uncompressed). Deterministic, on-curve, never the identity, `H != G`.
- `determ_pedersen_commit(out33, v, r)` — `out33 = compress(v*G + r*H)`, SEC1
  compressed (33 bytes). `v` and `r` are 32-byte big-endian scalars `< n`. `v == 0`
  is allowed (commits to zero value: `C = r*H`); `r == 0` is REJECTED (a zero
  blinding factor gives no hiding). `-1` if `v >= n`, `r` is invalid (`0` or
  `>= n`), or (negligibly) the result is the point at infinity (`v*G == -r*H`, i.e.
  a known `log_G(H)`).
- `determ_pedersen_verify(commitment33, v, r)` — the *opening* check: `0` iff
  `commitment33 == commit(v, r)` (recompute, then a constant-time compare of the
  33-byte encoding), `-1` otherwise. The committer later reveals `(v, r)` and anyone
  confirms it matches `C`.
- `determ_pedersen_add(out33, c1_33, c2_33)` — the homomorphic sum
  `out33 = compress(decompress(c1) + decompress(c2))`. By the group law
  `commit(v1,r1) (+) commit(v2,r2) == commit(v1+v2, r1+r2)` (sums mod `n`). `-1` if
  either input fails to decode or the result is the identity (`c2 == -c1`, i.e. the
  commitments cancel).

**Increment 2 — the vector commitment (the Bulletproofs building block):**

- `determ_pedersen_gen(out65, index, which)` — two independent nothing-up-my-sleeve
  generator FAMILIES: `G_i` (`which=0`) and `H_i` (`which=1`), each derived as
  `hash_to_curve(IntToBytes(index, 4), "DETERM-PEDERSEN-VEC-{G,H}-P256_XMD:SHA-256_
  SSWU_RO_")`. The three domains (`-VEC-G-`, `-VEC-H-`, and the scalar `H`'s
  `-P256_` DST) are distinct, so no family member shares a known discrete log with
  `G`, the scalar `H`, or any other family member. `-1` iff `which > 1`.
- `determ_pedersen_vector_commit(out33, a, b, n, r)` — the Bulletproofs A/S-commitment
  shape `C = r*H + Σ_{i<n}(a_i*G_i + b_i*H_i)`, where `a` and `b` are each `n`
  consecutive 32-byte big-endian scalars (`< n_order`), `r` is the blinding factor
  (`0 < r < n_order`). A zero-scalar term is skipped; `n == 0` yields `C = r*H`.
  This is the shape a range proof commits its bit-vectors (`a_L`, `a_R`) against.

**Increment 3 — the general multi-scalar multiplication:**

- `determ_pedersen_msm(out33, scalars, points33, n)` — `Σ_{i<n} s_i*P_i` over
  ARBITRARY compressed points (unlike `vector_commit`, whose points are the fixed
  generator families) — the operation the Bulletproofs inner-product argument
  reduces its `L`/`R` commitments and generator-folding to; `vector_commit` is the
  special case of it over the `[H, G_i, H_i]` list. Because the sum MAY legitimately
  be the group identity (which has no 33-byte SEC1 encoding), the return is 3-way:
  `0` = success (`out33` = the sum), `1` = the sum is the identity (`out33`
  untouched; `n == 0` returns `1`), `-1` = a scalar `>= n_order` or a point fails to
  decode. A zero-scalar term is skipped.

Wire convention (inherited from the P-256 module): scalars are 32-byte BIG-ENDIAN
(`< n`); commitments are 33-byte SEC1 COMPRESSED points.

## Provenance + construction

**Pure composition over the §3.8c P-256 primitives** — this module introduces NO
new field or group arithmetic of its own. Every operation is a call into the
already-validated P-256 API (`include/determ/crypto/p256/p256.h`):

- `H = hash_to_curve(MSG, DST)` via the RFC 9380 suite `P256_XMD:SHA-256_SSWU_RO_`
  (`determ_p256_hash_to_curve`), with the fixed nothing-up-my-sleeve inputs
  - `MSG = "Determ Pedersen generator H over NIST P-256 v1"`
  - `DST = "DETERM-PEDERSEN-P256_XMD:SHA-256_SSWU_RO_"`

  The message states its purpose in plain ASCII; the DST follows the RFC 9380
  suite-ID convention so `H` lands in a domain distinct from any OPRF / other
  hash-to-curve use of the same curve. Changing either byte changes `H` — which is
  why the compressed `H` is pinned by a KAT in the test. Because no party chose `H`
  by picking a scalar, no party knows `log_G(H)` — that unknown discrete log is
  exactly the binding assumption.
- `v*G` via `determ_p256_base_mul`, `r*H` via `determ_p256_point_mul`, the sum via
  `determ_p256_point_add` (the exception-free Renes–Costello–Batina complete
  addition formulas), and the wire encode/decode via
  `determ_p256_point_compress` / `_decompress`.

The P-256 primitives are each already validated byte-equal vs OpenSSL EC
(`determ test-p256-c99`) or against the RFC 9380 appendix vectors
(`determ test-p256-h2c-c99`), so the correctness of the arithmetic is inherited;
the only new logic is its composition. C99, ~185 LOC, Determ-original.

## Standards cited

- **RFC 9380** — Hashing to Elliptic Curves (`P256_XMD:SHA-256_SSWU_RO_`, the
  derivation of the second generator `H`).
- **FIPS 186** (with SEC 2 / SP 800-186) — the NIST P-256 (secp256r1) curve the
  commitments live over.
- **Pedersen (1991)** — "Non-Interactive and Information-Theoretic Secure
  Verifiable Secret Sharing" (CRYPTO '91), the commitment scheme itself.

## Validation evidence

`determ test-pedersen-c99` (14 assertions). These gates pin the COMPOSITION — the
underlying P-256 arithmetic is already gated byte-equal vs OpenSSL / RFC 9380:

1. **`H` generator** — on-curve (`determ_p256_point_check`), deterministic across
   calls, and `H != G`.
2. **`H` KAT** — compressed `H` byte-equals the pinned value
   `0235527ee68afadb08b77415a8b00cc314abb1fd526451508271ee6c441ae0ad55` (any DST/MSG
   byte change turns this RED).
3. **commit correctness** — `commit(v, r) == compress(v*G + r*H)` recomputed through
   the raw P-256 API (`base_mul` / `point_mul` / `point_add` / `point_compress`).
4. **`v == 0` path** — `commit(0, r) == r*H` (the zero-value branch).
5. **additive homomorphism** — `commit(v1,r1) (+) commit(v2,r2) == commit(v1+v2,
   r1+r2)` (the decisive algebraic gate).
6. **open/verify accept + reject** — a correct opening accepts; a wrong `v`, a wrong
   `r`, and a tampered `C` each reject.
7. **binding sanity** — `commit(v1, r) != commit(v2, r)` for `v1 != v2` under the
   same blinding.
8. **input validation** — `r == 0` rejected, `v >= n` rejected, and a non-decodable
   commitment fed to `add` rejected.

Increment 2 (vector commitment):

9. **vector generators** — `gen(i, which)` on-curve, deterministic, the four
   `G_0,G_1,H_0,H_1` mutually distinct and distinct from `G` and the scalar `H`, and
   `which > 1` rejects.
10. **vector_commit correctness** — `vector_commit(a,b,n,r) == r*H + Σ(a_i*G_i +
    b_i*H_i)` recomputed term-by-term through the raw P-256 API (pins the formula AND
    the `a_i↔G_i` / `b_i↔H_i` family pairing).
11. **vector homomorphism + edges** — `vc(a1,b1,r1) (+) vc(a2,b2,r2) == vc(a1+a2,
    b1+b2, r1+r2)`; `n == 0 ⇒ C = r*H`; a zero vector entry is skipped correctly; and
    `r == 0` rejects.

Increment 3 (general MSM):

12. **msm correctness** — `msm([3,5],[G_0,G_1]) == 3*G_0 + 5*G_1` recomputed via the
    raw API, AND `vector_commit(a,b,2,r) == msm([r,a_0,a_1,b_0,b_1],[H,G_0,G_1,H_0,H_1])`
    — a non-circular cross-check of both functions through independent code paths.
13. **msm identity + skip** — `msm([1,n-1],[G_0,G_0])` returns the identity (rc 1,
    since `(n-1)*G_0 == -G_0`); a zero-scalar term is skipped; `n == 0` returns the
    identity.
14. **msm rejects** — a scalar `= n_order` and a non-decodable point (bad SEC1 prefix)
    each return `-1`.

**§3.13 dual-oracle byte-frozen corpus** — `tools/vectors/pedersen.json` (14 vectors),
wired into BOTH gate halves: `determ test-c99-vectors` recomputes each vector through
the shipped C impl, and `tools/test_c99_vector_files.sh` recomputes through an
INDEPENDENT from-scratch Python (`tools/verify_pedersen.py` — its own P-256 EC ladder
+ RFC 9380 hash-to-curve, self-checked against the C-pinned `H` KAT before write). The
corpus carries the `H` generator, four `commit` vectors, a `homomorphism` vector whose
scalars force a **mod-n wraparound** in `v1+v2` and `r1+r2`, five vector-generator
KATs (`gen`), a `vector_commit` (with a zero entry), and an `msm` + an
`msm`→identity vector. A bug in `pedersen.c` — not
just a corrupted vector — turns the corpus RED, because the C and Python
implementations are independent.

## Constant-time / hygiene posture

- **Data-independent EXCEPT the documented zero-scalar branches.** In `commit()` the
  `scalar_is_zero(v)` shortcut (the `v == 0` value-commitment path) is the one
  secret-dependent branch; in `vector_commit()` the same predicate skips a zero
  `a_i`/`b_i` term. `scalar_is_zero` reads all 32 bytes (no short-circuit), but the
  branch on its result reveals whether that scalar is zero. This matters for a range
  prover: `vector_commit` over the SECRET bit-vectors `a_L`/`a_R` would leak the
  zero-positions via timing — such a caller needs a **constant-time multi-exp** (always
  computing `s*G_i` and conditionally selecting, or a Straus/Pippenger CT variant).
  That, plus removing `commit`'s `v == 0` branch, is the candidate hardening for the
  dedicated CT review.
- **The heavy lifting is inherited constant-time.** The secret-scalar multiplies
  (`base_mul`, `point_mul`) run the P-256 module's uniform double-and-add-always
  ladder with a branchless conditional swap — no secret-dependent branch or memory
  index. This module adds no new scalar arithmetic, so it inherits that posture.
- **`verify` compares only public data.** `determ_pedersen_verify` uses
  `determ_ct_memcmp` on the 33-byte encoding — both operands are public (the
  commitment is on the wire, the opening is being revealed), so the constant-time
  compare is hygiene, not a secret-dependent gate.
- A dedicated timing / side-channel review of the module (including the
  `scalar_is_zero` branch) is the separate owner-gated step, together with the P-256
  module's own CT-probe follow-up.

## Known limitations / future work

- **NOT a range proof.** These are the commitment primitives only (single value + the
  vector commit); the range proof / Bulletproof (showing the committed `v` lies in a
  valid range without revealing it) is the next increment on this track — it needs the
  inner-product argument, the polynomial commitments `T_1`/`T_2`, and the Fiat-Shamir
  transcript, none of which is here yet.
- **No constant-time multi-exp.** `vector_commit` skips zero-scalar terms (a
  data-dependent branch); a range prover over secret bit-vectors needs a CT multi-exp
  (see the CT posture above) — the owner-gated hardening step.
- **Library only — not yet a chain consensus or wallet primitive.** The module is
  additive with no in-tree call site; chain integration (confidential transactions)
  is a later, separately-reviewed, consensus-critical step.
- **CT review pending** — see the posture section: the `scalar_is_zero(v)` branch and
  a full timing audit are the remaining hardening before any production use.
