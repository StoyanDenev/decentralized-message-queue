# `src/crypto/pedersen/` — Pedersen commitment + Bulletproofs IPA over NIST P-256

Per-module provenance + audit README required by `docs/proofs/CRYPTO-C99-SPEC.md`
§3.16 (walked by `tools/operator_crypto_selftest.sh`). Module spec section:
CRYPTO-C99-SPEC §3.19. Status: **increments 1-8 of
the owner-authorized range-proof / confidential-transaction track** (authorized
2026-07-04, library-primitive-first). A Pedersen commitment `C = v*G + r*H` over
NIST P-256 (inc.1), the vector commit `C = r*H + Σ(a_i*G_i + b_i*H_i)` (inc.2), the
general multi-scalar multiplication `Σ s_i*P_i` (inc.3), the **Bulletproofs
inner-product argument** `P = <a,g> + <b,h> + <a,b>*u` in `2*log2(n)` points (inc.4),
the **single-value range proof** `v ∈ [0,2^n)` (inc.5), the **aggregated range proof**
(inc.6), and the **confidential-tx balance proof** — a Schnorr PoK that the excess
`E = Σ C_in − Σ C_out − fee*G` opens to zero (`E = x*H`, amount conservation; inc.7,
`balance.c`) — §3.19. This is the complete confidential-tx primitive set for the
FIPS profile, symmetric with the MODERN-profile §3.20 `Z_p*` stack. **ZERO consensus
touch — purely additive, not wired into any chain call site**; chain/wallet integration
is a later, separately-reviewed step. Headers under `include/determ/crypto/pedersen/`.

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

**Increment 4 — the Bulletproofs inner-product argument (`ipa.c` /
`include/determ/crypto/pedersen/ipa.h`):**

A logarithmic-size proof of knowledge of two length-`n` vectors `a`, `b` behind the
commitment `P = <a,g> + <b,h> + <a,b>*u`, where `g`/`h` are the inc.2 generator
families and `u` is a fixed independent generator. The proof is `2*log2(n)` group
points + 2 final scalars, made **non-interactive** by a deterministic Fiat-Shamir
transcript.

- `determ_ipa_proof_len(n)` — the exact proof size in bytes: `66*log2(n) + 64`
  (`2*log2(n)` compressed 33-byte points + two 32-byte scalars). Returns `0` for
  `n` not a power of two, `n > DETERM_IPA_MAX_N` (256), or `n < 1`.
- `determ_ipa_commit(out33, a, b, n)` — forms `P = <a,g> + <b,h> + <a,b>*u` (the
  statement the proof is about), via `determ_pedersen_msm` over the concatenated
  generator/scalar lists.
- `determ_ipa_prove(proof, a, b, P33, n)` — emits the proof. Each round splits the
  vectors in half, commits the cross-terms `L = <a_lo,g_hi> + <b_hi,h_lo> +
  <a_lo,b_hi>*u` and `R` (symmetric), derives the Fiat-Shamir challenge `x` by
  hashing the running transcript, then folds `a' = x*a_lo + x⁻¹*a_hi`,
  `b' = x⁻¹*b_lo + x*b_hi`, `g' = x⁻¹*g_lo + x*g_hi`, `h' = x*h_lo + x⁻¹*h_hi` and
  recurses. The loop invariant is `P' = <a',g'> + <b',h'> + <a',b'>*u = x²*L + P +
  x⁻²*R` — the decisive algebraic oracle the tests pin at every round.
- `determ_ipa_verify(P33, proof, n)` — replays the same transcript to recover each
  `x`, updates `P' = x²*L + P + x⁻²*R` (`msm([L, P', R], [x², 1, x⁻²])`), and checks
  the final `P'` equals `a_f*g_0 + b_f*h_0 + (a_f*b_f)*u`. Fail-**closed**: a
  malformed `L`/`R`, a wrong `P`, or a tampered scalar yields a mismatched final
  point and rejects.

The transcript is domain-separated by the label `DETERM-BP-IPA-v1`, seeded with
`compress(P)`, `compress(u)`, and `n` as a 4-byte big-endian integer; challenges
come from `hash_to_scalar` under a fixed challenge-DST, with a zero challenge
rejected and re-absorbed. Everything reduces to `determ_pedersen_msm` — the module
adds NO new group arithmetic. `sc_add` (mod-`n` scalar addition, used for the folds)
is the one new scalar op: a 33-byte big-endian add + one conditional subtract of the
order. The IPA also exposes **generator-supplied** variants
`determ_ipa_prove_gens` / `_verify_gens` (the fixed-generator forms are thin
wrappers over them); the range proof below drives them with a `y`-rescaled `h`
family.

**Increment 5 — the Bulletproofs single-value range proof (`rangeproof.c` /
`include/determ/crypto/pedersen/rangeproof.h`):**

The whole point of the track: a proof that a Pedersen-committed value `v` lies in
**`[0, 2^n)`** WITHOUT revealing `v`, in `2*log2(n) + O(1)` group elements. The
value commitment is the inc.1 shape `V = v*g + gamma*h` (`g` = the P-256 base
point, `h` = the nothing-up-my-sleeve scalar generator `H`).

- `determ_rangeproof_proof_len(n)` — the proof size in bytes: `228 +
  determ_ipa_proof_len(n)` (the `A|S|T1|T2` points + the `taux|mu|t_hat` scalars +
  the inner IPA proof). `0` for `n` not a power of two or `n >
  DETERM_RANGEPROOF_MAX_BITS` (64).
- `determ_rangeproof_prove(V_out, proof, v, gamma, alpha, rho, tau1, tau2, sL, sR,
  n)` — writes `V = v*g + gamma*h` to `V_out[33]` and the proof. The prover
  randomness (`alpha`, `rho` blind `A`,`S`; `tau1`,`tau2` blind the polynomial
  commitments `T1`,`T2`; `sL`,`sR` are the blinding vectors) is caller-supplied for
  reproducibility (a real prover draws it from a CSPRNG). Internally: bit-decompose
  `v` into `a_L`/`a_R = a_L - 1^n`; commit `A = alpha*h + <a_L,g_i> + <a_R,h_i>`
  (inc.2 shape) and `S`; Fiat-Shamir challenges `y`,`z` (after `A`,`S`) and `x`
  (after `T1`,`T2`); form `l = l(x)`, `r = r(x)`, `t_hat = <l,r>`, `taux`, `mu`;
  then the **inc.4 IPA** proves `<l,r> = t_hat` over `(g_i, h'_i = y^-i*h_i, u)`.
- `determ_rangeproof_verify(V33, proof, n)` — two checks: the `t_hat` polynomial
  identity `t_hat*g + taux*h == z^2*V + delta(y,z)*g + x*T1 + x^2*T2` (with
  `delta = (z - z^2)*<1,y^n> - z^3*<1,2^n>`), and the IPA over the reconstructed
  `P = A + x*S - z*<1,g_i> + <z*y^n + z^2*2^n, h'_i> - mu*h`. Fail-**closed**: any
  identity intermediate or decode failure (a tampered `A/S/T1/T2/V`, a wrong `V`,
  or an out-of-range `v`) rejects.

The transcript is domain-separated by its own label `DETERM-BP-RANGE-v1` (distinct
from the IPA's), so the two never collide. The only new arithmetic beyond the
inc.1-4 primitives is the modular add/sub (`sc_add` / `sc_sub`); everything else is
`determ_pedersen_msm` + the P-256 point/scalar ops. `n` is a power of two ≤ 64 (a
value fits a `uint64_t`).

**Increment 6 — the AGGREGATED range proof (same `rangeproof.c`):**

Proves that `m` committed values `v_0..v_{m-1}` EACH lie in `[0, 2^n)` in ONE proof
of size `2*log2(m*n) + O(1)` group elements — a per-value saving over `m` separate
proofs.

- `determ_agg_rangeproof_proof_len(m, n)` — `228 + determ_ipa_proof_len(m*n)`; `0`
  unless `n ≤ 64`, `m ≥ 1`, and `m*n` is a power of two `≤ DETERM_IPA_MAX_N` (256).
- `determ_agg_rangeproof_prove(V_out, proof, v[], gamma[], alpha, rho, tau1, tau2,
  sL, sR, m, n)` — writes `m` compressed value commitments `V_j = v[j]*g +
  gamma[j]*h` to `V_out` (`m*33` bytes) and the proof. `gamma` is `m` scalars; `sL`,
  `sR` are each `m*n` scalars; the rest are single scalars.
- `determ_agg_rangeproof_verify(V, proof, m, n)` — verifies against the `m` value
  commitments; a single out-of-range value anywhere in the batch rejects.

The construction concatenates the `m` bit-vectors into a length-`m*n` `a_L`; value
`j`'s `2^n` slot is scaled by `z^(2+j)` (0-indexed, so `m=1` reduces exactly to the
single-value proof). The verifier's `t̂` identity gains the `Σ_j z^(2+j)·V_j` term
and `delta` the `Σ_j z^(3+j)` sum. The final `<l,r>=t̂` check is the same inc.4 IPA
over the `m*n`-wide generators. Own transcript label `DETERM-BP-AGGRANGE-v1`
(seeds `m`, `n`, all `V_j`). Reuses every single-value static — no new arithmetic.

**Increment 7 — the confidential-tx balance proof (`balance.c` /
`include/determ/crypto/pedersen/balance.h`):** the *amount-conservation* half of a
confidential transaction (the inc.5/6 range proofs are the *no-inflation* half). Proves
`Σ v_in = Σ v_out + fee` WITHOUT revealing any amount: a tx balances iff the excess
`E = Σ C_in − Σ C_out − fee*G` has no G-component, i.e. `E = x*H` for the blinding excess
`x = (Σ r_in − Σ r_out) mod n`; the prover gives a Schnorr PoK of discrete log base `H`
(`E = x*H`), which — since `log_G(H)` is unknown — forces the G-coefficient to zero.
The point subtractions are **scalar negations in the exponent** (`−C = (n−1)*C`,
`−fee*G = (n−fee)*G`) so the excess is one `determ_pedersen_msm` — **no point-negation
primitive and NO change to the sealed P-256 core**; the only local arithmetic is a
256-bit add-mod-n / negate-mod-n over the exported curve order. API
`determ_p256_balance_excess` / `_prove` / `_verify`; 65-byte proof = `compress(T)‖s`;
transcript DST `DETERM-P256-BALANCE-v1-challenge`.

**Increment 8 — the end-to-end confidential-tx composition (`determ
test-p256-confidential-tx-c99`, a structural test — NOT a new primitive):** composes a
per-output inc.5 range proof + the inc.7 balance proof into one confidential transaction
over the PUBLIC APIs only, and pins the composition identity `V_j == C_out[j]` (a range
proof's value commitment IS its tx output commitment — both `v*G + r*H`, so a
cross-primitive generator mismatch turns it RED) plus the division of labour (balance
catches inflation, range catches an out-of-range amount). Mirror:
`tools/verify_p256_confidential_tx.py`. This completes the FIPS-profile confidential-tx
primitive set, symmetric with the MODERN-profile §3.20 `Z_p*` stack.

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
the only new logic is its composition. C99, ~370 LOC total (`pedersen.c` ~185 +
`ipa.c` ~185), Determ-original. The inner-product argument (inc.4) likewise composes
entirely over `determ_pedersen_msm` + the P-256 scalar ops — the only new arithmetic
is `sc_add` (mod-`n` scalar addition), exhaustively fuzzed against a Python oracle
(200k+ cases incl. all order boundaries) in the adversarial audit.

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

Increment 4 (inner-product argument) — `determ test-bp-ipa-c99` (4 assertions):

15. **proof_len contract** — `determ_ipa_proof_len` returns 64/130/196/262 for
    n=1/2/4/8 and `0` for a non-power-of-two (`n=3`) and `n > MAX` (`n=512`).
16. **round-trip** — `commit → prove → verify` accepts for `n ∈ {1,2,4,8}` (n=1 is
    the 0-round degenerate `P == a·g_0 + b·h_0 + ab·u`).
17. **determinism** — proving the same statement twice yields byte-identical proofs
    (the Fiat-Shamir transcript is a pure function of the inputs).
18. **soundness** — a byte-flipped proof AND a proof verified against a wrong
    commitment (`commit` over a different `a`) both reject.

**§3.13 dual-oracle byte-frozen corpus (inc.4)** — `tools/vectors/bp_ipa.json` (2
vectors: `ipa` n=4 → 2 L/R rounds, `ipa` n=8 → 3), wired into BOTH gate halves
(`determ test-c99-vectors` C-side + `tools/test_c99_vector_files.sh` → `chk_bp_ipa`
→ `tools/verify_bp_ipa.py` Python-side). The Python reference is INDEPENDENT (its
own IPA over the `verify_pedersen.py` EC ladder) and self-checks the per-round
algebraic invariant + round-trip + wrong-P reject + tamper over `n ∈ {1,2,4,8,16}`
before emitting. It recomputes `P`, every `L`/`R`, and the final `a`/`b` scalars
byte-for-byte, so a bug in `ipa.c` — not just a corrupted vector — turns the corpus
RED. The adversarial audit independently re-derived the corpus from scratch and it
matched byte-for-byte.

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
