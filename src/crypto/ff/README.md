# `src/crypto/ff/` — finite-field Bulletproofs stack over Z_p* (RFC 3526 MODP-3072)

Per-module provenance + audit README required by `docs/proofs/CRYPTO-C99-SPEC.md`
§3.16 (walked by `tools/operator_crypto_selftest.sh`). Module spec section:
CRYPTO-C99-SPEC §3.20. Status: **increment 1 of the v2.22 confidential-transaction
MODERN-profile backend** — the "large primes, not curves" amount-commitment group,
per the owner curve/group split (2026-07-05): FIPS profiles use the §3.19 P-256
Bulletproofs stack, MODERN profiles use this finite-field group. A Pedersen
commitment `C = g^v * h^r mod p` over the prime-order subgroup `G_q ⊂ Z_p*` — §3.20.
**ZERO consensus touch — purely additive, not wired into any chain call site**;
chain integration is a later, separately-reviewed, owner-gated step (see
`docs/proofs/ConfidentialTxIntegrationDesign.md`). Header under
`include/determ/crypto/ff/`.

## What this module implements

A Pedersen commitment binds a value `v` under a blinding factor `r`:

```
C = g^v * h^r mod p     (over the order-q subgroup G_q of Z_p*)
```

`g = 4` is a quadratic residue (hence an order-`q` generator of `G_q`); `h` is a
SECOND generator whose discrete log to `g` is unknown. *Binding* rests on the
finite-field discrete log: a second opening `(v',r') != (v,r)` would recover
`log_g(h)`. *Hiding* is information-theoretic: for uniform `r`, `C` is uniform over
`G_q` and reveals nothing about `v`.

`ffgroup.c` / `include/determ/crypto/ff/ffgroup.h`:

- `determ_ff_pedersen_generator_h(out384)` — the nothing-up-my-sleeve second
  generator `h` (raw 384-byte big-endian). Deterministic, in `G_q`, `h != 1`,
  `h != g`.
- `determ_ff_pedersen_commit(out384, v, r)` — `out384 = g^v * h^r mod p`. `v`, `r`
  are 384-byte big-endian scalars: `v in [0,q)` (`v == 0` allowed), `r in (0,q)`
  (`r == 0` rejected — no hiding). `-1` if `v >= q` or `r` is `0` / `>= q`.
- `determ_ff_pedersen_verify(commitment, v, r)` — the *opening* check: `0` iff
  `commitment == commit(v,r)`, `-1` otherwise.
- `determ_ff_pedersen_add(out384, c1, c2)` — the homomorphic sum
  `out384 = c1 * c2 mod p`, so `commit(v1,r1) (+) commit(v2,r2) == commit((v1+v2) mod
  q, (r1+r2) mod q)`. `-1` if an input is not a reduced element (`>= p`).

Wire convention: group elements AND scalars are 384-byte (3072-bit) BIG-ENDIAN.

## The group + generators

`p` is the **RFC 3526 group 15 (3072-bit MODP) safe prime**, an IETF-standard
nothing-up-my-sleeve prime (`p = 2^3072 - 2^3008 - 1 + 2^64*([2^2942 pi] +
1690314)`). It is reproduced from that published formula and **machine-verified
prime** (Miller-Rabin), with `q = (p-1)/2` **also prime** (safe prime), by
`tools/verify_ff_pedersen.py`. The order-`q` subgroup `G_q` is the set of quadratic
residues mod `p`.

- `g = 4` = `2^2`, a QR and therefore an order-`q` generator.
- `h = derive_h()` — hash-to-group: SHA-256 over the fixed DST
  `"DETERM-FF-PEDERSEN-MODP3072-H-v1"` (13 counter blocks → 416 bytes), reduced mod
  `p`, then SQUARED (mapping into the QR subgroup `G_q`). Squaring a non-`±1` value
  yields an order-`q` element; the derivation is pinned by a KAT. Because no party
  chose `h` by picking an exponent, no party knows `log_g(h)` — the binding
  assumption.

The group constants (`p`, `q`, the Montgomery `n' = -p^{-1} mod 2^32` and
`R^2 mod p`, and `h`) are **machine-generated** into `src/crypto/ff/ff_params.h` by
`tools/verify_ff_pedersen.py emit-params` (zero transcription risk on the 96-limb
arrays).

## Arithmetic + provenance

**Portable C99 bignum — 32-bit-limb CIOS Montgomery multiplication** (Koç, Acar,
Kaliski, "Analyzing and Comparing Montgomery Multiplication Algorithms"), 96 limbs
for the 3072-bit modulus. Uses only `uint64_t` intermediates — **no `__int128`, no
compiler intrinsics** — so it builds byte-identically on MSVC and GCC/MinGW. The
commitment is `modmul(modexp(g, v), modexp(h, r))`, with `modexp` a straightforward
square-and-multiply over the Montgomery domain. This module introduces the bignum;
its correctness is established by the byte-exact dual oracle (below), not by an
external EC library.

C99, ~180 LOC (bignum + Pedersen), Determ-original.

## Standards cited

- **RFC 3526** — More Modular Exponential (MODP) Diffie-Hellman groups for IKE (the
  group 15 / 3072-bit safe prime `p`).
- **Pedersen (1991)** — "Non-Interactive and Information-Theoretic Secure Verifiable
  Secret Sharing" (CRYPTO '91), the commitment scheme.
- **Koç–Acar–Kaliski (1996)** — the CIOS Montgomery multiplication method.

## Validation evidence

`determ test-ff-pedersen-c99` (4 assertions):

1. **H generator** — deterministic across calls, non-zero, `!= 1`.
2. **commit correctness** — `commit → verify` accepts a correct opening; a wrong `v`
   and a wrong `r` each reject.
3. **additive homomorphism** — `commit(v1,r1) (+) commit(v2,r2) == commit(v1+v2,
   r1+r2)` (small values, no q-wrap).
4. **input validation** — `r == 0`, `v >= q`, and `r >= q` each reject.

**§3.13 dual-oracle byte-frozen corpus** — `tools/vectors/ff_pedersen.json` (6
vectors: the `h` KAT, four `commit`s, and a `homomorphism` whose scalars force a
**mod-q wraparound** in `v1+v2` and `r1+r2`), wired into BOTH gate halves:
`determ test-c99-vectors` recomputes each through the shipped C, and
`tools/test_c99_vector_files.sh` recomputes through the INDEPENDENT from-scratch
Python (`tools/verify_ff_pedersen.py`), which uses **Python's native arbitrary-
precision integers** as the reference arithmetic and self-checks the safe prime +
subgroup membership before writing. A bug in the C bignum — not just a corrupted
vector — turns the corpus RED, because the C and Python arithmetics are independent.
The mod-q wraparound vector exercises full-width (~3071-bit) exponents.

## Constant-time / hygiene posture

- **`modexp` is now CONSTANT-TIME in the exponent (owner-authorized 2026-07-06).** The
  exponentiation is a fixed 4-bit-window square-and-multiply with a **branchless** 16-entry
  table select (the whole table is scanned every window and blended by a constant-time
  equality mask `ff_ct_eq`) — no branch on secret exponent bits, no secret-indexed memory
  access. The base is public (every caller exponentiates a public generator `g`/`h`/`G_i`/
  `H_i` by a secret scalar), so the table build leaks nothing. The Montgomery conditional
  subtraction (`montmul_c`) is likewise a **branchless masked blend**, not a data-dependent
  branch. The rewrite is **byte-output-invariant** — all 40 ff_* dual-oracle corpus vectors
  recompute byte-equal — and an independent adversarial audit confirmed the CT property
  (no secret branch / no secret-indexed access) + the masked-select correctness. Source-
  level CT (the standard codebase assumption, cf. `p256.c` `fe_cmov`); the empirical
  `ct-timing-probe` demonstration is a documented follow-up (the ~tens-of-ms 3072-bit op
  needs an operator-set small `--samples`). Windowing is also a modest perf win (~16% fewer
  Montgomery multiplies vs the old bit-serial square-and-multiply). This closes the
  amount-leak that `ConfidentialTxIntegrationDesign.md` (NC-4/L-4) flags as a hard
  prerequisite before any on-chain confidential-tx prover use.
- **`determ_ff_msm` / `determ_ff_vector_commit` zero-scalar skip: REMOVED (now
  constant-time, 2026-07-06).** The old `if (ff_is_zero(sl)) continue` / `if (!ff_is_zero
  (sl))` guards leaked which secret scalars are zero (in the range prover, the bits of the
  committed value); they are gone — the code always exponentiates (`base^0 = 1` contributes
  the identity, so it is byte-identical to skipping — all 40 ff_* corpus vectors, including
  the zero-entry ones, stay byte-equal). With this the **Z_p\* prover is constant-time for
  its own (honest) inputs**: no secret-value-dependent branch or memory access remains in
  the exponent path or the multi-exponentiation. The only residual branches are the
  `ff_ge(sl, q)` / point-validity rejects, which never fire for a prover's own honestly-
  generated scalars/points (the standard public-validity-rejection residual).
- **Cross-profile residual (a follow-up):** the §3.19 P-256 `determ_pedersen_msm` has the
  identical zero-scalar skip, but its CT fix is harder — the additive group identity `O`
  has no compressed encoding and is special-cased (an `acc_is_identity` flag), so a
  zero-scalar term (`0·P = O`) needs a constant-time identity-SELECT (don't fold `O` into
  the accumulator) rather than the finite-field no-op (`base^0 = 1`). Deferred.
- The size/perf cost of a 3072-bit finite-field group vs. a 256-bit curve
  (~10-12× larger elements, verify an order of magnitude slower) is the documented,
  owner-accepted trade for the "large primes, not curves" MODERN posture.

## Increments 2-8 (SHIPPED — the complete confidential-tx primitive set + end-to-end composition)

Built on the same bignum, mirroring §3.19 inc.2-4 (see `docs/proofs/CRYPTO-C99-SPEC.md`
§3.20 for the full treatment):

- **inc.2 — vector commit + MSM** (`ffgroup.c`): nothing-up-my-sleeve order-`q`
  generator families `G_i`/`H_i` (`determ_ff_gen`, hash-to-group + square), the vector
  commit `C = h^r·ΠG_i^{a_i}·ΠH_i^{b_i} mod p` (`determ_ff_vector_commit`), and the
  multi-exponentiation `ΠP_i^{s_i} mod p` (`determ_ff_msm`). Validated by
  `determ test-ff-pedersen-c99` (7 assertions) + `ff_pedersen.json` (14 vectors).
- **inc.3 — scalar field mod `q`** (`ffgroup.c`): the CIOS Montgomery core is
  parameterized by a `(modulus, R², n')` context (`CTX_P`/`CTX_Q`); mod-`p` routines
  stay byte-identical. `determ_ff_scalar_reduce`/`_add`/`_mul`/`_inv` + the Fiat-Shamir
  `determ_ff_hash_to_scalar`. Validated by `determ test-ff-scalar-c99` (5 assertions) +
  `ff_scalar.json` (11 vectors, `tools/verify_ff_scalar.py`).
- **inc.4 — Bulletproofs IPA** (`ffipa.c`): `determ_ff_ipa_commit`/`_prove`/`_verify`,
  a `2·log2(n)`-element inner-product argument, the log-size core the range proof
  reduces to. Validated by `determ test-ff-ipa-c99` + `ff_ipa.json`
  (`tools/verify_ff_ipa.py`; the C proof bytes match the Python byte-for-byte).
- **inc.5 — single-value range proof** (`ffrangeproof.c`): `determ_ff_rangeproof_prove`/
  `_verify` — proves `v ∈ [0,2^n)` in `2·log2(n)+O(1)` elements (the MODERN confidential-tx
  amount range). `V = g^v·h^gamma`; A/S bit commits; t-poly T1/T2; IPA over the y-rescaled
  h. Validated by `determ test-ff-rangeproof-c99` + `ff_rangeproof.json`
  (`tools/verify_ff_rangeproof.py`; C V+proof match byte-for-byte); an independent
  soundness audit re-derived δ/Check-1/Check-2 from Bünz et al. §4.2 and confirmed
  `t0 = δ(y,z)+z²·v`. Also adds `determ_ff_scalar_sub` to the inc.3 scalar field.
- **inc.6 — aggregated range proof** (`ffrangeproof.c`): `determ_ff_agg_rangeproof_prove`/
  `_verify` — m values in ONE proof of size `2·log2(m·n)+O(1)` (the confidential-tx batch
  range). Value j's `2^n` slot scaled `z^(2+j)`; `m=1` recovers the single-value proof.
  Transcript `DETERM-FF-BP-AGGRANGE-v1`. Validated by `determ test-ff-agg-rangeproof-c99`
  + `ff_aggrangeproof.json`; an independent audit re-derived the aggregation from Bünz et
  al. §4.3 and confirmed an out-of-range value rejects in every batch position.
- **inc.7 — confidential-tx balance proof** (`ffbalance.c`): `determ_ff_balance_excess`/
  `_prove`/`_verify` — proves `Σv_in = Σv_out + fee` without revealing amounts (the
  amount-conservation half; the range proofs are the no-inflation half). The excess
  `E = ΠC_in·ΠC_out^{-1}·g^{-fee}` (inverses are scalar negations in the exponent, so one
  `determ_ff_msm`, no group inverse) is proven to open to zero via a Schnorr PoK `E=h^x`.
  Built on the public inc.1-3 API only — no sealed-code change. Validated by
  `determ test-ff-balance-c99` + `ff_balance.json` (`tools/verify_ff_balance.py`).
- **inc.8 — end-to-end confidential-tx composition** (`determ test-ff-confidential-tx-c99`,
  a structural test — NOT a new primitive): composes a per-output inc.5 range proof + the
  inc.7 balance proof into one confidential transaction over the PUBLIC APIs only, and
  pins the composition identity `V_j == C_out[j]` (a range proof's value commitment IS its
  tx output commitment — both `g=4`,`h`, so a cross-primitive generator mismatch turns it
  RED) plus the division of labour (balance catches inflation, range catches an
  out-of-range amount). Mirror: `tools/verify_ff_confidential_tx.py`.

Full soundness accounting for inc.1-6: `docs/proofs/FiniteFieldBulletproofsSoundness.md`.

## Known limitations / future work

- **Confidential-tx primitive set COMPLETE + composed end-to-end (inc.1-8).** Remaining on
  this backend: a
  group-abstraction layer so P-256 (§3.19) and Z_p* (§3.20) share ONE Bulletproofs
  prover/verifier (avoids the two parallel implementations), then confidential-tx chain
  integration (owner-gated).
- **No constant-time modexp** — the owner-gated hardening step (see the CT posture).
- **Library only — not yet a chain consensus or wallet primitive.** Chain
  integration (confidential transactions) is a later, separately-reviewed,
  consensus-critical step.
