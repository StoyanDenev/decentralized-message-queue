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

- **NOT constant-time.** The `modexp` square-and-multiply branches on secret exponent
  bits, and the Montgomery conditional subtraction is data-dependent. This is the
  same posture as the §3.19 range prover and is the **owner-gated CT-hardening
  step** — and, per `ConfidentialTxIntegrationDesign.md` (NC-4/L-4), a hard
  requirement before any on-chain confidential-tx prover use, since a non-CT prover
  leaks the committed amount via timing.
- The size/perf cost of a 3072-bit finite-field group vs. a 256-bit curve
  (~10-12× larger elements, verify an order of magnitude slower) is the documented,
  owner-accepted trade for the "large primes, not curves" MODERN posture.

## Increments 2-4 (SHIPPED — the Bulletproofs core over this group)

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

## Known limitations / future work

- **NOT yet a range proof.** inc.1-4 give the commitment + vector commit + IPA core;
  the single-value + aggregated range proof over this group (mirroring §3.19 inc.5-6),
  behind a group-abstraction layer so P-256 and Z_p* share one prover, are the next
  increments on this backend.
- **No constant-time modexp** — the owner-gated hardening step (see the CT posture).
- **Library only — not yet a chain consensus or wallet primitive.** Chain
  integration (confidential transactions) is a later, separately-reviewed,
  consensus-critical step.
