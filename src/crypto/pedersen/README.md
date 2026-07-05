# `src/crypto/pedersen/` — Pedersen commitment over NIST P-256

Per-module provenance + audit README required by `docs/proofs/CRYPTO-C99-SPEC.md`
§3.16 (walked by `tools/operator_crypto_selftest.sh`). Status: **increment 1 of the
owner-authorized range-proof / confidential-transaction track** (authorized
2026-07-04, library-primitive-first). A Pedersen commitment `C = v*G + r*H` over
NIST P-256 (§3.19). **ZERO consensus touch — purely additive, not wired into any
chain call site**; chain/wallet integration is a later, separately-reviewed step.
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
the only new logic is its composition. C99, ~60 LOC, Determ-original.

## Standards cited

- **RFC 9380** — Hashing to Elliptic Curves (`P256_XMD:SHA-256_SSWU_RO_`, the
  derivation of the second generator `H`).
- **FIPS 186** (with SEC 2 / SP 800-186) — the NIST P-256 (secp256r1) curve the
  commitments live over.
- **Pedersen (1991)** — "Non-Interactive and Information-Theoretic Secure
  Verifiable Secret Sharing" (CRYPTO '91), the commitment scheme itself.

## Validation evidence

`determ test-pedersen-c99` (8 assertions). These gates pin the COMPOSITION — the
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

**§3.13 dual-oracle byte-frozen corpus** — `tools/vectors/pedersen.json`, wired into
BOTH gate halves: `determ test-c99-vectors` recomputes each vector through the
shipped C impl, and `tools/test_c99_vector_files.sh` recomputes through an
INDEPENDENT from-scratch Python (`tools/verify_pedersen.py` — its own P-256 EC ladder
+ RFC 9380 hash-to-curve, self-checked against the C-pinned `H` KAT before write). The
corpus carries the `H` generator, four `commit` vectors, and a `homomorphism` vector
whose scalars force a **mod-n wraparound** in `v1+v2` and `r1+r2` (exercising the
group-law reduction the small no-carry unit-test scalars do not). A bug in
`pedersen.c` — not just a corrupted vector — turns the corpus RED, because the C and
Python implementations are independent.

## Constant-time / hygiene posture

- **Data-independent EXCEPT one documented branch.** The single secret-dependent path
  is `scalar_is_zero(v)` in `commit()` — the `v == 0` value-commitment shortcut. It is
  noted honestly here rather than hidden: `scalar_is_zero` reads all 32 bytes (no
  short-circuit), but the branch on its result reveals whether the committed value is
  zero. For confidential-transaction use a caller committing to `v == 0` should be
  aware of this. Removing the branch (always computing `v*G` and adding, given a
  point-at-infinity-safe base multiply for `v == 0`) is a candidate hardening for the
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

- **NOT a range proof.** This is the commitment primitive only; a range proof /
  Bulletproof (showing the committed `v` lies in a valid range without revealing it)
  is the next increment on this track.
- **No vector / multi-value commitment form.** Only the single-value
  `C = v*G + r*H`; a multi-generator `C = Σ v_i*G_i + r*H` is not implemented (add if
  a consumer appears).
- **Library only — not yet a chain consensus or wallet primitive.** The module is
  additive with no in-tree call site; chain integration (confidential transactions)
  is a later, separately-reviewed, consensus-critical step.
- **CT review pending** — see the posture section: the `scalar_is_zero(v)` branch and
  a full timing audit are the remaining hardening before any production use.
