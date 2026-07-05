> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# PedersenCommitmentSoundness — Determ C99 Pedersen commitment over NIST P-256: binding / hiding / homomorphism + conformance accounting

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **C99-native Pedersen commitment** shipped in `src/crypto/pedersen/pedersen.c` (public API `include/determ/crypto/pedersen/pedersen.h`, CRYPTO-C99-SPEC.md §3.19). It answers two questions the individual test outputs do not answer on their own: (1) **what** the primitive computes, mapped onto the standard Pedersen construction over NIST P-256 and verified line-by-line against the source; and (2) **how much** the two validation legs — the structural/negative unit test (`determ test-pedersen-c99`) and the dual-oracle byte gate (both §3.13 halves over `tools/vectors/pedersen.json`) — jointly establish about the scheme's **binding**, **hiding**, **additive homomorphism**, and byte-exact **interop**, and where their reach stops.

The module is deliberately thin. It is written **entirely against the §3.8c P-256 module's PUBLIC API** — `base_mul` / `point_mul` / `point_add` / `hash_to_curve` / `point_compress` / `point_decompress` — introducing **no new field or group arithmetic of its own** (`pedersen.c:1-4`). Its correctness therefore composes on top of that layer's own validation (`test-p256-c99` OpenSSL EC parity + `test-p256-h2c-c99` RFC 9380 vectors) rather than re-deriving it; the only new logic is the composition `C = v·G + r·H`, which the homomorphism and open/verify gates pin structurally and `tools/vectors/pedersen.json` pins byte-for-byte.

## Scope

**In scope.** The exported operations, verified against `pedersen.c`:
- `determ_pedersen_generator_h` — the deterministic nothing-up-my-sleeve second generator `H`;
- `determ_pedersen_commit` — `C = v·G + r·H`, SEC1 compressed 33-byte output;
- `determ_pedersen_verify` — the opening check (recompute + constant-time compare);
- `determ_pedersen_add` — the homomorphic combination `decompress(c1) + decompress(c2)`;
- **(increment 2)** `determ_pedersen_gen` — the nothing-up-my-sleeve vector-generator families `G_i`/`H_i`; and `determ_pedersen_vector_commit` — `C = r·H + Σ(a_i·G_i + b_i·H_i)`, the Bulletproofs A/S-commitment shape.

This is **increments 1-2** of the range-proof / confidential-transaction track (owner-authorized 2026-07-04): **library-primitive-first, ZERO consensus touch** — additive, not wired into any chain call site (`pedersen.h:1-4`).

**Out of scope.**
- **Range proofs / Bulletproofs** — a later increment. A Pedersen commitment on its own says NOTHING about whether `v` lies in any valid range; that guarantee is not this primitive's job (see NC-1).
- **Multi-generator / vector commitments** (`v1·G1 + v2·G2 + … + r·H`) — this is the single-value form only (NC-4).
- **Any chain / wallet wiring** — no consensus, ledger, or wallet code path constructs or opens a commitment (NC-3).
- **Timing side channels** — the CT posture of the `scalar_is_zero(v)` branch is the separate owner-gated constant-time review step, same posture as every other §3 primitive (NC-2, L-4).

**Authoritative external sources.** Pedersen's 1991 unconditionally-hiding commitment scheme (Torben Pedersen, CRYPTO '91); the group is NIST **P-256** / secp256r1 (**FIPS 186-5** / SP 800-186); the second generator is derived by **RFC 9380** `P256_XMD:SHA-256_SSWU_RO_` hash-to-curve. Binding rests on the P-256 **discrete-log** hardness assumption (ECDLP) — assumed, not proved here (L-1).

Companion / trust-base documents: `docs/proofs/P256CryptoStackAudit.md` (the correctness + constant-time audit of the underlying P-256 field / RCB complete-addition / CT ladder / SSWU hash-to-curve — the forward-referenced reason the primitive calls under `commit`/`add` are themselves trustworthy); `docs/proofs/OprfConformanceMap.md` / `docs/proofs/VectorGateComposition.md` (the two-half §3.13 gate mechanics this document instantiates for the Pedersen corpus); `CRYPTO-C99-SPEC.md` §3.19 (design entry), §3.8c (the curve + hash-to-curve enablers), §3.13 (the dual-oracle vector gate); `docs/proofs/ConstantTimeInventory.md` / §3.12 (the timing boundary handed off in L-4).

---

## 1. The construction map

A Pedersen commitment binds a value `v` under a blinding factor `r`:

```
C = v·G + r·H        over the P-256 group of prime order n
```

where `G` is the standard P-256 base point (FIPS 186-5) and `H` is a **second generator whose discrete log to `G` is unknown**. `H` is derived by hashing a fixed public string onto the curve via RFC 9380 `P256_XMD:SHA-256_SSWU_RO_`, so **no party knows `log_G(H)`** — which is exactly the binding assumption.

**Wire convention** (inherited from the §3.8c P-256 module): scalars `v`, `r` are 32-byte **big-endian** integers `< n`; commitments are 33-byte **SEC1 compressed** points (`0x02`/`0x03` parity prefix ‖ X). `H` is exported as a 65-byte SEC1 uncompressed point (`0x04 ‖ X ‖ Y`).

### 1.1 The second generator H (nothing-up-my-sleeve)

`H = hash_to_curve(MSG, DST)` with the two fixed inputs (`pedersen.c:15-16`):

| Input | Exact source literal | Role |
|---|---|---|
| `PEDERSEN_H_MSG` | `"Determ Pedersen generator H over NIST P-256 v1"` | states the generator's purpose in plain ASCII |
| `PEDERSEN_H_DST` | `"DETERM-PEDERSEN-P256_XMD:SHA-256_SSWU_RO_"` | RFC 9380 suite-ID-shaped DST, landing `H` in a domain distinct from any OPRF/other h2c use of the same curve |

`determ_pedersen_generator_h` (`:18-23`) is a direct call to `determ_p256_hash_to_curve` over these bytes. Because the RFC 9380 random-oracle map never returns the identity and always returns an on-curve point (`p256.h:91-97`), `H` is by construction a well-formed non-identity curve point; that it is also `!= G` and reproducible is machine-checked (PC-1). Changing either input byte changes `H`, which is why the compressed-`H` KAT is pinned (PC-1).

### 1.2 commit — C = v·G + r·H

`determ_pedersen_commit(out33, v, r)` (`:34-56`), verified statement by statement:

1. `H = generator_h()` (`:38`).
2. `rH = r·H` via `determ_p256_point_mul(rH, r, H)` (`:42`). `point_mul` **rejects `r == 0` and `r >= n`** (`p256.h:50-55`) — so a zero or oversized blinding factor makes `commit` return `-1` before any point is formed. This is the enforcement of the header contract `0 < r < n` (`pedersen.h:48-49`).
3. Data-dependent split on `v` (`:44-53`):
   - `scalar_is_zero(v)` true → `C = rH` directly (`:46`). The `v == 0` value commitment is `C = r·H`; `base_mul` is skipped precisely because it would reject the zero scalar (`p256.h:44-46`). `scalar_is_zero` (`:28-32`) reads all 32 bytes with no short-circuit; the branch on its result is the one documented data-dependent path (NC-2 / L-4).
   - else → `vG = v·G` via `base_mul` (rejects `v >= n`), then `C = vG + rH` via `determ_p256_point_add` (`:51-52`). The RCB complete-addition formula handles `vG == rH` etc. uniformly; only the exact-inverse case `vG == -rH` yields the identity → `-1`.
4. `out33 = compress(C)` (`:55`).

So `commit` returns `-1` iff `v >= n`, `r` invalid (`0` or `>= n`), or (negligibly) `C` is the point at infinity — exactly the header contract (`pedersen.h:50-51`).

### 1.3 verify — the opening check

`determ_pedersen_verify(commitment33, v, r)` (`:58-66`) recomputes `commit(v, r)` and returns `0` iff it equals `commitment33` under a **constant-time** 33-byte compare (`determ_ct_memcmp`, `:65`). Both operands are public (the commitment is on the wire; the opening is being revealed), so the CT compare is hygiene, not a secret-dependent gate (`:62-64`). A malformed opening or a `commit` failure yields `-1`.

### 1.4 add — the homomorphic combination

`determ_pedersen_add(out33, c1, c2)` (`:68-75`): decompress both inputs, `sum = p1 + p2` via `point_add`, recompress. Returns `-1` if either input fails to decode **or** the result is the identity (`c2 == -c1`, i.e. the commitments cancel: `v1+v2 ≡ 0` AND `r1+r2 ≡ 0` mod `n`) (`pedersen.h:62-67`). By the group law this realizes `commit(v1,r1) (+) commit(v2,r2) == commit(v1+v2 mod n, r1+r2 mod n)`.

---

## 2. Soundness / conformance claims (PC-1 .. PC-10)

Each claim states the claim, the **evidence** (which `test-pedersen-c99` assertion, which `pedersen.json` vector, or which gate proves it), and honest caveats. The eight numbered assertions of `determ test-pedersen-c99` are at `src/main.cpp:13299-13388`; the six-vector corpus is `tools/vectors/pedersen.json`, consumed by both §3.13 halves.

### PC-1 — H is a deterministic, on-curve, non-identity second generator with H != G and a pinned byte identity

**Claim.** `determ_pedersen_generator_h` returns the same on-curve, non-identity point every call, distinct from `G`, whose compressed encoding is the frozen 33-byte KAT `0235527ee68afadb…1ae0ad55`.

**Evidence.** `test-pedersen-c99` assertion (1) (`main.cpp:13299-13310`): checks `hrc == 0`, `point_check(H) == 0` (on-curve), `H == H2` byte-for-byte across two independent calls (determinism), `H != G`, and the compressed KAT string-match. The **same** compressed-`H` KAT is independently pinned by the `h_generator` vector in `pedersen.json` and recomputed from scratch by both §3.13 halves: the C half (`main.cpp:14134-14138`) via `generator_h`+`compress`, and the Python half via `verify_pedersen.derive_h()` — an entirely separate RFC 9380 `expand_message_xmd` + simplified-SSWU + EC implementation (`verify_pedersen.py:36-111`) that `emit()` refuses to write unless its from-scratch derivation reproduces the C-pinned KAT (`:107-111`, `:157-160`).

**Caveat.** On-curve + non-identity are the properties a Pedersen `H` needs; "`log_G(H)` is unknown" is NOT machine-checkable — it is the RFC-9380-hash-to-curve provenance argument (L-1), the load-bearing assumption for binding (PC-2). That `H` is a *hash-to-curve output of a public string* (not an adversarially chosen point) is what the fixed `MSG`/`DST` + the reproducible KAT establish.

### PC-2 — Binding (computational, under ECDLP on P-256)

**Claim.** No efficient adversary can open one commitment `C` to two distinct message/blinding pairs `(v, r) != (v', r')` with `commit(v,r) == commit(v',r') == C`, unless it can compute `log_G(H)`.

**Argument (reduction).** Suppose `v·G + r·H == v'·G + r'·H` with `(v,r) != (v',r')`. Then `(v − v')·G == (r' − r)·H`. If `r' == r`, the left side is a nonzero multiple of `G` equal to `O`, impossible for `v != v'` with `v, v' < n` (so necessarily `r' != r`). With `r' != r`, invert `(r' − r)` mod the prime order `n` to get `log_G(H) = (v − v')·(r' − r)^{-1} mod n`. Producing a double-opening therefore **recovers `log_G(H)`**. Since `H = hash_to_curve(fixed public string)` is a public RFC 9380 output whose discrete log to `G` nobody knows, binding holds **computationally under ECDLP on P-256** (`pedersen.h:6-16`, `pedersen.c` header). This is **computational, not information-theoretic**, binding: an adversary that broke P-256 discrete log could equivocate.

**Evidence (structural witness).** `test-pedersen-c99` assertion (6) (`main.cpp:13367-13373`) confirms the *implemented* map is not degenerate: `commit(v1,r) != commit(v2,r)` for `v1 != v2` (same `r`) — i.e. distinct values under the same blinding give distinct commitments (a `commit` that collapsed values would be trivially non-binding). This is a **sanity witness** for the injectivity the algebra guarantees, NOT a proof of binding (which is the reduction above resting on L-1). No test can exhibit hardness of ECDLP.

**Caveat.** The reduction assumes `H`'s discrete log is genuinely unknown (PC-1 caveat / L-1). Binding is only as strong as ECDLP on P-256.

### PC-3 — Hiding (information-theoretic / perfect, for uniform r in [1, n))

**Claim.** For `r` drawn uniformly from `[1, n)`, the commitment `C = v·G + r·H` is uniformly distributed over the group generated by `H` and reveals nothing about `v` — perfect hiding.

**Argument.** `H` is a generator of the prime-order-`n` group, so as `r` ranges uniformly over the nonzero residues, `r·H` ranges (near-)uniformly over the nonzero group elements; `C = v·G + r·H` is then a uniform group element whose distribution is **independent of `v`** (adding the fixed `v·G` is a bijection on the group). Hence `C` carries no information about `v`: hiding is **information-theoretic**, holding against a computationally unbounded adversary — the standard Pedersen property (Pedersen '91). This is stronger than binding, which is only computational.

**Evidence + the r != 0 enforcement.** Hiding requires a genuinely random, **nonzero** blinding factor: `r == 0` gives `C = v·G`, which leaks `v` completely (it is a plain encoding of `v·G`). The implementation **rejects `r == 0`** — `point_mul(rH, r, H)` returns `-1` on the zero scalar (`pedersen.c:42`, `p256.h:50-55`), pinned by `test-pedersen-c99` assertion (7) (`main.cpp:13380`: `commit(v, zero) == -1`) and documented in the header (`pedersen.h:48-49`). The uniformity of `r` itself is the **caller's** responsibility (see caveat).

**Caveat.** The *scheme* is perfectly hiding **only if the caller supplies a uniform `r`**. The primitive does NOT sample `r` — it is a deterministic function of caller-supplied `(v, r)` (the test corpus uses fixed small `r` for byte-reproducibility, NOT uniform draws). A caller who reuses or biases `r` breaks hiding; the primitive can only enforce `r != 0`, not `r`'s distribution. Production callers must draw `r` from the CSPRNG.

### PC-4 — Additive homomorphism: commit(v1,r1) + commit(v2,r2) == commit(v1+v2, r1+r2) mod n

**Claim.** The group-law sum of two commitments is a commitment to the summed value under the summed blinding, with both sums taken **mod n**: `add(commit(v1,r1), commit(v2,r2)) == commit((v1+v2) mod n, (r1+r2) mod n)`.

**Evidence (two independent gates, covering both the no-carry and the reduction path).**
- **No-carry (small scalars):** `test-pedersen-c99` assertion (4) (`main.cpp:13338-13351`) commits `v1=5, r1=0x1122`, `v2=7, r2=0x3344`, and `v3=12, r3=0x4466` (chosen so `v1+v2` and `r1+r2` need **no** mod-n reduction), then checks `add(C1, C2) == C3` byte-for-byte. This is the decisive algebraic gate for the plain group law.
- **Mod-n wraparound:** the `homomorphism` vector in `pedersen.json` sets `v1 = n−2, r1 = n−1, v2 = 5, r2 = 5`, so `v1+v2 ≡ 3` and `r1+r2 ≡ 4` (mod n) both **wrap around** the order. `c3_hex` is the frozen `commit((v1+v2) mod n, (r1+r2) mod n)` (`verify_pedersen.py:177-188`). Both §3.13 halves recompute `add(commit(v1,r1), commit(v2,r2))` and match `c3_hex`: the C half (`main.cpp:14145-14155`) and the independent Python (`verify_pedersen.py:139-147`). This pins the reduction path assertion (4)'s no-carry inputs cannot reach.

**Caveat.** The commitment/add layer performs NO explicit modular reduction of `v1+v2` — the reduction is **inherent in the elliptic-curve group law** (the group has order `n`, so `(v1+v2)·G` is computed mod n by the curve). The wraparound vector's value is that it *witnesses* this inherent reduction is correct, not that the code contains a reduction step.

### PC-5 — Open/verify: correct openings accept; wrong value, wrong blinding, or tampered commitment reject

**Claim.** `verify(C, v, r) == 0` iff `C == commit(v, r)`; a wrong `v`, a wrong `r`, or a tampered `C` each reject.

**Evidence.** `test-pedersen-c99` assertion (5) (`main.cpp:13353-13365`): for `v=42, r=0xABCD`, `verify(C, v, r) == 0` (correct open accepts); `verify(C, v+1, r) != 0` (wrong value rejects); `verify(C, v, r^0x01) != 0` (wrong blinding rejects); `verify(C_tampered, v, r) != 0` (single-byte-flipped `C` rejects). The reject side is the property the accept-only `pedersen.json` `commit` vectors are structurally blind to — they only ever pin `commit(v,r) == c_hex`, never that a *wrong* opening fails.

**Caveat.** These are existence witnesses that the *implemented* reject paths fire on the *specific* tampers injected; they are not a proof over all malformed openings. Soundness of "wrong opening ⇒ reject" ultimately follows from PC-2 binding (a second valid opening would need `log_G(H)`).

### PC-6 — commit correctness: C == compress(v·G + r·H) via the raw P-256 API, incl. the v==0 path

**Claim.** `commit(v, r)` equals `compress(v·G + r·H)` computed through the raw P-256 primitives; and `commit(0, r)` equals `r·H`.

**Evidence.**
- **General path:** `test-pedersen-c99` assertion (2) (`main.cpp:13312-13325`): for `v=9, r=0x1234`, independently computes `vG = base_mul(v)`, `rH = point_mul(r, H)`, `sum = point_add(vG, rH)`, `Cref = compress(sum)` and checks `commit(v,r) == Cref` byte-for-byte. This pins that `commit` is exactly the claimed composition, not some other arrangement.
- **v==0 path:** assertion (3) (`main.cpp:13327-13336`): for `v=0, r=0x77`, checks `commit(0, r) == compress(point_mul(r, H))` — i.e. the zero-value branch yields `C = r·H`. The same `v=0, r=0x77` case is byte-frozen as the first `commit` vector in `pedersen.json` (`c_hex = 02b74944…99544a`) and recomputed by both §3.13 halves.
- **Four commit vectors** (`v=0`, `v=9`, `v=0xf4240`, `v=0xdeadbeef`) are byte-pinned in `pedersen.json` and recomputed against the frozen `c_hex` by the C half (`main.cpp:14139-14144`) and the independent Python `commit_hex` (`verify_pedersen.py:114-124`, `135-138`).

### PC-7 — Interop: dual-oracle byte-freeze, and the gate is NOT transposition-blind

**Claim.** Every frozen value in `pedersen.json` (the H KAT + the four commit vectors + the wraparound homomorphism) is recomputed and matched by **two implementations sharing zero source** — the shipped C99 (`main.cpp` `test-c99-vectors` `pedersen` branch, `:14129-14156`) and the independent from-scratch Python (`verify_pedersen.py`, its own `expand_message_xmd` + SSWU + EC ladder). A transposed construction `v·H + r·G` would produce different bytes and fail the gate.

**Evidence.** The §3.13 dual-oracle posture (`chk_pedersen` → `verify_pedersen.check_pedersen`, `tools/test_c99_vector_files.sh:1166-1176`): the file half (Python) recomputes each vector offline with no determ binary and compares to the frozen hex; the binary half (`determ test-c99-vectors`, run in `FAST=1`) drives the shipped C over the same bytes. Because the expected bytes come from an independent RFC 9380/EC re-derivation (not copied from the C), a bug shared *only by convention* is still caught; because `verify_pedersen.emit()` self-checks its `H` against the C-pinned KAT before writing (`:157-160`), the two oracles are cross-anchored. **Transposition non-blindness:** the adversarial audit confirmed `commit` computes `v·G + r·H` (not `v·H + r·G`) — the general-path assertion (2) reconstructs `base_mul(v)` (i.e. `v·G`) + `point_mul(r, H)` (i.e. `r·H`) and byte-matches, so a `G`/`H` transposition would diverge on the very first commit vector where `v != r`.

**Caveat.** Byte-exact conformance is over exactly these six frozen vectors (a fixed point set), not the input space (L-2). A wholesale self-consistent substitution of the whole corpus would survive recomputation by construction; what it defeats is only the free-text provenance, not the "C == Python oracle" soundness (the FB68 T-2 residual).

### PC-8 — Trust inheritance: the whole primitive is composition over already-gated P-256 primitives

**Claim.** `commit`/`verify`/`add`/`generator_h` add NO new field or group arithmetic; every arithmetic operation is a call into the §3.8c P-256 module, whose correctness is validated independently and byte-equal against OpenSSL EC + the RFC 9380 vectors.

**Evidence.** `pedersen.c` calls **only** `determ_p256_hash_to_curve`, `_point_mul`, `_base_mul`, `_point_add`, `_point_compress`, `_point_decompress` (verified: no other arithmetic appears in the file, `:1-75`). Each is validated by `determ test-p256-c99` (curve constants byte-equal OpenSSL `EC_GROUP`; `[k]G` byte-equal OpenSSL `EVP` over a scalar grid; on-curve accept/reject; scalar-validity gates) and `determ test-p256-h2c-c99` (the RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` appendix vectors + mod-n ops vs the OpenSSL BIGNUM oracle) — the audited subject of `docs/proofs/P256CryptoStackAudit.md`. Input-rejection at the Pedersen boundary is also inherited: `test-pedersen-c99` assertion (7) (`main.cpp:13376-13388`) confirms `r == 0` rejects (via `point_mul`), `v >= n` rejects (via `base_mul`, tested with `v = n` exactly), and a non-decodable commitment (bad SEC1 prefix `0x05`) makes `add` return `-1` (via `point_decompress`).

**Caveat.** This is a **forward-reference**, not a re-proof: that the underlying scalar-mult / point-add / SSWU are correct and constant-time is discharged in `P256CryptoStackAudit.md` + the OpenSSL parity tests, not here. The Pedersen gates give end-to-end cover only on the covered inputs (a primitive defect would diverge the frozen bytes — but only for those vectors, L-2).

### PC-9 — Increment 2: the vector-commitment generators are independent nothing-up-my-sleeve points

**Claim.** `determ_pedersen_gen(index, which)` yields, for `which ∈ {0,1}`, two generator FAMILIES `G_i`/`H_i` that are on-curve, deterministic, mutually distinct, and distinct from the base point `G` and the §3.19 scalar `H` — each with no known discrete-log relation to any of the others (the vector-Pedersen binding assumption).

**Evidence.** `G_i = hash_to_curve(IntToBytes(i,4), "DETERM-PEDERSEN-VEC-G-P256_XMD:SHA-256_SSWU_RO_")`, `H_i` the same with the `-VEC-H-` DST (`pedersen.c` `determ_pedersen_gen`). The three domains (`-VEC-G-`, `-VEC-H-`, and the increment-1 `-P256_` DST for the scalar `H`) are pairwise distinct RFC 9380 domain-separation tags, so the outputs are independent random-oracle images with unknown mutual dlog (same nothing-up-my-sleeve argument as PC-1/PC-2, now per-index). `test-pedersen-c99` assertion (8) checks on-curve (`point_check`), determinism (same index → same point), mutual distinctness of `G_0,G_1,H_0,H_1`, distinctness from `G` and the scalar `H`, and that `which > 1` returns `-1`. The exact bytes of five generators (`G_0,G_1,G_2,H_0,H_1`) are frozen in `pedersen.json` (`gen` vectors) and recomputed byte-for-byte by BOTH the C impl (`test-c99-vectors`) and the independent Python `derive_gen` (`verify_pedersen.py`).

**Caveat.** Independence rests on the RFC 9380 hash-to-curve behaving as a random oracle and on ECDLP (L-1), exactly as for `H`. The KAT freezes 5 of an unbounded family; the derivation is uniform in `index` so a per-index defect on an untested index would still diverge the (index-parameterised) recomputation.

### PC-10 — Increment 2: the vector commit computes `r*H + Σ(a_i*G_i + b_i*H_i)` and is vector-homomorphic

**Claim.** `determ_pedersen_vector_commit(a, b, n, r)` equals `r*H + Σ_{i<n}(a_i*G_i + b_i*H_i)` (the Bulletproofs A/S-commitment shape), and is additively homomorphic in the vectors: `vc(a1,b1,r1) (+) vc(a2,b2,r2) == vc(a1+a2, b1+b2, r1+r2)`.

**Evidence.** `test-pedersen-c99` assertion (9) recomputes `r*H + Σ(a_i*G_i + b_i*H_i)` term-by-term via the raw P-256 API (`point_mul` + `point_add`) and asserts byte-equality with `vector_commit`'s output — pinning both the formula AND the family pairing (`a_i` with `G_i = gen(i,0)`, `b_i` with `H_i = gen(i,1)`; a swap would diverge). Assertion (10) checks the vector homomorphism on no-carry small vectors. Assertion (11) checks the degenerate/edge behaviour: `n == 0 ⇒ C = r*H`, a zero vector entry is skipped correctly (`vc([0,5],[0,0],r) == r*H + 5*G_1`, recomputed), and `r == 0` is rejected. A `vector_commit` with a zero `b`-entry is additionally frozen in `pedersen.json` and recomputed by the independent Python `vector_commit_pt`. The homomorphism is the group law: `Σ a1_i*G_i + Σ a2_i*G_i = Σ(a1_i+a2_i)*G_i`, etc.

**Caveat.** The zero-scalar skip is a data-dependent branch on `a_i`/`b_i` (NC-2, extended). The homomorphism assertion uses no-carry vectors; the mod-n reduction is the same group-law argument as PC-4 and is not separately byte-pinned for the vector form. Binding of the vector commit reduces to the mutual-dlog-unknownness of the whole generator set (PC-9) under ECDLP — assumed, not proved (L-1).

---

## 3. What is NOT proven / non-claims (NC-1 .. NC-4)

- **NC-1 — This is NOT a range proof.** A Pedersen commitment reveals nothing about whether `v` lies in a valid range (e.g. `[0, 2^64)`), is non-negative, or is not an overflow value near `n`. Range enforcement (Bulletproofs or an equivalent) is the **next increment** and is entirely out of scope here. A committed `v` could be any scalar `< n`; the commitment binds and hides it but proves no predicate about it.
- **NC-2 — The `scalar_is_zero(v)` branch is a documented data-dependent branch on `v`.** `commit` branches on whether the value is zero (`pedersen.c:44`), taking the `C = r·H` path for a zero-value commitment. This is a data-dependent control-flow path on `v` (documented in the code comment `:26-27` and the README §CT posture). `scalar_is_zero` itself reads all 32 bytes without short-circuit, but the branch on its result is not constant-time in `v`. A timing-side-channel review is the **separate owner-gated CT step** — the same posture as every other §3 primitive (L-4); this document asserts **functional** correctness only, not timing.
- **NC-3 — Not a consensus or wallet primitive yet.** No Determ chain, ledger, or wallet code path constructs, stores, opens, or homomorphically combines a commitment. This is an additive **library primitive with no in-tree consumer** (`pedersen.h:1-4`). None of the binding/hiding/homomorphism claims here says anything about a chain-level confidential-transaction protocol — that is a later, separately-reviewed increment.
- **NC-4 — No inner-product argument / range-proof protocol yet.** Increment 2 (PC-9/PC-10) adds the two-family vector commit `r·H + Σ(a_i·G_i + b_i·H_i)` — the Bulletproofs A/S-commitment shape — but NOT the log-size inner-product argument, the polynomial commitments (`T_1`, `T_2`), the Fiat-Shamir transcript, or the range-proof protocol that binds them into a proof of `v ∈ [0, 2^n)`. Those are later increments. What is shipped is a *commitment* building block; it proves no range predicate (NC-1 stands).

---

## 4. Limits (L-1 .. L-4)

- **L-1 — Binding is not proven; it is assumed under ECDLP.** PC-2 reduces double-opening to computing `log_G(H)`; that `H`'s discrete log is genuinely unknown rests on `H` being a public RFC 9380 hash-to-curve output (PC-1) AND on P-256 discrete-log hardness. A break of ECDLP on P-256 breaks binding regardless of any byte-exactness here. This is the ambient EC assumption, assumed not proved.
- **L-2 — Bounded input set for byte-exact conformance.** PC-7/PC-9/PC-10 quantify over exactly the twelve frozen `pedersen.json` vectors (one `H` KAT, four commit inputs, one wraparound homomorphism, five generator KATs, one vector_commit). The structural tests (PC-3..PC-6, PC-9/PC-10 assertions (8)-(11)) widen coverage to fresh non-vector inputs but are not byte-pinned. Not exercised as frozen bytes: arbitrary `(v, r)`, `add` with mixed-sign near-inverse operands beyond the tested cases, the exact-inverse `commit`/`vector_commit` → identity `-1` path, and vector commits at large `n`.
- **L-3 — Hiding depends on the caller's `r`.** PC-3's perfect hiding holds only for a uniform, nonzero `r`; the primitive enforces only `r != 0`, not `r`'s distribution or uniqueness. Caller misuse (biased/reused `r`) is outside what any test here can catch.
- **L-4 — Timing out of scope.** The `scalar_is_zero(v)` branch (NC-2) and the underlying ladder's CT posture are asserted in `src/crypto/p256/README.md` / `P256CryptoStackAudit.md` and probed by the `ct-timing-probe` tranche; the normative timing boundary is CRYPTO-C99-SPEC §3.12 / `ConstantTimeInventory.md`. This document asserts functional conformance only.

---

## 5. Mechanized witnesses

| Layer | Script / subcommand | What it pins |
|---|---|---|
| Structural / negative | `determ test-pedersen-c99` (`src/main.cpp:13273-13392`) | The 8 assertions: (1) H KAT + on-curve + `!= G`; (2) `commit == compress(v·G+r·H)` via raw API; (3) `v==0` → `r·H`; (4) additive homomorphism (no-carry); (5) verify accept + wrong-v / wrong-r / tampered-C reject; (6) binding sanity (`v1 != v2` ⇒ distinct C); (7) input rejection `r==0` / `v>=n` / non-decodable add. |
| Byte gate, file half | `tools/test_c99_vector_files.sh` (`chk_pedersen` → `verify_pedersen.check_pedersen`, `:1166-1176`) | PC-7 leg 1 + PC-1/PC-4/PC-6: independent from-scratch Python (own RFC 9380 SSWU + EC ladder) recomputes the H KAT, four commit vectors, and the mod-n wraparound homomorphism; no binary, offline, fail-closed. |
| Byte gate, binary half | `determ test-c99-vectors` (`pedersen` branch, `src/main.cpp:14129-14156`), in `FAST=1` | PC-7 leg 2: the six vectors through the shipped C99 `generator_h`/`commit`/`add`, string-compared to the frozen hex. |
| Underlying primitives (context, PC-8) | `determ test-p256-c99` / `test-p256-h2c-c99` | Curve-constant + `[k]G` + on-curve parity vs OpenSSL EC; RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` appendix vectors + mod-n vs BIGNUM oracle — the correctness base under `commit`/`add`/`generator_h`. |

The two-leg split is the standard §3.13 defense-in-depth: the structural test (`test-pedersen-c99`) is the **reject-path + algebraic-property** witness the accept-only vectors cannot provide; the byte gate is the **dual-oracle conformance** witness (C99 == independent Python over frozen bytes); PC-8 forward-references the P-256 audit for the primitive-correctness base. Their conjunction — bounded by L-1..L-4 — is what "the C99 Pedersen commitment is sound and conformant" means for this increment-1 library primitive.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `src/crypto/pedersen/pedersen.c` | The shipped implementation — every §1 construction-map claim is verified against it (inc.1 commit/verify/add + inc.2 gen/vector_commit). |
| `include/determ/crypto/pedersen/pedersen.h` | The public API contracts (wire format, `0 < r < n`, `v == 0` allowed, the vector-commit families/skip semantics, return-code semantics). |
| `include/determ/crypto/p256/p256.h` | The §3.8c primitive contracts (`base_mul`/`point_mul`/`point_add`/`hash_to_curve`/`compress`/`decompress`) the module composes over. |
| `src/main.cpp` (`test-pedersen-c99`) | The 11-assertion structural/negative test (PC-1..PC-6, PC-8 inc.1; PC-9/PC-10 assertions (8)-(11) inc.2). |
| `src/main.cpp` (`test-c99-vectors` `pedersen` branch) | Byte gate binary half — `h_generator`/`commit`/`homomorphism`/`gen`/`vector_commit` types (PC-7 leg 2). |
| `tools/vectors/pedersen.json` | The 12-vector dual-oracle corpus — the byte-pinned middle term (PC-1/PC-4/PC-6/PC-7/PC-9/PC-10). |
| `tools/verify_pedersen.py` | The independent from-scratch Python oracle + `emit()` generator (PC-7 leg 1); self-checks its H against the C-pinned KAT. |
| `tools/test_c99_vector_files.sh` (`chk_pedersen`, `:1166-1176`) | Byte gate file half wiring. |
| `docs/proofs/P256CryptoStackAudit.md` | The correctness + constant-time companion for the underlying P-256 primitives (PC-8 / L-4 forward-reference). |
| `docs/proofs/VectorGateComposition.md` / `OprfConformanceMap.md` | The two-half §3.13 gate mechanics this document instantiates. |
| `docs/proofs/CRYPTO-C99-SPEC.md` §3.19 / §3.8c / §3.13 | The Pedersen / curve+h2c / vector-gate design entries. |
| `docs/proofs/ConstantTimeInventory.md` / §3.12 | The timing boundary handed off in NC-2 / L-4. |
| Pedersen (CRYPTO '91); FIPS 186-5 (P-256); RFC 9380 (hash-to-curve) | The external construction + curve + generator-derivation sources. |

---

## 7. Status

- **Spec.** Complete (this document).
- **The structural test + both byte-gate halves shipped and green.** `test-pedersen-c99` (11 assertions), the `pedersen` branch of `test-c99-vectors` (binary half), and `chk_pedersen`/`verify_pedersen.check_pedersen` (file half) validate the twelve-vector corpus + the reject/algebraic paths; the C99 output is byte-exact against the independent Python.
- **Claims.** PC-1 (H generator + KAT), PC-2 (computational binding, reduced to unknown `log_G(H)` under ECDLP — structural non-degeneracy witness only), PC-3 (information-theoretic hiding for uniform nonzero `r`; `r==0` rejected), PC-4 (additive homomorphism, no-carry gate + mod-n wraparound vector), PC-5 (open/verify accept+reject), PC-6 (commit == `v·G+r·H` incl. `v==0`), PC-7 (dual-oracle byte-freeze, transposition-non-blind), PC-8 (trust inheritance from the OpenSSL/RFC-9380-gated P-256 primitives), **PC-9 (inc.2 vector generators — independent nothing-up-my-sleeve families), PC-10 (inc.2 vector commit == `r·H+Σ(a_i·G_i+b_i·H_i)` + vector homomorphism)** — all closed.
- **Non-claims (NC-1..NC-4).** Not a range proof; the `scalar_is_zero` branches are documented data-dependent paths (CT review owner-gated); not a consensus/wallet primitive; no inner-product argument / range-proof protocol yet (the vector commit is shipped, the proof protocol is not).
- **Limits (L-1..L-4).** Binding assumes ECDLP; conformance is over the twelve frozen vectors; hiding depends on the caller's `r`; timing → §3.12 / `ConstantTimeInventory.md`.
