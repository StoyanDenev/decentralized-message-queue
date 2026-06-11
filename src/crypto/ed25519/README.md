# Ed25519 (C99) — provenance + audit notes

Per-module README required by CRYPTO-C99-SPEC.md §3.16. Module shipped in commit
`031be9e`; audit remediations in `3a6370f`. Spec: CRYPTO-C99-SPEC.md §3.2; audit:
C99CryptoStackAudit.md §6.

## 1. What this module implements

RFC 8032 Ed25519 in one self-contained C99 file (`ed25519.c`): field arithmetic,
scalar mod-L arithmetic, Edwards group operations, and the §5.1 sign/verify
framing, composing the C99 SHA-512 from `src/crypto/sha2/`. No libsodium, no
OpenSSL in the implementation (OpenSSL appears only as a test oracle).

Two public headers:

- `include/determ/crypto/ed25519/ed25519.h` — sign/verify API:
  - `determ_ed25519_pubkey_from_seed` — pk from 32-byte seed (RFC 8032 §5.1.5).
  - `determ_ed25519_sign` — deterministic 64-byte detached R||S (§5.1.6).
  - `determ_ed25519_verify` — §5.1.7 verification with the canonicality gates
    (see §2 below).
- `include/determ/crypto/ed25519/ed25519_group.h` — the scalar/group primitives
  the FROST-Ed25519 layer (`src/crypto/frost/frost.c`, RFC 9591) builds on, so
  FROST does not re-vendor the curve:
  - scalars mod L (32-byte little-endian): `determ_ed25519_sc_muladd`, `_sc_mul`,
    `_sc_add`, `_sc_sub`, `_sc_reduce64` (64→32 hash-to-scalar), `_sc_invert`
    (Fermat, a^(L−2)), `_sc_set_small`.
  - points (32-byte compressed Edwards): `determ_ed25519_point_basemul`,
    `_point_mul`, `_point_add` (`_point_mul` / `_point_add` decode → op →
    re-encode and return −1 on an off-curve / non-decodable input;
    `_point_basemul` takes only a scalar and cannot fail).
  - canonicality witnesses: `determ_ed25519_sc_is_canonical` (s < L) and
    `determ_ed25519_point_is_canonical` (y < q) — the same gates the verifier
    applies, exported so higher layers (e.g. the FROST DKG proof-of-possession)
    can apply them (audit findings 8.1/8.2).

## 2. Provenance + construction

- **Construction:** the field/group algorithms follow the public-domain
  **TweetNaCl** construction (Bernstein, van Gastel, Janssen, Lange, Schwabe,
  Smetsers) — the `gf[16]` (radix-2^16) field representation with a cswap-ladder
  scalar multiplication and the `modL` scalar reduction. RFC 8032 §5.1 fixes the
  signing/verification framing (clamp, r = H(prefix‖msg), k = H(R‖pk‖msg),
  S = r + k·a mod L, verify [S]B = R + [k]A).
- **Not vendored — no upstream version pin.** This is a from-scratch C99
  implementation of the TweetNaCl-lineage algorithms, not copied vendor code, so
  there is no pinned upstream release. CRYPTO-C99-SPEC §3.2 originally planned
  vendoring Bernstein's `ref10` from supercop with a version pin; the shipped
  choice is the table-free `gf[16]` form instead (spec §2 Q3 module table:
  "constant-time `gf[16]` cswap-ladder (TweetNaCl-derived); `ref10` radix-2^51
  is a future perf variant"). The table-free form is what makes the whole module
  auditable in one pass (audit §6) and shares one field lineage with
  `src/crypto/x25519/` (spec §3.3).
- **License posture:** public domain (spec §2 Q3 module table; the TweetNaCl
  reference is public domain, and this is an original re-implementation).
- **RFC 8032 canonicality gates (stricter than OpenSSL by design):**
  - `sc_lt_L` rejects a signature scalar S ≥ L (§5.1.7), so (R, S+L) does NOT
    re-verify — signatures are byte-unique. Added for audit finding 6.1
    (Medium): the TweetNaCl cofactorless gap.
  - `point_y_is_canonical` rejects a public key whose y ≥ q (§5.1.3), closing
    the 19 non-canonical encodings y ∈ {q..q+18} that OpenSSL's lenient ref10
    decoder accepts. Added for audit finding 6.2 (Low). Keeps "one point = one
    encoding" for any logic keyed on raw bytes (equivocation dedup,
    anon-address derivation).
  - Honest keys/signatures are always canonical, so behavior is identical to
    OpenSSL on honest inputs (asserted by the cross-validation below).

## 3. Validation evidence

- **`determ test-ed25519-c99`** (dispatch in `src/main.cpp`; wrapper
  `tools/test_ed25519_c99.sh`) — 12 assertions:
  - RFC 8032 §7.1 TEST 1 pubkey + signature KAT (empty message) — a published
    anchor independent of OpenSSL.
  - Pubkey + signature **byte-equal vs OpenSSL `EVP_PKEY_ED25519` /
    `EVP_DigestSign`** over a fuzzed (seed, message-length) grid
    (mlen ∈ {0, 1, 2, 31, 32, 33, 64, 127, 128, 200}) — the spec §Q9
    cross-validation gate.
  - 100000-byte extreme-length message: signature byte-equal vs OpenSSL +
    verify accepts (exercises SHA-512 streaming inside sign/verify).
  - Verify semantics: accepts a valid signature; rejects tampered signature,
    tampered message, wrong public key.
  - Anti-malleability regression: (R, S+L) is rejected (the finding-6.1 gate).
  - Cross-binary: our signature verifies under OpenSSL `EVP_DigestVerify`.
- **`determ test-ed25519-scalar-reduce`** (wrapper
  `tools/test_ed25519_scalar_reduce_edge.sh`) — 13 assertions, no external
  oracle (L is a public constant; `sc_is_canonical` is the witness): the
  pathological-input contract of `sc_reduce64` — reduce(0)=0, reduce(L)=0,
  reduce(L−1)=L−1, reduce(L+7)=7, reduce(2^256−1) canonical, canonical output
  for 256 patterned inputs, determinism — plus `sc_is_canonical(L)=false` /
  `(L−1)=true` sanity.
- **`determ test-frost-c99`** (wrapper `tools/test_frost_c99.sh`) — exercises
  the `ed25519_group.h` API end-to-end: group homomorphisms
  ([a]B+[b]B = [a+b]B, [k]([a]B) = [k·a]B), scalar-field a·a⁻¹ = 1,
  Shamir/Lagrange over the scalar field, and FROST aggregate signatures checked
  with `determ_ed25519_verify`.
- **`determ test-ed25519-vectors`** (wrapper `tools/test_ed25519_vectors.sh`) —
  the RFC 8032 §7.1 four-vector KAT suite (24 assertions). It pins the daemon's
  current OpenSSL signature backend, not this module directly, but RFC 8032
  signing is deterministic, so it is the independent oracle this module must
  reproduce byte-for-byte (the spec §Q7 decision — every primitive validated
  against canonical vectors before merge — which the dispatch comment glosses
  as "validate before you vendor").
- **Adversarial audit** (C99CryptoStackAudit.md §6): six dimensions (field
  arithmetic, scalar/mod-L, group ops, RFC 8032 framing, constant-time,
  memory-safety). Field and scalar layers were differential-tested against
  exact Python GMP modular arithmetic (250k+ `pack25519` inputs, 500k+ `modL`
  inputs, plus boundary bands) — a check the OpenSSL byte-equality oracle does
  not provide. Verdict: 0 Critical / 0 High; three actionable findings (6.1
  S ≥ L malleability, 6.2 non-canonical pk decode, 6.3 `int` splice index vs
  `size_t msglen` overflow) all remediated in commit `3a6370f`,
  output-preserving on honest inputs.

## 4. Constant-time / hygiene posture

Constant-time by construction — no secret-dependent branch, index, or table:

- The cswap ladder (`scalarmult`) runs a fixed 256 iterations, performs both
  `add()` calls every bit, and routes each secret scalar bit only through
  `cswap` → `sel25519` (branchless masked swap).
- Field arithmetic is branchless: `car25519` carry chain, `M`/`S` multiply,
  `pack25519` reduces via `sel25519` on a computed borrow bit.
- `modL` / `reduce` (scalar reduction) are branchless carry chains.
- `sc_lt_L` computes s − L byte-wise and inspects the final borrow — no
  data-dependent branch.
- No precomputed base table (the deliberate divergence from `ref10`), so there
  is no cache-timing channel to begin with.
- `determ_ed25519_sc_invert` branches only on the PUBLIC constant exponent
  L−2, never on the base.
- The only data-dependent branches are on public data: the public key in
  `unpackneg` / `point_unpack` / `point_y_is_canonical`, message and buffer
  lengths, the ladder bit counter.
- The verifier's final R comparison routes through **`determ_ct_memcmp`**
  (`include/determ/crypto/ct.h`) — the shared §3.10 constant-time equality
  primitive that consolidates the per-module compare helpers.
- **`determ_secure_zero`** (`include/determ/crypto/secure_zero.h`, the §3.10
  memory-hygiene half) scrubs every secret intermediate: the SHA-512 expansion
  of the seed in `pubkey_from_seed`; and in `sign` the hash `h`, the clamped
  scalar `a`, the nonce `rh`, the `i64` accumulator `x`, and the heap splice
  buffer before `free`.

## 5. Known limitations / future work

- **`ref10` radix-2^51 perf variant** (spec §2 Q3 table; same note in the
  `ed25519.h` header): a precomputed-table, radix-2^51 implementation would be
  faster; it is a throughput optimization, not a security gate. Tracked as
  future work.
- **Daemon sign/verify call sites still use OpenSSL `EVP_PKEY_ED25519`.** This
  module is additive at the sign/verify level; its in-tree consumer is the
  FROST layer via `ed25519_group.h`. (Verified: no `src/` caller of
  `determ_ed25519_sign`/`_verify` outside the `src/main.cpp` test dispatch and
  the module itself.)
- **RFC 9591 binding-factor interop vectors** are a tracked follow-up in the
  FROST module that builds on this one (C99CryptoStackAudit.md §7 documented
  non-goals) — they validate FROST's derivation, not this module's arithmetic,
  and are listed here only because `ed25519_group.h` is the substrate.
- Strictness delta vs OpenSSL on adversarial inputs (the §2 canonicality
  gates) is intentional and documented in `ed25519.h`; it is not scheduled to
  be relaxed.
