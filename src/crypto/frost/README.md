# src/crypto/frost — FROST-Ed25519 threshold signatures (RFC 9591)

Per-module provenance + audit README required by `docs/proofs/CRYPTO-C99-SPEC.md`
§3.16. Module spec section: CRYPTO-C99-SPEC §3.8.

---

## Deployment status — NOT a chain primitive

**FROST is not part of Determ's chain consensus path.** Per
`docs/proofs/FROST_DEVIATION_NOTICE.md` (2026-06-07, authority: Stoyan Denev),
FROST was identified as a Claude-introduced design deviation — not part of the
original Determ design — and was removed from the v1.1 launch scope. The code in
this directory is retained as an **additive C99 library** (CRYPTO-C99-SPEC §3.8):

- NOT wired into the consensus randomness path (`compute_block_rand` uses the
  v1.x commit-reveal protocol; block authentication uses K individual Ed25519
  signatures).
- NOT part of the v1.1-locked formal-verification surface or any substrate bundle.
- Post-launch DApp-layer use as a library is permitted (NOTICE §6); re-introduction
  into the chain consensus path requires Stoyan Denev's explicit written sign-off
  satisfying NOTICE §3.
- `tools/test_frost_chain_guard.sh` is a doc-coherence ratchet that turns RED if
  any T1-authoritative doc re-asserts FROST as a chain-consensus primitive.

Presence of this module does not imply protocol adoption.

---

## 1. What this module implements

One translation unit (`frost.c`) + one public header
(`include/determ/crypto/frost/frost.h`). FROST-Ed25519 threshold Schnorr
signatures whose t-of-n aggregate verifies as a **plain Ed25519 signature** under
the group public key. Built on the C99 Ed25519 scalar/group primitives in
`include/determ/crypto/ed25519/ed25519_group.h` (scalars mod L, 32-byte
compressed Edwards points) — no libsodium, no curve re-vendoring.

Public entry points:

| Pillar | Functions |
|---|---|
| Trusted-dealer keygen | `determ_frost_keygen_trusted` (Shamir split over the mod-L scalar field, Horner evaluation; emits shares + group_pk + per-share pubkeys), `determ_frost_reconstruct` (Lagrange interpolation at 0) |
| Two-round signing | `determ_frost_sign` (centralized simulation — needs every signer's nonces; test/reference API), `determ_frost_sign_partial` (round 2: one signer's share `z_i` from only its own secrets + the public round-1 commitment lists), `determ_frost_aggregate` (sums partials, recomputes the shared `R` from public commitments; output `R ‖ z`, 64 bytes) |
| Pedersen DKG (Feldman VSS + PoP, RFC 9591 §6.6) | `determ_frost_dkg_commit` (Feldman commitments `C_k = [poly_k]B` + Schnorr proof-of-possession of `a_0` bound to the participant index — rogue-key defence), `determ_frost_dkg_verify_pop`, `determ_frost_dkg_share` (dealt share `f_i(j)`), `determ_frost_dkg_verify_share` (`[s]B == Σ j^k·C_k`) |
| PSS refresh (Herzberg et al. 1995) | `determ_frost_pss_commit` (commitments for a zero-hole polynomial, `δ_0 = 0` enforced), `determ_frost_pss_verify_commit` (`C_0 == [0]B` zero-hole proof). Refresh shares are dealt/verified through the existing `determ_frost_dkg_share` / `determ_frost_dkg_verify_share`; the refreshed share `s'_j = s_j + Σ_i δ_i(j)` is a caller-side scalar sum. Rotates every share without changing the group secret or group key (mobile-adversary defence) |

The binding-factor / group-commitment / challenge derivation lives in one shared
static helper (`frost_binding_and_challenge`), used by all three signing entry
points — so the distributed path is **byte-identical** to the centralized one for
the same inputs. The signer-set guard (`frost_check_signer_set`: indices in
[1,255], pairwise distinct) is likewise applied by all three.

Note: `include/determ/crypto/frost.hpp` + `src/crypto/frost.cpp` are a separate,
adjacent C++ type layer (RFC 9591 §3 type-layout pins, validated by
`tools/test_frost_types.sh`). This README covers only the C99 module in this
directory.

## 2. Provenance + construction

- **Construction:** FROST per RFC 9591, instantiated directly on Ed25519 (not
  ristretto255 — CRYPTO-C99-SPEC §2 Q2). DKG is Pedersen-style with Feldman VSS
  + proof-of-possession per RFC 9591 §6.6. PSS refresh follows Herzberg et al.
  1995 (zero-hole polynomials). The challenge is the RFC 8032 Ed25519 challenge
  `c = SHA-512(R ‖ group_pk ‖ msg) mod L`, which is exactly why the aggregate
  verifies under any stock Ed25519 verifier.
- **License posture: Determ-original** (CRYPTO-C99-SPEC §2 Q3 table, ~330 LOC).
  Not vendored from a reference implementation — written from the RFC against the
  in-house Ed25519 group layer. The underlying curve arithmetic it calls
  (`src/crypto/ed25519/`) is the constant-time, table-free `gf[16]` cswap-ladder
  derived from the public-domain TweetNaCl construction.
- **Domain separation:** binding factors use the 16-byte tag `DETERM-FROST-RHO`
  (`rho_i = SHA-512(DOM ‖ idx_i ‖ signer-set commitment list ‖ msg) mod L`); the
  DKG PoP uses the 20-byte tag `DETERM-FROST-DKG-POP` with 1-byte sub-tags for
  nonce (0x01) vs challenge (0x02), and an RFC-6979-style deterministic nonce.
  These derivations are self-consistent (signer ⇄ aggregator agree) but **not
  byte-exact to the RFC 9591 ciphersuite H1..H5** — see §5.

## 3. Validation evidence

- **`determ test-frost-c99`** (dispatch block in `src/main.cpp`,
  `if (cmd == "test-frost-c99")`), wrapper **`tools/test_frost_c99.sh`** (pins the
  terminal marker `PASS: frost-c99 all keygen + DKG + PSS-refresh +
  threshold-signing invariants held`). Seven sections:
  1. Group homomorphism: `[a]B + [b]B == [a+b]B`, `[k]([a]B) == [k·a]B`.
  2. Scalar field: `a · a⁻¹ == 1 mod L`.
  3. Trusted-dealer keygen (t=3, n=5): share-pubkey consistency, group-key tie,
     four distinct t-subsets reconstruct the same secret (Shamir invariant).
  4. Threshold signing: two different quorums each produce an aggregate verified
     under **both the C99 verifier (`determ_ed25519_verify`) and OpenSSL EVP
     (`EVP_PKEY_ED25519` / `EVP_DigestVerify`)**; duplicate-signer-set rejection;
     §4b distributed parity — per-signer partials + aggregate are
     `memcmp(agg, ref, 64)==0` byte-identical to the centralized sign, re-verified
     under C99 + OpenSSL; a tampered partial breaks verification; out-of-range
     `pos` rejected.
  5. DKG: all PoPs verify; every dealt share passes the Feldman VSS check; summed
     commitments equal `[Σ a_i0]B`; t long-term shares reconstruct the group
     secret; a t-of-n quorum of DKG shares signs a valid Ed25519 sig (C99 +
     OpenSSL); tampered PoP and tampered share rejected; a mauled PoP `(R, z+L)`
     rejected by the canonical-scalar gate.
  6. PSS refresh: zero-hole commitments emitted, every `C_0` is the identity;
     non-zero-hole polynomial and non-identity `C_0` rejected; refresh shares pass
     VSS; refreshed shares differ but reconstruct the ORIGINAL secret (two
     subsets); mixing old + refreshed shares does NOT recover the secret; a
     refreshed quorum signs under the unchanged group key.
  7. Parameter coverage: degenerate t=1 and t=5/n=9 end-to-end, including
     distributed-path parity at t=5.
- **Cross-validation target:** OpenSSL's Ed25519 verifier (the load-bearing
  external check — the aggregate must be a *standard* Ed25519 signature). There
  is no libsodium byte-equality leg (the construction is Determ-original) and no
  RFC KAT leg yet (§5).
- **`tools/test_frost_chain_guard.sh`** — read-only doc ratchet enforcing the
  deployment status above (no binary required).
- **Adversarial audits** (`docs/proofs/C99CryptoStackAudit.md`):
  - §7 (keygen + signing, 4 dimensions): clean except **7.1 Low** — missing
    signer-set validation made a duplicate x silently produce a wrong signature
    (`sc_invert(0)=0` collapses the Lagrange weight); fixed in `55a0f34` as an
    inline guard in `determ_frost_sign`, later factored into the shared
    `frost_check_signer_set` by the `b49db4f` distributed-signing refactor.
  - §8 (DKG): **8.1 Low** (PoP scalar `z ≥ L` re-verified — malleability) and
    **8.2 Low** (non-canonical `R` encodings re-verified); both fixed in
    `12aa6ec` via the `determ_ed25519_sc_is_canonical` /
    `determ_ed25519_point_is_canonical` gates, matching the Ed25519 verifier's
    RFC 8032 posture.
  - §8b (PSS): 0 confirmed findings; the public zero-hole check was hardened to a
    branchless aggregate-OR anyway (`ab381be`).
  - Soundness proof: `docs/proofs/FrostThresholdSoundness.md` (PSS
    secret-preservation is T-6).

## 4. Constant-time / hygiene posture

- **Secrets only touch constant-time arithmetic.** Every secret scalar (dealer
  secret + coefficients, shares, nonces `d`/`e`, DKG polynomial) flows only
  through the constant-time `sc_*` ops and `determ_ed25519_point_basemul` of
  `ed25519_group.h` (`sc_invert` branches only on the public exponent L−2; the
  audit confirmed no secret reaches a hash buffer except the DKG PoP's
  RFC-6979-style deterministic nonce input, which is standard and leaks nothing).
  Lagrange numerators/denominators are public x-coordinates.
- **`determ_secure_zero`** (`include/determ/crypto/secure_zero.h`, the
  memory-hygiene half of CRYPTO-C99-SPEC §3.10) scrubs every transient
  secret-bearing buffer: the keygen Horner accumulator, reconstruct's
  `lam`/`acc`, sign's `z`/`zi`/`t1`/`ls`/`lam`, sign_partial's `lam`/`t1`/`ls`,
  the shared helper's SHA-512 scratch `hbuf`, dkg_commit's `kn`/`z`/`nb`/`hbuf`,
  and the `frost_poly_eval` Horner accumulator behind `determ_frost_dkg_share`
  (which deals the secret DKG / PSS-refresh shares). Binding factors (`rho`)
  are public by construction and are freed unscrubbed by design.
- **Comparisons route through `determ_ct_memcmp`**
  (`include/determ/crypto/ct.h`, CRYPTO-C99-SPEC §3.10): the VSS and PoP point
  compares in `determ_frost_dkg_verify_pop` / `determ_frost_dkg_verify_share`.
  Their operands are publicly recomputable group elements, but the uniform
  discipline removes the per-site "is this operand really public?" review burden
  (ct.h usage notes). The PSS zero-hole constant-term check is a branchless
  aggregate-OR over the protocol-mandated public-zero bytes;
  `determ_frost_pss_verify_commit` compares `C_0` against the freshly recomputed
  identity encoding — both public.
- Heap accounting in the shared helper (`rsize = 17 + t·65 + msglen`,
  `csize = 64 + msglen`, 256 MiB message cap) was audited exact-fit,
  `size_t`-overflow-safe, and freed on every path (audit §7).

## 5. Known limitations / future work

Only items the spec or audit actually records:

- **RFC 9591 binding-factor interop** (spec §3.8; audit §7 documented
  non-goal): the binding-factor/H1..H5 derivation is self-consistent and the
  aggregate verifies under OpenSSL, but it is not byte-exact to the RFC 9591
  ciphersuite. PARTIALLY CLOSED (R48): the RFC 9591 Appendix E.1 vector now
  gates the byte-reproducible subset through both §3.13 halves
  (`tools/vectors/frost_ed25519_rfc9591.json`) — keygen_trusted reproduces
  the E.1 Shamir shares + group pk BYTE-EXACT, reconstruct recovers the
  vector sk, the RFC aggregate verifies under the C99 Ed25519 verifier, and
  determ_frost_sign fed the RFC's own nonces yields a valid group-key
  signature. Byte-exact R/sig-share interop needs an RFC-mode binding-factor
  transcript (replacing the deliberate DETERM-FROST-RHO separation of §2) —
  a protocol change that stays authorization-gated; the zcash/frost-ed25519
  (Rust) cross-check remains open with it.
- **DKG complaint-phase / ceremony orchestration** (spec §3.8): this module ships
  the per-message verification predicates; broadcast, complaint handling, and
  epoch plumbing are caller-side. The previously tracked "wiring into
  `compute_block_rand`" follow-up (audit §8) is **superseded** by
  `FROST_DEVIATION_NOTICE.md` — chain wiring is de-scoped, not pending.
- **Trusted-dealer keygen** is retained for tests and simple deployments;
  trustless setups should use the DKG (audit §7 documented non-goal).
- **Centralized `determ_frost_sign`** requires every signer's secret nonces in
  one place — it is the reference/simulation API; production-shaped distribution
  uses `determ_frost_sign_partial` + `determ_frost_aggregate`.
- **Throughput**: the underlying curve is the TweetNaCl-derived `gf[16]` ladder;
  a `ref10` radix-2^51 variant remains a future perf optimization of
  `src/crypto/ed25519/` (spec §3.2 note) and would benefit this module
  transparently via `ed25519_group.h`.
