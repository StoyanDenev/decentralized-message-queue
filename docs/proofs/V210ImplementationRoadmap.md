# v2.10 Implementation Roadmap — FROST-Ed25519 Threshold Randomness

**Status:** roadmap / scoping only. No code change accompanies this document. It
records the *verified* state of the v2.10 work (threshold-signature block
randomness, the last permissionless-readiness gate) against the actual `src/`
tree as of this commit, and fixes the smallest-safe-first increment plus its
GO/NO-GO.

> **Progress (decision recorded + first increment landed).** The P0 backend
> decision is made: **libsodium-free C99 `ref10`** (consistent with this doc §2,
> `CRYPTO-C99-SPEC.md`, and the `determ-light` no-libsodium invariant; the
> `frost.hpp` / `F2-V210-IMPLEMENTATION-PLAN` "libsodium" wording is the outlier
> to reconcile). The "validate-before-vendor" oracle has shipped (commit
> `9d69f05`): `determ test-ed25519-vectors` pins the daemon's Ed25519 against the
> RFC 8032 §7.1 known-answer vectors (24 assertions; FAST=1 148/148) — this is the
> §Q9 byte-equal gate the forthcoming ref10 backend must pass. **The §3.1 work
> unit is now complete (commits `c349129` + `1bd9011`):** SHA-256 / SHA-512 (FIPS
> 180-4) + HMAC-SHA-256/512 (RFC 2104) + HKDF-SHA-256 (RFC 5869) in portable C99
> at `src/crypto/sha2/`, validated by `determ test-sha2-c99` — byte-equal against
> OpenSSL over all length/padding boundaries (SHA-2 + HMAC) + the NIST FIPS 180-4
> and RFC 5869 KATs. **PBKDF2-HMAC-SHA-256 (§3.8b) has also landed (commit
> `bebba14`)** on top of that HMAC — the KDF the wallet keyfile envelope (S-004)
> uses at rest — completing the HMAC-based KDF family (HMAC → HKDF + PBKDF2);
> `determ test-sha2-c99` now runs 14/14 (FAST 149/149). SHA-512 is itself a
> prerequisite for Ed25519 + the FROST H1..H5 hashes, and HMAC-SHA-256 already
> backs RPC auth (S-001), so this is squarely on the libsodium-removal / v2.10
> path. The **§3.4 AEAD family is now complete (commits `21385ed` + `4c9a9a9`):**
> C99 ChaCha20 (RFC 8439) + Poly1305 + the ChaCha20-Poly1305 AEAD combiner —
> `determ test-chacha20-c99` validates ChaCha20 + the full AEAD byte-equal vs
> OpenSSL `EVP_chacha20`/`EVP_chacha20_poly1305` and Poly1305 vs the RFC 8439
> §2.5.2 KAT (8/8; FAST 150/150). (ChaCha20-Poly1305 was taken ahead of AES-256-GCM
> because it is constant-time by construction — ARX + limb arithmetic — whereas
> AES-GCM's GHASH CT is the spec's flagged hard part; AES-256-GCM, which the wallet
> envelope actually uses, follows with the CT care it needs.) Notably, Poly1305 was
> the one primitive where an adversarial design workflow caught both agent attempts
> as buggy and its own fix as unverified — the canonical donna-32 was written by
> hand and proven only by the KAT + the byte-equal AEAD cross-validation. **§3.5
> byte-correctness is complete: the full C99 AES-256-GCM AEAD shipped** — the
> AES-256 block cipher (commit `facf915`, FIPS-197 C.3 KAT + byte-equal vs OpenSSL
> `EVP_aes_256_ecb`) plus GHASH over GF(2^128) + the GCM mode (NIST SP 800-38D).
> `determ test-aes-c99` now runs six assertions: the two block-cipher checks, the
> full AES-256-GCM (ciphertext AND tag) byte-equal vs OpenSSL `EVP_aes_256_gcm`
> over a (plaintext,aad)-length grid — the §Q9 gate — plus a GCM decrypt
> round-trip and tamper rejection of both the tag and the ciphertext (6/6; FAST
> 151/151). GHASH is written BRANCHLESS / constant-time (mask + reduction use no
> secret-dependent branch); the AES S-box, however, is table-based and carries a
> loud, documented CONSTANT-TIME caveat. The **only remaining §3.5 work is S-box
> CT-hardening** (constant-time S-box / AES-NI / BearSSL per the spec) before the
> module replaces OpenSSL at the keyfile-envelope (S-004) call site. Remaining P0:
> vendor the `ref10` scalar/point source into `src/crypto/ed25519/`, wire it into
> the `determ` target, and reconcile the three backend-naming docs. Then the
> Phase-A FROST primitives (keygen/sign/aggregate) become implementable.

v2.10 replaces the v1 commit-reveal block randomness — `ContribMsg.dh_input`
commit (`SHA256(secret‖pubkey)`) + `BlockSigMsg`/`creator_dh_secrets` Phase-2
reveal, aggregated by `compute_block_rand` — with a t-of-K FROST-Ed25519
aggregate per RFC 9591. The v1 path has a residual *selective-abort* attack: a
Phase-2 participant who observes others' reveals can abort to bias the output
(last-revealer advantage). A FROST aggregate is recomputable from any t-of-K
partials, so one withholding adversary cannot bias the result.

**Companion documents:**
- `v2.10-DKG-SPEC.md` — DKG ceremony + threshold-signing design (RFC 9591 §6.6;
  4 primary + 3 cascade decisions). This roadmap implements that spec.
- `FrostVerifyDelegation.md` (FA-Crypto) — soundness proof for the one shipped
  primitive, `frost_verify`. Cross-referenced from §1 and §4 below.
- `F2-V210-IMPLEMENTATION-PLAN.md` — the multi-phase plan this roadmap refines
  (Phase A status + per-phase file touchpoints). **Do not edit (concurrent
  session owns DECISION-LOG / IMPLEMENTATION-SEQUENCING / Improvements).**
- `CRYPTO-C99-SPEC.md` — the C99-native, libsodium-free crypto-stack
  architecture spec that the §2 prerequisite verdict must be reconciled against.

---

## 1. Current state — implemented vs stubbed

### Shipped (real implementation)

| Surface | Location | Notes |
|---|---|---|
| `frost_verify` | `src/crypto/frost.cpp:101-118` | Only real FROST primitive. Bytewise-adapts `FrostSig→Signature`, `Point→PubKey` (two `static_assert`s pin 64/32-byte shapes) and delegates to `determ::crypto::verify` (`src/crypto/keys.cpp:79-91`, OpenSSL `EVP_PKEY_ED25519`). Sound per `FrostVerifyDelegation.md` T-1. |
| FROST API header | `include/determ/crypto/frost.hpp:1-179` | Full type + struct + signature surface per RFC 9591 §3: `Identifier`/`Scalar`/`Point`/`FrostSig` typedefs; `KeygenRound1Output`/`KeygenRound2Output`/`LocalShare`/`SignRound1Output`/`CommitmentMap`; keygen/sign/aggregate/verify declarations. API is stable; only `frost.cpp` changes as primitives land. |
| Activation gate field | `include/determ/chain/genesis.hpp:216` | `uint64_t v2_10_active_from_height{0}` declared, parallel to the shipped `v2_7_f2_active_from_height` (line 208). Comment (lines 210-216) states apply-path enforcement is **no-op until Phase D** (no producer/validator branch reads it yet). |

### Stubbed (throw `std::logic_error("v2.10 Phase A not yet implemented: <fn>")`)

All in `src/crypto/frost.cpp` via the `unimplemented()` helper (`frost.cpp:41-45`):

| Function | frost.cpp line |
|---|---|
| `frost_keygen_round1` | 47-50 |
| `frost_keygen_round2` | 52-56 |
| `frost_keygen_finalize` | 58-65 |
| `frost_sign_round1` | 67-69 |
| `frost_sign_round2` | 71-76 |
| `frost_aggregate` | 78-84 |

Per `F2-V210-IMPLEMENTATION-PLAN.md` §122-125: Phase A is *partially* shipped
(verify only); keygen/sign/aggregate are scaffolded and PIN-tested (a test pins
that they throw, so the throw can't silently become a wrong answer).

### v1 randomness path that v2.10 augments (left intact below activation)

| Step | Location |
|---|---|
| Phase-1 commit | `ContribMsg.dh_input` built in `make_contrib` (`src/node/producer.cpp:647-663`) |
| Delay seed | `compute_delay_seed(block_index, prev_hash, tx_root, creator_dh_inputs)` — `producer.cpp:509`, called at `producer.cpp:804` |
| Phase-2 reveal aggregate | `compute_block_rand(delay_seed, ordered_secrets)` — `producer.cpp:637-643`, called at `producer.cpp:808-810` |
| Block randomness chain | `b.delay_output` → `b.cumulative_rand` fold — `producer.cpp:814-822` |
| Validator recompute | `check_cumulative_rand` (`validator.cpp:35`) + `compute_delay_seed`/`compute_block_rand` recompute at `validator.cpp:374,388` |
| Downstream consumers of `cumulative_rand` | committee selection seed (`node.cpp:332,958-975`), apply-time `derive_delay` for REGISTER/DEREGISTER (`chain.cpp:42-43,801,844`), NEF lottery (`chain.cpp:1246-1259`) |

This is the path that must remain byte-identical for blocks below
`v2_10_active_from_height` (see §5).

---

## 2. EC-primitive prerequisite verdict — THE LOAD-BEARING FINDING

**Verdict: BLOCKED-ON-PREREQ. No elliptic-curve scalar/point arithmetic
backend is currently wired into the `determ` daemon. The FROST keygen/sign/
aggregate primitives cannot be ported until one is chosen and linked. This is
the gating decision for all of v2.10 Phase A beyond `frost_verify`, and the
in-tree documentation currently disagrees with itself about which backend it
is.**

### What the daemon actually has today

- **OpenSSL `EVP_PKEY_ED25519` exposes only sign/verify**, not the underlying
  group operations. `src/crypto/keys.cpp` uses `EVP_DigestSign`/`EVP_DigestVerify`
  exclusively. FROST needs raw Ed25519 **scalar arithmetic mod L** (polynomial
  eval in F_L, Lagrange interpolation, challenge/binding-factor reduction) and
  **point arithmetic** (commitment `g^{a_k}`, multi-scalar mult, group-pubkey
  aggregation). OpenSSL 1.1.1 (pinned at CMakeLists.txt:45, `1.1.1w`) does not
  surface these for Ed25519 via the EVP interface. **OpenSSL alone is
  insufficient** — confirmed by reading `keys.cpp` end to end.

- **libsodium IS vendored, but is NOT linked into the `determ` daemon.**
  CMakeLists.txt:121-131 declares `sodium` via FetchContent. But the daemon
  target links only `ssl crypto nlohmann_json` (CMakeLists.txt:98-102). `sodium`
  is linked into `determ-wallet` (line 193) and `oprf` (line 174) **only** — NOT
  `determ`. `determ-light` explicitly excludes it (line 210 comment: "Explicitly
  NO libsodium"). So even though `frost.hpp:15-16` and `frost.cpp:8,20` *claim*
  the implementation "uses the already-vendored libsodium
  (`crypto_core_ed25519_*`)", **`src/crypto/frost.cpp` includes only
  `frost.hpp` + `keys.hpp` and calls no `crypto_core_ed25519_*` function** —
  those names appear only in comments. The libsodium reference in the header is
  aspirational, not wired.

- **`src/crypto/ed25519/` does not exist.** `v2.10-DKG-SPEC.md` §2.5/§4.1 and
  `CRYPTO-C99-SPEC.md` say FROST builds on an *independent* C99 Ed25519 stack
  (Bernstein `ref10`) vendored at `src/crypto/ed25519/`, **libsodium-free**. That
  directory is absent from the tree (`src/crypto/` contains only sha256, random,
  keys, frost, merkle, plus modern/fips/universal profile READMEs). So the
  designated C99 backend is also not present.

### The documentation contradiction (verifier correction — see §6)

Three in-tree sources name three *different, mutually exclusive* EC backends for
FROST, and **none of them is actually wired**:

1. `frost.hpp:15-16` + `frost.cpp:8,20` → "already-vendored **libsodium**
   `crypto_core_ed25519_*`".
2. `v2.10-DKG-SPEC.md` §2.5 (line 95) + §4.1 (lines 224-227) → "independent C99
   ... Bernstein's `ref10` in **`src/crypto/ed25519/`** ... NOT libsodium".
3. `CRYPTO-C99-SPEC.md` (title + line 73) → "**libsodium-free** ... zero
   ristretto255 callers ... No need to vendor libsodium."

These cannot all be the plan. Until this is resolved the "2-3 days for an
experienced FROST implementer" estimate in `frost.cpp:30-34` /
`v2.10-DKG-SPEC.md` §5 is **not actionable** — it presupposes a scalar/point
backend that does not yet exist in the daemon's link line.

### The decision that must be made first (prerequisite)

Pick exactly one and wire it before any keygen/sign/aggregate code is written:

- **Option P1 — link the already-vendored libsodium into `determ`.** Add
  `sodium` to the `determ` target's `target_link_libraries` (CMakeLists.txt:98).
  Lowest immediate effort: `crypto_core_ed25519_scalar_*` + `crypto_scalarmult_ed25519`
  + `crypto_core_ed25519_*` point ops already exist and are audited. **Cost:**
  contradicts `CRYPTO-C99-SPEC.md`'s libsodium-free goal and re-introduces the
  ~70K-LOC dependency that spec set out to remove; expands the daemon's binary +
  audit surface. Matches the `frost.hpp` comment.

- **Option P2 — vendor the independent C99 Ed25519 (`ref10`) at
  `src/crypto/ed25519/`.** Matches `v2.10-DKG-SPEC.md` + `CRYPTO-C99-SPEC.md`.
  **Cost:** vendoring + constant-time review of ~3K LOC of `ref10` scalar/point
  code *before* the FROST layer is even started; the C99 spec is itself
  "specification only, no code" today, so this is a larger up-front lift than the
  "2-3 day" Phase-A estimate assumes.

The choice is a clean GO/NO-GO precondition for Phase A. This roadmap's
recommended smallest-safe increment (§4) is constructed so it can be validated
**without** committing to either P1 or P2 — it does not call any scalar/point op.

---

## 3. Phased plan (refines F2-V210-IMPLEMENTATION-PLAN.md §116+)

| Phase | Scope | File touchpoints | Est. |
|---|---|---|---|
| **P0** (new — this roadmap) | Resolve §2 backend contradiction; link/vendor one EC backend into `determ`; reconcile the three docs to it. | `CMakeLists.txt` (link line) **or** new `src/crypto/ed25519/`; doc reconcile in `frost.hpp`, `v2.10-DKG-SPEC.md`, `CRYPTO-C99-SPEC.md` | 1-5 d (P1 ≈ 1 d, P2 ≈ 3-5 d) |
| **A** | FROST primitives onto the chosen backend (keygen/sign/aggregate). RFC 9591 §6.6 H1..H5, F_L poly eval, Lagrange, PoP Schnorr. Cross-validate vs `zcash/frost-ed25519` on RFC 9591 App. C vectors. | `src/crypto/frost.cpp` only (header stable) | 2-3 d *after P0* |
| **B** | DKG ceremony (3-phase, R blocks): `DKGCommitMsg`/`DKGShareMsg`/`DKGComplaintMsg`; VSS check; complaint/exclusion; PSS refresh. | `include/determ/net/messages.hpp`, `src/net/binary_codec.cpp`, `src/net/gossip.cpp`, new `src/node/dkg.cpp` | 1-1.5 wk |
| **C** | Epoch-boundary orchestration. Hook on `epoch_blocks`; fresh-DKG vs PSS by committee delta; commit `epoch_public_key`; `dkg_round_blocks`/`pss_refresh_blocks` genesis constants. | `src/chain/chain.cpp`, `src/chain/genesis.cpp` | 3-5 d |
| **D** | Threshold-sig integration. `creator_dh_secrets`→`creator_partial_sigs`; Phase-2 reveal becomes FROST partial over `(beacon_seed‖height)`; `compute_block_rand` aggregates t partials → canonical R; **`v2_10_active_from_height` gate goes live here** (producer/validator first read it). | `src/node/producer.cpp`, `src/chain/block.cpp` (signing_bytes binding), `src/node/validator.cpp` | 3-5 d |
| **E** | Failure modes: insufficient-partials → v1 fallback; DKG timeout → previous-epoch keys; below-threshold detection; metrics. | `src/node/dkg.cpp`, `src/node/node.cpp`, `src/chain/chain.cpp` | 3-5 d |
| **F** | Regression + migration + docs: cluster tests (R-block ceremony, silent member, complaint, PSS, same-R-from-different-subset, selective-abort-fails); wire-version bump; flag-day genesis; doc refresh. | `tools/test_*.sh`, `src/net/binary_codec.cpp`, docs | ~1 wk |

Total downstream of P0 matches the spec's ~3 weeks; **P0 is additive and was not
separately costed in the prior "2-3 day Phase A" line.**

---

## 4. Smallest-safe-first increment

**Goal:** ship one more real primitive that (a) advances Phase A, (b) needs NO
EC scalar/point backend (so it is independent of the unresolved P0 decision),
(c) is end-to-end testable in-process, and (d) cannot regress any v1 consensus
path.

### Recommended increment: `frost_aggregate` *commitment/response folding shell* — REJECTED; see below. Chosen instead: **RFC 9591 test-vector harness + `frost_sign_round1` nonce generation.**

After tracing the dependencies, the genuinely smallest safe unit is **nonce
generation for sign Round 1 plus an RFC 9591 Appendix C vector harness**, NOT
aggregation:

- `frost_aggregate` (`frost.cpp:78-84`) requires point addition + scalar-mul for
  `R := Σ(D_i + ρ_i·E_i)` and scalar sum mod L for `z`. **It needs the P0
  backend.** So it is not P0-independent and is excluded from the first
  increment.

- `frost_sign_round1` (`frost.cpp:67-69`) generates a `(hiding, binding)` nonce
  pair and their commitments. The *nonce scalars* are pure CSPRNG draws
  (reusable `src/crypto/random.cpp`), but the *commitments* are `g^nonce` — point
  mul, which again needs P0. So even round-1 is not fully P0-independent.

**Conclusion:** every remaining keygen/sign/aggregate function transitively
needs the EC backend. There is no further *primitive* that can be shipped
P0-free. Therefore the smallest safe increment is **not a primitive at all** —
it is the **validation scaffold that de-risks P0 and Phase A**:

### Chosen increment: `determ test-frost-vectors` harness (P0-independent, additive)

Add an in-process subcommand that loads the RFC 9591 Appendix C / Ed25519
ciphersuite test vectors and, for the *verify-only* surface that already ships,
asserts `frost_verify` accepts the canonical aggregate vectors and rejects every
tampered variant. This (1) locks the only shipped primitive against drift with
real RFC vectors (today's coverage is `test-view-root` scenario 27, which uses a
*self-generated* Ed25519 sig, not the RFC's published FROST aggregate — see
`FrostVerifyDelegation.md` §5), and (2) lands the vector-fixtures file that
Phase A's keygen/sign/aggregate cross-validation will reuse verbatim.

**Exact files:**
- `src/main.cpp` — new `cmd_test_frost_vectors` dispatch branch (mirrors the
  existing `test-view-root` scenario-27 block at `main.cpp:9792-9844` per
  `FrostVerifyDelegation.md` §5).
- `tools/test_frost_vectors.sh` — wrapper; add to `run_all.sh` FAST=1 regex.
- `tools/vectors/frost_ed25519_rfc9591.json` — vector fixtures (group pubkey,
  message, canonical aggregate sig) transcribed from RFC 9591 App. C.
- No change to `frost.cpp`, `frost.hpp`, `producer.cpp`, `validator.cpp`, or any
  consensus path.

**Test strategy:**
- Positive: each RFC vector's canonical `(R‖z)` verifies under its group pubkey.
- Negative: single-byte sig tamper, wrong group pubkey, single-byte message
  tamper each REJECT (mirrors `FrostVerifyDelegation.md` T-1.1/T-1.2/T-1.3).
- Edge: empty-message vector round-trips (RFC 8032 §5.1 zero-length support).
- Runs under the existing in-process test harness — no daemon, no network, no
  EC backend.

**GO / NO-GO for this increment:** **GO.** It is purely additive (new
subcommand + fixtures), touches zero consensus code, is independent of the
unresolved P0 backend decision, strengthens the regression for the one shipped
primitive against *real* RFC vectors (closing the self-generated-vector gap
flagged in `FrostVerifyDelegation.md` §5), and produces the fixture file Phase A
will reuse. It cannot regress the v1 randomness path because it does not touch
it.

**GO / NO-GO for the next step after this increment (Phase A proper):**
**NO-GO until P0 is resolved.** Porting keygen/sign/aggregate is blocked on the
§2 verdict: no scalar/point backend is linked into `determ`, and the three
in-tree docs disagree on which one it should be. Resolving P0 (pick + wire one
backend, reconcile the three docs) is the GO gate for Phase A.

---

## 5. Flag-day composition — `v2_10_active_from_height`

v2.10 follows the **exact** flag-day pattern already shipped for v2.7 F2
(`v2_7_f2_active_from_height`, `genesis.hpp:193-208`; producer/validator gate at
`producer.hpp:329`). The field exists today (`genesis.hpp:216`) but **no
producer or validator branch reads it yet** — enforcement is wired in Phase D,
per the field's own comment (`genesis.hpp:210-216`).

Activation semantics (to be implemented in Phase D, parallel to F2):

- **`block.index < v2_10_active_from_height`** → producer runs the v1
  commit-reveal path unchanged: `make_contrib` populates `dh_input`
  (`producer.cpp:647-663`); finalize calls `compute_delay_seed` +
  `compute_block_rand` over `creator_dh_secrets` (`producer.cpp:804-810`);
  `cumulative_rand` folds `delay_output` (`producer.cpp:814-822`). Validator
  recomputes identically (`validator.cpp:374,388`). **Byte-identical to today.**

- **`block.index >= v2_10_active_from_height`** → producer/validator switch to
  the FROST path: Phase-2 reveal becomes a FROST partial over
  `(beacon_seed‖height)`; `compute_block_rand` aggregates t-of-K partials into
  canonical R; `delay_output := R`.

- **Default `0`** = active from genesis (new deployments opt in from block 1).
  **`UINT64_MAX`** = never activate (chain stays on v1 commit-reveal forever),
  matching the F2 sentinel (`genesis.hpp:206-207`).

**Back-compat invariant (mirrors F2):** the field is mixed into
`compute_genesis_hash` **only when non-zero**, so existing pre-v2.10 genesis
files that omit it keep their exact chain identity. This is the same
absent-field-when-zero rule the F2 gate uses (`genesis.hpp:200-204`).

**Why the v1 path stays intact below activation:** the gate is a *height branch*
inside the producer-finalize and validator-recompute code, not a replacement.
The v1 functions (`compute_delay_seed`, `compute_block_rand`, the
`creator_dh_secrets` reveal) remain in `producer.cpp`/`validator.cpp` and are
still exercised for every pre-activation block — including during historical
sync of an already-activated chain (blocks below the flag-day height must still
validate under v1 rules). This is the same dual-path coexistence the F2 gate
already demonstrates in production.

**Flag-day migration de-risking (per `v2.10-DKG-SPEC.md` §6):** validator-side
dry-run for ~100 blocks pre-flag-day (log FROST-vs-v1 mismatches without
rejecting); DKG ceremony runs at the flag-day epoch boundary; threshold signing
activates at the subsequent block; pre-flag-day commit-reveal continues to
validate old blocks during sync.

---

## 6. Did any verifier correction change the conclusion?

**Yes — one correction materially changed the prerequisite verdict.**

The task brief framed the EC-primitive prerequisite as: "FROST needs Ed25519
scalar + point arithmetic, which raw OpenSSL `EVP_PKEY_ED25519` does NOT expose
— this is a load-bearing prerequisite to check," and noted "libsodium is linked
for the wallet ... but NOT necessarily for the daemon."

Verification confirmed the OpenSSL half **and sharpened the libsodium half into
a hard blocker plus a documentation contradiction:**

1. **libsodium is definitively NOT linked into the `determ` daemon** (only into
   `determ-wallet` + `oprf`; `determ-light` explicitly excludes it). CMakeLists
   line evidence: daemon links `ssl crypto nlohmann_json` only (98-102).

2. **`src/crypto/frost.cpp` calls no libsodium function** — the
   `crypto_core_ed25519_*` references are comments only; the file includes just
   `frost.hpp` + `keys.hpp`. So the header's "uses the already-vendored
   libsodium" claim (`frost.hpp:15-16`) is **false against the actual code**.

3. **The designated C99 backend `src/crypto/ed25519/` does not exist**, and
   `CRYPTO-C99-SPEC.md` is itself "specification only, no code."

4. **Three in-tree docs name three mutually-exclusive backends** (libsodium per
   frost.hpp; independent `ref10` per the DKG spec; libsodium-free per the C99
   spec). None is wired.

This turns the prerequisite from "check whether OpenSSL suffices" (answer: no)
into a **standalone gating decision (P0)** that must precede Phase A and that the
prior cost estimates did not budget. The conclusion is therefore **BLOCKED-ON-
PREREQ**, not a simple GO, for Phase A proper — while the §4 smallest-safe
increment (test-vector harness) remains a clean **GO** precisely because it was
chosen to sidestep P0.
