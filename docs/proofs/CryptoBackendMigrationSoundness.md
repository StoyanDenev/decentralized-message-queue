# CryptoBackendMigrationSoundness — the §3.15 consensus-crypto backend migration (OpenSSL → `determ::c99`)

This document is the soundness argument for the 2026-07-03 backend swap that moved the daemon's and light client's **consensus-path cryptography** off EOL OpenSSL 1.1.1w onto the in-tree `determ::c99` stack (`DECISION-LOG.md` 2026-07-03, "§3.15 daemon crypto migration SHIPPED (1b)", lines 1154-1166; `CRYPTO-C99-SPEC.md §3.15`, lines 852-875). Three production surfaces changed backend: `SHA256Builder` (`src/crypto/sha256.cpp` — the streaming hash behind every block hash, tx root, merkle/state root, and genesis hash), Ed25519 keygen/sign/verify (`src/crypto/keys.cpp` — the only shipped signature backend), and OS entropy (`src/crypto/rng/rng.c` — the per-round `dh_secret` and node keygen, formerly OpenSSL `RAND_bytes`).

The proof exists because a crypto-backend swap under a consensus system is a **fork-class hazard by default**: if two nodes ever disagree by one byte on a hash, or by one accept/reject decision on a signature, the chain splits. The argument below shows the hazard is closed along both axes — (i) every consensus-deterministic output is **byte-identical** across backends and toolchains, machine-checked; and (ii) the one deliberate semantic change (the strict RFC 8032 verify rule) is a **pre-genesis strengthening** whose divergence surface is confined to adversarial non-canonical encodings that no honest signer emits, locked in before any live fleet existed to fork.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A4** = CSPRNG uniform secret sampling (§2.3). Note a naming drift this migration creates: `Preliminaries.md` still parenthesizes A4 as "(`RAND_bytes`)" (line 62); post-§3.15 the instantiation of A4 is `determ_rng_bytes` (§3.4 below). The *assumption* (the OS CSPRNG yields uniform secrets) is unchanged; only the function that draws from it changed.

**Companion documents.** `DECISION-LOG.md` (the 2026-07-03 §3.15 entry — the shipping decision + evidence this document formalizes; also the preceding 1a/UBSan entries, lines 1130-1152, whose gates the evidence table reuses); `CRYPTO-C99-SPEC.md` §3.15 (migration status), §Q9 (the byte-equal cross-validation discipline, lines 382-409); `C99CryptoStackAudit.md` (adversarial audit of the C99 stack itself); `ConstantTimeInventory.md` (the CT posture of the new backend — orthogonal to the equivalence argument here); `EnvelopeKeyfileCrypto.md` (the wallet-envelope surface CB-5 leaves out of scope); `Preliminaries.md §2.0` (assumption labels). Every proof in the corpus that invokes A1/A2/A4 composes with this document per §6.

---

## 1. Scope

**In scope — the consensus path, exactly three production surfaces:**

1. **SHA-256.** `src/crypto/sha256.cpp` (`SHA256Builder`) now runs on the C99 FIPS 180-4 streaming engine `determ_sha256_init/update/final` (`src/crypto/sha2/sha256.c`, API at `include/determ/crypto/sha2/sha2.h:44-53`) instead of OpenSSL EVP. Every consensus artifact — block hash, tx root, merkle/state root, genesis hash — flows through this builder.
2. **Ed25519.** `src/crypto/keys.cpp` (`generate_node_key` / `sign` / `verify`) now calls `determ_ed25519_pubkey_from_seed` / `_sign` / `_verify` (`src/crypto/ed25519/ed25519.c`, contract at `include/determ/crypto/ed25519/ed25519.h`) instead of OpenSSL `EVP_PKEY_ED25519`.
3. **Entropy.** The daemon's two entropy sites — node keygen (`keys.cpp:36-37`) and the per-round `dh_secret` (`node.cpp:847-848`) — now call `determ_rng_bytes` (`src/crypto/rng/rng.c`), a thin shim over BCryptGenRandom / getrandom(2)+`/dev/urandom`, instead of OpenSSL `RAND_bytes`.

Auxiliary migrated sites (RPC-auth HMAC on `determ_hmac_sha256`, `light/keyfile.cpp` derivation — per `CRYPTO-C99-SPEC.md:862-864`; CLI pubkey derivations, genesis salt — per `DECISION-LOG.md:1158`) inherit the same primitives and the same equivalence argument; they are not consensus-rule-bearing and are not separately theoremized.

**Out of scope:**

- The internal correctness/audit of the C99 primitives themselves (`C99CryptoStackAudit.md`) and their constant-time posture (`ConstantTimeInventory.md`). This document takes the primitives as audited and argues *migration* soundness: that swapping them under the consensus path changes nothing it must not change.
- The wallet's keyfile/backup envelopes (PBKDF2 + AES-256-GCM + base64), which remain on OpenSSL by design (CB-5, §4.5).
- Key format migration — there is none: the raw private key IS the 32-byte RFC 8032 seed under both backends, so existing `node_key.json` files load identically (`keys.cpp:6-8`; `DECISION-LOG.md:1162`).

---

## 2. Threat model

Two failure classes a backend migration can introduce; the claims of §4 are organized against them.

### 2.1 `T-fork` — migration-introduced determinism divergence

The adversary here is not a person but a *deployment configuration*: any pair of nodes whose backends (or compilers) disagree on a consensus-deterministic function. One byte of divergence in any of `{SHA-256 digest, Ed25519 public key derivation, Ed25519 signature bytes, signature accept/reject}` forks the chain — silently, at the first block that exercises the divergent input. This class is real and recent in this tree: the 1a second-platform gate's **first run** caught a cross-toolchain `state_root` fork (the `ShardId` shift-UB, `DECISION-LOG.md:1130`), which is exactly why the migration was gated on both-platform golden-vector validation.

### 2.2 `T-weak` — migration-introduced cryptographic weakening

A hostile-input adversary in the standard sense: one who submits adversarially-encoded signatures or public keys to the verifier, or who benefits from weak/predictable entropy. Concretely: (a) a verify rule that accepts encodings the old rule rejected (a strengthened forgery/malleability surface); (b) an entropy path that silently degrades to a weak or partially-initialized secret (a predictable `dh_secret` breaks the commit-reveal selective-abort defense, `node.cpp:838-846`; a predictable node seed breaks A1 outright).

The migration must be shown to make `T-weak` no worse (CB-3, CB-4) — and on the documented non-canonical-encoding class it makes it strictly better (CB-3.4).

---

## 3. The migration surface (load-bearing facts, from source)

### 3.1 SHA-256 is a fixed function; the builder's encodings are unchanged

SHA-256 is a *deterministic standard function*: same input bytes, same digest, for any correct implementation. So backend equivalence for the hash reduces to two obligations: (i) the C99 engine is a correct FIPS 180-4 implementation (validated byte-equal against OpenSSL and against CAVP/NIST vectors — §5), and (ii) the **input bytes fed to it are unchanged**. Obligation (ii) is owned by `src/crypto/sha256.cpp` itself: the consensus-critical part of that file is the big-endian integer encodings in `append(uint64_t)`/`append(int64_t)` (`sha256.cpp:37-45`), which are pure C++ byte loops untouched by the swap (`sha256.cpp:10-13` header comment). The streaming shape is preserved 1:1 — `determ_sha256_init/update/final` reproduces OpenSSL's `EVP_DigestInit/Update/Final` structure (`sha2.h:36-43`), and the one-shot `determ_sha256` is reimplemented **on the same engine**, so the CAVP + §Q9 gates that validate the one-shot validate the streaming form too (`sha2.h:39-41`; `CRYPTO-C99-SPEC.md:856-858`). `determ_sha256_final` additionally zeroizes the ctx (`sha256.cpp:49`; `sha2.h:41-43`) — a hardening ridealong, invisible to outputs.

### 3.2 Ed25519 signing is deterministic; key format and EVP semantics are preserved

RFC 8032 Ed25519 signing is a **pure function of (seed, message)** — no signer randomness (`ed25519.h:32-34`). Therefore "backend equivalence for signing" is a byte-equality statement, testable on a grid, not a distributional one. Two preserved behaviors matter:

- **Key format.** The raw private key is the 32-byte RFC 8032 seed under both backends (`keys.cpp:6-8`); pubkey derivation is RFC 8032 §5.1.5 (`ed25519.h:26-28`). No keyfile rewrite, no re-registration.
- **EVP semantics on mismatched keyfiles.** OpenSSL's EVP signing ignored the stored `NodeKey.pub` and worked from the seed; `crypto::sign` reproduces this by re-deriving the public key from the seed before signing (`keys.cpp:67-77`), so a hand-edited keyfile with a mismatched stored pub behaves identically across backends.

### 3.3 Ed25519 verify: the one deliberate semantic change (strict RFC 8032 gates)

`crypto::verify` (`keys.cpp:79-83`) now calls `determ_ed25519_verify`, which enforces the RFC 8032 canonicality gates **before** the verification equation (`ed25519.c:321-349`):

- `ed25519.c:329` — reject a non-canonical public key with `y ≥ q` (RFC 8032 §5.1.3; `point_y_is_canonical`, `ed25519.c:245-259`);
- `ed25519.c:330` — reject `S ≥ L` (RFC 8032 §5.1.7; `sc_lt_L`, `ed25519.c:231-243`), which is exactly the gate that makes `(R, S+L)` non-verifying — signatures are unique.

The equation check itself is the standard cofactorless RFC 8032 form: recompute `[S]B − [k]A`, pack canonically, constant-time-compare against the signature's `R` bytes (`ed25519.c:341-346`). The in-tree contract states the backend difference exactly as far as the source verifies it: the C99 verifier is "intentionally STRICTER than OpenSSL's lenient ref10 decoder on adversarial inputs" (`ed25519.h:43-45`; `keys.cpp:10-16`), with the concrete divergence documented for the pubkey gate — ref10 accepts the 19 non-canonical `y` in `{q..q+18}` that the C99 gate rejects (`ed25519.c:248-251`). No claim is made (or needed — CB-3.3) about which non-canonical `S` encodings the old backend tolerated. Honest signers never produce a rejected input: the signer emits canonical `S` via `modL` (`ed25519.c:231-235` comment) and canonical point encodings by construction. This is the single consensus-visible rule change of the migration, and CB-3 argues its safety.

### 3.4 Entropy: fail-fatal OS CSPRNG, no userspace RNG

`determ_rng_bytes` (`rng.c`) is a shim with **no userspace RNG state, no seeding logic, and no fallback to anything weaker than the kernel CSPRNG** (`rng.h:1-13`): BCryptGenRandom with the system-preferred RNG on Windows (`rng.c:9-20`), getrandom(2) on Linux with a `/dev/urandom` continuation for the remaining bytes on non-EINTR errors such as ENOSYS on pre-3.17 kernels (`rng.c:31-64` — `/dev/urandom` is the same kernel CSPRNG, differing only in getrandom's block-until-initialized boot guarantee). On any failure it returns −1 with the contract that the buffer contents MUST NOT be used (`rng.h:24-27`). Both consensus call sites honor the contract by throwing before the secret escapes: keygen at `keys.cpp:34-37` (the fresh `NodeKey` is never returned) and the per-round `dh_secret` at `node.cpp:844-848` (thrown before assignment to `current_round_secret_`).

### 3.5 What remains on OpenSSL

Per `CMakeLists.txt:141-152` (comment + link line): the `determ` daemon keeps libcrypto **only** for (a) the §Q9 test-oracle subcommands (`test-*-c99` cross-validate the C99 stack against an independent implementation — by design a non-determ backend) and (b) wallet-shared helpers compiled into the daemon. `determ-light` links **zero** OpenSSL (`CMakeLists.txt:239-251`). `determ-wallet` keeps OpenSSL for its keyfile/backup envelopes (`CMakeLists.txt:181-197`; the 1c follow-up, `DECISION-LOG.md:1164`). libssl (TLS — never used; no TLS anywhere in `src/net`) is dropped from every target (`CMakeLists.txt:146-147`).

---

## 4. Soundness claims

### 4.1 CB-1 (SHA-256 backend equivalence — every consensus hash byte-identical)

**Statement.** For every input the consensus path can produce, the post-migration `SHA256Builder` emits the same digest bytes the OpenSSL-backed builder emitted, on both shipped toolchains (MSVC x64, GCC 13). Consequently no block hash, tx root, merkle/state root, or genesis hash moved: the migration is hash-invisible to the chain.

**Argument.** Three independent legs, composed:

1. **Fixed function + engine correctness.** SHA-256 admits exactly one output per input; the C99 engine matches OpenSSL byte-for-byte over lengths 0..300 (covering the single-block, multi-block, and both 55/56 padding edges) plus a 1 MiB multi-block message — the §Q9 gate in `determ test-sha2-c99` (`src/main.cpp:14118-14168`), which needs no transcribed digest and is thus immune to KAT-transcription error (`main.cpp:14098-14104`). Independent published anchors: FIPS 180-4 KATs in the same subcommand (`main.cpp:14142-14156`) and the NIST CAVP corpora `sha2_cavp_sha256.json` / `sha2_cavp_sha512.json` run by `determ test-c99-vectors` (`main.cpp:13284-13290`).
2. **Unchanged input encoding.** The builder's big-endian `append(uint64_t/int64_t)` loops — the only place `sha256.cpp` itself could change consensus bytes — are unmodified (`sha256.cpp:37-45`, §3.1). The streaming call sequence maps 1:1 onto the old EVP sequence, and the streaming form is validated through the same gates as the one-shot because the one-shot wraps it (`sha2.h:36-43`).
3. **End-to-end golden pin, both toolchains.** `determ test-consensus-vectors` (`src/main.cpp:38114-38126`) pins GOLDEN hex for genesis_hash + `compute_state_root()` + head block_hash over a fixed scenario battery including the composite `i:`/`m:`/`p:` namespaces; the goldens — generated **pre-swap** — **held byte-for-byte on both MSVC and GCC post-swap** (`DECISION-LOG.md:1162`). This is the direct machine check of the claim's conclusion, not merely of its premises: had any consensus hash moved, this gate is constructed to go RED.

Legs 1-2 make divergence *implausible*; leg 3 makes the observed absence of divergence *evidence*, on both platforms. ∎

### 4.2 CB-2 (Ed25519 signing equivalence — key derivation + signature bytes)

**Statement.** For every (seed, message) pair, the post-migration `crypto::sign` emits the same 64 signature bytes, and `generate_node_key`/pubkey-derivation the same 32 public-key bytes, as the OpenSSL EVP backend. Existing identities, registrations, and any pre-swap signed material remain valid unmodified.

**Argument.**

1. **Determinism makes equivalence testable.** RFC 8032 signing has no randomness (`ed25519.h:32-34`), so byte-equality on a grid is a meaningful equivalence check — there is exactly one valid signature per (key, message), and reproducing it pins the whole signing pipeline (nonce derivation, scalar arithmetic, point encoding).
2. **Fuzzed-grid byte-equality vs the OpenSSL oracle.** `determ test-ed25519-c99` cross-validates both pubkey derivation and signature bytes against `EVP_PKEY_ED25519`/`EVP_DigestSign` over a fuzzed (seed, message-length) grid spanning lengths 0..200 (`src/main.cpp:11442-11476`) plus a 100000-byte extreme-length message exercising the streamed SHA-512 interior (`main.cpp:11478-11498`) — the §Q9 gate for this primitive.
3. **Independent standard anchor.** The RFC 8032 §7.1 KATs: TEST 1 pubkey + signature literals inside `test-ed25519-c99` (`main.cpp:11428-11440`), and the four-vector KAT battery in `determ test-ed25519-vectors` — written explicitly as the **backend-swap detector** (`main.cpp:14293-14304`) — which now runs through the *shipped* `crypto::sign/verify` path on the C99 backend and passes (`DECISION-LOG.md:1162`). A backend diverging in key derivation fails the pubkey check; one diverging in signing fails verify, since no alternative valid signature exists under RFC 8032 (`main.cpp:14313-14322`).
4. **Call-site parity.** Key format (raw seed) and the EVP re-derive-from-seed semantics are preserved at the `keys.cpp` layer (§3.2), so equivalence of the primitives lifts to equivalence of the shipped functions. ∎

### 4.3 CB-3 (verify-rule strengthening is SAFE pre-genesis)

**Statement.** The strict verifier enforces the two RFC 8032 canonicality gates (reject `S ≥ L`, reject non-canonical pubkey `y ≥ q`) ahead of the standard verification equation, so its rejections beyond the equation are confined to non-canonical encodings — inputs no honest signer emits — and every honestly-generated signature verifies identically under both backends (machine-checked, CB-2). Because Determ has no live fleet, adopting the strict rule pre-genesis carries zero fork risk, and from genesis the strict rule simply **is** the consensus signature-validity rule. The strengthening kills the `(R, S+L)` malleability class: signatures are unique per (pk, msg).

**Argument.**

1. **Gates-then-equation structure.** `determ_ed25519_verify` computes the standard cofactorless RFC 8032 verification equation (recompute `[S]B − [k]A`, compare canonical packing against `R` — `ed25519.c:341-346`) behind two up-front reject gates (`ed25519.c:329-330`). Relative to any verifier of that same equation, added reject gates can only shrink the accept set — they admit nothing new — so the strict rule's entire divergence budget is *rejections*, and every gate-rejection is by construction a non-canonical encoding. On honestly-generated signatures the backends are machine-checked to agree: every honest signature is gate-passing and verifies identically under both (the CB-2 grid + the accept/tamper probes — `keys.cpp:14-16`; `ed25519.h:44-45`). Exhaustive adversarial-input equivalence with OpenSSL is neither claimed nor needed (§7.1): point 3 makes the residual question moot.
2. **The divergence surface is adversarial-only.** The gate-rejected inputs are precisely non-canonical encodings: scalar encodings with `S ≥ L` (in particular the `S+L` re-encoding of a valid `S`), and pubkeys with `y ≥ q` (exactly the 19 encodings `{q..q+18}` expressible in the 255-bit `y` field — `ed25519.c:248-251`). The RFC-conformant signer cannot emit them — `S` is produced by `modL` reduction (`ed25519.c:231-235`), and point encodings are packed reduced mod q. So no honest participant, no existing keyfile, and no honestly-signed historical artifact is affected; only a forger exercising the malleability/wrapped-encoding class loses inputs.
3. **No fleet ⇒ no fork event.** A verify-rule change on a *live* chain is coordinated-fork-class: mixed-version validators would disagree on adversarial signatures and split. Determ has no live fleet (`DECISION-LOG.md:1160`), so there is no transition, no rolling upgrade, and no window in which two rules coexist. From genesis, the strict rule is not an emulation of OpenSSL's behavior — it is the **definition** of signature validity for the chain (`keys.cpp:79-83` comment; `CRYPTO-C99-SPEC.md:870-875`). Any future second implementation must conform to *it* (locked by the KAT + tamper-reject gates of §5).
4. **Malleability closure.** `(R, S+L)` satisfies the verification equation itself — `[S+L]B = [S]B`, since `B` has order `L` — so any verifier with no `S`-range gate accepts two wire-distinct valid signatures for one (pk, msg), a hazard for any protocol that ever keys on signature bytes. The `S < L` gate closes the class outright: the honest signature is the unique accepted encoding (`ed25519.h:40-43`), and the canonical-pubkey gate keeps "one point = one encoding" on the key side (`ed25519.c:245-252`). The post-migration rule is at least as strict as the old backend on every axis the source documents, and strictly stricter on the pubkey-canonicality class (`ed25519.c:248-251`). ∎

### 4.4 CB-4 (entropy soundness — fail-fatal, no weak fallback, no partial secret)

**Statement.** Post-migration, every consensus secret (node key seed, per-round `dh_secret`) is drawn from the OS kernel CSPRNG or not at all: entropy failure is fatal at both call sites, there is no userspace RNG or weaker fallback, and a partially-filled or all-zero secret can never be used. A4 holds with `determ_rng_bytes` as its instantiation, with strength equal to the OS CSPRNG — the same ultimate source `RAND_bytes` drew from.

**Argument.**

1. **No weak path exists in the shim.** `rng.c` contains only kernel-CSPRNG calls: BCryptGenRandom(system-preferred) on Windows; getrandom(2) with a `/dev/urandom` continuation on POSIX (§3.4). There is no time/PID seeding, no userspace state to compromise or fork-duplicate, and no code path that returns success with fewer than `n` kernel-provided bytes: both branches loop to completion or return −1 (`rng.c:11-19`, `rng.c:36-63` — the short-read `got == 0` case returns −1 at `rng.c:57`).
2. **Failure is fatal at both consensus sites.** `generate_node_key` throws on a non-zero return before the key ever leaves the function (`keys.cpp:36-37` — "an all-zero/partial seed must never become a node identity", `keys.cpp:34-35`); the round-secret site throws before `current_round_secret_` is assigned (`node.cpp:847-848` — "a predictable dh_secret breaks the commit-reveal"). By the shim's contract (`rng.h:24-27`) the buffer is treated as poisoned on failure, and both callers discard it by unwinding.
3. **What A4-consuming proofs need is preserved.** The selective-abort defense (`SelectiveAbort.md`/FA3 lineage) and A1 both require uniform, per-use-fresh secrets; the kernel CSPRNG provides them exactly as before. The `getrandom → /dev/urandom` continuation does not weaken this in any deployed configuration (§7.3 notes the boot-time-edge honestly). ∎

### 4.5 CB-5 (residual-OpenSSL isolation — oracle-only in `determ`; wallet out of consensus scope)

**Statement.** After the migration, no consensus-rule-bearing code path in any Determ binary executes OpenSSL. The residual linkage is (a) the §Q9 cross-validation oracle inside `determ`'s `test-*-c99` subcommands — present *by design*, since cross-validation requires an independent non-determ implementation — and (b) the wallet's keyfile/backup envelopes, which are an offline, operator-local surface with no consensus role. The EOL 1.1.1w liability is therefore out of the consensus path entirely.

**Argument.**

1. **`determ-light`: zero OpenSSL.** The light client's whole crypto surface (SHA-256 via `src/crypto/sha256.cpp`, Ed25519 via `src/crypto/keys.cpp` + `light/keyfile.cpp`) runs on `determ-crypto-c99`; the target links no OpenSSL at all (`CMakeLists.txt:239-251`). The trust-minimized verification pipeline (the `LightClientThreatModel.md` family) is thus fully off the EOL library.
2. **`determ`: oracle + wallet-shared helpers only.** The daemon's link line keeps `crypto` (libcrypto) solely for the §Q9 test oracles and the wallet-shared helpers compiled into the daemon binary (`CMakeLists.txt:141-152`). The oracle usage is *load-inverted*: OpenSSL is the thing being compared **against**, inside test subcommands (`main.cpp:11459-11467`, `14133`); removing it would remove the independent cross-check, not a production dependency. Consensus execution (`sha256.cpp`, `keys.cpp`, `rng.c` call sites) contains no OpenSSL calls — verified by reading those files in full (§3).
3. **Wallet envelopes: out of consensus scope.** `determ-wallet` is a separate binary precisely so wallet secret material never shares address space with the networked daemon (`CMakeLists.txt:181-197`); its PBKDF2 + AES-256-GCM + base64 envelope work never touches block validity, state roots, or signature rules. Migrating it is the separable 1c follow-up, gated on the documented c99 AES-GCM decrypt-direction gap (`CRYPTO-C99-SPEC.md:897-905`; `DECISION-LOG.md:1164`), and can proceed without touching consensus.
4. **libssl: deleted everywhere.** TLS was never used by any target (no TLS in `src/net`); libssl is dropped from every link line (`CMakeLists.txt:146-147`), shrinking the residual surface to libcrypto-as-oracle + wallet-envelope. ∎

---

## 5. Verification evidence

All gates below ran green post-swap on **both** shipped platforms — MSVC x64 (Windows) and GCC 13 (Linux, via `tools/ci_local.sh`, the 1a second-platform gate) — per `DECISION-LOG.md:1162` ("both platforms' FAST suites ran green"). The §Q9 oracle comparisons execute inside the `determ` binary against its residual libcrypto (§4.5.2).

| Gate (test name) | Where | What it proves | Claim served | Result |
|---|---|---|---|---|
| `determ test-sha2-c99` | `src/main.cpp:14096` | C99 SHA-256/512 byte-equal to OpenSSL over lengths 0..300 (block + padding edges) + 1 MiB; FIPS 180-4 KATs; HMAC grids vs OpenSSL | CB-1 leg 1 | PASS, MSVC + GCC |
| `determ test-c99-vectors` | `src/main.cpp:13259` | NIST CAVP corpora (`sha2_cavp_sha256.json`, `sha2_cavp_sha512.json`, `main.cpp:13289`) + the full file-side KAT battery through the shipped C99 code; fail-closed on any missing/unknown vector class | CB-1 leg 1 | PASS, MSVC + GCC |
| `determ test-consensus-vectors` | `src/main.cpp:38114` | Cross-toolchain GOLDEN hex: genesis_hash + `compute_state_root()` + head block_hash over a fixed battery incl. composite `i:`/`m:`/`p:` namespaces; pre-swap goldens **held byte-for-byte post-swap** | CB-1 leg 3 (the end-to-end pin) | PASS, MSVC + GCC (`DECISION-LOG.md:1162`) |
| `determ test-ed25519-c99` | `src/main.cpp:11407` | RFC 8032 §7.1 TEST 1 anchors; pubkey + signature byte-equal to OpenSSL EVP over the fuzzed (seed, mlen 0..200) grid + 100000-byte message; verify accept/tamper-reject semantics | CB-2, CB-3.1 | PASS, MSVC + GCC |
| `determ test-ed25519-vectors` | `src/main.cpp:14293` | The designed **backend-swap detector**: RFC 8032 §7.1 four-vector KATs through the shipped `crypto::sign/verify` (now C99); one bit of divergence in derivation or deterministic signing fails loudly | CB-2 | PASS with C99 backend, MSVC + GCC (`DECISION-LOG.md:1162`) |
| FAST suite (`tools/run_all.sh FAST=1`) | `tools/` | The full offline regression surface over the swapped binary | all | GREEN, both platforms (`DECISION-LOG.md:1162`) |
| UBSan gate (`tools/ci_local.sh --sanitize`) | `DECISION-LOG.md:1142-1148` | The C99 crypto stack (31 subcommands) + consensus surface run abort-on-UB clean after the TweetNaCl negative-shift fixes — no UB-class determinism fork latent in the new backend | CB-1/CB-2 (toolchain-independence) | `SAN_FAIL=0` (GCC 13; pre-migration, on the code the migration ships) |

Evidence-shape note (house discipline): the byte-equality gates are *live cross-executions against an independent oracle in the same process*, not transcribed expectations — the class of test that cannot drift stale; the golden-vector gate is the *static* cross-toolchain complement (`main.cpp:38115-38124`). Together they cover both divergence axes of `T-fork` (backend × toolchain).

---

## 6. Composition

### 6.1 Every A1/A2 consumer in the corpus survives the swap unchanged

The proof corpus invokes A1 (Ed25519 EUF-CMA) and A2 (SHA-256 collision resistance) as *properties of the mathematical primitives*, never as properties of OpenSSL. CB-1/CB-2 establish that the functions computing those primitives are extensionally unchanged on the consensus path (identical input→output maps), so every reduction to A1/A2 — the `Safety.md` FA1 fork-freedom argument, the light-client family (`StateRootAnchorSoundness.md` SR-1..SR-3, `TxInclusionProofSoundness.md`, `LightClientThreatModel.md` T-L1..T-L4), the merkle/state-commitment family — composes with the new backend with **no restatement**. Where a proof cites a concrete bound (`2⁻¹²⁸`), the bound was always the primitive's, not the library's.

### 6.2 CB-3 strengthens, and slightly re-grounds, A1-adjacent claims

Consumers of signature *uniqueness* get a new, stronger footing: pre-swap, EUF-CMA gave "no forgery on a new message", but wire-level `(R, S+L)` mutation of an *existing* signature was outside its guarantee — nothing in the pre-swap contract excluded it (EUF-CMA does not speak to encoding uniqueness). Post-swap the accepted encoding is unique by an explicit gate (CB-3.4). Proofs that only assumed EUF-CMA are unaffected; anything that keys on signature bytes (dedup, evidence records) is now safe against that mutation class by construction. From genesis, "valid signature" in every corpus document denotes the strict rule of §3.3.

### 6.3 A4's instantiation

Proofs invoking A4 (fresh uniform secrets — the FA3 selective-abort lineage, keygen) now read through `determ_rng_bytes` (CB-4). The assumption content is unchanged; `Preliminaries.md:62`'s parenthetical "(`RAND_bytes`)" is a stale name for the instantiation, flagged here for the next Preliminaries touch (a naming drift, not a soundness gap).

### 6.4 CB-5 bounds what the 1c follow-up must re-argue

Because residual OpenSSL is oracle-only + wallet-envelope (CB-5), the eventual 1c cleanup (bump/isolate/remove the vendored 1.1.1w) is a *non-consensus* change: it can be argued entirely within `EnvelopeKeyfileCrypto.md`'s scope plus test-tooling notes, with no re-validation of the chain rules. This document is the boundary certificate for that claim.

---

## 7. Limitations (honest)

1. **Adversarial-input equivalence with OpenSSL is not claimed — and is not needed.** The byte-equality evidence for VERIFY covers the accept path (honestly-generated signatures, both backends accept identically) and tamper-reject probes; it does not exhaustively compare the two backends on the full space of malformed encodings. This is deliberate: pre-genesis lock-in (CB-3.3) makes the C99 rule the *definition* of validity rather than an emulation of OpenSSL, so residual lenient-rule behaviors on garbage inputs are simply not part of the consensus rule. Any future second validator implementation must match the strict rule, for which the KAT + canonicality gates are the conformance surface.
2. **The grid is a sample, not a proof of the field arithmetic.** CB-2's fuzzed grid + KATs + the 100000-byte probe give strong but finite coverage of the C99 scalar/point arithmetic; the deeper assurance for the arithmetic itself lives in `C99CryptoStackAudit.md` (adversarial audit) and the UBSan gate (§5), not in this document. A latent divergence outside all gates' coverage would be a `T-fork` event; the mitigation is the standing both-platform golden-vector contract, which turns any such event RED at test time rather than at fork time.
3. **The POSIX urandom continuation has a boot-time edge.** On pre-3.17 kernels (no getrandom) or exotic getrandom failures, `/dev/urandom` may serve before the kernel pool is initialized on first boot (§3.4). No shipped Determ deployment targets such kernels, and the Windows path has no analogous edge; noted for completeness, not remediated.
4. **CT posture is out of scope here.** The constant-time properties of the C99 backend (no key-dependent branches/indices — `ed25519.h:6-11`) are inventoried in `ConstantTimeInventory.md`; this document only argues migration equivalence and rule safety.
5. **Wallet envelopes remain on EOL OpenSSL** until 1c (CB-5.3). That is a bounded, non-consensus residual, tracked in `CRYPTO-C99-SPEC.md:897-905`.

---

## 8. Cross-references

| Component | File / location | Role in this proof |
|---|---|---|
| Migration decision + evidence record | `docs/proofs/DECISION-LOG.md:1154-1166` | The shipped 1b decision; the pre-genesis insight (`:1160`); both-platform byte-invariance results (`:1162`); residual-OpenSSL scope (`:1164`). |
| Migration status (spec) | `docs/proofs/CRYPTO-C99-SPEC.md:852-905` (§3.15) | Per-surface migration inventory; wallet residuals; §Q9 discipline at `:382-409`. |
| SHA-256 consensus builder | `src/crypto/sha256.cpp` (header `:4-13`; BE encodings `:37-45`) | CB-1: the swapped surface; unchanged input encodings. |
| C99 streaming SHA-256 API | `include/determ/crypto/sha2/sha2.h:36-53` | CB-1: EVP-shape parity; one-shot wraps the engine so gates validate both; final zeroizes ctx. |
| Ed25519 key/sign/verify wrapper | `src/crypto/keys.cpp` (header `:4-16`; keygen `:32-40`; sign `:67-77`; verify `:79-83`) | CB-2/CB-3/CB-4: the swapped surface; seed-format + EVP-semantics parity; strict verify as consensus rule; fatal entropy. |
| Strict-verify contract | `include/determ/crypto/ed25519/ed25519.h:38-45` | CB-3: the S < L + canonical-pubkey gates and the uniqueness statement. |
| Strict-verify implementation | `src/crypto/ed25519/ed25519.c:321-349` (gates `:329-330`; `sc_lt_L` `:231-243`; `point_y_is_canonical` `:245-259`) | CB-3: gates precede the standard equation; signer emits canonical S via modL (`:231-235`). |
| OS-entropy shim | `include/determ/crypto/rng/rng.h` + `src/crypto/rng/rng.c` | CB-4: kernel-CSPRNG-only, fail-fatal contract (`rng.h:24-27`). |
| Round-secret entropy site | `src/node/node.cpp:844-848` | CB-4: fatal on failure before `current_round_secret_` assignment. |
| Link-line isolation | `CMakeLists.txt:141-152` (daemon), `:239-251` (light, zero OpenSSL), `:181-197` (wallet) | CB-5: residual libcrypto is oracle + wallet-envelope only; libssl dropped. |
| `test-sha2-c99` | `src/main.cpp:14096` | Evidence: §Q9 SHA-2 byte-equal gate + FIPS KATs. |
| `test-c99-vectors` | `src/main.cpp:13259` (CAVP files `:13284-13290`) | Evidence: CAVP corpora through shipped code, fail-closed. |
| `test-consensus-vectors` | `src/main.cpp:38114` | Evidence: cross-toolchain golden pin; the end-to-end CB-1 check. |
| `test-ed25519-c99` | `src/main.cpp:11407` | Evidence: RFC 8032 anchors + fuzzed-grid OpenSSL cross-validation. |
| `test-ed25519-vectors` | `src/main.cpp:14293` | Evidence: the backend-swap detector, now green on the C99 backend. |
| `Preliminaries.md §2.0` | `docs/proofs/Preliminaries.md:59-62` | A1/A2/A4 labels; A4's stale `RAND_bytes` parenthetical (§6.3). |
| `C99CryptoStackAudit.md` | `docs/proofs/` | The primitive-level adversarial audit this document builds on (out of scope here). |
| `ConstantTimeInventory.md` | `docs/proofs/` | CT posture of the new backend (out of scope here). |
| `EnvelopeKeyfileCrypto.md` | `docs/proofs/` | The wallet-envelope surface CB-5 excludes; home of the 1c argument. |

---

## 9. Status

- **Migration.** SHIPPED 2026-07-03 (authorized by Stoyan Denev, the 1b decision): daemon + light consensus crypto on `determ::c99`; `determ-light` links zero OpenSSL; libssl dropped everywhere (`DECISION-LOG.md:1154-1166`).
- **Proof.** Complete (this document). CB-1..CB-5 cover hash equivalence, signing equivalence, verify-rule strengthening safety, entropy soundness, and residual isolation.
- **Machine evidence.** All §5 gates green on MSVC x64 + GCC 13 post-swap; the pre-swap `test-consensus-vectors` goldens held byte-for-byte on both — the strongest single artifact, since it checks the *conclusion* (no consensus byte moved), not just the premises.
- **The load-bearing insight.** Pre-genesis timing dissolves the migration's only semantic change: the strict RFC 8032 verifier (S < L, canonical pubkey) diverges from the old backend only by *rejecting* non-canonical encodings no honest signer can produce, and with no live fleet there is no transition — from genesis the strict rule **is** the consensus signature-validity rule, and `(R, S+L)` malleability is dead by construction.
- **Assumptions used.** A1, A2, A4 per `Preliminaries.md §2.0`; A4 now instantiated by `determ_rng_bytes` (naming drift in Preliminaries flagged, §6.3).
- **Open residuals.** Wallet envelopes on OpenSSL until 1c (non-consensus, CB-5); the POSIX boot-time urandom edge (§7.3, no shipped deployment affected).
