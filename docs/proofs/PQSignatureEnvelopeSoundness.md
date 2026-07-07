> **TIER: NEAR-TERM — 1.1.x in-flight.** The envelope module + client tooling are shipped and green; the §3.21 inc.4 `PQ_TRANSFER` consensus accept-rule (Option B, PQ-native bearer address) is now shipped too and state-root-invariant (see §Trust-Root §3.2). Roadmap index: docs/ROADMAP.md

# PQSignatureEnvelopeSoundness — the DPQ1 post-quantum transaction-authentication envelope: wire format / security properties / the honest account-level trust-root non-claim / coverage accounting

This document is the "what is proven-in-code vs. what is argued-in-prose" honest accounting for the **DPQ1 post-quantum transaction-authentication envelope** — `determ::pqauth`, CRYPTO-C99-SPEC.md **§3.21**:

- the envelope module `src/crypto/pqauth.cpp` (+ `include/determ/crypto/pqauth.hpp`), which binds a transaction's canonical signed message to an **ML-DSA (FIPS 204)** signature, optionally in **HYBRID** with Ed25519;
- the independent Python oracle `tools/verify_pqauth.py` + the frozen corpus `tools/vectors/pqauth.json`;
- the client tooling `light/pq_sign_tx.cpp` (`determ-light pq-sign-tx` / `pq-verify-tx`).

It composes over the already-gated **ML-DSA** stack (`src/crypto/mldsa/`, CRYPTO-C99-SPEC §3.16 — the full FIPS 204 scheme, every operation pinned byte-for-byte against the NIST ACVP keyGen/sigGen/sigVer KATs) and the already-gated **Ed25519** stack (`src/crypto/ed25519.c`, RFC 8032, ACVP/RFC-vector-pinned). It **adds only** the byte layout, a domain-separation context, and the hybrid composition — no new hardness assumption and no new field/group arithmetic above those two gated primitives.

This is **library-primitive-first + client-tooling, ZERO consensus touch.** The `pqauth` module carries no chain call site; `light/pq_sign_tx.cpp` is offline client tooling that touches no consensus path. **The consensus accept-rule that would admit a DPQ1-authenticated transaction is a separate, owner-gated, consensus-critical step** — and, as §Trust-Root makes precise, that step is *load-bearing* for the one property this layer cannot provide on its own: **account-level quantum resistance.**

## Scope

**In scope.** The exported operations of `determ::pqauth`, the dual-oracle corpus, and the client tooling, verified against the source:

- **`pqauth::sign(scheme, message, mldsa_seed, [ed_seed])`** — deterministic serialization of a DPQ1 envelope binding `message` (the chain's `Transaction::signing_bytes`).
- **`pqauth::verify(envelope, message)`** — memory-safe, fail-closed verification of an attacker-controlled envelope against `message`.
- **The wire format** DPQ1 and the exact signed messages (§1).
- **The client round-trip** `pq-sign-tx` → `pq-verify-tx` over a real transaction's canonical `signing_bytes`.

**Out of scope.**
- **Account-level quantum resistance** — NOT provided by this layer alone; it requires the consensus accept-rule to bind the account address/state to the ML-DSA key (the central **§Trust-Root** non-claim, PQE-NC-1).
- **The ML-DSA and Ed25519 primitives themselves** — their KeyGen/Sign/Verify correctness + KAT conformance are discharged by §3.16 (ML-DSA, ACVP) and the Ed25519 gates, not re-derived here. This document treats a verifying ML-DSA / Ed25519 signature as a black-box witness of its cited security property.
- **Any chain / wallet / mempool wiring** — no Determ *consensus* path constructs or verifies a DPQ1 envelope (PQE-NC-2). The only consumer in-tree is the offline `determ-light` tooling.
- **Timing side channels** — the ML-DSA `Sign_internal` was CT-hardened (§3.16 inc.1; the `chknorm`/`center` branches on secret data removed); this document asserts only **functional** soundness, not a timing proof (PQE-L-4).
- **Confidentiality / privacy** — an authentication envelope binds a message; it hides nothing and is not a confidential-transaction primitive (that is the separate §3.19/§3.22 stack; see [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md)).

**Authoritative external sources.** NIST **FIPS 204** (ML-DSA / CRYSTALS-Dilithium) — the module-lattice signature scheme and its `Sign_internal`/`Verify_internal` + the "external" `M'` framing (`0x00 ‖ len(ctx) ‖ ctx ‖ M`, ctx the domain-separation context) of FIPS 204 §5.2; NIST **ACVP** ML-DSA KATs — the byte-level conformance oracle for §3.16; **RFC 8032** (Ed25519) — the deterministic EdDSA signature the hybrid tail carries. ML-DSA's EUF-CMA security rests on Module-LWE / Module-SIS (assumed, not proved here — PQE-L-1); Ed25519's EUF-CMA rests on the discrete log over Curve25519 (assumed, classically hard, quantum-broken by Shor — PQE-L-2).

---

## 1. The DPQ1 wire format and the signed messages

### 1.1 Wire layout (v1)

An envelope is the concatenation (`src/crypto/pqauth.cpp`, mirrored in `tools/verify_pqauth.py`):

```
MAGIC(4)="DPQ1" | scheme(1) | pq_pk_len(2 BE) | pq_pk | pq_sig_len(2 BE) | pq_sig | [ ed_pk(32) | ed_sig(64) ]
```

- **`MAGIC`** = the 4 ASCII bytes `DPQ1`.
- **`scheme`** is exactly one of `{0x01,0x02,0x03,0x11,0x12,0x13}`: the low nibble selects the ML-DSA parameter set (`1`→ML-DSA-44, `2`→ML-DSA-65, `3`→ML-DSA-87); the `0x10` bit marks a **HYBRID** envelope that additionally carries the Ed25519 tail. `scheme_valid()` rejects every other byte (`(s & 0xE0) == 0` and the only high-nibble bit permitted is `0x10`).
- **`pq_pk_len` / `pq_sig_len`** are 2-byte big-endian lengths. On verify they are **not trusted**: each must equal the scheme's expected `determ_mldsa_pk_bytes` / `sig_bytes` exactly, else fail-closed (`pqauth.cpp:120,127`).
- **`pq_pk`** is the ML-DSA public key **recovered by KeyGen from the seed** at sign time (the envelope is self-describing — it carries its own verification key), and **`pq_sig`** is the ML-DSA signature over `M'` (§1.2).
- **The `ed_pk ‖ ed_sig` tail (32 + 64 = 96 bytes)** is present **iff** `scheme & 0x10`. `ed_sig` covers **`scheme ‖ message`** (scheme-bound, like the ML-DSA half) so the hybrid cannot be stripped/relabelled to a valid pq-only envelope over the same message (PQE-2).

Concrete lengths from the frozen corpus (`tools/vectors/pqauth.json`): ML-DSA-44 pq-only = **3741 B**, ML-DSA-65 = **5270 B**, ML-DSA-87 = **7228 B**, hybrid-ML-DSA-65 = **5366 B** (= 5270 + 96).

### 1.2 The exact signed messages

- **ML-DSA half** signs the **domain-separated, scheme-bound external message**
  ```
  M' = 0x00 | len(CTX') | CTX' | message ,   CTX' = "determ-pqtx-v1" || scheme  (15 bytes)
  ```
  This is the FIPS 204 §5.2 "external" `Sign(sk, M, ctx)` framing with `ctx = CTX'` where **the 1-byte scheme discriminator is appended to the context** (`format_mprime`, `pqauth.cpp`). Appending the scheme byte binds the scheme choice into the signature (the downgrade defence, see PQE-2). The framing is handed to the ML-DSA wrapper as an already-formatted `M'` — the `determ::c99::mldsa::sign/verify` wrappers take `mprime` **raw** and add no domain-separation of their own — so the `CTX'` binding is exactly and only what this document claims it is.
- **Ed25519 half** (hybrid only) signs **`scheme || message`** (`ed_message`, `pqauth.cpp`) — deterministic RFC 8032 detached 64-byte signature — so the Ed25519 half is scheme-bound too; stripping the tail and relabelling to a pq-only scheme breaks the ML-DSA half's scheme binding (PQE-2).

Here `message` is the chain's canonical `Transaction::signing_bytes` (`src/chain/block.cpp:17` — `type ‖ from ‖ 0 ‖ to ‖ 0 ‖ amount(8 BE) ‖ fee(8 BE) ‖ nonce(8 BE) ‖ payload`). The client tooling recomputes it byte-for-byte via the shared `compute_signing_bytes` on both the sign and verify sides (`light/pq_sign_tx.cpp:125,176`), so what the envelope binds is exactly what the chain hashes into the tx.

### 1.3 Determinism

Every field is a pure function of `(scheme, message, mldsa_seed, [ed_seed])`: ML-DSA KeyGen and `Sign_internal` are deterministic (the hedging `rnd` is the 32 zero bytes), Ed25519 is deterministic per RFC 8032, and the length prefixes are fixed by the scheme. Two `sign` calls with the same inputs produce byte-identical envelopes (`test-pqauth` "determinism" assertion; and the dual-oracle re-derives the same bytes from a second implementation — PQE-5).

---

## 2. Security properties (PQE-1 .. PQE-5)

**PROVEN-in-code** = byte-pinned or reject-witnessed by a shipped, green test (named in §4). **argued-in-prose** = a reduction to the cited FIPS 204 / RFC 8032 / lattice-assumption result (assumed, not machine-checked here).

- **PQE-1 (message integrity / authenticity — the envelope binds `message` under ML-DSA EUF-CMA).** A `pqauth::verify(env, message)` that returns `ok=true` witnesses that the ML-DSA signature in `env` verifies against `M'(message)` under the public key `env.pq_pk`. Under ML-DSA's **EUF-CMA** security (FIPS 204, Module-LWE/Module-SIS), an adversary without the signing key cannot produce, for a `message` it has not obtained a signature on, an envelope that verifies — so accepting `env` authenticates `message` to the holder of the ML-DSA key `pq_pk`. **Proven-in-code:** the round-trip + wrong-message-reject + tamper-reject assertions of `test-pqauth` (per scheme) show the deployed accept path fires exactly on the bound message and rejects a 1-bit-flipped message or a tampered signature; the client `pq-verify-tx` rejects a tampered `amount` (exit 3, `test_light_pq_sign.sh`). **argued-in-prose:** EUF-CMA itself is FIPS 204 + the lattice assumptions (PQE-L-1) — the tests witness the reject paths, they are **not** a machine-checked forgery reduction.

- **PQE-2 (HYBRID = break-BOTH — a hybrid envelope survives a classical break of *either* primitive).** For a hybrid scheme (`0x11/0x12/0x13`), `verify` returns `ok = pq_ok && ed_ok` (`pqauth.cpp:150`): **both** the ML-DSA signature over `M'` **and** the Ed25519 signature over the raw `message` must verify. Therefore forging a hybrid envelope for a fresh `message` requires forging **ML-DSA AND Ed25519** on that same message. A classical adversary who breaks Ed25519 (e.g. a future ECDLP advance, or a quantum computer running Shor) still faces ML-DSA; an adversary who breaks ML-DSA (e.g. a lattice cryptanalysis advance) still faces Ed25519. The hybrid is thus **defense-in-depth**: its security is the *max* of the two primitives' security, not the min. **Scheme-binding (downgrade defence).** The scheme byte is bound into BOTH signatures — appended to the ML-DSA context (`CTX' = CTX ‖ scheme`) and prepended to the Ed25519 message (`scheme ‖ message`). Without this, a hybrid envelope (`0x12`) could be relabelled to the same-param pq-only scheme (`0x02`) with the Ed25519 tail dropped, and the unchanged ML-DSA signature would still verify — stripping the belt-and-braces off a hybrid message (a real MEDIUM audit finding, fixed). With the binding, the relabel changes `CTX'`, so the ML-DSA signature no longer verifies. **Proven-in-code:** `test-pqauth`'s "hybrid ed-half tamper reject" + "hybrid pq-half tamper reject" (each half alone → reject; `ok = pq_ok && ed_ok`) **and** "hybrid-strip downgrade rejected" (relabel `0x12`→`0x02` + drop the 96-byte tail → INVALID). **argued-in-prose:** the "unforgeable unless BOTH broken" claim is the composition of the two EUF-CMA properties (PQE-L-1/L-2). **Honest bound:** hybrid removes *single-primitive* break as a forgery path; account-level PQ resistance for a PQ-native account comes from the §3.21 inc.4 accept-rule (§Trust-Root), now shipped as Option B.

- **PQE-3 (domain separation via CTX — no cross-protocol signature reuse).** The ML-DSA half signs `M' = 0x00 ‖ len(CTX) ‖ CTX ‖ message` with `CTX = "determ-pqtx-v1"`, never the bare `message`. The `0x00` prefix + length-prefixed context is the FIPS 204 §5.2 external framing, which is **prefix-free** in the context string: a signature produced under a *different* context (a different application's `ctx`, or the "pure" `ctx = ε` interface) yields a different `M'` and will not verify here, and vice-versa. So a DPQ1 ML-DSA signature cannot be lifted into another ML-DSA protocol that reuses the same key under a different domain tag, nor can a foreign signature be replayed as a DPQ1 one. **Proven-in-code:** the corpus + dual-oracle pin the exact `M'` framing byte-for-byte (both implementations independently prepend `0x00 ‖ 0x0e ‖ CTX`), so any drift in the context string or its length byte is a byte-mismatch failure. **argued-in-prose:** that this framing achieves cross-protocol separation is the FIPS 204 domain-separation argument (assumed). **Honest bound:** `CTX` separates DPQ1 from *other ML-DSA domains*; it does not separate two transactions **within** DPQ1 — that is the job of `message` = `signing_bytes`, whose `nonce`/`from`/`to`/`amount` fields make each tx's bound message unique (replay is a chain accept-rule concern, PQE-NC-2). The Ed25519 half signs the raw `message` with **no** `CTX`, by design, so the chain's existing Ed25519 path can verify it; the hybrid's PQ resistance rests on the ML-DSA half (the Ed25519 half is the classical belt-and-braces), so the un-separated Ed25519 half does not weaken PQE-2.

- **PQE-4 (parser is memory-safe + fail-closed on any malformed envelope).** `pqauth::verify` is `noexcept` and treats the envelope as fully attacker-controlled. Every read is bounds-checked by the local `need(n)` guard before it happens; the scheme byte is validated (`scheme_valid`); both length prefixes must **equal** the scheme's expected sizes (a lying length cannot over-read — it fails the `!= exp` check *before* the `need`); the hybrid tail requires its full 96 bytes; and the parse requires `off == env.size()` at the end, so **any trailing byte is a reject** (`pqauth.cpp:140`). A `catch(...)` returns a default (rejecting) `VerifyResult` on anything unexpected (`pqauth.cpp:153`). No path allocates on an unvalidated length, indexes past `env.size()`, or throws to the caller. **Proven-in-code:** `test-pqauth`'s malformed battery — bad magic, truncation, trailing byte, unknown scheme, empty input — each required to yield `ok=false`; plus every field-length mismatch is structurally impossible to accept because the length must equal the scheme constant. **argued-in-prose:** none beyond "the enumerated reject cases are representative"; the guard structure is exhaustive by construction (bounds-check-before-read on every field).

- **PQE-5 (determinism → the dual-oracle byte-freeze).** The shipped C++ `pqauth::sign` recomputes every corpus envelope byte-for-byte, and an **independent from-scratch Python** implementation (`tools/verify_pqauth.py`: pynacl Ed25519 + the from-scratch python ML-DSA signer `verify_mldsa_keygen`/`verify_mldsa_sign` — hashlib SHAKE + a python NTT, a distinct code path from the C) reproduces the **same** bytes from the same seeds+message. Two independent implementations agreeing on one frozen corpus means a divergence with both green is *our* bug, not the vectors'. **Proven-in-code:** `test-pqauth` (C side, "corpus byte-equal + verify" per vector) + `tools/verify_pqauth.py` (Python side) over `tools/vectors/pqauth.json` (4 vectors), both driven by `tools/test_pqauth.sh`. **argued-in-prose:** none — this property *is* the byte-equality gate.

---

## 3. §Trust-Root — the crucial honest limitation (PQE-NC-1)

**This is the load-bearing non-claim of the entire document. Read it before treating DPQ1 as "post-quantum".**

DPQ1, on its own — as a library + client-tooling layer — provides **(a)** message integrity/authenticity under the stated primitive assumptions (PQE-1) and **(b)** hybrid defense-in-depth (PQE-2). It does **NOT**, on its own, provide **account-level quantum resistance.**

**Why.** An envelope is *self-describing*: it carries its own ML-DSA public key `pq_pk` inside the bytes, and `verify` authenticates the message *to whatever key the envelope names*. Quantum resistance of an **account** requires that a quantum adversary cannot **substitute its own ML-DSA key** and spend that account's funds. That guarantee can only come from **binding the ML-DSA public key at a level the quantum adversary cannot forge — i.e. the account ADDRESS or the on-chain STATE — enforced by the consensus accept-rule.** The `pqauth` layer binds the key only *within the envelope*; nothing here ties `pq_pk` to any particular account.

Concretely, today an account address is a **bearer form over the Ed25519 key**: `make_anon_address(pk) = "0x" ‖ hex(pk)` for a 32-byte Ed25519 `pk` (`include/determ/types.hpp:153`; a 66-char `0x…` string). A quantum adversary who can run Shor recovers the Ed25519 private key from that public address and spends — **and a DPQ1 envelope does not help, because no accept-rule requires the envelope's ML-DSA key to match the account.** Until such an accept-rule exists, DPQ1 is a *transport for a PQ signature*, not *PQ account security*.

### 3.1 The two known on-chain binding options (design-level; owner-gated)

Making an account quantum-resistant means choosing how the address commits to the ML-DSA key. Two forms are known:

- **Option A — hash-based address: `address = H(form ‖ pubkey ‖ …)`.** The address is a hash that commits to the ML-DSA public key (and a form/version tag). The `pq_pk` is revealed only at spend time, inside the envelope, and the accept-rule checks `H(form ‖ envelope.pq_pk ‖ …) == address`. A quantum adversary who wants to substitute a key must find a *second preimage* of the address hash — hard even quantumly (Grover gives only a square-root speedup on preimage search, defeated by adequate hash length). This is the more conservative form (the key is hash-committed, not exposed until spend).
- **Option B — bearer address: `address = form-prefix ‖ pubkey`.** The address *is* (a prefix plus) the ML-DSA public key, analogous to today's Ed25519 bearer form. The accept-rule checks `envelope.pq_pk == address[after-prefix]`. Simpler and stateless, but the ML-DSA key is public from first use; its PQ resistance then rests **entirely** on ML-DSA's EUF-CMA (no hash-preimage backstop), and ML-DSA public keys are large (1312/1952/2592 B for ML-DSA-44/65/87) so a raw-bearer address is correspondingly large.

**Both are owner-gated and reopen the anon-address derivation freeze.** The current `make_anon_address` (Ed25519 bearer) is a frozen consensus-visible derivation; either option changes it, which **reopens `AnonAddressDerivationMigration`** — an owner-authority decision, not one this layer may take. (Per the project's governance record, on-chain PQ was owner-authorized to reopen exactly that freeze.)

### 3.2 The on-chain step is designed to be state-root-invariant for PQ-free chains

The consensus integration adds a **new `TxType::PQ_TRANSFER`** for a DPQ1-authenticated transaction, leaving **every existing tx type byte-identical**. Because `Transaction::signing_bytes` and the state-leaf encoding for the existing types are unchanged, and the `pq_auth` field is serialized only when non-empty, a chain that uses no PQ transactions produces a **byte-identical state root** before and after the feature — the new machinery is dormant until the first PQ tx. This mirrors the project's "additive TxType, existing bytes frozen" discipline and keeps the change a *pure extension*, not a migration of existing accounts.

**Status: SHIPPED (§3.21 inc.4).** The owner chose **Option B (PQ-native bearer address)** — `address = "0x" ‖ hex(form) ‖ hex(ML-DSA pubkey)`, form 0x01/02/03 = ML-DSA-44/65/87 (`determ::pq_address`; the length can never alias the fixed 66-char Ed25519 anon address, so the two address spaces are disjoint). The accept-rule is the shared `determ::chain::verify_pq_transaction` (called by BOTH the block validator and mempool admission): it recovers the ML-DSA key from `from`, verifies the PQ-ONLY DPQ1 envelope over `signing_bytes`, and **requires `envelope.pq_pk == address key`** — the binding that makes the account quantum-resistant (a quantum adversary cannot substitute its own ML-DSA key). This is the closure of PQE-NC-1 **for PQ-native accounts** (existing Ed25519 anon accounts remain classical, by design). Proven by `test-pq-transaction` (accept + fail-closed on tampered amount / non-PQ type / non-PQ `from` / empty envelope / **key ≠ address key** / hybrid) and by FAST state-root invariance (the golden vectors are byte-identical). See the §3.21 inc.4 accept-rule sources: `src/crypto/pq_address.cpp`, `src/chain/pq_tx_auth.cpp`, `src/node/validator.cpp`, `src/node/node.cpp`.

---

## 4. Coverage map

| Property | Proven-in-code (shipped, green) | argued-in-prose (reduction) | Status |
|---|---|---|---|
| **PQE-1** message integrity / authenticity | `test-pqauth` — per-scheme round-trip + wrong-message-reject + tamper-reject; `test_light_pq_sign.sh` — tampered `amount` → INVALID (exit 3) | ML-DSA EUF-CMA = FIPS 204 + Module-LWE/SIS (PQE-L-1) | code (reject/accept witnesses) + prose (EUF-CMA) |
| **PQE-2** HYBRID = break-BOTH | `test-pqauth` — "hybrid ed-half tamper reject" + "hybrid pq-half tamper reject" (each half alone → reject; `ok = pq_ok && ed_ok`) | composition of the two EUF-CMA properties (PQE-L-1/L-2) | code (AND witness) + prose (composition) |
| **PQE-3** domain separation via CTX | `test-pqauth` + `verify_pqauth.py` corpus — the `0x00‖len(CTX)‖CTX‖message` framing pinned byte-for-byte by both implementations | FIPS 204 §5.2 external-framing separation argument | code (byte-pinned framing) + prose (separation) |
| **PQE-4** memory-safe + fail-closed parser | `test-pqauth` — malformed battery (bad magic, truncation, trailing byte, unknown scheme, empty) all → `ok=false`; length-must-equal-scheme + `off==size` no-trailing check | exhaustive by construction (bounds-check-before-read on every field) | code (fail-closed witnesses) |
| **PQE-5** determinism → dual-oracle byte-freeze | `test-pqauth` (C side, "corpus byte-equal + verify") + `tools/verify_pqauth.py` (independent python ed25519 + from-scratch ML-DSA) over `tools/vectors/pqauth.json` (4 vectors), driven by `tools/test_pqauth.sh` | — (this property *is* the byte gate) | code (byte-pinned, dual-oracle) |
| **§Trust-Root** account-level PQ resistance | — (no accept-rule code exists) | requires the consensus accept-rule to bind address/state → ML-DSA key (Option A/B, §3.1) — owner-gated, NOT shipped | **NON-CLAIM (PQE-NC-1)** |

The two-leg split is the standard §3.13 defense-in-depth: the structural `test-pqauth` subcommand is the **round-trip + reject-path + malformed-fail-closed** witness the accept-only corpus cannot provide; the dual-oracle (`test-pqauth` C side + `verify_pqauth.py` python side over one frozen corpus) is the **byte-conformance** witness. Their conjunction — bounded by PQE-L-1..L-5 and the §Trust-Root non-claim — is what "DPQ1 is a deterministic, byte-conformant, fail-closed, hybrid-defense-in-depth *message*-authentication envelope under the stated primitive assumptions" means for this §3.21 library + tooling layer. It is **not** a claim of account-level post-quantum security; that is the owner-gated §Trust-Root work.

---

## 5. Non-claims (PQE-NC-1 .. PQE-NC-3) and limits (PQE-L-1 .. PQE-L-5)

### Non-claims
- **PQE-NC-1 — Account-level quantum resistance is NOT provided by this layer.** DPQ1 binds `message` to whatever ML-DSA key the envelope names; it does **not** bind that key to an account. Quantum-resistant accounts require the consensus accept-rule to commit the address/state to the ML-DSA key (Option A hash-based or Option B bearer, §3.1) — owner-gated, NOT shipped. Until then DPQ1 provides message integrity/authenticity + hybrid defense-in-depth, **not** PQ account security. **This is the load-bearing honest limitation (§3 / §Trust-Root).**
- **PQE-NC-2 — Not a consensus / wallet / mempool primitive.** No Determ consensus path constructs, verifies, or admits a DPQ1 envelope. The `pqauth` module has no chain call site; the only in-tree consumer is the offline `determ-light pq-sign-tx` / `pq-verify-tx` client tooling. Chain integration (the new `TxType` + accept-rule, §3.2) is a separate, owner-gated, consensus-critical step. Replay/nonce enforcement is a chain accept-rule concern, not the envelope's.
- **PQE-NC-3 — Not confidentiality / not privacy.** An authentication envelope binds a message in the clear; it hides no amount, sender, receiver, or the fact a transaction exists. Amount-hiding is the separate §3.19/§3.22 confidential-transaction stack ([`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md)).

### Limits
- **PQE-L-1 — ML-DSA EUF-CMA is assumed, not proved here.** PQE-1/PQE-2's PQ half rest on FIPS 204 ML-DSA's EUF-CMA security (Module-LWE / Module-SIS). This document treats a verifying ML-DSA signature as a black-box EUF-CMA witness; the §3.16 gates pin **byte-conformance to ACVP KATs**, which is *not* a security proof of the scheme. A cryptanalytic break of ML-DSA breaks PQE-1 (and the PQ half of PQE-2) regardless of any byte-exactness here.
- **PQE-L-2 — Ed25519 EUF-CMA is assumed and is classical-only.** The hybrid Ed25519 half rests on RFC 8032 EdDSA / discrete log over Curve25519 — **broken by Shor** on a scalable quantum computer. That is *by design* (it is the classical belt-and-braces of the hybrid); the PQ resistance of a hybrid envelope rests on the ML-DSA half (PQE-2).
- **PQE-L-3 — Bounded input set.** PQE-5's byte-exactness quantifies over exactly the frozen corpus (4 vectors: ML-DSA-{44,65,87} pq-only + hybrid-65) at fixed seeds/message. The structural `test-pqauth` exercises all six schemes for round-trip/tamper/malformed but on a single message per scheme. Determinism/soundness for arbitrary inputs follow from the §1 construction + the cited primitive properties, not exhaustive coverage. (The corpus omits hybrid-44 and hybrid-87 envelopes; `test-pqauth` does exercise those two schemes structurally for round-trip + both-half-tamper, so the hybrid AND-logic is witnessed on all three ML-DSA sizes even though only hybrid-65 is byte-frozen.)
- **PQE-L-4 — Timing not proven here.** ML-DSA `Sign_internal` was CT-hardened (§3.16 inc.1); this document asserts only functional soundness, not a machine-checked timing proof. The empirical `ct-timing-probe` measurement is the separate operator step (CRYPTO-C99-SPEC §3.12 / [`ConstantTimeInventory.md`](ConstantTimeInventory.md)). Envelope *verification* operates on public data (attacker-controlled envelope + public message), so its branching is not a secret-dependent timing concern.
- **PQE-L-5 — Self-describing key ≠ authenticated key.** `verify` authenticates `message` to the key the envelope *carries*; it performs no check that `pq_pk` (or `ed_pk`) is the *expected* account key. Binding the carried key to an account is exactly the §Trust-Root accept-rule work (PQE-NC-1). Callers who use `pqauth::verify` without such a binding get message-integrity-to-a-named-key, nothing more.

---

## 6. Status

- **Spec.** Complete (this document); CRYPTO-C99-SPEC §3.21 (design entry).
- **Envelope module + client tooling shipped and green.** `determ test-pqauth` (per-scheme round-trip + recovered-pubkeys + determinism + wrong-message/tamper/hybrid-both-half/malformed rejection + corpus byte-equality) + `tools/verify_pqauth.py` (independent python ed25519 + from-scratch ML-DSA oracle) over `tools/vectors/pqauth.json` (4 vectors), driven by `tools/test_pqauth.sh`; `tools/test_light_pq_sign.sh` (the offline `determ-light pq-sign-tx` → `pq-verify-tx` round-trip over a real tx's `signing_bytes`, incl. tampered-`amount` reject).
- **Claims.** PQE-1 (message integrity/authenticity under ML-DSA EUF-CMA), PQE-2 (HYBRID = break-BOTH, `ok = pq_ok && ed_ok`), PQE-3 (CTX domain separation), PQE-4 (memory-safe + fail-closed parser), PQE-5 (determinism → dual-oracle byte-freeze) — all closed at the code/prose split recorded in §4.
- **Non-claims (PQE-NC-1..NC-3).** Account-level PQ resistance is NOT provided by this layer (the §Trust-Root owner-gated accept-rule work — the load-bearing limitation); not a consensus/wallet/mempool primitive; not confidentiality/privacy.
- **Limits (PQE-L-1..L-5).** ML-DSA / Ed25519 EUF-CMA assumed (not proved; Ed25519 is classical-only); conformance is over a 4-vector frozen corpus + a single-message-per-scheme structural battery; timing → §3.12 / `ConstantTimeInventory.md`; a self-describing key is not an authenticated account key.

Cross-references: CRYPTO-C99-SPEC.md §3.21 (DPQ1 design entry), §3.16 (ML-DSA / FIPS 204 stack + ACVP KATs), §3.13 (the dual-oracle vector gate), §3.12 (constant-time posture); `src/crypto/pqauth.cpp` + `include/determ/crypto/pqauth.hpp` (the module); `tools/verify_pqauth.py` + `tools/vectors/pqauth.json` (the dual-oracle corpus); `light/pq_sign_tx.cpp` (the client tooling); `src/chain/block.cpp` (`Transaction::signing_bytes` — the bound message); `include/determ/types.hpp` (`make_anon_address` — today's Ed25519 bearer address, the §Trust-Root hook); [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (the sibling PQ-adjacent §3.19/§3.22 confidential-tx stack); [`ConstantTimeInventory.md`](ConstantTimeInventory.md) (the CT posture).
