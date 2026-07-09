> **TIER: NEAR-TERM — 1.1.x in-flight.** The A5 PQ anon-address HASH form (Option A) is shipped, green, and state-root-invariant for PQ-free chains (commit `e6d8ee9`, owner GO 2026-07-09). Roadmap index: docs/ROADMAP.md

# PqHashAddressSoundness — the A5 PQ anon-address HASH commitment scheme: address binding / cross-mechanism separation / the account-security composition

This document is the "proven-in-code vs. argued-in-prose" honest accounting for the **A5 PQ anon-address HASH form (Option A)** — the address *commitment scheme* `determ::pq_address` (CRYPTO-C99-SPEC §3.21 inc.4) together with the consensus accept-rule `determ::chain::verify_pq_transaction` that composes it with a DPQ1 envelope into an account-level spend authorization. Frozen at genesis per pre-launch register item A5 (owner 2026-07-09), commit `e6d8ee9`.

**This is distinct from — and composes over — [`PQSignatureEnvelopeSoundness.md`](PQSignatureEnvelopeSoundness.md).** That document proves the DPQ1 *envelope* (`determ::pqauth`): that a verifying envelope is a black-box witness of ML-DSA EUF-CMA over `signing_bytes` (its PQE-1..5), and it explicitly **defers** account-level quantum resistance to a consensus accept-rule (its §Trust-Root / PQE-NC-1). **This document proves exactly that deferred piece:** the address-commitment scheme and the recompute-and-compare accept-rule that binds the envelope's key to an account. Envelope internals (wire layout, `M'` framing, hybrid downgrade defence) are cited as a black box, never re-derived.

## Scope

**In scope**, verified against the source at the anchors cited:

- **`make_pq_anon_address(form, pk)`** = `"0x" + hex(SHA256(u8(len(DST)) ‖ DST ‖ u8(form) ‖ u32_be(len(pk)) ‖ pk))`, `DST = "determ-pq-anon-addr-v1"` (22 B) — `src/crypto/pq_address.cpp:59-81`, `PQ_ADDR_DST` at `:18-19`.
- **`pq_form_pk_bytes` / `pq_scheme_to_form`** — the form→pk-length (1312/1952/2592) and pure-scheme→form maps — `pq_address.cpp:26-46`.
- **`is_pq_anon_address` / `normalize_pq_anon_address`** — the 66-char `0x`+64hex shape recognizer and lowercase canonicaliser — `pq_address.cpp:48-91`.
- **`verify_pq_transaction`** — the recompute-and-compare accept-rule — `src/chain/pq_tx_auth.cpp:9-43`.
- **Routing** — `src/node/validator.cpp:540-542` (block-validator PQ_TRANSFER branch), `src/node/node.cpp:2135` (mempool), `:3781-3790` (RPC canonicalization), `src/chain/chain.cpp:1194` (COMPOSABLE_BATCH inner whitelist), `:802-803` (apply).
- **The dual-oracle** — `tools/verify_pq_address.py` + `tools/vectors/pq_address.json`, the C corpus cross-check `src/main.cpp:13263-13286`, and the independent `chk_pq_address` / `pq_addr_ref` in `tools/test_c99_vector_files.sh:1288-1349`.

**Out of scope.**

- **ML-DSA EUF-CMA and SHA-256 collision/preimage resistance** — assumed, discharged by §3.16 (ACVP) + the crypto stack, not re-derived here (PHA-L-1).
- **The DPQ1 envelope** — a black box; [`PQSignatureEnvelopeSoundness.md`](PQSignatureEnvelopeSoundness.md).
- **The Ed25519 anon-address family** — UNCHANGED and classical, separately owner-frozen 2026-07-03 (PHA-NC-1).
- **Confidentiality / privacy** — the §3.22 confidential-transaction stack, not an address concern.

---

## 1. The address-commitment scheme

### 1.1 A commitment, not a bearer key

A PQ address is a **non-invertible 66-char commitment to `(form, ML-DSA pubkey)`** — not the bearer key. That was the deliberate replacement of the shipped-then-removed Option-B bearer format; because a hash cannot be inverted, the inverse helpers `parse_pq_anon_pubkey` and `pq_anon_address_form` were **deleted** — they cannot exist for a hash (`pq_address.hpp:14-18`). Verification therefore never recovers a key *from* an address; it recomputes the address from a **carried** key and compares (§2, PHA-1).

The preimage is length-framed and injective:

```
addr = "0x" + hex( SHA256( u8(22) ‖ "determ-pq-anon-addr-v1" ‖ u8(form) ‖ u32_be(len(pk)) ‖ pk ) )
form: 0x01 = ML-DSA-44 (pk 1312 B) / 0x02 = ML-DSA-65 (1952 B) / 0x03 = ML-DSA-87 (2592 B)
```

The `SHA256Builder` appends each field in order (`pq_address.cpp:67-79`). A wrong-length or unknown-form pk throws before any hash is emitted (`:61-64`), so an address is **never** derived from an ambiguous input.

### 1.2 Why each preimage field

- **Length-framed DST** (`u8(len) ‖ DST`) — a self-delimiting, injective domain tag mirroring pqauth's `len(CTX) ‖ CTX`; it separates this hash use from every other SHA-256 use in the chain (tx hashes, Merkle/consensus digests).
- **`form` byte** — the discriminator MUST be *inside* the preimage so related-byte keys across parameter sets can never share an address, and the binding cannot be stripped post-launch (PHA-4).
- **`u32_be(len(pk))`** — endian-fixed, keeps the preimage injective across the differing form lengths and against any future variable-length form.
- **FULL pk, never truncated** — the commitment binds the *entire* verification key, so no two keys differing outside a hashed window can alias (the truncation canary, PHA-5 bit-flip vector).

---

## 2. Theorems (PHA-1 .. PHA-5)

### PHA-1 — Commitment binding

*Statement.* A `PQ_TRANSFER` from `from` is accepted only if the carried DPQ1 envelope both **verifies** and **recomputes** to `from`; forging a spend from a given `from` requires a SHA-256 preimage of an output the attacker cannot choose, on top of ML-DSA EUF-CMA.

*Proof (in code).* `verify_pq_transaction` (`pq_tx_auth.cpp`) runs, in order: reject non-`PQ_TRANSFER` (`:11`); require canonical shape (`:18-19`); `vr = pqauth::verify(pq_auth, signing_bytes)`, require `vr.ok` (`:21-23`); reject `vr.hybrid` (`:26`); `form = pq_scheme_to_form(vr.scheme)`, reject `form == 0` (`:27-28`); require `vr.pq_pk.size() == pq_form_pk_bytes(form)` (`:31`); and finally **`make_pq_anon_address(form, vr.pq_pk) == tx.from`** (`:38`). The `vr.pq_pk` fed into the recompute is provably *the very key whose signature verified*: `pqauth::verify` computes `pq_ok` over `pq_pk` (`pqauth.cpp:161`) and then **moves that same buffer** into the result (`r.pq_pk = std::move(pq_pk)`, `:170`) — there is no second key path.

*Reduction.* Acceptance thus requires an ML-DSA key `K` with (a) a valid ML-DSA signature over the tx and (b) `SHA256(preimage(form, K)) == from`. Forging from a *given* `from` without its key is a SHA-256 **preimage** search onto an uncontrollable target — classical 2^256, Grover 2^128 — strictly stronger than the recover-and-compare of the deleted bearer form (which had no preimage backstop).

### PHA-2 — Shape-collision safety

*Statement.* The hash address shares the Ed25519 anon shape and the same string-keyed account store, yet the two families cannot cross-spend below the chain's uniform 2^128 classical level.

*Setup (in code).* `is_pq_anon_address` and `is_anon_address` are byte-identical (below); both families key into the **same** `accounts_[tx.from]` map (`chain.cpp:795`), and PQ apply *is* TRANSFER apply (case fall-through, `chain.cpp:802-803`). Separation is **strictly by `tx.type` at the router** (PHA-3), never by shape.

*Direction 1 — Ed25519-spend a PQ address.* A non-PQ tx from a PQ-address string routes to the Ed25519 path (`from_anon = is_anon_address`, `validator.cpp:526`, `node.cpp:2137`), which verifies `tx.sig` under `pk = parse_anon_pubkey(from)` — the *identity* decoding of the 32 hash bytes (`types.hpp:144-155`). The attacker must forge an Ed25519 signature under a pubkey equal to a SHA-256 output it cannot steer: **classical EUF-CMA ≈ 2^128** (see PHA-L-2 for the quantum bound).

*Direction 2 — PQ-spend an Ed25519 address.* A `PQ_TRANSFER` from an Ed25519-address string routes to `verify_pq_transaction`, which requires `make_pq_anon_address(form, K) == from` where `from` is the victim's Ed25519 pubkey-hex — a SHA-256 **preimage** onto a fixed uncontrollable target: **2^256** (Grover 2^128).

### PHA-3 — Routing determinism

*Statement.* `tx.type` is the *sole* discriminator between the families, and the two shape predicates can never disagree.

*Proof (in code).* The block validator branches on `tx.type == PQ_TRANSFER` (`validator.cpp:540`) with every other type in the `else`; mempool admission is the identical one-line gate (`node.cpp:2135`); a `COMPOSABLE_BATCH` cannot smuggle a PQ tx — its inner whitelist hard-requires `inner.type == TxType::TRANSFER` (`chain.cpp:1194`). `is_pq_anon_address` (`pq_address.cpp:48-57`) and `is_anon_address` (`types.hpp:115-126`) are **byte-identical predicates** (same `size()==66` guard, same `0x` prefix check, same hex-digit classification over an equal index range), so no string is ever "PQ-shaped and not anon-shaped": routing never forks on shape, only on type.

*Canonical single-store-key (S-028).* Because the two families share the account map, a case-mixed spelling must not fragment balances. `verify_pq_transaction` **rejects** any non-lowercase `from` at consensus (`normalize_pq_anon_address(from) != from`, `pq_tx_auth.cpp:19`), and the RPC ingress rejects non-canonical `from`/`to` at submission (`node.cpp:3781-3790`) — redundant with the anon-canonicalization checks above (`normalize_pq_anon_address == normalize_anon_address` on this shape), kept so the PQ-specific error survives if the anon path ever narrows. Rejecting (rather than silently normalizing) is required because the signed `signing_bytes` embed `from` byte-for-byte. Pinned by `test-pq-transaction` "non-canonical (uppercase) PQ from rejected" (`main.cpp:13245-13253`).

### PHA-4 — Cross-scheme / form domain separation

*Statement.* No two distinct `(form, pk)` inputs alias to one address.

*Proof.* The **form byte** is in the preimage (`pq_address.cpp:71`) AND the **`u32_be(len(pk))`** field differs across forms (1312/1952/2592 via `pq_form_pk_bytes`, `:26-34`), so ML-DSA-44/65/87 keys with related bytes hash to unrelated addresses. Pinned by `test-pq-transaction` ("form is domain-separated in the hash", `main.cpp:13206`) and the `cross_scheme` corpus vector (an Ed25519 pubkey embedded at the head of an ML-DSA-length buffer derives a PQ address disjoint from its Ed25519 address).

### PHA-5 — Determinism + dual-oracle byte-freeze

*Statement.* The shipped C address is byte-identical to independent oracles on every frozen vector, on any platform.

*Proof.* The C preimage emits `u32_be` via endian-independent shifts (`pq_address.cpp:73-76`) and hashes with `SHA256Builder`; the Python oracle uses `len(pk).to_bytes(4,"big")` + `hashlib.sha256` (`verify_pq_address.py:131-133`) — no host endianness enters. The freeze is enforced two independent ways beyond the generator: `test-pq-transaction` recomputes **every** `pq` corpus vector through the shipped C `make_pq_anon_address` and requires byte-equality (`n >= 10`, `main.cpp:13263-13286`); and `tools/test_c99_vector_files.sh` re-derives each vector through a *third*, from-scratch Python reference `pq_addr_ref` (`:1288-1349`). Any drift in DST, framing, or hash is a byte-mismatch failure in at least two oracles.

### 2.6 Attack-cost ladder

Every path by which value could leave a PQ address `from` without its owner's ML-DSA key, and the best known work factor. "Uncontrollable target" means the attacker cannot choose the hash output it must hit (it is fixed by the victim's key), which is what forecloses a birthday/meet-in-the-middle shortcut.

| Attack | Route (by `tx.type`) | Reduces to | Classical | Quantum |
|---|---|---|---|---|
| Substitute a different ML-DSA key | `PQ_TRANSFER` | SHA-256 preimage onto `from` | 2^256 | 2^128 (Grover) |
| PQ-spend an Ed25519 address | `PQ_TRANSFER` | SHA-256 preimage onto victim's pubkey-hex | 2^256 | 2^128 (Grover) |
| Ed25519-spend a PQ address | `TRANSFER` (non-PQ) | Ed25519 forgery under a hash-looking pubkey | 2^128 | **broken (Shor, PHA-L-2)** |
| Strip / mutate `pq_auth` | `PQ_TRANSFER` | — (fails `verify_pq_transaction`) | rejected | rejected |

The classical floor is the chain's uniform 2^128 level; the single quantum soft spot is the Ed25519 cross-path (PHA-L-2), which is a documented deployment limit, not a code defect.

---

## 3. Coverage map

| Property | Proven-in-code (shipped, green) | argued-in-prose (reduction) | Status |
|---|---|---|---|
| **PHA-1** commitment binding | `test-pq-transaction` — accept valid + reject tampered amount / non-PQ type / wrong `from` / empty envelope / **envelope-key ≠ address commitment** / hybrid (`main.cpp:13231-13244`) | SHA-256 preimage (uncontrollable target) × ML-DSA EUF-CMA (PHA-L-1) | code (accept/reject witnesses) + prose (preimage) |
| **PHA-2** shape-collision safety | hash addr passes `is_anon_address` yet routes by type; non-PQ `from` rejected (`main.cpp:13215,13236`); shared apply (`chain.cpp:802`) | cross-path ⇒ Ed25519 forgery (2^128) **or** SHA-256 preimage (2^256) | code (routing witness) + prose (reduction) |
| **PHA-3** routing determinism | byte-identical predicates + `tx.type`-only branch (`validator.cpp:540`, `node.cpp:2135`); batch inner whitelist (`chain.cpp:1194`) | — (the discriminator *is* `tx.type`) | code (branch + whitelist) |
| **PHA-3** S-028 canonical store-key | `test-pq-transaction` "non-canonical (uppercase) PQ from rejected" (`main.cpp:13245-13253`); consensus (`pq_tx_auth.cpp:19`) + RPC (`node.cpp:3781-3790`) | — (reject-not-normalize; `signing_bytes` embed `from`) | code (reject witness) |
| **PHA-4** form/scheme separation | `test-pq-transaction` "form is domain-separated" (`main.cpp:13206`); `cross_scheme` corpus vector | injective length-framed preimage (form + pklen distinct) | code (byte-pinned) + prose (injectivity) |
| **PHA-5** determinism → dual-oracle | C corpus cross-check `main.cpp:13263-13286` + `verify_pq_address.py` + `chk_pq_address` (triple oracle) over `pq_address.json` | — (this property *is* the byte gate) | code (byte-pinned, multi-oracle) |

---

## 4. Non-claims (PHA-NC-*) and limits (PHA-L-*)

### Non-claims

- **PHA-NC-1 — The Ed25519 anon family is UNCHANGED and classical.** A5 is **PQ-only**: it adds the hash address + `PQ_TRANSFER` accept-rule and leaves `make_anon_address = "0x"+hex(pk)` (identity encoding, `types.hpp:153-155`) exactly as owner-frozen 2026-07-03. Existing Ed25519 anon accounts get no quantum resistance from A5, by design.
- **PHA-NC-2 — Account-level PQ resistance holds only for txs that flow through `verify_pq_transaction`.** Every consensus + mempool path for `PQ_TRANSFER` does (`validator.cpp:541`, `node.cpp:2135`); the property is a statement about that accept-rule, not the envelope in isolation (which gives only message-integrity-to-a-named-key — PQE-NC-1 / PQE-L-5).
- **PHA-NC-3 — No forward secrecy, no address unlinkability.** A PQ address is a *stable* per-key commitment: the same ML-DSA key always derives the same address, so activity under one key is linkable. The key is hidden until first spend (the commitment is non-invertible), then revealed in the envelope.
- **PHA-NC-4 — `pq_auth` is not authenticated data.** Like `sig`/`hash`, `pq_auth` is excluded from `signing_bytes()` and the tx hash (`block.hpp:285-289` — "a signature cannot sign itself"). Stripping or mutating it merely fails `verify_pq_transaction` — a liveness/DoS concern for the submitter, never a theft vector (symmetric with the Ed25519 `sig`).

### Limits

- **PHA-L-1 — Hardness is assumed, not proved.** SHA-256 preimage/collision resistance and ML-DSA EUF-CMA are cited black-boxes; this document proves only that a theft reduces *to* them.
- **PHA-L-3 — No verifier asymmetry, by construction.** The accept-rule is a *single* shared helper `verify_pq_transaction`, called verbatim from both the block validator (`validator.cpp:541`) and mempool admission (`node.cpp:2135`) — the S-043 one-helper discipline. There is therefore no second, drifting re-implementation of the commitment check that a sender and a validator could disagree on; the recompute formula is defined in exactly one place (`pq_tx_auth.cpp:38`). This is an in-code structural property, not a hardness claim.
- **PHA-L-2 — The Ed25519 cross-path (PHA-2, direction 1) is quantum-broken.** Its 2^128 bound is *classical* EUF-CMA. A CRQC recovers the discrete log of the (roughly half of) hash outputs that decode to valid Curve25519 points (Shor, polynomial) and drains those PQ addresses via the classical `TRANSFER` path — the shared namespace offers no shape-level defence. **A5 freezes the PQ address FORMAT and delivers clean binding + 2^128 classical account security; full account-level quantum resistance additionally requires segregating or disabling the classical anon-spend path in a post-quantum deployment, which is out of A5 scope** (consistent with the PQ-freeze-now / cutover-later posture and PQE-NC-1). This is the honest bound on PHA-2, not a defect in the shipped code.

---

## 5. Status

**Shipped, green, state-root-invariant for PQ-free chains** (commit `e6d8ee9`; FAST goldens unchanged; `test-pq-transaction` all-PASS including the triple-oracle corpus gate). Adversarially reviewed 2026-07-09 across six surfaces (shape collision, routing, commitment soundness, canonicalization, cross-platform determinism, cross-scheme disjointness) with no exploitable finding — every theft path reduces to a 2^128–2^256 inversion on an attacker-uncontrollable target. The one honest bound made explicit here (PHA-L-2) is a documented deployment limit, not a code bug. Cross-references: [`PQSignatureEnvelopeSoundness.md`](PQSignatureEnvelopeSoundness.md) (the envelope this composes over), [`AnonAddressDerivationMigration.md`](AnonAddressDerivationMigration.md) (the Option A/B/D design analysis).
