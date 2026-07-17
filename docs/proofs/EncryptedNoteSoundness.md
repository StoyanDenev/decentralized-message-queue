> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# EncryptedNoteSoundness — the NC-8 encrypted-note primitive: ephemeral-static ECIES over P-256 / what seal+open give / the reduction to ECDH+HKDF+AEAD / why a ciphertext cannot be re-pointed / trial-decrypt is the scan signal

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **NC-8 encrypted-note delivery** primitive — the shielded-pool **Option A** on-ramp (owner-decided 2026-07-17) that lets a confidential-tx output carry an **encrypted note** so the recipient can **scan** the chain, **trial-decrypt**, and recover the note secret `(value, blinding[, memo])` **without an out-of-band channel**. It closes [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) **NC-8** ("no on-chain output-secret delivery").

The construction is **standard ephemeral-static ECIES** (a.k.a. DHIES/ECIES-KEM+DEM) over **NIST P-256** — the confidential-transaction stack's curve in **both** profiles (MODERN + FIPS). It is a **composition only**: security reduces to **P-256 ECDH** + **HKDF-SHA256** (RFC 5869) + **ChaCha20-Poly1305 AEAD** (RFC 8439), all shipped, dual-oracle-frozen c99 primitives. It introduces **NO new hardness assumption** and touches **no consensus/wallet path** — it is a **library primitive**, and the chain wiring (attaching an enote to a confidential-transfer output) is a separate, owner-gated step.

Critically for the pool's design: enote adds **amount/secret DELIVERY only**. It adds **NO graph privacy** — inputs stay named ([`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) **NC-7** unchanged) — and does **not** touch the named-input / commitment-as-its-own-nullifier model, so the pool's no-double-spend-by-design property (a bounded unspent-commitment set, **no** nullifier set) is fully preserved.

- **Module —** `src/crypto/enote/enote.c` + `include/determ/crypto/enote/enote.h` (`determ_enote_seal` / `determ_enote_open`), CRYPTO-C99-SPEC.md primitive rows §3.1 (HKDF), §3.4 (ChaCha20-Poly1305), §3.8c (P-256).
- **Gate —** `test-enote-c99` (the `main.cpp` subcommand) via `tools/test_enote_c99.sh`: `seal→open` roundtrip (empty + a real 40-byte `v‖r` note), determinism (byte-identical re-seal), **wrong-key rejection with the output buffer untouched** (the scan "not mine" signal), per-region tamper rejection (ephemeral `E33` / ciphertext / tag), malformed + off-curve fail-closed, and the **dual-oracle KAT corpus** `tools/vectors/enote.json` — produced **byte-independently** by `tools/verify_enote.py` — reproduced byte-for-byte.
- **Inherited crypto —** P-256 ECDH (§3.8c; the FIPS ECDH primitive, SP 800-56A shape), HKDF-SHA256 (§3.1, RFC 5869), ChaCha20-Poly1305 (§3.4, RFC 8439). CT-hardening is inherited from the P-256 scalar-multiplication stack ([`P256CryptoStackAudit.md`](P256CryptoStackAudit.md), [`ConstantTimeInventory.md`](ConstantTimeInventory.md)). The primitive adds **no new hardness assumption**.

**Authoritative external sources.** Abdalla, Bellare, Rogaway, *"The Oracle Diffie-Hellman Assumptions and an Analysis of DHIES"* (CT-RSA 2001) — the ODH assumption + the DHIES/ECIES reduction, and the recommendation to bind the public keys into the KDF; Krawczyk, *"Cryptographic Extraction and Key Derivation: The HKDF Scheme"* (CRYPTO 2010) — HKDF as an extract-then-expand KDF; RFC 5869 (HKDF); RFC 8439 (ChaCha20-Poly1305 AEAD); Shoup, ISO/IEC 18033-2 (ECIES-KEM/DEM framing); SEC1 §2.3 (compressed point encoding). Nothing new is assumed beyond what these + the shipped §3.1/§3.4/§3.8c primitives already assume.

---

## 1. The construction — what `seal` / `open` compute

### 1.1 Wire format (from `enote.h` / `enote.c`)

An enote is one contiguous byte string, `len = ptlen + DETERM_ENOTE_OVERHEAD` where `DETERM_ENOTE_OVERHEAD = 49 = 33 (E33) + 16 (tag)`:

```
offset  field
------  ------------------------------------------------------------
0       E33 (33)   ephemeral pubkey, SEC1 compressed (0x02/0x03 prefix)
33      ct  (ptlen) ChaCha20-Poly1305 ciphertext (same length as pt)
33+ptl  tag (16)   Poly1305 authentication tag
```

`seal(recipient_pub[33], pt, ptlen, eph_sk[32]) → out`:

```
E    = eph_sk·G                                     ephemeral pubkey; base_mul rejects a degenerate/out-of-range eph_sk
E33  = compress(E)                                  33-byte SEC1
Z    = eph_sk·R  (ECDH) ; z = Z.x                   32-byte big-endian shared x-coordinate
K‖N  = HKDF-SHA256(salt = "determ-enote-v1",        info binds BOTH pubkeys: E and R
                   ikm  = z,
                   info = E33 ‖ recipient_pub33, L = 44)      K = okm[0:32], N = okm[32:44]
ct,tag = ChaCha20-Poly1305(K, N, aad = E33, pt)     tag over (K, N, aad=E33, ct)
out  = E33 ‖ ct ‖ tag
```

`open(recipient_sk[32], in, in_len) → pt`: recover `E` from the wire's `E33`; recompute the recipient's **own** compressed pubkey `recip33 = compress(recipient_sk·G)`; `Z = recipient_sk·E`, `z = Z.x`; re-run the **same** HKDF (`info = E33 ‖ recip33`); AEAD-decrypt `ct‖tag` with `aad = E33`. A **verifying tag IS** the "this note is mine" signal; a non-verifying tag ⟹ `-1` and **nothing is written** to `pt_out`.

Both salt (`ENOTE_DST = "determ-enote-v1"`, no trailing NUL hashed) and the 12-byte nonce `N` are **KDF-derived**, not caller counters — the nonce is a deterministic function of `(z, E, R)`, so it is single-use exactly when the ephemeral key is fresh (§EN-5).

---

## 2. The reduction — confidentiality + integrity from ECDH + HKDF + AEAD

The primitive is a KEM/DEM composition. The **KEM** is P-256 ECDH keying HKDF: the sender's ephemeral `E` and the ECDH secret `z = (eph_sk·R).x` are extracted+expanded by HKDF into `(K, N)`. The **DEM** is ChaCha20-Poly1305 under `(K, N)` with `aad = E33`. The standard DHIES analysis (Abdalla-Bellare-Rogaway 2001) applies:

- **Confidentiality (IND-CCA-ish) reduces to ODH + AEAD IND-CPA.** Against a non-recipient (who does not hold `recipient_sk`), the derived key material `(K, N)` is **pseudorandom** under the **Oracle Diffie-Hellman (ODH)** assumption on P-256 — a gap-DH variant: the adversary sees `R` and the challenge `E`, and must not distinguish `HKDF(z, E33‖R33)` from random even given a hashing oracle `H_v(·) = HKDF((v·recipient_sk).x, …)` on points `v ≠ E`. ODH holds in the **random-oracle model** when computational Diffie-Hellman is hard on P-256 (ODH ⟸ gap-CDH + HKDF-as-RO). Given `(K, N)` pseudorandom, the plaintext's confidentiality is exactly the **IND-CPA** security of ChaCha20-Poly1305 on a fresh key. The AEAD's integrity layer + the KEM's key-binding lift this toward IND-CCA (a decryption oracle cannot help: forging a new valid ciphertext is INT-CTXT-hard — below).
- **Integrity / ciphertext integrity reduces to AEAD INT-CTXT under a pseudorandom key.** A verifying tag on `(K, N, aad = E33, ct)` is **one-time INT-CTXT** of ChaCha20-Poly1305: with `K` pseudorandom (from the ODH/KDF step) and `(K, N)` used once (§EN-5), no PPT adversary produces a fresh `(ct, tag)` that verifies except with negligible probability. This is what makes **tamper-rejection** (EN-3) and the **soundness of the trial-decrypt scan signal** (a verifying tag ⟹ the note was sealed to this key) hold.

### 2.1 The binding argument — a ciphertext cannot be re-pointed

The load-bearing structural fact is that the ciphertext is **cryptographically bound to the exact `(E, R)` pair** it was created for, so it cannot be re-pointed to a different recipient or a different ephemeral key:

1. **HKDF `info = E33 ‖ recipient_pub33` commits the key material to BOTH pubkeys.** `open` derives `info` from the wire's `E33` and the opener's **own** `recip33 = compress(recipient_sk·G)` — it is **never taken from the wire**. So a party who is not the intended recipient derives a **different `info`** (their `R'33 ≠ R33`) **and** a different ECDH secret (`(recipient_sk'·E).x ≠ z`); either mismatch yields a different `(K, N)` and the tag fails. Binding `R` into the KDF is exactly the ABR-2001 defense against unknown-key-share / key-reuse confusion: a note valid "for `R`" cannot be made to key-derive as a note "for `R'`".
2. **AEAD `aad = E33` commits the tag to the ephemeral key.** If an attacker swaps the wire's `E33` for `E'33`, then (a) the recipient's ECDH gives `z' = (recipient_sk·E').x ≠ z` **and** (b) even under a hypothetical KDF collision, the AEAD associated data the recipient authenticates is now `E'33` while the tag was computed over `E33` — INT-CTXT fails. `E` is thus committed **twice**: in the key derivation (via `info` and via `z`) and in the AEAD associated data.

Consequently the only `(recipient_sk, E)` pair that yields a verifying tag is the intended one — which is precisely why `open` returning `0` is a **sound ownership signal** and returning `-1` is a **sound "not mine"** signal.

---

## 3. Claims (EN-1 .. EN-6)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green assertion in `test-enote-c99` (or by the dual-oracle KAT corpus). **argued-in-prose** = a reduction to a cited theorem (ODH / HKDF-KDF / AEAD), assumed, not machine-checked here.

- **EN-1 (correctness — `open ∘ seal = id` for the intended key; deterministic + byte-frozen).** For a note sealed to `R = recipient_sk·G` with ephemeral `eph_sk`, `open(recipient_sk, seal(R, pt, eph_sk)) = pt`. **Why:** ECDH agreement `recipient_sk·E = recipient_sk·(eph_sk·G) = eph_sk·(recipient_sk·G) = eph_sk·R = Z`, so the shared `z = Z.x` matches; `open` reconstructs the **same** `info = E33 ‖ recip33` (its `recip33 = compress(recipient_sk·G) = recipient_pub33`, its `E33` read from the wire) and the **same** `aad = E33`, so `(K, N)` match and the AEAD decrypts. `seal` is a **pure function** of `(R, pt, eph_sk)`, so its bytes are exactly reproducible. **Proven-in-code + dual-oracle-frozen:** `test-enote-c99` asserts the empty-note and 40-byte `v‖r` roundtrips, a byte-identical re-seal (determinism), and reproduces every `enote.json` vector byte-for-byte against the independent `verify_enote.py` oracle (seal `== ct_hex`; open recovers `pt`).

- **EN-2 (confidentiality of `pt` against non-recipients).** A party without `recipient_sk` learns nothing about `pt` beyond its length (NC-3). This is the DHIES **IND-CCA-ish** guarantee: `(K, N)` is pseudorandom under **ODH** on P-256 in the ROM (gap-CDH-hard + HKDF-as-RO), whereupon `pt`'s secrecy is the **IND-CPA** security of ChaCha20-Poly1305 on a fresh key. **Argued-in-prose** (the reduction; L-1/L-2) **+ witnessed-in-code** that a wrong key recovers nothing: `test-enote-c99` opens a note with a **wrong** `recipient_sk` and asserts `open == -1` with the recipient buffer **byte-unchanged**.

- **EN-3 (integrity / tamper-rejection — and the verifying tag is the scan signal).** Any modification of the wire (`E33`, `ct`, or `tag`) makes `open` return `-1` and write **nothing**. A verifying tag both authenticates the ciphertext **and** signals "this note is mine". This is one-time **INT-CTXT** of ChaCha20-Poly1305 under the pseudorandom `(K, N)`. **Proven-in-code** (the AEAD decrypt returns non-zero on any tag mismatch, and `determ_enote_open` `goto done`s without touching `pt_out`) **+ argued-in-prose** (INT-CTXT). **Evidence:** `test-enote-c99` flips a byte at each of the three wire regions (offset `0`, `DETERM_ENOTE_EPH_LEN`, `ctlen-1`) and asserts every variant **rejects**.

- **EN-4 (recipient-and-ephemeral binding — a ciphertext cannot be re-pointed).** The ciphertext is bound to the exact `(E, R)` pair it was sealed for: `info = E33 ‖ recipient_pub33` feeds **both** pubkeys into the KDF, and `aad = E33` feeds `E` into the AEAD tag. So a note cannot be re-addressed to a different recipient (`R' ⟹ different info AND different z`) nor have its ephemeral key substituted (`E' ⟹ different z AND aad mismatch`). **Proven-in-code** (the `info`/`aad` construction in `enote_kdf` + the two `determ_chacha20_poly1305_*` calls; `open` recomputes `recip33` from its **own** sk, never from the wire) **+ argued-in-prose** (the §2.1 binding argument, ABR-2001). **Evidence:** the wrong-key reject (EN-2) exercises the `R`-binding half; the `E33`-tamper reject (EN-3) exercises the `E`-binding half.

- **EN-5 (fresh ephemeral ⟹ single-use `(K, N)` — the nonce-uniqueness requirement).** Because `N` is **KDF-derived** from `(z, E33, R33)` and `z, E` are deterministic functions of `eph_sk` (for a fixed `R`), a **fresh, unique** `eph_sk` per note yields a **unique** `(K, N)` — the AEAD nonce is single-use, which is the precondition ChaCha20-Poly1305 needs for confidentiality. Deriving `N` from the KDF (rather than a caller counter) is what makes "fresh `eph_sk`" the **single** freshness obligation. **Argued-in-prose** (the reduction requires nonce-uniqueness) **+ the contract is documented** in `enote.h` ("`e` MUST be unique per note … reuse repeats `(K,N)` and breaks AEAD confidentiality"). **Non-enforcement caveat:** the primitive does **not** sample or check `eph_sk` freshness — that is the caller's obligation (NC-8); the choice keeps `seal` a deterministic, dual-oracle-testable pure function (EN-1).

- **EN-6 (memory-safe, fail-closed trial-open).** `open` treats every input byte as adversarial: `in_len < DETERM_ENOTE_OVERHEAD` ⟹ reject before any slice; a malformed/off-curve `E33` (`point_decompress`/implicit `point_check` on the ECDH) ⟹ reject; a degenerate `recipient_sk` (rejected by `base_mul`) ⟹ reject; a NULL arg ⟹ reject. On **every** reject path `pt_out` is left untouched and secrets (`z65`, `ks`) are `determ_secure_zero`'d. `seal` likewise validates the recipient point (`point_decompress` + `point_check`) and the ephemeral scalar (`base_mul`) before use, and never partially writes `out` on failure. **Proven-in-code** (the length gate + the decode/validate guards + `secure_zero` on the `done` path). **Evidence:** `test-enote-c99` — a truncated buffer (`< OVERHEAD`), a NULL sk, a NULL recipient, and an off-curve recipient pubkey each **reject**; the wrong-key open leaves the output buffer byte-identical.

---

## 4. Validation map

| Claim | Enforced in source | Gate (`test-enote-c99`) | Rests on | Status |
|---|---|---|---|---|
| **EN-1** correctness + determinism | `enote.c` ECDH agreement + shared `enote_kdf` (seal/open derive the same `info`/`aad`) | empty + 40-byte roundtrip; byte-identical re-seal; **`enote.json` reproduced byte-for-byte vs `verify_enote.py`** | ECDH agreement (algebraic) | proven-in-code + dual-oracle byte-freeze |
| **EN-2** confidentiality of `pt` | `enote_kdf` (P-256 ECDH → HKDF) + `chacha20_poly1305_encrypt` | wrong-key open `== -1`, output buffer **unchanged** | ODH (gap-CDH + HKDF-RO) + AEAD IND-CPA | argued-in-prose + witnessed (no wrong-key recovery) |
| **EN-3** integrity / tamper-reject / scan signal | AEAD tag verify; `open` `goto done` writes nothing on mismatch | per-region tamper (`E33` / `ct` / `tag`) all **reject** | AEAD INT-CTXT (one-time) | proven-in-code (fail-closed) + argued-in-prose (INT-CTXT) |
| **EN-4** recipient+ephemeral binding | `enote_kdf` `info = E33‖R33`; AEAD `aad = E33`; `open` recomputes `recip33` from own sk | wrong-key reject (R-half); `E33`-tamper reject (E-half) | §2.1 binding argument (ABR-2001) | proven-in-code (construction) + argued-in-prose |
| **EN-5** fresh-eph ⟹ unique `(K,N)` | `N = okm[32:44]` KDF-derived from `(z,E,R)`; `seal` pure in `eph_sk` | determinism (same `eph_sk` ⟹ same bytes) documents the dependence | AEAD nonce-uniqueness requirement | argued-in-prose (caller obligation, NC-8) |
| **EN-6** memory-safe fail-closed trial-open | `in_len < OVERHEAD` gate; `point_decompress`/`point_check`/`base_mul` guards; `secure_zero` on `done` | truncated / NULL-sk / NULL-recipient / off-curve all reject; output untouched on wrong key | bounds from validated inputs | proven-in-code |

The `test-enote-c99` gate is the **roundtrip + tamper + fail-closed + dual-oracle** witness that an accept-only vector set cannot give; the crypto conformance is the already-green §3.1/§3.4/§3.8c primitives underneath. Their conjunction — bounded by L-1..L-4 — is what "the NC-8 enote is a deterministic, fail-closed, recipient-and-ephemeral-bound ephemeral-static ECIES whose confidentiality + integrity reduce to P-256 ECDH + HKDF-SHA256 + ChaCha20-Poly1305, under ODH in the ROM" means for this shielded-pool Option-A delivery primitive.

---

## 5. Non-claims — THIS IS A DELIVERY PRIMITIVE, NOT A PRIVACY SYSTEM

**Read this before treating the encrypted note as anonymity.** enote delivers the recipient's note secret on-chain; it does **not** hide who transacts, and several of these are inherited from the shielded-pool docs:

- **NC-1 — Adds NO graph privacy; [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) NC-7 is UNCHANGED.** enote rides on a `CONFIDENTIAL_TRANSFER` whose **inputs are named** — the bundle lists the exact input commitments it consumes and apply removes them. An observer can still follow the note *graph*. enote supplies the missing **output-secret channel** (closing NC-8); it does **not** provide input-unlinkability (which needs a nullifier-from-secret + set-membership argument — a materially larger, owner-gated crypto increment, not built).

- **NC-2 — NOT sender/receiver-anonymous.** The wire carries **no** recipient identifier (the recipient is found by trial-decrypt — good), but enote does **not** anonymize the surrounding transaction: `tx.from`, the named inputs, and the public fee are visible. enote is **not** a stealth-address scheme and provides no one-time-address unlinkability across a recipient's notes; it hides the note *plaintext*, not the *fact* that a party posted a note.

- **NC-3 — The ciphertext reveals its OWN length and its presence (size side-channel).** `|wire| = |pt| + 49`, so an observer learns `|pt|` exactly, plus the existence of the note. There is **no** length-hiding / fixed-width padding: distinct plaintext lengths are distinguishable on-chain. Callers that need length-privacy must pad `pt` to a fixed width themselves.

- **NC-4 — No sender authentication; the plaintext is NOT bound to the on-chain commitment.** ChaCha20-Poly1305 authenticates **integrity**, not **origin**: anyone who knows `R` can seal a well-formed note. enote does **not** prove the delivered `(value, blinding)` actually *opens* the transfer's output commitment `C_out` — a malicious sender could deliver a note whose secret does not match `C`. Binding the note plaintext to `C` (so the recipient can trust what it decrypts) is the **consumer's** obligation, not this primitive's.

- **NC-5 — No forward secrecy (ephemeral-static).** The recipient key is **long-term static**; compromise of `recipient_sk` decrypts **all** past and future notes sealed to it. Only the sender side is ephemeral. There is no per-note recipient-side forward secrecy and no post-compromise recovery.

- **NC-6 — Not post-quantum.** Confidentiality rests on P-256 ECDH / ECDLP, broken by Shor. Because notes are delivered **on-chain**, this is a **store-now-decrypt-later** exposure of the note plaintext to a future quantum adversary. Classical-adversary construction.

- **NC-7 — No consensus / wallet consumer yet (LIBRARY primitive, owner-gated).** No Determ chain / ledger / wallet path constructs, attaches, or scans an enote today. Wiring an enote onto a `CONFIDENTIAL_TRANSFER` output (and the wallet scan loop) is a separate, consensus-adjacent, **owner-gated** step. This primitive proves only the *cryptographic* delivery guarantee.

- **NC-8 — `eph_sk` freshness is the CALLER's obligation — not enforced.** `seal` takes a caller-supplied `eph_sk` and is deterministic in it (for testability, EN-1). It does **not** sample randomness or detect reuse. Reusing an `eph_sk` across two notes repeats `(K, N)` and **breaks AEAD confidentiality** (the classic nonce-reuse catastrophe). The caller **must** draw a fresh, unique `eph_sk` per note (e.g. from `determ_rng_bytes`); enote gives the positive nonce-uniqueness guarantee (EN-5) only under that obligation.

---

## 6. Limits (L-1 .. L-4)

- **L-1 — Soundness is a COMPOSITION REDUCTION over shipped primitives, not a new hardness result or a machine-checked extractor.** EN-2/EN-3/EN-4 reduce enote to the security of **existing** primitives (P-256 ECDH, HKDF-SHA256, ChaCha20-Poly1305); this document adds **no** new assumption and re-proves **none** of the underlying primitives. A break of P-256 DL, of HKDF-as-KDF, or of the AEAD breaks enote regardless of any gating here. The `test-enote-c99` witnesses show the deployed reject/roundtrip paths behave — they are **not** a cryptographic proof.

- **L-2 — The confidentiality reduction rests on the ROM (ODH).** EN-2's key-pseudorandomness is the **Oracle Diffie-Hellman** assumption on P-256 with HKDF-SHA256 modeled as a random oracle (equivalently, gap-CDH hardness + HKDF-as-RO). This is the standard DHIES/ECIES assumption (ABR-2001) but it is a **random-oracle-model** argument, not a standard-model one.

- **L-3 — Conformance is over a FIXED witness + the dual-oracle KAT corpus, not the input space.** `test-enote-c99` exercises one empty note + one 40-byte `v‖r` note (plus the wrong-key / tamper / malformed / off-curve variants), and reproduces the `enote.json` vectors byte-for-byte against `verify_enote.py`. Completeness/soundness for arbitrary plaintext lengths and keys follows from the composition + the inherited primitive conformance, not an exhaustive sweep. The dual-oracle byte-freeze **is** shipped, but over that fixed corpus.

- **L-4 — Timing is INHERITED from the CT-hardened P-256 stack, not a fresh timing proof here.** The secret-dependent operations are the P-256 scalar multiplications (`base_mul`, `point_mul`), which use the CT ladder (CT-hardened 2026-07-06; [`P256CryptoStackAudit.md`](P256CryptoStackAudit.md), [`ConstantTimeInventory.md`](ConstantTimeInventory.md)); HKDF-SHA256 and ChaCha20-Poly1305 are constant-time, and the AEAD tag comparison is the constant-time compare that makes the trial-decrypt scan signal non-leaky (EN-3/EN-6). This document asserts only functional soundness and **inherits** the timing posture — it does not add a machine-checked timing proof of the enote composition.

---

## 7. Status

- **Spec.** Complete (this document); primitive rows CRYPTO-C99-SPEC.md §3.1 (HKDF-SHA256), §3.4 (ChaCha20-Poly1305), §3.8c (P-256). Construction frozen (`ENOTE_DST = "determ-enote-v1"`, `info = E33‖R33`, `aad = E33`, `L = 44 → K(32)‖N(12)`, overhead 49).
- **Module + gate shipped and green.** `src/crypto/enote/enote.c` + `include/determ/crypto/enote/enote.h` (`determ_enote_seal` / `determ_enote_open`); `test-enote-c99` via `tools/test_enote_c99.sh` — roundtrip (empty + 40-byte note) + determinism + wrong-key reject (output untouched) + per-region tamper reject (`E33` / `ct` / `tag`) + malformed/off-curve fail-closed + the dual-oracle KAT (`tools/vectors/enote.json` ⇄ `tools/verify_enote.py`, byte-for-byte). Underlying primitives are the already-green §3.1/§3.4/§3.8c c99 stack.
- **Claims (EN-1..EN-6).** EN-1 (correctness `open∘seal = id` + deterministic dual-oracle byte-freeze), EN-2 (confidentiality of `pt` vs non-recipients — ODH + AEAD IND-CPA), EN-3 (integrity/tamper-rejection + the verifying-tag scan signal — AEAD INT-CTXT), EN-4 (recipient+ephemeral binding — `info=E33‖R33`, `aad=E33`, cannot re-point), EN-5 (fresh-ephemeral ⟹ single-use `(K,N)` nonce), EN-6 (memory-safe fail-closed trial-open) — at the proven-in-code / argued-in-prose split in §3–§4.
- **Non-claims (NC-1..NC-8).** No graph privacy (ShieldedPool NC-7 unchanged); not sender/receiver-anonymous (no stealth address); reveals its own length + presence (size side-channel); no sender authentication + plaintext not bound to the commitment (consumer's job); no forward secrecy (ephemeral-static); not post-quantum (store-now-decrypt-later); no consensus/wallet consumer yet (library primitive, owner-gated); `eph_sk` freshness is the caller's obligation, not enforced.
- **Limits (L-1..L-4).** Soundness is a composition reduction over shipped primitives (no new hardness, no extractor); the confidentiality reduction rests on ODH in the ROM; conformance is a fixed witness + the dual-oracle KAT corpus; timing is inherited from the CT-hardened P-256 stack, not a fresh timing proof.

Cross-references: [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (**NC-8** — the on-chain output-secret delivery gap this primitive closes; **NC-7** input-unlinkability, which it does **not**); [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) (the DCT1 bundle whose output notes need the delivered secret); [`P256CryptoStackAudit.md`](P256CryptoStackAudit.md) / [`ConstantTimeInventory.md`](ConstantTimeInventory.md) (the inherited P-256 ECDH + CT-hardening); CRYPTO-C99-SPEC.md §3.1 (HKDF-SHA256, RFC 5869), §3.4 (ChaCha20-Poly1305, RFC 8439), §3.8c (NIST P-256).
