> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# OprfConformanceMap — RFC 9497 OPRF(P-256, SHA-256) conformance + trust composition for the C99 layer (FB69)

This document is the FB-track conformance-and-trust analysis of the **C99-native RFC 9497 OPRF(P-256, SHA-256)** protocol layer shipped in `src/crypto/p256/p256.c` (CRYPTO-C99-SPEC.md §3.9b). It answers two questions the individual test outputs do not answer on their own: (1) **what** each shipped C99 function is, mapped operation-by-operation onto the RFC 9497 construction and its exact byte transcripts / domain-separation tags, verified against the source; and (2) **how much** the two validation legs — the appendix-vector byte gate (both §3.13 halves over `tools/vectors/p256_oprf.json`) and the structural/negative test (`determ test-p256-oprf-c99`) — jointly establish, and where their reach stops.

The protocol layer is deliberately thin: it is written **entirely against the module's PUBLIC API** (the §3.8c curve + §3.9b hash-to-curve/mod-n groundwork), so its correctness composes on top of that layer's own validation rather than re-deriving it. The single-element OPRF/VOPRF construction reduces to a fixed sequence of scalar-mults, point-adds, hash-to-scalar / hash-to-curve calls, and length-prefixed SHA-256 transcripts; the conformance claim is therefore that (a) each transcript is assembled byte-for-byte per the RFC and (b) the composed outputs equal the genuine RFC 9497 appendix vectors, including the 64-byte DLEQ proof.

**Assumptions.** As with the §3.13 gate (`VectorGateComposition.md` FB68), the theorems are mostly *mechanical* — exact byte-equality of deterministic transcript functions against a byte-pinned corpus and against an independent re-derivation. Cryptography enters only at the edges: canonical labels per `Preliminaries.md` §2.0, **A2** = SHA-256 collision resistance, **A3** = SHA-256 preimage / second-preimage resistance (used in T-2's tamper argument), plus the P-256 **discrete-log / one-more-DH hardness** the OPRF's pseudorandomness and DLEQ soundness ultimately rest on — assumed, NOT proved here (T-3 limit L-3). Operational assumptions inherited from FB68: **(P-corpus)** both §3.13 halves read the same `tools/vectors/p256_oprf.json` bytes; **(P-oracle)** the independent python re-derivations compute RFC 9497/9380 correctly; **(P-json)** python `json` and nlohmann::json agree on the parse.

**Companion documents.** `P256CryptoStackAudit.md` — the correctness+constant-time companion for the underlying P-256 module (field arithmetic, RCB complete addition, the CT ladder, hash-to-curve/SSWU, mod-n scalar ops); this conformance map **forward-references it as the reason the primitive calls under each OPRF operation are themselves trustworthy** (an OPRF that assembles the right transcript over a wrong scalar-mult would still be wrong — that leg is discharged there, not here). `VectorGateComposition.md` (FB68) — the two-half §3.13 gate mechanics this document instantiates for the OPRF corpus (the file-half python recompute + the binary-half C99 consumption, and their fail-attribution split). `CRYPTO-C99-SPEC.md` §3.9b (the OPRF design entry) / §3.8c (the curve) / §3.13 (the vector gate). `ConstantTimeInventory.md` — the §3.12 timing boundary (T-3 limit L-4). `src/crypto/p256/README.md` — module provenance + the R46 vector/pseudocode fetch lineage. RFC 9497 (OPRF) and RFC 9380 (hash-to-curve) — the fetched normative texts (trust base §3).

---

## 1. The construction map

Ciphersuite: `OPRF(P-256, SHA-256)` = RFC 9497 suite `P256-SHA256`, over the RFC 9380 hash-to-curve suite `P256_XMD:SHA-256_SSWU_RO_`. `Nseed`/`Nh` = 32, elements on the wire are **SEC1 compressed** (`Ne` = 33), scalars are 32-byte big-endian, and `proof = SerializeScalar(c) || SerializeScalar(s)` (64 bytes). Two modes: **OPRF** `mode = 0x00`, **VOPRF** `mode = 0x01`. The POPRF mode `0x02` and batch (m>1) are out of scope (§4 L-1).

### 1.1 contextString and the per-operation DSTs (RFC 9497 §3.1)

Everything domain-separates through one 20-byte `contextString`, built by `oprf_context` (`p256.c:835-839`):

```
contextString = "OPRFV1-" || I2OSP(mode, 1) || "-P256-SHA256"       (20 bytes)
```

verified byte-for-byte: `memcpy(ctx, "OPRFV1-", 7)` (7 bytes), `ctx[7] = mode` (the mode is a **raw byte between two ASCII hyphens**, not its decimal text — the RFC's I2OSP(mode,1)), `memcpy(ctx+8, "-P256-SHA256", 12)`. `OPRF_CTX_LEN` = 20 = 7 + 1 + 12. Each operation's DST is `prefix || contextString`, assembled by `oprf_dst` (`:842-847`, `strlen(prefix)` + the 20-byte context). The prefixes, verified at each call site:

| DST | Prefix (exact source literal) | Used by | Source |
|---|---|---|---|
| DeriveKeyPair | `"DeriveKeyPair"` (**no trailing hyphen** — RFC quirk, the hyphen is absent from this one label) | `oprf_derive_key` | `:886-887` |
| HashToGroup | `"HashToGroup-"` (trailing hyphen) | `oprf_blind` → `hash_to_curve` | `:913-914` |
| HashToScalar | `"HashToScalar-"` (trailing hyphen) | composites (`oprf_composites`) / challenge (`oprf_challenge`) — NOT DeriveKeyPair, which calls the same `determ_p256_hash_to_scalar` primitive but under its own `"DeriveKeyPair"` DST above | `:988-989`, `:1011-1012` |
| Seed | `"Seed-"` (trailing hyphen) | ComputeComposites seed | `:981-982` |

The `"DeriveKeyPair"`-has-no-hyphen asymmetry is real in RFC 9497 and is preserved exactly (contrast `"HashToGroup-"` / `"HashToScalar-"` / `"Seed-"`, all of which DO carry the hyphen); it is called out in both the code comment (`:885`) and the header (`p256.h:131`). This asymmetry is one of the things the appendix-vector gate (T-1) pins, since a spurious or missing hyphen changes the derived key and cascades into every downstream byte.

### 1.2 Operation → C99 function map (each verified against the source transcript)

| RFC 9497 operation | C99 function | Byte transcript / construction (verified) | Source |
|---|---|---|---|
| **DeriveKeyPair** (§3.2.1) | `determ_p256_oprf_derive_key` | `deriveInput = seed || I2OSP(len(info),2) || info`; counter loop `0..255`: `sk = HashToScalar(deriveInput || I2OSP(counter,1))` with the DeriveKeyPair DST; accept first nonzero `sk`; exhaustion → -1 (prob ~2⁻²⁰⁴⁸) | `:880-908` |
| **Blind** (§3.3.1) | `determ_p256_oprf_blind` | `inputElement = HashToGroup(input)` (RFC 9380 h2c under the HashToGroup DST); reject if identity (`hash_to_curve` returns -1); `blindedElement = blind * inputElement`; wire = SEC1 compressed | `:910-927` |
| **BlindEvaluate** core (§3.3.1 / §3.3.2) | `determ_p256_oprf_evaluate` | `evaluatedElement = skS * blindedElement` (mode-agnostic; the VOPRF proof is a separate call). Validates `skS` and decodes the compressed input element | `:929-940` |
| **Finalize** (§3.3.1) | `determ_p256_oprf_finalize` | `N = blind⁻¹ * evaluatedElement`; `output = SHA-256( I2OSP(len(input),2) || input || I2OSP(len(N),2) || SerializeElement(N) || "Finalize" )`. `len(N)` is pinned as the literal `0x00 0x21` (= 33) | `:942-971` |
| **ComputeComposites(Fast)** (§2.2.1, m=1) | `oprf_composites` (static) | `seed = SHA-256( I2OSP(len(Bm),2) || Bm || I2OSP(len("Seed-"||ctx),2) || ("Seed-"||ctx) )` with `Bm = SerializeElement(pkS)`; then `di = HashToScalar( I2OSP(len(seed),2) || seed || I2OSP(0,2) || I2OSP(len(Ci),2) || Ci || I2OSP(len(Di),2) || Di || "Composite" )`; `M = di*C`, and (fast side) `Z = k*M` | `:973-1004` |
| **GenerateProof** (§2.2.2, m=1) | `determ_p256_voprf_prove` | via `oprf_composites` (fast, `k=skS`): `M`, `Z`; `t2 = r*G`, `t3 = r*M`; `c = challenge(pkS, M, Z, t2, t3)`; `s = r − c*skS mod n`; `proof = c || s` | `:1027-1067` |
| **VerifyProof** (§2.2.2, m=1) | `determ_p256_voprf_verify` | via `oprf_composites` (verify side, `k=None`): `M = di*C`, `Z = di*D`; `t2 = s*G + c*B`, `t3 = s*M + c*Z` (computed through the public `_base_mul`/`_point_mul`/`_point_add`/`_compress`); `c2 = challenge(...)`; accept iff `determ_ct_memcmp(c2, c, 32) == 0` | `:1069-1100` |
| **Challenge** transcript (§2.2.2) | `oprf_challenge` (static) | `c = HashToScalar( [ I2OSP(len(e),2) || SerializeElement(e) for e in (Bm=pkS, M, Z, t2, t3) ] || "Challenge" )` — five length-prefixed 33-byte elements then `"Challenge"` | `:1006-1025` |

Supporting wire/scalar primitives, also verified: `oprf_context`/`oprf_dst` (DST assembly, §1.1); `oprf_load33`/`oprf_store33` (`:867-878`, SEC1 compressed ↔ internal point via `_point_decompress`/`_point_compress`); `determ_p256_hash_to_scalar` (RFC 9380 hash_to_field with modulus **n**, m=1, L=48; `:738-751`) — this is the RFC 9497 `HashToScalar`; `determ_p256_scalar_inv_mod_n` (Fermat `blind⁻¹`, `:475-495`); `sc_sub_raw` (the `r − c*skS` in `GenerateProof`, `:849-864`). Two structural facts pinned by reading the code: (i) `_finalize`'s `len(N)` and the composites/challenge `len(elem)` are all the literal `0x0021` (33) because elements are compressed — a subtle byte the RFC's `SerializeElement` fixes at `Ne`; (ii) `oprf_composites` runs the SAME transcript for prove (fast, `k=skS` sets `Z=k*M`) and verify (`k=None` sets `Z=di*D`), differing only in how `Z` is formed — the source shares one helper, so a transcript-assembly bug cannot desynchronize prover and verifier (the S-043 "one shared helper per new formula" discipline).

**Determinism note.** The blind (`_blind`) and proof-randomness (`_prove`, argument `r`) scalars are caller-supplied, not internally sampled. This is deliberate: it makes the layer testable byte-for-byte against the appendix vectors (which fix `blind` and `ProofRandomScalar`). Production callers draw both from the CSPRNG (`p256.h:123-128`, `:160`).

---

## 2. Theorems

### T-1 — The appendix-vector gate pins byte-exact conformance for the covered inputs (both proof halves included)

**Statement.** If both §3.13 halves PASS over `tools/vectors/p256_oprf.json` (the 4 genuine RFC 9497 vectors: A.3.1.1/A.3.1.2 OPRF `mode 0x00` and A.3.2.1/A.3.2.2 VOPRF `mode 0x01`, all batch size 1), then the shipped C99 layer reproduces, **byte-for-byte**, every intermediate and final value RFC 9497 lists for those inputs: the derived `skSm` (re-derived from `Seed`+`KeyInfo`, never trusted from the file), `blindedElement`, `evaluationElement`, the 32-byte `output`, and — for the VOPRF vectors — `pkSm`, the recomputed 64-byte `proof` (`c || s`) generated from the vector's fixed `ProofRandomScalar`, and acceptance of the stored proof bytes by `VerifyProof`.

**Proof.** Transitivity through the byte-pinned file, per the FB68 T-1 template, specialized to the OPRF checkers.

*Leg 1 — file half green ⇒ pinned == independent-oracle.* `tools/test_c99_vector_files.sh`'s `chk_p256_oprf` (`:484-558`) recomputes every field from a **from-scratch python RFC 9497 pipeline** that shares no code with `src/crypto/*`: `contextString` (`:496`), `DeriveKeyPair` re-derived from `Seed`+`KeyInfo` and asserted `== sks_hex` (`:497-503`, so the key is proven, not copied), `Blind` via its own RFC 9380 SSWU hash-to-group (`:512-516`), `BlindEvaluate` (`:517-521`), `Finalize` with the length-prefixed transcript (`:522-528`), and for VOPRF: `pkS` (`:531-534`), `GenerateProof` with the fixed `r` reproducing `proof_hex` byte-for-byte (`:541-548`), and `VerifyProof` on the stored bytes returning accept (`:549-558`). Curve `p/a/b` are recovered from the `cryptography` library (not transcribed) and `n` cross-checked (`(n−1)*G == −G`, `n*G == identity`) — the same no-memory-constants discipline as the h2c file. Green ⇒ zero `bad:` lines ⇒ each pinned field equals this oracle's recomputation.

*Leg 2 — binary half green ⇒ C99 == pinned.* `determ test-c99-vectors`'s `p256_oprf` branch (`src/main.cpp:13242-13278`) drives the **shipped C99** functions over the same file and string-compares lowercase-hex outputs to the pinned fields: `derive_key` == `sks_hex` (`:13253-13255`), `blind` == `blinded_element_hex` (`:13256-13259`), `evaluate` == `evaluation_element_hex` (`:13260-13261`), `finalize` == `output_hex` (`:13262-13264`), and for VOPRF `base_mul`+`compress` == `pks_hex` (`:13268-13270`), `voprf_prove` from `proof_random_scalar_hex` == `proof_hex` (`:13271-13274`, the full 64 bytes), and `voprf_verify(stored proof) == accept` (`:13275-13277`). By FB68's L-1 (the file half's strict `unhex` guarantees canonical lowercase hex), these string comparisons are byte comparisons.

*Composition.* For each of the 4 vectors and each pinned field, `C99 == pinned == oracle`. The proof (both 32-byte halves) is covered twice over: the binary half regenerates it byte-exact AND re-accepts the stored bytes through the independent `voprf_verify`, and the file half does the same on the python side — so a `c`-half or `s`-half defect cannot pass. ∎

*Quantifier boundary.* The claim is over exactly these 4 inputs (2 fixed inputs `{0x00, 0x5a…5a}` × 2 modes, one fixed `Seed`/`KeyInfo`, one fixed `blind`, one fixed `ProofRandomScalar`). It is byte-exact conformance on a **fixed point set**, not over the input space — see L-1 below.

### T-2 — A tampered OPRF vector is caught by the file half alone, without the binary

**Statement.** Any state of `p256_oprf.json` in which a field is not consistent with the genuine RFC 9497 derivation — a flipped `output`/`proof`/element byte, a flipped `Seed`/`KeyInfo`/`input`/`blind`, a `type`/`mode` mismatch, a missing field, non-canonical hex, or a wrong `pks_hex` — turns `tools/test_c99_vector_files.sh` RED with no determ binary in the loop.

**Proof.** Case split, all landing on `chk_p256_oprf` returns or the shared strict-parse/verdict machinery (FB68 §1.1):
1. *Flipped output bytes.* `output`/`proof`/`blinded`/`evaluation`/`pks` are each recomputed from the (untampered) inputs and compared (`:515-516`, `:520-521`, `:527-528`, `:533-534`, `:547-548`); any flip is a direct mismatch string return.
2. *Flipped input bytes.* Recomputation now runs on the tampered `Seed`/`KeyInfo`/`input`/`blind`; surviving requires the tampered input to reproduce the untampered pinned outputs — a SHA-256 second-preimage (**A3**) for the Finalize/DeriveKeyPair transcripts, or an EC-relation break (a `blind` change preserving `blindedElement` and `output`; a `Seed` change preserving `skSm`). Infeasible.
3. *`type`/`mode` mismatch.* `(t, mode)` is constrained to `{(oprf,0),(voprf,1)}` (`:492-493`) — a crossed pair is an immediate string return; and `mode` flows into `contextString` (`:496`), so even a self-consistent re-label under the wrong mode fails DeriveKeyPair.
4. *Structural.* Missing fields → `need()` (`:488-490`, `:530`); non-canonical/odd hex → the strict `unhex` (FB68 L-1); a proof not 64 bytes or output not 32 bytes → explicit length checks (`:510`, `:536`). Each is a `bad:` line; the verdict forbids `bad:` on green. ∎

**Residual (inherited from FB68 T-2).** A **wholesale self-consistent substitution** — a different but internally-correct `(Seed, KeyInfo, input, blind, r)` tuple with its correctly-derived outputs — survives recomputation by construction; what it defeats is only the free-text **RFC A.3 attribution** (that these are the *published* vectors), not the gate's "C99 == oracle" soundness. Detection of substitution is by review + git history + the `source` field's fetch provenance (R46, §3), not by either half.

### T-3 — The structural test proves what accept-side vectors cannot: the protocol identity and DLEQ reject paths

**Statement.** `determ test-p256-oprf-c99` (`src/main.cpp:12393-12492`) establishes four properties that the 4 accept-only appendix vectors are structurally blind to, and a green result on it plus T-1 gives the joint conclusion of T-4:

- **(P-identity)** The §3.3.1 round-trip identity: client `blind → evaluate → finalize` equals the server-side direct `Evaluate(sk, input)` (simulated with `blind = 1`, whose inverse is 1). Assertion (2), `:12423-12441`. A vector set only ever shows one blind value; it never checks that a *different* blind unblinds to the *same* output — this assertion does.
- **(P-derive)** DeriveKeyPair is deterministic AND mode-separated: same `(seed, info)` under `mode 0x00` vs `0x01` yield **different** keys (the DST-separation RFC gotcha). Assertion (1), `:12410-12421`.
- **(P-reject-tamper)** VOPRF `prove → verify` accepts, and each of {tampered `c`, tampered `s`, tampered `evaluation` element (flipped parity), wrong mode-context `0x00` vs the `0x01` the proof was made under} is **rejected** (`verify == -1`). Assertion (3), `:12443-12465`. Accept-side vectors exercise only the accept path; the byte gate never sees a rejection.
- **(P-reject-soundness)** A proof generated under the WRONG key (`sk0` against `pk(sk1)`) does not verify — the DLEQ soundness shape — and invalid blinds (`0`, `≥ n`) are rejected. Assertion (4), `:12467-12485`.

**Proof.** Each is a direct assertion in the subcommand, read above; the subcommand returns nonzero on any failure (`:12487-12492`). (P-reject-tamper)/(P-reject-soundness) rest on the DLEQ verify equation and the constant-time challenge compare (`determ_ct_memcmp`, `:1099`): a tampered `c`/`s`/`Z` makes the verifier's recomputed `t2`/`t3` — and hence `c2` — diverge from the supplied `c`, so the compare fails; a wrong-key proof cannot satisfy `Z = di·D` and `s·G + c·B = t2` simultaneously without knowing `logG(pk)`. These are **structural** (they check the right thing rejects), not byte-exact; the accept-side vectors and the structural test are therefore complementary, not redundant. ∎

*Caveat.* (P-reject-*) demonstrate the *implemented* reject paths fire on the *specific* tampers injected; they are existence witnesses for soundness-shaped behaviour, not a proof of DLEQ soundness over all adversaries (that is L-3).

### T-4 — Composition: what T-1 + T-3 jointly establish, and the four limits

**Statement (joint conclusion).** For the RFC 9497 OPRF(P-256, SHA-256) single-element construction, the shipped C99 layer is (i) **byte-exact conformant** to the genuine appendix vectors across DeriveKeyPair/Blind/BlindEvaluate/Finalize/pkS/GenerateProof/VerifyProof including the 64-byte proof (T-1), and (ii) satisfies the protocol round-trip identity and fires the DLEQ/blind reject paths on the tested tampers (T-3) — the reject side that accept-only vectors cannot reach. The two legs also cover each other's blind spot in the FB68 mold: a corpus defect goes RED on the file half with no binary (T-2), a C99 defect on a covered input goes RED on the binary half localized to `src/crypto/p256/*` given the file half green (FB68 T-3 specialized).

**Limits (each explicit and handed off):**
- **L-1 — Bounded input set.** T-1 quantifies over exactly 4 fixed inputs/2 modes. Not exercised: other inputs/blinds/keys, the DeriveKeyPair counter actually *iterating* (all 4 vectors succeed at `counter = 0`), POPRF mode `0x02`, and batch m>1 DLEQ (A.3.2.3 is deliberately omitted — the layer is single-element; §4 L-1 of the README). The structural test (T-3) widens coverage to fresh non-vector inputs/keys but is not byte-pinned. New vectors would extend the set under the same gate.
- **L-2 — Underlying-primitive correctness is a forward-reference, not re-proved here.** Every OPRF operation is a transcript wrapped around `pt_scalar_mul` / `pt_add` / `hash_to_curve` / `hash_to_scalar` / `scalar_inv_mod_n`. This document proves the *transcripts* are RFC-correct and the *composed outputs* match the vectors; that the underlying scalar-mult/point-add/SSWU/mod-n are themselves correct and constant-time is the subject of **`P256CryptoStackAudit.md`** (the correctness companion) and is validated independently by `determ test-p256-c99` (OpenSSL EC_GROUP/EVP parity) + `test-p256-h2c-c99` (OpenSSL BIGNUM oracle + RFC 9380 vectors). T-1 does give end-to-end cover: a scalar-mult defect would make the composed OPRF bytes diverge from the vectors — but only on the covered inputs (L-1).
- **L-3 — Not a proof of the hardness assumptions.** OPRF pseudorandomness and VOPRF DLEQ soundness reduce to P-256 discrete-log / one-more-Diffie-Hellman hardness. This document assumes those (they are the ambient EC assumptions); it proves *conformance to the construction that is believed to realize them under those assumptions*, not the assumptions. A break of P-256 DL breaks the OPRF regardless of any byte-exactness here.
- **L-4 — Timing out of scope.** Byte gates and structural asserts are blind to timing. The layer's CT posture (ladder is double-and-add-always with mask-select cswap; SSWU is branchless; blind/msg are the secrets; the challenge compare is `determ_ct_memcmp`) is asserted in `src/crypto/p256/README.md` and probed by `determ ct-timing-probe` (tranche 3: `p256-base-mul`, `p256-h2c`, `p256-sc-mul`); the normative timing boundary is CRYPTO-C99-SPEC §3.12 / `ConstantTimeInventory.md`. This document asserts *functional* conformance only. ∎ (boundary statement)

---

## 3. Trust-base inventory

What must be trusted for T-1..T-3 to mean what they say, and why each is acceptable:

| Trusted component | Used by | Why acceptable |
|---|---|---|
| **RFC 9497 + RFC 9380 normative text** (the transcripts / DSTs / suite params) | the construction map §1; the vector provenance | **Fetched, not memorized** — the R46 lineage (`src/crypto/p256/README.md` §3.9b): the vectors were extracted mechanically from `rfc-editor.org/rfc9497.txt` and the protocol pseudocode implemented from the FETCHED text (`p256.c` comments + spec §3.9b state this explicitly). The `p256_oprf.json` `source` field records the extraction + re-derivation lineage in full. |
| **Two independent python RFC 9497 re-derivations** | T-1 leg 1 (file half); the vector import | (a) the **import-time** re-derivation cited in the `source` field (skSm+pkSm re-derived from Seed+KeyInfo, full §3.1/§3.2.1/§3.3/§3.3.2/§2.2 pipeline, 72/72 + 297/297 h2c-anchored checks); (b) the **continuously-run** `chk_p256_oprf` in `tools/test_c99_vector_files.sh` (`:484-558`) that re-performs DeriveKeyPair/Blind/BlindEvaluate/Finalize/GenerateProof/VerifyProof every run. Both share **zero source** with `src/crypto/p256/*` (different language, from-scratch SSWU + EC arithmetic). |
| **OpenSSL EC/BIGNUM oracle** (for the §3.8c/§3.9b enablers) | L-2's underlying-primitive validation | `determ test-p256-c99` asserts curve constants byte-equal OpenSSL `EC_GROUP` and `[k]G` byte-equal `EC_POINT_mul`; `test-p256-h2c-c99` checks mod-n ops vs the OpenSSL BIGNUM oracle. Independent lineage; the OPRF layer inherits this as its primitive-correctness base. |
| **The P-256 module's own correctness** (`P256CryptoStackAudit.md`) | L-2 | The adversarial correctness+CT audit of the field/RCB-addition/ladder/SSWU/mod-n layer the OPRF is built on — the forward-referenced companion that discharges the "right transcript over a correct primitive" leg. |
| python `json` + nlohmann::json | both §3.13 halves | (P-json): two mature parsers over a flat object of strings/ints. |

**Deliberately NOT in the trust base:** the determ binary/build (the file half runs without them — T-2); the `sks_hex`/`pks_hex` fields as authorities (both halves **re-derive** the key from `Seed`+`KeyInfo` and only then compare — the file's key claim is checked, not trusted); the free-text `source` provenance (asserted, not mechanically verified — T-2 residual). The load-bearing claim is the **independence** of the two python re-derivations and OpenSSL from `src/crypto/p256/*`: the same OPRF bytes reached from disjoint codebases (fetched RFC → python; fetched RFC → C99) is what makes a common-mode wrong-but-agreeing failure implausible (FB68 T-4(2), specialized).

---

## 4. Mechanized witnesses

| Layer | Script / subcommand | What it pins |
|---|---|---|
| Byte gate, file half | `tools/test_c99_vector_files.sh` (`chk_p256_oprf`) | T-1 leg 1 + T-2: independent python re-derivation of all 4 RFC 9497 vectors incl. the 64-byte proof + VerifyProof; no binary, offline, fail-closed |
| Byte gate, binary half | `determ test-c99-vectors` (`p256_oprf` branch, `src/main.cpp:13242-13278`), in `FAST=1` | T-1 leg 2: the 4 vectors through the shipped C99 functions, proof regenerated byte-exact + stored-proof re-accepted |
| Structural / negative | `determ test-p256-oprf-c99` (`src/main.cpp:12393-12492`) | T-3: (P-identity) blind/evaluate/finalize == direct Evaluate; (P-derive) mode-separated deterministic keygen; (P-reject-*) tampered c/s/eval, wrong-mode, wrong-key, invalid-blind all reject |
| Underlying primitives (context, L-2) | `determ test-p256-c99` / `test-p256-h2c-c99` | Curve-constant + `[k]G` + ECDH parity vs OpenSSL; mod-n vs BIGNUM oracle; RFC 9380 h2c appendix vectors — the correctness base under every OPRF operation |
| Index/tier guards (meta) | `tools/test_proofs_index_complete.sh`, `tools/test_doc_tier_check.sh` | This document's index row + tier banner coherence (the index row is threaded separately by the orchestrator) |

The two-leg split is the FB68/FB69 instantiation of defense-in-depth for the OPRF corpus: the byte gate (T-1) is the **conformance** witness (equal to the genuine RFC vectors, both proof halves), the structural test (T-3) is the **reject-path + identity** witness the accept-only vectors cannot provide, and T-4 is the statement that their conjunction — bounded by L-1..L-4 — is what "the C99 OPRF is RFC 9497-conformant" means for this layer.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `src/crypto/p256/p256.c` (`oprf_*` / `voprf_*` / `_oprf_*`) | The shipped OPRF layer — every construction-map claim in §1 is verified against these functions. |
| `include/determ/crypto/p256/p256.h` | The public API contracts (DST quirks, wire format, determinism note). |
| `tools/vectors/p256_oprf.json` | The 4 genuine RFC 9497 A.3.1/A.3.2 vectors — the byte-pinned middle term (T-1/T-2). |
| `tools/test_c99_vector_files.sh` (`chk_p256_oprf`, `:484-558`) | Byte gate file half: independent python re-derivation (T-1 leg 1, T-2). |
| `src/main.cpp:13242-13278` (`test-c99-vectors` `p256_oprf`) | Byte gate binary half: the vectors through the shipped C99 (T-1 leg 2). |
| `src/main.cpp:12393-12492` (`test-p256-oprf-c99`) | Structural/negative test (T-3). |
| `docs/proofs/P256CryptoStackAudit.md` | The correctness+CT companion for the underlying P-256 primitives (L-2 forward-reference). |
| `docs/proofs/VectorGateComposition.md` (FB68) | The two-half §3.13 gate mechanics this document instantiates (L-1, L-1-lemma, the fail-attribution split). |
| `docs/proofs/CRYPTO-C99-SPEC.md` §3.9b / §3.8c / §3.13 | The OPRF/curve/vector-gate design entries. |
| `docs/proofs/ConstantTimeInventory.md` / §3.12 | The timing boundary handed off in L-4. |
| `src/crypto/p256/README.md` | Module provenance + the R46 vector/pseudocode fetch lineage (trust base §3). |
| RFC 9497 (OPRF) / RFC 9380 (hash-to-curve) | The fetched normative texts — the construction the map §1 conforms to. |
| `docs/proofs/Preliminaries.md` §2.0 | Canonical assumption labels (A2/A3 — used in T-2; the EC hardness leg in L-3). |

---

## 6. Status

- **Spec.** Complete (this document, FB69).
- **Both byte-gate halves + the structural test shipped and green.** The file half (`chk_p256_oprf`), binary half (`test-c99-vectors` `p256_oprf`), and `test-p256-oprf-c99` all validate the 4 RFC 9497 A.3.1/A.3.2 vectors + the reject paths; the C99 output including the 64-byte proof is byte-exact.
- **Theorems.** T-1 (byte-exact conformance on the covered inputs incl. both proof halves, by transitivity through the byte-pinned file), T-2 (a tampered OPRF vector caught by the file half alone, no binary; residual: self-consistent substitution defeats only the free-text RFC attribution), T-3 (the structural test proves the round-trip identity + the DLEQ/blind reject paths the accept-only vectors cannot), T-4 (the joint conclusion + the four limits) — all closed. A2/A3 enter in T-2; EC hardness is assumed in L-3.
- **Limits (T-4).** L-1 bounded fixed-input set (POPRF/batch out of scope); L-2 underlying-primitive correctness forward-referenced to `P256CryptoStackAudit.md` + the OpenSSL parity tests; L-3 hardness assumptions assumed not proved; L-4 timing → §3.12 / `ConstantTimeInventory.md`.
- **Trust base.** Fetched RFC 9497/9380 text (R46 provenance), two independent python re-derivations (import-time + the continuously-run file half), the OpenSSL EC/BIGNUM oracle for the enablers, and the P-256 module's own audited correctness — all sharing zero source with `src/crypto/p256/*`.
