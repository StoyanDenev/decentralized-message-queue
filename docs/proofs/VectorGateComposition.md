> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# VectorGateComposition — trust analysis of the two-half §3.13 vector gate (file corpus vs shipped C99) (FB68)

This document is the FB-track trust analysis of the **CRYPTO-C99-SPEC §3.13 test-vector gate** — the pair of independent checks that together pin the shipped libsodium-free C99 crypto stack (`src/crypto/*`) byte-for-byte against an external reference, *through* a byte-pinned vector corpus (`tools/vectors/*.json`):

- **Half (a) — the file half**, `tools/test_c99_vector_files.sh`: every vector file is schema-validated and every vector **fully recomputed** by INDEPENDENT python implementations (stdlib `hashlib`/`hmac` for the hash/MAC/KDF families; `cryptography.hazmat` for the AEAD + curve families). Needs **no determ binary**, never SKIPs, runs offline.
- **Half (b) — the binary half**, `determ test-c99-vectors` (`src/main.cpp:12166-12347`, wrapper `tools/test_c99_vectors.sh`, in `FAST=1`): the **same** files are fed through the shipped C99 implementations and the outputs string-compared against the pinned hex.

The composition is a classic two-witness argument with the corpus as the shared middle term: half (a) green pins *file == oracle*; half (b) green pins *C99 == file*; together they pin **C99 == oracle on every corpus vector** (T-1), with each half additionally covering the other's blind spots (the strict-parses-for-the-lenient lemma L-1, the vacuous-pass mask W-2). The two failure directions separate cleanly: a corrupted/fabricated vector file turns half (a) RED with no binary in the loop (T-2); a C99 implementation defect on a covered input turns half (b) RED with the fault *localized* to `src/crypto/*` because (a) has already exonerated the corpus (T-3). What the gate cannot see — inputs outside the corpus, common-mode oracle agreement-on-wrong, and all timing properties — is bounded explicitly in T-4 and handed to its neighbours (`C99CryptoStackAudit.md` §1.1's structural-blindness list; `ConstantTimeInventory.md` / §3.12 for timing).

**Assumptions.** The theorems are mostly *mechanical* (exact string/byte equality of deterministic functions); cryptography enters only at the edges. Canonical labels per `Preliminaries.md` §2.0: **A2** = SHA-256 collision resistance, **A3** = SHA-256 preimage / second-preimage resistance — used once, in T-2's input-tamper case (a tamper that survives recomputation must find a second input mapping to the pinned output). Operational assumptions: **(P-corpus)** both halves read the same `tools/vectors/*.json` bytes (both repo-root-relative; the wrappers `cd` to repo root); **(P-oracle)** the python oracle stack computes the published algorithms correctly (the trust base, inventoried in §3); **(P-json)** python's `json` module and nlohmann::json agree on the parse of the same well-formed flat-object bytes.

**Companion documents.** `CRYPTO-C99-SPEC.md` §3.13 (the gate's design entry: both halves, the no-fabrication rule, the argon2id omission), §Q7 (test-vector validation design), §Q9 (the OpenSSL cross-validation gate the per-primitive `test-*-c99` subcommands implement); `C99CryptoStackAudit.md` §1.1 (the two validation layers and the four structural-blindness classes that frame T-4); `ConstantTimeInventory.md` (the §3.12 boundary: what *timing* verification needs that no byte compare can give); `src/crypto/*/README.md` (per-module provenance + version pins — the "independent lineage" leg of §3).

---

## 1. The gate as shipped

### 1.1 Half (a) — `tools/test_c99_vector_files.sh` (file corpus vs python oracles)

A single embedded python runner (`:31-245`) over the corpus. Checks, in order:

| Check | Mechanics | Failure mode |
|---|---|---|
| corpus presence | `EXPECTED` 10-file set (`:37-41`) vs the `tools/vectors/*.json` glob (`:202-205`); a missing expected file is `bad:`; an **extra** file is still validated but flagged `ok: note: … add it to EXPECTED when intentional` (`:206-207`) | fail-closed on deletion/rename |
| oracle availability | `cryptography.hazmat` import failure emits `bad:` (`:43-51`) — counted as a mismatch by the verdict logic, i.e. **FAIL, not SKIP** | fail-closed on missing oracle |
| JSON well-formedness | `json.load` per file (`:209-215`) | `bad:` on parse error |
| file schema | `primitive` non-empty str, `source` non-empty str, `vectors` non-empty list (`:217-223`) | `bad:` per missing/empty key |
| primitive dispatch | `CHECKERS` map (`:189-200`); an unknown `primitive` is `bad: … no recomputation path (fail-closed)` (`:224-227`) | fail-closed on unknown discriminator |
| per-vector fields | `need()` presence check (`:62-65`); **strict canonical hex** — `unhex()` rejects non-string, odd-length, non-hex, AND non-lowercase-canonical re-encodings (`:53-60`); range/length sanity (`mac_len ∈ [1,32]`, `mac_hex` length == `mac_len`, `okm_hex` length == `length`, digest length == declared width, `outlen ∈ [1,64]`, AEAD tag == 16 bytes) | `bad:` per violation |
| **full recomputation** | sha256/sha512: `hashlib.new` over `msg_hex` (× optional `repeat`) == `digest_hex` (`:78-84`); hmac_sha256: stdlib `hmac.new` truncated to `mac_len` (`:86-95`); pbkdf2: `hashlib.pbkdf2_hmac` (`:97-104`); hkdf: **two oracles** — a from-scratch RFC 5869 extract+expand on stdlib `hmac` (`:67-75`) AND `hazmat HKDF`, required to agree with each other (runner self-check, `:115-117`) and with `okm_hex`; blake2b: `hashlib.blake2b` keyed + `digest_size` (`:120-129`); AEAD (ChaCha20-Poly1305 / AES-256-GCM): hazmat `encrypt == ct‖tag` **and** `decrypt(ct‖tag) == pt` (`:131-145`); ed25519: derive pubkey from seed == `public_key_hex`, deterministic RFC 8032 `sign == signature_hex`, `pk.verify` accept (`:147-159`); x25519: `scalarmult` shape (`:163-169`) and full `dh` shape — base-derive **both** publics + shared secret equal from **both** directions (`:170-185`); unknown `type` is an error (`:186-187`) | `bad:` per byte of drift |
| exception hygiene | any exception during recomputation becomes `bad: … exception during recomputation` (`:237-242`) | fail-closed, never silent |
| verdict | PASS iff zero `bad:` lines **and >0 `ok:` lines** — "zero ok-lines — verifier produced no positive evidence (treated as failure)" (`:253-265`); python non-zero exit adds a mismatch (`:247-251`) | no green-by-default path |

### 1.2 Half (b) — `determ test-c99-vectors` (file corpus vs shipped C99)

The `src/main.cpp:12166-12347` dispatch block (help text `:460`; design comment `:12167-12177` states the fail-attribution intent: "A divergence here with the file-side runner green means OUR code is wrong, not the vectors"). Checks:

| Check | Mechanics | Failure mode |
|---|---|---|
| file list | hardcoded 10-name `files[]` (`:12191-12194`) — the **same set** as half (a)'s `EXPECTED` (verified name-for-name; order differs); default dir `tools/vectors`, optional `[dir]` arg (`:12190`) | missing/unreadable file is a per-file FAIL ("vector file present", `:12199`) |
| JSON parse | nlohmann `f >> doc` (`:12200-12203`) | FAIL with the parser diagnostic |
| dispatch | per-file `primitive` discriminator; unknown value is FAIL "unknown primitive discriminator" (`:12325-12328`) — the comment names the rationale: "silently skipping a vector class would read as coverage" | fail-closed |
| recompute | sha256/sha512: `determ_sha256`/`determ_sha512` with the same `repeat` expansion (`:12211-12230`); `determ_hmac_sha256` truncated to `mac_len` (`:12231-12236`); `determ_hkdf_sha256` (`:12237-12243`); `determ_pbkdf2_hmac_sha256` (`:12244-12250`); `determ_blake2b` keyed/varlen (`:12251-12257`); `determ_chacha20_poly1305_encrypt` == `ciphertext_hex`+`tag_hex` **and** `determ_chacha20_poly1305_decrypt(ct, tag) == pt` round-trip (`:12258-12273`); same encrypt+decrypt pair for `determ_aes256_gcm_*` (`:12274-12289`); ed25519: `determ_ed25519_pubkey_from_seed` == `public_key_hex`, `determ_ed25519_sign` == `signature_hex`, `determ_ed25519_verify` accept (`:12290-12299`); x25519 **dual shape**: `dh` — `determ_x25519_base` derives both publics + `determ_x25519` shared from both directions (`:12306-12317`); `scalarmult` — `determ_x25519(scalar, u) == output_hex` (`:12318-12324`); AEAD key/nonce length pre-checks 32/12 (`:12261`, `:12277`) | per-file FAIL naming the diverging vector |
| schema surprise | a missing/odd-typed field throws inside nlohmann; the catch converts it to FAIL "(schema: …)" rather than a crash (`:12329-12334`) | fail-closed |
| verdict | one PASS/FAIL line per file (`:12336-12338`); terminal `PASS: c99-vectors …` iff zero failures (`:12341-12346`); the wrapper `tools/test_c99_vectors.sh` greps that exact summary (with the re-pin-on-change comment, per the `test_frost_c99.sh` stale-pin precedent) | wrapper FAILs on any other output |

### 1.3 The corpus

`tools/vectors/<primitive>.json` — 10 files, one per shipped primitive family (sha256, sha512, hmac_sha256, pbkdf2_sha256, hkdf_sha256, blake2b, chacha20_poly1305, aes256_gcm, ed25519, x25519). Flat schema: `{primitive, source, vectors[]}` with per-vector named hex fields. Provenance is **mixed**, and each file's free-text `source` field says so: the published anchors are NIST FIPS 180-2 SHA examples + CAVP, RFC 4231, RFC 7914 §11, RFC 5869 A.1-A.3, RFC 7693, RFC 8439 §2.8.2, the McGrew-Viega GCM AES-256 KATs, RFC 8032 §7.1, and RFC 7748 §5.2 + §6.1; several files *additionally* carry oracle-**generated** boundary cases (AEAD block-boundary plaintexts, HKDF `L ∈ {0, 32, 8160}`, keyed-BLAKE2b edge shapes, low-`c` PBKDF2 pairs), labeled per file in the `source` field ("generated", "well-known", "python hashlib.blake2b reference cases") and in the vector names — those carry oracle provenance only, no published-KAT leg (see T-4(2)). Per the no-fabrication rule (`CRYPTO-C99-SPEC.md` §3.13), every vector — published or generated — was mechanically recomputed before inclusion — half (a) *re-performs* that recomputation on every run, so the rule is enforced continuously, not just at authoring. The corpus is growing under the same gate (each addition must pass both halves); this document therefore pins the **file set and schema**, not a vector count. Argon2id is deliberately absent (no local python oracle); its KATs are pinned in `determ test-argon2id-c99` instead.

---

## 2. Theorems

### L-1 — Corpus canonicality (the strict half sanitizes the lenient half)

**Statement.** Half (a) green implies every hex field in every EXPECTED file is canonical lowercase even-length hex, every required field is present, and every length/range constraint holds. Consequently half (b)'s deliberately lenient parsing — its `unhex` consumes byte pairs and would silently drop a trailing odd nibble (`:12183-12184`), and its comparisons are exact *string* equality between the file's hex and the lowercase output of `hx` (`:12185-12186`) — is sound on any corpus half (a) has vetted: on canonical input, lenient parse == strict parse, and lowercase string equality == byte equality.

**Proof.** Half (a)'s `unhex` (`:53-60`) raises unless `bytes.fromhex(v).hex() == v` — i.e. unless the string is the canonical lowercase even-length encoding of its own byte value; `need` + the explicit length checks cover presence and ranges; any raise is a `bad:` line and the verdict logic forbids `bad:` lines on green. On such a string, half (b)'s pairwise parse reads exactly the same bytes (no odd tail exists to drop), and since `hx` emits canonical lowercase, `hx(C99_output) == file_hex` as strings iff `C99_output == file_bytes` as bytes. ∎

This is a genuine composition dependency, not a nicety: an UPPERCASE-hex *expected-output* field would *fail* half (b)'s string compare even with a correct C99 (its `hx` emits lowercase), while an UPPERCASE-hex *input* field would be silently tolerated ((b)'s `std::stoi(…,16)` accepts either case) — one direction a spurious red, the other a quiet leniency. Half (a)'s strict `unhex` rules both out before (b) ever runs.

### T-1 — Both halves green ⇒ C99 == python oracle on every corpus vector

**Statement.** If half (a) and half (b) both PASS over the same corpus bytes (P-corpus), then for **every** vector `v` in every EXPECTED file, the shipped C99 implementation and the python oracle compute identical bytes on `v`'s inputs — across the full exercised surface: digest/MAC/KDF outputs, AEAD `ct‖tag` **and** the authenticated decrypt round-trip, ed25519 pubkey-derivation + deterministic signature + verify-accept, x25519 both shapes (and, for `dh`, both directions).

**Proof.** Transitivity through the byte-pinned file, leg by leg.

*Leg 1 — (a) green ⇒ `oracle(v) == pinned(v)` for all `v`.* Half (a) iterates every entry of every corpus file (`:209-244`) with no skip path: every file is either fully checked or emits `bad:` (missing oracle, bad JSON, bad schema, unknown primitive — §1.1's fail-closed rows), and every vector either matches the recomputation byte-for-byte or emits `bad:`. Green means zero `bad:` and positive `ok:` evidence, so each pinned expected-output field equals the oracle's recomputation of the pinned inputs. By L-1 the hex-string comparisons are byte comparisons.

*Leg 2 — (b) green ⇒ `C99(v) == pinned(v)` for all `v`.* Half (b) iterates every entry of every file on its list (`:12196-12339`), which equals the EXPECTED set (§1.2 row 1), again with no skip path (missing file, parse failure, unknown discriminator, schema surprise are all FAILs). Green means every C99 output, lowercase-hex-encoded, string-equals the pinned field — by L-1, byte-equals the pinned bytes — and every round-trip/verify leg returned success.

*Composition.* For each `v`, `C99(v) == pinned(v) == oracle(v)`. The shape tables in §1.1/§1.2 are in one-to-one correspondence (same input fields, same expected-output fields, same conditional legs: `repeat`, `mac_len` truncation, AEAD decrypt round-trip, ed25519 sign+verify, x25519 `type` discriminator), so the equality covers the full exercised surface, not just a common subset. ∎

*Remark (quantifier boundary).* The quantifier is over the 10-file EXPECTED corpus. An 11th file dropped into `tools/vectors/` is recomputed by (a) (extra-file note) but NOT exercised by (b) until `files[]` is extended — see T-4(1) and W-3.

### T-2 — A tampered or wrong vector file is caught by half (a) alone, without the binary

**Statement.** Any corpus state in which some vector is not a correct, well-formed input→output pair under the reference algorithm — a flipped output byte, a flipped input byte, a deleted/renamed file, malformed JSON, a missing field, non-canonical hex, an out-of-range length, an unknown `primitive` or x25519 `type` — turns half (a) RED. Half (a) requires no determ binary, no build, no network: a corrupted corpus cannot sit silently waiting for the next binary run.

**Proof.** Case split on the tamper class:

1. *Output bytes.* The oracle recomputes the output from the (untampered) inputs; the recomputation is deterministic (RFC 8032 signing included), so any flipped output byte is a direct mismatch → `bad:`.
2. *Input bytes.* The recomputation now runs on the tampered inputs and is compared against the untampered pinned output. Surviving requires the tampered input to map to the *same* pinned output — a second preimage for the hash/MAC/KDF families (**A3**-hard), and the analogous one-wayness break for the AEAD (a `(key,nonce,aad,pt)` change preserving `ct‖tag`) and curve families (a seed change preserving `pk` and the signature; a scalar change preserving the shared secret). All cryptographically infeasible.
3. *Structure.* Deleted/renamed file → the EXPECTED-missing loop; malformed JSON → the parse `bad:`; missing/empty top-level keys → the schema rows; missing per-vector fields → `need`; non-canonical/odd/non-hex → the strict `unhex`; out-of-range lengths → the explicit checks; unknown discriminators → the fail-closed CHECKERS / `type` branches. Each lands on a `bad:` line enumerated in §1.1. ∎

**Residual (provenance is asserted, not proved).** One corpus edit survives recomputation by construction: a **wholesale substitution** of a vector by a *different but self-consistent* pair — correctly computed under the real algorithm, just not the published KAT the `source` field claims. This does not weaken T-1 (a substituted vector is still a correct pair, so "C99 == oracle" is still exactly what gets checked, on different points); what it weakens is the **RFC/NIST attribution**, which is free text and mechanically unverifiable by either half. Detection of substitution is by review and git history, not by this gate. The practical consequence surfaces in T-4(2): the published-KAT leg of the common-mode argument holds only for vectors whose provenance is genuine.

### T-3 — A C99 defect on a covered input is caught by half (b), and localized, given (a) green

**Statement.** Assume half (a) is green. Then (i) any C99 implementation defect that changes behaviour on some corpus input — a wrong output byte, a decrypt that fails to invert encrypt or rejects a genuine tag, an ed25519 verifier that rejects a genuine signature, an asymmetric x25519 exchange — turns half (b) RED, naming the file and vector; and (ii) the simultaneous observation "(a) green, (b) red" **localizes** the fault to the shipped C99 code (or the §1.2 harness), not the corpus.

**Proof.** (i) By T-1 leg 1, (a) green gives `pinned(v) == oracle(v)` for every `v`. If the C99 output on `v`'s inputs differs from the oracle's, it differs from `pinned(v)`, so half (b)'s exact compare on that field fails → per-file FAIL → terminal FAIL (`:12336-12346`). The legs that are *not* direct byte pins extend coverage past the file's contents: the AEAD decrypt round-trip (`:12268-12273`, `:12284-12289`) catches a decrypt-side defect even though the file pins only encrypt outputs; the ed25519 `verify` call (`:12298-12299`) catches a verifier that rejects genuine signatures; the `dh` both-directions check (`:12314-12317`) catches a ladder defect that breaks commutativity. (ii) A red (b) means some C99 output ≠ `pinned(v)` (or a round-trip/verify leg failed). If the corpus were at fault, (a) — which recomputes every pinned byte with implementations sharing **no code** with `src/crypto/*` (§3) — would have flagged it; (a) green therefore exonerates the corpus, leaving the C99 side (or the §1.2 harness plumbing) as the only fault domain. This is precisely the fail-attribution the dispatch comment designs for (`:12170-12173`). ∎

*Caveat.* "On a covered input" is load-bearing: T-3 says nothing about inputs the corpus does not reach — that boundary is T-4(1).

### T-4 — Limits: what the gate cannot catch

**Statement and discussion.** Four classes, mapped onto `C99CryptoStackAudit.md` §1.1's structural-blindness frame:

1. **Inputs outside the corpus.** The gate quantifies over the corpus's input shapes only. Not exercised here: lengths/boundaries beyond the vectors (multi-block edges not in the corpus, the large-input counter boundaries of audit §1.1 class 1); **negative-path behaviour** — the AEAD decrypt legs run only with the *correct* tag, so a tag-verification bug that *accepts* a wrong tag is invisible to this gate (it is pinned instead by the tamper cases in the per-primitive `test-*-c99` subcommands); primitives without a corpus file (Argon2id — no local oracle, KATs pinned in `test-argon2id-c99`; FROST; future primitives as they ship per §3.13's "remaining"; secp256k1 was rejected 2026-07-07 and never built, so it is NOT a future corpus entry). Structurally: a NEW vector file is recomputed by (a) but silently un-exercised by (b) until `files[]` grows (W-3).
2. **Common-mode agreement-on-wrong.** If the C99 code and the python oracle compute the *same wrong* function, both halves stay green. Why this is implausible (but not impossible): the oracle stack is OpenSSL-lineage for most families — CPython's `hashlib`/`pbkdf2_hmac` bind OpenSSL via `_hashlib`, and `cryptography.hazmat` is an OpenSSL binding — plus CPython's vendored BLAKE2 reference module (`hashlib.blake2b` is *not* OpenSSL-backed; OpenSSL's EVP exposes only the unkeyed 64-byte digest, which is why the house blake2b oracle has always been hashlib — see `test-blake2b-c99`); the C99 stack shares **zero source** with either lineage (vendored/from-scratch per `CRYPTO-C99-SPEC.md` §Q3, e.g. the TweetNaCl-derived ed25519, the from-scratch Montgomery ladder). A common-mode wrong output therefore requires the same functional error independently present in OpenSSL (or the BLAKE2 reference) *and* in the determ C99 code *and* — for genuinely-published vectors — in the values printed in the RFC/NIST documents themselves, at which point "wrong" stops being meaningful (published-KAT interop *is* the spec). The HKDF family raises the bar further: half (a) runs **two** oracles (from-scratch stdlib-hmac RFC 5869 + hazmat) and requires three-way agreement. The argument thins exactly where T-2's residual bites: a self-consistently substituted vector loses the published-KAT leg and rests on OpenSSL-vs-C99 independence alone — and the corpus's deliberately *generated* boundary vectors (§1.3) sit in that oracle-only regime by construction, their `source` fields saying so honestly.
3. **Timing properties.** Byte compares are structurally blind to timing (audit §1.1 class 2): both halves would stay green if every C99 primitive leaked its key through a secret-dependent branch, table index, or short-circuit compare. Explicitly **out of scope** — the boundary is `CRYPTO-C99-SPEC.md` §3.12 (the dudect/ctgrind verification framework), whose seed inventory is `ConstantTimeInventory.md` (what is secret, which mechanism keeps it constant-time, what §3.12 must measure). This gate asserts *functional* equality only.
4. **Memory-safety and hygiene on adversarial inputs.** The corpus is well-formed by construction (and half (a) enforces it), so allocation-failure paths, overflow guards, and zeroization (audit §1.1 classes 3-4) are never exercised here; they are the subject of `C99CryptoStackAudit.md`'s adversarial review and its remediation commit. ∎ (boundary statement)

---

## 3. Trust-base inventory

What must be trusted for the gate's verdicts to mean what T-1..T-3 say, and why each item is an acceptable oracle:

| Trusted component | Used by | Why acceptable |
|---|---|---|
| CPython stdlib `hashlib` (SHA-256/512, `pbkdf2_hmac` — OpenSSL-backed via `_hashlib`; `blake2b` — CPython's vendored BLAKE2 reference module) | half (a) hash/KDF recompute | Mature, massively deployed, **independent lineage** from `src/crypto/*` (no shared source, different authors, different language); the blake2b path is reference-lineage rather than OpenSSL, diversifying the oracle stack |
| CPython stdlib `hmac` | half (a) HMAC + the from-scratch HKDF oracle | Pure-python RFC 2104 composition over `hashlib` — a *construction-level* second implementation, not a binding |
| pyca/`cryptography` hazmat (ChaCha20Poly1305, AESGCM, Ed25519, X25519, HKDF) | half (a) AEAD/curve recompute | OpenSSL binding; the de-facto python crypto standard; independent of `src/crypto/*`. Its absence is a FAIL, not a SKIP (`:43-51`) |
| python `json` + nlohmann::json | halves (a)/(b) respectively | (P-json): two mature standards-conformant parsers over flat objects of strings/ints; a divergent parse of the same well-formed bytes would be a parser bug in one of the two most-exercised JSON implementations in their ecosystems |
| harness plumbing | both halves | half (a)'s verdict logic is grep-counting with a positive-evidence floor (`:253-265`) — no green-by-default; half (b)'s `check()` accounting + the wrapper's pinned summary-grep (stale-pin risk documented in the wrapper itself, per the `test_frost_c99.sh` precedent: a stale pin fails on *every* run, i.e. loudly) |

**Deliberately NOT in the trust base:** the determ binary and build (half (a) runs without them — that is its point); the vector files themselves (the object under test for (a), a vetted middle term for (b)); the free-text `source` provenance (asserted, not verified — T-2 residual). The independence claim is the load-bearing one: `src/crypto/*` was written as the OpenSSL/libsodium *replacement* (per-module provenance in `src/crypto/*/README.md`), so the C99 side and the oracle side reach the same bytes from disjoint codebases — which is exactly what makes T-4(2)'s common-mode failure implausible.

**Coverage asymmetries (each half covers the other's blind spots):**

- **W-1** — (b)'s lenient hex parse and string-equality compares are sound only on a canonical corpus; (a)'s strict `unhex` guarantees it (L-1).
- **W-2** — (b) would PASS a file whose `vectors` key is absent or empty *vacuously* (nlohmann `doc["vectors"]` on a missing key yields null, whose `.size()` is 0, so the loop body never runs and the per-file check reports "0 vector(s) byte-equal"); (a)'s schema row requires `vectors` to be a **non-empty list**, masking the vacuous path. A reviewer reading (b)'s green alone should remember it is conditional on (a)'s schema gate.
- **W-3** — (b)'s coverage is its hardcoded `files[]`; (a)'s is the glob + EXPECTED. The two lists are equal today (verified name-for-name, §1.2) but are maintained at two sites; extending the corpus requires touching **both** (plus (a)'s `EXPECTED`). Drift is loud in one direction (a file in `files[]` but deleted from disk FAILs (b)) and quiet in the other (a new file validated by (a) but absent from `files[]` is silently un-exercised by the binary — (a)'s extra-file note is the only flag).

---

## 4. Mechanized witnesses

| Layer | Script / subcommand | What it pins | Run in-session (2026-06-11) |
|---|---|---|---|
| File half | `tools/test_c99_vector_files.sh` | T-2 in full + T-1 leg 1: schema + strict-hex + full oracle recomputation of every vector in every corpus file; fail-closed on every structural surprise; no binary, never SKIPs, offline | **PASS** — zero `bad:` lines over the full corpus (the `ok:`-line count tracks the growing corpus) |
| Binary half | `determ test-c99-vectors` via `tools/test_c99_vectors.sh` (in `FAST=1`) | T-1 leg 2 + T-3: every corpus vector through the shipped C99 implementations, AEAD decrypt round-trips, ed25519 pubkey+sign+verify, x25519 dual shape; fail-closed on missing file / unknown discriminator / schema surprise | **PASS** — all 10 per-file PASS lines + the terminal `PASS: c99-vectors` summary |
| Per-primitive cross-validation (context) | `determ test-sha2-c99 / test-blake2b-c99 / test-chacha20-c99 / test-xchacha-c99 / test-aes-c99 / test-ed25519-c99 / test-x25519-c99 / test-argon2id-c99 / test-ct-c99` | The §Q9 OpenSSL/KAT cross-validation grids — audit §1.1 layer (a). These shrink T-4(1)'s outside-the-corpus residual (length grids, tamper rejection) and carry the Argon2id KATs the corpus omits | not re-run here (out of this document's scope; exercised by `run_all.sh`) |
| Index/tier guards (meta) | `tools/test_proofs_index_complete.sh`, `tools/test_doc_tier_check.sh` | This document's index row + tier banner stay coherent | per run_all.sh |

The two-half split is itself defense-in-depth in the FB61/FB62 mold: the file half is the **pre-build, any-host** guard (a corrupted corpus goes RED on a machine that cannot even compile determ), the binary half is the **shipped-code** guard, and T-1 is the statement that their conjunction is stronger than either — equality to an independent oracle, not merely internal consistency.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `tools/test_c99_vector_files.sh` | Half (a): schema + strict hex + full python recomputation (§1.1; T-1 leg 1, T-2, L-1). |
| `src/main.cpp:12166-12347` (`test-c99-vectors`; help `:460`) | Half (b): the corpus through the shipped C99 implementations (§1.2; T-1 leg 2, T-3). |
| `tools/test_c99_vectors.sh` | Half (b)'s wrapper — pinned summary-grep, in `FAST=1` (`tools/run_all.sh` ONLY_PATTERN). |
| `tools/vectors/*.json` | The byte-pinned middle term: 10 files, one per shipped primitive family (§1.3). |
| `docs/proofs/CRYPTO-C99-SPEC.md` §3.13 / §Q7 / §Q9 / §Q3 | The gate's design entry; test-vector validation design; the OpenSSL cross-validation gate; per-primitive vendoring provenance (the independence leg of §3). |
| `docs/proofs/C99CryptoStackAudit.md` §1.1 | The two validation layers + the four structural-blindness classes that frame T-4; classes 3-4 (memory safety, zeroization) are its subject, not this gate's. |
| `docs/proofs/ConstantTimeInventory.md` | The §3.12 boundary: per-module secret inventory + CT mechanisms — what timing verification needs that no byte compare can provide (T-4(3)). |
| `src/crypto/*/README.md` | Per-module provenance + version pins backing the §3 independent-lineage claim. |
| `determ test-argon2id-c99` | Where the Argon2id KATs live (corpus omission, §1.3 / T-4(1)). |
| `CanonicalSigningBytesParity.md` (FB61) / `BlockDigestCrossBinaryParity.md` (FB62) | The sibling two-witness/parity proofs whose layered-guard discipline (pre-build half + built-binary half + negative controls) this gate instantiates for the crypto corpus. |
| `Preliminaries.md` §2.0 / §2.1 | Canonical assumption labels (A2/A3 — used only in T-2's input-tamper case). |

---

## 6. Status

- **Spec.** Complete (this document, FB68).
- **Both halves shipped and green.** Half (a) `tools/test_c99_vector_files.sh` and half (b) `determ test-c99-vectors` both PASS in-session (2026-06-11) over the live corpus; the corpus is being extended under the same gate (every addition must survive both halves), so this document pins the file set and mechanics, not vector counts.
- **Theorems.** L-1 (corpus canonicality — the strict half sanitizes the lenient half), T-1 (both green ⇒ C99 == python oracle on every corpus vector, by transitivity through the byte-pinned file), T-2 (a tampered/wrong vector file is caught by (a) alone, no binary; residual: self-consistent *substitution* defeats only the free-text provenance, not the gate's soundness), T-3 (a C99 defect on a covered input is caught by (b) and localized to `src/crypto/*` given (a) green) — all closed mechanically; A2/A3 enter only in T-2's input-tamper case.
- **Limits (T-4).** Open by design and handed off: inputs outside the corpus + negative-path tamper rejection → the per-primitive `test-*-c99` grids; common-mode agreement-on-wrong → bounded by the disjoint OpenSSL/reference vs vendored-C99 lineages (and the dual-oracle HKDF check), thinnest where provenance is unverified; timing → §3.12 / `ConstantTimeInventory.md`; memory-safety/zeroization → `C99CryptoStackAudit.md`.
- **Maintenance hazards (named).** W-3 two-site file-list maintenance (a new corpus file must be added to both (a)'s `EXPECTED` and (b)'s `files[]`); the wrapper's pinned summary string (stale-pin fails loudly, by design); W-2's vacuous-pass path in (b) is masked by (a)'s schema gate and would become live only if (a) were weakened.

---
