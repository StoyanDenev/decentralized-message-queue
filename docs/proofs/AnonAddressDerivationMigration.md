# Anon-address derivation migration — resolving the v1.0 `pubkey_form` compat-break

**Status:** OPEN — design analysis pending decision-authority sign-off. This is a forward-looking options analysis, NOT a re-decision. It exists to give the project the information it needs to MAKE the §7.6.7 address-derivation decision before v1.0 mainnet, and to propose that the resolution be recorded in `DECISION-LOG.md` once made.

**Trigger.** Sibling agent A5 flagged a compat-break in `docs/proofs/SchemaDiscriminatorsImpl.md §4` (shipped round 1, commit `6e529e8`): adopting the §7.6.7 requirement that the `pubkey_form` discriminator MUST enter the address-derivation preimage CHANGES the v1.0 address-derivation formula, because the current formula (`include/determ/types.hpp::make_anon_address`) binds no discriminator and applies no hash. A5 recommended Option A (hash-based) pending sign-off but explicitly noted the decision is not pre-resolved in `Improvements.md` / `DECISION-LOG.md`. This document is the focused analysis that tees up that decision.

**Companion documents.**
- `docs/proofs/SchemaDiscriminatorsImpl.md` §4 — A5's finding (the implementation spec for the seven §7.5 discriminators; §4 is the address-derivation lock-in).
- `docs/proofs/Improvements.md` §7.6.7 — the binding requirement ("the discriminator MUST be in the address-derivation preimage to prevent address collision across pubkey forms").
- `docs/proofs/Improvements.md` §7.5.7 — the `pubkey_form` discriminator + variable-length pubkey encoding decision.
- `docs/proofs/DECISION-LOG.md` — auditable deliberation log. **No entry exists for the address-derivation formula decision.** This document proposes that an entry be appended once the decision authority signs off.
- `include/determ/types.hpp` — the current `make_anon_address` / `parse_anon_pubkey` / `is_anon_address` / `normalize_anon_address` (the code under analysis).
- `src/node/validator.cpp` — the tx signature-verification path (§4 crux: where `from` → pubkey happens).
- `tools/test_anon_address_derivation.sh` — the existing regression that PINS the current formula as a bijection and explicitly fences against swapping it for a hash.

**Audience.** The decision authority weighing the §7.6.7 address-derivation formula; implementation threads that will land the §7.5.7 `pubkey_form` discriminator; reviewers asking "what breaks if the address formula changes, and what is the minimum-cost path to satisfy §7.6.7."

---

## 1. Problem statement

### 1.1 The two surfaces in conflict

**Surface 1 — what the code does today.** Determ's anonymous-account address is the literal lowercase hex of the 32-byte Ed25519 public key, with a `"0x"` prefix. From `include/determ/types.hpp:153-155`:

```cpp
inline std::string make_anon_address(const PubKey& pk) {
    return "0x" + to_hex(pk);
}
```

No hash. No discriminator byte. No domain separator. The address is 66 characters (`"0x"` + 64 hex chars). The pubkey body and the address are isomorphic — the address IS the pubkey, re-encoded as hex.

**Surface 2 — what §7.6.7 mandates.** Per `Improvements.md §7.6.7` (and restated in `SchemaDiscriminatorsImpl.md §4.1`):

> **Address derivation.** Determ addresses today derive from pubkeys (or domains). For Ed25519, derivation is `address = some_hash(pubkey_32B || ...)`. With pubkey_form discriminator, derivation becomes `address = some_hash(pubkey_form || pubkey_body || ...)` — the discriminator MUST be in the address-derivation preimage to prevent address collision across pubkey forms. This is a v1.0 design lock-in: getting it wrong now forecloses PQ pubkey migration even with the discriminator present.

### 1.2 Why they conflict

The §7.6.7 text assumes the current formula is *already* a hash (`address = some_hash(pubkey_32B || ...)`) and that the only change required is to prepend `pubkey_form` to the hash preimage. **That assumption is false.** The current formula is not a hash at all — it is a reversible hex encoding of the raw pubkey body. So §7.6.7 is not a one-line preimage edit; it is a wholesale replacement of the address-derivation scheme with consequences that ripple through the entire anon-account verification path.

Two distinct claims in §7.6.7 must both be satisfied for the discriminator to be load-bearing:

1. **Collision resistance across pubkey forms.** Two pubkeys of distinct forms (Ed25519 vs a hypothetical future PQ form whose body happens to be 32 bytes) must produce distinct addresses even if their body bytes alias. The current formula fails this: a 32-byte Dilithium-variant body and a 32-byte Ed25519 body with identical bytes would both render to the same `"0x"+hex` address.
2. **The discriminator is bound into the preimage.** Whatever the address formula is, `pubkey_form` must be part of what determines the address, so the binding cannot be stripped post-launch.

The current formula satisfies neither, because there is no preimage to bind into — the address is the body itself.

### 1.3 The hard constraint: this must be decided BEFORE v1.0 mainnet

Anonymous-account addresses are **permanent identity anchors**. An address is where balance lives; it is what a `TRANSFER` names in `to`; it is the store-key in the account map. Changing the address-derivation formula changes the address that a given private key controls. After mainnet launch:

- Every funded address derived under the old formula would become invisible under the new formula (balance stranded at an address no key derives to).
- A formula change is therefore a **hard fork** — exactly the class of migration the project's no-migrations constraint (`IMPLEMENTATION-SEQUENCING.md §4.4`, the no-migrations posture referenced throughout `Improvements.md §7.5`) forbids post-launch.

Pre-launch, the cost is bounded: there are no funded mainnet addresses to preserve, only test fixtures and operator-tooling artifacts that bake in specific hex (see §6). The decision window is exactly NOW — between the present pre-launch state and v1.0 genesis. The §7.5.7 discriminator lands in "Bundle 0" (the pre-bundle pass) per `SchemaDiscriminatorsImpl.md §10`, and §4 of that document is the substantive lock-in within Bundle 0. This document feeds that gate.

---

## 2. Current address scheme (from code)

This section documents EXACTLY what ships today in `include/determ/types.hpp`, with no editorializing — the analysis in §3–§5 builds on these facts.

### 2.1 Derivation (`make_anon_address`)

```cpp
inline std::string make_anon_address(const PubKey& pk) {
    return "0x" + to_hex(pk);
}
```

`PubKey` is `std::array<uint8_t, 32>` (`types.hpp:16`). `to_hex` lowercases (`std::hex` + `std::setfill('0')` + `std::setw(2)`; `types.hpp:61-72`). So a 32-byte Ed25519 pubkey produces `"0x"` + 64 lowercase hex chars = a 66-char string. **Deterministic and total**: same pubkey → same address, every pubkey maps to exactly one address.

### 2.2 The reversibility property (LOAD-BEARING)

The address-derivation function is a **bijection between 32-byte pubkeys and 66-char `0x`-addresses**. The inverse is `parse_anon_pubkey` (`types.hpp:144-151`):

```cpp
inline PubKey parse_anon_pubkey(const std::string& addr) {
    if (!is_anon_address(addr))
        throw std::invalid_argument("not an anon address: " + addr);
    return from_hex_arr<32>(addr.substr(2));
}
```

**The pubkey is RECOVERABLE from the address.** Drop the `"0x"`, hex-decode the remaining 64 chars, and you have the exact 32-byte Ed25519 pubkey. This is not incidental — it is the property the verification path *relies on* (proven in §4). The whole chain treats the address as a carrier of the pubkey.

This reversibility is so deliberate that the existing regression `tools/test_anon_address_derivation.sh` scenario (6) pins it as a contract:

> (6) Round-trip contract: `parse_anon_pubkey(make_anon_address(pk)) == pk` across {zero, 0xFF, random} — pins that the derivation is a BIJECTION (lowercase hex of the pubkey), NOT a one-way SHA-256 hash. **Loud regression-fence if the encoding is ever swapped for a hash.**

And scenario (7) bakes in golden vectors that encode the formula literally:

> (7) Cross-platform golden fixtures: `pk=0x00*32 → "0x" + "0"*64`; `pk[i]=i → "0x000102...1f"` (pins big-endian byte order + lowercase hex + nibble width).

Any hash-based scheme (Option A / Option D-hash) directly inverts this test's stated purpose. The test is not a passive fixture; it is an explicit fence the project erected against exactly the change §7.6.7 now requests. This is the strongest single signal that the change is substantive, not cosmetic.

### 2.3 Recognition (`is_anon_address`) and S-028 normalization

`is_anon_address` (`types.hpp:115-126`) recognizes an anon address by shape: exactly 66 chars, leading `"0x"`, remaining 64 chars all hex (either case). This is how the chain distinguishes anon addresses from domain names everywhere it branches on sender type.

S-028 case-normalization (`types.hpp:128-142`): `normalize_anon_address` lowercases the hex tail so `"0xABC…"` and `"0xabc…"` resolve to the same account-map entry. `make_anon_address` always emits lowercase (canonical form); user-input boundaries (RPC + CLI) call `normalize_anon_address` before storage or lookup. `parse_anon_pubkey` does not need to normalize because `std::stoul` base-16 is case-insensitive — both cases decode to the same 32 bytes.

**Interaction note for the options below.** S-028 is a property of the *hex-of-pubkey* form. A hash-based address (Option A) is already emitted lowercase by `to_hex`, so the canonicalization story survives trivially. A discriminator-prefix address (Option B) keeps the hex form and so keeps the S-028 contract unchanged for the body, but adds a 2-hex-char form prefix that is constant for Ed25519 (`00`), so S-028 logic would need its length check generalized.

### 2.4 Domain addresses are out of scope

For domain-name accounts (`"alice"`, `"bob"`, registered via REGISTER tx with an `ed_pub` binding in the registry), the address IS the domain string. No pubkey-derivation happens; the registry stores `(domain → ed_pub)` and verification reads the pubkey from the registry, not from the address. `is_anon_address` rejects domain names by shape, so the two code paths never cross. The §7.6.7 change touches ONLY the anon-address path. (Confirmed: `SchemaDiscriminatorsImpl.md §4.6`.)

---

## 3. The three options (deep analysis)

This section restates A5's three options and adds a fourth candidate (§3.4) to confirm no cleaner path was missed. Each option is judged against three criteria:

- **C1 — satisfies §7.6.7** (discriminator bound into preimage + cross-form collision resistance).
- **C2 — preserves pubkey-recoverability-from-address** (the property §4 proves the code relies on).
- **C3 — fixed-length address** (UX + storage; matters for future large PQ pubkeys).

### 3.1 Option A — hash-based with discriminator

```cpp
// address = "0x" + hex(SHA256(pubkey_form || body_len_be4 || body))
inline std::string make_anon_address(uint8_t pubkey_form,
                                     const uint8_t* body, size_t body_len) {
    SHA256Builder b;
    b.append(pubkey_form);
    b.append_u32_be(static_cast<uint32_t>(body_len));
    b.append(body, body_len);
    Hash h = b.finalize();
    return "0x" + to_hex(h);          // 66 chars, regardless of body size
}
```

| Criterion | Verdict |
|---|---|
| C1 §7.6.7 | **Satisfied.** `pubkey_form` is in the preimage; SHA-256 collision resistance (A2 in `Preliminaries.md §2.1`) makes cross-form aliasing infeasible (2⁻¹²⁸ per attempt). |
| C2 recoverability | **BROKEN.** SHA-256 is one-way; the pubkey CANNOT be recovered from the address. |
| C3 fixed-length | **Satisfied.** Always 66 chars — a Dilithium-3 1952-byte body still produces a 66-char address. |

**PRO.** Uniform across all pubkey forms; collision-resistant by construction; fixed-length irrespective of future PQ pubkey size; the discriminator is cryptographically bound (un-strippable post-launch). This is the cleanest *long-term* address scheme and the one most consistent with how essentially every other chain derives addresses (hash of pubkey).

**CON (the decisive one).** Breaking C2 means **every anon-tx must carry its sender pubkey explicitly**, because the verifier can no longer recover it from `from`. Today the verifier does `pk = parse_anon_pubkey(tx.from)` (§4); under Option A that line cannot exist — `tx.from` is now `SHA256(...)`, not the pubkey. So Option A is NOT free; its true cost is **Option A + a wire-format change adding an explicit pubkey field to the anon-tx envelope**. The precise wire + verification impact:

1. **`Transaction` gains a sender-pubkey field** (or the anon-tx envelope does). The struct at `block.hpp:205-221` has `from` (string), `to` (string), `sig` (Signature) — but NO pubkey field. A new field, e.g. `from_pubkey: PubKey` (a `pubkey_form`-prefixed record per §7.5.7), must be added and populated for anon senders.
2. **`signing_bytes()` must bind it.** Otherwise an attacker could swap the carried pubkey for one that verifies against a different signature. The new field enters the tx signing preimage (`block.cpp::Transaction::signing_bytes` + the light-client mirror `light/sign_tx.cpp::compute_signing_bytes`).
3. **The verifier checks address ⟷ pubkey consistency.** Before verifying the sig, the validator must check `make_anon_address(from_pubkey) == tx.from` (i.e., the carried pubkey actually hashes to the claimed `from` address). Without this check, a tx could carry pubkey P (whose sig is valid) while claiming `from` = the address of victim V, draining V's balance. This consistency check REPLACES the implicit binding that `parse_anon_pubkey` gave for free.
4. **The wallet + light-client signing paths must emit the field.** `wallet/main.cpp` and `light/sign_tx.cpp` both construct the tx envelope; both must add the pubkey field. The light-client today derives `from` = `kf.anon_address` and never separately surfaces the pubkey (it IS the address) — that changes.

Option A's verification path becomes: parse `from_pubkey` → check `make_anon_address(from_pubkey) == from` → check `pubkey_form`/`sig_form` curve-family match (§7.5.6 invariant) → `verify(from_pubkey.body, signing_bytes, sig)`. This is strictly more code than today's `parse_anon_pubkey(from)` one-liner, but it is mechanical and self-contained.

### 3.2 Option B — discriminator-prefix (reversible)

```cpp
// address = "0x" + hex(pubkey_form) + hex(body)  ; Ed25519 => "0x00" + hex(body_32B)
inline std::string make_anon_address(uint8_t pubkey_form,
                                     const uint8_t* body, size_t body_len) {
    std::string addr = "0x";
    addr += to_hex(&pubkey_form, 1);   // "00" for Ed25519
    addr += to_hex(body, body_len);
    return addr;
}
```

| Criterion | Verdict |
|---|---|
| C1 §7.6.7 | **Satisfied.** `pubkey_form` is the leading prefix → distinct forms produce distinct address prefixes → no cross-form collision; the discriminator is present in (and recoverable from) the address. |
| C2 recoverability | **Preserved.** Strip `"0x"`, read the first hex byte as `pubkey_form`, the remainder is the body. The pubkey is still recoverable from the address. |
| C3 fixed-length | **Violated.** Address length tracks body length: Ed25519 = `2 + 2 + 64` = 68 chars; Dilithium-3 = `2 + 2 + 3904` = 3908 chars. |

**PRO.** Preserves pubkey-recoverability (C2) — so it does NOT require an explicit pubkey field in the tx; the verifier can still do "recover pubkey from address" exactly as today, just reading a form byte first. Satisfies §7.6.7. No wire-format change to `Transaction`. The verification path stays close to today's structure: `(form, body) = parse_anon_address(from); check form/sig_form curve match; verify(body, signing_bytes, sig)`. This is the *minimum-disruption* path to satisfy §7.6.7.

**CON.** Variable-length addresses. For Ed25519 the cost is mild (66 → 68 chars). But the whole point of the discriminator is future PQ migration, and a future Dilithium-3 anon address would be ~3.9 KB of hex — unusable as a copy-pasteable identity string, hostile to QR codes, bloated in every log line and account-map key. The address format also changes shape for v1.0 Ed25519 (66 → 68 chars + the `is_anon_address` 66-char length check must change), so it still breaks every baked-in fixture (same one-time pre-launch cost as Option A — see §6). Option B trades Option A's recoverability-break for a length-explosion-on-future-forms problem.

### 3.3 Option C — keep-current, special-case future (REJECTED by A5)

Keep `address = "0x" + hex(body_32B)` for Ed25519 (zero compat-break for v1.0); use a different prefix scheme only for future non-Ed25519 forms.

| Criterion | Verdict |
|---|---|
| C1 §7.6.7 | **VIOLATED for Ed25519.** The discriminator is NOT in the v1.0 Ed25519 address preimage. |
| C2 recoverability | Preserved (it is the status quo). |
| C3 fixed-length | Preserved for Ed25519. |

**Why rejected.** The discriminator slot would exist in the wire format but the address-derivation preimage for Ed25519 would not bind it. A future v3 form whose body is 32 bytes could collide with the v1.0 Ed25519 address space — the *exact* collision §7.6.7 was written to prevent. §7.6.7 explicitly calls this out: "getting it wrong now forecloses PQ pubkey migration even with the discriminator present." Option C makes the §7.5.7 discriminator non-load-bearing at the address layer — you pay the wire-format byte cost of `pubkey_form` but get none of the address-collision protection it was supposed to buy. A5 correctly rejected it; this document concurs. (Note: A5's `SchemaDiscriminatorsImpl.md §4.5` path #3 — "adopt Option A only post-v1.0" — is structurally identical to Option C and falls to the same objection.)

### 3.4 Option D — discriminator-prefixed hash (the candidate I evaluated for completeness)

A natural "best of both" candidate: prefix the form byte (for visible form-routing) AND hash the body (for fixed length):

```cpp
// address = "0x" + hex(pubkey_form) + hex(SHA256(body))   ; Ed25519 => "0x00" + 64 hex
```

| Criterion | Verdict |
|---|---|
| C1 §7.6.7 | **Satisfied.** Form in the address (prefix) AND collision-resistant body (hash). |
| C2 recoverability | **BROKEN.** The body is hashed → pubkey not recoverable. |
| C3 fixed-length | **Satisfied.** 2 + 2 + 64 = 68 chars for every form. |

**Assessment.** Option D buys nothing over Option A. It is fixed-length and form-bound, but it STILL breaks recoverability (the hash is one-way), so it incurs the *same* explicit-pubkey-field wire change Option A does — while also reintroducing a variable prefix and a 2-char-longer address. The only thing it adds is a human-visible form byte at the front of the address, which is cosmetic given the form is already recoverable from the carried pubkey field (which Option A/D both require anyway). **Option D is dominated by Option A** (same recoverability cost, longer address, no functional gain). Reject.

**A genuinely cleaner hybrid?** I also considered a hybrid where Ed25519 keeps the current reversible `"0x"+hex(body)` form (form byte `0x00` *implied, not stored*) and only future non-Ed25519 forms switch to a hash-with-prefix. But this is *exactly Option C* (the §7.6.7 violation for Ed25519 — an implied form byte is not bound into the preimage, so a future 32-byte-body form still collides with v1.0 Ed25519 addresses). There is no hybrid that preserves Ed25519 recoverability AND binds the discriminator into the Ed25519 preimage, because binding-into-preimage with a reversible encoding *is* Option B (the form byte must be physically present in the address string, which is Option B's prefix). **The option space is genuinely {A, B, C} plus the dominated D.** No cleaner option exists.

### 3.5 Options summary table

| | C1 §7.6.7 | C2 recoverability | C3 fixed-length | Requires explicit-pubkey wire change? | Compat-break (pre-launch, one-time)? |
|---|---|---|---|---|---|
| **A** hash + disc | yes | **no** | yes | **yes** | yes |
| **B** disc-prefix | yes | yes | **no** | no | yes |
| **C** keep-current | **no (Ed25519)** | yes | yes | no | no |
| **D** prefix+hash | yes | **no** | yes | **yes** (same as A) | yes |

Option C is the only one that avoids the compat-break, and it does so by failing the requirement that motivated the whole exercise. So the real decision is **A vs B**, and the deciding factor is the §4 pubkey-recoverability finding: does adding an explicit pubkey field to the anon-tx envelope cost little (Option A viable cheaply) or much (Option B's no-wire-change advantage dominates)?

---

## 4. The pubkey-recoverability question (the crux)

This is the load-bearing analysis. The choice between Option A and Option B turns on a single empirical question about the code: **does Determ's anon-tx verification REQUIRE recovering the pubkey from the `from` address, or is the pubkey already carried explicitly in the tx/signature envelope?**

I read the three signing/verification surfaces the task identified. The answer is unambiguous.

### 4.1 The mainline verifier — `src/node/validator.cpp`

`validate_block`'s per-tx verification (`validator.cpp:479-566`) derives the verification pubkey by sender class:

```cpp
const bool from_anon = is_anon_address(tx.from);
// ...
PubKey pk;
if (from_anon) {
    if (tx.type != TxType::TRANSFER)
        return {false, "anonymous accounts may only TRANSFER ..."};
    pk = parse_anon_pubkey(tx.from);          // <-- RECOVERED FROM THE ADDRESS
} else {
    auto e = registry.find(tx.from);
    if (!e) return {false, "tx sender not in registry: " + tx.from};
    pk = e->pubkey;                           // registered: pubkey from registry
}
auto sb = tx.signing_bytes();
if (!verify(pk, sb.data(), sb.size(), tx.sig))
    return {false, "tx signature invalid from: " + tx.from};
```

For an anon sender, `pk = parse_anon_pubkey(tx.from)` — **the verification pubkey is recovered FROM the `from` address.** There is no pubkey field in the tx that the verifier reads instead. The address is the sole source of the verification key for anon senders.

### 4.2 The mempool-admission verifier — `src/node/node.cpp`

The pre-admission signature check (`node.cpp:1916-1929`) follows the identical pattern:

```cpp
PubKey pk{};
const bool from_anon = is_anon_address(tx.from);
if (tx.type == TxType::REGISTER) {
    // REGISTER: pubkey from the tx payload (registrant not yet in registry)
    std::copy_n(tx.payload.begin(), 32, pk.begin());
} else if (from_anon) {
    if (tx.type != TxType::TRANSFER) return false;
    pk = parse_anon_pubkey(tx.from);          // <-- RECOVERED FROM THE ADDRESS
} else {
    // registered: pubkey from registry
}
```

Same verdict: anon-tx admission recovers the pubkey from `from`. (Note the REGISTER special case at line 1920-1923: a *registrant's* pubkey comes from the payload because they are not yet in the registry — but REGISTER is never an anon-tx; anon accounts may only TRANSFER. So the payload-pubkey path is orthogonal to the anon path.)

### 4.3 The COMPOSABLE_BATCH inner-tx verifier — `src/node/validator.cpp`

Inner txs inside a COMPOSABLE_BATCH (`validator.cpp:1025-1042`) repeat the pattern a third time:

```cpp
PubKey ipk{};
if (is_anon_address(it.from)) {
    ipk = parse_anon_pubkey(it.from);         // <-- RECOVERED FROM THE ADDRESS
} else if (auto re = registry.find(it.from)) {
    ipk = re->pubkey;
} else { return {false, "... sender not in registry ..."}; }
auto sb = it.signing_bytes();
if (!verify(ipk, sb.data(), sb.size(), it.sig)) { /* reject */ }
```

### 4.4 The signing side — wallet + light-client

The signers confirm the symmetric fact: no separate pubkey is emitted because the address carries it.

- `light/sign_tx.cpp::compute_signing_bytes` (lines 37-62) builds the signing preimage from `type || from || 0x00 || to || 0x00 || amount || fee || nonce || payload`. The `from` string IS the anon address (= the pubkey hex). `sign_light_tx` (lines 64-124) emits the envelope `{from, to, amount, fee, nonce, payload, signature, sig, hash}` — **no `pubkey` / `from_pubkey` field.** The signing comment is explicit that this matches `src/chain/block.cpp::Transaction::signing_bytes` byte-for-byte.
- `wallet/main.cpp` derives `address = "0x" + to_hex(pub)` (e.g. lines 1253, 1731) and treats the address as the public identity; the privkey is held separately for signing. The pubkey surfaces only as the address.

The `Transaction` struct (`block.hpp:205-221`) corroborates: fields are `type, from, to, amount, fee, nonce, payload, sig, hash`. **There is no pubkey field.** For anon senders the pubkey exists on the wire ONLY as the hex inside `from`.

### 4.5 VERDICT

**The pubkey is RECOVERED from the `from` address (`parse_anon_pubkey`). It is NOT carried separately in the tx or signature envelope.** This holds across all three verification surfaces (mainline block validation, mempool admission, COMPOSABLE_BATCH inner txs) and is confirmed on the signing side (wallet + light-client emit no pubkey field; the `Transaction` struct has none).

**Consequence for the decision.** Pubkey-recoverability-from-address is a property the code *relies on*, not merely a convenience. Therefore:

- **Option A (hash) is NOT a low-cost drop-in.** It mandates a wire-format change: an explicit `from_pubkey` field added to every anon-tx, bound into `signing_bytes()`, plus a new `make_anon_address(from_pubkey) == from` consistency check at every verification site (three sites in `validator.cpp` + `node.cpp`), plus emission of the field in both signers (`light/sign_tx.cpp` + `wallet/main.cpp`). This is a genuine v1.0 wire + verification-path lift, not a one-function edit.
- **Option B (discriminator-prefix) requires NO wire change.** It preserves recoverability, so all four code surfaces keep their "recover pubkey from address" structure — they only gain a leading form-byte read and a `form ⟷ sig_form` curve-family check (which §7.5.6 mandates anyway). Option B's cost is concentrated in the address-format change itself (the variable-length / 68-char Ed25519 address) and the one-time fixture regeneration, not in the verification path.

This is the single most decision-relevant finding in the document, and it cuts AGAINST the reflexive "Option A is cleanest" instinct: Option A is cleanest *as an address scheme* but carries a hidden wire-format tax that Option B avoids entirely.

---

## 5. Recommendation

### 5.1 The trade-off, stated plainly

Given the §4 verdict, the decision is:

- **Option A** = the better long-term address scheme (fixed-length, uniform, hash-based like every mainstream chain) **+ a real v1.0 wire-format change** (explicit pubkey field + binding + consistency check at 3 verify sites + emission at 2 signers).
- **Option B** = no wire-format change, minimum disruption to the verification path **+ a worse long-term address scheme** (variable-length; future PQ addresses become multi-KB hex strings) **+ a v1.0 Ed25519 address shape change** (66 → 68 chars; `is_anon_address` length check generalized).

Both A and B incur the same one-time, pre-launch fixture regeneration (§6) — that cost does not discriminate between them.

### 5.2 Recommended option: **Option A**, conditioned on the explicit-pubkey-field work being in v1.0 scope

I recommend **Option A (hash-based with discriminator)**, *with eyes open* about the §4 cost. Rationale:

1. **Addresses are forever; the wire change is one-time.** The §4 wire-format tax is paid once, pre-launch, in mechanical code (add field, bind it, check it). The address *scheme* is permanent. Option B's variable-length addresses are a permanent UX/storage liability that grows worse with exactly the future PQ forms the discriminator exists to enable. Choosing B to dodge a one-time wire change locks in a forever-cost to avoid a once-cost.

2. **The explicit-pubkey-field work is largely already implied by §7.5.7.** `SchemaDiscriminatorsImpl.md §2.7-§2.8` already specifies that `Transaction.from` becomes a `pubkey_form`-prefixed variable-length PubKey *record* on the wire. The marginal work for Option A is the *consistency check* (`make_anon_address(from_pubkey) == from`) and ensuring anon-tx carry the pubkey — a smaller delta than it first appears, because the §7.5.7 lift is already touching this exact field.

3. **Option B's "no wire change" advantage is partly illusory under §7.5.7.** §7.5.7 changes pubkey wire encoding *anyway* (every pubkey becomes a `form||len||body` record). Option B keeps recoverability-from-address, but the address itself still changes shape (Ed25519 66→68 chars) and `is_anon_address` / `normalize_anon_address` / `shard_id_for_address` all consume the address-string shape and must be touched. So Option B is not zero-touch either; it trades the verifier-side pubkey-field work for address-string-shape work across the recognition/normalization/routing helpers.

4. **§7.6.7's own framing recommends A**, and A5 independently recommended A. The collision-resistance + fixed-length properties are what §7.6.7 was written to secure.

### 5.3 If the decision authority prefers to minimize v1.0 wire churn

If minimizing v1.0 wire-format change is the overriding priority (e.g., to keep the `Transaction` struct and the light-client envelope frozen), **Option B is the defensible fallback.** It satisfies §7.6.7, preserves recoverability (no pubkey field, no verifier-side consistency check), and confines the change to the address-string format + the recognition helpers. Accept the variable-length-address liability as the price. This is a legitimate engineering call; it is not the §7.6.7 violation that Option C is. The decision authority should choose A vs B explicitly on the "permanent address-scheme quality vs one-time wire-change cost" axis laid out in §5.1.

### 5.4 What each option entails for v1.0 (scope delta)

| Work item | Option A | Option B |
|---|---|---|
| Replace `make_anon_address` | yes (hash + form + len) | yes (form-prefix + body) |
| Replace `parse_anon_pubkey` | **removed** (no longer possible) / replaced by carried-field read | yes (read form byte, then body) |
| Generalize `is_anon_address` length/shape | yes (now hashes to fixed 66) | yes (68 chars + form prefix; variable for future) |
| Add explicit `from_pubkey` field to anon-tx | **yes (wire change)** | no |
| Bind `from_pubkey` into `signing_bytes()` (chain + light) | **yes** | no |
| Add `make_anon_address(from_pubkey)==from` check at verify sites | **yes (3 sites)** | no (recoverability gives it for free) |
| Emit pubkey field in signers (`light/sign_tx.cpp`, `wallet/main.cpp`) | **yes** | no |
| `form ⟷ sig_form` curve-family check | yes (§7.5.6, both options) | yes (§7.5.6, both options) |
| Regenerate baked-in fixtures (§6) | yes (one-time) | yes (one-time) |
| Permanent variable-length-address liability | no | **yes** |

---

## 6. Migration / fixture impact (blast radius)

Whichever of A or B is adopted, the address-derivation formula changes, so **every artifact that bakes in a specific anon-address hex string must be regenerated under the new formula.** This is one-time and pre-launch (per §1.3 there are no funded mainnet addresses to migrate).

### 6.1 What I found (grep over `tools/`)

- **Full 64-hex anon-address literals** (`0x` + exactly 64 hex): 3 files — `tools/operator_subsidy_audit.sh`, `tools/operator_subsidy_pool_health.sh`, `tools/test_negative_entry_fee.sh`.
- **`0x`-prefixed hex ≥ 8 chars (broader, catches partials + truncated displays):** 12 files — adds `operator_unstake_timeline.sh`, `test_anon_address_derivation.sh`, `operator_keystore_audit.sh`, `test_wallet_anon_batch_balance.sh`, `test_wallet_account_derive_batch.sh`, `operator_config_audit.sh`, `test_merge_event_bytes.sh`, `test_tx_signing_bytes.sh`, `test_state_proof.sh`.
- **Tests that exercise the derivation directly** (by name): `test_anon_address.sh`, `test_anon_address_case.sh`, `test_anon_address_derivation.sh`, `test_anon_routing.sh`, plus the ~40 `test_wallet_*.sh` scripts (many derive addresses at runtime rather than hardcoding them — those are lower-risk; see §6.2).

### 6.2 The blast radius is SMALLER than it looks, with two sharp exceptions

Most fixtures derive addresses **at runtime** (sign a keypair, then read back the address the binary produced) rather than hardcoding hex. Those tests are *self-adjusting*: change the formula, rebuild, and they re-derive correctly with no edit. The genuinely affected set is the artifacts that pin a *literal* expected address hex a priori. Two sharp exceptions dominate the actual work:

1. **`tools/test_anon_address_derivation.sh` — the golden-vector + bijection fence.** This is the single most affected file, and it is affected at the level of *intent*, not just fixture values:
   - Scenario (7) hardcodes golden vectors that ARE the current formula: `pk=0x00*32 → "0x"+"0"*64` and `pk[i]=i → "0x000102…1f"`. Under Option A these become `"0x"+hex(SHA256(0x00 || 0x00000020 || body))` — completely different hex that must be recomputed and re-pinned. Under Option B they become `"0x00"+<same body hex>`.
   - Scenario (6) asserts the derivation is a **bijection** and is a "loud regression-fence if the encoding is ever swapped for a hash." **Under Option A this assertion must be DELETED/INVERTED** — the whole point of Option A is that the derivation is no longer a bijection. Under Option B the bijection survives (recoverability preserved) and only the format-pin (`^0x[a-f0-9]{64}$` in scenario 2) widens to the 68-char prefixed shape.
   - This file is not a passive fixture; it encodes a *design contract* that Option A reverses. Updating it is part of the decision, not an afterthought.

2. **`tools/test_anon_address.sh` / `test_anon_address_case.sh`** — exercise `is_anon_address` / `normalize_anon_address` shape contracts (66-char length, lowercase canonicalization). Option A keeps 66 chars (hash output) so the shape pins survive; Option B changes to 68 chars + form prefix so the length pins and the S-028 normalization range must be updated.

### 6.3 Estimate

- **Option A:** ~3-6 fixture files with literal address hex to regenerate, PLUS the `test_anon_address_derivation.sh` bijection-fence inversion (a deliberate contract change, not a value swap) and golden-vector recompute. Estimate **< 1 day** of fixture work, dominated by the derivation-test rewrite. (Consistent with `SchemaDiscriminatorsImpl.md §7`'s "<1 day given existing fixture-generation patterns.")
- **Option B:** similar file count, but the changes are mechanical format-shape updates (66→68, add `00` prefix) and the bijection fence *survives* — arguably slightly less conceptual churn in the derivation test, slightly more in the shape/length helpers.

Either way the work is **one-time, pre-launch, and bounded.** The dominant cost is the `test_anon_address_derivation.sh` rewrite (Option A) plus regenerating the handful of operator-script literals — not a sprawling migration.

### 6.4 Non-fixture consumers to re-verify (not address-hex, but address-shape dependent)

`shard_id_for_address` (cross-shard routing) hashes the canonical address string; changing the address shape changes shard assignment for every anon account. This is fine pre-launch (no committed routing), but the routing tests (`test_anon_routing.sh`, `test_shard_routing_determinism`) must be re-baselined alongside the formula change. This is a re-baseline, not a logic change.

---

## 7. Decision status

**Status: OPEN.** This document is the analysis input; it does not finalize the decision. The §7.6.7 text mandates that `pubkey_form` be in the address-derivation preimage but does not specify the formula, and neither `Improvements.md §7.5/§7.6` nor `DECISION-LOG.md` pre-resolves it (confirmed: no DECISION-LOG entry exists for the address-derivation formula). Per `SchemaDiscriminatorsImpl.md §4.5` + §9.3, the implementation thread MUST obtain explicit decision-authority sign-off before shipping the address-derivation change, because it is a substantive deviation from the current code path.

**What this document adds beyond A5's finding.** A5 recommended Option A "pending decision-authority sign-off" but did not resolve the load-bearing question of whether Option A is cheap or expensive. This document resolves it: **§4 proves the pubkey is recovered from the address (not carried in the tx), so Option A carries a wire-format tax (explicit pubkey field) that A5's recommendation did not price in.** The recommendation here is still Option A (§5.2), but now with the wire-change cost surfaced and Option B identified as the defensible minimum-wire-churn fallback (§5.3). The option space is confirmed to be exactly {A, B, C} plus the dominated D (§3.4) — no cleaner hybrid exists.

**Proposed next step.** Once the decision authority chooses A or B, append a `DECISION-LOG.md` entry under the §7.5.7 / §7.6.7 lineage in the standard format (question → options considered → choice → why others rejected → cross-decision implications), citing this document and `SchemaDiscriminatorsImpl.md §4` as the analysis inputs. The cross-decision implications worth flagging in that entry: (a) the §4 wire-format consequence if A is chosen; (b) the permanent variable-length-address liability if B is chosen; (c) the one-time `test_anon_address_derivation.sh` bijection-fence inversion (A) or format-shape update (B).

**Cross-references.**
- `docs/proofs/SchemaDiscriminatorsImpl.md §4` (A5's finding — the source) + §4.5 (the three implementation paths) + §9.3 (the open decision).
- `docs/proofs/Improvements.md §7.6.7` (the binding requirement) + §7.5.7 (the discriminator + variable-length pubkey encoding).
- `docs/proofs/DECISION-LOG.md` — **no entry yet**; this document proposes one be appended once the decision is made.
- `include/determ/types.hpp` (`make_anon_address` / `parse_anon_pubkey` / `is_anon_address` / `normalize_anon_address`) — the current formula.
- `src/node/validator.cpp` lines 553-566, 1025-1042 + `src/node/node.cpp` lines 1916-1929 — the verification sites that prove the §4 recoverability dependence.
- `light/sign_tx.cpp` + `wallet/main.cpp` — the signing sites that confirm no pubkey field is carried.
- `tools/test_anon_address_derivation.sh` — the existing bijection-fence + golden-vector regression that Option A must invert.

---

*End of analysis. This document is decision-input only; it does not modify `make_anon_address` or finalize the §7.6.7 formula. Append the resolution to `DECISION-LOG.md` once the decision authority signs off.*
