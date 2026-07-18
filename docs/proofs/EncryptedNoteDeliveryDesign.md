> **TIER: NEAR-TERM — 1.1.x in-flight.** The crypto PRIMITIVE + its dual-oracle gate ship here (library-only, additive, state-root-invariant); the CONSENSUS WIRING is now DECIDED profile-keyed with wiring increment 1 (the genesis `CryptoProfile` pin, §5.1) shipped, and its branch-bodies remain owner-gated (§5). Roadmap index: docs/ROADMAP.md

# EncryptedNoteDeliveryDesign — shielded-pool Option A (NC-8): on-chain encrypted-note delivery so a recipient can SCAN + trial-decrypt a confidential output's note secret without an out-of-band channel

This is the **design record** for **shielded Option A** — an on-chain, ephemeral-static ECIES channel that delivers a confidential output's note secret `(value, blinding[, memo])` to its recipient, closing [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) **NC-8** ("no on-chain output-secret delivery — recipient channel is off-chain"). It is the receiver amount-communication channel that [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) §1.3 flagged as *"a hard prerequisite"* to a usable confidential transfer, now built — over **P-256** (the shipped CT curve) rather than the X25519 handshake that older document anticipated.

**What shipped in the FIRST increment is the crypto primitive only** (`src/crypto/enote/enote.c` + its header), plus its dual-oracle test gate — **library-only, additive, and state-root-invariant**: no chain, consensus, validator, producer, wallet, or light-client code path calls it. The consensus wiring that carries a ciphertext on a `CONFIDENTIAL_TRANSFER` output — and the scan RPC / light-client scan that consume it — was laid out in §5 with genuine sub-decisions. **Those sub-decisions are now owner-decided profile-keyed (§5), and wiring increment 1 — promoting `CryptoProfile` to a genesis-pinned consensus field so the wiring can branch on it, byte-neutral for MODERN — has shipped (§5.1).** The remaining branch-bodies (leaf/payload placement, key derivation, accept-rule + apply, scan) stay owner-gated increments under the one-design-doc-per-decision directive, because they touch consensus-load-bearing surfaces (tx payload / state root).

**The load-bearing property this increment preserves is no-double-spend-by-design.** NC-8 delivery is a **passive payload**: it adds amount-recipient *delivery* only. It introduces **no** nullifier set, leaves inputs **named** (NC-7 unchanged), and does **not** touch the commitment-as-its-own-nullifier model, so the pool's bounded-unspent-commitment-set invariant — and every SP-* claim of `ShieldedPoolSoundness.md` — is fully preserved. It also introduces **no new hardness assumption**: security reduces to P-256 ECDH + HKDF-SHA256 (RFC 5869) + ChaCha20-Poly1305 (RFC 8439), all shipped, dual-oracle-frozen c99 primitives.

**Companion documents.** [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) — the parent consensus track (SP-1..SP-13); **NC-7** (named inputs) and **NC-8** (this document) are its two open privacy residuals. [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) §1.3 — the earlier proposal that named the receiver channel a prerequisite (now superseded on the curve: P-256, not X25519). [`AuditLayerSoundness.md`](AuditLayerSoundness.md) + `include/determ/crypto/viewkey/viewkey.h` — the shipped A2 view-key / audit layer whose "opaque published key decrypts nothing on-chain" gap the same primitive would close (a §5 sub-decision). [`CRYPTO-C99-SPEC.md`](CRYPTO-C99-SPEC.md) — the c99 primitive stack (P-256 §3.8c, HKDF/SHA-256 §3.x, ChaCha20-Poly1305) this composes, and the python-first dual-oracle discipline. `FROST_DEVIATION_NOTICE.md` — the AI-deviation discipline under which the owner gates the consensus follow-on.

**Authoritative external sources.** Abdalla–Bellare–Rogaway, *DHIES* (2001) — the ephemeral-static ECIES / DHAES construction this instantiates; RFC 5869 (HKDF); RFC 8439 (ChaCha20-Poly1305); SEC 1 (compressed point encoding). Nothing new is assumed beyond the P-256 / HKDF / AEAD stack already relied on by the CT layer.

---

## 1. The problem (NC-8)

A confidential output today is a **bare Pedersen commitment** `C = v·G + r·H` with **no owner field**. Two facts follow directly from `ShieldedPoolSoundness.md`:

- **The recipient cannot spend an output they were paid** unless they learn its opening `(v, r)`. In a `CONFIDENTIAL_TRANSFER` (`TxType = 14`) the **sender** chooses each output's blinding `r`, so only the sender knows `(v, r)`. To later spend that note (as a named input to its own transfer, or to UNSHIELD it) the recipient must learn `(v, r)` — and §3.22c delivers **nothing** on-chain for this. NC-8, verbatim: *"the sender and recipient coordinate the output secret off-chain (or the sender transfers to their own future notes)."* That off-chain coordination is exactly what makes the confidential transfer unusable as a **payment** to a third party: there is no on-chain signal a wallet can scan to discover "a note was paid to me."

- **The A2 audit layer publishes an opaque key and can decrypt nothing on-chain.** The shipped audit layer (`ROTATE_AUDIT_KEY`/`LOG_AUDIT_ACCESS`, `TxType = 15/16`; `AuditLayerSoundness.md`) lets an account publish a standing view/audit pubkey, and `viewkey.c` derives per-epoch view keys from a view-master secret — but there is **no ciphertext on-chain** for such a key to open. An auditor holding the view key can prove *authority* to read amounts, yet there is nothing published to read. The amount is committed (hiding) and never delivered in a form any key can recover.

So NC-8 is a **delivery gap**, not a hiding gap: the chain hides amounts correctly (CTB-* / the DCT1 range∧balance bundle), but provides no channel to hand the opening to the party entitled to it (recipient, or authorized auditor). The absence of that channel is what keeps `CONFIDENTIAL_TRANSFER` a same-wallet / out-of-band primitive rather than a payment rail.

**What NC-8 is NOT.** It is not graph privacy and not input-unlinkability — those are **NC-7** (named inputs), a strictly larger, separately owner-gated crypto increment (nullifier-from-secret + set-membership). NC-8 and NC-7 are orthogonal: delivering the output secret says nothing about hiding *which* input was spent, and closing NC-8 neither helps nor harms NC-7.

---

## 2. The decision context — Option A (encrypted-note delivery) over graph-privacy (B/C) and do-nothing (D)

The owner (2026-07-17) chose **Option A: on-chain encrypted-note delivery**. The alternatives considered:

- **Option A — encrypted-note delivery (CHOSEN).** Publish, alongside each confidential output, a ciphertext sealing that output's `(v, r[, memo])` to the recipient's key. The recipient (or an authorized view-key holder) scans the chain and trial-decrypts; a verifying AEAD tag *is* the "this note is mine" signal. Delivers amount-recipient information **only** — no graph privacy. Reuses shipped primitives; no new hardness assumption; passive payload that never touches the state transition of the commitment set.

- **Option B — hidden inputs / input-unlinkability (NC-7).** A nullifier-from-secret + set-membership argument so a spend hides *which* note it consumes, breaking the deposit↔withdrawal and note-graph correlation. This is the genuinely private-payments increment — but it is a **materially larger** crypto build (a new nullifier set = new consensus state + a membership proof system) and it **replaces** the named-input model that the no-double-spend-by-design property and the SP-11 inflation dedup both rest on. Owner-deferred as its own track; not this increment.

- **Option C — stealth addresses / one-time output keys.** Per-output one-time addresses so an observer cannot link two outputs to the same recipient. This adds *receiver* graph privacy but still needs an amount-delivery channel (Option A) to be spendable, and it too enlarges the addressing/consensus surface. A superset of A's problem, not a substitute; deferred with B.

- **Option D — do nothing (keep the off-chain channel).** Leave NC-8 open: senders and recipients coordinate `(v, r)` out-of-band. Zero code, zero risk — but it is precisely what keeps confidential transfers unusable as third-party payments and leaves the A2 view key with nothing to open. Rejected as a permanent posture; acceptable only if the owner judged the payment use-case out-of-model.

**Why A preserves no-double-spend-by-design.** The pool's spend-safety is structural: a note is an entry in the bounded unspent-commitment set (`shielded_pool_`), the commitment **is its own nullifier** (apply erases it — SP-8), and there is **no separate nullifier set**. Option A adds a ciphertext that is **inert with respect to that machinery**: it is never an input to an accept-rule, never mutates the commitment set, never appears in the double-spend or inflation-dedup checks (SP-8/SP-11). It rides *alongside* an output as delivery metadata. Whether or not the ciphertext is present, malformed, or ignored, the set-membership state transition is byte-identical — so every SP-* claim, and the bounded-set / no-nullifier property, is untouched. (This is why the consensus follow-on in §5 must keep the enote **out of** any accept-rule: its presence must remain consensus-inert, at most block-hash-bound like `pq_auth`, never a spend precondition.)

**Why A stays inside the WHITEPAPER §12.1 on-chain-privacy non-goal.** §12.1 declares graph/on-chain privacy a v1.x non-goal. Option A does **not** cross that line: it hides nothing additional from third parties and reveals no less — inputs stay named, senders/recipients stay public, the transfer's existence stays public. It only routes the *already-hidden* amount secret to the one party entitled to spend it. Amount-privacy-in-motion (hiding amounts from observers) was already delivered by `CONFIDENTIAL_TRANSFER`; NC-8 is the dual — delivering the secret *to the recipient* — and adds **zero** observer-facing privacy. It is therefore inside the non-goal, not an exception to it.

---

## 3. The as-built construction — ephemeral-static ECIES over NIST P-256

A textbook DHIES/ECIES instantiation over **NIST P-256** — the CT stack's curve in **both** profiles (MODERN + FIPS), so the channel is profile-agnostic like the rest of §3.22. Composition **only**, from shipped, dual-oracle-frozen c99 primitives: **P-256 ECDH** (`determ_p256_*`) + **HKDF-SHA256** (RFC 5869, `determ_hkdf_sha256`) + **ChaCha20-Poly1305** (RFC 8439, `determ_chacha20_poly1305_*`). **No new primitive, no new hardness assumption.**

### 3.1 Wire format (frozen)

```
seal(recipient_pub[33 compressed], pt, eph_sk[32]):          # eph_sk fresh per note
    E     = eph_sk · G                                        # ephemeral pubkey
    E33   = compressed SEC1(E)                                # 33 bytes, 0x02/0x03 prefix
    Z     = eph_sk · R   (ECDH) ; z = Z.x                     # 32 big-endian bytes (shared x)
    okm   = HKDF-SHA256(salt = "determ-enote-v1",            # 15-byte DST, no trailing NUL
                        ikm  = z,
                        info = E33 ‖ recipient_pub33,         # 66 bytes
                        L    = 44)
    key   = okm[0:32] ; nonce = okm[32:44]                    # 12-byte nonce, KDF-derived
    ct‖tag = ChaCha20-Poly1305(key).encrypt(nonce, pt, aad = E33)   # 16-byte tag appended
    wire  = E33 ‖ ct ‖ tag                                    # len = len(pt) + 49

open(recipient_sk[32], wire):
    E     = decompress(wire[0:33])                            # bad point ⇒ -1 (not ours)
    Z     = recipient_sk · E ; z = Z.x
    recipient_pub33 = compressed(recipient_sk · G)            # SAME R33 bound into info
    okm, key, nonce  = HKDF-SHA256(... info = E33 ‖ recipient_pub33 ...)
    pt    = ChaCha20-Poly1305(key).decrypt(nonce, ct, tag, aad = E33)   # tag fail ⇒ -1
```

Constants: `DETERM_ENOTE_EPH_LEN = 33`, `DETERM_ENOTE_TAG_LEN = 16`, `DETERM_ENOTE_OVERHEAD = 49`; ciphertext length is exactly `len(pt) + 49`. The intended plaintext for the CT use-case is `value(8, BE) ‖ blinding(32) = 40` bytes (a memo may extend it), sealing to a `49 + 40 = 89`-byte wire note.

### 3.2 Properties (EN-1 .. EN-5)

- **EN-1 (delivery — a verifying tag *is* the scan signal).** `open(sk, wire) == 0` **iff** `wire` was sealed to `sk`'s pubkey and is untampered, in which case it yields the exact plaintext. A non-matching / tampered / malformed note returns `-1` and writes **nothing** to the output buffer — the constant-time AEAD compare is the "not mine" gate a wallet scans with. No separate recipient-tag or address-match step is needed.

- **EN-2 (no new hardness assumption).** Confidentiality reduces to ECIES/DHIES over P-256: an eavesdropper without `recipient_sk` faces the P-256 CDH/DDH problem to recover `z`, then HKDF (modeled as a random oracle / PRF) and the ChaCha20-Poly1305 IND-CCA2 AEAD. Every step is an already-relied-on assumption of the CT stack (`ConfidentialTxBalanceSoundness.md` rests on the same P-256 DL). No primitive is introduced.

- **EN-3 (binding — a ciphertext cannot be re-pointed).** The HKDF `info` commits to **both** `(E, R)` and the AEAD `aad` commits to `E`. So `(key, nonce, tag)` are bound to the specific ephemeral key and the specific recipient: an attacker cannot lift a valid note onto a different recipient key or splice a different ephemeral prefix without failing the tag. (`open` recomputes `R33` from `sk` locally, so the recipient identity in `info` is not attacker-chosen.)

- **EN-4 (determinism + dual-oracle testability).** `seal` is a **pure function of `(R, pt, eph_sk)`** — the caller supplies the ephemeral secret, so the ciphertext is byte-exactly reproducible and can be pinned against an independent oracle (the c99 house discipline). This is what makes the primitive gateable by a fixed KAT corpus rather than only by roundtrip.

- **EN-5 (nonce-reuse safety is a caller obligation).** `eph_sk` **MUST** be fresh (CSPRNG) per note. Reuse repeats `(key, nonce)` and breaks AEAD confidentiality. The nonce is **KDF-derived** from `z` (which depends on `E = eph_sk·G`) rather than a caller counter precisely so that a fresh `eph_sk` mechanically yields a fresh `(key, nonce)` — the safety obligation collapses to the single, standard "fresh ephemeral per encryption" ECIES requirement. The header states this contract explicitly.

---

## 4. Shipped scope — the primitive + its dual-oracle gate (library-only, additive, state-root-invariant)

**Shipped in this increment:**

1. **The primitive.** `determ_enote_seal` / `determ_enote_open` (`src/crypto/enote/enote.c` + `include/determ/crypto/enote/enote.h`), added to the `determ-crypto-c99` static library. Pure composition over `determ_p256_*` / `determ_hkdf_sha256` / `determ_chacha20_poly1305_*`; secrets (`z`, the keystream `ks`) are `determ_secure_zero`'d on every return path.

2. **The gate `test-enote-c99`** (`determ` subcommand, wrapper `tools/test_enote_c99.sh`, FAST-suite member via the `enote_c99` regex in `tools/run_all.sh`). Self-contained assertions: `seal→open` roundtrip (empty plaintext + a real 40-byte `v‖r` note); determinism (byte-equal twice); the `out_len == ptlen + 49` / compressed-prefix wire shape; wrong-key rejection with the output buffer left **untouched** (the scan "not mine" path); tamper rejection independently on each wire region (ephemeral point / ciphertext body / auth tag); and malformed / NULL / off-curve-recipient fail-closed. Layered on top is the **dual-oracle KAT corpus** (`tools/vectors/enote.json`, 5 vectors, produced **byte-independently** by the python oracle `tools/verify_enote.py`): `seal` must reproduce each `ct_hex` **byte-for-byte** and `open` must recover each plaintext — the same python-first discipline that gates the rest of the c99 stack (SHA-2, P-256, view-key, …).

**Why this is additive + state-root-invariant.** No `chain.cpp` / `validator.cpp` / `producer.cpp` / `block.hpp` code path references the module. No new `TxType`, no new state leaf, no new payload field, no change to `signing_bytes()` or `serialize_state`. The build adds one C source to an existing static library and one test subcommand. Therefore **every** golden `state_root`, every FAST determinism vector, and the cross-toolchain corpus are byte-identical with the module compiled in — the feature is entirely invisible to consensus until the §5 wiring lands. (This mirrors how §3.22 SHIELD/UNSHIELD were introduced feature-flagged-by-use.)

---

## 5. Owner-gated follow-on — the consensus wiring (NOT in this increment)

Closing NC-8 *end-to-end* means carrying an enote on-chain per confidential output and giving wallets a way to find it. That is consensus surgery on `CONFIDENTIAL_TRANSFER` and the tx/state wire, so it is **deferred to the owner** with the sub-decisions below. Sketch of the full wiring:

- **Attach the ciphertext to the output.** For each `CONFIDENTIAL_TRANSFER` (`TxType = 14`) output note, publish `seal((recipient key), value‖blinding[‖memo], fresh eph_sk)` in an **additional payload region**. (`SHIELD`'s single note is **self-owned** — the depositor chose `r` — so SHIELD delivery is moot except when depositing to a *different* recipient's key; the primary consumer is `CONFIDENTIAL_TRANSFER` outputs.) The enote must remain **consensus-inert** per §2: at most block-hash-bound (like `pq_auth`, serialized-only-when-present), **never** a spend precondition or accept-rule input, so the no-double-spend machinery stays byte-identical.
- **A scan RPC.** A node endpoint returning the enote payloads over a height range (or for the current unspent-output set) so a wallet can pull-and-trial-decrypt, using EN-1 (a verifying tag = mine) as the filter.
- **Light-client scan.** The same, but the light client verifies the enote's inclusion against the committed `state_root` before trial-decrypting — only meaningful if enotes are a state leaf (sub-decision 2).

**Sub-decisions for the owner:**

1. **Which recipient key.** (a) A **dedicated P-256 note key** per account (a new "note pubkey", registered or address-derived) — keeps scan/spend authority cleanly separate from the audit layer; or (b) **derive from the A2 / view-key layer** (`viewkey.c`, the view-master / per-epoch view pubkey) — one key infrastructure, and it simultaneously closes the "auditor has an opaque key that opens nothing" gap of §1, at the cost of coupling recipient-decryption to the audit-disclosure key. Both are P-256 points the primitive already accepts. **→ Owner-decided (2026-07-18), profile-keyed: FIPS ⇒ (b) view-master derivation (one auditable key infrastructure, matching the FIPS posture's audit-coupling appetite); every other profile (MODERN) ⇒ (a) dedicated note key (scan/spend authority separate from the audit layer).**
2. **Ciphertext-in-tx-payload vs a new state leaf.** (a) **In the tx payload** (append to the `CONFIDENTIAL_TRANSFER` payload, `pq_auth`-style: block-hash-bound, serialized only when present, **not** in the state root — preserves state-root-invariance, but a light client cannot trustlessly prove an enote's presence and must trust a node's scan); or (b) a dedicated **`en:` state leaf** (state-root-committed → light-client-provable scan, but adds a state namespace and makes the enote part of the state-root surface — a larger consensus change). **→ Owner-decided, profile-keyed: FIPS ⇒ (a) tx payload (holds state-root-invariance); MODERN ⇒ (b) `en:` state leaf (light-client-provable scan).**
3. **Per-output vs per-tx.** (a) **Per-output** — one enote per output note, each sealed to that output's recipient — the general case that supports genuine multi-recipient transfers (matches the `m` outputs of a DCT1 bundle); or (b) **per-tx** — a single enote — simpler wire, but limits a transfer to a single recipient / self-transfer. **→ Owner-decided: (a) per-output, both profiles.**

**RESOLUTION (owner, 2026-07-18).** The sub-decisions above are **decided profile-dependently**: `{FIPS ⇒ 1b + 2a, MODERN ⇒ 1a + 2b, 3a both}`. Because the wiring now *branches on the crypto profile*, the profile can no longer live as a build-time posture label (`params.hpp`): the value that selects a chain's enote wiring must be **consensus-visible and pinned at genesis** so two operators cannot silently disagree on which branch a block was applied under. **Increment 1 — the genesis profile pin — is SHIPPED (§5.1);** the remaining branch-bodies (MODERN `en:` leaf / FIPS payload region; MODERN note-key vs FIPS view-master derivation; the per-output enote vector; the `CONFIDENTIAL_TRANSFER`/`SHIELD` accept-rule + apply; the scan RPC; the light-client scan) follow as later owner-gated increments.

### 5.1 SHIPPED — increment 1: `CryptoProfile` promoted to a genesis-pinned consensus field

`CryptoProfile { MODERN=0, FIPS=1 }` (`include/determ/chain/params.hpp:122`) was a build-time posture label used only by the timing-profile constants. It is now also a **genesis-pinned consensus field** — the single value that selects the profile-keyed enote wiring of the RESOLUTION above — wired exactly like the `min_stake` / `confidential_tx_enabled` genesis parameters, and **byte-neutral for MODERN** so every pre-field chain stays byte-identical:

- **Genesis config field** `GenesisConfig::crypto_profile` (`include/determ/chain/genesis.hpp:191`), default `MODERN`. Emitted into the genesis JSON **only when non-default** (`src/chain/genesis.cpp:105`), parsed with a `MODERN` default (`:199`), and — when non-default — **mixed into the genesis hash** under the domain tag `DTM-genesis-crypto-profile-v1` (`:520`), so a FIPS genesis and a MODERN genesis cannot collide and no operator silently diverges.
- **Chain member** `Chain::crypto_profile_` + `crypto_profile()` / `set_crypto_profile()` (`include/determ/chain/chain.hpp:234`, `:804`), load-set before replay and on the genesis-bootstrap branch (`src/node/node.cpp:566`, `:640`, from `gcfg` at `:201`).
- **State-root binding — conditional.** A `k:crypto_profile` genesis-constant leaf is emitted **only when `≠ MODERN`** (`src/chain/chain.cpp:484`), so a MODERN chain's `state_root` is byte-identical to a pre-field chain; a FIPS chain's `state_root` diverges (light clients trustlessly bind the profile that selects the wiring). The value likewise round-trips through the state snapshot **only when non-default** (`src/chain/chain.cpp:2074` serialize, `:2283` restore).
- **Gate** `test-crypto-profile` (`src/main.cpp:25488`; FAST-suite member via `crypto_profile`, wrapper `tools/test_crypto_profile.sh`): 14 assertions — MODERN is byte-neutral (no `k:` leaf, no genesis-hash marker, no snapshot key, `state_root` == a profile-untouched chain); FIPS diverges both `state_root` and genesis hash; both round-trip through the genesis JSON and the state snapshot. **Falsify-on-mutant:** forcing the leaf unconditional turns the checked-in MODERN consensus goldens (`test_consensus_vectors.sh` V2–V4 `state_root`) RED — the `≠ MODERN` byte-neutrality guard is load-bearing.

MODERN being the default and byte-neutral, this increment is **consensus-invisible on every existing chain**; only a genesis that explicitly pins `FIPS` sees the new leaf, marker, and snapshot key. All FAST goldens + the cross-toolchain corpus are byte-identical with it compiled in.

---

## 6. Implementation cross-reference

| This document | Source |
|---|---|
| Construction + rationale + safety contract (header prose) | `include/determ/crypto/enote/enote.h:1-42` |
| Overhead constants (`EPH_LEN 33` / `TAG_LEN 16` / `OVERHEAD 49`) | `include/determ/crypto/enote/enote.h:53-55` |
| `determ_enote_seal` API contract | `include/determ/crypto/enote/enote.h:57-66` |
| `determ_enote_open` API contract (the `-1` = "not mine" scan path) | `include/determ/crypto/enote/enote.h:68-76` |
| HKDF salt / DST `"determ-enote-v1"` | `src/crypto/enote/enote.c:13` |
| Shared `enote_kdf` — `info = E33 ‖ R33`, `L = 44` → `K(32)‖N(12)` (EN-3 binding) | `src/crypto/enote/enote.c:18-28` |
| `seal`: decompress+check R, `E = e·G`, ECDH `Z = e·R`, AEAD `aad = E33`, secure-zero | `src/crypto/enote/enote.c:30-64` |
| `open`: `Z = r·E`, recompute local `R33`, AEAD-decrypt, secure-zero (writes nothing on fail) | `src/crypto/enote/enote.c:66-100` |
| Underlying primitives (ECDH / HKDF-SHA256 / ChaCha20-Poly1305 — no new primitive) | `include/determ/crypto/p256/p256.h`, `.../sha2/sha2.h`, `.../chacha20/chacha20.h` |
| Library membership (`determ-crypto-c99` source list) | `CMakeLists.txt:200-202` |
| Gate `test-enote-c99` — roundtrip / determinism / wrong-key / tamper / malformed / wire-shape / KAT | `src/main.cpp:15301-15434` |
| Gate wrapper (FAST-suite member) | `tools/test_enote_c99.sh` |
| FAST regex entry (`enote_c99`) | `tools/run_all.sh:108` |
| Dual-oracle KAT corpus + python-first oracle (5 vectors, byte-independent) | `tools/vectors/enote.json`, `tools/verify_enote.py` |
| NC-8 (the delivery gap this closes) + NC-7 (named inputs, orthogonal) | `docs/proofs/ShieldedPoolSoundness.md:168`, `:166` |
| `CONFIDENTIAL_TRANSFER = 14` (primary consumer) / `SHIELD = 12` (self-owned note) | `include/determ/chain/block.hpp:216`, `:198` |
| A2 view/audit layer (§5 sub-decision 1b; the "opaque key opens nothing" gap) | `include/determ/crypto/viewkey/viewkey.h`, `src/crypto/viewkey/viewkey.c`, `docs/proofs/AuditLayerSoundness.md`, `include/determ/chain/block.hpp:226` |
| Earlier proposal naming the receiver channel a prerequisite (superseded on curve) | `docs/proofs/ConfidentialTxIntegrationDesign.md:73` (§1.3) |
| **§5.1 profile pin** — `CryptoProfile { MODERN, FIPS }` enum (reused, not redefined) | `include/determ/chain/params.hpp:122` |
| §5.1 genesis field `crypto_profile` (default MODERN; emit/parse when non-default) | `include/determ/chain/genesis.hpp:191`, `src/chain/genesis.cpp:105`, `:199` |
| §5.1 genesis-hash mix (`DTM-genesis-crypto-profile-v1`, non-default only) | `src/chain/genesis.cpp:520` |
| §5.1 `Chain::crypto_profile_` member + getter/setter | `include/determ/chain/chain.hpp:234`, `:804` |
| §5.1 conditional `k:crypto_profile` state leaf (emit only when `≠ MODERN`) | `src/chain/chain.cpp:484` |
| §5.1 snapshot round-trip (serialize `:2074` / restore `:2283`, non-default only) | `src/chain/chain.cpp:2074`, `:2283` |
| §5.1 node wiring (load-set + genesis-bootstrap branch, from `gcfg`) | `src/node/node.cpp:566`, `:640`, `:201` |
| §5.1 gate `test-crypto-profile` (14 assertions; MODERN byte-neutral / FIPS diverges) | `src/main.cpp:25488`, `tools/test_crypto_profile.sh` |
| §5.1 FAST regex entry (`crypto_profile`) | `tools/run_all.sh:108` |

---

## 7. Status

- **STATUS: primitive SHIPPED (dual-oracle); wiring sub-decisions OWNER-DECIDED (profile-keyed, §5); wiring increment 1 — the genesis `CryptoProfile` pin (§5.1) — SHIPPED; the branch-bodies (leaf/payload, key derivation, accept-rule/apply, scan) remain owner-gated increments.**
- **Shipped surface.** The ephemeral-static ECIES-over-P-256 primitive `determ_enote_seal` / `determ_enote_open` (`src/crypto/enote/enote.{c,h}`), added to `determ-crypto-c99`; a pure composition of shipped P-256 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 with **no new hardness assumption**; secrets secure-zeroed on all paths. Gate `test-enote-c99` (FAST-suite member via `enote_c99`): the self-contained roundtrip / determinism / wrong-key-untouched / per-region tamper / malformed-fail-closed / wire-shape assertions **plus** the python-first dual-oracle KAT corpus (`tools/vectors/enote.json` produced byte-independently by `tools/verify_enote.py`, reproduced byte-for-byte).
- **Additive + state-root-invariant.** No chain/consensus/validator/producer/wallet/light path references the module; no new `TxType`, state leaf, or payload field. All golden `state_root`s, FAST determinism vectors, and the cross-toolchain corpus are byte-identical with it compiled in — the feature is consensus-invisible until §5 lands.
- **No-double-spend-by-design preserved.** NC-8 delivery is a passive payload orthogonal to the commitment set: no nullifier set, inputs stay named (NC-7 unchanged), commitment-as-its-own-nullifier untouched — every SP-* claim of `ShieldedPoolSoundness.md` holds. Inside the WHITEPAPER §12.1 on-chain-privacy non-goal (delivery only; zero observer-facing privacy added).
- **Wiring sub-decisions DECIDED, profile-keyed (§5; owner 2026-07-18).** `{FIPS ⇒ 1b view-master + 2a payload, MODERN ⇒ 1a note-key + 2b `en:` leaf, 3a per-output both}`. Because the wiring branches on the crypto profile, the profile is now a consensus value pinned at genesis (below), not a build-time posture label.
- **Wiring increment 1 SHIPPED — genesis `CryptoProfile` pin (§5.1).** `CryptoProfile { MODERN, FIPS }` promoted from a `params.hpp` posture label to a genesis-pinned consensus field: `GenesisConfig::crypto_profile` (mixed into the genesis hash under `DTM-genesis-crypto-profile-v1` when non-default), a `Chain::crypto_profile_` member (load-set + snapshot round-trip when non-default), and a conditional `k:crypto_profile` state leaf emitted **only for `≠ MODERN`**. **MODERN is byte-neutral** (no leaf, marker, or snapshot key) → every existing chain's `state_root`, genesis hash, and snapshot are byte-identical; a FIPS genesis diverges both `state_root` and genesis hash so operators cannot silently disagree. Gate `test-crypto-profile` (14 assertions, FAST-suite member via `crypto_profile`) + falsify-on-mutant against the consensus goldens. The remaining owner-gated increments carry the branch-bodies: MODERN `en:` leaf / FIPS payload region; MODERN dedicated note key / FIPS view-master derivation; the per-output enote vector; the `CONFIDENTIAL_TRANSFER`/`SHIELD` accept-rule + apply; the scan RPC; the light-client scan.
- **Limits.** (L-1) EN-2/EN-3 confidentiality + binding are an **argued reduction** to ECIES/DHIES under P-256 CDH + the HKDF-ROM + the AEAD, witnessed by the `test-enote-c99` reject paths, **not** a machine-checked proof. (L-2) The dual-oracle KAT corpus is a **fixed** 5-vector witness produced python-first; the gate flags a missing/short corpus fail-closed but does not sweep the input space. (L-3) EN-5 nonce-reuse safety is a **caller obligation** (fresh CSPRNG `eph_sk` per note) the primitive cannot enforce; the consensus wiring (§5) must supply fresh ephemerals. (L-4) This is an AI-drafted delivery channel; the §5 consensus follow-on enters immutable consensus code only under owner sign-off per `FROST_DEVIATION_NOTICE.md`.

Cross-references: [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (NC-7/NC-8 — the two open privacy residuals; SP-1..SP-13 preserved); [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) §1.3 (the receiver channel prerequisite, now built over P-256); [`AuditLayerSoundness.md`](AuditLayerSoundness.md) (the A2 layer whose view key §5 sub-decision 1b would give something to open); [`CRYPTO-C99-SPEC.md`](CRYPTO-C99-SPEC.md) (the P-256 / HKDF / ChaCha20-Poly1305 primitives + the dual-oracle discipline).
