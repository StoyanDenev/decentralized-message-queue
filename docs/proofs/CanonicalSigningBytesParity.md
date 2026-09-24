# CanonicalSigningBytesParity — byte-identity of the Transaction `signing_bytes` pre-image across the four gated implementations (FB61)

This document formalizes the **cross-binary signing_bytes byte-identity invariant**: that the canonical transaction pre-image — the byte string over which every Determ Ed25519 tx signature is computed and which SHA-256-hashes into the `tx_hash` — is computed **byte-for-byte identically** by the four implementations the source-parity guard pins (§1.2). The wallet and light binaries hold twelve further builders of the same pre-image (§1.3); their layout matches by inspection at 2b57d8ae, but no guard pins them. It is the per-pre-image *byte-identity* proof that `CrossBinaryCanonicalFormat.md` (CBF-2) names as the highest-stakes re-implementation surface but treats only at the structural-reuse level; this proof discharges the actual layout equality, field by field, with source-line citations.

The invariant matters because the copies are *deliberately decoupled*: `determ` holds the canonical `Transaction::signing_bytes`; `determ-wallet` re-implements it inline in eleven commands (it links neither `src/chain/block.cpp` nor any chain lib — `CMakeLists.txt:334-335`); and `determ-light` re-implements it in four places (it links `src/chain/block.cpp`, `CMakeLists.txt:398`, and its `outbox` verbs sign through the linked `Transaction::signing_bytes()`, but those four build the pre-image directly from CLI args). A one-line drift in any copy — a flipped endianness, a moved NUL, a reordered field — silently breaks tx interop: a tx signed by one binary fails verification on another, and because `tx_hash` is also the `tx_root` leaf, a divergent hash also breaks every inclusion proof (§6).

**Companion documents.** `Preliminaries.md` (F0) §2.0 canonical assumption labels — **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1). `CrossBinaryCanonicalFormat.md` (CBF — the structural-reuse parent: CBF-1 shared-by-linking vs CBF-2 re-implemented mirrors; this proof is the byte-identity discharge of CBF-2's Transaction `signing_bytes` mirror). `TxInclusionProofSoundness.md` (the `tx_root` reads back the `tx_hash` leaves this proof keeps identical — §3.3 there takes `Transaction::compute_hash` as the leaf-hash function; the parity invariant is what makes "the leaf" well-defined across binaries). `LightClientThreatModel.md` / `LightClientCompositionMap.md` (T-L5 `sign-tx` leg — the light-client signing path whose interop with the daemon depends on this parity). `MerkleTreeSoundness.md` (the sibling `state_root` substrate; orthogonal — the tx pre-image is *not* a Merkle leaf path).

---

## 1. The invariant

### 1.1 Statement

Fix any transaction tuple `T = (type, from, to, amount, fee, nonce, payload)` with `type ∈ {0..255}`, `from, to` arbitrary byte strings, `amount, fee, nonce ∈ [0, 2⁶⁴)`, and `payload` an arbitrary byte vector. Define the **canonical pre-image**

```
SB(T) = u8(type) ‖ from ‖ 0x00 ‖ to ‖ 0x00 ‖ u64_be(amount) ‖ u64_be(fee) ‖ u64_be(nonce) ‖ payload
```

where `u8(·)` is the single low byte and `u64_be(·)` is the 8-byte big-endian encoding (most-significant byte first). The invariant **CSP** asserts that all four implementations that build this pre-image produce `SB(T)` exactly:

> **CSP (signing-bytes parity).** For every `T`,
> `chain_SB(T) = wallet_tsv_SB(T) = wallet_cold_SB(T) = light_SB(T') = SB(T)` (byte-for-byte),
>
> where `T' = (type, from, to, amount, fee, nonce, ε)` is `T` restricted to the empty payload `ε`, and the light identity is `light_SB(T') = SB(T')` (the light implementation has no `payload` argument — §4.4). Consequently
>
> `SHA256(chain_SB(T)) = SHA256(wallet_tsv_SB(T)) = SHA256(wallet_cold_SB(T)) = tx_hash`, an **identical** 32-byte hash, and the Ed25519 signature computed over `SB(T)` by any one binary verifies under the recomputed `SB(T)` of any other (A1's message argument is byte-equal). Cross-binary tx-signature interop and identical `tx_root` leaves follow.

### 1.2 The four implementations

| # | Implementation | Where | Builds | Links chain lib? |
|---|---|---|---|---|
| C | canonical `Transaction::signing_bytes` | `src/chain/block.cpp:20-32` | full `SB(T)` incl. payload | — (it *is* the chain lib; `determ` links it) |
| W1 | wallet `tx-sign-verify` inline rebuild | `wallet/main.cpp:7726-7740` | full `SB(T)` incl. payload | no (`CMakeLists.txt:334-335` — wallet globs only `wallet/*.cpp`) |
| W2 | wallet `cold-sign` inline rebuild | `wallet/main.cpp:9926-9936` | full `SB(T)` incl. payload | no (same) |
| L | light `compute_signing_bytes` | `light/sign_tx.cpp:37-62` | `SB(T)` **minus** trailing payload | links `src/chain/block.cpp` (`CMakeLists.txt:398`), but this function **re-implements** the tx pre-image from CLI args; the light `outbox` verbs call the linked `Transaction::signing_bytes()` instead (§4.4) |

The light implementation omits the trailing `payload` append (`light/sign_tx.cpp:50` comment, line `:60` is the last layout statement — there is no payload insert after it). This is the **single permitted structural difference** and it is *vacuous* for the builder's callers: none of them passes a payload (§4.4), so every pre-image `compute_signing_bytes` builds is for `payload = ε`, where `SB(T)` minus an empty append is `SB(T')` exactly.

### 1.3 The other builders (not pinned by the guard)

The four sites above are the ones `tools/test_signing_bytes_source_parity.sh` and `tools/test_cross_binary_tx_parity.sh` pin. At 2b57d8ae the wallet and light binaries also build the pre-image in the places below. Each emits the same token sequence `TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE [PAYLOAD]`, with the same 7-down-to-0 big-endian loop (loop variable `j` in `bulk-send` / `bulk-stake`, a `be64` lambda in the two light helpers), by inspection of the cited lines; none binds a chain identity (the D23 binding that a84c3af1 added on 2026-09-21 was reverted by 25945193 on 2026-09-23; S-103 is open). CSP (§1.1) is **not** mechanically proved for them — a drift in one of them would not turn the source guard red.

| Builder | Where | Payload |
|---|---|---|
| wallet `sign-anon-tx` (`cmd_sign_anon_tx`) | `wallet/main.cpp:10327-10336` | TRANSFER, none appended (runtime-pinned by `test_cross_binary_tx_parity_edge.sh`, §5) |
| wallet `tx-batch-sign` | `wallet/main.cpp:10953-10962` | none appended |
| wallet `validate-tx` | `wallet/main.cpp:12170-12180` | full |
| wallet `verify-batch` (`verify_one_envelope`) | `wallet/main.cpp:12713-12724` | full |
| wallet `derive-tx-hash` | `wallet/main.cpp:15333-15344` | full |
| wallet `inspect-tx` | `wallet/main.cpp:16026-16037` | full |
| wallet `bulk-send` | `wallet/main.cpp:17295-17304` | TRANSFER, none appended |
| wallet `bulk-stake` | `wallet/main.cpp:17884-17894` | STAKE: the 8-byte LE amount, `amount` field 0 |
| wallet `param-change-build` | `wallet/main.cpp:23722-23732` | PARAM_CHANGE payload, `amount` 0, `to` empty |
| light `audit_signing_bytes` | `light/audit_tx.cpp:38-54` | full, `amount` 0, `to` empty |
| light `ct_signing_bytes` | `light/ct_tx.cpp:58-71` | full |
| light PQ_TRANSFER inline | `light/pq_sign_tx.cpp:369-375` | none appended (type 11) |

---

## 2. Preliminaries

We rely only on:

- **(P-det) Determinism of each builder.** `chain_SB`, `wallet_tsv_SB`, `wallet_cold_SB`, `light_SB` are pure functions of `T` — no clock, no RNG, no global mutable state, no allocator-dependent ordering. Each is a straight-line sequence of `push_back` / `insert` calls on a fresh `std::vector<uint8_t>` (cited per implementation below). A pure straight-line builder returns the same bytes on the same input on every host. (This is the per-pre-image specialization of `CrossBinaryCanonicalFormat.md` §4.3's determinism premise; the in-process `determ` leg is locked by `tools/test_tx_signing_determinism.sh`.)
- **(P-be) Fixed-width big-endian determinism.** The loop `for (int i = 7; i >= 0; --i) out.push_back((x >> (i*8)) & 0xFF)` emits exactly 8 bytes, most-significant first, for any `uint64_t x`, independent of host endianness (it is arithmetic on the value, not a memory `memcpy`). All four copies use this identical idiom (cited below).
- **A2** (SHA-256 collision resistance) is used only in §6 to argue that *equal pre-image ⇒ equal hash* is the load-bearing direction and a divergent pre-image would (overwhelmingly) yield a divergent hash; the parity equalities themselves are **unconditional** (exact byte equality, not probabilistic).

The struct field order that the canonical builder serializes is `type, from, to, amount, fee, nonce, payload` (`include/determ/chain/block.hpp:318-324`), exactly the order `SB(T)` lists — there is no reordering between the struct and its serialization. The struct's remaining fields `sig`, `hash` and `pq_auth` (`:325-331`) are not in the pre-image.

---

## 3. The canonical pre-image (the spec)

The canonical definition is `Transaction::signing_bytes` (`src/chain/block.cpp:20-32`):

```cpp
std::vector<uint8_t> Transaction::signing_bytes() const {            // block.cpp:20
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(type));                       // :22  TYPE
    out.insert(out.end(), from.begin(), from.end());                 // :23  FROM
    out.push_back(0);                                                // :24  NUL
    out.insert(out.end(), to.begin(), to.end());                     // :25  TO
    out.push_back(0);                                                // :26  NUL
    for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);  // :27  AMOUNT_BE
    for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);  // :28  FEE_BE
    for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);  // :29  NONCE_BE
    out.insert(out.end(), payload.begin(), payload.end());           // :30  PAYLOAD
    return out;                                                      // :31
}
```

and the tx hash is `Transaction::compute_hash` (`src/chain/block.cpp:34-37`):

```cpp
Hash Transaction::compute_hash() const {            // block.cpp:34
    auto sb = signing_bytes();                      // :35
    return sha256(sb.data(), sb.size());            // :36  tx_hash = SHA256(SB(T))
}
```

### 3.1 Field-by-field layout (canonical reference)

Offsets are within `SB(T)`; `|from|` and `|to|` denote the byte lengths of the (variable-length) `from` / `to` fields.

| # | Field | Offset | Width (bytes) | Encoding | Canonical source line |
|---|---|---|---|---|---|
| 1 | `type` | `0` | `1` | `static_cast<uint8_t>(type)` — low byte of the `TxType` enum | `block.cpp:22` |
| 2 | `from` | `1` | `|from|` | raw bytes, verbatim (no length prefix) | `block.cpp:23` |
| 3 | NUL sep | `1+|from|` | `1` | literal `0x00` (`push_back(0)`) | `block.cpp:24` |
| 4 | `to` | `2+|from|` | `|to|` | raw bytes, verbatim (no length prefix) | `block.cpp:25` |
| 5 | NUL sep | `2+|from|+|to|` | `1` | literal `0x00` (`push_back(0)`) | `block.cpp:26` |
| 6 | `amount` | `3+|from|+|to|` | `8` | `u64` big-endian (`i=7..0`, `(x>>(i*8))&0xFF`) | `block.cpp:27` |
| 7 | `fee` | `11+|from|+|to|` | `8` | `u64` big-endian, same idiom | `block.cpp:28` |
| 8 | `nonce` | `19+|from|+|to|` | `8` | `u64` big-endian, same idiom | `block.cpp:29` |
| 9 | `payload` | `27+|from|+|to|` | `|payload|` | raw bytes, verbatim (no length prefix) | `block.cpp:30` |

Total length `= 27 + |from| + |to| + |payload|`. The two NUL separators delimit `from` and `to` only when neither contains a `0x00` byte, and no rule in the C++ node enforces that: `BlockValidator::check_transaction` (`src/node/validator.cpp:746-1636`) has no character rule on `from` or `to`, and both ingress encodings carry them as arbitrary byte strings (`Transaction::from_json`, `src/chain/block.cpp:56-77`; the frame's `get_lp_str`, `:139-146`). The C99 charset check that does reject NUL (`wire_validate_charset_strict`, `src/wire/parser.c:53-80`) is reached only through `wire_parse_transaction`, whose only callers are the C99 fuzzer and test harness (`tests/fuzzer_parser.c`, `tests/test_k2_duel.c`); no node path calls it. The pre-image is therefore injective only on transactions whose `from` and `to` are NUL-free, and §4.6 gives a valid-looking collision outside that set. Once `|from|` and `|to|` are fixed, the `u64_be` triple and the `payload` tail parse positionally. The `Transaction` is declared with these fields in this order (`block.hpp:318-324`) and `signing_bytes` is its method (`block.hpp:333`).

---

## 4. Theorems

### 4.1 Theorem T-1 (canonical defines the spec)

**Statement.** `chain_SB(T) = SB(T)` for every `T`, and `Transaction::compute_hash() = SHA256(SB(T)) = tx_hash`.

**Proof.** By definition: `SB(T)` in §1.1 is the term-by-term transcription of `block.cpp:22-30` (the §3.1 table maps each emitted token to its source line). `compute_hash` (`block.cpp:35-36`) calls `signing_bytes()` then `sha256` over its bytes, so `tx_hash = SHA256(chain_SB(T)) = SHA256(SB(T))`. T-1 *defines* the reference against which T-2..T-4 are proved; there is no obligation beyond the transcription, which §3 exhibits in full. ∎

### 4.2 Theorem T-2 (wallet `tx-sign-verify` == spec)

**Statement.** `wallet_tsv_SB(T) = SB(T)` for every `T`; hence `SHA256(wallet_tsv_SB(T)) = tx_hash`.

**Proof obligation.** The source token sequence of `cmd_tx_sign_verify`'s inline rebuild equals the canonical token sequence.

**Proof (by inspection).** The rebuild is `wallet/main.cpp:7726-7740`:

```cpp
std::vector<uint8_t> sb;                                          // :7726
sb.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24 + payload_bytes.size()); // :7727 (capacity only)
sb.push_back(static_cast<uint8_t>(tx_type));                     // :7728  TYPE
sb.insert(sb.end(), from_str.begin(), from_str.end());          // :7729  FROM
sb.push_back(0);                                                 // :7730  NUL
sb.insert(sb.end(), to_str.begin(), to_str.end());              // :7731  TO
sb.push_back(0);                                                 // :7732  NUL
for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);  // :7737  AMOUNT_BE
for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);  // :7738  FEE_BE
for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);  // :7739  NONCE_BE
sb.insert(sb.end(), payload_bytes.begin(), payload_bytes.end()); // :7740  PAYLOAD
```

Token-by-token against §3: `TYPE (7728 ≡ block.cpp:22)`, `FROM (7729 ≡ :23)`, `NUL (7730 ≡ :24)`, `TO (7731 ≡ :25)`, `NUL (7732 ≡ :26)`, `AMOUNT_BE (7737 ≡ :27)`, `FEE_BE (7738 ≡ :28)`, `NONCE_BE (7739 ≡ :29)`, `PAYLOAD (7740 ≡ :30)`. The variable names differ (`sb`/`out`, `from_str`/`from`, `to_str`/`to`, `tx_type`/`type`, `payload_bytes`/`payload`) but the *operations* are identical: the same low-byte cast, the same verbatim `insert`s, the same `push_back(0)` separators, and the same `i=7..0` big-endian loops in the same `amount, fee, nonce` order. The `reserve` at `:7727` is a capacity hint that emits no bytes (`SB(T)` is unaffected). By (P-det)+(P-be) the resulting byte vectors are equal. The hash equality follows from `determ_sha256(sb.data(), sb.size(), sb_sha.data())` at `wallet/main.cpp:7746-7747` over the identical pre-image. ∎

**Mechanical discharge.** `tools/test_signing_bytes_source_parity.sh` reduces this exact region (anchored on the `sb.push_back(static_cast<uint8_t>(tx_type))` line at `:7728` and the `payload` insert at `:7740`) to the token list `TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE PAYLOAD` and asserts equality with the canonical site's tokens — turning any drift RED at the source level pre-build (§5).

### 4.3 Theorem T-3 (wallet `cold-sign` == spec)

**Statement.** `wallet_cold_SB(T) = SB(T)` for every `T`; hence `SHA256(wallet_cold_SB(T)) = tx_hash`.

**Proof obligation.** Same as T-2, for the `cmd_cold_sign` region.

**Proof (by inspection).** The rebuild is `wallet/main.cpp:9926-9936`:

```cpp
std::vector<uint8_t> sb;                                          // :9926
sb.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24 + payload_bytes.size()); // :9927 (capacity only)
sb.push_back(static_cast<uint8_t>(tx_type));                     // :9928  TYPE
sb.insert(sb.end(), from_str.begin(), from_str.end());          // :9929  FROM
sb.push_back(0);                                                 // :9930  NUL
sb.insert(sb.end(), to_str.begin(), to_str.end());              // :9931  TO
sb.push_back(0);                                                 // :9932  NUL
for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);  // :9933  AMOUNT_BE
for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);  // :9934  FEE_BE
for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);  // :9935  NONCE_BE
sb.insert(sb.end(), payload_bytes.begin(), payload_bytes.end()); // :9936  PAYLOAD
```

This is byte-for-byte the same statement list as T-2 (the in-source comment at `wallet/main.cpp:9921-9925` states "Same layout `cmd_tx_sign_verify` reconstructs above; keep this copy in sync"). Token-by-token it maps onto §3 identically: `TYPE (9928 ≡ block.cpp:22)` … `PAYLOAD (9936 ≡ :30)`. By (P-det)+(P-be) the vectors are equal; the hash equality follows from `determ_sha256` at `wallet/main.cpp:9940-9941` over the identical pre-image. ∎

**Mechanical discharge.** `tools/test_signing_bytes_source_parity.sh` isolates this second `sb`-block (it locates *both* `sb.push_back(static_cast<uint8_t>(tx_type))` anchors — `:7728` and `:9928` — and slices the file at the second for `cmd_cold_sign`) and asserts the same canonical token list. The cross-site assertion at the guard's tail (`SEQ1 = SEQ2 = SEQ3`) makes the W1≡W2≡C equality a single explicit check.

### 4.4 Theorem T-4 (light == spec restricted to empty payload — safe by construction)

**Statement.** `light_SB(T') = SB(T')` for every `T'` with `payload = ε`; and because no caller of `compute_signing_bytes` passes a payload, the restriction is total over the pre-images this builder is asked for, and `light_SB ≡ SB` there. (The light binary's payload-bearing signer, `outbox`, uses the linked canonical builder C, not this one.)

**Proof obligation.** The light source token sequence equals the canonical token sequence *minus the trailing PAYLOAD token*, and the omission is the sole structural difference.

**Proof (by inspection).** The builder is `compute_signing_bytes` (`light/sign_tx.cpp:37-62`):

```cpp
std::vector<uint8_t> compute_signing_bytes(LightTxType type,
        const std::string& from_str, const std::string& to_str,
        uint64_t amount, uint64_t fee, uint64_t nonce) {          // :37-42  (NO payload param)
    std::vector<uint8_t> out;
    out.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24); // :52 (capacity only; note: no payload term)
    out.push_back(static_cast<uint8_t>(type));                    // :53  TYPE
    out.insert(out.end(), from_str.begin(), from_str.end());      // :54  FROM
    out.push_back(0);                                             // :55  NUL
    out.insert(out.end(), to_str.begin(), to_str.end());          // :56  TO
    out.push_back(0);                                             // :57  NUL
    for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);  // :58  AMOUNT_BE
    for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);  // :59  FEE_BE
    for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);  // :60  NONCE_BE
    return out;                                                   // :61  (no PAYLOAD insert)
}
```

Token-by-token against §3: `TYPE (53 ≡ block.cpp:22)`, `FROM (54 ≡ :23)`, `NUL (55 ≡ :24)`, `TO (56 ≡ :25)`, `NUL (57 ≡ :26)`, `AMOUNT_BE (58 ≡ :27)`, `FEE_BE (59 ≡ :28)`, `NONCE_BE (60 ≡ :29)`. The builder *stops* at `:60`; there is no `insert(... payload ...)` line. So the light token list is exactly the canonical list minus the trailing `PAYLOAD`. For `payload = ε`, the canonical builder's `:30` append inserts *zero bytes*, so `SB(T') = (canonical tokens through NONCE_BE) = light_SB(T')`. Therefore `light_SB(T') = SB(T')` exactly.

**Safe by construction (the restriction is total over the builder's callers).** `compute_signing_bytes` takes no `payload` argument (`light/sign_tx.cpp:37-42`). It has three callers, and none has a payload to pass:

- `sign_light_tx` (`light/sign_tx.cpp:88-89`), behind `sign-tx`, which has no payload flag; the envelope it emits writes `payload` as the empty string (`:118`).
- `pq-sign-tx` (`light/pq_sign_tx.cpp:187`); its envelope also writes `payload` as `""` (`:198`).
- The generic DPQ1 leg of `pq-verify-tx` (`light/pq_sign_tx.cpp:260-273`). It reads `type, from, to, amount, fee, nonce` from the transaction and never its `payload`, so for a transaction with a non-empty `payload` it checks the envelope against `SB(T')`, not the `SB(T)` the chain uses. The leg only handles non-PQ_TRANSFER transactions that carry `pq_auth`, and the node rejects every such transaction (D9: `src/node/validator.cpp:805-807`, mirrored at ingress in `src/node/node.cpp:2856-2857`).

Within that domain `light_SB ≡ SB`, and any envelope `sign-tx` emits, fed to `determ tx-hash` / `determ-wallet tx-sign-verify`, hits the canonical builder with `payload = ε` and produces the identical `tx_hash`. (The comment at `light/sign_tx.cpp:50` — "payload (empty for all light-client tx types)" — records this contract in-source.) The light binary does sign payload-bearing transactions elsewhere: `outbox enqueue` and `outbox replace` accept `--payload-hex` and sign with the linked `Transaction::signing_bytes()` (`light/outbox.cpp:780-790`). That path is builder C itself, not a mirror, so it needs no parity argument. ∎

**Mechanical discharge.** `tools/test_signing_bytes_source_parity.sh` extracts site 4 with the `nonce` BE loop as its end-anchor, asserts its token list equals `TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE` (canonical minus `PAYLOAD`), and the cross-site assertion (`SEQ1` with one trailing `PAYLOAD` stripped `== SEQ4`) confirms the omission is the *sole* difference — any *other* divergence (a dropped NUL, an LE loop, a swapped field) would fail that exact-remainder check.

### 4.5 Corollary (cross-binary interop)

From T-1..T-4, for any `T` (with the light leg restricted to its empty-payload domain) all four pre-images are byte-equal, so:

1. **Identical `tx_hash`.** `SHA256` of a single byte string is a single value; equal pre-images ⇒ equal `tx_hash`. The four hashes coincide *exactly* (no probabilistic slack — A2 is not needed for the equality, only for §6's divergence-detection direction).
2. **Signature interop (A1).** Ed25519 signs/verifies the *message bytes* directly, not a pre-hashed digest, and both sides run the same C99 verifier: the wallet's `crypto_sign_verify_detached` is a shim over `determ_ed25519_verify` (`wallet/main.cpp:74-77`), which is also what the chain's `crypto::verify` calls (`src/crypto/keys.cpp:350-354`). (The wallet comment at `wallet/main.cpp:7754-7760` still names an `EVP_DigestVerify` path for the chain; that OpenSSL path is gone.) Since every binary recomputes the *same* message `SB(T)`, a signature produced over `SB(T)` by one binary verifies under the other's recomputed `SB(T)`.
3. **Identical `tx_root` leaf.** `compute_tx_root` (`src/node/producer.cpp:397-405`) hashes the sorted set of transaction hashes, each a `Transaction::compute_hash()` value (`block.cpp:34-37`; `TxInclusionProofSoundness.md` §3.3). Equal `tx_hash` ⇒ identical leaves ⇒ identical `tx_root` regardless of which binary produced the tx. ∎

### 4.6 Theorem T-6 (injectivity holds only for NUL-free `from` and `to`)

**Statement.** Let $\mathcal{T}_{\neg 0}$ be the set of transactions whose `from` and `to` contain no `0x00` byte. On $\mathcal{T}_{\neg 0}$ the pre-image map is injective:
$$\forall T_1, T_2 \in \mathcal{T}_{\neg 0}, \quad \mathrm{SB}(T_1) = \mathrm{SB}(T_2) \implies T_1 = T_2 .$$
Outside $\mathcal{T}_{\neg 0}$ it is not, and the node does not confine transactions to $\mathcal{T}_{\neg 0}$: no C++ accept rule rejects a NUL in `from` or `to` (§3.1).

**Proof (injectivity on $\mathcal{T}_{\neg 0}$).** Let $S = \mathrm{SB}(T)$ with $f = |T.\mathrm{from}|$ and $t = |T.\mathrm{to}|$; indices are 0-based.

1. $S[0]$ is the type byte.
2. $T.\mathrm{from}$ contains no $0\mathrm{x}00$, so the first $0\mathrm{x}00$ in $S[1..]$ is at index $1 + f$. That fixes $f$ and $T.\mathrm{from} = S[1 \,..\, f]$.
3. $T.\mathrm{to}$ contains no $0\mathrm{x}00$, so the next $0\mathrm{x}00$ is at index $2 + f + t$. That fixes $t$ and $T.\mathrm{to} = S[2+f \,..\, 1+f+t]$.
4. The three 8-byte big-endian fields are $\mathrm{amount} = S[3+f+t \,..\, 10+f+t]$, $\mathrm{fee} = S[11+f+t \,..\, 18+f+t]$ and $\mathrm{nonce} = S[19+f+t \,..\, 26+f+t]$. Big-endian encoding is a bijection on $[0, 2^{64})$.
5. $T.\mathrm{payload} = S[27+f+t \,..\, |S|-1]$.

Every field of $T$ is recovered from $S$, so $\mathrm{SB}(T_1) = \mathrm{SB}(T_2)$ forces $T_1 = T_2$. $\blacksquare$

**Counterexample outside $\mathcal{T}_{\neg 0}$.** Take any `type` and `from`, and

- $T$: `to = "bob"`, `amount = 1000`, `fee = 10`, `nonce = 0`, `payload = 00 6d 65 6d 6f` (`"\x00memo"`);
- $T'$: `to = "bob\x00"`, `amount = 256000`, `fee = 2560`, `nonce = 0`, `payload = 6d 65 6d 6f` (`"memo"`).

After the common prefix `u8(type) ‖ from ‖ 00 ‖ 62 6f 62` both pre-images end in the same 30 bytes:

```
00 00 00 00 00 00 00 03 e8 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 00 00 6d 65 6d 6f
```

$T$ reads them as `NUL ‖ u64_be(1000) ‖ u64_be(10) ‖ u64_be(0) ‖ "\x00memo"`. $T'$ reads them as `"\x00"` (the last byte of its `to`) followed by `NUL ‖ u64_be(256000) ‖ u64_be(2560) ‖ u64_be(0) ‖ "memo"`. So $\mathrm{SB}(T) = \mathrm{SB}(T')$ with $T \ne T'$: one Ed25519 signature and one `tx_hash` cover both.

In general, moving a leading `0x00` of `payload` onto the end of `to` gives a second parse of the same bytes whenever `amount < 2^56` and `payload` is non-empty, with `amount' = 256·amount + ⌊fee / 2^56⌋`, `fee' = (256·fee mod 2^64) + ⌊nonce / 2^56⌋`, `nonce' = (256·nonce mod 2^64) + payload[0]` and `payload' = payload[1..]`.

Nothing in the node excludes $T'$. It carries $T$'s `hash`, which the ingress recomputation confirms (`src/node/node.cpp:3336` on the gossip path), and $T$'s signature, which verifies over the same bytes; the verifier's TRANSFER case checks only the 128-byte payload cap (`src/node/validator.cpp:944-954`), and no rule restricts which bytes `to` may contain. A peer that has seen the signed $T$ can therefore relay $T'$ in its place. $T'$ is admissible whenever `nonce'` is the sender's next nonce (in the example it equals $T$'s nonce) and the sender's balance covers `amount' + fee'`. The mempool keeps the higher-fee version of a `(from, nonce)` slot (`Node::admit_tx_locked`, `src/node/node.cpp:3367-3375`), and `fee' = 256·fee > fee` for any `fee > 0`, so $T'$ displaces $T$ at every node it reaches. The included transaction then pays 256 times the amount and fee, to the account `"bob\x00"`, and a check of inclusion by `tx_hash` cannot tell which of the two was included. REGISTER does not restrict the bytes of a domain name either: its verifier case checks the region's charset, not `from`'s (`src/node/validator.cpp:809-885`).

Reproduced at 2b57d8ae on a three-node `single_test` chain: $T$ (signed with `determ-wallet cold-sign`) was submitted to one node and $T'$ to another; both were accepted as `queued` under the same hash, the block included $T'$, and the sender's balance fell by 258 560 (256 000 + 2 560) on every node.

The C99 charset check that would exclude $T'$ (`wire_validate_charset_strict`, `src/wire/parser.c:53-80`) is on no node path (§3.1). Parity (CSP, T-1..T-4) is unaffected: every builder produces the same colliding bytes.

---

## 5. Mechanized witnesses

Defense-in-depth: a **source-level guard** catches drift *before* a build, a **runtime parity** check catches it *after* a build, and **negative controls** in both prove the checks are live (not tautologies that pass on any input).

| Layer | Script | What it pins | Live-check (negative control) |
|---|---|---|---|
| Source (pre-build) | `tools/test_signing_bytes_source_parity.sh` | Parses all four C++ sites (block.cpp / wallet ×2 / light), reduces each layout region to an ordered token list, asserts sites C/W1/W2 == canonical `TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE PAYLOAD` and site L == that minus the trailing `PAYLOAD`, with the cross-site assertion that L's omission is the *sole* diff. Pure `awk`/`grep` over `.cpp`; no binary, never SKIPs, offline, deterministic. BE-direction is enforced *inside* the regex (`for(i=7;i>=0;--i)` only) and the shift width is bound to `(i * 8)`, so both a little-endian rewrite and an `i*4`/`i*16` byte-width corruption drop the field's token. | `SELFTEST=1 bash …` runs an executable liveness self-check: it feeds five synthetic snippets (canonical sanity + four drift classes — little-endian rewrite, fee/nonce field swap, dropped NUL, `i*4` width corruption) through the *same* `extract_tokens()` and asserts each drift reduces to a token sequence that differs from the canonical, i.e. the production guard *would* flag it RED. Exits non-zero if any drift is missed. |
| Runtime (post-build) | `tools/test_cross_binary_tx_parity.sh` | Boots none/needs no cluster: for TRANSFER (incl. `fee=0`), STAKE, UNSTAKE it has `determ-light sign-tx` produce a signed envelope, then asserts `light.hash == determ tx-hash == wallet.tx_hash_hex == wallet.computed_signing_bytes_sha256` AND that `determ-wallet tx-sign-verify` reports `valid=true` (a light-binary sig verifying under the wallet's independent `signing_bytes` rebuild — the interop invariant of §4.5). Runs on every host (signing_bytes/tx_hash only; no genesis-hash leg). | A tamper step mutates one byte of `amount` *after* signing while keeping the stale stored `hash`; `determ tx-hash` recomputes from the mutated body and must DIFFER from the stored hash — proving the four-way equality is a live check, not a tautology (script lines 225-256). |
| Runtime edge (post-build) | `tools/test_cross_binary_tx_parity_edge.sh` | Extends the runtime parity to the boundary inputs the base test omits: high-byte and `u64`-max `amount`/`fee`/`nonce` values — `2⁶⁴−1` (all `0xFF`), `2⁶³` (top-bit-only, catches a signed-shift bug), `2⁶⁴−2`, and a byte-walker `0x0101010101010101` — exercising every byte position of the three `u64_be` encodings, so a single mis-shifted byte in any copy diverges. It also drives the wallet's **second and third independent `signing_bytes` copies** — `cmd_cold_sign` (`wallet/main.cpp:9926`) and `cmd_sign_anon_tx` — which the base test never exercises (it only hits `cmd_tx_sign_verify`'s verify-side rebuild), pinning each to the canonical `determ tx-hash` at full `u64` width. (The light leg uses a signed parser that rejects values `> 2⁶³−1`, so the very-high tuples assert `determ == wallet-copyA == wallet-copyB` and the in-range tuples keep full four-way parity.) | A recompute-after-mutation control that flips a **high** byte (`amount ^= 1<<56`, the most-significant `u64_be` byte) and confirms the recomputed hash diverges — proving the high byte positions are genuinely bound. 48 assertions, 0 fail. |

Why all three are needed: the source guard catches a maintainer's edit at review time *even on a host that cannot build all three binaries* (e.g. this Windows box, where the genesis-hash path has a known edge); the runtime tests catch a *build* fault (a stale relink that the source agrees on but the binaries don't) and confirm real Ed25519 interop end-to-end; the edge test closes the "passes on `amount=1000` but diverges on `amount=2⁶⁴−1`" gap that low-value vectors leave open. The negative controls make each layer a *live* equality check rather than a green-by-default assertion.

> **Status note.** All three scripts are shipped and pass at 2b57d8ae: `tools/test_signing_bytes_source_parity.sh` (source guard, 6/6 + a `SELFTEST=1` liveness mode, exit 0), `tools/test_cross_binary_tx_parity.sh` (base runtime, 29/0), and `tools/test_cross_binary_tx_parity_edge.sh` (high-byte / `u64`-max + second/third-wallet-copy edge runtime, 48/0). A full `tools/run_all.sh` discovers them through its `tools/test_*.sh` glob, but none of the three is in the FAST=1 set, so `tools/ci_local.sh` and CI (`.github/workflows/ci.yml`) never run them.

---

## 6. Threat / why it matters

A one-line drift in any of the four copies — a flipped endianness in a `u64_be` loop (`i=0;i<8` instead of `i=7;i>=0`), a moved or dropped NUL separator, a reordered `amount`/`fee`/`nonce` field, or a stray field — silently breaks transaction interop. The failure is not loud: each binary still produces a *self-consistent* signature, but the pre-images diverge, so **a tx signed by one binary fails Ed25519 verification on another** (the verifier recomputes a different `SB(T)`, and A1's message argument no longer matches the signed bytes). An operator who signs offline with `determ-wallet cold-sign` or `determ-light sign-tx` and submits to a `determ` daemon would see otherwise-valid transactions rejected with no obvious cause.

The blast radius is wider than signing. Because `tx_hash = SHA256(SB(T))` is *also* the `tx_root` leaf (`TxInclusionProofSoundness.md` §3.3; `compute_tx_root` hashes the `compute_hash()` set), a divergent pre-image yields a divergent `tx_hash`, hence a **divergent `tx_root`** for the same logical transaction. A light-client running `verify-tx-inclusion` and computing the leaf with a drifted `light_SB` would compute a leaf the committee never signed — turning a genuine `INCLUDED` into a spurious `UNVERIFIABLE` (or, worse, mis-deciding membership). The same drift would make a wallet-generated `derive-tx-hash` disagree with the daemon's stored `hash`, breaking every tooling cross-check keyed on tx identity.

Under A2, divergence detection is reliable: two distinct pre-images hash to distinct `tx_hash` values except with probability `≤ 2⁻¹²⁸`, so the runtime parity check (§5) reliably *flags* any real drift rather than masking it behind a hash collision. But the parity equalities this proof establishes are **unconditional** byte equalities — the four copies do not merely "probably agree," they agree exactly — so the only way interop breaks at the four pinned sites is a *source edit* that the two guards are designed to turn RED (the twelve builders of §1.3 have no such guard). CSP is the invariant that keeps "the transaction" a single, binary-independent object; the four mechanized witnesses keep CSP from rotting.

---

## 7. Implementation cross-references

| Theorem / claim | Function | File:lines | Role |
|---|---|---|---|
| T-1 canonical | `Transaction::signing_bytes` | `src/chain/block.cpp:20-32` | The spec `SB(T)`; defines the reference token sequence. |
| T-1 hash | `Transaction::compute_hash` | `src/chain/block.cpp:34-37` | `tx_hash = SHA256(SB(T))`. |
| T-1 struct order | `struct Transaction` | `include/determ/chain/block.hpp:318-324` (decl `:333`) | Field order `type,from,to,amount,fee,nonce,payload` = serialization order. |
| T-2 wallet tsv | `cmd_tx_sign_verify` rebuild | `wallet/main.cpp:7726-7740` (SHA-256 `:7746-7747`) | W1 inline mirror; full payload. |
| T-3 wallet cold | `cmd_cold_sign` rebuild | `wallet/main.cpp:9926-9936` (SHA-256 `:9940-9941`) | W2 inline mirror; full payload; comment `:9921-9925`. |
| T-4 light | `compute_signing_bytes` | `light/sign_tx.cpp:37-62` (payload omission `:50`/no insert after `:60`) | L mirror; empty-payload domain. |
| T-4 light domain | callers of `compute_signing_bytes` | `light/sign_tx.cpp:88-89` (`sign_light_tx`; `payload`="" at `:118`), `light/pq_sign_tx.cpp:187` (`payload`="" at `:198`) and `:268` | No payload param; no caller passes one. |
| T-4 outbox | `outbox` signing | `light/outbox.cpp:780-790` | Payload-bearing light signing goes through builder C. |
| §4.5 interop | Ed25519 verify | `wallet/main.cpp:74-77`, `src/crypto/keys.cpp:350-354` | Both call `determ_ed25519_verify` over the raw message bytes. |
| T-6 | TRANSFER rule; mempool replace-by-fee | `src/node/validator.cpp:944-954`; `src/node/node.cpp:3367-3375` | No rule on the bytes of `to`; the collision's higher fee wins the slot. |
| §6 tx_root leaf | `compute_tx_root` | `src/node/producer.cpp:397-405` | `tx_hash` is the `tx_root` leaf. |
| build decoupling | wallet sources | `CMakeLists.txt:334-335` | `determ-wallet` globs only `wallet/*.cpp` — no chain lib. |

Tests:

| Script | Theorem coverage |
|---|---|
| `tools/test_signing_bytes_source_parity.sh` | T-2/T-3/T-4 source-level token-identity (all four sites) + the sole-PAYLOAD-omission cross-site assertion; `SELFTEST=1` liveness self-check (four drift classes). |
| `tools/test_cross_binary_tx_parity.sh` | T-1..T-4 runtime byte-identity (light==determ==wallet on `tx_hash`) + §4.5 sig interop (`valid=true`); tamper negative control. |
| `tools/test_cross_binary_tx_parity_edge.sh` | High-byte / `u64`-max field values + the wallet's second/third `signing_bytes` copies (`cold-sign`, `sign-anon-tx`) at full `u64` width; high-byte-flip negative control. |
| `tools/test_tx_signing_determinism.sh` | (P-det) in-process determinism of the canonical builder. |

---

## 8. Status

- **Spec.** Complete (this document, FB61).
- **Invariant.** CSP holds **unconditionally** (exact byte equality) across the four implementations: T-1 (canonical), T-2 (wallet tx-sign-verify), T-3 (wallet cold-sign), T-4 (light, restricted to the empty-payload domain all its callers use). The four `tx_hash` values and the `tx_root` leaf coincide exactly; Ed25519 signatures interoperate across all three binaries. The twelve builders of §1.3 match by inspection only.
- **Injectivity.** Conditional (T-6): `SB` is injective only on transactions whose `from` and `to` contain no `0x00`. The node does not enforce that, so the §4.6 collision (one signature and one `tx_hash` for two different transfers) is reachable at 2b57d8ae.
- **Assumptions.** None for the byte-identity equalities (straight-line pure-function transcription, (P-det)+(P-be)). A2 (SHA-256 collision resistance) is used only in §6 for the divergence-*detection* direction; A1 (Ed25519 EUF-CMA) only for the interop corollary's message-argument equality.
- **Relationship to CBF.** This is the byte-identity discharge of `CrossBinaryCanonicalFormat.md` CBF-2's Transaction `signing_bytes` mirror — CBF proves the *structural reuse regime* (re-implemented vs shared-by-linking); this proves the *actual layout equality* field by field.
- **Mechanized witnesses.** Source guard `tools/test_signing_bytes_source_parity.sh` (shipped; 6/6 + `SELFTEST=1` liveness mode) + runtime `tools/test_cross_binary_tx_parity.sh` (shipped; 29/0) + edge runtime `tools/test_cross_binary_tx_parity_edge.sh` (shipped; 48/0, high-byte/`u64`-max + second/third wallet copy). Each carries a live negative control. None is in the FAST=1 set, so `tools/ci_local.sh` and CI do not run them (§5). No witness exercises T-6.
- **Threat.** A single-line drift in any copy silently breaks tx-signature interop *and* `tx_root` / inclusion-proof consistency; at the four pinned sites the two guards turn such a drift RED pre- and post-build when they are run.

---
