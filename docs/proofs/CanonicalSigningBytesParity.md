# CanonicalSigningBytesParity — byte-identity of the Transaction `signing_bytes` pre-image across all four implementations (FB61)

This document formalizes the **cross-binary signing_bytes byte-identity invariant**: that the canonical transaction pre-image — the byte string over which every Determ Ed25519 tx signature is computed and which SHA-256-hashes into the `tx_hash` — is computed **byte-for-byte identically** by all four independent implementations that build it. It is the per-pre-image *byte-identity* proof that `CrossBinaryCanonicalFormat.md` (CBF-2) names as the highest-stakes re-implementation surface but treats only at the structural-reuse level; this proof discharges the actual layout equality, field by field, with source-line citations.

The invariant matters because the four copies are *deliberately decoupled*: `determ` holds the canonical `Transaction::signing_bytes`; `determ-wallet` re-implements it inline twice (it links neither `src/chain/block.cpp` nor any chain lib — `CMakeLists.txt:232`); and `determ-light` re-implements it once (it never instantiates a `Transaction`, building bytes directly from CLI args). A one-line drift in any copy — a flipped endianness, a moved NUL, a reordered field — silently breaks tx interop: a tx signed by one binary fails verification on another, and because `tx_hash` is also the `tx_root` leaf, a divergent hash also breaks every inclusion proof (§6).

**Companion documents.** `Preliminaries.md` (F0) §2.0 canonical assumption labels — **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1). `CrossBinaryCanonicalFormat.md` (CBF — the structural-reuse parent: CBF-1 shared-by-linking vs CBF-2 re-implemented mirrors; this proof is the byte-identity discharge of CBF-2's Transaction `signing_bytes` mirror). `TxInclusionProofSoundness.md` (the `tx_root` reads back the `tx_hash` leaves this proof keeps identical — §3.3 there cites `block.cpp:17-34` as the leaf-hash function; the parity invariant is what makes "the leaf" well-defined across binaries). `LightClientThreatModel.md` / `LightClientCompositionMap.md` (T-L5 `sign-tx` leg — the light-client signing path whose interop with the daemon depends on this parity). `MerkleTreeSoundness.md` (the sibling `state_root` substrate; orthogonal — the tx pre-image is *not* a Merkle leaf path).

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
| C | canonical `Transaction::signing_bytes` | `src/chain/block.cpp:17-29` | full `SB(T)` incl. payload | — (it *is* the chain lib; `determ` links it) |
| W1 | wallet `tx-sign-verify` inline rebuild | `wallet/main.cpp:8228-8242` | full `SB(T)` incl. payload | no (`CMakeLists.txt:232` — wallet globs only `wallet/*.cpp`) |
| W2 | wallet `cold-sign` inline rebuild | `wallet/main.cpp:9550-9560` | full `SB(T)` incl. payload | no (same) |
| L | light `compute_signing_bytes` | `light/sign_tx.cpp:37-62` | `SB(T)` **minus** trailing payload | links `src/chain/block.cpp` for the *Block* path, but **re-implements** the tx pre-image (it never builds a `Transaction`) |

The light implementation omits the trailing `payload` append (`light/sign_tx.cpp:50` comment, line `:60` is the last layout statement — there is no payload insert after it). This is the **single permitted structural difference** and it is *vacuous* for the light API: `light/sign_tx.cpp` exposes no `--payload` parameter (§4.4), so every tx it can sign carries `payload = ε`, and `SB(T') = SB(T)` minus an empty append = `SB(T')` exactly.

---

## 2. Preliminaries

We rely only on:

- **(P-det) Determinism of each builder.** `chain_SB`, `wallet_tsv_SB`, `wallet_cold_SB`, `light_SB` are pure functions of `T` — no clock, no RNG, no global mutable state, no allocator-dependent ordering. Each is a straight-line sequence of `push_back` / `insert` calls on a fresh `std::vector<uint8_t>` (cited per implementation below). A pure straight-line builder returns the same bytes on the same input on every host. (This is the per-pre-image specialization of `CrossBinaryCanonicalFormat.md` §4.3's determinism premise; the in-process `determ` leg is locked by `tools/test_tx_signing_determinism.sh`.)
- **(P-be) Fixed-width big-endian determinism.** The loop `for (int i = 7; i >= 0; --i) out.push_back((x >> (i*8)) & 0xFF)` emits exactly 8 bytes, most-significant first, for any `uint64_t x`, independent of host endianness (it is arithmetic on the value, not a memory `memcpy`). All four copies use this identical idiom (cited below).
- **A2** (SHA-256 collision resistance) is used only in §6 to argue that *equal pre-image ⇒ equal hash* is the load-bearing direction and a divergent pre-image would (overwhelmingly) yield a divergent hash; the parity equalities themselves are **unconditional** (exact byte equality, not probabilistic).

The struct field order that the canonical builder serializes is `type, from, to, amount, fee, nonce, payload` (`include/determ/chain/block.hpp:206-212`), exactly the order `SB(T)` lists — there is no reordering between the struct and its serialization.

---

## 3. The canonical pre-image (the spec)

The canonical definition is `Transaction::signing_bytes` (`src/chain/block.cpp:17-29`):

```cpp
std::vector<uint8_t> Transaction::signing_bytes() const {            // block.cpp:17
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(type));                       // :19  TYPE
    out.insert(out.end(), from.begin(), from.end());                 // :20  FROM
    out.push_back(0);                                                // :21  NUL
    out.insert(out.end(), to.begin(), to.end());                     // :22  TO
    out.push_back(0);                                                // :23  NUL
    for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);  // :24  AMOUNT_BE
    for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);  // :25  FEE_BE
    for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);  // :26  NONCE_BE
    out.insert(out.end(), payload.begin(), payload.end());           // :27  PAYLOAD
    return out;                                                      // :28
}
```

and the tx hash is `Transaction::compute_hash` (`src/chain/block.cpp:31-34`):

```cpp
Hash Transaction::compute_hash() const {            // block.cpp:31
    auto sb = signing_bytes();                      // :32
    return sha256(sb.data(), sb.size());            // :33  tx_hash = SHA256(SB(T))
}
```

### 3.1 Field-by-field layout (canonical reference)

Offsets are within `SB(T)`; `|from|` and `|to|` denote the byte lengths of the (variable-length) `from` / `to` fields.

| # | Field | Offset | Width (bytes) | Encoding | Canonical source line |
|---|---|---|---|---|---|
| 1 | `type` | `0` | `1` | `static_cast<uint8_t>(type)` — low byte of the `TxType` enum | `block.cpp:19` |
| 2 | `from` | `1` | `|from|` | raw bytes, verbatim (no length prefix) | `block.cpp:20` |
| 3 | NUL sep | `1+|from|` | `1` | literal `0x00` (`push_back(0)`) | `block.cpp:21` |
| 4 | `to` | `2+|from|` | `|to|` | raw bytes, verbatim (no length prefix) | `block.cpp:22` |
| 5 | NUL sep | `2+|from|+|to|` | `1` | literal `0x00` (`push_back(0)`) | `block.cpp:23` |
| 6 | `amount` | `3+|from|+|to|` | `8` | `u64` big-endian (`i=7..0`, `(x>>(i*8))&0xFF`) | `block.cpp:24` |
| 7 | `fee` | `11+|from|+|to|` | `8` | `u64` big-endian, same idiom | `block.cpp:25` |
| 8 | `nonce` | `19+|from|+|to|` | `8` | `u64` big-endian, same idiom | `block.cpp:26` |
| 9 | `payload` | `27+|from|+|to|` | `|payload|` | raw bytes, verbatim (no length prefix) | `block.cpp:27` |

Total length `= 27 + |from| + |to| + |payload|`. The two NUL separators are unambiguous because `from` / `to` are address/domain strings (the chain rejects embedded NUL in those fields at the validity layer); the fixed-width `u64_be` triple and the `payload` tail parse positionally. The `Transaction` is declared with these fields in this order (`block.hpp:206-212`) and `signing_bytes` is its method (`block.hpp:216`).

---

## 4. Theorems

### 4.1 Theorem T-1 (canonical defines the spec)

**Statement.** `chain_SB(T) = SB(T)` for every `T`, and `Transaction::compute_hash() = SHA256(SB(T)) = tx_hash`.

**Proof.** By definition: `SB(T)` in §1.1 is the term-by-term transcription of `block.cpp:19-27` (the §3.1 table maps each emitted token to its source line). `compute_hash` (`block.cpp:32-33`) calls `signing_bytes()` then `sha256` over its bytes, so `tx_hash = SHA256(chain_SB(T)) = SHA256(SB(T))`. T-1 *defines* the reference against which T-2..T-4 are proved; there is no obligation beyond the transcription, which §3 exhibits in full. ∎

### 4.2 Theorem T-2 (wallet `tx-sign-verify` == spec)

**Statement.** `wallet_tsv_SB(T) = SB(T)` for every `T`; hence `SHA256(wallet_tsv_SB(T)) = tx_hash`.

**Proof obligation.** The source token sequence of `cmd_tx_sign_verify`'s inline rebuild equals the canonical token sequence.

**Proof (by inspection).** The rebuild is `wallet/main.cpp:8228-8242`:

```cpp
std::vector<uint8_t> sb;                                          // :8228
sb.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24 + payload_bytes.size()); // :8229 (capacity only)
sb.push_back(static_cast<uint8_t>(tx_type));                     // :8230  TYPE
sb.insert(sb.end(), from_str.begin(), from_str.end());          // :8231  FROM
sb.push_back(0);                                                 // :8232  NUL
sb.insert(sb.end(), to_str.begin(), to_str.end());              // :8233  TO
sb.push_back(0);                                                 // :8234  NUL
for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);  // :8239  AMOUNT_BE
for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);  // :8240  FEE_BE
for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);  // :8241  NONCE_BE
sb.insert(sb.end(), payload_bytes.begin(), payload_bytes.end()); // :8242  PAYLOAD
```

Token-by-token against §3: `TYPE (8230 ≡ block.cpp:19)`, `FROM (8231 ≡ :20)`, `NUL (8232 ≡ :21)`, `TO (8233 ≡ :22)`, `NUL (8234 ≡ :23)`, `AMOUNT_BE (8239 ≡ :24)`, `FEE_BE (8240 ≡ :25)`, `NONCE_BE (8241 ≡ :26)`, `PAYLOAD (8242 ≡ :27)`. The variable names differ (`sb`/`out`, `from_str`/`from`, `to_str`/`to`, `tx_type`/`type`, `payload_bytes`/`payload`) but the *operations* are identical: the same low-byte cast, the same verbatim `insert`s, the same `push_back(0)` separators, and the same `i=7..0` big-endian loops in the same `amount, fee, nonce` order. The `reserve` at `:8229` is a capacity hint that emits no bytes (`SB(T)` is unaffected). By (P-det)+(P-be) the resulting byte vectors are equal. The hash equality follows from `SHA256` at `wallet/main.cpp:8248-8249` (`SHA256(sb.data(), sb.size())`) over the identical pre-image. ∎

**Mechanical discharge.** `tools/test_signing_bytes_source_parity.sh` reduces this exact region (anchored on the `sb.push_back(static_cast<uint8_t>(tx_type))` line at `:8230` and the `payload` insert at `:8242`) to the token list `TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE PAYLOAD` and asserts equality with the canonical site's tokens — turning any drift RED at the source level pre-build (§5).

### 4.3 Theorem T-3 (wallet `cold-sign` == spec)

**Statement.** `wallet_cold_SB(T) = SB(T)` for every `T`; hence `SHA256(wallet_cold_SB(T)) = tx_hash`.

**Proof obligation.** Same as T-2, for the `cmd_cold_sign` region.

**Proof (by inspection).** The rebuild is `wallet/main.cpp:9550-9560`:

```cpp
std::vector<uint8_t> sb;                                          // :9550
sb.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24 + payload_bytes.size()); // :9551 (capacity only)
sb.push_back(static_cast<uint8_t>(tx_type));                     // :9552  TYPE
sb.insert(sb.end(), from_str.begin(), from_str.end());          // :9553  FROM
sb.push_back(0);                                                 // :9554  NUL
sb.insert(sb.end(), to_str.begin(), to_str.end());              // :9555  TO
sb.push_back(0);                                                 // :9556  NUL
for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);  // :9557  AMOUNT_BE
for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);  // :9558  FEE_BE
for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);  // :9559  NONCE_BE
sb.insert(sb.end(), payload_bytes.begin(), payload_bytes.end()); // :9560  PAYLOAD
```

This is byte-for-byte the same statement list as T-2 (the in-source comment at `wallet/main.cpp:9545-9549` states "Same layout `cmd_tx_sign_verify` reconstructs above; keep this copy in sync"). Token-by-token it maps onto §3 identically: `TYPE (9552 ≡ block.cpp:19)` … `PAYLOAD (9560 ≡ :27)`. By (P-det)+(P-be) the vectors are equal; the hash equality follows from `SHA256` at `wallet/main.cpp:9564-9565` over the identical pre-image. ∎

**Mechanical discharge.** `tools/test_signing_bytes_source_parity.sh` isolates this second `sb`-block (it locates *both* `sb.push_back(static_cast<uint8_t>(tx_type))` anchors — `:8230` and `:9552` — and slices the file at the second for `cmd_cold_sign`) and asserts the same canonical token list. The cross-site assertion at the guard's tail (`SEQ1 = SEQ2 = SEQ3`) makes the W1≡W2≡C equality a single explicit check.

### 4.4 Theorem T-4 (light == spec restricted to empty payload — safe by construction)

**Statement.** `light_SB(T') = SB(T')` for every `T'` with `payload = ε`; and because the light sign-tx CLI exposes no payload parameter, *every* tx the light binary can sign satisfies `payload = ε`, so the restriction is total over the light API's tx set and `light_SB ≡ SB` there.

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

Token-by-token against §3: `TYPE (53 ≡ block.cpp:19)`, `FROM (54 ≡ :20)`, `NUL (55 ≡ :21)`, `TO (56 ≡ :22)`, `NUL (57 ≡ :23)`, `AMOUNT_BE (58 ≡ :24)`, `FEE_BE (59 ≡ :25)`, `NONCE_BE (60 ≡ :26)`. The builder *stops* at `:60`; there is no `insert(... payload ...)` line. So the light token list is exactly the canonical list minus the trailing `PAYLOAD`. For `payload = ε`, the canonical builder's `:27` append inserts *zero bytes*, so `SB(T') = (canonical tokens through NONCE_BE) = light_SB(T')`. Therefore `light_SB(T') = SB(T')` exactly.

**Safe-by-construction (the restriction is total over the light API).** `compute_signing_bytes` takes no `payload` argument (`light/sign_tx.cpp:37-42`), and the only caller, `sign_light_tx`, passes the six fields and then emits `{"payload", ""}` in the envelope (`light/sign_tx.cpp:88-89` calls `compute_signing_bytes(...)`; `:118` writes `payload` as the empty string). The light CLI (`light sign-tx`) likewise has no `--payload` flag. Hence no light-signed tx ever carries a non-empty payload; the empty-payload restriction is not a gap but the *entire* domain of the light signer. Within that domain `light_SB ≡ SB`, and any such envelope, fed to `determ tx-hash` / `determ-wallet tx-sign-verify`, hits the canonical builder with `payload = ε` and produces the identical `tx_hash`. (The comment at `light/sign_tx.cpp:50` — "payload (empty for all light-client tx types)" — records this contract in-source.) ∎

**Mechanical discharge.** `tools/test_signing_bytes_source_parity.sh` extracts site 4 with the `nonce` BE loop as its end-anchor, asserts its token list equals `TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE` (canonical minus `PAYLOAD`), and the cross-site assertion (`SEQ1` with one trailing `PAYLOAD` stripped `== SEQ4`) confirms the omission is the *sole* difference — any *other* divergence (a dropped NUL, an LE loop, a swapped field) would fail that exact-remainder check.

### 4.5 Corollary (cross-binary interop)

From T-1..T-4, for any `T` (with the light leg restricted to its empty-payload domain) all four pre-images are byte-equal, so:

1. **Identical `tx_hash`.** `SHA256` of a single byte string is a single value; equal pre-images ⇒ equal `tx_hash`. The four hashes coincide *exactly* (no probabilistic slack — A2 is not needed for the equality, only for §6's divergence-detection direction).
2. **Signature interop (A1).** Ed25519 signs/verifies the *message bytes* directly (the wallet's own comment at `wallet/main.cpp:8256-8262` notes both `crypto_sign_verify_detached` and the chain's `EVP_DigestVerify` path operate on the raw `signing_bytes`, not a pre-hashed digest). Since every binary recomputes the *same* message `SB(T)`, a signature produced over `SB(T)` by one binary verifies under the other's recomputed `SB(T)`.
3. **Identical `tx_root` leaf.** `compute_tx_root` hashes the set of `Transaction::compute_hash()` values (`TxInclusionProofSoundness.md` §3.3, citing `src/node/producer.cpp:262-270` + `block.cpp:31-34`). Equal `tx_hash` ⇒ identical leaves ⇒ identical `tx_root` regardless of which binary produced the tx. ∎

---

## 5. Mechanized witnesses

Defense-in-depth: a **source-level guard** catches drift *before* a build, a **runtime parity** check catches it *after* a build, and **negative controls** in both prove the checks are live (not tautologies that pass on any input).

| Layer | Script | What it pins | Live-check (negative control) |
|---|---|---|---|
| Source (pre-build) | `tools/test_signing_bytes_source_parity.sh` | Parses all four C++ sites (block.cpp / wallet ×2 / light), reduces each layout region to an ordered token list, asserts sites C/W1/W2 == canonical `TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE PAYLOAD` and site L == that minus the trailing `PAYLOAD`, with the cross-site assertion that L's omission is the *sole* diff. Pure `awk`/`grep` over `.cpp`; no binary, never SKIPs, offline, deterministic. BE-direction is enforced *inside* the regex (`for(i=7;i>=0;--i)` only) and the shift width is bound to `(i * 8)`, so both a little-endian rewrite and an `i*4`/`i*16` byte-width corruption drop the field's token. | `SELFTEST=1 bash …` runs an executable liveness self-check: it feeds five synthetic snippets (canonical sanity + four drift classes — little-endian rewrite, fee/nonce field swap, dropped NUL, `i*4` width corruption) through the *same* `extract_tokens()` and asserts each drift reduces to a token sequence that differs from the canonical, i.e. the production guard *would* flag it RED. Exits non-zero if any drift is missed. |
| Runtime (post-build) | `tools/test_cross_binary_tx_parity.sh` | Boots none/needs no cluster: for TRANSFER (incl. `fee=0`), STAKE, UNSTAKE it has `determ-light sign-tx` produce a signed envelope, then asserts `light.hash == determ tx-hash == wallet.tx_hash_hex == wallet.computed_signing_bytes_sha256` AND that `determ-wallet tx-sign-verify` reports `valid=true` (a light-binary sig verifying under the wallet's independent `signing_bytes` rebuild — the interop invariant of §4.5). Runs on every host (signing_bytes/tx_hash only; no genesis-hash leg). | A tamper step mutates one byte of `amount` *after* signing while keeping the stale stored `hash`; `determ tx-hash` recomputes from the mutated body and must DIFFER from the stored hash — proving the four-way equality is a live check, not a tautology (script lines 229-257). |
| Runtime edge (post-build) | `tools/test_cross_binary_tx_parity_edge.sh` | Extends the runtime parity to the boundary inputs the base test omits: high-byte and `u64`-max `amount`/`fee`/`nonce` values — `2⁶⁴−1` (all `0xFF`), `2⁶³` (top-bit-only, catches a signed-shift bug), `2⁶⁴−2`, and a byte-walker `0x0101010101010101` — exercising every byte position of the three `u64_be` encodings, so a single mis-shifted byte in any copy diverges. It also drives the wallet's **second and third independent `signing_bytes` copies** — `cmd_cold_sign` (`wallet/main.cpp:9550`) and `cmd_sign_anon_tx` — which the base test never exercises (it only hits `cmd_tx_sign_verify`'s verify-side rebuild), pinning each to the canonical `determ tx-hash` at full `u64` width. (The light leg uses a signed parser that rejects values `> 2⁶³−1`, so the very-high tuples assert `determ == wallet-copyA == wallet-copyB` and the in-range tuples keep full four-way parity.) | A recompute-after-mutation control that flips a **high** byte (`amount ^= 1<<56`, the most-significant `u64_be` byte) and confirms the recomputed hash diverges — proving the high byte positions are genuinely bound. 48 assertions, 0 fail. |

Why all three are needed: the source guard catches a maintainer's edit at review time *even on a host that cannot build all three binaries* (e.g. this Windows box, where the genesis-hash path has a known edge); the runtime tests catch a *build* fault (a stale relink that the source agrees on but the binaries don't) and confirm real Ed25519 interop end-to-end; the edge test closes the "passes on `amount=1000` but diverges on `amount=2⁶⁴−1`" gap that low-value vectors leave open. The negative controls make each layer a *live* equality check rather than a green-by-default assertion.

> **Status note.** All three scripts are shipped and pass on the current tree: `tools/test_signing_bytes_source_parity.sh` (source guard, 6/6 + a `SELFTEST=1` liveness mode, exit 0), `tools/test_cross_binary_tx_parity.sh` (base runtime, 29/0), and `tools/test_cross_binary_tx_parity_edge.sh` (high-byte / `u64`-max + second/third-wallet-copy edge runtime, 48/0). All are auto-discovered by `run_all.sh` (the `tools/test_*.sh` glob).

---

## 6. Threat / why it matters

A one-line drift in any of the four copies — a flipped endianness in a `u64_be` loop (`i=0;i<8` instead of `i=7;i>=0`), a moved or dropped NUL separator, a reordered `amount`/`fee`/`nonce` field, or a stray field — silently breaks transaction interop. The failure is not loud: each binary still produces a *self-consistent* signature, but the pre-images diverge, so **a tx signed by one binary fails Ed25519 verification on another** (the verifier recomputes a different `SB(T)`, and A1's message argument no longer matches the signed bytes). An operator who signs offline with `determ-wallet cold-sign` or `determ-light sign-tx` and submits to a `determ` daemon would see otherwise-valid transactions rejected with no obvious cause.

The blast radius is wider than signing. Because `tx_hash = SHA256(SB(T))` is *also* the `tx_root` leaf (`TxInclusionProofSoundness.md` §3.3; `compute_tx_root` hashes the `compute_hash()` set), a divergent pre-image yields a divergent `tx_hash`, hence a **divergent `tx_root`** for the same logical transaction. A light-client running `verify-tx-inclusion` and computing the leaf with a drifted `light_SB` would compute a leaf the committee never signed — turning a genuine `INCLUDED` into a spurious `UNVERIFIABLE` (or, worse, mis-deciding membership). The same drift would make a wallet-generated `derive-tx-hash` disagree with the daemon's stored `hash`, breaking every tooling cross-check keyed on tx identity.

Under A2, divergence detection is reliable: two distinct pre-images hash to distinct `tx_hash` values except with probability `≤ 2⁻¹²⁸`, so the runtime parity check (§5) reliably *flags* any real drift rather than masking it behind a hash collision. But the parity equalities this proof establishes are **unconditional** byte equalities — the four copies do not merely "probably agree," they agree exactly — so the only way interop breaks is a *source edit* that the two guards are designed to turn RED. CSP is the invariant that keeps "the transaction" a single, binary-independent object; the four mechanized witnesses keep CSP from rotting.

---

## 7. Implementation cross-references

| Theorem / claim | Function | File:lines | Role |
|---|---|---|---|
| T-1 canonical | `Transaction::signing_bytes` | `src/chain/block.cpp:17-29` | The spec `SB(T)`; defines the reference token sequence. |
| T-1 hash | `Transaction::compute_hash` | `src/chain/block.cpp:31-34` | `tx_hash = SHA256(SB(T))`. |
| T-1 struct order | `struct Transaction` | `include/determ/chain/block.hpp:206-212` (decl `:216`) | Field order `type,from,to,amount,fee,nonce,payload` = serialization order. |
| T-2 wallet tsv | `cmd_tx_sign_verify` rebuild | `wallet/main.cpp:8228-8242` (SHA256 `:8248-8249`) | W1 inline mirror; full payload. |
| T-3 wallet cold | `cmd_cold_sign` rebuild | `wallet/main.cpp:9550-9560` (SHA256 `:9564-9565`) | W2 inline mirror; full payload; comment `:9545-9549`. |
| T-4 light | `compute_signing_bytes` | `light/sign_tx.cpp:37-62` (payload omission `:50`/no insert after `:60`) | L mirror; empty-payload domain. |
| T-4 light domain | `sign_light_tx` | `light/sign_tx.cpp:88-89` (call), `:118` (`payload`="") | No payload param; envelope payload always empty. |
| §4.5 interop note | wallet verify path | `wallet/main.cpp:8256-8262` | Ed25519 verifies raw message bytes (both paths). |
| §6 tx_root leaf | `compute_tx_root` | `src/node/producer.cpp:262-270` (via `TxInclusionProofSoundness.md` §3.3) | `tx_hash` is the `tx_root` leaf. |
| build decoupling | wallet sources | `CMakeLists.txt:232` | `determ-wallet` globs only `wallet/*.cpp` — no chain lib. |

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
- **Invariant.** CSP holds **unconditionally** (exact byte equality) across the four implementations: T-1 (canonical), T-2 (wallet tx-sign-verify), T-3 (wallet cold-sign), T-4 (light, restricted to its total empty-payload domain). The four `tx_hash` values and the `tx_root` leaf coincide exactly; Ed25519 signatures interoperate across all three binaries.
- **Assumptions.** None for the byte-identity equalities (straight-line pure-function transcription, (P-det)+(P-be)). A2 (SHA-256 collision resistance) is used only in §6 for the divergence-*detection* direction; A1 (Ed25519 EUF-CMA) only for the interop corollary's message-argument equality.
- **Relationship to CBF.** This is the byte-identity discharge of `CrossBinaryCanonicalFormat.md` CBF-2's Transaction `signing_bytes` mirror — CBF proves the *structural reuse regime* (re-implemented vs shared-by-linking); this proves the *actual layout equality* field by field.
- **Mechanized witnesses.** Source guard `tools/test_signing_bytes_source_parity.sh` (shipped; 6/6 + `SELFTEST=1` liveness mode) + runtime `tools/test_cross_binary_tx_parity.sh` (shipped; 29/0) + edge runtime `tools/test_cross_binary_tx_parity_edge.sh` (shipped; 48/0, high-byte/`u64`-max + second/third wallet copy). Each carries a live negative control.
- **Threat.** A single-line drift in any copy silently breaks tx-signature interop *and* `tx_root` / inclusion-proof consistency; the two guards turn such a drift RED pre- and post-build.

---
