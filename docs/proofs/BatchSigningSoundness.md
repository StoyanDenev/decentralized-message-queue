# BatchSigningSoundness — per-transaction soundness of the batch wallet operations (BS-1..BS-4)

This document proves that Determ's **batch wallet operations** preserve per-transaction signing soundness: a batch sign / verify / import of `N` records is *exactly* `N` independent single-record operations, with no cross-record contamination, no per-record fault propagation, and no atomicity coupling beyond what the operator explicitly opted into. The subjects are three CLI commands on the `determ-wallet` binary, all shipped this session:

- **`determ-wallet tx-batch-sign`** (`cmd_tx_batch_sign`, `wallet/main.cpp:9609-10271`) — signs a JSON array of `N` tx-input records under one loaded key, emitting `N` signed envelopes in input order.
- **`determ-wallet account-import-many`** (`cmd_account_import_many`, `wallet/main.cpp:1847-2220`) — bulk-imports `N` accounts, each as an independent keyfile, with per-record fault isolation.
- **`determ-wallet verify-batch`** (sibling `cmd_verify_batch`, landing this round) — batch-verifies `N` signed envelopes, reporting per-envelope validity.

The thesis is a *compositional* one. Determ already has primitive-layer proofs for the single-record cryptographic operations: the per-tx Ed25519 signature is verified soundly under A1 (Ed25519 EUF-CMA), and the at-rest keyfile envelope under `EnvelopeKeyfileCrypto.md` (KE-1..KE-4) and `S004KeyfileAtRest.md` (T-1..T-5). What is *not* yet covered is the claim that wrapping those primitives in an `N`-element loop introduces no new attack surface — that the batch is a faithful `N`-fold replication of the single operation. That is the gap this document closes.

This is a **wallet-tooling soundness proof**, companion to the wallet-recovery flow proofs (`WalletRecoveryFlows.md`) and the envelope-crypto proofs (`EnvelopeKeyfileCrypto.md` / `S004KeyfileAtRest.md`). It modifies no source; it adds analytic coverage only.

---

## 1. Scope

**In scope.** The three batch wallet operations, treated as **compositions of the single-record primitives**:

- `tx-batch-sign` as an `N`-fold composition of the single-tx sign primitive (the same canonical `signing_bytes` encoder + Ed25519 `crypto_sign_detached` that `sign-anon-tx` / `tx-sign-verify` / `cold-sign` use).
- `account-import-many` as an `N`-fold composition of the single-record account-import primitive (seed → Ed25519 keypair → address-derivation → independent `DWE1`-envelope keyfile write).
- `verify-batch` as an `N`-fold composition of the single-tx verify primitive (`validate-tx`: structural + `signing_bytes` recompute + hash-match + Ed25519 `crypto_sign_verify_detached` under the `from`-derived pubkey).
- The four soundness properties BS-1 (batch = `N` independent singles), BS-2 (per-record fault isolation), BS-3 (verify-batch soundness), BS-4 (order + determinism).
- The composition of `account-import-many`'s encrypted path with the `DWE1` envelope primitive: each produced keyfile is an independent envelope, so `EnvelopeKeyfileCrypto.md` KE-1..KE-4 and `S004KeyfileAtRest.md` T-1..T-5 apply **per keyfile**. The keyfile decryption that feeds `tx-batch-sign`'s encrypted-keyfile path (`envelope::decrypt` at `wallet/main.cpp:9831`, AAD = header pubkey) is likewise covered by those companions; this document treats `envelope::encrypt` / `envelope::decrypt` as black boxes satisfying KE-1..KE-4 and reasons only about the loop structure that calls them.

**Out of scope.**

- **Breaking A1 / A2 (Ed25519 / SHA-256).** BS-1..BS-4 are conditional on the standard assumptions (§ below). A forged single signature, or a SHA-256 collision, is the single-primitive adversary's problem, covered by A1 / A2 and by `EnvelopeKeyfileCrypto.md`; the batch wrapper neither strengthens nor weakens those bounds.
- **The operator's own keyfile compromise.** If the adversary holds the operator's private seed (or the passphrase that unlocks an encrypted keyfile), it can forge arbitrary single signatures and the batch question is moot. Passphrase-strength is `EnvelopeKeyfileCrypto.md` KE-4 / F-policy territory; in-memory secret residency is `EnvelopeKeyfileCrypto.md` §5 / S-035 territory.
- **The chain-side admission of the produced envelopes.** Whether a signed envelope is *accepted* by a validator (nonce gating, balance, mempool admission, rate limiting) is the apply-layer / RPC-layer concern proven in `NonceMonotonicity.md` (FA-Apply-3), `RpcInputValidationDefense.md`, and `S014RateLimiterSoundness.md`. This document proves only that the batch produces envelopes that are *individually well-formed and soundly signed* — i.e. that a batch-signed envelope `e_i` is byte-identical to what a single `sign(t_i)` would produce, and therefore inherits whatever admission fate a single-signed envelope would have.
- **Process-level concurrency.** Each of the three commands is a single-threaded loop in a short-lived CLI process; there is no shared mutable state across processes and no thread-level interleaving inside the loop. The concurrency proofs (`S014ConcurrencyAnalysis.md`, `S031ConcurrencyComposition.md`) cover the daemon, not the wallet CLI.

---

## 2. Threat model

The batch operations defend against an adversary `A_batch` who **supplies a crafted batch** — a `--in` JSON array (for `tx-batch-sign` / `account-import-many`) or a set of signed envelopes (for `verify-batch`) — hoping to exploit the loop structure rather than the underlying crypto. `A_batch` controls the entire input array but does **not** hold the operator's key. Three concrete goals:

### 2.1 `A_xtalk` — cross-record contamination

`A_xtalk` crafts a batch hoping that record `i`'s output is influenced by record `j ≠ i`. Concrete sub-goals:

- **(a) Sign-side cross-talk.** Make `tx-batch-sign` produce an envelope `e_i` whose signature validates against a *different* record's content — e.g. by getting field bytes from `t_j` to leak into `t_i`'s `signing_bytes`. If the loop reused a buffer across iterations without clearing it, a short field in `t_i` followed by a long field in `t_j` could leave stale bytes in the hash pre-image.
- **(b) Verify-side cross-talk.** Make `verify-batch` report `e_i` valid because of something in `e_j` — e.g. by getting the verifier to check `e_i`'s signature against `e_j`'s pubkey, or to carry a "valid" verdict forward from a prior record.

The defense is **structural**: BS-1 (sign) and BS-3 (verify) show each iteration reads only the current record and writes only its own output slot; the sole cross-iteration state is the immutable loaded key and an append-only output array.

### 2.2 `A_fault` — fault propagation across records

`A_fault` crafts a batch where one record `i` is malformed (bad JSON shape, wrong-length privkey, non-canonical address, address/pubkey mismatch) hoping that the fault corrupts a *different*, well-formed record `j ≠ i` — e.g. by causing `j`'s keyfile to be written with `i`'s key material, or by aborting the whole batch so that a single bad row poisons thousands of good imports. The defense is BS-2 (per-record fault isolation) for `account-import-many`. (`tx-batch-sign` makes the opposite, equally-sound design choice — all-or-nothing — discussed in §6.)

### 2.3 `A_mutate` — post-sign envelope mutation

`A_mutate` takes a batch-produced envelope `e_i`, mutates its content (bumps `amount`, swaps `to`), and presents the result hoping the signature still validates or the stored `hash` still matches. This is the standard single-envelope tamper threat; the defense is A1 (the signature is over `signing_bytes`, so any body mutation invalidates it) composed with A2 (the `hash` field is checked against the recomputed `SHA256(signing_bytes)`). BS-3 confirms `verify-batch` inherits this per-envelope.

### 2.4 Out of scope

- Anything requiring `A_batch` to break A1 or A2 (see §1).
- An adversary who already holds the operator's key or passphrase (see §1).
- Denial of service via a gigantic `--in` array. The loop is `O(N)` in records and the per-record work is bounded; a `50k`-record batch is a documented, supported workload (the `account-import-many` loop comment at `wallet/main.cpp:1940-1941` explicitly cites the `N=50000` case). Memory pressure from an absurd array is an operator-resource concern, not a soundness defect.

---

## 3. The single-record primitive (ground truth)

The batch soundness theorems are stated *relative to* the single-record operations. This section pins down exactly what a single sign / verify guarantees, reading the shared encoder from the source.

### 3.1 Canonical `signing_bytes`

Every wallet command that signs or verifies a transaction builds the **same** canonical pre-image, byte-for-byte identical to `src/chain/block.cpp Transaction::signing_bytes`. The encoder appears verbatim in `sign-anon-tx` (`wallet/main.cpp:9424-9434`), `validate-tx` (`:10804-10814`), `derive-tx-hash` (`:11373-11384`), and the `tx-batch-sign` loop body (`:10183-10192`). The layout is:

```
signing_bytes(t) :=
    u8(type)                          // 1 byte: TxType enum value
  ‖ from_bytes ‖ 0x00                 // sender address string + NUL terminator
  ‖ to_bytes   ‖ 0x00                 // recipient address string + NUL terminator
  ‖ be_u64(amount)                    // 8 bytes big-endian
  ‖ be_u64(fee)                       // 8 bytes big-endian
  ‖ be_u64(nonce)                     // 8 bytes big-endian
  ‖ payload_bytes                     // variable (empty for TRANSFER / batch-mode txs)
```

The `sig` and `hash` fields are **excluded** from `signing_bytes` (they are the *output* of signing, not inputs to it). This is the standard sign-the-content-not-the-signature discipline.

### 3.2 The single sign primitive

A single sign (`sign-anon-tx`, `wallet/main.cpp:9438-9473`) computes:

1. `sb := signing_bytes(t)` from the tx fields.
2. `h := SHA256(sb)` (`:9438-9439`) — the canonical `tx_hash`, also `Transaction::compute_hash`.
3. `σ := crypto_sign_detached(sb, sk)` (`:9444`) — Ed25519 over `sb` under the loaded secret key.
4. Emit the envelope `{type, from, to, amount, fee, nonce, payload, sig := hex(σ), hash := hex(h)}` (`:9463-9473`).

**Single-sign guarantee.** Under A1, the emitted `σ` is a valid Ed25519 signature over `sb` and over nothing else; under A2, `h` is a binding commitment to `sb`. The signature binds the *exact* content `(type, from, to, amount, fee, nonce, payload)` and the holder of `sk`. RFC 8032 Ed25519 is **deterministic**: `σ` is a pure function of `(sb, sk)` with no randomness, so re-signing the same `(t, sk)` yields a byte-identical `σ`.

### 3.3 The single verify primitive

A single verify (`validate-tx`, `wallet/main.cpp:10511-...`) is a composite gate. Reading the source:

1. **Structural** (`:10615-10767`): parse and type-check every field; `sig`/`signature` must be 128 hex chars, `hash` 64 hex chars. A missing/malformed field flips `valid_structural := false`.
2. **`signing_bytes` recompute + hash-match** (`:10803-10849`): rebuild `sb` from the body fields using the §3.1 encoder, compute `SHA256(sb)`, and compare (case-insensitively) against the envelope's stored `hash` (`:10834-10848`). A mismatch is a *validity failure* — it means "the body was modified after signing, OR the encoder didn't re-hash before storing." This is the A2-backed binding check.
3. **Ed25519 verify** (`:10872-10907`): for an anon-address sender, derive the pubkey from the 64-hex tail of `from` (anon-address `= "0x" ‖ hex(ed_pub)`, `:10882-10888`), then `crypto_sign_verify_detached(σ, sb, pub)` (`:10896-10899`). `signature_verified := (rc == 0)`. For a domain-name sender (no in-wallet pubkey), the verify step is *skipped with a diagnostic* (`:10908-10913`) — domains require a chain-registry lookup the offline wallet does not have.

**Single-verify guarantee.** For an anon-address sender, `validate-tx` returns `overall_valid` iff (structural ∧ hash-match ∧ Ed25519-verify). Under A1, the Ed25519 step passes iff `σ` was produced by the holder of the seed whose pubkey is `from`'s tail, over the *exact* `sb` rebuilt from the body — so a forged or content-mutated envelope fails except with probability `≤ 2⁻¹²⁸`. Under A2, the hash-match step catches a stored-`hash` that disagrees with the body except with probability `≤ 2⁻¹²⁸`. The two checks are independent and both must pass.

The **homogeneous self-consistency** of the anon-address case is load-bearing for the batch: because the verifier *derives* the pubkey from each envelope's own `from` field, verifying `e_i` consults *only* `e_i` — there is no shared trust anchor across envelopes, hence no cross-envelope channel (see BS-3).

---

## 4. Soundness theorems

### Assumptions

The four theorems use the canonical assumption labels from `Preliminaries.md §2.0`:

- **(A1) Ed25519 EUF-CMA** — `Verify(pk, m, σ) = 1` implies the holder of `sk` signed `m`, except with probability `≤ 2⁻¹²⁸` (`Preliminaries.md §2.2`). The single-signature soundness primitive.
- **(A2) SHA-256 collision resistance** — finding `x ≠ y` with `SHA256(x) = SHA256(y)` is `≤ 2⁻¹²⁸` (`Preliminaries.md §2.1`). Underlies the `tx_hash` ↔ `signing_bytes` binding and the envelope `hash`-field check.
- **(A3) SHA-256 preimage / second-preimage resistance** — `≤ 2⁻²⁵⁶` (`Preliminaries.md §2.1`). Used transitively where the `hash` field commits to a fixed pre-image.
- **(A4) CSPRNG** — `RAND_bytes` output is computationally indistinguishable from uniform (`Preliminaries.md §2.3`). Used only by `account-import-many`'s encrypted path, via the `DWE1` envelope's per-keyfile salt + nonce draw (`EnvelopeKeyfileCrypto.md` KE-3, which rests on this).

These are exactly the assumptions the single-record primitives already rest on. BS-1..BS-4 add **no new cryptographic assumption** — they are structural reductions to the single-record case.

> Note on labels: this document uses **A2** for SHA-256 collision resistance per the `Preliminaries.md §2.0` legend. It does **not** use FA3 for SHA-256; `FA3` is the SelectiveAbort theorem (`SelectiveAbort.md`), an unrelated consensus property.

---

### BS-1 (Batch = N independent single signs)

**Statement.** Let `tx-batch-sign` be invoked on input array `[t_1, …, t_N]` with a loaded key `sk` (address `A`). The command either (i) emits an output array `[e_1, …, e_N]` where each `e_i` is **bit-identical** to the envelope a single `sign(t_i)` under `sk` would produce (modulo the envelope's `type`-field encoding convention, see remark below), or (ii) emits *nothing* and exits non-zero on the first invalid record. In case (i), there is **no cross-tx contamination**: `e_i` depends only on `t_i` and `sk`, never on any `t_j` or `e_j` for `j ≠ i`.

**Proof.** By reading the loop body at `wallet/main.cpp:10056-10232`. We establish three facts about the loop's state.

*Fact 1 — the only cross-iteration state is `(sk, out_arr)`.* Before the loop, the key is loaded exactly once: `crypto_sign_seed_keypair(pub, sk, priv_seed)` at `:10014`, after which `priv_seed` is immediately scrubbed (`:10025`). `sk` is **read-only** for the entire loop — no iteration writes to it — and is scrubbed exactly once *after* the loop at `:10234`. The output accumulator `out_arr` is initialised empty at `:10054` and is touched by exactly one statement inside the loop: `out_arr.push_back(std::move(envj))` at `:10231`. No iteration ever *reads* `out_arr`. The loop counter `idx` and `N := in_j.size()` (`:10055`) are the only other loop-scope state, and both are loop-control, not data.

*Fact 2 — every per-record datum is re-derived from `in_j[idx]` alone.* Inside the body, `rec := in_j[idx]` (`:10057`) is the current input record. Every field that feeds the signature is extracted from `rec`:
- `type_str := rec["type"]`, `tx_type_int := type_mnemonic_to_int(type_str)` (`:10108-10109`),
- `from_str := rec["from"]`, `to_str := rec["to"]` (`:10117-10118`),
- `amount`, `fee`, `nonce` from `rec["amount"]` / `rec["fee"]` / `rec["nonce"]` (`:10149-10157`).

These are all **fresh local `const` values** declared inside the loop body; none persists across iterations. There is no buffer that is allocated once and reused: the pre-image vector `sb` is a **fresh local** `std::vector<uint8_t>` declared at `:10183` *inside* the loop, constructed by a sequence of `push_back` / `insert` calls (`:10185-10192`) that append exactly the current record's fields. Because `sb` is constructed empty each iteration and only ever appended to, no stale bytes from `t_j` can survive into `t_i`'s pre-image — defeating `A_xtalk`(a) (the stale-buffer attack of §2.1).

*Fact 3 — the signature is over `sb` alone, under the immutable `sk`.* The signature is computed at `:10203` as `crypto_sign_detached(sig, &sig_len, sb.data(), sb.size(), sk.data())` — input is exactly the fresh `sb` and the read-only `sk`. The hash is `SHA256(sb)` at `:10198`, a fresh local `sb_sha`. The output envelope `envj` (`:10220-10230`) is assembled from the same current-record fields plus `hex(sig)` and `hex(sb_sha)`.

*Conclusion.* The map `idx ↦ e_idx` factors as `e_idx = f(t_idx, sk)` where `f` is precisely the single-sign primitive of §3.2 applied to `t_idx`: same encoder (§3.1, the `:10185-10192` calls are byte-identical to `sign-anon-tx`'s `:9426-9433`), same `crypto_sign_detached`, same envelope assembly. Since `sk` is identical across iterations and `f` is a pure function of `(t_idx, sk)`, we have `e_i ⟂ t_j` and `e_i ⟂ e_j` for all `j ≠ i`. Therefore the batch is an `N`-fold independent replication of the single sign, with **no cross-tx contamination**. ∎

**Corollary BS-1.1 (noninterference / permutation-covariance).** Because `e_i = f(t_i, sk)` depends on `t_i` alone, the batch map is *noninterfering* in the information-flow sense: for any two input arrays `T = [t_1..t_N]` and `T' = [t'_1..t'_N]` that agree at position `i` (`t_i = t'_i`), the outputs agree at position `i` (`e_i = e'_i`) whenever both batches reach case (i) (full emission). Equivalently, replacing record `j ≠ i` with arbitrary content — including adversarial content chosen by `A_xtalk` — leaves `e_i` unchanged. A direct consequence is **permutation-covariance**: signing a permuted input `π(T)` yields the permuted output `π([e_1..e_N])` (each envelope is unchanged, only its position moves), since `f` does not consult position. The sole coupling across positions is the *control* coupling of case (ii) — a fault at position `j` suppresses *all* output (the all-or-nothing abort of §6 R-3) — but this coupling cannot *alter* a `e_i` it does not suppress; it can only withhold the entire array. Noninterference on the emitted content is therefore exact. ∎

**Remark (type-field encoding).** `tx-batch-sign` emits the **numeric** `type` field (`{"type": tx_type_int, …}` at `:10221`), matching `Transaction::to_json`, whereas `sign-anon-tx` emits the **mnemonic** string (`{"type": "TRANSFER", …}` at `:9464`). This is a *presentation* difference in the JSON envelope, not a difference in the signed content: the `signing_bytes` first byte is `u8(tx_type_int)` in **both** cases (`:10185` vs `:9426`), so `σ` and `hash` are identical. `validate-tx` and `verify-batch` accept both `type` encodings interchangeably (`validate-tx` `:10670-10692`), so the envelopes are wire-equivalent. "Bit-identical" in the statement is therefore *modulo* this documented field-encoding convention; the *cryptographic* content (`signing_bytes`, `σ`, `hash`) is byte-identical.

**Remark (homogeneous-signer guard).** Each iteration also checks `from_str == keyfile_address` (`:10170`) and aborts the batch on mismatch. This is a fat-finger guard (§6), not a contamination vector: it reads only `rec["from"]` and the immutable `keyfile_address`, consistent with Fact 2.

---

### BS-2 (Per-record fault isolation)

**Statement.** In `account-import-many`, a malformed or invalid record `i` (non-object, missing/short `privkey_hex`, invalid hex, keypair-derivation failure, 64-byte-tail mismatch, address/pubkey mismatch, duplicate address, pre-existing output file, or write failure) is recorded with `status ∈ {"error", "skipped"}` and the loop **continues**, *without* aborting the batch and *without* corrupting any other record `j ≠ i`. Each keyfile write is independent.

**Proof.** By reading the loop body at `wallet/main.cpp:1946-2176`. The loop's explicit design contract is stated in the source comment at `:1937-1941`: *"each record produces exactly one summary entry … Failures DO NOT abort the loop — at N=50k a single malformed row mustn't invalidate 49,999 valid imports."* We verify the structural claims.

*Per-record locals are fresh each iteration.* Inside the body, `rec := arr[idx]` (`:1947`) and the extracted `address`, `priv_hex`, `name` (`:1953`) are loop-scope locals, re-declared every iteration. The derived material — `priv_bytes` (`:1989`), `seed` (`:2000`), `derived_pub` and `sk` (`:2002-2003`), `pubkey_hex` / `derived_addr` / `priv_seed_hex` (`:2031-2033`) — are all fresh locals, never carried across iterations. The secret-bearing buffers `seed` and `sk` are `sodium_memzero`'d on **every** exit edge of the iteration: the keypair-failure path (`:2006`), the tail-mismatch path (`:2021`), the address-mismatch path (`:2042`), the duplicate path (`:2063`), the file-exists path (`:2082`), and the normal post-write path (`:2149`); `sk` is additionally wiped at `:2014` immediately after derivation. No secret survives an iteration boundary.

*Every fault path is a `continue`, not a `return`.* Each validation failure pushes one summary entry and executes `continue` (`:1972, :1979, :1987, :1996, :2012, :2027, :2052, :2069, :2089, :2156`), advancing to the next record. There is **no `return` inside the loop body** on a per-record fault — the only early returns in the function are the *pre-loop* argument / IO / passphrase-resolution checks (`:1862-1935`) and the *post-loop* `--summary` write (`:2179-2202`). Hence a fault in record `i` cannot terminate the processing of records `j > i`, defeating `A_fault` (§2.2).

*The only cross-record state is monotone and append-only.* Across iterations the loop carries `summary` (a JSON array, only ever `push_back`'d), `seen_addresses` (a `std::set`, only ever `insert`'d at `:2071`), and the three counters `ok_count` / `skipped_count` / `error_count` (only ever incremented). None of these influences the *content* of any keyfile: the keyfile bytes for record `j` are a function of `(address_j, priv_seed_hex_j, passphrase)` only (`:2101-2147`). `seen_addresses` affects only the *control decision* of whether record `j` is written or skipped-as-duplicate (`:2062`) — a first-sighting-wins dedup that is itself a soundness *feature* (it prevents a later record from silently overwriting an earlier keyfile under the same filename; comment at `:2057-2061`), not a contamination channel.

*Each keyfile write is independent.* For the encrypted path (`:2095-2127`), each record builds its own canonical `{pubkey, priv_seed}` plaintext (`:2101-2104`) and calls `envelope::encrypt(pt_bytes, passphrase, aad)` at `:2109` with `aad := pubkey_hex_j` (`:2107`). By `EnvelopeKeyfileCrypto.md` KE-3, **each** `encrypt` invocation draws a *fresh* 16-byte salt and 12-byte nonce from `RAND_bytes` (under A4), so the `N` keyfiles are `N` independent `DWE1` envelopes with independent keys even at a shared passphrase — no envelope is derivable from another. The header (`DETERM-NODE-V1 ‖ pubkey_hex_j`) and AAD bind each envelope to *its own* pubkey, so by KE-2 (AAD coverage) no envelope can be grafted under another record's header. The plaintext path (`:2128-2147`) writes a self-contained `{address, privkey_hex}` JSON per record. In both paths the output path is `out_dir / (name|address).keyfile` (`:2078-2079`), a per-record filename derived from that record's own fields.

*Conclusion.* Record `i`'s fault is confined to record `i`'s summary entry; record `j`'s keyfile content and write outcome are functions of `j`'s own input and the shared (read-only) passphrase, never of `i`. The batch import is `N` independent single-imports with per-record fault isolation. ∎

**Contrast with BS-1.** `account-import-many` is **fault-isolating** (one bad row is skipped, the rest succeed) because its records are independent custodial accounts where partial success is the desired semantics. `tx-batch-sign` is **all-or-nothing** (any invalid record aborts the whole batch with no output; the `return` statements at `:10059, :10073, …` inside its loop) because a payroll/airdrop operator wants to fix the bad row and re-sign the *whole* batch rather than ship a partial run. Both are sound: in *neither* case does a fault in record `i` corrupt the *content* of record `j`. The difference is only in the control-flow response to a fault (continue vs. abort-with-no-output), which is a deliberate per-command UX choice, not a soundness property.

---

### BS-3 (verify-batch soundness)

**Statement.** Let `verify-batch` be invoked on signed envelopes `[e_1, …, e_N]`. For each `i`, `verify-batch` reports `e_i` as valid **iff** a single `validate-tx`(`e_i`) would report it valid. In particular, for an anon-address sender:

- (soundness) if `verify-batch` reports `e_i` valid, then under A1 the holder of the seed behind `e_i.from` signed exactly `e_i`'s content, and under A2 `e_i.hash` commits to that content — a forged or mutated envelope is reported valid with probability `≤ 2⁻¹²⁸`;
- (no cross-talk) the verdict for `e_i` consults *only* `e_i`; it never reads `e_j` for `j ≠ i`.

**Proof.** `verify-batch` (`cmd_verify_batch`, sibling D2 landing this round) is the batch analogue of `validate-tx` (§3.3): it parses the input as a JSON array and applies the single-envelope verify gate to each element, accumulating a per-envelope verdict array. The soundness reduction is in two parts.

*Part 1 — per-envelope soundness inherits from `validate-tx`.* For each `e_i`, the verify gate is exactly the §3.3 composite: structural ∧ (`SHA256(signing_bytes(e_i)) == e_i.hash`) ∧ (`crypto_sign_verify_detached(σ_i, signing_bytes(e_i), pub_i) == 0`), where `pub_i` is derived from `e_i.from`'s 64-hex tail. By the single-verify guarantee (§3.3): under A1, the Ed25519 step accepts a `σ_i` not produced over `signing_bytes(e_i)` by the holder of `sk_i` with probability `≤ 2⁻¹²⁸`; under A2, the hash-match step accepts an `e_i.hash` that disagrees with the recomputed pre-image with probability `≤ 2⁻¹²⁸`. So `A_mutate` (§2.3) — bumping `amount`, swapping `to` — breaks *both* the Ed25519 step (the sig no longer matches the mutated `signing_bytes`) and the hash-match step (the stored `hash` no longer matches the recomputed `SHA256(signing_bytes)`), and is caught except with probability `≤ 2⁻¹²⁸`.

*Part 2 — no cross-envelope channel.* The verifier derives the verification pubkey **from each envelope's own `from` field** (§3.3, `validate-tx:10882-10888`) — there is no shared trust anchor, no key cached from a prior envelope, no registry consulted. The `signing_bytes` for `e_i` is rebuilt from `e_i`'s own body fields (`validate-tx:10804-10814`), and the hash-match compares against `e_i`'s own stored `hash` (`:10834-10848`). The per-envelope verdict is therefore a pure function `verdict_i = g(e_i)` of the single envelope, identical to `validate-tx`(`e_i`). The batch verdict array is `[g(e_1), …, g(e_N)]` — `N` independent evaluations. Hence `A_xtalk`(b) (§2.1) has no channel: verifying `e_i` against `e_j`'s key, or carrying a verdict forward, would require the verifier to read `e_j` while computing `verdict_i`, which it provably does not. ∎

**Composition with hash-binding (A2).** The envelope's `hash` field is *not* merely informational — `validate-tx` (and hence `verify-batch`) treats a hash-mismatch as a **validity failure** (`:10842-10848`, comment: "envelope body was modified after signing OR encoder didn't re-hash before storing"). This closes the hash-substitution sub-attack: an adversary who keeps a genuine `σ` but swaps the advertised `hash` to commit to a *different* pre-image is caught, because the verifier recomputes `SHA256(signing_bytes)` from the *body* and compares — and by A2 cannot find a second pre-image that both (a) matches the swapped `hash` and (b) verifies under the genuine `σ`. The Ed25519 step (over `signing_bytes`) and the hash-match step (over `SHA256(signing_bytes)`) are mutually reinforcing.

**Note on `verify-batch` landing status.** As of this worktree, `cmd_verify_batch` is the D2 deliverable landing in this same round (R40); BS-3 is stated against the documented `verify-batch` contract — *"batch-verify `N` envelopes = `N` independent `validate-tx` operations"* — and the `validate-tx` ground truth (§3.3) that the sibling composes. The reduction is purely structural and does not depend on `verify-batch`'s internal loop mechanics beyond the per-element-independence that the contract specifies; when the sibling lands, the §7 cross-reference resolves to its line range and `tools/test_wallet_verify_batch.sh`.

---

### BS-4 (Order + determinism)

**Statement.**
1. **(Positional correspondence)** `tx-batch-sign` output array satisfies `output[i] ↔ input[i]` — the `i`-th emitted envelope corresponds to the `i`-th input record, in input order.
2. **(Sign determinism)** Same input array + same key ⟹ **byte-identical** batch output. There is no randomness in the sign path: Ed25519 signing is deterministic per RFC 8032.
3. **(Import filename/address determinism)** `account-import-many`'s **plaintext** output is byte-identical across runs for the same input, and in *all* modes the produced keyfile **filenames** and **recovered addresses** are identical across runs; but the **encrypted** keyfile bytes are *not* byte-identical across runs (fresh salt + nonce per `EnvelopeKeyfileCrypto.md` KE-3).

**Proof.**

*(1) Positional correspondence.* The `tx-batch-sign` loop iterates `idx` from `0` to `N-1` over `in_j[idx]` (`:10056`) and appends exactly one envelope per iteration via `out_arr.push_back` (`:10231`). `push_back` appends in call order, and the loop visits `idx` in increasing order, so `out_arr[idx]` is the envelope for `in_j[idx]`. The source comment at `:10042-10043` ("Build the output array in INPUT ORDER") states the intent; the `for`-loop + `push_back` structure enforces it. ∎(1)

*(2) Sign determinism.* By BS-1, `e_i = f(t_i, sk)` where `f` is the single-sign primitive. RFC 8032 Ed25519 derives the per-signature nonce deterministically from the secret key and message (`r := SHA512(prefix ‖ M)`), so `crypto_sign_detached(sb, sk)` is a **pure deterministic function** of `(sb, sk)` — no `RAND_bytes`, no system entropy, no timestamp enters the signature. `SHA256(sb)` is likewise deterministic. The output JSON is dumped compactly via `out_arr.dump()` (`:10240`); for a fixed key-set per envelope, nlohmann's dump is byte-stable. Therefore, for fixed `([t_1..t_N], sk)`, the entire output file is byte-identical across runs. The source contract is stated at `:9599` and in the `--help` text (`:9655-9656`: "same input + same keyfile → byte-identical output"); the test wrapper asserts it directly (`tools/test_wallet_tx_batch_sign.sh:241`, "output files byte-identical across runs"). ∎(2)

*(3) Import determinism split.* `account-import-many`'s **filename** is `(name|address).keyfile` (`:2078`), a deterministic function of the record's own fields, and the **recovered address** is `derived_addr := "0x" ‖ hex(ed_pub)` where `ed_pub := crypto_sign_ed25519_seed_keypair(seed)` (`:2004, :2032`) — a deterministic function of the seed. So filenames and addresses reproduce exactly across runs. The **plaintext** keyfile body is `{address, privkey_hex}` (`:2131-2134`), also deterministic. But the **encrypted** keyfile body is `serialize(encrypt(pt, passphrase, aad))` (`:2109-2110`), and by `EnvelopeKeyfileCrypto.md` KE-3 each `encrypt` draws a fresh salt + nonce (under A4) — so two runs produce *different* ciphertext bytes for the same plaintext, **by design** (this is precisely what defeats rainbow-table / cross-corpus precomputation amortization; KE-3). The decrypted plaintext, the recovered pubkey, and the address are nonetheless identical. The test wrapper encodes exactly this split (`tools/test_wallet_account_import_many.sh:21-24`: "same filenames + summary structure byte-equal (excluding envelope ciphertext which differs by design due to per-keyfile salt+nonce)"). ∎(3)

---

### Theorem → fact → assumption map

| Theorem | Property | Rests on | Bound / guarantee |
|---|---|---|---|
| BS-1 | Batch sign = `N` independent singles; no cross-tx contamination | Loop structure (`:10056-10232`) + single-sign primitive (§3.2) + A1 | Structural (exact); per-tx soundness `≤ 2⁻¹²⁸` (A1) |
| BS-2 | Per-record fault isolation in import | Loop structure (`:1946-2176`, `continue`-not-`return`) + KE-3 per-keyfile salt/nonce | Structural (exact); independent envelopes (A4 via KE-3) |
| BS-3 | verify-batch = `N` independent `validate-tx`; no cross-talk | Verify primitive (§3.3) + A1 + A2 | Forged/mutated envelope accepted `≤ 2⁻¹²⁸` |
| BS-4 | Order + determinism | `push_back`-in-order + RFC 8032 deterministic Ed25519 + KE-3 | Sign output byte-identical; encrypted import non-deterministic by design |

### Adversary-coverage matrix

| Threat | In scope? | Defense | Residual |
|---|---|---|---|
| `A_xtalk`(a): stale-buffer sign-side cross-talk (record `j` bytes leak into `e_i`) | yes | BS-1 — fresh per-iteration `sb` (`:10183`), only-append construction; `e_i = f(t_i, sk)` | none (structural) |
| `A_xtalk`(b): verify-side cross-talk (`e_i` validated against `e_j`'s key / carried verdict) | yes | BS-3 Part 2 — pubkey derived from each envelope's own `from`; `verdict_i = g(e_i)` | none (structural) |
| `A_fault`: one malformed record corrupts another record's keyfile / aborts the batch | yes | BS-2 — per-record `continue` (never `return`-in-loop); fresh per-record locals; independent envelopes | none for import; `tx-batch-sign` aborts-all by design (§6 R-3) |
| `A_mutate`: post-sign body mutation (bump `amount`, swap `to`) still verifies | yes | BS-3 — A1 over `signing_bytes` + A2 hash-match; both break under mutation | detected w.p. `≥ 1−2⁻¹²⁸` |
| `A_mutate'`: hash-field substitution (keep genuine `σ`, swap advertised `hash`) | yes | BS-3 composition with A2 — verifier recomputes `SHA256(signing_bytes)` from body | detected w.p. `≥ 1−2⁻¹²⁸` |
| Cross-keyfile leakage via shared passphrase in bulk import | yes | BS-2 + KE-3 — per-keyfile fresh salt/nonce; independent keys at fixed passphrase | none (KE-3 cross-corpus) |
| Wrong-signer batch (operator loads wrong keyfile) | yes | R-1 homogeneous-signer guard (`from == keyfile_address`, `:10170`) | UX guard; envelope would be invalid anyway |
| Forging a single signature without the key | no (§1) | A1 Ed25519 EUF-CMA (single-primitive concern) | covered by A1; out of batch scope |
| Operator key / passphrase compromise | no (§1) | by design the key signs (KE-4 / F-policy entropy) | operator failure; no batch mitigation |
| Live-memory read while secret resident | no (§2.4) | §6 R-6 `sodium_memzero` *bounds* residency only | OS-hardening / S-035 (`EnvelopeKeyfileCrypto.md §2.3`) |
| On-chain double-spend / non-atomic partial submission | no (§6 R-2) | each tx independent; `COMPOSABLE_BATCH` is the atomic alternative | apply-layer nonce gate (FA-Apply-3) |

---

## 5. Composition

**BS-1 + BS-3 round-trip.** A batch signed by `tx-batch-sign` and then verified by `verify-batch` round-trips soundly. By BS-1, each `e_i` is byte-identical (modulo §4 type-field convention) to a single `sign(t_i)`. By BS-3, `verify-batch` reports `e_i` valid iff `validate-tx`(`e_i`) would. Since a single `sign(t_i)` produces an envelope that a single `validate-tx` accepts (the signature is over `signing_bytes(t_i)` under the loaded key whose pubkey is `t_i.from`'s tail — the homogeneous-signer guard `:10170` guarantees `from == A`, and `A`'s pubkey is the verification key), the composition `verify-batch ∘ tx-batch-sign` reports **every** `e_i` valid. Conversely, by BS-3 soundness, if `verify-batch` reports `e_i` valid then `e_i` carries a genuine signature over its content — so the round-trip neither produces false-invalids (completeness) nor accepts forgeries (soundness), each per-tx and independently.

**`account-import-many` ∘ `DWE1` envelope.** By BS-2, each produced keyfile is an independent envelope. Each encrypted keyfile is a `DETERM-NODE-V1`-headered `DWE1` blob (`:2116-2117`) satisfying `EnvelopeKeyfileCrypto.md` KE-1..KE-4 (confidentiality, integrity, salt-independence, passphrase-dominance) and `S004KeyfileAtRest.md` T-1..T-5 (the application-layer node-keyfile contract, including pubkey-as-AAD header-substitution defense). The batch therefore inherits the full at-rest security of the single keyfile, *per keyfile*, with no cross-keyfile leakage (KE-3 salt-independence is exactly the cross-corpus guarantee). A keyfile produced by `account-import-many --passphrase-env X` is byte-format-identical to one produced by `keyfile-create` and decrypts via the same `keyfile-decrypt` / `tx-batch-sign --passphrase-env` path (the `envelope::decrypt` at `tx-batch-sign:9831` with AAD = header pubkey) — closing the loop: a batch-imported encrypted keyfile can feed a batch-sign run, both composing soundly through the same envelope primitive.

**Regression coverage (the empirical witness).** The structural claims are exercised end-to-end by the wallet test wrappers:

- `tools/test_wallet_tx_batch_sign.sh` (**38 assertions**) — covers BS-1 (single-tx sig validates via `validate-tx`; three-tx batch each validates *independently* — assertions B/C), BS-3 round-trip (each batch envelope fed back through `validate-tx`), BS-4 (order preservation via distinct per-tx amounts read back in order — assertion D; byte-identical output across runs — assertion E / line 241), and the encrypted-keyfile path (assertion F, `--passphrase-env DETERM_PASSPHRASE`).
- `tools/test_wallet_account_import_many.sh` (**30 assertions**) — covers BS-2 (duplicate → "skipped" with reason; invalid privkey → "error" *while other records still succeed* — assertions 5/6; address-mismatch → error — assertion 10; per-record summary entries — assertion 9), BS-4 import-determinism split (same filenames + summary byte-equal *excluding* ciphertext — assertion 8), and the encrypted-keyfile round-trip (wrong vs. right passphrase — assertion 7).
- `tools/test_wallet_verify_batch.sh` (sibling D2, landing this round) — covers BS-3 (batch-verify of mixed valid/invalid envelopes; per-envelope verdict matches single `validate-tx`).

These are *witnesses*, not proofs: the proofs are the structural reductions in §4; the tests confirm the implementation at the cited line ranges matches the structural claims.

---

## 6. Residual notes

**(R-1) Homogeneous-signer constraint is a guard, not a soundness property.** `tx-batch-sign` requires every input record's `from` to equal the loaded keyfile's address (`:10170-10179`), aborting the batch on the first mismatch. This is a **fat-finger guard** — it prevents an operator from accidentally batching txs from accounts whose keys they did not load (which would produce signatures that fail to verify under the stated sender). It is *not* a contamination defense: even without it, BS-1 would still hold (each `e_i` would still be `f(t_i, sk)`), but the resulting envelope would simply be invalid (signed by `sk` while claiming sender `from_i ≠ A`). The guard converts a silent operator error into a clean abort. An operator signing for multiple accounts runs `tx-batch-sign` once per keyfile (comment at `:10168-10169`).

**(R-2) No atomicity across the batch.** Neither command is a *transaction* in the database sense. `tx-batch-sign` produces `N` independent signed envelopes; the operator may submit any subset, and the chain admits each independently (subject to per-account nonce ordering — `NonceMonotonicity.md` FA-Apply-3). Partial submission is possible and *expected* (e.g. a payroll run where some recipients' txs land in block `h` and others in `h+1`). There is no all-or-nothing on-chain settlement guarantee from the batch tool — that would require a `COMPOSABLE_BATCH` tx (TxType 8), a *different* construction with its own apply-layer atomicity proof. `account-import-many` similarly produces `N` independent keyfiles; a crash mid-loop leaves the already-written keyfiles intact (each is `fsync`-free but self-contained) and the rest unwritten. This is the correct semantics for both use cases and is **orthogonal** to BS-1..BS-4 (which are per-record soundness, not cross-record atomicity).

**(R-3) `tx-batch-sign` all-or-nothing vs. `account-import-many` fault-isolation.** As noted in BS-2's contrast: the two commands respond to a per-record fault differently (abort-with-no-output vs. skip-and-continue). This is a deliberate, documented UX divergence keyed to the use case, not an inconsistency. Both preserve per-record content independence; only the control-flow response differs.

**(R-4) Empty-batch edge case.** Both commands handle `N = 0` cleanly: `tx-batch-sign` on an empty `--in` array emits an empty `--out` array and exits 0 (`--help` text `:9658`; test assertion A); `account-import-many` on `[]` produces no keyfiles and an empty summary (test assertion 2). The `N`-fold composition degenerates correctly to the `0`-fold (identity) case.

**(R-5) Negative-integer guard.** `tx-batch-sign` rejects negative `amount` / `fee` / `nonce` with a clean diagnostic (`:10122-10148`) rather than silently casting to a huge `u64`. This is an input-hygiene check feeding the `u64` `signing_bytes` encoder; it is per-record (reads only `rec`) and consistent with BS-1's Fact 2. A `TRANSFER` with `amount == 0` is also rejected (chain rule, `:10160-10165`).

**(R-6) Secret-zeroization discipline carries into the batch.** Both commands `sodium_memzero` the loaded secret on **every** exit edge — `tx-batch-sign` scrubs `sk` on each in-loop abort (`:10059, :10066, …`) and once after the loop (`:10234`); `account-import-many` scrubs `seed` / `sk` on every per-record edge (enumerated in BS-2's proof). This is the same in-memory discipline `EnvelopeKeyfileCrypto.md §5` documents for the single-record commands, extended unchanged across the loop. It *bounds* (does not eliminate) the in-memory residency window — the same out-of-scope caveat as the single-record case (live-memory adversary, `EnvelopeKeyfileCrypto.md §2.3`).

---

## 7. Implementation cross-references

| Surface | Location | Role |
|---|---|---|
| `tx-batch-sign` command | `wallet/main.cpp:9609-10271` | Batch sign entry; arg parse, keyfile load (plaintext + encrypted), per-record signing loop |
| `tx-batch-sign` signing loop | `wallet/main.cpp:10056-10232` | **BS-1 core** — fresh `sb` per iteration (`:10183`), single `crypto_sign_detached` (`:10203`), `push_back` in input order (`:10231`); only cross-iter state is read-only `sk` + append-only `out_arr` |
| `tx-batch-sign` `signing_bytes` build | `wallet/main.cpp:10185-10192` | Byte-identical to §3.1 encoder; first byte `u8(tx_type_int)` |
| `tx-batch-sign` encrypted-keyfile decrypt | `wallet/main.cpp:9823-9890` | `envelope::deserialize` + `envelope::decrypt` (AAD = header pubkey `:9829-9831`); composes with `EnvelopeKeyfileCrypto.md` KE-1..KE-4 |
| `tx-batch-sign` homogeneous-signer guard | `wallet/main.cpp:10170-10179` | R-1 fat-finger guard (`from == keyfile_address`) |
| `tx-batch-sign` key scrub | `wallet/main.cpp:10025, 10234` (+ per-abort `:10059…`) | R-6 secret-zeroization on every edge |
| `account-import-many` command | `wallet/main.cpp:1847-2220` | Bulk import entry; passphrase resolve, out-dir validate, per-record import loop |
| `account-import-many` import loop | `wallet/main.cpp:1946-2176` | **BS-2 core** — per-record `continue` (`:1972…2156`), fresh per-record locals, append-only `summary`/`seen_addresses`/counters |
| `account-import-many` fault-isolation contract | `wallet/main.cpp:1937-1941` | Source comment: "Failures DO NOT abort the loop … N=50k a single malformed row mustn't invalidate 49,999 valid imports" |
| `account-import-many` encrypted write | `wallet/main.cpp:2095-2127` | Per-record `envelope::encrypt` (fresh salt+nonce per KE-3), `DETERM-NODE-V1` header + DWE1 blob |
| `account-import-many` address derivation | `wallet/main.cpp:2004, 2031-2032` | `crypto_sign_ed25519_seed_keypair` → `derived_addr` (BS-4 deterministic) |
| `account-import-many` dedup + key scrub | `wallet/main.cpp:2062-2071`; `:2014, 2149` (+ per-edge) | First-sighting-wins dedup; `seed`/`sk` zeroized every edge |
| `sign-anon-tx` (single-sign ground truth) | `wallet/main.cpp:9110-9524` (encoder `:9424-9473`) | §3.2 single-sign primitive the batch replicates |
| `validate-tx` (single-verify ground truth) | `wallet/main.cpp:10511-...` (verify `:10803-10907`) | §3.3 single-verify primitive `verify-batch` replicates; structural + hash-match + Ed25519 |
| `derive-tx-hash` (shared encoder witness) | `wallet/main.cpp:11170-11435` (encoder `:11373-11387`) | Third independent copy of the §3.1 encoder; confirms byte-identity |
| `verify-batch` command | `cmd_verify_batch` (sibling D2, landing R40) | **BS-3 core** — `N`-fold `validate-tx`; per-envelope verdict, no cross-envelope channel |
| Batch-sign regression | `tools/test_wallet_tx_batch_sign.sh` (38 assertions) | BS-1 (independent per-tx validate), BS-3 round-trip, BS-4 order + byte-identical output, encrypted path |
| Bulk-import regression | `tools/test_wallet_account_import_many.sh` (30 assertions) | BS-2 (skip/error while others succeed), BS-4 import-determinism split, encrypted round-trip |
| Verify-batch regression | `tools/test_wallet_verify_batch.sh` (sibling D2, landing R40) | BS-3 (per-envelope verdict matches single `validate-tx`) |

**Companion proofs.**

- `EnvelopeKeyfileCrypto.md` (KE-1..KE-4) — the `DWE1` envelope primitive each `account-import-many` keyfile is, and the AAD-bound blob `tx-batch-sign`'s encrypted-keyfile path decrypts. BS-2's per-keyfile independence rests on KE-3 (per-envelope salt); BS-4's encrypted-non-determinism is exactly KE-3's freshness.
- `S004KeyfileAtRest.md` (T-1..T-5) — the application-layer node-keyfile-at-rest contract (PBKDF2 brute-force bound, AAD header-substitution defense, disk-theft confidentiality). Each batch-produced encrypted keyfile satisfies T-1..T-5 per keyfile.
- `WalletRecoveryFlows.md` (T-1..T-5) — sibling wallet-CLI flow proofs (Shamir / keyfile-recover / account-recover idempotence + determinism). Same compositional style; BS-4's determinism claim parallels WalletRecoveryFlows T-5 (cross-recovery determinism).
- `Preliminaries.md §2.0` — the canonical A1 / A2 / A3 / A4 assumption labels used throughout.

---

## 8. Status

**Specification complete.** BS-1 (batch = `N` independent single signs; no cross-tx contamination), BS-2 (per-record fault isolation in bulk import), BS-3 (verify-batch = `N` independent `validate-tx`, no cross-envelope channel), and BS-4 (positional correspondence + sign determinism + import-determinism split) are stated and proved as structural reductions to the single-record primitives (§3), conditional on the standard assumptions A1 (Ed25519 EUF-CMA) and A2 (SHA-256 collision resistance), with A4 (CSPRNG) entering only through the `DWE1` envelope's per-keyfile salt/nonce (KE-3). The proofs add **no new cryptographic assumption** beyond those the single-record commands already rest on.

**Implementations shipped.** `tx-batch-sign` (`cmd_tx_batch_sign`, `wallet/main.cpp:9609-10271`) and `account-import-many` (`cmd_account_import_many`, `wallet/main.cpp:1847-2220`) are live on this branch. `verify-batch` (`cmd_verify_batch`) is the sibling D2 deliverable landing in this same round (R40); BS-3 is stated against its documented contract and the `validate-tx` ground truth, and resolves to its line range + `tools/test_wallet_verify_batch.sh` on landing.

**Regression tests passing.** `tools/test_wallet_tx_batch_sign.sh` (38 assertions) and `tools/test_wallet_account_import_many.sh` (30 assertions) exercise the structural claims end-to-end — independent per-tx validation, order preservation, byte-identical sign output, per-record fault isolation, the encrypted-keyfile round-trip, and the encrypted-output-non-determinism-by-design split. `tools/test_wallet_verify_batch.sh` lands with the D2 sibling.

**Residuals (advisory, §6).** R-1 (homogeneous-signer guard is a fat-finger guard, not a soundness property), R-2 (no on-chain atomicity across the batch — each tx/keyfile is independent; `COMPOSABLE_BATCH` is the atomic alternative), R-3 (the deliberate all-or-nothing vs. fault-isolation UX divergence between the two commands), R-4 (empty-batch degeneracy), R-5 (negative-integer input hygiene), R-6 (secret-zeroization discipline carried unchanged into the loop; bounds-not-eliminates in-memory residency per `EnvelopeKeyfileCrypto.md §2.3`). None invalidates BS-1..BS-4. This document adds analytic coverage only; it modifies no source.

---

## 9. References

### Specifications and standards

- **RFC 8032** (Josefsson, Liusvaara, 2017) — Edwards-Curve Digital Signature Algorithm (EdDSA). §5.1.6 pins the *deterministic* nonce derivation that makes Ed25519 signing a pure function of `(message, secret key)` — the basis for BS-4's byte-identical-output claim. §5.1.7 the low-order-point rejection assumed by A1.
- **NIST FIPS 180-4** (2015) — Secure Hash Standard (SHA-256). The `signing_bytes` → `tx_hash` hash and the envelope `hash`-field commitment (A2 / A3).
- **RFC 8259** (Bray, 2017) — the JSON interchange format; the `--in` / `--out` / summary array wire shape.

### Determ-internal

- `wallet/main.cpp` — `cmd_tx_batch_sign` (`:9609-10271`), `cmd_account_import_many` (`:1847-2220`), the single-record `cmd_sign_anon_tx` (`:9110-9524`) / `cmd_validate_tx` (`:10511-…`) / `cmd_derive_tx_hash` (`:11170-11435`) primitives the batch ops replicate, and `cmd_verify_batch` (sibling D2, landing R40).
- `src/chain/block.cpp` — `Transaction::signing_bytes` / `Transaction::compute_hash` / `Transaction::to_json`, the canonical encoder + envelope shape the wallet commands mirror byte-for-byte (§3.1).
- `wallet/envelope.cpp`, `wallet/envelope.hpp` — the `DWE1` envelope primitive (`encrypt` / `decrypt` / `serialize` / `deserialize`) each bulk-imported keyfile is; the per-keyfile salt/nonce draw (KE-3) underlying BS-2's independence and BS-4's encrypted-non-determinism.
- `docs/proofs/EnvelopeKeyfileCrypto.md` (KE-1..KE-4) — the envelope-primitive companion; the at-rest contract each keyfile satisfies.
- `docs/proofs/S004KeyfileAtRest.md` (T-1..T-5) — the application-layer node-keyfile-at-rest companion.
- `docs/proofs/WalletRecoveryFlows.md` (T-1..T-5) — sibling wallet-CLI flow proofs (Shamir / recover idempotence + determinism); BS-4's determinism parallels its T-5.
- `docs/proofs/Preliminaries.md` (F0) §2.0 (canonical assumption labels), §2.1 (SHA-256 — A2/A3), §2.2 (Ed25519 EUF-CMA — A1), §2.3 (CSPRNG — A4).
- `tools/test_wallet_tx_batch_sign.sh`, `tools/test_wallet_account_import_many.sh`, `tools/test_wallet_verify_batch.sh` — the regression witnesses.

### Cryptographic literature

- **Brendel, Cremers, Jackson, Zhao** (USENIX Security 2021) — "The Provable Security of Ed25519: Theory and Practice." The EUF-CMA basis for A1, including the multi-user / batched-verification setting relevant to BS-3.
- **Bellare, Rogaway** — "Introduction to Modern Cryptography," §5.3 (collision resistance) — textbook basis for A2.
