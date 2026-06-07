# ParamChangeVerifySoundness — OFFLINE reimplementation of the PARAM_CHANGE K-of-K multisig gate (`determ-wallet param-change-verify`)

This document proves the soundness of the `determ-wallet param-change-verify` subcommand: a **read-only, fully OFFLINE** verifier that an operator runs against one assembled PARAM_CHANGE transaction JSON plus an operator-supplied keyholder-pubkey set, to obtain a PASS/FAIL verdict over the **A5 governance multisig gate** the daemon enforces in `src/node/validator.cpp:688-725`. A PASS asserts that the on-chain validator's PARAM_CHANGE signature gate **would accept** the assembled multisig — i.e. the wallet faithfully reimplements the validator check — **modulo the keyholder pubkey set + threshold**, which are on-chain governance state (`param_keyholders_`, `param_threshold_`) not carried in the transaction and therefore supplied by the operator. That single dependency is the sole trust boundary (§5 F-PCV1), stated precisely rather than papered over.

The proof's posture mirrors `OfflineBlockVerifySoundness.md` (the wallet `block-verify` sibling) and `LightVerifyChainFileSoundness.md` (the offline file verifier): `param-change-verify` is **a faithful reimplementation of one already-grounded consensus check**, not a new cryptographic construction. It introduces no signing capability — it verifies signatures it is given, never produces them (§5 F-PCV4). Its soundness reduces to four claims, each proved as a theorem below: (PCV-1) **byte-equivalence** of the `sig_msg` the wallet rebuilds against the bytes the validator builds; (PCV-2) **Ed25519 verification soundness** — under A1, a PASS means each *present* signature genuinely signs that `sig_msg` under the claimed keyholder key; (PCV-3) the **distinct-index + in-range + threshold** semantics match the validator's; and (PCV-4) the **honest read-only boundary** — the keyholder set and threshold are operator-supplied, and `verify` is a witness, never a signer.

**The load-bearing design fact (TCB separation).** `determ-wallet` does not link `libdeterm_chain`. Consequently the PARAM_CHANGE payload decode, the canonical `sig_msg` assembly, and the per-keyholder Ed25519 gate are **reimplemented inline** in `wallet/main.cpp` (`cmd_param_change_verify`, `wallet/main.cpp:23382-23545`) over `nlohmann::json` + `from_hex` + libsodium `crypto_sign_verify_detached`, rather than called from the chain library. PCV-1 proves the `sig_msg` reimplementation is **byte-identical** to the validator's assembly (`src/node/validator.cpp:693-701`), so the message each signature is checked against is exactly the one the validator checks. PCV-2 proves the per-signer verify is sound under A1. This is the *cost* of the wallet's lean TCB, paid as a stated trust boundary (the keyholder set / threshold the validator reads from on-chain state, §5 F-PCV1), not a hidden assumption.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (`Preliminaries.md §2.2`), **A2** = SHA-256 collision resistance (`Preliminaries.md §2.1`), **A3** = SHA-256 preimage / second-preimage resistance (`Preliminaries.md §2.1`). `param-change-verify` reduces to **A1** alone for the cryptographic core (the per-keyholder signature check); the decode + `sig_msg` assembly + threshold arithmetic are deterministic parsing with no cryptographic term (A2/A3 are *not* used — the gate signs a flat length-prefixed tuple, not a hash). The "A1 unitary-supply invariant" of the apply-layer proofs is an accounting identity unrelated to assumption A1; this document uses "A1" exclusively for Ed25519 EUF-CMA, since no supply identity appears here.

**Companion documents.**
- `OfflineBlockVerifySoundness.md` (BV-1/BV-2/F-BV2) — the wallet-TCB sibling whose "reimplement a daemon gate inline, prove byte-identity (BV-1) + per-signer A1 soundness (BV-2)" posture this document instantiates for the PARAM_CHANGE gate. The key *difference*: `block-verify`'s SIGS is **conditional** on an operator-supplied *digest* (the wallet cannot recompute `compute_block_digest`); `param-change-verify` has **no digest conditional** — the `sig_msg` is a flat tuple the wallet rebuilds verbatim from the transaction's own payload (PCV-1), so the message is self-determined. The residual here is the keyholder *set* + *threshold* (on-chain governance state), not a digest.
- `GovernanceWhitelistSoundness.md` (GW-1/GW-2) — the standalone closure proof for the *whitelist* layer of the same validator gate. `param-change-verify` does **not** reimplement the whitelist membership test (it verifies the *signature* layer only); GW-1's off-list rejection is independent of signatures and is the daemon's separate guard. `param-change-build`'s CLI documentation cites GW-1; this verifier is its read-only dual on the multisig layer. §4.2 states the division of labour.
- `Governance.md` (FA10, T-10 / T-11) — the consensus-layer governance soundness theorem. T-10 ("no unauthorized mutation") is the forgery reduction proving a whitelisted mutation requires genuine N-of-N (here K-of-K to threshold) keyholder consent under A1; `param-change-verify` is the operator-side, OFFLINE *predictor* of whether the signature half of that gate is satisfied. T-11 ("off-whitelist immunity") is the whitelist half this verifier does not cover.
- `GovernanceParamChange.md` (the FA-Apply governance track) — the apply-layer staging/activation proof. `param-change-verify` checks the *validate-time* signature gate, which is a precondition to a PARAM_CHANGE ever reaching the apply path; it does not assert anything about staging or activation at `effective_height` (§5 F-PCV5).
- `OperatorToolingReadOnly.md` (the read-only-tooling family, OT-1) — the sibling thesis that operator-facing verification tooling issues no state-mutating action. `param-change-verify` is the wallet-side analogue: it reads two files and verifies signatures, produces no transaction, opens no socket, and signs nothing (PCV-4 / §5 F-PCV4).
- `Preliminaries.md` (F0) §2.0 (assumption labels), §2.2 (A1).

---

## 0. Implementation status

**`int cmd_param_change_verify(int, char**)` is IMPLEMENTED and SHIPPED in `wallet/main.cpp:23382-23545`** (dispatched on `param-change-verify` at `wallet/main.cpp:25210`), exercised offline by `tools/test_wallet_param_change_verify.sh`. It is the OFFLINE, read-only dual of the daemon's PARAM_CHANGE multisig gate in `src/node/validator.cpp:688-725`. Both the reimplemented surface and its daemon reference are read directly off source for this document:

- **Wallet decode + `sig_msg` rebuild + verify loop** — `cmd_param_change_verify` (`wallet/main.cpp:23429-23510`): payload hex-decode, length-prefixed field walk, canonical `sig_msg` assembly (`:23451-23457`), per-`(idx, sig)` `crypto_sign_verify_detached` (`:23502`), distinct/in-range tracking (`:23496-23499`), and the `good >= threshold` verdict (`:23509-23510`).
- **Daemon reference gate** — `Validator::validate` PARAM_CHANGE case (`src/node/validator.cpp:636-726`): payload decode (`:644-672`), whitelist (`:677-686`, **out of scope here**, see §4.2), `sig_msg` assembly (`:693-701`), per-`(idx, sig)` `verify` over `param_keyholders_[idx]` (`:703-719`), and the `good_sigs < param_threshold_` reject (`:720-725`).

The wallet output is purely a verdict surface: human mode (`:23528-23542`) prints per-keyholder VALID/INVALID/OUT-OF-RANGE and the PASS/FAIL line; `--json` mode (`:23512-23526`) emits a structured object. Exit code `0` PASS, `2` FAIL (verdict-level), `1` args/parse error (`:23544`, `:23408-23413`, etc.). No socket, no daemon, no chain library, no signing.

---

## 1. Scope

### 1.1 In scope

The `determ-wallet param-change-verify` reimplementation of the validator's PARAM_CHANGE **signature gate**. Its control flow, read off `wallet/main.cpp:23382-23545`:

```
determ-wallet param-change-verify --tx-json <file> --keyholders <file>
                                  [--threshold N] [--json]
```

1. **Argument parse + validation (`:23386-23413`).** `--tx-json` and `--keyholders` are required (`:23410-23413`); `--threshold` and `--json` are optional. An unknown arg (`:23408`), a non-integer `--threshold` (`:23403-23406`), a missing required flag, an unreadable / non-JSON tx or keyholders file, a tx-json without a string `payload`, or a non-hex payload → `return 1` (args/parse error) **before any verdict is recorded** (`:23415-23427`, `:23460-23472`).

2. **PARAM_CHANGE payload decode (`:23429-23448`).** Hex-decode the tx `payload` and walk the length-prefixed layout `name_len(u8) | name | value_len(u16 LE) | value | effective_height(u64 LE) | sig_count(u8) | sig_count × { keyholder_index(u16 LE) | ed_sig(64B) }`. Each field is bounds-checked via the `need(n, what)` helper (`:23431-23434`); any truncation → `return 1` (parse fault, never a silent verdict).

3. **Canonical `sig_msg` rebuild (`:23451-23457`).** Reassemble the exact tuple the validator signs: `nlen(u8)` then `name` bytes, then `vlen` as two little-endian bytes (`vlen & 0xff`, `(vlen>>8) & 0xff`), then `value` bytes, then `effective_height` as eight little-endian bytes. PCV-1 proves this is byte-identical to `src/node/validator.cpp:693-701`.

4. **Keyholder set + threshold load (`:23459-23483`).** `--keyholders` is a JSON array of 32-byte pubkey hex, **or** `{keyholders:[...], threshold:N}`. Each entry `from_hex`-decodes and must be exactly 32 bytes (`:23479`). The threshold is resolved as `--threshold` override (if ≥ 0) **else** the file's `threshold` (if present) **else** the keyholder count (the K-of-K default) (`:23482-23483`).

5. **Per-`(idx, sig)` verification loop (`:23491-23506`).** For each of `sig_count` pairs: read `idx`(u16 LE) and the 64-byte `sig`; set `in_range = (0 ≤ idx < |pubkeys|)`; track `distinct` via `std::set<int>::insert`; only if **both** `in_range && distinct`, call `crypto_sign_verify_detached(sig, sig_msg, pubkeys[idx])` and, on success, increment `good`. A truncated tail mid-loop → `return 1` (`:23492`, `:23494`).

6. **Verdict + exit (`:23509-23544`).** `threshold_met = (good >= threshold)`; `pass = !dup && !oor && threshold_met`. Exit `0` iff `pass`, else `2`; `1` on the args/parse faults of steps 1-2. Output is read-only over the verdict.

### 1.2 The reimplemented surface vs. the daemon reference

| Surface | Wallet (reimplementation) | Daemon (reference) | What PASS establishes |
|---|---|---|---|
| **DECODE** | `wallet/main.cpp:23429-23448` | `src/node/validator.cpp:644-672` | The payload parses as a PARAM_CHANGE with `(name, value, effective_height, sig_count, sigs[])` — same length-prefixed layout (PCV-1 §3.1 Part A) |
| **SIG_MSG** | `wallet/main.cpp:23451-23457` | `src/node/validator.cpp:693-701` | The message each signature is checked against is byte-identical to the validator's (PCV-1 §3.1 Part B) |
| **VERIFY** | `wallet/main.cpp:23491-23506` | `src/node/validator.cpp:703-719` | Each *present* sig is a genuine Ed25519 signature over `sig_msg` under the claimed keyholder key (PCV-2 §3.2, A1) |
| **GATE** | `wallet/main.cpp:23496-23510` | `src/node/validator.cpp:711-725` | Distinct indices, all in range, `good ≥ threshold` — same accept condition (PCV-3 §3.3) |

### 1.3 Out of scope (intentional — the verifier's coverage boundary)

- **The keyholder set + threshold provenance.** This is the sole load-bearing residual (PCV-4 / §5 F-PCV1). The validator reads `param_keyholders_` and `param_threshold_` from **on-chain governance state** (set at genesis or by a prior whitelisted `param_keyholders` / `param_threshold` PARAM_CHANGE — both are themselves on the whitelist, `validator.cpp:681-682`). The transaction payload does **not** carry the keyholder set or threshold, so the wallet **cannot** derive them from the tx alone; the operator supplies them via `--keyholders` (+ optional `--threshold`). A PASS is sound *for the supplied set + threshold*; it is a faithful prediction of the validator's verdict **iff** the supplied set + threshold equal the chain's `param_keyholders_` / `param_threshold_` at validate time. §5 F-PCV1.
- **The whitelist membership test.** The validator additionally rejects any `name ∉ kWhitelist` (`validator.cpp:677-686`) *before* the multisig check, even under full threshold. `param-change-verify` does **NOT** reimplement this — it verifies the signature layer only. A PASS therefore does not assert the parameter name is governable; that is `GovernanceWhitelistSoundness.md` GW-1's closure (a separate, signature-independent set-membership guard). §4.2 / §5 F-PCV2.
- **The governance-mode gate.** The validator rejects all PARAM_CHANGE on an uncontrolled-governance chain (`governance_mode_ == 0`, `validator.cpp:640-643`) before reaching the multisig. `param-change-verify` does not model `governance_mode_` (it is on-chain state, not in the tx). A PASS does not assert the chain is in a governed mode. §5 F-PCV5.
- **Apply-layer staging / activation.** The validate-time signature gate is a *precondition* to a PARAM_CHANGE entering the apply path; it says nothing about staging at `effective_height` or the activation drain (`GovernanceParamChange.md` T-G1..T-G7). A PASS predicts validator *acceptance*, not the eventual parameter mutation. §5 F-PCV5.
- **Exact-payload-length canonicalization.** The validator enforces an **exact** tail size (`p.size() != off + expected_tail` ⇒ reject, `validator.cpp:669-671`); the wallet decoder does **not** reject trailing bytes after the last signature (it reads exactly `sig_count` pairs and ignores any surplus). This is a fail-*open* asymmetry in the wallet's *parse* tolerance — but it does **not** create a false PASS on the signature gate (the surplus bytes are not signed over and do not affect `good`/`threshold`); it only means the wallet may PASS a payload the validator would reject as malformed-length. §5 F-PCV3 records this honestly as a coverage caveat, not a soundness break.

---

## 2. Construction specification

Read directly off the two surfaces.

### 2.1 The canonical `sig_msg` (the signed tuple)

The daemon assembles `sig_msg` at `src/node/validator.cpp:693-701`:

```cpp
std::vector<uint8_t> sig_msg;
sig_msg.reserve(nlen + vlen + 8 + 16);
sig_msg.push_back(static_cast<uint8_t>(nlen));                    // name_len  (u8)
sig_msg.insert(sig_msg.end(), name.begin(), name.end());         // name      (nlen bytes)
sig_msg.push_back(static_cast<uint8_t>(vlen & 0xff));            // value_len lo (u8)
sig_msg.push_back(static_cast<uint8_t>((vlen >> 8) & 0xff));     // value_len hi (u8)
sig_msg.insert(sig_msg.end(), value.begin(), value.end());       // value     (vlen bytes)
for (int i = 0; i < 8; ++i)
    sig_msg.push_back(static_cast<uint8_t>((eff >> (8*i)) & 0xff)); // effective_height (u64 LE)
```

i.e. the byte string

$$
\mathrm{sig\_msg} \;=\; \underbrace{\mathrm{LE}_1(\mathit{nlen})}_{1\text{ B}} \,\Vert\, \mathit{name} \,\Vert\, \underbrace{\mathrm{LE}_2(\mathit{vlen})}_{2\text{ B}} \,\Vert\, \mathit{value} \,\Vert\, \underbrace{\mathrm{LE}_8(\mathit{eff})}_{8\text{ B}},
$$

where `LE_k(x)` is the `k`-byte little-endian encoding of `x`, `name` is the raw `nlen` parameter-name bytes, and `value` the raw `vlen` value bytes. There is **no hash**: the keyholders sign this flat tuple directly. (This is why A2/A3 are not in the cryptographic core — see §3.1.)

The wallet rebuilds the **same** byte string at `wallet/main.cpp:23451-23457`:

```cpp
std::vector<uint8_t> sig_msg;
sig_msg.push_back(static_cast<uint8_t>(nlen));
sig_msg.insert(sig_msg.end(), name.begin(), name.end());
sig_msg.push_back(static_cast<uint8_t>(vlen & 0xff));
sig_msg.push_back(static_cast<uint8_t>((vlen >> 8) & 0xff));
sig_msg.insert(sig_msg.end(), value.begin(), value.end());
for (int i = 0; i < 8; ++i)
    sig_msg.push_back(static_cast<uint8_t>((eff >> (8 * i)) & 0xff));
```

The only difference is the daemon's `reserve(...)` hint (a capacity preallocation with **no** effect on contents). PCV-1 proves the produced byte sequences are identical on every input.

### 2.2 The per-keyholder Ed25519 gate

The daemon verifies each `(keyholder_index, ed_sig)` pair at `src/node/validator.cpp:703-719`:

```cpp
std::set<uint16_t> seen_idx;
uint32_t good_sigs = 0;
for (uint8_t s = 0; s < sigc; ++s) {
    uint16_t idx = uint16_t(p[off]) | (uint16_t(p[off+1]) << 8);  off += 2;
    Signature msig{};  std::copy_n(p.begin() + off, 64, msig.begin());  off += 64;
    if (idx >= param_keyholders_.size())                          // in-range
        return {false, "PARAM_CHANGE keyholder_index out of range"};
    if (!seen_idx.insert(idx).second)                             // distinct
        return {false, "PARAM_CHANGE duplicate keyholder_index"};
    if (verify(param_keyholders_[idx], sig_msg.data(), sig_msg.size(), msig))
        good_sigs++;
}
if (good_sigs < param_threshold_)
    return {false, "PARAM_CHANGE signature threshold not met ..."};
```

where `verify(...)` is `determ::crypto::verify` (`src/crypto/keys.cpp:79-91`), an OpenSSL `EVP_DigestVerify` Ed25519 check. Note the daemon **hard-rejects** the whole transaction on the *first* out-of-range or duplicate index (`return {false, ...}`); a present-but-invalid signature is *not* a hard reject — it simply fails to increment `good_sigs`, and the gate later fails on the threshold if too few are valid.

The wallet's loop (`wallet/main.cpp:23491-23506`) is structurally the same, with the verdict-tracking adapted to the verifier's reporting surface:

```cpp
std::set<int> seen;
bool dup = false, oor = false;
int good = 0;
for (size_t s = 0; s < sigc; ++s) {
    int idx = int(p[off]) | (int(p[off + 1]) << 8);  off += 2;
    std::vector<uint8_t> sig(p.begin()+off, p.begin()+off+64);  off += 64;
    bool in_range = (idx >= 0 && (size_t)idx < pubkeys.size());
    if (!in_range) oor = true;                                    // tracked, not early-return
    bool distinct = seen.insert(idx).second;
    if (!distinct) dup = true;                                    // tracked, not early-return
    bool valid = false;
    if (in_range && distinct) {
        valid = (crypto_sign_verify_detached(sig.data(), sig_msg.data(),
                                             sig_msg.size(), pubkeys[idx].data()) == 0);
        if (valid) good++;
    }
    results.push_back({idx, in_range, valid});
}
...
bool pass = !dup && !oor && (good >= threshold);
```

The one *behavioural-style* difference — the wallet records `dup`/`oor` flags and reports every keyholder's status rather than early-returning on the first fault — is verdict-preserving: PCV-3 proves `pass` (wallet) ⟺ the daemon's accept condition. The cross-library substitution (`crypto_sign_verify_detached` vs. OpenSSL `verify`) is the same standard Ed25519 verification relation; PCV-2 records it as a stated cross-implementation equivalence (the identical posture `OfflineBlockVerifySoundness.md` BV-2 takes for the wallet's libsodium gate vs. the daemon's `verify`).

---

## 3. Soundness theorems

Throughout, let the assembled transaction decode to `(name, value, eff, sigc, [(idx_s, σ_s)]_{s<sigc})`, let `K = |pubkeys|` be the supplied keyholder count, `t` the resolved threshold, and `PCV ∈ {PASS, FAIL}` the verdict (exit `0` / non-zero). Bounds follow `Preliminaries.md §2.0` (A1 ≈ `2⁻¹²⁸`).

### 3.1 PCV-1 (`sig_msg` byte-equivalence — the reimplementation is faithful)

**Statement.** On every assembled PARAM_CHANGE payload, the wallet's reconstructed `sig_msg` (`wallet/main.cpp:23451-23457`) is **byte-identical** to the validator's `sig_msg` (`src/node/validator.cpp:693-701`). Hence the message each per-keyholder Ed25519 check is performed against is exactly the message the daemon's gate checks against — there is no digest conditional (contrast `OfflineBlockVerifySoundness.md` BV-2): the signed message is self-determined from the transaction's own payload.

**Proof.**

*Part A — the decode produces the same `(name, value, eff)`.* Both surfaces walk the **same** length-prefixed layout from offset 0: `nlen = p[0]` (u8); `name = p[1 .. 1+nlen)`; `vlen = p[off] | (p[off+1] << 8)` (u16 LE); `value = p[off .. off+vlen)`; `eff = Σ_{i<8} p[off+i] << 8i` (u64 LE); `sigc = p[off]` (u8). Match the operations field-for-field: validator `:651` `nlen = p[off++]` ≡ wallet `:23436` `nlen = p[off++]`; validator `:654` `name(p.begin()+off, p.begin()+off+nlen)` ≡ wallet `:23438` `name(p.data()+off, nlen)` (both take the same `nlen` raw bytes); validator `:657` `vlen = uint16_t(p[off]) | (uint16_t(p[off+1])<<8)` ≡ wallet `:23440` `vlen = size_t(p[off]) | (size_t(p[off+1])<<8)` (same little-endian decode, the wider wallet accumulator holds the identical 16-bit value since the payload field is two bytes); validator `:661` `value(...+off, ...+off+vlen)` ≡ wallet `:23442`; validator `:664-666` `eff |= uint64_t(p[off+i]) << (8*i)` ≡ wallet `:23444-23446` (identical little-endian u64 decode). Both then read `sigc = p[off++]` (validator `:668`, wallet `:23448`). The bounds-checks differ in *form* (validator inline `p.size() < off+n`; wallet `need(n, what)` helper) but not in *which* bytes get extracted — on any payload that both accept past the `sigc` read, the extracted `(name, value, eff)` are equal byte-for-byte. (The post-`sigc` exact-length check the validator applies, `:669-671`, is not part of `sig_msg`; it is §5 F-PCV3.)

*Part B — the `sig_msg` assembly is identical.* Given equal `(nlen, name, vlen, value, eff)` from Part A, both assemblies append, in order: `(u8) nlen`; the `name` bytes; `(u8) (vlen & 0xff)`; `(u8) ((vlen>>8)&0xff)`; the `value` bytes; then eight bytes `(u8) ((eff >> 8i) & 0xff)` for `i = 0..7`. These are the *same* operations in the *same* order on the *same* inputs (validator `:695-701` vs. wallet `:23452-23457`, line-for-line). The validator's `reserve(nlen+vlen+8+16)` (`:694`) is a `std::vector` capacity hint that does not alter contents or size. By structural induction over the append sequence, the produced `std::vector<uint8_t>` are byte-identical and of identical length `1 + nlen + 2 + vlen + 8`. ∎

**Consequence.** Because `sig_msg` is rebuilt from the transaction's own payload (not supplied externally), PCV-1 carries **no operator-input conditional** — unlike `OfflineBlockVerifySoundness.md` BV-2's digest, which the wallet cannot recompute. The PARAM_CHANGE signed message is a pure, deterministic function of the payload bytes the operator is verifying. The only operator input that matters is *which keys* the signatures are checked against (§3.4 / PCV-4).

### 3.2 PCV-2 (per-keyholder Ed25519 verification soundness, under A1)

**Statement.** Under A1 (Ed25519 EUF-CMA, `Preliminaries.md §2.2`), for each `(idx_s, σ_s)` pair the wallet counts as *valid* (i.e. `crypto_sign_verify_detached(σ_s, \mathrm{sig\_msg}, pubkeys[idx_s]) == 0`), the holder of the secret key for `pubkeys[idx_s]` genuinely produced a signature `σ_s` over `sig_msg`, except with probability `≤ 2⁻¹²⁸`. Consequently a PASS — which requires `good ≥ t` such valid pairs over **distinct** in-range indices (PCV-3) — implies at least `t` distinct supplied keyholders genuinely signed the canonical `sig_msg` (PCV-1), up to `≤ K · 2⁻¹²⁸`.

**Proof.** Fix the canonical `sig_msg` (PCV-1, a deterministic function of the payload). For a pair counted valid, `crypto_sign_verify_detached(σ_s, sig_msg, sig_msg.size, pubkeys[idx_s])` returned 0 — the libsodium Ed25519 detached-verify acceptance relation, identical (same RFC-8032 Ed25519 verification equation `[8]·s·B = [8]·R + [8]·H(R‖A‖M)·A`) to the daemon's OpenSSL `EVP_DigestVerify` path (`src/crypto/keys.cpp:79-91`); the cross-library equivalence is the standard Ed25519 verification relation and is recorded as a stated implementation-equivalence (the same posture `OfflineBlockVerifySoundness.md` BV-2 adopts for the wallet's libsodium SIGS gate against the daemon's `verify`). By A1, an adversary not holding `sk` for `pubkeys[idx_s]` produces a `σ_s` with `Verify(pubkeys[idx_s], sig_msg, σ_s) = 1` over a `sig_msg` that key never signed with probability `≤ 2⁻¹²⁸`. Therefore each counted-valid pair either (a) is a genuine signature by the holder of `sk` for `pubkeys[idx_s]` over `sig_msg`, or (b) the adversary broke A1 (`≤ 2⁻¹²⁸` per pair). The per-keyholder loop is a faithful `≤ sigc`-fold replication of the single-sig verify primitive with **no cross-signer state**: the only state shared across iterations is the immutable `sig_msg`, the immutable `pubkeys` vector, and the monotone `seen` set + `good` counter (which gate counting but never feed a verification input) — this is the `BatchSigningSoundness.md`-style structural-isolation property (signer `s`'s verdict depends only on `(σ_s, sig_msg, pubkeys[idx_s])`, never on signer `s' ≠ s`). Hence, over the ≤ `K` distinct counted indices, **PASS ⟹ at least `t` distinct supplied keyholders signed `sig_msg`**, under A1, up to `≤ K · 2⁻¹²⁸`. ∎

**Bound.** `Pr[\text{a counted-valid pair is not a genuine signature by } pubkeys[idx_s]] ≤ 2⁻¹²⁸` (A1, per pair); over the whole gate, `Pr[\text{PASS} ∧ ¬(t \text{ distinct keyholders signed } sig\_msg)] ≤ K · 2⁻¹²⁸`. For practical keyholder counts (`K ≤ 16`) this is `≤ 2⁻¹²⁴`-class.

### 3.3 PCV-3 (distinct-index + in-range + threshold equivalence)

**Statement.** The wallet's accept condition `pass = ¬dup ∧ ¬oor ∧ (good ≥ t)` (`wallet/main.cpp:23510`) is equivalent, on the signature gate, to the daemon's accept condition: *every* `(idx_s, σ_s)` has `idx_s < |param_keyholders_|` (in-range) **and** all `idx_s` distinct, **and** `good_sigs ≥ param_threshold_` (`src/node/validator.cpp:711-725`) — **modulo** the keyholder-set / threshold substitution (`pubkeys ↔ param_keyholders_`, `t ↔ param_threshold_`, the §3.4 boundary). The two implementations differ only in *control flow* (the daemon early-returns on the first out-of-range or duplicate index; the wallet records `oor`/`dup` flags and continues), and this difference is **verdict-preserving**.

**Proof.** Compare the three sub-conditions:

- **In-range.** Daemon: `if (idx >= param_keyholders_.size()) return reject` (`:711-712`) — any out-of-range index fails the whole tx. Wallet: `in_range = (idx ≥ 0 ∧ idx < |pubkeys|)`; `if (!in_range) oor = true` (`:23496-23497`), and `pass` requires `¬oor` (`:23510`). So *the verdict is identical*: ∃ an out-of-range index ⟺ daemon rejects ⟺ wallet `oor` ⟺ wallet FAIL. (The wallet additionally checks `idx ≥ 0`; since `idx` is decoded from a u16 it is always ≥ 0, so this guard never changes the verdict — it is defensive against the signed `int` accumulator.)
- **Distinct.** Daemon: `if (!seen_idx.insert(idx).second) return reject` (`:713-714`) — first duplicate fails the tx. Wallet: `distinct = seen.insert(idx).second`; `if (!distinct) dup = true` (`:23498-23499`), and `pass` requires `¬dup`. Identical verdict: ∃ a duplicate index ⟺ daemon rejects ⟺ wallet FAIL.
- **Threshold.** Daemon: counts `good_sigs` only for pairs that passed the in-range + distinct guards (it has already returned otherwise) and rejects iff `good_sigs < param_threshold_` (`:720`). Wallet: increments `good` only when `in_range && distinct && valid` (`:23501-23503`) and requires `good ≥ t`. On any payload with **no** duplicates and **no** out-of-range indices (the only payloads that can reach a PASS in either implementation), both count exactly the valid signatures over the same in-range distinct indices, so `good = good_sigs` (given the §3.4 set/threshold substitution and PCV-1's identical `sig_msg`). Thus `good ≥ t ⟺ good_sigs ≥ param_threshold_`.

The **control-flow** difference does not change any verdict: on a payload the daemon *rejects* for an out-of-range/duplicate index, the wallet also FAILs (via `oor`/`dup`), and the wallet's continued counting of the remaining pairs is irrelevant because `pass` is already pinned `false` by `¬oor`/`¬dup`. On a payload with no such fault, both implementations reach the threshold test over the identical set of counted-valid pairs. Hence `pass` (wallet) ⟺ the daemon's signature-gate acceptance, modulo §3.4. ∎

**Fail-closed corollary.** Every non-PASS pathway yields a non-zero exit with no false PASS: an args/parse fault or a mid-payload truncation → `return 1` *before any verdict* (`:23408-23413`, `:23427`, `:23492`, `:23494`, `:23507`); a duplicate index → `dup` → exit 2; an out-of-range index → `oor` → exit 2; `good < t` → `threshold_met` false → exit 2 (`:23544`). A *stricter* threshold than the chain's (e.g. an operator who over-states `--threshold`) can only push the verdict toward FAIL — a possible false FAIL, never a false PASS — so a mis-supplied-too-high threshold does not threaten soundness (it threatens only *completeness*, §3.4 / F-PCV1). No code path sets `pass = true` while a sub-condition failed.

### 3.4 PCV-4 (honest boundary — operator-supplied keyholders/threshold; read-only verify)

**Statement.** Two operator-supplied inputs stand between a PCV PASS and the daemon's actual verdict, and `param-change-verify` performs **no** state-mutating or signing action:

1. **Keyholder set + threshold are operator-supplied, not in the tx.** The daemon verifies signatures against `param_keyholders_[idx]` and gates on `param_threshold_` — both **on-chain governance state** read from the chain at validate time (`src/node/validator.cpp:715`, `:720`), set at genesis or by a prior whitelisted `param_keyholders` / `param_threshold` mutation. The PARAM_CHANGE payload carries neither. The wallet therefore takes them as operator input (`--keyholders` file's array + optional `threshold`, and/or `--threshold` override, `wallet/main.cpp:23459-23483`). A PCV PASS is **sound for the supplied set + threshold** (PCV-1+PCV-2+PCV-3); it is a **faithful prediction of the daemon's verdict iff the supplied `pubkeys` set (as an indexed vector) equals the chain's `param_keyholders_` and `t` equals `param_threshold_`** at the height the tx is validated. This is the sole trust boundary — identical in spirit to `OfflineBlockVerifySoundness.md` F-BV2 (operator-supplied digest) and `LightVerifyChainFileSoundness.md` F-VCF3 (operator-supplied committee provenance), specialized here to the keyholder-set/threshold the chain holds in governance state.

   *Why this is unavoidable from the tx alone, and how to discharge it.* The keyholder vector is **indexed** — `keyholder_index` is an offset into `param_keyholders_` — so the supplied array must match not only *membership* but also *ordering* (a permuted array verifies the same signatures against different indices, generally FAILing; a correct PASS requires the index→pubkey map to agree with the chain's). The operator obtains the authoritative set + threshold from a trusted, chain-linked source — canonically the daemon's governance read surface (e.g. an RPC/CLI that emits the current `param_keyholders_` + `param_threshold_`) or the genesis config. An operator who supplies a fabricated or stale keyholder set gets a PASS sound *for that set* but meaningless for the real chain.

2. **`param-change-verify` is read-only — it verifies, never signs.** The command reads two files (`--tx-json`, `--keyholders`), decodes, rebuilds `sig_msg`, and calls `crypto_sign_verify_detached` (a *verification* primitive that takes a public key and never touches secret-key material). It **opens no socket, contacts no daemon, links no chain library, constructs no transaction, and produces no signature** — there is no `crypto_sign` / `sign(...)` call and no keyfile/secret-key load anywhere in `cmd_param_change_verify`. Its only effects are reading the two input files and writing a verdict to stdout (`:23512-23543`) plus a process exit code (`:23544`). This is the wallet-side instance of the `OperatorToolingReadOnly.md` OT-1 read-only-family posture: a verifier is a witness, not an actor.

**Proof.** (1) is a direct reading of the two surfaces: the daemon's verify input `param_keyholders_[idx]` and gate bound `param_threshold_` are member fields of `Validator` populated from chain governance state, never from `tx.payload` (the payload decode at `:644-672` extracts only `name/value/eff/sigc/sigs` — no keyholder set, no threshold). The wallet's corresponding inputs come exclusively from the `--keyholders` file and `--threshold` flag (`:23459-23483`); no other source exists in `cmd_param_change_verify`. Hence the PCV-1+2+3 equivalence holds *conditioned on* `pubkeys = param_keyholders_ ∧ t = param_threshold_`, and that conditioning is an operator obligation, not a derivable fact. (2) is established by enumerating every side-effecting call in `cmd_param_change_verify` (`wallet/main.cpp:23382-23545`): two `std::ifstream` opens (`:23417`, `:23462`), `from_hex` decodes, `crypto_sign_verify_detached` (verify-only), `std::cout`/`std::cerr` writes, and `return`. No network call, no `crypto_sign`, no secret-key handling, no chain-state write. The verifier cannot mutate state or emit a signature. ∎

### 3.5 PCV-E (composite verdict + error bound)

**Statement.** Under A1, `PCV = PASS` (exit 0) implies, **conditioned on the operator supplying the chain's true `param_keyholders_` (as an index-matched vector) and `param_threshold_`** (PCV-4 boundary):

> the assembled PARAM_CHANGE carries **≥ `param_threshold_`** valid Ed25519 signatures, by **distinct, in-range** keyholders, over the **byte-identical** canonical `sig_msg` the validator builds (PCV-1) — i.e. **the daemon's PARAM_CHANGE signature gate (`src/node/validator.cpp:711-725`) would accept this multisig.**

The soundness error is the per-signer A1 term only; the decode, `sig_msg` assembly, distinctness/range tracking, and threshold arithmetic are deterministic and contribute no cryptographic term:

$$
\Pr[\text{PCV} = \text{PASS} \ \wedge\ \text{the validator signature gate would reject (same set/threshold)}]
\;\le\; \underbrace{K \cdot 2^{-128}}_{\text{A1, } \le K \text{ keyholders}}.
$$

**Derivation.** `PCV = PASS` ⟺ `¬dup ∧ ¬oor ∧ good ≥ t` (PCV-3). The event "PCV passes yet the validator's signature gate would reject on the same keyholder set + threshold" requires either (i) a counted-valid pair that is not a genuine signature by its claimed keyholder — bounded by A1 at `≤ K·2⁻¹²⁸` (PCV-2, union over ≤ K counted pairs) — or (ii) a mismatch in the deterministic gate logic (decode, `sig_msg`, distinct/range, threshold), which PCV-1 + PCV-3 prove is **zero** (byte-identical message, identical accept condition). The decode and assembly are deterministic (probability-1 correct on their own definition); the cross-library Ed25519 equivalence is a stated implementation-equivalence, not a probability term. Hence the bound is the A1 term alone. The **keyholder-set / threshold provenance** (PCV-4) is *not* in the bound: it is an operator-supplied precondition (a wrong set/threshold makes the verdict *meaningless for the real chain*, not *unsound under A1*), exactly as `OfflineBlockVerifySoundness.md` BV-E excludes its digest conditional and `LightVerifyChainFileSoundness.md` VCF-E excludes its committee-provenance conditional. ∎

---

## 4. Composition with companion proofs

### 4.1 `OfflineBlockVerifySoundness.md` — the wallet-TCB reimplementation sibling

`param-change-verify` is the same *species* of object as `block-verify`: an OFFLINE, read-only, chain-library-free reimplementation of one daemon accept gate, proved by (a) a byte-equivalence theorem on the reconstructed input (PCV-1 here ↔ BV-1's `tx_root` byte-equivalence) and (b) a per-signer A1 soundness theorem (PCV-2 ↔ BV-2). The decisive *difference* is the residual: `block-verify`'s SIGS is conditional on an operator-supplied **digest** the wallet cannot recompute (F-BV2); `param-change-verify` rebuilds its signed message (`sig_msg`) verbatim from the tx payload (PCV-1, **no digest conditional**), so its only residual is the keyholder **set + threshold** — on-chain governance state, not a digest (PCV-4 / F-PCV1). In both, the fail-closed posture holds: a stricter-than-true threshold/quorum can only cause a false FAIL, never a false PASS.

### 4.2 `GovernanceWhitelistSoundness.md` (GW-1/GW-2) — the whitelist layer this verifier does NOT cover

The daemon's PARAM_CHANGE gate has two independent guards: a **whitelist** membership test (`name ∈ kWhitelist`, `validator.cpp:677-686`) and the **multisig** gate (`validator.cpp:688-725`). `GovernanceWhitelistSoundness.md` GW-1 proves the whitelist is a closed, code-pinned, signature-independent set-membership rejection (an off-list name is rejected *even under full threshold*); GW-2 covers its width-checked-not-range-checked bounds posture. `param-change-verify` reimplements the **multisig gate only** — it makes no whitelist check, so a PCV PASS does not assert the parameter name is governable (§5 F-PCV2). The two layers compose at the daemon: the validator requires **both** (whitelist ∧ multisig). An operator wanting the full validate-time prediction pairs a PCV PASS (the multisig half) with a whitelist-membership check of `name` against the GW-1 enumeration (the closure half).

### 4.3 `Governance.md` (FA10, T-10/T-11) — the consensus-layer governance theorem this predicts

`Governance.md` T-10 ("no unauthorized mutation") is the forgery reduction: under A1, a whitelisted parameter mutates only if `≥ param_threshold_` genuine keyholder signatures over the canonical tuple exist — exactly the property a PCV PASS predicts the validator will find. `param-change-verify` is the operator-side, OFFLINE *oracle* for the signature half of T-10's hypothesis (it does not re-derive T-10; it predicts whether the gate T-10 relies on will accept). T-11 ("off-whitelist immunity") is the whitelist half (§4.2), out of scope here.

### 4.4 `GovernanceParamChange.md` — the apply-layer the gate is a precondition to

A validate-time signature-gate acceptance (what PCV predicts) is necessary but not sufficient for the parameter to actually change: the accepted PARAM_CHANGE is then *staged* and *activated* at `effective_height` per `GovernanceParamChange.md` T-G1..T-G7. PCV asserts nothing about staging/activation (§5 F-PCV5); it predicts only that the tx clears the signature gate and is eligible to enter the apply path.

### 4.5 `OperatorToolingReadOnly.md` (OT-1) + `Preliminaries.md` — the read-only posture + assumption base

PCV-4 part (2) is the wallet-side instance of the OT-1 read-only-family thesis: a verifier issues no state-mutating action and (here) no signature. The cryptographic core reduces to **A1** (`Preliminaries.md §2.2`) alone; A2/A3 are not used because the keyholders sign a flat length-prefixed tuple, not a hash (§3.1). The composite bound (PCV-E) is the single A1 term with no independent contribution.

---

## 5. Findings (honest limitations)

Stated so an operator knows exactly what a `param-change-verify: PASS` does and does not assert. None undermines the per-invocation soundness of PCV-E; all are coverage/scope statements or the one operator-input boundary.

### F-PCV1 The keyholder set + threshold are operator-supplied — provenance is the sole load-bearing boundary

This is the load-bearing honesty of the proof. The validator verifies signatures against `param_keyholders_` and gates on `param_threshold_`, **on-chain governance state** the transaction payload does not carry. `param-change-verify` takes both as operator input (`--keyholders`, `--threshold`). A PCV PASS is sound *for the supplied set + threshold* (PCV-1/2/3) and is a faithful prediction of the validator's verdict **iff** the supplied `pubkeys` vector equals the chain's `param_keyholders_` **including index ordering** (the gate indexes into the vector by `keyholder_index`) and `t` equals `param_threshold_` at the validating height. An operator who supplies a fabricated, permuted, or stale set/threshold gets a PASS of unknown meaning for the real chain. Discharge it by sourcing the set + threshold from the daemon's governance read surface or the genesis config — the same kind of trusted-input obligation as `OfflineBlockVerifySoundness.md` F-BV2 (digest) and `LightVerifyChainFileSoundness.md` F-VCF3 (committee provenance).

### F-PCV2 The whitelist layer is NOT reimplemented — PASS does not assert the name is governable

The daemon rejects any `name ∉ kWhitelist` *before* the multisig check, even under full threshold (`validator.cpp:677-686`). `param-change-verify` checks the **signature gate only**; a PCV PASS over a non-whitelisted `name` (e.g. an attempt to mutate `K` or the chain identity) means "the signatures are valid for this tuple," **not** "the validator would accept this PARAM_CHANGE" — the daemon would still reject it at the whitelist. For the full validate-time prediction, pair a PCV PASS with a whitelist-membership check of `name` against the `GovernanceWhitelistSoundness.md` GW-1 closed enumeration.

### F-PCV3 Parse tolerance is wider than the validator's exact-length canonicalization (fail-open on framing, not on the gate)

The validator enforces an **exact** payload tail (`p.size() != off + sig_count·(2+64)` ⇒ reject, `validator.cpp:669-671`). The wallet decoder reads exactly `sig_count` pairs and **ignores any trailing bytes** after the last signature; it does not reject an over-long payload. Consequently the wallet may PASS a payload the validator would reject as malformed-length. This is a fail-*open* asymmetry in the *framing* check — but it is **not a false PASS on the signature gate**: the surplus bytes are not part of `sig_msg` (PCV-1) and do not affect `good`/`threshold`, so the multisig conclusion PCV asserts remains sound; only the "the validator would accept the *whole transaction*" inference is weakened by the framing gap. An operator who needs exact-framing parity should additionally check `payload_len == header_len + sig_count·66`.

### F-PCV4 No semantic / governance-mode / apply-layer validity

A PCV PASS asserts the **signature gate** accepts. It does **not** assert: the chain is in a governed mode (`governance_mode_ != 0`, `validator.cpp:640-643` — on-chain state the wallet does not model); the parameter name is whitelisted (F-PCV2); the value is in any sane range (the validator does not range-check either — `GovernanceWhitelistSoundness.md` GW-2's consent-over-bounds posture); or that the change will stage/activate at `effective_height` (`GovernanceParamChange.md` T-G*). It is a signature-gate predictor on one isolated assembled transaction, not a full consensus-validity or apply-correctness oracle.

### F-PCV5 Cross-implementation Ed25519 equivalence is a stated implementation-equivalence

The wallet verifies with libsodium `crypto_sign_verify_detached` (`wallet/main.cpp:23502`); the daemon with OpenSSL `EVP_DigestVerify` Ed25519 (`src/crypto/keys.cpp:79-91`). Both implement the same RFC-8032 Ed25519 verification relation, so a signature accepted by one is accepted by the other (modulo the well-known cofactored/strict-verification edge cases, which both libraries handle consistently for canonically-produced signatures from `determ`'s own signers). This document treats their agreement as a stated implementation-equivalence — the identical posture `OfflineBlockVerifySoundness.md` BV-2 takes for the wallet's libsodium SIGS gate against the daemon's `verify`. PCV-2's A1 bound is over the abstract Ed25519 verification relation both realize.

---

## 6. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Surface | File:lines | Role |
|---|---|---|---|
| — | `cmd_param_change_verify` (the verifier) | `wallet/main.cpp:23382-23545` | Arg parse, decode, `sig_msg` rebuild, verify loop, verdict, exit 0/1/2. |
| — | dispatch | `wallet/main.cpp:25210` | `param-change-verify` → `cmd_param_change_verify`. |
| PCV-1 | wallet payload decode | `wallet/main.cpp:23429-23448` | `name_len|name|value_len LE|value|eff LE|sig_count` walk. |
| PCV-1 | wallet `sig_msg` rebuild | `wallet/main.cpp:23451-23457` | The reconstruction proved byte-identical. |
| PCV-1 | daemon decode reference | `src/node/validator.cpp:644-672` | The byte-identical reference decode. |
| PCV-1 | daemon `sig_msg` reference | `src/node/validator.cpp:693-701` | `nlen|name|vlen LE|value|eff LE` — the reference assembly. |
| PCV-2 | wallet per-keyholder verify | `wallet/main.cpp:23491-23506` | `crypto_sign_verify_detached(σ, sig_msg, pubkeys[idx])`; `good++` on valid. |
| PCV-2 | daemon per-keyholder verify | `src/node/validator.cpp:703-719` | `verify(param_keyholders_[idx], sig_msg, msig)`; `good_sigs++`. |
| PCV-2 | daemon Ed25519 `verify` | `src/crypto/keys.cpp:79-91` | OpenSSL `EVP_DigestVerify` Ed25519 (the reference verify primitive). |
| PCV-3 | wallet distinct/range/threshold | `wallet/main.cpp:23496-23510` | `oor`/`dup` flags; `pass = ¬dup ∧ ¬oor ∧ good ≥ t`. |
| PCV-3 | daemon distinct/range/threshold | `src/node/validator.cpp:711-725` | In-range + distinct hard-reject; `good_sigs < param_threshold_` reject. |
| PCV-4 | keyholder set + threshold (operator-supplied) | `wallet/main.cpp:23459-23483` | `--keyholders` array/object + `--threshold`; default = K-of-K. |
| PCV-4 | on-chain governance state (daemon side) | `src/node/validator.cpp:715, 720` | `param_keyholders_[idx]`, `param_threshold_` — chain state, not in tx. |
| PCV-4 | read-only / no-signing | `wallet/main.cpp:23382-23545` | Two file reads + verify + verdict; no socket, no `crypto_sign`, no keyfile. |
| F-PCV3 | validator exact-length check (not reimplemented) | `src/node/validator.cpp:669-671` | `p.size() != off + sig_count·66 ⇒ reject` — the framing parity gap. |
| F-PCV2 | whitelist layer (not reimplemented) | `src/node/validator.cpp:677-686` | `name ∈ kWhitelist` — covered by `GovernanceWhitelistSoundness.md` GW-1. |
| PCV-E | (no new term) | — | Bound = `K·ε_{A1}`; decode + `sig_msg` + gate logic deterministic; set/threshold provenance NOT in the bound. |

**Tests.**

| Test | Coverage |
|---|---|
| `tools/test_wallet_param_change_verify.sh` | PCV end-to-end (assemble a PARAM_CHANGE, supply keyholders, run offline): happy-path PASS (threshold met, distinct in-range valid sigs); sub-threshold → FAIL (exit 2); out-of-range index → FAIL; duplicate index → FAIL; tampered value/name/eff (breaks `sig_msg` ⇒ sigs invalid) → FAIL; wrong keyholder pubkey → FAIL; `--threshold` override semantics; `--json` shape; args/parse faults → exit 1. |

---

## 7. Status

- **Implementation.** **SHIPPED.** `int cmd_param_change_verify` is in `wallet/main.cpp:23382-23545` (dispatched on `param-change-verify` at `:25210`), exercised offline by `tools/test_wallet_param_change_verify.sh`. It is the OFFLINE, read-only reimplementation of the daemon's PARAM_CHANGE multisig gate (`src/node/validator.cpp:688-725`).
- **Proof.** Complete (this document). PCV-1 (`sig_msg` byte-equivalence — the wallet rebuilds the validator's exact `nlen|name|vlen LE|value|eff LE` tuple; **no digest conditional**, the message is self-determined from the payload); PCV-2 (per-keyholder Ed25519 soundness under A1 — a counted-valid pair is a genuine signature by the claimed keyholder, `≤ K·2⁻¹²⁸`); PCV-3 (distinct-index + in-range + threshold equivalence — the wallet's `¬dup ∧ ¬oor ∧ good ≥ t` matches the daemon's accept condition, the control-flow difference is verdict-preserving, fail-closed); PCV-4 (the honest boundary — keyholder set + threshold are operator-supplied on-chain governance state; the verifier is read-only and signs nothing). Composite verdict + bound PCV-E (`≤ K·ε_{A1}`; deterministic decode/assembly/gate add no term; the set/threshold provenance is NOT in the bound).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA, the per-keyholder signature check). A2, A3 **not** used — the gate signs a flat length-prefixed tuple, not a hash. Per `Preliminaries.md §2.0`.
- **The single trust boundary (load-bearing).** The keyholder pubkey set + threshold are **on-chain governance state** (`param_keyholders_`, `param_threshold_`) not carried in the PARAM_CHANGE payload, so the operator supplies them. A PASS is sound for the supplied set + threshold and is a faithful prediction of the validator's signature-gate verdict **iff** they equal the chain's values (including index ordering) at the validating height (F-PCV1). The verifier additionally does not reimplement the whitelist layer (F-PCV2, covered by `GovernanceWhitelistSoundness.md` GW-1) or the governance-mode gate (F-PCV4), and tolerates trailing payload bytes the validator rejects (F-PCV3).
- **Composes with.** `OfflineBlockVerifySoundness.md` (BV-1/BV-2/F-BV2 — the wallet-TCB reimplementation sibling whose byte-equivalence + per-signer-A1 posture this mirrors, minus the digest conditional), `GovernanceWhitelistSoundness.md` (GW-1/GW-2 — the whitelist layer this verifier does NOT cover; the two compose at the daemon as whitelist ∧ multisig), `Governance.md` (FA10 T-10/T-11 — the consensus governance theorem PCV predicts the signature half of), `GovernanceParamChange.md` (the apply-layer staging/activation the gate is a precondition to), `OperatorToolingReadOnly.md` (OT-1 — the read-only-tooling thesis PCV-4 instantiates wallet-side), `Preliminaries.md` (A1 base).
- **Known limitations (§findings).** **F-PCV1 (the load-bearing one: keyholder set + threshold are operator-supplied on-chain governance state — a PASS is a faithful validator-verdict prediction only if they match the chain's, index-ordering included)**; F-PCV2 (whitelist layer not reimplemented — PASS does not assert the name is governable); F-PCV3 (parse tolerates trailing bytes the validator's exact-length check rejects — fail-open on framing, not on the gate); F-PCV4 (no governance-mode / range / apply-layer validity); F-PCV5 (cross-library Ed25519 equivalence stated, not re-derived). None undermines the per-invocation soundness of PCV-E.
- **The read-only posture (load-bearing).** `param-change-verify` reads two files, rebuilds the canonical `sig_msg` from the tx's own payload, and Ed25519-*verifies* the assembled signatures against an operator-supplied keyholder set. It opens no socket, links no chain library, builds no transaction, and produces no signature (no `crypto_sign`, no secret-key load anywhere in the command). It is a witness over the validator's signature gate — sound under A1 for the supplied keyholder set + threshold, faithful to the daemon's verdict exactly when that set + threshold are the chain's.

---
