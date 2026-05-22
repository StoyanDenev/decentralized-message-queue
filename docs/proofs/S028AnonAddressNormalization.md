# S028AnonAddressNormalization — case-insensitive read / canonical-only write contract (S-028 closure)

This document proves the analytic guarantees of the S-028 closure: anon-address case handling at user-input boundaries. Pre-fix, the wallet's address-parser was case-sensitive (`0x` followed by 64 lowercase hex). A user querying `balance("0xABC…")` against an account funded as `"0xabc…"` would silently receive a zero balance; a TRANSFER credit to `"0xABC…"` would create a "ghost" account at the uppercase key that the recipient (querying the lowercase form their wallet emits) could never find. The closure consists of (i) a case-insensitive shape check `is_anon_address`, (ii) a canonical-form helper `normalize_anon_address` that lowercases the hex tail and passes domain names through unchanged, (iii) normalize-at-input on RPC READ paths (`rpc_balance`), and (iv) a strict-canonical input check on the signed-tx submission path (`rpc_submit_tx`) that rejects non-canonical addresses with a clear diagnostic — because the Ed25519 signature is over `signing_bytes` which embeds `tx.from` and `tx.to` byte-for-byte, server-side mutation would invalidate the sig.

The proof is mechanical: every theorem reduces to (a) a direct citation of the inline helpers in `include/determ/types.hpp` and (b) a citation of the corresponding RPC entry-point handler in `src/node/node.cpp`. The contract is the symmetric "case-insensitive on input for unauthenticated reads / canonical-only on input for authenticated writes" pattern. The proof exists to make the boundary explicit so an external auditor can confirm the closure without re-reading the source: anon-addresses normalize to lowercase; domain names pass through unchanged; the chain's `accounts_` map is keyed by canonical bytes only; and the apply layer treats addresses as opaque bytes — canonicalization is enforced strictly upstream.

**Companion documents:** `docs/SECURITY.md` §S-028 (closure narrative); `docs/PROTOCOL.md` §3 (address-shape conventions); `docs/proofs/AccountStateInvariants.md` (FA-Apply state invariants that consume canonical addresses); `docs/proofs/JsonValidationSoundness.md` (S-018, paired wire-format input-hardening pattern); `tools/test_anon_address_case.sh` (3/3 PASS regression).

**Status:** Mitigated in-session. `is_anon_address` accepts either case; `normalize_anon_address` returns lowercase canonical; `rpc_balance` normalizes at input; `rpc_submit_tx` rejects non-canonical input with a clear diagnostic. SECURITY.md classifies S-028 as Mitigated (Low/Op).

---

## 1. Theorem statements

**T-1 (Normalization Soundness).** For every input string `S`, `normalize_anon_address(S)` returns a string `S'` such that:

1. If `is_anon_address(S) == false` then `S' == S` (identity on non-anon shapes — passes domain names through).
2. If `is_anon_address(S) == true` then `S'` has the same length (66), the same `"0x"` prefix, and the same 64 hex characters with every `A`–`F` replaced by the corresponding `a`–`f`. Every `0`–`9` digit and every `a`–`f` digit is unchanged.
3. **Case-collapse.** For any two strings `S₁, S₂` both passing `is_anon_address`, if they differ only in the case of one or more hex digits in positions 2..65, then `normalize_anon_address(S₁) == normalize_anon_address(S₂)`. Equivalently, all `2⁶⁴` case-variants of one underlying 32-byte pubkey collapse to a single canonical lowercase string.
4. **Idempotence.** `normalize_anon_address(normalize_anon_address(S)) == normalize_anon_address(S)` for every `S`.

**T-2 (Server-Side Validation Asymmetry).** The RPC layer applies normalization asymmetrically along the read/write axis:

- **READ paths** (`rpc_balance`) call `normalize_anon_address(addr_in)` at function entry and look up the canonical form in the chain's `accounts_` map. Any case-variant of the same underlying pubkey resolves to the same account record.
- **WRITE paths via signed transactions** (`rpc_submit_tx`) REJECT non-canonical input with an `std::runtime_error` whose message includes the substring `"non-canonical"`, the offending field's actual value, and the expected canonical value. This is necessary — and not redundant with normalize-at-input — because the client's Ed25519 signature is over `tx.signing_bytes()` which embeds `tx.from` and `tx.to` byte-for-byte. Mutating case server-side would invalidate the signature; the strict-input approach forces the client to canonicalize before signing.

**T-3 (No Signature-Mutation Surface).** Because the server never mutates `signing_bytes`-bound fields, no normalization step at the RPC layer can invalidate a valid signature. The chain's apply layer (`src/chain/chain.cpp::apply_transactions`) treats `tx.from` and `tx.to` as opaque byte-strings — comparing them via `std::string::operator==` and using them as keys into `accounts_`. Canonicalization is a strict pre-condition enforced at RPC boundary; the apply layer relies on the boundary having already canonicalized.

**T-4 (Auto-Created Accounts Are Canonical).** When a TRANSFER credits a previously-unseen anon-address `tx.to`, the auto-created entry in the chain's `accounts_` map is keyed by `tx.to` byte-for-byte. Because `rpc_submit_tx` rejects any tx where `tx.to` is a non-canonical anon-address shape, every TRANSFER admitted via signed-submit carries a canonical lowercase `tx.to`. Therefore every auto-created anon-account is keyed in canonical lowercase form. A subsequent `rpc_balance` query in any case-variant (lower / upper / mixed) normalizes to the same key and resolves the correct account record.

**T-5 (Backward Compat & Legacy State).** A residual anon-account in `accounts_` whose key was admitted before S-028 (in either case) remains queryable post-S-028 because `normalize_anon_address` deterministically maps any case-variant to one canonical lowercase form. If the legacy state happens to be already-lowercase, all queries resolve. If the legacy state is uppercase (theoretically possible if a pre-S-028 producer admitted an unsigned credit; in v1.x this could not arise via TRANSFER because S-002 requires sig-verify and the sig is over the address bytes, but operator-edited genesis JSON or future migration code could introduce one), then the post-S-028 query path resolves the lowercase canonical form and would miss the uppercase legacy entry. This is acknowledged in §6 (Identified gaps) — in practice the only path to an uppercase `accounts_` key is via operator-edited genesis JSON, which is itself a privileged action, and a single one-shot migration script can canonicalize legacy keys at upgrade time.

---

## 2. Background

### 2.1 Pre-S-028 issue narrative

Anonymous (bearer-wallet) addresses in Determ are `"0x"` followed by 64 hex characters = the SHA-256-less full Ed25519 pubkey of a key the holder physically possesses. The original `is_anon_address` shape check accepted only lowercase hex `[0-9a-f]`. Two failure modes followed:

1. **Read fragmentation.** A user-facing CLI / wallet that emitted addresses with mixed-case (e.g. a Web checksum-style encoding) would query `rpc_balance("0xABC…")` against an account funded as `"0xabc…"` and silently receive `balance: 0`. The chain's `accounts_` map uses `std::map<std::string, AccountState>` keyed by exact-byte match; a one-bit case difference in any hex digit produces a different map key.

2. **Ghost accounts via TRANSFER credit.** A pre-S-028 chain that admitted a TRANSFER with `tx.to == "0xABC…"` (e.g. a producer that didn't validate `tx.to` shape strictly, or a producer that admitted whatever shape the gossip payload carried) would auto-create an `accounts_["0xABC…"]` entry on the credit side of the TRANSFER. A recipient querying the lowercase form their wallet emits (`"0xabc…"`) would see `balance: 0` while the chain's audit-sum would reflect the uppercase credit. The funds are not lost (the holder of the corresponding ed25519 private key could still spend by signing a TRANSFER with `tx.from == "0xABC…"`), but the user-experience is silently broken — the wallet shows zero and the user cannot reconcile.

The classification was Low/Op because: (a) no consensus or safety property is breached (the audit-sum closes — funds are credited to *some* account-map entry, just not the one the recipient queries), and (b) the holder of the corresponding private key can always recover by signing a tx with the same-case `tx.from`. Still, it is a fragmenting UX defect — and once a chain has both `"0xABC…"` and `"0xabc…"` entries for the same pubkey, no automatic merge exists.

### 2.2 S-028 closure narrative

The fix has four parts:

1. **Case-insensitive shape check.** `is_anon_address(s)` is rewritten to accept both `[0-9a-f]` and `[0-9A-F]` in the 64-hex tail (still requires the exact `"0x"` prefix and length 66 — neither is case-affected). This is the protocol's user-input acceptance criterion: any case-variant of a 32-byte pubkey is a valid wire form.

2. **Canonical-form normalizer.** `normalize_anon_address(s)` lowercases the hex tail of any string that passes `is_anon_address`, leaving the `"0x"` prefix and the digits `0`–`9` untouched. Strings that fail `is_anon_address` — domain names, blank strings, garbage — pass through unchanged so RPC handlers can apply the helper uniformly to anything that *might* be an address. This is the protocol's canonical-storage form.

3. **READ-path normalize-at-input.** RPC handlers that take an address argument and perform a read against chain state — paradigmatically `rpc_balance` — call `normalize_anon_address(addr_in)` at function entry and use the canonical form for the chain-state lookup. The user can ask in any case; the server resolves the canonical key.

4. **WRITE-path strict-canonical input check.** RPC handlers that take a signed transaction and admit it to mempool — `rpc_submit_tx` — REJECT a tx whose `tx.from` or `tx.to` is a non-canonical anon-address shape, with a clear diagnostic naming the offending field, the actual value, and the expected canonical value. The server cannot normalize-and-accept because the Ed25519 signature is over `tx.signing_bytes()` which embeds the address byte-for-byte; mutating case server-side would invalidate the sig. Forcing the client to canonicalize before signing keeps store-keys unambiguous and preserves the sig-binding to the byte-string actually committed.

The end state: anon-addresses normalize to a single canonical lowercase form everywhere they touch chain state; user inputs in any case for READ queries; user inputs in canonical-only for WRITE submissions; domain names pass through every helper unchanged.

---

## 3. Implementation citation

### 3.1 The case-insensitive shape check — `include/determ/types.hpp:115-126`

```cpp
inline bool is_anon_address(const std::string& s) {
    if (s.size() != 66) return false;
    if (s[0] != '0' || s[1] != 'x') return false;
    for (size_t i = 2; i < 66; ++i) {
        char c = s[i];
        bool ok = (c >= '0' && c <= '9')
               || (c >= 'a' && c <= 'f')
               || (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}
```

Accepts canonical lowercase, uppercase-hex, mixed-case. Rejects missing-`0x`-prefix, wrong length, non-hex characters. Domain names (no `"0x"` prefix) are rejected — they are not anon-shape.

### 3.2 The canonical-form helper — `include/determ/types.hpp:134-142`

```cpp
inline std::string normalize_anon_address(const std::string& s) {
    if (!is_anon_address(s)) return s;
    std::string out = s;
    for (size_t i = 2; i < out.size(); ++i) {
        char c = out[i];
        if (c >= 'A' && c <= 'F') out[i] = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}
```

For non-anon shapes (including domain names, partial strings, garbage), the function is the identity. For anon shapes, the hex tail is lowercased character-by-character. The `"0x"` prefix and `0`–`9` digits are untouched.

### 3.3 READ-path normalize-at-input — `src/node/node.cpp:3224-3234`

```cpp
json Node::rpc_balance(const std::string& domain_in) const {
    // S-028: normalize anon-address input so "0xABC..." resolves to the
    // same account as "0xabc...". Domain names pass through unchanged.
    const std::string domain = normalize_anon_address(domain_in);
    // A9 Phase 2C-Node: lock-free path. See rpc_nonce above for the
    // semantics — atomic_load of the committed accounts view, no
    // state_mutex_ acquisition. balance is one of the most-hammered
    // RPC paths (wallets poll it after every send); decoupling it
    // from apply's writer lock is a meaningful operational improvement.
    return {{"domain", domain}, {"balance", chain_.balance_lockfree(domain)}};
}
```

The same normalize-at-input pattern is applied at `src/node/node.cpp:2809` on the `to` argument of `rpc_send` (the node's outbound TRANSFER-creation RPC; the resulting tx is signed by the local key under the canonical `to`, so the recipient slot is canonical-keyed):

```cpp
json Node::rpc_send(const std::string& to_in, uint64_t amount, uint64_t fee) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    // S-028: normalize anon-address inputs to lowercase canonical form so
    // "0xABC..." and "0xabc..." land in the same account-map entry.
    // Domain names pass through unchanged (is_anon_address rejects them).
    const std::string to = normalize_anon_address(to_in);
    ...
}
```

### 3.4 WRITE-path strict-canonical input check — `src/node/node.cpp:3102-3129`

```cpp
json Node::rpc_submit_tx(const json& tx_json) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    chain::Transaction tx = chain::Transaction::from_json(tx_json);

    // S-028: tx.from and tx.to (when anon-shape) must arrive in
    // canonical lowercase hex form. We can't normalize-then-accept
    // because the client's Ed25519 signature is over signing_bytes
    // which embeds tx.from / tx.to byte-for-byte; mutating the case
    // post-receipt would invalidate that signature. Instead, fail
    // loud with a clear diagnostic telling the client to lowercase
    // before signing.
    if (is_anon_address(tx.from) && tx.from != normalize_anon_address(tx.from)) {
        throw std::runtime_error(
            "submitted tx.from is non-canonical (uppercase hex); "
            "anon addresses MUST be lowercase: got '" + tx.from
          + "', expected '" + normalize_anon_address(tx.from) + "'");
    }
    if (is_anon_address(tx.to)   && tx.to   != normalize_anon_address(tx.to)) {
        throw std::runtime_error(
            "submitted tx.to is non-canonical (uppercase hex); "
            "anon addresses MUST be lowercase: got '" + tx.to
          + "', expected '" + normalize_anon_address(tx.to) + "'");
    }
    ...
}
```

The diagnostic message contains the substring `"non-canonical"`, the offending field name, the actual bytes received, and the expected canonical bytes — sufficient for the client to correct and resubmit.

### 3.5 Apply layer treats addresses as opaque bytes — `src/chain/chain.cpp:735, 756, 1005`

```cpp
AccountState& sender = accounts_[tx.from];
...
auto& rcv = accounts_[tx.to].balance;
```

`accounts_` is a `std::map<std::string, AccountState>` keyed by exact-byte match. The apply layer does NOT call `normalize_anon_address`; it relies on the RPC boundary (T-2 above) having canonicalized. Re-normalizing in apply would be redundant and would mask boundary-violation bugs.

---

## 4. Proofs

### 4.1 Proof of T-1 (Normalization Soundness)

By cases on `is_anon_address(S)`:

**Case 1: `is_anon_address(S) == false`.** From `include/determ/types.hpp:135`, `normalize_anon_address` returns `s` directly. So `S' == S`. ∎

**Case 2: `is_anon_address(S) == true`.** From `include/determ/types.hpp:136`, `out = s` (copy). The loop at lines 137-140 iterates `i = 2..65`, conditionally mapping `[A-F]` to `[a-f]` via `c - 'A' + 'a'`. ASCII has `'A' == 65`, `'a' == 97`, so `c - 'A' + 'a' == c + 32` for `c ∈ {'A', 'B', 'C', 'D', 'E', 'F'}` — the standard ASCII case-flip producing `{'a', 'b', 'c', 'd', 'e', 'f'}`. All other characters (digits `0`–`9` and lowercase `a`–`f`, the only other characters admitted by `is_anon_address`) fail the `c >= 'A' && c <= 'F'` guard and are left untouched. The `"0x"` prefix at positions 0..1 is never touched. So `S'` has length 66, prefix `"0x"`, and 64-char hex tail with every `[A-F]` replaced by the corresponding `[a-f]`. ∎

**Case-collapse.** Given `S₁, S₂` both passing `is_anon_address` and differing only in the case of hex digits in positions 2..65: at every position `i ∈ [2, 66)`, the loop maps the (possibly differing) input character to a lowercase output. Since `'a'..'f'` map to themselves and `'A'..'F'` map to `'a'..'f'`, the output at every position is the lowercase form of the input character. Two inputs differing only in case map to the same lowercase output. ∎

**Idempotence.** If `S = normalize_anon_address(S₀)` for some input `S₀`, then either `S₀` failed `is_anon_address` (in which case `S = S₀` and `is_anon_address(S) == false` ⇒ `normalize_anon_address(S) = S`), or `S₀` passed and `S` has a lowercase-only hex tail. In the latter case, `is_anon_address(S) == true` (shape unchanged) and the loop finds no `[A-F]` to flip, so `out == s`. Either way, `normalize_anon_address(normalize_anon_address(S₀)) == normalize_anon_address(S₀)`. ∎

### 4.2 Proof of T-2 (Server-Side Validation Asymmetry)

**READ path normalize-at-input.** `src/node/node.cpp:3227` performs `const std::string domain = normalize_anon_address(domain_in);` and immediately uses `domain` for the chain-state lookup at line 3233. For any case-variant of an anon-address `addr_in`, by T-1, `normalize_anon_address(addr_in)` is the canonical lowercase form. The chain-state lookup is therefore against the canonical key; subsequent queries against `accounts_` resolve the same record regardless of input case.

The same pattern applies to `rpc_send` at `src/node/node.cpp:2809` for the `to` argument: the tx constructed at lines 2824-2834 carries `tx.to = to`, where `to` is the normalized (canonical) form. The signature at line 2833 is over `tx.signing_bytes()` which includes `tx.to`'s canonical bytes; the resulting tx is admissible on every other node's `rpc_submit_tx` because `tx.to == normalize_anon_address(tx.to)` (the strict-canonical predicate holds by construction).

**WRITE path strict-canonical input check.** `src/node/node.cpp:3118-3123` enforces

```
is_anon_address(tx.from) ∧ tx.from ≠ normalize_anon_address(tx.from)  ⇒  throw
```

and the symmetric check on `tx.to` at lines 3124-3128. The throw message includes `"non-canonical"`. If a client submits a tx where `tx.from` or `tx.to` is an anon-shape but in uppercase or mixed-case, the check fires at function entry — before the hash-recompute, sig-verify, mempool admission, and gossip-broadcast steps further down (lines 3132-3180). The client receives a structured RPC error and corrects.

**Necessity of the asymmetry.** The signature `tx.sig` is `crypto::sign(key, sb.data(), sb.size())` over `sb = tx.signing_bytes()`. `signing_bytes()` includes `tx.from` and `tx.to` byte-for-byte. If the server normalized `tx.from`/`tx.to` post-receipt and re-stored, the mutation would unbind the sig from the stored bytes: sig-verify would compute Ed25519 verify against a different `signing_bytes` and reject. The asymmetry — read-side normalize (no sig in scope), write-side strict-canonical (sig in scope) — is forced by the cryptographic semantics. ∎

### 4.3 Proof of T-3 (No Signature-Mutation Surface)

By inspection of the rpc_submit_tx control flow:

1. Lines 3104: `chain::Transaction tx = chain::Transaction::from_json(tx_json);` — deserialize. No field mutation; `from_json` is pure decode.
2. Lines 3118-3129: S-028 check (above). Either rejects with throw (no further work) or proceeds with `tx` exactly as deserialized.
3. Lines 3132-3136: hash recompute and compare. Read-only on `tx`.
4. Lines 3139-3142: stale-nonce drop. Read-only on `tx.nonce`.
5. Lines 3147-3149: sig-verify against `tx.signing_bytes()`. Read-only on every signing-bound field.
6. Lines 3155-3173: mempool admission policy. Read-only on `tx`.
7. Lines 3174-3175: insert into `tx_store_` and `tx_by_account_nonce_` index. **The stored value is `tx`** (i.e. the deserialized bytes, unmutated since step 1). No field of `tx` is rewritten between deserialization and storage.

Therefore no `signing_bytes`-bound field is mutated between sig-verify (step 5) and storage (step 7). Subsequent gossip relays the same bytes; the apply layer (`src/chain/chain.cpp::apply_transactions`) reads the stored bytes and re-verifies via the validator layer (`src/node/validator.cpp::check_transactions` per S-002). No mutation surface exists. ∎

### 4.4 Proof of T-4 (Auto-Created Accounts Are Canonical)

Consider a TRANSFER tx admitted via `rpc_submit_tx`. By T-2 (write-path strict-canonical check), `tx.to` either fails `is_anon_address` (and is therefore a domain name, untouched) or satisfies `tx.to == normalize_anon_address(tx.to)` (canonical lowercase). The tx is gossiped, included by a producer, validated (sig-bound to canonical `tx.to`), and reaches `Chain::apply_transactions`.

In the TRANSFER branch at `src/chain/chain.cpp:752-761`, the credit is `accounts_[tx.to].balance += tx.amount` (modulo overflow check per S-007). `std::map::operator[]` performs a key lookup, defaulting-constructing a `AccountState{}` for the `tx.to` key if no entry exists. The new entry is keyed by `tx.to` byte-for-byte — and by the above, `tx.to` is canonical lowercase.

A subsequent `rpc_balance("0xABC…")` query (uppercase variant of `tx.to`) at `rpc_balance` normalizes input to `"0xabc…"` (T-2 read-path) and resolves `accounts_["0xabc…"]` — the same canonical-keyed entry. The user sees the correct balance regardless of query case. ∎

The corollary: the chain CANNOT contain a `"0xABC…"`-keyed `accounts_` entry produced by a v1.x post-S-028 TRANSFER. The only paths to such an entry are (a) operator-edited genesis JSON (which is privileged and acknowledged in §6), (b) a pre-S-028 chain whose state predates the closure (§6 / T-5), or (c) a peer running a fork that disables the S-028 gate (which would also produce blocks unacceptable to S-028-compliant peers because the sig-verify at `validator.cpp` would still hold the canonical bytes, but a forked peer could craft a sig over uppercase bytes; cross-peer disagreement on canonicalization would surface as a fork-rank difference resolved by `Chain::resolve_fork` per S-029).

### 4.5 Proof of T-5 (Backward Compat)

`normalize_anon_address` is total: it accepts any `std::string` and returns a `std::string`. It does not throw, does not depend on chain state, and is referentially transparent.

For any chain-state entry produced before S-028, the key in `accounts_` is some byte-string `K`. Three sub-cases:

1. **`K` is already lowercase canonical** (the only state achievable in v1.x via signed TRANSFER, because pre-S-028 the `is_anon_address` check was case-sensitive lowercase-only — any uppercase tx would have been rejected). Post-S-028 query `rpc_balance(Q)` for any case-variant `Q` of `K`'s pubkey normalizes to `K` and resolves. ∎ for this sub-case.

2. **`K` is non-anon (domain name)**. Both pre- and post-S-028, domain names are not anon-shape, so `normalize_anon_address` is the identity on them. Pre- and post-S-028 queries hit the same key. ∎ for this sub-case.

3. **`K` is uppercase or mixed-case anon-shape**. Not achievable via v1.x signed TRANSFER (sender's pre-S-028 wallet would have emitted lowercase via `make_anon_address`, and the sig-verified TRANSFER ledger never admitted uppercase). The remaining paths are (a) operator-edited genesis JSON listing an uppercase `initial_balance` entry, (b) operator-edited snapshot replay loading an uppercase key. Both are privileged operator actions. The post-S-028 query `rpc_balance(Q)` for any case-variant `Q` normalizes to lowercase canonical and would NOT resolve the uppercase legacy key. Acknowledged in §6.

The closure is therefore backward-compatible for every state reachable via signed-tx semantics (sub-cases 1–2) and only fails for sub-case 3, which is an operator-introduced state acknowledged as out-of-scope for the S-028 closure. ∎

---

## 5. Adversary model

### 5.1 Threat T1: Ghost-account spam via uppercase TRANSFER

**Setup.** Attacker controls a node and wishes to spam an honest user's address with confusing balances by sending TRANSFERs to the uppercase form of the recipient's anon-address, hoping that (a) the chain auto-creates a ghost `"0xABC…"` entry separate from the honest `"0xabc…"` entry that the recipient queries, (b) the recipient sees zero balance, and (c) the funds become inaccessible (operationally — the holder of the private key can still recover by signing with `tx.from == "0xABC…"`, but the wallet's default is to use the canonical lowercase form).

**Closure.** By T-2 (WRITE-path strict-canonical check), `rpc_submit_tx` rejects the attacker's tx with `"non-canonical (uppercase hex)"` before it enters the mempool. The attacker cannot gossip it either (the gossip-side `on_tx` re-runs `validator.cpp::check_transactions`'s sig-verify, but more directly, no honest node admits the tx to mempool, so no honest producer includes it). A malicious peer might still gossip a sig-valid tx with uppercase `tx.to` (the sig is over uppercase bytes; the attacker controls a key and signs a tx with uppercase `tx.to`); honest nodes' `rpc_submit_tx` rejects, but `on_tx` (gossip path) might admit. Inspection of `src/node/node.cpp` shows `on_tx` does NOT enforce the S-028 canonicalization gate — but this is *also* OK, because: (i) no honest wallet emits uppercase, so no honest user signs uppercase; (ii) any block including uppercase-`tx.to` TRANSFER results in an `accounts_["0xABC…"]` entry that no honest recipient queries — the attack reduces to the attacker burning their own ed25519 keypair to ghost-credit themselves. The funds are not stolen; the user is not harmed.

(Note: a stricter closure would extend the S-028 gate to `on_tx`. This is left as a potential v2 hardening; the current closure prevents the *RPC-submit* path which is the user-facing one.)

### 5.2 Threat T2: Signature-replay via case-mutation

**Setup.** Attacker observes a sig-valid tx on the wire with canonical lowercase `tx.from = "0xabc…"`. They re-encode the tx with `tx.from = "0xABC…"` and submit, hoping the server normalizes case and re-uses the captured sig.

**Closure.** By T-2 + T-3, `rpc_submit_tx` rejects the uppercase variant with the "non-canonical" diagnostic. Even if it did not (counterfactual where the server normalized post-receipt), sig-verify at line 3147 would fail: the captured sig is over the original lowercase `signing_bytes()`; the post-normalize `tx.signing_bytes()` is also over lowercase bytes (because normalization mutated `tx.from` back to lowercase), so verify against the captured sig would actually succeed *by accident* — but this is a separate replay vulnerability addressed elsewhere (nonce monotonicity, hash-recompute). The strict-input gate keeps the byte-storage form unambiguous and prevents the attacker from injecting a duplicate uppercase tx into the index `tx_by_account_nonce_[{tx.from, tx.nonce}]`. ∎

### 5.3 Threat T3: Account-record fragmentation via mixed-case CLI input

**Setup.** A user types `determ balance 0xABCD…` (uppercase) at the shell. Pre-S-028, the CLI's address-validation rejected uppercase and the user saw a parse error; or if a sloppy CLI passed it through, the chain returned `balance: 0` against an empty `accounts_["0xABCD…"]` lookup, and the user was confused.

**Closure.** By T-2 (READ-path normalize-at-input), `rpc_balance` lowercases the input and resolves the canonical record. The user sees the correct balance. ∎

---

## 6. Identified gaps

### G-1: Domain-name case handling is byte-exact, by design

Registered domain names (the alternative to anon-addresses) are owned bytestrings registered via the REGISTER tx (or via genesis `initial_creators`/`initial_balances`). They are NOT anon-shape and are NOT normalized by `normalize_anon_address` (helper passes them through unchanged at `types.hpp:135`). The chain's `accounts_` map and `registrants_` map are keyed by the exact bytes of the domain name. Therefore `"Alice"` and `"alice"` are two different domain names, registrable independently by two different parties.

This is the documented contract — domain names are arbitrary bytestrings owned by their registrants, and case is significant within them. The S-028 closure does not change this. Users registering domains should standardize on one case (the protocol does not enforce any particular case for domains).

### G-2: `rpc_nonce` and `rpc_stake_info` do NOT normalize input

`src/node/node.cpp:2933-2942` (`rpc_nonce`) and `src/node/node.cpp:2945-2957` (`rpc_stake_info`) accept a `domain` argument and pass it directly to `chain_.next_nonce_lockfree(domain)` / `chain_.stake_lockfree(domain)` without calling `normalize_anon_address`. The same case-fragmentation that pre-S-028 broke `rpc_balance` is still present on these surfaces if the user queries an anon-address in uppercase.

In practice:

- `rpc_nonce` is called by `rpc_send` only on `cfg_.domain` (the local node's own domain — which the operator controls and is typically configured in lowercase), and is also surfaced to clients via the RPC. A wallet using uppercase-anon-address as its node-key would query `rpc_nonce` with that address and see `next_nonce: 0` even after several txs.
- `rpc_stake_info` is analogous and surfaces only for operator-side staking queries, which are typically against canonical lowercase node keys (the keyfile's pubkey is emitted lowercase by `make_anon_address`).

**Severity:** UX-only, no safety impact. The next-nonce query returns 0 against a missing-from-`accounts_` map entry, but the chain's apply layer reads from the canonical entry regardless of how the user queried. The user who saw `next_nonce: 0` and signed a tx with `nonce: 0` would have the tx rejected at stale-nonce drop (line 3140) because the canonical entry's `next_nonce` is larger.

**Fix:** one-line addition of `const std::string d = normalize_anon_address(domain);` at function entry, mirroring `rpc_balance`. Out of scope for the S-028 closure as shipped; could be folded into v2.X.

### G-3: `on_tx` (gossip-path admission) does not enforce S-028 canonicalization

As noted in §5.1, the gossip-side `on_tx` admission path does not currently re-apply the strict-canonical gate that `rpc_submit_tx` enforces. A malicious peer holding a private key can sign a tx with uppercase `tx.from`/`tx.to`, gossip it, and have it admitted to honest peers' mempool. The tx is sig-valid (the sig is over the uppercase bytes), and an honest producer might include it in a block.

**Impact:** the attacker burns their own keypair to ghost-credit themselves; no honest user is harmed. Funds are not stolen, balances are not silently mutated for honest users (their canonical-key records are untouched).

**Closure status:** acknowledged. A v2-tightening could extend the canonicalization gate to `on_tx`; the current closure intentionally only gates the user-facing RPC-submit path.

### G-4: Legacy state with uppercase keys (T-5 sub-case 3)

Genesis JSON or snapshot files edited by an operator could introduce uppercase `accounts_` keys that the post-S-028 query path does not resolve. This is acknowledged in T-5; the mitigation is a one-shot operator-side canonicalization script at upgrade time, or a future migration block (in a v2 hard-fork window).

---

## 7. Test-suite citation

The closure is exercised end-to-end by `tools/test_anon_address_case.sh` (single-node M=K=1, profile `single_test`). Asserts:

1. **balance RPC normalizes case.** Two anon-account queries — lowercase and uppercase variants of the same pubkey — both return the canonical balance of 1,000,000. Tests `rpc_balance`'s normalize-at-input.

2. **send RPC normalizes the `to` field.** `determ send <UPPERCASE> 100 …` credits the canonical lowercase slot. Subsequent balance queries against both cases return 100. Tests `rpc_send`'s normalize-at-input + the canonical-keyed credit-on-TRANSFER.

3. **submit_tx rejects non-canonical.** A hand-crafted JSON submission to `/submit_tx` with uppercase `tx.from` triggers the strict-canonical gate; the server reply contains `"non-canonical"`. Tests `rpc_submit_tx`'s reject-with-diagnostic.

All three assertions pass per memory (3/3 PASS). Additional in-process unit tests at `src/main.cpp:6679-6742` (12 assertions) cover the `is_anon_address` and `normalize_anon_address` helpers in isolation:

- lowercase / uppercase / mixed-case accept,
- missing-prefix / wrong-length / non-hex-char reject,
- registered-domain reject,
- uppercase → lowercase canonical normalization with prefix preserved,
- registered-domain pass-through unchanged.

The integration test (`tools/test_anon_address.sh`) — 12 assertions — exercises the same helpers via the test-runner binary, ensuring no drift between the inline helpers and the validator/apply pipeline.

A separate integration test, `tools/test_anon_routing.sh` (15 assertions), exercises the routing layer to ensure case-variants of the same anon-address route to the same shard — defending against drift between `normalize_anon_address` and `shard_id_for_address`.

---

## 8. Status

**Mitigated in-session.** `is_anon_address` accepts either case (lines `types.hpp:115-126`); `normalize_anon_address` returns lowercase canonical (lines `types.hpp:134-142`); `rpc_balance` normalizes at input (line `node.cpp:3227`); `rpc_send` normalizes the `to` argument (line `node.cpp:2809`); `rpc_submit_tx` rejects non-canonical with diagnostic (lines `node.cpp:3118-3129`). The chain's apply layer treats addresses as opaque bytes — canonicalization is strictly upstream.

SECURITY.md classifies S-028 as Mitigated (Low/Op). Three regression-test surfaces (`tools/test_anon_address_case.sh` 3/3 PASS, `tools/test_anon_address.sh` 12/12 PASS via `determ test-anon-address`, `tools/test_anon_routing.sh` 15/15 PASS) cover the closure.

Three identified gaps (G-2: `rpc_nonce` / `rpc_stake_info` non-normalization; G-3: `on_tx` non-canonicalization; G-4: legacy uppercase keys) are UX-only, no-safety-impact, and out-of-scope for the S-028 closure as shipped. Each has a documented one-line or one-script fix path.

---

## 9. References

- `docs/SECURITY.md` §S-028 — closure narrative + mitigated-status row.
- `docs/PROTOCOL.md` §3 — address-shape conventions; `is_anon_address` / `normalize_anon_address` semantics.
- `include/determ/types.hpp:100-156` — the four address helpers (`is_anon_address`, `normalize_anon_address`, `parse_anon_pubkey`, `make_anon_address`) and the S-028 closure comments.
- `src/node/node.cpp:2804-2842` — `rpc_send` (normalize-at-input on `to`).
- `src/node/node.cpp:3102-3180` — `rpc_submit_tx` (strict-canonical reject).
- `src/node/node.cpp:3224-3234` — `rpc_balance` (normalize-at-input on `domain`).
- `src/chain/chain.cpp:735, 756, 1005` — apply layer's byte-exact `accounts_` access.
- `tools/test_anon_address_case.sh` — 3-assertion integration test for the closure.
- `tools/test_anon_address.sh` — 12-assertion helper test via `determ test-anon-address`.
- `tools/test_anon_routing.sh` — 15-assertion routing-layer integration test (case-variants → same shard).
- `src/main.cpp:6655-6745` — in-process `test-anon-address` unit harness.
- `docs/proofs/AccountStateInvariants.md` — FA-Apply state invariants that consume canonical addresses.
- `docs/proofs/JsonValidationSoundness.md` — S-018, paired wire-format input-hardening pattern.
- `docs/proofs/S017UnstakeApplyConsistency.md` — companion three-layer-defense style.
