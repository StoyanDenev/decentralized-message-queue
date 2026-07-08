# RpcAuthHmacSoundness — v2.16 HMAC-SHA-256 RPC auth (S-001 closure)

This document proves that Determ's v2.16 HMAC-based RPC authentication is sound under standard HMAC-SHA-256 security assumptions. The scheme — closing the cross-tenant / external-bind half of S-001 — wraps every RPC request in a `hex(HMAC-SHA-256(secret, method || "|" || params_canonical_json))` envelope; the server recomputes the HMAC under its locally-stored secret and accepts the request iff the constant-time comparison matches. We prove the unforgeability, the constant-time-compare property, the secret-confidentiality property at the implementation surface, and the HMAC-SHA-256 forgery bound. We also surface a known limitation (replay) and one configuration-surface finding (plaintext at-rest persistence of the secret in the operator's config JSON).

The proof is a short cryptographic argument followed by an audit of `src/rpc/rpc.cpp::verify_auth` against the four operational requirements (T-1..T-4) and the underlying primitive's standard-model security (T-5). It exists to make the cross-tenant authentication argument explicit so an external auditor can confirm the S-001 closure without re-reading the source: the protocol-level surface is the HMAC primitive plus the constant-time compare; everything else (secret distribution, transport encryption, replay defense) is operator-or-future-work scope and called out as such.

**Companion documents:** `Preliminaries.md` (F0) §2.1 (SHA-256 collision resistance, the H1-style assumption this proof reduces to) + §2.2 (Ed25519 EUF-CMA, referenced only by analogy for the EUF-CMA-style game in T-1); `SECURITY.md` §3 S-001 for the closure-status narrative this proof formalizes; `EquivocationSlashing.md` (FA6) for the citation style and the soundness-against-honest-key family of arguments; `MakeContribCommitmentBackwardCompat.md` for the structural-disjointness style used here in §4 lemmas L-2 + L-3.

---

## 1. Theorem statements

**Setup.** Let `K ∈ {0,1}*` denote the server's `auth_secret_` field — a byte string produced by `hex_to_bytes(rpc_auth_secret)` at server construction (`src/rpc/rpc.cpp:90`). Let `S := |K|` be the key length in bytes. Operator policy in `docs/SECURITY.md` §3 + `docs/CLI-REFERENCE.md` §17 fixes the recommended generation as `openssl rand -hex 32`, so the canonical key length is `S = 32` bytes (256 bits of entropy). Let `HMAC : ({0,1}*) × ({0,1}*) → {0,1}²⁵⁶` denote HMAC-SHA-256 per RFC 2104 + FIPS 198, instantiated by OpenSSL `HMAC(EVP_sha256(), ...)` at `src/rpc/rpc.cpp:60-70`. Let `canonical(method, params) := method ‖ "|" ‖ params.dump()` denote the canonical request serialization (`src/rpc/rpc.cpp:52-58`), where `params.dump()` is nlohmann-json's deterministic compact-mode dump (sorted keys for objects per the library spec, used by both client and server so the parse-then-dump round trip on the server reproduces the client's pre-send bytes).

A request triple `(method, params, auth)` is **valid** iff:

```
auth = hex(HMAC(K, canonical(method, params)))
```

and the constant-time loop at `src/rpc/rpc.cpp:122-128` returns `diff == 0`.

**Theorem T-1 (Authentication soundness).** Under:

- **(A_HMAC) HMAC-SHA-256 PRF security** (this document §2.1 + RFC 2104): HMAC-SHA-256 keyed by a uniformly-random key `K ←ᵤ {0,1}²⁵⁶` is a PRF; no polynomial-time adversary, given oracle access to `HMAC(K, ·)`, distinguishes its outputs from a uniform random function with non-negligible advantage. Concrete bound: an adversary making `q` queries has distinguishing advantage `≤ q² / 2^256 + ε_compress`, where `ε_compress` is the SHA-256 compression-function's PRF advantage (assumed `≤ 2^{-128}` by the standard cryptanalytic margin on SHA-256).
- **(K_random) Uniform key distribution** (this document §2.2 + Preliminaries §2.3): operator generates `K` via a CSPRNG with min-entropy `≥ 256` bits per draw (operator follows the `openssl rand -hex 32` recommendation; OpenSSL `RAND_bytes` is the underlying source, identical to the assumption Preliminaries §2.3 makes for Phase-1 secrets).
- **(H1) SHA-256 collision resistance** (Preliminaries §2.1): no polynomial-time adversary finds `x ≠ y` with `SHA256(x) = SHA256(y)` with probability non-negligibly better than `2⁻¹²⁸`.

then for every adversary `A` that has never queried `HMAC(K, ·)` on the canonical bytes of `(method*, params*)`, the probability that `A` outputs a valid triple `(method*, params*, auth*)` is

$$
\Pr\!\bigl[\texttt{verify\_auth}(\texttt{method}^*, \texttt{params}^*, \texttt{auth}^*) = 0_{\text{accept}}\bigr] \;\leq\; 2^{-256} + q^2 / 2^{256} + \mathrm{negl}(\lambda).
$$

per single forgery attempt, where `q` is the number of HMACs the adversary has observed (e.g., from passively-eavesdropped legitimate traffic). Over `Q` attempts the cumulative bound is `Q · 2⁻²⁵⁶ + q² / 2^256`, which remains negligible for any operational `Q` and `q`.

**Theorem T-2 (Replay analysis / known limitation).** The `auth` field is a deterministic function of `(K, method, params)` only — it carries no nonce, no timestamp, no sequence number. An adversary `A` who eavesdrops a single valid triple `(method, params, auth)` from the wire (e.g., over an unencrypted localhost socket the adversary co-tenants on, or a non-TLS reverse-proxy hop) can replay the same triple indefinitely against the same server, and `verify_auth` will accept every replay. The protocol does NOT defend against replay in v2.16. The closure documents this as a **known limitation** scoped out of S-001's primary "unauthenticated requests" surface; the recommended mitigation (per-request nonce or timestamp + sliding-window-acceptance) is a follow-on, tracked in `docs/SECURITY.md` §3 S-001's threat-model matrix under "Replay of authenticated requests by MITM: NOT addressed in v2.16."

**Theorem T-3 (Constant-time comparison).** The `verify_auth` HMAC compare at `src/rpc/rpc.cpp:122-128` is constant-time: every byte of `expected` is XOR-OR'd into a single accumulator `diff` over a fixed-length loop, with no early `return`/`break`/`continue` inside the loop body. The early `expected.size() != got.size()` check at line 123 is a length comparison only, and `expected.size()` is the fixed constant `64` (the hex-encoded length of HMAC-SHA-256 output), so the length comparison reveals no information about `K`. T-3 is verified by inspection (this document §4 L-3).

**Theorem T-4 (Secret confidentiality at the implementation surface).** The `auth_secret_` field is never written to any log, error response, or wire message by `src/rpc/rpc.cpp`. The startup log at `src/rpc/rpc.cpp:95-97` emits the secret's *length in bytes* (`auth_secret_.size()`) but never the secret value. The `verify_auth` error returns (lines 115, 128) are fixed string constants (`"auth_required: missing 'auth' field"`, `"auth_failed"`) with no dependence on `K`, `expected`, or any per-key data. T-4 is verified by inspection (this document §4 L-4).

A configuration-surface caveat is registered in §6: `Config::to_json` (`src/node/node.cpp:30`) persists `rpc_auth_secret` in plaintext to the operator's config JSON. This is outside the RPC server's scope and is documented as a finding, not a defect of the HMAC scheme itself.

**Theorem T-5 (HMAC-SHA-256 scheme soundness).** Under H1 (SHA-256 collision resistance) and the Merkle–Damgård composition that backs SHA-256 + HMAC, HMAC-SHA-256 is a PRF (by the standard Bellare–Canetti–Krawczyk 1996 result, hardened by Bellare 2006). The single-query forgery probability is `≤ 2⁻²⁵⁶` (uniform random function output collision); the q-query existential-forgery advantage is `≤ q² / 2^256 + 2⁻¹²⁸` (the dominant term is the birthday-collision among the q queries' internal compression-function inputs, plus the compression-function's PRF advantage). For all operational `q ≪ 2^128`, this is negligible.

---

## 2. Background

### 2.1 The HMAC primitive

HMAC was defined by Bellare, Canetti, and Krawczyk in CRYPTO 1996 and standardized in RFC 2104 (Krawczyk, Bellare, Canetti, Feb 1997) + FIPS 198 (NIST, Mar 2002 / revised 198-1 Jul 2008). Given a hash function `H : {0,1}* → {0,1}^n` with block size `B` bytes (for SHA-256, `n = 256` bits and `B = 64` bytes) and a key `K`:

```
HMAC(K, m) := H((K' ⊕ opad) ‖ H((K' ⊕ ipad) ‖ m))
```

where `K' := K` if `|K| = B`, else `K' := H(K) ‖ 0…0` (padded to `B`), `ipad := 0x36 × B`, `opad := 0x5C × B`. The double-call structure provides PRF security under H's compression-function PRF security (Bellare 2006, "New Proofs for NMAC and HMAC: Security Without Collision-Resistance"); the original 1996 paper required compression-function collision-resistance, but Bellare's 2006 reduction is tighter.

Crucially, HMAC-SHA-256's PRF security is **standard-model**: no random-oracle assumption on `H` is needed. The q-query distinguishing advantage is bounded by

```
Adv^{PRF}_{HMAC-H}(q, t) ≤ Adv^{PRF}_{H_compression}(q, t) + q² / 2^c
```

where `c = 256` is SHA-256's chaining-variable size. For all operational `q ≪ 2^128`, this is negligible.

### 2.2 The HMAC scheme in v2.16 RPC auth

The protocol surface is:

- Client computes `auth = hex(HMAC(K, method ‖ "|" ‖ params.dump()))` and sends `{"method": ..., "params": ..., "auth": ...}` over a TCP connection (loopback by default per S-001's localhost-only mitigation; or externally if the operator opted out and set the secret).
- Server, on receiving a line, parses JSON, calls `verify_auth(req)`:
  1. If `auth_secret_` is empty (auth disabled), accept (line 113). This preserves the no-auth path for single-tenant boxes.
  2. If the request lacks `"auth"` or it's not a string, return `"auth_required: missing 'auth' field"` (lines 114-116).
  3. Recompute `expected = hex(HMAC(K, canonical(method, params)))` (lines 117-120).
  4. Constant-time compare `expected` vs `got` (lines 122-128). Mismatch → `"auth_failed"`.

The canonicalization step relies on nlohmann::json's deterministic `dump()` (compact mode, sorted keys for `json::object`). Both client and server parse the same `params` object — the client builds it locally, dumps; the server receives the line, parses, then re-dumps via the same library. The parse-then-dump round trip on the server reproduces the client's pre-send bytes because nlohmann's `parse + dump(compact)` is a canonical-form fixpoint for objects with string keys.

### 2.3 S-001 closure context

S-001 originally documented two adversaries:

1. **Network-reachable unauthenticated RPC.** Closed by Option 1 (localhost-only default at `src/rpc/rpc.cpp:79-89`).
2. **Cross-tenant on the same host** (e.g., another user on a shared box with localhost access to the RPC port). Closed by Option 3 (HMAC RPC auth — this proof's subject).

S-001's threat-model matrix in `docs/SECURITY.md` §3 explicitly carries Option 3's status:

> Cross-tenant on the same host (multi-user box): closed (option 3 — attacker without secret cannot forge requests)

T-1 below formalizes this "attacker without secret cannot forge requests" claim under the HMAC-SHA-256 PRF assumption.

The matrix also explicitly carries a residual:

> Replay of authenticated requests by MITM: NOT addressed in v2.16. Replay protection (per-request nonce + sequence) is a follow-on; S-001's primary issue (unauthenticated requests) is fully closed.

T-2 below formalizes this residual.

---

## 3. Implementation citation

The proof's primary object — `RpcServer::verify_auth` — at `src/rpc/rpc.cpp:112-129`:

```cpp
std::string RpcServer::verify_auth(const json& req) const {
    if (auth_secret_.empty()) return ""; // Auth disabled, pass.            // line 113
    if (!req.contains("auth") || !req["auth"].is_string()) {                // line 114
        return "auth_required: missing 'auth' field";                       // line 115
    }
    std::string method = req.value("method", "");                           // line 117
    auto params = req.value("params", json::object());                      // line 118
    std::string expected = hmac_sha256_hex(auth_secret_,                    // line 119
                                              canonical_for_hmac(method, params));
    std::string got = req.value("auth", std::string{});                     // line 121
    // Constant-time compare to avoid timing side-channels.
    if (expected.size() != got.size()) return "auth_failed";                // line 123
    int diff = 0;                                                           // line 124
    for (size_t i = 0; i < expected.size(); ++i) {                          // line 125
        diff |= (expected[i] ^ got[i]);                                     // line 126
    }                                                                       // line 127
    return (diff == 0) ? "" : "auth_failed";                                // line 128
}
```

The underlying HMAC primitive at `src/rpc/rpc.cpp:60-70`:

```cpp
std::string hmac_sha256_hex(const std::vector<uint8_t>& key,
                              const std::string& message) {
    unsigned char hmac[32];
    unsigned int  hmac_len = 0;
    HMAC(EVP_sha256(),
         key.data(),  static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(message.data()),
         message.size(),
         hmac, &hmac_len);
    return bytes_to_hex(hmac, hmac_len);
}
```

OpenSSL's `HMAC(EVP_sha256(), ...)` implements RFC 2104 with SHA-256 backing. The output is exactly 32 bytes (256 bits), hex-encoded by `bytes_to_hex` (lines 31-37) to produce a 64-character hex string.

The canonical-serialization helper at `src/rpc/rpc.cpp:52-58`:

```cpp
std::string canonical_for_hmac(const std::string& method, const json& params) {
    return method + "|" + params.dump();
}
```

The constructor accepts a hex-encoded secret and converts to bytes (`src/rpc/rpc.cpp:86-94`; the `asio::io_context&` parameter shown in earlier revisions of this doc was replaced by the minix `net::Transport&`/`net::EventLoop&` seam in the net::Transport slice B migration — the HMAC contract below is unaffected, since auth verification never touched the transport type):

```cpp
RpcServer::RpcServer(net::Transport& transport, net::EventLoop& loop,
                       node::Node& node, uint16_t port,
                       bool localhost_only, const std::string& auth_secret_hex,
                       double rate_per_sec, double burst)
    : transport_(transport)
    , loop_(loop)
    , node_(node)
    , acceptor_(transport_.listen(port, localhost_only))
    , auth_secret_(hex_to_bytes(auth_secret_hex)) {
    ...
}
```

The startup log at `src/rpc/rpc.cpp:96-108` emits only the length (`auth_secret_.size()`) — never the value.

The dispatch ordering at `src/rpc/rpc.cpp:161-209` (inside `handle_session`) runs rate-limit *before* parse, then auth *after* parse-but-before-dispatch (necessary because computing the expected HMAC requires the parsed `method` and `params`). The ordering is documented inline as a deliberate choice: rate-limited callers should not even reveal whether their auth was valid.

---

## 4. Lemmas and proofs

### Lemma L-1 (HMAC-SHA-256 single-query unforgeability under PRF security)

Under (A_HMAC) HMAC-SHA-256 PRF security with a uniform key `K ←ᵤ {0,1}²⁵⁶` (K_random), for any adversary `A` that has never queried `HMAC(K, m*)` for a particular `m* ∈ {0,1}*`, the probability that `A` outputs `t* = HMAC(K, m*)` is bounded by `2⁻²⁵⁶ + ε_PRF(q, t)` where `ε_PRF(q, t)` is `A`'s distinguishing advantage in the PRF game with `q` queries and running time `t`.

**Proof sketch.** By the standard PRF-to-MAC reduction (Bellare–Goldwasser–Micali 1984, formalized for HMAC in Bellare 2006), if `A` forges with probability `p`, we construct a PRF distinguisher `D` that uses `A`'s output as a guessed value for `HMAC(K, m*)` and tests against the oracle: `D` queries the oracle on `m*` (which `A` did not query) and compares against `A`'s guess. If the oracle is a random function, the probability of `A` guessing correctly is exactly `2⁻²⁵⁶`. If the oracle is `HMAC(K, ·)`, the probability is `p`. So `|p - 2⁻²⁵⁶| ≤ ε_PRF(q+1, t + t_A)`, giving `p ≤ 2⁻²⁵⁶ + ε_PRF`.   □

### Lemma L-2 (Canonical serialization is a function — same `(method, params)` ⇒ same input to HMAC)

The function `canonical_for_hmac(method, params) := method + "|" + params.dump()` is a deterministic byte function of its inputs. The `+` operator on `std::string` is byte-concatenation; `params.dump()` is nlohmann::json's compact-mode dump, which is a deterministic function of the parsed JSON object's content (per nlohmann::json's documented spec: sorted keys for `json::object`, no whitespace, fixed integer/float canonicalization).

For the client/server agreement property, both sides must hash the same bytes:

- The client builds `params` as a `json` object locally, calls `params.dump()`, and uses the result.
- The server receives the JSON line, parses with `json::parse(line)`, then calls `req.value("params", json::object()).dump()`.

For the round-trip to be a fixpoint (i.e., for `dump(parse(line))` to equal the client's original `dump(...)`), the client's `dump(...)` output must be canonical. nlohmann::json's compact mode satisfies this provided the client's `params` object had no sentinel-encoded integers (e.g., trailing zeros in floats, leading-zero ints). For the v2.16 RPC API surface, all parameter values are either `std::string`, integral `uint64_t`/`uint32_t`, or simple `json::object` of these — none of which exhibit the round-trip non-fixpoint behavior.

The pinning regression at `tools/test_rpc_hmac_auth.sh` (assertions 1-5) exercises this end-to-end with concrete `(method, params)` pairs and confirms client-server agreement on the canonical bytes.   □

### Lemma L-3 (`verify_auth` HMAC compare is constant-time)

The comparison at `src/rpc/rpc.cpp:122-128` consists of two phases:

1. **Length pre-check** (line 123): `if (expected.size() != got.size()) return "auth_failed";`. The `expected.size()` is a function of `hmac_sha256_hex`'s output, which is always exactly 64 bytes (the hex encoding of HMAC-SHA-256's 32-byte output). It does NOT depend on `K`. The `got.size()` is a function of the adversary's input only — the attacker controls it. The length check therefore reveals only "the attacker sent a non-64-byte hex string," which is no information about `K` (the attacker already knew the length they sent).

2. **Constant-time XOR-OR loop** (lines 124-128):

```cpp
int diff = 0;
for (size_t i = 0; i < expected.size(); ++i) {
    diff |= (expected[i] ^ got[i]);
}
return (diff == 0) ? "" : "auth_failed";
```

The loop executes exactly `expected.size() == 64` iterations regardless of byte-by-byte equality. The body is a constant-time bitwise XOR followed by a constant-time bitwise OR-assign — both are register-level operations on a `int` accumulator with no conditional branch dependent on `expected[i]` or `got[i]`. The final ternary `(diff == 0) ? "" : "auth_failed"` is the only branch; it depends on the *aggregate* `diff` over the whole comparison, not on any individual byte. The ternary's two branches both return a `std::string`; modern compilers compile this to a conditional move (`cmov`) on x86-64 / `csel` on ARM64, but even if compiled to a conditional branch, the timing information leaked is "all 64 bytes matched vs. ≥ 1 mismatched" — a single bit of aggregate information, useless to an attacker probing per-byte secret material.

The implementation is functionally equivalent to OpenSSL's `CRYPTO_memcmp` (which is similarly an XOR-OR loop, no early exit). Determ rolls its own here rather than calling `CRYPTO_memcmp` because the inputs are `std::string` (`std::char_traits<char>`), not opaque buffers; the std::string accessor `expected[i]` is `operator[]` which is `noexcept` and reduces to a direct byte access at -O1+.

**Caveat (not a finding):** the constant-time guarantee depends on the compiler not transforming the loop into a memcmp-style early-exit. The Determ build pins on `-O2` for release builds and the loop's structural form (independent XOR-OR on every iteration, no early-exit predicate) prevents standard compiler vectorizers from inserting an early-exit. A defense-in-depth measure would be to add `__attribute__((noinline))` or use `volatile`-qualified accumulator. This is documented in §6 as a minor hardening recommendation, not a defect.   □

### Lemma L-4 (No secret material flows to logs, error responses, or wire)

Audit of `src/rpc/rpc.cpp` for any flow of `auth_secret_` to an output sink:

| Sink | Reference | Behavior |
|---|---|---|
| `std::cout` startup log | `src/rpc/rpc.cpp:96-97` | Logs `auth_secret_.size()` (length in bytes), not the value. |
| `std::cout` external-bind warning | `src/rpc/rpc.cpp:101-103` | Static text; no secret reference. |
| `verify_auth` error return — missing auth | `src/rpc/rpc.cpp:115` | Static string `"auth_required: missing 'auth' field"`. |
| `verify_auth` error return — wrong auth | `src/rpc/rpc.cpp:128` | Static string `"auth_failed"`. |
| `expected` HMAC value | `src/rpc/rpc.cpp:119-120` | Computed locally, compared to `got`, never written. |
| `handle_session` exception path | `src/rpc/rpc.cpp:188-191` | Echoes `e.what()` from a parse failure; not derived from `auth_secret_` (the auth check happens AFTER successful parse). |
| Response envelope | `src/rpc/rpc.cpp:192-193` | `response.dump() + "\n"`; the response has only `"result"` + `"error"` fields, neither populated from `auth_secret_`. |

No flow leaks `auth_secret_` to any stdout/stderr/network sink. The startup-log length disclosure is a deliberate operational signal ("HMAC auth enabled, N-byte secret") that confirms to the operator the secret was parsed correctly — this is the standard pattern for cryptographic-key-loaded logs (libsodium, openssl, libssh all do similar), and revealing only the length leaks no information about the key value (assuming the operator chose the recommended 32-byte length, which is also the documented best practice).

The `dispatch` method at `src/rpc/rpc.cpp:197-272` doesn't touch `auth_secret_` at all — it only reads `method` and `params` from the parsed request.

The `rpc_call` client at `src/rpc/rpc.cpp:276-321` reads the secret from either the explicit argument or `DETERM_RPC_AUTH_SECRET` env var (line 294), computes the HMAC, and embeds it in the request. The secret itself is never written to any output (and the request payload carries only the HMAC, not the secret).   □

### Lemma L-5 (HMAC-SHA-256 q-query forgery bound)

By A_HMAC (HMAC-SHA-256 PRF security), the adversary's q-query distinguishing advantage is

$$
\mathrm{Adv}^{\mathrm{PRF}}_{\mathrm{HMAC-SHA256}}(q, t) \;\leq\; \mathrm{Adv}^{\mathrm{PRF}}_{\mathrm{SHA256\text{-}comp}}(q, t) + q^2 / 2^{256}.
$$

The first term is the SHA-256 compression-function PRF advantage, bounded by the best known cryptanalysis as `≤ 2⁻¹²⁸` (the dominant bound is the SHA-256-comp's PRF margin under known attacks; this is conservative). The second term is the birthday collision among the q queries' internal compression-function chaining values.

A single-query forgery (q = 1, the attacker tries one guess with no observations) succeeds with probability `≤ 2⁻²⁵⁶` (uniform random output on 256 bits). A q-query forgery (the attacker has observed q legitimate HMACs from eavesdropping) succeeds with the q² / 2^256 birthday term as the dominant factor, which remains `≤ 2⁻¹²⁸` for `q ≤ 2^64` (a generous bound on operational observable traffic over the chain's lifetime).   □

---

## 5. Proofs of T-1 .. T-5

**Proof of T-1 (Authentication soundness).** Fix an adversary `A` with no knowledge of `K`. `A` has eavesdropped `q` legitimate request/response pairs from the wire, yielding `q` (canonical_bytes_i, auth_i) pairs where `auth_i = HMAC(K, canonical_bytes_i)`. `A` outputs a forgery candidate `(method*, params*, auth*)` with the constraint that `canonical(method*, params*) ∉ {canonical_bytes_1, …, canonical_bytes_q}` (otherwise it's a replay, not a forgery; replay is T-2).

By L-1, the probability that `auth* = HMAC(K, canonical(method*, params*))` is bounded by `2⁻²⁵⁶ + Adv^{PRF}_{HMAC-SHA256}(q+1, t_A)`. By L-5, the PRF advantage is bounded by `2⁻¹²⁸ + (q+1)² / 2^256`. For all operational `q ≤ 2^64`, the cumulative bound is

$$
\Pr[\text{forgery accepted}] \;\leq\; 2^{-256} + 2^{-128} + q^2 / 2^{256} \;\leq\; 2^{-128} + \mathrm{negl}(\lambda).
$$

By the `verify_auth` flow at `src/rpc/rpc.cpp:112-129` + L-2 (canonical serialization is a function), the server's computed `expected` is exactly `HMAC(K, canonical(method*, params*))`. By L-3 (constant-time compare), the comparison reveals only `diff == 0` vs `diff ≠ 0`, with no per-byte leakage. The server therefore accepts iff `auth* = HMAC(K, canonical(method*, params*))`, which by the above bound happens with probability ≤ negligible. The 2⁻²⁵⁶ bound stated in the theorem is the single-query case (q = 0); the q² / 2^256 q-query term is the more pessimistic bound for an attacker who has eavesdropped substantial traffic.   ∎

**Proof of T-2 (Replay analysis).** Inspect `verify_auth` at `src/rpc/rpc.cpp:112-129`. The function's accept condition is purely:

```
auth == hex(HMAC(K, method ‖ "|" ‖ params.dump()))
```

with no reference to:

- A nonce field in the request.
- A timestamp.
- A monotonic sequence number.
- Any per-session state.

Therefore for any captured legitimate triple `(method, params, auth)`, every byte-identical replay against the same server (same `K`) produces `expected = auth` and `verify_auth` accepts. The replay attack is constructive: the attacker captures one legitimate triple over the wire (e.g., via co-tenant tcpdump on loopback, or a non-TLS reverse-proxy hop) and re-sends it; the server accepts.

This is a known limitation explicitly scoped out of v2.16 per S-001's closure narrative in `docs/SECURITY.md` §3:

> Replay of authenticated requests by MITM: NOT addressed in v2.16.

**Recommended mitigation (for a future v2.x):** add either:

- A monotonically-increasing client-side nonce (`auth_nonce`) included in the HMAC input + server-side per-secret high-water mark to reject `auth_nonce ≤ last_seen`.
- A timestamp (`auth_ts_ms`) included in the HMAC input + server-side sliding-window acceptance (e.g., `|now - auth_ts_ms| ≤ 30s`, matching the V14 block-timestamp window from `docs/proofs/Preliminaries.md` §5).

The timestamp option is simpler (no per-client state required) but requires loosely synchronized clocks (acceptable given V14 already requires the same loose synchrony for block timestamps). Either option closes the replay surface at the cost of one extra field in the request envelope and ~10 LOC in `verify_auth`. The implementation is straightforward; the proof would extend the canonical-bytes definition to `canonical(method, params, nonce_or_ts)` and re-derive T-1 with the same PRF reduction.   ∎

**Proof of T-3 (Constant-time comparison).** Direct from L-3. The XOR-OR loop at `src/rpc/rpc.cpp:124-127` executes a fixed 64 iterations with no early exit; the per-iteration body is `diff |= (expected[i] ^ got[i])` which has no branch dependence on `expected[i]` or `got[i]`. The aggregate accumulator `diff` is then tested once at line 128 — a single conditional whose information content is "all 64 bytes matched vs. ≥ 1 mismatch," not per-byte.

The audit conclusion: **T-3 PASSES**. The implementation is constant-time. No finding is registered in §6 for the core compare; a minor defense-in-depth recommendation (compiler-attribute hardening) is noted as advisory only.   ∎

**Proof of T-4 (Secret confidentiality at the implementation surface).** Direct from L-4. No flow of `auth_secret_` reaches any output sink in `src/rpc/rpc.cpp`. The startup-log length disclosure is the only side-channel; revealing `|K|` reveals at most `log_2(operational_key_lengths)` bits of information — for the documented operator choice of `S = 32`, this is zero bits (every operator follows the same recommendation).

The audit conclusion at the RPC-server surface: **T-4 PASSES**. The configuration-surface persistence finding (`Config::to_json` writes the secret plaintext to JSON) is registered in §6 as a finding outside this proof's scope but worth surfacing.   ∎

**Proof of T-5 (HMAC scheme soundness).** Direct from L-5. HMAC-SHA-256 is a PRF under SHA-256 compression-function PRF security (Bellare 2006). The single-query forgery bound is `2⁻²⁵⁶`; the q-query bound is `2⁻¹²⁸ + q² / 2^256`. For all operational `q ≪ 2^128`, the bound is negligible.

Combining with H1 (Preliminaries §2.1), the assumption stack is:

1. SHA-256 collision-resistance ⇒ SHA-256 compression-function PRF security (Bellare 2006 §4 — the reduction is tight for HMAC).
2. SHA-256 compression-function PRF security ⇒ HMAC-SHA-256 PRF security (Bellare–Canetti–Krawczyk 1996 + Bellare 2006).
3. HMAC-SHA-256 PRF security ⇒ HMAC-SHA-256 unforgeable as a MAC (standard PRF-to-MAC reduction, Bellare–Goldwasser–Micali 1984).

The chain is well-established and the concrete bounds are operationally negligible.   ∎

---

## 6. Adversary model + notable findings

### 6.1 Adversary model

The v2.16 HMAC scheme is designed against the following adversary families:

**(a) Network-passive attacker.** Observes wire traffic but does not inject. Threat: recovering `K` from observed HMACs. **Defended.** By L-1 + L-5, the q-query distinguishing advantage is negligible; an attacker cannot recover `K` from any number of legitimate HMACs without breaking HMAC-SHA-256's PRF security.

**(b) Network-active attacker (forger).** Observes and injects; chooses `(method, params)` at attack time. Threat: crafting a valid `(method, params, auth)` triple without knowing `K`. **Defended (T-1).** Single-attempt forgery probability ≤ 2⁻²⁵⁶; q-attempt cumulative ≤ negligible.

**(c) Replay attacker.** Captures one legitimate triple, replays verbatim. Threat: re-executing privileged operations (e.g., `submit_tx` debiting the operator's domain) by replaying a captured RPC. **NOT defended in v2.16 (T-2).** Documented as a known limitation; mitigated operationally by S-001 Option 1 (localhost-only default, limiting the wire-eavesdropping surface to co-tenants on the same host).

**(d) Side-channel attacker (timing).** Measures response latency to extract per-byte information about `K`. Threat: incrementally recovering `K` byte-by-byte over many forge attempts. **Defended (T-3).** The constant-time XOR-OR loop at `src/rpc/rpc.cpp:124-127` reveals no per-byte timing information.

**(e) Side-channel attacker (log scraping).** Reads server logs (e.g., a tenant with stdout access on a shared box, or a centralized log aggregator) and extracts `K` from any echoed material. Threat: log-based secret recovery. **Defended at the RPC-server surface (T-4).** A configuration-surface finding is registered in §6.2.

**(f) Compromised-host attacker (memory dump).** Reads the server process's memory directly. Out of scope. The HMAC scheme assumes the server's process memory is private (Preliminaries §3.2's "A may not eavesdrop on honest validators' private state"). A future hardware-enclave or memory-locking enhancement is outside v2.16's scope.

### 6.2 Notable findings (from T-3 and T-4 audits)

**Finding F-1 (Configuration-surface plaintext secret persistence).** `Config::to_json` at `src/node/node.cpp:30` serializes `rpc_auth_secret` to JSON in plaintext as part of the operator's config persistence path. The config JSON is written to disk via `Config::save` (`src/node/node.cpp`) under the operator-controlled `--config-path`. An attacker with read access to the config file recovers `K` directly.

**Severity:** Low to Medium (depends on operator's filesystem permissions on the config path).

**Recommended mitigation:**

1. **Short-term (operator hardening).** Document explicitly in `docs/CLI-REFERENCE.md` §17 that the config file containing `rpc_auth_secret` must be `chmod 0600` and owned by the determ user only. Add an at-startup permission audit similar to the `key_path` permission check (already present for the node's Ed25519 key).
2. **Medium-term (passphrase encryption).** Apply the v2.17 passphrase-encrypted-keyfile pattern (already shipped for the Ed25519 node key per `docs/SECURITY.md` S-004 closure) to `rpc_auth_secret`. The operator would set `DETERM_RPC_AUTH_SECRET` via env var (the existing env-var path at `src/rpc/rpc.cpp:294` already supports this) or via an encrypted config blob.
3. **Long-term (secrets manager integration).** Add an optional `rpc_auth_secret_source` field that can specify "file", "env", "vault", "aws-secrets-manager", etc. Out of scope for the HMAC primitive's correctness proof.

The HMAC primitive's soundness (T-1, T-3, T-5) is unaffected by F-1; F-1 is a key-management hygiene issue, not a defect in the HMAC scheme.

**Finding F-2 (DETERM_RPC_AUTH_SECRET env var leakage surface).** The client-side `rpc_call` at `src/rpc/rpc.cpp:294-296` reads the secret from `DETERM_RPC_AUTH_SECRET`. Environment variables are visible to any process the operator owns via `/proc/$pid/environ` (Linux) or `ps e` (BSD). A co-tenant on the same host without explicit permission to read the determ process can still see the env var on a misconfigured box (e.g., if `/proc` is not `hidepid=2`).

**Severity:** Low (mitigated by S-001 Option 1's localhost-only default — the attacker would need same-host access already).

**Recommended mitigation:** document `hidepid=2` mount option (Linux) as part of the operator deployment checklist, and recommend the explicit `--auth-secret <hex>` CLI argument over the env var for higher-trust deployments.

**Finding F-3 (compiler-attribute hardening — defense in depth).** The constant-time XOR-OR loop at `src/rpc/rpc.cpp:124-127` relies on the compiler not transforming the loop into an early-exit form. Modern GCC/Clang at `-O2` are observed to preserve the loop structure (no auto-introduced early exit), but a future compiler upgrade could introduce a regression.

**Severity:** Very Low (theoretical; current compilers are well-behaved).

**Recommended mitigation:** add a `volatile`-qualified accumulator (`volatile int diff = 0;`) or use OpenSSL's `CRYPTO_memcmp` directly. Either change is ~3 LOC and is a defense-in-depth measure, not a fix for any observed defect.

The three findings are advisory; none invalidates T-1 .. T-5. They are surfaced for completeness so an external auditor can confirm the scope of the proof's analytic conclusion.

---

## 7. Status

**Shipped (v2.16, in-session).** The HMAC RPC auth scheme is live in the current `main` branch:

- `src/rpc/rpc.cpp:60-129` — HMAC primitive + `verify_auth` + constant-time compare.
- `include/determ/rpc/rpc.hpp:35-52` — `RpcServer` constructor + `verify_auth` declaration + `auth_secret_` field.
- `src/rpc/rpc.cpp:276-321` — client-side `rpc_call` with `DETERM_RPC_AUTH_SECRET` env var support.
- `tools/test_rpc_hmac_auth.sh` — 5-assertion regression test (auth-disabled, missing-auth, wrong-secret, correct-secret, malformed-hex).
- `docs/SECURITY.md` §3 S-001 — closure narrative (Option 1 + Option 3 both landed).
- `docs/PROTOCOL.md` §10.2 — wire-level documentation of the `auth` field requirement.
- `docs/CLI-REFERENCE.md` §17 — operator-facing documentation of `rpc_auth_secret`.

**Not yet shipped (T-2 follow-on, future work):** per-request nonce or timestamp + sliding-window acceptance. Tracked in `docs/SECURITY.md` §3 S-001's "Replay of authenticated requests by MITM: NOT addressed in v2.16" note. No work-unit assigned yet; estimated ~1d implementation + ~0.5d test coverage.

This proof was added in the current review pass as part of the analytic-closure sweep for S-001; it does not modify any source code, only formalizes the cryptographic argument that the HMAC scheme closes the cross-tenant half of S-001 under standard assumptions.

---

## 8. References

### Specifications + standards

- **RFC 2104** (Krawczyk, Bellare, Canetti, Feb 1997) — "HMAC: Keyed-Hashing for Message Authentication." Normative reference for HMAC construction.
- **FIPS 198-1** (NIST, Jul 2008) — "The Keyed-Hash Message Authentication Code (HMAC)." NIST normative.
- **NIST FIPS 180-4** — Secure Hash Standard, SHA-256 specification (referenced by Preliminaries §2.1 + L-2).
- **RFC 6234** — "US Secure Hash Algorithms" (alternate normative reference for SHA-256).

### Cryptographic literature

- **Bellare, Canetti, Krawczyk** (CRYPTO 1996) — "Keying Hash Functions for Message Authentication." Original HMAC paper; PRF security under compression-function collision-resistance.
- **Bellare** (CRYPTO 2006) — "New Proofs for NMAC and HMAC: Security Without Collision-Resistance." Tighter PRF reduction; the standard-model bound this proof uses.
- **Bellare, Goldwasser, Micali** — "How to construct random functions" (J.ACM 1986; refined treatments in Bellare-Rogaway "Introduction to Modern Cryptography" §5.2-§5.5) — PRF-to-MAC reduction underlying L-1.
- **Bellare, Rogaway** — "Introduction to Modern Cryptography" §5.3 — textbook treatment of SHA family collision-resistance + HMAC PRF.

### Determ-internal references

- `src/rpc/rpc.cpp:60-129` — HMAC primitive + `verify_auth` (the proof's primary object).
- `include/determ/rpc/rpc.hpp:35-52` — header declaration + `auth_secret_` field.
- `src/node/node.cpp:25-72` — `Config::to_json` / `Config::from_json` (the configuration-surface persistence path referenced in F-1).
- `tools/test_rpc_hmac_auth.sh` — regression harness (5 assertions, T-1's exercised cases).
- `docs/SECURITY.md` §3 S-001 — closure-status narrative; threat-model matrix this proof formalizes.
- `docs/PROTOCOL.md` §10.2 — wire-level `auth` field documentation.
- `docs/CLI-REFERENCE.md` §17 — operator-facing config documentation.
- `docs/proofs/Preliminaries.md` §2.1 (SHA-256 / H1), §2.3 (CSPRNG / uniform-key assumption referenced as K_random).
- `docs/proofs/EquivocationSlashing.md` (FA6) — companion proof on EUF-CMA-style soundness against an honest-key forgery (citation-style template).
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` — companion proof; structural-disjointness lemma style used in L-3 + L-4.
- `docs/proofs/FrostVerifyDelegation.md` — companion proof; delegation-to-underlying-primitive style mirrored here (HMAC primitive delegated to OpenSSL `HMAC(EVP_sha256(), ...)`).
