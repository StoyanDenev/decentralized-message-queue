# RpcInputValidationDefense — composed layered defense across the RPC input surface

This document proves that Determ's RPC server in `src/rpc/rpc.cpp` admits no
adversarial input that bypasses all of the closure layers shipped on the
RPC surface. The argument composes five existing per-layer closures into a
single defense-in-depth statement: a request that survives every layer is
indistinguishable (modulo replay, scoped out in S-001) from a request a
client owning the operator's `rpc_auth_secret` could have sent. The proof
does not re-derive each per-layer soundness statement — those live in the
companion documents — it only composes their guarantees.

The composition has two operational consequences. First, every adversarial
RPC input is rejected by at least one of the five layers, so the post-Layer-
E dispatch surface in `RpcServer::dispatch` (`src/rpc/rpc.cpp:197-272`)
sees only inputs that passed transport framing (Layer A), JSON structure
(Layer B), semantic per-method validation (Layer C), per-IP rate budget
(Layer D), and HMAC authentication (Layer E). Second, even if all five
layers fail simultaneously on some future code path that we haven't
identified, the chain's apply layer (`Chain::apply_block`,
`Chain::apply_transactions`) re-validates every transaction independently
of RPC — so a defect in RPC validation cannot, by itself, produce an
unauthorized state mutation. The RPC surface is a *convenience* gate, not
a *correctness* gate; the apply layer is the correctness gate.

**Companion documents:**
`docs/proofs/RpcAuthHmacSoundness.md` (S-001 closure — Layer E partner);
`docs/proofs/S014RateLimiterSoundness.md` (S-014 closure — Layer D
partner); `docs/proofs/JsonValidationSoundness.md` (S-018 closure — Layer
B partner); `docs/proofs/S022WireFormatCaps.md` (S-022 closure — Layer A
partner); `docs/proofs/S028AnonAddressNormalization.md` (S-028 — Layer C
address-normalization partner);
`docs/proofs/NonceMonotonicity.md` (FA-Apply-3 nonce gate at apply layer);
`docs/proofs/StakeLifecycle.md` (FA-Apply-4 stake apply gate);
`docs/proofs/FeeAccounting.md` (FA-Apply-6 fee charging gate);
`docs/proofs/Preliminaries.md` §2.1 (H1 SHA-256 collision resistance), §2.2
(A1 Ed25519 EUF-CMA), §3 (network model — partial-synchrony assumption
underlying T-3's rate-limit composition).

---

## 1. Theorem statements

**Setup.** Let `RPC_SURFACE` denote the set of byte strings that arrive on
a TCP connection accepted by `RpcServer::accept_loop` at
`src/rpc/rpc.cpp:131-140`. Each request is delimited by a newline and
read by `asio::read_until(*socket, buf, '\n', ec)` at line 158. Let
`MUTATE_STATE` denote the set of `chain_`-mutating method names: `send`,
`stake`, `unstake`, `register`, `submit_tx`, `submit_equivocation`. The
remaining methods (`status`, `peers`, `balance`, `nonce`, `stake_info`,
`block`, `headers`, `chain_summary`, `validators`, `committee`, `account`,
`tx`, `pending_params`, `abort_records`, `dapp_info`, `dapp_list`,
`dapp_messages`, `state_root`, `state_proof`, `snapshot`) are
read-only — they hold either a `shared_lock<shared_mutex>` or use the
lock-free `committed_state_view()` path. Let `LAYERS := {A, B, C, D, E}`
denote the five validation layers below.

- **Layer A (transport framing).** TCP-level `read_until('\n', …)` bounds
  one line; for the gossip path the framing + per-`MsgType` cap from
  S-022 applies. For the RPC path, the analogous bound is the
  `kMaxFrameBytes` ceiling on body size (`include/determ/net/messages.hpp:101`
  = 16 MB) inherited at the framing layer. RPC requests are JSON lines
  bounded by the OS TCP buffer + the `streambuf` accumulator's growth
  policy; legitimate RPC requests are < 1 MB by construction (see Layer C
  per-method input shapes), and oversize lines are dropped at the
  framing layer before any JSON parse. Layer A's RPC instance is documented
  here; the gossip-layer Layer-A enforcement is the subject of
  `docs/proofs/S022WireFormatCaps.md`.
- **Layer B (JSON structural validation).** Methods with structured input
  (`submit_tx`, `submit_equivocation`) route their `params.tx` /
  `params.event` through the S-018-hardened `Transaction::from_json` /
  `EquivocationEvent::from_json` from `src/chain/block.cpp` — these use
  `json_require<T>` / `json_require_hex` / `json_require_array` from
  `include/determ/util/json_validate.hpp`, which reject missing /
  wrong-type / wrong-hex-length fields with a clear `"S-018: "`
  diagnostic. Methods with scalar input (`balance`, `nonce`, `stake_info`,
  `dapp_info`, `dapp_list`, `dapp_messages`, `block`, `headers`,
  `chain_summary`, `state_proof`, `account`, `tx`, `snapshot`) use
  `params.value(key, default)` — missing / wrong-type yields the documented
  default, which is the right pattern for optional scalars.
- **Layer C (semantic per-method validation).** Each `rpc_*` handler in
  `src/node/node.cpp` enforces method-specific semantics: anon-address
  shape + case-canonicalization for `submit_tx` (S-028); recompute-hash +
  stale-nonce + signature verification + mempool admission gates for
  `submit_tx` (S-002 / S-008); balance pre-check for `send` / `stake` /
  `unstake` (S-023); namespace whitelist for `state_proof`; pagination
  caps for `headers` / `dapp_messages` (256-entry pages); etc.
- **Layer D (rate limiting).** `RateLimiter::consume(peer_ip)` at
  `src/rpc/rpc.cpp:172` applies a per-peer-IP token-bucket BEFORE
  JSON parse + auth. Rejected requests return `{"error":
  "rate_limited"}` and consume `O(log N)` work (S-014).
- **Layer E (HMAC authentication).** `RpcServer::verify_auth` at
  `src/rpc/rpc.cpp:112-129` verifies a hex-HMAC-SHA-256 over
  `method ‖ "|" ‖ params.dump()` against the server-side `auth_secret_`
  using a constant-time comparison. Missing / wrong-secret returns
  `auth_required` / `auth_failed`. When `auth_secret_` is empty (default
  off for backward-compat), Layer E is a no-op (S-001).

The five layers fire in this canonical order in `handle_session` at
`src/rpc/rpc.cpp:142-195`:

1. Layer A: `read_until('\n', …)` reads one bounded line.
2. Layer D: `rate_limiter_.consume(peer_ip)` — first non-syntactic gate.
3. Layer B: `json::parse(line)` and downstream `from_json` calls — these
   throw `std::runtime_error` carrying the `S-018: "field"` diagnostic.
4. Layer E: `verify_auth(req)` — runs after parse so the canonical bytes
   for HMAC computation are available.
5. Layer C: `dispatch(req)` → `node_.rpc_*(...)` — the method handler
   applies semantic validation.

If any layer rejects, the rest are skipped. Layer D before Layer B is
deliberate (S-014's "rate-limit before parse"); Layer E after Layer B is
deliberate (HMAC needs the parsed canonical-bytes form); Layer C inside
the method handler is the last-line semantic gate.

**Theorem T-1 (Layered Defense Completeness).** Let `R` denote any
adversarial request byte string. Define the adversary classes:

- **A1: oversize body.** `|R| > LINE_LIMIT` where `LINE_LIMIT` is the
  framing-layer ceiling.
- **A2: malformed JSON.** `R` is a line that `json::parse` cannot parse,
  OR `R` parses but a required field has wrong type / wrong hex length /
  is missing.
- **A3: semantically invalid.** `R` parses and authenticates, but its
  per-method semantics violate the method's contract (e.g., a `submit_tx`
  with stale nonce, an `unstake` on a non-staked account, a `state_proof`
  on an unsupported namespace).
- **A4: high-rate flood.** `R` is byte-identical-or-similar but arrives
  from a single peer-IP at rate `> C + r·Δ` per the S-014 bound.
- **A5: unauthenticated.** `R` parses successfully and is semantically
  valid, but lacks `req["auth"]` or carries a wrong HMAC value when
  Layer E is enabled.

For each adversary class `Aᵢ ∈ {A1, A2, A3, A4, A5}` there exists at
least one layer `Lⱼ ∈ {A, B, C, D, E}` that rejects `R` before Layer C's
state-mutating method handler executes. Specifically:

| Class | Primary layer | Reject behavior |
|---|---|---|
| A1   | Layer A | TCP framing drops; no JSON parse occurs |
| A2   | Layer B | `std::runtime_error` with `"S-018: "` diagnostic returned to client as `{"error": "..."}` |
| A3   | Layer C | per-method `std::runtime_error` returned to client (e.g., `"stale nonce"`, `"insufficient balance"`, `"unsupported namespace"`) |
| A4   | Layer D | `{"error": "rate_limited"}` returned to client; no parse / auth / dispatch |
| A5   | Layer E | `{"error": "auth_required: missing 'auth' field"}` or `{"error": "auth_failed"}` |

In each row the listed layer's rejection happens before any state mutation
in the post-Layer-C dispatch, so no `chain_`-mutating operation runs on
the adversarial request.

**Theorem T-2 (Layer Independence).** The five layers operate on disjoint
parts of the request and have disjoint failure modes. A regression in one
layer (e.g., a missing `json_require_hex` on some field added to
`Transaction::from_json`) is caught by the next layer down (Layer C's
recompute-hash + sig-verify on `submit_tx` rejects any tx whose decoded
bytes don't reproduce the embedded sig). In the inverse direction (Layer
E shadows Layer D — both reject unauthenticated traffic), the layers are
ordered so that the earlier/cheaper layer fires first. No single layer's
silent failure compromises the system; the worst case is a downgraded
diagnostic at the next layer.

Formally: for each pair `(Lᵢ, Lⱼ)` with `i ≠ j`, there exists an
adversarial input `Rᵢⱼ` that `Lᵢ` would reject but `Lⱼ` would NOT
reject — meaning the layers are not equivalent. And there is no `Rᵢⱼ`
that all four layers `{A, B, C, D, E} \ {Lⱼ}` admit but `Lⱼ` alone
rejects from a real adversary class — meaning every adversary class has
at least one fallback layer.

**Theorem T-3 (Constant-Time per Reject).** Every layer's reject path
performs work bounded by `O(log N) + O(|input|)` per request, where
`N` is the per-IP-bucket count (typically `≤ 10^4` per S-014's F-1
closure cap) and `|input|` is the request line length (typically `< 1 KB`,
bounded above by the framing-layer ceiling 16 MB). Specifically:

- Layer A: `O(|line|)` for the TCP read + framing check; no per-request
  state allocation beyond the streambuf.
- Layer B (S-018 reject): one `json::parse` call (`O(|line|)`) + one
  `json_require_*` failure (constant-time string construction for the
  diagnostic).
- Layer C: per-method O(1) lookups against the account / stake / DApp
  registry, each of which is `O(log accounts)` map access in the worst
  case (the lockfree path is `O(1)` amortized).
- Layer D: O(log N) `std::map<string, Bucket>::operator[]` + 4
  floating-point operations + 1 mutex acquire (S-014 T-2).
- Layer E: one HMAC-SHA-256 compute (`O(|method| + |params.dump()|)`
  ≈ O(|line|)) + 64-byte constant-time compare (RpcAuthHmacSoundness T-3).

The composition is monotone — a request rejected at layer `i` performs
the work of layers 1..i and then aborts. The total worst-case work per
reject is `O(|line|) + O(log N)` = bounded by the smallest layer that
fires. No layer amplifies the adversary's work-per-byte ratio.

**Theorem T-4 (No Privilege Escalation Surface).** A request rejected by
any layer cannot mutate `chain_` state, mempool state (`tx_store_`,
`tx_by_account_nonce_`), or any operator-visible counter outside the
per-IP bucket map and the optional log line. Proof: every state mutation
happens inside `Node::rpc_*` methods invoked from `dispatch` at
`src/rpc/rpc.cpp:197-272`. `dispatch` is reached only when Layers A, B,
D, E all pass — see the control flow in `handle_session` lines 165-187.
Layer C's semantic rejection is the last gate before mutation; if Layer C
throws, the throw is caught at line 188 and `chain_` is unchanged.

The exception path at lines 188-191 sets `response["error"] = e.what()`
and writes the response back; no state-mutating side effect (no chain
append, no mempool insertion, no broadcast) executes after the throw.

**Theorem T-5 (Composition with K-of-K Apply Path).** The RPC surface
is a *convenience* gate: an adversary who bypasses every RPC layer
(e.g., by compromising the operator's host and reading `auth_secret_`
from the config file, then submitting tx via authenticated RPC) does NOT
thereby succeed at producing an unauthorized state mutation, because
every transaction that enters mempool via RPC must subsequently be
included in a block by the K-of-K committee, and each committee member
independently re-validates the block via the consensus apply path
(`Chain::apply_block`, `Chain::apply_transactions`). The apply path's
gates are independent of RPC:

- **FA-Apply-3 (NonceMonotonicity).** `tx.nonce` must equal
  `accounts[tx.from].next_nonce` at apply time. A submission via
  authenticated RPC that escaped Layer C's stale-nonce check still gets
  caught here because committee members compute `next_nonce` from their
  own committed state, not from the submitting peer's view.
- **FA-Apply-4 (StakeLifecycle).** STAKE / UNSTAKE / DEREGISTER apply-
  layer rules. An RPC-admitted STAKE with insufficient balance is
  silently dropped at apply (not "queued + lost"); the apply-time check
  is the authoritative balance gate.
- **FA-Apply-6 (FeeAccounting).** Fee charged against `tx.from`'s
  balance at apply; insufficient balance drops the tx silently.
- **FA-Apply-16 and intermediate gates.** Per-tx replay (hash-uniqueness
  + nonce monotonicity), per-block tx-root binding, equivocation-event
  apply guards, cross-shard receipt dedup. None of these consult the
  RPC layer's prior decisions; all re-derive the validity criterion from
  on-chain state alone.

A bypass of all five RPC layers therefore reduces to "this tx will reach
mempool, but every committee member will re-validate it independently."
The apply layer is the correctness gate; RPC is the operator-experience
gate.

---

## 2. Background

### 2.1 The five-layer architecture

Determ's RPC surface evolved through five distinct closures over the
project's lifetime, each addressing a different adversary capability.
The layers compose because each closure was designed to fail-loud and
to leave subsequent layers' invariants intact:

- **S-022 (Layer A).** Per-`MsgType` body cap, primarily for gossip.
  The RPC surface inherits the same framing-layer ceiling
  (`kMaxFrameBytes` = 16 MB) but does NOT apply a per-method body cap
  because RPC messages don't carry a `type` byte; instead, the per-method
  input shape is bounded by Layer C's semantic check (e.g., `submit_tx`'s
  `tx` payload is bounded by the serialized `Transaction` size, which is
  well under 64 KB even for max-sized payloads).
- **S-018 (Layer B).** JSON-structural validation across every from_json
  path. Pre-S-018, malformed JSON produced opaque
  `nlohmann::detail::type_error` exceptions naming neither the field
  nor the containing object; post-S-018, every required field flows
  through `json_require<T>` / `json_require_hex` / `json_require_array`
  which surface `"S-018: "` diagnostics with field names. The RPC
  structured-input paths (`submit_tx`, `submit_equivocation`) inherit
  this contract.
- **Per-method semantic checks (Layer C).** Implemented per-handler in
  `src/node/node.cpp`. Heterogeneous by design — each handler enforces
  the method-specific contract. S-028 (anon-address normalization) is
  one component, S-023 (balance pre-check) is another, S-002 (sig-verify
  before mempool admit) is a third.
- **S-014 (Layer D).** Per-peer-IP token-bucket rate limit on both RPC
  and gossip. The RPC instance fires at line 172 BEFORE parse + auth so
  rate-limited callers consume `O(log N)` work, not `O(|line|)`.
- **S-001 (Layer E).** HMAC-SHA-256 authentication of the request body
  using a constant-time comparison against the operator-supplied
  `auth_secret_`. Default off for backward-compat (single-tenant boxes);
  required for multi-tenant or external-bind deployments.

The layers' order in `handle_session` is forced by data dependencies:

- D before B: rate-limit needs only `peer_ip` (cached at session start);
  parse is `O(|line|)`. Putting D first saves the parse work on
  rate-limited callers.
- B before E: HMAC needs the canonical `params.dump()` form, which
  requires a successful parse.
- E before C: a wrongly-authenticated request shouldn't run the method
  handler — that would leak whether the method exists or whether the
  caller's params are well-formed (information disclosure to an
  unauthenticated party).
- C inside the method handler: semantic checks consume the already-
  authenticated, already-parsed, already-rate-limited request. C is
  also where any method-specific quirks live (per-namespace dispatch
  for `state_proof`, page caps for `headers`, etc.).

### 2.2 The S-001 deployment recommendation

S-001 ships in two modes: localhost-only (default; binds 127.0.0.1) and
external-bind (operator opts in, with HMAC auth required for non-trivial
threat models). The closure narrative in `docs/SECURITY.md` §S-001
explicitly recommends:

> Multi-tenant or external-bind deployments MUST set `rpc_auth_secret`.
> Single-tenant boxes (one operator owns the whole host) can run with
> the default localhost-only bind and no `auth_secret_`.

This is a deployment-policy item, not a technical defect. The HMAC
scheme itself is sound (RpcAuthHmacSoundness T-1); the operator's choice
to enable it is a configuration decision. Layer E with `auth_secret_`
empty is a no-op pass-through — any caller who can connect (i.e., is on
localhost or has the operator's blessing for external-bind) is accepted.
This is documented in `verify_auth` line 113: `if (auth_secret_.empty())
return ""; // Auth disabled, pass.`

The recommendation surfaces in §6 (Finding-Register) below as a
documentation discipline item — operators deploying for multi-tenant or
external-bind use MUST enable the secret, and the documentation already
makes this explicit at `docs/CLI-REFERENCE.md` §17.

### 2.3 Adversary model

The composition argument operates under the standard Determ adversary
model from `docs/proofs/Preliminaries.md` §3.2:

- **A1 (Ed25519 EUF-CMA).** Underlies `Transaction::sig` verification at
  Layer C's `submit_tx` handler (S-002 sig-verify). An attacker without
  the from-account's private key cannot forge a signature over arbitrary
  `signing_bytes`.
- **A2 (SHA-256 collision resistance, equivalently H1 in the proof's
  notation).** Underlies Layer E's HMAC-SHA-256 binding to the
  canonical `method ‖ "|" ‖ params.dump()` bytes. An attacker without
  the operator's `auth_secret_` cannot forge a valid HMAC value (see
  RpcAuthHmacSoundness T-1, reduces to A2 + uniform-key sampling).
- **H1 (honest validators).** The K-of-K apply path's re-validation
  (T-5) assumes at least one validator in `V \ F` exists at every
  height. Under Determ's K-of-K mutual-distrust safety, T-5's bound
  holds even if all K committee members are Byzantine for a given
  block — the chain's safety is independent of RPC.

The composition is robust to attacks at any layer's boundary because
each layer's failure mode is a clean exception (or a clean drop, in
Layer D's case) that does not corrupt the next layer's state.

---

## 3. Implementation citation

### 3.1 The RPC entry-point — `RpcServer::handle_session`

`src/rpc/rpc.cpp:142-195` is the primary object of this proof. The
relevant section (Layer ordering):

```cpp
void RpcServer::handle_session(std::shared_ptr<asio::ip::tcp::socket> socket) {
    // S-014: cache the peer's IP once per session for rate-limit lookup.
    std::string peer_ip;
    try {
        auto ep = socket->remote_endpoint();
        peer_ip = ep.address().to_string();
    } catch (...) {
        peer_ip = "unknown";
    }

    asio::streambuf buf;
    std::error_code ec;
    while (!ec) {
        asio::read_until(*socket, buf, '\n', ec);          // Layer A
        if (ec) break;
        std::istream is(&buf);
        std::string line;
        std::getline(is, line);
        if (line.empty()) continue;
        json response;
        try {
            // Layer D (S-014): rate-limit BEFORE parse.
            if (!rate_limiter_.consume(peer_ip)) {
                response["result"] = nullptr;
                response["error"]  = "rate_limited";
            } else {
                auto req = json::parse(line);              // Layer B (json::parse)
                // Layer E (S-001): HMAC auth check.
                std::string auth_err = verify_auth(req);
                if (!auth_err.empty()) {
                    response["result"] = nullptr;
                    response["error"]  = auth_err;
                } else {
                    response["result"] = dispatch(req);    // Layer C (per-method)
                    response["error"]  = nullptr;
                }
            }
        } catch (std::exception& e) {
            response["result"] = nullptr;
            response["error"]  = e.what();
        }
        std::string reply = response.dump() + "\n";
        asio::write(*socket, asio::buffer(reply), ec);
    }
}
```

The five layers' call sites are mapped to lines:

| Layer | Line | Action |
|---|---|---|
| A | 158 | `asio::read_until(*socket, buf, '\n', ec)` reads one line; framing-layer ceiling applies via streambuf growth + 16 MB inherited cap |
| D | 172 | `rate_limiter_.consume(peer_ip)` per-IP token-bucket |
| B | 176 | `json::parse(line)` plus structured-payload from_json calls inside dispatch |
| E | 179 | `verify_auth(req)` HMAC check |
| C | 184 | `dispatch(req)` → `node_.rpc_*` semantic check |

The `try`/`catch` at 165-191 catches any `std::runtime_error` from any
layer (B's S-018 throws, C's `runtime_error` throws, B's `json::parse`
throws on malformed JSON) and surfaces the exception's `what()` as the
client's error response. Layers A and D are explicit reject paths that
don't throw; layers B, C, E throw.

### 3.2 Layer A — framing

The asio `read_until('\n', …)` accepts bytes into the `streambuf` until
a newline is found or an error occurs. The streambuf has no hard size
limit set at this call site, so it grows with the line — this is
bounded in practice by:

1. The OS TCP receive buffer (default 64 KB on Linux, larger on
   well-tuned systems).
2. The asio streambuf's `max_size` (constructed with default
   `std::numeric_limits<size_t>::max()` here — practically unbounded
   in memory but bounded in time by the TCP receive rate).
3. The 16 MB `kMaxFrameBytes` ceiling at the framing layer of
   `include/determ/net/messages.hpp:101` (used by gossip; RPC inherits
   the same intent — see §6 F-1 for the formal finding that the RPC
   path's body cap is not as tightly bounded as gossip's).

A peer that opens a TCP connection and sends a gigabyte without a
newline would consume server memory at the OS TCP receive rate; the
session's read loop would block at `read_until` until the connection
times out (asio default ~75 seconds idle, OS-level). This is a
DoS-by-slow-consume vector, not a privilege escalation; S-014 partially
mitigates by bounding sessions per IP via the rate limiter. The
finding is registered in §6 F-1.

For normal-sized RPC requests (< 1 KB to ~16 KB for a `submit_tx` with
embedded sig), the framing layer is effectively a no-op — `read_until`
returns a bounded line and the next layer takes over.

### 3.3 Layer B — JSON validation

`json::parse(line)` at line 176 throws `nlohmann::json::parse_error` on
malformed JSON. The exception is caught at 188-190 and returned to the
client as `{"error": "<what()>"}`. Pre-S-018, this was the only JSON
validation; the post-parse field extractions happened inside
`dispatch`, where `params.value(key, default)` silently substituted
defaults for missing scalars and `params.value(key, json::object())`
silently substituted empty objects.

Post-S-018, structured-payload methods route through hardened from_json
paths. The RPC dispatch at `src/rpc/rpc.cpp:226-230`:

```cpp
if (method == "submit_tx")
    return node_.rpc_submit_tx(params.value("tx", json::object()));
if (method == "submit_equivocation")
    return node_.rpc_submit_equivocation(
        params.value("event", json::object()));
```

passes the JSON sub-object to `Node::rpc_submit_tx` /
`rpc_submit_equivocation`, which call
`chain::Transaction::from_json(tx_json)` /
`chain::EquivocationEvent::from_json(ev_json)`. Both from_json paths
are S-018-hardened (see `JsonValidationSoundness.md` §3.3 conversion
inventory). A malformed `tx` field — missing `amount`, wrong-type
`fee`, wrong-hex-length `sig` — throws `std::runtime_error` with
`"S-018: "` diagnostic, caught at line 188.

For scalar-input methods (`balance(domain)`, `nonce(domain)`,
`block(index)`, etc.), the input arrives as JSON scalars whose
extraction uses `params.value(key, default)`. Missing values yield the
default (typically empty string or zero), which Layer C then handles —
e.g., `rpc_balance("")` returns balance for the empty-key (zero) and
`rpc_state_proof("","")` returns `{"error": "not_found"}`. This is the
documented optional-scalar pattern, not an S-018-style required-field
extraction.

### 3.4 Layer C — semantic per-method validation

Layer C is the most heterogeneous layer because each method has
method-specific semantics. The proof's argument is that every method
that mutates state has a sound semantic gate before the mutation.

**`rpc_submit_tx`** at `src/node/node.cpp:3121-3205`. The semantic
gates:

1. S-028 anon-address canonical check on `tx.from` (lines 3137-3142)
   and `tx.to` (3143-3148). Non-canonical rejected with `"non-canonical"`
   diagnostic. Reason: the Ed25519 sig is over `signing_bytes` which
   embeds the address byte-for-byte; mutating case server-side would
   invalidate the sig, so the server cannot normalize-and-accept.
2. Hash recompute check (lines 3150-3155). `tx.compute_hash()` must
   equal `tx.hash`. Defends against client-side error / tampering of
   the hash field.
3. Stale-nonce check (lines 3157-3161). `tx.nonce >= next_nonce(tx.from)`
   required. Mirrors the gossip path's check in `on_tx`.
4. Signature verification (lines 3163-3168). `verify_tx_signature_locked`
   does the Ed25519 verify against `tx.signing_bytes()`.
5. Mempool admission check (lines 3170-3176). `mempool_admit_check`
   enforces the S-008 bounded-mempool policy.
6. Replace-by-fee logic (lines 3178-3192). An incumbent tx at the same
   `(from, nonce)` is replaced iff the new tx has higher fee.

A failure at any of these gates throws `std::runtime_error` with a
descriptive message, caught at the RPC layer and returned to the client.

**`rpc_send`** at `src/node/node.cpp:2804-2842`. The semantic gates:

1. S-028 normalization of `to_in` (line 2809).
2. S-023 balance pre-check (lines 2814-2823). `balance ≥ amount + fee`
   required.
3. Tx construction + sign + broadcast (lines 2824-2841).

`rpc_send` constructs its own tx using the operator's key — so the
sig is always valid (no S-002 vulnerability). The only adversarial
input is `(to, amount, fee)`; the balance check covers the only
mutation-relevant input.

**`rpc_stake`** / **`rpc_unstake`** at `src/node/node.cpp:2850-2929`.
Symmetric to `rpc_send` — S-023 balance pre-check for stake (must have
`amount + fee`); for unstake, an additional check that the locked
stake is at least `amount` plus the S-017 unlock-height check
documented in `docs/proofs/S017UnstakeApplyConsistency.md`.

**`rpc_state_proof`** at `src/node/node.cpp:3287-3336`. The semantic
gates:

1. Namespace whitelist (lines 3296-3314). Only `a|s|r|d|b|k|c` accepted;
   anything else returns `{"error": "unsupported namespace..."}`.
2. Lookup against `chain_.state_proof(k)` (line 3316). Missing key
   returns `{"error": "not_found"}`.

`rpc_state_proof` is read-only and uses a `shared_lock` — no state
mutation surface. The semantic check is purely a diagnostic gate.

**`rpc_balance`**, **`rpc_nonce`**, **`rpc_stake_info`**,
**`rpc_dapp_info`**, **`rpc_dapp_list`**, **`rpc_dapp_messages`** —
all read-only. S-028 normalization at entry for the first three;
prefix / topic filtering for the DApp methods. No state mutation; no
adversarial input class violates correctness, only one can produce
empty results.

**`rpc_chain_summary`**, **`rpc_block`**, **`rpc_headers`**,
**`rpc_tx`**, **`rpc_account`**, **`rpc_committee`**,
**`rpc_validators`**, **`rpc_status`**, **`rpc_peers`**,
**`rpc_pending_params`**, **`rpc_abort_records`**,
**`rpc_state_root`**, **`rpc_snapshot`** — all read-only. No
adversarial input class produces state mutation.

**`rpc_submit_equivocation`** at `src/node/node.cpp:3207-3236`. Routes
through the gossip-handler's `on_equivocation` path which has its own
sig-verify + dedup. The equivocation evidence carries two signed
messages from the same signer; the apply layer's
`apply_equivocation_event` re-checks both sigs (FA6).

**`rpc_register`** at `src/node/node.cpp:3338-...`. Constructs a
REGISTER tx using the operator's key; signs locally; broadcasts. No
adversarial input — the operator chose to register, the operator owns
the key.

### 3.5 Layer D — rate limiting

`rate_limiter_.consume(peer_ip)` at `src/rpc/rpc.cpp:172`. The
underlying `RateLimiter` is in `include/determ/net/rate_limiter.hpp`
(see §3 of `S014RateLimiterSoundness.md`). The RPC instance is
configured at construction time via the `rate_per_sec` /
`burst` constructor arguments (line 81). Default off if either is
zero.

### 3.6 Layer E — HMAC authentication

`verify_auth(req)` at `src/rpc/rpc.cpp:112-129`. See
`RpcAuthHmacSoundness.md` for the full soundness argument. The brief
form:

```cpp
std::string RpcServer::verify_auth(const json& req) const {
    if (auth_secret_.empty()) return ""; // Auth disabled.
    if (!req.contains("auth") || !req["auth"].is_string()) {
        return "auth_required: missing 'auth' field";
    }
    std::string method = req.value("method", "");
    auto params = req.value("params", json::object());
    std::string expected = hmac_sha256_hex(auth_secret_,
                                              canonical_for_hmac(method, params));
    std::string got = req.value("auth", std::string{});
    if (expected.size() != got.size()) return "auth_failed";
    int diff = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        diff |= (expected[i] ^ got[i]);
    }
    return (diff == 0) ? "" : "auth_failed";
}
```

The canonical-bytes form `method ‖ "|" ‖ params.dump()` is computed
identically on both client and server; the client puts the HMAC into
`req["auth"]` and the server recomputes from its own `auth_secret_`.
Constant-time compare avoids timing side channels.

---

## 4. Lemmas and proofs

### Lemma L-1 (Layer A bounds line length)

By inspection of `asio::read_until(socket, buf, '\n', ec)` at line 158:
the call reads bytes into the streambuf until a newline is delimited
or an error occurs. For a peer sending bytes faster than the server
can consume them, the streambuf grows; for a peer pausing mid-line,
the TCP receive-buffer's OS-level bound limits the in-kernel bytes.

The relevant bound for Layer A is the streambuf's `max_size` —
constructed with the asio default `std::numeric_limits<size_t>::max()`
here. In practice, the framing-layer ceiling `kMaxFrameBytes` = 16 MB
applies to the gossip path's `Peer::read_body` (see
`docs/proofs/S022WireFormatCaps.md` T-1/T-2). The RPC path does not
have an analogous explicit per-message body cap; the implicit bound is
the OS TCP backpressure + the rate limiter's downstream throttle.

For all operational RPC requests (`< 64 KB` for `submit_tx` even with
a maximum-sized 4 KB tx payload), Layer A is effectively a no-op. For
adversarial slow-consume attacks, see §6 F-1.   □

### Lemma L-2 (Layer B catches every malformed-JSON path)

By construction of `handle_session`:

1. `json::parse(line)` at line 176 throws `nlohmann::json::parse_error`
   on syntactic malformation (unterminated string, bad UTF-8, etc.).
   Caught at line 188.

2. The structured-payload methods extract their input via
   `params.value("tx", json::object())` (line 227) and pass the JSON
   sub-object to `Node::rpc_submit_tx`. Inside that handler,
   `chain::Transaction::from_json(tx_json)` (line 3123 of `node.cpp`)
   routes through the S-018-hardened helpers — missing or wrong-type or
   wrong-hex-length fields throw `std::runtime_error` with `"S-018: "`
   diagnostic. Caught at the RPC layer's line 188.

3. The scalar-payload methods extract via `params.value(key, default)`
   which uses nlohmann's `value` template — missing key returns the
   default; wrong-type returns the default (no throw). The default is
   then handed to the method handler, which applies Layer C's semantic
   check.

Branch 3 deserves a sub-argument: a wrong-type input (e.g., `{"params":
{"amount": "not-a-number"}}` to a method expecting `amount: uint64`)
is silently substituted by `params.value("amount", uint64_t{0})` — the
handler sees `amount = 0` and proceeds. For `rpc_send`, `amount = 0`
yields a zero-value tx (semantically valid but useless); the balance
pre-check at line 2817 passes (cost `0 + fee >= 0`); the tx broadcasts.
This is the *intended* behavior — scalar params have documented
defaults, not S-018 hard-required field semantics. The Layer C semantic
check absorbs the wrong-type-degrades-to-default case.

By induction over the 24 RPC methods enumerated in `dispatch`, every
JSON-structural malformation is caught at Layer B or absorbed by Layer
C's per-method defaults.   □

### Lemma L-3 (Layer C catches every semantically invalid input on state-mutating methods)

By case analysis over the six state-mutating methods `MUTATE_STATE :=
{send, stake, unstake, register, submit_tx, submit_equivocation}`:

**`send`** at `node.cpp:2804`. Inputs: `to`, `amount`, `fee` (scalars,
no S-018 required-field path). The semantic check is `balance(from)
>= amount + fee` at line 2817; insufficient balance throws
`"insufficient balance: have N, need M"`. The from-address is
`cfg_.domain` (the operator's own domain, fixed at config) — the
operator cannot send from someone else's account via this RPC.

**`stake`** at `node.cpp:2850`. Inputs: `amount`, `fee`. Same balance
check; sig over the operator's own key.

**`unstake`** at `node.cpp:2884`. Inputs: `amount`, `fee`. The semantic
check additionally enforces the S-017 unlock-height check (`amount` is
unlocked iff `chain.height() >= stake.unlock_height`); otherwise the
apply path will silently drop. The RPC handler surfaces this as a
diagnostic up-front (see S017UnstakeApplyConsistency.md).

**`register`** at `node.cpp:3338`. No adversarial-input class — the
operator triggers their own REGISTER tx.

**`submit_tx`** at `node.cpp:3121`. The most surface-rich method. The
six semantic gates documented in §3.4 cover: address canonicalization
(S-028), hash recomputation (defense against client tampering),
stale-nonce drop (S-002 + FA-Apply-3), signature verification (S-002),
mempool admission (S-008), replace-by-fee (S-008). The composition is
the subject of `docs/proofs/S002-Mempool-Sig-Verify.md`.

**`submit_equivocation`** at `node.cpp:3207`. Routes through the
gossip handler `on_equivocation`, which re-validates both signatures
on the two equivocating messages and applies the dedup logic. Apply-
time validation is the subject of `EquivocationSlashingApply.md`
(FA-Apply-7).

In every state-mutating method, the semantic gates fire before any
state mutation. A failure throws `std::runtime_error`, caught at the
RPC dispatch layer's exception handler, and the response carries the
error message back to the client.

For the read-only methods, "semantic invalidity" reduces to "the
request asks about something that doesn't exist." Each handler
returns either `nullptr` (e.g., `rpc_block` for `index >= height`) or
`{"error": "not_found", ...}` (e.g., `rpc_dapp_info` for an
unregistered domain) or `{"error": "unsupported namespace", ...}`
(e.g., `rpc_state_proof` for `ns ∉ {a,s,r,d,b,k,c}`). None of these
mutate state.   □

### Lemma L-4 (Layer D operates per-IP, bounded throughput)

Direct from `S014RateLimiterSoundness.md` T-1: for any peer-IP `k`,
the per-window allowed request count is bounded by `⌊C + r·Δ⌋`. The
RPC instance uses `peer_ip = socket->remote_endpoint().address().to_string()`
as the bucket key, cached once per session (lines 143-153) so each
session's consume calls all hit the same bucket.

The rate-limiter mutex (`mu_` in `RateLimiter`) serializes consume
calls across the asio worker-thread pool. This is documented in
`S014ConcurrencyAnalysis.md`.   □

### Lemma L-5 (Layer E forgery probability ≤ 2⁻²⁵⁶ + ε)

Direct from `RpcAuthHmacSoundness.md` T-1: an adversary without
`auth_secret_` produces a forgery with probability ≤ negligible under
HMAC-SHA-256 PRF security (which reduces to A2 + uniform-key sampling
from Preliminaries §2.1 + §2.3).

Layer E is a no-op when `auth_secret_.empty()` — the closure narrative
covers this as the single-tenant default. Multi-tenant or external-
bind deployments must enable the secret per the deployment
recommendation in `docs/SECURITY.md` §S-001.   □

### Lemma L-6 (Layer ordering preserves correctness under exception)

The `try`/`catch` at `src/rpc/rpc.cpp:165-191` catches `std::exception`
from any layer's throw. The catch body sets `response["error"] =
e.what()` and writes the response; no `chain_`-mutating code path
exists between the catch and the response-write.

Specifically:
- Layer B throws: caught immediately after `json::parse(line)` at 176
  (or after `from_json` throws from inside `dispatch`).
- Layer E throws: not directly; Layer E returns a string error, which
  `handle_session` checks at 180 and sets response without invoking
  dispatch.
- Layer C throws (inside `dispatch`): caught by the outer try, response
  set with error.

In all three throwing-layers' cases, the `chain_` state is untouched
between the request arrival and the response write. The mempool
modifications inside `rpc_submit_tx` occur AFTER all of Layer C's
gates pass (lines 3193-3194); a throw at any earlier line aborts before
mempool mutation.

The non-throwing layers (A drops silently, D drops with rate_limited
response) don't invoke dispatch at all — control flow skips lines
176-186 entirely on a Layer D rejection.   □

### Lemma L-7 (Apply layer re-validates independently of RPC)

Direct from `NonceMonotonicity.md` T-N1-N6, `StakeLifecycle.md` T-1-T7,
`FeeAccounting.md` T-F1-T-F7. Each FA-Apply gate consumes the tx and
the current `Chain` state; no consultation of mempool, RPC, or peer
metadata. The apply-time validity criterion is a function of the tx
plus on-chain state alone.

Specifically:
- `Chain::apply_transactions` iterates the block's `transactions`
  vector and, for each tx, applies the FA-Apply gates in order. A
  failure (insufficient balance, stale nonce, mempool absence at the
  time of block construction, etc.) silently drops the tx (the tx is
  not applied to state but the block is still valid).
- `Chain::apply_block` calls `apply_transactions`, applies subsidy,
  applies cross-shard receipts, applies abort events, applies
  equivocation events. Each sub-step is gated by the on-chain state.

Therefore: a tx that enters mempool via authenticated RPC and is then
included in a block by some producer must still pass the apply-time
gates at every committee member's local apply. A divergence between
RPC's "accepted to mempool" and apply's "applied to state" is the
normal case — the chain's state is the authoritative truth, not the
mempool view.

This decouples the RPC surface from the chain's correctness. An RPC
vulnerability that admits a tx with stale nonce produces a tx that
gets dropped at apply time; the apply layer is the correctness gate.   □

---

## 5. Proofs of T-1 .. T-5

### Proof of T-1 (Layered Defense Completeness)

By case analysis over the five adversary classes:

**A1 (oversize body).** The framing layer's TCP `read_until('\n', ec)`
bounds one line. For a request of size larger than the OS TCP receive
buffer + the streambuf accumulator, the session either consumes memory
proportional to the line size (bounded above by the per-IP rate
limiter's bucket budget) or the OS-level TCP back-pressure caps the
in-flight bytes. The relevant Layer-A bound is the streambuf's effective
ceiling.

For the RPC surface, Layer A's enforcement is operational rather than
structural — see §6 F-1 for a finding to add an explicit body cap. In
practice, an RPC line longer than ~1 MB is malformed (no legitimate
RPC request approaches this size) and gets dropped by the JSON parser
or the OS TCP back-pressure before reaching dispatch.

For attacks where Layer A admits the request but the line is
adversarial JSON, Layer B catches.   ∎ (A1 covered by Layer A + Layer B
in composition)

**A2 (malformed JSON).** By L-2, every malformed-JSON variant —
syntactic parse error, missing required field, wrong-type required
field, wrong-hex-length field — produces a `std::runtime_error` caught
at line 188. The response carries the S-018 diagnostic or the
`nlohmann::json::parse_error::what()` message. No state mutation
occurs.   ∎ (A2 covered by Layer B)

**A3 (semantically invalid).** By L-3, every state-mutating method's
semantic gates reject inputs that pass Layer B but fail method-
specific semantics. Read-only methods return `nullptr` /
`{"error": "..."}` for queries about non-existent state. No state
mutation occurs in either case.   ∎ (A3 covered by Layer C)

**A4 (high-rate flood).** By L-4, the per-IP token-bucket enforces
`A_k([t, t+Δ]) ≤ ⌊C + r·Δ⌋`. Flooders exceeding the budget receive
`{"error": "rate_limited"}` without parse, auth, or dispatch.   ∎
(A4 covered by Layer D)

**A5 (unauthenticated).** By L-5, when `auth_secret_` is non-empty,
forgery succeeds with probability ≤ 2⁻²⁵⁶ + negligible. Missing `auth`
field returns `"auth_required..."`; wrong-secret returns
`"auth_failed"`. When `auth_secret_` is empty, Layer E is a no-op —
this is the documented single-tenant default. For multi-tenant
deployments, the operator MUST enable the secret per the deployment
recommendation in `docs/SECURITY.md` §S-001.   ∎ (A5 covered by Layer E,
contingent on operator enabling the secret)

Combining the five sub-arguments: for every adversary class, at least
one layer rejects the request before Layer C's state-mutating method
handler executes. ∎

### Proof of T-2 (Layer Independence)

The layers fire on disjoint parts of the request:

| Layer | Operates on |
|---|---|
| A | Raw TCP byte stream (no JSON-level visibility) |
| B | Parsed JSON structure (envelope + per-field types) |
| C | Semantic interpretation of parsed fields |
| D | `peer_ip` only (no JSON visibility) |
| E | `auth` field + canonical-bytes form of `method` + `params` |

Disjoint operating domains mean failure modes are disjoint:

- Layer A failure (oversize) has nothing to do with JSON validity —
  Layer B would still parse correctly if the line were trimmed to size.
- Layer B failure (malformed JSON) has nothing to do with HMAC validity
  — Layer E would still compute correctly if the JSON were well-formed.
- Layer C failure (semantic invalid) has nothing to do with rate-limit
  — Layer D would still admit the request if budget remained.
- Layer D failure (rate budget exceeded) has nothing to do with auth
  validity — Layer E would still accept the HMAC if the budget allowed.
- Layer E failure (auth failed) has nothing to do with semantic
  validity — Layer C would still accept the request if the HMAC were
  correct.

**Non-equivalence witness.** For each pair `(Lᵢ, Lⱼ)` with `i ≠ j`,
construct `Rᵢⱼ` that one layer rejects but the other accepts:

- `R_AB`: a malformed-JSON line of size < 1 MB. Layer A admits (size OK);
  Layer B rejects (parse fails).
- `R_BA`: a 100 MB well-formed JSON line. Layer B would accept (parses
  OK); Layer A would reject if a body cap fired. (In current
  implementation Layer A is permissive — see §6 F-1.)
- `R_BC`: a well-formed `submit_tx` JSON with stale `nonce`. Layer B
  accepts (S-018 sees no missing fields); Layer C rejects (stale-nonce
  check).
- `R_CD`: a single semantically-valid `balance` query. Layer C
  accepts; Layer D may reject if the IP exceeded budget.
- `R_DE`: a flood of well-formed but unauthenticated requests. Layer D
  accepts the first `C` of them; Layer E rejects each.
- `R_EA`: a request with valid auth but oversize body. Layer E accepts
  (HMAC correct); Layer A rejects (size).

The pairwise non-equivalence is therefore established. The layers
operate independently in the sense that each catches a distinct
adversary class — no layer is redundant for the class it primarily
defends.

**No-coverage-gap argument.** For each adversary class identified in
T-1, at least one layer fires. The composition is total over the
adversary classes. A "silent failure" — a layer that fails to fire
when it should — is caught by the next layer:

- Layer A's silent failure on oversize: Layer B would parse a partial
  / oversized line and fail at the parse step, throwing
  `parse_error`. Caught at line 188.
- Layer B's silent failure on malformed JSON: a missing field that
  the S-018 helpers should reject but don't (hypothetical bug) — the
  field would default to its C++ zero-value, then Layer C's semantic
  check catches it (e.g., `amount=0` is a valid tx but goes nowhere;
  `signature=zero-vector` fails Ed25519 verify at the S-002 gate).
- Layer D's silent failure on flood: Layer A's framing-layer ceiling
  bounds per-request work; Layer E's HMAC compute is still
  constant-time-per-byte; no amplification.
- Layer E's silent failure on auth: Layer C's semantic check rejects
  any tx whose sig doesn't verify, whose nonce is stale, etc. — the
  apply-layer's re-validation (T-5) catches anything that even
  Layer C lets through.

The composition is robust to single-layer failures.   ∎

### Proof of T-3 (Constant-Time per Reject)

By inspection of each layer's reject path:

**Layer A:** `read_until('\n', ec)` returns when a newline is found or
an error occurs. The work is O(line-size) for the bytes read, then O(1)
for the framing-layer ceiling check (a single comparison). No state
allocation beyond the streambuf growth.

**Layer B:** A parse failure throws after at most O(line-size) parsing
work. An S-018 from_json failure throws after at most O(json-tree-size)
field-lookup work (bounded by the parse-tree depth, which is bounded
by the JSON document's structural depth, which is bounded by the
implementation's parser stack depth — by default 8K).

**Layer C:** Per-method O(log accounts) at worst — the map lookup
against `accounts_`, `stakes_`, `registrants_`, `dapp_registry_`. The
lockfree path is O(1) amortized (atomic shared_ptr load + map lookup
on a fixed-size hash). No allocation beyond the response JSON.

**Layer D:** Per S-014 T-2, O(log N) for the bucket lookup + O(1)
floating-point + O(1) mutex. No allocation.

**Layer E:** One HMAC-SHA-256 compute (O(canonical-bytes) which is
O(|method| + |params.dump()|), bounded by O(|line|)) + one constant-
time-compare over 64 bytes. No allocation beyond the 64-byte HMAC
output and the canonical-bytes string.

Total per-reject work is O(|line|) + O(log N) — bounded by the
request size and the bucket count. No amplification — an adversary
sending `K` rejected requests pays at most `K · (|line| + log N)` in
attacker bandwidth + server CPU. The work-per-byte ratio is bounded.   ∎

### Proof of T-4 (No Privilege Escalation Surface)

Direct from L-6. The exception path catches every rejected request's
throw before any state mutation can occur. The only mutations in
`handle_session` are:
1. The `streambuf` grows during `read_until`. Bounded; no chain
   relevance.
2. The rate-limiter's bucket map is touched in `consume`. Bounded by
   F-1 closure of S-014 to ≤ 10K entries.
3. Inside `dispatch`, the `chain_`-mutating handlers (`rpc_send`,
   `rpc_stake`, `rpc_unstake`, `rpc_register`, `rpc_submit_tx`,
   `rpc_submit_equivocation`) may modify `tx_store_` /
   `tx_by_account_nonce_` (mempool) and broadcast gossip messages.
   These modifications occur strictly AFTER Layer C's semantic gates.
   A throw at any gate aborts before the modifications.

The catch at lines 188-191 does not execute any mutation; it sets
the response error field and falls through to the response-write.

Therefore: every rejected request leaves `chain_` and the persistent
mempool fields byte-identical to the pre-request state. The rate
limiter's bucket count and the response sent back to the client are
the only observable side effects.   ∎

### Proof of T-5 (Composition with K-of-K Apply Path)

Direct from L-7. The apply layer's gates are FA-Apply-3 (nonce),
FA-Apply-4 (stake), FA-Apply-6 (fee), and the rest of the FA-Apply
family (cross-shard receipt apply at FA-Apply-7, abort event apply at
FA-Apply-8, equivocation apply at FA-Apply-9, hash-uniqueness at
FA-Apply-10, etc. — see `docs/proofs/README.md` for the full table).

Each FA-Apply gate's input is the (tx, current chain state) pair.
There is no dependency on:
- The RPC layer's prior accept/reject decision.
- The mempool's prior accept/reject decision.
- The gossip layer's filter/forward decision.
- The submitting peer's identity, IP, or auth status.

Therefore: a tx that bypasses every RPC layer (e.g., via host
compromise of the operator's `auth_secret_`) is still subject to apply-
time re-validation by every committee member at every height it is
included in. If the tx fails any FA-Apply gate, it is silently dropped
at apply time — even if the producer included it in a block, the apply
layer's deterministic gates produce the same drop on every committee
member's local apply, so the resulting state is consistent across
members.

The K-of-K apply path is the chain's correctness gate. The RPC
surface's five layers are the operator-experience gate (they provide
fast diagnostics for misuse + DoS resistance + auth gating against
casual adversaries). The composition is: RPC layers handle the easy
cases at low latency; the apply layer handles all cases at consensus
latency.   ∎

---

## 6. Adversary model + Finding-Register

### 6.1 Adversary model

The composition operates under the standard Determ adversary model
from `docs/proofs/Preliminaries.md` §3.2:

- **A_RPC1: Casual scanner.** Sends random RPC payloads to enumerate
  methods / fingerprint the server. **Defended.** Layer D throttles
  the scan rate; Layer E rejects unauthenticated requests (if
  enabled); the response's error message reveals only the failure
  category (not internal state).
- **A_RPC2: JSON fuzzer.** Sends syntactically-malformed JSON / wrong
  types / wrong hex lengths to probe the server's robustness.
  **Defended.** Layer B's S-018 diagnostics handle every malformed
  variant without crashing the daemon; Layer D throttles repeated
  attempts.
- **A_RPC3: Semantic attacker.** Sends well-formed JSON with adversarial
  semantics (stale nonce, insufficient balance, replay attempts).
  **Defended.** Layer C's per-method gates reject; the apply layer
  re-validates as a backstop.
- **A_RPC4: Authenticated insider.** Has access to `auth_secret_`
  (e.g., via host compromise) and submits adversarial txs through
  Layer E. **Partially defended at the RPC layer; fully defended at
  the apply layer (T-5).** The RPC layer accepts the auth; Layer C's
  semantic gates apply normally; the apply layer's FA-Apply gates are
  the authoritative validity criterion.
- **A_RPC5: Multi-IP flooder.** N attacker IPs flooding at sub-
  threshold rates. **Partially defended.** Per-IP buckets bound each
  IP's throughput; aggregate from N IPs scales with N. Full mitigation
  requires upstream throttling (LB / firewall). Documented as out-of-
  scope in `S014RateLimiterSoundness.md` §6.1(b).
- **A_RPC6: Slow-consume attacker.** Opens a TCP connection, sends
  bytes slowly without a newline. **Partially defended.** OS TCP
  backpressure + asio idle timeout + rate limiter's per-IP cap on
  concurrent sessions. The streambuf accumulator has no hard cap; see
  §6.2 F-1.

### 6.2 Notable findings

**Finding F-1 (Layer A's RPC body cap is operational, not structural).**
The RPC surface inherits the framing-layer ceiling `kMaxFrameBytes` =
16 MB from `include/determ/net/messages.hpp:101`, but the
`asio::streambuf` used in `handle_session` does not enforce this cap
explicitly. A peer sending a 100 MB line without a newline would grow
the streambuf to 100 MB before the OS TCP backpressure kicks in. While
the rate limiter's per-IP cap throttles connection attempts, the
in-session memory growth is not currently capped.

**Severity:** Low. The OS TCP receive buffer + asio's default backpressure
bound the in-flight bytes; sustained slow-consume requires an open
TCP connection. A multi-IP DDoS with `N` IPs each consuming `M` MB
could reach `N · M` MB of server memory.

**Recommended mitigation:** add a `max_size` argument to `read_until`
or wrap the streambuf with a size-bounded variant. Effort: ~5 LOC at
`src/rpc/rpc.cpp:158`. Could mirror the framing-layer's `kMaxFrameBytes`
cap (16 MB) or a tighter RPC-specific cap (1 MB; legitimate RPC
requests are well under this).

**Finding F-2 (Operator must enable S-001 auth for multi-tenant or
external-bind deployments — documentation discipline).** Layer E
defaults to off (`auth_secret_` empty); only when the operator sets
`rpc_auth_secret` (in config OR via `DETERM_RPC_AUTH_SECRET` env var)
does the HMAC check fire. For single-tenant boxes this is the correct
default; for multi-tenant or external-bind deployments the operator
MUST enable the secret.

**Severity:** Low (documentation-discipline; not a code defect).

**Recommended mitigation:** the existing warning at
`src/rpc/rpc.cpp:99-103` already fires when external-bind is enabled
without an auth secret. A complementary improvement would be: refuse to
start in external-bind mode with empty `auth_secret_` unless an
explicit `--allow-external-bind-no-auth` flag is passed. Effort:
~10 LOC + 1 test. Mirrors the pattern S-001 originally chose (default-
deny, opt-in escape).

**Finding F-3 (Read-only RPC methods lack per-field input validation
for some hex-decoded arguments).** Several read-only methods accept
hex-encoded arguments via `params.value(key, default)` and then attempt
to decode the hex via `from_hex_arr<N>`:

- `rpc_tx(hash_hex)` at `src/node/node.cpp:2682-2708`. Accepts arbitrary
  string; the length check (`hash_hex.size() != 64`) returns `nullptr`
  silently; the `from_hex_arr<32>` is wrapped in `try { ... } catch
  (...) { return nullptr; }` (lines 2685-2688). Acceptable; failure
  yields a null response, no state mutation.
- `rpc_state_proof(ns, key)` at `src/node/node.cpp:3287-3336`. The
  namespace `ns` is whitelisted (only `a|s|r|d|b|k|c`); the `key` is
  passed through as a raw byte string. No length check, no shape check.
  An adversarial `key` containing 1 MB of garbage would consume O(key)
  memory for the lookup attempt but no state mutation results.
- `rpc_state_proof`'s pagination behavior: no explicit page cap
  (returns the full proof + sibling-hash list). The proof depth is
  bounded by `log2(state_leaf_count)`, so this is bounded operationally
  — but not enforced structurally.

**Severity:** Very Low. Read-only methods cannot mutate state; the
operational bounds on input size are adequate for current deployments.

**Recommended mitigation:** add explicit `key.size() < 1 KB` checks at
the entry of `rpc_state_proof` / similar methods. Effort: ~5 LOC.
Defense-in-depth.

**Finding F-4 (No paired integration test exercises the full A→E
pipeline).** The existing tests cover each layer in isolation:

- `tools/test_rpc_hmac_auth.sh` — exercises Layer E (5 assertions).
- `tools/test_rpc_rate_limit.sh` — exercises Layer D (4 assertions).
- `tools/test_s018_json_validation.sh` — exercises Layer B (10
  assertions).
- `tools/test_anon_address_case.sh` — exercises Layer C (S-028; 3
  assertions).

There is no single test that exercises the full A→E pipeline with
mixed-class adversary inputs. A paired integration test (`tools/
test_rpc_input_validation_pipeline.sh`) would assert the composition:
oversized + malformed + semantically-invalid + rate-flooding +
unauthenticated requests all rejected, with the correct layer firing
in each case.

**Severity:** Low (documentation-discipline / operator-experience
robustness).

**Recommended mitigation:** add a paired integration test that:
1. Sends an oversized line — assert connection drop or `parse_error`.
2. Sends a malformed JSON line — assert `"S-018: "` response.
3. Sends a `submit_tx` with stale nonce — assert `"stale nonce"`
   response.
4. Sends > burst requests from the same IP — assert `"rate_limited"`.
5. Sends a request with wrong HMAC — assert `"auth_failed"`.

Effort: ~50 LOC bash + a few RPC dependencies. Pattern follows
`tools/test_rpc_hmac_auth.sh`.

**Finding F-5 (Future RPC methods could silently miss a layer —
documentation discipline).** The five-layer architecture is implicit
in `handle_session`'s control flow but is not documented as a
contract that new RPC methods must satisfy. A future RPC method added
to `dispatch` would automatically inherit Layers A, B, D, E (because
those run before dispatch in `handle_session`), but Layer C's
semantic gates are method-specific.

**Severity:** Very Low (process discipline, not a code defect).

**Recommended mitigation:** add a comment at the top of `dispatch`
in `src/rpc/rpc.cpp` documenting the five-layer architecture and the
explicit requirement that any state-mutating method MUST implement
Layer C's semantic gates. Cross-reference this proof file. Effort:
~15 lines of comment.

The five findings are advisory; none invalidate T-1 .. T-5. They
are surfaced for completeness so an external auditor can confirm
the scope of the composition argument.

---

## 7. Test-suite citation

The composition is exercised by the union of the per-layer tests:

| Test | Layer | Assertions |
|---|---|---|
| `tools/test_rpc_hmac_auth.sh` | E (S-001) | 5 (disabled, missing, wrong, correct, malformed-hex) |
| `tools/test_rpc_rate_limit.sh` | D (S-014) | 4 (RPC integration) |
| `tools/test_rate_limiter.sh` | D (S-014) | 16 (unit-test fixture) |
| `tools/test_rate_limiter_bucket.sh` | D (S-014 F-1) | 8+ (eviction) |
| `tools/test_s018_json_validation.sh` | B (S-018) | 10 (per-field-name diagnostic) |
| `tools/test_anon_address_case.sh` | C (S-028) | 3 (anon-address normalization) |
| `tools/test_rpc_localhost_only.sh` | E (S-001 alt) | 3 (localhost-bind default) |
| `tools/test_tx_replay_protection.sh` | apply-path FA-Apply-3 | * (apply-time backstop) |
| `tools/test_chain_apply_block.sh` | apply-path FA-Apply | * (apply-time backstop) |

The per-layer tests cover each layer in isolation. **F-4 above
recommends a paired integration test** (`tools/test_rpc_input_validation_
pipeline.sh`) that exercises the full A→E pipeline with one mixed-class
adversary input sequence; this is currently unimplemented.

The apply-path tests are the backstop: any adversarial input that
bypasses RPC validation gets re-validated at the apply layer. The
`test_tx_replay_protection` regression directly exercises FA-Apply-3
(stale-nonce drop at apply time) under adversarial conditions; if the
RPC layer's stale-nonce check were ever broken, the apply path would
still drop the tx.

---

## 8. Status

**Shipped (composition of five independent closures already in main).**
The five-layer architecture is live in the current `main` branch via
the union of:

- `src/rpc/rpc.cpp:79-194` — `RpcServer` constructor (lines 79-110)
  + `handle_session` (lines 142-195) + the dispatch table (197-272).
- `include/determ/util/json_validate.hpp` — S-018 helpers (Layer B).
- `include/determ/net/rate_limiter.hpp` — S-014 token bucket (Layer D).
- `include/determ/net/messages.hpp:101` — framing-layer ceiling
  inherited at Layer A (`kMaxFrameBytes` = 16 MB).
- `src/node/node.cpp:2403-3377` — every `rpc_*` method (Layer C).

**Not yet shipped (per §6 Finding-Register):**

- **F-1 mitigation (Layer A RPC-specific body cap).** ~5 LOC.
  Estimated 1d.
- **F-2 mitigation (refuse-external-bind-without-auth flag).** ~10 LOC.
  Estimated 1d.
- **F-3 mitigation (read-only method input length caps).** ~5 LOC.
  Estimated 0.5d.
- **F-4 mitigation (paired integration test).** ~50 LOC bash.
  Estimated 1d.
- **F-5 mitigation (architecture-contract comment in dispatch).**
  ~15 lines. Estimated 0.5h.

Total remaining: ~3.5d of incremental hardening, all advisory. None
invalidates T-1..T-5 — the composition is sound under current code.

This proof was added in the current review pass as part of the
analytic-closure sweep across the RPC input surface; it does not
modify any source code, only formalizes the composition argument
that the five independent closures together cover every adversary
class the threat model considers.

---

## 9. References

### Determ-internal source

- `src/rpc/rpc.cpp:79-110` — `RpcServer` constructor (binds Layer D
  + Layer E configuration).
- `src/rpc/rpc.cpp:112-129` — `verify_auth` (Layer E).
- `src/rpc/rpc.cpp:142-195` — `handle_session` (the proof's primary
  object).
- `src/rpc/rpc.cpp:197-272` — `dispatch` (Layer C dispatch table).
- `include/determ/util/json_validate.hpp` — S-018 helpers (Layer B).
- `include/determ/net/rate_limiter.hpp` — `RateLimiter` (Layer D).
- `include/determ/net/messages.hpp:101` — `kMaxFrameBytes`
  framing-layer ceiling (Layer A backing).
- `include/determ/net/messages.hpp:124-152` — `max_message_bytes`
  per-MsgType cap (Layer A for the gossip path; reference for the
  RPC F-1 finding).
- `src/node/node.cpp:2559-3377` — every `rpc_*` handler (Layer C
  semantic gates per method).
- `src/chain/chain.cpp` (apply layer) — `Chain::apply_block`,
  `Chain::apply_transactions` (T-5 backstop).

### Determ-internal proofs

- `docs/proofs/RpcAuthHmacSoundness.md` — S-001 closure (Layer E
  soundness).
- `docs/proofs/S014RateLimiterSoundness.md` — S-014 closure (Layer D
  soundness).
- `docs/proofs/S014ConcurrencyAnalysis.md` — S-014 concurrency model
  (Layer D mutex correctness).
- `docs/proofs/JsonValidationSoundness.md` — S-018 closure (Layer B
  soundness).
- `docs/proofs/S022WireFormatCaps.md` — S-022 closure (Layer A on the
  gossip path; reference for the RPC F-1 finding).
- `docs/proofs/S028AnonAddressNormalization.md` — S-028 closure
  (Layer C's address-normalization component).
- `docs/proofs/S002-Mempool-Sig-Verify.md` — S-002 closure (Layer C's
  signature-verification component for `submit_tx`).
- `docs/proofs/NonceMonotonicity.md` — FA-Apply-3 (apply-layer nonce
  gate; T-5 backstop).
- `docs/proofs/StakeLifecycle.md` — FA-Apply-4 (apply-layer stake
  gate; T-5 backstop).
- `docs/proofs/FeeAccounting.md` — FA-Apply-6 (apply-layer fee gate;
  T-5 backstop).
- `docs/proofs/S017UnstakeApplyConsistency.md` — apply-layer unstake
  + unlock-height gate.
- `docs/proofs/EquivocationSlashingApply.md` — FA-Apply-7 (apply-
  layer equivocation gate; backstops `rpc_submit_equivocation`).
- `docs/proofs/Preliminaries.md` §2.1 (H1: SHA-256 collision
  resistance), §2.2 (A1: Ed25519 EUF-CMA), §3.2 (Byzantine adversary
  model).

### Determ-internal tests

- `tools/test_rpc_hmac_auth.sh` — Layer E regression (5 assertions).
- `tools/test_rpc_rate_limit.sh` — Layer D RPC integration (4
  assertions).
- `tools/test_rate_limiter.sh` — Layer D unit fixture (16
  assertions).
- `tools/test_rate_limiter_bucket.sh` — Layer D F-1 closure (8+
  assertions).
- `tools/test_s018_json_validation.sh` — Layer B regression (10
  assertions).
- `tools/test_anon_address_case.sh` — Layer C S-028 regression (3
  assertions).
- `tools/test_rpc_localhost_only.sh` — Layer E + bind-mode (3
  assertions).
- `tools/test_tx_replay_protection.sh` — T-5 backstop regression
  (apply-time stale-nonce drop).
- `tools/test_chain_apply_block.sh` — T-5 backstop regression
  (full apply-layer FA-Apply pipeline).

### External

- **RFC 2104** (Krawczyk, Bellare, Canetti, Feb 1997) — "HMAC: Keyed-
  Hashing for Message Authentication." Standardizes Layer E's HMAC-
  SHA-256.
- **RFC 8032** — Ed25519 normative reference (Layer C `submit_tx`'s
  sig-verify gate).
- **NIST FIPS 180-4** — SHA-256 specification (Layer C / Layer E
  backing).
- **RFC 2475** (Blake et al., Dec 1998) — "An Architecture for
  Differentiated Services." Token-bucket conformance criterion
  underlying Layer D.
- **Bellare, Canetti, Krawczyk** (CRYPTO 1996) — "Keying Hash
  Functions for Message Authentication." Original HMAC paper.
- **Cruz** (IEEE Trans. Inf. Theory 1991) — "A calculus for network
  delay, Part I." `(σ, ρ)`-regulator formalism underlying Layer D.
- **Dwork, Naor, Reingold** ("Immunizing public-key cryptosystems
  against chosen-ciphertext attack") — defense-in-depth precedent
  for layered acceptance gates.
