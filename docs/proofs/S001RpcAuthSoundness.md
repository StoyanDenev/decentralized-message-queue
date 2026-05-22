# S001RpcAuthSoundness — composition theorem covering HMAC auth + input-validation defense (S-001 closure)

This document gives the comprehensive composition theorem for S-001 (RPC HMAC authentication) covering BOTH the cryptographic-soundness layer (HMAC-SHA-256 PRF + constant-time verify + secret confidentiality, as established in `RpcAuthHmacSoundness.md`) AND the second-line input-validation layer (range checks, length caps, type checks on RPC method arguments, as established in `RpcInputValidationDefense.md`). The composition exists to make a single end-to-end statement: under the **outside adversary** model (`A_outside` — no shared secret) the cryptographic layer alone establishes soundness; under the **authenticated insider** model (`A_inside` — has the operator's `rpc_auth_secret` but attempts to inject malformed or out-of-contract payloads) the input-validation layer is the second-line defense; and under **both** models replay safety reduces to apply-layer nonce gating (`FA-Apply-3`), so the joint soundness statement is the full RPC defense posture.

The proof is structural rather than novel: each constituent soundness statement is already proved in its respective companion document. The contribution here is to compose those statements into a single auth-then-validate pipeline soundness theorem, exhibit an exhaustive bypass-surface enumeration for state-mutating endpoints, and surface composition findings that no single per-layer proof catches — in particular, the question of whether a future RPC handler could bypass the canonical pattern at `src/rpc/rpc.cpp:130-145` (the pre-dispatch auth gate) by adding an out-of-band handler entry.

**Companion documents:** `RpcAuthHmacSoundness.md` (the HMAC-PRF cryptographic layer; T-1..T-5 composed here); `RpcInputValidationDefense.md` (the five-layer defense; Layer B / Layer C composed into the input-validation arm); `JsonValidationSoundness.md` (S-018; the structural-validation portion of the input-validation layer); `S022WireFormatCaps.md` (the framing-layer body-cap which gates the maximum size of any RPC request); `NonceMonotonicity.md` (FA-Apply-3; the apply-layer nonce gate that provides the replay backstop when HMAC alone does not bind a nonce per T-2); `S014RateLimiterSoundness.md` (the cheaper-than-HMAC pre-gate that defeats online HMAC brute-force by capping verify rate); `Preliminaries.md` §2.1 (A2/H1 SHA-256 collision resistance), §2.2 (A1 Ed25519 EUF-CMA — cited for the Layer C `submit_tx` sig-verify gate but not directly used for the HMAC auth); `SECURITY.md` §S-001 (closure narrative this composition formalizes) + §S-018 (input-validation closure that the second arm composes).

---

## 1. Background

### 1.1 S-001 closure context

S-001 originally documented two adversaries on the RPC surface:

1. **Network-reachable unauthenticated RPC.** Closed by Option 1 (localhost-only default at `src/rpc/rpc.cpp:79-89`). An attacker without same-host access cannot connect; the surface vanishes at the network layer.
2. **Cross-tenant on the same host.** Closed by Option 3 (HMAC-SHA-256 RPC authentication at `src/rpc/rpc.cpp:60-129`). An attacker without the operator's `rpc_auth_secret` cannot forge a valid request; the HMAC-PRF assumption (`RpcAuthHmacSoundness.md` T-1) bounds the forgery probability at `≤ 2^-256 + q²/2^256` per attempt.

Both closures are shipped in the current `main` branch. `RpcAuthHmacSoundness.md` formalizes Option 3 in isolation: T-1 (auth soundness), T-2 (replay analysis — confirms known limitation per S-001's threat model), T-3 (constant-time compare audit — passes), T-4 (secret confidentiality at the RPC surface — passes), T-5 (HMAC PRF soundness with q²/2^256 q-query bound).

### 1.2 The two-layer defense model

The cryptographic layer alone is sufficient against `A_outside` — an adversary with no access to the operator's secret. But once an adversary obtains the secret (e.g., via the F-1 / F-2 finding in `RpcAuthHmacSoundness.md` §6, or via a compromised operator workflow), the HMAC layer's soundness statement no longer constrains them: they can compute the HMAC over any (`method`, `params`) pair and the server's `verify_auth` will accept. The second-line defense against this authenticated-insider class is the input-validation layer (Layer B + Layer C of `RpcInputValidationDefense.md`): the server still applies structural validation (JSON shape + S-018 hardened from_json paths) and semantic validation (per-method semantic gates — balance pre-checks, nonce monotonicity at gossip-handler entry, signature verification, address canonicalization, etc.) before any state mutation.

The composition statement is: under `A_outside`, the HMAC layer is the security; under `A_inside`, the input-validation layer is the security; under both, the apply-layer nonce gate (`FA-Apply-3`) provides replay safety because the HMAC alone does not bind a nonce (T-2 in `RpcAuthHmacSoundness.md`). The three layers fire in canonical order at `src/rpc/rpc.cpp:142-195` (rate-limit → parse → auth → dispatch-to-handler-with-semantic-gates) and compose without cross-layer interference.

### 1.3 Why a composition document

Each per-layer proof is self-contained and provides the per-property soundness statement. The composition document exists for three reasons:

1. **Single-statement end-to-end soundness** — an auditor asking "is S-001 closed?" reads one document and confirms the joint posture, not three.
2. **Exhaustive bypass-surface enumeration** — the per-layer proofs each cite the canonical control flow at `handle_session`, but no single document enumerates the state-mutating endpoints and confirms that none reaches dispatch without auth. This document closes that gap (T-3 below).
3. **Cross-cutting findings** — observations that are visible only at the composition layer (e.g., F-2 below: a future RPC handler that bypasses dispatch by hooking into a non-standard code path would not be caught by any single per-layer proof). These findings are surfaced in §6.

---

## 2. Notation + assumptions

### 2.1 Notation

Let `K ∈ {0,1}*` denote the server's `auth_secret_` field — the operator's RPC secret bytes (`src/rpc/rpc.cpp:90`). Let `R = (method, params, auth)` denote an RPC request triple. Let `H(K, m) := hex(HMAC-SHA-256(K, m))` denote the canonical HMAC-hex output. Let `canonical(method, params) := method ‖ "|" ‖ params.dump()` denote the canonical pre-image bytes (`src/rpc/rpc.cpp:52-58`).

A request `R` is **authenticated** iff `H(K, canonical(method, params)) = auth`, modulo the constant-time compare at `src/rpc/rpc.cpp:124-128`. A request is **state-mutating** iff its `method` is in `MUTATE_STATE := {send, stake, unstake, register, submit_tx, submit_equivocation}` (the six endpoints that touch `chain_` state or the mempool via `Node::rpc_*`).

Let `RPC_DISPATCH` denote the set of methods accepted by `RpcServer::dispatch` at `src/rpc/rpc.cpp:197-272`. `MUTATE_STATE ⊂ RPC_DISPATCH`; the remaining methods are read-only.

### 2.2 Assumptions

The composition reduces to:

- **(A1) Ed25519 EUF-CMA** (Preliminaries §2.2). Not directly used by the HMAC scheme but cited by Layer C's `submit_tx` semantic gate where the tx's Ed25519 signature is verified before mempool admit (`src/node/node.cpp:3163-3168`). Provides the cryptographic backstop that even under `A_inside` (where the attacker has the HMAC secret), forging a transaction signed by an unowned account requires breaking A1.
- **(A2 / H1) SHA-256 collision resistance** (Preliminaries §2.1). Used implicitly by HMAC-SHA-256's PRF-via-compression-function-CR reduction (Bellare–Canetti–Krawczyk 1996; tightened by Bellare 2006). The single-query forgery bound `2^-256` and the q-query birthday bound `q²/2^256` both reduce to A2 + the standard HMAC reduction. Also used by Layer B's JSON parse on a sense: structural-validation soundness rests on the underlying parser's correctness, which itself does not consume A2 — but the apply-layer nonce gate and the per-tx hash-uniqueness check (T-2 below) reduce to A2.
- **(A6) HMAC-SHA-256 PRF assumption.** The standard cryptographic primitive's security parameter is `q²/2^256` for q-query distinguishing advantage (`RpcAuthHmacSoundness.md` §2.1 + L-5). Together with A2 above, this gives the auth-forgery bound `2^-256 + q²/2^256` per attempt that T-1 below composes.
- **(H_RPC_ORDERING) Canonical pre-dispatch ordering.** Every state-mutating method passes through `handle_session` at `src/rpc/rpc.cpp:142-195` whose control flow is rate-limit (`src/rpc/rpc.cpp:172`) → parse (`:176`) → auth (`:179`) → dispatch (`:184`). This is a property of the implementation; the audit at T-3 below confirms no state-mutating handler bypasses this ordering.

### 2.3 Adversary models

**`A_outside` (the outside-adversary model).** The adversary has no access to the operator's `rpc_auth_secret`. They can connect to the RPC socket (e.g., over loopback as a co-tenant, or externally if the operator opted out of localhost-only mode), eavesdrop on legitimate request traffic (passive), and inject arbitrary bytes (active). They cannot recover `K` from observed HMACs without breaking A6 (`RpcAuthHmacSoundness.md` L-5).

Under `A_outside`, the HMAC-auth layer is the security. The input-validation layer is a backup whose soundness is already established in `RpcInputValidationDefense.md` but is operationally redundant against this adversary class: every adversarial request is rejected at the HMAC gate before reaching the input-validation layer.

**`A_inside` (the authenticated-insider model).** The adversary has the operator's `rpc_auth_secret` (e.g., they compromised the operator's host, or are a multi-tenant peer with the secret via misconfiguration, or are the operator themselves attempting an out-of-contract operation). They can compute valid HMACs over arbitrary canonical bytes. The HMAC-auth layer accepts every request they send.

Under `A_inside`, the HMAC-auth layer is **not** the security — it accepts the request. The input-validation layer is the security: structural malformedness is caught by Layer B (S-018 hardened from_json + JSON parse errors), semantic out-of-contract behavior is caught by Layer C (per-method semantic gates), and replay of valid signed transactions is caught at the apply layer by FA-Apply-3 (nonce monotonicity).

The composition statement covers both classes:

```
soundness(A_outside) := HMAC-auth-gate(R) ∧ apply-layer(R)
soundness(A_inside)  := input-validation(R) ∧ apply-layer(R)
```

The joint statement is the conjunction over both: every request is either rejected at HMAC (under `A_outside`) or rejected at input-validation (under `A_inside`) or accepted at HMAC but caught at input-validation (the cross-cutting case where the operator's own host has been compromised to inject a malformed payload). Replay safety is the third arm that closes the loop.

---

## 3. Theorem set

### Theorem T-1 (Composition: Auth-then-Validate Pipeline Soundness)

A request `R` that reaches a state-mutating handler at `src/node/node.cpp::rpc_*` (the Layer C entry point for any `method ∈ MUTATE_STATE`) has passed **all three of**:

1. The HMAC-auth gate at `src/rpc/rpc.cpp:179` (Layer E in `RpcInputValidationDefense.md`'s nomenclature; T-1 in `RpcAuthHmacSoundness.md`'s nomenclature).
2. The JSON structural validation gate at Layer B — `json::parse` at `src/rpc/rpc.cpp:176` plus any downstream `from_json` calls in `dispatch`. For `submit_tx`, the `tx` sub-object is routed through the S-018-hardened `Transaction::from_json` per `JsonValidationSoundness.md`.
3. The per-method semantic validation gate at Layer C — the gates enumerated in `RpcInputValidationDefense.md` §3.4 (S-028 anon-address canonicalization, hash recompute, nonce monotonicity at gossip-handler entry, signature verification, mempool admission, replace-by-fee, balance pre-check).

The joint statement is:

$$
\Pr\bigl[R \text{ admitted to } \texttt{rpc\_submit\_tx} \text{ under } A_{\text{outside}}\bigr] \;\leq\; 2^{-256} + q^2 / 2^{256}
$$

per attempt by `RpcAuthHmacSoundness.md` T-1 — the auth gate alone gives this bound regardless of the input-validation gate's downstream behavior.

Under `A_inside`, the auth gate is a no-op (the attacker has the secret), so the bound reduces to whatever the input-validation gates establish. By `RpcInputValidationDefense.md` T-1 (Layered Defense Completeness — see L-3 there), every adversary class A1..A5 is rejected by at least one of the five layers; the relevant arm for `A_inside` is Layers B + C, which are deterministic gates with no probabilistic failure mode (they reject or accept by predicate, no cryptographic randomness involved).

The composition gives an end-to-end pipeline soundness statement: under either adversary model, no out-of-contract request mutates state. The argument is by case analysis over the two adversary models in §5 below.

### Theorem T-2 (Replay Defense Composition)

HMAC alone does not bind a nonce (this is `RpcAuthHmacSoundness.md` T-2's known-limitation finding). An attacker who observes a single legitimate state-mutating request `(method, params, auth)` over the wire — for example, by eavesdropping on the loopback socket as a co-tenant before the operator enabled S-001 Option 1 (localhost-only), or by a non-TLS reverse-proxy hop — can replay the same triple indefinitely against the same server. `verify_auth` accepts each replay because the HMAC over `canonical(method, params)` is byte-identical.

The replay defense composition is:

**Lemma L-1 (HMAC-bound auth + apply-layer nonce gate ⇒ end-to-end replay safety).** For any state-mutating method whose payload is a Determ transaction (`submit_tx`, `send`, `stake`, `unstake`, `register`), the underlying transaction carries a `nonce` field that the apply layer gates against `accounts_[tx.from].next_nonce` by strict equality at `src/chain/chain.cpp:739` (per `NonceMonotonicity.md` T-N1). A replay of a state-mutating RPC produces a transaction whose `nonce` was already consumed at the original transaction's application; on the replay attempt, the apply-time gate at `chain.cpp:739` short-circuits (`tx.nonce != sender.next_nonce` → `continue`), no state mutation occurs.

For `submit_equivocation` (the sixth state-mutating method), the apply-time replay defense is provided by `EquivocationSlashingApply.md` (FA-Apply-10) T-E3: re-applying the same `EquivocationEvent` finds `stake_locked = 0` (the offender's stake was zeroed at the first application) and is silently no-op'd.

So the end-to-end replay statement is: even under `A_outside` with HMAC replay, and under `A_inside` with the attacker computing fresh valid HMACs over a stale transaction, the apply-layer gate at `chain.cpp:739` (for tx-based methods) or `chain.cpp::apply_equivocation_event` (for slashing) provides the second-line defense. The HMAC layer is not required to bind a nonce because the apply layer already does — and the apply layer is the consensus-binding correctness gate (per `RpcInputValidationDefense.md` T-5).

The composition statement: HMAC ensures that an outside attacker cannot fabricate new state-mutating requests; the apply-layer nonce gate ensures that replays of legitimate requests (under either adversary model) are no-op'd. Together, the RPC surface is replay-safe modulo the read-only methods (which are idempotent by design — replaying a `balance` query is no information leakage beyond the original query).

### Theorem T-3 (Authentication Bypass Surfaces — Exhaustive)

We enumerate every state-mutating endpoint reachable through the RPC server and confirm that the auth check fires **before** any state mutation. The audit method is exhaustive case analysis over `dispatch` at `src/rpc/rpc.cpp:197-272`.

| Endpoint (Layer C entry) | RPC method name | dispatch line | Layer C handler (in `src/node/node.cpp`) | Auth-before-handler? |
|---|---|---|---|---|
| `rpc_send` | `send` | `:206-211` | `node.cpp:2804` | ✓ (via `:179` gate) |
| `rpc_stake` | `stake` | `:212-216` | `node.cpp:2850` | ✓ (via `:179` gate) |
| `rpc_unstake` | `unstake` | `:217-221` | `node.cpp:2884` | ✓ (via `:179` gate) |
| `rpc_register` | `register` | `:203` | `node.cpp:3338` | ✓ (via `:179` gate) |
| `rpc_submit_tx` | `submit_tx` | `:226-227` | `node.cpp:3121` | ✓ (via `:179` gate) |
| `rpc_submit_equivocation` | `submit_equivocation` | `:228-230` | `node.cpp:3207` | ✓ (via `:179` gate) |

For every endpoint, the dispatch entry is reached from `handle_session` at line `:184` (`response["result"] = dispatch(req);`), which executes only when `verify_auth(req)` at `:179` returned empty (passed) — see the control flow at lines `:165-187`. The audit conclusion is that **no state-mutating RPC method is reachable without auth** when `auth_secret_` is non-empty.

A subtle point: when `auth_secret_` is empty (the default for single-tenant boxes per `RpcAuthHmacSoundness.md` §2.3), `verify_auth` returns empty unconditionally (line `:113`), so every request reaches dispatch. This is the documented single-tenant escape hatch (`SECURITY.md` §S-001 narrative; `RpcInputValidationDefense.md` §2.2 deployment recommendation). Under the multi-tenant or external-bind threat model, the operator MUST enable the secret; under the single-tenant model, the host-level access control (only the operator can connect to localhost on a single-user box) substitutes for the HMAC layer.

The audit confirms three structural facts about `handle_session`:

1. **Single entry point.** All RPC requests arrive via `handle_session` (`:142-195`); there is no out-of-band injection path. The asio `accept_loop` (`:131-140`) is the only `post`-er to `handle_session`.
2. **Single dispatch point.** All `Node::rpc_*` invocations route through `dispatch` (`:197-272`). There is no direct call into a state-mutating `rpc_*` method from outside `dispatch`.
3. **Auth-before-dispatch is invariant.** The control flow at `:165-187` runs `verify_auth` (line `:179`) before `dispatch` (line `:184`). Refactoring this to call `dispatch` before `verify_auth` (or to allow `dispatch` from a different path) would require a non-trivial diff that the existing per-layer tests (`tools/test_rpc_hmac_auth.sh` 5 assertions) would not catch on their own — but **F-2 below** registers this as a code-review discipline finding.

The exhaustive enumeration is the bedrock of the composition theorem: T-1's "no out-of-contract request mutates state under either adversary model" reduces, for the `A_outside` arm, to "no state-mutating endpoint is reachable without auth," which is exactly T-3.

### Theorem T-4 (Constant-Time Verify Audit Under Composition)

`RpcAuthHmacSoundness.md` T-3 establishes that the HMAC compare at `src/rpc/rpc.cpp:122-128` is constant-time: the XOR-OR loop iterates fixed 64 bytes with no early exit, the per-iteration body has no branch dependence on individual byte values, and the final `(diff == 0) ? "" : "auth_failed"` ternary is the only conditional whose information content is "all 64 bytes matched vs ≥ 1 mismatched" — a single aggregate bit, useless for per-byte probing.

The composition argument under `A_inside`'s repeated probing model is:

**Lemma L-2 (Constant-time compare resists repeated probing under `A_inside`).** Even an attacker with the secret who tries to probe the server's timing channel via repeated `verify_auth` calls would observe constant per-request latency at the compare step (`:124-127`). The HMAC compute itself (line `:119-120`) is also constant-time per fixed-size canonical-bytes input — OpenSSL's `HMAC(EVP_sha256(), ...)` is implemented over the SHA-256 round function which has no data-dependent branches. The only variable-time component would be the JSON parse at `:176` (whose latency varies with input size) and the canonicalization at `canonical_for_hmac` (whose latency varies with `params.dump()` size). Neither of these is a secret-bearing operation, so timing variability there reveals nothing about `K`.

The composition statement: constant-time compare prevents timing-channel leakage of the secret under both `A_outside` (who doesn't have the secret and is trying to recover it) and `A_inside` (who has the secret but is trying to probe whether the constant-time property holds — a paranoid operator might also probe). Modern compilers at `-O2` are observed to preserve the loop structure (no auto-introduced early exit); the optional `volatile`-qualified accumulator hardening (F-3 in `RpcAuthHmacSoundness.md`) is defense-in-depth, not a fix for any observed defect.

### Theorem T-5 (Secret Lifecycle Composition)

`RpcAuthHmacSoundness.md` T-4 establishes that `auth_secret_` is never written to any log, error response, or wire message by `src/rpc/rpc.cpp`. The startup log at `src/rpc/rpc.cpp:95-97` emits only the length (`auth_secret_.size()`), never the value. The `verify_auth` error returns at lines `:115` and `:128` are fixed string constants with no dependence on `K`. The dispatch method at `:197-272` doesn't touch `auth_secret_`. The client-side `rpc_call` at `:276-321` reads the secret from either the explicit argument or the `DETERM_RPC_AUTH_SECRET` env var, computes the HMAC, embeds it in the request — the secret itself is never written to any output.

The composition with the input-validation layer's defense against secret-exposure via crafted JSON responses is:

**Lemma L-3 (No reflection of `auth_secret_` in error diagnostics).** By exhaustive audit of `RpcInputValidationDefense.md`'s Layer B and Layer C reject paths:

- **Layer B (`json::parse` failure).** The exception's `what()` is the nlohmann-json parse-error message, which references only the input line's structural problem (e.g., `"parse error at line 1, column 23: unexpected end of input"`). No reflection of any other request data, and certainly no reflection of `auth_secret_`.
- **Layer B (S-018 `from_json` failure).** The exception's `what()` carries the `"S-018: <field>"` diagnostic. Per `JsonValidationSoundness.md` T-2 (No Internal-Error Leakage), the diagnostic includes only the field name + type expectation, never input bytes or secret material.
- **Layer C (per-method semantic failure).** Each `rpc_*` handler throws `std::runtime_error` with a method-specific diagnostic. The exhaustive enumeration in `RpcInputValidationDefense.md` §3.4 covers all six state-mutating handlers; none of them references `auth_secret_` in any diagnostic.
- **Layer E (`verify_auth` failure).** The error strings are `"auth_required: missing 'auth' field"` and `"auth_failed"` — both fixed constants per `RpcAuthHmacSoundness.md` L-4.

The composition statement: `rpc_auth_secret` is never reflected in any response payload or error diagnostic. The HMAC layer's secret confidentiality (T-4 in `RpcAuthHmacSoundness.md`) and the input-validation layer's defense against information disclosure via crafted error messages (T-2 in `JsonValidationSoundness.md`) compose to give end-to-end secret confidentiality at the RPC surface.

A residual finding registered in `RpcAuthHmacSoundness.md` F-1 — the `Config::to_json` plaintext persistence path — is outside the RPC server's runtime scope (it's a configuration-surface lifecycle issue, not an active-state confidentiality breach). The composition does not cover that surface but cross-references it as out-of-scope for this RPC-runtime-soundness composition.

---

## 4. Composition with FA-track proofs

### 4.1 FA1 (K-of-K mutual-distrust safety)

RPC authentication is orthogonal to consensus safety. The K-of-K safety property of FA1 holds independently of who submitted any transaction to mempool — once a transaction is included in a block by the producer, every committee member independently verifies the block by re-applying its transactions (`Chain::apply_transactions`) and validating the block's signing-bytes. The RPC layer's accept/reject decision does not propagate to the consensus layer; it only gates mempool admission.

The composition with FA1 is that RPC is one of two paths into mempool (the other being gossip), and FA1's safety is preserved regardless of which path the transaction took. T-5 in `RpcInputValidationDefense.md` (Composition with K-of-K Apply Path) formalizes this orthogonality.

### 4.2 FA-Apply-3 (NonceMonotonicity)

The apply-layer nonce gate at `src/chain/chain.cpp:739` is the second-line replay defense composed in T-2 above. `NonceMonotonicity.md` T-N1..T-N6 establish that every committed block's transactions advance per-account `next_nonce` exactly once, that stale-nonce transactions are silently skipped, that future-nonce transactions are silently skipped (no gap-filling), and that the genesis state has `next_nonce = 0` for every auto-created account.

The composition with the RPC layer is: even if HMAC alone admits a replayed transaction (T-2 limitation), the apply-time gate rejects it before any state mutation. The replay attempt becomes a no-op at the apply boundary.

### 4.3 S-006 (ContribMsg equivocation)

S-006 (Phase-1 same-generation ContribMsg equivocation detection per `S006ContribMsgEquivocation.md`) is orthogonal to RPC authentication. ContribMsg is a consensus-protocol message that flows over gossip, not RPC; the equivocation defense fires at the consensus layer.

The cross-reference is: `rpc_submit_equivocation` (one of the six state-mutating RPC methods enumerated in T-3) accepts an `EquivocationEvent` constructed by an external party (e.g., a watchdog that observed equivocation off-chain and wants to submit evidence). The RPC layer's auth gate (T-1) ensures only authenticated callers can submit; the apply-layer slashing logic (FA-Apply-10) ensures the evidence is replayed-safe (re-application is no-op'd).

### 4.4 S-018 (JSON validation soundness)

S-018 is the input-validation layer's structural-validation arm (Layer B in `RpcInputValidationDefense.md`'s nomenclature). The composition at T-1 above incorporates the S-018 hardened from_json paths as a second-line defense under `A_inside`: an authenticated insider attempting to inject a malformed payload (e.g., a `submit_tx` with a missing `sig` field, or a wrong-hex-length `from` address, or a non-numeric `amount`) is rejected by S-018 before reaching Layer C's semantic gates.

The composition is mechanical: T-1's "the request has passed Layer B" reduces to `JsonValidationSoundness.md` T-1 (Clear-Diagnostic Soundness) + T-3 (Defense-in-Depth at 5 layers — wire / RPC / snapshot / keyfile / genesis).

### 4.5 S-022 (per-MsgType body caps)

S-022 is the framing-layer's body-cap (Layer A in `RpcInputValidationDefense.md`'s nomenclature) — primarily applied to the gossip path. For the RPC path, the analogous bound is the `kMaxFrameBytes` ceiling on body size (`include/determ/net/messages.hpp:101` = 16 MB) inherited at the framing layer.

The composition is: an attacker attempting an oversize RPC request (e.g., a 100 MB JSON line as a slow-consume DoS) is bounded by the framing-layer ceiling + the OS TCP backpressure + the rate limiter's per-IP cap. T-1's pipeline soundness statement composes with S-022's framing-layer bound at the very first gate. `RpcInputValidationDefense.md` F-1 surfaces the residual that the RPC path's body cap is operational rather than structural (the `asio::streambuf` accumulator lacks an explicit cap); a future hardening would mirror the gossip path's per-MsgType cap into a per-RPC-method cap.

---

## 5. Threat model coverage matrix

| Threat | Defense | Residual risk | Residual mitigation |
|---|---|---|---|
| Online brute-force of HMAC | `2^-256` per attempt (T-1) + S-014 rate limit caps verify rate per peer-IP at `≤ ⌊C + r·Δ⌋` per window. At `r = 100 req/s` (web profile default) the attacker's per-IP forge-rate is ≤ 100/s; cumulative `Q · 2^-256` is negligible for any operational `Q`. | Aggregate from N coordinated IPs scales the forge-rate to N · 100/s; even at N = 10^6 and `Q = 10^14 / day` the bound `Q · 2^-256` is `≤ 2^-209`, strongly negligible. | Log-and-alert at operator level on any `auth_failed` rate exceeding a threshold (e.g., `>100/min` per IP); the alert signals targeted probing rather than a probabilistic success risk. |
| Offline brute-force of `rpc_auth_secret` hash | Secret never persisted as a hash anywhere; the runtime secret is stored as raw bytes in `auth_secret_` (decoded from hex at server construction). No collision attack on a hash digest of the secret is available. | Plaintext at-rest in `Config::to_json` per `RpcAuthHmacSoundness.md` F-1. Env-var leak at `/proc/PID/environ` per F-2. | Config-file permissions `chmod 0600` + `hidepid=2` Linux mount option. Long-term: passphrase encryption (v2.17 pattern applied to RPC secret) + secrets-manager integration. |
| Replay of authenticated state-mutating RPC | Apply-layer nonce gate at `src/chain/chain.cpp:739` (FA-Apply-3) — every state-mutating tx is gated by strict-equality nonce check at apply; replays are silently no-op'd. For `submit_equivocation`, FA-Apply-10 T-E3 provides the parallel replay-safety. | Idempotent reads (`balance`, `nonce`, `status`, `block`, `headers`, etc.) are replay-safe by design — replaying a read query is no information leakage beyond the original query. | None required; the residual is benign. |
| Timing-channel HMAC compare | Constant-time XOR-OR loop at `src/rpc/rpc.cpp:124-127` (T-4). No per-byte timing channel. | Process-level timing observability (`top`, `perf`, kernel scheduling) is outside the RPC server's scope. An attacker with kernel-level observability already has the secret via memory dump. | Operator monitoring + kernel hardening (out of scope for the RPC server). |
| Malformed JSON payload | S-018 hardened `from_json` paths (Layer B per `RpcInputValidationDefense.md`) catch missing/wrong-type/wrong-hex-length fields with `"S-018: <field>"` diagnostic. Layer B's S-018 surface is exhaustively documented in `JsonValidationSoundness.md`'s conversion inventory. | None for state-mutating methods — every required field flows through S-018. Scalar-input methods (e.g., `balance(domain)`) accept wrong-type input as the default value (e.g., `""`), which Layer C's semantic check absorbs. | None required. |
| Oversized JSON payload | Framing-layer ceiling `kMaxFrameBytes` = 16 MB (S-022). Per-tx ceiling at canonical encoding limits any individual transaction to well under 64 KB. | Pre-cap parse cost is bounded by S-014's rate limit (the attacker pays parse work per request, capped at the bucket budget per peer-IP). Slow-consume attacks via partial bytes without newline are bounded by OS TCP backpressure + asio idle timeout. | `RpcInputValidationDefense.md` F-1 surfaces the residual hardening (add `max_size` to `read_until` to mirror the gossip path's per-MsgType cap on RPC). |
| State-mutation under no-auth | T-3 exhaustive enumeration confirms no state-mutating handler is reachable without auth when `auth_secret_` is non-empty. | Localhost-only mode (S-001 Option 1; default for single-tenant boxes) does not require auth — single-tenant operator owns the whole host, so the host-level access control substitutes for the HMAC layer. | Documented escape hatch in `SECURITY.md` §S-001 closure narrative; operator deploying for multi-tenant or external-bind use MUST enable the secret. F-2 surfaces a recommended "refuse external bind without auth" CLI flag. |
| Secret in log files | Startup log at `src/rpc/rpc.cpp:95-97` emits only `auth_secret_.size()`, never the value. All error paths return fixed string constants (T-5 above + `RpcAuthHmacSoundness.md` L-4). | None for chain logs (the audit confirms no secret material reaches any log emit site in `src/rpc/rpc.cpp` or `src/node/node.cpp`). Operator log-management is policy: log files containing the startup banner are no information leakage; if the operator pipes logs to a third-party aggregator, the startup-banner's `len = N` is `0 bits` of secret information (every operator follows the recommended 32-byte length). | None required for chain code; operator log-aggregator hygiene is operations scope. |
| Authenticated insider with malformed payload (`A_inside`) | Input-validation layer's Layer B (S-018) + Layer C (semantic gates) — under T-1, the request reaching `rpc_submit_tx` has passed both. | The insider can still submit a transaction signed by their own account; the apply layer treats this as a legitimate transaction. | This is the intended behavior — `A_inside` is the operator themselves (or a host compromise). Apply-layer FA-Apply-3 + FA-Apply-4 + FA-Apply-6 enforce the chain-state invariants regardless. |
| Authenticated insider replaying captured tx (`A_inside` + replay) | Apply-layer nonce gate (FA-Apply-3 T-N1) drops the replay at apply boundary. | None — even an authenticated insider cannot replay a state-mutating transaction to double-spend. | None required. |
| Authenticated insider submitting tx from someone else's account | Layer C's signature verification gate at `src/node/node.cpp:3163-3168` rejects any `submit_tx` whose `sig` does not verify against the embedded `signing_bytes` under the claimed `from` address's Ed25519 public key. Forging this requires breaking A1 (Ed25519 EUF-CMA). | None — A1 + Layer C composition is tight. | None required. |
| Authenticated insider exploiting a Layer C bug (hypothetical) | Apply-layer re-validation (T-5 in `RpcInputValidationDefense.md`). Every transaction admitted to mempool is re-validated by every committee member at every block height; per-block FA-Apply gates enforce the canonical chain-state invariants regardless of mempool admission decisions. | A Layer C bug that admits an invalid transaction to mempool would still result in apply-time silent drop — the chain state remains correct, but the operator-experience degrades (the transaction never appears in a block despite mempool admission). | Code-review discipline: every state-mutating Layer C gate has matched FA-Apply test coverage. |

---

## 6. Findings

### Finding F-1 (Secret-exposure-via-response is unit-test-uncovered).

The input-validation layer's defense against secret-exposure via crafted JSON responses (T-5 above) is established by audit of source files in §3.5 of `RpcInputValidationDefense.md` and §3 of `RpcAuthHmacSoundness.md`. The composition argument relies on the fact that no `rpc_*` handler's error path reflects any input bytes that could carry secret material. This is established by inspection; no unit test specifically exercises the "an attacker crafts an error-inducing input that, if reflected back, would leak the secret" pattern.

**Severity:** Low (the audit is comprehensive; the inspection-based defense is sound, but a unit-test pinning would be defense-in-depth).

**Recommended mitigation:** Add a regression test that asserts the following for every state-mutating RPC endpoint: send a malformed payload designed to trigger a Layer B or Layer C error path, then assert that the response's `error` field does NOT contain any substring of the configured `rpc_auth_secret`. The test would run with `rpc_auth_secret = "DEADBEEF…"` (a known marker), send 6 × 2 = 12 malformed payloads (one Layer B + one Layer C per state-mutating endpoint), and confirm that "DEADBEEF" never appears in any response. Chip task candidate.

**Effort:** ~50 LOC bash + a few RPC dependencies. Pattern follows `tools/test_rpc_hmac_auth.sh`. Estimated 0.5d.

### Finding F-2 (Composition gap if a future RPC handler bypasses the canonical auth pattern).

The T-3 exhaustive enumeration is valid as of the current code (rev. main as of this commit). It rests on the structural property that every `Node::rpc_*` handler is reached only via `dispatch` (`src/rpc/rpc.cpp:197-272`), which is itself reached only via `handle_session` (`:142-195`)'s auth-then-dispatch ordering at `:179-184`. A future RPC handler that bypasses this pattern — for example, a new handler invoked from an out-of-band code path (e.g., a WebSocket upgrade, a long-polling endpoint, or an admin-only side channel) — would not inherit the auth gate.

**Severity:** Very Low (process discipline, not a code defect — the current code passes T-3).

**Recommended mitigation:** Add a code-review checkbox to the contribution guide: "Every new state-mutating RPC handler MUST be added to `RpcServer::dispatch` AND only invoked from there." Add a structural unit test that scans `src/node/node.cpp` for `rpc_*` methods and asserts that every method's only call site is `RpcServer::dispatch` (a static analysis check could be a CI gate). Cross-reference this proof file in the dispatch table's leading comment.

A related canonical-position recommendation: keep the auth gate at `:179` in front of the dispatch call at `:184` in any future refactor of `handle_session`. The comment at `:177-178` already documents the rationale ("HMAC auth check before dispatching"), but a more explicit "DO NOT MOVE THIS BELOW DISPATCH" comment would prevent accidental regression.

**Effort:** ~5 lines of dispatch-table comment + ~30 LOC for the structural-test CI gate. Estimated 0.5d.

### Finding F-3 (Log-message safety in error paths — broad audit).

The T-5 audit (composition with T-4 in `RpcAuthHmacSoundness.md`) confirms no `rpc_*` handler's error path reflects any input bytes derived from `auth_secret_`. But the audit does NOT cover the question: does any error diagnostic embed a portion of the input that could carry secret material from a different source (e.g., the operator's wallet passphrase echoed back, or a piece of a Tx signature reflected in a hash-mismatch diagnostic)?

For example, the hash-recompute error at `src/node/node.cpp:3150-3155` throws `"hash mismatch: expected <hex>, got <hex>"` where the `expected` hex is the client-supplied `tx.hash`. The client controls this field; an attacker could try to embed secret material in `tx.hash` and harvest it from the error diagnostic. But: `tx.hash` is constrained to be a 32-byte SHA-256 hash (`hex` of size 64); a non-conforming value is rejected by S-018's `json_require_hex` for the `hash` field before the diagnostic fires. So the attack surface is bounded by the JSON-structural validation.

**Severity:** Very Low (the audit-extension confirms no secret-material echo in any error path under the current code).

**Recommended mitigation:** Extend the F-1 unit test to cover not just `rpc_auth_secret` echo but also wallet-passphrase echo, peer-secret echo, and any other operator-configured secret material. The pattern: parameterize the test with a list of "marker strings" representing known secrets, send a battery of error-inducing inputs, assert no marker appears in any response. Chip task candidate alongside F-1.

**Effort:** ~30 LOC additional to the F-1 test. Estimated 0.5d combined with F-1.

### Finding F-4 (No paired regression test exercises the auth-then-validate composition).

The existing per-layer tests cover the cryptographic layer (`tools/test_rpc_hmac_auth.sh` — 5 assertions for Layer E) and the input-validation layer (`tools/test_s018_json_validation.sh` — 10 assertions for Layer B; `tools/test_anon_address_case.sh` — Layer C S-028; `tools/test_rpc_rate_limit.sh` — Layer D) in isolation. There is no paired test that exercises the full composition: send a request that is well-authenticated AND well-validated AND succeeds vs send a request that is well-authenticated BUT input-malformed AND fails at Layer B vs send a request that is unauthenticated AND would have been valid AND fails at Layer E.

**Severity:** Low (each per-layer test is sound; the composition is established by audit, but a paired test would be defense-in-depth).

**Recommended mitigation:** Add a paired regression test `tools/test_rpc_auth_validate_pipeline.sh` that:
1. Configure RPC with `rpc_auth_secret = "<32-byte hex>"`.
2. Send a well-formed `submit_tx` with correct HMAC and assert acceptance.
3. Send the same `submit_tx` with wrong HMAC and assert `auth_failed`.
4. Send a malformed `submit_tx` (missing `sig` field) with correct HMAC and assert `S-018: sig` diagnostic.
5. Send a stale-nonce `submit_tx` with correct HMAC and assert `stale nonce` diagnostic at Layer C.
6. Send a replay of a previously-accepted `submit_tx` with correct HMAC and assert apply-time drop (idempotent — no state change at the chain layer).

**Effort:** ~80 LOC bash + harness for nonce setup. Estimated 1d.

### Finding F-5 (Constant-time compare hardening — defense-in-depth).

`RpcAuthHmacSoundness.md` F-3 already registered the compiler-attribute hardening recommendation (volatile-qualified accumulator or `CRYPTO_memcmp`). The composition-level observation is that under `A_inside`'s repeated probing — even though the constant-time compare is sound (T-4 + L-2) — a future compiler regression could introduce a timing channel that neither the per-layer audit nor the per-layer test would catch. The pinning regression would be: a microbenchmark that asserts the verify-time variance across mismatched-at-byte-N inputs is `< 5%` (or some operational threshold) for N ∈ {0, 1, 2, ..., 63}.

**Severity:** Very Low (defense-in-depth against future compiler regressions).

**Recommended mitigation:** Either add the volatile-qualified accumulator hardening (per `RpcAuthHmacSoundness.md` F-3) and call it done, or add a microbenchmark regression that pins the constant-time property. The former is simpler (~3 LOC); the latter is more robust but more code.

**Effort:** 3 LOC (volatile hardening) or ~100 LOC bash + harness (microbenchmark). Estimated 0.25d for the simple path.

The five findings are advisory; none invalidates T-1..T-5. They are surfaced for completeness so an external auditor can confirm the scope of the composition argument.

---

## 7. Cross-references

### 7.1 Companion proofs (per-layer soundness)

- **`docs/proofs/RpcAuthHmacSoundness.md`** — the HMAC-PRF cryptographic layer (Layer E). T-1 (auth soundness), T-2 (replay analysis — known limitation composed in T-2 here), T-3 (constant-time compare audit — composed in T-4 here), T-4 (secret confidentiality at RPC surface — composed in T-5 here), T-5 (HMAC PRF q²/2^256 q-query bound). Findings F-1 (config-surface plaintext at-rest), F-2 (env-var leakage), F-3 (compiler-attribute hardening).
- **`docs/proofs/RpcInputValidationDefense.md`** — the five-layer input-validation defense (Layers A/B/C/D/E). T-1..T-5 composed here as the input-validation arm of T-1 above; the per-layer enumeration in §3 is the source for T-3's exhaustive bypass-surface table.
- **`docs/proofs/JsonValidationSoundness.md`** — S-018 closure (Layer B). T-1 (Clear-Diagnostic Soundness), T-2 (No Internal-Error Leakage — referenced in L-3 of T-5 here), T-3 (Defense-in-Depth at 5 layers), T-4 (No Privilege Escalation Surface), T-5 (Backward-Compat Optional Fields).
- **`docs/proofs/NonceMonotonicity.md`** — FA-Apply-3 (apply-layer nonce gate). T-N1 (stale-nonce rejection), T-N2 (future-nonce rejection), T-N3 (per-account independence), T-N4 (replay defense via monotonic advance), T-N5 (monotonic accumulation across blocks), T-N6 (genesis `next_nonce = 0` bootstrap). Cited as the replay-defense backstop in T-2 here.
- **`docs/proofs/EquivocationSlashingApply.md`** — FA-Apply-10 (apply-layer slashing). T-E3 (idempotent re-apply) cited as the replay-defense backstop for `submit_equivocation` in T-2 here.
- **`docs/proofs/S014RateLimiterSoundness.md`** — S-014 closure (Layer D). T-1 (Bounded Burst) composed into the threat-model matrix's HMAC online brute-force row.
- **`docs/proofs/S022WireFormatCaps.md`** — S-022 closure (Layer A). T-1 + T-2 cited as the framing-layer bound under §4.5 + the threat-model matrix's oversized payload row.
- **`docs/proofs/S028AnonAddressNormalization.md`** — S-028 closure (Layer C's address-normalization component). Cited under §4 as one of the per-method semantic gates.
- **`docs/proofs/S002-Mempool-Sig-Verify.md`** — S-002 closure (Layer C's signature-verification component for `submit_tx`). Cited under §4 as the Ed25519 verify gate that backstops A_inside's "submit tx from someone else's account" threat row in §5.

### 7.2 Implementation sites

- **`src/rpc/rpc.cpp:52-58`** — `canonical_for_hmac(method, params)` canonical-serialization helper.
- **`src/rpc/rpc.cpp:60-70`** — `hmac_sha256_hex(key, message)` HMAC primitive wrapping OpenSSL `HMAC(EVP_sha256(), ...)`.
- **`src/rpc/rpc.cpp:79-90`** — `RpcServer` constructor; secret hex-decoded into `auth_secret_`.
- **`src/rpc/rpc.cpp:92-104`** — Startup log emitting only `auth_secret_.size()`.
- **`src/rpc/rpc.cpp:112-129`** — `verify_auth` (the proof's primary cryptographic-layer object).
- **`src/rpc/rpc.cpp:142-195`** — `handle_session` (the canonical control flow at the heart of T-3).
- **`src/rpc/rpc.cpp:172`** — Layer D rate-limit consume call.
- **`src/rpc/rpc.cpp:176`** — Layer B `json::parse` call.
- **`src/rpc/rpc.cpp:179`** — Layer E `verify_auth` call (auth gate).
- **`src/rpc/rpc.cpp:184`** — Dispatch invocation (post-auth).
- **`src/rpc/rpc.cpp:188-191`** — Exception path; sets `response["error"] = e.what()`.
- **`src/rpc/rpc.cpp:197-272`** — `dispatch` table (T-3's exhaustive enumeration source).
- **`src/rpc/rpc.cpp:276-321`** — Client-side `rpc_call` with `DETERM_RPC_AUTH_SECRET` env var support.
- **`src/node/node.cpp:2804-2842`** — `rpc_send` (Layer C entry for `send`).
- **`src/node/node.cpp:2850-...`** — `rpc_stake` (Layer C entry for `stake`).
- **`src/node/node.cpp:2884-...`** — `rpc_unstake` (Layer C entry for `unstake`).
- **`src/node/node.cpp:3121-3205`** — `rpc_submit_tx` (Layer C entry for `submit_tx`; six semantic gates documented in `RpcInputValidationDefense.md` §3.4).
- **`src/node/node.cpp:3207-3236`** — `rpc_submit_equivocation` (Layer C entry for `submit_equivocation`).
- **`src/node/node.cpp:3338-...`** — `rpc_register` (Layer C entry for `register`).
- **`src/chain/chain.cpp:739`** — Apply-layer nonce gate (FA-Apply-3; T-2 backstop).
- **`include/determ/net/messages.hpp:101`** — `kMaxFrameBytes` framing-layer ceiling (S-022 backing).
- **`include/determ/net/rate_limiter.hpp`** — `net::RateLimiter` shared helper (S-014 backing).

### 7.3 SECURITY.md sections + spec docs

- **`docs/SECURITY.md` §S-001** — S-001 closure narrative (Option 1 localhost-only + Option 3 HMAC); threat-model matrix that this composition formalizes.
- **`docs/SECURITY.md` §S-014** — Rate-limiter closure; cited in the threat-model matrix's online brute-force row.
- **`docs/SECURITY.md` §S-018** — JSON validation closure; cited under §4.4 as the input-validation arm's structural layer.
- **`docs/SECURITY.md` §S-022** — Per-MsgType body caps; cited under §4.5 as the framing-layer arm.
- **`docs/SECURITY.md` §S-028** — Anon-address normalization; cited under §4 as a per-method semantic gate component.
- **`docs/PROTOCOL.md` §10.2** — Wire-level documentation of the `auth` field requirement.
- **`docs/CLI-REFERENCE.md` §17** — Operator-facing documentation of `rpc_auth_secret`.

### 7.4 Tests

- **`tools/test_rpc_hmac_auth.sh`** — 5-assertion regression (Layer E / `RpcAuthHmacSoundness.md`).
- **`tools/test_rpc_rate_limit.sh`** — Layer D RPC integration (4 assertions).
- **`tools/test_s018_json_validation.sh`** — Layer B (S-018) regression (10 assertions).
- **`tools/test_anon_address_case.sh`** — Layer C (S-028) regression (6 assertions post-G-2 closure).
- **`tools/test_rpc_localhost_only.sh`** — Layer E + localhost-bind default (3 assertions).
- **`tools/test_tx_replay_protection.sh`** — FA-Apply-3 backstop regression (apply-time stale-nonce drop).
- **`tools/test_chain_apply_block.sh`** — FA-Apply pipeline regression (full apply-layer composition).

A paired auth-then-validate pipeline test is registered as F-4 above as not-yet-implemented; the existing per-layer tests cover each layer in isolation but no single test exercises the joint composition. The composition is established by audit + the per-layer tests' soundness; F-4 surfaces the recommendation to add a paired test as defense-in-depth.

### 7.5 External references

- **RFC 2104** (Krawczyk, Bellare, Canetti, Feb 1997) — "HMAC: Keyed-Hashing for Message Authentication."
- **FIPS 198-1** (NIST, Jul 2008) — "The Keyed-Hash Message Authentication Code (HMAC)."
- **NIST FIPS 180-4** — Secure Hash Standard, SHA-256.
- **Bellare, Canetti, Krawczyk** (CRYPTO 1996) — "Keying Hash Functions for Message Authentication." Original HMAC paper.
- **Bellare** (CRYPTO 2006) — "New Proofs for NMAC and HMAC: Security Without Collision-Resistance." Tighter PRF reduction.
- **Bellare, Goldwasser, Micali** (J.ACM 1986) — "How to construct random functions." PRF-to-MAC reduction.
