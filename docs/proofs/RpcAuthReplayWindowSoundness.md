# RpcAuthReplayWindowSoundness — bound-timestamp + sliding-window anti-replay for HMAC RPC auth (S-001 T-2 follow-on)

**Status: specification + soundness proof.** The base HMAC-SHA-256 RPC-auth scheme is shipped (`src/rpc/rpc.cpp:112-129`; soundness in `RpcAuthHmacSoundness.md` T-1..T-5). Its one documented residual is **replay**: the `auth` field is a deterministic function of `(K, method, params)` only — no nonce, no timestamp, no sequence — so a captured legitimate triple `(method, params, auth)` replays verbatim against the same server forever (`RpcAuthHmacSoundness.md` T-2; `SECURITY.md` §S-001 "Replay of authenticated requests by MITM: NOT addressed in v2.16"). This document specifies the anti-replay extension that closes T-2 and proves it sound under the same assumption stack the base scheme already consumes. No source is modified by this document; it formalizes the wire-format extension, the server-side acceptance predicate, and the soundness argument so the implementation lands against a fixed specification rather than ad-hoc.

The novelty relative to every sibling RPC-auth proof is the **freshness dimension**. `RpcAuthHmacSoundness.md` proves unforgeability + constant-time + secret-confidentiality of the *stateless* gate and explicitly leaves replay open (T-2). `S001RpcAuthSoundness.md` composes the stateless gate with the input-validation pipeline and routes replay to the **apply-layer** nonce gate (`NonceMonotonicity.md` FA-Apply-3) — but that backstop covers ONLY the five tx-carrying state-mutating methods (`send`/`stake`/`unstake`/`register`/`submit_tx`) plus `submit_equivocation` via idempotent re-apply (`EquivocationSlashingApply.md` T-E3); it provides **no** freshness for read methods and **no** RPC-layer freshness for any method (a replayed `submit_tx` is dropped at apply, but the server still pays parse + HMAC + dispatch + mempool-admit work on every replay). `F2RPCAuthEnvComposition.md` pins the secret-loading boundary, not freshness. None of these documents specifies a request-envelope nonce/timestamp, a server-side acceptance window, or proves the replay surface closed at the **RPC layer**. This document closes that gap. It is the freshness companion to the unforgeability proof, exactly as `S016InboundReceiptTimeOrdered.md` is the time-ordering companion to the cross-shard-receipt admission proofs.

**Companion documents:** `RpcAuthHmacSoundness.md` (the stateless HMAC gate; T-1 unforgeability + T-2 replay-as-known-limitation that THIS document closes; T-3 constant-time + T-5 PRF bound reused unchanged); `S001RpcAuthSoundness.md` (the auth-then-validate composition; T-2 there routes tx-replay to the apply layer — this document adds the RPC-layer freshness arm that composes in front of it); `F2RPCAuthEnvComposition.md` (the secret-loading boundary; the bound timestamp/nonce binds into the same `canonical(...)` pre-image the env-loaded secret keys); `S014RateLimiterSoundness.md` (the per-IP token bucket that bounds the rate at which an attacker can probe the window and bounds the size of the seen-set per IP per window — composed in §6); `NonceMonotonicity.md` (FA-Apply-3 apply-layer nonce gate — the deeper backstop that this RPC-layer defense sits in front of); `S016InboundReceiptTimeOrdered.md` (sibling sliding-window-over-time soundness style mirrored here); `Preliminaries.md` §2.0 (canonical assumption labels A1/A2/A4 + the derived A6 HMAC-PRF label), §2.1 (A2 SHA-256 collision resistance), §3.1 (partial-synchrony + bounded-clock-drift network model the timestamp window relies on), §3.2 (the active-network adversary `A_msg`); `SECURITY.md` §S-001 (the closure-status narrative this proof would let advance from "replay NOT addressed" to "replay addressed via bound-timestamp window").

---

## 1. The residual: replay of an authenticated request

### 1.1 The shipped stateless gate

The shipped `verify_auth` (`src/rpc/rpc.cpp:112-129`) accepts a request `(method, params, auth)` iff

```
auth = hex(HMAC-SHA-256(K, canonical(method, params)))
```

where `canonical(method, params) := method ‖ "|" ‖ params.dump()` (`src/rpc/rpc.cpp:52-58`) and the compare is the constant-time XOR-OR loop at `:124-127`. The acceptance predicate references **no** per-request freshness material: not a nonce, not a timestamp, not a sequence number, not any server-side per-secret state. This is exactly `RpcAuthHmacSoundness.md`'s observation in T-2.

### 1.2 The replay attack (constructive)

Let `A_msg` be the active-network adversary of `Preliminaries.md` §3.2 — observes wire traffic, injects arbitrary bytes, cannot forge Ed25519 (A1) or break SHA-256 (A2/A3) or recover `K` from observed HMACs (A6 PRF security). `A_msg` does **not** need the secret to replay:

1. `A_msg` observes one legitimate authenticated request `T = (method, params, auth)` on the wire. This is possible whenever the operator opts out of S-001 Option 1 (localhost-only) — e.g. an external bind behind a non-TLS reverse proxy, or a co-tenant performing loopback `tcpdump` before localhost-only is enabled. (Under localhost-only with a single tenant the eavesdropping surface vanishes, which is why T-2 is scoped as a *residual* and not a Critical.)
2. `A_msg` re-sends the byte-identical triple `T` to the same server. Because `verify_auth` is a pure function of `(K, method, params)` and `K` is unchanged, the server recomputes `expected = auth` and accepts.
3. For a state-mutating method, the request reaches the Layer C handler. For `submit_tx` and the four other tx-carrying methods, the **apply-layer** nonce gate (`NonceMonotonicity.md` FA-Apply-3, gate at `src/chain/chain.cpp`) drops the replay because the tx's `nonce` was already consumed — so the chain state is safe (`S001RpcAuthSoundness.md` T-2). But:
   - The server still pays full parse + HMAC + dispatch + mempool-admission work on **every** replay (an amplification vector bounded only by S-014, not eliminated).
   - For **read** methods (`balance`, `nonce`, `status`, `validators`, `committee`, `stakes`, `headers`, `state_proof`, `dapp_*`, …) there is no apply-layer backstop; the replay re-executes the read every time. Idempotent reads leak no new information (`S001RpcAuthSoundness.md` threat-model matrix), but the replay is *accepted*, which is precisely the property an anti-replay layer is supposed to deny.
   - For any future state-mutating RPC method that is **not** a determ-transaction (i.e. does not carry a per-account `nonce`), there is no apply-layer freshness at all — replay would re-execute the privileged operation.

The residual is therefore real at the RPC layer even though the apply layer makes the *common* case (tx replay) state-safe. This document closes it at the RPC layer.

---

## 2. Notation, assumptions, adversary model

### 2.1 Notation

Carrying over `RpcAuthHmacSoundness.md` §1: `K ∈ {0,1}*` is the server's `auth_secret_`; `H(K,m) := hex(HMAC-SHA-256(K,m))`; the constant-time compare is `ct_eq(·,·)`.

The extension adds two request-envelope fields:

- `ts ∈ ℕ` — a client-supplied wall-clock timestamp in **milliseconds since the Unix epoch** (`uint64`), matching the millisecond convention already used by `V14` block timestamps (`Preliminaries.md` §5).
- `nonce ∈ {0,1}*` — a client-supplied per-request unique token, hex-encoded; RECOMMENDED to be `hex(RAND_bytes(16))` (128 bits) so collisions among honest clients are negligible (A4).

The **extended canonical pre-image** is

```
canonical_v2(method, params, ts, nonce) := method ‖ "|" ‖ params.dump() ‖ "|" ‖ dec(ts) ‖ "|" ‖ nonce
```

where `dec(ts)` is the decimal ASCII encoding of `ts`. A request is the quintuple `R = (method, params, ts, nonce, auth)` and is **fresh-and-authentic** iff all of:

```
(F1)  |now_ms − ts|  ≤  W_ms                                (timestamp within the window)
(F2)  (ts, nonce)    ∉  SEEN                                (not previously accepted in-window)
(F3)  auth           =  H(K, canonical_v2(method, params, ts, nonce))   (HMAC binds ts+nonce)
```

`W_ms` is the server-configured half-window (RECOMMENDED `30_000` ms = ±30 s, matching the post-S-003 validator timestamp tolerance noted in `RpcAuthHmacSoundness.md` T-2's recommendation and `Preliminaries.md` §5). `SEEN` is the server-side replay cache: the set of `(ts, nonce)` pairs accepted within the trailing `2·W_ms` window, pruned of entries older than `now_ms − 2·W_ms` (the maximal age at which (F1) could still admit them, plus the window's own width on the late side).

`now_ms` is the server's `steady`-anchored wall-clock read at verify time (the server reads `system_clock` for the comparison against the client epoch-ms `ts`, exactly as block-timestamp validation does).

### 2.2 Assumptions

The extension consumes **no new cryptographic assumption** beyond the base scheme:

- **(A6) HMAC-SHA-256 PRF security** (`Preliminaries.md` §2.0 derived label; `RpcAuthHmacSoundness.md` §2.1). The forgery bound is unchanged: extending the pre-image from `canonical` to `canonical_v2` only lengthens the HMAC input, which does not weaken PRF security (HMAC is a PRF on inputs of any length). Single-attempt forgery of a fresh `auth*` over a chosen `(method*, params*, ts*, nonce*)` remains `≤ 2^-256 + q²/2^256` per `RpcAuthHmacSoundness.md` T-1 + L-5.
- **(A2) SHA-256 collision resistance** (`Preliminaries.md` §2.1). Used exactly as in the base scheme (HMAC reduction).
- **(A4) CSPRNG uniform sampling** (`Preliminaries.md` §2.3, §2.0). Used for the honest client's `nonce = hex(RAND_bytes(16))`; bounds honest nonce-collision probability (L-4).
- **(H-CLOCK) Bounded clock drift** (`Preliminaries.md` §3.1). Honest clients' and the server's wall clocks are within `δ_clock` of true time, with `δ_clock ≪ W_ms`. This is the SAME loose-synchrony assumption that block-timestamp validation (`V14`) already relies on; the extension introduces no stronger clock assumption. Adversarial clocks are NOT trusted — `A_msg` may set `ts*` to any value; (F1) bounds the *acceptance* of any `ts*`, it does not trust the client to be honest about time.

### 2.3 Adversary model

The freshness extension defends the **`A_msg` replay** family (the (c) "Replay attacker" of `RpcAuthHmacSoundness.md` §6.1):

- **`A_msg` (active-network, no secret).** Observes legitimate authenticated requests on the wire; injects arbitrary bytes; cannot forge a fresh HMAC over a pre-image it has not observed (A6). Goal: get the server to accept a request it did not originate. Pre-extension: succeeds by verbatim replay (T-2). Post-extension: defended by (F1)+(F2)+(F3) — Theorem T-1.
- **`A_msg`-window-shift.** Same adversary, attempting to extend the replay validity by re-sending a captured request at the edge of its window or by truncation/splice of the `ts`/`nonce` bytes. Defended by T-3 (the HMAC binds `ts` and `nonce`, so any mutation of either breaks (F3)).
- **`A_inside` (has the secret).** Out of scope for freshness in the same sense as `RpcAuthHmacSoundness.md`: an attacker with `K` can mint a *fresh* `(ts, nonce, auth)` at will, so freshness does not constrain them — they are bounded by the apply-layer (`NonceMonotonicity.md` FA-Apply-3) and the input-validation layer (`S001RpcAuthSoundness.md` T-1 `A_inside` arm), unchanged by this document. The freshness layer's job is to deny **replay by a no-secret network adversary**, which is precisely the T-2 residual.
- **`A_flood` (replay-DoS).** `A_msg` floods the server with the same captured request to exhaust the `SEEN` cache or the verify path. Bounded by T-4 (the cache is window-bounded) composed with `S014RateLimiterSoundness.md` T-1 (per-IP rate cap) — §6.

---

## 3. Specification

### 3.1 Wire-format extension (backward-compatible)

The request envelope gains two OPTIONAL fields, mirroring the optional-field discipline used for backward-compatible block fields (`WireFormatBackwardCompat.md`):

```jsonc
{ "method": "...", "params": { ... },
  "ts":    1733400000000,        // optional uint64 epoch-ms; absent ⇒ legacy stateless mode
  "nonce": "a1b2…",              // optional hex; absent ⇒ legacy stateless mode
  "auth":  "…64-hex…" }
```

Server-side acceptance is governed by a per-server policy flag `rpc_auth_require_fresh ∈ {false, true}`:

- `rpc_auth_require_fresh = false` (DEFAULT, backward-compatible): if `ts` and `nonce` are BOTH present, the server verifies against `canonical_v2` and additionally enforces (F1)+(F2); if either is absent, the server falls back to the legacy `canonical` path and enforces only (F3-legacy) — i.e. exactly the shipped stateless behavior. This default lets an upgraded client gain replay protection against an unupgraded server's *successor* without breaking existing clients. (Strictly: under this default an unupgraded server ignores `ts`/`nonce` because they are not in `canonical`; the protection materializes only once the server enforces. The default is therefore a migration affordance, not the secure mode.)
- `rpc_auth_require_fresh = true` (the SECURE mode an external-bind operator MUST set): the server REJECTS any request lacking a well-formed `ts` and `nonce` with `auth_required: stale (missing ts/nonce)`, and enforces (F1)+(F2)+(F3) on every request. This is the mode that closes T-2.

The flag's default-off + must-set-on-external-bind shape matches the existing S-001 escape-hatch discipline (the secret itself is default-empty and must be set for multi-tenant/external bind per `RpcAuthHmacSoundness.md` §2.3 + `S001RpcAuthSoundness.md` T-3's single-tenant escape-hatch note).

### 3.2 Server acceptance predicate (the verify_fresh extension)

The extended verify is a refinement of `verify_auth`: the constant-time HMAC compare is unchanged; (F1) and (F2) are added BEFORE the accept return. In pseudocode mirroring `src/rpc/rpc.cpp:112-129`:

```
verify_fresh(req):
    if auth_secret_.empty(): return ""                      # auth disabled, pass (unchanged)
    if !req.has_string("auth"): return "auth_required: missing 'auth' field"
    has_fresh := req.has_uint("ts") && req.has_string("nonce")
    if require_fresh_ && !has_fresh:
        return "auth_required: stale (missing ts/nonce)"     # SECURE mode rejects legacy envelopes
    if has_fresh:
        ts := req["ts"]; nonce := req["nonce"]
        if abs_diff(now_ms(), ts) > W_ms:                    # (F1)
            return "auth_failed: timestamp outside window"
        expected := H(K, canonical_v2(method, params, ts, nonce))   # (F3)
        if !ct_eq(expected, req["auth"]): return "auth_failed"
        if !seen_.insert_if_absent(ts, nonce):               # (F2) atomic test-and-set
            return "auth_failed: replay"
        return ""                                            # fresh + authentic
    else:                                                    # legacy stateless path (unchanged)
        expected := H(K, canonical(method, params))
        return ct_eq(expected, req["auth"]) ? "" : "auth_failed"
```

The ordering — (F1) before (F3) before (F2) — is deliberate and proved necessary in L-6: the cheap window check (F1) gates the expensive HMAC, the HMAC (F3) gates the cache insert (F2) so that an unauthenticated attacker cannot pollute `SEEN`, and the cache insert is the LAST step so a failed-HMAC request never consumes a `(ts,nonce)` slot.

### 3.3 The SEEN cache (bounded replay window)

`SEEN` is a set of `(ts, nonce)` accepted within the trailing window. It is pruned on every insert (amortized, exactly the lazy-prune discipline of `S014RateLimiterSoundness.md`'s eviction sweep): entries with `ts < now_ms − 2·W_ms` are erased, because (F1) can never again admit a request with such a `ts`. The factor `2·W_ms` (rather than `W_ms`) covers both the early side (`ts` up to `W_ms` in the future) and the late side (`ts` up to `W_ms` in the past) of the acceptance window — a `(ts, nonce)` must be retained until the latest `now_ms` at which a request bearing it could still pass (F1), which is `ts + W_ms`, i.e. age `2·W_ms` measured from the earliest admitting `now_ms = ts − W_ms`.

`SEEN` is keyed by `(ts, nonce)` rather than `nonce` alone so that two honest clients reusing a nonce across different windows do not false-collide, and so that pruning is a simple age test on `ts`.

---

## 4. Lemmas

### Lemma L-1 (HMAC binds the freshness fields)

`canonical_v2(method, params, ts, nonce) = method ‖ "|" ‖ params.dump() ‖ "|" ‖ dec(ts) ‖ "|" ‖ nonce` is an injective-on-components encoding: the `"|"` separators are not producible by `method` (an RPC method name is `[a-z_]+`), by `params.dump()` (a JSON value; a top-level `"|"` only appears inside quoted strings, which are balanced and therefore cannot terminate the field), by `dec(ts)` (decimal digits only), or by `nonce` (hex only). Hence distinct tuples `(method, params, ts, nonce) ≠ (method', params', ts', nonce')` yield distinct pre-images, and by A2 (collision resistance of the SHA-256 backing HMAC) distinct pre-images yield distinct HMAC outputs except with probability `≤ 2^-128`. Therefore the `auth` field cryptographically binds every one of the four components: an `A_msg` who alters `ts` or `nonce` (or `method`/`params`) on a captured request must produce a fresh `auth` over the altered pre-image, which by A6 it cannot do without the secret (`RpcAuthHmacSoundness.md` L-1). □

### Lemma L-2 (A captured request is fresh-and-authentic for at most one acceptance)

Fix a legitimate request `R = (method, params, ts, nonce, auth)` produced by an honest client at true time `t` (so `ts ≈ t` within `δ_clock` by H-CLOCK) and captured by `A_msg`. Consider any later replay attempt of `R` (byte-identical) at server-time `now_ms`. Two cases:

1. **`now_ms − ts > W_ms`** (the window has closed): (F1) fails; the server returns `auth_failed: timestamp outside window` without touching `SEEN`. Rejected.
2. **`now_ms − ts ≤ W_ms`** (still inside the window): the FIRST acceptance of `R` (whether the honest original or `A_msg`'s first in-window replay) executes `seen_.insert_if_absent(ts, nonce)`, which returns true and records `(ts, nonce)`. Every SUBSEQUENT in-window attempt finds `(ts, nonce) ∈ SEEN`, so (F2) fails and the server returns `auth_failed: replay`. Rejected.

Hence across the entire lifetime of `R`, the server accepts it **at most once**: either the honest original is accepted and all replays rejected by (F2), or — if `A_msg` races ahead of the honest client — `A_msg`'s first copy is accepted (indistinguishable from the original, since it IS the original bytes) and both the honest client's send and all further `A_msg` replays are rejected by (F2). In the racing case the honest client observes `auth_failed: replay` and reissues with a fresh `(ts, nonce)`; no privileged operation executes twice. □

### Lemma L-3 (SEEN is bounded; pruning is sound)

A `(ts, nonce)` entry can satisfy (F1) only while `now_ms ∈ [ts − W_ms, ts + W_ms]`. Once `now_ms > ts + W_ms`, (F1) rejects any request bearing that `ts` regardless of `SEEN` membership, so retaining the entry is unnecessary. The prune rule erases entries with `ts < now_ms − 2·W_ms`; since the latest admitting `now_ms` is `ts + W_ms`, an entry is retained for at most `(ts + W_ms) − (ts − W_ms) = 2·W_ms` of server-time, after which it is pruned. Therefore at any instant `SEEN` holds only entries whose `ts ∈ (now_ms − 2·W_ms, now_ms + W_ms]`, a window of width `3·W_ms`. The count of such entries is bounded by the number of *accepted* (HMAC-valid, hence honest-or-secret-holding) requests in that width — which, composed with the per-IP rate cap of `S014RateLimiterSoundness.md` T-1, is `≤ Σ_IP ⌊C + r·(3·W_ms/1000)⌋`. Pruning is sound (never erases an entry that could still gate a replay) and `SEEN` is bounded (no unbounded growth). □

### Lemma L-4 (Honest nonce-collision probability is negligible)

An honest client draws `nonce = hex(RAND_bytes(16))` (128 bits, A4). Within any `3·W_ms` retention window, let `Q_h` be the number of honest accepted requests sharing the same `ts` granularity. By the birthday bound, the probability that two honest requests collide on `(ts, nonce)` is `≤ Q_h² / 2^128`. For `W_ms = 30_000` and any operational honest request rate (say `Q_h ≤ 10^6` accepted requests per 90 s window), this is `≤ 2^-88`, negligible. Honest clients therefore are not spuriously rejected by (F2) except with negligible probability; a client that *does* lose the birthday lottery observes `auth_failed: replay` and reissues with a fresh draw. (A client MAY instead use a monotone counter for `nonce` to make collisions impossible by construction; the spec permits any per-request-unique token.) □

### Lemma L-5 (Window admits honest clock skew; rejects stale replay)

By H-CLOCK an honest client's `ts` is within `δ_clock` of true time and the server's `now_ms` is within `δ_clock` of true time, so `|now_ms − ts| ≤ 2·δ_clock` at honest send time. With `W_ms ≥ 2·δ_clock` (satisfied by `W_ms = 30_000` for any `δ_clock ≤ 15 s`, far above realistic NTP-synced or even unsynced-but-sane drift), (F1) admits every honest request. Conversely, a replay delayed past `now_ms − ts > W_ms` is rejected by (F1) even if `A_msg` never re-sends within the window. So the window simultaneously (a) admits honest skew up to `W_ms` and (b) caps the replay-validity lifetime of any captured request at `W_ms` on the late side — after which the apply-layer backstop is not even needed because the RPC layer rejects first. □

### Lemma L-6 (Predicate ordering is necessary)

The order (F1) → (F3) → (F2) is forced:

- **(F1) before (F3).** (F1) is an integer comparison; (F3) is an HMAC compute over `canonical_v2`. Placing (F1) first means an attacker spamming requests with an out-of-window `ts` (cheap to forge in the `ts` field, which is not yet HMAC-checked) is rejected at integer-compare cost, not HMAC cost — preserving the `S014RateLimiterSoundness.md` T-2 no-amplification property on the freshness path. An out-of-window `ts` need not pass (F3) to be rejected, so doing (F1) first is safe and cheaper.
- **(F3) before (F2).** (F2) mutates server state (`seen_.insert_if_absent`). If (F2) ran before (F3), an unauthenticated `A_msg` could insert arbitrary `(ts, nonce)` pairs into `SEEN` by sending requests with a garbage `auth`, polluting the cache (a cache-pollution DoS, and worse, a *denial-of-acceptance* attack: by pre-inserting the `(ts, nonce)` an honest client is about to use — feasible only if the attacker can guess the honest nonce, which A4 makes negligible, but the ordering removes even that residual). Gating (F2) behind a passing (F3) means only HMAC-valid requests ever touch `SEEN`; an attacker without `K` cannot insert anything (L-1 + A6).
- **(F2) last.** The cache insert is the final accept step so that a request failing any earlier check consumes no `(ts, nonce)` slot. This makes acceptance atomic: the request is recorded iff it is accepted.

The ordering is the same defense-in-depth-with-cheap-gate-first discipline as the shipped `rate-limit → parse → auth → dispatch` order (`src/rpc/rpc.cpp:166-187`; `S014RateLimiterSoundness.md` §3). □

---

## 5. Theorems and proofs

### Theorem T-1 (Replay soundness — the T-2 residual is closed at the RPC layer)

**Statement.** Under SECURE mode (`require_fresh_ = true`) and assumptions A6 + A2 + H-CLOCK, for every authenticated request `R = (method, params, ts, nonce, auth)`, the server `verify_fresh` accepts `R` **at most once** over the lifetime of the chain, and accepts it at all only if `R`'s `ts` is within `W_ms` of the server's clock at acceptance time. Consequently no `A_msg` (active-network adversary without `K`) can cause the server to accept any request it did not itself originate, beyond the single accepted instance of each honest request.

**Proof.** An `A_msg` request is accepted only if it passes (F1)+(F2)+(F3). By L-1 + A6, `A_msg` cannot produce a *new* `(method, params, ts, nonce, auth)` that passes (F3) for any pre-image it has not observed authenticated — its only options are (i) replay an observed `R` verbatim, or (ii) mutate an observed `R` and re-HMAC, which (ii) requires `K` (excluded). For option (i), L-2 establishes that verbatim replay of any `R` is accepted at most once: the first in-window acceptance records `(ts, nonce)` in `SEEN` (F2), and every later in-window copy is rejected by (F2) while every out-of-window copy is rejected by (F1). The "at most once" therefore holds per distinct `R`, and the only accepted instance is byte-identical to an honest-originated (or secret-holder-originated) request — i.e. `A_msg` gains nothing it could not have obtained by simply forwarding the honest request once, which is not an attack (the honest operation executes exactly once regardless of who delivered the bytes). The window bound on acceptance time is L-5. ∎

### Theorem T-2 (No weakening of the base unforgeability bound)

**Statement.** The extension preserves `RpcAuthHmacSoundness.md` T-1: the probability that `A_msg` forges a fresh accepted request over a never-observed `(method*, params*, ts*, nonce*)` is `≤ 2^-256 + q²/2^256` per attempt, unchanged.

**Proof.** The only cryptographic change is replacing the HMAC pre-image `canonical` with the longer `canonical_v2`. HMAC-SHA-256 is a PRF on arbitrary-length inputs (A6; `RpcAuthHmacSoundness.md` §2.1 + L-5), so the forgery bound depends on the number of queries `q`, not on the pre-image length. The added (F1)+(F2) checks are *additional* accept conditions ANDed in front of the HMAC check — they can only *reduce* the set of accepted requests, never enlarge it. Hence the forgery probability is bounded above by the base T-1 bound. The constant-time compare (`RpcAuthHmacSoundness.md` T-3) is reused verbatim on the `auth` field; (F1) is a data-independent integer comparison and (F2) is a set membership test whose timing depends on cache occupancy (public, attacker-influenced via rate-limited inserts) and not on `K`, so no new secret-dependent timing channel is introduced. ∎

### Theorem T-3 (Freshness fields are tamper-evident)

**Statement.** Any `A_msg` mutation of `ts` or `nonce` (or `method`/`params`) on a captured request is detected: the mutated request fails (F3) except with probability `≤ 2^-256 + q²/2^256`.

**Proof.** Direct from L-1: `auth` binds all four components via the injective `canonical_v2` encoding under A2 + A6. A mutated tuple is a never-observed pre-image (it differs from the captured one), so producing a passing `auth` for it is a forgery, bounded by T-2. In particular, `A_msg` cannot (a) shift a captured request's `ts` forward to extend its window, (b) swap in a fresh `nonce` to evade (F2), or (c) splice a valid `auth` from one request onto a different `(ts, nonce)` — each alters the pre-image and breaks (F3). ∎

### Theorem T-4 (Replay-DoS is bounded)

**Statement.** Composed with `S014RateLimiterSoundness.md` T-1, the freshness layer adds bounded server work and bounded server state under an `A_flood` replay flood.

**Proof.** Per-request added work on the rejection path: (F1) is `O(1)` (integer compare), and a request failing (F1) never reaches (F3)/(F2) (L-6), so a flood of out-of-window replays costs `O(1)` each on top of the S-014 rate-limit gate that already fronts the handler (`src/rpc/rpc.cpp:172`, BEFORE parse) — the flood is rate-capped at `⌊C + r·Δ⌋` per IP per `S014RateLimiterSoundness.md` T-1, and each admitted attempt costs `O(1)`. For in-window replays, the first is accepted (one `SEEN` insert) and the rest are rejected by (F2) at `O(log|SEEN|)` membership-test cost; `|SEEN|` is bounded by L-3. Server state is bounded by L-3 (`SEEN` holds only `(ts,nonce)` with `ts` in a `3·W_ms`-wide window, pruned on every insert), so the freshness cache cannot grow without bound — the same window-bounded-state property as the rate limiter's evicted bucket map. The two layers compose orthogonally: S-014 bounds the *rate* of attempts per IP; the freshness layer bounds the *acceptance* of each captured request to once and bounds its own cache by the window. ∎

### Theorem T-5 (Composition: RPC-layer freshness in front of apply-layer nonce gate)

**Statement.** The freshness layer composes in front of `NonceMonotonicity.md` FA-Apply-3 to give end-to-end replay safety for ALL methods, not just tx-carrying ones.

**Proof.** `S001RpcAuthSoundness.md` T-2 establishes that tx-carrying state-mutating methods are replay-safe at the *apply* layer (the consumed nonce is rejected). The freshness layer adds replay rejection at the *RPC* layer for **every** method — including reads and any future non-tx state-mutating method — by T-1. The composition is: a replayed `submit_tx` is now rejected at the RPC layer by (F2) (before parse-dispatch work, an efficiency gain) and would additionally be dropped at apply (defense-in-depth, unchanged); a replayed `balance` read is now rejected at the RPC layer (previously accepted-but-benign); a hypothetical future replayed non-tx mutation is rejected at the RPC layer (previously the only backstop, the apply nonce gate, did not apply to it). The two layers are independent (RPC-layer `(ts,nonce)` cache vs apply-layer per-account `next_nonce`) and their conjunction is strictly stronger than either alone. The freshness layer does not replace FA-Apply-3 — apply-layer nonce monotonicity remains the authoritative double-spend defense for the consensus state; the RPC freshness layer is the request-transport-level anti-replay that `RpcAuthHmacSoundness.md` T-2 flagged as missing. ∎

---

## 6. Composition with the shipped network-security layers

| Layer | Property it owns | This document's relation |
|---|---|---|
| HMAC gate (`RpcAuthHmacSoundness.md` T-1/T-3/T-5) | Unforgeability + constant-time + secret-confidentiality of the stateless `auth` | Reused unchanged; `canonical_v2` only lengthens the pre-image (T-2 here). |
| Auth-then-validate composition (`S001RpcAuthSoundness.md`) | Joint auth + input-validation pipeline; tx-replay routed to apply layer | This doc adds the RPC-layer freshness arm that closes the read-method + non-tx gaps the apply-layer backstop misses (T-5). |
| Per-IP rate limit (`S014RateLimiterSoundness.md` T-1/T-2) | Bounded per-IP request rate; no DoS amplification | Bounds the rate of replay attempts and the `SEEN` insert rate; composes for the replay-DoS bound (T-4). |
| Apply-layer nonce gate (`NonceMonotonicity.md` FA-Apply-3) | Per-account double-spend defense at consensus apply | The deeper backstop the RPC freshness layer sits in front of; remains authoritative for chain-state double-spend (T-5). |
| TCP keepalive reap (`S026TcpKeepalive.md`) | Stale-connection reaping | Orthogonal — operates on the connection-liveness dimension, not the request-freshness dimension; no interaction. |
| Per-MsgType body cap (`S022WireFormatCaps.md`) | Framing-layer size ceiling | The two added fields (`ts` uint + 32-hex `nonce`) add `< 64` bytes to a request, far under any cap; no interaction. |

The freshness layer is therefore a **new orthogonal dimension** (request freshness over time) added to the existing rate (S-014) and liveness (S-026) dimensions, sitting in front of the apply-layer correctness backstop (FA-Apply-3) and reusing the unforgeability core (S-001) without weakening it.

---

## 7. Findings

### Finding F-1 (Migration default is a UX affordance, not a secure mode).

The `require_fresh_ = false` default (§3.1) does not protect against replay — an unupgraded-policy server ignores `ts`/`nonce` because the legacy `canonical` path does not bind them. The protection materializes only when the operator sets `require_fresh_ = true`. This mirrors the S-001 secret-default-empty escape hatch and is safe *only* under localhost-only single-tenant deployment (where the eavesdropping surface vanishes per `RpcAuthHmacSoundness.md` §2.3). **Severity:** Low (operator-policy, documented). **Mitigation:** the startup banner SHOULD emit `[WARNING: external bind with auth but require_fresh=false — replay not enforced]` when `!localhost_only && !auth_secret_.empty() && !require_fresh_`, paralleling the existing external-bind-without-auth warning at `src/rpc/rpc.cpp:99-103`.

### Finding F-2 (Server clock is the freshness root of trust).

(F1) trusts the server's `now_ms`. A server with a badly-wrong clock (drift `≫ W_ms`) would reject all honest requests (clock ahead) or admit replays for an extended window (clock behind). **Severity:** Low (the same clock assumption block-timestamp validation already makes — `Preliminaries.md` §3.1 / V14). **Mitigation:** operators run NTP (already a deployment recommendation for block-timestamp sanity); no protocol change needed. A defense-in-depth option is to widen the prune retention if the operator anticipates clock corrections, at the cost of a larger `SEEN`.

### Finding F-3 (No regression test exercises the freshness predicate).

This is a specification; the implementation does not yet exist, so there is no `tools/test_rpc_auth_replay_window.sh`. **Severity:** N/A (spec). **Recommended test on implementation:** a regression that (1) sends a fresh `(ts, nonce, auth)` and asserts acceptance, (2) replays it verbatim and asserts `auth_failed: replay` (F2), (3) sends a request with `ts` shifted by `2·W_ms` and asserts `auth_failed: timestamp outside window` (F1), (4) mutates `nonce` keeping the captured `auth` and asserts `auth_failed` (F3/T-3), (5) under `require_fresh_=true` sends a legacy envelope (no `ts`/`nonce`) and asserts `auth_required: stale`. Pattern follows `tools/test_rpc_hmac_auth.sh`. Estimated ~80 LOC + ~1d. Chip-task candidate on implementation.

### Finding F-4 (SEEN is per-process, not shared across a horizontally-scaled RPC tier).

If an operator runs multiple RPC front-ends behind a load balancer, each holds an independent `SEEN`, so a replay routed to a *different* front-end than the original would not find the `(ts,nonce)` in that front-end's cache and could be accepted once per front-end. **Severity:** Low (the per-front-end "at most once" still bounds total acceptances at `#front-ends`, and the apply-layer nonce gate still de-dupes tx-carrying methods globally per T-5). **Mitigation:** for a horizontally-scaled tier requiring strict global once-only at the RPC layer, back `SEEN` with a shared store (e.g. a small Redis with TTL `= 2·W_ms`); out of scope for a single-node deployment, which is the common case. Documented so an operator scaling out is not surprised.

The four findings are advisory; none invalidates T-1..T-5. They scope the specification for the implementation pass that would advance `SECURITY.md` §S-001 from "replay NOT addressed in v2.16" to "replay addressed via bound-timestamp + nonce window."

---

## 8. Status

**Specification + proof only — no source modified by this document.** The base HMAC scheme it extends is shipped (`src/rpc/rpc.cpp:112-129`; `RpcAuthHmacSoundness.md`). The extension specified here (the `ts`/`nonce` envelope fields, the `canonical_v2` pre-image, the `verify_fresh` predicate with the `SEEN` cache, and the `rpc_auth_require_fresh` policy flag) is the implementation of `RpcAuthHmacSoundness.md` T-2's recommended follow-on and `SECURITY.md` §S-001's "Replay … NOT addressed in v2.16" line. The proof establishes that the extension closes the residual at the RPC layer (T-1), without weakening the base unforgeability bound (T-2), with tamper-evident freshness fields (T-3), under bounded replay-DoS (T-4), composing in front of the apply-layer nonce gate to cover all methods including reads (T-5).

Estimated implementation effort (per `RpcAuthHmacSoundness.md` T-2's note): ~10 LOC in `verify_auth` for (F1)+(F3-v2), ~30 LOC for the window-bounded `SEEN` cache (mirroring the `S014RateLimiterSoundness.md` eviction sweep), ~5 LOC for the config flag + banner warning, ~80 LOC for the regression test (F-3). The cryptographic argument requires no new primitive — only the longer pre-image — so the security review reduces to confirming the predicate ordering (L-6) and the cache-bound (L-3) at implementation time.

---

## 9. References

### Specifications + standards

- **RFC 2104** (Krawczyk, Bellare, Canetti, Feb 1997) — "HMAC: Keyed-Hashing for Message Authentication." The pre-image-length-independence of HMAC PRF security (T-2) is a consequence of the construction defined here.
- **FIPS 198-1** (NIST, Jul 2008) — "The Keyed-Hash Message Authentication Code (HMAC)."
- **NIST FIPS 180-4** — Secure Hash Standard, SHA-256 (A2).
- **RFC 8032** (Ed25519) — referenced only for the A1 backstop the apply-layer composition (T-5) inherits, not used directly by the freshness layer.

### Anti-replay / freshness literature

- **Needham, Schroeder** (CACM 1978) — "Using Encryption for Authentication in Large Networks of Computers." The nonce-based freshness pattern (F2) descends from this.
- **Denning, Sacco** (CACM 1981) — "Timestamps in Key Distribution Protocols." The timestamp-window pattern (F1) and the bounded-clock-drift requirement (H-CLOCK) descend from this; the ±window acceptance is the Denning-Sacco freshness window.
- **Lamport** (CACM 1978) — "Time, Clocks, and the Ordering of Events in a Distributed System." Underlies the loose-synchrony clock model (H-CLOCK / `Preliminaries.md` §3.1).
- **Dwork, Lynch, Stockmeyer** (J.ACM 1988) — "Consensus in the Presence of Partial Synchrony." The partial-synchrony bound `Δ` (`Preliminaries.md` §3.1) under which the window is well-defined.

### Determ-internal references

- `src/rpc/rpc.cpp:52-58` — `canonical_for_hmac` (the `canonical` this document extends to `canonical_v2`).
- `src/rpc/rpc.cpp:112-129` — `verify_auth` (the predicate `verify_fresh` refines).
- `src/rpc/rpc.cpp:166-187` — `handle_session` ordering (the rate-limit → parse → auth discipline L-6 mirrors).
- `src/rpc/rpc.cpp:276-321` — client `rpc_call` (the site that would add `ts`/`nonce` to the request envelope + HMAC over `canonical_v2`).
- `include/determ/net/rate_limiter.hpp` — the eviction-sweep pattern the `SEEN` prune (L-3) mirrors.
- `docs/proofs/RpcAuthHmacSoundness.md` — T-1/T-3/T-5 reused; T-2 (the residual) closed here.
- `docs/proofs/S001RpcAuthSoundness.md` — T-2 apply-layer routing extended by T-5 here.
- `docs/proofs/F2RPCAuthEnvComposition.md` — the secret-loading boundary the freshness fields bind under.
- `docs/proofs/S014RateLimiterSoundness.md` — T-1/T-2 composed for the replay-DoS bound (T-4).
- `docs/proofs/NonceMonotonicity.md` — FA-Apply-3, the apply-layer backstop (T-5).
- `docs/proofs/S016InboundReceiptTimeOrdered.md` — sibling sliding-window-over-time soundness style.
- `docs/proofs/Preliminaries.md` §2.0 (A2/A4/A6 labels), §2.1 (A2), §2.3 (A4), §3.1 (partial-synchrony + clock drift), §3.2 (`A_msg`).
- `docs/SECURITY.md` §S-001 — the closure-status narrative this proof would advance past the replay residual.
