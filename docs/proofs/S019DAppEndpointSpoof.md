# S019DAppEndpointSpoof — owner-authenticated DApp registration + service_pubkey rotation safety

This document formalizes the S-019 defense posture against **DApp endpoint spoofing** on the Determ v2.18+ DApp substrate. The attack class concerns an adversary attempting to publish a `DAPP_REGISTER` transaction that establishes a `domain → service_pubkey` binding the adversary does not legitimately own — by claiming someone else's domain, registering a typo-squatted look-alike, or attempting to mutate an existing DApp's `service_pubkey` without the owner's keypair.

The proof reduces the defense to two structural facts already proved elsewhere: (1) **owner-binding by construction** — the apply path keys every `dapp_registry_` access on `tx.from`, so a non-owner literally cannot reach another owner's entry; this is FA-Apply-5 (`DAppRegistryLifecycle.md`) T-D3 + T-D5 + T-D7; and (2) **sender-field unforgeability** — the `tx.from` field is bound to an Ed25519 keypair via `registrants_[tx.from].ed_pub` and the transaction-level signature gate at the validator (`src/node/validator.cpp`) + mempool (S-002) + chain-apply (FA-Apply I-2) reduces sender impersonation to forging Ed25519, i.e., to breaking FA1 (Ed25519 EUF-CMA, `Preliminaries.md` §2.2). The composition is that the registry binding `(domain → service_pubkey)` cannot be established or mutated without holding the registrant's Ed25519 secret key. The remaining attack surface — typosquatting `microsft.v` vs. `microsoft.v` — is an operational concern outside the cryptographic boundary; the chain provides no global namespace authority, only per-domain owner-binding. The defense reduces to operator-side discipline (wallet / UI display of the registry binding for human verification).

> **Note on S-019 numbering.** `docs/SECURITY.md` §S-019 is the closed entry for "Phase-2 timer R-arrival spoofing" (moot under M-F's delay-hash removal — see SECURITY.md §M-F). This proof reuses the S-019 number for the analytic treatment of DApp endpoint spoofing per the threat-class umbrella; the two attack classes are disjoint (consensus-layer Phase-2 timer vs. application-layer DApp registry) and the original SECURITY.md entry is unchanged. Both share the "spoof" label but the present document is the formalized defense story for the application-layer DApp endpoint vector.

**Companion documents:** `DAppRegistryLifecycle.md` (FA-Apply-5) for T-D1..T-D8 — the apply-side state-machine theorems on `dapp_registry_` that this proof rests on, especially T-D3 (cross-sender update unreachable), T-D5 (deactivation by non-owner unreachable), and T-D7 (per-domain independence); `S001RpcAuthSoundness.md` for the cross-cutting "auth-then-validate" composition pattern that the present document mirrors (HMAC-auth ↔ Ed25519-tx-sig as the gating cryptographic primitive); `S002-Mempool-Sig-Verify.md` for the mempool-layer Ed25519 verification that ensures `tx.from` cannot be forged at gossip time; `Preliminaries.md` §2.2 (FA1 — Ed25519 EUF-CMA assumption); `docs/PROTOCOL.md` §14.5 (DAPP_REGISTER wire format); `docs/V2-DAPP-DESIGN.md` §3.1 + §4 (conceptual model + DAppEntry struct); `docs/SECURITY.md` §S-019 (original Phase-2 timer entry — disjoint from this analytic treatment).

---

## 1. Adversary model

The adversary `A_spoof` is an honest-but-malicious Determ identity holder: they hold the secret key `sk_{A}` for one or more registered Determ domains `d_A, d_A', ...`, and may possess unlimited Ed25519 keypairs they generated themselves (so they can freely run REGISTER to create new `d_A^{(i)}` identities at the standard NEF cost). They cannot break Ed25519 EUF-CMA (FA1); they cannot recover Ed25519 secret keys from public keys, and they cannot forge signatures that verify under a public key whose secret they do not hold.

The chain provides per-domain owner-binding via `registrants_` (an `std::map<std::string, RegistrantEntry>` declared at `include/determ/chain/chain.hpp`, where each entry binds a Determ domain to its registrant's `ed_pub`). DApp registrations are keyed by the same domain string: `dapp_registry_[d]` requires `registrants_[d]` to exist (validator V15 precondition at `src/node/validator.cpp:805–808`), and the entire DAPP_REGISTER apply branch at `src/chain/chain.cpp:1049–1117` reads / writes only `dapp_registry_[tx.from]`. The adversary's question is: under what conditions, if any, can they cause the chain to publish a `domain → service_pubkey` binding where `domain` is not theirs (i.e., not one of `d_A, d_A', ...`)?

We enumerate three concrete attack variants:

### A-S1 — Typosquat (registering a look-alike domain)

The legitimate target is `microsoft.v` (held by Microsoft). The adversary registers `microsft.v` (typo: missing 'o'), `m1crosoft.v` (homoglyph), or `rnicrosoft.v` (rn/m visual collision). The chain admits the registration because `microsft.v` is a distinct domain string and the adversary's `sk_A` legitimately signs the underlying REGISTER + DAPP_REGISTER for `microsft.v`. The chain does not enforce a global Levenshtein-distance check or homoglyph-detection policy.

The adversary's goal is for human end-users to mistake `microsft.v`'s `service_pubkey` for `microsoft.v`'s and address DAPP_CALL traffic (or off-chain `crypto_box_seal` traffic per V2-DAPP-DESIGN.md §10.3) to the adversary's endpoint instead of the legitimate one. The attack succeeds against the human, not against the chain — the chain faithfully publishes the binding the adversary's keypair authorized.

### A-S2 — Cross-domain spoof (registering on someone else's domain)

The legitimate target is `microsoft.v`. The adversary attempts to publish a DAPP_REGISTER with `tx.from == microsoft.v` and a `service_pubkey` they control. For this transaction to be admitted by validators, the adversary needs the Ed25519 signature over the transaction's signing-bytes to verify under `registrants_[microsoft.v].ed_pub`. By assumption, the adversary does not hold the secret key for that public key.

### A-S3 — Service-pubkey rotation attack (mutating a registered DApp's key without owner consent)

The legitimate DApp `microsoft.v` is already registered with `service_pubkey = SP_legit`. The adversary attempts to issue a DAPP_REGISTER `op=0` against `microsoft.v` that replaces the binding with `service_pubkey = SP_attacker`. The DAPP_REGISTER update branch at `chain.cpp:1107–1115` is the rotation path: if the entry exists, the apply path's read-then-rewrite pattern preserves `registered_at` but overwrites every other field including `service_pubkey` (T-D2 in FA-Apply-5). The adversary's question is whether they can drive this update path with their own keypair against `microsoft.v`'s entry.

---

## 2. Defense theorems

### T-1 — Owner-Authenticated Registration

**Statement.** For every block `B` containing a transaction `tx` with `tx.type == DAPP_REGISTER`, if `tx` is admitted to apply (i.e., passes all validator gates and the mempool sig-verify post-S-002), then there exists a Determ domain `d` such that `tx.from == d`, `registrants_[d]` exists at apply-time, and the transaction's Ed25519 signature `tx.sig` verifies under `registrants_[d].ed_pub` over the canonical `signing_bytes(tx)`. Equivalently: a DAPP_REGISTER transaction reaches `chain.cpp:1049–1117` only with the registrant's authentic signature; sender-field forgery reduces to breaking FA1 (Ed25519 EUF-CMA).

*Proof sketch.* By composition of three gates:

1. **Validator V15-class precondition** (`src/node/validator.cpp:797–808`): rejects DAPP_REGISTER when `tx.from` is an anon-address (line 801) or when `registrants_.find(tx.from) == end()` (line 805). So at admit time `tx.from` is a registered Determ domain `d`, and `registrants_[d]` exists.

2. **Mempool-layer Ed25519 signature verification** (S-002, per `S002-Mempool-Sig-Verify.md`): every transaction admitted to the mempool has had its signature verified against `pubkey_of(tx.from)`. For a registered domain, `pubkey_of(d) := registrants_[d].ed_pub`. A transaction with `tx.from == d` passes mempool-admit only if `Ed25519.verify(registrants_[d].ed_pub, signing_bytes(tx), tx.sig) == true`.

3. **Apply-time defense in depth** (FA-Apply I-2, nonce monotonicity gate): even if a malformed transaction somehow bypassed mempool, the apply branch defensively performs the nonce check and fee-charge — but the V15 + mempool gates are the active defenses for the owner-binding property.

By FA1 (Ed25519 EUF-CMA, `Preliminaries.md` §2.2), an adversary `A_spoof` not holding the secret key `sk_d` corresponding to `registrants_[d].ed_pub` cannot produce a valid `Ed25519.sig` on any signing-bytes whatsoever, except with advantage negligible in the security parameter. Therefore the probability that `A_spoof` produces a DAPP_REGISTER admitted to apply with `tx.from == d` (for any `d` whose secret they do not hold) is bounded by the FA1 EUF-CMA advantage, i.e., effectively zero against a polynomial-time adversary. ∎

The structural conclusion is that the "owner identity" anchoring the DApp registry binding is the registrant's Ed25519 keypair — the same keypair that established the Determ domain in the first place. There is no separate "DApp owner key" stored on `DAppEntry`: the owner is structurally encoded in the registry's map key (`dapp_registry_[d]`), which can only be reached by a transaction whose `tx.from == d` and whose signature verifies under `registrants_[d].ed_pub`. T-D3 of `DAppRegistryLifecycle.md` formalizes the apply-side structural claim; T-1 here adds the cryptographic reduction.

**Code witness.** `src/node/validator.cpp:797–808` (V15 + registrants precondition); `src/node/node.cpp` mempool admit path (S-002 sig-verify per `S002-Mempool-Sig-Verify.md`); `src/chain/chain.cpp:1049–1117` (apply-time `tx.from` keying); `include/determ/chain/chain.hpp` (`registrants_` declaration). Cryptographic backstop: FA1 (Ed25519 EUF-CMA, `Preliminaries.md` §2.2).

**Test witness.** `tools/test_dapp_register.sh` exercises the legitimate-registrant create path; the validator-side reject for non-registered `tx.from` is exercised by the V15 negative cases in `tools/test_dapp_state_transition.sh`'s "Independent domain" block (bob's DAPP_REGISTER does not reach alice's slot, structurally enforced by the same `tx.from` keying). Adversarial Ed25519-forgery is non-falsifiable in finite test budget; the assumption FA1 stands per `Preliminaries.md`.

### T-2 — No Cross-Domain Spoof (A-S2 defense)

**Statement.** For every pair of distinct Determ domains `d, d'` with `d ≠ d'`, and every block `B` containing a DAPP_REGISTER transaction `tx` with `tx.from == d` admitted to apply, the apply path mutates only `dapp_registry_[d]` (op=0 or op=1) — never `dapp_registry_[d']`. Combined with T-1's owner-authentication, an adversary `A_spoof` not holding `sk_{d'}` cannot publish or mutate `dapp_registry_[d']`.

*Proof sketch.* The cross-sender-unreachability is exactly FA-Apply-5's T-D3 + T-D5 + T-D7: every `dapp_registry_` access in `chain.cpp:1049–1117` is keyed on `tx.from`, and `std::map` per-key isolation guarantees that mutating `dapp_registry_[tx.from]` does not disturb `dapp_registry_[other_key]`. By T-1, the only way to set `tx.from == d'` and have the transaction admitted to apply is to hold the Ed25519 secret `sk_{d'}`. Thus the composition gives: a DAPP_REGISTER admitted to apply with effective `tx.from == d'` requires either (a) the adversary holds `sk_{d'}` (in which case they are the legitimate owner and the "attack" is just normal operation), or (b) the adversary broke Ed25519 EUF-CMA on `registrants_[d'].ed_pub` (negligible advantage by FA1). ∎

The reduction is sharp: T-2 is not an additional security claim beyond T-1 + the apply-side keying; it is the user-facing statement of the conjunction. The "no cross-domain spoof" property is structural (`std::map` keying) + cryptographic (Ed25519 EUF-CMA) — there is no defense layer between the validator-gate and the apply-time write that the adversary could attack.

**Code witness.** `src/chain/chain.cpp:1049–1117` (all four `dapp_registry_` accesses keyed by `tx.from`: lines 1057, 1060, 1107, 1115); `include/determ/chain/chain.hpp` (`dapp_registry_` as `std::map<std::string, DAppEntry>`); T-D3 + T-D5 + T-D7 of `DAppRegistryLifecycle.md`.

**Test witness.** `tools/test_dapp_state_transition.sh` "Independent domain" block — 2 assertions: bob's DAPP_REGISTER does not affect alice's DApp; alice's deactivated entry survives bob's apply. Generalizes by the same structural argument to every pair `(d_attacker, d_target)`.

### T-3 — Service-Pubkey Rotation Safety (A-S3 defense)

**Statement.** For every DApp `d` with `dapp_registry_[d]` already populated (`service_pubkey = SP_old`, `registered_at = R_0`), the only path that mutates `dapp_registry_[d].service_pubkey` is a DAPP_REGISTER `op=0` transaction with `tx.from == d` that passes all admission gates. By T-1, this requires the registrant's Ed25519 signature on the transaction; an adversary not holding `sk_d` cannot drive the rotation path.

*Proof sketch.* By inspection of every write to `dapp_registry_[d].service_pubkey` in the codebase. The DAPP_REGISTER apply branch at `chain.cpp:1049–1117` is the only mutator: the op=0 path at lines 1107–1115 reads-or-defaults `registered_at` then overwrites the entry's mutable fields (including `service_pubkey`) with the payload's values; the op=1 path at lines 1057–1062 writes only `inactive_from`. No other apply branch, no snapshot-restore path (the restore loop at `chain.cpp:1818–1832` copies the donor's value but does not synthesize a new one), no PARAM_CHANGE (the A5 whitelist does not include any DApp-registry-touching parameter), and no governance path mutates `service_pubkey`.

The rotation path therefore reduces to "another op=0 DAPP_REGISTER with `tx.from == d`." T-D2 of `DAppRegistryLifecycle.md` formalizes the apply-side semantics (registered_at preserved, service_pubkey replaced); T-1 here adds the cryptographic admission requirement. The composition gives: the on-chain authority for rotating `service_pubkey` is the same Ed25519 keypair that established the binding originally — the "on-chain authority hasn't changed." A rotation by an adversary without `sk_d` is unreachable except via Ed25519 EUF-CMA forgery. ∎

The structural design choice is that `service_pubkey` is **not** a separate "second key" with its own authorization — it is data published by the registrant under the registrant's Ed25519 authority. Off-chain `service_pubkey` use (the libsodium `crypto_box_seal` recipient key per V2-DAPP-DESIGN.md §10) is a separate keypair the operator manages out-of-band, but its **chain-published binding** is authorized by `sk_d`. Rotation safety is therefore identical to owner-binding safety.

**Code witness.** `src/chain/chain.cpp:1115` (the only synthesizing write to `dapp_registry_[tx.from].service_pubkey`); `src/chain/chain.cpp:1818–1832` (snapshot-restore — copies donor's value, does not synthesize); T-D2 of `DAppRegistryLifecycle.md`; T-1 above.

**Test witness.** `tools/test_dapp_state_transition.sh` "Update op=0 on same domain" block — 7 assertions including service_pubkey replacement; combined with the "Independent domain" block which pins T-D3 (no cross-sender update), this exercises the rotation path under legitimate-owner-only access.

### T-4 — Off-Chain Service-Pubkey Use Verifiable Against On-Chain Binding

**Statement.** Off-chain DApp clients that wish to send `DAPP_CALL` traffic to domain `d` must first resolve the binding `d → SP_d` via the on-chain registry (the `dapp_info(d)` RPC at `src/rpc/rpc.cpp`, or chain replay over DAPP_REGISTER blocks). Once `SP_d` is resolved, the client encrypts payloads via `crypto_box_seal(SP_d, plaintext)` (libsodium sealed-box per V2-DAPP-DESIGN.md §10), and decryption authority lies with whoever holds `sk_{SP_d}` — by T-1 + T-3, the legitimate registrant. Equivalently: an adversary cannot induce a client to encrypt to an adversary-controlled `SP_attacker` for an honestly-resolved domain `d`, because the on-chain binding for `d` is owner-authenticated.

*Proof sketch.* The off-chain flow is documented in V2-DAPP-DESIGN.md §7.2 + §10.3:

1. Client calls `dapp_info(d)` RPC → server returns `(d, service_pubkey=SP_d, endpoint_url, ...)` from the local `dapp_registry_` view.
2. Client encrypts payload with `crypto_box_seal(SP_d, plaintext)`.
3. Payload is delivered (on-chain via DAPP_CALL, or off-chain directly to `endpoint_url`).
4. Recipient (whoever holds `sk_{SP_d}`) decrypts.

The chain's contribution is step 1: the resolved `SP_d` is the chain's published binding, written by the legitimate registrant per T-1 + T-3. The libsodium primitive guarantees that ciphertext encrypted to `SP_d` is decryptable only by `sk_{SP_d}`. Therefore the off-chain trust assumption is **only** that the chain's published binding is owner-authenticated — which is exactly T-1 + T-3. No additional cryptographic property of the off-chain channel is required for endpoint-spoof resistance; if `A_spoof` cannot publish `(d → SP_attacker)` on-chain, they cannot intercept off-chain traffic addressed to honestly-resolved `d`. ∎

Two caveats live outside this theorem's scope: (a) the RPC server itself must be honest (the local node's `dapp_registry_` could in principle be tampered with by a compromised RPC server, but that is the S-001 RPC-auth threat model, not the S-019 spoof model); (b) replay protection against re-use of stale `SP_d` post-rotation is a separate concern handled by versioned key history (V2-DAPP-DESIGN.md §11.7.1) — the present proof's scope is the **identity** of the binding, not the freshness.

**Code witness.** `src/rpc/rpc.cpp` `dapp_info` handler (returns `dapp_registry_[d]` snapshot); `wallet/main.cpp` `cmd_dapp_call` if applicable (resolves `SP_d` then `crypto_box_seal`); V2-DAPP-DESIGN.md §7.2 + §10.3.

**Test witness.** `tools/test_dapp_call.sh` exercises the full pipeline including `dapp_info` lookup → payload encryption → DAPP_CALL submission → chain inclusion. End-to-end `tools/test_dapp_e2e.sh` covers the multi-node gossip-driven flow.

### T-5 — Typosquat Resistance (A-S1 partial defense / operator responsibility)

**Statement.** For every pair of distinct domain strings `d, d'` with `d ≠ d'` (even if visually similar — `microsoft.v` vs. `microsft.v`), `dapp_registry_[d]` and `dapp_registry_[d']` are independent entries. The chain provides no global namespace authority, no Levenshtein-distance enforcement, and no homoglyph-detection policy. Equivalently: typosquat domains are not impersonations in the cryptographic sense (they are separate registry entries with separate owner keys); typosquat defense is operator-side.

*Proof sketch.* The DApp registry is keyed by raw UTF-8 domain strings (`std::map<std::string, DAppEntry>` declaration at `include/determ/chain/chain.hpp`). The validator and apply path treat domains as opaque byte strings — there is no canonicalization, normalization, or distance-check across the namespace. By T-D7 of `DAppRegistryLifecycle.md`, `dapp_registry_[d]` and `dapp_registry_[d']` are fully isolated. By T-1, the registrant of `d` is the holder of `sk_d`; the registrant of `d'` is the holder of `sk_{d'}`; these are distinct keypairs (assuming the registrants are distinct actors).

The structural conclusion is that a typosquat is not a cryptographic spoof: the typo-squatter genuinely owns the typo'd domain and the chain genuinely publishes their binding. The attack surface is **human**: an end-user mistakenly types `microsft.v` or copy-pastes from a phishing site and the chain has no signal to flag the error. ∎

The defense reduces to:

1. **Wallet / UI display of the full registry binding** — the user sees `domain = microsft.v` (not `microsoft.v`) plus the `service_pubkey` hex prefix and the `endpoint_url`; a careful user spots the typo. Finding F-1 in §4 below.
2. **Operator-side namespace policy** — a future protocol extension (not part of the current S-019 scope) could add a "verified-by-namespace-authority" attestation flag, similar to DNSSEC chain-of-trust. Out of scope for v2.18+.
3. **Off-chain reputation systems** — third-party "domain-registry indices" that flag known typosquats. Pure off-chain operator concern.

**Code witness.** No code witness for "the chain does not enforce typosquat policy" — the absence is structural. `include/determ/chain/chain.hpp` (`dapp_registry_` declaration with raw `std::string` keys); `src/node/validator.cpp:805–808` (precondition checks `registrants_.find(tx.from)` literally, no normalization).

**Test witness.** No regression test exercises typosquat resistance directly because the chain provides no defense to exercise; the "Independent domain" assertions in `tools/test_dapp_state_transition.sh` pin T-D7 structurally but do not target the operator-side disambiguation aspect of T-5.

---

## 3. Adversary outcomes (per attack variant)

| Variant | Goal | Theorem defending | Residual risk |
|---|---|---|---|
| **A-S1** (typosquat) | Lure humans to adversary's look-alike domain | T-5 (partial — structural, not cryptographic) | High at the human layer; **the chain cannot eliminate this**. Defense is operator-side: wallet UI must display the binding for verification (F-1); reputation systems may flag known typosquats; protocol-level "verified" attestation is a future extension. |
| **A-S2** (cross-domain spoof) | Publish a DAPP_REGISTER claiming another's domain | T-1 + T-2 | Negligible (reduces to FA1 Ed25519 EUF-CMA forgery). The only escape is a compromised registrant secret key, which is a key-management failure outside the chain's scope. |
| **A-S3** (service_pubkey rotation attack) | Replace a registered DApp's `service_pubkey` to redirect future traffic | T-1 + T-3 | Negligible (reduces to FA1 forgery). Operational note: if `sk_d` is suspected compromised, the operator's recovery path is to issue a fresh DAPP_REGISTER `op=0` with a new `service_pubkey` — but this requires `sk_d`, which by hypothesis is compromised. The owner-binding model has no chain-level recovery if `sk_d` is lost or stolen; this is the same constraint as every other Determ identity operation. |

The three variants form a complete adversary surface for endpoint-spoofing on the v2.18+ DApp substrate (single-shard, pre-versioned-key-rotation). The cross-shard case (V2-DAPP-DESIGN.md §11.7.2, deferred to Phase 7.6) and the versioned-key-rotation case (§11.7.1, deferred to v2.24) extend the surface but do not invalidate T-1..T-5: cross-shard DAPP_CALL routing inherits T-2's apply-side owner-binding via the same `tx.from` keying; versioned key rotation extends T-3 to a key-history list with per-version owner-authentication, preserving the rotation-safety property.

---

## 4. Findings

### F-1 — Wallet / UI display of the registry binding for verification (operational defense for A-S1)

The strongest defense the chain offers against typosquat attacks (A-S1) is faithful publication of the binding `(domain, service_pubkey, endpoint_url)`. A user sending traffic to `microsoft.v` should see, before submission, the resolved binding — both the domain string they typed (so they can spot a typo like `microsft.v`) and the `service_pubkey` fingerprint + `endpoint_url` (so they can cross-check against an out-of-band reference, such as the legitimate operator's website displaying its public-key fingerprint). The wallet's `dapp-info` and `submit-dapp-call` flows should surface this binding prominently — ideally as an explicit confirmation step ("Sending to domain `microsft.v` with service-pubkey `5f3a...` — confirm? y/N") rather than as a silent resolution.

Current state: `determ dapp-info <domain>` (per `docs/CLI-REFERENCE.md`) does return the full binding for inspection. The wallet-side `submit-dapp-call` invocation likely does not interactively confirm. **Recommendation**: add an opt-in `--confirm-binding` flag to `submit-dapp-call` (or make it the default for non-batch invocations) that prints `domain`, `service_pubkey` hex prefix (first 16 chars), `endpoint_url`, and prompts for explicit confirmation before signing. Low-effort, high-value defense against operator carelessness.

### F-2 — Documentation of the on-chain ↔ off-chain key separation

V2-DAPP-DESIGN.md §3.1 + §4 document the `DAppEntry` schema, and the design distinguishes "Determ identity Ed25519 keypair" (`registrants_[d].ed_pub`) from "DApp service keypair" (`service_pubkey`, libsodium box pubkey). The conceptual model is clean: the former is the chain authority that authorizes registry mutations; the latter is the off-chain crypto-recipient key that the chain merely publishes. However, the two are easy to confuse for newcomers — both are "keys associated with the DApp," and the security implications of each compromise are different. **Recommendation**: V2-DAPP-DESIGN.md §3 or §4 should add a short subsection titled "Two keys, two trust roles" that explicitly lays out: (a) Ed25519 registrant key → chain-authorization (mutations of `dapp_registry_[d]`); (b) `service_pubkey` → off-chain payload-decryption (no chain-authorization role); (c) compromise of (a) lets an attacker rotate (b); (d) compromise of (b) alone does not affect (a) — the binding is unchanged, but past traffic encrypted to the compromised key is exposed. The present proof's T-1 + T-3 + T-4 give the formal statement; a non-cryptographer reader benefits from the prose pointer.

### F-3 — `service_pubkey` rotation as a same-key-bootstrap loop

The current v2.18+ rotation path (T-3) requires the registrant's Ed25519 secret key `sk_d` to authorize a new `service_pubkey`. This is the right cryptographic constraint, but it creates an operational footgun: if `sk_d` is suspected of partial compromise (e.g., an HSM logs anomalous activity), the operator's only recovery path is to use `sk_d` once more to rotate `service_pubkey`. If `sk_d` is fully compromised, recovery is impossible at the chain layer — the attacker can race the legitimate operator to issue the rotation. The deferred v2.24 versioned-key-rotation work (V2-DAPP-DESIGN.md §11.7.1) addresses freshness but not recovery from primary-key compromise. **Recommendation**: a future enhancement (v2.26 or later) could add a "co-signed rotation key" (the `rotation_pubkey` slot already drafted in V2-DAPP-DESIGN.md §11.7.1's `DAppEntryV2` struct sketch) — a second authorized key, hardware-protected, whose role is specifically to authorize emergency `service_pubkey` rotations when the primary registrant key is compromised. Out of scope for the present proof; tracked as a v2.X+ design item.

---

## 5. Cross-references

| Reference | Role |
|---|---|
| `DAppRegistryLifecycle.md` (FA-Apply-5) | T-D1..T-D8 — the apply-side state-machine theorems that T-2 + T-3 + T-5 rest on, especially T-D3 (cross-sender update unreachable), T-D5 (deactivation by non-owner unreachable), T-D7 (per-domain independence). |
| `S001RpcAuthSoundness.md` | Cross-cutting "auth-then-validate" composition pattern that the present proof mirrors — HMAC-auth ↔ Ed25519-tx-sig as the gating cryptographic primitive. |
| `S002-Mempool-Sig-Verify.md` | Mempool-layer Ed25519 verification that ensures `tx.from` is unforgeable at gossip time; foundational for T-1. |
| `Preliminaries.md` §2.2 | FA1 — Ed25519 EUF-CMA assumption. The cryptographic reduction T-1's safety relies on. |
| `RpcInputValidationDefense.md` | Layer C semantic gates referenced in the V15 precondition chain. |
| `SnapshotEquivalence.md` (FA-Apply-2) | L-S0 / L-S1 row `d:` (S-037 closure) — guarantees DApp registry bindings survive snapshot bootstrap, so T-1..T-3 hold across the snapshot ↔ replay boundary. |
| `docs/PROTOCOL.md` §14.5 `DAPP_REGISTER` | Wire format + apply-rule summary. |
| `docs/PROTOCOL.md` §4.1.1 (`d:` namespace) | State-root binding for the DApp registry — makes the registry contents part of the chain's cryptographic commitment. |
| `docs/V2-DAPP-DESIGN.md` §3.1 | DAPP_REGISTER tx structure + service_pubkey field. |
| `docs/V2-DAPP-DESIGN.md` §4 | DAppEntry struct + registry schema. |
| `docs/V2-DAPP-DESIGN.md` §7.2 + §10.3 | Off-chain client flow + direct-to-DApp delivery pattern; foundational for T-4. |
| `docs/V2-DAPP-DESIGN.md` §11.7.1 | Deferred v2.24 versioned-key-rotation work; F-3 references this. |
| `docs/SECURITY.md` §S-019 | Original Phase-2 timer entry — disjoint from the present analytic treatment (see preamble note). |
| `docs/SECURITY.md` §S-001 | Companion RPC-auth threat model — T-4's RPC-server-honest caveat references this. |
| `src/chain/chain.cpp:1049–1117` | DAPP_REGISTER apply branch — keys all writes by `tx.from` (T-2 + T-3 structural basis). |
| `src/node/validator.cpp:797–808` | V15 + registrants precondition (T-1 admission gate). |
| `include/determ/chain/chain.hpp` | `dapp_registry_` declaration (`std::map<std::string, DAppEntry>` — raw-string keying for T-5 typosquat-resistance scope). |
| `tools/test_dapp_register.sh` | Legitimate-registrant create path (T-1 happy path). |
| `tools/test_dapp_state_transition.sh` | "Update op=0", "Deactivate op=1", "Independent domain" blocks — T-2 + T-3 structural pins. |
| `tools/test_dapp_call.sh` + `tools/test_dapp_e2e.sh` | End-to-end DAPP_CALL flow that depends on T-4's off-chain binding-resolution. |

---

## 6. Status

All five theorems (T-1 through T-5) are closed in the v2.18+ codebase:

- **T-1** (Owner-Authenticated Registration) closed via the composition of validator V15 + mempool S-002 sig-verify + FA1 (Ed25519 EUF-CMA).
- **T-2** (No Cross-Domain Spoof) closed via T-1 + T-D3 + T-D7 of FA-Apply-5 (`dapp_registry_[tx.from]` keying + `std::map` per-key isolation).
- **T-3** (Service-Pubkey Rotation Safety) closed via T-1 + T-D2 of FA-Apply-5 (rotation path requires owner Ed25519 sig).
- **T-4** (Off-Chain Service-Pubkey Use Verifiable) closed via T-1 + T-3 + libsodium `crypto_box_seal` recipient-key semantics.
- **T-5** (Typosquat Resistance) closed *structurally* — the chain provides per-domain owner-binding but no global-namespace authority; defense reduces to operator-side discipline (F-1 wallet/UI display, F-2 documentation of the two-key model).

No theorem is open or partial at the chain layer. The three findings F-1..F-3 are operational and documentation recommendations, not security gaps in the chain proper. F-1 (wallet binding-confirmation UI) is the most actionable; F-2 (two-key documentation clarification) is editorial; F-3 (emergency-rotation co-signed key) is a future-protocol design item tracked against the v2.24 versioned-key-rotation roadmap.

The proof's foundation rests on three primitives: (i) the `dapp_registry_[tx.from]` keying that makes owner-binding structural; (ii) the validator V15 precondition that gates DAPP_REGISTER on `registrants_[tx.from]` existence; (iii) the FA1 Ed25519 EUF-CMA assumption that makes `tx.from` unforgeable. The breadth of consequences — three cryptographically-defended attack variants, one operational-defense variant, four findings, complete coverage of the v2.18+ DApp endpoint-spoof attack surface — reduces to those three primitives plus the FA-Apply-5 state-machine inheritance.
