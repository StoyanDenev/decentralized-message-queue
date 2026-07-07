> **TIER: PROCESS / ARCHIVE.** Deliberation/meta; retained for rationale but NOT coherence-maintained as part of the 1.0 set. Roadmap index: docs/ROADMAP.md

> **SUPERSEDED — crypto substrate (2026-07-07).** This doc's MODERN-profile native-client stack (§3) is written around a **secp256k1 / libsecp256k1 / libsecp256k1-zkp / FROST** plan that was **never built and is abandoned**. Reality (per `DECISION-LOG.md` 2026-07-07 D1/D3, 2026-07-03; `CRYPTO-C99-SPEC.md` §3.8c/§3.9b/§3.19): the owner **rejected secp256k1** (a Koblitz curve) — **no `src/crypto/secp256k1*` exists**. All prime-order / Bulletproof / Pedersen / confidential-tx work is over **NIST P-256** (`src/crypto/pedersen/`, §3.19; `src/crypto/p256/`, §3.8c). **FROST is FROZEN** (removed from the chain path 2026-07-03). DSSO uses **DLT-A** (a T-OPRF, not FROST-based T-OPAQUE): the **FIPS** DSSO OPRF is **NIST P-256 voprf** (RFC 9497, §3.9b); the **MODERN** DSSO OPRF is **X25519 T-OPRF**. `ristretto255` was never used. Read every `secp256k1`/`libsecp256k1-zkp`/`FROST` mention below as the abandoned intended architecture; only the corrected per-profile OPRF rows in §3.3/§4/§6 have been updated in place — the rest of this ARCHIVE file is retained for rationale, not rewritten.

# DApp SDK guidance — browser-side crypto strategy

**Audience.** DApp developers building user-facing clients that interact with the Determ chain. Operator teams choosing between deployment-shape options.

**Purpose.** Specify the recommended browser-side crypto stack per deployment profile, the architectural split between native and web layers, and the cryptographic guarantees each shape preserves.

**Coherence with other artifacts.**
- `CRYPTO-C99-SPEC.md` — governs chain-side crypto primitives. **This doc governs only browser-side crypto.** Browser-side libraries are not subject to CRYPTO-C99's two-curve-family discipline.
- `v2.22-PRIVACY-SPEC.md` — confidential-transaction wire format whose verification primitives the DApp client may need.
- `PFS_DEPLOYMENT_GUIDANCE.md` — operator-facing PFS-mode-deployment framework.
- `Improvements.md §8.1` — DSSO-as-DApp reclassification (post-v1.0 chain-aware DApp); DSSO browser clients follow the architecture in this doc.

---

## 1. Two deployment shapes

| Profile | Shape | Why |
|---|---|---|
| **FIPS** (`tactical`, `cluster`) | **Smart-client web UI** — fully browser-based; no native component required | SJCL's primitive coverage matches the FIPS primitive set exactly. Self-contained browser deliverable; small audit surface; no native installation friction. The FIPS primitive set is NIST P-256 / AES-256-GCM / PBKDF2, so the MODERN-only libraries (secp256k1, ChaCha20) aren't needed browser-side. (FIPS does support confidential-tx via the P-256 shielded pool, but its Bulletproof verification stays server-side, like the MODERN row.) |
| **MODERN** (`web`, `regional`, `global`) | **Native DLT client + web interface** — native app handles wire-format crypto; web interface uses SJCL for UI-layer concerns | Browser-side Bulletproof verification has no maintained C99-WASM port; secp256k1 + ChaCha20 + Argon2id are similarly browser-friction-heavy at production-grade. Native client takes ownership of wire-format crypto; web layer becomes a thin UI. |

This split is the **load-bearing architectural choice** that this doc documents. Specific stack recommendations follow.

---

## 2. FIPS profile — Smart-client web UI

### 2.1 Crypto stack

| Need | Primitive | Source | Notes |
|---|---|---|---|
| AEAD | AES-256-GCM | SJCL (extension over AES-CCM/OCB core) | Direct fit |
| Hash | SHA-256, SHA-512 | SJCL | Direct fit |
| HMAC | HMAC-SHA-256, HMAC-SHA-512 | SJCL | Direct fit |
| KDF (passphrase) | PBKDF2-HMAC-SHA-256 | SJCL | Direct fit, FIPS-compliant per C99-11 |
| KDF (key derivation) | HKDF-SHA-256 | Thin wrapper over SJCL HMAC (~20 LOC) | RFC 5869 expand/extract from SJCL HMAC |
| Asymmetric (signing) | NIST P-256 ECDSA | SJCL | Direct fit |
| Asymmetric (key agreement) | NIST P-256 ECDH | SJCL | Direct fit; SP 800-56A compliant |
| Future: PQ signature | Dilithium | Separate library (when v2.8 ships) | No SJCL support; reserved for future addition |

Total browser-side surface: SJCL + ~20 LOC HKDF wrapper.

### 2.2 What's NOT needed

Because the FIPS browser smart-client uses NIST P-256 / AES-256-GCM / PBKDF2 and leaves wire-format ZK (Bulletproof / Pedersen) verification server-side:
- ❌ Bulletproof range-proof verification
- ❌ Pedersen commitment operations
- ❌ secp256k1 primitives
- ❌ ChaCha20-Poly1305 / XChaCha20-Poly1305
- ❌ Argon2id (FIPS uses PBKDF2)
- ❌ Ed25519 (FIPS uses ECDSA over P-256; though some FIPS-permissive deployments could use Ed25519 via FIPS 186-5)

### 2.3 Operator deliverable

A self-contained browser bundle: SJCL + HKDF wrapper + Determ chain-aware client code. Auditable; small footprint; no native install. Suitable for compliance-regulated environments where browser-only deployment is required (e.g., bank treasury operations, regulated gambling operators).

### 2.4 Composition with v2.16 (RPC auth) and v2.17 (encrypted keyfiles)

- v2.16 internal RPC auth uses HMAC-SHA-256 — SJCL covers directly.
- v2.17 keyfile encryption uses AES-256-GCM + PBKDF2 in FIPS profile — SJCL covers directly. The browser can load/decrypt v2.17 keyfiles natively.

---

## 3. MODERN profile — Native DLT client + web interface

### 3.1 Architectural split

```
┌──────────────────────────────────────────────────────────────┐
│ Browser (Web Interface)                                      │
│ ├─ SJCL — UI-layer crypto:                                   │
│ │  ├─ AES-256-GCM for form-data encryption-at-rest (browser  │
│ │  │  localStorage / IndexedDB)                              │
│ │  ├─ SHA-256/512 for display hashes, UX truncation          │
│ │  ├─ HMAC for browser-side integrity of cached objects      │
│ │  └─ PBKDF2 for password-derived UI session keys            │
│ ├─ JSON-RPC client for native bridge                         │
│ └─ UI framework (React/Vue/Svelte/etc.)                      │
└─────────────────────────┬────────────────────────────────────┘
                          │ IPC / WebSocket / localhost-HTTP
┌─────────────────────────▼────────────────────────────────────┐
│ Native DLT Client — Wire-format crypto:                      │
│ ├─ libsodium — Ed25519 sigs, X25519 (for v2.10 FROST)        │
│ ├─ libsecp256k1 — secp256k1 ECDH + ECDSA (v2.22 + ECDSA)     │
│ ├─ libsecp256k1-zkp — Bulletproof verify + Pedersen          │
│ ├─ ChaCha20-Poly1305 / XChaCha20-Poly1305 — AEAD             │
│ ├─ Argon2id — passphrase KDF                                 │
│ └─ Determ chain client — Bundle 1-5 client code              │
└──────────────────────────────────────────────────────────────┘
```

The web layer never touches wire-format crypto. SJCL's role is confined to UI-layer concerns that don't interact with chain primitives.

### 3.2 Web layer — SJCL usage

| Use case | SJCL primitive |
|---|---|
| Form-data encrypt-at-rest in browser storage | AES-256-GCM |
| Display hash truncation (e.g., short tx ID UI) | SHA-256 |
| Browser-cache integrity (e.g., signed cache entries) | HMAC-SHA-256 |
| Browser-side password-derived session key (if applicable) | PBKDF2-HMAC-SHA-256 |
| Comparison hashing for UI search/filter | SHA-256 |

**Important constraint.** The web layer MUST NOT:
- Sign transactions directly
- Verify on-chain proofs (Bulletproofs, signatures)
- Encrypt/decrypt confidential-tx amounts
- Derive view-keys (PRIV-1 HKDF chain)
- Handle OTPK privkeys (PRIV-6)

All of those operations are wire-format crypto. They live in the native client. The web layer requests them via IPC.

### 3.3 Native client — Wire-format crypto

| Wire-format need | Native library | Notes |
|---|---|---|
| Ed25519 signing (tx sigs, block creator sigs) | libsodium | Per C99-11 MODERN profile |
| FROST-Ed25519 threshold signing (v2.10) | libsodium + FROST-from-RFC-9591 impl | Per CRYPTO-C99 §3.x |
| secp256k1 ECDH (v2.22 amount handshake) | libsecp256k1 | Per PRIV-3 revise |
| secp256k1 ECDSA / Schnorr (if used) | libsecp256k1 | Per CRYPTO-C99 §2.Q3 |
| Bulletproof range-proof verify | libsecp256k1-zkp | Per PRIV-2 |
| Pedersen commitment operations | libsecp256k1-zkp | Per PRIV-2 |
| XChaCha20-Poly1305 AEAD | libsodium | Per PRIV-3 |
| Argon2id passphrase KDF | Argon2 reference (P-H-C) | Per C99-11 |
| OPRF (MODERN DSSO, DLT-A; future) | X25519 T-OPRF (per DECISION-LOG 2026-07-07 D1 — NOT secp256k1) | Per CRYPTO-C99 DSSO-OPRF profile matrix |

### 3.4 IPC bridge

The native ↔ web bridge defines a stable JSON-RPC surface for the web layer to invoke native wire-format operations. Recommended bridge operations:

| Bridge call | Purpose |
|---|---|
| `sign_tx(tx_body) → signed_tx` | Native signs a transaction with stored Ed25519 key |
| `verify_block_sig(block) → bool` | Native verifies block-creator signatures |
| `encrypt_amount(recipient_pk, amount, blinding) → ct + commit + range_proof` | Native builds confidential-tx amount payload |
| `decrypt_amount(eph_pk, ct) → amount` | Native decrypts inbound confidential amount |
| `verify_range_proof(commit, proof) → bool` | Native validates a Bulletproof |
| `derive_epoch_view_key(epoch) → vk_epoch_n` | Native runs PRIV-1 HKDF chain |
| `rotate_view_master() → new_pubkey + ROTATE_VIEW_MASTER tx` | Native handles ROTATE_VIEW_MASTER per PRIV-5 |
| `generate_otpk_batch(N) → published_batch_tx + privkey_storage` | Native handles PRIV-6 OTPK generation |

Bridge runs over IPC (Unix domain socket, named pipe, localhost-bound HTTP, or platform-native equivalent). Wallet UX flows traverse the bridge; web layer never sees private keys.

### 3.5 Operator deliverable

Two artifacts:
- **Native DLT client binary** per platform (Windows / macOS / Linux x86_64 + ARM64). Bundles libsodium + libsecp256k1 + libsecp256k1-zkp + Argon2 + Determ client code. Largest crypto surface; auditable per CRYPTO-C99 vendored sources.
- **Web bundle** consumed by browser or embedded in native client's webview. SJCL + UI framework + bridge client. Small; auditable independently.

---

## 4. DSSO-as-DApp implications

Per `Improvements.md §8.1`, DSSO is a chain-aware DApp shipping post-v1.0. DSSO's browser client follows the per-profile pattern in §2 / §3:

| Profile | DSSO browser client |
|---|---|
| FIPS | Standalone web UI using SJCL: NIST P-256 OPRF (RFC 9497, CRYPTO-C99 §3.9b — the DSSO DLT-A OPRF leg) + AES-256-GCM AEAD + PBKDF2 + HKDF wrapper. All DSSO/DLT-A coordination via DAPP_CALL through SJCL HTTP/WebSocket. |
| MODERN | Native DLT client provides X25519 T-OPRF (DLT-A, per DECISION-LOG 2026-07-07 D1 — NOT secp256k1) + XChaCha20-Poly1305 + Argon2id + HKDF. Web UI uses SJCL for UI concerns; the DSSO/DLT-A flow goes through the IPC bridge to native. |

This composition is internally consistent: DSSO assertions verify against on-chain committee pubkeys (resolved via state_proof RPC) regardless of profile; only the user-facing DSSO/DLT-A OPRF substrate differs per profile (FIPS = NIST P-256 voprf §3.9b, MODERN = X25519 T-OPRF).

---

## 5. Cross-cutting notes

### 5.1 Why SJCL specifically for the web layer

Alternatives considered:

| JS crypto library | Why not chosen |
|---|---|
| Web Crypto API (browser-native) | Limited primitive coverage; inconsistent browser support; awkward async API; no PBKDF2 ergonomics across all targets |
| libsodium.js | Comprehensive but large (~1-2 MB WASM bundle); covers MODERN primitives in browser which is unnecessary under the §3 split |
| noble-* family | Modern, audited, but split across many packages; tree-shake works but adds dependency management complexity |
| Pure browser implementation | Reinventing crypto; never recommended |

SJCL is chosen for: small footprint, well-audited Stanford pedigree, AES + SHA + PBKDF2 + P-256 coverage (the FIPS subset), permissive license. The FIPS-coverage match is the deciding factor.

### 5.2 SJCL maintenance status

SJCL is minimally maintained (last significant updates years prior). **For v1.0 this is acceptable** because:
- The primitives SJCL uses (AES, SHA-256, P-256, PBKDF2) are mathematically stable; no algorithmic update needed.
- The audit surface is fixed and reviewable.
- A fork-and-vendor strategy keeps the library under project control even if upstream becomes fully unmaintained.

**Recommended discipline.** Fork SJCL into Determ's vendoring tree (`src/web/sjcl/` or equivalent) with pinned upstream commit. Treat as vendored C99 libraries are treated (per CRYPTO-C99 §3.x): pinned, auditable, never auto-updated.

### 5.3 What if a DApp needs MODERN primitives in pure browser (no native client)?

This is **not the recommended pattern** under this guidance. If a DApp insists on browser-only deployment for a MODERN-profile chain, the DApp owner accepts:
- Significant browser-side library lift (libsodium.js + WASM libsecp256k1-zkp for Bulletproofs)
- Larger audit surface
- Increased browser-resource consumption
- The DApp ships its own non-SJCL-based browser crypto stack

This pattern is permitted (the chain doesn't constrain DApp implementation choices) but not recommended. Browser-only MODERN deployment is an explicit choice with cost trade-offs.

### 5.4 PQ migration browser-side

When v2.8 ships PQ signature migration (post-v1.0; classified Additive via 7.5.6/7.5.7 discriminators):
- FIPS web UI adds Dilithium JS library (no SJCL support); SJCL otherwise unchanged.
- MODERN native client adds Dilithium C99 library; web UI unchanged.
- Both profiles dispatch on `Transaction.sig_form` + `pubkey_form` discriminators per §7.5.6 / §7.5.7.

---

## 6. Open ecosystem needs (under this guidance)

Items NOT needed by this guidance (resolved):
- ✅ Browser-side Bulletproof verify (only needed if pure-browser MODERN; not recommended)
- ✅ Browser-side secp256k1 (only needed if pure-browser MODERN; not recommended)
- ✅ Browser-side ChaCha20 (only needed if pure-browser MODERN; not recommended)
- ✅ Native ECDSA over P-256 (libsecp256k1 covers via separate curve binding or via a vendored P-256 module per CRYPTO-C99 §3.8c)

Items still needed (open ecosystem work, post-v1.0):
- ⏳ FIPS-profile Dilithium JS library (when v2.8 ships)
- ⏳ FIPS-profile DSSO DLT-A primitives on top of SJCL NIST P-256 OPRF (RFC 9497, §3.9b) (when DSSO ships as DApp)
- ⏳ Native client packaging + IPC bridge spec (Bundle 5 era; operator deliverable)

---

## 7. DApp pricing patterns under AI-agent economy dominance (added 2026-06-05)

By 2026 AI traffic has surpassed human traffic on the broader internet. DApps building on Determ should structure pricing for AI-mediated usage where principals delegate to AI agents that act at higher transaction velocity than the principal alone would. The chain protocol itself stays free (per `Improvements.md §9.6` final monetization model — no protocol-level discrimination); DApps absorb the pricing-design problem and discriminate at the application layer where they have visibility to do so legitimately.

### 7.1 Why DApp-layer (not protocol-layer) pricing for AI traffic

The protocol cannot tell an AI agent's tx from a human agent's tx — both look like signed messages from key holders. Trying to discriminate at protocol level creates the same gaming dynamics as the rejected casino-fee proposal (per `Improvements.md §9.3` / DECISION-LOG.md 2026-06-03). DApps, by contrast, can see:
- Who is the principal (the human or organization the agent represents)
- Whether the action is part of a delegated workflow
- The principal's subscription tier / payment status

DApps price-discriminate where they have legitimate visibility; the chain stays free.

### 7.2 Recommended DApp pricing patterns

| Pattern | Mechanism | When appropriate |
|---|---|---|
| **Per-principal subscription** | Principal pays one recurring bill covering self + all delegated AI agents' actions for the period | Default for principal-mediated use; predictable revenue; AI volume doesn't bankrupt principal |
| **Per-action with principal-aggregate cap** | Per-tx pricing capped at a monthly per-principal maximum | Hybrid; per-action visibility + cap protection; matches "pay for what you use up to a cap" |
| **Delegation-credential issuance fee** | One-time fee at the moment a principal grants DSSO-DApp delegation to an AI agent | Captures AI proliferation directly; self-selecting (humans without delegates pay nothing); composes with DSSO-as-DApp delegation flow |
| **Volume-tier discounts scaling with AI orchestration** | Higher-volume principals pay less per-tx | Recognizes AI orchestration as legitimate; rewards consolidation under one principal vs proliferation of small accounts (which has Sybil implications) |

### 7.3 Composition with Determ chain primitives

| Primitive | AI-agent use |
|---|---|
| DSSO-as-DApp delegation (post-v1.0; `Improvements.md §8.1`) | Each AI agent is a DSSO-issued delegate of a principal; delegation credentials are the natural pricing unit |
| v2.22 PFS (PRIV-6) | AI agents transacting on principal's behalf use PFS mode to protect principal's financial patterns from AI-system-operator surveillance |
| v2.26 ROTATE_KEY (with KR-10 unified key_target) | Delegate revocation via ROTATE_KEY on the DApp service_pubkey for that delegate; principal can revoke specific AI agents without losing identity continuity |
| v2.24 audit hooks | Principal can audit delegate-action history via PRIV-4 dual-mode disclosure to compliance officer |

### 7.4 Practical guidance for DApp developers

1. **Default to per-principal subscription** for new DApps unless a specific use case requires per-action pricing.
2. **Use DSSO-as-DApp delegation credentials** (post-v1.0) as the unit of pricing for AI agents — one credential per agent; price the credential issuance, not the per-action stream.
3. **Cap per-action billing aggressively** to prevent runaway AI usage from bankrupting principals.
4. **Offer volume-tier discounts** to encourage principals to consolidate AI delegates under one account rather than proliferate Sybil-prone accounts (composes with §S-010 stake-pricing posture).
5. **Make the principal-vs-delegate distinction visible** in DApp UX — humans should be able to see and revoke their AI agents' delegations easily (compose with v2.26 ROTATE_KEY).

### 7.5 Composition with v1.x chain-level fee + subsidy mechanism

**Important context (clarified 2026-06-05):** DApp-layer pricing is the SECOND layer of revenue capture, not the only one. v1.x already provides a chain-level fee + subsidy mechanism (per `WHITEPAPER-v1.x.md §8.2-8.4` + `PROTOCOL.md`):

- Per-tx `fee` field on every transaction (sender pays; accumulates to block creators)
- `block_subsidy: u64` per-block reward to K committee members
- `subsidy_pool_initial: u64` optional cap on cumulative subsidy
- `subsidy_mode: u8` FLAT vs LOTTERY distribution

The chain-level rates are operator-configured per deployment via genesis-pinned constants. DApp-layer pricing in §7.2-7.4 is ADDITIONAL to v1.x chain-level fees, not a replacement.

**Practical implication.** DApp developers should treat per-tx chain fees as a cost-of-goods that gets factored into per-principal subscriptions or per-action prices. The DApp's effective per-action cost = (its application-layer price) + (chain-level per-tx fee paid for the user's tx). Per-principal subscription bills should be calibrated to cover both layers.

For sovereign-deployment chains (banks, governments, enterprises self-hosting), per-tx fees may be set to zero by the sponsor; DApp-layer pricing is the only layer. For public/permissionless chains, both layers apply.

See `Improvements.md §9.6` for the full three-layer framing (chain-level + DApp-layer + Foundation-services).

### 7.6 What this section is NOT

- Not the only revenue layer — v1.x chain-level fee + subsidy is the first layer; DApp-layer is the second; Foundation services is the third. Per `Improvements.md §9.6` final framing.
- Not a DSSO delegation protocol spec — that lives in `Improvements.md §8.1` as a post-v1.0 DApp.
- Not enforceable at chain level — DApps choose their application-layer pricing model; the chain doesn't validate DApp pricing compliance (the chain enforces only its own per-tx fee at the rate set by the deployment's genesis config).

---

## 8. What this doc is NOT

- **Not a chain-side crypto spec.** That's `CRYPTO-C99-SPEC.md`.
- **Not a DApp protocol spec.** DApp protocols (DAPP_REGISTER, DAPP_CALL) are governed by Theme 7 specs.
- **Not legal advice.** PFS-mode deployment regulatory implications live in `PFS_DEPLOYMENT_GUIDANCE.md`.
- **Not immutable.** Browser ecosystem evolves; revisit as PQ libraries mature, as Web Crypto API extends, as new browser-friendly Bulletproof implementations emerge.

---

*End of DApp SDK guidance.*
