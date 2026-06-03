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
| **FIPS** (`tactical`, `cluster`) | **Smart-client web UI** — fully browser-based; no native component required | SJCL's primitive coverage matches the FIPS primitive set exactly. Self-contained browser deliverable; small audit surface; no native installation friction. Confidential transactions don't exist in FIPS (per C99-11), so the heavy MODERN-only primitives (Bulletproofs, secp256k1, ChaCha20) are not needed. |
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

Because FIPS profile excludes confidential transactions (C99-11):
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
| OPRF on secp256k1 (future T-OPAQUE for DSSO-DApp) | voprf reference + RFC 9380 | Per CRYPTO-C99 §3.9 |

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
| FIPS | Standalone web UI using SJCL: P-256 OPRF (T-OPAQUE primitive) + AES-256-GCM AEAD + PBKDF2 + HKDF wrapper. All T-OPAQUE coordination via DAPP_CALL through SJCL HTTP/WebSocket. |
| MODERN | Native DLT client provides secp256k1 OPRF (per CRYPTO-C99 §3.9) + XChaCha20-Poly1305 + Argon2id + HKDF. Web UI uses SJCL for UI concerns; T-OPAQUE flow goes through the IPC bridge to native. |

This composition is internally consistent: DSSO assertions verify against on-chain committee pubkeys (resolved via state_proof RPC) regardless of profile; only the user-facing T-OPAQUE primitive substrate differs per profile.

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
- ⏳ FIPS-profile DSSO T-OPAQUE primitives on top of SJCL P-256 OPRF (when DSSO ships as DApp)
- ⏳ Native client packaging + IPC bridge spec (Bundle 5 era; operator deliverable)

---

## 7. What this doc is NOT

- **Not a chain-side crypto spec.** That's `CRYPTO-C99-SPEC.md`.
- **Not a DApp protocol spec.** DApp protocols (DAPP_REGISTER, DAPP_CALL) are governed by Theme 7 specs.
- **Not legal advice.** PFS-mode deployment regulatory implications live in `PFS_DEPLOYMENT_GUIDANCE.md`.
- **Not immutable.** Browser ecosystem evolves; revisit as PQ libraries mature, as Web Crypto API extends, as new browser-friendly Bulletproof implementations emerge.

---

*End of DApp SDK guidance.*
