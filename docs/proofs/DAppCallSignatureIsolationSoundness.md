# DAppCallSignatureIsolationSoundness — the DAPP_CALL transport/payload-crypto trust boundary

This document states precisely what the **chain** does and does **not** guarantee about a `DAPP_CALL` transaction's encrypted payload (`ciphertext`). It is a *boundary* proof, not a vulnerability disclosure: it draws the line between the chain's role (a transport + ordering + integrity layer that binds the payload **bytes as submitted** under the sender's Ed25519 signature and commits them per-block under `tx_root`) and the *off-chain* role (end-to-end confidentiality and recipient-binding of the ciphertext, performed by the sender via libsodium `crypto_box_seal(service_pubkey, plaintext)` and by the DApp operator via the matching secret). The load-bearing, easy-to-misread fact this proof pins is: **the chain never decrypts a `DAPP_CALL` ciphertext, never verifies the ciphertext was actually sealed to the registered DApp's `service_pubkey`, and need not — that recipient-binding is an end-to-end property between sender and DApp, not a chain invariant.** Stating this plainly prevents two equal-and-opposite errors: (1) *overclaiming* — implying the chain guarantees a `DAPP_CALL` payload is confidential to / decryptable by the registered DApp (it does not); and (2) *false-alarming* — implying that the chain's *failure* to validate the ciphertext recipient is an integrity hole (it is not — the integrity the chain owns, byte-for-byte authenticity of the submitted payload under A1, is fully provided and is exactly the right scope for a transport layer).

The proof exists because `DAPP_CALL` is the first transaction type whose payload is **simultaneously** (a) cryptographic material produced by a primitive *outside* the chain's trust base (libsodium sealed-box) and (b) carried verbatim through the chain's signature + commitment machinery. Every other payload-bearing tx (`DAPP_REGISTER`, `COMPOSABLE_BATCH`, `PARAM_CHANGE`) is *interpreted* by the apply layer — its bytes drive a state transition the chain validates. The `DAPP_CALL` ciphertext is the opposite: the apply layer reads the framing (topic tag length + ciphertext length) to enforce size/routing caps, then treats the ciphertext as **opaque** and stores nothing of it in chain state (`src/chain/chain.cpp:1118-1123` design comment: "Payload is opaque to chain … the payload sits in the block, indexed by tx_root, consumed off-chain by DApp nodes filtering on tx.to"). The boundary theorem (DI-3) is the novel contribution: it is the application-crypto instance of the general "the chain authenticates and orders bytes; it does not vouch for an off-chain primitive's semantics applied to those bytes." No new cryptographic primitive is introduced; the positive guarantee reduces to **A1** (Ed25519 EUF-CMA) + **A2** (SHA-256 collision resistance), and the negative boundary is an inspection result over the `DAPP_CALL` validator gate (`src/node/validator.cpp:915-980`) and apply branch (`src/chain/chain.cpp:1133-1224`) — neither of which contains any decryption, `service_pubkey`-recipient check, or AEAD verification.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1) — DI-1's payload-byte authenticity reduces to **A1**; DI-2's per-block commitment reduces to **A1** + **A2** (the `tx_root`/`tx_hash` binding); DI-3 (the off-chain boundary) is an inspection result, not a cryptographic reduction; `DAppRegistryLifecycle.md` (FA-Apply-5 — the apply-layer state machine; its T-D6 inactive-gate at `chain.cpp:1142` is the only place the DAPP_CALL apply branch consults the `DAppEntry`, and even there it reads `inactive_from`, never `service_pubkey`; §5 "What this doesn't prove" already records that `service_pubkey` is recorded as opaque 32 bytes with no apply-time validity check — DI-3 is the read-side / message-side complement of that registration-side observation); `S019DAppEndpointSpoof.md` (T-1..T-5 — owner-authenticated registration + the explicit §1.3/§6.4 statement that the chain commits *this* `service_pubkey` but does not vouch that the key is a sound libsodium box key nor that traffic is honestly encrypted; DI-3 composes with S019's T-4 "off-chain service-pubkey use verifiable against on-chain binding" — S019 secures *which key the chain published*; this proof clarifies that the chain does not enforce *that a given DAPP_CALL ciphertext was actually sealed to that key*); `DAppRegistryCommitmentSoundness.md` (DC-4 — DAPP_CALL message **bodies** are `tx_root`-bound per-block, NOT `state_root`-bound; DI-2 is the *signature/authenticity* companion to DC-4's *commitment-coverage* statement — DC-4 says "the payload is committed by `tx_root`, not `state_root`," DI-2 says "the payload is additionally authenticated by the sender's Ed25519 signature," and DI-3 says "neither commitment nor signature speaks to the ciphertext's recipient"); `DAppRegistryReadSoundness.md` (DR-1..DR-6 — the trust-minimized `d:` read that recovers the committed `service_pubkey`; DI-3's off-chain confidentiality property is what a sender obtains *after* a DR read resolves the recipient key — the read gives the key, the sender's own `crypto_box_seal` gives the recipient-binding, and the chain mediates neither); `TxInclusionProofSoundness.md` (the per-tx `tx_root` membership surface DI-2 invokes — a `DAPP_CALL` with a given `tx_hash` is provably included in its block against the committee-signed `tx_root`); `S002-Mempool-Sig-Verify.md` (the mempool-layer Ed25519 verification that makes `tx.from` + the full `signing_bytes` — including the payload — unforgeable at gossip time; foundational for DI-1); `Preliminaries.md` V-predicate (the validator gates DI-3 inspects to confirm no recipient-crypto check exists); `docs/PROTOCOL.md` §14.5 (`DAPP_CALL` wire format + validator constraints + the "opaque to chain" apply rule); `docs/V2-DAPP-DESIGN.md` §10 ("On-chain payload privacy" — the `crypto_box_seal(dapp.service_pubkey, plaintext)` recommended pattern, explicitly an off-chain operator choice: "The chain doesn't care"); `docs/SECURITY.md` §S-007 (the overflow-checked credit leg, the only value-bearing apply effect of DAPP_CALL).

---

## 1. Scope

### 1.1 In scope

The trust boundary around a single `DAPP_CALL` transaction's `payload` field (`Transaction::payload`, `include/determ/chain/block.hpp:212`), specifically the `ciphertext` segment of the canonical payload framing `[topic_len:u8][topic][ciphertext_len:u32 LE][ciphertext]` (`PROTOCOL.md` §14.5; `block.hpp:150-156`). The question: **what does the chain bind, commit, and validate about that ciphertext, and what does it deliberately leave to the off-chain sender↔DApp channel?**

Three theorems plus the central boundary statement:

| Theorem | Property |
|---|---|
| **DI-1** (Sender-signature payload authenticity) | The sender's Ed25519 signature over `Transaction::signing_bytes()` binds `type`, `from`, `to`, `amount`, `fee`, `nonce`, **and the full `payload` bytes** (including the ciphertext). Under **A1**, a daemon / relayer / producer cannot alter any payload byte of an admitted `DAPP_CALL` without invalidating the signature; replay of a verbatim `DAPP_CALL` is barred by the strict-equality nonce gate. The chain guarantees *byte-for-byte integrity of the payload as the sender submitted it*. |
| **DI-2** (Per-block commitment of the payload) | The `DAPP_CALL` transaction — and hence its payload bytes — is committed to the block's `tx_root` and identified by `tx_hash = SHA256(signing_bytes)`. Under **A1** + **A2**, a light client can verify a specific `DAPP_CALL`'s inclusion + payload bytes against the committee-signed `tx_root` (the `TxInclusionProofSoundness.md` surface). The payload is **not** committed to `state_root` (DC-4); the chain stores no payload byte in chain state. |
| **DI-3** (Off-chain recipient-binding boundary — the central statement) | The chain does **not** decrypt the ciphertext, does **not** verify it was sealed to the registered DApp's `service_pubkey`, and does **not** perform any AEAD / sealed-box validation. Validator + apply read only the *framing* (topic length, ciphertext length, size cap, topic-routing membership) and treat the ciphertext as opaque bytes. Confidentiality of the plaintext and the property "only the DApp holding the secret for `service_pubkey` can decrypt" are **end-to-end** between sender and DApp via libsodium `crypto_box_seal`, established **outside** the chain's trust base. This is a correct design boundary (transport vs. payload crypto), not a flaw. |

### 1.2 Out of scope

- The **registration-side** owner-binding of `service_pubkey` (that the chain commits the registrant-authorized `service_pubkey` for a domain, mutable only by the owner's Ed25519 key). That is `S019DAppEndpointSpoof.md` T-1/T-3 and `DAppRegistryLifecycle.md` T-D2/T-D3; DI-3 takes it as given and reasons about the *message* side.
- Whether the registered `service_pubkey` is a cryptographically sound libsodium box key. The apply path records it as opaque 32 bytes with no validity check (`DAppRegistryLifecycle.md` §5; validator enforces only 32-byte length). Out of scope here as there.
- The `state_root`-vs-`tx_root` commitment-coverage split for DAPP_CALL bodies — that is `DAppRegistryCommitmentSoundness.md` DC-4. DI-2 cites its conclusion (payload is `tx_root`-bound, not `state_root`-bound) but does not re-derive the namespace-coverage argument.
- DAPP_CALL **value semantics** (the `tx.amount` debit/credit + S-007 overflow gate at `chain.cpp:1216`) — those are TRANSFER-class effects covered by `AccountStateInvariants.md`; DI reasons about the *payload*, not the value leg.
- Cross-shard DAPP_CALL (rejected at `chain.cpp:1205` / `validator.cpp:929-933`; v2.19 is single-shard) and versioned `service_pubkey` rotation (deferred v2.24, `V2-DAPP-DESIGN.md` §11.7.1).
- The off-chain channel's own properties — `crypto_box_seal` IND-CCA2 / anonymity, transport MITM on a direct sender→endpoint connection, freshness/replay of stale ciphertext post-rotation. These live in the off-chain crypto's own assumptions; DI-3 names the boundary, it does not prove libsodium.

---

## 2. Setup

### 2.1 What `signing_bytes()` binds (read off source)

From `Transaction::signing_bytes()` (`src/chain/block.cpp:17-29`):

```cpp
std::vector<uint8_t> Transaction::signing_bytes() const {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(type));        // tx type discriminator
    out.insert(out.end(), from.begin(), from.end());  // sender domain/address
    out.push_back(0);                                 // NUL separator
    out.insert(out.end(), to.begin(), to.end());      // recipient (DApp domain for DAPP_CALL)
    out.push_back(0);                                 // NUL separator
    for (int i = 7; i >= 0; --i) out.push_back((amount >> (i*8)) & 0xFF);  // u64 be
    for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i*8)) & 0xFF);  // u64 be
    for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i*8)) & 0xFF);  // u64 be
    out.insert(out.end(), payload.begin(), payload.end());                // FULL payload bytes
    return out;
}
```

The decisive line is `out.insert(out.end(), payload.begin(), payload.end())` (`block.cpp:27`): **every byte of the payload — the topic-length prefix, the topic tag, the ciphertext-length prefix, and the ciphertext itself — is part of the message the sender signs.** `tx_hash = compute_hash() = SHA256(signing_bytes())` (`block.cpp:31-34`) therefore also binds the full payload. The sender's signature `tx.sig` is an Ed25519 signature over these `signing_bytes` (verified at the mempool per S-002 and at the validator), so the payload is authenticated under the sender's key.

### 2.2 What the DAPP_CALL validator gate checks (read off source)

From the `TxType::DAPP_CALL` branch of the validator (`src/node/validator.cpp:915-980`), the gate enforces, in order:

1. **Recipient is a registered, currently-active DApp** — `chain.dapp(tx.to)` exists (`validator.cpp:917-921`) and `d_opt->inactive_from > b.index` (`validator.cpp:924-927`). This reads `inactive_from` from the `DAppEntry`; it does **not** read `service_pubkey`.
2. **Single-shard** — `!chain.is_cross_shard(tx.to)` (`validator.cpp:929-933`).
3. **Framing well-formed** — payload ≥ 5 bytes (`validator.cpp:935-938`); `topic_len ≤ MAX_DAPP_TOPIC_LEN` (`validator.cpp:940-943`); topic bytes fit (`validator.cpp:944-947`).
4. **Topic routing** — `topic == ""` OR `topic ∈ DApp.topics` (`validator.cpp:948-960`).
5. **Ciphertext length sanity** — decode `ct_len` (LE u32, `validator.cpp:961-966`); `ct_len ≤ MAX_DAPP_CALL_PAYLOAD` (`validator.cpp:967-971`); `p + ct_len == payload.size()` exact-fit (`validator.cpp:972-980`).

**Crucially, the gate never inspects the ciphertext content.** It reads `ct_len` only to bound-check and confirm the framing closes exactly; the `ciphertext` bytes themselves are never decrypted, never matched against `service_pubkey`, never AEAD-verified. The `DAppEntry.service_pubkey` field is **not referenced anywhere in the validator's DAPP_CALL branch.**

### 2.3 What the DAPP_CALL apply branch does (read off source)

From the `TxType::DAPP_CALL` apply branch (`src/chain/chain.cpp:1133-1224`):

- Looks up `dapp_registry_.find(tx.to)`; missing ⇒ fee-charge + nonce-bump + skip (`chain.cpp:1135-1140`).
- Reads `dapp.inactive_from` for the inactive-gate (`chain.cpp:1141-1146`) — **the only `DAppEntry` field read**.
- Decodes `topic` and validates topic membership (`chain.cpp:1147-1176`) — same routing-tag check as the validator.
- Decodes `ct_len` and bound-checks framing (`chain.cpp:1177-1200`) — **never decrypts**.
- Rejects cross-shard (`chain.cpp:1201-1209`).
- Applies the value leg: debit `tx.amount + tx.fee` from sender, credit `tx.amount` to `accounts_[tx.to]` with the S-007 overflow guard, accumulate `total_fees += tx.fee`, bump nonce (`chain.cpp:1210-1223`).

The design comment at `chain.cpp:1118-1123` states the contract verbatim: *"Payload is opaque to chain. … the payload sits in the block, indexed by tx_root, consumed off-chain by DApp nodes filtering on tx.to."* No write to `dapp_registry_`, no storage of any payload byte in chain state, and — the load-bearing absence for DI-3 — **no call to any decryption, sealed-box-open, or `service_pubkey`-recipient routine.** The apply branch references `dapp.topics` and `dapp.inactive_from`; it never references `dapp.service_pubkey`.

### 2.4 The off-chain sealing the chain does not perform (read off design)

`V2-DAPP-DESIGN.md` §10 ("On-chain payload privacy") fixes the recommended off-chain pattern: the sender encrypts with `crypto_box_seal(dapp.service_pubkey, plaintext)` (libsodium sealed-box: ephemeral key, ChaCha20-Poly1305, anonymous sender), so "Only the DApp can decrypt" and "Chain validators, gossip relayers, other users see ciphertext only." The same section is explicit that this is the *sender's* choice, not a chain rule: *"For unencrypted messages (public DApps …), plaintext is fine. The chain doesn't care."* (`V2-DAPP-DESIGN.md:362-367`). The recipient resolves `service_pubkey` from the on-chain registry (the `dapp_info` RPC, or the trust-minimized `d:` read of `DAppRegistryReadSoundness.md`), then encrypts; the chain mediates **neither** the encryption **nor** any check that it occurred.

---

## 3. Theorems

### DI-1 — Sender-signature payload authenticity (the chain binds the payload bytes as submitted)

**Statement.** For any `DAPP_CALL` transaction `tx` admitted to a finalized block, the sender's Ed25519 signature `tx.sig` verifies under `pubkey_of(tx.from)` over `signing_bytes(tx)`, which includes the full `tx.payload` (§2.1). Consequently, under **A1** (Ed25519 EUF-CMA): (i) no party other than the holder of `sk_{tx.from}` could have produced an admitted `DAPP_CALL` with these exact payload bytes attributed to `tx.from`; (ii) no daemon, relayer, gossip peer, or block producer can mutate any payload byte (topic tag, length prefixes, or ciphertext) of an admitted `DAPP_CALL` without invalidating `tx.sig`, except with advantage negligible in the security parameter; (iii) verbatim replay of an already-applied `DAPP_CALL` is barred by the strict-equality nonce gate. The chain therefore guarantees **byte-for-byte integrity of the payload as the sender submitted it.**

*Proof.* (i)+(ii) The payload is part of `signing_bytes` (`block.cpp:27`), and the mempool admits a tx only after Ed25519-verifying `tx.sig` against `pubkey_of(tx.from)` over `signing_bytes(tx)` (S-002, `S002-Mempool-Sig-Verify.md`); the validator re-applies the same gate before inclusion. Any altered payload byte changes `signing_bytes`, so a signature valid for the original is invalid for the altered message; producing a fresh valid signature over the altered message without `sk_{tx.from}` is an Ed25519 forgery, bounded by the EUF-CMA advantage (**A1**), negligible against a polynomial adversary. (iii) The apply branch bumps `sender.next_nonce` on every reached terminal (`chain.cpp:1138,1144,1153,1160,1173,1183,1193,1198,1207,1222`), and the nonce gate admits a tx only at `tx.nonce == accounts_[from].next_nonce` (the I-2 strict-equality gate of `AccountStateInvariants.md`, applied uniformly to DAPP_CALL); a replayed verbatim tx carries a now-stale nonce and is skipped. ∎

**Code witness.** `src/chain/block.cpp:17-29` (`signing_bytes` includes the full payload — line 27); `src/chain/block.cpp:31-34` (`tx_hash = SHA256(signing_bytes)`); the mempool S-002 sig-verify (`S002-Mempool-Sig-Verify.md`); the nonce-gate increments throughout the DAPP_CALL apply branch (`src/chain/chain.cpp:1133-1224`).

**Cross-reference.** The general per-tx signature-binding is `Preliminaries.md` A1; DI-1 specializes it to the observation that the *opaque ciphertext* enjoys the same byte-integrity as the value-bearing fields, because `signing_bytes` makes no distinction between interpreted and opaque payload bytes.

### DI-2 — Per-block commitment of the payload (`tx_root`-bound, identified by `tx_hash`)

**Statement.** The admitted `DAPP_CALL`'s payload bytes are committed to the enclosing block's `tx_root` and identified by `tx_hash = SHA256(signing_bytes(tx))`. Under **A1** + **A2**, a light client can verify that a specific `DAPP_CALL` (with its exact payload, given `tx_hash`) was genuinely included in block `h` against block `h`'s committee-signed `tx_root` (the `TxInclusionProofSoundness.md` surface). The payload is **not** committed to `state_root` and the chain stores no payload byte in chain state.

*Proof.* The block body carries the ordered transaction list, including every `DAPP_CALL`, and `tx_root` is the Merkle root over that list (`block.hpp` body layout; `PROTOCOL.md` §4); `tx_root` sits in the block's signing bytes and is covered by the committee signature set (the standard header binding, `StateRootAnchorSoundness.md`'s `tx_root` analogue). Given `(h, tx_hash)`, a verifier confirms inclusion against the committee-signed `tx_root` via a Merkle inclusion proof (`TxInclusionProofSoundness.md`); since `tx_hash` binds the full transaction including payload under **A2** (DI-1), the verified inclusion is of *exactly* the submitted payload bytes. The non-`state_root` direction is `DAppRegistryCommitmentSoundness.md` DC-4(1) by inspection of `build_state_leaves` (`chain.cpp:284-410`): no `state_root` namespace reads a transaction payload, and the DAPP_CALL apply branch writes no payload byte to chain state (§2.3). ∎

**Code witness.** `src/chain/block.cpp:31-34` (`tx_hash`); `src/chain/chain.cpp:1133-1224` (apply stores no payload byte); `src/chain/chain.cpp:1118-1123` (design comment: payload "indexed by tx_root, consumed off-chain"); `DAppRegistryCommitmentSoundness.md` DC-4 (the `tx_root`-not-`state_root` coverage).

**Cross-reference.** DI-2 is the *authenticity/inclusion* companion to DC-4's *commitment-coverage* statement: DC-4 establishes which root commits the payload (per-block `tx_root`, not `state_root`); DI-2 establishes that a verifier can soundly check that commitment per-tx and that the payload it commits is exactly the signed bytes (DI-1).

### DI-3 — Off-chain recipient-binding boundary (the chain does not validate ciphertext sealing — by design)

**Statement.** The chain does **not** decrypt a `DAPP_CALL` ciphertext, does **not** verify the ciphertext was sealed to the registered DApp's `service_pubkey`, and performs **no** AEAD / sealed-box validation of the payload. The validator (`validator.cpp:915-980`) and apply branch (`chain.cpp:1133-1224`) read only the payload *framing* (topic-tag length + bytes for routing, ciphertext length for size/exact-fit bounds) and the `DAppEntry` fields `topics` + `inactive_from`; **neither references `DAppEntry.service_pubkey`.** Therefore:

1. **Confidentiality is not a chain invariant.** The chain does not ensure the payload is encrypted at all (a sender may submit plaintext — `V2-DAPP-DESIGN.md:362-367` "The chain doesn't care"), nor that any encryption present targets the registered DApp. Validators, gossip relayers, and other observers see whatever the sender put in the ciphertext field.
2. **Recipient-binding is end-to-end, established off-chain.** "Only the DApp holding the secret for `service_pubkey` can decrypt" follows **solely** from the sender having run `crypto_box_seal(service_pubkey, plaintext)` with the *correct* `service_pubkey` (resolved from the registry) and from libsodium sealed-box semantics — a property of the sender's off-chain action + the off-chain primitive, **not** of any chain check.
3. **A daemon cannot forge the sender's signature (A1, DI-1), but the chain neither needs nor performs ciphertext-recipient validation.** The integrity the chain owns — that the payload bytes are exactly what the signing sender submitted, authenticated under the sender's key and committed per-block — is fully provided (DI-1 + DI-2). The recipient-binding the chain does *not* perform is correctly delegated to the end-to-end channel.

*Proof.* By exhaustive inspection of the two surfaces. **Validator** (`validator.cpp:915-980`): the branch's only `DAppEntry` reads are `d_opt->inactive_from` (`validator.cpp:924`) and the topic-membership loop over `d_opt->topics` (`validator.cpp:948-960`); `service_pubkey` does not appear; `ct_len` is consumed only for the `≤ MAX_DAPP_CALL_PAYLOAD` cap (`validator.cpp:967`) and the exact-fit check (`validator.cpp:972`); the `ciphertext` bytes are never read into any cryptographic routine. **Apply** (`chain.cpp:1133-1224`): the only `DAppEntry` reads are `dapp.inactive_from` (`chain.cpp:1142`) and `dapp.topics` (`chain.cpp:1168`); `service_pubkey` does not appear; the ciphertext bytes drive only the framing bound-checks (`chain.cpp:1177-1200`); the value leg (`chain.cpp:1210-1223`) is a TRANSFER-style debit/credit on `tx.amount`, independent of payload content. There is **no** call site, in either surface, to a decrypt / sealed-box-open / AEAD-verify / `service_pubkey`-match routine. Hence claims (1)–(3) hold by construction: the chain validates framing + routing + value, and treats the ciphertext as opaque transport bytes.

For claim (2)'s positive direction (the recipient-binding the sender *does* obtain), the locus is entirely off-chain: the sender resolves `service_pubkey` for `tx.to` (via `dapp_info` or the trust-minimized `d:` read, `DAppRegistryReadSoundness.md` DR-2 — which under A1+A2 recovers the *committee-committed* `service_pubkey`, defeating a daemon that substitutes a different key, per `S019DAppEndpointSpoof.md` T-4), then runs `crypto_box_seal` against it. The chain's contribution to the end-to-end property is **only** the owner-authenticated publication of the correct `service_pubkey` (S019 T-1/T-3) and the byte-integrity of the resulting ciphertext in transit (DI-1/DI-2). The sealing itself, and the guarantee that only `sk_{service_pubkey}` decrypts, are libsodium's, outside the chain's trust base. ∎

**Why this is a correct boundary, not a flaw.** A transport + ordering + integrity layer's job is to deliver the sender's bytes, unaltered and in committed order, with authenticated provenance. The chain does exactly that (DI-1 + DI-2). Requiring the chain to validate that a ciphertext was sealed to the registered key would (a) be impossible without the plaintext or a zero-knowledge proof of correct sealing (the chain has neither), (b) gain nothing — a sender who mis-seals harms only themselves (their own message becomes undecryptable by the DApp), not the chain's integrity or other users, and (c) conflate the transport layer with payload semantics it is deliberately agnostic to (so the *same* framing carries plaintext public-bulletin-board messages and sealed-box confidential ones — `V2-DAPP-DESIGN.md:362-367`). The end-to-end principle places confidentiality + recipient-binding at the endpoints (sender + DApp), where the plaintext and the secret key live; the chain provides the authenticated, ordered, committed pipe between them. **No chain invariant claims ciphertext recipient-correctness; none is violated by its absence.**

**Code witness.** `src/node/validator.cpp:915-980` (DAPP_CALL gate — reads `inactive_from` + `topics`, never `service_pubkey`, never decrypts); `src/chain/chain.cpp:1133-1224` (apply — reads `inactive_from` + `topics`, never `service_pubkey`, never decrypts; ciphertext drives only framing bounds); `src/chain/chain.cpp:1118-1123` (the "opaque to chain" design contract); `docs/V2-DAPP-DESIGN.md:358-367` (off-chain `crypto_box_seal` pattern + "The chain doesn't care").

**Cross-reference.** DI-3 is the message-side complement of `DAppRegistryLifecycle.md` §5's registration-side note (the chain records `service_pubkey` as opaque 32 bytes with no validity check). It composes with `S019DAppEndpointSpoof.md` T-4: S019 secures *which* key the chain publishes (owner-authenticated, recoverable trustlessly); DI-3 clarifies the chain does not enforce *that a given DAPP_CALL was sealed to that key* — the sealing is the sender's off-chain responsibility against the (S019-secured) published key.

---

## 4. Adversary table

| Adversary | Capability | Defended? | Where the guarantee lives |
|---|---|---|---|
| `A_payload_mutate` | A daemon / relayer / producer alters any payload byte (topic, length prefix, or ciphertext) of an admitted DAPP_CALL | **Yes** — DI-1: any mutation invalidates `tx.sig` under **A1** | chain (signature over full payload, `block.cpp:27`) |
| `A_payload_forge` | Attribute a fabricated DAPP_CALL payload to another sender `tx.from` | **Yes** — DI-1: requires Ed25519 forgery on `sk_{tx.from}` (**A1**) | chain (S-002 mempool sig-verify) |
| `A_payload_replay` | Re-submit a verbatim already-applied DAPP_CALL | **Yes** — DI-1(iii): strict-equality nonce gate (I-2) | chain (nonce gate, apply branch) |
| `A_inclusion_lie` | Claim a DAPP_CALL (with some payload) was in block `h` when it was not | **Yes** — DI-2: `tx_root` inclusion proof under **A1**+**A2** | chain (committee-signed `tx_root`, `TxInclusionProofSoundness.md`) |
| `A_mis_seal` | Sender seals the ciphertext to the **wrong** key (not the registered `service_pubkey`) | **Not a chain concern** — DI-3: the chain does not validate sealing; the mis-sealed message is simply undecryptable by the DApp. Harms only the sender; no chain invariant broken. | off-chain sender (correct `service_pubkey` resolution + `crypto_box_seal`) |
| `A_plaintext_leak` | Sender submits plaintext (no encryption); observers read it | **Not a chain concern** — DI-3(1): confidentiality is the sender's off-chain choice (`V2-DAPP-DESIGN.md:362-367`) | off-chain sender (choice to encrypt) |
| `A_key_substitute` | Daemon serves a *different* `service_pubkey` for the domain so the sender seals to the attacker's key | **Yes, but by a different proof** — `S019DAppEndpointSpoof.md` T-4 + `DAppRegistryReadSoundness.md` DR-2: the *committee-committed* key is recoverable trustlessly. DI-3 assumes the sender resolved the correct key; key-substitution defense is S019/DR, not this proof. | chain (owner-authenticated `d:` registry leaf) — separate surface |
| `A_decrypt_observe` | A committee operator / observer decrypts a *correctly* sealed ciphertext | **No (and correctly so)** — sealed-box confidentiality is libsodium's, end-to-end; the chain never had the plaintext. Breaking it is breaking `crypto_box_seal`, outside the chain's scope. | off-chain primitive (libsodium sealed-box) |

The load-bearing rows are `A_mis_seal`, `A_plaintext_leak`, and `A_decrypt_observe`: they are the **honest negative results** — the chain neither claims nor enforces ciphertext-recipient-correctness or confidentiality, and that absence is by design, with the real guarantees living end-to-end. The `A_payload_*` and `A_inclusion_lie` rows are the **positive results** — the integrity the chain genuinely provides for the payload bytes as transport.

---

## 5. Relationship to sibling proofs

- **vs. `DAppRegistryCommitmentSoundness.md` (DC-4):** DC-4 establishes the *commitment-coverage* boundary (DAPP_CALL bodies are `tx_root`-bound, not `state_root`-bound). DI-2 is the *authenticity/inclusion* companion (the same bodies are signature-bound by the sender and soundly inclusion-checkable). DI-3 adds the *payload-crypto* boundary that neither DC-4 nor DI-1/DI-2 touch — commitment + signature speak to the bytes' integrity and ordering, never to the ciphertext's recipient.
- **vs. `S019DAppEndpointSpoof.md` (T-1..T-5):** S019 secures the *registration* of `service_pubkey` (owner-authenticated, mutable only by the owner's Ed25519 key) and T-4 secures *resolution* (the published key is recoverable trustlessly). DI-3 is downstream: given the correct key is published and resolved, the chain does not enforce that any individual DAPP_CALL ciphertext was sealed to it — that final step is the sender's off-chain `crypto_box_seal`. S019 + DR give "the chain committed *this* key"; DI-3 gives "the chain does not police whether the message used it."
- **vs. `DAppRegistryReadSoundness.md` (DR-2):** DR-2 is the trust-minimized recovery of the committed `service_pubkey` a sender needs *before* sealing. DI-3's off-chain confidentiality is what the sender obtains *after* DR-2 hands them the key — the read gives the key, the sender's own primitive gives the recipient-binding, the chain mediates neither the encryption nor a check of it.
- **vs. `DAppRegistryLifecycle.md` (FA-Apply-5):** that proof's §5 records the registration-side fact that `service_pubkey` is opaque-to-apply; DI-3 is the symmetric message-side fact (the ciphertext is opaque-to-apply, and the apply branch reads `inactive_from` + `topics` only). The two together show the chain handles `service_pubkey` purely as published data and the ciphertext purely as committed transport bytes.
- **vs. `TxInclusionProofSoundness.md`:** DI-2 invokes it directly as the per-tx `tx_root` membership surface that lets a verifier check a specific DAPP_CALL's payload bytes against the committee-signed root.

---

## 6. Empirical anchors

The integrity claims (DI-1, DI-2) are exercised by existing regressions; the boundary claim (DI-3) is an absence-of-code result and is, by construction, not falsifiable by a passing test (no decrypt/recipient-check path exists to exercise):

- `tools/test_tx_signing_bytes.sh` + `tools/test_tx_signing_determinism.sh` — pin that `signing_bytes` (including the full payload) is the signed/hashed message and is deterministic, underwriting DI-1's payload-byte binding.
- `tools/test_dapp_call.sh` — exercises the DAPP_CALL active-DApp success path (framing accepted, value leg applied, nonce bumped) and the inactive-gate / unknown-topic / framing-overrun reject paths; every reject path treats the ciphertext as opaque, never decrypting it (DI-3 by execution trace).
- `tools/test_dapp_e2e.sh` — end-to-end 3-node gossip-driven DAPP_CALL flow including off-chain `service_pubkey` resolution → payload encryption → submission → inclusion; the chain leg never decrypts (DI-3), the off-chain leg performs the sealing (the boundary in action).
- `tools/test_wallet_tx_tamper_fuzz.sh` + `tools/test_wallet_tx_hash_cross_command_fuzz.sh` — fuzz that altering any tx byte (including payload bytes) breaks signature/hash verification, underwriting DI-1(ii).
- `tools/test_light_verify_tx_inclusion.sh` (via the `verify-tx-inclusion` light subcommand) — exercises the `tx_root` inclusion-proof pipeline DI-2 composes onto.

DI-3's central negative — "no chain surface decrypts or validates the ciphertext's recipient" — is established by inspection of `validator.cpp:915-980` and `chain.cpp:1133-1224` (neither references `DAppEntry.service_pubkey` nor any decryption routine), not by a test, exactly as `DAppRegistryCommitmentSoundness.md` DC-4(3)'s non-completeness result is established by the absence of a payload-reading namespace rather than by execution.

---

## 7. Status

All three statements are closed in the current codebase:

- **DI-1** (sender-signature payload authenticity) closed via `signing_bytes` including the full payload (`block.cpp:27`) + the mempool/validator Ed25519 gate (A1) + the strict-equality nonce gate; the opaque ciphertext inherits the same byte-integrity as the value-bearing fields.
- **DI-2** (per-block payload commitment) closed via `tx_hash`/`tx_root` binding + the `TxInclusionProofSoundness.md` surface (A1 + A2); the payload is `tx_root`-bound, not `state_root`-bound (DC-4), and no payload byte is stored in chain state.
- **DI-3** (off-chain recipient-binding boundary) closed *structurally* — by inspection, neither the DAPP_CALL validator gate nor the apply branch decrypts the ciphertext or references `DAppEntry.service_pubkey`; confidentiality + recipient-binding are end-to-end via libsodium `crypto_box_seal`, outside the chain's trust base. This is a correct transport-vs-payload-crypto design boundary, **not** a vulnerability: the chain provides exactly the integrity (authenticated, ordered, committed bytes) a transport layer owns, and correctly delegates the payload-semantics (was this sealed to the right key?) to the endpoints that hold the plaintext and the secret.

No statement is open or partial. The proof introduces no new primitive: DI-1/DI-2 reduce to **A1** + **A2** already assumed across the proof corpus, and DI-3 is an inspection result. The single most important reader takeaway, stated to prevent both overclaiming and false-alarming: **a Determ daemon cannot forge a sender's DAPP_CALL signature or silently mutate the payload (A1, DI-1), and a light client can prove a DAPP_CALL's payload was genuinely included in a committee-signed block (DI-2) — but the chain does not, and need not, decrypt the ciphertext or verify it was sealed to the registered DApp's `service_pubkey`; that recipient-binding is an end-to-end property the sender establishes off-chain against the (S019-secured, DR-recoverable) published key.**
