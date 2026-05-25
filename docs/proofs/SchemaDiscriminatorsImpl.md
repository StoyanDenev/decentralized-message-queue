# Schema discriminators — v1.0 implementation specification

**Status:** specification only. No code. Implementation-side companion to `Improvements.md §7.5` (the SHIP-or-skip decision for the seven v1.0 schema discriminators) and `Improvements.md §7.6` (the coherence verification against existing review-week decisions). This document is the IMPLEMENTATION spec: what does the validator do at parse time, encode time, address-derive time, sig-verify time? It is NOT a re-decision — every "ship" / "default value" / "enum-space" judgment has already been resolved in `Improvements.md §7.5` + §7.6 + `DECISION-LOG.md` 2026-05-24 entries.

**Companion documents.**
- `Improvements.md` §7.5 — the decision artifact: SHIP all seven discriminators in v1.0; per-discriminator unlock-target table; cost-tier classification.
- `Improvements.md` §7.6 — discriminator-coherence verification against v2.10 FROST, PRIV-4 audit, PRIV-6 confidential_policy, v2.6 gossip-out-of-lock.
- `DECISION-LOG.md` 2026-05-24 §"Improvements.md §7.5 (pre-v1.0-schema-freeze optionality)" + §"Improvements.md §7.6 (discriminator-coherence verification)" + §"Improvements.md §7.5 completion (7.5.6 + 7.5.7)" — auditable narrative.
- `IMPLEMENTATION-SEQUENCING.md` §2.3 (pre-bundle discriminators table) + Bundle 3 / Bundle 5 entries — sequencing-side artifact: these discriminators land BEFORE any review-week bundle to lock the v1.0 genesis schema shape.
- `WireFormatBackwardCompat.md` — unified zero-skip backward-compat theorem (T-1..T-3); the §7.5 discriminators compose with that contract by adopting the same fail-closed-on-unknown-value posture.
- `MAINNET_READINESS.md` — readiness criteria; this implementation work feeds the "pre-bundle schema discriminators landed" checklist item.

**Audience.** Implementation threads landing the seven discriminator fields; reviewers asking "does the validator dispatch logic match the SHIP decision?"; future planning sessions evaluating whether a post-v1.0 enhancement is still reachable via the discriminator mechanism.

---

## 1. Scope and references

### 1.1 What this document specifies

For each of the seven §7.5 discriminators:

- **Wire-format encoding** — field position, byte representation, optional-companion-field presence rules.
- **Validator dispatch rules** — accepted vs rejected enum values at v1.0, fail-closed unknown-value handling, log diagnostics.
- **Address derivation discriminator inclusion** (§7.5.7 / §7.6.7 only) — the `pubkey_form` byte enters the address-derivation preimage to prevent post-PQ address collision.
- **Sig_form ↔ pubkey_form curve-family consistency invariant** (§7.5.6 + §7.5.7 jointly) — `SIG_ED25519` signatures verify only against `PUBKEY_ED25519` pubkeys; cross-form combinations are hard rejects.
- **Per-record byte-cost summary** — aggregate v1.0 schema cost matching `Improvements.md §7.6` final tally.
- **Test coverage requirements** — what regression tests must exist before "shipped" claim is defensible.

### 1.2 What this document does NOT specify

- **Re-decision** of any §7.5 SHIP / skip judgment. Those are resolved in `Improvements.md §7.5` + `DECISION-LOG.md` 2026-05-24 entries.
- **Implementation of unused enum slots** (e.g., `SIG_BLS12_381_AGGREGATE`, `PUBKEY_DILITHIUM`). v1.0 ships the discriminator slots and the default value's decode path; the additional enum-value codepaths are post-v1.0 work (each gated on its own primitive maturation per `Improvements.md §7.3` revisit-triggers).
- **Variable-length encoding for non-pubkey fields.** Only `pubkey_form` (§7.5.7) introduces variable-length pubkey wire format. The other six discriminators are single u8 enum bytes plus (for `view_key_mechanism` and `audit_model`) one optional fixed-size companion field.
- **Schema-version envelope field outside these seven.** Verified absent in v1.0 PROTOCOL.md §4 (see §9.2 below). These seven discriminators ARE the future-proofing mechanism; no separate version envelope.

### 1.3 Cross-references

Each discriminator's enum space and default value is fixed in `Improvements.md §7.5` table (rows 7.5.1 through 7.5.7) and §7.6.1 through §7.6.7 (coherence resolutions). This document treats those as immutable inputs; the implementation guidance below derives from them without re-litigating.

---

## 2. Wire-format encoding

This section specifies the byte-level encoding for each discriminator. The v1.0 wire format uses the existing Determ binary codec (length-prefixed varints + raw bytes; see `WireFormatBackwardCompat.md` for the codec contract). Discriminator bytes are inserted at field-ordering positions within their parent records, before any field whose decode path depends on the discriminator.

### 2.1 Encoding conventions used throughout

- **Enum bytes are u8.** Single-byte encoding; 256-value enum space; reserved 0xFF for forward-compat fail-closed reject. No multi-byte enum encodings.
- **Optional companion fields** (`fs_view_pk`, `trusted_issuer_pubkey`): presence-by-discriminator-value. When the discriminator is at its v1.0 default (`OTPK_STREAM` / `KEY_DISCLOSURE` respectively), the companion field is OMITTED from the encoding entirely. When the discriminator is set to a non-default value that requires the companion (e.g., a future `TRUSTED_ISSUER` audit model), the companion field MUST be present.
- **Length tags.** Companion pubkey fields encode as `pubkey_form: u8 || body_len: u16 || body: bytes` per §7.5.7 (i.e., they are full PubKey records, not raw 32-byte arrays). The `body_len` is present-but-elidable in known-form encodings; v1.0 encoders MAY elide it for `PUBKEY_ED25519` (body_len implicit at 32) to preserve byte-identical compatibility with the pre-discriminator codec, OR emit it explicitly for forward-compat uniformity. Implementations should pick one convention and stick to it. **Recommended: emit `body_len` explicitly** — the 2-byte cost per pubkey is trivial relative to the readability win at decode time, and post-v1.0 forms (Dilithium 1952B, BLS 96B) require it anyway.
- **Reserved value 0xFF.** Every discriminator reserves 0xFF as a fail-closed marker. v1.0 validators MUST reject 0xFF on every discriminator (no special case for 0xFF beyond "unknown value"). The reservation exists so future enum spaces can ship explicit "future-incompatible" markers without consuming a real enum slot.

### 2.2 7.5.1 `Block.signature_form`

**Field position.** Block header, immediately before `creator_block_sigs[]` (the K-of-K Phase-2 signature array). Logically, the discriminator gates how `creator_block_sigs[]` is decoded.

**Wire encoding.**

```
signature_form:    u8     // enum (default SIG_KK_ED25519 = 0)
creator_block_sigs:  ...  // decoded per signature_form
```

**v1.0 default.** `SIG_KK_ED25519 = 0`. Encoding of `creator_block_sigs[]` is the existing K × 64-byte Ed25519 sig array (status quo).

**Reserved values:** `SIG_BLS12_381_AGGREGATE = 1`, `SIG_DILITHIUM_KK = 2`, `0xFF` (forward-compat reject).

**Block.signing_bytes() inclusion.** The `signature_form` byte MUST be in `signing_bytes()` immediately before `creator_block_sigs[]` (per the §4.1 ordering convention in PROTOCOL.md). Including the discriminator in `signing_bytes()` prevents a malicious proposer from constructing a block whose stored discriminator says one thing but whose computed hash binds the same digest as a different discriminator's encoding. With the discriminator bound into `signing_bytes()`, two blocks that differ in `signature_form` but agree on every other field have distinct block hashes — a defense-in-depth property that composes with the dispatch-on-decode rule.

**Backward-compat shim.** Pre-§7.5 blocks have no `signature_form` byte and are interpreted as `SIG_KK_ED25519`. Per the `WireFormatBackwardCompat.md` zero-skip pattern: at any block height where the discriminator could legally be absent (e.g., pre-v1.0 historical blocks at hypothetical schema-version-N+1 readers), validators short-circuit decode to `SIG_KK_ED25519` and produce byte-identical `signing_bytes()` to the pre-§7.5 encoding. **v1.0 emits the byte unconditionally** — the backward-compat shim is for future hypothetical pre-v1.0 historical-replay scenarios, not for v1.0 mainnet itself, where every block carries the discriminator.

### 2.3 7.5.2 `Account.view_key_mechanism` + optional `Account.fs_view_pk`

**Field position.** Account state record, in the v2.22 PRIV-6 confidential_policy / view-key field group. Order: `confidential_policy: u8 || view_key_mechanism: u8 || fs_view_pk: PubKey?`.

**Wire encoding.**

```
confidential_policy:  u8       // PRIV-6 (already shipped via v2.22 design; not part of §7.5)
view_key_mechanism:    u8      // §7.5.2; default OTPK_STREAM = 0
fs_view_pk:            PubKey? // OPTIONAL; present iff view_key_mechanism != OTPK_STREAM
```

**v1.0 default.** `OTPK_STREAM = 0`. `fs_view_pk` is OMITTED entirely (zero bytes on the wire — not a 0-length entry, fully absent).

**Reserved values:** `FSE = 1`, `PUNCTURABLE = 2`, `0xFF` (forward-compat reject).

**Optional companion field presence rule:** `fs_view_pk` is present iff `view_key_mechanism ∈ {FSE, PUNCTURABLE}` (i.e., the long-lived-master pattern). For `view_key_mechanism == OTPK_STREAM`, the field is absent; the OTPK-stream mechanism uses periodic published OTPK batches per PRIV-6, not a long-lived master pubkey on Account.

**Encoding of `fs_view_pk` when present.** Encoded as a full PubKey record per §7.5.7: `pubkey_form: u8 || body_len: u16 || body: bytes`. For the only currently-implementable case (Ed25519 hypothetical FSE), body would be 32 bytes; for hypothetical lattice-based FSE, the body length tracks the chosen lattice parameter set. The `body_len` is non-elidable for FSE because no v1.0 form is implemented.

**Backward-compat shim.** Pre-§7.5 Account records are interpreted as `view_key_mechanism = OTPK_STREAM` with no `fs_view_pk`. Byte-identical to the pre-§7.5 Account encoding except for the explicit `view_key_mechanism = 0` byte.

### 2.4 7.5.3 `Account.audit_model` + optional `Account.trusted_issuer_pubkey`

**Field position.** Account state record, in the PRIV-4 audit-disclosure field group. Order: `view_master_pk: PubKey || audit_model: u8 || trusted_issuer_pubkey: PubKey?`.

**Wire encoding.**

```
view_master_pk:        PubKey       // PRIV-4 (already shipped via v2.22 design; not part of §7.5)
audit_model:           u8           // §7.5.3; default KEY_DISCLOSURE = 0
trusted_issuer_pubkey: PubKey?      // OPTIONAL; present iff audit_model == TRUSTED_ISSUER
```

**v1.0 default.** `KEY_DISCLOSURE = 0`. `trusted_issuer_pubkey` is OMITTED entirely.

**Reserved values:** `TRUSTED_ISSUER = 1`, `ZK_BASED_AUDIT = 2`, `NO_AUDIT = 3`, `0xFF` (forward-compat reject).

**Optional companion field presence rule:** `trusted_issuer_pubkey` is present iff `audit_model == TRUSTED_ISSUER`. For every other value (including the v1.0 default `KEY_DISCLOSURE`, and the reserved `ZK_BASED_AUDIT` / `NO_AUDIT`), the field is absent.

**Encoding of `trusted_issuer_pubkey` when present.** Same as `fs_view_pk` above — full PubKey record per §7.5.7. The trusted-issuer mechanism (§1.8 in `Improvements.md`) is principle-rejected at the implementation level for v1.0; the discriminator slot exists but no v1.0 code path constructs a TRUSTED_ISSUER account, so the encoding case is purely structural / forward-compat.

**Backward-compat shim.** Pre-§7.5 Account records are interpreted as `audit_model = KEY_DISCLOSURE` with no `trusted_issuer_pubkey`. Byte-identical to the pre-§7.5 Account encoding except for the explicit `audit_model = 0` byte.

### 2.5 7.5.4 `manifest.randomness_aggregation_form`

**Field position.** Beaconless v2 deployment manifest, in the cross-shard randomness section. Order: `merritt_k: u32 || randomness_aggregation_form: u8 || ...other-randomness-section-fields...`.

**Wire encoding.**

```
merritt_k:                  u32   // BL-5 (already shipped per Beaconless-v2-SPEC.md §Q2)
randomness_aggregation_form: u8   // §7.5.4; default THRESHOLD_SIG_ACCUMULATOR = 0
```

**v1.0 default.** `THRESHOLD_SIG_ACCUMULATOR = 0`. Manifest's downstream randomness-aggregation logic dispatches on this byte at manifest-validation time (per Q2.1 hard-invariant pattern; see `Beaconless-v2-SPEC.md §Q2.1`).

**Reserved values:** `VRF_PER_SHARD = 1`, `0xFF` (forward-compat reject).

**Manifest-pinning rationale.** Unlike the per-record discriminators (block / Account / ContribMsg / tx), `randomness_aggregation_form` is manifest-pinned — deployment-wide. Cross-shard randomness MUST agree on aggregation across all shards in the deployment; per-shard variation would break the cross-shard randomness invariant (see `Improvements.md §7.6.5` for the asymmetry rationale). Validator enforces manifest-pinning at manifest-validation time: `validate_manifest()` rejects any manifest whose `randomness_aggregation_form` is unknown OR mismatched against the deployment's claimed mode.

**Backward-compat shim.** Pre-§7.5 manifests are interpreted as `THRESHOLD_SIG_ACCUMULATOR`. Byte-identical to the pre-§7.5 manifest encoding except for the explicit `randomness_aggregation_form = 0` byte.

### 2.6 7.5.5 `ContribMsg.contrib_msg_form`

**Field position.** Phase-1 ContribMsg, FIRST field after the header / signer / generation prefix (so the discriminator gates body-decode). Order: `signer: PubKey || gen: u32 || block_index: u64 || prev_hash: Hash || aborts_gen: u32 || contrib_msg_form: u8 || body: bytes`.

**Wire encoding.**

```
signer:           PubKey   // already-present
gen:              u32      // already-present
block_index:      u64      // already-present
prev_hash:        Hash     // already-present
aborts_gen:       u32      // already-present
contrib_msg_form: u8       // §7.5.5; default TX_HASH_ARRAY = 0
body:             bytes    // decoded per contrib_msg_form
```

For `TX_HASH_ARRAY` (v1.0 default), `body` is the existing length-prefixed array of `Hash`. For hypothetical future `IBLT_PAYLOAD` (= 1), `body` would be the IBLT sketch — distinct decoder per `Improvements.md §6.4`.

**v1.0 default.** `TX_HASH_ARRAY = 0`. Body is the existing tx-hash array.

**Reserved values:** `IBLT_PAYLOAD = 1`, `MINISKETCH_PAYLOAD = 2`, `0xFF` (forward-compat reject).

**Body inclusion in ContribMsg signing bytes.** Per Determ ContribMsg signing-bytes contract (see `MakeContribCommitmentBackwardCompat.md` for the canonical pre-image), the discriminator MUST be in the ContribMsg signature pre-image. The §7.6.6 / §7.6.7 paired contract requires that the ContribMsg's discriminator + body are bound by the signature so a malicious peer cannot substitute one decoder for another while preserving the signature. Implementation: encode `contrib_msg_form` byte immediately after `aborts_gen` in the signature pre-image (mirroring the wire encoding).

**Backward-compat shim.** Pre-§7.5 ContribMsgs are interpreted as `contrib_msg_form = TX_HASH_ARRAY` with the existing body decode. The pre-image binding contract (Theorem T-1 in `MakeContribCommitmentBackwardCompat.md`) extends naturally: at `contrib_msg_form = 0`, the new encoding is byte-identical to the pre-§7.5 ContribMsg encoding modulo the explicit discriminator byte; signature pre-images differ by exactly one byte. **Mainnet v1.0 emits the discriminator unconditionally** — no pre-§7.5 blocks ever appear on a v1.0 chain, so the shim is for future hypothetical historical-replay only.

### 2.7 7.5.6 `Transaction.sig_form`

**Field position.** Every Transaction, immediately before the `sig: Signature` field. Order: `from: PubKey || to: PubKey || amount: u64 || fee: u64 || nonce: u64 || ...payload... || sig_form: u8 || sig: bytes`.

**Wire encoding.**

```
from:     PubKey       // §7.5.7-encoded (variable-length)
to:       PubKey       // §7.5.7-encoded (variable-length); for anon-address tx, `to` is the parse_anon_pubkey result
amount:   u64
fee:      u64
nonce:    u64
...payload-specific fields...
sig_form: u8           // §7.5.6; default SIG_ED25519 = 0
sig:      bytes        // decoded per sig_form
```

**v1.0 default.** `SIG_ED25519 = 0`. `sig` is the existing 64-byte Ed25519 signature.

**Reserved values:** `SIG_DILITHIUM = 1`, `SIG_BLS12_381 = 2`, `0xFF` (forward-compat reject).

**Tx.signing_bytes() inclusion.** The `sig_form` byte MUST be in `Transaction.signing_bytes()` immediately before the signature. Per the §7.5.6 / §7.6.6 contract: signing_bytes binds the discriminator so a malicious peer cannot substitute one sig-decoder for another while keeping the signature valid.

**Embedded sigs in payloads** (e.g., v2.26 ROTATE_KEY's `old_key_sig`, F2 reveal sigs, multi-sig aux_sigs per future v2.15): per §7.6.6, these are payload-internal and follow tx-level `sig_form`. A `SIG_DILITHIUM` tx has its outer sig AND all embedded sigs in Dilithium form — homogeneous within a tx. This avoids combinatorial form-mixing within a single tx and keeps decoder dispatch logic simple. Implementation: decoder for the embedded sig types reads tx-level `sig_form` at the outer-tx parse step and passes it through to all inner-sig decoders within the same tx.

**Backward-compat shim.** Pre-§7.5 transactions are interpreted as `sig_form = SIG_ED25519`. Byte-identical to the pre-§7.5 transaction encoding modulo the explicit `sig_form = 0` byte.

### 2.8 7.5.7 `pubkey_form` + variable-length pubkey encoding

**Pattern.** EVERY pubkey-bearing field in v1.0 is encoded as a PubKey record per the following uniform shape:

```
PubKey = {
    pubkey_form: u8        // discriminator; default PUBKEY_ED25519 = 0
    body_len:    u16       // length of body in bytes; non-zero for v1.0
    body:        bytes     // pubkey bytes (32 for Ed25519; future: 96 for BLS12-381 compressed, 1952 for Dilithium-3)
}
```

**v1.0 default.** `pubkey_form = PUBKEY_ED25519 = 0`; `body_len = 32`; `body = 32 raw Ed25519 pubkey bytes`. Total on-wire: 1 + 2 + 32 = **35 bytes per Ed25519 pubkey** in the new variable-length encoding vs the pre-§7.5 raw 32 bytes. The +3 byte overhead per pubkey applies uniformly to every pubkey-bearing field.

**Reserved values:** `PUBKEY_BLS12_381 = 1` (96-byte compressed body), `PUBKEY_DILITHIUM = 2` (1952-byte body for Dilithium-3), `0xFF` (forward-compat reject).

**body_len elision rule (recommended off).** Per §2.1: encoders MAY elide `body_len` for known-form values (i.e., decode the body length from `pubkey_form` directly: Ed25519 → 32, BLS → 96, Dilithium-3 → 1952). The cost saving is 2 bytes per pubkey × thousands of pubkeys per block — non-trivial at scale. The cost paid is decoder complexity and a coupling between enum value and body-length lookup table. **Recommended: emit `body_len` explicitly even for known forms.** Rationale: forward-compat is the entire point of §7.5.7; eliding `body_len` reintroduces a form-vs-length coupling that any future arbitrary-length form would have to break. The +2 bytes per pubkey is a small price for uniform decoder logic.

**Fields affected.** Every existing PubKey32 usage. Specifically:

| Field | Source | v1.0 wire-record shape after §7.5.7 |
|---|---|---|
| `RegistryEntry.ed_pub` | `include/determ/node/registry.hpp:25`, `include/determ/chain/genesis.hpp:56` | PubKey record (35 B for Ed25519) |
| `Transaction.from`, `Transaction.to` | All TRANSFER / REGISTER / STAKE / UNSTAKE / DAPP_CALL / etc. txs | PubKey record (35 B) |
| `Account.*` view-key / audit-key / etc. fields (per PRIV-6, PRIV-6.1) | v2.22 Account state | PubKey record (35 B each) |
| `Account.view_master_pk`, `Account.audit_view_master_pk` (PRIV-4) | v2.22 Account state | PubKey record (35 B each) |
| `Account.fs_view_pk` (OPTIONAL, §7.5.2) | v2.22 Account state | PubKey record (35 B when present) |
| `Account.trusted_issuer_pubkey` (OPTIONAL, §7.5.3) | v2.22 Account state | PubKey record (35 B when present) |
| `OtpkEntry.otpk_pk` (PRIV-6) | v2.22 OTPK batch | PubKey record (35 B per OTPK; aggregate cost dominated by OTPK batch count) |
| `DAppEntry.service_pubkey` | `include/determ/chain/chain.hpp:57`, `include/determ/chain/block.hpp:119` | PubKey record (35 B) |
| `Block.creators[]` (committee member pubkeys; encoded via Determ's per-creator-pubkey lookup) | Block header | PubKey record per creator (35 B) |
| `Block.creator_dh_inputs[]` (Phase-1 DH commitments) | Block header | Hash type (NOT a PubKey) — out of scope of §7.5.7 |
| ROTATE_KEY (v2.26) `new_pubkey` | v2.26 tx payload | PubKey record (35 B) |
| Multi-sig (v2.15) signer pubkeys | Future v2.15 work | PubKey record per signer when v2.15 ships |
| Beaconless v2 manifest committee pubkeys per shard (BL-2) | Bundle 5 manifest | PubKey record per committee member per shard |

**Out of scope of §7.5.7.** Hash-typed fields (`Hash`, `Signature`, etc.) are not pubkeys; they retain their existing fixed-size raw-byte encoding. Specifically: `Block.tx_root`, `Block.prev_hash`, `Block.delay_seed`, `Block.delay_output`, `Block.cumulative_rand`, `Block.state_root`, `Block.creator_dh_inputs[]` (Phase-1 commitments — Hash-typed by design), `Block.creator_dh_secrets[]` (Phase-2 revealed secrets — Hash-typed), `Transaction.sig` (Signature-typed). These fields remain at their pre-§7.5 encoding.

**v1.0 default.** Every pubkey on the wire is `PUBKEY_ED25519` (35 B per pubkey). The aggregate byte cost depends on per-block pubkey count; for a typical K=16 committee block with ~hundreds of transactions, the overhead is ~hundreds of bytes — small relative to existing block sizes.

**Backward-compat shim.** Pre-§7.5 PubKey32 fields are interpreted as `PUBKEY_ED25519` with `body_len = 32`. Byte-identical to the pre-§7.5 encoding modulo the explicit 3-byte prefix.

---

## 3. Validator dispatch rules

### 3.1 Universal pattern: read-discriminator-first-then-dispatch

For every discriminator, the validator's parse / verify path follows the same pattern:

1. **Read the discriminator byte** at the field-ordering position.
2. **Check enum value against the v1.0 accepted-set** (the singleton containing only the default value).
3. **Reject if value is not the default** with a diagnostic naming both the offending field AND the offending value.
4. **Dispatch decode** of the dependent body (the signature, the OTPK pool, the trusted issuer pubkey, etc.) by the discriminator value.

The validator NEVER tolerates unknown discriminator values, including `0xFF`. Forward-compat is realized by the v1.0 schema-shape lock-in (the slot exists) combined with fail-closed rejection (so unknown forms don't silently pass).

### 3.2 v1.0 accepted-values table per discriminator

| Discriminator | Default (v1.0 accepted) | Rejected at v1.0 | Diagnostic on reject |
|---|---|---|---|
| `Block.signature_form` | `SIG_KK_ED25519 = 0` | `SIG_BLS12_381_AGGREGATE = 1`, `SIG_DILITHIUM_KK = 2`, all other non-zero u8 (incl 0xFF) | `block.signature_form = <value>; only SIG_KK_ED25519 (0) is accepted at v1.0` |
| `Account.view_key_mechanism` | `OTPK_STREAM = 0` | `FSE = 1`, `PUNCTURABLE = 2`, all other non-zero u8 (incl 0xFF) | `account.view_key_mechanism = <value>; only OTPK_STREAM (0) is accepted at v1.0` |
| `Account.audit_model` | `KEY_DISCLOSURE = 0` | `TRUSTED_ISSUER = 1`, `ZK_BASED_AUDIT = 2`, `NO_AUDIT = 3`, all other non-zero u8 (incl 0xFF) | `account.audit_model = <value>; only KEY_DISCLOSURE (0) is accepted at v1.0` |
| `manifest.randomness_aggregation_form` | `THRESHOLD_SIG_ACCUMULATOR = 0` | `VRF_PER_SHARD = 1`, all other non-zero u8 (incl 0xFF) | `manifest.randomness_aggregation_form = <value>; only THRESHOLD_SIG_ACCUMULATOR (0) is accepted at v1.0` |
| `ContribMsg.contrib_msg_form` | `TX_HASH_ARRAY = 0` | `IBLT_PAYLOAD = 1`, `MINISKETCH_PAYLOAD = 2`, all other non-zero u8 (incl 0xFF) | `contrib_msg.contrib_msg_form = <value>; only TX_HASH_ARRAY (0) is accepted at v1.0` |
| `Transaction.sig_form` | `SIG_ED25519 = 0` | `SIG_DILITHIUM = 1`, `SIG_BLS12_381 = 2`, all other non-zero u8 (incl 0xFF) | `tx.sig_form = <value>; only SIG_ED25519 (0) is accepted at v1.0` |
| `pubkey_form` (per pubkey field) | `PUBKEY_ED25519 = 0` | `PUBKEY_BLS12_381 = 1`, `PUBKEY_DILITHIUM = 2`, all other non-zero u8 (incl 0xFF) | `pubkey_form = <value> at <field-name>; only PUBKEY_ED25519 (0) is accepted at v1.0` |

### 3.3 Optional companion field presence enforcement

Per §2.3 + §2.4, two of the seven discriminators have optional companion fields whose presence rule is derived from the discriminator value. The validator MUST enforce the rule:

| Discriminator | Rule |
|---|---|
| `view_key_mechanism = OTPK_STREAM` | `fs_view_pk` MUST be absent (encoding length matches the no-`fs_view_pk` case byte-for-byte) |
| `view_key_mechanism ∈ {FSE, PUNCTURABLE}` | `fs_view_pk` MUST be present and decode as a valid PubKey record |
| `audit_model = KEY_DISCLOSURE` | `trusted_issuer_pubkey` MUST be absent |
| `audit_model = TRUSTED_ISSUER` | `trusted_issuer_pubkey` MUST be present and decode as a valid PubKey record |
| `audit_model ∈ {ZK_BASED_AUDIT, NO_AUDIT}` | `trusted_issuer_pubkey` MUST be absent |

A violation of the presence rule (e.g., a v1.0 Account encoding that contains a `trusted_issuer_pubkey` field while `audit_model = KEY_DISCLOSURE`) is rejected with a diagnostic. Critically: this rule is structural — the validator MUST verify both directions (rule-implies-presence AND rule-implies-absence) so a malicious encoder can't smuggle an opportunistic companion field through. The strict enforcement composes with the fail-closed-on-unknown-discriminator rule into a tight "exactly the expected encoding" gate.

### 3.4 Fail-closed unknown-value security property

The fail-closed posture composes with `WireFormatBackwardCompat.md` T-2 (Domain-Separator Replay Defense): legacy v1.0 validators that encounter a hypothetical future v1.1 or v2 encoded block will reject the block at the discriminator dispatch step (because the future block's discriminator value lies outside the v1.0 accepted-set). The reject is at parse / verify time, well before any state mutation. **No silent-acceptance path exists.**

The implication for v3+ migration: any future protocol that introduces a new enum value (e.g., `SIG_DILITHIUM_KK`) MUST do so via an explicit protocol-version boundary (a fresh chain, or a coordinated hard fork). A v1.0 validator will reject the encoding regardless. This is the no-migrations constraint operating as designed: the slot exists, but legacy validators cannot follow the new path.

### 3.5 Per-discriminator diagnostic patterns

Per `JsonValidationSoundness.md` T-1 (Clear-Diagnostic Soundness): every reject MUST include the field name and the offending value. The diagnostic patterns in §3.2 above conform; additionally:

- For wire-format encoding violations (e.g., truncated PubKey record where `body_len > remaining_bytes`), the diagnostic should distinguish "discriminator-value-unknown" from "encoding-length-violation" so an operator can tell what went wrong. Recommended format: `pubkey_form decode error at <field-name>: <reason>`.
- For companion-field presence-rule violations: `trusted_issuer_pubkey unexpectedly present when audit_model = KEY_DISCLOSURE` (or the converse).
- Diagnostics MUST NOT include any secret material per `S027InfoLeakage` discipline — pubkey hex values are public, so they may be logged; signature contents likewise; private-key material never.

---

## 4. Address derivation discriminator inclusion

### 4.1 The §7.5.7 / §7.6.7 binding requirement

Per `Improvements.md §7.6.7`:

> **Address derivation.** Determ addresses today derive from pubkeys (or domains). For Ed25519, derivation is `address = some_hash(pubkey_32B || ...)`. With pubkey_form discriminator, derivation becomes `address = some_hash(pubkey_form || pubkey_body || ...)` — the discriminator MUST be in the address-derivation preimage to prevent address collision across pubkey forms. This is a v1.0 design lock-in: getting it wrong now forecloses PQ pubkey migration even with the discriminator present.

This is the critical implementation detail that distinguishes "discriminator slot present but useless" from "discriminator slot present and load-bearing."

### 4.2 CURRENT address-derivation formula

From `include/determ/types.hpp:153-155`:

```cpp
inline std::string make_anon_address(const PubKey& pk) {
    return "0x" + to_hex(pk);
}
```

And the corresponding parse:

```cpp
inline PubKey parse_anon_pubkey(const std::string& addr) {
    if (!is_anon_address(addr))
        throw std::invalid_argument("not an anon address: " + addr);
    return from_hex_arr<32>(addr.substr(2));
}
```

**The current Determ anonymous-account address IS the literal hex encoding of the 32-byte Ed25519 pubkey, with a `"0x"` prefix.** No hash, no discriminator, no domain separator. The address is 66 chars (`"0x"` + 64 hex chars).

This means: **today, every anonymous account address IS its Ed25519 pubkey body**. The pubkey body and the address are isomorphic.

### 4.3 The address-derivation problem post-§7.5.7

When `pubkey_form` discriminator is introduced, two distinct pubkeys of two different forms could share the same body bytes if the body hex spaces happen to overlap. For Ed25519 (32 B body) vs Dilithium-3 (1952 B body), this is moot — body lengths differ. But for hypothetical future PQ forms whose bodies happen to be 32 B (e.g., a compact lattice pubkey variant), or for an attacker constructing a malicious pubkey form whose body happens to alias a real Ed25519 pubkey, the same address could derive from two distinct pubkey forms.

**The §7.6.7 fix.** The address-derivation preimage MUST bind both `pubkey_form` AND `body`, so two pubkeys of distinct forms produce distinct addresses even if their body bytes collide.

### 4.4 v1.0 post-discriminator address-derivation formula (specification)

The specification REQUIRES that the address-derivation preimage include `pubkey_form` as a domain separator. Possible options, with trade-offs:

**Option A (recommended): hash-based with discriminator.**

```cpp
inline std::string make_anon_address(uint8_t pubkey_form, const uint8_t* body, size_t body_len) {
    // SHA256(pubkey_form || body_len_be4 || body) truncated to 32 bytes.
    SHA256Builder b;
    b.append(pubkey_form);
    b.append_u32_be(static_cast<uint32_t>(body_len));
    b.append(body, body_len);
    Hash h = b.finalize();
    return "0x" + to_hex(h);
}
```

Pros: Uniform across all pubkey forms; address is always 66 chars; address is decoupled from pubkey body length (Dilithium 1952 B body still produces 66-char address); discriminator is cryptographically bound into the address.

Cons: **This BREAKS every existing anon-address in the codebase, every test fixture, every operator audit script, every committed-to-the-database account record.** Today's addresses are `"0x" + hex(pubkey_32B)`; the new formula produces `"0x" + hex(SHA256(0 || 32 || pubkey_32B))`. Different output → different account record → balances at the old address invisible at the new address.

**Option B: leading-discriminator prefix.**

```cpp
inline std::string make_anon_address(uint8_t pubkey_form, const uint8_t* body, size_t body_len) {
    // "0x<form_hex>" + hex(body) — discriminator-prefix for Ed25519 = "0x00" + hex(body_32B).
    // Variable-length address for future forms.
    std::string addr = "0x";
    addr += to_hex(&pubkey_form, 1);
    addr += to_hex(body, body_len);
    return addr;
}
```

Pros: Discriminator visible in the address string; binding preserved without a hash; v1.0 Ed25519 addresses become `"0x00" + hex(body_32B)` = 2 + 2 + 64 = 68 chars (different format from current 66 chars).

Cons: Same compat-break as Option A; also makes addresses variable-length (Dilithium addresses would be huge, ~2 + 2 + 3904 hex chars).

**Option C: post-hoc-binding (rejected).**

Keep the current formula `"0x" + hex(body_32B)` for Ed25519 (preserve compat). Use a different prefix scheme for future forms (e.g., `"0xdilithium:..."` or similar). v1.0 Ed25519 addresses are unchanged.

Pros: Zero compat-break for v1.0 Ed25519 addresses.

Cons: **The discriminator is NOT in the v1.0 address-derivation preimage for Ed25519.** This re-creates the §7.6.7 binding problem for any future v3 migration: if a v3 form produces a 32-B body, its address space could collide with v1.0 Ed25519 addresses. The §7.6.7 lock-in is violated.

### 4.5 The compat-break finding (v1.0 design lock-in)

**Critical finding: §7.5.7 implementation as specified in `Improvements.md §7.6.7` MUST address how it composes with the current address-derivation formula.** The current formula does NOT bind the discriminator into the address preimage — the address IS the pubkey body bytes, with no domain-separation byte.

Three implementation paths exist:

1. **Adopt Option A or B and accept a one-time address-shape change for v1.0 mainnet.** This means: any address pre-computed under the current Determ codebase (testnets, fixtures, manual operator audits, third-party indexers) does NOT match a v1.0 mainnet address. Operationally manageable because v1.0 mainnet is pre-launch (no legacy mainnet addresses to preserve). But every existing tool / test / fixture / doc that bakes in a specific anon-address hex string MUST be regenerated. **Estimated impact:** dozens of test scripts in `tools/test_anon_*.sh`, `tools/test_anon_address.sh`, `tools/test_wallet_*.sh`, and adjacent code paths. Address-derivation determinism is preserved (same pubkey → same address) but the formula changes.

2. **Adopt Option C and accept the §7.6.7 binding violation for v1.0 Ed25519.** This means: the discriminator slot is present in the wire format, but the address-derivation preimage for Ed25519 does NOT bind it. A future v3 migration to a 32-B-body PQ form would re-encounter the collision risk that §7.6.7 was designed to prevent. The optionality the discriminator buys is reduced.

3. **Adopt Option A and apply it ONLY post-v1.0.** This is structurally Option C — the discriminator is absent from the v1.0 address-derivation preimage; the §7.6.7 binding only kicks in for non-Ed25519 forms. Same caveat as #2.

**Recommendation.** Adopt **Option A** decisively at v1.0 mainnet. The compat-break is one-time and pre-launch; the alternative (#2 / #3) re-introduces the post-v1.0 forclosure risk that §7.6.7 was specifically designed to eliminate. The whole point of shipping the §7.5.7 discriminator is to preserve post-v1.0 PQ-migration optionality; eliding the address-derivation binding undermines that goal.

**Decision authority.** This decision is NOT pre-resolved in `Improvements.md §7.5/§7.6` or `DECISION-LOG.md`. The §7.6.7 text says "address-derivation preimage MUST include `pubkey_form` discriminator" but does not specify the formula. This document RECOMMENDS Option A; the implementation thread MUST get explicit user / decision-authority sign-off before shipping the address-derivation change because it is a substantive deviation from the current code path.

**Migration risk for shipped addresses.** If v1.0 is pre-mainnet (per the no-migrations / pre-launch posture confirmed in `IMPLEMENTATION-SEQUENCING.md §4.4`), there are NO shipped mainnet addresses to migrate; only test fixtures and operator-tooling artifacts that bake in specific hex strings. Mainnet launches with the post-§7.5.7 formula or it never adopts it; there is no hybrid path.

### 4.6 Domain addresses (not affected)

For domain-name accounts (`"alice"`, `"bob"`, etc. — registered via REGISTER tx and ed_pub binding), the address IS the domain name string. No pubkey-derivation happens. The §7.5.7 discriminator does not interact with domain addresses; the registry stores `(domain, ed_pub)` mappings where `ed_pub` is now a full PubKey record (per §2.8) but the domain-name string is unchanged. Domain addresses are unaffected by the §7.5.7 change.

---

## 5. sig_form ↔ pubkey_form curve-family consistency invariant

### 5.1 The invariant

A signature with `sig_form = SIG_X` MUST verify against a pubkey with `pubkey_form = PUBKEY_X` (matching curve family). Cross-form combinations are hard rejects at verification time. Specifically at v1.0:

| `Transaction.sig_form` | Required `Transaction.from.pubkey_form` | Verify procedure |
|---|---|---|
| `SIG_ED25519 = 0` | `PUBKEY_ED25519 = 0` | `ed25519_verify(from.body, signing_bytes, sig)` |
| `SIG_DILITHIUM = 1` (future) | `PUBKEY_DILITHIUM = 2` (future) | `dilithium_verify(from.body, signing_bytes, sig)` |
| `SIG_BLS12_381 = 2` (future) | `PUBKEY_BLS12_381 = 1` (future) | `bls_verify(from.body, signing_bytes, sig)` |

Cross-form combinations — e.g., `sig_form = SIG_DILITHIUM` with `from.pubkey_form = PUBKEY_ED25519` — are hard rejects. The validator MUST check curve-family consistency BEFORE attempting verification (because attempting an Ed25519 verify against a Dilithium key blob is undefined behavior in the underlying crypto library; the curve-family gate is a safety AND correctness requirement).

### 5.2 Same invariant for block-level sigs (§7.5.1)

For `Block.signature_form`, every committee member's pubkey (in `RegistryEntry.ed_pub`) MUST match the curve family of the block's `creator_block_sigs[]` form. At v1.0: every committee member has `RegistryEntry.ed_pub.pubkey_form = PUBKEY_ED25519`, and `Block.signature_form = SIG_KK_ED25519`. The verifier checks the match before attempting Ed25519 verify on each per-creator sig.

### 5.3 Embedded sig consistency (within a tx)

Per §2.7, embedded sigs within a tx payload follow tx-level `sig_form`. So:

- `SIG_ED25519` tx → outer `sig` is Ed25519 AND every embedded sig within the payload (e.g., `old_key_sig` in ROTATE_KEY, multi-sig aux sigs in v2.15) is Ed25519. Every embedded sig's pubkey reference (e.g., the old pubkey in ROTATE_KEY, signer pubkeys in multi-sig) MUST be `PUBKEY_ED25519`.
- Mixed-form embedded sigs (e.g., a `SIG_ED25519` outer with a `SIG_DILITHIUM` embedded) are forbidden by §7.6.6. Validator rejects.

### 5.4 ContribMsg.signer curve-family consistency

Per `MakeContribCommitmentBackwardCompat.md`, the ContribMsg's signer pubkey verifies the ContribMsg's signature. The §7.5.7 / §7.6.7 contract requires `ContribMsg.signer.pubkey_form` match the curve family of the ContribMsg sig. At v1.0: every ContribMsg sig is Ed25519 and every signer pubkey is `PUBKEY_ED25519`. Validator checks consistency. (No discriminator on the ContribMsg sig itself — ContribMsg sigs are always Ed25519 at v1.0; the discriminator is on the signer pubkey, and the curve family follows.)

### 5.5 Verification-time enforcement (test contract)

The curve-family check is a parse-time + verify-time gate. The implementation MUST:

1. Parse the sig pre-image's `sig_form` byte.
2. Parse the corresponding pubkey reference (e.g., `from` for tx, `signer` for ContribMsg).
3. Check `sig_form` ⟷ `pubkey_form` curve-family match against the §5.1 table.
4. If mismatch: reject with diagnostic `sig_form/pubkey_form curve-family mismatch: sig_form = <S>, pubkey_form = <P>` BEFORE any cryptographic verification step.
5. If match: dispatch verification to the appropriate cryptographic primitive.

The pre-verify check ensures that no malformed cross-form combination reaches the underlying crypto library. Combined with the §3.1 unknown-value reject, this gives a two-stage defense: unknown discriminator → reject, known but cross-form combination → reject.

---

## 6. Per-record byte-cost summary

Following `Improvements.md §7.6.8` aggregate cost summary, here are the per-record byte costs of the seven discriminators at v1.0 default values:

| Record | Discriminator(s) | v1.0 bytes added | Notes |
|---|---|---|---|
| Block (header) | `signature_form` | +1 | Single u8 byte |
| Account | `view_key_mechanism` + `audit_model` | +2 | Two u8 bytes (companion fields omitted at default values) |
| Manifest | `randomness_aggregation_form` | +1 | One-time deployment-wide cost |
| ContribMsg | `contrib_msg_form` | +1 | Per Phase-1 ContribMsg |
| Transaction | `sig_form` | +1 | Per tx |
| Per PubKey field | `pubkey_form` + `body_len` | +3 | 1 byte discriminator + 2 byte body_len; body unchanged at 32 B for Ed25519 |

**Aggregate cost per block** (rough estimate for a tactical-profile block with K=16 committee, ~50 txs, ~10 ContribMsgs):

- 1 byte for block.signature_form
- 16 × 3 = 48 bytes for the K committee creators[i] pubkeys (excluding the existing 32-byte body — only the +3 byte overhead per pubkey)
- 50 × 1 = 50 bytes for per-tx sig_form
- 50 × (2 × 3) = 300 bytes for the K=2 pubkeys per tx (from + to, each +3 overhead)
- 10 × 1 = 10 bytes for per-ContribMsg contrib_msg_form
- 10 × 3 = 30 bytes for the per-ContribMsg signer pubkey overhead

Total: ~440 bytes per block of discriminator overhead. Relative to a typical block size of tens of KB at full mempool throughput, this is well under 1% overhead.

**Per-Account overhead at creation** (one-time):

- 2 bytes for view_key_mechanism + audit_model
- ~6 bytes for the +3 overhead per PubKey on the various Account pubkey fields (view_master_pk, audit_view_master_pk, etc.) — exact count depends on how many pubkey fields Account carries post-v2.22

Total: ~10 bytes per Account at creation. Negligible.

**Optional companion field cost when populated** (NOT v1.0 default; future-state):

- `fs_view_pk` (if FSE / PUNCTURABLE adopted post-v1.0): +35 bytes per Account (PubKey record at Ed25519 size, or larger for lattice-based forms)
- `trusted_issuer_pubkey` (if TRUSTED_ISSUER adopted post-v1.0): +35 bytes per Account

These are zero-cost at v1.0 because the companion fields are omitted at default values per the §3.3 presence-enforcement rule.

---

## 7. Implementation effort by discriminator

Per `IMPLEMENTATION-SEQUENCING.md §2.3` pre-bundle discriminator table:

| Discriminator | Location | Effort | Notes |
|---|---|---|---|
| `Block.signature_form` | Block header | ~1-2 days | Add field; wire-format encode/decode; validator dispatch; signing_bytes inclusion; backward-compat shim for hypothetical historical replay |
| `ContribMsg.contrib_msg_form` | Phase-1 ContribMsg | ~1-2 days | Add field; wire-format encode/decode; validator dispatch; signing pre-image inclusion |
| `Transaction.sig_form` | Every Transaction | ~1-2 days | Add field; wire-format encode/decode; validator dispatch; signing_bytes inclusion; embedded-sig homogeneity check per §2.7 |
| `pubkey_form` + variable-length pubkey encoding | Every pubkey-bearing field | **~3-5 days** | Substantive lift: touches sig verification, address derivation, serialization, deserialization throughout. Address-derivation preimage change per §4 is the substantive sub-component |
| `Account.view_key_mechanism` + optional `fs_view_pk` | Account state (lands within Bundle 3) | ~1 day | Adds within v2.22 Account schema; landing inside Bundle 3 amortizes the Account-schema lift |
| `Account.audit_model` + optional `trusted_issuer_pubkey` | Account state (lands within Bundle 3) | ~1 day | Same as above; pairs with audit-disclosure work within Bundle 3 |
| `manifest.randomness_aggregation_form` | Beaconless v2 deployment manifest (lands within Bundle 5) | ~0.5 days | Trivial addition to `validate_manifest()` per Q2.1 hard-invariant pattern |

**Aggregate effort: ~6-10 days** for the pre-bundle work (the first four discriminators), per `IMPLEMENTATION-SEQUENCING.md §2.3`. The 7.5.7 lift dominates at ~3-5 days; the remaining three pre-bundle discriminators are ~1-2 days each.

The two Bundle-3 discriminators (7.5.2 + 7.5.3) add ~1-2 days within Bundle 3's ~3-3.5 month effort.

The single Bundle-5 discriminator (7.5.4) adds ~0.5 days within Bundle 5's ~3-4 month effort.

**Critical-path positioning.** The pre-bundle discriminators (4 of 7) MUST land BEFORE any of Bundle 1, 2, 3, 4, or 5 starts, to lock the v1.0 genesis schema shape. Per `IMPLEMENTATION-SEQUENCING.md §2.3`: "Foundation / pre-bundle: ...must land before any of the review-week bundles to lock the genesis schema shape." Bundle work that produces blocks / txs / ContribMsgs without the discriminator slots would have to be retrofitted, undermining the schema-freeze gate.

**Address-derivation lock-in (§4) is the gate within Bundle 0.** If §4 Option A is adopted, every test fixture that contains a specific Ed25519 anon-address hex MUST be regenerated. The address-derivation change is part of the 7.5.7 ~3-5 day estimate; the fixture regeneration adds some overhead (estimated <1 day given the existing test-fixture-generation patterns in `tools/test_*.sh`).

---

## 8. Test coverage requirements

For each discriminator to be considered "shipped," the following regression tests MUST exist and pass:

### 8.1 Round-trip encode/decode at default value

**Test pattern.** For each discriminator field, construct a record carrying the v1.0 default value, encode to wire format, decode from wire format, assert structural equality.

Suggested test names:
- `tools/test_block_signature_form_roundtrip.sh`
- `tools/test_account_view_key_mechanism_roundtrip.sh`
- `tools/test_account_audit_model_roundtrip.sh`
- `tools/test_manifest_randomness_form_roundtrip.sh`
- `tools/test_contrib_msg_form_roundtrip.sh`
- `tools/test_tx_sig_form_roundtrip.sh`
- `tools/test_pubkey_form_roundtrip.sh`

Each test verifies:
- Encoded byte at the expected position has value 0 (the default).
- Decoded record has discriminator = default.
- Companion fields (where applicable) are absent at default values.
- Byte-length of encoded record matches the §6 byte-cost summary.

### 8.2 Fail-closed reject for non-default enum values

**Test pattern.** For each discriminator field, construct an encoded record with each non-default enum value (including all reserved values and 0xFF), submit to validator, assert the validator rejects with the expected diagnostic.

Suggested test names:
- `tools/test_block_signature_form_unknown_reject.sh`
- `tools/test_account_view_key_mechanism_unknown_reject.sh`
- `tools/test_account_audit_model_unknown_reject.sh`
- `tools/test_manifest_randomness_form_unknown_reject.sh`
- `tools/test_contrib_msg_form_unknown_reject.sh`
- `tools/test_tx_sig_form_unknown_reject.sh`
- `tools/test_pubkey_form_unknown_reject.sh`

Each test verifies:
- Submitting `SIG_BLS12_381_AGGREGATE = 1` (or analogous reserved value) at the discriminator position produces a validator reject.
- Submitting `0xFF` produces a validator reject.
- The reject diagnostic includes the field name AND the offending value.
- No state mutation occurs as a result of the rejected submission (validator rejects pre-apply).

### 8.3 Companion field presence-enforcement (7.5.2 + 7.5.3)

**Test pattern.** For `view_key_mechanism` + `audit_model`, construct records that violate the presence rule (e.g., `view_key_mechanism = OTPK_STREAM` with `fs_view_pk` present, OR `audit_model = TRUSTED_ISSUER` with no `trusted_issuer_pubkey`), submit, assert reject.

Suggested test names:
- `tools/test_account_view_key_mechanism_presence_rule.sh`
- `tools/test_account_audit_model_presence_rule.sh`

Each test verifies both directions of the presence rule (rule-implies-presence AND rule-implies-absence; both must be enforced to defeat a malicious encoder).

### 8.4 Address-derivation preimage with `pubkey_form` — golden vector

**Test pattern.** Given a specific Ed25519 pubkey body (32 B), the address derivation formula (per §4 Option A) MUST produce a specific known address. The golden vector pins the formula so future implementation changes can be verified.

Suggested test name: `tools/test_pubkey_form_address_derivation.sh`

The test:
- Defines a constant test pubkey body (e.g., all-zeros 32 B, all-0xFF 32 B, plus 2 random fixed values).
- Computes `address = some_hash(pubkey_form_byte || body_len_be4 || body)` using the v1.0 formula (whichever option is adopted per §4.5).
- Asserts the address matches the golden vector hex string.
- The golden vector is regenerated when the formula changes; the test prevents accidental formula drift.

**This is the load-bearing test for §4.** If §4 Option A is adopted, the golden vector encodes the formula choice; any post-launch change would break the test (and break every shipped address, which is why the change must happen pre-launch).

### 8.5 Sig-pubkey curve-family consistency reject test

**Test pattern.** Construct a tx with `sig_form = SIG_ED25519` but with `from.pubkey_form = PUBKEY_DILITHIUM` (or any cross-form combination), submit, assert reject.

Suggested test name: `tools/test_sig_pubkey_curve_family.sh`

Test cases:
- Valid: `sig_form = SIG_ED25519`, `from.pubkey_form = PUBKEY_ED25519`. ACCEPT.
- Invalid: `sig_form = SIG_ED25519`, `from.pubkey_form = PUBKEY_BLS12_381`. REJECT with curve-family-mismatch diagnostic.
- Invalid: `sig_form = SIG_ED25519`, `from.pubkey_form = PUBKEY_DILITHIUM`. REJECT.
- Invalid: ContribMsg.signer with `pubkey_form` not matching the ContribMsg sig's implicit curve family.
- Invalid: Block.creator with `pubkey_form` not matching `Block.signature_form`'s curve family.

Each test verifies the §5.5 pre-verify gate fires before the cryptographic library is invoked.

### 8.6 Optional companion field roundtrip (7.5.2 + 7.5.3)

**Test pattern.** Construct an Account with a non-default `view_key_mechanism` (e.g., `FSE`) carrying `fs_view_pk`, encode, decode, assert round-trip identity. (This is forward-looking: v1.0 validators reject `FSE` per §3, but the encoder/decoder MUST handle the encoding shape for future-compat.)

Suggested test name: `tools/test_account_optional_companion_roundtrip.sh`

The test verifies:
- Encoder can construct an Account with `view_key_mechanism = FSE` and `fs_view_pk` populated.
- The wire encoding is structurally correct (companion field present).
- Decoder parses the encoding back to the original Account state.
- Validator REJECTS submission of such an Account at v1.0 (per §3 — only OTPK_STREAM is accepted).

This test verifies that the encoding scaffolding is in place even though the validator path is not yet implemented; future post-v1.0 work to enable FSE adoption builds on top of this scaffolding.

### 8.7 Test count contribution

Adding the above test suites to `tools/test_*.sh` would increase the test count by approximately 8-12 new scripts (one or more per discriminator surface). The current `tools/test_*.sh` count per `MEMORY.md` is ~48 + ongoing growth; adding the discriminator test surface brings it to ~58-60.

---

## 9. Open implementation questions

### 9.1 FIPS-profile variant of §7.5.1 — uses same `SIG_KK_ED25519` slot

Per `Improvements.md §6.1`:

> The block-header schema gains a `signature_form` discriminator: `SIG_KK_ED25519` (FIPS path, identical to v1.0 wire format) or `SIG_BLS12_381_AGGREGATE` (MODERN path).

**Resolved: FIPS profile uses the same `SIG_KK_ED25519` enum slot.** FIPS deployments retain the v1.0 K-of-K Ed25519 wire format. The §7.5.1 discriminator does NOT need a separate FIPS-specific enum value; the curve-follows-profile pattern from C99-11 means a FIPS-profile build uses Ed25519 (already FIPS-compatible for the K-of-K array), and a MODERN-profile build retains the option to switch to `SIG_BLS12_381_AGGREGATE` post-v1.0. No FIPS-specific enum slot needed at v1.0.

Per `Improvements.md §6.1`: "The 'improvement' for FIPS is the absence of change." This is consistent with §7.5.1's default value `SIG_KK_ED25519` covering the FIPS path as-is.

### 9.2 Schema version field outside the seven discriminators

**Question.** Is there a "schema version" field outside these seven that gates the whole envelope?

**Answer.** No. Verified by inspection of `docs/PROTOCOL.md §4` (Block format):

> ```cpp
> struct Block {
>     uint64                index;
>     Hash                  prev_hash;
>     int64                 timestamp;
>     Transaction[]         transactions;
>     string[]              creators;
>     ...
>     Hash                  state_root;
> };
> ```

No `schema_version`, `protocol_version`, or `envelope_version` field in the Block struct or elsewhere in the v1.0 wire format. The seven §7.5 discriminators ARE the future-proofing mechanism — there is no separate version envelope.

This is intentional. Per `Improvements.md §7.5` rationale: "Under the no-migrations constraint, several improvements classified as Breaking could be downgraded to Additive if the v1.0 schema includes a cheap discriminator or optional field that lets future protocol-mode dispatch happen without a schema change. The cost per discriminator is small ... The cost of NOT shipping a discriminator is permanent foreclosure of the improvement under no-migrations."

The discriminator-per-affected-field pattern is structurally cleaner than a global envelope version because:

1. **Field-level granularity** — different post-v1.0 enhancements affect different subsets of fields. A global envelope version forces all-or-nothing migration; per-field discriminators allow incremental adoption.
2. **No coordination overhead** — a global version requires every consumer to track which version they're parsing. Per-field discriminators are local to the field consumer.
3. **No "what does version N mean" ambiguity** — each discriminator's enum space is self-documenting (the enum values name the variants). A global version number has no semantic content without a separate documentation table.

The trade-off accepted: per-field discriminators add ~6-10 bytes per record (per §6), whereas a global version field would add just 1-4 bytes. For the multi-year optionality being purchased, the byte cost is trivial.

**Implication for future implementation threads.** Any v3+ migration that adds a new wire-format mechanism MUST add it via a new enum value within an existing discriminator slot (or via a new optional field). Adding a NEW global version field post-v1.0 would itself be a schema migration — forbidden under no-migrations.

### 9.3 Address-derivation formula decision (§4)

**Open.** §4 RECOMMENDS Option A (hash-based with discriminator) but flags that this decision is not pre-resolved in `Improvements.md §7.5/§7.6` or `DECISION-LOG.md`. The implementation thread MUST get explicit decision-authority sign-off before shipping the address-derivation change.

**Default recommendation in this document: Option A.** Trade-off rationale per §4.5: the compat-break is one-time and pre-launch; the alternative re-introduces the post-v1.0 foreclosure risk that §7.6.7 was specifically designed to eliminate.

### 9.4 `body_len` elision policy

**Open.** §2.1 + §2.8 recommend NOT eliding `body_len` (emit the 2-byte length explicitly even for known forms). The opposing argument: 2 bytes × per-pubkey × per-block = non-trivial bandwidth at scale. The trade-off is decoder-uniformity vs bandwidth.

**Default recommendation in this document: explicit `body_len`.** Trade-off rationale per §2.8: forward-compat is the entire point of §7.5.7; eliding `body_len` reintroduces a form-vs-length coupling that future arbitrary-length forms would have to break.

---

## 10. Status

**Specification.** Complete (this document).

**Implementation.** Pending. Per `IMPLEMENTATION-SEQUENCING.md §2.3`, the seven discriminators land in Bundle 0 (the pre-bundle pass) before any of Bundle 1 / 2 / 3 / 4 / 5 begins. Aggregate effort: ~6-10 days for the four pre-bundle discriminators (7.5.1, 7.5.5, 7.5.6, 7.5.7), plus ~2 days within Bundle 3 (7.5.2, 7.5.3), plus ~0.5 days within Bundle 5 (7.5.4). Total: ~8-13 days across the three bundle-positions.

**Critical-path dependency.** This document's §4 (address-derivation discriminator inclusion) is the substantive lock-in. The decision authority on §4's Option A vs Option B vs Option C is the gate that releases the 7.5.7 implementation. The other six discriminators do NOT carry comparable lock-in risk; their implementation can proceed independently.

**Test coverage.** Once shipped, ~8-12 new tests in `tools/test_*.sh` per §8. Adding to the FAST=1 regression count.

**Mainnet readiness gate.** Per `MAINNET_READINESS.md`, the "pre-bundle schema discriminators landed" item is a v1.0 readiness criterion. Until this work is shipped, v1.0 cannot launch (the discriminator slots would be missing from genesis, foreclosing post-mainnet enhancements that depend on them per the no-migrations constraint).

---

*End of implementation specification. Append new findings or implementation notes as the discriminator work proceeds.*
