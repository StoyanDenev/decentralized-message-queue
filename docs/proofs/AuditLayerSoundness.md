# AuditLayerSoundness — A2 audit-layer consensus: ROTATE_AUDIT_KEY + LOG_AUDIT_ACCESS (owner-bound, fail-closed, additive, atomic)

**Status:** SHIPPED 2026-07-09 (pre-launch register A2, owner-decided
2026-07-09: "build FULL"; commit `268cfaa`). Gated by `determ test-audit-keys`
(35 assertions, in the FAST set via [tools/test_audit_keys.sh](../../tools/test_audit_keys.sh))
+ the live cluster gate + the FAST golden state-root corpus as the
byte-invariance witness. Relates to
[PRE-LAUNCH-DECISIONS.md](../../PRE-LAUNCH-DECISIONS.md) A2; composes with the
A1 per-epoch view-key derivation (§3.24) — the keys these txs publish/disclose
are that layer's `view_master_pk` / epoch keys.

## 1. What shipped

Two fee-only transaction types ([include/determ/chain/block.hpp](../../include/determ/chain/block.hpp)):

- **`ROTATE_AUDIT_KEY = 15`** (block.hpp:226) — set (payload = opaque 32 bytes,
  `AUDIT_KEY_PAYLOAD_SIZE`, block.hpp:241), rotate, or clear (payload empty)
  the account's standing audit pubkey. State: the `"ak:" + addr` leaf, value
  `SHA256(pk_bytes)`, emitted only while a key is set (chain.cpp:430-438).
- **`LOG_AUDIT_ACCESS = 16`** (block.hpp:237) — on-chain record of a view-key
  disclosure: payload = `epoch_u64_BE(8) ‖ auditor_pk(32) ‖ context_hash(32)`,
  exactly 72 bytes (`AUDIT_LOG_PAYLOAD_SIZE`, block.hpp:242);
  `AUDIT_EPOCH_ALL = UINT64_MAX` (block.hpp:245) is the full-history sentinel.
  The tx in chain history IS the record; state tracks only the per-account
  count on the `"al:" + addr` leaf, value `SHA256(count_LE)`, emitted only
  when > 0 (chain.cpp:439-445). A standing `ak:` key is NOT required — ad-hoc
  disclosure to a non-standing auditor is the register's dual-mode model.

Enforcement sites: validator gates ([src/node/validator.cpp](../../src/node/validator.cpp):1162-1187),
apply cases + belt-and-suspenders re-checks ([src/chain/chain.cpp](../../src/chain/chain.cpp):941-970),
producer provisional fee-only debit ([src/node/producer.cpp](../../src/node/producer.cpp):1057-1064),
conditional snapshot serialize/restore (chain.cpp:1838-1847 / 1976-1981),
RPC/test reads `audit_key` / `audit_log_count`
([include/determ/chain/chain.hpp](../../include/determ/chain/chain.hpp):459-467).
The same increment added the validator's fail-closed `default:` for unknown tx
types (validator.cpp:1188-1195) — see AL-3.

## 2. Claims (AL-1 .. AL-5)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green
`test-audit-keys` assertion ([src/main.cpp](../../src/main.cpp):37055-37206)
or the FAST golden corpus.

- **AL-1 (owner-bind: only the account's signer can rotate or log).** Types
  15/16 ride the ordinary per-tx signature path: the validator resolves the
  sender pubkey (registered accounts from the registry, validator.cpp:605-607;
  anonymous/bearer accounts from the address-committed key via
  `parse_anon_pubkey`, validator.cpp:603 — the anon allow-list explicitly
  admits both audit types, validator.cpp:597-602) and verifies `tx.sig` over
  `signing_bytes()` (validator.cpp:610-612). `Transaction::signing_bytes`
  inlines `type ‖ from ‖ to ‖ amount ‖ fee ‖ nonce ‖ payload`
  ([src/chain/block.cpp](../../src/chain/block.cpp):17-29), so the published
  key / the disclosure record is signature-bound — it cannot be swapped in
  flight, and no third party can rotate someone else's audit key or forge a
  disclosure record in their name. Replay is blocked by the sequential nonce
  (validator.cpp:615-620; apply safety net chain.cpp:799). **Proven-in-code**
  (nothing new: the audit types add zero bypasses to the existing signature
  gate; the anon-relax is an allow-list extension, not a signature relaxation).

- **AL-2 (additive byte-invariance: an audit-free chain is byte-identical to a
  pre-A2 chain).** Every emission site is conditional: the `ak:`/`al:` leaves
  are loops over maps that are empty on any audit-free chain
  (chain.cpp:430-445; members chain.hpp:627-628), and the snapshot JSON emits
  `audit_keys` / `audit_log_counts` only when non-empty (chain.cpp:1838-1847),
  with contains-guarded restore defaults (chain.cpp:1976-1981). Genesis always
  clears both maps (chain.cpp:774-775). So `build_state_leaves()` and
  `serialize_state()` on a chain that never uses the feature produce the
  identical bytes they produced before A2. **Proven-in-code + golden-corpus
  witness:** every pre-existing FAST golden state root stays green with A2
  compiled in; `test-audit-keys` additionally asserts both leaves are ABSENT
  at genesis, that a SET makes the root change (observable only when used),
  and that a snapshot omits the cleared key map while a live-key snapshot
  serializes it (assertions 1-2, 7, 31, 34).

- **AL-3 (fail-closed shapes — including the unknown-tx-type fail-open this
  increment closed).** The validator is the authoritative shape gate:
  ROTATE payload must be exactly 32 bytes or empty, `amount == 0`, `to` empty
  (validator.cpp:1166-1173); LOG payload must be exactly 72 bytes, `amount == 0`,
  `to` empty (validator.cpp:1179-1185). Apply re-checks the same shapes and
  skips without any mutation or nonce advance (chain.cpp:946-948, 963-964) —
  belt-and-suspenders against a hostile producer. The same commit added the
  validator switch's `default:` reject (validator.cpp:1188-1195). Exact pre-fix
  failure mode: the validator increments its per-sender simulated nonce BEFORE
  the type switch (validator.cpp:620), and an unknown discriminator then fell
  out of the switch and was ACCEPTED, while apply's `default: continue`
  (chain.cpp:1430) skips it without advancing `sender.next_nonce` — the
  validator's nonce simulation diverged from apply's state, so a block could
  carry accepted-but-no-op txs and desync subsequent same-sender validation.
  Now an unrecognized type is rejected at submit time. **Proven-in-code:**
  `test-audit-keys` pins five malformed-shape apply skips, each asserting no
  key, no count, and no debit (assertions 21-30).

- **AL-4 (rotation semantics: last-writer-wins; clear removes the leaf; count
  monotone).** `audit_keys_[tx.from] = hex(payload)` overwrites unconditionally
  (chain.cpp:952-953) — the newest ROTATE wins per account; empty payload
  `erase`s the entry (chain.cpp:951), and since the `ak:` leaf is emitted only
  for map entries (chain.cpp:433-438), clearing removes the leaf entirely — no
  tombstone, restoring byte-identity with a never-rotated account. The only
  mutation of `audit_log_count_` anywhere is the increment at chain.cpp:967
  (genesis clear aside, chain.cpp:775), so the per-account count is
  monotonically non-decreasing across the chain's life. **Proven-in-code:**
  set → rotate (new pk visible) → clear (leaf REMOVED, `state_proof` fails) →
  two LOG records counting 1 then 2, including the `AUDIT_EPOCH_ALL` sentinel
  (assertions 3-18); fee-only accounting: exactly 5 fees debited over the whole
  lifecycle and the A1 supply identity holds (assertions 19-20; producer
  provisional debit is fee-only, producer.cpp:1057-1064).

- **AL-5 (crash/rollback atomicity: a failed apply restores both maps
  byte-identically).** `apply_transactions` captures a `StateSnapshot` at entry
  (chain.cpp:691) with lazy ensure-lambdas for the audit maps
  (`__ensure_audit_keys` / `__ensure_audit_log_count`, chain.cpp:720-727;
  optional fields chain.hpp:791-792); each apply case calls its ensure BEFORE
  the first mutation (chain.cpp:950, 966), so the snapshot holds the exact
  pre-block map. Any throw from the apply body hits the catch-all
  (chain.cpp:1689-1701), which move-restores every captured collection —
  including both audit maps (chain.cpp:655-658) — and re-raises. Blocks that
  never touch the audit layer pay nothing (the lazy optionals stay empty).
  **Proven-in-code** (same A9 Phase-1 machinery as the shielded pool; the
  audit maps are wired into all three of its stages: ensure, restore, and the
  snapshot struct). The snapshot round-trip half is directly witnessed:
  serialize → restore reproduces count + cleared key + a byte-identical
  recomputed state root (assertions 31-35).

## 3. Non-claims — READ BEFORE TREATING THIS AS AN AUDIT GUARANTEE

- **NC-1 — The published pubkey is OPAQUE 32 bytes.** Neither validator nor
  apply checks that a ROTATE payload is a well-formed/real public key on any
  curve, or that the owner knows its secret. A garbage key produces a valid
  `ak:` leaf. Key validity is a client/wallet concern.
- **NC-2 — LOG_AUDIT_ACCESS records what the OWNER chose to record.** It
  proves the owner signed a statement "I disclosed (epoch, auditor, context)".
  It does NOT prove a disclosure actually happened, that the disclosed key was
  correct, nor — critically — that undisclosed access did not happen. An owner
  who leaks a view key off-chain and never logs it leaves no trace here.
- **NC-3 — No auditor-side signature.** The auditor named by `auditor_pk` does
  not countersign; the record is unilateral. Duplicate records are not deduped
  — the same triple can be logged N times, bumping the count each time.
- **NC-4 — Epoch semantics are not consensus-bound.** The 8-byte epoch is
  length-checked only; no gate ties it to a block-range schedule or to the A1
  derivation's epoch numbering, and `AUDIT_EPOCH_ALL` is a convention, not an
  enforced semantic (A2-remaining work).
- **NC-5 — No wallet/light tooling yet.** No CLI to build these txs, no
  determ-light reader for the `ak:`/`al:` leaves (the leaves are
  `state_proof`-provable today; the value is a hash, so a reader needs the
  pk/count preimage from history or RPC).
- **NC-6 — The `ak:` leaf is PUBLIC metadata.** Publishing a standing audit
  key reveals to every observer that the account has an auditor arrangement
  (and each LOG reveals a disclosure event, its epoch scope, and the auditor
  pubkey). This is by design — "audit the auditors" — but it is a privacy
  disclosure the account owner opts into.

## 4. Validation map

| Claim | Enforced in source | Witness | Status |
|---|---|---|---|
| **AL-1** owner-bind | validator.cpp:597-612 (anon allow-list + sig verify); block.cpp:17-29 (payload in signing_bytes) | every `test-audit-keys` block applies through the full signed path; existing tx-signature gates (test-transaction / test-tx-signing-bytes) | proven-in-code (no new bypass) |
| **AL-2** additive byte-invariance | chain.cpp:430-445 (conditional leaves), 1838-1847 / 1976-1981 (conditional snapshot), 774-775 (genesis clear) | FAST golden state-root corpus green with A2 compiled in; assertions 1-2, 7, 31, 34 | proven-in-code + golden-corpus witness |
| **AL-3** fail-closed shapes + unknown-type default | validator.cpp:1162-1195; chain.cpp:946-948, 963-964 (apply re-checks) | assertions 21-30 (five malformed shapes: no key/count/debit) | proven-in-code |
| **AL-4** last-writer-wins / leaf removal / monotone count | chain.cpp:951-953 (overwrite/erase), 967 (sole increment) | assertions 3-18 (set/rotate/clear/log lifecycle), 19-20 (fee-only + A1) | proven-in-code |
| **AL-5** rollback atomicity + snapshot round-trip | chain.cpp:691, 720-727, 655-658, 1689-1701 | assertions 31-35 (round-trip, byte-identical root); A9 rollback machinery shared with the shielded pool | proven-in-code (rollback path inherited, not separately fault-injected) |

Cross-references: [ShieldedPoolSoundness.md](ShieldedPoolSoundness.md) (the
§3.22 family whose conditional-emission and dual-ingress discipline A2
mirrors); [SupplyProofSoundness.md](SupplyProofSoundness.md) (the A1 identity
the fee-only accounting preserves); PRE-LAUNCH-DECISIONS.md A2 (the register
authority); CRYPTO-C99-SPEC.md §3.24 (the A1 view-key derivation this layer
publishes keys for).
