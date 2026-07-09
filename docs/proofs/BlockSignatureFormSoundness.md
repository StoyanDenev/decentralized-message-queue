# BlockSignatureFormSoundness — the A6 `Block.signature_form` discriminator (dormant, fail-closed, additive)

**Status:** SHIPPED 2026-07-09 (pre-launch register A5+A6, owner-decided
2026-07-09: the PQ-freeze block-signature discriminator; commit `9093189`).
Gated by `determ test-block-signature-form`
(14 assertions, in the FAST set via [tools/test_block_signature_form.sh](../../tools/test_block_signature_form.sh)),
the FB62 static cross-binary digest-parity guard
([tools/test_block_digest_xbinary_parity.sh](../../tools/test_block_digest_xbinary_parity.sh),
16 tokens), the live 3-node cluster + light block-verify, and the FAST golden
state-root corpus as the no-perturbation witness. Relates to
[PRE-LAUNCH-DECISIONS.md](../../PRE-LAUNCH-DECISIONS.md) A5+A6; the as-built
reconciliation of the §7.5.1 sketch is recorded inline in
[SchemaDiscriminatorsImpl.md](SchemaDiscriminatorsImpl.md) §2.2 (the SHIPPED
note, lines 73-75). Mirrors the `partner_subset_hash` / `state_root` zero-skip
discipline this feature reuses.

## 1. What shipped

One `uint8_t` field on `Block` and its enum constants
([include/determ/chain/block.hpp](../../include/determ/chain/block.hpp)):

- **`signature_form{0}`** (block.hpp:606) — gates how `creator_block_sigs[]` is
  interpreted. Constants: `SIG_FORM_KK_ED25519 = 0` (the shipped K-of-K Ed25519
  array — today's only form), `SIG_FORM_BLS12_381_AGGREGATE = 1` (reserved
  slot), `SIG_FORM_MLDSA_KK = 2` (the reserved PQ committee-signature target)
  (block.hpp:242-244). `0xFF` and every other value are forward-compat rejects.

Enforcement / encoding sites, all reusing the non-zero-only zero-skip pattern:
`signing_bytes()` trailing append ([src/chain/block.cpp](../../src/chain/block.cpp):359-366),
`to_json()` form-0 elision (block.cpp:518-521), `from_json()` S-018 range guard
(block.cpp:660-668), the producer digest tail
([src/node/producer.cpp](../../src/node/producer.cpp):703-714), the light-client
digest tail ([light/verify.cpp](../../light/verify.cpp):190-198), and the
validator fail-closed dispatch
([src/node/validator.cpp](../../src/node/validator.cpp):34-38).

## 2. Theorems (SF-1 .. SF-4)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green
`test-block-signature-form` assertion ([src/main.cpp](../../src/main.cpp):37261-37353)
or the FB62 static guard.

- **SF-1 (additive byte-invariance: an all-form-0 chain is byte-identical to a
  pre-A6 chain).** At every serialization site the discriminator is emitted
  only when non-zero: `signing_bytes()` appends the byte under
  `if (signature_form != 0)` at the TAIL, after `state_root` (block.cpp:364-366);
  `to_json()` writes the key only when non-zero (block.cpp:520-521); both digest
  sites append under the identical guard (producer.cpp:712-713; verify.cpp:196-197).
  Because every v1.1 block is form 0 (SF-4), each of these appends is skipped, so
  a v1.1 block's `signing_bytes`, `compute_hash`, committee digest, `to_json`,
  and snapshot are byte-identical to a chain built before the field existed.
  **Honest sub-point:** form 0 is *by definition* the pre-discriminator encoding
  — there is nothing to distinguish it from a no-discriminator block, and that
  is the point. The security phrasing "two blocks differing only in
  `signature_form` have distinct hashes" therefore holds for every NON-zero
  form; it does not apply to form 0 vs a no-field block, which are deliberately
  indistinguishable (SchemaDiscriminatorsImpl §2.2 reconciliation note 1).
  **Proven-in-code + witness:** the test asserts form 0 is elided from JSON, the
  absent key round-trips to 0, form 0 is hash-identical to the pre-A6 encoding,
  and form 0 keeps the byte-identical v1 digest (assertions 1-2, 6, 8); the FAST
  golden state-root corpus stays green with A6 compiled in (the field never
  enters `compute_state_root`, so its addition perturbs no existing chain).

- **SF-2 (digest-binding / no-relabel).** For a NON-zero form the byte is bound
  into the committee-signed `block_digest` (producer.cpp:712-713), so the K-of-K
  Phase-2 signatures cover the very discriminator that declares how those
  signatures are to be read. A relayer that relabels the sig array after signing
  changes the digest, and the signatures no longer verify. Binding is RAW (no
  reconciliation-root indirection) and this is safe because `signature_form` is
  a deterministic block field, not a gossip-async per-member view — every honest
  assembler digests the identical value — so the S-030-D2 §3.2 argument that
  licenses raw binding for `partner_subset_hash` applies unchanged
  (producer.cpp:703-711 comment). **Proven-in-code:** the test asserts the
  committee-signed digest differs between a form-0 and a form-2 copy of an
  otherwise-identical block, and that two form-0 copies digest identically
  (assertions 7-8); the block hash likewise differs form-0 vs form-2 (assertion 5).

- **SF-3 (producer↔light digest parity).** Both digest implementations append
  the byte under the identical `if (b.signature_form != 0)` guard in the
  identical field position — last, after `…partner_subset_hash, timestamp`
  (producer.cpp:712-713; verify.cpp:196-197). The scalar survives the
  `rpc_headers` strip (it is not one of the four heavy stripped collections), so
  a light client digests the same value the committee signed. Pinned STATICALLY
  by the FB62 guard: both function bodies reduce to the 16-token sequence
  `… PARTNER_SUBSET TIMESTAMP SIG_FORM`, and the load-bearing cross-site check
  asserts producer == light token-for-token (test_block_digest_xbinary_parity.sh:115,
  182); pinned DYNAMICALLY by the live cluster + light block-verify.
  **Proven-in-code (static + live).**

- **SF-4 (fail-closed dispatch: only form 0 accepted at v1.1).**
  `BlockValidator::validate` rejects any `signature_form != SIG_FORM_KK_ED25519`
  BEFORE any signature check runs (validator.cpp:34-38) — a block is never
  verified under a different sig interpretation than its discriminator declares.
  Reserved values 1 (BLS slot) and 2 (ML-DSA) and unknown values (incl. 0xFF)
  all reject at this one gate. The `from_json` S-018 guard closes the parse-side
  hole: a present `signature_form` key outside `[0, 0xFF]` throws rather than
  truncating into a DIFFERENT (possibly accepted) form (block.cpp:663-667).
  **Proven-in-code:** the test asserts forms 1, 2, and 0xFF each reject at the
  discriminator gate (diagnostic names `signature_form`), form 0 passes the gate
  (failing only later, unrelated checks), and the range guard rejects 256 and −1
  (assertions 3-4, 11-14).

## 3. Non-claims — READ BEFORE TREATING THE RESERVED SLOTS AS ACTIVE

- **NC-1 — The discriminator is DORMANT.** No non-zero form has an implemented
  verify path: BLS12-381 and ML-DSA committee signatures are not built, and the
  validator fail-closes on forms 1/2 (validator.cpp:34-38). A6 reserves the wire
  slot only, so a future activation is a value change, not a wire break
  (no-migrations). It does NOT itself provide PQ committee signatures.
- **NC-2 — No producer emits a non-zero form.** As with `partner_subset_hash`
  pre-R4, only `Block::from_json` / direct construction can carry a non-zero
  value today; every production and genesis block is form 0. The field's
  digest/hash binding is DEFENSIVE — it guarantees a future activation cannot
  ship the discriminator unbound.
- **NC-3 — Genesis is not gated.** `validate` returns at validator.cpp:27 for
  `index == 0` before the SF-4 gate, so a genesis block's `signature_form` is
  not rejected. This is not a gap: genesis carries no committee sigs and is
  trusted by the operator-pinned genesis hash, not by this dispatch; `make_genesis_block`
  produces form 0, so the pinned hash already fixes it.
- **NC-4 — The byte is opaque to state.** `signature_form` never enters
  `compute_state_root` or any account leaf; it is a header/consensus field only.
  SF-1's golden-corpus witness therefore attests non-perturbation of the state
  path, not the block-hash byte-invariance — that is witnessed directly by the
  test's form-0 hash/digest identity assertions.
- **NC-5 — Curve-family consistency is not yet enforced.** The SchemaDiscriminatorsImpl
  §5.2 invariant (block sig form ⟷ each creator's pubkey form) is vacuous at
  v1.1 (one form, one curve) and unimplemented; it becomes load-bearing only if
  a non-zero form is ever activated.

## 4. Validation map

| Claim | Enforced in source | Witness | Status |
|---|---|---|---|
| **SF-1** additive byte-invariance | block.cpp:364-366 (signing_bytes tail), 520-521 (json elision); producer.cpp:712-713 + verify.cpp:196-197 (digest skip) | assertions 1-2, 6, 8 (form-0 elided/round-trip/hash-identical/digest-identical); FAST golden state-root corpus green with A6 compiled in | proven-in-code + witness |
| **SF-2** digest-binding / no-relabel | producer.cpp:703-714 (raw bind, deterministic per S-030-D2 §3.2) | assertions 5, 7-8 (form-0 vs form-2 hash + digest distinct; form-0 pairs identical) | proven-in-code |
| **SF-3** producer↔light parity | producer.cpp:712-713 ≡ verify.cpp:196-197 (same guard, same tail position) | FB62 static guard (16 tokens, cross-site producer==light + SELFTEST); live cluster + light block-verify | proven-in-code (static + live) |
| **SF-4** fail-closed dispatch + range guard | validator.cpp:34-38 (pre-sig reject); block.cpp:663-667 (S-018 range guard) | assertions 3-4, 11-14 (forms 1/2/0xFF reject, form 0 passes gate, 256/−1 rejected) | proven-in-code |

Cross-references: [SchemaDiscriminatorsImpl.md](SchemaDiscriminatorsImpl.md) §2.2
(the §7.5.1 sketch this refines — zero-skip-at-tail vs the sketch's "emit
unconditionally before `creator_block_sigs`") + §3.2/§9.1 (dispatch table, FIPS
uses the same slot); [ChainStorageV1.md](ChainStorageV1.md) /
[AuditLayerSoundness.md](AuditLayerSoundness.md) (the additive / golden-corpus
house style this proof follows); PRE-LAUNCH-DECISIONS.md A5+A6 (the register
authority + the PQ-freeze scope).
