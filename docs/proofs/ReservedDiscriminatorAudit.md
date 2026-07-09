# ReservedDiscriminatorAudit — B4 pre-genesis reserved-slot inventory: keep only with a named future

**Status: WORKING AUDIT (decision-support, no code changed by this document).** This is the pre-genesis reserved-slot audit ordered 2026-07-09 as register item **B4** ([PRE-LAUNCH-DECISIONS.md](../../PRE-LAUNCH-DECISIONS.md) §B4: "pre-genesis audit of every reserved discriminator; keep only slots with a plausible, NAMED future use, one-line rationale per keep/drop"). It inventories every reserved-but-unused discriminator/slot/flag in the wire format and the genesis schema, and gives each a KEEP/DROP verdict. **The integrator executes the DROP verdicts serially** (§7 execution order), each behind its named gate — nothing is deleted here. Every claim below was verified against the tree on 2026-07-09; each row carries a file anchor.

**Fresh register decisions that CHANGE verdicts** (all owner-decided 2026-07-09, [PRE-LAUNCH-DECISIONS.md](../../PRE-LAUNCH-DECISIONS.md)):

- **(a) B2 + A7** — FROST and the RingCT/LSAG/CLSAG libraries are DELETED. Any FROST-tied slot has lost its named future.
- **(b) A5 + A6** — on-chain PQ IS a launch capability: hash-based PQ anon-address + `signature_form` enum {Ed25519 K-of-K, ML-DSA}. PQ-reserved slots at the *block-sig* layer now have a NAMED future.
- **(c) A8** — hierarchical sharding is DROPPED outright. Any slot reserved for it loses its future (finding: **none exists** — §6.1).
- **(d) D3** — launch posture is EXTENDED sharding; SHARD_TIP/v2.11 will be built. EXTENDED-tied slots (region rebalancing, merged-committee fields) have a named future.

**Companion documents.** [SchemaDiscriminatorsImpl.md](SchemaDiscriminatorsImpl.md) — the §7.5 discriminator catalog this audit cross-checks (spec-only; §10 "Implementation. Pending." — verified: zero `signature_form` / `sig_form` / `pubkey_form` / `POLICY_` hits in `src/` + `include/`). [Improvements.md](Improvements.md) §7.5/§7.6 — the SHIP-or-skip decision artifact. [DECISION-LOG.md](DECISION-LOG.md) 2026-05-24 + 2026-06-03 entries — the original ship decisions; drops below that reverse a prior SHIP are flagged as such. [F2ViewReconciliationAnalysis.md](F2ViewReconciliationAnalysis.md) — F2 gate status (its "zero readers" banner is stale; see §6.2). [V210ImplementationRoadmap.md](V210ImplementationRoadmap.md) — the (now moot) v2.10 FROST activation plan.

**What a kept reserved slot buys — and what it doesn't.** Under no-migrations + the fail-closed unknown-value rule ([SchemaDiscriminatorsImpl.md](SchemaDiscriminatorsImpl.md) §3.4), a reserved slot does NOT enable silent post-launch activation — a v1.0 validator rejects any new value regardless. What it buys: (1) a stable wire SHAPE so a genesis-pinned activation height can gate the new behavior (the `v2_7_f2_active_from_height` pattern), and (2) per-deployment optionality — new chains built from the same codebase can enable a different value without a format fork. A kept dead slot is therefore permanent audit surface purchased against exactly these two uses; a slot with no named consumer of either use is dead weight.

**Line-number caveat.** The B2 purge executed in the working tree in parallel with this audit (FROST/RingCT sources already absent; `src/main.cpp` test-section line numbers drifted as FROST test blocks were deleted). `src/main.cpp` anchors below are therefore given by check-string, not line number. All other anchors were read at their cited lines this session and are unaffected by the purge.

---

## 1. Summary table

Verdict key: **KEEP** = named future confirmed; **DROP** = no named future survives the fresh decisions; rows reversing a prior owner SHIP decision are marked ⚠ (integrator surfaces them for owner confirmation before executing).

| # | Slot | Location | Current state | Named future use | Verdict | Dropping byte-invariant? |
|---|------|----------|---------------|------------------|---------|--------------------------|
| G-1 | `GenesisConfig::v2_10_active_from_height` | formerly [genesis.hpp](../../include/determ/chain/genesis.hpp) (field deleted) | Was declared; **zero readers in `src/`**; NOT parsed by `from_json`, NOT emitted by `to_json`, NOT hash-mixed | **NONE** — the FROST v2.10 threshold-randomness gate; FROST deleted (B2) | **DROP — EXECUTED 2026-07-09** | **YES** — field was never serialized nor hashed; pure struct-field delete (byte-invariance confirmed by goldens) |
| G-2 | `GenesisConfig::v2_7_f2_active_from_height` | [genesis.hpp:220](../../include/determ/chain/genesis.hpp) | LIVE reader: [node.cpp:202](../../src/node/node.cpp) → `Chain::set_f2_active_from_height` ([chain.hpp:316](../../include/determ/chain/chain.hpp)) | v2.7 F2 view reconciliation — ACTIVE feature gate | **KEEP** | n/a (see §6.2 coherence note) |
| G-3 | `TxType::REGION_CHANGE = 5` | [block.hpp:34](../../include/determ/chain/block.hpp); reject at [validator.cpp:587](../../src/node/validator.cpp) | Wire slot locked; validator rejects unconditionally, no apply path | v2 epoch-boundary region rebalancing under EXTENDED regional sharding (plan.md Path A; D3 launches EXTENDED) | **KEEP** | n/a |
| G-4 | `Block::partner_subset_hash` | [block.hpp:533](../../include/determ/chain/block.hpp) | DORMANT — no producer sets it; zero-default omitted from JSON + digest; defensively digest-bound when non-zero | R4 Phase 3 merged-committee block production (MERGE_EVENT Phases 1–2 already live; D3 EXTENDED launch) | **KEEP** | n/a |
| W-1 | Binary envelope reserved byte (offset 3) | [binary_codec.cpp:48](../../src/net/binary_codec.cpp) | Always 0x00 on encode; all three binaries REJECT non-zero on decode (asymmetry FIXED 2026-07-09 — see §6) | Wire-v1 flag byte (evolution inside the v1 frame without a version bump) + 4-byte header alignment | **KEEP** (weakest keep) | **NO** — reshapes every binary frame across 3 binaries |
| W-2 | TRANSACTION amount-block reserved u64 (frame bytes 56..63) | [binary_codec.cpp:222](../../src/net/binary_codec.cpp), reject [.:269-271](../../src/net/binary_codec.cpp) | Zero-enforced on encode AND decode; light mirrors the reject | 4th u64 lane of the plan-§A3 256-bit amount block — carrier for a future per-tx u64 (e.g. valid-until height) without frame reshape | **KEEP** | **NO** — 128-byte frame → 120, breaks the 4×256-bit invariant |
| S-1 | `Block.signature_form` (§7.5.1) | [SchemaDiscriminatorsImpl.md](SchemaDiscriminatorsImpl.md) §2.2 | Spec-only (no code) | **A6 owner-confirmed SHIP**: enum {Ed25519 K-of-K, ML-DSA} | **KEEP** (owner-decided) | n/a — not in code |
| S-1a | · value `SIG_BLS12_381_AGGREGATE = 1` | §2.2 | Reserved enum value | **NONE** — MODERN = no-new-crypto (2026-07-07 posture decision) + FROST purge | **DROP** | YES — spec edit only |
| S-1b | · ML-DSA K-of-K value (spec'd `SIG_DILITHIUM_KK = 2`) | §2.2 | Reserved enum value | A5+A6 launch PQ block-sig form | **KEEP** (renumber to =1 is free pre-genesis) | n/a |
| S-2 | `Transaction.sig_form` (§7.5.6) | §2.7 | Spec-only | **Superseded** — tx-level PQ shipped as `PQ_TRANSFER` + `pq_auth` ([block.hpp:189](../../include/determ/chain/block.hpp)); BLS tx sigs unnamed | **DROP** ⚠ | YES — spec/plan edit only |
| S-3 | `pubkey_form` + variable-length PubKey records (§7.5.7) | §2.8 | Spec-only | **Gutted** — 2026-07-03 owner freeze of the anon-address formula + A5's separate hash-based PQ address format | **DROP** ⚠ | YES — spec/plan edit only |
| S-4 | `Account.view_key_mechanism` (§7.5.2) | §2.3 | Spec-only | Dispatch byte for the A1/A2 launch CT view-key layer | **KEEP** | n/a |
| S-4a | · values `FSE = 1`, `PUNCTURABLE = 2` + `fs_view_pk` companion | §2.3 | Reserved values + optional field | **NONE** — no design doc names either mechanism | **DROP** | YES — spec edit only |
| S-5 | `Account.audit_model` (§7.5.3) | §2.4 | Spec-only | Dispatch byte for the A2 FULL audit layer (`KEY_DISCLOSURE = 0` live at launch) | **KEEP** | n/a |
| S-5a | · value `TRUSTED_ISSUER = 1` + `trusted_issuer_pubkey` companion | §2.4 | Reserved value + optional field | §1.8 trusted-issuer audit as deployment opt-in ([DECISION-LOG.md](DECISION-LOG.md) 2026-06-03; pairs with policy bit 0) | **KEEP** (stands/falls with S-8 bit 0) | n/a |
| S-5b | · values `ZK_BASED_AUDIT = 2`, `NO_AUDIT = 3` | §2.4 | Reserved values | **NONE** — names only, no design | **DROP** | YES — spec edit only |
| S-6 | `manifest.randomness_aggregation_form` (§7.5.4) | §2.5 | Spec-only; rides the UNBUILT Beaconless-v2 manifest | **NONE** — default `THRESHOLD_SIG_ACCUMULATOR` was FROST-class threshold aggregation (B2); Beaconless v2 is not in the decided launch plan | **DROP** ⚠ | YES — spec edit only |
| S-7 | `ContribMsg.contrib_msg_form` (§7.5.5) + values `IBLT_PAYLOAD`, `MINISKETCH_PAYLOAD` | §2.6 | Spec-only | [Improvements.md](Improvements.md) §6.4 tx-set reconciliation (gossip bandwidth); untouched by fresh decisions; consensus-path record where no-migrations forecloses retrofit hardest | **KEEP** | n/a |
| S-8 | `policy_tier_flags` bits 0, 1, 2, 4 (§7.5.10) | [Improvements.md](Improvements.md) §7.6.8 (lines 667-673) | Spec-only u32 bitset, zero-enforced | §1.8 opt-in (bit 0) / §5.2 external audit (bit 1) / §5.5 HW-wallet tier (bit 2) / §6.2 BFT-threshold finalization (bit 4) | **KEEP** — with RE-HOME caveat (§4.8: its spec'd home, the Beaconless-v2 manifest, is unbuilt; must land on `GenesisConfig` instead) | n/a |
| S-8a | · bit 3 (`POLICY_TIER_BONDS_ENABLED`) | [Improvements.md](Improvements.md) line 672 | Vestigial NAMED reservation (7.5.8 skipped) | **NONE** — the renumbering-safety rationale presumes a v3 protocol opening, which under no-migrations is a new chain that renumbers freely | **DROP** (demote the name; bit becomes ordinary headroom) | YES — spec edit only |
| S-8b | · bits 5..31 | [Improvements.md](Improvements.md) line 673 | Zero-enforced headroom | Generic future policy opt-ins (the canonical opt-in pattern, DECISION-LOG 2026-06-03) | **KEEP** | n/a |
| S-9 | `Block.quorum_bitset` (§7.5.11) | [DECISION-LOG.md](DECISION-LOG.md) 2026-06-03 (7.5.11 SHIP) | Spec-only; default all-1s ≡ current K-of-K | §6.2 Quorum-Liveness BFT-threshold finalization (pairs with bit 4; shipped specifically so bit 4 is not vestigial) | **KEEP** | n/a |

**Tally: 22 rows — 14 KEEP, 8 DROP, 0 UNRESOLVED.** Exactly **one** DROP touches code (G-1), and it is byte-invariant. No recommended drop changes serialization shape (W-1/W-2, the only shape-affecting candidates, are KEEP).

---

## 2. Code-level slots — genesis schema

### 2.1 G-1 `v2_10_active_from_height` — DROP (the prime drop) — **EXECUTED 2026-07-09**

> **EXECUTED 2026-07-09:** the field is deleted from `genesis.hpp` and both operator tools no longer display the key; gate passed — build + genesis goldens byte-identical + genesis-determinism green + both tools run. The facts below record the pre-execution audit state.

[genesis.hpp:228](../../include/determ/chain/genesis.hpp) declared the v2.10 FROST threshold-randomness activation height "parallel to the shipped `v2_7_f2_active_from_height`". Verified facts:

- **Zero readers in `src/`.** The planned consumer (producer/validator branch, [V210ImplementationRoadmap.md](V210ImplementationRoadmap.md) Phase D) never landed. The only other code reference ever was a comment in the FROST header (`include/determ/crypto/frost.hpp`) — already GONE: the B2 purge executed in the working tree while this audit ran, so the declaration at [genesis.hpp:228](../../include/determ/chain/genesis.hpp) was the field's sole remaining code site (deleted with this drop).
- **Not serialized.** `GenesisConfig::to_json` ([genesis.cpp:49-99](../../src/chain/genesis.cpp)) does not emit it; `from_json` ([genesis.cpp:101-280](../../src/chain/genesis.cpp)) does not parse it. A genesis JSON carrying the key is silently ignored today.
- **Not hash-mixed.** Neither the conditional mixins ([genesis.cpp:392-423](../../src/chain/genesis.cpp)) nor the unconditional `DTM-genesis-ops-v1` block ([genesis.cpp:440-452](../../src/chain/genesis.cpp)) touch it. **Dropping changes no existing genesis hash for ANY genesis file, zero-default or otherwise** — the field simply does not exist outside the C++ struct.
- FROST is deleted under B2 → the named future ("DKG ceremony + FROST-Ed25519 threshold aggregation") is gone. A future non-FROST randomness upgrade would get its own gate field on its own reviewed design; carrying this one buys nothing.

Collateral for the integrator (non-code): [operator_genesis_diff.sh](../../tools/operator_genesis_diff.sh) (lines 334-337, 362) and [operator_genesis_inspect.sh](../../tools/operator_genesis_inspect.sh) (lines 277-282) display the JSON key the loader never honored; `docs/CLI-REFERENCE.md` mentions it once. Drop those display lines in the same commit.

### 2.2 G-2 `v2_7_f2_active_from_height` — KEEP

[genesis.hpp:220](../../include/determ/chain/genesis.hpp). Unlike G-1 this has a live consumer: [node.cpp:202](../../src/node/node.cpp) copies it at boot and [node.cpp:560](../../src/node/node.cpp) installs it via `Chain::set_f2_active_from_height` ([chain.hpp:311-317](../../include/determ/chain/chain.hpp)), gating the F2 producer/validator paths. F2 is a shipped launch feature (default 0 = active from genesis). Named use: it IS the activation-height pattern this audit's preamble describes. Coherence gap (not a verdict-changer) recorded in §6.2.

### 2.3 G-3 `TxType::REGION_CHANGE = 5` — KEEP

[block.hpp:29-34](../../include/determ/chain/block.hpp): "reserved for v2 epoch-boundary region rebalancing (Resolved decision #1 in plan.md, Path A). NO apply path in v1.x." The validator rejects it unconditionally at [validator.cpp:587-591](../../src/node/validator.cpp) (and again at :666), so the slot is fail-closed. The named future — moving a validator's region tag at an epoch boundary — is a *flat* EXTENDED-sharding maintenance operation, not hierarchical sharding, so decision (c) does not kill it and decision (d) (EXTENDED launch posture) strengthens it. Cost of keeping: one reject branch. Cost of dropping: nothing gained — the value would just become an unknown-`TxType` reject instead of a diagnostic one, and later types (PARAM_CHANGE=6 … CONFIDENTIAL_TRANSFER=14) keep their numbers either way. Enum value pinned by the `src/main.cpp` check `"TxType::REGION_CHANGE == 5 (reserved for v2 epoch-boundary rebalancing)"`.

### 2.4 G-4 `Block::partner_subset_hash` — KEEP

[block.hpp:533](../../include/determ/chain/block.hpp), explicitly documented DORMANT at v1.1: no production path sets a non-zero value (only `Block::from_json` at [block.cpp:641-643](../../src/chain/block.cpp) can carry one). It is serialized only when non-zero ([block.cpp:506-507](../../src/chain/block.cpp)) and digest-bound only when non-zero ([producer.cpp:685-686](../../src/node/producer.cpp), [block.cpp:338-339](../../src/chain/block.cpp)) — so keeping it costs zero bytes on every existing block. Named future: R4 Phase 3 merged-committee production, whose Phases 1–2 (MERGE_EVENT trigger/apply, merge-state map) are already live in [chain.cpp](../../src/chain/chain.cpp), and whose launch relevance is set by D3 (EXTENDED). The defensive digest binding exists precisely so the Phase-3 producer cannot ship with the field unbound.

### 2.5 Genesis fields audited and found live (not reserved)

For completeness — every remaining `GenesisConfig` field with a zero-default/"mixed only when non-zero" pattern was checked and has a live consumer, so none is a reserved slot: `genesis_message` (conditional mix, [genesis.cpp:392-395](../../src/chain/genesis.cpp)), `governance_mode`/`param_keyholders`/`param_threshold` (conditional mix :401-407; `PARAM_CHANGE` apply/validate implemented — 60+ references across [validator.cpp](../../src/node/validator.cpp)/[chain.cpp](../../src/chain/chain.cpp)/[node.cpp](../../src/node/node.cpp)), `suspension_slash`/`unstake_delay` (:411-414), merge thresholds (:417-423, R4 live), `zeroth_pool_initial` (E1 NEF pool, bound via `initial_state` when non-zero), `subsidy_mode`+`lottery_jackpot_multiplier` (E3, both values implemented; values >1 rejected at load [genesis.cpp:132-136](../../src/chain/genesis.cpp)), `inclusion_model` (both values implemented — [registry.cpp:54](../../src/node/registry.cpp), [chain.cpp:1475](../../src/chain/chain.cpp); see §6.4 for a hash-mix observation), `chain_role`/`shard_id`/`initial_shard_count`/`epoch_blocks`/`shard_address_salt` (rev.9 sharding, live), `committee_region` (R1, live).

---

## 3. Code-level slots — wire format

### 3.1 W-1 Binary envelope reserved byte (offset 3) — KEEP

Layout `[magic 0xB1][version 0x01][msg_type][reserved 0x00]` ([binary_codec.cpp:43-49](../../src/net/binary_codec.cpp)); zeroed on encode (:313). This is the weakest KEEP in the audit: its named use — a flag byte for wire-v1 evolution (e.g. a compression bit) without a version bump, plus 4-byte header alignment — is generic. It survives the razor on cost asymmetry: keeping costs 1 byte/frame with determinism enforced; dropping reshapes every binary frame across daemon, light ([light/main.cpp](../../light/main.cpp) wire-audit path), and wallet frame-inspect ([wallet/main.cpp](../../wallet/main.cpp)), regenerating the cross-binary parity goldens, for a 1-byte saving. The adjacent `version` byte (checked at decode, [binary_codec.cpp:358-359](../../src/net/binary_codec.cpp)) already provides versioned evolution and is live, not reserved. **Enforcement asymmetry found — FIXED 2026-07-09 (see §6).**

### 3.2 W-2 TRANSACTION amount-block reserved u64 (frame bytes 56..63) — KEEP

The fixed 1024-bit tx frame carries `[amount][fee][nonce][reserved]` as its 256-bit amount block ([binary_codec.cpp:218-222](../../src/net/binary_codec.cpp)). Unlike W-1 it is zero-enforced on BOTH sides — encode writes 0 and decode throws on non-zero ([binary_codec.cpp:269-271](../../src/net/binary_codec.cpp)); the light client mirrors the reject ([light/main.cpp:7055-7057](../../light/main.cpp) at audit time). Named use: it is the 4th u64 lane of the plan-§A3 4×256-bit frame design and the only place a future per-tx u64 (e.g. a valid-until expiry height — a commonly wanted anti-replay/anti-stale field) can land without reshaping the frame. Transport-layer only (NOT part of `signing_bytes`), so a future assignment is a codec change, not a consensus change. Dropping shrinks the frame 128→120 bytes and breaks the fixed-frame invariant plus the daemon/light/wallet decoder triple and `tools/test_cross_binary_tx_parity*.sh` — permanent-regret risk for an 8-byte saving.

### 3.3 Wire surfaces audited and found not-reserved

- **MsgType 0..18** ([messages.hpp:13-82](../../include/determ/net/messages.hpp)) — all 19 values live, no gaps. 19..255 is ordinary enum headroom, fail-closed: light rejects out-of-range, daemon's `max_message_bytes` default branch caps unknowns at 1 MB (:143-151), and a `src/main.cpp` test casts a "future-reserved value (e.g., 200)" through MsgType to pin the behavior. No action.
- **Wire versions** `kWireVersionLegacy=0` / `kWireVersionBinary=1` ([messages.hpp:90-92](../../include/determ/net/messages.hpp)) — both live (HELLO negotiation). No action.
- **Snapshot `version` field** — emitted as `1` at [chain.cpp:1681](../../src/chain/chain.cpp), restore rejects ≠1 at [chain.cpp:1860-1863](../../src/chain/chain.cpp). Live discriminator, not reserved. No action.
- **`Transaction.pq_auth`** ([block.hpp:255](../../include/determ/chain/block.hpp)) — serialized only when non-empty, but LIVE (§3.21 PQ_TRANSFER, launch capability per A5). Not reserved.
- **Enums with full coverage**: `ChainRole` {SINGLE, BEACON, SHARD} and `ShardingMode` {NONE, CURRENT, EXTENDED} ([types.hpp:26-50](../../include/determ/types.hpp)) — every value used by the shipped [params.hpp](../../include/determ/chain/params.hpp) profiles; `ConsensusMode` {MUTUAL_DISTRUST, BFT} both live; `InclusionModel` {STAKE, DOMAIN} both live. No reserved enum values anywhere in code.

---

## 4. Spec-level slots — the §7.5 pre-genesis discriminator catalog

None of the seven §7.5 discriminators exists in code (verified by tree-wide grep; [SchemaDiscriminatorsImpl.md](SchemaDiscriminatorsImpl.md) §10 concurs: "Implementation. Pending."). They are nonetheless genesis-schema surface: Bundle 0 is a MAINNET_READINESS criterion, so **these verdicts decide what Bundle 0 builds**. A spec-level DROP costs zero bytes anywhere — it is an edit to the catalog + sequencing docs — but several reverse pieces of the 2026-05-24/06-03 SHIP sweep and are marked ⚠ for owner confirmation, exactly as B4's newer razor entitles.

### 4.1 S-1 `Block.signature_form` — KEEP (owner-decided, A6)

Not this audit's call: A6 confirms SHIP with the enum covering Ed25519 K-of-K + ML-DSA. Sub-verdicts on its reserved values: **S-1a `SIG_BLS12_381_AGGREGATE=1` DROP** — BLS aggregation's named path was the old MODERN-profile idea; the 2026-07-07 crypto-posture decision (MODERN = Ed25519+X25519+P-256, "no new crypto") plus the FROST purge leaves no named consumer, and A6's enum names exactly two forms. **S-1b ML-DSA form KEEP** (the spec's `SIG_DILITHIUM_KK` under its FIPS-204 name; renumbering to =1 is free pre-genesis). The 0xFF fail-closed marker pattern stays (costless).

### 4.2 S-2 `Transaction.sig_form` — DROP ⚠ (supersession)

The spec reserved `SIG_DILITHIUM=1` / `SIG_BLS12_381=2` for future tx-sig schemes. Both futures are now dead or superseded: (i) tx-level PQ **shipped** as `PQ_TRANSFER` + the `pq_auth` DPQ1 envelope ([block.hpp:180-189, 251-255](../../include/determ/chain/block.hpp)) — the chain's proven, additive pattern is *scheme = new TxType*, not a per-tx discriminator byte; A5 freezes launch PQ on that pattern. (ii) BLS tx sigs have no named future (same posture decision as S-1a). Keeping a second, unused dispatch mechanism for the same job is dead optionality on EVERY transaction forever. Reverses part of the 2026-05-24 SHIP — owner confirm before executing. Bundle-0 scope shrinks ~1-2 days.

### 4.3 S-3 `pubkey_form` + variable-length PubKey records — DROP ⚠ (supersession)

The §7.5.7 retrofit (+3 bytes on every pubkey field, ~3-5 days + fixture regeneration) had one load-bearing purpose: binding the form byte into address derivation to prevent cross-form address aliasing ([SchemaDiscriminatorsImpl.md](SchemaDiscriminatorsImpl.md) §4). That purpose was **removed by the owner on 2026-07-03**: the anon-address formula is FROZEN as Ed25519-only raw-hex "for the chain's lifetime" (§4.5 RESOLVED banner). A5 then gave PQ its own separate hash-based address format (`is_pq_anon_address`, live in [pq_address.cpp](../../src/crypto/pq_address.cpp)) with ML-DSA keys traveling inside DPQ1 envelopes — never inside `from`/`to` PubKey32 fields. Cross-form aliasing is prevented by format disjunction, not by a form byte. `PUBKEY_BLS12_381`/`PUBKEY_DILITHIUM` values fall with it. This is the largest avoided Bundle-0 lift. Reverses a 2026-05-24 SHIP — owner confirm.

### 4.4 S-4 `Account.view_key_mechanism` — KEEP byte, DROP unnamed values

The byte itself gates the A1/A2 launch CT view-key layer (a launch build item; the B3 spec rewrite re-specifies the Account schema against the as-built P-256 pool, and this dispatch byte is where the ratified per-epoch-HKDF mechanism registers). **S-4a DROP**: `FSE=1`, `PUNCTURABLE=2` and the `fs_view_pk` companion field — no design document names forward-secure or puncturable view keys anywhere in the corpus; the companion's presence rule is keyed entirely on the dropped values.

### 4.5 S-5 `Account.audit_model` — KEEP byte, split values

`KEY_DISCLOSURE=0` is the live launch value (A2 FULL audit layer). **S-5a KEEP**: `TRUSTED_ISSUER=1` + `trusted_issuer_pubkey` — named future via the DECISION-LOG 2026-06-03 reclassification of §1.8 from principle-rejected to *deployment opt-in* (the canonical policy-bit pattern; pairs with S-8 bit 0 — the two stand or fall together). **S-5b DROP**: `ZK_BASED_AUDIT=2`, `NO_AUDIT=3` — bare enum names with no design behind them.

### 4.6 S-6 `manifest.randomness_aggregation_form` — DROP ⚠

Doubly dead: its home (the Beaconless-v2 deployment manifest, Bundle 5) is not in the decided launch plan and exists nowhere in code, and its default value `THRESHOLD_SIG_ACCUMULATOR` named FROST-class threshold aggregation as the implementation basis — deleted under B2. `VRF_PER_SHARD=1` has no named plan either. If a Beaconless architecture is ever revived, it arrives as a new reviewed design (new chains, per the no-migrations logic) and can define its own manifest. Reverses a 2026-05-24 SHIP — owner confirm.

### 4.7 S-7 `ContribMsg.contrib_msg_form` — KEEP

Named future intact: [Improvements.md](Improvements.md) §6.4 IBLT / minisketch tx-set reconciliation (`IBLT_PAYLOAD=1`, `MINISKETCH_PAYLOAD=2` both named there), a pure bandwidth optimization untouched by decisions (a)–(d). ContribMsgs are the highest-rate consensus-path record; this is the surface where a foreclosed wire slot would hurt most and the keep cost is 1 byte per contrib.

### 4.8 S-8 `policy_tier_flags` — KEEP bits 0/1/2/4 with a RE-HOME caveat; DROP bit 3

Bits 0 (§1.8 trusted-issuer opt-in), 1 (§5.2 external audit), 2 (§5.5 HW-wallet certification), 4 (§6.2 BFT-threshold finalization) each carry a named, documented future and the zero-enforced bitset pattern costs nothing until set. **Caveat the integrator must resolve**: the catalog homes this field on the Beaconless-v2 manifest ([Improvements.md](Improvements.md) §7.6.8), which per §4.6 is unbuilt and staying unbuilt — if Bundle 0 ships the field, it must land on `GenesisConfig` (genesis-pinned u32, hash-mixed) instead. **S-8a bit 3 DROP**: `POLICY_TIER_BONDS_ENABLED` is the register's own poster-child vestige — 7.5.8 was skipped, so there is no tier field to enforce against, and the kept-for-renumbering rationale presumes a "v3 protocol opening," which under no-migrations means a new chain that can renumber freely. Demote the name; the bit joins the 5..31 headroom (S-8b, KEEP).

### 4.9 S-9 `Block.quorum_bitset` — KEEP

Shipped as 7.5.11 specifically so bit 4 would not be vestigial ([DECISION-LOG.md](DECISION-LOG.md) 2026-06-03). Default all-1s is semantically identical to current K-of-K, validator short-circuits, cost 1-16 bytes/block by profile K. Its named future (§6.2 optional 2f+1 finalization) is untouched by (a)–(d). Dependency note for the integrator: S-9, S-8 bit 4, and §6.2 form one keep/drop unit.

---

## 5. Findings against decisions (c) and (d)

- **(c) Hierarchical sharding (A8, dropped):** exhaustive search found **no reserved slot for it anywhere** — no enum value beyond `ShardingMode::EXTENDED`, no hierarchical-VRF field, nothing in the §7.5 catalog. There is nothing to execute; the A8 drop is already schema-clean.
- **(d) v2.11 SHARD_TIP (D3, to be built):** no *reserved* slot exists yet — `MsgType::SHARD_TIP=13` is live (B2c.3 tip gossip), and the on-chain SHARD_TIP record is a new build item, not a reservation. No slot in this audit is rescued *solely* by (d); it strengthens G-3 and G-4.

---

## 6. Side observations (recorded for the integrator; NOT slot verdicts)

1. **Envelope reserved-byte enforcement asymmetry (W-1) — FIXED 2026-07-09.** `decode_binary` previously IGNORED offset-3 while the light client throws `WireMalformed` on non-zero ([light/main.cpp:7169](../../light/main.cpp)) and wallet frame-inspect reports `reserved_ok=false`; per the S-043 lesson (every enforcement rule needs both halves) the daemon now REJECTS non-zero fail-closed ([binary_codec.cpp](../../src/net/binary_codec.cpp)), pinned by 3 new `test-binary-codec` assertions — light/wallet behavior unchanged (they already rejected). The fix pass also repaired 8 rc-captured-after-pipe bugs in the wallet wrapper that were masking its own exit-code assertions (`test_wallet_decode_wire_frame.sh`, now 47/47).
2. **G-2 is not settable from genesis JSON.** `from_json` never parses `v2_7_f2_active_from_height` ([genesis.cpp:101-280](../../src/chain/genesis.cpp)), so the documented `UINT64_MAX` = "never activate" sentinel ([genesis.hpp:219](../../include/determ/chain/genesis.hpp)) is unreachable for operators, while [operator_genesis_inspect.sh](../../tools/operator_genesis_inspect.sh)/[operator_genesis_diff.sh](../../tools/operator_genesis_diff.sh) display a JSON key the loader silently ignores. Also the [F2ViewReconciliationAnalysis.md](F2ViewReconciliationAnalysis.md) banner's "zero readers in `src/`" claim is stale (reader landed at [node.cpp:202](../../src/node/node.cpp)). Decide: wire the parse (+ hash-mix question) or delete the sentinel promise and the tool lines.
3. **`inclusion_model` is absent from the genesis-hash mix.** The S-039 fix bound "ALL consensus-critical operational parameters" unconditionally ([genesis.cpp:424-452](../../src/chain/genesis.cpp)), but `inclusion_model` is not in the list — two operators differing only in it (with equal `min_stake`, e.g. both 0) compute the SAME genesis hash with different admission/disincentive semantics. `min_stake` (which IS mixed) masks the common case since DOMAIN_INCLUSION pins it to 0. Pre-genesis is the free window to add it to the ops-v1 block (changes all genesis hashes → gate on the genesis golden suite).

---

## 7. Integrator execution order — DROP verdicts, safest first

All eight drops are byte-invariant (one code drop that touches no serialization; seven spec/plan edits). **No serialization-shape-affecting drop is recommended — that tier is intentionally empty** (W-1/W-2 were the only candidates and both are KEEP). Execute serially, each behind its gate:

| Order | Drop | Kind | Gate |
|-------|------|------|------|
| 1 | **G-1** `v2_10_active_from_height` (+ operator-tool display lines, CLI-REFERENCE mention) | Code (header field, zero readers) | Build + FAST both platforms; genesis goldens byte-identical: [test_genesis.sh](../../tools/test_genesis.sh), [test_genesis_determinism.sh](../../tools/test_genesis_determinism.sh), [test_determ_genesis_roundtrip_offline.sh](../../tools/test_determ_genesis_roundtrip_offline.sh), [test_make_genesis_block.sh](../../tools/test_make_genesis_block.sh), [test_verify_genesis.sh](../../tools/test_verify_genesis.sh); natural rider on the B2 purge commit (purge already executed in-tree; its commit removed the field's only comment-referencing header) — **EXECUTED 2026-07-09, gate passed (goldens byte-identical)** |
| 2 | **S-8a** bit 3 `POLICY_TIER_BONDS_ENABLED` → demote to headroom | Spec edit ([Improvements.md](Improvements.md):672, §7.6.9; catalog) | Doc guards: [test_docs_link_check.sh](../../tools/test_docs_link_check.sh), [test_proofs_index_complete.sh](../../tools/test_proofs_index_complete.sh), [test_doc_tier_check.sh](../../tools/test_doc_tier_check.sh), [test_doc_citation_bounds.sh](../../tools/test_doc_citation_bounds.sh); DECISION-LOG entry |
| 3 | **S-6** `randomness_aggregation_form` (whole slot) | Spec edit ⚠ owner confirm (reverses 2026-05-24 SHIP) | Same doc guards; DECISION-LOG entry |
| 4 | **S-1a** `SIG_BLS12_381_AGGREGATE` value (+ renumber ML-DSA form) | Spec edit | Same doc guards; must land BEFORE Bundle 0 implements S-1 |
| 5 | **S-4a** `FSE`/`PUNCTURABLE` + `fs_view_pk` companion | Spec edit | Same doc guards; natural vehicle = the B3 v2.22 rewrite (Account schema is re-specified there anyway) |
| 6 | **S-5b** `ZK_BASED_AUDIT`/`NO_AUDIT` values | Spec edit | Same as 5 (same section, same vehicle) |
| 7 | **S-2** `Transaction.sig_form` (whole slot) | Plan-scope edit ⚠ owner confirm | Doc guards + IMPLEMENTATION-SEQUENCING Bundle-0 scope update (−1-2 days); DECISION-LOG entry citing PQ_TRANSFER supersession |
| 8 | **S-3** `pubkey_form` + variable-length PubKey records (whole slot) | Plan-scope edit ⚠ owner confirm (largest scope change) | Doc guards + Bundle-0 scope update (−3-5 days, fixture regen avoided); DECISION-LOG entry citing the 2026-07-03 address freeze + A5 format disjunction |

Sequencing rationale: 1 is the only code touch and is provably inert (no serialization, no hash, no reader); 2–6 shrink pure spec surface with no plan impact; 7–8 change what Bundle 0 builds and reverse prior SHIP decisions, so they carry the owner-confirm flag and go last.

**Bookkeeping for this document itself:** it is a process/audit doc under `docs/proofs/`, so [test_proofs_index_complete.sh](../../tools/test_proofs_index_complete.sh) requires the integrator to either add it to the guard's EXCLUDE list or link it from the proofs README — this audit deliberately modifies no other file, so that one-line action ships with the first executed drop.

---

*Audit complete 2026-07-09. Append per-drop execution notes below as the integrator lands them.*
