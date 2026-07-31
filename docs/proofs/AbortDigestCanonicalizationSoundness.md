# Abort-event digest canonicalization soundness

**Status: SHIPPED (consensus hardening, byte-neutral for honest chains).**
Records why hashing a *canonical* form of an abort event's claims — rather than
the verbatim peer JSON — binds only semantic content into the K-of-K block
digest, without changing the digest of any honest abort block.

Anchored by `include/determ/chain/abort_canonical.hpp` (the shared helper),
`src/node/producer.cpp` + `light/verify.cpp` (`hash_abort_event`, both callers),
and `determ test-abort-claims-canonical` (`tools/test_abort_claims_canonical.sh`).

## 1. The exposure

`hash_abort_event()` SHA-256s an abort event's `claims_json` into the block
digest via the abort view root (`src/node/producer.cpp`, mirrored byte-for-byte
in `light/verify.cpp`), and that digest is what the K-of-K committee signs.
Three facts compose into an exposure:

1. `AbortEvent::from_json` (`src/chain/block.cpp`) stored `claims_json`
   **verbatim** from peer JSON (`j.value("claims", json::array())`), and
   nlohmann keeps **unknown object members**. *(This is the fact the round-13
   increment changed — see §2.1; the exposure is stated here as it originally
   stood, because the digest argument below does not depend on the change.)*
2. Per-claim validation — `AbortClaimMsg::from_json` (`src/node/producer.cpp`),
   used by `check_abort_certs` (`validator.cpp`) and `on_abort_event`
   (`node.cpp`) — reads only the six named fields and **ignores extras**.
3. The per-claim Ed25519 signature (`make_abort_claim_message`) covers only
   `block_index‖round‖prev_hash‖missing_creator` — **not the JSON**, not the
   extra members.

So a legitimate abort claimant (or the block producer) could inject an arbitrary
extra member — e.g. `"z":0.1` — into an otherwise-valid claim, and it would ride
the signed digest as **non-semantic, attacker-controlled bytes**. Under a
uniform nlohmann fleet this does not fork (all nodes hash the same bytes), but it
is a canonicalization weakness: the consensus digest binds content no one
authenticated, and it is the exact reason the minix nlohmann→`determ::djson`
swap would be UNSAFE at this site (an injected double dumps differently across
the two serializers — see [DetermJsonParitySoundness.md](DetermJsonParitySoundness.md)
NC-1).

## 2. The fix

`canonical_abort_claims_dump(claims)` (`include/determ/chain/abort_canonical.hpp`)
rebuilds each claim from **only** the six consensus-bound fields (the exact set
`AbortClaimMsg::to_json` emits) and dumps the array; `hash_abort_event` appends
this canonical dump instead of `claims_json.dump()`. Each field is **re-derived
through its typed parse**, not copied verbatim: the two integer fields via
`get<uint64_t>`/`get<uint8_t>`, the two hex fields via `get<std::string>` +
ASCII-lowercase, the two identifier strings verbatim. This collapses three
non-semantic channels at once — unknown **members** (dropped), the numeric
**value encoding** of the integers (see §3 ADC-2: nlohmann's `get<uint64_t>`
truncates a float without throwing, so `"10.9"`/`"10.0"`/`"1e1"` all validate
and would otherwise ride the digest), and hex **case** (accepted
case-insensitively by validation).

### 2.1 Also applied on INGEST (round-13, closes F-10)

`AbortEvent::from_json` now stores `canonical_abort_claims(...)` — the same
rebuild, returned as a value — instead of the verbatim peer JSON.
`canonical_abort_claims_dump` is defined as `canonical_abort_claims(...).dump()`,
so there is still exactly ONE rebuild and the stored bytes cannot drift from the
hashed bytes.

This was **not** cosmetic tidy-up of NC-2. `claims_json` is schema-free and
`to_json` re-emits it verbatim, so an injected member could carry arbitrary
**nesting** into a block body that nothing authenticates (`Block::signing_bytes`
appends only `ae.event_hash`, and the digest is canonicalized) — honest
validators sign it and no validator can distinguish it. The WIRE-2 structural
ceiling ([S022WireFormatCaps.md](S022WireFormatCaps.md) §2.3) is
**envelope-relative**: the same claim object sits at depth 6 under `BLOCK` but 8
under `CHAIN_RESPONSE`. A claim nested L ∈ {`kMaxJsonDepth`−7, `kMaxJsonDepth`−6}
levels deep was therefore **accepted on every ingest path and rejected on every
serve path** — the block committed fleet-wide and could never be re-served, and
WIRE-3 escalated that from a dropped frame to a disconnect loop, so no new node
could sync past that height. That is **F-10**, and the band is exactly 2 wide for
*every* value of the cap, so retuning the constant cannot remove it.

Canonicalizing on ingest closes it at the source: a stored claim is six scalars,
contributing **zero** nesting, so the admitted depth is a property of the schema
again — which is what the ceiling was sized against. It also makes true a claim
the WIRE-2 sizing note and gate 8d had asserted prematurely (that `Block` nesting
"cannot recurse past that second level"), which held of the Block *schema* but
not of the depth the schema *admitted*.

**One shared helper (S-043 discipline).** BOTH the daemon (`producer.cpp`) and
the light-client mirror (`light/verify.cpp`) call the *same* function, so the
two digests cannot drift on a canonicalization detail — a hazard a hand-mirrored
copy would carry. The helper depends only on nlohmann, so both binaries include
it. This is pinned by `tools/test_block_digest_xbinary_parity.sh` (producer ==
light, byte-parity).

## 3. Properties

**ADC-1 (byte-neutral for honest chains → no fork, no migration).** An honest
claim already carries exactly the six keys, produced by `AbortClaimMsg::to_json`
and re-serialized by nlohmann's sorted-key dump. Rebuilding those six keys (same
values) and dumping yields the byte-identical string, so `hash_abort_event` is
unchanged for every honest abort event → every honest abort block's digest is
identical → no chain forks and no golden needs migrating. Witnessed by MSVC +
WSL2 GCC FAST staying green with the change in (every existing abort test —
`test-abort-event-apply`, the FA abort traces — and the consensus goldens
unchanged), plus the direct byte-neutrality assertion in
`test-abort-claims-canonical`.

**ADC-2 (all three non-semantic channels collapsed → digest binds only semantic
content).** Three ways an attacker can vary the bytes of a claim that validation
still accepts, each closed by the rebuild: (a) **unknown members** — any key that
is not one of the six is absent from the rebuilt object; (b) **numeric-value
encoding** — nlohmann's `get<uint64_t>()`/`get<uint8_t>()` *truncate* a
`number_float` WITHOUT throwing (exactly as `json_require` does, so
`"block_index":10.9` / `10.0` / `1e1` all validate to 10), and re-emitting the
parsed integer collapses every such encoding to the one canonical decimal —
without this a verbatim copy would leave the attacker's `.9`/`.0` in the hashed
bytes (the adversarial-review finding this doc records); (c) **hex case** — the
two hex fields are accepted case-insensitively and the claim signature covers the
decoded *bytes*, so lowercasing them collapses upper/mixed case. `test-abort-claims-canonical`
asserts the digest is identical with and without an injected `"z":0.1` /
`"extra_note"`, a float-encoded `block_index`/`round`, and upper-case hex — and
that each of those variations *does* change the verbatim bytes (the fix is
load-bearing on all three).

**ADC-3 (daemon == light).** Because both `hash_abort_event` implementations
call the one shared helper, they compute byte-identical canonical dumps and
therefore byte-identical digests; the light client verifies the same digest the
committee signed. Pinned by the x-binary parity guard.

**ADC-4 (fallback cannot smuggle into an accepted digest).** The helper falls
back to the verbatim `claims.dump()` in exactly two cases: a claim that is **not
an object**, or one **missing a required key**. Both cases are precisely what
per-claim validation rejects — `AbortClaimMsg::from_json` calls `json_require`
on each of the six fields, which throws on a non-object or a missing/wrong-type
field, so `check_abort_certs` / `on_abort_event` reject the abort event before
any block carrying it is accepted or signed. Hence the fallback path is
unreachable for a claim whose digest a node signs or trusts: the
fallback ⟺ malformed ⟺ validation-reject coupling is airtight, so the fallback
preserves prior bytes without ever binding attacker-controlled bytes into an
accepted digest.

**ADC-7 (ingest canonicalization is consensus-byte-neutral for EVERY input, not
just honest ones).** ADC-1 argues byte-neutrality for *honest* claims. The
ingest application needs the stronger statement, because it changes the bytes a
node stores for a *hostile* claim too — and those bytes feed the digest. It
holds because the rebuild is **idempotent**: the two integers re-read to
themselves through the same `get<T>`, `lower_hex_ascii` is a no-op on an already
lowercase string, the two identifier strings are copied, and nlohmann's
`object_t` is `std::map`, so key order is sorted regardless of insertion order —
hence `canon∘canon = canon`. Two cases exhaust the input space. If the claim
canonicalizes, the stored value is `canon(v)` and the digest hashes
`canon(canon(v)).dump() = canon(v).dump()` — exactly what it hashed when the
stored value was `v`. If it does not, ingest keeps `v` verbatim (§4 NC-2) and
nothing changed at all. **Therefore every block's hash is identical before and
after this increment, and no accept/reject decision moves** — no fork, no golden
migration, and nothing for the no-migrations constraint to bite on. Pinned by
the byte-neutral legs of `test-abort-claims-canonical` §5 (honest block
round-trips through ingest byte-identically; the ingested poisoned block is
byte-identical to the honest one; the ingested abort-event digest is unchanged).

*"No accept/reject decision moves" needs its own argument*, because per-claim
validation reads the **stored** claim, which this increment changes — so the
sharpest adversarial question is whether canonicalization can **widen** what
validation accepts. Field by field, for a claim that canonicalizes: the two
integers are stored as the very value `json_require<T>` would have derived from
the verbatim claim (both use the same `get<T>`, including its silent float
truncation), so the equality checks against `b.index` / `ae.round` are unchanged;
the two hex fields are lowercased, which alters neither the length that
`json_require_hex` checks nor the bytes `from_hex` decodes — so the length check
and the Ed25519 verification over the decoded digest are unchanged; and the two
identifier strings are copied byte-for-byte, so the set-membership,
`claimer != missing_creator`, and duplicate-claimer checks are unchanged. The
array's length and element order are preserved (one rebuilt entry per input
entry, in order), so the exact `size() != max(2,K-1)` count check is unchanged.
For a claim that does *not* canonicalize, the stored value is the verbatim one
and nothing changed at all. ⇒ Validation returns the identical verdict on every
input: **no widening and no narrowing**, so this cannot admit a block the fleet
would reject nor reject one the fleet admits.

**ADC-8 (ingest keeps the verbatim fallback, and that is sound).** Ingest does
**not** reject a claim it cannot canonicalize; it stores it unchanged. Rejecting
would be strictly worse: `from_json` throwing is a parse failure, and under
WIRE-3 a parse failure now **closes the peer**, so a malformed gossiped claim
would become a disconnect for no security gain. Soundness is ADC-4's coupling,
which the ingest path inherits unchanged — canonicalization is strictly *weaker*
than per-claim validation (`at(k).get<T>()` versus `json_require<T>`, which is
the same `get<T>` plus a `contains(k)` check, plus an exact hex-length check on
the two hex fields), so *canonicalization throws ⟹ validation throws ⟹ no such
block is ever accepted*. The fallback therefore cannot deliver un-stripped bytes
into a committed block. `test-abort-claims-canonical` pins the implication
directly over five malformed shapes rather than leaving it in prose.

**ADC-9 (ingest coverage is complete, and the fix HEALS an already-poisoned
chain).** A single choke point only helps if it is the *only* way an
`AbortEvent` materializes from JSON. The claim is stated over **callers of
`AbortEvent::from_json`**, not over the far larger and constantly-growing set of
`Block::from_json` call sites, because the latter is exactly the kind of
enumeration that rots — a first draft of this entry miscounted it. Over `src/`,
`light/`, `wallet/` and `sdk/`, excluding tests, there are exactly **two**:

1. **`Block::from_json`** (`src/chain/block.cpp:822`). This subsumes every
   Block-carrying path however many there are — network ingress (`BLOCK`,
   `CHAIN_RESPONSE`, beacon header, shard tip, cross-shard `src_block`), disk
   reload (`src/chain/chain.cpp`), the light client's readers, the
   `verify-block-sigs` CLI, and **nested witness blocks** (`block.cpp:897`
   recurses with `allow_witnesses=false`, so abort events inside
   `shard_tip_witnesses` — the deepest legitimate nesting the wire admits — are
   canonicalized too).
2. **The `MsgType::ABORT_EVENT` gossip handler** (`src/net/gossip.cpp:226`),
   which materializes a standalone event *without* a Block. This is the one that
   matters most: per the §2.1 depth table it is the **shallowest** envelope
   (claim at depth 5), so it admits the **deepest** injection — an ingress that
   reasoning only about blocks would have missed entirely.

The only other assignment to `claims_json` in non-test code is `src/node/node.cpp`,
where the producer builds the array from `AbortClaimMsg::to_json()` — already
exactly the six keys with canonical types, so a locally-formed event and a
received one are byte-identical and no producer/validator asymmetry is
introduced.

Because **disk reload** is on that list, a node that already stored a poisoned
block canonicalizes it on the next restart, and ADC-7 says the digest is
unchanged — so the block stays valid and becomes servable. **The sync wedge
therefore self-heals at restart; it does not require a resync or a migration.**

**ADC-5 (equivocation dimension needs no analogue).** `hash_equivocation_event`
hashes the **typed** `EquivocationEvent` struct fields directly (equivocator,
block_index, digest_a/b, sig_a/b, shard_id, beacon_anchor_height) — never a
verbatim `claims_json.dump()`. `EquivocationEvent` has no free-form JSON field
(`from_json` extracts every field typed). So it has no unknown-member exposure
and needs no canonicalization.

**ADC-6 (unblocks the minix swap for this site).** With unknown members stripped
and known-field values constrained to canonical types by upstream validation
(ADC-4), no attacker-controlled double reaches `claims_json`'s serialization on
an accepted block, so swapping this site's serializer to `determ::djson` no
longer risks the mixed-fleet double divergence of
[DetermJsonParitySoundness.md](DetermJsonParitySoundness.md) NC-1.

## 4. Non-claims

- **NC-1 (the typed rebuild is what closes the numeric channel; the fallback
  stays coupled to validation-reject).** An earlier draft copied the six field
  *values* verbatim and claimed "values of a validated claim are already
  canonical" — the adversarial review REFUTED that: `get<uint64_t>` truncates a
  float without throwing, so a verbatim copy of `"block_index":10.9` (accepted by
  validation) rode the digest. The shipped helper therefore re-derives each field
  through its typed parse (ADC-2). This does NOT weaken the fallback argument
  (ADC-4): `.get<uint64_t>()` throws only on a *non-number* and `.get<std::string>()`
  only on a *non-string* — exactly the cases `json_require` also throws on, so the
  fallback still fires ⟺ the claim is malformed ⟺ per-claim validation rejects it.
  A float in an integer field does NOT hit the fallback (it truncates like
  validation), so it is canonicalized, not smuggled. Type-normalizing the known
  fields is thus strictly *stronger* than the verbatim copy, not weaker.
- **NC-2 (SUPERSEDED — and its "harmless" was wrong).** This entry previously
  read: *"Canonicalization is applied at HASH time only; the stored `claims_json`
  (and any re-broadcast of it) still carries injected members. This is harmless
  — they are never hashed and validation ignores them — and keeps the wire
  backward-compatible. A future increment could canonicalize at ingestion to
  also clean the re-emitted bytes."* The future increment shipped (§2.1), and it
  was **not** optional tidy-up: "harmless" was **false**. It reasoned only about
  what the retained bytes *mean* (nothing — never hashed, ignored by validation)
  and never about what they *cost*, and their SIZE and DEPTH are the whole
  attack. Round-13's F-10 turned exactly those retained bytes into a permanent
  sync wedge once a depth ceiling existed to trip over. The residual scope is
  now only the fallback shapes of ADC-8, which validation rejects.

  Worth naming, because it is the same shape as the S-022 lesson recorded in
  `S022WireFormatCaps.md` §8: **a non-claim that dismisses a residual on
  SEMANTIC grounds is blind to a RESOURCE consequence.** "These bytes are never
  interpreted" does not imply "these bytes are free" — they still get stored,
  re-serialized, and measured against a ceiling.
- **NC-3 (no new authentication over the claims JSON).** This hardens what the
  digest binds; it does not extend the per-claim signature to cover the JSON.
  The claim signature still covers only the four scalars (`make_abort_claim_message`).

## 5. Gate

`determ test-abort-claims-canonical` (`tools/test_abort_claims_canonical.sh`,
FAST via `abort_claims_canonical`; **23 assertions**): byte-neutrality (canonical ==
verbatim for honest claims; digest deterministic), the load-bearing check
(injection changes verbatim bytes), the security property (injected members
stripped → identical digest, directly and through `hash_abort_event`), and the
non-array / malformed / empty fallbacks.

**Ingest legs (§2.1 / ADC-7 / ADC-8), added round-13.** Two of them assert the
F-10 **precondition** rather than the fix, and they are the reason the rest is
not vacuous: a block carrying a claim nested `kMaxJsonDepth`−7 levels deep *is*
accepted as a `BLOCK` envelope and *is* rejected as `CHAIN_RESPONSE` — the
envelope-relative wedge, reproduced through the real `Message::deserialize`. If
either half ever stopped holding, the vector would have drifted out of the band
and every leg below it would silently pass for the wrong reason. The fix legs
then assert that after ingest the block re-serves at CHAIN_RESPONSE depth and
that the injected member is gone from the stored body; the byte-neutrality legs
that the honest block round-trips through ingest byte-identically, that the
ingested poisoned block is byte-identical to the honest one, and that the
abort-event digest is unchanged. The nesting depth is expressed as
`net::kMaxJsonDepth - 7`, not hard-coded, since the band is `{cap−7, cap−6}` for
every cap value.

**Falsify-on-mutant (M4).** Restoring the verbatim
`ae.claims_json = j.value("claims", json::array())` turns exactly **four** legs
RED — re-serve, member-stripped, poisoned-==-honest, and the standalone
`ABORT_EVENT` ingress (so the ADC-9 second caller is pinned independently, not
merely by sharing a function with the first) — while **every digest-path leg
stays GREEN**, including *both* *"digest is UNCHANGED"* legs.
That last one is the interesting result: the mutant does not merely fail to
falsify ADC-7, it *witnesses* it. The digest is identical whether the claim is
stored verbatim or canonical, which is precisely why this increment is
consensus-byte-neutral — the mutant separates the wire-level property being
fixed from the consensus-level property being preserved. Whole-suite witness of ADC-1: every
existing abort test + the consensus goldens stay green (MSVC FAST 253/0 + WSL2
GCC `ci_local`). Cross-mirror witness of ADC-3: `test_block_digest_xbinary_parity.sh`.
Cross-references `MinixTacticalProfile.md` §5, `DetermJsonParitySoundness.md`
(NC-1, the swap-blocker this closes for the abort site),
`EqAbortViewDigestExtension.md` (the abort view root this feeds).
