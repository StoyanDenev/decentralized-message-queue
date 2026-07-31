# Abort-event digest: the canonical binary claim preimage

**Status: SHIPPED (D2-inc3, `c8a63d2`; pre-genesis digest change, no golden migration).**
Records what an abort event's claim list binds into the K-of-K block digest, and
why. The claim list is a **typed** `std::vector<chain::AbortClaim>` whose digest
preimage **is** its canonical binary encoding — so the digest binds exactly the
six consensus-bound fields of each claim, plus claim order and claim count, and
the JSON channels this document was originally written about are
**unrepresentable** rather than stripped.

Anchored by `include/determ/chain/block.hpp:355-403` (the typed claim + the
codec's contract), `src/chain/block.cpp:352-426` (`encode_abort_claims` /
`decode_abort_claims` / the container round-trip),
`src/node/producer.cpp:437-457` + `light/verify.cpp:87-101` (`hash_abort_event`,
both mirrors, domain `DTM-F2-ABORT-v2`), and
`determ test-abort-claims-canonical` (`tools/test_abort_claims_canonical.sh`).

## 1. What the digest binds

One claim is six fields, typed (`include/determ/chain/block.hpp:362-372`):

```cpp
struct AbortClaim {
    uint64_t    block_index;
    uint8_t     round;
    Hash        prev_hash;        // 32 B
    std::string missing_creator;
    std::string claimer;
    Signature   ed_sig;           // 64 B
};
```

`AbortEvent::claims` is a `std::vector<AbortClaim>`
(`include/determ/chain/block.hpp:399`). There is exactly ONE serialization of
that vector — the canonical fixed-layout binary encoding declared at
`include/determ/chain/block.hpp:374-388` and defined at
`src/chain/block.cpp:352-396`:

```
[count: u16 LE]
count × [block_index: u64 LE][round: u8][prev_hash: 32 B][ed_sig: 64 B]
        [missing_creator_len: u8][missing_creator][claimer_len: u8][claimer]
```

Those same bytes are used in three places, which is the whole structural
argument of this document:

1. **The digest preimage.** `hash_abort_event` appends
   `chain::encode_abort_claims(e.claims)` verbatim after the event scalars
   (`src/node/producer.cpp:454-455`, mirrored at `light/verify.cpp:98-99`).
   The domain tag is `DTM-F2-ABORT-v2` (`producer.cpp:443`,
   `light/verify.cpp:93`) — bumped from `v1` with the preimage change, so the
   old and new formulas occupy disjoint domains by construction.
2. **The block container.** `AbortEvent::to_json` emits `"claims"` as ONE hex
   string of the same encoding (`src/chain/block.cpp:407-408`), so the stored
   value and the hashed bytes cannot drift.
3. **The ingest path.** `AbortEvent::from_json` decodes that hex through
   `decode_abort_claims` (`src/chain/block.cpp:423-424`) — fail-closed, with
   exact-consumption semantics.

`hash_abort_event` feeds the abort view root, which
`compute_block_digest` binds when the block carries non-zero
`creator_view_abort_roots` (`src/node/producer.cpp:807-812`) — that root is what
the K-of-K committee signs. See
[EqAbortViewDigestExtension.md](EqAbortViewDigestExtension.md).

Downstream consumers read the typed vector directly: the validator
(`src/node/validator.cpp:317-355`), the gossip-adoption path
(`src/node/node.cpp:1856-1908`), and the producer that assembles an event from
its own claim bucket (`src/node/node.cpp:1827-1838`).

## 2. Why this document exists (history)

Pre-D2, `AbortEvent` carried a **schema-free** `nlohmann::json claims_json`,
stored verbatim from peer JSON (`j.value("claims", json::array())`), and
`hash_abort_event` SHA-256'd its `dump()`. Three facts composed into an
exposure:

1. nlohmann keeps **unknown object members**, and `to_json` re-emitted them.
2. Per-claim validation read only the six named fields and **ignored extras**.
3. The per-claim Ed25519 signature covers only
   `block_index‖round‖prev_hash‖missing_creator` — **not** any serialization
   (`make_abort_claim_message`, `src/node/producer.cpp:193-203`).

So a legitimate claimant (or the producer) could inject an arbitrary extra
member — e.g. `"z":0.1` — that rode the signed digest as non-semantic,
attacker-controlled bytes, and rode the *block body* as attacker-controlled
**structure**.

The first closure (round-13) was a JSON **canonicalization** layer
(`canonical_abort_claims` / `canonical_abort_claims_dump`) that rebuilt each
claim from the six named fields at hash time and, later, on ingest. That layer
policed four channels: unknown members, float-encoded integers (nlohmann's
`get<uint64_t>` truncates a `number_float` without throwing, so `10.9` / `10.0`
/ `1e1` all validated to 10), hex case, and injected nesting.

**D2-inc3 deleted that layer** (`include/determ/chain/abort_canonical.hpp`, 180
lines) — **not as a removed defense, but as dead code**. A typed claim has no
unknown members to drop, no alternate integer encoding to normalize, no hex
representation to case-fold, and no nesting to flatten. All four channels are
*unrepresentable* in `struct AbortClaim`. Nothing that layer did has a residual;
its whole premise was that the value was schema-free, and it no longer is.

### 2.1 F-10 — the wedge that made typing the right closure

[S022WireFormatCaps.md](S022WireFormatCaps.md) **F-10**: the WIRE-2
`kMaxJsonDepth` ceiling is **envelope-relative** — the same `Block` JSON sits at
different absolute depths depending on the carrying message (claim object at
depth 5 under `ABORT_EVENT`, 6 under `BLOCK`, 8 under `CHAIN_RESPONSE`). A claim
nested L ∈ {`kMaxJsonDepth`−7, `kMaxJsonDepth`−6} levels deep was therefore
**accepted on every ingest path and rejected on every serve path**: the block
committed fleet-wide and could never be re-served, and WIRE-3 escalated that
from a dropped frame to a disconnect loop, so no new node could sync past that
height. The band is exactly 2 wide for *every* value of the cap, so retuning the
constant cannot remove it.

F-10 required a claims value whose **structure** the attacker chose. Three
shipped facts remove that, and they are what closes it now:

1. **A claim contributes ZERO JSON nesting.** It is six scalars in a binary
   blob; there is no attacker-reachable container inside `claims`.
2. **The container value is ONE string at every depth.**
   `to_json` writes `j["claims"] = to_hex(...)` (`src/chain/block.cpp:408`), a
   JSON *string*, so the depth an abort-carrying block admits is a constant of
   the schema again — identical under `BLOCK` and under `CHAIN_RESPONSE`. There
   is no ingest/serve asymmetry left for claims content to sit in.
3. **The old shape is rejected at the parse boundary.** A JSON-array `"claims"`
   is no longer canonicalized — `json_require<std::string>` throws the S-018
   wrong-type diagnostic naming the field
   (`include/determ/util/json_validate.hpp:37-49`), before any structure is
   admitted.

This also retires the premature claim F-10 falsified (gate 8d / the
`messages.hpp` sizing note: Block nesting "cannot recurse past that second
level"). It held of the Block *schema* and not of the depth the schema
*admitted*; with `claims` a scalar string, it is true as written.

## 3. Properties

**ADC-1 (pre-genesis digest change; block HASHES and the goldens do not move).**
The abort-event digest formula changed: preimage `claims_json.dump()` →
`encode_abort_claims(claims)`, domain `DTM-F2-ABORT-v1` → `v2`. This is a
consensus change and it is **free only because it is pre-genesis** (no-migrations
binds post-genesis). Two things it does *not* touch: (a) **block hashes** —
`Block::signing_bytes` appends only `ae.event_hash` for each abort event
(`src/chain/block.cpp:640`), never the claim list, so no block hash moves; (b)
**per-claim signatures** — `make_abort_claim_message`
(`src/node/producer.cpp:193-203`) never covered any serialization, so every
existing claim signature verifies unchanged (ADC-6 below). Witness: the D2-inc3
commit touches 13 source/tool files and **no golden or vector data file**, and
the FULL FAST tier was 293/293 green on MSVC with the change in — including
`test-consensus-vectors`, `test-abort-event-apply`, `test-abort-cert-validation`
and the FA abort traces.

**ADC-2 (the digest binds exactly the six typed fields per claim, plus ORDER and
COUNT).** The preimage suffix **is** `encode_abort_claims(claims)`, and that
encoding is injective on the claim-vector value space: every field is either
fixed-width (`u64`, `u8`, 32 B, 64 B) or `u8`-length-prefixed
(`put_lp_str`, `src/chain/block.cpp:132-137`), the vector is prefixed by its
`u16` count, and `decode_abort_claims` consumes the buffer **exactly**
(`src/chain/block.cpp:393-394`) — so `decode ∘ encode = id` and distinct claim
vectors have distinct preimage suffixes. Two consequences:

- *Nothing else can ride the digest.* There is no unknown-member channel, no
  alternate integer encoding, no hex case and no nesting, because a value
  carrying any of them cannot be constructed as a `std::vector<AbortClaim>` in
  the first place. This is stronger than the canonicalization it replaced: a
  filter must keep working, an unrepresentable state cannot recur.
- *Every semantic bit is bound.* All six fields, the order of the claims and
  their count each change the digest. Pinned leg-by-leg by
  `test-abort-claims-canonical` group (2) — eight assertions, one per field plus
  ORDER plus COUNT — and mutant-verified: dropping `claimer` from the encoder
  reds "digest binds claim.claimer" and the round-trip fidelity leg.

Scope: this is a statement about the **claims segment**. See NC-4 for the
event-prefix framing, which this increment does not change and does not claim.

**ADC-3 (daemon == light).** `src/node/producer.cpp:437-457` and
`light/verify.cpp:87-101` are two copies of `hash_abort_event` (the light client
deliberately does not link `producer.cpp`). They append the same fields in the
same order under the same `DTM-F2-ABORT-v2` tag, and — the load-bearing part —
both call the **one shared** `chain::encode_abort_claims` from `block.cpp`,
which both binaries link. There is no hand-mirrored serialization to drift.
Pinned by `tools/test_block_digest_xbinary_parity.sh:817`
(`check_subhasher hash_abort_event DTM-F2-ABORT-v2`), which normalizes both
bodies to an append sequence and requires equality, with an extractor-liveness
leg at `tools/test_block_digest_xbinary_parity.sh:651-704` proving a reordered
field would be seen.

**ADC-4 (there is no fallback — the decode is fail-closed).** The prior form of
this register argued that a *canonicalization fallback* (verbatim bytes on a
claim that could not be rebuilt) was sound because canonicalization was strictly
weaker than validation. **The fallback concept is gone.** `decode_abort_claims`
either returns a well-formed `std::vector<AbortClaim>` or throws
`std::runtime_error` with a specific reason:

| Reject string | Site |
|---|---|
| `abort claims: truncated count header` | `src/chain/block.cpp:370` |
| `abort claims: truncated claim <i>` | `src/chain/block.cpp:379-380` |
| `abort claims: trailing bytes after last claim` | `src/chain/block.cpp:394` |
| `tx frame: truncated lp_str header` / `... body` (shared helper) | `src/chain/block.cpp:140,142` |

Encode-side bounds throw too: `abort claims: count exceeds u16`
(`src/chain/block.cpp:353-354`) and `tx frame: string > 255 bytes`
(`src/chain/block.cpp:134`). Exact consumption is what makes the encoding
canonical *as accepted*, not merely as produced: a padded or truncated blob is
not an alternate spelling of a valid claim list, it is a reject. Pinned by
`test-abort-claims-canonical` group (3), four legs, each asserting the
**specific** reject string rather than "it threw".

**ADC-5 (validation reads the typed vector; its reject surface is preserved
minus one retired string).** `check_abort_certs`
(`src/node/validator.cpp:317-355`) consumes `ae.claims` directly. The exact
count check `ae.claims.size() != max(2, K-1)` (`src/node/validator.cpp:328-331`)
and every per-claim reject — `claim block_index mismatch`, `claim round
mismatch`, `claim prev_hash mismatch`, `claim missing_creator mismatch`,
`claimer == missing`, `claimer not in at-event set`, `duplicate claimer in
cert`, `claimer not found in registry`, `claim sig invalid from …` — are
preserved verbatim (`src/node/validator.cpp:335-354`), and are pinned as typed
field/vector mutants by `tools/test_abort_cert_validation.sh`. Exactly one
reject **retired** with the JSON array: the non-array `"claims missing"` shape
check, which is now unreachable because a malformed blob throws at the parse
boundary before a `Block` exists (`src/main.cpp:34307-34310`). This also removes
a real hazard: the old `AbortClaimMsg::from_json` could **throw out of**
`validate()` on a mistyped field instead of returning a `Result`; shape failure
now lives in the decoder, so `check_abort_certs` returns a `Result` on every
input it can be reached with.

**ADC-6 (per-claim signatures are unchanged by the container swap).**
`make_abort_claim_message` binds `DTM-AbortClaim-v1 ‖ block_index ‖ round ‖
prev_hash ‖ missing_creator` (`src/node/producer.cpp:193-203`) and never covered
any serialization — pre-D2 it did not cover `claims_json`, post-D2 it does not
cover the binary encoding. The codec round-trips `ed_sig` byte-identically
(`test-abort-claims-canonical` group (1)), so verification outcomes are
invariant under the container change. The gossip-layer `AbortClaimMsg`
(`include/determ/node/producer.hpp:99-109`) keeps its own JSON form for the
standalone `ABORT_CLAIM` message; `chain::AbortClaim` is its chain-layer twin,
and the producer copies field-for-field (`src/node/node.cpp:1827-1838`).

**ADC-7 (the stored value and the hashed bytes cannot drift, and container
representation cannot reach the digest).** One codec serves both roles:
`to_json` emits `to_hex(encode_abort_claims(claims))` and `hash_abort_event`
appends `encode_abort_claims(claims)` — the same function over the same value,
so there is no second definition to fall out of step with the first (the
`MergeEvent` / `ShardTipRecord` discipline). The digest is a function of the
**decoded typed value only**, never of how that value was spelled on the wire:
`from_hex` decodes either hex case (`include/determ/types.hpp:74-82`), so an
uppercase-hex `"claims"` string decodes to the identical claim vector and
therefore the identical digest, while `to_json` re-serves the canonical
lowercase form. Hex case is thus non-semantic **by construction**, not by a
case-folding step that could be deleted. Pinned by `test-abort-claims-canonical`
group (1) leg 4 ("the digest of a round-tripped event is UNCHANGED") and group
(5b) — the abort-carrying block is a container byte fixed point and the ingested
event's digest equals the pre-serialization digest.

**ADC-8 (rejecting at the parse boundary is the correct disposition here — and
that is a re-derivation, not an inheritance).** The round-13 fix deliberately
did **not** reject a claim it could not canonicalize, because under WIRE-3 a
parse failure **closes the peer** ([S022WireFormatCaps.md](S022WireFormatCaps.md)
F-8), and a malformed *but legally shaped* JSON claim would then have become a
disconnect for no security gain. D2-inc3 reverses that disposition, and the
reason is that the premise changed underneath it: pre-D2 a schema-free
`"claims"` array was a **representable wire form**, so peers could legitimately
emit shapes the canonicalizer choked on. Post-D2 the only producer of a
`"claims"` value is `to_hex(encode_abort_claims(...))`
(`src/chain/block.cpp:407-408`), so a blob that fails `decode_abort_claims`
**cannot come from a conforming peer at all**. Closing the connection on it is
exactly WIRE-3's intended trade, not a regression against it. *(The general
lesson — a fix's disposition must be re-derived against the other fixes shipping
beside it, not carried forward — is the round-13 hostile-wire finding this
register now instantiates twice, in opposite directions.)*

**ADC-9 (ingest coverage is complete — stated over the ONE decode, not over a
caller set).** Completeness is claimed over the narrowest choke point:
**every** `AbortEvent` that materializes from JSON does so through
`AbortEvent::from_json` (`src/chain/block.cpp:412-426`), which contains the
single `decode_abort_claims` call. Over `src/`, `light/`, `wallet/` and `sdk/`,
excluding tests, that function has exactly **two** non-test callers:

1. **`Block::from_json`** (`src/chain/block.cpp:1113-1114`), which subsumes
   every Block-carrying path however many there are — network ingress (`BLOCK`,
   `CHAIN_RESPONSE`, beacon header, shard tip, cross-shard `src_block`), disk
   reload, the light client's readers, the `verify-block-sigs` CLI, and
   **nested witness blocks** (`src/chain/block.cpp:1189` recurses with
   `allow_witnesses=false`, so abort events inside `shard_tip_witnesses` — the
   deepest legitimate nesting the wire admits — decode through the same call).
2. **The `MsgType::ABORT_EVENT` gossip handler**
   (`src/net/gossip.cpp:206-221`), which materializes a standalone event
   *without* a Block. Pre-D2 this was the ingress that mattered most, because it
   is the **shallowest** envelope and therefore admitted the **deepest**
   injection — an ingress that reasoning only about blocks would have missed.

Because both callers share the one fail-closed decode, the second-ingress hazard
is closed **by construction** rather than by a repeated check. The gate pins
both halves independently anyway: group (5c) drives the old attack shape through
`Block::from_json`, group (6) drives a real `make_abort_event` envelope through
the gossip parse and asserts the typed claims and the digest survive it.

The only other non-test writer of `AbortEvent::claims` is the producer
(`src/node/node.cpp:1827-1838`), which builds the vector from its own verified
`AbortClaimMsg` bucket — so a locally formed event and a received one encode
identically, and no producer/validator asymmetry is introduced.

## 4. Non-claims

- **NC-1 (this is a type, not a filter — do not describe it as sanitization).**
  The codec does not strip, normalize, or reject *content*; it makes the four
  historical channels unconstructible. The distinction is load-bearing for
  maintenance: a sanitizer has a bypass surface and needs a gate that reddens
  when it is removed, whereas `struct AbortClaim` has no "unknown member" state
  to leak. The corollary is also a non-claim: the codec asserts **nothing**
  about field *semantics* — a claim with a nonsense `block_index`, an unknown
  `claimer` or a bad signature encodes and decodes perfectly. Rejecting those is
  `check_abort_certs`' job (ADC-5), and this document does not do it twice.
- **NC-2 (the container hex string is not claimed to be a strict byte fixed
  point over every input).** `from_hex` is case-insensitive
  (`include/determ/types.hpp:74-82`), so an uppercase-hex `"claims"` value
  ingests successfully and is re-served lowercase. That is a *representation*
  round-trip, not a byte round-trip, and it is harmless precisely because the
  digest is taken over the decoded bytes (ADC-7) — the block hash does not cover
  the claim container at all (`src/chain/block.cpp:640`). The gate's byte
  fixed-point leg (5b) asserts the property for the canonical form the node
  itself produces, which is the form that is ever re-served.
- **NC-3 (SUPERSEDED, kept for the lesson).** An earlier revision recorded that
  retaining injected members was *"harmless — they are never hashed and
  validation ignores them"*. That was **false**, and F-10 is why: it reasoned
  only about what the retained bytes *mean* and never about what they *cost*,
  and their SIZE and DEPTH were the whole attack. Same shape as the S-022 lesson
  in [S022WireFormatCaps.md](S022WireFormatCaps.md) §8: **a non-claim that
  dismisses a residual on SEMANTIC grounds is blind to a RESOURCE
  consequence.** "These bytes are never interpreted" does not imply "these bytes
  are free" — they are still stored, re-serialized, and measured against a
  ceiling.
- **NC-4 (the EVENT-prefix framing is out of scope and unchanged).** ADC-2 is
  scoped to the claims segment. `hash_abort_event` appends the event scalars as
  `round (u8) ‖ aborting_node (raw, unprefixed) ‖ timestamp (u64) ‖ event_hash
  (32 B)` before the claim bytes (`src/node/producer.cpp:443-455`), and
  `SHA256Builder::append(const std::string&)` writes raw bytes with no length
  prefix (`include/determ/crypto/sha256.hpp:21-23`). This document therefore
  does **not** claim injectivity of the full event preimage across the
  `aborting_node` / `timestamp` boundary. The property is identical before and
  after D2-inc3 — the increment replaced only the suffix — so nothing here is a
  regression, and nothing here is asserted as closed.
- **NC-5 (no new authentication over the claim list).** The per-claim Ed25519
  signature still covers only the four scalars (ADC-6). `claimer` is
  authenticated indirectly — it selects the pubkey the signature must verify
  under (`src/node/validator.cpp:348-354`) — and `ed_sig` is self-authenticating,
  but neither is *inside* the signed message. What D2-inc3 adds is that all six
  fields now ride the **block digest**, so a relayer cannot alter them after the
  K-of-K signature without invalidating it (ADC-2). That is digest binding, not
  a signature extension.
- **NC-6 (the minix `determ::djson` swap is unblocked for this site, and for a
  stronger reason than before).** The former blocker was
  [DetermJsonParitySoundness.md](DetermJsonParitySoundness.md) NC-1: an injected
  double in `claims_json` would dump differently across nlohmann and
  `determ::djson`, forking a mixed fleet. That site is now **off the JSON
  serializer entirely** — the digest preimage is binary, and the container value
  is a lowercase hex string, which every conforming serializer emits identically.
  This is a removal of the hazard, not a mitigation of it; the residual
  double-parity concern lives on other paths (RPC HMAC), not here.

## 5. Gate + traceability

`determ test-abort-claims-canonical` (`src/main.cpp:46790-47048`, driven by
`tools/test_abort_claims_canonical.sh`; FAST via `abort_claims_canonical`,
`tools/run_all.sh:108`) — **23 assertions**:

| Group (source label) | Legs | Asserts | Register | Falsified by |
|---|---|---|---|---|
| Codec fidelity (1) | 4 | encode is byte-deterministic; encode→decode round-trips ALL six fields of every claim (sig bytes byte-identical); the empty list round-trips; the digest of a round-tripped event is UNCHANGED | ADC-2, ADC-6, ADC-7 | dropping any field from `encode_abort_claims`; a lossy decode |
| Per-field digest binding (2) | 8 | each of `block_index`, `round`, `prev_hash`, `ed_sig`, `missing_creator`, `claimer` changes the digest; claim **ORDER** changes it; claim **COUNT** changes it | ADC-2 | dropping a field's append (**mutant-verified on `claimer`**: reds this leg + the round-trip leg); dropping the count prefix |
| Fail-closed decode (3) | 4 | the **specific** reject strings — `truncated count header` (1-byte blob), `truncated lp_str` (last byte cut), `truncated claim` (mid-claim cut), `trailing bytes after last claim` (one byte appended) | ADC-4 | a decoder tolerating truncation or trailing bytes |
| F-10 structural closure (5a-5d) | 6 | the container `claims` value **is a string** (zero JSON nesting); the abort-carrying block is accepted at **BOTH** `BLOCK` and `CHAIN_RESPONSE` depths through the real `Message::deserialize` (no wedge band); block container round-trip is a byte fixed point; the ingested event's digest is unchanged; the **pre-D2 JSON-array claims shape is REJECTED** with the S-018 `claims` diagnostic; a non-hex blob is rejected at parse | ADC-7, ADC-8, ADC-9 | re-admitting a JSON-array `"claims"` in `AbortEvent::from_json` → the (5c) leg goes RED |
| `ABORT_EVENT` gossip round-trip (6) | 1 | a real `net::make_abort_event` envelope re-parses through `AbortEvent::from_json` with the typed claims intact and the digest unchanged — the second ingress pinned independently | ADC-3, ADC-9 | a divergent second decode on the standalone path |

**Companion guards.**

- `tools/test_block_digest_xbinary_parity.sh` — ADC-3. Line 817 pins
  `hash_abort_event` against domain `DTM-F2-ABORT-v2` and requires the
  `producer.cpp` and `light/verify.cpp` bodies to normalize to the same append
  sequence; the three `hash_abort_event` heredocs (lines 659-700) were re-derived
  to v2 with the increment, and the extractor-liveness leg proves a reordered
  field is caught.
- `tools/test_abort_cert_validation.sh` — ADC-5. Every distinct
  `check_abort_certs` reject marker, driven by **typed** field/vector mutants
  (the JSON-shape mutant class died with the type).
- `tools/test_abort_event_apply.sh`, `tools/test_fa_abort_trace.sh`,
  `tools/test_wire_types.sh` (which now **asserts** the claims round-trip — the
  pre-D2 JSON array never checked it), and the consensus vectors: the
  whole-suite witness for ADC-1, green at FULL FAST 293/293 on MSVC with no
  golden regenerated.

**Historical mutant (retired with its code).** The round-13 M4 mutant — restore
`ae.claims_json = j.value("claims", json::array())` — no longer applies: the
field it restored does not exist. Its successor is the (5c) leg above, whose
mutant (re-admitting a JSON-array `"claims"`) is the direct analogue, plus the
per-field encoder mutants of group (2), which are the ones that guard what the
digest binds.

Cross-references: [S022WireFormatCaps.md](S022WireFormatCaps.md) (WIRE-2/WIRE-3,
F-8, F-10), [EqAbortViewDigestExtension.md](EqAbortViewDigestExtension.md) (the
abort view root this feeds), [AbortCascadeLiveness.md](AbortCascadeLiveness.md)
§4.1 (the `max(2, K-1)` quorum the count check enforces),
[DetermJsonParitySoundness.md](DetermJsonParitySoundness.md) NC-1 (the swap
blocker this site no longer has), [MinixTacticalProfile.md](MinixTacticalProfile.md)
§5, and `docs/PROTOCOL.md` §5 (the normative claim-list layout).
