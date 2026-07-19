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

1. `AbortEvent::from_json` (`src/chain/block.cpp`) stores `claims_json`
   **verbatim** from peer JSON (`j.value("claims", json::array())`), and
   nlohmann keeps **unknown object members**.
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
- **NC-2 (wire re-emission unchanged).** Canonicalization is applied at HASH
  time only; the stored `claims_json` (and any re-broadcast of it) still carries
  injected members. This is harmless — they are never hashed and validation
  ignores them — and keeps the wire backward-compatible. A future increment
  could canonicalize at ingestion to also clean the re-emitted bytes.
- **NC-3 (no new authentication over the claims JSON).** This hardens what the
  digest binds; it does not extend the per-claim signature to cover the JSON.
  The claim signature still covers only the four scalars (`make_abort_claim_message`).

## 5. Gate

`determ test-abort-claims-canonical` (`tools/test_abort_claims_canonical.sh`,
FAST via `abort_claims_canonical`; 14 assertions): byte-neutrality (canonical ==
verbatim for honest claims; digest deterministic), the load-bearing check
(injection changes verbatim bytes), the security property (injected members
stripped → identical digest, directly and through `hash_abort_event`), and the
non-array / malformed / empty fallbacks. Whole-suite witness of ADC-1: every
existing abort test + the consensus goldens stay green (MSVC FAST 253/0 + WSL2
GCC `ci_local`). Cross-mirror witness of ADC-3: `test_block_digest_xbinary_parity.sh`.
Cross-references `MinixTacticalProfile.md` §5, `DetermJsonParitySoundness.md`
(NC-1, the swap-blocker this closes for the abort site),
`EqAbortViewDigestExtension.md` (the abort view root this feeds).
