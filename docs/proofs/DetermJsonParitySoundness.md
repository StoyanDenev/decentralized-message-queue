# determ::djson — dump() byte-parity soundness (minix JSON phase 2, inc.1)

**Status: SHIPPED (increment 1, additive/library-only).** This proof records the
load-bearing property of the in-tree JSON module `determ::djson`
(`include/determ/json/json.hpp`) and the dual-oracle gate that establishes it.
It is the minix JSON-track counterpart of the crypto dual-oracle proofs: a
from-scratch component whose correctness is pinned against a frozen reference.

See [MinixTacticalProfile.md](MinixTacticalProfile.md) §5 for the track design
and the two byte-critical sites; this doc is the property/soundness record.

## 1. Why this exists

The minix goal (`MinixTacticalProfile.md`) is a minimal, fully-auditable
external-dependency footprint. JSON is one of the last two third-party source
libraries: nlohmann_json is **phase-1 vendored** in-tree
(`third_party/nlohmann/json.hpp`, SHA-256 byte-ratcheted). Phase 2 replaces it
with an in-tree module. The blocker that gates any such replacement is that
**two daemon sites serialize JSON onto a byte-exact consensus/authentication
path**, so a replacement writer must be byte-identical to nlohmann there or it
forks a mixed-implementation fleet:

1. **Consensus digest.** `hash_abort_event()` SHA-256s `claims_json.dump()`
   (`src/node/producer.cpp`), and that hash feeds `compute_block_digest` via the
   abort view root — i.e. the K-of-K-signed block digest of any abort-carrying
   block depends on nlohmann's canonical dump bytes (sorted keys, compact
   separators). The light client MIRRORS the same dump-hash (`light/verify.cpp`).
   A one-byte writer divergence forks consensus on abort-carrying chains.
2. **RPC HMAC.** The HMAC pre-image is `method + "|" + params.dump()`
   (`src/rpc/rpc.cpp`), computed independently by the server and by
   wallet/light clients. A mixed-implementation fleet must dump byte-identically
   or authentication fails across implementations.

Everything else is schema-only: the state root is over binary domain-prefixed
leaves (not JSON bytes), and snapshots are re-verified against the
committee-signed header — they need fidelity, not cross-implementation
byte-equality.

## 2. The module (increment 1 scope)

`determ::djson` is a header-only, **dependency-free** JSON value model with a
strict recursive-descent parser and a canonical compact serializer:

- **Value model** — Null, Boolean, signed/unsigned 64-bit Integer, Double,
  String, Array, and Object stored as `std::map<std::string, Value>` (sorted
  keys by construction).
- **`dump()`** — the nlohmann default compact form: `{"a":1,"b":2}` /
  `[1,2,3]`, no spaces after `:`/`,`; RFC 8259 string escaping (`" \ \b \f \n
  \r \t` two-char, other controls `< 0x20` as `\u00xx` lowercase-hex, every
  other byte including multi-byte UTF-8 emitted literally, forward slash NOT
  escaped); integers plain decimal (unsigned and signed dump identically).
- **`parse()`** — strict RFC 8259 with a nesting depth cap, strict UTF-8, and
  the number/escape/structure rejections nlohmann's strict mode makes.

**The C++ namespace is `determ::djson`, not `determ::json`**: the tree carries a
pervasive `using json = nlohmann::json;` alias plus many `using namespace
determ;` blocks, so a `determ::json` namespace would make the bare name `json`
ambiguous everywhere. The module keeps its descriptive name (“the in-tree
determ JSON module”); the namespace just sidesteps the alias.

Increment 1 is **additive**: it introduces the module and PROVES the parity
property. No production consumer is swapped onto it. Swapping the two
byte-critical sites (and the wider nlohmann surface) is the owner-gated serial
follow-on, at which point a mixed-fleet abort-event cluster test becomes an
additional gate.

## 3. The dual oracle

The strongest possible oracle for byte-parity is nlohmann **itself**: it is
already linked into the `determ` binary (vendored). The gate `determ
test-determ-json` (`tools/test_determ_json.sh`, FAST) therefore MEASURES parity
rather than predicting it — for each corpus input `s` it asserts

```
determ::djson::Value::parse(s).dump()  ==  nlohmann::json::parse(s).dump()
```

byte for byte, plus round-trip idempotence, over a corpus spanning the in-scope
subset AND the two exact byte-critical shapes (an abort `claims_json` array of
sorted-key claim objects; a sorted-and-unsorted RPC `params` object). Any
divergence on any covered value fails the gate; the property is checked, not
asserted.

## 4. Properties

**DJP-1 (dump byte-parity on the consensus subset).** For every value in the
in-scope subset — sorted-key objects, arrays, booleans, null, unsigned/signed
64-bit integers, and strings over valid UTF-8 — `determ::djson::dump()` equals
nlohmann's default `dump()` byte for byte. Established empirically by the §3
dual oracle over a representative corpus that includes the two byte-critical
shapes; the parity of the abort-`claims_json` and RPC-`params` shapes is a
direct corpus assertion, not an extrapolation.

**DJP-2 (key canonicalization = the HMAC-canonical form).** Objects dump keys in
byte-lexicographic order (backed by `std::map`), matching nlohmann's
`std::map`-backed default. Hence a parse-then-dump round trip yields the same
canonical bytes regardless of input key order — exactly the property
`canonical_for_hmac` (`src/rpc/rpc.cpp`) relies on so that a client's pre-send
dump and the server's re-dump agree.

**DJP-3 (idempotent canonical form).** `parse(dump(v))` dumps to the identical
bytes: the canonical form is a fixed point. Gated by the idempotence leg on
every corpus item.

**DJP-4 (strict-UTF-8 fail-closed on dump).** Serializing a String node (or
object key) whose bytes are not valid UTF-8 THROWS (`dump_error`), matching
nlohmann's strict error handler. This is load-bearing: it is what makes a
non-UTF-8 abort-path leaf key fail closed instead of silently serializing to a
divergent byte string. The gate cross-checks that nlohmann throws on the same
input.

**DJP-5 (parse-rejection agreement — adversarially swept in inc.4).** On the
in-scope grammar, `determ::djson` and nlohmann agree on which inputs are
malformed — both reject leading zeros, `+` signs, bare control characters in
strings, invalid escapes, lone surrogates, non-leading trailing garbage, and
truncated tokens. Verified by an agreement corpus (`both_reject`). A mixed fleet
must not have one implementation accept what another rejects on a consensus-bound
input; agreement on rejection closes that class within scope. A leading UTF-8 BOM
is the one input where the two once diverged (nlohmann skips it, RFC 8259 §8.1);
`determ::djson` now skips it too, restoring agreement (corpus item). And per
parse()'s contract, invalid UTF-8 anywhere — including inside a string or object
key — surfaces as `parse_error` (not the serialize-time `dump_error`), asserted
by type in the gate; both implementations still reject the input.

**Increment 4 (`determ test-determ-json-adversarial`) sweeps this agreement
across the adversarial boundary comprehensively** — literal-case lookalikes
(`True`/`NULL`/`None`), NaN/Infinity barewords, the full number-malformation
grammar, `\u` surrogate edges (lone/paired/high+high), structural truncations
(`{"a":`, `[1,`, mismatched brackets, single-quoted/unquoted keys), the u64/i64
magnitude boundaries, and whitespace/duplicate-key canonicalization — 94+
assertions, nlohmann the measured oracle. **The inc.4 adversarial review found and
CLOSED one real accept/reject divergence in the fork-unsafe direction:** a number
overflowing double to ±inf (`1e400`, or a 400-digit integer) `strtod`-ed to
`HUGE_VAL` and `determ::djson` ACCEPTED it while nlohmann REJECTS non-finite
floats (`out_of_range` 406). `include/determ/json/json.hpp` now routes every
numeric `strtod` through `real_checked`, which throws on `!std::isfinite` —
restoring agreement (both reject); inc.4's `both_reject("1e400", …)` pins it.
(Underflow to a finite subnormal/0.0 is accepted by both, so the guard is on
`isfinite`, not `errno`.)

**DJP-6 (peer-facing hardening).** The parser is (in a future increment) the
outermost consumer of every peer-supplied byte, so it enforces a nesting DEPTH
CAP (default 64) on both objects and arrays, strict UTF-8 validation (rejecting
overlong encodings, surrogates-as-UTF-8, and out-of-range/stray lead bytes), and
bounded lookahead. The depth cap is an INTENTIONAL divergence from nlohmann
(which recurses unbounded); the consensus subset nests only a handful deep, so
the cap cannot false-reject an honest consensus input. Every `s[pos]` /
`s[pos+k]` access is bounds-checked before use.

**DJP-7 (additive / goldens byte-identical).** Increment 1 changes no production
serialization path: the two byte-critical sites still call nlohmann, so every
consensus, snapshot, and state-root golden is byte-identical (the FAST golden
corpus is the witness), and the minix dependency-surface ratchet stays green
because `determ::djson` is dependency-free (it includes NO nlohmann; only the
in-binary test does, as the oracle).

## 5. Non-claims

- **NC-1 (double dump-parity is a SWAP-BLOCKER, not out of scope — corrected
  after adversarial review).** `determ::djson` stores and dumps doubles
  best-effort (`%.17g`) and does NOT yet match nlohmann's shortest-round-trip
  dtoa (e.g. `0.1` → `"0.10000000000000001"` vs `"0.1"`). An earlier draft
  claimed doubles never reach a digest path and excluded them from scope; the
  review REFUTED that. A double IS adversarially reachable on the abort-event
  K-of-K digest: `src/chain/block.cpp` stores `AbortEvent::claims_json`
  VERBATIM from peer JSON (unknown members kept), the per-claim Ed25519
  signature covers only typed scalars (`make_abort_claim_message` hashes
  `block_index‖round‖prev_hash‖missing_creator`, not the JSON), and
  `hash_abort_event()` SHA-256s `claims_json.dump()` into the digest — so an
  attacker can inject `"z":0.1` into an otherwise-valid claim and it rides the
  digest. Therefore the consumer swap (owner-gated) MUST close double
  dump-parity before it touches this site — either (a) give `dump_double` a
  shortest-round-trip serializer matching nlohmann byte for byte, or (b)
  re-canonicalize `claims_json` from typed `AbortClaimMsg` fields before hashing
  (stripping unknown members; this also hardens the pre-existing weakness that
  the abort digest today binds attacker-injectable non-semantic bytes even under
  nlohmann). `test-determ-json` WITNESSES the current double gap (a passing
  `diverge > 0` tripwire that flips RED when parity lands) so it cannot be
  forgotten. Any integer literal exceeding `uint64` also falls back to double
  (stricter classification), on the same footing. **UPDATE: the concrete fork
  vector this finding named — an injected double riding the abort-event digest —
  is now CLOSED at the source by
  [AbortDigestCanonicalizationSoundness.md](AbortDigestCanonicalizationSoundness.md):
  `hash_abort_event` canonicalizes the claims (stripping unknown members) before
  hashing, so no attacker-controlled double reaches that serializer. The residual
  double concern for the swap is the RPC-HMAC path (`method|params.dump()`),
  where a serializer divergence fails auth CLOSED (mismatch) rather than forking
  consensus. Double dump-parity therefore remains a swap *robustness* item, not a
  live fork vector.**
- **NC-2 (property, not yet a consumer).** DJP-1 is a property of the module.
  Increment 1 does not make `determ::djson` the writer at any consensus byte
  path; the swap is the owner-gated increment where a mixed-implementation
  abort-event cluster test is the additional gate.
- **NC-3 (empirical, corpus-bounded — now widened to the daemon's real
  surfaces).** Parity is established against nlohmann as the reference over a
  representative corpus plus the two exact shapes — not a formal proof over all
  inputs. **Increment 2 (`determ test-determ-json-surfaces`) widens the coverage
  to the daemon's ACTUAL serialization:** for each real object the daemon emits
  — Transaction, Block (incl. an abort-carrying block), AbortEvent+claim,
  EquivocationEvent, GenesisAlloc, `Chain::serialize_state` snapshot, RPC params,
  gossip envelope — it asserts `determ::djson::parse(obj.to_json().dump()).dump()
  == obj.to_json().dump()`, i.e. determ::djson round-trips the daemon's exact
  bytes. This is the **parse+dump** byte-parity on real shapes; the **build+dump**
  path (determ::djson's own builder producing canonical bytes) is covered by the
  DJP-2 builder assertion in inc.1. Together they are the swap-readiness
  evidence `MinixTacticalProfile.md` §5 asks for. **Increment 3 (`determ
  test-determ-json-fuzz`) elevates the coverage from corpus-bounded to
  FUZZ-TESTED:** a deterministic (splitmix64, fixed-seed → identical inputs on
  MSVC + GCC) differential fuzzer generates thousands of random in-scope values
  (bounded-depth objects/arrays, u64/i64, bool/null, ASCII + UTF-8 +
  escape-triggering strings) and cross-checks BOTH determ::djson code paths
  against nlohmann per value — build+dump (nlohmann tree → determ::djson builder
  → dump) and parse+dump — each byte-identical to nlohmann's dump; a
  type-coverage assertion proves the generator exercises all seven value kinds
  (non-vacuous). 100k-value standalone runs pass on both platforms with zero
  divergence. **Increment 4 (`determ test-determ-json-adversarial`) adds the
  ADVERSARIAL accept/reject-agreement sweep (DJP-5): 94+ hostile/boundary inputs
  where the risk is a parse-disagreement, not a dump-mismatch — it found + closed
  the overflow-to-non-finite accept divergence (DJP-5) and witnesses the NC-4
  deliberate carve-outs.** Node `Config` doubles remain the one uncovered surface
  (NC-1, off every wire/digest/HMAC path).
- **NC-4 (deliberate stricter-than-nlohmann surface).** Three divergences are
  stricter than / divergent from nlohmann by design (peer-facing hardening), and
  DJP-5 agreement is claimed only on the in-scope grammar, NOT on these: (a) the
  nesting **depth cap** (determ rejects >64-deep input nlohmann accepts); (b) the
  `>uint64 → double` fallback (dump-form divergence, NC-1); and (c) a **trailing
  NUL** after a complete value — nlohmann's lexer maps `0x00` to end-of-input (a
  string-literal convenience) and ACCEPTS `1\x00`, while `determ::djson` treats
  `0x00` as non-whitespace trailing content and REJECTS it. All three are safe:
  the honest consensus subset never nests 64 deep, never exceeds u64, and never
  carries a trailing NUL, so none can false-reject an honest input, and the
  trailing-NUL/depth cases fail CLOSED (determ stricter). inc.4 WITNESSES the
  depth and trailing-NUL divergences explicitly (asserting determ rejects while
  nlohmann accepts) so a future change can't silently flip them.

## 6. Gate

`determ test-determ-json` (`tools/test_determ_json.sh`, FAST via
`determ_json`): the §3 dual-oracle parity corpus + idempotence, explicit
key-sort canonicalization, the two byte-critical shapes, the builder path
(programmatic construction dumps canonically), strict-UTF-8 fail-closed on dump
(both implementations throw), the parse-rejection agreement corpus, and the
depth-cap hardening (over-deep rejected; within-cap still byte-parity). **inc.2
`determ test-determ-json-surfaces` (`tools/test_determ_json_surfaces.sh`, FAST
via `determ_json_surfaces`): the real-surface parse+dump byte-parity of NC-3 over
the daemon's actual Transaction / Block / AbortEvent / EquivocationEvent /
GenesisAlloc / snapshot / RPC / envelope serialization. **inc.3 `determ
test-determ-json-fuzz` (`tools/test_determ_json_fuzz.sh`, FAST via
`determ_json_fuzz`): the deterministic differential fuzzer of NC-3 — thousands
of random in-scope values, both build+dump and parse+dump byte-checked vs
nlohmann, with a generator type-coverage (non-vacuity) assertion.** **inc.4
`determ test-determ-json-adversarial` (`tools/test_determ_json_adversarial.sh`,
FAST via `determ_json_adversarial`): the DJP-5 adversarial accept/reject-agreement
sweep — literal-case, NaN/Infinity, the number-malformation grammar (incl. the
overflow-to-non-finite case its review closed), `\u` surrogate edges, u64/i64
boundaries, and whitespace/dup-key canonicalization; witnesses the NC-4 deliberate
divergences (depth cap, trailing NUL) rather than asserting agreement on them.**
Both platforms: MSVC + WSL2 GCC `ci_local`. Anchored by
`include/determ/json/json.hpp` + the `test-determ-json` subcommand in
`src/main.cpp`. Cross-references `MinixTacticalProfile.md` §5,
`RpcAuthHmacSoundness.md` (the HMAC pre-image this canonical form feeds).
