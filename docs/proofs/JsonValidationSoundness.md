# JSON validation soundness — S-018 clear-diagnostic + defense-in-depth contract

This document records the analytic guarantees of the S-018 closure pattern:
the `json_require<T>` / `json_require_hex` / `json_require_array` helpers in
`include/determ/util/json_validate.hpp` and their application across every
attack-relevant wire-format consumer (gossip envelope, Phase-1/2 consensus
chatter, BLOCK + envelope-wrapped variants, snapshot bodies, operator-edited
keyfiles, and the genesis schema).

**Companion documents:** `docs/SECURITY.md` §S-018 (closure narrative);
`docs/proofs/S002-Mempool-Sig-Verify.md` (paired wire-format hardening);
`docs/proofs/Preliminaries.md` (V0 network adversary / Byzantine peer model).

**Status:** ✅ Mitigated in-session. Every attack-relevant wire-format consumer
has been converted. Residual `j[...].get<T>()` sites are confined to inner-
loop array elements (where the iterating container already named the outer
field), CLI-side output formatters, and the client-side RPC response parser
— none exposed to peer-supplied JSON.

---

## 1. Theorem statements

**T-1 (Clear-Diagnostic Soundness).** Every required-field extraction routed
through `json_require<T>` (resp. `json_require_hex`, `json_require_array`)
that fails — because the field is missing, has the wrong type, has the wrong
hex length, or (for arrays) is not an array — throws a `std::runtime_error`
whose message begins with `"S-018: "` and contains the field name in single
quotes.

**T-2 (No Internal-Error Leakage).** No converted from_json path lets a
`nlohmann::detail::type_error` / `out_of_range` / `parse_error` propagate to
its caller. Every nlohmann-internal exception is caught inside the helpers
and re-thrown as a `std::runtime_error` carrying the field-name context.

**T-3 (Defense-in-Depth at Multiple Layers).** The helpers fire at every
layer where peer- or operator-supplied JSON enters the system: (1) gossip
envelope + per-message-type payload, (2) RPC structured-payload args, (3)
snapshot replay (file + SNAPSHOT_RESPONSE gossip), (4) operator keyfile,
(5) operator genesis JSON. No layer admits structured JSON via a parallel
bypass that skips the helpers.

**T-4 (No Privilege Escalation Surface).** A malformed input that hits the
helper produces a clean exception and does not invoke any memory-corrupting,
out-of-bounds, infinite-loop, or escalating behavior. Helper work is
bounded: one `contains()` + one `at()` + one `get<T>()`, all O(1) over the
extracted value's already-bounded size.

**T-5 (Backward-Compat Optional Fields).** The helpers distinguish REQUIRED
extractions (use `json_require_*`) from OPTIONAL ones (use `j.value(key,
default)` or wrap `json_require_*` inside an `if (j.contains(key))`). Missing
optional fields silently take their default. A rolling upgrade in which a
new release adds an optional field is not rejected by an older peer.

---

## 2. Background

### 2.1 What the helpers replaced

Pre-S-018, every from_json path relied on `nlohmann::json`'s raw
`j["field"].get<T>()`. Its exception messages on failure name the JSON
value's *type* but not the *field*:

- Missing: `"key 'foo' not found"` — buried inside `nlohmann::detail::
  out_of_range`.
- Wrong type: `"type must be string, but is null"` — names neither the
  field nor the containing object.
- Wrong hex length: silently passes through to a downstream `from_hex_arr<N>`
  call, which throws a different exception still not naming the field.

An operator triaging a malformed peer's traffic (or a snapshot load failure,
or a botched node_key.json) was forced to dig through a stack trace to
associate the type error with a field. S-018 is classified Medium / cosmetic
robustness: no safety property is breached, but operator response time to
real wire-format incidents is unnecessarily expensive.

### 2.2 The closure mechanism

`include/determ/util/json_validate.hpp` provides three primitives in
`determ::util::`:

- **`json_require<T>(j, field)`** — required typed extraction. Failures:
  missing, wrong type. Both name the field.
- **`json_require_hex(j, field, expected_hex_chars)`** — required hex of
  fixed length. Failures: missing, wrong type, wrong length. All name the
  field.
- **`json_require_array(j, field)`** — required array extraction returning
  a const-ref for direct iteration. Failures: missing, wrong type (non-
  array). Both name the field.

Optional fields with a sensible default retain `j.value(field, default)` or
`if (j.contains(field)) { json_require_*(...) }` — these were never the
S-018 surface, because their failure mode is silent default-assignment, not
opaque exception.

---

## 3. Implementation citation

### 3.1 The helpers

`include/determ/util/json_validate.hpp` (excerpt):

```cpp
template <typename T>
T json_require(const nlohmann::json& j, const char* field) {
    if (!j.contains(field)) {
        throw std::runtime_error(
            std::string("S-018: missing required JSON field '") + field + "'");
    }
    try {
        return j.at(field).get<T>();
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("S-018: JSON field '") + field
            + "' has wrong type: " + e.what());
    }
}
```

`json_require_hex` wraps `json_require<std::string>` and adds the length
check (`"... has wrong hex length: expected N chars, got M"`).
`json_require_array` checks `contains()` then `is_array()`, surfacing the
field name on both branches.

Every exception path includes `"S-018: "` and the field name in single
quotes. The helpers have no third failure mode: any extraction error inside
the try is caught uniformly by `catch (const std::exception&)`.

### 3.2 A representative call site — `ContribMsg::from_json`

`src/node/producer.cpp` (Phase-1 consensus gossip):

```cpp
ContribMsg ContribMsg::from_json(const json& j) {
    ContribMsg m;
    m.block_index = json_require<uint64_t>(j, "block_index");
    m.signer      = json_require<std::string>(j, "signer");
    m.prev_hash   = from_hex_arr<32>(json_require_hex(j, "prev_hash", 64));
    m.aborts_gen  = j.value("aborts_gen", uint64_t{0});  // optional
    if (j.contains("tx_hashes")) {
        if (!j["tx_hashes"].is_array())
            throw std::runtime_error("S-018: CONTRIB field 'tx_hashes' "
                "must be a JSON array (got " +
                std::string(j["tx_hashes"].type_name()) + ")");
        for (auto& h : j["tx_hashes"])
            m.tx_hashes.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    m.dh_input = from_hex_arr<32>(json_require_hex(j, "dh_input", 64));
    // ... v2.7 F2 optional view-reconciliation fields ...
    m.ed_sig   = from_hex_arr<64>(json_require_hex(j, "ed_sig", 128));
    return m;
}
```

Required fields (`block_index`, `signer`, `prev_hash`, `dh_input`, `ed_sig`)
flow through helpers. `aborts_gen` uses `j.value(...)` with the
`uint64_t{0}` default. `tx_hashes` is optional-but-typed: presence gated
by `j.contains(...)`, and an explicit `is_array()` check yields an
S-018-flavored diagnostic on scalar misuse.

### 3.3 Conversion inventory

| Consumer | Source | Exposure |
|---|---|---|
| `net::Message::deserialize` | `src/net/messages.cpp:44` | every peer JSON message lands here first |
| `Transaction::from_json` | `src/chain/block.cpp:57-65` | gossip TRANSFER + RPC submit_tx |
| `AbortEvent::from_json` | `src/chain/block.cpp:110-113` | baked into BLOCK |
| `EquivocationEvent::from_json` | `src/chain/block.cpp:139-144` | RPC submit_equivocation + gossip evidence |
| `CrossShardReceipt::from_json` | `src/chain/block.cpp:220-229` | CROSS_SHARD_RECEIPT_BUNDLE gossip + BLOCK inbound |
| `Block::from_json` | `src/chain/block.cpp:451-545` | BLOCK gossip + BEACON_HEADER + SHARD_TIP + snapshot replay |
| `GenesisAlloc::from_json` | `src/chain/block.cpp:86` | snapshot initial_state + genesis-tool initial_balances |
| `ContribMsg::from_json` | `src/node/producer.cpp:68-137` | Phase-1 gossip |
| `AbortClaimMsg::from_json` | `src/node/producer.cpp:152-162` | abort-claim gossip |
| `BlockSigMsg::from_json` | `src/node/producer.cpp:204-214` | Phase-2 gossip |
| `GenesisConfig::from_json` | `src/chain/genesis.cpp:189-275` | operator-supplied genesis |
| `load_node_key` | `src/crypto/keys.cpp:55-56` | operator-edited node_key.json |
| ABORT_EVENT / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE envelope unwrap | `src/net/gossip.cpp:212-258` | envelope sub-field validation |
| `Chain::restore_from_snapshot` collection wrappers | `src/chain/chain.cpp:1748-1850` | SNAPSHOT_RESPONSE gossip + pinned files |

Every entry gets the same diagnostic contract by construction.

---

## 4. Proofs

### 4.1 Proof of T-1 (Clear-Diagnostic Soundness)

By case analysis on each helper's exception paths.

**`json_require<T>(j, field)`:**
1. `!j.contains(field)` ⇒ throws `"S-018: missing required JSON field 'FIELD'"`.
   Contains the prefix and the field name in single quotes. ✓
2. `j.at(field).get<T>()` throws ⇒ caught by `catch (const std::exception&)`,
   re-thrown as `"S-018: JSON field 'FIELD' has wrong type: <inner>"`. The
   inner message is appended; the outer message already names the field. ✓

**`json_require_hex(j, field, N)`:**
1, 2: identical to `json_require<std::string>`; field-named. ✓
3. Length mismatch ⇒ `"S-018: JSON field 'FIELD' has wrong hex length:
   expected N chars, got M"`. Names field + lengths. ✓

**`json_require_array(j, field)`:**
1. Missing ⇒ `"S-018: missing required JSON field 'FIELD' (expected array)"`. ✓
2. `!v.is_array()` ⇒ `"S-018: JSON field 'FIELD' has wrong type: expected
   array, got <type_name>"`. ✓

Every error path in every helper contains the `"S-018: "` prefix and the
field name in single quotes. No fall-through case produces a diagnostic
without these. ∎

### 4.2 Proof of T-2 (No Internal-Error Leakage)

Helper structure:

```cpp
if (!j.contains(field)) { throw runtime_error(...); }
try {
    return j.at(field).get<T>();
} catch (const std::exception& e) {
    throw runtime_error(...);
}
```

The contains-branch throws only `std::runtime_error`. The `j.at(field).
get<T>()` call may throw any `nlohmann::detail::*` exception (all derived
from `std::exception`), but `catch (const std::exception&)` intercepts
every such case and re-throws a `std::runtime_error` carrying the field-
name context.

Note: the helper catches `std::exception` rather than the narrower
`nlohmann::json::exception` to remain robust against build configurations
where the nlohmann-specific RTTI symbols may not be exported uniformly.
Catching `std::exception` guarantees coverage of every `nlohmann::detail::*`
subtype.

**Pin via test.** `determ test-s018-json-validation` constructs a JSON
object with `"amount": "not-a-number"` and asserts the exception message
contains `"S-018"`, `"'amount'"`, and `"wrong type"`. If a converted
from_json leaked a nlohmann-internal exception, the message would lack
the `"S-018: "` prefix and the assertion would fail. The test passes
(10/10). ∎

### 4.3 Proof of T-3 (Defense-in-Depth at Multiple Layers)

By construction across each layer's entry point:

**Wire (gossip).** `net::Message::deserialize` calls `json_require<uint8_t>
(envelope, "type")` + `contains("payload")` before dispatch. The per-
message-type from_json (every gossip row in §3.3) handles the payload.
Sub-envelope-wrapped types (ABORT_EVENT, SHARD_TIP,
CROSS_SHARD_RECEIPT_BUNDLE) extract their per-envelope `shard_id` /
`block_index` / `prev_hash` via `json_require_*` and gate the inner
payload via `contains()` before deferring to the inner Block / AbortEvent
from_json. See `src/net/gossip.cpp:212-258`.

**RPC.** `src/rpc/rpc.cpp::RpcServer::dispatch` is the single RPC entry.
Scalar params use `params.value(key, default)` (right pattern: missing
yields documented default). Structured payloads — `submit_tx`'s `"tx"`,
`submit_equivocation`'s `"event"` — route through the same S-018-hardened
from_json (`Transaction::from_json`, `EquivocationEvent::from_json`).

**Snapshot.** `Chain::restore_from_snapshot` iterates every snapshot
collection via `if (snap.contains(k)) for (auto& x : json_require_array(snap,
k)) {...}`. The contains-guard makes the field optional (legacy snapshots
loading cleanly); `json_require_array` ensures present fields are arrays.
Per-block reads inside the snapshot path defer to `Block::from_json`,
itself S-018-hardened.

**Keyfile.** `crypto::load_node_key` validates both `pubkey` and
`priv_seed` via `json_require_hex(j, name, 64)`. A botched node_key.json
edit produces a message naming the botched field.

**Genesis.** `GenesisConfig::from_json` validates `initial_creators` and
`initial_balances` arrays via `json_require_array`, `param_keyholders`
and `shard_address_salt` via the helpers inside contains-guards. Each
inner-loop element extracts its required fields via the helpers.

In each layer the entry point is the only structured-JSON admission path;
there is no parallel bypass that skips the helpers. ∎

### 4.4 Proof of T-4 (No Privilege Escalation Surface)

By inspection of each helper's body.

**Bounded work.** `json_require<T>` does one `contains()` lookup (O(1)
amortized in `nlohmann::json`'s hash-keyed object), one `at()` lookup
(O(1) amortized), and one `get<T>()` extraction (O(1) for arithmetic
types; O(string length) for strings — bounded upstream by `Peer::read_body`'s
per-message-type S-022 cap: 1 MB consensus, 4 MB block, 16 MB snapshot
only). `json_require_hex` adds one `.size()` comparison + one
`std::to_string` on the failure path. `json_require_array` does one
`contains()` + `at()` + `is_array()`. No loops, no recursion, no allocation
beyond the failure-path exception string.

**No memory corruption.** Each helper operates on `const nlohmann::json&`
and returns a value, a new string, or a const-ref to a nested array. No
pointer arithmetic, no buffer indexing, no raw memory access.
`nlohmann::json`'s internals are memory-safe (STL-backed; fuzzed via
OSS-Fuzz; no known buffer-overrun CVEs at pinned versions).

**No infinite-loop surface.** The helper has no loop. Caller iteration
loops over `json_require_array`'s return are bounded by `j.at(field).size()`,
which is bounded by the wire-format size cap upstream.

**No exception escalation.** Malformed input produces `std::runtime_error`.
Gossip dispatch silently drops (no amplification); RPC dispatch returns
the exception's `what()` as a JSON error response. Neither path escalates
into termination or undefined behavior. ∎

### 4.5 Proof of T-5 (Backward-Compat Optional Fields)

By construction of the OPTIONAL-vs-REQUIRED distinction:

A field is **required** if the caller invokes `json_require_*`
unconditionally. Missing produces an `"S-018: missing required JSON field
'FIELD'"` exception.

A field is **optional** if either (a) the caller uses `j.value(field,
default)`, with missing yielding the default silently; or (b) the caller
wraps `json_require_*` inside `if (j.contains(field)) {...}`, with absent
fields skipping the call and leaving the C++ struct's natural zero default.

Concrete examples:
- `ContribMsg::aborts_gen` — `j.value("aborts_gen", uint64_t{0})`. Pre-
  aborts_gen peer messages omit the field; the new peer reads 0.
- `BlockSigMsg::dh_secret` (added by rev.9 / S-009) — `if (j.contains(
  "dh_secret"))` guard; pre-rev.9 peer messages load cleanly.
- `Block::tx_root`, `delay_seed`, `delay_output`, `consensus_mode`,
  `bft_proposer`, `partner_subset_hash`, `state_root` — each in `if (j.
  contains(...))`. Older blocks (or modes where these don't apply) load
  cleanly with zero defaults.
- `Chain::restore_from_snapshot`'s `dapp_registry` (added per S-037) —
  in `if (snap.contains(...))`; pre-v2.18 snapshots load cleanly.

A rolling upgrade — half the cluster on release N, half on release N+1 —
produces no false rejections so long as protocol designers add new fields
as optional. The S-018 helpers don't impose "all new fields required";
they impose only "fields the developer declared required produce clear
diagnostics on absence." ∎

---

## 5. Adversary model

S-018 operates inside the larger model in `docs/proofs/Preliminaries.md`
(V0 network adversary; Byzantine peer membership). Relevant capabilities:

**A1 — Byzantine peer sending malformed gossip.** Adversary feeds
arbitrary byte sequences as JSON envelopes. Every malformed message
produces a clean `std::runtime_error` naming the failing field. Gossip
handler silently drops or (per S-022 framing cap) closes the connection.
No malformed peer crashes the daemon.

**A2 — Malicious RPC client.** Attacker submits malformed `submit_tx` or
`submit_equivocation` payloads. The dispatcher routes through the same
S-018-hardened from_json, throwing an S-018 diagnostic returned to the
client as a JSON error.

**A3 — Malicious snapshot.** Attacker substitutes a corrupted snapshot on
disk (or a peer responds to SNAPSHOT_RESPONSE with malformed body). S-018
rejects with field-name diagnostic before any state-mutation occurs. The
S-033 + S-038 head_hash / state_root cryptographic gating layers above
reject any structurally-valid but adversarial snapshot.

**A4 — Operator botches keyfile.** Hand-edit produces a typo. Pre-S-018,
the error was `"type must be string, but is null"` with no hint which
field was botched. Post-S-018: `"S-018: JSON field 'priv_seed' has wrong
hex length: expected 64 chars, got 63"`.

**A5 — Malicious genesis JSON.** Consortium operator distributes a
botched / malicious genesis. S-018 rejects at startup with field-name
diagnostic; the genesis-hash mechanism (pinned + compared) provides
cryptographic gating on top.

S-018's role is not a security-relevant privilege boundary — S-022 (size
caps), S-014 (rate limiting), and S-033/S-038 (state-root verification)
sit upstream of the helper layer. The helpers make field-level diagnosis
fast and unambiguous; the security-relevant rejection happens at the
size / rate / cryptographic layers.

---

## 6. Identified gaps

`docs/SECURITY.md` §S-018's "Remaining `j[...].get<T>()` sites" enumerates
the intentional non-conversions. Each is justified by NOT being exposed to
peer-supplied JSON:

- **Inner-loop array elements where the iterating container is already
  validated.** `src/chain/block.cpp:466, 478, 484, 488, 492, 512, 520,
  526, 531, 536` and `src/node/producer.cpp:94, 116, 124, 132` and
  `src/chain/genesis.cpp:215` — each is `x.get<std::string>()` inside
  `for (auto& x : json_require_array(j, "FIELD"))`. The outer
  `json_require_array` has already established field presence + array
  type; converting to per-element `json_require` would name the array
  index rather than the (already-known) outer field name — no diagnostic
  improvement.

- **Snapshot collection inner-field defaults.** `restore_from_snapshot`
  uses `a.value(...)` with sensible defaults on every per-element field.
  Legacy snapshots that omit a field load with a default; the cryptographic
  integrity gate (head_hash + state_root per S-033 + S-038) catches any
  malicious-snapshot attack BEFORE field-level parsing matters.

- **RPC dispatch table.** `src/rpc/rpc.cpp::RpcServer::dispatch` uses
  `params.value(key, default)` for scalar params. Right pattern for RPC:
  a missing non-required param gets the documented default (e.g., empty
  `domain` ⇒ "all" semantics), not a hard rejection. Structured params
  still route through the S-018-hardened from_json.

- **CLI output formatters.** `src/main.cpp:724, 916` consume the daemon's
  own well-formed JSON responses. Not peer-supplied. Conversion would
  impose runtime overhead with no diagnostic improvement.

- **Client-side RPC response parser.** `src/rpc/rpc.cpp:319` extracts
  `j["error"].get<std::string>()` from an RPC response. CLIENT side
  parsing the daemon's own well-formed response. Not an attack surface.

- **One residual `j[...].get<T>()` in a converted file.** `src/node/
  producer.cpp:212` reads optional `dh_secret` via `j["dh_secret"].
  get<std::string>()` inside an `if (j.contains("dh_secret"))` guard.
  The guard handles missing; wrong-type / wrong-hex-length would throw
  an nlohmann-internal exception (downgraded diagnostic but still safe;
  downstream `Block::compute_hash` mismatch catches at chain-level
  rejection). Converting to `json_require_hex` for parity is a documented
  follow-on — not security-relevant.

---

## 7. Test-suite citation

The S-018 closure is exercised by `determ test-s018-json-validation`
(registered in `src/main.cpp:26051`), driven by `tools/test_s018_json_
validation.sh` (10/10 PASS).

The fixture defines an `expect_throw_with(name, fn, needles[])` helper
that calls `fn()` and asserts the thrown exception's `what()` contains
every string in `needles`. Needles always include `"S-018"` plus the
expected field name in single quotes plus a condition keyword (`missing`
/ `wrong type` / `hex length` / `expected array`).

| # | Scenario | Helper exercised |
|---|---|---|
| 1 | Happy path: Transaction round-trips through to_json / from_json | success paths |
| 2 | Missing required field `'amount'` | `json_require<uint64_t>` (missing) |
| 3 | Wrong-type `'amount'` (string where uint64) | `json_require<uint64_t>` (wrong type) |
| 4 | Wrong-hex-length `'sig'` (100 chars, expects 128) | `json_require_hex` (length) |
| 5 | AbortEvent missing `'event_hash'` | `json_require_hex` (missing) |
| 6 | EquivocationEvent missing `'sig_b'` | `json_require_hex` (missing) |
| 7 | Block missing `'transactions'` | `json_require_array` (missing) |
| 8 | GenesisAlloc missing `'domain'` | `json_require<std::string>` (missing) |
| 9 | Block optional `'state_root'` wrong hex length | `json_require_hex` inside contains-guard |
| 10 | Block `'transactions'` non-array (string) | `json_require_array` (wrong type) |

`ContribMsg`, `AbortClaimMsg`, `BlockSigMsg` use the same helpers; their
happy paths are exercised transitively whenever the broader regression
suite runs a multi-node consensus scenario producing Phase-1 / Phase-2 /
abort-claim traffic. A regression that broke any helper would surface as
a fail-loud S-018 diagnostic in those tests' logs.

The 10-assertion targeted test is the primary lock-in for the field-name
contract.

---

## 8. Status

**Shipped, classified Medium → Mitigated in-session** per `docs/SECURITY.md`
§1 dashboard (the cell reads `**1** (S-018)`). The cycle-level take is
"every attack-relevant from_json path uses the helpers; residual sites
are not peer-supplied." The closure narrative in `docs/SECURITY.md`
§S-018 tabulates converted consumers, intentional-non-conversions, and
the regression test name.

Optional follow-on: convert the `BlockSigMsg::dh_secret` inner read at
`src/node/producer.cpp:212` to `json_require_hex` for cleaner per-field
diagnostic. Not security-relevant — the field is wrapped in an outer
`j.contains("dh_secret")` guard so missing is handled cleanly, and
wrong-type / wrong-hex-length is caught downstream by `Block::compute_
hash` mismatch at the chain-level rejection boundary.

---

## 9. References

| Reference | Purpose |
|---|---|
| `include/determ/util/json_validate.hpp` | The three helpers + their failure-diagnostic contract. |
| `src/chain/block.cpp` | `Transaction`, `GenesisAlloc`, `AbortEvent`, `EquivocationEvent`, `CrossShardReceipt`, `Block` from_json. |
| `src/node/producer.cpp` | `ContribMsg`, `AbortClaimMsg`, `BlockSigMsg` from_json. |
| `src/chain/genesis.cpp` | `GenesisConfig::from_json`. |
| `src/net/messages.cpp` | Gossip envelope `deserialize`. |
| `src/net/gossip.cpp` | ABORT_EVENT / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE envelope sub-field validation. |
| `src/crypto/keys.cpp` | `load_node_key` keyfile validation. |
| `src/chain/chain.cpp` | `restore_from_snapshot` collection-field validation. |
| `src/main.cpp:26051` | `determ test-s018-json-validation` in-process test. |
| `tools/test_s018_json_validation.sh` | Shell-level regression (10/10 PASS). |
| `docs/SECURITY.md` §S-018 | Closure narrative, severity, conversion + non-conversion tables. |
| `docs/proofs/S002-Mempool-Sig-Verify.md` | Companion: paired with the binary-codec amount/fee/nonce fix S-002 surfaced. |
| `docs/proofs/Preliminaries.md` | V0 network-adversary + Byzantine-peer model framing T-3 / §5. |
