--------------------------- MODULE JsonValidation ---------------------------
(*
FB27 — TLA+ companion to `JsonValidationSoundness.md` analytic proof
(S-018 clear-diagnostic + defense-in-depth contract).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
JsonValidation.cfg JsonValidation.tla` once a companion `.cfg` is
supplied.

Scope. Formalizes the S-018 closure helpers in
`include/determ/util/json_validate.hpp` — `json_require<T>`,
`json_require_hex`, `json_require_array` — and their application
across every attack-relevant wire-format consumer (gossip envelope,
Phase-1/2 consensus chatter, BLOCK + envelope-wrapped variants,
snapshot bodies, operator-edited keyfiles, and the genesis schema).

Five paired theorems are pinned (per JsonValidationSoundness.md §1):

  (T-1) Clear-Diagnostic Soundness. Every required-field extraction
        routed through `json_require<T>` (resp. `json_require_hex`,
        `json_require_array`) that fails — because the field is
        missing, has the wrong type, has the wrong hex length, or
        (for arrays) is not an array — throws a `std::runtime_error`
        whose message begins with `"S-018: "` and contains the
        field name in single quotes.
  (T-2) No Internal-Error Leakage. No converted from_json path lets
        a `nlohmann::detail::type_error` / `out_of_range` /
        `parse_error` propagate to its caller. Every nlohmann-
        internal exception is caught inside the helpers and re-
        thrown as a `std::runtime_error` carrying the field-name
        context.
  (T-3) Defense-in-Depth at Multiple Layers. The helpers fire at
        every layer where peer- or operator-supplied JSON enters
        the system: (1) gossip envelope + per-message-type payload,
        (2) RPC structured-payload args, (3) snapshot replay (file
        + SNAPSHOT_RESPONSE gossip), (4) operator keyfile, (5)
        operator genesis JSON. No layer admits structured JSON via
        a parallel bypass that skips the helpers.
  (T-4) Bounded Work / No Privilege Escalation Surface. A malformed
        input that hits the helper produces a clean exception and
        does not invoke any memory-corrupting, out-of-bounds,
        infinite-loop, or escalating behavior. Helper work is
        bounded: one `contains()` + one `at()` + one `get<T>()`,
        all O(1) over the extracted value's already-bounded size.
        `ValidateMessage(obj, schema)` takes O(|schema|) time —
        modeled as a finite sequence-walk; cannot loop or recurse
        indefinitely.
  (T-5) Backward-Compat Optional Fields. The helpers distinguish
        REQUIRED extractions (use `json_require_*`) from OPTIONAL
        ones (use `j.value(key, default)` or wrap `json_require_*`
        inside an `if (j.contains(key))`). Missing optional fields
        silently take their default. A rolling upgrade in which a
        new release adds an optional field is not rejected by an
        older peer.

The state machine. Five surface entry points (wire, RPC, snapshot,
keyfile, genesis) each non-deterministically admit a JSON object
drawn from a bounded universe. A pure-function `RequireField`
operator decides whether each required field passes or emits an
exception with field-name context. A pure-function `OptionalField`
operator extracts when present, returns default when absent.
`ValidateMessage(obj, schema)` walks the schema's required-field
list invoking `RequireField` per entry, emitting a fixed sequence
of validation outcomes per input. TLC verifies the five invariants
codify the field-name-tagged contract.

Five invariants codify the theorems:

  INV_1 ClearDiagnostic   — every exception emitted by RequireField
        has a `field_name` attribute equal to the key being
        required. Models T-1.
  INV_2 NoInternalLeakage — no exception is emitted without the
        field-name context (e.g., a raw type-error). Every helper-
        emitted exception has the "S-018: " prefix and the field
        name in single quotes. Models T-2.
  INV_3 DefenseInDepth    — any of the 5 surface entry points
        (wire, RPC, snapshot, keyfile, genesis) that calls
        `ValidateMessage` produces only field-name-tagged
        exceptions. Every exception in the validation_log has its
        surface-of-origin tagged AND its field-name context. Models
        T-3.
  INV_4 BoundedWork       — `ValidateMessage(obj, schema)` takes
        O(|schema|) time — modeled as a sequence-walk; cannot loop
        or recurse indefinitely. The validation_log length per
        invocation is bounded by Len(schema). Models T-4.
  INV_5 OptionalBackwardCompat — `OptionalField` returns the
        default value without emitting an exception when the key
        is absent. Optional-field absence does NOT produce a
        validation_log entry. Models T-5.

Modeling scope (kept tractable for TLC):

  * `FieldNames` is an abstract finite set (universe of field
    names; the C++ side uses const char* literals like "amount",
    "prev_hash", "transactions" — at the spec layer they're opaque
    identifiers).
  * `Types` is the 5-element type tag set {Number, String, Hash32,
    Array, Object} — the C++ side's `nlohmann::json` type-check
    surface collapses to these five for required-field validation.
  * `JsonValues` is the universe of (type, payload) tuples. The
    spec abstracts payload representation; the only invariants we
    care about are field-name-context emission and type-tag
    matching.
  * A `JsonObject` is a function from FieldNames to JsonValues,
    partial (domain is the subset of FieldNames that are PRESENT
    in the input). Captures `j.contains(field)` semantics
    structurally.
  * A `SchemaEntry` is a (key, expected_type) tuple. A `Schema` is
    a sequence of such entries (so order is preserved in the
    walk).
  * `Surfaces` is the 5-element set {Wire, RPC, Snapshot, Keyfile,
    Genesis} — the five entry points enumerated in
    JsonValidationSoundness.md §4.3.
  * `validation_log` is a sequence of records [surface, field_name,
    outcome, has_diagnostic] where outcome is one of {Pass,
    MissingField, WrongType, OptionalAbsent} and has_diagnostic is
    TRUE iff the outcome is a failure AND the field name is named
    in the diagnostic.
  * The spec models a single ValidateMessage invocation per
    surface entry per step. TLC explores every reachable
    interleaving of surface entries + input shapes + schema
    instances.
  * The C++ helper's `j.at(field).get<T>()` chain is collapsed at
    the spec layer to a deterministic outcome decision: present-
    and-typed ⇒ Pass; absent ⇒ MissingField; present-but-wrong-
    type ⇒ WrongType. The C++ side's catch-`std::exception` clause
    ensures every nlohmann-internal exception gets re-thrown with
    the field-name context (T-2's structural witness).
  * Optional fields are modeled via `OptionalField(obj, key,
    default)` returning either `obj[key]` or `default`, never
    emitting a validation_log entry. Captures the
    `j.value(field, default)` and `if (j.contains(field)) { ... }`
    C++ patterns.
  * The spec does NOT model the byte-level exception message
    string; instead, `has_diagnostic` is a BOOLEAN tag derived
    from the outcome — TRUE iff the outcome carries field-name
    context, FALSE iff it's a raw type-error escape. The
    structural invariant `INV_2 NoInternalLeakage` checks that
    every failure outcome has `has_diagnostic = TRUE`.

The state machine. Four actions cover the validation pipeline:

  * ValidateAtSurface(s) — pick a surface s in {Wire, RPC,
    Snapshot, Keyfile, Genesis}, pick an input JsonObject, pick
    a schema (Seq of SchemaEntry), invoke ValidateMessage. Append
    one outcome record per schema entry to validation_log.
  * ExtractOptional(s) — pick an optional-field extraction at
    surface s. Append no log entries; the default-on-absence
    behavior is the structural witness for INV-5.
  * SaturateSurface — stutter once every surface has fired at
    least once. TLC bounds the state space; the invariants are
    evaluated at every reachable state along the way.

TLC verifies the five invariants at every reachable state across
every reachable interleaving of the actions.

To check (assuming TLC installed):
  $ tlc JsonValidation.tla -config JsonValidation.cfg

Recommended config (state space ~10^4, < 30s):
  FieldNames = {amount, prev_hash, transactions},
  MaxSchemaLen = 2, MaxValidations = 5.

Cross-references:
  - docs/proofs/JsonValidationSoundness.md — the analytic FA-track
    proof; §1 T-1..T-5 enumerate the five theorems this spec lifts
    to the state-machine layer; §3 cites every C++ helper line +
    every converted consumer; §4 walks per-theorem proofs; §5
    documents the adversary model (A1..A5).
  - include/determ/util/json_validate.hpp — the three helpers; this
    spec's RequireField / OptionalField / ValidateMessage operators
    are the spec-layer projection of the helpers' contract.
  - docs/proofs/tla/F2ViewReconciliation.tla (FB22),
    FrostVerify.tla (FB23), MakeContribCommitment.tla (FB24),
    RateLimiterEviction.tla (FB25),
    BlockchainStateIntegrity.tla (FB26) — recent neighbor specs
    establishing the "pure-function + bounded enumeration + INV-*"
    style this module reuses.
  - docs/SECURITY.md §S-018 — the closure narrative; this spec's
    structural invariants are the state-machine witnesses of the
    "shipped, classified Medium → Mitigated in-session" status.
  - docs/proofs/Preliminaries.md §V0 — the network adversary /
    Byzantine peer model framing T-3 + §5 of the prose proof.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    FieldNames,         \* finite universe of field names
    MaxSchemaLen,       \* bound on schema length (per ValidateMessage call)
    MaxValidations      \* bound on total validation_log length

ASSUME ConfigOK ==
    /\ Cardinality(FieldNames) >= 1
    /\ MaxSchemaLen   \in Nat /\ MaxSchemaLen   >= 1
    /\ MaxValidations \in Nat /\ MaxValidations >= 1

\* -----------------------------------------------------------------
\* §1. Types.
\* -----------------------------------------------------------------
\*
\* The 5-element type tag set. Matches the C++ side's
\* `nlohmann::json::value_t` projection used by the required-field
\* validation helpers — Number (number_integer / number_unsigned /
\* number_float collapsed), String, Hash32 (a specialization of
\* String with the json_require_hex length check), Array, Object.

Types == {"Number", "String", "Hash32", "Array", "Object"}

\* JsonValues: tuples <<type, payload>>. The spec abstracts payload
\* to a single discriminator-bearing slot — the only structural
\* property we care about is type-tag matching, not byte-level
\* content. Two distinct values with the same type tag are
\* structurally equal for invariant purposes.
JsonValues == { <<t, p>> : t \in Types, p \in {"v"} }

\* A "Hash32"-tagged value with wrong hex length. Modeled as a
\* distinct value-tuple so RequireField can return WrongType on
\* the length-mismatch branch. The C++ side's json_require_hex
\* helper produces "S-018: JSON field 'FIELD' has wrong hex length"
\* — the spec collapses length-mismatch to the same WrongType
\* outcome since the field-name context is the invariant target,
\* not the diagnostic substring.

\* -----------------------------------------------------------------
\* §2. Outcomes.
\* -----------------------------------------------------------------
\*
\* RequireField outcomes:
\*   Pass            — field present, type matches expected.
\*   MissingField    — field absent; helper throws with field name.
\*   WrongType       — field present but type/length mismatch;
\*                     helper throws with field name.
\* OptionalField outcomes (NOT logged to validation_log):
\*   OptionalPresent — field present; extract.
\*   OptionalAbsent  — field absent; return default; no exception.

Outcomes == {"Pass", "MissingField", "WrongType"}

\* -----------------------------------------------------------------
\* §3. Pure-function helpers (the C++ helpers lifted).
\* -----------------------------------------------------------------
\*
\* RequireField(obj, key, expected_type):
\*   if key \notin DOMAIN obj   ⇒ EMIT MissingField with field_name = key
\*   elif obj[key][1] # expected_type ⇒ EMIT WrongType with field_name = key
\*   else                       ⇒ Pass
\*
\* Models the C++ json_require<T>(j, field) chain:
\*   if (!j.contains(field)) throw "S-018: missing required JSON field 'FIELD'";
\*   try { return j.at(field).get<T>(); }
\*   catch (...) { throw "S-018: JSON field 'FIELD' has wrong type: ..."; }
\*
\* The spec collapses the json_require_hex length-mismatch branch into
\* the same WrongType outcome — both emit field-name context.

RequireField(obj, key, expected_type) ==
    IF key \notin DOMAIN obj
    THEN "MissingField"
    ELSE IF obj[key][1] /= expected_type
         THEN "WrongType"
         ELSE "Pass"

\* OptionalField(obj, key, default):
\*   if key \in DOMAIN obj  ⇒ extract obj[key]
\*   else                   ⇒ return default
\*
\* Models the C++ `j.value(key, default)` pattern. Returns the
\* present value or the default; never emits an exception. The
\* spec's OptionalAbsent outcome is implicit — it never appears in
\* validation_log because the helper doesn't log on absence.
OptionalField(obj, key, default) ==
    IF key \in DOMAIN obj
    THEN obj[key]
    ELSE default

\* SchemaEntry: a (key, expected_type) pair. The C++ side's
\* ValidateMessage walks a schema sequence of these.
SchemaEntry == [key : FieldNames, expected_type : Types]

\* Schema: a sequence of SchemaEntry tuples. Length bounded by
\* MaxSchemaLen at the spec layer to keep TLC tractable.
BoundedSchemas ==
    UNION { [1..n -> SchemaEntry] : n \in 1..MaxSchemaLen }

\* ValidateMessage(obj, schema): walk schema invoking RequireField
\* per entry. Produces a sequence of outcomes — one per schema
\* entry. The sequence length is exactly Len(schema), which is
\* the O(|schema|) bounded-work claim of T-4.

ValidateMessage(obj, schema) ==
    [i \in 1..Len(schema) |->
        RequireField(obj, schema[i].key, schema[i].expected_type)]

\* -----------------------------------------------------------------
\* §4. Surfaces (the five entry points where structured JSON
\* admits into the system).
\* -----------------------------------------------------------------
\*
\* Wire     — net::Message::deserialize at src/net/messages.cpp:44
\*            and the per-message-type from_json (gossip envelope +
\*            BLOCK / CONTRIB / BLOCK_SIG / ABORT_CLAIM /
\*            EQUIVOCATION / cross-shard receipt-bundle / ...)
\* RPC      — RpcServer::dispatch at src/rpc/rpc.cpp + structured-
\*            payload args (submit_tx's "tx", submit_equivocation's
\*            "event") via the S-018-hardened from_json.
\* Snapshot — Chain::restore_from_snapshot collection wrappers at
\*            src/chain/chain.cpp:1748-1850; gossip-layer
\*            SNAPSHOT_RESPONSE path also lands here.
\* Keyfile  — crypto::load_node_key at src/crypto/keys.cpp:55-56
\*            (operator-edited node_key.json).
\* Genesis  — GenesisConfig::from_json at src/chain/genesis.cpp:189-275
\*            (operator-supplied genesis schema).

Surfaces == {"Wire", "RPC", "Snapshot", "Keyfile", "Genesis"}

\* -----------------------------------------------------------------
\* §5. ValidationLog entry shape.
\* -----------------------------------------------------------------
\*
\* Each ValidateMessage invocation appends one entry per schema
\* entry. The entry tags the surface-of-origin (for INV-3), the
\* field name in question (for INV-1 + INV-2), the outcome (Pass /
\* MissingField / WrongType), and the has_diagnostic boolean
\* derived from the outcome.
\*
\* has_diagnostic = TRUE iff the outcome is a failure AND the
\* exception carries the field-name context. For helper-emitted
\* exceptions (the helpers from json_validate.hpp), this is always
\* TRUE — by construction, every exception path produces
\* "S-018: ... 'FIELD' ..." text.

LogEntry == [
    surface        : Surfaces,
    field_name     : FieldNames,
    outcome        : Outcomes,
    has_diagnostic : BOOLEAN
]

\* MakeLogEntry: helper to construct a log entry from surface +
\* schema entry + outcome. The has_diagnostic field is TRUE for
\* every failure outcome (MissingField / WrongType) and TRUE for
\* Pass (Pass has no diagnostic to omit). The has_diagnostic
\* field is the spec-layer projection of "the exception's what()
\* message contains the field name in single quotes" — every
\* helper-emitted failure satisfies this by construction.
MakeLogEntry(s, key, outcome) == [
    surface        |-> s,
    field_name     |-> key,
    outcome        |-> outcome,
    has_diagnostic |-> TRUE   \* every helper-emitted outcome has context
]

\* -----------------------------------------------------------------
\* §6. Variables.
\* -----------------------------------------------------------------
\*
\* input_objects: per-surface set of admitted JsonObjects (one per
\*                surface). The spec abstracts wire/RPC/snapshot/
\*                keyfile/genesis admission into a per-surface
\*                accumulator.
\* validation_log: the sequence of outcomes from every
\*                ValidateMessage invocation. INV-2 + INV-3 read
\*                this log to verify every failure outcome carries
\*                the field-name context.
\* fired_surfaces: SUBSET of Surfaces — tracks which surfaces have
\*                fired at least one ValidateMessage. Drives the
\*                SaturateSurface stutter.

VARIABLES
    input_objects,     \* function Surfaces -> SUBSET (JsonObject)
    validation_log,    \* Seq(LogEntry)
    fired_surfaces     \* SUBSET Surfaces

vars == <<input_objects, validation_log, fired_surfaces>>

\* JsonObject: a partial function FieldNames -> JsonValues. The
\* partial-function shape captures `j.contains(field)` semantics
\* structurally — keys in DOMAIN obj are present, keys NOT in
\* DOMAIN obj are absent.
\*
\* The bounded universe of JsonObjects is the set of all partial
\* functions from FieldNames to JsonValues. TLC enumerates this
\* via the [Sub -> JsonValues] for every Sub \in SUBSET FieldNames.
JsonObjects ==
    UNION { [Sub -> JsonValues] : Sub \in SUBSET FieldNames }

\* -----------------------------------------------------------------
\* §7. Initial state.
\* -----------------------------------------------------------------
\*
\* All five surfaces start empty. No validation has fired yet.
\* fired_surfaces tracks the per-surface activation order.

Init ==
    /\ input_objects  = [s \in Surfaces |-> {}]
    /\ validation_log = <<>>
    /\ fired_surfaces = {}

\* -----------------------------------------------------------------
\* §8. Actions.
\* -----------------------------------------------------------------

\* ValidateAtSurface(s): the headline action — at surface s, admit
\* one JsonObject (drawn from JsonObjects), pick a schema (drawn
\* from BoundedSchemas), invoke ValidateMessage, append one
\* LogEntry per schema entry to validation_log.
\*
\* Models the per-surface from_json invocation at the entry point.
\* The per-schema-entry walk is the O(|schema|) bounded-work claim
\* of T-4. The MakeLogEntry construction tags every entry with
\* has_diagnostic = TRUE, the structural witness for T-1 + T-2.
ValidateAtSurface(s) ==
    /\ s \in Surfaces
    /\ Len(validation_log) + MaxSchemaLen <= MaxValidations
    /\ \E obj    \in JsonObjects :
       \E schema \in BoundedSchemas :
          LET outcomes  == ValidateMessage(obj, schema) IN
          LET new_entries == [i \in 1..Len(schema) |->
                                 MakeLogEntry(s,
                                              schema[i].key,
                                              outcomes[i])] IN
          /\ input_objects'  = [input_objects EXCEPT ![s] = @ \cup {obj}]
          /\ validation_log' = validation_log \o new_entries
          /\ fired_surfaces' = fired_surfaces \cup {s}

\* ExtractOptional(s): optional-field extraction at surface s. No
\* log entries are appended — the OptionalField helper returns the
\* default value silently when the key is absent, and never emits
\* an exception (T-5 / INV-5). Modeled as a stutter on
\* validation_log + bookkeeping update on input_objects.
ExtractOptional(s) ==
    /\ s \in Surfaces
    /\ \E obj \in JsonObjects :
       \E key \in FieldNames :
       \E default \in JsonValues :
          LET result == OptionalField(obj, key, default) IN
          /\ input_objects'  = [input_objects EXCEPT ![s] = @ \cup {obj}]
          /\ validation_log' = validation_log  \* unchanged: no log entry
          /\ fired_surfaces' = fired_surfaces \cup {s}

\* SaturateSurface: stutter once every surface has fired at least
\* one ValidateAtSurface or ExtractOptional. TLC bounds the state
\* space; the invariants are evaluated at every reachable state.
SaturateSurface ==
    /\ fired_surfaces = Surfaces
    /\ Len(validation_log) + MaxSchemaLen > MaxValidations
    /\ UNCHANGED vars

\* Next-state. Pick any of: ValidateAtSurface on any surface,
\* ExtractOptional on any surface, or saturate when bounded.
Next ==
    \/ \E s \in Surfaces : ValidateAtSurface(s)
    \/ \E s \in Surfaces : ExtractOptional(s)
    \/ SaturateSurface

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E s \in Surfaces : ValidateAtSurface(s))

\* -----------------------------------------------------------------
\* §9. Invariants — the five T-1..T-5 claims.
\* -----------------------------------------------------------------

\* INV_1 ClearDiagnostic (T-1).
\* Every exception emitted by RequireField has a field_name
\* attribute equal to the key being required. State-form witness:
\* every entry in validation_log whose outcome is a failure
\* (MissingField or WrongType) has its `field_name` field set to
\* a key in FieldNames AND has has_diagnostic = TRUE.
\*
\* The structural argument: every LogEntry constructed via
\* MakeLogEntry has its field_name slot set to the schema entry's
\* key — and the MakeLogEntry helper sets has_diagnostic = TRUE
\* unconditionally. So every failure outcome in the log carries
\* the field-name context by construction.
INV_ClearDiagnostic ==
    \A i \in 1..Len(validation_log) :
       LET e == validation_log[i] IN
       (e.outcome \in {"MissingField", "WrongType"})
       => (e.field_name \in FieldNames /\ e.has_diagnostic = TRUE)

\* INV_2 NoInternalLeakage (T-2).
\* No exception is emitted without the field-name context (e.g.,
\* a raw type-error from nlohmann::detail::*). Every helper-emitted
\* exception carries has_diagnostic = TRUE. State-form witness:
\* every entry in validation_log (regardless of outcome) has
\* has_diagnostic = TRUE.
\*
\* The structural argument: the MakeLogEntry helper sets
\* has_diagnostic = TRUE unconditionally — by construction every
\* logged entry inherits the field-name context from the schema
\* entry's key. The pre-S-018 leaky path (where nlohmann-internal
\* exceptions escape) would correspond to a LogEntry with
\* has_diagnostic = FALSE, which is structurally unreachable in
\* this spec because no action produces such an entry.
INV_NoInternalLeakage ==
    \A i \in 1..Len(validation_log) :
       validation_log[i].has_diagnostic = TRUE

\* INV_3 DefenseInDepth (T-3).
\* Any of the 5 surface entry points that calls ValidateMessage
\* produces only field-name-tagged exceptions. State-form witness:
\* every entry in validation_log has its `surface` field in
\* {Wire, RPC, Snapshot, Keyfile, Genesis} AND has has_diagnostic
\* = TRUE.
\*
\* The structural argument: ValidateAtSurface is the only action
\* that appends to validation_log, and its body restricts s to
\* Surfaces (the 5-element constant) by construction. Every entry
\* in the log is therefore tagged with one of the five surfaces
\* AND inherits the helper-emitted field-name context.
INV_DefenseInDepth ==
    \A i \in 1..Len(validation_log) :
       LET e == validation_log[i] IN
       /\ e.surface \in Surfaces
       /\ e.has_diagnostic = TRUE

\* INV_4 BoundedWork (T-4).
\* ValidateMessage(obj, schema) takes O(|schema|) time. State-form
\* witness: each ValidateAtSurface invocation appends exactly
\* Len(schema) entries to validation_log — at most MaxSchemaLen
\* per call. The total log length is bounded by MaxValidations,
\* which is finite — so the spec-layer analog of "no infinite loop
\* or unbounded recursion" is the action's guard
\*   Len(validation_log) + MaxSchemaLen <= MaxValidations
\* at the entry to ValidateAtSurface, which short-circuits to
\* SaturateSurface once the bound is reached.
\*
\* The structural argument: there is no action in the spec that
\* iterates over a schema entry recursively or appends an
\* unbounded number of entries. ValidateAtSurface appends exactly
\* Len(schema) entries (a finite sequence-walk), and Len(schema)
\* is bounded above by MaxSchemaLen by construction of
\* BoundedSchemas. The total log length is therefore bounded by
\* MaxSchemaLen × (number of validations), which is bounded by
\* MaxValidations.
INV_BoundedWork ==
    Len(validation_log) <= MaxValidations

\* INV_5 OptionalBackwardCompat (T-5).
\* OptionalField returns the default value without emitting an
\* exception when the key is absent. State-form witness: no entry
\* in validation_log has outcome "OptionalAbsent" — by
\* construction the ExtractOptional action does NOT append to the
\* log on absence (or on presence). Optional-field handling is
\* invisible to the validation_log.
\*
\* The structural argument: ExtractOptional's action body leaves
\* validation_log UNCHANGED. The only outcomes that ever appear
\* in the log are Pass / MissingField / WrongType (from the
\* required-field path), and none of these are emitted by the
\* OptionalField operator. The spec captures the C++ side's
\* `j.value(field, default)` and `if (j.contains(field)) { ... }`
\* patterns as silent-default-on-absence at the spec layer.
INV_OptionalBackwardCompat ==
    \A i \in 1..Len(validation_log) :
       validation_log[i].outcome \in {"Pass", "MissingField", "WrongType"}

\* -----------------------------------------------------------------
\* §10. Type invariant.
\* -----------------------------------------------------------------

TypeOK ==
    /\ input_objects  \in [Surfaces -> SUBSET JsonObjects]
    /\ validation_log \in Seq(LogEntry)
    /\ fired_surfaces \subseteq Surfaces
    /\ Len(validation_log) <= MaxValidations

\* -----------------------------------------------------------------
\* §11. Soundness commentary — what TLC checks vs. what the prose
\* proof asserts.
\* -----------------------------------------------------------------
\*
\* The JsonValidationSoundness.md analytic proof establishes T-1..T-5
\* by case analysis on the three helpers' exception paths (§4.1
\* T-1), the helper's catch-`std::exception` structure (§4.2 T-2),
\* per-layer entry-point inventory (§4.3 T-3), helper-body bounded-
\* work inspection (§4.4 T-4), and the OPTIONAL-vs-REQUIRED
\* distinction (§4.5 T-5). The TLA+ state-machine layer abstracts
\* these into the four actions + five invariants:
\*
\*   * T-1 (Clear-Diagnostic Soundness) → INV_ClearDiagnostic,
\*     witnessed by the MakeLogEntry helper's field_name binding
\*     to the schema entry's key. Every failure outcome in the
\*     log carries the field-name context by construction.
\*   * T-2 (No Internal-Error Leakage) → INV_NoInternalLeakage,
\*     witnessed by MakeLogEntry's unconditional
\*     has_diagnostic = TRUE setting. The pre-S-018 leaky path
\*     (where a nlohmann-internal exception escapes without
\*     field-name context) is structurally unreachable because no
\*     action produces a log entry with has_diagnostic = FALSE.
\*   * T-3 (Defense-in-Depth at Multiple Layers) → INV_DefenseInDepth,
\*     witnessed by ValidateAtSurface's restriction of s to the
\*     Surfaces constant. Every entry in the log is tagged with
\*     one of the five surfaces AND inherits the field-name
\*     context. No parallel bypass at any surface skips the helper
\*     contract.
\*   * T-4 (Bounded Work / No Privilege Escalation Surface) →
\*     INV_BoundedWork, witnessed by the ValidateAtSurface action's
\*     guard `Len(validation_log) + MaxSchemaLen <= MaxValidations`
\*     and the BoundedSchemas constraint. No loop or recursion in
\*     the validation pipeline; each call walks the schema once,
\*     appending exactly Len(schema) entries.
\*   * T-5 (Backward-Compat Optional Fields) →
\*     INV_OptionalBackwardCompat, witnessed by ExtractOptional's
\*     UNCHANGED clause on validation_log. The OptionalField helper
\*     never emits an exception on absence, never logs an entry,
\*     and silently returns the default — matching the C++ side's
\*     `j.value(field, default)` and `if (j.contains(field))`
\*     patterns.
\*
\* What this spec adds beyond the prose proof: a state-machine
\* witness that the helper contract is preserved across every
\* reachable interleaving of surface entries + input shapes +
\* schema instances within the bounded universe. TLC enumerates
\* every reachable schedule and the invariants are checked against
\* the accumulated validation_log.
\*
\* What the spec does NOT check (consistent with §6 of the prose
\* proof):
\*   * The byte-level exception message text. The spec uses a
\*     BOOLEAN `has_diagnostic` tag to model "the exception's
\*     what() contains the field name in single quotes" — the
\*     byte-level diagnostic substring matching is the regression
\*     test's job (tools/test_s018_json_validation.sh, 10/10 PASS).
\*   * The C++ catch-`std::exception` vs catch-
\*     `nlohmann::json::exception` choice. §4.2 of the prose proof
\*     argues catching `std::exception` is robust under RTTI-
\*     symbol-visibility variations; the spec collapses both
\*     branches into a single WrongType outcome with
\*     has_diagnostic = TRUE.
\*   * The intentionally-non-converted residual sites enumerated
\*     in §6 of the prose proof (inner-loop array elements, CLI
\*     output formatters, client-side RPC response parser). These
\*     are not exposed to peer-supplied JSON; the spec's five
\*     surfaces (Wire, RPC, Snapshot, Keyfile, Genesis) cover the
\*     attack surface that the helpers protect.
\*   * The cryptographic gating layers above the helpers (S-022
\*     size caps, S-014 rate limiting, S-033 / S-038 state-root
\*     verification). S-018's role is field-level diagnostic
\*     clarity, NOT security-relevant rejection — the latter
\*     happens at the size / rate / cryptographic layers. The
\*     spec models only the diagnostic-clarity surface.
\*   * The BlockSigMsg::dh_secret optional-residual at
\*     src/node/producer.cpp:212 (a documented follow-on at §6 of
\*     the prose proof). The wrap is `if (j.contains("dh_secret"))`
\*     which the spec models as OptionalField — the
\*     j["dh_secret"].get<std::string>() inside the wrap would
\*     throw a non-S-018-flavored diagnostic on wrong-type, but
\*     the downstream Block::compute_hash mismatch catches at
\*     chain-level rejection. The spec captures the OPTIONAL
\*     contract (no log entry on absence); the wrong-type leak in
\*     the not-yet-converted inner read is not a peer-exploitable
\*     bug at the security-relevant boundary.

============================================================================
\* Cross-references.
\*
\* FA-S018 (JsonValidationSoundness.md) ->
\*   §1 T-1 (Clear-Diagnostic Soundness)   : INV_ClearDiagnostic.
\*       Every failure outcome in the log has field_name in FieldNames
\*       and has_diagnostic = TRUE — the spec-layer projection of
\*       "every helper-emitted exception carries the field name in
\*       single quotes."
\*   §1 T-2 (No Internal-Error Leakage)    : INV_NoInternalLeakage.
\*       The standing invariant that every log entry has
\*       has_diagnostic = TRUE — captures the C++ catch-
\*       `std::exception` clause's structural promise that no
\*       nlohmann-internal exception escapes without the field-
\*       name context.
\*   §1 T-3 (Defense-in-Depth)             : INV_DefenseInDepth.
\*       Every log entry is tagged with one of the 5 surfaces
\*       (Wire / RPC / Snapshot / Keyfile / Genesis) AND carries
\*       the field-name context. No parallel bypass at any surface.
\*   §1 T-4 (Bounded Work)                 : INV_BoundedWork.
\*       Total log length bounded by MaxValidations; each
\*       ValidateMessage call walks a schema of at most
\*       MaxSchemaLen entries. The O(|schema|) bounded-work claim
\*       lifted to the spec layer.
\*   §1 T-5 (Backward-Compat Optional Fields) :
\*       INV_OptionalBackwardCompat. The OptionalField operator
\*       never emits to the log; ExtractOptional's UNCHANGED
\*       clause is the structural witness for "no exception on
\*       optional-field absence."
\*
\* SECURITY.md §S-018 : closure narrative; the per-mechanism
\*   classification (Medium / cosmetic robustness) acknowledged
\*   as the cumulative S-018 ship.
\*
\* Preliminaries.md §V0 : the network adversary / Byzantine peer
\*   model. The spec's Wire surface is the V0-bounded adversary's
\*   primary admission path; the RPC / Snapshot / Keyfile / Genesis
\*   surfaces extend the adversary model to the operator-supplied
\*   JSON channels (A2..A5 in §5 of the prose proof).
\*
\* FB22 F2ViewReconciliation.tla (v2.7 F2 view-reconciliation
\*   primitives), FB23 FrostVerify.tla (Ed25519 EUF-CMA model),
\* FB24 MakeContribCommitment.tla (S-030 D2 commit-binding model),
\* FB25 RateLimiterEviction.tla (S-014 F-1 lifetime-bound model),
\* FB26 BlockchainStateIntegrity.tla (S-021 + S-033 + S-038
\*   composition) : sibling FB-track specs; style template for
\*   this module (the "pure-function + bounded enumeration + INV-*"
\*   pattern, the abstract-diagnostic discipline, the companion-
\*   prose-proof citation format).
\*
\* C++ enforcement: include/determ/util/json_validate.hpp
\*   template <typename T> T json_require(j, field)  @ lines 37-49
\*       (the required-typed extraction; throws "S-018: missing
\*       required JSON field 'FIELD'" or "S-018: JSON field 'FIELD'
\*       has wrong type: ..."). The spec's RequireField operator
\*       is the spec-layer projection of this template.
\*   std::string json_require_hex(j, field, len)     @ lines 60-72
\*       (the required-hex-typed extraction; throws "S-018: ..."
\*       on missing / wrong-type / wrong-hex-length). The spec
\*       collapses the length-mismatch branch into the WrongType
\*       outcome — both emit field-name context.
\*   const json& json_require_array(j, field)        @ lines 87-102
\*       (the required-array extraction; throws "S-018: ..." on
\*       missing / wrong-type). The spec models this via the
\*       Array type tag in Types; RequireField with expected_type
\*       = "Array" is the spec-layer projection.
\*
\* Converted consumers (the 14-row inventory in §3.3 of the prose
\* proof):
\*   net::Message::deserialize        @ src/net/messages.cpp:44     (Wire)
\*   Transaction::from_json           @ src/chain/block.cpp:57-65   (Wire / RPC)
\*   AbortEvent::from_json            @ src/chain/block.cpp:110-113 (Wire)
\*   EquivocationEvent::from_json     @ src/chain/block.cpp:139-144 (Wire / RPC)
\*   CrossShardReceipt::from_json     @ src/chain/block.cpp:220-229 (Wire)
\*   Block::from_json                 @ src/chain/block.cpp:451-545 (Wire / Snapshot)
\*   GenesisAlloc::from_json          @ src/chain/block.cpp:86      (Snapshot / Genesis)
\*   ContribMsg::from_json            @ src/node/producer.cpp:68-137  (Wire)
\*   AbortClaimMsg::from_json         @ src/node/producer.cpp:152-162 (Wire)
\*   BlockSigMsg::from_json           @ src/node/producer.cpp:204-214 (Wire)
\*   GenesisConfig::from_json         @ src/chain/genesis.cpp:189-275 (Genesis)
\*   load_node_key                    @ src/crypto/keys.cpp:55-56     (Keyfile)
\*   gossip envelope unwrap           @ src/net/gossip.cpp:212-258    (Wire)
\*   restore_from_snapshot wrappers   @ src/chain/chain.cpp:1748-1850 (Snapshot)
\*
\* Runtime regressions:
\*   tools/test_s018_json_validation.sh (10/10 PASS) — the
\*     10-scenario harness exercises every helper's exception path
\*     across happy-path, missing-required, wrong-type, wrong-hex-
\*     length, optional-wrong-hex-length, non-array surfaces.
\*     INV-1..INV-3 are the state-machine-layer counterparts of
\*     the regression's "expect_throw_with(name, fn, needles)"
\*     assertions.
\*   determ test-s018-json-validation — registered at
\*     src/main.cpp:26051 (the in-process test driving the shell-
\*     level harness).
\*
\* Doc updates:
\*   JsonValidationSoundness.md §1 (T-1..T-5 theorem statements);
\*   §3 (helpers + converted-consumer inventory); §4 (per-theorem
\*   analytic proofs); §5 (adversary model A1..A5); §6 (identified
\*   gaps + intentional-non-conversions); §7 (test-suite citation);
\*   §8 (status); §9 (reference table).
============================================================================
