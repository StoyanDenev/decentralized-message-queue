--------------------------- MODULE LightStatePersistence ---------------------------
(*
FB57 — TLA+ specification of the determ-light PERSISTED-ANCHOR CACHE lifecycle
(SHIPPED feature; the `verify-chain --persist` writer + `state` management
subcommand + `light/persist.{hpp,cpp}` module). Machine-checkable companion to
`docs/proofs/LightStatePersistenceSoundness.md` (theorems LSP-1..LSP-7 — LSP-7's
head-monotonicity gates modeled via the MonotonicityGate action +
INV_MonotoneResume / INV_LSP7_RefusalTotal; also pinned at source by
tools/test_light_resume_monotonicity_guard.sh).

This is the state-machine model of the "validated, genesis-pinned,
schema-versioned, fail-closed cache" the medium-tier light client uses to
remember its last committee-verified head. It models the four real surfaces —
WRITE (only after a committee-verified head), LOAD (schema + hex-shape
validation, fail-closed to a sentinel BAD), RE-VERIFY (the
`state --verify-anchor` offline genesis re-pin gate), and TAMPER (an attacker
rewriting the local file, in scope ONLY to show the genesis-pin / forward-verify
catch it under the trusted-local model) — and pins the LSP-1..LSP-5 invariants
over them. The LSP-6 fast-resume CONSUMER is documented below as the explicit
NOT-yet-modeled boundary (it is the marked daemon-bound follow-up; this increment
ships the validated substrate, not the trust-reducing resume).

NOTE: spec-only, model-check pending TLC install (matching every sibling in this
directory).

--------------------------------------------------------------------------
The headline contract — the LSP-1..LSP-5 theorems lifted to the state-machine
layer (each grounded in shipped source):

  LSP-1 (No-unverified-write). `cmd_verify_chain` (light/main.cpp:1386-1396)
    calls `save_light_state` ONLY on the success path AFTER `anchor_genesis`
    (genesis pin; light/trustless_read.cpp:55-82) AND `verify_chain_to_head`
    (prev_hash continuity + per-block K-of-K committee Ed25519 over
    `light_compute_block_digest`; trustless_read.cpp:81+) both return. A genesis
    mismatch, chain break, bad signature, or unreachable daemon THROWS before the
    write (the try/catch at main.cpp:1360/1398). So a persisted anchor is ALWAYS a
    fully committee-verified head of the operator's pinned chain — never a head the
    daemon merely asserted. Modeled: WriteAnchor is enabled ONLY when a
    committee-verified head exists (`verifiedHead # NoHead`); the persisted
    `genesis` is the LOCAL recompute (`localGenesis`), never a daemon claim.

  LSP-2 (Genesis-pin on reuse). The persisted `genesis_hash` is the
    light-client's LOCAL `compute_genesis_hash` recompute (main.cpp:1389 stores
    `genesis_hash_hex`, the value `anchor_genesis` returned from the local
    recompute at trustless_read.cpp:55). `state --verify-anchor --genesis <file>`
    (main.cpp:1463-1490) recomputes `compute_genesis_hash` LOCALLY (main.cpp:1477)
    and reports PASS (exit 0, anchor is for this chain) iff `s.genesis_hash ==
    local_hex`, MISMATCH (exit 2) otherwise. So a state file from a DIFFERENT chain
    (eclipse-onto-another-chain) is rejected — the anchor is honored only under the
    operator's own genesis. Modeled: ReVerifyAnchor accepts iff the cache's pinned
    genesis equals the locally-recomputed `localGenesis`.

  LSP-3 (Schema-version gate). `load_light_state` (persist.cpp:101-107) rejects
    any `schema_version != 1` with a diagnostic, rather than misreading a field
    set a future/past build wrote. Modeled: Load yields BAD when the on-disk
    record's schema != SchemaCurrent.

  LSP-4 (Fail-closed load). A corrupt cache (malformed JSON, missing required
    field, wrong-length / non-hex `genesis_hash` / `head_block_hash` /
    `head_state_root`) THROWS (persist.cpp:84-132) — never a partial / half-loaded
    LightState. `head_state_root` is the ONE field allowed empty ("") — the
    pre-S-033 chain case — and only that (persist.cpp:127-129). Modeled: Load over
    a malformed on-disk record returns the distinguished sentinel BAD (a clean,
    total fail-closed verdict), never an accepted record and never a partial one.

  LSP-5 (Read-soundness of the cache). Composing LSP-1..LSP-4: anything Load
    ACCEPTS is (a) well-formed + schema-current, and (b) — if this client wrote it
    — a committee-verified head; honored on reuse only under the operator's own
    genesis. The cache cannot INJECT an unverified or wrong-chain head into a later
    decision. Modeled: INV_ReadSound — any loaded (non-BAD) record is WellFormed,
    and a record this client wrote (`provenance = "self"`) carries the
    verified-head pin it was written from.

--------------------------------------------------------------------------
Trust model (LightStatePersistenceSoundness.md §2 / LightClientThreatModel.md
§6 — TRUSTED LOCAL ENVIRONMENT). The state file lives on the operator's own
machine. A locally-tampered state.json is OUT of scope for confidentiality /
integrity-of-the-file (an attacker who can rewrite it can rewrite the binary that
reads it). The security the code DOES provide — and the only thing the Tamper
action exists to witness — is that a stale, wrong-chain, or corrupt cache cannot
cause the client to ACCEPT AN UNVERIFIED CHAIN: it can at worst change WHERE
verification starts, and the genesis pin (LSP-2, ReVerifyAnchor) + the forward
re-verification (LSP-6, the consumer modeled below as out of scope) catch a
divergent chain there. No new cryptographic assumption beyond the per-run
verify-chain base {A1 Ed25519 EUF-CMA, A2 SHA-256 collision resistance}
(Preliminaries.md §2.0-§2.2). Tamper is therefore NOT a confidentiality breach in
this spec; it is the adversarial input the genesis-pin / fail-closed gates
neutralize, and the invariants below pin exactly that neutralization.

--------------------------------------------------------------------------
Modeling scope (kept small + finite-checkable so it COULD be model-checked):

  * A SINGLE persisted-anchor slot (one operator, one cache file). The cache holds
    a record drawn from a tiny finite universe: the schema version (SchemaCurrent
    vs a single Stale value, projecting LSP-3), a pinned genesis (the
    operator's OwnGenesis vs a single OtherGenesis, projecting the wrong-chain /
    eclipse case for LSP-2), and a hex-shape flag (Good vs Bad, projecting the
    fail-closed wrong-length / non-hex / missing-field family for LSP-4). The head
    height / block_hash / state_root payload is abstracted to a verified-head
    handle (`headPin`) plus a provenance tag — their concrete bytes do not affect
    any LSP-1..LSP-5 invariant, only the verified-head provenance does.
  * `verifiedHead`: the committee-verify result of the current run. NoHead until a
    run completes anchor_genesis + verify_chain_to_head; a verified head handle
    afterwards. WriteAnchor is GATED on `verifiedHead # NoHead` — the LSP-1
    no-unverified-write gate. `localGenesis` = the operator's locally-recomputed
    genesis for this run (OwnGenesis); the persisted pin is always set FROM it on a
    self-write (LSP-2).
  * `disk`: the on-disk record, or Empty (no cache). A record is the triple
    <<schema, pinnedGenesis, hexShape>> plus `provenance` ("self" if this client
    wrote it, "attacker" if a Tamper produced it). `loaded`: the verdict of the
    last Load — Empty (no file / not yet loaded), BAD (fail-closed sentinel), or an
    accepted record. `anchorVerdict`: the verdict of the last ReVerifyAnchor —
    Unverified, PASS, or MISMATCH (the exit-0 / exit-2 of `state --verify-anchor`).
  * The cryptographic layer (SHA-256 genesis hash, Ed25519 committee sigs) is
    abstracted exactly as the sibling FB-track specs abstract theirs: a genesis is
    an opaque symbol (equality is the only operation; OwnGenesis /= OtherGenesis
    encodes A2 collision resistance — distinct configs hash distinctly), and a
    committee-verified head is the opaque handle `verifiedHead` (the A1/A2 chain
    verification of verify_chain_to_head, modeled as the precondition that produced
    the handle). The validation predicate of Load is the spec-layer projection of
    `load_light_state`'s schema + hex-shape checks.

--------------------------------------------------------------------------
Invariants (mapping LSP-1..LSP-5):

  (LSP-0) TypeOK — variables have the right shapes; the value universes are
          finite so TLC's state space is bounded.
  (LSP-1) INV_NoUnverifiedWrite — every self-written on-disk record was written
          while a committee-verified head existed: a record with provenance
          "self" implies the write happened under `verifiedHead # NoHead`, pinned
          from it. State-form: the cache never holds a self-written anchor that
          was not, at write time, a fully committee-verified head. The
          no-unverified-write gate of cmd_verify_chain.
  (LSP-2) INV_GenesisPinned — a ReVerifyAnchor that returned PASS implies the
          cache's pinned genesis equals the operator's locally-recomputed genesis;
          a wrong-chain pin yields MISMATCH, never PASS. So a resume can NEVER be
          told "this anchor is for your chain" when it is not — the eclipse-onto-
          another-chain reuse is rejected. The `state --verify-anchor` gate.
  (LSP-3) INV_SchemaGated — Load NEVER accepts a record whose schema != current:
          any on-disk record with a stale/unknown schema_version loads as BAD. The
          schema-version fail-closed of load_light_state.
  (LSP-4) INV_FailClosed — a malformed on-disk record (bad hex shape, or — via
          the schema gate — wrong schema) ALWAYS loads as the sentinel BAD, never
          as an accepted record and never as a partial one. There is no reachable
          state in which `loaded` is a half-populated record. The total
          fail-closed contract of load_light_state.
  (LSP-5) INV_ReadSound — anything Load ACCEPTED (loaded # Empty /\ loaded # BAD)
          is WellFormed (schema-current + good hex shape), and if it was
          self-written it carries the verified-head pin it was written from. The
          cache cannot inject an unverified or malformed head into a later
          decision. The read-soundness composition LSP-1..LSP-4.

A temporal property pins the fail-closed-on-tamper liveness face:

  (LSP-6t) Prop_TamperNeverLoadsAccepted — across every reachable state, a Load
           that ACCEPTED an attacker-tampered record while that record is
           malformed is unreachable: an accepted load is always WellFormed (the
           []-restatement of INV_FailClosed + INV_ReadSound). A genesis-swapped
           but well-formed tamper still loads, but ReVerifyAnchor then returns
           MISMATCH (INV_GenesisPinned) — the trusted-local model's guarantee that
           tamper changes WHERE verification starts, never WHETHER it is verified.

--------------------------------------------------------------------------
LSP-6 — the resume CONSUMER — is now SHIPPED (commit `22c04fa`) and MODELED here.

`verify-chain --resume` (`verify_chain_from_anchor`, light/trustless_read.cpp)
re-pins the genesis against the cached anchor (LSP-2, ReVerifyAnchor) then verifies
ONLY the suffix the daemon added above it, skipping the committee-signed prefix.
The ResumeVerify action below models the daemon's suffix offering as a finite
nondeterministic choice over the cases that matter for soundness:

  * a corrupt or wrong-chain anchor ⇒ FALLBACK to a full verify (never weaker);
  * the daemon not ahead of the anchor ⇒ FALLBACK at THIS layer (the
    verify_chain_from_anchor function's resumed=false); since LSP-7 the CALLER
    (anchored_head) no longer accepts that fallback silently — head BELOW the
    anchor throws, head AT it triggers the full-verify + anchor-hash
    cross-check. The caller-layer gates are modeled by the MonotonicityGate
    action (LSP-7, below);
  * an honest suffix that chains onto the cached head_block_hash at the correct
    next index ⇒ RESUMED (a new committee-verified head);
  * a suffix that does NOT chain onto the anchor (a fork/rollback below it) ⇒
    REJECTED (a HARD error, never a silent from-genesis re-verify);
  * the ADVERSARIAL index-0 diversion (a malicious daemon serving a first suffix
    header claiming index 0, to divert verify_headers into its binding-free
    genesis branch and dodge the anchor + committee-sig checks) ⇒ REJECTED by the
    index-contiguity gate (a suffix's first index must be anchor_height, not 0) +
    the verify_headers anchored-page guard.

INV_ResumeSound + INV_ResumeNoFalseAccept pin that a RESUMED verdict is reached
ONLY for a valid, genesis-pinned anchor AND a genuinely-chaining honest suffix —
the index-0 and fork offerings NEVER yield RESUMED. The prefix-skip soundness
(each suffix block's K-of-K sig binds its index+prev_hash, so block_hash ==
anchor transitively re-validates the skipped prefix under A1+A2) is the
cryptographic content abstracted by "the honest suffix chains onto the verified
anchor handle"; it is argued in full in LightStatePersistenceSoundness.md §3
LSP-6. The single-slot, head-only abstraction reflects §4: the cache stores the
verified HEAD, not the full committee history (committee rotation across a long
offline gap is re-derived by the suffix verify, not cached).

--------------------------------------------------------------------------
Companion analytic source: `docs/proofs/LightStatePersistenceSoundness.md`
(LSP-1..LSP-7, all modeled — LSP-7 via MonotonicityGate).
Empirical pin: `tools/test_light_state.sh` (27 offline
assertions — `state --selftest` round-trip + 5 fail-closed reject paths;
`--show`/`--clear`/`--show --json` graceful-absence + fail-closed-on-corrupt;
`--verify-anchor` PASS / MISMATCH-exit-2; `--persist` arg acceptance + the LSP-1
no-write-on-failed-verify guarantee).

Adjacent specs:
  FB26 (BlockchainStateIntegrity.tla) — the daemon-side chain.json load/tamper
    detection sibling; INV_FailClosed here is its light-client cache analog (a
    malformed persisted record fails closed to BAD exactly as a tampered chain.json
    is rejected on load).
  FB56 (PartnerSubsetDigestBinding.tla) — the digest-binding tamper-detection
    family; PartnerSubset's Inv_BindingDetectsTamper detects a post-sign mutation
    via the digest, where this spec's INV_GenesisPinned detects a wrong-chain
    cache via the local genesis recompute. Both are "tamper changes a bound value,
    the gate catches it" arguments at different layers (digest vs genesis pin).
  StateRootAnchorSoundness.md (SR-1) — the head_state_root the cache stores (the
    one field allowed empty on a pre-S-033 chain; LSP-4's "" exception).

To check (assuming TLC installed):
  $ tlc LightStatePersistence.tla -config LightStatePersistence.cfg
Recommended config (small + finite): SchemaCurrent = 1, SchemaStale = 2,
  OwnGenesis = "g_own", OtherGenesis = "g_other".
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    SchemaCurrent,   \* the schema_version this build understands (== 1)
    SchemaStale,     \* a single distinct stale/unknown schema (projects LSP-3)
    OwnGenesis,      \* the operator's own chain genesis (the locally-recomputed pin)
    OtherGenesis     \* a different chain's genesis (the eclipse / wrong-chain case)

\* Distinguished sentinels (chosen disjoint from every record-field value).
NoHead    == "NO_HEAD"       \* verifiedHead before a run completes anchor+verify
Empty     == "EMPTY"         \* no cache file on disk / no load performed yet
BAD       == "BAD"           \* the fail-closed Load verdict (LSP-4 sentinel)
Unverified == "UNVERIFIED"   \* anchorVerdict before any ReVerifyAnchor
Good      == "GOOD"          \* hex-shape flag: all fields well-formed
Bad       == "BAD_HEX"       \* hex-shape flag: a malformed (short/non-hex/missing) field
ResumeNone == "RESUME_NONE"  \* resumeResult before any ResumeVerify (LSP-6)

\* The daemon's suffix offering on a `verify-chain --resume` attempt (LSP-6):
\*   "extends"   — an honest suffix chaining onto the cached head_block_hash at
\*                 the correct next index (index == anchor_height) → RESUMED;
\*   "fork"      — a suffix that does NOT chain onto the anchor (prev_hash break /
\*                 rollback below it) → REJECTED (hard error);
\*   "index0"    — the adversarial index-0 diversion (first suffix header claims
\*                 index 0) → REJECTED by the index-contiguity gate;
\*   "not_ahead" — daemon head <= anchor height (nothing new) → FALLBACK.
Offerings == {"none", "extends", "fork", "index0", "not_ahead"}

\* The daemon-head vs cached-anchor relation the LSP-7 MonotonicityGate measures
\* (anchored_head's own fetch_head_height, BEFORE the LSP-6 suffix walk). The
\* == case splits on whether the full verify's tip matches the cached anchor
\* block_hash ("at_same") or not ("at_fork" — a same-height fork at the anchor).
HeadRelations == {"below", "at_same", "at_fork", "ahead"}

\* The set of schema versions + genesis symbols + hex-shape flags.
Schemas    == {SchemaCurrent, SchemaStale}
Genatures  == {OwnGenesis, OtherGenesis}
HexShapes  == {Good, Bad}

\* A verified-head handle: the opaque result of a committee-verify run for the
\* operator's own chain. A single symbolic handle suffices (the concrete height /
\* block_hash / state_root payload is abstracted; only its provenance matters).
HeadPin == "VERIFIED_HEAD"

\* An on-disk record: <<schema, pinnedGenesis, hexShape>>. The record universe.
Records == Schemas \X Genatures \X HexShapes

\* A record is WELL-FORMED iff its schema is current AND its hex shape is good —
\* the exact pair load_light_state checks (schema_version == 1 + every required
\* field present, right-length, hex). The genesis symbol is well-formed by
\* construction (it is a 64-hex string in both the OwnGenesis and OtherGenesis
\* cases; wrong-CHAIN is an LSP-2 concern, not an LSP-4 malformation).
WellFormed(r) == (r[1] = SchemaCurrent) /\ (r[3] = Good)

ASSUME ConfigOK ==
    /\ SchemaCurrent \in Nat
    /\ SchemaStale \in Nat
    /\ SchemaCurrent /= SchemaStale                 \* a distinct stale schema exists
    /\ OwnGenesis /= OtherGenesis                    \* A2: distinct chains hash distinctly
    \* the sentinels are disjoint from every record-field value
    /\ OwnGenesis \notin Schemas /\ OtherGenesis \notin Schemas
    /\ NoHead \notin Genatures /\ Empty \notin Genatures /\ BAD \notin Genatures

----------------------------------------------------------------------------
\* §1. State.
\*
\* `localGenesis` is the operator's locally-recomputed genesis for this run — the
\* value anchor_genesis returns and cmd_verify_chain pins (always OwnGenesis: the
\* operator runs verify against their own --genesis). `verifiedHead` is the
\* committee-verify result of the current run (NoHead until anchor_genesis +
\* verify_chain_to_head complete; HeadPin afterwards). `disk` is the on-disk record
\* (Empty if no cache). `provenance` tags who wrote the on-disk record ("self" =
\* this client via WriteAnchor; "attacker" = a Tamper rewrite). `loaded` is the
\* verdict of the last Load (Empty / BAD / an accepted record). `anchorVerdict` is
\* the verdict of the last ReVerifyAnchor (Unverified / PASS / MISMATCH).

VARIABLES
    localGenesis,   \* the operator's locally-recomputed genesis for this run (OwnGenesis)
    verifiedHead,   \* HeadPin once committee-verified this run; NoHead otherwise
    disk,           \* the on-disk record (a Records triple) or Empty
    provenance,     \* "self" | "attacker" | "none" — who wrote the on-disk record
    loaded,         \* last Load verdict: Empty | BAD | a Records triple
    anchorVerdict,  \* last ReVerifyAnchor verdict: Unverified | "PASS" | "MISMATCH"
    resumeOffering, \* daemon's suffix offering on the last ResumeVerify (Offerings)
    resumeResult,   \* last ResumeVerify verdict: ResumeNone | RESUMED | FALLBACK | REJECTED
    \* History snapshots (verdict-time): a verdict judges the record it CONSUMED,
    \* not whatever a later Tamper/Clear leaves on disk. Without these, the
    \* INV_GenesisPinned / INV_ResumeSound implications would be falsified by a
    \* Tamper firing AFTER a PASS / RESUMED while the stale verdict persists —
    \* a latent instability found by manual review (TLC pending).
    anchorPinned,   \* the disk record the last ReVerifyAnchor judged (or Empty)
    resumeAnchor,   \* the disk record the last RESUMED consumed (or Empty)
    \* LSP-7 (head-monotonicity gate at the anchored_head caller layer):
    headRelation,   \* last measured daemon-head vs anchor relation ("rel_none" initial)
    lsp7Verdict     \* last MonotonicityGate verdict (see TypeOK for the universe)

vars == <<localGenesis, verifiedHead, disk, provenance, loaded, anchorVerdict,
          resumeOffering, resumeResult, anchorPinned, resumeAnchor,
          headRelation, lsp7Verdict>>

----------------------------------------------------------------------------
\* §2. Helpers.

\* The schema + hex-shape validation Load performs (load_light_state): a record is
\* ACCEPTED iff it is well-formed; otherwise Load fails closed to BAD. This is the
\* total fail-closed map — every malformed input lands on the single sentinel.
LoadVerdict(d) ==
    IF d = Empty           THEN Empty       \* absent file: graceful "no anchor" (exit 0)
    ELSE IF WellFormed(d)  THEN d           \* schema-current + good hex: accepted record
    ELSE                        BAD          \* malformed: fail-closed sentinel (LSP-4)

\* The pinned genesis carried by an accepted record (meaningful only when loaded is
\* a Records triple). The 2nd component is the genesis the cache was written under.
PinnedGenesis(r) == r[2]

----------------------------------------------------------------------------
\* §3. Initial state. A fresh client: the operator's local genesis is their own,
\* no committee-verify has run yet (NoHead), the cache is Empty, nothing loaded,
\* no anchor re-verify performed.

Init ==
    /\ localGenesis  = OwnGenesis
    /\ verifiedHead  = NoHead
    /\ disk          = Empty
    /\ provenance    = "none"
    /\ loaded        = Empty
    /\ anchorVerdict = Unverified
    /\ resumeOffering = "none"
    /\ resumeResult   = ResumeNone
    /\ anchorPinned   = Empty
    /\ resumeAnchor   = Empty
    /\ headRelation   = "rel_none"
    /\ lsp7Verdict    = "LSP7_NONE"

----------------------------------------------------------------------------
\* §4. Actions.

\* VerifyRun: a verify-chain run completes anchor_genesis (genesis pin) +
\* verify_chain_to_head (prev_hash continuity + per-block K-of-K committee Ed25519)
\* successfully, producing a committee-verified head handle. This is the PRECONDITION
\* WriteAnchor gates on (LSP-1): the verified head exists in memory before any write.
\* Abstracts the A1/A2 cryptographic chain verification to its result handle.
VerifyRun ==
    /\ verifiedHead = NoHead
    /\ verifiedHead' = HeadPin
    /\ UNCHANGED <<localGenesis, disk, provenance, loaded, anchorVerdict,
                   resumeOffering, resumeResult, anchorPinned, resumeAnchor,
                   headRelation, lsp7Verdict>>

\* WriteAnchor: cmd_verify_chain --persist calls save_light_state. ENABLED ONLY
\* after a committee-verified head exists (verifiedHead # NoHead) — the LSP-1
\* no-unverified-write gate (the write is on the success path AFTER anchor_genesis +
\* verify_chain_to_head). The persisted record is schema-current, pinned to the
\* LOCAL genesis recompute (localGenesis, LSP-2 — never a daemon claim), with a good
\* hex shape (the client always serializes well-formed fields). Provenance "self".
WriteAnchor ==
    /\ verifiedHead /= NoHead
    /\ disk'       = <<SchemaCurrent, localGenesis, Good>>
    /\ provenance' = "self"
    /\ UNCHANGED <<localGenesis, verifiedHead, loaded, anchorVerdict,
                   resumeOffering, resumeResult, anchorPinned, resumeAnchor,
                   headRelation, lsp7Verdict>>

\* Load: load_light_state parses + validates the on-disk record. An ABSENT file is
\* the graceful "no anchor" (loaded = Empty, exit 0). A present record is accepted
\* IFF well-formed (schema-current + good hex); a malformed record (stale schema —
\* LSP-3 — or bad hex / missing field — LSP-4) fails closed to BAD. NEVER a partial
\* record. Models `state --show` / the load step of `--verify-anchor`.
Load ==
    /\ loaded' = LoadVerdict(disk)
    /\ UNCHANGED <<localGenesis, verifiedHead, disk, provenance, anchorVerdict,
                   resumeOffering, resumeResult, anchorPinned, resumeAnchor,
                   headRelation, lsp7Verdict>>

\* ReVerifyAnchor: `state --verify-anchor --genesis <file>` — the offline LSP-2
\* genesis re-pin gate (the SHIPPED security-critical half of the LSP-6 resume).
\* Loads the cache fail-closed, recomputes compute_genesis_hash LOCALLY
\* (localGenesis), and reports PASS iff the cache's pinned genesis equals it,
\* MISMATCH otherwise. A malformed cache fails closed (no verdict — the load throws
\* first, modeled as anchorVerdict staying MISMATCH-safe, never PASS). Enabled only
\* when a record is on disk (the no-cache usage gate returns exit 1 in the code; not
\* a PASS).
ReVerifyAnchor ==
    /\ disk /= Empty
    /\ IF WellFormed(disk) /\ PinnedGenesis(disk) = localGenesis
       THEN anchorVerdict' = "PASS"        \* exit 0: anchor is for THIS chain
       ELSE anchorVerdict' = "MISMATCH"    \* exit 2 (wrong chain) or fail-closed (corrupt)
    /\ anchorPinned' = disk                \* the record THIS verdict judged (history)
    /\ UNCHANGED <<localGenesis, verifiedHead, disk, provenance, loaded,
                   resumeOffering, resumeResult, resumeAnchor,
                   headRelation, lsp7Verdict>>

\* Tamper: an attacker rewrites the local state.json (the trusted-local model's
\* in-scope adversary, present ONLY to witness that the genesis-pin / fail-closed
\* gates catch it). The attacker may write ANY record — a wrong-chain pin
\* (OtherGenesis, the eclipse-onto-another-chain attempt), a stale schema, or a
\* malformed hex shape. Provenance flips to "attacker" (so INV_NoUnverifiedWrite
\* scopes only self-writes). The attacker cannot mint a committee-verified head — it
\* can only change the bytes on disk; the verifiedHead handle (A1/A2) is unforgeable
\* and untouched. NOT fair (an optional adversarial step the safety invariants
\* tolerate, not a liveness requirement).
Tamper ==
    /\ \E sc \in Schemas, g \in Genatures, hx \in HexShapes :
          /\ disk'       = <<sc, g, hx>>
          /\ provenance' = "attacker"
    /\ UNCHANGED <<localGenesis, verifiedHead, loaded, anchorVerdict,
                   resumeOffering, resumeResult, anchorPinned, resumeAnchor,
                   headRelation, lsp7Verdict>>

\* Clear: `state --clear` deletes the cache file (a benign management action).
\* Resets the on-disk record to Empty; the next Load is the graceful "no anchor".
Clear ==
    /\ disk'       = Empty
    /\ provenance' = "none"
    /\ UNCHANGED <<localGenesis, verifiedHead, loaded, anchorVerdict,
                   resumeOffering, resumeResult, anchorPinned, resumeAnchor,
                   headRelation, lsp7Verdict>>

\* ResumeVerify: `verify-chain --resume` (verify_chain_from_anchor). Reads the
\* cache and either RESUMES (verifies only the suffix above the anchor), FALLS
\* BACK to a full verify, or REJECTS (hard error). The daemon's suffix is a finite
\* nondeterministic offering. Decision order matches the code (main.cpp resume
\* control flow + trustless_read.cpp::verify_chain_from_anchor):
\*   1. anchor corrupt OR wrong-chain (not WellFormed, or pin != local genesis,
\*      LSP-2) ⇒ FALLBACK to a full verify (never weaker than a full verify);
\*   2. daemon not ahead ("not_ahead") ⇒ FALLBACK (nothing new to verify at the
\*      verify_chain_from_anchor layer; since LSP-7 the anchored_head CALLER
\*      converts this to a throw (head < anchor) or a full-verify + anchor-hash
\*      cross-check (head == anchor) — caller gates modeled by MonotonicityGate);
\*   3. honest chaining suffix ("extends") ⇒ RESUMED, producing a verified head;
\*   4. fork-below-anchor ("fork") OR the index-0 diversion ("index0") ⇒ REJECTED
\*      (the prev_hash continuity break / the index-contiguity gate — a hard error,
\*      never a silent from-genesis re-verify). Enabled only when a record is on
\*      disk (a resume with no cache falls back; modeled by requiring disk /= Empty
\*      here and leaving the no-cache→full-verify routing to VerifyRun).
ResumeVerify ==
    /\ disk /= Empty
    /\ \E offer \in (Offerings \ {"none"}) :
         /\ resumeOffering' = offer
         /\ IF ~(WellFormed(disk) /\ PinnedGenesis(disk) = localGenesis)
            THEN /\ resumeResult' = "FALLBACK"      \* corrupt / wrong-chain anchor
                 /\ verifiedHead' = verifiedHead
                 /\ resumeAnchor' = resumeAnchor
            ELSE IF offer = "not_ahead"
            THEN /\ resumeResult' = "FALLBACK"      \* daemon not ahead of anchor
                 /\ verifiedHead' = verifiedHead
                 /\ resumeAnchor' = resumeAnchor
            ELSE IF offer = "extends"
            THEN /\ resumeResult' = "RESUMED"       \* honest suffix chains onto anchor
                 /\ verifiedHead' = HeadPin         \* the new committee-verified tip
                 /\ resumeAnchor' = disk            \* the anchor THIS resume consumed
            ELSE \* offer \in {"fork", "index0"}
                 /\ resumeResult' = "REJECTED"      \* fork-below / index-0 diversion
                 /\ verifiedHead' = verifiedHead
                 /\ resumeAnchor' = resumeAnchor
    /\ UNCHANGED <<localGenesis, disk, provenance, loaded, anchorVerdict,
                   anchorPinned, headRelation, lsp7Verdict>>

\* MonotonicityGate: the LSP-7 head-monotonicity gates anchored_head runs BEFORE
\* the LSP-6 suffix walk, given a VALID genesis-pinned anchor (the gate's enabling
\* condition in the code: anchor loaded + genesis pin matched + head_height > 0;
\* with no usable anchor the gates don't run — the absent/corrupt/wrong-chain
\* fallbacks are unchanged). The daemon's head relation is a finite
\* nondeterministic measurement; the verdict mapping is the code's:
\*   "below"   ⇒ REFUSED_BELOW           (G1: a fork-free chain never regresses —
\*                                        stale/truncated daemon state; THROW)
\*   "at_same" ⇒ CROSSCHECK_OK           (G2 pass: full verify ran AND the verified
\*                                        tip block_hash == the cached anchor's —
\*                                        produces a committee-verified head)
\*   "at_fork" ⇒ REFUSED_FORK_AT_ANCHOR  (G2 fail: same-height fork at the anchor;
\*                                        THROW — a plain full verify would have
\*                                        accepted it, only the cache compare
\*                                        catches it)
\*   "ahead"   ⇒ PROCEED_RESUME          (control passes to ResumeVerify / LSP-6;
\*                                        the G3 between-queries regression is the
\*                                        PROCEED_RESUME state followed by a
\*                                        "not_ahead" ResumeVerify offering, which
\*                                        the caller converts to a THROW — see
\*                                        INV_LSP7_RefusalTotal's companion note)
MonotonicityGate ==
    /\ disk /= Empty
    /\ WellFormed(disk) /\ PinnedGenesis(disk) = localGenesis
    /\ \E rel \in HeadRelations :
         /\ headRelation' = rel
         /\ lsp7Verdict' =
              CASE rel = "below"   -> "REFUSED_BELOW"
                [] rel = "at_same" -> "CROSSCHECK_OK"
                [] rel = "at_fork" -> "REFUSED_FORK_AT_ANCHOR"
                [] rel = "ahead"   -> "PROCEED_RESUME"
         /\ verifiedHead' = IF rel = "at_same" THEN HeadPin ELSE verifiedHead
    /\ UNCHANGED <<localGenesis, disk, provenance, loaded, anchorVerdict,
                   resumeOffering, resumeResult, anchorPinned, resumeAnchor>>

----------------------------------------------------------------------------
\* §5. Next-state relation + spec. A verify run produces a verified head; the
\* client may persist it (gated); the cache is loaded / re-verified; the adversary
\* may tamper or the operator may clear, in arbitrary interleaving.

Next ==
    \/ VerifyRun
    \/ WriteAnchor
    \/ Load
    \/ ReVerifyAnchor
    \/ MonotonicityGate
    \/ ResumeVerify
    \/ Tamper
    \/ Clear

\* Weak fairness on the read-side actions drives the liveness face: a cache on disk
\* is eventually loaded and (offline) re-verified, exposing any tamper. The safety
\* invariants (LSP-1..LSP-5) hold in EVERY reachable state regardless of which
\* actions fire. Tamper / Clear are NOT fair (optional steps, not liveness reqs).
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Load)
    /\ WF_vars(ReVerifyAnchor)

----------------------------------------------------------------------------
\* §6. Invariants — LSP-0..LSP-7.

\* LSP-0 / TypeOK. Shapes + bounds; the value universes are finite for TLC.
TypeOK ==
    /\ localGenesis  \in Genatures
    /\ verifiedHead  \in {NoHead, HeadPin}
    /\ disk          \in (Records \cup {Empty})
    /\ provenance    \in {"none", "self", "attacker"}
    /\ loaded        \in (Records \cup {Empty, BAD})
    /\ anchorVerdict \in {Unverified, "PASS", "MISMATCH"}
    /\ resumeOffering \in Offerings
    /\ resumeResult   \in {ResumeNone, "RESUMED", "FALLBACK", "REJECTED"}
    /\ anchorPinned   \in (Records \cup {Empty})
    /\ resumeAnchor   \in (Records \cup {Empty})
    /\ headRelation   \in ({"rel_none"} \cup HeadRelations)
    /\ lsp7Verdict    \in {"LSP7_NONE", "REFUSED_BELOW", "CROSSCHECK_OK",
                           "REFUSED_FORK_AT_ANCHOR", "PROCEED_RESUME"}

\* LSP-1 / INV_NoUnverifiedWrite. Every SELF-written on-disk record was written
\* while a committee-verified head existed. State-form: if the cache holds a
\* self-written record, then verifiedHead # NoHead (the WriteAnchor gate held at
\* write time and verifiedHead is monotone — VerifyRun only sets it, never clears
\* it). So the cache never holds a self-written anchor that was not, at write time,
\* a fully committee-verified head — the no-unverified-write gate of
\* cmd_verify_chain (main.cpp:1386: the `if (persist)` block runs only after the
\* successful anchor_genesis + verify_chain_to_head above).
INV_NoUnverifiedWrite ==
    (disk /= Empty /\ provenance = "self") => (verifiedHead /= NoHead)

\* LSP-2 / INV_GenesisPinned. A ReVerifyAnchor that returned PASS implies the
\* cache's pinned genesis equals the operator's locally-recomputed genesis. A
\* wrong-chain pin (OtherGenesis when localGenesis = OwnGenesis) can NEVER yield
\* PASS — only MISMATCH. So a resume is never told "this anchor is for your chain"
\* when it is not; the eclipse-onto-another-chain reuse is rejected. The
\* `state --verify-anchor` gate (main.cpp:1478 `if (s.genesis_hash == local_hex)`).
\* STABILITY NOTE (history-variable form): the implication is over anchorPinned —
\* the record the verdict JUDGED — not the current disk. The naive disk-form is
\* falsified by a Tamper firing AFTER a PASS (the stale verdict persists while
\* disk mutates); the verdict's claim is about what it consumed, which the
\* snapshot preserves. Found by manual review; TLC pending.
INV_GenesisPinned ==
    (anchorVerdict = "PASS") =>
        (anchorPinned \in Records /\ WellFormed(anchorPinned)
         /\ PinnedGenesis(anchorPinned) = localGenesis)

\* LSP-3 / INV_SchemaGated. Load NEVER accepts a record whose schema is not
\* current: a present on-disk record with a stale/unknown schema_version loads as
\* BAD (or Empty if absent), never as an accepted record. The schema-version
\* fail-closed of load_light_state (persist.cpp:104-107 rejects schema != 1).
INV_SchemaGated ==
    (loaded \in Records) => (loaded[1] = SchemaCurrent)

\* LSP-4 / INV_FailClosed. A malformed on-disk record (bad hex shape, OR — via the
\* schema gate — a stale schema) ALWAYS loads as the sentinel BAD, never as an
\* accepted record and never partially. State-form: whenever the on-disk record is
\* present but not well-formed, the last Load verdict is BAD (the total fail-closed
\* map: there is no reachable state where `loaded` is a half-populated record). The
\* load_light_state throw-on-corrupt contract (persist.cpp:84-132). Scoped to the
\* states where Load has actually observed the current disk — pinned via the
\* LoadVerdict total function: a malformed disk can only ever map to BAD, so an
\* accepted `loaded` is necessarily well-formed.
INV_FailClosed ==
    (loaded \in Records) => WellFormed(loaded)

\* LSP-5 / INV_ReadSound. Anything Load ACCEPTED (loaded is a Records triple, i.e.
\* loaded # Empty /\ loaded # BAD) is WELL-FORMED (schema-current + good hex), AND
\* if that accepted record is the one currently on disk written by this client
\* (provenance = "self"), it pins the operator's own genesis (localGenesis) — the
\* committee-verified head's chain. The cache cannot inject an unverified or
\* malformed head into a later decision. The read-soundness composition
\* LSP-1..LSP-4 (LightStatePersistenceSoundness.md §3 LSP-5).
INV_ReadSound ==
    (loaded \in Records) =>
        /\ WellFormed(loaded)
        /\ (provenance = "self" /\ disk = loaded) => (PinnedGenesis(loaded) = localGenesis)

\* LSP-6 / INV_ResumeSound. A RESUMED verdict is reached ONLY for a valid,
\* genesis-pinned anchor: verify-chain --resume re-pins the genesis (LSP-2) and
\* falls back to a full verify on a corrupt or wrong-chain cache, so it can NEVER
\* report "resumed from this anchor" when the anchor is malformed or for a
\* different chain. The resume is therefore never weaker than a full verify (the
\* skipped prefix is exactly the one the cached, genesis-pinned, committee-verified
\* anchor already covered).
\* STABILITY NOTE: stated over resumeAnchor (the record the RESUMED consumed),
\* not the current disk — same Tamper-after-verdict rationale as
\* INV_GenesisPinned above.
INV_ResumeSound ==
    (resumeResult = "RESUMED") =>
        (resumeAnchor \in Records /\ WellFormed(resumeAnchor)
         /\ PinnedGenesis(resumeAnchor) = localGenesis)

\* LSP-6 / INV_ResumeNoFalseAccept. A RESUMED verdict implies the daemon's suffix
\* offering was a genuinely-chaining honest suffix ("extends"): the fork-below-
\* anchor and the adversarial index-0 diversion offerings are ALWAYS REJECTED,
\* never RESUMED. This is the resume-soundness fix an adversarial verifier forced
\* (the index-0 header that diverted verify_headers into its binding-free genesis
\* branch) — closed by the index-contiguity gate + the verify_headers anchored-page
\* guard, abstracted here as: only "extends" reaches RESUMED.
INV_ResumeNoFalseAccept ==
    (resumeResult = "RESUMED") => (resumeOffering = "extends")

\* LSP-7 / INV_MonotoneResume. An ACCEPTING MonotonicityGate verdict exists only
\* under a non-regressed daemon: CROSSCHECK_OK only for "at_same" (head == anchor
\* AND the verified tip IS the cached anchor block) and PROCEED_RESUME only for
\* "ahead". A daemon measured below the anchor, or at it with a different block,
\* can never reach an accepting verdict — the anchored_head gates throw
\* (trustless_read.cpp LSP-7; the pre-LSP-7 silent full-verify fail-open is
\* unreachable in the gated model). headRelation and lsp7Verdict change only
\* together (atomically, in MonotonicityGate), so the implication is stable.
INV_MonotoneResume ==
    (lsp7Verdict \in {"CROSSCHECK_OK", "PROCEED_RESUME"}) =>
        (headRelation \in {"at_same", "ahead"})

\* LSP-7 / INV_LSP7_RefusalTotal. Every regression-shaped measurement is REFUSED —
\* totally, with no third disposition: "below" and "at_fork" map only to the two
\* refusal verdicts (the G1/G2 throws). Together with INV_MonotoneResume this
\* pins the gate's verdict mapping as a bijection-on-classes: regressed ⇒ refused,
\* non-regressed ⇒ accepted-or-deferred. The G3 between-queries regression is the
\* PROCEED_RESUME state followed by a "not_ahead" ResumeVerify offering — at the
\* anchored_head layer that combination is a THROW (the model keeps the layers
\* separate; the caller mapping is pinned by the source guard
\* tools/test_light_resume_monotonicity_guard.sh I3/I6).
INV_LSP7_RefusalTotal ==
    (headRelation \in {"below", "at_fork"}) =>
        (lsp7Verdict \in {"REFUSED_BELOW", "REFUSED_FORK_AT_ANCHOR"})

----------------------------------------------------------------------------
\* §7. Temporal property.

\* LSP-6t / Prop_TamperNeverLoadsAccepted. Across every reachable state, an
\* ACCEPTED Load is always WELL-FORMED — even one produced by an attacker Tamper.
\* A malformed tamper (stale schema / bad hex) fails closed to BAD on Load
\* (INV_FailClosed); a genesis-swapped but well-formed tamper DOES load (the
\* trusted-local model lets the bytes through), but ReVerifyAnchor then returns
\* MISMATCH (INV_GenesisPinned), never PASS. So tamper changes WHERE verification
\* would start, never WHETHER the anchor is verified-for-this-chain. The
\* []-restatement of the fail-closed + genesis-pin neutralization.
Prop_TamperNeverLoadsAccepted ==
    [](  (loaded \in Records) => WellFormed(loaded)  )

============================================================================
\* Cross-references.
\*
\* FB26 (BlockchainStateIntegrity.tla) — the daemon-side chain.json load/tamper
\*   detection sibling. INV_FailClosed here is its light-client persisted-cache
\*   analog: a malformed cache record fails closed to BAD exactly as a tampered
\*   chain.json is rejected on load. Both are total fail-closed-on-corrupt maps.
\*
\* FB56 (PartnerSubsetDigestBinding.tla) — the digest-binding tamper-detection
\*   family. PartnerSubset's Inv_BindingDetectsTamper detects a post-sign mutation
\*   via the recomputed digest; this spec's INV_GenesisPinned detects a wrong-chain
\*   cache via the local genesis recompute. Both: "tamper mutates a bound value,
\*   the gate catches it" — at the digest layer (FB56) vs the genesis-pin layer (FB57).
\*
\* FB55 (TimestampMedianReconciliation.tla) — sibling SHIPPED-feature companion;
\*   same banner / Init-Next-Spec / INV_* conventions and the four-phase
\*   action-gating discipline this spec mirrors.
\*
\* Companion analytic source:
\*   docs/proofs/LightStatePersistenceSoundness.md (LSP-1..LSP-7; LSP-7 =
\*     MonotonicityGate + INV_MonotoneResume + INV_LSP7_RefusalTotal, also
\*     source-guarded by tools/test_light_resume_monotonicity_guard.sh). LSP-1 =
\*     INV_NoUnverifiedWrite; LSP-2 = INV_GenesisPinned; LSP-3 = INV_SchemaGated;
\*     LSP-4 = INV_FailClosed; LSP-5 = INV_ReadSound; LSP-6 = INV_ResumeSound +
\*     INV_ResumeNoFalseAccept (the resume CONSUMER is SHIPPED, commit 22c04fa, and
\*     modeled via the ReVerifyAnchor genesis re-pin gate + the ResumeVerify suffix
\*     walk; the prefix-skip cryptographic content is abstracted by "the honest
\*     'extends' suffix chains onto the verified anchor handle").
\*   docs/proofs/StateRootAnchorSoundness.md (SR-1) — the head_state_root the cache
\*     stores; the one field allowed empty ("") on a pre-S-033 chain (LSP-4's
\*     state_root exception, persist.cpp:127-129).
\*   docs/proofs/LightClientThreatModel.md §6 — the trusted-local environment the
\*     Tamper action's scope rests on (T-L1 anchor reused by LSP-2).
\*
\* C++ enforcement:
\*   light/main.cpp:1386-1396       : cmd_verify_chain --persist — the `if (persist)`
\*       block calls save_light_state ONLY after the successful anchor_genesis +
\*       verify_chain_to_head above; genesis_hash pinned from the LOCAL recompute
\*       genesis_hash_hex (WriteAnchor gate + LSP-2 local pin / INV_NoUnverifiedWrite +
\*       INV_GenesisPinned).
\*   light/main.cpp:1463-1490       : cmd_state --verify-anchor — recompute
\*       compute_genesis_hash LOCALLY (:1477) + compare to the cached pin (:1478);
\*       PASS exit 0 (:1478-1484) iff equal, MISMATCH exit 2 (:1486-1490) otherwise
\*       (ReVerifyAnchor / INV_GenesisPinned).
\*   light/main.cpp:1446-1461       : cmd_state --show — load + validate + print; an
\*       absent file is graceful exit-0 "no anchor" (:1447-1450), a corrupt file
\*       throws → exit 1 (Load / INV_FailClosed).
\*   light/persist.cpp:84-132       : load_light_state — parse + validate; throws a
\*       field-naming runtime_error on malformed JSON (:91-96), non-object (:97-98),
\*       missing/invalid schema_version (:101-102), schema != 1 (:104-107, LSP-3 /
\*       INV_SchemaGated), missing/non-string/wrong-length/non-hex field
\*       (:109-129) — never a partial LightState (Load / LoadVerdict /
\*       INV_FailClosed). head_state_root is the ONE allowed-empty field (:127-129).
\*   light/persist.cpp:57-82        : save_light_state — serialize the well-formed
\*       record (schema_version + 64-hex genesis_hash / head_block_hash + optional
\*       head_state_root) atomically (WriteAnchor's Good hex shape).
\*   light/persist.cpp:22-30        : is_hex_len — the 64-hex shape check the Good /
\*       Bad HexShapes project (LSP-4 fail-closed family).
\*   light/persist.hpp:32-38        : struct LightState {schema_version, genesis_hash,
\*       head_height, head_block_hash, head_state_root} — the persisted record the
\*       Records triple abstracts (head_state_root "" on a pre-S-033 chain, :37).
\*   light/trustless_read.cpp:55-82 : anchor_genesis — recompute compute_genesis_hash
\*       LOCALLY (:55) + reject a daemon whose block 0 hash differs (:72-77); the
\*       local pin VerifyRun / WriteAnchor write into the cache (LSP-2 source of the
\*       locally-recomputed genesis).
\*   light/trustless_read.cpp:81+   : verify_chain_to_head — prev_hash continuity +
\*       per-block K-of-K committee Ed25519 over light_compute_block_digest; the
\*       committee-verify VerifyRun's HeadPin abstracts (LSP-1 source of the
\*       verified head).
\*   light/verify.cpp:57            : light_compute_block_digest — the per-block
\*       digest verify_chain_to_head's committee-sig check is taken over (the
\*       A1/A2 chain verification abstracted by VerifyRun). Binds index + prev_hash,
\*       so a suffix block's K-of-K sig forces its anchor link (LSP-6 prefix-skip).
\*   light/trustless_read.cpp (verify_chain_from_anchor) : the LSP-6 resume CONSUMER
\*       — re-pin genesis, fall back when the daemon is not ahead, else suffix-walk
\*       from the cached head_block_hash (ResumeVerify / INV_ResumeSound).
\*   light/trustless_read.cpp (verify_chain_walk index-contiguity gate) + light/verify.cpp
\*       (verify_headers anchored-page guard rejecting an index-0 header when a
\*       prev_hash anchor is supplied) : the resume-soundness fix — a suffix's first
\*       index must be anchor_height, not 0 (ResumeVerify "index0" → REJECTED /
\*       INV_ResumeNoFalseAccept).
\*   light/main.cpp (cmd_verify_chain --resume control flow) : corrupt/wrong-chain/
\*       not-ahead fallback + fork-below-anchor hard error + --resume --persist loop.
\*
\* Runtime regression:
\*   tools/test_light_state.sh (27 offline assertions) — state --selftest round-trip
\*     + 5 fail-closed reject paths (malformed JSON / bad schema_version / short
\*     genesis_hash / missing field / empty-state_root round-trip — LSP-3 / LSP-4 /
\*     INV_FailClosed / INV_SchemaGated); --show / --clear graceful-absence +
\*     fail-closed-on-corrupt; --verify-anchor PASS on matching genesis +
\*     MISMATCH-exit-2 on a wrong-chain anchor (LSP-2 / INV_GenesisPinned);
\*     verify-chain --persist arg acceptance + the LSP-1 no-write-on-failed-verify
\*     guarantee (INV_NoUnverifiedWrite). The in-binary `state --selftest` is the
\*     round-trip + reject-path witness (main.cpp:1506-1576).
\*
\* Doc updates (done by the orchestrator, NOT this file):
\*   docs/proofs/README.md FB57 row — index entry (house format).
\*   CHECK-RESULTS.md FB57 row — pending TLC install.
============================================================================
