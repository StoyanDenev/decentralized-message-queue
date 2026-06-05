--------------------------- MODULE RpcAdmissionOrdering ---------------------------
(*
FB51 — TLA+ specification of the RPC request-pipeline ADMISSION-ORDERING
state machine: the composed three-stage gate where the per-peer-IP
rate limiter (S-014) fires BEFORE the JSON parse and the HMAC auth
verify (S-001) fires AFTER the parse but BEFORE dispatch.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
RpcAdmissionOrdering.cfg RpcAdmissionOrdering.tla` once the TLC
toolchain is installed in CI.

Scope. Where FB36 (RpcHmacAuth.tla) models the HMAC auth gate in
isolation and FB25 (RateLimiterEviction.tla) models the rate-limiter
bucket lifecycle in isolation, NEITHER pins the ORDER in which those
two gates fire on a single inbound RPC line — and ordering is itself
a security property. This spec formalizes the per-connection request
loop at `src/rpc/rpc.cpp:142-195` (`RpcServer::handle_session`), the
one place where both subsystems compose on the hot path:

  Stage 1 (rate-limit, BEFORE parse). `rate_limiter_.consume(peer_ip)`
    at `src/rpc/rpc.cpp:172`. Mirrors the S-014 per-peer-IP token
    bucket. A peer that exceeds its bucket is shed with
    `error = "rate_limited"` and the request is NOT parsed, NOT
    authenticated, NOT dispatched. The deliberate ordering comment at
    `src/rpc/rpc.cpp:166-171` states two reasons: (a) avoid spending
    JSON-parse cost on rate-limited callers, and (b) rate-limited
    callers should not even learn whether their auth was valid.
  Stage 2 (HMAC auth, AFTER parse, BEFORE dispatch).
    `verify_auth(req)` at `src/rpc/rpc.cpp:179`. Mirrors the S-001
    HMAC-SHA-256 gate. Runs only on rate-limit-admitted requests
    (it is in the ELSE arm of the rate-limit branch at lines
    175-186). On a non-empty `auth_err` the request is shed with that
    error and NOT dispatched.
  Stage 3 (dispatch). `dispatch(req)` at `src/rpc/rpc.cpp:184`. Runs
    only on the doubly-admitted path: rate-limit PASS and auth PASS.

This composition surface is novel relative to the two component
specs: FB25 proves the rate limiter's bucket-eviction soundness but
treats `consume()` as the leaf; FB36 proves the auth gate's
unforgeability but explicitly notes (its §6 commentary) that the
rate limiter "is FB25 territory" and models the unbounded-rate
baseline. FB51 is the join: it pins that the two gates are wired in
series, in the right order, with no path to `dispatch` that skips
either gate.

Four paired theorems are pinned:

  (T-1) No-dispatch-without-both-gates. Every request that reaches
        the DISPATCHED outcome passed the rate-limit gate AND the
        auth gate. No interleaving admits a request to dispatch
        with a failed rate-limit or a failed auth. State-form
        witness: INV_DispatchImpliesBothGates.
  (T-2) Rate-limit-precedes-auth (ordering). A request that is
        rate-limited never has its auth evaluated — its outcome is
        RATE_LIMITED and its `auth_evaluated` flag is FALSE. This is
        the information-non-leakage contract at
        `src/rpc/rpc.cpp:166-171`: a flooding peer cannot use the
        server's response to distinguish a valid auth header from an
        invalid one, because the rate-limit shed happens before the
        HMAC recompute. State-form witness: INV_RateLimitedNeverAuthed.
  (T-3) Parse-deferred-past-rate-limit (cost-shedding). A request
        that is rate-limited is never parsed — its `parsed` flag is
        FALSE. This is the DoS-cost contract: the (relatively
        expensive) JSON parse + HMAC recompute are shed for
        rate-limited callers, so the per-peer token bucket bounds
        the parse+verify work an attacker can induce. State-form
        witness: INV_RateLimitedNeverParsed.
  (T-4) Outcome-totality + mutual-exclusion. Every processed request
        lands in EXACTLY ONE of {RATE_LIMITED, AUTH_FAILED,
        DISPATCHED}, matching the three response branches at
        `src/rpc/rpc.cpp:172-186`. No request is silently dropped and
        none is double-counted. State-form witness:
        INV_OutcomeTotality.

Plus one temporal property:

  PROP_EventualDrain — under fairness on Process, every enqueued
    request is eventually processed (lands in the processed log with
    one of the three outcomes). The forward-progress contract that
    the admission pipeline does not wedge: every line read off the
    socket reaches a terminal outcome.

The state machine. Three actions cover the admission surface (plus a
Stutter to bound TLC):

  * Arrive(peer, hdr) — a peer enqueues a request bearing an auth
    header that is either the canonical HMAC for the request body
    ("VALID") or a forged value ("FORGED"). Models a line arriving on
    the socket at `src/rpc/rpc.cpp:158`. We abstract the request body
    to its single peer identity (the bucket key) plus the auth-header
    validity tag — the auth payload's cryptographic detail is FB36
    territory; here we only need the boolean "would verify_auth pass".
  * Process — dequeue the head request and run the three-stage gate:
    consult the peer's token bucket; if empty, outcome = RATE_LIMITED
    (parsed = FALSE, auth_evaluated = FALSE); else spend a token,
    parse (parsed = TRUE), evaluate auth (auth_evaluated = TRUE):
    if the header is "VALID" outcome = DISPATCHED, else AUTH_FAILED.
    Mirrors `RpcServer::handle_session` lines 165-191.
  * Refill(peer) — restore one token to a peer's bucket, bounded by
    burst. Abstracts the S-014 refill-on-elapsed-time arithmetic
    (`rate_limiter.hpp` consume() refill branch); we model token
    grants as discrete Refill steps rather than a clock so the
    ordering invariants stay the focus (the refill arithmetic itself
    is FB25 territory).

Modeling scope (kept tractable for TLC):

  * `Peers` — finite universe of peer-IP bucket keys. Operationally
    the dotted-quad / v6-prefix string keyed in `buckets_`
    (`rate_limiter.hpp:151`); abstracted to opaque identifiers.
  * `Burst` — the per-peer token-bucket capacity (`burst_` in the C++
    RateLimiter; `configure(rate, burst)` at `rate_limiter.hpp:42`).
    The model uses a small burst so the rate-limit branch is reachably
    exercised within the bounded run.
  * `MaxArrivals` — bound on the processed-log + queue growth so TLC
    exhausts in seconds. Production runs unbounded.
  * The auth header is abstracted to a tag in {"VALID", "FORGED"}:
    "VALID" is the canonical HMAC the legitimate caller computes
    (`hmac_sha256_hex(key, canonical_for_hmac(method, params))` at
    `src/rpc/rpc.cpp:305-306`); "FORGED" is any adversary-chosen
    header distinct from the canonical value. The cryptographic
    non-collision (a FORGED header never equals the canonical HMAC)
    is FB36's contract (its ForgedHeaders ∩ HmacOutputs = {}
    disjointness); FB51 consumes it as the precondition that a
    "FORGED" header always fails verify_auth.
  * The auth-disabled escape hatch (`auth_secret_.empty()` short-
    circuit at `src/rpc/rpc.cpp:113`) is abstracted out: the spec
    models the auth-ENABLED configuration (the security-relevant
    case). With auth disabled, Stage 2 is a pass-through and the
    ordering contract degenerates trivially.
  * The token bucket is modeled as an integer level in 0..Burst, NOT
    the fractional-token + clock arithmetic of the C++ side. The
    ordering invariants (T-1..T-4) depend only on the boolean
    "bucket empty?" predicate, which the integer model captures
    exactly; the fractional refill arithmetic is FB25 territory.

The processed-log. `processed` is a sequence of records
`[peer, hdr, parsed, auth_evaluated, outcome]` — one entry per
Process invocation. The flags `parsed` and `auth_evaluated` are
spec-only observability lifts that make the ordering contracts
(T-2, T-3) checkable as state-form invariants: the C++ side does not
materialize these booleans, but the control-flow structure at
`src/rpc/rpc.cpp:172-186` determines them deterministically (a
rate-limited request takes the if-arm and never reaches the parse at
line 176 nor the verify at line 179).

To check (assuming TLC installed):
  $ tlc RpcAdmissionOrdering.tla -config RpcAdmissionOrdering.cfg

Recommended config (state space ~10^4, < 30s):
  Peers = {"p1", "p2"}, Burst = 2, MaxArrivals = 4.

Cross-references:
  - src/rpc/rpc.cpp:142-195 : RpcServer::handle_session — the
      per-connection request loop; the proof's primary object. The
      spec's Process action mirrors the three-stage gate.
  - src/rpc/rpc.cpp:166-171 : the ordering-comment block — the
      design rationale for rate-limit-before-auth (cost-shedding +
      information-non-leakage); the structural witness for T-2 + T-3.
  - src/rpc/rpc.cpp:172     : rate_limiter_.consume(peer_ip) — Stage 1.
  - src/rpc/rpc.cpp:176     : json::parse(line) — the parse that the
      rate-limit gate defers past (T-3).
  - src/rpc/rpc.cpp:179-182 : verify_auth(req) — Stage 2 (in the
      rate-limit ELSE arm; runs only on admitted requests).
  - src/rpc/rpc.cpp:184     : dispatch(req) — Stage 3 (the doubly-
      admitted path).
  - include/determ/net/rate_limiter.hpp:42-117 : configure() +
      consume() — the S-014 token bucket the Stage-1 gate consults.
  - docs/proofs/tla/RateLimiterEviction.tla (FB25) — the rate-limiter
      bucket-lifecycle spec; FB51's Stage-1 gate consumes FB25's
      consume()-as-leaf and adds the ordering composition above it.
  - docs/proofs/tla/RpcHmacAuth.tla (FB36) — the HMAC auth spec;
      FB51's Stage-2 gate consumes FB36's verify-gate determinism
      ("FORGED" always fails) and adds the ordering composition.
  - docs/proofs/S014RateLimiterSoundness.md — the analytic S-014
      proof; T-2 (no DoS amplification) is the cost-shedding side of
      FB51's T-3.
  - docs/proofs/RpcAuthHmacSoundness.md — the analytic S-001 proof;
      its §6 commentary names the rate limiter as the composing
      pre-gate that FB51 formalizes.
  - docs/SECURITY.md §S-001 + §S-014 — the closure narratives for the
      two subsystems this spec composes.
*)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Peers,              \* finite universe of peer-IP bucket keys.
    Burst,              \* per-peer token-bucket capacity (Nat >= 1).
    MaxArrivals         \* bound on processed + queue growth (TLC).

ASSUME ConfigOK ==
    /\ Cardinality(Peers) >= 1
       \* At least one peer so the model is non-trivial.
    /\ Burst \in Nat /\ Burst >= 1
       \* Positive burst so a request can be admitted at Stage 1.
    /\ MaxArrivals \in Nat /\ MaxArrivals >= 1
       \* Positive bound so TLC has a non-empty reachable state space.

\* -----------------------------------------------------------------
\* §1. Auth-header tags + outcome alphabet.
\* -----------------------------------------------------------------
\*
\* AuthTags: the abstracted auth-header validity. "VALID" is the
\* canonical HMAC the legitimate caller computes; "FORGED" is any
\* adversary-chosen header distinct from the canonical value. FB36
\* proves the cryptographic non-collision (a FORGED header never
\* equals the canonical HMAC); FB51 consumes that as the precondition
\* that verify_auth ACCEPTs iff the tag is "VALID".

AuthTags == {"VALID", "FORGED"}

\* Outcomes: the three terminal branches of handle_session's request
\* loop at `src/rpc/rpc.cpp:172-186`:
\*   "RATE_LIMITED" — Stage 1 shed (line 173-174).
\*   "AUTH_FAILED"  — Stage 2 shed (line 181-182).
\*   "DISPATCHED"   — Stage 3 reached (line 184-185).

Outcomes == {"RATE_LIMITED", "AUTH_FAILED", "DISPATCHED"}

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    tokens,             \* function Peers -> 0..Burst — each peer's
                         \*  current token-bucket level. Mirrors the
                         \*  Bucket.tokens field at `rate_limiter.hpp`
                         \*  collapsed to an integer level.
    queue,              \* Seq of [peer, hdr] — the inbound request
                         \*  queue (lines read off sockets awaiting
                         \*  the handle_session gate). FIFO: Process
                         \*  dequeues the head.
    processed           \* Seq of [peer, hdr, parsed, auth_evaluated,
                         \*  outcome] — the audit log of every Process
                         \*  invocation; one entry per gated request.

vars == <<tokens, queue, processed>>

\* QueueEntry: shape of an inbound request awaiting the gate.
QueueEntry == [peer : Peers, hdr : AuthTags]

\* ProcEntry: shape of a processed-log element. `parsed` and
\* `auth_evaluated` are the spec-only observability lifts that make
\* the ordering contracts (T-2, T-3) state-form-checkable.
ProcEntry == [
    peer           : Peers,
    hdr            : AuthTags,
    parsed         : BOOLEAN,
    auth_evaluated : BOOLEAN,
    outcome        : Outcomes
]

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* Every peer's bucket starts FULL at Burst (matches the C++ first-
\* touch branch `b.tokens = burst_` at `rate_limiter.hpp:107`; a
\* never-seen peer is admitted on its first request). queue +
\* processed start empty.

Init ==
    /\ tokens    = [p \in Peers |-> Burst]
    /\ queue     = <<>>
    /\ processed = <<>>

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* Arrive(peer, hdr): a peer enqueues a request bearing an auth-header
\* tag. Models a line arriving on the socket at `src/rpc/rpc.cpp:158`.
\* Bounded by MaxArrivals on the combined queue+processed length so
\* TLC explores a bounded universe.
\*
\* Pre-condition: peer ∈ Peers; hdr ∈ AuthTags; the total work
\* (queued + processed) is below the bound.
\*
\* Post-condition: queue grows by one entry; tokens + processed
\* unchanged.

Arrive(peer, hdr) ==
    /\ peer \in Peers
    /\ hdr \in AuthTags
    /\ Len(queue) + Len(processed) < MaxArrivals
    /\ queue' = Append(queue, [peer |-> peer, hdr |-> hdr])
    /\ UNCHANGED <<tokens, processed>>

\* Process: dequeue the head request and run the three-stage gate.
\*
\* Mirrors `RpcServer::handle_session` lines 165-191:
\*
\*   if (!rate_limiter_.consume(peer_ip)) {        // Stage 1 shed
\*       response["error"] = "rate_limited";
\*   } else {
\*       auto req = json::parse(line);             // parse (Stage 1 PASS)
\*       std::string auth_err = verify_auth(req);  // Stage 2
\*       if (!auth_err.empty()) {                  // Stage 2 shed
\*           response["error"] = auth_err;
\*       } else {
\*           response["result"] = dispatch(req);   // Stage 3
\*       }
\*   }
\*
\* Stage 1: if the head peer's bucket is empty (tokens = 0), the
\* request is RATE_LIMITED — NOT parsed, NOT auth-evaluated. This is
\* the structural witness for T-2 (rate-limited never authed) + T-3
\* (rate-limited never parsed): the spec sets parsed = FALSE and
\* auth_evaluated = FALSE on this branch, exactly mirroring the
\* control flow that never reaches line 176 (parse) nor line 179
\* (verify_auth).
\*
\* Stage 1 PASS: spend a token (tokens[peer] - 1), parse (parsed =
\* TRUE), then evaluate auth (auth_evaluated = TRUE):
\*   Stage 2 PASS (hdr = "VALID"): outcome = DISPATCHED.
\*   Stage 2 shed (hdr = "FORGED"): outcome = AUTH_FAILED.
\*
\* Pre-condition: queue non-empty; processed below the bound.
\*
\* Post-condition: queue shrinks by one; processed grows by one with
\* the gated outcome; tokens decremented for the head peer iff the
\* rate-limit gate passed.

Process ==
    /\ Len(queue) > 0
    /\ Len(processed) < MaxArrivals
    /\ LET head_req == Head(queue) IN
       LET p        == head_req.peer IN
       LET h        == head_req.hdr  IN
       LET admitted == tokens[p] > 0 IN
       LET outcome  == IF ~admitted        THEN "RATE_LIMITED"
                       ELSE IF h = "VALID"  THEN "DISPATCHED"
                       ELSE                      "AUTH_FAILED" IN
       LET entry    == [peer           |-> p,
                        hdr            |-> h,
                        parsed         |-> admitted,
                        auth_evaluated |-> admitted,
                        outcome        |-> outcome] IN
       /\ queue'     = Tail(queue)
       /\ processed' = Append(processed, entry)
       /\ tokens'    = IF admitted
                       THEN [tokens EXCEPT ![p] = tokens[p] - 1]
                       ELSE tokens

\* Refill(peer): restore one token to a peer's bucket, capped at
\* Burst. Abstracts the S-014 refill-on-elapsed-time arithmetic at
\* `rate_limiter.hpp` consume()'s refill branch
\* (`b.tokens = min(burst, b.tokens + elapsed*rate)`) — modeled as a
\* discrete grant so the ordering invariants stay the focus. The
\* fractional-token + clock arithmetic itself is FB25 territory.
\*
\* Pre-condition: peer ∈ Peers; the bucket is below capacity.
\*
\* Post-condition: tokens[peer] grows by one; queue + processed
\* unchanged.

Refill(peer) ==
    /\ peer \in Peers
    /\ tokens[peer] < Burst
    /\ tokens' = [tokens EXCEPT ![peer] = tokens[peer] + 1]
    /\ UNCHANGED <<queue, processed>>

\* Stutter (TLC bounds the state space; invariants are evaluated at
\* every reachable state along the way). Fires at saturation when the
\* processed log has reached the bound and the queue is drained.

Stutter ==
    /\ Len(processed) >= MaxArrivals
    /\ Len(queue) = 0
    /\ UNCHANGED vars

Next ==
    \/ \E p \in Peers : \E h \in AuthTags : Arrive(p, h)
    \/ Process
    \/ \E p \in Peers : Refill(p)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(Process)
             /\ WF_vars(\E p \in Peers : Refill(p))

\* -----------------------------------------------------------------
\* §5. Invariants — T-1..T-4 + TypeOK.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.

TypeOK ==
    /\ tokens \in [Peers -> 0..Burst]
    /\ queue  \in Seq(QueueEntry)
    /\ processed \in Seq(ProcEntry)
    /\ Len(queue) <= MaxArrivals
    /\ Len(processed) <= MaxArrivals

\* INV_DispatchImpliesBothGates (T-1).
\*
\* Every processed entry with outcome = "DISPATCHED" was parsed AND
\* auth-evaluated AND carried a "VALID" header. There is no path to
\* dispatch that skips either gate.
\*
\* Structural witness in Process: outcome is set to "DISPATCHED" iff
\* the rate-limit gate passed (admitted = TRUE ⇒ parsed = TRUE,
\* auth_evaluated = TRUE) AND the header was "VALID". So a DISPATCHED
\* entry necessarily has parsed = auth_evaluated = TRUE and
\* hdr = "VALID".

INV_DispatchImpliesBothGates ==
    \A i \in 1..Len(processed) :
       LET e == processed[i] IN
       (e.outcome = "DISPATCHED")
       => /\ e.parsed = TRUE
          /\ e.auth_evaluated = TRUE
          /\ e.hdr = "VALID"

\* INV_RateLimitedNeverAuthed (T-2).
\*
\* Every processed entry with outcome = "RATE_LIMITED" has
\* auth_evaluated = FALSE — the rate-limit shed happened before the
\* HMAC recompute, so the auth was never evaluated. This is the
\* information-non-leakage contract at `src/rpc/rpc.cpp:166-171`: a
\* flooding peer cannot tell from the response whether its auth
\* header was valid, because rate-limited requests never reach
\* verify_auth at line 179.
\*
\* Structural witness in Process: the RATE_LIMITED branch sets
\* auth_evaluated = admitted = FALSE.

INV_RateLimitedNeverAuthed ==
    \A i \in 1..Len(processed) :
       LET e == processed[i] IN
       (e.outcome = "RATE_LIMITED")
       => (e.auth_evaluated = FALSE)

\* INV_RateLimitedNeverParsed (T-3).
\*
\* Every processed entry with outcome = "RATE_LIMITED" has
\* parsed = FALSE — the JSON parse at `src/rpc/rpc.cpp:176` is in the
\* rate-limit ELSE arm, so a rate-limited request is never parsed.
\* This is the DoS-cost contract: the per-peer token bucket bounds
\* the parse + verify work an attacker can induce, because the
\* (relatively expensive) parse is shed for rate-limited callers.
\*
\* Structural witness in Process: the RATE_LIMITED branch sets
\* parsed = admitted = FALSE.

INV_RateLimitedNeverParsed ==
    \A i \in 1..Len(processed) :
       LET e == processed[i] IN
       (e.outcome = "RATE_LIMITED")
       => (e.parsed = FALSE)

\* INV_OutcomeTotality (T-4).
\*
\* Every processed entry lands in EXACTLY ONE of the three outcomes,
\* and the flags are consistent with the outcome:
\*   - RATE_LIMITED  ⇒ ~parsed ∧ ~auth_evaluated.
\*   - AUTH_FAILED   ⇒  parsed ∧  auth_evaluated ∧ hdr = "FORGED".
\*   - DISPATCHED    ⇒  parsed ∧  auth_evaluated ∧ hdr = "VALID".
\* No request is silently dropped (every Process appends exactly one
\* entry) and none is double-counted. Matches the three response
\* branches at `src/rpc/rpc.cpp:172-186`.
\*
\* The mutual-exclusion + totality is structurally guaranteed by the
\* outcome being a single value from the three-element Outcomes set;
\* this invariant additionally pins the flag/outcome consistency.

INV_OutcomeTotality ==
    \A i \in 1..Len(processed) :
       LET e == processed[i] IN
       /\ e.outcome \in Outcomes
       /\ (e.outcome = "RATE_LIMITED")
            => (e.parsed = FALSE /\ e.auth_evaluated = FALSE)
       /\ (e.outcome = "AUTH_FAILED")
            => (e.parsed = TRUE /\ e.auth_evaluated = TRUE
                /\ e.hdr = "FORGED")
       /\ (e.outcome = "DISPATCHED")
            => (e.parsed = TRUE /\ e.auth_evaluated = TRUE
                /\ e.hdr = "VALID")

\* INV_NoTokenUnderflow — supporting invariant: a token is spent only
\* when the bucket is non-empty (Stage 1 PASS), so the level never
\* goes negative and never exceeds Burst. The structural witness that
\* the rate-limit gate's "consume" never over-draws — the C++
\* `consume()` returns false (RATE_LIMITED) when `b.tokens < 1.0`
\* WITHOUT decrementing (`rate_limiter.hpp` consume() guard). Ties the
\* ordering model back to the bucket invariant FB25 proves in full.

INV_NoTokenUnderflow ==
    \A p \in Peers : tokens[p] \in 0..Burst

\* -----------------------------------------------------------------
\* §6. Temporal property.
\* -----------------------------------------------------------------

\* PROP_EventualDrain — under fairness on Process, every enqueued
\* request is eventually processed (the queue does not wedge). The
\* forward-progress contract that the admission pipeline always makes
\* progress: every line read off the socket reaches one of the three
\* terminal outcomes. The model bound MaxArrivals pins the surface;
\* within the bounded run, WF on Process drains the queue to empty.

PROP_EventualDrain ==
    (Len(queue) > 0) ~> (Len(queue) = 0)

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The composition contract (S-014 rate limiter wired in series ahead
\* of the S-001 HMAC gate) is pinned at the state-machine layer by the
\* five invariants + one temporal property. The abstraction boundary:
\*
\*   * The auth header is collapsed to a {"VALID", "FORGED"} tag. The
\*     cryptographic non-collision (a FORGED header never equals the
\*     canonical HMAC, so verify_auth ACCEPTs iff the tag is "VALID")
\*     is FB36 / RpcAuthHmacSoundness.md territory. FB51 consumes that
\*     as the precondition `outcome = DISPATCHED iff hdr = "VALID"`
\*     on the admitted path; it does NOT re-prove HMAC unforgeability.
\*
\*   * The token bucket is an integer level in 0..Burst. The
\*     fractional-token + steady_clock refill arithmetic at
\*     `rate_limiter.hpp` consume() is FB25 territory. FB51 models the
\*     bucket only as far as the boolean "empty?" predicate the Stage-1
\*     gate consults; Refill abstracts the time-decay refill as a
\*     discrete grant. The ordering invariants (T-1..T-4) depend only
\*     on the empty?-predicate, which the integer model captures
\*     exactly.
\*
\*   * The idle-bucket eviction policy (S-014 F-1; FB25) is NOT
\*     modeled here — eviction operates on `last_touch` and does not
\*     affect the admission ordering. A peer whose bucket was evicted
\*     re-creates at FULL on its next Arrive→Process (FB25's INV-3
\*     ResurrectionSafe); FB51's Init-at-Burst + Refill captures the
\*     observationally-equivalent re-creation.
\*
\*   * The HELLO-exemption gate (S-014 T-4; the gossip-layer carve-out
\*     that lets handshakes complete under rate-limit pressure) is NOT
\*     on the RPC path. handle_session has no HELLO concept; HELLO is a
\*     gossip-wire message (FB37 HelloHandshake.tla territory). FB51
\*     models the RPC admission surface only.
\*
\*   * The auth-DISABLED escape hatch (`auth_secret_.empty()` short-
\*     circuit at `src/rpc/rpc.cpp:113`) is abstracted out: the spec
\*     models the auth-ENABLED configuration. With auth disabled,
\*     Stage 2 is a pass-through (every admitted request DISPATCHes)
\*     and the ordering contract degenerates trivially.
\*
\*   * The per-message-type size caps (S-022; FB47 WireFrameCap.tla)
\*     and TCP keepalive reaping (S-026; FB39 TcpKeepaliveReap.tla)
\*     are sibling network-hardening surfaces NOT on the RPC
\*     admission-ordering path; FB51 does not model them.
\*
\* What this spec adds beyond the component specs: a state-machine
\* witness that the two gates are wired IN SERIES, IN THE RIGHT ORDER,
\* with NO path to dispatch that skips either gate, across every
\* reachable interleaving of Arrive / Process / Refill within the
\* bounded universe. TLC enumerates every reachable schedule —
\* including the adversarial flood case (many Arrive on one peer
\* draining its bucket so subsequent requests are RATE_LIMITED before
\* their auth is ever evaluated) and the mixed-validity case (VALID
\* and FORGED headers interleaved under rate-limit pressure) — and the
\* invariants are checked against the accumulated processed log.
\*
\* What the spec does NOT check (consistent with the §scope above):
\*   * HMAC-SHA-256 unforgeability — FB36 / RpcAuthHmacSoundness.md.
\*   * Token-bucket refill arithmetic + idle-eviction — FB25 /
\*     RateLimiterEviction.tla + S014RateLimiterSoundness.md.
\*   * The constant-time auth compare — FB36 T-3 (the byte-level
\*     XOR-OR loop at `src/rpc/rpc.cpp:122-128`).
\*   * Concurrent-session interleaving across distinct sockets — the
\*     C++ side serializes the rate limiter via `std::mutex mu_`
\*     (`rate_limiter.hpp`); the spec uses TLA+ atomic actions to model
\*     the serialized critical section.

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   src/rpc/rpc.cpp:142-195 : RpcServer::handle_session — the per-
\*       connection request loop; the proof's primary object. The
\*       spec's Process action mirrors the three-stage gate.
\*   src/rpc/rpc.cpp:166-171 : the ordering-comment block — the design
\*       rationale (cost-shedding + information-non-leakage); the
\*       structural witness for T-2 + T-3.
\*   src/rpc/rpc.cpp:172     : rate_limiter_.consume(peer_ip) — Stage 1
\*       (rate-limit, BEFORE parse).
\*   src/rpc/rpc.cpp:176     : json::parse(line) — the parse the
\*       rate-limit gate defers past (T-3).
\*   src/rpc/rpc.cpp:179-182 : verify_auth(req) — Stage 2 (HMAC auth,
\*       in the rate-limit ELSE arm; runs only on admitted requests).
\*   src/rpc/rpc.cpp:184-185 : dispatch(req) — Stage 3 (the doubly-
\*       admitted path: rate-limit PASS and auth PASS).
\*   include/determ/net/rate_limiter.hpp:42-117 : configure() +
\*       consume() — the S-014 token bucket the Stage-1 gate consults.
\*
\* SECURITY.md §S-001 — HMAC RPC auth closure (the Stage-2 gate).
\* SECURITY.md §S-014 — per-peer-IP rate-limit closure (the Stage-1
\*   gate); T-2 (no DoS amplification) is the cost-shedding side of
\*   FB51's T-3.
\*
\* docs/proofs/RpcAuthHmacSoundness.md — the analytic S-001 proof;
\*   its §6 commentary names the rate limiter as the composing pre-gate
\*   that FB51 formalizes at the state-machine layer.
\* docs/proofs/S014RateLimiterSoundness.md — the analytic S-014 proof;
\*   T-2 (no DoS amplification) + T-3 (per-IP independence) are the
\*   FA-track theorems whose RPC-pipeline composition FB51 pins.
\*
\* FB25 RateLimiterEviction.tla — the rate-limiter bucket-lifecycle
\*   spec; FB51's Stage-1 gate consumes FB25's consume()-as-leaf and
\*   adds the ordering composition above it.
\* FB36 RpcHmacAuth.tla — the HMAC auth spec; FB51's Stage-2 gate
\*   consumes FB36's verify-gate determinism ("FORGED" always fails)
\*   and adds the ordering composition. FB36's §6 explicitly defers
\*   the rate-limiter composition; FB51 fills that gap.
\* FB37 HelloHandshake.tla — the gossip-layer handshake admission gate
\*   (sibling network-hardening surface; HELLO is NOT on the RPC path).
\* FB39 TcpKeepaliveReap.tla, FB47 WireFrameCap.tla — sibling network-
\*   hardening surfaces (S-026 / S-022) NOT on the RPC admission path.
\*
\* Runtime regressions:
\*   tools/test_rpc_hmac_auth.sh   — pins the Stage-2 HMAC gate.
\*   tools/test_rpc_rate_limit.sh  — pins the Stage-1 rate-limit gate;
\*     the regression that exercises the rate-limit-before-auth
\*     ordering at the C++ layer (a rate-limited request returns
\*     "rate_limited" regardless of its auth header).
\*   tools/test_rate_limiter.sh    — the S-014 unit-test harness for
\*     the token bucket the Stage-1 gate consults.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB51 row — added.
============================================================================
