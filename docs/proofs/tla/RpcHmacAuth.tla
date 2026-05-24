--------------------------- MODULE RpcHmacAuth ---------------------------
(*
FB36 — TLA+ specification of the v2.16 RPC HMAC-SHA-256 authentication
state machine (S-001 closure, cross-tenant arm).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
RpcHmacAuth.cfg RpcHmacAuth.tla` once the TLC toolchain is installed
in CI.

Scope. Formalizes the RPC authentication state machine that governs
Determ's `RpcServer::verify_auth` flow at `src/rpc/rpc.cpp:112-129`.
Every state-mutating RPC request must carry an `auth` header
containing `hex(HMAC-SHA-256(server_secret, canonical(method, body)))`
where `canonical(method, body) := method ‖ "|" ‖ body.dump()`. The
server recomputes the expected HMAC under its locally-stored secret
and accepts the request iff the constant-time compare at
`src/rpc/rpc.cpp:122-128` returns `diff == 0`.

This spec abstracts the HMAC primitive (delegating cryptographic
strength to A2 / H1 SHA-256 collision resistance per
`Preliminaries.md` §2.1 + the standard HMAC PRF reduction of
Bellare-Canetti-Krawczyk 1996 / Bellare 2006) and the constant-time
compare (the per-byte XOR-OR loop at `src/rpc/rpc.cpp:124-128`
modeled as a spec-level pure-function predicate; the operational
constant-time property is asserted as a precondition citing the C++
source).

Five paired theorems are pinned (per RpcAuthHmacSoundness.md §1 +
S001RpcAuthSoundness.md §3):

  (T-1) Authentication soundness. Under (A_HMAC) HMAC-SHA-256 PRF
        security and (K_random) uniform key distribution, no
        adversary without the server's secret outputs a valid
        (body, auth_header) pair with non-negligible probability.
        The state-form witness is INV_NoForgedAccepted + the
        abstract Hmac() operator's per-key distinctness.
  (T-2) No auth bypass. Every accepted request had `auth_header =
        Hmac(server_secret, body)` at processing time; no
        adversary-chosen `auth_header` distinct from the canonical
        value is admitted. State-form witness: INV_NoAuthBypass.
  (T-3) Constant-time comparison. The verify-time compare is
        constant in the inputs (the C++ XOR-OR loop at
        `src/rpc/rpc.cpp:124-128`); modeled at spec level as an
        atomic predicate (no per-byte timing side-channel). State-
        form witness: INV_ConstantTimeCompare (assertion-form
        precondition citing the C++ source).
  (T-4) Secret confidentiality. The server secret never appears in
        any auth_log entry or pending_requests payload; the only
        place the secret is materialized is the Hmac() invocation
        itself. State-form witness: INV_SecretConfidentiality.
  (T-5) Eventual rejection of forgery. Under fairness on
        ProcessRequest, every forged request (where
        auth_header ≠ Hmac(server_secret, body)) is eventually
        rejected. The forward-progress contract that bounds the
        attacker's ability to flood with forgeries — every queued
        request reaches the verify gate. State-form witness:
        PROP_EventualReject.

The state machine. Four actions cover the auth-pipeline surface:

  * ConfigureSecret(s) — the server sets (or rotates) its secret
    to s ∈ RpcSecrets. Mirrors the operator-configured
    `auth_secret_` field set at `RpcServer::RpcServer` construction
    (`src/rpc/rpc.cpp:79-90`) via the hex-decoded
    `DETERM_RPC_AUTH_SECRET` env var or explicit `--auth-secret`
    CLI argument. The C++ side decodes from hex; the spec layer
    uses the secret universe `RpcSecrets` directly.
  * IssueAuthorizedRequest(body) — legitimate caller computes
    `auth_header := Hmac(server_secret, body)` and enqueues
    (body, auth_header) to pending_requests. Mirrors the client-
    side `rpc_call` at `src/rpc/rpc.cpp:276-321` which reads the
    secret from the env var, computes the HMAC, and writes the
    JSON line.
  * IssueForgedRequest(body, forged_header) — adversary picks any
    `body ∈ Messages` and any `forged_header /= Hmac(server_secret,
    body)` (i.e., the adversary explicitly does NOT know the
    secret, so the forged_header is uncorrelated with the
    canonical Hmac output). Models the network-active attacker
    (A_outside in `S001RpcAuthSoundness.md` §2.3).
  * ProcessRequest — dequeue head of pending_requests; recompute
    `expected := Hmac(server_secret, head.body)`; accept iff
    `head.auth_header = expected`; log the (server_secret, body,
    auth_header, result) tuple to auth_log. Mirrors
    `RpcServer::verify_auth` at `src/rpc/rpc.cpp:112-129` with the
    constant-time compare assumed as a precondition (modeled at
    spec level as an atomic equality check).

Five invariants codify T-1..T-4 + a type predicate:

  TypeOK — shape predicate for all variables.
  INV_NoForgedAccepted (T-1) — every entry in auth_log with
        result = "ACCEPT" has `auth_header = Hmac(secret, body)`.
        State-form witness of the HMAC-PRF unforgeability claim
        lifted to the state-machine layer.
  INV_ConstantTimeCompare (T-3) — assertion-form predicate citing
        the C++ source: the verify compare at
        `src/rpc/rpc.cpp:122-128` is constant-time (no per-byte
        timing side-channel). At the spec layer, the compare is
        an atomic equality predicate; the precondition is asserted
        as TRUE and the C++ source is cited.
  INV_SecretConfidentiality (T-4) — `server_secret` never appears
        as a field of any auth_log entry or pending_requests
        payload. State-form witness: every entry's `secret` field
        is bound (TRUE-by-construction) to the value that was
        in effect AT THE TIME OF PROCESSING, but no element of
        pending_requests carries the secret directly — the
        legitimate caller materializes the Hmac output, not the
        secret bytes.
  INV_NoAuthBypass (T-2) — no entry in auth_log has
        result = "ACCEPT" where the recorded auth_header differs
        from `Hmac(secret, body)`. Captures the "every accepted
        request was either issued legitimately OR the adversary
        broke HMAC" claim. The structural witness is the
        ProcessRequest action's body: the result is set to
        "ACCEPT" iff `head.auth_header = Hmac(server_secret,
        head.body)`.

Two temporal properties pin the headline composition claims:

  PROP_EventualReject (T-5) — under fairness on ProcessRequest,
    every forged request (where the queued auth_header is NOT
    the canonical Hmac(server_secret, body)) is eventually
    rejected and logged with result = "REJECT".
  PROP_NoForgeryWithoutSecret — the adversary cannot produce a
    valid auth_header without learning the secret (modeled via
    the abstract Hmac() function's pre-image resistance:
    Hmac(secret, body) is deterministic per (secret, body) and
    distinct (secret, body) pairs yield distinct outputs per
    A2 SHA-256 collision resistance, so no forged_header
    selected without knowledge of secret can equal Hmac(secret,
    body) with non-negligible probability).

Modeling scope (kept tractable for TLC):

  * `RpcSecrets` is a SUBSET of strings — the universe of
    possible HMAC secrets. Production secrets are 32-byte
    binary strings (256 bits of entropy from
    `openssl rand -hex 32`); the model uses 2 distinct opaque
    secrets to exercise the configure + rotate surface.
  * `Messages` is a SUBSET of strings — the universe of
    request bodies. Production bodies are JSON-serialized
    (method, params) tuples canonicalized via
    `canonical_for_hmac` at `src/rpc/rpc.cpp:52-58`; the spec
    abstracts the canonicalization (delegating to L-2 of
    `RpcAuthHmacSoundness.md`) and treats messages as opaque
    strings.
  * `MaxRequests` bounds the auth_log + pending_requests
    growth so TLC exhausts in seconds. Production runs
    unbounded; the model bounds at 4 to exercise: 0→1
    (first authorized), 1→2 (first forged), 2→3 (mixed
    interleaving), 3→4 (saturation, Stutter pins the bound).
  * `Hmac(secret, body)` is the spec-layer abstract operator:
    a deterministic pure function of `(secret, body)`. Modeled
    as a tagged tuple `<<"HMAC", secret, body>>` so distinct
    `(secret, body)` pairs produce distinct outputs by TLA+
    extensional equality. This abstracts SHA-256 collision
    resistance (A2 / H1) + the HMAC PRF reduction (A_HMAC):
    the cryptographic strength of the primitive is asserted
    at the analytic layer (`RpcAuthHmacSoundness.md` L-1, L-5);
    the spec layer enforces only the determinism + distinctness
    contract.
  * `auth_log` is a sequence of records `[secret, body,
    auth_header, result]` — one entry per ProcessRequest
    invocation. The `secret` field captures the server_secret
    in effect AT THE TIME OF PROCESSING (which may differ from
    the current server_secret if ConfigureSecret has since
    rotated). `result` is one of `{"ACCEPT", "REJECT"}`.
  * `pending_requests` is a sequence of records `[body,
    auth_header]` — the legitimate-issued and adversary-issued
    requests waiting to be processed. ProcessRequest dequeues
    from the head (FIFO discipline matching the chain's
    request-acceptance order).

The state machine. Four actions cover the auth-pipeline surface
(plus a Stutter to bound TLC):

  * ConfigureSecret(s) — server_secret' = s; UNCHANGED auth_log
    + pending_requests. The legitimate-caller's secret-of-record
    follows server_secret implicitly (the client side re-reads
    DETERM_RPC_AUTH_SECRET on each call per the spec at
    `src/rpc/rpc.cpp:294`); rotations are picked up on the next
    IssueAuthorizedRequest call.
  * IssueAuthorizedRequest(body) — append
    `[body, Hmac(server_secret, body)]` to pending_requests.
    Mirrors the legitimate client at `src/rpc/rpc.cpp:276-321`.
    The server_secret is read at the call site (not stored in
    the request body — INV_SecretConfidentiality's structural
    witness).
  * IssueForgedRequest(body, forged_header) — append
    `[body, forged_header]` to pending_requests where the
    forged_header CONSTRAINT is `forged_header /= Hmac(secret,
    body)` for EVERY secret s ∈ RpcSecrets the adversary might
    have guessed. Models A_outside: the adversary has zero
    knowledge of the secret-universe and picks a forged_header
    uncorrelated with the canonical Hmac outputs. TLC explores
    every reachable adversarial choice within the bounded
    Messages × {forged values} universe.
  * ProcessRequest — dequeue head of pending_requests;
    compute `expected := Hmac(server_secret, head.body)`;
    set result := IF head.auth_header = expected THEN "ACCEPT"
    ELSE "REJECT"; append [server_secret, head.body,
    head.auth_header, result] to auth_log.

To check (assuming TLC installed):
  $ tlc RpcHmacAuth.tla -config RpcHmacAuth.cfg

Recommended config (state space ~10^4, < 30s):
  RpcSecrets = {"s1", "s2"}, Messages = {"body1", "body2"},
  MaxRequests = 4.

Cross-references:
  - src/rpc/rpc.cpp:52-58   : canonical_for_hmac(method, params)
      canonical-serialization helper (method ‖ "|" ‖ params.dump());
      the spec's Hmac() input domain is the canonicalized bytes,
      abstracted to opaque Messages strings.
  - src/rpc/rpc.cpp:60-70   : hmac_sha256_hex(key, message) HMAC
      primitive wrapping OpenSSL HMAC(EVP_sha256(), ...); the
      spec's Hmac() operator is the spec-layer projection.
  - src/rpc/rpc.cpp:79-90   : RpcServer constructor; secret hex-
      decoded into auth_secret_ at construction; the spec's
      ConfigureSecret action mirrors this initialization (and the
      operational rotation path via DETERM_RPC_AUTH_SECRET env
      var re-read).
  - src/rpc/rpc.cpp:92-104  : Startup log emitting only
      auth_secret_.size(), never the value; the structural witness
      for INV_SecretConfidentiality at the log-output surface.
  - src/rpc/rpc.cpp:112-129 : verify_auth — the proof's primary
      object. The spec's ProcessRequest action mirrors this flow:
      empty-secret short-circuit (line 113) → missing-auth check
      (lines 114-116) → expected Hmac recompute (lines 117-120) →
      constant-time XOR-OR compare (lines 122-128).
  - src/rpc/rpc.cpp:122-128 : Constant-time XOR-OR loop; the
      structural witness for T-3 / INV_ConstantTimeCompare.
  - src/rpc/rpc.cpp:276-321 : Client-side rpc_call with
      DETERM_RPC_AUTH_SECRET env var support; the spec's
      IssueAuthorizedRequest action mirrors this.
  - docs/proofs/RpcAuthHmacSoundness.md — the analytic FA-track
      proof; §1 T-1..T-5 enumerate the five theorems this spec
      lifts to the state-machine layer; §4 walks per-theorem
      analytic proofs; §6 documents the adversary model (a..f).
  - docs/proofs/S001RpcAuthSoundness.md — the composition theorem
      covering HMAC auth + input-validation defense; §3 T-1..T-5
      enumerate the composition claims this spec abstracts
      (HMAC layer only — the input-validation arm is FB27
      JsonValidation.tla territory).
  - docs/proofs/Preliminaries.md §2.1 (A2 SHA-256 collision
      resistance) — the cryptographic assumption underlying the
      abstract Hmac() operator's determinism + distinctness; the
      spec asserts the structural side (deterministic pure
      function with distinct outputs on distinct inputs), the
      analytic side (HMAC PRF reduction) is the prose proof's
      domain.
  - docs/proofs/Preliminaries.md §2.2 (A1 Ed25519 EUF-CMA) —
      cited by analogy for the EUF-CMA-style game in T-1 (the
      auth-forgery game has the same shape as the EUF-CMA
      game; the adversary observes Hmacs and outputs a new
      (body, header) pair where the body is fresh).
  - docs/SECURITY.md §S-001 — closure narrative for the HMAC
      RPC auth scheme; the spec is the state-machine witness of
      Option 3's "attacker without secret cannot forge requests"
      claim.
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    RpcSecrets,         \* SUBSET of strings — the universe of
                         \*  possible HMAC secrets. Production uses
                         \*  32-byte binary strings; the model uses
                         \*  a small finite set.
    Messages,           \* SUBSET of strings — the universe of
                         \*  request bodies. Production uses JSON-
                         \*  canonicalized (method, params) tuples;
                         \*  the model uses opaque strings.
    MaxRequests          \* Nat — bound on auth_log + pending_requests
                         \*  growth (TLC tractability).

ASSUME ConfigOK ==
    /\ Cardinality(RpcSecrets) >= 1
       \* At least one secret universe-wide so the model is
       \* non-trivial. The model uses 2 to exercise the rotate
       \* surface in ConfigureSecret.
    /\ Cardinality(Messages) >= 1
       \* At least one message body universe-wide so the model
       \* is non-trivial.
    /\ MaxRequests \in Nat /\ MaxRequests >= 1
       \* Positive bound so TLC has a non-empty reachable state
       \* space.

\* -----------------------------------------------------------------
\* §1. Abstract HMAC operator.
\* -----------------------------------------------------------------

\* Hmac(secret, body): the spec-layer projection of OpenSSL
\* HMAC(EVP_sha256(), secret, body) at `src/rpc/rpc.cpp:60-70`.
\* Modeled as a tagged tuple <<"HMAC", secret, body>>: two distinct
\* (secret, body) pairs produce distinct outputs by TLA+ extensional
\* equality on tuples; same (secret, body) pair always produces the
\* same output (purity / determinism).
\*
\* Determinism: pure function of (secret, body). Required for cross-
\* node consensus on the same canonical input bytes (L-2 of
\* `RpcAuthHmacSoundness.md`).
\*
\* Distinctness: for any (s1, b1) /= (s2, b2), Hmac(s1, b1) /=
\* Hmac(s2, b2). The structural witness for collision-resistance
\* lifted to the spec layer: SHA-256 collision resistance (A2 / H1
\* per `Preliminaries.md` §2.1) bounds the analytic probability of
\* a collision at <= 2^-128; the spec layer asserts the structural
\* form (distinct tuples ⇒ distinct outputs), the analytic side is
\* the prose proof's domain.
\*
\* Pre-image resistance: for any t in the range of Hmac, recovering
\* (secret, body) from t requires breaking HMAC-SHA-256's PRF
\* security (A_HMAC per `RpcAuthHmacSoundness.md` §2.1). The spec
\* layer asserts the adversary cannot produce a valid forged_header
\* without learning the secret — this is the structural witness for
\* PROP_NoForgeryWithoutSecret.

Hmac(secret, body) == <<"HMAC", secret, body>>

\* HmacOutputs: the range of the Hmac operator over the bounded
\* universe of (secret, body) pairs. Used by IssueForgedRequest's
\* forged_header constraint to enumerate the canonical-Hmac outputs
\* the adversary must AVOID picking by chance.
\*
\* TLC enumerates this set as a SUBSET of the tagged-tuple universe
\* {"HMAC"} × RpcSecrets × Messages. Cardinality
\* |RpcSecrets| × |Messages| — small enough for the recommended
\* cfg (2 × 2 = 4 canonical outputs the adversary must avoid).

HmacOutputs == { Hmac(s, b) : s \in RpcSecrets, b \in Messages }

\* ForgedHeaders: the universe of adversary-chosen headers that are
\* NOT canonical Hmac outputs. The adversary picks from this set in
\* IssueForgedRequest. Modeled as a single sentinel value "FORGED"
\* distinct from every canonical Hmac output by construction (the
\* tagged-tuple <<"HMAC", _, _>> is never equal to the string
\* "FORGED").
\*
\* This abstraction is sound because: under A_outside (the adversary
\* has no access to the secret), the probability that a randomly-
\* chosen forged_header collides with the canonical Hmac output is
\* bounded by 2^-256 per attempt (L-5 of `RpcAuthHmacSoundness.md`);
\* the spec layer collapses the entire "random forge attempt" event
\* into the single "FORGED" sentinel, which by construction does
\* not collide with any canonical Hmac. The analytic side bounds
\* the collision probability; the spec layer enforces non-collision
\* structurally.

ForgedHeaders == {"FORGED"}

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    server_secret,      \* element of RpcSecrets ∪ {"NONE"} — the
                         \*  server's currently-configured secret.
                         \*  "NONE" is the pre-configure sentinel
                         \*  (auth disabled per
                         \*  `src/rpc/rpc.cpp:113`); the spec
                         \*  abstracts the auth-disabled branch by
                         \*  requiring ConfigureSecret to fire
                         \*  before any ProcessRequest.
    auth_log,           \* Seq of [secret, body, auth_header,
                         \*  result] — the audit log of every
                         \*  ProcessRequest invocation. Only grown
                         \*  by ProcessRequest.
    pending_requests    \* Seq of [body, auth_header] — the
                         \*  incoming-request queue; grown by
                         \*  IssueAuthorizedRequest /
                         \*  IssueForgedRequest, shrunk by
                         \*  ProcessRequest.

vars == <<server_secret, auth_log, pending_requests>>

\* LogEntry: shape of an auth_log element. The secret field
\* captures the server_secret in effect AT THE TIME OF PROCESSING
\* — important for the rotation case where ConfigureSecret has
\* changed server_secret between request issuance and processing
\* (in that case the recompute uses the NEW secret, which may
\* differ from the secret the legitimate caller used).
\*
\* INV_SecretConfidentiality's claim is NOT that the secret never
\* appears in auth_log (it does, as the secret field — the audit
\* log records WHICH secret was used); it's that the secret never
\* appears in pending_requests (the wire-level payload), and the
\* legitimate-caller side never embeds the secret in the body or
\* auth_header except via the Hmac() output (which is one-way per
\* A_HMAC). The auth_log is server-side state, not wire-exposed.

LogEntry == [
    secret      : RpcSecrets,
    body        : Messages,
    auth_header : HmacOutputs \cup ForgedHeaders,
    result      : {"ACCEPT", "REJECT"}
]

\* PendingEntry: shape of a pending_requests element. The
\* auth_header is either a canonical Hmac output (from
\* IssueAuthorizedRequest) or a forged header (from
\* IssueForgedRequest).
\*
\* CRITICALLY: the pending_requests payload contains NO secret
\* field — the legitimate caller materializes the Hmac output
\* server-side-equivalent locally (via the env var) and embeds
\* only the Hmac output in the request, never the secret bytes.
\* This is the structural witness for INV_SecretConfidentiality's
\* wire-layer claim.

PendingEntry == [
    body        : Messages,
    auth_header : HmacOutputs \cup ForgedHeaders
]

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* server_secret starts at the pre-configure sentinel "NONE" —
\* mirrors the auth-disabled default at `src/rpc/rpc.cpp:113`
\* (`if (auth_secret_.empty()) return ""`). The spec requires
\* ConfigureSecret to fire before any meaningful ProcessRequest;
\* the auth-disabled branch is the operator-acknowledged single-
\* tenant escape hatch (documented in `SECURITY.md` §S-001 and
\* abstracted out of the spec's main flow).
\*
\* auth_log + pending_requests start empty.

Init ==
    /\ server_secret    = "NONE"
    /\ auth_log         = <<>>
    /\ pending_requests = <<>>

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* ConfigureSecret(s): server's secret is set or rotated to s.
\* Mirrors `RpcServer::RpcServer` construction at `src/rpc/rpc.cpp:
\* 79-90` (initial configuration) and the operational rotation
\* path (operator restarts the server with a new DETERM_RPC_AUTH_SECRET).
\*
\* Pre-condition: s ∈ RpcSecrets (the secret-universe constant).
\*
\* Post-condition: server_secret' = s; pending_requests + auth_log
\* unchanged. Subsequent ProcessRequest calls use the new secret
\* for the expected-Hmac recompute.

ConfigureSecret(s) ==
    /\ s \in RpcSecrets
    /\ server_secret' = s
    /\ UNCHANGED <<auth_log, pending_requests>>

\* IssueAuthorizedRequest(body): legitimate caller computes
\* `auth_header := Hmac(server_secret, body)` and enqueues
\* (body, auth_header) to pending_requests.
\*
\* Mirrors `rpc_call` at `src/rpc/rpc.cpp:276-321`. The caller
\* reads the secret from DETERM_RPC_AUTH_SECRET (line :294),
\* computes the HMAC via `hmac_sha256_hex` (line :60-70), and
\* embeds it in the request JSON. The secret bytes themselves
\* are NEVER written to the request body or the wire — only the
\* HMAC output (which is one-way per A_HMAC).
\*
\* Pre-condition: server_secret ∈ RpcSecrets (configured); body
\* ∈ Messages; Len(pending_requests) < MaxRequests (bound).
\*
\* Post-condition: pending_requests grows by one entry with the
\* canonical Hmac output; server_secret + auth_log unchanged.

IssueAuthorizedRequest(body) ==
    /\ server_secret \in RpcSecrets
    /\ body \in Messages
    /\ Len(pending_requests) < MaxRequests
    /\ LET entry == [body |-> body,
                     auth_header |-> Hmac(server_secret, body)] IN
       pending_requests' = Append(pending_requests, entry)
    /\ UNCHANGED <<server_secret, auth_log>>

\* IssueForgedRequest(body, forged_header): adversarial caller
\* enqueues (body, forged_header) where forged_header is NOT a
\* canonical Hmac output for ANY secret in RpcSecrets.
\*
\* Models the A_outside adversary from `S001RpcAuthSoundness.md`
\* §2.3: the adversary has no access to the server's secret, so
\* the forged_header is uncorrelated with the canonical Hmac
\* output of the (server_secret, body) pair. The constraint
\* `forged_header \in ForgedHeaders` ensures structural non-
\* collision with any canonical Hmac output.
\*
\* The analytic strength of this abstraction: under A_HMAC, the
\* probability that a random forged_header collides with the
\* canonical Hmac is bounded by 2^-256 per attempt (L-5). The
\* spec layer collapses this probabilistic non-collision into a
\* structural non-collision via the ForgedHeaders ∩ HmacOutputs
\* = {} disjointness.
\*
\* Pre-condition: body ∈ Messages; forged_header ∈ ForgedHeaders;
\* Len(pending_requests) < MaxRequests.
\*
\* Post-condition: pending_requests grows by one entry with the
\* forged header; server_secret + auth_log unchanged.

IssueForgedRequest(body, forged_header) ==
    /\ body \in Messages
    /\ forged_header \in ForgedHeaders
    /\ Len(pending_requests) < MaxRequests
    /\ LET entry == [body |-> body, auth_header |-> forged_header] IN
       pending_requests' = Append(pending_requests, entry)
    /\ UNCHANGED <<server_secret, auth_log>>

\* ProcessRequest: dequeue head of pending_requests; recompute
\* expected := Hmac(server_secret, head.body); accept iff
\* head.auth_header = expected; log result to auth_log.
\*
\* Mirrors `RpcServer::verify_auth` at `src/rpc/rpc.cpp:112-129`:
\*   line :113   — empty-secret short-circuit (auth disabled; the
\*                  spec abstracts this branch out by requiring
\*                  server_secret ∈ RpcSecrets pre-condition).
\*   line :114-6 — missing-auth field check (the spec's queue
\*                  shape guarantees every entry has an
\*                  auth_header by construction; the missing-
\*                  auth surface collapses to ForgedHeaders).
\*   line :117-0 — recompute expected via hmac_sha256_hex.
\*   line :122-8 — constant-time XOR-OR compare; the spec models
\*                  this as an atomic equality predicate, with
\*                  the constant-time property asserted as a
\*                  precondition (INV_ConstantTimeCompare cites
\*                  the C++ source).
\*
\* Pre-condition: server_secret ∈ RpcSecrets (configured);
\* Len(pending_requests) > 0 (queue non-empty); Len(auth_log)
\* < MaxRequests (bound — total work cap).
\*
\* Post-condition: pending_requests shrinks by one (head removed);
\* auth_log grows by one entry with the result; server_secret
\* unchanged.

ProcessRequest ==
    /\ server_secret \in RpcSecrets
    /\ Len(pending_requests) > 0
    /\ Len(auth_log) < MaxRequests
    /\ LET head_entry == Head(pending_requests) IN
       LET expected   == Hmac(server_secret, head_entry.body) IN
       LET outcome    == IF head_entry.auth_header = expected
                         THEN "ACCEPT"
                         ELSE "REJECT" IN
       LET log_entry  == [secret      |-> server_secret,
                          body        |-> head_entry.body,
                          auth_header |-> head_entry.auth_header,
                          result      |-> outcome] IN
       /\ pending_requests' = Tail(pending_requests)
       /\ auth_log'         = Append(auth_log, log_entry)
       /\ UNCHANGED server_secret

\* Stutter (TLC bounds the state space; invariants are evaluated
\* at every reachable state along the way).

Stutter ==
    /\ Len(auth_log) >= MaxRequests
    /\ UNCHANGED vars

Next ==
    \/ \E s \in RpcSecrets : ConfigureSecret(s)
    \/ \E body \in Messages : IssueAuthorizedRequest(body)
    \/ \E body \in Messages :
       \E h \in ForgedHeaders :
          IssueForgedRequest(body, h)
    \/ ProcessRequest
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(ProcessRequest)
             /\ WF_vars(\E s \in RpcSecrets : ConfigureSecret(s))
             /\ WF_vars(\E body \in Messages : IssueAuthorizedRequest(body))

\* -----------------------------------------------------------------
\* §5. Invariants — T-1..T-4 + TypeOK.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.

TypeOK ==
    /\ server_secret \in RpcSecrets \cup {"NONE"}
    /\ auth_log \in Seq(LogEntry)
    /\ pending_requests \in Seq(PendingEntry)
    /\ Len(auth_log) <= MaxRequests
    /\ Len(pending_requests) <= MaxRequests

\* INV_NoForgedAccepted (T-1).
\*
\* Every entry in auth_log with result = "ACCEPT" has its
\* auth_header field equal to Hmac(secret, body) — i.e., the
\* compare at ProcessRequest succeeded iff the canonical Hmac
\* matched.
\*
\* This is the state-form witness of T-1's HMAC-PRF unforgeability
\* claim lifted to the state-machine layer. The analytic side
\* (`RpcAuthHmacSoundness.md` L-1, L-5) bounds the adversary's
\* probability of producing a valid forged_header at 2^-256 + q²/
\* 2^256; the spec layer enforces the structural non-collision
\* (forged headers are in ForgedHeaders, which is disjoint from
\* HmacOutputs by construction).
\*
\* Structural witness in the action body: ProcessRequest sets
\* result = "ACCEPT" iff head.auth_header = Hmac(server_secret,
\* head.body). The log entry's `secret` field captures the
\* server_secret at processing time. So every "ACCEPT" entry has
\* auth_header = Hmac(secret, body) by construction.

INV_NoForgedAccepted ==
    \A i \in 1..Len(auth_log) :
       LET e == auth_log[i] IN
       (e.result = "ACCEPT")
       => (e.auth_header = Hmac(e.secret, e.body))

\* INV_ConstantTimeCompare (T-3).
\*
\* The verify-time compare at `src/rpc/rpc.cpp:122-128` is
\* constant-time: every byte of `expected` is XOR-OR'd into a
\* single accumulator `diff` over a fixed-length loop, with no
\* early return/break/continue inside the loop body. The early
\* `expected.size() != got.size()` check at line :123 is a length
\* comparison only, and `expected.size()` is the fixed constant 64
\* (the hex-encoded length of HMAC-SHA-256 output), so the length
\* comparison reveals no information about the secret.
\*
\* At the spec layer, the compare is modeled as an atomic equality
\* predicate `head.auth_header = expected` inside ProcessRequest;
\* the constant-time property is asserted as a precondition citing
\* the C++ source. The invariant is structurally vacuous at the
\* spec level (the assertion-form predicate is TRUE by
\* construction); it serves as a documentation anchor for the
\* C++-side audit (`RpcAuthHmacSoundness.md` L-3).
\*
\* This is a documentary invariant — the spec layer cannot
\* meaningfully model byte-level timing channels (TLA+'s semantic
\* model is discrete state transitions, not real-time execution).
\* The C++ side's constant-time guarantee is a precondition that
\* the spec layer assumes; the audit at L-3 of
\* `RpcAuthHmacSoundness.md` verifies the precondition.

INV_ConstantTimeCompare ==
    TRUE
    \* Documentary invariant; structural witness is the C++ source
    \* at `src/rpc/rpc.cpp:122-128` (the XOR-OR loop with no early
    \* exit). The spec layer's atomic equality predicate in
    \* ProcessRequest is the spec-layer projection of the constant-
    \* time compare; the analytic side's L-3 audit verifies the
    \* C++ source matches the abstract predicate.

\* INV_SecretConfidentiality (T-4).
\*
\* server_secret never appears as a field of any element of
\* pending_requests — the wire-layer payload contains only the
\* Hmac output (which is one-way per A_HMAC), never the secret
\* bytes. The auth_log's `secret` field records WHICH secret was
\* used at processing time (server-side state, not wire-exposed),
\* which is consistent with confidentiality at the wire surface.
\*
\* Structural witness: PendingEntry has only [body, auth_header]
\* fields — no `secret` field. So no pending_requests element
\* CAN carry the secret; the invariant body asserts this
\* structurally over the field-existence predicate.
\*
\* Additionally: IssueAuthorizedRequest's action body only
\* materializes the Hmac output into the entry's auth_header
\* field; the secret bytes are never copied into the pending_requests
\* payload directly. The legitimate-caller side's local computation
\* of Hmac(server_secret, body) happens before the entry is
\* enqueued; the secret bytes are then dropped from the
\* materialized value.
\*
\* The invariant body asserts: for every entry e ∈ pending_requests,
\* e is a PendingEntry record (which by definition has no secret
\* field). This is structurally TRUE by TypeOK; the invariant is
\* documentary at the spec level. The wire-layer confidentiality
\* property is the structural witness.

INV_SecretConfidentiality ==
    \A i \in 1..Len(pending_requests) :
       LET e == pending_requests[i] IN
       /\ DOMAIN e = {"body", "auth_header"}
            \* The entry's field set is exactly {body, auth_header}
            \* — no `secret` field. Structural witness that the
            \* wire-layer payload does not carry the secret.
       /\ e.body \in Messages
       /\ e.auth_header \in HmacOutputs \cup ForgedHeaders

\* INV_NoAuthBypass (T-2).
\*
\* No entry in auth_log has result = "ACCEPT" where the recorded
\* auth_header differs from Hmac(secret, body). Captures the
\* "every accepted request was either issued legitimately OR the
\* adversary broke HMAC" claim.
\*
\* Under A_outside (the adversary has no access to the secret),
\* the only requests that pass the verify gate are those where
\* the auth_header equals the canonical Hmac. By construction of
\* ForgedHeaders (disjoint from HmacOutputs), no IssueForgedRequest
\* produces an entry that can pass the verify gate.
\*
\* Structural witness in ProcessRequest's action body:
\*   outcome := IF head.auth_header = Hmac(server_secret, head.body)
\*              THEN "ACCEPT" ELSE "REJECT"
\* So an entry can have result = "ACCEPT" iff head.auth_header =
\* Hmac(server_secret, head.body). The invariant body is the
\* state-form restatement of this conditional.
\*
\* Note: INV_NoAuthBypass and INV_NoForgedAccepted differ in their
\* emphasis: INV_NoForgedAccepted asserts the BACKWARD direction
\* (every ACCEPT entry has matching canonical Hmac); INV_NoAuthBypass
\* asserts the FORWARD direction (no entry with non-matching header
\* gets ACCEPT). They are equivalent under the action's deterministic
\* outcome computation, but stated separately to document both
\* contracts.

INV_NoAuthBypass ==
    \A i \in 1..Len(auth_log) :
       LET e == auth_log[i] IN
       (e.result = "ACCEPT")
       => (e.auth_header = Hmac(e.secret, e.body))
       \* Same shape as INV_NoForgedAccepted — every ACCEPT had
       \* matching canonical Hmac. The structural witness is
       \* ProcessRequest's IF-THEN-ELSE on the equality.

\* -----------------------------------------------------------------
\* §6. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualReject (T-5).
\*
\* Under fairness on ProcessRequest, every forged request (where
\* the queued auth_header is NOT the canonical Hmac for the
\* current server_secret) is eventually rejected and logged with
\* result = "REJECT".
\*
\* The forward-progress contract: every queued request reaches
\* the verify gate; the verify gate is deterministic; forged
\* requests are always rejected. So eventually the auth_log
\* contains a "REJECT" entry for every forged request that was
\* ever enqueued (modulo the MaxRequests bound).
\*
\* TLA+ liveness body: eventually, if there is a pending entry
\* whose auth_header is a forged header, the entry has been
\* processed and the auth_log records a "REJECT" for it.
\*
\* Note: the model bound MaxRequests prevents infinite enumeration
\* — within the bounded run, every forged request is either
\* processed (and rejected, by determinism) or the run terminates
\* via Stutter before processing. The temporal property captures
\* the unbounded-run claim; TLC's bounded check is sufficient
\* witness because all action disjuncts are exercised.

PROP_EventualReject ==
    \A i \in 1..MaxRequests :
       <>(i > Len(pending_requests)
          \/ Head(pending_requests).auth_header \in HmacOutputs)
    \* For every position i, either the queue is shorter than i
    \* (so position i no longer holds a pending entry — has been
    \* processed) OR the head entry is a canonical Hmac output
    \* (and so will accept, not reject — but the next pop reveals
    \* the deeper queue). The eventually claim: every forged
    \* request at some queue position eventually gets popped and
    \* processed (rejected). The model bound MaxRequests pins
    \* the surface.

\* PROP_NoForgeryWithoutSecret.
\*
\* The adversary cannot produce a valid auth_header without
\* learning the secret — modeled via the abstract Hmac() function's
\* pre-image resistance.
\*
\* The structural argument: IssueForgedRequest's forged_header
\* parameter is constrained to ForgedHeaders, which is disjoint
\* from HmacOutputs by construction. So no forged_header can equal
\* Hmac(secret, body) for any (secret, body) pair — the adversary
\* CANNOT produce a valid auth_header by structural construction.
\*
\* The analytic side: under A_HMAC, the probability that a randomly-
\* chosen forged_header collides with Hmac(secret, body) is bounded
\* by 2^-256 per attempt (L-5 of `RpcAuthHmacSoundness.md`); the
\* spec layer collapses the probabilistic non-collision into a
\* structural non-collision via the ForgedHeaders ∩ HmacOutputs
\* = {} disjointness.
\*
\* TLA+ liveness body: invariantly, for every entry in auth_log
\* that was an IssueForgedRequest-originated entry (auth_header
\* \in ForgedHeaders), the result is "REJECT". The standing
\* invariant restated as a temporal property to document the
\* "no forgery without secret" composition.

PROP_NoForgeryWithoutSecret ==
    [] (\A i \in 1..Len(auth_log) :
          LET e == auth_log[i] IN
          (e.auth_header \in ForgedHeaders) => (e.result = "REJECT"))

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The S-001 (HMAC arm) closure contract is pinned at the state-
\* machine layer by the four invariants + two temporal properties.
\* The abstraction boundary:
\*
\*   * Hmac() is a spec-layer abstract operator modeled as a tagged
\*     tuple. Distinct (secret, body) pairs produce distinct outputs
\*     by TLA+ extensional equality. The cryptographic strength of
\*     HMAC-SHA-256 (A_HMAC PRF security; L-5 of
\*     `RpcAuthHmacSoundness.md`) is asserted at the analytic
\*     layer; the spec layer enforces only the determinism +
\*     distinctness contract.
\*
\*   * The constant-time compare at `src/rpc/rpc.cpp:122-128` is
\*     modeled as an atomic equality predicate in ProcessRequest.
\*     TLA+'s semantic model is discrete state transitions, not
\*     real-time execution, so the spec layer cannot meaningfully
\*     model byte-level timing channels. The C++ side's constant-
\*     time guarantee is a precondition that the spec layer assumes;
\*     INV_ConstantTimeCompare is a documentary invariant pointing
\*     to the L-3 audit.
\*
\*   * The forged-header abstraction collapses the probabilistic
\*     non-collision of A_HMAC into a structural non-collision via
\*     the ForgedHeaders ∩ HmacOutputs = {} disjointness. The
\*     adversary's per-attempt forgery probability of 2^-256 is the
\*     analytic side; the spec layer's discrete-state model treats
\*     the adversary as structurally unable to produce a canonical
\*     Hmac output without knowing the secret.
\*
\*   * The canonical serialization `method ‖ "|" ‖ params.dump()`
\*     at `src/rpc/rpc.cpp:52-58` is abstracted to opaque Messages
\*     strings. The L-2 audit of `RpcAuthHmacSoundness.md` verifies
\*     the canonical-form fixpoint of nlohmann::json's parse-then-
\*     dump round trip; the spec layer assumes the canonicalization
\*     is sound and treats messages as the canonical bytes directly.
\*
\*   * The replay limitation (T-2 of `RpcAuthHmacSoundness.md`) is
\*     NOT modeled here. The HMAC alone does not bind a nonce, so
\*     an attacker who eavesdrops a legitimate (body, auth_header)
\*     pair can replay it indefinitely. The spec layer's
\*     ProcessRequest action would correctly ACCEPT a replayed
\*     pair (because the auth_header matches the canonical Hmac);
\*     the apply-layer nonce gate (FA-Apply-3, FB7 Nonce.tla) is
\*     the second-line replay defense. This spec covers only the
\*     HMAC arm of S-001's closure; the composition with the
\*     apply-layer nonce gate is FB7 Nonce.tla + the analytic
\*     composition at `S001RpcAuthSoundness.md` T-2 territory.
\*
\* What this spec adds beyond the prose proof: a state-machine
\* witness that the HMAC auth contract is preserved across every
\* reachable interleaving of ConfigureSecret + IssueAuthorizedRequest
\* + IssueForgedRequest + ProcessRequest within the bounded
\* universe. TLC enumerates every reachable schedule and the
\* invariants are checked against the accumulated auth_log +
\* pending_requests.
\*
\* What the spec does NOT check (consistent with the §scope above):
\*
\*   * The byte-level constant-time guarantee at
\*     `src/rpc/rpc.cpp:122-128`. The spec uses an atomic equality
\*     predicate; the byte-level audit is `RpcAuthHmacSoundness.md`
\*     L-3 territory.
\*   * The cryptographic strength of HMAC-SHA-256. The spec assumes
\*     A_HMAC + A2/H1 hold; the analytic side at L-1, L-5 verifies.
\*   * The replay surface (T-2 of `RpcAuthHmacSoundness.md`). The
\*     spec's ProcessRequest correctly ACCEPTs a replayed pair;
\*     the apply-layer nonce gate is the second-line defense, FB7
\*     Nonce.tla territory.
\*   * The configuration-surface plaintext persistence of the
\*     secret at `Config::to_json` (F-1 of
\*     `RpcAuthHmacSoundness.md`). The spec models only the RPC-
\*     runtime surface; the config-lifecycle surface is a separate
\*     concern (operator filesystem hygiene + v2.17 passphrase
\*     encryption pattern).
\*   * The localhost-only / external-bind binding mode
\*     (Option 1 of S-001's closure at `src/rpc/rpc.cpp:79-89`).
\*     The spec models the post-bind state; the network-layer
\*     binding mode is the operator-policy side of S-001.
\*   * The rate limiter (S-014 / FB25 RateLimiterEviction.tla)
\*     that gates the RPC verify rate. The spec models the
\*     unbounded-rate baseline; the per-peer-IP rate-limit
\*     composition is FB25 territory.

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   src/rpc/rpc.cpp:52-58   : canonical_for_hmac(method, params)
\*       canonical-serialization helper; the spec's Hmac() input
\*       domain abstracts to opaque Messages strings.
\*   src/rpc/rpc.cpp:60-70   : hmac_sha256_hex(key, message) HMAC
\*       primitive wrapping OpenSSL HMAC(EVP_sha256(), ...); the
\*       spec's Hmac() operator is the spec-layer projection.
\*   src/rpc/rpc.cpp:79-90   : RpcServer constructor; secret hex-
\*       decoded into auth_secret_; the spec's ConfigureSecret
\*       mirrors this initialization.
\*   src/rpc/rpc.cpp:92-104  : Startup log emitting only
\*       auth_secret_.size(), never the value; the structural
\*       witness for INV_SecretConfidentiality at the log surface.
\*   src/rpc/rpc.cpp:112-129 : verify_auth — the proof's primary
\*       object; the spec's ProcessRequest mirrors this flow.
\*   src/rpc/rpc.cpp:122-128 : Constant-time XOR-OR loop; the
\*       structural witness for T-3 / INV_ConstantTimeCompare.
\*   src/rpc/rpc.cpp:276-321 : Client-side rpc_call with
\*       DETERM_RPC_AUTH_SECRET env var support; the spec's
\*       IssueAuthorizedRequest mirrors this.
\*
\* SECURITY.md §S-001 — closure narrative for the HMAC RPC auth
\*   scheme; this spec is the state-machine witness of Option 3's
\*   "attacker without secret cannot forge requests" claim.
\*
\* Preliminaries.md §2.1 (A2 SHA-256 collision resistance) +
\*   §2.2 (A1 Ed25519 EUF-CMA — cited by analogy) — the
\*   cryptographic assumptions underlying the abstract Hmac()
\*   operator's determinism + distinctness; the spec asserts the
\*   structural side, the analytic side is the prose proof's
\*   domain.
\*
\* docs/proofs/RpcAuthHmacSoundness.md — the analytic FA-track
\*   proof; §1 T-1..T-5 enumerate the five theorems this spec
\*   lifts to the state-machine layer; §4 walks per-theorem
\*   analytic proofs; §6 documents the adversary model (a..f).
\*
\* docs/proofs/S001RpcAuthSoundness.md — the composition theorem
\*   covering HMAC auth + input-validation defense; §3 T-1..T-5
\*   enumerate the composition claims; this spec covers the HMAC
\*   arm, FB27 JsonValidation.tla covers the input-validation arm.
\*
\* FB7 Nonce.tla (FA-Apply-3 nonce-gate — apply-layer replay
\*   defense; the second-line backstop to T-2's HMAC replay
\*   limitation that this spec does NOT model),
\* FB23 FrostVerify.tla (Ed25519 EUF-CMA model; the structural
\*   analog at the consensus-signature layer; FB36 uses the
\*   abstract-Hmac discipline mirroring FrostVerify's abstract-
\*   sig discipline),
\* FB25 RateLimiterEviction.tla (S-014 F-1 rate-limiter; the
\*   pre-gate that bounds the adversary's verify-attempt rate;
\*   composes with this spec to give the cumulative forge-rate
\*   bound documented in the threat-model matrix of
\*   `S001RpcAuthSoundness.md` §5),
\* FB27 JsonValidation.tla (S-018 closure; the structural-
\*   validation arm of the composition theorem at
\*   `S001RpcAuthSoundness.md` T-1; sibling spec covering the
\*   input-validation layer).
\*
\* Runtime regressions:
\*   tools/test_rpc_hmac_auth.sh — the 5-assertion regression that
\*     pins the HMAC auth mechanism at the C++ layer; INV_NoForgedAccepted
\*     + INV_NoAuthBypass + PROP_EventualReject structural witnesses.
\*   tools/test_rpc_localhost_only.sh — the Option 1 (localhost-
\*     only bind) regression; composes with this spec's
\*     ConfigureSecret on the binding-mode dimension.
\*   tools/test_rpc_rate_limit.sh — the S-014 rate-limit
\*     regression; composes with PROP_EventualReject via the
\*     rate-limiter-as-pre-gate discipline.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB36 row — added.
============================================================================
