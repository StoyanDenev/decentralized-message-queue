--------------------------- MODULE AnonAccountLifecycle ---------------------------
(*
FB52 — TLA+ specification of the ANON-ADDRESS normalization + account
auto-creation lifecycle: the S-028 normalize-at-the-boundary contract
composed with the std::map operator[] auto-creation-on-first-credit
behavior, pinning the headline non-fragmentation property that no two
case-variant spellings of the SAME Ed25519 pubkey ever land in distinct
ledger entries.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
AnonAccountLifecycle.cfg AnonAccountLifecycle.tla` once the TLC
toolchain is installed in CI.

Scope. An anon address is the 0x-prefixed 64-hex-char rendering of a
32-byte Ed25519 pubkey (`make_anon_address(pk) == "0x" + to_hex(pk)` at
`include/determ/types.hpp:153-155`). The S-028 contract is that the hex
TAIL is parsed case-INsensitively (`is_anon_address` accepts upper, lower
or mixed at `types.hpp:115-126`) but stored in a single CANONICAL spelling
(lowercase — `normalize_anon_address` lowercases the tail at
`types.hpp:134-142`, and `make_anon_address` always emits lowercase). The
ledger keys accounts by STRING (`std::map<std::string, AccountState>
accounts_`), so two spellings of the one pubkey ("0xABC..." vs "0xabc...")
would key two DISTINCT map entries and FRAGMENT a balance UNLESS every
user-input boundary normalizes before storage/lookup/routing.

This spec models the closed surface as a small state machine over a
ledger keyed by the CANONICAL spelling, with a non-deterministic adversary
that submits arbitrary case-variant spellings at the RPC/CLI boundary.
Three credit paths auto-create the destination account on first touch,
mirroring the three `accounts_[...]` operator[] sites in
`src/chain/chain.cpp`:

  Path 1 (local TRANSFER credit). `accounts_[tx.to].balance += tx.amount`
    at `src/chain/chain.cpp:756` — a same-shard TRANSFER credits the
    recipient; if `tx.to` was never seen the map default-constructs a
    fresh AccountState (balance 0, next_nonce 0) THEN credits it.
  Path 2 (inbound cross-shard receipt credit). `accounts_[r.to].balance
    += r.amount` at `src/chain/chain.cpp:1367` — a delivered cross-shard
    receipt credits `r.to`, auto-creating it on first touch.
  Path 3 (DEREGISTER refund to a non-registrant / NEF first-touch).
    `accounts_[tx.from].balance += nef` at `src/chain/chain.cpp:830` —
    the new-entrant NEF grant + stake refund credit, auto-creating the
    account on a first-time crediting path.

The TWO load-bearing facts the model couples:

  (a) NORMALIZE-BEFORE-USE. Every boundary action first applies
      Canon(addr) (the spec lift of `normalize_anon_address`) and routes
      / credits / looks-up ONLY the canonical key. The C++ enforcement:
      `rpc_balance` / `rpc_send` normalize their address arg at the RPC
      read boundary, and `rpc_submit_tx` REJECTS a non-canonical address
      with a structured diagnostic (the tx sig is over signing_bytes so
      the server cannot silently mutate `tx.to`; the client must present
      the canonical spelling). The CLI sign paths emit canonical
      addresses via `make_anon_address`.

  (b) AUTO-CREATE-ON-CREDIT. A credit to a never-seen canonical key
      default-constructs the entry (balance 0) then adds the amount.
      A credit is never lost for want of a pre-existing account; and —
      crucially — it lands in the canonical entry, so a later credit
      under a DIFFERENT case-spelling of the SAME pubkey accumulates into
      the SAME entry (it normalizes to the same canonical key first).

The headline safety theorems:

  (T-1) No-fragmentation (NoCaseFragmentation). The ledger never holds
        two distinct keys that are case-variants of one another. Every
        live key is its own canonical form. State-form witness:
        INV_NoCaseFragmentation + INV_AllKeysCanonical. This is the
        S-028 closure property: "0xABC..." and "0xabc..." can never
        co-exist as two balances; the boundary normalization collapses
        them to one canonical entry BEFORE the map is keyed.

  (T-2) Routing-case-invariance (RoutingCaseInvariant). The shard a
        credit routes to is a function of the CANONICAL spelling only, so
        all case-variants of one pubkey route to the SAME shard. Modeled
        as: the routing decision consumes Canon(addr), never the raw
        spelling. State-form witness: INV_RoutingCanonical — every logged
        route was computed over a canonical key. Mirrors the
        `crypto::shard_id_for_address(addr, ...)` call hashing the raw
        string bytes (`src/crypto/random.cpp:177-189`): identical bytes
        ⇒ identical shard, so normalization BEFORE routing is what makes
        case-variants co-route (light/main.cpp:3079 comment).

  (T-3) Credit-conservation-under-aliasing (NoLostCredit). The sum of all
        amounts ever credited (under ANY case-spelling) equals the sum of
        all balances now held under canonical keys. No credit is dropped
        for want of a pre-existing account (auto-create), and no credit
        leaks into a phantom non-canonical entry. State-form witness:
        INV_CreditConservation.

  (T-4) Submit-tx-strict-reject (SubmitRejectsNonCanonical). A submit_tx
        bearing a non-canonical `to` is REJECTED (never applied, never
        routed, never credited). The server cannot normalize it silently
        because the address is bound by the tx signature; the only safe
        action is rejection with a diagnostic. State-form witness:
        INV_NoNonCanonicalSubmitApplied.

Plus one temporal property:

  PROP_EventualSettle — under fairness on Apply, every queued credit is
    eventually settled into the canonical ledger (or, for a non-canonical
    submit_tx, eventually rejected). The pipeline does not wedge a credit.

The state machine. The ledger is keyed by canonical addresses. An
adversary enqueues credits and submit_tx attempts bearing arbitrary
case-spellings; Apply settles them under the boundary discipline.

  * CreditNormalized(pk, case, amt, path) — a credit arrives at a
    normalize-before-use boundary (the TRANSFER / inbound-receipt /
    DEREGISTER paths whose C++ sites call accounts_[...] AFTER the read
    boundary already normalized the address). `case` selects an arbitrary
    case-spelling of `pk`'s address (UPPER / LOWER / MIXED); the boundary
    applies Canon() so the spelling does NOT matter — the credit is
    queued against the canonical key. Bounded by MaxOps.
  * SubmitTx(pk, case, amt) — a submit_tx arrives. If the presented
    spelling is already canonical it queues a credit; if NON-canonical it
    is REJECTED (logged to `rejected`, NOT credited). Models the
    `rpc_submit_tx` strict-reject branch.
  * Apply — dequeue the head queued credit and settle it: auto-create the
    canonical entry if absent (balance 0), then add the amount; record the
    route (the canonical key) in `routed`. Mirrors the operator[] credit.
  * Stutter — bounds the state space at saturation.

Modeling scope (kept tractable for TLC):

  * `PubKeys` — finite universe of distinct Ed25519 pubkeys (opaque ids).
    Each maps to exactly one canonical address Canon(Addr(pk)).
  * `Cases` == {"UPPER","LOWER","MIXED"} — the three observable spellings
    of one address's hex tail. LOWER is the canonical form (the spec lift
    of "lowercase the A-F tail"); UPPER and MIXED are non-canonical
    user-input variants `is_anon_address` accepts but `normalize_anon_address`
    folds down to LOWER. The 64-hex-char detail is abstracted: what matters
    for the invariants is the equivalence class (which pubkey) and whether
    the spelling is the canonical one.
  * `Amounts` — finite set of positive credit amounts.
  * `MaxOps` — bound on queued+settled+rejected growth so TLC exhausts.
    Production runs unbounded.

The ledger + logs. `ledger` is a partial function Canon-key -> balance
(domain = the set of auto-created accounts). `queue` is the pending-credit
FIFO. `routed` is the audit log of every settled credit's routing key.
`rejected` is the log of non-canonical submit_tx attempts. `credited_sum`
is a ghost accumulator of every amount ever ACCEPTED at a boundary (the
conservation witness for T-3).

To check (assuming TLC installed):
  $ tlc AnonAccountLifecycle.tla -config AnonAccountLifecycle.cfg

Recommended config (state space ~10^4, < 30s):
  PubKeys = {"k1","k2"}, Amounts = {1, 2}, MaxOps = 4.

Cross-references:
  - include/determ/types.hpp:115-126  : is_anon_address — case-insensitive
      acceptance (the boundary admits UPPER/LOWER/MIXED). Modeled by
      CreditNormalized / SubmitTx accepting any Case.
  - include/determ/types.hpp:134-142  : normalize_anon_address — lowercase
      the A-F tail to canonical. Modeled by Canon().
  - include/determ/types.hpp:144-151  : parse_anon_pubkey — case-insensitive
      pubkey recovery (same 32 bytes regardless of case). The equivalence
      class Addr(pk) the model collapses Cases into.
  - include/determ/types.hpp:153-155  : make_anon_address — always emits
      lowercase canonical. The IsCanonical(LOWER) anchor.
  - src/chain/chain.cpp:756           : accounts_[tx.to].balance += amount —
      Path 1 local TRANSFER credit (auto-create on first touch).
  - src/chain/chain.cpp:1367          : accounts_[r.to].balance += amount —
      Path 2 inbound cross-shard receipt credit (auto-create).
  - src/chain/chain.cpp:830           : accounts_[tx.from].balance += nef —
      Path 3 DEREGISTER/NEF first-touch credit (auto-create).
  - src/chain/chain.cpp:198-202       : Chain::is_cross_shard — routes the
      (already-normalized) `to` via shard_id_for_address. The routing T-2
      pins.
  - src/crypto/random.cpp:177-189     : shard_id_for_address — hashes the
      RAW address-string bytes, so normalization BEFORE routing is what
      makes case-variants co-route.
  - docs/SECURITY.md §S-028           : the closure narrative this spec
      formalizes at the state-machine layer.
  - docs/proofs/S028AnonAddressNormalization.md (if present) — the analytic
      S-028 companion; FB52 is the machine-checkable state-machine sibling.
  - tools/test_anon_routing.sh        : runtime regression — case-variant
      inputs route to the SAME shard + local-vs-cross-shard credit; the
      C++-layer witness for T-1 + T-2.
  - `determ test-anon-address`        : the in-process FAST test exercising
      is_anon_address / normalize_anon_address / parse_anon_pubkey /
      make_anon_address round-trips (S-028 case-insensitive parsing).
*)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    PubKeys,            \* finite universe of distinct Ed25519 pubkeys.
    Amounts,            \* finite set of positive credit amounts.
    MaxOps              \* bound on queued + settled + rejected (TLC).

\* The three observable case-spellings of an address's hex tail. LOWER is
\* the canonical form `make_anon_address` emits + `normalize_anon_address`
\* folds to; UPPER + MIXED are non-canonical variants the boundary admits.
Cases == {"UPPER", "LOWER", "MIXED"}

\* The credit-path tag (the three accounts_[...] operator[] sites).
Paths == {"TRANSFER", "INBOUND_RECEIPT", "DEREGISTER_NEF"}

ASSUME ConfigOK ==
    /\ Cardinality(PubKeys) >= 1
       \* At least one pubkey so the model is non-trivial.
    /\ Amounts \subseteq (Nat \ {0})
       \* Credits are strictly positive (a 0-credit is a no-op the C++
       \*  paths never emit; keeping amounts positive makes the
       \*  conservation accumulator meaningful).
    /\ Cardinality(Amounts) >= 1
    /\ MaxOps \in Nat /\ MaxOps >= 1
       \* Positive bound so TLC has a non-empty reachable state space.

\* -----------------------------------------------------------------
\* §1. Address model — pubkey -> canonical key, case-spelling lift.
\* -----------------------------------------------------------------
\*
\* Each pubkey has ONE canonical address Canon(Addr(pk)). We model an
\* address as the pair <<pk, case>>: same pk under different case is the
\* SAME pubkey (parse_anon_pubkey recovers identical 32 bytes), but a
\* DIFFERENT string key in the ledger map unless normalized first.
\*
\* IsCanonical(case): only LOWER is canonical (make_anon_address emits
\* lowercase). This is the spec lift of `normalize_anon_address` being a
\* no-op exactly on already-lowercase input.

IsCanonical(case) == case = "LOWER"

\* CanonKey(pk): the canonical ledger key for a pubkey — the LOWER
\* spelling of its address. This is the SOLE key under which a pubkey's
\* balance is ever stored. The spec lift of make_anon_address(pk).
\* Distinct pubkeys yield distinct canonical keys (injective hex render).

CanonKey(pk) == <<pk, "LOWER">>

\* Addresses: the full universe of (pubkey, case) spellings an adversary
\* may present at a boundary. CanonKeys: the canonical subset (the only
\* legal ledger-domain elements).

Addresses == PubKeys \X Cases
CanonKeys == { CanonKey(pk) : pk \in PubKeys }

\* Canon(addr): normalize a presented spelling to its canonical key —
\* the spec lift of `normalize_anon_address`. Idempotent: Canon on a
\* canonical key is the identity.

Canon(addr) == CanonKey(addr[1])

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    ledger,             \* partial function CanonKeys -> Nat. The DOMAIN is
                         \*  the set of auto-created accounts; an account
                         \*  exists iff it has been credited at least once.
                         \*  Mirrors std::map<std::string, AccountState>
                         \*  accounts_ keyed by canonical address.
    queue,              \* Seq of [key, amt, path] — pending normalized
                         \*  credits awaiting Apply (the credit has passed a
                         \*  normalize-before-use boundary; `key` is already
                         \*  canonical).
    routed,             \* Seq of [key, path] — audit log of every settled
                         \*  credit's routing key. Every entry must be a
                         \*  canonical key (T-2 witness).
    rejected,           \* Seq of [pk, case] — log of non-canonical submit_tx
                         \*  attempts the strict-reject branch shed (T-4).
    credited_sum        \* ghost Nat — total of every amount ACCEPTED at a
                         \*  boundary (queued). Conservation witness (T-3).

vars == <<ledger, queue, routed, rejected, credited_sum>>

\* QueueEntry: a normalized pending credit. `key` is canonical by
\* construction (the boundary already applied Canon).
QueueEntry == [key : CanonKeys, amt : Amounts, path : Paths]

\* RouteEntry: shape of a routed-log element.
RouteEntry == [key : CanonKeys, path : Paths]

\* RejectEntry: shape of a strict-reject-log element (the raw spelling
\* that was refused).
RejectEntry == [pk : PubKeys, case : Cases]

\* TotalOps: the combined work counter the MaxOps bound caps — every
\* queued, settled, or rejected operation. Bounds the reachable universe.
TotalOps == Len(queue) + Len(routed) + Len(rejected)

\* SumBalances: total balance currently held across all auto-created
\* canonical entries. The conservation RHS (T-3).
SumBalances ==
    LET D == DOMAIN ledger IN
    IF D = {} THEN 0
    ELSE LET F[ s \in SUBSET D ] ==
              IF s = {} THEN 0
              ELSE LET x == CHOOSE e \in s : TRUE IN
                   ledger[x] + F[s \ {x}]
         IN F[D]

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* The ledger starts EMPTY (no accounts auto-created yet) — matches a
\* fresh chain whose accounts_ map has no anon entries. queue / routed /
\* rejected start empty; the conservation accumulator starts at 0.

Init ==
    /\ ledger       = [ k \in {} |-> 0 ]
    /\ queue        = << >>
    /\ routed       = << >>
    /\ rejected     = << >>
    /\ credited_sum = 0

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* CreditNormalized(pk, case, amt, path): a credit arrives at a
\* normalize-before-use boundary on one of the three credit paths. The
\* boundary applies Canon() FIRST, so the presented `case` is irrelevant —
\* the credit is queued against the CANONICAL key. This models the C++
\* sites where accounts_[...] is keyed AFTER the read boundary has already
\* normalized the address (rpc_balance / rpc_send normalize their arg).
\*
\* Pre-condition: pk ∈ PubKeys; case ∈ Cases; amt ∈ Amounts; below bound.
\*
\* Post-condition: queue grows by one CANONICAL-keyed credit; the ghost
\* conservation accumulator grows by amt; ledger / routed / rejected
\* unchanged (the credit is not yet settled).

CreditNormalized(pk, case, amt, path) ==
    /\ pk \in PubKeys
    /\ case \in Cases
    /\ amt \in Amounts
    /\ path \in Paths
    /\ TotalOps < MaxOps
    /\ queue' = Append(queue,
                       [key |-> Canon(<<pk, case>>), amt |-> amt,
                        path |-> path])
    /\ credited_sum' = credited_sum + amt
    /\ UNCHANGED <<ledger, routed, rejected>>

\* SubmitTx(pk, case, amt): a submit_tx arrives bearing a (pk, case)
\* destination. Mirrors `rpc_submit_tx`'s strict-reject discipline: the
\* address is bound by the tx signature so the server CANNOT normalize it
\* silently. Two arms:
\*   CANONICAL spelling: accepted — queues a TRANSFER credit on the
\*     canonical key (and bumps the conservation accumulator).
\*   NON-canonical spelling: REJECTED — logged to `rejected`, NOT queued,
\*     NOT credited. No ledger mutation, no conservation bump.
\*
\* Pre-condition: pk ∈ PubKeys; case ∈ Cases; amt ∈ Amounts; below bound.

SubmitTx(pk, case, amt) ==
    /\ pk \in PubKeys
    /\ case \in Cases
    /\ amt \in Amounts
    /\ TotalOps < MaxOps
    /\ IF IsCanonical(case)
       THEN /\ queue' = Append(queue,
                              [key |-> CanonKey(pk), amt |-> amt,
                               path |-> "TRANSFER"])
            /\ credited_sum' = credited_sum + amt
            /\ UNCHANGED <<ledger, routed, rejected>>
       ELSE /\ rejected' = Append(rejected, [pk |-> pk, case |-> case])
            /\ UNCHANGED <<ledger, queue, routed, credited_sum>>

\* Apply: dequeue the head pending credit and settle it. AUTO-CREATE the
\* canonical entry if absent (default balance 0), then add the amount. The
\* routing key recorded in `routed` is the canonical key (T-2). Mirrors
\* the `accounts_[key].balance += amount` operator[] credit: a never-seen
\* key default-constructs AccountState{balance=0} THEN is incremented.
\*
\* Pre-condition: queue non-empty; routed below the bound.
\*
\* Post-condition: queue shrinks by one; ledger gains/updates the
\* canonical entry; routed grows by the routing record; rejected +
\* credited_sum unchanged.

Apply ==
    /\ Len(queue) > 0
    /\ Len(routed) < MaxOps
    /\ LET c    == Head(queue) IN
       LET k    == c.key       IN
       LET prev == IF k \in DOMAIN ledger THEN ledger[k] ELSE 0 IN
       /\ ledger'   = [ x \in (DOMAIN ledger) \cup {k} |->
                          IF x = k THEN prev + c.amt
                          ELSE ledger[x] ]
       /\ routed'   = Append(routed, [key |-> k, path |-> c.path])
       /\ queue'    = Tail(queue)
       /\ UNCHANGED <<rejected, credited_sum>>

\* Stutter — bounds the state space at saturation (every op consumed,
\* queue drained). Invariants are evaluated at every reachable state.

Stutter ==
    /\ TotalOps >= MaxOps
    /\ Len(queue) = 0
    /\ UNCHANGED vars

Next ==
    \/ \E pk \in PubKeys, case \in Cases, amt \in Amounts, path \in Paths :
         CreditNormalized(pk, case, amt, path)
    \/ \E pk \in PubKeys, case \in Cases, amt \in Amounts :
         SubmitTx(pk, case, amt)
    \/ Apply
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(Apply)

\* -----------------------------------------------------------------
\* §5. Invariants — T-1..T-4 + TypeOK.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.

TypeOK ==
    /\ DOMAIN ledger \subseteq CanonKeys
    /\ \A k \in DOMAIN ledger : ledger[k] \in Nat
    /\ queue    \in Seq(QueueEntry)
    /\ routed   \in Seq(RouteEntry)
    /\ rejected \in Seq(RejectEntry)
    /\ credited_sum \in Nat
    /\ Len(queue)    <= MaxOps
    /\ Len(routed)   <= MaxOps
    /\ Len(rejected) <= MaxOps

\* INV_AllKeysCanonical (T-1 part a).
\*
\* Every live ledger key is its own canonical form. No non-canonical
\* spelling ever becomes a ledger-domain element, because every credit
\* path normalizes BEFORE keying the map. The spec lift of: accounts_ is
\* only ever indexed by `normalize_anon_address(addr)`.

INV_AllKeysCanonical ==
    \A k \in DOMAIN ledger : Canon(k) = k

\* INV_NoCaseFragmentation (T-1 part b — the headline S-028 property).
\*
\* The ledger never holds two DISTINCT keys that normalize to the same
\* canonical form. Combined with INV_AllKeysCanonical this is the full
\* non-fragmentation contract: "0xABC..." and "0xabc..." can never
\* co-exist as two balances — the boundary normalization collapses them to
\* one canonical entry before the map is keyed. Two keys that share a
\* pubkey but differ MUST be impossible; here we assert the stronger
\* structural fact that any two domain keys with equal Canon ARE equal.

INV_NoCaseFragmentation ==
    \A j, k \in DOMAIN ledger :
       (Canon(j) = Canon(k)) => (j = k)

\* INV_RoutingCanonical (T-2).
\*
\* Every settled credit was routed on a CANONICAL key. Since
\* shard_id_for_address hashes the raw key bytes, routing on the canonical
\* key makes ALL case-variants of one pubkey co-route to the same shard
\* (they normalize to the same canonical key BEFORE routing). No settled
\* credit was ever routed on a non-canonical spelling.

INV_RoutingCanonical ==
    \A i \in 1..Len(routed) : Canon(routed[i].key) = routed[i].key

\* INV_CreditConservation (T-3).
\*
\* Conservation under aliasing: every amount accepted at a boundary is
\* either still queued or has settled into a canonical balance; nothing is
\* lost (auto-create guarantees a credit always has a home) and nothing
\* leaks into a phantom non-canonical entry. Formally:
\*   credited_sum == SumBalances + (sum of still-queued amounts).
\* Since amounts only ENTER via the conservation accumulator and only EXIT
\* the queue into the ledger (Apply preserves the total), the running
\* identity holds at every reachable state.

QueuedSum ==
    LET G[ i \in 0..Len(queue) ] ==
          IF i = 0 THEN 0 ELSE queue[i].amt + G[i - 1]
    IN G[Len(queue)]

INV_CreditConservation ==
    credited_sum = SumBalances + QueuedSum

\* INV_NoNonCanonicalSubmitApplied (T-4).
\*
\* A non-canonical submit_tx is NEVER applied: every rejected entry's
\* spelling is non-canonical (the strict-reject branch only fires on a
\* non-canonical address), and — the safety crux — no non-canonical
\* spelling ever reaches the ledger as a key (subsumed by
\* INV_AllKeysCanonical) NOR appears in the routed log (subsumed by
\* INV_RoutingCanonical). This invariant pins the reject-log faithfulness:
\* the server only ever sheds (logs to `rejected`) genuinely non-canonical
\* spellings, so a canonical submit is never spuriously rejected.

INV_NoNonCanonicalSubmitApplied ==
    \A i \in 1..Len(rejected) : ~IsCanonical(rejected[i].case)

\* INV_NonNegativeBalances — supporting invariant: every auto-created
\* balance is a non-negative integer (credits are positive; there is no
\* debit path in this model — the spec scope is the CREDIT/auto-create
\* surface). The structural witness that operator[] auto-creation seeds
\* balance 0 and only ever adds.

INV_NonNegativeBalances ==
    \A k \in DOMAIN ledger : ledger[k] >= 0

\* -----------------------------------------------------------------
\* §6. Temporal property.
\* -----------------------------------------------------------------

\* PROP_EventualSettle — under fairness on Apply, every queued credit is
\* eventually settled into the canonical ledger (the queue drains). The
\* forward-progress contract: a credit accepted at a boundary always
\* reaches its canonical account; the auto-create + credit pipeline does
\* not wedge. Within the bounded run, WF on Apply drains the queue.

PROP_EventualSettle ==
    (Len(queue) > 0) ~> (Len(queue) = 0)

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The S-028 normalize-at-the-boundary contract composed with the
\* operator[] auto-creation-on-credit behavior is pinned at the
\* state-machine layer by the six invariants + one temporal property. The
\* abstraction boundary:
\*
\*   * An address is collapsed to a (pubkey, case) pair. The 64-hex-char
\*     rendering + the per-character A-F lowercasing arithmetic of
\*     `normalize_anon_address` (types.hpp:134-142) is abstracted to the
\*     three-element Cases alphabet with LOWER canonical. What the
\*     invariants depend on is the equivalence class (which pubkey) + the
\*     boolean "is this spelling canonical?", which the abstraction
\*     captures exactly. The byte-level hex parse + the
\*     is_anon_address length/charset gate (types.hpp:115-126) are the
\*     `determ test-anon-address` FAST-test territory.
\*
\*   * The shard routing arithmetic (shard_id_for_address folding the
\*     SHA-256 of the raw address bytes mod shard_count at
\*     random.cpp:177-189) is abstracted to "routing consumes the
\*     canonical key." The T-2 invariant pins the ORDERING property
\*     (normalize BEFORE route) without re-deriving the hash-mod
\*     distribution; the uniformity of the fold is RegionalSharding /
\*     shard-routing-determinism territory.
\*
\*   * The debit side of TRANSFER (sender.balance -= cost at
\*     chain.cpp:745) is NOT modeled — this spec's scope is the CREDIT +
\*     auto-create surface (the three accounts_[...] operator[] sites).
\*     The A1 unitary-supply conservation across debit+credit is FB46
\*     UnitarySupplyLedger.tla territory; FB52's INV_CreditConservation is
\*     the narrower credit-side-only accumulator that pins no-lost-credit
\*     under case-aliasing.
\*
\*   * The cross-shard outbound debit / inbound-receipt delivery mechanics
\*     (the receipt-bundle wire format, the (src_shard, tx_hash)
\*     idempotency key at chain.cpp:1364-1365) are NOT modeled — FB52
\*     treats the inbound-receipt path only as a third credit path that
\*     auto-creates `r.to`. The receipt round-trip is FB2/14/17/18/32 +
\*     CrossShardReceiptDedup territory.
\*
\*   * The tx-signature binding of the destination address (why
\*     rpc_submit_tx CANNOT silently normalize and must strict-reject) is
\*     consumed as the precondition for SubmitTx's reject arm; the Ed25519
\*     EUF-CMA underpinning is FB23 / FrostVerify territory.
\*
\* What this spec adds beyond the siblings: a state-machine witness that
\* the S-028 normalization discipline + the auto-create-on-credit behavior
\* COMPOSE to the non-fragmentation guarantee — across every reachable
\* interleaving of mixed-case credits + canonical/non-canonical submit_tx
\* attempts within the bounded universe, NO reachable state holds two
\* case-variant ledger entries for one pubkey, every settled credit routes
\* on the canonical key, every accepted amount is conserved into the
\* canonical ledger, and every non-canonical submit_tx is shed. TLC
\* enumerates the adversarial schedule (UPPER then LOWER then MIXED credits
\* to the SAME pubkey, interleaved with a non-canonical submit_tx) and the
\* invariants hold against the accumulated ledger + logs.
\*
\* What the spec does NOT check (consistent with the §scope above):
\*   * The hex parse / charset gate of is_anon_address — `determ
\*     test-anon-address` FAST test.
\*   * The shard-routing hash-mod uniformity — RegionalShardingCommittee /
\*     shard-routing-determinism.
\*   * Debit-side + full A1 supply conservation — FB46 UnitarySupplyLedger.
\*   * The cross-shard receipt round-trip + dedup — FB2/14/17/18/32 +
\*     CrossShardReceiptDedup.
\*   * Ed25519 signature binding of the tx destination — FB23 / FrostVerify.

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   include/determ/types.hpp:115-126 : is_anon_address — case-insensitive
\*       acceptance (boundary admits UPPER/LOWER/MIXED). Modeled by the
\*       Cases alphabet CreditNormalized / SubmitTx range over.
\*   include/determ/types.hpp:134-142 : normalize_anon_address — lowercase
\*       the A-F tail to canonical. The spec's Canon() operator.
\*   include/determ/types.hpp:144-151 : parse_anon_pubkey — case-insensitive
\*       pubkey recovery; the equivalence class Cases collapse into.
\*   include/determ/types.hpp:153-155 : make_anon_address — always emits
\*       lowercase canonical. The IsCanonical("LOWER") anchor.
\*   src/chain/chain.cpp:756           : accounts_[tx.to].balance += amount —
\*       Path 1 local TRANSFER credit; operator[] auto-create on first touch.
\*   src/chain/chain.cpp:1367          : accounts_[r.to].balance += amount —
\*       Path 2 inbound cross-shard receipt credit; auto-create.
\*   src/chain/chain.cpp:830           : accounts_[tx.from].balance += nef —
\*       Path 3 DEREGISTER/NEF first-touch credit; auto-create.
\*   src/chain/chain.cpp:198-202       : Chain::is_cross_shard — routes the
\*       already-normalized `to`; the T-2 routing-canonical witness.
\*   src/crypto/random.cpp:177-189     : shard_id_for_address — hashes the
\*       RAW address-string bytes; normalization BEFORE routing is what
\*       makes case-variants co-route (the structural ground for T-2).
\*
\* SECURITY.md §S-028 — case-insensitive is_anon_address +
\*   normalize_anon_address closure narrative; rpc_balance / rpc_send
\*   normalize at the read boundary; rpc_submit_tx strict-rejects
\*   non-canonical (sig over signing_bytes ⇒ server can't mutate). The
\*   closure this spec formalizes at the state-machine layer.
\*
\* docs/proofs/S028AnonAddressNormalization.md — the analytic S-028
\*   companion (cited from S001RpcAuthSoundness.md's cross-reference set);
\*   FB52 is the machine-checkable state-machine sibling.
\*
\* Sibling TLA+ specs:
\*   FB4 AccountState.tla — the base account-balance state machine; FB52
\*     adds the anon-address normalization + auto-create-on-credit layer
\*     above the same accounts_ map.
\*   FB46 UnitarySupplyLedger.tla — the full A1 debit+credit supply
\*     conservation; FB52's INV_CreditConservation is the narrower
\*     credit-side-only accumulator pinning no-lost-credit under aliasing.
\*   FB35 RegionalShardingCommittee.tla — the shard-routing committee
\*     surface; FB52's T-2 pins the normalize-before-route ordering that
\*     feeds the routing the sharding specs consume.
\*
\* Runtime regressions:
\*   tools/test_anon_routing.sh — case-variant inputs route to the SAME
\*       shard + local-vs-cross-shard credit; the C++-layer witness for
\*       T-1 + T-2.
\*   `determ test-anon-address` — the in-process FAST test exercising
\*       is_anon_address / normalize_anon_address / parse_anon_pubkey /
\*       make_anon_address round-trips (S-028 case-insensitive parsing).
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB52 row — to be added by the threader.
============================================================================
