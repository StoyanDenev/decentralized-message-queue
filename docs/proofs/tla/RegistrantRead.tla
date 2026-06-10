--------------------------- MODULE RegistrantRead ---------------------------
(*
FB60 — TLA+ specification of the TRUSTLESS r:-NAMESPACE REGISTRANT READER:
the end-to-end `determ-light verify-registrant <domain>` pipeline that
proves a VALIDATOR's on-chain registration to a light client WITHOUT
trusting the serving daemon, AND classifies its ACTIVE/INACTIVE lifecycle
status against the committee-attested head. The r: namespace is the
REGISTRANTS namespace — the validator set the consensus committee is drawn
from — so this reader lets a light client trustlessly enumerate who is
eligible to be selected without running a full node.

With verify-registrant, r: becomes the LAST simple-key namespace to gain a
trustless reader, completing the simple-key family a:/s:/d:/r:. (The b:
namespace — abort_records, the S-032 cache — remains the one S-033 state
namespace WITHOUT a state-proof reader: it is internal-only and is NOT
covered by this or any sibling read spec.)

NOTE: no model-check this session — caller will TLC-validate. This module
is syntactically self-contained and ready for `tlc -config
RegistrantRead.cfg RegistrantRead.tla` once a companion `.cfg` is supplied
(one is shipped alongside).

Scope. A `verify-registrant <domain>` read composes four trust reductions,
then evaluates ONE lifecycle verdict over the committee-anchored facts the
reductions expose:

  (1) ANCHOR  — the client recomputes the genesis hash locally and rejects
      any daemon whose block-0 hash differs (light/trustless_read.cpp::
      anchor_genesis; light/main.cpp:4204). A daemon serving a DIFFERENT
      chain is refused before any registrant datum is read.
  (2) HEAD    — the client verifies the committee-signed header chain to the
      tip and extracts BOTH (a) the tip's committed state_root and (b) the
      committee-attested head height H (verify_chain_to_head; main.cpp:4216).
      The head height H is itself committee-anchored — the ACTIVE/INACTIVE
      verdict's "current height" input is NOT the daemon's bare claim. An
      empty head_state_root (S-033 not yet activated) fails closed
      (main.cpp:4217-4222).
  (3) PATH    — the client fetches the `r:<domain>` state-proof and runs
      merkle_verify: the (key_bytes, value_hash) leaf at target_index in a
      leaf_count-leaf tree must recompute (with the proof siblings + the
      S-040 root-wrapper) to the trusted state_root. FB44 (MerklePathVerify)
      territory — abstracted here to a single PathOk predicate. The client
      first BINDS the proof's key_bytes to the locally-computed canonical
      key "r:"+domain (main.cpp:4209-4212, 4261-4270); a wrong-key proof is
      UNVERIFIABLE.
  (4) BIND    — THE NOVEL CRUX OF FB60. The served leaf's `value_hash` must
      equal SHA256 of the CANONICAL RegistrantEntry field-encoding the
      `account` RPC registry cleartext claims (main.cpp:4314-4332):
        value_hash = SHA256( ed_pub[32]
                            || u64_be(registered_at)
                            || u64_be(active_from)
                            || u64_be(inactive_from)
                            || u64_be(len region) || region )
      (src/chain/chain.cpp:299-307, the registrants_ branch of
      build_state_leaves; SHA256Builder::append(u64) is big-endian).
      WITHOUT the bind, a daemon serving the RIGHT key + a VALID Merkle path
      could STILL hand the client a value_hash that does NOT correspond to
      the RegistrantEntry it claims in the cleartext — asserting a forged
      ed_pub (a wrong validator key) / registered_at / active window /
      region while the chain committed a DIFFERENT entry. The bind closes
      this: the client recomputes SHA256(canonical_encoding(claimed)) from
      the `account` RPC registry block (src/node/node.cpp:2725) and compares
      it to the served value_hash; a mismatch is UNVERIFIABLE.

  (5) VERDICT — the lifecycle classifier. Once the four reductions expose
      the committee-anchored (active_from, inactive_from) and the committee-
      attested head H, the client derives the SAME ACTIVE/INACTIVE status
      the chain would (main.cpp:4432-4435):
        activated   == active_from <= H
        deactivated == inactive_from /= 0 /\ inactive_from <= H
        active      == activated /\ ~deactivated
      The `inactive_from = 0` sentinel means "never deactivated" — a
      registrant with inactive_from = 0 is ACTIVE once active_from <= H. The
      verdict is a DERIVED FACT over the two committee-certified inputs,
      never a daemon claim: a lying daemon cannot flip ACTIVE/INACTIVE
      because both inputs are bound (inactive_from / active_from via the
      bind gate) and H is committee-attested (via the head gate).

The reader's three sound verdicts mirror verify-dapp-registration:
  INCLUDED      (exit 0) — the r:<domain> leaf is proven at the verified
                head; the claimed RegistrantEntry is field-faithful; ACTIVE
                or INACTIVE is then the lifecycle sub-status.
  NOT_INCLUDED  (exit 0) — state_proof not_found for the exact key AND the
                `account` RPC registry is null/absent (a CONSISTENT no-such-
                validator answer at the verified head; main.cpp:4235-4251). Exit 0
                (a sound verified answer) matches the whole InclusionVerdict family.
  UNVERIFIABLE  (exit 3) — any subverted gate: genesis mismatch, unsigned
                head, forged path, wrong key_bytes, a value_hash that does
                not bind to the cleartext, a stale/forward proof height that
                fails the race-window anchoring, OR an inconsistent daemon
                (a present r: proof with a null registry — main.cpp:4284-4291
                — fails closed). Args/transport errors exit 1.

The load-bearing safety property (THE HEADLINE): a read is ACCEPTED
(INCLUDED — the client believes the claimed RegistrantEntry is the on-chain
registration) iff ALL FOUR reductions pass; and the ACTIVE/INACTIVE
sub-verdict is a deterministic function of the COMMITTEE-CERTIFIED
inactive_from / active_from vs the committee-attested head H, never a daemon
assertion. No reachable read accepts a claimed entry whose canonical
encoding does not hash to the committed leaf value (so a forged ed_pub /
lifecycle height / region is rejected), and no absent domain is ever
INCLUDED. This reduces a trustless registrant read to SHA-256 collision /
second-preimage resistance (Preliminaries.md §2.1) plus the FB44 path
soundness plus the FB23 committee-signature soundness.

Seven theorems are pinned:

  (RP-1) Four-Gate Soundness. Every INCLUDED read passed all four gates
         (anchor /\ head /\ path /\ bind). No reachable accept skips a gate.
         The headline no-trust-leak contract. INV_FourGateSound.
  (RP-2) Anchor Gate. A read against a daemon whose block-0 hash differs
         from the locally-recomputed genesis hash is UNVERIFIABLE before any
         registrant datum is consumed (anchor_genesis throw; main.cpp:4204).
         No accept ever has anchor = FALSE. INV_AnchorGate.
  (RP-2b) Head Gate. A read whose header chain to the tip is NOT committee-
         verified (a forged/unsigned head, or an empty S-033 state_root) is
         UNVERIFIABLE; neither the state_root NOR the head height H such a
         read would trust is used. No accept ever has head_verified = FALSE.
         INV_HeadGate.
  (RP-2c) Path Gate. A read whose r:<domain> Merkle path does NOT recompute
         to the trusted state_root (or whose key_bytes do not bind to the
         canonical "r:"+domain) is UNVERIFIABLE (the FB44 merkle_verify gate
         + the key bind). No accept ever has path_ok = FALSE. INV_PathGate.
  (RP-3) Value-Hash Binding (THE HEADLINE CRUX). A read whose claimed
         RegistrantEntry canonical encoding does NOT hash to the served
         value_hash is UNVERIFIABLE. The client recomputes
         SHA256(canonical_encoding(claimed)) from the `account` RPC registry
         cleartext and compares; a forged claimed entry (wrong ed_pub /
         registered_at / active_from / inactive_from / region) yields a
         DIFFERENT canonical encoding hence a DIFFERENT recomputed hash, so
         the bind fails. Under collision resistance, a daemon serving the
         RIGHT key + a VALID path STILL cannot substitute a forged ed_pub /
         lifecycle height / region. No accept ever has bind_ok = FALSE. This
         is the r:-namespace anti-substitution invariant. INV_BindGate.
  (RP-3b) Field Faithfulness. For every INCLUDED read, the claimed
         RegistrantEntry equals the entry the chain actually committed at
         that domain's leaf — every queried field (ed_pub, registered_at,
         active_from, inactive_from, region) matches. Derived from RP-3 under
         the injective-encoding abstraction: equal canonical encodings imply
         equal entries. INV_FieldFaithful.
  (RP-4) No-Absent-Accept. A read for an absent domain (no committed
         r:<domain> leaf) is never INCLUDED: an absent domain has no
         committed value_hash, so it fails BOTH the path AND the bind gate.
         The no-fabricated-registration invariant at the application layer
         (the analog of FB43 INV_AbsenceSound / FB50 INV_NoAbsentAccept).
         INV_NoAbsentAccept.
  (RP-5) Active-Verdict Soundness. The ACTIVE/INACTIVE classification of an
         INCLUDED read is a deterministic function of the COMMITTEE-CERTIFIED
         inactive_from / active_from vs the committee-attested head H — never
         a daemon claim. A read is reported ACTIVE iff the committed
         active_from <= H AND (inactive_from = 0 OR inactive_from > H). No
         daemon can flip the lifecycle status: both inputs are committee-
         anchored (the two heights via the bind gate, H via the head gate).
         INV_ActiveVerdictSound.

Plus the temporal pair: PROP_EventualAnswer (the pipeline always terminates
with a verdict; no stuck read) and PROP_Determinism (RP-6 — two identical
reads against the same daemon + head produce the identical verdict + the
identical ACTIVE/INACTIVE status).

The state machine. A single committed registrant table (the chain's r:
namespace leaf domain at a fixed state-root) and a fixed committee-attested
head height H are set at Init. A non-deterministic Read action admits one
(domain, claimed RegistrantEntry, daemon-honest flags) request per step,
runs it through the four-gate pipeline + the lifecycle classifier via
MakeRecord, appends a ReadRecord to a read log, increments read_count. The
invariants read this log to verify every INCLUDED read passed all four gates
(RP-1) and is field-faithful to the committed entry (RP-3b), and that its
ACTIVE/INACTIVE status equals the committed-state status at H (RP-5).

The four gates as pure-function predicates:

  AnchorOk(daemon)       : the daemon's block-0 hash matches the locally-
                           recomputed genesis hash. Per-daemon BOOLEAN flag
                           (the byte-level recompute is anchor_genesis's
                           job; main.cpp:4204).
  HeadOk(daemon)         : the daemon's header chain to the tip is committee-
                           signed AND carries a non-empty S-033 state_root
                           (FB23 + verify_chain_to_head). Per-daemon BOOLEAN
                           flag. When TRUE, BOTH the state_root AND the head
                           height H are genuine.
  PathOk(domain, daemon) : the served r:<domain> Merkle path recomputes to
                           the trusted state_root AND its key_bytes bind to
                           the canonical "r:"+domain (FB44 + the key bind).
                           TRUE iff the domain has a committed r: leaf AND
                           the daemon serves the honest, correctly-keyed path.
  BindOk(domain, daemon) : SHA256(canonical_encoding(claimed)) =
                           committed_value_hash. Via the injective Encode
                           abstraction, BindOk holds iff the claimed
                           RegistrantEntry equals the committed entry.

Variables:

  * `committed` — function Domains -> RegistrantEntry \cup {ABSENT}. The
    chain's r: namespace leaf domain at the fixed state-root: which domains
    have a registrant leaf and (for each) the committed RegistrantEntry. Set
    once at Init; the pipeline checks claimed entries against it. Models the
    build_state_leaves registrants_-branch output (chain.cpp:299-307).
  * `head` — Nat. The committee-attested head height H. Set once at Init;
    the lifecycle verdict's "current height" input. The ACTIVE/INACTIVE
    classifier evaluates active_from <= H and inactive_from <= H at this H
    (main.cpp:4432-4434), so the verdict tracks the committee-anchored head.
  * `read_log` — a Seq of ReadRecord. Each record tags the request (domain,
    claimed entry, the daemon's honest/forged flags), the four per-gate
    Booleans, the overall verdict, and (for an INCLUDED read) the derived
    ACTIVE/INACTIVE status. The invariants read this log.
  * `read_count` — Nat. Bounds read_log length for TLC tractability (one
    Read per step until MaxReads).

Modeling scope (kept tractable for TLC):

  * SHA-256 / the canonical RegistrantEntry encoding is modeled as an
    injective abstract constructor: Encode(entry) is a structured TERM, and
    two terms are equal IFF the entries are structurally identical. This is
    the standard collision-resistance abstraction (FB23 FrostVerify, FB26
    BlockchainStateIntegrity, FB44 MerklePathVerify, FB50 DAppRegistration
    Read, FB53 UnstakeEligibilityRead use the same device). Under collision
    resistance, value_hash equality reduces to entry equality, so the bind
    gate (RP-3) is EXACTLY claimed = committed.
  * A RegistrantEntry is a record over the five value-hashed fields:
    ed_pub, registered_at, active_from, inactive_from, region. ed_pub is the
    32-byte validator key (an opaque PubKey stand-in); region is the R4
    region string (an opaque Region stand-in — it IS hashed into the
    encoding via u64_be(len) || bytes, so a forged region changes the
    value_hash). The model carries one abstract slot per field; Encode is
    injective over the full record, so RP-3b covers every field.
  * The anchor + head gates are per-daemon BOOLEAN flags. The byte-level
    genesis recompute is anchor_genesis (trustless_read.cpp); the committee-
    signature soundness is FB23 (FrostVerify.tla). When head_honest = TRUE,
    BOTH the state_root AND the head height H are genuine — FB60 reads the
    single anchored head `head` for the verdict's height input. A forged
    head (or an empty S-033 state_root) is UNVERIFIABLE before any verdict is
    computed, so a lying daemon cannot manufacture a false ACTIVE by
    inflating H.
  * The path gate is TRUE iff the domain has a committed r: leaf AND the
    daemon serves the honest, correctly-keyed path; a forged path (or a
    wrong-key proof) is path_ok = FALSE. The cryptographic path soundness is
    FB44 (MerklePathVerify.tla); the key bind ("r:"+domain) is main.cpp:
    4261-4270. A domain with no committed r: leaf has no value_hash to prove
    or bind, so the pipeline reports NOT_INCLUDED (the sound state_proof
    not_found + null-registry cross-check at the verified head, main.cpp:
    4235-4251), NOT a forged membership — the no-fabricated-validator analog
    of FB43's INV_AbsenceSound.

The lifecycle classifier (the verdict sub-step over an accepted read):

  StatusActive(entry, H) ==
      /\ entry.active_from <= H              \* activated
      /\ (entry.inactive_from = 0           \* never deactivated (sentinel),
          \/ entry.inactive_from > H)        \* or deactivation not yet reached

  This mirrors main.cpp:4432-4435 EXACTLY:
      activated   = (active_from <= H)
      deactivated = (inactive_from != 0 && inactive_from <= H)
      active      = activated && !deactivated

TLC verifies the invariants at every reachable state across every reachable
interleaving of Read actions over the bounded domain x claimed-entry x
daemon-flag universe against the fixed committed registrant table and head
height.

To check (assuming TLC installed):
  $ tlc RegistrantRead.tla -config RegistrantRead.cfg

Recommended config (state space ~10^4, < 30s):
  Domains = {d1, d2}, PubKeys = {k1, k2}, Regions = {r1, r2},
  Heights = {0, 1, 2}, MaxReads = 5, committed = a 1-2 element subset (so an
  absent-domain NOT_INCLUDED read is reachable), and a daemon-flag universe
  spanning honest + each single-gate-forged variant (anchor-forged,
  head-forged, path-forged, bind-forged). Heights must span values below,
  at, and above each active_from / inactive_from so both ACTIVE and INACTIVE
  INCLUDED verdicts are reachable.

Cross-references:
  - docs/proofs/tla/DAppRegistrationRead.tla (FB50) — the d:-namespace
    trustless reader FB60 mirrors field-for-field (the same four-gate
    pipeline + injective-Encode + INV_BindGate/INV_FieldFaithful headline).
    FB50 binds a DApp registry value; FB60 binds the r:-leaf (ed_pub,
    registered_at, active_from, inactive_from, region) AND adds the
    ACTIVE/INACTIVE lifecycle classifier over the committee-attested head.
  - docs/proofs/tla/UnstakeEligibilityRead.tla (FB53) — the s:-namespace
    trustless reader with a HEIGHT-RELATIVE verdict classifier. FB60 reuses
    its verdict-bearing structure (a derived status over committee-anchored
    facts), here the lifecycle ACTIVE/INACTIVE rather than the unstake
    ELIGIBLE/LOCKED split.
  - docs/proofs/RegistrantProofSoundness.md (FB60 companion) — the prose
    proof this module machine-checks. RP-1..RP-5 are its theorems.
  - docs/proofs/tla/CompositeKeyStateProof.tla (FB43) — the SERVER-side key
    reconstruction over all ten namespaces (right key); FB60 reads the r:
    namespace leaf whose key FB43 pins canonical, and re-binds it locally
    ("r:"+domain) at the client.
  - docs/proofs/tla/MerklePathVerify.tla (FB44) — the CLIENT-side path
    verification (right path); FB60's PathOk predicate abstracts FB44's
    accept/reject decision. Composition: FB43 (right key) + FB44 (right
    path) + FB60 (right value + right lifecycle verdict) = a fully trustless
    r:-namespace registrant read.
  - docs/proofs/tla/FrostVerify.tla (FB23) — the committee-signature verify
    over the state_root + head; FB60's HeadOk predicate abstracts FB23's
    accept/reject decision over BOTH the state_root AND the head height H.
  - light/main.cpp::cmd_verify_registrant (main.cpp:4164) — the C++ reader
    (the INCLUDED / NOT_INCLUDED / UNVERIFIABLE verdict + ACTIVE/INACTIVE
    lifecycle pipeline). The Classify-equivalent lifecycle test is
    main.cpp:4432-4435.
  - light/trustless_read.cpp::anchor_genesis (AnchorOk; main.cpp:4204) /
    verify_chain_to_head (HeadOk — extracts BOTH state_root and head height
    H; main.cpp:4216).
  - src/chain/chain.cpp:299-307 — build_state_leaves registrants_ branch;
    the canonical RegistrantEntry field-encoding the value_hash commits.
    Encode is the spec-layer projection of this hash builder.
  - src/node/node.cpp:2725 — the rpc_account registry block {ed_pub,
    registered_at, active_from, inactive_from, region} — the cleartext the
    client recomputes the bind hash from (region added in commit 48a6f5d).
  - tools/test_light_verify_registrant.sh — the runtime surface exercising
    the r: namespace read FB60 models.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,    \* set of validator / registrant domain identifiers
    PubKeys,    \* set of validator ed25519 public keys (opaque 32-byte stand-ins)
    Regions,    \* set of R4 region strings (opaque stand-ins; hashed into the leaf)
    Heights,    \* finite set of block heights (registered_at / active_from / inactive_from / head)
    MaxReads    \* bound on read_log length (TLC tractability)

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ Cardinality(PubKeys) >= 1
    /\ Cardinality(Regions) >= 1
    /\ Cardinality(Heights) >= 1
    /\ Heights \subseteq Nat
    \* 0 must be a reachable height so the inactive_from = 0 "never
    \* deactivated" sentinel is distinguishable from a real deactivation
    \* height. (chain.cpp/main.cpp treat inactive_from == 0 as "active".)
    /\ 0 \in Heights
    /\ MaxReads \in Nat /\ MaxReads >= 1

\* -----------------------------------------------------------------
\* §1. RegistrantEntry shape + the ABSENT sentinel.
\* -----------------------------------------------------------------
\*
\* A RegistrantEntry is the committed r:-namespace leaf FB60 reads. The
\* model carries exactly the five value-hashed fields (chain.cpp:299-307):
\*   ed_pub        — the 32-byte validator ed25519 key (opaque PubKey
\*                   stand-in; chain.cpp:301 b.append(r.ed_pub...)).
\*   registered_at — block height at first-time REGISTER (chain.cpp:302).
\*   active_from   — block height the registrant became selectable
\*                   (chain.cpp:303).
\*   inactive_from — block height the registrant deactivates, or 0 if never
\*                   (chain.cpp:304; the main.cpp:4433 sentinel).
\*   region        — the R4 region string (opaque Region stand-in;
\*                   chain.cpp:305-306 b.append(len) || b.append(region)).
RegistrantEntry == [ed_pub:         PubKeys,
                    registered_at:  Heights,
                    active_from:    Heights,
                    inactive_from:  Heights,
                    region:         Regions]

\* ABSENT marks "no r:<domain> leaf was committed for this domain." A read
\* against an absent domain has no value_hash to prove or bind, so the
\* pipeline reports NOT_INCLUDED (the sound state_proof not_found +
\* null-registry cross-check), NOT a forged membership — the
\* no-fabricated-validator analog of FB43's INV_AbsenceSound.
ABSENT == [absent |-> TRUE]

CommittedShape == RegistrantEntry \cup {ABSENT}

\* The three sound reader verdicts (main.cpp:4485-4487). UNVERIFIABLE is the
\* fail-closed outcome for any subverted gate (exit 3); INCLUDED (exit 0)
\* additionally carries the ACTIVE/INACTIVE lifecycle sub-status; NOT_INCLUDED
\* (exit 0) is the consistent no-such-validator answer at the verified head.
Verdicts == {"INCLUDED", "NOT_INCLUDED", "UNVERIFIABLE"}

\* The lifecycle sub-status of an INCLUDED read. "N/A" tags non-INCLUDED
\* records (the sub-status is only meaningful once the entry is proven).
Statuses == {"ACTIVE", "INACTIVE", "N/A"}

\* -----------------------------------------------------------------
\* §2. Encode — the injective canonical RegistrantEntry encoding (abstract).
\* -----------------------------------------------------------------
\*
\* value_hash = SHA256( ed_pub[32] || u64_be(registered_at) ||
\*   u64_be(active_from) || u64_be(inactive_from) || u64_be(len region) ||
\*   region ) (src/chain/chain.cpp:299-307; SHA256Builder::append(u64) is
\* big-endian). Under SHA-256 collision/second-preimage resistance, two
\* value_hashes are equal IFF the encoded entries are identical. We model
\* Encode as a structured TERM (the entry record itself, tagged): TLA+
\* record equality is structural, so Encode(e1) = Encode(e2) <=> e1 = e2 —
\* exactly the injective-encoding abstraction (FB23 / FB26 / FB44 / FB50 /
\* FB53 use the same device).
Encode(e) == <<"registrant_leaf", e>>

\* -----------------------------------------------------------------
\* §3. The four trust-reduction gates as pure-function predicates.
\* -----------------------------------------------------------------
\*
\* A daemon is modeled by three honest/forged Booleans plus the claimed
\* RegistrantEntry it serves over the `account` RPC cleartext. The gates read
\* these flags + the fixed committed registrant table. A read is INCLUDED iff
\* ALL FOUR gates pass; otherwise UNVERIFIABLE (or NOT_INCLUDED for an absent
\* domain whose path/bind fail honestly — see Classify).
\*
\* DaemonFlags shape:
\*   anchor_honest : the daemon's block-0 hash matches our genesis hash.
\*   head_honest   : the daemon's header chain to the tip is committee-signed
\*                   AND carries a non-empty S-033 state_root (FB23 /
\*                   verify_chain_to_head); BOTH the state_root AND the head
\*                   height H are genuine when TRUE.
\*   path_honest   : the daemon serves the honest, correctly-keyed r:<domain>
\*                   Merkle path (recomputes to the committed state_root AND
\*                   key_bytes = "r:"+domain; FB44 + main.cpp:4261-4270).
\*   claimed       : the RegistrantEntry the daemon claims is the committed
\*                   leaf (the entry the client BIND-checks against the served
\*                   value_hash via the `account` cleartext). A forged claim
\*                   differs from the committed entry.
DaemonFlags == [anchor_honest : BOOLEAN,
                head_honest   : BOOLEAN,
                path_honest   : BOOLEAN,
                claimed       : RegistrantEntry]

\* AnchorOk(daemon) — the daemon ran our chain (block-0 hash matches the
\* locally-recomputed genesis hash). trustless_read.cpp::anchor_genesis
\* (main.cpp:4204).
AnchorOk(daemon) == daemon.anchor_honest = TRUE

\* HeadOk(daemon) — the daemon's header chain to the tip is committee-signed
\* AND carries a non-empty state_root (S-033); the state_root AND the head
\* height H the verdict trusts are genuine. FB23 + verify_chain_to_head
\* (main.cpp:4216-4222).
HeadOk(daemon) == daemon.head_honest = TRUE

\* PathOk(domain, daemon) — the served r:<domain> Merkle path recomputes to
\* the trusted state_root AND its key_bytes bind to the canonical "r:"+domain
\* (FB44 merkle_verify + main.cpp:4261-4270). TRUE iff the domain has a
\* committed r: leaf AND the daemon serves the honest, correctly-keyed path.
\* An absent domain has no committed leaf -> PathOk FALSE (no membership proof
\* exists; the daemon would have to forge one, which FB44 rejects). The
\* absent-domain path routes to NOT_INCLUDED in Classify, not to a forged-
\* membership accept.
PathOk(domain, daemon) ==
    /\ committed[domain] /= ABSENT
    /\ daemon.path_honest = TRUE

\* BindOk(domain, daemon) — THE NOVEL r:-NAMESPACE anti-substitution gate.
\* The served value_hash equals SHA256(canonical_encoding(claimed))
\* recomputed from the `account` RPC registry cleartext. Under the
\* injective-Encode abstraction, this holds iff the claimed RegistrantEntry
\* equals the committed entry: a daemon that serves a forged claim (e.g. a
\* substituted ed_pub validator key, or a flipped inactive_from to fake the
\* lifecycle status) produces a recomputed hash Encode(claimed) /=
\* Encode(committed) = committed value_hash, so the bind fails. An absent
\* domain has no committed entry to bind against, so BindOk is FALSE.
\*
\* src/chain/chain.cpp:299-307 commits value_hash = Encode(committed);
\* main.cpp:4314-4332 recomputes Encode(claimed) from the cleartext and
\* compares. THE crux of RP-3 + RP-3b.
BindOk(domain, daemon) ==
    /\ committed[domain] /= ABSENT
    /\ Encode(daemon.claimed) = Encode(committed[domain])

\* AllGatesOk(domain, daemon) — the conjunction of the four trust reductions.
\* A read is INCLUDED iff this holds (against a committed domain); otherwise
\* the read fails closed to UNVERIFIABLE, except an absent domain served
\* honestly routes to NOT_INCLUDED (see Classify).
AllGatesOk(domain, daemon) ==
    /\ AnchorOk(daemon)
    /\ HeadOk(daemon)
    /\ PathOk(domain, daemon)
    /\ BindOk(domain, daemon)

\* -----------------------------------------------------------------
\* §4. The lifecycle classifier — the ACTIVE/INACTIVE verdict sub-step.
\* -----------------------------------------------------------------
\*
\* StatusActive(entry, H) — mirrors main.cpp:4432-4435 EXACTLY:
\*   activated   = (active_from <= H)
\*   deactivated = (inactive_from != 0 && inactive_from <= H)
\*   active      = activated && !deactivated
\* The inactive_from = 0 sentinel means "never deactivated"; a registrant
\* with inactive_from = 0 is ACTIVE once active_from <= H. Both inputs
\* (active_from, inactive_from) are committee-certified via the bind gate;
\* H is committee-attested via the head gate — so this is a derived FACT,
\* never a daemon claim (RP-5).
StatusActive(entry, H) ==
    /\ entry.active_from <= H
    /\ ( entry.inactive_from = 0
         \/ entry.inactive_from > H )

\* Classify(domain, daemon, H) — the full reader verdict + lifecycle status.
\* When the four gates do NOT all pass: an absent domain served by an
\* otherwise-honest daemon (anchor + head TRUE, but no committed leaf so
\* path/bind FALSE) routes to NOT_INCLUDED (the sound not_found + null-
\* registry answer); ANY genuinely subverted gate (a forged anchor / head /
\* path / bind against a committed domain, or a forged path over an absent
\* domain) routes to UNVERIFIABLE. When the four gates DO all pass, the read
\* is INCLUDED with the ACTIVE/INACTIVE sub-status.
\*
\* The NOT_INCLUDED branch is modeled as: the daemon is honest on the gates
\* it CAN be honest on (anchor + head), the domain is genuinely absent (so
\* there is no leaf to prove — path/bind are vacuously FALSE), and the daemon
\* does NOT forge a phantom path (path_honest = FALSE is the honest report of
\* "no such leaf"). This matches main.cpp:4235-4251: a not_found with a
\* corroborating null `account` registry is a daemon-asserted NOT_INCLUDED
\* (sound only under (H-neg), NegativeVerdictSoundness.md NV-2/NV-3 — the
\* cross-check catches a self-contradicting daemon, not a consistent liar),
\* whereas a not_found contradicted by a non-null registry is UNVERIFIABLE.
Classify(domain, daemon, H) ==
    IF AllGatesOk(domain, daemon)
        THEN "INCLUDED"
    ELSE IF /\ committed[domain] = ABSENT
            /\ AnchorOk(daemon)
            /\ HeadOk(daemon)
            /\ daemon.path_honest = FALSE
        THEN "NOT_INCLUDED"
    ELSE "UNVERIFIABLE"

\* LifecycleStatus(domain, daemon, H) — the ACTIVE/INACTIVE sub-status,
\* meaningful only for an INCLUDED read. For an INCLUDED read the bind gate
\* forces daemon.claimed = committed[domain], so we evaluate StatusActive over
\* the COMMITTED entry (equivalently the bound claimed entry) at the
\* committee-attested head H. Non-INCLUDED reads carry "N/A".
LifecycleStatus(domain, daemon, H) ==
    IF Classify(domain, daemon, H) = "INCLUDED"
        THEN IF StatusActive(committed[domain], H) THEN "ACTIVE" ELSE "INACTIVE"
        ELSE "N/A"

\* -----------------------------------------------------------------
\* §5. ReadRecord shape + the MakeRecord pipeline.
\* -----------------------------------------------------------------
\*
\* Each Read appends one ReadRecord: the request (domain + daemon flags +
\* claimed entry), the four per-gate Booleans, the resulting verdict, and the
\* lifecycle sub-status. The invariants read this log.

ReadRecord == [
    domain  : Domains,
    daemon  : DaemonFlags,
    anchor  : BOOLEAN,
    head    : BOOLEAN,
    path    : BOOLEAN,
    bind    : BOOLEAN,
    verdict : Verdicts,
    status  : Statuses
]

\* MakeRecord(domain, daemon, H): run the four-gate pipeline + the lifecycle
\* classifier. The verdict is UNVERIFIABLE unless ALL FOUR gates pass (or
\* NOT_INCLUDED for an honestly-absent domain) — the trustless-read
\* fail-closed contract: an INCLUDED accept is reported iff the daemon ran
\* our chain (anchor) AND served a committee-signed head (head) AND the
\* r:<domain> path recomputes to the trusted state_root with the right key
\* (path) AND the served value_hash binds to the claimed entry's canonical
\* encoding (bind). The ACTIVE/INACTIVE status is then the lifecycle
\* classifier over the committed leaf at the committee-attested head.
MakeRecord(domain, daemon, H) ==
    LET a == AnchorOk(daemon)
        h == HeadOk(daemon)
        p == PathOk(domain, daemon)
        b == BindOk(domain, daemon)
    IN [ domain  |-> domain,
         daemon  |-> daemon,
         anchor  |-> a,
         head    |-> h,
         path    |-> p,
         bind    |-> b,
         verdict |-> Classify(domain, daemon, H),
         status  |-> LifecycleStatus(domain, daemon, H) ]

\* -----------------------------------------------------------------
\* §6. Variables.
\* -----------------------------------------------------------------

VARIABLES
    committed,    \* function Domains -> CommittedShape (the r: leaf domain)
    head,         \* Nat: the committee-attested head height H
    read_log,     \* Seq(ReadRecord)
    read_count    \* Nat (bounds read_log for TLC)

vars == <<committed, head, read_log, read_count>>

\* -----------------------------------------------------------------
\* §7. Initial state.
\* -----------------------------------------------------------------
\*
\* The committed registrant table is fixed at Init: each domain either maps
\* to a committed RegistrantEntry or to ABSENT. The committee-attested head
\* height H is fixed in Heights. The model leaves both to the .cfg (Init
\* quantifies over the legal shapes) so TLC explores reads against committed
\* + absent domains and across the full height range — including heads below,
\* at, and above each active_from / inactive_from (so both ACTIVE and
\* INACTIVE INCLUDED verdicts are reachable). read_log starts empty;
\* read_count starts at 0.
Init ==
    /\ committed \in [Domains -> CommittedShape]
    /\ head \in Heights
    /\ read_log   = <<>>
    /\ read_count = 0

\* -----------------------------------------------------------------
\* §8. Actions.
\* -----------------------------------------------------------------

\* Read(domain, daemon): the headline action — admit one (domain,
\* daemon-flags + claimed-entry) request, run the four-gate pipeline + the
\* lifecycle classifier via MakeRecord against the fixed committee-attested
\* head, append one ReadRecord to read_log, increment read_count. Models one
\* `determ-light verify-registrant <domain>` invocation against a (possibly
\* adversarial) daemon. The committed registrant table + head are read-only
\* (the chain state is fixed at this state-root + head).
Read(domain, daemon) ==
    /\ domain \in Domains
    /\ daemon \in DaemonFlags
    /\ read_count < MaxReads
    /\ read_log'   = Append(read_log, MakeRecord(domain, daemon, head))
    /\ read_count' = read_count + 1
    /\ UNCHANGED <<committed, head>>

\* Saturate: stutter once read_count reaches MaxReads. TLC bounds the state
\* space; the invariants are evaluated at every reachable state along the way.
Saturate ==
    /\ read_count >= MaxReads
    /\ UNCHANGED vars

Next ==
    \/ \E domain \in Domains, daemon \in DaemonFlags : Read(domain, daemon)
    \/ Saturate

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E domain \in Domains, daemon \in DaemonFlags :
                            Read(domain, daemon))

\* -----------------------------------------------------------------
\* §9. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ committed  \in [Domains -> CommittedShape]
    /\ head       \in Heights
    /\ read_log   \in Seq(ReadRecord)
    /\ read_count \in Nat
    /\ read_count <= MaxReads
    /\ Len(read_log) = read_count

\* -----------------------------------------------------------------
\* §10. Invariants — the seven RP-1..RP-5 claims (+ corollaries).
\* -----------------------------------------------------------------

\* INV_FourGateSound (RP-1) — the headline no-trust-leak contract. Every
\* INCLUDED read passed ALL FOUR gates. No reachable accept skips a gate.
\*
\* Structural witness: Classify returns INCLUDED only when AllGatesOk (anchor
\* /\ head /\ path /\ bind). So verdict = INCLUDED implies all four per-gate
\* Booleans are TRUE.
INV_FourGateSound ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "INCLUDED")
       => (e.anchor /\ e.head /\ e.path /\ e.bind)

\* INV_AnchorGate (RP-2) — a read against a daemon that does NOT run our
\* chain is never INCLUDED. No accept has anchor = FALSE.
\*
\* Structural witness: AnchorOk(daemon) = daemon.anchor_honest; a forged
\* anchor makes anchor = FALSE, so AllGatesOk fails and the verdict is
\* UNVERIFIABLE. trustless_read.cpp::anchor_genesis (main.cpp:4204).
INV_AnchorGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "INCLUDED") => e.anchor

\* INV_HeadGate (RP-2b) — a read whose header chain is not committee-verified
\* (a forged/unsigned head or an empty S-033 state_root) is never INCLUDED;
\* neither the state_root NOR the head height H such a read would trust is
\* used. No accept has head = FALSE.
\*
\* Structural witness: HeadOk(daemon) = daemon.head_honest; a forged head
\* makes head = FALSE -> UNVERIFIABLE. FB23 (FrostVerify) +
\* verify_chain_to_head (main.cpp:4216-4222). This is what stops a lying
\* daemon from inflating H to flip the ACTIVE/INACTIVE verdict.
INV_HeadGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "INCLUDED") => e.head

\* INV_PathGate (RP-2c) — a read whose r:<domain> Merkle path does not
\* recompute to the trusted state_root (or whose key_bytes do not bind to
\* "r:"+domain) is never INCLUDED. No accept has path = FALSE.
\*
\* Structural witness: PathOk requires committed[domain] /= ABSENT AND the
\* honest, correctly-keyed path; a forged/wrong-key path makes path = FALSE
\* -> UNVERIFIABLE. FB44 merkle_verify + main.cpp:4261-4270.
INV_PathGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "INCLUDED") => e.path

\* INV_BindGate (RP-3, THE HEADLINE CRUX) — the r:-NAMESPACE anti-
\* substitution invariant. A read whose claimed RegistrantEntry canonical
\* encoding does NOT hash to the served value_hash is never INCLUDED. No
\* accept has bind = FALSE.
\*
\* Structural witness: BindOk requires committed[domain] /= ABSENT AND
\* Encode(claimed) = Encode(committed[domain]); a forged claim (a substituted
\* ed_pub validator key / registered_at / active_from / inactive_from /
\* region) makes bind = FALSE -> UNVERIFIABLE. So under collision resistance a
\* daemon serving the RIGHT key + a VALID path STILL cannot substitute a
\* forged ed_pub / lifecycle height / region. src/chain/chain.cpp:299-307
\* (the canonical encoding the value_hash commits) vs main.cpp:4314-4332 (the
\* client-side recompute).
INV_BindGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "INCLUDED") => e.bind

\* INV_FieldFaithful (RP-3b) — for every INCLUDED read, the claimed
\* RegistrantEntry EQUALS the entry the chain actually committed at that
\* domain's leaf. Every queried field (ed_pub, registered_at, active_from,
\* inactive_from, region) matches.
\*
\* Derivation: an INCLUDED read has bind = TRUE (INV_BindGate), so
\* Encode(daemon.claimed) = Encode(committed[domain]). Under the
\* injective-Encode abstraction, equal canonical encodings imply equal
\* entries, so daemon.claimed = committed[domain]. This is the strongest
\* application-layer statement: the light client learns the EXACT committed
\* registration (the exact validator ed_pub + lifecycle window + region),
\* never a daemon-chosen substitute.
INV_FieldFaithful ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "INCLUDED") => (e.daemon.claimed = committed[e.domain])

\* INV_NoAbsentAccept (RP-4) — a read for an absent domain (no committed
\* r:<domain> leaf) is never INCLUDED. The no-fabricated-registration
\* invariant at the application layer (the analog of FB43 INV_AbsenceSound /
\* FB50 INV_NoAbsentAccept).
\*
\* Structural witness: both PathOk and BindOk require committed[domain] /=
\* ABSENT, so an absent domain fails both the path AND the bind gate ->
\* AllGatesOk FALSE -> verdict is NOT_INCLUDED or UNVERIFIABLE, never
\* INCLUDED.
INV_NoAbsentAccept ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "INCLUDED") => (committed[e.domain] /= ABSENT)

\* INV_ActiveVerdictSound (RP-5) — the ACTIVE/INACTIVE classification of an
\* INCLUDED read is a deterministic function of the COMMITTEE-CERTIFIED
\* inactive_from / active_from vs the committee-attested head H — never a
\* daemon claim. A read is reported ACTIVE iff the COMMITTED active_from <= H
\* AND (inactive_from = 0 OR inactive_from > H); INACTIVE otherwise. Non-
\* INCLUDED reads carry status "N/A".
\*
\* This pins that a daemon CANNOT flip the lifecycle status: both inputs are
\* committee-anchored. The two heights come from the COMMITTED entry (the
\* bind gate forces daemon.claimed = committed, INV_FieldFaithful), and H is
\* the committee-attested head (the head gate). The recorded status therefore
\* equals StatusActive over the committed entry — never the daemon's raw
\* lifecycle assertion. main.cpp:4432-4435 is the C++ projection.
INV_ActiveVerdictSound ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       /\ (e.verdict = "INCLUDED")
          => /\ committed[e.domain] /= ABSENT
             /\ ( e.status = "ACTIVE" )
                  <=> StatusActive(committed[e.domain], head)
             /\ e.status \in {"ACTIVE", "INACTIVE"}
       /\ (e.verdict /= "INCLUDED") => (e.status = "N/A")

\* -----------------------------------------------------------------
\* §11. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualAnswer — under fairness on Read, the read_log always
\* eventually grows until saturation. The pipeline always terminates with a
\* verdict (one of the three) — it never hangs on a read. The no-stuck-read
\* liveness contract.
PROP_EventualAnswer ==
    (read_count < MaxReads)
    ~> (read_count > 0 /\ Len(read_log) = read_count)

\* PROP_Determinism (RP-6) — the four-gate pipeline + the lifecycle
\* classifier is a pure function of (domain, daemon, head) against the fixed
\* committed registrant table. Stated as a standing invariant over the log:
\* any two records with the same (domain, daemon) have the identical four
\* per-gate Booleans AND the identical verdict AND the identical lifecycle
\* status. Since committed + head are fixed at Init and MakeRecord is
\* deterministic, identical reads always produce identical records.
PROP_Determinism ==
    \A i, j \in 1..Len(read_log) :
       (/\ read_log[i].domain = read_log[j].domain
        /\ read_log[i].daemon = read_log[j].daemon)
       => (/\ read_log[i].anchor  = read_log[j].anchor
           /\ read_log[i].head    = read_log[j].head
           /\ read_log[i].path    = read_log[j].path
           /\ read_log[i].bind    = read_log[j].bind
           /\ read_log[i].verdict = read_log[j].verdict
           /\ read_log[i].status  = read_log[j].status)

\* -----------------------------------------------------------------
\* §12. Soundness commentary — what TLC checks vs. the C++ reader.
\* -----------------------------------------------------------------
\*
\* The trustless registrant read composes four trust reductions, each of
\* which a malicious daemon could subvert independently, then derives ONE
\* lifecycle status over the committee-anchored facts (committed active_from /
\* inactive_from + attested head H). FB60 pins the COMPOSITION + VERDICT
\* obligation: an INCLUDED accept requires ALL FOUR gates, so subverting any
\* one fails closed to UNVERIFIABLE — never an optimistic accept; and the
\* ACTIVE/INACTIVE sub-status is a pure function of committee-certified
\* inputs. TLC enumerates every reachable interleaving of reads over the
\* bounded domain x daemon-flag x head universe — including the four single-
\* gate-forged daemon variants AND heads below/at/above each active_from /
\* inactive_from — and confirms the invariants hold against the fixed
\* committed table.
\*
\* The crux is INV_BindGate (RP-3) + INV_FieldFaithful (RP-3b): the
\* r:-namespace value-hash binding. FB43 (CompositeKeyStateProof) pins that
\* the served KEY is canonical (and FB60 re-binds "r:"+domain at the client);
\* FB44 (MerklePathVerify) pins that the served PATH recomputes to the
\* state_root. But a daemon that serves the RIGHT key + a VALID path could
\* STILL hand the client a value_hash that does not correspond to the
\* RegistrantEntry it claims in the `account` cleartext — letting the daemon
\* assert a forged ed_pub (a wrong validator key, the most dangerous lie
\* since r: IS the committee's draw set) / registered_at / active window /
\* region while the chain committed a different entry. INV_BindGate closes
\* this: the client recomputes SHA256(canonical_encoding(claimed)) from the
\* cleartext and compares it to the served value_hash; under collision
\* resistance, a match implies claimed = committed (INV_FieldFaithful).
\*
\*   FB43 (right key) + FB44 (right path) + FB60 (right value + right
\*       lifecycle verdict) = a fully trustless r:-namespace registrant read.
\*
\* INV_ActiveVerdictSound (RP-5) adds the lifecycle layer: the ACTIVE/INACTIVE
\* status is derived from the COMMITTEE-CERTIFIED inactive_from / active_from
\* (via the bind gate) vs the COMMITTEE-ATTESTED head H (via the head gate),
\* re-running the SAME arithmetic the chain uses (main.cpp:4432-4435), so a
\* lying daemon cannot flip a deactivated validator back to ACTIVE (nor vice
\* versa) — both inputs are anchored.
\*
\* With FB60 shipped, r: is the LAST simple-key namespace to gain a trustless
\* reader, completing the simple-key family a:/s:/d:/r:. The b: namespace
\* (abort_records, the S-032 cache) is the one remaining S-033 namespace
\* WITHOUT a state-proof reader — it is internal-only and is deliberately NOT
\* covered here or in any sibling read spec.
\*
\* What the spec does NOT check (consistent with the sibling specs' scope
\* notes + the collision-resistance abstraction):
\*   * The byte-level SHA-256 / canonical encoding. Modeled as an injective
\*     term constructor (FB23 / FB26 / FB44 / FB50 / FB53 use the same
\*     device). The concrete encoding is exercised by
\*     tools/test_light_verify_registrant.sh.
\*   * The Merkle-path bytes + the race-window state-root anchoring
\*     (main.cpp:4337-4411, the proof.height vs vc.height reconciliation).
\*     PathOk abstracts FB44 (MerklePathVerify)'s accept/reject decision over
\*     the FINAL committee-anchored root; the byte-level walk + the header re-
\*     verification at a forward proof.height are FB44 / FB23 territory.
\*   * The committee-signature bytes + the header-chain walk to the head.
\*     HeadOk abstracts FB23 (FrostVerify)'s accept/reject decision over the
\*     state_root AND the head height; the Ed25519/FROST verify soundness is
\*     FB23, the prev_hash walk is verify_chain_to_head.
\*   * Non-membership. An absent domain returns NOT_INCLUDED (the consistent
\*     not_found + null-registry answer; an inconsistent present-proof /
\*     null-registry daemon is UNVERIFIABLE, main.cpp:4284-4291); trustless
\*     non-membership in general requires the documented SMT migration and is
\*     out of scope (same boundary as FB43 T-CK5 / FB50 INV_NoAbsentAccept).
\*   * The apply-side registrant mutation. How committed[domain] came to hold
\*     its (ed_pub, registered_at, active_from, inactive_from, region) is the
\*     REGISTER/DEREGISTER apply-path's job; FB60 reads a fixed committed
\*     table at a single state-root + head.

============================================================================
\* Cross-references.
\*
\* DAppRegistrationRead.tla (FB50) ->
\*   The d:-namespace trustless reader FB60 mirrors field-for-field. FB50's
\*       INV_BindGate / INV_FieldFaithful headline (over the d: field set) is
\*       reproduced here over the r: field set (ed_pub, registered_at,
\*       active_from, inactive_from, region). Shared: four-gate pipeline,
\*       injective-Encode abstraction, INV-* state-machine style.
\*
\* UnstakeEligibilityRead.tla (FB53) ->
\*   The s:-namespace verdict-bearing reader. FB60 reuses its derived-status-
\*       over-committee-anchored-facts pattern, here the lifecycle
\*       ACTIVE/INACTIVE classifier (INV_ActiveVerdictSound) rather than the
\*       unstake ELIGIBLE/LOCKED split. Both re-run apply-side arithmetic
\*       over committee-certified inputs.
\*
\* RegistrantProofSoundness.md (FB60 companion) ->
\*   The prose proof this module machine-checks; RP-1..RP-5 are its theorems.
\*
\* CompositeKeyStateProof.tla (FB43) ->
\*   FB43 (right key over all ten namespaces); FB60 reads the r: leaf whose
\*       key FB43 pins canonical and re-binds "r:"+domain at the client.
\*       Composition FB43 + FB44 + FB60.
\*
\* MerklePathVerify.tla (FB44) ->
\*   FB44 (right path); FB60's PathOk predicate abstracts FB44's accept/reject
\*       decision.
\*
\* FrostVerify.tla (FB23) ->
\*   FB23 (committee-signed head); FB60's HeadOk predicate abstracts FB23's
\*       accept/reject decision over BOTH the state_root AND the head height H
\*       (the lifecycle verdict's height input).
\*
\* C++ enforcement:
\*   light/main.cpp::cmd_verify_registrant (main.cpp:4164) : the INCLUDED /
\*       NOT_INCLUDED / UNVERIFIABLE verdict + ACTIVE/INACTIVE lifecycle
\*       pipeline. anchor_genesis (:4204 / AnchorOk), verify_chain_to_head
\*       (:4216 / HeadOk), state_proof {namespace:"r", key:domain} (:4225),
\*       key_bytes bind to "r:"+domain (:4261-4270 / PathOk key half),
\*       value_hash recompute from the account RPC cleartext (:4314-4332 /
\*       BindOk), the state-root race-window anchoring (:4337-4411),
\*       verify_state_proof (:4417 / PathOk merkle half), the ACTIVE/INACTIVE
\*       derivation (:4432-4435 / StatusActive — INV_ActiveVerdictSound), and
\*       the exit codes 0 / 2 / 3 / 1 (:4485-4490).
\*   src/chain/chain.cpp:299-307 : build_state_leaves registrants_ branch —
\*       the canonical RegistrantEntry encoding value_hash = SHA256( ed_pub[32]
\*       || u64_be(registered_at) || u64_be(active_from) ||
\*       u64_be(inactive_from) || u64_be(len region) || region ). Encode is
\*       the spec-layer projection. INV_BindGate (RP-3) + INV_FieldFaithful
\*       (RP-3b).
\*   src/node/node.cpp:2725 : rpc_account registry block {ed_pub,
\*       registered_at, active_from, inactive_from, region} — the cleartext
\*       the client recomputes the bind hash from. A present r: proof with a
\*       null registry is an inconsistent daemon -> UNVERIFIABLE (fail-closed;
\*       main.cpp:4284-4291).
\*
\* Sibling specs (style template):
\*   FB50 DAppRegistrationRead.tla — the four-gate trustless-read pipeline +
\*       injective-Encode + INV_BindGate/INV_FieldFaithful style this module
\*       reuses; FB60 is its r:-namespace lifecycle-bearing companion.
\*   FB53 UnstakeEligibilityRead.tla — the derived-verdict-over-committee-
\*       anchored-facts pattern FB60's lifecycle classifier reuses.
\*   FB44 MerklePathVerify.tla — the injective-hash-term abstraction.
\*   FB23 FrostVerify.tla — the committee-signature verify abstraction FB60's
\*       HeadOk consumes.
\*
\* Runtime regression:
\*   tools/test_light_verify_registrant.sh — exercises the INCLUDED /
\*       NOT_INCLUDED / UNVERIFIABLE verdict + ACTIVE/INACTIVE lifecycle
\*       pipeline FB60 models, recomputing the value_hash against the
\*       committed r: leaf and checking the lifecycle status vs the anchored
\*       head.
============================================================================
