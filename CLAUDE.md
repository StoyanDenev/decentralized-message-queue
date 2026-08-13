This is working folder for DLT
Tone: direct and professional, not chatty

## PROJECT DOCTRINE — non-negotiable, applies to ALL work
Read this before writing code or docs. On any decision conflict, docs/proofs/DECISION-LOG.md wins.

- Provable security (B3): every claim is proof-backed, nothing aspirational.
  New behavior ships with a falsify-on-mutant gate. Do not add unproven or
  speculative surface.
- No migrations, ever (owner constraint). Pre-genesis changes are free;
  post-genesis consensus + state format is frozen. Upgrades are additive only.
- From-scratch C99 crypto, zero heavy deps: no libsodium / OpenSSL in the
  consensus path; every primitive vendored in src/crypto/** (CRYPTO-C99-SPEC.md).
- C99 / Minix-portable discipline throughout: no heavy deps, portable C99 so the
  eventual Minix reference build stays possible (docs/C99-MINIX-PORT.md).
- Minimalism / smallest green surface: do not build speculative or aspirational
  surface; delete dead abstraction. A feature that changes zero behavior is not
  built.
- Canonical binary only in storage / wire / keyfiles / test vectors — no JSON on
  those paths (DECISION-LOG D2). Human-readable text is a non-authoritative view.
- Security model is K-of-K mutual distrust + fork-free consensus. FROST is out;
  reintroduction needs owner sign-off (FROST_DEVIATION_NOTICE).
- Sequence-before-harden: do NOT spend B3 falsify-on-mutant effort on code
  scheduled for replacement (e.g. JSON serialization paths pending the D2
  binary migration). Do the replacement first, then gate the survivor —
  hardening doomed code is wasted proof-work. Consensus accept-rule/logic
  fixes that survive a container swap are exempt (they are not 'replaced').
- Convergence: keep the canonical doc set coherent; extend an existing doc, do
  not spawn parallel ones. Rule: a doc with NO tier marker is an authoritative
  convergence point and must track shipped code; a doc marked TIER: FUTURE /
  NEAR-TERM / PROCESS-ARCHIVE is not. Core convergence points:
    * README.md ................. public overview / entry point
    * docs/WHITEPAPER-v1.x.md + docs/PROTOCOL.md ... the v1 specification
    * docs/proofs/*.md .......... per-claim formal proofs (the B3 record)
    * docs/SECURITY.md .......... the S-item security ledger
    * LICENSING.md .............. licensing authority
  docs/proofs/DECISION-LOG.md is the decisions + rationale authority (wins on any
  decision conflict; append-only). Any unavoidable new doc carries its TIER on line 1.

## CURRENT FRONT — read before selecting any work (owner directive 2026-07-28)
ACTIVE FRONT = execute the D2 JSON->binary migration NOW (DECISION-LOG 2026-07-28).
Rationale: D.5 reference RP + RP SDK are built (inc.6b + sdk/rp), G5/G6 shipped —
and the pool has been hardening JSON-envelope code that D2 deletes (e.g. round-12
net perf on the JSON envelope). Per sequence-before-harden, migrate first.
  1. Strip JSON from the p2p wire envelope (src/net/gossip.cpp, messages.cpp,
     binary_codec.cpp) + storage/genesis (src/chain/block.cpp, chain.cpp,
     genesis.cpp) + wallet keyfiles. Wire portion is GENESIS-DEADLINE (no-migrations).
     PROGRESS 2026-07-31: the ENVELOPE strip is DONE (b29d422 pq_auth tx-frame
     gap + ce31c6f binary-only envelope/HELLO, negotiation deleted, mirrors +
     gates rewritten, mutant-verified, FAST green). PER-TYPE PAYLOAD frames:
     7bcd32d COMPOSABLE_BATCH, c8a63d2+40d61cd abort claims typed,
     ad595bb inc6a (5 request/status), e845b44 inc6b (4 consensus-chatter),
     2803a13 the both-directions exact-length gate. 11 of the 19 types are now
     fixed binary frames; 8 still carry length-prefixed JSON PAYLOADS inside
     the binary envelope (BLOCK, CONTRIB, CHAIN_RESPONSE, BEACON_HEADER,
     SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE, SNAPSHOT_RESPONSE,
     HEADERS_RESPONSE) — WIRE-2 stays until those binarize per-type. Next is
     inc5 (Block frame), the keystone: BLOCK/BEACON_HEADER/SHARD_TIP/
     CROSS_SHARD_RECEIPT_BUNDLE/CHAIN_RESPONSE all carry a Block, and chain
     storage (inc8) has a TOTAL hard dependency on it.
     PROGRESS 2026-08-12 (d34c632): inc5 (the canonical binary Block container)
     LANDED at d33d410+76d7ea4. WALLET/LIGHT KEYFILES ARE DONE — D2 step 3
     shipped seven at-rest containers (DWE bytes, DAK1, DAB1, DNK1, DSS1, DBE1,
     DRS1) + DLS1 for the light anchor cache; the dot-hex envelope, the
     JSON-interior node keyfile and the JSON light state are deleted; DAK1/DNK1
     derive-equality replaces the S-028 address cross-check; ZERO src/ edits.
     REMAINDER (explicit, still open): node_key.json (src/crypto/keys.cpp) and
     DETERM-ACCOUNT-V1 stay src-owned JSON/text until the src-side increment
     (marked D2-DEFERRED(src) in code); the light export-headers archive waits
     on the binary header frame.
     PROGRESS 2026-08-12 (8a106aa): inc7a/7b + inc8 LANDED. Six of the eight
     lp-JSON wire payloads are true binary frames now (BLOCK, CONTRIB,
     CHAIN_RESPONSE, BEACON_HEADER, SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE), all
     delegating to chain::Block::encode_frame; SHARD_TIP decodes with
     allow_witnesses=false (fail-closes POISON-WITNESS pre-auth). CHAIN STORAGE +
     GENESIS + SNAPSHOT are binary-only: <path>.blocks/<i>.blk DBK1 frames + a
     fixed 44-byte DMF1 manifest written atomically last; Chain::save and the
     whole legacy chain.json read path DELETED (a chain.json with no manifest
     loads as an EMPTY chain — gate CS-8); GenesisConfig gains DGC1 (hash-neutral,
     GB-3); snapshots gain DSN1 via Chain::encode_state/decode_state.
     REMAINDER, still open: inc7c — SNAPSHOT_RESPONSE + HEADERS_RESPONSE are the
     last two lp-JSON payloads, so WIRE-2 + the fallback stay until they binarize;
     node_key.json (src/crypto/keys.cpp) and DETERM-ACCOUNT-V1 stay src-owned
     JSON/text (marked D2-DEFERRED(src) in code); the light export-headers archive
     waits on the binary header frame.
  1b. ENDGAME, before step 2 — Improvements.md §12.1: extract the 237 test/selftest
     subcommands out of src/main.cpp into a determ-selftest binary. Measured at
     53a849d: 237 of 292 `cmd ==` handlers are test-*/selftest-*, spanning lines
     6,955-64,364 of 64,683, and 1,151 of the file's 1,513 json-bearing lines (76%)
     sit inside that region. Doing this AFTER D2 stops touching src/main.cpp and
     BEFORE step 2 means the parser deletion faces a main.cpp with ~76% less JSON.
     Sequencing fixed by DECISION-LOG 2026-08-13, correction (i).
  2. Delete third_party/nlohmann/json.hpp AND include/determ/json/json.hpp;
     regenerate test vectors as binary. RPC/CLI/config may keep optional text.
     (= step 4 of the five-step D2 authorization, DECISION-LOG 2026-07-28.)
  3. Gate the BINARY replacements falsify-on-mutant — not the deleted JSON paths.

FOLDED IN (DECISION-LOG 2026-08-13, directive 1): pre-launch item B1 is closed as a
standalone item. Its (a) half — per-block append-only files replacing monolithic
chain.json — was ABSORBED by inc8 above. Its (b) half — an incrementally-persisted
state so Chain::load (src/chain/chain.cpp:3483) stops replaying apply_transactions
over every block — folds into the NEXT src/chain/chain.cpp storage pass, scheduled
with that pass and not ahead of it. It is cheaper than when scoped: inc8 already
built the container it needs (Chain::encode_state/decode_state, the DSN1 record at
src/chain/chain.cpp:2859 / :3018). Do NOT open B1 as separate work — a thread that
did would rewrite the storage inc8 just rewrote.

FROZEN for new hardening until D2 lands: do NOT open perf/robustness/gate work on
the JSON-path files listed above — they are being deleted; hardening them is wasted.
Harden the binary survivors after the swap.

WHERE THE PRIORITY LIVES (DECISION-LOG 2026-08-13, directive 2). This CURRENT FRONT
section is the operational source for WHAT TO WORK ON NEXT. PRE-LAUNCH-DECISIONS.md's
9-build + 3-verification execution plan, docs/proofs/IMPLEMENTATION-SEQUENCING.md and
docs/proofs/V1.1-PLAN.md are SUPERSEDED-FOR-SEQUENCING: their ORDERING predates the D2
authorization and must not be used to select work. Their per-item DECISIONS remain the
standing record and are unaffected. DECISION-LOG.md wins over all of them.

PRE-GENESIS BACKLOG (must land before mainnet) — DApp substrate Q2/Q3/Q4 code
(DECISION-LOG 2026-07-28): governed payload cap; enforce topic routing; accept_anon.
Also: decide the final CryptoProfile enum value set (currently {MODERN=0, FIPS=1},
include/determ/chain/params.hpp:122-125). It is GENESIS-FROZEN and invisible to work
selection until now: crypto_profile is mixed into the genesis hash when non-default
(src/chain/genesis.cpp:837-839, reaching compute_genesis_hash at :891-894), written as
a u8 by the DGC1 encoder (:497), and FAIL-CLOSED on decode — an unknown value is
rejected outright (:571-574). Cross-ref Improvements.md §12.5 (whose named subjects
tactical_civilian / cluster_civilian are TIMING presets that were never implemented —
zero occurrences in src/ include/ light/ wallet/; see DECISION-LOG 2026-08-13
directive 4 for the correction).
Also: B4 reserved-discriminator audit (docs/proofs/ReservedDiscriminatorAudit.md, 14 KEEP
/ 8 DROP; drop 1 of 8 executed 2026-07-09, drops 2-8 unexecuted) — the audit stands, but
EXECUTION of drops 2-8 is deferred to the LAST pre-genesis act (DECISION-LOG 2026-08-13,
directive 3): every slot KEPT preserves a post-genesis additive path (that is exactly how v2.15
Option-B on-chain multisig stays shippable later), every slot DROPPED forecloses one
PERMANENTLY under no-migrations. Do not execute DROPs early. KEEP verdicts need no
execution.
Also: C2 adversarial FA/DSF sweep is UNBLOCKED NOW. Its recorded prerequisite (the
"remaining deterministic-scheduler increments 2-5") is DISCHARGED —
docs/proofs/DeterministicSchedulerDesign.md reads "increments 1-11 SHIPPED", and
increment 5 IS the adversarial-schedule harness (test-fa-adversarial-deterministic).
What remains is RUNNING the full sweep (seed/scenario breadth), not building anything.
Also: macOS/Darwin support — LANDED (DECISION-LOG 2026-08-11, both entries): RNG
__APPLE__ getentropy branch, kqueue reactor backend, script portability; first
native Darwin/arm64 build green, byte-freeze pins matched, no goldens regenerated
(FAST was 294/0 at that commit; 299/0 as of d34c632). Tail: full run_all on Darwin
(pip3 pynacl — three EQV cluster scripts now carry a pynacl fallback and run here),
macOS CI runner, APFS.

BOTH RANK-1 CONSENSUS HOLES ARE CLOSED (authorized owner 2026-07-31; LANDED d34c632,
DECISION-LOG 2026-08-12). Do not re-open them; harden forward from here.
  - Hole 1 forged-slash -> docs/SECURITY.md S-052. Closed by HEIGHT BINDING, not by
    carrying headers (rejected on analysis: unbounded size + Block>EquivocationEvent>Block
    recursion). Both digest families are now two-level and openable:
      block_digest   = SHA256("DTM-BLKDIG-v2"  || index       u64BE || body_root)
      contrib_commit = SHA256("DTM-CONTRIB-v2" || block_index u64BE || body_root)
    EquivocationEvent carries kind + per-side {index, body_root, sig}; digest_a/digest_b
    DELETED; verifier rejects kind>1, asserts index_a==index_b==block_index, verifies
    against DERIVED digests. Wire (GENESIS-DEADLINE): EQUIV_REC + EQUIVOCATION_EVIDENCE
    fixed 229 B after the lp_str, kMinEquivEvent 230, decode fail-closes on kind>1.
    Gate: the 8-arm EQV block of test-abort-cert-validation.
    RESIDUAL, OPEN, NOT authorized: same-height cross-round honest double-signing still
    satisfies V11 (an abort re-round changes the body at one height). Closing it needs
    the round/aborts_gen bound into the openings. Recorded in EquivocationSlashing.md
    §2 Case (c) + PROTOCOL.md §6.1 — do NOT treat it as closed.
    SUPERSEDED IN PART 2026-08-13: that "bound the round into the openings" route is what
    the six failed designs tried; it is REFUTED, not merely unimplemented (DECISION-LOG
    2026-08-12 "final".."final+9"). Do not re-propose it. The residual's HARM is now gone
    (the pre-finalization layer carries no consequence — see the SLASHING block below);
    what remains open is the sound successor. Tracked as R-1 on the DECISION CLOCK.
  - Hole 2 empty-committee beacon -> docs/SECURITY.md S-053. Closed by extracting
    verify_committee_sigs as the ONE committee-signature core (non-empty + size match +
    membership + verify + signed_count >= required_k); both verify_shard_tip_committee_
    sig_root and on_beacon_header route through it. Gate: test-beacon-header-committee.
    SCOPE, stated honestly: this does NOT authenticate cumulative_rand (outside
    compute_block_digest; check_cumulative_rand is apply-path only) — PRE-EXISTING, still
    NOT authorized, adjacent to the also-unauthorized HELLO beacon-role authentication.

ALSO LANDED d34c632: S-050 straggler recovery (owner-authorized in-session 2026-08-12).
An idle non-committee follower arms no round timer, so the S-050 stall valve never fired
for it and one missed block stranded it permanently. apply_block_locked now treats
b.index > height() as proof a peer minted past our head and arms the existing tolerance-0
catch-up, GUARDED to fire once per stall episode. Gate: test-straggler-resync.
FAST was 299/0 at d34c632 (294 baseline + 5 new gates: test-beacon-header-committee,
test-straggler-resync, selftest-envelope-bytes, selftest-keyfile-binary,
selftest-backup-binary); 302/0 as of 8a106aa (+wire_payload_frames,
genesis_binary_codec, snapshot_binary_codec).
NOT authorized (separate future item): authenticate the self-declared BEACON role in HELLO.

SLASHING AT THE PRE-FINALIZATION LAYER NOW CARRIES NO CONSEQUENCE (owner decision
2026-08-13; DECISION-LOG 2026-08-13). A same-height duplicate signature detected before
finalization is logged and gossiped for operator attention and takes NO consensus action
— no stake forfeiture, no exclusion. Six designs failed (DECISION-LOG 2026-08-12 entries
"final", "final+1", "final+3", "final+5", "final+7", "final+9") and together
proved the predicate unsound and unfixable: no predicate over two signed openings is both
sound and complete under asynchrony (a splitter's openings are bit-identical to an honest
node's — only DELIVERY differs), and at K == M no exclusion is safe either (M-of-M
selection is the identity on the SET, so rotation evicts no one, and a non-liftable
exclusion is a self-sustaining permanent halt).
  THE CHANGE IS A RELOCATION, NOT A REMOVAL (owner correction 2026-08-13). Slashing moves
  OUT OF L1 INTO L2. L1 keeps DETECTION and the on-chain EVIDENCE RECORD but attaches no
  consensus consequence; the economic consequence is applied at the DApp/L2 layer, which
  may use inputs L1 provably cannot (off-chain corroboration, elapsed time, arbitration,
  dispute/appeal) and whose verdict is therefore not required to be sound-and-complete as
  a consensus rule. This is why the impossibility results above are not fatal: they bound
  what a CONSENSUS predicate can decide, not what an L2 policy can.
  CONSEQUENCE FOR THE EVIDENCE RECORD: it is NOT merely diagnostic — it is the INPUT to
  L2. It must therefore be reliable, capped and queryable, which makes the per-block cap +
  in-block duplicate rejection (see below) a correctness requirement of the L2 design, not
  just a DoS fix.
  OPEN ARCHITECTURAL QUESTION (owner): what does L2 slash? Either (a) L1 exposes a
  DApp-callable stake primitive — but then the L2 verdict re-enters consensus and the
  soundness problem returns; or (b) validators post a SEPARATE L2 bond and L1 stake is
  never slashable — fully clean, opt-in, and consistent with K-of-K mutual distrust; or
  (c) L2 consequence is exclusion/reputation at the service layer only. NOT DECIDED.
  NOT LANDED — the code change was written, FAILED adversarial review (22 findings
  confirmed, 1 false alarm) and was REVERTED. The core removal is sound (A1 neutral,
  snapshot round-trips, no state_root leaf changes shape), but landing it additionally
  requires: a per-block CAP + in-block duplicate rejection on equivocation_events (2
  Ed25519 verifies each and deregistration was the only limiter, so the same event becomes
  re-includable forever — a NEW DoS vector the removal creates); S-006's status re-derived
  (its entire closure was "route detection into the slashing apply path", so it is
  silently reopened); an HONEST S-011 residual (the drafted one was wrong in three places
  — BFT escalation can seat a zero-honest committee at K == M, abort-driven stake drain
  below min_stake IS permanent and S-051 does not lift it, and DOMAIN_INCLUSION zeroes
  BOTH legs); and ~16 authoritative no-TIER proof docs still asserting the deleted
  forfeiture as shipped. Full finding list: DECISION-LOG 2026-08-13.
  THIS REOPENS S-011 WHEN IT LANDS. docs/SECURITY.md states S-011's mitigation as the
  S-010 stake floor PLUS the FA6 equivocation-slashing economic bound; once the
  pre-finalization consequence is removed, the slashing half no longer holds as written.
  Same flag stands against BFTSafety.md B2 / T-5.1 (DECISION-LOG 2026-08-12 "final+6")
  and, newly, against S-029's Level-3 block_hash-grinding closure and S-013's economic
  leg. Until the re-derivation lands, do NOT cite the old bound.

DECISION CLOCK — three UNAUTHORIZED consensus/wire residuals (DECISION-LOG 2026-08-13,
directive 5). All three are pre-genesis or never. They are correctly marked NOT
authorized, but an unauthorized item does not self-surface and THE DECISION HAS A
DEADLINE even when the work does not. A thread reaching one of these milestones must
surface the row to the owner before calling the milestone complete.
  R-1  Hole-1 residual: same-height CROSS-ROUND double-signing satisfies V11
       (EquivocationSlashing.md §2 Case (c) + PROTOCOL.md §6.1).
       DECIDE BY: the finalization-layer slashing design gate, itself due before B4's
       DROP execution (the last pre-genesis act).
  R-2  cumulative_rand is NOT authenticated on the beacon-header path (outside
       compute_block_digest; check_cumulative_rand is apply-path only).
       DECIDE BY: D3 / S-036 closure (on-chain SHARD_TIP, v2.11) — same code path, and
       the launch posture is EXTENDED.
  R-3  The self-declared BEACON role in HELLO is unauthenticated.
       DECIDE BY: D2 completion, the parser-deletion step — HELLO is wire surface and D2
       is its last wholesale rewrite.
  IF UNDECIDED AT GENESIS the default becomes "never", PERMANENTLY, under no-migrations.
  No decision is not a neutral state.
