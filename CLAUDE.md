This is working folder for DLT
Tone: direct and professional, not chatty

## PROJECT DOCTRINE — non-negotiable, applies to ALL work
Read this before writing code or docs. On any decision conflict, docs/proofs/DECISION-LOG.md wins.

- Provable security (B3): every claim is proof-backed, nothing aspirational.
  New behavior ships with a falsify-on-mutant gate. Do not add unproven or
  speculative surface.
- Green is not proof (B3 corollary; measured 2026-08-12/13, DECISION-LOG). A
  falsify-on-mutant gate proves the code enforces what the gate ASSERTS. It
  cannot prove the assertion is the property you NEED. Nine consensus designs in
  one session were wrong; six of them were carried to a green tree — Option D's
  gate was 34/34 with six mutants confirmed RED and FAST 303/0 — and three were
  refuted on paper (DECISION-LOG 2026-08-13, doctrine entry). For consensus work a
  green gate is NECESSARY AND NOT SUFFICIENT. Standing rules:
    * ADVERSARIAL REVIEW OF THE DIFF, BEFORE COMMIT, INDEPENDENT OF GATE COLOUR,
      on any change to consensus accept-rules, the apply path, wire formats,
      committee derivation, or the slashing/evidence path. Across those nine,
      review returned 124 confirmed defects against 11 false alarms; the
      mutant-verified gates shipped with the changes found none of them. A
      purpose-built ratchet is not a substitute — round_seq shipped one and a
      reviewer defeated it with a ONE-LINE edit while it stayed green.
    * ASSERT AT THE LAYER WHERE THE RULE LIVES. A gate built on a producer-side
      proxy goes green while the bug is live; that is exactly how Option C was
      refuted. The slashing predicate is body_root_a != body_root_b in the
      VERIFIER (validator.cpp V11 + the node.cpp adoption gate); the core
      comparison in the in-tree assembler is a courtesy, not the rule.
    * DESIGN-AND-PROVE BEFORE IMPLEMENTING when the design is uncertain. The
      time-bucket and lock-rule designs were REFUTED at design stage for a
      fraction of the cost of the ones implemented first.
    * SMALLEST INCREMENT THAT KEEPS THE TREE GREEN AND TRUTHFUL. All three slashing
      attempts failed and were reverted; the first two by BUNDLING: the ~10-line core removal was verified sound
      BOTH times and was sunk by a per-block cap, an exit-code change and doc
      convergence that each failed independently. Land the verified core alone;
      every rider is its own increment with its own review.
    * VERIFY WITH tools/ci_local.sh — never a bare tools/run_all.sh or bare
      tools/test_*.sh. Only ci_local exports DETERM_BIN / DETERM_WALLET_BIN /
      DETERM_LIGHT_BIN / DETERM_DSF_BIN; a bare run resolves the binary by
      tools/common.sh search order (three "faked" mutant results this session
      were a stale tree shadowing build-linux — that tree is deleted, the
      discipline stands) and SKIPs every DSF gate when DETERM_DSF_BIN is unset.
      CONFIRM THE BUILD SUCCEEDED before trusting any mutant result: a failed
      build leaves the previous binary in place, so the mutant "dies" against
      unmutated code.
- Never seed anything security-relevant from a block hash. Block::compute_hash
  (src/chain/block.cpp) hashes signing_bytes() and then APPENDS
  creator_block_sigs, and Ed25519 verification checks only pk-y canonicality,
  S < L and the group equation — RFC 8032's deterministic nonce is a signer-side
  convention NO verifier can check. So a member broadcasting its BlockSigMsg
  last can enumerate unboundedly many VALID signatures over the SAME
  compute_block_digest, each yielding a different block hash, and publish the
  one that seats the committee it wants: the hash is MALLEABLE under a fixed
  digest, at ~one Ed25519 sign per trial. This is harmless today ONLY because
  committee selection and the subsidy lottery route through cumulative_rand's
  commit-reveal, every input of which is digest-covered or commit-pinned. Keep
  it that way (DECISION-LOG 2026-08-12 "final+9").
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
- No systemic backdoor (owner HARD CONSTRAINT, DECISION-LOG 2026-08-18 6265d34):
  "No key escrow, no protocol-level disclosure compulsion, no third-party master
  key — ever." Selective disclosure exists only as the holder's voluntary,
  per-view-key act in the designed v2.22/v2.24 mechanism. Any doc asserting
  unqualified PFS alongside view-key disclosure is wrong (same entry).

## CURRENT FRONT — read before selecting any work (owner directives 2026-07-28 and 2026-09-16)
ACTIVE FRONT (owner, DECISION-LOG 2026-09-16 D1 — supersedes the 2026-07-28 "D2 now" line
for ORDERING; D2 itself stays authorized): SAFETY FIRST, D2 WIRE REMAINDER IN PARALLEL. Work is
selected from the IMPLEMENTATION SEQUENCE in DECISION-LOG 2026-09-16 §E, in that order:
(1) apply exports 0001-0015; (2) the record; (3) the O-1 chain (forfeiture removal alone —
LANDED 2026-09-16, export 0016 -> evidence cap + in-block dedup -> abort-deduction
retirement -> re-derivations; S-102 ADJUDICATED + CLOSED 2026-09-16: reachable at HEAD by a
zero-key state_root relabel, the reorg made atomic — test-node-reorg-guard); (4) the joint design gate R-4 + F-c + R-15
(+R-16); (5) the V-REG-1 companions (join
rule, exit rule, rotation, small-order rule); (6) pq_auth rule + block-byte cap + chain
identity in signing_bytes (the last transaction-frame changes); (7) R-8 C0 demotion -> S-089
-> S-090 rebroadcast; (8) CT verification off the lock; (9) the EXTENDED closure set;
(10) D2 inc7c in PARALLEL from step 3, D2 step 1b + step 4 AFTER step 9; (11) the
node-/client-local backlog interleaved by severity from step 3 (S-078 first); (12) cluster
gates + TLA into ci_local, the C2 sweep; (13) B4 DROP execution last; launch predicate.
Every consensus/apply/wire/genesis increment: design-and-prove -> independent adversarial
review -> falsify-on-mutant gate at the layer where the rule lives -> ci_local -> review of
the diff; smallest increment; no bundling. The D2 record below is kept as history and as
the definition of the D2 remainder.
D2 (DECISION-LOG 2026-07-28) — what it was and what remains:
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

LIVE CRITICALS ON THE RECORD (audit 2026-09-14; DECISION-LOG 2026-08-13..16 and
2026-09-14; ledger rows docs/SECURITY.md S-055..S-073). Recorded in the log after this
section was last written and carried in the ledger. STILL OPEN: S-055 C0 F2
equivocation-view digest halt; S-057 unsigned unbounded pq_auth -> unrelayable blocks;
S-063 DAPP_CALL frames report payments never made; S-064 cross-shard bundles
unauthenticated (multi-shard only); S-065 CT proof verification (~2.2 s per bundle)
under the consensus lock; S-067 UNSTAKE is unincludable (stake unrecoverable through
consensus).
CLOSED 2026-09-15 (owner-authorized accept-rule change, DECISION-LOG 2026-09-15): S-060
REGISTER identity takeover — REGISTER is CREATE-ONLY (V-REG-1: rejected for any domain in
the raw registrants map, and unless nonce == 0); with it the reopened leg of S-052 and
the companion S-068 (a small-order REGISTER key is rejected, after the signature).
Decided consequences: a domain name is single-use, a lost key is terminal, key rotation
is a separate incumbent-signed transaction (R-6, open).
CLOSED 2026-09-15 (found and fixed the same day by the S-068 review): S-071 Zeroth pool
drain — the pool's all-zero anon key is a SMALL-ORDER point (forgeable, not unsignable)
and a COMPOSABLE_BATCH inner TRANSFER from it bypassed the outer-only E1 guard; E1 is
now asserted on every inner tx (verifier) and mirrored at apply. The economic route
stays OPEN: the shipped NEF hands pool/2 to EVERY fee-0 fresh REGISTER (the whitepaper's
lottery + cap was never shipped) — S-073, R-14.
CLOSED 2026-09-15 (owner: "address them"; found by the per-block-committee design pass):
S-074 the abort event's identity was the assembler's choice — no verifier recomputed
`event_hash`, its timestamp was a wall clock, and any in-sync peer could assemble, so
any peer chose the post-abort committee; now canonical (parent-block timestamp; hash
re-derived from parent + tail) and enforced at check_abort_certs, on_abort_event and
on_abort_claim, and re-derived by the beacon's tip verification and the light auditor.
Gates: test-abort-cert-validation (S-074 arms), test-abort-event-canonical,
test-shardtip-witness-verify (S-074 arms).
CLOSED 2026-09-14 (node-local, no consensus change): S-056/S-059/S-061/S-062 — the
producer now asks the verifier (BlockValidator::check_transaction is the ONE per-tx
rule set; build_body admits only what it accepts; a resident rejected tx is evicted
on the first build at each head) — S-058 (the Phase-2 trigger is committee
completeness, not map size; the Phase-1 timer is released only once complete) and
S-066 (gossip trusted the unsigned wire hash).
DECIDED 2026-09-16 (DECISION-LOG 2026-09-16): the order is O-3 = safety first (ACTIVE FRONT
above); S-055 closes through steps 3->7 (the O-1 chain, then R-8); S-057 through step 6
(R-7 both rules); S-063 is confirmed Critical and closes at the delivery layer in step 11;
S-064 in step 9 (the EXTENDED set); S-065 in step 8 (R-10); S-067 in step 5 (R-11). Twenty-six
further open rows S-078..S-103 were carried from the log into the ledger the same day, each
with its disposition. Nothing is closed by decision: a row moves only when its increment
lands, is gated and reviewed. The ledger is NOT clean until then.

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
Also: the CryptoProfile enum value set is DECIDED 2026-09-16 (D18c): {MODERN=0, FIPS=1} is
the frozen set; nothing to build. Record of why it mattered (params.hpp:122-125): crypto_profile is mixed into the genesis hash when non-default
(src/chain/genesis.cpp:872-875, reaching compute_genesis_hash at :926), written as
a u8 by the DGC1 encoder (:532), and FAIL-CLOSED on decode — an unknown value is
rejected outright (:606-609). Cross-ref Improvements.md §12.5 (whose named subjects
tactical_civilian / cluster_civilian are TIMING presets that were never implemented —
zero occurrences in src/ include/ light/ wallet/; see DECISION-LOG 2026-08-13
directive 4 for the correction).
Also, DECIDED 2026-09-16 (genesis-level constants and schema, DECISION-LOG 2026-09-16 §B):
launch configuration = the shipped presets GLOBAL beacon 7/5 + WEB shards 4/3 (D2c);
epoch_blocks = 100 on beacon and shards (D2d); zeroth_pool_initial = 0 (D8, NEF a no-op);
inclusion_model DELETED — STAKE_INCLUSION is the only model, min_stake >= 1 validated at
genesis (D21); sharding_mode becomes a genesis field mixed into the genesis hash (D19b-ii);
signing_bytes() binds the chain identity (genesis hash || shard id) for every tx type (D23,
R-17); a tactical/cluster chain is in scope as SHAPE B only (D19c); the launch clause is a
WRITTEN go/no-go predicate judged over a beta on the frozen surface, drafted for approval in
Step 6, with the cluster gates + TLA models added to ci_local as its instrument (D2b).
Also: B4 reserved-discriminator audit (docs/proofs/ReservedDiscriminatorAudit.md, 14 KEEP
/ 8 DROP; drop 1 of 8 executed 2026-07-09, drops 2-8 unexecuted; R-9 MsgTypes 12/13/14
recorded KEEP 2026-09-16) — the audit stands, but
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
DECISION-LOG 2026-08-12). Hole 1's closure (S-052) was REOPENED on a different leg on
2026-08-14 — S-060, the REGISTER identity takeover (any key could replace the accused
key in the registry the verifier resolves against, validator.cpp:471) — and RE-CLOSED
2026-09-15 by the owner-authorized V-REG-1: REGISTER is create-only (raw registrants
map, nonce 0), so no key can be rebound (DECISION-LOG 2026-09-15). Hole 2 (S-053)
stands. Do not re-open the closed legs; harden forward from here.
  - Hole 1 forged-slash -> docs/SECURITY.md S-052. Closed by HEIGHT BINDING, not by
    carrying headers (rejected on analysis: unbounded size + Block>EquivocationEvent>Block
    recursion). Both digest families are now two-level and openable:
      block_digest   = SHA256("DTM-BLKDIG-v3"  || index       || gen || body_root)
      contrib_commit = SHA256("DTM-CONTRIB-v3" || block_index || gen || body_root)
    (as SHIPPED: src/node/producer.cpp compose_block_digest / compose_contrib_commitment;
    the v2 tags without gen that this block and several docs carried were never the
    shipped bytes — corrected 2026-09-14). EquivocationEvent carries kind + per-side
    {index, gen, body_root, sig}; digest_a/digest_b DELETED; verifier rejects kind>1,
    asserts index_a==index_b==block_index AND gen_a==gen_b (validator.cpp:441-460),
    verifies against DERIVED digests. Wire (GENESIS-DEADLINE): EQUIV_REC +
    EQUIVOCATION_EVIDENCE fixed 245 B after the lp_str (binary_codec.cpp:547), decode
    fail-closes on kind>1.
    Gate: the 8-arm EQV block of test-abort-cert-validation.
    RESIDUAL, OPEN, NOT authorized: same-height cross-round honest double-signing.
    The gen binding IS SHIPPED (v3 digests above; the gen_a==gen_b assert), so a
    cross-round pair is no longer a recognized double-sign — but the binding is
    EVADABLE: gen is signer-chosen off-chain, so a splitter signs side B at gen+1 and
    is acquitted, while an honest node's openings are bit-identical to a splitter's
    (DECISION-LOG 2026-08-13 b5838fb; the six 2026-08-12 designs "final".."final+9").
    Recorded in EquivocationSlashing.md §2 Case (c) + PROTOCOL.md §6.1 — do NOT treat
    it as closed and do NOT re-propose a predicate over two signed openings. The
    residual's HARM is gone: the forfeiture + deregistration were REMOVED 2026-09-16
    (O-1 step 3a, export 0016 — see STEP 3a LANDED in the SLASHING block below). What
    remains open is the sound successor. Tracked as R-1.
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
node's — only DELIVERY differs), and at |eligible pool| == K no exclusion is safe
either (K-of-K selection is the identity on the SET, so rotation evicts no one, and a
non-liftable exclusion is a self-sustaining permanent halt). Stated over the POOL, not
m_creators: no accept rule reads M (DECISION-LOG 2026-08-14 ddfe877).
  THE CHANGE IS A RELOCATION, NOT A REMOVAL (owner correction 2026-08-13). SUPERSESSION
  RESOLVED 2026-09-16 (O-1, DECISION-LOG 2026-09-16 D4): option (b) — L2 relocation with a
  SEPARATE L2 bond; L1 stake is never slashable for equivocation; L1 keeps detection + a
  capped, deduplicated evidence record as the L2 input; the L2 bond/arbitration policy is
  v1.1 DApp scope (D22). Also decided (O-1b, D13): the ROUND-1 ABORT STAKE DEDUCTION IS
  RETIRED — aborts suspend only; and a Phase-2 withholder is suspended, no deduction (R-16,
  D12). The lock-rule entry (5082737) stands refuted (b5838fb). Slashing moves
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
  WHAT L2 SLASHES — DECIDED 2026-09-16: (b), validators post a SEPARATE L2 bond and L1 stake
  is never slashable (the only variant that does not re-enter consensus). (a) and (c) are
  not pursued.
  STEP 3a LANDED 2026-09-16 (export 0016; DECISION-LOG 2026-09-16 "O-1 step 3a"): the
  forfeiture + deregistration loop is GONE from Chain::apply_transactions — an
  EquivocationEvent moves NO L1 state (gate `determ test-equivocation-apply`: neutrality
  against an event-free twin, A1, positive control; mutants M1-M8 RED). Earlier attempts
  FAILED adversarial review because of their RIDERS, never the removal; this time the
  removal landed ALONE. STILL TO LAND, each its own increment, in this order:
  3b a per-block CAP + in-block duplicate rejection on equivocation_events (2 Ed25519
  verifies each and deregistration was the only limiter, so the same event is now
  re-includable — the DoS vector the removal creates; a bound that is a pure function of
  the block's bytes, or none — DECISION-LOG 2026-08-13); D13 abort-deduction retirement;
  3c S-006's status re-derived (its closure was "route detection into the slashing apply
  path"); an HONEST S-011 residual (the drafted one was wrong in three places — BFT
  escalation can seat a zero-honest committee at |pool| == K, abort-driven stake drain
  below min_stake IS permanent and S-051 does not lift it); the S-013 / S-029 Level-3 /
  BFTSafety T-5.1 re-derivations; S-095; and the 51 untiered docs that stated the removed
  consequence as shipped — each now carries a uniform "STATUS 2026-09-16" banner (list in
  the log entry) until its re-derivation replaces it. Full 2026-08-13 finding list:
  DECISION-LOG 2026-08-13.
  S-011 IS REOPENED IN SUBSTANCE (ledger marker updated 2026-09-16): docs/SECURITY.md
  states S-011's mitigation as the S-010 stake floor PLUS the FA6 equivocation-slashing
  economic bound; the slashing half no longer holds. Same flag stands against BFTSafety.md
  B2 / T-5.1 (DECISION-LOG 2026-08-12 "final+6"), S-029's Level-3 block_hash-grinding
  closure and S-013's economic leg. Until the re-derivation lands, do NOT cite the old bound.

DECISION CLOCK — consensus/wire residuals (DECISION-LOG 2026-08-13, directive 5; rows
R-4..R-9 added 2026-09-14; R-10..R-16 added 2026-09-15; R-17 added 2026-09-16). ALL ROWS
WERE DECIDED BY THE OWNER ON 2026-09-16 (DECISION-LOG 2026-09-16); each row below keeps its
problem statement as the record and carries its DISPOSITION. A disposition is a decision,
not a closure: the rule lands only through the sequence in ACTIVE FRONT, with its own
design gate, adversarial review and falsify-on-mutant gate. A thread implementing a row
must not widen or narrow the disposition without a new owner entry.
  R-1  [DECIDED 2026-09-16, D4: no L1 verdict over two signed openings — a same-height pair, cross-round or not, is L2 EVIDENCE requiring corroboration.]
       Hole-1 residual: same-height CROSS-ROUND double-signing satisfies V11
       (EquivocationSlashing.md §2 Case (c) + PROTOCOL.md §6.1).
       DECIDE BY: the owner's restatement of the slashing position (O-1 below; the
       "finalization-layer design gate" this row named was itself a mis-recording per
       DECISION-LOG f310086), due before B4's DROP execution (the last pre-genesis act).
  R-2  [DECIDED 2026-09-16, D16: the FIELD binding landed with Q1 (check_header_rand_binding); the two residuals — creators not checked against the derived committee (S-093) and the unconfirmed first header (S-094) — are AUTHORIZED design gates.]
       cumulative_rand is NOT authenticated on the beacon-header path (outside
       compute_block_digest; check_cumulative_rand is apply-path only).
       DECIDE BY: D3 / S-036 closure (on-chain SHARD_TIP, v2.11) — same code path, and
       the launch posture is EXTENDED.
  R-3  [DECIDED 2026-09-16, D16: AUTHORIZED design gate — the BEACON role is authenticated (bound to a genesis-pinned or registry-derived beacon set; HELLO signed).]
       The self-declared BEACON role in HELLO is unauthenticated.
       DECIDE BY: D2 completion, the parser-deletion step — HELLO is wire surface and D2
       is its last wholesale rewrite.
  R-4  [DECIDED 2026-09-16, D5a: cap at REGISTER/eligibility + assertion at selection, per shard; genesis check 2K > |initial creators|; joint design gate with F-c and R-15 AUTHORIZED (D5b/D11).]
       The committee-derivation safety bound 2K > N(h) over the ELIGIBLE POOL (S-054 is
       partial: the shipped band guards m_creators, which no accept rule reads; with
       N >= 2K two racing same-height committees finalize conflicting blocks with no
       double-signer — DECISION-LOG 2026-08-14 ddfe877). Two shapes: a genesis-pinned
       pool cap, or the verifier refusing a committee drawn from a pool larger than
       2K-1 (halt, not fork). Design together with F-c (AbortCascadeLiveness.md §4.3),
       whose soundness turns on whether the pool can be adversarially shrunk.
       DECIDE BY: before genesis; frozen accept rule.
  R-5  DECIDED + LANDED 2026-09-15 (owner): create-only REGISTER (V-REG-1) closes S-060;
       key loss is terminal for the domain; DEREGISTER is terminal too (no re-entry under
       the same name — balance, stake and DApp ownership stay with the domain, S-067).
       The small-order-key companion S-068 landed the same day (a REGISTER payload key
       must decode to a large-order point). Gates: test-register-create-only,
       test-register-small-order-key. Kept here as the record.
  R-6  [DECIDED 2026-09-16, D15: ships BEFORE genesis — free TxType, rk: leaf, incumbent-signed, ed_pub only; KR-10 unification additive later.]
       ROTATE_IDENTITY_KEY / revocability: a new TxType is free at the wire and state
       layer (1c0a61d), but old validators fail closed on unknown types, so first use
       needs every validator upgraded — a coordination requirement, not a migration.
       The open question is whether it ships BEFORE genesis. DECIDE BY: before genesis if
       validators must be able to rotate before an upgrade window exists.
  R-7  [DECIDED 2026-09-16, D9: BOTH rules — empty pq_auth on non-PQ types (PQ exact size) AND a consensus block-byte cap matching the wire limit; lands with R-17 as the last frame changes.]
       S-057: a rule that non-PQ transaction types carry empty pq_auth, and/or a
       consensus block-byte cap matching the 4 MB wire cap (a valid block must never be
       unrelayable). New accept rules. DECIDE BY: before genesis.
  R-8  [DECIDED 2026-09-16, D4: proceeds after the O-1 chain (sequence step 7), then S-089, then the S-090 rebroadcast.]
       S-055 C0: evidence-payload demotion (design AUTHORIZED, DECISION-LOG 5b2d7fe) is
       sound only once the evidence carries no L1 consequence (7570989) — gated on O-1;
       lands with the per-block cap + in-block duplicate rejection as their own
       increments. DECIDE BY: O-1.
  R-9  [DECIDED 2026-09-16, D20a: KEEP, recorded in ReservedDiscriminatorAudit.md; DROP execution of the other verdicts stays the last pre-genesis act.]
       B4 interaction: MsgTypes 12/13/14 KEEP-or-DROP flips the audit's 14/8 to 12/10
       under the P1 sharding posture (DECISION-LOG e7c6fc2). DECIDE BY: B4 DROP execution.
  R-10 [DECIDED 2026-09-16, D14: verification OFF the consensus lock + a recomputed-hash verdict cache + a consensus per-block CT cap + a node-local quota; anonymous CT ALLOWED at ingress to match the verifier; cap value proposed by the gate (D24).]
       S-065: CT proof verification (~2.2 s per aggregated range proof, measured
       2026-09-14) runs under the exclusive consensus lock at validation and at the
       first build of each head; and anonymous CT ingress is blocked only by the S-002
       mirror's anon->TRANSFER-only rule, which is NOT the verifier's rule (the
       documented light-client shield flow from an anonymous key is rejected at
       ingress). Design: verification off the lock (or a CT budget) + settle the anon
       CT ingress rule. DECIDE BY: before any CT deployment; node-local except the
       ingress rule's consistency with the verifier.
  R-11 [DECIDED 2026-09-16, D7: UNSTAKE after DEREGISTER at block_index >= unlock_height via a sender-rule exception scoped to UNSTAKE.]
       S-067: no UNSTAKE is includable (unlock only after DEREGISTER, by which time the
       domain is ineligible and the verifier rejects its every tx) — staked funds are
       unrecoverable through consensus. Accept-rule change (an inactive registrant may
       UNSTAKE). DECIDE BY: before genesis; frozen accept rule.
  R-12 [DECIDED 2026-09-16, D6: OPEN SET — STAKE (and its funding TRANSFER) accepted from a registered-but-unstaked domain; eligibility at the next epoch once stake >= min_stake; the R-4 cap enforced at that point.]
       S-069: under STAKE_INCLUSION (the default) no domain can JOIN after genesis — a
       fresh registrant holds 0 stake, is therefore absent from the eligible registry,
       and the verifier rejects its STAKE ("tx sender not in registry") before the stake
       can be established (DECISION-LOG 0fe6eda REVERSED 1 states it as a fact; README
       §"joins the eligible pool" claims the opposite). Either the validator set is
       closed at genesis BY DESIGN (then say so and the REGISTER/STAKE tooling is
       misleading) or STAKE from a registered-but-unstaked domain must be accepted (an
       accept-rule change). With V-REG-1 + terminal DEREGISTER the set can only shrink.
       DECIDE BY: before genesis; frozen accept rule.
  R-13 [DECIDED 2026-09-16, D10: REJECT at the verifier (after the signature), mirrored at ingress — burn semantics; wallet warns on send.]
       S-072: the nine unguarded small-order anonymous addresses (an anon address is its
       own key; the all-zero one is the E1 pool, closed by S-071) are anyone-can-ACT
       identities: every tx type an anonymous sender may submit (TRANSFER, SHIELD,
       UNSHIELD, CONFIDENTIAL_TRANSFER, ROTATE_AUDIT_KEY, LOG_AUDIT_ACCESS,
       REGISTER_NOTE_KEY) verifies under a forged signature there. Nobody but the
       sender to such an address loses — footgun, not theft. Either reject EVERY tx whose
       anonymous sender key is small-order (the anon arm, one rule — burn semantics,
       an accept rule) or document them as anyone-can-act. DECIDE BY: before genesis.
  R-14 [DECIDED 2026-09-16, D8: zeroth_pool_initial = 0 at genesis; NEF a no-op; §8.5 stays design-not-shipped.]
       S-073: the shipped NEF grants pool/2 to every first-time REGISTER, unconditionally
       — no lottery, no per-block cap, no balance or stake floor (a fee-0 REGISTER needs
       none), so ~log2(pool) fresh names empty the Zeroth pool at zero cost. Under
       DOMAIN_INCLUSION the grants are spendable (theft of protocol funds); under
       STAKE_INCLUSION they are stranded (S-069). The whitepaper §8.5 lottery + cap
       (nef_grant / nef_probability_denom / nef_max_wins_per_block) was never shipped;
       EconomicSoundness.md already flags the rewrite. Owner decision: ship the lottery +
       cap, gate NEF on a stake/balance floor, or set zeroth_pool_initial = 0 at
       genesis (E1 off). DECIDE BY: before genesis (a genesis with a funded pool and the
       shipped rule is a giveaway).
  R-15 [DECIDED 2026-09-16, D11: DESIGN, not accept — tolerate up to floor(K/3) silent members; beyond that a CERTIFIED formation failure (>= ceil(2K/3) eligible-pool signatures, committed on chain, folded into the seed) re-draws the committee at the same height; no halt; in the R-4 + F-c design gate.]
       S-076: two silent committee members halt the height permanently at every K (the
       abort quorum max(2, K-1) is unreachable with K-2 live claimers; the valve re-derives
       the same committee). This — not the committee-selection cadence — is the
       availability lever (design analysis 2026-09-15: per-block selection buys a few
       blocks of delay against a blind two-node flood and nothing against a targeted
       one). Options: a lower claim quorum, or claims from non-committee pool members
       when N(h) > K (accept rules; the S-044 cascade/attribution trade-off), or accept
       the crash-stop bound and say so. The time-bucket / round-marker family is
       REFUTED — do not revive. DECIDE BY: before genesis; frozen accept rule.
  R-16 [DECIDED 2026-09-16, D12: the withholder is SUSPENDED for the existing window, no deduction.]
       S-077: the last Phase-2 revealer can reject one cumulative_rand sample per height
       at zero cost (Phase-2 aborts neither slash nor suspend). Rejection sampling, not
       choice (S-074 removed the assembler's choice). Either a cost for Phase-2 silence
       (revisits the S-044-era "no punishment for Phase-2 timing skew") or accept and
       document. DECIDE BY: before genesis if a cost is wanted (apply-path rule).
  R-17 [DECIDED 2026-09-16, D23] signing_bytes() binds NO chain identity and no expiry
       (src/chain/block.cpp:20-32): a transaction is valid on any chain where (from, nonce)
       matches — testnet-to-mainnet and cross-shard replay (S-103). Decision: bind the
       GENESIS HASH || SHARD ID for every tx type; no expiry field (a released tx still cannot
       be cancelled; the outbox's replace is the recourse). Lands with R-7 (step 6).
  IF UNDECIDED AT GENESIS the default becomes "never", PERMANENTLY, under no-migrations.
  No decision is not a neutral state. As of 2026-09-16 no row is undecided.

OWNER DECISIONS — ALL DECIDED 2026-09-16 (DECISION-LOG 2026-09-16); the problem statements
are kept as the record:
  O-1  DECIDED: option (b) — L2 relocation with a separate L2 bond; L1 stake never slashable;
       plus O-1b: the round-1 abort deduction retired (D4, D13).
       The standing slashing position after b5838fb: L2 relocation (option (b), a
       separate L2 bond with L1 stake never slashable, is the only one of (a)/(b)/(c)
       that does not re-enter consensus), or no consequence at all. Gates R-1, R-8 and
       the S-011/S-013/S-029/BFTSafety T-5.1 re-derivations.
  O-2  DECIDED: RATIFIED as binding (D18b).
       Ratify or narrow the 2026-08-13 "green is not proof" doctrine (352fc52 was
       recorded "at the direction of the session orchestrator ... flagged for owner
       review"; it is applied as binding above).
  O-3  DECIDED: safety first, D2 wire remainder in parallel (D1; ACTIVE FRONT above).
       Order the LIVE CRITICALS (S-055..S-063, SECURITY.md) against the D2 front. The log
       recommends the halts first (84c1447, 3dbe5f2, ddf93eb); ACTIVE FRONT still says D2.
  O-4  DECIDED: REJECTED — value, fees, stake economics and CT stay as designed (D3);
       v2.22 + v2.24 ship together; S-083 closes before CT is enabled anywhere.
       The no-cryptocurrency scope reduction (evaluated 0fe6eda, superseding 8b86d39) and
       its DIRECT CONFLICT with the no-backdoor constraint (6265d34 hazard 2): adopt,
       reject, or scope.
  O-5  DECIDED: E >= 2 on beacon and shards; E = 100 (D17, D2d); no witness-path change.
       epoch_blocks: the committee-selection cadence is genesis-frozen. A per-block
       cadence (E = 1) on SINGLE / cluster deployments buys the targeting window and
       reward fairness, not availability; a DYNAMIC cadence computed from network state
       cannot improve availability either (no committed input moves while a height is
       stalled) and degenerates to the constant 1 wherever it matters (design analysis
       2026-09-15 §13). Pick E at genesis; nothing to build.

AUTHORIZED DESIGN GATES (DECISION-LOG 2026-09-16) — design-and-prove, independent adversarial
review, THEN implementation; each its own increment; numeric caps proposed by the gate with
measured evidence and approved by the owner at review (D24):
  G1  R-4 + F-c + R-15 (+R-16): the pool bound 2K > N(h) at two layers; the certified
      formation-failure re-draw (>= ceil(2K/3) pool signatures, seed fold, attested-silent
      exclusion); Phase-2 and round-1 aborts suspend only. Closes S-054, S-076, S-077, S-086, S-087.
  G2  The V-REG-1 companions: D6 join rule (S-069), D7 exit rule (S-067), D15 rotation (R-6),
      D10 small-order anonymous senders (S-072).
  G3  D9 + D23: empty pq_auth on non-PQ types, the block-byte cap, chain identity in
      signing_bytes (S-057, S-103); S-101 presented with it for approval.
  G4  The O-1 chain: forfeiture removal (LANDED 2026-09-16, export 0016), evidence cap +
      in-block dedup, abort-deduction retirement, re-derivations; then R-8 (S-055), S-089, S-090.
  G5  D14: CT verification off the lock, cache, per-block CT cap, anon-CT ingress (S-065, S-083).
  G6  The EXTENDED closure set (D16): S-093, S-094, R-3, S-064/B3.4, S-088, S-036, S-081, S-096;
      D19b-ii sharding_mode genesis pin lands with the first genesis-hash-changing increment here.
NODE-/CLIENT-LOCAL BACKLOG (D19a, no accept-rule change; each its own gate + review), by
severity: S-078, S-079, S-080, S-085, S-082, S-097, S-100, S-084, S-098, S-099, S-070, S-075,
S-091 (with the D2 src-side keyfile increment), S-063 (delivery layer, D18a). S-102 was
ADJUDICATED + CLOSED 2026-09-16 (step 3, before R-8): reachable at HEAD by a relayer's zero-key
state_root relabel of the head (outside the digest and every validator rule); the depth-1 reorg
is now atomic over an apply throw (node.cpp maybe_reorg_to_locked; gate test-node-reorg-guard,
M1-M4 RED). Open observations from the adjudication (argued from code, NOT closed, need their
own accept-rule increments): a ZERO-root twin of the head shares the digest, skips the S-033
apply gate and is ADOPTED when it wins the tie-break; and `initial_state` on a non-genesis block
is in signing_bytes, outside the digest, ignored by apply and unchecked by the validator — a
free hash-grinding field, so any clean same-digest twin can be made to win and the block hash
is relayer-malleable, not only signer-malleable (DECISION-LOG 2026-09-16 S-102 entry).
