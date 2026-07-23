# RPC / Peer-Gossip Ingress Gate-Gap Audit

**Status:** discovery + adversarial-verification complete (2026-07-23). **Third register** after
[`ProofClaimGateTraceability.md`](ProofClaimGateTraceability.md) (docs-claim traceability) and
[`ConsensusValidatorGateAudit.md`](ConsensusValidatorGateAudit.md) (block-acceptance `validate()`/apply,
19/19 CLOSED). This one covers the **live external-ingress surface**: how untrusted input (a remote RPC
client or a malicious mesh peer) enters the node — `src/rpc/rpc.cpp` (RPC server: parse → rate-limit →
HMAC `verify_auth` → dispatch), the `node_.rpc_*` handlers, and the `net::MsgType` peer-gossip handlers in
`src/node/node.cpp`.

**Method.** A 2026-07-23 ultracode discovery Workflow (`wf_bc523f34-2af`: 6 finders → adversarial
REFUTED-by-default verifier per candidate → judge; 22 agents, ~2.4M tokens) surfaced 15 raw candidates;
adversarial verification confirmed 7 after dedup and refuted the rest (e.g. the pre-HELLO role-filter skip
grants no capability beyond the trivially-available self-declared-role path; `dapp_messages` paging is
bounded). **The two rank-1 findings were independently re-verified against source by hand** before this
register was written.

**NON-CLAIM / scope.** This is an *accept-widening* audit — a check whose removal (or absence) lets a remote
client/peer do something it should not, invisible to the honest-direction suite. The chain is **pre-launch**
(no live network), so these are pre-launch hardening findings, not live-exploit disclosures. The
authorization spine is **sound**: uniform rate-limit → parse → constant-time HMAC → dispatch; fail-closed
`try/catch`; `dapp_subscribe` behind both rate-limit AND auth (SS-5). No authz bypass exists in `rpc.cpp`
itself. The gaps are on the unauthenticated **gossip** surface or are missing per-request/per-line **bounds**.

---

## 1. Surface verdict

MOSTLY well-guarded but NOT clean: **7 confirmed accept-widening gaps** in two classes —
**(A) two rank-1 remote-unauthenticated consensus-integrity holes** on the peer-gossip paths where a
self-declared-role or zero-consent message is trusted, and **(B) five rank-2 resource / liveness / integrity
gaps** (one pure-test, four missing-bound). Each is invisible to the current suite (no test drives the
adversarial input), so each is a clean falsify-on-mutant candidate.

---

## 2. OPEN consensus-integrity findings (rank-1) — **OWNER-GATED (fix is a consensus/wire change)**

These require production changes to consensus/slashing behavior. Per the project's consensus-change
discipline (defer security/consensus design to the owner, as with every prior S-0xx decision), they are
**NOT** closed autonomously — they are escalated for an owner decision on the fix. The test-only backlog in
§3 is closed by the falsify-on-mutant method WITHOUT touching consensus code.

### 2a. EQV-INGRESS-height-unbound-forged-slash — `validator.cpp:378-402` (+ `node.cpp:1902` ingress) — **value_rank 1, HIGHEST severity**

**Property.** The two signed digests in an equivocation proof must be bound to the SAME height (both must be
`compute_block_digest` of blocks at one `ev.block_index`).
**Gap.** `check_equivocation_events` accepts on `digest_a != digest_b && sig_a != sig_b && equivocator
resolvable && verify(sig_a) && verify(sig_b)` (:382/:385/:389/:394/:397) — it **never asserts the two
digests are same-height**. The digests are opaque `Hash`es; `ev.block_index` (free-text) only feeds the
epoch/dedup, not the digests. Since `compute_block_digest` binds `b.index` (producer.cpp:694), a validator
V's NORMAL per-height signatures over two DIFFERENT heights are each distinct-and-valid. An attacker harvests
`(compute_block_digest(block_H1), block_H1.creator_block_sigs[V])` and the H2 pair from public finalized
blocks and submits them as evidence; the predicate ACCEPTS non-equivocation. At apply
(`chain.cpp:1813-1819`) V's ENTIRE locked stake is forfeited and V deregistered — a **remote unauthenticated
forge-a-slash** of an honest validator's full stake. The sibling `on_abort_event` DOES bind
`block_index`/`round`/`prev_hash`; the equivocation path is the anomaly. In MUTUAL_DISTRUST every committee
member signs every block, so every validator's cross-height signatures are harvestable; the
`(equivocator, block_index)` dedup is bypassed by varying the free-text `ev.block_index`.
**Reachable by.** Any unauthenticated remote peer, any role (`EQUIVOCATION_EVIDENCE` is role-filter-exempt,
gossip.cpp:118-120) — a single crafted message; also via `rpc_submit_equivocation`.
**Corroboration.** The *positive control* of the already-shipped `test-equivocation-evidence` /
EQV-sig-verify-forged-slash gate (two distinct digests signed by one key → ACCEPTED) is itself the attack
shape — the shipped sig-verify gate pins authenticity but not same-height binding.
**Fix direction (owner-gated).** Extend `EquivocationEvent` to carry the two conflicting block headers (or
enough to recompute `compute_block_digest`); the verifier recomputes both digests and asserts
`header_a.index == header_b.index == ev.block_index`. This is a **wire-format / struct change** to slashing
evidence. Once the struct binds height, pin it via the existing `check_equivocation_events_for_test` seam
(genuine cross-height pairs → REJECT; honest same-height → ACCEPT; falsify-on-mutant on the height-equality
assertion).

### 2b. INGRESS-beacon-header-empty-committee-vacuous-kofk — `node.cpp:1973-2007` (`on_beacon_header`) — **value_rank 1**

**Property.** A gossiped beacon header must carry a real, non-empty, correctly-derived K-of-K committee
signature set before it seeds the shard's beacon anchor.
**Gap.** With `creators = []`: the size-match `creator_block_sigs.size() == creators.size()` (:1973) holds at
`0 == 0`; the per-creator verify loop (:1981) never runs so `signed_count` stays 0; the completeness check
`signed_count != creators.size()` (:2000) is `0 != 0` → false. All three pass **vacuously**, and the
zero-consent header with attacker-chosen `cumulative_rand` is stored (`beacon_headers_.push_back`, :2007).
That value is the SHARD validator's external epoch-rand provider (node.cpp:382-391) seeding epoch committee
selection, so a forged anchor biases committee selection. The audited sibling
`verify_shard_tip_committee_sig_root` guards exactly this (`expected_k >= 1`); `on_beacon_header` is the
outlier missing the size-binding.
**Reachable by.** Any untrusted mesh peer: `BEACON_HEADER` is routed only from a peer whose
`chain_role()==BEACON`, but role is self-declared in the unauthenticated HELLO payload (gossip.cpp:182-183);
fresh-shard bootstrap skips the prev_hash check (:1955), so an index-1 poison needs no chaining.
**Fix direction (owner-gated but small).** Add `if (b.creators.empty()) return;` plus a
`signed_count >= reg-derived required_k` floor, reusing the `verify_shard_tip_committee_sig_root`
size+derivation pattern. Small blast radius (rejects a malformed gossip message honest producers never send),
but it is a **consensus-relevant accept rule on the gossip path**, so it carries an owner sign-off. Pin via a
new byte-neutral `on_beacon_header_for_test` seam + a `test-beacon-header-committee` subcommand
(empty-committee header → NOT stored; falsify-on-mutant on the empty-check).

---

## 3. The FAST-gateable backlog (rank-2 — a ranked, mostly test-or-small-hardening set)

Closed one per directive, cheapest-value-first. **#3 is a PURE TEST gap** (the guard already runs in
production — zero consensus-code change, the direct analog of the closed `VAL-tx-sender-sig:685`) and is the
recommended first closure. #4–#7 add a missing bound (a one-line clamp/recompute/ceiling matching an existing
sibling pattern) + its falsify-on-mutant test; #4/#5 touch the gossip/sync accept path (present to the owner),
#6/#7 are pure DoS hardening.

| # | id | file:line | property (accept-widening consequence) | surviving mutation | class | val |
|---|---|---|---|---|---|---|
| 3 | MEM-tx-sig-admit | node.cpp:2819 (on_tx) + :4453 (rpc_submit_tx) → verify_tx_signature_locked | a tx must carry a valid sender sig before mempool admission — else forged-sender txs poison every node's mempool (production stall / cap exhaustion) | `if (false && !verify_tx_signature_locked(tx))` at :2819 + delete the :4453 throw | **PURE TEST** (guard exists) | 2 |
| 4 | GOSSIP-on_tx-tx-hash-not-rechecked | node.cpp:2843 (on_tx) vs the present-but-unpinned :4438 (rpc_submit_tx) | on_tx never recomputes `tx.hash==compute_hash()`, so a validly-signed tx can enter `tx_store_` under a forged key (light-client inclusion-proof false-negatives; on sharded, a cross-shard-receipt front-run → targeted fund-lock) | neuter the :4438 recompute; add `if (tx.hash != tx.compute_hash()) return;` to on_tx | 1-line fix + test | 2 (borderline 2/3) |
| 5 | STATUS-height-unbounded-sync-stall | node.cpp:3204 (on_status_response) | a peer-reported height is stored verbatim with no plausibility bound; one `UINT64_MAX` STATUS_RESPONSE pins the victim in SYNCING forever (block production halts; `peer_heights_` never pruned) → remote hit-and-run liveness DoS | add + delete `if (height > chain_.height()+MAX_SYNC_LEAD) return;` (or same-genesis median) | clamp + test | 2 |
| 6 | ING-chain-summary-last_n-uncapped | node.cpp:3667-3672 (rpc_chain_summary) | the sole pagination handler missing the 256-page cap its siblings enforce (rpc_headers/on_get_chain); `last_n>=height` re-hashes + copies the ENTIRE chain under one state_mutex_ read lock (per-request-work DoS the token bucket doesn't bound) | insert then delete `if (last_n > 256) last_n = 256;` at :3668 | 256-clamp + test | 2 |
| 7 | RPC-readline-unbounded | iocp_transport.cpp:329 + reactor_transport.cpp:241 (read_line `carry_.append`) | a single RPC line has no size ceiling; a client streaming bytes with no `\n` grows `carry_` unbounded BEFORE rate-limit/auth (both per-completed-line) → pre-auth OOM. Gossip ingress IS bounded (kMaxFrameBytes=16MB); the RPC read path is the asymmetric outlier | insert then delete `if (carry_.size() > (64u<<20)) return false;` after each append | ceiling (both transports) + test | 2 |

---

## 4. Completeness / follow-up

Deduped 9→7 (RPC-readline == C1; GOSSIP-tx-hash == C2). A follow-up audit should still deep-read surfaces the
coverage finder flagged but did not clear (none produced a confirmed gap here): `on_block` +
apply-block equivocation-assembly; the consensus-chatter handlers (`on_contrib`, `on_block_sig`,
`on_abort_claim`, `on_abort_event` — partly covered by the consensus-validator register, not re-verified
here); the acknowledged **B2c.2-minimal** secondary beacon weakness (`node.cpp:1971`: non-empty creators
verified against the shard's OWN registry, so one registered node can self-sign a sole-creator header —
worth its own gate); `on_cross_shard_receipt_bundle` relay amplification + unverified-`src_block` buffering
(confirm the deferral to the sister VAL-csr / VAL-inbound-f2 gates holds); `on_snapshot_request(header_count)`
against a crafted peer value; whether `on_snapshot_response`/`on_headers_response` are truly never wired on
the full node; and the lower-confidence `verify_auth` empty-expected-MAC observation (rpc.cpp:123-128 — the
internal-failure trigger is not attacker-forceable so it is unregistered, but it contradicts the
`fails CLOSED` comment and merits a defense-in-depth assertion).

Cross-references [`ConsensusValidatorGateAudit.md`](ConsensusValidatorGateAudit.md) (the sibling
block-acceptance register). Any gate confirmed here is closed by the same falsify-on-mutant method; a
consensus/wire-format fix (§2) is owner-gated.
