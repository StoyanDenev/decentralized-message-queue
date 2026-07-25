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
gaps** (one pure-test, four missing-bound) — **4 CLOSED** (#3 MEM-tx-sig-admit §3a, #6
ING-chain-summary-last_n-uncapped §3b, #7 RPC-readline-unbounded §3c, plus the follow-up-promoted #8
SNAP-header-count-uncapped §3d) = the **entire autonomous DoS-hardening track**; the 2 remaining ranked rows
(#4/#5) touch the accept path and are OWNER-GATED. Each is invisible to the current suite (no test drives the
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

Closed one per directive, cheapest-value-first. **The autonomous read-only DoS-hardening track is CLOSED:**
the three ranked rows #3 (MEM-tx-sig-admit) §3a, #6 (ING-chain-summary-last_n-uncapped) §3b, #7
(RPC-readline-unbounded) §3c, **plus the follow-up-promoted row #8 (SNAP-header-count-uncapped) §3d** — the
snapshot-request analog of #6, found during #7's close and clamped the same way. The **only remaining rank-2
rows, #4 and #5, touch the gossip/sync accept path** → they are OWNER-GATED (a production accept-rule change
is not shipped autonomously) and are **presented to the owner**, alongside the two rank-1 consensus vulns
(§2). **No autonomous rank-2 work remains; NEXT (owner) = #4.**

| # | id | file:line | property (accept-widening consequence) | surviving mutation | class | val |
|---|---|---|---|---|---|---|
| 3 | MEM-tx-sig-admit | node.cpp:2819 (on_tx) + :4453 (rpc_submit_tx) → verify_tx_signature_locked | a tx must carry a valid sender sig before mempool admission — else forged-sender txs poison every node's mempool (production stall / cap exhaustion) | `if (false && !verify_tx_signature_locked(tx))` at :2819 + delete the :4453 throw | ✅ **CLOSED** (test-rpc-tx-sig-admit) | 2 |
| 4 | GOSSIP-on_tx-tx-hash-not-rechecked | node.cpp:2843 (on_tx) vs the present-but-unpinned :4438 (rpc_submit_tx) | on_tx never recomputes `tx.hash==compute_hash()`, so a validly-signed tx can enter `tx_store_` under a forged key (light-client inclusion-proof false-negatives; on sharded, a cross-shard-receipt front-run → targeted fund-lock) | neuter the :4438 recompute; add `if (tx.hash != tx.compute_hash()) return;` to on_tx | 1-line fix + test | 2 (borderline 2/3) |
| 5 | STATUS-height-unbounded-sync-stall | node.cpp:3204 (on_status_response) | a peer-reported height is stored verbatim with no plausibility bound; one `UINT64_MAX` STATUS_RESPONSE pins the victim in SYNCING forever (block production halts; `peer_heights_` never pruned) → remote hit-and-run liveness DoS | add + delete `if (height > chain_.height()+MAX_SYNC_LEAD) return;` (or same-genesis median) | clamp + test | 2 |
| 6 | ING-chain-summary-last_n-uncapped | node.cpp:3667-3672 (rpc_chain_summary) | the sole pagination handler missing the 256-page cap its siblings enforce (rpc_headers/on_get_chain); `last_n>=height` re-hashes + copies the ENTIRE chain under one state_mutex_ read lock (per-request-work DoS the token bucket doesn't bound) | neuter the clamp in `chain_summary.hpp` (`if (false && last_n > kChainSummaryPageMax)`) → over-cap asserts flip | ✅ **CLOSED** (test-chain-summary-cap) | 2 |
| 7 | RPC-readline-unbounded | iocp_transport.cpp:329 + reactor_transport.cpp:241 (read_line `carry_.append`) | a single RPC line has no size ceiling; a client streaming bytes with no `\n` grows `carry_` unbounded BEFORE rate-limit/auth (both per-completed-line) → pre-auth OOM. Gossip ingress IS bounded (kMaxFrameBytes=16MB); the RPC read path is the asymmetric outlier | `if (false && carry_.size() > kMaxRpcLineBytes)` in each transport → the 64 MiB-flood assert flips (read_line consumes all, returns true) | ✅ **CLOSED** (test-net-native 6e, both transports) | 2 |
| 8 | SNAP-header-count-uncapped | chain.cpp:2367 (serialize_state) ← on_snapshot_request (gossip) + rpc_snapshot (RPC) | the snapshot "headers" array walked an unbounded client `header_count`; `header_count>=height` forced start=0 → `to_json()` over the ENTIRE chain per request (the snapshot analog of #6; serialize_state backs ONLY the two external snapshot paths — `Chain::save` persists via its own path — so this is pure DoS, no persistence impact) | neuter the clamp (`if (false && header_count > kSnapshotHeaderMax)`) → over-cap asserts flip to the whole chain | ✅ **CLOSED** (test-snapshot-header-cap) | 2 |

---

### 3a. CLOSED — MEM-tx-sig-admit (`test-rpc-tx-sig-admit`)

The mempool signature-admission gate is now pinned on **both** ingress call sites. `verify_tx_signature_locked`
runs in production on `on_tx` (gossip, silent drop) and `rpc_submit_tx` (RPC, hard throw); the negative
behavior was previously untested. Gate = a new `test-rpc-tx-sig-admit` subcommand that builds an in-process
M=K=1 Node ("node0", genesis-registered + funded) over a `VirtualTransport` — a fresh node per leg so the
`mempool_size` observable is independent (replace-by-fee / nonce dedup would otherwise cross-contaminate).
A validly-signed TRANSFER is ADMITTED (queued, `mempool==1`); the same tx with one `tx.sig` byte flipped
(after `compute_hash`, which excludes the sig, so it survives the hash-recompute and reaches the sig gate) is
REJECTED — `rpc_submit_tx` throws `"submitted tx signature verification failed"`, and `on_tx` (driven via a
new byte-neutral `on_tx_for_test` seam) SILENTLY drops it (`mempool` unchanged). **Each call site was
falsified INDEPENDENTLY**: `if (false && !verify_tx_signature_locked(tx))` at `on_tx:2819` flips only the
gossip leg RED; the same neutering of the `rpc_submit_tx:4453` throw flips only the RPC leg; the control and
the other path stay GREEN in each pass. Zero consensus-code change (the guard already ran in production) —
this round establishes the reusable in-process Node-ingress harness for the remaining rank-2 rows.

### 3b. CLOSED — ING-chain-summary-last_n-uncapped (`test-chain-summary-cap`)

`Node::rpc_chain_summary(last_n)` (node.cpp:3667) surfaces the trailing `last_n` blocks. Its sibling history
handlers all clamp to a 256-page anti-DoS cap — `on_get_chain:3119` (`if (count > 256) count = 256`),
`rpc_headers:3445` (`HEADERS_PAGE_MAX = 256`) — but chain_summary was the **lone reader** that walked an
unbounded client-supplied `last_n` (dispatched from `rpc.cpp` as `params.value("last_n", uint32_t{10})`). A
`last_n >= height` forced `start = 0` → a full-chain walk recomputing `compute_hash()` on **every** block
under the `state_mutex_` read lock: a per-request-**work** amplification the rate-limiter's token bucket
(which meters requests, not units of work) does not bound.

**Fix (minimal, mirrors NC-8's `scan_enotes` free-function convention).** A new pure `inline` helper
`chain::chain_summary_start(height, last_n)` in `include/determ/chain/chain_summary.hpp` clamps `last_n` to
`kChainSummaryPageMax = 256` and returns the window start; `rpc_chain_summary` replaces its one unclamped
`start` line with a call to it (`height - start <= 256`). Read-only, no state/gossip/consensus touch —
byte-neutral for the default `last_n = 10` and every `last_n <= 256`; only an abusive `last_n > 256` now
returns a 256-block window instead of the whole chain. **Autonomous-safe** (pure DoS hardening, no accept-rule
change), unlike #4/#5. Gate = `test-chain-summary-cap`: builds a real 301-block bare Chain (genesis + 300
empty blocks) and does the REAL block walk (`c.at` over `[start, height)`), asserting `last_n=10→10`,
`256→256` (boundary honored exactly), and `257/1000/UINT32_MAX→256` (clamped), plus
`start(UINT32_MAX)==height−256` (bounded, not restarted at 0). **Falsify-on-mutant**: neutering the clamp
(`if (false && last_n > kChainSummaryPageMax) …`) flips EXACTLY the four over-cap asserts RED while the
boundary/small/short/empty asserts stay GREEN — a targeted counter-delta, both platforms.

### 3c. CLOSED — RPC-readline-unbounded (`test-net-native` case 6e, both transports)

`Connection::read_line` accumulates socket bytes into `carry_` until it sees a `'\n'`, then returns that
line. Both native backends — `IocpConnection::read_line` (iocp_transport.cpp:329) and
`ReactorConnection::read_line` (reactor_transport.cpp:241) — appended to `carry_` with **no size ceiling**, so
a client that streams bytes with no newline grows `carry_` without bound BEFORE the request ever reaches
rate-limit or auth (both per-completed-line) — a pre-auth OOM. The gossip framing path is already bounded
(`messages.hpp` `kMaxFrameBytes = 16 MiB`, S-022); the RPC line path was its asymmetric, unbounded
counterpart.

**Fix (minimal, one shared constant).** A single `kMaxRpcLineBytes = 16 MiB` in `transport.hpp` (symmetric
with the gossip `kMaxFrameBytes`; a legitimate JSON-RPC line tops out near 2 MiB given the tiny tx-payload
caps, so 16 MiB is ~8× headroom). Both `read_line` loops add `if (carry_.size() > kMaxRpcLineBytes) return
false;` immediately after the append — dropping the session (fail-closed, exactly as an EOF/recv error already
does). Pure transport-layer DoS hardening below the RPC dispatch/auth layer: no consensus / accept-rule /
wire-format impact (autonomous-safe). Gate = a new case **6e** appended to the existing `test-net-native`
socket fixture (no new subcommand/wrapper — reuses the real loopback `Connection` pair, so **each platform's
FAST run exercises its own native transport**: IOCP on MSVC, epoll/reactor on WSL GCC). A writer floods 64 MiB
of newline-less bytes then a single `'\n'`; with the ceiling `read_line` drops the session after ~16 MiB
(bytes delivered `< 64 MiB`), without it `read_line` consumes the whole flood and returns the line at 64 MiB —
the delivered-bytes gap is the falsify signal (and the trailing `'\n'` ensures the mutant returns rather than
hangs). **Falsified INDEPENDENTLY per transport**: `if (false && carry_.size() > kMaxRpcLineBytes)` flips only
the 6e flood assert while the small-line `read_line` asserts stay GREEN — on MSVC (iocp) and on WSL GCC
(reactor).

### 3d. CLOSED — SNAP-header-count-uncapped (`test-snapshot-header-cap`)

The snapshot analog of #6, found while closing #7 (the "follow-up surfaces" list flagged
`on_snapshot_request(header_count)` against a crafted peer value). `Chain::serialize_state(header_count)`
(chain.cpp:2367) builds the snapshot's trailing `"headers"` array from a **client-supplied** `header_count`,
via the exact unbounded pattern #6 had: `start = (total > header_count) ? total - header_count : 0`. It is
reachable from **both** external snapshot paths — `on_snapshot_request` (gossip, node.cpp:2300) and
`rpc_snapshot` (RPC, node.cpp:4533, default 16) — so a `header_count >= height` forces `start = 0` →
`to_json()` over the ENTIRE chain per request (a per-request-work DoS, heavier than #6 since the whole state
also serializes). **Not dual-use**: `serialize_state` backs ONLY those two external paths — full-chain disk
persistence uses `Chain::save`'s own block loop (chain.cpp:2687), not `serialize_state` — so capping the
header window has no persistence impact.

**Fix**: clamp `header_count` to a file-local `kSnapshotHeaderMax = 256` at the top of the headers loop (the
same 256-page cap `on_get_chain` / `rpc_headers` / `chain_summary` enforce). Read-only, no state/gossip/
consensus touch; byte-neutral for every existing snapshot golden (all serialize with `header_count ≤ 16`), so
only an abusive `> 256` is bounded — the requester default is 16, ~16× below the cap, so no legitimate
snapshot truncates. Gate = `test-snapshot-header-cap`: builds a real 301-block bare Chain and asserts
`serialize_state(hc)["headers"].size()` — `16→16`, `256→256` (boundary), `257/1000/UINT32_MAX→256` (clamped),
and a short 11-block chain returns all 11 regardless. **Falsify-on-mutant**: neutering the clamp
(`if (false && header_count > kSnapshotHeaderMax) …`) flips EXACTLY the three over-cap asserts while the
default/boundary/short-chain asserts stay GREEN — a targeted counter-delta, both platforms.

## 4. Completeness / follow-up

Deduped 9→7 (RPC-readline == C1; GOSSIP-tx-hash == C2). A follow-up audit should still deep-read surfaces the
coverage finder flagged but did not clear (none produced a confirmed gap here): `on_block` +
apply-block equivocation-assembly; the consensus-chatter handlers (`on_contrib`, `on_block_sig`,
`on_abort_claim`, `on_abort_event` — partly covered by the consensus-validator register, not re-verified
here); the acknowledged **B2c.2-minimal** secondary beacon weakness (`node.cpp:1971`: non-empty creators
verified against the shard's OWN registry, so one registered node can self-sign a sole-creator header —
worth its own gate); `on_cross_shard_receipt_bundle` relay amplification + unverified-`src_block` buffering
(confirm the deferral to the sister VAL-csr / VAL-inbound-f2 gates holds); ~~`on_snapshot_request(header_count)`
against a crafted peer value~~ — **CLOSED as row #8 §3d** (SNAP-header-count-uncapped); whether
`on_snapshot_response`/`on_headers_response` are truly never wired on
the full node; and the lower-confidence `verify_auth` empty-expected-MAC observation (rpc.cpp:123-128 — the
internal-failure trigger is not attacker-forceable so it is unregistered, but it contradicts the
`fails CLOSED` comment and merits a defense-in-depth assertion).

Cross-references [`ConsensusValidatorGateAudit.md`](ConsensusValidatorGateAudit.md) (the sibling
block-acceptance register). Any gate confirmed here is closed by the same falsify-on-mutant method; a
consensus/wire-format fix (§2) is owner-gated.
