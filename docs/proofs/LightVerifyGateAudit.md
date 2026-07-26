# Light-Client Verifier Gate-Gap Audit

**Status:** open (2026-07-26); **3 autonomous gates CLOSED — LV-1/LV-2 committee-size mode-eligibility now
COMPLETE (inc.1 mechanism + falsify; inc.2 state-root anchor wiring; inc.2b chain-walk wiring — both
live-regressed), 5 confirmed autonomous-safe in backlog, 0 owner-gated.** SIXTH code-surface register in
the falsify-on-mutant series, after
[ProofClaimGateTraceability](ProofClaimGateTraceability.md),
[ConsensusValidatorGateAudit](ConsensusValidatorGateAudit.md) (19/19),
[RpcIngressGateAudit](RpcIngressGateAudit.md), [SnapshotRestoreGateAudit](SnapshotRestoreGateAudit.md),
and [BlockIngressGateAudit](BlockIngressGateAudit.md).

## 0. Surface & method

The **`determ-light` trustless-read verifier** — the CLIENT-SIDE trust boundary. The light client
consumes RPC/archive responses from an **untrusted or MITM server**; its only trust anchors are the
genesis-pinned committee/config and committee-signed `state_root`s. A **soundness gap = the verifier
ACCEPTS a forged proof/value it should reject** → the user is deceived about their balance / a tx's
inclusion / history / a receipt. Tightening the light client's own verification is client-side and
**autonomous-safe** (it is not consensus).

Discovery workflow `wf_4df8efc1-41a` — 5 finders (state-root anchor / inclusion proofs / trustless-read
core / history composites / archive-CT-RPC-decode) → adversarial REFUTE-by-default verifiers that
traced the full CLI flow. **11 findings → 10 CONFIRMED autonomous-safe, 1 REFUTED, 0 owner-gated.**
The surface is genuinely leaky (3 rank-1 anchor-forgery gaps).

## 1. CLOSED — empty-committee anchor forgery (`test-light-verify-empty-committee`, LVS-1)

`verify_block_sigs` (light/verify.cpp) — the **sole committee-signature gate** under
`committee_bound_state_root` (and thus the anchor for every balance/inclusion/history read) — derived
its quorum threshold from the block's **own attacker-controlled** `creators.size()`:
`required = bft ? (2*K+2)/3 : K`. With an empty `creators:[]`/`creator_block_sigs:[]` header, the
membership loop and the signature loop run zero iterations (`valid=0`), the size check is `0==0`, and
`required=0` in **both** MD and BFT modes, so `valid(0) < required(0)` is false and it returned
`ok=true` with **ZERO signatures verified**. `Block::from_json` accepts an empty `creators` array, so
the header is fully attacker-suppliable. A malicious/MITM daemon serves an empty-committee successor
header and forges the committee-attested `state_root` (`committee_verified=true`) with zero sigs —
deceiving the user. A forged **non-empty** block would need real committee keys, so the empty set is
the **unique keys-free forgery**; the empty-committee guard is the load-bearing soundness fix.
Confirmed independently by two finders (state-root-anchor + inclusion-proofs); it is the client-side
sibling of the node-side `beacon-header-empty-committee` rank-1 vuln (owner-gated in RpcIngress).

**Fix (client-side soundness, no node/consensus/wire change):** reject an empty creator set —
`if (b.creators.empty()) { r.detail = "…no creators (empty committee)…"; return r; }`. Every
legitimate committee-signed block carries `K>=1` creators, and genesis (index 0) is routed around this
function by both sinks (`verify_state_root_at` height==0 branch; `verify_chain_walk` skips idx0), so
no honest header regresses.

**Gate** = `test_light_verify_empty_committee.sh` — a FAST, fully-offline harness (hand-built JSON
fixtures; the empty case needs no real crypto, which is the point): NEG-1 empty committee (MD) →
FAIL + exit 1; NEG-2 empty committee (`--bft`) → FAIL + exit 1; CTRL a non-member creator reaches +
fails the membership check (non-vacuity — proves the CLI reaches the real quorum path). **Falsify-on-
mutant** (`if (false && b.creators.empty())`): the mutant prints `OK … verified: 0 sig(s) …
state_root: <forged>` (exit 0) — literally accepting a forged state_root with zero signatures — while
CTRL stays FAIL; a clean directional split on both platforms.

## 1b. CLOSED — anchor-index label not bound (`test-light-verify-state-bundle-anchor-index`, LSB-ANCHOR-INDEX)

`verify-state-bundle` (light/verify_state_bundle.cpp) verifies a **proof-carrying artifact offline**: a
`(namespace, key)` state proof plus the `anchor_block`/`successor_header` pair whose crypto binding
(`successor.prev_hash == compute_hash(anchor)`) is committee-authenticated. The envelope also carries an
`anchor_index` field that the tool read (line 283) and **echoed into the VERIFIED report + JSON**
(`anchor_index: N`) but never bound to anything. The anchor block's own `index` is the first field of the
committee-signed block digest — so it is authenticated — but nothing tied the **displayed** `anchor_index`
label to it. A valid bundle for a real anchor at height `B'` could therefore be **re-labelled**
`anchor_index = B` and the tool would print `VERIFIED … anchor_index: B` for state actually anchored at
`B'`, deceiving the offline verifier about the height. (Same "label not bound to the committee-anchored
value" class as the backlog's LTX-HEIGHT-NOT-BOUND, but file-based and cleanly gateable offline.)

**Fix (client-side soundness, no node/consensus/wire change):** a structural gate placed next to the
existing key-binding gate (before the crypto/genesis gates) requiring the envelope `anchor_index` to equal
`anchor_block.index`. Because the anchor block's index is committee-authenticated by the crypto chain, the
label is then transitively bound. When `anchor_block.index` is absent the check no-ops (the crypto binding
still governs), so no honest bundle regresses.

**Gate** = `test_light_verify_state_bundle_anchor_index.sh` — FAST, fully-offline (hand-built JSON
fixtures; the structural check needs no real crypto, mirroring the key-binding leg): NEG `anchor_index(5)
!= anchor_block.index(1)` → UNVERIFIABLE exit 3 with the exact `anchor_index label … != anchor_block.index`
diagnostic, rejected **before** the genesis-load gate; CTRL a matching `anchor_index(1)==index(1)` passes
the gate and falls through to a later gate (non-vacuity). **Falsify-on-mutant** (`if (false && anchor_index
!= anchor_block_index)`): the NEG bundle falls through to the genesis-load gate (exit 1, no anchor_index
diagnostic), flipping the NEG assert — a clean directional split on both platforms.

## 1c. MECHANISM LANDED (increment 1) — committee-size mode-eligibility gate (`test-light-verify-committee-size`, LV-1 + LV-2)

`verify_block_sigs` (light/verify.cpp) set its MD quorum floor to the block's **own** attacker-controlled
`creators.size()`: `required = creators.size()`. The membership loop only proves each listed creator is IN
the committee; the **count** was never bound to the chain's required signing-committee size. Because
genesis permits `1 <= k_block_sigs <= m_creators`, the committee POOL the light client passes in may be
LARGER than `k_block_sigs`, so a MITM/malicious RPC daemon could serve:
- **(LV-1)** an MD block naming a SINGLE committee member (`creators=[one]` with that member's real
  signature) → `required=1` → a **1-of-K quorum downgrade** the node itself rejects (its `m==k_full`
  eligibility at validator.cpp:127); and
- **(LV-2)** a reduced-quorum `ceil(2K/3)` BFT block on a chain whose genesis has `bft_enabled=false` (a
  mutual-distrust-only chain that never escalates), via the unconditional MD→BFT fallback.

`verify_block_sigs` is the sole committee-sig gate under the state-root / inclusion / history anchors, so
either downgrade lets a MITM forge a committee-attested read the user trusts.

**Fix (client-side; a byte-for-byte mirror of the NODE's `check_block_sigs`, no consensus/wire change):**
when the caller supplies the genesis `k_block_sigs` (a new `expected_k` param, default 0 = not enforced),
`verify_block_sigs` enforces the node's mode-eligibility on the committee-signed `b.consensus_mode`
(mirrors validator.cpp:120-133 + the `bft_enabled` gate at :467-469):
`MD → creators.size()==k_block_sigs`; `BFT → bft_enabled AND creators.size()==bft_committee_size(k)`.
When enforced, the sig-count floor + sentinel-zero tolerance below **also** follow the committee-signed
`b.consensus_mode` (not the caller's `--bft` flag), so a mis-asserted `--bft` on an MD block cannot loosen
its K-of-K quorum to `ceil(2K/3)` (closes the sig-count consistency gap the adversarial review flagged;
NEG-LV1b covers it). **Regression-safety is a proof, not a hope:** any block the node accepted satisfies
the node's `md_ok||bft_ok`, which is exactly this check — so it rejects **no** honest block. A 3-lens
adversarial review (`wf_03db0c50`) returned SHIP on all lenses, 0 blocking/major.

**Increment 1 (this round) landed the mechanism + proved it:** the gate is in `verify_block_sigs`
(guarded by `expected_k>0`) and enforced by the offline `verify-block-sigs` CLI primitive via
`--k-block-sigs N` / `--no-bft-enabled`. **Gate** = `test_light_verify_committee_size.sh` — FAST,
fully-offline (hand-built headers, placeholder sigs; the mode-eligibility gate fires BEFORE the sig loop):
NEG-LV1 (MD 1-of-3) → `genesis k_block_sigs=3`; NEG-LV2a (BFT + `--no-bft-enabled`) → `bft_enabled=false`;
NEG-LV2b (BFT wrong size) → `escalated committee size`; NEG-LV1b (MD block + a sentinel slot under
`--bft`) → `sentinel-zero signature in MD mode` (the sig semantics follow `b.consensus_mode`, not `--bft`);
CTRL (MD 3-of-3) passes the gate and reaches the sig check (`does NOT verify`) — non-vacuity.
**Falsify-on-mutant** — two independent mutants: (i) `if (false && expected_k>0)` neutralizes the
mode-eligibility gate → NEG-LV1/LV2a/LV2b fall through, their diagnostics disappear, those three asserts
flip, all else unchanged; (ii) `sig_bft = bft_mode` neutralizes the sig-count refinement → only NEG-LV1b
flips. Clean directional splits on both platforms.

**Increment 2 (LANDED) — state-root anchor wiring:** threaded `genesis.k_block_sigs` +
`genesis.bft_enabled` into the **state-root anchor** `committee_bound_state_root` (new defaulted
`expected_k`/`bft_enabled` params inserted before the out-pointer, so untouched callers are byte-neutral)
and its **18 call sites** — the 14 `verify-*` / `stake-trustless` / `supply-trustless` command handlers +
`read_account_trustless` (balance) + `run_export_state_bundle` (state-bundle), all of which carry a
genesis directly, plus two one-level cascades whose helper took only a committee (`verify_header_state_root_at`
in account_history, `verify_state_root_at` in verify_state_root — each gained defaulted params threaded from
its genesis-bearing caller). Now every state-root-anchored read (balance / supply / stake / state-bundle /
account / inclusion / history) enforces the node's committee-size mode-eligibility on the anchor's
committee-signed successor. **Validation:** the enforcement path has no FAST-offline falsify (every call
does a live `rpc.call`); the falsify already happened at the `verify_block_sigs` level (inc.1), so inc.2 is
a live-cluster NON-REGRESSION check — 7 core live light tests pass with the enforcement active
(`balance-trustless`, `stake-trustless`, `supply-trustless`, `state-bundle`, `verify-account`,
`committee-at-height`, `verify-state-root` — covering `read_account_trustless`, the direct handlers, the
export path, and BOTH cascade helpers). Regression-safety is the same proof: a node-accepted successor
satisfies `md_ok||bft_ok`, so no honest read regresses.

**Increment 2b (LANDED) — chain-walk wiring:** threaded `expected_k`/`bft_enabled` into the header-only
`verify_chain_walk` (defaulted params after `track_registry`, forwarded to all four per-block
`verify_block_sigs` calls incl. the F2 full-block fallback) via `verify_chain_to_head` +
`verify_chain_from_anchor` (both `.hpp`/`.cpp` + the resume path), and all their callers — the 11 direct
`verify-*`/read handlers (regex) + the 1 `--track-registry` caller + the 4 internal `anchored_head`
callers (which carry `genesis`). So the from-genesis / resume chain walk now enforces the committee-size
mode-eligibility on EVERY walked block header. This closes LV-1/LV-2 for the walk-only commands
(`verify-chain`, etc.) that don't subsequently anchor a state read, and hardens the whole chain-trust for
the reads. Same live-cluster non-regression validation (the walk is exercised by every trustless read +
the resume path); regression-safety is the same proof. LV-1/LV-2 is now enforced on BOTH the state-root
anchor (inc.2) and the full chain walk (inc.2b) — the gate is complete.

## 2. Backlog — confirmed autonomous-safe (ordered; each is a future gate)

| id | rank | file | gap |
|---|---|---|---|
| EXP-1 | 1 | export.cpp | `export-headers --from > 0` anchors the first page to NOTHING (no genesis in a `from>0` range), letting a MITM inject a fabricated/wrong-range archive marked `verified_committee_sigs=true`. Fix mirrors `verify_chain_walk`: require `headers[0].index == from`, reject any `index==0` when `from>0`. |
| LTX-HEIGHT-NOT-BOUND | 2 | verify_tx_inclusion.cpp | never binds the returned block's `index` to the requested `height` — a real committee-signed block at a DIFFERENT height forges an "included at height B" proof. Fix: `if (b.index != height) UNVERIFIABLE`. |
| WATCH-1 | 2 | watch.cpp | `watch-head` prints `state_root`/`head_hash` with `sigs_valid=yes` although the committee sig covers neither (the head has no signed successor). Fix: report a committee-bound `state_root` for `head-1`, label the head's own as unverified. |
| LRPC-1 | 2 | rpc_client.cpp | `RpcClient::read_line` grows its buffer unbounded → a MITM daemon OOM-crashes the reader. Fix: a light-local 16 MiB `kLightRpcMaxLineBytes` cap (the client-side sibling of the RpcIngress readline cap). |
| AH-1 | 3 | account_history.cpp | the genesis row (h=0) reports the served `state_root` FIELD, which `anchor_genesis` never binds (block 0 hash is only string-compared, never recomputed). Fix: route idx==0 through `committee_bound_state_root` or derive the genesis `state_root` locally. |

## 3. REFUTED

**LARCH-1** (`verify-archive` accepts a committee-sig-stripped archive): refuted on verification — a
later bind/verify in the flow already catches the stripped-sig case.

## 4. Non-claim

Each finding establishes that the light verifier ACCEPTS an input it should reject (or is
DoS-crashable), not that a specific chain has been exploited. Every fix is client-side; none changes
the node, consensus, wire format, or what the chain accepts. Cross-references
`RpcIngressGateAudit.md` (the node-side `beacon-header-empty-committee` sibling of §1) and the F-6/F-7
light lessons in `ProofClaimGateTraceability.md`.
