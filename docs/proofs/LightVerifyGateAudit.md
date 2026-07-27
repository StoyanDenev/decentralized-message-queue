# Light-Client Verifier Gate-Gap Audit

**Status:** COMPLETE (2026-07-26); **8 of 8 autonomous gates CLOSED, 0 backlog, 0 owner-gated — LVS-1
empty-committee, LSB anchor-index, LV-1/LV-2 committee-size mode-eligibility (inc.1 mechanism + falsify;
inc.2 state-root anchor wiring; inc.2b chain-walk wiring — both live-regressed), EXP-1 archive range-label
binding, LRPC-1 read_line DoS cap, LTX-HEIGHT-NOT-BOUND tx-inclusion index binding, WATCH-1 tip-state_root
relabel, and AH-1 genesis-row state_root not echoed. All FAST-offline falsify-on-mutant, both platforms.**
SIXTH code-surface register in
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

## 1d. CLOSED — archive range-label not bound (`test-light-verify-archive-range-bind`, EXP-1)

`verify-archive` (light/verify_archive.cpp) verifies an **export-headers archive offline**: a `genesis_hash`
+ a `headers[]` array whose prev_hash chain and per-header committee sigs (step 4) it re-checks. The archive
also carries self-declared `from` / `count` fields, and the summary (step 5) prints
`range: [from, from+count)` from them — but **nothing bound those DISPLAYED labels to the headers actually
present**. So a MITM/archive-forger could serve a genuinely committee-signed slice — say the real headers for
indices `[500..510]` — yet stamp `from=0, count=1000`, and verify-archive would print `range: [0, 1000)` for
content that actually covers `[500, 511)`, deceiving the auditor about WHICH range was verified. (Same
"displayed label not bound to committee-anchored content" class as §1b LSB-ANCHOR-INDEX; the backlog listed
this as EXP-1 with `file: export.cpp`, but the fix belongs in the VERIFIER — fixing only the honest producer
does nothing against a MITM who controls the archive bytes.) This also subsumes the backlog's `index==0 when
from>0` sub-case: if `from>0` but `headers[0].index==0`, the `from != headers[0].index` gate fires.

**Fix (client-side soundness, no node/consensus/wire change):** a structural gate placed BEFORE the
genesis/crypto gates (right after the records-nonempty check) requiring the declared `from` to equal
`headers[0].index` and the declared `count` to equal the number of records. Because each non-genesis
header's `index` is committee-authenticated by the step-4 sig check (the block digest's first field), the
displayed labels are transitively bound to committee-authenticated content. `export-headers` always writes
`from == first_index` and `count == size`, so no honest archive regresses; the `contains` guards keep a
legacy field-less archive working (the crypto binding below still governs it).

**Gate** = `test_light_verify_archive_range_bind.sh` — FAST, fully-offline (hand-built JSON fixtures; the
structural check needs no real crypto and fires before the genesis-load step, so a nonexistent `--genesis`
suffices): NEG-from `from(0) != headers[0].index(5)` → reject (exit 1) with the exact `declared from=0 !=
headers[0].index=5` diagnostic; NEG-count `count(99) != #records(1)` → reject with the exact `declared
count=99 != actual header count=1` diagnostic; CTRL `from(5)==index(5), count(1)==#records(1)` passes the
range gate and falls through to a later gate (genesis-load on the nonexistent `--genesis`) — non-vacuity.
**Falsify-on-mutant** (`if (false && …)` on BOTH range checks): NEG-from + NEG-count fall through to the
genesis-load gate (no `declared` diagnostic), flipping both NEG asserts while CTRL is unchanged — a clean
directional split on both platforms.

## 1e. CLOSED — read_line unbounded → MITM OOM (`selftest-readline-cap`, LRPC-1)

`RpcClient::read_line` (light/rpc_client.cpp) accumulated `recv()` bytes into `inbuf` until it saw a `'\n'`
— with **no upper bound**. The light client talks to an untrusted / MITM daemon (this surface's whole
premise); a malicious daemon that streams an endless newline-less body grows `inbuf` without limit until the
client **OOM-crashes** — a trivial remote DoS. This is the client-side sibling of the node-side ingress
readline cap already shipped in `RpcIngressGateAudit.md` (`net::kMaxRpcLineBytes`).

**Fix (client-side, no wire/consensus change):** a light-local `kLightRpcMaxLineBytes = 16 MiB` cap. The
newline-scan + cap were factored into a pure `read_line_capped(inbuf, fill)` core with the byte source
**injected** (`fill` appends bytes and returns false on EOF/error), so the cap is **FAST-offline
falsifiable with no socket**; the socket `read_line` is now a thin wrapper whose `fill` does one `recv()`.
When `inbuf` exceeds the cap without a newline the core throws a `runtime_error` (which the command handler
already surfaces as a clean error) instead of growing toward OOM. Behaviour is byte-identical for every
response under 16 MiB, and every legitimate daemon response (state proof / header / committee list / paged
history) is far under it, so nothing regresses.

**Gate** = `test_light_rpc_readline_cap.sh` — FAST, fully-offline (the determ-light `selftest-readline-cap`
subcommand drives `read_line_capped` with a synthetic `fill`, no daemon): CTRL-1 a normal newline-terminated
line is returned + remainder buffered; CTRL-2 an under-cap newline-less stream that EOFs returns `nullopt`
(the cap does **not** false-trip on a legitimate short response); NEG an endless newline-less stream is
aborted at the 16 MiB cap with bounded memory. **Falsify-on-mutant** (`if (false && inbuf.size() > cap)`):
**only** the NEG assert flips (the stream is no longer aborted → it EOFs to `nullopt` with no cap
diagnostic), both CTRLs stay green — a clean directional split on both platforms.

## 1f. CLOSED — tx-inclusion height not bound (`selftest-tx-inclusion-height`, LTX-HEIGHT-NOT-BOUND)

`verify_tx_inclusion` (light/verify_tx_inclusion.cpp) asks the `block` RPC for `index==height`, verifies the
returned block's committee sigs over its digest (which binds the block's OWN `index`), recomputes `tx_root`,
cross-checks the body, and answers membership — but it **never asserted the returned block's `index` equals
the requested `height`**, and it reports the verdict at the requested height (`res.height`). Critically it
anchors on the **static genesis committee** (`build_genesis_committee`), so a real committee-signed block from
ANY height passes the sig check. A hostile/MITM daemon therefore returns a real committee-signed block from a
DIFFERENT height `B'` that contains the queried tx: every check (committee sigs, `tx_root`, body bijection)
passes, and the tool prints `INCLUDED … height: <requested>` while the tx is actually at `B'` — a relabel that
deceives the caller about WHICH height the tx was included at. (Same "displayed label not bound to committee-
anchored content" class as §1b LSB-ANCHOR-INDEX and §1d EXP-1.)

**Fix (client-side soundness, no node/consensus/wire change):** a structural gate placed right after the block
parse (BEFORE the committee-sig anchor) requiring `b.index == height`. `b.index` is the first field of the
committee-signed block digest (verified in step 2 for `B>0`, bound by `compute_genesis_hash` for `B==0`), so
requiring the match binds the reported height to committee-authenticated content. An honest daemon returns the
block AT the requested index (`b.index == height`), so no honest query regresses. To make the gate FAST-offline
falsifiable, the RPC fetch was split out of a pure core `verify_tx_inclusion_from_block(blk_json, …)` with the
block JSON **injected**; `verify_tx_inclusion` is now a thin wrapper that fetches block `height` (handling the
out-of-range / RPC-error cases) then delegates to the core.

**Gate** = `test_light_verify_tx_inclusion_height.sh` — FAST, fully-offline (the determ-light
`selftest-tx-inclusion-height` subcommand drives the core with a hand-built block, no daemon): NEG a block whose
own `index(500) != height(100)` → UNVERIFIABLE at the index-binding gate with the exact `block index binding
failed … index=500 … requested height=100` diagnostic, BEFORE the committee-sig anchor; CTRL a matching
`index(100)==height(100)` passes the gate and reaches the committee-sig anchor (fails on the empty committee) —
a positive non-vacuity check robust against a parse-failure vacuous pass. **Falsify-on-mutant** (`if (false &&
b.index != height)`): ONLY the NEG assert flips (the mismatched block reaches the sig anchor, no index
diagnostic); CTRL stays green — a clean directional split on both platforms.

## 1g. CLOSED — watch-head tip state_root presented as verified (`selftest-watch-label`, WATCH-1)

`watch-head` (light/watch.cpp) polls only the chain TIP and printed its `state_root` — read from the daemon's
self-declared header field — next to `sigs_valid=yes`. But the committee signature authenticates the block
DIGEST (`light_compute_block_digest`: index / prev_hash / tx_root / creators / creator_tx_lists / F2 roots),
which **excludes** `state_root`, and the tip has **no committee-signed successor** to anchor it (a block's
state_root is only committee-authenticated once a later block commits to it via `prev_hash == compute_hash`).
So a hostile/MITM daemon can swap the tip's `state_root` field to a forged value — the digest is unchanged, so
the K committee sigs still verify — and the operator trusts a root the committee never signed. head_hash is
likewise the daemon's self-declared id (not recomputed). Same "displayed value not bound to committee-anchored
content" class as §1b/§1d/§1f, on the live head-monitor surface.

**Fix (client-side, no wire/consensus change):** the per-tick line renders the tip's own `state_root` under a
`tip_state_root(UNVERIFIED)` label — never as a verified value — and head_hash `as-served`; `sigs_valid`
continues to mean only "the digest carries a valid committee quorum" (which is true and useful — a daemon that
loses quorum is still immediately visible). A committee-VERIFIED state_root for a non-tip height stays available
via the `verify-state-root` command (which runs the committee-signed-successor anchor). Per the minimalism
doctrine this closes the deception with the smallest change (relabel the unverifiable field); it does not add a
speculative in-loop head-1 anchor. The line-formatting decision was factored into a pure `format_watch_tick(...)`
(the socket fetch stays in `do_one_tick`) so the relabel is falsifiable OFFLINE with no daemon.

**Gate** = `test_light_watch_head_label.sh` — FAST, fully-offline (the determ-light `selftest-watch-label`
subcommand drives `format_watch_tick` with a forged tip state_root): the tip state_root is rendered under the
`tip_state_root(UNVERIFIED)` label; the forged value appears ONLY under that label (never as verified); a valid
tick still renders `sigs_valid=yes` + height + `head_hash(as-served)` (non-vacuity). **Falsify-on-mutant**
(revert to a bare `state_root=` label): the two label asserts flip while the non-vacuity assert stays green — a
clean directional split on both platforms.

## 1h. CLOSED — account-history genesis row echoes the daemon's forgeable state_root (`selftest-genesis-row`, AH-1)

`account-history`'s per-height helper `verify_header_state_root_at` (light/account_history.cpp) routes
`idx >= 1` through `committee_bound_state_root` (transitively binding the row's state_root), but its
`idx == 0` branch returned `page["headers"][0].value("state_root", …)` — the daemon's self-declared
genesis `state_root` FIELD. Genesis carries **no committee-attested state_root**: `make_genesis_block`
(src/chain/genesis.cpp) sets `tx_root = {}` and never touches `state_root`, so the genuine value is the
all-zero `Hash{}`; genesis also has zero `creator_block_sigs`, and `anchor_genesis` binds only block-0's
`block_hash` (string-compared, never recomputed over the served header). So a hostile/MITM daemon could
put an **arbitrary forged root** on the `h=0` row. Rank-3 / low severity: balance + next_nonce come from
the Merkle-verified head_view, not this field, so only the informational state_root column of the genesis
row was deceived. (The in-code comment claiming genesis "carries the post-genesis-apply commitment when
S-033 is active" is factually wrong — no genesis `state_root` is ever set.)

**Fix (client-side, no wire/consensus change):** route the genesis-row value through a pure
`genesis_row_state_root(served)` that returns the GENUINE (empty) genesis root — rendered "(none)" —
DELIBERATELY IGNORING the served field. No GenesisConfig threading is needed: the genuine genesis
state_root is the constant empty `Hash{}` (per minimalism, "a feature that changes zero behavior is not
built"). The `served` parameter exists only to make the "ignore the forgeable field" contract explicit
and offline-testable.

**Gate** = `test_light_account_history_genesis_root.sh` — FAST, fully-offline (the determ-light
`selftest-genesis-row` subcommand drives `genesis_row_state_root`): two forged served values are NOT
echoed (NEG ×2); an empty served value stays empty (CTRL, unaffected by the mutant). **Falsify-on-mutant**
(`return served_state_root` — the AH-1 bug): the two NEG asserts flip while CTRL stays green — a clean
directional split on both platforms.

## 1i. LVS-2 — committee-metadata read off a weakly-bound stripped header (2026-07-27)

A second adversarial pass (`wf_517af620`, 8 lenses, once the CURRENT-FRONT pause lifted) re-audited the
shipped surface against "never a false YES" and found **3 CLIENT-side false-YES gaps, all the same class
as the D.5 F-7 finding** — a consumer reads committee metadata off a STRIPPED header the daemon controls
but the walk never recomputes. (0 consensus-side; lenses committee_bound_state_root / inclusion-proofs /
composite-reads / dapp-registration / anchor-walk verified SOUND.)

- **CM-1 (HIGH) `committee`-at-height forged creators[]** (`light/main.cpp` cmd_committee_at_height). The
  verb bound its re-fetched header only by a STRING-compare of the daemon-controlled `block_hash` field
  (never recomputed), then read `b.creators` off it. But `verify_state_root_at` (H≥1) verifies committee
  sigs on the SUCCESSOR H+1, never on H's own header — so creators[H] are authenticated ONLY via
  `committee_bound_state_root`'s full-block recompute, which the verb DISCARDED. A daemon serving the real
  full block (to pass the anchor) + a stripped header with `block_hash` copied but a FORGED `creators[]`
  → a false IN_COMMITTEE verdict. **Fix:** new pure `authenticated_committee(full, attested_block_hash)`
  (`light/trustless_read.{hpp,cpp}`) recomputes `compute_hash` and requires it == the successor-bound
  `block_hash`, THROWS otherwise — the verb re-fetches the FULL block and reads creators from it.
  `Block::compute_hash` binds `creators` (block.cpp:323) AND `creator_block_sigs` (block.cpp:488), so the
  recompute-bound body authenticates membership AND per-slot signed/abstained status.
- **CM-2 (MED) verify-state-root forged committee_size** (`light/verify_state_root.cpp`). `committee_size`
  was `|creators|` of the stripped header — daemon-forgeable. **Fix:** new `committee_bound_state_root`
  out-param `out_committee_size`, set from the bound full block's `creators.size()`.
- **CM-3 (MED) watch-head head_height relabel** (`light/watch.cpp` do_one_tick). The tick printed a
  daemon-asserted `head_height` as `sigs_valid=yes` without checking the committee-verified header's own
  `index == head_height-1` — a daemon inflates `head_height` then serves a GENUINE signed EARLIER block
  (digest binds THAT block's index) → a fictitious head as `sigs_valid=yes` (the LTX relabel class).
  **Fix:** new pure `watch_head_slot_bound(head_height, served_index)`.

**Gate** = `test_light_committee_auth.sh` — FAST, offline (the `selftest-committee-auth` subcommand):
`authenticated_committee` yields a genuine body's creators (CTRL) but REFUSES a forged creators[] with a
copied block_hash (NEG); `watch_head_slot_bound` binds the true head slot (CTRL) but refuses a relabeled
earlier block (NEG). **Falsify-on-mutant, independently, both platforms:** dropping the
`compute_hash==attested` check flips only the CM-1 NEG; dropping the `index==head-1` term flips only the
CM-3 NEG.

**Recurring lesson (3rd sighting of this class):** the stripped-header laundering CLASS recurs at EVERY
consumer that reads a daemon-controlled header field the walk doesn't recompute — after finding one, audit
ALL consumers, not just the trigger. "Built + gated" ≠ "adversarially sound".

## 1j. CT/ENOTE — light↔node accept-rule parity (2026-07-27)

A 5-lens adversarial audit (`wf_8f47bd9e`) of the confidential-tx / enote client verifiers found
**0 false-VERIFIED / false-INCLUDED gaps** — 4 lenses SOUND, and `verify-ct-block` (ANCHOR → BODY-PIN
`compute_hash == committee-anchored block_hash` → client-side proof re-verify) + `verify-enote-inclusion`
(the full F-6 bind: KEY = locally-computed `en:` leaf key, VALUE = `SHA256(commitment‖enote)` == the
committed leaf, ROOT = `committee_bound_state_root`, + merkle path + stale-height check) held up. It did
surface **2 LOW light-vs-node accept-rule PARITY drifts** (neither forges value, so `verify_ct.cpp`'s
"MUST stay byte-identical to the validator's" contract was violated in a fail-closed-ish way):

- **CT-P1 (correctness / false-FAILED)** — `verify_ct.cpp` passed the FULL `tx.payload.size()` to the
  frozen bundle verifiers, but the node splits off the OPTIONAL trailing NC-8 per-output enote region
  first (`ctx_split_enotes`, validator.cpp:1263). So a legit **enote-bearing** CONFIDENTIAL_TRANSFER the
  node ACCEPTS was reported FAILED by the light client (a light client would flag a valid committee-
  attested CT block as INVALID). **Fix:** call `determ::chain::ctx_split_enotes` → `bundle_len`, run the
  header/verify + commitment offsets over `bundle_len`.
- **CT-P2 (accept-widening)** — light checked only intra-bundle INPUT duplicates; the node also rejects
  OUTPUT collisions (output == an input or another output; validator.cpp:1290). A degenerate colliding-
  output bundle the node rejects was reported VERIFIED by light (no value forged — the balance proof
  still binds sum(in)=sum(out)+fee, apply no-ops the collision — a submit-time hygiene / S-039
  completeness parity gap). **Fix:** new pure `ct_bundle_has_intra_collision(bundle, n_in, m)` (shared
  `seen` over inputs + outputs; the pool-existence half stays out of a stateless verifier's scope).

**Gate** = `test_light_verify_ct.sh` extended: a valid bundle + a structurally-valid NC-8 enote region →
VERIFIED (CT-P1; falsify: reverting `ctx_split_enotes` false-FAILs it) + the pure offline
`selftest-ct-collision` (CT-P2; falsify: dropping the OUTPUT half misses the output==input / output==output
NEGs). Both platforms.

## 1k. CLOSED — verify-state-bundle offline committee-size gate dropped (`test-light-verify-state-bundle-committee-size`, LSB-COMMITTEE-SIZE, 2026-07-27)

A 6-lens adversarial audit (`wf_e73b18ec`) of the 11 remaining unaudited verifier subcommands
(param-change/value, unstake-eligibility, account, merge-state, shardtip-records, dapp-registration,
registrant, abort-record, equivocation, state-bundle) found **5 of 6 lenses SOUND** and **one HIGH
CLIENT-fixable false-VERIFIED gap** (survived 2/2 diverse refutation votes): the OFFLINE
`verify-state-bundle` verified the bundle's committee-signed SUCCESSOR header with the 3-arg
`verify_block_sigs(successor, committee, /*bft=*/false)`, so `expected_k` defaulted to 0. With
`expected_k==0` the LV-1/LV-2 committee-size mode-eligibility gate (verify.cpp: "refusing a quorum
downgrade") is SKIPPED and the accepted quorum floor becomes `creators.size()` instead of the genesis
`k_block_sigs`. Under K-of-K mutual distrust ONE colluding genesis committee member M suffices: M serves a
bundle whose successor is a **1-of-K MUTUAL_DISTRUST** block (`creators=[M]`, one real M-signature). Every
other bundle leg (key-bind, anchor-index-bind, genesis-pin, `prev_hash == compute_hash(anchor)` binding,
`state_root == proof_root`, merkle, value_hash) is a structural self-consistency check M satisfies by
construction, so the offline verifier would emit **VERIFIED** for arbitrary (namespace,key,balance)/
state_root the full committee never attested. (Via the unconditional `bft=true` retry it also admits a
reduced-quorum BFT block on a `bft_enabled=false` chain.) The node's `check_creator_selection`
(validator.cpp) rejects the same successor (`m=1 != k_full=K`). This is the SAME class as the shipped
LV-1/LV-2 chain-walk fix, on a **4th consumer** that had been missed — the online sibling
`committee_bound_state_root` and even this file's OWN export side already forward the params.

- **Fix (client-side only; no node/consensus change):** forward `genesis.k_block_sigs` +
  `genesis.bft_enabled` to both `verify_block_sigs` calls (`genesis` is already loaded above), mirroring
  `trustless_read.cpp::committee_bound_state_root` and `build_state_bundle`.
- **Gate** = `test_light_verify_state_bundle_committee_size.sh` (FAST + offline): a real genesis built with
  `determ genesis-tool build` (no cluster) so the chain-identity pin passes, then a hand-built bundle whose
  successor is a **1-of-3 MD downgrade** → UNVERIFIABLE with the "quorum downgrade" diagnostic (the mode-
  eligibility gate is a structural `creators.size()` check reached BEFORE any signature verification, so no
  real sigs are needed to trip it); a **3-of-3 MD** control passes the gate and falls through to the later
  signature gate (live, not a tautology). Falsify-on-mutant: reverting to the 3-arg calls (`expected_k=0`)
  makes the 1-of-3 NEG fall through to the signature gate instead → its diagnostic no longer says "quorum
  downgrade" → the NEG assert flips. Both platforms.

The other 5 lenses (governance / stake-eligibility / cross-shard-merge / registration / abort-equivocation)
returned **0 surviving findings** after refutation — those verifiers bind their consumed fields to the
committee-authenticated walk / `committee_bound_state_root` correctly.

## 1l. CLOSED — pq-verify-tx accepted a PQ_TRANSFER whose key does not hash to `from` (`test-light-pq-addr-bind`, PQ-ADDR-BIND, 2026-07-27)

A direct read of the ONE verifier subcommand no register had swept — `pq-verify-tx` (the offline verifier
of a post-quantum / ML-DSA-authenticated tx) — found a HIGH CLIENT-fixable false-authenticity gap.
`cmd_pq_verify_tx` verified **only** that the DPQ1 envelope's ML-DSA signature verifies over the tx
signing_bytes. But a DPQ1 envelope is **self-certifying** — it carries its own ML-DSA pubkey — so "the
signature verifies" only proves the CARRIED key signed, NOT that the key is the one committed to by the
account `from` (an A5 Option-A hash address = `make_pq_anon_address(form, pubkey)`). So an attacker who
signs a victim-`from` message with ITS OWN key was reported **VERIFIED** offline, even though the node's
shipped accept-rule `determ::chain::verify_pq_transaction` REJECTS it (recomputes
`make_pq_anon_address(form, envelope_pubkey) == from` at `src/chain/pq_tx_auth.cpp:38`). The verifier's
"VERIFIED … binds this tx's signing_bytes" was true-but-misleading: it never proved the tx was authorized
by the account it names. The stale `pq_sign_tx.hpp` header ("the consensus accept-rule … is a separate,
owner-gated step") predated inc.4, which shipped `verify_pq_transaction` — the light verifier never caught
up to the shipped node rule (the same "light under-checks vs node" class as §1j CT-P2 and §1k).

- **Fix (client-side only; no node/consensus change):** route a PQ_TRANSFER (type 11) through the SHARED
  `verify_pq_transaction` (the exact node rule — ML-DSA signature AND the address binding AND non-hybrid
  AND normalized-address legs). The generic (non-PQ-native) DPQ1 envelope check is unchanged. Extracted a
  testable `pq_verify_tx_core(json)`; added `src/chain/pq_tx_auth.cpp` to the determ-light target.
- **Gate** = `test_light_pq_addr_bind.sh` driving the pure in-process `selftest-pq-addr-bind`: it builds a
  concrete forgery (attacker key B signs a victim-`from`(==H(A)) message), asserts the raw envelope check
  STILL accepts it (the gap), the legit tx (A signs) → VERIFIED, and the forged tx → **INVALID** (the
  address binding catches it). Falsify-on-mutant: neutering the PQ_TRANSFER routing makes the forged case
  fall through to the envelope-only check → VERIFIED → the "→ INVALID" assertion flips. Both platforms.

## 2. Backlog — EMPTY (register COMPLETE, incl. LVS-2 + CT/enote parity + LSB-committee-size + PQ-addr-bind)

Every finding this register enumerated as a future gate is now CLOSED, across the **8 gate-sections
§1a–§1h** (LVS-1, LSB, LV-1/LV-2, EXP-1, LRPC-1, LTX, WATCH-1, AH-1), the **LVS-2 committee-metadata
trio §1i** (CM-1/CM-2/CM-3), the **CT/enote parity pair §1j** (CT-P1/CT-P2; the CT/enote *soundness*
surface itself audited clean — 0 false-VERIFIED), and **§1k LSB-COMMITTEE-SIZE** (the 4th consumer of the
LV-1/LV-2 class; the other 10 unaudited verifiers audited clean). No remaining backlog; 0 owner-gated. Any future
light-verifier gap opens a new row here.

## 3. REFUTED

**LARCH-1** (`verify-archive` accepts a committee-sig-stripped archive): refuted on verification — a
later bind/verify in the flow already catches the stripped-sig case.

## 4. Non-claim

Each finding establishes that the light verifier ACCEPTS an input it should reject (or is
DoS-crashable), not that a specific chain has been exploited. Every fix is client-side; none changes
the node, consensus, wire format, or what the chain accepts. Cross-references
`RpcIngressGateAudit.md` (the node-side `beacon-header-empty-committee` sibling of §1) and the F-6/F-7
light lessons in `ProofClaimGateTraceability.md`.
