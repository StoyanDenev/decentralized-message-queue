# WaitHoldAndWaitSoundness — `determ-light`'s opt-in `--wait` hold-and-wait is soundness-neutral (the S-042 head-read liveness fix)

This document proves that the opt-in `--wait <seconds>` flag added to `determ-light`'s trust-minimized readers — the **hold-and-wait** path inside `light/trustless_read.cpp::committee_bound_state_root` — is **SOUNDNESS-NEUTRAL**: it can change *whether* a verdict is produced (a bounded wait instead of an immediate fail-closed at the chain head), but it can never change *which* value the light client reports. Any `state_root` (and hence any balance / nonce / stake / supply / governance / receipt / merge / registrant / dapp / account value derived from it) that a `--wait` invocation reports is the **identical** committee-attested value an un-`--wait`'d invocation would report, or the invocation fail-closes.

This document **EXTENDS** `StateRootAnchorSoundness.md` (the S-042 successor-binding proof — `SR-1`..`SR-5`, §3.3 transitive-forward link, §6.3 head-regime fail-closed boundary, §6.4 `committee_bound_state_root` resolution). It does **not** contradict it: `StateRootAnchorSoundness.md §6.3`'s *Liveness note* already names `--wait` and states the no-weakening claim informally; this document supplies the missing rigorous argument (lemmas `WH-1`..`WH-6`, an attacker model, the soundness-neutrality theorem, and a concrete-security statement). The binding logic this document reasons about (the full-block fetch via the `"block"` RPC, the `b.compute_hash()` recompute, the `successor.prev_hash == recomputed-hash` check, the fail-closed `SECURITY` throw) is exactly the mechanism `StateRootAnchorSoundness.md §3` / §6.4 proves; here we prove that toggling `--wait` perturbs *none* of it.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage / second-preimage (§2.1), **A4** = CSPRNG uniform sampling (§2.3). This document inherits the bounds of `StateRootAnchorSoundness.md` unchanged; it introduces **no new cryptographic assumption** — the whole point is that `--wait` is a control-flow change orthogonal to the binding's cryptography.

**Companion documents.** `StateRootAnchorSoundness.md` (the parent: `SR-1` committee-anchored root, `SR-4` fail-closed, §3.3 forward link, §6.3 head boundary, §6.4 `committee_bound_state_root`); `LightClientThreatModel.md` (T-L1 genesis anchor, T-L2 committee-sig trust, T-L3 state-proof correctness, T-L4 balance/nonce composition, L-6 fail-closed exit); `MerkleTreeSoundness.md` (MT-4 inclusion-proof soundness — the consumer of the bound root); `S033StateRootNamespaceCoverage.md` (T-1..T-5 — the 10-namespace coverage of the root being anchored); `docs/SECURITY.md §S-042` (the closure this document's `--wait` is the liveness follow-up to); `Preliminaries.md` (F0) §2.0 (assumption labels).

> **Source-availability note.** Every claim below is grounded in code present in this worktree. The hold-and-wait loop is `light/trustless_read.cpp::committee_bound_state_root` (`:383-387`, the `for (waited …)` poll); the captured-once proof is `light/trustless_read.cpp::read_account_trustless` (`state_proof` fetched at `:466-468`, verified at `:477`, the held `proof_root` bound at `:498-527`); the head-fail-closed throw is `:388-401`; the load-bearing binding is `:417-432`. The forwarding call sites are `light/main.cpp` (`read_stake_trustless` decl `:1936-1943`, its embedded `committee_bound_state_root` forward `:2040-2041`; `verify_state_root_at` decl `light/verify_state_root.cpp:102-107`, its forward `:194-196`). The **eleven direct `committee_bound_state_root` call sites** in `light/main.cpp` — each forwarding the command's parsed `wait_seconds` — are `:2040` (inside `read_stake_trustless`), `:2303` (`verify-abort-record`), `:2565` (`verify-constant`), `:3625` (`verify-receipt-inclusion`), `:3950` (`verify-merge-state`), `:4292` (`verify-param-change`), `:4602` (`verify-param-value`), `:4935` (`verify-registrant`), `:5288` (`verify-dapp-registration`), `:5671` (`verify-account`, inline), and `:6332` (`supply-trustless`); the remaining consumers reach the binding through `read_account_trustless` (`trustless_read.cpp`), `verify_state_root_at` (`verify_state_root.cpp`), and `run_account_history` (`account_history.cpp`). The flag default is `0` (every parse site initializes `uint64_t wait_seconds = 0;` and forwards it; the helper's parameter defaults to `0` per `trustless_read.hpp:224`).

---

## 1. Scope

The subject is the `uint64_t max_wait_seconds` parameter of `light/trustless_read.cpp::committee_bound_state_root` and the `--wait <seconds>` CLI flag that feeds it. Concretely, `committee_bound_state_root` performs the S-042 binding in six steps (`:339-436`):

1. **Fetch the FULL block** at `anchor_index` via the `"block"` RPC (`:343`); reject null / RPC-error (`:344-353`).
2. **Recompute `block_hash`** = `b.compute_hash()` from the full body (`:356-364`) — this binds the served `state_root`, which is inside `signing_bytes` (`StateRootAnchorSoundness.md §3.2`).
3. **Fetch the committee-signed successor header** at `succ = anchor_index + 1` (`:369-374`), then **the hold-and-wait loop** (`:383-387`): while `waited < max_wait_seconds` and the successor is not yet present, sleep 1s and re-fetch the successor header.
4. **Fail closed** if no successor is present after the loop (`:388-401`).
5. **Verify the successor's committee sigs** (MD then BFT fallback, `:408-415`).
6. **The load-bearing binding** (`:417-432`): require `succ_hdr.prev_hash == to_hex(recomputed)`; on mismatch throw the `SECURITY — …` error. Only on a match return the anchor's `state_root` (`:434-436`).

`--wait` touches **only step 3's loop bound**. The claim of this document is that steps 1, 2, 4, 5, 6 — the entire soundness surface — are byte-identical regardless of `max_wait_seconds`, and that the value bound in step 6 is a value the caller captured *before* the loop ran.

**Out of scope** (inherited from `StateRootAnchorSoundness.md §1` / §2.3): `A_crypto` (SHA-256 collision finder / Ed25519 forger), `A_local`, `A_net`, `A_genesis`, and the orthogonal availability attacks (daemon stalls / truncates). These surface as fail-closed exit and are unaffected by `--wait`. This document adds **no** new out-of-scope class — `--wait` introduces no new trust surface.

---

## 2. Threat model

### 2.1 Adversary `A_wait`

`A_wait` is the standard malicious-daemon `A_root` of `StateRootAnchorSoundness.md §2.1`, observed across the wait window. It controls the daemon for the full duration of a `--wait N` invocation: it answers the one-time `state_proof` call, the `"block"` call, and *every* `headers` poll in the loop with arbitrary JSON, and it may change its served state between polls (it is not pinned to a single chain view across the round-trips). Its goal is **soundness-specific**: to exploit the *temporal* gap `--wait` opens — the wait window between proof capture and successor binding — to make a `--wait` invocation report a value `R_A` that is **not** the committee-attested value the same anchor's `state_root` commits, *without the invocation throwing*. Three temporal attack shapes specific to the wait window:

- **(a) Mid-wait proof swap.** Hope the reader re-fetches the `state_proof` after the chain advances during the wait, so a proof against a *newer* (or forged) root replaces the one originally captured.
- **(b) Mid-wait anchor swap.** Hope the reader re-fetches or re-recomputes the anchor block during the wait, so the `block_hash` bound in step 6 reflects a different body than the proof was captured against.
- **(c) Successor substitution under time pressure.** Serve, only after some polls, a successor header at `succ` that is *not* the genuine committee-signed successor of the recomputed anchor (a forged or fork successor), betting that the loop's repeated fetching weakens the step-6 check.

### 2.2 Honest auditor

An honest invocation loads a genuine operator-trusted `genesis.json`, runs the released `determ-light` unmodified, and passes `--wait N` (or omits it ⇒ `N = 0`). The security claim (§5) is that under `A_wait`, such an invocation either reports the genuine committee-attested value as of the bound anchor or fail-closed exits — `--wait` changes only whether the wait ends in a verdict or a fail-close, never which value the verdict carries.

### 2.3 Out of scope

As §1, plus: this document does **not** re-prove `SR-1`..`SR-5` (the binding's correctness — that is `StateRootAnchorSoundness.md`'s job). It proves the *delta* between `max_wait_seconds == 0` and `max_wait_seconds > 0` is soundness-empty. Availability (a daemon that never produces a successor and runs out the clock) surfaces as the same fail-closed throw `N == 0` produces, only later.

---

## 3. What `--wait` does and does not change (source-grounded)

This section reads the delta off the source so the lemmas in §4 have a precise object.

### 3.1 The only `max_wait_seconds`-dependent statement is the loop bound

In `committee_bound_state_root`, `max_wait_seconds` appears in exactly three places (`light/trustless_read.cpp`):

1. **The loop bound** (`:383-387`):
   ```cpp
   for (uint64_t waited = 0; waited < max_wait_seconds && !succ_present(pg);
        ++waited) {
       std::this_thread::sleep_for(std::chrono::seconds(1));
       pg = rpc.call("headers", {{"from", succ}, {"count", 1}});
   }
   ```
2. **The diagnostic string** in the fail-closed throw (`:392-400`) — purely the text of the error message (whether it says "after waiting Ns" and whether it suggests `--wait`); it does not affect control flow or the bound value.
3. **(transitively) nothing else.** `max_wait_seconds` is not read in step 1, 2, 5, or 6.

The loop body re-runs **only** `rpc.call("headers", {from: succ, count: 1})` (the successor *header* RPC) and `succ_present(pg)` (the predicate at `:370-373`: `pg.contains("headers") && …is_array() && !…empty()`). It does **not** re-fetch the block (`:343`), does **not** re-recompute `b.compute_hash()` (`:364`, computed once *before* the loop), and does **not** touch the proof (which lives in the caller, not in this helper at all). When the loop exits (either because `succ_present(pg)` became true, or because `waited == max_wait_seconds`), control falls into the **identical** `:388` `if (!succ_present(pg))` gate, the **identical** `:403` successor-index check, the **identical** `:408-415` committee-sig verify, and the **identical** `:417-432` `prev_hash` binding. Every statement after `:387` is reached by both the `N == 0` and `N > 0` paths with the same program state except for the (possibly now-present) `pg`.

### 3.2 `max_wait_seconds == 0` runs zero iterations

The `for` loop's guard is `waited < max_wait_seconds`. With `max_wait_seconds == 0`, the guard `0 < 0` is false at entry, so the loop body never executes: no sleep, no re-fetch. `pg` retains exactly the single pre-loop value from `:374` (the one `headers` call made *before* the loop). The subsequent `:388` `if (!succ_present(pg))` then fails closed immediately if and only if that single pre-loop fetch found no successor — which is **byte-for-byte** the pre-`--wait` behaviour (the helper before the loop was added did exactly: fetch successor once, fail closed if absent).

### 3.3 The proof is captured once, in the caller, before the helper is ever entered

The held value the binding certifies is captured by the caller **before** `committee_bound_state_root` is called, and is never re-fetched. In `read_account_trustless` (`light/trustless_read.cpp`):

- The `state_proof` is fetched **once** at `:466-468` (`rpc.call("state_proof", {namespace:"a", key:domain})`).
- It is verified self-consistently **once** at `:477` (`verify_state_proof`).
- `proof_root` is read out of that single reply at `:499` (`proof.value("state_root", …)`) and `proof_height` at `:498`.
- `anchor_index = proof_height - 1` is computed at `:517`.
- `committee_bound_state_root(rpc, committee_json, anchor_index, max_wait_seconds)` is called **once** at `:518-520`; its return is compared against the **held** `proof_root` at `:521` (`if (attested != proof_root) throw …`).

The wait loop lives entirely inside the helper and polls **only** the successor *header*. The captured `proof` object — and the `proof_root` extracted from it — are immutable local state in the caller for the whole duration of the helper call (including its internal wait). There is **no** code path on which the proof is re-fetched after `:468`. The identical capture-once-then-bind structure holds in `read_stake_trustless` (`light/main.cpp`: proof at `:1965-1966`, verified `:2002`, `proof_root` at `:2015`, helper call `:2040-2041`, held comparison `:2042`) and in `verify_state_root_at` (`light/verify_state_root.cpp`: the helper's *own* return is the value, and `:194-198` reads it straight out without any second proof fetch).

### 3.4 The successor header RPC carries no state payload

`succ_present` and the loop poll the `headers` RPC (`{from: succ, count: 1}`), which serves a *stripped* header (no `state_root`-bearing body — the heavy fields `signing_bytes` needs are absent from `headers`, per `StateRootAnchorSoundness.md §3.2` and `SECURITY.md §S-042`). The successor header's role in the binding is solely to provide a committee-signed `prev_hash` (step 6). The reported value is `b.state_root` of the **anchor** block (`:434-436`), recomputed/bound from the **pre-loop** full-block fetch. So nothing the loop fetches can become the reported value — the loop fetches only the object whose *signature over `prev_hash`* certifies the already-recomputed anchor hash.

---

## 4. Lemmas

Throughout, `R_T` denotes the genuine committee-attested `state_root` the anchor block commits (per `StateRootAnchorSoundness.md`'s `R_T`); `H = anchor_index`; `N = max_wait_seconds`. "The binding" denotes steps 1, 2, 4, 5, 6 of §1 (everything except the loop bound).

### 4.1 WH-1 (binding-logic invariance)

**Statement.** The full-block fetch (step 1), the `b.compute_hash()` recompute (step 2), the `succ_hdr.prev_hash == to_hex(recomputed)` comparison and its fail-closed `SECURITY` throw (step 6), the no-successor fail-closed throw (step 4), and the successor committee-sig verify (step 5) are **byte-identical** whether or not `--wait` is set. `--wait` changes only *when* the successor header is fetched (the loop re-issues the `headers` RPC up to `N` times), not *what* is compared or *what* is thrown on mismatch.

**Proof.** By the §3.1 source enumeration: `max_wait_seconds` is read only by the loop guard (`:383`) and woven into the diagnostic *text* (`:392-400`); it appears in no other statement of the helper. Steps 1 (`:343-353`) and 2 (`:356-364`) execute **before** the loop and are textually independent of `max_wait_seconds`. Steps 4 (`:388-401` — the gate condition is `!succ_present(pg)`, independent of `N`; only the message text varies), 5 (`:408-415`), and 6 (`:417-432`) execute **after** the loop and are reached on every path with the same operands: `recomputed` (fixed at `:364`), `succ_hdr` (the first element of whatever `pg` holds at loop exit), and `committee_json` (the caller's argument). The comparison at `:424` is `succ_prev != recomputed_hex` and the throw at `:425-431` is the same `SECURITY — …` string template on both paths. Hence the binding's *predicate* and its *fail-closed disposition* are invariant under `--wait`; only the **number of `headers` re-fetches** before the binding runs differs. ∎

**Remark.** The diagnostic-text variation (`:392-400`) is observable to the operator but is not part of any soundness predicate: a wrong value is never *reported as a verdict* via an error string — the throw aborts the command with a non-zero exit (`SR-4` / L-6 fail-closed discipline). Changing the help text of a fail-closed throw cannot upgrade a fail-close into a wrong verdict.

### 4.2 WH-2 (no-re-fetch / no-race)

**Statement.** The caller captures the `state_proof` for the anchor **exactly once**, before `committee_bound_state_root` is entered; the wait loop polls **only** the successor *header* (the `headers` RPC), never the proof; and the held `proof_root` is the value the binding compares against. Therefore a state change on the daemon *during* the wait window cannot swap the bound root: the proof the verdict rests on was frozen before the loop began.

**Proof.** Two facts compose.

(i) **The proof is frozen before the helper runs (§3.3).** In each binding consumer the `state_proof` is fetched once (`read_account_trustless:466-468`; `read_stake_trustless`; the composite consumers in `light/main.cpp` each fetch their `state_proof` once *before* their `committee_bound_state_root` call — the eleven direct calls being `:2040` (in `read_stake_trustless`), `:2303`, `:2565`, `:3625`, `:3950`, `:4292`, `:4602`, `:4935`, `:5288`, `:5671`, `:6332`). The extracted `proof_root` is an immutable local; no path re-issues the `state_proof` RPC after that point.

(ii) **The loop touches only the successor header (§3.1, §3.4).** The loop body (`:385-386`) re-runs only `rpc.call("headers", {from: succ, count: 1})` and re-evaluates `succ_present(pg)`. It does not call `state_proof`, does not call `block`, and does not re-read `proof_root`. The recomputed anchor hash (`recomputed`, `:364`) is fixed before the loop.

Compose: the value finally bound is `committee_bound_state_root`'s return = `b.state_root` of the **pre-loop** full block (`:434-436`), and the caller's accept condition is `attested == proof_root` for the **pre-loop** `proof_root` (`:521`). A daemon that advances its state mid-wait can change only what a *future* `state_proof` / `block` call would return — but no such call is made after the freeze. The `headers` polls it does answer feed only the successor-`prev_hash` check, which can either match the frozen anchor hash (binding succeeds, reporting the frozen value) or not (fail-closed, `WH-1`). Attack shapes §2.1(a) and (b) are thus unreachable: there is no re-fetch of the proof or the anchor to exploit. ∎

**Corollary (the "one block settled" semantics are sound, not a downgrade).** When `--wait` succeeds, the successor `H+1` has landed, so the committee has signed `digest(H+1)` which binds `prev_hash(H+1) = block_hash(H)` (`StateRootAnchorSoundness.md §3.3`). The reported value is therefore `state_root(H)` *with its forward link now in place* — strictly the **interior-regime `SR-1`** guarantee, not a weaker head-regime one. `--wait` converts a head-regime read (no successor ⇒ no `SR-1`) into an interior-regime read (successor exists ⇒ full `SR-1`) by *waiting for the chain to make it interior*, never by relaxing the check.

### 4.3 WH-3 (default-off identity)

**Statement.** `max_wait_seconds == 0` runs zero loop iterations and is byte-for-byte the pre-fix behaviour: fetch the successor once, and fail closed at the head if it is absent.

**Proof.** §3.2: with `N == 0` the loop guard `0 < 0` is false at entry, so the body never executes — `pg` is exactly the single pre-loop fetch from `:374`. Control falls to `:388 if (!succ_present(pg))`, which fails closed iff that one fetch found no successor. This is identical to the helper's behaviour before the loop existed (single successor fetch, fail closed if absent). Every default invocation (the flag is initialized to `0` at every parse site and the helper parameter defaults to `0`, `trustless_read.hpp:224`) is therefore the unchanged S-042 fail-closed-at-head disposition of `StateRootAnchorSoundness.md §6.3`. ∎

### 4.4 WH-4 (liveness boundary — why `--wait` exists, and that it is a liveness, not soundness, change)

**Statement.** Because the daemon's `state_proof` RPC always serves the head (`rpc_state_proof` returns the proof at `chain_.height()`), the anchor in any *current-state* read is the head, whose committee-signed successor does not yet exist. So **without** `--wait`, the trustless readers fail closed on **every** live current-state read (not an edge case): the helper requests the successor at `head + 1`, finds none, and throws (`:388-401`). `--wait` converts that universal fail-close into a **bounded wait-then-bind**: poll up to `N` seconds for the next block, then bind the **held** proof. The change is purely on the *liveness* axis (verdict-vs-fail-close); §4.1–§4.2 establish it does not touch the *soundness* axis (which value).

**Proof.** Two regimes, distinguished by how the anchor index is chosen:

- **Always-head readers (current-state reads).** `read_account_trustless` sets `anchor_index = proof_height - 1` where `proof_height` comes from the head-serving `state_proof` reply (`:498`, `:517`); identically `read_stake_trustless` (`light/main.cpp:1950`, `:1975`) and the composite consumers, which all anchor at `proof_height - 1`. Since the proof is always for the head, `anchor_index` is always the head index, and `succ = anchor_index + 1` is always one past the head. With `N == 0` (`WH-3`) the single successor fetch finds nothing ⇒ fail closed. This is *every* current-state read, not a corner case — which is exactly why `StateRootAnchorSoundness.md §6.3`'s Liveness note flags the readers as unusable for live current-state reads without intervention. `--wait` polls until the producer emits `head + 1`, at which point the held proof's anchor becomes interior and binds (`WH-2` corollary).

- **Committee-at-height readers (explicit `--height H`).** `verify_state_root_at` (and `committee-at-height`, which calls it, `light/main.cpp:5969-5970`) takes an operator-supplied `H` and anchors at exactly `H` (`verify_state_root.cpp:195` passes `height` as the anchor). For `H < head` the successor `H+1` already exists, so the binding completes with `N == 0` and `--wait` is inert (the help text says so: `light/main.cpp:5965-5968` — "--wait (default 0) matters only when H == head"). The *only* sub-case where `--height H` hits the head boundary is `H == head`, which then behaves exactly like an always-head reader. So `--wait` is a no-op on the common explicit-height path and only matters at `H == head`.

In both regimes, `--wait` changes solely whether the command *waits for a successor* or *fails closed now*. The bound value is `state_root(H)` either way (`WH-1`, `WH-2`); only its *availability* (verdict vs. fail-close) is affected. This is the definition of a liveness change. ∎

### 4.5 WH-5 (successor substitution gains nothing under the wait)

**Statement.** Attack §2.1(c) — a daemon that, after some polls, serves a non-genuine successor at `succ` — is caught by the **same** step-5 committee-sig verify and step-6 `prev_hash` binding that `SR-1` relies on, with **no** new advantage from the wait. The wait gives the daemon *more polls*, but each poll's reply is subjected to the identical post-loop checks; serving a fake successor on the k-th poll is no different from serving it on the 1st.

**Proof.** Whatever `pg` holds when the loop exits, the post-loop code (identical on all paths, `WH-1`) runs: `:403` requires `succ_hdr.index == succ` (a successor at the wrong index throws); `:408-415` requires the successor's committee sigs to verify against `committee_json` (a sig failure throws — an A1 forgery to pass it costs `≤ K·2⁻¹²⁸`, the `T-L2` reduction); `:424` requires `succ_hdr.prev_hash == recomputed_hex` (a successor whose `prev_hash` does not equal the recomputed anchor hash throws — to make a fake successor's signed `prev_hash` equal the recomputed hash *and* carry valid committee sigs is again an A1 forgery on `digest(H+1)`, or an A2 collision on the anchor's `signing_bytes`). The loop does not bypass, reorder, or weaken any of these — it only delays reaching them. The number of attempts the daemon gets to *produce* a passing successor is irrelevant: a valid committee-signed successor of the genuine anchor binds the genuine `state_root` (a correct verdict, `SR-1`); anything else throws. The adversary's win probability is therefore the **same** `≤ K·2⁻¹²⁸ + 2⁻¹²⁸` of `SR-1`, independent of `N`. ∎

### 4.6 WH-6 (coverage — every binding consumer forwards `--wait`, and only the state-reading ones)

**Statement.** Every trust-minimized reader whose verdict rests on a `committee_bound_state_root` binding forwards `--wait` to that binding; the pure offline / non-state commands correctly do **not** accept it (they have no anchor to wait for).

**Proof (enumeration against the source).** The forwarding consumers, each parsing `--wait` into `uint64_t wait_seconds` (initialized `0`) and threading it to the binding:

| Command (`light/main.cpp`) | Parse site | Forwards via | Binding reached |
|---|---|---|---|
| `balance-trustless` / `nonce-trustless` (account read) | its `--wait` arg-loop branch | `read_account_trustless(…, wait_seconds)` | `committee_bound_state_root` `trustless_read.cpp:518-520` |
| `stake-trustless` | its `--wait` arg-loop branch | `read_stake_trustless(…, wait_seconds)` | `committee_bound_state_root` `:2040` |
| `verify-abort-record` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:2303` | direct (b: reader) |
| `verify-constant` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:2565` | direct (k: reader) |
| `verify-unstake-eligibility` | its `--wait` arg-loop branch | embeds `read_stake_trustless(…, wait_seconds)` | via the stake read |
| `verify-state-root` | its `--wait` arg-loop branch | `verify_state_root_at(…, wait_seconds)` | `committee_bound_state_root` `verify_state_root.cpp:195-196` |
| `verify-and-submit` | its `--wait` arg-loop branch | embeds `read_account_trustless(…, wait_seconds)` | via the account read |
| `verify-receipt-inclusion` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:3625` | direct |
| `verify-merge-state` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:3950` | direct |
| `verify-param-change` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:4292` | direct |
| `verify-param-value` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:4602` | direct |
| `verify-registrant` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:4935` | direct |
| `verify-dapp-registration` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:5288` | direct |
| `verify-account` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:5671` | direct (inline anchoring — **not** via `read_account_trustless`) |
| `supply-trustless` | its `--wait` arg-loop branch | `committee_bound_state_root(…, wait_seconds)` `:6332` | direct (per supply counter) |
| `account-history` | its `--wait` arg-loop branch (`opts.wait_seconds`) | `run_account_history(opts)` → `committee_bound_state_root(…, max_wait)` in `light/account_history.cpp` | direct (per sampled height) |
| `committee-at-height` | its `--wait` arg-loop branch | `verify_state_root_at(…, wait_seconds)` | `committee_bound_state_root` `verify_state_root.cpp:195-196` |

(The help text exposing `--wait` on each of these is in `light/main.cpp`'s usage block.)

Every one of these reaches the binding through a captured-once proof or an explicit-height anchor (§3.3), so `WH-1`–`WH-5` apply uniformly. The forwarding is mechanical: `wait_seconds` is parsed identically (`a == "--wait" && i+1 < argc ⇒ wait_seconds = parse_u64("--wait", argv[++i])`) and passed as the helper's `max_wait_seconds` argument with no transformation.

**The non-state commands correctly omit `--wait`.** Pure offline / non-binding commands (e.g. local keyfile / tx-signing helpers, `tx-hash`, header-only walks that produce no `state_root`-anchored verdict) have no `state_proof` capture and no `committee_bound_state_root` call, hence nothing to wait for; they do not accept `--wait`. Adding it would be meaningless (no anchor) and they correctly do not. ∎

---

## 5. Soundness-neutrality theorem

**Theorem (WH-SN).** Let `C` be any binding consumer of §4.6 (WH-6). For any daemon behaviour `B` of `A_wait` (§2.1) and any `N = max_wait_seconds ≥ 0`, the value `C` *reports as a verdict* under `(B, N)` is, with probability `≥ 1 − ε`, the genuine committee-attested value the bound anchor's `state_root` commits — and this value is **independent of `N`**. Enabling `--wait` (`N > 0`) can change only whether `C` produces a verdict or fail-closed exits; it can **never** change *which* value the verdict carries. Here `ε` is the `StateRootAnchorSoundness.md` `SR-1`/`SR-2`/`SR-3` bound (`≤ (H·K + K + 1)·2⁻¹²⁸` for the full anchored read), **unchanged** by `--wait`.

**Proof.** Fix `C`, `B`. Consider the two executions `E_0 = (B, N=0)` and `E_N = (B, N>0)`.

1. **The captured proof is identical across `E_0` and `E_N`.** The `state_proof` is fetched once, before the helper and its loop (§3.3, `WH-2`(i)); this fetch precedes any `max_wait_seconds`-dependent statement. So `proof_root` (the value `C` will report iff the binding accepts) is the *same object* in `E_0` and `E_N` for the same `B`. (`A_wait` may serve a different proof in a *different* run, but within a fixed `B` the single pre-loop fetch is the same in both executions.)

2. **The binding predicate is identical across `E_0` and `E_N`.** By `WH-1`, steps 1, 2, 4, 5, 6 are byte-identical functions of `(anchor block body, successor header, committee_json)`; none reads `N`. The recomputed anchor hash is fixed pre-loop (`:364`).

3. **The only difference is loop iteration count, which affects only *whether* a successor is present at the gate `:388`, not the gate's verdict logic.** By `WH-3`, `E_0` evaluates `:388` against the single pre-loop `pg`; by §3.1, `E_N` evaluates `:388` against the post-loop `pg` (possibly now non-empty). Two cases:
   - **Successor present in `E_0`** (the anchor was already interior). Then `E_N`'s loop guard `succ_present(pg)` is already true after the first poll-equivalent (the pre-loop fetch), so `E_N` also enters `:388` with a present successor; both run the identical steps 5–6 on the identical successor and report the identical value (or both throw identically). `N` is inert.
   - **Successor absent in `E_0`** (head regime). `E_0` fails closed at `:388-401`. `E_N` either (a) still finds no successor after `N` polls ⇒ fails closed at the same gate (just later, with a different message string), or (b) finds the successor on some poll ⇒ proceeds to steps 5–6. In sub-case (b), the value it can report is constrained exactly as in `WH-5`/`SR-1`: a *genuine* committee-signed successor of the recomputed anchor binds the genuine `state_root` (correct verdict), and anything else throws — at probability `ε` of `SR-1`. The value reported, if any, is `state_root(H)`, the same value `E_0` *would* have reported had a successor existed — `N` did not change it, it only allowed the chain to supply the successor that makes the (already-frozen) anchor's value bindable.

4. **Composing:** in every case, the *value* a verdict carries is `proof_root` accepted iff it equals the committee-attested `state_root(H)`, a function of the frozen proof and the binding predicate — both `N`-independent. `--wait` moved only the verdict/fail-close boundary. The probability that an accepted verdict carries a non-attested value is the `SR-1`/`SR-2`/`SR-3` bound `ε`, with no `N`-dependent term (the wait adds *more successor fetches*, each subject to the identical A1/A2 checks of `WH-5` — a union over more attempts does not help because only a *genuine* successor passes, and producing one is exactly producing the honest answer). Hence `Pr[C reports a non-attested value under (B,N)] ≤ ε`, independent of `N`. ∎

**Restatement (the operative one-line claim).** *Enabling `--wait` cannot cause the light client to report any value not committee-attested as of the bound anchor; it can only change whether a verdict is produced versus a fail-closed exit, never which value.*

---

## 6. Concrete security

`--wait` introduces **no new term** into the soundness bound. The full trust-minimized account read remains, per `StateRootAnchorSoundness.md §5.4`:

```
Pr[full read compromised under --wait N] = Pr[full read compromised under N=0]
  ≤ Pr[SR-1] + Pr[MT-4] + Pr[cleartext collision]
  ≤ (H·K + K + 1)·2⁻¹²⁸ + log₂(leaf_count)·2⁻¹²⁸ + 2⁻¹²⁸
  ≤ 2⁻⁹²   for  H ≤ 2³², K ≤ 16, leaf_count ≤ 2⁶⁴,
```

for **all** `N ≥ 0`. The `--wait` perturbation contributes `0` to ε: by `WH-1`/`WH-5` the per-attempt forgery/collision probabilities are unchanged, and by `WH-2` no proof-re-fetch race is opened, so there is no `N·(·)` union term. The only `N`-dependent quantity is the **wall-clock latency** of a current-state read (bounded by `N` seconds, an availability/UX property), and the **liveness** disposition (verdict reachable within `N` seconds of a producer emitting the next block vs. immediate fail-close) — neither is a soundness term. A daemon that runs out the `N`-second clock yields the same fail-closed exit as `N = 0`, only later (availability, not soundness — `StateRootAnchorSoundness.md §6.1`).

---

## 7. Cross-references

| Component | File / location | Role in this proof |
|---|---|---|
| `committee_bound_state_root` (full-block fetch + recompute + binding) | `light/trustless_read.cpp:335-437` (decl `trustless_read.hpp:221-224`) | The helper whose `max_wait_seconds` this document proves soundness-neutral; steps 1–6 of §1. |
| The hold-and-wait loop | `light/trustless_read.cpp:383-387` | The **only** `max_wait_seconds`-dependent control flow (§3.1, `WH-1`). |
| Head fail-closed throw | `light/trustless_read.cpp:388-401` | `WH-3`/`WH-4` fail-closed disposition; default-off (`N==0`) identity. |
| The load-bearing `prev_hash` binding | `light/trustless_read.cpp:417-432` | The `SR-1` check; invariant under `--wait` (`WH-1`, `WH-5`). |
| `read_account_trustless` (proof captured once) | `light/trustless_read.cpp:439-572` (proof `:466-468`, held `proof_root` `:499`, helper `:518-520`, accept `:521`) | The capture-once-then-bind structure (`WH-2`); forwards `--wait` via `max_wait_seconds`. |
| `read_stake_trustless` | `light/main.cpp:1936-2070` (proof `:1965-1966`, key-bind `:1985-1998` (F-6), helper `:2040-2041`) | Stake consumer; identical capture-once + forward. |
| `verify_state_root_at` | `light/verify_state_root.cpp:102-205` (helper `:194-196`) | Explicit-`--height H` anchor; `WH-4` committee-at-height regime. |
| The eleven direct `committee_bound_state_root` call sites | `light/main.cpp:2040` (in `read_stake_trustless`), `:2303` (abort-record), `:2565` (constant), `:3625`, `:3950`, `:4292`, `:4602`, `:4935`, `:5288`, `:5671`, `:6332` | The `WH-6` coverage enumeration (verify-* / supply readers); the rest route via `read_account_trustless` / `verify_state_root_at` / `run_account_history`. |
| `--wait` help text | `light/main.cpp:183-483` | Operator-facing flag documentation (default 0 = unchanged behaviour). |
| `StateRootAnchorSoundness.md` | `SR-1`..`SR-5`, §3.3, §6.3 (Liveness note), §6.4 | **Parent.** This document extends its §6.3 Liveness note into a rigorous soundness-neutrality proof. |
| `docs/SECURITY.md §S-042` | the closure entry | The HIGH binding fix this `--wait` is the liveness follow-up to. |
| `LightClientThreatModel.md` | L-6 (fail-closed exit), T-L4 | The fail-closed discipline `WH-1`'s throws inherit; the composite read `WH-2` corollary feeds. |
| `MerkleTreeSoundness.md` | MT-4 | Consumer of the bound root; unaffected by `--wait`. |
| `tools/test_light_wait_flag.sh` | (offline flag contract) | The offline witness: `--wait` help present, bad-value rejection, `N==0` no-op default (`WH-3`). The live "succeeds once the next block lands" leg runs on CI. |
| `tools/test_light_state_root_binding.sh` | (offline; S-042 witness) | The binding mechanized witness `WH-1`/`WH-5` reason about: swapped `state_root` REJECTED, head fails closed. |

---

## 8. Status

- **Implementation.** The `--wait <seconds>` flag and its `max_wait_seconds` plumbing are shipped: the hold-and-wait loop is `light/trustless_read.cpp:383-387`; the parameter is threaded through `read_account_trustless` / `read_stake_trustless` / `verify_state_root_at` and forwarded by all seventeen binding consumers of `WH-6` (`light/main.cpp`; the census grew from fifteen when the `b:` `verify-abort-record` and `k:` `verify-constant` readers landed — both forward `wait_seconds` to their direct `committee_bound_state_root` calls, so `WH-1`–`WH-5` apply verbatim). Default is `0` (fail-closed-at-head, unchanged). Tracked as the liveness follow-up to `docs/SECURITY.md §S-042`.
- **Proof.** Complete (this document). `WH-1` (binding-logic invariance), `WH-2` (no-re-fetch / no-race; the proof is frozen before the loop), `WH-3` (default-off identity — zero iterations at `N==0`), `WH-4` (liveness boundary — always-head readers vs explicit-`--height H`; the head is `H==head`), `WH-5` (successor substitution gains nothing under the wait), and `WH-6` (coverage). The soundness-neutrality theorem `WH-SN` (§5) establishes that `--wait` changes only verdict-vs-fail-close, never which value is reported.
- **The load-bearing finding.** `--wait` is a **liveness** change orthogonal to the binding's **soundness**: it re-issues only the successor *header* RPC up to `N` times, never re-fetches the once-captured proof or re-recomputes the anchor hash, and reaches the byte-identical `prev_hash` binding + fail-closed throw of `StateRootAnchorSoundness.md §3`/`SR-1`. With `N==0` it is the pre-fix S-042 fail-closed-at-head disposition exactly; with `N>0` it waits for the chain to supply the successor that makes the (frozen) anchor's `state_root` bindable — promoting a head-regime read to the strong interior-regime `SR-1` guarantee, not relaxing it.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision resistance), transitively A3 — **all inherited from `StateRootAnchorSoundness.md`; `--wait` adds none.** Per `Preliminaries.md §2.0`.
- **Concrete-security bound.** Unchanged by `--wait`: `Pr[reported value not committee-attested] ≤ ε`, where `ε` is the `SR-1`/`SR-2`/`SR-3` bound (`≤ (H·K+1)·2⁻¹²⁸`), with **no** `N`-dependent term (§6). Full account read: `≤ 2⁻⁹²` for `H ≤ 2³²`, `K ≤ 16`, `leaf_count ≤ 2⁶⁴`, for all `N ≥ 0` — matching `T-L4` and the un-`--wait`'d path.
- **Boundaries (inherited, unchanged by `--wait`).** Single-daemon (no multi-peer) — a stalling daemon that never produces a successor runs out the `N`-second clock and fail-closes (availability, not soundness; `StateRootAnchorSoundness.md §6.1`). Committee-rotation (`K_0`-only) — `§6.2` there. Pre-S-033 vacuous binding — `SR-5` there. None of these is created or widened by `--wait`.

This document is `FB64` in the proof family.
