# ParamChangeLintSoundness — OFFLINE prediction of on-chain PARAM_CHANGE activation outcome (`determ-wallet param-change-lint`)

This document proves the soundness of the `determ-wallet param-change-lint` subcommand: a **one-shot, fully OFFLINE, read-only lint** that an operator runs against a single governance `PARAM_CHANGE` (supplied either as a `--name`/`--value-hex` pair or as a `param-change-build`-output JSON via `--tx-json`) to obtain, *before the transaction is ever submitted*, a verdict that **predicts what the chain will do with the change at activation**:

- **EFFECTIVE** — a whitelisted numeric chain-scalar (`MIN_STAKE` / `SUSPENSION_SLASH` / `UNSTAKE_DELAY`) whose value is **exactly 8 bytes** wide: the activation path's `parse_u64` lambda accepts it and writes the destination scalar.
- **INERT_BAD_WIDTH** — the *trap*: a whitelisted numeric chain-scalar whose value is **not 8 bytes** wide. The transaction is accepted by the validator (the name is on the whitelist; the value width is never checked at validate time), it stages, and then at activation `parse_u64` returns `false` **before** writing the destination — so the scalar is **silently never updated**. The operator sees an accepted, finalized governance transaction that accomplishes *nothing*.
- **HOOK_ONLY** — a whitelisted name with **no chain-instance storage** (`tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`, `bft_escalation_threshold`, `param_keyholders`, `param_threshold`): the activation path forwards `(name, value)` to the Node-installed `param_changed_hook_`. Whether that produces a real effect depends on whether the operator's Node wired the hook — which the wallet **cannot observe**. The verdict is honestly scoped to "forwarded; effect is the Node's responsibility."
- **UNKNOWN_NAME** — an off-whitelist name: the validator rejects the transaction outright (`validator.cpp:683-686`), so it never lands and never activates.

The exit code is monitor-friendly: `0` for EFFECTIVE / HOOK_ONLY (the change will take effect or is forwarded), `2` for INERT_BAD_WIDTH / UNKNOWN_NAME (the change is a no-op or is rejected), `1` for an args/parse fault.

**The load-bearing design fact (TCB separation).** `determ-wallet` deliberately does **not** link `libdeterm_chain`. The two on-chain rules this lint predicts — the validator's `kWhitelist` admission set and the activation path's `parse_u64` 8-byte-width decode — are therefore **reimplemented inline** in `wallet/main.cpp` as a 9-element `std::set<std::string>` plus a 3-element numeric-scalar `std::set` plus a `value_hex.size() / 2 == 8` width test, rather than called from the chain library. **PCL-1** proves the reimplemented whitelist and scalar/hook partition are **byte-for-byte** the validator's `kWhitelist` and the activation dispatch; **PCL-2** proves the reimplemented width rule is **byte-for-byte** the `parse_u64` `value.size() != 8` guard. This is the same wallet-TCB posture as the `block-verify` sibling (`OfflineBlockVerifySoundness.md` BV-1): the lint trades a chain-library link for a lean trusted base, and pays the cost as a stated boundary, not a hidden assumption.

**What the verify-proof for the companion command rests on, vs. what THIS lint rests on.** The sibling `param-change-verify` reimplements the validator's *Ed25519 multisig gate* and its soundness reduces to **A1** (Ed25519 EUF-CMA) — that proof is referenced here for the verify half of the governance toolchain, but `param-change-lint` is a *different* check: it predicts the **activation effect**, not signature validity, and assumes nothing about the signatures (a lint is run *before* the multisig is even assembled, or against a build that has not yet collected signatures). The lint's soundness therefore reduces not to A1 but to the **determinism of the whitelist set-membership test and the `parse_u64` width decode** (themselves grounded in A2 SHA-256 determinism for the on-chain state-root binding of the resulting parameter, via `GovernanceWhitelistSoundness.md` GW-3, but not for the lint's verdict, which is a pure byte-length comparison). This document states that reduction precisely.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (`Preliminaries.md §2.2`), **A2** = SHA-256 collision resistance (`Preliminaries.md §2.1`). The lint *verdict* itself is purely deterministic (set membership + integer width comparison) and uses **neither** A1 nor A2 — it is a decidable predicate over the input bytes. A1 and A2 enter only at the *boundaries*: A1 governs whether the transaction the lint describes will eventually be *accepted* by the multisig gate (the `param-change-verify` companion, not this lint), and A2 governs whether the activated scalar is *bound into the state root* (the `GovernanceWhitelistSoundness.md` GW-3 / `ParamChangeDeterminism.md` convergence the lint's EFFECTIVE verdict presupposes for cross-node agreement). This document cites both honestly and disclaims that the lint verdict carries a cryptographic error term.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (assumption labels), §2.1 (A2), §2.2 (A1) — the lint verdict reduces to *neither* base primitive (it is deterministic), the labels are cited to scope the boundaries precisely; `GovernanceWhitelistSoundness.md` (**GW-1** whitelist closure, **GW-2** the width-checked-not-range-checked bounds posture, **GW-3** the `p:`/`k:` state-root binding) — the authoritative proof of the *on-chain* whitelist + width semantics this lint reimplements; PCL-1/PCL-2 reduce to GW-1/GW-2 plus a byte-equivalence argument; `OfflineBlockVerifySoundness.md` (**BV-1** the TX-ROOT byte-equivalence reimplementation, **BV-2** the SIGS digest conditional) — the wallet-TCB-separation sibling whose "reimplement an on-chain rule inline, prove byte-equivalence, state the trust boundary" thesis PCL-1/PCL-2 instantiate for the activation rule; `LightVerifyChainFileSoundness.md` (the OFFLINE whole-chain file verifier, **Lemma L-2** byte-equivalence posture) — a further instance of the offline-reimplementation discipline this document follows; `BatchSigningSoundness.md` (**BS-3** per-record structural isolation) — cited for the `param-change-verify` companion's per-signer loop, not for this lint; `GovernanceParamChange.md` (FA-Apply governance) for the staging/activation drain mechanics the EFFECTIVE/INERT verdicts predict; `docs/PROTOCOL.md` §3.3 (PARAM_CHANGE apply rules) + §4.1.1 (state-root namespace table) + §9 (the PARAM_CHANGE wire layout); `docs/SECURITY.md` for the TCB-separation narrative.

---

## 0. Implementation status and the object proved

**`int cmd_param_change_lint(int, char**)` is IMPLEMENTED and SHIPPED in `wallet/main.cpp:23106-23237`** (dispatched on `param-change-lint` at `wallet/main.cpp:25078`). The two on-chain rules it reimplements are read directly off source:

- The validator's whitelist gate — `kWhitelist` (9 names) at `src/node/validator.cpp:677-682`, applied at `src/node/validator.cpp:683-686` (`kWhitelist.find(name) == kWhitelist.end()` ⇒ reject).
- The activation decode — `activate_pending_params`' `parse_u64` lambda (`value.size() != 8` ⇒ return `false`, no write) at `src/chain/chain.cpp:476-482`, the three numeric chain-scalar dispatches at `src/chain/chain.cpp:483-485`, and the unconditional hook forward at `src/chain/chain.cpp:493`.

**SPEC of `param-change-lint` (the object proved):**

```
determ-wallet param-change-lint
    (--name <P> --value-hex <hex> | --tx-json <file>) [--json]
```

A one-shot OFFLINE activation-effect lint emitting one of four verdicts with a monitor-friendly exit code (`0` EFFECTIVE/HOOK_ONLY, `2` INERT_BAD_WIDTH/UNKNOWN_NAME, `1` args/parse). Control flow, read off `wallet/main.cpp:23230-23361`:

1. **Input acquisition (`:23259-23301`).** Either `--tx-json` (mutually exclusive with `--name`/`--value-hex`, `:23262-23266`) — from which the lint **prefers to decode the authoritative on-chain `payload` hex** via the exact wire layout `[name_len u8][name][value_len u16 LE][value]…` (`:23277-23290`, mirroring `validator.cpp:644-662`), falling back to the convenience `name` + `value_hex` fields (`:23291-23297`) — or the direct `--name`/`--value-hex` pair (`:23298-23301`). A missing required input, an unreadable file, bad JSON, or a non-hex payload → `return 1` before any verdict.

2. **Strict value-width computation (`:23303-23311`).** The lint validates `value_hex` with a **strict** hex check (`:23306-23309`) — deliberately *not* the shared lenient `from_hex` (`wallet/main.cpp:93-107`, whose `istringstream >> hex` accepts a leading hex prefix of a malformed string) — rejects odd length (`:23310`), and computes `value_bytes = value_hex.size() / 2` (`:23311`). This is the byte width the on-chain `parse_u64` will see (PCL-2).

3. **Whitelist + scalar partition (`:23315-23323`).** Two compile-time `static const std::set<std::string>`: `kWhitelist` (the 9-name mirror) and `kNumericScalars` (the 3 chain-instance scalars).

4. **Verdict (`:23325-23341`).** `name ∉ kWhitelist` ⇒ **UNKNOWN_NAME**; else `name ∈ kNumericScalars` ⇒ **EFFECTIVE** if `value_bytes == 8` else **INERT_BAD_WIDTH**; else (whitelisted non-scalar) ⇒ **HOOK_ONLY**.

5. **Exit (`:23343-23360`).** `ok = (verdict == "EFFECTIVE" || verdict == "HOOK_ONLY")`; exit `0` iff `ok`, else `2`; `1` is reserved for the step-1/step-2 parse faults. `--json` emits an object (`name`, `value_bytes`, `value_hex`, `verdict`, `detail`, `effective`); human mode emits a per-field summary. Read-only over the verdict.

**No proof-to-spec divergence.** The shipped command matches this SPEC; there are no open implementation obligations (contrast `OfflineBlockVerifySoundness.md` §0 D1/D2, which were resolved during that command's implementation). The verdict logic is the source of truth for PCL-3/PCL-4 below.

---

## 1. Scope

### 1.1 In scope

The `determ-wallet param-change-lint` command per the §0 SPEC: its input acquisition, the strict width computation, the four-way verdict, and the exit-code mapping. The claim proved is that **the verdict correctly predicts the on-chain activation outcome by faithful reimplementation** of two on-chain rules (the whitelist admission set and the 8-byte width decode), with HOOK_ONLY honestly scoped to "the wallet cannot observe the Node hook."

### 1.2 The four verdicts and what each asserts

| Verdict | Reimplements | On-chain prediction | Backing |
|---|---|---|---|
| **UNKNOWN_NAME** | `validator.cpp:683-686` whitelist reject | Validator rejects the tx; it never lands, never stages, never activates | PCL-1 (§3.1) + GW-1 |
| **EFFECTIVE** | `chain.cpp:483-485` scalar dispatch + `:476-482` width-pass | `parse_u64` accepts the 8-byte value; the destination scalar is written at activation height | PCL-1 + PCL-2 + PCL-3 (§3.3) |
| **INERT_BAD_WIDTH** | `chain.cpp:477` `value.size() != 8` ⇒ `return false` (no write) | The tx is accepted + finalized, but `parse_u64` short-circuits and the scalar is **never written** — a silent no-op (the trap) | PCL-2 + PCL-3 (§3.3) |
| **HOOK_ONLY** | `chain.cpp:493` unconditional `param_changed_hook_(name, value)` | The value is forwarded to the Node hook; the realized effect depends on whether the operator's Node wired the hook — **not observable by the wallet** | PCL-4 (§3.4, conditional) |

### 1.3 Out of scope (intentional — the lint's coverage boundary)

- **Signature validity.** The lint says **nothing** about whether the PARAM_CHANGE carries a valid K-of-K keyholder multisig. A UNKNOWN_NAME tx is rejected on the *name* before the multisig loop even runs (`validator.cpp:683-686` precedes `:688-725`); an EFFECTIVE/INERT/HOOK_ONLY verdict assumes the tx will *pass* the multisig but does not verify it. Multisig verification is the **separate** `param-change-verify` command (`wallet/main.cpp:23382+`), whose soundness reduces to A1 (Ed25519 EUF-CMA, `Preliminaries.md §2.2`) and which this document references but does not re-derive. A lint is run *before* signatures are assembled; conflating the two would defeat its purpose. (§5 F-PCL2.)
- **Whether the change *should* be made.** The lint predicts the *mechanical* outcome of activation, not its *advisability*. It does not range-check the value: `MIN_STAKE = 0` and `MIN_STAKE = 2⁶⁴−1` are both EFFECTIVE (the chain has no range gate — `GovernanceWhitelistSoundness.md` GW-2 Part 2, the consent-over-bounds boundary). EFFECTIVE means "the scalar will be set to this value," not "this value is sensible." (§5 F-PCL3.)
- **The Node hook's behavior.** For HOOK_ONLY names the wallet cannot link the Node and cannot know whether `param_changed_hook_` is installed, nor what it does with the value. HOOK_ONLY is honestly "forwarded; effect = Node's responsibility," not "will take effect." (§5 F-PCL1 — the load-bearing honesty of this proof.)
- **Activation timing / staging mechanics.** The lint predicts *whether* the change takes effect, not *when*. The `effective_height` field, the staging drain (`GovernanceParamChange.md` T-G4), and the per-height activation are out of scope; the lint reads `value` and `name`, not the schedule. EFFECTIVE asserts "the write happens at the change's activation height," deferring the height semantics to `GovernanceParamChange.md`.
- **Governance mode.** A chain in uncontrolled governance mode rejects *every* PARAM_CHANGE (`validator.cpp:640`) regardless of name. The lint does not know the target chain's mode (it is OFFLINE, with no chain context); an EFFECTIVE/HOOK_ONLY verdict additionally presupposes the target chain is in governed mode. This is a context precondition, stated in §5 F-PCL4, not a verdict the lint can render.

---

## 2. Construction specification

Read directly off the two on-chain rules plus the wallet's reimplementation.

### 2.1 The on-chain whitelist (validator admission)

`src/node/validator.cpp:677-682`:

```cpp
static const std::set<std::string> kWhitelist = {
    "tx_commit_ms", "block_sig_ms", "abort_claim_ms",
    "bft_escalation_threshold", "SUSPENSION_SLASH",
    "MIN_STAKE", "UNSTAKE_DELAY",
    "param_keyholders", "param_threshold",
};
```

applied at `src/node/validator.cpp:683-686`:

```cpp
if (kWhitelist.find(name) == kWhitelist.end()) {
    return {false, "PARAM_CHANGE rejected: parameter '"
                 + name + "' is not on the governance whitelist"};
}
```

Nine names. The reject fires *after* the mode gate (`:640`) and shape/truncation checks (`:644-671`) but *before* the multisig loop (`:688-725`), so an off-list name is rejected **independent of signatures**. The same `kWhitelist` literal and its closure property are the subject of `GovernanceWhitelistSoundness.md` GW-1.

### 2.2 The on-chain activation decode (the width rule + scalar/hook partition)

`src/chain/chain.cpp:476-493`, inside `activate_pending_params`:

```cpp
auto parse_u64 = [&](uint64_t& dst) {
    if (value.size() != 8) return false;          // ← the 8-byte width gate
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
    dst = v;                                       // ← write only reached if width == 8
    return true;
};
if (name == "MIN_STAKE")            { parse_u64(min_stake_); }
else if (name == "SUSPENSION_SLASH") { parse_u64(suspension_slash_); }
else if (name == "UNSTAKE_DELAY")    { parse_u64(unstake_delay_); }
// …
if (param_changed_hook_) param_changed_hook_(name, value);   // unconditional forward
```

The partition is exact and exhaustive over the 9 whitelisted names:

- **Numeric chain-scalars (3):** `MIN_STAKE`, `SUSPENSION_SLASH`, `UNSTAKE_DELAY` — dispatched at `:483-485`; the *only* write to the scalar happens **after** the `value.size() != 8` early-return, so a non-8-byte value leaves the scalar untouched (`return false` before `dst = v`).
- **Hook-forwarded (the other 6):** `tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`, `bft_escalation_threshold`, `param_keyholders`, `param_threshold` — none has a chain-instance `if` branch; all 9 (including the 3 scalars) reach the unconditional `param_changed_hook_(name, value)` at `:493`, but for the 6 non-scalar names the hook forward is the *only* effect path.

Note the hook fires for the 3 scalars too — but their *chain-instance* effect (the one the lint predicts as EFFECTIVE/INERT) is governed by `parse_u64`, not the hook. The lint's EFFECTIVE/INERT verdict is a statement about the *scalar write*, which is fully determined by the width rule and is observable in chain state; the hook's additional effect on those names is a Node concern the lint does not claim.

### 2.3 The wallet reimplementation

`wallet/main.cpp:23315-23341`:

```cpp
static const std::set<std::string> kWhitelist = {            // mirror of validator.cpp:677-682
    "tx_commit_ms", "block_sig_ms", "abort_claim_ms",
    "bft_escalation_threshold", "SUSPENSION_SLASH",
    "MIN_STAKE", "UNSTAKE_DELAY",
    "param_keyholders", "param_threshold",
};
static const std::set<std::string> kNumericScalars = {       // mirror of chain.cpp:483-485
    "MIN_STAKE", "SUSPENSION_SLASH", "UNSTAKE_DELAY",
};
if (kWhitelist.find(name) == kWhitelist.end()) {
    verdict = "UNKNOWN_NAME"; …
} else if (kNumericScalars.find(name) != kNumericScalars.end()) {
    if (value_bytes == 8) { verdict = "EFFECTIVE"; … }       // mirror of chain.cpp:477 width gate
    else                  { verdict = "INERT_BAD_WIDTH"; … }
} else {
    verdict = "HOOK_ONLY"; …                                 // mirror of chain.cpp:493 hook forward
}
```

with `value_bytes = value_hex.size() / 2` (`:23311`) after the strict hex validation (`:23306-23310`).

---

## 3. Soundness theorems

Throughout, let `name` and `value` be the decoded parameter name and value bytes the on-chain validator/activation path would see for a given PARAM_CHANGE, and let `V_lint ∈ {EFFECTIVE, INERT_BAD_WIDTH, HOOK_ONLY, UNKNOWN_NAME}` be the wallet's verdict on the same `(name, value)`. The "activation outcome" `O_chain` is the observable effect on chain state of activating the change (a scalar write, no write, a hook forward, or a validator rejection). Bounds, where they appear, follow `Preliminaries.md §2.0` (A1, A2 ≈ `2⁻¹²⁸`).

### 3.1 PCL-1 (whitelist + partition byte-equivalence)

**Statement.** The wallet's `kWhitelist` (`wallet/main.cpp:23315-23320`) is **byte-for-byte** the validator's `kWhitelist` (`src/node/validator.cpp:677-682`) — the same 9 string literals — and the wallet's `kNumericScalars` (`:23321-23323`) is **byte-for-byte** the set of names with a chain-instance scalar dispatch in `activate_pending_params` (`src/chain/chain.cpp:483-485`) — the same 3 string literals. Consequently the wallet's three-way name classification (`∉ kWhitelist` / `∈ kNumericScalars` / whitelisted-non-scalar) agrees with the chain's classification (rejected / scalar-write-candidate / hook-only) on **every** `name`.

**Proof.** Direct string-literal comparison of the two sets in each codebase:

- *Whitelist.* The validator literal is `{"tx_commit_ms", "block_sig_ms", "abort_claim_ms", "bft_escalation_threshold", "SUSPENSION_SLASH", "MIN_STAKE", "UNSTAKE_DELAY", "param_keyholders", "param_threshold"}` (`validator.cpp:677-682`); the wallet literal is identical, character-for-character including the formatting (`wallet/main.cpp:23315-23320`). Both are `static const std::set<std::string>` initialized from a brace-enclosed compile-time literal — neither is assembled from runtime input, so membership is fixed at program load (the closure property `GovernanceWhitelistSoundness.md` GW-1 proves for the validator copy applies verbatim to the wallet mirror). `std::set<std::string>::find` uses `std::less<std::string>` (lexicographic byte comparison) in both, so `find(name) == end()` returns the *same* boolean in wallet and validator for every `name`. ⇒ The wallet's UNKNOWN_NAME branch fires on exactly the names the validator rejects.

- *Scalar partition.* The chain's scalar dispatch is the `if`/`else if` chain at `chain.cpp:483-485`, whose guards are the string equalities `name == "MIN_STAKE"`, `name == "SUSPENSION_SLASH"`, `name == "UNSTAKE_DELAY"` — exactly the 3 members of the wallet's `kNumericScalars`. No fourth name has a chain-instance branch (exhaustive: lines `:483-485` are the complete `if/else-if` cascade; the next statement is the unconditional hook fire at `:493` with no further `else if`). ⇒ The wallet's `kNumericScalars` membership test partitions the whitelisted names into {scalar-write-candidate} vs {hook-only} identically to the chain's dispatch structure.

The classification is total (every `name` falls into exactly one of the three buckets in both codebases) and the bucket boundaries coincide. Hence the wallet's name-classification is byte-equivalent to the chain's. ∎

**Soundness corollary.** A drift in either set (a name added to / removed from the validator's `kWhitelist` or the chain's scalar dispatch without a matching wallet edit) would make the lint mispredict. This is a *source-coherence* obligation, not a runtime/cryptographic risk: both sets are compile-time literals, so the lint is correct *as of the source it was compiled against*. §6 records the coherence guard (`tools/`); the byte-equivalence here is the property the guard protects.

### 3.2 PCL-2 (width-rule byte-equivalence)

**Statement.** The wallet's width predicate `value_bytes == 8` (where `value_bytes = value_hex.size() / 2`, `wallet/main.cpp:23311` after strict hex validation `:23306-23310`) is **byte-for-byte equivalent** to the on-chain `parse_u64` guard `value.size() == 8` (`src/chain/chain.cpp:477`) on the value the chain decodes for the same PARAM_CHANGE. Therefore the wallet predicts `parse_u64`'s accept/short-circuit decision exactly.

**Proof.** Match the two byte-length computations to the same underlying value:

1. **The value the chain sees.** At activation, `value` is the byte vector the validator decoded from the wire payload at `validator.cpp:661` (`std::vector<uint8_t> value(p.begin()+off, p.begin()+off+vlen)`), staged verbatim via `stage_param_change`, and replayed unchanged into `activate_pending_params`. Its length is `vlen`, the `value_len:u16 LE` field of the payload (`validator.cpp:657`).

2. **The value the lint sees.** When the lint reads `--tx-json` and decodes the **authoritative `payload` hex** (`wallet/main.cpp:23277-23290`), it parses the *same* wire layout (`[name_len u8][name][value_len u16 LE][value]`, `:23286-23289`) and extracts exactly `vlen` value bytes (`vbytes = p[off .. off+vlen]`, `:23289`), then sets `value_hex = to_hex(vbytes)`. So `value_hex.size() = 2·vlen` and `value_bytes = value_hex.size()/2 = vlen` — **identical** to the chain's `value.size()`. When the lint reads `--name`/`--value-hex` directly, `value_bytes = value_hex.size()/2` is by construction the byte length the operator intends the on-chain value to be; the `param-change-build` companion emits exactly this `value_hex`, so the build→lint→submit pipeline carries one consistent value width end to end.

3. **Strict-hex equivalence of the length.** The lint computes the byte width from the hex string length, *not* by decoding through the lenient shared `from_hex` (`wallet/main.cpp:93-107`). The strict per-character hex check (`:23306-23309`) plus the even-length check (`:23310`) guarantee `value_hex` is a well-formed even-length hex string, so `value_hex.size()/2` is its exact decoded byte count — there is no truncation or partial-parse divergence from the chain's `value.size()`. (The comment at `:23303-23305` records precisely why the lenient `from_hex` is *not* used here: `istringstream >> hex` reads a `0` out of `"0g"` without failing, which would let a malformed input pass as a shorter-than-real width — a lint must not silently accept that.)

4. **The decision.** The chain writes the scalar iff `value.size() == 8` (`chain.cpp:477` returns `false` and skips `dst = v` otherwise); the lint emits EFFECTIVE iff `value_bytes == 8`. Since `value_bytes == value.size()` on every input the chain would decode (steps 1-3), the two `== 8` tests return the same boolean. ⇒ EFFECTIVE ⟺ `parse_u64` will write; INERT_BAD_WIDTH ⟺ `parse_u64` will short-circuit. ∎

**The trap is faithfully reproduced.** The honest core of this proof: at the *validator*, a wrong-width value for a whitelisted scalar name is **accepted** — the PARAM_CHANGE validate case (`validator.cpp:636-725`) decodes the value, structurally length-bounds the payload, checks the *name* against `kWhitelist`, binds the value into the multisig `sig_msg` (`validator.cpp:699`), and verifies the K-of-K signatures, but it **never validates the value's byte-width** (per `GovernanceWhitelistSoundness.md` GW-2 / §1.3 — consent is over the *name*, not the value's bounds; the `(void)value;` at `validator.cpp:673` is a defensive unused-cast superseded by the real use at `:699`, not a discard). The transaction is signed, finalized, and drained from the pending set — and only then, at activation, does `parse_u64` enforce the exact-8-byte rule (`chain.cpp:476-482`) and silently drop a mis-sized value. INERT_BAD_WIDTH is the lint's name for this trap, and PCL-2 proves the lint flags it on exactly the inputs the chain will silently no-op.

### 3.3 PCL-3 (composite verdict soundness for the chain-scalar + unknown cases)

**Statement.** For the three chain-scalar names and all off-whitelist names, the lint verdict is a **sound and complete** predictor of the on-chain activation outcome `O_chain`:

- `V_lint = UNKNOWN_NAME` ⟺ the validator rejects the tx (`O_chain` = "never lands");
- `V_lint = EFFECTIVE` ⟺ `name ∈ {MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY}` ∧ width 8 ⟺ the destination scalar is written at activation (`O_chain` = scalar set);
- `V_lint = INERT_BAD_WIDTH` ⟺ same names, width ≠ 8 ⟺ the scalar is never written (`O_chain` = silent no-op).

(The HOOK_ONLY case is PCL-4, conditional.)

**Proof.** By PCL-1, the lint's name classification (`∉ kWhitelist`, scalar, hook-only) coincides with the chain's. By PCL-2, on the scalar names the lint's width decision coincides with `parse_u64`'s. Compose:

- **UNKNOWN_NAME.** PCL-1 ⇒ `name ∉ kWhitelist` in the wallet ⟺ `name ∉ kWhitelist` in the validator ⟺ the validator's reject at `validator.cpp:683-686` fires. The reject precedes the multisig loop (`:688`), so it is signature-independent; it precedes apply, so the tx never stages and never reaches `activate_pending_params`. `O_chain` is "rejected; never lands." Sound (the verdict only fires when the chain rejects) and complete (every off-list name is flagged). This is the lint-side reflection of `GovernanceWhitelistSoundness.md` GW-1's off-list immunity.

- **EFFECTIVE.** PCL-1 ⇒ scalar name; PCL-2 ⇒ width 8 ⇒ `parse_u64` reaches `dst = v`, writing `min_stake_` / `suspension_slash_` / `unstake_delay_` at activation height. `O_chain` is "scalar set to the decoded `uint64`." The lint emits EFFECTIVE on exactly these inputs.

- **INERT_BAD_WIDTH.** PCL-1 ⇒ scalar name; PCL-2 ⇒ width ≠ 8 ⇒ `parse_u64` returns `false` before `dst = v`, leaving the scalar at its prior value. `O_chain` is "tx accepted + finalized, scalar unchanged" — the silent no-op trap. The lint emits INERT_BAD_WIDTH on exactly these inputs.

No verdict is rendered that disagrees with `O_chain` on these cases, and every such case is covered (the three branches are exhaustive over scalar names, and the UNKNOWN_NAME branch is exhaustive over off-list names). ∎

**No cryptographic error term.** Each implication above is a *deterministic* consequence of set membership (PCL-1) and an integer comparison (PCL-2). There is no A1 or A2 term in PCL-3: the lint verdict is a decidable predicate over `(name, value_bytes)`, correct with probability 1 *given byte-equivalent sets* (PCL-1/PCL-2). A1 governs only whether the EFFECTIVE/INERT tx will pass the *multisig* (the §1.3 / §5 F-PCL2 boundary, the `param-change-verify` companion's concern); A2 governs only whether the *resulting* scalar binds into the state root for cross-node agreement (`GovernanceWhitelistSoundness.md` GW-3) — neither is a term in the lint's verdict correctness.

### 3.4 PCL-4 (HOOK_ONLY soundness, CONDITIONAL on the Node hook)

**Statement.** For the six whitelisted non-scalar names (`tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`, `bft_escalation_threshold`, `param_keyholders`, `param_threshold`), the lint emits HOOK_ONLY, which soundly asserts: *the validator accepts the tx (the name is whitelisted, PCL-1) and at activation the chain forwards `(name, value)` to `param_changed_hook_` (`chain.cpp:493`).* **The realized effect is conditional on the Node having installed and wired the hook — which the OFFLINE wallet cannot observe.** HOOK_ONLY therefore asserts "forwarded; effect = Node's responsibility," **not** "will take effect."

**Proof (the forward is unconditional; the effect is not observable).** By PCL-1, a whitelisted non-scalar name passes the validator's whitelist gate. At activation, `activate_pending_params` has *no* chain-instance `if` branch for these six names (PCL-1, the partition is exhaustive at `chain.cpp:483-485`), so no scalar is written — the *only* activation effect path is the unconditional `if (param_changed_hook_) param_changed_hook_(name, value);` at `chain.cpp:493`. Two facts bound what the lint can claim:

1. **The forward is real and unconditional *in the chain*.** Whenever a Node has installed `param_changed_hook_`, every drained PARAM_CHANGE — scalar or not — invokes it with `(name, value)`. So HOOK_ONLY's "the value is forwarded to the hook" is a sound prediction *of the chain's behavior at the activation site*.

2. **The hook body is in the Node layer the wallet does not link.** `param_changed_hook_` is a `ParamChangedHook` installed by `src/node/node.cpp` (its body dispatches on `name` with branches for the validator/Node-mirror names; an unrecognized name produces no Node mutation — `GovernanceWhitelistSoundness.md` §4 / GW-1 Layer 2). Whether the hook is installed at all, and what it does with a given `(name, value)`, is **Node-instance state**. `determ-wallet` does not link `libdeterm_chain` *or* the Node, so it has zero visibility into the hook's presence or semantics. The lint therefore *cannot* upgrade HOOK_ONLY to a definite EFFECTIVE/INERT verdict without overreaching.

Consequence: HOOK_ONLY is the **honest** verdict — it states exactly what the wallet *can* know (the name is whitelisted; the chain will forward the value) and explicitly defers the realized effect to the Node (`wallet/main.cpp:23340`: "forwarded to the Node-installed param hook; effect depends on whether the operator's Node wired the hook"). The exit code treats HOOK_ONLY as `0` (alongside EFFECTIVE) because the tx *will land and be forwarded* — a non-rejection, non-trap outcome — while the human/JSON `detail` field carries the conditional so the operator is not misled into believing a definite mutation occurred. ∎

**The conditional is NOT a probability term.** Like `OfflineBlockVerifySoundness.md` BV-2's digest conditional, PCL-4's "the Node wired the hook" is an *operator/Node-context precondition*, not a cryptographic event. It is handled as a stated boundary (§5 F-PCL1), not absorbed into an `ε`. An operator who needs to know the realized effect of a HOOK_ONLY change must consult the Node's hook implementation (or observe the live Node), which is outside the lint's OFFLINE TCB.

### 3.5 PCL-E (composite verdict total correctness)

**Statement.** Combining PCL-1..PCL-4, the lint's four-way verdict is **total** (every well-formed `(name, value)` input yields exactly one verdict) and **sound** (each verdict correctly predicts `O_chain` — unconditionally for UNKNOWN_NAME / EFFECTIVE / INERT_BAD_WIDTH, conditionally-on-the-Node-hook for HOOK_ONLY), with **no cryptographic error term** in the verdict itself:

$$
\Pr[\,V_{\text{lint}} \neq \text{predict}(O_{\text{chain}})\,\mid\,\text{sets byte-equivalent (PCL-1/PCL-2), target chain governed, Node-hook context known}\,] \;=\; 0.
$$

**Derivation.** Input well-formedness is enforced before the verdict (§0 step 1-2: parse faults → exit 1, never a verdict). On a well-formed input the verdict is one of four, selected by a total decision tree (`∉ kWhitelist` → UNKNOWN_NAME; else `∈ kNumericScalars` → {EFFECTIVE | INERT_BAD_WIDTH} by `value_bytes == 8`; else → HOOK_ONLY) — exactly one leaf per input, so the verdict is total. Soundness is PCL-3 (the three unconditional cases) ∧ PCL-4 (HOOK_ONLY, conditional). Both PCL-1 (set byte-equivalence) and PCL-2 (width byte-equivalence) are deterministic source-level facts; the decision tree is deterministic boolean/integer logic. Hence, *conditioned on the stated preconditions* (byte-equivalent sets — the §6 coherence guard; target chain in governed mode — §5 F-PCL4; Node-hook context for the HOOK_ONLY effect — §5 F-PCL1), the verdict equals the chain's outcome with probability 1. No A1/A2 term appears: the lint neither verifies a signature nor recomputes a hash — its verdict is a pure function of the input bytes. ∎

**Where A1 / A2 *do* enter (boundaries, not the verdict).** (i) **A1** bounds whether an EFFECTIVE/INERT/HOOK_ONLY tx will *clear the multisig gate* and thus actually land — the `param-change-verify` companion's `≤ K·2⁻¹²⁸` forgery bound (`Preliminaries.md §2.2`), *referenced* here, *not re-derived*. (ii) **A2** bounds whether an *activated* EFFECTIVE scalar binds identically into every honest node's state root (`GovernanceWhitelistSoundness.md` GW-3's `p:`/`k:` namespace, `≤ 2⁻¹²⁸`-class) — the cross-node-agreement guarantee the EFFECTIVE verdict presupposes for the change to be globally consistent, *not* a term in the lint's local verdict. Both are stated to scope the lint's claim precisely: the lint predicts *activation effect given the tx lands on a governed chain*; A1 underwrites the landing, A2 underwrites the agreement.

---

## 4. Composition with companion proofs

### 4.1 `GovernanceWhitelistSoundness.md` — the on-chain rule this lint reimplements

PCL-1 reduces directly to **GW-1** (whitelist closure: the 9-name `kWhitelist` is a compile-time `static const` literal, off-list names rejected by set-membership independent of signatures and mode). The wallet's `kWhitelist` is the same literal; PCL-1 adds only the byte-equivalence of the *mirror* to the original. PCL-2/PCL-3's INERT_BAD_WIDTH case reduces to **GW-2 Part 1** (the 8-byte width gate at `chain.cpp:477` gating chain-instance mutation, fail-soft on mismatch — "assign on well-formed, no-op on malformed"). The lint's refusal to range-check (an EFFECTIVE verdict on `MIN_STAKE = 0`) reflects **GW-2 Part 2** (the honest consent-over-bounds gap: width-checked, not range-checked). And the EFFECTIVE verdict's cross-node meaning rests on **GW-3** (the `p:`/`k:` state-root binding ⇒ honest-node convergence on the activated scalar). The lint is, in effect, the OFFLINE *operator-facing read* of GW-1+GW-2: it tells an operator, before submission, which GW-1/GW-2 bucket their change falls into.

### 4.2 `OfflineBlockVerifySoundness.md` — the wallet-TCB-separation sibling

`param-change-lint` instantiates the same discipline as `block-verify`'s **BV-1**: an on-chain rule (there, `compute_tx_root`; here, the whitelist + `parse_u64` width decode) is **reimplemented inline** in `determ-wallet` because the wallet does not link the chain library, and the proof establishes **byte-equivalence** of the reimplementation to the source (BV-1 for the tx-root commitment; PCL-1/PCL-2 for the whitelist + width rule). PCL-4's HOOK_ONLY conditional mirrors **BV-2**'s digest conditional: a verdict that is sound for what the wallet *can* compute but carries an explicit, honestly-stated boundary for what the wallet *cannot* observe (there, the true `compute_block_digest`; here, the Node hook's installation and behavior). Both pay the lean-TCB cost as a stated precondition, not a hidden assumption.

### 4.3 `LightVerifyChainFileSoundness.md` — the offline-reimplementation family

`verify-chain-file` is another member of the OFFLINE-reimplementation family: it consumes a local file and reimplements the chain-walk + per-block sig verify (its **Lemma L-2** byte-equivalence of `light_compute_block_digest`). `param-change-lint` shares the posture — OFFLINE, read-only, reimplements an on-chain check, exit `0`/`2`/`1` — but predicts an *activation outcome* rather than verifying *structural validity*, and (unlike `verify-chain-file`, which links the verification path) carries the HOOK_ONLY conditional because the activation effect for the non-scalar names lives in the Node layer the wallet does not link.

### 4.4 `param-change-verify` companion + `BatchSigningSoundness.md` — the signature half (referenced, not used here)

The lint deliberately says nothing about signatures (§1.3). The *signature* half of the governance toolchain is `param-change-verify` (`wallet/main.cpp:23382+`), which reimplements the validator's Ed25519 multisig gate (`validator.cpp:688-725`) and whose per-signer verification loop instantiates **BS-3** (`BatchSigningSoundness.md`, per-record structural isolation: signer `i`'s verdict depends only on `(σ_i, message, pk_i)`, no cross-signer channel) under **A1**. This document references that reduction to delineate the boundary — a complete governance preflight runs *both* `param-change-lint` (will it take effect?) and `param-change-verify` (is the multisig valid?) — but PCL-1..PCL-E do not use A1 or BS-3.

### 4.5 `Preliminaries.md` — the assumption base (boundaries only)

The lint *verdict* reduces to neither A1 nor A2 — it is deterministic (PCL-E). A1 (`§2.2`) and A2 (`§2.1`) are cited only to scope the boundaries: A1 for the multisig landing (the verify companion), A2 for the state-root binding of the activated scalar (GW-3). This is consistent with the deterministic-reimplementation posture: a byte-length comparison and a set-membership test have no cryptographic error term.

---

## 5. Findings (honest limitations)

Stated so an operator knows exactly what each lint verdict does and does not assert. None undermines PCL-1..PCL-3's unconditional soundness; F-PCL1 is the one TCB-separation conditional (PCL-4), and the rest are scope statements.

### F-PCL1 HOOK_ONLY is conditional on the Node hook — the wallet cannot observe the realized effect (the TCB-separation cost)

This is the load-bearing honesty of the proof. For the six whitelisted non-scalar names, the chain's *only* activation effect path is the forward to `param_changed_hook_` (`chain.cpp:493`), whose body lives in `src/node/node.cpp` — the Node layer `determ-wallet` does **not** link. A HOOK_ONLY verdict soundly asserts "whitelisted ⇒ accepted, and the chain will forward `(name, value)` to the hook," but it **cannot** assert the change takes a specific effect: whether the hook is installed, and what it does with the value, is Node-instance state invisible to the OFFLINE wallet. HOOK_ONLY is deliberately scoped to "forwarded; effect = Node's responsibility" (`wallet/main.cpp:23340`), and exits `0` because the tx lands and is forwarded (a non-rejection, non-trap outcome), not because a definite mutation is guaranteed. An operator who needs the realized effect of a HOOK_ONLY change must consult the Node's hook implementation. This is the cost of the wallet's lean, chain-library-free TCB, paid as a stated operator obligation.

### F-PCL2 The lint says nothing about signature validity

A lint verdict (other than UNKNOWN_NAME) presupposes the tx will *pass* the validator's K-of-K multisig gate but does **not** verify it. The multisig is the separate `param-change-verify` command (A1 / BS-3, §4.4). UNKNOWN_NAME is rendered on the *name* before the multisig loop even runs (`validator.cpp:683-686` precedes `:688`), so it is correct regardless of signatures; EFFECTIVE/INERT/HOOK_ONLY describe the *activation* outcome *conditional on the tx landing*. A complete preflight runs both commands.

### F-PCL3 EFFECTIVE means "the scalar will be set," not "the value is sensible" — no range check

The lint reimplements the chain's *width* gate, not a range gate, because the chain has no range gate (`GovernanceWhitelistSoundness.md` GW-2 Part 2 — consent-over-bounds). `MIN_STAKE = 0`, `MIN_STAKE = 2⁶⁴−1`, and `UNSTAKE_DELAY = 2⁶⁴−1` all lint EFFECTIVE: each is a well-formed 8-byte value the chain will write. EFFECTIVE is a prediction of the *mechanical* outcome, not an endorsement of the value's operational wisdom. The N-of-N keyholder threshold — not the lint — is the value-correctness oracle.

### F-PCL4 EFFECTIVE / HOOK_ONLY presuppose a governed target chain — the lint has no chain context

The lint is OFFLINE with no chain context, so it does not know the target chain's `governance_mode`. A chain in uncontrolled governance mode rejects *every* PARAM_CHANGE (`validator.cpp:640`) before the whitelist gate. An EFFECTIVE/HOOK_ONLY verdict therefore additionally presupposes the target chain is in governed mode; against an uncontrolled chain, the true outcome for *all* names is "rejected," which the lint cannot detect. (UNKNOWN_NAME is correct in both modes: an off-list name is rejected either way.) This is a context precondition, not a verdict defect.

### F-PCL5 Source-coherence is a maintenance obligation, not a runtime guarantee

PCL-1/PCL-2 prove byte-equivalence *as of the source the wallet was compiled against*. If a future change adds a name to the validator's `kWhitelist` (or a scalar dispatch to `chain.cpp:483-485`) without a matching edit to the wallet's `kWhitelist`/`kNumericScalars`, the lint will mispredict the new name (e.g. classify a newly-added scalar as HOOK_ONLY, or a newly-whitelisted name as UNKNOWN_NAME). This is a coherence-drift risk addressed by the offline `tools/` guards (§6), not a cryptographic or runtime hazard. The proof's byte-equivalence is the invariant those guards protect.

### F-PCL6 The `--tx-json` path trusts the build's payload/name fields it decodes

When fed `--tx-json`, the lint *prefers* to decode the authoritative on-chain `payload` hex (the bytes the validator will actually see, `wallet/main.cpp:23277-23290`), which makes the verdict a faithful prediction of the chain's view (PCL-2 step 2). It falls back to the convenience `name`/`value_hex` fields only if no `payload` is present (`:23291-23297`). An operator who supplies a hand-edited tx-json whose convenience fields disagree with its `payload` gets a verdict over whichever field the lint decoded (payload-first); the build tool (`param-change-build`) emits self-consistent JSON, so the build→lint pipeline carries one value. This is inherited from the build's correctness, not a new surface.

---

## 6. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Subject | File:lines | Role |
|---|---|---|---|
| PCL-1 | wallet `kWhitelist` mirror | `wallet/main.cpp:23315-23320` | The 9-name reimplementation. |
| PCL-1 | wallet `kNumericScalars` | `wallet/main.cpp:23321-23323` | The 3 chain-scalar names. |
| PCL-1 | validator `kWhitelist` (original) | `src/node/validator.cpp:677-682` | The byte-identical reference set. |
| PCL-1 | validator whitelist reject | `src/node/validator.cpp:683-686` | `find(name)==end()` ⇒ reject (signature-independent, pre-multisig). |
| PCL-1 | chain scalar dispatch (original) | `src/chain/chain.cpp:483-485` | The 3-case `if/else-if` defining the scalar partition. |
| PCL-2 | wallet strict width compute | `wallet/main.cpp:23306-23311` | Strict hex check + `value_bytes = value_hex.size()/2`. |
| PCL-2 | wallet payload decode | `wallet/main.cpp:23277-23290` | `--tx-json` decodes the authoritative `[…value_len u16 LE][value]` payload. |
| PCL-2 | chain `parse_u64` width gate | `src/chain/chain.cpp:476-482` | `if (value.size() != 8) return false;` before `dst = v` — the reference rule. |
| PCL-2 | why not lenient `from_hex` | `wallet/main.cpp:23303-23305`, `:93-107` | The strict check exists because shared `from_hex` (`istringstream >> hex`) is lenient. |
| PCL-3 | wallet verdict decision tree | `wallet/main.cpp:23325-23341` | UNKNOWN_NAME / EFFECTIVE / INERT_BAD_WIDTH / HOOK_ONLY selection. |
| PCL-3 | validator mode gate (precondition) | `src/node/validator.cpp:640` | Uncontrolled mode rejects all (F-PCL4). |
| PCL-3 | value width never checked at validate | `src/node/validator.cpp:636-725` | the value is bound into `sig_msg` (`:699`) + multisig-verified but its byte-width is never validated; the 8-byte gate is only at activation (`chain.cpp:476-482`) — the trap's enabling condition. |
| PCL-4 | chain unconditional hook forward | `src/chain/chain.cpp:493` | `param_changed_hook_(name, value)` — the only effect path for the 6 non-scalar names. |
| PCL-4 | wallet HOOK_ONLY detail | `wallet/main.cpp:23338-23340` | "forwarded … effect depends on whether the operator's Node wired the hook." |
| PCL-E | wallet exit-code map | `wallet/main.cpp:23343-23360` | `ok = EFFECTIVE||HOOK_ONLY`; exit 0/2; 1 on parse faults. |
| PCL-E | dispatch | `wallet/main.cpp:25078` | `param-change-lint` → `cmd_param_change_lint`. |

**Coherence guard (F-PCL5).** The byte-equivalence of the wallet mirror to the validator/chain sources is protected by the offline `tools/test_*.sh` family (the doc-tier / surface guards described in `docs/SECURITY.md`); a divergence between the wallet's `kWhitelist`/`kNumericScalars` and `validator.cpp:677-682` / `chain.cpp:483-485` is a coherence-drift regression those guards are positioned to catch. The companion `param-change-verify` (signatures) and `param-change-build` (assembly) round out the offline governance preflight toolchain.

---

## 7. Status

- **Implementation.** **SHIPPED.** `int cmd_param_change_lint` is in `wallet/main.cpp:23230-23361` (dispatched on `param-change-lint` at `:25209`). It reimplements two on-chain rules — the validator's 9-name `kWhitelist` (`src/node/validator.cpp:677-682`) and the activation path's `parse_u64` 8-byte-width decode + scalar/hook partition (`src/chain/chain.cpp:476-493`) — over a chain-library-free TCB.
- **Proof.** Complete (this document). **PCL-1** (whitelist + scalar-partition byte-equivalence to the validator/chain source — the 9-name set and 3-name scalar set are character-identical mirrors, so the lint's name classification coincides with the chain's). **PCL-2** (width-rule byte-equivalence — `value_bytes == 8` predicts `parse_u64`'s `value.size() == 8` accept/short-circuit exactly, including the strict-hex length that avoids the lenient `from_hex` divergence; the INERT_BAD_WIDTH trap is faithfully reproduced). **PCL-3** (composite verdict soundness — UNKNOWN_NAME ⟺ validator reject, EFFECTIVE ⟺ scalar write, INERT_BAD_WIDTH ⟺ silent no-op, with **no cryptographic error term**). **PCL-4** (HOOK_ONLY soundness, **CONDITIONAL** on the Node hook — the forward at `chain.cpp:493` is real and unconditional, but the realized effect lives in the Node layer the OFFLINE wallet cannot observe; the verdict is honestly scoped). **PCL-E** (total correctness — the four-way verdict is total and sound, deterministic, no A1/A2 term in the verdict; A1 and A2 enter only at the multisig-landing and state-root-binding boundaries).
- **Cryptographic assumptions used.** **None in the verdict** (the lint is a deterministic set-membership + integer-width predicate). **A1** (Ed25519 EUF-CMA, `Preliminaries.md §2.2`) and **A2** (SHA-256 collision resistance, `Preliminaries.md §2.1`) are cited only to scope the boundaries: A1 for whether the predicted tx clears the multisig gate (the `param-change-verify` companion), A2 for whether an activated EFFECTIVE scalar binds into the state root for cross-node agreement (`GovernanceWhitelistSoundness.md` GW-3). A3, A4 not used.
- **Composes with.** `GovernanceWhitelistSoundness.md` (GW-1 whitelist closure / GW-2 width-not-range / GW-3 state-root binding — the on-chain rule this lint reimplements), `OfflineBlockVerifySoundness.md` (BV-1 byte-equivalence reimplementation / BV-2 the honestly-stated conditional — the wallet-TCB-separation sibling), `LightVerifyChainFileSoundness.md` (the offline-reimplementation family, Lemma L-2 byte-equivalence posture), `BatchSigningSoundness.md` (BS-3 — referenced for the `param-change-verify` signature companion, not used here), `GovernanceParamChange.md` (staging/activation drain mechanics), `Preliminaries.md` (A1 + A2 boundary base).
- **Known limitations (§findings).** **F-PCL1 (the load-bearing one: HOOK_ONLY is conditional on the Node hook — the wallet-TCB-separation cost; the wallet cannot observe whether/how the Node wired the hook)**; F-PCL2 (the lint says nothing about signature validity — that is `param-change-verify`); F-PCL3 (EFFECTIVE means the scalar will be set, not that the value is sensible — no range check, per GW-2); F-PCL4 (EFFECTIVE/HOOK_ONLY presuppose a governed target chain — the OFFLINE lint has no chain-mode context); F-PCL5 (source-coherence is a maintenance obligation protected by the `tools/` guards, not a runtime guarantee); F-PCL6 (the `--tx-json` path decodes the authoritative payload first, trusting the build's self-consistency). None undermines PCL-1..PCL-3's unconditional soundness.
- **The TCB-separation posture (load-bearing).** `determ-wallet` deliberately does not link the chain library. The whitelist set and the `parse_u64` width rule are reimplemented inline; PCL-1/PCL-2 prove the reimplementations are byte-identical to the source, so for the scalar + unknown cases the verdict is exactly the chain's outcome (sound, unconditional, no cryptographic term — PCL-3). The HOOK_ONLY case cannot be resolved to a definite effect because the hook body is in the Node layer the wallet does not link, so its verdict is honestly scoped to "forwarded; effect = Node's responsibility" (PCL-4). This is the precise boundary between what `param-change-lint` predicts unconditionally (whitelist admission + the chain-scalar write/no-op) and what it predicts conditionally (the hook-forwarded effect, given a wired Node).
