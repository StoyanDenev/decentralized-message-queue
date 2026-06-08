# Light-Client Persisted-Anchor Soundness (`determ-light state` / `verify-chain --persist`)

**Status: implementation + soundness analysis.** Lands the *persisted stateful
light client* substrate the medium-tier light-client scope deferred
(`robust-gathering-oasis.md` "What's explicitly NOT in this scope": *"No
persistence. Each invocation re-anchors from genesis. The 'stateful sync client'
tier would add a `~/.determ-light/state.json` with the last verified head"*) and
the limitation `LightClientCompositionMap.md` §6 records as *"no persistence
(re-anchors from genesis every run)"*. The `verify-chain --persist` writer +
`state` management subcommand + `light/persist.{hpp,cpp}` module are the
validated, genesis-pinned, schema-versioned, fail-closed cache. The fast-resume
*consumer* (`verify_chain_from_anchor` — skip re-verifying `0..head_height`) is
the clearly-marked daemon-bound follow-up (LSP-6).

## 1. Mechanism

`LightState` (`light/persist.hpp`) = `{schema_version, genesis_hash, head_height,
head_block_hash, head_state_root}`.

- **Write** (`verify-chain --persist [--state <path>]`,
  `light/main.cpp::cmd_verify_chain`): after — and only after —
  `anchor_genesis` + `verify_chain_to_head` succeed, the verified head is
  serialized via `save_light_state`. The persisted `genesis_hash` is the
  light-client's LOCAL `compute_genesis_hash` recompute (`genesis_hash_hex`),
  never the daemon's claimed value.
- **Read / validate** (`load_light_state`): parses + validates JSON, throwing a
  field-naming `std::runtime_error` on malformed JSON / unknown `schema_version`
  / missing / wrong-length / non-hex field. A clean return is a well-formed,
  schema-current state — never a partial one.
- **Manage** (`state --show | --clear | --selftest`,
  `light/main.cpp::cmd_state`): offline (no daemon). `--show` loads + validates +
  prints; `--clear` deletes; `--selftest` runs the in-binary round-trip +
  reject-path checks.
- **Path resolution** (`default_state_path`): `--state <path>` ›
  `$DETERM_LIGHT_STATE` › `<home>/.determ-light/state.json`.

## 2. Trust model

`LightClientThreatModel.md` §6 — **trusted local environment**. The state file
lives on the operator's own machine. A locally-tampered `state.json` is OUT of
scope: an attacker who can rewrite it can rewrite the binary that reads it, so
defending the file against its own host buys nothing. The security the code DOES
provide is that a stale, wrong-chain, or corrupt cache cannot cause the client to
*accept an unverified chain* — it can at worst change *where* verification starts,
and the genesis pin + forward re-verification (LSP-2, LSP-6) catch a divergent
chain there. **No new cryptographic assumption** beyond the per-run
`verify-chain` base {A1 Ed25519 EUF-CMA, A2 SHA-256 collision resistance}
(`Preliminaries.md` §2.0–§2.2).

## 3. Theorems

**LSP-1 (No-unverified-write).** `cmd_verify_chain` calls `save_light_state` only
on the success path *after* `anchor_genesis` (genesis pin) and
`verify_chain_to_head` (prev_hash continuity + K-of-K committee Ed25519 over
`compute_block_digest` for every block `1..head`) both return. A genesis
mismatch, chain break, bad signature, or unreachable daemon throws before the
write. Therefore a persisted anchor is *always* a fully committee-verified head
of the operator's pinned chain — never a head the daemon merely asserted. (Test:
`tools/test_light_state.sh` (C) pins that a failed verify leaves no state file.)

**LSP-2 (Genesis-pin on reuse).** The persisted `genesis_hash` is the local
recompute. Any future consumer re-checks it against the `--genesis` the operator
supplies on the resuming run (LSP-6); a state whose `genesis_hash` ≠ the
recomputed genesis of the supplied config is rejected. So an attacker who swaps
in a state file from a *different* chain (eclipse-onto-another-chain) cannot make
a resume silently adopt it — the anchor is only honored under the operator's own
genesis. (This is the persisted analog of the T-L1 anchor.)

**LSP-3 (Schema-version gate).** `load_light_state` rejects any
`schema_version ≠ 1` with a diagnostic, rather than misreading a field set a
future/past build wrote. A schema change bumps the version; an incompatible
cache fails closed and is cleared, not silently half-parsed.

**LSP-4 (Fail-closed load).** A corrupt cache (malformed JSON, missing required
field, wrong-length / non-hex `genesis_hash` / `head_block_hash` / `head_state_root`)
throws — surfaced as exit 1 on `state --show`, distinct from the exit-0 graceful
"no anchor" for an *absent* file. A corrupt anchor is therefore never silently
treated as empty (which could mask tampering) nor partially loaded (which could
yield a half-populated `LightState`). `head_state_root` is the one field allowed
empty (`""`) — exactly the pre-S-033 chain case — and only that; a non-empty
value must be 64 hex.

**LSP-5 (Read-soundness of the cache).** Combining LSP-1..LSP-4: anything
`load_light_state` returns is (a) well-formed and schema-current, (b) — if it was
written by this client — a committee-verified head, (c) honored on reuse only
under the operator's own genesis. The cache cannot *inject* an unverified or
wrong-chain head into a later decision; the worst a tampered-but-well-formed file
achieves within the threat model is moving the resume origin, which LSP-6's
forward re-verification then validates.

**LSP-6 (Resume soundness — the follow-up boundary, stated honestly).** This
increment ships the cache + writer + management surface. It does NOT yet make
`verify-chain` *consume* the cache to skip work: the current `verify-chain`
re-verifies `0..head` from genesis on every run regardless of any persisted
anchor, so reading the cache trust-reduces nothing *yet*. The fast-resume
optimization — `verify_chain_from_anchor`: re-verify only headers ABOVE
`head_height`, chaining from `head_block_hash`, after re-pinning `genesis_hash`
(LSP-2) — is the marked daemon-bound next increment. Its soundness will rest on:
prev_hash continuity from the persisted `head_block_hash` (a daemon serving a
fork *below* the anchor breaks the link and is caught) + committee-verifying the
suffix `head_height+1 .. new_head`. Until then, persistence is a correctness- and
ergonomics-neutral substrate whose only live effect is the `state` management
surface and the `--persist` write — both fully exercised offline.

## 4. What it does NOT do (honest limitations)

- **No trust reduction yet** — see LSP-6. The fast-resume consumer is the
  follow-up; this increment is the validated substrate it builds on.
- **Local-tamper is out of scope** — §2. The file is trusted-local; integrity
  against its own host is not a goal (and not achievable without a separate root
  of trust the medium tier does not assume).
- **Single-anchor, head-only** — the cache stores the verified head, not the full
  committee history or a checkpoint chain. Committee rotation across a long
  offline gap is re-derived by the resume's forward verify, not cached.

## 5. Test surface

`tools/test_light_state.sh` — 15 offline assertions, deterministic on every host
(the persistence module is daemon-free): (A) `state --selftest` (the in-binary
round-trip + 5 fail-closed reject paths: malformed JSON, bad `schema_version`,
short `genesis_hash`, missing field, empty-`state_root` round-trip); (B)
`--show`/`--clear` graceful-absence + valid-show + fail-closed-on-corrupt +
mode-flag / unknown-arg / `$DETERM_LIGHT_STATE`-override contract; (C)
`verify-chain --persist`/`--state` arg acceptance + the LSP-1 no-write-on-failed-
verify guarantee. The cluster-bound live `--persist` write (a real verified head
landing in the cache) and the LSP-6 resume path are exercised on WSL2 / CI.

## 6. Cross-references

`LightClientThreatModel.md` §6 (trusted local environment; T-L1 anchor reused by
LSP-2), `LightClientCompositionMap.md` §6 (the "no persistence" limitation this
substrate addresses), `MultiPeerCrossCheckSoundness.md` (the sibling §6-residual
closure — multi-peer eclipse detection), `StateRootAnchorSoundness.md` (the
`head_state_root` the cache stores), `Preliminaries.md` §2.0–§2.2 (A1/A2).
