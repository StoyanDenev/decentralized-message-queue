# DSSO PID Verification — DSSO as a Wallet-Relying Party

**Subject.** The code that lets DSSO accept a **Person Identification Data (PID)
presentation** from an EUDI Wallet Unit, verify it, and decide whether it may be
bound to a DSSO account: `dapps/dsso/dsso_jose.{h,c}` (the bounded external-format
readers and ES256), `dapps/dsso/dsso_pid.{h,c}` (the nine verification rules and
the PID Provider trust anchor store), `dapps/dsso/dsso_bind.{h,c}` (the account
binding rules and the pseudonym). Gate: `determ-dsso selftest-pid`, wrapper
`tools/test_dsso_pid.sh`, FAST.

**Role.** Regulation (EU) 2024/1183 Art. 5b — *wallet-relying party*. DSSO
consumes PID presented by a wallet in order to proof identity at enrolment. DSSO
is **not** a European Digital Identity Wallet, **not** a Wallet Provider, **not**
a Member State-notified electronic identification scheme, and **not** a qualified
trust service provider. Nothing in this document or in the code may be read as
any of those.

**Passing this gate is not a compliance claim.** A falsify-on-mutant gate proves
the code enforces what the gate asserts. It does not prove the assertion is the
property a regulation requires, and it certainly does not confer a status that
only a Member State can confer. §8 lists what is NOT claimed, in full.

---

## 1. What is claimed

Let `Π` be a byte string a wallet presents and `P` the relying-party policy
(`dsso_pid_policy`: DSSO's own relying-party identifier, the nonce DSSO issued for
this request, the current time and its tolerances, the required assurance level,
the PID Provider trust anchor list, and the injected status-token fetch).

> **T-PID.** `dsso_pid_verify(Π, P)` returns `DSSO_OK` only if **all nine** of the
> following hold, and returns the named status for the first that fails:
>
> | # | Rule | Fails with |
> |---|---|---|
> | 1 | `Π` is a well-formed SD-JWT VC combined-format presentation under the bounds of `dsso.h`, with canonical base64url and strict JSON throughout | `DSSO_E_FORMAT` |
> | 2 | the issuer's verification key is an entry of the configured PID Provider trust anchor list selected by the token's `iss` and `kid`, and the token supplies no key material of its own | `DSSO_E_TRUST` |
> | 3 | the issuer JWT carries a valid ES256 signature, by that key, over exactly the wire bytes `header.payload` | `DSSO_E_CRYPTO` |
> | 4 | every presented disclosure hashes to a distinct entry of the issuer-signed `_sd` array, introduces no registered or already-present claim name, and there are at most `DSSO_MAX_CLAIMS` of them | `DSSO_E_FORMAT` |
> | 5 | a Key Binding JWT is present, typed `kb+jwt`, signed by the key the credential binds in `cnf`, and its `sd_hash` is SHA-256 over exactly the presented credential and disclosures | `DSSO_E_BINDING` |
> | 6a | the KB-JWT's `aud` equals DSSO's own relying-party identifier | `DSSO_E_AUDIENCE` |
> | 6b | the KB-JWT's `nonce` equals the challenge DSSO issued for **this** request | `DSSO_E_REPLAY` |
> | 7 | `iat`, `nbf` and `exp` place the credential, and `iat` places the presentation, inside the policy's skew and maximum-age windows | `DSSO_E_EXPIRED` |
> | 8 | the credential's Token Status List entry is readable and says VALID | `DSSO_E_STATUS` (revoked/suspended) or `DSSO_E_UNAVAILABLE` (not readable) |
> | 9 | the effective assurance level — `min(anchor cap, credential `acr`)` — is at least the required level | `DSSO_E_ASSURANCE` |
>
> On any failure the result structure is zeroed, so a caller that ignores the
> status reads no claims.

> **T-BIND.** `dsso_bind_commit` binds a verified subject to a DSSO account only
> if (i) the account holder produced a fresh re-authentication proof under the
> account's own key when the binding challenge was opened, (ii) the subject is
> bound to no other account and the account is bound to no other subject, and
> (iii) the presentation answers the still-open, not-yet-expired challenge
> recorded for **that account**, which is consumed by the attempt. What is stored
> is a keyed pseudonym; the raw national identifier is scrubbed before the
> function returns.

> **T-PARSE.** Every reader in `dsso_jose.c` terminates with a definite verdict on
> every input, writes nothing outside the buffer it was given, and allocates
> nothing. Its worst-case work and stack are compile-time constants derived from
> the caps in `dsso.h`, not functions of what a wallet sent. Measured with GCC
> `-fstack-usage`: `pid_verify_inner` 59 888 bytes (the status check inlines into
> it — 16 KiB fetched token, 16 KiB inflated bitstring, 4 KiB compressed, 4 KiB
> payload), `dsso_json_member` 2 768, everything else three figures. A whole
> verification runs in roughly 62 KiB of stack, allocates nothing, and that number
> does not move with what a wallet sent.

---

## 2. Format choice: SD-JWT VC, and mdoc is NOT implemented

ARF v2.9.0 **OIA_03 / OIA_03b / OIA_04** admit two attestation formats for remote
presentation over OpenID4VP: the JOSE/JSON profile (**SD-JWT VC**) and **ISO/IEC
18013-5 mdoc**, profiled for remote use by ISO/IEC TS 18013-7 Annex B. This
increment implements the first and only the first.

**Why SD-JWT VC.**

1. **Attack surface.** The relying party's parser is the service's front door and
   is reached before any signature has been checked. SD-JWT VC needs base64url
   and JSON — two readers, both written here, both fuzzed here. mdoc needs CBOR
   *and* COSE_Sign1 *and* the mdoc device-engagement/session structures, and its
   `IssuerSignedItemBytes` are CBOR tag-24 byte strings whose deterministic
   encoding has to be enforced byte-exactly, or the issuer digests can be
   recomputed over a re-encoding that means something else. That is a strictly
   larger and strictly subtler thing to write fail-closed. The repository rule is
   the smallest increment that is true (`CLAUDE.md`, project doctrine).
2. **No new primitive, no new dependency.** SD-JWT VC with a Key Binding JWT
   composes from SHA-256 and P-256, both shipped in `determ::c99`. ES256 itself is
   not exposed by the shipped stack — there is no ECDSA verifier in
   `include/determ/crypto/p256/p256.h` — so the JOSE framing is built here on the
   primitives that *are* exposed (`determ_p256_scalar_inv_mod_n`,
   `determ_p256_scalar_mul_mod_n`, `determ_p256_msm_ct`,
   `determ_p256_point_compress`, `determ_p256_point_check`). Nothing is vendored
   and no hardness assumption is added.
3. **Holder binding is explicit and separable.** SD-JWT VC carries `cnf` and a
   KB-JWT that signs over audience, nonce and a hash of exactly the presented
   material, so **OIA_02** is checkable with the same signature machinery as the
   issuer signature. mdoc's `DeviceAuth` is equivalent in intent but consumes the
   ISO 18013-7 session transcript, i.e. the handshake as well as the credential.

**Consequence, stated plainly: a wallet that can only present ISO/IEC 18013-5
mdoc is out of scope for DSSO.** DSSO does not negotiate down to a weaker check
for such a wallet; `dsso_pid_verify` refuses it at rule 1. mdoc support is a
second increment with its own design, its own CBOR reader and its own gate.

---

## 3. The argument, rule by rule

### 3.1 Structure (rule 1) — `dsso_b64url_decode`, `dsso_json_validate`, `dsso_jwt_split`, `wire_charset_ok`

The claim is not "the parser is correct" but the weaker and checkable **one byte
string, one meaning**: two inputs that a lenient reader would treat as equivalent
must not both be accepted, because that equivalence is exactly how a signature
ends up covering different bytes than the ones acted on.

- base64url is **unpadded and canonical**: `'='`, `'+'`, `'/'`, whitespace and
  every other non-alphabet byte are rejected; a length ≡ 1 mod 4 is rejected; and
  the unused low bits of a final partial group must be zero, so `"QQ"` decodes to
  `0x41` and `"QR"` is refused rather than decoding to the same byte. The decoder
  validates the whole input before writing anything, so a failure leaves the
  output untouched.
- JSON **duplicate member names are rejected**, not resolved. First-wins and
  last-wins are both defensible and that is the problem: a signer using one rule
  and a verifier using the other read two different documents out of one byte
  string. The detector compares names **after unescaping**, so a name spelled
  with a `\u` escape does not slip past it, and `dsso_json_member` unescapes too,
  so lookup and detection cannot disagree.
- Trailing data after the top-level value is rejected; so are RFC 8259 violations
  that lenient parsers accept (leading `+`, leading zero, `NaN`, comments,
  trailing commas, single quotes, raw control characters in strings, unpaired
  surrogates).
- Nesting is capped at `DSSO_JSON_MAX_DEPTH`, which is also the parser's
  recursion depth, so the C stack footprint is a compile-time constant. Containers
  are capped at `DSSO_JSON_MAX_ELEMS` elements and the document at
  `DSSO_JSON_MAX_KEYS` recorded member names — the duplicate detector's working
  set, which is a fixed array, not an allocation.
- The whole presentation is first screened against the combined-format alphabet
  (`[A-Za-z0-9-_.~]`) by `wire_charset_ok`, so no later stage has to reason about
  an embedded NUL or a byte that could split a claim name.
- `dsso_jwt_split` takes the **signing input from the wire** rather than
  re-encoding the header and payload it parsed.

### 3.2 Issuer trust (rule 2, ARF **OIA_12**) — `dsso_trust_lookup`, `header_ok`

ARF v2.9.0 **OIA_12**: *"a Relying Party SHALL validate the signature of a PID
using a trust anchor provided in a PID Provider Trusted List."* The operative word
is **provided**. `dsso_trust_lookup` takes the token's `iss` and `kid` as
**selectors** into a configured `dsso_trust_list` and returns a key the operator
already trusted; an unmatched pair is `DSSO_E_TRUST` with no fallback, no
discovery and no "unknown issuer at reduced assurance".

`header_ok` refuses a header carrying `jwk`, `jku`, `x5u`, `x5c` or `x5t`
outright: a token that carries its own key is not asking to be verified, it is
asking to choose its own verifier. `crit` is refused because DSSO implements no
critical extension and RFC 7515 §4.1.11 forbids processing a header it does not
understand.

The gate proves the key really comes from the list in two directions: emptying
the list makes the same presentation fail `DSSO_E_TRUST`, and flipping one bit of
the anchor's stored key makes it fail `DSSO_E_CRYPTO`.

### 3.3 Signature (rule 3) — `dsso_es256_verify`, `header_ok`

`alg` must be exactly `"ES256"`. That single comparison is what rejects both the
`alg: none` family and algorithm substitution (an EC public key re-presented as an
HMAC key under `HS256`), because the algorithm is never read to *select* a
verifier — only to be compared against the one algorithm this service implements.
The algorithm check runs **before** the signature is decoded, deliberately: an
`alg: none` token carries an empty signature, and a verifier that rejects it for
being the wrong length has not actually refused `none`.

`dsso_es256_verify` is standard ECDSA verification composed on the shipped
primitives: reduce SHA-256(`m`) mod *n*, `w = s⁻¹`, `R = (e·w)·G + (r·w)·Q` via
the constant-time two-term multi-scalar multiplication, accept iff
`x(R) mod n == r`. The public key is re-validated on the curve inside the
function, so no caller can smuggle an off-curve point past the check, and the
point at infinity is a rejection rather than a special case.

**Canonical encodings and malleability, stated plainly.** JOSE fixes the
signature at 2·32 bytes, which removes DER's length and negative-integer
ambiguities; what remains to check is that `r` and `s` are both in `[1, n−1]`, and
a zero, ≥ n, short or long scalar is `DSSO_E_FORMAT`. ECDSA is nonetheless
**signature-malleable by construction**: if `(r, s)` verifies then so does
`(r, n − s)`. RFC 7515 does not mandate the low-S form, so rejecting high-S would
reject conforming wallets, and this verifier accepts both. The property DSSO needs
instead is that **nothing downstream is keyed on signature bytes**: the replay key
is the DSSO-issued nonce (single-use, §3.9), holder binding is the KB-JWT's
`sd_hash` over the presented material, and the account pseudonym is derived from
the subject material. A malleated re-presentation therefore buys an attacker a
second byte string and no second acceptance. The gate asserts this rather than
assuming it: the `(r, n − s)` twin is a *different byte string* that verifies and
yields the *same claims*.

### 3.4 Selective disclosure (rule 4)

`_sd_alg` must be `"sha-256"`. Each `_sd` entry must be canonical base64url of
exactly 32 bytes, and the entries must be distinct. Each presented disclosure is
hashed **as it appears on the wire** and must match one `_sd` entry; a matched
entry is marked used, so a second disclosure hashing to the same entry is a
duplicate and is rejected. A disclosure matching no entry is rejected.

Four further rejections close the "claimed but not disclosed" shape — an attribute
asserted outside the digest mechanism:

- a disclosure whose name is a registered JWT or SD-JWT VC name (`iss`, `sub`,
  `cnf`, `exp`, `status`, `acr`, `_sd`, `...`, …), which would let the holder
  overwrite what the issuer signed;
- a disclosure whose name is already a member of the issuer-signed payload, which
  would let the holder supply a second value for a claim the issuer stated in
  cleartext;
- two disclosures with the same name;
- a salt below 128 bits of base64url, which would let the `_sd` array be
  brute-forced back into the attribute values the holder withheld.

At most `DSSO_MAX_CLAIMS` attributes are accepted.

### 3.5 Holder binding (rule 5, ARF **OIA_02**)

`cnf.jwk` must be a P-256 JWK with 32-byte fixed-width coordinates and a point on
the curve. The KB-JWT must be present (a presentation ending in `~` is
`DSSO_E_BINDING`, not "holder binding optional"), typed `kb+jwt`, and signed by
that key.

Its `sd_hash` must equal SHA-256 over the presentation **up to and including the
final `~`** — that is, over exactly this issuer JWT and exactly these
disclosures. This is what makes a KB-JWT non-transferable between presentations:
lifting one from another presentation, or editing the disclosure set under it,
changes the hashed bytes. The gate's `KB_REPLAY` vector is precisely that attack.

### 3.6 Audience and request binding (rule 6)

`aud` must equal `pol->rp_id`; otherwise `DSSO_E_AUDIENCE`. A presentation
addressed to another relying party is not evidence for this one, however valid.
Profile restriction, stated: `aud` must be a JSON **string**. RFC 7519 also allows
an array, and an array would force a "does any element match" rule — which is
exactly the shape that turns an audience check into an audience *suggestion*. The
SD-JWT KB-JWT carries a single relying-party identifier, so the restriction costs
nothing and removes the question.

`nonce` must equal the challenge DSSO issued for this request; otherwise
`DSSO_E_REPLAY`. The gate asserts both directions: a presentation for request A is
rejected under request B's policy, and the same bytes are accepted only under the
policy whose nonce they answer.

**Scope, stated.** `dsso_pid_verify` is stateless: it enforces nonce EQUALITY,
not that the nonce has never been seen. SINGLE-USE lives one layer up, in
`dsso_bind`'s challenge record, which is consumed on any attempt (§4 (iii)). A
caller that reuses a nonce across two requests reuses the window in which a
captured presentation is valid; DSSO's own callers do not.

### 3.7 Freshness (rule 7)

`iat` and `exp` are required. The credential is rejected if it was issued in the
future beyond the skew, if `exp ≤ iat`, if it is past `exp` beyond the skew, if an
`nbf` places it in the future beyond the skew, or if it is older than
`max_cred_age`. The **presentation** is rejected if the KB-JWT's `iat` is in the
future beyond the skew or older than `max_pres_age`.

The skew tolerance is real and the gate says so out loud rather than leaving it
invisible: `EXPIRED` (past `exp` by more than the skew) is rejected, and
`EXP_IN_SKEW` (past `exp` by less) is accepted. An operator who wants no
tolerance sets `max_skew` to zero.

### 3.8 Status (rule 8) — `check_status`, `dsso_inflate`

The credential carries `status.status_list` with a `uri` and an `idx` (IETF Token
Status List). The status token is fetched through an **injected callback** —
`dsso_status_fetch_fn` — because a gate cannot reach a network and because a
verifier with its own embedded transport cannot be driven adversarially. The
callback is the whole of DSSO's network dependency for this check.

The token is then held to the same standard as the credential: it must be a JWT
typed `statuslist+jwt` with `alg: ES256`, its `(iss, kid)` must resolve **in the
same trust anchor list**, and its signature must verify — a revocation feed that
anyone may sign is not a revocation feed. Its `sub` must equal the `uri` the
credential named, or an attacker answers a revocation question with a different
list's answer. And — this is an **adversarial-review finding closed in this
increment** — its `iss` must equal the **credential's own** issuer. Requiring
only "signed by some anchor on the list" would let any PID Provider on the list
answer for another provider's credentials: one compromised, low-assurance issuer
could un-revoke every other Member State's PID by hosting a token at the named
URI and signing it with its own key, and `sub`, the signature and the dates would
all check out. This is stricter than draft-ietf-oauth-status-list, which permits
a third-party status provider; a deployment that needs one adds it under the
credential issuer's own identifier rather than to the list at large.

`lst` is canonical base64url of a zlib stream, inflated by `dsso_inflate`: a
from-scratch, allocation-free RFC 1950/1951 implementation with a **hard output
ceiling**, so a compression bomb costs `O(cap)` and nothing more. Stored,
fixed-Huffman and dynamic-Huffman blocks are supported; a truncated stream, a bad
zlib header, a preset dictionary, an over-subscribed or incomplete code, a
distance reaching before the start of the output, trailing data after the final
block, and a wrong Adler-32 are each a rejection. Statuses are read
least-significant-bits-first at `bits ∈ {1,2,4,8}`.

**It fails closed, in five distinct ways, each with its own gate arm:** the fetch
fails; the token is past its own `exp`; the token is for another list; the index is
past the end of the bitstring; the bitstring inflates past the cap. All five are
`DSSO_E_UNAVAILABLE` and the verification **fails**. A status that *is* readable
and is not `0x00` is `DSSO_E_STATUS` — `0x01` INVALID, `0x02` SUSPENDED, and any
other value is an extension this verifier does not understand and therefore
refuses. There is no "allow on outage" path and adding one would be a defect.

### 3.9 Assurance (rule 9) — `assurance_of`

**How DSSO decides the level of a presentation.** The credential must ASSERT its
level, in the **issuer-signed payload** — never in a disclosure, because a level
the holder can withhold or select is not evidence. DSSO reads the OIDC `acr`
claim and requires one of the three eIDAS level URIs of Commission Implementing
Regulation (EU) 2015/1502 (`http://eidas.europa.eu/LoA/{low,substantial,high}`).
An absent, non-string or unrecognised `acr` is `DSSO_E_ASSURANCE`, never "unknown,
proceed".

The **effective** level is `min(anchor.max_loa, credential.acr)`. Each trust
anchor entry declares the highest level its issuer is entitled to assert, so an
issuer configured as substantial cannot mint a "high" credential and a token
cannot talk its own issuer up. The gate's `LOA_CAPPED` vector is exactly that: a
credential asserting `high` from an issuer capped at `substantial`, rejected.

**Stated limitation.** The ARF v2.9.0 PID Rulebook does not fix a claim name for
the assurance level of the credential *itself* in the SD-JWT VC profile. `acr`
with the eIDAS LoA URIs is **DSSO's profile choice**, recorded here and in the
comment above `assurance_of`. If a future rulebook fixes a different carrier,
`assurance_of` is the one function that changes.

---

## 4. Account binding — `dsso_bind.c`

Verifying a presentation says *this wallet holds a PID for some person*. Binding
says *that person owns DSSO account A*. Everything that goes wrong in identity
systems lives in the second sentence, so three shapes are made impossible in code
rather than described in a deployment note.

**(i) A session is not authorisation.** Possession of an existing DSSO session
must never, on its own, authorise binding an identity to that account — an
attacker with a stolen session cookie would otherwise staple the victim's account
to the attacker's identity. `dsso_bind_challenge_new` therefore requires
`dsso_account_auth` with `kind == DSSO_AUTH_FRESH`, a timestamp inside the
re-auth window, and an HMAC under the **account's own** authentication key. It is
a positive test on a proof the holder produced, not a negative test on an "is this
a session?" flag — a negative test degrades to *allowed* the moment a caller
forgets to set the flag. `DSSO_AUTH_SESSION_ONLY` exists as a value so that
refusing it is a test the code performs rather than an omission a reader has to
notice. The same proof is required to **unbind**.

**(ii) One subject, one account, and no silent swaps.** `dsso_bind_commit`
refuses when the derived pseudonym is already actively bound to a different
account, and when the account is already actively bound to a different pseudonym.
Both are `DSSO_E_BINDING`. The only way through is `dsso_bind_unbind`, which takes
its own fresh account authentication — so a re-bind is two separately authorised
operations, never one. Re-presenting the *same* subject for the *same* account is
idempotent, not a second binding.

**(iii) No reuse.** The challenge is recorded on the account (at most one
outstanding, so issuing a new one invalidates the old), it expires after
`challenge_ttl`, and it is **consumed the moment a presentation is offered against
it — pass or fail**: a single-use challenge with a retry oracle is not single-use.
Crucially, `dsso_bind_commit` takes the nonce **from the account's challenge
record** and supplies it to `dsso_pid_verify` itself. A caller cannot verify
against one challenge and commit against another; the linkage is structural
rather than a convention.

### 4.1 The pseudonym, and why it is derived this way

**Open finding (2026-09-25, SECURITY.md S-121):** the code hashes the raw JSON
token of the identifier (quotes and escapes included), not the unescaped `id`
this section specifies, so two legal spellings of one identifier derive two
pseudonyms. The derivation below is the specified one.

The persistent identifier is

```
pseudonym = HMAC-SHA256(K_pseu, "DSSO-PID-PSEUDONYM-v1" ‖ len(iss) ‖ iss ‖ len(id) ‖ id)
```

where `id` is the PID's `personal_administrative_number`. The raw identifier is
**never stored** and is scrubbed before `dsso_bind_commit` returns — ARF
**OIA_16**, *discard unique elements as soon as they are no longer needed*.

- **Never the raw national identifier, never a document number.** Neither is
  stored, and `dsso_pid_result_scrub` zeroes the whole verification result.
- **Keyed, not a plain hash.** National identifier spaces are small and
  structured — a Bulgarian ЕГН or an Estonian isikukood is on the order of 10¹⁰
  candidates with most of the entropy in a birth date — so a table of plain
  SHA-256 values is invertible in CPU-hours and a database leak would *be* a
  population-wide identity list. `K_pseu` lives outside the account database (an
  HSM or KMS key in a deployment), so a leak of the database alone yields
  uncorrelatable 32-byte strings. The gate asserts the key dependence directly.
- **Domain-separated by issuer, and length-separated.** Two Member States may
  allocate colliding identifiers; including `iss` prevents that, and the length
  prefixes stop `(iss, id)` pairs from being re-split to collide. The gate
  asserts the length separation.
- **Not per-account salted, deliberately.** Rule (ii) requires comparing subjects
  *across* accounts, which a per-account salt makes impossible. This is a
  recorded trade: the pseudonym is service-wide and therefore linkable **within**
  DSSO — which is the linkability rule (ii) is built from — and it is keyed so
  that it is linkable nowhere else. It never leaves the service. Identifiers DSSO
  hands to its own relying parties are a different value and stay pairwise
  ([`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) §5).

A presentation that discloses no `personal_administrative_number` still
*verifies*; it simply yields no subject material, so it binds nothing
(`dsso_pid_subject_material` → `DSSO_E_FORMAT`). The gate asserts both halves.

---

## 5. Code loci

| Property | Where |
|---|---|
| Canonical base64url | `dsso_b64url_decode` (`dapps/dsso/dsso_jose.c`) |
| Strict JSON, duplicate-key rejection, depth/element caps | `dsso_json_validate` / `jp_object` / `js_body_equal` (same file) |
| Wire signing input taken from the wire | `dsso_jwt_split` (same file) |
| ES256 over P-256 | `dsso_es256_verify` (same file) |
| Bounded inflate | `dsso_inflate` and the `inf_*` statics (same file) |
| Trust anchor store and OIA_12 lookup | `dsso_trust_lookup` (`dapps/dsso/dsso_pid.c`) |
| Algorithm pin, refusal of token-supplied key material | `header_ok` (same file) |
| The nine rules in order | `pid_verify_inner` (same file) |
| Status list, fail-closed | `check_status` (same file) |
| Assurance policy | `assurance_of` (same file) |
| OIA_16 scrub | `dsso_pid_result_scrub` (same file) |
| Fresh account authentication | `auth_ok` (`dapps/dsso/dsso_bind.c`) |
| Binding rules (i)/(ii)/(iii) | `dsso_bind_challenge_new`, `dsso_bind_commit`, `dsso_bind_unbind` (same file) |
| Pseudonym derivation | `dsso_pseudonym_derive` (same file) |
| Input bounds | `dapps/dsso/dsso.h` |

`determ-dsso` links `determ-crypto-c99` and nothing else (`CMakeLists.txt`), so no
consensus object is reachable from any of it. That is what lets DSSO parse the
JSON the EUDI specifications mandate while the canonical-binary rule (DECISION-LOG
D2) stays intact for consensus data.

---

## 6. The gate

`determ-dsso selftest-pid` — **156 assertions**, wrapper `tools/test_dsso_pid.sh`,
in the FAST tier, ~2.5 s, no network, no files, no flakes.

**Fixtures.** Generated by an **independent** implementation: a pure-Python P-256
ECDSA with RFC 6979 deterministic nonces, anchored to the published **RFC 6979
A.2.5** known-answer vectors and cross-checked against OpenSSL before any vector
is emitted. Three implementations must agree before a fixture ships — the
generator, OpenSSL, and the C verifier under test — so the accept case is not "a C
signer agreeing with a C verifier". The generated vectors are committed as
`dapps/dsso/dsso_pid_vectors.h` rather than under `tools/vectors/`, because
`determ-dsso` has no file IO and no fixture-path resolution, and because reading a
JSON corpus in order to test a JSON reader would make the gate depend on the thing
it tests. **The generator is committed as
[`tools/gen_dsso_pid_vectors.py`](../../tools/gen_dsso_pid_vectors.py)** (added
2026-09-17; the PID increment had left it outside the repository, so the vectors
were frozen data nobody could regenerate). Running
`python3 tools/gen_dsso_pid_vectors.py` from the repository root rewrites
`dapps/dsso/dsso_pid_vectors.h` in place; the run is deterministic — every secret
scalar, salt and nonce is a fixed constant and ECDSA `k` is RFC 6979 — so an
empty `git diff` afterwards is the check that the committed vectors are the ones
that generator produces. The generator re-runs its own RFC 6979 A.2.5 anchor and
its OpenSSL cross-check before it writes, and fails rather than skipping either.

**Independently of the generator**, the ES256 verifier is asserted directly
against the RFC 6979 A.2.5 vectors inside the gate, together with the rejections
that matter: a changed message, a flipped bit of `r` or of `s`, `r`/`s` zero or
≥ n, an off-curve key, a non-SEC1 key encoding.

**Arms.** An accept case for the pipeline; **45 rejection vectors** plus a boundary
accept (the skew tolerance of §3.7), at least two per rule, each asserted against the status code that rule returns; the malleability
statement (§3.3) asserted rather than assumed; the "failure leaves nothing behind"
scrub; the trust-anchor provenance pair (empty list → `DSSO_E_TRUST`, bent key →
`DSSO_E_CRYPTO`); the binding rules with their rejections; the pseudonym
properties.

**Fuzz arms — 8400 mutated inputs.** (Recorded as 6900 until 2026-09-17: that figure
omitted the zlib corpus. The four counts below are the loops in
`dapps/dsso/dsso_selftest_pid.c` and the gate prints each one.)

| Corpus | Count | Property asserted |
|---|---|---|
| Presentations | 2400 | bit flips, truncations, deletions, insertions and chunk splices. **Every mutant that differs from the original is REJECTED** — every byte of a presentation is covered by one of the two signatures or by `sd_hash`. Guard bytes either side of the input are untouched. |
| JSON documents | 3000 | every mutant either validates (and is then walked by every accessor without incident, with the root span inside the input) or is rejected with a bounded failure. |
| base64url strings | 1500 | every accepted decode has exactly the length its input length dictates — the canonical-encoding property, restated as a total function. |
| zlib streams | 1500 | every mutant either inflates to the byte-identical plaintext or is rejected; none exceeds the output cap. |

The PRNG is a fixed-seed xorshift, so the corpus is deterministic and a failure is
reproducible.

### 6.1 Mutants (all RED against a rebuilt binary)

Each removes exactly one check; the source is restored and rebuilt after each.

| # | What it removes | RED arm |
|---|---|---|
| M1 | the trust anchor lookup (accept any issuer) | `ISS_UNKNOWN`, `KID_UNKNOWN` |
| M2 | the issuer ES256 verification | `SIG_WRONG_KEY`, `SIG_OTHER_BYTES` |
| M3 | the disclosure→`_sd` digest match | `DISC_NO_DIGEST` |
| M4 | the KB-JWT presence requirement | `KB_MISSING` |
| M5 | the KB-JWT key-identity check | `KB_OTHER_KEY` |
| M6 | the audience check | `AUD_OTHER` |
| M7 | the nonce check | `NONCE_OTHER` |
| M8 | the expiry checks | `EXPIRED`, `CRED_ANCIENT` |
| M9 | the status check | `REVOKED`, `SUSPENDED` |
| M10 | fail-closed on an unavailable status list | `STATUS_UNAVAIL`, `STATUS_STALE` |
| M11 | the binding layer's fresh-re-authentication check | the four `bind (i)` arms |
| M12 | the duplicate-disclosure check | `DISC_DUP` |
| M13 | the base64url canonical-tail check | the `b64url` non-canonical arm |
| M14 | the JSON duplicate-key check | the two `json` duplicate arms |
| M15 | the `alg` pin | `ALG_NONE`, `ALG_HS256` |
| M16 | the "one subject, one account" check | `bind (ii)` |
| M17 | the requirement that a status token come from the credential's own issuer | `STATUS_CROSSISS` |

---

## 7. Where this sits relative to the existing DSSO login

[`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) describes DSSO's **second**
role: a private, non-notified identity provider that authenticates its own users
(threshold-OPRF + OPAQUE-3DH) and asserts to its own relying parties (the §5
dual-hash token). That role is about *returning* users.

This increment is the **first** role and it happens once, at **enrolment**: a
wallet presents PID, DSSO verifies it, and the subject is bound to an account. The
two meet at exactly one place — the account — and nowhere else: no PID attribute,
no raw identifier and no presentation byte enters the login path, the assertion
path, or the chain. What the login path can learn is that an account carries a
binding at some assurance level.

**DSSO never claims the wallet's level for its own later logins.** Identity
proofing at enrolment is inherited from the PID (CIR (EU) 2015/1502 Annex §2.1.2);
DSSO records what it verified. Its own authentication is a separate question,
targeted at *equivalence to* level substantial via §2.2.1 (two factors from
different categories) and §2.3.1 (dynamic authentication), and that target is the
login path's business, not this module's.

---

## 8. What is NOT claimed

1. **No compliance claim of any kind.** Passing this gate does not make DSSO
   conformant with the ARF, notified under Art. 9, certified under CIR (EU)
   2024/2981, or qualified for anything. It shows the code enforces what §1
   states.
2. **The wallet-relying-party ACCESS CERTIFICATE (ARF RPA_01..RPA_06) is NOT
   obtained and is NOT implemented here.** Registration with a Member State
   registrar is an external act that cannot happen in a repository, and without
   it there is no certificate to present. **Nothing in this module authenticates
   DSSO to a wallet.** A real deployment needs that certificate, carried by value
   and validated by the wallet against Member State Trusted Lists, before any
   wallet would answer a request at all. This is the increment's single largest
   external blocker and it is not closed.
3. **OpenID4VP (OIA_03/OIA_03b/OIA_04) is NOT implemented.** This module verifies
   a presentation that some transport already delivered. The Authorization
   Request, the `presentation_definition`/DCQL query, response modes and
   encryption are all absent.
4. **ISO/IEC 18013-5 mdoc is NOT implemented** (§2). An mdoc-only wallet is out
   of scope.
5. **No eIDAS Trusted List is fetched, parsed or validated.** `dsso_trust_list`
   is a configured array; populating it from an ETSI TS 119 612 Trusted List is a
   deployment act with its own (unwritten) code.
6. **The gate does not prove memory safety, it evidences it.** The fuzz arms show
   a definite verdict, untouched guard bytes and no crash over 8400 inputs; they
   cannot observe an out-of-bounds *read*. That property is argued structurally —
   every loop is bounded by its slice length, recursion by `DSSO_JSON_MAX_DEPTH`,
   and nothing allocates. **Since 2026-09-17 a sanitizer build also runs it:**
   `tools/ci_local.sh --asan` builds `determ-dsso` with `-fsanitize=address` on
   `dapps/dsso`'s own translation units (the readers allocate nothing, so only
   compile-side instrumentation makes their stack buffers observable) and runs all
   four selftests, fuzz corpus included. That is evidence, not proof: ASan reports
   what the corpus actually executes. The first run found **no defect**; a
   deliberate one-byte over-read introduced into `dsso_b64url_decode` was reported
   as `stack-buffer-overflow` while the same mutant passed the uninstrumented gate
   green — which is what makes the leg worth having.
7. **The status-list fetch is a callback, not a transport.** Nothing here does
   TLS, caching, retry, or Trusted-List discovery, and the security of the fetch
   path itself is the deployment's problem. What is proved is that every way the
   fetch can fail lands on `DSSO_E_UNAVAILABLE` and fails closed.
8. **No claim about the wallet.** Whether the wallet's secure area really holds
   the `cnf` key, whether the holder is the person the PID names, and whether the
   PID Provider proofed that person correctly, are all inherited from the wallet
   and the issuer. DSSO checks signatures, not people.
9. **Timing.** The verifier compares digests and nonces with `dsso_ct_equal`, but
   it is a *public-data* verifier and no constant-time claim is made for it as a
   whole. The DSSO constant-time record is
   [`DssoG5ConstantTimeReview.md`](DssoG5ConstantTimeReview.md) and covers the
   secret-scalar paths, which this module does not touch.
10. **Requirements discharged, precisely.** **OIA_12** (trust-anchored issuer
    validation) and **OIA_02** (holder binding) are implemented and gated.
    **OIA_16** is *partially* discharged: the raw subject material is scrubbed
    after use and never stored or forwarded, but there is no storage layer here
    whose retention could be audited. **OIA_03 / OIA_03b / OIA_04** are **not**
    discharged (no OpenID4VP, no mdoc). **RPA_01..RPA_06** are **not** discharged
    (see 2). The IETF Token Status List check is implemented and gated.

---

## 9. Cross-references

- [`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) §11 — the wallet-relying-party
  role and where it sits relative to the login.
- [`DssoThresholdOprfSoundness.md`](DssoThresholdOprfSoundness.md) — the login and
  assertion halves of DSSO.
- [`DssoG5ConstantTimeReview.md`](DssoG5ConstantTimeReview.md) — the constant-time
  record for the secret-scalar paths.
- [`P256CryptoStackAudit.md`](P256CryptoStackAudit.md),
  [`CRYPTO-C99-SPEC.md`](CRYPTO-C99-SPEC.md) §3.8c — the P-256 primitives this
  module composes.
- `docs/SECURITY.md` — the gate's row in the in-process test table.
