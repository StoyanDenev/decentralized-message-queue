#!/usr/bin/env bash
# test_proofs_no_deleted_crypto_backend.sh — coherence guard: a NO-TIER
# proof-of-record must not cite a DELETED crypto backend as ITS implementation.
#
# WHY THIS EXISTS
# --------------
# The 2026-07-03 "1c" swap replaced the OpenSSL + libsodium crypto backend with
# the in-tree `determ::c99` stack (see `wallet/envelope.cpp:4-5` header note). A
# NO-TIER proof under docs/proofs/ is (per CLAUDE.md) an authoritative
# convergence point that MUST track shipped code. A proof that still names the
# deleted backend's API symbols as ITS OWN implementation has silently become a
# proof-of-record for code that no longer ships — the exact drift that stranded
# `EnvelopeKeyfileCrypto.md` (found by wf_6c5a9e49; that doc is now migrated to
# the c99 API). This guard makes that drift RED so a future backend swap cannot
# silently re-strand a proof.
#
# WHAT IT CHECKS
# --------------
# For every NO-TIER docs/proofs/*.md (a file with no `TIER:` banner — the same
# tiering signal `test_doc_tier_check.sh` reads) grep for the deleted-backend
# SYMBOL names:
#     EVP_   PKCS5_   RAND_bytes   CRYPTO_memcmp   sodium_
# These are SYMBOLS, not the words "OpenSSL"/"libsodium": a proof may
# legitimately narrate the migration, or name the cross-validation oracle, in
# prose without naming an API symbol.
#
# A symbol hit is RED unless the file is on one of two DOCUMENTED allowlists:
#   ORACLE_OK   — proofs that reference the symbols as the OpenSSL/libsodium
#                 cross-validation ORACLE, or as the c99 migration/removal
#                 SUBJECT. Legitimate and permanent.
#   PENDING_C99 — proofs stranded by the 1c/c99 swap that STILL cite the old
#                 backend as their implementation. TRACKED DEBT, *not* a
#                 legitimacy claim: each is to be migrated to the c99 API (as
#                 `EnvelopeKeyfileCrypto.md` now is) and then dropped from here.
#                 Listed so the guard is green today while the debt stays VISIBLE
#                 (the run prints how many remain).
#
# `EnvelopeKeyfileCrypto.md` is on NEITHER list — it is ENFORCED clean: if it
# (or any new/unlisted no-tier crypto proof) ever names a deleted-backend
# symbol, this guard goes RED. An allowlisted file that no longer cites any
# symbol is also RED (list hygiene — prune the stale entry) so the backlog can
# only shrink.
#
# Pure read-only (grep/find over docs/). No binary; never SKIPs; offline;
# deterministic. run_all.sh auto-discovers it (tools/test_*.sh); ci_local.sh
# lists it in the offline doc-guard loop. SELFTEST=1 proves the detector is
# live. Exit 0 = coherent; exit 1 = an unlisted no-tier proof cites a deleted
# backend (or a stale allowlist entry).
set -u
cd "$(dirname "$0")/.."

PROOFS_DIR="docs/proofs"
SYMS='EVP_|PKCS5_|RAND_bytes|CRYPTO_memcmp|sodium_'

# ── Allowlists (see header). One basename per line; keep sorted; annotate. ──
# Proofs that LEGITIMATELY name the symbols (oracle / migration / removal).
ORACLE_OK="
C99CryptoStackAudit.md             # c99-stack audit; OpenSSL EVP_* is the byte-equality oracle
CRYPTO-C99-SPEC.md                 # the c99 crypto spec; names OpenSSL EVP_* oracles per primitive
CryptoBackendMigrationSoundness.md # the OpenSSL->c99 migration proof itself; names both sides
S009DelayHashRemoval.md            # removal audit; EVP_MD_CTX are the grep-for-removal targets
"
# Proofs STRANDED by the 1c/c99 swap, still citing the deleted backend as their
# implementation. TRACKED DEBT to migrate file-by-file (NOT a legitimacy claim);
# drop each entry once its proof is moved to the determ::c99 API.
PENDING_C99="
BatchSigningSoundness.md
CanonicalSigningBytesParity.md
CommitteeSelectionAbortDeterminismSoundness.md
ConsensusPhaseStructureSoundness.md
F2RPCAuthEnvComposition.md
KeyfileArgon2Migration.md
MakeContribCommitmentBackwardCompat.md
OfflineEquivocationEvidenceSoundness.md
ParamChangeVerifySoundness.md
RpcAuthHmacSoundness.md
S001RpcAuthSoundness.md
S004KeyfileAtRest.md
S005PassphraseKeyfile.md
S023NodeKeyfileEncryption.md
S027InfoLeakage.md
SelectiveAbort.md
WalletRecovery.md
WalletRecoveryFlows.md
WireFormatBackwardCompat.md
"

# bare-basename set membership (strip inline "# reason" comments + whitespace).
# grep -F (fixed) + -x (whole line) so the '.' in a basename is literal.
_norm() { printf '%s\n' "$1" | sed 's/#.*//' | tr -d ' \t' | grep -v '^$'; }
in_oracle()    { _norm "$ORACLE_OK"  | grep -Fxq -- "$1"; }
in_pending()   { _norm "$PENDING_C99" | grep -Fxq -- "$1"; }
in_allowlist() { { _norm "$ORACLE_OK"; _norm "$PENDING_C99"; } | grep -Fxq -- "$1"; }

is_no_tier() { ! grep -q -- "TIER:" "$1"; }
has_syms()   { grep -qE -- "$SYMS" "$1"; }

VIOLATIONS=0
ok()   { echo "  ok:   $1"; }
bad()  { echo "  bad:  $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }
note() { echo "  note: $1"; }

# ── SELFTEST: prove the detector fires (falsify-on-mutant) ──────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: an injected deleted-backend symbol must be detected ==="
  st_fail=0
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  printf 'A clean c99 proof: determ_aes256_gcm_decrypt + determ_ct_memcmp + determ_rng_bytes.\n' > "$tmp"
  if has_syms "$tmp"; then echo "  bad: SELFTEST clean c99 file falsely flagged" >&2; st_fail=$((st_fail+1))
  else ok "SELFTEST: a clean determ::c99 proof carries no deleted-backend symbol"; fi
  printf 'Stale: key via OpenSSL PKCS5_PBKDF2_HMAC + EVP_sha256; tag via CRYPTO_memcmp; wipe via sodium_memzero.\n' > "$tmp"
  if has_syms "$tmp"; then ok "SELFTEST: an injected PKCS5_/EVP_/CRYPTO_memcmp/sodium_ line IS detected"
  else echo "  bad: SELFTEST injected deleted-backend symbol NOT detected (detector dead)" >&2; st_fail=$((st_fail+1)); fi
  # The enforced target must currently be clean.
  if has_syms "$PROOFS_DIR/EnvelopeKeyfileCrypto.md"; then
    echo "  bad: SELFTEST EnvelopeKeyfileCrypto.md still carries a deleted-backend symbol" >&2; st_fail=$((st_fail+1))
  else ok "SELFTEST: EnvelopeKeyfileCrypto.md (enforced) is clean"; fi
  echo ""
  if [ "$st_fail" = "0" ]; then echo "  PASS: test_proofs_no_deleted_crypto_backend SELFTEST"; exit 0
  else echo "  FAIL: test_proofs_no_deleted_crypto_backend SELFTEST ($st_fail)"; exit 1; fi
fi

echo "=== no-tier docs/proofs/*.md must not cite a deleted crypto backend (EVP_/PKCS5_/RAND_bytes/CRYPTO_memcmp/sodium_) ==="

pending_remaining=0
enforced_clean=0
for f in "$PROOFS_DIR"/*.md; do
  [ -f "$f" ] || continue
  b="$(basename "$f")"
  # TIER-banner docs are out of scope (roadmap / historical convergence points).
  is_no_tier "$f" || continue
  if has_syms "$f"; then
    if in_oracle "$b"; then
      ok "$b — deleted-backend symbol present but ALLOWED (oracle / migration / removal)"
    elif in_pending "$b"; then
      note "$b — PENDING c99 migration (tracked debt; still cites the old backend)"
      pending_remaining=$((pending_remaining + 1))
    else
      bad "$b — NO-TIER proof-of-record cites a DELETED crypto backend; migrate to determ::c99 [$(grep -oE -- "$SYMS" "$f" | sort -u | tr '\n' ' ')]"
    fi
  else
    # No forbidden symbol. If it is allowlisted, that entry is now stale -> prune.
    if in_allowlist "$b"; then
      bad "$b — on an allowlist but no longer cites any deleted-backend symbol; remove it from the allowlist (list hygiene)"
    fi
    [ "$b" = "EnvelopeKeyfileCrypto.md" ] && { ok "EnvelopeKeyfileCrypto.md — ENFORCED clean (determ::c99)"; enforced_clean=1; }
  fi
done

echo ""
note "$pending_remaining no-tier proof(s) remain on the PENDING_C99 c99-migration backlog (tracked debt to drain)."
[ "$enforced_clean" = "1" ] || note "EnvelopeKeyfileCrypto.md not found / unexpectedly tiered — check the enforced target."

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_proofs_no_deleted_crypto_backend (no unlisted no-tier proof cites a deleted crypto backend)"
  exit 0
else
  echo "  FAIL: test_proofs_no_deleted_crypto_backend ($VIOLATIONS violation(s))"
  exit 1
fi
