#!/usr/bin/env bash
# KM-4 (docs/proofs/KeyfileArgon2Migration.md) — determ-wallet envelope
# deserialize/decrypt must reject every MALFORMED or DEGENERATE DWE2 (Argon2id)
# blob and every degenerate decrypt-path Envelope with std::nullopt — never an
# out-of-bounds read, an uncaught throw, or a false ACCEPT.
#
# THE GAP (found by the proof-claim traceability audit wf_6c5a9e49, MED — an OOB
# read is in scope): KM-4 claims deserialize/decrypt reject every malformed /
# degenerate envelope with std::nullopt. The reject edges exist in
# wallet/envelope.cpp, but the DWE2 params-slot guards and the decrypt() argon2 /
# iters degeneracy guards were UNGATED. The existing envelope tests
#   tools/test_wallet_envelope_decrypt_malformed_edge.sh  (DWE1 STRUCTURAL edges)
#   tools/test_wallet_envelope.sh / _roundtrip_fuzz.sh    (wrong-pw / ct-tamper)
#   tools/test_wallet_keyfile_argon2.sh                   (DWE2 create + wrong-pw)
# build ONLY DWE1 fixtures or feed a wrong-passphrase / tampered-tag blob (which
# the AEAD rejects). NONE feeds a DWE2 blob to deserialize() nor calls decrypt()
# on a hand-built degenerate Envelope, so these guards were unpinned:
#   envelope.cpp:251      DWE2 params.size()!=12  (SHARPEST: delete -> a 4-byte
#                         params slot reaches rd_u32_le(params,4/8) -> heap OOB)
#   envelope.cpp:256-257  DWE2 argon2_t==0 / argon2_p==0 / argon2_m_kib<8*p
#   envelope.cpp:145-146  decrypt() Argon2id degeneracy (p==0/t==0 -> throw)
#   envelope.cpp:262      DWE1 pbkdf2_iters==0
#   envelope.cpp:150      decrypt() DWE1 pbkdf2_iters==0
#
# THE FIX (this wrapper): drive the pure in-process falsify gate
# `selftest-envelope-param-reject`, which hand-builds each malformed DWE2 blob
# and each degenerate Envelope and asserts deserialize/decrypt return nullopt
# without crashing. Falsify-on-mutant: deleting any one guard at
# envelope.cpp:251 / 256-257 / 262 / 145-146 flips at least one assertion RED
# (and under a sanitizer build the deleted :251 additionally trips the OOB).
# Positive controls prove the negatives are not vacuous.
#
# FAST + OFFLINE (no cluster / no daemon; tiny KDF params).
# Run from repo root: bash tools/test_wallet_envelope_param_reject.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  echo "  SKIP: determ-wallet binary not found; build with"
  echo "        cmake --build build --config Release --target determ-wallet"
  exit 0
fi

set +e
OUT=$("$DETERM_WALLET" selftest-envelope-param-reject 2>&1)
RC=$?
set -e
# The selftest prints ONLY its own 2-space-indented `  ok:` / `  FAIL:` markers,
# the `  N pass / M fail` tally, and its `selftest-envelope-param-reject` verdict
# — it does not drive another verifier, so nothing here can leak a foreign
# unindented `FAIL:` into run_all.sh's last-lines scan.
echo "$OUT" | grep -E "^  ok:|^  FAIL:|^  [0-9]+ pass / |selftest-envelope-param-reject" || true

if [ "$RC" = "0" ] && echo "$OUT" | grep -q "PASS: selftest-envelope-param-reject"; then
  echo "  PASS: test_wallet_envelope_param_reject"
  exit 0
else
  echo "  FAIL: test_wallet_envelope_param_reject (rc=$RC)"
  exit 1
fi
