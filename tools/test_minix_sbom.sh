#!/usr/bin/env bash
# test_minix_sbom.sh — verifies the Minix SBOM (docs/proofs/MinixSBOM.md) is
# FACTUALLY TRUE against the live tree, so the auditable dependency manifest is
# a proven artifact, not stale prose. Complements test_minix_dependency_surface.sh
# (which pins the same set from the build-invariant side); this guard pins the
# SBOM DOCUMENT's recorded facts to reality:
#
#   1. The vendored nlohmann/json SHA-256 recorded in the SBOM equals the actual
#      third_party/nlohmann/json.hpp hash (a silent bump/edit turns this RED).
#   2. The vendored header carries the SBOM's claimed provenance: the MIT
#      SPDX marker + the v3.11.3 version string.
#   3. The OpenSSL GIT_TAG recorded in the SBOM equals CMakeLists.txt's.
#   4. COMPLETENESS (source set): every FetchContent_Declare in CMakeLists.txt is
#      documented in the SBOM — a new undocumented third-party SOURCE dependency
#      turns this RED. (Scoped to FetchContent source deps, not the full link
#      graph — see MinixSBOM.md §4 for the scope bound.)
#   5. OpenSSL OUT-of-TCB (§3): the DETERM_BUILD_CRYPTOTEST gate exists, the
#      OpenSSL FetchContent sits INSIDE that gate (a tactical OFF build never
#      fetches it), AND exactly one bare `crypto` link token exists tree-wide —
#      cryptotest's — so no shipped binary links OpenSSL. Option-existence alone
#      is necessary-not-sufficient, so all three are checked.
#   6. Apache-2.0 provenance: the repo LICENSE/NOTICE are Apache-2.0 (the
#      load-bearing legal fact) AND every src/crypto C++ wrapper .cpp carries the
#      per-file SPDX marker the SBOM claims for THAT set (non-vacuous: a new
#      unmarked .cpp turns this RED — not a first-match grep).
#   7. determ-cryptotest links NO nlohmann (SBOM §2 corrected graph).
#
# Pure read-only TEXT check (grep/sha256sum over docs/ + CMakeLists + source).
# No determ binary → never SKIPs; offline; deterministic. run_all.sh
# auto-discovers it. Exit 0 = the SBOM matches the tree.
set -u
cd "$(dirname "$0")/.."

SBOM="docs/proofs/MinixSBOM.md"
CMK="CMakeLists.txt"
JSON_HDR="third_party/nlohmann/json.hpp"

VIOLATIONS=0
ok()   { echo "  ok:  $1"; }
bad()  { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

echo "=== minix SBOM factual-accuracy guard (SBOM vs the live tree) ==="

if [ ! -f "$SBOM" ]; then bad "$SBOM not found"; echo ""; echo "  FAIL: test_minix_sbom"; exit 1; fi

# Load the SBOM once and test membership with bash substring matching, NOT grep:
# MSYS2 / Git Bash `grep -F` can abort (SIGABRT) on this UTF-8 doc, and this
# guard must run on Windows Git Bash AND Linux.
SBOM_CONTENT="$(cat "$SBOM")"

sha_of() {
    python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1" 2>/dev/null \
        || sha256sum "$1" | cut -d' ' -f1
}

# ── 1. vendored nlohmann SHA-256: SBOM pin == actual file hash ───────────────
if [ -f "$JSON_HDR" ]; then
    ACTUAL="$(sha_of "$JSON_HDR")"
    if [[ "$SBOM_CONTENT" == *"$ACTUAL"* ]]; then
        ok "SBOM records the current nlohmann/json.hpp SHA-256 ($ACTUAL)"
    else
        bad "SBOM's nlohmann SHA-256 does NOT match the actual header ($ACTUAL) — the vendored header was bumped/edited without updating the SBOM"
    fi
else
    bad "$JSON_HDR (vendored nlohmann) not found"
fi

# ── 2. vendored header provenance: MIT SPDX + v3.11.3 ────────────────────────
if grep -q "SPDX-License-Identifier: MIT" "$JSON_HDR" 2>/dev/null; then
    ok "vendored nlohmann header carries the SBOM's claimed MIT SPDX marker"
else
    bad "vendored nlohmann header missing the MIT SPDX marker the SBOM claims"
fi
if grep -q "version 3.11.3" "$JSON_HDR" 2>/dev/null; then
    ok "vendored nlohmann header is the SBOM's claimed v3.11.3"
else
    bad "vendored nlohmann header version != the SBOM's claimed 3.11.3"
fi

# ── 3. OpenSSL GIT_TAG: SBOM == CMakeLists ───────────────────────────────────
CMK_TAG="$(grep -E 'GIT_TAG' "$CMK" | grep -oE '1\.1\.1w-[0-9]+' | head -1)"
if [ -n "$CMK_TAG" ] && [[ "$SBOM_CONTENT" == *"$CMK_TAG"* ]]; then
    ok "SBOM records the OpenSSL GIT_TAG CMakeLists actually pins ($CMK_TAG)"
else
    bad "OpenSSL GIT_TAG drift: CMakeLists='$CMK_TAG' not found verbatim in the SBOM"
fi

# ── 4. COMPLETENESS: every FetchContent_Declare is documented in the SBOM ─────
DECLARED="$(grep -A1 'FetchContent_Declare(' "$CMK" \
            | grep -vE 'FetchContent_Declare|^--' | awk '{print $1}' | sort -u)"
if [ -z "$DECLARED" ]; then
    ok "no FetchContent_Declare in CMakeLists (nothing to document)"
else
    MISSING=""
    for dep in $DECLARED; do
        [[ "$SBOM_CONTENT" == *"$dep"* ]] || MISSING="$MISSING $dep"
    done
    if [ -z "$MISSING" ]; then
        ok "every FetchContent_Declare {$(echo $DECLARED | tr '\n' ' ')} is documented in the SBOM"
    else
        bad "undocumented third-party source dependency(ies) in CMakeLists NOT in the SBOM:$MISSING — a new external dep must be added to the SBOM (+ an owner decision)"
    fi
fi

# ── 5. OpenSSL OUT-of-TCB: gate exists + OpenSSL fetch INSIDE the gate + no ───
#      shipped binary links the OpenSSL `crypto` lib. Option-existence alone is
#      necessary-not-sufficient (a de-gating refactor keeps the option but moves
#      the fetch out), so all three legs are verified.
if grep -q "option(DETERM_BUILD_CRYPTOTEST" "$CMK"; then
    ok "DETERM_BUILD_CRYPTOTEST gate exists"
else
    bad "DETERM_BUILD_CRYPTOTEST option gone — the SBOM's 'OpenSSL build-gated OFF for tactical' claim is stale"
fi
# 5b: the OpenSSL FetchContent block must be textually inside the gate. index()
#     (fixed-string) avoids treating the parens in `if(DETERM_BUILD_CRYPTOTEST)`
#     as awk regex metacharacters.
if awk '
    index($0,"if(DETERM_BUILD_CRYPTOTEST)"){g=1}
    g && index($0,"FetchContent_MakeAvailable(openssl)"){f=1}
    g && index($0,"endif()"){g=0}
    END{exit !f}' "$CMK"; then
    ok "the OpenSSL FetchContent sits inside the DETERM_BUILD_CRYPTOTEST gate (a tactical OFF build never fetches OpenSSL)"
else
    bad "OpenSSL FetchContent is NOT inside the DETERM_BUILD_CRYPTOTEST gate — a tactical (OFF) build would fetch OpenSSL, falsifying the SBOM"
fi
# 5c: exactly one bare `crypto` (OpenSSL) link token tree-wide — cryptotest's.
#     `determ-crypto-c99` cannot match (the $ anchor excludes the -c99 suffix).
CRYPTO_LINKS="$(grep -cE '^[[:space:]]*crypto[[:space:]]*$' "$CMK")"
if [ "$CRYPTO_LINKS" = "1" ]; then
    ok "exactly one bare 'crypto' (OpenSSL) link token — the cryptotest oracle; no shipped binary links OpenSSL"
else
    bad "expected exactly 1 bare 'crypto' OpenSSL link token (cryptotest only); found $CRYPTO_LINKS — a shipped binary may now link OpenSSL"
fi

# ── 6. Apache-2.0 provenance: the repo LICENSE/NOTICE + the per-file SPDX ─────
#      marker on the C++ wrapper set the SBOM claims (NOT a first-match grep —
#      the from-scratch C99 .c core is covered by the repo LICENSE, and the SBOM
#      no longer claims 'every source file').
if [ -f LICENSE ] && grep -q "Apache License" LICENSE && grep -q "Version 2.0" LICENSE; then
    ok "repo LICENSE is Apache-2.0 (the SBOM's determ-crypto-c99 license fact)"
else
    bad "repo LICENSE missing or not Apache-2.0 — the SBOM's Apache-2.0 license claim is unverified"
fi
if [ -f NOTICE ]; then
    ok "repo NOTICE (Apache-2.0 attribution) present"
else
    bad "repo NOTICE missing — the SBOM's Apache-2.0 attribution claim is unverified"
fi
# 6b: EVERY src/crypto C++ wrapper .cpp must carry the marker (non-vacuous — a
#     new unmarked wrapper turns this RED, unlike `grep -rql` which exits on the
#     first hit and greenlit the false 'every source file' claim).
UNMARKED_CPP=""
while IFS= read -r f; do
    grep -q "SPDX-License-Identifier: Apache-2.0" "$f" || UNMARKED_CPP="$UNMARKED_CPP $f"
done < <(find src/crypto -name '*.cpp' 2>/dev/null)
if [ -z "$UNMARKED_CPP" ]; then
    ok "every src/crypto C++ wrapper .cpp carries the Apache-2.0 SPDX marker"
else
    bad "src/crypto C++ wrapper .cpp missing the SPDX marker the SBOM claims:$UNMARKED_CPP"
fi

# ── 7. determ-cryptotest links NO nlohmann (SBOM §2 corrected graph) ──────────
CT_BLOCK="$(awk '/target_link_libraries\(determ-cryptotest/{p=1} p{print} p&&/\)/{p=0}' "$CMK")"
if printf '%s' "$CT_BLOCK" | grep -q "nlohmann"; then
    bad "determ-cryptotest now links nlohmann — SBOM §2 says it does not; update §1/§2 or the link"
else
    ok "determ-cryptotest links no nlohmann (matches SBOM §2)"
fi

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
    echo "  PASS: test_minix_sbom (the SBOM is factually accurate against the tree)"
    exit 0
else
    echo "  FAIL: test_minix_sbom ($VIOLATIONS drift)"
    exit 1
fi
