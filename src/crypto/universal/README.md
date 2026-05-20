# `src/crypto/universal/` — both stacks under namespaced symbols

Linked when CMake is invoked with `-DDETERM_CRYPTO=universal`. CI / DSF
/ cross-validation only — **not** for production FIPS deployment,
because the presence of MODERN primitives in the binary breaks the FIPS
module boundary required by NH4 military certification.

Layout: thin dispatch shim plus links against both `modern/` and
`fips/`. Symbols from each subtree are namespaced to avoid collision;
the dispatch shim picks the runtime variant by reading the loaded
genesis `CryptoProfile`.

Placeholder — dispatch shim lands in Phase 0 Track 2.
