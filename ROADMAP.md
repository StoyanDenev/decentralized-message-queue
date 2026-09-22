# Path to Mainnet: The C99 PoSW Sovereign Architecture

## Phase 1: Local Testnet & Stabilization (Current)
* [x] C99 Cryptography Migration (`determ::c99`).
* [x] Dependency Purge (No ASIO/JSON/OpenSSL).
* [x] K=2 PoSW Consensus State Machine & Heaviest-Chain Fork Choice.
* [ ] Finalize Native Event Loop Reactor (`epoll`/`kqueue`/`IOCP`).
* [ ] Implement Triple-Entry Ledger State and OPAQUE DSSO in memory-safe C99.
* [ ] Pass DSF (Deterministic Simulation Framework) End-to-End Tests.

## Phase 2: Public Testnet
* [ ] Build the RPC Gateway (C99 Binary Ingestion for DApps).
* [ ] P2P Mesh Stabilization & Gossip Sub-protocol.
* [ ] Cross-Platform Validation (Darwin ARM64 / Linux x86_64 / Windows MSVC).
* [ ] Distributed Peer Fuzzing & Network Delay Injection.

## Phase 3: Mainnet Genesis
* [ ] Parameter Freezing (VDF Target Times, DDA Dampening $\tau$, Window Size).
* [ ] Formal Verification of Core State Transitions (Verified C / CompCert Target).
* [ ] Genesis Ceremonial Epoch & Network Launch.
