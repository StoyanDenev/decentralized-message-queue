# ADR 004: Fault Model Correction (Proof of Sequential Work)
**Date:** 2026-09-22
**Status:** ACCEPTED

## 1. Architectural Correction: Equivocation and Finality
An independent audit conclusively proved that the K=2 VDF Duel cannot achieve instant, fork-free finality. An Aggregator can sign two valid candidate blocks and fork the network. To resolve this, we formally define the consensus mechanism as **Proof of Sequential Work (PoSW)**. We adopt a Nakamoto Heaviest-Chain fork choice rule: network forks are resolved by adopting the chain branch with the highest cumulative sequential work (`vdf_iterations`). 

## 2. Pre-computation and Zero-Bias
Colluding participants own all seed inputs before the commit window opens, allowing them to pre-compute the VDF offline. Under PoSW, this is mitigated purely by the economic opportunity cost of losing the chain race. If colluders pause to grind a more favorable VDF seed, competing honest K=2 pairs will continue advancing the heaviest chain, rendering the pre-computed branch orphaned and economically void.

## 3. Supersession
This ADR supersedes all previous claims of "fork-free finality" and "instant zero-bit bias" in the README, Whitepaper, and legacy proofs.
