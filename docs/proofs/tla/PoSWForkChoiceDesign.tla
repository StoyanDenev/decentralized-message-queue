--------------------------- MODULE PoSWForkChoiceDesign ---------------------------
(*
TIER: FUTURE — DESIGN MODEL, NOT A PROOF OF SHIPPED CODE. Roadmap: docs/ROADMAP.md.
Proposed direction: docs/decisions/ADR-004-Fault-Model.md.

Heaviest-chain fork choice over self-declared cumulative work, as sketched
for ADR-004 (K=2 Proof of Sequential Work). Written 2026-09-22 as a rewrite
of FB1 (Consensus.tla); demoted and renamed 2026-09-23 by owner decision —
FB1 is again the K-of-K model the C++ implementation runs.

What this model does NOT establish (each is an open obligation of ADR-004):
  * No block validation: accumulated_vdf_iterations is trusted as declared;
    nothing checks it against parent weight + verified work.
  * No adversary: every node is honest and every block is eventually
    delivered to every node (the convergence property assumes exactly that).
  * No verifiable delay function: the shipped C99 evaluator (src/crypto/vdf.c)
    is verified only by re-evaluation and has no sequential-hardness bound.
  * No producer eligibility, election, replacement rule or grinding bound.
  * No reorganization depth / settlement (confirmation) rule.
No code implements this fork choice; it is not part of the TLC gate (there is
no .cfg). To explore it by hand, use e.g. CONSTANTS Nodes = {"node_1",
"node_2"}, BlockIds = {1, 2, 3}, MaxHeight = 2, WeightOptions = {1, 2};
SPECIFICATION Spec; INVARIANTS TypeOK Inv_HeaviestChain Inv_EventualConsensus.
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,              \* Set of honest observer nodes, e.g. {"node_1", "node_2"}
    BlockIds,           \* Finite set of available block IDs, e.g. {1, 2, 3}
    MaxHeight,          \* Maximum block height to explore, e.g. 2
    WeightOptions       \* Set of possible VDF iterations per block, e.g. {1, 2}

GenesisId == 0

GenesisBlock == [
    id |-> GenesisId,
    height |-> 0,
    parent |-> GenesisId,
    accumulated_vdf_iterations |-> 0
]

ASSUME ConstantsOK ==
    /\ Nodes /= {}
    /\ BlockIds /= {}
    /\ GenesisId \notin BlockIds
    /\ MaxHeight \in Nat /\ MaxHeight >= 1
    /\ WeightOptions \subseteq (Nat \ {0})

VARIABLES
    blocks,             \* Set of all mined blocks in the universe
    network_pool,       \* Set of broadcasted blocks in flight in the network
    delivered,          \* [n \in Nodes |-> set of blocks delivered to node n]
    local_tip           \* [n \in Nodes |-> current canonical tip block of node n]

vars == <<blocks, network_pool, delivered, local_tip>>

----------------------------------------------------------------------------
\* Helper Predicates

UsedBlockIds == {b.id : b \in blocks}

IsHeavier(cand, current) ==
    \/ cand.accumulated_vdf_iterations > current.accumulated_vdf_iterations
    \/ (cand.accumulated_vdf_iterations = current.accumulated_vdf_iterations /\ cand.id < current.id)

AllDelivered ==
    \A n \in Nodes: network_pool \subseteq delivered[n]

----------------------------------------------------------------------------
\* Initial State

Init ==
    /\ blocks = {GenesisBlock}
    /\ network_pool = {GenesisBlock}
    /\ delivered = [n \in Nodes |-> {GenesisBlock}]
    /\ local_tip = [n \in Nodes |-> GenesisBlock]

----------------------------------------------------------------------------
\* Actions

\* 1. Mining / Proposing a block: extends an existing block, possibly creating a fork at height H
MineBlock(b_id, parent_block, weight) ==
    /\ b_id \in BlockIds \ UsedBlockIds
    /\ parent_block \in blocks
    /\ parent_block.height < MaxHeight
    /\ weight \in WeightOptions
    /\ LET new_block == [
            id |-> b_id,
            height |-> parent_block.height + 1,
            parent |-> parent_block.id,
            accumulated_vdf_iterations |-> parent_block.accumulated_vdf_iterations + weight
          ]
       IN
          /\ blocks' = blocks \cup {new_block}
          /\ network_pool' = network_pool \cup {new_block}
          /\ UNCHANGED <<delivered, local_tip>>

\* 2. Receiving a block and applying the Heaviest-Chain fork choice rule
ReceiveBlock(n, b) ==
    /\ b \in network_pool \ delivered[n]
    /\ delivered' = [delivered EXCEPT ![n] = delivered[n] \cup {b}]
    /\ local_tip' = [local_tip EXCEPT ![n] = IF IsHeavier(b, local_tip[n]) THEN b ELSE local_tip[n]]
    /\ UNCHANGED <<blocks, network_pool>>

\* 3. Stuttering action when all blocks are mined and delivered
Terminating ==
    /\ AllDelivered
    /\ BlockIds \subseteq UsedBlockIds
    /\ UNCHANGED vars

----------------------------------------------------------------------------
\* Next-State Relation

Next ==
    \/ \E b_id \in BlockIds, parent \in blocks, w \in WeightOptions:
          MineBlock(b_id, parent, w)
    \/ \E n \in Nodes, b \in network_pool:
          ReceiveBlock(n, b)
    \/ Terminating

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

----------------------------------------------------------------------------
\* Invariants

\* Type invariant
TypeOK ==
    /\ blocks \subseteq [
            id: Nat,
            height: Nat,
            parent: Nat,
            accumulated_vdf_iterations: Nat
       ]
    /\ network_pool \subseteq blocks
    /\ \A n \in Nodes: delivered[n] \subseteq network_pool
    /\ \A n \in Nodes: local_tip[n] \in delivered[n]

\* Heaviest-Chain Invariant:
\* Every honest node's local tip is the maximal accumulated_vdf_iterations block among all delivered blocks
Inv_HeaviestChain ==
    \A n \in Nodes:
        \A b \in delivered[n]:
            \/ local_tip[n].accumulated_vdf_iterations > b.accumulated_vdf_iterations
            \/ (local_tip[n].accumulated_vdf_iterations = b.accumulated_vdf_iterations /\ local_tip[n].id <= b.id)

\* Eventual Consensus Invariant:
\* Once synchronous delivery bounds ensure all broadcasted blocks are delivered to all honest nodes,
\* all honest nodes hold the identical canonical tip.
Inv_EventualConsensus ==
    AllDelivered => (\A n1, n2 \in Nodes: local_tip[n1] = local_tip[n2])

----------------------------------------------------------------------------
\* Temporal Liveness Property:
\* Under fair delivery, the network eventually converges to consensus.
Prop_EventualConvergence ==
    <>(AllDelivered /\ (\A n1, n2 \in Nodes: local_tip[n1] = local_tip[n2]))

============================================================================
