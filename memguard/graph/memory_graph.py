"""
Memory Graph — tracks relationships between memories.
Enables blast radius analysis and trust propagation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from memguard.core.memory_entry import MemoryEntry


@dataclass
class GraphNode:
    memory_id: str
    key: str
    trust_score: float
    source_type: str
    edges_out: list[str] = field(default_factory=list)  # memory_ids this influences
    edges_in: list[str] = field(default_factory=list)   # memory_ids that influenced this


class MemoryGraph:
    """In-memory directed graph of memory relationships.
    
    Tracks:
    - parent_ids: which memories derived this memory
    - Usage edges: which memories were used together in decisions
    
    Enables:
    - Blast radius: if memory X is poisoned, what else is affected?
    - Trust propagation: untrusted source → low trust for derived memories
    """

    def __init__(self):
        self._nodes: dict[str, GraphNode] = {}
        self._key_to_ids: dict[str, list[str]] = defaultdict(list)

    def add_memory(self, entry: MemoryEntry) -> None:
        """Add a memory entry to the graph."""
        node = GraphNode(
            memory_id=entry.id,
            key=entry.key,
            trust_score=entry.trust_score,
            source_type=entry.provenance.source_type.value,
        )
        self._nodes[entry.id] = node
        self._key_to_ids[entry.key].append(entry.id)

        # Link parent edges
        for parent_id in entry.provenance.parent_memory_ids:
            if parent_id in self._nodes:
                self._nodes[parent_id].edges_out.append(entry.id)
                node.edges_in.append(parent_id)

    def get_blast_radius(self, memory_id: str) -> set[str]:
        """Get all memory IDs that could be affected if this memory is poisoned."""
        affected = set()
        queue = [memory_id]
        while queue:
            current = queue.pop(0)
            if current in affected:
                continue
            affected.add(current)
            node = self._nodes.get(current)
            if node:
                queue.extend(node.edges_out)
        affected.discard(memory_id)
        return affected

    def get_trust_chain(self, memory_id: str) -> list[tuple[str, float]]:
        """Trace the trust chain back to original sources."""
        chain = []
        visited = set()
        queue = [memory_id]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            node = self._nodes.get(current)
            if node:
                chain.append((node.key, node.trust_score))
                queue.extend(node.edges_in)
        return chain

    def get_node(self, memory_id: str) -> Optional[GraphNode]:
        return self._nodes.get(memory_id)

    def get_ids_for_key(self, key: str) -> list[str]:
        return self._key_to_ids.get(key, [])

    @property
    def node_count(self) -> int:
        return len(self._nodes)
