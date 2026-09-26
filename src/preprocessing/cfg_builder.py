"""
CFG Builder — Constructs Control Flow Graphs from Slither's internal IR.

Exports as NetworkX graph and edge-list JSON for PyTorch Geometric ingestion.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


class CFGBuilder:
    """Builds Control Flow Graphs from Slither contract objects."""

    def __init__(self):
        self.graphs: dict[str, nx.DiGraph] = {}

    def build_from_slither(self, sol_path: str | Path, solc: str = "solc") -> dict[str, nx.DiGraph]:
        """Build CFGs for all functions in a Solidity file.

        Args:
            sol_path: Path to the .sol file.
            solc: Path or name of the solc binary (default: "solc" from PATH via solc-select).
        """
        try:
            from slither.slither import Slither
        except ImportError:
            raise ImportError("Install slither-analyzer")

        slither = Slither(str(sol_path), solc=solc)

        for contract in slither.contracts:
            for func in contract.functions:
                key = f"{contract.name}.{func.name}"
                graph = self._build_function_cfg(func)
                self.graphs[key] = graph
                logger.info(f"Built CFG for {key}: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

        return self.graphs

    def _build_function_cfg(self, func: Any) -> nx.DiGraph:
        """Build a CFG for a single function from Slither nodes."""
        g = nx.DiGraph()

        for node in func.nodes:
            node_type = str(node.type) if hasattr(node, "type") else "unknown"
            g.add_node(
                node.node_id,
                label=str(node),
                node_type=node_type,
                expression=str(node.expression) if node.expression else "",
                irs=[str(ir) for ir in node.irs],
            )

            for son in node.sons:
                edge_type = "branch" if len(node.sons) > 1 else "sequential"
                g.add_edge(node.node_id, son.node_id, edge_type=edge_type)

        # Detect loop-back edges
        try:
            cycles = list(nx.simple_cycles(g))
            for cycle in cycles:
                if len(cycle) >= 2:
                    back_edge = (cycle[-1], cycle[0])
                    if g.has_edge(*back_edge):
                        g.edges[back_edge]["edge_type"] = "loop_back"
        except Exception:
            pass

        return g

    def export_edge_list(self, output_dir: str | Path) -> dict[str, str]:
        """Export all CFGs as edge-list JSON files."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        exported = {}

        for name, graph in self.graphs.items():
            safe_name = name.replace(".", "_")
            path = output_dir / f"{safe_name}_cfg.json"

            data = {
                "function": name,
                "num_nodes": graph.number_of_nodes(),
                "num_edges": graph.number_of_edges(),
                "nodes": [{"id": n, **graph.nodes[n]} for n in graph.nodes],
                "edges": [{"source": u, "target": v, **graph.edges[u, v]} for u, v in graph.edges],
            }

            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            exported[name] = str(path)

        return exported

    def to_networkx(self, function_name: str) -> nx.DiGraph | None:
        """Get the NetworkX graph for a specific function."""
        return self.graphs.get(function_name)

    def get_all_graphs(self) -> dict[str, nx.DiGraph]:
        """Return all built CFGs."""
        return self.graphs
