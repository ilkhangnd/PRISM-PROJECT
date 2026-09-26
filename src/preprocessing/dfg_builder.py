"""
DFG Builder — Constructs Data Flow Graphs tracking variable defs/uses.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


class DFGBuilder:
    """Builds Data Flow Graphs from Slither function objects."""

    def build_from_slither_func(self, func: Any) -> nx.DiGraph:
        """Build a DFG for a single function."""
        g = nx.DiGraph()

        # Track variable definitions: var_name -> list of defining node IDs
        var_defs: dict[str, list[int]] = {}

        for node in func.nodes:
            node_id = node.node_id
            g.add_node(node_id, label=str(node), expression=str(node.expression) if node.expression else "")

            for ir in node.irs:
                # Track definitions (lvalue)
                if hasattr(ir, "lvalue") and ir.lvalue:
                    var_name = str(ir.lvalue)
                    if var_name not in var_defs:
                        var_defs[var_name] = []
                    var_defs[var_name].append(node_id)

                # Track uses (read variables)
                if hasattr(ir, "read") and ir.read:
                    for read_var in ir.read:
                        var_name = str(read_var)
                        if var_name in var_defs:
                            for def_node in var_defs[var_name]:
                                if def_node != node_id:
                                    g.add_edge(def_node, node_id, edge_type="data_dep", variable=var_name)

        return g

    def build_from_file(self, sol_path: str, solc: str = "solc") -> dict[str, nx.DiGraph]:
        """Build DFGs for all functions in a Solidity file."""
        try:
            from slither.slither import Slither
        except ImportError:
            raise ImportError("Install slither-analyzer")

        slither = Slither(sol_path, solc=solc)
        graphs = {}

        for contract in slither.contracts:
            for func in contract.functions:
                key = f"{contract.name}.{func.name}"
                graphs[key] = self.build_from_slither_func(func)
                logger.info(f"Built DFG for {key}")

        return graphs
