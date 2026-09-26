"""
Graph Embeddings — Converts NetworkX graphs to PyTorch Geometric Data objects.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx
import torch

logger = logging.getLogger(__name__)

# Node type encoding
NODE_TYPE_MAP = {
    "ENTRY_POINT": 0,
    "EXPRESSION": 1,
    "RETURN": 2,
    "IF": 3,
    "ENDIF": 4,
    "BEGIN_LOOP": 5,
    "END_LOOP": 6,
    "NEW_VARIABLE": 7,
    "ASSEMBLY": 8,
    "THROW": 9,
    "CATCH": 10,
    "TRY": 11,
    "OTHER": 12,
}

# Edge type encoding
EDGE_TYPE_MAP = {"sequential": 0, "branch": 1, "loop_back": 2, "data_dep": 3}


def encode_node_type(node_type: str) -> int:
    """Map a node type string to an integer."""
    for key in NODE_TYPE_MAP:
        if key.lower() in node_type.lower():
            return NODE_TYPE_MAP[key]
    return NODE_TYPE_MAP["OTHER"]


def graph_to_pyg_data(
    cfg: nx.DiGraph,
    dfg: nx.DiGraph | None = None,
    label: int = 0,
    embedding_dim: int = 128,
) -> Any:
    """
    Convert a NetworkX CFG (and optional DFG) to a PyG Data object.

    Args:
        cfg: Control Flow Graph (NetworkX DiGraph).
        dfg: Optional Data Flow Graph to merge edges from.
        label: Vulnerability class label.
        embedding_dim: Dimension for node feature vectors.

    Returns:
        torch_geometric.data.Data object.
    """
    try:
        from torch_geometric.data import Data
    except ImportError:
        raise ImportError("Install torch-geometric: pip install torch-geometric")

    # Remap node IDs to contiguous 0..N-1
    node_list = list(cfg.nodes)
    node_map = {n: i for i, n in enumerate(node_list)}
    num_nodes = len(node_list)

    # Build node features
    features = torch.zeros(num_nodes, embedding_dim)
    for orig_id, new_id in node_map.items():
        node_data = cfg.nodes[orig_id]
        node_type = node_data.get("node_type", "OTHER")
        features[new_id][0] = encode_node_type(node_type)

        expr = node_data.get("expression", "")
        features[new_id][1] = 1.0 if "call" in expr.lower() else 0.0
        features[new_id][2] = 1.0 if "transfer" in expr.lower() or "send" in expr.lower() else 0.0
        features[new_id][3] = 1.0 if "require" in expr.lower() or "assert" in expr.lower() else 0.0
        features[new_id][4] = 1.0 if "delegatecall" in expr.lower() else 0.0

    # Build edge index from CFG
    edge_src, edge_dst, edge_attrs = [], [], []

    for u, v, data in cfg.edges(data=True):
        if u in node_map and v in node_map:
            edge_src.append(node_map[u])
            edge_dst.append(node_map[v])
            edge_attrs.append(EDGE_TYPE_MAP.get(data.get("edge_type", "sequential"), 0))

    # Merge DFG edges if provided
    if dfg:
        for u, v, data in dfg.edges(data=True):
            if u in node_map and v in node_map:
                edge_src.append(node_map[u])
                edge_dst.append(node_map[v])
                edge_attrs.append(EDGE_TYPE_MAP["data_dep"])

    if not edge_src:
        edge_index = torch.zeros(2, 0, dtype=torch.long)
        edge_attr = torch.zeros(0, dtype=torch.long)
    else:
        edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
        edge_attr = torch.tensor(edge_attrs, dtype=torch.long)

    return Data(
        x=features,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor([label], dtype=torch.long),
        num_nodes=num_nodes,
    )
