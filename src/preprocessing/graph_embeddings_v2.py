"""
Graph Embeddings V2 — Rich feature extraction for improved vulnerability detection.

Key improvements over v1:
  - 32-dim dense features vs 128-dim sparse (only 1% non-zero in v1!)
  - One-hot node type encoding (13 dims) vs single integer
  - Security-sensitive pattern detection (msg.value, msg.sender, tx.origin, etc.)
  - Graph structure features (degree, position, loop detection)
  - State variable read/write tracking
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx
import torch

logger = logging.getLogger(__name__)

# Node type encoding (one-hot, 13 types)
NODE_TYPES = [
    "ENTRY_POINT",
    "EXPRESSION",
    "RETURN",
    "IF",
    "ENDIF",
    "BEGIN_LOOP",
    "END_LOOP",
    "NEW_VARIABLE",
    "ASSEMBLY",
    "THROW",
    "CATCH",
    "TRY",
    "OTHER",
]
NODE_TYPE_IDX = {t: i for i, t in enumerate(NODE_TYPES)}
NUM_NODE_TYPES = len(NODE_TYPES)

# Edge type encoding
EDGE_TYPE_MAP = {"sequential": 0, "branch": 1, "loop_back": 2, "data_dep": 3}
NUM_EDGE_TYPES = len(EDGE_TYPE_MAP)

# Feature dimension breakdown:
# [0:13]  node_type one-hot           = 13 dims
# [13]    has_external_call           = 1
# [14]    has_state_write             = 1
# [15]    has_state_read              = 1
# [16]    has_require_assert          = 1
# [17]    has_delegatecall            = 1
# [18]    has_msg_value               = 1
# [19]    has_msg_sender              = 1
# [20]    has_timestamp               = 1
# [21]    has_block_number            = 1
# [22]    has_tx_origin               = 1
# [23]    in_degree                   = 1 (normalized)
# [24]    out_degree                  = 1 (normalized)
# [25]    is_loop_body                = 1
# [26]    num_irs (normalized)        = 1
# [27]    has_return_value            = 1
# [28]    has_condition               = 1
# [29]    position_ratio              = 1 (0-1)
# [30]    num_state_vars_read         = 1 (normalized)
# [31]    num_state_vars_written      = 1 (normalized)
# TOTAL = 32

FEATURE_DIM = 32


def _match_node_type(node_type_str: str) -> int:
    """Map a node type string to its index."""
    nt = node_type_str.upper().strip()
    for key, idx in NODE_TYPE_IDX.items():
        if key in nt:
            return idx
    return NODE_TYPE_IDX["OTHER"]


def _extract_expression_features(expr: str) -> dict:
    """Extract security-relevant features from an expression string."""
    expr_lower = expr.lower() if expr else ""
    return {
        "has_external_call": 1.0
        if any(kw in expr_lower for kw in [".call(", ".call{", ".send(", ".transfer("])
        else 0.0,
        "has_state_write": 1.0
        if any(kw in expr_lower for kw in ["=", "+=", "-=", "*=", "/="]) and "==" not in expr_lower
        else 0.0,
        "has_state_read": 1.0 if len(expr_lower) > 0 else 0.0,  # will be refined with IR
        "has_require_assert": 1.0 if any(kw in expr_lower for kw in ["require(", "assert(", "revert("]) else 0.0,
        "has_delegatecall": 1.0 if "delegatecall" in expr_lower else 0.0,
        "has_msg_value": 1.0 if "msg.value" in expr_lower else 0.0,
        "has_msg_sender": 1.0 if "msg.sender" in expr_lower else 0.0,
        "has_timestamp": 1.0 if any(kw in expr_lower for kw in ["block.timestamp", "now"]) else 0.0,
        "has_block_number": 1.0 if "block.number" in expr_lower else 0.0,
        "has_tx_origin": 1.0 if "tx.origin" in expr_lower else 0.0,
        "has_return_value": 1.0 if any(kw in expr_lower for kw in ["return", "returns"]) else 0.0,
        "has_condition": 1.0 if any(kw in expr_lower for kw in ["if(", "if (", "require(", "assert("]) else 0.0,
    }


def _extract_ir_features(irs: list) -> dict:
    """Extract features from Slither IR instructions."""
    num_irs = len(irs) if irs else 0
    state_reads = 0
    state_writes = 0
    has_ext_call = False
    has_delegatecall = False

    for ir_str in irs or []:
        ir_lower = str(ir_str).lower()
        if "high_level_call" in ir_lower or "low_level_call" in ir_lower:
            has_ext_call = True
        if "library_call" in ir_lower:
            pass  # library calls are generally safe
        if "delegatecall" in ir_lower:
            has_delegatecall = True
        # Count state variable accesses from IR patterns
        if "state_variable" in ir_lower:
            if "read" in ir_lower or "ref" in ir_lower:
                state_reads += 1
            if "write" in ir_lower or "assign" in ir_lower:
                state_writes += 1

    return {
        "num_irs": num_irs,
        "state_reads": state_reads,
        "state_writes": state_writes,
        "ir_has_ext_call": has_ext_call,
        "ir_has_delegatecall": has_delegatecall,
    }


def graph_to_pyg_data_v2(
    cfg: nx.DiGraph,
    dfg: nx.DiGraph | None = None,
    label: int = 0,
) -> Any:
    """
    Convert a NetworkX CFG (and optional DFG) to a PyG Data object with rich features.

    Args:
        cfg: Control Flow Graph (NetworkX DiGraph).
        dfg: Optional Data Flow Graph to merge edges from.
        label: Vulnerability class label.

    Returns:
        torch_geometric.data.Data object with 32-dim node features.
    """
    try:
        from torch_geometric.data import Data
    except ImportError:
        raise ImportError("Install torch-geometric: pip install torch-geometric")

    # Remap node IDs to contiguous 0..N-1
    node_list = list(cfg.nodes)
    node_map = {n: i for i, n in enumerate(node_list)}
    num_nodes = len(node_list)

    if num_nodes == 0:
        return Data(
            x=torch.zeros(1, FEATURE_DIM),
            edge_index=torch.zeros(2, 0, dtype=torch.long),
            edge_attr=torch.zeros(0, NUM_EDGE_TYPES),
            y=torch.tensor([label], dtype=torch.long),
            num_nodes=1,
        )

    # Detect loop nodes
    loop_nodes = set()
    try:
        for cycle in nx.simple_cycles(cfg):
            loop_nodes.update(cycle)
    except Exception:
        pass

    # Build node features
    features = torch.zeros(num_nodes, FEATURE_DIM)

    for orig_id, new_id in node_map.items():
        node_data = cfg.nodes[orig_id]

        # [0:13] Node type one-hot
        node_type_str = node_data.get("node_type", "OTHER")
        type_idx = _match_node_type(node_type_str)
        features[new_id][type_idx] = 1.0

        # Expression features
        expr = node_data.get("expression", "")
        expr_feats = _extract_expression_features(expr)

        # IR features
        irs = node_data.get("irs", [])
        ir_feats = _extract_ir_features(irs)

        # [13] has_external_call (combine expression + IR)
        features[new_id][13] = max(expr_feats["has_external_call"], 1.0 if ir_feats["ir_has_ext_call"] else 0.0)

        # [14] has_state_write
        features[new_id][14] = max(expr_feats["has_state_write"], min(ir_feats["state_writes"], 1.0))

        # [15] has_state_read
        features[new_id][15] = min(ir_feats["state_reads"], 1.0) if ir_feats["state_reads"] > 0 else 0.0

        # [16] has_require/assert
        features[new_id][16] = expr_feats["has_require_assert"]

        # [17] has_delegatecall
        features[new_id][17] = max(expr_feats["has_delegatecall"], 1.0 if ir_feats["ir_has_delegatecall"] else 0.0)

        # [18-22] Security-sensitive patterns
        features[new_id][18] = expr_feats["has_msg_value"]
        features[new_id][19] = expr_feats["has_msg_sender"]
        features[new_id][20] = expr_feats["has_timestamp"]
        features[new_id][21] = expr_feats["has_block_number"]
        features[new_id][22] = expr_feats["has_tx_origin"]

        # [23-24] Degree features (normalized by max degree)
        features[new_id][23] = float(cfg.in_degree(orig_id))
        features[new_id][24] = float(cfg.out_degree(orig_id))

        # [25] is_loop_body
        features[new_id][25] = 1.0 if orig_id in loop_nodes else 0.0

        # [26] num_irs (will be normalized later)
        features[new_id][26] = float(ir_feats["num_irs"])

        # [27] has_return_value
        features[new_id][27] = expr_feats["has_return_value"]

        # [28] has_condition
        features[new_id][28] = expr_feats["has_condition"]

        # [29] position_ratio (topological order / num_nodes)
        features[new_id][29] = new_id / max(num_nodes - 1, 1)

        # [30-31] State variable counts (will be normalized later)
        features[new_id][30] = float(ir_feats["state_reads"])
        features[new_id][31] = float(ir_feats["state_writes"])

    # Normalize continuous features
    for col in [23, 24, 26, 30, 31]:  # degree, num_irs, state_var counts
        col_max = features[:, col].max()
        if col_max > 0:
            features[:, col] = features[:, col] / col_max

    # Build edge index from CFG
    edge_src, edge_dst = [], []
    edge_type_indices = []

    for u, v, data in cfg.edges(data=True):
        if u in node_map and v in node_map:
            edge_src.append(node_map[u])
            edge_dst.append(node_map[v])
            et = data.get("edge_type", "sequential")
            edge_type_indices.append(EDGE_TYPE_MAP.get(et, 0))

    # Merge DFG edges
    if dfg:
        for u, v, data in dfg.edges(data=True):
            if u in node_map and v in node_map:
                edge_src.append(node_map[u])
                edge_dst.append(node_map[v])
                edge_type_indices.append(EDGE_TYPE_MAP["data_dep"])

    if not edge_src:
        edge_index = torch.zeros(2, 0, dtype=torch.long)
        edge_attr = torch.zeros(0, NUM_EDGE_TYPES)
    else:
        edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
        # One-hot encode edge types
        edge_attr = torch.zeros(len(edge_type_indices), NUM_EDGE_TYPES)
        for i, et in enumerate(edge_type_indices):
            edge_attr[i, et] = 1.0

    return Data(
        x=features,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor([label], dtype=torch.long),
        num_nodes=num_nodes,
    )
