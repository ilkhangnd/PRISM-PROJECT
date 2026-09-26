"""
GNN-MHA Model V2 — Improved architecture for higher accuracy.

Key improvements over v1:
  - Edge-type aware GATConv (uses edge_attr)
  - JumpingKnowledge aggregation (combines ALL layer outputs)
  - BatchNorm instead of LayerNorm (better for graph data)
  - Improved classifier head with 2 hidden layers
  - Default dropout aligned with the canonical reported experiment (0.15)
  - Proper skip connections with projection
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import GATConv, GlobalAttention, global_mean_pool

    HAS_PYG = True
except ImportError:
    HAS_PYG = False


class GNNMHAv2(nn.Module):
    """
    Graph Attention Network with Multi-Head Attention V2.

    Improvements:
    - Edge attribute encoding for edge-type awareness
    - JumpingKnowledge for multi-scale feature aggregation
    - Dual pooling (attention + mean) for richer graph-level representation
    - Improved classifier head
    """

    def __init__(
        self,
        in_channels: int = 32,
        hidden_channels: int = 256,
        num_classes: int = 5,
        num_heads: int = 8,
        num_layers: int = 4,
        dropout: float = 0.15,
        edge_dim: int = 4,
        jk_mode: str = "cat",  # "cat", "max", "lstm", "none"
        pooling: str = "dual",  # "dual" (attention + mean) or "mean"
    ):
        super().__init__()

        if not HAS_PYG:
            raise ImportError("torch-geometric is required.")

        self.num_layers = num_layers
        self.dropout = dropout
        self.jk_mode = jk_mode

        # Input projection
        self.input_proj = nn.Linear(in_channels, hidden_channels)

        # Edge encoding
        self.edge_encoder = nn.Linear(edge_dim, hidden_channels) if edge_dim > 0 else None

        # GAT layers
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()

        for i in range(num_layers):
            self.convs.append(
                GATConv(
                    hidden_channels,
                    hidden_channels,
                    heads=num_heads,
                    concat=False,
                    dropout=dropout,
                    edge_dim=hidden_channels if edge_dim > 0 else None,
                )
            )
            self.norms.append(nn.BatchNorm1d(hidden_channels))

        # JumpingKnowledge: combine features from all layers
        if jk_mode == "cat":
            jk_channels = hidden_channels * num_layers
        else:
            jk_channels = hidden_channels

        # Pooling: dual (attention + mean) or mean-only for ablation
        self.pooling = pooling
        if pooling == "dual":
            gate_nn = nn.Sequential(nn.Linear(jk_channels, 128), nn.ReLU(), nn.Linear(128, 1))
            self.attn_pool = GlobalAttention(gate_nn)
            pool_dim = jk_channels * 2  # attention + mean
        elif pooling == "mean":
            self.attn_pool = None
            pool_dim = jk_channels
        else:
            raise ValueError(f"Unsupported pooling: {pooling}")

        # Classifier head
        self.classifier = nn.Sequential(
            nn.Linear(pool_dim, hidden_channels),
            nn.LayerNorm(hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.ReLU(),
            nn.Dropout(dropout / 2),
            nn.Linear(hidden_channels // 2, num_classes),
        )

    def forward(self, x, edge_index, batch=None, edge_attr=None):
        """Forward pass."""
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)

        # Input projection
        x = self.input_proj(x)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        # Encode edge attributes
        encoded_edge_attr = None
        if self.edge_encoder is not None and edge_attr is not None:
            encoded_edge_attr = self.edge_encoder(edge_attr.float())

        # Graph convolutions with skip connections + JK collection
        layer_outputs = []

        for i in range(self.num_layers):
            identity = x
            x = self.convs[i](x, edge_index, edge_attr=encoded_edge_attr)
            x = self.norms[i](x)
            x = F.elu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
            x = x + identity  # Residual connection (always works since dims match)
            layer_outputs.append(x)

        # JumpingKnowledge aggregation
        if self.jk_mode == "cat":
            x = torch.cat(layer_outputs, dim=-1)
        elif self.jk_mode == "max":
            x = torch.stack(layer_outputs, dim=0).max(dim=0)[0]
        else:
            x = layer_outputs[-1]

        # Graph-level pooling
        if self.pooling == "dual":
            x_attn = self.attn_pool(x, batch)
            x_mean = global_mean_pool(x, batch)
            x = torch.cat([x_attn, x_mean], dim=-1)
        else:
            x = global_mean_pool(x, batch)

        # Classification
        return self.classifier(x)

    def get_attention_weights(self, x, edge_index, batch=None, edge_attr=None):
        """Extract attention weights for hotspot detection."""
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)

        x = self.input_proj(x)
        x = F.relu(x)

        encoded_edge_attr = None
        if self.edge_encoder is not None and edge_attr is not None:
            encoded_edge_attr = self.edge_encoder(edge_attr.float())

        attention_weights = []
        for i in range(self.num_layers):
            identity = x
            x, (edge_idx, alpha) = self.convs[i](
                x, edge_index, edge_attr=encoded_edge_attr, return_attention_weights=True
            )
            x = self.norms[i](x)
            x = F.elu(x)
            x = x + identity
            attention_weights.append({"layer": i, "edge_index": edge_idx, "attention": alpha})

        return attention_weights
