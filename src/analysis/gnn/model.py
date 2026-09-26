"""
GNN-MHA Model — Multi-Head Attention Graph Neural Network for vulnerability detection.

Architecture: GATConv × 3 → Global Attention Pooling → MLP Classifier
Supports multi-class vulnerability classification.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import GATConv, GlobalAttention

    HAS_PYG = True
except ImportError:
    HAS_PYG = False


class GNNMHA(nn.Module):
    """
    Graph Attention Network with Multi-Head Attention for smart contract
    vulnerability classification.
    """

    def __init__(
        self,
        in_channels: int = 128,
        hidden_channels: int = 256,
        num_classes: int = 8,
        num_heads: int = 8,
        num_layers: int = 3,
        dropout: float = 0.3,
    ):
        super().__init__()

        if not HAS_PYG:
            raise ImportError("torch-geometric is required. Install with: pip install torch-geometric")

        self.num_layers = num_layers
        self.dropout = dropout

        # GAT convolution layers
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()

        # First layer
        self.convs.append(GATConv(in_channels, hidden_channels, heads=num_heads, concat=False, dropout=dropout))
        self.norms.append(nn.LayerNorm(hidden_channels))

        # Hidden layers
        for _ in range(num_layers - 1):
            self.convs.append(GATConv(hidden_channels, hidden_channels, heads=num_heads, concat=False, dropout=dropout))
            self.norms.append(nn.LayerNorm(hidden_channels))

        # Global attention pooling
        gate_nn = nn.Sequential(nn.Linear(hidden_channels, 64), nn.ReLU(), nn.Linear(64, 1))
        self.pool = GlobalAttention(gate_nn)

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels // 2, num_classes),
        )

    def forward(self, x, edge_index, batch=None):
        """Forward pass."""
        # Graph convolutions with residual connections
        for i in range(self.num_layers):
            identity = x if x.shape[-1] == self.convs[i].out_channels else None
            x = self.convs[i](x, edge_index)
            x = self.norms[i](x)
            x = F.elu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
            if identity is not None:
                x = x + identity  # Residual

        # Global pooling
        if batch is None:
            batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        x = self.pool(x, batch)

        # Classification
        return self.classifier(x)

    def get_attention_weights(self, x, edge_index, batch=None):
        """Extract attention weights for hotspot detection."""
        attention_weights = []

        for i in range(self.num_layers):
            x, (edge_idx, alpha) = self.convs[i](x, edge_index, return_attention_weights=True)
            x = self.norms[i](x)
            x = F.elu(x)
            attention_weights.append({"layer": i, "edge_index": edge_idx, "attention": alpha})

        return attention_weights
