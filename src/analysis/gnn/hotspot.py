"""
Hotspot Detection — Ranks functions by vulnerability risk using GNN attention weights.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import torch

logger = logging.getLogger(__name__)


@dataclass
class Hotspot:
    """A detected high-risk function."""

    function_name: str
    contract_name: str
    risk_score: float
    vulnerability_hint: str
    line_start: int
    line_end: int


# Vulnerability type names indexed by class ID
VULN_NAMES = {
    0: "Reentrancy",
    1: "Integer Overflow/Underflow",
    2: "Access Control",
    3: "Unchecked Return Values",
    4: "Denial of Service",
    5: "Front-Running",
    6: "Timestamp Dependence",
    7: "Delegatecall Injection",
}


class HotspotDetector:
    """Identifies high-risk functions using GNN predictions and attention weights."""

    def __init__(self, model, threshold: float = 0.5):
        self.model = model
        self.threshold = threshold

    @torch.no_grad()
    def detect(self, data, function_metadata: list[dict] | None = None) -> list[Hotspot]:
        """
        Run inference and identify hotspots.

        Args:
            data: PyG Data object (single graph).
            function_metadata: Optional list of function info dicts for enrichment.

        Returns:
            Sorted list of Hotspot objects (highest risk first).
        """
        self.model.eval()
        device = next(self.model.parameters()).device
        data = data.to(device)

        # Get predictions
        logits = self.model(data.x, data.edge_index)
        probs = torch.softmax(logits, dim=1)
        pred_class = probs.argmax(dim=1).item()
        confidence = probs.max(dim=1).values.item()

        # Get attention weights for node-level risk scoring
        attention_data = self.model.get_attention_weights(data.x, data.edge_index)
        node_scores = self._compute_node_risk_scores(attention_data, data.num_nodes)

        hotspots = []
        if confidence >= self.threshold:
            vuln_name = VULN_NAMES.get(pred_class, f"Unknown (class {pred_class})")

            # Create hotspot entries
            if function_metadata:
                for i, func_meta in enumerate(function_metadata):
                    score = node_scores[i].item() if i < len(node_scores) else confidence
                    hotspots.append(
                        Hotspot(
                            function_name=func_meta.get("name", f"func_{i}"),
                            contract_name=func_meta.get("contract", "Unknown"),
                            risk_score=float(score),
                            vulnerability_hint=vuln_name,
                            line_start=func_meta.get("line_start", 0),
                            line_end=func_meta.get("line_end", 0),
                        )
                    )
            else:
                hotspots.append(
                    Hotspot(
                        function_name="unknown",
                        contract_name="unknown",
                        risk_score=float(confidence),
                        vulnerability_hint=vuln_name,
                        line_start=0,
                        line_end=0,
                    )
                )

        hotspots.sort(key=lambda h: h.risk_score, reverse=True)
        return hotspots

    def _compute_node_risk_scores(self, attention_data: list, num_nodes: int) -> torch.Tensor:
        """Aggregate attention weights across layers to score each node."""
        scores = torch.zeros(num_nodes)

        for layer_data in attention_data:
            alpha = layer_data["attention"]
            edge_index = layer_data["edge_index"]

            if alpha is not None and edge_index is not None:
                # Sum incoming attention for each node
                for i in range(edge_index.shape[1]):
                    dst = edge_index[1, i].item()
                    if dst < num_nodes:
                        scores[dst] += alpha[i].mean().item()

        # Normalize to [0, 1]
        if scores.max() > 0:
            scores = scores / scores.max()

        return scores
