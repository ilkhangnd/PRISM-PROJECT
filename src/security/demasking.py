"""
De-masking Module — Restores original identifiers in analysis reports.

After the pipeline produces vulnerability reports using masked identifiers,
this module applies the reverse mapping to make reports human-readable.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.security.data_masking import MaskMapping


class Demasker:
    """Restores original identifiers from masked analysis output."""

    def __init__(self, mapping: MaskMapping | None = None, mapping_path: Path | None = None):
        """
        Initialize the demasker.

        Args:
            mapping: An existing MaskMapping object.
            mapping_path: Path to a saved mapping JSON file.
        """
        if mapping is not None:
            self.mapping = mapping
        elif mapping_path is not None:
            self.mapping = MaskMapping.load(mapping_path)
        else:
            raise ValueError("Either 'mapping' or 'mapping_path' must be provided.")

    def demask_text(self, text: str) -> str:
        """
        Replace all masked identifiers in text with original names.

        Args:
            text: Text containing masked identifiers.

        Returns:
            Text with original identifiers restored.
        """
        result = text
        # Sort by length (longest first) to avoid partial replacements
        sorted_masked = sorted(self.mapping.masked_to_original.keys(), key=len, reverse=True)
        for masked in sorted_masked:
            original = self.mapping.masked_to_original[masked]
            pattern = re.compile(rf"\b{re.escape(masked)}\b")
            result = pattern.sub(original, result)
        return result

    def demask_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively demask all string values in a vulnerability report dict.

        Args:
            report: Report dictionary with masked identifiers.

        Returns:
            Report with all string values demasked.
        """
        return self._demask_recursive(report)

    def _demask_recursive(self, obj: Any) -> Any:
        """Recursively walk a data structure and demask all strings."""
        if isinstance(obj, str):
            return self.demask_text(obj)
        elif isinstance(obj, dict):
            return {k: self._demask_recursive(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._demask_recursive(item) for item in obj]
        return obj

    def demask_json_file(self, input_path: Path, output_path: Path) -> None:
        """
        Demask a JSON report file and save the result.

        Args:
            input_path: Path to the masked JSON report.
            output_path: Path to save the demasked report.
        """
        with open(input_path) as f:
            report = json.load(f)

        demasked = self.demask_report(report)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(demasked, f, indent=2)
