"""
Mutation Generator — Inject vulnerabilities into clean contracts for synthetic dataset.

Applies semantic-aware mutation operators to create labeled vulnerability samples.
This ensures 100% anti-contamination since mutated contracts never existed before.
"""

from __future__ import annotations

import json
import logging
import random
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class MutationResult:
    """Result of a single mutation operation."""

    original_file: str
    mutated_code: str
    mutation_type: str
    vulnerability_label: str
    mutation_description: str
    line_number: int = 0


# Mutation operators: each injects a specific vulnerability
MUTATION_OPERATORS = {
    "reentrancy": {
        "label": "reentrancy",
        "description": "Swap state update and external call order (CEI violation)",
    },
    "remove_access_control": {
        "label": "access_control",
        "description": "Remove onlyOwner or access control modifier",
    },
    "add_unchecked": {
        "label": "integer_overflow",
        "description": "Wrap arithmetic in unchecked block",
    },
    "ignore_return": {
        "label": "unchecked_return",
        "description": "Remove return value check from low-level call",
    },
    "use_timestamp": {
        "label": "timestamp_dependence",
        "description": "Replace secure source with block.timestamp",
    },
}


class MutationGenerator:
    """Generates mutated contracts with injected vulnerabilities."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def mutate_file(self, sol_path: str | Path) -> list[MutationResult]:
        """Apply all applicable mutations to a Solidity file."""
        source = Path(sol_path).read_text()
        results = []

        for op_name, op_info in MUTATION_OPERATORS.items():
            mutated = self._apply_mutation(source, op_name)
            if mutated and mutated != source:
                results.append(
                    MutationResult(
                        original_file=str(sol_path),
                        mutated_code=mutated,
                        mutation_type=op_name,
                        vulnerability_label=op_info["label"],
                        mutation_description=op_info["description"],
                    )
                )

        return results

    def generate_dataset(
        self,
        source_dir: str | Path,
        output_dir: str | Path,
        max_per_file: int = 3,
    ) -> dict:
        """Generate mutated dataset from clean contracts."""
        source_dir = Path(source_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = output_dir / "raw"
        raw_dir.mkdir(exist_ok=True)

        sol_files = sorted(source_dir.glob("**/*.sol"))
        labels = {}
        stats = {"total_mutations": 0, "by_type": {}}
        count = 0

        for sol_file in sol_files:
            try:
                mutations = self.mutate_file(sol_file)
                self.rng.shuffle(mutations)

                for mut in mutations[:max_per_file]:
                    name = f"mut_{count:04d}_{mut.mutation_type}_{sol_file.stem}"
                    out_path = raw_dir / f"{name}.sol"
                    out_path.write_text(mut.mutated_code)

                    labels[name] = mut.vulnerability_label
                    stats["total_mutations"] += 1
                    stats["by_type"][mut.mutation_type] = stats["by_type"].get(mut.mutation_type, 0) + 1
                    count += 1

            except Exception as e:
                logger.debug(f"Cannot mutate {sol_file.name}: {e}")

        # Save labels
        labels_path = output_dir / "labels.json"
        with open(labels_path, "w") as f:
            json.dump(labels, f, indent=2)

        logger.info(f"Generated {stats['total_mutations']} mutations → {raw_dir}")
        logger.info(f"Distribution: {stats['by_type']}")

        return stats

    def _apply_mutation(self, source: str, op_name: str) -> str | None:
        """Apply a specific mutation operator."""
        dispatch = {
            "reentrancy": self._mutate_reentrancy,
            "remove_access_control": self._mutate_access_control,
            "add_unchecked": self._mutate_unchecked,
            "ignore_return": self._mutate_ignore_return,
            "use_timestamp": self._mutate_timestamp,
        }
        func = dispatch.get(op_name)
        if func:
            return func(source)
        return None

    def _mutate_reentrancy(self, source: str) -> str:
        """Inject reentrancy by reordering state update and external call."""
        # Pattern: state_update followed by external call → swap them
        lines = source.split("\n")
        result = list(lines)

        for i in range(len(lines) - 1):
            line = lines[i].strip()
            next_line = lines[i + 1].strip() if i + 1 < len(lines) else ""

            # Find pattern: balance update then transfer
            if re.search(r"balances?\[.*\]\s*[-=]", line) and re.search(r"\.(call|transfer|send)\s*[\({]", next_line):
                # Already vulnerable pattern (update before call) - skip
                continue

            # Find pattern: transfer then balance update → already CEI violation
            if re.search(r"\.(call|transfer|send)\s*[\({]", line) and re.search(r"balances?\[.*\]\s*[-=]", next_line):
                continue  # Already vulnerable

            # Find safe pattern: balance update THEN transfer → swap to make vulnerable
            if re.search(r"balances?\[.*\]\s*[-=]", line):
                # Look ahead for external call
                for j in range(i + 1, min(i + 5, len(lines))):
                    if re.search(r"\.(call|transfer|send)\s*[\({]", lines[j]):
                        # Swap: move external call before state update
                        call_line = result[j]
                        result[j] = result[i]
                        result[i] = call_line
                        result.insert(i, "        // MUTATED: CEI violation injected")
                        return "\n".join(result)

        # Alternative: add a reentrancy-vulnerable withdraw pattern
        if "function" in source and "balance" in source.lower():
            inject = """
    // MUTATED: Reentrancy-vulnerable function injected
    function withdrawAll_mut() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // State update AFTER external call
    }"""
            # Insert before the last closing brace
            last_brace = source.rfind("}")
            if last_brace > 0:
                return source[:last_brace] + inject + "\n}\n"

        return source

    def _mutate_access_control(self, source: str) -> str:
        """Remove access control modifiers."""
        # Remove onlyOwner modifier
        mutated = re.sub(
            r"\bonlyOwner\b\s*",
            "",
            source,
            count=1,
        )
        if mutated != source:
            mutated = mutated.replace(
                "// SPDX-License-Identifier",
                "// MUTATED: Access control removed\n// SPDX-License-Identifier",
                1,
            )
            return mutated

        # Remove require(msg.sender == owner)
        mutated = re.sub(
            r"require\s*\(\s*msg\.sender\s*==\s*owner.*?\);\s*\n",
            "// MUTATED: access check removed\n",
            source,
            count=1,
        )
        return mutated

    def _mutate_unchecked(self, source: str) -> str:
        """Wrap arithmetic operations in unchecked blocks."""
        # Find arithmetic operations
        pattern = r"(\s+)(\w+\s*[+\-*]=\s*\w+;)"
        match = re.search(pattern, source)
        if match:
            indent = match.group(1)
            expr = match.group(2)
            replacement = f"{indent}unchecked {{ // MUTATED: overflow possible\n{indent}    {expr}\n{indent}}}"
            return source[: match.start()] + replacement + source[match.end() :]
        return source

    def _mutate_ignore_return(self, source: str) -> str:
        """Remove return value checks from low-level calls."""
        # Pattern: (bool success, ) = addr.call{...}(...); require(success);
        mutated = re.sub(
            r"\(bool\s+\w+,?\s*\)\s*=\s*([\w.]+\.call\{[^}]*\}\([^)]*\));"
            r"\s*require\s*\(\w+[^;]*\);",
            r"\1; // MUTATED: return value ignored",
            source,
            count=1,
        )
        if mutated != source:
            return mutated

        # Pattern: require(addr.send(amount))
        mutated = re.sub(
            r"require\s*\(\s*(\w+\.send\([^)]+\))\s*[^)]*\)",
            r"\1 // MUTATED: return unchecked",
            source,
            count=1,
        )
        return mutated

    def _mutate_timestamp(self, source: str) -> str:
        """Replace secure randomness with block.timestamp."""
        # Add timestamp-dependent logic
        if "block.timestamp" not in source and "function" in source:
            inject = """
    // MUTATED: Timestamp-dependent logic injected
    function isLucky_mut() public view returns (bool) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 2 == 0;
    }"""
            last_brace = source.rfind("}")
            if last_brace > 0:
                return source[:last_brace] + inject + "\n}\n"
        return source
