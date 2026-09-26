"""
Solidity Parser — Converts .sol files to AST using Slither.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    """Metadata about a Solidity function."""

    name: str
    visibility: str
    state_mutability: str
    modifiers: list[str] = field(default_factory=list)
    parameters: list[dict[str, str]] = field(default_factory=list)
    return_types: list[str] = field(default_factory=list)
    has_external_call: bool = False
    has_eth_transfer: bool = False
    has_delegatecall: bool = False
    line_start: int = 0
    line_end: int = 0


@dataclass
class ContractInfo:
    """Metadata about a parsed Solidity contract."""

    name: str
    contract_type: str
    base_contracts: list[str] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    state_variables: list[dict[str, Any]] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    modifiers_list: list[str] = field(default_factory=list)
    source_path: str = ""


class SolidityParser:
    """Parses Solidity files using Slither for AST extraction."""

    def __init__(self, solc: str = "solc", remappings: list[str] | None = None):
        self.solc = solc
        self.remappings = remappings or []

    def parse(self, sol_path: str | Path) -> list[ContractInfo]:
        """Parse a Solidity file and return contract metadata."""
        sol_path = Path(sol_path)
        if not sol_path.exists():
            raise FileNotFoundError(f"Solidity file not found: {sol_path}")

        try:
            from slither.slither import Slither
        except ImportError:
            raise ImportError("Install slither-analyzer: pip install slither-analyzer")

        logger.info(f"Parsing {sol_path} with solc binary: {self.solc}")
        slither = Slither(str(sol_path), solc=self.solc)

        contracts: list[ContractInfo] = []
        for contract in slither.contracts:
            info = self._extract_contract(contract, str(sol_path))
            contracts.append(info)

        logger.info(f"Extracted {len(contracts)} contracts from {sol_path}")
        return contracts

    def _extract_contract(self, contract: Any, source_path: str) -> ContractInfo:
        """Extract metadata from a Slither contract object."""
        ctype = "library" if contract.is_library else ("interface" if contract.is_interface else "contract")
        functions = [self._extract_function(f) for f in contract.functions]

        state_vars = [
            {"name": v.name, "type": str(v.type), "visibility": v.visibility} for v in contract.state_variables
        ]

        return ContractInfo(
            name=contract.name,
            contract_type=ctype,
            base_contracts=[bc.name for bc in contract.inheritance],
            functions=functions,
            state_variables=state_vars,
            events=[e.name for e in contract.events],
            modifiers_list=[m.name for m in contract.modifiers],
            source_path=source_path,
        )

    def _extract_function(self, func: Any) -> FunctionInfo:
        """Extract metadata from a Slither function object."""
        has_ext, has_eth, has_del = False, False, False
        for node in func.nodes:
            for ir in node.irs:
                s = str(ir)
                if "EXTERNAL_CALL" in s or "HIGH_LEVEL_CALL" in s:
                    has_ext = True
                if "SEND" in s or "TRANSFER" in s:
                    has_eth = True
                if "DELEGATE" in s:
                    has_del = True

        lines = func.source_mapping.lines if func.source_mapping else []
        return FunctionInfo(
            name=func.name,
            visibility=func.visibility,
            state_mutability="view" if getattr(func, "view", False) else "nonpayable",
            modifiers=[m.name for m in func.modifiers],
            parameters=[{"name": p.name, "type": str(p.type)} for p in func.parameters],
            return_types=[str(r.type) for r in func.returns],
            has_external_call=has_ext,
            has_eth_transfer=has_eth,
            has_delegatecall=has_del,
            line_start=lines[0] if lines else 0,
            line_end=lines[-1] if lines else 0,
        )

    def parse_to_json(self, sol_path: str | Path, output_path: str | Path | None = None) -> dict:
        """Parse and optionally save as JSON."""
        contracts = self.parse(sol_path)
        result = {"source_file": str(sol_path), "solc": self.solc, "contracts": []}
        for c in contracts:
            result["contracts"].append(
                {
                    "name": c.name,
                    "type": c.contract_type,
                    "base_contracts": c.base_contracts,
                    "state_variables": c.state_variables,
                    "events": c.events,
                    "functions": [
                        {
                            "name": f.name,
                            "visibility": f.visibility,
                            "has_external_call": f.has_external_call,
                            "has_eth_transfer": f.has_eth_transfer,
                            "lines": [f.line_start, f.line_end],
                        }
                        for f in c.functions
                    ],
                }
            )
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2)
        return result
