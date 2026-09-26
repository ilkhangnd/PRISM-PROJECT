"""
Data Masking Module — Anonymizes identifiers in Solidity source code.

This module provides deterministic anonymization of function names, variable names,
and contract names before sending code to external LLM APIs, preserving privacy
while maintaining structural integrity for analysis.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class MaskMapping:
    """Stores the bidirectional mapping between original and masked identifiers."""

    original_to_masked: dict[str, str] = field(default_factory=dict)
    masked_to_original: dict[str, str] = field(default_factory=dict)
    _counter: int = field(default=0, repr=False)

    def add(self, original: str, prefix: str = "prism_") -> str:
        if original in self.original_to_masked:
            return self.original_to_masked[original]

        # Use semantic-preserving prefixes based on capitalization
        if original[0].isupper():
            semantic_prefix = "Type_"
        elif original.startswith("is") or original.startswith("has") or original.startswith("can"):
            semantic_prefix = "b_"
        else:
            semantic_prefix = "v_"

        masked = f"{prefix}{semantic_prefix}{self._counter:04d}"
        self._counter += 1

        self.original_to_masked[original] = masked
        self.masked_to_original[masked] = original
        return masked

    def get_masked(self, original: str) -> str | None:
        """Look up the masked version of an original identifier."""
        return self.original_to_masked.get(original)

    def get_original(self, masked: str) -> str | None:
        """Look up the original version of a masked identifier."""
        return self.masked_to_original.get(masked)

    def save(self, path: Path) -> None:
        """Persist the mapping to a JSON file for later de-masking."""
        data = {
            "original_to_masked": self.original_to_masked,
            "masked_to_original": self.masked_to_original,
            "counter": self._counter,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: Path) -> MaskMapping:
        """Load a previously saved mapping from disk."""
        with open(path) as f:
            data = json.load(f)
        mapping = cls(
            original_to_masked=data["original_to_masked"],
            masked_to_original=data["masked_to_original"],
            _counter=data["counter"],
        )
        return mapping


class DataMasker:
    """
    Anonymizes Solidity source code identifiers while preserving structure.

    Preserves:
    - Solidity keywords (contract, function, modifier, etc.)
    - Standard interface names (ERC-20/721 function signatures)
    - Built-in globals (msg.sender, block.timestamp, etc.)
    - Numeric literals and string literals
    """

    # Solidity keywords and units that must never be masked
    SOLIDITY_KEYWORDS = {
        "contract", "library", "interface", "abstract", "is",
        "function", "modifier", "event", "error", "constructor", "fallback", "receive",
        "mapping", "struct", "enum", "type",
        "public", "private", "internal", "external",
        "view", "pure", "payable", "nonpayable", "virtual", "override",
        "immutable", "constant", "memory", "storage", "calldata",
        "returns", "return", "if", "else", "for", "while", "do", "break", "continue",
        "try", "catch", "emit", "require", "assert", "revert", "new", "delete",
        "this", "super", "true", "false", "unchecked", "indexed", "anonymous",
        "assembly", "let", "leave", "switch", "case", "default",
        "pragma", "solidity", "import", "using",
        "address", "bool", "string", "bytes",
        # Units
        "wei", "gwei", "szabo", "finney", "ether",
        "seconds", "minutes", "hours", "days", "weeks", "years",
        # SPDX / Directives
        "SPDX", "License", "Identifier", "MIT", "GPL", "UNLICENSED",
        "experimental", "ABIEncoderV2",
    }

    # Populate all standard uint/int/bytes variants
    for i in range(8, 264, 8):
        SOLIDITY_KEYWORDS.add(f"uint{i}")
        SOLIDITY_KEYWORDS.add(f"int{i}")
    SOLIDITY_KEYWORDS.add("uint")
    SOLIDITY_KEYWORDS.add("int")
    for i in range(1, 33):
        SOLIDITY_KEYWORDS.add(f"bytes{i}")

    # Built-in globals and methods to preserve
    BUILTINS = {
        "msg", "sender", "value", "data", "sig", "gas",
        "block", "timestamp", "number", "difficulty", "gaslimit", "coinbase",
        "chainid", "basefee", "prevrandao", "blobbasefee",
        "tx", "origin", "gasprice",
        "abi", "encode", "encodePacked", "encodeWithSelector", "encodeWithSignature",
        "encodeCall", "decode",
        "keccak256", "sha256", "ripemd160", "ecrecover", "addmod", "mulmod",
        "selfdestruct", "suicide", "gasleft", "blockhash", "blobhash",
        "call", "delegatecall", "staticcall", "code", "codehash", "length", "push", "pop",
        "selector", "creationCode", "runtimeCode", "name", "wrap", "unwrap",
        # EVM / Solidity address & balance operations
        "transfer", "send", "balance",
        # ERC20 / Standard interface functions
        "transferFrom", "approve", "balanceOf", "allowance", "totalSupply", "decimals", "symbol",
        # NatSpec keywords
        "dev", "notice", "param", "return", "returns", "author", "title", "custom", "inheritdoc",
    }

    # Regex to extract Solidity identifiers
    IDENTIFIER_PATTERN = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.mapping = MaskMapping()

        # Load preserved identifiers from config
        self.preserved: set[str] = set()
        self.preserved.update(self.SOLIDITY_KEYWORDS)
        self.preserved.update(self.BUILTINS)

        # Load additional preserved identifiers from privacy config
        privacy_config_path = self.config.get("privacy_config_path")
        if privacy_config_path and Path(privacy_config_path).exists():
            with open(privacy_config_path) as f:
                privacy_cfg = yaml.safe_load(f)
            masking_cfg = privacy_cfg.get("masking", {})
            self.preserved.update(masking_cfg.get("preserved_identifiers", []))
            self.preserved.update(masking_cfg.get("keywords", []))

        self.mask_prefix = self.config.get("mask_prefix", "prism_")

    def _should_mask(self, identifier: str) -> bool:
        """Determine if an identifier should be masked."""
        # Never mask keywords, builtins, or preserved names
        if identifier in self.preserved:
            return False
        # Never mask single-character identifiers (loop vars like i, j)
        if len(identifier) <= 1:
            return False
        # Never mask hexadecimal constants, numbers, or standard interface prefixes
        if identifier.startswith(("0x", "0X")) or identifier.isdigit():
            return False
        if identifier.startswith(("uint", "int", "bytes", "IERC", "ERC", "IUniswap", "IPair")):
            return False
        return True

    def mask_source(self, source_code: str) -> str:
        """
        Mask all user-defined identifiers in Solidity source code while protecting
        comments, NatSpec tags, and string literals from corruption.

        Args:
            source_code: Raw Solidity source code.

        Returns:
            Anonymized source code with identifiers replaced.
        """
        # Step 1: Protect comments and strings with placeholders
        placeholders: dict[str, str] = {}
        counter = 0

        def replace_with_placeholder(match: re.Match) -> str:
            nonlocal counter
            ph = f"__PRISM_PROTECTED_{counter}__"
            placeholders[ph] = match.group(0)
            counter += 1
            return ph

        # Pattern matching single-line comments, multi-line comments, and string literals
        protected_pattern = re.compile(
            r"(//[^\n]*)|(/\*[\s\S]*?\*/)|(\"(?:\\.|[^\"\\])*\")|(\'(?:\\.|[^\'\\])*\')"
        )
        code_without_literals = protected_pattern.sub(replace_with_placeholder, source_code)

        # Step 2: Extract maskable identifiers from the code body
        identifiers = set(self.IDENTIFIER_PATTERN.findall(code_without_literals))
        to_mask = {ident for ident in identifiers if self._should_mask(ident) and not ident.startswith("__PRISM_PROTECTED_")}

        # Sort by length (longest first) to avoid partial replacements
        sorted_identifiers = sorted(to_mask, key=len, reverse=True)

        # Generate mappings
        for ident in sorted_identifiers:
            self.mapping.add(ident, prefix=self.mask_prefix)

        # Replace identifiers in source code (using word boundaries)
        masked_code = code_without_literals
        for ident in sorted_identifiers:
            masked_name = self.mapping.get_masked(ident)
            if masked_name:
                pattern = re.compile(rf"\b{re.escape(ident)}\b")
                masked_code = pattern.sub(masked_name, masked_code)

        # Step 3: Restore protected comments and string literals
        for ph, orig_content in placeholders.items():
            masked_code = masked_code.replace(ph, orig_content)

        return masked_code

    def get_mapping(self) -> MaskMapping:
        """Return the current mapping object."""
        return self.mapping

    def save_mapping(self, path: Path) -> None:
        """Save the mapping to disk."""
        self.mapping.save(path)

    def load_mapping(self, path: Path) -> None:
        """Load a mapping from disk."""
        self.mapping = MaskMapping.load(path)
