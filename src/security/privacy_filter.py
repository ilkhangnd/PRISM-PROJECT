"""
Privacy Filter Module — Detects and redacts sensitive information in Solidity source code.

Handles: Ethereum addresses, private keys, API keys, RPC endpoints,
and sensitive comments before code is sent to external services.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RedactionRecord:
    """Records a single redaction for audit purposes."""

    pattern_name: str
    original_value: str
    replacement: str
    line_number: int
    start_pos: int
    end_pos: int


@dataclass
class FilterResult:
    """Result of applying the privacy filter to source code."""

    filtered_code: str
    redactions: list[RedactionRecord] = field(default_factory=list)
    total_redacted: int = 0

    @property
    def has_redactions(self) -> bool:
        return self.total_redacted > 0


class PrivacyFilter:
    """
    Detects and redacts sensitive patterns in Solidity source code.

    Configurable via `configs/privacy.yaml` with support for:
    - Ethereum addresses
    - Private keys
    - API keys
    - RPC endpoint URLs
    - Sensitive comments
    """

    # Default patterns (used if no config file provided)
    DEFAULT_PATTERNS = {
        "ethereum_address": {
            "pattern": r"0x[a-fA-F0-9]{40}",
            "replacement": "0x_REDACTED_ADDRESS_",
            "description": "Ethereum address",
        },
        "private_key": {
            "pattern": r"(?:0x)?[a-fA-F0-9]{64}",
            "replacement": "REDACTED_PRIVATE_KEY",
            "description": "Private key (64 hex chars)",
            "context_keywords": ["privateKey", "private_key", "secret", "PRIVATE"],
        },
        "api_key": {
            "pattern": r"(?:sk-|pk-|api_)[a-zA-Z0-9]{20,}",
            "replacement": "REDACTED_API_KEY",
            "description": "API key",
        },
        "rpc_endpoint": {
            "pattern": r"https://(?:mainnet|goerli|sepolia)\.(?:infura|alchemy)\.(?:io|com)/v[0-9]/[a-zA-Z0-9]+",
            "replacement": "REDACTED_RPC_ENDPOINT",
            "description": "RPC endpoint URL",
        },
        "sensitive_comment": {
            "pattern": r"//.*(?:password|secret|key|token|credential).*",
            "replacement": "// [REDACTED SENSITIVE COMMENT]",
            "description": "Comment containing sensitive keywords",
            "case_insensitive": True,
        },
    }

    def __init__(self, config_path: str | Path | None = None, sensitivity_level: str = "high"):
        """
        Initialize the privacy filter.

        Args:
            config_path: Path to privacy.yaml config file.
            sensitivity_level: One of 'low', 'medium', 'high'.
        """
        self.sensitivity_level = sensitivity_level
        self.patterns: dict[str, dict[str, Any]] = {}

        if config_path and Path(config_path).exists():
            self._load_config(Path(config_path))
        else:
            self.patterns = self.DEFAULT_PATTERNS.copy()

        # Compile regex patterns
        self._compiled: dict[str, re.Pattern] = {}
        for name, cfg in self.patterns.items():
            flags = re.IGNORECASE if cfg.get("case_insensitive", False) else 0
            self._compiled[name] = re.compile(cfg["pattern"], flags)

    def _load_config(self, path: Path) -> None:
        """Load patterns from a YAML configuration file."""
        with open(path) as f:
            config = yaml.safe_load(f)

        sensitive_patterns = config.get("sensitive_patterns", {})
        for name, cfg in sensitive_patterns.items():
            self.patterns[name] = {
                "pattern": cfg["pattern"],
                "replacement": cfg.get("replacement", f"[REDACTED_{name.upper()}]"),
                "description": cfg.get("description", name),
                "case_insensitive": cfg.get("case_insensitive", False),
                "context_keywords": cfg.get("context_keywords", []),
                "action": cfg.get("action", "replace"),
            }

    def filter(self, source_code: str) -> FilterResult:
        """
        Apply all privacy filters to the given source code.

        Args:
            source_code: Raw Solidity source code.

        Returns:
            FilterResult with filtered code and redaction records.
        """
        filtered = source_code
        redactions: list[RedactionRecord] = []
        source_code.split("\n")

        for pattern_name, compiled_pattern in self._compiled.items():
            cfg = self.patterns[pattern_name]
            context_keywords = cfg.get("context_keywords", [])

            for match in compiled_pattern.finditer(source_code):
                matched_text = match.group()

                # For patterns with context keywords, only redact if a keyword is nearby
                if context_keywords:
                    # Check surrounding context (100 chars before and after)
                    start = max(0, match.start() - 100)
                    end = min(len(source_code), match.end() + 100)
                    context = source_code[start:end]
                    if not any(kw in context for kw in context_keywords):
                        continue

                # Determine line number
                line_num = source_code[: match.start()].count("\n") + 1

                redactions.append(
                    RedactionRecord(
                        pattern_name=pattern_name,
                        original_value=matched_text,
                        replacement=cfg["replacement"],
                        line_number=line_num,
                        start_pos=match.start(),
                        end_pos=match.end(),
                    )
                )

            # Apply replacements
            replacement = cfg.get("replacement", f"[REDACTED_{pattern_name.upper()}]")
            action = cfg.get("action", "replace")

            if action == "remove":
                filtered = compiled_pattern.sub("", filtered)
            else:
                filtered = compiled_pattern.sub(replacement, filtered)

        return FilterResult(
            filtered_code=filtered,
            redactions=redactions,
            total_redacted=len(redactions),
        )

    def is_sensitive(self, text: str) -> bool:
        """Quick check if text contains any sensitive patterns."""
        for compiled_pattern in self._compiled.values():
            if compiled_pattern.search(text):
                return True
        return False
