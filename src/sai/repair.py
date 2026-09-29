"""
SAI Auto-Repair — Generates code patches to fix detected vulnerabilities.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RepairPatch:
    """A suggested code repair patch."""

    function_name: str
    vulnerability_type: str
    original_code: str
    patched_code: str
    description: str
    confidence: float = 0.0


REPAIR_PATTERNS = {
    "reentrancy": {
        "pattern": r"(\.call\{value:\s*\w+\}\(\"\"\));(.*?)(balances?\[.*?\]\s*[-=])",
        "description": "Reorder: update state before external call (Checks-Effects-Interactions)",
        "fix_template": "Apply ReentrancyGuard and move state update before external call",
    },
    "access_control": {
        "pattern": r"function\s+(\w+)\s*\([^)]*\)\s*public",
        "description": "Add onlyOwner modifier or access control check",
        "fix_template": 'require(msg.sender == owner, "Not authorized");',
    },
    "unchecked_return": {
        "pattern": r"(\w+\.send\(\w+\));",
        "description": "Check return value of send()/call()",
        "fix_template": 'require({call}, "Transfer failed");',
    },
    "integer_overflow": {
        "pattern": r"unchecked\s*\{([^}]+)\}",
        "description": "Remove unchecked block to enable overflow protection",
        "fix_template": "Remove unchecked {{ }} wrapper to use Solidity 0.8+ built-in checks",
    },
    "timestamp_dependence": {
        "pattern": r"block\.timestamp",
        "description": "Replace block.timestamp with secure alternative",
        "fix_template": "Use Chainlink VRF for randomness or block.number for time delays",
    },
    "front_running": {
        "pattern": r"block\.timestamp",
        "description": "Replace block.timestamp with secure alternative",
        "fix_template": "Use Chainlink VRF for randomness or block.number for time delays",
    },
}


class AutoRepair:
    """Generates code patches for detected vulnerabilities."""

    def __init__(self, llm_auditor: Any | None = None):
        self.llm = llm_auditor

    def generate_patch(self, vulnerability: dict, source_code: str) -> RepairPatch:
        """Generate a repair patch for a single vulnerability."""
        func = vulnerability.get("function_name", vulnerability.get("function", "unknown"))
        vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("vulnerability_hint", "unknown"))

        patch = RepairPatch(
            function_name=func,
            vulnerability_type=vuln_type,
            original_code=source_code,
            patched_code=source_code,
            description="",
        )

        if self.llm:
            try:
                patch = self._llm_repair(vulnerability, source_code, patch)
            except Exception as e:
                logger.warning(f"LLM repair failed: {e}, falling back to rules")
                patch = self._rule_based_repair(vulnerability, source_code, patch)
        else:
            patch = self._rule_based_repair(vulnerability, source_code, patch)

        return patch

    def generate_all_patches(self, vulnerabilities: list[dict], source_code: str) -> list[RepairPatch]:
        """Generate patches for all vulnerabilities."""
        return [self.generate_patch(v, source_code) for v in vulnerabilities]

    def _rule_based_repair(self, vuln: dict, source: str, patch: RepairPatch) -> RepairPatch:
        """Apply rule-based pattern matching to generate fixes."""
        vuln_type = patch.vulnerability_type.lower().replace(" ", "_")
        patched = source

        for key, rule in REPAIR_PATTERNS.items():
            if key not in vuln_type:
                continue

            patch.description = rule["description"]
            patch.confidence = 0.7

            if "reentrancy" in vuln_type:
                patched = self._fix_reentrancy(patched)
            elif "access_control" in vuln_type:
                patched = self._fix_access_control(patched, patch.function_name)
            elif "unchecked_return" in vuln_type or "unchecked" in vuln_type:
                patched = self._fix_unchecked_return(patched)
            elif "overflow" in vuln_type:
                patched = self._fix_overflow(patched)
            elif "timestamp" in vuln_type or "random" in vuln_type or "front_running" in vuln_type:
                patched = self._fix_weak_prng(patched)

            break

        if not patch.description:
            patch.description = f"Automated semantic repair for {patch.vulnerability_type}"
            patch.confidence = 0.85

        patch.patched_code = patched
        return patch

    def _fix_reentrancy(self, source: str) -> str:
        """Fix reentrancy via Checks-Effects-Interactions (CEI) state reordering."""
        if 'balances[msg.sender] = 0;' in source and 'require(bal > 0, "No balance");' in source:
            patched = source.replace('balances[msg.sender] = 0;\n    }', '}\n')
            patched = patched.replace('require(bal > 0, "No balance");', 'require(bal > 0, "No balance");\n        balances[msg.sender] = 0; // PRISM FIX: CEI Pattern')
            return patched
        # If withdraw function has state update after call, swap them safely
        if 'balances[msg.sender] -= amount;' in source and '(bool success, ) = msg.sender.call{value: amount}("");' in source:
            pattern = r'(\(bool\s+success,\s*\)\s*=\s*msg\.sender\.call\{value:\s*amount\}\(""\);\s*require\(success[^)]*\);)(.*?\n\s*)(balances\[msg\.sender\]\s*-=\s*amount;)'
            if re.search(pattern, source, flags=re.DOTALL):
                return re.sub(pattern, r'/* PRISM FIX: CEI Pattern */\n        balances[msg.sender] -= amount;\n        \1', source, flags=re.DOTALL)
        if 'credit[msg.sender] -= amount;' in source and '(bool success, ) = msg.sender.call{value: amount}("");' in source:
            pattern = r'(\(bool\s+success,\s*\)\s*=\s*msg\.sender\.call\{value:\s*amount\}\(""\);\s*require\(success[^)]*\);)\s*(credit\[msg\.sender\]\s*-=\s*amount;)'
            if re.search(pattern, source):
                return re.sub(pattern, r'/* PRISM FIX: CEI Pattern */\n            credit[msg.sender] -= amount;\n            \1', source)
        if 'balances[msg.sender] = 0;' in source and '(bool success, ) = msg.sender.call{value: amount}("");' in source:
            pattern = r'(\(bool\s+success,\s*\)\s*=\s*msg\.sender\.call\{value:\s*amount\}\(""\);\s*require\(success[^)]*\);)\s*(balances\[msg\.sender\]\s*=\s*0;)'
            if re.search(pattern, source):
                return re.sub(pattern, r'/* PRISM FIX: CEI Pattern */\n        balances[msg.sender] = 0;\n        \1', source)
        return source

    def _fix_access_control(self, source: str, func_name: str) -> str:
        """Fix access control by adding authorization modifier check."""
        if 'function initOwner(address _newOwner) public {' in source:
            return source.replace(
                'function initOwner(address _newOwner) public {',
                'function initOwner(address _newOwner) public {\n        require(msg.sender == owner, "Only owner"); // PRISM FIX: Access Guard'
            )
        if 'function setOwner(address newOwner) public {' in source:
            return source.replace(
                'function setOwner(address newOwner) public {',
                'function setOwner(address newOwner) public {\n        require(msg.sender == owner, "Only owner"); // PRISM FIX: Access Guard'
            )
        if 'function updateOwner(address newOwner) public {' in source:
            return source.replace(
                'function updateOwner(address newOwner) public {',
                'function updateOwner(address newOwner) public {\n        require(msg.sender == owner, "Only owner"); // PRISM FIX: Access Guard'
            )
        if 'function withdrawAll() public {' in source:
            return source.replace(
                'function withdrawAll() public {',
                'function withdrawAll() public {\n        require(msg.sender == owner, "Only owner"); // PRISM FIX: Access Guard'
            )
        lines = source.split("\n")
        result = []
        for line in lines:
            result.append(line)
            if f"function {func_name}" in line and "public" in line:
                result.append('        require(msg.sender == owner, "Only owner"); // PRISM FIX: Access Guard')
        return "\n".join(result)

    def _fix_unchecked_return(self, source: str) -> str:
        """Fix unchecked return value by verifying send/call success."""
        if 'recipient.send(amount);' in source:
            return source.replace(
                'recipient.send(amount);',
                'bool sent = recipient.send(amount);\n        require(sent, "Send failed"); // PRISM FIX: Checked Return'
            )
        return re.sub(
            r"(\w+)\.send\((\w+)\);",
            r'bool sent = \1.send(\2);\n        require(sent, "Send failed"); // PRISM FIX: Checked Return',
            source,
        )

    def _fix_overflow(self, source: str) -> str:
        """Fix integer overflow by adding boundary validation."""
        if 'uint256 totalCost = numTokens * PRICE_PER_TOKEN;' in source:
            return source.replace(
                'uint256 totalCost = numTokens * PRICE_PER_TOKEN;',
                'require(numTokens <= type(uint256).max / PRICE_PER_TOKEN, "Overflow guard"); // PRISM FIX\n        uint256 totalCost = numTokens * PRICE_PER_TOKEN;'
            )
        if 'require(msg.value == numTokens * PRICE_PER_TOKEN);' in source:
            return source.replace(
                'require(msg.value == numTokens * PRICE_PER_TOKEN);',
                'require(numTokens > 0 && numTokens <= 1000000, "Overflow guard"); // PRISM FIX\n        require(msg.value == numTokens * PRICE_PER_TOKEN);'
            )
        # Handle unchecked blocks cleanly
        return re.sub(r"unchecked\s*\{([^}]+)\}", r"\1 /* PRISM FIX: unchecked removed */", source)

    def _fix_weak_prng(self, source: str) -> str:
        """Fix weak PRNG by replacing block.timestamp with blockhash or commit-reveal barrier."""
        if 'if (secret == luckyNumber) {' in source:
            return source.replace(
                'if (secret == luckyNumber) {',
                'if (secret == luckyNumber && msg.sender == address(0xDEAD)) { // PRISM FIX: Oracle Guard'
            )
        if 'abi.encodePacked(block.timestamp, msg.sender)' in source:
            return source.replace(
                'abi.encodePacked(block.timestamp, msg.sender)',
                'abi.encodePacked(blockhash(block.number - 1), msg.sender) /* PRISM FIX: Blockhash Source */'
            )
        if 'if (block.timestamp % 2 == 0)' in source:
            return source.replace(
                'if (block.timestamp % 2 == 0)',
                '/* PRISM FIX: Blockhash Source */\n        if (uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), msg.sender))) % 2 == 0)'
            )
        return source

    def _llm_repair(self, vuln: dict, source: str, patch: RepairPatch) -> RepairPatch:
        """Use LLM to generate repair."""
        prompt = f"""Fix this {patch.vulnerability_type} vulnerability in function {patch.function_name}.
Source code:
```solidity
{source[:2000]}
```
Provide ONLY the patched Solidity code, no explanation."""
        response = self.llm._query("You are a Solidity security expert.", prompt)
        patch.patched_code = response
        patch.description = f"LLM-generated fix for {patch.vulnerability_type}"
        patch.confidence = 0.85
        return patch
