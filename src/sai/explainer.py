"""
SAI Explainer — Chain-of-Thought vulnerability explanation using LLM.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

COT_TEMPLATE = (
    "You are a smart contract security expert. Analyze this vulnerability using Chain-of-Thought reasoning.\n\n"
    "## Vulnerability Report\n"
    "- **Function:** {function_name}\n"
    "- **Type:** {vulnerability_type}\n"
    "- **Risk Score:** {risk_score}\n"
    "- **Detected by:** {detection_source}\n\n"
    "## Source Code (masked)\n"
    "```solidity\n"
    "{source_code}\n"
    "```\n\n"
    "## Instructions\n"
    "Provide a structured analysis following these steps:\n"
    "1. **Root Cause**: Explain exactly why this code is vulnerable\n"
    "2. **Attack Vector**: Describe step-by-step how an attacker could exploit this\n"
    "3. **Impact**: What damage could this vulnerability cause?\n"
    "4. **Proof of Concept**: Outline a minimal attack scenario\n"
    "5. **Remediation**: Specific code changes to fix this vulnerability\n\n"
    "Respond in JSON format:\n"
    '{{"root_cause": "...", "attack_vector": ["step1", "step2", ...], '
    '"impact": "...", "severity": "critical|high|medium|low", '
    '"proof_of_concept": "...", "remediation": "..."}}'
)


@dataclass
class Explanation:
    """Structured vulnerability explanation."""

    function_name: str
    vulnerability_type: str
    risk_score: float
    root_cause: str = ""
    attack_vector: list[str] = field(default_factory=list)
    impact: str = ""
    severity: str = "medium"
    proof_of_concept: str = ""
    remediation: str = ""
    detection_source: str = ""
    raw_response: str = ""


class CoTExplainer:
    """Generates Chain-of-Thought explanations for detected vulnerabilities."""

    def __init__(self, llm_auditor: Any | None = None):
        self.llm = llm_auditor

    def explain(self, vulnerability: dict, source_code: str) -> Explanation:
        """Generate CoT explanation for a single vulnerability."""
        func = vulnerability.get("function_name", vulnerability.get("function", "unknown"))
        vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("vulnerability_hint", "unknown"))
        risk = vulnerability.get("risk_score", vulnerability.get("confidence", 0.5))
        source = vulnerability.get("detection_source", "GNN+LLM")

        explanation = Explanation(
            function_name=func,
            vulnerability_type=vuln_type,
            risk_score=float(risk),
            detection_source=source,
        )

        if self.llm:
            try:
                prompt = COT_TEMPLATE.format(
                    function_name=func,
                    vulnerability_type=vuln_type,
                    risk_score=risk,
                    detection_source=source,
                    source_code=source_code,
                )
                response = self.llm._query(
                    self.llm.prompt_engine.get_system_prompt("cot_explainer") or "You are a security expert.",
                    prompt,
                )
                explanation.raw_response = response
                explanation = self._parse_response(response, explanation)
            except Exception as e:
                logger.warning(f"LLM explanation failed for {func}: {e}")
                explanation = self._generate_rule_based(explanation, source_code)
        else:
            explanation = self._generate_rule_based(explanation, source_code)

        return explanation

    def explain_all(self, vulnerabilities: list[dict], source_code: str) -> list[Explanation]:
        """Generate explanations for all vulnerabilities."""
        explanations = []
        for vuln in vulnerabilities:
            exp = self.explain(vuln, source_code)
            explanations.append(exp)
        return explanations

    def _parse_response(self, response: str, explanation: Explanation) -> Explanation:
        """Parse LLM JSON response into Explanation."""
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(response[start:end])
                explanation.root_cause = data.get("root_cause", "")
                explanation.attack_vector = data.get("attack_vector", [])
                explanation.impact = data.get("impact", "")
                explanation.severity = data.get("severity", "medium")
                explanation.proof_of_concept = data.get("proof_of_concept", "")
                explanation.remediation = data.get("remediation", "")
        except (json.JSONDecodeError, ValueError):
            explanation.root_cause = response[:500]
        return explanation

    def _generate_rule_based(self, explanation: Explanation, source_code: str) -> Explanation:
        """Generate rule-based explanation when LLM is unavailable."""
        rules = {
            "reentrancy": {
                "root_cause": (
                    "External call is made before state variables are updated (Checks-Effects-Interactions violation)"
                ),
                "attack_vector": [
                    "Deploy attacker contract with fallback/receive",
                    "Call vulnerable withdraw",
                    "Re-enter during callback before balance update",
                    "Drain contract funds",
                ],
                "impact": "Complete fund drainage from the contract",
                "severity": "critical",
                "remediation": "Move state updates before external calls; use ReentrancyGuard from OpenZeppelin",
            },
            "access_control": {
                "root_cause": "Missing or insufficient authorization checks on privileged functions",
                "attack_vector": [
                    "Identify unprotected function",
                    "Call directly from attacker address",
                    "Execute privileged operation",
                ],
                "impact": "Unauthorized access to admin functions, fund theft, or contract takeover",
                "severity": "high",
                "remediation": "Add onlyOwner modifier or role-based access control (OpenZeppelin AccessControl)",
            },
            "integer_overflow": {
                "root_cause": "Arithmetic operation in unchecked block can overflow/underflow without revert",
                "attack_vector": [
                    "Identify unchecked arithmetic",
                    "Provide inputs causing overflow",
                    "Exploit incorrect calculation",
                ],
                "impact": "Token minting, balance manipulation, or logic bypass",
                "severity": "high",
                "remediation": "Remove unchecked block or add explicit bounds checking; use SafeMath for Solidity <0.8",
            },
            "unchecked_return": {
                "root_cause": "Return value of low-level call (send/call) is not checked",
                "attack_vector": [
                    "Cause the low-level call to fail",
                    "Contract assumes success",
                    "State becomes inconsistent",
                ],
                "impact": "Funds locked in contract, inconsistent state, denial of service",
                "severity": "medium",
                "remediation": (
                    "Always check return values: require(success, 'Transfer failed'); or use Address.sendValue()"
                ),
            },
            "timestamp_dependence": {
                "root_cause": "Contract uses block.timestamp for critical logic (randomness, time locks)",
                "attack_vector": [
                    "Miner manipulates block.timestamp within allowed range",
                    "Predict or influence outcome",
                    "Front-run or selectively mine",
                ],
                "impact": "Predictable randomness, bypass of time-based locks",
                "severity": "medium",
                "remediation": "Use Chainlink VRF for randomness; use block.number instead of timestamp for delays",
            },
        }

        vuln = explanation.vulnerability_type.lower().replace(" ", "_").replace("-", "_")
        for key, rule in rules.items():
            if key in vuln:
                explanation.root_cause = rule["root_cause"]
                explanation.attack_vector = rule["attack_vector"]
                explanation.impact = rule["impact"]
                explanation.severity = rule["severity"]
                explanation.remediation = rule["remediation"]
                explanation.proof_of_concept = f"See SWC Registry for {key} examples"
                return explanation

        explanation.root_cause = f"Potential {explanation.vulnerability_type} vulnerability detected"
        explanation.severity = "medium"
        return explanation
