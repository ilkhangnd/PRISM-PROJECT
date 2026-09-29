"""
Prompt Engine — Jinja2-based prompt template management for LLM interactions.

Manages system prompts, analysis templates, and dynamic prompt rendering
for all LLM-powered components in PRISM (auditor, seed generator, explainer).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from jinja2 import BaseLoader, Environment

logger = logging.getLogger(__name__)


# Default prompts (fallback when config file not found)
DEFAULT_SYSTEM_PROMPTS = {
    "security_auditor": (
        "You are a senior smart contract security auditor with extensive experience in "
        "Ethereum/EVM-based protocols. Your task is to analyze Solidity smart contracts "
        "for security vulnerabilities.\n\n"
        "IMPORTANT RULES:\n"
        "1. Analyze ONLY the code provided. Do not assume external context.\n"
        "2. For each vulnerability found, provide:\n"
        "   - Vulnerability type (from SWC Registry)\n"
        "   - Severity: Critical / High / Medium / Low / Informational\n"
        "   - Affected function and line numbers\n"
        "   - Detailed description of the attack vector\n"
        "   - Proof-of-concept exploit scenario\n"
        "   - Recommended fix with code snippet\n"
        "3. If identifiers appear anonymized (e.g., func_a3x9), focus on the logic flow.\n"
        "4. Respond ONLY in valid JSON format."
    ),
    "security_auditor_compact": (
        "Audit only the supplied Solidity. Return only a valid JSON array, never Markdown. "
        "Emit at most three objects with exactly these keys: vulnerability_type, function_name, evidence. "
        "Use one of: reentrancy, integer_overflow, access_control, unchecked_return, timestamp_dependence. "
        "If no supported issue is present, return []. Keep each evidence field under 20 words."
    ),
    "seed_generator": (
        "You are a smart contract fuzzing expert. Your task is to generate test inputs "
        "(seeds) that will maximize code coverage in the target contract.\n\n"
        "Given:\n"
        "- The source code of the contract (may be partially anonymized)\n"
        "- Current code coverage report showing uncovered branches\n"
        "- GNN-identified hotspot functions with risk scores\n\n"
        "Generate Solidity test functions that:\n"
        "1. Target uncovered branches, especially those involving require/assert guards\n"
        "2. Use boundary values, edge cases, and type-specific extremes\n"
        "3. Chain multiple function calls to reach deep states\n"
        "4. Include both valid and malicious input patterns\n\n"
        "Output format: Valid Solidity test functions compatible with Foundry's forge test."
    ),
    "cot_explainer": (
        "You are a security researcher explaining a smart contract vulnerability.\n"
        "Use Chain-of-Thought reasoning to walk through the vulnerability step by step.\n\n"
        "For each vulnerability:\n"
        "1. **Context**: What does the affected code do?\n"
        "2. **Vulnerability**: What is the security flaw?\n"
        "3. **Attack Path**: Step-by-step, how would an attacker exploit this?\n"
        "4. **Impact**: What is the worst-case outcome?\n"
        "5. **Fix**: What is the recommended remediation?\n\n"
        "Be precise, technical, and reference specific code constructs."
    ),
}

DEFAULT_TEMPLATES = {
    "vulnerability_scan": (
        "Analyze the following Solidity smart contract for security vulnerabilities.\n\n"
        "```solidity\n{{ source_code }}\n```\n\n"
        "{% if hotspots %}\n"
        "The following functions have been flagged as high-risk by our structural analysis:\n"
        "{% for h in hotspots %}\n"
        "- {{ h.function_name }}: Risk Score {{ h.risk_score }} ({{ h.vulnerability_hint }})\n"
        "{% endfor %}\n"
        "{% endif %}\n\n"
        "Respond with a JSON array of vulnerabilities found. Each object should have: "
        "vulnerability_type, severity, function_name, description, recommendation."
    ),
    "vulnerability_scan_compact": (
        "Audit this Solidity code only for reentrancy, integer overflow, access control, unchecked return, "
        "or timestamp dependence.\n\n```solidity\n{{ source_code }}\n```\n\n"
        "{% if hotspots %}GNN candidates (hints are not ground truth):\n"
        "{% for h in hotspots %}- {{ h.function_name }} ({{ h.vulnerability_hint }})\n{% endfor %}{% endif %}\n"
        "Return only a JSON array with at most three objects; each object has exactly "
        "vulnerability_type, function_name, evidence. Return [] if none."
    ),
    "seed_mutation": (
        "The following smart contract has uncovered code branches that need fuzzing:\n\n"
        "```solidity\n{{ source_code }}\n```\n\n"
        "Current coverage: {{ coverage_pct }}%\n\n"
        "Uncovered branches:\n"
        "{% for branch in uncovered_branches %}\n"
        "- Function: {{ branch.function }} {% if branch.condition %}| Condition: {{ branch.condition }}{% endif %}\n"
        "{% endfor %}\n\n"
        "Generate {{ num_seeds }} Foundry test functions to cover these branches.\n"
        "Focus on edge cases: zero values, max uint256, address(0), reentrancy patterns."
    ),
    "repair_suggestion": (
        "A vulnerability has been detected in the following code:\n\n"
        "```solidity\n{{ vulnerable_code }}\n```\n\n"
        "Vulnerability: {{ vuln_type }} ({{ severity }})\n"
        "Description: {{ description }}\n\n"
        "Suggest a fix following Solidity security best practices and OpenZeppelin patterns.\n"
        "Provide the corrected code snippet."
    ),
    "hotspot_analysis": (
        "Our GNN model has identified the following hotspot functions with high risk scores:\n\n"
        "{% for h in hotspots %}\n"
        "### {{ h.function_name }} (Risk: {{ h.risk_score }})\n"
        "- Predicted vulnerability: {{ h.vulnerability_hint }}\n"
        "- Contract: {{ h.contract_name }}\n"
        "{% endfor %}\n\n"
        "Source code:\n```solidity\n{{ source_code }}\n```\n\n"
        "For each hotspot, analyze whether the GNN's prediction is correct. "
        "If so, describe the vulnerability in detail. If not, explain why it may be a false positive."
    ),
}


class PromptEngine:
    """
    Manages Jinja2-based LLM prompt templates.

    Loads templates from YAML config file, with built-in defaults as fallback.
    Supports dynamic rendering with variable substitution.
    """

    def __init__(self, config_path: str | Path = "configs/llm_prompts.yaml"):
        self.config_path = Path(config_path)
        self.templates: dict[str, str] = dict(DEFAULT_TEMPLATES)
        self.system_prompts: dict[str, str] = dict(DEFAULT_SYSTEM_PROMPTS)
        self._jinja_env = Environment(loader=BaseLoader())

        # Override with config file if present
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    config = yaml.safe_load(f) or {}
                self.system_prompts.update(config.get("system_prompts", {}))
                self.templates.update(config.get("analysis_templates", {}))
                logger.debug(f"Loaded {len(self.templates)} templates from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to load prompts config: {e}, using defaults")

    def render(self, template_name: str, **kwargs: Any) -> str:
        """Render a prompt template with given variables."""
        raw = self.templates.get(template_name)
        if not raw:
            raise ValueError(f"Template '{template_name}' not found. Available: {list(self.templates.keys())}")

        try:
            template = self._jinja_env.from_string(raw)
            return template.render(**kwargs)
        except Exception as e:
            logger.error(f"Template rendering failed for '{template_name}': {e}")
            # Fallback: simple string format
            return raw

    def get_system_prompt(self, role: str) -> str:
        """Get the system prompt for a given role."""
        prompt = self.system_prompts.get(role, "")
        if not prompt:
            logger.warning(f"No system prompt found for role '{role}'")
        return prompt

    def add_template(self, name: str, template: str) -> None:
        """Register a custom template at runtime."""
        self.templates[name] = template

    def list_templates(self) -> list[str]:
        """List all available template names."""
        return list(self.templates.keys())

    def list_roles(self) -> list[str]:
        """List all available system prompt roles."""
        return list(self.system_prompts.keys())
