"""
LLM Security Auditor — Queries LLM for semantic vulnerability analysis.

Supports multiple backends:
- Ollama (local, recommended)
- OpenAI API
- Anthropic API
- Mock mode (for testing without LLM)
"""

from __future__ import annotations

import json
import logging

from src.analysis.llm.prompt_engine import PromptEngine

logger = logging.getLogger(__name__)


class LLMAuditor:
    """Queries an LLM (local or API) for semantic vulnerability analysis."""

    def __init__(
        self,
        provider: str = "local",
        model: str = "deepseek-coder-v2:16b",
        base_url: str = "http://localhost:11434",
        api_key: str | None = None,
        allow_mock_fallback: bool = True,
    ):
        self.provider = provider
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.allow_mock_fallback = allow_mock_fallback
        self.prompt_engine = PromptEngine()

    def analyze(self, source_code: str, hotspots: list[dict] | None = None) -> list[dict]:
        """
        Analyze source code for vulnerabilities using LLM.

        Args:
            source_code: Masked Solidity source code.
            hotspots: Optional GNN hotspot results.

        Returns:
            List of vulnerability dicts.
        """
        system_prompt = self.prompt_engine.get_system_prompt("security_auditor")
        user_prompt = self.prompt_engine.render(
            "vulnerability_scan",
            source_code=source_code,
            hotspots=hotspots or [],
        )

        response = self._query(system_prompt, user_prompt)

        try:
            return json.loads(response) if isinstance(response, str) else response
        except json.JSONDecodeError:
            logger.warning("LLM response was not valid JSON, returning raw text")
            return [{"raw_response": response}]

    def generate_seeds(
        self, source_code: str, coverage_pct: float, uncovered_branches: list[dict], num_seeds: int = 5
    ) -> str:
        """Generate fuzzing seeds for uncovered branches."""
        system_prompt = self.prompt_engine.get_system_prompt("seed_generator")
        user_prompt = self.prompt_engine.render(
            "seed_mutation",
            source_code=source_code,
            coverage_pct=coverage_pct,
            uncovered_branches=uncovered_branches,
            num_seeds=num_seeds,
        )
        return self._query(system_prompt, user_prompt)

    def _query(self, system_prompt: str, user_prompt: str) -> str:
        """Send a query to the LLM backend."""
        dispatch = {
            "local": self._query_ollama,
            "openai": self._query_openai,
            "anthropic": self._query_anthropic,
            "mock": self._query_mock,
        }
        handler = dispatch.get(self.provider)
        if not handler:
            raise ValueError(f"Unknown provider: {self.provider}. Choose from: {list(dispatch.keys())}")
        return handler(system_prompt, user_prompt)

    def _query_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """Query local Ollama instance."""
        try:
            from src.analysis.llm.local_llm import LocalLLM

            llm = LocalLLM(model=self.model, base_url=self.base_url)
            response = llm.chat(user_prompt, system_prompt)
            return response.content
        except Exception as e:
            if self.allow_mock_fallback:
                logger.warning(f"Ollama query failed: {e}. Falling back to mock mode.")
                return self._query_mock(system_prompt, user_prompt)
            raise RuntimeError(f"Local LLM unavailable and mock fallback is disabled: {e}") from e

    def _query_openai(self, system_prompt: str, user_prompt: str) -> str:
        """Query OpenAI API."""
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI query failed: {e}")
            raise

    def _query_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        """Query Anthropic Claude API."""
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.model or "claude-sonnet-4-20250514",
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic query failed: {e}")
            raise

    def _query_mock(self, system_prompt: str, user_prompt: str) -> str:
        """Mock LLM for testing — returns rule-based analysis."""
        from src.analysis.llm.local_llm import MockLLM

        mock = MockLLM()
        response = mock.chat(user_prompt, system_prompt)
        return response.content
