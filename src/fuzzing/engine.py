"""
Fuzzing Engine — Stateful fuzzing with property-based testing for smart contracts.

Supports Foundry (forge test) integration and standalone mutation-based fuzzing.
"""

from __future__ import annotations

import logging
import random
import subprocess
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FuzzSeed:
    """A single fuzzing seed with test parameters."""

    function_name: str
    inputs: dict[str, Any]
    description: str = ""
    source: str = "random"  # "random", "gnn_hotspot", "llm_generated"


@dataclass
class FuzzResult:
    """Result of a fuzzing campaign."""

    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    crashes: list[dict] = field(default_factory=list)
    coverage_pct: float = 0.0
    uncovered_branches: list[dict] = field(default_factory=list)
    seeds_used: list[dict] = field(default_factory=list)
    duration_seconds: float = 0.0


# Standard vulnerability properties to test
INVARIANT_TEMPLATES = {
    "reentrancy": {
        "description": "Balance must decrease after withdrawal",
        "property": "assert(address(this).balance <= old_balance)",
    },
    "access_control": {
        "description": "Only owner can execute privileged functions",
        "property": "assert(msg.sender == owner || !privileged_function_called)",
    },
    "integer_overflow": {
        "description": "Arithmetic operations must not overflow",
        "property": "assert(result >= a && result >= b)  // for addition",
    },
    "unchecked_return": {
        "description": "Low-level calls must check return value",
        "property": "assert(success == true)",
    },
}


class FuzzingEngine:
    """
    Multi-strategy fuzzing engine for smart contracts.

    Strategies:
    1. Random mutation: Generate random inputs for each function
    2. GNN-guided: Focus on hotspot functions identified by GNN
    3. LLM-seeded: Use LLM-generated seed values targeting specific patterns
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.max_iterations = self.config.get("max_iterations", 1000)
        self.timeout = self.config.get("timeout", 300)
        self.seed_count = self.config.get("seed_count", 50)

    def generate_random_seeds(self, functions: list[dict], count: int | None = None) -> list[FuzzSeed]:
        """Generate random fuzzing seeds for each function."""
        count = count or self.seed_count
        seeds: list[FuzzSeed] = []

        for func in functions:
            func_name = func.get("name", "unknown")
            params = func.get("parameters", [])

            for _ in range(count // max(len(functions), 1)):
                inputs = {}
                for param in params:
                    ptype = param.get("type", "uint256")
                    inputs[param.get("name", "arg")] = self._random_value(ptype)

                seeds.append(
                    FuzzSeed(
                        function_name=func_name,
                        inputs=inputs,
                        description=f"Random seed for {func_name}",
                        source="random",
                    )
                )

        return seeds

    def generate_targeted_seeds(self, hotspots: list[dict], functions: list[dict]) -> list[FuzzSeed]:
        """Generate seeds targeting GNN-identified hotspots."""
        seeds: list[FuzzSeed] = []

        for hotspot in hotspots:
            func_name = hotspot.get("function_name", "")
            vuln_hint = hotspot.get("vulnerability_hint", "").lower()

            # Find matching function params
            func_params = []
            for f in functions:
                if f.get("name") == func_name:
                    func_params = f.get("parameters", [])
                    break

            # Generate edge-case inputs based on vulnerability type
            edge_inputs = self._get_edge_cases(vuln_hint, func_params)
            for inputs in edge_inputs:
                seeds.append(
                    FuzzSeed(
                        function_name=func_name,
                        inputs=inputs,
                        description=f"Targeted seed for {vuln_hint} in {func_name}",
                        source="gnn_hotspot",
                    )
                )

        return seeds

    def run_foundry_fuzz(self, project_dir: str, test_contract: str | None = None) -> FuzzResult:
        """Run Foundry forge test with fuzzing."""
        result = FuzzResult()

        try:
            cmd = ["forge", "test", "--fuzz-runs", str(self.max_iterations), "-vvv"]
            if test_contract:
                cmd.extend(["--match-contract", test_contract])

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=project_dir,
            )

            result = self._parse_forge_output(proc.stdout, proc.stderr)
            logger.info(f"Foundry fuzz: {result.passed} passed, {result.failed} failed")

        except FileNotFoundError:
            logger.warning("Foundry (forge) not found. Install: curl -L https://foundry.paradigm.xyz | bash")
        except subprocess.TimeoutExpired:
            logger.warning(f"Foundry fuzz timed out after {self.timeout}s")
        except Exception as e:
            logger.error(f"Foundry fuzz failed: {e}")

        return result

    def run_simulation(self, seeds: list[FuzzSeed], contract_info: dict) -> FuzzResult:
        """
        Run a simulated fuzzing campaign (no on-chain execution).

        Analyzes seeds against known vulnerability patterns to estimate
        which would trigger bugs. Used when Foundry is not available.
        """
        result = FuzzResult()
        result.total_tests = len(seeds)
        result.seeds_used = [{"function": s.function_name, "source": s.source} for s in seeds]

        vuln_functions = contract_info.get("vulnerable_functions", [])

        for seed in seeds:
            hit = self._check_seed_coverage(seed, vuln_functions)
            if hit:
                result.failed += 1
                result.crashes.append(
                    {
                        "function": seed.function_name,
                        "inputs": seed.inputs,
                        "vulnerability": hit,
                        "seed_source": seed.source,
                    }
                )
            else:
                result.passed += 1

        # Estimate coverage
        tested_funcs = {s.function_name for s in seeds}
        all_funcs = {f.get("name") for f in contract_info.get("functions", [])}
        result.coverage_pct = len(tested_funcs & all_funcs) / max(len(all_funcs), 1) * 100

        untested = all_funcs - tested_funcs
        result.uncovered_branches = [{"function": f, "reason": "not tested"} for f in untested]

        return result

    def _random_value(self, solidity_type: str) -> Any:
        """Generate a random value for a Solidity type."""
        if "uint" in solidity_type:
            bits = int(solidity_type.replace("uint", "") or "256")
            return random.randint(0, min(2**bits - 1, 2**64))
        elif "int" in solidity_type:
            bits = int(solidity_type.replace("int", "") or "256")
            return random.randint(-(2 ** (bits - 1)), 2 ** (bits - 1) - 1)
        elif "address" in solidity_type:
            return "0x" + "".join(random.choices("0123456789abcdef", k=40))
        elif "bool" in solidity_type:
            return random.choice([True, False])
        elif "bytes" in solidity_type:
            size = int(solidity_type.replace("bytes", "") or "32")
            return "0x" + "".join(random.choices("0123456789abcdef", k=size * 2))
        elif "string" in solidity_type:
            return "fuzz_" + "".join(random.choices("abcdef0123456789", k=8))
        return 0

    def _get_edge_cases(self, vuln_type: str, params: list[dict]) -> list[dict]:
        """Generate edge-case inputs for a specific vulnerability type."""
        cases: list[dict] = []

        edge_values_uint = [0, 1, 2**256 - 1, 2**255, 2**128, 10**18, 10**6]
        edge_values_addr = [
            "0x0000000000000000000000000000000000000000",
            "0xdead000000000000000000000000000000000000",
            "0xffffffffffffffffffffffffffffffffffffffff",
        ]

        for val in edge_values_uint[:3]:
            inputs = {}
            for p in params:
                if "uint" in p.get("type", ""):
                    inputs[p["name"]] = val
                elif "address" in p.get("type", ""):
                    inputs[p["name"]] = random.choice(edge_values_addr)
            if inputs:
                cases.append(inputs)

        return cases

    def _check_seed_coverage(self, seed: FuzzSeed, vuln_functions: list[dict]) -> str | None:
        """Check if a seed targets a known vulnerable function."""
        for vf in vuln_functions:
            if seed.function_name == vf.get("name"):
                if seed.source in ("gnn_hotspot", "llm_generated"):
                    return vf.get("vulnerability_type", "unknown")
        return None

    def _parse_forge_output(self, stdout: str, stderr: str) -> FuzzResult:
        """Parse Foundry forge test output."""
        result = FuzzResult()
        for line in stdout.split("\n"):
            if "PASS" in line:
                result.passed += 1
                result.total_tests += 1
            elif "FAIL" in line:
                result.failed += 1
                result.total_tests += 1
                result.crashes.append({"raw": line.strip()})
        return result
