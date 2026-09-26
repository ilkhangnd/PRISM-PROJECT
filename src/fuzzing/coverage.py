"""
Coverage Tracker — Parse and track code coverage from fuzzing campaigns.

Supports:
- Foundry (forge coverage)
- Solidity instruction-level coverage estimation
- Branch coverage analysis for feedback loop
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BranchInfo:
    """Information about a single code branch."""

    function_name: str
    line_number: int = 0
    condition: str = ""
    branch_type: str = ""  # if | require | assert | while | for
    covered: bool = False
    hit_count: int = 0


@dataclass
class FunctionCoverage:
    """Coverage information for a single function."""

    name: str
    total_branches: int = 0
    covered_branches: int = 0
    total_lines: int = 0
    covered_lines: int = 0
    coverage_pct: float = 0.0
    uncovered_branches: list[BranchInfo] = field(default_factory=list)


@dataclass
class CoverageReport:
    """Aggregated coverage report for a contract."""

    contract_name: str = ""
    total_functions: int = 0
    covered_functions: int = 0
    total_branches: int = 0
    covered_branches: int = 0
    total_lines: int = 0
    covered_lines: int = 0
    overall_coverage_pct: float = 0.0
    function_coverage: list[FunctionCoverage] = field(default_factory=list)
    uncovered_branches: list[BranchInfo] = field(default_factory=list)

    def get_uncovered_functions(self) -> list[str]:
        """Get list of function names with < 100% coverage."""
        return [fc.name for fc in self.function_coverage if fc.coverage_pct < 100.0]

    def get_coverage_gaps(self) -> list[dict]:
        """Get all uncovered branches as dicts (for feedback loop)."""
        gaps = []
        for fc in self.function_coverage:
            for branch in fc.uncovered_branches:
                gaps.append(
                    {
                        "function": fc.name,
                        "line": branch.line_number,
                        "condition": branch.condition,
                        "type": branch.branch_type,
                    }
                )
        return gaps


class CoverageTracker:
    """
    Tracks and analyzes code coverage across fuzzing iterations.

    Provides coverage deltas between iterations for the feedback loop.
    """

    def __init__(self):
        self._history: list[CoverageReport] = []

    @property
    def current_coverage(self) -> float:
        """Get the latest overall coverage percentage."""
        if self._history:
            return self._history[-1].overall_coverage_pct
        return 0.0

    @property
    def coverage_delta(self) -> float:
        """Get coverage improvement since last measurement."""
        if len(self._history) >= 2:
            return self._history[-1].overall_coverage_pct - self._history[-2].overall_coverage_pct
        return self.current_coverage

    def analyze_source(self, source_code: str, tested_functions: set[str] | None = None) -> CoverageReport:
        """
        Analyze source code to estimate coverage based on tested functions.

        This is the primary coverage method when Foundry is not available.
        Performs static analysis to identify branches and estimate coverage.
        """
        report = CoverageReport()
        tested = tested_functions or set()

        functions = self._extract_functions(source_code)
        report.total_functions = len(functions)

        for func_name, func_body in functions.items():
            fc = FunctionCoverage(name=func_name)
            branches = self._extract_branches(func_name, func_body)
            fc.total_branches = len(branches)

            # Count lines
            lines = [line for line in func_body.split("\n") if line.strip() and not line.strip().startswith("//")]
            fc.total_lines = len(lines)
            report.total_lines += fc.total_lines

            if func_name in tested:
                report.covered_functions += 1
                # Estimate: tested function has ~70% branch coverage
                fc.covered_branches = int(fc.total_branches * 0.7)
                fc.covered_lines = int(fc.total_lines * 0.8)
                fc.coverage_pct = 70.0 if fc.total_branches > 0 else 100.0

                # Mark some branches as uncovered (complex conditions)
                for branch in branches:
                    if any(kw in branch.condition.lower() for kw in ["&&", "||", ">=", "<=", "require(", "assert("]):
                        branch.covered = False
                        fc.uncovered_branches.append(branch)
                    else:
                        branch.covered = True
            else:
                fc.covered_branches = 0
                fc.covered_lines = 0
                fc.coverage_pct = 0.0
                fc.uncovered_branches = branches

            report.total_branches += fc.total_branches
            report.covered_branches += fc.covered_branches
            report.covered_lines += fc.covered_lines
            report.function_coverage.append(fc)
            report.uncovered_branches.extend(fc.uncovered_branches)

        # Compute overall coverage
        if report.total_branches > 0:
            report.overall_coverage_pct = (report.covered_branches / report.total_branches) * 100
        elif report.total_lines > 0:
            report.overall_coverage_pct = (report.covered_lines / report.total_lines) * 100

        self._history.append(report)
        return report

    def run_foundry_coverage(self, project_dir: str) -> CoverageReport:
        """
        Run Foundry's forge coverage and parse the output.

        Requires Foundry (forge) to be installed and a valid Foundry project.
        """
        report = CoverageReport()

        try:
            proc = subprocess.run(
                ["forge", "coverage", "--report", "summary"],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=project_dir,
            )

            if proc.returncode == 0:
                report = self._parse_forge_coverage(proc.stdout)
            else:
                logger.warning(f"forge coverage failed: {proc.stderr[:500]}")

        except FileNotFoundError:
            logger.warning("Foundry (forge) not found. Using source-based coverage estimation.")
        except subprocess.TimeoutExpired:
            logger.warning("forge coverage timed out")
        except Exception as e:
            logger.error(f"Coverage analysis failed: {e}")

        self._history.append(report)
        return report

    def get_improvement_report(self) -> dict:
        """Get coverage improvement across all iterations."""
        if not self._history:
            return {"iterations": 0, "coverage_trend": []}

        return {
            "iterations": len(self._history),
            "initial_coverage": self._history[0].overall_coverage_pct,
            "final_coverage": self._history[-1].overall_coverage_pct,
            "total_improvement": (self._history[-1].overall_coverage_pct - self._history[0].overall_coverage_pct),
            "coverage_trend": [
                {"iteration": i + 1, "coverage": r.overall_coverage_pct} for i, r in enumerate(self._history)
            ],
            "remaining_gaps": self._history[-1].get_coverage_gaps() if self._history else [],
        }

    def _extract_functions(self, source_code: str) -> dict[str, str]:
        """Extract function names and bodies from Solidity source."""
        functions = {}
        # Match function declarations
        pattern = r"function\s+(\w+)\s*\([^)]*\)[^{]*\{"
        matches = list(re.finditer(pattern, source_code))

        for match in matches:
            func_name = match.group(1)
            start = match.end()
            # Find matching closing brace
            depth = 1
            pos = start
            while pos < len(source_code) and depth > 0:
                if source_code[pos] == "{":
                    depth += 1
                elif source_code[pos] == "}":
                    depth -= 1
                pos += 1

            functions[func_name] = source_code[match.start() : pos]

        return functions

    def _extract_branches(self, func_name: str, func_body: str) -> list[BranchInfo]:
        """Extract branch points from a function body."""
        branches = []
        lines = func_body.split("\n")

        branch_patterns = [
            (r"if\s*\((.+?)\)", "if"),
            (r"require\s*\((.+?)(?:,|\))", "require"),
            (r"assert\s*\((.+?)\)", "assert"),
            (r"while\s*\((.+?)\)", "while"),
            (r"for\s*\((.+?)\)", "for"),
            (r"\?\s*", "ternary"),
        ]

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            for pattern, btype in branch_patterns:
                match = re.search(pattern, stripped)
                if match:
                    condition = match.group(1) if match.lastindex else ""
                    branches.append(
                        BranchInfo(
                            function_name=func_name,
                            line_number=i + 1,
                            condition=condition[:100],  # Truncate long conditions
                            branch_type=btype,
                        )
                    )

        return branches

    def _parse_forge_coverage(self, output: str) -> CoverageReport:
        """Parse Foundry forge coverage summary output."""
        report = CoverageReport()

        for line in output.split("\n"):
            # Parse lines like: | Contract | 85.71% | 90.00% | 66.67% | 100.00% |
            match = re.match(
                r"\|\s*(\w+)\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|",
                line,
            )
            if match:
                name = match.group(1)
                float(match.group(2))
                float(match.group(3))
                branch_cov = float(match.group(4))

                fc = FunctionCoverage(
                    name=name,
                    coverage_pct=branch_cov,
                    total_branches=100,
                    covered_branches=int(branch_cov),
                )
                report.function_coverage.append(fc)
                report.contract_name = name

        # Compute aggregated coverage
        if report.function_coverage:
            total = sum(fc.coverage_pct for fc in report.function_coverage)
            report.overall_coverage_pct = total / len(report.function_coverage)

        return report
