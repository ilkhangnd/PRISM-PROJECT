"""
Feedback Loop — Multi-feedback loop connecting GNN → LLM → Fuzzer → Coverage.

Core feedback cycle:
    1. GNN hotspots → prioritize fuzzing targets
    2. LLM seed generator → create targeted test inputs
    3. Fuzzer → execute seeds and find crashes
    4. Coverage tracker → identify remaining gaps
    5. Seed pool → accumulate and prioritize seeds
    6. Repeat until convergence or max iterations
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class LoopIteration:
    """Results from one feedback loop iteration."""

    iteration: int
    hotspots_count: int = 0
    seeds_generated: int = 0
    seeds_from_llm: int = 0
    seeds_from_mutation: int = 0
    tests_run: int = 0
    crashes_found: int = 0
    coverage_pct: float = 0.0
    coverage_delta: float = 0.0
    new_findings: list[dict] = field(default_factory=list)


@dataclass
class FeedbackLoopResult:
    """Aggregated results from the full feedback loop."""

    total_iterations: int = 0
    total_crashes: int = 0
    total_seeds_generated: int = 0
    final_coverage: float = 0.0
    all_findings: list[dict] = field(default_factory=list)
    iterations: list[LoopIteration] = field(default_factory=list)
    converged: bool = False
    coverage_trend: list[float] = field(default_factory=list)
    seed_pool_stats: dict = field(default_factory=dict)


class FeedbackLoop:
    """
    Multi-feedback loop connecting GNN hotspots, LLM seed generation,
    fuzzing execution, and coverage analysis in an iterative cycle.

    Each iteration:
    1. Generates targeted seeds from hotspots (GNN-guided)
    2. Generates smart seeds from LLM (coverage-guided)
    3. Mutates high-value seeds from the pool
    4. Runs fuzzer with combined seeds
    5. Analyzes coverage and crash data
    6. Updates hotspots and seed priorities
    """

    def __init__(self, max_iterations: int = 5, coverage_target: float = 90.0, convergence_threshold: float = 1.0):
        self.max_iterations = max_iterations
        self.coverage_target = coverage_target
        self.convergence_threshold = convergence_threshold

    def run(
        self,
        source_code: str,
        contract_info: dict,
        hotspots: list[dict],
        fuzzing_engine: Any,
        llm_auditor: Any | None = None,
        seed_generator: Any | None = None,
        coverage_tracker: Any | None = None,
        seed_pool: Any | None = None,
    ) -> FeedbackLoopResult:
        """
        Execute the multi-feedback loop.

        Args:
            source_code: Contract source code.
            contract_info: Contract metadata (functions, vulnerabilities).
            hotspots: GNN-identified hotspot functions.
            fuzzing_engine: FuzzingEngine instance.
            llm_auditor: Optional LLMAuditor for seed generation.
            seed_generator: Optional SeedGenerator for smart seed creation.
            coverage_tracker: Optional CoverageTracker for gap analysis.
            seed_pool: Optional SeedPool for seed management.
        """
        result = FeedbackLoopResult()
        prev_coverage = 0.0
        functions = contract_info.get("functions", [])

        # Initialize optional components
        if coverage_tracker is None:
            try:
                from src.fuzzing.coverage import CoverageTracker

                coverage_tracker = CoverageTracker()
            except ImportError:
                pass

        if seed_pool is None:
            try:
                from src.fuzzing.seed_pool import SeedPool

                seed_pool = SeedPool()
            except ImportError:
                pass

        if seed_generator is None and llm_auditor is not None:
            try:
                from src.analysis.llm.seed_generator import SeedGenerator

                seed_generator = SeedGenerator(llm=llm_auditor)
            except ImportError:
                pass

        logger.info(f"Starting feedback loop (max {self.max_iterations} iterations)")
        logger.info(
            f"  Components: fuzzer=✅, seed_gen={'✅' if seed_generator else '❌'}, "
            f"coverage={'✅' if coverage_tracker else '❌'}, pool={'✅' if seed_pool else '❌'}"
        )

        for i in range(1, self.max_iterations + 1):
            logger.info(f"--- Feedback Loop: Iteration {i}/{self.max_iterations} ---")
            iteration = LoopIteration(iteration=i, hotspots_count=len(hotspots))

            # === Step 1: Generate targeted seeds from GNN hotspots ===
            targeted = fuzzing_engine.generate_targeted_seeds(hotspots, functions)
            random_seeds = fuzzing_engine.generate_random_seeds(functions, count=20)
            seeds = targeted + random_seeds
            iteration.seeds_generated = len(seeds)

            # === Step 2: LLM-powered seed generation ===
            if seed_generator and i > 1 and result.iterations:
                try:
                    prev_iter = result.iterations[-1]
                    uncovered = [f for f in prev_iter.new_findings if f.get("type") == "uncovered"]
                    if uncovered:
                        batch = seed_generator.generate(
                            source_code=source_code,
                            coverage_pct=prev_coverage,
                            uncovered_branches=uncovered,
                            hotspots=hotspots,
                            num_seeds=5,
                            iteration=i,
                        )
                        # Convert GeneratedSeeds to FuzzSeeds
                        from src.fuzzing.engine import FuzzSeed

                        for gs in batch.seeds:
                            seeds.append(
                                FuzzSeed(
                                    function_name=gs.function_name,
                                    inputs=gs.inputs,
                                    description=gs.description,
                                    source="llm_generated",
                                )
                            )
                        iteration.seeds_from_llm = len(batch.seeds)
                except Exception as e:
                    logger.debug(f"LLM seed generation skipped: {e}")
            elif llm_auditor and i > 1 and result.iterations:
                # Fallback: use auditor's built-in seed generation
                try:
                    uncovered = [
                        {"function": b.get("function", "")}
                        for b in result.iterations[-1].new_findings
                        if b.get("type") == "uncovered"
                    ]
                    if uncovered:
                        llm_auditor.generate_seeds(source_code, prev_coverage, uncovered, 5)
                except Exception as e:
                    logger.debug(f"LLM seed generation fallback skipped: {e}")

            # === Step 3: Mutate high-performing seeds from pool ===
            if seed_pool and seed_pool.size > 0:
                try:
                    top_seeds = seed_pool.get_top(n=5)
                    from src.fuzzing.engine import FuzzSeed

                    for pool_seed in top_seeds:
                        mutated = seed_pool.mutate_seed(pool_seed)
                        seeds.append(
                            FuzzSeed(
                                function_name=mutated.function_name,
                                inputs=mutated.inputs,
                                description=mutated.description,
                                source="mutation",
                            )
                        )
                        iteration.seeds_from_mutation += 1
                except Exception as e:
                    logger.debug(f"Seed mutation skipped: {e}")

            # === Step 4: Run fuzzer ===
            fuzz_result = fuzzing_engine.run_simulation(seeds, contract_info)
            iteration.tests_run = fuzz_result.total_tests
            iteration.crashes_found = fuzz_result.failed
            iteration.coverage_pct = fuzz_result.coverage_pct
            iteration.coverage_delta = fuzz_result.coverage_pct - prev_coverage

            # === Step 5: Update seed pool with results ===
            if seed_pool:
                try:
                    from src.fuzzing.seed_pool import SeedEntry

                    for seed in seeds:
                        entry = SeedEntry(
                            function_name=seed.function_name,
                            inputs=seed.inputs,
                            source=seed.source,
                            description=seed.description,
                        )
                        seed_pool.add(entry)
                except Exception as e:
                    logger.debug(f"Seed pool update skipped: {e}")

            # === Step 6: Analyze coverage gaps ===
            if coverage_tracker:
                try:
                    tested_funcs = {s.function_name for s in seeds}
                    cov_report = coverage_tracker.analyze_source(source_code, tested_funcs)
                    iteration.coverage_pct = cov_report.overall_coverage_pct
                    iteration.coverage_delta = coverage_tracker.coverage_delta
                except Exception as e:
                    logger.debug(f"Coverage analysis skipped: {e}")

            # Collect findings
            for crash in fuzz_result.crashes:
                finding = {
                    "iteration": i,
                    "function": crash.get("function", ""),
                    "vulnerability": crash.get("vulnerability", ""),
                    "seed_source": crash.get("seed_source", ""),
                    "inputs": crash.get("inputs", {}),
                }
                iteration.new_findings.append(finding)
                result.all_findings.append(finding)

            for branch in fuzz_result.uncovered_branches:
                iteration.new_findings.append(
                    {
                        "type": "uncovered",
                        "function": branch.get("function", ""),
                    }
                )

            result.iterations.append(iteration)
            result.total_crashes += iteration.crashes_found
            result.total_seeds_generated += (
                iteration.seeds_generated + iteration.seeds_from_llm + iteration.seeds_from_mutation
            )
            result.coverage_trend.append(iteration.coverage_pct)

            logger.info(
                f"  Iteration {i}: seeds={iteration.seeds_generated}+{iteration.seeds_from_llm}llm+"
                f"{iteration.seeds_from_mutation}mut, crashes={iteration.crashes_found}, "
                f"coverage={iteration.coverage_pct:.1f}% (Δ{iteration.coverage_delta:+.1f}%)"
            )

            # === Step 7: Check convergence ===
            coverage_delta = abs(fuzz_result.coverage_pct - prev_coverage)
            prev_coverage = fuzz_result.coverage_pct

            if fuzz_result.coverage_pct >= self.coverage_target:
                result.converged = True
                logger.info(f"  ✅ Coverage target reached: {fuzz_result.coverage_pct:.1f}%")
                break

            if i > 1 and coverage_delta < self.convergence_threshold:
                result.converged = True
                logger.info(
                    f"  ✅ Converged: coverage delta {coverage_delta:.2f}% < threshold {self.convergence_threshold}%"
                )
                break

            # === Step 8: Update hotspots for next iteration ===
            if fuzz_result.uncovered_branches:
                # Combine original hotspots with uncovered branches
                new_hotspots = [
                    {"function_name": b["function"], "risk_score": 1.0, "vulnerability_hint": "uncovered"}
                    for b in fuzz_result.uncovered_branches
                ]
                # Keep original high-risk hotspots
                existing_high = [h for h in hotspots if h.get("risk_score", 0) > 0.7]
                hotspots = existing_high + new_hotspots

        result.total_iterations = len(result.iterations)
        result.final_coverage = prev_coverage

        if seed_pool:
            result.seed_pool_stats = seed_pool.get_stats()

        logger.info(
            f"Feedback loop complete: {result.total_iterations} iters, "
            f"{result.total_crashes} crashes, {result.final_coverage:.1f}% coverage"
        )
        return result
