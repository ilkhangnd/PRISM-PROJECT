"""
Seed Pool — Manages the fuzzing seed corpus with prioritization and deduplication.

Maintains a prioritized pool of fuzzing seeds from multiple sources:
- Random generation
- GNN hotspot targeting
- LLM-generated seeds
- Coverage-guided mutations
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SeedEntry:
    """A seed in the pool with metadata."""

    function_name: str
    inputs: dict[str, Any]
    source: str = "random"  # random | gnn_hotspot | llm_generated | coverage_guided
    priority: float = 1.0  # Higher = fuzz first
    description: str = ""
    hash: str = ""
    times_used: int = 0
    crashes_found: int = 0
    coverage_delta: float = 0.0  # Coverage improvement when this seed was used

    def __post_init__(self):
        if not self.hash:
            self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute a unique hash for deduplication."""
        key = f"{self.function_name}:{json.dumps(self.inputs, sort_keys=True, default=str)}"
        return hashlib.md5(key.encode()).hexdigest()[:12]


class SeedPool:
    """
    Priority-based seed pool for fuzzing campaigns.

    Seeds are deduplicated by content hash and prioritized by:
    1. Source (LLM > GNN > coverage > random)
    2. Crash history (seeds that found bugs are amplified)
    3. Coverage delta (seeds that improved coverage are kept)
    """

    SOURCE_PRIORITY = {
        "llm_generated": 3.0,
        "gnn_hotspot": 2.5,
        "coverage_guided": 2.0,
        "mutation": 1.5,
        "random": 1.0,
    }

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._seeds: dict[str, SeedEntry] = {}  # hash -> SeedEntry
        self._by_function: dict[str, list[str]] = defaultdict(list)  # func -> [hashes]

    @property
    def size(self) -> int:
        """Number of seeds in the pool."""
        return len(self._seeds)

    def add(self, seed: SeedEntry) -> bool:
        """Add a seed to the pool. Returns False if duplicate."""
        if seed.hash in self._seeds:
            return False

        # Apply source-based priority boost
        seed.priority *= self.SOURCE_PRIORITY.get(seed.source, 1.0)

        self._seeds[seed.hash] = seed
        self._by_function[seed.function_name].append(seed.hash)

        # Evict lowest priority if pool is full
        if len(self._seeds) > self.max_size:
            self._evict_lowest()

        return True

    def add_batch(self, seeds: list[SeedEntry]) -> int:
        """Add multiple seeds. Returns number of new seeds added."""
        added = 0
        for seed in seeds:
            if self.add(seed):
                added += 1
        return added

    def get_top(self, n: int = 50) -> list[SeedEntry]:
        """Get top-N seeds by priority."""
        sorted_seeds = sorted(self._seeds.values(), key=lambda s: s.priority, reverse=True)
        return sorted_seeds[:n]

    def get_for_function(self, func_name: str) -> list[SeedEntry]:
        """Get all seeds targeting a specific function."""
        hashes = self._by_function.get(func_name, [])
        return [self._seeds[h] for h in hashes if h in self._seeds]

    def get_unused(self, n: int = 50) -> list[SeedEntry]:
        """Get seeds that haven't been used yet."""
        unused = [s for s in self._seeds.values() if s.times_used == 0]
        unused.sort(key=lambda s: s.priority, reverse=True)
        return unused[:n]

    def update_seed_stats(self, seed_hash: str, crashed: bool = False, coverage_delta: float = 0.0):
        """Update seed statistics after fuzzing."""
        if seed_hash in self._seeds:
            seed = self._seeds[seed_hash]
            seed.times_used += 1
            seed.coverage_delta += coverage_delta

            if crashed:
                seed.crashes_found += 1
                # Boost priority of crash-finding seeds
                seed.priority *= 1.5

            # Amplify seeds that improve coverage
            if coverage_delta > 0:
                seed.priority *= 1.0 + coverage_delta / 10.0

    def mutate_seed(self, seed: SeedEntry) -> SeedEntry:
        """Create a mutated variant of an existing seed."""
        import random

        new_inputs = dict(seed.inputs)

        # Mutate one random input
        if new_inputs:
            key = random.choice(list(new_inputs.keys()))
            value = new_inputs[key]

            if isinstance(value, int):
                mutations = [
                    value + 1,
                    value - 1,
                    value * 2,
                    value // 2,
                    0,
                    1,
                    2**256 - 1,
                    value ^ 0xFF,
                    abs(value),
                ]
                new_inputs[key] = random.choice(mutations)
            elif isinstance(value, str) and value.startswith("0x"):
                # Flip random byte in hex string
                hex_part = value[2:]
                if hex_part:
                    pos = random.randint(0, len(hex_part) - 1)
                    new_char = random.choice("0123456789abcdef")
                    hex_part = hex_part[:pos] + new_char + hex_part[pos + 1 :]
                    new_inputs[key] = "0x" + hex_part
            elif isinstance(value, bool):
                new_inputs[key] = not value

        return SeedEntry(
            function_name=seed.function_name,
            inputs=new_inputs,
            source="mutation",
            priority=seed.priority * 0.8,
            description=f"Mutated from {seed.hash}",
        )

    def get_stats(self) -> dict:
        """Get pool statistics."""
        by_source = defaultdict(int)
        by_function = defaultdict(int)
        total_crashes = 0

        for seed in self._seeds.values():
            by_source[seed.source] += 1
            by_function[seed.function_name] += 1
            total_crashes += seed.crashes_found

        return {
            "total_seeds": len(self._seeds),
            "by_source": dict(by_source),
            "by_function": dict(by_function),
            "total_crashes_found": total_crashes,
            "avg_priority": sum(s.priority for s in self._seeds.values()) / max(len(self._seeds), 1),
        }

    def save(self, path: str | Path):
        """Persist seed pool to JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "seeds": [
                {
                    "function_name": s.function_name,
                    "inputs": s.inputs,
                    "source": s.source,
                    "priority": s.priority,
                    "description": s.description,
                    "hash": s.hash,
                    "times_used": s.times_used,
                    "crashes_found": s.crashes_found,
                    "coverage_delta": s.coverage_delta,
                }
                for s in self._seeds.values()
            ],
            "stats": self.get_stats(),
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.debug(f"Saved {len(self._seeds)} seeds to {path}")

    def load(self, path: str | Path):
        """Load seed pool from JSON."""
        path = Path(path)
        if not path.exists():
            logger.warning(f"Seed pool file not found: {path}")
            return

        with open(path) as f:
            data = json.load(f)

        for item in data.get("seeds", []):
            seed = SeedEntry(
                function_name=item["function_name"],
                inputs=item["inputs"],
                source=item.get("source", "random"),
                priority=item.get("priority", 1.0),
                description=item.get("description", ""),
                hash=item.get("hash", ""),
                times_used=item.get("times_used", 0),
                crashes_found=item.get("crashes_found", 0),
                coverage_delta=item.get("coverage_delta", 0.0),
            )
            self._seeds[seed.hash] = seed
            self._by_function[seed.function_name].append(seed.hash)

        logger.debug(f"Loaded {len(self._seeds)} seeds from {path}")

    def _evict_lowest(self):
        """Remove lowest-priority seed when pool is full."""
        if not self._seeds:
            return

        min_hash = min(self._seeds, key=lambda h: self._seeds[h].priority)
        evicted = self._seeds.pop(min_hash)

        # Clean up function index
        func_hashes = self._by_function.get(evicted.function_name, [])
        if min_hash in func_hashes:
            func_hashes.remove(min_hash)
