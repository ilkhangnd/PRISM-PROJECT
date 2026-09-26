"""
Solc Version Resolver — Auto-detect Solidity version from pragma statements.

Matches the pragma version constraint to the best available installed solc version.
"""

from __future__ import annotations

import logging
import re
import subprocess
from functools import lru_cache

logger = logging.getLogger(__name__)

# Regex to extract pragma solidity version
PRAGMA_PATTERN = re.compile(
    r"pragma\s+solidity\s+([^;]+);",
    re.MULTILINE,
)

# Version constraint operators
VERSION_RE = re.compile(r"([><=^~!]*)(\d+\.\d+\.\d+)")

# Ordered list of common solc versions to try (newest first)
FALLBACK_VERSIONS = [
    "0.8.20",
    "0.8.19",
    "0.8.17",
    "0.8.13",
    "0.8.10",
    "0.8.7",
    "0.8.4",
    "0.8.0",
    "0.7.6",
    "0.7.5",
    "0.7.0",
    "0.6.12",
    "0.6.6",
    "0.6.0",
    "0.5.16",
    "0.5.12",
    "0.5.0",
    "0.4.25",
    "0.4.24",
    "0.4.21",
    "0.4.18",
    "0.4.11",
]


def parse_version(ver_str: str) -> tuple[int, int, int]:
    """Parse a version string like '0.8.20' into a tuple (0, 8, 20)."""
    parts = ver_str.strip().split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


@lru_cache(maxsize=1)
def get_installed_versions() -> list[str]:
    """Get list of solc versions installed via solc-select."""
    try:
        result = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        versions = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip().replace(" (current, set by", "").split(")")[0].strip()
            if re.match(r"\d+\.\d+\.\d+", line):
                versions.append(line.split()[0])
        return sorted(versions, key=parse_version, reverse=True)
    except Exception as e:
        logger.warning(f"Cannot get installed solc versions: {e}")
        return FALLBACK_VERSIONS[:5]


def detect_pragma_version(source_code: str) -> str | None:
    """
    Extract the Solidity version constraint from pragma statement.

    Returns the raw constraint string, e.g., "^0.4.25", ">=0.5.0 <0.6.0", "0.8.20"
    """
    match = PRAGMA_PATTERN.search(source_code)
    if match:
        return match.group(1).strip()
    return None


def resolve_solc_version(source_code: str) -> str:
    """
    Determine the best solc version to use for a given Solidity source.

    Logic:
    1. Extract pragma constraint from source
    2. Find the best matching installed version
    3. Fall back to 0.8.20 if no match

    Args:
        source_code: Solidity source code.

    Returns:
        Version string like "0.8.20".
    """
    constraint = detect_pragma_version(source_code)
    if not constraint:
        logger.debug("No pragma found, defaulting to 0.8.20")
        return "0.8.20"

    installed = get_installed_versions()
    if not installed:
        return "0.8.20"

    # Parse version constraints
    matches = VERSION_RE.findall(constraint)
    if not matches:
        return "0.8.20"

    # Simple strategy: find the best installed version that satisfies the constraint
    for version_str in installed:
        ver = parse_version(version_str)
        if _satisfies_constraint(ver, constraint, matches):
            return version_str

    # If no exact match, try to find closest compatible version
    # For "^0.X.Y", any 0.X.Z where Z >= Y works
    # For ">=0.X.Y <0.A.B", find version in range
    first_op, first_ver = matches[0]
    target = parse_version(first_ver)

    # Find closest version with same major.minor
    for version_str in installed:
        ver = parse_version(version_str)
        if ver[0] == target[0] and ver[1] == target[1]:
            return version_str

    # Last resort: closest major.minor that's >= target
    for version_str in installed:
        ver = parse_version(version_str)
        if ver >= target:
            return version_str

    logger.warning(f"No matching solc for pragma '{constraint}', using {installed[0]}")
    return installed[0]


def _satisfies_constraint(
    ver: tuple[int, int, int],
    constraint: str,
    matches: list[tuple[str, str]],
) -> bool:
    """Check if a version satisfies the given pragma constraint."""
    for op, ver_str in matches:
        target = parse_version(ver_str)

        if op in ("", "=", "=="):
            if ver != target:
                return False
        elif op == "^":
            # ^0.X.Y means >=0.X.Y and <0.(X+1).0
            if ver < target:
                return False
            if ver[0] != target[0] or ver[1] != target[1]:
                # For 0.x versions, ^ locks major.minor
                if target[0] == 0:
                    return False
        elif op == "~":
            # ~0.X.Y means >=0.X.Y and <0.X+1.0
            if ver < target or ver[0] != target[0] or ver[1] != target[1]:
                return False
        elif op == ">=":
            if ver < target:
                return False
        elif op == ">":
            if ver <= target:
                return False
        elif op == "<=":
            if ver > target:
                return False
        elif op == "<":
            if ver >= target:
                return False

    return True


def switch_solc_version(version: str) -> bool:
    """
    Switch the active solc version using solc-select.

    Args:
        version: Version string like "0.8.20".

    Returns:
        True if successfully switched, False otherwise.
    """
    try:
        from solc_select.solc_select import switch_global_version

        switch_global_version(version, always_install=False)
        logger.debug(f"Switched solc to {version}")
        return True
    except ImportError:
        # Fallback: use CLI
        try:
            subprocess.run(
                ["solc-select", "use", version],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            logger.debug(f"Switched solc to {version} (CLI)")
            return True
        except Exception as e:
            logger.warning(f"Cannot switch solc to {version}: {e}")
            return False
    except Exception as e:
        logger.warning(f"Cannot switch solc to {version}: {e}")
        return False


def resolve_and_get_solc(source_code: str) -> tuple[str, str]:
    """
    Detect pragma version, switch solc-select to that version, return (version, "solc").

    The returned "solc" binary will point to the correct version because solc-select
    manages a global symlink.

    Args:
        source_code: Solidity source code.

    Returns:
        Tuple of (version_string, solc_binary_name).
    """
    version = resolve_solc_version(source_code)
    switch_solc_version(version)
    return version, "solc"
