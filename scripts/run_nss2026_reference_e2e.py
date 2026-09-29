#!/usr/bin/env python3
"""Run auditable PRISM traces with pre-authored Foundry reference harnesses.

This runner is deliberately narrower than a general ``source -> synthesized
harness`` system.  It couples PRISM's masking/preprocessing/GNN stages with
*pre-authored*, versioned Foundry tests for five public canonical contracts.
It is therefore suitable for collecting reproducible execution evidence, but
its output must not be described as evidence of general-purpose harness
synthesis or of benchmark-wide end-to-end performance.

The LLM stage is opt-in because it depends on a local Ollama service and can
be slow.  A run without ``--with-llm`` records that omission explicitly rather
than treating it as a negative prediction or silently using a mock response.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
from queue import Empty
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = ROOT / "artifacts" / "fuzzing_runs" / "benchmark_workspace"
CONFIG = ROOT / "configs" / "nss2026_execution.yaml"

# Executing ``python scripts/<runner>.py`` puts scripts/ rather than the
# repository root on sys.path.  Make the documented invocation work without
# requiring users to set PYTHONPATH manually.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TARGETS: dict[str, dict[str, str]] = {
    "SimpleDAO": {
        "source": "SimpleDAO.sol",
        "test_contract": "SimpleDAOTest",
        "vulnerability_class": "Reentrancy",
        "swc": "SWC-107",
    },
    "TokenSale": {
        "source": "TokenSale.sol",
        "test_contract": "TokenSaleTest",
        "vulnerability_class": "Integer Overflow",
        "swc": "SWC-101",
    },
    "UnprotectedVault": {
        "source": "UnprotectedVault.sol",
        "test_contract": "UnprotectedVaultTest",
        "vulnerability_class": "Access Control",
        "swc": "SWC-105",
    },
    "UncheckedBank": {
        "source": "UncheckedBank.sol",
        "test_contract": "UncheckedBankTest",
        "vulnerability_class": "Unchecked Return Value",
        "swc": "SWC-104",
    },
    "TimestampLock": {
        "source": "TimestampLock.sol",
        "test_contract": "TimestampLockTest",
        "vulnerability_class": "Timestamp Dependence",
        "swc": "SWC-114",
    },
}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def run_command(command: list[str], cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    """Run Foundry and retain compact, tamper-evident execution metadata."""
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout, stderr = completed.stdout, completed.stderr
        return_code: int | None = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        return_code = None
        timed_out = True

    duration_ms = (time.perf_counter() - started) * 1000
    return {
        "command": command,
        "return_code": return_code,
        "timed_out": timed_out,
        "passed": return_code == 0 and "[PASS]" in stdout,
        "duration_ms": round(duration_ms, 2),
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        # Keeping a short tail makes failures inspectable without storing
        # unbounded logs in the aggregate research artifact.
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-1000:],
    }


def run_prism_gnn(source: Path, output_dir: Path, config_path: Path) -> dict[str, Any]:
    """Run only deterministic local PRISM stages up through GNN routing."""
    from src.pipeline import PRISMPipeline

    pipeline = PRISMPipeline(str(config_path))
    source_text = source.read_text(encoding="utf-8")
    masked_code, mapping_path = pipeline._run_security_layer(source_text, output_dir)
    graphs = pipeline._run_preprocessing(
        str(output_dir / "masked_source.sol"), output_dir, fallback_path=str(source)
    )

    gnn_config = pipeline.config.get("gnn", {})
    model_path = ROOT / gnn_config.get("model_path", "")
    mapping_count = len(json.loads(mapping_path.read_text(encoding="utf-8")).get("original_to_masked", {}))
    if not model_path.exists():
        return {
            "status": "skipped",
            "reason": f"GNN checkpoint unavailable: {model_path}",
            "masked_identifier_count": mapping_count,
            "graphs_built": graphs.get("graphs_built", 0),
            "hotspots": [],
        }

    hotspots = pipeline._run_gnn_inference(graphs, str(model_path), gnn_config)
    return {
        "status": "completed",
        "checkpoint": str(model_path.relative_to(ROOT)),
        "checkpoint_sha256": sha256_file(model_path),
        "masked_identifier_count": mapping_count,
        "graphs_built": graphs.get("graphs_built", 0),
        "hotspot_count": len(hotspots),
        "hotspots": hotspots,
    }


def run_llm(masked_source: Path, hotspots: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    """Call the configured local LLM; exceptions are evidence, not fallback data."""
    from src.analysis.llm.auditor import LLMAuditor

    llm_config = config.get("llm", {})
    auditor = LLMAuditor(
        provider=llm_config.get("provider", "local"),
        model=llm_config.get("local", {}).get("model", "deepseek-coder-v2:latest"),
        base_url=llm_config.get("local", {}).get("base_url", "http://localhost:11434"),
        allow_mock_fallback=False,
        temperature=llm_config.get("temperature", 0.1),
        max_tokens=llm_config.get("max_tokens", 4096),
        timeout=llm_config.get("timeout", 120),
    )
    started = time.perf_counter()
    try:
        findings = auditor.analyze(
            masked_source.read_text(encoding="utf-8"),
            hotspots=hotspots,
            compact=llm_config.get("compact_output", False),
        )
        return {
            "status": "completed",
            "model": llm_config.get("local", {}).get("model"),
            "finding_count": len(findings),
            "findings": findings,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    except Exception as error:  # Local service/model failures must stay visible.
        return {
            "status": "error",
            "model": llm_config.get("local", {}).get("model"),
            "error": f"{type(error).__name__}: {error}",
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }


def _llm_worker(
    masked_source: str, hotspots: list[dict[str, Any]], config: dict[str, Any], queue: Any
) -> None:
    """Separate process so an unresponsive local model cannot hang a campaign."""
    queue.put(run_llm(Path(masked_source), hotspots, config))


def run_llm_bounded(
    masked_source: Path,
    hotspots: list[dict[str, Any]],
    config: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run local LLM analysis with a hard wall-clock bound and no mock fallback."""
    context = mp.get_context("spawn")
    queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_llm_worker,
        args=(str(masked_source), hotspots, config, queue),
        daemon=True,
    )
    process.start()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(10)
        return {
            "status": "timeout",
            "model": config.get("llm", {}).get("local", {}).get("model"),
            "timeout_seconds": timeout_seconds,
            "reason": "LLM worker exceeded the configured wall-clock limit; no mock result was substituted.",
        }
    try:
        return queue.get(timeout=2)
    except Empty:
        pass
    return {
        "status": "error",
        "model": config.get("llm", {}).get("local", {}).get("model"),
        "error": f"LLM worker exited with code {process.exitcode} without a result",
    }


def run_case(
    name: str,
    target: dict[str, str],
    output_dir: Path,
    config: dict[str, Any],
    config_path: Path,
    forge: str,
    seed: int,
    fuzz_runs: int,
    timeout_seconds: int,
    with_llm: bool,
    llm_timeout_seconds: int,
    route_via_gnn: bool,
) -> dict[str, Any]:
    source = WORKSPACE / "src" / target["source"]
    case_dir = output_dir / "cases" / name
    case_dir.mkdir(parents=True, exist_ok=True)
    case: dict[str, Any] = {
        "target": name,
        "source": str(source.relative_to(ROOT)),
        "source_sha256": sha256_file(source),
        "vulnerability_class": target["vulnerability_class"],
        "swc": target["swc"],
        "harness_kind": "pre-authored Foundry reference harness",
    }

    try:
        case["gnn"] = run_prism_gnn(source, case_dir, config_path)
    except Exception as error:
        case["gnn"] = {"status": "error", "error": f"{type(error).__name__}: {error}"}

    if with_llm and case["gnn"].get("status") == "completed":
        case["llm"] = run_llm_bounded(
            case_dir / "masked_source.sol",
            case["gnn"].get("hotspots", []),
            config,
            llm_timeout_seconds,
        )
    else:
        case["llm"] = {
            "status": "skipped",
            "reason": "--with-llm was not supplied" if not with_llm else "GNN stage did not complete",
        }

    should_route = not route_via_gnn or (
        case["gnn"].get("status") == "completed" and case["gnn"].get("hotspot_count", 0) > 0
    )
    case["routing"] = {
        "policy": "any_gnn_hotspot" if route_via_gnn else "unconditional_reference_execution",
        "routed_to_foundry": should_route,
        "hotspot_count": case["gnn"].get("hotspot_count", 0),
    }
    if should_route:
        base = [forge, "test", "--fuzz-seed", str(seed), "--match-contract", target["test_contract"]]
        case["foundry"] = {
            "guided_reference_test": run_command(
                [*base, "--match-test", "testGuidedExploit", "-vvv"], WORKSPACE, timeout_seconds
            ),
            "parameterized_reference_fuzz": run_command(
                [
                    *base,
                    "--match-test",
                    "testRandomFuzz",
                    "--fuzz-runs",
                    str(fuzz_runs),
                    "-vvv",
                ],
                WORKSPACE,
                timeout_seconds,
            ),
        }
    else:
        skipped = {
            "passed": False,
            "status": "skipped",
            "reason": "No GNN hotspot met the routing policy; Foundry was not invoked.",
        }
        case["foundry"] = {
            "guided_reference_test": skipped,
            "parameterized_reference_fuzz": skipped.copy(),
        }
    return case


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", nargs="+", choices=sorted(TARGETS), default=sorted(TARGETS))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fuzz-runs", type=int, default=10_000)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument(
        "--llm-timeout-seconds",
        type=int,
        default=120,
        help="Hard wall-clock limit for each local LLM invocation.",
    )
    parser.add_argument(
        "--llm-max-tokens",
        type=int,
        help="Override configured generation budget for a bounded experiment; recorded in summary.json.",
    )
    parser.add_argument(
        "--llm-request-timeout-seconds",
        type=int,
        help="Override the HTTP timeout passed to Ollama inside the LLM worker.",
    )
    parser.add_argument(
        "--llm-compact",
        action="store_true",
        help="Use a short, strict JSON triage prompt for bounded LLM measurement.",
    )
    parser.add_argument("--with-llm", action="store_true", help="Run the configured local Ollama audit stage.")
    parser.add_argument(
        "--route-via-gnn",
        action="store_true",
        help="Invoke the reference Foundry harness only when GNN returns at least one hotspot.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Directory for a new run. Defaults to artifacts/nss2026/e2e_reference/<UTC timestamp>.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    numeric_args = [args.fuzz_runs, args.timeout_seconds, args.llm_timeout_seconds]
    if args.llm_max_tokens is not None:
        numeric_args.append(args.llm_max_tokens)
    if args.llm_request_timeout_seconds is not None:
        numeric_args.append(args.llm_request_timeout_seconds)
    if min(numeric_args) < 1:
        raise SystemExit("All supplied timeout and token-count arguments must be positive")
    if not WORKSPACE.exists() or not CONFIG.exists():
        raise SystemExit("Reference Foundry workspace or NSS 2026 config is missing")
    forge = shutil.which("forge")
    if forge is None:
        raise SystemExit("forge was not found on PATH")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output or ROOT / "artifacts" / "nss2026" / "e2e_reference" / timestamp
    output_dir = output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"Refusing to overwrite a non-empty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    config = load_config(CONFIG)
    llm_config = config.setdefault("llm", {})
    if args.llm_max_tokens is not None:
        llm_config["max_tokens"] = args.llm_max_tokens
    if args.llm_request_timeout_seconds is not None:
        llm_config["timeout"] = args.llm_request_timeout_seconds
    if args.llm_compact:
        llm_config["compact_output"] = True

    version = run_command([forge, "--version"], ROOT, timeout_seconds=30)
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "complete": False,
        "evidence_scope": {
            "claimed": "PRISM masking/preprocessing/GNN trace coupled with real execution of pre-authored Foundry reference harnesses.",
            "not_claimed": [
                "General-purpose harness synthesis",
                "Benchmark-wide end-to-end recall or specificity",
                "LLM-stage performance when --with-llm is absent",
                "Causal attribution from a GNN hotspot to a Foundry test outcome",
            ],
        },
        "configuration": {
            "config_file": str(CONFIG.relative_to(ROOT)),
            "config_sha256": sha256_file(CONFIG),
            "seed": args.seed,
            "fuzz_runs": args.fuzz_runs,
            "with_llm": args.with_llm,
            "llm_timeout_seconds": args.llm_timeout_seconds,
            "llm_max_tokens": llm_config.get("max_tokens"),
            "llm_request_timeout_seconds": llm_config.get("timeout", 120),
            "llm_compact": llm_config.get("compact_output", False),
            "route_via_gnn": args.route_via_gnn,
            "forge": version,
        },
        "cases": [],
    }

    def write_checkpoint() -> None:
        """Persist completed cases so an interrupted long LLM run remains auditable."""
        result["summary"] = {
            "case_count": len(result["cases"]),
            "gnn_completed": sum(c["gnn"].get("status") == "completed" for c in result["cases"]),
            "llm_completed": sum(c["llm"].get("status") == "completed" for c in result["cases"]),
            "guided_foundry_passed": sum(c["foundry"]["guided_reference_test"]["passed"] for c in result["cases"]),
            "fuzz_foundry_passed": sum(c["foundry"]["parameterized_reference_fuzz"]["passed"] for c in result["cases"]),
        }
        (output_dir / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    for name in args.targets:
        print(f"[reference-e2e] {name}", flush=True)
        case = run_case(
            name,
            TARGETS[name],
            output_dir,
            config,
            CONFIG,
            forge,
            args.seed,
            args.fuzz_runs,
            args.timeout_seconds,
            args.with_llm,
            args.llm_timeout_seconds,
            args.route_via_gnn,
        )
        result["cases"].append(case)
        case_path = output_dir / "cases" / name / "case.json"
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        write_checkpoint()

    result["complete"] = True
    write_checkpoint()
    print(f"Wrote {output_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
