#!/usr/bin/env python3
"""Run a reproducible, isolated privacy audit over the frozen 57-source set."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.security.data_masking import DataMasker
from src.security.demasking import Demasker


def invoke(command: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def detectors(command: list[str]) -> tuple[int, set[str]]:
    code, stdout, _ = invoke(command)
    try:
        parsed = json.loads(stdout)
        values = {item.get("check") for item in parsed.get("results", {}).get("detectors", [])}
        return code, {value for value in values if value}
    except json.JSONDecodeError:
        return code, set()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=ROOT / "artifacts/nss2026/phase2_readiness.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/nss2026/phase2_privacy")
    parser.add_argument("--solc", default="/opt/homebrew/bin/solc")
    parser.add_argument("--slither", default=str(ROOT / ".venv/bin/slither"))
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"refusing to overwrite existing output directory: {args.output_dir}")
    masked_dir = args.output_dir / "masked_contracts"
    mapping_dir = args.output_dir / "mask_mappings"
    masked_dir.mkdir(parents=True)
    mapping_dir.mkdir(parents=True)

    records = []
    raw_total = masked_total = shared_total = 0
    for item in manifest["records"]:
        source = ROOT / item["relative_path"]
        raw = source.read_text(encoding="utf-8")
        masker = DataMasker()
        masked = masker.mask_source(raw)
        masked_path = masked_dir / item["file_name"]
        masked_path.write_text(masked, encoding="utf-8")
        (mapping_dir / f"{source.stem}_mapping.json").write_text(json.dumps({
            "forward": masker.mapping.original_to_masked,
            "reverse": masker.mapping.masked_to_original,
        }, indent=2) + "\n", encoding="utf-8")
        compile_code, _, compile_stderr = invoke([args.solc, "--bin", str(masked_path)])
        recovered = Demasker(masker.mapping).demask_text(masked)
        bijective = all(masker.mapping.masked_to_original.get(v) == k for k, v in masker.mapping.original_to_masked.items())
        raw_code, raw_detectors = detectors([args.slither, str(source), "--json", "-"])
        masked_code, masked_detectors = detectors([args.slither, str(masked_path), "--json", "-"])
        raw_total += len(raw_detectors)
        masked_total += len(masked_detectors)
        shared_total += len(raw_detectors & masked_detectors)
        records.append({
            "file_name": item["file_name"],
            "relative_path": item["relative_path"],
            "source_sha256": item["sha256"],
            "identifiers_masked": len(masker.mapping.original_to_masked),
            "solc_masked_returncode": compile_code,
            "solc_masked_compiled": compile_code == 0,
            "demask_exact": recovered.strip() == raw.strip(),
            "mapping_bijective": bijective,
            "raw_slither_returncode": raw_code,
            "masked_slither_returncode": masked_code,
            "raw_detector_names": sorted(raw_detectors),
            "masked_detector_names": sorted(masked_detectors),
            "shared_detector_names": sorted(raw_detectors & masked_detectors),
            "compile_stderr_tail": compile_stderr[-1000:],
        })
        print(f"{item['file_name']}: compile={'PASS' if compile_code == 0 else 'FAIL'}, "
              f"demask={'PASS' if records[-1]['demask_exact'] else 'FAIL'}")

    total = len(records)
    payload = {
        "schema_version": "1.0",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "execution_scope": "DataMasker/DeMasker plus solc and Slither detector-name retention; no LLM invocation",
        "input_manifest": str(args.manifest.relative_to(ROOT)),
        "tools": {"solc": args.solc, "slither": args.slither},
        "contracts_evaluated": total,
        "metrics": {
            "masked_compile_rate_pct": round(100 * sum(r["solc_masked_compiled"] for r in records) / max(1, total), 2),
            "exact_demask_rate_pct": round(100 * sum(r["demask_exact"] for r in records) / max(1, total), 2),
            "bijective_mapping_rate_pct": round(100 * sum(r["mapping_bijective"] for r in records) / max(1, total), 2),
            "shared_detector_name_retention_pct": round(100 * shared_total / max(1, raw_total), 2),
        },
        "detector_name_counts": {"raw": raw_total, "masked": masked_total, "shared": shared_total},
        "records": records,
        "limitations": [
            "Detector-name retention is not semantic equivalence and is not an LLM utility measure.",
            "This audit uses benchmark/template labels only; it does not establish source-span SWC ground truth.",
        ],
    }
    output = args.output_dir / "privacy_audit.json"
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
