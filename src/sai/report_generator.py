"""
SAI Report Generator — Generates comprehensive security audit reports.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportGenerator:
    """Generates structured security audit reports in JSON and Markdown."""

    def __init__(self, project_name: str = "PRISM Security Audit"):
        self.project_name = project_name

    def generate(
        self,
        source_file: str,
        explanations: list[Any],
        patches: list[Any],
        fuzzing_result: Any | None = None,
        gnn_hotspots: list[dict] | None = None,
        llm_findings: list[dict] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Generate the full audit report as a dict."""
        findings = []
        for i, exp in enumerate(explanations):
            patch = patches[i] if i < len(patches) else None
            findings.append(
                {
                    "id": f"PRISM-{i + 1:03d}",
                    "function": exp.function_name,
                    "vulnerability_type": exp.vulnerability_type,
                    "severity": getattr(exp, "severity", "medium"),
                    "risk_score": exp.risk_score,
                    "detection_source": getattr(exp, "detection_source", ""),
                    "root_cause": exp.root_cause,
                    "attack_vector": exp.attack_vector,
                    "impact": exp.impact,
                    "remediation": exp.remediation,
                    "has_patch": patch is not None and patch.patched_code != patch.original_code,
                    "patch_confidence": patch.confidence if patch else 0,
                }
            )

        findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

        severity_counts = {}
        for f in findings:
            s = f["severity"]
            severity_counts[s] = severity_counts.get(s, 0) + 1

        report = {
            "title": self.project_name,
            "generated_at": datetime.now().isoformat(),
            "source_file": source_file,
            "summary": {
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
                "functions_analyzed": len({f["function"] for f in findings}),
                "auto_patches_generated": sum(1 for f in findings if f["has_patch"]),
            },
            "findings": findings,
        }

        if fuzzing_result:
            report["fuzzing"] = {
                "total_tests": getattr(fuzzing_result, "total_tests", 0),
                "crashes": getattr(fuzzing_result, "failed", 0),
                "coverage_pct": getattr(fuzzing_result, "coverage_pct", 0),
            }

        if metadata:
            report["metadata"] = metadata

        return report

    def save_json(self, report: dict, output_path: str | Path) -> Path:
        """Save report as JSON."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"JSON report saved to {path}")
        return path

    def save_markdown(self, report: dict, output_path: str | Path) -> Path:
        """Save report as Markdown."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        md = [f"# {report['title']}\n"]
        md.append(f"**Generated:** {report['generated_at']}  ")
        md.append(f"**Source:** `{report['source_file']}`\n")

        # Summary
        s = report["summary"]
        md.append("## Summary\n")
        md.append("| Metric | Value |")
        md.append("|---|---|")
        md.append(f"| Total Findings | {s['total_findings']} |")
        for sev, cnt in s["severity_breakdown"].items():
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")
            md.append(f"| {emoji} {sev.capitalize()} | {cnt} |")
        md.append(f"| Auto-patches | {s['auto_patches_generated']} |")
        md.append("")

        # Findings
        md.append("## Findings\n")
        for f in report["findings"]:
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f["severity"], "⚪")
            md.append(f"### {f['id']}: {f['vulnerability_type']} {sev_emoji}\n")
            md.append(f"- **Function:** `{f['function']}`")
            md.append(f"- **Severity:** {f['severity']} (score: {f['risk_score']:.2f})")
            md.append(f"- **Detected by:** {f['detection_source']}")
            md.append(f"- **Root Cause:** {f['root_cause']}")

            if f["attack_vector"]:
                md.append("\n**Attack Vector:**")
                for step in f["attack_vector"]:
                    md.append(f"1. {step}")

            md.append(f"\n**Impact:** {f['impact']}")
            md.append(f"\n**Remediation:** {f['remediation']}")
            if f["has_patch"]:
                md.append(f"\n✅ Auto-patch available (confidence: {f['patch_confidence']:.0%})")
            md.append("\n---\n")

        # Fuzzing
        if "fuzzing" in report:
            fz = report["fuzzing"]
            md.append("## Fuzzing Results\n")
            md.append(f"- Tests run: {fz['total_tests']}")
            md.append(f"- Crashes: {fz['crashes']}")
            md.append(f"- Coverage: {fz['coverage_pct']:.1f}%\n")

        with open(path, "w") as f:
            f.write("\n".join(md))

        logger.info(f"Markdown report saved to {path}")
        return path
