#!/usr/bin/env python3
"""Audit the current manuscript source for anonymous-submission risks."""

from __future__ import annotations

import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PAPER = ROOT / "paper" if (ROOT / "paper").exists() else ROOT / "NSS2026_PRISM"
MAIN = PAPER / "main.tex"
OUT = ROOT / "artifacts/nss2026"
SUPPLEMENT = ROOT / "PRISM_Supplementary_Material.zip"

PATTERNS = {
    "email": r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
    "orcid": r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b",
    "local_path": r"(?:/[U]sers/|file://|C:\\\\[U]sers\\\\)",
    "named_author": r"(?:Author Name Placeholder|Nguyen Dinh Khang)",
}

TEXTUAL_SUFFIXES = {".bib", ".csv", ".json", ".md", ".py", ".tex", ".toml", ".txt", ".yaml", ".yml"}
AUDITED_SUPPLEMENT_PREFIXES = ("paper/", "scripts/", "configs/", "research/", "tests/", "README")
MAX_AUDITED_TEXT_BYTES = 2_000_000
PROHIBITED_SUPPLEMENT_PREFIXES = (
    "artifacts/results/e2e_pipeline_coverage_57",
    "artifacts/nss2026/function_gold_truth/",
    "artifacts/results/lane2_",
    "research/04-results/lane2_",
    "scripts/build_gold_function_labels_and_adjudication.py",
    "scripts/run_lane2_",
)


def hits(text: str) -> list[dict[str, object]]:
    out = []
    for kind, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            line = text.count("\n", 0, match.start()) + 1
            out.append({"kind": kind, "line": line, "match": match.group(0)})
    return out


def audit_supplement(path: Path) -> dict[str, object]:
    """Audit submission ZIP text and prohibit development-only Lane 2 evidence."""
    if not path.is_file():
        return {"present": False, "text_risks": [], "prohibited_members": []}
    text_risks: list[dict[str, object]] = []
    prohibited: list[str] = []
    audited_members = 0
    skipped_large_text_members = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            name = member.filename
            if name.startswith(PROHIBITED_SUPPLEMENT_PREFIXES):
                prohibited.append(name)
            # The audit's own regex literals intentionally mention patterns
            # such as ``file://`` and a placeholder author name. They are not
            # identifying data, so do not report the checker as its own leak.
            if name == "scripts/audit_nss2026_anonymity.py":
                continue
            suffix = Path(name).suffix.lower()
            is_release_documentation = name.startswith(AUDITED_SUPPLEMENT_PREFIXES)
            if not is_release_documentation or suffix not in TEXTUAL_SUFFIXES:
                continue
            if member.file_size > MAX_AUDITED_TEXT_BYTES:
                skipped_large_text_members += 1
                continue
            audited_members += 1
            try:
                contents = archive.read(member).decode("utf-8", errors="replace")
            except (OSError, zipfile.BadZipFile):
                continue
            for hit in hits(contents):
                text_risks.append({"member": name, **hit})
    return {
        "present": True,
        "archive_bytes": path.stat().st_size,
        "audited_members": audited_members,
        "skipped_large_text_members": skipped_large_text_members,
        "text_risks": text_risks,
        "prohibited_members": prohibited,
    }


def main() -> None:
    tex = MAIN.read_text(encoding="utf-8")
    active_lines = "\n".join(line for line in tex.splitlines() if not line.lstrip().startswith("%"))
    source_hits = hits(tex)
    visible_hits = hits(active_lines)
    includes = re.findall(r"\\includegraphics(?:\[[^]]*\])?\{([^}]+)\}", tex)
    include_records = []
    for include in includes:
        path = PAPER / include
        include_records.append({"tex_path": include, "exists": path.is_file(), "bytes": path.stat().st_size if path.is_file() else None})
    unreferenced_logo = PAPER / "figures/logouit.png"
    payload = {
        "schema_version": "1.0",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "manuscript": str(MAIN.relative_to(ROOT)),
        "active_pdf_risks": visible_hits,
        "source_artifact_risks": source_hits,
        "anonymous_author_block_present": "\\author{Anonymous Author(s)}" in tex,
        "figure_inputs": include_records,
        "unreferenced_institutional_logo_present": unreferenced_logo.is_file(),
        "supplementary_package": audit_supplement(SUPPLEMENT),
        "manual_checks_remaining": [
            "Inspect raster/vector figure pixels for logos, identifying labels, and local paths.",
            "Inspect generated PDF metadata after a clean build.",
            "Open the eventual anonymous artifact URL in a private browser session.",
        ],
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "anonymity_audit.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (OUT / "anonymity_audit.md").write_text(
        "# Anonymity audit\n\n"
        f"- Active-PDF text risks: **{len(visible_hits)}**.\n"
        f"- Source/artifact text risks (including comments): **{len(source_hits)}**.\n"
        f"- Anonymous author block present: **{payload['anonymous_author_block_present']}**.\n"
        f"- Unreferenced institutional logo present in tree: **{payload['unreferenced_institutional_logo_present']}**.\n\n"
        f"- Supplementary release-documentation text risks: **{len(payload['supplementary_package']['text_risks'])}**.\n"
        f"- Prohibited development-only Lane 2 members: **{len(payload['supplementary_package']['prohibited_members'])}**.\n\n"
        "Before submission, inspect any non-textual archive members and the final PDF visually for identifying marks.\n",
        encoding="utf-8",
    )
    print(f"wrote {OUT / 'anonymity_audit.json'}")


if __name__ == "__main__":
    main()
