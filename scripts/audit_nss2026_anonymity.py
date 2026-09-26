#!/usr/bin/env python3
"""Audit the current manuscript source for anonymous-submission risks."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PAPER = ROOT / "NSS2026_PRISM"
MAIN = PAPER / "main.tex"
OUT = ROOT / "artifacts/nss2026"

PATTERNS = {
    "email": r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
    "orcid": r"\b\d{4}-\d{4}-\d{4}-\d{3}[\dX]\b",
    "local_path": r"(?:/Users/|file://|C:\\\\Users\\\\)",
    "institution": r"University of Information Technology|Ho Chi Minh City|Vietnam",
    "named_author": r"Dinh-Khang Nguyen|T\.-D\. Tran",
}


def hits(text: str) -> list[dict[str, object]]:
    out = []
    for kind, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            line = text.count("\n", 0, match.start()) + 1
            out.append({"kind": kind, "line": line, "match": match.group(0)})
    return out


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
        "manuscript": "NSS2026_PRISM/main.tex",
        "active_pdf_risks": visible_hits,
        "source_artifact_risks": source_hits,
        "anonymous_author_block_present": "\\author{Anonymous Author(s)}" in tex,
        "figure_inputs": include_records,
        "unreferenced_institutional_logo_present": unreferenced_logo.is_file(),
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
        "The commented real author block must be removed before any source artifact is shared, even though it is not typeset in the PDF.\n",
        encoding="utf-8",
    )
    print(f"wrote {OUT / 'anonymity_audit.json'}")


if __name__ == "__main__":
    main()
