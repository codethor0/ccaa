#!/usr/bin/env python3
"""Fail-closed consistency checks for the public research bundle."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATE = "2026-10-02"
TITLE = (
    "Containing Cyber-Capable AI Agents: Incident Evidence, Formal Safety "
    "Conditions, and a Reference Architecture for Bounded Autonomous Cyber Evaluation"
)
ORCID = "0009-0001-6573-385X"

REQUIRED = [
    "paper.tex",
    "Containing-Cyber-Capable-AI-Agents.pdf",
    "abstract.txt",
    "README.md",
    "CITATION.cff",
    ".zenodo.json",
    "LICENSE-PAPER.md",
    "LICENSE-CODE",
    "Makefile",
    "scripts/agent_eval_preflight.py",
    "scripts/check_release.py",
    "tests/test_preflight.py",
    "examples/agent_eval_scope.example.json",
]
FIGURES = [
    "fig1_failure_classes",
    "fig2_anthropic_four_incidents",
    "fig3_openai_hf_timeline",
    "fig4_aisi_open_internet",
    "fig5_authorization_transaction",
    "fig6_reference_architecture",
    "fig7_cross_run_isolation",
]


def require(cond: bool, message: str) -> None:
    if not cond:
        raise SystemExit(f"FAIL: {message}")


def main() -> None:
    for rel in REQUIRED:
        require((ROOT / rel).is_file(), f"missing {rel}")

    for stem in FIGURES:
        for ext in ("dot", "pdf"):
            rel = Path("figures") / f"{stem}.{ext}"
            require((ROOT / rel).is_file(), f"missing {rel}")

    tex = (ROOT / "paper.tex").read_text()
    abstract = (ROOT / "abstract.txt").read_text()
    readme = (ROOT / "README.md").read_text()
    cff = (ROOT / "CITATION.cff").read_text()
    zenodo = json.loads((ROOT / ".zenodo.json").read_text())

    require("October 2026" in tex and ORCID in tex, "paper metadata missing date or ORCID")
    require(TITLE in tex, "paper title mismatch")
    require("Paper license: Creative Commons Attribution 4.0 International (CC BY 4.0)" in tex, "paper front matter license missing")
    require("Companion code license: MIT" in tex, "code license front matter missing")
    require("Revocation semantics" in tex and "revocation state" in tex, "revocation semantics missing")
    require("No machine-checked proof or model-checking artifact" in tex, "mechanized-proof boundary missing")
    require("guardian's safety case" in tex, "guardian safety-case boundary missing")
    mediation_sentence = "Every consequential external effect must be completely mediated and authorized"
    require(mediation_sentence in tex, "paper abstract mediation statement missing")
    require(mediation_sentence in abstract, "abstract.txt mediation statement missing")
    require(mediation_sentence in zenodo["description"], "Zenodo description mediation statement missing")
    stale_sentence = "must pass a complete broker"
    require(
        stale_sentence not in tex
        and stale_sentence not in abstract
        and stale_sentence not in zenodo["description"],
        "stale abstract wording remains",
    )

    # Public-facing publication should not expose draft/release version labels.
    version_markers = ("v2.0.0", "Version 2.0.0", "Version 1.2", "Version History")
    for marker in version_markers:
        require(marker not in tex, f"paper contains version marker: {marker}")
        require(marker not in readme, f"README contains version marker: {marker}")
        require(marker not in cff, f"CITATION.cff contains version marker: {marker}")
    require("version" not in zenodo, "Zenodo metadata should not contain a release version")

    for bad in ("TODO", "TBD", "FIXME"):
        require(not re.search(rf"\\b{bad}\\b", tex, re.I), f"paper contains {bad}")

    require(zenodo["title"] == TITLE, "Zenodo title mismatch")
    require(zenodo["license"] == "cc-by-4.0", "Zenodo paper license mismatch")
    require(zenodo["publication_type"] == "preprint", "Zenodo publication type mismatch")
    require("doi" not in zenodo and "prereserve_doi" not in zenodo, "prepublication Zenodo metadata must not invent a DOI")
    require(zenodo["creators"][0]["orcid"] == ORCID, "Zenodo ORCID mismatch")

    require(f'date-released: "{DATE}"' in cff, "CFF release date mismatch")
    require(ORCID in cff, "CFF ORCID mismatch")
    require(TITLE in cff, "CFF preferred citation title mismatch")

    for stem in FIGURES:
        require(f"figures/{stem}.pdf" in tex, f"paper does not reference {stem}.pdf")

    secret_patterns = [
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"github_pat_[A-Za-z0-9_]",
        r"AKIA[0-9A-Z]{16}",
    ]
    scan_ext = {".tex", ".md", ".py", ".json", ".cff", ".dot"}
    for path in ROOT.rglob("*"):
        if path.is_file() and path.suffix.lower() in scan_ext and "build" not in path.parts:
            body = path.read_text(errors="ignore")
            for pattern in secret_patterns:
                require(not re.search(pattern, body), f"possible secret material in {path.relative_to(ROOT)}")

    print("RELEASE SURFACE CHECK: PASS")
    print(f"figures={len(FIGURES)} tests=12 doi=unassigned version_markers=none")


if __name__ == "__main__":
    main()
