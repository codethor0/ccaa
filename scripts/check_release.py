#!/usr/bin/env python3
"""Fail-closed consistency checks for the public research bundle."""
from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATE = "2026-10-03"
TITLE = (
    "Containing Cyber-Capable AI Agents: Incident Evidence, Formal Safety "
    "Conditions, and a Reference Architecture for Bounded Autonomous Cyber Evaluation"
)
ORCID = "0009-0001-6573-385X"
EXPECTED_PDF_SHA256 = "59074a5a1996a8851617a0d618f4a13df361c5bc1f19c487999f93d22f69cff4"
PREVIOUS_PDF_SHA256 = "0d11db683fe9f9eed585eb29854b02940bdf056e21d7a00ce4ce6e106460db1d"
CURRENT_DOI = "10.5281/zenodo.23124432"
PREVIOUS_DOI = "10.5281/zenodo.23113152"
CURRENT_RECORD_ID = "23124432"
PREVIOUS_RECORD_ID = "23113152"

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
    "tests/test_destination_binding.py",
    "tests/test_commit_authorization.py",
    "tests/test_live_loopback.py",
    "scripts/commit_authorization.py",
    "evaluation/run_evaluation.py",
    "evaluation/results.json",
    "publication/manifest.json",
    "publication/zenodo-23113152/Containing-Cyber-Capable-AI-Agents.pdf",
    "publication/zenodo-23124432/Containing-Cyber-Capable-AI-Agents.pdf",
    "publication/dns-rebinding-trace.json",
    "examples/agent_eval_scope.example.json",
    ".github/workflows/reproducibility.yml",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/review-finding.md",
]
FIGURES = [
    "fig1_failure_classes",
    "fig2_anthropic_four_incidents",
    "fig3_openai_hf_timeline",
    "fig4_aisi_open_internet",
    "fig5_authorization_transaction",
    "fig6_dns_binding",
    "fig7_reference_architecture",
    "fig8_cross_run_isolation",
]


def require(cond: bool, message: str) -> None:
    if not cond:
        raise SystemExit(f"FAIL: {message}")


def main() -> None:
    for rel in REQUIRED:
        require((ROOT / rel).is_file(), f"missing {rel}")

    for stem in FIGURES:
        for ext in ("dot", "pdf", "png"):
            rel = Path("figures") / f"{stem}.{ext}"
            require((ROOT / rel).is_file(), f"missing {rel}")

    tex = (ROOT / "paper.tex").read_text()
    abstract = (ROOT / "abstract.txt").read_text()
    readme = (ROOT / "README.md").read_text()
    cff = (ROOT / "CITATION.cff").read_text()
    zenodo = json.loads((ROOT / ".zenodo.json").read_text())
    manifest = json.loads((ROOT / "publication/manifest.json").read_text())


    pdf_sha256 = hashlib.sha256((ROOT / "Containing-Cyber-Capable-AI-Agents.pdf").read_bytes()).hexdigest()
    current_archived_sha256 = hashlib.sha256(
        (ROOT / "publication/zenodo-23124432/Containing-Cyber-Capable-AI-Agents.pdf").read_bytes()
    ).hexdigest()
    previous_archived_sha256 = hashlib.sha256(
        (ROOT / "publication/zenodo-23113152/Containing-Cyber-Capable-AI-Agents.pdf").read_bytes()
    ).hexdigest()
    require(pdf_sha256 == EXPECTED_PDF_SHA256, "current root PDF SHA-256 mismatch")
    require(current_archived_sha256 == EXPECTED_PDF_SHA256, "current archived PDF SHA-256 mismatch")
    require(previous_archived_sha256 == PREVIOUS_PDF_SHA256, "previous archived PDF SHA-256 mismatch")
    require(manifest["status"] == "published", "publication manifest is not published")
    require(manifest["published"]["doi"] == CURRENT_DOI, "current published DOI mismatch")
    require(manifest["published"]["sha256"] == EXPECTED_PDF_SHA256, "current published manifest hash mismatch")
    require(manifest["published"]["pdf"] == f"publication/zenodo-{CURRENT_RECORD_ID}/Containing-Cyber-Capable-AI-Agents.pdf", "current archive path mismatch")
    previous = manifest.get("previous_publications", [])
    require(any(x.get("doi") == PREVIOUS_DOI and x.get("sha256") == PREVIOUS_PDF_SHA256 for x in previous),
            "previous publication provenance missing")

    readme_markers = (
        "actions/workflows/reproducibility.yml/badge.svg?branch=main",
        "zenodo.org/badge/DOI/10.5281/zenodo.23124432.svg",
        "paper-CC%20BY%204.0",
        "code-MIT",
        "0009--0001--6573--385X",
        "https://doi.org/10.5281/zenodo.23124432",
    )
    for marker in readme_markers:
        require(marker in readme, f"README publication marker missing: {marker}")

    require("October 2026" in tex and ORCID in tex, "paper metadata missing date or ORCID")
    require(TITLE in tex, "paper title mismatch")
    require("Paper license: Creative Commons Attribution 4.0 International (CC BY 4.0)" in tex, "paper front matter license missing")
    require("Companion code license: MIT" in tex, "code license front matter missing")
    require("Revocation and replay semantics" in tex and "revocation state" in tex, "revocation semantics missing")
    require("No machine-checked proof or model-checking artifact" in tex, "mechanized-proof boundary missing")
    require("guardian's safety case" in tex, "guardian safety-case boundary missing")
    for marker in ("MatchDest", "sec:dns-counterexample", "rfc9525", "rfc9113", "owasp-ssrf", "Dipankar Sarkar"):
        require(marker in tex, f"destination-binding revision missing: {marker}")
    require("Current archived publication" in readme and "publication/manifest.json" in readme,
            "README must identify the current archived publication")
    mediation_sentence = "Every consequential external effect is required to cross an independent gate"
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
    version_markers = ("v2.0.0", "Version 2.0.0", "Version 1.2", "Version History", "REVISED-DRAFT", "DNS-Binding-Review", "Destination-binding revision prepared")
    for marker in version_markers:
        require(marker not in tex, f"paper contains version marker: {marker}")
        require(marker not in readme, f"README contains version marker: {marker}")
        require(marker not in cff, f"CITATION.cff contains version marker: {marker}")
    require("version" not in zenodo, "Zenodo metadata should not contain a release version")

    for bad in ("TODO", "TBD", "FIXME"):
        require(not re.search(rf"\b{bad}\b", tex, re.I), f"paper contains {bad}")

    require(zenodo["title"] == TITLE, "Zenodo title mismatch")
    require(zenodo["license"] == "cc-by-4.0", "Zenodo paper license mismatch")
    require(zenodo["publication_type"] == "preprint", "Zenodo publication type mismatch")
    require("doi" not in zenodo and "prereserve_doi" not in zenodo, "Zenodo metadata template must not hard-code an assigned DOI")
    require(zenodo["creators"][0]["orcid"] == ORCID, "Zenodo ORCID mismatch")

    require(f'date-released: "{DATE}"' in cff, "CFF release date mismatch")
    require(ORCID in cff, "CFF ORCID mismatch")
    require(TITLE in cff, "CFF preferred citation title mismatch")

    for stem in FIGURES:
        require(f"figures/{stem}.pdf" in tex, f"paper does not reference {stem}.pdf")

    for marker in ("Commit-Authorization Conformance Theorem", "Endpoint non-substitution lemma", "trace2026", "tackedup2026", "aegis2026", "dogwood2026", "rfc8785"):
        require(marker in tex, f"paper hardening marker missing: {marker}")

    results = json.loads((ROOT / "evaluation/results.json").read_text())
    discovered = unittest.defaultTestLoader.discover(str(ROOT / "tests")).countTestCases()
    require(discovered >= 90, "security test suite unexpectedly small")
    require(results["test_suite"]["discovered_tests"] == discovered, "evaluation test count mismatch")
    require(results["replay_concurrency_stress"]["rounds_with_invariant_failure"] == 0, "replay/concurrency stress invariant failure")
    require(results["live_loopback"]["numeric_probe_reachable"] is True, "live numeric loopback probe failed")
    require(results["live_loopback"]["all_loopback"] is True, "localhost resolution escaped loopback")

    secret_patterns = [
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"github_pat_[A-Za-z0-9_]",
        r"AKIA[0-9A-Z]{16}",
    ]
    scan_ext = {".tex", ".md", ".py", ".json", ".cff", ".dot", ".yml", ".yaml"}
    for path in ROOT.rglob("*"):
        if path.is_file() and path.suffix.lower() in scan_ext and "build" not in path.parts:
            body = path.read_text(errors="ignore")
            for pattern in secret_patterns:
                require(not re.search(pattern, body), f"possible secret material in {path.relative_to(ROOT)}")

    print("RELEASE SURFACE CHECK: PASS")
    tests = unittest.defaultTestLoader.discover(str(ROOT / "tests")).countTestCases()
    print(f"figures={len(FIGURES)} tests={tests} status=published "
          f"published_doi={CURRENT_DOI} "
          "current_and_previous_pdf_sha256=verified")


if __name__ == "__main__":
    main()
