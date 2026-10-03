# Containing Cyber-Capable AI Agents

[![Reproducibility](https://github.com/codethor0/ccaa/actions/workflows/reproducibility.yml/badge.svg)](https://github.com/codethor0/ccaa/actions/workflows/reproducibility.yml)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23113152.svg)](https://doi.org/10.5281/zenodo.23113152)

**Incident Evidence, Formal Safety Conditions, and a Reference Architecture for Bounded Autonomous Cyber Evaluation**

Thor Thor  
Independent Open-Source Researcher, THOR-SEC  
ORCID: 0009-0001-6573-385X

October 2, 2026

## Status

This repository contains the publication source and reproducibility artifacts for *Containing Cyber-Capable AI Agents*.

Archival deposit: https://doi.org/10.5281/zenodo.23113152 (CC BY 4.0). The committed `Containing-Cyber-Capable-AI-Agents.pdf` is the exact byte-identical artifact deposited on Zenodo (SHA-256 `0d11db683fe9f9eed585eb29854b02940bdf056e21d7a00ce4ce6e106460db1d`).

The paper is a public-source technical analysis and reference design. It is not peer reviewed, does not claim deployed-system validation, and does not claim that any specific real-world system implements the proposed architecture.

## Scope and contributions

The paper:

- reconstructs the public incident record through October 2, 2026;
- incorporates Anthropic's September reassessment and fourth disclosed incident;
- incorporates OpenAI's August 26 technical report and the METR/Redwood independent investigation;
- includes AISI's permitted-internet incident as a distinct containment failure class;
- treats shared writable infrastructure and unauthorized cross-run communication as first-class containment threats;
- replaces stateless action-only policy with state-bound, commit-time authorization;
- separates prevention, containment, and recovery guarantees;
- makes destination/service binding, stale authorization, revocation, budget races, run epochs, and policy versions explicit;
- includes seven publication diagrams rebuilt from editable Graphviz source;
- includes a dependency-free preflight validator and 12 unit tests;
- states explicit limitations and non-claims.

## Core security claim

The formal result is conditional. Under the paper's stated assumptions, a prohibited external effect is unreachable when every effect-capable action is completely mediated and the effect gate atomically revalidates the exact request, current scope, run epoch, policy, state generation, budget, destination binding, revocation state, and short-lived authorization at commit time.

The paper does **not** claim that a model-based guardian alone proves containment. It also does not claim a machine-checked proof or TLA+ model-checking result; the formal theorem is an architectural implication under explicit proof obligations.

## Repository layout

- `paper.tex` - publication source
- `Containing-Cyber-Capable-AI-Agents.pdf` - compiled paper
- `abstract.txt` - plain-text abstract
- `figures/*.dot` - editable Graphviz source for all figures
- `figures/*.pdf` - vector figures used in the paper
- `scripts/agent_eval_preflight.py` - dependency-free preflight validator
- `tests/test_preflight.py` - standard-library unit tests
- `examples/agent_eval_scope.example.json` - example scope manifest
- `scripts/check_release.py` - publication/repository consistency checks
- `CITATION.cff` - citation metadata
- `.zenodo.json` - Zenodo deposit metadata; intentionally contains no DOI before deposit

## Reproduce

Requirements:

- Python 3.10+
- Graphviz
- `latexmk`
- a TeX Live installation containing the packages used by `paper.tex`

Run:

```bash
make check
make all
```

`make check` runs the validator unit tests and release-surface checks. `make all` regenerates the vector figures and builds the paper.

## Validator boundary

The preflight validator is a diagnostic release gate, not a proof of isolation. A successful run does not prove the absence of arbitrary egress, future DNS changes, hidden credentials, host compromise, or runtime drift. Those properties require independent runtime enforcement as described in the paper.

## Citation

Cite the archival deposit:

> Thor, T. (2026). *Containing Cyber-Capable AI Agents: Incident Evidence, Formal Safety Conditions, and a Reference Architecture for Bounded Autonomous Cyber Evaluation* [Preprint]. https://doi.org/10.5281/zenodo.23113152

## Licenses

The paper text, abstract, and figures are licensed under Creative Commons Attribution 4.0 International. See `LICENSE-PAPER.md`.

The validator, tests, CI configuration, and build tooling are licensed under the MIT License. See `LICENSE-CODE`.

This repository intentionally contains no live credentials, undisclosed incident artifacts, victim identifiers, or weaponized exploit payloads.
