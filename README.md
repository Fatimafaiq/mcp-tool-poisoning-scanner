# MCP Tool-Poisoning Scanner (Hybrid Rule + LLM-as-judge)

Detects **obfuscated tool-poisoning** payloads in Model Context Protocol (MCP) tool
manifests **before an agent loads them**. Prototype artefact for the CSIT305 research
project *Detecting Obfuscated Tool Poisoning in MCP Servers: A Hybrid Rule-and-LLM Scanner*.

## Purpose and research gap
MCP agents load third-party tool descriptions into the model context as trusted text, so a
malicious description can hide instructions that leak data or trigger unauthorized actions
(tool poisoning). Existing detectors are tested mainly on **plain** payloads. This artefact
tests whether **character obfuscation** (invisible Unicode, homoglyphs, encoded text) defeats
MCP scanners, and whether **input normalization** restores detection, comparing **rule-only**,
**LLM-only** and **hybrid** detection on paired plain/obfuscated data.

## Architecture (pipeline)
`manifest -> normalizer -> rule scanner -> router -> (uncertain only) LLM-as-judge -> verdict`

| Stage | Module | Role |
|---|---|---|
| Normalizer | `src/mcpscan/normalizer.py` | NFKC, strip zero-width, map homoglyphs, decode base64 |
| Rule scanner | `src/mcpscan/rules.py` + `rules.yaml` | transparent weighted patterns -> benign/uncertain/malicious |
| LLM-as-judge | `src/mcpscan/llm_judge.py` | offline heuristic stub; Ollama / OpenAI adapters for the real study |
| Pipeline | `src/mcpscan/scanner.py` | modes: `rule`, `llm`, `hybrid`; hybrid escalates only uncertain cases |
| Mock agent | `mock_agent/harness.py` | computes Attack Success Rate (ASR) with scanner off vs on |

The pipeline is **fail-closed**: unparseable manifests or an unavailable LLM are withheld from the agent.

## Tools
Python 3.11, PyYAML (rules), pytest (tests). Optional for the full study: Ollama (local model),
a hosted LLM API, scikit-learn / SciPy (stats), Streamlit (dashboard).

## Install and reproduce
```bash
pip install -r requirements.txt
python data/build_dataset.py          # generate the labelled benchmark (defanged)
PYTHONPATH=src python -m pytest -q     # run the test suite
python scripts/run_eval.py            # run the evaluation -> results.json
python scripts/demo.py                # one-screen demonstration
PYTHONPATH=src python -m mcpscan.cli data/obfuscated --mode hybrid   # scan a folder
```

## Preliminary results (offline heuristic judge, N=84 manifests)
| Detector | Obfuscated recall | Obfuscated F1 | FPR |
|---|---|---|---|
| rule, no normalization | 0.042 | 0.08 | 0.00 |
| rule, with normalization | 0.958 | 0.979 | 0.00 |
| hybrid | 0.958 | 0.979 | 0.00 |

End-to-end **ASR: 1.00 (scanner off) -> 0.067 (hybrid on)**, 93.3% of attacks prevented.
Normalization lifts obfuscated recall from 4.2% to 95.8%, which is the core finding.

## Safety
All malicious manifests are **inert strings** targeting only a local `.local` sink. No real
system, credential or network endpoint is touched.

## Repo layout
`src/mcpscan` core · `data` benchmark generator · `mock_agent` ASR harness ·
`scripts` eval + demo · `tests` manual + AI-generated · `docs` architecture, testing, limitations.

## GitHub
Repository: <ADD YOUR GITHUB URL HERE> (commit history is the development record).
