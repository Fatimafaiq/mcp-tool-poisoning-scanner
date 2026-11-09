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
PYTHONPATH=src python -m pytest -q     # run the test suite (14 tests)
python scripts/run_eval.py            # run the evaluation -> results.json
python scripts/demo.py                # one-screen demonstration
PYTHONPATH=src python -m mcpscan.cli data/obfuscated --mode hybrid   # scan a folder
```

## Preliminary results (v0.4, offline heuristic judge, frozen test split)
100 manifests (24 benign, 16 benign Unicode controls, 12 plain attacks, 48 obfuscated);
group-wise 40/60 dev/test split, so an attack and its variants never cross the split.

| Detector | Obfuscated recall (95% CI) | Obfuscated F1 | FPR benign | FPR Unicode controls |
|---|---|---|---|---|
| rule, no normalization | 0.036 (0.006 to 0.177) | 0.069 | 0.00 | 0.00 |
| rule, with normalization | 0.964 (0.823 to 0.994) | 0.982 | 0.00 | 0.00 |
| LLM stub only | 0.857 (0.685 to 0.943) | 0.923 | 0.00 | 0.00 |
| hybrid | 0.964 (0.823 to 0.994) | 0.982 | 0.00 | 0.00 |

Normalization lifts obfuscated recall from 3.6% to 96.4% (exact McNemar p < 0.001).
End-to-end ASR on the test split: 1.00 (scanner off) -> 0.057 (hybrid on).
v0.3 blocked 3 of 16 legitimate Unicode tools (FPR 0.188); v0.4 blocks none.
See `docs/testing_and_limitations.md` for the iteration log and limitations.

## Interactive demo
`demo/index.html` runs the same scanner in the browser (a line-for-line port, checked identical to the
Python code on all 100 manifests). Open it directly for the rule stage and offline stub judge; open the
published Claude artifact to use Claude as a live LLM-as-judge and save benchmark runs. Screenshots are in
`docs/screenshots/`.

## Safety
All malicious manifests are **inert strings** targeting only a local `.local` sink. No real
system, credential or network endpoint is touched.

## Repo layout
`src/mcpscan` core · `data` benchmark generator · `mock_agent` ASR harness ·
`scripts` eval + demo · `tests` manual + AI-generated · `docs` architecture, testing, limitations.

## GitHub
Repository: https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner (commit history is the development record).
