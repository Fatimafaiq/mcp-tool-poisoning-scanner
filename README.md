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
PYTHONPATH=src python -m pytest -q     # run the test suite (25 pass, 1 known limitation)
python scripts/run_eval.py            # synthetic benchmark -> results.json

# real MCP data (MCPTox, AAAI 2026)
git clone https://github.com/zhiqiangwang4/MCPTox-Benchmark data/external/MCPTox-Benchmark
python scripts/build_real_dataset.py  # 2,787 real manifests, defanged -> data/real/
python scripts/run_real_eval.py       # dev/test by server, v0.4 vs v0.6 -> results_real.json

# real MCP server files (published attacks + official servers), see docs/USAGE_GUIDE.md
python scripts/scan_file.py path/to/server.py_or_folder
python scripts/run_realfiles_eval.py  # -> results_realfiles.json
python scripts/demo.py                # one-screen demonstration
PYTHONPATH=src python -m mcpscan.cli data/obfuscated --mode hybrid   # scan a folder
```

## Results on real MCP data (v0.6)
MCPTox (Wang et al., AAAI 2026): real tool descriptions from 45 live MCP servers and 485 real
poisoned descriptions, plus our obfuscated copies. Split by server (40% dev, 60% test, seed 305);
attack rules were written from the dev servers only. Test set: 27 unseen servers.

| Detector (test servers) | Recall, real attacks (95% CI) | Recall, obfuscated | FPR, real tools |
|---|---|---|---|
| v0.4 rules + normalisation | 0.008 (0.002 to 0.027) | 0.069 | 0.000 |
| v0.6 rules, no normalisation | 0.592 | 0.149 | 0.000 |
| v0.6 rules + normalisation | 0.592 (0.532 to 0.650) | 0.785 | 0.000 |

## Results on real MCP server files (v0.6)
48 real source files, read as text: Invariant Labs' published tool-poisoning attacks, Damn
Vulnerable MCP Server (15 challenges) and the official reference servers. 7 tools are poisoned
(hand-labelled from each project's documentation), 138 are benign. No rule was written from these files.

| Detector | Poisoned tools caught | Disguised copies caught | Benign tools blocked |
|---|---|---|---|
| Rules, no normalisation | 2/7 | 1/28 | 2/138 |
| Rules + normalisation | 2/7 | 19/28 | 2/138 |
| Hybrid (offline stub judge) | 5/7 | 20/28 | 2/138 |

Missed: the WhatsApp rug pull ("make sure to change the recipient...") and a DVMCP tool that orders
a second tool call after the main one. Blocked by mistake: the official filesystem server's
`read_text_file` ("Use this tool when you need to examine...", see the known-limitation test) and a
DVMCP challenge tool that describes the attack. The live Claude judge in the demo is the next measurement.

## Synthetic benchmark results (v0.6, offline heuristic judge, frozen test split)
100 manifests (24 benign, 16 benign Unicode controls, 12 plain attacks, 48 obfuscated);
group-wise 40/60 dev/test split, so an attack and its variants never cross the split.

| Detector | Obfuscated recall (95% CI) | Obfuscated F1 | FPR benign | FPR Unicode controls |
|---|---|---|---|---|
| rule, no normalization | 0.071 (0.020 to 0.226) | 0.133 | 0.00 | 0.00 |
| rule, with normalization | 0.964 (0.823 to 0.994) | 0.982 | 0.00 | 0.00 |
| LLM stub only | 0.857 (0.685 to 0.943) | 0.923 | 0.00 | 0.00 |
| hybrid | 0.964 (0.823 to 0.994) | 0.982 | 0.00 | 0.00 |

Normalization lifts obfuscated recall from 7.1% to 96.4% (3.6% with the v0.4 rules) (exact McNemar p < 0.001).
End-to-end ASR on the test split: 1.00 (scanner off) -> 0.057 (hybrid on).
v0.3 blocked 3 of 16 legitimate Unicode tools (FPR 0.188); v0.4 blocks none.
See `docs/testing_and_limitations.md` for the iteration log and limitations.

## Interactive demo
`demo/index.html` runs the same scanner in the browser (a line-for-line port, checked identical to the
Python code on all 2,887 manifests and the file reader on 260 real files). Open it directly to scan real
server files (Scan server files tab) and use the rule stage with the offline stub judge; the published Claude artifact also contains the real MCPTox data and uses Claude as a
live LLM-as-judge with saved benchmark runs. Step-by-step instructions: `docs/USAGE_GUIDE.md`. Screenshots are in
`docs/screenshots/`.

## Safety
All malicious manifests are **inert strings** targeting only a local `.local` sink (real MCPTox attacks are defanged the same way when built). No real
system, credential or network endpoint is touched.

## Repo layout
`src/mcpscan` core · `data` benchmark generator · `mock_agent` ASR harness ·
`scripts` eval + demo · `tests` manual + AI-generated · `docs` architecture, testing, limitations.

## GitHub
Repository: https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner (commit history is the development record).
