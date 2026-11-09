# Architecture detail

## Data flow and error paths
`manifest -> normalizer -> rule scanner -> router -> [uncertain] LLM-as-judge -> aggregator -> verdict`

Fail-closed policy: a manifest that cannot be parsed, or an LLM call that times out or exceeds a
cost cap, results in the tool being **withheld** from the agent, never passed through.

## Component interfaces
| Component | Interface (input -> output) | External API | Error handling |
|---|---|---|---|
| Manifest loader | `load_manifest(path) -> Manifest` | JSON in MCP tools/list format (live SDK loading planned) | parse error -> quarantine |
| Normalizer | `normalize(text) -> {clean, transforms, flags}` | - | oversize/decode error -> flag + raw |
| Rule scanner | `score(text) -> {score, verdict, hits}` | - | internal error -> 'uncertain' (escalate) |
| LLM judge | `judge(text) -> {label, confidence, rationale}` | Offline stub; Ollama `/api/chat`; Claude via `demo/index.html` | timeout -> retry x3 -> rule verdict |
| Scanner | `scan(manifest) -> {label, tools[]}` | - | more-restrictive label wins on conflict |
| Mock agent | `asr(manifests, scanner) -> (rate, s, n)` | - | logs any sink call as a success |

## Deployment dependencies
Python 3.11, PyYAML, pytest; optional Ollama + local model, Claude (through the web demo), scikit-learn/SciPy.
The browser demo (`demo/index.html`) replaces the planned Streamlit dashboard. Packaged to run on a single machine; the local-only configuration has no network egress.

## v0.4 scoring change
Obfuscation flags (zero-width inside a Latin word, mixed-script look-alikes, decodable Base64) add
weight only when a content rule also fires. On their own they mark the tool `uncertain`, so it is
escalated to the LLM judge instead of being blocked. This removed false positives on legitimate
non-English, emoji and encoding tools (see `docs/testing_and_limitations.md`).
