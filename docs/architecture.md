# Architecture detail

## Data flow and error paths
`manifest -> normalizer -> rule scanner -> router -> [uncertain] LLM-as-judge -> aggregator -> verdict`

Fail-closed policy: a manifest that cannot be parsed, or an LLM call that times out or exceeds a
cost cap, results in the tool being **withheld** from the agent, never passed through.

## Component interfaces
| Component | Interface (input -> output) | External API | Error handling |
|---|---|---|---|
| Manifest loader | `load_manifest(path) -> Manifest` | MCP tools/list (JSON-RPC 2.0) | parse error -> quarantine |
| Normalizer | `normalize(text) -> {clean, transforms, flags}` | - | oversize/decode error -> flag + raw |
| Rule scanner | `score(text) -> {score, verdict, hits}` | - | internal error -> 'uncertain' (escalate) |
| LLM judge | `judge(text) -> {label, confidence, rationale}` | Ollama `/api/chat` or OpenAI-compatible | timeout -> retry x3 -> rule verdict |
| Scanner | `scan(manifest) -> {label, tools[]}` | - | more-restrictive label wins on conflict |
| Mock agent | `asr(manifests, scanner) -> (rate, s, n)` | - | logs any sink call as a success |

## Deployment dependencies
Python 3.11, PyYAML; optional Ollama + local model, a hosted LLM API key, scikit-learn/SciPy,
Streamlit. Packaged to run on a single machine; the local-only configuration has no network egress.
