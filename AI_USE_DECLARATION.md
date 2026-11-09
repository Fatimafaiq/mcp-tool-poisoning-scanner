# GenAI use declaration

GenAI was used as an assistant. Every output was human-reviewed and tested before inclusion,
in line with the unit's academic-integrity policy. AI used **inside** the system is separated
from AI used to **help build** it.

| Where | Tool | What it did | How verified |
|---|---|---|---|
| Inside the system | Claude (web demo), Ollama adapter, offline stub | Classifies uncertain manifests with a versioned prompt that marks tool text as untrusted | Measured against the labelled benchmark; demo runs saved for citation |
| Browser port (v0.4) | Claude | Ported the Python scanner to JavaScript for `demo/index.html` | Checked identical to Python on all 100 manifests (score, verdict, rule hits, cleaned text) |
| Iteration (v0.4) | Claude | Proposed the Unicode control set and the false-positive fix | Team reviewed; 3 regression tests fail on v0.3 and pass on v0.4 |
| Code scaffolding | GenAI assistant | Drafted module skeletons and the eval harness | Executed, unit-tested, reviewed by the author |
| Test generation | GenAI assistant | Drafted `tests/test_ai_generated.py` (edge cases) | Run in CI; compared against the manual suite |
| Drafting / editing | GenAI assistant | Rewrote prose in README and docs | Author checked facts and figures |

The LLM-as-judge system prompt is version-controlled in `src/mcpscan/llm_judge.py` (`PROMPT`)
so the AI component is reproducible, not a hidden step.
