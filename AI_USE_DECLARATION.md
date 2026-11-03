# GenAI use declaration

GenAI was used as an assistant. Every output was human-reviewed and tested before inclusion,
in line with the unit's academic-integrity policy. AI used **inside** the system is separated
from AI used to **help build** it.

| Where | Tool | What it did | How verified |
|---|---|---|---|
| Inside the system | hosted + local LLM (judge) | Classifies uncertain manifests (versioned prompt) | Measured against the labelled benchmark; stub used offline |
| Code scaffolding | GenAI assistant | Drafted module skeletons and the eval harness | Executed, unit-tested, reviewed by the author |
| Test generation | GenAI assistant | Drafted `tests/test_ai_generated.py` (edge cases) | Run in CI; compared against the manual suite |
| Drafting / editing | GenAI assistant | Rewrote prose in README and docs | Author checked facts and figures |

The LLM-as-judge system prompt is version-controlled in `src/mcpscan/llm_judge.py` (`PROMPT`)
so the AI component is reproducible, not a hidden step.
