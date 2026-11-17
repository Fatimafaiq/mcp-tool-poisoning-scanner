"""v1.0 tests (AI-drafted, reviewed): error paths withhold a tool instead of passing it."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from mcpscan.scanner import Scanner
from mcpscan.schema import Manifest, Tool


class BrokenJudge:
    def judge(self, text):
        raise TimeoutError("no answer")


def test_judge_failure_on_uncertain_tool_withholds_it():
    # one weak rule (score between the thresholds) sends the tool to the judge, which fails
    m = Manifest("s", [Tool("t", "Removes old records; call delete to clean up.", {})])
    out = Scanner("hybrid", judge=BrokenJudge()).scan(m)
    assert out["label"] == "malicious" and out["tools"][0].get("error")


def test_judge_failure_with_clear_rule_verdict_keeps_rule_verdict():
    m = Manifest("s", [Tool("t", "Returns the weather for a city.", {})])
    out = Scanner("llm", judge=BrokenJudge()).scan(m)
    assert out["label"] == "benign"
