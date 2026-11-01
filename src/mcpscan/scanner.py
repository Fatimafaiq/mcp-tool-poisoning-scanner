"""Staged pipeline: (normalize) -> rule scan -> (uncertain) LLM judge -> verdict."""
from .normalizer import normalize
from .rules import load_rules
from .llm_judge import HeuristicJudge

class RuleScanner:
    def __init__(self, normalize_on=True):
        self.rules, self.t_low, self.t_high, self.flag_w = load_rules()
        self.normalize_on = normalize_on

    def score(self, text):
        if self.normalize_on:
            n = normalize(text)
        else:  # naive baseline: match on raw text, no normalization
            n = {"clean": text or "", "flags": [], "transforms": []}
        s, hits = 0.0, []
        for r in self.rules:
            if r["re"].search(n["clean"]):
                s += r["weight"]; hits.append(r["id"])
        for fl in n["flags"]:
            w = float(self.flag_w.get(fl, 0))
            if w:
                s += w; hits.append("flag:" + fl)
        score = min(1.0, s)
        verdict = "benign" if score <= self.t_low else ("malicious" if score >= self.t_high else "uncertain")
        return {"score": round(score, 3), "verdict": verdict, "hits": hits,
                "transforms": n["transforms"], "flags": n["flags"]}

class Scanner:
    def __init__(self, mode="hybrid", judge=None, normalize_on=True):
        assert mode in ("rule", "llm", "hybrid")
        self.mode = mode
        self.rs = RuleScanner(normalize_on=normalize_on)
        self.judge = judge or HeuristicJudge()
        self.llm_calls = 0

    def _tool(self, text):
        r = self.rs.score(text)
        if self.mode == "rule":
            return {"label": "malicious" if r["verdict"] == "malicious" else "benign", "rule": r, "llm": None}
        if self.mode == "llm":
            self.llm_calls += 1
            j = self.judge.judge(text)
            return {"label": j["label"], "rule": r, "llm": j}
        if r["verdict"] in ("malicious", "benign"):
            return {"label": r["verdict"], "rule": r, "llm": None}
        self.llm_calls += 1
        j = self.judge.judge(text)
        return {"label": j["label"], "rule": r, "llm": j}

    def scan(self, manifest):
        tools = [self._tool(b) for b in manifest.text_blobs()]
        label = "malicious" if any(t["label"] == "malicious" for t in tools) else "benign"
        return {"server": manifest.server, "label": label, "tools": tools}
