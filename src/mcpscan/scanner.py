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
        content_hit = bool(hits)
        flag_s = 0.0
        for fl in n["flags"]:
            w = float(self.flag_w.get(fl, 0))
            if w:
                flag_s += w; hits.append("flag:" + fl)
        # v0.4: obfuscation is corroborating evidence only. It adds weight when a content rule
        # also fires; on its own it can only escalate the tool to the judge ("uncertain").
        if content_hit:
            s += flag_s
        score = min(1.0, s)
        verdict = "benign" if score <= self.t_low else ("malicious" if score >= self.t_high else "uncertain")
        if not content_hit and flag_s > 0:
            verdict = "uncertain"
        return {"score": round(score, 3), "verdict": verdict, "hits": hits,
                "transforms": n["transforms"], "flags": n["flags"]}

class Scanner:
    def __init__(self, mode="hybrid", judge=None, normalize_on=True):
        assert mode in ("rule", "llm", "hybrid")
        self.mode = mode
        self.rs = RuleScanner(normalize_on=normalize_on)
        self.judge = judge or HeuristicJudge()
        self.llm_calls = 0

    # Fail closed (v1.0): any error in a stage withholds the tool instead of passing it.
    WITHHELD = {"label": "malicious", "error": True}

    def _judge(self, text, r):
        self.llm_calls += 1
        try:
            j = self.judge.judge(text)
            if j.get("label") not in ("malicious", "benign"):
                raise ValueError("judge returned no label")
            return {"label": j["label"], "rule": r, "llm": j}
        except Exception as e:  # timeout, bad JSON, network: fall back to a decisive rule verdict, else withhold
            if r and r.get("verdict") in ("malicious", "benign"):
                return {"label": r["verdict"], "rule": r, "llm": None, "error": f"judge failed: {e}"}
            return {**self.WITHHELD, "rule": r, "llm": None, "reason": f"judge failed: {e}"}

    def _tool(self, text):
        try:
            r = self.rs.score(text)
        except Exception as e:  # rule error: escalate to the judge; if that fails too, withhold
            r = {"score": None, "verdict": "uncertain", "hits": [], "error": str(e)}
            if self.mode == "rule":
                return {**self.WITHHELD, "rule": r, "llm": None, "reason": f"rule error: {e}"}
        if self.mode == "rule":
            return {"label": "malicious" if r["verdict"] == "malicious" else "benign", "rule": r, "llm": None}
        if self.mode == "llm":
            return self._judge(text, r)
        if r["verdict"] in ("malicious", "benign"):
            return {"label": r["verdict"], "rule": r, "llm": None}
        return self._judge(text, r)

    def scan(self, manifest):
        tools = [self._tool(b) for b in manifest.text_blobs()]
        label = "malicious" if any(t["label"] == "malicious" for t in tools) else "benign"
        return {"server": manifest.server, "label": label, "tools": tools}
