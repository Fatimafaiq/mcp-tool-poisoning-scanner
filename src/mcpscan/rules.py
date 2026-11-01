import re, os, yaml
RULES_PATH = os.path.join(os.path.dirname(__file__), "rules.yaml")

def load_rules(path=RULES_PATH):
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    rules = [{"id": r["id"], "weight": float(r["weight"]), "desc": r.get("desc", ""),
              "re": re.compile(r["pattern"], re.I)} for r in data["rules"]]
    return (rules, float(data.get("t_low", 0.2)), float(data.get("t_high", 0.5)),
            data.get("flag_weights", {}))
