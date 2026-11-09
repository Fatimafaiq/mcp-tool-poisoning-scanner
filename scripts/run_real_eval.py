"""Evaluation on real MCP data (MCPTox). Run scripts/build_real_dataset.py first.

v0.4 rules were written on the synthetic benchmark only, so for them the whole real set is unseen.
v0.5 rules were added after looking ONLY at the dev servers (40% of the 45 servers, seed 305);
the 27 test servers were not looked at until the rules were frozen. Reports recall on real attacks
(plain and per obfuscation type), false-positive rate on real tool descriptions, Wilson 95%
intervals, exact McNemar tests (v0.4 vs v0.5 rules), and how many misses reach the LLM judge.
"""
import os, sys, json, random
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)
from mcpscan.schema import Manifest, Tool
from mcpscan.scanner import Scanner
from mcpscan.rules import load_rules
from run_eval import wilson, mcnemar_exact

PATH = os.path.join(ROOT, "data", "real", "mcptox_manifests.json")
OUT = os.path.join(ROOT, "results_real.json")
V04_RULES = os.path.join(ROOT, "src", "mcpscan", "rules_v0_4.yaml")
SEED, DEV_FRAC = 305, 0.40


def load():
    rows = json.load(open(PATH, encoding="utf-8"))
    M = []
    for r in rows:
        m = Manifest(r["server"], [Tool(t["name"], t["description"], t.get("parameters", {})) for t in r["tools"]],
                     r["label"], r["base_id"], r["variant"])
        m.obfuscation = r.get("obfuscation", "none")
        M.append(m)
    return M


def rate(pred, items):
    k = sum(pred[id(m)] for m in items)
    return {"k": k, "n": len(items), "rate": round(k / len(items), 3) if items else None, "ci": wilson(k, len(items))}


def split_servers(M):
    servers = sorted({m.server for m in M})
    random.Random(SEED).shuffle(servers)
    dev = set(servers[:round(DEV_FRAC * len(servers))])
    return [m for m in M if m.server in dev], [m for m in M if m.server not in dev], sorted(dev)


def v04(mode, **kw):
    sc = Scanner(mode, **kw)
    sc.rs.rules, sc.rs.t_low, sc.rs.t_high, sc.rs.flag_w = load_rules(V04_RULES)
    return sc


def evaluate(detectors, M):
    benign = [m for m in M if m.label == "benign"]
    plain = [m for m in M if m.label == "malicious" and m.variant == "plain"]
    obf = [m for m in M if m.label == "malicious" and m.variant == "obfuscated"]
    kinds = sorted({m.obfuscation for m in obf})
    out, preds, routes = {}, {}, {}
    for name, sc in detectors.items():
        sc.llm_calls = 0
        p, r = {}, {}
        for m in M:
            res = sc.scan(m)
            p[id(m)] = res["label"] == "malicious"
            r[id(m)] = any(t["llm"] is not None for t in res["tools"]) if "tools" in res else False
        preds[name], routes[name] = p, r
        tp, fp = sum(p[id(m)] for m in obf), sum(p[id(m)] for m in benign)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / len(obf) if obf else 0.0
        missed = [m for m in plain + obf if not p[id(m)]]
        out[name] = {
            "recall_plain": rate(p, plain), "recall_obfuscated": rate(p, obf),
            "recall_by_obfuscation": {k: rate(p, [m for m in obf if m.obfuscation == k]) for k in kinds},
            "fpr_real_benign": rate(p, benign),
            "precision_obf": round(prec, 3), "f1_obf": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0,
            "judge_call_share": round(sc.llm_calls / len(M), 3) if sc.mode != "rule" else 0.0,
            "missed_attacks_sent_to_judge": round(sum(1 for m in missed if routes[name][id(m)] or sc.rs.score(m.text_blobs()[0])["verdict"] == "uncertain") / len(missed), 3) if missed else None,
        }
    n = {"benign_real": len(benign), "attacks_real": len(plain), "attacks_obfuscated": len(obf),
         "servers": len({m.server for m in M})}
    return out, preds, n, plain, obf, benign


def main():
    M = load()
    dev, test, dev_servers = split_servers(M)
    res = {"source": "MCPTox (Wang et al., AAAI 2026), defanged", "seed": SEED, "dev_servers": dev_servers}
    for part, items in (("all", M), ("dev", dev), ("test", test)):
        dets = {"v0.4_rule_no_norm": v04("rule", normalize_on=False), "v0.4_rule_norm": v04("rule"),
                "v0.4_hybrid": v04("hybrid"), "v0.5_rule_no_norm": Scanner("rule", normalize_on=False),
                "v0.5_rule_norm": Scanner("rule"), "v0.5_hybrid": Scanner("hybrid")}
        out, preds, n, plain, obf, benign = evaluate(dets, items)
        res[part] = {"n": n, "detectors": out}
        if part == "test":
            def paired(a, b, xs):
                x = sum(1 for m in xs if preds[a][id(m)] and not preds[b][id(m)])
                y = sum(1 for m in xs if preds[b][id(m)] and not preds[a][id(m)])
                return {"a_only": x, "b_only": y, "p_value": mcnemar_exact(x, y)}
            res["test"]["mcnemar"] = {
                "v0.5_rule_norm_vs_v0.4_rule_norm (plain)": paired("v0.5_rule_norm", "v0.4_rule_norm", plain),
                "v0.5_rule_norm_vs_v0.4_rule_norm (obfuscated)": paired("v0.5_rule_norm", "v0.4_rule_norm", obf),
                "v0.5_rule_norm_vs_v0.5_rule_no_norm (obfuscated)": paired("v0.5_rule_norm", "v0.5_rule_no_norm", obf)}
            res["test"]["missed_plain_examples"] = [
                {"server": m.server, "tool": m.tools[0].name, "text": m.tools[0].description[:240]}
                for m in plain if not preds["v0.5_hybrid"][id(m)]][:15]
            res["test"]["false_positive_examples"] = [
                {"server": m.server, "tool": m.tools[0].name, "text": m.tools[0].description[:240]}
                for m in benign if preds["v0.5_hybrid"][id(m)]]
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    for part in ("dev", "test"):
        n = res[part]["n"]
        print(f"\n[{part}] {n['servers']} servers: {n['benign_real']} real benign tools, {n['attacks_real']} real attacks, "
              f"{n['attacks_obfuscated']} obfuscated variants")
        print(f"{'detector':20} {'recall plain':>12} {'recall obf':>11} {'FPR benign':>11} {'F1 obf':>7} {'to judge':>9}")
        for name, d in res[part]["detectors"].items():
            print(f"{name:20} {d['recall_plain']['rate']:>12} {d['recall_obfuscated']['rate']:>11} "
                  f"{d['fpr_real_benign']['rate']:>11} {d['f1_obf']:>7} {d['judge_call_share']:>9}")
    print("\nv0.5 rule_norm recall by obfuscation (test):",
          {k: v["rate"] for k, v in res["test"]["detectors"]["v0.5_rule_norm"]["recall_by_obfuscation"].items()})
    print("McNemar (test):", json.dumps(res["test"]["mcnemar"]))
    print(f"\nwrote {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
