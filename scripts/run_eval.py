import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
from mcpscan.schema import load_manifest
from mcpscan.scanner import Scanner
sys.path.insert(0, os.path.join(ROOT, "mock_agent"))
from harness import asr

DATA = os.path.join(ROOT, "data")

def load():
    idx = json.load(open(os.path.join(DATA, "index.json")))
    out = []
    for row in idx:
        m = load_manifest(os.path.join(DATA, row["path"]))
        m.label, m.variant, m.base_id = row["label"], row["variant"], row["base_id"]
        out.append(m)
    return out

def metrics(scanner, manifests):
    tp = fp = tn = fn = 0
    for m in manifests:
        pred = scanner.scan(m)["label"]
        if m.label == "malicious":
            tp += pred == "malicious"; fn += pred != "malicious"
        else:
            fp += pred == "malicious"; tn += pred != "malicious"
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(precision=round(prec, 3), recall=round(rec, 3), f1=round(f1, 3),
                fpr=round(fpr, 3), tp=tp, fp=fp, tn=tn, fn=fn)

def main():
    M = load()
    benign = [m for m in M if m.label == "benign"]
    mal_plain = [m for m in M if m.label == "malicious" and m.variant == "plain"]
    mal_obf = [m for m in M if m.label == "malicious" and m.variant == "obfuscated"]
    detectors = {
        "rule_no_norm": Scanner("rule", normalize_on=False),
        "rule_norm":    Scanner("rule", normalize_on=True),
        "llm_stub":     Scanner("llm"),
        "hybrid":       Scanner("hybrid"),
    }
    results = {"counts": {"benign": len(benign), "mal_plain": len(mal_plain), "mal_obf": len(mal_obf)}, "detectors": {}}
    print(f"dataset: benign={len(benign)}  malicious_plain={len(mal_plain)}  malicious_obfuscated={len(mal_obf)}\n")
    header = f"{'detector':14}{'subset':10}{'recall':>8}{'precision':>11}{'f1':>7}{'fpr':>7}"
    print(header); print("-" * len(header))
    for name, sc in detectors.items():
        row = {}
        for subset, items in [("plain", benign + mal_plain), ("obfuscated", benign + mal_obf)]:
            sc.llm_calls = 0
            m = metrics(sc, items)
            row[subset] = m
            print(f"{name:14}{subset:10}{m['recall']:>8}{m['precision']:>11}{m['f1']:>7}{m['fpr']:>7}")
        results["detectors"][name] = row
    # end-to-end ASR (all malicious, plain + obfuscated)
    allmal_env = benign + mal_plain + mal_obf
    asr_off, s0, n0 = asr(allmal_env, None)
    asr_on, s1, n1 = asr(allmal_env, detectors["hybrid"])
    results["asr"] = {"off": round(asr_off, 3), "on": round(asr_on, 3),
                      "prevention_rate": round(1 - (asr_on / asr_off if asr_off else 0), 3),
                      "attacks": n0}
    print(f"\nEnd-to-end ASR (hybrid):  off={asr_off:.3f}  on={asr_on:.3f}  "
          f"prevention_rate={results['asr']['prevention_rate']:.3f}  (n={n0} attacks)")
    out = os.path.join(ROOT, "results.json")
    json.dump(results, open(out, "w"), indent=2)
    print(f"\nsaved {out}")

if __name__ == "__main__":
    main()
