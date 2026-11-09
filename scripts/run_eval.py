"""Evaluation harness (v0.4).

Adds to v0.3: benign Unicode controls (false-positive edge case), a frozen group-wise
40/60 dev/test split, Wilson 95% confidence intervals, an exact McNemar test for paired
detector comparisons, a flag ablation, and measured latency per manifest.
"""
import os, sys, json, time, random, math
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
from mcpscan.schema import load_manifest
from mcpscan.scanner import Scanner
sys.path.insert(0, os.path.join(ROOT, "mock_agent"))
from harness import asr

DATA = os.path.join(ROOT, "data")
SEED, DEV_FRAC = 305, 0.40


def load():
    idx = json.load(open(os.path.join(DATA, "index.json"), encoding="utf-8"))
    out = []
    for row in idx:
        m = load_manifest(os.path.join(DATA, row["path"]))
        m.label, m.variant, m.base_id = row["label"], row["variant"], row["base_id"]
        out.append(m)
    return out


def split(M):
    """Group-wise split by base_id: an attack and all its obfuscated variants stay together."""
    rng = random.Random(SEED)
    test_ids = set()
    for group in ("benign_plain", "control", "malicious"):
        ids = sorted({m.base_id for m in M if _group(m) == group})
        rng.shuffle(ids)
        test_ids.update(ids[int(round(DEV_FRAC * len(ids))):])
    return [m for m in M if m.base_id not in test_ids], [m for m in M if m.base_id in test_ids]


def _group(m):
    if m.label == "malicious":
        return "malicious"
    return "control" if m.variant == "unicode_control" else "benign_plain"


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 3), round(min(1.0, c + h), 3))


def mcnemar_exact(b, c):
    """Two-sided exact McNemar p-value from discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return float(f"{min(1.0, 2 * p):.3g}")


def predict(scanner, items):
    return {id(m): scanner.scan(m)["label"] == "malicious" for m in items}


def summarise(scanner, M):
    benign = [m for m in M if _group(m) == "benign_plain"]
    controls = [m for m in M if _group(m) == "control"]
    mp = [m for m in M if m.label == "malicious" and m.variant == "plain"]
    mo = [m for m in M if m.label == "malicious" and m.variant == "obfuscated"]
    pred = predict(scanner, M)
    tp_p = sum(pred[id(m)] for m in mp)
    tp_o = sum(pred[id(m)] for m in mo)
    fp_b = sum(pred[id(m)] for m in benign)
    fp_c = sum(pred[id(m)] for m in controls)
    neg = len(benign) + len(controls)
    prec_o = tp_o / (tp_o + fp_b + fp_c) if tp_o + fp_b + fp_c else 0.0
    rec_o = tp_o / len(mo) if mo else 0.0
    f1_o = 2 * prec_o * rec_o / (prec_o + rec_o) if prec_o + rec_o else 0.0
    return {
        "n": {"benign": len(benign), "controls": len(controls), "mal_plain": len(mp), "mal_obf": len(mo)},
        "recall_plain": round(tp_p / len(mp), 3) if mp else None, "recall_plain_ci": wilson(tp_p, len(mp)),
        "recall_obf": round(rec_o, 3), "recall_obf_ci": wilson(tp_o, len(mo)),
        "precision_obf": round(prec_o, 3), "f1_obf": round(f1_o, 3),
        "fpr_benign": round(fp_b / len(benign), 3) if benign else None, "fpr_benign_ci": wilson(fp_b, len(benign)),
        "fpr_controls": round(fp_c / len(controls), 3) if controls else None, "fpr_controls_ci": wilson(fp_c, len(controls)),
        "fpr_all": round((fp_b + fp_c) / neg, 3) if neg else None,
    }, pred


def latency_ms(scanner, M, repeats=30):
    t0 = time.perf_counter()
    for _ in range(repeats):
        for m in M:
            scanner.scan(m)
    return round(1000 * (time.perf_counter() - t0) / (repeats * len(M)), 4)


def main():
    M = load()
    dev, test = split(M)
    noflags = Scanner("rule", normalize_on=True)
    noflags.rs.flag_w = {}  # ablation: normalization cleans text but obfuscation earns no weight
    detectors = {
        "rule_no_norm": Scanner("rule", normalize_on=False),
        "rule_norm": Scanner("rule", normalize_on=True),
        "rule_norm_noflags": noflags,
        "llm_stub": Scanner("llm"),
        "hybrid": Scanner("hybrid"),
    }
    res = {"seed": SEED, "dev_fraction": DEV_FRAC,
           "counts": {"all": len(M), "dev": len(dev), "test": len(test)}, "full": {}, "test": {}, "latency_ms": {}}
    preds = {}
    for name, sc in detectors.items():
        res["full"][name], _ = summarise(sc, M)
        res["test"][name], preds[name] = summarise(sc, test)
        res["latency_ms"][name] = latency_ms(sc, M)
    hyb = detectors["hybrid"]
    hyb.llm_calls = 0
    for m in M:
        hyb.scan(m)
    res["hybrid_llm_call_share"] = round(hyb.llm_calls / sum(len(m.tools) for m in M), 3)

    mo_test = [m for m in test if m.label == "malicious" and m.variant == "obfuscated"]
    def paired(a, b):
        bb = sum(1 for m in mo_test if preds[a][id(m)] and not preds[b][id(m)])
        cc = sum(1 for m in mo_test if preds[b][id(m)] and not preds[a][id(m)])
        return {"a_only": bb, "b_only": cc, "p_value": mcnemar_exact(bb, cc)}
    res["mcnemar_test_obf"] = {
        "rule_norm_vs_rule_no_norm": paired("rule_norm", "rule_no_norm"),
        "hybrid_vs_llm_stub": paired("hybrid", "llm_stub"),
        "rule_norm_vs_rule_norm_noflags": paired("rule_norm", "rule_norm_noflags"),
    }
    a_off, _, n_atk = asr(M, None)
    a_on, _, _ = asr(M, hyb)
    t_off, _, n_t = asr(test, None)
    t_on, _, _ = asr(test, hyb)
    res["asr"] = {"full": {"off": round(a_off, 3), "on": round(a_on, 3), "prevention_rate": round(1 - a_on / a_off, 3), "attacks": n_atk},
                  "test": {"off": round(t_off, 3), "on": round(t_on, 3), "prevention_rate": round(1 - t_on / t_off, 3), "attacks": n_t}}

    print(f"manifests: all={len(M)}  dev={len(dev)}  test={len(test)}  (group-wise split, seed {SEED})\n")
    hdr = f"{'detector':19}{'rec plain':>10}{'rec obf':>9}{'F1 obf':>8}{'FPR benign':>11}{'FPR ctrl':>9}{'ms/manifest':>12}"
    for part in ("full", "test"):
        print(f"[{part}]"); print(hdr); print("-" * len(hdr))
        for name in detectors:
            r = res[part][name]
            print(f"{name:19}{r['recall_plain']:>10}{r['recall_obf']:>9}{r['f1_obf']:>8}{r['fpr_benign']:>11}{r['fpr_controls']:>9}{res['latency_ms'][name]:>12}")
        print()
    print("McNemar (test, obfuscated attacks):", json.dumps(res["mcnemar_test_obf"]))
    print("ASR (hybrid):", json.dumps(res["asr"]))
    print("Hybrid share of tools sent to judge:", res["hybrid_llm_call_share"])
    out = os.path.join(ROOT, "results.json")
    json.dump(res, open(out, "w"), indent=2)
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
