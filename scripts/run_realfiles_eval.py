"""Test the scanner on real MCP server source files (not written by us).

Download into data/external/ (git clone or GitHub "Download ZIP" and unzip, any of these names work):
  mcp-injection-experiments   https://github.com/invariantlabs-ai/mcp-injection-experiments  (malicious PoCs)
  damn-vulnerable-MCP-server  https://github.com/harishsg993010/damn-vulnerable-MCP-server  (15 vulnerable servers)
  servers                     https://github.com/modelcontextprotocol/servers               (official, benign)

Tools are extracted with mcpscan.extract (files are read, never run) and labelled from
data/realfiles_labels.json. Each poisoned description is also scanned in four disguised copies
(zero-width, look-alike letters, Base64, mixed) made with our obfuscation functions.
None of these files were used to write rules. Output: results_realfiles.json
"""
import os, sys, glob, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src")); sys.path.insert(0, os.path.join(ROOT, "data"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from mcpscan.extract import extract
from mcpscan.scanner import Scanner
from mcpscan.schema import Manifest, Tool
from run_eval import wilson
import build_dataset as bd

EXT = os.path.join(ROOT, "data", "external")
LAB = json.load(open(os.path.join(ROOT, "data", "realfiles_labels.json"), encoding="utf-8"))


def collect():
    poisoned = {(s, f, t) for s, f, t in LAB["poisoned"]}
    rows, missing = [], []
    for src in LAB["sources"]:
        roots = [d for d in glob.glob(os.path.join(EXT, src["folder_glob"])) if os.path.isdir(d)]
        if not roots:
            missing.append(src["repo"]); continue
        root = roots[0]
        for pat in src["files"]:
            for f in sorted(glob.glob(os.path.join(root, pat))):
                rel = os.path.relpath(f, root).replace("\\", "/")
                for t in extract(f):
                    lab = "malicious" if any(s == src["id"] and rel.endswith(fp) and t["name"] == tn
                                             for s, fp, tn in poisoned) else "benign"
                    rows.append({"source": src["id"], "file": rel, "name": t["name"],
                                 "desc": t["description"], "label": lab, "variant": "plain"})
    return rows, missing


def main():
    rows, missing = collect()
    if missing:
        print("missing (download into data/external/):", *missing, sep="\n  ")
    import random; random.seed(305)
    for r in [r for r in rows if r["label"] == "malicious"]:
        for tag, fn in [("zero_width", bd.obf_zero_width), ("homoglyph", bd.obf_homoglyph),
                        ("base64", bd.obf_base64), ("mixed", bd.obf_mixed)]:
            rows.append({**r, "desc": fn(r["desc"]), "variant": tag})
    dets = {"rule_no_norm": Scanner("rule", normalize_on=False), "rule_norm": Scanner("rule"), "hybrid": Scanner("hybrid")}
    plain = [r for r in rows if r["label"] == "malicious" and r["variant"] == "plain"]
    obf = [r for r in rows if r["label"] == "malicious" and r["variant"] != "plain"]
    ben = [r for r in rows if r["label"] == "benign"]
    out = {"n": {"files": len({(r["source"], r["file"]) for r in rows}), "benign_tools": len(ben),
                 "poisoned_tools": len(plain), "obfuscated_copies": len(obf)}, "detectors": {}, "per_tool": []}
    for name, sc in dets.items():
        verdict = {}
        for i, r in enumerate(rows):
            res = sc.scan(Manifest(r["file"], [Tool(r["name"], r["desc"], {})]))
            verdict[i] = res["label"]
        hit = lambda xs: sum(verdict[rows.index(x)] == "malicious" for x in xs)
        k1, k2, k3 = hit(plain), hit(obf), hit(ben)
        out["detectors"][name] = {"recall_poisoned": [k1, len(plain), wilson(k1, len(plain))],
                                  "recall_obfuscated": [k2, len(obf), wilson(k2, len(obf))],
                                  "false_positives": [k3, len(ben), wilson(k3, len(ben))],
                                  "uncertain_poisoned": sum(verdict[rows.index(x)] == "uncertain" for x in plain)}
        for i, r in enumerate(rows):
            if r["variant"] == "plain" and (r["label"] == "malicious" or verdict[i] == "malicious"):
                out["per_tool"].append({"detector": name, "source": r["source"], "file": r["file"], "tool": r["name"],
                                        "label": r["label"], "verdict": verdict[i]})
    json.dump(out, open(os.path.join(ROOT, "results_realfiles.json"), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    n = out["n"]
    print(f"Real MCP server files: {n['files']} files, {n['benign_tools']} benign tools, "
          f"{n['poisoned_tools']} poisoned tools (+{n['obfuscated_copies']} disguised copies)\n")
    print(f"{'detector':14} {'poisoned caught':>16} {'disguised caught':>17} {'benign blocked':>15}")
    for name, d in out["detectors"].items():
        f = lambda v: f"{v[0]}/{v[1]}"
        print(f"{name:14} {f(d['recall_poisoned']):>16} {f(d['recall_obfuscated']):>17} {f(d['false_positives']):>15}")
    print("\nPoisoned tools (hybrid):")
    for p in out["per_tool"]:
        if p["detector"] == "hybrid":
            print(f"  {p['label']:9} {p['verdict']:9} {p['source']}/{p['file']} :: {p['tool']}")
    print("\nwrote results_realfiles.json")


if __name__ == "__main__":
    main()
