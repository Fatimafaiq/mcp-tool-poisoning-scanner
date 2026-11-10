"""Scan real MCP server files or folders: python scripts/scan_file.py <file or folder> [...] [--mode rule|hybrid]

Reads .py / .ts / .js / .json files as text (never runs them), pulls out every tool description
and prints the verdict for each tool, the rules that fired, and a verdict for the whole file.
"""
import os, sys, glob
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from mcpscan.extract import extract
from mcpscan.scanner import Scanner, RuleScanner
from mcpscan.schema import Manifest, Tool

EXTS = (".py", ".ts", ".js", ".mjs", ".json")
SKIP = ("node_modules", "__tests__", "/tests/", "/test/", ".git")


def files_in(paths):
    for p in paths:
        if os.path.isdir(p):
            for f in sorted(glob.glob(os.path.join(p, "**", "*"), recursive=True)):
                if f.endswith(EXTS) and not any(s in f.replace("\\", "/") for s in SKIP):
                    yield f
        else:
            yield p


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    mode = "rule" if "--mode" in sys.argv and sys.argv[sys.argv.index("--mode") + 1] == "rule" else "hybrid"
    if not args:
        sys.exit(__doc__)
    args = [a for a in args if a not in ("rule", "hybrid")]
    sc, rs = Scanner(mode), RuleScanner()
    total = flagged = 0
    for f in files_in(args):
        try:
            tools = extract(f)
        except Exception as e:  # not a server file (e.g. unrelated JSON)
            continue
        if not tools:
            continue
        verdicts = []
        print(f"\n{f}  ({len(tools)} tools)")
        for t in tools:
            res = sc.scan(Manifest(os.path.basename(f), [Tool(t["name"], t["description"], {})]))
            r = rs.score(f"{t['name']} :: {t['description']} :: {{}}")
            verdicts.append(res["label"])
            mark = {"malicious": "BLOCK", "benign": "ok   "}.get(res["label"], "?    ")
            why = ", ".join(h for h in r["hits"]) or "-"
            print(f"  {mark} {t['name'][:45]:45} score {r['score']:.2f}  {why}")
        total += 1
        bad = verdicts.count("malicious")
        flagged += bool(bad)
        print(f"  => file verdict: {'MALICIOUS (' + str(bad) + ' poisoned tool' + ('s' if bad > 1 else '') + ')' if bad else 'clean'}")
    print(f"\n{flagged} of {total} files flagged (mode: {mode})")


if __name__ == "__main__":
    main()
