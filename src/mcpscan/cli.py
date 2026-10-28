import argparse, glob, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from mcpscan.schema import load_manifest
from mcpscan.scanner import Scanner

def main():
    ap = argparse.ArgumentParser(description="Scan MCP tool manifests for tool poisoning.")
    ap.add_argument("path", help="manifest .json file or a directory of them")
    ap.add_argument("--mode", default="hybrid", choices=["rule", "llm", "hybrid"])
    a = ap.parse_args()
    files = glob.glob(os.path.join(a.path, "*.json")) if os.path.isdir(a.path) else [a.path]
    sc = Scanner(mode=a.mode)
    for f in sorted(files):
        v = sc.scan(load_manifest(f))
        print(f"[{v['label'].upper():9}] {os.path.basename(f)}")
    print(f"-- mode={a.mode}  llm_calls={sc.llm_calls}")

if __name__ == "__main__":
    main()
