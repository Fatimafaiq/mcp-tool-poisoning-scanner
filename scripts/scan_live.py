"""Scan a RUNNING MCP server, live, the way an agent would meet it.

  python scripts/scan_live.py [--mode rule|hybrid] [--pin pins.json] -- <command that starts the server>
  python scripts/scan_live.py [--mode rule|hybrid] [--pin pins.json] https://server.example/mcp
  --save <folder> also writes the server's raw tools/list answer as <name>.tools.json

Starts (or connects to) the server, does the MCP handshake, asks for tools/list and scans every
tool description and parameter description before any agent sees them. No tool is ever called.
--pin keeps a fingerprint of each tool; if a later scan of the same server shows a different
description, it is reported as CHANGED (a rug pull: the server swapped its description).
"""
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from mcpscan.live import list_tools, fingerprint, schema_text, LiveError
from mcpscan.scanner import Scanner, RuleScanner
from mcpscan.schema import Manifest, Tool


def scan_server(target, mode="hybrid", pin=None, quiet=False, save=None):
    info, tools = list_tools(target, timeout=240)
    key = target if isinstance(target, str) else " ".join(target)
    if save:  # the raw tools/list answer, e.g. to drop into the demo's "Scan server files" tab
        os.makedirs(save, exist_ok=True)
        fn = os.path.join(save, "".join(c if c.isalnum() or c in "-_" else "_" for c in info.get("name", "server")) + ".tools.json")
        base, k = fn[:-len(".tools.json")], 2
        while os.path.exists(fn) and json.load(open(fn, encoding="utf-8")).get("cmd") != key:
            fn = f"{base}_{k}.tools.json"; k += 1
        json.dump({"serverInfo": info, "cmd": key, "tools": tools}, open(fn, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    pins = json.load(open(pin, encoding="utf-8")) if pin and os.path.exists(pin) else {}
    old = pins.get(key, {})
    sc, rs, rows = Scanner(mode), RuleScanner(), []
    for t in tools:
        params = schema_text(t)
        res = sc.scan(Manifest(info.get("name", key), [Tool(t["name"], t.get("description") or "", params)]))
        r = rs.score(Manifest("x", [Tool(t["name"], t.get("description") or "", params)]).text_blobs()[0])
        fp = fingerprint(t)
        rows.append({"name": t["name"], "description": t.get("description") or "", "params": params,
                     "verdict": res["label"], "score": r["score"], "hits": r["hits"], "fingerprint": fp,
                     "changed": bool(old) and old.get(t["name"]) not in (None, fp), "new": bool(old) and t["name"] not in old})
    if pin:
        pins[key] = {x["name"]: x["fingerprint"] for x in rows}
        json.dump(pins, open(pin, "w", encoding="utf-8"), indent=1)
    if not quiet:
        print(f"\nLIVE  {info.get('name', '?')} {info.get('version', '')}  ({len(rows)} tools)  <- {key}")
        for x in rows:
            mark = {"malicious": "BLOCK", "benign": "ok   "}.get(x["verdict"], "?    ")
            flag = "  CHANGED since last scan" if x["changed"] else ("  NEW since last scan" if x["new"] else "")
            print(f"  {mark} {x['name'][:40]:40} score {x['score']:.2f}  {', '.join(x['hits']) or '-'}{flag}")
        bad = [x for x in rows if x["verdict"] == "malicious"]
        ch = [x for x in rows if x["changed"]]
        print(f"  => server verdict: {'DO NOT CONNECT (' + str(len(bad)) + ' poisoned tool' + ('s' if len(bad) != 1 else '') + ')' if bad else 'clean'}"
              + (f"; {len(ch)} description(s) changed since the pinned scan" if ch else ""))
    return info, rows


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    mode, pin, save = "hybrid", None, None
    while a and a[0].startswith("--") and a[0] != "--":
        if a[0] == "--mode":
            mode = a[1]; a = a[2:]
        elif a[0] == "--pin":
            pin = a[1]; a = a[2:]
        elif a[0] == "--save":
            save = a[1]; a = a[2:]
        else:
            sys.exit(f"unknown option {a[0]}")
    if a and a[0] == "--":
        a = a[1:]
    target = a[0] if len(a) == 1 and a[0].startswith(("http://", "https://")) else a
    try:
        scan_server(target, mode, pin, save=save)
    except (LiveError, OSError) as e:
        sys.exit(f"could not reach the server: {e}")


if __name__ == "__main__":
    main()
