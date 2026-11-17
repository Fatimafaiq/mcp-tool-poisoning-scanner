"""mcpscan: check MCP tool descriptions for hidden instructions before an AI agent loads them.

  mcpscan scan <file or folder> [...]        scan server source files (.py .ts .js) or tools/list JSON
  mcpscan live [--pin pins.json] -- <cmd>    start a local MCP server and scan its live tool list
  mcpscan live https://server/mcp            scan a remote MCP server (Streamable HTTP)
  mcpscan text "description" [--name tool]   scan one tool description

Options: --mode rule|hybrid (default hybrid), --no-normalize, --json.
Exit code: 0 clean, 1 at least one tool withheld, 2 error. Files are read as text, never run.
"""
import argparse, glob, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from mcpscan import __version__
from mcpscan.extract import extract
from mcpscan.scanner import Scanner, RuleScanner
from mcpscan.schema import Manifest, Tool

EXTS = (".py", ".ts", ".js", ".mjs", ".cjs", ".json")
SKIP = ("node_modules", "/.git/", "/tests/", "/test/", "__tests__", "/dist/", "/build/")


def _files(paths):
    for p in paths:
        if os.path.isdir(p):
            for f in sorted(glob.glob(os.path.join(p, "**", "*"), recursive=True)):
                if f.endswith(EXTS) and not any(s in f.replace("\\", "/") for s in SKIP):
                    yield f
        else:
            yield p


def _check(tools, source, args):
    sc, rs = Scanner(args.mode, normalize_on=not args.no_normalize), RuleScanner(normalize_on=not args.no_normalize)
    rows = []
    for t in tools:
        params = t.get("params") or {}
        m = Manifest(source, [Tool(t["name"], t.get("description") or "", params)])
        res, r = sc.scan(m), rs.score(m.text_blobs()[0])
        rows.append({"tool": t["name"], "verdict": "withheld" if res["label"] == "malicious" else "allowed",
                     "score": r["score"], "rules": [h for h in r["hits"] if not h.startswith("flag:")],
                     "flags": r["flags"], "error": res["tools"][0].get("reason") or res["tools"][0].get("error"),
                     **({"changed": t["changed"]} if "changed" in t else {})})
    return rows


def _print(source, rows, args, note=""):
    bad = [x for x in rows if x["verdict"] == "withheld"]
    print(f"\n{source}  ({len(rows)} tool{'s' if len(rows) != 1 else ''}){note}")
    for x in rows:
        mark = "BLOCK" if x["verdict"] == "withheld" else "ok   "
        why = ", ".join(x["rules"] + ["flag:" + f for f in x["flags"]]) or "-"
        extra = "  CHANGED since last scan" if x.get("changed") else ""
        print(f"  {mark} {x['tool'][:44]:44} score {x['score'] if x['score'] is not None else '-':>4}  {why}{extra}")
    print(f"  => {'DO NOT LOAD: ' + str(len(bad)) + ' poisoned tool' + ('s' if len(bad) != 1 else '') if bad else 'clean'}")


def cmd_scan(args):
    out, any_bad = [], False
    for f in _files(args.paths):
        try:
            tools = extract(f)
        except Exception:
            continue
        if not tools:
            continue
        rows = _check(tools, f, args)
        any_bad |= any(x["verdict"] == "withheld" for x in rows)
        out.append({"source": f, "tools": rows})
        if not args.json:
            _print(f, rows, args)
    if args.json:
        print(json.dumps(out, indent=1, ensure_ascii=False))
    elif not out:
        print("No MCP tools found. Give server source files (.py .ts .js), a tools/list JSON, or a folder.")
    else:
        print(f"\n{sum(1 for o in out if any(x['verdict'] == 'withheld' for x in o['tools']))} of {len(out)} files flagged (mode {args.mode})")
    return 1 if any_bad else 0


def cmd_live(args):
    from mcpscan.live import list_tools, fingerprint, schema_text, LiveError
    target = args.target[0] if len(args.target) == 1 and args.target[0].startswith(("http://", "https://")) else args.target
    if not target:
        print("Give a server command after -- or a URL.", file=sys.stderr)
        return 2
    try:
        info, tools = list_tools(target, timeout=240)
    except (LiveError, OSError) as e:
        print(f"could not reach the server: {e}", file=sys.stderr)
        return 2
    key = target if isinstance(target, str) else " ".join(target)
    pins = {}
    if args.pin and os.path.exists(args.pin):
        pins = json.load(open(args.pin, encoding="utf-8"))
    old = pins.get(key, {})
    items = []
    for t in tools:
        fp = fingerprint(t)
        items.append({"name": t["name"], "description": t.get("description") or "", "params": schema_text(t),
                      "fp": fp, "changed": bool(old) and old.get(t["name"]) not in (None, fp)})
    rows = _check(items, key, args)
    if args.pin:
        pins[key] = {i["name"]: i["fp"] for i in items}
        json.dump(pins, open(args.pin, "w", encoding="utf-8"), indent=1)
    if args.json:
        print(json.dumps({"server": info, "tools": rows}, indent=1, ensure_ascii=False))
    else:
        _print(f"LIVE {info.get('name', '?')} {info.get('version', '')}", rows, args, f"  <- {key}")
        ch = sum(1 for x in rows if x.get("changed"))
        if ch:
            print(f"  => {ch} description(s) changed since the pinned scan: review before trusting")
    return 1 if any(x["verdict"] == "withheld" or x.get("changed") for x in rows) else 0


def cmd_text(args):
    rows = _check([{"name": args.name, "description": args.description}], "text", args)
    if args.json:
        print(json.dumps(rows[0], indent=1, ensure_ascii=False))
    else:
        _print("text", rows, args)
    return 1 if rows[0]["verdict"] == "withheld" else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("scan", "live", "text", "-h", "--help", "--version", "-V"):
        argv = ["scan"] + argv  # backwards compatible: mcpscan <path>
    ap = argparse.ArgumentParser(prog="mcpscan", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-V", "--version", action="version", version=f"mcpscan {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--mode", default="hybrid", choices=["rule", "hybrid"], help="rule only, or rules then judge (default)")
    common.add_argument("--no-normalize", action="store_true", help="scan raw text (to compare)")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", parents=[common], help="scan files or folders")
    s.add_argument("paths", nargs="+")
    s.set_defaults(fn=cmd_scan)
    l = sub.add_parser("live", parents=[common], help="scan a running MCP server")
    l.add_argument("--pin", help="file that remembers each tool, to report changed descriptions")
    l.add_argument("target", nargs=argparse.REMAINDER, help="-- <command> or a URL")
    l.set_defaults(fn=cmd_live)
    t = sub.add_parser("text", parents=[common], help="scan one description")
    t.add_argument("description")
    t.add_argument("--name", default="tool")
    t.set_defaults(fn=cmd_text)
    a = ap.parse_args(argv)
    if a.cmd == "live" and a.target and a.target[0] == "--":
        a.target = a.target[1:]
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
