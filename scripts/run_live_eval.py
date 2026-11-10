"""Live evaluation: start real MCP servers, fetch their tool lists over the MCP protocol right now,
and scan them. Server list: data/live_servers.json. Output: results_live.json (dated snapshot)
and data/live/<server>.tools.json (raw tools/list answers, loadable in the demo).

Needs Node.js (npx) and uv (uvx) installed; the Invariant PoCs need data/external/mcp-injection-experiments*.
"""
import os, sys, glob, json, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src")); sys.path.insert(0, os.path.join(ROOT, "scripts"))
from scan_live import scan_server

CFG = json.load(open(os.path.join(ROOT, "data", "live_servers.json"), encoding="utf-8"))
EXT = os.path.join(ROOT, "data", "external")


def main():
    pins = os.path.join(ROOT, "data", "live", "pins.json")
    os.makedirs(os.path.dirname(pins), exist_ok=True)
    if os.path.exists(pins):
        os.remove(pins)
    trig = os.path.expanduser("~/.mcp-triggered")
    if os.path.exists(trig):
        os.remove(trig)  # so the rug-pull server starts in its innocent state
    out = {"scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "servers": []}
    for s in CFG["servers"]:
        cmd = []
        for c in s["cmd"]:
            if "{ext}" in c:
                hits = glob.glob(c.replace("{ext}", EXT))
                c = hits[0] if hits else c.replace("{ext}", EXT)
            cmd.append(c)
        for attempt in range(2 if s.get("rescan") else 1):
            try:
                info, rows = scan_server(cmd, "hybrid", pins, save=os.path.join(ROOT, "data", "live"))
            except Exception as e:
                print(f"\nSKIPPED {' '.join(cmd)}: {e}")
                out["servers"].append({"cmd": cmd, "error": str(e)}); break
            poisoned = set(s.get("poisoned_tools", []))
            for r in rows:
                # the rug-pull server is innocent on its first start and poisoned once swapped
                r["label"] = "malicious" if r["name"] in poisoned and not (s.get("rescan") and attempt == 0) else "benign"
            out["servers"].append({"cmd": [c.replace(ROOT + os.sep, "") for c in cmd], "source": s["source"], "scan": attempt + 1, "server": info.get("name"),
                                   "version": info.get("version"), "tools": rows})
    tools = [t for sv in out["servers"] for t in sv.get("tools", [])]
    mal = [t for t in tools if t["label"] == "malicious"]
    ben = [t for t in tools if t["label"] == "benign"]
    out["summary"] = {
        "servers_reached": sum(1 for sv in out["servers"] if "tools" in sv), "tools": len(tools),
        "poisoned_caught_by_content": f"{sum(t['verdict'] == 'malicious' for t in mal)}/{len(mal)}",
        "poisoned_caught_incl_change_alert": f"{sum(t['verdict'] == 'malicious' or t['changed'] for t in mal)}/{len(mal)}",
        "benign_blocked": f"{sum(t['verdict'] == 'malicious' for t in ben)}/{len(ben)}",
    }
    json.dump(out, open(os.path.join(ROOT, "results_live.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("\nLive scan", out["scanned_at"], json.dumps(out["summary"], indent=1))
    print("wrote results_live.json and data/live/*.tools.json")


if __name__ == "__main__":
    main()
