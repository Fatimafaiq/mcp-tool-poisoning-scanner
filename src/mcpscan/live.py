"""Live scanning: connect to a running MCP server, ask for its tool list over the real MCP
protocol (JSON-RPC 2.0: initialize -> notifications/initialized -> tools/list), and return the
tool descriptions exactly as an agent would receive them. No tool is ever called.

Two transports, standard library only (no SDK version to match):
  stdio  the server is a local command, e.g. ["npx", "-y", "@modelcontextprotocol/server-memory"]
  http   a remote server URL using Streamable HTTP, e.g. "https://example.com/mcp"
"""
import hashlib, json, os, queue, shutil, subprocess, sys, threading, time, urllib.request

PROTOCOL = "2025-06-18"
CLIENT = {"name": "mcpscan", "version": "0.7.0"}


class LiveError(RuntimeError):
    pass


def _resolve(cmd):
    exe = shutil.which(cmd[0]) or cmd[0]
    return [exe] + list(cmd[1:])


def list_tools_stdio(cmd, timeout=90, env=None):
    p = subprocess.Popen(_resolve(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, encoding="utf-8", errors="replace", env={**os.environ, **(env or {})})
    out = queue.Queue()
    threading.Thread(target=lambda: [out.put(l) for l in p.stdout], daemon=True).start()
    threading.Thread(target=lambda: [None for _ in p.stderr], daemon=True).start()
    deadline = time.time() + timeout

    def send(msg):
        p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()

    def wait(rid):
        while time.time() < deadline:
            try:
                line = out.get(timeout=0.5)
            except queue.Empty:
                if p.poll() is not None:
                    raise LiveError(f"server exited with code {p.returncode} before answering")
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue  # servers sometimes log to stdout
            if msg.get("id") == rid:
                if "error" in msg:
                    raise LiveError(msg["error"].get("message", "error"))
                return msg["result"]
        raise LiveError("timed out waiting for the server")

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": CLIENT}})
        info = wait(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools, cursor, rid = [], None, 2
        while True:
            send({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}})
            res = wait(rid); tools += res.get("tools", []); cursor = res.get("nextCursor"); rid += 1
            if not cursor:
                break
        return info.get("serverInfo", {}), tools
    finally:
        try:
            p.stdin.close(); p.terminate(); p.wait(timeout=5)
        except Exception:
            p.kill()


def _post(url, msg, session=None, timeout=30):
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL, **({"Mcp-Session-Id": session} if session else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        sid = r.headers.get("Mcp-Session-Id") or session
        body = r.read().decode("utf-8", "replace")
        if "event-stream" in (r.headers.get("Content-Type") or ""):
            msgs = [json.loads(l[5:]) for l in body.splitlines() if l.startswith("data:") and l[5:].strip()]
            body = next((m for m in msgs if m.get("id") == msg.get("id")), None)
        else:
            body = json.loads(body) if body.strip() else None
    return sid, body


def list_tools_http(url, timeout=30):
    sid, res = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": CLIENT}}, timeout=timeout)
    if not res or "error" in res:
        raise LiveError((res or {}).get("error", {}).get("message", "no answer to initialize"))
    try:
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, timeout)
    except Exception:
        pass
    tools, cursor, rid = [], None, 2
    while True:
        _, r = _post(url, {"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}}, sid, timeout)
        if not r or "error" in r:
            raise LiveError((r or {}).get("error", {}).get("message", "no answer to tools/list"))
        tools += r["result"].get("tools", []); cursor = r["result"].get("nextCursor"); rid += 1
        if not cursor:
            break
    return res["result"].get("serverInfo", {}), tools


def list_tools(target, timeout=90):
    """target: a URL string, or a command as a list / string."""
    if isinstance(target, str) and target.startswith(("http://", "https://")):
        return list_tools_http(target, timeout)
    cmd = target.split() if isinstance(target, str) else target
    return list_tools_stdio(cmd, timeout)


def fingerprint(tool):
    """Hash of what the agent sees for one tool (name, description, input schema). A change between
    two scans of the same server means the description was swapped (a rug pull)."""
    blob = json.dumps({"name": tool.get("name"), "description": tool.get("description"),
                       "inputSchema": tool.get("inputSchema")}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def schema_text(tool):
    """Parameter descriptions are also read by the agent, so they are scanned too."""
    props = ((tool.get("inputSchema") or {}).get("properties") or {})
    return {k: v.get("description", "") for k, v in props.items() if isinstance(v, dict) and v.get("description")}
