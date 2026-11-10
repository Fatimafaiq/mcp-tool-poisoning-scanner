"""Extract MCP tool names and descriptions from real files, so the scanner can check a server
before it is installed. Files are only read as text, never imported or run.

Supported:
  .py        FastMCP-style   @mcp.tool() / @server.tool(name=..., description=...) + docstring,
             fn.__doc__ = "..." (a description swapped at run time, i.e. a rug pull),
             and Tool(name="...", description="...") / {"name": ..., "description": ...}
  .ts / .js  server.tool("name", "description", ...), registerTool("name", {description: ...}),
             and { name: "...", description: "..." } objects (string concatenation with + is joined)
  .json      a tools/list response ({"tools": [...]} or {"result": {"tools": [...]}}), a list of tools,
             or a scanner manifest

The same logic is ported line-for-line to the browser demo (demo/index.html).
"""
import json, os, re

WS = re.compile(r"[ \t\r\n\f\v]+")
DECOR = re.compile(r"@[\w.]*\btool\b\s*(\((?P<args>(?:[^()]|\([^()]*\))*)\))?")
DEF = re.compile(r"\s*(?:@[^\n]*\n\s*)*(?:async\s+)?def\s+(?P<name>\w+)\s*\(")
NAME_KV = re.compile(r"""\bname\s*[:=]\s*(?P<q>["'`])(?P<v>[^"'`\n]{1,80})(?P=q)""")
DESC_KEY = re.compile(r"""\bdescription["']?\s*[:=]\s*""")
DOC_SET = re.compile(r"\b(?P<name>\w+)\.__doc__\s*=\s*")
TOOL_CALL = re.compile(r"""\.(?:tool|registerTool)\s*\(\s*(?P<q>["'`])(?P<v>[\w.-]{1,80})(?P=q)\s*,\s*""")
ESC = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "`": "`", "\\": "\\", "0": "\0"}


def clean(s):
    return WS.sub(" ", s).strip()


def _unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", s[i + 2:i + 6] or ""):
                out.append(chr(int(s[i + 2:i + 6], 16))); i += 6; continue
            if n == "\n":
                i += 2; continue
            out.append(ESC.get(n, "\\" + n)); i += 2; continue
        out.append(c); i += 1
    return "".join(out)


def read_strings(src, i):
    """Read one or more string literals starting at src[i], joined by +, whitespace or (adjacent
    Python literals). Returns (text, end) or (None, i)."""
    parts, j, n = [], i, len(src)
    while True:
        k = j
        while k < n and src[k] in " \t\r\n(+":
            k += 1
        m = re.match(r"[rRbBuUfF]{0,2}", src[k:])
        pre = m.group(0).lower(); k += len(pre)
        if k >= n or src[k] not in "\"'`":
            break
        q = src[k]
        if src.startswith(q * 3, k) and q != "`":
            e = src.find(q * 3, k + 3)
            if e < 0:
                break
            body, j = src[k + 3:e], e + 3
        else:
            e, k2 = None, k + 1
            while k2 < n:
                if src[k2] == "\\":
                    k2 += 2; continue
                if src[k2] == q:
                    e = k2; break
                if src[k2] == "\n" and q != "`":
                    break
                k2 += 1
            if e is None:
                break
            body, j = src[k + 1:e], e + 1
        parts.append(body if "r" in pre else _unescape(body))
    return ("".join(parts), j) if parts else (None, i)


def _docstring(src, i):
    """Docstring of the def whose argument list starts at src[i] (just after the opening bracket)."""
    depth, k = 1, i
    while k < len(src):
        c = src[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ":" and depth == 0:
            break
        k += 1
    m = re.match(r"\s*(?:[rRuU]?)(\"\"\"|''')", src[k + 1:])
    if not m:
        return None
    s, _ = read_strings(src, k + 1)
    return s


def from_python(src):
    tools = []
    for d in DECOR.finditer(src):
        args = d.group("args") or ""
        m = DEF.match(src, d.end())
        if not m:
            continue
        name = (NAME_KV.search(args).group("v") if NAME_KV.search(args) else m.group("name"))
        desc = None
        dk = DESC_KEY.search(args)
        if dk:
            desc, _ = read_strings(args, dk.end())
        if desc is None:
            desc = _docstring(src, m.end())
        if desc is not None:
            tools.append({"name": name, "description": clean(desc)})
    # Rug pull: a description swapped at run time (fn.__doc__ = "...") is still in the source.
    for d in DOC_SET.finditer(src):
        desc, _ = read_strings(src, d.end())
        if desc:
            tools.append({"name": d.group("name") + " (description replaced at run time)", "description": clean(desc)})
    return tools + _from_objects(src, {t["name"] for t in tools})


def _from_objects(src, seen):
    tools = []
    for m in NAME_KV.finditer(src):
        name = m.group("v")
        if name in seen:
            continue
        dk = DESC_KEY.search(src, m.end(), m.end() + 400)
        if not dk:
            continue
        nxt = NAME_KV.search(src, m.end(), dk.start())
        if nxt:
            continue
        desc, _ = read_strings(src, dk.end())
        if desc:
            seen.add(name)
            tools.append({"name": name, "description": clean(desc)})
    return tools


def from_js(src):
    tools, seen = [], set()
    for m in TOOL_CALL.finditer(src):
        name, j = m.group("v"), m.end()
        desc, _ = read_strings(src, j)
        if desc is None:
            dk = DESC_KEY.search(src, j, j + 600)
            if dk:
                desc, _ = read_strings(src, dk.end())
        if desc:
            seen.add(name)
            tools.append({"name": name, "description": clean(desc)})
    return tools + _from_objects(src, seen)


def from_json(src):
    data = json.loads(src)
    if isinstance(data, dict):
        data = (data.get("result") or data).get("tools", data)
    if isinstance(data, dict):
        data = [data]
    tools = []
    for t in data if isinstance(data, list) else []:
        if isinstance(t, dict) and "tools" in t and isinstance(t["tools"], list):
            tools += [{"name": x.get("name", ""), "description": clean(x.get("description", ""))} for x in t["tools"]]
        elif isinstance(t, dict) and "description" in t:
            tools.append({"name": t.get("name", ""), "description": clean(t.get("description") or "")})
    return tools


def extract(path, text=None):
    if text is None:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return from_json(text)
    if ext in (".ts", ".js", ".mjs", ".cjs", ".tsx"):
        return from_js(text)
    return from_python(text)
