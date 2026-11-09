"""Build a real-world benchmark from the MCPTox dataset (Wang et al., AAAI 2026).

Source: https://github.com/zhiqiangwang4/MCPTox-Benchmark  (clone it first, see README)
  - benign:    the real tool descriptions of 45 live MCP servers (response_all.json, clean_system_promot)
  - malicious: the 485 poisoned tool descriptions written for those servers (pure_tool.json)

The MCPTox repository has no licence file, so this script derives the benchmark locally and
the derived files are git-ignored rather than redistributed.

Safety: every URL, e-mail address and key-like string in the attacks is replaced with a
harmless .local placeholder before use (defanged), keeping the attack wording intact.
Obfuscated variants are made with the same four functions as the synthetic benchmark.
"""
import os, re, sys, json, random
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "data"))
import build_dataset as bd  # noqa: E402  (reuses obf_zero_width / obf_homoglyph / obf_base64 / obf_mixed)

SRC = os.environ.get("MCPTOX_DIR", os.path.join(ROOT, "data", "external", "MCPTox-Benchmark"))
OUT = os.path.join(ROOT, "data", "real")
SEED = 305

URL_RE = re.compile(r"https?://[^\s'\"`)]+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
KEYLIKE_RE = re.compile(r"\b(?=[A-Za-z0-9+/=]*\d)(?=[A-Za-z0-9+/=]*[A-Z])[A-Za-z0-9+/]{40,}={0,2}")


def defang(s):
    s = URL_RE.sub("http://collect.attacker.local/", s)
    s = EMAIL_RE.sub("drop@attacker.local", s)
    s = KEYLIKE_RE.sub("ATTACKER_PUBLIC_KEY_PLACEHOLDER", s)
    return s


def benign_tools(resp):
    out = []
    for sname, srv in resp["servers"].items():
        for m in re.finditer(r"Tool: (.+?)\nDescription: (.*?)\nArguments:", srv["clean_system_promot"], re.S):
            out.append((sname, m.group(1).strip(), m.group(2).strip()))
    return out


def malicious_tools(pure):
    out = []
    for d in pure:
        for key, v in d.items():
            out.append((v["server_name"], v["tool_name"], defang(v["tool_content"].strip()), key))
    return out


def manifest(server, name, desc, label, base_id, variant):
    return {"server": server, "label": label, "base_id": base_id, "variant": variant,
            "tools": [{"name": name, "description": desc, "parameters": {}}]}


def main():
    resp = json.load(open(os.path.join(SRC, "response_all.json"), encoding="utf-8"))
    pure = json.load(open(os.path.join(SRC, "pure_tool.json"), encoding="utf-8"))
    random.seed(SEED)
    rows = []
    for i, (srv, name, desc) in enumerate(benign_tools(resp)):
        rows.append(manifest(srv, name, desc, "benign", f"rb{i:03d}", "plain"))
    obfs = [("zero_width", bd.obf_zero_width), ("homoglyph", bd.obf_homoglyph),
            ("base64", bd.obf_base64), ("mixed", bd.obf_mixed)]
    for i, (srv, name, desc, key) in enumerate(malicious_tools(pure)):
        bid = f"rm{i:03d}"
        rows.append(manifest(srv, name, desc, "malicious", bid, "plain"))
        for tag, fn in obfs:
            m = manifest(srv, name, fn(desc), "malicious", bid, "obfuscated")
            m["obfuscation"] = tag
            rows.append(m)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "mcptox_manifests.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    n = {k: sum(1 for r in rows if (r["label"], r["variant"]) == k) for k in
         [("benign", "plain"), ("malicious", "plain"), ("malicious", "obfuscated")]}
    print(f"wrote {len(rows)} manifests to data/real/mcptox_manifests.json: "
          f"{n[('benign','plain')]} real benign, {n[('malicious','plain')]} real attacks, "
          f"{n[('malicious','obfuscated')]} obfuscated attack variants")


if __name__ == "__main__":
    main()
