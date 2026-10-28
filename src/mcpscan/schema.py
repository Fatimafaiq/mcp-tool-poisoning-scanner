from dataclasses import dataclass, field
import json

@dataclass
class Tool:
    name: str
    description: str
    parameters: dict = field(default_factory=dict)

@dataclass
class Manifest:
    server: str
    tools: list
    label: str = "unknown"      # benign | malicious  (for evaluation data)
    base_id: str = ""           # groups a base attack with its obfuscated variants
    variant: str = "plain"      # plain | obfuscated

    def text_blobs(self):
        return [f"{t.name} :: {t.description} :: {t.parameters}" for t in self.tools]

def load_manifest(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    tools = [Tool(t["name"], t.get("description", ""), t.get("parameters", {})) for t in d.get("tools", [])]
    return Manifest(d.get("server", "unknown"), tools, d.get("label", "unknown"),
                    d.get("base_id", ""), d.get("variant", "plain"))
