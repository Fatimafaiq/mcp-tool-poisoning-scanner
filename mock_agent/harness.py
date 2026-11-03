"""Mock agent: a manifest's malicious tool 'fires' only if the scanner lets it load.
Deterministic simulation (no real LLM), honest about being a mock. Computes ASR."""
def attack_still_succeeds(manifest, scanner):
    if manifest.label != "malicious":
        return False
    if scanner is None:
        return True  # no scanner -> poisoned tool loads and fires
    v = scanner.scan(manifest)
    return v["label"] != "malicious"  # loaded despite being poisoned -> attack fires

def asr(manifests, scanner):
    atk = [m for m in manifests if m.label == "malicious"]
    succ = sum(1 for m in atk if attack_still_succeeds(m, scanner))
    return (succ / len(atk) if atk else 0.0), succ, len(atk)
