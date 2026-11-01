"""Transparent text normalization: the defensive core against obfuscation."""
import unicodedata, re, base64

ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿", "­", "‎", "‏"]
# A small, auditable confusables table (Cyrillic/Greek look-alikes -> Latin).
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "ѕ": "s", "і": "i", "ј": "j", "һ": "h",
    "Α": "A", "Ε": "E", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Н": "H", "К": "K", "М": "M", "Ѕ": "S",
}
B64_RE = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")

def _strip_zero_width(s):
    for z in ZERO_WIDTH:
        s = s.replace(z, "")
    return s

def _map_homoglyphs(s):
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in s)

def _decode_blobs(s):
    out = []
    for m in B64_RE.finditer(s):
        tok = m.group(0)
        try:
            txt = base64.b64decode(tok + "===").decode("utf-8", "ignore")
        except Exception:
            continue
        if len(txt) >= 4 and sum(c.isprintable() for c in txt) >= 0.8 * len(txt):
            out.append(txt)
    return out

def normalize(text):
    text = text or ""
    transforms, flags = [], []
    if any(z in text for z in ZERO_WIDTH):
        flags.append("zero_width")
    s = _strip_zero_width(text)
    if s != text:
        transforms.append("strip_zero_width")
    s2 = unicodedata.normalize("NFKC", s)
    if s2 != s:
        transforms.append("nfkc")
    s = s2
    s3 = _map_homoglyphs(s)
    if s3 != s:
        transforms.append("map_homoglyphs"); flags.append("homoglyph")
    s = s3
    blobs = _decode_blobs(s)
    if blobs:
        transforms.append("decode_base64"); flags.append("encoded_blob")
        s = s + " || " + " ".join(blobs)
    return {"clean": s, "transforms": transforms, "flags": flags, "raw": text}
