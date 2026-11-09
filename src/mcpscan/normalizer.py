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
# v0.4: soft hyphen is legitimate typography, so it is stripped but never flagged.
FLAG_ZW = set(ZERO_WIDTH) - {"\u00ad"}
WORD_RE = re.compile(r"\w+", re.U)

def _is_latin(ch):
    return "a" <= ch.lower() <= "z"

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

def _zero_width_inside_latin_word(text):
    """v0.4: flag an invisible character only when it splits a Latin word (re\u200bad).
    Zero-width joiners inside emoji or Persian/Arabic text are legitimate and not flagged."""
    for i, ch in enumerate(text):
        if ch in FLAG_ZW:
            j, k = i - 1, i + 1
            while j >= 0 and text[j] in ZERO_WIDTH: j -= 1
            while k < len(text) and text[k] in ZERO_WIDTH: k += 1
            if j >= 0 and k < len(text) and _is_latin(text[j]) and _is_latin(text[k]):
                return True
    return False

def _map_homoglyphs_mixed(s):
    """v0.4: map look-alikes only inside mixed-script words (Latin letters plus Cyrillic or
    Greek look-alikes, e.g. 'rеаd'), following the mixed-script idea in Unicode TR39.
    Genuine Russian, Ukrainian or Greek words are left alone and not flagged."""
    hit = False
    def fix(m):
        nonlocal hit
        w = m.group(0)
        if any(_is_latin(c) for c in w) and any(c in HOMOGLYPHS for c in w):
            hit = True
            return "".join(HOMOGLYPHS.get(c, c) for c in w)
        return w
    return WORD_RE.sub(fix, s), hit

def normalize(text):
    text = text or ""
    transforms, flags = [], []
    if _zero_width_inside_latin_word(text):
        flags.append("zero_width")
    s = _strip_zero_width(text)
    if s != text:
        transforms.append("strip_zero_width")
    s2 = unicodedata.normalize("NFKC", s)
    if s2 != s:
        transforms.append("nfkc")
    s = s2
    s3, mixed = _map_homoglyphs_mixed(s)
    if mixed:
        transforms.append("map_homoglyphs"); flags.append("homoglyph")
    s = s3
    blobs = _decode_blobs(s)
    if blobs:
        transforms.append("decode_base64"); flags.append("encoded_blob")
        s = s + " || " + " ".join(blobs)
    return {"clean": s, "transforms": transforms, "flags": flags, "raw": text}
