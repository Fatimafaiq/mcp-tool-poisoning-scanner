# Changelog (development history)

## v0.4.0 - iteration 3 (false-positive fix and stronger evaluation)
- Failure found: legitimate tools with non-Latin text, emoji joiners or encoded examples were
  blocked as attacks (3 of 16 new benign Unicode controls, FPR 0.188), because any obfuscation
  flag added risk weight even with no attack content.
- Revision: zero-width flagged only inside Latin words; homoglyphs mapped and flagged only in
  mixed-script words (Unicode TR39 idea); soft hyphen stripped but not flagged; obfuscation flags
  now corroborate a content rule hit, and on their own only escalate the tool to the judge.
- Retest: control FPR 0.188 -> 0.000 with no loss of obfuscated recall (0.958); all tests pass.
- Benchmark: +16 benign Unicode controls (100 manifests).
- Evaluation: frozen group-wise 40/60 dev/test split, Wilson 95% CIs, exact McNemar test,
  flag ablation, measured latency, share of tools sent to the judge.
- Tests: +5 manually written regression tests (3 fail on v0.3, all pass on v0.4).
- Demo: `demo/index.html`, browser port of the scanner on the real benchmark, with a live Claude
  LLM-as-judge (raw vs normalised text) and saved runs; replaces the earlier hand-written demo page.
- Judge prompt hardened: tool text is marked as untrusted data inside <tool> tags.

## v0.3.0 - 2026-11-03
- Added obfuscation on/off evaluation and the mock-agent ASR harness.
- Added AI-generated test file alongside the manual suite (edge cases: mixed obfuscation, benign trap).
- Fixed base64 detector threshold (missed short encoded secrets); retested, all tests pass.
- First full evaluation run: obfuscated recall 0.042 (naive) -> 0.958 (normalized); ASR 1.00 -> 0.067.

## v0.2.0 - 2026-11-01
- Added normalizer (NFKC, zero-width strip, homoglyph map, base64 decode) and YAML rule set.
- Added hybrid router (escalate only uncertain cases) and heuristic LLM-judge stub for offline runs.
- Added dataset generator (24 benign, 12 malicious, 48 obfuscated; group-wise base ids).

## v0.1.0 - 2026-10-28
- Project skeleton, manifest schema, rule-only scanner, initial benign/malicious fixtures.
