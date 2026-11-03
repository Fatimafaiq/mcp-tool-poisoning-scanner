# Changelog (development history)

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
