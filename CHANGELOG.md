# Changelog (development history)

## v0.7.0 - iteration 6 (live MCP servers)
- New: `mcpscan.live` connects to a running MCP server (local command over stdio, or a remote
  URL over Streamable HTTP), performs the real MCP handshake and `tools/list`, and scans every
  tool and parameter description before any agent sees them. No tool is ever called. Standard
  library only.
- `scripts/scan_live.py -- <command>` scans one server; `--pin` stores a fingerprint of each tool
  so a later scan reports descriptions that CHANGED (rug pull); `--save` keeps the raw answer.
- `scripts/run_live_eval.py` starts 10 servers from `data/live_servers.json`: 7 official servers
  at their latest npm / PyPI versions and Invariant Labs' 3 attack servers.
- Live result (10 Nov 2026): 11 scans, 59 tools. Poisoned tools caught by content 2/3; with the
  change alert 3/3 (the WhatsApp rug pull is caught only because its description changed
  between scans). Official tools blocked: 1/56 (filesystem `read_text_file`, the known limitation).
- Tests: +3 using a stand-in stdio server (no network).

## v0.6.0 - iteration 5 (tested on real MCP server files)
- New: `mcpscan.extract` reads real MCP server source files (FastMCP Python, TypeScript/JavaScript
  `registerTool`/`server.tool`, `tools/list` JSON) as text, without running them, including a
  description swapped at run time (`fn.__doc__ = ...`, the rug pull in Invariant's WhatsApp attack).
  `scripts/scan_file.py <file or folder>` scans any server; `scripts/run_realfiles_eval.py` scores
  48 real files: Invariant Labs' published attacks, Damn Vulnerable MCP Server, and the official
  reference servers. Ground truth: `data/realfiles_labels.json` (7 poisoned tools, 138 benign).
- Failures found: (1) the Base64 check flagged ordinary long words ("sequentialthinking") as
  encoded text, sending about 1 in 5 official tools to the judge; (2) rule verbs matched inside
  words ("authenti**cat**e ... password" read as "cat ... password"), blocking normal login tools;
  (3) "silently" alone blocked the official filesystem server's `create_directory`
  ("will succeed silently").
- Revision: decoded Base64 must read like text (a space, >= 90% plain ASCII); rule verbs need
  whole-word matches; "silently" counts only before an action verb. No new attack rules were added,
  so the real files stay an untouched test.
- Retest, real files: 5/7 poisoned tools caught by the hybrid, 20/28 disguised copies,
  2/138 benign tools blocked (rules only: 2/7, 19/28; without normalisation: 1/28 disguised).
- Retest, MCPTox test servers: recall 0.592 plain (was 0.653), 0.785 obfuscated (was 0.808),
  FPR 0. The v0.5 figure was partly inflated by accidental in-word matches.
- Synthetic benchmark unchanged. Tests: +7 (2 fail on v0.5). Demo: new "Scan server files" tab
  (choose or drop real files or folders), option to disguise every description, new colour scheme;
  JS extractor checked identical to Python on 260 real files.

## v0.5.0 - iteration 4 (tested on real MCP data)
- Data: real-world benchmark from MCPTox (Wang et al., AAAI 2026): 362 real tool descriptions from
  45 live MCP servers and 485 real poisoned descriptions written for them, plus 1,940 obfuscated
  copies made with our four obfuscation functions. All links, e-mail addresses and keys in the
  attacks are replaced with `.local` placeholders. Built locally by `scripts/build_real_dataset.py`
  (MCPTox has no licence file, so the data is not redistributed in this repo).
- Failure found: v0.4 rules caught only 2.3% of real attacks on unseen servers (7.2% obfuscated).
  They were written for "read the secret and send it out" attacks; real attacks mostly order the
  agent to call another tool first, rewrite a tool's arguments, or claim priority over the user.
- Revision: six new rules (priority_claim, argument_tampering, cross_tool_precondition,
  other_tool_call, threat_language, sensitive_target) and a wider secret_file_read window,
  written from the 18 dev servers only. v0.4 rules kept as `rules_v0_4.yaml` for comparison.
- Retest on the 27 unseen test servers: recall 0.023 -> 0.653 (plain) and 0.072 -> 0.808
  (obfuscated), false-positive rate 0.000 on 187 real tools (McNemar p < 1e-50).
  Synthetic benchmark: obfuscated recall 0.964 and FPR 0 unchanged; the no-normalisation
  baseline now catches 2 of 28 obfuscated test attacks instead of 1.
- Gap: dev recall 0.914 vs test 0.653, so the rules partly fit the dev servers. 79% of the attacks
  still missed are scored "uncertain" and reach the LLM judge, which is where a real model is needed.
- Tests: +5 (2 fail on v0.4; 1 known limitation kept as an expected failure).
- Demo: real MCPTox data in the inspector and benchmark (test servers), JS port re-checked
  identical to Python on all 2,887 manifests; JS word boundaries made Unicode-aware like Python's.

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
