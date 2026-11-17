# Development evidence log

Project: Detecting Obfuscated Tool Poisoning in MCP Servers: A Hybrid Rule-and-LLM Scanner (CSIT305)
Repository: https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner
Live demo: https://claude.ai/artifact/FvvSS7XkiBubX5428oB7xY (offline copy: `demo/index.html`)
Final version: v1.0.0 (17 Nov 2026)

## 1. Version history

Every version is a commit on `main` (hashes below; open them under Commits on GitHub). Each one
records what failed, what changed, and the retest.

| Version | Date | Commit | Prototype stage | Size of change |
|---|---|---|---|---|
| v0.1.0 | 28 Oct | `554592c` | Skeleton: manifest schema, rule-only scanner, command line | 6 files, +62 lines |
| v0.2.0 | 1 Nov | `e952915` | Detection core: normaliser, YAML rules, hybrid router, judge stub, dataset generator | 6 files, +286 |
| v0.3.0 | 3 Nov | `ffede06` | Evaluation: 100-manifest benchmark, attack-success harness, manual and AI-generated tests, first results | 98 files, +1,993 |
| v0.4.0 | 9 Nov | `97552c6` | Iteration 1: false-positive fix for legitimate Unicode, frozen test split, statistics, browser demo with live Claude judge | 34 files, +1,581 / -149 |
| v0.5.0 | 9 Nov | `058a784` | Iteration 2: first test on real data (MCPTox), six rules for real attack styles | 15 files, +2,065 / -63 |
| v0.6.0 | 10 Nov | `5621b7e` | Iteration 3: reads real server source files; three false-positive fixes found on official servers | 20 files, +1,648 / -435 |
| v0.7.0 | 10 Nov | `8bbc2f7` | Iteration 4: scans live MCP servers over the protocol; change alert for rug pulls | 13 files, +1,438 / -38 |
| (team) | 12 Nov | `1e60bcb`, `35c94d4` | Team copy of the demo and colour fixes | 1 file |
| v1.0.0 | 17 Nov | see `git log` | Final: evidence log, screenshots, team colour fixes merged, fail-closed error handling, results re-run | |

## 2. Prototype iterations (failure, revision, retest)

| # | Version | Test that exposed the problem | Failure | Revision | Retest |
|---|---|---|---|---|---|
| 1 | v0.1 to v0.2 | Obfuscated copies of each attack | Rules on raw text caught 1 of 28 disguised test attacks | Normaliser: NFKC, strip zero-width, map look-alikes, decode Base64 | 27 of 28 caught |
| 2 | v0.2 to v0.3 | Short encoded secrets | Base64 decoder ignored blobs under 16 characters | Threshold 12 characters | Pass |
| 3 | v0.3 to v0.4 | 16 legitimate Unicode tools (Russian, Greek, emoji, JWT...) | 3 of 16 blocked (FPR 0.19) | Flags only inside Latin words / mixed-script words; flags count only with attack wording | 0 of 16 blocked; 3 new regression tests |
| 4 | v0.3 to v0.4 | Demo vs code comparison | Hand-written demo used different rules from the Python code | Line-for-line JavaScript port | 100 of 100 identical |
| 5 | v0.4 to v0.5 | MCPTox: 485 real attacks, 45 real servers | Rules caught 0.8% of real attacks on unseen servers | Six rules written from 18 dev servers only, then frozen | 59 to 65% on 27 unseen servers, 0 false positives |
| 6 | v0.5 to v0.6 | 48 real server files (attack PoCs, DVMCP, official servers) | Long words read as Base64; "cat" matched inside "authenticate"; "silently" blocked an official tool | Text check on decoded Base64; whole-word verbs; "silently" only before an action | Benign tools blocked in real files 8 of 138 to 2 of 138; MCPTox recall 0.653 to 0.592 (honest figure) |
| 7 | v0.6 to v0.7 | 10 live servers over the MCP protocol | WhatsApp attack server is clean at first start, poisoned at second | Fingerprint each tool, report CHANGED | 3 of 3 attacks caught (2 by content, 1 by change alert) |

## 3. Implementation records

| Component | File | Introduced | Last changed |
|---|---|---|---|
| Manifest schema | `src/mcpscan/schema.py` | v0.1 | v0.3 |
| Normaliser | `src/mcpscan/normalizer.py` | v0.2 | v0.6 (Base64 text check) |
| Rules (11) | `src/mcpscan/rules.yaml` | v0.1 | v0.6 (whole-word verbs) |
| Rule scanner and hybrid router | `src/mcpscan/scanner.py` | v0.1 | v1.0 (fail-closed error paths) |
| LLM judge (stub, Ollama, Claude in demo) | `src/mcpscan/llm_judge.py` | v0.2 | v0.4 |
| File reader (Python, TS/JS, JSON) | `src/mcpscan/extract.py` | v0.6 | v0.6 |
| Live MCP client (stdio, HTTP) | `src/mcpscan/live.py` | v0.7 | v1.0 |
| Synthetic benchmark | `data/build_dataset.py` | v0.2 | v0.4 |
| Real-data builder (MCPTox) | `scripts/build_real_dataset.py` | v0.5 | v0.5 |
| Evaluations | `scripts/run_eval.py`, `run_real_eval.py`, `run_realfiles_eval.py`, `run_live_eval.py` | v0.3 to v0.7 | v0.7 |
| Command-line scanners | `scripts/scan_file.py`, `scripts/scan_live.py` | v0.6, v0.7 | v0.7 |
| Browser demo | `demo/index.html` | v0.3 | v1.0 |
| Tests (31) | `tests/` | v0.1 | v1.0 |

## 4. Design decisions

| Date | Decision | Alternatives rejected | Reason |
|---|---|---|---|
| 28 Oct | Staged hybrid: rules first, LLM only for uncertain tools | LLM-only gateway; rule-only; supervised classifier | Cost, auditability, and isolating the effect of obfuscation |
| 1 Nov | Normalise before matching (NFKC, zero-width, look-alikes, Base64) | Match raw text; block any non-ASCII | Covers the three obfuscation families in the research question |
| 3 Nov | Fail closed: errors withhold a tool | Fail open | A security control must not pass what it cannot read |
| 9 Nov | Obfuscation flags count only with attack wording | Flag any hidden character | Legitimate multilingual tools were being blocked |
| 9 Nov | Frozen group-wise split; Wilson intervals; exact McNemar | Results on the full set | Avoid reporting on data used for tuning |
| 9 Nov | Real data split by server (18 dev, 27 test) | Random split by item | Attacks on one server must not appear on both sides |
| 10 Nov | No new attack rules after v0.5 | Tune on the real files | Keep real files and live servers as untouched tests |
| 10 Nov | Live client written with the standard library | MCP SDK client | No version lock; SDK v2 broke the attack PoCs |
| 10 Nov | Pin tool fingerprints | Content rules only | Rug pulls cannot be seen in one scan |
| 17 Nov | Merge the team's demo colour fixes into the official demo | Keep two versions | One demo, matching the GitHub copy |
| 17 Nov | Implement fail-closed error paths in code (judge or rule error withholds the tool) | Document only | The design promised it; review found it was not yet in the code |

## 5. Testing and validation evidence

| Level | What | Result | Evidence |
|---|---|---|---|
| Unit and regression tests | 31 tests in 7 files | 30 pass, 1 expected failure (known limitation) | `docs/screenshots/v1.0/t_pytest.png` |
| Synthetic benchmark | 100 manifests, frozen 59-manifest test split | Disguised attacks caught 0.071 without normalisation, 0.964 with; 0 false positives | `results.json`, `t_eval.png` |
| Real data (MCPTox) | 2,787 manifests, 27 unseen test servers | Recall 0.592 plain, 0.785 disguised (0.149 without normalisation); 0 of 187 real tools blocked | `results_real.json`, `t_real.png` |
| Real server files | 48 files, 145 tools, 7 poisoned | Hybrid 5 of 7; disguised 20 of 28 (1 of 28 without normalisation); 2 of 138 benign blocked | `results_realfiles.json`, `t_files.png` |
| Live servers (17 Nov) | 10 servers, 59 tools | Poisoned 3 of 3 (2 by content, 1 by change alert); 1 of 56 official tools blocked | `results_live.json`, `t_live.png` |
| Cross-implementation | Browser demo vs Python | Identical on 2,887 manifests and 260 real files | `CHANGELOG.md` v0.6 |

Commands to reproduce: `docs/USAGE_GUIDE.md`.

## 6. Screenshots (docs/screenshots/v1.0/)

| File | Shows |
|---|---|
| `t_pytest.png` | All tests run |
| `t_demo.png` | Same attack plain and disguised, without and with normalisation |
| `t_eval.png`, `t_real.png`, `t_files.png`, `t_live.png` | Evaluation output on each dataset |
| `d_files.png` | Demo scanning real server files |
| `d_files_disguised_off.png`, `d_files_disguised_on.png` | Every description disguised: 0 blocked without normalisation, attacks blocked with it |
| `d_inspect_off.png`, `d_inspect_on.png` | A real MCPTox attack in disguise, before and after normalisation |
| `d_bench.png` | Benchmark on the 27 unseen real servers |

## 7. Work distribution matrix

R = responsible (did the work), C = contributed, Rv = reviewed. **Each member confirms their row
and adds their own commit to this file from their own GitHub account.**

| Work package | Fatima | Zehra | Tamar | Dimah | Samaira |
|---|---|---|---|---|---|
| Research question, literature review | C | C | C | C | R |
| Normaliser and rules | Rv | R | | C | |
| LLM judge and prompt | R | | | | C |
| Synthetic dataset and Unicode controls | | C | R | | |
| Real data (MCPTox) and labels | | | R | C | |
| Evaluation scripts and statistics | | | C | R | |
| Real files and live scanning | R | C | | C | |
| Demo page and colour scheme | C | | | | R |
| Tests | | R | C | C | |
| Report, paper, evidence log | C | C | C | C | R |

[To confirm by each member before submission]

Note on commit authors: v0.1 to v0.4 and the 12 Nov demo commits were pushed from the shared
Emtec Group account; v0.5 to v0.7 show "Claude" as author because they were produced with Claude
and pushed from this session (see `AI_USE_DECLARATION.md`). Individual work is therefore recorded in
this matrix and in each member's own commits from 17 Nov onward.
