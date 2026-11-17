# Evidence index (one page for reviewers)

Repository: https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner · Final release: [v1.0.0](https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner/releases/tag/v1.0.0)

| What is claimed | Evidence | Where |
|---|---|---|
| Sustained development, v0.1 (28 Oct) to v1.0 (17 Nov) | Every version as a commit, with date and author | [Commits](https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner/commits/main), [Releases](https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner/releases) |
| Prototype iterations (failure, revision, retest) | 7 iterations with the test that exposed each failure | [DEVELOPMENT_LOG.md §2](DEVELOPMENT_LOG.md), [CHANGELOG.md](../CHANGELOG.md) |
| Implementation records | Each component, file, version introduced and last changed | [DEVELOPMENT_LOG.md §3](DEVELOPMENT_LOG.md) |
| Design decisions and rejected alternatives | Dated decisions with reasons | [DEVELOPMENT_LOG.md §4](DEVELOPMENT_LOG.md) |
| Tests pass | 31 tests: 30 pass, 1 expected failure (known limitation) | [`tests/`](../tests), [screenshot](screenshots/v1.0/t_pytest.png), [output](screenshots/v1.0/pytest.txt) |
| Obfuscation defeats raw-text rules; normalisation restores them | Synthetic test split: 0.071 to 0.964 | [`results.json`](../results.json), [screenshot](screenshots/v1.0/t_eval.png) |
| Works on real attacks (MCPTox, 27 unseen servers) | Recall 0.592 plain, 0.785 disguised, 0 of 187 real tools blocked | [`results_real.json`](../results_real.json), [screenshot](screenshots/v1.0/t_real.png) |
| Works on real malicious files (not written by us) | 5 of 7 poisoned tools; 1 of 28 to 20 of 28 disguised | [`results_realfiles.json`](../results_realfiles.json), [labels](../data/realfiles_labels.json), [screenshot](screenshots/v1.0/t_files.png) |
| Works on live MCP servers | 10 servers, 59 tools, 17 Nov: 3 of 3 attacks caught, 1 of 56 official tools blocked | [`results_live.json`](../results_live.json), [screenshot](screenshots/v1.0/t_live.png) |
| Demo shows the same results as the code | Browser port identical on 2,887 manifests and 260 files | [demo](../demo/index.html), [screenshots](screenshots/v1.0/) |
| The tool can be installed and used | `pip install git+https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner`, then `mcpscan` | [README](../README.md), [cli.py](../src/mcpscan/cli.py) |
| Paper | 6-page IEEE paper; every number from the results files | [paper/](../paper/CSIT305_IEEE_Paper_Final.pdf) |
| How to reproduce every number | Step-by-step commands | [USAGE_GUIDE.md](USAGE_GUIDE.md) |
| AI use | What AI did, prompts used, how it was checked; AI commits show "Claude" as author | [AI_USE_DECLARATION.md](../AI_USE_DECLARATION.md), [AI_PROMPT_LOG.md](AI_PROMPT_LOG.md) |
| Individual contributions | Work distribution matrix and each member's own commit | [DEVELOPMENT_LOG.md §7](DEVELOPMENT_LOG.md), [Commits](https://github.com/Fatimafaiq/mcp-tool-poisoning-scanner/commits/main) |

Live demo (hosted): https://claude.ai/artifact/FvvSS7XkiBubX5428oB7xY
