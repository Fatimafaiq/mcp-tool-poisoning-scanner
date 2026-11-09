# Updating the repository to v0.4.0

One person (the repo owner) does this once. It takes about five minutes.

## Steps

1. Open a terminal in your local copy of the repository and get the latest version:
   ```bash
   git checkout main
   git pull
   ```
2. Unzip `mcp-tool-poisoning-scanner_v0.4.0.zip` and copy everything inside it over your repository
   folder, replacing files when asked. (The zip has no `.git` folder, so your history is kept.)
3. Check it works:
   ```bash
   pip install -r requirements.txt
   PYTHONPATH=src python -m pytest -q      # expect: 14 passed
   python scripts/run_eval.py              # expect: rule_norm obfuscated recall 0.964 on the test split
   ```
4. Commit, tag and push:
   ```bash
   git add -A
   git commit -m "v0.4.0: fix false positives on legitimate Unicode tools, frozen test split, live LLM judge demo"
   git tag v0.4.0
   git push --follow-tags
   ```
5. Check GitHub shows the `v0.4.0` tag, a `demo/` folder and `docs/screenshots/`.

Optional, for clearer individual contributions: instead of one commit in step 4, each owner commits
their own files (see the table below) with their own GitHub account, then the owner tags `v0.4.0`.

## What changed in v0.4.0

| File | Change | Owner |
|---|---|---|
| `src/mcpscan/normalizer.py` | Zero-width flagged only inside Latin words; look-alikes mapped only in mixed-script words | Zehra |
| `src/mcpscan/scanner.py` | Obfuscation flags add weight only with attack wording; otherwise escalate to the judge | Zehra |
| `src/mcpscan/llm_judge.py` | Judge prompt treats tool text as untrusted data, same prompt as the demo | Fatima |
| `data/build_dataset.py`, `data/controls/`, `data/index.json` | 16 legitimate Unicode control tools (100 manifests total) | Tamar |
| `scripts/run_eval.py`, `results.json` | Frozen 40/60 split, Wilson intervals, McNemar test, flag ablation, latency | Dimah |
| `tests/test_v04_unicode_controls.py` | 5 regression tests (3 fail on v0.3, all pass on v0.4) | Zehra |
| `demo/index.html` | Browser demo: same scanner on the real benchmark, live Claude judge | Samaira, Fatima |
| `docs/screenshots/` | Demo screenshots, test and evaluation output | Samaira |
| `README.md`, `CHANGELOG.md`, `docs/testing_and_limitations.md` | Updated results, iteration log, limitations | Samaira |
