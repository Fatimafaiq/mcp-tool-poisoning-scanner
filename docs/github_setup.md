# GitHub setup and development-history guidance

Create the repo under your own accounts so commit history is genuine, traceable, individual evidence.

```bash
git init
git add .
git commit -m "v0.1: skeleton, schema, rule-only scanner"      # then stage iterations as separate commits
git branch -M main
git remote add origin https://github.com/<org>/mcp-tool-poisoning-scanner.git
git push -u origin main
git tag v0.3.0 && git push --tags
```

For traceable individual contributions (rubric), each member works on a branch and opens a pull
request for their workstream (see CONTRIBUTIONS.md), so authorship, reviews and revisions are recorded.
Do not squash the history before submission: the iteration record is the evidence.
