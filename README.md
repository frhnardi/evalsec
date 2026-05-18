# evalsec

An open-source LLM benchmark for DevSecOps tasks.

> **Status:** v0.1.0 — alpha

## Quick start

```bash
uv sync
uv run evalsec --help
```

## Tasks

| Task | Type | Cases | Description |
|------|------|-------|-------------|
| [`trivy_triage`](src/evalsec/tasks/trivy_triage.py) | Container CVE | 20 | Prioritise and assess Trivy scan findings |
| [`codeql_triage`](src/evalsec/tasks/codeql_triage.py) | SAST | 3 | Triage CodeQL alerts (SQLi, XSS, path traversal) |

## Current results (trivy_triage)

| Model | Average Score | Judge |
|-------|:------------:|-------|
| **deepseek_v4_pro** | **85.16** | DeepSeek V4 Pro |
| baseline_reachability | 68.84 | — |
| baseline_cvss | 61.72 | — |
| baseline_epss | 61.72 | — |
| baseline_trivy | 54.69 | — |

*20 trivy_triage cases. See `dist/index.html` for full dashboard. CodeQL results pending.*

> **Note:** These are pre-fix results from an older dataset version. A fresh benchmark run with the current 136/136 validated dataset is the next step.

## Known limitations

See [`LIMITATIONS.md`](LIMITATIONS.md) for a detailed discussion of:

- **Judge-model bias** — same-family judging (Claude Opus → Claude Sonnet) and the legacy self-judging issue
- **Ground truth quality** — LLM-assisted labels, the Trivy compact-format truncation fix, and synthetic deployment contexts
- **Scope** — only 2 of 8 planned DevSecOps categories covered
- **Dataset size** — 23 cases is insufficient for statistical significance
- **Reproducibility** — API-dependent, no frozen model snapshots
- **Cost estimation** — naive token heuristic, judge costs excluded
- **Regulatory context** — Indonesian regulation friction in English prompts
