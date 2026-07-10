# evalsec

<p align="center">
  <strong>An LLM benchmark for vulnerability triage.</strong><br>
  Evaluating how well language models can perform real DevSecOps work.
</p>

<p align="center">
  <a href="#quick-start"><strong>Quick Start</strong></a> ·
  <a href="#tasks"><strong>Tasks</strong></a> ·
  <a href="#results"><strong>Results</strong></a> ·
  <a href="https://github.com/frhnardi/evalsec/blob/main/LIMITATIONS.md"><strong>Limitations</strong></a>
</p>

---

## What is evalsec?

evalsec measures how well LLMs triage container vulnerability scans. Instead of testing general knowledge or code generation, it tests a specific, safety-critical skill:

> **Given a Trivy scan + deployment context, can the model correctly determine which vulnerabilities are actually exploitable and produce a prioritized remediation plan in VEX format?**

The benchmark uses real Trivy scan output from real container images, combined with expert-reviewed ground truth labels. Each test case includes stack context (deployment architecture, code reachability, runtime hardening, regulatory requirements) so models must distinguish scanner noise from genuine threats.

## Why this matters

Security teams drown in scanner alerts. A typical Trivy scan surfaces dozens or hundreds of findings, but only a fraction are exploitable in context. Getting triage wrong means wasting engineering time on false positives, or missing a real Log4Shell in an internet-facing payment gateway.

This benchmark tests whether LLMs can make these judgment calls reliably. It also includes dedicated prompt injection test cases (OWASP LLM Top 10 #1) where scan output contains malicious override instructions, testing instruction hierarchy robustness.

## Quick Start

```bash
git clone git@github.com:frhnardi/evalsec.git
cd evalsec

# Install dependencies
uv sync

# Run the benchmark (requires API keys)
uv run evalsec run --model deepseek_v4_pro --model claude_sonnet_46

# Grade existing responses
uv run evalsec grade outputs/responses_trivy_triage_*.json

# Build dashboard from scores
uv run evalsec build --scores outputs/scores_*.json --responses outputs/responses_*.json
```

Set `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, and `ANTHROPIC_API_KEY` in your `.env` file. See `.env.example`.

## Tasks

| Task | Type | Cases | Description |
|------|------|:----:|-------------|
| `trivy_triage` | Container CVE | 20 | Prioritize and assess Trivy scan findings using deployment context |
| `codeql_triage` | SAST | 3 | Triage CodeQL alerts: SQL injection, stored XSS, path traversal |

Each case provides verbatim Trivy output, stack context (Kubernetes deployment details, code reachability analysis, runtime hardening), risk metadata (CVSS, EPSS, CISA KEV, exploit maturity), and regulatory context (NIST SP 800-53, PCI-DSS).

Models must produce structured JSON in VEX format (CSAF standard) with per-CVE status, justification, priority, and actionable remediation steps.

## How Grading Works

evalsec uses a **two-pass grading system**:

| Pass | Method | Weight | Description |
|------|--------|:------:|-------------|
| Pass 1 | Deterministic | 40% | Regex + JSON validation: format, CVE coverage, verdict accuracy, priority ordering, hallucination detection. Pure Python, no API calls, zero cost. |
| Pass 2 | LLM-as-Judge | 60% | Claude Opus 4.7 scores 4 rubric dimensions: reachability reasoning, prioritization, actionability, conciseness. Anti-bias instructions prevent stylistic self-preference. |

Non-LLM baselines (CVSS sort, Trivy severity sort, EPSS sort, reachability heuristic) provide a lower bound. They score 55–69 out of 100, confirming that simple severity sorting is insufficient.

## Results

| Model | Average Score | Category |
|-------|:------------:|----------|
| DeepSeek V4 Pro | 85.16 | LLM |
| Reachability Heuristic | 68.84 | Baseline |
| CVSS Severity Sort | 61.72 | Baseline |
| EPSS-Based Priority | 61.72 | Baseline |
| Trivy Severity Sort | 54.69 | Baseline |

*20 trivy_triage cases. CodeQL results pending. Full dashboard at `dist/index.html`.*

> These are pre-fix results from an older dataset version. A fresh benchmark run with the validated dataset is the next step.

## Architecture

```
CLI (evalsec run / grade / build)
  └─ Runner: loads YAML test cases, calls models via adapters
       ├─ LLM Adapters: OpenRouter (Claude, Kimi, Qwen) + DeepSeek API
       ├─ Baselines: CVSS, EPSS, Trivy severity, reachability heuristic
       └─ Grader: Pass 1 (deterministic) + Pass 2 (LLM judge)
            └─ Dashboard: static HTML + Chart.js → GitHub Pages
```

## Tech Stack

- **Python 3.12** with Pydantic, Typer, structlog, httpx, Rich
- **uv** for package management
- **136 unit tests** (pytest), strict mypy, ruff linting
- **GitHub Actions CI/CD** with weekly benchmark pipeline
- **Static dashboard** built with Jinja2 + Chart.js

## Known Limitations

See [LIMITATIONS.md](LIMITATIONS.md) for a full discussion:

- **Judge-model bias**: Claude Opus judging Claude Sonnet creates same-family scoring inflation
- **Small dataset**: 23 cases is insufficient for statistical significance
- **Single-run design**: no repeated measures for within-model variance
- **Synthetic deployment contexts**: generated rather than from real incidents
- **API-dependent**: no frozen model snapshots, scores change with model versions
- **Distribution skew**: CRITICAL/HIGH-weighted, limited distroless/scratch images

## Roadmap

- [ ] Multi-judge ensembles with inter-rater agreement tracking
- [ ] IaC scanning tasks (Checkov, tfsec) — 6 of 8 planned categories
- [ ] Secrets detection and DAST tasks
- [ ] Expand to 200+ cases for statistical significance
- [ ] Frozen model snapshots for reproducibility

## License

MIT — see [LICENSE](LICENSE).
