# evalsec — DevSecOps LLM Benchmark

> **Evaluating how well LLMs can perform real DevSecOps work — specifically, vulnerability triage from container scans.**

## 1. What is evalsec?

evalsec is a benchmark framework that measures how well LLMs can do the job of a **DevSecOps engineer**. Instead of testing general knowledge (like MMLU) or code generation (like HumanEval), it tests a specific, practical skill:

> **Given a container vulnerability scan (Trivy output) + deployment context, can the model produce a correct, prioritized remediation plan?**

The benchmark uses **real Trivy scan output** from real container images, combined with **expert-written ground truth** (exploitability verdicts, priority order, remediation actions). Models are scored through a two-pass grading system.

---

## 2. Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│                    CLI (src/evalsec/cli.py)                   │
│  evalsec run    → benchmark models                            │
│  evalsec grade  → grade existing responses                    │
│  evalsec build  → rebuild dashboard from scores               │
└───────────────────────┬───────────────────────────────────────┘
                        │
┌───────────────────────▼───────────────────────────────────────┐
│                    Runner (src/evalsec/runner.py)              │
│  • Loads YAML test cases (tests/data/trivy_triage/*.yaml)     │
│  • Calls each model via adapter                               │
│  • Saves responses JSON + estimates cost                       │
└──────┬────────────────────────────────┬───────────────────────┘
       │                                │
       ▼                                ▼
┌──────────────┐               ┌──────────────────┐
│  Adapters    │               │   Baselines      │
│  (LLMs)      │               │  (non-LLM)       │
│              │               │                  │
│  OpenRouter  │               │  CVSS sort       │
│  ├─ claude   │               │  Trivy severity  │
│  ├─ kimi     │               │  EPSS sort       │
│  └─ qwen     │               │  Reachability    │
│              │               │                  │
│  DeepSeek    │               └──────────────────┘
│  └─ deepseek │
└──────────────┘
       │
       ▼
┌───────────────────────────────────────────────────────────────┐
│                    Grader (src/evalsec/grader.py)              │
│  Two-pass grading system:                                     │
│  Pass 1 → Deterministic (free, no API calls)                  │
│  Pass 2 → LLM-as-judge (paid, uses Claude Opus 4.7)          │
└───────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────────┐
│               Dashboard (src/evalsec/dashboard.py)             │
│  Static HTML + Chart.js, deployed to GitHub Pages              │
└───────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| [`src/evalsec/cli.py`](src/evalsec/cli.py) | CLI entry point — `run`, `grade`, `build` commands |
| [`src/evalsec/runner.py`](src/evalsec/runner.py) | Benchmark runner — loads cases, calls models, saves responses |
| [`src/evalsec/grader.py`](src/evalsec/grader.py) | Two-pass grader — deterministic + LLM judge |
| [`src/evalsec/dashboard.py`](src/evalsec/dashboard.py) | Static HTML dashboard builder |
| [`src/evalsec/tasks/trivy_triage.py`](src/evalsec/tasks/trivy_triage.py) | Task definition — prompts, schema, judge prompt |
| [`src/evalsec/tasks/base.py`](src/evalsec/tasks/base.py) | Pydantic data models (TaskCase, Rubric, GroundTruth) |
| [`src/evalsec/adapters/__init__.py`](src/evalsec/adapters/__init__.py) | Model registry — pricing, endpoints, configs |
| [`src/evalsec/adapters/openai_compat.py`](src/evalsec/adapters/openai_compat.py) | OpenAI-compatible API adapter (OpenRouter + DeepSeek) |
| [`src/evalsec/baselines.py`](src/evalsec/baselines.py) | Non-LLM baselines for comparison |
| [`tests/data/trivy_triage/*.yaml`](tests/data/trivy_triage) | Test case YAML files (20 cases) |
| [`tests/unit/`](tests/unit) | 136 unit tests |

---

## 3. The `trivy_triage` Task (Core Benchmark)

### 3.1 What It Tests

The `trivy_triage` task simulates a real-world scenario where a DevSecOps engineer must analyze a Trivy container scan and produce a prioritized remediation plan in **VEX (Vulnerability Exploitability eXchange)** format — the CSAF industry standard.

### 3.2 Input → Model → Output

```
┌─────────────────────────────────────────────┐
│                 INPUT (YAML)                 │
│                                              │
│  Trivy Scan Output:                          │
│  ┌─────────────────────────────────────┐    │
│  │ Library    │ Vuln         │ Severity │    │
│  │ log4j-core │ CVE-2021-44228│ CRITICAL│    │
│  │ Pillow     │ CVE-2023-50447│ HIGH    │    │
│  │ runc       │ CVE-2024-21626│ HIGH    │    │
│  │ ...        │ ...          │ ...     │    │
│  └─────────────────────────────────────┘    │
│                                              │
│  Stack Context:                              │
│  • Service: payment-gateway-v2               │
│  • Exposure: public internet via ALB         │
│  • Code reachability analysis                │
│  • Regulatory: OJK 22/2023                   │
│  • Runtime hardening controls                │
│                                              │
│  Risk Metadata (per finding):                │
│  • CVSS Score, EPSS Percentile               │
│  • CISA KEV status, Exploit Maturity         │
│  • Fixed Version, Runtime Exposure           │
│  • Asset Criticality, Internet-Facing        │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│           MODEL must produce VEX JSON        │
│                                              │
│  {                                           │
│    "document": { "type": "vex" },            │
│    "statements": [                           │
│      {                                       │
│        "vulnerability": {"id": "CVE-..."},   │
│        "status": "affected",                 │
│        "justification": "code_not_reachable",│
│        "impact_statement": "...",            │
│        "action_statement": "...",            │
│        "priority": "P0",                     │
│        "timeline": "72 hours"                │
│      }                                       │
│    ]                                         │
│  }                                           │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│              TWO-PASS GRADING                │
│  See Section 4 below                         │
└─────────────────────────────────────────────┘
```

### 3.3 Priority Definitions

| Priority | Meaning | Timeline |
|----------|---------|----------|
| **P0** | Actively exploited in the wild AND reachable from this deployment | 72 hours |
| **P1** | Reachable but no known active exploitation | This sprint |
| **P2** | Partial — mitigating controls exist but risk not fully eliminated | This sprint |
| **P3** | Not reachable / false positive | Next quarter |

### 3.4 Example: Case 001 — Log4Shell

**Trivy finds 5 CVEs** in a tomcat container running a payment gateway:

| CVE | Severity | Stack Context Says | Correct Verdict | Priority |
|-----|----------|-------------------|-----------------|----------|
| CVE-2021-44228 (Log4Shell) | CRITICAL | log4j dipakai di HTTP handlers, internet-facing, CISA KEV | **affected** | **P0** |
| CVE-2024-21626 (runc) | HIGH | Container escape, tapi ada RO rootfs + non-root user mitigasi | **under_investigation** | **P1** |
| CVE-2023-50447 (Pillow) | HIGH | eval() **never called** — dead code | **not_affected** | **P3** |
| CVE-2023-0286 (openssl) | HIGH | No attacker-controlled cert path | **not_affected** | **P3** |
| CVE-2022-29824 (libxml2) | HIGH | No XML parsing in application | **not_affected** | **P3** |

**Key insight:** A good model must NOT mark all CRITICAL/HIGH as exploitable. It must use the stack context to determine real reachability. Log4Shell is P0 because it's reachable + internet-facing + KEV catalogued. Pillow is a false positive because `eval()` is never called.

### 3.5 VEX Status Values

| Status | Meaning |
|--------|---------|
| `affected` | Vulnerable code is reachable and exploitable |
| `not_affected` | Vulnerable code is NOT reachable (with justification) |
| `under_investigation` | Partial — some mitigations exist, risk not fully eliminated |

### 3.6 Justification Values (when `not_affected`)

| Value | Meaning |
|-------|---------|
| `code_not_reachable` | The vulnerable code path is not reachable from this deployment |
| `vulnerable_code_cannot_be_controlled_by_attacker` | Attacker cannot control the vulnerable input |
| `vulnerable_code_not_in_execute_path` | The vulnerable function is never called |
| `protected_by_compensating_control` | WAF, seccomp, NetworkPolicy mitigates the risk |
| `component_not_present` | The affected component is not included |

---

## 4. Two-Pass Grading System

### 4.1 Pass 1 — Deterministic (Free, No API Calls)

Performed by [`JsonValidator`](src/evalsec/grader.py:276) + [`RegexGrader`](src/evalsec/grader.py:201). These are pure Python checks — no LLM involved, zero cost.

| Component | What It Checks | Score Range |
|-----------|---------------|-------------|
| **Format** | Valid JSON? Has `document.type = "vex"`? Required fields present? | 0–10 |
| **Coverage** | Did the model address all CVEs from the ground truth? Penalizes missing CVEs | 0–20 |
| **Verdict** | Are VEX statuses correct? (affected/not_affected matches ground truth) | 0–20 |
| **Priority** | Does priority ordering match ground truth priority_order? | 0–15 |
| **Regex** | Does response contain expected keywords? (e.g., "log4shell", "reachable") | 0–10 |
| **Hallucination** | Did the model invent CVEs that don't exist? Penalty applied | 0–(-15) |

**`pass1_score` = weighted combination of the above** — max ~75, but hallucination can pull it down.

### 4.2 Pass 2 — LLM-as-Judge (Paid)

Performed by [`JudgeGrader`](src/evalsec/grader.py:552). Uses a separate LLM (default: **Claude Opus 4.7**) to score 4 rubric dimensions.

| Dimension | Max | What It Measures |
|-----------|-----|-----------------|
| **reachability_reasoning** | 25 | Does the model use stack context to determine real exploitability? Full marks for correctly identifying reachability of each finding |
| **prioritization** | 25 | Does the model rank findings by real-world urgency (not just CVSS)? Correct P0→P3 ordering |
| **actionability** | 25 | Are remediation steps specific (version numbers, config changes, timelines)? Penalizes vague "update dependencies" |
| **conciseness** | 25 | Is the response focused? No preamble, no disclaimers, no irrelevant details |

**`pass2_score` = sum of 4 rubric dimensions** — max 100.

### 4.3 Final Score Calculation

```
total = (pass1_score × WEIGHT_PASS1) + (pass2_score × WEIGHT_PASS2)
      = (pass1_score × 0.40) + (pass2_score × 0.60)
```

Pass 2 is weighted higher (60%) because it captures nuanced qualitative judgment that deterministic checks cannot.

### 4.4 Important: The Judge Doesn't Know Model Names

The [`JUDGE_USER_PROMPT_TEMPLATE`](src/evalsec/tasks/trivy_triage.py:194) only passes `{model_response}` — the raw response text. The model name/identity is **never** injected. However, since the judge is Claude Opus 4.7 and one of the benchmarked models is Claude Sonnet 4.6, subtle **stylistic self-preference bias** is theoretically possible (see [`LIMITATIONS.md`](LIMITATIONS.md) Section 1).

Anti-bias instructions were added to [`JUDGE_SYSTEM_PROMPT`](src/evalsec/tasks/trivy_triage.py:167) on 2026-05-22 to mitigate this.

---

## 5. Models Benchmarked

### 5.1 LLM Models

| Model | Key | Provider | Input Cost/1M | Output Cost/1M | Notes |
|-------|-----|----------|---------------|----------------|-------|
| **Claude Sonnet 4.6** | `claude_sonnet_46` | OpenRouter | $3.00 | $15.00 | Anthropic |
| **Kimi K2 Thinking** | `kimi_k2_thinking` | OpenRouter | $1.50 | $7.50 | Moonshot AI |
| **Qwen 3.5** | `qwen_3_5` | OpenRouter | $0.40 | $2.40 | Alibaba |
| **DeepSeek V4 Pro** | `deepseek_v4_pro` | DeepSeek API | $0.50 | $2.00 | DeepSeek |

### 5.2 Judge Model

| Model | Key | Provider | Input Cost/1M | Output Cost/1M |
|-------|-----|----------|---------------|----------------|
| **Claude Opus 4.7** (default) | `claude_opus_47` | OpenRouter | $5.00 | $25.00 |
| DeepSeek V4 Pro (alternative) | `deepseek_v4_pro` | DeepSeek API | $0.50 | $2.00 |

Use `--judge-model deepseek_v4_pro` to reduce judge cost by ~10x (~$0.22 vs ~$2.20 for 80 grades).

### 5.3 Non-LLM Baselines

| Baseline | Strategy | Description |
|----------|----------|-------------|
| **CVSS sort** | `cvss` | Sort findings by CVSS score descending, all marked `affected` |
| **Trivy severity** | `trivy` | Sort by Trivy severity (CRITICAL → LOW), all `affected` |
| **EPSS sort** | `epss` | Sort by EPSS exploit probability percentile descending |
| **Reachability heuristic** | `reachability` | Uses internet_facing + cvss + runtime_exposure heuristics |

Baselines score 54–69 out of 100, providing a lower bound for LLM comparison.

---

## 6. Test Cases

### 6.1 Dataset (20 cases)

| ID | Case | Image | Weight | Highlights |
|----|------|-------|--------|------------|
| 001 | Log4Shell | tomcat:9.0.30 | 1.5 | **Flagship** — classic Log4Shell reachability test |
| 002 | Grafana | grafana:8.0.0 | 1.0 | Multiple plugins, mixed reachability |
| 003 | MySQL | mysql:5.7 | 1.0 | Database-specific vulnerabilities |
| 004 | Nginx | nginx:1.18 | 1.0 | Web server, WAF mitigating controls |
| 005 | PostgreSQL | postgres:11 | 1.0 | Database with authentication bypass |
| 006 | Python 3.8 | python:3.8 | 1.0 | Python library vulns, dead code paths |
| 008 | Redis | redis:5.0 | 1.0 | In-memory DB, ACL mitigations |
| 009 | Tomcat | tomcat:9.0.30 | 1.0 | Java servlet container |
| 010 | Alpine | alpine:3.14 | 1.0 | Minimal distro, musl libc vulns |
| 011 | Elasticsearch | elasticsearch:7.17.28 | 1.0 | Java-based search engine |
| 013 | Golang | golang:1.16 | 1.0 | Go stdlib vulnerabilities |
| 015 | Prometheus | prometheus:v2.30.0 | 1.0 | Monitoring system |
| 016 | RabbitMQ | rabbitmq:3.8 | 1.0 | Message broker |
| 017 | Ubuntu | ubuntu:18.04 | 1.0 | Old Ubuntu LTS |
| 018 | Vault | vault:1.8 | 1.0 | HashiCorp Vault |
| 019 | Ghost | ghost:4 | 1.0 | Node.js CMS — **context overflow risk** |
| 020 | Node 18 | node:18 | 1.0 | Node.js runtime |
| 021 | WordPress | wordpress:5.7 | 1.0 | PHP-based CMS |
| 022 | Nginx prompt injection | nginx:1.18 | 1.0 | Tests resistance to prompt injection |
| 023 | Elasticsearch prompt injection | elasticsearch:7.17.28 | 1.0 | Tests resistance to prompt injection |

### 6.2 YAML Structure

Each test case is a YAML file containing:

```yaml
id: trivy_triage_001
task: trivy_triage
version: v1

source:          # Metadata tentang scan
  type: self_scan
  image: tomcat:9.0.30
  scanned_at: 2026-05-12

input: |         # Raw Trivy scan output (verbatim)
  ...

stack_context: | # Deployment context + code analysis
  Service: payment-gateway-v2
  Exposure: public internet
  Code reachability: ...
  Regulatory: OJK 22/2023

ground_truth:    # Expert-written answers
  exploitable_findings:
    - cve: CVE-2021-44228
      verdict: exploitable
      reasoning: ...
      action: ...
  non_exploitable_findings: [...]
  partial_findings: [...]
  priority_order:
    - CVE-2021-44228
    - ...

expected_response_includes:  # Regex patterns pass1 checks
  - "(?i)log4shell|log4j"

rubric:          # Pass 2 judge rubric (per case)
  reachability_reasoning: { max_score: 25, description: ... }
  prioritization:          { max_score: 25, description: ... }
  actionability:           { max_score: 25, description: ... }
  conciseness:             { max_score: 25, description: ... }

weight: 1.5      # Case weight in final score (flagship = 1.5x)
```

---

## 7. Pipeline & Deployment

### 7.1 GitHub Actions Workflow

The benchmark runs via [`benchmark.yml`](.github/workflows/benchmark.yml):

1. **Phase 1: Benchmark** — Run LLM models against all 20 cases
2. **Phase 2: Grade** — Grade responses through two-pass system
3. **Phase 3: Build & Deploy** — Generate static dashboard + deploy to GitHub Pages

The pipeline supports a **deploy-only mode** (checkbox) that skips benchmark + grading and rebuilds from existing scores.

### 7.2 Cost per Full Run

| Component | Models × Cases | Approx Cost |
|-----------|---------------|-------------|
| 3 OpenRouter models | 3 × 20 = 60 calls | ~$1.50 |
| DeepSeek V4 Pro | 1 × 20 = 20 calls | ~$0.20 |
| Judge (Claude Opus 4.7) | 80 grades | ~$2.20 |
| **Total** | | **~$3.90** |

The judge model is the primary cost driver (~56% of total).

### 7.3 finish_reason System

Each model response captures a `finish_reason` field:

| finish_reason | Meaning | Dashboard Badge |
|---------------|---------|-----------------|
| `stop` | Normal completion | None |
| `length` | Response exceeded max_tokens | "Truncated" |
| `error` | API error (403, timeout, etc.) | "Error" |
| `context_overflow` | Context window exceeded | "Skipped" |

---

## 8. Dashboard

The dashboard ([`dashboard.html.j2`](src/evalsec/templates/dashboard.html.j2)) is a static HTML page built with:

- **Chart.js** — Radar/bar charts comparing model performance
- **Tab navigation** — Overview, Leaderboard, Models, Methodology
- **Theme toggle** — Dark/light mode
- **Model detail panels** — Per-model breakdown with dimension scores
- **Cost display** — Total cost per model per run

The dashboard is rebuilt automatically on every pipeline run and deployed to GitHub Pages at `dist/index.html`.

---

## 9. Current Results (as of May 2026)

Based on the last successful benchmark run (before OpenRouter credits ran out):

| Rank | Model | Score |
|------|-------|-------|
| 🥇 | DeepSeek V4 Pro | 91.2 |
| 🥈 | Claude Sonnet 4.6 | 82.0 |
| 🥉 | Kimi K2 Thinking | 72.3 |
| 4 | Qwen 3.5 | 68.0 |

**Note:** DeepSeek is the current leader. These results should be treated as directional indicators due to small sample size (20 cases).

---

## 10. Known Limitations

See [`LIMITATIONS.md`](LIMITATIONS.md) for full details. Key limitations:

1. **Judge-model bias** — Claude Opus 4.7 judging Claude Sonnet 4.6 creates same-family scenario
2. **Small dataset** — Only 20 test cases, insufficient for statistical significance
3. **Single-run design** — No repeated measures for within-model variance
4. **API-dependent** — Results depend on model versions that change without notice
5. **Distribution skew** — Heavily weighted toward Alpine, CRITICAL/HIGH severities
6. **Task coverage** — Only Trivy (20 cases) + CodeQL (3 cases), no IaC/secrets/runtime
7. **Synthetic context** — Stack contexts are generated, not from real incidents

---

## 11. How to Run

```bash
# Full benchmark run
uv run evalsec run --model claude_sonnet_46 --model kimi_k2_thinking --model qwen_3_5 --model deepseek_v4_pro

# Grade existing responses
uv run evalsec grade outputs/responses_trivy_triage_*.json

# Rebuild dashboard from existing scores (skip benchmark + grade)
uv run evalsec build --scores outputs/scores_trivy_triage_*.json --responses outputs/responses_trivy_triage_*.json --deploy

# Use DeepSeek as judge (cheaper)
uv run evalsec grade --judge-model deepseek_v4_pro

# Dry-run cost estimate
uv run evalsec run --model claude_sonnet_46 --dry-run

# Run tests
uv run pytest
```

---

*For detailed technical documentation, see the source files linked throughout this overview.*
