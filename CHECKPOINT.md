# evalsec — Project Checkpoint (v0.1.0)

> Generated: 2026-05-13T07:00 UTC+7
> Purpose: Provide full context to Claude for continuing development

---

## 1. Project Identity

| Field | Value |
|-------|-------|
| **Name** | evalsec |
| **Description** | Open-source LLM benchmark for DevSecOps tasks |
| **Version** | 0.1.0 (alpha) |
| **License** | MIT |
| **Author** | Farhan Ngenz (`frhnardi` on GitHub) |
| **Domain** | `evalsec.farhan.ngenz.org` (also OK: `evalsec.ngenz.org`) |
| **Repository** | `https://github.com/frhnardi/evalsec` |
| **Timezone** | Asia/Jakarta (UTC+7) — all timestamps |

---

## 2. Tech Stack (Locked)

| Category | Choice | Why |
|----------|--------|-----|
| **Language** | Python ≥3.12 | Type hints, strict mode |
| **Package manager** | `uv` | Fast, deterministic lockfile (`uv.lock`) |
| **Build backend** | Hatchling | Minimal config, PEP 621 |
| **CLI framework** | Typer | Auto `--help`, async support |
| **Data models** | Pydantic v2 (strict) | Extra fields forbidden, coercion disabled |
| **Config** | pydantic-settings | `Settings` from env vars |
| **HTTP client** | httpx | Async, connection pooling |
| **OpenAI client** | openai ≥1.58 | OpenAI-compatible API calls |
| **Retry** | tenacity | Exponential backoff for API calls |
| **Logging** | structlog | Structured, JSON-parseable |
| **Templating** | Jinja2 | Static HTML dashboard generation |
| **Dashboard charts** | Chart.js (CDN) | Radar + bar charts in generated HTML |
| **Testing** | pytest | Standard Python testing |
| **Linting** | Ruff | Fast, configured in `pyproject.toml` |
| **Type checking** | mypy | Strict mode, Pydantic plugin |

---

## 3. Model Registry (5 Models)

Defined in [`src/evalsec/adapters/__init__.py`](src/evalsec/adapters/__init__.py)

| Key | Model Name (API) | Provider | Access | Cost (Input/Output per 1M) |
|-----|------------------|----------|--------|---------------------------|
| `claude_sonnet_46` | `anthropic/claude-sonnet-4-6` | OpenRouter | `OPENROUTER_API_KEY` | $3.00 / $15.00 |
| `kimi_k2_thinking` | `moonshotai/kimi-k2-thinking` | OpenRouter | `OPENROUTER_API_KEY` | $1.50 / $7.50 |
| `qwen_3_5` | `qwen/qwen3.5-plus-20260420` | OpenRouter | `OPENROUTER_API_KEY` | $0.40 / $2.40 |
| `deepseek_v4_pro` | `deepseek-chat` | DeepSeek direct | `DEEPSEEK_API_KEY` | $0.50 / $2.00 |
| `claude_opus_47` | `anthropic/claude-opus-4.7` | OpenRouter | `OPENROUTER_API_KEY` | $5.00 / $25.00 |

> **Note**: `claude_opus_47` is the **judge model** (pass 2 grader), not a benchmarked model. It uses the real `claude-opus-4.7` for LLM-as-judge scoring.

### Baseline Participants (4 non-LLM)

Defined in [`src/evalsec/baselines.py`](src/evalsec/baselines.py)

| Key | Strategy | Description |
|-----|----------|-------------|
| `baseline_cvss` | CVSS score sort | Prioritise by CVSS descending, all exploitable |
| `baseline_trivy` | Trivy severity sort | Prioritise by severity (CRITICAL→LOW), all exploitable |
| `baseline_epss` | EPSS percentile sort | Prioritise by exploit probability, all exploitable |
| `baseline_reachability` | Network-context heuristic | Uses `internet_facing` + `cvss_score` + `runtime_exposure` |

Baselines are graded against the same ground truth as LLMs (deterministic pass only, no judge pass). They appear in a separate **Baseline Comparison** section on the dashboard, visually distinct from LLM rankings.

---

## 4. Directory Structure

```
evalsec/
├── pyproject.toml              # Project metadata, deps, tool config
├── uv.lock                     # Deterministic dependency lock
├── .python-version             # Python 3.12
├── .env.example                # Required env vars template
├── .gitignore
├── .gitattributes
│
├── 01-system-prompt.md         # System prompt for Claude (initial)
├── 02-data-collection.md       # Guide for Phase 2 (dataset collection)
├── 03-improvement-system-prompt.md  # System prompt for Issues 1-10
├── 04-dashboard-baseline-fix-prompt.md  # Implementation brief for Issue 11
├── CHECKPOINT.md               # ← This file
├── README.md                   # Project readme
│
├── src/evalsec/
│   ├── __init__.py
│   ├── py.typed                # PEP 561 marker
│   ├── cli.py                  # Typer CLI: run, grade, build
│   ├── config.py               # Settings (pydantic-settings)
│   ├── runner.py               # Benchmark runner (async)
│   ├── grader.py               # Two-pass grader (deterministic + judge)
│   ├── baselines.py            # Non-LLM baseline generation + grading
│   ├── dashboard.py            # Static HTML dashboard builder
│   │
│   ├── adapters/
│   │   ├── __init__.py         # Model registry (5 models)
│   │   ├── base.py             # Protocol + shared models (ModelConfig, LLMRequest, LLMResponse)
│   │   └── openai_compat.py    # OpenAI-compatible adapter (OpenRouter + DeepSeek)
│   │
│   ├── tasks/
│   │   ├── __init__.py
│   │   ├── base.py             # Pydantic models: TaskCase, Rubric, GroundTruth, FindingDetail, etc.
│   │   └── trivy_triage.py     # Task definition: prompts, schemas, configs
│   │
│   └── templates/
│       ├── card.html.j2        # Per-model result card (Chart.js radar)
│       └── dashboard.html.j2   # Main dashboard page
│
├── tests/
│   ├── data/trivy_triage/
│   │   └── 001_log4shell_reachable.yaml   # Only 1 test case (NEED 9+ MORE)
│   └── unit/
│       ├── test_models.py               # Pydantic model tests
│       ├── test_grader.py               # JsonValidator, Score, RegexGrader tests
│       ├── test_baselines.py            # Baseline generation + grading (Issue 10)
│       ├── test_risk_metadata.py        # Risk metadata rendering (Issue 9)
│       └── test_dataset_validation.py   # Cross-field YAML integrity checks
│
├── infra/
│   ├── providers.tf            # AWS providers (default ap-southeast-3, alias us-east-1)
│   ├── main.tf                 # S3 + CloudFront + ACM + Route 53 + OIDC IAM
│   ├── github_oidc.tf          # GitHub OIDC provider + IAM role
│   ├── variables.tf            # Terraform variables
│   ├── outputs.tf              # Bucket name, dist ID, role ARN
│   └── README.md               # Infrastructure setup guide
│
├── .github/
│   ├── workflows/
│   │   ├── benchmark.yml       # Full benchmark on push to main
│   │   └── ci.yml              # PR checks (lint, type, test)
│   └── dependabot.yml          # Weekly dependency updates
│
├── outputs/
│   ├── dry_run_estimate.txt    # Cost estimate for 1 model × 1 case
│   └── mock_scores.json        # Mock scores for dashboard demo
│
├── dist/
│   └── index.html              # Generated dashboard (23KB)
│
├── scripts/
│   ├── test_adapter.py         # Manual adapter smoke-test script
│   └── test_judge.py           # Manual judge grader smoke-test script
│
└── plans/
    ├── evalsec-phase3-plan.md  # Phase 3 implementation plan
    └── phase3.2-models-design.md  # Model registry design doc
```

---

## 5. CLI Reference

All commands via `uv run evalsec <command>`:

| Command | Purpose | Key Options |
|---------|---------|-------------|
| `run` | Run benchmark (load YAML → call models → save responses) | `--dry-run`, `--models`, `--task`, `--max-concurrent` |
| `grade` | Grade responses (pass 1 deterministic → pass 2 judge) | `--responses`, `--judge-model`, `--pass1-weight`, `--pass2-weight`, `--output` |
| `build` | Build static HTML dashboard from scores JSON | `--scores`, `--responses`, `--output-dir` |

### Usage examples:

```bash
# Dry run — estimate costs without calling APIs
uv run evalsec run --dry-run

# Full run (API keys must be set)
uv run evalsec run --models claude_sonnet_46,deepseek_v4_pro

# Grade responses
uv run evalsec grade --responses outputs/responses_*.json

# Build dashboard
uv run evalsec build --scores outputs/mock_scores.json
```

---

## 6. Architecture Overview

### Benchmark Flow (run → grade → build)

```
YAML test cases
     │
     ▼
┌─────────────────┐
│   Runner        │  Loads TaskCase[] from YAML
│   (async)       │  Builds Adapter per model (from registry)
│                 │  Calls each model for each case
│                 │  Saves responses_*.json
└──────┬──────────┘
       │ responses_*.json
       ▼
┌─────────────────────────────────────┐
│   Grader (two-pass)                 │
│                                     │
│   Pass 1: Deterministic grading     │
│     - JsonValidator.validate()      │
│       • format_score   (10%)        │
│       • coverage_score (30%)        │
│       • verdict_score  (30%)        │
│       • priority_score (20%)        │
│       • regex_score    (10%)        │
│       - hallucination_penalty (max 20 pts) │
│     → deterministic_total (0-100)   │
│     → pass1 = deterministic * P1_W │
│                                     │
│   Pass 2: JudgeGrader (LLM-as-judge)│
│     - 4 rubric dimensions:          │
│       reachability_reasoning (35%)  │
│       prioritization        (25%)   │
│       actionability         (25%)   │
│       conciseness           (15%)   │
│     → pass2_raw (0-100)            │
│     → pass2 = pass2_raw * P2_W     │
│                                     │
│   Final = pass1 + pass2             │
│   (P1_W=0.20, P2_W=0.80 default)   │
│                                     │
│   Baselines: deterministic_only     │
│     total = deterministic_total     │
│     model_type = "baseline"         │
└──────┬──────────┘
       │ scores_*.json
       ▼
┌─────────────────────────────────────┐
│   Dashboard (Jinja2 + Chart.js)     │
│                                     │
│   - LLM Leaderboard table           │
│     (Composite, Pass 1, Pass 2,     │
│      Format, Coverage, Verdict,     │
│      Priority, Judge, Hall., Cost)  │
│                                     │
│   - Baseline Comparison table       │
│     (separate section,              │
│      deterministic-only metrics)    │
│                                     │
│   - Bar Chart (composite scores)    │
│   - Radar Chart (dimension scores)  │
│   - Model Cards (per-model detail)  │
└──────┬──────────┘
       │ dist/index.html
       ▼
   S3 → CloudFront (Terraform-managed)
```

### Scoring Semantics

```
LLMs:    total = P1_W × deterministic_total + P2_W × judge_score
         deterministic_total = weighted sum of 5 sub-scores − hallucination_penalty
         model_type = "llm"

Baselines:  total = deterministic_total (no judge pass)
            pass1_score = deterministic_total × P1_W (weighted, like LLMs)
            model_type = "baseline"

Dashboard separates LLM leaderboard from baseline comparison
so baselines never silently outrank LLMs in the main ranking.
```

---

## 7. Test Data

**Only 1 test case exists** — this is the critical gap:

| # | YAML | Status | Notes |
|---|------|--------|-------|
| 001 | `001_log4shell_reachable.yaml` | ✅ Complete | Synthetic — trivy output with reachable Log4Shell |

**Need 9+ real cases** from:
- Real Docker image scans (preferred)
- Public GitHub issues on `aquasecurity/trivy`
- Public security advisories (NVD, CVE feeds)

> See [`02-data-collection.md`](02-data-collection.md) for detailed collection guide.

---

## 8. Infrastructure (AWS — ap-southeast-3)

| Resource | Purpose | Region |
|----------|---------|--------|
| **S3 bucket** | Private storage for dashboard HTML | ap-southeast-3 |
| **CloudFront** | CDN with custom domain, HTTPS | Global (edge) |
| **ACM** | TLS certificate | us-east-1 (req. by CloudFront) |
| **Route 53** | DNS for custom domain | ap-southeast-3 |
| **IAM role (OIDC)** | GitHub Actions deploy role | ap-southeast-3 |

### OIDC Trust Policy
- Only `repo:frhnardi/evalsec:ref:refs/heads/main` can assume the role
- Permissions: `s3:PutObject`, `s3:DeleteObject`, `cloudfront:CreateInvalidation`

### GitHub Secrets/Variables Required

| Name | Type | Source |
|------|------|--------|
| `OPENROUTER_API_KEY` | Secret | OpenRouter account |
| `DEEPSEEK_API_KEY` | Secret | DeepSeek platform |
| `ANTHROPIC_API_KEY` | Secret | Anthropic console |
| `AWS_ROLE_ARN` | Secret | Terraform output `github_actions_role_arn` |
| `S3_BUCKET` | Variable | Terraform output `s3_bucket_name` |
| `CF_DISTRIBUTION_ID` | Variable | Terraform output `cloudfront_distribution_id` |
| `AWS_REGION` | Variable | `ap-southeast-3` |

---

## 9. GitHub Actions Workflows

### [`benchmark.yml`](.github/workflows/benchmark.yml)
- Trigger: `push` to `main` (paths: `tests/data/**`, `src/**`)
- Steps: lint → type-check → test → run benchmark → grade → build → deploy
- Deploys `dist/` to S3, invalidates CloudFront cache

### [`ci.yml`](.github/workflows/ci.yml)
- Trigger: `pull_request` on any branch
- Steps: lint → type-check → test only (no API calls, no deploy)

### [`dependabot.yml`](.github/dependabot.yml)
- Weekly updates for pip and GitHub Actions dependencies

---

## 10. What's Still Needed (Before v0.1.0 Launch)

### Critical (Blocks Launch)
1. **9+ real test cases** ([`02-data-collection.md`](02-data-collection.md) has full guide)
   - Real trivy scan outputs from Docker images
   - Ground truth (exploitable vs non-exploitable findings)
   - Scoring rubric per case
2. **Terraform apply** (`cd infra && terraform apply`)
3. **GitHub repo setup**
   - Create repo `frhnardi/evalsec`
   - Push code
   - Set secrets + variables
4. **First CI run** — trigger by pushing to main

### Important (After Launch)
5. **`evalsec deploy` command** — implement actual S3 sync + CloudFront invalidation
6. **Real judge model upgrade** — change `claude_opus_47` from haiku to actual opus
7. **Regional test cases** (Indonesia-specific CVEs) — stretch goal from Phase 2

### Optional Enhancements
8. Error budget dashboard (SLA tracking per model)
9. Model comparison page (side-by-side responses)
10. Automated regression detection (score drops across runs)

---

## 11. Implementation Status

| # | Component | Status | Details |
|---|-----------|--------|---------|
| 1 | CI gates green | ✅ | `ruff check`, `ruff format --check`, `mypy`, `pytest` all pass |
| 2 | Terraform valid | ✅ | `terraform validate` passes |
| 3 | Separate benchmark/judge models | ✅ | Distinct registries in `adapters/__init__.py` |
| 4 | CLI, README, CHECKPOINT, workflow sync | ✅ | All docs reference same commands |
| 5 | GitHub Actions deploy config | ✅ | `benchmark.yml` + `ci.yml` + OIDC |
| 6 | JSON output validation | ✅ | `JsonValidator` with format, coverage, verdict, priority checks |
| 7 | Deterministic grading beyond regex | ✅ | 5-dimension scoring with configurable weights |
| 8 | Enriched dataset | ✅ | `FindingDetail` with CISA KEV, EPSS, CVSS, exploit_maturity, runtime_exposure, etc. |
| 9 | Risk metadata | ✅ | `_render_risk_metadata()` injects metadata into LLM prompts |
| 10 | Non-LLM baselines | ✅ | 4 baseline strategies (CVSS, Trivy, EPSS, Reachability) with full grading pipeline |
| 11 | Dashboard metrics + baseline scoring semantics | ✅ | Deterministic metrics exposed; baselines visually separated (Option A) |
| 12 | README, CHECKPOINT, infra docs, .env.example | 🔄 | This checklist update in progress |

### Test Suite Growth

| Milestone | Test Count |
|-----------|-----------|
| Phase 3 initial (models + grader) | ~55 |
| After Issues 6-9 (validation, metadata, dataset) | ~90 |
| After Issue 10 (baselines) | ~125 |
| After Issue 11 (dashboard fix) | **135** |

---

## 12. Quick Commands Reference

```bash
# Test
uv run pytest                                   # Run all 135 tests
uv run pytest -v                                # Verbose
uv run pytest tests/unit/test_baselines.py      # Baseline-specific tests
uv run pytest -k "model_type or deterministic"  # Filter by keyword

# Lint & Type
uv run ruff check src/                          # Lint (ruff)
uv run ruff format --check src/                 # Format check
uv run mypy src/evalsec/ tests/                 # Type check

# Run
uv run evalsec run --dry-run                    # Cost estimate
uv run evalsec run --models claude_sonnet_46    # Single model

# Grade & Build
uv run evalsec grade --responses outputs/responses_*.json
uv run evalsec build --scores outputs/mock_scores.json

# Full CI (one-liner)
uv run ruff check src/ && uv run ruff format --check src/ && uv run mypy src/evalsec/ tests/ && uv run pytest
```

---

## 13. Environment Variables (.env)

```
OPENROUTER_API_KEY=sk-or-v1-...
DEEPSEEK_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
AWS_REGION=ap-southeast-3
```

---

## 14. Key Design Decisions

1. **No database** — Everything is file-based (YAML in, JSON out, HTML dashboard). This keeps infra costs at ~$1.40/month.
2. **Static site** — Dashboard is a pre-built HTML file with Chart.js. No server, no API, no dynamic queries.
3. **Async runner** — Models are called concurrently (semaphore-limited) for faster benchmarks.
4. **OpenRouter for 3/4 models** — Unified billing, standard API. DeepSeek direct because OpenRouter doesn't offer the latest v4 model.
5. **Pydantic strict mode** — Extra fields forbidden (`extra="forbid"`), no coercion to catch API or YAML schema drift early.
6. **Two-pass grading** — Deterministic pass (5 dimensions + hallucination penalty) covers structural compliance; expensive judge pass handles qualitative scoring. Weights are configurable via CLI.
7. **Jakarta timezone** — All timestamps use `Asia/Jakarta` (UTC+7).
8. **OIDC for deployment** — No long-lived AWS keys. GitHub Actions assumes IAM role via OIDC with minimum permissions.
9. **ACM in us-east-1** — CloudFront requires certificates in us-east-1, even when the rest of the infra is in ap-southeast-3.
10. **S3 bucket private** — No public access. CloudFront accesses via Origin Access Control (OAC).
11. **Baselines as comparison, not competition** — Baselines use a separate dashboard section with `model_type="baseline"` so they never silently outrank LLMs despite lacking a judge pass.
12. **Jinja2 `tojson` filter** — All template data uses `{{ var | tojson }}` instead of the unsafe pre-serialized `| safe` pattern.

---

## 15. Contact / Attribution

- **Author**: Farhan Ngenz
- **Email**: farhan@ngenz.org
- **GitHub**: [frhnardi](https://github.com/frhnardi)
- **Website**: [farhan.ngenz.org](https://farhan.ngenz.org)
- **Domain**: [evalsec.farhan.ngenz.org](https://evalsec.farhan.ngenz.org)
