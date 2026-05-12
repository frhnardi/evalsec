# evalsec — Phase 3 Implementation Plan

## Overview

Build **evalsec**, an open-source LLM benchmark for DevSecOps tasks. This plan covers Phase 3 (MVP Runner) implementation, broken into numbered sub-steps per the system prompt.

**Current Status:** Ready for Phase 3.1 — Project scaffolding
**Model Update:** DeepSeek V3.x → **DeepSeek V4 Pro** (system prompt updated)

---

## Phase 3 — MVP Runner (10 sub-steps)

### 3.1 — Project Scaffolding
**Goal:** Empty Python project with correct tooling. `uv run evalsec --help` shows Typer output.

**Files to create (in order):**
1. `pyproject.toml` — uv project metadata, all deps
2. `.gitignore` — Python + IDE + secrets + dist/output
3. `.gitattributes` — CRLF normalization for WSL2
4. `.python-version` — `3.12`
5. `.env.example` — API key placeholders
6. `src/evalsec/__init__.py` — version constant
7. `src/evalsec/cli.py` — Typer skeleton with stub commands
8. `src/evalsec/config.py` — Pydantic Settings

**Checkpoint:** `uv sync && uv run evalsec --help` shows 4 stub commands.

### 3.2 — Pydantic Data Models
**Goal:** Type-safe schemas for all data flowing through the system.

**Files to create:**
1. `src/evalsec/tasks/base.py` — TaskCase, RubricDef, GroundTruth
2. `src/evalsec/adapters/base.py` — LLMRequest, LLMResponse, ModelConfig, Adapter Protocol
3. `src/evalsec/grader.py` (skeleton) — RubricScore, Score, GradedResponse
4. `tests/unit/test_models.py` — pytest test loading YAML

**Checkpoint:** pytest passes loading `001_log4shell_reachable.yaml` against TaskCase.

### 3.3 — OpenAI-Compatible Adapter
**Goal:** One adapter for OpenRouter (3 models) + DeepSeek (1 model).

**Files to create:**
1. `src/evalsec/adapters/openai_compat.py` — async httpx client with tenacity retry
2. `src/evalsec/adapters/__init__.py` — MODELS dict with 4 configs
3. `scripts/test_adapter.py` — one-off test script

**Checkpoint:** Owner runs test script, sees response with cost_usd.

### 3.4 — Anthropic Adapter (Judge)
**Goal:** Separate adapter for Claude Opus 4.7 judge model.

**Files to create:**
1. `src/evalsec/adapters/anthropic_direct.py` — anthropic SDK with JSON mode
2. `scripts/test_judge.py` — one-off test script

**Checkpoint:** Owner runs test script, gets valid Score object.

### 3.5 — Task Definition (trivy_triage)
**Goal:** Prompt templates, expected output schema, rubric prompt.

**Files to create:**
1. `src/evalsec/tasks/trivy_triage.py` — PROMPT_VERSION, system/user/judge prompts

**Checkpoint:** Owner reviews and approves prompt text.

### 3.6 — Runner
**Goal:** Load YAML cases, call models, save responses.

**Files to create:**
1. `src/evalsec/runner.py` — async runner with Semaphore(5), cost estimation, incremental save
2. Wire into `cli.py` as `evalsec run`

**Checkpoint:** `evalsec run --task trivy_triage --max-cases 3` generates responses JSON.

### 3.7 — Grader
**Goal:** Two-pass grader (regex + LLM-as-judge).

**Files to create:**
1. `src/evalsec/grader.py` (full implementation) — pass 1 regex, pass 2 judge, diskcache
2. Wire into `cli.py` as `evalsec grade`

**Checkpoint:** `evalsec grade --input output/responses-*.json` generates scores JSON.

### 3.8 — Dashboard
**Goal:** Static HTML dashboard with Chart.js.

**Files to create:**
1. `templates/dashboard.html.j2` — main page
2. `templates/card.html.j2` — model card
3. `src/evalsec/dashboard.py` — Jinja2 renderer
4. Wire into `cli.py` as `evalsec build`

**Checkpoint:** `evalsec build` produces `dist/index.html` viewable in browser.

### 3.9 — Terraform for AWS
**Goal:** All AWS resources as code.

**Files to create:**
1. `infra/providers.tf` — two providers (ap-southeast-3 + us-east-1 alias)
2. `infra/main.tf` — S3 + CloudFront + Route 53 + ACM
3. `infra/github_oidc.tf` — OIDC provider + IAM role
4. `infra/variables.tf` — domain, org/repo vars
5. `infra/outputs.tf` — bucket name, CF ID, role ARN
6. `infra/README.md` — apply instructions

**Checkpoint:** `terraform plan` shows ~12 resources.

### 3.10 — GitHub Actions Workflow
**Goal:** Automated weekly benchmark + deploy.

**Files to create:**
1. `.github/workflows/benchmark.yml` — cron + workflow_dispatch
2. `.github/workflows/ci.yml` — PR checks (ruff + mypy + pytest)
3. `.github/dependabot.yml` — weekly dep updates

**Checkpoint:** Manual workflow_dispatch updates live dashboard within 10 minutes.

---

## MCP Tool Usage

With **GitHub MCP** available, we can:
- Create the GitHub repository if not already created
- Manage branches and PRs
- Create issues for tracking

With **Filesystem MCP** available, we can:
- Read/write files efficiently
- Manage project structure

---

## Key Design Decisions

1. **Async-first:** All LLM-touching functions are `async def` with `httpx.AsyncClient`
2. **Cost discipline:** Default small models for dev, cache judge results, estimate cost before runs
3. **Security:** OIDC-only AWS auth, no long-lived keys, pre-commit with detect-secrets
4. **Data integrity:** Pydantic strict mode, Decimal for financial fields, JSON audit trail
5. **WSL2 compatibility:** `.gitattributes` for LF line endings, repo inside WSL2 filesystem

---

## Next Steps

1. Review and approve this plan
2. Switch to **Code mode** for implementation
3. Begin Phase 3.1 — Project scaffolding (one file at a time)
