# Implementation Brief — Dashboard Metrics + Baseline Scoring Semantics

You are a senior Python + DevSecOps engineer improving **evalsec**, an open-source benchmark for evaluating LLM vulnerability triage on Trivy-style scanner output.

This brief focuses on two specific issues:

1. Dashboard metric visibility.
2. Baseline scoring semantics.

Do not broaden the scope unless required to make these two fixes correct and tested.

---

## Current State

The core gates are already green:

- `uv run ruff check src/ tests/`
- `uv run ruff format --check src/ tests/`
- `uv run mypy src/evalsec/`
- `uv run pytest tests/ -v --tb=short`
- `terraform -chdir=infra validate`
- `uv run evalsec run --dry-run`
- `uv run evalsec build --scores outputs/mock_scores.json`

The runner now separates benchmark models from judge models by default. The grader also includes deterministic scoring dimensions:

- `format_score`
- `coverage_score`
- `verdict_score`
- `priority_score`
- `regex_score`
- `judge_score`
- `hallucination_penalty`

Baselines exist in `src/evalsec/baselines.py`:

- `baseline_cvss`
- `baseline_trivy`
- `baseline_epss`
- `baseline_reachability`

---

## Problem 1 — Dashboard Does Not Expose New Metrics

### Issue

The dashboard currently still behaves mostly like the older judge-rubric dashboard. In `src/evalsec/dashboard.py`, `_build_leaderboard()` calculates `dimension_scores` only from `rubric_scores`.

This means:

- `format_score` is not visible.
- `coverage_score` is not visible.
- `verdict_score` is not visible.
- `priority_score` is not visible.
- `regex_score` is not visible.
- `hallucination_penalty` is not visible.
- Baselines often have empty radar/dimension charts because they do not have judge `rubric_scores`.

This makes the dashboard misleading: the scoring model has improved, but the UI does not show why a model won or lost.

### Target

Update dashboard aggregation and templates so the leaderboard clearly shows both:

1. Overall score.
2. Deterministic quality metrics.

Recommended leaderboard columns:

- Rank
- Model
- Type: `LLM` or `Baseline`
- Total
- Format
- Coverage
- Verdict
- Priority
- Judge
- Hallucination penalty
- Cost

Recommended chart updates:

- Keep the composite score bar chart.
- Replace or augment the current radar chart with a deterministic metrics radar:
  - Format
  - Coverage
  - Verdict
  - Priority
  - Regex
- Optionally show judge score separately because baselines do not have judge scores.

Recommended card updates:

- Each model card should show:
  - total score
  - deterministic metric bars
  - judge score if present
  - hallucination penalty
  - cost
  - type badge: LLM or Baseline

### Implementation Notes

- Keep dashboard static HTML.
- Do not add a frontend framework.
- Use existing Jinja2 + Chart.js structure.
- Preserve compatibility with old `outputs/mock_scores.json` if possible.
- Add fallback behavior for missing fields:
  - missing metric score should default to `0.0`
  - missing hallucination penalty should default to `0.0`
  - missing judge score should default to `0.0`
- Baselines should display deterministic metrics even when `rubric_scores` is empty.
- Use Jinja `tojson` instead of manually passing `json.dumps(... ) | safe` into `<script>`.

### Acceptance Criteria

- `uv run evalsec build --scores outputs/mock_scores.json --output-dir /tmp/evalsec-dashboard-test` passes.
- Dashboard includes deterministic metrics in leaderboard data.
- Baselines no longer appear with empty metric breakdowns.
- Generated dashboard does not crash when:
  - `rubric_scores` is missing,
  - `judge_score` is missing,
  - new deterministic fields are missing,
  - baseline entries have no judge rubric.
- Template no longer embeds model-generated JSON using `| safe`; use `tojson`.
- Add/update unit tests for `_build_leaderboard()` covering:
  - LLM score with deterministic fields and rubric scores.
  - Baseline score with deterministic fields and no rubric scores.
  - Old score JSON with only `total`, `pass1_score`, and `pass2_score`.

---

## Problem 2 — Baseline Scoring Is Not Apples-To-Apples

### Issue

Current LLM total score is weighted like this:

```text
total = pass1_weight * deterministic_score + pass2_weight * judge_score
```

With defaults:

```text
pass1_weight = 0.20
pass2_weight = 0.80
```

But baselines currently receive their deterministic raw score directly as total:

```text
baseline_total = deterministic_score
```

This means baselines and LLMs are not on the same scoring scale.

Example:

- LLM deterministic = 100, judge = 80
  - total = 20 + 64 = 84
- Baseline deterministic = 100, judge = 0
  - current total = 100

That makes baselines look stronger than LLMs even though they skip the judge pass entirely.

### Decision Needed

Pick one explicit scoring semantic and implement it consistently.

Recommended option:

## Option A — Separate Comparison Mode

Use two scores:

- `total`: official benchmark score, used for LLM ranking.
- `deterministic_total`: deterministic-only score, used for LLM-vs-baseline comparison.

For LLM entries:

```text
deterministic_total = deterministic_score
total = pass1_weight * deterministic_score + pass2_weight * judge_score
```

For baseline entries:

```text
deterministic_total = deterministic_score
total = null or deterministic_score, but mark it as baseline-only
```

Dashboard should clearly separate:

- Official LLM leaderboard.
- Baseline comparison section.

This is the cleanest option because baselines do not have judge scores and should not pretend to compete in the official judged leaderboard.

Alternative option:

## Option B — Same Weighting For Everyone

For baselines:

```text
judge_score = 0
total = pass1_weight * deterministic_score
```

This is mathematically consistent but visually harsh: a perfect baseline only gets 20 with default weights.

Avoid this unless the dashboard clearly explains that baselines are not judge-graded.

### Recommended Implementation

Implement Option A.

Concretely:

- Add `entry_type` or `model_type` to score entries:
  - `llm`
  - `baseline`
- For LLM grades:
  - include `deterministic_total`
  - keep existing `total`
- For baseline grades:
  - include `deterministic_total`
  - either:
    - set `total` to `deterministic_total` but mark `model_type="baseline"` and keep it out of official LLM ranking; or
    - set `official_total` / `rank_score` separately.
- Dashboard should not mix baselines into official LLM rank unless explicitly labeled as a comparison.

Suggested score fields:

```json
{
  "total": 84.0,
  "deterministic_total": 92.0,
  "official_total": 84.0,
  "model_type": "llm",
  "format_score": 100.0,
  "coverage_score": 100.0,
  "verdict_score": 80.0,
  "priority_score": 90.0,
  "regex_score": 100.0,
  "judge_score": 82.0,
  "hallucination_penalty": 0.0
}
```

For baseline:

```json
{
  "total": 76.0,
  "deterministic_total": 76.0,
  "official_total": null,
  "model_type": "baseline",
  "format_score": 100.0,
  "coverage_score": 90.0,
  "verdict_score": 60.0,
  "priority_score": 70.0,
  "regex_score": 100.0,
  "judge_score": 0.0,
  "hallucination_penalty": 0.0
}
```

### Acceptance Criteria

- Baselines are visually separated or clearly labeled.
- Baselines do not silently outrank LLMs in the official judged leaderboard.
- Dashboard can still show baseline deterministic scores for comparison.
- Scores JSON includes enough metadata to distinguish LLM vs baseline.
- Tests cover:
  - LLM grade has `model_type="llm"`.
  - Baseline grade has `model_type="baseline"`.
  - Official LLM ranking excludes baselines or ranks them in a separate comparison section.
  - Deterministic comparison includes both LLMs and baselines.

---

## Files Likely To Change

Expected files:

- `src/evalsec/grader.py`
- `src/evalsec/baselines.py`
- `src/evalsec/dashboard.py`
- `src/evalsec/templates/dashboard.html.j2`
- `src/evalsec/templates/card.html.j2`
- `tests/unit/test_grader.py`
- `tests/unit/test_baselines.py`
- new or updated dashboard tests, for example:
  - `tests/unit/test_dashboard.py`

Avoid changing unrelated infrastructure, model registry, or runner logic unless necessary.

---

## Verification Commands

Run all of these before considering the work complete:

```bash
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/evalsec/
uv run pytest tests/ -v --tb=short
uv run evalsec build --scores outputs/mock_scores.json --output-dir /tmp/evalsec-dashboard-test
```

If any generated scores fixture is updated, also run:

```bash
uv run evalsec run --dry-run
```

---

## Definition of Done

This task is complete when:

- Dashboard exposes deterministic metrics clearly.
- Baseline entries have meaningful metric breakdowns.
- Baselines are clearly separated from official LLM ranking or explicitly labeled.
- The scoring semantics are documented in code comments and/or README.
- No `| safe` JSON injection remains in dashboard scripts.
- All verification commands pass.

---

## Important Design Principle

The leaderboard must not reward a baseline or model merely because it avoids the judge step.

Make the dashboard answer two distinct questions:

1. **Official judged ranking:** Which LLM performs best under the full scoring pipeline?
2. **Deterministic baseline comparison:** Is an LLM actually better than simple severity/reachability heuristics?

Those are related but not the same question. Keep them visually and semantically distinct.
