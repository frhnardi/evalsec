# Limitations

## 1. Judge-Model Bias

### 1.1 Same-family bias

The default judge configuration uses **Claude Opus 4.7** ([`src/evalsec/adapters/__init__.py:48`](src/evalsec/adapters/__init__.py:48)) as the pass-2 LLM grader. When benchmarking Claude Sonnet 4.6, this creates a **same-family judging scenario** — both models share the same underlying architecture and training lineage. This may inflate scores due to shared stylistic preferences, prioritization heuristics, and response format biases.

**Impact:** A model's score reflects not only its DevSecOps competency but also how well its output aligns with the judge's own preferences. This confounds the measurement.

**Mitigations:**
- The pass-1 grader (regex + JSON validation, [`src/evalsec/grader.py:201`](src/evalsec/grader.py:201)) is fully deterministic and bias-free — it checks format compliance, CVE coverage, verdict accuracy, and hallucination counts without any LLM involvement.
- Cross-family judging is supported: DeepSeek V4 Pro ([`src/evalsec/adapters/__init__.py:56`](src/evalsec/adapters/__init__.py:56)) can be used as the judge via `--judge-model deepseek_v4_pro`.
- Anti-bias instructions were added to the [`JUDGE_SYSTEM_PROMPT`](src/evalsec/tasks/trivy_triage.py:167) on 2026-05-22 — the judge is now explicitly instructed to evaluate solely on technical merit, avoid stylistic preference, and apply consistent standards across all models.
- Future releases should adopt a multi-judge ensemble (e.g., Claude + GPT-4.1 + Gemini 2.5) with inter-rater agreement tracking.

### 1.2 Self-judging (legacy)

In earlier versions, DeepSeek V4 Pro served as both the benchmarked model and the judge — a direct self-judging scenario. This has been partially addressed by introducing Claude Opus 4.7 as the default judge, but the same-family concern remains for Anthropic models.

---

## 2. Ground Truth Quality

### 2.1 LLM-assisted generation

All ground truth labels (exploitable / non-exploitable / partial) were initially generated with LLM assistance and subsequently underwent manual human review. All cases are marked as `human_verified`, but the review process did not follow a strict inter-rater reliability protocol (e.g., multiple independent reviewers with Cohen's κ tracking).

### 2.2 Trivy compact format truncation

**Root cause:** Trivy's compact output format only displays the first CVE line per library. Libraries with multiple CVEs have their additional CVEs present in the full scan artifact but absent from the compact `input:` field. This caused an earlier data quality issue where ground-truth CVEs existed in the YAML but had no corresponding scan line — making them appear to be hallucinations if the model relied on the input alone.

**Fix applied:** An injection script ([`scripts/inject_missing_scan_cves.py`](scripts/inject_missing_scan_cves.py)) was run to add the missing compact-format CVE lines into the `input:` field for cases 005 (postgres), 008 (redis), and 018 (vault). The script reads from the full scan files in [`scans/`](scans/) and inserts the relevant lines at the correct anchor position.

**Current status:** All 136 cross-field integrity tests pass, confirming that every ground-truth CVE has a corresponding line in the scan input, and every priority-order entry exists in the findings.

### 2.3 Synthetic deployment context

Each test case includes a `stack_context` describing the deployment environment (e.g., "internal cluster, non-root, NetworkPolicy ketat"). These contexts are generated rather than derived from real production incidents. A model might score differently when confronted with real-world ambiguity versus neatly described toy scenarios.

---

## 3. Scope Limitations

### 3.1 Task coverage

Despite the project name "evalsec" suggesting a general security evaluation framework, the current coverage is limited:

| Category | Task Type | Cases | Status |
|----------|-----------|-------|--------|
| Container CVE triage | [`trivy_triage`](src/evalsec/tasks/trivy_triage.py) | 20 | ✅ Active |
| SAST triage | [`codeql_triage`](src/evalsec/tasks/codeql_triage.py) | 3 | ✅ Active |
| IaC scanning (Checkov, tfsec) | — | 0 | ❌ Not implemented |
| Secrets detection | — | 0 | ❌ Not implemented |
| DAST / runtime | — | 0 | ❌ Not implemented |
| Kubernetes admission | — | 0 | ❌ Not implemented |
| SBOM validation | — | 0 | ❌ Not implemented |
| Policy-as-Code (OPA) | — | 0 | ❌ Not implemented |

The CodeQL task covers SQL injection (Django), stored XSS (Express), and path traversal (Spring) — a narrow but representative slice of SAST findings. Expanding to IaC, secrets, and runtime is planned for v0.2.0.

### 3.2 Distribution skew

Even within the supported task types, the dataset is skewed:

- **Trivy:** Heavily weighted toward Alpine (3 cases), with only 1–2 cases per other distro. No distroless or scratch images.
- **CodeQL:** Only 3 cases, all web-application focused. No Java deserialization, no insecure crypto, no hardcoded credentials.
- **Severity:** A disproportionate number of CRITICAL/HIGH CVEs. Models rarely encounter LOW or MEDIUM severities in the benchmark, making it harder to evaluate nuanced prioritization.

### 3.3 Missing CVE categories

Some important vulnerability classes are absent or underrepresented:
- Supply chain attacks (malicious packages)
- Dependency confusion
- Insecure defaults in container images
- Kernel-level vulnerabilities (need separate trivy image scan)

---

## 4. Dataset Size and Statistical Significance

### 4.1 Small sample size

The benchmark contains only **23 test cases** (20 trivy_triage + 3 codeql_triage). This is insufficient for statistical significance:

- A 5% score difference between models may be noise rather than a meaningful signal.
- Confidence intervals are wide; model rankings should be treated as directional indicators.
- A production-grade benchmark would require 200–500 cases with balanced distribution across ecosystems.

### 4.2 Single-run design

Results are based on a single run per model per case. There is no repeated-measures design to estimate within-model variance. Scores can fluctuate due to:
- LLM output stochasticity (temperature > 0)
- API response timing differences
- Judge inconsistency on borderline cases

---

## 5. Cost Estimation Accuracy

The cost estimate in [`evalsec run --dry-run`](src/evalsec/runner.py:224) uses a naive `len(text) // 4` token heuristic rather than a model-specific tokenizer. Actual API costs may differ:

| Factor | Impact |
|--------|--------|
| Tokenizer mismatch | ±20–40% variance |
| Cached input discounts (OpenRouter) | Input costs may be lower than estimated |
| Long-output cases | Output estimate of 300 tokens/finding × 5 findings may undercount |
| Judge grading cost | Not included in the run estimate — billed separately per case per model |

---

## 6. Regulatory and Geographic Context

### 6.1 Indonesian regulation friction

The benchmark uses English prompts with deployment scenarios referencing Indonesian regulatory frameworks (OJK regulation, PCI-DSS alignment). This mild language–regulation friction may penalize models unfamiliar with Indonesian compliance terminology, without this being an intentional part of the evaluation.

### 6.2 Single-region focus

All scenarios assume deployment in Indonesia (AWS Jakarta region, Telkom datacenter, etc.). Models tuned for US/EU regulatory environments may produce different prioritization decisions, which could be incorrectly scored as errors.

---

## 7. Benchmark Ceiling

The non-LLM baselines (CVSS sort, EPSS sort, Trivy severity sort, reachability heuristic) score between 54–69 out of 100. Early LLM results reach ~85. This leaves limited headroom for demonstrating LLM superiority at the high end. Harder cases — such as ambiguous CVEs, conflicting severity signals, or multi-step reasoning — are needed to push differentiation.

---

## 8. Reproducibility

### 8.1 API-dependent

Results depend on model API versions, which change without notice. A score from May 2026 may not be reproducible in June 2026 if the provider updates the model.

### 8.2 No frozen model snapshots

Unlike benchmarks with local model inference (e.g., HumanEval, SWE-bench), evalsec relies on cloud APIs. There is no mechanism to pin model weights. This is a known limitation of the API-benchmark paradigm.

---

*Last updated: 2026-05-22*
