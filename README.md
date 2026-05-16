# evalsec

An open-source LLM benchmark for DevSecOps tasks.

> **Status:** v0.1.0 — alpha

## Quick start

```bash
uv sync
uv run evalsec --help
```

## Current results

| Model | Average Score |
|-------|:------------:|
| **deepseek_v4_pro** | **85.16** |
| baseline_reachability | 68.84 |
| baseline_cvss | 61.72 |
| baseline_epss | 61.72 |
| baseline_trivy | 54.69 |

*Judged by DeepSeek V4 Pro. 18 test cases. See `dist/index.html` for full dashboard.*

## Limitations

### 1. Ground truth quality
All ground truth labels (exploitable / non-exploitable / partial) in the test cases were generated with LLM assistance and have subsequently undergone manual human review. All 18 cases are now marked as `human_verified`. However, the human review process was informal and did not follow a strict inter-rater reliability protocol. A more rigorous verification pipeline — with multiple independent reviewers and consensus reconciliation — would strengthen the benchmark's credibility.

### 2. Judge-model bias
The judge model (pass 2 grader) and the benchmarked model share the same underlying architecture. As of v0.1.0, grading uses DeepSeek V4 Pro as the judge — the same model being benchmarked. This creates a self-judging scenario that may inflate scores. Future iterations should use an independent judge model from a different family (e.g., Claude, Gemini, or a human evaluation panel).

### 3. Limited dataset size
The benchmark currently contains only **18 test cases**, covering a narrow slice of real-world DevSecOps scenarios. This is insufficient for statistical significance. A production-grade benchmark would require at least 100–200 cases spanning diverse ecosystems (Alpine, Debian, Ubuntu, distroless), languages (Python, Go, Java, Node.js), and deployment contexts (K8s, EC2, serverless).

### 4. Single-task scope
Despite the project name "evalsec" suggesting a general security evaluation framework, the current implementation supports only one task: **Trivy vulnerability triage**. There is no coverage of SAST, DAST, secret detection, IaC scanning, or other common DevSecOps workflows.

### 5. Synthetic deployment context
Each test case includes a `stack_context` describing the deployment environment (e.g., "internal cluster, non-root, NetworkPolicy ketat"). These contexts are synthetic — written by an LLM rather than derived from real production incidents. A model might score differently when confronted with real-world ambiguity versus neatly described toy scenarios.

### 6. English prompts, Indonesian regulation context
The benchmark uses English system prompts with deployment scenarios that reference Indonesian regulatory frameworks (OJK, PCI-DSS). This mild language–regulation friction may penalize models unfamiliar with Indonesian compliance terminology, without this being an intentional part of the evaluation.

### 7. Deterministic baseline ceiling
The non-LLM baselines (CVSS sort, EPSS sort, Trivy severity sort, reachability heuristic) score between 54–69 out of 100. While these provide a useful floor, a score of 85 from DeepSeek V4 Pro leaves limited headroom for demonstrating LLM superiority. The benchmark may need harder cases to create meaningful differentiation.

### 8. Cost estimation accuracy
Token counting uses a naive `len(text.split())` heuristic rather than a proper tokenizer. Actual API costs may differ from estimates. The judge grader also incurs additional cost per case that is not reflected in the benchmark model's cost estimate.
