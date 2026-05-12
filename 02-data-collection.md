# Phase 2 — Dataset Collection Guide

> Goal: collect 10 high-quality `trivy_triage` test cases as YAML files. This is the foundation of the entire project — a great runner with a bad dataset produces meaningless benchmarks.

**Estimated time:** 8-12 hours over one weekend.

**You don't need to write code in this phase.** This is research and curation work. Save the coding for Phase 3.

---

## What a test case actually is

A test case is **one YAML file** that contains:
1. A real Trivy scan output (the *input* sent to LLMs)
2. Stack context — what's actually running, what's reachable, what's deployed (the realism layer)
3. Ground truth — *your* judgment on which findings are truly exploitable and why
4. A rubric used to grade LLM responses against your ground truth

The LLMs being tested will see only the input + stack context. They will NOT see your ground truth. Your ground truth is for the grader (Claude Opus) to use when scoring their responses.

---

## What makes a good test case

A "good" test case is one that **discriminates between models** — different models give meaningfully different answers. This is much more valuable than cases where all models score 90+.

**Five criteria for a great case:**

1. **Realism** — the scan output looks like something a real engineer would receive. Right format, right verbosity, includes the noise of a real scan (not 1-2 cherry-picked CVEs).

2. **Multiple findings, mixed exploitability** — at least 3 vulnerabilities, where at least one is exploitable and at least one is a false positive in context. This forces the model to *reason*, not just pattern-match on CVSS scores.

3. **Context-dependent** — the same CVE might be exploitable in one stack but not another. Your stack context should make the answer *depend* on the context.

4. **Not in obvious training data** — if the case is straight from CISA KEV with classic phrasing, all models will pattern-match perfectly. Twist it slightly: rename services, change exposed ports, add a quirky deployment detail.

5. **Has a defensible ground truth** — you can explain in 1-2 sentences why each finding is or isn't exploitable. If you can't explain it, the model definitely can't, and the case isn't useful.

---

## Where to find raw artifacts

You have **three sources**, in order of preference:

### Source 1 — Scan real Docker images yourself (best)

This is the highest-quality source. Pick old or deliberately-vulnerable images, scan them with Trivy, capture the output verbatim.

**Recommended images for v0.1.0:**

| Image | Why it's good | Likely CVE count (HIGH+CRITICAL) |
|---|---|---|
| `nginx:1.18` | Web server, public-facing scenarios | 15-25 |
| `python:3.8` | Lots of stdlib + pip-cached deps | 40-60 |
| `node:14` | Old Node, deprecated openssl | 30-50 |
| `postgres:11` | Database server scenarios | 20-30 |
| `redis:5.0` | Cache/queue scenarios | 5-15 |
| `tomcat:9.0.30` | Java app server, classic log4j-era | 30-40 |
| `wordpress:5.5` | PHP, plugin ecosystem | 25-40 |
| `vulnerables/web-dvwa` | Deliberately vulnerable for training | 50+ |

**Commands to run:**

```bash
# Quick text output (human-readable, easiest to copy into YAML)
trivy image --severity HIGH,CRITICAL nginx:1.18 > scans/nginx_1_18.txt

# Detailed JSON output (machine-parseable, more accurate)
trivy image --severity HIGH,CRITICAL --format json nginx:1.18 > scans/nginx_1_18.json

# With timestamp and version pinning for reproducibility
trivy image --severity HIGH,CRITICAL,MEDIUM \
  --scanners vuln \
  --pkg-types os,library \
  nginx:1.18 > scans/nginx_1_18_$(date +%Y%m%d).txt
```

**Tip:** capture both text and JSON formats. The text version goes into the YAML `input:` field (because that's what a real developer sees), but the JSON gives you parseable data to build your ground truth.

### Source 2 — Public GitHub issues on aquasecurity/trivy

Many users post real scan outputs in GitHub issues, often with discussion about whether findings are real. Goldmine for authentic artifacts.

**Search queries that work:**

- `is:issue "false positive"` in aquasecurity/trivy
- `is:issue "vulnerable but not exploitable"` in aquasecurity/trivy
- `is:issue "should I patch"` in aquasecurity/trivy
- `is:issue "production-deployed"` in aquasecurity/trivy

**Workflow:**
1. Find an issue with a full scan output pasted
2. Copy the scan output verbatim
3. Read the comments — the user and maintainers often debate exploitability, which IS your ground truth for free
4. Always add `source:` field in the YAML pointing to the issue URL (attribution courtesy)

### Source 3 — Public security advisories

Use these for the "rare advanced CVE" scenarios. Less hands-on but useful for variety.

- https://github.com/advisories
- https://nvd.nist.gov/vuln/search
- https://www.cve.org/

**Use these only as supplements** — they don't contain real scan output, so you'd need to fabricate the "Trivy wrapper" around them, which reduces authenticity.

---

## The YAML structure

Every test case YAML follows this shape exactly. If you change the schema, change it in code first (Pydantic model in `src/evalsec/tasks/base.py`).

```yaml
# tests/data/trivy_triage/001_log4shell_reachable.yaml
id: trivy_triage_001
task: trivy_triage
version: v1                    # bump if you change input or ground truth

# Where the artifact came from (attribution + reproducibility)
source:
  type: self_scan              # or: github_issue, advisory, synthetic
  image: tomcat:9.0.30
  scanned_at: 2026-05-12
  trivy_version: 0.50.1
  url: null                    # populate if from GitHub issue

# What the LLM sees (input prompt artifact)
input: |
  myapp:1.0 (debian 11.7)

  Total: 47 (HIGH: 32, CRITICAL: 15)

  ┌─────────────────────────────────────┬────────────────┬──────────┐
  │ Library                              │ Vulnerability  │ Severity │
  ├─────────────────────────────────────┼────────────────┼──────────┤
  │ log4j-core (2.14.1)                   │ CVE-2021-44228 │ CRITICAL │
  │   Apache Log4j2 JNDI features...      │ (Log4Shell)    │          │
  │                                       │ KEV catalogued │          │
  │                                       │                │          │
  │ Pillow (9.0.1)                        │ CVE-2023-50447 │ HIGH     │
  │   PIL.ImageMath.eval() RCE...         │                │          │
  │                                       │                │          │
  │ runc (1.1.7)                          │ CVE-2024-21626 │ HIGH     │
  │   Container escape via /proc/self/fd  │                │          │
  └─────────────────────────────────────┴────────────────┴──────────┘

# What's true about the deployment that the LLM should consider
stack_context: |
  - Java 17 service exposed to public internet on port 443
  - log4j IS loaded and used by application code (reachable from request handlers)
  - Pillow is imported but PIL.ImageMath.eval() is NEVER called
    (only used for basic image resize via PIL.Image.resize)
  - Container runs in EKS with:
    - read-only root filesystem
    - non-root user (uid 10001)
    - seccomp default profile
    - no SYS_ADMIN capability

# YOUR ground truth — used by the grader
ground_truth:
  exploitable_findings:
    - cve: CVE-2021-44228
      verdict: exploitable
      reasoning: |
        log4j is reachable, service is public-facing,
        KEV catalogued with active mass exploitation.
        Patch immediately.

  non_exploitable_findings:
    - cve: CVE-2023-50447
      verdict: not_exploitable
      reasoning: |
        Vulnerable code path (ImageMath.eval) is never invoked.
        Dead code from attacker's perspective.
        Patch in normal upgrade cycle, not urgent.

  partial_findings:
    - cve: CVE-2024-21626
      verdict: partial
      reasoning: |
        Container escape vector partially mitigated by
        read-only root + non-root user + seccomp.
        Still patch this sprint, but not P0.

  priority_order:
    - CVE-2021-44228   # patch today
    - CVE-2024-21626   # patch this sprint
    - CVE-2023-50447   # patch next quarter

# Cheap deterministic check (pass 1 grader)
expected_response_includes:
  - "log4shell|log4j|CVE-2021-44228"  # regex: model must mention log4shell
  - "exploitable"                     # model must reason about exploitability
  - "not reachable|dead code|never called"  # model must catch Pillow false positive
  - "runc"                            # model must address runc

# Qualitative rubric (pass 2 grader — LLM-as-judge)
rubric:
  reachability_reasoning:
    max_score: 25
    description: |
      Does the model use the stack context to determine real
      exploitability? Does it correctly identify that Pillow
      is not exploitable because the vulnerable function is
      never called?

  prioritization:
    max_score: 25
    description: |
      Does the model rank findings correctly?
      log4shell > runc > Pillow.
      Penalize if it treats all critical CVEs as equal.

  actionability:
    max_score: 25
    description: |
      Are recommended next steps concrete and specific?
      ("Patch log4j to 2.17.1") vs vague ("Update dependencies").

  conciseness:
    max_score: 25
    description: |
      Is the response under 10 sentences with no padding,
      no caveats about being an AI, no preamble?

weight: 1.0   # for cases that should count more, e.g. flagship examples = 1.5
```

---

## Workflow — your weekend

Allocate 8-12 hours total. Here's a realistic split:

### Saturday morning — collect raw outputs (3 hours)

- **9:00-10:00** — Scan 5 Docker images locally with Trivy. Save text and JSON output.
- **10:00-11:30** — Browse 10-15 GitHub issues on aquasecurity/trivy. Save 5 that look promising.
- **11:30-12:00** — Quick review: do you have 8-10 raw artifacts that look interesting? If not, scan 2 more images.

### Saturday afternoon — write ground truth (4 hours)

For each of your 10 candidate cases:

- Read the scan output carefully
- Imagine the deployment context (or use the real one if you scanned your own image)
- Write the stack context section honestly
- For each CRITICAL/HIGH finding, decide: exploitable, partial, or false positive in this specific context
- Justify each verdict in 1-2 sentences

**This is the most valuable part of the project.** Don't rush it. If you can't justify a verdict, your test case isn't ready.

### Sunday morning — convert to YAML (2 hours)

- Copy your work into the YAML template for each case
- Number them sequentially: `001_*.yaml` through `010_*.yaml`
- Use descriptive filenames: `001_log4shell_reachable.yaml`, `002_nginx_old_apt.yaml`

### Sunday afternoon — sanity check (1 hour)

- Test ONE case manually: open claude.ai, paste your input + stack context, paste the same prompt your runner will use, and check Claude's response against your ground truth
- If Claude perfectly nails it, your case might not be discriminative — consider making it harder
- If Claude misses key things your ground truth identified, you have a great case

---

## Quality checklist before committing

Before you commit a YAML file to the repo, verify each item:

- [ ] `id` is unique across all test cases
- [ ] `source` is filled in honestly — no fake attributions
- [ ] `input` is verbatim from real tool output, not paraphrased or "cleaned up"
- [ ] `stack_context` describes a plausible real deployment
- [ ] `ground_truth` has at least one exploitable AND one non-exploitable finding
- [ ] Every CVE in the input is addressed in `ground_truth` somehow
- [ ] `expected_response_includes` is achievable but not trivial
- [ ] `rubric` weights add up to 100 across the 4 dimensions
- [ ] You can defend every ground truth verdict to a peer in 1-2 sentences
- [ ] Filename matches `id` and is descriptive

---

## Common mistakes to avoid

**Don't fabricate scan output.** Models trained on synthetic data will rank higher than they should because the patterns are clean. Real scans are messy. Keep them messy.

**Don't make every case "exploitable: YES on the obvious one."** If 8 of 10 cases have log4shell as the answer, you're testing model memory of log4shell, not its reasoning. Variety matters.

**Don't include cases where you're not 100% sure of the ground truth.** Ambiguous cases produce noisy benchmark results. When in doubt, drop the case and find a clearer one.

**Don't write ground truth from the LLM's perspective.** Don't think "what would a model say" — think "what would a senior security engineer with full code access say." The harder the gap, the better the test.

**Don't worry about coverage of every Trivy feature.** Focus on the 80% case: container image vulnerability scanning. IaC scanning, secret scanning, license scanning can come in later tasks.

---

## Stretch goal — make 2 of your 10 cases regional

This is a low-effort, high-reward differentiation:

Pick 2 cases where the stack context references **Indonesian fintech compliance** — for example, a case where the deployment is described as "OJK-supervised payment service" or "stores customer PII subject to UU PDP requirements." Then have the ground truth explicitly tie the priority decision to that regulatory context — "must patch within 7 days per OJK 22/2023 Article 18 timeline" — vs a non-regulated case where the same CVE has a 30-day tolerance.

This becomes a **specific finding** for your LinkedIn launch post:

> "Models trained on global compliance frameworks consistently miss Indonesian regulatory timelines. Across UU PDP-relevant cases, Claude Sonnet was the only model that correctly identified the 72-hour breach notification requirement."

You can't fake this kind of result with synthetic data. It comes from putting real regional context into your dataset. This is your moat.

---

## What to do when you're stuck

**"I can't decide if this CVE is exploitable in my context."**
→ Drop the case. Ambiguity hurts benchmark quality more than dataset size helps.

**"My ground truth might be wrong."**
→ Ask a peer. If you don't have a peer, post the case (sanitized) in a DevSecOps Slack or Discord and ask. Better to fix it now than to publish a wrong benchmark.

**"I only have 7 cases by Sunday."**
→ Ship with 7. You can add 3 more next weekend. 7 high-quality cases > 10 mediocre cases. The benchmark grows over time.

**"Should I include LOW severity findings?"**
→ Not for v0.1.0. Focus on HIGH+CRITICAL where the exploitability question matters most.

**"How long should the input field be?"**
→ 500-2000 tokens (roughly 300-1500 words). Long enough to be realistic, short enough that LLM token costs stay reasonable.

---

## Once Phase 2 is done

When you have your 10 YAML files committed to `tests/data/trivy_triage/`, hand the project over to Roo Code for Phase 3. The system prompt is set up so it knows your dataset is the foundation.

A reasonable first message to Roo Code after Phase 2:

> "Phase 2 is done — I have 10 YAML cases in `tests/data/trivy_triage/`. Please start Phase 3.1: scaffold the project (pyproject.toml, .gitignore, basic Typer CLI skeleton). Show me the files one at a time and wait for my confirmation before moving to 3.2."

Then go step by step. Don't let Roo Code generate the whole project in one shot — review each file as it's produced.
