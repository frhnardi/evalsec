"""Task definition for trivy_triage — the core DevSecOps benchmark task.

Prompt templates and output schema for the trivy vulnerability triage task.
Models receive a Trivy scan output + deployment context and must produce
a prioritised remediation plan.

Prompt Version: trivy_triage/v1
"""

from __future__ import annotations

from typing import Any

from evalsec.tasks.base import GroundTruth

# ---------------------------------------------------------------------------
# Version — stamped on every graded response for audit trail
# ---------------------------------------------------------------------------
PROMPT_VERSION = "trivy_triage/v1"

# ---------------------------------------------------------------------------
# Pass 1 — System Prompt (shown to the benchmarked model)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a senior DevSecOps engineer at a financial services company operating under NIST SP 800-53 (US security standard) and PCI-DSS v4.0 (payment card industry) regulatory frameworks.

Your task is to analyze a container image vulnerability scan and produce a prioritised remediation plan in VEX (Vulnerability Exploitability eXchange) format. You will receive:

1. Trivy scan output — a table of vulnerable packages with CVE IDs, severity ratings, and library versions.
2. Stack context — deployment architecture, code reachability analysis, runtime hardening controls, and regulatory requirements.

You MUST respond in this exact VEX JSON format:

{
  "document": {
    "type": "vex",
    "author": "evalsec-benchmark"
  },
  "statements": [
    {
      "vulnerability": { "id": "CVE-XXXX-XXXXX" },
      "status": "affected | not_affected | under_investigation",
      "justification": "code_not_reachable | vulnerable_code_cannot_be_controlled_by_attacker | vulnerable_code_not_in_execute_path | protected_by_compensating_control | component_not_present",
      "impact_statement": "1-sentence impact analysis using stack context...",
      "action_statement": "Brief remediation with version numbers...",
      "priority": "P0 | P1 | P2 | P3",
      "timeline": "72 hours | this sprint | next quarter"
    }
  ]
}

Priority definitions:
- P0 = Actively exploited in the wild AND reachable from this deployment (e.g. Log4Shell with public HTTP exposure). Remediate within 72 hours.
- P1 = Reachable but no known active exploitation. Remediate this sprint.
- P2 = Partial — some mitigating controls exist but risk is not fully eliminated. Remediate this sprint.
- P3 = Not reachable / false positive. Remediate next quarter during normal dependency cycle.

Justification values (required when status is not_affected):
- code_not_reachable: The vulnerable code path is not reachable from this deployment.
- vulnerable_code_cannot_be_controlled_by_attacker: Attacker cannot control the vulnerable input.
- vulnerable_code_not_in_execute_path: The vulnerable function is never called.
- protected_by_compensating_control: A compensating control (WAF, seccomp, NetworkPolicy) mitigates the risk.
- component_not_present: The affected component is not included in this deployment.

Rules:
- Base EVERY status on the stack context provided. If the CVE describes a code path that is NOT reachable in this deployment, mark it not_affected.
- Be specific but concise in action statements: include version numbers, JVM flags, WAF rules, config changes where relevant.
- No preamble, no disclaimers, no "As an AI assistant". Begin directly with the JSON object.
- Conciseness critical: You have a limited token budget for the entire response. Keep each statement to 1-2 sentences max. Prioritize the most impactful CVEs."""

# ---------------------------------------------------------------------------
# Pass 1 — User Prompt Template
# ---------------------------------------------------------------------------
USER_PROMPT_TEMPLATE = """## Trivy Scan Output

{input}

## Stack Context

{stack_context}
{risk_metadata}

Analyze the findings above. Output JSON only."""

# Template for per-finding risk metadata block (rendered when data is available)
RISK_METADATA_TEMPLATE = """
## Risk Metadata (per finding)

{cve_blocks}"""

CVE_METADATA_TEMPLATE = """- {cve}:
    CVSS Score: {cvss}
    EPSS Percentile: {epss}
    CISA KEV: {kev}
    Exploit Maturity: {maturity}
    Fixed Version: {fixed}
    Package: {pkg}
    Runtime Exposure: {exposure}
    Asset Criticality: {criticality}
    Internet-Facing: {facing}"""

# ---------------------------------------------------------------------------
# Expected output schema (VEX format — CSAF standard, Pass 1 regex grader)
# ---------------------------------------------------------------------------
EXPECTED_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "document": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["vex"]},
                "author": {"type": "string"},
            },
            "required": ["type"],
        },
        "statements": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "vulnerability": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"},
                        },
                        "required": ["id"],
                    },
                    "status": {
                        "type": "string",
                        "enum": ["affected", "not_affected", "under_investigation"],
                    },
                    "justification": {"type": "string"},
                    "impact_statement": {"type": "string"},
                    "action_statement": {"type": "string"},
                    "priority": {
                        "type": "string",
                        "enum": ["P0", "P1", "P2", "P3"],
                    },
                    "timeline": {
                        "type": "string",
                        "enum": ["72 hours", "this sprint", "next quarter"],
                    },
                },
                "required": [
                    "vulnerability",
                    "status",
                    "priority",
                    "impact_statement",
                    "action_statement",
                    "timeline",
                ],
            },
        },
    },
    "required": ["document", "statements"],
}

# VEX status → internal verdict mapping (for grading)
VEX_STATUS_TO_VERDICT: dict[str, str] = {
    "affected": "exploitable",
    "not_affected": "not_exploitable",
    "under_investigation": "partial",
}

# ---------------------------------------------------------------------------
# Pass 2 — Judge System Prompt (shown to Claude Opus 4.7 grader)
# ---------------------------------------------------------------------------
JUDGE_SYSTEM_PROMPT = """You are a strict DevSecOps evaluator grading a model's vulnerability triage response.

You will receive:
1. The original task context (scan output + stack context)
2. The model's response
3. A rubric with 4 dimensions, each scored 0-25 (total 100)

Score each dimension carefully. Return ONLY valid JSON — no markdown fences, no extra text:

{
  "rubric_scores": [
    {"dimension": "reachability_reasoning", "score": 0-25, "reasoning": "Brief justification for score..."},
    {"dimension": "prioritization", "score": 0-25, "reasoning": "Brief justification for score..."},
    {"dimension": "actionability", "score": 0-25, "reasoning": "Brief justification for score..."},
    {"dimension": "conciseness", "score": 0-25, "reasoning": "Brief justification for score..."}
  ]
}

Anti-bias guidelines:
- Judge the response solely on its technical DevSecOps merit and rubric criteria.
- Do not prefer or penalize any particular writing style, format, verbosity level, or phrasing.
- Apply the same standards consistently across all responses regardless of which model produced them.
- Be aware of potential stylistic self-preference: evaluate the content, not how closely it matches a particular output pattern.

Scoring guidelines:
- reachability_reasoning: Does the model use stack context to determine real exploitability? Full marks for correctly identifying each finding's reachability status.
- prioritization: Does the model rank findings by real-world urgency, not just CVSS score? Full marks for P0→P3 ordering that matches business impact.
- actionability: Are remediation steps specific (version numbers, config changes, timelines)? Penalize vague advice like "update dependencies".
- conciseness: Response is focused. No preamble, no disclaimers, no irrelevant details."""

# ---------------------------------------------------------------------------
# Pass 2 — Judge User Prompt Template
# ---------------------------------------------------------------------------
JUDGE_USER_PROMPT_TEMPLATE = """## Task

{system_prompt}

## Scan Output

{input}

## Stack Context

{stack_context}

## Model Response

{model_response}

## Rubric

{rubric}

Grade the response. JSON only."""

# ---------------------------------------------------------------------------
# Task registry — maps task names to their prompt configs
# ---------------------------------------------------------------------------

TASK_CONFIGS: dict[str, dict[str, Any]] = {
    "trivy_triage": {
        "version": PROMPT_VERSION,
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt_template": USER_PROMPT_TEMPLATE,
        "judge_system_prompt": JUDGE_SYSTEM_PROMPT,
        "judge_user_prompt_template": JUDGE_USER_PROMPT_TEMPLATE,
        "expected_schema": EXPECTED_OUTPUT_SCHEMA,
    },
}


def get_task_config(task_name: str) -> dict[str, Any]:
    """Return the prompt config for a given task name.

    Raises KeyError if the task is not registered.
    """
    if task_name not in TASK_CONFIGS:
        valid = list(TASK_CONFIGS.keys())
        raise KeyError(f"Unknown task '{task_name}'. Registered tasks: {valid}")
    return TASK_CONFIGS[task_name]


def _render_risk_metadata(ground_truth: GroundTruth | None) -> str:
    """Render risk metadata block when per-finding data is available.

    Returns an empty string if no finding has any risk metadata set.
    """
    if ground_truth is None:
        return ""

    all_findings = (
        list(ground_truth.exploitable_findings)
        + list(ground_truth.non_exploitable_findings)
        + list(ground_truth.partial_findings)
    )

    # Check if any finding has metadata
    has_metadata = any(
        f.cvss_score is not None
        or f.epss_percentile is not None
        or f.cisa_kev is not None
        or f.exploit_maturity is not None
        or f.fixed_version is not None
        or f.package_path is not None
        or f.runtime_exposure is not None
        or f.asset_criticality is not None
        or f.internet_facing is not None
        for f in all_findings
    )

    if not has_metadata:
        return ""

    cve_lines: list[str] = []
    for f in all_findings:
        cvss = f"  CVSS: {f.cvss_score}" if f.cvss_score is not None else ""
        epss = f"  EPSS: {f.epss_percentile:.2f}%" if f.epss_percentile is not None else ""
        kev = "  CISA KEV: YES" if f.cisa_kev else ("  CISA KEV: NO" if f.cisa_kev is False else "")
        maturity = (
            f"  Exploit Maturity: {f.exploit_maturity}" if f.exploit_maturity is not None else ""
        )
        fixed = f"  Fixed Version: {f.fixed_version}" if f.fixed_version is not None else ""
        pkg = f"  Package: {f.package_path}" if f.package_path is not None else ""
        exposure = f"  Exposure: {f.runtime_exposure}" if f.runtime_exposure is not None else ""
        criticality = (
            f"  Criticality: {f.asset_criticality}" if f.asset_criticality is not None else ""
        )
        facing = (
            "  Internet-Facing: YES"
            if f.internet_facing
            else ("  Internet-Facing: NO" if f.internet_facing is False else "")
        )

        fields = [
            line
            for line in [cvss, epss, kev, maturity, fixed, pkg, exposure, criticality, facing]
            if line
        ]
        if fields:
            cve_lines.append(f"  {f.cve}:")
            cve_lines.extend(fields)
            cve_lines.append("")

    if not cve_lines:
        return ""

    return "\n## Risk Metadata\n\n" + "\n".join(cve_lines)


def build_user_prompt(
    task_name: str,
    input_text: str,
    stack_context: str,
    ground_truth: GroundTruth | None = None,
) -> str:
    """Build the user prompt for a task by filling the template.

    If ``ground_truth`` is provided and any finding has risk metadata
    (CVSS, EPSS, CISA KEV, etc.), a ``## Risk Metadata`` section is
    appended to the prompt.
    """
    config = get_task_config(task_name)
    template: str = config["user_prompt_template"]
    risk_metadata = _render_risk_metadata(ground_truth)
    return template.format(
        input=input_text,
        stack_context=stack_context,
        risk_metadata=risk_metadata,
    )


def build_judge_prompt(
    task_name: str,
    system_prompt: str,
    input_text: str,
    stack_context: str,
    model_response: str,
    rubric: str,
) -> str:
    """Build the judge user prompt for a task."""
    config = get_task_config(task_name)
    template: str = config["judge_user_prompt_template"]
    return template.format(
        system_prompt=system_prompt,
        input=input_text,
        stack_context=stack_context,
        model_response=model_response,
        rubric=rubric,
    )


__all__ = [
    "EXPECTED_OUTPUT_SCHEMA",
    "JUDGE_SYSTEM_PROMPT",
    "JUDGE_USER_PROMPT_TEMPLATE",
    "PROMPT_VERSION",
    "SYSTEM_PROMPT",
    "TASK_CONFIGS",
    "USER_PROMPT_TEMPLATE",
    "build_judge_prompt",
    "build_user_prompt",
    "get_task_config",
]
