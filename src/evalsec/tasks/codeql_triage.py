"""Task definition for codeql_triage — SAST triage (CodeQL output).

Prompt templates and output schema for the CodeQL SAST triage task.
Models receive CodeQL SARIF-like output + deployment context and must
produce a prioritised remediation plan in VEX format.

Prompt Version: codeql_triage/v1
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Version — stamped on every graded response for audit trail
# ---------------------------------------------------------------------------
PROMPT_VERSION = "codeql_triage/v1"

# ---------------------------------------------------------------------------
# Pass 1 — System Prompt (shown to the benchmarked model)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a senior DevSecOps engineer at a financial services company operating under NIST SP 800-53 (US security standard) and PCI-DSS v4.0 (payment card industry) regulatory frameworks.

Your task is to analyze a CodeQL SAST scan output and produce a prioritised remediation plan in VEX (Vulnerability Exploitability eXchange) format. You will receive:

1. CodeQL scan output — a list of security findings with rule IDs, severity levels (error/warning/note), file locations, line numbers, and descriptions.
2. Stack context — application architecture, input validation controls, WAF rules, and data sensitivity classification.

CodeQL findings represent code-level security bugs detected via semantic analysis. Each finding has:
- A rule ID (e.g. py/sql-injection, js/xss, java/path-injection)
- A severity level: error (must-fix), warning (should-fix), note (informational)
- The exact file path and line number where the vulnerability was detected
- A description of the vulnerable code pattern
- Code flow paths showing how tainted data reaches the sink

You MUST respond in this exact VEX JSON format:

{
  "document": {
    "type": "vex",
    "author": "evalsec-benchmark"
  },
  "statements": [
    {
      "vulnerability": { "id": "RULE-ID-AT-LOCATION" },
      "status": "affected | not_affected | under_investigation",
      "justification": "code_not_reachable | vulnerable_code_cannot_be_controlled_by_attacker | vulnerable_code_not_in_execute_path | protected_by_compensating_control | component_not_present",
      "impact_statement": "1-sentence impact analysis using stack context...",
      "action_statement": "Brief remediation with specific code changes...",
      "priority": "P0 | P1 | P2 | P3",
      "timeline": "72 hours | this sprint | next quarter"
    }
  ]
}

Priority definitions:
- P0 = Exploitable from public internet, no compensating controls, high data sensitivity. Remediate within 72 hours.
- P1 = Reachable but limited blast radius or partial controls exist. Remediate this sprint.
- P2 = Theoretical risk — attack requires preconditions (auth bypass, internal access). Remediate this sprint.
- P3 = Protected by compensating controls / false positive. Remediate next quarter.

Justification values (required when status is not_affected):
- code_not_reachable: The vulnerable code path is not reachable from this deployment.
- vulnerable_code_cannot_be_controlled_by_attacker: Attacker cannot control the vulnerable input.
- vulnerable_code_not_in_execute_path: The vulnerable function is never called.
- protected_by_compensating_control: A compensating control (WAF, input validation, CSP) mitigates the risk.
- component_not_present: The affected component is not included in this deployment.

Rules:
- Base EVERY status on the stack context provided. If a CodeQL finding describes a code path that is protected by a WAF or input validation, mark it not_affected with appropriate justification.
- Be specific in action statements: include file paths, line numbers, and specific code changes where relevant.
- No preamble, no disclaimers, no "As an AI assistant". Begin directly with the JSON object.
- Conciseness critical: You have a limited token budget for the entire response. Keep each statement to 1-2 sentences max. Prioritize the most impactful findings."""

# ---------------------------------------------------------------------------
# Pass 1 — User Prompt Template
# ---------------------------------------------------------------------------
USER_PROMPT_TEMPLATE = """## CodeQL SAST Scan Output

{input}

## Stack Context

{stack_context}
{risk_metadata}

Analyze the findings above. Output JSON only."""

# ---------------------------------------------------------------------------
# Expected output schema (VEX format — same as trivy_triage for compatibility)
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
                            "id": {"type": "string", "pattern": r"^[a-z]+/[a-z0-9_-]+"},
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
# Pass 2 — Judge System Prompt (shown to the grader LLM)
# ---------------------------------------------------------------------------
JUDGE_SYSTEM_PROMPT = """You are a strict DevSecOps evaluator grading a model's SAST triage response.

You will receive:
1. The original task context (CodeQL scan output + stack context)
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

Scoring guidelines:
- reachability_reasoning: Does the model use stack context to determine real exploitability? Full marks for correctly identifying each finding's reachability status based on WAF rules, input validation, and deployment architecture.
- prioritization: Does the model rank findings by real-world exploitability, not just CodeQL severity? Full marks for P0→P3 ordering that matches business impact.
- actionability: Are remediation steps specific (file paths, code changes, config updates)? Penalize vague advice like "sanitize input" without specifics.
- conciseness: Response is focused. No preamble, no disclaimers, no irrelevant details."""

# ---------------------------------------------------------------------------
# Pass 2 — Judge User Prompt Template
# ---------------------------------------------------------------------------
JUDGE_USER_PROMPT_TEMPLATE = """## Task

{system_prompt}

## CodeQL Scan Output

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
    "codeql_triage": {
        "version": PROMPT_VERSION,
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt_template": USER_PROMPT_TEMPLATE,
        "judge_system_prompt": JUDGE_SYSTEM_PROMPT,
        "judge_user_prompt_template": JUDGE_USER_PROMPT_TEMPLATE,
        "expected_schema": EXPECTED_OUTPUT_SCHEMA,
    },
}

__all__ = [
    "EXPECTED_OUTPUT_SCHEMA",
    "JUDGE_SYSTEM_PROMPT",
    "JUDGE_USER_PROMPT_TEMPLATE",
    "PROMPT_VERSION",
    "SYSTEM_PROMPT",
    "TASK_CONFIGS",
    "USER_PROMPT_TEMPLATE",
    "VEX_STATUS_TO_VERDICT",
]
