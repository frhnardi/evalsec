"""Non-LLM baselines for benchmark comparison (Issue 10).

Each baseline implements a simple heuristic to produce a mock LLM response
in the expected JSON format. These responses are then graded by the same
``JsonValidator`` pipeline as real LLM responses, allowing the dashboard
to answer:

    > Is the LLM actually better than ordinary severity sorting?

Baselines require no API key and produce deterministic, reproducible results.
"""

from __future__ import annotations

import json
from typing import Any

from evalsec.tasks.base import FindingDetail, GroundTruth

# ---------------------------------------------------------------------------
# Baseline registry
# ---------------------------------------------------------------------------

BASELINE_MODELS: dict[str, str] = {
    "baseline_cvss": "CVSS Severity Sorting",
    "baseline_trivy": "Trivy Severity Sorting",
    "baseline_epss": "EPSS-Based Priority",
    "baseline_reachability": "Reachability Heuristic",
}

# Severity ordering (highest first)
TRIVY_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


def _collect_all_findings(ground_truth: GroundTruth) -> list[FindingDetail]:
    """Return all findings from all categories, in declaration order."""
    return (
        list(ground_truth.exploitable_findings)
        + list(ground_truth.non_exploitable_findings)
        + list(ground_truth.partial_findings)
    )


def _build_json_response(
    findings: list[dict[str, Any]],
) -> str:
    """Build a JSON response string from a list of finding dicts."""
    return json.dumps({"analysis": findings}, indent=2)


def _priority_from_position(idx: int, total: int) -> str:
    """Assign P0/P1/P2 based on position (0-indexed)."""
    if total <= 1:
        return "P0"
    if idx == 0:
        return "P0"
    if idx == 1:
        return "P1"
    return "P2"


def _default_reasoning(cve: str, priority: str) -> str:
    """Generate generic reasoning text for a baseline."""
    return (
        f"Baseline assessment for {cve}. "
        f"Priority {priority} assigned by deterministic sorting rule."
    )


def _default_action(cve: str, fixed_version: str | None = None) -> str:
    """Generate generic action text for a baseline."""
    if fixed_version:
        return f"Patch {cve} to version {fixed_version} or later."
    return f"Apply vendor-supplied fix for {cve}."


# ---------------------------------------------------------------------------
# Baseline generators
# ---------------------------------------------------------------------------


def _generate_cvss_baseline(ground_truth: GroundTruth) -> str:
    """Sort by CVSS score descending. Mark all as exploitable.

    Findings without CVSS scores are placed at the end with P3.
    """
    all_findings = _collect_all_findings(ground_truth)

    # Separate findings with and without CVSS scores
    with_cvss = [f for f in all_findings if f.cvss_score is not None]
    without_cvss = [f for f in all_findings if f.cvss_score is None]

    # Sort by CVSS descending
    with_cvss.sort(key=lambda f: f.cvss_score or 0.0, reverse=True)

    sorted_findings = with_cvss + without_cvss
    analysis: list[dict[str, Any]] = []
    total = len(sorted_findings)

    for idx, f in enumerate(sorted_findings):
        if f.cvss_score is not None:
            priority = _priority_from_position(idx, total)
        else:
            priority = "P3"

        analysis.append(
            {
                "cve": f.cve,
                "verdict": "exploitable",
                "priority": priority,
                "reasoning": _default_reasoning(f.cve, priority),
                "action": _default_action(f.cve, f.fixed_version),
                "timeline": "72 hours"
                if priority == "P0"
                else "this sprint"
                if priority == "P1"
                else "next quarter",
            }
        )

    return _build_json_response(analysis)


def _extract_trivy_severity(input_text: str, cve: str) -> str:
    """Parse Trivy output to find severity for a given CVE.

    Falls back to UNKNOWN if the CVE is not found in the scan output.
    """
    for line in input_text.split("\n"):
        if cve in line:
            parts = line.split()
            for part in parts:
                upper = part.upper()
                if upper in TRIVY_SEVERITY_ORDER:
                    return upper
    return "UNKNOWN"


def _generate_trivy_baseline(ground_truth: GroundTruth, input_text: str) -> str:
    """Sort by Trivy severity (CRITICAL > HIGH > MEDIUM > LOW).

    All findings marked as exploitable. Priority derived from severity rank.
    """
    all_findings = _collect_all_findings(ground_truth)

    # Extract severity for each finding from Trivy scan output
    severity_map: dict[str, int] = {}
    for f in all_findings:
        sev = _extract_trivy_severity(input_text, f.cve)
        severity_map[f.cve] = TRIVY_SEVERITY_ORDER.get(sev, 4)

    # Sort by severity (lower number = more severe)
    sorted_findings = sorted(all_findings, key=lambda f: severity_map.get(f.cve, 4))
    total = len(sorted_findings)
    analysis: list[dict[str, Any]] = []

    for idx, f in enumerate(sorted_findings):
        priority = _priority_from_position(idx, total)

        analysis.append(
            {
                "cve": f.cve,
                "verdict": "exploitable",
                "priority": priority,
                "reasoning": _default_reasoning(f.cve, priority),
                "action": _default_action(f.cve, f.fixed_version),
                "timeline": "72 hours"
                if priority == "P0"
                else "this sprint"
                if priority == "P1"
                else "next quarter",
            }
        )

    return _build_json_response(analysis)


def _generate_epss_baseline(ground_truth: GroundTruth) -> str:
    """Sort by EPSS percentile descending. Mark all as exploitable.

    Findings without EPSS data are placed at the end with P3.
    """
    all_findings = _collect_all_findings(ground_truth)

    with_epss = [f for f in all_findings if f.epss_percentile is not None]
    without_epss = [f for f in all_findings if f.epss_percentile is None]

    with_epss.sort(key=lambda f: f.epss_percentile or 0.0, reverse=True)

    sorted_findings = with_epss + without_epss
    total = len(sorted_findings)
    analysis: list[dict[str, Any]] = []

    for idx, f in enumerate(sorted_findings):
        if f.epss_percentile is not None:
            priority = _priority_from_position(idx, total)
        else:
            priority = "P3"

        analysis.append(
            {
                "cve": f.cve,
                "verdict": "exploitable",
                "priority": priority,
                "reasoning": _default_reasoning(f.cve, priority),
                "action": _default_action(f.cve, f.fixed_version),
                "timeline": "72 hours"
                if priority == "P0"
                else "this sprint"
                if priority == "P1"
                else "next quarter",
            }
        )

    return _build_json_response(analysis)


def _generate_reachability_baseline(ground_truth: GroundTruth) -> str:
    """Use internet_facing + runtime_exposure + cvss to determine exploitability.

    Heuristic rules (in order of priority):
    1. internet_facing=True AND cvss_score >= 7.0 → exploitable, P0
    2. internet_facing=True AND cvss_score < 7.0 → exploitable, P1
    3. internet_facing=False AND runtime_exposure="network" → partial, P2
    4. Otherwise → not_exploitable, P3
    5. If no metadata at all → not_exploitable, P3 (conservative)
    """
    all_findings = _collect_all_findings(ground_truth)
    analysis: list[dict[str, Any]] = []

    for f in all_findings:
        # Check internet-facing
        if f.internet_facing is True and f.cvss_score is not None and f.cvss_score >= 7.0:
            verdict = "exploitable"
            priority = "P0"
            timeline = "72 hours"
        elif f.internet_facing is True:
            verdict = "exploitable"
            priority = "P1"
            timeline = "this sprint"
        elif f.runtime_exposure == "network":
            verdict = "partial"
            priority = "P2"
            timeline = "this sprint"
        else:
            verdict = "not_exploitable"
            priority = "P3"
            timeline = "next quarter"

        analysis.append(
            {
                "cve": f.cve,
                "verdict": verdict,
                "priority": priority,
                "reasoning": (
                    f"Reachability heuristic: internet_facing={f.internet_facing}, "
                    f"cvss={f.cvss_score}, exposure={f.runtime_exposure}. "
                    f"Verdict: {verdict}, Priority: {priority}."
                ),
                "action": _default_action(f.cve, f.fixed_version),
                "timeline": timeline,
            }
        )

    return _build_json_response(analysis)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

BASELINE_GENERATORS: dict[str, str] = {
    "baseline_cvss": "CVSS Score (descending)",
    "baseline_trivy": "Trivy Severity (CRITICAL→LOW)",
    "baseline_epss": "EPSS Percentile (descending)",
    "baseline_reachability": "Reachability Heuristic",
}


def generate_baseline_response(
    baseline_key: str,
    ground_truth: GroundTruth,
    input_text: str = "",
) -> str:
    """Generate a mock LLM response for the given baseline strategy.

    Args:
        baseline_key: One of ``BASELINE_GENERATORS.keys()``.
        ground_truth: The ground truth for the test case.
        input_text: The raw Trivy scan output (needed for Trivy severity baseline).

    Returns:
        A JSON string following the expected output schema.

    Raises:
        ValueError: If ``baseline_key`` is unknown.
    """
    if baseline_key == "baseline_cvss":
        return _generate_cvss_baseline(ground_truth)
    if baseline_key == "baseline_trivy":
        return _generate_trivy_baseline(ground_truth, input_text)
    if baseline_key == "baseline_epss":
        return _generate_epss_baseline(ground_truth)
    if baseline_key == "baseline_reachability":
        return _generate_reachability_baseline(ground_truth)

    valid = list(BASELINE_GENERATORS.keys())
    raise ValueError(f"Unknown baseline '{baseline_key}'. Valid baselines: {valid}")


def grade_baselines(
    ground_truth: GroundTruth,
    input_text: str,
    regex_patterns: list[str],
) -> dict[str, dict[str, Any]]:
    """Grade all baselines against the given ground truth.

    Returns a dict mapping baseline_key → graded score dict, compatible
    with the dashboard's expected format.
    """
    from evalsec.grader import PASS1_WEIGHT, JsonValidator

    results: dict[str, dict[str, Any]] = {}
    for key in BASELINE_GENERATORS:
        response_text = generate_baseline_response(key, ground_truth, input_text)

        validation = JsonValidator.validate(
            response_text=response_text,
            ground_truth=ground_truth,
            regex_patterns=regex_patterns,
        )

        # Compute blended deterministic score
        deterministic_raw = (
            validation.format_score * 0.10  # FORMAT_WEIGHT
            + validation.coverage_score * 0.30  # COVERAGE_WEIGHT
            + validation.verdict_score * 0.30  # VERDICT_WEIGHT
            + validation.priority_score * 0.20  # PRIORITY_WEIGHT
            + validation.regex_score * 0.10  # REGEX_WEIGHT
        )
        deterministic_raw = max(0.0, deterministic_raw - validation.hallucination_penalty)
        pass1_weighted = deterministic_raw * PASS1_WEIGHT

        results[key] = {
            "total": round(deterministic_raw, 2),
            "pass1_score": round(pass1_weighted, 2),
            "pass2_score": 0.0,
            "format_score": round(validation.format_score, 1),
            "coverage_score": round(validation.coverage_score, 1),
            "verdict_score": round(validation.verdict_score, 1),
            "priority_score": round(validation.priority_score, 1),
            "regex_score": round(validation.regex_score, 1),
            "judge_score": 0.0,
            "hallucination_penalty": validation.hallucination_penalty,
            "deterministic_total": round(deterministic_raw, 2),
            "model_type": "baseline",
            "validation": {
                "missing_cves": validation.missing_cves,
                "hallucinated_cves": validation.hallucinated_cves,
                "verdict_mismatches": validation.verdict_mismatches,
                "priority_mismatches": validation.priority_mismatches,
                "parse_error": validation.parse_error,
            },
        }

    return results


__all__ = [
    "BASELINE_GENERATORS",
    "BASELINE_MODELS",
    "generate_baseline_response",
    "grade_baselines",
]
