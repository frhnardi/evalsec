"""Unit tests for non-LLM baselines — Issue 10.

Tests cover:
- Each baseline generator produces valid JSON matching the expected schema.
- Sort order (CVSS descending, severity descending, EPSS descending).
- Reachability heuristic decision tree.
- ``grade_baselines()`` integration with ``JsonValidator``.
- Edge cases: empty ground truth, no metadata, unknown baseline key.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from evalsec.baselines import (
    BASELINE_GENERATORS,
    _extract_trivy_severity,
    _generate_cvss_baseline,
    _generate_epss_baseline,
    _generate_reachability_baseline,
    _generate_trivy_baseline,
    _priority_from_position,
    generate_baseline_response,
    grade_baselines,
)
from evalsec.tasks.base import FindingDetail, GroundTruth

# ---------------------------------------------------------------------------
# Fixtures — shared test data
# ---------------------------------------------------------------------------


@pytest.fixture
def ground_truth_with_metadata() -> GroundTruth:
    """Ground truth with 3 findings, all with CVSS and EPSS metadata."""
    return GroundTruth(
        exploitable_findings=[
            FindingDetail(
                cve="CVE-2021-44228",
                verdict="exploitable",
                reasoning="Log4Shell reachable from HTTP",
                action="Patch to 2.17.1",
                cvss_score=9.8,
                epss_percentile=97.5,
                cisa_kev=True,
                exploit_maturity="active",
                fixed_version="2.17.1",
            ),
        ],
        non_exploitable_findings=[
            FindingDetail(
                cve="CVE-2023-50447",
                verdict="not_exploitable",
                reasoning="Pillow eval() never called",
                action="Defer",
                cvss_score=5.5,
                epss_percentile=12.3,
                cisa_kev=False,
            ),
        ],
        partial_findings=[
            FindingDetail(
                cve="CVE-2024-21626",
                verdict="partial",
                reasoning="Container escape mitigated",
                action="Patch runc soon",
                cvss_score=7.5,
                epss_percentile=45.0,
                internet_facing=True,
                runtime_exposure="network",
            ),
        ],
        priority_order=[
            "CVE-2021-44228",
            "CVE-2024-21626",
            "CVE-2023-50447",
        ],
    )


@pytest.fixture
def ground_truth_no_metadata() -> GroundTruth:
    """Ground truth with 3 findings but NO risk metadata fields set."""
    return GroundTruth(
        exploitable_findings=[
            FindingDetail(
                cve="CVE-2021-44228",
                verdict="exploitable",
                reasoning="Log4Shell",
                action="Patch now",
            ),
        ],
        non_exploitable_findings=[
            FindingDetail(
                cve="CVE-2023-50447",
                verdict="not_exploitable",
                reasoning="Not reachable",
                action="Defer",
            ),
        ],
        partial_findings=[
            FindingDetail(
                cve="CVE-2024-21626",
                verdict="partial",
                reasoning="Mitigated",
                action="Patch runc",
            ),
        ],
        priority_order=[
            "CVE-2021-44228",
            "CVE-2024-21626",
            "CVE-2023-50447",
        ],
    )


@pytest.fixture
def ground_truth_empty() -> GroundTruth:
    """Ground truth with zero findings — edge case."""
    return GroundTruth(
        exploitable_findings=[],
        non_exploitable_findings=[],
        partial_findings=[],
        priority_order=[],
    )


@pytest.fixture
def trivy_scan_output() -> str:
    """Simulated Trivy scan output for severity parsing tests.

    Severity keyword must appear as a standalone word (not as ``CRITICAL:``)
    because ``_extract_trivy_severity()`` splits by whitespace and looks for
    exact matches in ``TRIVY_SEVERITY_ORDER``.
    """
    return """\
CVE-2021-44228 CRITICAL (log4j 2.15.0)
CVE-2024-21626 HIGH (runc 1.1.0)
CVE-2023-50447 MEDIUM (pillow 9.0.0)
CVE-2025-12345 not found in severity map
"""


# ---------------------------------------------------------------------------
# Tests: _priority_from_position
# ---------------------------------------------------------------------------


class TestPriorityFromPosition:
    """Tests for the position-based priority assignment logic."""

    def test_single_item_gets_p0(self) -> None:
        assert _priority_from_position(0, 1) == "P0"

    def test_first_item_gets_p0(self) -> None:
        assert _priority_from_position(0, 5) == "P0"

    def test_second_item_gets_p1(self) -> None:
        assert _priority_from_position(1, 5) == "P1"

    def test_third_item_gets_p2(self) -> None:
        assert _priority_from_position(2, 5) == "P2"

    def test_fourth_item_gets_p2(self) -> None:
        assert _priority_from_position(3, 5) == "P2"

    def test_last_item_gets_p2(self) -> None:
        assert _priority_from_position(4, 5) == "P2"


# ---------------------------------------------------------------------------
# Tests: _extract_trivy_severity
# ---------------------------------------------------------------------------


class TestExtractTrivySeverity:
    """Tests for parsing Trivy severity from scan output text."""

    def test_critical_found(self, trivy_scan_output: str) -> None:
        assert _extract_trivy_severity(trivy_scan_output, "CVE-2021-44228") == "CRITICAL"

    def test_high_found(self, trivy_scan_output: str) -> None:
        assert _extract_trivy_severity(trivy_scan_output, "CVE-2024-21626") == "HIGH"

    def test_medium_found(self, trivy_scan_output: str) -> None:
        assert _extract_trivy_severity(trivy_scan_output, "CVE-2023-50447") == "MEDIUM"

    def test_cve_not_in_output(self, trivy_scan_output: str) -> None:
        assert _extract_trivy_severity(trivy_scan_output, "CVE-9999-99999") == "UNKNOWN"

    def test_empty_input(self) -> None:
        assert _extract_trivy_severity("", "CVE-2021-44228") == "UNKNOWN"

    def test_case_insensitive_severity(self) -> None:
        output = "CVE-2021-44228 critical severity"
        assert _extract_trivy_severity(output, "CVE-2021-44228") == "CRITICAL"


# ---------------------------------------------------------------------------
# Tests: _generate_cvss_baseline
# ---------------------------------------------------------------------------


class TestGenerateCvssBaseline:
    """CVSS baseline: sorts findings by CVSS descending, all exploitable."""

    def test_sorts_by_cvss_descending(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = _generate_cvss_baseline(ground_truth_with_metadata)
        data = json.loads(response)
        analysis: list[dict[str, Any]] = data["analysis"]

        # CVSS order: 9.8 (CVE-2021-44228) -> 7.5 (CVE-2024-21626) -> 5.5 (CVE-2023-50447)
        assert len(analysis) == 3
        assert analysis[0]["cve"] == "CVE-2021-44228"
        assert analysis[1]["cve"] == "CVE-2024-21626"
        assert analysis[2]["cve"] == "CVE-2023-50447"

    def test_all_verdicts_exploitable(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = _generate_cvss_baseline(ground_truth_with_metadata)
        data = json.loads(response)
        for entry in data["analysis"]:
            assert entry["verdict"] == "exploitable"

    def test_priority_from_cvss_rank(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = _generate_cvss_baseline(ground_truth_with_metadata)
        data = json.loads(response)
        # 3 items: idx=0 -> P0, idx=1 -> P1, idx=2 -> P2
        assert data["analysis"][0]["priority"] == "P0"
        assert data["analysis"][1]["priority"] == "P1"
        assert data["analysis"][2]["priority"] == "P2"

    def test_findings_without_cvss_get_p3(self) -> None:
        """Findings with no CVSS score are placed at end with P3."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2021-44228",
                    verdict="exploitable",
                    reasoning="x",
                    action="y",
                    cvss_score=9.8,
                ),
            ],
            non_exploitable_findings=[
                FindingDetail(
                    cve="CVE-2023-50447",
                    verdict="not_exploitable",
                    reasoning="x",
                    action="y",
                ),
            ],
            partial_findings=[],
            priority_order=["CVE-2021-44228", "CVE-2023-50447"],
        )
        response = _generate_cvss_baseline(gt)
        data = json.loads(response)
        # CVE-2021-44228 (CVSS 9.8) first, CVE-2023-50447 (no CVSS) last with P3
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"
        assert data["analysis"][0]["priority"] == "P0"
        assert data["analysis"][1]["cve"] == "CVE-2023-50447"
        assert data["analysis"][1]["priority"] == "P3"

    def test_empty_ground_truth(self, ground_truth_empty: GroundTruth) -> None:
        response = _generate_cvss_baseline(ground_truth_empty)
        data = json.loads(response)
        assert data["analysis"] == []

    def test_no_cvss_metadata(self, ground_truth_no_metadata: GroundTruth) -> None:
        """All findings have no CVSS -> all get P3."""
        response = _generate_cvss_baseline(ground_truth_no_metadata)
        data = json.loads(response)
        for entry in data["analysis"]:
            assert entry["priority"] == "P3"


# ---------------------------------------------------------------------------
# Tests: _generate_trivy_baseline
# ---------------------------------------------------------------------------


class TestGenerateTrivyBaseline:
    """Trivy baseline: sorts by Trivy severity CRITICAL -> LOW."""

    def test_sorts_by_severity(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        response = _generate_trivy_baseline(ground_truth_with_metadata, trivy_scan_output)
        data = json.loads(response)
        # Severity order: CRITICAL (CVE-2021-44228) -> HIGH (CVE-2024-21626) -> MEDIUM (CVE-2023-50447)
        assert len(data["analysis"]) == 3
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"
        assert data["analysis"][1]["cve"] == "CVE-2024-21626"
        assert data["analysis"][2]["cve"] == "CVE-2023-50447"

    def test_all_verdicts_exploitable(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        response = _generate_trivy_baseline(ground_truth_with_metadata, trivy_scan_output)
        data = json.loads(response)
        for entry in data["analysis"]:
            assert entry["verdict"] == "exploitable"

    def test_priority_from_severity_rank(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        response = _generate_trivy_baseline(ground_truth_with_metadata, trivy_scan_output)
        data = json.loads(response)
        # 3 items: idx=0 -> P0, idx=1 -> P1, idx=2 -> P2
        assert data["analysis"][0]["priority"] == "P0"
        assert data["analysis"][1]["priority"] == "P1"
        assert data["analysis"][2]["priority"] == "P2"

    def test_cve_not_in_scan_goes_last(self, trivy_scan_output: str) -> None:
        """CVE not found in Trivy output (UNKNOWN severity) goes to end."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2021-44228", verdict="exploitable", reasoning="x", action="y"
                ),
                FindingDetail(
                    cve="CVE-9999-99999", verdict="exploitable", reasoning="x", action="y"
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2021-44228", "CVE-9999-99999"],
        )
        response = _generate_trivy_baseline(gt, trivy_scan_output)
        data = json.loads(response)
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"  # CRITICAL
        assert data["analysis"][1]["cve"] == "CVE-9999-99999"  # UNKNOWN -> last

    def test_empty_input_text(self, ground_truth_with_metadata: GroundTruth) -> None:
        """With empty scan output, all severities are UNKNOWN -> preserve original order."""
        response = _generate_trivy_baseline(ground_truth_with_metadata, "")
        data = json.loads(response)
        assert len(data["analysis"]) == 3


# ---------------------------------------------------------------------------
# Tests: _generate_epss_baseline
# ---------------------------------------------------------------------------


class TestGenerateEpssBaseline:
    """EPSS baseline: sorts by EPSS percentile descending."""

    def test_sorts_by_epss_descending(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = _generate_epss_baseline(ground_truth_with_metadata)
        data = json.loads(response)
        # EPSS order: 97.5 (CVE-2021-44228) -> 45.0 (CVE-2024-21626) -> 12.3 (CVE-2023-50447)
        assert len(data["analysis"]) == 3
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"
        assert data["analysis"][1]["cve"] == "CVE-2024-21626"
        assert data["analysis"][2]["cve"] == "CVE-2023-50447"

    def test_all_verdicts_exploitable(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = _generate_epss_baseline(ground_truth_with_metadata)
        data = json.loads(response)
        for entry in data["analysis"]:
            assert entry["verdict"] == "exploitable"

    def test_priority_from_epss_rank(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = _generate_epss_baseline(ground_truth_with_metadata)
        data = json.loads(response)
        assert data["analysis"][0]["priority"] == "P0"
        assert data["analysis"][1]["priority"] == "P1"
        assert data["analysis"][2]["priority"] == "P2"

    def test_findings_without_epss_get_p3(self) -> None:
        """Findings with no EPSS percentile are placed at end with P3."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2021-44228",
                    verdict="exploitable",
                    reasoning="x",
                    action="y",
                    epss_percentile=95.0,
                ),
            ],
            non_exploitable_findings=[
                FindingDetail(
                    cve="CVE-2023-50447",
                    verdict="not_exploitable",
                    reasoning="x",
                    action="y",
                ),
            ],
            partial_findings=[],
            priority_order=["CVE-2021-44228", "CVE-2023-50447"],
        )
        response = _generate_epss_baseline(gt)
        data = json.loads(response)
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"
        assert data["analysis"][0]["priority"] == "P0"
        assert data["analysis"][1]["cve"] == "CVE-2023-50447"
        assert data["analysis"][1]["priority"] == "P3"

    def test_empty_ground_truth(self, ground_truth_empty: GroundTruth) -> None:
        response = _generate_epss_baseline(ground_truth_empty)
        data = json.loads(response)
        assert data["analysis"] == []

    def test_no_epss_metadata(self, ground_truth_no_metadata: GroundTruth) -> None:
        """All findings have no EPSS -> all get P3."""
        response = _generate_epss_baseline(ground_truth_no_metadata)
        data = json.loads(response)
        for entry in data["analysis"]:
            assert entry["priority"] == "P3"


# ---------------------------------------------------------------------------
# Tests: _generate_reachability_baseline
# ---------------------------------------------------------------------------


class TestGenerateReachabilityBaseline:
    """Reachability heuristic baseline: uses internet_facing + cvss + runtime_exposure."""

    def test_internet_facing_high_cvss_exploitable_p0(self) -> None:
        """internet_facing=True, cvss>=7.0 -> exploitable P0."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2021-44228",
                    verdict="exploitable",
                    reasoning="x",
                    action="y",
                    internet_facing=True,
                    cvss_score=9.8,
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2021-44228"],
        )
        response = _generate_reachability_baseline(gt)
        data = json.loads(response)
        assert data["analysis"][0]["verdict"] == "exploitable"
        assert data["analysis"][0]["priority"] == "P0"
        assert data["analysis"][0]["timeline"] == "72 hours"

    def test_internet_facing_low_cvss_exploitable_p1(self) -> None:
        """internet_facing=True, cvss<7.0 -> exploitable P1."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2024-21626",
                    verdict="exploitable",
                    reasoning="x",
                    action="y",
                    internet_facing=True,
                    cvss_score=5.5,
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2024-21626"],
        )
        response = _generate_reachability_baseline(gt)
        data = json.loads(response)
        assert data["analysis"][0]["verdict"] == "exploitable"
        assert data["analysis"][0]["priority"] == "P1"
        assert data["analysis"][0]["timeline"] == "this sprint"

    def test_network_exposure_partial_p2(self) -> None:
        """internet_facing=False, runtime_exposure=network -> partial P2."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2023-50447",
                    verdict="exploitable",
                    reasoning="x",
                    action="y",
                    internet_facing=False,
                    runtime_exposure="network",
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2023-50447"],
        )
        response = _generate_reachability_baseline(gt)
        data = json.loads(response)
        assert data["analysis"][0]["verdict"] == "partial"
        assert data["analysis"][0]["priority"] == "P2"
        assert data["analysis"][0]["timeline"] == "this sprint"

    def test_not_internet_facing_not_network_not_exploitable_p3(self) -> None:
        """No internet facing, no network exposure -> not_exploitable P3."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2023-50447",
                    verdict="exploitable",
                    reasoning="x",
                    action="y",
                    internet_facing=False,
                    runtime_exposure="local",
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2023-50447"],
        )
        response = _generate_reachability_baseline(gt)
        data = json.loads(response)
        assert data["analysis"][0]["verdict"] == "not_exploitable"
        assert data["analysis"][0]["priority"] == "P3"
        assert data["analysis"][0]["timeline"] == "next quarter"

    def test_no_metadata_conservative_not_exploitable(self) -> None:
        """No metadata at all -> not_exploitable P3 (conservative default)."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2021-44228",
                    verdict="exploitable",
                    reasoning="x",
                    action="y",
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2021-44228"],
        )
        response = _generate_reachability_baseline(gt)
        data = json.loads(response)
        assert data["analysis"][0]["verdict"] == "not_exploitable"
        assert data["analysis"][0]["priority"] == "P3"

    def test_multiple_findings(self, ground_truth_with_metadata: GroundTruth) -> None:
        """All three rules applied across mixed findings."""
        response = _generate_reachability_baseline(ground_truth_with_metadata)
        data = json.loads(response)
        findings_map = {e["cve"]: e for e in data["analysis"]}

        # CVE-2021-44228: internet_facing not set -> None -> not_exploitable P3
        assert findings_map["CVE-2021-44228"]["verdict"] == "not_exploitable"
        assert findings_map["CVE-2021-44228"]["priority"] == "P3"

        # CVE-2024-21626: internet_facing=True, cvss=7.5 >= 7.0 -> exploitable P0
        assert findings_map["CVE-2024-21626"]["verdict"] == "exploitable"
        assert findings_map["CVE-2024-21626"]["priority"] == "P0"

        # CVE-2023-50447: internet_facing not set -> not_exploitable P3
        assert findings_map["CVE-2023-50447"]["verdict"] == "not_exploitable"
        assert findings_map["CVE-2023-50447"]["priority"] == "P3"

    def test_empty_ground_truth(self, ground_truth_empty: GroundTruth) -> None:
        response = _generate_reachability_baseline(ground_truth_empty)
        data = json.loads(response)
        assert data["analysis"] == []


# ---------------------------------------------------------------------------
# Tests: generate_baseline_response (public API)
# ---------------------------------------------------------------------------


class TestGenerateBaselineResponse:
    """Tests for the public ``generate_baseline_response()`` API."""

    def test_cvss_baseline_key(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = generate_baseline_response("baseline_cvss", ground_truth_with_metadata)
        data = json.loads(response)
        assert len(data["analysis"]) == 3
        # First item should be highest CVSS
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"

    def test_trivy_baseline_key(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        response = generate_baseline_response(
            "baseline_trivy", ground_truth_with_metadata, input_text=trivy_scan_output
        )
        data = json.loads(response)
        assert len(data["analysis"]) == 3
        # First item should be CRITICAL severity
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"

    def test_epss_baseline_key(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = generate_baseline_response("baseline_epss", ground_truth_with_metadata)
        data = json.loads(response)
        assert len(data["analysis"]) == 3
        # First item should be highest EPSS
        assert data["analysis"][0]["cve"] == "CVE-2021-44228"

    def test_reachability_baseline_key(self, ground_truth_with_metadata: GroundTruth) -> None:
        response = generate_baseline_response("baseline_reachability", ground_truth_with_metadata)
        data = json.loads(response)
        assert len(data["analysis"]) == 3

    def test_unknown_baseline_key(self, ground_truth_with_metadata: GroundTruth) -> None:
        with pytest.raises(ValueError, match="Unknown baseline"):
            generate_baseline_response("baseline_nonexistent", ground_truth_with_metadata)

    def test_output_is_valid_json(self, ground_truth_with_metadata: GroundTruth) -> None:
        """All baselines produce valid parseable JSON."""
        for key in BASELINE_GENERATORS:
            response = generate_baseline_response(key, ground_truth_with_metadata)
            data = json.loads(response)
            assert "analysis" in data
            assert isinstance(data["analysis"], list)

    def test_each_entry_has_required_fields(self, ground_truth_with_metadata: GroundTruth) -> None:
        """Each baseline entry has cve, verdict, priority, reasoning, action, timeline."""
        required = {"cve", "verdict", "priority", "reasoning", "action", "timeline"}
        for key in BASELINE_GENERATORS:
            response = generate_baseline_response(key, ground_truth_with_metadata)
            data = json.loads(response)
            for entry in data["analysis"]:
                assert required.issubset(entry.keys()), (
                    f"Baseline {key} missing fields in {entry['cve']}"
                )

    def test_deterministic_output(self, ground_truth_with_metadata: GroundTruth) -> None:
        """Same inputs produce identical output (deterministic)."""
        response1 = generate_baseline_response("baseline_cvss", ground_truth_with_metadata)
        response2 = generate_baseline_response("baseline_cvss", ground_truth_with_metadata)
        assert response1 == response2


# ---------------------------------------------------------------------------
# Tests: grade_baselines (integration with JsonValidator)
# ---------------------------------------------------------------------------


class TestGradeBaselines:
    """Tests for the ``grade_baselines()`` integration with ``JsonValidator``."""

    def test_returns_all_baselines(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        assert set(results.keys()) == set(BASELINE_GENERATORS.keys())

    def test_each_result_has_required_keys(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        required_keys = {
            "total",
            "pass1_score",
            "pass2_score",
            "format_score",
            "coverage_score",
            "verdict_score",
            "priority_score",
            "regex_score",
            "judge_score",
            "hallucination_penalty",
            "deterministic_total",
            "model_type",
            "validation",
        }
        for key, result in results.items():
            assert required_keys.issubset(result.keys()), (
                f"Baseline {key} missing keys: {required_keys - result.keys()}"
            )

    def test_pass2_score_and_judge_score_are_zero(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        """Baselines only have pass 1 scores; pass 2 and judge are always 0."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        for key, result in results.items():
            assert result["pass2_score"] == 0.0, f"{key}: pass2_score should be 0"
            assert result["judge_score"] == 0.0, f"{key}: judge_score should be 0"

    def test_model_type_is_baseline(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        """Each baseline result has model_type='baseline'."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        for key, result in results.items():
            assert result["model_type"] == "baseline", (
                f"{key}: expected model_type='baseline', got {result['model_type']!r}"
            )

    def test_deterministic_total_matches_total(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        """Baseline deterministic_total matches total (no judge pass)."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        for key, result in results.items():
            assert result["deterministic_total"] == result["total"], (
                f"{key}: deterministic_total={result['deterministic_total']} != total={result['total']}"
            )

    def test_pass1_score_is_weighted(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        """Baseline pass1_score should be deterministic_raw * PASS1_WEIGHT (0.20)."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        for key, result in results.items():
            expected_pass1 = round(result["deterministic_total"] * 0.20, 2)
            assert result["pass1_score"] == expected_pass1, (
                f"{key}: pass1_score={result['pass1_score']} != expected={expected_pass1}"
            )

    def test_validation_has_expected_subkeys(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        validation_keys = {
            "missing_cves",
            "hallucinated_cves",
            "verdict_mismatches",
            "priority_mismatches",
            "parse_error",
        }
        for key, result in results.items():
            assert validation_keys.issubset(result["validation"].keys()), (
                f"{key}: missing validation subkeys"
            )

    def test_with_regex_patterns(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        """Regex patterns are checked against baseline output."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=["Patch", "CVE"],
        )
        # All baselines use "Patch" in action and "CVE" in cve, so regex_score > 0
        for result in results.values():
            assert result["regex_score"] > 0.0

    def test_empty_ground_truth(self, ground_truth_empty: GroundTruth) -> None:
        results = grade_baselines(
            ground_truth=ground_truth_empty,
            input_text="",
            regex_patterns=[],
        )
        assert set(results.keys()) == set(BASELINE_GENERATORS.keys())
        # Empty ground truth -> perfect coverage (0 CVEs to cover)
        for result in results.values():
            assert result["coverage_score"] == 100.0

    def test_baseline_cvss_verdict_accuracy(self, ground_truth_with_metadata: GroundTruth) -> None:
        """CVSS baseline marks all as exploitable, but some ground truth entries
        are partial or not_exploitable -> verdict accuracy will be < 100."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text="",
            regex_patterns=[],
        )
        cvss_result = results["baseline_cvss"]
        # Out of 3 findings, CVSS baseline marks all exploitable.
        # Ground truth: 1 exploitable, 1 partial, 1 not_exploitable.
        # Verdict matches only 1/3 ~ 33.3 out of 100
        assert cvss_result["verdict_score"] < 100.0
        assert cvss_result["verdict_score"] >= 0.0

    def test_baseline_reachability_verdict_accuracy(
        self, ground_truth_with_metadata: GroundTruth
    ) -> None:
        """Reachability baseline might get some verdicts right."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text="",
            regex_patterns=[],
        )
        reach_result = results["baseline_reachability"]
        # At least scoreable without error
        assert isinstance(reach_result["total"], float)
        assert reach_result["validation"]["parse_error"] is None

    def test_no_parse_error_for_any_baseline(
        self, ground_truth_with_metadata: GroundTruth, trivy_scan_output: str
    ) -> None:
        """All baselines produce valid JSON that JsonValidator can parse."""
        results = grade_baselines(
            ground_truth=ground_truth_with_metadata,
            input_text=trivy_scan_output,
            regex_patterns=[],
        )
        for key, result in results.items():
            assert result["validation"]["parse_error"] is None, (
                f"{key} had parse error: {result['validation']['parse_error']}"
            )


# ---------------------------------------------------------------------------
# Tests: BASELINE_GENERATORS constant
# ---------------------------------------------------------------------------


class TestBaselineConstants:
    """Verify BASELINE_GENERATORS and BASELINE_MODELS are consistent."""

    def test_baseline_generators_has_four_entries(self) -> None:
        assert len(BASELINE_GENERATORS) == 4

    def test_baseline_generators_keys_are_strings(self) -> None:
        for key in BASELINE_GENERATORS:
            assert isinstance(key, str)
            assert key.startswith("baseline_")
