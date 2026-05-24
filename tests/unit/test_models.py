"""Unit tests for Pydantic data models: Phase 3.2 checkpoint."""

from pathlib import Path

import pytest
import yaml

from evalsec.tasks.base import TaskCase

TEST_DATA_DIR = Path(__file__).parent.parent / "data" / "trivy_triage"


def test_task_case_loads_001_log4shell() -> None:
    """Verify that 001_log4shell_reachable.yaml loads and validates against TaskCase."""
    yaml_path = TEST_DATA_DIR / "001_log4shell_reachable.yaml"
    assert yaml_path.exists(), f"YAML file not found: {yaml_path}"

    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    case = TaskCase.model_validate(raw)

    # Check top-level fields
    assert case.id == "trivy_triage_001"
    assert case.task == "trivy_triage"
    assert case.version == "v1"
    assert case.weight == 1.5

    # Check source
    assert case.source.type == "self_scan"
    assert case.source.image == "tomcat:9.0.30"

    # Check that input is non-empty verbatim text
    assert len(case.input) > 100
    assert "log4j-core" in case.input

    # Check ground_truth
    assert len(case.ground_truth.exploitable_findings) >= 1
    assert len(case.ground_truth.non_exploitable_findings) >= 1
    assert len(case.ground_truth.partial_findings) >= 1

    # Verify exploitable finding
    exploitable = case.ground_truth.exploitable_findings[0]
    assert exploitable.cve == "CVE-2021-44228"
    assert exploitable.verdict == "exploitable"

    # Verify non-exploitable finding
    non_exploitable = case.ground_truth.non_exploitable_findings[0]
    assert non_exploitable.verdict == "not_exploitable"

    # Verify priority_order
    assert case.ground_truth.priority_order[0] == "CVE-2021-44228"

    # Check expected_response_includes
    assert len(case.expected_response_includes) >= 3

    # Check rubric
    assert case.rubric.reachability_reasoning.max_score == 25
    assert case.rubric.prioritization.max_score == 25
    assert case.rubric.actionability.max_score == 25
    assert case.rubric.conciseness.max_score == 25

    # Verify rubric total = 100
    rubric_total = (
        case.rubric.reachability_reasoning.max_score
        + case.rubric.prioritization.max_score
        + case.rubric.actionability.max_score
        + case.rubric.conciseness.max_score
    )
    assert rubric_total == 100, f"Rubric scores should sum to 100, got {rubric_total}"


def test_strict_mode_rejects_extra_fields() -> None:
    """Verify that extra="forbid" rejects unknown fields."""
    with pytest.raises((ValueError, TypeError)):
        TaskCase.model_validate(
            {
                "id": "trivy_triage_999",
                "task": "trivy_triage",
                "version": "v1",
                "source": {"type": "synthetic", "unknown_field": "oops"},
                "input": "scan output",
                "stack_context": "some context",
                "ground_truth": {
                    "exploitable_findings": [],
                    "non_exploitable_findings": [],
                    "partial_findings": [],
                    "priority_order": [],
                },
                "expected_response_includes": ["test"],
                "rubric": {
                    "reachability_reasoning": {"max_score": 25, "description": "a"},
                    "prioritization": {"max_score": 25, "description": "b"},
                    "actionability": {"max_score": 25, "description": "c"},
                    "conciseness": {"max_score": 25, "description": "d"},
                },
                "extra_field_should_fail": True,
            }
        )


def test_rubric_item_rejects_negative_score() -> None:
    """Verify that RubricItem max_score cannot be negative."""
    from evalsec.tasks.base import RubricItem

    with pytest.raises((ValueError, TypeError)):
        RubricItem(max_score=-5, description="negative should fail")


# ---------------------------------------------------------------------------
# Risk metadata tests (Issue 9)
# ---------------------------------------------------------------------------


def test_finding_detail_backward_compatible_no_metadata() -> None:
    """FindingDetail without risk metadata fields still loads (backward compat)."""
    from evalsec.tasks.base import FindingDetail

    detail = FindingDetail(
        cve="CVE-2021-44228",
        verdict="exploitable",
        reasoning="Test reasoning",
        action="Patch to 2.17.1",
    )
    assert detail.cvss_score is None
    assert detail.epss_percentile is None
    assert detail.cisa_kev is None
    assert detail.exploit_maturity is None
    assert detail.fixed_version is None
    assert detail.package_path is None
    assert detail.runtime_exposure is None
    assert detail.asset_criticality is None
    assert detail.internet_facing is None


def test_finding_detail_with_all_metadata() -> None:
    """FindingDetail accepts all risk metadata fields."""
    from evalsec.tasks.base import FindingDetail

    detail = FindingDetail(
        cve="CVE-2021-44228",
        verdict="exploitable",
        reasoning="Reachable via HTTP",
        action="Patch to 2.17.1",
        cvss_score=9.8,
        epss_percentile=97.5,
        cisa_kev=True,
        exploit_maturity="active",
        fixed_version="2.17.1",
        package_path="/usr/lib/log4j-core-2.14.1.jar",
        runtime_exposure="network",
        asset_criticality="critical",
        internet_facing=True,
    )
    assert detail.cvss_score == 9.8
    assert detail.epss_percentile == 97.5
    assert detail.cisa_kev is True
    assert detail.exploit_maturity == "active"
    assert detail.fixed_version == "2.17.1"
    assert detail.package_path == "/usr/lib/log4j-core-2.14.1.jar"
    assert detail.runtime_exposure == "network"
    assert detail.asset_criticality == "critical"
    assert detail.internet_facing is True


def test_finding_detail_rejects_invalid_cvss_range() -> None:
    """CVSS score outside 0.0-10.0 range is rejected."""
    from evalsec.tasks.base import FindingDetail

    with pytest.raises((ValueError, TypeError)):
        FindingDetail(
            cve="CVE-2021-44228",
            verdict="exploitable",
            reasoning="Test",
            action="Patch",
            cvss_score=11.0,
        )

    with pytest.raises((ValueError, TypeError)):
        FindingDetail(
            cve="CVE-2021-44228",
            verdict="exploitable",
            reasoning="Test",
            action="Patch",
            cvss_score=-1.0,
        )


def test_finding_detail_rejects_invalid_epss_range() -> None:
    """EPSS percentile outside 0.0-100.0 range is rejected."""
    from evalsec.tasks.base import FindingDetail

    with pytest.raises((ValueError, TypeError)):
        FindingDetail(
            cve="CVE-2021-44228",
            verdict="exploitable",
            reasoning="Test",
            action="Patch",
            epss_percentile=101.0,
        )


def test_finding_detail_partial_metadata() -> None:
    """FindingDetail with only some metadata fields set."""
    from evalsec.tasks.base import FindingDetail

    detail = FindingDetail(
        cve="CVE-2024-21626",
        verdict="partial",
        reasoning="Container escape partial mitigation",
        action="Patch runc",
        cvss_score=7.5,
        cisa_kev=False,
        # Note: epss_percentile, exploit_maturity, etc. intentionally omitted
    )
    assert detail.cvss_score == 7.5
    assert detail.cisa_kev is False
    assert detail.epss_percentile is None
    assert detail.exploit_maturity is None
    assert detail.fixed_version is None
    assert detail.internet_facing is None


def test_existing_yaml_still_loads_without_metadata() -> None:
    """The existing 001_log4shell YAML has no risk metadata and still loads."""
    yaml_path = TEST_DATA_DIR / "001_log4shell_reachable.yaml"
    assert yaml_path.exists()

    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    case = TaskCase.model_validate(raw)

    # Verify all findings have no metadata set
    for finding in case.ground_truth.exploitable_findings:
        assert finding.cvss_score is None
        assert finding.epss_percentile is None

    for finding in case.ground_truth.non_exploitable_findings:
        assert finding.cvss_score is None

    for finding in case.ground_truth.partial_findings:
        assert finding.cvss_score is None
