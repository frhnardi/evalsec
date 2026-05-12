"""Unit tests for Pydantic data models — Phase 3.2 checkpoint."""

from pathlib import Path

import pytest
import yaml

from evalsec.tasks.base import TaskCase

TEST_DATA_DIR = Path(__file__).parent.parent / "data" / "trivy_triage"


def test_task_case_loads_001_log4shell() -> None:
    """Verify that 001_log4shell_reachable.yaml loads and validates against TaskCase."""
    yaml_path = TEST_DATA_DIR / "001_log4shell_reachable.yaml"
    assert yaml_path.exists(), f"YAML file not found: {yaml_path}"

    with open(yaml_path, "r") as f:
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
        TaskCase.model_validate({
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
        })


def test_rubric_item_rejects_negative_score() -> None:
    """Verify that RubricItem max_score cannot be negative."""
    from evalsec.tasks.base import RubricItem

    with pytest.raises((ValueError, TypeError)):
        RubricItem(max_score=-5, description="negative should fail")
