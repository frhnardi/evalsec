"""Tests for risk metadata rendering in prompt templates (Issue 9).

Verifies that:
- _render_risk_metadata returns empty string when no metadata exists.
- _render_risk_metadata renders all fields when present.
- build_user_prompt includes risk metadata section when ground_truth has it.
- build_user_prompt omits risk metadata section when ground_truth is None.
- Scoring does not crash when metadata is absent.
"""

from __future__ import annotations

import pytest

from evalsec.tasks.base import FindingDetail, GroundTruth
from evalsec.tasks.trivy_triage import _render_risk_metadata, build_user_prompt

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_ground_truth() -> GroundTruth:
    """Ground truth with no risk metadata."""
    return GroundTruth(
        exploitable_findings=[
            FindingDetail(
                cve="CVE-2021-44228",
                verdict="exploitable",
                reasoning="Reachable via HTTP",
                action="Patch to 2.17.1",
            ),
        ],
        non_exploitable_findings=[],
        partial_findings=[],
        priority_order=["CVE-2021-44228"],
    )


@pytest.fixture
def metadata_ground_truth() -> GroundTruth:
    """Ground truth with full risk metadata on one finding."""
    return GroundTruth(
        exploitable_findings=[
            FindingDetail(
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
            ),
        ],
        non_exploitable_findings=[
            FindingDetail(
                cve="CVE-2023-50447",
                verdict="not_exploitable",
                reasoning="Dead code",
                action="Defer",
            ),
        ],
        partial_findings=[],
        priority_order=["CVE-2021-44228", "CVE-2023-50447"],
    )


@pytest.fixture
def partial_metadata_ground_truth() -> GroundTruth:
    """Ground truth with partial risk metadata (CVSS + KEV only)."""
    return GroundTruth(
        exploitable_findings=[
            FindingDetail(
                cve="CVE-2021-44228",
                verdict="exploitable",
                reasoning="Reachable",
                action="Patch",
                cvss_score=9.8,
                cisa_kev=True,
            ),
        ],
        non_exploitable_findings=[],
        partial_findings=[],
        priority_order=["CVE-2021-44228"],
    )


# ---------------------------------------------------------------------------
# Tests - _render_risk_metadata
# ---------------------------------------------------------------------------


class TestRenderRiskMetadata:
    """Verify _render_risk_metadata behavior."""

    def test_none_ground_truth_returns_empty(self) -> None:
        """None ground truth returns empty string."""
        assert _render_risk_metadata(None) == ""

    def test_no_metadata_returns_empty(self, empty_ground_truth: GroundTruth) -> None:
        """Ground truth without metadata returns empty string."""
        result = _render_risk_metadata(empty_ground_truth)
        assert result == ""

    def test_full_metadata_includes_all_fields(self, metadata_ground_truth: GroundTruth) -> None:
        """Full metadata renders all fields."""
        result = _render_risk_metadata(metadata_ground_truth)
        assert "## Risk Metadata" in result
        assert "CVE-2021-44228" in result
        assert "CVSS: 9.8" in result
        assert "EPSS: 97.50%" in result
        assert "CISA KEV: YES" in result
        assert "Exploit Maturity: active" in result
        assert "Fixed Version: 2.17.1" in result
        assert "Package: /usr/lib/log4j-core-2.14.1.jar" in result
        assert "Exposure: network" in result
        assert "Criticality: critical" in result
        assert "Internet-Facing: YES" in result

    def test_metadata_only_for_findings_that_have_it(
        self, metadata_ground_truth: GroundTruth
    ) -> None:
        """Findings without metadata are not rendered."""
        result = _render_risk_metadata(metadata_ground_truth)
        # CVE-2023-50447 has no metadata, should not appear
        assert "CVE-2023-50447" not in result

    def test_partial_metadata_renders_only_present_fields(
        self, partial_metadata_ground_truth: GroundTruth
    ) -> None:
        """Only the fields that are set are rendered."""
        result = _render_risk_metadata(partial_metadata_ground_truth)
        assert "## Risk Metadata" in result
        assert "CVSS: 9.8" in result
        assert "CISA KEV: YES" in result
        # Fields not set should not appear
        assert "EPSS:" not in result
        assert "Exploit Maturity:" not in result
        assert "Fixed Version:" not in result
        assert "Package:" not in result
        assert "Exposure:" not in result
        assert "Criticality:" not in result
        assert "Internet-Facing:" not in result

    def test_cisa_kev_false_is_rendered(self) -> None:
        """CISA KEV: False is explicitly rendered."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2024-21626",
                    verdict="partial",
                    reasoning="Test",
                    action="Test",
                    cisa_kev=False,
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2024-21626"],
        )
        result = _render_risk_metadata(gt)
        assert "CISA KEV: NO" in result

    def test_internet_facing_false_is_rendered(self) -> None:
        """Internet-Facing: False is explicitly rendered."""
        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2024-21626",
                    verdict="partial",
                    reasoning="Test",
                    action="Test",
                    internet_facing=False,
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2024-21626"],
        )
        result = _render_risk_metadata(gt)
        assert "Internet-Facing: NO" in result


# ---------------------------------------------------------------------------
# Tests - build_user_prompt with ground_truth
# ---------------------------------------------------------------------------


class TestBuildUserPromptWithMetadata:
    """Verify build_user_prompt includes risk metadata when available."""

    def test_without_ground_truth_no_metadata_section(
        self,
    ) -> None:
        """No risk metadata section when ground_truth is None."""
        prompt = build_user_prompt(
            "trivy_triage",
            "Scan output here",
            "Stack context here",
        )
        assert "## Risk Metadata" not in prompt
        assert "Analyze the findings above" in prompt

    def test_with_metadata_section_included(self, metadata_ground_truth: GroundTruth) -> None:
        """Risk metadata section is included when ground_truth has metadata."""
        prompt = build_user_prompt(
            "trivy_triage",
            "Scan output here",
            "Stack context here",
            ground_truth=metadata_ground_truth,
        )
        assert "## Risk Metadata" in prompt
        assert "CVSS: 9.8" in prompt
        assert "CISA KEV: YES" in prompt

    def test_without_metadata_no_section(self, empty_ground_truth: GroundTruth) -> None:
        """No risk metadata section when ground_truth has no metadata."""
        prompt = build_user_prompt(
            "trivy_triage",
            "Scan output here",
            "Stack context here",
            ground_truth=empty_ground_truth,
        )
        assert "## Risk Metadata" not in prompt
        assert "Analyze the findings above" in prompt


# ---------------------------------------------------------------------------
# Tests - scoring does not crash when metadata is absent
# ---------------------------------------------------------------------------


class TestGraderWithMetadataAbsent:
    """Verify the grader does not crash when findings lack risk metadata."""

    def test_json_validator_handles_missing_metadata(
        self,
    ) -> None:
        """JsonValidator handles findings with no metadata gracefully."""
        from evalsec.grader import JsonValidator
        from evalsec.tasks.base import FindingDetail

        gt = GroundTruth(
            exploitable_findings=[
                FindingDetail(
                    cve="CVE-2021-44228",
                    verdict="exploitable",
                    reasoning="Test",
                    action="Patch",
                ),
            ],
            non_exploitable_findings=[],
            partial_findings=[],
            priority_order=["CVE-2021-44228"],
        )

        valid_json = """{
            "analysis": [
                {
                    "cve": "CVE-2021-44228",
                    "verdict": "exploitable",
                    "priority": "P0",
                    "reasoning": "It is reachable",
                    "action": "Patch now",
                    "timeline": "72 hours"
                }
            ]
        }"""

        result = JsonValidator.validate(
            valid_json,
            gt,
            ["CVE-2021-44228"],
        )
        # Should not crash and should produce valid scores
        assert result.format_score >= 0
        assert result.verdict_score >= 0
