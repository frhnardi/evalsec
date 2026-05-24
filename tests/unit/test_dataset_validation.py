"""Dataset validation: load and validate all YAML test cases.

This module verifies that every YAML file in the test data directories:
- Parses as valid YAML.
- Validates against the TaskCase Pydantic model.
- Has internally consistent cross-field references.
- Meets minimum quality standards (ground truth, rubric, etc.).

This is the dataset-equivalent of a schema migration check:
if this test fails, new dataset files have structural problems.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from evalsec.tasks.base import FindingDetail, TaskCase

# All task data directories: add new tasks here
TEST_DATA_DIRS: list[Path] = [
    Path(__file__).parent.parent / "data" / "trivy_triage",
    Path(__file__).parent.parent / "data" / "codeql_triage",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover_yaml_files() -> list[Path]:
    """Return sorted list of all YAML files across all task data directories."""
    files: list[Path] = []
    for data_dir in TEST_DATA_DIRS:
        if not data_dir.exists():
            pytest.fail(f"Test data directory not found: {data_dir}")
        dir_files = sorted(data_dir.glob("*.yaml"))
        if not dir_files:
            pytest.fail(f"No YAML files found in {data_dir}")
        files.extend(dir_files)
    return files


def _collect_all_findings(case: TaskCase) -> dict[str, FindingDetail]:
    """Build a CVE-to-FindingDetail lookup from all finding categories."""
    findings: dict[str, FindingDetail] = {}
    for finding in case.ground_truth.exploitable_findings:
        findings[finding.cve] = finding
    for finding in case.ground_truth.non_exploitable_findings:
        findings[finding.cve] = finding
    for finding in case.ground_truth.partial_findings:
        findings[finding.cve] = finding
    return findings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def all_yaml_files() -> list[Path]:
    """Discover all YAML files once per test session."""
    return _discover_yaml_files()


@pytest.fixture(scope="session")
def all_cases(all_yaml_files: list[Path]) -> list[tuple[str, TaskCase]]:
    """Load and parse all YAML files into TaskCase instances."""
    cases: list[tuple[str, TaskCase]] = []
    errors: list[str] = []

    for yaml_path in all_yaml_files:
        try:
            with open(yaml_path) as f:
                raw = yaml.safe_load(f)
            if raw is None:
                errors.append(f"{yaml_path.name}: empty YAML file")
                continue
            case = TaskCase.model_validate(raw)
            case_id = getattr(case, "id", yaml_path.stem)
            cases.append((case_id, case))
        except Exception as exc:
            errors.append(f"{yaml_path.name}: {exc}")

    if errors:
        pytest.fail(f"{len(errors)} file(s) failed to load:\n" + "\n".join(errors))

    return cases


# ---------------------------------------------------------------------------
# Tests: loading
# ---------------------------------------------------------------------------


class TestDatasetLoading:
    """Verify all YAML files parse and validate against TaskCase."""

    def test_at_least_one_case(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """There should be at least 1 test case (minimum viable)."""
        assert len(all_cases) >= 1, f"Found {len(all_cases)} case(s); expected at least 1"

    def test_all_files_discovered(self, all_yaml_files: list[Path]) -> None:
        """At least one YAML file should exist in the data directory."""
        assert len(all_yaml_files) >= 1

    def test_all_case_ids_are_unique(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """No two cases should share the same ID."""
        ids = [cid for cid, _ in all_cases]
        duplicates = {cid for cid in ids if ids.count(cid) > 1}
        assert not duplicates, f"Duplicate case IDs: {duplicates}"

    def test_all_case_ids_match_filename(self, all_yaml_files: list[Path]) -> None:
        """Case ID numeric suffix should appear in the YAML filename."""
        for yaml_path in all_yaml_files:
            stem = yaml_path.stem  # e.g. "001_log4shell_reachable"
            with open(yaml_path) as f:
                raw = yaml.safe_load(f)
            if raw is None:
                continue
            case_id: str = raw.get("id", "")
            id_suffix = case_id.split("_")[-1]  # e.g. "001"
            assert id_suffix in stem, (
                f"Case id '{case_id}' doesn't match filename '{stem}' "
                f"(expected '{id_suffix}' in filename)"
            )


# ---------------------------------------------------------------------------
# Tests: cross-field integrity
# ---------------------------------------------------------------------------


class TestCrossFieldIntegrity:
    """Verify internal consistency across fields within each case."""

    def test_priority_order_cves_exist_in_findings(
        self, all_cases: list[tuple[str, TaskCase]]
    ) -> None:
        """Every CVE in priority_order must appear in one of the finding lists."""
        for case_id, case in all_cases:
            findings = _collect_all_findings(case)
            missing = [cve for cve in case.ground_truth.priority_order if cve not in findings]
            assert not missing, (
                f"{case_id}: CVEs in priority_order not found in any finding list: {missing}"
            )

    def test_every_finding_has_non_empty_reasoning(
        self, all_cases: list[tuple[str, TaskCase]]
    ) -> None:
        """Every finding detail must have non-empty reasoning."""
        for case_id, case in all_cases:
            findings = _collect_all_findings(case)
            empty = [
                cve for cve, f in findings.items() if not f.reasoning or not f.reasoning.strip()
            ]
            assert not empty, f"{case_id}: findings with empty reasoning: {empty}"

    def test_exploitable_findings_have_action(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """Exploitable findings should have a non-empty action field."""
        for case_id, case in all_cases:
            no_action = [
                f.cve
                for f in case.ground_truth.exploitable_findings
                if not f.action or not f.action.strip()
            ]
            assert not no_action, f"{case_id}: exploitable findings missing action: {no_action}"

    def test_rubric_scores_sum_to_100(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """All four rubric dimensions should sum to exactly 100."""
        for case_id, case in all_cases:
            total = (
                case.rubric.reachability_reasoning.max_score
                + case.rubric.prioritization.max_score
                + case.rubric.actionability.max_score
                + case.rubric.conciseness.max_score
            )
            assert total == 100, f"{case_id}: rubric scores sum to {total}, expected 100"

    def test_each_finding_in_one_category_only(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """A CVE should not appear in multiple finding categories."""
        for case_id, case in all_cases:
            gt = case.ground_truth
            exploitable_set = {f.cve for f in gt.exploitable_findings}
            non_exploitable_set = {f.cve for f in gt.non_exploitable_findings}
            partial_set = {f.cve for f in gt.partial_findings}

            duplicates = (
                exploitable_set & non_exploitable_set
                | exploitable_set & partial_set
                | non_exploitable_set & partial_set
            )
            assert not duplicates, f"{case_id}: CVEs appear in multiple categories: {duplicates}"

    def test_expected_response_includes_non_empty(
        self, all_cases: list[tuple[str, TaskCase]]
    ) -> None:
        """Every case must have at least one expected_response_include pattern."""
        for case_id, case in all_cases:
            assert len(case.expected_response_includes) > 0, (
                f"{case_id}: expected_response_includes is empty"
            )

    def test_source_has_valid_type(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """Every case must have a recognised source type."""
        valid_types = {
            "self_scan",
            "github_issue",
            "advisory",
            "synthetic",
            "ai_assisted_deepseek_v4",
            "human_verified",
        }
        for case_id, case in all_cases:
            assert case.source.type in valid_types, (
                f"{case_id}: source.type '{case.source.type}' not in valid types {valid_types}"
            )

    def test_priority_order_non_empty(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """Every case with exploitable or partial findings should have priority_order entries.

        Only non_exploitable findings with empty priority_order is valid when all
        exploitable/partial entries were hallucinated GT-only CVEs removed.
        """
        for case_id, case in all_cases:
            gt = case.ground_truth
            has_exploitable_or_partial = bool(gt.exploitable_findings or gt.partial_findings)
            if has_exploitable_or_partial:
                assert len(case.ground_truth.priority_order) > 0, (
                    f"{case_id}: {len(gt.exploitable_findings)} exploitable + "
                    f"{len(gt.partial_findings)} partial findings but empty priority_order"
                )

    def test_all_verdicts_are_valid(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """All finding verdicts must be valid enum values."""
        valid_verdicts = {"exploitable", "not_exploitable", "partial"}
        for case_id, case in all_cases:
            findings = _collect_all_findings(case)
            invalid = [
                f"{cve}: '{f.verdict}'"
                for cve, f in findings.items()
                if f.verdict not in valid_verdicts
            ]
            assert not invalid, f"{case_id}: invalid verdicts: {invalid}"

    def test_at_least_one_finding(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """Every case should have at least one finding across all categories."""
        for case_id, case in all_cases:
            findings = _collect_all_findings(case)
            assert len(findings) >= 1, f"{case_id}: no findings in any category"


# ---------------------------------------------------------------------------
# Tests: ground truth integrity (no hallucinated CVEs)
# ---------------------------------------------------------------------------


class TestGroundTruthIntegrity:
    """Verify ground truth CVEs are present in the scan input."""

    CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
    GHSA_RE = re.compile(r"(GHSA-\w+-\w+-\w+)", re.IGNORECASE)

    @staticmethod
    def _is_cve_or_ghsa(identifier: str) -> bool:
        """Check if an identifier is a CVE or GHSA (not a CodeQL rule ID or NONE)."""
        if identifier == "NONE":
            return False
        return bool(re.match(r"^(CVE-\d{4}-\d{4,7}|GHSA-[\w-]+)$", identifier, re.IGNORECASE))

    def test_no_gt_only_cves(self, all_yaml_files: list[Path]) -> None:
        """Every CVE/GHSA in ground_truth must also appear in the scan input text.

        CVEs in ground_truth that are NOT in the scan input are "hallucinated" —
        the model cannot see them in the scan, so it will never mention them,
        resulting in unfair coverage penalties during grading.

        Notes:
        - "NONE" is a special marker for clean-scan cases (ignored).
        - CodeQL rule IDs (e.g. PY/SQL-INJECTION) are not CVE/GHSA format and
          are only checked in codeql_triage files, not by this test.
        """
        errors: list[str] = []
        for yaml_path in all_yaml_files:
            with open(yaml_path) as f:
                raw = yaml.safe_load(f)
            if raw is None:
                continue

            input_text: str = raw.get("input", "")
            gt = raw.get("ground_truth")
            if gt is None:
                continue

            # Extract all CVE/GHSA identifiers from the scan input
            input_cves: set[str] = set()
            for m in self.CVE_RE.finditer(input_text):
                input_cves.add(m.group(1).upper())
            for m in self.GHSA_RE.finditer(input_text):
                input_cves.add(m.group(1).upper())

            # Collect CVE/GHSA identifiers from ground_truth (skip NONE and CodeQL rule IDs)
            gt_cves: set[str] = set()
            for category in (
                "exploitable_findings",
                "non_exploitable_findings",
                "partial_findings",
            ):
                for finding in gt.get(category, []):
                    cve = finding.get("cve", "").upper().strip()
                    if self._is_cve_or_ghsa(cve):
                        gt_cves.add(cve)

            # Find GT-only CVEs (in ground_truth but NOT in scan input)
            gt_only = sorted(gt_cves - input_cves)
            if gt_only:
                errors.append(f"{yaml_path.name}: GT-only CVEs not in scan input: {gt_only}")

        assert not errors, (
            "One or more test cases have CVEs in ground_truth that don't appear "
            "in the scan input text. These cause unfair coverage penalties.\n" + "\n".join(errors)
        )


# ---------------------------------------------------------------------------
# Tests: runner compatibility
# ---------------------------------------------------------------------------


class TestRunnerCompatibility:
    """Verify cases can be loaded the same way Runner._load_cases does."""

    def test_roundtrip_through_runner_logic(self) -> None:
        """Replicate Runner._load_cases processing exactly."""
        yaml_files = _discover_yaml_files()
        assert len(yaml_files) >= 1

        cases: list[TaskCase] = []
        for path in yaml_files:
            with open(path) as f:
                data = yaml.safe_load(f)
            case = TaskCase.model_validate(data)
            cases.append(case)

        # Verify sortability (Runner sorts by weight then id)
        cases.sort(key=lambda c: c.weight, reverse=True)
        cases.sort(key=lambda c: c.id)

        assert all(isinstance(c, TaskCase) for c in cases)
        assert cases == sorted(cases, key=lambda c: c.id)

    def test_weight_in_valid_range(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """Weight must be between 0.5 and 2.0 (Pydantic validation)."""
        for case_id, case in all_cases:
            assert 0.5 <= case.weight <= 2.0, f"{case_id}: weight {case.weight} outside [0.5, 2.0]"


# ---------------------------------------------------------------------------
# Tests: case listing
# ---------------------------------------------------------------------------


class TestCaseListing:
    """Document all discovered cases."""

    def test_all_cases_loaded(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """List every discovered case ID for documentation."""
        case_ids = [cid for cid, _ in all_cases]
        assert len(case_ids) >= 1, "No cases were loaded"
        summary = ", ".join(case_ids)
        assert summary, "No case IDs found"

    def test_all_cases_have_valid_weight(self, all_cases: list[tuple[str, TaskCase]]) -> None:
        """Every case should have weight in the valid range."""
        for case_id, case in all_cases:
            assert 0.5 <= case.weight <= 2.0, f"{case_id}: weight {case.weight} out of range"
