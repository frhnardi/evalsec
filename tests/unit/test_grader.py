"""Unit tests for the enhanced grader — JsonValidator, scoring, and grading pipeline."""

from __future__ import annotations

import json

import pytest

from evalsec.grader import (
    COVERAGE_WEIGHT,
    FORMAT_WEIGHT,
    HALLUCINATION_PENALTY_MAX,
    PRIORITY_WEIGHT,
    REGEX_WEIGHT,
    VALID_PRIORITIES,
    VALID_TIMELINES,
    VALID_VERDICTS,
    VERDICT_WEIGHT,
    JsonValidationResult,
    JsonValidator,
    RegexGrader,
    Score,
)
from evalsec.tasks.base import FindingDetail, GroundTruth

# ---------------------------------------------------------------------------
# Fixtures — shared test data
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_ground_truth() -> GroundTruth:
    """Ground truth with 3 findings: 1 exploitable, 1 partial, 1 non-exploitable."""
    return GroundTruth(
        exploitable_findings=[
            FindingDetail(
                cve="CVE-2021-44228",
                verdict="exploitable",
                reasoning="Log4Shell, reachable from HTTP handlers",
                action="Patch to 2.17.1",
            ),
        ],
        partial_findings=[
            FindingDetail(
                cve="CVE-2024-21626",
                verdict="partial",
                reasoning="Container escape mitigated by RO root",
                action="Patch runc in next sprint",
            ),
        ],
        non_exploitable_findings=[
            FindingDetail(
                cve="CVE-2023-50447",
                verdict="not_exploitable",
                reasoning="Pillow eval() never called",
                action="Defer to next quarter",
            ),
        ],
        priority_order=[
            "CVE-2021-44228",
            "CVE-2024-21626",
            "CVE-2023-50447",
        ],
    )


@pytest.fixture
def perfect_json_response() -> str:
    """A VEX model response that perfectly matches ground truth.

    VEX status mappings:
      - status="affected" → verdict "exploitable"
      - status="under_investigation" → verdict "partial"
      - status="not_affected" → verdict "not_exploitable"
    """
    return json.dumps(
        {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-2021-44228"},
                    "status": "affected",
                    "justification": "code_not_reachable",
                    "impact_statement": "Log4Shell reachable from HTTP",
                    "action_statement": "Patch to 2.17.1 within 72 hours",
                    "priority": "P0",
                    "timeline": "72 hours",
                },
                {
                    "vulnerability": {"id": "CVE-2024-21626"},
                    "status": "under_investigation",
                    "justification": "protected_by_compensating_control",
                    "impact_statement": "Container escape but RO root mitigates",
                    "action_statement": "Patch runc this sprint",
                    "priority": "P1",
                    "timeline": "this sprint",
                },
                {
                    "vulnerability": {"id": "CVE-2023-50447"},
                    "status": "not_affected",
                    "justification": "code_not_reachable",
                    "impact_statement": "Pillow eval() is dead code",
                    "action_statement": "Defer to next quarter",
                    "priority": "P3",
                    "timeline": "next quarter",
                },
            ],
        }
    )


@pytest.fixture
def hallucinated_json_response() -> str:
    """A VEX response with an extra CVE not in ground truth."""
    data = {
        "document": {
            "type": "vex",
            "author": "evalsec-benchmark",
        },
        "statements": [
            {
                "vulnerability": {"id": "CVE-2021-44228"},
                "status": "affected",
                "justification": "code_not_reachable",
                "impact_statement": "Log4Shell",
                "action_statement": "Patch now",
                "priority": "P0",
                "timeline": "72 hours",
            },
            {
                "vulnerability": {"id": "CVE-9999-99999"},  # Hallucinated!
                "status": "affected",
                "justification": "code_not_reachable",
                "impact_statement": "Made up CVE",
                "action_statement": "Patch",
                "priority": "P2",
                "timeline": "this sprint",
            },
        ],
    }
    return json.dumps(data)


@pytest.fixture
def wrong_verdict_json_response() -> str:
    """A VEX response with wrong status values for some CVEs.

    CVE-2021-44228: status="not_affected" → verdict "not_exploitable" (WRONG, should be exploitable)
    CVE-2024-21626: status="affected" → verdict "exploitable" (WRONG, should be partial)
    """
    return json.dumps(
        {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-2021-44228"},
                    "status": "not_affected",  # WRONG! Should be affected (→ exploitable)
                    "justification": "code_not_reachable",
                    "impact_statement": "Wrong reasoning",
                    "action_statement": "Patch",
                    "priority": "P0",
                    "timeline": "72 hours",
                },
                {
                    "vulnerability": {"id": "CVE-2024-21626"},
                    "status": "affected",  # WRONG! Should be under_investigation (→ partial)
                    "justification": "code_not_reachable",
                    "impact_statement": "Wrong reasoning",
                    "action_statement": "Patch",
                    "priority": "P1",
                    "timeline": "this sprint",
                },
            ],
        }
    )


@pytest.fixture
def invalid_json_response() -> str:
    """Completely invalid JSON."""
    return "This is not JSON at all"


@pytest.fixture
def markdown_fenced_response(perfect_json_response: str) -> str:
    """A valid VEX JSON response wrapped in markdown code fences."""
    return f"```json\n{perfect_json_response}\n```"


# ---------------------------------------------------------------------------
# Tests: JsonValidator._extract_json
# ---------------------------------------------------------------------------


class TestExtractJson:
    """Tests for the _extract_json static method."""

    def test_plain_json(self, perfect_json_response: str) -> None:
        """Plain JSON without fences is returned as-is."""
        result = JsonValidator._extract_json(perfect_json_response)
        parsed = json.loads(result)
        assert "document" in parsed

    def test_markdown_fenced(self, markdown_fenced_response: str) -> None:
        """Markdown fences are stripped, including the json language tag."""
        result = JsonValidator._extract_json(markdown_fenced_response)
        parsed = json.loads(result)
        assert "document" in parsed
        assert len(parsed["statements"]) == 3

    def test_markdown_no_lang_tag(self) -> None:
        """Fences without language tag are still stripped."""
        text = '```\n{"document": {"type": "vex"}, "statements": []}\n```'
        result = JsonValidator._extract_json(text)
        parsed = json.loads(result)
        assert parsed == {"document": {"type": "vex"}, "statements": []}

    def test_markdown_uppercase_json(self) -> None:
        """Uppercase JSON language tag is handled."""
        text = '```JSON\n{"document": {"type": "vex"}, "statements": []}\n```'
        result = JsonValidator._extract_json(text)
        parsed = json.loads(result)
        assert parsed == {"document": {"type": "vex"}, "statements": []}

    def test_no_closing_fence(self) -> None:
        """Missing closing fence — extracts everything after opening fence."""
        text = '```json\n{"document": {"type": "vex"}, "statements": []}'
        result = JsonValidator._extract_json(text)
        parsed = json.loads(result)
        assert parsed == {"document": {"type": "vex"}, "statements": []}


# ---------------------------------------------------------------------------
# Tests: JsonValidator.validate — format validation
# ---------------------------------------------------------------------------


class TestJsonValidatorFormat:
    """Tests for JSON format validation."""

    def test_valid_json_perfect(
        self,
        perfect_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Perfect VEX JSON response gets 100% format score."""
        result = JsonValidator.validate(
            response_text=perfect_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.format_score == 100.0
        assert result.parse_error is None

    def test_invalid_json(
        self,
        invalid_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Invalid JSON gets 0% format score."""
        result = JsonValidator.validate(
            response_text=invalid_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.format_score == 0.0
        assert result.parse_error is not None
        assert "Invalid JSON" in result.parse_error

    def test_missing_document_key(
        self,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Missing 'document' key gets 0% format."""
        text = json.dumps({"some_other_key": True})
        result = JsonValidator.validate(
            response_text=text,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.format_score == 0.0
        assert "Missing 'document' key" in (result.parse_error or "")

    def test_missing_required_fields(
        self,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Missing required fields in VEX statements gets partial score."""
        data = {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-2021-44228"},
                    "status": "affected",
                    # missing priority, impact_statement, action_statement, timeline
                }
            ],
        }
        text = json.dumps(data)
        result = JsonValidator.validate(
            response_text=text,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.format_score == 0.0  # item has missing required fields

    def test_invalid_vex_status(
        self,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Invalid VEX status value gets partial format score."""
        data = {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-2021-44228"},
                    "status": "maybe_exploitable",  # invalid VEX status
                    "priority": "P0",
                    "impact_statement": "test",
                    "action_statement": "test",
                    "timeline": "72 hours",
                }
            ],
        }
        text = json.dumps(data)
        result = JsonValidator.validate(
            response_text=text,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.format_score == 50.0  # partial credit for having the right structure

    def test_invalid_priority(
        self,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Invalid priority value gets partial format score."""
        data = {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-2021-44228"},
                    "status": "affected",
                    "priority": "P5",  # invalid
                    "impact_statement": "test",
                    "action_statement": "test",
                    "timeline": "72 hours",
                }
            ],
        }
        text = json.dumps(data)
        result = JsonValidator.validate(
            response_text=text,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.format_score == 50.0

    def test_markdown_fenced_valid(
        self,
        markdown_fenced_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Valid VEX JSON wrapped in markdown fences is still validated."""
        result = JsonValidator.validate(
            response_text=markdown_fenced_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.format_score == 100.0
        assert result.parse_error is None


# ---------------------------------------------------------------------------
# Tests: JsonValidator.validate — CVE coverage
# ---------------------------------------------------------------------------


class TestJsonValidatorCoverage:
    """Tests for CVE coverage scoring."""

    def test_full_coverage(
        self,
        perfect_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """All ground-truth CVEs are addressed."""
        result = JsonValidator.validate(
            response_text=perfect_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.coverage_score == 100.0
        assert result.missing_cves == []

    def test_partial_coverage(
        self,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Only 1 of 3 CVEs addressed."""
        data = {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-2021-44228"},
                    "status": "affected",
                    "impact_statement": "test",
                    "action_statement": "test",
                    "priority": "P0",
                    "timeline": "72 hours",
                }
            ],
        }
        text = json.dumps(data)
        result = JsonValidator.validate(
            response_text=text,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.coverage_score == pytest.approx(33.3, rel=1.0)
        assert len(result.missing_cves) == 2

    def test_no_coverage(
        self,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """No ground-truth CVEs addressed."""
        data = {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-9999-99999"},
                    "status": "affected",
                    "impact_statement": "test",
                    "action_statement": "test",
                    "priority": "P0",
                    "timeline": "72 hours",
                }
            ],
        }
        text = json.dumps(data)
        result = JsonValidator.validate(
            response_text=text,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.coverage_score == 0.0
        assert len(result.missing_cves) == 3


# ---------------------------------------------------------------------------
# Tests: JsonValidator.validate — verdict accuracy
# ---------------------------------------------------------------------------


class TestJsonValidatorVerdict:
    """Tests for verdict accuracy scoring (via VEX status mapping)."""

    def test_all_verdicts_correct(
        self,
        perfect_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """All verdicts match ground truth (correct VEX status mapping)."""
        result = JsonValidator.validate(
            response_text=perfect_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.verdict_score == 100.0
        assert result.verdict_mismatches == []

    def test_all_verdicts_wrong(
        self,
        wrong_verdict_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """All verdicts are wrong (wrong VEX status mapping)."""
        result = JsonValidator.validate(
            response_text=wrong_verdict_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.verdict_score == 0.0
        assert len(result.verdict_mismatches) == 2


# ---------------------------------------------------------------------------
# Tests: JsonValidator.validate — hallucination detection
# ---------------------------------------------------------------------------


class TestJsonValidatorHallucination:
    """Tests for hallucination detection."""

    def test_no_hallucinations(
        self,
        perfect_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """No hallucinated CVEs."""
        result = JsonValidator.validate(
            response_text=perfect_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.hallucinated_cves == []
        assert result.hallucination_penalty == 0.0

    def test_hallucinated_cve(
        self,
        hallucinated_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Hallucinated CVE is detected and penalty applied."""
        result = JsonValidator.validate(
            response_text=hallucinated_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert "CVE-9999-99999" in result.hallucinated_cves
        assert result.hallucination_penalty > 0.0

    def test_only_hallucinated(
        self,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Only hallucinated CVEs, no real ones."""
        data = {
            "document": {
                "type": "vex",
                "author": "evalsec-benchmark",
            },
            "statements": [
                {
                    "vulnerability": {"id": "CVE-9999-99999"},
                    "status": "affected",
                    "impact_statement": "fake",
                    "action_statement": "fake",
                    "priority": "P0",
                    "timeline": "72 hours",
                }
            ],
        }
        text = json.dumps(data)
        result = JsonValidator.validate(
            response_text=text,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        # 1 hallucinated vs 3 real = ratio 0.33
        assert len(result.hallucinated_cves) == 1
        expected_penalty = round(HALLUCINATION_PENALTY_MAX * (1 / 3), 1)
        assert result.hallucination_penalty == expected_penalty


# ---------------------------------------------------------------------------
# Tests: JsonValidator.validate — priority accuracy
# ---------------------------------------------------------------------------


class TestJsonValidatorPriority:
    """Tests for priority accuracy scoring."""

    def test_all_priorities_correct(
        self,
        perfect_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """All priorities match expected ordering."""
        result = JsonValidator.validate(
            response_text=perfect_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=[],
        )
        assert result.priority_score == 100.0
        assert result.priority_mismatches == []


# ---------------------------------------------------------------------------
# Tests: JsonValidator.validate — regex score passthrough
# ---------------------------------------------------------------------------


class TestJsonValidatorRegex:
    """Tests that regex score is properly computed alongside validation."""

    def test_regex_score_computed(
        self,
        perfect_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Regex score is computed even for perfect JSON."""
        patterns = ["(?i)log4shell", "(?i)reachable"]
        result = JsonValidator.validate(
            response_text=perfect_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=patterns,
        )
        # The response text contains "Log4Shell" and "Log4Shell reachable"
        assert result.regex_score > 0

    def test_regex_score_with_invalid_json(
        self,
        invalid_json_response: str,
        sample_ground_truth: GroundTruth,
    ) -> None:
        """Regex score is still computed even when JSON is invalid."""
        patterns = ["(?i)JSON", "(?i)at all"]
        result = JsonValidator.validate(
            response_text=invalid_json_response,
            ground_truth=sample_ground_truth,
            regex_patterns=patterns,
        )
        assert result.format_score == 0.0
        assert result.regex_score == 100.0  # both patterns match "This is not JSON at all"


# ---------------------------------------------------------------------------
# Tests: Score model with new fields
# ---------------------------------------------------------------------------


class TestScoreModel:
    """Tests for the updated Score model with new granular fields."""

    def test_all_new_fields_default_to_zero(self) -> None:
        """New granular fields default to 0.0 when not provided."""
        score = Score(
            total=85.0,
            pass1_score=17.0,
            pass2_score=68.0,
        )
        assert score.format_score == 0.0
        assert score.coverage_score == 0.0
        assert score.verdict_score == 0.0
        assert score.priority_score == 0.0
        assert score.regex_score == 0.0
        assert score.judge_score == 0.0
        assert score.hallucination_penalty == 0.0
        assert score.deterministic_total == 0.0
        assert score.model_type == "llm"

    def test_new_fields_can_be_set(self) -> None:
        """All new fields can be explicitly set."""
        score = Score(
            total=90.0,
            pass1_score=18.0,
            pass2_score=72.0,
            format_score=100.0,
            coverage_score=100.0,
            verdict_score=66.7,
            priority_score=100.0,
            regex_score=80.0,
            judge_score=90.0,
            hallucination_penalty=5.0,
            deterministic_total=85.0,
            model_type="baseline",
        )
        assert score.format_score == 100.0
        assert score.coverage_score == 100.0
        assert score.verdict_score == 66.7
        assert score.priority_score == 100.0
        assert score.regex_score == 80.0
        assert score.judge_score == 90.0
        assert score.hallucination_penalty == 5.0
        assert score.deterministic_total == 85.0
        assert score.model_type == "baseline"

    def test_strict_mode_rejects_extra(self) -> None:
        """Score still rejects unknown fields (extra='forbid' at runtime)."""
        with pytest.raises((ValueError, TypeError)):
            Score.model_validate(
                {
                    "total": 50.0,
                    "pass1_score": 10.0,
                    "pass2_score": 40.0,
                    "unknown_field": True,
                }
            )

    def test_json_serialization_includes_new_fields(self) -> None:
        """New fields appear in JSON serialization."""
        score = Score(
            total=90.0,
            pass1_score=18.0,
            pass2_score=72.0,
            format_score=100.0,
            coverage_score=100.0,
            deterministic_total=85.0,
            model_type="baseline",
        )
        data = json.loads(score.model_dump_json())
        assert data["format_score"] == 100.0
        assert data["coverage_score"] == 100.0
        assert data["hallucination_penalty"] == 0.0
        assert data["deterministic_total"] == 85.0
        assert data["model_type"] == "baseline"


# ---------------------------------------------------------------------------
# Tests: Valid value constants
# ---------------------------------------------------------------------------


class TestValidValues:
    """Tests for the valid value constants."""

    def test_valid_verdicts(self) -> None:
        assert "exploitable" in VALID_VERDICTS
        assert "not_exploitable" in VALID_VERDICTS
        assert "partial" in VALID_VERDICTS
        assert len(VALID_VERDICTS) == 3

    def test_valid_priorities(self) -> None:
        assert "P0" in VALID_PRIORITIES
        assert "P1" in VALID_PRIORITIES
        assert "P2" in VALID_PRIORITIES
        assert "P3" in VALID_PRIORITIES
        assert len(VALID_PRIORITIES) == 4

    def test_valid_timelines(self) -> None:
        assert "72 hours" in VALID_TIMELINES
        assert "this sprint" in VALID_TIMELINES
        assert "next quarter" in VALID_TIMELINES
        assert len(VALID_TIMELINES) == 3

    def test_weight_constants_sum_to_one(self) -> None:
        """The pass 1 sub-weights should sum to 1.0."""
        total = FORMAT_WEIGHT + COVERAGE_WEIGHT + VERDICT_WEIGHT + PRIORITY_WEIGHT + REGEX_WEIGHT
        assert total == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# Tests: JsonValidationResult dataclass
# ---------------------------------------------------------------------------


class TestJsonValidationResult:
    """Tests for the JsonValidationResult dataclass."""

    def test_default_values(self) -> None:
        """New instance has sensible defaults."""
        result = JsonValidationResult()
        assert result.format_score == 0.0
        assert result.parsed_cves == []
        assert result.parse_error is None

    def test_with_parse_error(self) -> None:
        """Parse error sets format_score to 0."""
        result = JsonValidationResult(
            format_score=0.0,
            regex_score=50.0,
            parse_error="Invalid JSON: test",
        )
        assert result.format_score == 0.0
        assert result.regex_score == 50.0
        assert result.parse_error == "Invalid JSON: test"


# ---------------------------------------------------------------------------
# Tests: RegexGrader passthrough via JsonValidator
# ---------------------------------------------------------------------------


class TestRegexGrader:
    """Tests for RegexGrader used within the validation pipeline."""

    def test_empty_patterns(self) -> None:
        """Empty patterns list returns 100."""
        score = RegexGrader.grade("any text", [])
        assert score == 100.0

    def test_all_match(self) -> None:
        """All patterns match."""
        score = RegexGrader.grade("hello world", ["hello", "world"])
        assert score == 100.0

    def test_partial_match(self) -> None:
        """Some patterns match."""
        score = RegexGrader.grade("hello world", ["hello", "world", "missing"])
        assert score == pytest.approx(66.67, rel=1.0)

    def test_no_match(self) -> None:
        """No patterns match."""
        score = RegexGrader.grade("hello world", ["goodbye", "universe"])
        assert score == 0.0

    def test_broken_pattern(self) -> None:
        """Broken regex patterns don't crash."""
        score = RegexGrader.grade("hello", ["hello", r"[invalid"])
        assert score == 50.0  # one matches, one broken (counts as non-match)

    def test_case_insensitive_flag_respected(self) -> None:
        """Embedded (?i) flag works."""
        score = RegexGrader.grade("HELLO WORLD", ["(?i)hello"])
        assert score == 100.0
