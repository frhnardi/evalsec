"""Two-pass grader for LLM benchmark responses.

Pass 1: Deterministic regex matching against expected_response_includes.
Pass 2: LLM-as-judge (Claude Opus 4.7 via OpenRouter) scoring against rubric.

Usage:
    grader = Grader(task_name="trivy_triage")
    scores_path = await grader.grade_file("outputs/responses_20260512_020000.json")
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field
from rich.console import Console
from rich.table import Table

from evalsec.adapters import ALL_MODELS
from evalsec.adapters.base import LLMRequest
from evalsec.adapters.openai_compat import OpenAICompatAdapter
from evalsec.baselines import BASELINE_GENERATORS, grade_baselines
from evalsec.config import settings
from evalsec.tasks import (
    VEX_STATUS_TO_VERDICT,
    build_judge_prompt,
    get_prompt_version,
    get_task_config,
)
from evalsec.tasks.base import FindingDetail, GroundTruth, Rubric, RubricItem, TaskCase

logger = structlog.get_logger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Weights — can be overridden by CLI flags
# ---------------------------------------------------------------------------
PASS1_WEIGHT: float = 0.20
PASS2_WEIGHT: float = 0.80

# ---------------------------------------------------------------------------
# Valid values for model output validation
# ---------------------------------------------------------------------------
VALID_VERDICTS: frozenset[str] = frozenset({"exploitable", "not_exploitable", "partial"})
VALID_PRIORITIES: frozenset[str] = frozenset({"P0", "P1", "P2", "P3"})
VALID_TIMELINES: frozenset[str] = frozenset({"72 hours", "this sprint", "next quarter"})

# ---------------------------------------------------------------------------
# Scoring dimension weights within deterministic grading (pass 1)
# ---------------------------------------------------------------------------
FORMAT_WEIGHT: float = 0.10
COVERAGE_WEIGHT: float = 0.30
VERDICT_WEIGHT: float = 0.30
PRIORITY_WEIGHT: float = 0.20
REGEX_WEIGHT: float = 0.10
HALLUCINATION_PENALTY_MAX: float = 20.0  # max points deducted for hallucinated CVEs

# ---------------------------------------------------------------------------
# Pydantic data models (legacy exports — used by external tools)
# ---------------------------------------------------------------------------


class RubricScore(BaseModel):
    """Score for a single rubric dimension from the judge."""

    model_config = ConfigDict(strict=True, extra="forbid")

    dimension: str = Field(..., description="Rubric dimension name, e.g. reachability_reasoning")
    score: int = Field(..., description="Score awarded by the judge", ge=0)
    max_score: int = Field(..., description="Maximum possible score for this dimension", ge=1)
    reasoning: str | None = Field(default=None, description="Judge's explanation for this score")


class Score(BaseModel):
    """Composite score combining multiple grading dimensions.

    The new deterministic scoring (v2) splits the old single pass1_score into:
      - format_score:    JSON validity + schema conformance
      - coverage_score:  Fraction of ground-truth CVEs addressed
      - verdict_score:   Verdict accuracy vs ground truth
      - priority_score:  Priority accuracy vs expected ordering
      - regex_score:     Old regex pattern matching (smaller component)
      - judge_score:     LLM-as-judge (pass 2)
      - hallucination_penalty: Deduction for CVEs not in ground truth

    Backward-compatible ``pass1_score`` / ``pass2_score`` fields are retained.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    total: float = Field(
        ...,
        description="Weighted composite score, 0-100",
        ge=0.0,
        le=100.0,
    )
    pass1_score: float = Field(
        ...,
        description="Pass 1 weighted score (backward compat)",
        ge=0.0,
        le=100.0,
    )
    pass2_score: float = Field(
        ...,
        description="Pass 2 weighted score (backward compat)",
        ge=0.0,
        le=100.0,
    )

    # New granular scoring dimensions
    format_score: float = Field(
        default=0.0,
        description="JSON format validity, 0-100",
        ge=0.0,
        le=100.0,
    )
    coverage_score: float = Field(
        default=0.0,
        description="CVE coverage vs ground truth, 0-100",
        ge=0.0,
        le=100.0,
    )
    verdict_score: float = Field(
        default=0.0,
        description="Verdict accuracy vs ground truth, 0-100",
        ge=0.0,
        le=100.0,
    )
    priority_score: float = Field(
        default=0.0,
        description="Priority accuracy vs expected ordering, 0-100",
        ge=0.0,
        le=100.0,
    )
    regex_score: float = Field(
        default=0.0,
        description="Regex pattern matching score, 0-100",
        ge=0.0,
        le=100.0,
    )
    judge_score: float = Field(
        default=0.0,
        description="LLM-as-judge raw score, 0-100",
        ge=0.0,
        le=100.0,
    )
    hallucination_penalty: float = Field(
        default=0.0,
        description="Penalty for hallucinated CVEs, 0-100 (deducted from total)",
        ge=0.0,
        le=100.0,
    )

    deterministic_total: float = Field(
        default=0.0,
        description="Raw deterministic score before pass1 weighting, 0-100",
        ge=0.0,
        le=100.0,
    )
    model_type: str = Field(
        default="llm",
        description="Type of model: 'llm' or 'baseline'",
    )

    rubric_scores: list[RubricScore] = Field(
        default_factory=list,
        description="Per-dimension breakdown from the judge",
    )
    judge_error: str | None = Field(
        default=None,
        description="Error message if judge parsing failed",
    )


class GradedResponse(BaseModel):
    """A fully graded LLM response, ready for leaderboard aggregation."""

    model_config = ConfigDict(strict=True, extra="forbid")

    case_id: str = Field(..., description="Test case ID this response belongs to")
    model_id: str = Field(..., description="Model that generated the response")
    prompt_version: str = Field(..., description="Prompt version used when generating")
    response_text: str = Field(..., description="The raw LLM response text")
    score: Score = Field(..., description="The computed score")
    graded_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When grading was performed",
    )


# ---------------------------------------------------------------------------
# Pass 1 — Regex Grader
# ---------------------------------------------------------------------------


class RegexGrader:
    """Pass 1 deterministic grader.

    Scores a response based on how many expected regex patterns match.
    Each pattern is searched independently; case-insensitive flags embedded
    in the pattern (e.g. ``(?i)``) are respected.
    """

    @staticmethod
    def grade(response_text: str, patterns: list[str]) -> float:
        """Score 0-100 based on fraction of patterns that match.

        Args:
            response_text: The raw LLM output to grade.
            patterns: Regex patterns from ``TaskCase.expected_response_includes``.

        Returns:
            A float 0-100 representing the percentage of matching patterns.
        """
        if not patterns:
            return 100.0

        matches = 0
        for pattern in patterns:
            try:
                if re.search(pattern, response_text):
                    matches += 1
            except re.error as exc:
                logger.warning("regex_compile_failed", pattern=pattern, error=str(exc))
                # A broken pattern counts as a non-match but doesn't crash
                continue

        return (matches / len(patterns)) * 100.0


# ---------------------------------------------------------------------------
# JSON Validator — Pass 1.5 structural grading
# ---------------------------------------------------------------------------


class JsonValidationResult:
    """Result of validating a model's JSON output against expected schema and ground truth."""

    def __init__(
        self,
        *,
        format_score: float = 0.0,
        coverage_score: float = 0.0,
        verdict_score: float = 0.0,
        priority_score: float = 0.0,
        regex_score: float = 0.0,
        hallucination_penalty: float = 0.0,
        parsed_cves: list[dict[str, Any]] | None = None,
        ground_truth_cves: list[str] | None = None,
        missing_cves: list[str] | None = None,
        hallucinated_cves: list[str] | None = None,
        verdict_mismatches: list[dict[str, str]] | None = None,
        priority_mismatches: list[dict[str, str]] | None = None,
        parse_error: str | None = None,
    ) -> None:
        self.format_score = format_score
        self.coverage_score = coverage_score
        self.verdict_score = verdict_score
        self.priority_score = priority_score
        self.regex_score = regex_score
        self.hallucination_penalty = hallucination_penalty
        self.parsed_cves = parsed_cves or []
        self.ground_truth_cves = ground_truth_cves or []
        self.missing_cves = missing_cves or []
        self.hallucinated_cves = hallucinated_cves or []
        self.verdict_mismatches = verdict_mismatches or []
        self.priority_mismatches = priority_mismatches or []
        self.parse_error = parse_error


class JsonValidator:
    """Validates model VEX JSON output against ground truth.

    This is the structural grading pass (1.5) — evaluates:
      - JSON validity and VEX schema conformance (format_score)
      - CVE coverage vs ground truth (coverage_score)
      - Verdict accuracy via VEX status mapping (verdict_score)
      - Priority accuracy vs expected ordering (priority_score)
      - Hallucinated CVE detection (hallucination_penalty)
    """

    # Required fields per VEX statement
    _VEX_REQUIRED_FIELDS: frozenset[str] = frozenset(
        {"vulnerability", "status", "priority", "impact_statement", "action_statement", "timeline"}
    )

    @staticmethod
    def _extract_json(text: str) -> str:
        """Extract JSON object from model output, stripping markdown fences if present."""
        stripped = text.strip()

        if stripped.startswith("```"):
            end = stripped.find("```", 3)
            if end != -1:
                stripped = stripped[3:end]
            else:
                stripped = stripped[3:]
            stripped = stripped.strip()
            if stripped.startswith("json"):
                stripped = stripped[4:].strip()
            elif stripped.startswith("JSON"):
                stripped = stripped[4:].strip()

        return stripped

    @classmethod
    def validate(
        cls,
        response_text: str,
        ground_truth: GroundTruth,
        regex_patterns: list[str],
    ) -> JsonValidationResult:
        """Run all structural validations on a model response.

        Args:
            response_text: The raw LLM response text.
            ground_truth: The ``GroundTruth`` object from the test case.
            regex_patterns: ``expected_response_includes`` from the test case.

        Returns:
            A ``JsonValidationResult`` with all computed scores.
        """
        # 1. Regex score (always computed, even if JSON is invalid)
        regex_score = RegexGrader.grade(response_text, regex_patterns)

        # 2. Try to extract and parse JSON
        clean_text = cls._extract_json(response_text)

        try:
            data = json.loads(clean_text)
        except json.JSONDecodeError as exc:
            return JsonValidationResult(
                format_score=0.0,
                regex_score=regex_score,
                parse_error=f"Invalid JSON: {exc}",
            )

        # 3. Validate top-level structure (VEX format)
        if not isinstance(data, dict):
            return JsonValidationResult(
                format_score=0.0,
                regex_score=regex_score,
                parse_error=f"Expected JSON object, got {type(data).__name__}",
            )

        if "document" not in data:
            return JsonValidationResult(
                format_score=0.0,
                regex_score=regex_score,
                parse_error=f"Missing 'document' key. Keys: {list(data.keys())}",
            )

        if "statements" not in data:
            return JsonValidationResult(
                format_score=0.0,
                regex_score=regex_score,
                parse_error=f"Missing 'statements' key. Keys: {list(data.keys())}",
            )

        statements = data["statements"]
        if not isinstance(statements, list):
            return JsonValidationResult(
                format_score=30.0,
                regex_score=regex_score,
                parse_error=f"'statements' must be an array, got {type(statements).__name__}",
            )

        # 4. Validate each VEX statement against schema
        item_scores: list[float] = []
        parsed_cves: list[dict[str, Any]] = []

        # Build ground-truth lookup maps
        gt_cves: dict[str, FindingDetail] = {}
        for finding in ground_truth.exploitable_findings:
            gt_cves[finding.cve.upper()] = finding
        for finding in ground_truth.non_exploitable_findings:
            gt_cves[finding.cve.upper()] = finding
        for finding in ground_truth.partial_findings:
            gt_cves[finding.cve.upper()] = finding

        # Normalise ground-truth priority order
        gt_priority_order: list[str] = [cve.upper() for cve in ground_truth.priority_order]

        for stmt in statements:
            if not isinstance(stmt, dict):
                item_scores.append(0.0)
                continue

            missing = cls._VEX_REQUIRED_FIELDS - set(stmt.keys())
            if missing:
                item_scores.append(0.0)
                continue

            item_ok = True

            # Extract VEX fields
            vuln = stmt.get("vulnerability", {})
            cve: str = str(vuln.get("id", "")) if isinstance(vuln, dict) else ""
            status: str = str(stmt.get("status", ""))
            priority: str = str(stmt.get("priority", ""))
            impact_statement: str = str(stmt.get("impact_statement", ""))
            action_statement: str = str(stmt.get("action_statement", ""))
            timeline: str = str(stmt.get("timeline", ""))

            # Map VEX status to internal verdict
            verdict: str = VEX_STATUS_TO_VERDICT.get(status.strip().lower(), "unknown")

            # CVE must match pattern
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve, re.IGNORECASE):
                item_ok = False

            # VEX status must be valid (via VEX_STATUS_TO_VERDICT mapping)
            if verdict == "unknown":
                item_ok = False

            # Priority must be valid
            if priority not in VALID_PRIORITIES:
                item_ok = False

            # Impact and action statements must be non-empty
            if not impact_statement.strip():
                item_ok = False
            if not action_statement.strip():
                item_ok = False

            # Timeline must be valid
            if timeline not in VALID_TIMELINES:
                item_ok = False

            item_scores.append(100.0 if item_ok else 50.0)
            parsed_cves.append(
                {
                    "cve": cve.upper(),
                    "verdict": verdict,  # mapped from VEX status
                    "priority": priority,
                    "reasoning": impact_statement,
                    "action": action_statement,
                    "timeline": timeline,
                }
            )

        format_score = sum(item_scores) / len(item_scores) if item_scores else 0.0

        # 5. CVE coverage — which ground-truth CVEs did the model address?
        ground_truth_cves: list[str] = list(gt_cves.keys())
        model_cves: list[str] = [c["cve"] for c in parsed_cves]
        model_cve_set: set[str] = set(model_cves)

        covered = [cve for cve in ground_truth_cves if cve in model_cve_set]
        missing_cves_list = [cve for cve in ground_truth_cves if cve not in model_cve_set]
        hallucinated_cves_list = [cve for cve in model_cves if cve not in ground_truth_cves]

        coverage_score = (
            (len(covered) / len(ground_truth_cves)) * 100.0 if ground_truth_cves else 100.0
        )

        # 6. Verdict accuracy (only for CVEs that exist in ground truth)
        verdict_matches = 0
        verdict_total = 0
        verdict_mismatches_list: list[dict[str, str]] = []

        for mcve in model_cves:
            if mcve in ground_truth_cves:
                gt_detail = gt_cves[mcve]
                model_verdict = next(
                    (p["verdict"] for p in parsed_cves if p["cve"] == mcve),
                    "",
                )
                verdict_total += 1
                if model_verdict == gt_detail.verdict.lower():
                    verdict_matches += 1
                else:
                    verdict_mismatches_list.append(
                        {"cve": mcve, "expected": gt_detail.verdict, "got": model_verdict}
                    )

        verdict_score = (verdict_matches / verdict_total) * 100.0 if verdict_total > 0 else 0.0

        # 7. Priority accuracy (compare to priority_order)
        priority_matches = 0
        priority_total = 0
        priority_mismatches_list: list[dict[str, str]] = []

        # Build expected priority from ground truth
        expected_priorities: dict[str, str] = {}
        for idx, cve in enumerate(gt_priority_order):
            if idx == 0:
                expected_priorities[cve] = "P0"
            elif idx == 1:
                expected_priorities[cve] = "P1"
            else:
                expected_priorities[cve] = "P2"

        # Non-exploitable findings override to P3 regardless of priority_order position
        for cve in ground_truth_cves:
            detail = gt_cves[cve]
            if detail.verdict == "not_exploitable":
                expected_priorities[cve] = "P3"

        for mcve in model_cves:
            if mcve in ground_truth_cves:
                expected_p = expected_priorities.get(mcve, "P2")
                model_p = next(
                    (p["priority"] for p in parsed_cves if p["cve"] == mcve),
                    "",
                )
                priority_total += 1
                if model_p == expected_p:
                    priority_matches += 1
                else:
                    priority_mismatches_list.append(
                        {"cve": mcve, "expected": expected_p, "got": model_p}
                    )

        priority_score = (priority_matches / priority_total) * 100.0 if priority_total > 0 else 0.0

        # 8. Hallucination penalty
        hallucination_penalty = 0.0
        if hallucinated_cves_list:
            max_hallucination_ratio = min(
                len(hallucinated_cves_list) / max(len(ground_truth_cves), 1),
                1.0,
            )
            hallucination_penalty = round(HALLUCINATION_PENALTY_MAX * max_hallucination_ratio, 1)

        return JsonValidationResult(
            format_score=round(format_score, 1),
            coverage_score=round(coverage_score, 1),
            verdict_score=round(verdict_score, 1),
            priority_score=round(priority_score, 1),
            regex_score=round(regex_score, 1),
            hallucination_penalty=hallucination_penalty,
            parsed_cves=parsed_cves,
            ground_truth_cves=ground_truth_cves,
            missing_cves=missing_cves_list,
            hallucinated_cves=hallucinated_cves_list,
            verdict_mismatches=verdict_mismatches_list,
            priority_mismatches=priority_mismatches_list,
        )


# ---------------------------------------------------------------------------
# Pass 2 — Judge Grader (LLM-as-judge via Claude Opus 4.7 / OpenRouter)
# ---------------------------------------------------------------------------


class JudgeGrader:
    """Pass 2 LLM-as-judge grader.

    Uses a configurable judge model (default: Claude Opus 4.7 via OpenRouter)
    to score a model's response against the task rubric.
    Returns a per-dimension breakdown.
    """

    def __init__(self, judge_model_key: str = "claude_opus_47") -> None:
        if judge_model_key not in ALL_MODELS:
            valid = list(ALL_MODELS.keys())
            raise ValueError(f"Unknown judge model '{judge_model_key}'. Available models: {valid}")

        model_config = ALL_MODELS[judge_model_key]

        # Select the correct API key based on provider
        if model_config.provider == "deepseek":
            api_key = settings.deepseek_api_key
            key_name = "DEEPSEEK_API_KEY"
        else:
            api_key = settings.openrouter_api_key
            key_name = "OPENROUTER_API_KEY"

        if not api_key:
            raise ValueError(
                f"{key_name} is required for the judge model "
                f"('{judge_model_key}', provider='{model_config.provider}'). "
                f"Set it in your .env file."
            )

        self._adapter = OpenAICompatAdapter(
            model_config=model_config,
            api_key=api_key,
        )
        self._judge_model_key = judge_model_key

        # Running totals of judge API usage, accumulated across grade() calls.
        self._total_cost: Decimal = Decimal("0")
        self._total_tokens_in: int = 0
        self._total_tokens_out: int = 0
        self._call_count: int = 0

    @property
    def judge_model_key(self) -> str:
        """Return the model key used for judging (e.g. ``claude_opus_47``)."""
        return self._judge_model_key

    @property
    def cost_summary(self) -> dict[str, Any]:
        """Total judge API usage accumulated across all ``grade()`` calls."""
        return {
            "model_id": self._judge_model_key,
            "total_cost": float(self._total_cost),
            "tokens_in": self._total_tokens_in,
            "tokens_out": self._total_tokens_out,
            "call_count": self._call_count,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def grade(
        self,
        *,
        task_name: str,
        system_prompt: str,
        input_text: str,
        stack_context: str,
        model_response: str,
        rubric: Rubric,
    ) -> tuple[float, list[dict[str, Any]], str | None]:
        """Grade a response using the judge model.

        Args:
            task_name: Task name (e.g. ``trivy_triage``) for prompt building.
            system_prompt: The system prompt that was shown to the model.
            input_text: The scan output / input that was given to the model.
            stack_context: The deployment context given to the model.
            model_response: The model's raw output to grade.
            rubric: The ``Rubric`` object from the test case.

        Returns:
            A tuple of ``(pass2_score, rubric_scores, error_message)`` where:
            - ``pass2_score`` is the weighted average of all rubric dimensions, 0-100.
            - ``rubric_scores`` is a list of ``RubricScore`` dicts (one per dimension).
            - ``error_message`` is ``None`` on success, or a description of the failure.
        """
        # Build a human-readable rubric string for the judge prompt
        rubric_str = self._format_rubric(rubric)

        # Build the judge user prompt
        judge_user_prompt = build_judge_prompt(
            task_name=task_name,
            system_prompt=system_prompt,
            input_text=input_text,
            stack_context=stack_context,
            model_response=model_response,
            rubric=rubric_str,
        )

        # Look up judge system prompt from task config (supports multi-task)
        task_config = get_task_config(task_name)
        judge_system_prompt = task_config["judge_system_prompt"]

        request = LLMRequest(
            model_id=self._adapter.model_config.model_id,
            system_prompt=judge_system_prompt,
            user_prompt=judge_user_prompt,
            max_tokens=1024,
            temperature=0.0,  # deterministic judge
        )

        response = await self._adapter.complete(request)

        # Accumulate judge API usage so the pipeline can report grading cost.
        self._call_count += 1
        self._total_cost += response.cost_usd
        self._total_tokens_in += response.tokens_in
        self._total_tokens_out += response.tokens_out

        if response.error:
            return 0.0, [], response.error

        # Parse judge JSON output
        return self._parse_judge_response(response.text, rubric)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_rubric(rubric: Rubric) -> str:
        """Convert a ``Rubric`` model into a readable string for the judge prompt."""
        parts: list[str] = []
        for dim_name in rubric.model_fields:
            item: RubricItem = getattr(rubric, dim_name)
            readable = dim_name.replace("_", " ").title()
            parts.append(f"{readable} (max {item.max_score}): {item.description}")
        return "\n\n".join(parts)

    @staticmethod
    def _parse_judge_response(
        raw_text: str,
        rubric: Rubric,
    ) -> tuple[float, list[dict[str, Any]], str | None]:
        """Parse judge JSON output into rubric scores.

        Handles markdown-fenced JSON blocks and partial failures.
        Returns ``(pass2_score, rubric_scores, error)``.
        """
        text = raw_text.strip()

        # Strip markdown fences if present
        if text.startswith("```"):
            # Find the closing fence
            end = text.find("```", 3)
            if end != -1:
                text = text[3:end]
            else:
                text = text[3:]
            # Strip optional "json" language tag
            text = text.strip()
            if text.startswith("json"):
                text = text[4:].strip()

        # Parse JSON
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return 0.0, [], f"Judge returned invalid JSON: {exc}"

        # Validate top-level structure
        if "rubric_scores" not in data:
            return (
                0.0,
                [],
                f"Judge response missing 'rubric_scores' key. Keys received: {list(data.keys())}",
            )

        scores_raw: list[dict[str, Any]] = data["rubric_scores"]
        if not scores_raw:
            return 0.0, [], "Judge returned empty rubric_scores array."

        # Parse each rubric score entry using RubricScore-like validation
        rubric_scores: list[dict[str, Any]] = []
        total_pct = 0.0
        dimension_count = 0

        # Get expected dimensions from the rubric model fields
        expected_dims = list(rubric.model_fields.keys())
        dim_map = {d.replace("_", " ").lower(): d for d in expected_dims}

        for entry in scores_raw:
            dim_name_raw = entry.get("dimension", "").strip().lower()
            score = entry.get("score", 0)
            reasoning = entry.get("reasoning")

            # Normalise dimension name to match rubric fields
            dim_normalised = dim_map.get(dim_name_raw, dim_name_raw.replace(" ", "_"))

            # Find max_score for this dimension
            max_score = 25  # default fallback
            for ed in expected_dims:
                if ed == dim_normalised or ed.replace("_", " ") == dim_name_raw:
                    item = getattr(rubric, ed)
                    max_score = item.max_score
                    break

            # Clamp score to [0, max_score]
            score = max(0, min(score, max_score))

            rubric_scores.append(
                {
                    "dimension": dim_normalised,
                    "score": score,
                    "max_score": max_score,
                    "reasoning": reasoning,
                }
            )

            total_pct += (score / max_score) * 100.0 if max_score > 0 else 0.0
            dimension_count += 1

        pass2_score = total_pct / dimension_count if dimension_count > 0 else 0.0
        return pass2_score, rubric_scores, None


# ---------------------------------------------------------------------------
# Grader — Orchestrator
# ---------------------------------------------------------------------------


class Grader:
    """Two-pass grader orchestrator.

    Loads a responses JSON file (produced by ``Runner``), runs both grading
    passes on each response, and saves the graded results as a scores JSON file.
    """

    def __init__(
        self,
        task_name: str = "trivy_triage",
        judge_model_key: str = "claude_opus_47",
        pass1_weight: float = PASS1_WEIGHT,
        pass2_weight: float = PASS2_WEIGHT,
        output_dir: str = "outputs",
    ) -> None:
        self.task_name = task_name
        self.judge_model_key = judge_model_key
        self.pass1_weight = pass1_weight
        self.pass2_weight = pass2_weight
        self.output_dir = Path(output_dir)

        # Validate weights
        total_weight = pass1_weight + pass2_weight
        if abs(total_weight - 1.0) > 0.001:
            raise ValueError(
                f"pass1_weight ({pass1_weight}) + pass2_weight ({pass2_weight}) "
                f"= {total_weight}, but must sum to 1.0"
            )

        self._judge_grader: JudgeGrader | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def grade_file(self, input_path: str) -> Path:
        """Grade all responses in a JSON file. Returns path to saved scores.

        Args:
            input_path: Path to a responses JSON file from ``Runner``.

        Returns:
            Path to the scores JSON file that was written.
        """
        path = Path(input_path)
        if not path.exists():
            console.print(f"[red]Input file not found: {input_path}[/red]")
            raise SystemExit(1)

        # 1. Load responses file
        with open(path) as f:
            data: dict[str, Any] = json.load(f)

        metadata = data.get("metadata", {})
        cases_raw = data.get("cases", [])
        responses_raw = data.get("responses", [])

        console.print(f"[bold]Grading:[/bold] {path.name}")
        console.print(f"  Task:          {metadata.get('task', '?')}")
        console.print(f"  Prompt ver:    {metadata.get('prompt_version', '?')}")
        console.print(f"  Cases loaded:  {len(cases_raw)}")
        console.print(f"  Responses:     {len(responses_raw)}")
        console.print(f"  Judge model:   {self.judge_model_key}")
        console.print(f"  Weights:       pass1={self.pass1_weight}, pass2={self.pass2_weight}")
        console.print()

        # 2. Build case lookup map
        cases_map: dict[str, TaskCase] = {}
        for c in cases_raw:
            tc = TaskCase.model_validate(c)
            cases_map[tc.id] = tc

        # 3. Get task config
        task_config = get_task_config(self.task_name)

        # 4. Initialise judge grader (lazy)
        judge = self._get_judge()

        # 5. Grade each response
        graded_responses: list[dict[str, Any]] = []
        total = len(responses_raw)

        for idx, resp in enumerate(responses_raw, start=1):
            case_id = resp.get("case_id", "?")
            model_id = resp.get("model_id", "?")
            response_data = resp.get("response", {})
            response_text = response_data.get("text", "")
            finish_reason = response_data.get("finish_reason", "")
            response_error = response_data.get("error") or ""

            case = cases_map.get(case_id)
            if case is None:
                logger.warning("case_not_found", case_id=case_id)
                continue

            # -- Pass 1.5: JSON validation + structural grading --
            validation = JsonValidator.validate(
                response_text=response_text,
                ground_truth=case.ground_truth,
                regex_patterns=case.expected_response_includes,
            )

            # Compute blended deterministic score from granular sub-scores
            # (before hallucination penalty)
            deterministic_raw = (
                validation.format_score * FORMAT_WEIGHT
                + validation.coverage_score * COVERAGE_WEIGHT
                + validation.verdict_score * VERDICT_WEIGHT
                + validation.priority_score * PRIORITY_WEIGHT
                + validation.regex_score * REGEX_WEIGHT
            )
            # Apply hallucination penalty
            hallucination_penalty = validation.hallucination_penalty
            deterministic_raw = max(0.0, deterministic_raw - hallucination_penalty)

            pass1_weighted = deterministic_raw * self.pass1_weight

            # -- Pass 2: Judge --
            pass2_raw = 0.0
            rubric_scores: list[dict[str, Any]] = []
            judge_error: str | None = None

            # Only run judge if there's a non-empty response
            if response_text.strip():
                pass2_raw, rubric_scores, judge_error = await judge.grade(
                    task_name=self.task_name,
                    system_prompt=task_config["system_prompt"],
                    input_text=case.input,
                    stack_context=case.stack_context,
                    model_response=response_text,
                    rubric=case.rubric,
                )
            else:
                judge_error = "Empty response text — skipped judge grading"

            pass2_weighted = pass2_raw * self.pass2_weight
            total_score = pass1_weighted + pass2_weighted

            # Determine status icon
            if validation.parse_error and not validation.parsed_cves:
                status_icon = "  ✗"
            elif hallucination_penalty > 0 or validation.verdict_mismatches:
                status_icon = "  ⚠"
            elif judge_error:
                status_icon = "  ⚠"
            else:
                status_icon = "  ✓"

            graded_responses.append(
                {
                    "case_id": case_id,
                    "model_id": model_id,
                    "prompt_version": resp.get("prompt_version", ""),
                    "score": {
                        "total": round(total_score, 2),
                        "pass1_score": round(pass1_weighted, 2),
                        "pass2_score": round(pass2_weighted, 2),
                        # New granular dimensions
                        "format_score": round(validation.format_score, 1),
                        "coverage_score": round(validation.coverage_score, 1),
                        "verdict_score": round(validation.verdict_score, 1),
                        "priority_score": round(validation.priority_score, 1),
                        "regex_score": round(validation.regex_score, 1),
                        "judge_score": round(pass2_raw, 1),
                        "hallucination_penalty": hallucination_penalty,
                        # Raw deterministic total (before pass1 weighting)
                        "deterministic_total": round(deterministic_raw, 2),
                        "model_type": "llm",
                        # Validation metadata
                        "validation": {
                            "missing_cves": validation.missing_cves,
                            "hallucinated_cves": validation.hallucinated_cves,
                            "verdict_mismatches": validation.verdict_mismatches,
                            "priority_mismatches": validation.priority_mismatches,
                            "parse_error": validation.parse_error,
                            "finish_reason": finish_reason,
                            "error": response_error,
                        },
                        # Legacy fields
                        "rubric_scores": rubric_scores,
                        "judge_error": judge_error,
                    },
                }
            )

            # Progress indicator
            console.print(
                f"  [{idx}/{total}] {model_id} / {case_id}: "
                f"fmt={validation.format_score:.0f} "
                f"cov={validation.coverage_score:.0f} "
                f"ver={validation.verdict_score:.0f} "
                f"pri={validation.priority_score:.0f} "
                f"hal={hallucination_penalty:.0f} "
                f"judge={pass2_raw:.0f}  "
                f"total={total_score:.1f}"
                f"{status_icon}"
            )

        # 6. Grade baselines (non-LLM comparison participants)
        if BASELINE_GENERATORS:
            console.print(f"\n[bold]Grading {len(BASELINE_GENERATORS)} baselines...[/bold]")
            for case_id, case in cases_map.items():
                baseline_scores = grade_baselines(
                    ground_truth=case.ground_truth,
                    input_text=case.input,
                    regex_patterns=case.expected_response_includes,
                )
                for baseline_key, score in baseline_scores.items():
                    graded_responses.append(
                        {
                            "case_id": case_id,
                            "model_id": baseline_key,
                            "prompt_version": get_prompt_version(self.task_name),
                            "score": score,
                        }
                    )
            console.print(
                f"  Added {len(BASELINE_GENERATORS)} baseline(s) "
                f"x {len(cases_map)} case(s) = "
                f"{len(BASELINE_GENERATORS) * len(cases_map)} entries"
            )

        # 7. Print summary table
        self._print_summary(graded_responses)

        # 7b. Report judge API cost for this grading run
        if self._judge_grader is not None:
            cs = self._judge_grader.cost_summary
            if cs["call_count"] > 0:
                console.print(
                    f"\n[bold]Judge cost:[/bold] ${cs['total_cost']:.2f} "
                    f"over {cs['call_count']} call(s) "
                    f"({cs['tokens_in']:,} in / {cs['tokens_out']:,} out tokens)"
                )

        # 8. Save scores
        scores_path = self._save_scores(graded_responses, metadata, path)
        console.print(f"\n[green]Scores saved to {scores_path}[/green]")
        return scores_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_judge(self) -> JudgeGrader:
        """Lazy-init and cache the judge grader."""
        if self._judge_grader is None:
            self._judge_grader = JudgeGrader(judge_model_key=self.judge_model_key)
        return self._judge_grader

    @staticmethod
    def _print_summary(graded: list[dict[str, Any]]) -> None:
        """Print a results summary table with granular scores."""
        if not graded:
            return

        table = Table(title="Grading Results")
        table.add_column("Model", style="cyan")
        table.add_column("Case")
        table.add_column("Format", justify="right")
        table.add_column("Cover", justify="right")
        table.add_column("Verdict", justify="right")
        table.add_column("Priority", justify="right")
        table.add_column("Judge", justify="right")
        table.add_column("Total", justify="right")
        table.add_column("Status")

        for g in graded:
            s = g["score"]
            # Determine status
            val = s.get("validation", {})
            if val.get("parse_error") and not s.get("format_score", 0):
                status = "✗"
            elif s.get("hallucination_penalty", 0) > 0 or val.get("verdict_mismatches"):
                status = "⚠"
            elif s.get("judge_error"):
                status = "⚠"
            else:
                status = "✓"

            table.add_row(
                g["model_id"],
                g["case_id"],
                f"{s.get('format_score', 0):.0f}",
                f"{s.get('coverage_score', 0):.0f}",
                f"{s.get('verdict_score', 0):.0f}",
                f"{s.get('priority_score', 0):.0f}",
                f"{s.get('judge_score', 0):.0f}",
                f"[bold]{s['total']:.1f}[/bold]",
                status,
            )

        console.print()
        console.print(table)

    def _save_scores(
        self,
        graded: list[dict[str, Any]],
        metadata: dict[str, Any],
        input_path: Path,
    ) -> Path:
        """Save graded scores to a timestamped JSON file."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Jakarta timezone (UTC+7)
        now = datetime.now(timezone(timedelta(hours=7)))
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        filename = f"scores_{self.task_name}_{timestamp}.json"
        scores_path = self.output_dir / filename

        # Compute per-model averages
        model_totals: dict[str, list[float]] = {}
        for g in graded:
            mid = g["model_id"]
            model_totals.setdefault(mid, []).append(g["score"]["total"])

        model_averages: dict[str, float] = {}
        for mid, scores in model_totals.items():
            if scores:
                model_averages[mid] = round(sum(scores) / len(scores), 2)

        judge_cost: dict[str, Any] = (
            self._judge_grader.cost_summary if self._judge_grader is not None else {}
        )

        payload: dict[str, Any] = {
            "metadata": {
                "task": self.task_name,
                "prompt_version": get_prompt_version(self.task_name),
                "judge_model": self.judge_model_key,
                "graded_at": now.isoformat(),
                "source_file": input_path.name,
                "response_count": len(graded),
                "model_averages": model_averages,
                "judge_cost": judge_cost,
            },
            "grades": graded,
        }

        scores_path.write_text(json.dumps(payload, indent=2, default=str))
        logger.info("scores_saved", path=str(scores_path), count=len(graded))
        return scores_path


__all__ = [
    "COVERAGE_WEIGHT",
    "FORMAT_WEIGHT",
    "HALLUCINATION_PENALTY_MAX",
    "PASS1_WEIGHT",
    "PASS2_WEIGHT",
    "PRIORITY_WEIGHT",
    "REGEX_WEIGHT",
    "VALID_PRIORITIES",
    "VALID_TIMELINES",
    "VALID_VERDICTS",
    "VERDICT_WEIGHT",
    "GradedResponse",
    "Grader",
    "JsonValidationResult",
    "JsonValidator",
    "JudgeGrader",
    "RegexGrader",
    "RubricScore",
    "Score",
]
