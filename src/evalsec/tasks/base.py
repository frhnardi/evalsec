"""Pydantic data models for task (test case) definitions.

All test cases are loaded from YAML files in `tests/data/<task>/`.
Every field uses strict mode + extra=forbid — Pydantic will fail loudly
if YAML structure drifts from these schemas.
"""

from __future__ import annotations

from datetime import date
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SourceInfo(BaseModel):
    """Metadata about where this scan artifact came from."""

    model_config = ConfigDict(strict=True, extra="forbid")

    type: str = Field(..., description="One of: self_scan, github_issue, advisory, synthetic")
    image: Optional[str] = Field(default=None, description="Docker image scanned (if self_scan)")
    scanned_at: Optional[date] = Field(default=None, description="Date the scan was performed")
    trivy_version: Optional[str] = Field(default=None, description="Trivy version used")
    url: Optional[str] = Field(default=None, description="URL if sourced from GitHub issue")
    notes: Optional[str] = Field(default=None, description="Any additional context about the source")


class FindingDetail(BaseModel):
    """A single CVE finding in the ground truth — exploitable or not."""

    model_config = ConfigDict(strict=True, extra="forbid")

    cve: str = Field(..., description="CVE identifier, e.g. CVE-2021-44228")
    verdict: str = Field(
        ...,
        description="One of: exploitable, not_exploitable, partial",
    )
    reasoning: str = Field(..., description="Why this verdict was reached")
    action: Optional[str] = Field(default=None, description="Recommended remediation action")


class GroundTruth(BaseModel):
    """The owner's expert judgment on exploitability for each finding."""

    model_config = ConfigDict(strict=True, extra="forbid")

    exploitable_findings: List[FindingDetail] = Field(
        default_factory=list,
        description="Findings that are truly exploitable in this context",
    )
    non_exploitable_findings: List[FindingDetail] = Field(
        default_factory=list,
        description="Findings that are false positives or dead code in this context",
    )
    partial_findings: List[FindingDetail] = Field(
        default_factory=list,
        description="Findings where exploitability is partial or mitigated",
    )
    priority_order: List[str] = Field(
        default_factory=list,
        description="Ordered list of CVEs from highest to lowest priority",
    )


class RubricItem(BaseModel):
    """One dimension of the scoring rubric."""

    model_config = ConfigDict(strict=True, extra="forbid")

    max_score: int = Field(..., description="Maximum possible score for this dimension", ge=0, le=100)
    description: str = Field(..., description="What this dimension measures and how to score it")


class Rubric(BaseModel):
    """Qualitative scoring rubric used by the judge (pass 2 grader)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    reachability_reasoning: RubricItem = Field(
        ...,
        description="Does the model reason about reachability using stack context?",
    )
    prioritization: RubricItem = Field(
        ...,
        description="Does the model rank findings correctly by real-world urgency?",
    )
    actionability: RubricItem = Field(
        ...,
        description="Are recommended actions concrete and specific?",
    )
    conciseness: RubricItem = Field(
        ...,
        description="Is the response concise and direct without AI preamble?",
    )


class TaskCase(BaseModel):
    """A complete test case — one YAML file's worth of data.

    This is the primary schema that all test case YAML files must conform to.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    id: str = Field(..., description="Unique identifier, e.g. trivy_triage_001", pattern=r"^[a-z_]+[0-9]+$")
    task: str = Field(..., description="Task name, e.g. trivy_triage")
    version: str = Field(..., description="Bump when input or ground truth changes", pattern=r"^v[0-9]+$")

    source: SourceInfo = Field(..., description="Where the artifact came from")
    input: str = Field(..., description="Verbatim Trivy scan output (the LLM sees this)")
    stack_context: str = Field(..., description="Deployment context for the LLM to reason about")

    ground_truth: GroundTruth = Field(..., description="Owner's expert exploitability judgments")
    expected_response_includes: List[str] = Field(
        ...,
        description="Regex patterns expected in a good LLM response (pass 1 grader)",
    )

    rubric: Rubric = Field(..., description="Qualitative scoring rubric (pass 2 grader)")

    weight: float = Field(
        default=1.0,
        description="Multiplier for this case's contribution to overall score (e.g., 1.5 for flagship cases)",
        ge=0.5,
        le=2.0,
    )
