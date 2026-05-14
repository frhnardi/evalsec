"""Pydantic data models for task (test case) definitions.

All test cases are loaded from YAML files in `tests/data/<task>/`.
Every field uses strict mode + extra=forbid — Pydantic will fail loudly
if YAML structure drifts from these schemas.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceInfo(BaseModel):
    """Metadata about where this scan artifact came from."""

    model_config = ConfigDict(strict=True, extra="forbid")

    type: str = Field(..., description="One of: self_scan, github_issue, advisory, synthetic")
    image: str | None = Field(default=None, description="Docker image scanned (if self_scan)")
    scanned_at: date | str | None = Field(default=None, description="Date the scan was performed")
    trivy_version: str | None = Field(default=None, description="Trivy version used")
    url: str | None = Field(default=None, description="URL if sourced from GitHub issue")
    notes: str | None = Field(default=None, description="Any additional context about the source")
    total_cves_found: int | None = Field(default=None, description="Total CVEs found in the raw scan")
    cves_selected: int | None = Field(default=None, description="Number of CVEs included in this test case after selection")
    selection_criteria: str | None = Field(default=None, description="Criteria used to select CVEs for this test case")

    @field_validator("scanned_at", mode="before")
    @classmethod
    def _parse_scanned_at(cls, v: Any) -> date | None:
        if v is None:
            return None
        if isinstance(v, date):
            return v
        if isinstance(v, str):
            return date.fromisoformat(v)
        raise ValueError(f"Cannot parse scanned_at: {v!r}")


class FindingDetail(BaseModel):
    """A single CVE finding in the ground truth — exploitable or not.

    Risk metadata fields (cvss_score, epss_percentile, etc.) are all optional.
    Existing dataset files remain fully compatible — they simply omit these keys.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    cve: str = Field(..., description="CVE identifier, e.g. CVE-2021-44228")
    verdict: str = Field(
        ...,
        description="One of: exploitable, not_exploitable, partial",
    )
    reasoning: str = Field(..., description="Why this verdict was reached")
    action: str | None = Field(default=None, description="Recommended remediation action")

    # ------------------------------------------------------------------
    # Risk metadata (all optional — backward-compatible)
    # ------------------------------------------------------------------
    cvss_score: float | None = Field(
        default=None,
        description="CVSS v3 base score (0.0 to 10.0)",
        ge=0.0,
        le=10.0,
    )
    epss_percentile: float | None = Field(
        default=None,
        description="EPSS percentile (0.0 to 100.0)",
        ge=0.0,
        le=100.0,
    )
    cisa_kev: bool | None = Field(
        default=None,
        description="Listed in CISA Known Exploited Vulnerabilities catalog",
    )
    exploit_maturity: str | None = Field(
        default=None,
        description="One of: active, proof_of_concept, none, unknown",
    )
    fixed_version: str | None = Field(
        default=None,
        description="Version string that fixes this vulnerability",
    )
    package_path: str | None = Field(
        default=None,
        description="Path to the vulnerable package in the image",
    )
    runtime_exposure: str | None = Field(
        default=None,
        description="One of: network, local, none, unknown",
    )
    asset_criticality: str | None = Field(
        default=None,
        description="One of: critical, high, medium, low, unknown",
    )
    internet_facing: bool | None = Field(
        default=None,
        description="Whether the asset is exposed to the public internet",
    )


class GroundTruth(BaseModel):
    """The owner's expert judgment on exploitability for each finding."""

    model_config = ConfigDict(strict=True, extra="forbid")

    exploitable_findings: list[FindingDetail] = Field(
        default_factory=list,
        description="Findings that are truly exploitable in this context",
    )
    non_exploitable_findings: list[FindingDetail] = Field(
        default_factory=list,
        description="Findings that are false positives or dead code in this context",
    )
    partial_findings: list[FindingDetail] = Field(
        default_factory=list,
        description="Findings where exploitability is partial or mitigated",
    )
    priority_order: list[str] = Field(
        default_factory=list,
        description="Ordered list of CVEs from highest to lowest priority",
    )


class RubricItem(BaseModel):
    """One dimension of the scoring rubric."""

    model_config = ConfigDict(strict=True, extra="forbid")

    max_score: int = Field(
        ..., description="Maximum possible score for this dimension", ge=0, le=100
    )
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

    id: str = Field(
        ..., description="Unique identifier, e.g. trivy_triage_001", pattern=r"^[a-z_]+[0-9]+$"
    )
    task: str = Field(..., description="Task name, e.g. trivy_triage")
    version: str = Field(
        ..., description="Bump when input or ground truth changes", pattern=r"^v[0-9]+$"
    )

    source: SourceInfo = Field(..., description="Where the artifact came from")
    input: str = Field(..., description="Verbatim Trivy scan output (the LLM sees this)")
    stack_context: str = Field(..., description="Deployment context for the LLM to reason about")

    ground_truth: GroundTruth = Field(..., description="Owner's expert exploitability judgments")
    expected_response_includes: list[str] = Field(
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
