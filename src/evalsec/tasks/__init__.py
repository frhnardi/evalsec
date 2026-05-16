"""Task registry — central hub for all benchmark tasks.

Each task module (``trivy_triage``, ``codeql_triage``, etc.) registers its
prompt configs in ``TASK_CONFIGS``. This module merges them into a single
registry and provides generic builder functions that dispatch based on
``task_name``.

Usage:
    from evalsec.tasks import get_task_config, build_user_prompt
    config = get_task_config("codeql_triage")
    prompt = build_user_prompt("codeql_triage", input_text, stack_context)
"""

from __future__ import annotations

from typing import Any

from evalsec.tasks.base import GroundTruth

# ---------------------------------------------------------------------------
# Mutable merged registry — populated by each task module's TASK_CONFIGS
# ---------------------------------------------------------------------------

TASK_CONFIGS: dict[str, Any] = {}

# ---------------------------------------------------------------------------
# Import and register from each task module
# ---------------------------------------------------------------------------

from evalsec.tasks.trivy_triage import (  # noqa: E402
    PROMPT_VERSION as TRIVY_PROMPT_VERSION,
)
from evalsec.tasks.trivy_triage import (  # noqa: E402
    TASK_CONFIGS as _TRIVY_TC,
)
from evalsec.tasks.trivy_triage import (  # noqa: E402
    VEX_STATUS_TO_VERDICT,
    _render_risk_metadata,
)

TASK_CONFIGS.update(_TRIVY_TC)

# Import and register codeql_triage
try:
    from evalsec.tasks.codeql_triage import PROMPT_VERSION as CODEQL_PROMPT_VERSION
    from evalsec.tasks.codeql_triage import TASK_CONFIGS as _CODEQL_TC

    TASK_CONFIGS.update(_CODEQL_TC)
except ImportError:
    CODEQL_PROMPT_VERSION = "codeql_triage/unknown"

# ---------------------------------------------------------------------------
# Prompt version lookup per task
# ---------------------------------------------------------------------------

_PROMPT_VERSIONS: dict[str, str] = {
    "trivy_triage": TRIVY_PROMPT_VERSION,
    "codeql_triage": CODEQL_PROMPT_VERSION,
}


def get_prompt_version(task_name: str) -> str:
    """Return the prompt version string for a task."""
    return _PROMPT_VERSIONS.get(task_name, f"{task_name}/unknown")


# ---------------------------------------------------------------------------
# Public API — generic prompt builders
# ---------------------------------------------------------------------------


def get_task_config(task_name: str) -> dict[str, Any]:
    """Return the prompt config for a given task name.

    Raises KeyError if the task is not registered.
    """
    if task_name not in TASK_CONFIGS:
        valid = list(TASK_CONFIGS.keys())
        raise KeyError(f"Unknown task '{task_name}'. Registered tasks: {valid}")
    return TASK_CONFIGS[task_name]  # type: ignore[no-any-return]


def build_user_prompt(
    task_name: str,
    input_text: str,
    stack_context: str,
    ground_truth: GroundTruth | None = None,
) -> str:
    """Build the user prompt for a task by filling the template.

    If ``ground_truth`` is provided and any finding has risk metadata
    (CVSS, EPSS, CISA KEV, etc.), a ``## Risk Metadata`` section is
    appended to the prompt.
    """
    config = get_task_config(task_name)
    template: str = config["user_prompt_template"]
    risk_metadata = _render_risk_metadata(ground_truth)
    return template.format(
        input=input_text,
        stack_context=stack_context,
        risk_metadata=risk_metadata,
    )


def build_judge_prompt(
    task_name: str,
    system_prompt: str,
    input_text: str,
    stack_context: str,
    model_response: str,
    rubric: str,
) -> str:
    """Build the judge user prompt for a task."""
    config = get_task_config(task_name)
    template: str = config["judge_user_prompt_template"]
    return template.format(
        system_prompt=system_prompt,
        input=input_text,
        stack_context=stack_context,
        model_response=model_response,
        rubric=rubric,
    )


# ---------------------------------------------------------------------------
# Re-export shared symbols for convenience
# ---------------------------------------------------------------------------

__all__ = [
    "TASK_CONFIGS",
    "VEX_STATUS_TO_VERDICT",
    "build_judge_prompt",
    "build_user_prompt",
    "get_prompt_version",
    "get_task_config",
]
