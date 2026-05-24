"""Static HTML dashboard builder: Jinja2 + Chart.js.

Loads a scores JSON file (from ``evalsec grade``) and renders a
self-contained ``dist/index.html`` with all data baked in at build time.

Usage:
    builder = BuildDashboard()
    builder.build("outputs/scores_20260512_020000.json")
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console

logger = structlog.get_logger(__name__)
console = Console()

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Human-readable display names keyed by model_id. Single source of truth —
# injected into both the rendered HTML and the dashboard's client-side JS
# (where it is used for chart labels).
MODEL_DISPLAY: dict[str, str] = {
    "claude_sonnet_46": "Claude Sonnet 4.6",
    "kimi_k2_thinking": "Kimi K2 Thinking",
    "qwen_3_5": "Qwen 3.5",
    "deepseek_v4_pro": "DeepSeek V4 Pro",
    "claude_opus_47": "Claude Opus 4.7 (Judge)",
    "baseline_cvss": "Baseline: CVSS Sort",
    "baseline_trivy": "Baseline: Trivy Severity",
    "baseline_epss": "Baseline: EPSS Score",
    "baseline_reachability": "Baseline: Reachability",
}


class BuildDashboard:
    """Renders a static HTML dashboard from scores JSON using Jinja2 + Chart.js."""

    def __init__(self, templates_dir: str | None = None) -> None:
        if templates_dir is None:
            templates_dir = str(TEMPLATES_DIR)
        self._env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        scores_path: str,
        responses_path: str | None = None,
        output_dir: str = "dist",
    ) -> Path:
        """Build the dashboard. Returns path to ``dist/index.html``.

        Args:
            scores_path: Path to a scores JSON file from ``evalsec grade``.
            responses_path: Optional path to responses JSON for cost data.
            output_dir: Output directory (default: ``dist``).

        Returns:
            Path to the generated ``index.html``.
        """
        scores_file = Path(scores_path)
        if not scores_file.exists():
            console.print(f"[red]Scores file not found: {scores_path}[/red]")
            raise SystemExit(1)

        # 1. Load scores
        with open(scores_file) as f:
            scores_data: dict[str, Any] = json.load(f)

        grades: list[dict[str, Any]] = scores_data.get("grades", [])
        meta: dict[str, Any] = scores_data.get("metadata", {})

        console.print(f"[bold]Building dashboard:[/bold] {scores_file.name}")
        console.print(f"  Grades:      {len(grades)}")
        console.print(f"  Task:        {meta.get('task', '?')}")
        console.print(f"  Judge model: {meta.get('judge_model', '?')}")

        # 2. Load responses for cost data (optional)
        cost_map = _load_costs(responses_path) if responses_path else {}

        # 3. Build leaderboard from grades
        leaderboard = _build_leaderboard(grades, cost_map)

        # 3b. Build the judge cost card (omitted when no judge usage was recorded)
        judge_entry = _build_judge_entry(meta)

        # 4. Collect unique dimension names across all entries
        dim_names: list[str] = []
        seen_dims: set[str] = set()
        for entry in leaderboard:
            for dim in entry.get("dimension_scores", {}):
                if dim not in seen_dims:
                    seen_dims.add(dim)
                    dim_names.append(dim)

        # 5. Render template
        template = self._env.get_template("dashboard.html.j2")
        html = template.render(
            title=f"evalsec: {meta.get('task', 'unknown')}",
            task=meta.get("task", "unknown"),
            prompt_version=meta.get("prompt_version", "?"),
            judge_model=meta.get("judge_model", "?"),
            graded_at=meta.get("graded_at", "?"),
            response_count=meta.get("response_count", 0),
            model_averages=meta.get("model_averages", {}),
            leaderboard=leaderboard,
            dim_names=dim_names,
            model_display=MODEL_DISPLAY,
            judge_entry=judge_entry,
        )

        # 6. Write to dist/
        dist_dir = Path(output_dir)
        dist_dir.mkdir(parents=True, exist_ok=True)
        index_path = dist_dir / "index.html"
        index_path.write_text(html)

        # 7. Copy vendored Chart.js asset alongside index.html
        chart_src = TEMPLATES_DIR / "chart.umd.min.js"
        chart_dst = dist_dir / "chart.umd.min.js"
        if chart_src.exists():
            shutil.copy2(str(chart_src), str(chart_dst))
            logger.info("chartjs_copied", src=str(chart_src), dst=str(chart_dst))
        else:
            logger.warning("chartjs_not_found", path=str(chart_src))

        console.print(f"\n[green]Dashboard written to {index_path}[/green]")
        logger.info("dashboard_built", path=str(index_path), grades=len(grades))
        return index_path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_costs(responses_path: str) -> dict[str, float]:
    """Load per-model total cost from a responses JSON file."""
    resp_file = Path(responses_path)
    if not resp_file.exists():
        console.print(
            f"[yellow]Responses file not found, skipping cost data: {responses_path}[/yellow]"
        )
        return {}

    with open(resp_file) as f:
        resp_data: dict[str, Any] = json.load(f)

    cost_map: dict[str, float] = {}
    for r in resp_data.get("responses", []):
        mid: str = r.get("model_id", "?")
        cost_str = r.get("response", {}).get("cost_usd", "0")
        try:
            cost = float(cost_str)
        except (ValueError, TypeError):
            cost = 0.0
        cost_map[mid] = cost_map.get(mid, 0.0) + cost

    return cost_map


def _build_judge_entry(meta: dict[str, Any]) -> dict[str, Any] | None:
    """Build a synthetic judge-cost card entry from recorded judge usage.

    The judge (e.g. Claude Opus 4.7) never performs the triage task, so it
    has no score and is not part of the leaderboard ranking: this entry
    exists only to surface grading-infrastructure cost on the Models tab.

    Returns ``None`` when no judge usage was recorded (mock data, or a run
    that never invoked the judge), so the dashboard simply omits the card.
    """
    judge_cost = meta.get("judge_cost") or {}
    calls = judge_cost.get("call_count", 0)
    if calls <= 0:
        return None

    total = float(judge_cost.get("total_cost", 0.0))
    return {
        "model_id": judge_cost.get("model_id") or meta.get("judge_model", "claude_opus_47"),
        "model_type": "judge",
        "total_cost": total,
        "judge_calls": calls,
        "judge_tokens_in": judge_cost.get("tokens_in", 0),
        "judge_tokens_out": judge_cost.get("tokens_out", 0),
        "avg_cost_per_call": total / calls if calls else 0.0,
    }


def _build_leaderboard(
    grades: list[dict[str, Any]],
    cost_map: dict[str, float],
) -> list[dict[str, Any]]:
    """Group grades by model and compute averages."""
    # Group by model_id
    model_groups: dict[str, list[dict[str, Any]]] = {}
    for g in grades:
        mid = g.get("model_id", "unknown")
        model_groups.setdefault(mid, []).append(g)

    leaderboard: list[dict[str, Any]] = []

    for mid, group in model_groups.items():
        scores = [g.get("score", {}) for g in group]
        totals = [s.get("total", 0) for s in scores]
        pass1s = [s.get("pass1_score", 0) for s in scores]
        pass2s = [s.get("pass2_score", 0) for s in scores]

        avg_total = sum(totals) / len(totals) if totals else 0.0
        avg_pass1 = sum(pass1s) / len(pass1s) if pass1s else 0.0
        avg_pass2 = sum(pass2s) / len(pass2s) if pass2s else 0.0

        # Determine model_type from first score (backward compat: default "llm")
        model_type = scores[0].get("model_type", "llm") if scores else "llm"

        # Compute deterministic metric averages
        fmt_scores = [s.get("format_score", 0) for s in scores]
        cov_scores = [s.get("coverage_score", 0) for s in scores]
        ver_scores = [s.get("verdict_score", 0) for s in scores]
        pri_scores = [s.get("priority_score", 0) for s in scores]
        reg_scores = [s.get("regex_score", 0) for s in scores]
        judge_scores = [s.get("judge_score", 0) for s in scores]
        hal_scores = [s.get("hallucination_penalty", 0) for s in scores]
        det_totals = [s.get("deterministic_total", 0) for s in scores]

        avg_format = sum(fmt_scores) / len(fmt_scores) if fmt_scores else 0.0
        avg_coverage = sum(cov_scores) / len(cov_scores) if cov_scores else 0.0
        avg_verdict = sum(ver_scores) / len(ver_scores) if ver_scores else 0.0
        avg_priority = sum(pri_scores) / len(pri_scores) if pri_scores else 0.0
        avg_regex = sum(reg_scores) / len(reg_scores) if reg_scores else 0.0
        avg_judge = sum(judge_scores) / len(judge_scores) if judge_scores else 0.0
        avg_hal = sum(hal_scores) / len(hal_scores) if hal_scores else 0.0
        avg_det_total = sum(det_totals) / len(det_totals) if det_totals else 0.0

        # Collect per-dimension scores: rubric dimensions + deterministic dimensions
        dim_scores: dict[str, list[float]] = {}
        for s in scores:
            for rs in s.get("rubric_scores", []):
                dim: str = rs.get("dimension", "?")
                max_s = rs.get("max_score", 1)
                score_val = rs.get("score", 0)
                pct = (score_val / max_s) * 100.0 if max_s > 0 else 0.0
                dim_scores.setdefault(dim, []).append(pct)

        # Also include deterministic dimensions so baselines have radar chart data
        det_dims: dict[str, float] = {
            "format": avg_format,
            "coverage": avg_coverage,
            "verdict": avg_verdict,
            "priority": avg_priority,
        }
        for dim, val in det_dims.items():
            dim_scores.setdefault(dim, []).append(val)

        dim_avgs = {dim: round(sum(vals) / len(vals), 1) for dim, vals in dim_scores.items()}

        leaderboard.append(
            {
                "model_id": mid,
                "model_type": model_type,
                "avg_score": round(avg_total, 1),
                "avg_pass1": round(avg_pass1, 1),
                "avg_pass2": round(avg_pass2, 1),
                "avg_format": round(avg_format, 1),
                "avg_coverage": round(avg_coverage, 1),
                "avg_verdict": round(avg_verdict, 1),
                "avg_priority": round(avg_priority, 1),
                "avg_regex": round(avg_regex, 1),
                "avg_judge": round(avg_judge, 1),
                "avg_hallucination_penalty": round(avg_hal, 1),
                "avg_deterministic_total": round(avg_det_total, 1),
                "total_cost": round(cost_map.get(mid, 0.0), 2),
                "dimension_scores": dim_avgs,
                "details": group,
            }
        )

    # Sort by avg_score descending (LLMs and baselines mixed: template separates)
    leaderboard.sort(key=lambda x: x["avg_score"], reverse=True)

    # Add rank
    for i, entry in enumerate(leaderboard, start=1):
        entry["rank"] = i

    return leaderboard


__all__ = ["BuildDashboard"]
