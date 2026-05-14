"""evalsec CLI — Typer entry point."""

import asyncio
from collections.abc import Coroutine
from typing import Any

import typer
from rich.console import Console

from evalsec import __version__
from evalsec.runner import Runner

app = typer.Typer(
    name="evalsec",
    help="LLM benchmark for DevSecOps tasks",
    no_args_is_help=True,
)
console = Console()


def _version_callback(show: bool) -> None:
    if show:
        console.print(f"evalsec v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """evalsec — LLM benchmark for DevSecOps tasks."""
    pass


@app.command()
def run(
    task: str = typer.Option(
        "trivy_triage",
        "--task",
        "-t",
        help="Task name to run (e.g., trivy_triage)",
    ),
    max_cases: int | None = typer.Option(
        None,
        "--max-cases",
        help="Maximum number of test cases to run (default: all)",
    ),
    model: list[str] | None = typer.Option(
        None,
        "--model",
        help="Model(s) to benchmark (repeatable: --model m1 --model m2). Default: all",
    ),
    models_str: str | None = typer.Option(
        None,
        "--models",
        help="Comma-separated model list alias for --model (e.g., --models m1,m2)",
    ),
    max_concurrent: int = typer.Option(
        5,
        "--max-concurrent",
        help="Maximum concurrent API calls (default: 5)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Estimate cost without making API calls",
    ),
    data_dir: str = typer.Option(
        "tests/data/trivy_triage",
        "--data-dir",
        help="Directory containing YAML test case files",
    ),
    output_dir: str = typer.Option(
        "outputs",
        "--output-dir",
        "-o",
        help="Directory to save responses JSON",
    ),
) -> None:
    """Run benchmark: load test cases, call LLMs, save responses."""
    # Resolve models: --models (comma-separated) takes precedence if --model not given
    resolved_models = model
    if not resolved_models and models_str:
        resolved_models = [m.strip() for m in models_str.split(",") if m.strip()]
    _run_async(
        Runner(
            task_name=task,
            max_cases=max_cases,
            models=resolved_models,
            data_dir=data_dir,
            output_dir=output_dir,
            dry_run=dry_run,
            max_concurrency=max_concurrent,
        ).run()
    )


@app.command()
def grade(
    input_file: str = typer.Option(
        ...,
        "--input",
        "--responses",
        "-i",
        help="Path to responses JSON file (from `evalsec run`)",
    ),
    judge_model: str = typer.Option(
        "claude_opus_47",
        "--judge-model",
        "-j",
        help="Judge model key from the registry (default: claude_opus_47)",
    ),
    pass1_weight: float = typer.Option(
        0.20,
        "--pass1-weight",
        help="Weight for pass 1 regex grading (default: 0.20)",
    ),
    pass2_weight: float = typer.Option(
        0.80,
        "--pass2-weight",
        help="Weight for pass 2 LLM-as-judge grading (default: 0.80)",
    ),
    output_dir: str = typer.Option(
        "outputs",
        "--output-dir",
        "-o",
        help="Directory to save scores JSON",
    ),
) -> None:
    """Grade responses: pass 1 regex, pass 2 LLM-as-judge."""
    # Import here to avoid circular imports at module level
    from evalsec.grader import Grader

    _run_async(
        Grader(
            judge_model_key=judge_model,
            pass1_weight=pass1_weight,
            pass2_weight=pass2_weight,
            output_dir=output_dir,
        ).grade_file(input_file)
    )


@app.command()
def build(
    scores_file: str = typer.Option(
        ...,
        "--scores",
        "-s",
        help="Path to scores JSON file (from `evalsec grade`)",
    ),
    responses_file: str | None = typer.Option(
        None,
        "--responses",
        "-r",
        help="Optional path to responses JSON file (for cost data)",
    ),
    output_dir: str = typer.Option(
        "dist",
        "--output-dir",
        "-o",
        help="Output directory for the built dashboard",
    ),
) -> None:
    """Build static dashboard from scores JSON."""
    from evalsec.dashboard import BuildDashboard

    BuildDashboard().build(
        scores_path=scores_file,
        responses_path=responses_file,
        output_dir=output_dir,
    )


@app.command()
def deploy() -> None:
    """Deploy dashboard to AWS S3 + CloudFront."""
    console.print("[bold yellow]deploy[/bold yellow] [dim](not yet implemented)[/dim]")


def _run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run an async command synchronously."""
    return asyncio.run(coro)


if __name__ == "__main__":
    app()
