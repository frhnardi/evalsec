"""evalsec CLI — Typer entry point."""

import asyncio
from typing import Optional

import typer
from rich.console import Console

from evalsec import __version__

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
        ...,
        "--task",
        "-t",
        help="Task name to run (e.g., trivy_triage)",
    ),
    max_cases: Optional[int] = typer.Option(
        None,
        "--max-cases",
        "-m",
        help="Maximum number of test cases to run (default: all)",
    ),
) -> None:
    """Run benchmark: load test cases, call LLMs, save responses."""
    console.print(f"[bold yellow]run[/bold yellow] --task {task} --max-cases {max_cases or 'all'} [dim](not yet implemented)[/dim]")


@app.command()
def grade(
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to responses JSON file",
    ),
) -> None:
    """Grade responses: pass 1 regex, pass 2 LLM-as-judge."""
    console.print(f"[bold yellow]grade[/bold yellow] --input {input_file} [dim](not yet implemented)[/dim]")


@app.command()
def build() -> None:
    """Build static dashboard from latest scores."""
    console.print("[bold yellow]build[/bold yellow] [dim](not yet implemented)[/dim]")


@app.command()
def deploy() -> None:
    """Deploy dashboard to AWS S3 + CloudFront."""
    console.print("[bold yellow]deploy[/bold yellow] [dim](not yet implemented)[/dim]")


def _run_async(coro):
    """Run an async command synchronously."""
    return asyncio.run(coro)


if __name__ == "__main__":
    app()
