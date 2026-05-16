"""Benchmark runner — load YAML cases, call models, save responses.

Orchestrates the core benchmark workflow:
  1. Load and filter YAML test cases
  2. Build adapters for requested models
  3. Estimate cost (dry-run or pre-run summary)
  4. Run cases with Semaphore(5) concurrency
  5. Incremental save after each model completes
  6. Return path to saved responses JSON
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import structlog
import yaml
from rich.console import Console
from rich.table import Table

from evalsec.adapters import ALL_MODELS, BENCHMARK_MODELS
from evalsec.adapters.base import LLMRequest
from evalsec.adapters.openai_compat import OpenAICompatAdapter
from evalsec.config import settings
from evalsec.tasks.base import TaskCase
from evalsec.tasks import (
    build_user_prompt,
    get_prompt_version,
    get_task_config,
)

logger = structlog.get_logger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# API key resolution
# ---------------------------------------------------------------------------

_PROVIDER_KEY_MAP: dict[str, str | None] = {
    "openrouter": settings.openrouter_api_key,
    "deepseek": settings.deepseek_api_key,
}


def _resolve_api_key(provider: str) -> str | None:
    """Return the API key for a provider, or None if not set."""
    return _PROVIDER_KEY_MAP.get(provider)


def _is_json_truncated(text: str) -> bool:
    """Check if a model response looks like truncated/incomplete JSON.

    Some API providers return ``finish_reason: "stop"`` even when the output
    is cut short at ``max_tokens``, producing an incomplete JSON string.
    This detects that case by trying to parse the JSON after stripping markdown
    fences.

    Returns ``True`` if the text appears to be an incomplete JSON object/array.
    """
    stripped = text.strip()
    # Strip markdown code fences if present
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

    # Only check if it looks like JSON (starts with { or [)
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False

    try:
        json.loads(stripped)
        return False  # Valid JSON — not truncated
    except json.JSONDecodeError:
        return True  # Invalid JSON — likely truncated


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class Runner:
    """Orchestrates benchmark runs.

    Usage:
        runner = Runner(task_name="trivy_triage", models=["claude_sonnet_46"])
        output_path = await runner.run()
    """

    def __init__(
        self,
        task_name: str = "trivy_triage",
        max_cases: int | None = None,
        models: list[str] | None = None,
        data_dir: str = "tests/data/trivy_triage",
        output_dir: str = "outputs",
        dry_run: bool = False,
        max_concurrency: int = 5,
    ) -> None:
        self.task_name = task_name
        self.max_cases = max_cases
        self.models = models or list(BENCHMARK_MODELS.keys())
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.dry_run = dry_run
        self._sem = asyncio.Semaphore(max_concurrency)

        # Validate all requested models exist
        for m in self.models:
            if m not in ALL_MODELS:
                valid = list(ALL_MODELS.keys())
                raise ValueError(f"Unknown model '{m}'. Available models: {valid}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> Path:
        """Execute the benchmark. Returns path to saved responses JSON."""
        # 1. Load cases
        cases = self._load_cases()
        if not cases:
            console.print("[red]No test cases found.[/red]")
            raise SystemExit(1)

        console.print(f"[bold]Task:[/bold] {self.task_name}")
        console.print(f"[bold]Cases:[/bold] {len(cases)}")
        console.print(f"[bold]Models:[/bold] {', '.join(self.models)}")
        console.print()

        # 2. Build adapters
        adapters = await self._build_adapters()

        # 3. Estimate cost
        estimate = self._estimate_cost(cases, adapters)
        self._print_estimate(estimate)

        if self.dry_run:
            console.print("[yellow]Dry-run mode. No API calls made.[/yellow]")
            dry_path = self.output_dir / "dry_run_estimate.txt"
            self.output_dir.mkdir(parents=True, exist_ok=True)
            dry_path.write_text(json.dumps(estimate, indent=2, default=str))
            return dry_path

        # 4. Run the benchmark
        responses = await self._run_cases(cases, adapters)

        # 5. Save results
        path = self._save_responses(responses, cases)
        console.print(f"\n[green]Responses saved to {path}[/green]")
        return path

    # ------------------------------------------------------------------
    # Internal — loading
    # ------------------------------------------------------------------

    def _load_cases(self) -> list[TaskCase]:
        """Load YAML files from data_dir and parse into TaskCase models."""
        if not self.data_dir.exists():
            console.print(f"[red]Data directory not found: {self.data_dir}[/red]")
            raise SystemExit(1)

        yaml_files = sorted(self.data_dir.glob("*.yaml"))
        if not yaml_files:
            console.print(f"[red]No YAML files found in {self.data_dir}[/red]")
            raise SystemExit(1)

        cases: list[TaskCase] = []
        for path in yaml_files:
            with open(path) as f:
                data = yaml.safe_load(f)
            case = TaskCase.model_validate(data)
            cases.append(case)

        # Apply --max-cases filter
        if self.max_cases is not None and self.max_cases > 0:
            # Sort by weight descending (flagship cases first), then take top N
            cases.sort(key=lambda c: c.weight, reverse=True)
            cases = cases[: self.max_cases]
            cases.sort(key=lambda c: c.id)  # Restore stable order

        return cases

    # ------------------------------------------------------------------
    # Internal — adapters
    # ------------------------------------------------------------------

    async def _build_adapters(self) -> dict[str, OpenAICompatAdapter]:
        """Create one adapter per requested model with correct API key."""
        adapters: dict[str, OpenAICompatAdapter] = {}
        for model_key in self.models:
            model_config = ALL_MODELS[model_key]
            api_key = _resolve_api_key(model_config.provider)
            if not api_key:
                console.print(
                    f"[yellow]Skipping {model_key} — no API key for "
                    f"provider '{model_config.provider}'[/yellow]"
                )
                continue
            adapters[model_key] = OpenAICompatAdapter(
                model_config=model_config,
                api_key=api_key,
            )
        return adapters

    # ------------------------------------------------------------------
    # Internal — cost estimation
    # ------------------------------------------------------------------

    def _estimate_cost(
        self,
        cases: list[TaskCase],
        adapters: dict[str, OpenAICompatAdapter],
    ) -> list[dict[str, Any]]:
        """Compute estimated cost for each model x case combination."""
        rows: list[dict[str, Any]] = []
        for model_key, adapter in adapters.items():
            cfg = adapter.model_config
            total_cost = Decimal("0")
            total_in = 0
            total_out = 0
            case_estimates: list[dict[str, Any]] = []

            for case in cases:
                # Rough estimate: input ~= len(input + stack_context) / 4 tokens
                input_tokens = len(case.input + case.stack_context) // 4
                # Output: assume ~300 tokens per finding x ~5 findings
                output_tokens = 300 * 5

                cost = Decimal(str(input_tokens)) * cfg.input_cost_per_1m / Decimal(
                    "1_000_000"
                ) + Decimal(str(output_tokens)) * cfg.output_cost_per_1m / Decimal("1_000_000")

                total_cost += cost
                total_in += input_tokens
                total_out += output_tokens

                case_estimates.append(
                    {
                        "case_id": case.id,
                        "est_input_tokens": input_tokens,
                        "est_output_tokens": output_tokens,
                        "est_cost_usd": str(cost.quantize(Decimal("0.0000001"))),
                    }
                )

            rows.append(
                {
                    "model": model_key,
                    "model_id": cfg.model_id,
                    "cases": len(cases),
                    "est_total_in": total_in,
                    "est_total_out": total_out,
                    "est_total_cost_usd": str(total_cost.quantize(Decimal("0.0001"))),
                    "case_estimates": case_estimates,
                }
            )

        return rows

    def _print_estimate(self, estimate: list[dict[str, Any]]) -> None:
        """Print cost estimate table to console."""
        table = Table(title="Cost Estimate")
        table.add_column("Model", style="cyan")
        table.add_column("Cases")
        table.add_column("Est. Input Tokens", justify="right")
        table.add_column("Est. Output Tokens", justify="right")
        table.add_column("Est. Cost (USD)", justify="right")

        grand_total = Decimal("0")
        for row in estimate:
            cost = Decimal(row["est_total_cost_usd"])
            grand_total += cost
            table.add_row(
                row["model"],
                str(row["cases"]),
                f"{row['est_total_in']:,}",
                f"{row['est_total_out']:,}",
                f"${cost}",
            )

        table.add_row(
            "[bold]TOTAL[/bold]",
            "",
            "",
            "",
            f"[bold]${grand_total.quantize(Decimal('0.0001'))}[/bold]",
        )
        console.print(table)
        console.print()

    # ------------------------------------------------------------------
    # Internal — execution
    # ------------------------------------------------------------------

    async def _run_cases(
        self,
        cases: list[TaskCase],
        adapters: dict[str, OpenAICompatAdapter],
    ) -> list[dict[str, Any]]:
        """Iterate models x cases with concurrency control."""
        task_config = get_task_config(self.task_name)
        system_prompt = task_config["system_prompt"]

        all_responses: list[dict[str, Any]] = []

        for model_key, adapter in adapters.items():
            console.print(f"[bold]Running model:[/bold] {model_key}")
            model_responses: list[dict[str, Any]] = []

            # Build all requests for this model first
            tasks = []
            for case in cases:
                user_prompt = build_user_prompt(
                    self.task_name,
                    case.input,
                    case.stack_context,
                    ground_truth=case.ground_truth,
                )
                request = LLMRequest(
                    model_id=adapter.model_config.model_id,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=8192,
                    temperature=0.2,
                )
                tasks.append((case.id, request))

            # Execute with concurrency limit
            sem = self._sem

            async def _call(
                case_id: str,
                request: LLMRequest,
            ) -> dict[str, Any]:
                async with sem:
                    start = time.monotonic()
                    response = await adapter.complete(request)

                    # Fix C: Truncation detection + auto-retry with doubled max_tokens
                    # Two triggers:
                    #   1. finish_reason == "length" (API-level truncation)
                    #   2. _is_json_truncated() — some providers return "stop" even when
                    #      the response is cut mid-JSON at max_tokens
                    max_retries = 2
                    retry_count = 0
                    while retry_count < max_retries and (
                        response.finish_reason == "length" or _is_json_truncated(response.text)
                    ):
                        retry_count += 1
                        doubled = request.max_tokens * 2
                        retry_max_tokens = min(doubled, 32768)  # Cap at model max
                        logger.warning(
                            "truncated_response",
                            case_id=case_id,
                            model_id=model_key,
                            tokens_out=response.tokens_out,
                            max_tokens=request.max_tokens,
                            retry_max_tokens=retry_max_tokens,
                            retry=retry_count,
                        )
                        console.print(
                            f"  [yellow]⚠ {case_id} truncated ({response.tokens_out}/{request.max_tokens})"
                            f" — retrying with max_tokens={retry_max_tokens}[/yellow]"
                        )
                        retry_request = LLMRequest(
                            model_id=request.model_id,
                            system_prompt=request.system_prompt,
                            user_prompt=request.user_prompt,
                            max_tokens=retry_max_tokens,
                            temperature=request.temperature,
                        )
                        response = await adapter.complete(retry_request)
                        request = retry_request

                    elapsed = time.monotonic() - start

                    if response.finish_reason == "length":
                        console.print(
                            f"  [red]✗ {case_id} STILL truncated after {max_retries} retries"
                            f" ({response.tokens_out}/{request.max_tokens})[/red]"
                        )
                    elif retry_count > 0:
                        console.print(
                            f"  [green]✓ {case_id} recovered after {retry_count} retry(ies)"
                            f" ({response.tokens_out} tokens)[/green]"
                        )

                    console.print(
                        f"  [{case_id}] {response.tokens_in} in → "
                        f"{response.tokens_out} out | "
                        f"${response.cost_usd} | "
                        f"{response.latency_ms}ms | "
                        f"{response.finish_reason}"
                    )

                    return {
                        "case_id": case_id,
                        "model_id": model_key,
                        "prompt_version": get_prompt_version(self.task_name),
                        "request": {
                            "system_prompt": request.system_prompt,
                            "user_prompt": request.user_prompt,
                            "max_tokens": request.max_tokens,
                            "temperature": request.temperature,
                        },
                        "response": {
                            "text": response.text,
                            "tokens_in": response.tokens_in,
                            "tokens_out": response.tokens_out,
                            "cost_usd": str(response.cost_usd),
                            "latency_ms": response.latency_ms,
                            "finish_reason": response.finish_reason,
                            "error": response.error,
                        },
                        "wall_clock_s": round(elapsed, 2),
                    }

            coros = [_call(cid, req) for cid, req in tasks]
            results = await asyncio.gather(*coros, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error("model_case_failed", error=str(result))
                    continue
                if isinstance(result, dict):
                    model_responses.append(result)

            all_responses.extend(model_responses)

            # Incremental save after each model
            self._save_responses(all_responses, cases)

        return all_responses

    # ------------------------------------------------------------------
    # Internal — persistence
    # ------------------------------------------------------------------

    def _save_responses(
        self,
        responses: list[dict[str, Any]],
        cases: list[TaskCase],
    ) -> Path:
        """Save responses JSON with timestamped filename."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Jakarta timezone (UTC+7)
        now = datetime.now(timezone(timedelta(hours=7)))
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        filename = f"responses_{self.task_name}_{timestamp}.json"
        path = self.output_dir / filename

        # Collect model_ids that actually ran
        model_ids = list(set(r["model_id"] for r in responses)) if responses else []

        payload = {
            "metadata": {
                "task": self.task_name,
                "prompt_version": get_prompt_version(self.task_name),
                "run_at": now.isoformat(),
                "models": model_ids,
                "case_count": len(cases),
                "response_count": len(responses),
            },
            "cases": [c.model_dump() for c in cases],
            "responses": responses,
        }

        path.write_text(json.dumps(payload, indent=2, default=str))
        logger.info("responses_saved", path=str(path), count=len(responses))
        return path


__all__ = ["Runner"]
