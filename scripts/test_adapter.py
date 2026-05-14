#!/usr/bin/env python3
"""One-off test script for Phase 3.3 checkpoint.

Usage:
    uv run python scripts/test_adapter.py [model_key]

Defaults to the cheapest model (deepseek_v4_pro at $0.50/$2.00 per 1M tokens).
Set the corresponding API key in .env before running.

Examples:
    uv run python scripts/test_adapter.py
    uv run python scripts/test_adapter.py claude_sonnet_46
    uv run python scripts/test_adapter.py qwen_3_5
"""

from __future__ import annotations

import asyncio
import sys

from evalsec.adapters import ALL_MODELS
from evalsec.adapters.base import LLMRequest
from evalsec.adapters.openai_compat import OpenAICompatAdapter
from evalsec.config import settings

# ---------------------------------------------------------------------------
# Model → API key mapping
# ---------------------------------------------------------------------------
PROVIDER_KEY_MAP: dict[str, str] = {
    "openrouter": settings.openrouter_api_key or "",
    "deepseek": settings.deepseek_api_key or "",
}


def _resolve_api_key(model_key: str) -> str | None:
    """Return the API key for a model, or None if not set."""
    config = ALL_MODELS.get(model_key)
    if config is None:
        return None
    key = PROVIDER_KEY_MAP.get(config.provider)
    if not key:
        return None
    return key


async def test_model(model_key: str) -> None:
    """Run a single test call against the given model and print results."""
    model_config = ALL_MODELS.get(model_key)
    if model_config is None:
        print(f"  ✘ Unknown model key '{model_key}'. Available keys:")
        for k in ALL_MODELS:
            cfg = ALL_MODELS[k]
            print(
                f"      {k}  →  {cfg.model_id}  (${cfg.input_cost_per_1m}/${cfg.output_cost_per_1m} per 1M)"
            )
        return

    api_key = _resolve_api_key(model_key)
    if not api_key:
        print(
            f"  ✘ No API key found for provider '{model_config.provider}'. "
            f"Set the appropriate key in .env and try again."
        )
        return

    print(f"  Model      : {model_config.model_id}")
    print(f"  Provider   : {model_config.provider}")
    print(f"  Base URL   : {model_config.base_url}")
    print(
        f"  Pricing    : ${model_config.input_cost_per_1m} / ${model_config.output_cost_per_1m} per 1M tokens"
    )
    print()

    adapter = OpenAICompatAdapter(model_config=model_config, api_key=api_key)

    request = LLMRequest(
        model_id=model_config.model_id,
        system_prompt="You are a helpful assistant.",
        user_prompt='Reply with exactly: "Hello from evalsec. API is working."',
        max_tokens=64,
        temperature=0.0,
    )

    print("  Sending request...")
    response = await adapter.complete(request)
    await adapter._client.aclose()

    print()
    print(f"  Finish reason : {response.finish_reason}")
    print(f"  Tokens in     : {response.tokens_in}")
    print(f"  Tokens out    : {response.tokens_out}")
    print(f"  Cost USD      : ${response.cost_usd}")
    print(f"  Latency       : {response.latency_ms} ms")
    print(f"  Model ID      : {response.model_id}")
    print(f"  Provider      : {response.provider}")
    if response.error:
        print(f"  Error         : {response.error}")
    print()
    print("  Response text:")
    for line in response.text.strip().split("\n"):
        print(f"    {line}")
    print()

    if response.error:
        print("  ✘ FAILED — see error above.")
    elif response.text.strip():
        print("  ✔ SUCCESS — response received with cost attached.")
    else:
        print("  ⚠ Empty response text (no error, but no content either).")


def main() -> None:
    model_key = sys.argv[1] if len(sys.argv) > 1 else "deepseek_v4_pro"
    asyncio.run(test_model(model_key))


if __name__ == "__main__":
    main()
