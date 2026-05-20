"""LLM model registry — hardcoded model configs for v0.1.0.

Pricing is hardcoded here (not configurable via YAML) to reduce surface area.
Prices are per 1M tokens in USD, sourced from provider pricing pages.
"""

from decimal import Decimal

from evalsec.adapters.base import ModelConfig

# ------------------------------------------------------------------
# Pricing source (v0.1.0):
#   OpenRouter: https://openrouter.ai/models (as of 2026-05)
#   DeepSeek:   https://api-docs.deepseek.com/quick_start/pricing
# ------------------------------------------------------------------

BENCHMARK_MODELS: dict[str, ModelConfig] = {
    "claude_sonnet_46": ModelConfig(
        model_id="anthropic/claude-sonnet-4-6",
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        input_cost_per_1m=Decimal("3.00"),
        output_cost_per_1m=Decimal("15.00"),
        max_context_length=200_000,
    ),
    "kimi_k2_thinking": ModelConfig(
        model_id="moonshotai/kimi-k2-thinking",
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        input_cost_per_1m=Decimal("1.50"),
        output_cost_per_1m=Decimal("7.50"),
        max_context_length=262_144,
    ),
    "qwen_3_5": ModelConfig(
        model_id="qwen/qwen3.5-plus-20260420",
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        input_cost_per_1m=Decimal("0.40"),
        output_cost_per_1m=Decimal("2.40"),
        max_context_length=131_072,
    ),
    "deepseek_v4_pro": ModelConfig(
        model_id="deepseek-chat",
        provider="deepseek",
        base_url="https://api.deepseek.com/v1",
        input_cost_per_1m=Decimal("0.50"),
        output_cost_per_1m=Decimal("2.00"),
        max_context_length=64_000,
    ),
}

JUDGE_MODELS: dict[str, ModelConfig] = {
    "claude_opus_47": ModelConfig(
        model_id="anthropic/claude-opus-4.7",
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        input_cost_per_1m=Decimal("5.00"),
        output_cost_per_1m=Decimal("25.00"),
        max_context_length=200_000,
    ),
    "deepseek_v4_pro": ModelConfig(
        model_id="deepseek-chat",
        provider="deepseek",
        base_url="https://api.deepseek.com/v1",
        input_cost_per_1m=Decimal("0.50"),
        output_cost_per_1m=Decimal("2.00"),
        max_context_length=64_000,
    ),
}

# Combined dict for lookup convenience (e.g. grader validation).
ALL_MODELS: dict[str, ModelConfig] = {**BENCHMARK_MODELS, **JUDGE_MODELS}

__all__ = [
    "ALL_MODELS",
    "BENCHMARK_MODELS",
    "JUDGE_MODELS",
    "ModelConfig",
]
