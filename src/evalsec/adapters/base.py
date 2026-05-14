"""Base adapter protocol and shared data models for LLM API calls.

All LLM adapters (OpenRouter/DeepSeek via openai-compat, Anthropic direct)
implement the `Adapter` protocol defined here.
"""

from __future__ import annotations

from abc import abstractmethod
from decimal import Decimal
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class ModelConfig(BaseModel):
    """Configuration for a single model — pricing, endpoint, provider."""

    model_config = ConfigDict(strict=True, extra="forbid")

    model_id: str = Field(..., description="Model identifier used in API calls")
    provider: str = Field(..., description="One of: openrouter, deepseek, anthropic")
    base_url: str = Field(..., description="API base URL")
    input_cost_per_1m: Decimal = Field(
        ...,
        description="Cost per 1M input tokens in USD",
        ge=Decimal("0"),
    )
    output_cost_per_1m: Decimal = Field(
        ...,
        description="Cost per 1M output tokens in USD",
        ge=Decimal("0"),
    )


class LLMRequest(BaseModel):
    """A prompt to send to an LLM."""

    model_config = ConfigDict(strict=True, extra="forbid")

    model_id: str = Field(..., description="Which model to call")
    system_prompt: str = Field(..., description="System-level instruction")
    user_prompt: str = Field(..., description="The actual user prompt / input")
    max_tokens: int = Field(default=1024, description="Maximum output tokens", ge=1, le=16384)
    temperature: float = Field(default=0.2, description="Sampling temperature", ge=0.0, le=2.0)


class LLMResponse(BaseModel):
    """The response from an LLM API call, including cost and metadata."""

    model_config = ConfigDict(strict=True, extra="forbid")

    text: str = Field(..., description="Generated response text")
    tokens_in: int = Field(..., description="Prompt tokens consumed", ge=0)
    tokens_out: int = Field(..., description="Completion tokens consumed", ge=0)
    cost_usd: Decimal = Field(
        ...,
        description="Computed cost in USD from actual token usage",
        ge=Decimal("0"),
    )
    latency_ms: int = Field(..., description="Round-trip latency in milliseconds", ge=0)
    model_id: str = Field(..., description="Model that generated this response")
    provider: str = Field(..., description="Provider that served this request")
    finish_reason: str = Field(..., description="One of: stop, length, content_filter, error")
    error: str | None = Field(default=None, description="Error message if the call failed")


@runtime_checkable
class Adapter(Protocol):
    """Protocol that all LLM adapters must satisfy.

    Implementations:
    - `OpenAICompatAdapter` — OpenRouter + DeepSeek via openai-compatible API
    - `AnthropicDirectAdapter` — Claude Opus via Anthropic SDK
    """

    model_config: ModelConfig

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a completion request to the LLM and return the response.

        Must handle:
        - HTTP errors → log + re-raise
        - Timeouts → retry via tenacity
        - Rate limits → retry with exponential backoff
        - Token counting → use actual tokens returned by API
        - Cost calculation → use ModelConfig pricing x actual tokens
        """
        ...
