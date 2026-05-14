"""OpenAI-compatible adapter for OpenRouter (3 models) and DeepSeek (1 model).

Uses httpx.AsyncClient directly (not the openai SDK's sync mode).
Implements the Adapter protocol from evalsec.adapters.base.
"""

from __future__ import annotations

import time
from decimal import Decimal
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from evalsec.adapters.base import Adapter, LLMRequest, LLMResponse, ModelConfig

logger = structlog.get_logger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    """Retry only on timeouts, rate limits (429), and server errors (5xx)."""
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


# 3 attempts: initial 2s, then 4s, then 8s exponential backoff
_DEFAULT_RETRY = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=8),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)


class OpenAICompatAdapter(Adapter):
    """Adapter for OpenAI-compatible chat completion APIs.

    Works for:
    - OpenRouter (base_url: https://openrouter.ai/api/v1)
    - DeepSeek (base_url: https://api.deepseek.com/v1)

    Does NOT use the `openai` SDK. Uses raw httpx.AsyncClient for
    better timeout control and lower overhead.
    """

    def __init__(
        self,
        model_config: ModelConfig,
        api_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.model_config = model_config
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            limits=httpx.Limits(max_keepalive_connections=5),
        )

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a chat completion request, retry on failure, return parsed response."""
        payload = self._build_payload(request)
        headers = self._build_headers()

        start_ns = time.monotonic_ns()

        try:
            response = await self._send_request(payload, headers)
        except httpx.HTTPStatusError as exc:
            logger.error(
                "llm_request_failed",
                model_id=request.model_id,
                status_code=exc.response.status_code,
                response_text=exc.response.text[:500],
            )
            return self._error_response(request, str(exc))
        except Exception as exc:
            logger.error(
                "llm_request_exception",
                model_id=request.model_id,
                error=str(exc),
            )
            return self._error_response(request, str(exc))

        latency_ms = (time.monotonic_ns() - start_ns) // 1_000_000

        return self._parse_response(request, response, latency_ms)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payload(self, request: LLMRequest) -> dict[str, Any]:
        """Construct the JSON body for the /chat/completions endpoint."""
        return {
            "model": self.model_config.model_id,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

    def _build_headers(self) -> dict[str, str]:
        """Construct HTTP headers for the API call."""
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        # OpenRouter-specific headers (harmless for DeepSeek)
        if "openrouter" in self.model_config.base_url:
            headers["HTTP-Referer"] = "https://evalsec.farhan.ngenz.org"
            headers["X-Title"] = "evalsec"
        return headers

    @_DEFAULT_RETRY
    async def _send_request(
        self,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> httpx.Response:
        """POST to /chat/completions with tenacity retry wrapping."""
        url = f"{self.model_config.base_url.rstrip('/')}/chat/completions"
        response = await self._client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response

    def _parse_response(
        self,
        request: LLMRequest,
        response: httpx.Response,
        latency_ms: int,
    ) -> LLMResponse:
        """Parse the API response JSON into an LLMResponse."""
        data = response.json()

        # Navigate the OpenAI-compatible response structure
        choice = data["choices"][0]
        text = choice.get("message", {}).get("content", "") or ""

        usage = data.get("usage", {})
        tokens_in = usage.get("prompt_tokens", 0)
        tokens_out = usage.get("completion_tokens", 0)

        finish_reason = choice.get("finish_reason", "stop") or "stop"

        # Compute cost from actual token usage
        cost = self._compute_cost(tokens_in, tokens_out)

        return LLMResponse(
            text=text,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost,
            latency_ms=latency_ms,
            model_id=self.model_config.model_id,
            provider=self.model_config.provider,
            finish_reason=finish_reason,
        )

    def _compute_cost(self, tokens_in: int, tokens_out: int) -> Decimal:
        """Compute cost in USD from actual token usage and model pricing."""
        input_cost = (
            Decimal(str(tokens_in)) * self.model_config.input_cost_per_1m / Decimal("1_000_000")
        )
        output_cost = (
            Decimal(str(tokens_out)) * self.model_config.output_cost_per_1m / Decimal("1_000_000")
        )
        return (input_cost + output_cost).quantize(Decimal("0.0000001"))

    def _error_response(self, request: LLMRequest, error: str) -> LLMResponse:
        """Build an LLMResponse for a failed request."""
        return LLMResponse(
            text="",
            tokens_in=0,
            tokens_out=0,
            cost_usd=Decimal("0"),
            latency_ms=0,
            model_id=self.model_config.model_id,
            provider=self.model_config.provider,
            finish_reason="error",
            error=error,
        )

    async def __aenter__(self) -> OpenAICompatAdapter:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.aclose()
