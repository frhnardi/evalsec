#!/usr/bin/env python3
"""One-off test script for Phase 3.4 checkpoint — judge model via OpenRouter.

Sends a sample grading prompt to Claude Opus 4.7 and attempts to parse
the response as a JSON Score object. This simulates what the Pass 2
grader will do during a real benchmark run.

Usage:
    uv run python scripts/test_judge.py

Requires OPENROUTER_API_KEY in .env.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from evalsec.adapters import ALL_MODELS
from evalsec.adapters.base import LLMRequest
from evalsec.adapters.openai_compat import OpenAICompatAdapter
from evalsec.config import settings

# ---------------------------------------------------------------------------
# Judge-specific prompt template (simplified version of the real grader)
# ---------------------------------------------------------------------------

JUDGE_SYSTEM_PROMPT = """You are a strict DevSecOps evaluator. Grade the assistant's response
against each rubric dimension below. Respond ONLY with valid JSON in this exact format:

{
  "rubric_scores": [
    {"dimension": "reachability_reasoning", "score": 0-25, "reasoning": "..."},
    {"dimension": "prioritization", "score": 0-25, "reasoning": "..."},
    {"dimension": "actionability", "score": 0-25, "reasoning": "..."},
    {"dimension": "conciseness", "score": 0-25, "reasoning": "..."}
  ]
}

Do not include markdown code blocks. Return raw JSON only."""

SAMPLE_USER_PROMPT = """# Task: Trivy Vulnerability Triage

You are a DevSecOps engineer responding to a critical vulnerability report.

## Context
A container image scan has found CVE-2021-44228 (Log4Shell) in the application.
The service is a public-facing API gateway that processes user-supplied data.

## Your Response to Grade
"The Log4Shell vulnerability (CVE-2021-44228) is present and exploitable in this
context. Since this is a public-facing API gateway, remote code execution is possible
via unauthenticated requests. Immediate actions required:
1. Deploy WAF rule to block JNDI injection patterns
2. Upgrade log4j-core to 2.17.0+ within 72 hours
3. Verify no other services share the vulnerable library

For the non-exploitable findings: the PIL/Pillow issue affects only a dev-only
utility that is not reachable from the network, and runc is affected but mitigated
by the host's AppArmor profile."

## Rubric
- reachability_reasoning (0-25): Correctly identifies exploitable vs non-exploitable
- prioritization (0-25): Orders fixes by business impact
- actionability (0-25): Provides specific, implementable steps
- conciseness (0-25): No irrelevant information"""


async def test_judge() -> None:
    """Call the judge model and attempt to parse its JSON response."""
    model_config = ALL_MODELS.get("claude_opus_47")
    if model_config is None:
        print("  ✘ Model 'claude_opus_47' not found in model registry.")
        return

    api_key = settings.openrouter_api_key
    if not api_key:
        print("  ✘ OPENROUTER_API_KEY not set in .env")
        return

    print(f"  Judge model : {model_config.model_id}")
    print(f"  Provider    : {model_config.provider}")
    print(
        f"  Pricing     : ${model_config.input_cost_per_1m} / ${model_config.output_cost_per_1m} per 1M"
    )
    print()

    adapter = OpenAICompatAdapter(model_config=model_config, api_key=api_key)

    request = LLMRequest(
        model_id=model_config.model_id,
        system_prompt=JUDGE_SYSTEM_PROMPT,
        user_prompt=SAMPLE_USER_PROMPT,
        max_tokens=1024,
        temperature=0.0,
    )

    print("  Sending grading request to judge...")
    response = await adapter.complete(request)
    await adapter._client.aclose()

    print()
    print(f"  Finish reason : {response.finish_reason}")
    print(f"  Tokens in     : {response.tokens_in}")
    print(f"  Tokens out    : {response.tokens_out}")
    print(f"  Cost USD      : ${response.cost_usd}")
    print(f"  Latency       : {response.latency_ms} ms")
    print()
    print("  Raw response text:")
    print(f"    {response.text[:500]}")
    print()

    if response.error:
        print(f"  ✘ FAILED — judge error: {response.error}")
        return

    # Attempt to extract JSON from the response
    json_str = _extract_json(response.text)
    if not json_str:
        print("  ✘ FAILED — no valid JSON found in judge response.")
        return

    try:
        parsed: dict[str, Any] = json.loads(json_str)
        scores: list[dict[str, Any]] = parsed.get("rubric_scores", [])

        if len(scores) != 4:
            print(f"  ⚠ Expected 4 rubric scores, got {len(scores)}")
        else:
            print("  ✔ JSON parsed successfully:")
            for item in scores:
                dim = item.get("dimension", "?")
                score = item.get("score", 0)
                max_s = 25
                bar = "█" * score + "░" * (max_s - score)
                print(f"      {dim:30s}  {bar}  {score}/{max_s}")
            print()

        total = sum(s.get("score", 0) for s in scores)
        print(f"  Total score  : {total}/100")
        print()
        print("  ✔ SUCCESS — judge returned valid Score object.")
    except json.JSONDecodeError as exc:
        print(f"  ✘ FAILED — JSON parse error: {exc}")
        print(f"  Extracted JSON string: {json_str[:300]}")


def _extract_json(text: str) -> str | None:
    """Extract JSON object from model response, handling markdown fences."""
    # Try to find content inside ```json ... ``` fences
    m = re.search(r"```(?:json)?\s*\n?({.*?})\s*\n?```", text, re.DOTALL)
    if m:
        return m.group(1)
    # Try to find a top-level JSON object directly
    m = re.search(r"\{.*\"rubric_scores\".*\}", text, re.DOTALL)
    if m:
        return m.group(0)
    return None


def main() -> None:
    asyncio.run(test_judge())


if __name__ == "__main__":
    main()
