# Phase 3.2 — Pydantic Models Design (Pre-Review)

## 1. `src/evalsec/adapters/base.py`

### `ModelConfig`
```python
class ModelConfig(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    model_id: str                              # e.g. "anthropic/claude-sonnet-4-6"
    provider: str                              # "openrouter" | "deepseek" | "anthropic"
    base_url: str                              # API endpoint
    input_cost_per_1m: Decimal                 # cost per 1M input tokens
    output_cost_per_1m: Decimal                # cost per 1M output tokens
```

### `LLMRequest`
```python
class LLMRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    model_id: str                              # which model to call
    system_prompt: str                         # system instruction
    user_prompt: str                           # the actual prompt
    max_tokens: int = 1024                     # max output tokens
    temperature: float = 0.2                   # lower = more deterministic
```

### `LLMResponse`
```python
class LLMResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    text: str                                  # generated response text
    tokens_in: int                             # prompt tokens used
    tokens_out: int                            # completion tokens used
    cost_usd: Decimal                          # computed from pricing + actual tokens
    latency_ms: int                            # round-trip time
    model_id: str                              # which model responded
    provider: str                              # which provider
    finish_reason: str                         # "stop" | "length" | "error"
    error: Optional[str] = None                # error message if failed
```

### `Adapter` (Protocol class)
```python
class Adapter(Protocol):
    """Protocol for LLM adapters. Implementations: OpenAIChatCompat, AnthropicDirect."""
    
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a prompt to the LLM and return the response."""
        ...
```

---

## 2. `src/evalsec/grader.py` (skeleton — full impl in 3.7)

### `RubricScore`
```python
class RubricScore(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    dimension: str                             # e.g. "reachability_reasoning"
    score: int                                 # actual score awarded
    max_score: int                             # max possible for this dimension
    reasoning: Optional[str] = None            # judge's explanation
```

### `Score`
```python
class Score(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    total: float                               # weighted total (0-100)
    pass1_score: float                         # regex match % × pass1_weight
    pass2_score: float                         # judge score × pass2_weight
    rubric_scores: List[RubricScore]           # per-dimension breakdown
    judge_error: Optional[str] = None          # if judge parse failed
```

### `GradedResponse`
```python
class GradedResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    
    case_id: str                               # links back to test case
    model_id: str                              # which model was graded
    prompt_version: str                        # prompt version used
    response_text: str                         # the raw LLM response
    score: Score                               # the computed score
    graded_at: datetime                        # ISO timestamp
```

---

## Key Design Decisions

1. **`cost_usd` uses `Decimal`** — not `float`. Floats lose pennies on cumulative cost; the dashboard needs exact totals per system prompt requirement.

2. **`Adapter` is a `Protocol`** (PEP 544) — not an ABC. Structural subtyping is more Pythonic and doesn't force inheritance. Both `OpenAICompatAdapter` and `AnthropicDirectAdapter` will satisfy this protocol.

3. **`Score` combines both passes** — pass 1 (regex) + pass 2 (judge) weighted scores are in one object. Default weights: pass1 = 20%, pass2 = 80%.

4. **No Enums for v0.1.0** — `provider` and `finish_reason` are plain strings. Enums add maintenance overhead for marginal benefit at this stage.

5. **`GradedResponse` includes full `response_text`** — not just the score. This enables audit trail and re-grading if rubric changes.
