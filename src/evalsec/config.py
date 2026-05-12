"""Application configuration via environment variables."""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables.

    Reads from .env file at project root (gitignored).
    All values can be overridden by actual environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # === LLM API Keys ===
    openrouter_api_key: Optional[str] = Field(
        default=None,
        description="OpenRouter API key for Sonnet, Kimi, Qwen models",
    )
    deepseek_api_key: Optional[str] = Field(
        default=None,
        description="DeepSeek API key for DeepSeek V4 Pro",
    )
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key for judge model (Claude Opus 4.7)",
    )

    # === AWS Configuration ===
    aws_region: str = Field(
        default="ap-southeast-3",
        description="AWS region (default: Jakarta)",
    )


# Module-level singleton — instantiated once on import.
# Call settings.xxx anywhere in the codebase.
settings = Settings()  # type: ignore[call-arg]
