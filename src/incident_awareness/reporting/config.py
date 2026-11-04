"""Server-only MonoRouter configuration. Secrets never appear in representations."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import SecretStr

ENDPOINT = "https://monogpt.kr/api/monorouter/v1/anthropic/v1/messages"
REQUEST_MODEL = "claude-haiku-4.5"
RESPONSE_MODEL = "claude-haiku-4-5-20251001"


@dataclass(frozen=True)
class MonoRouterSettings:
    endpoint: str = ENDPOINT
    model: str = REQUEST_MODEL
    expected_response_model: str = RESPONSE_MODEL
    connect_timeout: float = 3
    read_timeout: float = 25
    max_tokens: int = 1200
    enabled: bool = False
    development: bool = False
    api_key: SecretStr = field(default_factory=lambda: SecretStr(""), repr=False)

    def __post_init__(self):
        parts = urlsplit(self.endpoint)
        approved = urlsplit(ENDPOINT)
        if (
            (parts.scheme, parts.netloc, parts.path)
            != (approved.scheme, approved.netloc, approved.path)
            or parts.query
            or parts.fragment
        ):
            raise ValueError("Unapproved MonoRouter endpoint")
        for model in (self.model, self.expected_response_model):
            if not re.fullmatch(r"claude-[a-zA-Z0-9._-]{1,100}", model):
                raise ValueError("Invalid MonoRouter model configuration")
        if not 0 < self.connect_timeout <= 10 or not 0 < self.read_timeout <= 45:
            raise ValueError("Invalid MonoRouter timeout configuration")
        if type(self.max_tokens) is not int or not 1 <= self.max_tokens <= 4096:
            raise ValueError("Invalid MonoRouter token configuration")

    @classmethod
    def from_environment(cls):
        try:
            return cls(
                endpoint=os.getenv("IAE_MONOROUTER_ENDPOINT", ENDPOINT),
                model=os.getenv("IAE_MONOROUTER_MODEL", REQUEST_MODEL),
                expected_response_model=os.getenv("IAE_MONOROUTER_RESPONSE_MODEL", RESPONSE_MODEL),
                connect_timeout=float(os.getenv("IAE_MONOROUTER_CONNECT_TIMEOUT", "3")),
                read_timeout=float(os.getenv("IAE_MONOROUTER_READ_TIMEOUT", "25")),
                max_tokens=int(os.getenv("IAE_MONOROUTER_MAX_TOKENS", "1200")),
                enabled=os.getenv("IAE_MONOROUTER_ENABLED") == "1",
                development=os.getenv("APP_ENV") == "development",
                api_key=SecretStr(os.getenv("IAE_MONOROUTER_API_KEY", "")),
            )
        except (ValueError, TypeError):
            # Do not propagate validation inputs, URLs, or credential-bearing exceptions.
            raise ValueError("Invalid server MonoRouter configuration; values withheld") from None


def report_store_path() -> Path:
    configured = os.getenv("IAE_REPORT_STORE_PATH")
    return (
        Path(configured)
        if configured
        else (Path(__file__).resolve().parents[3] / "build" / "grounded-reports" / "drafts.sqlite3")
    )
