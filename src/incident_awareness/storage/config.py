import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

DATABASE_URL_ENV = "INCIDENT_AWARENESS_DATABASE_URL"
_POSTGRESQL_SCHEMES = frozenset({"postgres", "postgresql"})


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    """PostgreSQL 연결 정보를 환경 변수에서 읽는 설정 계약이다."""

    url: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "DatabaseConfig":
        values = os.environ if environment is None else environment
        url = values.get(DATABASE_URL_ENV)

        if not url:
            raise RuntimeError(f"{DATABASE_URL_ENV} 환경 변수가 필요합니다.")

        parsed = urlparse(url)
        if parsed.scheme not in _POSTGRESQL_SCHEMES or not parsed.path.strip("/"):
            raise ValueError(f"{DATABASE_URL_ENV}은 PostgreSQL 연결 URL이어야 합니다.")

        return cls(url=url)
