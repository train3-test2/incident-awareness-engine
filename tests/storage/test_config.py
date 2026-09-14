import pytest

from incident_awareness.storage.config import DATABASE_URL_ENV, DatabaseConfig


def test_database_config_rejects_missing_database_url() -> None:
    with pytest.raises(RuntimeError, match=DATABASE_URL_ENV):
        DatabaseConfig.from_environment({})


@pytest.mark.parametrize(
    "url",
    [
        "mysql://user:password@localhost:3306/incident_awareness",
        "postgresql://localhost",
    ],
)
def test_database_config_rejects_invalid_database_url(url: str) -> None:
    with pytest.raises(ValueError, match="PostgreSQL"):
        DatabaseConfig.from_environment({DATABASE_URL_ENV: url})


def test_database_config_accepts_postgresql_database_url() -> None:
    url = "postgresql://test_user:test_password@localhost:5432/incident_awareness_test"

    config = DatabaseConfig.from_environment({DATABASE_URL_ENV: url})

    assert config.url == url
