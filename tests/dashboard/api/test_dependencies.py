from collections.abc import Iterator

import pytest

from incident_awareness.dashboard.api import dependencies
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.storage.config import DATABASE_URL_ENV


class FakeConnection:
    def __init__(self) -> None:
        self.closes = 0

    def close(self) -> None:
        self.closes += 1


def test_create_app_does_not_open_database_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connect_calls = 0

    def unexpected_connect(*args: object, **kwargs: object) -> None:
        nonlocal connect_calls
        del args, kwargs
        connect_calls += 1
        raise AssertionError("application creation must not connect to PostgreSQL")

    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
    monkeypatch.setattr(dependencies.psycopg, "connect", unexpected_connect)

    # When
    app = create_app()

    # Then
    assert app is not None
    assert connect_calls == 0


def test_database_connection_dependency_closes_request_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    database_url = "postgresql://dashboard-user:secret-value@database/dashboard"
    connection = FakeConnection()
    connect_urls: list[str] = []

    def connect(url: str) -> FakeConnection:
        connect_urls.append(url)
        return connection

    monkeypatch.setenv(DATABASE_URL_ENV, database_url)
    monkeypatch.setattr(dependencies.psycopg, "connect", connect)

    # When
    dependency: Iterator[object] = dependencies.get_database_connection()
    provided_connection = next(dependency)
    with pytest.raises(StopIteration):
        next(dependency)

    # Then
    assert provided_connection is connection
    assert connect_urls == [database_url]
    assert connection.closes == 1


def test_event_repository_dependency_reuses_request_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    connection = FakeConnection()
    repository_connections: list[FakeConnection] = []

    class FakeEventRepository:
        def __init__(self, provided_connection: FakeConnection) -> None:
            repository_connections.append(provided_connection)

    monkeypatch.setattr(dependencies, "EventRepository", FakeEventRepository)

    # When
    repository = dependencies.get_event_repository(connection)

    # Then
    assert isinstance(repository, FakeEventRepository)
    assert repository_connections == [connection]
