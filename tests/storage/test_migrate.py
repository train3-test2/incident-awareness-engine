from incident_awareness.storage.migrate import apply_first_cycle_migration


class _Cursor:
    def __init__(self, row: tuple[object, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class _Connection:
    def __init__(self, *, already_applied: bool) -> None:
        self._already_applied = already_applied
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, query: str, params: tuple[object, ...] = ()) -> _Cursor:
        self.queries.append((query, params))
        if "SELECT 1 FROM schema_migrations" in query:
            return _Cursor((1,) if self._already_applied else None)
        return _Cursor(None)


def test_applies_first_cycle_migration_and_records_it() -> None:
    connection = _Connection(already_applied=False)

    applied = apply_first_cycle_migration(connection)

    assert applied is True
    assert any("CREATE TABLE runs" in query for query, _ in connection.queries)
    assert connection.queries[-1] == (
        "INSERT INTO schema_migrations (migration_id) VALUES (%s)",
        ("001_first_cycle",),
    )


def test_skips_first_cycle_migration_when_it_is_already_recorded() -> None:
    connection = _Connection(already_applied=True)

    applied = apply_first_cycle_migration(connection)

    assert applied is False
    assert not any("CREATE TABLE runs" in query for query, _ in connection.queries)
