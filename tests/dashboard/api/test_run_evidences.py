"""GET /runs/{run_id}/evidences over real R1 writer archives and a fake read-only connection."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.dashboard.api import dependencies
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import get_dashboard_evidence_reader
from incident_awareness.dashboard.evidence_read_model import (
    MAX_EVIDENCE_ARCHIVE_BYTES,
    MAX_SUMMARY_ARCHIVE_BYTES,
    DashboardEvidenceReader,
)
from incident_awareness.pipeline.r1_artifacts import run_and_write_r1_evidence_artifacts
from incident_awareness.pipeline.r1_production import (
    R1ProductionConfig,
    generate_r1_production_archive,
)
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.r1_archive_publication_repository import (
    R1ArchivePublicationRepository,
)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "evidence" / "r1_pair004_selector_events.jsonl"
CONFIG = R1ProductionConfig(
    family_id="remote_management",
    approved_policy_id="r1-remote-management-approved-lineage",
    approved_policy_version="v0.3",
    approved_policy_config_hash="b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2",
    archive_bucket="fixture-bucket",
)
SENSITIVE_MARKERS = (
    "fixture-bucket",
    "archive/first-cycle",
    "s3://",
    "last_error",
    "attempt_count",
)


def fixture_events() -> tuple[NormalizedEvent, ...]:
    return tuple(
        NormalizedEvent.model_validate(json.loads(line))
        for line in FIXTURE.read_text(encoding="utf-8").splitlines()
    )


@dataclass(frozen=True)
class Archive:
    run_id: str
    evidence: bytes
    summary: bytes

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.evidence).hexdigest()

    @property
    def summary_sha256(self) -> str:
        return hashlib.sha256(self.summary).hexdigest()

    def lines(self) -> list[dict[str, object]]:
        return [json.loads(line) for line in self.evidence.decode("utf-8").splitlines()]

    def rewritten(self, lines: list[dict[str, object]]) -> "Archive":
        """Re-encode edited Evidence and re-bind every hash, isolating one content defect."""
        evidence = "".join(json.dumps(line) + "\n" for line in lines).encode("utf-8")
        summary = json.loads(self.summary)
        summary["evidence_count"] = len(lines)
        summary["evidence_artifact_sha256"] = hashlib.sha256(evidence).hexdigest()
        return Archive(self.run_id, evidence, json.dumps(summary).encode("utf-8"))


# Function scope: the Event type vocabulary comes from the function-scoped autouse fixture.
@pytest.fixture
def archive(tmp_path) -> Archive:
    events = fixture_events()
    generated = generate_r1_production_archive(
        events,
        run_id=events[0].run_id,
        output_directory=tmp_path / "r1",
        config=CONFIG,
    )
    publication = generated.to_publication()
    return Archive(events[0].run_id, publication.evidence_content, publication.summary_content)


@pytest.fixture
def empty_archive(tmp_path) -> Archive:
    written = run_and_write_r1_evidence_artifacts(
        (),
        run_id="RUN-20261018-990",
        output_directory=tmp_path,
    )
    return Archive(
        "RUN-20261018-990",
        written.evidence_path.read_bytes(),
        written.summary_path.read_bytes(),
    )


class Connection:
    """Answers the two read statements; records every call."""

    def __init__(self, archive_row=None, provenance=(), error=None):
        self.archive_row = archive_row
        self.provenance = list(provenance)
        self.error = error
        self.calls = []
        self._result = None

    def execute(self, query, params=()):
        self.calls.append((query, params))
        if self.error:
            raise self.error
        self._result = "provenance" if "FROM events" in query else "archive"
        return self

    def fetchone(self):
        return self.archive_row

    def fetchall(self):
        return self.provenance


def archive_row(archive: Archive | None, *, run_id: str, status="published", payload=True):
    if archive is None:
        return (run_id, None, None, None, None, None, None, None)
    return (
        run_id,
        status,
        archive.evidence_sha256,
        archive.summary_sha256,
        len(archive.evidence),
        len(archive.summary),
        archive.evidence if payload else None,
        archive.summary if payload else None,
    )


def stored(archive: Archive, *, run_id=None, host=None, skip=()):
    rows = []
    for line in archive.lines():
        for event_id in line["event_ids"]:
            if event_id not in skip and event_id not in {row[0] for row in rows}:
                rows.append((event_id, run_id or archive.run_id, host or line["entity_id"]))
    return rows


def client(connection):
    app = create_app()
    app.dependency_overrides[get_dashboard_evidence_reader] = lambda: DashboardEvidenceReader(
        R1ArchivePublicationRepository(connection), EventRepository(connection)
    )
    return TestClient(app)


def get(connection, run_id, query=""):
    return client(connection).get(f"/runs/{run_id}/evidences{query}")


def test_published_archive_returns_verified_evidence_with_event_provenance(archive):
    # Given
    connection = Connection(archive_row(archive, run_id=archive.run_id), stored(archive))
    # When
    response = get(connection, archive.run_id)
    # Then
    assert response.status_code == 200
    body = response.json()
    assert body["availability"] == "published"
    assert body["archive_status"] == "published"
    assert (body["source"], body["evidence_scope"], body["fusion_input"]) == (
        "r1_archive_publication",
        "offline_whole_episode",
        False,
    )
    assert (body["timestamp_meaning"], body["entity_scope"]) == ("event_time", "run")
    assert body["total"] == 2
    assert body["evidence_sha256"] == archive.evidence_sha256
    assert body["entity_ids"] == ["PAIR004-DERIVED-HOST"]
    assert body["unstored_event_reference_count"] == 0
    lines = archive.lines()
    assert [item["evidence_id"] for item in body["items"]] == [
        line["evidence_id"] for line in lines
    ]
    for item, line in zip(body["items"], lines, strict=True):
        assert item["events"] == [{"event_id": e, "stored": True} for e in line["event_ids"]]
        assert item["timestamp"].endswith("Z")
        assert item["extractor_version"] == "r1-v0.1"
    lineage = body["items"][0]
    assert lineage["evidence_type"] == "remote_session_process_lineage_deviation"
    assert lineage["policy"] == {
        "policy_id": lines[0]["features"]["policy_id"],
        "version": lines[0]["features"]["version"],
        "config_hash": lines[0]["features"]["config_hash"],
    }
    assert body["items"][1]["policy"] is None
    assert all(item["withheld_field_count"] == 0 for item in body["items"])
    archive_query, archive_params = connection.calls[0]
    assert "FROM r1_archive_publications" not in archive_query.split("FROM runs")[0]
    assert "bucket" not in archive_query and "object_prefix" not in archive_query
    assert "last_error" not in archive_query
    assert archive_params == (
        MAX_EVIDENCE_ARCHIVE_BYTES,
        MAX_SUMMARY_ARCHIVE_BYTES,
        MAX_EVIDENCE_ARCHIVE_BYTES,
        MAX_SUMMARY_ARCHIVE_BYTES,
        archive.run_id,
    )


def test_response_never_exposes_raw_bytes_storage_location_or_unlisted_fields(archive):
    # Given
    connection = Connection(archive_row(archive, run_id=archive.run_id), stored(archive))
    # When
    text = get(connection, archive.run_id).text
    # Then
    for marker in SENSITIVE_MARKERS:
        assert marker not in text
    assert archive.evidence.decode("utf-8") not in text
    assert '"features"' not in text
    assert "summary_sha256" not in text
    assert "lineage_inputs" not in text


def test_completed_archive_with_zero_evidence_is_distinct_from_no_archive(empty_archive):
    # Given
    zero = Connection(archive_row(empty_archive, run_id=empty_archive.run_id))
    none = Connection(archive_row(None, run_id="RUN-NO-ARCHIVE"))
    # When
    zero_body = get(zero, empty_archive.run_id).json()
    none_body = get(none, "RUN-NO-ARCHIVE").json()
    # Then
    assert (zero_body["availability"], zero_body["total"], zero_body["items"]) == (
        "published",
        0,
        [],
    )
    assert (none_body["availability"], none_body["archive_status"]) == ("no_archive", None)
    assert none_body["total"] is None
    assert len(none.calls) == 1


@pytest.mark.parametrize("status", ["pending", "retryable", "failed"])
def test_unpublished_archive_is_withheld_without_reading_payload(archive, status):
    # Given
    connection = Connection(
        archive_row(archive, run_id=archive.run_id, status=status, payload=False)
    )
    # When
    response = get(connection, archive.run_id)
    # Then
    body = response.json()
    assert response.status_code == 200
    assert (body["availability"], body["archive_status"]) == ("not_published", status)
    assert (body["items"], body["total"], body["evidence_sha256"]) == ([], None, None)
    assert len(connection.calls) == 1


def test_unpublished_payload_returned_by_storage_is_rejected(archive):
    # Given
    connection = Connection(archive_row(archive, run_id=archive.run_id, status="pending"))
    # When / Then
    assert get(connection, archive.run_id).json() == {"detail": "Evidence read failed"}


def test_unknown_run_is_not_found():
    # Given
    connection = Connection(None)
    # When
    response = get(connection, "RUN-MISSING")
    # Then
    assert (response.status_code, response.json()) == (404, {"detail": "Run not found"})


def tamper(archive: Archive, kind: str) -> Archive:
    lines = archive.lines()
    if kind == "evidence_bytes":
        return Archive(
            archive.run_id, archive.evidence.replace(b"r1-v0.1", b"r1-v0.2"), archive.summary
        )
    if kind == "summary_binding":
        evidence = archive.evidence + b" "
        return Archive(archive.run_id, evidence, archive.summary)
    if kind == "non_utc":
        lines[0]["timestamp"] = "2026-10-08T17:10:30.538000+09:00"
    elif kind == "missing_field":
        del lines[0]["entity_id"]
    elif kind == "extra_field":
        lines[0]["raw_command_line"] = "secret"
    elif kind == "no_events":
        lines[0]["event_ids"] = []
    elif kind == "duplicate_id":
        lines = [lines[0], lines[0]]
    elif kind == "other_run_evidence":
        lines[0]["run_id"] = "RUN-OTHER"
    elif kind == "unsupported_type":
        lines[0]["evidence_type"] = "process_start"
    return archive.rewritten(lines)


@pytest.mark.parametrize(
    "kind",
    [
        "evidence_bytes",
        "summary_binding",
        "non_utc",
        "missing_field",
        "extra_field",
        "no_events",
        "duplicate_id",
        "other_run_evidence",
        "unsupported_type",
    ],
)
def test_corrupted_archive_fails_closed(archive, kind):
    # Given
    damaged = tamper(archive, kind)
    row = archive_row(damaged, run_id=archive.run_id)
    if kind == "evidence_bytes":
        row = (*row[:2], archive.evidence_sha256, *row[3:])  # stored hash of the original bytes
    connection = Connection(row, stored(archive))
    # When
    response = get(connection, archive.run_id)
    # Then
    assert (response.status_code, response.json()) == (
        500,
        {"detail": "Stored Evidence archive is invalid"},
    )
    assert "PAIR004" not in response.text


def test_archive_of_another_run_is_rejected(archive):
    # Given: the bytes are valid but describe another Run.
    connection = Connection(archive_row(archive, run_id="RUN-REQUESTED"), stored(archive))
    # When
    response = get(connection, "RUN-REQUESTED")
    # Then
    assert response.json() == {"detail": "Stored Evidence archive is invalid"}


@pytest.mark.parametrize("mismatch", ["entity", "run"])
def test_stored_event_of_another_entity_or_run_fails_closed(archive, mismatch):
    # Given
    rows = (
        stored(archive, host="OTHER-HOST")
        if mismatch == "entity"
        else stored(archive, run_id="RUN-X")
    )
    connection = Connection(archive_row(archive, run_id=archive.run_id), rows)
    # When
    response = get(connection, archive.run_id)
    # Then
    assert (response.status_code, response.json()) == (
        500,
        {"detail": "Stored Evidence provenance is inconsistent"},
    )


def test_unstored_event_reference_is_reported_without_a_link_target(archive):
    # Given
    missing = archive.lines()[1]["event_ids"][0]
    connection = Connection(
        archive_row(archive, run_id=archive.run_id), stored(archive, skip={missing})
    )
    # When
    body = get(connection, archive.run_id).json()
    # Then
    references = [ref for item in body["items"] for ref in item["events"]]
    assert {"event_id": missing, "stored": False} in references
    assert body["unstored_event_reference_count"] == 1
    assert body["availability"] == "published"


def test_archive_over_the_read_limit_is_not_loaded(archive):
    # Given: storage withholds the payload because it exceeds the byte limits.
    connection = Connection(archive_row(archive, run_id=archive.run_id, payload=False))
    # When
    response = get(connection, archive.run_id)
    # Then
    assert response.json() == {"detail": "Stored Evidence archive exceeds the read limit"}


def test_unlisted_features_and_malformed_technique_ids_are_withheld(archive):
    # Given
    lines = archive.lines()
    lines[0]["features"]["process_command_line"] = "not public"
    lines[0]["attack_technique_ids"] = ["T1021.006", "<script>"]
    edited = archive.rewritten(lines)
    connection = Connection(archive_row(edited, run_id=archive.run_id), stored(archive))
    # When
    item = get(connection, archive.run_id).json()["items"][0]
    # Then
    assert item["policy"] is None
    assert item["attack_technique_ids"] == ["T1021.006"]
    assert item["withheld_field_count"] == 5
    assert "not public" not in json.dumps(item)


def test_page_limits_items_but_verifies_the_whole_archive(archive):
    # Given
    connection = Connection(archive_row(archive, run_id=archive.run_id), stored(archive))
    # When
    body = get(connection, archive.run_id, "?limit=1&offset=1").json()
    # Then
    assert (body["total"], body["limit"], body["offset"]) == (2, 1, 1)
    assert [item["evidence_id"] for item in body["items"]] == [archive.lines()[1]["evidence_id"]]


@pytest.mark.parametrize(
    ("error", "status", "detail"),
    [
        (psycopg.OperationalError("down"), 503, "Evidence database is unavailable"),
        (
            psycopg.errors.UndefinedTable("missing"),
            503,
            "Evidence archive storage is not provisioned",
        ),
        (psycopg.errors.InsufficientPrivilege("denied"), 500, "Evidence read failed"),
    ],
)
def test_database_errors_are_distinct_and_never_empty_success(error, status, detail):
    # Given
    connection = Connection(error=error)
    # When
    response = get(connection, "RUN-ANY")
    # Then
    assert (response.status_code, response.json()) == (status, {"detail": detail})
    assert "missing" not in response.text and "denied" not in response.text


@pytest.mark.parametrize(
    "path",
    [
        "/runs/%20RUN/evidences",
        "/runs/RUN%20/evidences",
        "/runs/" + "R" * 513 + "/evidences",
        "/runs/RUN/evidences?limit=0",
        "/runs/RUN/evidences?limit=201",
        "/runs/RUN/evidences?offset=-1",
        "/runs/RUN/evidences?event_type=process_create",
    ],
)
def test_invalid_request_does_not_open_database(monkeypatch, path):
    # Given
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid request must not connect")

    monkeypatch.setattr(dependencies.psycopg, "connect", forbidden)
    # When / Then
    assert TestClient(create_app()).get(path).status_code == 422


def test_reader_connection_is_read_only_bounded_and_closed(monkeypatch):
    # Given
    opened = []

    class Closing(Connection):
        closed = False

        def close(self):
            self.closed = True

    def connect(url, **kwargs):
        connection = Closing(archive_row(None, run_id="RUN-1"))
        opened.append((kwargs, connection))
        return connection

    monkeypatch.setattr(
        dependencies.DatabaseConfig, "from_environment", lambda: type("C", (), {"url": "x"})()
    )
    monkeypatch.setattr(dependencies.psycopg, "connect", connect)
    # When
    response = TestClient(create_app()).get("/runs/RUN-1/evidences")
    # Then
    assert response.json()["availability"] == "no_archive"
    kwargs, connection = opened[0]
    assert "default_transaction_read_only=on" in kwargs["options"]
    assert "statement_timeout=5000" in kwargs["options"]
    assert kwargs["connect_timeout"] == 2
    assert connection.closed is True
