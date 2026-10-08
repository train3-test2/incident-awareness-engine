from pathlib import Path

import pytest

from incident_awareness.dashboard import startup
from incident_awareness.dashboard.evaluation_read_model import (
    EVALUATION_SNAPSHOT_PATH_ENV,
)
from incident_awareness.dashboard.startup import (
    EVALUATION_SNAPSHOT_S3_URI_ENV,
    S3EvaluationSnapshotLocation,
    materialize_evaluation_snapshot,
    parse_evaluation_snapshot_s3_uri,
    prepare_evaluation_snapshot,
)


class _RecordingS3Client:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.downloads: list[tuple[str, str, Path]] = []
        self.target_during_download: bytes | None = None
        self.expected_target: Path | None = None

    def download_file(self, bucket: str, key: str, filename: str) -> None:
        temporary_path = Path(filename)
        self.downloads.append((bucket, key, temporary_path))
        if self.expected_target is not None:
            self.target_during_download = self.expected_target.read_bytes()
        temporary_path.write_bytes(self.content)


class _FailingS3Client:
    def download_file(self, _bucket: str, _key: str, filename: str) -> None:
        Path(filename).write_bytes(b"partial")
        raise RuntimeError("download failed")


def _environment(target: Path, source: str) -> dict[str, str]:
    return {
        EVALUATION_SNAPSHOT_PATH_ENV: str(target),
        EVALUATION_SNAPSHOT_S3_URI_ENV: source,
    }


def test_parses_an_exact_evaluation_snapshot_s3_object_uri() -> None:
    # Given
    source = "s3://bucket-name/evaluation/snapshot-001/snapshot.json"

    # When
    result = parse_evaluation_snapshot_s3_uri(source)

    # Then
    assert result == S3EvaluationSnapshotLocation(
        bucket="bucket-name",
        key="evaluation/snapshot-001/snapshot.json",
    )


@pytest.mark.parametrize(
    "source",
    [
        "https://bucket-name/evaluation/snapshot.json",
        "s3:///evaluation/snapshot.json",
        "s3://bucket-name",
        "s3://bucket-name/evaluation/snapshot-001/",
        "s3://bucket-name/evaluation//snapshot.json",
        "s3://bucket-name/evaluation/../snapshot.json",
        "s3://bucket-name/evaluation/snapshot.json?versionId=1",
        "s3://bucket-name/evaluation/snapshot.json#fragment",
        "not a URI",
    ],
)
def test_rejects_non_exact_or_malformed_s3_uris(source: str) -> None:
    # Given
    invalid_source = source

    # When
    with pytest.raises(ValueError) as error:
        parse_evaluation_snapshot_s3_uri(invalid_source)

    # Then
    assert EVALUATION_SNAPSHOT_S3_URI_ENV in str(error.value)


def test_downloads_bytes_to_a_unique_sibling_and_atomically_replaces_target(
    tmp_path: Path,
) -> None:
    # Given
    target = tmp_path / "current-snapshot.json"
    target.write_bytes(b"old-snapshot")
    client = _RecordingS3Client(b"new-snapshot")
    client.expected_target = target
    location = S3EvaluationSnapshotLocation("bucket-name", "evaluation/snapshot.json")

    # When
    materialize_evaluation_snapshot(location, target, s3_client=client)

    # Then
    assert target.read_bytes() == b"new-snapshot"
    assert client.target_during_download == b"old-snapshot"
    assert len(client.downloads) == 1
    bucket, key, temporary_path = client.downloads[0]
    assert (bucket, key) == ("bucket-name", "evaluation/snapshot.json")
    assert temporary_path.parent == target.parent
    assert temporary_path != target
    assert not temporary_path.exists()
    assert list(tmp_path.iterdir()) == [target]


def test_uses_the_default_boto3_s3_client_when_none_is_injected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Given
    target = tmp_path / "current-snapshot.json"
    client = _RecordingS3Client(b"snapshot")
    services: list[str] = []

    def create_client(service: str):
        services.append(service)
        return client

    monkeypatch.setattr(startup.boto3, "client", create_client)
    location = S3EvaluationSnapshotLocation("bucket-name", "evaluation/snapshot.json")

    # When
    materialize_evaluation_snapshot(location, target)

    # Then
    assert services == ["s3"]
    assert target.read_bytes() == b"snapshot"


def test_publishes_invalid_json_bytes_without_interpreting_them(tmp_path: Path) -> None:
    # Given
    target = tmp_path / "current-snapshot.json"
    content = b"not-json\x00unchanged"
    client = _RecordingS3Client(content)
    environment = _environment(
        target,
        "s3://bucket-name/evaluation/snapshot-001/snapshot.json",
    )

    # When
    prepared = prepare_evaluation_snapshot(environment, s3_client=client)

    # Then
    assert prepared is True
    assert target.read_bytes() == content


@pytest.mark.parametrize("source", [None, "", "   "])
def test_missing_or_blank_source_removes_a_stale_target(
    source: str | None,
    tmp_path: Path,
) -> None:
    # Given
    target = tmp_path / "current-snapshot.json"
    target.write_bytes(b"stale")
    environment = {EVALUATION_SNAPSHOT_PATH_ENV: str(target)}
    if source is not None:
        environment[EVALUATION_SNAPSHOT_S3_URI_ENV] = source

    # When
    prepared = prepare_evaluation_snapshot(environment)

    # Then
    assert prepared is False
    assert not target.exists()


def test_download_failure_removes_partial_file_and_stale_target(tmp_path: Path) -> None:
    # Given
    target = tmp_path / "current-snapshot.json"
    target.write_bytes(b"stale")
    environment = _environment(
        target,
        "s3://bucket-name/evaluation/snapshot-001/snapshot.json",
    )

    # When
    prepared = prepare_evaluation_snapshot(environment, s3_client=_FailingS3Client())

    # Then
    assert prepared is False
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []


def test_failed_preparation_disables_snapshot_path_and_starts_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot_path = "/evaluation/current-snapshot.json"
    paths_at_startup: list[str | None] = []
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, snapshot_path)
    monkeypatch.setattr(startup, "prepare_evaluation_snapshot", lambda: False)
    monkeypatch.setattr(
        startup,
        "start_dashboard_server",
        lambda: paths_at_startup.append(startup.os.environ.get(EVALUATION_SNAPSHOT_PATH_ENV)),
    )

    # When
    startup.main()

    # Then
    assert paths_at_startup == [None]
    assert EVALUATION_SNAPSHOT_PATH_ENV not in startup.os.environ


def test_unexpected_preparation_error_disables_snapshot_path_and_starts_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot_path = "/evaluation/current-snapshot.json"
    paths_at_startup: list[str | None] = []
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, snapshot_path)

    def fail_prepare() -> bool:
        raise RuntimeError("unexpected preparation failure")

    monkeypatch.setattr(startup, "prepare_evaluation_snapshot", fail_prepare)
    monkeypatch.setattr(
        startup,
        "start_dashboard_server",
        lambda: paths_at_startup.append(startup.os.environ.get(EVALUATION_SNAPSHOT_PATH_ENV)),
    )

    # When
    startup.main()

    # Then
    assert paths_at_startup == [None]
    assert EVALUATION_SNAPSHOT_PATH_ENV not in startup.os.environ


def test_stale_unlink_failure_still_disables_snapshot_serving_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Given
    target = tmp_path / "current-snapshot.json"
    target.write_bytes(b"stale")
    paths_at_startup: list[str | None] = []
    original_unlink = Path.unlink

    def fail_target_unlink(
        path: Path,
        missing_ok: bool = False,
    ) -> None:
        if path == target:
            raise PermissionError("target is locked")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(target))
    monkeypatch.delenv(EVALUATION_SNAPSHOT_S3_URI_ENV, raising=False)
    monkeypatch.setattr(Path, "unlink", fail_target_unlink)
    monkeypatch.setattr(
        startup,
        "start_dashboard_server",
        lambda: paths_at_startup.append(startup.os.environ.get(EVALUATION_SNAPSHOT_PATH_ENV)),
    )

    # When
    startup.main()

    # Then
    assert target.read_bytes() == b"stale"
    assert paths_at_startup == [None]
    assert EVALUATION_SNAPSHOT_PATH_ENV not in startup.os.environ


def test_successful_preparation_preserves_snapshot_path_and_starts_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot_path = "/evaluation/current-snapshot.json"
    paths_at_startup: list[str | None] = []
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, snapshot_path)
    monkeypatch.setattr(startup, "prepare_evaluation_snapshot", lambda: True)
    monkeypatch.setattr(
        startup,
        "start_dashboard_server",
        lambda: paths_at_startup.append(startup.os.environ.get(EVALUATION_SNAPSHOT_PATH_ENV)),
    )

    # When
    startup.main()

    # Then
    assert paths_at_startup == [snapshot_path]
    assert startup.os.environ[EVALUATION_SNAPSHOT_PATH_ENV] == snapshot_path


def test_uvicorn_start_uses_process_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    executions: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        startup.os,
        "execvp",
        lambda executable, arguments: executions.append((executable, arguments)),
    )

    # When
    startup.start_dashboard_server()

    # Then
    assert executions == [
        (
            "uvicorn",
            [
                "uvicorn",
                "incident_awareness.dashboard.api.app:app",
                "--host",
                "0.0.0.0",
                "--port",
                "8080",
            ],
        )
    ]
