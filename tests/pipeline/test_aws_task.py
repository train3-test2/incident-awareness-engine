from pathlib import Path

import pytest

from incident_awareness.pipeline import aws_task


class _Paginator:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self._pages = pages
        self.arguments: dict[str, str] | None = None

    def paginate(self, **kwargs: str) -> list[dict[str, object]]:
        self.arguments = kwargs
        return self._pages


class _S3Client:
    def __init__(self, pages: list[dict[str, object]], contents: dict[str, bytes]) -> None:
        self.paginator = _Paginator(pages)
        self.contents = contents
        self.downloads: list[tuple[str, str]] = []

    def get_paginator(self, operation_name: str) -> _Paginator:
        assert operation_name == "list_objects_v2"
        return self.paginator

    def download_file(self, bucket: str, key: str, filename: str) -> None:
        assert bucket == "input-bucket"
        self.downloads.append((bucket, key))
        Path(filename).write_bytes(self.contents[key])


def test_parse_s3_input_location_accepts_documented_run_prefix() -> None:
    location = aws_task.parse_s3_input_location("s3://input-bucket/first-cycle/RUN-20260920-001/")

    assert location == aws_task.S3InputLocation(
        bucket="input-bucket",
        prefix="first-cycle/RUN-20260920-001/",
        run_id="RUN-20260920-001",
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://input-bucket/first-cycle/RUN-20260920-001/",
        "s3://input-bucket/other-prefix/RUN-20260920-001/",
        "s3://input-bucket/first-cycle/RUN-20260920-001/extra/",
        "s3://input-bucket/first-cycle/",
    ],
)
def test_parse_s3_input_location_rejects_non_contract_uri(value: str) -> None:
    with pytest.raises(ValueError, match="S3"):
        aws_task.parse_s3_input_location(value)


def test_download_s3_inputs_preserves_relative_paths(tmp_path: Path) -> None:
    location = aws_task.parse_s3_input_location("s3://input-bucket/first-cycle/RUN-20260920-001/")
    prefix = location.prefix
    client = _S3Client(
        pages=[
            {
                "Contents": [
                    {"Key": prefix},
                    {"Key": f"{prefix}run_metadata.json"},
                    {"Key": f"{prefix}fast/hits.jsonl"},
                ]
            }
        ],
        contents={
            f"{prefix}run_metadata.json": b"metadata",
            f"{prefix}fast/hits.jsonl": b"hits",
        },
    )

    aws_task.download_s3_inputs(location, tmp_path, s3_client=client)

    assert client.paginator.arguments == {"Bucket": "input-bucket", "Prefix": prefix}
    assert (tmp_path / "run_metadata.json").read_bytes() == b"metadata"
    assert (tmp_path / "fast" / "hits.jsonl").read_bytes() == b"hits"


def test_download_s3_inputs_rejects_key_outside_requested_prefix(tmp_path: Path) -> None:
    location = aws_task.parse_s3_input_location("s3://input-bucket/first-cycle/RUN-20260920-001/")
    client = _S3Client(
        pages=[{"Contents": [{"Key": "first-cycle/RUN-20260920-002/run_metadata.json"}]}],
        contents={},
    )

    with pytest.raises(ValueError, match="outside"):
        aws_task.download_s3_inputs(location, tmp_path, s3_client=client)


def test_main_downloads_contract_paths_and_invokes_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[object] = []
    location = aws_task.S3InputLocation(
        bucket="input-bucket",
        prefix="first-cycle/RUN-20260920-001/",
        run_id="RUN-20260920-001",
    )
    monkeypatch.setenv(
        "INCIDENT_AWARENESS_S3_INPUT_URI", "s3://input-bucket/first-cycle/RUN-20260920-001/"
    )
    monkeypatch.setenv("INCIDENT_AWARENESS_ENTITY_ID", "WIN-01")
    monkeypatch.setenv("INCIDENT_AWARENESS_DECISION_ID", "D-001")
    monkeypatch.setenv("INCIDENT_AWARENESS_DECISION_CONFIG_VERSION", "parallel-v0.2")
    monkeypatch.setattr(aws_task, "_INPUT_ROOT", Path("/downloaded-inputs"))
    monkeypatch.setattr(aws_task, "download_s3_inputs", lambda *args: received.append(args))
    monkeypatch.setattr(
        aws_task, "_validate_downloaded_run_metadata", lambda *args: received.append(args)
    )
    monkeypatch.setattr(aws_task, "pipeline_main", lambda argv: received.append(argv) or 0)

    assert aws_task.main() == 0
    assert received[0] == (location, Path("/downloaded-inputs"))
    assert received[1] == (Path("/downloaded-inputs"), "RUN-20260920-001")
    input_root = Path("/downloaded-inputs")
    assert received[2] == [
        "--run-metadata",
        str(input_root / "run_metadata.json"),
        "--manifest",
        str(input_root / "manifest.json"),
        "--sysmon-jsonl",
        str(input_root / "telemetry" / "sysmon-0001.jsonl"),
        "--fast-hits",
        str(input_root / "fast" / "hits.jsonl"),
        "--fast-trace",
        str(input_root / "fast" / "trace.json"),
        "--fast-selection",
        str(input_root / "fast" / "selection.json"),
        "--fusion-config",
        "/app/configs/fusion/fusion_config_s0_pair_v0.1.yaml",
        "--entity-id",
        "WIN-01",
        "--decision-id",
        "D-001",
        "--decision-config-version",
        "parallel-v0.2",
    ]
