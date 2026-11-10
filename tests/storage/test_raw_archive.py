"""Isolated synthetic bytes; never modify a source archive or live database."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from incident_awareness.reporting.public_view import public_report_view
from incident_awareness.storage.raw_archive import (
    AtomicRawMirror,
    RawArchiveError,
    RawCollectionIdentity,
    RawRunArchive,
    canonical_bytes,
    collection_identity,
    raw_collection_context,
    sha256,
)


def archive(run="RUN-20990101-991"):
    content = (
        canonical_bytes(
            {
                "EventId": 1,
                "RecordId": 9001,
                "Computer": "SYNTHETIC-HOST",
                "TimeCreated": "2026-01-01T00:00:00Z",
                "EventData": {
                    "UtcTime": "2026-01-01 00:00:00.000",
                    "Image": "C:\\Synthetic\\cmd.exe",
                    "CommandLine": "cmd.exe /c echo synthetic",
                },
            }
        )
        + b"\n"
    )
    raw_id = f"RAW-{run}-SYSMON-001"
    manifest = canonical_bytes(
        {
            "run_id": run,
            "items": [
                {
                    "raw_log_id": raw_id,
                    "path": f"raw/{run}/telemetry/sysmon-0001.jsonl",
                    "sha256": sha256(content),
                    "source": "sysmon",
                    "layer": "raw_telemetry",
                }
            ],
        }
    )
    return RawRunArchive(
        run,
        raw_id,
        content,
        manifest,
        b"[]",
        "s0-v0.1",
        "a" * 64,
        {"source": "sysmon", "target_host": "SYNTHETIC-HOST"},
    ).validate()


def test_atomic_mirror_deduplicates_content_but_preserves_run_references(tmp_path):
    first, second = archive(), archive("RUN-20990101-992")
    assert first.content == second.content and first.manifest_content != second.manifest_content
    mirror = AtomicRawMirror(tmp_path)
    mirror.publish(first)
    mirror.publish(second)
    assert len(list((tmp_path / "sha256").rglob("*.jsonl"))) == 1
    assert len(list((tmp_path / "manifests").rglob("*.json"))) == 2
    assert len(list(tmp_path.rglob(".raw-pending-*"))) == 0


def test_concurrent_publish_and_duplicate_retries_never_replace_bytes(tmp_path):
    item = archive()
    mirror = AtomicRawMirror(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda _: mirror.publish(item), range(24)))
    mirror.verify(item)
    assert len(list((tmp_path / "sha256").rglob("*.jsonl"))) == 1


def test_conflicting_or_corrupted_mirror_is_not_overwritten(tmp_path):
    item = archive()
    mirror = AtomicRawMirror(tmp_path)
    mirror.publish(item)
    path = tmp_path / next(iter(mirror.files(item)))
    path.write_bytes(b"TEST-ONLY: deliberately corrupted owned fixture")
    with pytest.raises(RawArchiveError, match="archive_mirror_content_conflict"):
        mirror.publish(item)
    assert path.read_bytes() == b"TEST-ONLY: deliberately corrupted owned fixture"


def test_hash_collision_is_not_an_identity_shortcut(tmp_path, monkeypatch):
    from incident_awareness.storage import raw_archive

    first = archive()
    second = replace(first, content=b"different synthetic bytes")
    # Both now address the same content path, as an actual SHA-256 collision would.
    monkeypatch.setattr(raw_archive, "sha256", lambda _: "0" * 64)
    mirror = AtomicRawMirror(tmp_path)
    mirror.publish(first)
    with pytest.raises(RawArchiveError, match="archive_mirror_content_conflict"):
        mirror.publish(second)
    assert (tmp_path / next(iter(mirror.files(first)))).read_bytes() == first.content


def test_permission_or_disk_failure_leaves_no_partial_target(tmp_path, monkeypatch):
    from incident_awareness.storage import raw_archive

    def denied(*args):
        raise PermissionError("TEST FIXTURE")

    monkeypatch.setattr(raw_archive.os, "link", denied)
    with pytest.raises(RawArchiveError, match="archive_mirror_write_failed"):
        AtomicRawMirror(tmp_path).publish(archive())
    assert not list(tmp_path.rglob("*.jsonl"))
    assert not list(tmp_path.rglob(".raw-pending-*"))


def test_run_scope_rejects_path_injection(tmp_path):
    with pytest.raises(RawArchiveError, match="invalid_archive_run_id"):
        AtomicRawMirror(tmp_path).publish(replace(archive(), run_id="../other"))


def test_link_below_root_is_not_followed_outside(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    try:
        (root / "evidence").symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("symlink creation is not permitted for this account")
        import _winapi

        # A junction needs no symlink privilege and is the Windows escape to reject.
        _winapi.CreateJunction(str(outside), str(root / "evidence"))
    with pytest.raises(RawArchiveError, match="archive_path_outside_root"):
        AtomicRawMirror(root).publish(archive())
    assert not list(outside.iterdir())


@pytest.mark.parametrize("part", ["raw", "manifest", "evidence"])
def test_manifest_or_payload_corruption_is_not_accepted(part):
    item = archive()
    if part == "raw":
        item = replace(item, content=b"different")
    if part == "manifest":
        manifest = json.loads(item.manifest_content)
        manifest["run_id"] = "RUN-20990101-999"
        item = replace(item, manifest_content=canonical_bytes(manifest))
    if part == "evidence":
        item = replace(item, evidence_content=b"{}")
    with pytest.raises(RawArchiveError):
        item.validate()


def test_collection_context_is_attempt_scoped_and_restored():
    first = RawCollectionIdentity("ING-TEST", "test-bucket", "test-key", "opaque-etag")
    assert collection_identity() is None
    with raw_collection_context(first):
        assert collection_identity() == first
        with raw_collection_context(None):
            assert collection_identity() is None
        assert collection_identity() == first
    assert collection_identity() is None


def test_public_views_redact_sensitive_normalized_fields_without_mutating_snapshots():
    private = {
        "analysis": {
            "source_events": [
                {
                    "event_id": "TEST",
                    "source_event_id": "9001",
                    "process": {"command_line": "PRIVATE-COMMAND"},
                    "network": {"src_ip": "10.1.2.3"},
                    "user": "PRIVATE-USER",
                }
            ]
        },
        "source_snapshot_sha256": "UNCHANGED-SOURCE-DIGEST",
    }
    public = public_report_view(private)
    serialized = json.dumps(public)
    assert "PRIVATE" not in serialized and "10.1.2.3" not in serialized
    assert public["analysis"]["source_events"][0]["source_event_id"] == "9001"
    assert public["source_snapshot_sha256"] == "UNCHANGED-SOURCE-DIGEST"
    assert private["analysis"]["source_events"][0]["process"]["command_line"] == "PRIVATE-COMMAND"
