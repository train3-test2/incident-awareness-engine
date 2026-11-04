"""Read a server-selected Run archive without opening paths supplied by a browser.

An archive is a retained Run manifest plus its JSONL bytes. A similarly named file,
another Run's manifest, an S3 identity hash, or an ETag is not a replacement.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.collection.s0_validation import manifest_artifact_name
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)

MAX_RAW_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class RawVerification:
    verified: bool
    reason: str | None = None
    details: dict = field(default_factory=dict)


class RawArtifactVerifier:
    def __init__(self, root: Path | None = None, *, artifact_loader=None):
        self.root = root.resolve() if root is not None else None
        self.artifact_loader = artifact_loader
        # This verifier is request-scoped. Never reuse a success after a file changes.
        self._artifacts = {}

    def _read(self, path, limit):
        if self.root is None or not path.resolve().is_relative_to(self.root):
            raise ValueError("archive_path_outside_root")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("archive_size_limit")
        return data

    def _artifact(self, event):
        if self.root is None and self.artifact_loader is None:
            raise ValueError("run_manifest_unavailable")
        # A Run ID is one directory component, never a filesystem path.
        if event.run_id in {".", ".."} or any(c in event.run_id for c in "/\\:"):
            raise ValueError("invalid_archive_run_id")
        extra = {}
        if self.artifact_loader is not None:
            manifest_bytes, data, extra = self.artifact_loader(event)
        else:
            directory = self.root / event.run_id
            manifest_bytes = self._read(directory / "manifest.json", MAX_MANIFEST_BYTES)
        manifest = json.loads(manifest_bytes)
        if manifest.get("run_id") != event.run_id:
            raise ValueError("manifest_run_mismatch")
        items = [
            item
            for item in manifest.get("items", [])
            if item.get("raw_log_id") == event.raw_ref.raw_log_id
            and item.get("segment_no", 1) == event.raw_ref.segment_no
        ]
        if len(items) != 1:
            raise ValueError("manifest_raw_mapping_mismatch")
        item = items[0]
        if (item.get("source"), item.get("layer")) != (event.source, event.source_layer):
            raise ValueError("manifest_source_mismatch")
        name = manifest_artifact_name(item.get("path"), run_id=event.run_id)
        if name != "sysmon-0001.jsonl" or event.raw_ref.segment_no != 1:
            raise ValueError("unsupported_raw_artifact")
        expected = item.get("sha256")
        if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
            raise ValueError("manifest_sha256_missing")
        if self.artifact_loader is None:
            data = self._read(directory / "telemetry" / name, MAX_RAW_BYTES)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES or len(data) > MAX_RAW_BYTES:
            raise ValueError("archive_size_limit")
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected.lower():
            raise ValueError("raw_sha256_mismatch")
        return data.splitlines(), {
            **extra,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "raw_sha256": digest,
            "manifest_run_id": event.run_id,
            "raw_log_id": event.raw_ref.raw_log_id,
            "segment_no": event.raw_ref.segment_no,
            "artifact": f"{event.run_id}/telemetry/{name}",
            "verification_scope": "retained_sysmon_jsonl_not_evtx_authenticity",
        }

    def verify(self, event: NormalizedEvent) -> RawVerification:
        try:
            key = (event.run_id, event.raw_ref.raw_log_id, event.raw_ref.segment_no)
            if key not in self._artifacts:
                self._artifacts[key] = self._artifact(event)
            lines, details = self._artifacts[key]
            ordinal = event.raw_ref.record_no
            if ordinal > len(lines):
                raise ValueError("raw_record_missing")
            line = lines[ordinal - 1]
            data = json.loads(line)
            if not isinstance(data, dict):
                raise TypeError("raw_record_invalid")
            record_id = data.get("RecordId")
            if (
                isinstance(record_id, bool)
                or not isinstance(record_id, int)
                or str(record_id) != event.source_event_id
                or str(record_id) != event.raw_ref.source_record_id
            ):
                raise ValueError("source_record_id_mismatch")
            if (event.raw_ref.parser_id, event.raw_ref.parser_version) != (
                "sysmon-normalizer",
                "v0.3",
            ):
                raise ValueError("parser_version_unsupported")
            normalizer = {
                "process_create": normalize_sysmon_process_create,
                "network_connection": normalize_sysmon_network_connection,
            }.get(event.event_type)
            if normalizer is None or event.source != "sysmon":
                raise ValueError("raw_event_type_unsupported")
            normalized = normalizer(
                SysmonJsonlRecord(record_no=ordinal, data=data),
                context=SysmonNormalizationContext(
                    run_id=event.run_id,
                    raw_log_id=event.raw_ref.raw_log_id,
                    segment_no=event.raw_ref.segment_no,
                ),
            )
            if normalized != event:
                raise ValueError("raw_normalized_event_mismatch")
            return RawVerification(
                True,
                details={**details, "raw_record_sha256": hashlib.sha256(line).hexdigest()},
            )
        except FileNotFoundError:
            return RawVerification(False, "run_archive_file_missing")
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            # Return only code-owned reason codes; never parser messages containing raw values.
            code = str(error)
            if not re.fullmatch(r"[a-z0-9_]+", code):
                code = "raw_archive_invalid"
            return RawVerification(False, code)
        except OSError:
            return RawVerification(False, "run_archive_unreadable")
