"""Best-effort input identities; never persist raw filesystem paths or S3 keys."""

import hashlib
import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.pipeline_telemetry import PipelineTelemetryInputIdentity
from incident_awareness.pipeline.timeseries_telemetry import _log_failure

# An explicit unknown S3 identity must not silently fall back to file-content identity.
# The scoped context preserves the Worker's existing three-argument business callback.
_INPUT_IDENTITY: ContextVar[tuple[PipelineTelemetryInputIdentity | None] | None] = ContextVar(
    "pipeline_telemetry_input_identity", default=None
)


def s3_input_identity(bucket: str, key: str, e_tag: str) -> PipelineTelemetryInputIdentity | None:
    """Hash the same bucket/decoded-key/ETag tuple used by the Receipt identity."""
    try:
        if not all(isinstance(value, str) and value for value in (bucket, key, e_tag)):
            raise ValueError("S3 identity requires bucket, key and ETag")
        if e_tag.startswith('"') and e_tag.endswith('"'):
            e_tag = e_tag[1:-1]  # S3 listing quotes vs Event Notification's unquoted ETag.
        if not e_tag:
            raise ValueError("S3 identity requires a nonempty ETag")
        # Length-delimited JSON avoids delimiter collisions in arbitrary object keys.
        encoded = json.dumps([bucket, key, e_tag], ensure_ascii=False, separators=(",", ":"))
        return PipelineTelemetryInputIdentity(
            kind="s3_object_sha256_v1", sha256=hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        )
    except Exception:  # noqa: BLE001 - input fingerprint errors cannot fail business execution.
        _log_failure("S3 input identity")
        return None


@contextmanager
def s3_telemetry_input_context(bucket: str, key: str, e_tag: str) -> Iterator[None]:
    identity = None
    try:
        identity = s3_input_identity(bucket, key, e_tag)
    except Exception:  # noqa: BLE001 - protect the Worker even from an identity helper defect.
        _log_failure("S3 input identity bootstrap")
    with telemetry_input_context(identity):
        yield


@contextmanager
def telemetry_input_context(identity: PipelineTelemetryInputIdentity | None) -> Iterator[None]:
    """Bind only this input invocation; restore context on success or business failure."""
    token = None
    try:
        token = _INPUT_IDENTITY.set((identity,))
    except Exception:  # noqa: BLE001 - optional context must not change business execution.
        _log_failure("input identity context")
    try:
        yield
    finally:
        if token is not None:
            try:
                _INPUT_IDENTITY.reset(token)
            except Exception:  # noqa: BLE001 - preserve a business exception during cleanup.
                _log_failure("input identity context cleanup")


def resolve_telemetry_input_identity(
    path: Path, records: Sequence[SysmonJsonlRecord], verified_sha256: str | None = None
) -> PipelineTelemetryInputIdentity | None:
    """Fingerprint accepted JSONL bytes only when they match the loaded raw records.

    A file changed after validation is unknown, not relabelled as a different input.
    Compare physical line ordinals, not Standalone's chronological processing order.
    This extra streaming read is outside latency measurement and has no DB writes.
    """
    try:
        supplied = _INPUT_IDENTITY.get()
        if supplied is not None:
            return supplied[0]
        digest = hashlib.sha256()
        ordered = iter(sorted(records, key=lambda record: record.record_no))
        with path.open("rb") as stream:
            for record_no, raw_line in enumerate(stream, 1):
                expected = next(ordered, None)
                data = json.loads(raw_line)
                if (
                    expected is None
                    or expected.record_no != record_no
                    or json.dumps(data, sort_keys=True, separators=(",", ":"))
                    != json.dumps(expected.data, sort_keys=True, separators=(",", ":"))
                ):
                    raise ValueError("fingerprinted input no longer matches accepted records")
                digest.update(raw_line)
        if next(ordered, None) is not None:
            raise ValueError("fingerprinted input is missing accepted records")
        if verified_sha256 is not None and digest.hexdigest() != verified_sha256:
            raise ValueError("fingerprinted bytes differ from the validated manifest checksum")
        return PipelineTelemetryInputIdentity(
            kind="file_content_sha256_v1", sha256=digest.hexdigest()
        )
    except Exception:  # noqa: BLE001 - unknown identity is conservative, not a business failure.
        _log_failure("file input identity")
        return None
