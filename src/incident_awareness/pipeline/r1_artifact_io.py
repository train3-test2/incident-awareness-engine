"""Filesystem durability helpers shared by R1 artifact writers."""

from __future__ import annotations

import errno
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

_UNSUPPORTED_DIRECTORY_SYNC_ERRORS = {
    errno.EINVAL,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
}


def utc_now() -> datetime:
    """Return the raw UTC system-clock observation."""

    return datetime.now(UTC)


def ceil_utc_clock_observation(field_name: str, value: datetime) -> datetime:
    """Validate an internal UTC clock observation and ceil it to milliseconds."""

    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone information")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC")
    normalized = value.astimezone(UTC)
    remainder = normalized.microsecond % 1000
    if remainder == 0:
        return normalized
    return normalized + timedelta(microseconds=1000 - remainder)


def fsync_parent_directory(path: Path) -> None:
    """Persist a published directory entry where directory fsync is supported.

    Windows does not provide the POSIX directory-descriptor contract used here,
    so file-level fsync plus the atomic publication primitive remains its stated
    durability boundary. On POSIX, unsupported-filesystem errors are tolerated;
    other open/fsync failures are real publication errors and propagate.
    """

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path.parent, flags)
    except OSError as error:
        if error.errno in _UNSUPPORTED_DIRECTORY_SYNC_ERRORS:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno in _UNSUPPORTED_DIRECTORY_SYNC_ERRORS:
                return
            raise
    finally:
        os.close(descriptor)


__all__ = ["ceil_utc_clock_observation", "fsync_parent_directory", "utc_now"]
