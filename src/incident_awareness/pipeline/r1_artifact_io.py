"""Filesystem durability helpers shared by R1 artifact writers."""

from __future__ import annotations

import errno
import os
from pathlib import Path

_UNSUPPORTED_DIRECTORY_SYNC_ERRORS = {
    errno.EINVAL,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
}


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


__all__ = ["fsync_parent_directory"]
