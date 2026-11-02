"""Inter-process exclusive lock for one R1 operational directory.

The Role2 consume sidecar and the finalize command share a state root, and the
Role1 handoff appends to its output trace. Each holds this lock for one whole
read-check-write step. The OS releases the lock when the holder exits, so a
crashed process never leaves a stale lock behind.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

R1_DIRECTORY_LOCK_FILENAME = ".r1_operational.lock"
DEFAULT_R1_LOCK_TIMEOUT_SEC = 30.0
_POLL_INTERVAL_SEC = 0.05

if sys.platform == "win32":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class R1DirectoryLockTimeout(TimeoutError):
    """Another process held the directory lock for longer than the timeout."""


@contextmanager
def r1_directory_lock(
    directory: Path,
    *,
    timeout_sec: float = DEFAULT_R1_LOCK_TIMEOUT_SEC,
) -> Iterator[None]:
    """Hold the exclusive lock of ``directory`` for the duration of the block."""
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / R1_DIRECTORY_LOCK_FILENAME, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        deadline = time.monotonic() + timeout_sec
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise R1DirectoryLockTimeout(
                    f"R1 operational directory is locked by another process: {directory}"
                )
            time.sleep(_POLL_INTERVAL_SEC)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


__all__ = [
    "DEFAULT_R1_LOCK_TIMEOUT_SEC",
    "R1_DIRECTORY_LOCK_FILENAME",
    "R1DirectoryLockTimeout",
    "r1_directory_lock",
]
