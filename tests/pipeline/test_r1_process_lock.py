"""Cross-process behavior of the R1 operational directory lock."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import incident_awareness
from incident_awareness.pipeline.r1_process_lock import (
    R1DirectoryLockTimeout,
    r1_directory_lock,
)

_HOLDER = """
import sys
from pathlib import Path
from incident_awareness.pipeline.r1_process_lock import r1_directory_lock
with r1_directory_lock(Path(sys.argv[1])):
    print("locked", flush=True)
    sys.stdin.read()
"""


def _start_holder(directory: Path) -> subprocess.Popen[str]:
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(directory)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path(incident_awareness.__file__).parents[1])},
    )
    assert holder.stdout is not None
    assert holder.stdout.readline().strip() == "locked"
    return holder


def test_lock_held_by_another_process_blocks_until_timeout(tmp_path: Path) -> None:
    # Given
    holder = _start_holder(tmp_path)
    try:
        # When / Then
        with pytest.raises(R1DirectoryLockTimeout), r1_directory_lock(tmp_path, timeout_sec=0.2):
            pytest.fail("lock must not be granted while another process holds it")
    finally:
        holder.communicate("")


def test_lock_is_released_when_the_holder_process_dies(tmp_path: Path) -> None:
    # Given
    holder = _start_holder(tmp_path)

    # When
    holder.kill()
    holder.wait()

    # Then
    with r1_directory_lock(tmp_path, timeout_sec=5.0):
        pass


def test_lock_is_reentrant_across_sequential_holders(tmp_path: Path) -> None:
    # Given / When
    with r1_directory_lock(tmp_path):
        pass

    # Then
    with r1_directory_lock(tmp_path, timeout_sec=0.0):
        pass
