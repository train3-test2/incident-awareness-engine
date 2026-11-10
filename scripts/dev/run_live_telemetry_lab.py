"""Repository-root launcher for the opt-in, local-only Telemetry lab."""

import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

if __name__ == "__main__":
    runpy.run_module("incident_awareness.devtools.live_telemetry_lab", run_name="__main__")
