"""Run the opt-in isolated full-Pipeline QA server from the repository checkout."""

import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
runpy.run_module("incident_awareness.devtools.final_e2e_qa", run_name="__main__")
