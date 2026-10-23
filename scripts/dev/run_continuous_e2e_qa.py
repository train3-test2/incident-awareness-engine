"""Explicit local-only entry point; no automatic input on startup."""

import runpy

if __name__ == "__main__":
    runpy.run_module("incident_awareness.devtools.continuous_e2e_qa", run_name="__main__")
