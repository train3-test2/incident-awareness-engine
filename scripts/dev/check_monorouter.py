"""Verify only the code-owned synthetic fixture. Never reads an existing Run or raw logs."""

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import yaml

from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.service import GroundedReportService
from incident_awareness.reporting.store import ReportDraftStore
from incident_awareness.reporting.synthetic import synthetic_report_input


def inject_key_from_local_config(path: Path):
    """Private YAML -> this process's server environment; no config is copied into the repo."""
    data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("models"), list):
        raise TypeError("Invalid local credential configuration")
    matches = [
        m
        for m in data["models"]
        if isinstance(m, dict)
        and isinstance(m.get("apiKey"), str)
        and m["apiKey"].strip()
        and urlsplit(str(m.get("apiBase", ""))).hostname == "monogpt.kr"
    ]
    if len(matches) != 1:
        raise ValueError("Exactly one MonoRouter credential entry is required")
    os.environ["IAE_MONOROUTER_API_KEY"] = matches[0]["apiKey"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--config-file", type=Path)
    parser.add_argument(
        "--store-path", type=Path, default=Path("build/grounded-reports/synthetic-check.sqlite3")
    )
    args = parser.parse_args()
    if args.live:
        if os.getenv("APP_ENV") != "development" or os.getenv("IAE_MONOROUTER_ENABLED") != "1":
            parser.exit(
                2, "Live checks require APP_ENV=development and IAE_MONOROUTER_ENABLED=1.\n"
            )
        try:
            if args.config_file:
                inject_key_from_local_config(args.config_file)
            settings = MonoRouterSettings.from_environment()
            if not settings.api_key.get_secret_value().strip():
                raise ValueError("Missing key")
        except (OSError, ValueError, yaml.YAMLError, TypeError):
            parser.exit(2, "Credential/configuration could not be loaded; values withheld.\n")
    else:
        settings = MonoRouterSettings(enabled=False)
    source = synthetic_report_input()
    try:
        draft = GroundedReportService(
            ReportDraftStore(args.store_path), MonoRouterAdapter(settings)
        ).generate(
            source,
            uuid4(),
            1,
            synthetic_report_input,
        )
    except Exception:  # noqa: BLE001 - CLI boundary must not expose credential-bearing tracebacks.
        parser.exit(1, "Synthetic check failed; provider details and credentials withheld.\n")
    print(
        json.dumps(
            {
                "synthetic_only": True,
                "draft_id": draft["draft_id"],
                "method": draft["method"],
                "call_metadata": draft["call_metadata"],
                "source_verified": True,
                "submission_status": draft["submission_status"],
            }
        )
    )
    if args.live and draft["method"] != "monorouter_grounded":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
