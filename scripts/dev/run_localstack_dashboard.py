"""Run the opt-in local Dashboard against an already-running First Cycle stack."""

import argparse
import os
import socket
from pathlib import Path
from urllib.parse import quote

import uvicorn


def configure(environment_file: Path) -> None:
    values = {}
    for line in environment_file.read_text(encoding="utf-8-sig").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip("\"'")
    if values.get("LOCAL_POSTGRES_PORT") != "54330" or values.get("LOCALSTACK_PORT") != "4566":
        raise ValueError("Expected existing LocalStack ports 54330 and 4566")
    os.environ["INCIDENT_AWARENESS_DATABASE_URL"] = "postgresql://{}:{}@127.0.0.1:54330/{}".format(
        quote(values["LOCAL_POSTGRES_USER"], safe=""),
        quote(values["LOCAL_POSTGRES_PASSWORD"], safe=""),
        quote(values["LOCAL_POSTGRES_DB"], safe=""),
    )
    os.environ["INCIDENT_AWARENESS_LOCAL_DEMO"] = "1"
    os.environ["INCIDENT_AWARENESS_EVENT_TYPES_PATH"] = str(
        Path(__file__).resolve().parents[2] / "configs/event_types_v0.2.yaml"
    )
    os.environ["INCIDENT_AWARENESS_S3_INPUT_BUCKET"] = values["LOCAL_FIRST_CYCLE_BUCKET"]
    os.environ["INCIDENT_AWARENESS_LOCAL_INGEST_LEDGER"] = str(
        Path(__file__).resolve().parents[2] / "build/localstack-dashboard/ingest.sqlite3"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8794)
    args = parser.parse_args()
    try:
        configure(args.env_file)
    except (KeyError, OSError, ValueError):
        parser.exit(2, "LocalStack environment is missing or invalid (values withheld).\n")
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", args.port)) == 0:
            parser.exit(2, "Selected Dashboard port is already in use.\n")
    uvicorn.run(
        "incident_awareness.dashboard.api.app:app",
        host="127.0.0.1",
        port=args.port,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
