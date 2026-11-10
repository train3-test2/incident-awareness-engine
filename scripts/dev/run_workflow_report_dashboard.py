"""Start a new loopback preview without restarting any existing Dashboard."""

import argparse
import os
import socket
from pathlib import Path

import uvicorn
import yaml
from check_monorouter import inject_key_from_local_config
from run_localstack_dashboard import configure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8798)
    parser.add_argument("--enable-synthetic-external", action="store_true")
    parser.add_argument("--monorouter-config", type=Path)
    parser.add_argument("--verification-store", type=Path)
    args = parser.parse_args()
    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", args.port)) == 0:
            parser.exit(2, "Preview port is already in use; existing server preserved.\n")
    try:
        configure(args.env_file)
        os.environ["APP_ENV"] = "development" if args.enable_synthetic_external else "local"
        os.environ["IAE_MONOROUTER_ENABLED"] = "1" if args.enable_synthetic_external else "0"
        if args.enable_synthetic_external and args.monorouter_config:
            inject_key_from_local_config(args.monorouter_config)
        if args.verification_store:
            os.environ["IAE_MONOROUTER_VERIFICATION_STORE_PATH"] = str(
                args.verification_store.resolve()
            )
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        parser.exit(2, "Server configuration unavailable; values withheld.\n")
    uvicorn.run(
        "incident_awareness.dashboard.api.app:app",
        host="127.0.0.1",
        port=args.port,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
