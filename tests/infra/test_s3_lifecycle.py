"""Static contract tests for First Cycle S3 Lifecycle configuration."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_CONFIGURATION = ROOT / "infra" / "s3" / "first-cycle-ingest-lifecycle.json"


def test_first_cycle_ingest_lifecycle_is_scoped_and_bounded() -> None:
    configuration = json.loads(LIFECYCLE_CONFIGURATION.read_text(encoding="utf-8"))

    assert configuration == {
        "Rules": [
            {
                "ID": "expire-first-cycle-sysmon-ingest-after-21-days",
                "Status": "Enabled",
                "Filter": {"Prefix": "incoming/first-cycle/sysmon/"},
                "Expiration": {"Days": 21},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 21},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
            }
        ]
    }
