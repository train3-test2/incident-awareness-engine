"""Generate deterministic synthetic evaluator cases, not model training data."""

import argparse
import sys
from datetime import UTC, datetime, timedelta

import pandas as pd

from incident_awareness.common.models.result import _serialize_utc_datetime


def make_fake_runs(*, method: str, horizon_seconds: int) -> pd.DataFrame:
    """Seven complete Runs with expected Recall=2/5 and benign Run FPR=1/2."""
    if not isinstance(method, str):
        raise TypeError("method must be a string")
    if not method or method != method.strip():
        raise ValueError("method must be nonblank and trimmed")
    if isinstance(horizon_seconds, bool) or not isinstance(horizon_seconds, int):
        raise TypeError("horizon_seconds must be an integer")
    # Bound fixture durations, not production evaluation horizons.
    if not 1 <= horizon_seconds <= 86400:
        raise ValueError("synthetic horizon_seconds must be between 1 and 86400")
    horizon = timedelta(seconds=horizon_seconds)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    cases = (
        ("immediate", "attack", timedelta(0)),
        ("horizon_boundary", "attack", horizon),
        ("miss", "attack", None),
        ("pre_reference", "attack", timedelta(milliseconds=-1)),
        ("after_horizon", "attack", horizon + timedelta(milliseconds=1)),
        ("normal_alert", "normal", timedelta(seconds=1)),
        ("normal_clean", "normal", None),
    )
    rows = []
    for index, (case, kind, offset) in enumerate(cases, start=1):
        start = base + timedelta(days=index - 1)
        reference = start + timedelta(seconds=60)
        rows.append(
            {
                "run_id": f"RUN-{start:%Y%m%d}-{index:03d}",
                "scenario_id": "SYNTHETIC-EVALUATOR-v1",
                "synthetic_case": case,
                "data_origin": "synthetic",
                "synthetic_horizon_seconds": horizon_seconds,
                "entity_id": "SYNTHETIC-HOST",
                "class": kind,
                "run_start": start,
                "run_end": reference + horizon + timedelta(seconds=60),
                "reference_time": reference if kind == "attack" else None,
                "timestamp": reference + offset if offset is not None else None,
                "method": method,
            }
        )
    frame = pd.DataFrame(rows)
    for name in ("run_start", "run_end", "reference_time", "timestamp"):
        frame[name] = pd.to_datetime(frame[name], utc=True)
    return frame


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", required=True)
    parser.add_argument("--horizon-seconds", required=True, type=int)
    args = parser.parse_args()
    try:
        frame = make_fake_runs(method=args.method, horizon_seconds=args.horizon_seconds)
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))
    for name in ("run_start", "run_end", "reference_time", "timestamp"):
        frame[name] = frame[name].map(
            lambda value: _serialize_utc_datetime(value) if pd.notna(value) else None
        )
    frame.to_csv(sys.stdout, index=False, na_rep="")


if __name__ == "__main__":
    main()
