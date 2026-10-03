"""Execute validated statistical inputs and preserve replayable provenance."""

import hashlib
import json
from datetime import timedelta

from pydantic import BaseModel

from incident_awareness.decision.fusion.stopping_policy import ScorePoint
from incident_awareness.evaluation.baselines.provenance import StatisticalConfig, StatisticalInput
from incident_awareness.evaluation.baselines.statistical import cusum_trajectory, ewma_trajectory


def _digest(record: BaseModel) -> str:
    serialized = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def run_statistical_comparison(
    source: StatisticalInput, config: StatisticalConfig
) -> dict[str, object]:
    """Return JSON-serializable inputs, settings and output without inventing evidence attribution.

    Artifact/calibration hashes are caller-supplied references, not verification
    of files on disk. Input/config hashes below cover the actual embedded data.
    """
    # Revalidate even instances created through Pydantic's unchecked model_copy/construct.
    source = StatisticalInput.model_validate(source.model_dump(mode="json"))
    config = StatisticalConfig.model_validate(config.model_dump(mode="json"))
    points = [ScorePoint(point.timestamp, point.score) for point in source.points]
    common = {
        "baseline_mean": config.baseline_mean,
        "step_size": timedelta(seconds=config.step_seconds),
    }
    if config.method == "ewma":
        assert config.alpha is not None
        output = ewma_trajectory(points, alpha=config.alpha, **common)
    else:
        assert config.allowance is not None and config.scale is not None
        output = cusum_trajectory(points, allowance=config.allowance, scale=config.scale, **common)
    return {
        "schema_version": "statistical-comparison-v0.1",
        "implementation_version": "statistical-v0.1",
        "input_sha256": _digest(source),
        "config_sha256": _digest(config),
        "input": source.model_dump(mode="json"),
        "config": config.model_dump(mode="json"),
        "output": [
            {
                "timestamp": point.timestamp.isoformat(),
                "score": point.score,
                "input_prefix_length": index + 1,
            }
            for index, point in enumerate(output)
        ],
    }
