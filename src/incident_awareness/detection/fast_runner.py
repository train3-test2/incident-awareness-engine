"""Convert one Hayabusa CSV into a run-local FastHitRecord handoff."""

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.detection.fast_hit_adapter import (
    hayabusa_rows_to_fast_hits,
    read_hayabusa_csv,
    write_fast_hits_jsonl,
)

Identifier = Annotated[str, StringConstraints(strict=True, min_length=1, pattern=r"^\S+$")]


class RuleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_version: Identifier
    alert_key: Identifier


class FastRunnerConfig(BaseModel):
    """Runner settings only; not a new shared result contract."""

    model_config = ConfigDict(extra="forbid")
    detector_engine_version: Identifier
    detector_config_version: Identifier
    qualifying_rule_ids: list[Identifier]
    rule_metadata: dict[Identifier, RuleMetadata]

    @field_validator("qualifying_rule_ids")
    @classmethod
    def reject_duplicates(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("qualifying_rule_ids must be unique")
        return value


def _publish_handoff(hits: list[dict], trace: dict, output_path: Path, trace_path: Path) -> None:
    """Stage both files, publish without replacement, and roll back this call on failure.

    The trace is published last as the completion marker. This is not a two-file
    atomic transaction or crash recovery mechanism.
    """
    staged: list[Path] = []
    published: list[tuple[Path, Path]] = []
    try:
        for target in (output_path, trace_path):
            with tempfile.NamedTemporaryFile(
                dir=target.parent, prefix=f".{target.name}.", delete=False
            ) as temporary:
                staged.append(Path(temporary.name))
        write_fast_hits_jsonl(hits, staged[0])
        trace["output_sha256"] = hashlib.sha256(staged[0].read_bytes()).hexdigest()
        staged[1].write_text(
            json.dumps(trace, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        for source, target in zip(staged, (output_path, trace_path), strict=True):
            # Hard-link publication is exclusive: an existing destination is never replaced.
            os.link(source, target)
            published.append((source, target))
    except BaseException:
        for source, target in reversed(published):
            # Only remove artifacts still referring to the file created by this call.
            try:
                if os.path.samestat(source.stat(), target.lstat()):
                    target.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for source in staged:
            source.unlink(missing_ok=True)


def run_fast_handoff(
    *, csv_path: Path, config_path: Path, run_id: str, output_path: Path, trace_path: Path
) -> int:
    # Reuse the existing canonical format/date validation without loading Ground Truth.
    RunMetadata.validate_required_identifier(run_id)
    RunMetadata.validate_run_id(run_id)
    paths = [p.resolve() for p in (csv_path, config_path, output_path, trace_path)]
    if len(paths) != len(set(paths)):
        raise ValueError("input, config, output and trace paths must be distinct")
    if output_path.exists() or trace_path.exists():
        raise FileExistsError("output and trace must be new files")
    config = FastRunnerConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
    metadata = {key: value.model_dump() for key, value in config.rule_metadata.items()}
    for rule_id in config.qualifying_rule_ids:
        if rule_id not in metadata:
            raise KeyError(f"missing metadata for qualifying rule: {rule_id}")
    rows = read_hayabusa_csv(csv_path)
    hits = hayabusa_rows_to_fast_hits(
        rows,
        run_id=run_id,
        detector_engine_version=config.detector_engine_version,
        detector_config_version=config.detector_config_version,
        qualifying_rule_ids=set(config.qualifying_rule_ids),
        rule_metadata=metadata,
    )
    hits_by_id = {hit["hit_id"]: hit for hit in hits}
    trace = {
        "run_id": run_id,
        "input_csv": str(csv_path.resolve()),
        "input_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "input_row_count": len(rows),
        "hit_count": len(hits),
        "hits": [
            {"hit_id": hit["hit_id"], "source_row_index": index, "rule_id": row["RuleID"]}
            for index, row in enumerate(rows, 1)
            if (hit := hits_by_id.get(f"{run_id}-hit-{index}")) is not None
        ],
    }
    _publish_handoff(hits, trace, output_path, trace_path)
    return len(hits)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()
    count = run_fast_handoff(
        csv_path=args.csv,
        config_path=args.config,
        run_id=args.run_id,
        output_path=args.output,
        trace_path=args.trace,
    )
    print(f"FastHitRecord: {count} records written")


if __name__ == "__main__":
    main()
