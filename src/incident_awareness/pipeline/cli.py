"""First Cycle Pipeline CLI input contract.

This module deliberately validates only invocation-level inputs. Artifact content
validation and pipeline orchestration are added in later First Cycle stages.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PipelineInputs:
    """Paths and execution identifiers required for one First Cycle run."""

    run_metadata_path: Path
    manifest_path: Path
    sysmon_jsonl_path: Path
    fast_hits_path: Path
    fast_trace_path: Path
    fast_selection_path: Path
    fusion_config_path: Path
    entity_id: str
    decision_id: str
    decision_config_version: str


def build_parser() -> argparse.ArgumentParser:
    """Build the stable command-line contract for the First Cycle Pipeline."""
    parser = argparse.ArgumentParser(
        prog="incident-awareness-pipeline",
        description="Run one First Cycle Pipeline from collected S0 artifacts.",
    )
    parser.add_argument("--run-metadata", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--sysmon-jsonl", required=True, type=Path)
    parser.add_argument("--fast-hits", required=True, type=Path)
    parser.add_argument("--fast-trace", required=True, type=Path)
    parser.add_argument("--fast-selection", required=True, type=Path)
    parser.add_argument("--fusion-config", required=True, type=Path)
    parser.add_argument("--entity-id", required=True)
    parser.add_argument("--decision-id", required=True)
    parser.add_argument("--decision-config-version", required=True)
    return parser


def parse_cli_args(argv: Sequence[str] | None = None) -> PipelineInputs:
    """Parse and validate one First Cycle Pipeline invocation.

    The named S0 and Fast paths stay independent so later stages can validate
    their respective artifact contracts without inferring paths from untrusted
    manifest content.
    """
    namespace = build_parser().parse_args(argv)
    paths = {
        "run_metadata_path": namespace.run_metadata,
        "manifest_path": namespace.manifest,
        "sysmon_jsonl_path": namespace.sysmon_jsonl,
        "fast_hits_path": namespace.fast_hits,
        "fast_trace_path": namespace.fast_trace,
        "fast_selection_path": namespace.fast_selection,
        "fusion_config_path": namespace.fusion_config,
    }
    _validate_paths(paths)

    return PipelineInputs(
        **paths,
        entity_id=_validate_identifier(namespace.entity_id, "entity_id"),
        decision_id=_validate_identifier(namespace.decision_id, "decision_id"),
        decision_config_version=_validate_identifier(
            namespace.decision_config_version,
            "decision_config_version",
        ),
    )


def _validate_paths(paths: dict[str, Path]) -> None:
    resolved_paths = {name: path.resolve() for name, path in paths.items()}
    if len(set(resolved_paths.values())) != len(resolved_paths):
        raise ValueError("Pipeline input paths must be distinct")

    missing = [name for name, path in resolved_paths.items() if not path.is_file()]
    if missing:
        raise ValueError(f"Pipeline input path must be an existing file: {', '.join(missing)}")


def _validate_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a non-blank identifier without surrounding whitespace")

    return value


__all__ = ["PipelineInputs", "build_parser", "parse_cli_args"]
