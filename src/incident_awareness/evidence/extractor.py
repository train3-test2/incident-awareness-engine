import json
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from uuid import NAMESPACE_URL, uuid5

EXTRACTOR_VERSION = "s0-v0.1"

_POWERSHELL_PROCESS_NAMES = frozenset({"powershell.exe", "pwsh.exe"})
_SCRIPT_INTERPRETER_PROCESS_NAMES = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
    }
)
_ENCODED_COMMAND_OPTIONS = frozenset({"-enc", "-encodedcommand"})


@dataclass(frozen=True, slots=True)
class EvidenceCandidate:
    evidence_id: str
    run_id: str
    timestamp: str
    entity_id: str
    evidence_type: str
    source_event_ids: list[str]
    extractor_version: str
    features: dict[str, object]


def extract_evidence(event: Mapping[str, object]) -> tuple[EvidenceCandidate, ...]:
    """Extract S0 evidence candidates from one event_v0 draft event."""
    event_type = event.get("event_type")

    if event_type == "process_create":
        candidate = _extract_encoded_powershell_command(event)
    elif event_type == "network_connection":
        candidate = _extract_script_interpreter_external_connection(event)
    else:
        candidate = None

    return (candidate,) if candidate is not None else ()


def _extract_encoded_powershell_command(
    event: Mapping[str, object],
) -> EvidenceCandidate | None:
    process = _mapping_value(event, "process")
    if process is None:
        return None

    process_name = _normalized_string(process, "name")
    if process_name not in _POWERSHELL_PROCESS_NAMES:
        return None

    command_line = _string_value(process, "command_line")
    if command_line is None:
        return None

    matched_option = _find_encoded_command_option(command_line)
    if matched_option is None:
        return None

    return _new_candidate(
        event,
        evidence_type="encoded_powershell_command",
        features={
            "process_name": process_name,
            "matched_option": matched_option,
        },
    )


def _extract_script_interpreter_external_connection(
    event: Mapping[str, object],
) -> EvidenceCandidate | None:
    process = _mapping_value(event, "process")
    network = _mapping_value(event, "network")
    if process is None or network is None:
        return None

    process_name = _normalized_string(process, "name")
    if process_name not in _SCRIPT_INTERPRETER_PROCESS_NAMES:
        return None

    destination = _string_value(network, "dst_ip")
    if destination is None:
        return None

    try:
        destination_ip = ip_address(destination.strip())
    except ValueError:
        return None

    if not destination_ip.is_global:
        return None

    protocol = _normalized_string(network, "protocol")

    return _new_candidate(
        event,
        evidence_type="script_interpreter_external_connection",
        features={
            "process_name": process_name,
            "protocol": protocol,
            "dst_ip": str(destination_ip),
            "dst_port": network.get("dst_port"),
        },
    )


def _find_encoded_command_option(command_line: str) -> str | None:
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError:
        return None

    for token in tokens:
        normalized_token = _strip_matching_quotes(token).casefold()
        if normalized_token in _ENCODED_COMMAND_OPTIONS:
            return normalized_token

    return None


def _strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _new_candidate(
    event: Mapping[str, object],
    *,
    evidence_type: str,
    features: dict[str, object],
) -> EvidenceCandidate:
    event_id = _required_string(event, "event_id")
    run_id = _required_string(event, "run_id")
    timestamp = _required_string(event, "timestamp")
    host_id = _required_string(event, "host_id")

    identity = json.dumps(
        [run_id, event_id, evidence_type, EXTRACTOR_VERSION],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    evidence_id = f"evd-{uuid5(NAMESPACE_URL, identity)}"

    return EvidenceCandidate(
        evidence_id=evidence_id,
        run_id=run_id,
        timestamp=timestamp,
        entity_id=host_id,
        evidence_type=evidence_type,
        source_event_ids=[event_id],
        extractor_version=EXTRACTOR_VERSION,
        features=features,
    )


def _mapping_value(
    mapping: Mapping[str, object],
    key: str,
) -> Mapping[str, object] | None:
    value = mapping.get(key)
    return value if isinstance(value, Mapping) else None


def _string_value(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) else None


def _normalized_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = _string_value(mapping, key)
    return value.strip().casefold() if value is not None else None


def _required_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value
