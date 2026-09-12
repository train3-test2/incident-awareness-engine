import json
import logging
import shlex
from collections.abc import Mapping
from ipaddress import ip_address
from uuid import NAMESPACE_URL, uuid5

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence

EXTRACTOR_VERSION = "s0-v0.1"

_LOGGER = logging.getLogger(__name__)

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
_ENCODED_COMMAND_OPTIONS = frozenset({"-e", "-ec", "-enc", "-encodedcommand"})
_POWERSHELL_FILE_OPTION = "-file"


def extract_evidence(event: NormalizedEvent) -> list[Evidence]:
    """Extract S0 Evidence from one NormalizedEvent v0.2 model."""
    if not isinstance(event, NormalizedEvent):
        raise TypeError("event must be a NormalizedEvent")

    event_data = event.model_dump()
    event_type = event_data.get("event_type")

    # 현재 S0 Evidence 규칙은 서로 다른 event_type을 사용하므로 한 Event에서 복수 규칙이 동시에 매치되지 않는다.
    if event_type == "process_create":
        evidence = _extract_encoded_powershell_command(event_data)
    elif event_type == "network_connection":
        evidence = _extract_script_interpreter_external_connection(event_data)
    else:
        evidence = None

    return [evidence] if evidence is not None else []


def _extract_encoded_powershell_command(
    event: Mapping[str, object],
) -> Evidence | None:
    process = _mapping_value(event, "process")
    if process is None:
        return None

    process_name = _normalized_string(process, "name")
    if process_name not in _POWERSHELL_PROCESS_NAMES:
        return None

    command_line = _string_value(process, "command_line")
    if command_line is None:
        return None

    matched_option = _find_encoded_command_option(
        command_line,
        event_id=_string_value(event, "event_id"),
    )
    if matched_option is None:
        return None

    return _new_evidence(
        event,
        evidence_type="encoded_powershell_command",
        features={
            "process_name": process_name,
            "matched_option": matched_option,
        },
    )


def _extract_script_interpreter_external_connection(
    event: Mapping[str, object],
) -> Evidence | None:
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
        # DNS 해석은 상위 정규화 단계의 책임이며 Evidence Extractor에서는 수행하지 않는다.
        _LOGGER.warning(
            "Skipping external-connection detection for event_id=%s because dst_ip=%r "
            "is not an IP literal; DNS resolution is unsupported.",
            event.get("event_id"),
            destination,
        )
        return None

    if not destination_ip.is_global or destination_ip.is_multicast:
        return None

    protocol = _normalized_string(network, "protocol")

    return _new_evidence(
        event,
        evidence_type="script_interpreter_external_connection",
        features={
            "process_name": process_name,
            "protocol": protocol,
            "dst_ip": str(destination_ip),
            "dst_port": network.get("dst_port"),
        },
    )


def _find_encoded_command_option(
    command_line: str,
    *,
    event_id: str | None,
) -> str | None:
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError as error:
        # 외부 Evidence 계약을 바꾸지 않고도 비정상 입력의 원인을 확인할 수 있게 남긴다.
        _LOGGER.warning(
            "Skipping encoded PowerShell detection for event_id=%s because command-line "
            "parsing failed: %s",
            event_id,
            error,
        )
        return None

    for token in tokens:
        normalized_token = _strip_matching_quotes(token).casefold()

        # -File 뒤의 토큰은 PowerShell 호스트 옵션이 아니라 스크립트 경로와 인자다.
        if normalized_token == _POWERSHELL_FILE_OPTION:
            return None

        if normalized_token in _ENCODED_COMMAND_OPTIONS:
            return normalized_token

    return None


def _strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _new_evidence(
    event: Mapping[str, object],
    *,
    evidence_type: str,
    features: dict[str, object],
) -> Evidence:
    event_id = _required_string(event, "event_id")
    run_id = _required_string(event, "run_id")
    host_id = _required_string(event, "host_id")
    source_layer = _required_string(event, "source_layer")

    identity = json.dumps(
        [run_id, event_id, evidence_type, EXTRACTOR_VERSION],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    evidence_id = f"E-{uuid5(NAMESPACE_URL, identity)}"

    return Evidence.model_validate(
        {
            "evidence_id": evidence_id,
            "run_id": run_id,
            "timestamp": event.get("timestamp"),
            "entity_id": host_id,
            "evidence_type": evidence_type,
            "event_ids": [event_id],
            "derived_from_source_layer": source_layer,
            "feature_channel_group": "fusion_feature",
            "extractor_version": EXTRACTOR_VERSION,
            "features": features,
        }
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
