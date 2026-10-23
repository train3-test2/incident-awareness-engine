"""Historical connection verification is distinct from current data transmission policy."""

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.contracts import CallMetadata


def reporting_status(store):
    try:
        settings = MonoRouterSettings.from_environment()
    except ValueError:
        return {
            "adapter": "configuration_error",
            "connection_verification": None,
            "actual_workflow_transmission_allowed": False,
            "synthetic_transmission_enabled": False,
        }
    candidates = []
    for path in [
        store.path,
        Path(os.environ["IAE_MONOROUTER_VERIFICATION_STORE_PATH"])
        if os.getenv("IAE_MONOROUTER_VERIFICATION_STORE_PATH")
        else None,
    ]:
        if path is None or not path.exists():
            continue
        try:
            with closing(
                sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
            ) as connection:
                rows = connection.execute(
                    "SELECT draft_json FROM report_drafts WHERE status='completed' ORDER BY created_at DESC LIMIT 50"
                ).fetchall()
            for (raw,) in rows:
                value = json.loads(raw)
                call = CallMetadata.model_validate(value["call_metadata"])
                if (
                    value.get("context") == "synthetic_development"
                    and value["method"] == "monorouter_grounded"
                    and call.status == "success"
                    and call.http_status == 200
                ):
                    candidates.append(call.model_dump(mode="json"))
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            continue
    verified = (
        max(candidates, key=lambda item: item.get("requested_at") or "") if candidates else None
    )
    return {
        "adapter": "configured",
        "provider": "MonoGPT MonoRouter",
        "request_model": settings.model,
        "connection_verification": verified,
        "verification_meaning": "historical_synthetic_request_not_live_health",
        "credentials_configured": bool(settings.api_key.get_secret_value()),
        "synthetic_transmission_enabled": settings.enabled
        and settings.development
        and bool(settings.api_key.get_secret_value()),
        "synthetic_explicit_consent_required": True,
        "actual_workflow_transmission_allowed": False,
        "snapshot_approval_supported": True,
        "actual_workflow_block_reason": "일괄 전송 차단; 검증된 비식별 입력 Snapshot의 개별 승인 필요",
    }
