"""Local demo form inputs never alter the original ReportDraft or human awareness ledger."""

import hashlib
import sqlite3
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from incident_awareness.dashboard.api.human_workflow import local_actor, repository
from incident_awareness.dashboard.api.report_drafts import get_draft_store
from incident_awareness.reporting.kisa_contracts import KISAFormCommand, form_schema
from incident_awareness.reporting.kisa_docx import generate_docx, template_info
from incident_awareness.reporting.kisa_mapping import build_form_data
from incident_awareness.reporting.kisa_readiness import assess_readiness
from incident_awareness.reporting.kisa_service import create_form
from incident_awareness.reporting.kisa_store import KISAFormStore
from incident_awareness.reporting.public_view import public_report_view
from incident_awareness.reporting.store import DraftConflict, ReportDraftStore

router = APIRouter(
    prefix="/human-workflow/alerts/{alert_id}/report-drafts/{draft_id}",
    tags=["kisa-forms"],
    dependencies=[Depends(local_actor)],
)


def load_source(store, alert_id, draft_id, *, current=False, expected_version=None):
    from incident_awareness.dashboard.api.report_drafts import synthetic_workflow_state
    from incident_awareness.reporting.synthetic_observations import (
        ALERT_ID,
        validated_saved_narrative,
    )

    if alert_id == ALERT_ID:
        draft = store.load(draft_id, alert_id)
        validated_saved_narrative(draft)
        state = synthetic_workflow_state(store, draft_id)
        if current and (
            state["report_choice"] != "proceed" or expected_version != draft["workflow_version"]
        ):
            raise DraftConflict("Synthetic form requires the current human proceed authorization")
        return draft
    with repository() as repo:
        state = repo.detail(alert_id)["state"]
    draft = store.load(draft_id, alert_id)
    if current and (
        state["report_choice"] != "proceed"
        or state["version"] != expected_version
        or draft["workflow_version"] != state["version"]
    ):
        raise DraftConflict(
            "현재 신고 진행 결정과 동일한 버전의 초안이 필요합니다. 새로 조회하거나 새 초안을 생성하세요."
        )
    return draft


def export_summary(saved):
    if saved is None:
        return None
    return {
        key: saved[key]
        for key in ("docx_sha256", "generated_at", "renderer_version", "template_sha256")
    }


def handle_error(error):
    if isinstance(error, LookupError):
        raise HTTPException(404, "Saved draft or KISA form not found") from None
    if isinstance(error, DraftConflict):
        raise HTTPException(409, str(error)) from None
    raise HTTPException(
        503, "KISA template or saved form storage unavailable; values withheld"
    ) from None


@router.get("/kisa-forms")
def forms(
    alert_id: str, draft_id: str, store: Annotated[ReportDraftStore, Depends(get_draft_store)]
):
    try:
        draft = load_source(store, alert_id, draft_id)
        form_store = KISAFormStore(store.path)
        items = form_store.list(draft_id)
        # This is an unsaved assessment, never a fabricated human action or classification.
        preview = build_form_data(
            draft,
            store.version(draft_id),
            KISAFormCommand(
                expected_workflow_version=draft["workflow_version"],
                expected_form_version=0,
                idempotency_key="00000000-0000-4000-8000-000000000000",
            ),
            action_id=None,
            actor_id=None,
            recorded_at=None,
        )
        return public_report_view(
            {
                "items": items,
                "schema": form_schema(),
                "template": template_info(),
                "latest_version": items[0]["report_version"] if items else 0,
                "readiness_assessments": {
                    item["form_id"]: assess_readiness(item) for item in items
                },
                # Read-only: lets a reloaded page offer an existing Word file without
                # re-rendering. The download endpoint still revalidates every digest.
                "exports": {
                    item["form_id"]: export_summary(form_store.export(item["form_id"]))
                    for item in items
                },
                "unsaved_preview": {
                    "preview_only": True,
                    "fields": preview["fields"],
                    "readiness": preview["readiness"],
                },
            }
        )
    except (LookupError, ValueError, OSError, sqlite3.Error) as error:
        handle_error(error)


@router.post("/kisa-forms")
def save_form(
    alert_id: str,
    draft_id: str,
    command: KISAFormCommand,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    try:
        draft = load_source(
            store,
            alert_id,
            draft_id,
            current=True,
            expected_version=command.expected_workflow_version,
        )
        return public_report_view(
            create_form(
                store,
                KISAFormStore(store.path),
                draft,
                command,
                lambda: load_source(
                    store,
                    alert_id,
                    draft_id,
                    current=True,
                    expected_version=command.expected_workflow_version,
                ),
            )
        )
    except (LookupError, ValueError, OSError, sqlite3.Error) as error:
        handle_error(error)


@router.post("/kisa-forms/{form_id}/docx")
def prepare_docx(
    alert_id: str,
    draft_id: str,
    form_id: str,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    try:
        load_source(store, alert_id, draft_id)
        forms = KISAFormStore(store.path)
        form = forms.load(form_id, alert_id, draft_id)
        saved = generate_docx(forms, form)
        return {key: value for key, value in saved.items() if key != "docx_bytes"}
    except (LookupError, ValueError, OSError, sqlite3.Error) as error:
        handle_error(error)


@router.get("/kisa-forms/{form_id}/docx")
def download_docx(
    alert_id: str,
    draft_id: str,
    form_id: str,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    try:
        load_source(store, alert_id, draft_id)
        forms = KISAFormStore(store.path)
        form = forms.load(form_id, alert_id, draft_id)
        if forms.export(form_id) is None:
            raise LookupError("Generate the saved Word document first")
        saved = generate_docx(forms, form)
        return Response(
            saved["docx_bytes"],
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={
                "Content-Disposition": f"attachment; filename=\"KISA-incident-report-v{form['report_version']}.docx\"; filename*=UTF-8''{quote(saved['filename'])}",
                "X-Document-SHA256": saved["docx_sha256"],
                "X-Draft-SHA256": saved["source_snapshot_sha256"],
                "X-Template-SHA256": saved["template_sha256"],
                "X-Document-Version": str(form["report_version"]),
                "Cache-Control": "private, no-store",
            },
        )
    except (LookupError, ValueError, OSError, sqlite3.Error) as error:
        handle_error(error)


@router.get("/kisa-forms/{form_id}/technical-evidence")
def technical_evidence(
    alert_id: str,
    draft_id: str,
    form_id: str,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    import json

    try:
        load_source(store, alert_id, draft_id)
        form = KISAFormStore(store.path).load(form_id, alert_id, draft_id)
        content = json.dumps(
            {
                "form_id": form_id,
                "form_version": form["report_version"],
                "source_report_version": form["source_report_version"],
                "technical_attachment": public_report_view(form["technical_attachment"]),
                "awareness_audit": form["fields"]["t_h"]["awareness_audit"],
                "notice": "개발용 참고자료; Evidence 원문 연결 미검증; 외부 제출되지 않음",
            },
            ensure_ascii=False,
            indent=2,
        ).encode()
        return Response(
            content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="technical-evidence-v{form["report_version"]}.json"',
                "X-Document-SHA256": hashlib.sha256(content).hexdigest(),
                "Cache-Control": "private, no-store",
            },
        )
    except (LookupError, ValueError, OSError, sqlite3.Error) as error:
        handle_error(error)
