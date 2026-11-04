"""No browser-provided grounding, data classification, provider settings, or secrets."""

import sqlite3
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from incident_awareness.dashboard.api.human_workflow import local_actor, repository
from incident_awareness.dashboard.grounded_report_contract import build_report_input
from incident_awareness.dashboard.human_workflow import DEMO_ACTOR, fingerprint
from incident_awareness.reporting.approved_snapshot import preview as snapshot_preview
from incident_awareness.reporting.approved_word import latest_form, prepare_word, reuse_command
from incident_awareness.reporting.config import MonoRouterSettings, report_store_path
from incident_awareness.reporting.kisa_contracts import KISAFormCommand
from incident_awareness.reporting.kisa_store import KISAFormStore
from incident_awareness.reporting.pdf import get_or_create_pdf
from incident_awareness.reporting.public_view import public_report_view
from incident_awareness.reporting.service import GroundedReportService
from incident_awareness.reporting.status import reporting_status
from incident_awareness.reporting.store import DraftConflict, ReportDraftStore
from incident_awareness.reporting.synthetic import synthetic_report_input
from incident_awareness.reporting.synthetic_observations import (
    ALERT_ID as OBSERVATION_ALERT_ID,
)
from incident_awareness.reporting.synthetic_observations import (
    synthetic_observation_input,
)

router = APIRouter(
    prefix="/human-workflow/alerts", tags=["report-drafts"], dependencies=[Depends(local_actor)]
)
tools_router = APIRouter(
    prefix="/human-workflow/reporting", tags=["report-tools"], dependencies=[Depends(local_actor)]
)


class DraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1, strict=True)
    idempotency_key: UUID


def get_draft_store():
    return ReportDraftStore(report_store_path())


def load_report_input(alert_id):
    with repository() as repo:
        detail = repo.detail(alert_id)
        if detail["state"]["report_choice"] != "proceed":
            raise HTTPException(409, "A current human proceed decision is required")
        analysis = repo.report_analysis(detail) if hasattr(repo, "report_analysis") else None
        return build_report_input(detail, analysis)


class SnapshotApprovalRequest(DraftRequest):
    snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    approve_external: Literal[True]

    @field_validator("approve_external", mode="before")
    @classmethod
    def explicit_approval(cls, value):
        if value is not True:
            raise ValueError("Explicit approval is required")
        return value


class ApprovedDraftRequest(DraftRequest):
    consent_id: UUID
    word_inputs: KISAFormCommand | None = None
    reuse_form_id: UUID | None = None


@router.get("/{alert_id}/report-snapshot")
def preview_report_snapshot(
    alert_id: str, store: Annotated[ReportDraftStore, Depends(get_draft_store)]
):
    """No provider call, SQLite connection or approval side effect."""
    try:
        source = load_report_input(alert_id)
        value = snapshot_preview(source, MonoRouterSettings.from_environment())
        form = latest_form(store, source)
        value["word_reuse"] = (
            {k: form[k] for k in ("form_id", "incident_type", "classification_reason")}
            if form
            else None
        )
        return value
    except ValueError:
        raise HTTPException(
            422, "Verified observations or provider configuration are not eligible"
        ) from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Saved form lookup unavailable") from None


@router.post("/{alert_id}/report-snapshot-approvals")
def approve_report_snapshot(
    alert_id: str,
    command: SnapshotApprovalRequest,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    source = load_report_input(alert_id)
    try:
        snapshot = snapshot_preview(source, MonoRouterSettings.from_environment())
        if (
            source.human_state["version"] != command.expected_version
            or snapshot["snapshot_sha256"] != command.snapshot_sha256
        ):
            raise DraftConflict("Input changed; preview and approve the current snapshot")
        return store.approve_snapshot(
            alert_id,
            command.idempotency_key,
            command.expected_version,
            DEMO_ACTOR["actor_id"],
            snapshot["snapshot_sha256"],
        )
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except ValueError:
        raise HTTPException(422, "Input is not eligible for external wording") from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Approval storage unavailable") from None


@router.post("/{alert_id}/ai-report-drafts")
def generate_approved_draft(
    alert_id: str,
    command: ApprovedDraftRequest,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    source = load_report_input(alert_id)
    try:
        word = command.word_inputs
        if command.reuse_form_id:
            if word is not None:
                raise ValueError("Choose one form input source")
            old = KISAFormStore(store.path).load(str(command.reuse_form_id), alert_id)
            prior = store.load(old["source_draft_id"], alert_id)
            if old.get("run_id") != source.run_id or prior.get("entity_id") != source.entity_id:
                raise DraftConflict("Saved form scope does not match this incident")
            word = reuse_command(old, command.expected_version)
        if word is not None and (
            word.expected_workflow_version != command.expected_version
            or word.incident_type == "undetermined"
            or word.expected_form_version != 0
        ):
            raise ValueError("Explicit incident classification and current form inputs required")
        draft = GroundedReportService(store).generate(
            source,
            command.idempotency_key,
            command.expected_version,
            lambda: load_report_input(alert_id),
            approval=command.consent_id,
            actor_id=DEMO_ACTOR["actor_id"],
        )
        result = public_report_view(draft)
        if word is not None and draft["method"] == "monorouter_grounded":

            def reload_draft():
                if (
                    fingerprint(load_report_input(alert_id).model_dump(mode="json"))
                    != draft["source_snapshot_sha256"]
                ):
                    raise DraftConflict("Source changed before Word generation")
                return store.load(draft["draft_id"], alert_id)

            try:
                result["word_result"] = prepare_word(store, draft, word, reload_draft)
            except (LookupError, ValueError, sqlite3.Error, OSError):
                result["word_result"] = {
                    "status": "failed",
                    "reason": "AI draft saved; Word input or template requires review",
                }
        else:
            result["word_result"] = {
                "status": "not_prepared",
                "reason": "Explicit classification required or AI generation did not succeed",
            }
        return result
    except LookupError:
        raise HTTPException(404, "Saved form not found for this incident") from None
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except ValueError:
        raise HTTPException(422, "Approved input or configuration is not valid") from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Approved draft storage unavailable") from None


@router.post("/{alert_id}/report-drafts")
def generate_draft(
    alert_id: str,
    command: DraftRequest,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    source = load_report_input(alert_id)
    try:
        return public_report_view(
            GroundedReportService(store).generate(
                source,
                command.idempotency_key,
                command.expected_version,
                lambda: load_report_input(alert_id),
            )
        )
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except ValueError:
        raise HTTPException(422, "Report input is not grounded in verified source facts") from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Report draft storage unavailable") from None


@router.get("/{alert_id}/report-drafts")
def list_drafts(alert_id: str, store: Annotated[ReportDraftStore, Depends(get_draft_store)]):
    try:
        items = store.list_for_alert(alert_id)
        if alert_id == OBSERVATION_ALERT_ID:
            states = {
                item["draft_id"]: synthetic_workflow_state(store, item["draft_id"])
                for item in items
            }
        else:
            with repository() as repo:
                current = repo.detail(alert_id)["state"]
            states = {item["draft_id"]: current for item in items}
        return public_report_view(
            {
                "items": [
                    {
                        **item,
                        "current": states[item["draft_id"]]["report_choice"] == "proceed"
                        and (
                            alert_id == OBSERVATION_ALERT_ID
                            or item["workflow_version"] == states[item["draft_id"]]["version"]
                        ),
                        "document_version": store.version(item["draft_id"]),
                        "review": store.review_for(item["draft_id"]),
                    }
                    for item in items
                ]
            }
        )
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Report draft storage unavailable") from None


def synthetic_workflow_state(store, draft_id):
    authorization = store.synthetic_authorization(draft_id)
    with repository() as repo:
        state = repo.detail(authorization["anchor_alert_id"])["state"]
    return {
        "version": state["version"],
        "report_choice": state["report_choice"]
        if state["version"] == authorization["workflow_version"]
        else None,
    }


@tools_router.get("/synthetic/{alert_id}/drafts")
def saved_synthetic(alert_id: str, store: Annotated[ReportDraftStore, Depends(get_draft_store)]):
    with repository() as repo:
        state = repo.detail(alert_id)["state"]
    items = []
    try:
        for item in store.list_for_alert(OBSERVATION_ALERT_ID):
            authorization = store.synthetic_authorization(item["draft_id"])
            if authorization["anchor_alert_id"] != alert_id:
                continue
            items.append(
                {
                    **item,
                    "document_version": store.version(item["draft_id"]),
                    "current": state["report_choice"] == "proceed"
                    and state["version"] == authorization["workflow_version"],
                }
            )
        return public_report_view({"items": items})
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Synthetic report storage unavailable") from None


class ReviewRequest(DraftRequest):
    pass


@router.post("/{alert_id}/report-drafts/{draft_id}/review")
def review_draft(
    alert_id: str,
    draft_id: str,
    command: ReviewRequest,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    current = load_report_input(alert_id)
    try:
        draft = store.load(draft_id, alert_id)
        if (
            current.human_state["version"] != command.expected_version
            or draft["workflow_version"] != command.expected_version
        ):
            raise DraftConflict("Review requires a draft of the current workflow version")
        return store.review(
            draft_id, command.idempotency_key, DEMO_ACTOR["actor_id"], fingerprint(draft)
        )
    except LookupError:
        raise HTTPException(404, "Draft not found") from None
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Report review storage unavailable") from None


def pdf_response(store, draft_id, alert_id=None):
    try:
        saved, filename = get_or_create_pdf(store, draft_id, alert_id)
    except LookupError:
        raise HTTPException(404, "Draft not found") from None
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except (ValueError, OSError, sqlite3.Error):
        raise HTTPException(503, "Saved PDF could not be generated or verified") from None
    return Response(
        saved["pdf_bytes"],
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-PDF-SHA256": saved["pdf_sha256"],
            "X-Draft-SHA256": saved["draft_sha256"],
            "X-Document-Version": str(saved["document_version"]),
            "Cache-Control": "private, no-store",
        },
    )


@router.get("/{alert_id}/report-drafts/{draft_id}/pdf")
def download_pdf(
    alert_id: str, draft_id: str, store: Annotated[ReportDraftStore, Depends(get_draft_store)]
):
    with repository() as repo:
        repo.detail(alert_id)
    return pdf_response(store, draft_id, alert_id)


@tools_router.get("/status")
def status(store: Annotated[ReportDraftStore, Depends(get_draft_store)]):
    return reporting_status(store)


class SyntheticRequest(DraftRequest):
    allow_external_synthetic: Literal[True]
    fixture: Literal["legacy", "verified_observations_v1"] = "legacy"

    @field_validator("allow_external_synthetic", mode="before")
    @classmethod
    def explicit_boolean_consent(cls, value):
        if value is not True:
            raise ValueError("Explicit synthetic transmission consent is required")
        return value


@tools_router.post("/synthetic/{alert_id}/drafts")
def generate_synthetic(
    alert_id: str,
    command: SyntheticRequest,
    store: Annotated[ReportDraftStore, Depends(get_draft_store)],
):
    current = load_report_input(alert_id)
    if current.human_state["version"] != command.expected_version:
        raise HTTPException(409, "Workflow changed")
    if not reporting_status(store)["synthetic_transmission_enabled"]:
        raise HTTPException(409, "Synthetic external transmission is disabled on this server")
    fixture = (
        synthetic_observation_input
        if command.fixture == "verified_observations_v1"
        else synthetic_report_input
    )
    source = fixture()
    try:
        store.consent(
            alert_id,
            command.idempotency_key,
            command.expected_version,
            DEMO_ACTOR["actor_id"],
            fingerprint(source.model_dump(mode="json")),
        )

        def reload():
            if load_report_input(alert_id).human_state["version"] != command.expected_version:
                raise DraftConflict("Workflow changed during synthetic generation")
            return fixture()

        return GroundedReportService(store).generate(
            source, uuid5(NAMESPACE_URL, alert_id + ":" + str(command.idempotency_key)), 1, reload
        )
    except DraftConflict as error:
        raise HTTPException(409, str(error)) from None
    except (sqlite3.Error, OSError):
        raise HTTPException(503, "Synthetic report storage unavailable") from None


@tools_router.get("/synthetic/drafts/{draft_id}/pdf")
def synthetic_pdf(draft_id: str, store: Annotated[ReportDraftStore, Depends(get_draft_store)]):
    return pdf_response(store, draft_id, synthetic_report_input().alert_id)
