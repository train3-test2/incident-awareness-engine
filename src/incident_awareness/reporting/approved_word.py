"""Reuse human form inputs locally; no organizational data is sent to the provider."""

import json
import sqlite3
from contextlib import closing
from uuid import NAMESPACE_URL, uuid5

from incident_awareness.reporting.kisa_contracts import KISAFormCommand
from incident_awareness.reporting.kisa_docx import generate_docx
from incident_awareness.reporting.kisa_service import create_form
from incident_awareness.reporting.kisa_store import KISAFormStore


def latest_form(store, source):
    if not store.path.exists():
        return None
    with closing(
        sqlite3.connect(store.path.resolve().as_uri() + "?mode=ro", uri=True)
    ) as connection:
        if not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='kisa_form_versions'"
        ).fetchone():
            return None
        rows = connection.execute(
            "SELECT f.form_json,d.draft_json FROM kisa_form_versions f JOIN report_drafts d "
            "ON d.draft_id=f.source_draft_id WHERE f.alert_id=? ORDER BY f.rowid DESC LIMIT 20",
            (source.alert_id,),
        ).fetchall()
    for raw, draft_raw in rows:
        value = json.loads(raw)
        draft = json.loads(draft_raw)
        if (
            value.get("run_id") == source.run_id
            and draft.get("entity_id") == source.entity_id
            and value["incident_type"] != "undetermined"
        ):
            return value
    return None


def reuse_command(form, version):
    # Only organization/reporter details. Never copy an old incident time, response
    # assertion, technical classification of damage, or any consent selection.
    keys = {
        "company_name",
        "business_number",
        "industry",
        "company_size",
        "company_address",
        "reporter_name",
        "reporter_email",
        "reporter_phone",
    }
    return KISAFormCommand(
        expected_workflow_version=version,
        expected_form_version=0,
        idempotency_key=uuid5(NAMESPACE_URL, "reuse-form:" + form["form_id"]),
        incident_type=form["incident_type"],
        classification_reason=form["classification_reason"],
        fields={k: v for k, v in form["inputs"]["fields"].items() if k in keys},
    )


def prepare_word(store, draft, command, reload_source):
    forms = KISAFormStore(store.path)
    form = create_form(store, forms, draft, command, reload_source)
    saved = generate_docx(forms, form)
    return {
        "status": "ready",
        "form_id": form["form_id"],
        "docx_sha256": saved["docx_sha256"],
        "download_url": f"/human-workflow/alerts/{draft['alert_id']}/report-drafts/{draft['draft_id']}/kisa-forms/{form['form_id']}/docx",
    }
