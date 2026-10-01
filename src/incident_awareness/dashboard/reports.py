"""Human-authored report drafts, separate from detection and legal awareness decisions."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, field_validator

from incident_awareness.dashboard.queries import MissingResource, decision, serialized

Text = Annotated[StrictStr, Field(max_length=500)]
Paragraph = Annotated[StrictStr, Field(max_length=10000)]


class ReportFields(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_type: Literal["ransomware", "ddos", "other"] | None = None
    company_name: Text | None = None
    business_number: Text | None = None
    industry: Text | None = None
    company_size: Literal["large", "mid", "small", "nonprofit"] | None = None
    company_address: Text | None = None
    reporter_name: Text | None = None
    reporter_email: Text | None = None
    reporter_phone: Text | None = None
    occurred_at: datetime | None = None
    awareness_at: datetime | None = None
    awareness_evidence: Paragraph | None = None
    incident_description: Paragraph | None = None
    damage_description: Paragraph | None = None
    victim_ip: Text | None = None
    victim_domain: Text | None = None
    response_actions: Paragraph | None = None
    encrypted_extensions: Text | None = None
    backup_status: Text | None = None
    affected_server_count: Annotated[int, Field(strict=True, ge=0)] | None = None
    affected_pc_count: Annotated[int, Field(strict=True, ge=0)] | None = None
    server_type: Text | None = None
    service_status: Text | None = None
    attack_scale: Text | None = None
    extortion_status: Text | None = None
    technical_support_consent: StrictBool | None = None
    personal_data_consent: StrictBool | None = None

    @field_validator("occurred_at", "awareness_at", mode="before")
    @classmethod
    def reject_numeric_time(cls, value):
        if isinstance(value, int | float):
            raise ValueError("Use an explicit timezone timestamp")  # noqa: TRY004
        if isinstance(value, str):
            try:
                float(value)
            except ValueError:
                pass
            else:
                raise ValueError("Numeric timestamps are not accepted")
        return value

    @field_validator("occurred_at", "awareness_at")
    @classmethod
    def require_timezone(cls, value):
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("Timezone required")
            return value.astimezone(UTC)
        return value


class SaveReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: Annotated[int, Field(strict=True, ge=0)]
    fields: ReportFields


class ReportConflict(Exception):
    pass


class ReportStore:
    def __init__(self, connection):
        self.db = connection

    def source(self, run_id, decision_id):
        row = self.db.execute(
            "SELECT payload, created_at FROM decisions WHERE run_id = %s AND decision_id = %s",
            (run_id, decision_id),
        ).fetchone()
        if row is None:
            raise MissingResource("DECISION_NOT_FOUND")
        return decision(row, detail=True)

    def get(self, run_id, decision_id):
        source = self.source(run_id, decision_id)
        row = self.db.execute(
            "SELECT revision, fields, source_decision, updated_at FROM report_drafts "
            "WHERE run_id = %s AND decision_id = %s",
            (run_id, decision_id),
        ).fetchone()
        if row is None:
            return {
                "availability": "missing",
                "revision": 0,
                "status": "draft",
                "fields": ReportFields().model_dump(mode="json"),
                "source_decision": source,
                "updated_at": None,
            }
        return {**serialized(row), "availability": "available", "status": "draft"}

    def save(self, run_id, decision_id, request):
        source = self.source(run_id, decision_id)
        fields = Jsonb(request.fields.model_dump(mode="json"))
        if request.expected_revision == 0:
            row = self.db.execute(
                "INSERT INTO report_drafts (run_id, decision_id, fields, source_decision) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (run_id, decision_id) DO NOTHING "
                "RETURNING revision, fields, source_decision, updated_at",
                (run_id, decision_id, fields, Jsonb(source)),
            ).fetchone()
        else:
            row = self.db.execute(
                "UPDATE report_drafts SET fields = %s, revision = revision + 1, "
                "updated_at = CURRENT_TIMESTAMP WHERE run_id = %s AND decision_id = %s "
                "AND revision = %s RETURNING revision, fields, source_decision, updated_at",
                (fields, run_id, decision_id, request.expected_revision),
            ).fetchone()
        if row is None:
            raise ReportConflict()
        return {**serialized(row), "availability": "available", "status": "draft"}
