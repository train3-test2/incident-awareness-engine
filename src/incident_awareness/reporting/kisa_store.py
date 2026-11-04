"""Append-only KISA form supplements and immutable DOCX exports in the existing ledger."""

import json
import sqlite3
from contextlib import closing, contextmanager
from uuid import uuid4

from incident_awareness.dashboard.human_workflow import fingerprint
from incident_awareness.reporting.monorouter import utc_now
from incident_awareness.reporting.store import DraftConflict


class KISAFormStore:
    def __init__(self, path):
        self.path = path

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=3)) as connection, connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=3000")
            connection.execute("""CREATE TABLE IF NOT EXISTS kisa_form_versions (
                form_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, source_draft_id TEXT NOT NULL,
                version INTEGER NOT NULL, idempotency_key TEXT NOT NULL,
                request_sha256 TEXT NOT NULL, source_snapshot_sha256 TEXT NOT NULL,
                actor_id TEXT NOT NULL, recorded_at TEXT NOT NULL, form_json TEXT NOT NULL,
                UNIQUE(source_draft_id,version), UNIQUE(source_draft_id,idempotency_key))""")
            connection.execute("""CREATE TABLE IF NOT EXISTS kisa_docx_exports (
                form_id TEXT PRIMARY KEY, template_sha256 TEXT NOT NULL,
                source_snapshot_sha256 TEXT NOT NULL, form_sha256 TEXT NOT NULL,
                docx_sha256 TEXT NOT NULL, renderer_version TEXT NOT NULL,
                generated_at TEXT NOT NULL, filename TEXT NOT NULL, docx_bytes BLOB NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS kisa_narrative_attempts (
                attempt_id TEXT PRIMARY KEY, human_action_id TEXT NOT NULL,
                source_draft_id TEXT NOT NULL, recorded_at TEXT NOT NULL,
                call_metadata TEXT NOT NULL)""")
            expected = {
                "kisa_form_versions": [
                    "form_id",
                    "alert_id",
                    "source_draft_id",
                    "version",
                    "idempotency_key",
                    "request_sha256",
                    "source_snapshot_sha256",
                    "actor_id",
                    "recorded_at",
                    "form_json",
                ],
                "kisa_docx_exports": [
                    "form_id",
                    "template_sha256",
                    "source_snapshot_sha256",
                    "form_sha256",
                    "docx_sha256",
                    "renderer_version",
                    "generated_at",
                    "filename",
                    "docx_bytes",
                ],
                "kisa_narrative_attempts": [
                    "attempt_id",
                    "human_action_id",
                    "source_draft_id",
                    "recorded_at",
                    "call_metadata",
                ],
            }
            for table, names in expected.items():
                if [
                    row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
                ] != names:
                    raise ValueError("Existing KISA ledger schema conflicts with this version")
                for verb in ["UPDATE", "DELETE"]:
                    connection.execute(
                        f"CREATE TRIGGER IF NOT EXISTS {table}_no_{verb.lower()} BEFORE {verb} ON {table} BEGIN SELECT RAISE(ABORT,'KISA records are append-only'); END"
                    )
            yield connection

    def record_attempt(self, action_id, draft_id, metadata):
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO kisa_narrative_attempts VALUES (?,?,?,?,?)",
                (str(uuid4()), action_id, draft_id, utc_now(), metadata.model_dump_json()),
            )

    def list(self, draft_id):
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT form_json FROM kisa_form_versions WHERE source_draft_id=? ORDER BY version DESC",
                (draft_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def load(self, form_id, alert_id=None, draft_id=None):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM kisa_form_versions WHERE form_id=?", (form_id,)
            ).fetchone()
        if (
            row is None
            or (alert_id is not None and row["alert_id"] != alert_id)
            or (draft_id is not None and row["source_draft_id"] != draft_id)
        ):
            raise LookupError("Saved KISA form not found")
        return json.loads(row["form_json"])

    def existing(self, draft_id, key, request_digest):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT request_sha256,form_json FROM kisa_form_versions WHERE source_draft_id=? AND idempotency_key=?",
                (draft_id, str(key)),
            ).fetchone()
        if row is None:
            return None
        if row[0] != request_digest:
            raise DraftConflict("Idempotency key conflicts with KISA inputs")
        return json.loads(row[1])

    def save(self, form, command, request_digest):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT request_sha256,form_json FROM kisa_form_versions WHERE source_draft_id=? AND idempotency_key=?",
                (form["source_draft_id"], str(command.idempotency_key)),
            ).fetchone()
            if previous:
                if previous[0] != request_digest:
                    raise DraftConflict("Idempotency key conflicts with KISA inputs")
                return json.loads(previous[1])
            latest = connection.execute(
                "SELECT coalesce(max(version),0) FROM kisa_form_versions WHERE source_draft_id=?",
                (form["source_draft_id"],),
            ).fetchone()[0]
            if latest != command.expected_form_version:
                raise DraftConflict(
                    "KISA form was concurrently modified; reload its latest version"
                )
            saved = {**form, "form_id": str(uuid4()), "report_version": latest + 1}
            saved["form_snapshot_sha256"] = fingerprint(saved)
            connection.execute(
                "INSERT INTO kisa_form_versions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    saved["form_id"],
                    form["alert_id"],
                    form["source_draft_id"],
                    saved["report_version"],
                    str(command.idempotency_key),
                    request_digest,
                    form["source_snapshot_sha256"],
                    form["actor_id"],
                    form["recorded_at"],
                    json.dumps(saved, ensure_ascii=False),
                ),
            )
        return saved

    def export(self, form_id):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM kisa_docx_exports WHERE form_id=?", (form_id,)
            ).fetchone()
        return dict(row) if row else None

    def save_export(
        self,
        form_id,
        template_digest,
        source_digest,
        form_digest,
        docx_digest,
        renderer_version,
        filename,
        content,
    ):
        with self.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO kisa_docx_exports VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    form_id,
                    template_digest,
                    source_digest,
                    form_digest,
                    docx_digest,
                    renderer_version,
                    utc_now(),
                    filename,
                    content,
                ),
            )
        return self.export(form_id)
