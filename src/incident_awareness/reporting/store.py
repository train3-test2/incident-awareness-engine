"""Separate durable draft ledger. Never stores prompts, provider bodies or API keys."""

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

from incident_awareness.reporting.monorouter import utc_now


class DraftConflict(ValueError):
    pass


class ReportDraftStore:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=2)) as connection, connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=2000")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS report_drafts (
                    draft_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    workflow_version INTEGER NOT NULL,
                    human_action_id TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL CHECK(status IN ('processing','completed','stale','failed')),
                    call_metadata TEXT,
                    draft_json TEXT,
                    UNIQUE(alert_id,idempotency_key)
                )
            """)
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS report_versions (
                    draft_id TEXT PRIMARY KEY REFERENCES report_drafts(draft_id),
                    alert_id TEXT NOT NULL, version INTEGER NOT NULL,
                    UNIQUE(alert_id,version)
                );
                CREATE TABLE IF NOT EXISTS report_reviews (
                    review_id TEXT PRIMARY KEY, draft_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, actor_id TEXT NOT NULL,
                    recorded_at TEXT NOT NULL, draft_sha256 TEXT NOT NULL,
                    UNIQUE(draft_id,idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS report_pdf_exports (
                    draft_id TEXT PRIMARY KEY, document_version INTEGER NOT NULL,
                    draft_sha256 TEXT NOT NULL, pdf_sha256 TEXT NOT NULL,
                    generated_at TEXT NOT NULL, pdf_bytes BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS report_external_consents (
                    consent_id TEXT PRIMARY KEY, anchor_alert_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, workflow_version INTEGER NOT NULL,
                    actor_id TEXT NOT NULL, recorded_at TEXT NOT NULL,
                    fixture_sha256 TEXT NOT NULL,
                    UNIQUE(anchor_alert_id,idempotency_key)
                );
            """)
            yield connection

    def version(self, draft_id):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT alert_id FROM report_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise LookupError("Draft not found")
            alert = row[0]
            latest = connection.execute(
                "SELECT coalesce(max(version),0) FROM report_versions WHERE alert_id=?", (alert,)
            ).fetchone()[0]
            for (identity,) in connection.execute(
                "SELECT draft_id FROM report_drafts WHERE alert_id=? ORDER BY rowid", (alert,)
            ).fetchall():
                if not connection.execute(
                    "SELECT 1 FROM report_versions WHERE draft_id=?", (identity,)
                ).fetchone():
                    latest += 1
                    connection.execute(
                        "INSERT INTO report_versions VALUES (?,?,?)", (identity, alert, latest)
                    )
            return connection.execute(
                "SELECT version FROM report_versions WHERE draft_id=?", (draft_id,)
            ).fetchone()[0]

    def load(self, draft_id, alert_id=None):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT alert_id,status,draft_json FROM report_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
        if row is None or (alert_id is not None and row["alert_id"] != alert_id):
            raise LookupError("Draft not found")
        if row["status"] != "completed" or not row["draft_json"]:
            raise DraftConflict("Draft is not completed")
        return json.loads(row["draft_json"])

    def review(self, draft_id, key, actor_id, digest):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO report_reviews VALUES (?,?,?,?,?,?)",
                (str(uuid4()), draft_id, str(key), actor_id, utc_now(), digest),
            )
            row = connection.execute(
                "SELECT * FROM report_reviews WHERE draft_id=? AND idempotency_key=?",
                (draft_id, str(key)),
            ).fetchone()
            if row["draft_sha256"] != digest:
                raise DraftConflict("Review conflicts with saved draft")
            return dict(row)

    def review_for(self, draft_id):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM report_reviews WHERE draft_id=? ORDER BY recorded_at DESC LIMIT 1",
                (draft_id,),
            ).fetchone()
            return dict(row) if row else None

    def consent(self, alert_id, key, version, actor_id, digest):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO report_external_consents VALUES (?,?,?,?,?,?,?)",
                (str(uuid4()), alert_id, str(key), version, actor_id, utc_now(), digest),
            )
            row = connection.execute(
                "SELECT * FROM report_external_consents WHERE anchor_alert_id=? AND idempotency_key=?",
                (alert_id, str(key)),
            ).fetchone()
            if row["workflow_version"] != version or row["fixture_sha256"] != digest:
                raise DraftConflict("Synthetic consent conflicts with current source")
            return dict(row)

    @contextmanager
    def snapshot_connection(self):
        """Separate, append-only grants. No existing consent is upgraded or reused."""
        with self.connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS report_snapshot_consents (
                    consent_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL, snapshot_sha256 TEXT NOT NULL,
                    workflow_version INTEGER NOT NULL, recorded_at TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, UNIQUE(alert_id,idempotency_key)
                )
            """)
            for verb in ("UPDATE", "DELETE"):
                connection.execute(
                    f"CREATE TRIGGER IF NOT EXISTS report_snapshot_consents_no_{verb.lower()} "
                    f"BEFORE {verb} ON report_snapshot_consents BEGIN "
                    "SELECT RAISE(ABORT,'Snapshot approvals are append-only'); END"
                )
            yield connection

    def approve_snapshot(self, alert_id, key, version, actor_id, digest):
        with self.snapshot_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO report_snapshot_consents VALUES (?,?,?,?,?,?,?)",
                (str(uuid4()), alert_id, actor_id, digest, version, utc_now(), str(key)),
            )
            row = connection.execute(
                "SELECT * FROM report_snapshot_consents WHERE alert_id=? AND idempotency_key=?",
                (alert_id, str(key)),
            ).fetchone()
            if (row["workflow_version"], row["actor_id"], row["snapshot_sha256"]) != (
                version,
                actor_id,
                digest,
            ):
                raise DraftConflict("Snapshot approval key conflicts with current input")
            return dict(row)

    def require_snapshot(self, consent_id, alert_id, version, actor_id, digest):
        if not self.path.exists():
            raise DraftConflict("Snapshot approval is missing; preview and approve first")
        with closing(
            sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)
        ) as connection:
            connection.row_factory = sqlite3.Row
            if not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='report_snapshot_consents'"
            ).fetchone():
                raise DraftConflict("Snapshot approval is missing; preview and approve first")
            row = connection.execute(
                "SELECT * FROM report_snapshot_consents WHERE consent_id=?", (str(consent_id),)
            ).fetchone()
        if row is None or (
            row["alert_id"],
            row["workflow_version"],
            row["actor_id"],
            row["snapshot_sha256"],
        ) != (alert_id, version, actor_id, digest):
            raise DraftConflict("Snapshot approval is missing or stale; preview and approve again")
        return dict(row)

    def pdf_export(self, draft_id):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM report_pdf_exports WHERE draft_id=?", (draft_id,)
            ).fetchone()
            return dict(row) if row else None

    def synthetic_authorization(self, draft_id):
        """Resolve a synthetic draft to its local-only, explicit consent anchor."""
        from incident_awareness.dashboard.human_workflow import fingerprint
        from incident_awareness.reporting.synthetic_observations import synthetic_observation_input

        fixture = synthetic_observation_input()
        with self.connect() as connection:
            draft = connection.execute(
                "SELECT * FROM report_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if (
                draft is None
                or draft["alert_id"] != fixture.alert_id
                or draft["source_sha256"] != fingerprint(fixture.model_dump(mode="json"))
            ):
                raise DraftConflict("Synthetic source authorization does not match")
            rows = connection.execute(
                "SELECT * FROM report_external_consents WHERE fixture_sha256=?",
                (draft["source_sha256"],),
            ).fetchall()
        for row in rows:
            key = str(uuid5(NAMESPACE_URL, row["anchor_alert_id"] + ":" + row["idempotency_key"]))
            if key == draft["idempotency_key"]:
                return dict(row)
        raise DraftConflict("Explicit synthetic transmission consent is missing")

    def save_pdf(self, draft_id, version, draft_digest, pdf_digest, content):
        with self.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO report_pdf_exports VALUES (?,?,?,?,?,?)",
                (draft_id, version, draft_digest, pdf_digest, utc_now(), content),
            )
        return self.pdf_export(draft_id)

    def claim(self, report, key: str, source_hash: str):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM report_drafts WHERE alert_id=? AND idempotency_key=?",
                (report.alert_id, key),
            ).fetchone()
            if row:
                if row["source_sha256"] != source_hash:
                    raise DraftConflict("Idempotency key conflicts with current report input")
                if row["status"] != "completed":
                    raise DraftConflict("Draft is in progress or invalidated; inspect its status")
                return row["draft_id"], json.loads(row["draft_json"])
            draft_id = str(uuid4())
            connection.execute(
                "INSERT INTO report_drafts "
                "(draft_id,alert_id,idempotency_key,workflow_version,human_action_id,"
                "source_sha256,created_at,status) VALUES (?,?,?,?,?,?,?,'processing')",
                (
                    draft_id,
                    report.alert_id,
                    key,
                    report.human_state["version"],
                    report.human_action_id,
                    source_hash,
                    utc_now(),
                ),
            )
            return draft_id, None

    def record_attempt(self, draft_id, metadata):
        with self.connect() as connection:
            connection.execute(
                "UPDATE report_drafts SET call_metadata=? WHERE draft_id=? AND status='processing'",
                (metadata.model_dump_json(), draft_id),
            )

    def finish(self, draft_id, draft, *, stale=False):
        with self.connect() as connection:
            result = connection.execute(
                "UPDATE report_drafts SET status=?,completed_at=?,call_metadata=?,draft_json=? "
                "WHERE draft_id=? AND status='processing'",
                (
                    "stale" if stale else "completed",
                    utc_now(),
                    json.dumps(draft["call_metadata"]),
                    None if stale else json.dumps(draft),
                    draft_id,
                ),
            )
            if result.rowcount != 1:
                raise DraftConflict("Draft already finalized")

    def fail(self, draft_id):
        with self.connect() as connection:
            connection.execute(
                "UPDATE report_drafts SET status='failed',completed_at=? "
                "WHERE draft_id=? AND status='processing'",
                (utc_now(), draft_id),
            )

    def list_for_alert(self, alert_id):
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT draft_id,workflow_version,created_at,completed_at,status,call_metadata,"
                "draft_json FROM report_drafts WHERE alert_id=? ORDER BY created_at DESC LIMIT 50",
                (alert_id,),
            ).fetchall()
        return [
            {
                **{k: row[k] for k in dict(row) if k not in {"call_metadata", "draft_json"}},
                "call_metadata": json.loads(row["call_metadata"]) if row["call_metadata"] else None,
                "draft": json.loads(row["draft_json"]) if row["draft_json"] else None,
            }
            for row in rows
        ]
