"""Separate continuous-QA ownership namespace, never an existing lab or business DB."""

import re
from dataclasses import dataclass
from uuid import uuid4

import psycopg
from psycopg import sql

from incident_awareness.devtools.telemetry_lab_database import (
    LabIdentity,
    connect_lab,
    drop_database,
)
from incident_awareness.storage.migrate import apply_migrations


@dataclass(frozen=True)
class ContinuousQaIdentity(LabIdentity):
    def validate(self) -> None:
        if (
            not re.fullmatch(r"iae_continuous_qa_[a-f0-9]{32}", self.database)
            or self.database != "iae_continuous_qa_" + self.lab_id
            or type(self.database_oid) is not int
            or self.database_oid <= 0
            or not re.fullmatch(
                r"incident-awareness-continuous-qa-v1:[a-f0-9]{32}", self.owner_marker
            )
        ):
            raise ValueError("Not an owned continuous QA database")


def create_continuous_database(admin_dsn: str) -> tuple[ContinuousQaIdentity, tuple[str, ...]]:
    identity_id = uuid4().hex
    name = "iae_continuous_qa_" + identity_id
    marker = "incident-awareness-continuous-qa-v1:" + uuid4().hex
    with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=2) as admin:
        if admin.info.host not in {"127.0.0.1", "::1"} or admin.info.dbname != "postgres":
            raise ValueError("Local explicit administration connection required")
        if admin.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
            raise ValueError("QA DB collision")
        admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
        admin.execute(
            sql.SQL("COMMENT ON DATABASE {} IS {}").format(
                sql.Identifier(name), sql.Literal(marker)
            )
        )
        oid = admin.execute("SELECT oid FROM pg_database WHERE datname=%s", (name,)).fetchone()[0]
    identity = ContinuousQaIdentity(name, identity_id, oid, marker)
    try:
        with connect_lab(admin_dsn, identity) as connection:
            if connection.execute(
                "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
            ).fetchone()[0]:
                raise ValueError("Migrations require a newly empty continuous QA DB")
            migrations = apply_migrations(connection)
            if len(migrations) != 15 or not migrations[-1].startswith("015_"):
                raise ValueError("Unreviewed migration set")
        return identity, migrations
    except BaseException:
        drop_database(admin_dsn, identity)
        raise
