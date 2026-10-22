"""Fail-closed ownership of one newly created, disposable local PostgreSQL database."""

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from urllib.parse import quote
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from incident_awareness.storage.migrate import apply_migrations

LAB_DATABASE = re.compile(r"iae_telemetry_lab_[a-f0-9]{32}\Z")
READ_OPTIONS = "-c default_transaction_read_only=on -c statement_timeout=5000 -c timezone=UTC"
WRITE_OPTIONS = (
    "-c default_transaction_read_only=off -c statement_timeout=2000 "
    "-c lock_timeout=2000 -c transaction_timeout=5000 -c timezone=UTC"
)


@dataclass(frozen=True)
class LabIdentity:
    database: str
    lab_id: str
    database_oid: int
    owner_marker: str

    def validate(self) -> None:
        if (
            not LAB_DATABASE.fullmatch(self.database)
            or self.database != "iae_telemetry_lab_" + self.lab_id
            or type(self.database_oid) is not int
            or self.database_oid <= 0
            or not re.fullmatch(
                r"incident-awareness-telemetry-lab-v1:[a-f0-9]{32}", self.owner_marker
            )
        ):
            raise ValueError("Not an owned Telemetry lab database")

    def public(self) -> dict:
        return {"database": self.database, "lab_id": self.lab_id}


def local_admin_dsn(container: str = "modeling-postgres-1") -> str:
    """Read local Docker credentials in memory; never return them to HTTP or logs."""
    inspected = subprocess.run(
        ["docker", "inspect", container], capture_output=True, text=True, check=True, timeout=10
    )
    data = json.loads(inspected.stdout)[0]
    settings = dict(item.split("=", 1) for item in data["Config"]["Env"])
    bindings = data["NetworkSettings"]["Ports"]["5432/tcp"]
    binding = next(item for item in bindings if item["HostIp"] in {"127.0.0.1", "0.0.0.0"})
    return make_conninfo(
        host="127.0.0.1",
        port=binding["HostPort"],
        dbname="postgres",
        user=settings["POSTGRES_USER"],
        password=settings["POSTGRES_PASSWORD"],
    )


def _require_local(connection, expected_database: str) -> None:
    if connection.info.host not in {"127.0.0.1", "::1"}:
        raise ValueError("Only a local PostgreSQL connection is allowed")
    if connection.info.dbname != expected_database:
        raise ValueError("Connection database does not match the explicit target")


def target_dsn(admin_dsn: str, identity: LabIdentity) -> str:
    identity.validate()
    values = conninfo_to_dict(admin_dsn)
    if values.get("host") not in {"127.0.0.1", "::1"} or values.get("dbname") != "postgres":
        raise ValueError("Explicit local postgres administration connection required")
    # Dashboard DatabaseConfig validates a PostgreSQL URI, not libpq keyword DSNs.
    host = values["host"]
    if ":" in host:
        host = f"[{host}]"
    credentials = quote(values.get("user", ""), safe="")
    if "password" in values:
        credentials += ":" + quote(values["password"], safe="")
    return f"postgresql://{credentials}@{host}:{values.get('port', '5432')}/" + quote(
        identity.database, safe=""
    )


def verify_owner(connection, identity: LabIdentity) -> None:
    """Called BEFORE migrations, every writer connection, reset, and cleanup."""
    identity.validate()
    _require_local(connection, identity.database)
    row = connection.execute(
        "SELECT current_database(), oid, shobj_description(oid, 'pg_database') "
        "FROM pg_database WHERE datname = current_database()"
    ).fetchone()
    if row != (identity.database, identity.database_oid, identity.owner_marker):
        raise ValueError("Lab ownership/OID marker mismatch; refusing access")


def connect_lab(admin_dsn: str, identity: LabIdentity, *, readonly: bool = False):
    identity.validate()
    connection = psycopg.connect(
        target_dsn(admin_dsn, identity),
        connect_timeout=2,
        options=READ_OPTIONS if readonly else WRITE_OPTIONS,
    )
    try:
        verify_owner(connection, identity)
        actual = connection.execute("SHOW transaction_read_only").fetchone()[0]
        if actual != ("on" if readonly else "off"):
            raise ValueError("Unexpected transaction access mode")
        connection.commit()
        return connection
    except BaseException:
        connection.close()
        raise


def create_database(admin_dsn: str) -> tuple[LabIdentity, tuple[str, ...]]:
    """No caller-supplied target name. Existing DBs can never be migration targets."""
    lab_id = uuid4().hex
    name = "iae_telemetry_lab_" + lab_id
    marker = "incident-awareness-telemetry-lab-v1:" + uuid4().hex
    with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=2) as admin:
        _require_local(admin, "postgres")
        if admin.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
            raise ValueError("Lab target already exists")
        admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
        admin.execute(
            sql.SQL("COMMENT ON DATABASE {} IS {}").format(
                sql.Identifier(name), sql.Literal(marker)
            )
        )
        oid = admin.execute("SELECT oid FROM pg_database WHERE datname=%s", (name,)).fetchone()[0]
    identity = LabIdentity(name, lab_id, oid, marker)
    try:
        with connect_lab(admin_dsn, identity) as connection:
            if connection.execute(
                "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
            ).fetchone()[0]:
                raise ValueError("Migration requires a newly empty lab database")
            migrations = apply_migrations(connection)
            if len(migrations) != 15 or not migrations[-1].startswith("015_"):
                raise ValueError("Expected the reviewed 001 through 015 migration set")
        return identity, migrations
    except BaseException:
        drop_database(admin_dsn, identity)
        raise


def reset_observations(admin_dsn: str, identity: LabIdentity) -> None:
    with connect_lab(admin_dsn, identity) as connection:
        # Explicit allowlist: no business Run/Event/Evidence/Decision tables are written.
        connection.execute("DELETE FROM pipeline_telemetry_buckets")
        connection.execute("DELETE FROM pipeline_telemetry_executions")


def drop_database(admin_dsn: str, identity: LabIdentity) -> None:
    """Never FORCE/terminate sessions, never drop a name without matching marker and OID."""
    identity.validate()
    with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=2) as admin:
        _require_local(admin, "postgres")
        row = admin.execute(
            "SELECT oid, shobj_description(oid, 'pg_database') FROM pg_database WHERE datname=%s",
            (identity.database,),
        ).fetchone()
        if row != (identity.database_oid, identity.owner_marker):
            raise ValueError("Cleanup ownership mismatch; refusing to drop database")
        if admin.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE datname=%s", (identity.database,)
        ).fetchone()[0]:
            raise ValueError("Lab sessions are still connected; stop the owned lab server first")
        admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(identity.database)))


def identity_record(identity: LabIdentity) -> dict:
    """Private local cleanup manifest, not part of the public API."""
    return asdict(identity)
