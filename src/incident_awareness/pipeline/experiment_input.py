"""Content-bound experimental labels, never detector conclusions or authenticated truth."""

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.run import RunType


class ExperimentDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run_type: RunType
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def verify(self, content):
        if hashlib.sha256(content).hexdigest() != self.content_sha256:
            raise ValueError("experiment_content_sha256_mismatch")
        return self

    def metadata(self):
        return {
            "experiment-version": "v1",
            "experiment-run-type": self.run_type.value,
            "experiment-content-sha256": self.content_sha256,
            "experiment-source": "explicit_local_demo_declaration",
            "experiment-actor-kind": "unauthenticated_local_demo",
            "experiment-actor-id": "local-demo-analyst",
            "experiment-declared-at": datetime.now(UTC).isoformat(),
        }


def verified_declaration(metadata, content):
    try:
        if (
            metadata["experiment-version"] != "v1"
            or metadata["experiment-source"] != "explicit_local_demo_declaration"
            or metadata["experiment-actor-kind"] != "unauthenticated_local_demo"
            or metadata["experiment-actor-id"] != "local-demo-analyst"
        ):
            raise ValueError
        declared = datetime.fromisoformat(metadata["experiment-declared-at"])
        if declared.utcoffset() is None or declared.utcoffset().total_seconds() != 0:
            raise ValueError
        declaration = ExperimentDeclaration(
            run_type=metadata["experiment-run-type"],
            content_sha256=metadata["experiment-content-sha256"],
        ).verify(content)
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError("valid_content_bound_experiment_declaration_required") from None
    keys = (
        "version",
        "run-type",
        "content-sha256",
        "source",
        "actor-kind",
        "actor-id",
        "declared-at",
    )
    return declaration, {"experiment-" + key: metadata["experiment-" + key] for key in keys}


_DECLARATION = ContextVar("experiment_declaration", default=None)


@contextmanager
def experiment_declaration_context(proof):
    token = _DECLARATION.set(proof)
    try:
        yield
    finally:
        _DECLARATION.reset(token)


def current_experiment_declaration():
    return _DECLARATION.get()
