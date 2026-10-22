"""Source-draft mapping, conservative narrative, and versioned human form inputs."""

from uuid import uuid4

from incident_awareness.dashboard.human_workflow import DEMO_ACTOR, fingerprint
from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.kisa_mapping import build_form_data
from incident_awareness.reporting.kisa_narrative import generate_narrative
from incident_awareness.reporting.monorouter import MonoRouterAdapter, utc_now
from incident_awareness.reporting.store import DraftConflict


def create_form(draft_store, form_store, draft, command, reload_source):
    if draft["workflow_version"] != command.expected_workflow_version:
        raise DraftConflict("KISA form requires the selected source draft's workflow version")
    request_digest = fingerprint(
        {"command": command.model_dump(mode="json"), "source_sha256": fingerprint(draft)}
    )
    previous = form_store.existing(draft["draft_id"], command.idempotency_key, request_digest)
    if previous:
        return previous
    form = build_form_data(
        draft,
        draft_store.version(draft["draft_id"]),
        command,
        action_id=str(uuid4()),
        actor_id=DEMO_ACTOR["actor_id"],
        recorded_at=utc_now(),
    )
    try:
        adapter = MonoRouterAdapter(MonoRouterSettings.from_environment())
    except ValueError:
        adapter = None
    form["narrative"] = generate_narrative(
        draft,
        form,
        adapter,
        lambda metadata: form_store.record_attempt(
            form["human_action_id"], draft["draft_id"], metadata
        ),
    )
    if fingerprint(reload_source()) != fingerprint(draft):
        raise DraftConflict("Source draft or workflow changed during form preparation")
    return form_store.save(form, command, request_digest)
