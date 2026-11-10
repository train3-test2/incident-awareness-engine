"""Human approval -> trusted input -> optional provider -> grounding -> fixed rendering."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from incident_awareness.dashboard.human_workflow import fingerprint
from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.contracts import CallMetadata, canonical_output, verify_output
from incident_awareness.reporting.monorouter import MonoRouterAdapter, ProviderResult, utc_now
from incident_awareness.reporting.store import DraftConflict, ReportDraftStore
from incident_awareness.reporting.synthetic import is_synthetic_fixture, validate_source_input
from incident_awareness.reporting.synthetic_observations import (
    FIXTURE_ID,
    fallback_output,
    is_observation_fixture,
    narrative_output,
    validate_observation_output,
)

LABELS = {
    "incident_occurred_at": "사고 발생 일시",
    "incident_cause": "원인",
    "damage_description": "피해 내용·규모",
    "response_measures": "대응 현황",
    "responsible_department": "담당 부서",
    "contact_information": "연락처",
}


def render_report(output, *, synthetic, analysis=None):
    environment = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
    )
    # A fixed plaintext template, never a template received from a model or user.
    return environment.get_template("draft.txt.j2").render(
        fields=output.fields,
        labels=LABELS,
        synthetic=synthetic,
        analysis=analysis,
    )


class GroundedReportService:
    def __init__(self, store: ReportDraftStore, adapter=None):
        self.store = store
        self.adapter = adapter

    def generate(
        self, report, key, expected_version, reload_input, *, approval=None, actor_id=None
    ):
        source = validate_source_input(report)
        output = canonical_output(source)
        if source.human_state.get("version") != expected_version:
            raise DraftConflict("Workflow changed; reload before generating a draft")
        source_hash = fingerprint(source.model_dump(mode="json"))
        snapshot = None
        adapter = None
        if approval is not None:
            from incident_awareness.reporting.approved_snapshot import preview

            adapter = self.adapter or MonoRouterAdapter(MonoRouterSettings.from_environment())
            snapshot = preview(source, adapter.settings)
            if not actor_id:
                raise DraftConflict("An explicit local actor is required")
            self.store.require_snapshot(
                approval, source.alert_id, expected_version, actor_id, snapshot["snapshot_sha256"]
            )
        draft_id, saved = self.store.claim(source, str(key), source_hash)
        if saved is not None:
            if (
                snapshot
                and saved.get("approved_input", {}).get("snapshot_sha256")
                != snapshot["snapshot_sha256"]
            ):
                raise DraftConflict("Idempotency key belongs to another outbound snapshot")
            return saved
        try:
            try:
                adapter = (
                    adapter
                    or self.adapter
                    or MonoRouterAdapter(MonoRouterSettings.from_environment())
                )
            except ValueError:
                adapter = None
            if (
                snapshot
                and fingerprint(validate_source_input(reload_input()).model_dump(mode="json"))
                != source_hash
            ):
                raise DraftConflict("Source changed before transmission; approve the new snapshot")
            result = (
                adapter.generate_approved(
                    source,
                    self.store,
                    approval,
                    actor_id,
                    lambda m: self.store.record_attempt(draft_id, m),
                )
                if snapshot
                else (
                    adapter.generate(source, lambda m: self.store.record_attempt(draft_id, m))
                    if adapter
                    else (ProviderResult(CallMetadata(status="configuration_error")))
                )
            )
            method = "jinja2_fallback"
            observation_output = (
                fallback_output(source) if is_observation_fixture(source) and not snapshot else None
            )
            approved_prose = None
            if result.text is not None:
                try:
                    if snapshot:
                        from incident_awareness.reporting.approved_snapshot import validate_prose

                        approved_prose = validate_prose(result.text, snapshot["request"])
                    elif observation_output is not None:
                        observation_output = validate_observation_output(result.text, source)
                    else:
                        output = verify_output(result.text, source)
                    method = "monorouter_grounded"
                except (ValueError, TypeError):
                    result.metadata.status = "invalid_output"
            # Persist safe call accounting before checking concurrent workflow updates.
            self.store.record_attempt(draft_id, result.metadata)
            draft = {
                "schema_version": "grounded_report_draft_v1",
                "draft_id": draft_id,
                "document_version": self.store.version(draft_id),
                "run_id": source.run_id,
                "entity_id": source.entity_id,
                "alert_id": source.alert_id,
                "workflow_version": expected_version,
                "human_action_id": source.human_action_id,
                "human_action_version": source.human_action_version,
                "source_snapshot_id": "sha256:" + source_hash,
                "source_snapshot_sha256": source_hash,
                "context": "synthetic_development"
                if is_synthetic_fixture(source)
                else "local_development",
                "method": method,
                "generated_at": utc_now(),
                "submission_status": "not_submitted",
                "legal_obligation": "UNDETERMINED",
                "output": output.model_dump(mode="json"),
                "analysis": source.analysis,
                "verified_observations": [
                    item.model_dump(mode="json") for item in source.verified_observations
                ],
                "review_status_at_generation": "not_reviewed",
                "call_metadata": result.metadata.model_dump(mode="json"),
                "text": render_report(
                    output, synthetic=is_synthetic_fixture(source), analysis=source.analysis
                ),
            }
            if observation_output is not None:
                draft["synthetic_fixture_id"] = FIXTURE_ID
                draft["narrative"] = {
                    "method": method,
                    "call_metadata": draft["call_metadata"],
                    "output": narrative_output(observation_output),
                    "observation_output": observation_output.model_dump(mode="json"),
                    "validation": {
                        "status": "passed" if method == "monorouter_grounded" else "fallback",
                        "validator": "bounded_observation_language_v1",
                        "fallback_reason": None
                        if method == "monorouter_grounded"
                        else result.metadata.status,
                        "input_snapshot_sha256": source_hash,
                        "synthetic_reference_simulation": True,
                    },
                }
                draft["text"] += "\n" + draft["narrative"]["output"]["observed_indicators"] + "\n"
            if snapshot:
                draft["approved_input"] = {
                    "snapshot_sha256": snapshot["snapshot_sha256"],
                    "consent_id": str(approval),
                    "policy": snapshot["policy"],
                }
                if approved_prose is not None and method == "monorouter_grounded":
                    from incident_awareness.reporting.approved_snapshot import saved_narrative

                    settings = adapter.settings
                    draft["approved_input"].update(
                        {
                            "source": source.model_dump(mode="json"),
                            "settings": {
                                name: getattr(settings, name)
                                for name in (
                                    "endpoint",
                                    "model",
                                    "expected_response_model",
                                    "max_tokens",
                                )
                            },
                            "prose": approved_prose.model_dump(mode="json"),
                        }
                    )
                    draft["narrative"] = saved_narrative(draft)
                    draft["text"] += (
                        f"\n{approved_prose.incident_content}\n{approved_prose.confirmed_damage}"
                        f"\n{approved_prose.confirmed_response}\n{approved_prose.further_checks}\n"
                    )
            latest = validate_source_input(reload_input())
            stale = fingerprint(latest.model_dump(mode="json")) != source_hash
            self.store.finish(draft_id, draft, stale=stale)
            if stale:
                raise DraftConflict("Workflow changed during generation; draft invalidated")
            return draft
        except BaseException:
            self.store.fail(draft_id)
            raise
