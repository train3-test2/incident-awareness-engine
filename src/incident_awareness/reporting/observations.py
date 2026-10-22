"""Recheck immutable provenance snapshots before using their observations in prose."""

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evidence.provenance import EvidenceResolution, digest, make_observation


def snapshot_observations(analysis, *, run_id, entity_id):
    try:
        return _snapshot_observations(analysis, run_id=run_id, entity_id=entity_id)
    except (KeyError, IndexError, TypeError, AttributeError) as error:
        raise ValueError("Observation snapshot is incomplete") from error


def _snapshot_observations(analysis, *, run_id, entity_id):
    provenance = analysis.get("evidence_provenance") if analysis else None
    if provenance is None:
        return []
    if (
        provenance.get("run_id") != run_id
        or provenance.get("schema_version") != "evidence_provenance_v1"
    ):
        raise ValueError("Observation snapshot scope mismatch")
    events = {}
    for payload in provenance["source_events"]:
        event = NormalizedEvent.model_validate(payload)
        if event.run_id != run_id or event.event_id in events:
            raise ValueError("Observation Event scope mismatch")
        events[event.event_id] = event
    observations = []
    for payload in provenance["items"]:
        item = EvidenceResolution.model_validate(payload)
        if item.resolution_status != "raw_verified":
            if item.observed_behavior:
                raise ValueError("Unverified Evidence cannot describe behavior")
            continue
        if (item.run_id, item.entity_id) != (run_id, entity_id):
            raise ValueError("Observation Evidence scope mismatch")
        evidence = Evidence.model_validate(
            {
                key: payload[key]
                for key in (
                    "evidence_id",
                    "run_id",
                    "timestamp",
                    "entity_id",
                    "evidence_type",
                    "event_ids",
                    "derived_from_source_layer",
                    "feature_channel_group",
                    "extractor_version",
                    "features",
                )
            }
        )
        details = item.validation_details
        if digest(evidence.model_dump(mode="json")) != details["evidence_sha256"]:
            raise ValueError("Observation Evidence digest mismatch")
        checks = details["raw_checks"]
        event_checks = details["events"]
        if len(checks) != len(item.event_ids) or len(event_checks) != len(item.event_ids):
            raise ValueError("Incomplete multi-Event observation proof")
        expected = []
        for index, (eid, proof, event_check) in enumerate(
            zip(item.event_ids, checks, event_checks, strict=True)
        ):
            event = events[eid]
            if (
                event.host_id != entity_id
                or proof.get("verified") is not True
                or proof.get("reason") is not None
                or proof["event_id"] != eid
                or event_check["event_id"] != eid
                or event_check["event_sha256"] != digest(event.model_dump(mode="json"))
                or item.raw_references[index] != event.raw_ref
                or item.source_event_ids[index] != event.source_event_id
            ):
                raise ValueError("Observation raw proof mismatch")
            observation = make_observation(evidence, event, proof)
            if observation and evidence.feature_channel_group == "fusion_feature":
                expected.append(observation)
        if tuple(expected) != item.observed_behavior:
            raise ValueError("Observation prose conflicts with verified fields")
        observations.extend(expected)
    serialized = [o.model_dump(mode="json") for o in observations]
    if serialized != provenance["verified_observations"] or serialized != analysis.get(
        "verified_observations"
    ):
        raise ValueError("Observation list conflicts with source proof")
    return observations
