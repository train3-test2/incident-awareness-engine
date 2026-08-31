from datetime import UTC, datetime

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from incident_awareness.common.models.fusion_output import FusionOutput


def make_detected_output() -> FusionOutput:
    return FusionOutput(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_status="detected",
        fusion_time=datetime(
            2026,
            8,
            31,
            1,
            0,
            40,
            tzinfo=UTC,
        ),
        score_at_decision=0.75,
        contributing_evidence_ids=[
            "E-001",
            "E-002",
            "E-003",
        ],
        decision_reason="threshold_persistence_satisfied",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        evidence_schema_version="v0.1",
        scoring_config_version="v0.1",
        scoring_profile_id="fixture-v0.1",
        git_commit="abc1234",
    )


def test_accepts_detected_output() -> None:
    output = make_detected_output()

    assert output.fusion_status == "detected"
    assert output.fusion_time is not None
    assert output.score_at_decision == 0.75


def test_accepts_miss_output() -> None:
    output = FusionOutput(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_status="miss",
        fusion_time=None,
        score_at_decision=None,
        contributing_evidence_ids=[],
        decision_reason="stopping_condition_not_satisfied",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        evidence_schema_version="v0.1",
        scoring_config_version="v0.1",
        scoring_profile_id="fixture-v0.1",
        git_commit="abc1234",
    )

    assert output.fusion_time is None
    assert output.score_at_decision is None


def test_accepts_not_evaluated_output() -> None:
    output = FusionOutput(
        run_id="RUN-01",
        entity_id="HOST-01",
        fusion_status="not_evaluated",
        fusion_time=None,
        score_at_decision=None,
        contributing_evidence_ids=[],
        decision_reason="fusion_evaluator_not_run",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        evidence_schema_version="v0.1",
        scoring_config_version="v0.1",
        scoring_profile_id="fixture-v0.1",
        git_commit="abc1234",
    )

    assert output.fusion_status == "not_evaluated"


def test_detected_requires_fusion_time() -> None:
    with pytest.raises(
        ValidationError,
        match="fusion_time is required",
    ):
        FusionOutput(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_status="detected",
            fusion_time=None,
            score_at_decision=0.75,
            contributing_evidence_ids=["E-001"],
            decision_reason="threshold_persistence_satisfied",
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            evidence_schema_version="v0.1",
            scoring_config_version="v0.1",
            scoring_profile_id="fixture-v0.1",
            git_commit="abc1234",
        )


def test_detected_requires_score_at_decision() -> None:
    with pytest.raises(
        ValidationError,
        match="score_at_decision is required",
    ):
        FusionOutput(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_status="detected",
            fusion_time=datetime(
                2026,
                8,
                31,
                1,
                0,
                40,
                tzinfo=UTC,
            ),
            score_at_decision=None,
            contributing_evidence_ids=["E-001"],
            decision_reason="threshold_persistence_satisfied",
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            evidence_schema_version="v0.1",
            scoring_config_version="v0.1",
            scoring_profile_id="fixture-v0.1",
            git_commit="abc1234",
        )


def test_miss_rejects_fusion_time() -> None:
    with pytest.raises(
        ValidationError,
        match="fusion_time must be null",
    ):
        FusionOutput(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_status="miss",
            fusion_time=datetime(
                2026,
                8,
                31,
                1,
                0,
                40,
                tzinfo=UTC,
            ),
            score_at_decision=None,
            contributing_evidence_ids=[],
            decision_reason="stopping_condition_not_satisfied",
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            evidence_schema_version="v0.1",
            scoring_config_version="v0.1",
            scoring_profile_id="fixture-v0.1",
            git_commit="abc1234",
        )


def test_rejects_score_outside_unit_interval() -> None:
    with pytest.raises(ValidationError):
        FusionOutput(
            run_id="RUN-01",
            entity_id="HOST-01",
            fusion_status="detected",
            fusion_time=datetime(
                2026,
                8,
                31,
                1,
                0,
                40,
                tzinfo=UTC,
            ),
            score_at_decision=1.1,
            contributing_evidence_ids=["E-001"],
            decision_reason="threshold_persistence_satisfied",
            scoring_method="simple_score",
            scorer_version="simple-score-v0.1",
            evidence_schema_version="v0.1",
            scoring_config_version="v0.1",
            scoring_profile_id="fixture-v0.1",
            git_commit="abc1234",
        )


def test_generated_schema_rejects_detected_with_null_fusion_time() -> None:
    schema = FusionOutput.model_json_schema()

    invalid_output = {
        "schema_version": "fusion_output_v0.1",
        "run_id": "RUN-01",
        "entity_id": "HOST-01",
        "fusion_status": "detected",
        "fusion_time": None,
        "score_at_decision": 0.75,
        "contributing_evidence_ids": ["E-001"],
        "decision_reason": "threshold_persistence_satisfied",
        "scoring_method": "simple_score",
        "scorer_version": "simple-score-v0.1",
        "evidence_schema_version": "v0.1",
        "scoring_config_version": "v0.1",
        "scoring_profile_id": "fixture-v0.1",
        "git_commit": "abc1234",
    }

    validator = Draft202012Validator(schema)

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(invalid_output)


def test_generated_schema_rejects_miss_with_fusion_time() -> None:
    schema = FusionOutput.model_json_schema()

    invalid_output = {
        "schema_version": "fusion_output_v0.1",
        "run_id": "RUN-01",
        "entity_id": "HOST-01",
        "fusion_status": "miss",
        "fusion_time": "2026-08-31T01:00:40Z",
        "score_at_decision": None,
        "contributing_evidence_ids": [],
        "decision_reason": "stopping_condition_not_satisfied",
        "scoring_method": "simple_score",
        "scorer_version": "simple-score-v0.1",
        "evidence_schema_version": "v0.1",
        "scoring_config_version": "v0.1",
        "scoring_profile_id": "fixture-v0.1",
        "git_commit": "abc1234",
    }

    validator = Draft202012Validator(schema)

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(invalid_output)
