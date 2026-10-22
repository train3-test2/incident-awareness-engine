-- Additive only. No rewrite/backfill of analytical results or human actions.
CREATE TABLE human_workflow_alerts (
    alert_id TEXT PRIMARY KEY,
    source_key TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    entity_id TEXT NOT NULL CHECK (btrim(entity_id) <> ''),
    decision_id TEXT REFERENCES decisions(decision_id) ON DELETE RESTRICT,
    detection_kind TEXT NOT NULL CHECK (detection_kind IN ('fusion', 'hybrid')),
    detected_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    source_snapshot JSONB NOT NULL CHECK (jsonb_typeof(source_snapshot) = 'object')
);
CREATE INDEX human_workflow_alerts_run_idx ON human_workflow_alerts(run_id, issued_at);

CREATE TABLE human_workflow_actions (
    action_id UUID PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES human_workflow_alerts(alert_id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version > 0),
    idempotency_key UUID NOT NULL,
    actor_id TEXT NOT NULL CHECK (actor_id = 'local-demo-analyst'),
    actor_kind TEXT NOT NULL CHECK (actor_kind = 'unauthenticated_local_demo'),
    action TEXT NOT NULL CHECK (action IN ('acknowledge', 'review_evidence', 'record_awareness',
                                         'decide_reporting')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    command JSONB NOT NULL CHECK (jsonb_typeof(command) = 'object'),
    previous_state JSONB NOT NULL CHECK (jsonb_typeof(previous_state) = 'object'),
    resulting_state JSONB NOT NULL CHECK (jsonb_typeof(resulting_state) = 'object'),
    UNIQUE(alert_id, version),
    UNIQUE(alert_id, idempotency_key)
);

CREATE FUNCTION guard_human_workflow_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Human Workflow records are append-only';
END;
$$;
CREATE TRIGGER human_workflow_alerts_immutable BEFORE UPDATE OR DELETE ON human_workflow_alerts
    FOR EACH ROW EXECUTE FUNCTION guard_human_workflow_immutable();
CREATE TRIGGER human_workflow_actions_immutable BEFORE UPDATE OR DELETE ON human_workflow_actions
    FOR EACH ROW EXECUTE FUNCTION guard_human_workflow_immutable();
