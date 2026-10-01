-- Apply once after 001_first_cycle.sql, in a transaction.
-- The composite FK prevents cross-Run Decision references.
ALTER TABLE decisions ADD CONSTRAINT decisions_run_decision_unique UNIQUE (run_id, decision_id);
CREATE TABLE report_drafts (
    run_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    fields JSONB NOT NULL CHECK (jsonb_typeof(fields) = 'object'),
    source_decision JSONB NOT NULL CHECK (jsonb_typeof(source_decision) = 'object'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, decision_id),
    FOREIGN KEY (run_id, decision_id) REFERENCES decisions (run_id, decision_id)
);
