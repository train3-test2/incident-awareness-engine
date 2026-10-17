// Test-only Read v1 fixtures. Never imported by the operating Dashboard.
export const stages = ["artifact_validation", "normalization", "fusion", "fast_handoff", "hybrid", "persistence"];
export const target = { runId: "RUN-TEST", entityId: "ENTITY-TEST", executionId: "execution-test", status: "completed", currentStage: null };
export function timingPayload({ scope = target, selectedStages = stages, durations = [], failed = null,
    active = null, issues = [], nullDuration = false } = {}) {
    const records = selectedStages.map((stage, index) => ({
        stage, invocation_index: String(index + 1), outcome: stage === failed ? "failed" : "completed",
        started_at: "2026-10-18T01:02:03.000Z", ended_at: "2026-10-18T01:02:03.001Z",
        duration_ns: nullDuration ? null : durations[index] ?? String((index + 1) * 1000000),
        issues: nullDuration ? ["monotonic_clock_error"] : [],
    }));
    return {
        schema_version: "pipeline_stage_timing_read_v1", execution_id: scope.executionId,
        availability: records.length ? "recorded" : "no_stage_timings",
        snapshot: { schema_version: "pipeline_stage_timing_v1", attempt_id: "attempt-test",
            execution_id: scope.executionId, run_id: scope.runId, entity_id: scope.entityId,
            revision: "17", records, active_stage: active,
            active_invocation_index: active ? String(records.length + 1) : null, issues,
            quality_status: !records.length ? "unavailable" : issues.length || nullDuration ? "partial" : "observed" },
        persisted_at: "2026-10-18T01:02:04.000Z", duration_unit: "ns", integer_encoding: "decimal_string",
        coverage_status: "not_evaluable", execution_outcome: "unknown", ended_invocation_count: records.length,
        operation_failure_recorded: failed !== null,
        unmeasured_stages: stages.filter((stage) => !selectedStages.includes(stage)),
        missing_stage_meaning: "not_observed_not_proof_of_not_run",
    };
}
