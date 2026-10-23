import assert from "node:assert/strict";
import test from "node:test";
import { labPresentation } from "../../../src/incident_awareness/devtools/telemetry_lab/lab-contract.mjs";

function status(phase = "idle") {
    return { schema_version: "telemetry_lab_v1", simulation: true, operational_measurement: false,
        dashboard_read_only: true, database: "iae_telemetry_lab_" + "a".repeat(32), phase, speed: "low", active_seconds: 0,
        stored: { accepted: 0, completed: 0, failed: 0, executions: 0, buckets: 0, latency_samples: 0, latency_sum_ns: 0 } };
}
for (const [phase, enabled] of [["idle", "start"], ["running", "pause"], ["paused", "resume"], ["completed", "reset"], ["error", "reset"]]) {
    test(`Lab ${phase} labels fixture semantics and offers ${enabled}`, () => {
        // Given / When
        const model = labPresentation(status(phase));
        // Then
        assert.match(model.label, /운영 실측 아님/);
        assert.equal(model[enabled], true);
        assert.equal(model.elapsed, "0");
    });
}
for (const patch of [{ operational_measurement: true }, { simulation: false }, { dashboard_read_only: false },
    { phase: "invented" }, { database: "incident_awareness_dev" }, { active_seconds: -1 }]) {
    test(`Lab rejects misleading status ${Object.keys(patch)[0]}=${Object.values(patch)[0]}`, () => {
        // Given / When / Then
        assert.throws(() => labPresentation({ ...status(), ...patch }), TypeError);
    });
}
test("Lab rejects unknown stored counters instead of inventing zero", () => {
    // Given
    const value = status();
    value.stored.completed = null;
    // When / Then
    assert.throws(() => labPresentation(value), TypeError);
});
