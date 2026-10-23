import assert from "node:assert/strict";
import {test} from "node:test";
import {loadOfflineDisplay, offlineCase, validateOfflineDisplay} from "../../../src/incident_awareness/dashboard/ui/assets/offline-ml-contract.mjs";

function fixture() {
    const training = Array.from({length: 6}, (_, i) => `RUN-20261008-${915 + i}`);
    const checks = ["RUN-20261016-928", "RUN-20261016-929"];
    const hash = "a".repeat(64);
    return {
        availability: "verified", schema_version: "offline-ml-display-v1", package_version: "test-v1",
        package_sha256: hash, verified_member_count: 17,
        model: {version: "test-model", feature_version: "test-feature", feature_scope: "whole_observation",
            file_sha256: hash, canonical_sha256: hash, training_sha256: hash},
        feature_names: ["feature_one", "feature_two"],
        training_run_ids: training, check_run_ids: checks,
        classification_threshold: null, formal_performance: null, TTSD: null,
        cases: [...checks, ...training].map(run => ({run_id: run, feature_values: [0, 1], probability: 0.25,
            training_overlap: training.includes(run), input_file_sha256: hash,
            input_canonical_sha256: hash, result_file_sha256: hash})),
    };
}

test("reads only the local sanitized result export with caching disabled", async () => {
    const data = fixture();
    const calls = [];
    const result = await loadOfflineDisplay(async (...args) => {
        calls.push(args);
        return {ok: true, json: async () => data};
    });
    assert.equal(result, data);
    assert.deepEqual(calls, [["/dashboard-assets/offline-ml-data.local.json", {cache: "no-store"}]]);
    assert.equal(offlineCase(result, "RUN-20261016-928").training_overlap, false);
    assert.equal(offlineCase(result, "RUN-20261008-915").training_overlap, true);
    assert.throws(() => offlineCase(result, "RUN-20261019-006"));
    assert.throws(() => offlineCase(result, "RUN-20261019-007"));
});

for (const [name, edit] of [
    ["threshold added", d => { d.classification_threshold = 0.5; }],
    ["formal evaluation added", d => { d.formal_performance = {accuracy: 1}; }],
    ["TTSD added", d => { d.TTSD = 1; }],
    ["training/check overlap", d => { d.check_run_ids[0] = d.training_run_ids[0]; }],
    ["eight-run training", d => { d.training_run_ids.push(...d.check_run_ids); }],
    ["false overlap label", d => { d.cases[0].training_overlap = true; }],
    ["duplicate case", d => { d.cases[0] = d.cases[1]; }],
    ["probability NaN", d => { d.cases[0].probability = NaN; }],
    ["probability outside range", d => { d.cases[0].probability = 1.01; }],
    ["probability string", d => { d.cases[0].probability = "0.25"; }],
    ["feature missing", d => { d.cases[0].feature_values = [1]; }],
    ["feature nonbinary", d => { d.cases[0].feature_values = [0, 2]; }],
    ["private model path", d => { d.model.version = "C:/secret/model"; }],
    ["invalid SHA", d => { d.model.file_sha256 = "unknown"; }],
]) {
    test(`rejects ${name}`, () => {
        const data = fixture();
        edit(data);
        assert.throws(() => validateOfflineDisplay(data));
    });
}

test("missing and malformed exports fail without synthesizing results", async () => {
    await assert.rejects(loadOfflineDisplay(async () => ({ok: false})));
    await assert.rejects(loadOfflineDisplay(async () => ({ok: true, json: async () => ({})})));
    await assert.rejects(loadOfflineDisplay(async () => { throw new Error("offline"); }));
});
