const fail = () => { throw new Error("Offline 표시 데이터 검증 실패"); };
const token = value => typeof value === "string" && /^[A-Za-z0-9_.-]{1,120}$/.test(value);
const sha = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const runs = (value, count) => Array.isArray(value) && value.length === count
    && new Set(value).size === count && value.every(id => typeof id === "string" && /^RUN-\d{8}-\d{3}$/.test(id));

export function validateOfflineDisplay(data) {
    if (!data || data.availability !== "verified" || data.schema_version !== "offline-ml-display-v1"
        || !token(data.package_version) || !sha(data.package_sha256)
        || !Number.isInteger(data.verified_member_count) || data.verified_member_count < 9
        || data.classification_threshold !== null || data.formal_performance !== null || data.TTSD !== null
        || !runs(data.training_run_ids, 6) || !runs(data.check_run_ids, 2)
        || data.check_run_ids.some(id => data.training_run_ids.includes(id))) fail();
    const model = data.model;
    if (!model || ![model.version, model.feature_version, model.feature_scope].every(token)
        || ![model.file_sha256, model.canonical_sha256, model.training_sha256].every(sha)
        || !Array.isArray(data.feature_names) || data.feature_names.length !== 2
        || new Set(data.feature_names).size !== 2 || !data.feature_names.every(token)
        || !Array.isArray(data.cases) || data.cases.length !== 8) fail();
    const allIds = [...data.check_run_ids, ...data.training_run_ids];
    if (new Set(data.cases.map(item => item.run_id)).size !== 8) fail();
    for (const item of data.cases) {
        if (!allIds.includes(item.run_id)
            || item.training_overlap !== data.training_run_ids.includes(item.run_id)
            || !Array.isArray(item.feature_values) || item.feature_values.length !== data.feature_names.length
            || !item.feature_values.every(value => value === 0 || value === 1)
            || !Number.isFinite(item.probability) || item.probability < 0 || item.probability > 1
            || ![item.input_file_sha256, item.input_canonical_sha256, item.result_file_sha256].every(sha)) fail();
    }
    return data;
}

export async function loadOfflineDisplay(fetchImpl) {
    const response = await fetchImpl("/dashboard-assets/offline-ml-data.local.json", {cache: "no-store"});
    if (!response.ok) throw new Error("검증된 표시 데이터 없음");
    return validateOfflineDisplay(await response.json());
}

export function offlineCase(data, runId) {
    const item = data.cases.find(row => row.run_id === runId);
    if (!item) fail();
    return item;
}
