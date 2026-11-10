// Pure Evidence tab helpers for GET /runs/{run_id}/evidences (dashboard_run_evidence_v1).
// Only the verified, published R1 archive is listed; Events and Fusion contributions are not.

export const EVIDENCE_PAGE_LIMIT = 100;

// Names of the stored extractor rules only; they state what was observed, never an attack purpose.
const EVIDENCE_TYPE_LABELS = new Map([
    ["remote_session_process_lineage_deviation", "원격 세션 프로세스 계보 이탈"],
    ["remote_process_network_follow_on", "원격 프로세스 네트워크 후속 연결"],
    ["encoded_powershell_command", "인코딩된 PowerShell 실행 옵션 사용"],
    ["script_interpreter_external_connection", "스크립트 실행기의 공인 IP 연결"],
]);
const SOURCE_LAYER_LABELS = new Map([
    ["raw_telemetry", "원시 Telemetry"],
    ["detector_output", "탐지기 출력"],
    ["mixed", "혼합"],
]);
const FEATURE_CHANNEL_LABELS = new Map([
    ["fusion_feature", "Fusion feature"],
    ["diagnostic_only", "진단 전용"],
]);
const ARCHIVE_STATUSES = new Set(["pending", "retryable", "published", "failed"]);
// Python's UTC datetime serialization: seconds with optional fraction, always "Z".
const UTC_TIMESTAMP = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d{1,6})?Z$/;
const SHA256 = /^[0-9a-f]{64}$/;

export const EVIDENCE_MESSAGES = Object.freeze({
    idle: "분석을 선택하면 저장된 증거 아카이브를 조회합니다.",
    loading: "선택한 분석의 증거 아카이브를 조회하는 중입니다.",
    // No status line: the evidence overview already states that no archive is published.
    noArchive: "",
    empty: "저장된 증거 0건 · 검증된 R1 아카이브에 증거가 없습니다.",
    pending: "아카이브 게시 전 · 게시가 완료되지 않은 아카이브의 증거는 표시하지 않습니다.",
    failed: "아카이브 게시 실패 · 충돌로 종료된 아카이브의 증거는 표시하지 않습니다.",
    invalid: "데이터 검증 실패 · 저장된 아카이브가 무결성 또는 계약 검증을 통과하지 못해 표시하지 않습니다.",
    notReady: "조회 기능 미준비 · 이 서버에서 증거 조회 API 또는 아카이브 저장소를 사용할 수 없습니다.",
    runMissing: "분석을 찾을 수 없어 증거를 조회하지 않았습니다.",
    error: "증거 조회 실패 · 결과 다시 조회로 재시도할 수 있습니다.",
});

const requireValue = (condition) => {
    if (!condition) throw new TypeError("Invalid or mismatched Evidence response");
};
const isText = (value) => typeof value === "string" && value.length > 0;
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

// Date.parse rolls impossible dates over (02-30 -> 03-02), so the components must round-trip.
function isUtcTimestamp(value) {
    const match = typeof value === "string" ? UTC_TIMESTAMP.exec(value) : null;
    if (match === null) return false;
    const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
    const date = new Date(value);
    return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1
        && date.getUTCDate() === day && date.getUTCHours() === hour
        && date.getUTCMinutes() === minute && date.getUTCSeconds() === second;
}

export function buildEvidenceApiPath(runId, limit = EVIDENCE_PAGE_LIMIT) {
    requireValue(isText(runId) && runId.length <= 512 && runId.trim() === runId
        && Number.isSafeInteger(limit) && limit >= 1 && limit <= 200);
    return `/runs/${encodeURIComponent(runId)}/evidences?limit=${limit}`;
}

export const getEvidenceTypeLabel = (type) => EVIDENCE_TYPE_LABELS.get(type) ?? type;
export const getSourceLayerLabel = (layer) => SOURCE_LAYER_LABELS.get(layer) ?? layer;
export const getFeatureChannelLabel = (channel) => FEATURE_CHANNEL_LABELS.get(channel) ?? channel;

function validateItem(item) {
    requireValue(item !== null && typeof item === "object" && !Array.isArray(item));
    requireValue(isText(item.evidence_id) && isText(item.evidence_type) && isText(item.entity_id)
        && isText(item.extractor_version) && isUtcTimestamp(item.timestamp)
        && SOURCE_LAYER_LABELS.has(item.derived_from_source_layer)
        && FEATURE_CHANNEL_LABELS.has(item.feature_channel_group)
        && Array.isArray(item.attack_technique_ids) && item.attack_technique_ids.every(isText)
        && Array.isArray(item.events) && item.events.length > 0 && isCount(item.withheld_field_count));
    for (const reference of item.events) {
        requireValue(reference !== null && typeof reference === "object"
            && isText(reference.event_id) && typeof reference.stored === "boolean");
    }
    requireValue(item.policy === null || (item.policy !== null && typeof item.policy === "object"
        && isText(item.policy.policy_id) && isText(item.policy.version) && isText(item.policy.config_hash)));
}

// Returns { state, message, items, total, entityIds, unstored } or throws on any mismatch.
export function resolveEvidenceResponse(payload, runId) {
    requireValue(payload !== null && typeof payload === "object"
        && payload.schema_version === "dashboard_run_evidence_v1" && payload.run_id === runId
        && payload.source === "r1_archive_publication" && payload.evidence_scope === "offline_whole_episode"
        && payload.fusion_input === false && payload.timestamp_meaning === "event_time"
        && payload.entity_scope === "run" && Array.isArray(payload.items) && Array.isArray(payload.entity_ids)
        && isCount(payload.unstored_event_reference_count) && isCount(payload.offset)
        && Number.isSafeInteger(payload.limit) && payload.limit >= 1 && payload.limit <= 200);
    if (payload.availability === "no_archive" || payload.availability === "not_published") {
        requireValue(payload.items.length === 0 && payload.total === null && payload.evidence_sha256 === null);
        requireValue(payload.extractor_version === null && payload.entity_ids.length === 0
            && payload.unstored_event_reference_count === 0);
        if (payload.availability === "no_archive") {
            requireValue(payload.archive_status === null);
            return { state: "no_archive", message: EVIDENCE_MESSAGES.noArchive, items: [], total: null, entityIds: [], unstored: 0 };
        }
        requireValue(ARCHIVE_STATUSES.has(payload.archive_status) && payload.archive_status !== "published");
        const failed = payload.archive_status === "failed";
        return { state: failed ? "archive_failed" : "archive_pending",
            message: `${failed ? EVIDENCE_MESSAGES.failed : EVIDENCE_MESSAGES.pending} (상태: ${payload.archive_status})`,
            items: [], total: null, entityIds: [], unstored: 0 };
    }
    requireValue(payload.availability === "published" && payload.archive_status === "published"
        && isCount(payload.total) && typeof payload.evidence_sha256 === "string"
        && SHA256.test(payload.evidence_sha256) && isText(payload.extractor_version)
        && payload.items.length === Math.min(payload.limit, Math.max(0, payload.total - payload.offset))
        && (payload.items.length === 0 || payload.offset + payload.items.length <= payload.total)
        && payload.entity_ids.every(isText) && new Set(payload.entity_ids).size === payload.entity_ids.length);
    const evidenceIds = new Set();
    for (const item of payload.items) {
        validateItem(item);
        requireValue(!evidenceIds.has(item.evidence_id) && payload.entity_ids.includes(item.entity_id)
            && item.extractor_version === payload.extractor_version);
        evidenceIds.add(item.evidence_id);
    }
    if (payload.total === 0) {
        requireValue(payload.items.length === 0 && payload.entity_ids.length === 0
            && payload.unstored_event_reference_count === 0);
        return { state: "empty", message: EVIDENCE_MESSAGES.empty, items: [], total: 0, entityIds: [], unstored: 0,
            extractorVersion: payload.extractor_version, evidenceSha256: payload.evidence_sha256 };
    }
    const shown = payload.items.length === 0 ? " · 현재 페이지 0건"
        : payload.items.length < payload.total ? ` · ${payload.offset + 1}–${payload.offset + payload.items.length}건 표시` : "";
    const unstored = payload.unstored_event_reference_count;
    return {
        state: "published",
        message: `증거 조회 완료 · 검증된 ${payload.total}건${shown} · Entity ${payload.entity_ids.length}개`
            + (unstored ? ` · 저장 Event 미조회 ${unstored}건(링크 없음)` : ""),
        items: payload.items,
        total: payload.total,
        entityIds: payload.entity_ids,
        unstored,
        extractorVersion: payload.extractor_version,
        evidenceSha256: payload.evidence_sha256,
    };
}

// One short overview value per archive state; the full message stays in #evidence-status.
const ARCHIVE_STATE_LABELS = {
    idle: "미조회", loading: "조회 중", no_archive: "게시 아카이브 없음 · 원본 보관과 별개", empty: "게시됨 · 증거 0건",
    archive_pending: "게시 전", archive_failed: "게시 실패", invalid: "검증 실패 · 표시하지 않음",
    not_ready: "조회 기능 미준비", run_missing: "분석 없음", error: "조회 실패",
};

export function describeArchiveState(state, total = null) {
    if (state === "published") return `게시됨 · 검증된 증거 ${total}건`;
    return ARCHIVE_STATE_LABELS[state] ?? "조회 실패";
}

// Archive provenance line for a verified, published archive (scope limits are in #evidence-scope).
export function describeVerifiedArchive(model) {
    return `R1 아카이브 · Extractor ${model.extractorVersion} · SHA-256 ${model.evidenceSha256.slice(0, 12)}… 검증`;
}

// Only exact Read API details name a cause; anything else is a generic query failure.
export function classifyEvidenceFailure(status, detail) {
    if ((status === 404 && detail === "Not Found")
        || (status === 503 && detail === "Evidence archive storage is not provisioned")) {
        return { state: "not_ready", message: EVIDENCE_MESSAGES.notReady };
    }
    if (status === 404 && detail === "Run not found") {
        return { state: "run_missing", message: EVIDENCE_MESSAGES.runMissing };
    }
    if (status === 500 && [
        "Stored Evidence archive is invalid",
        "Stored Evidence provenance is inconsistent",
        "Stored Evidence archive exceeds the read limit",
    ].includes(detail)) {
        return { state: "invalid", message: EVIDENCE_MESSAGES.invalid };
    }
    return { state: "error", message: EVIDENCE_MESSAGES.error };
}
