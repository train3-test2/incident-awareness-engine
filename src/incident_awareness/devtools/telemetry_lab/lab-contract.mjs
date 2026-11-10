const PHASES = new Map([
    ["idle", "시작 대기"], ["running", "입력·실제 처리 중"], ["paused", "일시정지 · 추가 입력 없음"],
    ["completed", "실험 상한 도달 · 초기화 후 다시 시작"], ["error", "계측 또는 저장 실패 · 초기화 필요"],
    ["closed", "실험 종료"],
]);

export function labPresentation(value) {
    if (!value || value.schema_version !== "telemetry_lab_v1" || value.simulation !== true
        || value.operational_measurement !== false || value.dashboard_read_only !== true
        || !PHASES.has(value.phase) || !["low", "normal", "high"].includes(value.speed)
        || !Number.isFinite(value.active_seconds) || value.active_seconds < 0
        || !/^iae_telemetry_lab_[a-f0-9]{32}$/.test(value.database)) throw TypeError("Invalid lab status");
    for (const key of ["accepted", "completed", "failed", "executions", "buckets", "latency_samples", "latency_sum_ns"]) {
        if (!Number.isSafeInteger(value.stored?.[key]) || value.stored[key] < 0) throw TypeError("Invalid stored counters");
    }
    return {
        label: `${PHASES.get(value.phase)} · 테스트 전용/운영 실측 아님`,
        start: value.phase === "idle", pause: value.phase === "running", resume: value.phase === "paused",
        reset: value.phase !== "closed", speed: value.speed, stored: value.stored,
        elapsed: String(Math.floor(value.active_seconds)), database: value.database,
    };
}
