import { createDashboardTelemetryController } from "/dashboard-assets/dashboard-telemetry-controller.mjs";
import { createPreviewSource } from "./telemetry-preview-model.mjs";

const byId = (id) => document.getElementById(id);
let responses = 0;
let phase = "idle";
const source = createPreviewSource({
    onResponse({ payload, status, elapsedSeconds }) {
        responses += 1;
        byId("preview-response").textContent = `조회 ${responses}회 · 경과 ${elapsedSeconds}초 · HTTP ${status}`
            + (payload ? ` · ${payload.range_start} ~ ${payload.range_end} · 관측 ${payload.points.length}버킷` : " · API 조회 실패");
        byId("preview-response").dataset.responses = String(responses);
        byId("preview-response").dataset.elapsed = String(elapsedSeconds);
    },
});
const controller = createDashboardTelemetryController(document, { fetchImpl: source.fetchImpl });
function setPhase(next) {
    phase = next;
    byId("preview-start").disabled = phase !== "idle";
    byId("preview-pause").disabled = phase !== "running";
    byId("preview-resume").disabled = phase !== "paused";
    byId("preview-state").textContent = phase === "running" ? "시연 중 · 5초 Polling"
        : phase === "paused" ? "일시정지 · 시계와 조회 중단" : "시작 대기";
}
function start() {
    source.start();
    setPhase("running");
    void controller.start();
}
function pause() {
    controller.stop();
    source.pause();
    setPhase("paused");
}
function reset() {
    controller.stop();
    source.reset(byId("preview-scenario").value);
    responses = 0;
    for (const kind of ["throughput", "latency"]) {
        const notice = document.createElement("span");
        notice.textContent = "Preview 시작 대기";
        byId(`telemetry-${kind}-chart`).replaceChildren(notice);
        byId(`telemetry-${kind}-summary`).textContent = "미관측";
        byId(`telemetry-${kind}-note`).textContent = "대기";
        byId(`telemetry-${kind}-status`).textContent = "시작 대기";
        byId(`telemetry-${kind}-details`).textContent = "시작 대기";
    }
    byId("preview-response").textContent = "조회 0회 · 시작하면 합성 시간의 최근 300초를 조회합니다.";
    byId("preview-response").dataset.responses = "0";
    byId("preview-response").dataset.elapsed = "0";
    setPhase("idle");
}
byId("preview-start").addEventListener("click", start);
byId("preview-resume").addEventListener("click", start);
byId("preview-pause").addEventListener("click", pause);
byId("preview-reset").addEventListener("click", reset);
byId("preview-scenario").addEventListener("change", reset);
window.addEventListener("pagehide", () => { if (phase === "running") pause(); });
document.body.dataset.previewReady = "true";
