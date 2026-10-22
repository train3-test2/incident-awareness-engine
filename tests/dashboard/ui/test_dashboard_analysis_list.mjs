import assert from "node:assert/strict";
import test from "node:test";
import {
    createListSummaryController, buildListSummaryPath, runInputRange, runRowAnalysis, runRowWorkflow, runRowObservation,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-analysis-list.mjs";
import { resolveAdjacentRuns } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs";

const decision = (run = "R") => ({ run_id: run, entity_id: "HOST", decision_id: "D",
    fast_status: "not_evaluated", fusion_status: "detected", fusion_time: "2026-10-03T00:00:20Z",
    t_e: null, decision_path: null, winning_path: null, config_version: "parallel-v0.2",
    decision_reason: "Required parallel evaluation was not completed" });
const analysis = (ids = ["R"]) => ({ schema_version: "dashboard_analysis_summaries_v1",
    items: ids.map(run_id => ({ run_id, entity_id: "HOST", status: "available", decision: decision(run_id),
        fusion_result: { run_id, entity_id: "HOST", fusion_status: "detected", fusion_time: "2026-10-03T00:00:20.000Z", contributing_evidence_ids: ["E1", "E2"] } })) });
const alerts = (ids = ["R"]) => ({ schema_version: "human_workflow_alert_summaries_v1",
    items: ids.map(run_id => ({ run_id, alerts: [] })) });
const reply = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

function harness() {
    const requests = [], timers = new Map();
    let counter = 0;
    const controller = createListSummaryController({ onChange() {},
        fetchImpl: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
        setTimeoutImpl: callback => { const id = ++counter; timers.set(id, callback); return id; },
        clearTimeoutImpl: id => timers.delete(id),
    });
    return { controller, requests, timers };
}

test("Task 5 zero rows finish without any summary request", async () => {
    const h = harness();
    await h.controller.refresh([]);
    assert.equal(h.requests.length, 0);
    assert.equal(h.controller.state.analysis.queryState, "success");
    assert.equal(h.controller.state.workflow.items.size, 0);
});

for (const size of [1, 5, 20, 25]) {
    test(`Task 5 ${size} rows use two GETs, bounded to 20 identifiers without row details`, async () => {
        const h = harness(), ids = Array.from({ length: size }, (_, i) => `R${i}`);
        const pending = h.controller.refresh(ids);
        assert.equal(h.requests.length, 2);
        for (const request of h.requests) {
            assert.equal(request.options.method ?? "GET", "GET");
            assert.equal(new URL(request.url, "http://fixture").searchParams.getAll("run_id").length, Math.min(20, size));
            assert.doesNotMatch(request.url, /\/sync|\/actions|\/report|\/runs\//);
        }
        h.requests[0].resolve(reply(analysis(ids.slice(0, 20))));
        h.requests[1].resolve(reply(alerts(ids.slice(0, 20))));
        await pending;
        assert.equal(h.controller.state.analysis.items.size, Math.min(20, size));
        assert.equal(h.timers.size, 0);
    });
}

test("Task 5 identifiers are encoded once and duplicate requests are removed", async () => {
    assert.equal(new URL(buildListSummaryPath("/analysis-summaries", ["A/B ?한"]), "http://fixture").searchParams.get("run_id"), "A/B ?한");
    const h = harness(), pending = h.controller.refresh(["R", "R"]);
    h.requests[0].resolve(reply(analysis())); h.requests[1].resolve(reply(alerts()));
    await pending;
    assert.equal(new URL(h.requests[0].url, "http://fixture").searchParams.getAll("run_id").length, 1);
    assert.equal(h.controller.state.analysis.queryState, "success");
});

test("Task 5 a new scope discards old response bodies even if AbortSignal is ignored", async () => {
    const h = harness();
    const first = h.controller.refresh(["A"]);
    const second = h.controller.refresh(["B"]);
    assert.equal(h.requests[0].options.signal.aborted, true);
    h.requests[2].resolve(reply(analysis(["B"]))); h.requests[3].resolve(reply(alerts(["B"])));
    await second;
    h.requests[0].resolve(reply(analysis(["A"]))); h.requests[1].resolve(reply(alerts(["A"])));
    await first;
    assert.deepEqual([...h.controller.state.analysis.items.keys()], ["B"]);
});

test("Task 5 same-list refresh clears old success and reports failures separately from no results", async () => {
    const h = harness(); let pending = h.controller.refresh(["R"]);
    h.requests[0].resolve(reply(analysis())); h.requests[1].resolve(reply(alerts())); await pending;
    pending = h.controller.refresh(["R"]);
    assert.equal(h.controller.state.analysis.items.size, 0);
    assert.match(runRowAnalysis(h.controller.state.analysis, "R").headline, /조회 중/);
    h.requests[2].resolve(reply({}, 503)); h.requests[3].reject(new Error("offline")); await pending;
    assert.match(runRowAnalysis(h.controller.state.analysis, "R").headline, /조회 실패/);
    assert.equal(runRowWorkflow(h.controller.state.workflow, "R"), "조회 실패");
});

for (const [status, detail, analysisState, workflowState] of [
    [404, "Not Found", "unsupported", "unsupported"],
    [404, "Run not found", "error", "error"], [403, "Forbidden", "error", "forbidden"],
]) {
    test(`Task 5 HTTP ${status} / ${detail} preserves availability and permission semantics`, async () => {
        const h = harness(), pending = h.controller.refresh(["R"]);
        for (const request of h.requests) request.resolve(reply({ detail }, status));
        await pending;
        assert.equal(h.controller.state.analysis.queryState, analysisState);
        assert.equal(h.controller.state.workflow.queryState, workflowState);
    });
}

for (const kind of ["wrong-run", "wrong-entity", "duplicate", "invalid-status", "missing-item"]) {
    test(`Task 5 malformed summary ${kind} is rejected without presenting a detection`, async () => {
        const h = harness(), body = analysis(), pending = h.controller.refresh(["R"]);
        if (kind === "wrong-run") body.items[0].decision.run_id = "OTHER";
        if (kind === "wrong-entity") body.items[0].fusion_result.entity_id = "OTHER";
        if (kind === "duplicate") body.items.push(body.items[0]);
        if (kind === "invalid-status") body.items[0].decision.fast_status = "skipped";
        if (kind === "missing-item") body.items = [];
        h.requests[0].resolve(reply(body)); h.requests[1].resolve(reply(alerts())); await pending;
        assert.equal(h.controller.state.analysis.queryState, "error");
        assert.equal(h.controller.state.analysis.items.size, 0);
    });
}

test("Task 5 stop/resume suppresses old results and never issues a write", async () => {
    const h = harness(), first = h.controller.refresh(["R"]);
    h.controller.stop();
    for (const [index, request] of h.requests.entries()) request.resolve(reply(index ? alerts() : analysis()));
    await first;
    assert.notEqual(h.controller.state.analysis.queryState, "success");
    await h.controller.refresh(["R"]); assert.equal(h.requests.length, 2);
    h.controller.start(); const second = h.controller.refresh(["R"]);
    h.requests[2].resolve(reply(analysis())); h.requests[3].resolve(reply(alerts())); await second;
    assert.equal(h.controller.state.analysis.queryState, "success");
});

test("Task 5 timeout does not accept a late success from an uncooperative transport", async () => {
    const h = harness(), pending = h.controller.refresh(["R"]);
    for (const callback of h.timers.values()) callback();
    h.requests[0].resolve(reply(analysis())); h.requests[1].resolve(reply(alerts())); await pending;
    assert.equal(h.controller.state.analysis.queryState, "error");
    assert.equal(h.controller.state.workflow.queryState, "error");
});

test("Task 5 input range describes 11 minutes of input events, retaining missing and invalid ends", () => {
    const range = runInputRange({ start_time: "2026-10-03T00:00:00Z", end_time: "2026-10-03T00:11:00Z" });
    assert.deepEqual([range.start, range.end, range.span], ["2026.10.03 09:00:00", "09:11:00", "11분 0초"]);
    assert.match(range.title, /분석 처리 시간.*공격 지속 시간이 아닙니다/);
    assert.equal(runInputRange({ start_time: "2026-10-03T00:00:00Z" }).end, "종료 미기록");
    assert.equal(runInputRange({ start_time: "2026-10-03T00:00:00Z", end_time: "2026-10-02T00:00:00Z" }).span, null);
});

test("Task 5 list reuses incomplete Decision meaning without promoting Fusion detection", () => {
    const item = analysis().items[0], state = { queryState: "success", items: new Map([["R", item]]) };
    const row = runRowAnalysis(state, "R");
    assert.match(row.headline, /증거 누적 분석에서 의심 행위 탐지/);
    // The list keeps judgment completion only; the detail keeps the full summary.
    assert.equal(row.status, "미완료");
    assert.equal(row.evidence, "기여 증거 2건");
    item.decision.t_e = null;
    assert.doesNotMatch(row.status, /공격 확률|종합 판단 완료/);
    item.decision = null;
    // No stored judgment is not a completed one.
    assert.equal(runRowAnalysis(state, "R").status, "미완료");
    item.fusion_result = null;
    assert.equal(runRowAnalysis(state, "R").headline, "저장된 분석 결과 없음");
});

test("Task 5 conflicting stored Decision/Fusion snapshot is withheld", () => {
    const item = analysis().items[0]; item.fusion_result.fusion_time = "2026-10-03T00:00:30Z";
    const row = runRowAnalysis({ queryState: "success", items: new Map([["R", item]]) }, "R");
    assert.equal(row.known, false); assert.match(row.headline, /저장 시점 불일치/); assert.equal(row.evidence, null);
});

test("Task 5 an independently refreshed summary cannot describe a different row target", () => {
    const item = analysis().items[0];
    const row = runRowAnalysis({ queryState: "success", items: new Map([["R", item]]) }, "R", "OTHER");
    assert.equal(row.known, false);
    assert.equal(row.evidence, null);
    assert.match(row.status, /조회 범위 불일치/);
});

test("Task 5 staff summaries are scoped to the target Entity and do not create records", () => {
    const state = { queryState: "success", items: new Map([["R", { alerts: [{
        run_id: "R", entity_id: "OTHER", state: { version: 0, analyst_ack_time: null },
    }] }]]) };
    assert.equal(runRowWorkflow(state, "R", "HOST"), "처리 기록 없음");
    assert.equal(runRowWorkflow(state, "R", "OTHER"), "알림 대기");
    assert.equal(runRowWorkflow({ queryState: "error" }, "R"), "조회 실패");
});

test("Task 5 previous/next use the searched and typed list without choosing an excluded item", () => {
    const rows = ["A", "B", "C"].map((run_id, index) => ({ run_id, target_host: "H", scenario_id: "S", run_type: index === 1 ? "normal" : "attack" }));
    assert.deepEqual(resolveAdjacentRuns(rows, "", "attack", "A"), { previous: "C", next: null, selectedShown: true });
    assert.deepEqual(resolveAdjacentRuns(rows, "A", "all", "B"), { previous: null, next: null, selectedShown: false });
});


test("Review: stored observations are available without a row detail request and stay separate from detection", async () => {
    const h = harness(), body = analysis(), pending = h.controller.refresh(["R"]);
    body.items[0].observations = { source: "stored_events", entity_id: "HOST", event_count: 3,
        event_type_counts: { process_create: 1, network_connection: 2 } };
    h.requests[0].resolve(reply(body)); h.requests[1].resolve(reply(alerts()));
    await pending;
    assert.equal(h.requests.length, 2);
    assert.equal(runRowObservation(h.controller.state.analysis, "R", "HOST"), "프로세스 생성 1건 · 네트워크 연결 2건");
    assert.equal(runRowAnalysis(h.controller.state.analysis, "R", "HOST").status, "미완료");
    assert.equal(runRowObservation(h.controller.state.analysis, "R", "OTHER"), null);
    assert.equal(runRowObservation(h.controller.state.analysis, "OLD", "HOST"), null);
    assert.equal(runRowObservation({ ...h.controller.state.analysis, queryState: "error" }, "R", "HOST"), null);
});

test("Review: zero stored Events and unknown stored Event types do not imply no detection or invent an attack", async () => {
    const h = harness(), body = analysis(), pending = h.controller.refresh(["R"]);
    body.items[0].observations = { source: "stored_events", entity_id: "HOST", event_count: 0, event_type_counts: {} };
    h.requests[0].resolve(reply(body)); h.requests[1].resolve(reply(alerts())); await pending;
    assert.equal(runRowObservation(h.controller.state.analysis, "R", "HOST"), "이 대상에 저장된 관측 Event 없음");
    assert.match(runRowAnalysis(h.controller.state.analysis, "R", "HOST").headline, /의심 행위 탐지/);
    body.items[0].observations = { source: "stored_events", entity_id: "HOST", event_count: 1, event_type_counts: { unfamiliar_type: 1 } };
    const next = h.controller.refresh(["R"]);
    h.requests[2].resolve(reply(body)); h.requests[3].resolve(reply(alerts())); await next;
    assert.equal(runRowObservation(h.controller.state.analysis, "R", "HOST"), "unfamiliar_type 1건");
});

for (const invalid of [
    { source: "inferred" }, { entity_id: "OTHER" }, { event_count: -1 },
    { event_count: 4 }, { event_type_counts: { process_create: 1.5 } }, { event_type_counts: [3] },
]) {
    test(`Review: malformed stored observation is an error, never a successful empty summary: ${JSON.stringify(invalid)}`, async () => {
        const h = harness(), body = analysis(), pending = h.controller.refresh(["R"]);
        body.items[0].observations = { source: "stored_events", entity_id: "HOST", event_count: 3,
            event_type_counts: { process_create: 3 }, ...invalid };
        h.requests[0].resolve(reply(body)); h.requests[1].resolve(reply(alerts())); await pending;
        assert.equal(h.controller.state.analysis.queryState, "error");
        assert.equal(runRowObservation(h.controller.state.analysis, "R", "HOST"), null);
        assert.equal(h.controller.state.workflow.queryState, "success");
    });
}
