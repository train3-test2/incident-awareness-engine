import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createDashboardStageTimingController } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-stage-timing-controller.mjs";
import { target, timingPayload } from "./stage-timing-fixture.mjs";

const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const response = (payload = timingPayload(), ok = true) => ({ ok, json: async () => payload });
function harness(fetchImpl = async () => response()) {
    const nodes = new Map();
    for (const key of ["state", "caption", "scope", "records", "refresh", "detail"]) {
        nodes.set(`insight-bottleneck-${key}`, {
            text: "", writes: 0, dataset: {}, children: [], disabled: true,
            get textContent() { return this.text; },
            set textContent(value) { this.text = value; this.writes += 1; },
            replaceChildren(...rows) { this.children = rows; },
            addEventListener(name, fn) { this[name] = fn; },
        });
    }
    const doc = { getElementById: (id) => nodes.get(id) ?? null, createElement: () => ({ textContent: "" }) };
    const timers = new Map(); let timer = 0; const calls = [];
    const controller = createDashboardStageTimingController(doc, {
        fetchImpl: (...args) => { calls.push(args); return fetchImpl(...args); },
        setTimeoutImpl: (fn) => { timers.set(++timer, fn); return timer; },
        clearTimeoutImpl: (id) => timers.delete(id),
    });
    return { ...controller, nodes, calls, timers, node: (key) => nodes.get(`insight-bottleneck-${key}`) };
}

test("One exact Execution request renders duration, scope, UTC invocation details and accessible explicit refresh", async () => {
    // Given
    const h = harness();
    // When
    await h.select({ target, reason: "" });
    // Then
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0][0], "/operations/stage-timings?execution_id=execution-test");
    assert.equal(h.node("state").textContent, "결과 저장 · 6 ms");
    assert.match(h.node("caption").textContent, /부분 비교 · Execution execution-test/);
    assert.match(h.node("scope").textContent, /Run RUN-TEST · Entity ENTITY-TEST/);
    assert.equal(h.node("detail").textContent, h.node("scope").textContent);
    assert.equal(h.node("records").children.length, 6);
    assert.match(h.node("records").children[0].textContent, /2026-10-18T01:02:03.000Z/);
    assert.equal(h.node("refresh").disabled, false);
    assert.equal(h.timers.size, 0);
});

test("Unchanged Runtime heartbeats cause neither duplicate fetch nor live-region text mutations", async () => {
    // Given
    const h = harness(); await h.select({ target, reason: "" });
    const writes = h.node("state").writes;
    // When
    for (let i = 0; i < 5; i++) await h.select({ target: { ...target }, reason: "" });
    // Then
    assert.equal(h.calls.length, 1);
    assert.equal(h.node("state").writes, writes);
});

test("In-flight explicit refresh coalesces and completed refresh reads again", async () => {
    // Given
    const held = deferred(); const h = harness(() => held.promise);
    // When
    const first = h.select({ target, reason: "" }); const second = h.refresh();
    held.resolve(response()); await Promise.all([first, second]);
    // Then
    assert.equal(h.calls.length, 1);
    await h.refresh(); assert.equal(h.calls.length, 2);
});

for (const field of ["runId", "entityId", "executionId"]) {
    test(`Changing ${field} aborts the prior request and rejects its late response`, async () => {
        // Given
        const held = deferred(); let index = 0;
        const next = { ...target, [field]: "next-value" };
        const h = harness(() => ++index === 1 ? held.promise : Promise.resolve(response(timingPayload({ scope: next }))));
        const first = h.select({ target, reason: "" }); await Promise.resolve(); await Promise.resolve();
        // When
        await h.select({ target: next, reason: "" }); held.resolve(response()); await first;
        // Then
        assert.equal(h.calls[0][1].signal.aborted, true);
        assert.match(h.node("scope").textContent, /next-value/);
        assert.equal(h.calls.length, 2);
    });
}

test("Phase changes re-read once, stable terminal reports do not keep polling", async () => {
    // Given
    const h = harness();
    const running = { ...target, status: "running", currentStage: "normalization" };
    // When
    await h.select({ target: running });
    await h.select({ target: { ...running, currentStage: "fusion" } });
    await h.select({ target }); await h.select({ target });
    // Then
    assert.equal(h.calls.length, 3);
});

test("No scope or Runtime query failure clears old measurements and invalidates pending results", async () => {
    // Given
    const held = deferred(); const h = harness(() => held.promise);
    const pending = h.select({ target }); await Promise.resolve();
    // When
    await h.select({ target: null, reason: "Runtime 조회 실패" }); held.resolve(response()); await pending;
    // Then
    assert.equal(h.node("state").textContent, "비교 대상 없음");
    assert.equal(h.node("refresh").disabled, true);
    assert.equal(h.node("records").children.length, 0);
    assert.match(h.node("scope").textContent, /조회 실패/);
});

for (const status of [404, 500, 503]) {
    test(`HTTP ${status} is a query error, not a zero measurement or inferred missing migration`, async () => {
        // Given
        let fail = false; const h = harness(async () => fail ? response(null, false) : response());
        await h.select({ target }); fail = true;
        // When
        await h.refresh();
        // Then
        assert.equal(h.node("state").textContent, "계측 조회 실패");
        assert.equal(h.node("records").children.length, 0);
        assert.match(h.node("scope").textContent, /저장 미준비 여부는 구분할 수 없습니다/);
        fail = false; await h.refresh(); assert.equal(h.node("state").textContent, "결과 저장 · 6 ms");
    });
}

for (const [detail, label, tone] of [
    ["Not Found", "계측 저장 미준비", "neutral"],
    ["Execution is not present in stored observation records", "측정 기록 없음", "neutral"],
]) {
    test(`HTTP 404 "${detail}" shows ${label} without measurements or an error tone`, async () => {
        // Given
        let fail = false;
        const h = harness(async () => fail
            ? { ok: false, status: 404, json: async () => ({ detail }) }
            : response());
        await h.select({ target, reason: "" }); fail = true;
        // When
        await h.refresh();
        // Then
        assert.equal(h.node("state").textContent, label);
        assert.equal(h.node("state").dataset.timingTone, tone);
        assert.equal(h.node("records").children.length, 0);
        assert.doesNotMatch(h.node("state").textContent + h.node("caption").textContent, /\d+(\.\d+)? ms/);
        assert.match(h.node("scope").textContent, /0ms|미실행/);
    });
}

test("An unreadable error body stays a generic query failure", async () => {
    // Given
    const h = harness(async () => ({ ok: false, status: 404, json: async () => { throw new SyntaxError("not json"); } }));
    // When
    await h.select({ target, reason: "" });
    // Then
    assert.equal(h.node("state").textContent, "계측 조회 실패");
    assert.equal(h.node("caption").textContent, "HTTP 404 · 원인 구분 불가");
});

test("An unresolved selection shows the short caption and keeps the full reason accessible", async () => {
    // Given
    const h = harness();
    // When
    await h.select({ target: null, caption: "Runtime 보고 없음", reason: "Run만 선택되어 Execution을 알 수 없습니다." });
    // Then
    assert.equal(h.node("state").textContent, "비교 대상 없음");
    assert.equal(h.node("caption").textContent, "Runtime 보고 없음");
    assert.equal(h.node("scope").textContent, "Run만 선택되어 Execution을 알 수 없습니다.");
    assert.equal(h.calls.length, 0);
});

test("Synchronous fetch failure and malformed/mixed response can recover without retaining old values", async () => {
    // Given
    let kind = "sync";
    const h = harness(() => {
        if (kind === "sync") throw Error("synthetic failure");
        const p = timingPayload(); if (kind === "mixed") p.snapshot.entity_id = "other";
        return Promise.resolve(response(p));
    });
    // When / Then
    await h.select({ target }); assert.equal(h.node("state").textContent, "계측 조회 실패");
    kind = "mixed"; await h.refresh(); assert.equal(h.node("state").textContent, "계측 조회 실패");
    kind = "ok"; await h.refresh(); assert.equal(h.node("records").children.length, 6);
});

test("Bounded timeout aborts fetch and ignores its eventual completion", async () => {
    // Given
    const held = deferred(); const h = harness(() => held.promise);
    const task = h.select({ target }); await Promise.resolve();
    // When
    [...h.timers.values()][0](); await task; held.resolve(response()); await Promise.resolve();
    // Then
    assert.equal(h.node("state").textContent, "계측 조회 실패");
    assert.equal(h.calls[0][1].signal.aborted, true);
    assert.equal(h.timers.size, 0);
});

test("Pagehide invalidates even an abort-ignoring response; pageshow re-reads only current selection", async () => {
    // Given
    const held = deferred(); let index = 0; const h = harness(() => ++index === 1 ? held.promise : Promise.resolve(response()));
    const task = h.select({ target }); await Promise.resolve();
    // When
    h.stop(); held.resolve(response()); await task;
    // Then
    assert.equal(h.node("state").textContent, "조회 중지");
    assert.equal(h.calls[0][1].signal.aborted, true);
    await h.start(); assert.equal(h.node("state").textContent, "결과 저장 · 6 ms");
});

test("Missing Insight DOM in the independent Preview is supported without requests", async () => {
    // Given
    let calls = 0;
    const c = createDashboardStageTimingController({ getElementById: () => null }, { fetchImpl: () => { calls += 1; } });
    // When
    c.select({ target }); c.refresh(); c.stop(); c.start();
    // Then
    assert.equal(calls, 0);
});

test("Dashboard wiring retains Runtime/Telemetry cadence, lifecycle, six Pipeline stages and native details", async () => {
    // Given
    const root = new URL("../../../", import.meta.url);
    const source = await readFile(new URL("src/incident_awareness/dashboard/ui/assets/dashboard.js", root), "utf8");
    const html = await readFile(new URL("src/incident_awareness/dashboard/ui/dashboard.html", root), "utf8");
    // When / Then
    assert.match(source, /RUNTIME_POLL_INTERVAL_MS = 5000/);
    assert.match(source, /stageTimingController\.select\(resolveStageTimingTarget/);
    assert.match(source, /stageTimingController\.stop\(\)/);
    assert.match(source, /stageTimingController\.start\(\)/);
    assert.match(source, /createDashboardTelemetryController\(document\)/);
    assert.match(html, /id="insight-bottleneck-state" role="status" aria-live="polite" aria-atomic="true"/);
    assert.ok(html.indexOf('id="insight-bottleneck-state"') < html.indexOf('<summary>인사이트 계측 안내'));
    assert.match(html, /id="insight-bottleneck-refresh"[^>]*type="button"/);
});
