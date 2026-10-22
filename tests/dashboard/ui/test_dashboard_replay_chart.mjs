import assert from "node:assert/strict";
import test from "node:test";

import { buildScoreTrajectoryModel } from "../../../src/incident_awareness/dashboard/ui/assets/fusion-engine-contract.mjs";
import {
    buildDashboardReplayPresentation,
    createDashboardReplayChart,
    createDashboardReplayRecords,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-replay-chart.mjs";

const DIMENSIONS = {
    width: 960,
    height: 140,
    padding: { top: 50, right: 72, bottom: 23, left: 50 },
};

for (const count of [67, 101, 137, 301]) {
    test(`Replay retains all ${count} valid points and details without altering cadence`, () => {
        // Given
        const previous = globalThis.document;
        globalThis.document = {
            createElement: tag => new FakeElement(tag),
            createElementNS: (_, tag) => new FakeElement(tag),
            createTextNode: value => ({ textContent: value, children: [] }),
        };
        const trace = makeTrace(count);
        const original = JSON.stringify(trace);
        // When
        try {
            const model = buildScoreTrajectoryModel(trace, null, DIMENSIONS);
            const chart = createDashboardReplayChart(model, makeEpisode(trace.points));
            // Then
            assert.equal(model.points.length, count);
            assert.equal(chart.querySelectorAll(".fusion-score-chart__point").length, count);
            assert.equal(chart.querySelectorAll("tr").length, count + 1);
            assert.equal(model.points.at(-1).timestamp, trace.points.at(-1).timestamp);
            assert.equal(JSON.stringify(trace), original);
        } finally {
            if (previous === undefined) delete globalThis.document;
            else globalThis.document = previous;
        }
    });
}

function makeTrace(count = 67) {
    return {
        points: Array.from({ length: count }, (_, index) => ({
            timestamp: new Date(Date.UTC(2026, 9, 5, 0, 0, index * 10)).toISOString(),
            score: index < 20 ? 0.3 : index < 45 ? 0.9 : 0.1,
            policy_state: index >= 20 && index < 45 ? "on" : "off",
            persistence_count: index === 20 ? 2 : null,
        })),
    };
}

function makeEpisode(points, endIndex = 45) {
    return {
        fusion_episodes: [{
            start_time: points[20].timestamp,
            end_time: endIndex === null ? null : points[endIndex].timestamp,
            end_reason: endIndex === null ? null : "released",
        }],
    };
}

class FakeElement {
    constructor(tagName) {
        this.tagName = tagName;
        this.children = [];
        this.parentNode = null;
        this.attributes = new Map();
        this.classes = new Set();
        this.classList = {
            add: (...names) => names.forEach((name) => this.classes.add(name)),
            contains: (name) => this.classes.has(name),
        };
        this.ownText = "";
        this.listeners = new Map();
    }

    get textContent() {
        return this.ownText + this.children.map((child) => child.textContent).join("");
    }

    set textContent(value) {
        this.children = [];
        this.ownText = String(value);
    }

    setAttribute(name, value) {
        this.attributes.set(name, String(value));
        if (name === "class") {
            for (const className of String(value).split(" ")) {
                this.classes.add(className);
            }
        }
    }

    append(...children) {
        for (const child of children) {
            child.parentNode = this;
            this.children.push(child);
        }
    }

    addEventListener(type, listener) {
        this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    dispatch(type, event = {}) {
        for (const listener of this.listeners.get(type) ?? []) listener({ target: this, ...event });
    }

    focus() {
        this.dispatch("focus");
    }

    before(sibling) {
        const index = this.parentNode.children.indexOf(this);
        sibling.parentNode = this.parentNode;
        this.parentNode.children.splice(index, 0, sibling);
    }

    querySelectorAll(selector) {
        const matches = [];
        const isMatch = (element) => selector.startsWith(".")
            ? element.classes?.has(selector.slice(1))
            : element.tagName === selector;
        const visit = (element) => {
            for (const child of element.children) {
                if (isMatch(child)) {
                    matches.push(child);
                }
                visit(child);
            }
        };
        visit(this);
        return matches;
    }

    querySelector(selector) {
        return this.querySelectorAll(selector)[0] ?? null;
    }
}

test("Dashboard Replay keeps all 67 saved scores and highlights stored episode boundaries", () => {
    // Given
    const trace = makeTrace();
    const model = buildScoreTrajectoryModel(trace, {
        stopping: { threshold_on: 0.8, threshold_off: 0.4 },
    }, DIMENSIONS);
    const result = makeEpisode(trace.points);

    // When
    const presentation = buildDashboardReplayPresentation(model, result);

    // Then
    assert.equal(model.points.length, 67);
    assert.deepEqual(model.points.map((point) => point.score), trace.points.map((point) => point.score));
    assert.equal(presentation.bands.length, 1);
    assert.equal(presentation.bands[0].startX, model.points[20].x);
    assert.equal(presentation.bands[0].endX, model.points[45].x);
    assert.deepEqual(presentation.transitions.map((item) => item.label), [
        "탐지 구간 시작",
        "탐지 구간 해제",
    ]);
    assert.deepEqual([...presentation.highlightedIndices], [0, 66, 20, 45]);
    assert.equal(presentation.tickLabels.length, model.xTicks.length);
    assert.ok(presentation.tickLabels.every((label) => !label.includes("2026")));
});

test("Dashboard Replay does not shade an episode without a confirmed end", () => {
    // Given
    const trace = makeTrace();
    const model = buildScoreTrajectoryModel(trace, null, DIMENSIONS);

    // When
    const presentation = buildDashboardReplayPresentation(
        model,
        makeEpisode(trace.points, null),
    );

    // Then
    assert.deepEqual(presentation.bands, []);
    assert.deepEqual(presentation.transitions.map((item) => item.label), ["탐지 구간 시작"]);
});

test("Dashboard Replay marks only a stored in-range technical decision time", () => {
    // Given
    const trace = makeTrace();
    const model = buildScoreTrajectoryModel(trace, null, DIMENSIONS);
    const episodes = makeEpisode(trace.points);

    // When
    const distinct = buildDashboardReplayPresentation(
        model,
        episodes,
        trace.points[10].timestamp,
    );
    const sameAsEpisodeStart = buildDashboardReplayPresentation(
        model,
        episodes,
        trace.points[20].timestamp,
    );
    const outsideTrace = buildDashboardReplayPresentation(
        model,
        episodes,
        "2026-10-06T00:00:00.000Z",
    );

    // Then
    assert.deepEqual(distinct.transitions.map((item) => item.label), [
        "종합 판단 시각 (t_e)",
        "탐지 구간 시작",
        "탐지 구간 해제",
    ]);
    assert.ok(distinct.highlightedIndices.has(10));
    assert.deepEqual(sameAsEpisodeStart.transitions.map((item) => item.label), [
        "탐지 구간 시작",
        "종합 판단 시각 (t_e)",
        "탐지 구간 해제",
    ]);
    assert.equal(outsideTrace.transitions.length, 3);
    assert.equal(outsideTrace.transitions.find(item => item.kind === "decision").x, null);
});

test("Dashboard Replay keeps close timestamp ticks distinct without changing the scores", () => {
    // Given
    const trace = {
        points: [100, 200, 300].map((millisecond, index) => ({
            timestamp: `2026-10-05T00:00:00.${millisecond}Z`,
            score: index / 2,
            policy_state: "off",
            persistence_count: null,
        })),
    };
    const model = buildScoreTrajectoryModel(trace, null, DIMENSIONS);

    // When
    const presentation = buildDashboardReplayPresentation(model, null);

    // Then
    assert.deepEqual(model.points.map((point) => point.score), [0, 0.5, 1]);
    assert.equal(new Set(presentation.tickLabels).size, 3);
    assert.ok(presentation.tickLabels[0].endsWith(".100"));
    assert.ok(presentation.tickLabels[1].endsWith(".200"));
    assert.ok(presentation.tickLabels[2].endsWith(".300"));
    assert.deepEqual(presentation.bands, []);
});

test("Dashboard Replay renderer retains the full point table but mutes ordinary markers", () => {
    // Given
    const previousDocument = globalThis.document;
    globalThis.document = {
        createElement: (tagName) => new FakeElement(tagName),
        createElementNS: (_namespace, tagName) => new FakeElement(tagName),
        createTextNode: (value) => ({ textContent: value, children: [] }),
    };
    const trace = makeTrace();
    const model = buildScoreTrajectoryModel(trace, {
        stopping: { threshold_on: 0.8, threshold_off: 0.4 },
    }, DIMENSIONS);

    try {
        // When
        const chart = createDashboardReplayChart(
            model,
            makeEpisode(trace.points),
            trace.points[10].timestamp,
        );

        // Then
        assert.equal(chart.querySelectorAll(".fusion-score-chart__point").length, 67);
        assert.equal(chart.querySelectorAll(".dashboard-replay-chart__point--key").length, 5);
        assert.equal(chart.querySelectorAll(".dashboard-replay-chart__episode").length, 1);
        assert.equal(chart.querySelectorAll(".dashboard-replay-chart__transition").length, 3);
        assert.equal(new Set(chart.querySelectorAll(".dashboard-replay-chart__callout").map(
            (label) => label.attributes.get("y"),
        )).size, 3);
        assert.ok(chart.querySelectorAll(".dashboard-replay-chart__callout").every(
            (label) => Number(label.attributes.get("y")) < model.plot.top,
        ));
        assert.ok(chart.querySelectorAll(".dashboard-replay-chart__transition").every(
            (line) => Number(line.attributes.get("y1")) === model.plot.top
                && Number(line.attributes.get("y2")) === model.plot.bottom,
        ));
        assert.equal(chart.querySelectorAll("tr").length, 68);
        assert.match(chart.querySelector("desc").textContent, /저장된 점수/);
        assert.match(chart.querySelector("desc").textContent, /탐지 구간 시작/);
        assert.match(chart.querySelector("desc").textContent, /탐지 구간 해제/);
        assert.match(chart.querySelector("desc").textContent, /종합 판단 시각 \(t_e\)/);
    } finally {
        if (previousDocument === undefined) {
            delete globalThis.document;
        } else {
            globalThis.document = previousDocument;
        }
    }
});

function task3Fixture() {
    const trace = {
        run_id: "RUN-20261021-901",
        points: Array.from({ length: 67 }, (_, index) => ({
            timestamp: new Date(Date.UTC(2026, 9, 3, 0, 0, index * 10)).toISOString(),
            score: index === 0 ? 0.5 : index < 32 ? 1 : 0,
            policy_state: index >= 2 && index < 32 ? "on" : "off",
            persistence_count: index === 1 ? 1 : index === 2 ? 2 : null,
        })),
    };
    const result = { fusion_time: trace.points[2].timestamp, fusion_episodes: [{
        episode_id: "FEP-001", start_time: trace.points[2].timestamp,
        end_time: trace.points[32].timestamp, end_reason: "released",
    }] };
    const config = { stopping: { threshold_on: 0.8, threshold_off: 0.4, persistence_k: 2 } };
    return { trace, result, config, model: buildScoreTrajectoryModel(trace, config, DIMENSIONS) };
}

function withReplayDocument(callback) {
    const previous = globalThis.document;
    globalThis.document = {
        createElement: tag => new FakeElement(tag),
        createElementNS: (_, tag) => new FakeElement(tag),
    };
    try { return callback(); }
    finally {
        if (previous === undefined) delete globalThis.document;
        else globalThis.document = previous;
    }
}

test("Task 3 representative case preserves 67 records and exact 09:00:20 / 09:05:20 transitions", () => {
    // Given
    const { trace, model, result } = task3Fixture();
    const before = JSON.stringify([trace, result, model]);
    // When
    const presentation = buildDashboardReplayPresentation(model, result, null);
    // Then
    assert.equal(model.points.length, 67);
    assert.equal(model.points[1].policy_state, "off");
    assert.equal(model.points[1].persistence_count, 1);
    assert.equal(model.points[2].persistence_count, 2);
    assert.deepEqual(presentation.transitions.map(item => item.timestamp), [
        "2026-10-03T00:00:20.000Z", "2026-10-03T00:05:20.000Z",
    ]);
    assert.deepEqual(presentation.tickLabels, ["09:00:00", "09:05:30", "09:11:00"]);
    assert.equal(presentation.transitions[1].x, model.points[32].x);
    assert.notEqual(presentation.transitions[1].x, model.xTicks[1].x);
    assert.equal(presentation.transitions.some(item => item.kind === "decision"), false);
    assert.equal(JSON.stringify([trace, result, model]), before);
    withReplayDocument(() => {
        const chart = createDashboardReplayChart(model, result, null);
        assert.equal(chart.querySelectorAll(".fusion-score-chart__point").length, 67);
        assert.equal(chart.querySelectorAll("tr").length, 68);
        const records = chart.querySelector(".dashboard-replay-chart__records").textContent;
        assert.match(records, /09:00:20\.000 KST — 탐지 구간 시작/);
        assert.match(records, /09:05:20\.000 KST — 탐지 구간 해제/);
        assert.match(records, /종합 판단 시각: 미확정/);
        assert.doesNotMatch(records, /09:05:30/);
        assert.equal(chart.querySelector(".fusion-score-chart__clock").textContent, "2026-10-03 · KST");
    });
});

test("Task 3 first threshold hit and incomplete persistence do not create a transition", () => {
    // Given
    const { trace, config } = task3Fixture();
    const partial = { points: trace.points.slice(0, 2) };
    // When
    const model = buildScoreTrajectoryModel(partial, config, DIMENSIONS);
    const presentation = buildDashboardReplayPresentation(model, { fusion_episodes: [] });
    // Then
    assert.equal(model.points[1].score, 1);
    assert.equal(model.points[1].persistence_count, 1);
    assert.deepEqual(presentation.transitions, []);
    withReplayDocument(() => {
        const chart = createDashboardReplayChart(model, { fusion_episodes: [] });
        assert.match(chart.textContent, /진입 기준 0\.80 이상 · 2회 연속/);
        assert.match(chart.textContent, /해제 기준 0\.40 미만/);
        assert.doesNotMatch(chart.querySelector(".dashboard-replay-chart__records").textContent, /탐지 구간 해제/);
    });
});

test("Task 3 an exact off threshold stays active and only the saved later release is shown", () => {
    // Given: saved policy output keeps 0.40 active; 0.39 is the release point.
    const { trace, result, config } = task3Fixture();
    trace.points[31].score = 0.4;
    trace.points[32].score = 0.39;
    // When
    const model = buildScoreTrajectoryModel(trace, config, DIMENSIONS);
    const presentation = buildDashboardReplayPresentation(model, result);
    // Then
    assert.equal(model.points[31].policy_state, "on");
    assert.equal(model.points[32].policy_state, "off");
    assert.equal(presentation.transitions.filter(item => item.kind === "end").length, 1);
    assert.equal(presentation.transitions[1].timestamp, trace.points[32].timestamp);
    assert.notEqual(presentation.transitions[1].timestamp, trace.points[31].timestamp);
});

for (const [reason, label] of [["run_end", "관측 경계"], ["replay_end", "재생 경계"]]) {
    test(`Task 3 ${reason} is a boundary end with the original reason, never a release`, () => {
        // Given
        const { model, result } = task3Fixture();
        result.fusion_episodes[0].end_reason = reason;
        // When
        const presentation = buildDashboardReplayPresentation(model, result);
        // Then
        assert.equal(presentation.transitions[1].kind, "boundary");
        assert.match(presentation.transitions[1].label, new RegExp(label));
        assert.equal(presentation.transitions[1].reason, reason);
        assert.doesNotMatch(presentation.transitions[1].label, /해제/);
        withReplayDocument(() => {
            const chart = createDashboardReplayChart(model, result);
            assert.equal(chart.querySelectorAll(".dashboard-replay-chart__transition--boundary").length, 1);
            assert.match(chart.querySelector(".dashboard-replay-chart__records").textContent, new RegExp(reason));
        });
    });
}

test("Task 3 multiple Episodes retain all identities, source times and reasons", () => {
    // Given
    const { model, result } = task3Fixture();
    result.fusion_episodes.push({ episode_id: "FEP-002", start_time: model.points[40].timestamp,
        end_time: model.points[66].timestamp, end_reason: "replay_end" });
    const before = JSON.stringify(result);
    // When
    const presentation = buildDashboardReplayPresentation(model, result);
    // Then
    assert.equal(presentation.bands.length, 2);
    assert.deepEqual(presentation.transitions.map(item => item.kind), ["start", "end", "start", "boundary"]);
    assert.deepEqual(presentation.transitions.map(item => item.episodeLabel), ["FEP-001", "FEP-001", "FEP-002", "FEP-002"]);
    assert.equal(JSON.stringify(result), before);
});

test("Task 3 policy ON/OFF changes and fusion_time alone do not invent stored Episodes", () => {
    // Given
    const { model, result } = task3Fixture();
    // When / Then
    for (const empty of [null, {}, { fusion_time: result.fusion_time }, { fusion_episodes: [] }]) {
        const presentation = buildDashboardReplayPresentation(model, empty);
        assert.deepEqual(presentation.transitions, []);
        assert.deepEqual(presentation.bands, []);
    }
});

test("Task 3 records survive missing trajectory without inventing chart geometry", () => {
    // Given
    const { result } = task3Fixture();
    // When
    const presentation = buildDashboardReplayPresentation({ points: [], xTicks: [] }, result);
    // Then
    assert.equal(presentation.transitions.length, 2);
    assert.ok(presentation.transitions.every(item => item.x === null));
    assert.deepEqual(presentation.bands, []);
    withReplayDocument(() => {
        const records = createDashboardReplayRecords(result);
        assert.match(records.textContent, /09:00:20\.000 KST/);
        assert.match(records.textContent, /09:05:20\.000 KST/);
        assert.match(records.textContent, /fusion_episodes\.end_time/);
        assert.equal(records.querySelectorAll("svg").length, 0);
    });
});

test("Task 3 an Episode spanning the chart is clipped visually while exact stored times remain", () => {
    // Given
    const { model } = task3Fixture();
    const result = { fusion_episodes: [{ start_time: "2026-10-02T23:59:00.000Z",
        end_time: "2026-10-03T00:12:00.000Z", end_reason: "released" }] };
    // When
    const presentation = buildDashboardReplayPresentation(model, result);
    // Then
    assert.deepEqual(presentation.bands, [{ startX: model.plot.left, endX: model.plot.right }]);
    assert.ok(presentation.transitions.every(item => item.x === null));
    assert.equal(presentation.transitions[0].timestamp, result.fusion_episodes[0].start_time);
    assert.equal(presentation.transitions[1].timestamp, result.fusion_episodes[0].end_time);
});

test("Task 3 unknown end reason is retained without calling it a threshold release", () => {
    // Given
    const { model, result } = task3Fixture();
    result.fusion_episodes[0].end_reason = "future_reason";
    // When
    const presentation = buildDashboardReplayPresentation(model, result);
    // Then
    assert.equal(presentation.transitions[1].reason, "future_reason");
    assert.match(presentation.transitions[1].label, /사유 미확인/);
    assert.doesNotMatch(presentation.transitions[1].label, /해제/);
});

test("Task 3 invalid or zoneless Episode timestamps never become local-time events", () => {
    // Given
    const { model } = task3Fixture();
    const result = { fusion_episodes: [
        { start_time: null, end_time: null },
        { start_time: "2026-10-03T00:00:20", end_time: null },
        { start_time: "2026-10-03T00:00:20Z", end_time: "invalid", end_reason: "released" },
    ] };
    // When
    const presentation = buildDashboardReplayPresentation(model, result);
    // Then
    assert.equal(presentation.transitions.length, 1);
    assert.equal(presentation.transitions[0].kind, "start");
    assert.equal(presentation.unavailable, 3);
    withReplayDocument(() => assert.match(createDashboardReplayRecords(result).textContent, /표시할 수 없는 저장 구간 항목 3건/));
});

test("Task 3 coincident Fusion and t_e are separate facts and null t_e is stated, never filled in", () => {
    // Given
    const { model, result } = task3Fixture();
    // When
    const coincident = buildDashboardReplayPresentation(model, result, result.fusion_time);
    const incomplete = buildDashboardReplayPresentation(model, result, null);
    const withoutDecision = buildDashboardReplayPresentation(model, result);
    const invalid = buildDashboardReplayPresentation(model, result, "2026-10-03T00:00:30");
    // Then
    assert.equal(coincident.transitions.filter(item => item.timestamp === result.fusion_time).length, 2);
    assert.deepEqual(coincident.transitions.filter(item => item.timestamp === result.fusion_time).map(item => item.source),
        ["fusion_episodes.start_time", "Decision.t_e"]);
    assert.equal(coincident.decisionStatus, "recorded");
    assert.equal(incomplete.transitions.some(item => item.kind === "decision"), false);
    assert.equal(incomplete.decisionStatus, "pending");
    assert.equal(withoutDecision.decisionStatus, null);
    assert.deepEqual([invalid.decisionStatus, invalid.decisionOriginal], ["invalid", "2026-10-03T00:00:30"]);
    assert.equal(invalid.transitions.some(item => item.kind === "decision"), false);
    withReplayDocument(() => {
        const pending = createDashboardReplayRecords(result, null).textContent;
        assert.match(pending, /종합 판단 시각: 미확정/);
        assert.doesNotMatch(pending, /KST — 종합 판단 시각/);
        assert.doesNotMatch(createDashboardReplayRecords(result).textContent, /종합 판단 시각/);
        assert.match(createDashboardReplayRecords(result, "2026-10-03T00:00:30").textContent,
            /종합 판단 시각: 확인 불가 · 원본 2026-10-03T00:00:30/);
        assert.match(createDashboardReplayRecords(result, result.fusion_time).textContent,
            /09:00:20\.000 KST — 종합 판단 시각 \(t_e\)/);
    });
});

test("Task 3 chart date context follows the stored KST dates, including a KST midnight crossing", async () => {
    // Given
    const { scoreClockText } = await import("../../../src/incident_awareness/dashboard/ui/assets/fusion-score-chart.mjs");
    const crossing = { points: ["2026-10-03T14:59:50Z", "2026-10-03T15:00:00Z"].map((timestamp) => ({
        timestamp, score: 0, policy_state: "off", persistence_count: null })) };
    // When / Then
    assert.equal(scoreClockText(task3Fixture().model), "2026-10-03 · KST");
    assert.equal(scoreClockText(buildScoreTrajectoryModel(crossing, null, DIMENSIONS)), "2026-10-03 – 2026-10-04 · KST");
    assert.equal(scoreClockText(buildScoreTrajectoryModel({ points: [] }, null, DIMENSIONS)), "시각 기준 KST");
});

test("Task 3 hover and keyboard focus expose identical exact time, score and state", () => {
    // Given
    const { model, result } = task3Fixture();
    withReplayDocument(() => {
        const chart = createDashboardReplayChart(model, result);
        const markers = chart.querySelectorAll(".fusion-score-chart__point");
        const detail = chart.querySelector(".fusion-score-chart__point-detail");
        // When
        markers[1].dispatch("mouseenter");
        const hover = detail.textContent;
        markers[2].dispatch("focus");
        const focus = detail.textContent;
        // Then
        assert.equal(markers.length, 67);
        assert.deepEqual(markers.map(marker => marker.attributes.get("tabindex")).filter(value => value === "0"), ["0"]);
        assert.equal(markers[2].attributes.get("tabindex"), "0");
        assert.match(hover, /09:00:10\.000 KST.*증거 누적 점수 1.*탐지 구간 비활성/);
        assert.match(focus, /09:00:20\.000 KST.*탐지 구간 활성/);
        markers[1].dispatch("focus");
        assert.equal(detail.textContent, hover);
        assert.equal(markers[1].attributes.get("aria-label"), hover);
        assert.match(markers[1].querySelector("title").textContent, /UTC 2026-10-03T00:00:10\.000Z.*원본/);
        assert.doesNotMatch(hover, /T00:00|원본/);
        assert.equal(detail.attributes.has("aria-live"), false);
        assert.match(chart.textContent, /공격 확률이나 종합 판단 결과가 아닙니다/);
        assert.doesNotMatch(chart.textContent, /확률 100|100%/);
    });
});

test("Task 3 keyboard walks every stored score record from a single tab stop", () => {
    // Given
    const { model, result } = task3Fixture();
    withReplayDocument(() => {
        const chart = createDashboardReplayChart(model, result);
        const markers = chart.querySelectorAll(".fusion-score-chart__point");
        const detail = chart.querySelector(".fusion-score-chart__point-detail");
        const press = (marker, key) => {
            let prevented = false;
            marker.dispatch("keydown", { key, preventDefault: () => { prevented = true; } });
            return prevented;
        };
        // When / Then: initial single tab stop is the first stored record.
        assert.equal(markers[0].attributes.get("tabindex"), "0");
        assert.ok(markers.slice(1).every(marker => marker.attributes.get("tabindex") === "-1"));
        markers[0].focus();
        assert.equal(press(markers[0], "ArrowRight"), true);
        assert.equal(markers[1].attributes.get("tabindex"), "0");
        assert.equal(markers[0].attributes.get("tabindex"), "-1");
        assert.match(detail.textContent, /09:00:10\.000 KST/);
        assert.equal(press(markers[1], "End"), true);
        assert.match(detail.textContent, /2026\.10\.03 09:11:00\.000 KST.*탐지 구간 비활성/);
        assert.equal(press(markers[66], "ArrowRight"), false);
        assert.equal(press(markers[66], "Home"), true);
        assert.match(detail.textContent, /09:00:00\.000 KST/);
        assert.equal(press(markers[0], "ArrowLeft"), false);
        assert.equal(press(markers[0], "Enter"), false);
        assert.equal(markers.filter(marker => marker.attributes.get("tabindex") === "0").length, 1);
    });
});

test("Task 3 callouts carry the exact stored clock and the legend leaves thresholds on their lines", () => {
    // Given
    const { model, result } = task3Fixture();
    result.fusion_episodes.push({ episode_id: "FEP-002", start_time: model.points[40].timestamp,
        end_time: model.points[66].timestamp, end_reason: "replay_end" });
    withReplayDocument(() => {
        // When
        const chart = createDashboardReplayChart(model, result);
        // Then
        const callouts = chart.querySelectorAll(".dashboard-replay-chart__callout");
        assert.deepEqual(callouts.map(label => label.ownText), [
            "09:00:20 탐지 구간 시작",
            "09:05:20 탐지 구간 해제",
            "09:06:40 탐지 구간 시작",
            "09:11:00 탐지 구간 종료 · 재생 경계",
        ]);
        assert.ok(callouts.every(label => !label.ownText.startsWith("09:05:30")));
        // Labels sit to the right of their own line unless the widest label would leave the SVG.
        assert.deepEqual(callouts.map(label => label.attributes.get("text-anchor")), ["start", "start", "start", "end"]);
        assert.ok(callouts.filter(label => label.attributes.get("text-anchor") === "start")
            .every(label => Number(label.attributes.get("x")) + 260 <= model.width));
        assert.match(callouts[1].querySelector("title").textContent,
            /2026-10-03 09:05:20\.000 KST · UTC 2026-10-03T00:05:20\.000Z · 원본 2026-10-03T00:05:20\.000Z/);
        const legend = chart.querySelector(".fusion-score-chart__legend").textContent;
        assert.doesNotMatch(legend, /진입 기준|해제 기준/);
        assert.match(legend, /탐지 구간 활성.*탐지 구간 비활성.*탐지 구간/);
        assert.deepEqual(chart.querySelectorAll(".fusion-score-chart__threshold-label").map(label => label.textContent),
            []);
        assert.equal(chart.querySelectorAll(".fusion-score-chart__threshold").length, 0);
        const technical = chart.querySelector(".fusion-score-chart__technical");
        assert.match(technical.textContent, /진입 기준 0.80.*해제 기준 0.40/);
        assert.equal(technical.attributes.has("open"), false);
    });
});

test("Task 3 an open stored Episode keeps its start and states the missing end without a band", () => {
    // Given
    const { model, result } = task3Fixture();
    result.fusion_episodes[0].end_time = null;
    result.fusion_episodes[0].end_reason = null;
    // When
    const presentation = buildDashboardReplayPresentation(model, result);
    // Then
    assert.deepEqual(presentation.transitions.map(item => item.kind), ["start"]);
    assert.deepEqual(presentation.openEpisodes, ["FEP-001"]);
    assert.deepEqual(presentation.bands, []);
    withReplayDocument(() => {
        const records = createDashboardReplayRecords(result).textContent;
        assert.match(records, /09:00:20\.000 KST — 탐지 구간 시작/);
        assert.match(records, /FEP-001 · 종료 시각 저장 없음/);
        assert.doesNotMatch(records, /탐지 구간 해제|09:11:00/);
    });
});

test("Task 3 KST milliseconds, UTC and verbatim offset/submillisecond strings remain accessible", async () => {
    // Given
    const { scoreTimestampDetails, createTraceTable } = await import("../../../src/incident_awareness/dashboard/ui/assets/fusion-score-chart.mjs");
    const original = "2026-10-03T09:00:20.123456+09:00";
    // When
    const details = scoreTimestampDetails(original);
    // Then
    assert.deepEqual(details, { date: "2026-10-03", time: "09:00:20", kst: "2026-10-03 09:00:20.123 KST",
        utc: "2026-10-03T00:00:20.123Z", original });
    assert.equal(scoreTimestampDetails("2026-10-03T23:59:59.999Z").kst, "2026-10-04 08:59:59.999 KST");
    assert.equal(scoreTimestampDetails("2026-10-03T00:00:20").time, "시각 미확인");
    withReplayDocument(() => {
        const table = createTraceTable([{ timestamp: original, score: 1, policy_state: "on", persistence_count: 2 }]);
        const cells = table.querySelectorAll("td");
        assert.equal(cells[0].textContent, details.kst);
        assert.equal(cells[4].textContent, details.utc);
        assert.equal(cells[5].textContent, original);
    });
});

test("Task 3 chart and shared dashboard clocks stay KST in UTC, US and Asian process time zones", async () => {
    // Given
    const { execFileSync } = await import("node:child_process");
    const chartUrl = new URL("../../../src/incident_awareness/dashboard/ui/assets/fusion-score-chart.mjs", import.meta.url).href;
    const contractUrl = new URL("../../../src/incident_awareness/dashboard/ui/assets/dashboard-contract.mjs", import.meta.url).href;
    const script = `import { scoreTimestampDetails } from ${JSON.stringify(chartUrl)};
        import { formatRunTimestamp } from ${JSON.stringify(contractUrl)};
        process.stdout.write(JSON.stringify({ zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            localHour: new Date('2026-10-03T00:00:20.123Z').getHours(),
            chart: scoreTimestampDetails('2026-10-03T00:00:20.123Z'),
            shared: formatRunTimestamp('2026-10-08T18:49:53.429Z') }));`;
    const zones = ["UTC", "America/Los_Angeles", "Asia/Tokyo"];
    // When
    const outputs = zones.map(TZ => JSON.parse(execFileSync(
        process.execPath, ["--input-type=module", "-e", script], { env: { ...process.env, TZ }, encoding: "utf8" },
    )));
    // Then: the subprocesses really ran in different zones, yet every clock is the same KST value.
    assert.deepEqual(outputs.map(output => output.zone), zones);
    assert.deepEqual(outputs.map(output => output.localHour), [0, 17, 9]);
    assert.ok(outputs.every(output => output.chart.kst === "2026-10-03 09:00:20.123 KST"));
    assert.deepEqual(outputs[0].chart, outputs[1].chart);
    assert.deepEqual(outputs[1].chart, outputs[2].chart);
    assert.ok(outputs.every(output => output.shared === outputs[0].shared));
    assert.match(outputs[0].shared, /2026\.10\.09/);
    assert.match(outputs[0].shared, /KST/);
});

test("Standalone score chart uses KST for focus and preserves exact source in technical detail", async () => {
    // Given
    const { createScoreTrajectoryChart } = await import("../../../src/incident_awareness/dashboard/ui/assets/fusion-score-chart.mjs");
    const previous = globalThis.document;
    globalThis.document = {
        createElement: tag => new FakeElement(tag),
        createElementNS: (_, tag) => new FakeElement(tag),
        createTextNode: value => ({ textContent: value, children: [] }),
    };
    const trace = makeTrace();
    trace.points[0].timestamp = "2026-10-05T00:00:00.123456+00:00";
    const original = JSON.stringify(trace);
    try {
        // When
        const model = buildScoreTrajectoryModel(trace, null, DIMENSIONS);
        const chart = createScoreTrajectoryChart(model);
        const marker = chart.querySelector(".fusion-score-chart__point");
        marker.focus();
        // Then
        const detail = chart.querySelector(".fusion-score-chart__point-detail").textContent;
        assert.match(detail, /2026\.10\.05 09:00:00\.123456 KST/);
        assert.doesNotMatch(detail, /2026-10-05T/);
        assert.equal(marker.attributes.get("aria-label"), detail);
        assert.ok(marker.querySelector("title").textContent.includes(trace.points[0].timestamp));
        assert.equal(JSON.stringify(trace), original);
    } finally {
        if (previous === undefined) delete globalThis.document;
        else globalThis.document = previous;
    }
});
