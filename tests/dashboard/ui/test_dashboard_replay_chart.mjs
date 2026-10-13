import assert from "node:assert/strict";
import test from "node:test";

import { buildScoreTrajectoryModel } from "../../../src/incident_awareness/dashboard/ui/assets/fusion-engine-contract.mjs";
import {
    buildDashboardReplayPresentation,
    createDashboardReplayChart,
} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-replay-chart.mjs";

const DIMENSIONS = {
    width: 960,
    height: 180,
    padding: { top: 50, right: 72, bottom: 27, left: 50 },
};

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
        "판단 진입",
        "판단 해제",
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
    assert.deepEqual(presentation.transitions.map((item) => item.label), ["판단 진입"]);
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
        "판단 진입",
        "판단 해제",
        "기술적 판단 t_e",
    ]);
    assert.ok(distinct.highlightedIndices.has(10));
    assert.deepEqual(sameAsEpisodeStart.transitions.map((item) => item.label), [
        "판단 진입 · t_e",
        "판단 해제",
    ]);
    assert.equal(outsideTrace.transitions.length, 2);
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
        assert.match(chart.querySelector("desc").textContent, /FusionStoppingTrace/);
        assert.match(chart.querySelector("desc").textContent, /판단 진입/);
        assert.match(chart.querySelector("desc").textContent, /판단 해제/);
        assert.match(chart.querySelector("desc").textContent, /기술적 판단 t_e/);
    } finally {
        if (previousDocument === undefined) {
            delete globalThis.document;
        } else {
            globalThis.document = previousDocument;
        }
    }
});
