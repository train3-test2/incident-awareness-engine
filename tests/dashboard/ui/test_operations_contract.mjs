// Operations View UI contract: runs the real presentation module under Node's built-in test runner.
// Run with: node --test tests/dashboard/ui/test_operations_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    NOT_APPLICABLE,
    getRuntimeProgressPresentation,
    getRuntimeQueryMessage,
    getRuntimeStatePresentation,
    getStageLabel,
    resolveRuntimeQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/operations-contract.mjs";

const RUNNING_STATUS_LABEL = "실행 중(마지막 보고)";
const PIPELINE_FAILURE_WORDING = /실패|중단|종료|failed|stopped|dead|timeout/i;

function runtime(overrides) {
    return {
        status: "running",
        is_stale: false,
        has_error: false,
        current_stage: "normalization",
        failed_stage: null,
        normalization_processed_count: 137,
        input_total: 250,
        remaining_count: 113,
        ...overrides,
    };
}

function presentationText(presentation) {
    return [presentation.statusLabel, presentation.telemetryLabel, presentation.livenessLabel]
        .filter((label) => label !== null)
        .join(" ");
}

function createFakeElement(tagName) {
    let text = "";
    return {
        tagName: tagName.toUpperCase(),
        children: [],
        attributes: new Map(),
        classList: {
            values: new Set(),
            add(...values) {
                for (const value of values) {
                    this.values.add(value);
                }
            },
        },
        append(...children) {
            this.children.push(...children);
        },
        setAttribute(name, value) {
            this.attributes.set(name, String(value));
        },
        get textContent() {
            return text;
        },
        set textContent(value) {
            text = String(value);
        },
    };
}

test("fresh running reports recent telemetry without claiming liveness", () => {
    // Given
    const freshRunning = runtime({ status: "running", is_stale: false });

    // When
    const presentation = getRuntimeStatePresentation(freshRunning, true);

    // Then
    assert.deepEqual(presentation, {
        modifiers: ["running"],
        statusLabel: RUNNING_STATUS_LABEL,
        telemetryLabel: "최근 갱신",
        livenessLabel: null,
    });
});

test("stale running keeps the running status but cannot confirm current execution", () => {
    // Given
    const staleRunning = runtime({ status: "running", is_stale: true });

    // When
    const presentation = getRuntimeStatePresentation(staleRunning, true);

    // Then
    assert.deepEqual(presentation, {
        modifiers: ["running", "stale"],
        statusLabel: RUNNING_STATUS_LABEL,
        telemetryLabel: "오래됨",
        livenessLabel: "확인 불가",
    });
    assert.doesNotMatch(presentationText(presentation), PIPELINE_FAILURE_WORDING);
    assert.doesNotMatch(presentationText(presentation), /현재 실행 중/);
});

test("retained running shows unavailable telemetry while the query is failing", () => {
    // Given
    const retained = [
        runtime({ status: "running", is_stale: false }),
        runtime({ status: "running", is_stale: true }),
    ];

    // When
    const presentations = retained.map((item) => getRuntimeStatePresentation(item, false));

    // Then
    for (const presentation of presentations) {
        assert.deepEqual(presentation, {
            modifiers: ["running", "telemetry-unavailable"],
            statusLabel: RUNNING_STATUS_LABEL,
            telemetryLabel: "확인 불가 (조회 실패)",
            livenessLabel: "확인 불가",
        });
        assert.notEqual(presentation.telemetryLabel, "최근 갱신");
        assert.notEqual(presentation.telemetryLabel, "오래됨");
        assert.notEqual(presentation.statusLabel, "실패");
        assert.ok(!presentation.modifiers.includes("failed"));
    }
});

test("completed is presented as completed regardless of query availability", () => {
    // Given
    const completed = runtime({ status: "completed", current_stage: null, remaining_count: 0 });

    // When
    const available = getRuntimeStatePresentation(completed, true);
    const unavailable = getRuntimeStatePresentation(completed, false);

    // Then
    assert.equal(available.statusLabel, "완료");
    assert.deepEqual(available.modifiers, ["completed"]);
    assert.equal(available.telemetryLabel, NOT_APPLICABLE);
    assert.deepEqual(unavailable, available);
});

test("failed is presented as failed regardless of query availability", () => {
    // Given
    const failed = runtime({
        status: "failed",
        has_error: true,
        current_stage: null,
        failed_stage: "hybrid",
    });

    // When
    const available = getRuntimeStatePresentation(failed, true);
    const unavailable = getRuntimeStatePresentation(failed, false);

    // Then
    assert.equal(available.statusLabel, "실패");
    assert.deepEqual(available.modifiers, ["failed"]);
    assert.equal(available.telemetryLabel, NOT_APPLICABLE);
    assert.deepEqual(unavailable, available);
});

test("persisted status, not has_error, decides the presented state", () => {
    // Given
    const runningWithErrorFlag = runtime({ status: "running", has_error: true });

    // When
    const presentation = getRuntimeStatePresentation(runningWithErrorFlag, true);

    // Then
    assert.equal(presentation.statusLabel, RUNNING_STATUS_LABEL);
    assert.deepEqual(presentation.modifiers, ["running"]);
});

test("stage vocabulary maps to readable labels with safe fallbacks", () => {
    // Given
    const expectedLabels = [
        ["artifact_validation", "입력 검증"],
        ["normalization", "이벤트 처리"],
        ["fusion", "증거 누적 판단"],
        ["fast_handoff", "즉시 판단 연계"],
        ["hybrid", "통합 판단"],
        ["persistence", "결과 저장"],
    ];

    // When
    const labels = expectedLabels.map(([stage]) => getStageLabel(stage));

    // Then
    assert.deepEqual(labels, expectedLabels.map(([, label]) => label));
    assert.equal(getStageLabel(null), "-");
    assert.equal(getStageLabel(undefined), "-");
    assert.equal(getStageLabel("future_stage_x"), "future_stage_x");
});

test("progress shows processed, total, and remaining counts as reported", () => {
    // Given
    const inProgress = {
        normalization_processed_count: 137,
        input_total: 250,
        remaining_count: 113,
    };
    const finished = { normalization_processed_count: 250, input_total: 250, remaining_count: 0 };

    // When
    const inProgressPresentation = getRuntimeProgressPresentation(inProgress);
    const finishedPresentation = getRuntimeProgressPresentation(finished);

    // Then
    assert.deepEqual(inProgressPresentation, { processed: "137 / 250 처리", remaining: "113" });
    assert.deepEqual(finishedPresentation, { processed: "250 / 250 처리", remaining: "0" });
    assert.doesNotMatch(JSON.stringify(inProgressPresentation), /%|대기열|backlog|queue/i);
});

test("query messages cover loading, success, empty, and error states", () => {
    // Given
    const states = [["loading"], ["success", 3], ["success", 0], ["error"]];

    // When
    const messages = states.map(([state, count]) => getRuntimeQueryMessage(state, count));

    // Then
    assert.deepEqual(messages, [
        "Runtime 정보를 불러오는 중입니다.",
        "Runtime 3건을 불러왔습니다.",
        "표시할 Runtime 정보가 없습니다.",
        "Runtime 정보를 불러오지 못했습니다.",
    ]);
});

test("query messages reject unknown states and invalid counts", () => {
    // Given
    const invalidCalls = [
        () => getRuntimeQueryMessage("refreshing"),
        () => getRuntimeQueryMessage("success"),
        () => getRuntimeQueryMessage("success", -1),
        () => getRuntimeQueryMessage("success", 1.5),
    ];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall, RangeError);
    }
});

test("empty query success clears the visible Runtime items", () => {
    // Given
    const previousItems = [{ status: "running" }];
    const previousSnapshot = structuredClone(previousItems);

    // When
    const result = resolveRuntimeQueryState(
        previousItems,
        { kind: "success", items: [] },
    );

    // Then
    assert.deepEqual(result.items, []);
    assert.equal(result.telemetryAvailable, true);
    assert.equal(result.message, "표시할 Runtime 정보가 없습니다.");
    assert.deepEqual(previousItems, previousSnapshot);
});

test("query error retains the last successful Runtime items", () => {
    // Given
    const previousItems = [{ run_id: "RUN-1", status: "running" }];
    const previousSnapshot = structuredClone(previousItems);

    // When
    const result = resolveRuntimeQueryState(previousItems, { kind: "error" });

    // Then
    assert.strictEqual(result.items, previousItems);
    assert.equal(result.telemetryAvailable, false);
    assert.equal(result.message, "Runtime 정보를 불러오지 못했습니다.");
    assert.deepEqual(previousItems, previousSnapshot);
});

test("query state rejects invalid previous items, success items, and result kinds", () => {
    // Given
    const invalidCalls = [
        () => resolveRuntimeQueryState(null, { kind: "error" }),
        () => resolveRuntimeQueryState([], { kind: "success", items: null }),
        () => resolveRuntimeQueryState([], { kind: "unknown" }),
    ];

    // When / Then
    for (const invalidCall of invalidCalls) {
        assert.throws(invalidCall);
    }
});

test("Operations links only completed Runtime items with the shared Run Detail path", async () => {
    // Given
    const scriptPath = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/operations.js",
        import.meta.url,
    );

    // When
    const script = await readFile(scriptPath, "utf8");
    const cardSource = script.slice(
        script.indexOf("function createRuntimeCard"),
        script.indexOf("function renderRuntimeItems"),
    );

    // Then
    assert.match(
        script,
        /import \{ buildRunDetailViewPath \} from "\.\/run-detail-contract\.mjs";/,
    );
    assert.match(
        cardSource,
        /if \(runtime\.status === "completed" && runtime\.run_id\.trim\(\)\) \{/,
    );
    assert.match(cardSource, /link\.href = buildRunDetailViewPath\(runtime\.run_id\);/);
    assert.equal(cardSource.match(/buildRunDetailViewPath/g)?.length, 1);
});

test("Operations DOM renderer links completed Runs and leaves running Runs as text", async () => {
    // Given
    const originalDocument = globalThis.document;
    globalThis.document = {
        createElement: createFakeElement,
        getElementById() {
            return null;
        },
    };
    const moduleUrl = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/operations.js",
        import.meta.url,
    );

    try {
        const operationsContractUrl = new URL(
            "../../../src/incident_awareness/dashboard/ui/assets/operations-contract.mjs",
            import.meta.url,
        );
        const runDetailContractUrl = new URL(
            "../../../src/incident_awareness/dashboard/ui/assets/run-detail-contract.mjs",
            import.meta.url,
        );
        const moduleSource = (await readFile(moduleUrl, "utf8"))
            .replace("./operations-contract.mjs", operationsContractUrl.href)
            .replace("./run-detail-contract.mjs", runDetailContractUrl.href);
        const moduleDataUrl = `data:text/javascript;charset=utf-8,${encodeURIComponent(
            moduleSource,
        )}`;
        const { createRuntimeCard } = await import(moduleDataUrl);
        const completed = runtime({
            run_id: "RUN 251/completed",
            status: "completed",
            current_stage: null,
            remaining_count: 0,
        });
        const running = runtime({ run_id: "RUN-251-running" });

        // When
        const completedCard = createRuntimeCard(completed, true);
        const runningCard = createRuntimeCard(running, true);
        const completedHeading = completedCard.children[0].children[0];
        const runningHeading = runningCard.children[0].children[0];

        // Then
        assert.equal(completedHeading.children.length, 1);
        assert.equal(
            completedHeading.children[0].href,
            "/dashboard/runs/RUN%20251%2Fcompleted",
        );
        assert.equal(completedHeading.children[0].textContent, "RUN 251/completed");
        assert.equal(runningHeading.children.length, 0);
        assert.equal(runningHeading.textContent, "RUN-251-running");
    } finally {
        if (originalDocument === undefined) {
            delete globalThis.document;
        } else {
            globalThis.document = originalDocument;
        }
    }
});

// The polling scenarios below run the real operations.js against a minimal DOM, fetch, and
// timer double. Focus follows browser rules: a removed element cannot keep focus.
const OPERATIONS_ASSETS_URL = new URL(
    "../../../src/incident_awareness/dashboard/ui/assets/",
    import.meta.url,
);
const OPERATIONS_POLL_DELAY_MS = 5000;
let operationsHarnessCount = 0;

class OperationsElement {
    constructor(ownerDocument, tagName) {
        this.ownerDocument = ownerDocument;
        this.tagName = tagName.toUpperCase();
        this.parentNode = null;
        this.childNodes = [];
        this.classNames = new Set();
        this.classList = {
            add: (...names) => names.forEach((name) => this.classNames.add(name)),
            contains: (name) => this.classNames.has(name),
        };
        this.attributes = new Map();
        this.ownText = "";
        this.href = "";
        this.focusCalls = [];
    }

    get children() {
        return this.childNodes;
    }

    get textContent() {
        return this.ownText + this.childNodes.map((child) => child.textContent).join("");
    }

    set textContent(value) {
        this.replaceChildren();
        this.ownText = String(value);
    }

    get isConnected() {
        return this.ownerDocument.body.contains(this);
    }

    append(...nodes) {
        for (const node of nodes) {
            node.parentNode = this;
            this.childNodes.push(node);
        }
    }

    replaceChildren(...nodes) {
        for (const child of this.childNodes) {
            child.parentNode = null;
        }
        this.childNodes = [];
        this.ownText = "";
        this.append(...nodes);
    }

    setAttribute(name, value) {
        this.attributes.set(name, String(value));
    }

    getAttribute(name) {
        return this.attributes.get(name) ?? null;
    }

    focus(options = {}) {
        if (!this.isConnected || (this.tagName === "A" && this.href === "")) {
            return;
        }
        this.focusCalls.push({ ...options });
        this.ownerDocument.focusedElement = this;
    }

    scrollIntoView() {
        throw new Error("Operations focus restoration must not scroll the page");
    }

    contains(node) {
        for (let current = node; current !== null && current !== undefined;) {
            if (current === this) {
                return true;
            }
            current = current.parentNode;
        }
        return false;
    }

    querySelectorAll(selector) {
        assert.match(selector, /^\.[\w-]+$/);
        const className = selector.slice(1);
        const matches = [];
        const visit = (element) => {
            for (const child of element.childNodes) {
                if (child.classList.contains(className)) {
                    matches.push(child);
                }
                visit(child);
            }
        };
        visit(this);
        return matches;
    }
}

async function startOperationsHarness(initialItems) {
    const document = {
        focusedElement: null,
        createElement: (tagName) => new OperationsElement(document, tagName),
        getElementById: (id) => document.elements.get(id) ?? null,
        get activeElement() {
            const focused = this.focusedElement;
            return focused === null || !focused.isConnected ? this.body : focused;
        },
    };
    document.body = new OperationsElement(document, "body");
    document.elements = new Map([
        ["runtime-status", new OperationsElement(document, "p")],
        ["runtime-list", new OperationsElement(document, "div")],
    ]);
    const navigationLink = new OperationsElement(document, "a");
    navigationLink.href = "/dashboard";
    document.body.append(navigationLink, ...document.elements.values());

    const requests = [];
    const timers = new Map();
    let nextTimerId = 1;
    const fakeGlobals = {
        document,
        fetch: (url) => new Promise((resolve) => {
            requests.push({ url: String(url), resolve, settled: false });
        }),
        setTimeout: (callback, delay) => {
            const id = nextTimerId;
            nextTimerId += 1;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeout: (id) => {
            timers.delete(id);
        },
    };
    const originalGlobals = new Map(
        Object.keys(fakeGlobals).map(
            (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)],
        ),
    );
    const restore = () => {
        for (const [name, descriptor] of originalGlobals) {
            if (descriptor === undefined) {
                delete globalThis[name];
            } else {
                Object.defineProperty(globalThis, name, descriptor);
            }
        }
    };
    for (const [name, value] of Object.entries(fakeGlobals)) {
        Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
    }
    const flush = async () => {
        for (let index = 0; index < 10; index += 1) {
            await new Promise((resolve) => setImmediate(resolve));
        }
    };
    const respond = async (status, body) => {
        const request = requests.find((candidate) => !candidate.settled);
        assert.ok(request, "Expected a pending Runtime request");
        assert.equal(request.url, "/operations/runtime");
        request.settled = true;
        request.resolve({ ok: status >= 200 && status < 300, status, json: async () => body });
        await flush();
    };
    const triggerPollTimer = async () => {
        const pollTimers = [...timers].filter(
            ([, timer]) => timer.delay === OPERATIONS_POLL_DELAY_MS,
        );
        assert.equal(pollTimers.length, 1, "Exactly one Runtime poll must be scheduled");
        const [[timerId, timer]] = pollTimers;
        timers.delete(timerId);
        timer.callback();
        await flush();
    };

    const source = await readFile(new URL("operations.js", OPERATIONS_ASSETS_URL), "utf8");
    const moduleSource = source.replaceAll(
        /from "\.\/([^"]+)"/g,
        (_, file) => `from "${new URL(file, OPERATIONS_ASSETS_URL).href}"`,
    );
    operationsHarnessCount += 1;
    try {
        await import(
            "data:text/javascript;charset=utf-8,"
            + encodeURIComponent(`${moduleSource}\n// operations harness ${operationsHarnessCount}\n`)
        );
        await flush();
        await respond(200, { items: initialItems });
    } catch (error) {
        restore();
        throw error;
    }

    const runtimeList = document.getElementById("runtime-list");
    // card > header > heading > completed-Run link
    const headingOf = (card) => card.children[0].children[0];
    return {
        document,
        navigationLink,
        restore,
        respond,
        triggerPollTimer,
        async poll(items) {
            await triggerPollTimer();
            await respond(200, { items });
        },
        async pollFailure() {
            await triggerPollTimer();
            await respond(503, { detail: "Runtime unavailable" });
        },
        cards: () => runtimeList.children,
        completedLink(runId, entityId) {
            const card = runtimeList.children.find(
                (candidate) => (
                    headingOf(candidate).textContent === runId
                    && candidate.children[1].children[0].children[1].textContent === entityId
                ),
            );
            return headingOf(card).children[0];
        },
        cardSummary: () => runtimeList.children.map((card) => ({
            runId: headingOf(card).textContent,
            entityId: card.children[1].children[0].children[1].textContent,
            linked: headingOf(card).children.length === 1,
            status: card.children[0].children[1].textContent,
            modifiers: [...card.classNames].filter((name) => name !== "runtime-card"),
        })),
    };
}

function pollingRuntime(runId, entityId, status, updatedAt = "2026-09-20T01:00:00Z") {
    return {
        ...runtime({
            run_id: runId,
            status,
            current_stage: status === "running" ? "normalization" : null,
            failed_stage: status === "failed" ? "hybrid" : null,
            has_error: status === "failed",
        }),
        execution_id: `${runId}-${entityId}`,
        entity_id: entityId,
        started_at: "2026-09-20T00:59:00Z",
        stage_started_at: null,
        updated_at: updatedAt,
        completed_at: status === "completed" ? "2026-09-20T01:00:00Z" : null,
    };
}

function operationsPollingItems(runningUpdatedAt) {
    return [
        pollingRuntime("RUN-S0", "WIN-01", "completed"),
        pollingRuntime("RUN-S0", "WIN-02", "completed"),
        pollingRuntime("RUN-DEMO", "WIN-DEMO", "running", runningUpdatedAt),
        pollingRuntime("RUN-FAILED", "WIN-03", "failed"),
    ];
}

test("Operations polling restores completed Run link focus by Run, Entity and link kind", async (t) => {
    // Given
    const harness = await startOperationsHarness(operationsPollingItems("2026-09-20T01:00:00Z"));
    t.after(harness.restore);
    const cardsBefore = harness.cardSummary();
    const original = harness.completedLink("RUN-S0", "WIN-02");
    original.focus();

    // When
    await harness.poll(operationsPollingItems("2026-09-20T01:00:05Z"));
    const firstRestore = harness.document.activeElement;
    await harness.poll(operationsPollingItems("2026-09-20T01:00:10Z"));
    const secondRestore = harness.document.activeElement;

    // Then
    assert.equal(original.isConnected, false);
    assert.notStrictEqual(firstRestore, original);
    assert.notStrictEqual(secondRestore, firstRestore);
    assert.strictEqual(secondRestore, harness.completedLink("RUN-S0", "WIN-02"));
    assert.notStrictEqual(secondRestore, harness.completedLink("RUN-S0", "WIN-01"));
    for (const restored of [firstRestore, secondRestore]) {
        assert.equal(restored.tagName, "A");
        assert.equal(restored.href, "/dashboard/runs/RUN-S0");
        assert.equal(restored.textContent, "RUN-S0");
        assert.deepEqual(restored.focusCalls, [{ preventScroll: true }]);
    }
    assert.deepEqual(harness.cardSummary(), cardsBefore);
    assert.deepEqual(
        cardsBefore.map(({ runId, entityId, linked, modifiers }) => ({
            runId,
            entityId,
            linked,
            modifiers,
        })),
        [
            { runId: "RUN-S0", entityId: "WIN-01", linked: true, modifiers: ["runtime-card--completed"] },
            { runId: "RUN-S0", entityId: "WIN-02", linked: true, modifiers: ["runtime-card--completed"] },
            { runId: "RUN-DEMO", entityId: "WIN-DEMO", linked: false, modifiers: ["runtime-card--running"] },
            { runId: "RUN-FAILED", entityId: "WIN-03", linked: false, modifiers: ["runtime-card--failed"] },
        ],
    );
});

test("Operations polling restores the completed Run link after a failed Runtime query", async (t) => {
    // Given
    const harness = await startOperationsHarness(operationsPollingItems("2026-09-20T01:00:00Z"));
    t.after(harness.restore);
    harness.completedLink("RUN-S0", "WIN-01").focus();

    // When
    await harness.pollFailure();

    // Then
    assert.strictEqual(harness.document.activeElement, harness.completedLink("RUN-S0", "WIN-01"));
    assert.equal(harness.cards().length, 4);
    assert.equal(harness.document.getElementById("runtime-status").textContent.includes("불러오지 못했습니다"), true);
});

test("Operations polling never moves focus to another card or away from a new user target", async (t) => {
    // Given
    const harness = await startOperationsHarness(operationsPollingItems("2026-09-20T01:00:00Z"));
    t.after(harness.restore);

    // When: the user moves to the navigation link while the Runtime request is pending.
    harness.completedLink("RUN-S0", "WIN-02").focus();
    await harness.triggerPollTimer();
    harness.navigationLink.focus();
    await harness.respond(200, { items: operationsPollingItems("2026-09-20T01:00:05Z") });
    const afterUserMove = harness.document.activeElement;
    // When: the focused Run/Entity card is no longer reported.
    harness.completedLink("RUN-S0", "WIN-02").focus();
    await harness.poll(
        operationsPollingItems("2026-09-20T01:00:10Z").filter(
            (item) => item.entity_id !== "WIN-02",
        ),
    );
    const afterCardRemoved = harness.document.activeElement;

    // Then
    assert.strictEqual(afterUserMove, harness.navigationLink);
    assert.strictEqual(afterCardRemoved, harness.document.body);
    assert.deepEqual(harness.completedLink("RUN-S0", "WIN-01").focusCalls, []);
    assert.equal(harness.cards().length, 3);
});
