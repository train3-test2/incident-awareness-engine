// Event Timeline UI contract tests use Node's built-in test runner only.
// Run with: node --test tests/dashboard/ui/test_event_timeline_contract.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    buildEventTimelineApiPath,
    buildEventTimelineViewPath,
    extractTimelineRunIdFromPathname,
    filterEventTimelinePage,
    getEventTimelinePagination,
    getEventTimelinePagePosition,
    resolveEventTimelineQueryState,
} from "../../../src/incident_awareness/dashboard/ui/assets/event-timeline-contract.mjs";

function makeEvent(index) {
    return {
        event_id: `evt-${String(index).padStart(3, "0")}`,
        timestamp: `2026-09-20T01:00:${String(index % 60).padStart(2, "0")}.000Z`,
        host_id: "WIN-01",
        event_type: "process_create",
    };
}

function makePayload({ itemCount = 2, total = itemCount, limit = 50, offset = 0 } = {}) {
    return {
        items: Array.from({ length: itemCount }, (_, index) => makeEvent(offset + index)),
        total,
        limit,
        offset,
    };
}

test("Event type filter covers only a supplied page and never mutates its order or totals", () => {
    // Given
    const page = makePayload({ itemCount: 3, total: 129, offset: 50 });
    page.items[1].event_type = "network_connection";
    Object.freeze(page.items);
    const snapshot = JSON.stringify(page);

    // When
    const matches = filterEventTimelinePage(page.items, "network_connection");
    const position = getEventTimelinePagePosition(page);

    // Then
    assert.deepEqual(matches, [page.items[1]]);
    assert.strictEqual(matches[0], page.items[1]);
    assert.equal(filterEventTimelinePage(page.items, "all").length, 3);
    assert.deepEqual(filterEventTimelinePage(page.items, "not-in-page"), []);
    assert.deepEqual(filterEventTimelinePage([], "all"), []);
    assert.equal(position.currentPage, 2);
    assert.equal(position.totalPages, 3);
    assert.equal(position.displayStart, 51);
    assert.equal(position.displayEnd, 53);
    assert.equal(JSON.stringify(page), snapshot);
    assert.equal(getEventTimelinePagePosition(makePayload({ itemCount: 0 })).currentPage, 0);
    assert.throws(() => filterEventTimelinePage(null), TypeError);
    assert.throws(() => filterEventTimelinePage(page.items, ""), TypeError);
});

test("Event Timeline view and API paths encode identifiers and query parameters", () => {
    // Given
    const runId = "RUN 20260920/001";

    // When
    const viewPath = buildEventTimelineViewPath(runId);
    const apiPath = buildEventTimelineApiPath(runId, 50, 0);

    // Then
    assert.equal(viewPath, "/dashboard/runs/RUN%2020260920%2F001/timeline");
    assert.equal(apiPath, "/runs/RUN%2020260920%2F001/timeline?limit=50&offset=0");
});

test("Event Timeline path builders reject invalid identifiers and pagination", () => {
    // Given
    const invalidRunIds = [null, undefined, "", "   "];
    const invalidPagination = [
        [0, 0],
        [201, 0],
        [50.5, 0],
        [50, -1],
        [50, 0.5],
    ];

    // When
    const buildViewPath = (runId) => buildEventTimelineViewPath(runId);

    // Then
    for (const runId of invalidRunIds) {
        assert.throws(() => buildViewPath(runId));
        assert.throws(() => buildEventTimelineApiPath(runId, 50, 0));
    }
    for (const [limit, offset] of invalidPagination) {
        assert.throws(() => buildEventTimelineApiPath("RUN-20260920-001", limit, offset));
    }
});

test("Event Timeline pathname extracts one encoded Run ID segment", () => {
    // Given
    const pathname = "/dashboard/runs/RUN%2020260920%2F001/timeline";

    // When
    const runId = extractTimelineRunIdFromPathname(pathname);

    // Then
    assert.equal(runId, "RUN 20260920/001");
});

test("Event Timeline pathname rejects malformed and unrelated paths", () => {
    // Given
    const invalidPathnames = [
        null,
        "/dashboard/runs/",
        "/dashboard/runs/RUN-001",
        "/dashboard/runs/RUN-001/timeline/extra",
        "/runs/RUN-001/timeline",
        "/dashboard/runs/%/timeline",
        "/dashboard/runs/%20/timeline",
        "/dashboard/runs/A/B/timeline",
    ];

    // When
    const runIds = invalidPathnames.map((pathname) => (
        extractTimelineRunIdFromPathname(pathname)
    ));

    // Then
    assert.deepEqual(runIds, [null, null, null, null, null, null, null, null]);
});

test("Event Timeline query states keep loading and failures distinct", () => {
    // Given
    const previousState = null;

    // When
    const loading = resolveEventTimelineQueryState(previousState, { kind: "loading" });
    const runNotFound = resolveEventTimelineQueryState(loading, {
        kind: "run_not_found",
    });
    const error = resolveEventTimelineQueryState(loading, { kind: "error" });

    // Then
    assert.deepEqual(loading, {
        queryState: "loading",
        payload: null,
        message: "Event Timeline을 불러오는 중입니다.",
    });
    assert.deepEqual(runNotFound, {
        queryState: "run_not_found",
        payload: null,
        message: "분석을 찾을 수 없습니다.",
    });
    assert.deepEqual(error, {
        queryState: "error",
        payload: null,
        message: "Event Timeline을 불러오지 못했습니다.",
    });
});

test("Event Timeline success preserves API references, order, and payload", () => {
    // Given
    const previousState = resolveEventTimelineQueryState(null, { kind: "loading" });
    const payload = makePayload();
    payload.items = [makeEvent(2), makeEvent(1)];
    const payloadSnapshot = structuredClone(payload);
    const items = payload.items;

    // When
    const state = resolveEventTimelineQueryState(previousState, {
        kind: "success",
        payload,
    });

    // Then
    assert.equal(state.queryState, "success");
    assert.equal(state.message, "Event Timeline을 불러왔습니다.");
    assert.strictEqual(state.payload, payload);
    assert.strictEqual(state.payload.items, items);
    assert.deepEqual(
        state.payload.items.map((event) => event.event_id),
        ["evt-002", "evt-001"],
    );
    assert.deepEqual(payload, payloadSnapshot);
});

test("Event Timeline total zero resolves to the empty state", () => {
    // Given
    const payload = makePayload({ itemCount: 0, total: 0 });

    // When
    const state = resolveEventTimelineQueryState(null, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "empty");
    assert.strictEqual(state.payload, payload);
    assert.equal(state.message, "이 분석에 저장된 Event가 없습니다.");
});

test("Event Timeline preserves a whitespace-only string Event ID", () => {
    // Given
    const payload = makePayload({ itemCount: 1 });
    payload.items[0].event_id = "   ";

    // When
    const state = resolveEventTimelineQueryState(null, { kind: "success", payload });

    // Then
    assert.equal(state.queryState, "success");
    assert.strictEqual(state.payload.items, payload.items);
    assert.equal(state.payload.items[0].event_id, "   ");
});

test("Event Timeline pagination follows API page boundaries", () => {
    // Given
    const pages = [
        makePayload({ itemCount: 50, total: 123, offset: 0 }),
        makePayload({ itemCount: 50, total: 123, offset: 50 }),
        makePayload({ itemCount: 23, total: 123, offset: 100 }),
        makePayload({ itemCount: 0, total: 0, offset: 0 }),
    ];

    // When
    const pagination = pages.map((page) => getEventTimelinePagination(page));

    // Then
    assert.deepEqual(pagination, [
        {
            hasPrevious: false,
            hasNext: true,
            previousOffset: 0,
            nextOffset: 50,
            displayStart: 1,
            displayEnd: 50,
        },
        {
            hasPrevious: true,
            hasNext: true,
            previousOffset: 0,
            nextOffset: 100,
            displayStart: 51,
            displayEnd: 100,
        },
        {
            hasPrevious: true,
            hasNext: false,
            previousOffset: 50,
            nextOffset: 123,
            displayStart: 101,
            displayEnd: 123,
        },
        {
            hasPrevious: false,
            hasNext: false,
            previousOffset: 0,
            nextOffset: 0,
            displayStart: 0,
            displayEnd: 0,
        },
    ]);
});

test("Event Timeline query state rejects malformed responses", () => {
    // Given
    const validItem = makeEvent(1);
    const malformedPayloads = [
        null,
        [],
        { items: null, total: 0, limit: 50, offset: 0 },
        { items: [], total: -1, limit: 50, offset: 0 },
        { items: [], total: 0, limit: 0, offset: 0 },
        { items: [], total: 0, limit: 50, offset: -1 },
        { items: [null], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, event_id: 1 }], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, timestamp: null }], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, host_id: 1 }], total: 1, limit: 50, offset: 0 },
        { items: [{ ...validItem, event_type: 1 }], total: 1, limit: 50, offset: 0 },
    ];

    // When
    const validatePayload = (payload) => resolveEventTimelineQueryState(
        null,
        { kind: "success", payload },
    );

    // Then
    assert.throws(() => resolveEventTimelineQueryState([], { kind: "error" }), TypeError);
    assert.throws(() => resolveEventTimelineQueryState(null, null), TypeError);
    for (const payload of malformedPayloads) {
        assert.throws(() => validatePayload(payload));
    }
    assert.throws(
        () => resolveEventTimelineQueryState(null, { kind: "unknown" }),
        RangeError,
    );
});

test("Event Timeline contract remains independent of browser and network APIs", async () => {
    // Given
    const contractUrl = new URL(
        "../../../src/incident_awareness/dashboard/ui/assets/event-timeline-contract.mjs",
        import.meta.url,
    );

    // When
    const source = await readFile(contractUrl, "utf8");

    // Then
    for (const forbiddenApi of [
        "document",
        "window",
        "fetch(",
        "setInterval(",
        "setTimeout(",
        "AbortController",
    ]) {
        assert.equal(source.includes(forbiddenApi), false);
    }
});

// The scenarios below run the real event-timeline.js against a minimal DOM whose focus
// follows browser rules: removed, disabled, or non-focusable elements cannot hold focus.
const TIMELINE_ASSETS_URL = new URL(
    "../../../src/incident_awareness/dashboard/ui/assets/",
    import.meta.url,
);
const TIMELINE_RUN_ID = "RUN-1";
const TIMELINE_ELEMENT_IDS = [
    "event-timeline-view",
    "event-timeline-status",
    "event-timeline-summary",
    "event-timeline-list",
    "event-timeline-pagination",
    "run-detail-back-navigation",
    "event-timeline-type",
    "event-timeline-filter-reset",
    "event-timeline-filter-status",
];
let timelineHarnessCount = 0;

class TimelineElement {
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
        this.dataset = {};
        this.attributes = new Map();
        this.listeners = new Map();
        this.ownText = "";
        this.disabled = false;
        this.href = "";
        this.type = "";
        this.focusCalls = [];
        this.scrollIntoViewCalls = [];
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

    get tabIndex() {
        if (this.attributes.has("tabindex")) {
            return Number(this.attributes.get("tabindex"));
        }
        return this.tagName === "BUTTON" || this.tagName === "A" ? 0 : -1;
    }

    set tabIndex(value) {
        this.attributes.set("tabindex", String(value));
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

    hasAttribute(name) {
        return this.attributes.has(name);
    }

    addEventListener(type, listener) {
        this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
    }

    click() {
        if (this.disabled) {
            return;
        }
        for (const listener of this.listeners.get("click") ?? []) {
            listener({ type: "click", target: this });
        }
    }

    focus(options = {}) {
        const focusable = this.tagName === "BUTTON" || this.tagName === "SELECT"
            ? !this.disabled
            : this.tagName === "A"
                ? this.href !== ""
                : this.attributes.has("tabindex");
        if (!this.isConnected || !focusable) {
            return;
        }
        this.focusCalls.push({ ...options });
        this.ownerDocument.focusedElement = this;
    }

    scrollIntoView(options) {
        this.scrollIntoViewCalls.push({ ...options });
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
        assert.match(selector, /^[a-z]+$/);
        const matches = [];
        const visit = (element) => {
            for (const child of element.childNodes) {
                if (child.tagName === selector.toUpperCase()) {
                    matches.push(child);
                }
                visit(child);
            }
        };
        visit(this);
        return matches;
    }
}

async function startEventTimelineHarness({ blurOnDisable }) {
    const document = {
        focusedElement: null,
        createElement: (tagName) => new TimelineElement(document, tagName),
        getElementById: (id) => document.elements.get(id) ?? null,
        get activeElement() {
            const focused = this.focusedElement;
            if (
                focused === null
                || !focused.isConnected
                || (blurOnDisable && focused.disabled)
            ) {
                return this.body;
            }
            return focused;
        },
    };
    document.body = new TimelineElement(document, "body");
    document.elements = new Map(
        TIMELINE_ELEMENT_IDS.map((id) => [id, new TimelineElement(
            document,
            id === "event-timeline-type" ? "select"
                : id === "event-timeline-filter-reset" ? "button" : "div",
        )]),
    );
    const headerLink = new TimelineElement(document, "a");
    headerLink.href = "/dashboard";
    document.body.append(headerLink, ...document.elements.values());

    const requests = [];
    const fakeGlobals = {
        document,
        window: { location: { pathname: `/dashboard/runs/${TIMELINE_RUN_ID}/timeline` } },
        fetch: (url) => new Promise((resolve) => {
            requests.push({ url: String(url), resolve, settled: false });
        }),
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

    const source = await readFile(new URL("event-timeline.js", TIMELINE_ASSETS_URL), "utf8");
    const moduleSource = source.replaceAll(
        /from "\.\/([^"]+)"/g,
        (_, file) => `from "${new URL(file, TIMELINE_ASSETS_URL).href}"`,
    );
    timelineHarnessCount += 1;
    try {
        await import(
            "data:text/javascript;charset=utf-8,"
            + encodeURIComponent(`${moduleSource}\n// timeline harness ${timelineHarnessCount}\n`)
        );
        await flush();
    } catch (error) {
        restore();
        throw error;
    }

    const element = (id) => document.getElementById(id);
    const pagination = element("event-timeline-pagination");
    return {
        document,
        headerLink,
        restore,
        status: element("event-timeline-status"),
        pendingCount: () => requests.filter((request) => !request.settled).length,
        async respond(offset, status, body) {
            const url = buildEventTimelineApiPath(TIMELINE_RUN_ID, 50, offset);
            const request = requests.find(
                (candidate) => !candidate.settled && candidate.url === url,
            );
            assert.ok(request, `Expected a pending request for ${url}`);
            request.settled = true;
            request.resolve({
                ok: status >= 200 && status < 300,
                status,
                json: async () => body,
            });
            await flush();
        },
        async respondPage(offset, itemCount, total) {
            await this.respond(offset, 200, makePayload({ itemCount, total, offset }));
        },
        // Enter on a focused button activates it; on anything else it does nothing here.
        async pressEnter() {
            const active = document.activeElement;
            if (active.tagName === "BUTTON") {
                active.click();
            }
            await flush();
        },
        button: (label) => pagination.children.find((button) => button.textContent === label),
        buttons: () => pagination.children,
        backLink: () => element("run-detail-back-navigation").children[0],
        range: () => element("event-timeline-summary").children[2]?.children[1].textContent,
        cardCount: () => element("event-timeline-list").children.length,
    };
}

for (const blurOnDisable of [true, false]) {
    const focusModel = blurOnDisable ? "blur on disable" : "focus kept on disabled";

    test(`Event Timeline keeps focus on the activated page control across Enter presses (${focusModel})`, async (t) => {
        // Given
        const harness = await startEventTimelineHarness({ blurOnDisable });
        t.after(harness.restore);
        await harness.respondPage(0, 50, 129);
        const initialFocus = harness.document.activeElement;
        const originalNext = harness.button("다음");
        originalNext.focus();
        const visited = [];
        const recordPage = () => {
            const active = harness.document.activeElement;
            visited.push({
                range: harness.range(),
                cards: harness.cardCount(),
                focused: active.textContent,
                focusedDisabled: active.disabled,
                focusedInPagination: harness.buttons().includes(active),
                preventScroll: active.focusCalls.at(-1)?.preventScroll,
            });
        };

        // When
        await harness.pressEnter();
        const pendingAfterEnter = harness.pendingCount();
        await harness.pressEnter();
        const pendingAfterRepeatedEnter = harness.pendingCount();
        await harness.respondPage(50, 50, 129);
        const restoredNext = harness.document.activeElement;
        recordPage();
        await harness.pressEnter();
        await harness.respondPage(100, 29, 129);
        recordPage();
        await harness.pressEnter();
        await harness.respondPage(50, 50, 129);
        recordPage();
        await harness.pressEnter();
        await harness.respondPage(0, 50, 129);
        recordPage();

        // Then
        assert.strictEqual(initialFocus, harness.document.body);
        assert.equal(pendingAfterEnter, 1);
        assert.equal(pendingAfterRepeatedEnter, 1);
        assert.notStrictEqual(restoredNext, originalNext);
        assert.equal(originalNext.isConnected, false);
        const page = (range, cards, focused) => ({
            range,
            cards,
            focused,
            focusedDisabled: false,
            focusedInPagination: true,
            preventScroll: true,
        });
        assert.deepEqual(visited, [
            page("51–100 / 129", 50, "다음"),
            page("101–129 / 129", 29, "이전"),
            page("51–100 / 129", 50, "이전"),
            page("1–50 / 129", 50, "다음"),
        ]);
        assert.equal(harness.button("이전").disabled, true);
        assert.equal(harness.status.hasAttribute("tabindex"), false);
    });

    test(`Event Timeline moves focus to the status only when no page control remains (${focusModel})`, async (t) => {
        // Given
        const harness = await startEventTimelineHarness({ blurOnDisable });
        t.after(harness.restore);
        await harness.respondPage(0, 50, 129);

        // When: the next page shrank below the requested offset.
        harness.button("다음").focus();
        await harness.pressEnter();
        await harness.respond(50, 200, makePayload({ itemCount: 0, total: 40, offset: 50 }));
        const afterShrunkPage = {
            focused: harness.document.activeElement.textContent,
            nextDisabled: harness.button("다음").disabled,
            range: harness.range(),
        };
        // When: going back finds a single remaining page.
        await harness.pressEnter();
        await harness.respondPage(0, 10, 10);
        const afterSinglePage = {
            focusedStatus: harness.document.activeElement === harness.status,
            tabIndex: harness.status.getAttribute("tabindex"),
            buttonsDisabled: harness.buttons().map((button) => button.disabled),
            range: harness.range(),
        };

        // Then
        assert.deepEqual(afterShrunkPage, { focused: "이전", nextDisabled: true, range: "0–0 / 40" });
        assert.deepEqual(afterSinglePage, {
            focusedStatus: true,
            tabIndex: "-1",
            buttonsDisabled: [true, true],
            range: "1–10 / 10",
        });
        assert.deepEqual(harness.status.focusCalls.at(-1), { preventScroll: true });
        assert.deepEqual(
            harness.status.scrollIntoViewCalls.at(-1),
            { block: "nearest", inline: "nearest" },
        );
    });

    test(`Event Timeline keeps keyboard position on the status after a failed page (${focusModel})`, async (t) => {
        // Given
        const harness = await startEventTimelineHarness({ blurOnDisable });
        t.after(harness.restore);
        await harness.respondPage(0, 50, 129);
        harness.button("다음").focus();

        // When
        await harness.pressEnter();
        await harness.respond(50, 503, { detail: "unavailable" });

        // Then
        assert.equal(harness.status.textContent, "Event Timeline을 불러오지 못했습니다.");
        assert.equal(harness.buttons().length, 0);
        assert.equal(harness.cardCount(), 0);
        assert.strictEqual(harness.document.activeElement, harness.status);
        assert.equal(harness.status.tabIndex, -1);
    });

    test(`Event Timeline leaves focus alone after the user moves during a late page (${focusModel})`, async (t) => {
        // Given
        const harness = await startEventTimelineHarness({ blurOnDisable });
        t.after(harness.restore);
        await harness.respondPage(0, 50, 129);

        // When: the keyboard user moves to the back link while the page is still loading.
        harness.button("다음").focus();
        await harness.pressEnter();
        harness.backLink().focus();
        await harness.respondPage(50, 50, 129);
        const afterMove = harness.document.activeElement;
        const rangeAfterMove = harness.range();
        // When: a pointer activation that never focused the control.
        harness.document.focusedElement = null;
        harness.button("다음").click();
        await harness.respondPage(100, 29, 129);
        const afterUnfocusedClick = harness.document.activeElement;

        // Then
        assert.strictEqual(afterMove, harness.backLink());
        assert.equal(rangeAfterMove, "51–100 / 129");
        assert.strictEqual(afterUnfocusedClick, harness.document.body);
        assert.equal(harness.range(), "101–129 / 129");
        assert.equal(harness.status.hasAttribute("tabindex"), false);
    });
}

test("Event page filter hides cards in place and persists on the next API page without extra requests", async (t) => {
    // Given
    const harness = await startEventTimelineHarness({ blurOnDisable: true });
    t.after(harness.restore);
    const first = makePayload({ itemCount: 50, total: 129 });
    first.items[4].event_type = "network_connection";
    await harness.respond(0, 200, first);
    const element = (id) => harness.document.getElementById(id);
    const filter = element("event-timeline-type");
    const cards = [...element("event-timeline-list").children];

    // When
    filter.focus();
    filter.value = "network_connection";
    for (const listener of filter.listeners.get("change")) listener({ target: filter });

    // Then
    assert.equal(element("event-timeline-list").children.filter((card) => !card.hidden).length, 1);
    assert.deepEqual([...element("event-timeline-list").children], cards);
    assert.equal(harness.pendingCount(), 0);
    assert.strictEqual(harness.document.activeElement, filter);
    assert.match(element("event-timeline-filter-status").textContent, /현재 페이지 50건 중 1건/);
    assert.equal(harness.range(), "1–50 / 129");

    // When: filter does not change offset/limit or prevent moving to an unmatched page.
    harness.button("다음").focus();
    await harness.pressEnter();
    assert.equal(filter.disabled, true);
    await harness.respondPage(50, 50, 129);

    // Then
    assert.equal(filter.value, "network_connection");
    assert.equal(element("event-timeline-list").children.filter((card) => !card.hidden).length, 0);
    assert.match(element("event-timeline-filter-status").textContent, /현재 페이지에서.*없습니다.*0 \/ 50/);
    assert.equal(harness.range(), "51–100 / 129");
    assert.equal(harness.document.activeElement, harness.button("다음"));
    assert.equal(filter.disabled, false);
    assert.ok(filter.children.some((option) => option.value === "network_connection"));
    const reset = element("event-timeline-filter-reset");
    reset.focus();
    reset.click();
    assert.equal(filter.value, "all");
    assert.equal(element("event-timeline-list").children.filter((card) => !card.hidden).length, 50);
    assert.equal(harness.document.activeElement, reset);
    assert.equal(harness.pendingCount(), 0);
});

test("Event filtering distinguishes empty page, failed query and a local zero result", async (t) => {
    // Given
    const harness = await startEventTimelineHarness({ blurOnDisable: true });
    t.after(harness.restore);

    // When
    await harness.respondPage(0, 0, 0);
    const filterStatus = harness.document.getElementById("event-timeline-filter-status");

    // Then
    assert.equal(harness.status.textContent, "이 분석에 저장된 Event가 없습니다.");
    assert.equal(filterStatus.textContent, "현재 페이지에 표시할 Event가 없습니다.");
    assert.equal(harness.range(), "0–0 / 0");
});

test("Event query failure keeps page filters disabled and does not announce a local no-match", async (t) => {
    // Given
    const harness = await startEventTimelineHarness({ blurOnDisable: true });
    t.after(harness.restore);
    const element = (id) => harness.document.getElementById(id);
    assert.equal(element("event-timeline-list").getAttribute("aria-busy"), "true");

    // When
    await harness.respond(0, 503, { detail: "unavailable" });

    // Then
    assert.equal(element("event-timeline-type").disabled, true);
    assert.equal(element("event-timeline-filter-reset").disabled, true);
    assert.equal(element("event-timeline-list").getAttribute("aria-busy"), "false");
    assert.match(element("event-timeline-filter-status").textContent, /조회하지 못해/);
    assert.doesNotMatch(element("event-timeline-filter-status").textContent, /0건|유형.*없습니다/);
    assert.equal(harness.cardCount(), 0);
});
