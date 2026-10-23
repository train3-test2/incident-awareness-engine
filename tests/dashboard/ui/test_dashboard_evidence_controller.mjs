// Evidence tab controller tests. Run with: node --test tests/dashboard/ui/test_dashboard_evidence_controller.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createDashboardEvidenceController } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-evidence-controller.mjs";
import { EVIDENCE_MESSAGES } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-evidence-contract.mjs";
import { RUN_ID, evidenceItem, evidencePayload } from "./evidence-fixture.mjs";

class Element {
    constructor(doc, tagName) {
        this.doc = doc;
        this.tagName = tagName.toUpperCase();
        this.childNodes = [];
        this.parentNode = null;
        this.classNames = new Set();
        this.classList = { add: (...n) => n.forEach((x) => this.classNames.add(x)), contains: (n) => this.classNames.has(n) };
        this.dataset = {};
        this.attributes = new Map();
        this.ownText = "";
        this.textWrites = 0;
        this.hidden = false;
        this.href = "";
        this.title = "";
        this.focusCalls = [];
        this.listeners = new Map();
    }

    addEventListener(type, listener) { this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]); }

    click() { for (const listener of this.listeners.get("click") ?? []) listener({ type: "click", target: this }); }

    get textContent() { return this.ownText + this.childNodes.map((c) => c.textContent).join(""); }

    set textContent(value) { this.textWrites += 1; this.replaceChildren(); this.ownText = String(value); }

    get children() { return this.childNodes; }

    append(...nodes) { for (const n of nodes) { n.parentNode = this; this.childNodes.push(n); } }

    replaceChildren(...nodes) { for (const c of this.childNodes) c.parentNode = null; this.childNodes = []; this.ownText = ""; this.append(...nodes); }

    setAttribute(name, value) { this.attributes.set(name, String(value)); }

    getAttribute(name) { return this.attributes.get(name) ?? null; }

    focus(options = {}) { this.focusCalls.push(options); this.doc.activeElement = this; }

    contains(node) { for (let n = node; n; n = n.parentNode) if (n === this) return true; return false; }

    querySelectorAll(selector) {
        assert.match(selector, /^\.[\w-]+$/);
        const found = [];
        const visit = (e) => { for (const c of e.childNodes) { if (c.classList.contains(selector.slice(1))) found.push(c); visit(c); } };
        visit(this);
        return found;
    }

    find(predicate) {
        const all = [];
        const visit = (e) => { for (const c of e.childNodes) { all.push(c); visit(c); } };
        visit(this);
        return all.filter(predicate);
    }
}

const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
const ok = (payload = evidencePayload()) => ({ ok: true, status: 200, json: async () => payload });
const fail = (status, detail) => ({ ok: false, status, json: async () => ({ detail }) });

function harness(fetchImpl = async () => ok()) {
    const doc = { activeElement: null, createElement: (tag) => new Element(doc, tag) };
    const nodes = new Map(["status", "archive", "region", "list", "archive-state"].map((key) => [`evidence-${key}`, new Element(doc, "div")]));
    doc.getElementById = (id) => nodes.get(id) ?? null;
    const calls = [];
    const timers = new Map();
    let timer = 0;
    const controller = createDashboardEvidenceController(doc, {
        fetchImpl: (...args) => { calls.push(args); return fetchImpl(...args); },
        setTimeoutImpl: (fn) => { timers.set(++timer, fn); return timer; },
        clearTimeoutImpl: (id) => timers.delete(id),
    });
    const node = (key) => nodes.get(`evidence-${key}`);
    return { controller, calls, timers, doc, node, rows: () => node("list").children };
}

test("Evidence is read only once the tab is shown, once per Run", async () => {
    // Given
    const h = harness();
    // When
    await h.controller.select(RUN_ID);
    const beforeActivation = h.calls.length;
    await h.controller.setActive(true);
    await h.controller.select(RUN_ID); // e.g. another Entity of the same Run
    await h.controller.setActive(false);
    await h.controller.setActive(true);
    // Then
    assert.equal(beforeActivation, 0);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0][0], `/runs/${RUN_ID}/evidences?limit=100`);
    assert.equal(h.calls[0][1].cache, "no-store");
    assert.equal(h.rows().length, 2);
    assert.equal(h.node("region").hidden, false);
    assert.match(h.node("status").textContent, /^증거 조회 완료 · 검증된 2건/);
    assert.match(h.node("archive").textContent, /^R1 아카이브 · Extractor r1-v0\.1 · SHA-256 /);
    assert.equal(h.timers.size, 0);
});

test("Rows show the contract fields and link only Events stored for the Run", async () => {
    // Given
    const h = harness();
    // When
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    // Then
    const [lineage, network] = h.rows();
    const cells = lineage.children.map((c) => c.textContent);
    // Task 6: the row leads with the KST time and the observation; identifiers move to the detail row.
    assert.deepEqual(cells, ["2026.10.09 02:10:30.538000 KST", "원격 세션 프로세스 계보 이탈", "PAIR004-DERIVED-HOST",
        "원시 TelemetryFusion feature", "evt-anchorevt-middleevt-terminal · 저장 Event 없음", "상세"]);
    assert.equal(lineage.children[0].children[0].getAttribute("datetime"), "2026-10-08T17:10:30.538000Z");
    assert.equal(lineage.children[0].children[0].title, "UTC 2026-10-08T17:10:30.538000Z");
    assert.equal(cells.some((value) => value.includes("evidence-lineage")), false);
    const links = h.node("list").querySelectorAll(".dashboard-evidence-event-link");
    assert.deepEqual(links.map((l) => l.href), [
        `/dashboard/runs/${RUN_ID}/events/evt-anchor`,
        `/dashboard/runs/${RUN_ID}/events/evt-middle`,
        `/dashboard/runs/${RUN_ID}/events/evt-network`,
    ]);
    assert.equal(links[0].getAttribute("aria-label"), "Event evt-anchor 상세");
    assert.equal(network.find((e) => e.tagName === "A" && e.textContent === "evt-terminal").length, 0);
});

test("Completion invalidation rejects a late pre-commit response for the same Run", async () => {
    // Given
    const held = deferred(); let index = 0;
    const h = harness(() => ++index === 1 ? held.promise : Promise.resolve(ok()));
    await h.controller.setActive(true);
    const first = h.controller.select(RUN_ID);
    await Promise.resolve();
    // When
    await h.controller.refresh({ invalidatePending: true });
    held.resolve(fail(404, "Run not found")); await first;
    // Then
    assert.equal(h.calls.length, 2);
    assert.equal(h.calls[0][1].signal.aborted, true);
    assert.equal(h.rows().length, 2);
    assert.match(h.node("status").textContent, /^증거 조회 완료/);
});

test("Changing Run clears the previous Evidence at once and drops its late response", async () => {
    // Given
    const held = deferred();
    let index = 0;
    const h = harness(() => (++index === 1 ? held.promise : Promise.resolve(ok(evidencePayload({ runId: "RUN-20261008-918" })))));
    await h.controller.setActive(true);
    const first = h.controller.select(RUN_ID);
    await Promise.resolve();
    // When
    const second = h.controller.select("RUN-20261008-918");
    const clearedImmediately = h.rows().length;
    await second;
    held.resolve(ok());
    await first;
    // Then
    assert.equal(clearedImmediately, 0);
    assert.equal(h.calls[0][1].signal.aborted, true);
    assert.equal(h.calls.length, 2);
    assert.ok(h.node("list").querySelectorAll(".dashboard-evidence-event-link").every((l) => l.href.includes("RUN-20261008-918")));
});

test("A response for another Run is rejected instead of rendered", async () => {
    // Given
    const h = harness(async () => ok(evidencePayload({ runId: "RUN-OTHER" })));
    // When
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    // Then
    assert.equal(h.node("status").textContent, EVIDENCE_MESSAGES.invalid);
    assert.equal(h.rows().length, 0);
    assert.equal(h.node("region").hidden, true);
});

test("Repeated explicit refresh during one read coalesces without aborting its request", async () => {
    // Given
    const held = deferred();
    const h = harness(() => held.promise);
    await h.controller.select(RUN_ID);
    const first = h.controller.setActive(true);
    await Promise.resolve();
    // When
    const second = h.controller.refresh();
    const third = h.controller.refresh();
    held.resolve(ok());
    await Promise.all([first, second, third]);
    // Then
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0][1].signal.aborted, false);
    assert.equal(h.rows().length, 2);
});

test("A malformed success response clears old rows and reports validation failure, then recovers", async () => {
    // Given
    let malformed = false;
    const h = harness(async () => ok(malformed ? { schema_version: "wrong" } : evidencePayload()));
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    // When
    malformed = true;
    await h.controller.refresh();
    // Then
    assert.equal(h.node("status").textContent, EVIDENCE_MESSAGES.invalid);
    assert.equal(h.rows().length, 0);
    assert.equal(h.node("archive").hidden, true);
    malformed = false;
    await h.controller.refresh();
    assert.equal(h.rows().length, 2);
});

test("Network TypeError remains an API failure rather than an archive integrity claim", async () => {
    // Given
    const h = harness(async () => { throw new TypeError("Synthetic connection failure"); });
    await h.controller.select(RUN_ID);
    // When
    await h.controller.setActive(true);
    // Then
    assert.equal(h.node("status").textContent, EVIDENCE_MESSAGES.error);
    assert.equal(h.rows().length, 0);
});

for (const [status, detail, message] of [
    [404, "Not Found", EVIDENCE_MESSAGES.notReady],
    [503, "Evidence archive storage is not provisioned", EVIDENCE_MESSAGES.notReady],
    [500, "Stored Evidence archive is invalid", EVIDENCE_MESSAGES.invalid],
    [500, "Stored Evidence provenance is inconsistent", EVIDENCE_MESSAGES.invalid],
    [503, "Evidence database is unavailable", EVIDENCE_MESSAGES.error],
    [404, "Run not found", EVIDENCE_MESSAGES.runMissing],
]) {
    test(`HTTP ${status} "${detail}" shows its state, clears rows, and recovers on refresh`, async () => {
        // Given
        let failing = false;
        const h = harness(async () => (failing ? fail(status, detail) : ok()));
        await h.controller.select(RUN_ID);
        await h.controller.setActive(true);
        failing = true;
        // When
        await h.controller.refresh();
        const failed = { status: h.node("status").textContent, rows: h.rows().length, archive: h.node("archive").hidden };
        failing = false;
        await h.controller.refresh();
        // Then
        assert.deepEqual(failed, { status: message, rows: 0, archive: true });
        assert.equal(h.rows().length, 2);
    });
}

for (const [label, payload, message] of [
    ["no archive", evidencePayload({ availability: "no_archive" }), EVIDENCE_MESSAGES.noArchive],
    ["zero Evidence", evidencePayload({ items: [], total: 0, unstored: 0 }), EVIDENCE_MESSAGES.empty],
]) {
    test(`${label} shows its own state without a table`, async () => {
        // Given
        const h = harness(async () => ok(payload));
        // When
        await h.controller.select(RUN_ID);
        await h.controller.setActive(true);
        // Then
        assert.equal(h.node("status").textContent, message);
        assert.equal(h.node("region").hidden, true);
    });
}

test("Stored text is rendered as text, never as markup", async () => {
    // Given
    const hostile = "<img src=x onerror=alert(1)>";
    const payload = evidencePayload({ items: [evidenceItem({ evidence_id: hostile, entity_id: hostile,
        events: [{ event_id: hostile, stored: true }] })] });
    const h = harness(async () => ok(payload));
    // When
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    // Then
    const [row] = h.rows();
    assert.equal(row.children[2].textContent, hostile);
    row.find((e) => e.classList.contains("dashboard-evidence-expand"))[0].click();
    const [, detail] = h.rows();
    assert.match(detail.textContent, /<img src=x onerror=alert\(1\)>/);
    for (const element of [h.rows()[0], detail]) assert.equal(element.find((e) => e.tagName === "IMG").length, 0);
    assert.equal(h.rows()[0].find((e) => e.tagName === "A")[0].href, `/dashboard/runs/${RUN_ID}/events/${encodeURIComponent(hostile)}`);
    const source = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/assets/dashboard-evidence-controller.mjs", import.meta.url), "utf8");
    for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "setInterval("]) assert.equal(source.includes(forbidden), false);
});

test("Refreshing the same Run keeps keyboard focus on the same Event link", async () => {
    // Given
    const h = harness();
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    const [first] = h.node("list").querySelectorAll(".dashboard-evidence-event-link");
    first.focus();
    // When
    await h.controller.refresh();
    // Then
    const [replacement] = h.node("list").querySelectorAll(".dashboard-evidence-event-link");
    assert.notStrictEqual(replacement, first);
    assert.strictEqual(h.doc.activeElement, replacement);
    assert.deepEqual(replacement.focusCalls, [{ preventScroll: true }]);
});

test("A refresh never pulls focus back after the user moved during the read", async () => {
    // Given
    const held = deferred();
    let index = 0;
    const h = harness(() => (++index === 1 ? Promise.resolve(ok()) : held.promise));
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    h.node("list").querySelectorAll(".dashboard-evidence-event-link")[0].focus();
    const elsewhere = h.doc.createElement("button");
    // When
    const task = h.controller.refresh();
    elsewhere.focus();
    held.resolve(ok());
    await task;
    // Then
    assert.strictEqual(h.doc.activeElement, elsewhere);
    assert.equal(h.rows().length, 2);
});

test("Unchanged status is not rewritten for the live region", async () => {
    // Given
    const h = harness(async () => ok(evidencePayload({ availability: "no_archive" })));
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    const writes = h.node("status").textWrites;
    // When
    await h.controller.setActive(false);
    await h.controller.setActive(true);
    // Then
    assert.equal(h.node("status").textWrites, writes);
});

test("A timed-out read aborts, reports an error, and ignores its late completion", async () => {
    // Given
    const held = deferred();
    const h = harness(() => held.promise);
    await h.controller.select(RUN_ID);
    const task = h.controller.setActive(true);
    await Promise.resolve();
    // When
    [...h.timers.values()][0]();
    await task;
    held.resolve(ok());
    await Promise.resolve();
    // Then
    assert.equal(h.node("status").textContent, EVIDENCE_MESSAGES.error);
    assert.equal(h.calls[0][1].signal.aborted, true);
    assert.equal(h.rows().length, 0);
});

test("Leaving the page invalidates a pending read; returning re-reads the shown Run", async () => {
    // Given
    const held = deferred();
    let index = 0;
    const h = harness(() => (++index === 1 ? held.promise : Promise.resolve(ok())));
    await h.controller.select(RUN_ID);
    const task = h.controller.setActive(true);
    await Promise.resolve();
    // When
    h.controller.stop();
    held.resolve(ok());
    await task;
    const afterStop = h.rows().length;
    await h.controller.start();
    // Then
    assert.equal(afterStop, 0);
    assert.equal(h.calls.length, 2);
    assert.equal(h.rows().length, 2);
});

const expandButton = (row) => row.find((e) => e.classList.contains("dashboard-evidence-expand"))[0];

test("Task 6 detail row keeps every stored identifier and mapping, shown only on request", async () => {
    // Given
    const h = harness();
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    const toggle = expandButton(h.rows()[0]);
    // When
    toggle.click();
    // Then
    assert.equal(h.rows().length, 3);
    const detail = h.rows()[1].textContent;
    for (const expected of ["evidence-lineage", "remote_session_process_lineage_deviation",
        "r1-remote-management-approved-lineage · v0.3", "b".repeat(64), "저장된 매핑 없음", "비공개 필드0개",
        "r1-v0.1", "UTC 2026-10-08T17:10:30.538000Z", "Fusion 입력 아님"]) assert.ok(detail.includes(expected), expected);
    const reopened = expandButton(h.rows()[0]);
    assert.equal(reopened.getAttribute("aria-expanded"), "true");
    assert.equal(reopened.getAttribute("aria-label"), "원격 세션 프로세스 계보 이탈 · 2026.10.09 02:10:30.538000 KST 상세 접기");
    assert.strictEqual(h.doc.activeElement, reopened, "The re-rendered toggle keeps keyboard focus");
    reopened.click();
    assert.equal(h.rows().length, 2);
    assert.equal(h.calls.length, 1, "Expanding a row never re-reads the archive");
});

test("Task 6 expansion and its toggle focus survive a same-Run refresh and reset on Run change", async () => {
    // Given
    const h = harness(async (url) => ok(evidencePayload({ runId: url.includes("918") ? "RUN-20261008-918" : RUN_ID })));
    await h.controller.select(RUN_ID);
    await h.controller.setActive(true);
    expandButton(h.rows()[0]).click();
    expandButton(h.rows()[0]).focus();
    // When
    await h.controller.refresh();
    // Then
    assert.equal(h.rows().length, 3);
    assert.strictEqual(h.doc.activeElement, expandButton(h.rows()[0]));
    assert.equal(h.doc.activeElement.dataset.rowKey, "evidence-lineage");
    await h.controller.select("RUN-20261008-918");
    assert.equal(h.rows().length, 2);
    assert.ok(h.rows().every((row) => row.classList.contains("dashboard-evidence-row")));
});

for (const [label, fetchImpl, expected] of [
    ["published", async () => ok(), "게시됨 · 검증된 증거 2건"],
    ["no archive", async () => ok(evidencePayload({ availability: "no_archive" })), "게시 아카이브 없음 · 원본 보관과 별개"],
    ["pending", async () => ok(evidencePayload({ availability: "not_published", archiveStatus: "pending" })), "게시 전"],
    ["unprovisioned", async () => fail(503, "Evidence archive storage is not provisioned"), "조회 기능 미준비"],
    ["network failure", async () => { throw new TypeError("offline"); }, "조회 실패"],
]) {
    test(`Task 6 archive overview names the ${label} state apart from raw retention`, async () => {
        // Given
        const h = harness(fetchImpl);
        // When
        await h.controller.select(RUN_ID);
        const beforeActivation = h.node("archive-state").textContent;
        await h.controller.setActive(true);
        // Then
        assert.equal(beforeActivation, "조회 중");
        assert.equal(h.node("archive-state").textContent, expected);
        assert.doesNotMatch(h.node("archive-state").textContent, /원본 없음|원본 전체/);
    });
}

test("Without the Evidence DOM (e.g. Preview) the controller is inert", async () => {
    // Given
    let calls = 0;
    const controller = createDashboardEvidenceController({ getElementById: () => null }, { fetchImpl: () => { calls += 1; } });
    // When
    controller.select(RUN_ID);
    controller.setActive(true);
    controller.refresh();
    // Then
    assert.equal(calls, 0);
});
