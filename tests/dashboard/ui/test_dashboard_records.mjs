// 기록 tab records (Task 6). 분석 with: node --test tests/dashboard/ui/test_dashboard_records.mjs
import assert from "node:assert/strict";
import test from "node:test";

import { createDecisionRecord, createWorkflowRecord, decisionRecordFields, workflowAuditEntries }
    from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-records.mjs";
import { workflowTimeLabel } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-operator-contract.mjs";

class Element {
    constructor(tagName) {
        this.tagName = tagName.toUpperCase();
        this.childNodes = [];
        this.classNames = new Set();
        this.classList = { add: (...names) => names.forEach((name) => this.classNames.add(name)),
            contains: (name) => this.classNames.has(name) };
        this.attributes = new Map();
        this.dataset = {};
        this.ownText = "";
        this.title = "";
    }

    get textContent() { return this.ownText + this.childNodes.map((child) => child.textContent).join(""); }

    set textContent(value) { this.childNodes = []; this.ownText = String(value); }

    append(...nodes) { this.childNodes.push(...nodes); }

    setAttribute(name, value) { this.attributes.set(name, String(value)); }

    getAttribute(name) { return this.attributes.get(name) ?? null; }

    addEventListener() {}

    all() { return this.childNodes.flatMap((child) => [child, ...child.all()]); }
}

const doc = { createElement: (tag) => new Element(tag) };
const fields = (decision) => Object.fromEntries(decisionRecordFields(decision));
const decision = (overrides = {}) => ({ run_id: "RUN-20261021-901", entity_id: "WIN-01", decision_id: "DEC-A",
    fast_status: "not_evaluated", fusion_status: "detected", detector_time: null, fusion_time: "2026-10-03T00:00:20.000Z",
    t_e: null, decision_path: null, winning_path: null, config_version: "parallel-v0.2",
    decision_reason: "Required parallel evaluation was not completed", supersedes_decision_id: null, ...overrides });
const state = (overrides = {}) => ({ version: 0, analyst_ack_time: null, evidence_reviewed_at: null, t_h: null,
    t_h_recorded_at: null, report_choice: null, report_decided_at: null, report_reason: null, ...overrides });
function entry(version, action, before, after, command = {}) {
    return { action_id: `act-${version}`, alert_id: "ALERT-A", version, idempotency_key: `key-${version}`,
        actor_id: "local-demo-analyst", actor_kind: "unauthenticated_local_demo", action,
        recorded_at: `2026-10-21T0${version}:00:00.000Z`, command: { action, expected_version: version - 1, ...command },
        previous_state: before, resulting_state: after };
}
// Acknowledge, review, a past awareness time entered by hand, then a hold decision.
const acknowledged = state({ version: 1, analyst_ack_time: "2026-10-21T01:00:00.000Z" });
const reviewed = { ...acknowledged, version: 2, evidence_reviewed_at: "2026-10-21T02:00:00.000Z" };
const aware = { ...reviewed, version: 3, t_h: "2026-10-20T15:30:00.000Z", t_h_recorded_at: "2026-10-21T03:00:00.000Z" };
const held = { ...aware, version: 4, report_choice: "hold", report_decided_at: "2026-10-21T04:00:00.000Z", report_reason: "추가 확인 필요" };
const alert = (audit) => ({ alert_id: "ALERT-A", run_id: "RUN-20261021-901", entity_id: "WIN-01", detection_kind: "fusion",
    issued_at: "2026-10-21T00:30:00.000Z", state: held, audit });
const history = [entry(1, "acknowledge", state(), acknowledged), entry(2, "review_evidence", acknowledged, reviewed),
    entry(3, "record_awareness", reviewed, aware, { t_h: "2026-10-21T00:30:00+09:00", reason: "보고 메일 확인 시각" }),
    entry(4, "decide_reporting", aware, held, { report_choice: "hold", reason: "추가 확인 필요" })];

test("Task 6 a stored incomplete Decision reads as stored, with undetermined time and path", () => {
    // Given / When
    const record = fields(decision({ supersedes_decision_id: "DEC-OLD" }));
    // Then
    assert.equal(record["종합 판단"], "종합 판단 미완료 · 즉시 규칙 분석 미평가");
    assert.equal(record["판단 사유"], "필수 병렬 평가 미완료");
    assert.equal(record["탐지 시각"], "증거 누적 분석 · 2026.10.03 09:00:20 KST");
    assert.equal(record["종합 판단 시각"], "미확정 · 저장값 없음 (t_e null)");
    assert.equal(record["종합 판단 경로"], "미확정 · 저장값 없음");
    assert.equal(record["이전 결정 연결"], "DEC-OLD를 대체한 결정");
    assert.equal(record["설정·정책 버전"], "config parallel-v0.2");
    assert.equal(record["판단 사유 원문"], "Required parallel evaluation was not completed");
    assert.equal(Object.keys(record).some((label) => /저장 ?시각|기록 ?시각|발행/.test(label)), false);
});

test("Task 6 completed miss and completed detection keep their own stored time and path", () => {
    // Given
    const miss = decision({ fast_status: "miss", fusion_status: "miss", fusion_time: null, decision_path: "none",
        winning_path: "none", decision_reason: "Both evaluated paths missed" });
    const detected = decision({ fast_status: "detected", detector_time: "2026-10-03T00:00:10.000Z",
        t_e: "2026-10-03T00:00:10.000Z", decision_path: "fast_and_fusion", winning_path: "fast",
        decision_reason: "Both paths detected; compared canonical UTC millisecond timestamps",
        rule_version: "fast-r1", detector_set_version: "set-2" });
    // When / Then
    assert.equal(fields(miss)["종합 판단 시각"], "없음 · 탐지 기준 미충족 · 저장값 없음 (t_e null)");
    assert.equal(fields(miss)["종합 판단 경로"], "확정 · 탐지 경로 없음");
    assert.equal(fields(detected)["종합 판단 시각"], "확정 · 2026.10.03 09:00:10 KST");
    assert.equal(fields(detected)["종합 판단 경로"], "확정 · 즉시 규칙·증거 누적 분석");
    assert.equal(fields(detected)["설정·정책 버전"], "config parallel-v0.2 · rule fast-r1 · detector_set set-2");
});

test("Task 6 the current Decision is open while superseded Decisions stay complete but collapsed", () => {
    // Given / When
    const current = createDecisionRecord(doc, decision({ decision_id: "DEC-NEW", supersedes_decision_id: "DEC-OLD" }), 0);
    const older = createDecisionRecord(doc, decision({ decision_id: "DEC-OLD" }), 1);
    // Then
    assert.ok(current.classList.contains("dashboard-decision-record--current"));
    assert.match(current.childNodes[0].textContent, /^현재 결정종합 판단 미완료/);
    assert.equal(current.childNodes[1].tagName, "P");
    assert.match(current.childNodes[1].textContent, /판단 사유필수 병렬 평가 미완료/);
    assert.equal(current.childNodes[2].tagName, "DL");
    assert.match(older.childNodes[0].textContent, /^이전 결정 1종합 판단 미완료/);
    assert.equal(older.childNodes[1].tagName, "DETAILS");
    assert.match(older.textContent, /이 결정의 판단 필드 보기/);
    assert.match(older.textContent, /"decision_id": "DEC-OLD"/);
    const code = current.all().find((node) => node.tagName === "CODE");
    assert.equal(code.textContent, "DEC-NEW");
});

test("Task 6 audit rows list newest version first with actor, recorded time, before/after values and reason", () => {
    // Given / When
    const rows = workflowAuditEntries(alert(history));
    // Then
    assert.deepEqual(rows.map((row) => [row.version, row.action]), [
        [4, "신고 진행 결정"], [3, "인지시각 기록"], [2, "근거 검토"], [1, "담당자 확인"]]);
    assert.ok(rows.every((row) => row.actor === "local-demo-analyst · 로컬 실험 담당자 · 인증 계정 아님"));
    assert.equal(rows[0].recordedAt, "2026-10-21T04:00:00.000Z");
    assert.deepEqual(rows[0].changes, [
        { label: "신고 진행 결정", before: "미기록", after: "판단 보류" },
        { label: "결정 기록시각", before: "미기록", after: workflowTimeLabel("2026-10-21T04:00:00.000Z", true) },
        { label: "결정 사유", before: "미기록", after: "추가 확인 필요" }]);
    assert.equal(rows[0].reason, "추가 확인 필요");
    // The awareness time and its system recording time are two different stored values,
    // and operators never see the internal field name.
    assert.ok(rows.every((row) => row.changes.every((change) => !/(^|[^A-Za-z_])t_h([^A-Za-z_]|$)/.test(change.label))));
    const awareness = Object.fromEntries(rows[1].changes.map((change) => [change.label, change.after]));
    assert.equal(awareness["내부 인지시각"], workflowTimeLabel("2026-10-20T15:30:00.000Z", true));
    assert.equal(awareness["내부 인지시각 시스템 기록시각"], workflowTimeLabel("2026-10-21T03:00:00.000Z", true));
    assert.notEqual(awareness["내부 인지시각"], awareness["내부 인지시각 시스템 기록시각"]);
    assert.match(awareness["내부 인지시각"], /KST$/);
    assert.equal(rows[1].mode, "담당자가 직접 입력한 시각");
    assert.equal(rows[1].reason, "보고 메일 확인 시각");
    assert.equal(rows[3].mode, null);
});

test("Task 6 a later awareness record is a correction and a now-record names the server time", () => {
    // Given
    const corrected = { ...held, version: 5, t_h: "2026-10-20T16:00:00.000Z", t_h_recorded_at: "2026-10-21T05:00:00.000Z" };
    const nowRecord = entry(3, "record_awareness", reviewed, aware, { awareness_mode: "now", reason: "현재 인지" });
    // When
    const rows = workflowAuditEntries(alert([...history, entry(5, "record_awareness", held, corrected, { t_h: "x", reason: "정정 사유" })]));
    const now = workflowAuditEntries(alert([nowRecord]))[0];
    // Then
    assert.equal(rows[0].action, "인지시각 정정");
    assert.equal(rows[0].reason, "정정 사유");
    assert.deepEqual(rows[0].changes.map((change) => change.label), ["내부 인지시각", "내부 인지시각 시스템 기록시각"]);
    assert.equal(now.action, "인지시각 기록");
    assert.equal(now.mode, "현재 시각으로 기록 (서버 수신 시각)");
});

test("Task 6 proceed, do-not-proceed and an unknown stored action are each named", () => {
    // Given
    const proceed = { ...aware, version: 4, report_choice: "proceed", report_decided_at: "2026-10-21T04:00:00.000Z", report_reason: "신고" };
    const decline = { ...aware, version: 4, report_choice: "do_not_proceed", report_decided_at: "2026-10-21T04:00:00.000Z", report_reason: "오탐" };
    // When
    const [first] = workflowAuditEntries(alert([entry(4, "decide_reporting", aware, proceed)]));
    const [second] = workflowAuditEntries(alert([entry(4, "decide_reporting", aware, decline)]));
    const [third] = workflowAuditEntries(alert([entry(4, "future_action", aware, aware)]));
    // Then
    assert.equal(first.changes[0].after, "신고 진행");
    assert.equal(second.changes[0].after, "진행하지 않음");
    assert.equal(third.action, "확인 필요 (future_action)");
    assert.deepEqual(third.changes, []);
});

test("Task 6 a missing audit and an empty audit stay different facts", () => {
    // Given / When
    const missing = createWorkflowRecord(doc, { ...alert(undefined), audit: undefined });
    const empty = createWorkflowRecord(doc, alert([]));
    // Then
    assert.equal(workflowAuditEntries({}), null);
    assert.deepEqual(workflowAuditEntries(alert([])), []);
    assert.match(missing.textContent, /감사 기록이 없어 표시하지 않습니다/);
    assert.match(empty.textContent, /담당자 처리 기록 없음 · 알림만 발행됨/);
    assert.match(empty.textContent, /^증거 누적 분석 탐지 알림 · 대상 WIN-01/);
});

test("Task 6 stored audit text is rendered as text with its raw record kept on request", () => {
    // Given
    const hostile = "<img src=x onerror=alert(1)>";
    const value = alert([entry(4, "decide_reporting", aware, { ...held, report_reason: hostile }, { report_choice: "hold", reason: hostile })]);
    // When
    const closed = createWorkflowRecord(doc, value);
    const rendered = createWorkflowRecord(doc, value, { expanded: new Set(["act-4"]) });
    // Then
    assert.doesNotMatch(closed.textContent, /원본 기록|"idempotency_key"/, "Raw record and reason stay in the row detail");
    assert.ok(rendered.textContent.includes(`사유${hostile}`));
    assert.equal(rendered.all().some((node) => node.tagName === "IMG"), false);
    assert.match(rendered.textContent, /원본 기록/);
    assert.match(rendered.textContent, /"idempotency_key": "key-4"/);
    const time = rendered.all().find((node) => node.tagName === "TIME");
    assert.equal(time.getAttribute("datetime"), "2026-10-21T04:00:00.000Z");
    assert.match(time.title, /UTC 2026-10-21T04:00:00\.000Z/);
});

// Review: one table per alert, newest version first, one row per stored action.
const rows = (record) => record.all().filter((node) => node.classList.contains("dashboard-audit-row"));
const cellsOf = (row) => row.childNodes.map((cell) => cell.textContent);

test("Review audit rows lead with time, action, actor and changed values", () => {
    // Given / When
    const record = createWorkflowRecord(doc, alert(history));
    // Then
    assert.deepEqual(record.all().filter((node) => node.tagName === "TH").map((node) => node.textContent),
        ["기록시각 (KST)", "행위", "행위자", "변경 내용", "상세"]);
    assert.equal(rows(record).length, 4);
    const [latest, awareness] = rows(record).map(cellsOf);
    assert.equal(latest[0], `${workflowTimeLabel("2026-10-21T04:00:00.000Z", true)}기록 버전 v4`);
    assert.equal(latest[1], "신고 진행 결정");
    assert.equal(latest[2], "로컬 담당자로컬 실험 담당자 · 인증 계정 아님");
    assert.match(latest[3], /신고 진행 결정: 미기록 → 판단 보류/);
    assert.equal(latest[4], "상세");
    assert.equal(awareness[1], "인지시각 기록담당자가 직접 입력한 시각");
    assert.match(record.childNodes[0].textContent, /기록 4건 · 최신 기록부터/);
});

test("Review an expanded audit row adds one detail row with reason, input mode and request identity", () => {
    // Given
    const toggled = [];
    const buttons = new Map();
    // When
    const record = createWorkflowRecord(doc, alert(history), { expanded: new Set(["act-3"]), onToggle: (key) => toggled.push(key), buttons });
    // Then
    const body = record.all().find((node) => node.tagName === "TBODY");
    assert.equal(body.childNodes.length, 5);
    const detail = body.childNodes[2];
    assert.ok(detail.classList.contains("dashboard-evidence-detail-row"));
    assert.match(detail.textContent, /사유보고 메일 확인 시각/);
    assert.match(detail.textContent, /인지시각 입력 방식담당자가 직접 입력한 시각/);
    assert.match(detail.textContent, /기록 버전 · 요청 식별v3 · key-3/);
    assert.equal(buttons.get("act-3").getAttribute("aria-expanded"), "true");
    assert.equal(buttons.get("act-4").getAttribute("aria-expanded"), "false");
    assert.deepEqual([...buttons.keys()], ["act-4", "act-3", "act-2", "act-1"]);
});

test("Review one stored action renders a one-row table and no record is invented", () => {
    // Given / When
    const record = createWorkflowRecord(doc, alert([history[0]]));
    // Then
    assert.equal(rows(record).length, 1);
    assert.match(record.childNodes[0].textContent, /기록 1건 · 최신 기록부터/);
    assert.equal(record.all().filter((node) => node.tagName === "TR").length, 2, "header row and one action row");
});

test("Task 7-R prioritizes judgment and reason while keeping identity, versions and raw values accessible", () => {
    // Given / When
    const value = decision({ decision_id: "DEC-READ", supersedes_decision_id: "DEC-PREV" });
    const node = createDecisionRecord(doc, value, 0);
    // Then: technical identity is outside the primary judgment heading, not discarded.
    assert.doesNotMatch(node.childNodes[0].textContent, /DEC-READ|parallel-v0.2/);
    assert.match(node.childNodes[1].textContent, /필수 병렬 평가 미완료/);
    const primary = node.childNodes[2].textContent;
    assert.ok(primary.indexOf("즉시 규칙 분석") < primary.indexOf("탐지 시각"));
    assert.match(primary, /종합 판단 시각미확정/);
    assert.doesNotMatch(primary, /t_e/);
    const technical = node.childNodes[3];
    assert.equal(technical.tagName, "DETAILS");
    assert.match(technical.textContent, /DEC-READ|DEC-PREV/);
    assert.match(technical.textContent, /parallel-v0.2/);
    assert.match(technical.textContent, /Required parallel evaluation was not completed/);
    assert.match(technical.textContent, /"t_e": null/);
    assert.match(technical.textContent, /종합 판단 시각 원천t_e: null/);
    assert.equal(node.all().find((child) => child.classList.contains("dashboard-decision-id")).textContent, "DEC-READ");
});

test("Task 7-R an absent decision clock is not presented as a stored null or a synthesized time", () => {
    // Given / When
    const value = decision({ t_e: undefined });
    const node = createDecisionRecord(doc, value, 0);
    // Then
    assert.match(node.childNodes[3].textContent, /종합 판단 시각 원천저장값 미확인/);
    assert.doesNotMatch(node.childNodes[3].textContent, /t_e: null/);
    assert.match(node.childNodes[2].textContent, /종합 판단 시각미확정/);
});

test("Manual copy review hides the server-clock hint in the audit action while retaining its source detail", () => {
    // Given
    const original = entry(3, "record_awareness", reviewed, aware, { awareness_mode: "now" });
    const value = alert([original]);
    const raw = JSON.stringify(value);
    // When
    const compact = createWorkflowRecord(doc, value);
    const expanded = createWorkflowRecord(doc, value, { expanded: new Set(["act-3"]) });
    // Then
    assert.equal(cellsOf(rows(compact)[0])[1], "인지시각 기록");
    assert.doesNotMatch(compact.textContent, /현재 시각으로 기록/);
    assert.match(expanded.textContent, /인지시각 입력 방식현재 시각으로 기록/);
    assert.match(expanded.textContent, /"awareness_mode": "now"/);
    assert.equal(JSON.stringify(value), raw);
});
