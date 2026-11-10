// "기록" tab: stored analysis Decisions and human Workflow audit entries as two separate lists.
// Neither invents a time order: Decisions follow their supersedes links, audit entries their version.
import { analysisDecisionPresentation, analysisStatusLabel, workflowTimeDetail, workflowTimeLabel } from "./dashboard-operator-contract.mjs";
import { createCopyableValue, createDetailList, createDetailRow, createExpandButton, createStackedText } from "./dashboard-detail-rows.mjs";

const isText = value => typeof value === "string" && value.length > 0;

export function decisionRecordFields(decision) {
    const presentation = analysisDecisionPresentation(decision);
    const versions = [["config", decision.config_version], ["rule", decision.rule_version],
        ["model", decision.model_version], ["detector_set", decision.detector_set_version]]
        .filter(([, value]) => isText(value)).map(([name, value]) => `${name} ${value}`).join(" · ");
    return [
        ["종합 판단", presentation.summary],
        ["즉시 규칙 분석", analysisStatusLabel(decision.fast_status)],
        ["증거 누적 분석", analysisStatusLabel(decision.fusion_status)],
        ["판단 사유", presentation.reason],
        ["탐지 시각", presentation.detectionTime],
        // A null t_e or path is a stored fact; neither is filled from Fusion or alert times.
        ["종합 판단 시각", decision.t_e == null ? `${presentation.decisionTime} · 저장값 없음 (t_e null)`
            : `확정 · ${presentation.decisionTime}`],
        ["종합 판단 경로", decision.decision_path == null ? "미확정 · 저장값 없음" : `확정 · ${presentation.path}`],
        ["설정·정책 버전", versions || "미기록"],
        ["이전 결정 연결", isText(decision.supersedes_decision_id)
            ? `${decision.supersedes_decision_id}를 대체한 결정` : "연결된 이전 결정 없음"],
        ["판단 사유 원문", decision.decision_reason ?? "원문 없음"],
    ];
}

function field(doc, label, value) {
    const wrapper = doc.createElement("div");
    const term = doc.createElement("dt");
    term.textContent = label;
    const description = doc.createElement("dd");
    if (typeof value === "string") description.textContent = value;
    else description.append(value);
    wrapper.append(term, description);
    return wrapper;
}

// history[0] is the stored head; later entries are the earlier Decisions it superseded.
export function createDecisionRecord(doc, decision, index) {
    const item = doc.createElement("li");
    item.classList.add("dashboard-decision-record");
    if (index === 0) item.classList.add("dashboard-decision-record--current");
    const header = doc.createElement("div");
    header.classList.add("dashboard-decision-record__header");
    const order = doc.createElement("span");
    order.classList.add("dashboard-decision-record__order");
    order.textContent = index === 0 ? "현재 결정" : `이전 결정 ${index}`;
    const presentation = analysisDecisionPresentation(decision);
    const summary = doc.createElement("span");
    summary.textContent = presentation.summary;
    summary.classList.add("dashboard-decision-record__summary");
    header.append(order, summary);
    const reason = doc.createElement("p");
    reason.classList.add("dashboard-decision-record__reason");
    reason.append(text(doc, "span", "판단 사유"), text(doc, "span", presentation.reason));
    reason.hidden = presentation.reasonRepeatsSummary;
    const fields = doc.createElement("dl");
    fields.classList.add("dashboard-decision-record__fields");
    const technicalLabels = new Set(["설정·정책 버전", "이전 결정 연결", "판단 사유 원문"]);
    const recordFields = decisionRecordFields(decision);
    fields.append(...recordFields.filter(([label]) => !technicalLabels.has(label) && !["종합 판단", "판단 사유"].includes(label))
        .map(([label, value]) => field(doc, label, label === "종합 판단 시각" && decision.t_e == null
            ? analysisDecisionPresentation(decision).decisionTime : value)));
    const technical = doc.createElement("dl");
    technical.classList.add("dashboard-decision-record__technical-fields");
    const identity = createCopyableValue(doc, decision.decision_id, "결정 ID");
    identity.childNodes[0].classList.add("dashboard-decision-id");
    technical.append(field(doc, "결정 ID", identity),
        field(doc, "종합 판단 시각 원천", decision.t_e === null ? "t_e: null" : decision.t_e ?? "저장값 미확인"),
        ...recordFields.filter(([label]) => technicalLabels.has(label)).map(([label, value]) => field(doc, label, value)));
    const raw = doc.createElement("details");
    const rawLabel = doc.createElement("summary");
    rawLabel.textContent = "판단 식별 정보·버전·원문";
    const json = doc.createElement("pre");
    json.textContent = JSON.stringify(decision, null, 2);
    raw.append(rawLabel, technical, json);
    if (index === 0) {
        item.append(header, reason, fields, raw);
        return item;
    }
    // Earlier Decisions stay complete but collapsed under their one-line summary.
    const older = doc.createElement("details");
    const olderLabel = doc.createElement("summary");
    olderLabel.textContent = `이 결정의 판단 필드 보기 · ${decision.decision_id}`;
    older.append(olderLabel, reason, fields, raw);
    item.append(header, older);
    return item;
}

const ACTIONS = { acknowledge: "담당자 확인", review_evidence: "근거 검토", record_awareness: "인지시각 기록",
    decide_reporting: "신고 진행 결정" };
const CHOICES = { proceed: "신고 진행", hold: "판단 보류", do_not_proceed: "진행하지 않음" };
const STATE_FIELDS = [
    ["analyst_ack_time", "담당자 확인 시각", "time"], ["evidence_reviewed_at", "근거 검토 시각", "time"],
    ["t_h", "내부 인지시각", "time"], ["t_h_recorded_at", "내부 인지시각 시스템 기록시각", "time"],
    ["report_choice", "신고 진행 결정", "choice"], ["report_decided_at", "결정 기록시각", "time"],
    ["report_reason", "결정 사유", "text"],
];
const stateValue = (value, kind) => value == null || value === "" ? "미기록"
    : kind === "time" ? workflowTimeLabel(value, true)
        : kind === "choice" ? CHOICES[value] ?? `확인 필요 (${value})` : String(value);

// Stored audit rows only; a changed field is read from previous_state/resulting_state, never inferred.
export function workflowAuditEntries(alert) {
    if (!Array.isArray(alert?.audit)) return null;
    return [...alert.audit].sort((left, right) => (right.version ?? 0) - (left.version ?? 0)).map(entry => {
        const before = entry.previous_state ?? {}, after = entry.resulting_state ?? {};
        const correction = entry.action === "record_awareness" && Boolean(before.t_h);
        const actorId = entry.actor_id ?? "행위자 미기록";
        const actorKind = entry.actor_kind === "unauthenticated_local_demo" ? "로컬 실험 담당자 · 인증 계정 아님"
            : entry.actor_kind ?? "유형 미기록";
        return {
            key: entry.action_id ?? `${alert.alert_id}:${entry.version}`,
            version: entry.version,
            action: correction ? "인지시각 정정" : ACTIONS[entry.action] ?? `확인 필요 (${entry.action})`,
            actorId,
            actorKind,
            actor: `${actorId} · ${actorKind}`,
            recordedAt: entry.recorded_at ?? null,
            mode: entry.action !== "record_awareness" ? null
                : entry.command?.awareness_mode === "now" ? "현재 시각으로 기록 (서버 수신 시각)" : "담당자가 직접 입력한 시각",
            reason: isText(entry.command?.reason) ? entry.command.reason : null,
            changes: STATE_FIELDS.filter(([key]) => (before[key] ?? null) !== (after[key] ?? null))
                .map(([key, label, kind]) => ({ label, before: stateValue(before[key], kind), after: stateValue(after[key], kind) })),
            raw: entry,
        };
    });
}

function text(doc, tag, value, className = null) {
    const element = doc.createElement(tag);
    if (className) element.classList.add(className);
    element.textContent = value;
    return element;
}

const AUDIT_COLUMNS = 5;

// One row per stored action: time, action, actor and changed values; reason and raw record on request.
function createAuditRow(doc, entry, { expanded, onToggle, buttons }) {
    const row = doc.createElement("tr");
    row.classList.add("dashboard-audit-row");
    const time = text(doc, "time", workflowTimeLabel(entry.recordedAt, true));
    if (entry.recordedAt) time.setAttribute("datetime", entry.recordedAt);
    time.title = workflowTimeDetail(entry.recordedAt);
    const changes = doc.createElement("ul");
    changes.classList.add("dashboard-audit-changes");
    changes.append(...(entry.changes.length ? entry.changes.map(change => text(doc, "li", `${change.label}: ${change.before} → ${change.after}`))
        : [text(doc, "li", "변경된 상태 값 없음")]));
    const open = expanded.has(entry.key);
    const button = createExpandButton(doc, { key: entry.key, label: `${entry.action} · ${time.textContent}`, expanded: open, onToggle });
    buttons.set(entry.key, button);
    const timeCell = doc.createElement("span");
    timeCell.classList.add("dashboard-evidence-cell");
    timeCell.append(time, text(doc, "small", `기록 버전 v${entry.version}`));
    for (const value of [timeCell, createStackedText(doc, entry.action, entry.raw.command?.awareness_mode === "now" ? null : entry.mode), createStackedText(doc, entry.actorId === "local-demo-analyst" ? "로컬 담당자" : entry.actorId, entry.actorKind),
        changes, button]) {
        const cell = doc.createElement("td");
        cell.append(value);
        row.append(cell);
    }
    if (!open) return [row];
    const raw = text(doc, "pre", JSON.stringify(entry.raw, null, 2));
    return [row, createDetailRow(doc, AUDIT_COLUMNS, createDetailList(doc, [
        ["사유", entry.reason ?? "저장된 사유 없음"],
        ["인지시각 입력 방식", entry.mode ?? "해당 없음"],
        ["기록 버전 · 요청 식별", `v${entry.version} · ${entry.raw.idempotency_key ?? "미기록"}`],
        ["원본 기록", raw],
    ]))];
}

// One table per alert. expanded/onToggle/buttons let the caller keep open rows and focus across re-renders.
export function createWorkflowRecord(doc, alert, { expanded = new Set(), onToggle = () => {}, buttons = new Map() } = {}) {
    const item = doc.createElement("li");
    item.classList.add("dashboard-workflow-record");
    const header = doc.createElement("p");
    header.classList.add("dashboard-workflow-record__header");
    header.append(text(doc, "strong", `${alert.detection_kind === "fusion" ? "증거 누적 분석 탐지" : "통합 판단 탐지"} 알림 · 대상 ${alert.entity_id}`),
        text(doc, "span", `알림 발행 ${workflowTimeLabel(alert.issued_at, true)}`));
    item.append(header);
    const entries = workflowAuditEntries(alert);
    if (entries === null) {
        item.append(text(doc, "p", "이 응답에는 감사 기록이 없어 표시하지 않습니다."));
        return item;
    }
    if (!entries.length) {
        item.append(text(doc, "p", "담당자 처리 기록 없음 · 알림만 발행됨"));
        return item;
    }
    header.append(text(doc, "span", `기록 ${entries.length}건 · 최신 기록부터`));
    const region = doc.createElement("div");
    region.classList.add("dashboard-table-wrapper", "dashboard-audit-region");
    region.dataset.alertId = alert.alert_id;
    const table = doc.createElement("table");
    table.classList.add("dashboard-table", "dashboard-audit-table");
    const caption = text(doc, "caption", `${alert.entity_id} 알림의 담당자 처리 기록`, "dashboard-visually-hidden");
    const head = doc.createElement("thead");
    const headRow = doc.createElement("tr");
    for (const label of ["기록시각 (KST)", "행위", "행위자", "변경 내용", "상세"]) {
        const cell = text(doc, "th", label);
        cell.setAttribute("scope", "col");
        headRow.append(cell);
    }
    head.append(headRow);
    const body = doc.createElement("tbody");
    body.append(...entries.flatMap(entry => createAuditRow(doc, entry, { expanded, onToggle, buttons })));
    table.append(caption, head, body);
    region.append(table);
    item.append(region);
    return item;
}
