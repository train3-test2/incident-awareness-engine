import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {draftPresentation, awarenessRecordStatus, workflowSteps, rawVerificationLabel, workflowTimeLabel, workflowTimeDetail,
    analysisStatusLabel, analysisPathLabel, analysisDecisionPresentation, analysisTimestampLabel, classificationReason, snapshotEligibility, reportSummaryRows, readinessSummary,
    generationOutcome, normalizeRawVerificationScope, sameRawVerificationScope, buildRawVerificationSummary} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-operator-contract.mjs";

const PHRASES = ["PowerShell 인코딩 명령 옵션 사용", "스크립트 인터프리터의 외부 주소 연결"];
const preview = (overrides = {}) => ({ snapshot_sha256: "a".repeat(64), workflow_version: 4, external_transmission: "not_sent",
    request: { messages: [{ content: JSON.stringify({ observations: PHRASES.map((fact_phrase, i) => ({ reference: `O${i + 1}`, fact_phrase })) }) }] },
    word_reuse: null, ...overrides });
const caseDetail = (state = {}, source = {}) => ({ alert_id: "A", run_id: "RUN-1", entity_id: "HOST-1", detection_kind: "fusion",
    source_snapshot: { evidence_ids: ["E1", "E2"], hybrid_status: "not_evaluated", context: "local_historical_development", ...source },
    state: { version: 4, analyst_ack_time: "T1", evidence_reviewed_at: "T2", t_h: "T3", t_h_recorded_at: "T3",
        report_choice: "proceed", ...state } });

test("Classification reason records the human selection and shown basis, never an inferred type", () => {
    // Given / When
    const reason = classificationReason("other_hacking", PHRASES);
    // Then
    assert.match(reason, /'그 밖의 해킹' 양식을 직접 선택/);
    for (const phrase of PHRASES) assert.ok(reason.includes(phrase));
    assert.match(reason, /자동 확정하지 않음/);
    assert.doesNotMatch(reason, /랜섬웨어|디도스|유출되었|확인되었습니다/);
    assert.equal(classificationReason("undetermined", PHRASES), "");
    assert.equal(classificationReason("unknown_type"), "");
    assert.ok(classificationReason("ddos", Array(200).fill("긴 관측 문구")).length <= 1000);
});

test("Snapshot eligibility reads phrases only from a well-formed, unsent server preview", () => {
    // Given / When / Then
    assert.deepEqual(snapshotEligibility(preview(), 4), { state: "eligible", phrases: PHRASES, reuse: null });
    assert.deepEqual(snapshotEligibility(preview({ request: undefined }), 4).phrases, []);
    for (const broken of [preview({ snapshot_sha256: "x" }), preview({ workflow_version: 3 }), preview({ external_transmission: "sent" }), null]) {
        assert.equal(snapshotEligibility(broken, 4).state, "unknown");
    }
});

test("Report summary shows only the verified basis, eligibility and detection basis without repeating the case", () => {
    // Given
    const value = caseDetail();
    // When
    const rows = Object.fromEntries(reportSummaryRows(value, { state: "eligible", phrases: PHRASES }, { adapter: "configured" }));
    const stored = Object.fromEntries(reportSummaryRows(caseDetail({}, { decision: { t_e: null } }), { state: "eligible", phrases: PHRASES }));
    // Then: Run, target and human progress are shown once elsewhere and are not repeated here.
    assert.deepEqual(Object.keys(rows), ["확인된 관측 사실", "자동 작성", "탐지 근거"]);
    assert.equal(rows["확인된 관측 사실"], `원본 검증 관측 2건 · ${PHRASES.join(", ")}`);
    assert.equal(rows["자동 작성"], "가능");
    assert.equal(rows["탐지 근거"], "근거 증거 2건 · 저장된 종합 판단 없음");
    assert.equal(stored["탐지 근거"], "근거 증거 2건 · 종합 판단 미완료");
    assert.doesNotMatch(Object.values(rows).join("|"), /RUN-1|HOST-1|담당자 확인|공란/);
});

for (const [name, state, eligibility, status, observed, possible] of [
    ["before a proceed decision", { report_choice: "hold" }, null, null, /신고 진행 결정 후/, /신고 진행 결정 후 가능/],
    ["ineligible observations", {}, { state: "ineligible" }, null, /원본 검증 관측이 없습니다/, /^불가 ·/],
    ["no approval API", {}, { state: "unsupported" }, null, /확인하지 못했습니다/, /승인형 AI 작성 기능 없음/],
    ["adapter misconfigured", {}, { state: "eligible", phrases: [] }, { adapter: "configuration_error" }, /원본 검증 관측 확인됨/, /설정 확인 필요/],
    ["still checking", {}, { state: "checking" }, null, /확인 중/, /확인 중/],
]) {
    test(`Report summary eligibility: ${name}`, () => {
        // Given / When
        const rows = Object.fromEntries(reportSummaryRows(caseDetail(state), eligibility, status));
        // Then
        assert.match(rows["확인된 관측 사실"], observed);
        assert.match(rows["자동 작성"], possible);
    });
}

test("Report summary labels synthetic data while incomplete awareness stays visible in the timeline", () => {
    // Given / When
    const value = caseDetail({ t_h_recorded_at: null, analyst_ack_time: null }, { context: "synthetic_development" });
    const rows = Object.fromEntries(reportSummaryRows(value));
    // Then
    assert.match(rows["탐지 근거"], /합성 개발 데이터/);
    assert.equal(workflowSteps(value)[1].state, "pending");
    assert.equal(workflowSteps(value)[3].state, "incomplete");
    assert.equal(workflowSteps(value)[3].label, "인지 기록 상태 확인");
    assert.deepEqual(reportSummaryRows(null), []);
});

test("Readiness summary groups the server checklist by category", () => {
    // Given
    const status = { required_items: [{ key: "company_name", target: "field:company_name" }, { key: "reporter_phone", target: "field:reporter_phone" },
        { key: "t_h", target: "awareness" }, { key: "affected_ip", target: "field:affected_ip" },
        { key: "privacy_collection", target: "consent:privacy_collection" }, { key: "incident_type", target: "type" }] };
    // When / Then
    assert.deepEqual(readinessSummary(status), { count: 6, groups: [{ label: "기업·신고자 정보", count: 2 }, { label: "인지시각", count: 1 },
        { label: "사고 세부사항", count: 1 }, { label: "동의·확인", count: 1 }, { label: "사고 유형", count: 1 }] });
    assert.deepEqual(readinessSummary({ blockers: ["company_name", "truth_confirmation"] }).groups.map(g => g.label), ["기업·신고자 정보", "동의·확인"]);
    assert.deepEqual(readinessSummary(null), { count: 0, groups: [] });
});

for (const [name, draft, expected, forbidden] of [
    ["verified AI with Word", { method: "monorouter_grounded", call_metadata: { status: "success", http_status: 200 }, word_result: { status: "ready" } }, /^Word 생성 완료$/, /실패|미통과|검토 완료|제출/],
    ["verified AI, Word failed", { method: "monorouter_grounded", call_metadata: { status: "success", http_status: 200 }, word_result: { status: "failed" } }, /Word 양식 생성에 실패/, /생성 완료/],
    ["verified AI, type missing", { method: "monorouter_grounded", call_metadata: { status: "success", http_status: 200 }, word_result: { status: "not_prepared" } }, /Word 양식 미생성/, /생성 완료/],
    ["invalid AI output", { method: "jinja2_fallback", call_metadata: { status: "invalid_output", requested_at: "T" }, word_result: { status: "not_prepared" } }, /AI 초안 검증 미통과\(AI 출력 검증 실패\) · 검증되지 않은 내용은 Word에 기입하지 않았습니다/, /Word 초안 생성 완료/],
    ["adapter label without HTTP success", { method: "monorouter_grounded", call_metadata: { status: "timeout" }, word_result: { status: "ready" } }, /검증 미통과/, /생성 완료/],
]) {
    test(`Generation outcome: ${name}`, () => {
        // Given / When
        const actual = generationOutcome(draft);
        // Then
        assert.match(actual, expected);
        assert.doesNotMatch(actual, forbidden);
    });
}

test("Report compose shows summary and main actions first; inputs and evidence stay collapsed", async () => {
    // Given / When
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html", import.meta.url), "utf8");
    const compose = html.split('aria-labelledby="workflow-compose-title"')[1].split('<details class="operator-technical"><summary>합성 시연 초안')[0];
    const primary = compose.split('id="workflow-snapshot-panel"')[0];
    const preview = compose.split('<details id="workflow-draft-preview">')[1].split('<details id="kisa-inputs-panel">')[0];
    // Then
    assert.doesNotMatch(compose, /operator-report-lead|확인된 사건 분석 결과를 바탕으로|공란으로 남깁니다|외부 제출되지 않습니다/);
    for (const id of ["workflow-report-summary", "workflow-draft-generate", "workflow-draft-inspect", "kisa-generate", "kisa-download", "workflow-draft-status"]) assert.ok(primary.includes(`id="${id}"`), id);
    assert.match(primary, />AI 신고서 초안 생성</);
    assert.match(primary, />내용 확인·보완</);
    assert.match(primary, />Word 신고서 다운로드</);
    // Word is secondary; the review record is made at the end of the preview, not beside the download.
    assert.doesNotMatch(primary, /operator-primary|id="workflow-draft-review"/);
    assert.match(primary, /<a id="kisa-download" class="operator-secondary" hidden>/);
    assert.match(preview, /<button id="workflow-draft-review" class="operator-primary" type="button" disabled hidden>초안 검토 완료 기록<\/button>/);
    assert.match(preview, /<button id="workflow-draft-collapse"[^>]*type="button"[^>]*>미리보기 접기<\/button>\s*<\/div>\s*<\/details>\s*$/);
    assert.match(compose, /<dl id="kisa-document-summary"/);
    for (const id of ["kisa-type", "kisa-reason", "kisa-fields", "kisa-consents", "kisa-save", "kisa-required-items", "kisa-template", "workflow-draft-fallback"]) {
        assert.ok(!primary.includes(`id="${id}"`), id);
    }
    for (const id of ["kisa-inputs-panel", "kisa-checklist", "workflow-draft-preview"]) assert.match(compose, new RegExp(`<details id="${id}">`));
    assert.match(compose, /<summary>추가 정보 입력·수정<\/summary>/);
    assert.match(compose, /<summary>신고서 내용 미리보기<\/summary>/);
    assert.match(compose, /<summary>작성 근거 및 검증 상세<\/summary>/);
    // No incident type is preselected anywhere in the report flow.
    assert.doesNotMatch(compose, /type="radio"[^>]*checked|<option[^>]*selected/);
    assert.match(compose, /<input id="workflow-snapshot-type" type="hidden" value="undetermined">/);
    assert.equal((compose.match(/name="workflow-snapshot-type-choice"/g) ?? []).length, 3);
    assert.match(compose, /<input id="workflow-snapshot-consent" type="checkbox">/);
});

for (const [name, method, status, http, expected] of [
    ["verified AI", "monorouter_grounded", "success", 200, "AI 작성"],
    ["blocked real data", "jinja2_fallback", "blocked_data", null, "대체 작성"],
    ["adapter name without success", "monorouter_grounded", "timeout", null, "작성 방식 확인 필요"],
    ["success without HTTP verification", "monorouter_grounded", "success", null, "작성 방식 확인 필요"],
    ["fallback despite old connection success", "jinja2_fallback", "success", 200, "대체 작성"],
]) {
    test(`Operator draft method: ${name}`, () => {
        // Given / When
        const actual = draftPresentation({method,context:"synthetic_development",call_metadata:{status,http_status:http}});
        // Then
        assert.equal(actual.method,expected);
        assert.equal(actual.ai,expected === "AI 작성");
        assert.equal(actual.demo,true);
    });
}
for (const [name, draft, method, reason, source] of [
    ["real Run blocked before any call", {method:"jinja2_fallback",context:"local_development",call_metadata:{status:"blocked_data",requested_at:null}}, "대체 작성", "실제 분석 외부 전송 차단", "이 분석 초안"],
    ["provider disabled", {method:"jinja2_fallback",call_metadata:{status:"disabled",requested_at:null}}, "대체 작성", "외부 호출 없음", "이 분석 초안"],
    ["called but failed", {method:"jinja2_fallback",call_metadata:{status:"http_error",requested_at:"2026-10-21T00:00:00Z"}}, "대체 작성", "AI 호출 실패", "이 분석 초안"],
    ["unknown fallback status without a request", {method:"jinja2_fallback",call_metadata:{}}, "대체 작성", "외부 호출 없음", "이 분석 초안"],
    ["verified synthetic AI", {method:"monorouter_grounded",context:"synthetic_development",call_metadata:{status:"success",http_status:200}}, "AI 작성", "검증 통과", "합성 시연 초안"],
    ["adapter label without a verified call", {method:"monorouter_grounded",call_metadata:{status:"timeout"}}, "작성 방식 확인 필요", null, "이 분석 초안"],
]) {
    test(`Draft source and reason: ${name}`, () => {
        // Given / When
        const actual = draftPresentation(draft);
        // Then
        assert.equal(actual.method,method);
        assert.equal(actual.reason,reason);
        assert.equal(actual.source,source);
        assert.equal(actual.ai,method === "AI 작성");
    });
}
test("Task 6 status summary holds the six steps once; the current task holds the step and next action", async () => {
    // Given / When
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html",import.meta.url),"utf8");
    const status = html.split('aria-labelledby="workflow-heading"')[1].split("</section>")[0];
    const task = html.split('aria-labelledby="workflow-task-heading"')[1].split('<div id="workflow-record"')[0];
    const compose = html.split('id="workflow-compose"')[1].split('id="workflow-history"')[0];
    // Then
    assert.match(status,/id="workflow-detail-timeline"/);
    assert.doesNotMatch(status,/id="workflow-next"/);
    assert.doesNotMatch(task,/<ol\b/);
    assert.match(task,/id="workflow-current-step"/);
    assert.match(task,/id="workflow-next"/);
    assert.equal((html.match(/id="workflow-detail-timeline"/g)??[]).length,1);
    const order = ['id="workflow-heading"','id="workflow-task-heading"','id="workflow-compose-title"','id="workflow-history"','id="workflow-dev-tools"']
        .map(marker => html.indexOf(marker));
    assert.deepEqual(order,[...order].sort((left,right) => left-right));
    assert.ok(order.every(index => index > 0));
    // Developer tools stay available, outside the report workspace.
    assert.doesNotMatch(compose,/workflow-synthetic/);
    assert.match(html.split('id="workflow-dev-tools"')[1],/id="workflow-synthetic-consent"/);
    assert.match(html,/<h3 id="workflow-compose-title">침해사고 신고서<\/h3>/);
    assert.match(compose,/id="kisa-document-summary"[^>]*aria-label="신고서 문서 요약"/); // Submission is retained in the document state, not a repeated disclaimer.
    assert.doesNotMatch(html,/AI 신고서 초안 작성|>실행 시작</);
    assert.match(html,/>입력 이벤트 범위<\/th>/);
    assert.match(html,/id="kisa-source-label"/);
});
test("Workflow does not infer awareness from reporting or draft creation", () => {
    // Given
    const value = {issued_at:"2026-10-21T01:00:00Z",state:{analyst_ack_time:"A",evidence_reviewed_at:"B",t_h:null,report_choice:"proceed",report_decided_at:"C"}};
    // When
    const steps = workflowSteps(value,{current:true,draft:{generated_at:"D"}});
    // Then
    assert.deepEqual(steps.map(s=>s.label),["알림","담당자 확인","근거 검토","인지 기록","신고 검토","초안·검토"]);
    assert.equal(steps[3].state,"pending");
    assert.equal(steps[3].active,true);
    assert.equal(steps[5].state,"partial");
    assert.equal(steps[5].active,false);
    assert.equal(workflowSteps(value,{current:false,draft:{generated_at:"D"},review:{}})[5].state,"partial");
    assert.equal(workflowSteps(value,{current:true,draft:{generated_at:"D"},review:{}})[5].state,"complete");
    assert.deepEqual(workflowSteps(null),[]);
});
test("Operator shell keeps technical settings closed and action IDs available", async () => {
    // Given / When
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html",import.meta.url),"utf8");
    // Then
    assert.ok(html.includes("dashboard-operator.css"));
    assert.doesNotMatch(html,/실시간 운영 및 사건 분석 화면|MonoRouter Adapter 구성됨|Human Workflow<\/h2>/);
    for (const id of ["workflow-next","workflow-ack","workflow-review","workflow-awareness","workflow-audit","workflow-report","workflow-draft-generate","kisa-generate","kisa-download","workflow-synthetic-consent"]) assert.ok(html.includes(`id="${id}"`));
    assert.match(html,/<details class="operator-technical"><summary>식별 정보<\/summary>/);
    assert.match(html,/id="dashboard-tab-summary"[\s\S]*?aria-selected="true"/);
    assert.equal((html.match(/id="workflow-draft-text"/g)??[]).length,1);
});

test("Raw summary never reuses a count for another contributing Evidence set", () => {
    // Given
    const scope={runId:"RUN-A",entityId:"HOST-A",decisionId:"DEC-A",evidenceIds:["E-A"]};
    const summary={scope,evidenceIds:["E-A"],queryState:"ready",resultState:"passed",verified:1,failed:0,total:1};
    // When / Then
    assert.equal(rawVerificationLabel(["E-A"],summary,scope),"원본 대조 통과 · 1/1건");
    assert.equal(rawVerificationLabel(["E-A"],summary),"검증 상태 미조회");
    assert.equal(rawVerificationLabel([],{...summary,evidenceIds:[],verified:0,total:0,
        scope:{...scope,evidenceIds:[]}}, {...scope,evidenceIds:[]}),"조회 실패");
    assert.equal(rawVerificationLabel(["E-B"],summary),"검증 상태 미조회");
    assert.equal(rawVerificationLabel(null,summary),"검증 상태 미조회");
    assert.equal(rawVerificationLabel([],null),"검증 대상 없음");
    assert.equal(rawVerificationLabel(["E-A"],{...summary,queryState:"error"},scope),"조회 실패");
    for(const change of [{runId:"RUN-B"},{entityId:"HOST-B"},{decisionId:"DEC-B"},{evidenceIds:["E-B"]}])
        assert.equal(rawVerificationLabel(["E-A"],summary,{...scope,...change}),"검증 상태 미조회");
});

test("Awareness step uses its recording time while a past awareness remains a separate fact", () => {
    // Given
    const value = { state: { t_h: "2026-10-20T00:00:00Z", t_h_recorded_at: "2026-10-21T04:47:24.708123Z" } };
    // When
    const step = workflowSteps(value)[3];
    // Then
    assert.equal(step.timestamp, value.state.t_h_recorded_at);
    assert.equal(step.state, "complete");
    assert.equal(value.state.t_h, "2026-10-20T00:00:00Z");
    assert.match(workflowTimeDetail(step.timestamp), /24\.708/);
    assert.match(workflowTimeDetail(step.timestamp), /UTC 2026-10-21T04:47:24\.708Z/);
    assert.match(workflowTimeDetail(step.timestamp), /원본 2026-10-21T04:47:24\.708123Z/);
});

test("Missing awareness fields are never filled from each other or from a reporting decision", () => {
    // Given / When
    const pastOnly = workflowSteps({ state: { t_h: "2026-10-20T00:00:00Z", t_h_recorded_at: null, report_choice: "proceed" } })[3];
    const recordedOnly = workflowSteps({ state: { t_h: null, t_h_recorded_at: "2026-10-21T00:00:00Z" } })[3];
    // Then
    assert.equal(pastOnly.state, "incomplete");
    assert.equal(pastOnly.timestamp, null);
    assert.equal(recordedOnly.state, "incomplete");
    assert.equal(recordedOnly.timestamp, "2026-10-21T00:00:00Z");
    assert.equal(workflowTimeLabel(null), "미기록");
    assert.equal(workflowTimeDetail("invalid"), "시각 확인 필요");
});

for (const [t_h, t_h_recorded_at, expected] of [
    [null, null, "missing"],
    ["2026-10-20T00:00:00Z", null, "incomplete"],
    [null, "2026-10-21T04:47:24.708123Z", "incomplete"],
    ["2026-10-20T00:00:00Z", "2026-10-21T04:47:24.708123Z", "complete"],
]) {
    test(`Awareness presentation shares the stored pair judgment: ${expected} ${Boolean(t_h)}`, () => {
        const state = Object.freeze({t_h, t_h_recorded_at, report_choice: "proceed"});
        assert.equal(awarenessRecordStatus(state), expected);
        const step = workflowSteps({state})[3];
        assert.equal(step.state, expected === "missing" ? "pending" : expected);
        assert.equal(step.label, expected === "incomplete" ? "인지 기록 상태 확인" : "인지 기록");
        assert.equal(step.timestamp, t_h_recorded_at);
    });
}

test("Operator results distinguish unevaluated, pending, failed and absent facts", () => {
    // Given / When / Then
    assert.equal(analysisStatusLabel("not_evaluated"), "미평가");
    assert.equal(analysisStatusLabel("pending"), "대기");
    assert.equal(analysisStatusLabel("failed"), "실패");
    assert.equal(analysisStatusLabel(null), "현재 확인된 정보 없음");
    assert.equal(analysisStatusLabel("constructor"), "상태 확인 필요");
    assert.equal(analysisPathLabel("fast_and_fusion"), "즉시 규칙·증거 누적 분석");
    assert.equal(analysisPathLabel(null), "미확정");
});

test("Only recorded stage status is shown; the explanatory diagram was removed", async () => {
    // Given / When
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html", import.meta.url), "utf8");
    // Then
    assert.doesNotMatch(html, /operator-analysis-logic|operator-logic-node/);
    assert.doesNotMatch(html, /설명용 도식/);
    assert.match(html, /id="pipeline-stage-list"[^>]*aria-label="단계별 저장 보고"/);
});


const incompleteDecision = Object.freeze({
    run_id: "RUN-20261021-901", decision_id: "DEC-RUN-20261021-901", entity_id: "WIN-01",
    fast_status: "not_evaluated", fusion_status: "detected", detector_time: null,
    fusion_time: "2026-10-03T00:00:20.000Z", t_e: null, decision_path: null, winning_path: null,
    config_version: "parallel-v0.2", decision_reason: "Required parallel evaluation was not completed",
});

test("A stored incomplete Decision preserves Fusion detection without manufacturing a hybrid time or path", () => {
    // Given
    const before = JSON.stringify(incompleteDecision);
    // When
    const result = analysisDecisionPresentation(incompleteDecision);
    // Then
    assert.equal(result.headline, "증거 누적 분석에서 의심 행위 탐지");
    assert.equal(result.summary, "종합 판단 미완료 · 즉시 규칙 분석 미평가");
    assert.equal(result.reason, "필수 병렬 평가 미완료");
    assert.equal(result.path, "미확정");
    assert.equal(result.decisionTime, "미확정");
    assert.equal(result.detectionTime, "증거 누적 분석 · 2026.10.03 09:00:20 KST");
    assert.equal(result.rawReason, incompleteDecision.decision_reason);
    assert.equal(JSON.stringify(incompleteDecision), before);
    assert.doesNotMatch(result.summary, /미실행|평가 대상 제외|미탐지|결과 없음/);
});

test("Both evaluated detections and both misses retain their distinct complete outcomes", () => {
    // Given
    const both = {...incompleteDecision, fast_status:"detected", detector_time:"2026-10-03T00:00:10Z",
        t_e:"2026-10-03T00:00:10Z", decision_path:"fast_and_fusion", winning_path:"fast",
        decision_reason:"Both paths detected; compared canonical UTC millisecond timestamps"};
    const misses = {...incompleteDecision, fast_status:"miss", fusion_status:"miss", fusion_time:null,
        decision_path:"none", winning_path:"none", decision_reason:"Both evaluated paths missed"};
    // When
    const detected = analysisDecisionPresentation(both), missed = analysisDecisionPresentation(misses);
    // Then
    assert.equal(detected.summary, "종합 판단 완료 · 의심 행위 탐지");
    assert.equal(detected.path, "즉시 규칙·증거 누적 분석");
    assert.equal(detected.decisionTime, "2026.10.03 09:00:10 KST");
    assert.match(detected.detectionTime, /즉시 규칙 분석.*09:00:10.*증거 누적 분석.*09:00:20/);
    assert.equal(missed.summary, "종합 판단 완료 · 탐지 기준 미충족");
    assert.equal(missed.path, "탐지 경로 없음");
    assert.equal(missed.decisionTime, "없음 · 탐지 기준 미충족");
    assert.doesNotMatch(missed.headline, /정상|안전|미평가/);
});

test("Unknown reasons and policies remain uninterpreted while the original reason stays available", () => {
    // Given / When / Then
    for (const change of [{decision_reason:"future reason: input excluded"}, {config_version:"other-policy"},
        {decision_reason:null}, {decision_reason:"Required parallel evaluation was not completed (new)"}]) {
        const decision = {...incompleteDecision, ...change};
        const result = analysisDecisionPresentation(decision);
        assert.equal(result.reason, "미평가 사유 미확인");
        assert.match(result.summary, /종합 판단 미완료.*즉시 규칙 분석 미평가.*사유 미확인/);
        assert.equal(result.rawReason, decision.decision_reason);
        assert.doesNotMatch(result.summary, /미실행|평가 대상 제외|미탐지/);
    }
});

test("Missing, failed, loading and mismatched Decision reads cannot be confused", () => {
    // Given
    const fusion = {fusion_status:"detected", fusion_time:incompleteDecision.fusion_time};
    // When / Then
    assert.equal(analysisDecisionPresentation(null, fusion).summary, "저장된 종합 판단 결과 없음");
    for (const [state, label] of [["error","종합 판단 조회 실패"], ["loading","종합 판단 조회 중"],
        ["not_found","종합 판단 조회 불가"], ["version_mismatch","종합 판단 확인 보류 · 조회 버전 불일치"]]) {
        const result = analysisDecisionPresentation(null, state === "version_mismatch" ? null : fusion, state);
        assert.equal(result.summary, label);
        assert.doesNotMatch(result.summary, /결과 없음|판단 완료/);
        assert.notEqual(result.decisionTime, "2026.10.03 09:00:20 KST");
    }
});

test("A missing canonical Fusion time is never filled from a latest result or t_e", () => {
    // Given
    const decision = {...incompleteDecision, fusion_time:null};
    // When
    const result = analysisDecisionPresentation(decision, {fusion_status:"detected", fusion_time:incompleteDecision.fusion_time});
    // Then
    assert.match(result.detectionTime, /탐지 시각 미확인/);
    assert.doesNotMatch(result.detectionTime, /09:00:20/);
    assert.equal(result.decisionTime, "미확정");
    assert.equal(analysisTimestampLabel("invalid"), "시각 확인 필요");
    assert.equal(analysisTimestampLabel(null), "미확정");
    assert.equal(analysisTimestampLabel("2026-10-02T15:00:00Z"), "2026.10.03 00:00:00 KST");
});

test("A known English reason is interpreted only for its matching evaluated path", () => {
    // Given
    const decision = {...incompleteDecision,fast_status:"miss",fusion_status:"detected",
        t_e:incompleteDecision.fusion_time,decision_path:"fusion",winning_path:"fusion"};
    // When / Then
    assert.equal(analysisDecisionPresentation({...decision,decision_reason:"Only Fusion detected"}).reason,
        "증거 누적 분석에서 탐지");
    assert.equal(analysisDecisionPresentation({...decision,decision_reason:"Only Fast detected"}).reason,
        "판단 사유 미확인");
    assert.equal(analysisDecisionPresentation({...decision,decision_reason:"future reason"}).reason,
        "판단 사유 미확인");
});


test("Task 2 scope snapshots use actual identifiers without mutating or inventing server revisions",()=>{
    // Given
    const source={runId:"RUN-A",entityId:"HOST-A",decisionId:null,evidenceIds:["E-B","E-A"]};
    // When
    const snapshot=normalizeRawVerificationScope(source);source.evidenceIds.push("E-C");
    // Then
    assert.deepEqual(snapshot.evidenceIds,["E-A","E-B"]);
    assert.equal(sameRawVerificationScope(snapshot,{...snapshot,evidenceIds:["E-B","E-A"]}),true);
    assert.equal(normalizeRawVerificationScope({...source,evidenceIds:["E-A","E-A"]}),null);
    assert.equal(normalizeRawVerificationScope({...source,entityId:null}),null);
    assert.equal(sameRawVerificationScope(null,null),false);
    assert.doesNotMatch(JSON.stringify(snapshot),/revision|sha256/);
});

test("Task 2 raw label never trusts an unscoped legacy success label",()=>{
    // Given / When / Then
    assert.equal(rawVerificationLabel(["E-A"],null),"검증 상태 미조회");
    assert.equal(rawVerificationLabel(["E-A"],{label:"原本 SUCCESS"}),"검증 상태 미조회");
    assert.equal(rawVerificationLabel(["E-A"],{queryState:"loading",evidenceIds:["E-A"]}),"원본 검증 확인 중");
    assert.equal(rawVerificationLabel(["E-A"],{queryState:"unsupported",evidenceIds:["E-A"]}),"검증 정보 미지원");
});

test("Review report workspace reads status, then actions, then the full-width document and its checks", async () => {
    // Given / When
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html",import.meta.url),"utf8");
    const compose = html.split('id="workflow-compose"')[1].split('id="workflow-history"')[0];
    const at = id => compose.indexOf(`id="${id}"`);
    // Then
    const order = ["kisa-document-summary","workflow-report-summary","workflow-draft-generate","workflow-draft-inspect","kisa-download",
        "kisa-panel","kisa-readiness","workflow-draft-preview","kisa-checklist","workflow-draft-text","workflow-draft-review","workflow-draft-collapse","kisa-inputs-panel","kisa-source"];
    assert.ok(order.every(id => at(id) > 0), order.filter(id => at(id) <= 0).join());
    assert.deepEqual(order.map(at),[...order.map(at)].sort((left,right) => left-right));
    assert.ok(at("kisa-document-summary") < at("kisa-panel"), "Document status is shown above, not inside the document area");
    assert.doesNotMatch(html,/kisa-panel__document|kisa-panel__summary|operator-report-overview/);
    assert.match(compose,/<details id="workflow-draft-preview"><summary>신고서 내용 미리보기<\/summary>/, "The preview starts closed");
});

test("Review current task starts without a prompt for a control that may not be shown", async () => {
    // Given / When
    const html = await readFile(new URL("../../../src/incident_awareness/dashboard/ui/dashboard.html",import.meta.url),"utf8");
    const task = html.split('aria-labelledby="workflow-task-heading"')[1].split('<div id="workflow-record"')[0];
    // Then
    assert.match(task,/<p id="workflow-guidance" class="operator-guidance" role="status" aria-live="polite"><\/p>/);
    assert.match(task,/<p id="workflow-action-status" role="status" aria-live="polite"><\/p>/);
    assert.doesNotMatch(html,/알림 상세를 선택하세요/);
});


test("Operator KST clocks retain different fractional observations and verbatim UTC originals", () => {
    // Given / When / Then
    assert.equal(analysisTimestampLabel("2026-10-03T00:00:00Z"), "2026.10.03 09:00:00 KST");
    assert.equal(analysisTimestampLabel("2026-10-03T09:00:00.123456+09:00"), "2026.10.03 09:00:00.123456 KST");
    assert.notEqual(analysisTimestampLabel("2026-10-03T00:00:00.123001Z"), analysisTimestampLabel("2026-10-03T00:00:00.123002Z"));
    assert.match(workflowTimeDetail("2026-10-03T00:00:00.123456Z"), /원본 2026-10-03T00:00:00.123456Z/);
    assert.equal(analysisTimestampLabel("2026-10-03T00:00:00"), "시각 확인 필요");
    assert.equal(analysisTimestampLabel(null), "미확정");
});


test("Observed sentence timestamps are KST presentation only, without duplicate clocks or changed facts", async () => {
    const {observationDisplayText} = await import("../../../src/incident_awareness/dashboard/ui/assets/dashboard-operator-contract.mjs");
    const raw = '2026-10-03T00:00:00.000+00:00 관측 시스템 "WIN-01"의 "powershell.exe" 프로세스에서 인코딩된 PowerShell 실행 옵션 "-encodedcommand"이 관측되었습니다.';
    const value = Object.freeze({observed_at: "2026-10-03T00:00:00.000Z", behavior_summary: raw});
    const shown = observationDisplayText(value.behavior_summary,value.observed_at);
    assert.equal(shown, '2026.10.03 09:00:00 KST — 관측 시스템 "WIN-01"의 "powershell.exe" 프로세스에서 인코딩된 PowerShell 실행 옵션 "-encodedcommand"이 관측되었습니다.');
    assert.equal(shown.match(/09:00:00/g).length,1);
    assert.equal(value.behavior_summary,raw);
    assert.doesNotMatch(shown,/T00:00|\+00:00/);
});

test("Observation clock mismatches stay distinct rather than discarding a source", async () => {
    const {observationDisplayText} = await import("../../../src/incident_awareness/dashboard/ui/assets/dashboard-operator-contract.mjs");
    assert.equal(observationDisplayText("관측 문장", "2026-10-03T00:00:10Z"), "2026.10.03 09:00:10 KST — 관측 문장");
    assert.equal(observationDisplayText("2026-10-03T00:00:00.123001Z 관측", "2026-10-03T00:00:00.123002Z"),
        "2026.10.03 09:00:00.123002 KST — 문장 시각 2026.10.03 09:00:00.123001 KST · 관측");
    assert.equal(observationDisplayText("시각 없는 관측"),"시각 없는 관측");
});
