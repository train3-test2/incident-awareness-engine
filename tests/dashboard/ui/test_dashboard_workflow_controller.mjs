import test from "node:test";
import assert from "node:assert/strict";
import { createHumanWorkflowController } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-workflow-controller.mjs";

test("Task 5 review passive case selection and refresh read alerts without synchronizing or loading drafts", async () => {
    const calls = [], states = [], value = detail("A", 0);
    const h = harness(async (url, options) => {
        calls.push({ url, method: options?.method ?? "GET" });
        assert.ok(url.endsWith("/runs/R/alerts"), `Unexpected passive read: ${url}`);
        return response({ items: [value] });
    }, { onProgress: progress => states.push(progress) });
    await h.controller.select("R", { readOnly: true });
    assert.deepEqual(calls, [{ url: "/human-workflow/runs/R/alerts", method: "GET" }]);
    assert.ok(states.some(state => state.entityId === "E" && state.alerts?.length === 1));
    h.node("refresh").listeners.click();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls.length, 2);
    assert.ok(calls.every(call => call.method === "GET"));
});

test("Task 5 review missing stored alerts do not imply a missing detection", async () => {
    const h = harness(async () => response({ items: [] }));
    await h.controller.select("R", { readOnly: true });
    assert.equal(h.node("status").textContent, "저장된 담당자 처리 알림 없음 · 분석 결과와 별도");
    assert.doesNotMatch(h.node("status").textContent, /탐지 결과 없음 또는 미평가/);
});

test("Task 5 progress publication reuses loaded workflow data without extra requests", async () => {
    const observed = [];
    async function run(withCallback) {
        const calls = [], value = detail("A", 0);
        const h = harness(async (url, options) => {
            calls.push([url, options?.method ?? "GET"]);
            return response(url.endsWith("/sync") ? { items: [value] }
                : url.endsWith("/report-drafts") ? { items: [] } : value);
        }, withCallback ? { onProgress: progress => observed.push(progress) } : {});
        await h.controller.select("R");
        await new Promise(resolve => setImmediate(resolve));
        return calls;
    }
    const withoutCallback = await run(false);
    const withCallback = await run(true);
    assert.deepEqual(withCallback, withoutCallback);
    assert.ok(observed.some(progress => progress.runId === "R" && progress.alerts === null));
    assert.ok(observed.some(progress => progress.entityId === "E" && progress.alerts?.[0].alert_id === "A"));
    assert.ok(withCallback.every(([url]) => !/\/actions|\/ai-report-drafts|\/report-snapshot-approvals/.test(url)));
});

test("AI click previews only; explicit snapshot consent and classification precede external generation", async () => {
    const value=detail("A",4);value.state.report_choice="proceed";
    const calls=[];const snapshot={snapshot_sha256:"a".repeat(64),workflow_version:4,external_transmission:"not_sent",endpoint:"https://monogpt.kr",request_body:"SAFE O1",word_reuse:null};
    const h=harness(async(url,options)=>{
        calls.push({url,options});
        return response(url.endsWith("/report-snapshot")?snapshot:url.endsWith("/report-snapshot-approvals")?{consent_id:"GRANT"}:url.endsWith("/ai-report-drafts")?{draft_id:"D",method:"monorouter_grounded",text:"관측 사실",generated_at:"2026-10-21T01:00:00Z",call_metadata:{status:"success",http_status:200},word_result:{status:"ready"}}:url.endsWith("/report-drafts")?{items:[]}:value);
    });
    await h.controller.open("A");await h.controller.previewSnapshot();
    assert.match(h.node("snapshot-request").textContent,/SAFE O1/);
    assert.equal(h.node("snapshot-consent").checked,false);
    await h.controller.generateApproved();assert.equal(calls.filter(x=>x.options.method==="POST").length,0);
    h.node("snapshot-type").value="other_hacking";h.node("snapshot-reason").value="확인한 검토용 유형";h.node("snapshot-consent").checked=true;
    await h.controller.generateApproved();
    const posts=calls.filter(x=>x.options.method==="POST");
    assert.equal(posts.length,2);assert.ok(posts[0].url.endsWith("report-snapshot-approvals"));
    assert.equal(JSON.parse(posts[0].options.body).snapshot_sha256,snapshot.snapshot_sha256);
    assert.equal(JSON.parse(posts[1].options.body).consent_id,"GRANT");
    assert.equal(JSON.parse(posts[1].options.body).word_inputs.incident_type,"other_hacking");
    assert.match(h.node("draft-status").textContent,/AI 작성 · 검증 통과/);
    assert.equal(h.node("snapshot-panel").hidden,true);
});

test("a late snapshot approval cannot send the previously selected Run after switching", async () => {
    const value=detail("A",4);value.state.report_choice="proceed";let resolveApproval;let sent=0;
    const h=harness(async(url,options)=>{
        if(url.endsWith("/report-snapshot"))return response({snapshot_sha256:"b".repeat(64),workflow_version:4,external_transmission:"not_sent",request_body:"O1"});
        if(url.endsWith("/report-snapshot-approvals"))return new Promise(resolve=>{resolveApproval=resolve;});
        if(url.endsWith("/ai-report-drafts")){sent++;throw Error("Must not send");}
        return response(url.endsWith("/report-drafts")||url.endsWith("/sync")?{items:[]}:value);
    });
    await h.controller.open("A");await h.controller.previewSnapshot();
    h.node("snapshot-type").value="other_hacking";h.node("snapshot-reason").value="분류 사유";h.node("snapshot-consent").checked=true;
    const pending=h.controller.generateApproved();await h.controller.select("other");
    resolveApproval(response({consent_id:"OLD"}));await pending;
    assert.equal(sent,0);assert.equal(h.node("snapshot-consent").checked,false);assert.equal(h.node("snapshot-panel").hidden,true);
});

test("ambiguous AI transport failure retries exactly the same approval and draft keys", async () => {
    const value=detail("A",4);value.state.report_choice="proceed";const bodies=[];
    const h=harness(async(url,options)=>{
        if(url.endsWith("/report-snapshot"))return response({snapshot_sha256:"c".repeat(64),workflow_version:4,external_transmission:"not_sent",request_body:"O1"});
        if(url.endsWith("/report-snapshot-approvals"))return response({consent_id:"SAME"});
        if(url.endsWith("/ai-report-drafts")){bodies.push(JSON.parse(options.body));throw Error("Disconnected");}
        return response(url.endsWith("/report-drafts")?{items:[]}:value);
    });
    await h.controller.open("A");await h.controller.previewSnapshot();h.node("snapshot-consent").checked=true;
    h.node("snapshot-type").value="other_hacking";h.node("snapshot-reason").value="분류 사유";
    await h.controller.generateApproved();await h.controller.generateApproved();
    assert.equal(bodies.length,2);assert.deepEqual(bodies[0],bodies[1]);
    assert.doesNotMatch(h.node("draft-status").textContent,/검증 통과/);
});

function harness(fetchImpl, options = {}) {
    const nodes = new Map();
    function element() {
        return { hidden: false, disabled: false, textContent: "", value: "", children: [],
            listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; },
            replaceChildren(...items) { this.children = items; },
            append(...items) { this.children.push(...items); } };
    }
    const document = { createElement: element, getElementById(id) {
        if (!nodes.has(id)) nodes.set(id, element());
        return nodes.get(id);
    } };
    const controller = createHumanWorkflowController(document, { fetchImpl, ...options });
    return { controller, document, node: name => document.getElementById(`workflow-${name}`) };
}
const response = (value, status = 200) => ({ ok: status < 400, status, json: async () => value });
const detail = (id = "A", version = 0) => ({ alert_id: id, run_id: "R", entity_id: "E",
    detected_at: "2026-09-27T01:00:00Z", issued_at: "2026-10-20T01:00:00Z",
    detection_kind: "fusion", source_snapshot: { context: "local_historical_development",
        source_path: "decision_runtime_snapshots.fusion_result", hybrid_status: "not_evaluated",
        evidence_ids: ["E1"], decision: { t_e: null } },
    state: { version, analyst_ack_time: null, evidence_reviewed_at: null },
    audit: [], operational_24h: { status: "no_awareness" } });

test("synthetic prose requires consent and passes its separate source to Word forms", async () => {
    const value = detail("A", 4); value.state.report_choice = "proceed";
    const calls = [], selected = [];
    const draft = {draft_id:"S",alert_id:"SYNTHETIC-OBS-ALERT-001",workflow_version:1,
        method:"monorouter_grounded",text:"합성 문서",call_metadata:{status:"success",http_status:200}};
    const h = harness(async (url, options) => {
        if (options.method === "POST" && url.includes("/reporting/synthetic/")) {
            calls.push(JSON.parse(options.body)); return response(draft);
        }
        return response(url.endsWith("/sync") ? {items:[value]} : url.endsWith("/reporting/status")
            ? {adapter:"configured",synthetic_transmission_enabled:true} : value);
    }, {onDraft: context => selected.push(context)});
    await h.controller.select("R"); await h.controller.open("A");
    await h.controller.generateSynthetic(); assert.equal(calls.length,0);
    h.node("synthetic-consent").checked = true;
    await h.controller.generateSynthetic();
    assert.equal(calls[0].fixture,"verified_observations_v1");
    assert.equal(calls[0].allow_external_synthetic,true);
    assert.equal(selected.at(-1).alertId,draft.alert_id);
    assert.equal(selected.at(-1).draft,draft);
});

test("late regular draft read cannot replace an explicitly selected synthetic source", async () => {
    const value = detail("A", 4); value.state.report_choice = "proceed";
    const selected = []; let resolveRegular;
    const synthetic = {draft_id:"S",alert_id:"SYNTHETIC-OBS-ALERT-001",workflow_version:1,
        method:"monorouter_grounded",text:"합성",call_metadata:{status:"success",http_status:200}};
    const h = harness(async (url, options) => {
        if(url.endsWith("/report-drafts")) return new Promise(resolve => { resolveRegular = resolve; });
        if(options.method === "POST" && url.includes("/reporting/synthetic/")) return response(synthetic);
        return response(url.endsWith("/sync") ? {items:[value]} : url.endsWith("/reporting/status")
            ? {adapter:"configured",synthetic_transmission_enabled:true} : value);
    }, {onDraft: context => selected.push(context)});
    await h.controller.select("R");
    const opening = h.controller.open("A"); await new Promise(resolve=>setImmediate(resolve));
    h.node("synthetic-consent").checked = true;
    await h.controller.generateSynthetic();
    resolveRegular(response({items:[{status:"completed",current:true,draft:{draft_id:"OLD",method:"jinja2_fallback",text:"old",call_metadata:{status:"blocked_data"}}}]}));
    await opening;
    assert.equal(selected.at(-1).draft.draft_id,"S");
    assert.ok(selected.includes(null));
});

test("real API paths and explicit separate fields; no automatic human actions", async () => {
    const calls = [];
    const h = harness(async (url, options) => {
        calls.push({ url, options });
        return response(url.endsWith("/sync") ? { items: [detail()] } : detail());
    });
    await h.controller.select("R");
    assert.equal(h.node("alerts").children.length, 1);
    assert.equal(calls.filter(c => c.url.endsWith("/sync")).length, 1);
    await h.controller.open("A");
    assert.equal(h.node("awareness").disabled, true);
    assert.match(h.node("source").textContent, /not_evaluated/);
    assert.match(h.node("state").textContent, /no_awareness/);
    assert.equal(calls.every(c => !c.url.endsWith("/actions")), true);
});

test("duplicate click suppressed and ambiguous failure retries same key", async () => {
    const bodies = [];
    let fail = true;
    let finish;
    const h = harness(async (url, options) => {
        if (!url.endsWith("/actions")) return response(detail());
        bodies.push(JSON.parse(options.body));
        if (fail) { fail = false; throw new Error("network interrupted"); }
        await new Promise(resolve => { finish = resolve; });
        return response(detail("A", 1));
    });
    await h.controller.open("A");
    await h.controller.act("acknowledge");
    const pending = h.controller.act("acknowledge");
    await h.controller.act("acknowledge");
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0].idempotency_key, bodies[1].idempotency_key);
    assert.equal(h.node("ack").disabled, true);
    finish();
    await pending;
    assert.match(h.node("action-status").textContent, /영속 저장/);
});

test("conflicts preserve input and instruct explicit refresh", async () => {
    const h = harness(async url => response(detail(), url.endsWith("/actions") ? 409 : 200));
    await h.controller.open("A");
    h.node("th-reason").value = "정정 사유";
    await h.controller.act("record_awareness", { t_h: "2026-10-20T01:00:00Z", reason: "정정 사유" });
    assert.match(h.node("action-status").textContent, /다시 조회/);
    assert.equal(h.node("th-reason").value, "정정 사유");
});

test("late responses from previous Run cannot restore stale records", async () => {
    let oldResponse;
    const h = harness(async url => {
        if (url.includes("old")) return new Promise(resolve => { oldResponse = resolve; });
        return response({ items: [] });
    });
    const first = h.controller.select("old");
    await h.controller.select("new");
    oldResponse(response({ items: [detail()] }));
    await first;
    assert.equal(h.node("alerts").children.length, 0);
    assert.equal(h.node("record").hidden, true);
});

test("server errors do not display a successful action", async () => {
    const h = harness(async url => response(detail(), url.endsWith("/actions") ? 503 : 200));
    await h.controller.open("A");
    await h.controller.act("review_evidence");
    assert.match(h.node("action-status").textContent, /서버 오류/);
    assert.doesNotMatch(h.node("action-status").textContent, /영속 저장/);
});

test("draft generation is disabled until proceed; requests have no client data classification", async () => {
    let current = detail();
    const calls = [];
    const h = harness(async (url, options) => {
        calls.push({ url, options });
        return response(url.endsWith("/report-drafts") ? {
            method: "jinja2_fallback", text: "검토 초안 · UNKNOWN · 제출되지 않음",
            call_metadata: { status: "disabled", actual_model: null },
        } : current);
    });
    await h.controller.open("A");
    assert.equal(h.node("draft-generate").disabled, true);
    await h.controller.generateDraft();
    assert.equal(calls.filter(c => c.options.method === "POST").length, 0);
    current = { ...detail("A", 5), state: { ...detail("A", 5).state, report_choice: "proceed" } };
    await h.controller.open("A");
    assert.equal(h.node("draft-generate").disabled, false);
    await h.controller.generateDraft();
    const command = JSON.parse(calls.at(-1).options.body);
    assert.deepEqual(Object.keys(command).sort(), ["expected_version", "idempotency_key"]);
    assert.equal(command.expected_version, 5);
    assert.match(h.node("draft-text").textContent, /UNKNOWN/);
    assert.match(h.node("draft-status").textContent, /대체 작성/);
    assert.doesNotMatch(h.node("draft-status").textContent, /AI 작성/);
});

test("saved draft history restores text and identifies an older workflow version", async () => {
    const h = harness(async url => response(url.endsWith("/report-drafts") ? { items: [{
        status: "completed", current: false, draft: { method: "jinja2_fallback", text: "저장된 초안",
            call_metadata: { status: "blocked_data" } },
    }] } : detail()));
    await h.controller.open("A");
    await h.controller.loadDrafts();
    assert.equal(h.node("draft-text").textContent, "저장된 초안");
    assert.match(h.node("draft-status").textContent, /이전 버전 초안/);
});

test("six-step timeline comes from stored actions and distinguishes verified adapter from fallback", async () => {
    const value = { ...detail("A",3), state: { version:3, analyst_ack_time:"2026-10-20T01:00:00Z",
        evidence_reviewed_at:"2026-10-20T01:01:00Z", t_h:null, report_choice:"proceed",report_decided_at:"2026-10-20T01:02:00Z" } };
    const h = harness(async url => response(url.endsWith("/sync") ? {items:[value]} :
        url.endsWith("/reporting/status") ? { adapter:"configured",connection_verification:{requested_at:"2026-10-20T01:00:00Z",actual_model:"claude-haiku-4-5-20251001"},synthetic_transmission_enabled:true } :
        url.endsWith("/report-drafts") ? {items:[{status:"completed",current:true,draft:{draft_id:"D",generated_at:"2026-10-20T01:03:00Z",method:"jinja2_fallback",text:"UNKNOWN",call_metadata:{status:"blocked_data"}},review:null}]} : value));
    await h.controller.select("R");
    await h.controller.open("A");
    // The six-step progress belongs to the case detail; the overview card shows only the current step.
    const steps=h.node("detail-timeline").children;
    assert.equal(steps.length,6);
    assert.deepEqual(steps.map(step=>step.dataset.state),["complete","complete","complete","pending","complete","partial"]);
    assert.equal(h.node("current").hidden,false);
    assert.equal(h.node("current-step").textContent,"4/6 · 인지 기록");
    // The count is scoped to the selected item, never a global queue.
    assert.equal(h.node("status").textContent,"선택 항목 미완료 알림 1건");
    assert.doesNotMatch(h.node("status").textContent,/데모/);
    assert.match(h.node("llm-status").textContent,/초안 작성 준비됨/);
    assert.match(h.node("transmission-status").textContent,/이 서버: 실제 데이터 외부 전송 차단/);
    assert.match(h.node("provider-detail").textContent,/claude-haiku-4-5-20251001/);
    assert.match(h.node("draft-status").textContent,/^저장 초안 · 대체 작성 \(실제 분석 외부 전송 차단\) · /);
    assert.doesNotMatch(h.node("draft-status").textContent,/AI 작성/);
    assert.match(h.node("draft-metadata").textContent,/blocked_data/);
    assert.match(h.node("next").textContent,/인지 기록/);
    // Only the executable next action is primary; completed actions are collapsed.
    assert.equal(h.node("awareness").dataset.next,"true");
    assert.equal(h.node("awareness").hidden,false);
    assert.equal(h.node("ack").hidden,true);
    assert.equal(h.node("review").hidden,true);
    assert.equal(h.node("draft-inspect").dataset.next,undefined);
    assert.equal(h.node("synthetic-generate").disabled,true);
    assert.equal(h.node("correction-panel").hidden,true);
});

test("follow-up actions stay collapsed until the stored state allows them", async () => {
    let value = { ...detail("A",3), state: { version:3, analyst_ack_time:"2026-10-20T01:00:00Z",
        evidence_reviewed_at:"2026-10-20T01:01:00Z", t_h:"2026-10-20T01:02:00Z",
        t_h_recorded_at:"2026-10-20T01:02:00Z", report_choice:null } };
    let drafts = [];
    const h = harness(async url => response(url.endsWith("/sync") ? {items:[value]} : url.endsWith("/reporting/status")
        ? {adapter:"configured"} : url.endsWith("/report-drafts") ? {items:drafts} : value));
    await h.controller.select("R");
    await h.controller.open("A");
    assert.equal(h.node("report-panel").dataset.next,"true");
    assert.equal(h.node("draft-generate").hidden,true);
    assert.equal(h.node("draft-review").hidden,true);
    assert.equal(h.node("draft-load").hidden,false);
    assert.match(h.node("compose-note").textContent,/신고 진행 결정 후/);
    assert.match(h.node("next").textContent,/신고 검토 진행/);
    value = { ...value, state: { ...value.state, version:4, report_choice:"proceed", report_decided_at:"2026-10-20T01:03:00Z" } };
    drafts = [{status:"completed",current:true,review:null,draft:{draft_id:"D",generated_at:"2026-10-20T01:04:00Z",
        method:"jinja2_fallback",text:"UNKNOWN",call_metadata:{status:"disabled",requested_at:null}}}];
    await h.controller.open("A");
    // Reading the draft is the primary step; its review record waits at the end of the preview.
    assert.equal(h.node("draft-inspect").dataset.next,"true");
    assert.equal(h.node("draft-inspect").hidden,false);
    assert.equal(h.node("draft-review").hidden,false);
    assert.equal(h.node("draft-generate").hidden,false);
    assert.equal(h.node("draft-generate").dataset.next,undefined);
    assert.equal(h.node("report-panel").dataset.next,undefined);
    assert.equal(h.node("current-step").textContent,"6/6 · 초안·검토 · 검토 전");
    assert.equal(h.node("next").dataset.tone,"primary");
    assert.match(h.node("draft-status").textContent,/대체 작성 \(외부 호출 없음\)/);
});

test("one-click awareness sends explicit mode and never a browser timestamp", async () => {
    let value={...detail("A",2),state:{version:2,analyst_ack_time:"2026-10-20T01:00:00Z",evidence_reviewed_at:"2026-10-20T01:01:00Z",t_h:null}};
    let command;
    const h=harness(async (url,options)=>{
        if(url.endsWith("/report-drafts"))return response({items:[]});
        if(url.endsWith("/actions")){
            command=JSON.parse(options.body);
            value={...value,state:{...value.state,version:3,t_h:"2026-10-20T02:00:00.123Z",t_h_recorded_at:"2026-10-20T02:00:00.123Z"}};
        }
        return response(value);
    });
    await h.controller.open("A");
    h.node("awareness").listeners.click();
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(command.awareness_mode,"now");
    assert.equal("t_h" in command,false);
    assert.equal(h.node("awareness").disabled,true);
    assert.equal(h.node("correction-panel").hidden,false);
});

test("Awareness rendering retains distinct source times and the original audit without actions", async () => {
    // Given
    const value = detail("A", 3);
    value.state = { ...value.state, t_h: "2026-10-20T00:00:00Z", t_h_recorded_at: "2026-10-21T04:47:24.708123Z" };
    value.audit = [{ version: 3, recorded_at: value.state.t_h_recorded_at }];
    const calls = [];
    const h = harness(async (url, options) => {
        calls.push({ url, options });
        return response(url.endsWith("/report-drafts") ? { items: [] } : value);
    });
    // When
    await h.controller.open("A");
    // Then
    const step = h.node("detail-timeline").children[3];
    assert.equal(step.dataset.state, "complete");
    assert.match(step.children[1].title, /2026-10-21T04:47:24\.708123Z/);
    assert.doesNotMatch(step.children[1].title, /2026-10-20/);
    assert.match(h.node("human-summary").textContent, /내부 인지시각 .*기록시각/);
    const summary = h.node("state-summary").children.map(node => node.textContent).join("\n");
    assert.match(summary, /2026-10-20T00:00:00Z/);
    assert.match(summary, /2026-10-21T04:47:24\.708123Z/);
    assert.equal(h.node("audit").textContent, JSON.stringify(value.audit, null, 2));
    assert.equal(calls.some(call => call.options.method === "POST"), false);
});

test("A past awareness with no recording time needs checking even after reporting proceeds", async () => {
    // Given
    const value = detail("A", 4);
    value.state = { ...value.state, t_h: "2026-10-20T00:00:00Z", t_h_recorded_at: null,
        report_choice: "proceed", report_decided_at: "2026-10-21T04:00:00Z" };
    const h = harness(async url => response(url.endsWith("/report-drafts") ? { items: [] } : value));
    // When
    await h.controller.open("A");
    // Then
    assert.equal(h.node("detail-timeline").children[3].dataset.state, "incomplete");
    assert.equal(h.node("detail-timeline").children[3].children[1].title, "미기록");
    assert.match(h.node("human-summary").textContent, /기록시각 미기록/);
});

for (const [t_h, t_h_recorded_at, expectedStep, expectedNext] of [
    [null, null, "pending", "인지 기록 진행 →"],
    ["2026-10-20T00:00:00Z", null, "incomplete", "인지 기록 상태 확인 →"],
    [null, "2026-10-21T04:47:24.708123Z", "incomplete", "인지 기록 상태 확인 →"],
    ["2026-10-20T00:00:00Z", "2026-10-21T04:47:24.708123Z", "complete", "신고서 내용 확인·보완 →"],
]) {
    test(`Timeline and next navigation agree without writes: ${expectedStep} ${Boolean(t_h)}`, async () => {
        const value = detail("A", 4);
        value.state = {...value.state, analyst_ack_time: "2026-10-21T04:00:00Z",
            evidence_reviewed_at: "2026-10-21T04:01:00Z", t_h, t_h_recorded_at,
            report_choice: "proceed", report_decided_at: "2026-10-21T04:02:00Z"};
        value.audit = [{version: 4, action: "decide_reporting", recorded_at: value.state.report_decided_at}];
        const original = JSON.stringify(value), calls = [];
        const entry = {status: "completed", current: true, review: null,
            draft: {draft_id: "D", method: "jinja2_fallback", generated_at: "2026-10-21T04:03:00Z", text: "저장된 초안"}};
        const h = harness(async (url, options) => {
            calls.push({url, options});
            return response(url.endsWith("/report-drafts") ? {items: [entry]} : value);
        });
        const panel = {open: false};
        let focused = false;
        h.node("state-summary").closest = selector => selector === "details" ? panel : null;
        h.node("state-summary").focus = () => { focused = true; };
        await h.controller.open("A");
        const row = h.node("detail-timeline").children[3];
        assert.equal(row.dataset.state, expectedStep);
        assert.equal(h.node("next").textContent, expectedNext);
        assert.equal(h.node("detail-timeline").children[4].dataset.state, "complete");
        assert.equal(h.node("draft-generate").disabled, false);
        await h.node("next").listeners.click();
        if (expectedStep === "incomplete") {
            assert.equal(h.node("current-step").textContent, "4/6 · 인지 기록 상태 확인");
            assert.equal(row.children[1].textContent, "확인 필요");
            assert.equal(panel.open, true);
            assert.equal(focused, true);
            assert.equal(h.node("state-summary").tabIndex, -1);
            assert.notEqual(h.node("awareness").dataset.next, "true");
        }
        assert.equal(calls.some(call => call.options.method === "POST"), false);
        assert.equal(JSON.stringify(value), original);
        assert.equal(h.node("audit").textContent, JSON.stringify(value.audit, null, 2));
    });
}

for (const recordedOnly of [false, true]) {
    for (const reportChoice of [null, "hold", "do_not_proceed"]) {
        test(`Incomplete awareness stays inspectable with independent reporting: ${recordedOnly} ${reportChoice}`, async () => {
            const value = detail("A", 4);
            value.state = {...value.state, analyst_ack_time: "2026-10-21T04:00:00Z",
                evidence_reviewed_at: "2026-10-21T04:01:00Z",
                t_h: recordedOnly ? null : "2026-10-20T00:00:00Z",
                t_h_recorded_at: recordedOnly ? "2026-10-21T04:02:00Z" : null,
                report_choice: reportChoice, report_decided_at: reportChoice ? "2026-10-21T04:03:00Z" : null};
            const original = JSON.stringify(value);
            const entry = {status: "completed", current: true, review: {reviewed_at: "2026-10-21T04:05:00Z"},
                draft: {draft_id: "D", generated_at: "2026-10-21T04:04:00Z", text: "저장된 이력", method: "jinja2_fallback"}};
            const h = harness(async url => response(url.endsWith("/report-drafts") ? {items: [entry]} : value));
            await h.controller.open("A");
            assert.equal(h.node("current-step").textContent, "4/6 · 인지 기록 상태 확인");
            assert.equal(h.node("next").textContent, "인지 기록 상태 확인 →");
            assert.equal(h.node("detail-timeline").children[3].dataset.state, "incomplete");
            assert.equal(h.node("detail-timeline").children[4].dataset.state, reportChoice ? "complete" : "pending");
            assert.equal(h.node("detail-timeline").children[5].dataset.state, "complete");
            assert.equal(h.node("draft-text").textContent, "저장된 이력");
            assert.equal(JSON.stringify(value), original);
        });
    }
}

// One-click report UX: the operator chooses a form type and approves; nothing else is typed.
const PHRASES = ["PowerShell 인코딩 명령 옵션 사용", "스크립트 인터프리터의 외부 주소 연결"];
const ready = (id = "A", version = 6) => ({ ...detail(id, version), state: { version, analyst_ack_time: "2026-10-21T01:00:00Z",
    evidence_reviewed_at: "2026-10-21T01:01:00Z", t_h: "2026-10-21T01:02:00Z", t_h_recorded_at: "2026-10-21T01:02:00Z",
    report_choice: "proceed", report_decided_at: "2026-10-21T01:03:00Z" } });
const preview = (version = 6, extra = {}) => ({ snapshot_sha256: "d".repeat(64), workflow_version: version, external_transmission: "not_sent",
    endpoint: "https://monogpt.kr", request_body: "O1 O2", word_reuse: null,
    request: { messages: [{ content: JSON.stringify({ observations: PHRASES.map((fact_phrase, i) => ({ reference: `O${i + 1}`, fact_phrase })) }) }] }, ...extra });
const aiDraft = (extra = {}) => ({ draft_id: "D", method: "monorouter_grounded", text: "관측 사실", generated_at: "2026-10-21T01:05:00Z",
    call_metadata: { status: "success", http_status: 200 }, word_result: { status: "ready" }, ...extra });
const summaryText = h => h.node("report-summary").children.map(child => child.textContent).join("\n");
const chooseType = (h, value) => h.node("snapshot-type-group").listeners.change({ target: { type: "radio", checked: true, value } });
const settle = () => new Promise(resolve => setImmediate(resolve));
function reportHarness(routes = {}) {
    const calls = [];
    const value = routes.value ?? ready();
    const h = harness(async (url, options = {}) => {
        calls.push({ url, options });
        for (const [suffix, reply] of Object.entries(routes)) {
            if (suffix !== "value" && url.endsWith(suffix)) return typeof reply === "function" ? reply(url, options) : response(reply);
        }
        if (url.endsWith("/report-drafts")) return response({ items: [] });
        return response(value);
    });
    return { ...h, calls, posts: () => calls.filter(call => call.options.method === "POST") };
}

test("Proceeding case shows read-only eligibility and verified basis before any approval", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview() });
    // When
    await h.controller.open("A");
    await settle();
    // Then
    const summary = summaryText(h);
    assert.doesNotMatch(summary, /R · 대상 E|공란/);
    assert.match(summary, /원본 검증 관측 2건 · PowerShell 인코딩 명령 옵션 사용, 스크립트 인터프리터의 외부 주소 연결/);
    assert.match(summary, /자동 작성\n가능\n/);
    assert.equal(h.node("draft-generate").disabled, false);
    assert.equal(h.node("draft-generate").textContent, "AI 신고서 초안 생성");
    assert.equal(h.posts().length, 0);
});

test("Ineligible case disables AI generation and states the reason without sending", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": () => response({ detail: "not eligible" }, 422) });
    // When
    await h.controller.open("A");
    await settle();
    await h.controller.generateApproved();
    // Then
    assert.equal(h.node("draft-generate").disabled, true);
    assert.match(summaryText(h), /불가 · 원본 검증된 정식 분석 관측이 없거나/);
    assert.equal(h.posts().length, 0);
});

test("Before a proceed decision no preview is requested and generation stays disabled", async () => {
    // Given
    const value = { ...ready(), state: { ...ready().state, report_choice: null, report_decided_at: null } };
    const h = reportHarness({ value });
    // When
    await h.controller.open("A");
    // Then
    assert.equal(h.calls.some(call => call.url.endsWith("/report-snapshot")), false);
    assert.equal(h.node("draft-generate").disabled, true);
    assert.match(summaryText(h), /신고 진행 결정 후 가능/);
});

test("One type click and one approval send the existing approval and draft requests only", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview(), "/report-snapshot-approvals": { consent_id: "GRANT" }, "/ai-report-drafts": aiDraft() });
    await h.controller.open("A");
    await h.controller.previewSnapshot();
    // When
    chooseType(h, "other_hacking");
    h.node("snapshot-consent").checked = true;
    await h.controller.generateApproved();
    // Then
    const posts = h.posts();
    assert.deepEqual(posts.map(post => post.url.split("/").at(-1)), ["report-snapshot-approvals", "ai-report-drafts"]);
    const body = JSON.parse(posts[1].options.body);
    assert.equal(body.consent_id, "GRANT");
    assert.deepEqual(Object.keys(body.word_inputs).sort(), ["classification_reason", "expected_form_version",
        "expected_workflow_version", "idempotency_key", "incident_type"]);
    assert.equal(body.word_inputs.incident_type, "other_hacking");
    assert.match(body.word_inputs.classification_reason, /'그 밖의 해킹' 양식을 직접 선택.*PowerShell 인코딩 명령 옵션 사용/);
    assert.match(h.node("draft-status").textContent, /AI 작성 · 검증 통과.* · Word 생성 완료$/);
    assert.equal(h.node("snapshot-panel").hidden, true);
    assert.equal(h.node("snapshot-type").value, "undetermined");
});

test("An explicit reason is kept verbatim instead of the recorded selection text", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview(), "/report-snapshot-approvals": { consent_id: "GRANT" }, "/ai-report-drafts": aiDraft() });
    await h.controller.open("A");
    await h.controller.previewSnapshot();
    // When
    chooseType(h, "ransomware");
    h.node("snapshot-reason").value = "  담당자 직접 사유  ";
    h.node("snapshot-consent").checked = true;
    await h.controller.generateApproved();
    // Then
    const body = JSON.parse(h.posts()[1].options.body);
    assert.equal(body.word_inputs.incident_type, "ransomware");
    assert.equal(body.word_inputs.classification_reason, "담당자 직접 사유");
});

test("Without a type choice the approval is not sent and the operator is told why", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview() });
    await h.controller.open("A");
    await h.controller.previewSnapshot();
    // When
    h.node("snapshot-consent").checked = true;
    await h.controller.generateApproved();
    // Then
    assert.equal(h.posts().length, 0);
    assert.equal(h.node("snapshot-generate").disabled, true);
    assert.match(h.node("draft-status").textContent, /사고 유형을 선택하세요 · 아직 전송하지 않았습니다/);
});

test("Rapid repeated clicks create one approval and one draft request", async () => {
    // Given
    let finish;
    const h = reportHarness({ "/report-snapshot": preview(), "/report-snapshot-approvals": { consent_id: "GRANT" },
        "/ai-report-drafts": () => new Promise(resolve => { finish = () => resolve(response(aiDraft())); }) });
    await h.controller.open("A");
    await h.controller.previewSnapshot();
    chooseType(h, "other_hacking");
    h.node("snapshot-consent").checked = true;
    // When
    const first = h.controller.generateApproved();
    await h.controller.generateApproved();
    await h.controller.generateApproved();
    await settle();
    finish();
    await first;
    // Then
    assert.equal(h.posts().length, 2);
    assert.match(h.node("draft-status").textContent, /Word 생성 완료/);
});

test("A rejected AI wording is shown as not verified and never as a Word success", async () => {
    // Given
    const fallback = aiDraft({ method: "jinja2_fallback", call_metadata: { status: "invalid_output", requested_at: "2026-10-21T01:04:00Z" },
        word_result: { status: "not_prepared" } });
    const h = reportHarness({ "/report-snapshot": preview(), "/report-snapshot-approvals": { consent_id: "GRANT" }, "/ai-report-drafts": fallback });
    await h.controller.open("A");
    await h.controller.previewSnapshot();
    chooseType(h, "other_hacking");
    h.node("snapshot-consent").checked = true;
    // When
    await h.controller.generateApproved();
    // Then
    const status = h.node("draft-status").textContent;
    assert.match(status, /AI 초안 검증 미통과\(AI 출력 검증 실패\) · 검증되지 않은 내용은 Word에 기입하지 않았습니다/);
    assert.doesNotMatch(status, /검증 통과|Word 생성 완료/);
});

test("Closing the confirmation sends nothing and resets the choice", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview() });
    await h.controller.open("A");
    await h.controller.previewSnapshot();
    chooseType(h, "ddos");
    h.node("snapshot-consent").checked = true;
    // When
    h.node("snapshot-cancel").listeners.click();
    await h.controller.generateApproved();
    // Then
    assert.equal(h.posts().length, 0);
    assert.equal(h.node("snapshot-panel").hidden, true);
    assert.equal(h.node("snapshot-consent").checked, false);
    assert.equal(h.node("snapshot-type").value, "undetermined");
    assert.match(h.node("draft-status").textContent, /전송하지 않고 닫았습니다/);
});

test("A restored current draft makes regeneration secondary and keeps the stored draft", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview(), "/report-drafts": { items: [{ status: "completed", current: true, review: null, draft: aiDraft({ word_result: undefined }) }] } });
    // When
    await h.controller.open("A");
    // Then
    assert.equal(h.node("draft-generate").textContent, "AI 초안 다시 생성");
    assert.equal(h.node("draft-generate").dataset.next, undefined);
    assert.equal(h.node("draft-inspect").dataset.next, "true");
    assert.match(h.node("draft-status").textContent, /AI 작성 · 검증 통과/);
    assert.equal(h.posts().length, 0);
});

test("A late eligibility answer for the previous Run never fills the new selection", async () => {
    // Given
    let answer;
    const h = reportHarness({ "/report-snapshot": () => new Promise(resolve => { answer = resolve; }), "/sync": { items: [] } });
    await h.controller.open("A");
    // When
    await h.controller.select("OTHER");
    answer(response(preview()));
    await settle();
    // Then
    assert.equal(h.node("report-summary").children.length, 0);
    assert.equal(h.node("record").hidden, true);
});

// Task 4: one primary action, selected-item counts and human decisions that end the reporting path.
const NEXT_CANDIDATES = ["ack", "review", "awareness", "report-panel", "draft-generate", "draft-inspect"];
const primaries = h => NEXT_CANDIDATES.filter(name => h.node(name).dataset?.next === "true");

test("Task 4 hold and do-not-proceed never push drafting; only a hold invites a renewed review", async () => {
    for (const [choice, nextText, tone, stepText, current, status] of [
        ["hold", "보류 중 · 신고 검토 다시 확인 →", "primary", "신고 보류 · 작성 대상 아님", "신고 보류 · 초안 작성 대상 아님", "선택 항목 미완료 알림 1건"],
        ["do_not_proceed", "처리 기록 확인 →", "secondary", "신고 진행 안 함 · 작성 대상 아님", "신고 진행 안 함 · 초안 작성 대상 아님", "선택 항목 알림 처리 기록됨"],
    ]) {
        // Given
        const value = { ...ready(), state: { ...ready().state, report_choice: choice } };
        const original = JSON.stringify(value);
        const h = reportHarness({ value, "/sync": { items: [value] } });
        // When
        await h.controller.select("R");
        await h.controller.open("A");
        await h.node("next").listeners.click();
        // Then
        const step = h.node("detail-timeline").children[5];
        assert.equal(step.children[0].textContent, "초안·검토");
        assert.equal(step.dataset.state, "not_applicable");
        assert.equal(step.children[1].textContent, stepText);
        assert.equal(h.node("current-step").textContent, current);
        assert.equal(h.node("next").textContent, nextText);
        assert.equal(h.node("next").dataset.tone, tone);
        assert.equal(h.node("draft-generate").hidden, true);
        assert.deepEqual(primaries(h), choice === "hold" ? ["report-panel"] : []);
        assert.equal(h.node("status").textContent, status);
        assert.equal(h.calls.some(call => call.url.endsWith("/report-snapshot")), false);
        assert.deepEqual(h.posts().map(post => post.url.split("/").at(-1)), ["sync"]);
        assert.equal(JSON.stringify(value), original);
    }
});

test("Task 4 the draft step separates written, review-pending, reviewed and previous drafts with one primary", async () => {
    const cases = [
        [[], "초안 없음", ["draft-generate"], "신고서 초안 생성 →", "primary", false],
        [[{ status: "completed", current: true, review: null, draft: aiDraft() }], "작성됨 · 검토 전", ["draft-inspect"], "신고서 내용 확인·보완 →", "primary", true],
        [[{ status: "completed", current: true, review: { reviewed_at: "2026-10-21T01:06:00Z" }, draft: aiDraft() }], "검토 완료", [], "작성된 신고서 확인 →", "secondary", false],
        [[{ status: "completed", current: false, review: null, draft: aiDraft() }], "이전 버전", ["draft-generate"], "신고서 초안 생성 →", "primary", false],
    ];
    for (const [items, stepText, primary, nextText, tone, reviewShown] of cases) {
        // Given / When
        const h = reportHarness({ "/report-snapshot": preview(), "/report-drafts": { items } });
        await h.controller.open("A");
        await settle();
        // Then: an AI draft never stands in for the human review record.
        assert.equal(h.node("detail-timeline").children[5].children[1].textContent, stepText);
        assert.deepEqual(primaries(h), primary);
        assert.equal(h.node("next").textContent, nextText);
        assert.equal(h.node("next").dataset.tone, tone);
        assert.equal(h.node("draft-inspect").hidden, !reviewShown);
        assert.equal(h.node("draft-review").hidden, !reviewShown);
        assert.equal(h.node("compose-note").hidden, true);
        assert.equal(h.posts().length, 0);
    }
});

test("Task 4 reading the draft opens the preview without recording a review", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview(), "/report-drafts": { items: [{ status: "completed", current: true, review: null, draft: aiDraft() }] } });
    let focused = 0;
    h.node("draft-preview").querySelector = selector => selector === "summary" ? { focus: () => { focused += 1; } } : null;
    await h.controller.open("A");
    // When
    h.node("draft-inspect").listeners.click();
    await h.node("next").listeners.click();
    // Then
    assert.equal(h.node("draft-preview").open, true);
    assert.equal(focused, 2);
    assert.equal(h.posts().length, 0);
    assert.equal(h.node("draft-review").disabled, false);
});

test("Task 4 a synthetic draft in the form never offers this case's review controls", async () => {
    // Given
    const value = ready();
    const synthetic = { draft_id: "S", alert_id: "SYNTHETIC-OBS-ALERT-001", workflow_version: 1, method: "monorouter_grounded",
        text: "합성", call_metadata: { status: "success", http_status: 200 } };
    const h = reportHarness({ value, "/sync": { items: [value] }, "/reporting/status": { adapter: "configured", synthetic_transmission_enabled: true },
        "synthetic/A/drafts": synthetic, "/report-drafts": { items: [{ status: "completed", current: true, review: null, draft: aiDraft() }] } });
    await h.controller.select("R");
    await h.controller.open("A");
    assert.equal(h.node("draft-review").hidden, false);
    // When
    h.node("synthetic-consent").checked = true;
    await h.controller.generateSynthetic();
    // Then
    assert.equal(h.node("draft-inspect").hidden, true);
    assert.equal(h.node("draft-review").hidden, true);
    assert.equal(h.posts().some(post => post.url.endsWith("/review")), false);
});

test("Task 4 the legal-awareness caveat is shown exactly while the awareness record is available", async () => {
    // Given
    let value = { ...detail("A", 2), state: { version: 2, analyst_ack_time: "2026-10-20T01:00:00Z", evidence_reviewed_at: "2026-10-20T01:01:00Z", t_h: null } };
    const h = harness(async url => response(url.endsWith("/report-drafts") ? { items: [] } : value));
    // When / Then
    await h.controller.open("A");
    assert.equal(h.node("awareness").hidden, false);
    assert.equal(h.node("awareness-note").hidden, false);
    value = { ...value, state: { ...value.state, version: 3, t_h: "2026-10-20T00:00:00Z", t_h_recorded_at: "2026-10-21T04:47:24.708Z" } };
    await h.controller.open("A");
    assert.equal(h.node("awareness").hidden, true);
    assert.equal(h.node("awareness-note").hidden, true);
    assert.equal(h.node("correction-panel").hidden, false);
    assert.match(h.node("human-summary").textContent, /^내부 인지시각 2026\.10\.20.* · 기록시각 2026\.10\.21/);
});

test("Task 4 alert counts are scoped to the selected item and never presented as a demo or global queue", async () => {
    // Given
    const first = ready("A"), second = detail("B", 1);
    const closed = { ...ready("C"), state: { ...ready("C").state, report_choice: "do_not_proceed" } };
    const h = harness(async url => response(url.endsWith("/sync") ? { items: [first, second, closed] } : url.endsWith("/report-drafts") ? { items: [] } : first));
    // When
    await h.controller.select("R");
    await settle();
    // Then
    assert.equal(h.node("status").textContent, "선택 항목 알림 3건 중 미완료 2건");
    assert.doesNotMatch(h.node("status").textContent, /데모|처리 대기/);
});

test("Task 4 the environment badge appears only after the local-actor API answers", async () => {
    for (const [status, hidden] of [[200, false], [503, true]]) {
        // Given
        const value = ready();
        const h = harness(async url => url.endsWith("/reporting/status") ? response({ adapter: "configured" }, status)
            : response(url.endsWith("/sync") ? { items: [value] } : url.endsWith("/report-drafts") ? { items: [] } : value));
        const badge = h.document.getElementById("operator-demo-badge");
        badge.hidden = true;
        // When
        await h.controller.select("R");
        await settle();
        // Then
        assert.equal(badge.hidden, hidden);
    }
});

test("Task 6 the report workspace, audit trail and developer tools belong to one opened alert", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview(), "/alerts": { items: [ready()] } });
    const areas = () => ["record", "compose", "history", "dev-tools"].map(name => h.node(name).hidden);
    // When
    await h.controller.select("R", { readOnly: true });
    const passive = areas();
    await h.controller.open("A");
    const opened = areas();
    await h.controller.select("OTHER", { readOnly: true });
    // Then
    assert.deepEqual(passive, [true, true, true, true]);
    assert.deepEqual(opened, [false, false, false, true]);
    assert.deepEqual(areas(), [true, true, true, true]);
    assert.equal(h.posts().length, 0);
});

test("Task 6 an open preview or approval holds its own primary, so the opener steps back", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview(), "/report-drafts": { items: [{ status: "completed", current: true, review: null, draft: aiDraft() }] } });
    await h.controller.open("A");
    assert.deepEqual(primaries(h), ["draft-inspect"]);
    // When: the preview is opened by the person (toggle), nothing is recorded.
    h.node("draft-preview").open = true;
    h.node("draft-preview").listeners.toggle();
    // Then
    assert.deepEqual(primaries(h), []);
    assert.equal(h.node("draft-review").hidden, false);
    assert.equal(h.node("draft-review").disabled, false);
    assert.equal(h.calls.some(call => call.url.includes("/review")), false);
    assert.equal(h.posts().length, 0);
    h.node("draft-preview").open = false;
    h.node("draft-preview").listeners.toggle();
    assert.deepEqual(primaries(h), ["draft-inspect"]);
});

test("Task 6 the approval panel replaces the drafting primary until it is closed without sending", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview() });
    await h.controller.open("A");
    assert.deepEqual(primaries(h), ["draft-generate"]);
    // When
    await h.controller.previewSnapshot();
    const whileApproving = primaries(h);
    h.node("snapshot-cancel").listeners.click();
    // Then
    assert.deepEqual(whileApproving, []);
    assert.equal(h.node("snapshot-generate").disabled, true, "Approval is never preselected");
    assert.deepEqual(primaries(h), ["draft-generate"]);
    assert.equal(h.posts().length, 0);
});

// Review: the five states of the current-task area. Values below come from stored reads only.
const steps = h => h.node("detail-timeline").children.map(item => item.children[1].textContent);
const guidance = h => h.node("guidance").textContent;
const current = (version = 6) => ({ items: [{ status: "completed", current: true, review: null, document_version: 5, draft: aiDraft({ workflow_version: version }) }] });

test("Review 1/3: before an alert is opened the drafts are named unread and no hidden control is requested", async () => {
    // Given: passive selection reads stored alerts only.
    const value = ready();
    const h = reportHarness({ value, "/alerts": { items: [value] } });
    // When
    await h.controller.select("R", { readOnly: true });
    // Then
    assert.deepEqual([h.node("next").textContent, h.node("next").dataset.tone, h.node("next").disabled], ["알림 열기 · 저장 초안 확인 →", "primary", false]);
    assert.equal(steps(h)[5], "미조회");
    assert.equal(guidance(h), "저장 초안 미조회");
    assert.equal(h.node("action-status").textContent, "");
    assert.ok(h.calls.every(call => call.url.endsWith("/runs/R/alerts")), "No draft list, alert detail or write before opening");
});

test("Review 2: a draft list read without opening the alert names the stored draft", async () => {
    // Given: the explicit alert-preparation path reads progress for the first alert.
    const value = ready();
    const h = reportHarness({ value, "/sync": { items: [value] }, "/report-drafts": current(), "/reporting/status": { adapter: "configured" } });
    // When
    await h.controller.select("R");
    await settle();
    // Then
    assert.equal(h.node("next").textContent, "신고서 내용 확인·보완 →");
    assert.equal(steps(h)[5], "작성됨 · 검토 전");
    assert.match(guidance(h), /저장 초안 확인됨/);
    assert.equal(h.node("compose").hidden, true, "Nothing is opened by the read");
});

test("Review 3: with several alerts and none opened the guidance points to the visible list", async () => {
    // Given
    const h = reportHarness({ "/alerts": { items: [ready("A"), ready("B")] } });
    // When
    await h.controller.select("R", { readOnly: true });
    // Then
    assert.equal(h.node("alerts").hidden, false);
    assert.match(guidance(h), /알림 2건 · 상단 목록에서 처리할 알림을 열 수 있습니다/);
});

test("Review 4: once the alert and its drafts are read, the stale prompts are gone", async () => {
    // Given
    let release;
    const value = ready();
    const h = reportHarness({ value, "/alerts": { items: [value] }, "/report-snapshot": preview(),
        "/report-drafts": () => new Promise(resolve => { release = () => resolve(response(current())); }) });
    await h.controller.select("R", { readOnly: true });
    // When: the alert is open but its draft list is still being read.
    const opening = h.controller.open("A");
    await settle();
    const during = [h.node("next").textContent, h.node("next").disabled, steps(h)[5], guidance(h)];
    release();
    await opening;
    // Then
    assert.deepEqual(during, ["알림·저장 초안 조회 중", true, "조회 중", "알림·저장 초안 조회 중"]);
    assert.equal(h.node("next").textContent, "신고서 내용 확인·보완 →");
    assert.equal(h.node("next").disabled, false);
    assert.equal(h.node("current-step").textContent, "6/6 · 초안·검토 · 검토 전");
    assert.equal(guidance(h), "");
    assert.equal(h.node("action-status").textContent, "");
    assert.equal(h.posts().length, 0);
});

test("Review 4: re-opening the same alert keeps the known draft while it is read again", async () => {
    // Given
    let hold = false, release;
    const value = ready();
    const h = reportHarness({ value, "/alerts": { items: [value] }, "/report-snapshot": preview(),
        "/report-drafts": () => hold ? new Promise(resolve => { release = () => resolve(response(current())); }) : response(current()) });
    await h.controller.select("R", { readOnly: true });
    await h.controller.open("A");
    // When: 상태 새로고침 re-reads the same alert version.
    hold = true;
    h.node("refresh").listeners.click();
    await settle();
    // Then
    assert.equal(h.node("next").textContent, "신고서 내용 확인·보완 →");
    assert.equal(steps(h)[5], "작성됨 · 검토 전");
    release();
    await settle();
    assert.equal(h.node("next").textContent, "신고서 내용 확인·보완 →");
});

test("Review 5: failed reads are named as failures, never as missing drafts or missing alerts", async () => {
    // Given
    const value = ready();
    const h = reportHarness({ value, "/alerts": { items: [value] }, "/report-drafts": () => response({ detail: "unavailable" }, 503) });
    await h.controller.select("R", { readOnly: true });
    // When
    await h.controller.open("A");
    // Then
    assert.equal(h.node("next").textContent, "저장 초안 다시 조회 →");
    assert.equal(steps(h)[5], "조회 실패");
    assert.match(guidance(h), /저장 초안 조회 실패/);
    assert.doesNotMatch(steps(h)[5], /초안 없음/);
    assert.equal(h.posts().length, 0);
    const known = reportHarness({ value, "/alerts": { items: [value] } });
    await known.controller.open("A");
    assert.equal(known.node("next").textContent, "신고서 초안 생성 →", "A confirmed empty list still leads to drafting");
    const broken = reportHarness({ "/alerts": () => response({ detail: "unavailable" }, 503) });
    await broken.controller.select("R", { readOnly: true });
    assert.equal(broken.node("next").hidden, true);
    assert.match(guidance(broken), /알림을 조회하지 못했습니다/);
    const none = reportHarness({ "/alerts": { items: [] } });
    await none.controller.select("R", { readOnly: true });
    assert.equal(guidance(none), "처리할 담당자 알림이 없습니다.");
});

test("Review hold and do-not-proceed keep their own next step whether or not drafts were read", async () => {
    for (const [choice, label] of [["hold", "보류 중 · 신고 검토 다시 확인 →"], ["do_not_proceed", "처리 기록 확인 →"]]) {
        // Given
        const value = { ...ready(), state: { ...ready().state, report_choice: choice } };
        const h = reportHarness({ value, "/alerts": { items: [value] } });
        // When
        await h.controller.select("R", { readOnly: true });
        // Then
        assert.equal(h.node("next").textContent, label);
        assert.match(steps(h)[5], /작성 대상 아님/);
        assert.equal(guidance(h), "");
        assert.equal(h.posts().length, 0);
    }
});

test("Review a pending draft from the previous Run never makes the new selection appear to be loading", async () => {
    // Given
    let release;
    const value = ready();
    const h = reportHarness({ value, "/alerts": { items: [value] }, "/report-snapshot": preview(),
        "/report-drafts": () => new Promise(resolve => { release = () => resolve(response(current())); }) });
    await h.controller.select("R", { readOnly: true });
    const oldRead = h.controller.open("A");
    await settle();
    // When: this selection has not opened an alert or requested its drafts.
    await h.controller.select("NEXT", { readOnly: true });
    // Then
    assert.equal(steps(h)[5], "미조회");
    assert.equal(h.node("next").textContent, "알림 열기 · 저장 초안 확인 →");
    assert.equal(h.node("next").disabled, false);
    release();
    await oldRead;
    assert.equal(steps(h)[5], "미조회");
    assert.equal(h.node("next").disabled, false);
    assert.equal(h.posts().length, 0);
});

test("Review an older alert's pending read cannot conceal a failed draft read on the currently opened alert", async () => {
    // Given
    let release;
    const first = ready("A"), second = ready("B");
    const h = reportHarness({ "/alerts": { items: [first, second] }, "/A": first, "/B": second,
        "/report-snapshot": preview(), "/report-drafts": url => url.includes("/A/")
            ? new Promise(resolve => { release = () => resolve(response(current())); })
            : response({}, 503) });
    await h.controller.select("R", { readOnly: true });
    const oldRead = h.controller.open("A");
    await settle();
    // When
    await h.controller.open("B");
    // Then
    assert.equal(steps(h)[5], "조회 실패");
    assert.equal(h.node("next").textContent, "저장 초안 다시 조회 →");
    assert.equal(h.node("next").disabled, false);
    release();
    await oldRead;
    assert.equal(steps(h)[5], "조회 실패");
    assert.equal(h.node("next").textContent, "저장 초안 다시 조회 →");
    assert.equal(h.posts().length, 0);
});

test("Preview toggle and lower close preserve the document and inputs without requests", async () => {
    // Given
    const h = reportHarness({ "/report-snapshot": preview(), "/report-drafts": current() });
    await h.controller.open("A");
    const before = h.calls.length, text = h.node("draft-text").textContent;
    const input = h.document.getElementById("kisa-reason"); input.value = "작성 중인 사유";
    let focused = 0;
    h.node("draft-inspect").focus = () => { focused += 1; };
    const attributes = {};
    h.node("draft-inspect").setAttribute = (key, value) => { attributes[key] = value; };
    // When / Then
    for (let repeat = 0; repeat < 3; repeat += 1) {
        h.node("draft-inspect").listeners.click();
        assert.equal(h.node("draft-preview").open, true);
        assert.equal(h.node("draft-inspect").textContent, "미리보기 접기");
        assert.equal(attributes["aria-expanded"], "true");
        h.document.getElementById("kisa-checklist").open = true;
        h.document.getElementById("kisa-inputs-panel").open = true;
        (repeat === 1 ? h.node("draft-inspect") : h.node("draft-collapse")).listeners.click();
        assert.equal(h.node("draft-preview").open, false);
        assert.equal(h.document.getElementById("kisa-checklist").open, false);
        assert.equal(h.document.getElementById("kisa-inputs-panel").open, false);
        assert.equal(h.node("draft-inspect").textContent, "내용 확인·보완");
        assert.equal(attributes["aria-expanded"], "false");
    }
    assert.equal(focused, 3);
    assert.equal(input.value, "작성 중인 사유");
    assert.equal(h.node("draft-text").textContent, text);
    assert.equal(h.node("draft-review").disabled, false, "Closing does not record or change a review");
    assert.equal(h.calls.length, before);
    assert.equal(h.posts().length, 0);
});

test("Native preview close synchronizes the upper action and closes its reading space", async () => {
    // Given
    const h = reportHarness({ "/report-drafts": current() });
    await h.controller.open("A");
    h.node("draft-inspect").listeners.click();
    h.document.getElementById("kisa-checklist").open = true;
    // When: the browser summary's default keyboard/click action closes its details.
    h.node("draft-preview").open = false;
    h.node("draft-preview").listeners.toggle();
    // Then
    assert.equal(h.node("draft-inspect").textContent, "내용 확인·보완");
    assert.equal(h.document.getElementById("kisa-checklist").open, false);
    assert.equal(h.posts().length, 0);
});

for (const native of [false, true]) {
    test(`A late next-action read respects a ${native ? "native summary" : "button"} close`, async () => {
        // Given
        let delayed = false, release;
        const h = reportHarness({ "/A": () => delayed ? new Promise(resolve => { release = () => resolve(response(ready())); }) : response(ready()),
            "/report-drafts": current(), "/report-snapshot": preview() });
        await h.controller.open("A");
        h.node("draft-inspect").listeners.click();
        delayed = true;
        const pending = h.node("next").listeners.click();
        await settle();
        // When
        if (native) { h.node("draft-preview").open = false; h.node("draft-preview").listeners.toggle(); }
        else h.node("draft-collapse").listeners.click();
        release(); await pending;
        // Then
        assert.equal(h.node("draft-preview").open, false);
        assert.equal(h.node("draft-inspect").textContent, "내용 확인·보완");
        assert.equal(h.posts().length, 0);
    });
}

test("Draft refresh leaves a closed preview closed, and a new selection starts collapsed", async () => {
    // Given
    const h = reportHarness({ "/report-drafts": current(), "/report-snapshot": preview(), "/alerts": { items: [ready()] } });
    await h.controller.open("A");
    h.node("draft-inspect").listeners.click();
    h.node("draft-collapse").listeners.click();
    // When / Then
    await h.node("draft-load").listeners.click();
    await settle();
    assert.equal(h.node("draft-preview").open, false);
    h.node("draft-inspect").listeners.click();
    await h.controller.select("NEXT", { readOnly: true });
    assert.equal(h.node("draft-preview").open, false);
    assert.equal(h.posts().length, 0);
});

test("Task 7 stored draft wording is displayed verbatim even when it contains development terminology", async () => {
    // Given
    const original = "저장 분석 기반 로컬 개발 초안입니다. 기존 S0 개발 Run을 실제 운영 사고로 확정하지 않습니다. UNKNOWN";
    const h = reportHarness({ "/report-drafts": { items: [{ status: "completed", current: true, review: null, draft: aiDraft({text:original}) }] } });
    // When
    await h.controller.open("A");
    h.node("draft-inspect").listeners.click();
    h.node("draft-collapse").listeners.click();
    // Then
    assert.equal(h.node("draft-text").textContent, original);
    assert.equal(h.posts().length, 0);
});


test("Developer tools require explicit developer mode and do not become visible by opening an alert", async () => {
    // Given / When / Then
    for (const developerTools of [false, true]) {
        const calls = [];
        const h = harness(async (url, options = {}) => {
            calls.push({url, options});
            return response(url.endsWith('/report-drafts') || url.endsWith('/alerts') ? {items: []} : ready());
        }, {developerTools});
        await h.controller.open("A");
        assert.equal(h.node("dev-tools").hidden, !developerTools);
        assert.equal(h.node("developer-area").hidden, !developerTools);
        assert.ok(calls.every(call => !call.options.method || call.options.method === "GET"));
        await h.controller.select("OTHER", {readOnly: true});
        assert.equal(h.node("dev-tools").hidden, true);
    }
});
