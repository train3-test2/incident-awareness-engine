import test from "node:test";
import assert from "node:assert/strict";
import {createKisaFormController} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-kisa-controller.mjs";

function harness(fetchImpl, options = {}) {
    const nodes = new Map();
    const element = () => ({value:"",hidden:false,disabled:false,textContent:"",children:[],listeners:{},
        append(...values){this.children.push(...values);},replaceChildren(...values){this.children=values;},
        setAttribute(){},addEventListener(name,fn){this.listeners[name]=fn;}});
    const document = {createElement:element,getElementById(id){if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);}};
    return {controller:createKisaFormController(document,{fetchImpl,...options}),node:name=>document.getElementById(`kisa-${name}`),nodes};
}
const draft={draft_id:"D",workflow_version:3,generated_at:"2026-10-20T00:00:00Z"};
const schema={common_fields:{company_name:"기업명"},type_fields:{other_hacking:{},undetermined:{}},choices:{},consents:{privacy_collection:"필수 동의"},types:{other_hacking:"그 밖의 해킹",undetermined:"미확정"}};
// Stored server forms always record submission_status and the human classification basis (kisa_mapping).
const form={form_id:"F",report_version:1,source_report_version:6,incident_type:"other_hacking",classification_reason:"TEST",submission_status:"not_submitted",classification:{basis:"explicit_human_form_selection"},inputs:{fields:{},consents:{}},fields:{t_h:{label:"인지시각",value:"미기록",confirmation_status:"NOT_RECORDED"}},consents:{privacy_collection:null},
    readiness:{blockers:["t_h"],unconfirmed_fields:["t_h"],unconfirmed_consents:["privacy_collection"]},
    narrative:{method:"jinja2_fallback",call_metadata:{status:"blocked_data",actual_model:null},output:{incident_summary:"개발용 사례",observed_indicators:"저장된 사실",response_actions:"확인불가",unconfirmed_items:["원인"]}}};
const response=(body,status=200)=>({ok:status<400,status,json:async()=>body});
const summaryText=h=>h.node('document-summary').children.map(c=>c.textContent).join('|');
const list=(items=[])=>({items,schema,template:{supported:true,sha256:"HASH",renderer_version:"v1"},latest_version:items[0]?.report_version??0});

test("loading a saved draft does not create classification, consent or awareness",async()=>{
    const calls=[];const h=harness(async(url,options)=>{calls.push({url,options});return response(url.endsWith('/report-drafts')?{items:[{draft_id:'D',draft,current:true,document_version:6,status:'completed'}]}:list());});
    await h.controller.setDraft({alertId:'A',draft,current:true});
    assert.equal(h.node('type').value,'undetermined');assert.equal(h.node('generate').disabled,true);
    assert.ok(calls.every(c=>!c.options.method));assert.match(h.node('readiness').textContent,/미저장/);
    await h.controller.setDraft(null);assert.equal(h.node('panel').hidden,true);
});

test("failed save retries the same key and suppresses duplicate clicks",async()=>{
    const bodies=[];let fail=true,finish;const h=harness(async(url,options)=>{
        if(options.method==='POST') {bodies.push(JSON.parse(options.body));if(fail){fail=false;throw Error('network');}await new Promise(resolve=>{finish=resolve;});return response(form);}
        return response(url.endsWith('/report-drafts')?{items:[]}:list(bodies.length>1?[form]:[]));
    });
    await h.controller.setDraft({alertId:'A',draft,current:true});
    h.node('type').value='other_hacking';h.node('reason').value='TEST';
    await h.controller.save();const retry=h.controller.save();await h.controller.save();
    assert.equal(bodies.length,2);assert.equal(bodies[0].idempotency_key,bodies[1].idempotency_key);
    assert.deepEqual(bodies[0].consents,{privacy_collection:null});assert.equal('t_h' in bodies[0].fields,false);
    finish();await retry;assert.equal(h.node('readiness').textContent,'추가 확인 1항목');
    assert.match(summaryText(h),/양식 v1\|상태\|.* · 미제출$/);
});

test("Word generation references a stored form and never sends unsaved field values",async()=>{
    const calls=[];const h=harness(async(url,options)=>{calls.push({url,options});return response(options.method==='POST'?{docx_sha256:'SHA'}:url.endsWith('/report-drafts')?{items:[]}:list([form]));});
    await h.controller.setDraft({alertId:'A',draft,current:true});await h.controller.generate();
    assert.equal(h.node('download').href,'/human-workflow/alerts/A/report-drafts/D/kisa-forms/F/docx');
    assert.equal(calls.at(-1).options.body,undefined);
    h.node('reason').listeners.input();assert.equal(h.node('generate').disabled,true);assert.equal(h.node('download').hidden,true);
    assert.equal(h.node('narrative').textContent.includes('대체 작성'),false);
    assert.match(summaryText(h), /작성 방식 미확인/);
    assert.equal(h.node('narrative').textContent.includes('AI 작성'),false);
    assert.match(h.node('generation-detail').textContent,/blocked_data/);
});

test("the form names its source draft so a synthetic demo is never read as this Run",async()=>{
    const h=harness(async url=>response(url.endsWith('/report-drafts')?{items:[]}:list([form])));
    const real={...draft,method:"jinja2_fallback",context:"local_development",call_metadata:{status:"blocked_data",requested_at:null}};
    await h.controller.setDraft({alertId:'A',draft:real,current:true});
    // A selected item's own draft needs no source badge; the document summary names its method.
    assert.equal(h.node('source-label').textContent,'');assert.equal(h.node('source-label').hidden,true);
    const synthetic={...draft,method:"monorouter_grounded",context:"synthetic_development",call_metadata:{status:"success",http_status:200}};
    await h.controller.setDraft({alertId:'SYNTHETIC-OBS-ALERT-001',draft:synthetic,current:true});
    assert.equal(h.node('source-label').textContent,'합성 시연 초안 · 데모 · AI 작성 (검증 통과)');assert.equal(h.node('source-label').hidden,false);
    await h.controller.setDraft(null);assert.equal(h.node('source-label').textContent,'');
});

test("previous workflow drafts can be viewed but cannot record new human inputs",async()=>{
    const h=harness(async url=>response(url.endsWith('/report-drafts')?{items:[]}:list([form])));
    await h.controller.setDraft({alertId:'A',draft,current:false});assert.equal(h.node('save').disabled,true);
    assert.equal(h.node('generate').disabled,false);
});

test("server assessment lists missing inputs and opens their editor without human actions",async()=>{
    const calls=[];
    const assessment={blockers:["company_name","t_h"],unconfirmed_fields:["company_name","t_h"],unconfirmed_consents:[],required_items:[
        {key:"company_name",label:"기업명",state:"missing_input",target:"field:company_name"},
        {key:"t_h",label:"사고인지시점",state:"missing_input",target:"awareness"}]};
    const h=harness(async(url,options)=>{calls.push({url,options});return response(url.endsWith('/report-drafts')?{items:[]}:{...list(),unsaved_preview:{readiness:assessment}});});
    await h.controller.setDraft({alertId:'A',draft,current:true});
    assert.equal(h.node('readiness').textContent,'저장 전 기준 · 추가 확인 2항목');
    const rows=h.node('required-items').children;assert.equal(rows.length,2);
    rows[0].children[0].listeners.click();assert.equal(h.node('inputs-panel').open,true);
    rows[1].children[0].listeners.click();assert.match(h.node('status').textContent,/명시적으로 기록/);
    assert.ok(calls.every(c=>!c.options.method));
});

test("a restored form with a stored Word export offers download without any write",async()=>{
    // Given
    const calls=[];const h=harness(async(url,options={})=>{calls.push({url,options});return response(url.endsWith('/report-drafts')?{items:[]}:{...list([form]),exports:{F:{docx_sha256:'SHA'}}});});
    // When
    await h.controller.setDraft({alertId:'A',draft:{...draft,word_result:{status:'ready'}},current:true});
    // Then
    assert.equal(h.node('download').hidden,false);
    assert.equal(h.node('download').href,'/human-workflow/alerts/A/report-drafts/D/kisa-forms/F/docx');
    assert.equal(h.node('download').textContent,'Word 신고서 다운로드 (양식 v1)');
    assert.equal(h.node('generate').hidden,true);
    assert.equal(h.node('status').textContent,'');
    assert.match(summaryText(h),/ · 미제출$/);
    assert.ok(calls.every(c=>!c.options.method));
});

test("a saved version without an export shows one make-Word action instead of a dead link",async()=>{
    // Given
    const h=harness(async url=>response(url.endsWith('/report-drafts')?{items:[]}:{...list([form]),exports:{F:null}}));
    // When
    await h.controller.setDraft({alertId:'A',draft,current:true});
    // Then
    assert.equal(h.node('download').hidden,true);
    assert.equal(h.node('generate').hidden,false);
    assert.equal(h.node('generate').disabled,false);
    await h.controller.generate();
    assert.equal(h.node('download').hidden,false);
    assert.equal(h.node('generate').hidden,true);
});

test("readiness is summarized by category; item details stay in the collapsed checklist",async()=>{
    // Given
    const assessment={required_items:[{key:"company_name",label:"기업명",state:"missing_input",target:"field:company_name"},
        {key:"reporter_phone",label:"연락처",state:"missing_input",target:"field:reporter_phone"},
        {key:"privacy_collection",label:"필수 동의",state:"missing_input",target:"consent:privacy_collection"}]};
    const h=harness(async url=>response(url.endsWith('/report-drafts')?{items:[]}:{...list([{...form,readiness:assessment}]),readiness_assessments:{F:assessment}}));
    // When
    await h.controller.setDraft({alertId:'A',draft,current:true});
    // Then
    assert.equal(h.node('readiness').textContent,'추가 확인 3항목');
    assert.equal(h.node('checklist-label').textContent,'항목별 확인 (기업·신고자 정보 2 · 동의·확인 1)');
    assert.equal(h.node('required-items').children.length,3);
});

test("choosing a type in the advanced editor prefills an editable selection record",async()=>{
    // Given
    const h=harness(async url=>response(url.endsWith('/report-drafts')?{items:[]}:list()));
    await h.controller.setDraft({alertId:'A',draft,current:true});
    // When
    h.node('type').value='other_hacking';h.node('type').listeners.change();
    // Then
    assert.match(h.node('reason').value,/'그 밖의 해킹' 양식을 직접 선택/);
    h.node('reason').value='담당자 사유';h.node('type').value='other_hacking';h.node('type').listeners.change();
    assert.equal(h.node('reason').value,'담당자 사유');
});

test("typed values require explicit confirmation before saving",async()=>{
    const calls=[];const h=harness(async(url,options)=>{calls.push({url,options});return response(url.endsWith('/report-drafts')?{items:[]}:list());});
    await h.controller.setDraft({alertId:'A',draft,current:true});
    h.node('fields').children[0].children[1].value='SYNTHETIC';
    await h.controller.save();assert.match(h.node('status').textContent,/확인 상태/);
    assert.ok(calls.every(c=>!c.options.method));
});

// Task 4: one document summary; the values below are fixtures, never constants in the controller.
const aiDraft={...draft,method:"monorouter_grounded",call_metadata:{status:"success",http_status:200}};
const fallbackDraft={...draft,method:"jinja2_fallback",call_metadata:{status:"disabled",requested_at:null}};
const items24=Array.from({length:24},(_,i)=>({key:`detail_${i}`,label:`세부 ${i}`,state:"missing_input",target:`field:detail_${i}`}));
function documentHarness({source=aiDraft,current=true,review=null,forms,exports={},unsaved=null}={}){
    const ddosSchema={...schema,types:{...schema.types,ddos:"디도스"},type_fields:{...schema.type_fields,ddos:{}}};
    const stored=forms??[{...form,incident_type:"ddos",readiness:{required_items:items24}}];
    const calls=[];
    const h=harness(async(url,options={})=>{calls.push({url,options});return response(url.endsWith('/report-drafts')
        ?{items:[{draft_id:'D',draft:source,current,document_version:5,review,status:'completed'}]}
        :{...list(stored),schema:ddosSchema,readiness_assessments:Object.fromEntries(stored.map(item=>[item.form_id,item.readiness])),exports,
            unsaved_preview:unsaved});});
    return {...h,calls,load:()=>h.controller.setDraft({alertId:'A',draft:source,current})};
}

test("Task 4 document summary separates the human type choice, both versions and AI, review and submission states",async()=>{
    // Given
    const h=documentHarness({exports:{F:{docx_sha256:'SHA'}}});
    // When
    await h.load();
    // Then
    // The report type shows the attack type only, without who selected it.
    assert.equal(summaryText(h),'신고서 유형|디도스|문서 버전|초안 v5 / 양식 v1|상태|AI 검증 통과 · 검토 전 · 미제출');
    assert.equal(h.node('readiness').textContent,'추가 확인 24항목');
    assert.equal(h.node('checklist-label').textContent,'항목별 확인 (사고 세부사항 24)');
    assert.equal(h.node('download').hidden,false);
    assert.equal(h.node('generate').hidden,true);
    assert.equal(h.node('status').textContent,'');
    assert.equal(h.node('source-label').hidden,true);
    assert.ok(h.calls.every(call=>!call.options.method));
});

for (const [name,options,expected] of [
    ["a recorded review",{review:{reviewed_at:"2026-10-21T05:00:00Z"}},'AI 검증 통과 · 검토 완료 · 미제출'],
    ["a previous Workflow draft",{current:false},'AI 검증 통과 · 이전 버전 · 미제출'],
    ["a fallback draft",{source:fallbackDraft},'대체 작성 (외부 호출 없음) · 검토 전 · 미제출'],
    ["a legacy form without stored basis or submission",{forms:[{...form,incident_type:"ddos",submission_status:undefined,classification:undefined}]},'AI 검증 통과 · 검토 전 · 제출 상태 확인 필요'],
]) {
    test(`Task 4 document summary never upgrades a state: ${name}`,async()=>{
        // Given
        const h=documentHarness(options);
        // When
        await h.load();
        // Then
        const rows=h.node('document-summary').children.map(c=>c.textContent);
        assert.equal(rows[5],expected);
        if(name.startsWith("a legacy")) assert.equal(rows[1],'디도스');
        assert.doesNotMatch(summaryText(h),/제출 완료|제출 준비 완료|검토 완료.*검토 전/);
        assert.ok(h.calls.every(call=>!call.options.method));
    });
}

test("Task 4 an unsaved form states no type choice and labels the preview assessment",async()=>{
    // Given
    const h=documentHarness({forms:[],unsaved:{readiness:{required_items:items24.slice(0,3)}}});
    // When
    await h.load();
    // Then
    assert.equal(summaryText(h),'신고서 유형|미선택|문서 버전|초안 v5 / 양식 미저장|상태|AI 검증 통과 · 검토 전 · 미제출');
    assert.equal(h.node('readiness').textContent,'저장 전 기준 · 추가 확인 3항목');
    assert.equal(h.node('type').value,'undetermined');
});

test("Same-document refresh preserves unsaved editor nodes while refreshing review metadata", async () => {
    // Given
    let reviewed = null, delayed = false, release;
    const calls = [];
    const h = harness(async (url, options = {}) => {
        calls.push({url, options});
        if (url.endsWith('/report-drafts')) return response({items:[{draft_id:'D',draft:aiDraft,current:true,document_version:5,review:reviewed,status:'completed'}]});
        if (delayed) return new Promise(resolve => { release = () => resolve(response(list([form]))); });
        return response(list([form]));
    });
    const context = {alertId:'A',workflowVersion:3,draft:aiDraft,current:true};
    await h.controller.setDraft(context);
    const editor = h.node('fields').children[0], consent = h.node('consents').children[1];
    editor.children[1].value = '入力途中'; editor.children[1].listeners.input();
    consent.value = 'false'; consent.listeners.change();
    h.node('reason').value = '작성 중'; h.node('reason').listeners.input();
    // When
    reviewed = {reviewed_at:'2026-10-22T00:00:00Z'}; delayed = true;
    const pending = h.controller.setDraft({...context});
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(h.node('fields').children[0], editor);
    release(); await pending;
    // Then
    assert.strictEqual(h.node('fields').children[0], editor);
    assert.equal(editor.children[1].value, '入力途中');
    assert.equal(consent.value, 'false');
    assert.equal(h.node('reason').value, '작성 중');
    assert.match(summaryText(h), /검토 완료/);
    assert.match(h.node('status').textContent, /입력 변경 미저장/);
    assert.equal(h.node('generate').disabled, true);
    assert.ok(calls.every(call => !call.options.method));
});

test("Edits made while a same-document read is pending survive its response; a new source resets them", async () => {
    // Given
    let delayed = false, release;
    const h = harness(async url => {
        if (url.endsWith('/report-drafts')) return response({items:[]});
        return delayed ? new Promise(resolve => { release = () => resolve(response(list([form]))); }) : response(list([form]));
    });
    const context = {alertId:'A',workflowVersion:3,draft:aiDraft,current:true};
    await h.controller.setDraft(context);
    const editor = h.node('fields').children[0];
    // When
    delayed = true;
    const pending = h.controller.setDraft(context);
    await new Promise(resolve => setImmediate(resolve));
    editor.children[1].value = '재조회 중 입력'; editor.children[1].listeners.input();
    release(); await pending;
    // Then
    assert.strictEqual(h.node('fields').children[0], editor);
    assert.equal(editor.children[1].value, '재조회 중 입력');
    delayed = false;
    await h.controller.setDraft({...context,alertId:'B',draft:{...aiDraft,draft_id:'OTHER'}});
    assert.notStrictEqual(h.node('fields').children[0], editor);
    assert.equal(h.node('fields').children[0].children[1].value, '');
});

test("Task 7 stored document narrative and UNKNOWN field values remain unchanged", async () => {
    // Given
    const original = "기존 S0 개발 Run · 개발용 문구가 포함된 저장 본문 · Decision";
    const stored = {...form, fields:{source:{label:"원천", value:"UNKNOWN", confirmation_status:"UNKNOWN"}},
        narrative:{...form.narrative,output:{...form.narrative.output,incident_summary:original}}};
    const h = documentHarness({forms:[stored]});
    // When
    await h.load();
    // Then
    assert.ok(h.node("narrative").textContent.includes(original));
    assert.equal(h.node("preview").children[0].children[1].textContent,"UNKNOWN");
    assert.ok(h.calls.every(call=>!call.options.method));
});


test("Operator preview contains one narrative while source fields and versions remain exact in details", async () => {
    // Given: deliberately distinct source and form text, never reconstructed from displayed prose.
    const raw = "저장 원문 · UNKNOWN · 보존용 고유 정보";
    const source = {...draft, text: raw, method: "jinja2_fallback", call_metadata: {status: "blocked_data"}};
    const stored = {...form, source_draft_id: "D", source_snapshot_sha256: "a".repeat(64)};
    const before = JSON.stringify(stored);
    const calls = [];
    const h = harness(async (url, options = {}) => {
        calls.push({url, options});
        return response(url.endsWith('/report-drafts') ? {items: []} : list([stored]));
    });
    // When
    await h.controller.setDraft({alertId: "A", draft: source, current: true});
    // Then
    assert.equal(h.node('narrative').textContent, "개발용 사례\n저장된 사실\n실제 조치: 확인불가\n추가 확인: 원인");
    assert.match(summaryText(h), /대체 작성/);
    const record = JSON.parse(h.node('source-record').textContent);
    assert.equal(record.source_draft.text, raw);
    assert.equal(record.source_draft_id, "D");
    assert.equal(record.source_report_version, 6);
    assert.deepEqual(record.narrative, stored.narrative);
    assert.equal(JSON.stringify(stored), before);
    assert.ok(calls.every(call => !call.options.method));
});


test("Report confirmation codes have explicit labels while unknown codes stay unknown in the basic table", async () => {
    // Given
    const fields = {one: {label: "근거", value: "저장값", confirmation_status: "STORED_REPORT_FACT"},
        two: {label: "인지", value: "담당자 저장값", confirmation_status: "RECORDED_HUMAN_AWARENESS"},
        three: {label: "기타", value: "고유 정보", confirmation_status: "NEW_FUTURE_CODE"}};
    const value = {...form, fields};
    const h = harness(async url => response(url.endsWith('/report-drafts') ? {items: []} : list([value])));
    // When
    await h.controller.setDraft({alertId: "A", draft, current: true});
    // Then
    assert.deepEqual(h.node('preview').children.map(row => row.children[2].textContent),
        ["저장 초안 근거", "담당자 인지 기록", "확인 상태 미확인"]);
    assert.deepEqual(JSON.parse(h.node('source-record').textContent).fields, fields);
});


test("Report review converts ISO clocks for display while retaining the exact saved form and source", async () => {
    const value = structuredClone(form);
    value.narrative.output.incident_summary = "2026-10-03T00:00:00.123456+00:00 확인된 관측";
    value.fields.t_h.value = "2026-10-03T00:00:10Z";
    const before = JSON.stringify(value);
    const h = harness(async url=>response(url.endsWith('/report-drafts') ? {items: []} : list([value])));
    await h.controller.setDraft({alertId: "A",draft,current:true});
    assert.match(h.node('narrative').textContent,/2026\.10\.03 09:00:00\.123456 KST 확인된 관측/);
    assert.equal(h.node('preview').children[0].children[1].textContent,"2026.10.03 09:00:10 KST");
    assert.equal(JSON.stringify(value),before);
    const source = JSON.parse(h.node('source-record').textContent);
    assert.deepEqual(source.narrative,value.narrative);
    assert.deepEqual(source.fields,value.fields);
});


test("Report version selectors show KST while their raw timestamps and version IDs remain accessible", async () => {
    const saved = {...form, recorded_at: "2026-10-03T00:41:00.123456+00:00"};
    const entry = {draft_id: "D", document_version: 6, status: "completed", current: true,
        draft: {...draft, generated_at: "2026-10-03T00:40:00.123456+00:00"}};
    const h = harness(async url=>response(url.endsWith('/report-drafts') ? {items: [entry]} : list([saved])));
    await h.controller.setDraft({alertId: "A",draft: entry.draft,current:true});
    assert.match(h.node('source').children[0].textContent,/2026\.10\.03 09:40:00\.123456 KST/);
    assert.equal(h.node('source').children[0].title,entry.draft.generated_at);
    assert.equal(h.node('source').children[0].value,"D");
    assert.match(h.node('version').children[0].textContent,/2026\.10\.03 09:41:00\.123456 KST/);
    assert.equal(h.node('version').children[0].title,saved.recorded_at);
    assert.equal(h.node('version').children[0].value,"F");
});

test("Track-B capability prevents KISA save requests without losing unsaved form inputs", async () => {
    let allowed = true;
    const calls = [];
    const h = harness(async (url, options) => { calls.push({url, options}); return response(url.endsWith('/report-drafts') ? {items: []} : list()); }, {canUseSelectedSource: () => allowed});
    await h.controller.setDraft({alertId: 'A',draft,current:true});
    h.node('type').value = 'other_hacking';h.node('reason').value = '저장하지 않은 내용';
    const count = calls.length;allowed = false;
    await h.controller.save();
    assert.equal(calls.length,count);
    assert.equal(h.node('reason').value,'저장하지 않은 내용');
    assert.match(h.node('status').textContent,/Live 관측/);
});
