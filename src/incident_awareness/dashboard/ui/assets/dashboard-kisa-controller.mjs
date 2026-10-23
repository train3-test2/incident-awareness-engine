import { formatOperatorProse, formatRunTimestamp, operatorAwarenessTerm } from "./dashboard-contract.mjs";
import { draftPresentation, readinessSummary, classificationReason } from "./dashboard-operator-contract.mjs";

export function createKisaFormController(document, {fetchImpl = globalThis.fetch.bind(globalThis), canUseSelectedSource = () => true} = {}) {
    const node = name => document.getElementById(`kisa-${name}`);
    let context = null, source = null, entry = null, schema = null, saved = null, latest = 0;
    let generation = 0, busy = false, loading = false, dirty = false, pending = null, template = null;
    let assessments = {}, unsavedPreview = null, exports = {};
    const fields = new Map(), consents = new Map();
    function controls() {
        node("save").disabled = busy || loading || !source || !source.current || !schema;
        node("generate").disabled = busy || loading || !saved || dirty || saved.incident_type === "undetermined" || !template?.supported;
        // A stored export is offered directly; "make Word" appears only for a saved version without one.
        node("generate").hidden = !saved || saved.incident_type === "undetermined" || Boolean(!dirty && exports[saved.form_id]);
        for (const id of ["source", "version", "type", "reason"]) node(id).disabled = busy || loading || !source;
    }
    function showDownload(form) {
        node("download").href = `${base()}/kisa-forms/${form.form_id}/docx`;
        node("download").textContent = `Word 신고서 다운로드 (양식 v${form.report_version})`;
        node("download").hidden = false;
    }
    async function request(path, options = {}) {
        if (!canUseSelectedSource()) throw new Error("Live 관측에서는 KISA 신고서를 실행할 수 없습니다.");
        const response = await fetchImpl(path, {...options, headers:{"Content-Type":"application/json"},signal:AbortSignal.timeout(60000)});
        if (!response.ok) {
            const error = new Error(response.status === 409 ? "동시 수정 또는 이전 초안입니다. 저장 상태를 다시 조회하세요."
                : response.status === 422 ? "유형 사유, 확인값과 동의 항목의 일치 여부를 확인하세요."
                : "양식 처리 오류입니다. 같은 입력으로 재시도할 수 있습니다.");
            error.status = response.status; throw error;
        }
        return response.json();
    }
    const base = () => `/human-workflow/alerts/${encodeURIComponent(context.alertId)}/report-drafts/${encodeURIComponent(source.draft.draft_id)}`;
    function change() { dirty = true; node("download").hidden = true; node("status").textContent = "입력 변경 미저장 · 저장하면 새 양식 버전으로 Word를 다시 만들 수 있습니다."; controls(); }
    function renderInputs(input = {}) {
        fields.clear(); consents.clear(); node("fields").replaceChildren(); node("consents").replaceChildren();
        const definitions = {...schema.common_fields,...schema.type_fields[node("type").value]};
        for (const [key,label] of Object.entries(definitions)) {
            const wrapper = document.createElement("div"); wrapper.className = "kisa-field";
            const name = document.createElement("label"); name.textContent = label; name.htmlFor = `kisa-field-${key}`;
            const value = document.createElement(key === "response_actions" ? "textarea" : schema.choices[key] ? "select" : "input");
            value.id = `kisa-field-${key}`; value.maxLength = 2000;
            if (schema.choices[key]) {
                for (const optionValue of ["",...schema.choices[key]]) {
                    const option = document.createElement("option"); option.value = optionValue; option.textContent = optionValue || "선택 안 함"; value.append(option);
                }
            } else if (key.endsWith("_at")) value.placeholder = "예: 2026-10-20T09:30:00+09:00 · 확인된 발생/종료 시각만";
            const status = document.createElement("select"); status.id = `kisa-confirm-${key}`; status.setAttribute("aria-label",`${label} 확인 상태`);
            for (const [v,label] of [["","미입력 / 미확인"],["missing_input","담당자 입력 대기"],["confirmed","값을 확인함"],["unknown","기술적으로 확인불가로 기록"]]) {
                const option = document.createElement("option"); option.value = v; option.textContent = label; status.append(option);
            }
            value.value = input.fields?.[key]?.value ?? ""; status.value = input.fields?.[key]?.confirmation ?? "";
            value.addEventListener("input", change); value.addEventListener("change", change);
            status.addEventListener("change", () => { if(["unknown","missing_input"].includes(status.value)) value.value = ""; change(); });
            wrapper.append(name,value,status); node("fields").append(wrapper); fields.set(key,{value,status});
        }
        for (const [key,label] of Object.entries(schema.consents)) {
            if (key === "technical_support" && node("type").value === "ddos") continue;
            const name = document.createElement("label"), choice = document.createElement("select");
            name.textContent = label; name.htmlFor = `kisa-consent-${key}`; choice.id = `kisa-consent-${key}`;
            for (const [v,title] of [["","미확인 / 선택 안 함"],["true","명시적으로 동의·확인"],["false","명시적으로 미동의"]]) {
                const option = document.createElement("option"); option.value = v; option.textContent = title; choice.append(option);
            }
            choice.value = input.consents?.[key] == null ? "" : String(input.consents[key]);
            choice.addEventListener("change",change); node("consents").append(name,choice); consents.set(key,choice);
        }
    }
    // One document summary: the human type choice, both versions and three independent states.
    function renderSummary() {
        const target = node("document-summary");
        if (!target?.replaceChildren) return;
        target.replaceChildren();
        if (!source) return;
        const presentation = draftPresentation(source.draft);
        const type = !saved ? "미선택"
            : schema?.types?.[saved.incident_type] ?? saved.incident_type;
        const versions = `${entry?.document_version ? `초안 v${entry.document_version}` : "초안 버전 확인 필요"}`
            + ` / ${saved ? `양식 v${saved.report_version}` : "양식 미저장"}`;
        const ai = presentation.ai ? "AI 검증 통과" : `${presentation.method}${presentation.reason ? ` (${presentation.reason})` : ""}`;
        const review = !source.current ? "이전 버전" : entry?.review ? "검토 완료" : entry ? "검토 전" : "검토 상태 확인 필요";
        // No submission path exists in this system; a stored form also records not_submitted itself.
        const submission = !saved || saved.submission_status === "not_submitted" ? "미제출" : "제출 상태 확인 필요";
        for (const [label, content] of [["신고서 유형", type], ["문서 버전", versions], ["상태", `${ai} · ${review} · ${submission}`]]) {
            const term = document.createElement("dt"), description = document.createElement("dd");
            term.textContent = label; description.textContent = content;
            target.append(term, description);
        }
    }
    function showReadiness(status, form = null) {
        node("required-items").replaceChildren();
        if (!status) return;
        const summary = readinessSummary(status);
        // An unsaved form is the server's preview assessment, so it is labelled as such.
        node("readiness").textContent = `${form ? "" : "저장 전 기준 · "}${summary.count ? `추가 확인 ${summary.count}항목` : "추가 확인 항목 없음"}`;
        if (node("checklist-label")) node("checklist-label").textContent = `항목별 확인 (${summary.groups.map(group => `${group.label} ${group.count}`).join(" · ")})`;
        if (node("checklist")) node("checklist").hidden = !summary.count;
        for (const item of status.required_items ?? []) {
            const row = document.createElement("li"), button = document.createElement("button");
            button.type = "button";
            button.textContent = `${operatorAwarenessTerm(item.label)} · ${{missing_input:"담당자 입력 대기",unknown:"확인불가 여부 검토 필요",not_agreed:"필수 동의·확인 미완료"}[item.state] ?? item.state} · 확인·수정`;
            button.addEventListener("click", () => {
                const [kind,key] = item.target.split(":");
                if(kind === "awareness") {
                    document.getElementById("workflow-awareness")?.focus?.();
                    node("status").textContent = "담당자 처리에서 인지시각을 명시적으로 기록한 후 새 초안을 작성하세요.";
                } else if(kind === "type") { node("inputs-panel").open = true; node("type").focus?.(); }
                else {
                    node("inputs-panel").open = true;
                    (kind === "consent" ? consents.get(key) : fields.get(key)?.status)?.focus?.();
                }
            });
            row.append(button); node("required-items").append(row);
        }
    }
    function show(form) {
        saved = form; dirty = false; node("download").hidden = true; if (node("evidence")) node("evidence").hidden = true;
        node("type").value = form?.incident_type ?? "undetermined";
        node("reason").value = form?.classification_reason ?? "";
        renderInputs(form?.inputs ?? {});
        node("preview").replaceChildren();
        if (!form) {
            node("readiness").textContent = "양식 입력 미저장";
            showReadiness(unsavedPreview?.readiness);
            node("narrative").textContent = "";
            if (node("source-reference")) node("source-reference").textContent = "저장 양식 없음 · 초안 원문";
            if (node("source-record")) node("source-record").textContent = "";
            renderSummary();
            controls(); return;
        }
        const assessment = assessments[form.form_id] ?? form.readiness;
        for (const [key,field] of Object.entries(form.fields)) {
            const row = document.createElement("tr");
            const state = assessment.field_states?.[key] ?? field.input_state;
            const confirmation = {HUMAN_CONFIRMED: "담당자 확인", CONFIRMED_UNKNOWN: "확인불가로 기록",
                UNCONFIRMED: "미확인", STORED_REPORT_FACT: "저장 초안 근거",
                RECORDED_HUMAN_AWARENESS: "담당자 인지 기록", NOT_RECORDED: "미기록"}[field.confirmation_status]
                ?? "확인 상태 미확인";
            const displayState = {missing_input:"담당자 입력 대기",unknown:"확인불가 / 조사 중",confirmed:"확인함"}[state] ?? confirmation;
            for (const content of [operatorAwarenessTerm(field.label),state === "missing_input" ? "미입력 (담당자 입력 대기)" : formatOperatorProse(field.value),displayState]) {
                const cell = document.createElement("td"); cell.textContent = content; row.append(cell);
            }
            node("preview").append(row);
        }
        showReadiness(assessments[form.form_id] ?? form.readiness, form);
        const narrative = form.narrative;
        node("narrative").textContent = formatOperatorProse(`${narrative.output.incident_summary}\n${narrative.output.observed_indicators}\n실제 조치: ${narrative.output.response_actions}\n추가 확인: ${narrative.output.unconfirmed_items.join(", ")}`);
        if (node("generation-detail")) node("generation-detail").textContent = JSON.stringify(narrative.call_metadata, null, 2);
        if (node("source-reference")) node("source-reference").textContent = `표시 양식 v${form.report_version} · 근거 초안 v${form.source_report_version ?? "미확인"} · 아래 초안 원문은 연 알림의 초안입니다. 선택 양식의 정확한 근거·버전은 원문 기록에서 확인하세요.`;
        if (node("source-record")) node("source-record").textContent = JSON.stringify({
            source_draft_id: form.source_draft_id, source_report_version: form.source_report_version,
            source_draft: source.draft,
            source_snapshot_sha256: form.source_snapshot_sha256, form_id: form.form_id,
            report_version: form.report_version, narrative: form.narrative, fields: form.fields,
        }, null, 2);
        if (node("evidence")) { node("evidence").href = `${base()}/kisa-forms/${form.form_id}/technical-evidence`; node("evidence").hidden = false; }
        // The download button itself states that a stored Word exists; the summary holds review/submission.
        if (exports[form.form_id]) showDownload(form);
        renderSummary();
        controls();
    }
    async function loadForms(current = generation, preserveInputs = false) {
        const result = await request(`${base()}/kisa-forms`);
        if (current !== generation) return;
        schema = result.schema; template = result.template; latest = result.latest_version;
        assessments = result.readiness_assessments ?? {}; unsavedPreview = result.unsaved_preview ?? null;
        exports = result.exports ?? {};
        node("template").textContent = template.supported ? `제공된 원본 DOCX 확인 · ${template.renderer_version} · 원본 SHA-256 ${template.sha256}` : template.reason;
        node("version").replaceChildren();
        for (const item of result.items) {
            const option = document.createElement("option"); option.value = item.form_id; option.textContent = `양식 v${item.report_version} · ${schema.types[item.incident_type]} · ${formatRunTimestamp(item.recorded_at)}`; option.title = item.recorded_at; node("version").append(option);
        }
        node("version").onchange = () => show(result.items.find(item=>item.form_id === node("version").value));
        if (preserveInputs && dirty) {
            // A same-document read may update metadata, but must not replace an editor in use.
            if (saved) node("version").value = saved.form_id;
            renderSummary(); change();
        } else show(result.items[0] ?? null);
    }
    async function setDraft(value) {
        const sameSource = Boolean(value && context && source
            && context.alertId === value.alertId && context.workflowVersion === value.workflowVersion
            && source.draft.draft_id === value.draft.draft_id && source.current === value.current);
        const current = ++generation;
        context = value; loading = true;
        if (!sameSource) {
            source = null; entry = null; saved = null; pending = null; dirty = false; schema = null; exports = {};
        }
        node("panel").hidden = !value; node("download").hidden = true; node("status").textContent = "";
        if (!sameSource) {
            node("fields").replaceChildren(); node("consents").replaceChildren(); node("preview").replaceChildren();
            node("document-summary")?.replaceChildren?.();
        }
        const label = value ? draftPresentation(value.draft) : null;
        // Only a synthetic demo source is labelled, so it is never read as the selected item's report.
        if (node("source-label")) {
            node("source-label").textContent = label?.demo
                ? `${label.source} · 데모 · ${label.method}${label.reason ? ` (${label.reason})` : ""}` : "";
            node("source-label").hidden = !label?.demo;
        }
        controls(); if (!value) { loading = false; return; }
        source = {draft:value.draft,current:value.current};
        try {
            const result = await request(`/human-workflow/alerts/${encodeURIComponent(value.alertId)}/report-drafts`);
            if (current !== generation) return;
            entry = result.items.find(item => item.draft_id === value.draft.draft_id) ?? null;
            node("source").replaceChildren();
            for (const item of result.items.filter(item=>item.status === "completed" && item.draft)) {
                const option = document.createElement("option"); option.value = item.draft_id; option.textContent = `원천 초안 v${item.document_version} · ${item.current ? "현재 Workflow" : "이전 Workflow"} · ${formatRunTimestamp(item.draft.generated_at)}`; option.title = item.draft.generated_at; node("source").append(option);
            }
            node("source").value = value.draft.draft_id;
            node("source").onchange = async () => {
                const identity = ++generation;
                source = result.items.find(item=>item.draft_id === node("source").value); entry = source; loading = true;
                saved = null; pending = null; controls();
                try { await loadForms(identity); } catch(error) { if(identity === generation) node("status").textContent = error.message; }
                finally { if(identity === generation) { loading = false; controls(); } }
            };
            await loadForms(current, sameSource);
        } catch(error) { if(current === generation) node("status").textContent = error.message; }
        finally { if(current === generation) { loading = false; controls(); } }
        // Older servers do not list exports; the stored file is then fetched by its idempotent prepare call.
        if (current === generation && value.draft.word_result?.status === "ready" && saved && !exports[saved.form_id]) await generate();
    }
    function payload() {
        const values = {};
        for (const [key,{value,status}] of fields) if(status.value) values[key] = {confirmation:status.value,value:["unknown","missing_input"].includes(status.value) ? "" : value.value};
        const choices = {}; for (const [key,choice] of consents) choices[key] = choice.value === "" ? null : choice.value === "true";
        return {expected_workflow_version:source.draft.workflow_version,expected_form_version:latest,
            incident_type:node("type").value,classification_reason:node("reason").value,fields:values,consents:choices};
    }
    async function save() {
        if(busy || loading || !schema || !source?.current) return;
        for (const [key,{value,status}] of fields) {
            if(value.value.trim() && !status.value) {
                node("status").textContent = `${schema.common_fields[key] ?? schema.type_fields[node("type").value][key]} 입력값의 확인 상태를 선택하세요.`;
                node("inputs-panel").open = true; status.focus?.(); return;
            }
        }
        const current = generation, body = payload(), signature = JSON.stringify(body);
        if(pending?.signature !== signature) pending = {signature,body:{...body,idempotency_key:crypto.randomUUID()}};
        busy = true; controls(); node("status").textContent = "담당자 입력 저장 중";
        try {
            await request(`${base()}/kisa-forms`,{method:"POST",body:JSON.stringify(pending.body)});
            if(current !== generation) return;
            pending = null; await loadForms(current); node("status").textContent = "새 양식 버전으로 저장했습니다 · 이전 버전과 Word는 보존됩니다. 새 Word는 'Word 신고서 만들기'로 생성합니다.";
        } catch(error) { if(current === generation) { node("status").textContent = error.message; if([409,422].includes(error.status)) pending = null; } }
        finally { busy = false; controls(); }
    }
    async function generate() {
        if(busy || !saved || dirty || saved.incident_type === "undetermined") return;
        const current = generation, form = saved; busy = true; controls();
        node("status").textContent = "저장 버전의 원본 양식 Word 신고서 생성 중";
        try {
            const result = await request(`${base()}/kisa-forms/${form.form_id}/docx`,{method:"POST"});
            if(current !== generation) return;
            exports = {...exports,[form.form_id]:{docx_sha256:result.docx_sha256}};
            showDownload(form);
            node("status").textContent = `Word 생성 완료 · 양식 v${form.report_version}`;
            if (node("generation-detail")) node("generation-detail").textContent += `\nDOCX SHA-256 ${result.docx_sha256}`;
        } catch(error) { if(current === generation) node("status").textContent = error.message; }
        finally { busy = false; controls(); }
    }
    node("type").addEventListener("change",()=>{
        if(!schema) return;
        // Prefill a visible, editable record of the human selection instead of demanding free text.
        if(!node("reason").value.trim()) node("reason").value = classificationReason(node("type").value);
        const old=payload(); renderInputs(old); change();
    });
    node("reason").addEventListener("input",change);
    node("save").addEventListener("click",()=>void save());
    node("generate").addEventListener("click",()=>void generate());
    controls();
    return {setDraft,save,generate};
}
