"use strict";
const $ = id => document.getElementById(id);
const labels = {detected:"탐지",miss:"미탐지",not_evaluated:"미평가",fast:"Fast",fusion:"Fusion",tie:"동시",none:"없음",fast_only:"Fast만",fusion_only:"Fusion만",fast_and_fusion:"Fast + Fusion"};
let token = "", listOffset = 0, generation = 0, reportDirty = false;
const fmt = value => value == null ? "—" : new Intl.DateTimeFormat("ko-KR",{timeZone:"Asia/Seoul",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",fractionalSecondDigits:3,hour12:false}).format(new Date(value));
function el(tag,text,parent){const n=document.createElement(tag);if(text!=null)n.textContent=String(text);if(parent)parent.append(n);return n;}
function button(text,parent,fn,disabled=false){const n=el("button",text,parent);n.disabled=disabled;n.onclick=fn;return n;}
function fields(parent,values){const dl=el("dl",null,parent);for(const [key,value] of values){el("dt",key,dl);el("dd",value??"—",dl);}}
function table(parent,headers,rows){const wrap=el("div",null,parent);wrap.className="scroll";const t=el("table",null,wrap),head=el("tr",null,el("thead",null,t));headers.forEach(x=>el("th",x,head));const body=el("tbody",null,t);rows.forEach(values=>{const tr=el("tr",null,body);values.forEach(value=>{const td=el("td",null,tr);if(value instanceof Node)td.append(value);else td.textContent=value??"—";});});}
async function load(path,render){if(reportDirty&&!window.confirm("저장하지 않은 입력을 버리고 이동할까요?"))return;reportDirty=false;const request=++generation;$("content").replaceChildren();$("message").className="";$("message").textContent="조회 중…";try{const response=await fetch(path,{headers:{Authorization:`Bearer ${token}`},cache:"no-store"});if(!response.ok)throw new Error(response.status===401?"인증이 만료되었거나 토큰이 올바르지 않습니다.":response.status===404?"요청한 Run, Decision 또는 Event가 없습니다.":"조회 오류가 발생했습니다. 연결 상태를 확인하고 다시 시도해 주세요.");const data=await response.json();if(request!==generation)return;$("message").textContent="";render(data);}catch(error){if(request!==generation)return;$("message").className="error";$("message").textContent=error.message;button("다시 시도",$("content"),()=>load(path,render));}}
function runs(){load(`/api/runs?limit=20&offset=${listOffset}`,data=>{const root=$("content");el("h1","Runs",root);el("p",`전체 ${data.total}개 · 시각: KST (UTC+9)`,root);if(!data.items.length)el("p","표시할 Run이 없습니다.",root);else table(root,["Run / 시나리오","대상 호스트","시작 시각","Fast / Fusion","최신 Decision"],data.items.map(run=>{const link=el("button",run.run_id);link.onclick=()=>detail(run.run_id);const d=run.latest_decision;const identity=el("div");identity.append(link);el("p",run.scenario_id,identity);return [identity,run.target_host,fmt(run.start_time),d?`${labels[d.fast_status]} / ${labels[d.fusion_status]}`:"결과 없음",d?`${d.decision_id} · ${d.entity_id}`:"결과 없음"];}));const p=el("div",null,root);p.className="pagination";button("이전",p,()=>{listOffset-=20;runs();},listOffset===0);button("다음",p,()=>{listOffset+=20;runs();},listOffset+20>=data.total);});}
function detail(runId,decisionId=null,offset=0){const params=new URLSearchParams({event_limit:"50",event_offset:String(offset)});if(decisionId)params.set("decision_id",decisionId);load(`/api/runs/${encodeURIComponent(runId)}?${params}`,data=>{const root=$("content"),d=data.selected_decision;el("h1",runId,root);el("p","모든 시각은 KST (UTC+9)입니다. 시스템 판단 시각은 담당자의 사고 인지 시각과 다릅니다.",root);fields(root,[["시나리오",data.run.scenario_id],["Run 유형 (실험 분류)",data.run.run_type],["대상 호스트",data.run.target_host],["시작",fmt(data.run.start_time)],["종료",fmt(data.run.end_time)]]);
button("Decision 이력",root,()=>history(runId,d?.decision_id??decisionId));
if(d)button("Report 초안",root,()=>report(runId,d.decision_id));
const form=el("form",null,root),label=el("label","Decision ID ",form),input=el("input",null,label);input.value=decisionId??"";input.placeholder="비우면 최신 Decision";button("조회",form,()=>{});form.onsubmit=e=>{e.preventDefault();detail(runId,input.value.trim()||null);};
const summary=el("article",null,root);el("h2","선택한 판단 결과",summary);if(!d)el("p","결과 없음",summary);else fields(summary,[["Decision / Entity",`${d.decision_id} / ${d.entity_id}`],["Fast",labels[d.fast_status]],["Fast 탐지 시각",fmt(d.detector_time)],["Fusion",labels[d.fusion_status]],["Fusion 탐지 시각",fmt(d.fusion_time)],["시스템 판단 시각",fmt(d.t_e)],["탐지 경로",labels[d.decision_path]??"—"],["최초 탐지 경로",labels[d.winning_path]??"—"],["설정 버전",d.config_version],["판단 근거",d.decision_reason]]);
const current=el("article",null,root);el("h2","현재 Entity 결과",current);el("p","선택한 Decision과 동일 실행의 결과인지 확인되지 않았습니다. 과거 판단의 근거로 사용하지 않습니다.",current);if(!data.current_entity_results)el("p","결과 없음",current);else for(const name of ["fast","fusion"]){const item=data.current_entity_results[name];const value=item.value;fields(current,[[name==="fast"?"Fast":"Fusion",item.availability==="missing"?"결과 없음":labels[value.detector_status??value.fusion_status]],["시각",fmt(value?.detector_time??value?.fusion_time)]]);}
const evidence=el("article",null,root);el("h2","Evidence ID",evidence);el("p",data.evidence.availability==="not_available"?"Evidence 정보 없음":data.evidence.ids.length?data.evidence.ids.join(", "):"기여 Evidence ID 없음",evidence);el("p","Evidence 본문 및 Event와의 연결은 제공되지 않습니다.",evidence);
el("h2","Event",root);table(root,["ID","시각","호스트","유형"],data.events.items.map(e=>{const link=el("button",e.event_id);link.onclick=()=>eventDetail(runId,e.event_id,d?.decision_id??decisionId,offset);return [link,fmt(e.timestamp),e.host_id,e.event_type];}));if(!data.events.items.length)el("p","표시할 Event가 없습니다.",root);const page=el("div",null,root);page.className="pagination";el("span",`전체 ${data.events.total}개`,page);button("이전",page,()=>detail(runId,d?.decision_id??decisionId,offset-50),offset===0);button("다음",page,()=>detail(runId,d?.decision_id??decisionId,offset+50),offset+50>=data.events.total);
el("h2","타임라인",root);el("p","현재 Event 페이지와 선택한 Decision의 시각만 표시합니다.",root);table(root,["시각","종류","출처 ID"],data.timeline.items.map(e=>[fmt(e.timestamp),e.kind,e.source_id]));});}
$("auth").onsubmit=e=>{e.preventDefault();listOffset=0;token=$("token").value;$("token").value="";$("login").hidden=true;$("workspace").hidden=false;overview();};
$("home").onclick=runs;$("logout").onclick=()=>{if(reportDirty&&!window.confirm("저장하지 않은 입력을 버리고 연결을 해제할까요?"))return;reportDirty=false;token="";generation++;$("content").replaceChildren();$("message").textContent="";$("workspace").hidden=true;$("login").hidden=false;};

function overview() {
  load("/api/overview", data => {
    const root = $("content");
    el("h1", "Overview", root);
    el("p", "전체 Run 기준 · Run마다 가장 최근에 저장된 Decision 1건을 집계합니다. 여러 호스트의 통합 판정이나 성능 평가 지표가 아닙니다.", root);
    const cards = el("div", null, root);
    cards.className = "cards";
    for (const [name, count] of [["전체 Run", data.total_runs], ["판단 결과 있음", data.runs_with_decision], ["결과 없음", data.runs_without_decision], ["전체 Event", data.total_events]]) {
      const card = el("article", null, cards);
      el("h2", name, card);
      el("strong", count, card).className = "metric";
    }
    if (!data.total_runs) el("p", "저장된 Run이 없습니다.", root);
    el("h2", "경로별 상태", root);
    table(root, ["경로", "탐지", "미탐지", "미평가", "결과 없음"], ["fast", "fusion"].map(key => [labels[key], data[key].detected, data[key].miss, data[key].not_evaluated, data[key].missing]));
    el("h2", "최신 Decision의 탐지 경로", root);
    table(root, ["탐지 경로", "Run 수"], Object.entries(data.decision_paths).map(([key, count]) => [key === "missing" ? "결과 없음" : labels[key], count]));
    button("Run 목록 보기", root, runs);
  });
}
$("overview").onclick = overview;

function history(runId, selectedId = null, offset = 0) {
  load(`/api/runs/${encodeURIComponent(runId)}/decisions?limit=20&offset=${offset}`, data => {
    const root = $("content");
    el("h1", "Decision 이력", root);
    el("p", `${runId} · 전체 ${data.total}건 · 저장 시각 최신순 · KST (UTC+9)`, root);
    el("p", "여러 Entity의 결과를 포함합니다. 대체 관계는 저장된 supersedes_decision_id만 표시합니다.", root);
    button("상세로 돌아가기", root, () => detail(runId, selectedId));
    button("최신 Decision 보기", root, () => detail(runId));
    if (!data.items.length) el("p", "표시할 Decision 이력이 없습니다.", root);
    else table(root, ["Decision", "Entity", "저장 시각", "Fast / Fusion", "시스템 판단 시각", "대체 대상 ID"], data.items.map(item => {
      const select = el("button", item.decision_id === selectedId ? `${item.decision_id} (선택됨)` : item.decision_id);
      select.onclick = () => detail(runId, item.decision_id);
      return [select, item.entity_id, fmt(item.created_at), `${labels[item.fast_status]} / ${labels[item.fusion_status]}`, fmt(item.t_e), item.supersedes_decision_id ?? "—"];
    }));
    const pager = el("div", null, root);
    pager.className = "pagination";
    button("이전", pager, () => history(runId, selectedId, offset - 20), offset === 0);
    button("다음", pager, () => history(runId, selectedId, offset + 20), offset + 20 >= data.total);
  });
}

function eventDetail(runId, eventId, decisionId, eventOffset) {
  load(`/api/runs/${encodeURIComponent(runId)}/events/${encodeURIComponent(eventId)}`, data => {
    const root = $("content");
    el("h1", "Event 상세", root);
    button("Run 상세로 돌아가기", root, () => detail(runId, decisionId, eventOffset));
    const provenance = data.provenance;
    fields(root, [["Run ID", data.run_id], ["Event ID", data.event_id], ["시각 (KST)", fmt(data.timestamp)], ["호스트", data.host_id], ["이벤트 유형", data.event_type], ["로그 소스", provenance.source], ["소스 계층", provenance.source_layer], ["원본 Event ID", provenance.source_event_id], ["시각 출처", provenance.timestamp_source]]);
    el("h2", "원본 로그 참조", root);
    const ref = provenance.raw_ref;
    fields(root, [["Raw log ID", ref.raw_log_id], ["원본 Record ID", ref.source_record_id], ["Segment 번호", ref.segment_no], ["Record 번호", ref.record_no], ["Parser", ref.parser_id], ["Parser 버전", ref.parser_version]]);
    el("p", "이 화면은 이벤트 식별 정보와 수집 출처를 제공합니다. 명령행·사용자·파일 경로·네트워크 주소 및 원본 payload는 제공하지 않습니다. 이 Event가 선택한 Decision의 근거라는 의미는 아닙니다.", root);
  });
}

window.addEventListener("beforeunload", event => {
  if (reportDirty) { event.preventDefault(); event.returnValue = ""; }
});
const reportInputs = [
  ["incident_type", "침해사고 유형", [["ransomware","랜섬웨어"],["ddos","디도스"],["other","그 밖의 해킹"]]],
  ["company_name","기업명"], ["business_number","사업자번호"], ["industry","업종"],
  ["company_size","기업 규모", [["large","대기업"],["mid","중견기업"],["small","중소기업"],["nonprofit","비영리"]]],
  ["company_address","회사 주소"], ["reporter_name","신고자 이름"], ["reporter_email","신고자 이메일"], ["reporter_phone","신고자 연락처"],
  ["occurred_at","사고 발생 시각 (KST)","datetime-local"], ["awareness_at","담당자 사고 인지 시각 (KST)","datetime-local"],
  ["awareness_evidence","인지 시각 근거·증적 참조","textarea"], ["incident_description","사고 내용·이상 징후","textarea"],
  ["damage_description","확인된 피해 내역","textarea"], ["victim_ip","피해 IP"], ["victim_domain","피해 도메인"],
  ["response_actions","실제로 수행한 조치","textarea"], ["encrypted_extensions","암호화 파일 확장자"], ["backup_status","백업 상태"],
  ["affected_server_count","피해 서버 수","number"], ["affected_pc_count","피해 PC 수","number"],
  ["server_type","공격 대상 서버 종류"], ["service_status","서비스 장애 상태"], ["attack_scale","공격 규모 (단위 포함)"], ["extortion_status","협박 여부"],
  ["technical_support_consent","기술지원 동의", [["true","동의"],["false","미동의"]]],
  ["personal_data_consent","개인정보 수집·이용 동의", [["true","동의"],["false","미동의"]]]
];
function report(runId, decisionId) {
  const path = `/api/runs/${encodeURIComponent(runId)}/decisions/${encodeURIComponent(decisionId)}/report`;
  load(path, data => {
    const root = $("content"), currentGeneration = generation;
    let revision = data.revision;
    el("h1", "Report 초안", root);
    el("p", "KISA 신고서 참고 입력 화면입니다. 확인된 사실만 작성하고 모르는 항목은 비워두세요. 이 화면에서 신고가 제출되지 않습니다.", root);
    fields(root, [["Run / Decision", `${runId} / ${decisionId}`], ["시스템 판단 시각 (인지 시각과 별개)", fmt(data.source_decision.t_e)]]);
    button("Run 상세로 돌아가기", root, () => detail(runId, decisionId));
    button("최신 저장본 다시 불러오기", root, () => report(runId, decisionId));
    const status = el("p", revision ? `저장된 초안 · 버전 ${revision}` : "아직 저장하지 않은 초안", root);
    status.setAttribute("role", "status");
    const form = el("form", null, root); form.className = "report-form";
    const inputs = new Map();
    for (const [key, title, type] of reportInputs) {
      const label = el("label", title, form);
      const input = el(Array.isArray(type) ? "select" : type === "textarea" ? "textarea" : "input", null, label);
      if (Array.isArray(type)) {
        el("option", "미입력 / 미확인", input).value = "";
        type.forEach(([value, title]) => { el("option", title, input).value = value; });
      } else if (type !== "textarea") input.type = type || "text";
      if (type === "number") { input.min = "0"; input.step = "1"; }
      if (type === "datetime-local") input.step = "0.001";
      if (!Array.isArray(type) && type !== "number" && type !== "datetime-local") input.maxLength = type === "textarea" ? 10000 : 500;
      const value = data.fields[key];
      input.value = value == null ? "" : type === "datetime-local" ? new Date(new Date(value).getTime() + 9 * 3600000).toISOString().slice(0,-1) : String(value);
      input.oninput = () => { reportDirty = true; status.textContent = "저장하지 않은 변경 사항이 있습니다."; };
      inputs.set(key, [input, type]);
    }
    const save = button("초안 저장", form, () => {});
    form.onsubmit = async event => {
      event.preventDefault();
      const fields = {};
      for (const [key, [input, type]] of inputs) {
        const value = input.value.trim();
        fields[key] = value === "" ? null : type === "datetime-local" ? new Date(value + "+09:00").toISOString() : type === "number" ? Number(value) : key.endsWith("_consent") ? value === "true" : value;
      }
      save.disabled = true;
      for (const [input] of inputs.values()) input.disabled = true;
      status.textContent = "저장 중…";
      try {
        const response = await fetch(path, {method:"PUT", headers:{Authorization:`Bearer ${token}`, "Content-Type":"application/json"}, body:JSON.stringify({expected_revision:revision, fields})});
        if (!response.ok) throw new Error(response.status === 409 ? "다른 창에서 수정했습니다. 입력 내용을 복사해 보존한 후 최신 저장본을 다시 불러오세요." : "저장하지 못했습니다. 입력 내용을 유지했습니다. 인증·입력값·서버 연결을 확인해 주세요.");
        const saved = await response.json();
        if (generation !== currentGeneration) return;
        revision = saved.revision; reportDirty = false;
        status.textContent = `초안 저장 완료 · 버전 ${revision} · ${fmt(saved.updated_at)} KST`;
      } catch (error) { if (generation === currentGeneration) status.textContent = error.message; }
      finally { save.disabled = false; for (const [input] of inputs.values()) input.disabled = false; }
    };
  });
}
