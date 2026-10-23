// Track-B is a separate read-only identity. This module never calls a canonical API.
import { formatOperatorTimestamp } from "./dashboard-contract.mjs";

const STATES = new Set(["observing", "condition_not_met", "demo_rule_match", "input_error"]);
const READS = new Set(["ok", "file_missing", "read_failed", "invalid_snapshot", "timeout", "connection_failed", "remote_error", "clock_skew", "configuration_error"]);
const LABELS = {waiting:"수락 대기",observing:"관측 중",condition_not_met:"현재 관측 범위에서 조건 미충족",
    demo_rule_match:"규칙 기반 의심 관측 · 정식 분석 미수행",delayed:"보고 지연",unknown:"상태 미확인"};
const READ_LABELS = {file_missing:"Snapshot 파일 없음",read_failed:"Snapshot 읽기 실패",invalid_snapshot:"Snapshot 계약 검증 실패",
    timeout:"조회 시간 초과",connection_failed:"연결 실패",remote_error:"원격 조회 실패",clock_skew:"서버·detector 시각 확인 필요",configuration_error:"연결 설정 확인 필요"};
const runPattern = /^RUN-[0-9]{8}-[0-9]{3,6}$/;
const instant = value => typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
export const liveIdentity = item => JSON.stringify(["live_observation", item.run_id, item.host_id]);

export function liveDisplayState(item, elapsed = 0) {
    if (item.read_status !== "ok" || item.snapshot_age_ms === null || !Number.isFinite(elapsed)) return "unknown";
    const age = item.snapshot_age_ms + Math.max(0, elapsed);
    if (age > 15000) return "unknown";
    if (age > 5000) return "delayed";
    if (item.detector_state === "observing") return item.accepted_chunk_count === 0 ? "waiting" : "observing";
    return ["condition_not_met", "demo_rule_match"].includes(item.detector_state) ? item.detector_state : "unknown";
}

export function validateLiveEnvelope(payload) {
    if (payload?.schema_version !== "track_b_observations_v1" || typeof payload.enabled !== "boolean" || !instant(payload.server_time)
        || !Array.isArray(payload.items) || payload.items.length > 20) throw Error("Invalid Live envelope");
    const runs = new Set();
    for (const item of payload.items) {
        if (!runPattern.test(item.run_id) || runs.has(item.run_id) || item.source_kind !== "live_observation"
            || item.data_class !== "demo_only" || item.canonical_result !== null || !READS.has(item.read_status)
            || item.human_workflow !== false || item.ai_report !== false || item.formal_analysis !== false
            || item.acceptance_scope !== "detector_reported" || item.ledger_independently_verified !== false
            || (item.generated_at !== null && !instant(item.generated_at))
            || (item.last_accepted_at !== null && !instant(item.last_accepted_at))
            || (item.snapshot_age_ms !== null && (!Number.isInteger(item.snapshot_age_ms) || item.snapshot_age_ms < 0))) throw Error("Invalid Live item");
        runs.add(item.run_id);
        if (item.read_status === "ok") {
            if (!STATES.has(item.detector_state) || !instant(item.generated_at)
                || !Number.isInteger(item.accepted_chunk_count) || item.accepted_chunk_count < 0
                || !Number.isInteger(item.accepted_event_count) || item.accepted_event_count < 0
                || item.acceptance !== (item.accepted_chunk_count ? "post_commit_ack_verified" : "pending")) throw Error("Invalid acceptance");
            if (["demo_rule_match", "condition_not_met"].includes(item.detector_state)
                && (!item.accepted_chunk_count || !item.accepted_event_count || !item.host_id || !item.network_event_id
                    || !item.terminal_process_guid || !Array.isArray(item.observed_lineage) || item.observed_lineage.length < 2
                    || !Array.isArray(item.lineage_event_ids) || item.lineage_event_ids.length !== item.observed_lineage.length
                    || !Array.isArray(item.source_event_ids) || !item.source_event_ids.length || item.diagnostics?.length)) throw Error("Incomplete candidate");
        }
        if (item.state !== liveDisplayState(item)) throw Error("Live API state mismatch");
    }
    if (!payload.enabled && payload.items.length) throw Error("Disabled Live source has items");
    return payload;
}

export function createLiveObservationController(doc, {fetchImpl = (...args) => fetch(...args), onChange = () => {},
    nowImpl = () => performance.now(), setTimeoutImpl = globalThis.setTimeout, clearTimeoutImpl = globalThis.clearTimeout} = {}) {
    const node = id => doc.getElementById(id);
    let items = [], received = 0, selected = null, selectedLast = null, enabled = false, active = false;
    let version = 0, pending = null, abort = null, pollTimer = null, ageTimer = null, requestTimer = null, failures = 0;
    function element(tag, value, className = null) {
        const el = doc.createElement(tag);if(className)el.classList.add(className);el.textContent=value;return el;
    }
    function label(item) { return LABELS[liveDisplayState(item, nowImpl()-received)]; }
    function setStatus(text) { const el=node("live-source-status");if(el){el.textContent=text;el.hidden=!text;} }
    function selectionViews() {
        for (const id of ["stored-selection-view","stored-analysis-view"]) if(node(id))node(id).hidden=selected!==null;
        for (const id of ["live-selection-view","live-analysis-view"]) if(node(id))node(id).hidden=selected===null;
        const region=node("live-analysis-view")?.parentElement;
        region?.setAttribute("aria-labelledby", selected ? "live-analysis-heading" : "selected-run-heading");
    }
    function renderSelected() {
        selectionViews();if(!selected)return;
        const item=items.find(value=>liveIdentity(value)===selected)??selectedLast;
        if(!item)return;selectedLast=item;
        const state=liveDisplayState(item,nowImpl()-received);
        const status=label(item), clock=formatOperatorTimestamp(item.generated_at,{missing:"보고 시각 미확인"});
        for(const id of ["live-selected-target","live-detail-target"])if(node(id))node(id).textContent=item.host_id??"대상 미확인";
        if(node("live-selected-status"))node("live-selected-status").textContent=status;
        if(node("live-selected-run"))node("live-selected-run").textContent=`${item.run_id} · Live · demo_only`;
        const content=node("live-detail-content");
        if(content){
            const values=[["현재 상태",status],["조회 상태",READ_LABELS[item.read_status]??"조회 완료"],
                ["마지막 detector 보고",`${item.detector_state??"미확인"} · ${clock}`],
                ["ACK 수락 시각",formatOperatorTimestamp(item.last_accepted_at,{missing:"수락 시각 없음"})],
                ["detector 보고 수락량",item.accepted_chunk_count===null?"미확인":`${item.accepted_chunk_count} chunk · ${item.accepted_event_count} 이벤트`],
                ["수락 상태 (detector 보고)",item.acceptance==="post_commit_ack_verified"?"post_commit_ack_verified":item.acceptance==="pending"?"수락 대기":"미확인"],
                ["관측 계보",item.observed_lineage?.join(" → ")||"관측 계보 없음"],
                ["정식 분석", "미수행 · Workflow·AI 신고서 사용 불가"]];
            const dl=doc.createElement("dl");dl.classList.add("dashboard-analysis-summary");
            dl.append(...values.map(([key,value])=>{const field=doc.createElement("div");field.append(element("dt",key),element("dd",value));return field;}));
            content.replaceChildren(dl);
            content.dataset.currentMatch=String(state==="demo_rule_match");
        }
        if(node("live-technical-json"))node("live-technical-json").textContent=JSON.stringify(item,null,2);
    }
    function notify(){renderSelected();onChange();}
    function ageLoop(){if(!active||!enabled)return;ageTimer=setTimeoutImpl(()=>{notify();ageLoop();},1000);}
    function schedule(){if(active)pollTimer=setTimeoutImpl(()=>void poll(),failures?Math.min(10000,1000*2**failures):1000);}
    async function poll(){
        if(!active||pending)return pending;
        clearTimeoutImpl(pollTimer);pollTimer=null;
        const current=version;abort=new AbortController();const requestAbort=abort;
        const timeout=setTimeoutImpl(()=>requestAbort.abort(),4000);
        requestTimer=timeout;
        pending=(async()=>{
            try{
                const response=await fetchImpl("/operations/observations",{cache:"no-store",signal:requestAbort.signal,headers:{Accept:"application/json"}});
                if(!response.ok)throw Error(response.status===404?"unsupported":"unavailable");
                const payload=validateLiveEnvelope(await response.json());
                if(!active||current!==version||requestAbort.signal.aborted)return;
                items=payload.items;received=nowImpl();
                const transportFailed=items.length>0&&items.every(item=>["timeout","connection_failed","remote_error","configuration_error"].includes(item.read_status));
                failures=transportFailed?failures+1:0;
                const justEnabled=!enabled;enabled=payload.enabled;
                setStatus(enabled?`Live 시연 관측 ${items.length}건 · 정식 분석과 별도${transportFailed?" · 연결 상태 확인 필요":""}`:"");
                if(justEnabled&&enabled)ageLoop();
                if(!enabled){active=false;clearTimeoutImpl(ageTimer);}
                // A waiting/error row has no host yet. Resolve it once within that same Run;
                // never silently replace a previously known host with a different one.
                if(selected&&selectedLast?.host_id===null){
                    const resolved=items.find(item=>item.run_id===selectedLast.run_id&&item.host_id!==null&&item.read_status==="ok");
                    if(resolved){selected=liveIdentity(resolved);selectedLast=resolved;}
                }
                // A removed registration never leaves a previous Match current in the selection.
                if(selected&&!items.some(value=>liveIdentity(value)===selected)&&selectedLast)selectedLast={...selectedLast,read_status:"remote_error",state:"unknown"};
                notify();
            }catch(error){
                if(!active||current!==version)return;
                failures+=1;items=items.map(item=>({...item,read_status:"connection_failed",state:"unknown"}));
                if(selectedLast)selectedLast={...selectedLast,read_status:"connection_failed",state:"unknown"};
                setStatus(error.message==="unsupported"?"Live 관측 API 미지원 · 서버 반영 필요":"Live 관측 조회 실패 · 현재 상태 미확인");
                notify();if(error.message==="unsupported")active=false;
            }finally{clearTimeoutImpl(timeout);if(current===version){pending=null;abort=null;schedule();}}
        })();return pending;
    }
    function clearSelection(){if(!selected)return;selected=null;selectedLast=null;selectionViews();notify();}
    function choose(item){selected=liveIdentity(item);selectedLast=item;notify();}
    node("live-detail-open")?.addEventListener("click",()=>{node("live-analysis-heading")?.focus?.();node("live-analysis-view")?.scrollIntoView?.({block:"start"});});
    node("live-detail-refresh")?.addEventListener("click",()=>{clearTimeoutImpl(pollTimer);if(!active){active=true;version+=1;}void poll();});
    return {
        get isSelected(){return selected!==null;},
        get selectedIdentity(){return selected;},
        get items(){return items;},
        clearSelection,choose,poll,
        rows(query="",runType="all"){
            if(runType!=="all")return [];
            return items.filter(item=>`${item.run_id} ${item.host_id??""} Live`.toLowerCase().includes(query.toLowerCase())).map(item=>{
                const tr=doc.createElement("tr");tr.dataset.kind="live_observation";tr.dataset.runId=item.run_id;tr.dataset.entityId=item.host_id??"";
                tr.dataset.currentMatch=String(liveDisplayState(item,nowImpl()-received)==="demo_rule_match");
                if(liveIdentity(item)===selected)tr.classList.add("dashboard-table__row--selected");
                const button=element("button",`${item.host_id??"대상 미확인"} · Live`,"dashboard-run-selector");
                button.type="button";button.dataset.kind="live_observation";button.dataset.runId=item.run_id;button.dataset.entityId=item.host_id??"";
                button.setAttribute("aria-pressed",String(liveIdentity(item)===selected));button.addEventListener("click",()=>choose(item));
                const values=[`Live 보고 ${formatOperatorTimestamp(item.generated_at,{missing:"미확인"})}`,button,
                    `시연 관측 · ${item.accepted_event_count===null?"수락량 미확인":`수락 이벤트 ${item.accepted_event_count}건 (detector 보고)`}`,
                    label(item),"Workflow·AI 사용 불가",`${item.run_id} · demo_only`];
                for(const value of values){const td=doc.createElement("td");if(typeof value==="string")td.textContent=value;else td.append(value);tr.append(td);}
                return tr;
            });
        },
        start(){if(active)return pending;active=true;version+=1;notify();if(enabled)ageLoop();return poll();},
        stop(){active=false;version+=1;abort?.abort();pending=null;clearTimeoutImpl(pollTimer);clearTimeoutImpl(ageTimer);clearTimeoutImpl(requestTimer);},
    };
}
