// S0 Fusion provenance is distinct from the R1 offline archive below it.
import {buildEventDetailViewPath} from "./event-detail-contract.mjs";
import {normalizeRawVerificationScope, sameRawVerificationScope, buildRawVerificationSummary, rawVerificationLabel,
    rawVerificationItemFailed, analysisTimestampLabel, observationDisplayText} from "./dashboard-operator-contract.mjs";
import {getEvidenceTypeLabel, getFeatureChannelLabel, getSourceLayerLabel} from "./dashboard-evidence-contract.mjs";
import {createCopyableValue, createDetailList, createDetailRow, createExpandButton, createStackedText,
    focusedRowKey, restoreRowFocus} from "./dashboard-detail-rows.mjs";

const LABELS = {unresolved:"미해결", event_verified:"저장 Event 연결 검증 · 원본 미검증", raw_verified:"Manifest·원본 레코드 검증"};
const REASONS = {run_manifest_unavailable:"해당 분석의 보존 Manifest 없음", run_archive_file_missing:"보존 원본 파일 없음", current_extractor_did_not_reproduce_id:"현재 Extractor로 해당 ID 재현 불가", raw_sha256_mismatch:"원본 SHA-256 불일치", manifest_raw_mapping_mismatch:"Manifest와 Raw 참조 불일치", raw_normalized_event_mismatch:"원본 레코드와 저장 Event 불일치",
    manifest_run_mismatch:"다른 분석의 Manifest", manifest_source_mismatch:"Manifest Source/Layer 불일치", manifest_sha256_missing:"Manifest에 원본 SHA-256 없음", raw_record_missing:"원본에 해당 레코드 없음", source_record_id_mismatch:"원본 RecordId와 Source Event ID 불일치",
    archive_event_identity_mismatch:"다른 분석/Raw ID의 보존 원본", stored_archive_sha256_mismatch:"저장된 보존본 해시 불일치", stored_archive_identity_mismatch:"저장된 보존본 식별자 불일치", archive_mirror_missing:"보존 복제본 파일 없음", archive_mirror_content_conflict:"보존 복제본 내용 충돌", archive_mirror_unreadable:"보존 복제본 접근 불가", archive_mirror_unconfigured:"필수 보존 복제본 경로 미설정"};
const ORIGINS = {retained:"생성 당시 증거 보존 · 버전·코드 해시 일치", retained_code_changed:"생성 당시 증거 보존 · 현재 Extractor 코드와 해시 다름", reconstructed:"현재 규칙으로 재구성 · 당시 규칙 동일성 미확인", missing:"증거 보존본 없음 · 현재 규칙으로도 재현되지 않음"};
const ORIGIN_SHORT = {retained:"생성 당시 보존본", retained_code_changed:"생성 당시 보존본 · 코드 해시 다름", reconstructed:"현재 규칙으로 재구성", missing:"증거 재현 불가"};
const COLUMNS = 6;
const SHA256 = /^[0-9a-f]{64}$/;
const noop = () => Promise.resolve();
const isText = value => typeof value === "string" && value.length > 0;
const originOf = item => item.evidence_origin === "missing" ? "missing" : item.evidence_origin !== "retained_archive" ? "reconstructed"
    : item.historical_extractor_verified ? "retained" : "retained_code_changed";

// Overview value for stored raw retention. The R1 publication is a different record, shown apart.
export function retentionStateLabel(retention) {
    if (!retention) return "보관 정보 미제공";
    if (retention.status === "storage_verified") return "보관 원본 검증됨";
    if (retention.available || retention.failure) return `보관 원본 검증 제한 · ${REASONS[retention.failure] ?? "검증 조건 미충족"}`;
    return "영속 보존 기록 없음";
}

// Detail values come from stored structured features and appear only after raw verification.
function verifiedDetail(type, features) {
    if (type === "encoded_powershell_command" && isText(features.matched_option)) return `실행 옵션 ${features.matched_option}`;
    if (type === "script_interpreter_external_connection" && isText(features.dst_ip)) {
        const protocol = isText(features.protocol) ? `${features.protocol.toUpperCase()} ` : "";
        const port = Number.isInteger(features.dst_port) ? `:${features.dst_port}` : "";
        return `${protocol}${features.dst_ip}${port} · 연결 목적·악성 여부 미확인`;
    }
    return "원본 대조 통과 · 세부 값은 상세에서 확인";
}

// One table row per contributing Evidence. Nothing is parsed out of prose; no purpose is inferred.
export function provenanceRowPresentation(item, sourceEvents) {
    const events = item.event_ids.map(id => sourceEvents.find(event => event.event_id === id
        && event.run_id === item.run_id && event.host_id === item.entity_id) ?? null);
    const stored = events.filter(Boolean);
    const verified = item.resolution_status === "raw_verified";
    const failed = rawVerificationItemFailed(item);
    const features = item.features !== null && typeof item.features === "object" ? item.features : {};
    const processes = [...new Set(stored.map(event => event.process?.name).filter(isText))];
    if (!processes.length && isText(features.process_name)) processes.push(features.process_name);
    const checks = Array.isArray(item.validation_details?.raw_checks) ? item.validation_details.raw_checks : [];
    const code = item.unresolved_reason ?? checks.find(check => check.verified === false)?.reason ?? null;
    return {
        time: analysisTimestampLabel(item.timestamp, "시각 미확인"),
        behavior: isText(item.evidence_type) ? getEvidenceTypeLabel(item.evidence_type) : "유형 미확인 · 증거 재현 불가",
        behaviorDetail: verified ? verifiedDetail(item.evidence_type, features) : "원본 대조 전 · 세부 값 미표시",
        target: item.entity_id,
        process: processes.join(", ") || "프로세스 미확인",
        source: [...new Set(stored.map(event => `${event.source} · ${getSourceLayerLabel(event.source_layer)}`))].join(", ")
            || "저장 Event 미확인",
        origin: ORIGIN_SHORT[originOf(item)],
        state: verified ? "verified" : failed ? "failed" : "unverified",
        stateLabel: verified ? "원본 대조 통과" : failed ? "원본 검증 실패"
            : item.resolution_status === "event_verified" ? "원본 대조 미완료" : "연결 미해결",
        reason: verified || !code ? null : `${REASONS[code] ?? "검증 조건 미충족"}`,
        code: verified ? null : code,
        events,
    };
}

export function createProvenanceController(doc, {fetchImpl=globalThis.fetch,onSummary=()=>{}}={}) {
    const status=doc.getElementById("provenance-status"), list=doc.getElementById("provenance-list"), retention=doc.getElementById("provenance-retention");
    if (!status || !list) return {select:noop,setActive:noop,refresh:noop,stop:noop,start:noop};
    // Optional table wrapper and overview values; older shells without them keep working.
    const region=doc.getElementById("provenance-region"), count=doc.getElementById("provenance-count"),
        retentionState=doc.getElementById("provenance-retention-state");
    let run=null, scope=null, active=false, enabled=true, version=0, shown=null, pending=null, abort=null;
    let rows=[], payloadShown=null, expanded=new Set(), buttons=new Map(), restore=null;
    const text=(tag,value)=>{const node=doc.createElement(tag);node.textContent=value;return node;};
    function cancel() {version++;abort?.abort();abort=null;pending=null;}
    function renderCount() {
        if (count) count.textContent = !run ? "선택 항목 없음" : !scope ? "기여 증거 미확인" : `${scope.evidenceIds.length}건`;
    }
    function publish(queryState, extra = {}) {
        const value = {runId:run, scope, evidenceIds:scope?.evidenceIds ?? null, queryState, ...extra};
        value.label = rawVerificationLabel(scope?.evidenceIds, value, scope);
        onSummary(value);
        return value;
    }
    // A re-read empties the table, so the focused toggle is remembered first and restored on render.
    function empty(state="미조회") {
        const key=focusedRowKey(doc,list);
        if (key!==null) restore={key,previous:doc.activeElement};
        rows=[];payloadShown=null;list.replaceChildren();
        if(region)region.hidden=true;
        if(retention)retention.textContent="";
        if(retentionState)retentionState.textContent=state;
    }
    function clear() {
        empty();
        status.textContent="검증 상태 미조회";
        renderCount();
        publish("not_requested");
    }
    function eventDetails(row) {
        const items=doc.createElement("ul");items.classList.add("provenance-events");
        row.item.event_ids.forEach((id,index)=>{
            const entry=doc.createElement("li"), event=row.events[index];
            if (!event) {entry.append(text("p",`${id} · 해당 분석의 저장 Event 미확인`));items.append(entry);return;}
            const link=text("a",`Event ${id} 상세`);link.href=buildEventDetailViewPath(run,id);
            entry.append(link,text("p",`Source Event: ${event.source_event_id} · ${event.source}/${event.source_layer} · 관측 ${analysisTimestampLabel(event.timestamp,"시각 미확인")}`));
            const reference=doc.createElement("details");
            reference.append(text("summary","원본 참조 (raw_ref)"),text("pre",JSON.stringify({timestamp:event.timestamp, timestamp_source:event.timestamp_source ?? null, raw_ref:event.raw_ref},null,2)));
            entry.append(reference);items.append(entry);
        });
        return items;
    }
    // Full hashes stay one click away so the detail row leads with the observation and its links.
    function hashDetails(item) {
        const values=doc.createElement("details");
        const label=text("summary","해시 값 보기");values.append(label);
        const evidence=item.validation_details?.evidence_sha256;
        if (SHA256.test(evidence??"")) values.append(text("p","Evidence"),createCopyableValue(doc,evidence,"Evidence SHA-256"));
        for (const check of Array.isArray(item.validation_details?.raw_checks)?item.validation_details.raw_checks:[]) {
            for (const key of ["manifest_sha256","raw_sha256","raw_record_sha256"]) {
                if (SHA256.test(check[key]??"")) values.append(text("p",`${check.event_id} · ${key}`),createCopyableValue(doc,check[key],`${check.event_id} ${key}`));
            }
        }
        const count=[...values.children].filter(child=>child.classList?.contains("dashboard-copyable")).length;
        if (!count) return text("p","해시 미제공");
        label.textContent=`해시 값 ${count}개 보기`;
        return values;
    }
    function details(row) {
        const {item}=row, verified=item.resolution_status==="raw_verified";
        const observations=verified ? item.observed_behavior.filter(observation=>isText(observation?.behavior_summary)) : [];
        const observed=doc.createElement("div");
        if (!observations.length) observed.append(text("p","상세 행위 미확인 · 원본 검증이 완료된 관측 요약 없음"));
        else for (const observation of observations) {
            observed.append(text("p",observationDisplayText(observation.behavior_summary, observation.observed_at)));
            const original=doc.createElement("details");
            original.append(text("summary","관측 문장 원문·UTC"),text("pre",JSON.stringify(observation,null,2)));
            observed.append(original);
        }
        const layer=[item.derived_from_source_layer&&getSourceLayerLabel(item.derived_from_source_layer),
            item.feature_channel_group&&getFeatureChannelLabel(item.feature_channel_group)].filter(Boolean).join(" · ");
        const content=doc.createElement("div");
        content.append(createDetailList(doc,[
            ["증거 ID",createCopyableValue(doc,item.evidence_id,"증거 ID")],
            ["증거 Type 원문",item.evidence_type??"미확인"],
            ["원본 검증 결과",`${LABELS[item.resolution_status]}${row.code?` · ${row.reason} (${row.code})`:""}`],
            ["원본 검증 관측 문장",observed],
            ["연결 Event · 원본 참조",eventDetails(row)],
            ["Extractor",`저장 ${item.extractor_version??"미확인"} · 현재 ${item.validation_details?.current_extractor_version??"미확인"}`],
            ["원본 재구성 여부",ORIGINS[originOf(item)]],
            ["출처 계층 · 채널",layer||"미확인"],
            ["원본 대조 해시",hashDetails(item)],
            ["보관 범위",`누적 분석 기여 증거만 대조 · ${retentionStateLabel(payloadShown?.raw_retention)} · R1 게시 아카이브와 별개`],
        ]));
        const proof=doc.createElement("details");proof.append(text("summary","검증 근거 원문 (validation_details)"),text("pre",JSON.stringify(item.validation_details,null,2)));
        content.append(proof);
        return content;
    }
    function row(presentation) {
        const {item}=presentation, key=`${item.entity_id}\u0000${item.evidence_id}`;
        const tr=doc.createElement("tr");tr.classList.add("dashboard-evidence-row");tr.dataset.state=presentation.state;
        const time=doc.createElement("time");time.textContent=presentation.time;
        if (item.timestamp) {time.setAttribute("datetime",item.timestamp);time.title=`원본 ${item.timestamp}`;}
        const button=createExpandButton(doc,{key,label:`${presentation.behavior} · ${presentation.time}`,expanded:expanded.has(key),onToggle:toggle});
        buttons.set(key,button);
        for (const value of [time,createStackedText(doc,presentation.behavior,presentation.behaviorDetail,item.evidence_type??""),
            createStackedText(doc,presentation.target,presentation.process),createStackedText(doc,presentation.source,presentation.origin),
            createStackedText(doc,presentation.stateLabel,presentation.reason),button]) {
            const cell=doc.createElement("td");cell.append(value);tr.append(cell);
        }
        return expanded.has(key) ? [tr,createDetailRow(doc,COLUMNS,details(presentation))] : [tr];
    }
    function renderRows() {
        buttons=new Map();
        list.replaceChildren(...rows.flatMap(row));
        if(region)region.hidden=rows.length===0;
    }
    function toggle(key) {
        if (expanded.has(key)) expanded.delete(key); else expanded.add(key);
        const previous=doc.activeElement;
        renderRows();
        restoreRowFocus(doc,buttons,key,previous);
    }
    function render(payload, targetScope) {
        const summary = buildRawVerificationSummary(payload, targetScope);
        if (payload.schema_version!=="evidence_provenance_v1" || payload.run_id!==run || !Array.isArray(payload.items)
            || !Array.isArray(payload.source_events)) throw Error("Invalid provenance response");
        const selectedItems=payload.items.filter(item=>item.entity_id===targetScope.entityId && targetScope.evidenceIds.includes(item.evidence_id));
        for (const item of selectedItems) {
            if (item.run_id!==run || !(item.resolution_status in LABELS) || !Array.isArray(item.event_ids)
                || !Array.isArray(item.observed_behavior)) throw Error("Invalid provenance item");
        }
        const instant=item=>{const value=Date.parse(item.timestamp??"");return Number.isFinite(value)?value:Infinity;};
        rows=selectedItems.map(item=>({item,...provenanceRowPresentation(item,payload.source_events)}))
            .sort((left,right)=>instant(left.item)-instant(right.item) || left.item.evidence_id.localeCompare(right.item.evidence_id));
        payloadShown=payload;
        if(retention){const r=payload.raw_retention;
            retention.textContent=r?.status==="storage_verified"
                ? `PostgreSQL 원본 보존 검증 · ${r.byte_size} bytes · SHA-256 ${r.content_sha256} · Manifest ${r.manifest_identity}`
                : r?.available || r?.failure ? `원본 보존 검증 제한: ${REASONS[r.failure]??"검증 조건 미충족"} (${r.failure??"미확인"})` : "이 분석의 영속 Raw 보존 증적이 조회되지 않았습니다.";
            const experiment=payload.experiment_input;
            if(experiment?.declaration) retention.textContent+=` · 실험 입력 선언: ${experiment.declaration["experiment-run-type"]} · 실행 Metadata: ${experiment.execution_run_type} · 출처: 로컬 데모 Actor의 명시적 선언 (탐지 결과 아님)`;
        }
        if(retentionState)retentionState.textContent=retentionStateLabel(payload.raw_retention);
        renderRows();
        if (restore) restoreRowFocus(doc,buttons,restore.key,restore.previous);
        restore=null;
        status.textContent=rawVerificationLabel(targetScope.evidenceIds,summary,targetScope);
        onSummary({...summary,label:status.textContent});
    }

    function load() {
        if (!enabled || !active || !run || !scope) return Promise.resolve();
        if (pending) return pending;
        if (!scope.evidenceIds.length) {
            shown=scope;
            const value=publish("not_requested",{resultState:"empty",verified:0,failed:0,total:0});
            status.textContent=value.label;
            return Promise.resolve();
        }
        cancel();const target=run,targetScope=scope,current=version;shown=scope;abort=new AbortController();
        const requestAbort=abort,signal=abort.signal;
        empty("조회 중");
        status.textContent=publish("loading").label;
        pending=(async()=>{
            const timer=setTimeout(()=>requestAbort.abort(),10000);
            try {
                const response=await fetchImpl(`/runs/${encodeURIComponent(target)}/evidence-provenance`,{signal,cache:"no-store",headers:{Accept:"application/json"}});
                if (!enabled || current!==version) return;
                if (!response.ok) {
                    let detail=null;
                    try {detail=(await response.json())?.detail;} catch {}
                    if (!enabled || current!==version) return;
                    if (response.status===404 && detail==="Not Found") {
                        empty("검증 정보 미지원");
                        status.textContent=publish("unsupported").label;
                    } else {
                        shown=null;empty("조회 실패");
                        status.textContent=publish("error",{errorKind:detail==="Run not found"?"run_missing":"http",httpStatus:response.status}).label
                            + (detail==="Run not found"?" · 선택한 분석 항목 없음":` · HTTP ${response.status}`);
                    }
                    return;
                }
                const payload=await response.json();
                if (enabled && current===version && sameRawVerificationScope(scope,targetScope)) render(payload,targetScope);
            } catch {
                if (enabled && current===version) {
                    empty("조회 실패");
                    status.textContent=publish("error").label+" · 원본 검증 정보를 다시 조회하세요.";
                    shown=null;
                }
            } finally {clearTimeout(timer);if (current===version) {pending=null;abort=null;}}
        })();return pending;
    }
    return {
        select(next, selection=null) {
            const nextScope=normalizeRawVerificationScope(selection);
            const matching=run===next && (scope===null && nextScope===null || sameRawVerificationScope(scope,nextScope));
            if (!matching) {cancel();run=next;scope=nextScope?.runId===next?nextScope:null;shown=null;expanded=new Set();clear();restore=null;}
            return !sameRawVerificationScope(shown,scope)?load():(pending??Promise.resolve());
        },
        setActive(next) {active=next;return !sameRawVerificationScope(shown,scope)?load():(pending??Promise.resolve());},
        refresh() {cancel();shown=null;clear();return load();},
        stop() {enabled=false;cancel();shown=null;clear();},
        start() {enabled=true;return load();},
    };
}
