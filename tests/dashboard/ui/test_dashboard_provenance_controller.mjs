import test from "node:test";
import assert from "node:assert/strict";
import {createProvenanceController, provenanceRowPresentation} from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-provenance-controller.mjs";

function harness(fetchImpl, options = {}) {
    const nodes=new Map();
    const doc={activeElement:null};
    // Task 6 table rows use attributes, classes, toggles and focus; the fake keeps only those.
    const element=tag=>{
        const node={tag,textContent:"",children:[],attributes:new Map(),listeners:new Map(),dataset:{},classes:new Set(),hidden:false,
            classList:{add:(...names)=>names.forEach(name=>node.classes.add(name)),contains:name=>node.classes.has(name)},
            append(...values){this.children.push(...values);},replaceChildren(...values){this.children=values;},
            setAttribute(name,value){this.attributes.set(name,String(value));},getAttribute(name){return this.attributes.get(name)??null;},
            addEventListener(type,listener){this.listeners.set(type,[...(this.listeners.get(type)??[]),listener]);},
            click(){for(const listener of this.listeners.get("click")??[])listener({type:"click",target:this});},
            focus(){doc.activeElement=this;},
            contains(target){return target===this||this.children.some(child=>child.contains?.(target));}};
        return node;
    };
    doc.createElement=element;
    doc.getElementById=id=>{if(!nodes.has(id))nodes.set(id,element("div"));return nodes.get(id);};
    const calls=[];
    return {controller:createProvenanceController(doc,{...options,fetchImpl:(...args)=>{calls.push(args);return fetchImpl(...args);}}),calls,doc,
        status:()=>doc.getElementById("provenance-status").textContent,list:()=>doc.getElementById("provenance-list").children};
}
const payload=(run="TEST-RUN",level="event_verified")=>({schema_version:"evidence_provenance_v1",scope:"fusion_contributing_ids_only",run_id:run,
    items:[{run_id:run,evidence_id:"E-TEST",evidence_type:"encoded_powershell_command",entity_id:"TEST-HOST",extractor_version:"s0-v0.1",resolution_status:level,
        event_ids:["evt-test"],unresolved_reason:level==="raw_verified"?null:"run_manifest_unavailable",validation_details:{},observed_behavior:[]}],
    source_events:[{event_id:"evt-test",run_id:run,host_id:"TEST-HOST",source_event_id:"7732",raw_ref:{record_no:14},timestamp:"2026-01-01T00:00:00Z",source:"sysmon",source_layer:"raw_telemetry"}]});
const scope=(run="TEST-RUN",ids=["E-TEST"],decision="DEC-TEST",entity="TEST-HOST")=>({runId:run,entityId:entity,decisionId:decision,evidenceIds:ids});
const response=value=>({ok:true,json:async()=>value});
const flatten=node=>node.textContent+node.children.map(flatten).join("");
const descendants=node=>node.children.flatMap(child=>[child,...descendants(child)]);
const mainRows=h=>h.list().filter(row=>row.classList.contains("dashboard-evidence-row"));
// Opens one row's detail and returns the row and its detail text; nothing is fetched by expanding.
function expanded(h,index=0){
    const calls=h.calls.length;
    descendants(mainRows(h)[index]).find(node=>node.classList?.contains("dashboard-evidence-expand")).click();
    const row=mainRows(h)[index], detail=h.list()[h.list().indexOf(row)+1];
    assert.ok(detail.classList.contains("dashboard-evidence-detail-row"));assert.equal(h.calls.length,calls);
    return flatten(row)+flatten(detail);
}

test("operator summary uses measured provenance counts and clears error instead of claiming validation",async()=>{
    // Given
    const observed=[];let fail=false;
    const h=harness(async()=>{if(fail)throw Error("network");return response(payload("TEST-RUN","raw_verified"));},{onSummary:summary=>observed.push(summary)});
    // When / Then
    await h.controller.select("TEST-RUN",scope("TEST-RUN"));await h.controller.setActive(true);
    assert.deepEqual(observed.at(-1),{runId:"TEST-RUN",scope:scope(),evidenceIds:["E-TEST"],queryState:"ready",resultState:"passed",verified:1,failed:0,total:1,observations:[],label:"원본 대조 통과 · 1/1건"});
    fail=true;await h.controller.refresh();
    assert.equal(observed.at(-1).queryState,"error");
    assert.equal(observed.at(-1).label,"조회 실패");
    assert.equal(observed.at(-1).resultState,undefined);
});

test("reads selected Run lazily without recording human actions",async()=>{
    const h=harness(async()=>response(payload()));
    await h.controller.select("TEST-RUN",scope("TEST-RUN"));assert.equal(h.calls.length,0);
    await h.controller.setActive(true);await h.controller.setActive(true);
    assert.equal(h.calls.length,1);assert.equal(h.calls[0][0],"/runs/TEST-RUN/evidence-provenance");
    const row=flatten(mainRows(h)[0]);
    assert.match(row,/인코딩된 PowerShell 실행 옵션 사용/);assert.match(row,/원본 대조 전 · 세부 값 미표시/);
    assert.match(row,/원본 대조 미완료/);assert.equal(row.includes("E-TEST"),false);
    const card=expanded(h);assert.match(card,/Event 연결 검증 · 원본 미검증/);
    assert.match(card,/7732/);assert.match(card,/14/);
    assert.match(card,/상세 행위 미확인/);assert.equal(h.calls[0][1].method,undefined);
});

test("event_verified never displays a falsely asserted behavior",async()=>{
    const p=payload();p.items[0].observed_behavior=[{behavior_summary:"FORGED EXFILTRATION"}];
    const h=harness(async()=>response(p));await h.controller.select("TEST-RUN",scope("TEST-RUN"));await h.controller.setActive(true);
    assert.equal(expanded(h).includes("FORGED"),false);
});

test("Run switch discards a stale response and handles failures without claiming verification",async()=>{
    let finish;
    const h=harness(async url=>url.includes("FIRST")?await new Promise(resolve=>{finish=()=>resolve(response(payload("FIRST")));}):response(payload("SECOND")));
    await h.controller.select("FIRST",scope("FIRST"));const old=h.controller.setActive(true);
    await h.controller.select("SECOND",scope("SECOND"));finish();await old;
    assert.match(expanded(h),/E-TEST/);
    assert.ok(descendants(h.list()[1]).find(child=>child.tag==="a").href.includes("SECOND"));
    const bad=harness(async()=>{throw Error("server unavailable");});await bad.controller.select("TEST-RUN",scope("TEST-RUN"));await bad.controller.setActive(true);
    assert.match(bad.status(),/조회 실패/);assert.equal(bad.list().length,0);
});

test("unselected or mismatched Run is never shown as verified",async()=>{
    const h=harness(async()=>response(payload("OTHER-RUN")));
    await h.controller.select("TEST-RUN",scope("TEST-RUN"));await h.controller.setActive(true);
    assert.match(h.status(),/조회 실패/);assert.equal(h.list().length,0);
});

test("miss and not_evaluated leave the evidence list empty",async()=>{
    const p=payload();p.items=[];p.source_events=[];
    const h=harness(async()=>response(p));await h.controller.select("TEST-RUN",scope("TEST-RUN",[]));await h.controller.setActive(true);
    assert.equal(h.calls.length,0);assert.equal(h.status(),"검증 대상 없음");assert.equal(h.list().length,0);
});

test("raw_verified shows retained storage proof and only the verified observation",async()=>{
    const p=payload("TEST-RUN","raw_verified");
    Object.assign(p.items[0],{unresolved_reason:null,evidence_origin:"retained_archive",historical_extractor_verified:true,
        observed_behavior:[{behavior_summary:"TEST-ONLY 검증된 관측 요약"}]});
    p.raw_retention={available:true,status:"storage_verified",byte_size:42,content_sha256:"a".repeat(64),manifest_identity:"raw-manifest:TEST-RUN:sha256:"+"b".repeat(64)};
    const h=harness(async()=>response(p));await h.controller.select("TEST-RUN",scope("TEST-RUN"));await h.controller.setActive(true);
    const card=expanded(h);
    assert.match(card,/Manifest·원본 레코드 검증/);assert.match(card,/TEST-ONLY 검증된 관측 요약/);
    assert.match(card,/버전·코드 해시 일치/);assert.equal(card.includes("상세 행위 미확인"),false);
    assert.match(h.doc.getElementById("provenance-retention").textContent,/PostgreSQL 원본 보존 검증 · 42 bytes/);
});

test("retained Evidence after an extractor edit is not described as a reconstruction",async()=>{
    const p=payload("TEST-RUN","raw_verified");
    Object.assign(p.items[0],{unresolved_reason:null,evidence_origin:"retained_archive",historical_extractor_verified:false});
    const h=harness(async()=>response(p));await h.controller.select("TEST-RUN",scope("TEST-RUN"));await h.controller.setActive(true);
    const card=expanded(h);
    assert.match(card,/현재 Extractor 코드와 해시 다름/);assert.equal(card.includes("현재 규칙으로 재구성"),false);
});

test("degraded retention states the code-owned reason, never a verified archive",async()=>{
    const p=payload();
    p.raw_retention={available:false,status:"degraded",failure:"stored_archive_sha256_mismatch"};
    const h=harness(async()=>response(p));await h.controller.select("TEST-RUN",scope("TEST-RUN"));await h.controller.setActive(true);
    const line=h.doc.getElementById("provenance-retention").textContent;
    assert.match(line,/검증 제한: 저장된 보존본 해시 불일치/);assert.equal(line.includes("PostgreSQL 원본 보존 검증"),false);
});

test("preserved older servers without the new API do not claim missing evidence",async()=>{
    const h=harness(async()=>({ok:false,status:404,json:async()=>({detail:"Not Found"})}));
    await h.controller.select("TEST-RUN",scope("TEST-RUN"));await h.controller.setActive(true);
    assert.equal(h.status(),"검증 정보 미지원");
    assert.equal(h.list().length,0);
});


function pair(run="TEST-RUN", levels=["raw_verified","raw_verified"]) {
    const value=payload(run);
    value.items=levels.map((level,index)=>({...payload(run,level).items[0],
        evidence_id:`E-${index+1}`,event_ids:[`evt-${index+1}`]}));
    value.source_events=levels.map((_,index)=>({...value.source_events[0],event_id:`evt-${index+1}`}));
    return value;
}

test("Task 2 exposes not-requested and loading before replacing them with a scoped verification result",async()=>{
    // Given
    let deliver;const seen=[];
    const h=harness(()=>new Promise(resolve=>{deliver=resolve;}),{onSummary:value=>seen.push(value)});
    // When
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-1","E-2"]));
    assert.equal(seen.at(-1).label,"검증 상태 미조회");assert.equal(h.calls.length,0);
    const request=h.controller.setActive(true);
    assert.equal(seen.at(-1).queryState,"loading");assert.equal(seen.at(-1).label,"원본 검증 확인 중");
    deliver(response(pair()));await request;
    // Then
    assert.equal(seen.at(-1).label,"원본 대조 통과 · 2/2건");
    assert.deepEqual(seen.at(-1).scope,scope("TEST-RUN",["E-1","E-2"]));
});

for (const [name,levels,reason,label] of [
    ["partial",["raw_verified","event_verified"],"run_manifest_unavailable","일부 검증 · 1/2건 통과"],
    ["hash mismatch",["event_verified","event_verified"],"raw_sha256_mismatch","원본 검증 실패 · 0/2건 통과"],
    ["partial with failure",["raw_verified","event_verified"],"raw_normalized_event_mismatch","일부 검증 · 1/2건 통과 · 원본 검증 실패 1건"],
    ["unavailable file",["event_verified","unresolved"],"run_archive_file_missing","원본 대조 미완료 · 0/2건 통과"],
    ["unknown reason",["event_verified","unresolved"],"future_reason","원본 대조 미완료 · 0/2건 통과"],
]) {
    test(`Task 2 distinguishes ${name} from a transport failure`,async()=>{
        // Given
        const p=pair("TEST-RUN",levels);
        for(const item of p.items)if(item.resolution_status!=="raw_verified")item.unresolved_reason=reason;
        const seen=[];const h=harness(async()=>response(p),{onSummary:value=>seen.push(value)});
        // When
        await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-1","E-2"]));await h.controller.setActive(true);
        // Then
        assert.equal(seen.at(-1).queryState,"ready");assert.equal(h.status(),label);
        assert.ok(expanded(h,1).includes(reason));
        assert.doesNotMatch(h.status(),/^조회 실패/);
    });
}

for(const [name,makeResponse] of [
    ["network",async()=>{throw Error("network");}],
    ["missing response",async()=>undefined],
    ["invalid JSON",async()=>({ok:true,json:async()=>{throw Error("parse");}})],
    ["HTTP 422",async()=>({ok:false,status:422,json:async()=>({detail:"Stored Evidence provenance could not be verified"})})],
    ["HTTP 503",async()=>({ok:false,status:503,json:async()=>({detail:"unavailable"})})],
]) {
    test(`Task 2 reports ${name} as query failure and clears prior success`,async()=>{
        // Given
        let fail=false;const seen=[];
        const h=harness(async()=>fail?makeResponse():response(payload("TEST-RUN","raw_verified")),{onSummary:value=>seen.push(value)});
        await h.controller.select("TEST-RUN",scope());await h.controller.setActive(true);
        assert.equal(seen.at(-1).resultState,"passed");
        // When
        fail=true;await h.controller.refresh();
        // Then
        assert.equal(seen.at(-1).queryState,"error");assert.equal(seen.at(-1).resultState,undefined);
        assert.match(h.status(),/^조회 실패/);assert.doesNotMatch(h.status(),/원본 검증 실패|대조 통과/);
        assert.equal(h.list().length,0);
    });
}

test("Task 2 does not call every 404 unsupported",async()=>{
    // Given / When / Then
    for(const detail of ["Run not found","unknown response",null]){
        const seen=[];const h=harness(async()=>({ok:false,status:404,json:async()=>({detail})}),{onSummary:value=>seen.push(value)});
        await h.controller.select("TEST-RUN",scope());await h.controller.setActive(true);
        assert.equal(seen.at(-1).queryState,"error");assert.match(h.status(),/^조회 실패/);
        assert.notEqual(h.status(),"검증 정보 미지원");
    }
});

test("Task 2 invalidates the same Run when its Decision or evidence set changes",async()=>{
    // Given
    const seen=[];const h=harness(async()=>response(pair()),{onSummary:value=>seen.push(value)});
    const original=scope("TEST-RUN",["E-1","E-2"]);
    await h.controller.select("TEST-RUN",original);await h.controller.setActive(true);
    // When / Then: order is not identity; a new Decision is.
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-2","E-1"]));assert.equal(h.calls.length,1);
    await h.controller.setActive(false);
    await h.controller.select("TEST-RUN",{...original,decisionId:"DEC-NEXT"});
    assert.equal(seen.at(-1).label,"검증 상태 미조회");assert.equal(h.list().length,0);assert.equal(h.calls.length,1);
    await h.controller.setActive(true);assert.equal(h.calls.length,2);
    assert.equal(seen.at(-1).scope.decisionId,"DEC-NEXT");
    await h.controller.setActive(false);
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-NEW"],"DEC-NEXT"));
    assert.equal(seen.at(-1).queryState,"not_requested");
    await h.controller.setActive(true);assert.equal(seen.at(-1).queryState,"error");assert.equal(h.list().length,0);
});

test("Task 2 discards an in-flight old Decision even if its Evidence IDs are unchanged",async()=>{
    // Given
    let deliver;const seen=[];let count=0;
    const h=harness(async()=>++count===1?new Promise(resolve=>{deliver=resolve;}):response(payload("TEST-RUN","event_verified")),
        {onSummary:value=>seen.push(value)});
    await h.controller.select("TEST-RUN",scope());const old=h.controller.setActive(true);
    // When
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-TEST"],"DEC-NEXT"));
    deliver(response(payload("TEST-RUN","raw_verified")));await old;
    // Then
    assert.equal(seen.at(-1).scope.decisionId,"DEC-NEXT");assert.equal(seen.at(-1).resultState,"unverified");
    assert.doesNotMatch(h.status(),/원본 대조 통과/);
});

test("Task 2 resets a verified Run on Run switch, null selection and inactive refresh",async()=>{
    // Given
    const seen=[];const h=harness(async url=>response(payload(url.includes("FIRST")?"FIRST":"SECOND","raw_verified")),{onSummary:value=>seen.push(value)});
    await h.controller.select("FIRST",scope("FIRST"));await h.controller.setActive(true);
    await h.controller.setActive(false);
    // When / Then
    await h.controller.select("SECOND",scope("SECOND"));assert.equal(seen.at(-1).label,"검증 상태 미조회");
    await h.controller.setActive(true);assert.equal(seen.at(-1).runId,"SECOND");
    await h.controller.setActive(false);await h.controller.refresh();assert.equal(seen.at(-1).label,"검증 상태 미조회");
    await h.controller.select(null);assert.equal(h.list().length,0);assert.equal(seen.at(-1).scope,null);
});

test("Task 2 counts only the selected Entity and current contributing set",async()=>{
    // Given
    const p=pair();
    p.items.push({...p.items[0],entity_id:"OTHER-HOST",evidence_id:"E-OTHER",resolution_status:"unresolved"});
    const seen=[];const h=harness(async()=>response(p),{onSummary:value=>seen.push(value)});
    // When
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-1"]));await h.controller.setActive(true);
    // Then
    assert.equal(h.list().length,1);assert.equal(h.status(),"원본 대조 통과 · 1/1건");
    assert.deepEqual(seen.at(-1).evidenceIds,["E-1"]);
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-1"],"DEC-TEST","OTHER-HOST"));
    assert.match(h.status(),/^조회 실패/);assert.equal(h.list().length,0);
});

test("Task 2 rejects unknown or contradictory verification payloads as query failures",async()=>{
    // Given / When / Then
    for(const mutate of [p=>p.items[0].resolution_status="constructor",p=>p.items.push({...p.items[0]}),
        p=>p.source_events=[],p=>p.items[0].unresolved_reason="raw_sha256_mismatch"]){
        const p=payload("TEST-RUN","raw_verified");mutate(p);
        const h=harness(async()=>response(p));await h.controller.select("TEST-RUN",scope());await h.controller.setActive(true);
        assert.match(h.status(),/^조회 실패/);assert.equal(h.list().length,0);
    }
});

test("Task 2 preserves an explicit failure from a secondary raw check",async()=>{
    // Given: the API may report the first unresolved reason while listing every raw check.
    const p=payload();
    p.items[0].validation_details.raw_checks=[
        {verified:false,reason:"run_archive_file_missing"},
        {verified:false,reason:"raw_sha256_mismatch"},
    ];
    const h=harness(async()=>response(p));
    // When
    await h.controller.select("TEST-RUN",scope());await h.controller.setActive(true);
    // Then
    assert.equal(h.status(),"원본 검증 실패 · 0/1건 통과");
    assert.match(flatten(mainRows(h)[0]),/원본 검증 실패/);
    assert.match(expanded(h),/raw_sha256_mismatch/);
});

test("Task 2 rejects a repeated source event identity rather than asserting raw verification",async()=>{
    // Given
    const p=payload("TEST-RUN","raw_verified");p.source_events.push({...p.source_events[0]});
    const h=harness(async()=>response(p));
    // When
    await h.controller.select("TEST-RUN",scope());await h.controller.setActive(true);
    // Then
    assert.match(h.status(),/^조회 실패/);assert.equal(h.list().length,0);
});

test("Task 2 null selection discards an outstanding stored-analysis response",async()=>{
    // Given: the Live integration clears the stored controller with select(null).
    let deliver;const seen=[];
    const h=harness(()=>new Promise(resolve=>{deliver=resolve;}),{onSummary:value=>seen.push(value)});
    await h.controller.select("TEST-RUN",scope());const old=h.controller.setActive(true);
    // When
    await h.controller.select(null);deliver(response(payload("TEST-RUN","raw_verified")));await old;
    // Then
    assert.equal(seen.at(-1).scope,null);assert.equal(seen.at(-1).queryState,"not_requested");
    assert.equal(h.list().length,0);assert.equal(h.status(),"검증 상태 미조회");
});

// Task 6: operator table. Two S0 rules with their stored structured features, as the extractor writes them.
function task6Item(id,type,features,level="raw_verified",timestamp="2026-10-03T00:00:20.000+00:00"){
    const base=payload("TEST-RUN",level).items[0];
    return {...base,evidence_id:id,evidence_type:type,features,timestamp,event_ids:[`evt-${id}`],
        unresolved_reason:level==="raw_verified"?null:"run_manifest_unavailable",evidence_origin:"retained_archive",historical_extractor_verified:true,
        derived_from_source_layer:"raw_telemetry",feature_channel_group:"fusion_feature",
        validation_details:{evidence_sha256:"c".repeat(64),current_extractor_version:"s0-v0.1",
            raw_checks:[{event_id:`evt-${id}`,verified:level==="raw_verified",reason:level==="raw_verified"?null:"run_manifest_unavailable",
                manifest_sha256:"d".repeat(64),raw_sha256:"e".repeat(64),raw_record_sha256:"f".repeat(64)}]}};
}
function task6Payload(items){
    const p=payload("TEST-RUN","raw_verified");
    p.items=items;
    p.source_events=items.map(item=>({event_id:item.event_ids[0],run_id:"TEST-RUN",host_id:"TEST-HOST",source_event_id:`SRC-${item.evidence_id}`,
        raw_ref:{record_no:7},timestamp:item.timestamp,source:"sysmon",source_layer:"raw_telemetry",process:{name:"powershell.exe"}}));
    p.raw_retention={available:true,status:"storage_verified",byte_size:42,content_sha256:"a".repeat(64),manifest_identity:"fixture"};
    return p;
}
const encoded=(level="raw_verified",id="E-ENC")=>task6Item(id,"encoded_powershell_command",{process_name:"powershell.exe",matched_option:"-enc"},level);
const external=(level="raw_verified",id="E-NET")=>task6Item(id,"script_interpreter_external_connection",
    {process_name:"powershell.exe",protocol:"tcp",dst_ip:"203.0.113.10",dst_port:443},level,"2026-10-03T00:00:21.000+00:00");
const cells=row=>row.children.map(flatten);

test("Task 6 rows lead with time, observation, target and state; detail values follow raw verification",async()=>{
    // Given
    const h=harness(async()=>response(task6Payload([external(),encoded()])));
    // When
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-NET","E-ENC"]));await h.controller.setActive(true);
    // Then: sorted by observation time, not by response order.
    assert.deepEqual(mainRows(h).map(cells),[
        ["2026.10.03 09:00:20 KST","인코딩된 PowerShell 실행 옵션 사용실행 옵션 -enc","TEST-HOSTpowershell.exe",
            "sysmon · 원시 Telemetry생성 당시 보존본","원본 대조 통과","상세"],
        ["2026.10.03 09:00:21 KST","스크립트 실행기의 공인 IP 연결TCP 203.0.113.10:443 · 연결 목적·악성 여부 미확인","TEST-HOSTpowershell.exe",
            "sysmon · 원시 Telemetry생성 당시 보존본","원본 대조 통과","상세"]]);
    assert.equal(mainRows(h)[0].dataset.state,"verified");
    const text=mainRows(h).map(flatten).join("")+expanded(h,0)+expanded(h,1);
    assert.doesNotMatch(text,/C2|유출|랜섬웨어|명령제어|공격 목적/);
    assert.equal(text.includes("E-ENC"),true,"IDs remain available in the detail row");
    assert.equal(mainRows(h).map(flatten).join("").includes("E-ENC"),false,"IDs are not the row title");
});

test("Task 6 unverified rows keep the stored rule name but withhold detail values",async()=>{
    // Given
    const h=harness(async()=>response(task6Payload([encoded("event_verified"),external("unresolved")])));
    // When
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-ENC","E-NET"]));await h.controller.setActive(true);
    // Then
    const [first,second]=mainRows(h).map(cells);
    assert.deepEqual(first.slice(1,2),["인코딩된 PowerShell 실행 옵션 사용원본 대조 전 · 세부 값 미표시"]);
    assert.equal(first[4],"원본 대조 미완료해당 분석의 보존 Manifest 없음");
    assert.equal(second[4],"연결 미해결해당 분석의 보존 Manifest 없음");
    assert.doesNotMatch(first.join("")+second.join(""),/-enc|203\.0\.113\.10/);
    assert.equal(mainRows(h)[0].dataset.state,"unverified");
});

test("Task 6 a missing Evidence row names what is unknown instead of guessing",()=>{
    // Given
    const item={evidence_id:"E-GONE",run_id:"TEST-RUN",entity_id:"TEST-HOST",resolution_status:"unresolved",evidence_origin:"missing",
        event_ids:[],observed_behavior:[],features:{},validation_details:{},unresolved_reason:"current_extractor_did_not_reproduce_id",timestamp:null};
    // When
    const row=provenanceRowPresentation(item,[]);
    // Then
    assert.deepEqual([row.time,row.behavior,row.process,row.source,row.origin,row.stateLabel,row.reason],
        ["시각 미확인","유형 미확인 · 증거 재현 불가","프로세스 미확인","저장 Event 미확인","증거 재현 불가","연결 미해결","현재 Extractor로 해당 ID 재현 불가"]);
});

test("Task 6 detail exposes full identifiers and hashes with explicit copy actions",async()=>{
    // Given
    const longId=`E-${"9".repeat(300)}`;
    const h=harness(async()=>response(task6Payload([encoded("raw_verified",longId)])));
    await h.controller.select("TEST-RUN",scope("TEST-RUN",[longId]));await h.controller.setActive(true);
    // When
    const detail=expanded(h);
    // Then
    for (const value of [longId,"c".repeat(64),"d".repeat(64),"e".repeat(64),"f".repeat(64),"SRC-"+longId,"encoded_powershell_command","s0-v0.1"])
        assert.ok(detail.includes(value),value.slice(0,20));
    const detailRow=h.list()[1];
    const code=descendants(detailRow).find(node=>node.tag==="code");
    assert.equal(code.textContent,longId);assert.equal(code.title,longId);
    const copy=descendants(detailRow).find(node=>node.classList?.contains("dashboard-copy-button"));
    assert.equal(copy.getAttribute("aria-label"),"증거 ID 전체 값 복사");
    const written=[];
    globalThis.navigator={clipboard:{writeText:async value=>{written.push(value);}}};
    try {copy.click();await new Promise(resolve=>setImmediate(resolve));} finally {delete globalThis.navigator;}
    assert.deepEqual(written,[longId]);assert.equal(copy.textContent,"복사됨");
    const fallback=descendants(h.list()[1]).filter(node=>node.classList?.contains("dashboard-copy-button"))[1];
    fallback.click();await new Promise(resolve=>setImmediate(resolve));
    assert.equal(fallback.textContent,"복사 불가 · 값을 직접 선택");
});

test("Task 6 overview keeps contributing count, raw comparison and retention as separate facts",async()=>{
    // Given
    const node=(h,id)=>h.doc.getElementById(id).textContent;
    const cases=[["storage_verified",{available:true,status:"storage_verified"},"보관 원본 검증됨"],
        ["unavailable",{available:false,status:"unavailable",failure:null},"영속 보존 기록 없음"],
        ["degraded",{available:true,status:"degraded",failure:"stored_archive_sha256_mismatch"},"보관 원본 검증 제한 · 저장된 보존본 해시 불일치"]];
    for (const [,retention,expected] of cases) {
        const p=task6Payload([encoded()]);p.raw_retention=retention;
        const h=harness(async()=>response(p));
        // When
        await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-ENC"]));
        const before=[node(h,"provenance-count"),node(h,"provenance-retention-state")];
        await h.controller.setActive(true);
        // Then
        assert.deepEqual(before,["1건","미조회"]);
        assert.equal(node(h,"provenance-retention-state"),expected);
        assert.equal(h.status(),"원본 대조 통과 · 1/1건","Retention never changes the comparison result");
    }
    const unknown=harness(async()=>response(task6Payload([])));
    await unknown.controller.select("TEST-RUN",null);
    assert.equal(node(unknown,"provenance-count"),"기여 증거 미확인");
    await unknown.controller.select(null);
    assert.equal(node(unknown,"provenance-count"),"선택 항목 없음");
});

test("Task 6 zero, one and many contributing Evidence render as that many rows",async()=>{
    // Given / When / Then
    const none=harness(async()=>response(task6Payload([])));
    await none.controller.select("TEST-RUN",scope("TEST-RUN",[]));await none.controller.setActive(true);
    assert.equal(none.calls.length,0);assert.equal(none.list().length,0);assert.equal(none.status(),"검증 대상 없음");
    assert.equal(none.doc.getElementById("provenance-count").textContent,"0건");
    const one=harness(async()=>response(task6Payload([encoded()])));
    await one.controller.select("TEST-RUN",scope("TEST-RUN",["E-ENC"]));await one.controller.setActive(true);
    assert.equal(mainRows(one).length,1);assert.equal(one.doc.getElementById("provenance-region").hidden,false);
    const many=harness(async()=>response(task6Payload([external("raw_verified","E-3"),encoded("event_verified","E-1"),external("raw_verified","E-2")])));
    await many.controller.select("TEST-RUN",scope("TEST-RUN",["E-1","E-2","E-3"]));await many.controller.setActive(true);
    assert.equal(mainRows(many).length,3);assert.equal(many.status(),"일부 검증 · 2/3건 통과");
});

test("Task 6 expansion and toggle focus survive a same-scope re-read and reset when the evidence set changes",async()=>{
    // Given
    const h=harness(async()=>response(task6Payload([encoded(),external()])));
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-ENC","E-NET"]));await h.controller.setActive(true);
    expanded(h,1);
    const toggle=descendants(mainRows(h)[1]).find(node=>node.classList?.contains("dashboard-evidence-expand"));
    toggle.focus();
    // When
    await h.controller.refresh();
    // Then
    assert.equal(h.list().length,3);
    const restored=h.doc.activeElement;
    assert.notStrictEqual(restored,toggle);assert.equal(restored.dataset.rowKey,"TEST-HOST\u0000E-NET");
    assert.equal(restored.getAttribute("aria-expanded"),"true");
    await h.controller.select("TEST-RUN",scope("TEST-RUN",["E-ENC"]));await h.controller.setActive(true);
    assert.equal(h.list().length,1);
});
