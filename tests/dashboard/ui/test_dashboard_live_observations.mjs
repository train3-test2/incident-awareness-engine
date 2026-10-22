import assert from "node:assert/strict";
import test from "node:test";
import { createLiveObservationController, liveDisplayState, liveIdentity, validateLiveEnvelope } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-live-observations.mjs";

const normal="RUN-20301231-009", attack="RUN-20301231-010";
const item=(changes={})=>({source_kind:"live_observation",data_class:"demo_only",canonical_result:null,
    run_id:attack,host_id:"R1-TGTA",detector_state:"demo_rule_match",state:"demo_rule_match",read_status:"ok",
    generated_at:"2030-12-31T00:01:00.000Z",last_accepted_at:"2030-12-31T00:00:59.000Z",
    accepted_chunk_count:4,accepted_event_count:4,policy_id:"r1-wmi-management-approved-lineage",policy_version:"v0.1",
    observed_lineage:["WmiPrvSE.exe","cmd.exe","powershell.exe"],lineage_event_ids:["e1","e2","e3"],
    network_event_id:"e4",source_event_ids:["1","2","3","4"],terminal_process_guid:"{33333333-3333-3333-3333-333333333333}",
    diagnostics:[],snapshot_age_ms:0,acceptance:"post_commit_ack_verified",acceptance_scope:"detector_reported",
    ledger_independently_verified:false,human_workflow:false,ai_report:false,formal_analysis:false,...changes});
const envelope=(items=[item()])=>({schema_version:"track_b_observations_v1",enabled:true,server_time:"2030-12-31T00:01:00.000Z",items});

class Element{
    constructor(tag){this.tag=tag;this.children=[];this.dataset={};this.attributes=new Map();this.classes=new Set();this.listeners=new Map();this.textContent="";this.classList={add:value=>this.classes.add(value)};}
    append(...values){this.children.push(...values);}
    setAttribute(key,value){this.attributes.set(key,value);}
    addEventListener(key,fn){this.listeners.set(key,fn);}
}
const document=()=>({getElementById:()=>null,createElement:tag=>new Element(tag)});
function harness(fetchImpl){
    let now=0,sequence=0;const timers=new Map(),calls=[];
    const controller=createLiveObservationController(document(),{fetchImpl:async(path,options)=>{calls.push({path,options});return fetchImpl(path,options);},nowImpl:()=>now,
        setTimeoutImpl:(fn,delay)=>{timers.set(++sequence,{fn,delay});return sequence;},clearTimeoutImpl:id=>timers.delete(id)});
    return {controller,calls,timers,setNow:value=>{now=value;}};
}

for(const [age,expected] of [[0,"demo_rule_match"],[5000,"demo_rule_match"],[5000.1,"delayed"],[15000,"delayed"],[15000.1,"unknown"]]){
    test(`Track-B heartbeat age ${age} expires to ${expected} without treating ACK time as event time`,()=>{
        const source=item();assert.equal(liveDisplayState(source,age),expected);assert.equal(source.state,"demo_rule_match");
    });
}

test("Normal, observing, waiting and input errors remain separate",()=>{
    assert.equal(liveDisplayState(item({detector_state:"condition_not_met"})),"condition_not_met");
    assert.equal(liveDisplayState(item({detector_state:"observing",accepted_chunk_count:0,acceptance:"pending"})),"waiting");
    assert.equal(liveDisplayState(item({detector_state:"observing"})),"observing");
    assert.equal(liveDisplayState(item({detector_state:"input_error",diagnostics:["duplicate_process_guid"]})),"unknown");
    assert.equal(liveDisplayState(item({read_status:"clock_skew"})),"unknown");
});

test("Only demo-only noncanonical readonly identities pass validation",()=>{
    assert.equal(validateLiveEnvelope(envelope()).items[0].acceptance,"post_commit_ack_verified");
    for(const changes of [{canonical_result:{}},{data_class:"canonical"},{source_kind:"formal_run"},{human_workflow:true},
        {ledger_independently_verified:true},{acceptance_scope:"dashboard_verified"},{detector_state:"detected"},
        {accepted_chunk_count:0},{network_event_id:null},{lineage_event_ids:[]},{generated_at:"2030-12-31T00:01:00"}]){
        assert.throws(()=>validateLiveEnvelope(envelope([item(changes)])));
    }
    assert.throws(()=>validateLiveEnvelope(envelope([item(),item()])));
    assert.notEqual(liveIdentity(item()),JSON.stringify(["formal_run",attack,"R1-TGTA"]));
});

test("Selecting Live only performs observation GETs; two Runs and repeated heartbeats never synchronize alerts",async()=>{
    let payload=envelope([item({run_id:normal,detector_state:"condition_not_met",state:"condition_not_met"}),item()]);
    const h=harness(async()=>({ok:true,json:async()=>payload}));
    await h.controller.start();h.controller.choose(h.controller.items[0]);const first=h.controller.selectedIdentity;
    payload=structuredClone(payload);payload.items[0].generated_at="2030-12-31T00:01:01.000Z";
    await h.controller.poll();
    assert.equal(h.controller.selectedIdentity,first);
    assert.equal(h.controller.items.length,2);
    h.controller.choose(h.controller.items[1]);assert.notEqual(h.controller.selectedIdentity,first);
    assert.equal(h.controller.rows().length,2);
    assert.ok(h.calls.every(call=>call.path==="/operations/observations"&&!call.options.method&&!call.options.body));
    h.controller.clearSelection();assert.equal(h.controller.isSelected,false);h.controller.stop();
    assert.equal(h.timers.size,0);
});

test("A stopped detector loses Match emphasis even while the next request hangs",async()=>{
    let pending=false;const h=harness(async()=>pending?new Promise(()=>{}):({ok:true,json:async()=>envelope()}));
    await h.controller.start();assert.equal(h.controller.rows()[0].dataset.currentMatch,"true");
    pending=true;void h.controller.poll();h.setNow(5001);
    assert.equal(h.controller.rows()[0].dataset.currentMatch,"false");
    h.setNow(15001);assert.equal(liveDisplayState(h.controller.items[0],15001),"unknown");
    h.controller.stop();
});

test("Network failures clear prior Match immediately and a later full snapshot recovers",async()=>{
    let fail=false;const h=harness(async()=>{if(fail)throw Error("network");return {ok:true,json:async()=>envelope()};});
    await h.controller.start();h.controller.choose(h.controller.items[0]);fail=true;await h.controller.poll();
    assert.equal(h.controller.rows()[0].dataset.currentMatch,"false");
    assert.equal(h.controller.items[0].read_status,"connection_failed");
    fail=false;await h.controller.poll();assert.equal(h.controller.rows()[0].dataset.currentMatch,"true");
    h.controller.stop();
});

test("Late responses from an old lifecycle cannot replace another Run or revive a Match",async()=>{
    let resolve;let old=false;
    const h=harness(async()=>old?new Promise(done=>{resolve=done;}):({ok:true,json:async()=>envelope([item({run_id:normal})])}));
    await h.controller.start();h.controller.choose(h.controller.items[0]);old=true;const late=h.controller.poll();
    h.controller.stop();old=false;await h.controller.start();
    resolve({ok:true,json:async()=>envelope([item()])});await late;
    assert.equal(h.controller.items[0].run_id,normal);assert.equal(h.controller.selectedIdentity,liveIdentity(item({run_id:normal})));
    h.controller.stop();
});

test("Disabled Snapshot integration stops after one read and creates no rows",async()=>{
    const h=harness(async()=>({ok:true,json:async()=>({...envelope([]),enabled:false})}));
    await h.controller.start();assert.equal(h.calls.length,1);assert.equal(h.controller.rows().length,0);assert.equal(h.timers.size,0);
    h.controller.stop();
});

test("A selected unknown host resolves only inside its own Run after recovery",async()=>{
    let payload=envelope([item({host_id:null,read_status:"remote_error",state:"unknown",snapshot_age_ms:null})]);
    const h=harness(async()=>({ok:true,json:async()=>payload}));
    await h.controller.start();h.controller.choose(h.controller.items[0]);
    payload=envelope([item({run_id:normal})]);await h.controller.poll();
    assert.equal(h.controller.selectedIdentity,liveIdentity(item({host_id:null})));
    payload=envelope([item()]);await h.controller.poll();
    assert.equal(h.controller.selectedIdentity,liveIdentity(item()));
    payload=envelope([item({host_id:"OTHER-HOST"})]);await h.controller.poll();
    assert.equal(h.controller.selectedIdentity,liveIdentity(item()),"A known entity is never silently replaced");
    h.controller.stop();
});
