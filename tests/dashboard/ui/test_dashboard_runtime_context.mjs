import assert from "node:assert/strict";
import test from "node:test";
import { timingPayload } from "./stage-timing-fixture.mjs";
import { buildRuntimeContext, createRuntimeContextController, createPipelineStageReader,
    resolvePipelineTarget, scopeKey } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-runtime-context.mjs";

const runtime = (run="R", entity="H", status="completed") => ({ execution_id:run+entity, run_id:run,
    entity_id:entity, status, current_stage:status==="running"?"normalization":null,
    updated_at:"2026-10-18T01:00:00.000Z", is_stale:false,
    input_total:10,normalization_processed_count:5,remaining_count:5 });
const scopes = [{run_id:"R",entity_id:"H"}];
const payload = () => ({schema_version:"dashboard_runtime_context_v1", generated_at:"2026-10-18T01:00:01Z",
    pipeline:runtime("NEW","HOST","running"), scopes:[{...scopes[0],runtime:runtime()}]});
const response = p => ({ok:true,json:async()=>p});
const tick = () => new Promise(r=>setImmediate(r));

test("Default automatic Pipeline and selected incident scope remain independent", () => {
    // Given / When
    const context=buildRuntimeContext(payload(),scopes);
    // Then
    assert.equal(resolvePipelineTarget(context,true,scopes[0]).run_id,"NEW");
    assert.equal(resolvePipelineTarget(context,false,scopes[0]).run_id,"R");
    assert.equal(context.scopes.get(scopeKey("R","H")).entity_id,"H");
    assert.equal(resolvePipelineTarget({...context,queryState:"error"},true,null),null);
});

for(const [name,change] of [
    ["other entity",p=>{p.scopes[0].runtime.entity_id="OTHER";}],
    ["duplicate",p=>p.scopes.push(p.scopes[0])],
    ["missing",p=>{p.scopes=[];}],
    ["bad execution",p=>{p.pipeline.execution_id="";}],
    ["bad time",p=>{p.pipeline.updated_at="invalid";}],
    ["bad progress",p=>{p.scopes[0].runtime.normalization_processed_count=-1;}],
])test(`Reject ${name} rather than mixing or displaying old scope`,()=>{
    // Given / When / Then
    const p=payload();change(p);assert.throws(()=>buildRuntimeContext(p,scopes),TypeError);
});

test("Exact absent Runtime is null, not a completed or zero record",()=>{
    // Given / When
    const p=payload();p.pipeline=null;p.scopes[0].runtime=null;
    const model=buildRuntimeContext(p,scopes);
    // Then
    assert.equal(model.pipeline,null);assert.equal(model.scopes.get(scopeKey("R","H")),null);
});

test("Held scope response cannot overwrite a new scope; same inflight query is deduplicated",async()=>{
    // Given
    const held=[],states=[];const c=createRuntimeContextController({onChange:s=>states.push(s),origin:null,
        fetchImpl:(_url,options)=>new Promise(resolve=>held.push({resolve,options}))});
    // When
    const old=c.refresh(scopes);await tick();assert.equal(c.refresh(scopes),old);
    const current=c.refresh([{run_id:"B",entity_id:"E"}]);await tick();
    const p=payload();p.scopes=[{run_id:"B",entity_id:"E",runtime:runtime("B","E")}];
    held[1].resolve(response(p));await current;held[0].resolve(response(payload()));await old;
    // Then
    assert.equal(states.at(-1).scopes.get(scopeKey("B","E")).run_id,"B");
    assert.equal(held.length,2);assert.equal(held[0].options.signal.aborted,true);c.stop();
});

test("API failure clears all measurements; later poll recovers without a new timer loop",async()=>{
    // Given
    const states=[],timers=[];let error=false;const c=createRuntimeContextController({origin:null,onChange:s=>states.push(s),
        setTimeoutImpl:(_fn,ms)=>{timers.push(ms);return 1;},clearTimeoutImpl:()=>{},
        fetchImpl:async()=>error?{ok:false,status:503}:response(payload())});
    // When / Then
    await c.refresh(scopes);error=true;await c.refresh(scopes);
    assert.equal(states.at(-1).queryState,"error");assert.equal(states.at(-1).pipeline,null);
    assert.equal(states.at(-1).scopes.size,0);error=false;await c.refresh(scopes);
    assert.equal(states.at(-1).queryState,"success");assert.ok(timers.every(ms=>ms===10000));c.stop();
});

test("Local companion discovery is accepted only for the exact loopback Dashboard origin",async()=>{
    // Given / When / Then
    for(const dashboard of ["http://127.0.0.1:8792","http://127.0.0.1:8768"]){
        const paths=[];const c=createRuntimeContextController({origin:dashboard,onChange:()=>{},fetchImpl:async url=>{
            paths.push(url);return response(url.endsWith('.json')?{schema_version:"local_runtime_companion_v1",dashboard_origin:"http://127.0.0.1:8792",origin:"http://127.0.0.1:8793"}:payload());
        }});await c.refresh(scopes);
        assert.equal(paths.at(-1).startsWith("http://127.0.0.1:8793"),dashboard.endsWith(':8792'));c.stop();
    }
});

test("Stage reader failure does not trigger recursive retries or invent prior completed stages",async()=>{
    // Given
    let calls=0;const states=[];const c=createPipelineStageReader({onChange:(v,s)=>{states.push([v,s]);if(s==='error')c.select(runtime());},
        fetchImpl:async()=>{calls++;return {ok:false};}});
    // When
    c.select(runtime());await tick();await tick();
    // Then
    assert.equal(calls,1);assert.equal(states.at(-1)[0],null);assert.equal(states.at(-1)[1],"error");c.stop();
});

test("An old Stage Timing response cannot overwrite a new automatic Execution",async()=>{
    // Given
    const held=[],states=[];const c=createPipelineStageReader({onChange:(v,s)=>states.push([v,s]),
        fetchImpl:()=>new Promise(resolve=>held.push(resolve))});
    const first=runtime("OLD","HOST"),second=runtime("NEW","HOST");
    const fixture=r=>timingPayload({scope:{runId:r.run_id,entityId:r.entity_id,executionId:r.execution_id}});
    // When
    c.select(first);c.select(second);held[1](response(fixture(second)));await tick();
    held[0](response(fixture(first)));await tick();
    // Then
    assert.equal(states.at(-1)[0].executionId,second.execution_id);c.stop();
});
