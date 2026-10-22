import assert from "node:assert/strict";
import test from "node:test";
import { createSysmonIngestController } from "../../../src/incident_awareness/dashboard/ui/assets/dashboard-ingest-controller.mjs";

const ID = "ING-52a99b8f-f520-4f6f-bdcc-d7e4f296a90a";
const tick = () => new Promise(resolve => setImmediate(resolve));
const response = (data, status = 200) => ({ ok: status < 300, status, json: async () => data });

function setup({ restored = null, configStatus = 200, uploadStatus = 202, declarationRequired = false } = {}) {
    const ids = ["sysmon-ingest", "sysmon-ingest-form", "sysmon-ingest-file",
        "sysmon-ingest-file-label", "sysmon-ingest-submit", "sysmon-ingest-status",
        "sysmon-ingest-identity", "sysmon-ingest-run", "sysmon-ingest-open",
        "sysmon-ingest-run-type", "sysmon-ingest-label-control"];
    const nodes = new Map(ids.map(id => [id, { hidden: true, textContent: "", disabled: false,
        listeners: new Map(), addEventListener(name, callback) { this.listeners.set(name, callback); } }]));
    const document = { getElementById: id => nodes.get(id) ?? null };
    const get = id => nodes.get(`sysmon-ingest${id ? `-${id}` : ""}`);
    const values = new Map(restored ? [["iae.local-demo.ingest", restored]] : []);
    const storage = { getItem: k => values.get(k) ?? null, setItem: (k, v) => values.set(k, v), removeItem: k => values.delete(k) };
    const timers = new Map(); let nextTimer = 0;
    const requests = [], completed = [], opened = [];
    const state = { status: 200, result: { ingest_id: ID, upload_status: "uploaded", processing_status: "unconfirmed", run_id: null } };
    const controller = createSysmonIngestController(document, { storage,
        setTimer: (callback, ms) => { assert.equal(ms, 5000); timers.set(++nextTimer, callback); return nextTimer; },
        clearTimer: id => timers.delete(id),
        onCompleted: async id => completed.push(id), onOpenRun: async id => opened.push(id),
        fetchImpl: async (url, options) => {
            requests.push([url, options]);
            if (url.endsWith("/config")) return response({ enabled: true, max_file_bytes: 10485760, experiment_declaration_required: declarationRequired }, configStatus);
            if (options.method === "POST") return uploadStatus === 202 ? response(state.result, 202)
                : response({ detail: { ingest_id: ID } }, uploadStatus);
            return response(state.result, state.status);
        },
    });
    const choose = (size = 10, name = "sample.jsonl") => {
        const file = new Blob(["a".repeat(size)]); file.name = name;
        get("file").files = [file]; get("file").listeners.get("change")();
    };
    const submit = async () => { await get("form").listeners.get("submit")({ preventDefault() {} }); await tick(); };
    const poll = async () => {
        const [id, callback] = timers.entries().next().value;
        timers.delete(id); callback(); await tick();
    };
    return { controller, get, state, requests, completed, opened, choose, submit, poll, timers, values };
}

test("Upload acceptance stays unconfirmed until a persisted Run is returned; opens only on user action", async () => {
    const h = setup(); await h.controller.start(); h.choose();
    assert.match(h.get("file-label").textContent, /sample.jsonl.*10/);
    await h.submit();
    assert.match(h.get("status").textContent, /미확인/);
    assert.equal(h.get("run").hidden, true); assert.deepEqual(h.completed, []);
    assert.equal(h.timers.size, 1);
    h.state.result = { ...h.state.result, processing_status: "completed", run_id: "REAL-RUN" };
    await h.poll();
    assert.deepEqual(h.completed, ["REAL-RUN"]); assert.equal(h.timers.size, 0);
    assert.equal(h.get("run").href, "/dashboard/runs/REAL-RUN");
    assert.deepEqual(h.opened, []); h.get("open").listeners.get("click")();
    assert.deepEqual(h.opened, ["REAL-RUN"]); h.controller.stop();
});

test("New API requires an explicit label and binds it to the actual file hash", async () => {
    const h = setup({declarationRequired:true}); await h.controller.start(); h.choose();
    assert.equal(h.get("submit").disabled,true);
    h.get("run-type").value="normal"; h.get("run-type").listeners.get("change")();
    assert.equal(h.get("submit").disabled,false);
    await h.submit();
    const form=h.requests.find(([url,options])=>options.method==='POST')[1].body;
    const declaration=JSON.parse(form.get('declaration'));
    assert.equal(declaration.run_type,'normal');
    assert.equal(declaration.content_sha256,'bf2cb58a68f684d95a3b78ef8f661c9a4e5b09e82cc8f9cc88cce90528caeb27');
    h.controller.stop();
});

test("Restored submission survives a new Controller; query failure never invents Pipeline failure", async () => {
    const h = setup({ restored: ID }); h.state.status = 503;
    await h.controller.start(); await tick();
    assert.match(h.get("status").textContent, /조회 실패/);
    assert.deepEqual(h.completed, []); assert.equal(h.timers.size, 1);
    h.state.status = 200; await h.poll();
    assert.match(h.get("status").textContent, /완료 여부 미확인/);
    h.controller.stop(); assert.equal(h.timers.size, 0);
    await h.controller.start(); await tick(); assert.equal(h.timers.size, 1); h.controller.stop();
});

test("Disabled feature stays hidden and performs no upload or status query", async () => {
    const h = setup({ configStatus: 404 }); await h.controller.start();
    assert.equal(h.get("").hidden, true); assert.equal(h.requests.length, 1); h.controller.stop();
});

test("Empty and oversized selections cannot submit; server connection failure retains unknown status", async () => {
    const h = setup({ uploadStatus: 503 }); await h.controller.start();
    h.choose(0); assert.equal(h.get("submit").disabled, true);
    h.choose(10485761); assert.equal(h.get("submit").disabled, true);
    h.choose(); await h.submit();
    assert.equal(h.get("run").hidden, true); assert.deepEqual(h.completed, []);
    assert.ok(h.requests.some(([url]) => url.endsWith(ID))); h.controller.stop();
});

test("A response for another ingest never exposes a Run link", async () => {
    const h = setup({ restored: ID }); h.state.result = { ingest_id: "other", processing_status: "completed", run_id: "WRONG" };
    await h.controller.start(); await tick();
    assert.equal(h.get("run").hidden, true); assert.deepEqual(h.completed, []); h.controller.stop();
});
