import { labPresentation } from "./lab-contract.mjs";

const byId = id => document.getElementById(id);
const setText = (node, value) => { if (node.textContent !== value) node.textContent = value; };
let token = null, pending = false, timer = null, generation = 0, enabled = true, request = null;
const controls = ["start", "pause", "resume", "reset"];
function lock() {
    for (const key of controls) byId(`lab-${key}`).disabled = true;
    byId("lab-speed").disabled = true;
}
function failure() {
    lock();
    setText(byId("lab-state"), "실험 제어 조회 실패 · 이전 상태를 현재 저장값으로 표시하지 않습니다.");
    for (const key of ["accepted", "completed", "failed", "executions", "elapsed"]) setText(byId(`lab-${key}`), "—");
}
async function readStatus() {
    if (!enabled || pending) return;
    pending = true;
    const version = ++generation;
    const controller = new AbortController();
    request = controller;
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
        if (token === null) {
            const config = await fetch("/lab/config", { cache: "no-store", signal: request.signal });
            if (!config.ok) throw Error("Config failed");
            token = (await config.json()).control_token;
            if (typeof token !== "string" || token.length !== 64) throw Error("Config rejected");
        }
        const response = await fetch("/lab/status", { cache: "no-store", signal: request.signal });
        if (!response.ok) throw Error("Status failed");
        const model = labPresentation(await response.json());
        if (!enabled || version !== generation) return;
        setText(byId("lab-state"), model.label);
        for (const key of controls) byId(`lab-${key}`).disabled = !model[key];
        byId("lab-speed").disabled = false;
        byId("lab-speed").value = model.speed;
        for (const key of ["accepted", "completed", "failed", "executions"]) setText(byId(`lab-${key}`), String(model.stored[key]));
        setText(byId("lab-elapsed"), model.elapsed);
        setText(byId("lab-database"), `격리 DB: ${model.database} · Dashboard 연결 읽기 전용`);
    } catch {
        if (enabled && version === generation) failure();
    } finally {
        clearTimeout(timeout);
        if (version === generation) { request = null; pending = false; schedule(); }
    }
}
function schedule() {
    if (timer !== null || !enabled) return;
    timer = setTimeout(() => { timer = null; if (!document.hidden) void readStatus(); else schedule(); }, 2000);
}
async function control(action, speed) {
    if (token === null) return;
    generation += 1;
    request?.abort();
    request = null;
    pending = true;
    if (timer !== null) { clearTimeout(timer); timer = null; }
    lock();
    const version = generation;
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), 10000);
    try {
        const response = await fetch("/lab/control", {
            method: "POST", headers: { "Content-Type": "application/json", "X-Lab-Token": token },
            body: JSON.stringify({ action, ...(speed ? { speed } : {}) }), signal: abort.signal,
        });
        if (!response.ok) throw Error("Control rejected");
    } catch {
        if (enabled && generation === version) failure();
    } finally {
        clearTimeout(timeout);
        if (generation === version) { pending = false; void readStatus(); }
    }
}
for (const action of controls) byId(`lab-${action}`).addEventListener("click", () => { void control(action); });
byId("lab-speed").addEventListener("change", () => { void control("speed", byId("lab-speed").value); });
window.addEventListener("pagehide", () => { enabled = false; generation += 1; request?.abort(); if (timer !== null) clearTimeout(timer); timer = null; pending = false; });
window.addEventListener("pageshow", event => { if (event.persisted) { enabled = true; void readStatus(); } });
void readStatus();
