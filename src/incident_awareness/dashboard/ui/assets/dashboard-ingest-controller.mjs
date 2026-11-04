const STORAGE_KEY = "iae.local-demo.ingest";

export function createSysmonIngestController(document, {
    fetchImpl = globalThis.fetch.bind(globalThis),
    storage = globalThis.sessionStorage,
    setTimer = globalThis.setTimeout,
    clearTimer = globalThis.clearTimeout,
    onCompleted = async () => {},
    onOpenRun = async () => {},
} = {}) {
    const section = document.getElementById("sysmon-ingest");
    if (section === null) return { async start() {}, stop() {} };
    const form = document.getElementById("sysmon-ingest-form");
    const fileInput = document.getElementById("sysmon-ingest-file");
    const runType = document.getElementById("sysmon-ingest-run-type");
    const labelControl = document.getElementById("sysmon-ingest-label-control");
    const fileLabel = document.getElementById("sysmon-ingest-file-label");
    const submit = document.getElementById("sysmon-ingest-submit");
    const status = document.getElementById("sysmon-ingest-status");
    const identity = document.getElementById("sysmon-ingest-identity");
    const link = document.getElementById("sysmon-ingest-run");
    const open = document.getElementById("sysmon-ingest-open");
    let ingestId = null;
    let timer = null;
    let active = false;
    let generation = 0;
    let completedRunId = null;
    let maxBytes = 0;
    let declarationRequired = false;
    let uploading = false;
    function canSubmit() {
        const file = fileInput.files?.[0];
        return !uploading && file && file.size > 0 && file.size <= maxBytes
            && (!declarationRequired || ["normal", "attack"].includes(runType?.value));
    }
    runType?.addEventListener("change", () => { submit.disabled = !canSubmit(); });

    function remember(value) {
        try { value === null ? storage.removeItem(STORAGE_KEY) : storage.setItem(STORAGE_KEY, value); }
        catch { /* Tracking still works when browser storage is unavailable. */ }
    }
    function schedule() {
        if (active && ingestId !== null && completedRunId === null) {
            timer = setTimer(() => { timer = null; void poll(); }, 5000);
        }
    }
    async function request(url, options = {}) {
        return fetchImpl(url, { ...options, signal: AbortSignal.timeout(10000) });
    }
    async function poll() {
        const version = generation;
        try {
            const response = await request(`/ingest/sysmon/${encodeURIComponent(ingestId)}`);
            if (!response.ok) throw new Error("status unavailable");
            const data = await response.json();
            if (!active || version !== generation) return;
            if (data.ingest_id !== ingestId) throw new Error("identity mismatch");
            if (data.processing_status === "completed" && typeof data.run_id === "string" && data.run_id) {
                completedRunId = data.run_id;
                status.textContent = "분석 완료 · 저장된 처리 결과를 확인했습니다.";
                identity.textContent = `${ingestId} · ${data.run_id}`;
                link.href = `/dashboard/runs/${encodeURIComponent(data.run_id)}`;
                link.hidden = false;
                if (open) open.hidden = false;
                await onCompleted(data.run_id);
            } else {
                status.textContent = data.upload_status === "uploaded"
                    ? "업로드 접수 완료 · 분석 완료 여부 미확인 (5초마다 조회)"
                    : "업로드 접수 여부 미확인 · 상태를 다시 조회합니다.";
            }
        } catch {
            if (active && version === generation) {
                status.textContent = "상태 조회 실패 · 분석 완료 여부를 확인할 수 없습니다. 다시 조회합니다.";
            }
        } finally {
            if (active && version === generation) schedule();
        }
    }
    fileInput.addEventListener("change", () => {
        const file = fileInput.files?.[0];
        fileLabel.textContent = file ? `${file.name} · ${file.size.toLocaleString()} bytes` : "선택한 파일 없음";
        submit.disabled = !canSubmit();
    });
    open?.addEventListener("click", () => {
        if (completedRunId !== null) void onOpenRun(completedRunId);
    });
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const file = fileInput.files?.[0];
        if (!canSubmit() || submit.disabled) return;
        uploading = true;
        const declaredType = runType?.value;
        generation += 1;
        const version = generation;
        if (timer !== null) clearTimer(timer);
        ingestId = null;
        completedRunId = null;
        remember(null);
        link.hidden = true;
        if (open) open.hidden = true;
        identity.textContent = "";
        submit.disabled = true;
        fileInput.disabled = true;
        status.textContent = "파일 검증 및 업로드 중";
        try {
            const body = new FormData();
            body.append("file", file);
            if (declarationRequired) {
                const hash = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
                const content_sha256 = Array.from(new Uint8Array(hash), n => n.toString(16).padStart(2, "0")).join("");
                body.append("declaration", JSON.stringify({run_type: declaredType, content_sha256}));
            }
            const response = await request("/ingest/sysmon", { method: "POST", body });
            const data = await response.json();
            if (!active || version !== generation) return;
            const returnedId = response.ok ? data.ingest_id : data.detail?.ingest_id;
            if (typeof returnedId === "string" && /^ING-[0-9a-f-]{36}$/.test(returnedId)) {
                ingestId = returnedId;
                identity.textContent = ingestId;
                remember(ingestId);
                status.textContent = response.ok
                    ? "업로드 접수 완료 · 분석 완료 여부 미확인"
                    : "업로드 접수 여부 미확인 · 상태를 조회합니다.";
                void poll();
            } else {
                status.textContent = response.status === 422 || response.status === 400
                    ? "입력 오류 · UTF-8 JSONL, Event ID 1·3, 단일 Computer와 필수 필드를 확인하세요."
                    : response.status === 413 ? "크기 제한 초과 · 10 MiB 이하 파일을 선택하세요."
                        : "업로드 실패 · LocalStack 연결과 로컬 설정을 확인하세요.";
            }
        } catch {
            if (active && version === generation) status.textContent = "업로드 접수 여부 미확인 · 연결이 끊어졌습니다.";
        } finally {
            uploading = false;
            fileInput.disabled = false;
            submit.disabled = !canSubmit();
        }
    });
    return {
        async start() {
            if (active) return;
            active = true;
            const version = ++generation;
            try {
                const response = await request("/ingest/sysmon/config");
                if (!active || version !== generation) return;
                if (!response.ok) { section.hidden = true; return; }
                const config = await response.json();
                if (!active || version !== generation) return;
                maxBytes = config.max_file_bytes;
                declarationRequired = config.experiment_declaration_required === true;
                if (labelControl) labelControl.hidden = !declarationRequired;
                submit.disabled = !canSubmit();
                section.hidden = false;
                try { ingestId = storage.getItem(STORAGE_KEY); } catch { /* Optional. */ }
                if (ingestId && completedRunId === null) {
                    identity.textContent = ingestId;
                    void poll();
                }
            } catch { section.hidden = true; }
        },
        stop() {
            active = false;
            generation += 1;
            if (timer !== null) clearTimer(timer);
            timer = null;
        },
    };
}
