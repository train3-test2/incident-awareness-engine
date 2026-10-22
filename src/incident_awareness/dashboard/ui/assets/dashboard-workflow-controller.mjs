import { draftPresentation, awarenessRecordStatus, workflowSteps, workflowTimeLabel, workflowTimeDetail,
    classificationReason, snapshotEligibility, reportSummaryRows, generationOutcome } from "./dashboard-operator-contract.mjs";

export function actionPayload(action, version, fields = {}, key = crypto.randomUUID()) {
    return { action, expected_version: version, idempotency_key: key, ...fields };
}

export function createHumanWorkflowController(document, {
    fetchImpl = globalThis.fetch.bind(globalThis), developerTools = false, onOpen = () => {}, onDraft = () => {}, onProgress = () => {},
} = {}) {
    const node = (name) => document.getElementById(`workflow-${name}`);
    let runId = null;
    let detail = null;
    let generation = 0;
    let detailGeneration = 0;
    let busy = false;
    let pending = null;
    let pendingDraft = null;
    let currentDraft = null;
    let reportingStatus = null;
    let timelineSource = null;
    // What is known about timelineSource's drafts: null (not read), {empty}, {unavailable} or a draft entry.
    let timelineEntry = null;
    const draftReads = new Set();
    const readingFor = alertId => [...draftReads].filter(read => read.generation === generation && read.alertId === alertId).length;
    let alertsState = "idle";
    let pendingSynthetic = null;
    let alertItems = [];
    let snapshot = null;
    let pendingApproved = null;
    let eligibility = null;
    let shownDraft = null;
    let previewInteraction = 0;
    let previewOpen = false;
    const buttons = ["review", "ack", "awareness", "awareness-correct", "report", "refresh", "draft-generate", "draft-inspect", "draft-load", "draft-review", "synthetic-generate", "synthetic-load"];
    const timeLabel = workflowTimeLabel;
    const declinedLabels = { hold: "신고 보류", do_not_proceed: "신고 진행 안 함" };
    // The form shows one draft at a time; review controls apply only when it is this case's draft.
    const showInForm = value => {
        if (!value || shownDraft?.draft_id !== value.draft?.draft_id) setPreviewOpen(false);
        shownDraft = value?.draft ?? null;
        onDraft(value);
    };
    // The next action or read-only inspection. Follow-up steps are never implied as done.
    function nextAction(state, draft) {
        if (!state) return null;
        if (!state.analyst_ack_time) return "ack";
        if (!state.evidence_reviewed_at) return "review";
        const awareness = awarenessRecordStatus(state);
        if (awareness === "incomplete") return "state-summary";
        if (awareness === "missing") return "awareness";
        // A human decision not to report is respected; nothing further is suggested.
        if (state.report_choice === "do_not_proceed") return "decision-summary";
        if (state.report_choice !== "proceed") return "report-panel";
        // Reading the draft comes before recording its review.
        if (draft?.draft && draft.current && !draft.review) return "draft-inspect";
        return draft?.draft && draft.current ? "kisa-panel" : "draft-generate";
    }
    const nextLabels = { ack: "담당자 확인 진행 →", review: "근거 검토 진행 →", awareness: "인지 기록 진행 →",
        "state-summary": "인지 기록 상태 확인 →", "decision-summary": "처리 기록 확인 →",
        "draft-generate": "신고서 초안 생성 →", "draft-inspect": "신고서 내용 확인·보완 →", "kisa-panel": "작성된 신고서 확인 →" };
    // Completed or terminal work keeps the overview button but never as the primary action.
    const secondaryTargets = new Set(["decision-summary", "kisa-panel"]);
    // Shares the already-loaded state with the summaries; it never starts a read or a write itself.
    function publish(alerts) {
        onProgress({ runId, entityId: timelineSource?.entity_id ?? null, alerts, status: node("status").textContent,
            step: node("current") && !node("current").hidden ? node("current-step").textContent : "",
            next: node("next") && !node("next").hidden ? node("next").textContent : "" });
    }
    function setPreviewOpen(open, returnFocus = false) {
        const preview = node("draft-preview");
        if (!preview) return;
        previewOpen = open;
        preview.open = open;
        if (!open) {
            // Collapse the reading/editing space without replacing any inputs or saved document.
            for (const id of ["kisa-checklist", "kisa-inputs-panel"]) {
                const panel = document.getElementById(id);
                if (panel) panel.open = false;
            }
        }
        controls();
        if (returnFocus) {
            const target = node("draft-inspect")?.hidden ? preview.querySelector?.("summary") : node("draft-inspect");
            target?.focus?.({ preventScroll: true });
            target?.scrollIntoView?.({ block: "nearest", behavior: "instant" });
        }
    }
    function inspectDraft() {
        previewInteraction += 1;
        setPreviewOpen(true);
        const preview = node("draft-preview");
        if (!preview) return;
        preview.scrollIntoView?.({block:"start",behavior:"smooth"});
        preview.querySelector?.("summary")?.focus?.();
    }
    function collapseDraftPreview() {
        previewInteraction += 1;
        setPreviewOpen(false, true);
    }
    function renderTimeline(value, entry = null) {
        timelineSource = value;
        const reading = readingFor(value?.alert_id);
        const steps = workflowSteps(value, entry);
        for (const list of [node("timeline"), node("detail-timeline")].filter(Boolean)) {
            list.replaceChildren();
            for (const step of steps) {
                const li = document.createElement("li");
                li.dataset ??= {};
                li.dataset.state = step.state;
                if (step.active) li.setAttribute?.("aria-current", "step");
                const title = document.createElement("span"), text = document.createElement("strong");
                title.textContent = step.label;
                text.textContent = step.state === "incomplete" ? "확인 필요"
                    : step.timestamp ? list === node("timeline") ? "완료" : timeLabel(step.timestamp) : step.active ? "다음 단계" : "대기";
                text.title = workflowTimeDetail(step.timestamp);
                if (step.label === "신고 검토") text.textContent = { proceed: "신고 진행", hold: "보류", do_not_proceed: "진행하지 않음" }[value.state.report_choice] ?? "미결정";
                if (step.label === "초안·검토") text.textContent = step.state === "not_applicable"
                    ? `${declinedLabels[value.state.report_choice]} · 작성 대상 아님`
                    : entry?.draft ? !entry.current ? "이전 버전" : entry.review ? "검토 완료" : "작성됨 · 검토 전"
                    : entry?.unavailable ? "조회 실패" : entry?.empty ? "초안 없음" : reading > 0 ? "조회 중" : "미조회";
                li.append(title, text); list.append(li);
            }
        }
        // Overview card: current step, pending count and the next action only.
        const activeIndex = steps.findIndex(step => step.active);
        const declined = declinedLabels[value?.state.report_choice];
        if (node("current")) {
            node("current").hidden = !value;
            const step = steps[activeIndex];
            node("current-step").textContent = !value ? "" : !step ? declined ? `${declined} · 초안 작성 대상 아님` : "모든 단계 기록됨"
                : `${activeIndex + 1}/${steps.length} · ${step.label}${step.state === "partial" ? entry?.current ? " · 검토 전" : " · 이전 버전" : ""}`;
        }
        // Counts cover only the selected item's alerts; a hold is still open work.
        if (value && alertItems.length) {
            const pending = alertItems.filter(item => item.state?.report_choice === "hold" || (item.alert_id === value.alert_id ? activeIndex >= 0
                : workflowSteps(item).slice(0, 5).some(step => step.state !== "complete"))).length;
            node("status").textContent = alertItems.length > 1
                ? `선택 항목 알림 ${alertItems.length}건 중 미완료 ${pending}건`
                : pending ? "선택 항목 미완료 알림 1건" : "선택 항목 알림 처리 기록됨";
        }
        timelineEntry = entry;
        renderNext();
        // The rendered alert carries its latest state; the synced list may still hold the older one.
        if (value) publish(alertItems.some(item => item.alert_id === value.alert_id)
            ? alertItems.map(item => item.alert_id === value.alert_id ? value : item) : [...alertItems, value]);
    }
    // The next action and one guidance sentence come only from what has actually been read:
    // the stored alert list, whether an alert is open, and whether its draft list was read.
    function renderNext() {
        const value = timelineSource, entry = timelineEntry;
        const reading = readingFor(value?.alert_id);
        const action = nextAction(value?.state, entry);
        const opened = Boolean(value && detail?.alert_id === value.alert_id);
        const draftUnknown = action === "draft-generate" && (!entry || entry.unavailable);
        const next = node("next");
        if (next) {
            next.hidden = !value;
            next.disabled = !value || busy || (reading > 0 && draftUnknown);
            next.textContent = !value ? "처리할 알림 없음"
                : draftUnknown ? reading > 0 ? "알림·저장 초안 조회 중" : entry?.unavailable ? "저장 초안 다시 조회 →"
                    : opened ? "저장 초안 확인 →" : "알림 열기 · 저장 초안 확인 →"
                : action === "report-panel" ? value.state.report_choice === "hold" ? "보류 중 · 신고 검토 다시 확인 →" : "신고 검토 진행 →"
                : nextLabels[action] ?? "처리 기록 확인 →";
            next.dataset ??= {};
            next.dataset.tone = !value || !action || secondaryTargets.has(action) ? "secondary" : "primary";
        }
        const guide = node("guidance");
        if (!guide) return;
        guide.textContent = !value
            ? { loaded: alertItems.length ? "" : "처리할 담당자 알림이 없습니다.",
                failed: "알림을 조회하지 못했습니다 · 상태 새로고침으로 다시 읽습니다." }[alertsState] ?? ""
            : reading > 0 && (draftUnknown || !opened) ? "알림·저장 초안 조회 중"
            : !opened && alertItems.length > 1 ? `알림 ${alertItems.length}건 · 상단 목록에서 처리할 알림을 열 수 있습니다. 버튼은 첫 알림을 엽니다.`
            : entry?.unavailable ? "저장 초안 조회 실패 · 다시 조회하세요."
            : opened ? ""
            : draftUnknown ? "저장 초안 미조회"
            : entry?.draft || entry?.empty ? "저장 초안 확인됨"
            : "";
    }
    // Steps and guidance are redrawn when a read starts and settles, so "조회 중" never outlives the read.
    const redraw = () => (timelineSource ? renderTimeline(timelineSource, timelineEntry) : renderNext());
    async function readDrafts(alertId, work) {
        const read = { generation, alertId };
        draftReads.add(read);
        redraw();
        try { return await work(); } finally {
            draftReads.delete(read);
            if (read.generation === generation) redraw();
        }
    }
    async function refreshProgress(value) {
        const current = generation;
        await readDrafts(value.alert_id, async () => {
            try {
                const response = await request(`alerts/${value.alert_id}/report-drafts`);
                if (current !== generation || timelineSource !== value) return;
                const item = response.items?.find(item => item.status === "completed" && item.draft);
                renderTimeline(value,item ?? {empty: true});
            } catch {
                if (current === generation && timelineSource === value) renderTimeline(value,{ unavailable: true });
            }
        });
    }
    async function refreshReportingStatus() {
        try {
            reportingStatus = await request("reporting/status");
            node("llm-status").textContent = reportingStatus.adapter === "configured" ? "초안 작성 준비됨" : "작성 기능 설정 확인 필요";
            // Only an explicit server flag may say otherwise; synthetic demo status is reported separately.
            node("transmission-status").textContent = reportingStatus.snapshot_approval_supported === true
                ? "AI 작성: 비식별 전송 내용 확인 및 개별 승인 필요"
                : "이 서버: 실제 데이터 외부 전송 차단 · 대체 작성만 가능";
            if (node("provider-detail")) node("provider-detail").textContent = JSON.stringify(reportingStatus, null, 2);
            const badge = document.getElementById("operator-demo-badge");
            if (badge) badge.hidden = false;
        } catch {
            reportingStatus = null;
            node("llm-status").textContent = "초안 작성 상태 확인 불가";
        }
        renderReportSummary();
        controls();
    }
    // Read-only eligibility for the summary card: GET preview has no provider call or approval.
    function renderReportSummary() {
        const target = node("report-summary");
        if (!target?.replaceChildren) return;
        target.replaceChildren();
        const identity = detail ? `${detail.alert_id}:${detail.state.version}` : null;
        for (const [label, content] of reportSummaryRows(detail, eligibility?.identity === identity ? eligibility : null, reportingStatus)) {
            const term = document.createElement("dt"), description = document.createElement("dd");
            term.textContent = label;
            description.textContent = content;
            target.append(term, description);
        }
    }
    async function checkEligibility() {
        if (!detail || detail.state.report_choice !== "proceed") return;
        const identity = `${detail.alert_id}:${detail.state.version}`, current = generation, version = detail.state.version;
        if (eligibility?.identity === identity) return;
        eligibility = { identity, state: "checking", phrases: [] };
        renderReportSummary();
        let next;
        try {
            next = snapshotEligibility(await request(`alerts/${detail.alert_id}/report-snapshot`), version);
        } catch (error) {
            next = { state: { 422: "ineligible", 404: "unsupported", 409: "blocked" }[error.status] ?? "unknown", phrases: [] };
        }
        if (current !== generation || eligibility?.identity !== identity) return;
        eligibility = { ...next, identity };
        renderReportSummary();
        controls();
    }
    function savedSelection() {
        try { return JSON.parse(globalThis.localStorage?.getItem("iae.workflow.selection") ?? "null"); }
        catch { return null; }
    }
    function controls() {
        for (const name of ["snapshot-consent", "snapshot-reuse", "snapshot-type", "snapshot-reason", "snapshot-cancel"]) {
            if (node(name)) node(name).disabled = busy;
        }
        const reuse = Boolean(snapshot?.word_reuse && node("snapshot-reuse")?.checked);
        // A saved reuse form carries its own human type selection; the radios do not apply then.
        if (node("snapshot-type-group")) node("snapshot-type-group").disabled = busy || reuse;
        if (node("draft-fallback")) node("draft-fallback").disabled = busy || detail?.state.report_choice !== "proceed";
        const wordReady = reuse || Boolean(node("snapshot-type")?.value && node("snapshot-type").value !== "undetermined");
        if (node("snapshot-generate")) node("snapshot-generate").disabled = busy || !snapshot || !node("snapshot-consent")?.checked || !wordReady;
        renderNext();
        for (const name of buttons) node(name).disabled = busy || (name !== "refresh" && !detail);
        if (detail && !busy) {
            node("ack").disabled = Boolean(detail.state.analyst_ack_time);
            node("review").disabled = Boolean(detail.state.evidence_reviewed_at);
            const ready = detail.state.analyst_ack_time && detail.state.evidence_reviewed_at;
            node("awareness").disabled = !ready || Boolean(detail.state.t_h);
            node("awareness-correct").disabled = !ready || !detail.state.t_h;
            node("report").disabled = !ready;
            const identity = `${detail.alert_id}:${detail.state.version}`;
            node("draft-generate").disabled = detail.state.report_choice !== "proceed"
                || eligibility?.identity === identity && ["ineligible", "unsupported", "blocked"].includes(eligibility.state);
            node("draft-review").disabled = !currentDraft || !currentDraft.current || Boolean(currentDraft.review);
            node("synthetic-generate").disabled = detail.state.report_choice !== "proceed" || !node("synthetic-consent").checked || !reportingStatus?.synthetic_transmission_enabled;
        }
        emphasize();
    }
    // Completed or not-yet-possible actions are collapsed; only the next action is primary.
    function emphasize() {
        const state = detail?.state;
        const ready = Boolean(state?.analyst_ack_time && state?.evidence_reviewed_at);
        const proceed = state?.report_choice === "proceed";
        if (detail) {
            node("ack").hidden = Boolean(state.analyst_ack_time);
            node("review").hidden = Boolean(state.evidence_reviewed_at);
            node("awareness").hidden = !ready || Boolean(state.t_h);
            // The legal-awareness caveat is shown where the awareness record is made.
            if (node("awareness-note")) node("awareness-note").hidden = node("awareness").hidden;
            node("draft-generate").hidden = !proceed;
            // With a current draft, reading it is the main action; regeneration stays secondary.
            node("draft-generate").textContent = currentDraft?.current ? "AI 초안 다시 생성" : "AI 신고서 초안 생성";
            const unreviewed = proceed && Boolean(currentDraft?.current) && !currentDraft.review
                && shownDraft === currentDraft.draft;
            if (node("draft-inspect")) node("draft-inspect").hidden = !unreviewed;
            node("draft-review").hidden = !unreviewed;
            node("compose-note").textContent = proceed ? ""
                : "신고 진행 결정 후 작성할 수 있습니다. 저장된 초안은 조회할 수 있습니다.";
            node("compose-note").hidden = proceed;
        }
        const target = nextAction(state, currentDraft);
        // An open approval or preview holds that area's own primary button, so the opener steps back.
        const approving = Boolean(node("snapshot-panel") && !node("snapshot-panel").hidden);
        const previewing = Boolean(node("draft-preview")?.open);
        if (node("draft-inspect")) {
            node("draft-inspect").textContent = previewing ? "미리보기 접기" : "내용 확인·보완";
            node("draft-inspect").setAttribute?.("aria-expanded", String(previewing));
        }
        for (const name of ["ack", "review", "awareness", "report-panel", "draft-generate", "draft-inspect"]) {
            const element = node(name);
            if (!element) continue;
            element.dataset ??= {};
            if (detail && !busy && name === target && !(approving && name === "draft-generate")
                && !(previewing && name === "draft-inspect")) element.dataset.next = "true";
            else delete element.dataset.next;
        }
    }
    async function request(path, options = {}) {
        const { timeoutMs = 10000, ...fetchOptions } = options;
        const response = await fetchImpl(`/human-workflow/${path}`, {
            ...fetchOptions, signal: AbortSignal.timeout(timeoutMs),
            headers: { "Content-Type": "application/json" },
        });
        if (!response.ok) {
            const error = new Error(response.status === 409
                ? "동시 수정 또는 중복 기록입니다. 알림 다시 조회 후 입력을 확인하세요."
                : response.status === 422 ? "필수 입력과 시간대·시각을 확인하세요."
                : "서버 오류: 같은 입력으로 재시도할 수 있습니다.");
            error.status = response.status;
            throw error;
        }
        return response.json();
    }
    function render(value) {
        if (value?.alert_id !== detail?.alert_id || value?.state.version !== detail?.state.version) {
            clearSnapshot();
            eligibility = null;
            pendingDraft = null;
            node("draft-text").textContent = "";
            node("draft-status").textContent = "";
            currentDraft = null;
            showInForm(null);
        }
        detail = value;
        // Report and audit scope follow the opened alert; developer tools also require explicit mode.
        for (const name of ["record", "compose", "history"]) if (node(name)) node(name).hidden = !value;
        if (node("dev-tools")) node("dev-tools").hidden = !developerTools || !value;
        if (document.getElementById("workflow-developer-area")) document.getElementById("workflow-developer-area").hidden = !developerTools || !value;
        renderReportSummary();
        if (!value) { controls(); return; }
        void checkEligibility();
        const source = value.source_snapshot;
        // Re-opening the same alert version keeps what was already read about its drafts.
        renderTimeline(value, timelineSource?.alert_id === value.alert_id
            && timelineSource?.state?.version === value.state.version ? timelineEntry : null);
        node("correction-panel").hidden = !value.state.t_h;
        // The Run is already in the detail header; only the alert's own target and source are added.
        node("source-summary").textContent = `${value.detection_kind === "fusion" ? "증거 누적 분석 탐지" : "통합 판단 탐지"} · 대상 ${value.entity_id}`;
        if (node("human-summary")) node("human-summary").textContent = `내부 인지시각 ${timeLabel(value.state.t_h)} · 기록시각 ${timeLabel(value.state.t_h_recorded_at)} · 신고 ${ {proceed:"진행",hold:"보류",do_not_proceed:"진행하지 않음"}[value.state.report_choice] ?? "미결정"}`;
        node("source").textContent = JSON.stringify({
            context: source.context, detection_kind: value.detection_kind,
            run_id: value.run_id, entity_id: value.entity_id, decision_id: value.decision_id,
            detected_at: value.detected_at, issued_at: value.issued_at,
            source_path: source.source_path, decision_source_path: source.decision_source_path,
            hybrid_status: source.hybrid_status, t_e: source.decision?.t_e ?? null,
            evidence_ids: source.evidence_ids,
            source_hit_ids: source.source_hit_ids ?? [],
        }, null, 2);
        node("state").textContent = JSON.stringify({ ...value.state,
            operational_24h: value.operational_24h }, null, 2);
        const time = workflowTimeDetail;
        const choice = { proceed: "신고 진행", hold: "판단 보류", do_not_proceed: "진행하지 않음" };
        const clock = { no_awareness: "기산점 없음 · 내부 인지시각 미기록", within_24h: "내부 운영 기준 24시간 이내",
            over_24h: "내부 운영 기준 24시간 경과" };
        node("state-summary").replaceChildren();
        for (const [label, content] of [
            ["탐지 시각 / 알림 발행 시각", `${time(value.detected_at)} / ${time(value.issued_at)}`],
            ["알림 확인 / 근거 검토", `${time(value.state.analyst_ack_time)} / ${time(value.state.evidence_reviewed_at)}`],
            ["조직 내부 인지시각", time(value.state.t_h)],
            ["내부 인지시각 시스템 기록시각", time(value.state.t_h_recorded_at)],
            ["24시간 상태 (법적 판단 아님)", clock[value.operational_24h.status] ?? "확인 필요"],
            ["신고 진행 결정", choice[value.state.report_choice] ?? "미결정"],
            ["결정 기록시각 / 사유", `${time(value.state.report_decided_at)} / ${value.state.report_reason ?? "미기록"}`],
        ]) {
            const term = document.createElement("dt");
            const description = document.createElement("dd");
            term.textContent = label;
            description.textContent = content;
            node("state-summary").append(term, description);
        }
        node("audit").textContent = JSON.stringify(value.audit, null, 2);
        node("evidence-link").href = `/dashboard/runs/${encodeURIComponent(value.run_id)}`;
        if (node("report-input")) {
            node("report-input").hidden = value.state.report_choice !== "proceed";
            node("report-input").href = `/human-workflow/alerts/${value.alert_id}/report-input`;
        }
        controls();
    }
    async function open(alertId) {
        const current = generation;
        const requestVersion = ++detailGeneration;
        // Opening reads the alert and then its drafts; the guidance shows the read until both settle.
        await readDrafts(alertId, async () => {
            try {
                const value = await request(`alerts/${encodeURIComponent(alertId)}`);
                if (current !== generation || requestVersion !== detailGeneration) return;
                render(value);
                pending = null;
                try { globalThis.localStorage?.setItem("iae.workflow.selection", JSON.stringify({ runId, alertId })); }
                catch { /* Persistence of actions belongs to PostgreSQL. */ }
                node("action-status").textContent = "";
                onOpen();
                await loadDrafts();
            } catch (error) {
                if (current === generation) node("action-status").textContent = error.message;
            }
        });
    }
    async function select(selectedRun, { readOnly = false } = {}) {
        const current = ++generation;
        ++detailGeneration;
        draftReads.clear();
        runId = selectedRun;
        pending = null;
        pendingDraft = null;
        alertsState = selectedRun ? "loading" : "idle";
        node("draft-text").textContent = "";
        node("draft-status").textContent = "";
        render(null);
        renderTimeline(null);
        node("synthetic-text").textContent = "";
        node("synthetic-status").textContent = "";
        node("synthetic-consent").checked = false;
        pendingSynthetic = null;
        alertItems = [];
        for (const name of ["th", "th-reason", "report-choice", "report-reason"]) node(name).value = "";
        node("alerts").replaceChildren();
        node("status").textContent = "선택 항목의 알림을 조회 중입니다.";
        if (!runId) return;
        publish(null);
        try {
            const result = readOnly
                ? await request(`runs/${encodeURIComponent(runId)}/alerts`)
                : await request(`runs/${encodeURIComponent(runId)}/sync`, { method: "POST" });
            if (current !== generation) return;
            alertItems = result.items;
            alertsState = "loaded";
            node("status").textContent = result.items.length
                ? `선택 항목 알림 ${result.items.length}건`
                : readOnly ? "저장된 담당자 처리 알림 없음 · 분석 결과와 별도"
                    : "선택 항목에 처리할 탐지 알림 없음 · 탐지 결과 없음 또는 미평가";
            node("alerts").hidden = result.items.length <= 1;
            if (!result.items.length) { publish([]); renderNext(); }
            for (const alert of result.items) {
                const item = document.createElement("li");
                const button = document.createElement("button");
                button.type = "button";
                button.textContent = `${alert.detection_kind === "fusion" ? "증거 누적 분석 탐지" : "통합 판단 탐지"} · ${alert.entity_id} · 처리 열기`;
                button.addEventListener("click", () => void open(alert.alert_id));
                item.append(button);
                node("alerts").append(item);
            }
            if (result.items[0]) {
                renderTimeline(result.items[0]);
                if (!readOnly) void refreshProgress(result.items[0]);
            }
            if (!readOnly) void refreshReportingStatus();
            const saved = savedSelection();
            if (!readOnly && saved?.runId === runId && result.items.some(item => item.alert_id === saved.alertId)) {
                await open(saved.alertId);
            }
        } catch (error) {
            if (current === generation) { alertsState = "failed"; node("status").textContent = error.message; publish(null); renderNext(); }
        }
    }
    async function act(action, fields = {}) {
        if (busy || !detail) return;
        const current = generation;
        const alertId = detail.alert_id;
        const requestVersion = ++detailGeneration;
        const signature = JSON.stringify({ alertId, action, fields });
        if (!pending || pending.signature !== signature) {
            pending = { signature, payload: actionPayload(action, detail.state.version, fields) };
        }
        busy = true;
        controls();
        node("action-status").textContent = "저장 중";
        try {
            const value = await request(`alerts/${alertId}/actions`, {
                method: "POST", body: JSON.stringify(pending.payload),
            });
            if (current !== generation || requestVersion !== detailGeneration) return;
            pending = null;
            render(value);
            void refreshProgress(value);
            node("action-status").textContent = "기록이 영속 저장되었습니다.";
        } catch (error) {
            if (current === generation) {
                node("action-status").textContent = error.message;
                if ([409, 422].includes(error.status)) pending = null;
            }
        } finally { busy = false; controls(); }
    }
    node("refresh").addEventListener("click", () => {
        if (detail) void open(detail.alert_id);
        else void select(runId, { readOnly: true });
    });
    node("sync")?.addEventListener("click", () => void select(runId));
    node("ack").addEventListener("click", () => void act("acknowledge"));
    node("next")?.addEventListener("click", async () => {
        if (!timelineSource) return;
        const selection = generation, interaction = previewInteraction;
        await open(timelineSource.alert_id);
        // A newer selection or a manual close while this read was pending wins over its shortcut.
        if (!detail || selection !== generation || interaction !== previewInteraction) return;
        // A failed draft read leads to its message, never to drafting as if no draft existed.
        if (timelineEntry?.unavailable) {
            node("draft-status")?.scrollIntoView?.({block:"center",behavior:"smooth"});
            return;
        }
        const target = nextAction(detail.state, currentDraft) ?? "record";
        if (target === "draft-inspect") { inspectDraft(); return; }
        const element = target === "kisa-panel" ? document.getElementById("kisa-panel")
            : target === "decision-summary" ? node("state-summary") : node(target);
        if (target === "report-panel" && element) element.open = true;
        if ((target === "state-summary" || target === "decision-summary") && element) {
            const panel = element.closest?.("details");
            if (panel) panel.open = true;
            element.tabIndex = -1;
        }
        element?.focus?.();
        element?.scrollIntoView?.({block:"center",behavior:"smooth"});
    });
    node("review").addEventListener("click", () => void act("review_evidence"));
    node("awareness").addEventListener("click", () => void act("record_awareness", {
        awareness_mode: "now", reason: "담당자가 현재 시각으로 인지 기록을 명시적으로 선택",
    }));
    node("awareness-form").addEventListener("submit", (event) => {
        event.preventDefault();
        const local = node("th").value;
        void act("record_awareness", { t_h: (local.length === 16 ? local + ":00" : local) + "+09:00", reason: node("th-reason").value });
    });
    node("report-form").addEventListener("submit", (event) => {
        event.preventDefault();
        void act("decide_reporting", { report_choice: node("report-choice").value,
            reason: node("report-reason").value });
    });
    function showDraft(draft, current = true, entry = {}) {
        currentDraft = { draft, current, review: entry.review ?? null };
        showInForm({draft,current,alertId:detail.alert_id,workflowVersion:detail.state.version});
        node("draft-text").textContent = draft.text;
        const metadata = draft.call_metadata;
        const presentation = draftPresentation(draft);
        // Review and submission states live in the document summary; this line names the draft only.
        node("draft-status").textContent = `${current ? "저장 초안" : "이전 버전 초안"} · ${presentation.ai ? "AI 작성 · 검증 통과"
            : `${presentation.method}${presentation.reason ? ` (${presentation.reason})` : ""}`} · ${timeLabel(draft.generated_at)}`;
        if (node("draft-metadata")) node("draft-metadata").textContent = JSON.stringify(metadata, null, 2);
        renderTimeline(detail,{ draft, current, review: entry.review });
        controls();
    }
    async function generateDraft() {
        if (busy || !detail || detail.state.report_choice !== "proceed") return;
        const current = generation, requestVersion = ++detailGeneration;
        const identity = `${detail.alert_id}:${detail.state.version}`;
        if (pendingDraft?.identity !== identity) pendingDraft = {
            identity, payload: { expected_version: detail.state.version, idempotency_key: crypto.randomUUID() },
        };
        busy = true;
        controls();
        node("draft-status").textContent = "초안 생성 및 원천 근거 검증 중";
        try {
            const draft = await request(`alerts/${detail.alert_id}/report-drafts`, {
                method: "POST", body: JSON.stringify(pendingDraft.payload), timeoutMs: 60000,
            });
            if (current !== generation || requestVersion !== detailGeneration) return;
            pendingDraft = null;
            showDraft(draft);
        } catch (error) {
            if (current === generation && requestVersion === detailGeneration) {
                node("draft-status").textContent = error.status === 404
                    ? "저장 초안 조회 기능 미지원" : error.message;
                if ([409, 422].includes(error.status)) pendingDraft = null;
            }
        } finally { busy = false; controls(); }
    }
    function clearSnapshot() {
        snapshot = null;
        pendingApproved = null;
        if (node("snapshot-panel")) node("snapshot-panel").hidden = true;
        if (node("snapshot-request")) node("snapshot-request").textContent = "";
        if (node("snapshot-consent")) node("snapshot-consent").checked = false;
        if (node("snapshot-reuse")) node("snapshot-reuse").checked = false;
        if (node("snapshot-type")) node("snapshot-type").value = "undetermined";
        for (const radio of node("snapshot-type-group")?.querySelectorAll?.("input[type=radio]") ?? []) radio.checked = false;
        if (node("snapshot-reason")) node("snapshot-reason").value = "";
    }
    async function previewSnapshot() {
        if (busy || !detail || detail.state.report_choice !== "proceed") return;
        clearSnapshot();
        const current = generation, version = ++detailGeneration, identity = detail.alert_id;
        const eligibilityIdentity = `${identity}:${detail.state.version}`;
        busy = true; controls();
        node("draft-status").textContent = "분석 자료 검증 중 · 아직 외부로 전송하지 않았습니다.";
        try {
            const value = await request(`alerts/${identity}/report-snapshot`);
            if (current !== generation || version !== detailGeneration) return;
            if (!/^[a-f0-9]{64}$/.test(value.snapshot_sha256) || value.workflow_version !== detail.state.version || value.external_transmission !== "not_sent") throw new Error("전송 미리보기 검증 실패");
            snapshot = value;
            eligibility = { ...snapshotEligibility(value, detail.state.version), identity: eligibilityIdentity };
            renderReportSummary();
            const phrases = eligibility.phrases;
            node("snapshot-reuse-label").hidden = !value.word_reuse;
            if (value.word_reuse && node("snapshot-reuse-text")) node("snapshot-reuse-text").textContent =
                `같은 사건에 저장된 사고 유형(${{ransomware:"랜섬웨어",ddos:"디도스",other_hacking:"그 밖의 해킹"}[value.word_reuse.incident_type] ?? "확인 필요"})·기업·신고자 정보 재사용 (동의 항목 제외)`;
            if (node("snapshot-summary")) node("snapshot-summary").textContent = phrases.length
                ? `전송 대상: 원본 검증 관측 ${phrases.length}건의 행위 유형 문구 (${phrases.join(", ")})`
                : "전송 대상: 서버가 검증한 비식별 행위 유형 문구";
            node("snapshot-request").textContent = `전송 대상: ${value.endpoint ?? "미확인"}\n포함 정보: 아래 비식별 요청 본문\nSnapshot ${value.snapshot_sha256}\n${value.request_body}`;
            node("snapshot-panel").hidden = false;
            node("draft-status").textContent = "전송 내용을 확인하고 Word 양식 사고 유형을 선택한 뒤 승인하세요 · 아직 전송하지 않았습니다.";
            node("snapshot-panel").scrollIntoView?.({block:"nearest",behavior:"smooth"});
        } catch (error) {
            if (current === generation && version === detailGeneration) {
                if ([404, 409, 422].includes(error.status)) {
                    eligibility = { identity: eligibilityIdentity, phrases: [], state: { 422: "ineligible", 404: "unsupported", 409: "blocked" }[error.status] };
                    renderReportSummary();
                }
                node("draft-status").textContent = error.status === 404
                    ? "AI 전송 승인 기능 미지원 · 대체 작성을 이용하세요."
                    : error.status === 422 ? "자동 작성 불가: 원본 검증된 정식 분석 관측이 없거나 외부 작성이 허용되지 않은 관측입니다. 전송하지 않았습니다."
                    : "검증된 비식별 입력을 준비할 수 없습니다. 전송하지 않았습니다.";
            }
        } finally { busy = false; controls(); }
    }
    async function generateApproved() {
        if (busy || !detail || !snapshot || !node("snapshot-consent")?.checked) return;
        const reuse = Boolean(snapshot.word_reuse && node("snapshot-reuse")?.checked);
        const type = node("snapshot-type")?.value ?? "undetermined";
        if (!reuse && (!type || type === "undetermined")) {
            node("draft-status").textContent = "Word 양식 사고 유형을 선택하세요 · 아직 전송하지 않았습니다.";
            return;
        }
        const current = generation, version = ++detailGeneration;
        const identity = detail.alert_id, workflowVersion = detail.state.version, selected = snapshot;
        // An explicit reason wins; otherwise record the human selection and the shown verified basis.
        const reason = node("snapshot-reason")?.value.trim()
            || classificationReason(type, snapshotEligibility(snapshot, workflowVersion).phrases);
        const word = reuse
            ? {reuse_form_id:snapshot.word_reuse.form_id}
            : {word_inputs:{expected_workflow_version:workflowVersion,expected_form_version:0,
                incident_type:type,classification_reason:reason,
                idempotency_key:pendingApproved?.wordKey ?? crypto.randomUUID()}};
        const signature = JSON.stringify({...word, word_inputs:word.word_inputs ? {...word.word_inputs,idempotency_key:null} : undefined});
        if (pendingApproved && pendingApproved.signature !== signature) {
            node("draft-status").textContent = "재시도 중인 입력은 변경할 수 없습니다. 전송 미리보기부터 다시 확인하세요.";
            return;
        }
        pendingApproved ??= {approvalKey: crypto.randomUUID(), draftKey: crypto.randomUUID(), wordKey:word.word_inputs?.idempotency_key, signature};
        const pending = pendingApproved;
        busy = true; controls();
        node("draft-status").textContent = "외부 전송 승인 기록 중 · 아직 전송하지 않았습니다.";
        try {
            const grant = await request(`alerts/${identity}/report-snapshot-approvals`, {
                method: "POST", body: JSON.stringify({expected_version:workflowVersion,
                    idempotency_key:pending.approvalKey, snapshot_sha256:selected.snapshot_sha256, approve_external:true}),
            });
            if (current !== generation || version !== detailGeneration || snapshot !== selected) return;
            // One server request covers the AI call, its validation and the Word form; no fake progress.
            node("draft-status").textContent = "AI 초안 작성 · 근거 검증 · 신고서 양식 생성 중 (서버 응답 대기)";
            const draft = await request(`alerts/${identity}/ai-report-drafts`, {
                method:"POST", timeoutMs:60000, body:JSON.stringify({expected_version:workflowVersion,
                    idempotency_key:pending.draftKey, consent_id:grant.consent_id, ...word}),
            });
            if (current !== generation || version !== detailGeneration) return;
            clearSnapshot();
            showDraft(draft);
            node("draft-status").textContent += ` · ${generationOutcome(draft)}`;
        } catch (error) {
            if (current === generation && version === detailGeneration) {
                if ([409,422].includes(error.status)) clearSnapshot();
                node("draft-status").textContent = {
                    409: "입력 또는 승인 상태가 변경되었습니다. 전송 내용을 다시 확인하세요.",
                    422: "승인 입력 또는 사고 유형이 유효하지 않아 생성하지 않았습니다. 전송 내용을 다시 확인하세요.",
                    404: "저장된 양식을 찾을 수 없습니다. 재사용 없이 다시 확인하세요.",
                    503: "저장소를 사용할 수 없습니다. 같은 요청으로 다시 시도하면 중복 생성 없이 이어집니다.",
                }[error.status] ?? "응답을 받지 못했습니다. 같은 요청으로 다시 시도하면 중복 생성 없이 결과를 확인합니다.";
            }
        } finally { busy = false; controls(); }
    }
    async function loadDrafts({ allowBusy = false } = {}) {
        if ((!allowBusy && busy) || !detail) return;
        const current = generation, requestVersion = ++detailGeneration;
        await readDrafts(detail.alert_id, async () => {
            try {
                const response = await request(`alerts/${detail.alert_id}/report-drafts`);
                if (current !== generation || requestVersion !== detailGeneration) return;
                const item = response.items.find(item => item.status === "completed" && item.draft);
                if (item) showDraft(item.draft, item.current, item);
                else {
                    node("draft-text").textContent = "";
                    node("draft-status").textContent = "완료된 저장 초안 없음";
                    renderTimeline(detail,{ empty: true });
                }
            } catch (error) {
                if (current !== generation || requestVersion !== detailGeneration) return;
                node("draft-status").textContent = error.message;
                // A failed read is shown as such; it never reads as "no draft" or keeps an older answer.
                renderTimeline(detail,{ unavailable: true });
            }
        });
    }
    node("draft-generate").addEventListener("click", () => void previewSnapshot());
    node("draft-inspect")?.addEventListener("click", () => {
        if (node("draft-preview")?.open) collapseDraftPreview();
        else inspectDraft();
    });
    node("draft-collapse")?.addEventListener("click", collapseDraftPreview);
    // Native summary activation also records a reading choice, before any delayed response arrives.
    node("draft-preview")?.querySelector?.("summary")?.addEventListener?.("click", () => { previewInteraction += 1; });
    node("draft-preview")?.addEventListener?.("toggle", () => {
        const open = Boolean(node("draft-preview").open);
        if (open !== previewOpen) previewInteraction += 1;
        setPreviewOpen(open);
    });
    node("draft-fallback")?.addEventListener("click", () => void generateDraft());
    node("snapshot-consent")?.addEventListener("change", controls);
    node("snapshot-reuse")?.addEventListener("change", controls);
    node("snapshot-type")?.addEventListener("change", controls);
    // One click on a radio records the human type selection; nothing is preselected.
    node("snapshot-type-group")?.addEventListener("change", (event) => {
        if (event?.target?.type === "radio" && event.target.checked && node("snapshot-type")) node("snapshot-type").value = event.target.value;
        controls();
    });
    node("snapshot-cancel")?.addEventListener("click", () => {
        if (busy) return;
        clearSnapshot();
        node("draft-status").textContent = "외부로 전송하지 않고 닫았습니다.";
        controls();
    });
    node("snapshot-reason")?.addEventListener("input", controls);
    node("snapshot-generate")?.addEventListener("click", () => void generateApproved());
    node("draft-load").addEventListener("click", () => void loadDrafts());
    node("draft-review").addEventListener("click", async () => {
        if (busy || !detail || !currentDraft?.current) return;
        busy = true; controls();
        const current = generation, identity = detail.alert_id, version = detail.state.version;
        try {
            await request(`alerts/${identity}/report-drafts/${currentDraft.draft.draft_id}/review`, {
                method: "POST", body: JSON.stringify({expected_version:version,idempotency_key:crypto.randomUUID()}),
            });
            if (current === generation) await loadDrafts({ allowBusy: true });
        } catch (error) { if (current === generation) node("draft-status").textContent = error.message; }
        finally { busy = false; controls(); }
    });
    async function generateSynthetic() {
        if (busy || !detail || detail.state.report_choice !== "proceed" || !node("synthetic-consent").checked || !reportingStatus?.synthetic_transmission_enabled) return;
        const current = generation;
        ++detailGeneration;
        showInForm(null);
        pendingSynthetic ??= {expected_version:detail.state.version,idempotency_key:crypto.randomUUID(),allow_external_synthetic:true,fixture:"verified_observations_v1"};
        busy = true; controls();
        node("synthetic-status").textContent = "허용된 합성 fixture만 전송·생성 중";
        try {
            const draft = await request(`reporting/synthetic/${detail.alert_id}/drafts`, {
                method:"POST",body:JSON.stringify(pendingSynthetic),timeoutMs:60000,
            });
            if (current !== generation) return;
            pendingSynthetic = null;
            node("synthetic-text").textContent = draft.text;
            node("synthetic-status").textContent = `합성 시연 · 데모 · ${draftPresentation(draft).method} · ${timeLabel(draft.generated_at)} · 아래 신고서 확인에 표시 · 외부 제출되지 않음`;
            node("synthetic-status").title = JSON.stringify(draft.call_metadata);
            showInForm({draft,current:true,alertId:draft.alert_id,workflowVersion:draft.workflow_version});
            await refreshReportingStatus();
        } catch (error) { if (current === generation) node("synthetic-status").textContent = error.message; }
        finally { busy = false; controls(); }
    }
    node("synthetic-consent").addEventListener("change", controls);
    node("synthetic-generate").addEventListener("click", () => void generateSynthetic());
    node("synthetic-load").addEventListener("click", async () => {
        if (busy || !detail) return;
        const current = generation;
        ++detailGeneration;
        showInForm(null);
        busy = true; controls();
        try {
            const result = await request(`reporting/synthetic/${detail.alert_id}/drafts`);
            if (current !== generation) return;
            const item = result.items.find(item => item.status === "completed" && item.draft);
            if (!item) { node("synthetic-status").textContent = "저장된 합성 초안 없음"; return; }
            const draft = item.draft;
            node("synthetic-text").textContent = draft.text;
            node("synthetic-status").textContent = `합성 시연 · 데모 · 저장 초안 v${item.document_version} · ${draftPresentation(draft).method} · 아래 신고서 확인에 표시`;
            node("synthetic-status").title = JSON.stringify(draft.call_metadata);
            showInForm({draft,current:item.current,alertId:draft.alert_id,workflowVersion:draft.workflow_version});
        } catch(error) { if(current === generation) node("synthetic-status").textContent = error.message; }
        finally { busy = false; controls(); }
    });
    controls();
    return { select, open, act, savedSelection, generateDraft, loadDrafts, generateSynthetic, previewSnapshot, generateApproved };
}
