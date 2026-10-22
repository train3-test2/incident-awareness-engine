// Evidence tab reads for the selected Run only: lazy (on tab activation), deduplicated per Run,
// no polling timer, and stale responses are discarded by version.
import {
    EVIDENCE_MESSAGES,
    buildEvidenceApiPath,
    classifyEvidenceFailure,
    describeArchiveState,
    describeVerifiedArchive,
    getEvidenceTypeLabel,
    getFeatureChannelLabel,
    getSourceLayerLabel,
    resolveEvidenceResponse,
} from "./dashboard-evidence-contract.mjs";
import { buildEventDetailViewPath } from "./event-detail-contract.mjs";
import { analysisTimestampLabel } from "./dashboard-operator-contract.mjs";
import {
    createCopyableValue,
    createDetailList,
    createDetailRow,
    createExpandButton,
    createStackedText,
    focusedRowKey,
    restoreRowFocus,
} from "./dashboard-detail-rows.mjs";

const REQUEST_TIMEOUT_MS = 10000;
const EVENT_LINK_CLASS = "dashboard-evidence-event-link";
const COLUMNS = 6;
const updateText = (element, text) => {
    if (element.textContent !== text) element.textContent = text;
};

export function createDashboardEvidenceController(doc, {
    fetchImpl = globalThis.fetch, setTimeoutImpl = globalThis.setTimeout,
    clearTimeoutImpl = globalThis.clearTimeout,
} = {}) {
    const nodes = Object.fromEntries(["status", "archive", "region", "list"].map((key) => (
        [key, doc.getElementById(`evidence-${key}`)]
    )));
    if (Object.values(nodes).some((node) => node === null)) {
        return { select() {}, setActive() {}, refresh() {}, stop() {}, start() {} };
    }
    // Optional overview value beside the S0 verification state; absent in older shells.
    const overview = doc.getElementById("evidence-archive-state");
    let enabled = true;
    let active = false;
    let runId = null;
    let shownRunId = null; // Run whose result is shown or being read.
    let version = 0;
    let request = null;
    let pending = null;
    let shownItems = [];
    let expanded = new Set(); // Evidence IDs with an open detail row; cleared on Run change.
    let buttons = new Map();

    function cancel() {
        version += 1;
        request?.abort();
        request = null;
        pending = null;
    }

    function cell(...children) {
        const element = doc.createElement("td");
        element.append(...children);
        return element;
    }

    function text(tag, value, className = null) {
        const element = doc.createElement(tag);
        if (className) element.classList.add(className);
        element.textContent = value;
        return element;
    }

    function eventReference(evidence, reference) {
        const item = doc.createElement("li");
        if (reference.stored) {
            // Only an Event stored for this Run gets a link to the existing Event Detail view.
            const link = doc.createElement("a");
            link.classList.add(EVENT_LINK_CLASS);
            link.href = buildEventDetailViewPath(runId, reference.event_id);
            link.textContent = reference.event_id;
            link.setAttribute("aria-label", `Event ${reference.event_id} 상세`);
            link.dataset.evidenceId = evidence.evidence_id;
            link.dataset.eventId = reference.event_id;
            link.title = reference.event_id;
            item.append(link);
        } else {
            const unstored = text("span", `${reference.event_id} · 저장 Event 없음`, "dashboard-evidence-unstored");
            unstored.title = `${reference.event_id} · 이 분석에 저장된 Event가 없어 링크하지 않습니다.`;
            item.append(unstored);
        }
        return item;
    }

    // Identifiers and stored mappings stay complete here; the row leads with what was observed.
    function details(evidence) {
        const fields = [
            ["증거 ID", createCopyableValue(doc, evidence.evidence_id, "증거 ID")],
            ["증거 Type 원문", evidence.evidence_type],
            ["정책", evidence.policy ? `${evidence.policy.policy_id} · ${evidence.policy.version}` : "저장된 정책 없음"],
        ];
        if (evidence.policy) {
            fields.push(["정책 config_hash", createCopyableValue(doc, evidence.policy.config_hash, "정책 config_hash")]);
        }
        fields.push(
            ["ATT&CK (저장값)", evidence.attack_technique_ids.length
                ? evidence.attack_technique_ids.join(", ") : "저장된 매핑 없음"],
            ["비공개 필드", `${evidence.withheld_field_count}개`],
            ["Extractor", evidence.extractor_version],
            ["관측 시각 원본", `UTC ${evidence.timestamp}`],
            ["보관 범위", "게시 완료된 R1 아카이브 · 오프라인 전체 구간 · Fusion 입력 아님"],
        );
        return createDetailList(doc, fields);
    }

    // IDs keep their full text in the DOM (read aloud, copied, linked); CSS only truncates them.
    function row(evidence) {
        const tr = doc.createElement("tr");
        tr.classList.add("dashboard-evidence-row");
        const time = doc.createElement("time");
        time.setAttribute("datetime", evidence.timestamp);
        time.textContent = analysisTimestampLabel(evidence.timestamp, "시각 미확인");
        time.title = `UTC ${evidence.timestamp}`;
        const label = getEvidenceTypeLabel(evidence.evidence_type);
        const events = doc.createElement("ul");
        events.classList.add("dashboard-evidence-events");
        events.append(...evidence.events.map((reference) => eventReference(evidence, reference)));
        const key = evidence.evidence_id;
        const button = createExpandButton(doc, {
            key, label: `${label} · ${time.textContent}`, expanded: expanded.has(key), onToggle: toggle,
        });
        buttons.set(key, button);
        tr.append(
            cell(time),
            cell(createStackedText(doc, label, null, evidence.evidence_type)),
            cell(text("span", evidence.entity_id)),
            cell(createStackedText(doc, getSourceLayerLabel(evidence.derived_from_source_layer),
                getFeatureChannelLabel(evidence.feature_channel_group))),
            cell(events),
            cell(button),
        );
        return tr;
    }

    function renderRows() {
        buttons = new Map();
        nodes.list.replaceChildren(...shownItems.flatMap((evidence) => (expanded.has(evidence.evidence_id)
            ? [row(evidence), createDetailRow(doc, COLUMNS, details(evidence))] : [row(evidence)])));
    }

    function toggle(key) {
        if (expanded.has(key)) expanded.delete(key);
        else expanded.add(key);
        const previous = doc.activeElement;
        renderRows();
        restoreRowFocus(doc, buttons, key, previous);
    }

    // The focused Event link or detail toggle, captured before a read empties the list.
    function focusedControl() {
        const focused = doc.activeElement;
        if (!nodes.list.contains(focused)) return null;
        return focused?.dataset?.eventId || focusedRowKey(doc, nodes.list) ? focused : null;
    }

    function render({ message, items = [], archive = "", state = "error", total = null }, restoreFrom = null) {
        updateText(nodes.status, message);
        updateText(nodes.archive, archive);
        nodes.archive.hidden = archive === "";
        if (overview) updateText(overview, describeArchiveState(state, total));
        shownItems = items;
        renderRows();
        nodes.region.hidden = items.length === 0;
        // Return focus to the same Evidence/Event control only if the user has not moved since.
        const current = doc.activeElement;
        if (restoreFrom && (current === restoreFrom || current === null || current === doc.body)) {
            if (restoreFrom.dataset.rowKey) {
                buttons.get(restoreFrom.dataset.rowKey)?.focus({ preventScroll: true });
                return;
            }
            const replacement = Array.from(nodes.list.querySelectorAll(`.${EVENT_LINK_CLASS}`)).find((link) => (
                link.dataset.evidenceId === restoreFrom.dataset.evidenceId
                && link.dataset.eventId === restoreFrom.dataset.eventId
            ));
            replacement?.focus({ preventScroll: true });
        }
    }

    function load() {
        if (!enabled || runId === null) return Promise.resolve();
        if (pending !== null && shownRunId === runId) return pending;
        cancel();
        const target = runId;
        const current = version;
        shownRunId = target;
        const abort = new AbortController();
        request = abort;
        const restoreFrom = focusedControl();
        render({ message: EVIDENCE_MESSAGES.loading, state: "loading" });
        let timeout;
        const expired = new Promise((_, reject) => {
            timeout = setTimeoutImpl(() => {
                abort.abort();
                reject(new Error("Evidence read timeout"));
            }, REQUEST_TIMEOUT_MS);
        });
        const task = (async () => {
            try {
                const response = await Promise.race([
                    Promise.resolve().then(() => fetchImpl(buildEvidenceApiPath(target), {
                        signal: abort.signal, headers: { Accept: "application/json" }, cache: "no-store",
                    })),
                    expired,
                ]);
                if (!response.ok) {
                    let detail = null;
                    try {
                        detail = (await Promise.race([response.json(), expired]))?.detail ?? null;
                    } catch {
                        detail = null;
                    }
                    if (enabled && current === version) {
                        render(classifyEvidenceFailure(response.status, typeof detail === "string" ? detail : null));
                    }
                    return;
                }
                const payload = await Promise.race([response.json(), expired]);
                let model;
                try {
                    model = resolveEvidenceResponse(payload, target);
                } catch {
                    if (enabled && current === version) render({ message: EVIDENCE_MESSAGES.invalid, state: "invalid" });
                    return;
                }
                if (!enabled || current !== version) return;
                render({
                    message: model.message,
                    items: model.items,
                    state: model.state,
                    total: model.total,
                    archive: model.state === "published" || model.state === "empty"
                        ? describeVerifiedArchive(model) : "",
                }, restoreFrom);
            } catch {
                if (enabled && current === version) render({ message: EVIDENCE_MESSAGES.error, state: "error" });
            } finally {
                clearTimeoutImpl(timeout);
                if (current === version) {
                    request = null;
                    pending = null;
                }
            }
        })();
        pending = task;
        return task;
    }

    return {
        // Run change clears the previous Run's Evidence immediately; Entity changes do not re-read.
        select(nextRunId) {
            if (nextRunId === runId) return active && shownRunId !== runId ? load() : (pending ?? Promise.resolve());
            runId = nextRunId;
            cancel();
            shownRunId = null;
            expanded = new Set();
            render(runId === null
                ? { message: EVIDENCE_MESSAGES.idle, state: "idle" }
                : { message: EVIDENCE_MESSAGES.loading, state: "loading" });
            return active && runId !== null ? load() : Promise.resolve();
        },
        setActive(next) {
            active = next;
            return active && runId !== null && shownRunId !== runId ? load() : (pending ?? Promise.resolve());
        },
        refresh({ invalidatePending = false } = {}) {
            if (runId === null) return Promise.resolve();
            if (!invalidatePending && pending !== null && shownRunId === runId) return pending;
            cancel();
            shownRunId = null;
            return active ? load() : Promise.resolve();
        },
        stop() {
            enabled = false;
            cancel();
            shownRunId = null;
        },
        start() {
            enabled = true;
            return active && runId !== null ? load() : Promise.resolve();
        },
    };
}
