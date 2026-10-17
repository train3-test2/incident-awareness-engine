// Evidence tab reads for the selected Run only: lazy (on tab activation), deduplicated per Run,
// no polling timer, and stale responses are discarded by version.
import {
    EVIDENCE_MESSAGES,
    buildEvidenceApiPath,
    classifyEvidenceFailure,
    describeVerifiedArchive,
    getEvidenceTypeLabel,
    getFeatureChannelLabel,
    getSourceLayerLabel,
    resolveEvidenceResponse,
} from "./dashboard-evidence-contract.mjs";
import { buildEventDetailViewPath } from "./event-detail-contract.mjs";

const REQUEST_TIMEOUT_MS = 10000;
const EVENT_LINK_CLASS = "dashboard-evidence-event-link";
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
    let enabled = true;
    let active = false;
    let runId = null;
    let shownRunId = null; // Run whose result is shown or being read.
    let version = 0;
    let request = null;
    let pending = null;

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
            unstored.title = `${reference.event_id} · 이 Run에 저장된 Event가 없어 링크하지 않습니다.`;
            item.append(unstored);
        }
        return item;
    }

    // IDs keep their full text in the DOM (read aloud, copied, linked); CSS only truncates them.
    function row(evidence) {
        const tr = doc.createElement("tr");
        const type = cell(text("span", getEvidenceTypeLabel(evidence.evidence_type)));
        type.title = evidence.evidence_type;
        if (evidence.policy) {
            const policy = text("small", `· 정책 ${evidence.policy.version} · ${evidence.policy.policy_id}`);
            policy.title = `${evidence.policy.policy_id} ${evidence.policy.version} · config_hash ${evidence.policy.config_hash}`;
            type.append(policy);
        }
        if (evidence.attack_technique_ids.length) {
            type.append(text("small", `· ATT&CK ${evidence.attack_technique_ids.join(", ")}`));
        }
        if (evidence.withheld_field_count) {
            type.append(text("small", `· 비공개 필드 ${evidence.withheld_field_count}개`));
        }
        const time = doc.createElement("time");
        time.setAttribute("datetime", evidence.timestamp);
        time.textContent = evidence.timestamp.replace("T", " ").replace("Z", "");
        const events = doc.createElement("ul");
        events.classList.add("dashboard-evidence-events");
        events.append(...evidence.events.map((reference) => eventReference(evidence, reference)));
        const id = text("code", evidence.evidence_id);
        id.title = evidence.evidence_id;
        tr.append(
            cell(id),
            type,
            cell(time),
            cell(text("span", evidence.entity_id)),
            cell(text("span", getSourceLayerLabel(evidence.derived_from_source_layer))),
            cell(text("span", getFeatureChannelLabel(evidence.feature_channel_group))),
            cell(events),
            cell(text("span", evidence.extractor_version)),
        );
        return tr;
    }

    // The focused Event link, captured before a read empties the list.
    function focusedLink() {
        const focused = doc.activeElement;
        return nodes.list.contains(focused) && focused?.dataset?.eventId ? focused : null;
    }

    function render({ message, items = [], archive = "" }, restoreFrom = null) {
        updateText(nodes.status, message);
        updateText(nodes.archive, archive);
        nodes.archive.hidden = archive === "";
        nodes.list.replaceChildren(...items.map(row));
        nodes.region.hidden = items.length === 0;
        // Return focus to the same Evidence/Event link only if the user has not moved since.
        const current = doc.activeElement;
        if (restoreFrom && (current === restoreFrom || current === null || current === doc.body)) {
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
        const restoreFrom = focusedLink();
        render({ message: EVIDENCE_MESSAGES.loading });
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
                    if (enabled && current === version) render({ message: EVIDENCE_MESSAGES.invalid });
                    return;
                }
                if (!enabled || current !== version) return;
                render({
                    message: model.message,
                    items: model.items,
                    archive: model.state === "published" || model.state === "empty"
                        ? describeVerifiedArchive(model) : "",
                }, restoreFrom);
            } catch {
                if (enabled && current === version) render({ message: EVIDENCE_MESSAGES.error });
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
            render({ message: runId === null ? EVIDENCE_MESSAGES.idle : EVIDENCE_MESSAGES.loading });
            return active && runId !== null ? load() : Promise.resolve();
        },
        setActive(next) {
            active = next;
            return active && runId !== null && shownRunId !== runId ? load() : (pending ?? Promise.resolve());
        },
        refresh() {
            if (runId === null) return Promise.resolve();
            if (pending !== null && shownRunId === runId) return pending;
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
