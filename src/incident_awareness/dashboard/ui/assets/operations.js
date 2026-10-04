"use strict";

(() => {
    const RUNTIME_ENDPOINT = "/operations/runtime";
    const POLL_INTERVAL_MS = 5000;
    // Upper bound for one Runtime request; separate from the delay between polls.
    const RUNTIME_REQUEST_TIMEOUT_MS = 10000;
    const LOADING_MESSAGE = "Runtime 정보를 불러오는 중입니다.";
    const EMPTY_MESSAGE = "표시할 Runtime 정보가 없습니다.";
    const ERROR_MESSAGE = "Runtime 정보를 불러오지 못했습니다.";
    const NOT_APPLICABLE = "-";
    const RUNNING_STATUS_LABEL = "실행 중(마지막 보고)";
    const STAGE_LABELS = new Map([
        ["artifact_validation", "입력 검증"],
        ["normalization", "이벤트 처리"],
        ["fusion", "증거 누적 판단"],
        ["fast_handoff", "즉시 판단 연계"],
        ["hybrid", "통합 판단"],
        ["persistence", "결과 저장"],
    ]);

    const runtimeStatus = document.getElementById("runtime-status");
    const runtimeList = document.getElementById("runtime-list");
    let latestRuntimeItems = [];

    if (runtimeStatus === null || runtimeList === null) {
        return;
    }

    function updateRuntimeStatus(message) {
        if (runtimeStatus.textContent !== message) {
            runtimeStatus.textContent = message;
        }
    }

    function displayValue(value) {
        if (value === null || value === undefined) {
            return NOT_APPLICABLE;
        }
        return String(value);
    }

    function getStageLabel(stage) {
        if (stage === null || stage === undefined) {
            return NOT_APPLICABLE;
        }
        return STAGE_LABELS.get(stage) ?? String(stage);
    }

    function formatTimestamp(value) {
        if (value === null || value === undefined) {
            return NOT_APPLICABLE;
        }

        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return String(value);
        }
        return date.toLocaleString("ko-KR", { timeZoneName: "short" });
    }

    // Presentation only: the persisted status stays authoritative. A stale snapshot keeps its
    // last reported running status but lacks recent telemetry, so current execution is unknown.
    // When the latest query failed, retained items cannot vouch for current telemetry freshness.
    function getRuntimeStatePresentation(runtime, telemetryAvailable) {
        if (runtime.status === "running") {
            if (!telemetryAvailable) {
                return {
                    modifiers: ["running", "telemetry-unavailable"],
                    statusLabel: RUNNING_STATUS_LABEL,
                    telemetryLabel: "확인 불가 (조회 실패)",
                    livenessLabel: "확인 불가",
                };
            }
            if (runtime.is_stale === true) {
                return {
                    modifiers: ["running", "stale"],
                    statusLabel: RUNNING_STATUS_LABEL,
                    telemetryLabel: "오래됨",
                    livenessLabel: "확인 불가",
                };
            }
            return {
                modifiers: ["running"],
                statusLabel: RUNNING_STATUS_LABEL,
                telemetryLabel: "최근 갱신",
                livenessLabel: null,
            };
        }
        if (runtime.status === "completed") {
            return {
                modifiers: ["completed"],
                statusLabel: "완료",
                telemetryLabel: NOT_APPLICABLE,
                livenessLabel: null,
            };
        }
        if (runtime.status === "failed") {
            return {
                modifiers: ["failed"],
                statusLabel: "실패",
                telemetryLabel: NOT_APPLICABLE,
                livenessLabel: null,
            };
        }
        return {
            modifiers: [],
            statusLabel: displayValue(runtime.status),
            telemetryLabel: NOT_APPLICABLE,
            livenessLabel: null,
        };
    }

    function createField(label, value) {
        const field = document.createElement("div");
        field.classList.add("runtime-field");

        const term = document.createElement("dt");
        term.classList.add("runtime-field__label");
        term.textContent = label;

        const description = document.createElement("dd");
        description.classList.add("runtime-field__value");
        description.textContent = value;

        field.append(term, description);
        return field;
    }

    function createRuntimeCard(runtime, telemetryAvailable) {
        const presentation = getRuntimeStatePresentation(runtime, telemetryAvailable);

        const card = document.createElement("article");
        card.classList.add("runtime-card");
        for (const modifier of presentation.modifiers) {
            card.classList.add(`runtime-card--${modifier}`);
        }

        const heading = document.createElement("h3");
        heading.classList.add("runtime-card__title");
        heading.textContent = displayValue(runtime.run_id);

        const fields = document.createElement("dl");
        fields.classList.add("runtime-card__fields");
        fields.append(
            createField("Entity ID", displayValue(runtime.entity_id)),
            createField("상태", presentation.statusLabel),
            createField("Telemetry", presentation.telemetryLabel),
        );
        if (presentation.livenessLabel !== null) {
            fields.append(createField("현재 실행 여부", presentation.livenessLabel));
        }
        fields.append(
            createField("현재 단계", getStageLabel(runtime.current_stage)),
            createField(
                "진행",
                `${displayValue(runtime.normalization_processed_count)} / `
                    + `${displayValue(runtime.input_total)} 처리`,
            ),
            createField("남은 항목", displayValue(runtime.remaining_count)),
            createField("시작", formatTimestamp(runtime.started_at)),
            createField("단계 시작", formatTimestamp(runtime.stage_started_at)),
            createField("마지막 갱신", formatTimestamp(runtime.updated_at)),
            createField("완료", formatTimestamp(runtime.completed_at)),
            createField("실패 단계", getStageLabel(runtime.failed_stage)),
        );

        card.append(heading, fields);
        return card;
    }

    // Keeps the API order; cards are built before the list is replaced so a rendering
    // failure leaves the last successful list untouched.
    function renderRuntimeItems(items, telemetryAvailable) {
        const cards = items.map((runtime) => createRuntimeCard(runtime, telemetryAvailable));
        runtimeList.replaceChildren(...cards);
    }

    function validateRuntimePayload(payload) {
        if (
            payload === null
            || typeof payload !== "object"
            || Array.isArray(payload)
            || !Array.isArray(payload.items)
        ) {
            throw new Error("Runtime API response is invalid");
        }
    }

    async function fetchRuntimeItems() {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), RUNTIME_REQUEST_TIMEOUT_MS);

        try {
            const response = await fetch(RUNTIME_ENDPOINT, {
                headers: {
                    Accept: "application/json",
                },
                cache: "no-store",
                signal: controller.signal,
            });

            if (!response.ok) {
                throw new Error("Runtime API request failed");
            }

            const payload = await response.json();
            validateRuntimePayload(payload);
            return payload.items;
        } finally {
            clearTimeout(timeoutId);
        }
    }

    async function pollRuntime() {
        try {
            const items = await fetchRuntimeItems();
            renderRuntimeItems(items, true);
            latestRuntimeItems = items;
            if (latestRuntimeItems.length === 0) {
                updateRuntimeStatus(EMPTY_MESSAGE);
            } else {
                updateRuntimeStatus(`Runtime ${latestRuntimeItems.length}건을 불러왔습니다.`);
            }
        } catch {
            updateRuntimeStatus(ERROR_MESSAGE);
            renderRuntimeItems(latestRuntimeItems, false);
        } finally {
            setTimeout(pollRuntime, POLL_INTERVAL_MS);
        }
    }

    function startRuntimePolling() {
        updateRuntimeStatus(LOADING_MESSAGE);
        void pollRuntime();
    }

    startRuntimePolling();
})();
