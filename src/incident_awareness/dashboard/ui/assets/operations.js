"use strict";

(() => {
    const RUNTIME_ENDPOINT = "/operations/runtime";
    const POLL_INTERVAL_MS = 5000;
    const LOADING_MESSAGE = "Runtime 정보를 불러오는 중입니다.";
    const EMPTY_MESSAGE = "표시할 Runtime 정보가 없습니다.";
    const ERROR_MESSAGE = "Runtime 정보를 불러오지 못했습니다.";

    const runtimeStatus = document.getElementById("runtime-status");
    let latestRuntimeItems = [];

    if (runtimeStatus === null) {
        return;
    }

    function updateRuntimeStatus(message) {
        if (runtimeStatus.textContent !== message) {
            runtimeStatus.textContent = message;
        }
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
        const response = await fetch(RUNTIME_ENDPOINT, {
            headers: {
                Accept: "application/json",
            },
            cache: "no-store",
        });

        if (!response.ok) {
            throw new Error("Runtime API request failed");
        }

        const payload = await response.json();
        validateRuntimePayload(payload);
        return payload.items;
    }

    async function pollRuntime() {
        try {
            const items = await fetchRuntimeItems();
            latestRuntimeItems = items;
            if (latestRuntimeItems.length === 0) {
                updateRuntimeStatus(EMPTY_MESSAGE);
            } else {
                updateRuntimeStatus(`Runtime ${latestRuntimeItems.length}건을 불러왔습니다.`);
            }
        } catch {
            updateRuntimeStatus(ERROR_MESSAGE);
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
