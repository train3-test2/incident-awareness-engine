// Pure Fusion Engine presentation, path, and query-state helpers.

const QUERY_MESSAGES = new Map([
    ["loading", "Fusion Engine 정보를 불러오는 중입니다."],
    ["success", "Fusion Engine 정보를 불러왔습니다."],
    ["not_found", "Run을 찾을 수 없습니다."],
    ["error", "Fusion Engine 정보를 불러오지 못했습니다."],
]);

function requireRunId(runId) {
    if (typeof runId !== "string") {
        throw new TypeError("runId must be a string");
    }
    if (!runId.trim()) {
        throw new RangeError("runId must not be blank");
    }
    return runId;
}

function requireObjectOrNull(value, name) {
    if (value !== null && (typeof value !== "object" || Array.isArray(value))) {
        throw new TypeError(`${name} must be an object or null`);
    }
}

function getQueryMessage(queryState) {
    const message = QUERY_MESSAGES.get(queryState);
    if (message === undefined) {
        throw new RangeError(`Unknown Fusion Engine query state: ${queryState}`);
    }
    return message;
}

function requireFiniteNumber(value, name) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new TypeError(`${name} must be a finite number`);
    }
    return value;
}

function requireChartDimensions(dimensions) {
    if (dimensions === null || typeof dimensions !== "object" || Array.isArray(dimensions)) {
        throw new TypeError("Score trajectory dimensions must be an object");
    }
    const width = requireFiniteNumber(dimensions.width, "dimensions.width");
    const height = requireFiniteNumber(dimensions.height, "dimensions.height");
    const padding = dimensions.padding;
    if (padding === null || typeof padding !== "object" || Array.isArray(padding)) {
        throw new TypeError("Score trajectory dimensions.padding must be an object");
    }
    const top = requireFiniteNumber(padding.top, "dimensions.padding.top");
    const right = requireFiniteNumber(padding.right, "dimensions.padding.right");
    const bottom = requireFiniteNumber(padding.bottom, "dimensions.padding.bottom");
    const left = requireFiniteNumber(padding.left, "dimensions.padding.left");
    if (
        width <= 0
        || height <= 0
        || top < 0
        || right < 0
        || bottom < 0
        || left < 0
        || left + right >= width
        || top + bottom >= height
    ) {
        throw new RangeError("Score trajectory dimensions must define a positive plot area");
    }
    return { width, height, padding: { top, right, bottom, left } };
}

function requireTracePoint(point, index) {
    if (point === null || typeof point !== "object" || Array.isArray(point)) {
        throw new TypeError(`Stopping Trace point ${index} must be an object`);
    }
    const timestamp = Date.parse(point.timestamp);
    if (!Number.isFinite(timestamp)) {
        throw new RangeError(`Stopping Trace point ${index} timestamp must be valid`);
    }
    requireFiniteNumber(point.score, `Stopping Trace point ${index} score`);
    return timestamp;
}

export function buildScoreTrajectoryModel(trace, runtimeConfig, dimensions) {
    if (trace === null || typeof trace !== "object" || Array.isArray(trace)) {
        throw new TypeError("Stopping Trace must be an object");
    }
    if (!Array.isArray(trace.points)) {
        throw new TypeError("Stopping Trace points must be an array");
    }
    if (
        runtimeConfig !== null
        && (typeof runtimeConfig !== "object" || Array.isArray(runtimeConfig))
    ) {
        throw new TypeError("Runtime Config Snapshot must be an object or null");
    }

    const chart = requireChartDimensions(dimensions);
    const plot = {
        left: chart.padding.left,
        top: chart.padding.top,
        right: chart.width - chart.padding.right,
        bottom: chart.height - chart.padding.bottom,
        width: chart.width - chart.padding.left - chart.padding.right,
        height: chart.height - chart.padding.top - chart.padding.bottom,
    };
    const timestamps = trace.points.map((point, index) => requireTracePoint(point, index));
    const firstTimestamp = timestamps[0] ?? null;
    const lastTimestamp = timestamps.at(-1) ?? null;
    if (
        timestamps.length > 1
        && (lastTimestamp === null
            || firstTimestamp === null
            || lastTimestamp <= firstTimestamp)
    ) {
        throw new RangeError("Stopping Trace timestamps must be strictly increasing");
    }

    const points = trace.points.map((point, index) => {
        const x = timestamps.length === 1
            ? plot.left + plot.width / 2
            : plot.left
                + ((timestamps[index] - firstTimestamp) / (lastTimestamp - firstTimestamp))
                    * plot.width;
        const y = plot.top + (1 - point.score) * plot.height;
        return {
            timestamp: point.timestamp,
            score: point.score,
            persistence_count: point.persistence_count,
            policy_state: point.policy_state,
            x,
            y,
        };
    });

    let thresholds = [];
    if (runtimeConfig !== null) {
        const stopping = runtimeConfig.stopping;
        if (stopping === null || typeof stopping !== "object" || Array.isArray(stopping)) {
            throw new TypeError("Runtime Config stopping must be an object");
        }
        const thresholdOn = requireFiniteNumber(stopping.threshold_on, "stopping.threshold_on");
        const thresholdOff = requireFiniteNumber(
            stopping.threshold_off,
            "stopping.threshold_off",
        );
        thresholds = [
            {
                kind: "on",
                label: "T_on",
                value: thresholdOn,
                y: plot.top + (1 - thresholdOn) * plot.height,
            },
            {
                kind: "off",
                label: "T_off",
                value: thresholdOff,
                y: plot.top + (1 - thresholdOff) * plot.height,
            },
        ];
    }

    return {
        width: chart.width,
        height: chart.height,
        plot,
        points,
        thresholds,
        yTicks: [
            { value: 1, label: "1.0", y: plot.top },
            { value: 0.5, label: "0.5", y: plot.top + plot.height / 2 },
            { value: 0, label: "0.0", y: plot.bottom },
        ],
    };
}

export function buildFusionEngineApiPath(runId) {
    return `/runs/${encodeURIComponent(requireRunId(runId))}/fusion-engine`;
}

export function buildFusionEngineViewPath(runId) {
    return `/dashboard/runs/${encodeURIComponent(requireRunId(runId))}/fusion-engine`;
}

export function extractFusionEngineRunIdFromPathname(pathname) {
    if (typeof pathname !== "string") {
        return null;
    }
    const match = /^\/dashboard\/runs\/([^/]+)\/fusion-engine$/.exec(pathname);
    if (match === null) {
        return null;
    }
    try {
        const runId = decodeURIComponent(match[1]);
        return runId.trim() ? runId : null;
    } catch {
        return null;
    }
}

export function resolveFusionEngineQueryState(previousState, result) {
    if (
        previousState !== null
        && (typeof previousState !== "object" || Array.isArray(previousState))
    ) {
        throw new TypeError("Previous Fusion Engine state must be an object or null");
    }
    if (result === null || typeof result !== "object" || Array.isArray(result)) {
        throw new TypeError("Fusion Engine query result must be an object");
    }
    if (result.kind === "loading") {
        return {
            queryState: "loading",
            payload: null,
            message: getQueryMessage("loading"),
        };
    }
    if (result.kind === "success") {
        const payload = result.payload;
        if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
            throw new TypeError("Fusion Engine payload must be an object");
        }
        if (payload.run === null || typeof payload.run !== "object" || Array.isArray(payload.run)) {
            throw new TypeError("Fusion Engine run must be an object");
        }
        requireObjectOrNull(payload.current_decision, "Fusion Engine current_decision");
        requireObjectOrNull(payload.fusion_result, "Fusion Engine fusion_result");
        requireObjectOrNull(payload.stopping_trace, "Fusion Engine stopping_trace");
        requireObjectOrNull(
            payload.runtime_config_snapshot,
            "Fusion Engine runtime_config_snapshot",
        );
        return {
            queryState: "success",
            payload,
            message: getQueryMessage("success"),
        };
    }
    if (result.kind === "not_found") {
        return {
            queryState: "not_found",
            payload: null,
            message: getQueryMessage("not_found"),
        };
    }
    if (result.kind === "error") {
        return {
            queryState: "error",
            payload: null,
            message: getQueryMessage("error"),
        };
    }
    throw new RangeError(`Unknown Fusion Engine query result kind: ${result.kind}`);
}
