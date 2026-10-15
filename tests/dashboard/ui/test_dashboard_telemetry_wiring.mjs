import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../../", import.meta.url);
const htmlPath = new URL("src/incident_awareness/dashboard/ui/dashboard.html", root);
const jsPath = new URL("src/incident_awareness/dashboard/ui/assets/dashboard.js", root);
const cssPath = new URL("src/incident_awareness/dashboard/ui/assets/dashboard.css", root);

test("Issue #289 panels use real Telemetry controller and retain existing Dashboard polling", async () => {
    // Given
    const [html, script, style] = await Promise.all([
        readFile(htmlPath, "utf8"),
        readFile(jsPath, "utf8"),
        readFile(cssPath, "utf8"),
    ]);

    // When
    const wiredIds = [
        "telemetry-throughput-chart", "telemetry-throughput-summary", "telemetry-throughput-details",
        "telemetry-throughput-status", "telemetry-throughput-note",
        "telemetry-latency-chart", "telemetry-latency-summary", "telemetry-latency-details",
        "telemetry-latency-status", "telemetry-latency-note",
    ];

    // Then
    assert.ok(wiredIds.every((id) => html.includes(`id="${id}"`)));
    assert.match(script, /from "\.\/dashboard-telemetry-controller\.mjs"/);
    assert.match(script, /createDashboardTelemetryController\(document\)/);
    assert.match(script, /void telemetryController\.start\(\)/);
    assert.match(script, /telemetryController\.stop\(\)/);
    assert.match(script, /startRuntimePolling\(\)/);
    assert.match(style, /Issue #289: observed Pipeline Telemetry charts/);
});
