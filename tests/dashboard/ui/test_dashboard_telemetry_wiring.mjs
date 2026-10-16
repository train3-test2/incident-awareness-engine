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

function locateElement(html, id) {
    const ancestors = [];
    const voidTags = new Set(["meta", "link", "input", "br", "hr", "img"]);
    for (const match of html.matchAll(/<(\/?)([a-z][\w-]*)\b[^>]*>/gi)) {
        const [, closing, tag] = match;
        if (closing) {
            assert.equal(ancestors.pop()?.tag, tag, "Dashboard markup must be balanced");
        } else {
            if (match[0].includes(`id="${id}"`)) {
                return { markup: match[0], ancestors: [...ancestors] };
            }
            if (!voidTags.has(tag)) {
                ancestors.push({ tag, markup: match[0] });
            }
        }
    }
    assert.fail(`Dashboard element ${id} must exist`);
}

test("Telemetry live regions remain accessible when observation details are closed", async () => {
    // Given
    const [html, style] = await Promise.all([readFile(htmlPath, "utf8"), readFile(cssPath, "utf8")]);

    // When / Then
    for (const kind of ["throughput", "latency"]) {
        const region = locateElement(html, `telemetry-${kind}-status`);
        assert.match(region.markup, /role="status"/);
        assert.match(region.markup, /aria-live="polite"/);
        assert.match(region.markup, /aria-atomic="true"/);
        assert.match(region.markup, /dashboard-visually-hidden/);
        for (const element of [region, ...region.ancestors]) {
            assert.doesNotMatch(element.markup, /\s(?:hidden|inert)(?:\s|>|=)|aria-hidden="true"/);
        }
        assert.equal(region.ancestors.some((element) => element.tag === "details"), false);
        const detail = locateElement(html, `telemetry-${kind}-details`);
        const disclosure = detail.ancestors.find((element) => element.tag === "details");
        assert.ok(disclosure, "Detailed coverage must stay in a disclosure");
        assert.doesNotMatch(disclosure.markup, /\sopen(?:\s|>|=)/);
    }
    const hiddenRule = style.split(".dashboard-visually-hidden {")[1].split("}")[0];
    assert.match(hiddenRule, /position: absolute/);
    assert.match(hiddenRule, /clip-path: inset\(50%\)/);
    assert.doesNotMatch(hiddenRule, /display:\s*none|visibility:\s*hidden|content-visibility:\s*hidden/);
});

test("The four KPI regions share a panel with dividers and insights state missing instrumentation explicitly", async () => {
    // Given
    const [html, style] = await Promise.all([readFile(htmlPath, "utf8"), readFile(cssPath, "utf8")]);

    // When / Then
    for (const id of ["system-status-value", "active-runtime-run", "latest-runtime-updated"]) {
        const element = locateElement(html, id);
        assert.ok(element.ancestors.some((ancestor) => ancestor.markup.includes("dashboard-command")));
    }
    assert.equal((html.match(/class="dashboard-kpi(?: dashboard-kpi--system)?"/g) ?? []).length, 4);
    const gridRule = style.split(".dashboard-kpi-grid {")[1].split("}")[0];
    const kpiRule = style.split(".dashboard-kpi {")[1].split("}")[0];
    assert.match(gridRule, /gap: 0;/);
    assert.match(kpiRule, /border-left: 1px solid/);
    assert.match(kpiRule, /box-shadow: none/);
    assert.equal((html.match(/<strong>계측 미연결<\/strong>/g) ?? []).length, 4);
});

test("Concise cards keep technical definitions and scope in native keyboard-accessible disclosures", async () => {
    // Given
    const html = await readFile(htmlPath, "utf8");
    // When / Then
    const context = locateElement(html, "pipeline-stage-context");
    assert.ok(context.ancestors.some((ancestor) => ancestor.tag === "details"));
    assert.doesNotMatch(context.markup, /hidden|aria-hidden/);
    for (const kind of ["throughput", "latency"]) {
        const frame = locateElement(html, `telemetry-${kind}-chart`);
        assert.match(frame.markup, /tabindex="0"/);
        assert.match(frame.markup, /role="region"/);
        assert.match(frame.markup, /aria-label="[^"]+스크롤"/);
    }
    for (const definition of [
        "지속적 외부 EDR ingest rate가 아닙니다", "전체 End-to-End 판단 지연이나 전체 Pipeline 소요시간이 아닙니다",
        "미관측은 실측 0과 다릅니다", "실행 완료만으로 모든 시스템이 정상이라고 판단하지 않습니다",
        "기술적 판정 시각 t_e는 조직 인지 시각 t_h가 아닙니다",
    ]) {
        assert.ok(html.includes(definition));
        const beforeDefinition = html.slice(0, html.indexOf(definition));
        assert.ok(beforeDefinition.lastIndexOf("<details") > beforeDefinition.lastIndexOf("</details>"));
    }
    assert.match(html, /자동 갱신 · 5초/);
    assert.equal((html.match(/<strong>계측 미연결<\/strong>/g) ?? []).length, 4);
});
