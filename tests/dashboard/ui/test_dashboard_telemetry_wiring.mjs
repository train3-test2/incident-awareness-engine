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

function assertInsightScope(html) {
    assert.equal((html.match(/class="dashboard-insight-cell(?: dashboard-processing-observation)?"/g) ?? []).length, 4);
    assert.match(html, /<strong id="insight-bottleneck-state">미계측<\/strong>/);
    assert.match(html, /<strong id="insight-sla-state">기준 미설정<\/strong>/);
    assert.match(html, /<strong id="insight-queue-state">미계측<\/strong>/);
    assert.match(html, /<h3 id="processing-observation-heading">최근 처리 관측<\/h3>/);
    assert.doesNotMatch(html, /최신 이벤트 수신/);
}

test("The four KPI regions share a panel and unsupported Insight metrics stay unmeasured", async () => {
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
    assertInsightScope(html);
});

test("Concise cards expose Pipeline scope while keeping technical definitions in native disclosures", async () => {
    // Given
    const html = await readFile(htmlPath, "utf8");
    // When / Then
    const context = locateElement(html, "pipeline-stage-context");
    assert.equal(context.ancestors.some((ancestor) => ancestor.tag === "details"), false);
    assert.ok(context.ancestors.some((ancestor) => ancestor.markup.includes("dashboard-pipeline-section")));
    for (const element of [context, ...context.ancestors]) {
        assert.doesNotMatch(element.markup, /\s(?:hidden|inert)(?:\s|>|=)|aria-hidden="true"|dashboard-visually-hidden/);
    }
    assert.equal((html.match(/id="pipeline-stage-context"/g) ?? []).length, 1);
    assert.ok(html.indexOf('id="pipeline-stage-context"') < html.indexOf('id="pipeline-stage-list"'));
    const runtimeDetails = html.match(/<details class="dashboard-runtime-disclosure">([\s\S]*?)<\/details>/)[1];
    assert.match(runtimeDetails, /API 순서를 유지합니다\. Runtime은 Run ID와 Entity ID 조합으로 선택하며/);
    assert.match(runtimeDetails, /저장 분석 결과는 run_id 기준으로 조회합니다/);
    assert.match(runtimeDetails, /id="runtime-summary-list"/);
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
    assertInsightScope(html);
});

test("Processing observation is optional in the shared Controller and reuses existing Telemetry announcements", async () => {
    // Given
    const [html, source] = await Promise.all([
        readFile(htmlPath, "utf8"),
        readFile(new URL("src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-controller.mjs", root), "utf8"),
    ]);

    // When
    const state = locateElement(html, "processing-observation-state");
    const time = locateElement(html, "processing-observation-time");
    const details = locateElement(html, "processing-observation-details");
    const group = state.ancestors.find((element) => element.markup.includes("dashboard-processing-observation"));
    const required = source.split("const REQUIRED_IDS = Object.freeze({")[1].split("});")[0];

    // Then
    assert.match(group.markup, /role="group"/);
    assert.match(group.markup, /aria-labelledby="processing-observation-heading"/);
    assert.match(group.markup, /aria-describedby="processing-observation-details telemetry-throughput-status"/);
    for (const element of [state, time, details, ...state.ancestors]) {
        assert.doesNotMatch(element.markup, /aria-live=|role="status"/);
    }
    assert.match(details.markup, /dashboard-visually-hidden/);
    assert.equal(time.ancestors.some((element) => element.tag === "details"), false);
    assert.doesNotMatch(required, /processing-observation/);
    assert.equal((source.match(/fetchImpl\(TELEMETRY_ENDPOINT/g) ?? []).length, 1);
    assert.match(source, /renderProcessingObservation\(observationNodes, model\)/);
    assert.match(source, /renderProcessingObservation\(observationNodes, null, "error"\)/);
    for (const definition of [
        "Event 최초 수신 시각이나 시스템 가동 여부가 아닙니다", "시각은 UTC로 표시합니다",
        "current_stage는 병목 근거가 아니고", "SQS 큐 깊이가 아닙니다", "E2E SLA로 사용하지 않습니다",
    ]) assert.ok(html.includes(definition));
});

test("Unsupported Insights expose metric-specific scope outside closed help without claiming measurements", async () => {
    // Given
    const html = await readFile(htmlPath, "utf8");
    const metrics = [
        ["bottleneck", "병목 단계", "미계측", "단계별 소요시간 미수집"],
        ["sla", "SLA 경고 여부", "기준 미설정", "경고/위반 규칙이 정의되지 않아 평가하지 않습니다"],
        ["queue", "큐 적체 위험", "미계측", "미계측은 대기 0건이나 위험 없음이라는 뜻이 아닙니다"],
    ];

    // When / Then
    for (const [metric, title, label, reason] of metrics) {
        const state = locateElement(html, `insight-${metric}-state`);
        const scope = locateElement(html, `insight-${metric}-scope`);
        const group = state.ancestors.find((element) => element.markup.includes("dashboard-insight-cell"));
        assert.match(group.markup, /role="group"/);
        assert.ok(group.markup.includes(`aria-labelledby="insight-${metric}-heading"`));
        assert.ok(group.markup.includes(`aria-describedby="insight-${metric}-scope"`));
        assert.ok(html.includes(`<h3 id="insight-${metric}-heading">${title}</h3>`));
        assert.ok(html.includes(`<strong id="insight-${metric}-state">${label}</strong>`));
        assert.match(scope.markup, /dashboard-visually-hidden/);
        assert.equal(scope.ancestors.some((element) => element.tag === "details"), false);
        for (const element of [state, scope, ...state.ancestors]) {
            assert.doesNotMatch(element.markup, /\s(?:hidden|inert)(?:\s|>|=)|aria-hidden="true"|aria-live=|role="status"/);
        }
        assert.equal((html.match(new RegExp(`id="insight-${metric}-scope"`, "g")) ?? []).length, 1);
        assert.ok(html.includes(reason));
    }
    assertInsightScope(html);
});

test("Insight help explains source limits and distinguishes missing contracts from Telemetry query errors", async () => {
    // Given
    const html = await readFile(htmlPath, "utf8");
    const help = html.match(/<summary>인사이트 계측 안내<\/summary>([\s\S]*?)<\/details>/)[1];

    // When / Then
    for (const explanation of [
        "동일 Execution 내 비교가 불가능합니다", "기준 미설정은 정상 판정이 아닙니다",
        "표시 기준이며 SLA가 아닙니다", "24h 상태도 Pipeline SLA로 전용하지 않습니다",
        "archive 발행 재시도 기록은 현재 큐 대기량이 아닙니다", "안전/위험 판정을 제공하지 않습니다",
        "보고된 Execution Attempt · 최근 5분, 요약 최근 60초", "선택 Run 전용 지표나 시스템 전체 계측이 아닙니다",
        "조회 실패는 해당 관측 카드에", "미계측/기준 미설정과 구분합니다",
    ]) assert.ok(help.includes(explanation), explanation);
    assert.match(help, /<strong>병목 단계:<\/strong>/);
    assert.match(help, /<strong>SLA 경고 여부:<\/strong>/);
    assert.match(help, /<strong>큐 적체 위험:<\/strong>/);
});

test("Time guidance positions one wrapper while paragraphs remain in document flow", async () => {
    // Given
    const [html, style] = await Promise.all([readFile(htmlPath, "utf8"), readFile(cssPath, "utf8")]);
    // When
    const content = html.match(/<div class="dashboard-time-note__content">([\s\S]*?)<\/div>/)[1];
    const wrapperRule = style.split(".dashboard-time-note__content {")[1].split("}")[0];
    const paragraphRule = style.split(".dashboard-time-note p {")[1].split("}")[0];
    const mobileRule = style.split(".dashboard-time-note[open] .dashboard-time-note__content {")[1].split("}")[0];
    // Then
    assert.equal((content.match(/<p(?:\s|>)/g) ?? []).length, 2);
    assert.match(content, /저장된 Runtime 보고와 Run 분석 결과/);
    assert.match(content, /Runtime updated_at은 마지막 저장 보고 시각/);
    assert.match(content, /전체 실행 통계가 아닙니다/);
    assert.match(wrapperRule, /position: absolute/);
    assert.match(wrapperRule, /overflow-y: auto/);
    assert.match(wrapperRule, /width: min\(28rem, calc\(100vw - 2rem\)\)/);
    assert.doesNotMatch(paragraphRule, /position: absolute|top:|right:/);
    assert.match(style, /\.dashboard-time-note p \+ p\s*\{\s*margin-top: var\(--shell-space-3\)/);
    assert.match(mobileRule, /position: static/);
    assert.match(mobileRule, /max-height: none/);
    assert.match(html, /<details class="dashboard-time-note">\s*<summary>표시 기준 및 상태 안내<\/summary>/);
});

test("Asymmetric independent columns retain side summaries and legends outside scrolling plots", async () => {
    // Given
    const [html, style, renderer] = await Promise.all([
        readFile(htmlPath, "utf8"), readFile(cssPath, "utf8"),
        readFile(new URL("src/incident_awareness/dashboard/ui/assets/dashboard-telemetry-chart.mjs", root), "utf8"),
    ]);
    // When / Then
    for (const [id, column] of [
        ["pipeline-heading", "primary"], ["throughput-heading", "primary"], ["runs-heading", "primary"],
        ["insights-heading", "secondary"], ["latency-heading", "secondary"], ["workflow-heading", "secondary"],
    ]) {
        const heading = locateElement(html, id);
        assert.ok(heading.ancestors.some((ancestor) => ancestor.markup.includes(`dashboard-monitor-column--${column}`)));
    }
    const grid = style.split(".dashboard-monitor-grid {")[1].split("}")[0];
    assert.match(grid, /grid-template-columns: minmax\(0, 906fr\) minmax\(0, 548fr\)/);
    assert.doesNotMatch(html, /class="dashboard-telemetry-grid"/);
    const column = style.split(".dashboard-monitor-column {")[1].split("}")[0];
    assert.match(column, /flex-direction: column/);
    const metrics = style.split(".dashboard-metric-layout {")[1].split("}")[0];
    assert.match(metrics, /grid-template-columns: minmax\(0, 1fr\) 8\.75rem/);
    for (const kind of ["throughput", "latency"]) {
        const note = locateElement(html, `telemetry-${kind}-note`);
        assert.ok(note.ancestors.some((ancestor) => ancestor.tag === "summary"), "Quality remains visible when technical details are closed");
    }
    assert.match(renderer, /figure\.append\(plot\)/);
    assert.match(renderer, /figure\.append\(legend\)/);
    assert.doesNotMatch(renderer, /plot\.append\(legend\)/);
    assert.match(style, /\.dashboard-telemetry-chart__plot\s*\{[^}]*overflow-x: auto/);
    const sprite = await readFile(new URL("src/incident_awareness/dashboard/ui/assets/dashboard-icons.svg", root), "utf8");
    for (const name of ["artifact_validation", "normalization", "fusion", "fast_handoff", "hybrid", "persistence"]) {
        assert.ok(sprite.includes(`id="${name}"`));
    }
    assert.equal((html.match(/href="\/dashboard-assets\/dashboard-icons\.svg#/g) ?? []).length, 13);
    assert.doesNotMatch(html, />[◈▷◷↻⇥↧≋]</);
});

test("Compact Replay keeps analysis tools reachable and retains complete semantic content", async () => {
    // Given
    const [html, style] = await Promise.all([readFile(htmlPath, "utf8"), readFile(cssPath, "utf8")]);
    // When / Then
    for (const id of ["selected-run-refresh", "selected-run-detail-link", "selected-run-fusion-link"]) {
        const tool = locateElement(html, id);
        assert.ok(tool.ancestors.some((ancestor) => ancestor.markup.includes('class="dashboard-detail-context"')));
        assert.ok(tool.ancestors.some((ancestor) => ancestor.markup.includes('class="dashboard-detail-context__content"')));
    }
    for (const id of ["dashboard-prev-run", "dashboard-next-run", "selected-run-heading", "dashboard-tab-replay"]) {
        assert.equal(locateElement(html, id).ancestors.some((ancestor) => ancestor.tag === "details"), false);
    }
    for (const id of ["selected-run-chart", "decision-timeline-list", "event-type-summary"]) {
        assert.equal(locateElement(html, id).ancestors.some((ancestor) => ancestor.tag === "details"), false);
    }
    assert.match(style, /\.dashboard-analysis\s*\{[^}]*min-height: 14\.4375rem/);
    assert.doesNotMatch(style, /\.dashboard-analysis\s*\{[^}]*\n\s*(?:height|max-height):/);
    assert.match(style, /\.dashboard-detail-context__content\s*\{[^}]*overflow-y: auto/);
    assert.match(style, /\.dashboard-detail-context__content\s*\{[^}]*position: static/);
    assert.match(html, /aria-label="연관 Event 집계 기준"/);
});

test("Dashboard state text tokens keep readable contrast without remote font dependencies", async () => {
    // Given
    const style = await readFile(cssPath, "utf8");
    const tokens = new Map([...style.matchAll(/(--[a-z-]+):\s*(#[a-f0-9]{6});/g)].map((match) => [match[1], match[2]]));
    const luminance = (hex) => {
        const channels = hex.slice(1).match(/../g).map((channel) => parseInt(channel, 16) / 255)
            .map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
        return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    };
    // When / Then
    for (const [ink, background] of [
        ["--shell-color-text", "#ffffff"], ["--shell-color-muted", "#ffffff"],
        ["--shell-color-success", tokens.get("--shell-color-success-soft")],
        ["--shell-color-warning", tokens.get("--shell-color-warning-soft")],
        ["--shell-color-danger", tokens.get("--shell-color-danger-soft")],
    ]) {
        const values = [luminance(tokens.get(ink)), luminance(background)].sort((left, right) => left - right);
        assert.ok((values[1] + 0.05) / (values[0] + 0.05) >= 4.5, ink);
    }
    assert.match(style, /--dashboard-font: Arial, "Noto Sans KR", "Malgun Gothic", sans-serif/);
    for (const name of ["--dashboard-input", "--dashboard-processing", "--dashboard-latency"]) {
        assert.ok((1 + 0.05) / (luminance(tokens.get(name)) + 0.05) >= 3, name);
    }
    assert.doesNotMatch(style, /@import|@font-face|https?:\/\//);
});

test("Recent Runs keeps its existing disclosure in the header and wraps full identifiers naturally", async () => {
    // Given
    const [html, style] = await Promise.all([readFile(htmlPath, "utf8"), readFile(cssPath, "utf8")]);

    // When
    const toggle = locateElement(html, "dashboard-runs-toggle");
    const identifier = style.split(".runs-table .dashboard-table__run > span {")[1].split("}")[0];
    const timestamp = style.split(".dashboard-run-time {")[1].split("}")[0];

    // Then
    assert.ok(toggle.ancestors.some((ancestor) => ancestor.markup.includes('class="section-header dashboard-section-header"')));
    assert.ok(toggle.ancestors.some((ancestor) => ancestor.markup.includes("dashboard-runs-section")));
    assert.equal(toggle.ancestors.some((ancestor) => ancestor.tag === "details"), false);
    assert.equal((html.match(/id="dashboard-runs-toggle"/g) ?? []).length, 1);
    assert.match(identifier, /display: flex/);
    assert.match(identifier, /flex-wrap: wrap/);
    assert.match(timestamp, /display: inline-flex/);
    assert.match(timestamp, /flex-wrap: wrap/);
    assert.doesNotMatch(identifier + timestamp, /overflow: hidden|text-overflow: ellipsis|max-height:/);
    assert.match(style, /\.dashboard-telemetry-chart__segment\s*\{[^}]*stroke-width: 2;/);
});

test("Navigation alignment polish is scoped to Dashboard and preserves compact mobile spacing", async () => {
    // Given
    const [html, style] = await Promise.all([readFile(htmlPath, "utf8"), readFile(cssPath, "utf8")]);

    // When
    const header = style.split(".dashboard-app-header .app-header__inner {")[1].split("}")[0];
    const navigation = style.split(".dashboard-app-header .app-navigation {")[1].split("}")[0];
    const desktop = style.split("@media (min-width: 70rem) {")[1];
    const mobile = style.split("@media (max-width: 48rem) {")[1];

    // Then
    assert.match(header, /min-height: 2\.6875rem/);
    assert.match(header, /padding: 0\.25rem 1rem 0\.25rem 1\.5rem/);
    assert.match(navigation, /gap: 0\.375rem/);
    assert.doesNotMatch(navigation, /margin-left:/);
    assert.match(desktop, /\.dashboard-app-header \.app-navigation\s*\{\s*margin-left: 0\.1875rem/);
    assert.match(mobile, /\.dashboard-app-header \.app-header__inner\s*\{\s*gap: var\(--shell-space-2\)/);
    assert.match(html, /aria-current="page"/);
    assert.match(html, /<input id="dashboard-run-search" type="search" aria-label="조회된 Run 검색"/);
    assert.match(html, /placeholder="조회된 Run 검색"/);
    assert.doesNotMatch(html, /사건 검색 · 연동 전/);
});

test("Header Run search is enabled, scoped to fetched Runs, and wraps only below the desktop row", async () => {
    // Given
    const [html, style] = await Promise.all([readFile(htmlPath, "utf8"), readFile(cssPath, "utf8")]);

    // When
    const input = html.match(/<input id="dashboard-run-search"[^>]*>/s)?.[0] ?? "";
    const search = style.split(".dashboard-header-search {")[1].split("}")[0];
    const tablet = style.split("@media (max-width: 70rem) {")[1].split("@media")[0];

    // Then
    assert.doesNotMatch(input, /\bdisabled\b/);
    assert.match(input, /aria-describedby="dashboard-run-search-scope"/);
    assert.match(input, /aria-controls="runs-list"/);
    assert.match(input, /autocomplete="off"/);
    assert.match(html, /<div class="dashboard-header-search" role="search">/);
    assert.match(html, /id="dashboard-run-search-scope" class="dashboard-visually-hidden">최근 조회된 최대 20건의 Run/);
    assert.match(html, /id="dashboard-run-navigation-note" class="dashboard-visually-hidden">검색어와 관계없이/);
    assert.equal((html.match(/aria-describedby="dashboard-run-navigation-note"/g) ?? []).length, 2);
    assert.match(search, /flex: 0 1 20rem/);
    assert.doesNotMatch(tablet, /\.dashboard-header-search\s*\{\s*display: none/);
    assert.match(tablet, /\.dashboard-app-header \.app-header__inner\s*\{\s*flex-wrap: wrap;/);
    assert.match(style, /\.dashboard-header-search input:focus-visible\s*\{/);
});
