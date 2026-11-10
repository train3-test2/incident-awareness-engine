// Decorative, local SVG symbols. Operational meaning always remains in adjacent text.
const NAMESPACE = "http://www.w3.org/2000/svg";
const PIPELINE_ICONS = new Set([
    "artifact_validation", "normalization", "fusion", "fast_handoff", "hybrid", "persistence",
]);

export function createPipelineIcon(stage, doc = document) {
    if (!PIPELINE_ICONS.has(stage)) throw new RangeError("Unknown Pipeline icon");
    const svg = doc.createElementNS(NAMESPACE, "svg");
    for (const [name, value] of Object.entries({
        class: "dashboard-icon", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
        "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round",
        "aria-hidden": "true", focusable: "false", "data-icon": stage,
    })) svg.setAttribute(name, value);
    const use = doc.createElementNS(NAMESPACE, "use");
    use.setAttribute("href", `/dashboard-assets/dashboard-icons.svg#${stage}`);
    svg.append(use);
    return svg;
}
