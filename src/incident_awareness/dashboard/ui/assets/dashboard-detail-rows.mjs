// Expandable table rows shared by the Evidence tables. A collapsed row has no detail row in the
// DOM, so row counts equal item counts. IDs and hashes keep their full text for reading and copying.

export function createCopyableValue(doc, value, label) {
    const wrapper = doc.createElement("span");
    wrapper.classList.add("dashboard-copyable");
    const code = doc.createElement("code");
    code.textContent = value;
    code.title = value;
    const button = doc.createElement("button");
    button.type = "button";
    button.classList.add("dashboard-copy-button");
    button.textContent = "복사";
    button.setAttribute("aria-label", `${label} 전체 값 복사`);
    button.addEventListener("click", async () => {
        // The value itself stays selectable when the clipboard is unavailable.
        try {
            await globalThis.navigator.clipboard.writeText(value);
            button.textContent = "복사됨";
        } catch {
            button.textContent = "복사 불가 · 값을 직접 선택";
        }
    });
    wrapper.append(code, button);
    return wrapper;
}

// fields: [label, string | node] pairs; strings are always set as text.
export function createDetailList(doc, fields) {
    const list = doc.createElement("dl");
    list.classList.add("dashboard-evidence-detail");
    for (const [label, value] of fields) {
        const field = doc.createElement("div");
        const term = doc.createElement("dt");
        term.textContent = label;
        const description = doc.createElement("dd");
        if (typeof value === "string") description.textContent = value;
        else description.append(value);
        field.append(term, description);
        list.append(field);
    }
    return list;
}

export function createExpandButton(doc, { key, label, expanded, onToggle }) {
    const button = doc.createElement("button");
    button.type = "button";
    button.classList.add("dashboard-evidence-expand");
    button.textContent = expanded ? "접기" : "상세";
    button.setAttribute("aria-expanded", String(expanded));
    button.setAttribute("aria-label", `${label} ${expanded ? "상세 접기" : "상세 보기"}`);
    button.dataset.rowKey = key;
    button.addEventListener("click", () => onToggle(key));
    return button;
}

export function createDetailRow(doc, columns, content) {
    const row = doc.createElement("tr");
    row.classList.add("dashboard-evidence-detail-row");
    const cell = doc.createElement("td");
    cell.setAttribute("colspan", String(columns));
    cell.append(content);
    row.append(cell);
    return row;
}

export function createStackedText(doc, primary, secondary = null, title = "") {
    const wrapper = doc.createElement("span");
    wrapper.classList.add("dashboard-evidence-cell");
    const main = doc.createElement("span");
    main.textContent = primary;
    wrapper.append(main);
    if (secondary) {
        const note = doc.createElement("small");
        note.textContent = secondary;
        wrapper.append(note);
    }
    if (title) wrapper.title = title;
    return wrapper;
}

// The row key of a focused toggle, captured before a re-render empties the table.
export function focusedRowKey(doc, container) {
    const focused = doc.activeElement;
    return focused && container.contains?.(focused) && focused.dataset?.rowKey ? focused.dataset.rowKey : null;
}

// Focus returns to the same row only if the user has not moved since the re-render began.
export function restoreRowFocus(doc, buttons, key, previous) {
    const current = doc.activeElement;
    if (key === null || !(current === previous || current === null || current === doc.body)) return;
    buttons.get(key)?.focus({ preventScroll: true });
}
