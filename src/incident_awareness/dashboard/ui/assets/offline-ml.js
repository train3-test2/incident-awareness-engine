import {loadOfflineDisplay, offlineCase} from "./offline-ml-contract.mjs";

const element = id => document.getElementById(id);

function fields(id, pairs) {
    const target = element(id);
    target.replaceChildren();
    for (const [label, value] of pairs) {
        const term = document.createElement("dt");
        term.className = "detail-field__label";
        term.textContent = label;
        const description = document.createElement("dd");
        description.className = "detail-field__value";
        description.textContent = value;
        target.append(term, description);
    }
}

function render(data, runId) {
    const item = offlineCase(data, runId);
    const group = item.training_overlap ? "학습 데이터 포함 · 개발 출력 확인" : "Pair-008 · 학습 미포함 · Offline 개발 확인";
    element("offline-case-group").textContent = `${group} · 공식 Holdout 성능평가가 아닙니다.`;
    fields("offline-case-fields", [
        ["분석 유형", "오프라인 모델 분석"],
        ["원본 분석 ID", item.run_id],
        ["보정되지 않은 P(label=1)", String(item.probability)],
        ["학습 데이터 포함 여부", String(item.training_overlap)],
    ]);
    fields("offline-model-fields", [
        ["모델 버전", data.model.version],
        ["Feature Version", data.model.feature_version],
        ["Feature Scope", data.model.feature_scope],
        ["Calibration", "보정되지 않음 · 보정 정보 미제공"],
        ["Classification Threshold", "없음 (null)"],
        ["공식 성능평가", "없음 (null)"],
        ["TTSD", "없음 (null)"],
    ]);
    const body = element("offline-feature-body");
    body.replaceChildren();
    data.feature_names.forEach((name, index) => {
        const row = document.createElement("tr");
        const heading = document.createElement("th");
        heading.scope = "row";
        heading.textContent = name;
        const value = document.createElement("td");
        value.textContent = String(item.feature_values[index]);
        row.append(heading, value);
        body.append(row);
    });
    fields("offline-provenance-fields", [
        ["전달 패키지", data.package_version],
        ["내부 SHA-256 검증", `${data.verified_member_count}개 파일 일치`],
        ["ZIP SHA-256", data.package_sha256],
        ["모델 파일 SHA-256", data.model.file_sha256],
        ["모델 canonical SHA-256", data.model.canonical_sha256],
        ["입력 파일 SHA-256", item.input_file_sha256],
        ["입력 canonical SHA-256", item.input_canonical_sha256],
        ["출력 파일 SHA-256", item.result_file_sha256],
        ["학습 데이터 canonical SHA-256", data.model.training_sha256],
        ["학습 분석 (6개)", data.training_run_ids.join(", ")],
        ["개발 확인 분석 (2개)", data.check_run_ids.join(", ")],
    ]);
}

async function start() {
    const content = element("offline-content");
    try {
        const data = await loadOfflineDisplay(window.fetch.bind(window));
        const select = element("offline-case");
        select.replaceChildren();
        for (const [label, ids] of [["Pair-008 · 개발 확인", data.check_run_ids], ["학습 데이터 포함", data.training_run_ids]]) {
            const group = document.createElement("optgroup");
            group.label = label;
            for (const id of ids) {
                const option = document.createElement("option");
                option.value = id;
                option.textContent = id;
                group.append(option);
            }
            select.append(group);
        }
        select.addEventListener("change", () => render(data, select.value));
        render(data, select.value);
        content.hidden = false;
        element("offline-status").textContent = "검증된 전달 결과 · 학습 분석 6개 / 개발 확인 분석 2개 · 읽기 전용";
    } catch {
        content.hidden = true;
        element("offline-status").textContent = "검증된 Offline ML 표시 데이터를 읽을 수 없습니다. 패키지 검증·로컬 표시 파일 준비 상태를 확인하세요.";
    }
}

start();
