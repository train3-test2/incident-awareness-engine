import { formatOperatorTimestamp, formatOperatorProse } from "./dashboard-contract.mjs";
import { getHybridDecisionNotice } from "./run-detail-contract.mjs";

// Presentation only. Never infer a human action, legal awareness or successful AI call.
const FALLBACK_REASONS = {
    disabled: "외부 호출 없음", blocked_data: "실제 분석 외부 전송 차단", http_error: "AI 호출 실패",
    rate_limited: "AI 호출 제한", timeout: "AI 응답 시간 초과", invalid_output: "AI 출력 검증 실패",
    invalid_response: "AI 응답 형식 검증 실패", transport_error: "AI 통신 실패",
    missing_key: "AI 인증 설정 없음", configuration_error: "AI 설정 오류",
};

export function draftPresentation(draft) {
    const call = draft?.call_metadata;
    const ai = draft?.method === "monorouter_grounded" && call?.status === "success" && call.http_status === 200;
    const fallback = draft?.method === "jinja2_fallback" || draft?.method === "jinja2";
    const method = ai ? "AI 작성" : fallback ? "대체 작성"
        : draft?.method === "monorouter_grounded" ? "작성 방식 확인 필요" : "작성 방식 미확인";
    // A fallback never claims an AI call; the reason distinguishes "not called" from "failed".
    const reason = ai ? "검증 통과" : fallback
        ? FALLBACK_REASONS[call?.status] ?? (call?.requested_at ? "AI 호출 후 대체" : "외부 호출 없음") : null;
    const demo = draft?.context === "synthetic_development";
    return { method, reason, demo, ai, source: demo ? "합성 시연 초안" : "이 분석 초안" };
}

// Presentation only: an incomplete stored pair requires inspection, never repair.
export function awarenessRecordStatus(state) {
    const awareness = Boolean(state?.t_h), recorded = Boolean(state?.t_h_recorded_at);
    return awareness && recorded ? "complete" : awareness || recorded ? "incomplete" : "missing";
}

const FORM_TYPES = { ransomware: "랜섬웨어", ddos: "디도스", other_hacking: "그 밖의 해킹" };

// The incident type stays a human choice. The reason records only that choice and what was shown.
export function classificationReason(type, phrases = []) {
    const label = FORM_TYPES[type];
    if (!label) return "";
    const basis = phrases.length ? `선택 화면에 표시된 원본 검증 관측: ${phrases.join(", ")}.` : "선택 화면의 원본 검증 관측을 확인함.";
    return `담당자가 대시보드에서 '${label}' 양식을 직접 선택함. ${basis} 피해·원인은 미확인이며 시스템이 사고 유형을 자동 확정하지 않음.`.slice(0, 1000);
}

// Observation phrases come only from the server-built, deidentified request; nothing is inferred.
export function snapshotEligibility(value, version) {
    if (!/^[a-f0-9]{64}$/.test(value?.snapshot_sha256 ?? "") || value.workflow_version !== version
        || value.external_transmission !== "not_sent") return { state: "unknown", phrases: [] };
    let phrases = [];
    try {
        phrases = JSON.parse(value.request.messages[0].content).observations
            .map(item => item.fact_phrase).filter(item => typeof item === "string");
    } catch { phrases = []; }
    return { state: "eligible", phrases, reuse: value.word_reuse ?? null };
}

// Only what the compose step needs. The case, target and human progress are shown once elsewhere
// (detail header, source line, timeline and human summary), so they are not repeated here.
export function reportSummaryRows(value, eligibility = null, status = null) {
    if (!value) return [];
    const state = value.state, source = value.source_snapshot ?? {};
    const proceed = state.report_choice === "proceed", kind = eligibility?.state, phrases = eligibility?.phrases ?? [];
    const observed = !proceed ? "신고 진행 결정 후 확인합니다."
        : kind === "eligible" ? phrases.length ? `원본 검증 관측 ${phrases.length}건 · ${phrases.join(", ")}`
            : "원본 검증 관측 확인됨 · 목록은 작성 근거에서 확인"
        : kind === "ineligible" ? "자동 작성에 쓸 수 있는 원본 검증 관측이 없습니다."
        : !kind || kind === "checking" ? "확인 중" : "확인하지 못했습니다.";
    const possible = !proceed ? "신고 진행 결정 후 가능"
        : status && status.adapter !== "configured" ? "AI 작성 설정 확인 필요 · 작성 근거에서 대체 작성만 가능"
        : { eligible: "가능",
            ineligible: "불가 · 원본 검증된 정식 분석 관측이 없거나 외부 작성이 허용되지 않은 관측 유형",
            unsupported: "불가 · 이 서버에는 승인형 AI 작성 기능 없음",
            blocked: "불가 · 신고 진행 결정을 다시 확인하세요",
            unknown: "확인 필요 · 생성 버튼을 누르면 다시 확인" }[kind] ?? "확인 중";
    // not_evaluated covers both a stored Decision without t_e and no Decision at all.
    const basis = [`근거 증거 ${source.evidence_ids?.length ?? 0}건`,
        source.hybrid_status === "not_evaluated" ? source.decision ? "종합 판단 미완료" : "저장된 종합 판단 없음" : null,
        source.context === "synthetic_development" ? "합성 개발 데이터" : null].filter(Boolean).join(" · ");
    return [["확인된 관측 사실", observed], ["자동 작성", possible], ["탐지 근거", basis]];
}

const PARTY_FIELDS = new Set(["company_name", "business_number", "industry", "company_size", "company_address",
    "reporter_name", "reporter_email", "reporter_phone"]);
const CONSENT_FIELDS = new Set(["privacy_collection", "support_programs", "ctas", "provision_overall",
    "technical_support", "truth_confirmation"]);

// Counts by category for the collapsed checklist; the server assessment stays authoritative.
export function readinessSummary(status) {
    const items = status?.required_items ?? (status?.blockers ?? []).map(key => ({ key }));
    const groups = new Map();
    for (const item of items) {
        const group = item.key === "incident_type" ? "사고 유형" : item.key === "t_h" ? "인지시각"
            : PARTY_FIELDS.has(item.key) ? "기업·신고자 정보"
            : CONSENT_FIELDS.has(item.key) || item.target?.startsWith("consent:") ? "동의·확인" : "사고 세부사항";
        groups.set(group, (groups.get(group) ?? 0) + 1);
    }
    return { count: items.length, groups: [...groups].map(([label, count]) => ({ label, count })) };
}

// A Word file is described as ready only from the server's own result for a verified AI draft.
export function generationOutcome(draft) {
    const presentation = draftPresentation(draft);
    if (!presentation.ai) return `AI 초안 검증 미통과(${presentation.reason ?? presentation.method}) · 검증되지 않은 내용은 Word에 기입하지 않았습니다. 다시 생성하거나 작성 근거를 확인하세요.`;
    const word = draft?.word_result?.status;
    // Review and submission states are shown once in the document summary, not repeated here.
    if (word === "ready") return "Word 생성 완료";
    if (word === "failed") return "AI 초안은 저장했지만 Word 양식 생성에 실패했습니다. 추가 정보 입력·수정에서 확인 후 Word 신고서를 만드세요.";
    return "Word 양식 미생성 · 사고 유형 확인 후 Word 신고서를 만드세요.";
}

// The last step covers both the draft and its human review; a draft alone never completes it.
// Hold and do-not-proceed are human decisions, so drafting is then never the next step.
export function workflowSteps(value, entry = null) {
    if (!value) return [];
    const state = value.state;
    const awareness = awarenessRecordStatus(state);
    const declined = state.report_choice === "hold" || state.report_choice === "do_not_proceed";
    const rows = [
        ["알림", value.issued_at, Boolean(value.issued_at)],
        ["담당자 확인", state.analyst_ack_time, Boolean(state.analyst_ack_time)],
        ["근거 검토", state.evidence_reviewed_at, Boolean(state.evidence_reviewed_at)],
        [awareness === "incomplete" ? "인지 기록 상태 확인" : "인지 기록", state.t_h_recorded_at, awareness === "complete"],
        ["신고 검토", state.report_decided_at, Boolean(state.report_choice)],
        ["초안·검토", entry?.draft?.generated_at, Boolean(entry?.draft && entry?.current && entry?.review)],
    ];
    let current = false;
    return rows.map(([label, timestamp, done], index) => {
        const draftStep = index === 5;
        const active = !done && !current && !(draftStep && declined);
        if (active) current = true;
        return { label, timestamp, state: index === 3 && awareness === "incomplete" ? "incomplete"
            : done ? "complete" : draftStep && entry?.draft ? "partial"
                : draftStep && declined ? "not_applicable" : "pending", active };
    });
}

// List rows read stored alerts without the draft list, so only the first five steps are judged.
const ROW_CHOICES = { proceed: "신고 진행 결정", hold: "신고 보류", do_not_proceed: "신고 진행 안 함" };
export function workflowRowLabel(alerts) {
    if (!Array.isArray(alerts)) return "확인 불가";
    if (!alerts.length) return "처리 기록 없음";
    const open = alert => alert.state?.report_choice === "hold"
        || workflowSteps(alert).slice(0, 5).some(step => step.state !== "complete");
    if (alerts.length > 1) return `알림 ${alerts.length}건 · 미완료 ${alerts.filter(open).length}건`;
    const steps = workflowSteps(alerts[0]).slice(0, 5);
    const waiting = steps.find(step => step.state !== "complete");
    if (waiting) return waiting.state === "incomplete" ? "인지 기록 상태 확인 필요" : `${waiting.label} 대기`;
    return ROW_CHOICES[alerts[0].state.report_choice] ?? "신고 검토 확인 필요";
}

export function workflowTimeLabel(value, precise = false) {
    if (!value) return "미기록";
    return formatOperatorTimestamp(value, { missing: "미기록", precise });
}

export function workflowTimeDetail(value) {
    if (!value || !Number.isFinite(new Date(value).getTime())) return workflowTimeLabel(value);
    return `${workflowTimeLabel(value, true)} · UTC ${new Date(value).toISOString()} · 원본 ${value}`;
}

// Keep the verified source sentence intact in data; normalize only its display.
export function observationDisplayText(text, observedAt = null) {
    const raw = typeof text === "string" ? text : "";
    const prefix = raw.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))(?=\s|$)/)?.[1];
    if (prefix && formatOperatorProse(prefix) !== prefix) {
        const clock = formatOperatorProse(prefix);
        const body = formatOperatorProse(raw.slice(prefix.length).trimStart());
        const recorded = observedAt == null ? null : formatOperatorTimestamp(observedAt);
        const fraction = value => value.match(/\.(\d+)(?:Z|[+-]\d{2}:\d{2})$/)?.[1].padEnd(9,"0") ?? "000000000";
        const same = observedAt == null || (Date.parse(prefix) === Date.parse(observedAt) && fraction(prefix) === fraction(observedAt));
        return !same && recorded && recorded !== "시각 확인 필요"
            ? `${recorded} — 문장 시각 ${clock} · ${body}` : `${clock} — ${body}`;
    }
    const converted = formatOperatorProse(raw);
    const clock = observedAt == null ? null : formatOperatorTimestamp(observedAt);
    return clock && clock !== "시각 확인 필요" ? `${clock} — ${converted}` : converted;
}

export function analysisStatusLabel(status) {
    return new Map([["detected", "의심 행위 탐지"], ["miss", "탐지 기준 미충족"], ["not_evaluated", "미평가"],
        ["pending", "대기"], ["failed", "실패"]]).get(status)
        ?? (status == null ? "현재 확인된 정보 없음" : "상태 확인 필요");
}

export function analysisPathLabel(path) {
    return new Map([["fast", "즉시 규칙 분석"], ["fusion", "증거 누적 분석"],
        ["fast_and_fusion", "즉시 규칙·증거 누적 분석"], ["none", "탐지 경로 없음"]]).get(path)
        ?? (path == null ? "미확정" : "판단 경로 확인 필요");
}

// Analysis and Workflow share the explicit KST formatter; source timestamps stay unchanged.
export function analysisTimestampLabel(value, missing = "미확정") {
    return formatOperatorTimestamp(value, { missing });
}

// Presentation only. A missing Decision and a failed Decision read are different facts.
export function analysisDecisionPresentation(decision, fusion = null, decisionQueryState = "success") {
    const fast = decision?.fast_status;
    const cumulative = decision?.fusion_status ?? (decision == null ? fusion?.fusion_status : null);
    const detected = [fast === "detected" && "즉시 규칙 분석",
        cumulative === "detected" && "증거 누적 분석"].filter(Boolean);
    let headline = detected.length ? `${detected.join("·")}에서 의심 행위 탐지`
        : fast === "miss" && cumulative === "miss" ? "평가된 두 경로의 탐지 기준 미충족"
        : cumulative === "miss" ? "증거 누적 분석의 탐지 기준 미충족"
        : fast === "miss" ? "즉시 규칙 분석의 탐지 기준 미충족" : "탐지 결과 미확정";
    const times = [];
    if (fast === "detected") times.push(`즉시 규칙 분석 · ${analysisTimestampLabel(decision.detector_time, "탐지 시각 미확인")}`);
    if (cumulative === "detected") times.push(`증거 누적 분석 · ${analysisTimestampLabel(
        decision == null ? fusion?.fusion_time : decision.fusion_time, "탐지 시각 미확인",
    )}`);
    let summary, reason;
    // Judgment completion only: 완료, 미완료, or null when the stored state could not be read or checked.
    let completion = null;
    let path = decision == null ? "미확정" : analysisPathLabel(decision.decision_path);
    let decisionTime = analysisTimestampLabel(decision?.t_e);
    if (decision == null) {
        summary = new Map([["error", "종합 판단 조회 실패"], ["loading", "종합 판단 조회 중"],
            ["not_found", "종합 판단 조회 불가"], ["version_mismatch", "종합 판단 확인 보류 · 조회 버전 불일치"]])
            .get(decisionQueryState) ?? "저장된 종합 판단 결과 없음";
        reason = summary;
        if (decisionQueryState === "success") completion = "미완료";
        if (decisionQueryState !== "success") {
            path = decisionTime = decisionQueryState === "version_mismatch" ? "표시 보류" : "조회 미완료";
        }
        if (decisionQueryState === "version_mismatch") headline = "조회 버전 불일치 · 결과 확인 보류";
    } else if ([fast, cumulative].includes("not_evaluated")) {
        const notice = getHybridDecisionNotice(decision);
        const unevaluated = [fast === "not_evaluated" && "즉시 규칙 분석",
            cumulative === "not_evaluated" && "증거 누적 분석"].filter(Boolean).join("·");
        reason = notice ? "필수 병렬 평가 미완료" : "미평가 사유 미확인";
        summary = notice ?? `종합 판단 미완료 · ${unevaluated} 미평가 · 사유 미확인`;
        completion = "미완료";
    } else if (fast === "miss" && cumulative === "miss" && decision.decision_path === "none"
        && decision.t_e === null) {
        summary = "종합 판단 완료 · 탐지 기준 미충족";
        completion = "완료";
        reason = decision.decision_reason === "Both evaluated paths missed"
            ? "평가된 두 경로의 탐지 기준 미충족" : "판단 사유 미확인";
        decisionTime = "없음 · 탐지 기준 미충족";
    } else if ([fast, cumulative].every(status => ["detected", "miss"].includes(status))
        && ({fast: fast === "detected" && cumulative === "miss",
            fusion: fast === "miss" && cumulative === "detected",
            fast_and_fusion: fast === "detected" && cumulative === "detected"})[decision.decision_path] === true
        && decision.t_e != null && Number.isFinite(Date.parse(decision.t_e))) {
        summary = "종합 판단 완료 · 의심 행위 탐지";
        completion = "완료";
        const knownReason = new Map([
            ["fast", ["Only Fast detected", "즉시 규칙 분석에서 탐지"]],
            ["fusion", ["Only Fusion detected", "증거 누적 분석에서 탐지"]],
            ["fast_and_fusion", ["Both paths detected; compared canonical UTC millisecond timestamps", "두 경로 탐지 · 저장된 판단 시각 비교"]],
        ]).get(decision.decision_path);
        reason = decision.decision_reason === knownReason[0] ? knownReason[1] : "판단 사유 미확인";
    } else {
        summary = "종합 판단 상태 확인 필요";
        reason = "판단 상태·시각·경로 확인 필요";
    }
    // The stored hybrid notice is already the summary, so a separate reason line would only repeat it.
    const reasonRepeatsSummary = reason === "필수 병렬 평가 미완료";
    return { headline, summary, completion, reason, reasonRepeatsSummary, path, decisionTime,
        detectionTime: times.join(" / ") || "탐지 시각 없음 · 탐지 결과 확인",
        rawReason: decision?.decision_reason ?? null };
}

// Local selection identity, not a server revision or an integrity digest.
export function normalizeRawVerificationScope(scope) {
    const identifier = value => typeof value === "string" && value.trim() === value && value.length > 0;
    if (!scope || !identifier(scope.runId) || !identifier(scope.entityId)
        || !(scope.decisionId === null || identifier(scope.decisionId))
        || !Array.isArray(scope.evidenceIds) || !scope.evidenceIds.every(identifier)
        || new Set(scope.evidenceIds).size !== scope.evidenceIds.length) return null;
    return { runId: scope.runId, entityId: scope.entityId, decisionId: scope.decisionId,
        evidenceIds: [...scope.evidenceIds].sort() };
}

export function sameRawVerificationScope(left, right) {
    const a = normalizeRawVerificationScope(left), b = normalizeRawVerificationScope(right);
    return a !== null && b !== null && a.runId === b.runId && a.entityId === b.entityId
        && a.decisionId === b.decisionId && a.evidenceIds.length === b.evidenceIds.length
        && a.evidenceIds.every((id, index) => id === b.evidenceIds[index]);
}

// Only explicit mismatch/invalid-original codes imply failure; unavailable files do not.
const RAW_VERIFICATION_FAILURES = new Set([
    "raw_sha256_mismatch", "raw_normalized_event_mismatch", "source_record_id_mismatch",
    "manifest_raw_mapping_mismatch", "manifest_run_mismatch", "manifest_source_mismatch",
    "stored_archive_sha256_mismatch", "stored_archive_identity_mismatch",
    "archive_event_identity_mismatch", "archive_mirror_content_conflict",
    "raw_record_invalid", "raw_archive_invalid",
]);

// Shared by the summary count and the Evidence table so one item never reads two ways.
export function rawVerificationItemFailed(item) {
    const checks = Array.isArray(item?.validation_details?.raw_checks) ? item.validation_details.raw_checks : [];
    return item?.resolution_status !== "raw_verified" && (RAW_VERIFICATION_FAILURES.has(item?.unresolved_reason)
        || checks.some(check => check.verified === false && RAW_VERIFICATION_FAILURES.has(check.reason)));
}

export function buildRawVerificationSummary(payload, selection) {
    const scope = normalizeRawVerificationScope(selection);
    if (!scope || payload?.schema_version !== "evidence_provenance_v1"
        || payload.run_id !== scope.runId || payload.scope !== "fusion_contributing_ids_only"
        || !Array.isArray(payload.items) || !Array.isArray(payload.source_events)) {
        throw Error("Invalid provenance response scope");
    }
    const identities = new Set();
    const eventIds = new Set();
    for (const event of payload.source_events) {
        if (event.run_id !== scope.runId || typeof event.event_id !== "string" || !event.event_id
            || typeof event.host_id !== "string" || !event.host_id || eventIds.has(event.event_id)) {
            throw Error("Invalid provenance source event");
        }
        eventIds.add(event.event_id);
    }
    for (const item of payload.items) {
        const key = JSON.stringify([item.entity_id, item.evidence_id]);
        if (item.run_id !== scope.runId || typeof item.entity_id !== "string" || !item.entity_id
            || typeof item.evidence_id !== "string" || !item.evidence_id || identities.has(key)
            || !["unresolved", "event_verified", "raw_verified"].includes(item.resolution_status)
            || !Array.isArray(item.event_ids) || !Array.isArray(item.observed_behavior)) {
            throw Error("Invalid provenance item");
        }
        identities.add(key);
    }
    // This API covers the entire Run, including other entities/episodes. Count only the selection.
    const items = payload.items.filter(item => item.entity_id === scope.entityId
        && scope.evidenceIds.includes(item.evidence_id));
    if (items.length !== scope.evidenceIds.length) throw Error("Provenance evidence set mismatch");
    let verified = 0, failed = 0;
    for (const item of items) {
        const checks = item.validation_details?.raw_checks ?? [];
        if (!Array.isArray(checks)) throw Error("Invalid raw checks");
        if (item.resolution_status === "raw_verified") {
            if (item.unresolved_reason != null || checks.some(check => check.verified === false)
                || !item.event_ids.length || item.event_ids.some(id => !payload.source_events.some(event =>
                    event.event_id === id && event.run_id === scope.runId && event.host_id === scope.entityId))) {
                throw Error("Contradictory verified provenance");
            }
            verified++;
        } else if (rawVerificationItemFailed(item)) {
            failed++;
        }
    }
    const total = items.length;
    // Only raw-verified Evidence carries behavioural prose; its text is shown verbatim, never rebuilt.
    const observations = items.filter(item => item.resolution_status === "raw_verified")
        .flatMap(item => item.observed_behavior
            .filter(observation => typeof observation?.behavior_summary === "string" && observation.behavior_summary)
            .map(observation => ({ evidenceId: item.evidence_id, observedAt: observation.observed_at ?? null,
                text: observation.behavior_summary })))
        .sort((left, right) => String(left.observedAt).localeCompare(String(right.observedAt)));
    return { runId: scope.runId, scope, evidenceIds: scope.evidenceIds, queryState: "ready",
        resultState: !total ? "empty" : verified === total ? "passed" : verified > 0 ? "partial"
            : failed > 0 ? "failed" : "unverified",
        verified, failed, total, observations };
}

export function rawVerificationLabel(expectedIds, summary, selection = null) {
    const scope = normalizeRawVerificationScope(selection);
    if (!Array.isArray(expectedIds) || new Set(expectedIds).size !== expectedIds.length
        || selection != null && !scope) return "검증 상태 미조회";
    if (!summary) return expectedIds.length ? "검증 상태 미조회" : "검증 대상 없음";
    if (scope && !sameRawVerificationScope(scope, summary.scope)) return "검증 상태 미조회";
    if (!Array.isArray(summary.evidenceIds) || expectedIds.length !== summary.evidenceIds.length
        || new Set(summary.evidenceIds).size !== summary.evidenceIds.length
        || expectedIds.some(id => !summary.evidenceIds.includes(id))) return "검증 상태 미조회";
    if (summary.queryState === "loading") return "원본 검증 확인 중";
    if (summary.queryState === "unsupported") return "검증 정보 미지원";
    if (summary.queryState === "error") return summary.errorKind === "scope_mismatch"
        ? "조회 실패 · 검증 범위 불일치" : "조회 실패";
    if (summary.queryState !== "ready") return expectedIds.length ? "검증 상태 미조회" : "검증 대상 없음";
    if (!scope) return "검증 상태 미조회";
    const {verified, failed, total} = summary;
    if (!Number.isInteger(verified) || !Number.isInteger(failed) || !Number.isInteger(total)
        || total !== expectedIds.length || verified < 0 || failed < 0 || verified + failed > total) return "조회 실패";
    if (!total && summary.resultState === "empty") return "검증 대상 없음";
    if (summary.resultState === "passed" && total > 0 && verified === total) return `원본 대조 통과 · ${verified}/${total}건`;
    if (summary.resultState === "partial" && verified > 0 && verified < total) return `일부 검증 · ${verified}/${total}건 통과`
        + (failed ? ` · 원본 검증 실패 ${failed}건` : "");
    if (summary.resultState === "failed" && failed > 0) return `원본 검증 실패 · ${verified}/${total}건 통과`;
    if (summary.resultState === "unverified") return `원본 대조 미완료 · ${verified}/${total}건 통과`;
    return "조회 실패";
}
