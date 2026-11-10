"""A4 PDFs rendered exclusively from a completed, immutable saved draft."""

import hashlib
import re
from html import escape
from io import BytesIO
from pathlib import Path
from threading import Lock

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

from incident_awareness.dashboard.human_workflow import fingerprint

_FONT_LOCK = Lock()


def render_pdf(draft, version):
    with _FONT_LOCK:
        if "IAE-Korean" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(
                TTFont("IAE-Korean", Path(__file__).parent / "fonts" / "NanumGothic-Regular.ttf")
            )
    normal = ParagraphStyle(
        "body", fontName="IAE-Korean", fontSize=9, leading=14, wordWrap="CJK", spaceAfter=5
    )
    heading = ParagraphStyle(
        "section",
        parent=normal,
        fontSize=13,
        leading=20,
        spaceBefore=14,
        spaceAfter=9,
        keepWithNext=True,
        textColor=colors.HexColor("#164577"),
    )
    small = ParagraphStyle("cell", parent=normal, fontSize=8, leading=12, spaceAfter=0)
    title = ParagraphStyle("title", parent=heading, fontSize=19, leading=27)
    story = []

    def p(value, style=normal):
        return Paragraph(
            escape(str(value if value is not None else "UNKNOWN")).replace("\n", "<br/>"), style
        )

    def section(label):
        story.append(p(label, heading))

    def table(headers, rows, widths=None):
        content = [[p(v, small) for v in row] for row in [headers, *rows]]
        width = A4[0] - 36 * mm
        result = LongTable(
            content,
            colWidths=widths or [width / len(headers)] * len(headers),
            repeatRows=1,
            splitByRow=1,
            splitInRow=1,
            hAlign="LEFT",
        )
        result.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf1fb")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d6e0ec")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.extend([result, Spacer(1, 5 * mm)])

    analysis = draft.get("analysis") or {}
    metadata = analysis.get("run_metadata") or {}
    times = analysis.get("times") or {}
    fusion = analysis.get("fusion") or {}
    detection = analysis.get("detection") or {}
    statistics = analysis.get("event_statistics") or {}
    fields = {f["report_field_id"]: f["value"] for f in draft["output"]["fields"]}
    run = draft.get("run_id") or metadata.get("run_id") or "UNKNOWN"
    call = draft.get("call_metadata") or {}
    llm_used = draft["method"] == "monorouter_grounded"
    requested = bool(call.get("requested_at"))
    fallback_reason = {
        "blocked_data": "실제 Workflow 데이터 외부 전송 차단",
        "disabled": "외부 호출 비활성",
        "timeout": "외부 호출 시간 초과",
        "rate_limited": "외부 사용량 제한",
        "invalid_output": "출력과 원천 근거 불일치",
    }.get(call.get("status"), call.get("status", "UNKNOWN"))
    digest = fingerprint(draft)
    story.extend(
        [
            p("침해사고 신고 검토용 초안", title),
            p("개발용 시나리오 · 담당자 검토 전 · 외부 제출되지 않음"),
        ]
    )
    story.append(
        p(
            "KISA 공식 서식 원본과 완전 일치 여부는 검증되지 않았습니다. 법적 신고의무 및 인지시점을 확정하는 문서가 아닙니다."
        )
    )
    if draft.get("context") == "synthetic_development":
        story.append(
            p(
                "코드 소유 합성 fixture 기반 별도 문서이며 실제 Run 분석이나 조직정보를 사용하지 않았습니다."
            )
        )
    section("1. 문서 기본정보 및 버전")
    table(
        ["항목", "저장된 값"],
        [
            ("문서 버전", f"v{version}"),
            ("Run ID", run),
            ("초안 ID", draft["draft_id"]),
            ("초안 생성시각 (UTC)", draft["generated_at"]),
            ("분석 맥락", draft.get("context")),
            ("초안 SHA-256", digest),
            ("신고 상태", "외부 제출되지 않음"),
        ],
    )
    section("2. 신고 조직·담당자 정보")
    table(
        ["항목", "내용"],
        [
            ("신고 조직", "UNKNOWN"),
            ("담당 부서", fields.get("responsible_department", "UNKNOWN")),
            ("연락처", fields.get("contact_information", "UNKNOWN")),
            ("Actor", "local-demo-analyst / 제한된 데모 Actor, 사용자 인증 아님"),
        ],
    )
    section("3. 사고 개요")
    table(
        ["구분", "값 / 의미"],
        [
            ("실제 사고 발생시각", fields.get("incident_occurred_at", "UNKNOWN")),
            ("기술적 탐지시각", times.get("technical_detection_at")),
            ("알림 발행시각", times.get("alert_issued_at")),
            ("조직 내부 인지시각 t_h", times.get("t_h")),
            ("t_h 시스템 기록시각", times.get("t_h_recorded_at")),
            ("시나리오", metadata.get("scenario_id")),
            ("실험 Run 라벨", metadata.get("run_type")),
            (
                "실험 데이터 구간",
                f"{metadata.get('start_time', 'UNKNOWN')} ~ {metadata.get('end_time', 'UNKNOWN')}",
            ),
        ],
    )
    story.append(PageBreak())
    section("4. 확인된 기술적 탐지 사실")
    table(
        ["항목", "저장된 분석 사실"],
        [
            (
                "저장 Runtime 입력 건수",
                (analysis.get("runtime_observation") or {}).get("input_total"),
            ),
            ("정규화 이벤트 건수", statistics.get("normalized_event_count")),
            ("이벤트 유형별 건수", statistics.get("by_type")),
            ("Fast Detection 상태", detection.get("fast_status")),
            ("Fusion 상태", fusion.get("fusion_status")),
            ("판단 시 Score", fusion.get("score_at_decision")),
            ("Hybrid 상태", analysis.get("hybrid_status")),
            ("Hybrid t_e", detection.get("t_e")),
            ("Scoring 설정 버전", fusion.get("scoring_config_version")),
            ("Decision ID", detection.get("decision_id")),
        ],
    )
    story.append(
        p(
            "Fusion 탐지와 Hybrid 미평가는 함께 존재할 수 있습니다. 탐지시각을 실제 사고 발생시각으로 대입하지 않았습니다."
        )
    )
    episodes = fusion.get("fusion_episodes", [])
    table(
        ["Episode", "시작 / 종료", "Peak score"],
        [
            (
                e.get("episode_id"),
                f"{e.get('start_time')} / {e.get('end_time')}",
                e.get("peak_score"),
            )
            for e in episodes
        ]
        or [("UNKNOWN", "UNKNOWN", "UNKNOWN")],
    )
    section("5. Evidence 및 타임라인")
    table(
        ["Evidence ID", "존재 범위 / 원문 연결"],
        [
            (e["evidence_id"], "Fusion에 저장된 참조 ID / " + e.get("verification", "UNRESOLVED"))
            for e in analysis.get("evidence", [])
        ]
        or [("UNKNOWN", "기존 초안에 Evidence snapshot 없음")],
    )
    story.append(p(analysis.get("evidence_link_note", "Evidence 원문 연결 미검증")))
    story.append(
        p(
            f"아래는 정규화 이벤트 {statistics.get('normalized_event_count', 'UNKNOWN')}건 중 시간순 {len(analysis.get('source_events', []))}건의 저장 참조입니다. 원문 로그 내용은 포함하지 않았습니다."
        )
    )
    event_rows = []
    for e in analysis.get("source_events", []):
        raw = e.get("raw_ref") or {}
        event_rows.append(
            (
                e["event_id"],
                e.get("source_event_id"),
                f"{e['timestamp']}\n{e['event_type']}",
                f"{raw.get('raw_log_id', 'UNKNOWN')}\nsegment={raw.get('segment_no', 'UNKNOWN')}, record={raw.get('record_no', 'UNKNOWN')}",
            )
        )
    table(
        [
            "Normalized Event",
            "Source Event ID",
            "이벤트 시각 / 유형",
            "저장 Raw 참조 (내용 미검증)",
        ],
        event_rows or [("UNKNOWN",) * 4],
    )
    story.append(PageBreak())
    section("6. 사고 원인·피해 현황")
    table(
        ["항목", "확인 상태"],
        [
            ("원인", fields.get("incident_cause", "UNKNOWN")),
            ("피해 내용·규모", fields.get("damage_description", "UNKNOWN")),
            ("유출 여부", "UNKNOWN / 조사 중"),
        ],
    )
    section("7. 대응 및 조치 현황")
    story.append(p(fields.get("response_measures", "UNKNOWN")))
    story.append(
        p(
            "알림 확인·근거 검토·신고 진행 결정은 대응조치 완료나 실제 신고 완료를 의미하지 않습니다."
        )
    )
    section("8. 추가 확인 필요 사항")
    for item in [
        "실제 사고 발생시각, 원인, 피해 규모와 유출 여부 확인",
        "신고 조직·담당부서·연락처 확인",
        "Evidence archive와 원천 이벤트·원문 무결성 연결 검증",
        "KISA 공식 서식 및 신고의무에 대한 담당자 확인",
    ]:
        story.append(p("• " + item))
    section("9. 담당자 검토 및 생성 이력")
    table(
        ["항목", "초안 생성 당시 값"],
        [
            ("생성 방식", draft["method"]),
            ("생성 제공자", "MonoGPT MonoRouter" if llm_used else "Local Jinja2"),
            ("이 초안의 실제 LLM 사용 여부", "사용" if llm_used else "사용 안 함"),
            ("요청 모델", call.get("requested_model")),
            ("실제 응답 모델", call.get("actual_model") or "해당 없음"),
            ("LLM 요청시각", call.get("requested_at") or "호출 없음"),
            (
                "입력 / 출력 토큰",
                f"{call.get('input_tokens', 'UNKNOWN')} / {call.get('output_tokens', 'UNKNOWN')}"
                if requested
                else "해당 없음 (LLM 호출 없음)",
            ),
            ("fallback 사용 여부 / 사유", "미사용" if llm_used else f"사용 / {fallback_reason}"),
            ("Workflow 버전", draft.get("workflow_version")),
            ("담당자 검토 상태", "담당자 검토 전 (생성 당시 snapshot)"),
            ("신고 진행 action ID", draft.get("human_action_id")),
        ],
    )
    table(
        ["Actor / Action", "실제 기록시각", "인지시각 이전 / 이후", "기록 사유"],
        [
            (
                f"{a['actor_id']}\n{a['action']}\n{a['action_id']}",
                a["recorded_at"],
                f"{a.get('previous_t_h') or 'UNKNOWN'} / {a.get('new_t_h') or 'UNKNOWN'}",
                a.get("reason") or a["action"],
            )
            for a in analysis.get("human_history", [])
        ]
        or [("UNKNOWN",) * 4],
    )
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=18 * mm,
        title="침해사고 신고 검토용 초안",
        author="Incident Awareness · local demo",
        invariant=1,
    )

    def footer(canvas, doc):
        canvas.setFont("IAE-Korean", 8)
        canvas.setFillColor(colors.HexColor("#526b91"))
        canvas.drawString(
            18 * mm, 10 * mm, f"개발용 시나리오 · 담당자 검토 전 · 외부 제출되지 않음 | v{version}"
        )
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, str(doc.page))

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def get_or_create_pdf(store, draft_id, alert_id=None):
    draft = store.load(draft_id, alert_id)
    saved = store.pdf_export(draft_id)
    version = store.version(draft_id)
    digest = fingerprint(draft)
    if saved is None:
        content = render_pdf(draft, version)
        saved = store.save_pdf(
            draft_id, version, digest, hashlib.sha256(content).hexdigest(), content
        )
    if (
        saved["draft_sha256"] != digest
        or saved["document_version"] != version
        or hashlib.sha256(saved["pdf_bytes"]).hexdigest() != saved["pdf_sha256"]
    ):
        raise ValueError("Saved PDF digest does not match its draft version")
    run = re.sub(r"[^A-Za-z0-9._-]", "_", str(draft.get("run_id") or "UNKNOWN"))[:80]
    return saved, f"incident-report-{run}-v{version}.pdf"
