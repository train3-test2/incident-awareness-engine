import hashlib
from copy import deepcopy
from uuid import uuid4

import pymupdf
import pytest

from incident_awareness.reporting.config import MonoRouterSettings
from incident_awareness.reporting.monorouter import MonoRouterAdapter
from incident_awareness.reporting.pdf import get_or_create_pdf
from incident_awareness.reporting.service import GroundedReportService
from incident_awareness.reporting.store import ReportDraftStore
from incident_awareness.reporting.synthetic import synthetic_report_input


def analysis_fixture():
    return {
        "run_metadata": {
            "run_id": "RUN-20261019-007",
            "scenario_id": "S0",
            "run_type": "attack",
            "start_time": "2026-09-27T07:49:31Z",
            "end_time": "2026-09-27T08:00:38Z",
        },
        "event_statistics": {
            "normalized_event_count": 869,
            "by_type": {"process_create": 16, "network_connection": 853},
        },
        "times": {
            "technical_detection_at": "2026-09-27T07:52:01Z",
            "alert_issued_at": "2026-10-20T06:00:00Z",
            "t_h": None,
            "t_h_recorded_at": None,
        },
        "fusion": {
            "fusion_status": "detected",
            "score_at_decision": 1.0,
            "scoring_config_version": "test-config",
            "fusion_episodes": [
                {
                    "episode_id": "FEP-001",
                    "start_time": "2026-09-27T07:52:01Z",
                    "end_time": "2026-09-27T07:56:51Z",
                    "peak_score": 1.0,
                }
            ],
        },
        "detection": {"decision_id": "DEC-TEST", "fast_status": "not_evaluated", "t_e": None},
        "hybrid_status": "not_evaluated",
        "evidence": [{"evidence_id": "REFERENCE-EVIDENCE-001", "verification": "UNRESOLVED"}],
        "evidence_link_note": "Evidence 원문 연결 미검증",
        "source_events": [
            {
                "event_id": f"NORMALIZED-EVENT-{i:04d}-TEST-ONLY",
                "timestamp": "2026-09-27T07:49:31Z",
                "event_type": "network_connection",
                "source_event_id": f"SOURCE-{i:04d}",
                "raw_ref": {
                    "raw_log_id": "SYNTHETIC-RAW-REFERENCE-ONLY",
                    "segment_no": 1,
                    "record_no": i + 1,
                },
            }
            for i in range(40)
        ],
        "human_state": {"report_choice": "proceed"},
        "human_history": [
            {
                "actor_id": "local-demo-analyst",
                "action": "decide_reporting",
                "action_id": "test-action",
                "recorded_at": "2026-10-20T06:00:00Z",
                "previous_t_h": None,
                "new_t_h": None,
                "reason": "테스트 검토 사유",
            }
        ],
    }


def saved_draft(tmp_path):
    source = synthetic_report_input()
    source.alert_id = "TEST-ANALYSIS-ALERT"
    source.run_id = "RUN-20261019-007"
    source.analysis = analysis_fixture()
    for field in source.fields:
        field.value = "UNKNOWN"
        field.references = []
    store = ReportDraftStore(tmp_path / "reports.sqlite3")
    draft = GroundedReportService(store, MonoRouterAdapter(MonoRouterSettings())).generate(
        source, uuid4(), 1, lambda: source
    )
    return store, draft


def test_a4_embedded_korean_multipage_tables_and_required_sections(tmp_path):
    store, draft = saved_draft(tmp_path)
    saved, name = get_or_create_pdf(store, draft["draft_id"], draft["alert_id"])
    assert name == "incident-report-RUN-20261019-007-v1.pdf"
    assert saved["pdf_sha256"] == hashlib.sha256(saved["pdf_bytes"]).hexdigest()
    with pymupdf.open(stream=saved["pdf_bytes"], filetype="pdf") as document:
        assert len(document) >= 3
        text = "\n".join(page.get_text() for page in document)
        compact = "".join(text.split())
        for expected in [
            "침해사고 신고 검토용 초안",
            "개발용 시나리오",
            "담당자 검토 전",
            "외부 제출되지 않음",
            "문서 기본정보 및 버전",
            "신고 조직·담당자 정보",
            "사고 개요",
            "확인된 기술적 탐지 사실",
            "Evidence 및 타임라인",
            "사고 원인·피해 현황",
            "대응 및 조치 현황",
            "추가 확인 필요 사항",
            "담당자 검토 및 생성 이력",
        ]:
            assert "".join(expected.split()) in compact
        assert "RUN-20261019-007" in text and "869" in text and "FEP-001" in text
        assert "UNKNOWN" in text and "not_evaluated" in text
        assert "\ufffd" not in text
        assert any(document.extract_font(f[0])[3] for f in document.get_page_fonts(0))
        assert text.count("Normalized Event") >= 2
        for page in document:
            assert abs(page.rect.width - 595.28) < 1 and abs(page.rect.height - 841.89) < 1
            for block in page.get_text("dict")["blocks"]:
                for line in block.get("lines", []):
                    for span in line["spans"]:
                        x0, y0, x1, y1 = span["bbox"]
                        assert (
                            0 <= x0 < x1 <= page.rect.width + 1
                            and 0 <= y0 < y1 <= page.rect.height + 1
                        )


def test_pdf_reuses_saved_bytes_and_does_not_mix_new_workflow_values(tmp_path):
    store, draft = saved_draft(tmp_path)
    first, _ = get_or_create_pdf(store, draft["draft_id"])
    changed = deepcopy(draft)
    changed["analysis"]["times"]["t_h"] = "2099-01-01T00:00:00Z"
    second, _ = get_or_create_pdf(ReportDraftStore(store.path), draft["draft_id"])
    assert first["pdf_bytes"] == second["pdf_bytes"]
    with pymupdf.open(stream=second["pdf_bytes"], filetype="pdf") as document:
        assert "2099-01-01" not in "".join(p.get_text() for p in document)
    assert store.load(draft["draft_id"])["analysis"]["times"]["t_h"] is None


def test_export_integrity_failure_is_not_silently_replaced(tmp_path):
    store, draft = saved_draft(tmp_path)
    get_or_create_pdf(store, draft["draft_id"])
    with store.connect() as connection:
        connection.execute(
            "UPDATE report_pdf_exports SET pdf_bytes=? WHERE draft_id=?",
            (b"tampered", draft["draft_id"]),
        )
    with pytest.raises(ValueError, match="digest"):
        get_or_create_pdf(store, draft["draft_id"])


def test_review_is_separate_explicit_and_idempotent(tmp_path):
    store, draft = saved_draft(tmp_path)
    assert store.review_for(draft["draft_id"]) is None
    key = uuid4()
    first = store.review(draft["draft_id"], key, "local-demo-analyst", "fixture-digest")
    second = store.review(draft["draft_id"], key, "local-demo-analyst", "fixture-digest")
    assert first == second
    assert store.load(draft["draft_id"])["review_status_at_generation"] == "not_reviewed"
