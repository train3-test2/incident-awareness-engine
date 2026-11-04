# Human Workflow / Grounded Report UX 개선 기록

2026-10-20, `feature/dashboard/demo-polish`.

접속: **http://127.0.0.1:8798/dashboard**. 기존 8794/8795/8797은 재시작하지 않았다.
기존 [Human Workflow](human-workflow-v1.md), [MonoRouter 구현](monorouter-grounded-reports.md)의
API·PostgreSQL 감사 원장·SQLite 초안 원장을 확장했다. 이 문서는 후속 구현 상태를 설명한다.

## 조사 결과와 보존 계획

기존 담당자 상세 영역은 실제 API와 DB에 연결되어 있었다. 상단 요약에는 알림 개수만 있었고,
인지시각은 문자열 입력, 보고서는 텍스트 조회 방식이었다. 외부 연결 성공 이력과 해당 초안의
fallback 상태가 화면에서 충분히 구분되지 않았다. 기존 구조를 유지하면서 상단에 저장 상태
타임라인을 복구하고, 입력을 접이식 패널로 이동했다.

작업 시작 시 Run 007은 근거 검토·알림 확인·신고 진행 결정의 감사 행 3개, Workflow v3,
`t_h=null`이었다. 이 상태는 작업 종료 시에도 동일하다. 007은 과거 개발 실험 데이터이며
Fusion detected / Hybrid not_evaluated / t_e=null을 함께 보존한다. 006 miss와 008 미평가는
탐지 알림을 생성하지 않는다.

PostgreSQL 변경 및 신규 Migration은 없다. Migration 014의 action 제약을 그대로 사용한다.
014 SHA-256: `53d6a5d98bde7cc938fe29beb4ae94481bd815e81c823a9d00d718af0cabf114`.
기존 모든 public 테이블의 행 해시·OID·컬럼·인덱스·제약·트리거 및 함수를 전후 비교했다.
행 1,795개인 events, runs/Fusion/Decision 각 8개, 알림 1개, 액션 3개를 포함해 모두 동일하다.

SQLite는 온라인 backup API로 `build/workflow-report-ux/report-before.sqlite3`에 먼저 백업했다.
기존 `report_drafts`의 스키마와 기존 초안 2건의 모든 컬럼·JSON을 변경하지 않았다.
추가 테이블은 기존 테이블과 이름이 겹치지 않음을 확인하고 `CREATE TABLE IF NOT EXISTS`로
추가했다. 애플리케이션을 이전 코드로 되돌려도 기존 원장을 읽을 수 있으며, 롤백을 위해
기존 데이터나 추가 감사·PDF 테이블을 삭제할 필요가 없다. 별도 버전 매핑은 기존 JSON을
보충하거나 재작성하지 않는다.

## 사용자 동작

Run 선택 → 알림 상세 → 근거 확인 → 알림 확인 → 인지 기록 → 신고 진행 결정 → 초안 생성 →
PDF 다운로드 → 필요한 경우 해당 저장 초안 검토 완료 기록.

상단 여섯 단계는 알림/Workflow/저장 초안/초안 검토 API 응답으로만 계산한다. 버튼 클릭만으로
완료 상태를 만들지 않는다. 이전 Workflow 버전의 초안과 현재 초안을 구분하고, 조회 실패를
미완료나 완료로 확정하지 않는다. 생성된 초안만 있으면 마지막 단계는 부분 진행이며 별도의
검토 기록이 있어야 완료로 표시한다.

일반 UI의 **현재 시각으로 인지 기록**은 담당자의 명시적 선택이다. 요청 본문은
`action=record_awareness, awareness_mode=now, expected_version, idempotency_key, reason`이며
브라우저 시각을 보내지 않는다. API handler가 DB 연결·잠금 이전에 UTC를 한 번 캡처하고
밀리초로 절삭한다. 그 하나의 값이 `t_h`, `t_h_recorded_at`, 감사 행 `recorded_at`에 사용된다.
Actor와 action_id는 기존 감사 행에 저장된다. 동일 키 재시도는 최초 기록을 반환하며,
다른 키의 동시 수정/이미 기록된 now 요청은 409다. 기존 저장 명령에 새 기본 속성이 없어도
정규화 후 멱등성 비교가 가능하다.

기존 수동 `t_h` API는 유지한다. 화면에서는 최초 기록 후 별도 **과거 인지시각 정정** 패널을
열고 KST 달력/시간 및 사유를 입력한다. 이전 값·새 값·사유·기록시각·Actor는 기존 append-only
감사 원장에 누적된다. 알림 확인시각, 신고 진행 결정시각, t_h는 각각 별개다. 제한된
`local-demo-analyst`는 실제 사용자 인증으로 취급하지 않으며 기존 loopback/origin 경계를 유지한다.

## API와 저장 계약

| API | 동작 및 제한 |
| --- | --- |
| `POST /human-workflow/alerts/{alert}/actions` | 기존 계약 + `awareness_mode=now`; manual 기본값/수동 API 호환 |
| `GET /human-workflow/alerts/{alert}/report-input` | 기존 필드 + 서버가 만든 `analysis` 사실 snapshot |
| `GET /human-workflow/alerts/{alert}/report-drafts` | 저장 초안, current, 문서 버전, 별도 검토 기록 |
| `POST /human-workflow/alerts/{alert}/report-drafts` | 기존 계약; 현재 사람의 proceed 결정 및 expected_version 필요 |
| `POST /human-workflow/alerts/{alert}/report-drafts/{draft}/review` | 현재 Workflow 버전의 저장 초안에 대한 별도 멱등 검토 기록 |
| `GET /human-workflow/alerts/{alert}/report-drafts/{draft}/pdf` | 해당 alert의 저장 초안만 PDF 출력 |
| `GET /human-workflow/reporting/status` | Adapter 설정, 과거 합성 연결 검증, 전송 정책을 별도로 반환 |
| `POST /human-workflow/reporting/synthetic/{alert}/drafts` | 실제 anchor의 현재 proceed 결정·버전 + 서버 개발/외부 허용 + boolean true 동의 필요 |
| `GET /human-workflow/reporting/synthetic/drafts/{draft}/pdf` | 코드 소유 합성 fixture 초안만 다운로드 |

PDF 응답은 `application/pdf`, attachment 파일명, `X-PDF-SHA256`, `X-Draft-SHA256`,
`X-Document-Version`, `Cache-Control: private, no-store`를 포함한다.

| SQLite 추가 테이블 | 저장 내용 |
| --- | --- |
| `report_versions` | draft_id ↔ alert_id 내 단조 문서 버전; 기존 초안은 생성 순서대로 배정 |
| `report_reviews` | review_id, draft_id, 멱등 키, Actor, 기록시각, 검토한 초안 해시 |
| `report_external_consents` | anchor alert, Workflow 버전, 동의 키, Actor, 기록시각, 합성 fixture 해시 |
| `report_pdf_exports` | draft_id, 문서 버전, 초안/PDF SHA-256, 생성시각, 실제 PDF 바이트 |

PDF는 최초 출력 바이트를 저장해 이후 요청/프로세스 재시작에도 같은 문서를 반환한다.
초안/버전/바이트 해시가 불일치하면 오류를 반환하며 다른 내용으로 조용히 덮어쓰지 않는다.
검토 기록은 저장 초안의 생성 당시 snapshot을 수정하지 않는다. 따라서 생성 당시 PDF의
“담당자 검토 전” 표시는 이후 별도 검토 이력과 구분된다.

## LLM, 사실과 전송 경계

Adapter 설정과 과거 연결 검증은 현재 실시간 health check가 아니다. 상태 API는 저장된
합성 호출의 HTTP 200·검증 통과 모델·요청시각·토큰을 조회한다. 별도 검증 원장은
`IAE_MONOROUTER_VERIFICATION_STORE_PATH`로 지정할 수 있으며 읽기 전용으로 조회한다.
키·설정 파일 경로·프롬프트·응답 원문을 브라우저 상태 응답에 포함하지 않는다.

기존 requests Adapter, 타임아웃·사용량 제한·출력 검증·Jinja2 fallback을 재사용한다.
실제 Workflow 전송은 차단하며, 서버의 코드 소유 합성 fixture와 **완전히 동일한 입력만**
외부 전송할 수 있다. 합성 UI는 선택된 Run의 사실·Actor·사유·t_h·Raw Sysmon을 전송하지 않는다.
별도 합성 문서를 생성하며 Run 007 보고서와 합치지 않는다. 브라우저가 제공한 데이터 분류나
VERIFIED 주장으로 전송을 허용하지 않는다. 동의 입력은 실제 boolean `true`만 허용한다.

이번 실제 브라우저 호출 결과:

- 2026-10-20 07:25:09.852328 UTC 요청, 07:25:13.738347 UTC 완료, HTTP 200.
- 요청 `claude-haiku-4.5`, 실제 `claude-haiku-4-5-20251001`.
- 입력 573 / 출력 307 토큰, cache creation/read 0.
- `monorouter_grounded`, 출력 필드·Evidence 참조를 코드 소유 원천 계약과 대조해 통과.
- 앞선 네트워크 제한 환경의 합성 요청은 transport_error로 Jinja2 fallback 처리됐다.
  네트워크가 허용된 명시적 개발 서버에서 재검증했으며 실제 Workflow 전송은 계속 차단했다.

Run 007 초안은 `jinja2_fallback / blocked_data / requested_at=null`이다. LLM이 사용되지 않았음을
해당 초안에 표시하며 Adapter 연결 성공 사실을 “미연동”으로 표현하지 않는다.

새 로컬 `analysis` snapshot은 Run/S0 메타데이터, 수집 Runtime 입력 869,
정규화 869(network_connection 853 / process_create 16), Fusion detected·score 1.0·Episode,
Decision/설정 버전, Fusion에 저장된 Evidence 참조 2개, 시간순 정규화 이벤트 참조 40개,
기존 담당자 action 3개의 사실을 보존한다. 원문 로그 본문이나 명령행·사용자정보를 가져오지 않는다.
실제 사고 발생시각은 탐지시각으로 대입하지 않으며 조직정보·원인·피해·유출·조치의
미확인 내용은 UNKNOWN/조사 중이다.

Evidence ID가 Fusion에 존재하는 사실과 Evidence archive 내용 검증은 다르다. 현재 참조 2개는
`UNRESOLVED`이며, 별도로 저장된 Normalized Event → Source Event → Raw 참조를 Evidence에
근거 없이 연결하지 않았다. LLM은 이 공백을 채우지 않는다. 향후 archive resolver가
`report_field_id → evidence_id → source_event_id → raw_ref`와 원문 무결성을 검증해야 한다.

## PDF 및 실제 검증

ReportLab로 요청한 9개 섹션을 구성했다. A4, 포함된 NanumGothic TTF, CJK 줄바꿈,
반복 표 머리글과 행/페이지 분할을 사용한다. 구현 근거는
[ReportLab 표 문서](https://docs.reportlab.com/reportlab/userguide/ch7_tables/),
[문단 문서](https://docs.reportlab.com/reportlab/userguide/ch6_paragraphs/)이며, 글꼴과 OFL 라이선스는
[Google Fonts NanumGothic](https://github.com/google/fonts/tree/main/ofl/nanumgothic)에서 함께 가져왔다.
OS의 특정 한글 글꼴 설치에 의존하지 않는다.

| 샘플 | 페이지 | PDF SHA-256 |
| --- | --- | --- |
| `build/workflow-report-ux/samples/real-incident-report-RUN-20261019-007-v6.pdf` | 8 | `e9e085efa127c8fde3840959ea1b92edca86ad468b5220bdc9b4c75fa313d6f7` |
| `build/workflow-report-ux/samples/synthetic-incident-report-SYNTHETIC-RUN-001-v2.pdf` | 4 | `27d94ce3c0f9b7123c027838286a5531963dfad1d4437fdb60f60842af851a86` |

브라우저 다운로드 바이트와 API 해시 일치, Chromium 실제 PDF viewer 열람,
PyMuPDF 한글 텍스트 추출·대체문자 없음·A4 크기·글꼴 포함·표 머리글 반복·페이지 경계 검사,
첫/분할/마지막 페이지 렌더링 육안 확인을 수행했다. “침해사고 신고 검토용 초안”,
“개발용 시나리오”, “담당자 검토 전”, “외부 제출되지 않음”을 명시한다.
KISA 공식 서식 원본과 완전 일치는 검증되지 않았다. DOCX/HWP 변환은 제공하지 않는다.

Playwright 검증은 실제 8798에서 007/006/008 알림, 기존 action 3개/t_h 미기록,
타임라인, 전송 차단 fallback, 실제 합성 LLM 및 PDF, 새로고침, 모바일 폭을 확인했다.
별도 소유권 검증된 임시 PostgreSQL/SQLite와 8800 서버에서 인지 버튼·과거 정정·신고결정·
초안검토·PDF·새로고침·서버 재시작 후 상태/감사/초안/검토/PDF 바이트 복원을 확인했다.
임시 DB/서버만 정리했고 실제 서버·데이터는 유지했다. 최종 8798 재시작 뒤에도 실제 Run 007의
동일 상태와 v6 PDF 해시를 다시 확인했다. PDF 생성 이력에는 실제 LLM 사용 여부,
Local Jinja2 제공자, 호출 없음과 전송 차단 사유를 별도로 명시한다.

추가 증거는 `build/workflow-report-ux/`의 `browser-real.json`, `browser-isolated.json`,
`server-restart.json`, `final-browser.json`, `preservation.json`, 테스트 로그와 화면 캡처에 있다.

| 검사 | 결과 |
| --- | --- |
| 전체 Python 비통합 검사 (Fusion/Decision/Evidence/S0 Replay/Offline ML/Workflow/Report 포함) | 4,837 통과, 4 건너뜀 |
| PostgreSQL Workflow/API 통합 검사 | 6 통과; 멱등성·동시 수정 200/409·정정·버전 경계·PDF·검토 |
| Dashboard UI Node 검사 | 514 통과 |
| 최종 PDF 생성 이력 표시 변경 후 Report/API 재검사 | 58 통과 |
| Ruff check / format | 통과 / 467개 파일 형식 일치 |
| 실제 브라우저 | 007 알림 1 / 006·008 알림 0, page error 0, 모바일 가로 넘침 없음 |
| 실제 데이터 보존 | PostgreSQL 전체 기존 행/스키마/함수 일치, 기존 SQLite 초안 2건 일치 |
| 비밀정보 | 소스·문서·테스트·로그·SQLite·출력 633개 파일 및 상태/OpenAPI 응답에 실제 API 키 없음 |

첫 전체 검사에서는 저장소 안 `--basetemp` 때문에 저장소 밖 출력을 요구하는 기존 R1 검사
17개가 실패했다. 테스트 임시 경로만 전용 시스템 임시 디렉터리로 바꿔 전체를 재실행했고
위 결과로 통과했다. 해당 R1 구현은 변경하지 않았다.

## 이번 변경 파일

- `dashboard/human_workflow.py`, `dashboard/api/human_workflow.py`,
  `storage/repositories/human_workflow_repository.py`: now 모드, 단일 서버 시각, 호환 멱등 처리.
- `dashboard/grounded_report_contract.py`, `reporting/analysis_snapshot.py`: 로컬 저장 분석 사실.
- `reporting/{service,store,status,pdf}.py`, `reporting/templates/draft.txt.j2`,
  `reporting/fonts/{NanumGothic-Regular.ttf,OFL.txt}`: 초안·버전·검토·동의·PDF·상태.
- `dashboard/api/{report_drafts,app}.py`: 상태/합성/검토/PDF API 연결.
- `dashboard/ui/dashboard.html`, `assets/dashboard-workflow-controller.mjs`,
  `assets/dashboard.css`: 타임라인, 패널, 인지 버튼, LLM 구분, PDF.
- `scripts/dev/run_workflow_report_dashboard.py`, `.env.example`: 기존 서버를 보존하는 별도 preview.
- `pyproject.toml`, `uv.lock`: ReportLab, 개발 검증용 PyMuPDF.
- `tests/dashboard/test_human_workflow.py`, `tests/dashboard/api/test_report_drafts.py`,
  `tests/dashboard/ui/test_dashboard_workflow_controller.mjs`,
  `tests/integration/test_human_workflow_postgres.py`, `tests/reporting/test_pdf_reports.py`: 동작/경계 검증.
- 이 문서 및 기존 두 구현 기록의 후속 문서 링크.

그 외 기존 미커밋 변경은 유지했다. PostgreSQL Migration, Run/Fusion/Decision 결과,
Docker Volume, AWS/KISA 제출 기능에는 변경이 없다.

## 남은 범위

실제 조직/개인정보 외부 전송 승인·운영 인증/RBAC, 완전한 Evidence archive resolver,
KISA 공식 서식 대조, 공식 제출 및 DOCX/HWP 변환은 이번 범위에서 구현하지 않았다.
실제 분석 데이터의 LLM 문장화는 승인과 resolver가 마련된 뒤 별도 허용 정책으로 확장해야 한다.
현재 LLM 출력은 사실 필드의 엄격한 복사·검증 계약이며 자유로운 원인/피해 추론을 허용하지 않는다.

[DOCX 출력: 제공된 KISA 원본 양식 기반 Word 신고서](kisa-docx-quality.md).
