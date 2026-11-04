# KISIA Human Workflow 1차 구현·검증

검증일: 2026-10-20 (Asia/Seoul). 작업 브랜치: `feature/dashboard/demo-polish`.
기존 미커밋 변경을 보존했으며 commit/push/merge/PR은 수행하지 않았다.

후속 외부 LLM·초안 연동은 [MonoRouter Grounded Report 구현 기록](monorouter-grounded-reports.md)을 참조한다.
현재 타임라인·인지 버튼·정정·PDF 동작은 [Workflow / Report UX 개선 기록](workflow-report-ux.md)을 참조한다.

## 조사 결과와 구현 범위

기존 Dashboard의 우측 Human Workflow와 상세 Workflow 탭은 정적 미연결 화면이었다.
전용 알림·담당자 액션·감사 모델/Repository/Migration은 없었다. 기존 Runtime telemetry,
S3 receipt, R1 archive publication을 사람의 판단 기록으로 재사용하지 않았다.

기준은 `docs/data-contract-v0.2.md` §10, `docs/schema/result-contracts.md`, 현재 Pydantic
모델과 Decision lifecycle이다. 통합 표준안 3.0 및 용어/기존 Human Workflow 원본 계약은
저장소에서 별도 본문을 찾지 못했다. 원본 대조는 후속 확인 사항이다.

기존 Run/FusionResult/DecisionResult와 그 payload를 수정하지 않는다. 내부 기술 알림은
Dashboard 안에 전달하며 이메일·외부 메시지·KISA 자동 신고를 수행하지 않는다.
LLM API, Claude SDK, Jinja2 의존성은 추가하지 않았다.

## 법령 기준과 의미의 경계

2026-10-20 확인한 현행 [정보통신망법 제48조의3](https://law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1025111303)은
침해사고 발생 사실을 알게 된 시점을 신고 시한의 기준으로 둔다.
[시행령 제58조의8](https://www.law.go.kr/LSW/lsLinkCommonInfo.do?lspttninfSeq=189991)은
신고 내용·방법·절차를 규정하며, 조문에 2026-09-30 제58조의2에서 이동했다고 명시돼 있다.
관련 인용은 이번 문서에 반영했으며 무관한 기존 문서를 일괄 치환하지 않았다.

시스템의 `t_h`는 사람이 입력한 **조직 내부 인지시각 기록**이다. 알림 확인시각,
기술 탐지시각, 신고 진행 결정시각으로 자동 추정하지 않는다. 법적 인지시점·신고의무·신고 완료를
확정하지 않는다. `operational_24h`는 입력된 `t_h + 24h`와 DB 현재시각을 비교하는 내부 운영
참고 상태이며 Pipeline SLA가 아니다. 신고 진행 결정으로 시계를 멈추거나 신고 완료를 표시하지 않는다.

## 알림 후보와 버전

`POST /human-workflow/runs/{run_id}/sync`가 저장된 실제 분석에서 알림을 조정한다.
현재는 선택한 Run을 조회할 때 실행하며 별도 background worker/outbox 전달은 없다.

- 현재 Decision head는 기존 `DecisionRepository.get_current_head`로 식별한다.
- Decision이 있으면 해당 Decision의 불변 `decision_runtime_snapshots`를 사용한다.
  최신 mutable Fusion을 과거 Decision에 결합하지 않는다.
- Fusion `detected`이면 Fusion 기술 알림을 허용한다. Hybrid의 `t_e=null`과 미평가 상태는 보존한다.
- Fusion이 탐지되지 않아도 유효한 `t_e`와 성공 `decision_path`를 가진 Hybrid는 후보가 된다.
- Decision 없이 Fusion만 있는 경우에는 검증된 Fusion payload로 후보를 만든다.
- miss/not_evaluated 자체는 탐지 근거가 아니다. Snapshot 없는 legacy Decision은 자동 결합을
  보류한다. 이런 legacy 데이터의 연결 정책은 별도 합의가 필요하다.
- Decision 후보는 `source_key=decision:{decision_id}`로 유일하다. 새로운 Decision ID는 별도 알림이다.
  Decision 없는 Fusion은 canonical payload SHA-256으로 중복을 막는다.
- Run 단위 advisory lock과 DB UNIQUE 제약이 동시 sync의 중복 발행을 막는다.
- source path, Run/Entity/Decision ID, 원래 탐지시각, 실제 발행시각, 근거 ID와 원본 결과 snapshot을 저장한다.
- 로컬 모드의 모든 후보는 `local_historical_development`로 표시한다. 실제 신규 운영 사고로 주장하지 않는다.

## DB Migration과 보존

`infra/postgres/migrations/014_human_workflow.sql`은 다음 두 테이블과 전용 함수·인덱스·트리거만 추가한다.

| 테이블 | 계약 |
| --- | --- |
| `human_workflow_alerts` | `alert_id` PK, `source_key` UNIQUE, Run/Decision FK, `detected_at`, DB `issued_at`, immutable source snapshot |
| `human_workflow_actions` | UUID PK, `(alert_id,version)`/`(alert_id,idempotency_key)` UNIQUE, Actor, action, DB 기록시각, command, 이전/이후 상태 |

기존 분석 테이블을 ALTER/UPDATE/DELETE하지 않는다. FK 삭제 정책은 RESTRICT이다.
두 테이블은 UPDATE/DELETE 거부 트리거를 가진다. 정정과 결정 변경은 새 액션을 INSERT한다.
이는 로컬 데모의 기록 보호이며 DB 관리자까지 방어하는 외부 감사 시스템으로 주장하지 않는다.

적용 대상은 `iae-localstack-demo-postgres-1`, `127.0.0.1:54330`이다. LocalStack의 기존
Migration 구성은 저장소와 다르므로 **전체 pending Migration을 일괄 실행하지 않고 014만 적용**했다.
014 이름/테이블/함수 충돌과 기존 migration ledger를 검사했다. 자동 baseline 등록은 추가하지 않았다.
일부 테이블만 이미 있거나 Migration 이력이 유실되면 CREATE 오류로 전체 트랜잭션이 롤백된다.

적용 전 절차와 증적:

1. `pg_dump --format=custom --no-owner --no-acl` 전체 백업 및 `pg_restore --list` 검증.
2. 기존 21개 public 테이블의 행 SHA-256, OID, 컬럼, 제약, 인덱스, 트리거와 함수 정의 기록.
3. 014만 트랜잭션 시험 적용 후 롤백. 새 테이블/이력이 사라지고 기존 지문이 같은지 확인.
4. 014 실제 적용 후 기존 데이터·스키마 보존 및 재적용 no-op 확인.

백업: `build/human-workflow/before.dump` (210,087 bytes).
SHA-256: `09f987fa8f1368679ce2d588af01a8b29fa8f38db9f4dd86d24c1f7e52bb0d6c`.
Migration SHA-256: `53d6a5d98bde7cc938fe29beb4ae94481bd815e81c823a9d00d718af0cabf114`.
로컬 보조 증적은 gitignored `build/human-workflow/`에 보관한다.

실제 적용 후 기능 롤백은 새 router/UI 사용을 중지하고 새 테이블을 보존하는 방식이다.
이미 기록된 알림/감사 이력은 DROP하지 않는다. 기존 DB를 덮는 복구 작업은 수행하지 않았다.
Docker Volume 삭제·초기화·기존 서버 종료도 하지 않았다.

## API와 담당자 액션

| Method / 경로 (`/human-workflow` 아래) | 동작 |
| --- | --- |
| POST `/runs/{run_id}/sync` | 후보 조정, `created` 및 최대 최근 100개 알림 |
| GET `/runs/{run_id}/alerts` | 영속 알림 목록 |
| GET `/alerts/{alert_id}` | source snapshot, state, audit, 내부 24h 상태 |
| POST `/alerts/{alert_id}/actions` | 버전 검사 후 감사 액션 추가 |
| GET `/alerts/{alert_id}/report-input` | 현재 `proceed` 결정이 있는 경우 후속 Report 최소 입력 |

쓰기 command는 `action`, 정수 `expected_version`, UUID `idempotency_key`를 필수로 받는다.
추가 필드와 클라이언트 지정 Actor는 거부한다.

| action | 입력 및 전이 |
| --- | --- |
| `review_evidence` | 명시적인 근거 검토 기록. 같은 알림에서 1회 |
| `acknowledge` | 알림 확인. `analyst_ack_time`을 DB 현재시각으로 기록. 같은 알림에서 1회 |
| `record_awareness` | 시간대 있는 RFC3339 `t_h`, 사유 필수. 미래시각 금지. 확인·검토 선행 |
| `decide_reporting` | `proceed`/`hold`/`do_not_proceed`, 사유 필수. 확인·검토 선행 |

확인과 근거 검토의 순서는 고정하지 않는다. `t_h`는 독립 입력이다. 신고 진행 결정도 `t_h`를
자동 생성하지 않으며, `t_h` 없이 결정한 경우 내부 24h 상태는 계속 기산점 없음이다.

`t_h_recorded_at` 및 `report_decided_at`은 각각 실제 기록시각이다. 정정은 이전/이후 상태와
사유를 포함한 별도 감사 행으로 남긴다. DB row lock 안에서 버전을 검사하며 충돌은 409,
누락/부적절한 입력은 422, 없는 대상은 404, DB 미준비/실패는 503이다. 실패 트랜잭션은 롤백된다.
동일 키+동일 command 재전송은 추가 기록 없이 기존 저장 상태를 반환한다. 같은 키의 다른 입력은 409다.

## Actor와 UI

환경변수 `INCIDENT_AWARENESS_LOCAL_DEMO=1`을 명시해야 한다. Actor는 서버가 고정한
`local-demo-analyst` / `unauthenticated_local_demo`다. 실제 사용자 인증으로 주장하지 않는다.
loopback client, local Host, same Origin을 확인하며 cross-site 요청과 임의 Actor 입력을 거부한다.
기존 local launcher는 proxy headers를 사용하지 않는다. 운영 인증·조직별 권한은 후속 작업이다.

기존 우측 알림 영역 → 상세 보기 → 출처/근거 보기 → 근거 검토·알림 확인 → `t_h` 기록/정정 →
신고 진행 결정 동선이다. 모든 기록 버튼은 API/DB에 연결된다. 입력 전 버튼 잠금, 브라우저 필수 입력,
중복 클릭 방지, 실패 안내, 동일 입력 재시도 키 재사용, 409 후 수동 최신 조회를 제공한다.
성공은 DB 저장 응답 후에만 표시한다. 늦게 도착한 이전 Run/상세 응답은 적용하지 않는다.

화면에는 한국어 상태와 KST 시각을 표시하며 세부 source/state 계약은 접어서 볼 수 있다.
DB가 기록의 원본이다. localStorage는 마지막으로 열었던 Run/알림 ID만 기억하며 새로고침 후
API로 다시 읽는다. 로컬 저장소가 없어도 Run을 선택하면 기록을 복원할 수 있다.

기존 `8794` 서버를 종료하지 않았다. 새 코드 검증용 서버는
`http://127.0.0.1:8795/dashboard`다. 기존 8794 프로세스의 새 router 반영에는 사용자가 관리하는
재시작이 필요하다. 자동화한 사람의 입력 검증은 별도 일회성 `8796` 테스트 서버/임시 DB에서만
수행했고, 해당 테스트 서버와 소유권/OID가 확인된 테스트 DB만 종료·정리했다.

## Report 입력 계약과 2차 책임

`grounded_report_input_v1`은 alert/Run/Entity/Decision 참조, 신고 진행 action ID/version,
현재 human state, 필드 목록, 미해결 candidate Evidence 참조를 포함한다.
각 필드는 `report_field_id → references[].evidence_id → source_event_id → raw_ref` 관계를 가진다.
`raw_ref`는 현재 `RawLogReference` 모델을 재사용한다.

발생 일시/원인/피해/대응/담당부서/연락처 6개 필드는 모두 UNKNOWN으로 시작한다.
탐지시각을 사고 발생시각으로 복사하거나, Evidence ID만으로 내용을 만들어 채우지 않는다.
현재 실제 DB의 R1 Evidence archive publication은 0건이며 원문 chain을 검증할 수 없다.
따라서 candidate Evidence는 UNRESOLVED, source_event_id/raw_ref는 null이다.

구조적으로도 VERIFIED 참조에는 event/raw_ref가 필수이며, UNKNOWN 이외 값에는 검증된 참조가
필수다. 실제 증거의 Run/Entity 일치·원문 무결성·필드와 근거의 의미적 대응 검증은 후속 resolver
책임이다. `ReportGroundingResolver`, `GroundedReportGenerator`, `ReportRenderer` Protocol을
분리했다. 2차에서 archive resolver → Claude generator → 검증 → Jinja2 fallback renderer를
구현하고 provider 오류·재시도·비용·생성 결과 버전/감사 저장을 추가한다. 이번 API는 입력만 제공한다.

## 검증 결과

| 검증 | 결과 |
| --- | --- |
| 실제 007 Fusion detected | 알림 1건, 과거 개발 분석 표시, Hybrid 미평가/t_e=null 유지 |
| 실제 006 Fusion miss / 008 not_evaluated | 각각 0건 |
| 반복/동시 sync | 중복 생성 없음 |
| 실제 데모 담당자 행위 | 0건, t_h/확인/신고 결정 미생성 |
| 임시 DB API 검증 | lifecycle/멱등성/동시 수정/새 Decision 버전 3개 통합 테스트 통과 |
| 임시 DB 실제 브라우저 | 검토·확인·인지·정정·신고 결정 5개 감사 이력, 새로고침 복원 |
| 임시 서버 실제 재시작 | 동일 상태·5개 감사 이력 복원 |
| 실제/임시 브라우저 | JavaScript 오류 0, 390px 가로 넘침 없음 |
| Dashboard/API/Offline ML/저장소·CI 목록 | Python 550건 통과 |
| 전체 Python | 최초 4,838 통과/223 skip. 임시 경로 조건에 따른 17 실패는 시스템 임시 경로 재검증으로 해소 |
| 해당 외부 임시 경로 테스트 묶음 | 87 통과/1 skip |
| 실제 PostgreSQL Migration/Telemetry/기존 Dashboard API 회귀 | 127 통과 |
| Node UI 전체 | 510 통과 (기존 S0 Replay·Offline ML 포함) |
| Ruff | check/format 검사 통과 |

전체 Python의 skip은 별도 DB/도구 환경이 필요한 기존 검사와, 명시적 테스트 DB gate가 없는
신규 통합 테스트다. 실제 실행한 신규 통합/기존 DB 회귀는 위 별도 결과로 구분했다.
검증 로그와 스크린샷: `build/human-workflow/`의 `python-*.log`, `postgres-regression.log`,
`node-regression.log`, `browser-real.json`, `browser-isolated.json`, `server-restart.json`.

## 이번 작업에서 추가·수정한 파일

새 파일:

- `infra/postgres/migrations/014_human_workflow.sql`
- `src/incident_awareness/dashboard/human_workflow.py`
- `src/incident_awareness/dashboard/grounded_report_contract.py`
- `src/incident_awareness/dashboard/api/human_workflow.py`
- `src/incident_awareness/storage/repositories/human_workflow_repository.py`
- `src/incident_awareness/dashboard/ui/assets/dashboard-workflow-controller.mjs`
- `tests/dashboard/test_human_workflow.py`, `tests/dashboard/api/test_human_workflow.py`
- `tests/dashboard/ui/test_dashboard_workflow_controller.mjs`
- `tests/integration/test_human_workflow_postgres.py`
- `tests/fixtures/human_workflow/reference-results.json` (실제 개발 결과의 읽기 전용 참조 fixture)
- 이 문서

기존 파일의 필요한 부분만 수정:

- `dashboard/api/app.py`: router 등록
- `dashboard/ui/dashboard.html`, `assets/dashboard.js`, `assets/dashboard.css`: 기존 Workflow 연결
- `.github/workflows/ci.yml`: 신규 UI 테스트 목록 등록
- `tests/dashboard/api/test_dashboard_view.py`, `tests/dashboard/ui/test_dashboard_contract.mjs`: 실제 UI 반영
- `tests/storage/test_migrate.py`: Migration 목록에 014 반영
- `devtools/{telemetry_lab_database,continuous_qa_database,e2e_qa_database}.py`: 새 임시 DB의 승인된 Migration 집합 001~014
- `tests/integration/test_{continuous_e2e_qa,live_telemetry_lab}_postgres.py`: 새 Migration 개수 반영
- `tests/integration/test_postgres_{evidence_read,stage_timing,migration_constraints,pipeline_telemetry,telemetry_input_identity}.py`:
  최신 Migration 기대값과 upgrade 검사 대상의 명시적 버전 범위 반영

기존 미커밋 작업의 다른 파일은 이번 변경 목록에 포함하지 않는다.

[DOCX 출력: 제공된 KISA 원본 양식 기반 Word 신고서](kisa-docx-quality.md).
