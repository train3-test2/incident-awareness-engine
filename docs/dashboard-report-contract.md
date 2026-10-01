# Report 초안 입력·저장 계약 v1

이 화면은 사용자가 제공한 KISA 신고서 양식의 입력 항목을 참고한 **작성 지원 초안**입니다.
공식 신고 완료, 제출 가능성 검증, 법적 기한 판정 또는 개인정보 동의 절차를 대신하지 않습니다.
외부 제출 및 LLM 호출은 없습니다.

## 식별과 API

Report는 `(run_id, decision_id)`마다 초안 한 건입니다. 다른 Decision을 선택하면 별도 초안입니다.
해당 Run 소속 Decision이 존재해야 하며 없으면 404 DECISION_NOT_FOUND입니다.

- GET `/api/runs/{run_id}/decisions/{decision_id}/report`
- PUT 같은 경로: `{expected_revision: 0, fields: {...}}`

응답: `availability`, `revision`, `status: draft`, `fields`, `source_decision`, `updated_at`.
미저장은 availability=missing, revision=0, updated_at=null과 빈 입력 항목을 반환합니다.
첫 저장은 expected_revision=0, 수정은 최근 조회·저장으로 받은 revision을 사용합니다.
저장마다 revision이 증가합니다. 동시 생성·수정 충돌은 409 REPORT_CONFLICT이며 덮어쓰지 않습니다.
PUT은 fields 전체 교체입니다. 생략 필드는 null이 되므로 일부 항목만 PATCH하듯 사용하지 않습니다.
저장 성공 응답은 트랜잭션 커밋 후 반환합니다. 실패 시 UI 입력을 유지합니다.
네트워크 응답 유실로 저장 여부를 모르면 입력을 복사해 보존한 후 최신 저장본을 조회합니다.

## 입력 필드

- 공통: incident_type(ransomware/ddos/other), company_name, business_number, industry,
  company_size(large/mid/small/nonprofit), company_address, reporter_name, reporter_email,
  reporter_phone, occurred_at, awareness_at, awareness_evidence, incident_description,
  damage_description, victim_ip, victim_domain, response_actions
- 랜섬웨어 참고: encrypted_extensions, backup_status, affected_server_count, affected_pc_count
- 디도스 참고: server_type, service_status, attack_scale, extortion_status
- 담당자 선택: technical_support_consent, personal_data_consent (true/false/null)

초안은 부분 저장을 허용하며 모르는 값은 null입니다. 일반 텍스트 최대 500자, 서술 최대
10,000자, 피해 대수는 0 이상 정수입니다. 음수·잘못된 enum·알 수 없는 필드·타입은 400입니다.
메일/전화/IP는 초안 텍스트이며 공식 제출 형식 검증을 제공하지 않습니다.
모든 유형의 필드를 유지하여 유형 변경 시 입력을 몰래 삭제하지 않습니다.

발생 시각과 담당자 인지 시각은 시간대를 포함한 ISO timestamp만 허용합니다.
API는 UTC로 저장하고 UI는 KST로 입력·표시합니다. 숫자 timestamp와 시간대 없는 값은 거부합니다.
`t_e`를 인지 시각으로 복사하지 않으며 시각 간 순서도 임의 보정하지 않습니다.
인지 시각의 증적은 텍스트 참조만 저장합니다. 증적 파일 업로드·검증은 포함하지 않습니다.

## 시스템 참조와 사용자 입력 분리

`source_decision`은 서버가 확인한 DecisionSummary/상세를 첫 저장 시 복사하고 수정 시 유지합니다.
이는 과거 Decision 참조 보존용이며 현재 Fast/Fusion 상세의 불변 스냅샷을 뜻하지 않습니다.
사용자는 source_decision, t_e, 상태, revision을 임의 덮어쓸 수 없습니다.
동의 값은 기본 null이며 시스템이나 LLM이 대신 승인하지 않습니다.
개인정보·기업정보는 DB에 저장되며 LLM으로 전달하지 않습니다.

## DB 적용

`001_first_cycle.sql` 적용 후 `002_report_drafts.sql`을 한 번 적용해야 합니다.
기존 First Cycle migration runner는 001만 관리하므로 002는 별도 운영 단계입니다.
서버를 시작할 때 자동으로 DDL을 실행하지 않습니다.

```bash
psql "$INCIDENT_AWARENESS_DATABASE_URL" -v ON_ERROR_STOP=1 --single-transaction \
  -f infra/postgres/migrations/002_report_drafts.sql
```

대상 DB·권한을 확인한 운영 환경에서 적용합니다. 이번 작업은 실제 RDS에 적용하지 않았습니다.
API DB 사용자는 기존 테이블 조회 및 report_drafts SELECT/INSERT/UPDATE 권한이 필요합니다.
일반 조회 API의 read-only 트랜잭션은 유지하고 Report 저장 경로만 별도 쓰기 트랜잭션을 씁니다.
공유 운영자 토큰은 개인별 작성자 식별·감사 이력을 제공하지 않습니다.

## 화면

Run 상세에서 특정 Decision을 선택한 후 `Report 초안`을 엽니다.
초안 저장 → 새로 조회 → 수정 저장 흐름을 제공합니다. 저장하지 않은 상태로 이동하거나
연결 해제할 때 확인하며, 충돌·서버 오류 시 입력을 지우지 않습니다.

후속 작업: LLM 입력 비식별화·근거 기반 초안 생성, 사람 검토·출력, 실제 DB 통합 검증.
