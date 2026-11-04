# 최종 통합 E2E 및 실험 Run 라벨 정합성

2026-10-21 KST · `feature/dashboard/demo-polish`.

## 구현 범위와 호환성

실험 입력 라벨을 탐지 결과와 분리했다. 새 업로드 API는 `file`과 함께 `declaration` JSON을 요구한다:

```json
{"run_type":"normal","content_sha256":"<업로드할 실제 바이트의 SHA-256>"}
```

입력 선언은 `normal/attack` 중 명시적 선택과 실제 파일 SHA-256이 일치해야 한다. 누락·미확정·변조·
추가 필드는 422이며 Run/Raw/수집 원장을 만들기 전에 거부한다. 파일명이나 Fusion miss로 추정하지 않는다.
API는 선언을 S3 metadata에 저장한다. Worker는 같은 bucket/key/ETag의 HEAD와 다운로드된 바이트를
검증한 뒤 `run_type`을 Standalone에 **명시적으로 전달**한다.

`RunMetadata`의 기존 두 값 enum, JSON schema, PostgreSQL 열/제약은 유지했다. Migration은 추가하거나
재적용하지 않았다. Raw 015의 기존 `source_metadata` JSON에 별도로 선언 원문/출처/제한된 Actor/
서버 기록시각과 실제 `effective_run_type`을 보존한다. 선언은 실험자의 주장과 바이트 연결을 확인하는 것이며,
사고 사실·악성 여부·조직 인증을 검증하는 것이 아니다. Actor는 `local-demo-analyst` /
`unauthenticated_local_demo`로 한정한다.

`GET /ingest/sysmon/config`의 `experiment_declaration_required=true`를 통해 새 UI가 기능을 확인한다.
기존 8812처럼 이전 API가 실행 중인 서버에는 새 필드를 보내지 않아 기존 화면 동작을 유지한다.
**새 API의 file-only 요청은 의도적으로 422로 제한**하므로 API를 갱신하는 클라이언트는 선언을 추가해야 한다.
기존 RunMetadata 데이터 계약 자체가 바뀐 것은 아니다.

기존 Python Standalone 호출의 기본값은 라이브러리 하위 호환을 위해 유지했다. 이 경로의 Raw 출처는
`legacy_standalone_parameter_or_default`이며 명시적 선언으로 주장하지 않는다. 새 API/Worker 경로는
이 기본값에 의존하지 않는다. 미확정 신규 업로드는 Run을 만들지 않고 선택을 기다리게 한다.
운영용 미분류 Run 자체가 필요하면 향후 enum/DB 계약 변경이 필요하며 이번에 추가하지 않았다.

## 하나의 격리 환경

- Dashboard: **http://127.0.0.1:8814/dashboard**.
- LocalStack: `http://127.0.0.1:4578`, 이번 작업에서 만든 전용 컨테이너.
- DB: 별도 54329 서버의 새 소유 marker DB `iae_telemetry_lab_095cb993d5e54d54b94506483df203e5`.
- 원본 54330을 읽기 전용 custom-format dump로 복제했고 복원본 전체 행/스키마/함수 동일성을 확인했다.
- Report SQLite는 복사본, ingest SQLite는 이 환경 전용이다. 외부 LLM은 비활성이다.
- 업로드·Worker·Raw·알림·담당자 행위·Report·DOCX가 **이 DB 하나**에 연결된다. 중간에 다른 DB로
  업무 상태를 옮겨 이어 붙이지 않았다.

기존 8812와 Docker Worker는 재시작/교체하지 않았다. 따라서 **이번 라벨 수정이 기존 8812의 실행
프로세스에 배포됐다고 주장하지 않는다**. 수정된 소스와 실제 동작은 8814에서 검증했다.

## 신규 Run과 원본 검증

| 입력 | 신규 Run | 실제 run_type | 이벤트 | Fusion | 기여 Evidence / raw_verified |
| --- | --- | --- | ---: | --- | ---: |
| Attack | RUN-20261020-003 | attack | 869 | detected | 2 / 2 |
| Normal | RUN-20261020-004 | normal | 884 | miss | 0 / 0 |

Run ID 날짜는 실제 생성 시점 UTC 기준이다. 기존 001/002와 006/007/008 행은 수정하지 않았다.
선언 라벨·실제 RunMetadata·아카이브 출처가 각각 조회 가능하며 두 신규 Run에서 일치한다.
Normal 전체 추출 관측 1건은 보존되지만 Fusion에 기여하지 않아 알림/신고서 관측으로 쓰이지 않는다.

Raw SHA-256:

- Attack: `78c4b4a200e72a007790c0cf3cf96f8e6efa77ceb3691317de0a8e6ea326d8da`
- Normal: `7733a61b4c8bea37c279f3ab26ac5cffa166f2e7314f947ecee70fdc2e84ca53`

각 생성 시점 Manifest가 자기 Run ID/Raw ID/SHA를 가리키는지 검증했다. 생성 시점 Evidence →
저장 Event → raw_ref → 같은 Run Manifest → 보존 바이트 → Source Record를 재검증해 Attack 2건이
`raw_verified`다. 상세 Manifest SHA, 증거 ID, 선언은 `build/final-integrated-e2e/verification.json`에 있다.

## 같은 Attack Run의 업무 흐름

대상은 `RUN-20261020-003 / WIN-01`, Workflow
`HWA-e9631ce2b8b2020ac030607e54c7d27d9e558cc8cd54c5681844fc791e1b88db` 하나다.

| 단계 | 실제 검증 |
| --- | --- |
| JSONL 업로드 | 실제 브라우저에서 Attack 선택, 바이트 SHA 선언, 202 |
| Worker 분석 | 같은 DB에 새 Run, Fusion detected |
| Evidence | 2건 raw_verified |
| 기술 알림 | 해당 Run·Entity·Decision에 근거해 생성 |
| 알림 확인 | 버튼 → 감사 v1 |
| 근거 검토 | 버튼 → 감사 v2 |
| t_h 기록 | 현재 시각 버튼 → 감사 v3, UTC 밀리초 서버 시각 |
| 신고 진행 결정 | 명시적 proceed/TEST FIXTURE 사유 → 감사 v4 |
| Grounded Report | 같은 Workflow v4에서 초안 v1 |
| KISA 양식 | 테스트 Actor가 그 밖의 해킹 명시 선택, 양식 v1 |
| DOCX | 브라우저 실제 다운로드, API 해시 일치 |

t_h는 버튼을 실제 조작한 테스트 기록이다. 브라우저가 시간을 보내지 않았고 서버가 한 번 캡처한
시각을 t_h/t_h_recorded_at에 동일하게 저장했다. 확인시각·신고 결정시각은 별도 행위/필드다.
이는 법적 인지시점 확정이 아니다. 중복 클릭 및 동일 idempotency key 재시도에서 t_h/action_id가
바뀌지 않았고 감사는 4건뿐이다. 오래된 expected_version 요청은 409로 거부했다.

초안 생성 중복 클릭/동일 요청 재시도는 같은 draft_id를 반환한다. 초안·양식·DOCX export는 각각
1건이다. 이번 서버 8814만 정상 재시작한 뒤 같은 Workflow 상태/감사 4건/t_h/초안 ID/DOCX SHA가
복원되는지 새 브라우저에서 확인했다.

## 실제 신고서 내용과 Word

Jinja2 fallback으로 다음 두 사실을 문장화했다:

- 2026-09-27T07:49:41.358Z, WIN-01/powershell.exe의 `-encodedcommand` 옵션 관측.
- 2026-09-27T07:51:42.089Z, 같은 시스템/프로세스의 `1.1.1.1:443` 공인 IP 연결 관측. 악성 여부 미확인.

Evidence/Event/Raw 참조는 저장된 Grounded 입력과 technical_attachment에 연결된다.
원인·피해·유출 등 미확인 생성 필드 6개는 UNKNOWN이고 실제 수행 조치는 만들지 않았다.
실제 사고 발생시간은 확인불가다. t_h는 확인 입력으로 반영됐지만 조직/신고자/동의가 미입력이므로
**제출 준비는 false**다. 감염/C2/공격 성공을 확정하지 않는다.

파일: `build/final-integrated-e2e/downloads/KISA_침해사고_신고서_RUN-20261020-003_v1.docx`.
SHA-256: `9ed5760e02893617af9eaee0be7f6bec0beda1b18e6cf2766eb8c467bdfeaf39`.

Word 16.0 인쇄 레이아웃에서 한글/표/체크박스/실제 사고내용/t_h 반영을 확인했고, 별도 입력 셀을
편집한 사본 저장·재열기도 통과했다. 원본 템플릿/생성 원본 바이트를 유지했다. 3페이지이며
마지막 페이지의 큰 여백은 기존 renderer 한계로 남는다. 새 문서 양식이나 PDF/HWP는 만들지 않았다.

MonoRouter Adapter와 외부 전송 정책은 수정하지 않았다. 실제 LLM 호출 0건,
requested_at/actual_model=null이다. 실제 AWS API나 KISA 신고도 수행하지 않았다.

## 검사·보존 및 남은 사항

| 검사 | Pass | Fail | Skip |
| --- | ---: | ---: | ---: |
| 전체 Python | 5,033 | 0 | 239 |
| PostgreSQL Raw/Workflow | 19 | 0 | 0 |
| UI | 530 | 0 | 0 |
| Ruff / format / Git diff check | 통과 | 0 | — |
| 통합 브라우저 / 서버 재시작 / Word | 통과 | 0 | — |

초기 업로드는 기본 Windows 임시 공간 부족으로 저장 전에 실패했다. 파일을 삭제하지 않고 이
환경의 TEMP/TMP만 D: 전용 폴더로 지정해 재검증했다. 업로드 staging I/O 오류를 비밀 경로 없는
503/미확인 응답으로 처리하도록 수정하고 검사도 추가했다. 최종 점검 SQL의 잘못된 열 이름은
기존 계약 `source_draft_id`로 정정했으며 제품 데이터/스키마는 수정하지 않았다.

원본 54330 전체 행·스키마·함수, Report/ingest SQLite 전체 행·스키마, 컨테이너 ID/시작 시각/
마운트와 기존 서버 응답을 비교했다. 007은 event_verified 2건, t_h=null, Workflow v3/감사 3건 그대로다.
001/002 및 006/007/008을 포함한 기존 Run을 갱신하지 않았다. 기존 PostgreSQL/LocalStack/Worker와
8812 및 이전 Dashboard 서버는 유지했다. Git reset/clean/stash/commit/push/merge는 수행하지 않았다.

DB 삭제·초기화/Volume 삭제를 하지 않았다. PostgreSQL 검사도 종료 시 DB 삭제 대신 소유 marker를
확인해 보존하도록 실행했다. 보존한 테스트 DB 목록은 `retained-test-databases.json`에 있다.
통합 환경/증적은 `build/final-integrated-e2e/`에 남겨 두었다.

남은 범위는 기존 8812/Worker에 대한 별도 배포, 미분류 운영 Run의 향후 계약 설계, 기존 DOCX 여백
개선이다. 실제 LLM E2E는 비식별 데이터 구성과 별도 승인 이후에만 진행한다.

## 수정 파일

- `pipeline/experiment_input.py`: 선언 계약/바이트 검증/출처 context.
- `dashboard/api/sysmon_ingest.py`: 명시적 선언, admission 거부, staging 오류 응답.
- `pipeline/sqs_worker.py`, `pipeline/raw_retention.py`: 검증된 타입 전달, 출처/실제 타입 영속화.
- `dashboard/provenance_read_model.py`: 선언과 실행 메타데이터 분리 조회.
- `dashboard.html`, `dashboard-ingest-controller.mjs`, `dashboard-provenance-controller.mjs`: 선택/해시/기능 협상/출처 표시.
- `pipeline/standalone.py`: 기존 Python 호출 기본값의 호환 범위 문서화.
- 해당 API/Python/UI/PostgreSQL 검사와 `build/final-integrated-e2e/` 실행·검증 스크립트.
