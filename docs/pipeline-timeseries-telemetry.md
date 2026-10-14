# Pipeline 시계열 Telemetry V1

계측 단위는 Execution Attempt다. 검증된 Batch의 입력 레코드 수를 수락 시각에 한 번
기록하며 외부 스트림 유입률로 해석하지 않는다. Normalization과 Evidence 추출을 모두
마친 레코드를 성공 처리량으로 기록한다. 실패 레코드는 별도 집계하고 성공 지연 샘플에
포함하지 않는다. 성공 처리량은 Business DB 저장 성공량이 아니다.

레코드 처리 직전부터 Evidence 추출 직후까지 `monotonic_ns`로 측정한다. 기존 progress
callback, Runtime 저장 및 시계열 저장은 측정 구간 뒤에 실행된다. UTC 밀리초 관측 시각의
1초 반개구간에 집계하며, 관측하지 않은 버킷을 0으로 생성하지 않는다.
레코드는 검증된 처리 순서에서 1부터 세는 execution 내 ordinal로 식별한다.
원본 Event의 raw_ref.record_no와 생성 순서는 변경하지 않는다.
측정 범위는 `normalize_sysmon_and_extract_evidence()`의 공통 추출 구간이다. 후속 R1
archive 생성, Fusion, Persistence와 전체 End-to-End 지연은 포함하지 않는다.

RuntimeTracker의 execution ID를 Collector에 전달한다. Runtime bootstrap이 실패하면
해당 invocation의 시계열 연결도 생략한다. 이후 Runtime 내부 오류와 시계열 오류는
각자의 경계에서 격리된다. Collector/Observer 오류가 Business 반환값이나 예외를 바꾸지
않으며 기존 Runtime의 완료·실패 상태를 시계열 저장 오류로 변경하지 않는다.

Flush는 background timer가 아닌 callback 기반이다. 입력 수락 시 한 번, 처리 callback
기회에서 약 5초 간격, 레코드 처리 실패 직후, 각 stage 종료 및 Pipeline 함수 종료 시
시도한다. 긴 단일 레코드나 callback이 없는 stage 도중에는 5초 이내 저장을 보장하지 않는다.
짧은 Batch도 함수 종료 전에 최종 버킷을 저장한다. SQS 경로의 시계열 Observer는 Standalone stage 실행 범위를
감싸며, 그 뒤의 Business/Receipt commit, archive publication, Runtime finalization 및
SQS 삭제 순서는 기존대로 유지된다.

Observer는 Business와 별도 `autocommit=False`, READ COMMITTED 연결을 사용한다.
Snapshot 저장 후 no-op을 포함해 commit한다. 실패 시 rollback/close 후 다음 기회에
reconnect하며 3회 연속 실패 시 비활성화한다. 연결 제한은 2초, statement/lock timeout은
2초, transaction timeout은 5초다. `transaction_timeout`은 PostgreSQL 17부터 제공되는
설정이므로 Observer 연결에는 PostgreSQL 17 이상이 필요하다. 프로젝트 기준은 18.x이다.
동기식 I/O이므로 Business의 총 경과시간에 제한된 저장 대기 시간이 추가될 수 있다.

Observer는 한 실행의 최신 누적 Snapshot 하나만 대기시킨다. Pipeline Collector의 추가
메모리는 최대 3,600개 관측 버킷과 100,000개 레코드 식별 상태로 제한한다. 한도를 넘으면
이미 수집한 값을 보존하고 `buffer_limit`과 비활성화 상태를 표시한다. Batch 자체의
Business 처리 건수는 제한하지 않는다. 저장 재시도는 revision 기반 절대값 교체다.
Collector는 레코드마다 내부 가변 카운터만 갱신한다. Pydantic 계약 검증은 `snapshot()`에서
revision이 바뀐 버킷에만 수행하고, 바뀌지 않은 버킷은 이전 불변 객체를 재사용한다.

저장 오류는 Collector의 revision 순서 안에서 `storage_error`로 기록하고 다음 Snapshot에
보존한다. 이 표시는 이후 Flush가 한 번이라도 성공해야 DB에 남는다. 한 실행에서 저장이
3회 연속 실패하면 그 실행의 시계열은 비활성화되고 이후 재시도하지 않는다. 그 실행의 행이
전혀 없으면 Read API는 그 실행을 알 수 없으므로 품질 집계에도 나타나지 않는다. 이 경우
Runtime 상태는 completed여도 시계열은 비어 있을 수 있다. 강제 종료 전 마지막 Flush 이후의
미저장 관측값도 손실될 수 있다. 마지막 관측 시각은 heartbeat나 프로세스 생존 증거가 아니다.

함수 호출자는 `telemetry_observer`를 선택적으로 전달한다. 일반 CLI, Standalone CLI와
SQS CLI는 PostgreSQL Observer를 연결한다. 테스트는 TEST_DATABASE_URL의 테스트 전용
DB에 임시 schema를 만들고 정리한다. 실행 경로는 자동 Migration을 수행하지 않는다.
보존기간/삭제 정책과 그래프 UI 연결은 후속 범위다.

## Dashboard 시계열 Read API (Phase D)

`GET /operations/telemetry`는 읽기 전용이다. 기존 `/operations/runtime`는 변경하지 않는다.
`scope=execution&execution_id=...`는 한 Attempt, `scope=run&run_id=...`는 모든 해당
Attempt(선택적 `entity_id` 제한), 기본 `scope=reported`는 기간 내 실제 버킷을 저장한
Attempt들의 합계다. 재실행은 별도 작업량이며 고유 이벤트 수나 시스템 전체 입력량이 아니다.
Standalone과 SQS 경로에서는 같은 run_id가 서로 다른 입력에 재사용될 수 있다. 자세한
제한은 아래 "Run scope 제한사항"을 따른다.
반대 Scope의 식별자, 빈 식별자, 지원하지 않는 query parameter는 422로 거부한다.
식별자 query는 512자까지 지원한다(기존 core ID 계약을 변경하지 않는 HTTP 자원 제한).

요청 기준시각은 한 번 확정한다. 기본 300초, `window_seconds=60..300`,
`resolution_seconds=1`만 지원하며 현재 초를 제외한 UTC `[start, end)`를 조회한다.
`end_at`은 과거 검증용 UTC timezone-aware 밀리초 datetime이다. 미래 시각은 거부하며
초 미만은 완료된 초 경계까지 내려서 사용한다. 과거 조회의 최대 폭도 300초다.
저장 timestamp는 UTC 밀리초 `Z` 형식으로 반환한다.

응답 `points`는 실제 저장된 초만 시간순으로 반환한다(최대 300개). 누락 초는 배열에서
빠지며 절대 0으로 채우지 않는다. 1초 count의 수치가 해당 버킷의 records/s 수치와 같지만
Batch 수락은 한 시점의 펄스이며 지속적 외부 ingest rate를 의미하지 않는다.
`recent_60s_summary`는 동일 end 기준 마지막 60초의 알려진 count만 합산한다.
샘플이 전혀 없으면 count와 지연 합계·평균은 null이다. 관측 버킷에 기록된 0은 유지한다.
`observed_bucket_count`/`missing_bucket_count`는 시간축 존재 여부다. 모든 60초에 버킷이
있더라도 `continuous_coverage=false`이며 고정 60초 평균 처리율을 제공하지 않는다.

`processing_latency_sum_ns`와 `processing_latency_sample_count`는 저장된 `latency_sum_ns`,
`latency_sample_count`를 정수로 합산한 값이다. 평균 ms는 합계/샘플 수/1,000,000이며
샘플 수 0이면 null, 실제 측정 duration 0이면 0이다. Worker별 평균의 평균이 아니다.
측정 대상은 Normalization + Evidence 추출이며 E2E 또는 SQS 대기 지연이 아니다.
ns 정수는 JavaScript의 안전한 정수 범위를 넘을 수 있으므로 UI는 서버 계산 mean_ms를
사용하고 ns 합계로 재계산하지 않아야 한다.

품질은 최신 영속 Execution metadata의 observed/partial/unavailable, issue 목록 및
collection_disabled를 보존하여 집계한다. `basis=latest_persisted_execution_snapshot`은
과거 end_at에서도 최신 저장 품질임을 명시하며 과거 품질을 복원한 것으로 해석하지 않는다.
`no_samples`와 `partial`을 구분하고, 미보고 Execution은 포함하거나 0으로 판정하지 않는다.
시계열 모델에는 Business 완료/실패 상태가 없으므로 이 API가 이를 추론하지 않는다.

`last_observed_at`은 완료-window end 이전의 확인 가능한 실제 관측 시각,
`persisted_at`은 선택 Execution들의 실제 최신 DB `updated_at`,
`response_generated_at`은 요청 기준시각이다. 세 시각은 서로 대체하지 않는다.
현재 snapshot의 마지막 관측이 역사 조회 end 이후이고 기간 내 버킷도 없으면 관측 시각은
null이다(전체 역사 재검색 또는 가상 관측 시각 생성 금지).
Freshness는 `reference_at=range_end`와 마지막 관측 간격이 15초 초과면 stale, 없으면 unknown이다.
15초는 callback Flush 약 5초에 대한 초기 표시 기준일 뿐 보장된 Flush 주기나 SLA가 아니다.
완료 후 관측 중단·긴 단일 레코드·저장 지연도 stale일 수 있고 process_liveness는 항상 unknown이다.

Repository는 한 SQL statement에서 metadata와 버킷을 읽는다. execution PK로만 JOIN하고
각 초별 합계를 내므로 동일 execution/bucket 중복 합산이 없다. 응답에 무제한 Execution 목록은
포함하지 않는다. 기존 execution scope/time 인덱스를 사용하므로 Read API만을 위한 추가 Migration은 필요하지 않다.
단, 조회 SQL은 Migration 012에서 추가된 `input_identity_kind`와 `input_identity_sha256` 컬럼을 참조하므로, 운영 배포 전 Migration 011·012 적용이 필수다.
미적용 시 `GET /operations/telemetry`는 정상 조회할 수 없다. Dashboard 전용 연결은 read-only, 연결 timeout 2초, statement timeout 5초다.
이 연결은 `transaction_timeout`을 쓰지 않는다. 대규모 reported 집계는 DB 부하에 따라 timeout/503일 수 있다.
DB 오류는 psycopg 예외 계열로 구분한다.

| 원인 | HTTP | detail |
| --- | --- | --- |
| 연결 실패·연결 timeout, 인증 실패, 서버 종료·기동 중, 연결 수 초과, statement timeout, lock·직렬화 충돌 (`OperationalError`) | 503 | `Telemetry database is unavailable` |
| 테이블·컬럼 누락, SQL 오류, 권한 부족, 잘못된 연결 문자열, DB URL 설정 누락·형식 오류, 기타 psycopg 오류 | 500 | `Telemetry read failed` |
| 저장 집계가 응답 계약을 위반 | 500 | `Stored telemetry is invalid` |

HTTP에는 URL, 비밀번호, SQL 또는 traceback을 노출하지 않는다. DB·설정 오류의 원인 예외는
서버 로그에만 남는다. 503은 WARNING, 500 `Telemetry read failed`는 ERROR로 기록한다.

응답 예시(가독성을 위해 주요 필드만 발췌):

```json
{
    "schema_version": "pipeline_telemetry_read_v1",
    "scope": "reported",
    "aggregation_basis": "execution_attempt",
    "range_start": "2026-10-14T01:00:00.000Z",
    "range_end": "2026-10-14T01:05:00.000Z",
    "resolution_seconds": 1,
    "points": [{
        "bucket_start": "2026-10-14T01:04:59.000Z",
        "bucket_end": "2026-10-14T01:05:00.000Z",
        "observed_at": "2026-10-14T01:04:59.123Z",
        "executions_count": 2,
        "input_accepted_count": 0,
        "processing_completed_count": 3,
        "processing_failed_count": 0,
        "processing_latency_sample_count": 3,
        "processing_latency_sum_ns": 3000000,
        "processing_latency_mean_ms": 1.0
    }],
    "recent_60s_summary": {
        "range_start": "2026-10-14T01:04:00.000Z",
        "range_end": "2026-10-14T01:05:00.000Z",
        "observed_bucket_count": 1,
        "missing_bucket_count": 59,
        "continuous_coverage": false,
        "input_accepted_count": 0,
        "processing_completed_count": 3,
        "processing_failed_count": 0,
        "processing_latency_sample_count": 3,
        "processing_latency_sum_ns": 3000000,
        "processing_latency_mean_ms": 1.0
    }
}
```

## 운영 배포와 제한사항

### PostgreSQL 요구사항

Observer 연결은 시작 옵션으로 `transaction_timeout`을 전달한다. PostgreSQL 16 이하 서버는
이 이름을 알 수 없는 설정으로 보고 연결 시작 단계에서 거부한다. 그러면 실행마다 저장이
3회 연속 실패한 뒤 시계열만 비활성화되고 Business, Runtime, Receipt는 그대로 진행된다.
배포 대상 RDS 엔진이 17 이상인지 먼저 확인한다. Dashboard Read API 연결은 이 설정을 쓰지
않는다.

### Migration 011/012 적용 순서

1. 아래 "009 Migration 이력 사전 확인"으로 대상 DB의 이력을 확인한다.
2. `python -m incident_awareness.storage.migrate`로 pending 011/012를 적용한다.
3. Worker를 배포한다.
4. Dashboard를 배포한다.

develop push의 CI는 ECS migrate task를 먼저 실행하고, 성공한 경우에만 Worker 서비스,
Smoke task, Dashboard 순서로 갱신한다. Worker, CLI, Dashboard 실행 경로는 자동 Migration을
수행하지 않는다. 로컬 docker compose의 새 volume은 initdb가 012까지 실행한다.
012는 입력 식별자 컬럼·제약·함수·트리거가 모두 존재할 때만 DDL 재실행 없이 history를
기록한다. 일부만 존재하면 partial schema 오류다. 이 보호는 아래 기존 009 이력 누락 문제를
해결하지 않으므로, 이력 없는 전체 initdb schema에 runner를 바로 실행하지 않는다.

### Schema 미적용 시 영향

Worker와 CLI는 저장 시 테이블이 없어 실패한다. 실행마다 연결과 저장을 최대 3회 시도한 뒤
시계열만 비활성화한다. Business 결과, Runtime 상태, Receipt, SQS 삭제 순서는 바뀌지 않는다.
그 실행의 시계열은 남지 않으며 Migration 후에도 복구되지 않는다.

Dashboard의 `/operations/telemetry`는 500 `Telemetry read failed`를 반환한다. 일시 장애가
아니므로 재시도로 해결되지 않는다. 다른 Dashboard API는 이 테이블을 읽지 않는다.

### 입력 식별자 및 Run scope 충돌 보호

Standalone과 SQS Worker는 `RUN-YYYYMMDD-NNN` 중 commit된 runs와 decisions에 없는 첫 번호를
run_id로 할당한다. 시계열은 별도 연결로 먼저 commit된다. 따라서 입력 A의 Business 저장이나
Receipt 단계가 실패해 롤백되면, 같은 날 다음 입력 B가 같은 run_id를 받는다. 이때
`scope=run`은 두 입력의 식별자가 다르거나 안전하게 같음을 확인할 수 없으면 HTTP 409로
거부한다. 같은 입력의 재시도는 별도 실제 Attempt로 보존하고 합산한다.
`/operations/runtime`은 (run_id, entity_id)별 최신 실행만 보여 주므로 두 API의 결과가 다르다.

`test_run_scope_does_not_combine_a_rolled_back_input_with_the_next_input`의 두 경우는 일반 PASS
회귀로 전환했다. 비재사용 Run ID 예약은 별도 Issue이며 이번 작업에서 할당 방식을 바꾸지
않는다. `scope=execution`은 영향 없이 한 Attempt를 조회하고, `scope=reported`는 서로 다른
입력을 포함한 보고 Attempt 합계 의미를 유지한다. First Cycle CLI는 run_metadata의 run_id를
그대로 쓰므로 이 자동 할당 경로가 없다.

Snapshot의 선택적 `input_identity`는 `{kind, sha256}` 불변 모델이다. 파일 입력은
`file_content_sha256_v1`로 JSONL 원본 바이트의 SHA-256을 기록한다. 추가 streaming read에서
physical record_no 및 내용이 로드된 raw records와 일치하는지 검사하고, 변경·I/O 오류 시
식별자는 unknown(null)으로 남긴다. 일반/Standalone 경로는 기존 artifact 검증에서 이미 확인한
manifest SHA-256과도 비교하여 whitespace-only 변경도 새 입력으로 relabel하지 않는다.
이 checksum은 내부 artifact의 equality/repr에 영향을 주지 않는 telemetry 전용 보조 정보다.
Standalone의 시간순 처리 정렬을 바꾸지 않는다.
식별 범위는 계측 Batch인 Sysmon JSONL이며 Fusion 정책이나 Fast 설정 버전을 동일 입력이라고
추론하는 계약이 아니다. 추가 읽기·해시 비용은 처리 지연 측정 구간에 포함하지 않는다.

SQS Worker는 기존 Receipt의 bucket/decoded key/ETag를 canonical JSON tuple로 SHA-256
해시한 `s3_object_sha256_v1`을 사용한다. sequencer와 임시 파일 경로는 사용하지 않는다.
동일 콘텐츠라도 다른 key 또는 ETag는 다른 S3 객체이고, 파일 콘텐츠 식별 방식과도 구분된다.
AWS prefix materialization도 JSONL object의 ETag를 같은 방식으로 전달한다. S3 식별자를
확보하지 못하면 파일 콘텐츠 해시로 대체하지 않는다. invocation-local context는 성공·실패
후 복원하며 Worker의 기존 3-argument callback 및 Receipt/commit 순서를 변경하지 않는다.
S3 객체의 불변성은 기존 Receipt 입력 계약에 의존한다(VersionId 기반 조건부 다운로드를
새로 구현하지 않음). 해시/계측 오류는 Business 결과나 예외를 변경하지 않는다.

012는 기존 011을 변경하지 않고 nullable `input_identity_kind`, `input_identity_sha256`을
추가한다. Legacy payload, counters, revision, 저장 timestamp는 재작성하지 않는다.
Legacy 식별자를 추정하거나 backfill하지 않는다. 동일 execution_id에서는 unknown을 known으로
바꾸는 것까지 포함해 식별자 변경을 금지한다. Repository는 stale/equal/newer revision 모두
identity를 먼저 검사하며 DB 제약·트리거도 변경을 IntegrityError로 거부한다.

run scope는 entity filter와 조회 기간에 관계없이 해당 run_id의 모든 저장 Execution을 같은
SQL snapshot에서 검사한다. 복수 Execution 중 하나라도 unknown이거나 kind/digest가 다르면
집계 결과를 반환하지 않고 409다. 단일 Legacy Execution 조회는 결합이 없어 허용한다.
원본 경로와 식별자 digest는 API에 노출하지 않는다. DB 조회 오류는 기존 500/503 분류를
유지하며 409로 바꾸지 않는다. 식별자는 저장 실패로 영속화되지 않을 수 있으므로 미보고
Attempt까지 충돌 검사를 보장하는 것은 아니다.

### 009 Migration 이력 사전 확인

Migration runner는 테이블 존재 여부로 기존 schema를 baseline한다. 009는 컬럼만 추가하므로
baseline할 테이블이 없다. docker initdb처럼 이력 없이 모든 SQL 파일이 이미 실행된 DB에서
migrate를 실행하면 009를 다시 실행하다 `DuplicateColumn`으로 실패한다. 트랜잭션 전체가
롤백되므로 011도 기록되지 않는다. 011을 적용하기 전에 대상 DB를 읽기 전용으로 확인한다.

```sql
SELECT migration_id FROM schema_migrations ORDER BY migration_id;
SELECT count(*) FROM information_schema.columns
WHERE table_schema = current_schema()
  AND table_name = 'r1_stream_watermarks'
  AND column_name = 'watermark_at';
```

이력에 `009_r1_stream_close_watermark_binding`이 있으면 그대로 진행한다. `schema_migrations`가
없거나 009 이력이 빠졌는데 컬럼 수가 1이면 migrate를 실행하지 않고 조치를 따로 정한다. 009
자체의 수정은 이 문서의 범위가 아니다.
